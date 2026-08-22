// The paynymd scheduler and its three ticks: publish, inbox, scan.
//
// Three tasks, three intervals, one rule each: a task never overlaps itself.
// The loop skips (with a counter) rather than queueing — queued ticks against
// a slow Tor circuit turn a transient stall into a stampede. On failure each
// task backs off exponentially to a 15-minute cap and keeps retrying; it never
// exits. Transport errors are the normal case, not the exceptional one.
//
// Ordering rule: perform the effect → update memory → make it durable →
// only then destroy the remote copy. Every Soroban remove in this daemon is
// the last statement of its transaction, and every failure before it leaves
// the entry in place. Duplicated work is free; lost work is not, because
// receive keys cannot be re-derived from the seed without the registered
// sender payment codes.

import type { Config } from './config.ts'
import { MODE_TTL_MS } from './config.ts'
import type { Logger } from './log.ts'
import { shortSender } from './log.ts'
import type { PersistedState } from './store.ts'
import type { StateStore } from './store.ts'
import { STATE_VERSION } from './store.ts'
import type { Registrar } from './register.ts'
import type { SorobanRPC } from './soroban.ts'
import { watchWindow } from './watcher.ts'
import type { UsedAddressOracle } from './watcher.ts'

export const MAX_BACKOFF_MS = 15 * 60 * 1000
export const SHUTDOWN_CAP_MS = 5_000

export type TaskName = 'publish' | 'inbox' | 'scan'

export type TaskStats = {
  runs: number
  skipped: number
  consecutiveFailures: number
  lastRunAt?: number
  lastOkAt?: number
  lastError?: string
}

export class StateMismatchError extends Error {
  constructor(statePaymentCode: string, seedPaymentCode: string) {
    super(
      `state payment code ${statePaymentCode} does not match the seed-derived ${seedPaymentCode}; ` +
        `pointing a different seed at an existing registry would watch addresses you hold no keys for`,
    )
    this.name = 'StateMismatchError'
  }
}

export type DaemonOptions = {
  config: Config
  registrar: Registrar
  rpc: SorobanRPC
  oracle: UsedAddressOracle & { close?: () => Promise<void> }
  store: StateStore
  logger: Logger
  /** Box secret hex from the persisted/current keypair, written into state. */
  boxSecretKeyHex: string
  now?: () => number
  sleep?: (ms: number) => Promise<void>
  /** Jitter fraction applied per schedule (default 0.2 = ±20%). */
  jitter?: number
}

export class Daemon {
  private readonly config: Config
  private readonly registrar: Registrar
  private readonly rpc: SorobanRPC
  private readonly oracle: UsedAddressOracle & { close?: () => Promise<void> }
  private readonly store: StateStore
  private readonly logger: Logger
  private readonly boxSecretKeyHex: string
  private readonly now: () => number
  private readonly sleep: (ms: number) => Promise<void>
  private readonly jitter: number

  private state: PersistedState
  private readonly stats: Record<TaskName, TaskStats> = {
    publish: emptyStats(),
    inbox: emptyStats(),
    scan: emptyStats(),
  }
  private readonly inFlight: Record<TaskName, boolean> = { publish: false, inbox: false, scan: false }
  private running = false
  private stopping = false
  private pendingPersist = false
  private lastPublishOk = 0
  private lastRejectCount = 0

  constructor(opts: DaemonOptions) {
    this.config = opts.config
    this.registrar = opts.registrar
    this.rpc = opts.rpc
    this.oracle = opts.oracle
    this.store = opts.store
    this.logger = opts.logger
    this.boxSecretKeyHex = opts.boxSecretKeyHex
    this.now = opts.now ?? Date.now
    this.sleep = opts.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)))
    this.jitter = opts.jitter ?? 0.2

    const loaded = this.store.load()
    if (loaded) {
      if (loaded.paymentCode !== this.registrar.identity.paymentCode()) {
        throw new StateMismatchError(loaded.paymentCode, this.registrar.identity.paymentCode())
      }
      this.state = loaded
    } else {
      this.state = {
        version: STATE_VERSION,
        network: this.config.network,
        paymentCode: this.registrar.identity.paymentCode(),
        boxSecretKey: this.boxSecretKeyHex,
        registry: this.registrar.registry.toJSON(),
        credited: [],
      }
    }
    this.lastRejectCount = this.registrar.rejected()
  }

  /** Start the three independent task loops. */
  start(): void {
    this.running = true
    this.loop('publish')
    this.loop('inbox')
    this.loop('scan')
  }

  /**
   * Stop scheduling, await the in-flight tick (bounded by SHUTDOWN_CAP_MS),
   * flush state, and return. No process.exit here — the caller owns exit codes.
   */
  async stop(): Promise<void> {
    if (this.stopping) return
    this.stopping = true
    this.running = false
    const deadline = this.now() + SHUTDOWN_CAP_MS
    while (this.anyInFlight() && this.now() < deadline) {
      await this.sleep(50)
    }
    this.persist()
    if (this.oracle.close) await this.oracle.close().catch(() => {})
  }

  statsOf(name: TaskName): TaskStats {
    return this.stats[name]
  }

  /** Timestamp of the last successful rendezvous publish (0 = never). */
  get publishOkAt(): number {
    return this.lastPublishOk
  }

  // --- task loops ----------------------------------------------------------

  private loop(name: TaskName): void {
    const intervalMs = intervalFor(this.config, name)
    ;(async () => {
      while (this.running) {
        const delay = this.nextDelay(name, intervalMs)
        await this.sleep(delay)
        if (!this.running) return
        if (this.inFlight[name]) {
          this.stats[name].skipped++
          continue
        }
        this.inFlight[name] = true
        this.stats[name].runs++
        this.stats[name].lastRunAt = this.now()
        try {
          await this.runTick(name)
          this.stats[name].consecutiveFailures = 0
          this.stats[name].lastOkAt = this.now()
        } catch (e) {
          this.stats[name].consecutiveFailures++
          this.stats[name].lastError = (e as Error)?.message ?? String(e)
          this.logger.error(`task ${name} failed`, { error: this.stats[name].lastError })
        } finally {
          this.inFlight[name] = false
        }
      }
    })()
  }

  private nextDelay(name: TaskName, intervalMs: number): number {
    const failures = this.stats[name].consecutiveFailures
    if (failures > 0) {
      const backoff = Math.min(intervalMs * 2 ** failures, MAX_BACKOFF_MS)
      return jittered(backoff, this.jitter)
    }
    return jittered(intervalMs, this.jitter)
  }

  private anyInFlight(): boolean {
    return this.inFlight.publish || this.inFlight.inbox || this.inFlight.scan
  }

  /** The three ticks, exposed for deterministic tests and for stop(). */
  async runTick(name: TaskName): Promise<void> {
    if (name === 'publish') return this.publishTick()
    if (name === 'inbox') return this.inboxTick()
    return this.scanTick()
  }

  // --- publishTick ---------------------------------------------------------

  private async publishTick(): Promise<void> {
    this.warnClearnet()
    const ttl = MODE_TTL_MS[this.config.soroban.publishMode]
    if (this.lastPublishOk > 0 && this.now() - this.lastPublishOk > ttl) {
      // A receiver that is not published is invisible, and invisibility looks
      // identical to "nobody is paying me this week". Say so loudly.
      this.logger.error('receiver has not been published within the TTL; new senders cannot find us')
    }
    const ok = await this.registrar.publishRendezvous(this.rpc, this.config.soroban.publishMode)
    if (!ok) throw new Error('rendezvous publish returned failure')
    this.lastPublishOk = this.now()
    this.logger.debug('rendezvous published', { mode: this.config.soroban.publishMode })
  }

  // --- inboxTick -----------------------------------------------------------

  private async inboxTick(): Promise<void> {
    this.warnClearnet()
    // Durability ordering: retry any prior failed persist BEFORE touching the inbox,
    // or a retry-remove could destroy the only copy of an unpersisted
    // registration. persist() throws on failure, aborting this tick before
    // any poll/remove runs.
    if (this.pendingPersist) this.persist()

    const added = await this.registrar.poll(this.rpc, {
      onAccepted: async (paymentCode) => {
        try {
          this.persist()
        } catch (e) {
          this.pendingPersist = true
          throw e // entry must stay in the inbox; the exception propagates out of poll
        }
      },
    })
    for (const code of added) {
      this.logger.info('new sender registered', { sender: shortSender(code) })
    }
    const rejected = this.registrar.rejected()
    const newRejects = rejected - this.lastRejectCount
    this.lastRejectCount = rejected
    if (newRejects > 0) {
      // A rejected inbox entry is removed by design (it must never pin the
      // queue); the counter makes a spam attack observable.
      this.logger.warn('inbox entries rejected', { count: newRejects })
    }
    if (added.length > 0) this.logger.info('inbox drained', { added: added.length })
  }

  // --- scanTick ------------------------------------------------------------

  private async scanTick(): Promise<void> {
    this.warnClearnet()
    const gap = this.config.oracle.gapLimit
    const trailing = this.config.oracle.trailingWindow
    const watch = watchWindow(this.registrar.identity, this.registrar.registry, gap, trailing)
    if (watch.length === 0) return

    const statuses = await this.oracle.status(watch.map((w) => w.address))
    const byAddress = new Map(watch.map((w) => [w.address, w]))
    // Deduplicate credits by (txid, index) so a re-scan never re-notifies.
    const seen = new Set(this.state.credited.map((c) => `${c.txid}:${c.index}`))
    let credits = 0
    for (const st of statuses) {
      if (!st.used) continue
      const w = byAddress.get(st.address)
      if (!w) continue
      const belowTrailing = w.index < (this.registrar.registry.get(w.paymentCode)?.nextIndex ?? 0)
      if (belowTrailing) {
        // A sender reusing indices is a correctness signal about the peer.
        this.logger.warn('sender reused an index below the trailing window', {
          sender: shortSender(w.paymentCode),
          index: w.index,
        })
      }
      const txids = st.txids && st.txids.length > 0 ? st.txids : ['unknown']
      for (const txid of txids) {
        const key = `${txid}:${w.index}`
        if (seen.has(key)) continue
        seen.add(key)
        this.state.credited.push({
          paymentCode: w.paymentCode,
          index: w.index,
          txid,
          height: st.height ?? 0,
        })
        credits++
      }
      this.registrar.registry.advance(w.paymentCode, w.index)
    }
    if (credits > 0) {
      // Durable before any external notification, so a webhook can never claim
      // a payment the daemon has forgotten. There is no webhook yet; persist
      // anyway as the ordering invariant.
      this.persist()
      this.logger.info('scan credited', { credits })
    }
  }

  // --- helpers -------------------------------------------------------------

  private warnClearnet(): void {
    // --allow-clearnet exists only for the local integration test and must be
    // prominent on every tick.
    if (this.config.allowClearnet) {
      this.logger.warn('running with --allow-clearnet: traffic is NOT over Tor')
    }
  }

  private persist(): void {
    this.state = {
      ...this.state,
      boxSecretKey: this.boxSecretKeyHex,
      registry: this.registrar.registry.toJSON(),
    }
    this.store.save(this.state)
    this.pendingPersist = false
  }
}

function intervalFor(config: Config, name: TaskName): number {
  switch (name) {
    case 'publish':
      return config.soroban.publishIntervalMs
    case 'inbox':
      return config.soroban.inboxIntervalMs
    case 'scan':
      return config.oracle.scanIntervalMs
  }
}

function jittered(ms: number, fraction: number): number {
  if (fraction <= 0) return ms
  const spread = ms * fraction
  return ms - spread + Math.random() * spread * 2
}

function emptyStats(): TaskStats {
  return { runs: 0, skipped: 0, consecutiveFailures: 0 }
}
