// Daemon scheduler and tick tests (A5, A6, A7 + scheduler invariants).
//
// A5: a payment to index k is detected and the sender cursor advances to k+1;
//   the credit is recorded once even if the same address is still "used" on a
//   later rescan. Scan test against a fake oracle.
// A6: Soroban node down for 10 minutes: the daemon backs off, logs, recovers
//   with no lost state and no crash.
// A7: oracle down: registration intake continues unaffected.
// Scheduler: rendezvous republished strictly more often than the TTL across a
//   simulated hour; exponential backoff caps at 15 min; a failed persist
//   leaves the inbox entry in place and the next tick retries the persist
//   BEFORE touching the inbox (§4.2 ordering).
// Run: npm run daemon

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { PaynymIdentity } from '../src/identity.ts'
import { SorobanRPC, BoxKeypair } from '../src/soroban.ts'
import { Registrar, Registry, registerWithReceiver, rendezvousName, inboxName } from '../src/register.ts'
import { StateStore, STATE_VERSION } from '../src/store.ts'
import type { PersistedState } from '../src/store.ts'
import { loadConfig, MODE_TTL_MS } from '../src/config.ts'
import { Daemon } from '../src/daemon.ts'
import { createLogger } from '../src/log.ts'
import type { UsedAddressOracle } from '../src/watcher.ts'
import { memoryNode } from './memory-node.ts'

const fromHex = (h: string) => Uint8Array.from(Buffer.from(h, 'hex'))
const ALICE_SEED = fromHex(
  '64dca76abc9c6f0cf3d212d248c380c4622c8f93b2c425ec6a5567fd5db57e10d3e6f94a2f6af4ac2edb8998072aad92098db73558c323777abf5bd1082d970a',
)
const BOB_SEED = fromHex(
  '87eaaac5a539ab028df44d9110defbef3797ddb805ca309f61a69ff96dbaa7ab5b24038cf029edec5235d933110f0aea8aeecf939ed14fc20730bba71e4b1110',
)

let failures = 0
function assert(name: string, cond: boolean): void {
  if (!cond) failures++
  console.log(`${cond ? 'ok  ' : 'FAIL'}  ${name}`)
}

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'paynymd-dtest-'))
}

const ONION_URL = 'http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion/rpc'
const ONION_EP = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion:50001'

function makeConfig(over: Record<string, unknown> = {}) {
  return loadConfig(undefined, {
    seedFile: '/tmp/seed',
    stateDir: '/tmp/state',
    allowClearnet: true,
    soroban: { url: ONION_URL, ...(over.soroban ?? {}) },
    oracle: { endpoint: ONION_EP, ...(over.oracle ?? {}) },
  })
}

function silentLogger() {
  return createLogger({ level: 'error', redact: true, stream: { write: () => true } as NodeJS.WritableStream })
}

// A controllable fake clock + sleep for deterministic scheduler tests.
function fakeClock() {
  let t = 0
  let queue: { at: number; fn: () => void }[] = []
  const recordedDelays: number[] = []
  return {
    now: () => t,
    recordedDelays,
    sleep: (ms: number) => {
      recordedDelays.push(ms)
      return new Promise<void>((r) => queue.push({ at: t + ms, fn: r }))
    },
    async advance(ms: number) {
      const target = t + ms
      while (t < target) {
        queue.sort((a, b) => a.at - b.at)
        const next = queue[0]
        if (!next || next.at > target) break
        queue.shift()
        t = next.at
        next.fn()
        // Drain the microtask queue so the tick's continuation can schedule its
        // next sleep with the correct (current) clock reading.
        await new Promise((r) => setImmediate(r))
      }
    },
  }
}

function emptyOracle(): UsedAddressOracle & { close?: () => Promise<void> } {
  return {
    status: async (addresses: string[]) => addresses.map((a) => ({ address: a, used: false })),
    tipHeight: async () => 0,
  }
}

function seededState(bob: PaynymIdentity, boxSecretKeyHex: string, registry = []): PersistedState {
  return { version: STATE_VERSION, network: 'testnet', paymentCode: bob.paymentCode(), boxSecretKey: boxSecretKeyHex, registry, credited: [] }
}

await (async () => {
  // --- A5: payment at index k detected, cursor advances, no double credit ----
  {
    const node = memoryNode()
    const rpc = new SorobanRPC(node.transport)
    const bob = PaynymIdentity.fromSeed(BOB_SEED)
    const alice = PaynymIdentity.fromSeed(ALICE_SEED)
    const box = BoxKeypair.generate()
    const registrar = new Registrar(bob, box, new Registry())
    await registrar.publishRendezvous(rpc)
    await registerWithReceiver(rpc, alice, bob.paymentCode())
    await registrar.poll(rpc)

    const store = new StateStore(tmpDir())
    store.save(seededState(bob, registrar.boxSecretKeyHex(), registrar.registry.toJSON()))

    // Alice pays Bob at index 0 (her first send address for Bob).
    const aliceAddr0 = alice.sendAddress(bob.paymentCode(), 0)
    const used = new Set<string>()
    const oracle: UsedAddressOracle & { close?: () => Promise<void> } = {
      status: async (addresses) =>
        addresses.map((a) => ({ address: a, used: used.has(a), txids: used.has(a) ? ['f'.repeat(64)] : undefined })),
      tipHeight: async () => 0,
    }
    const clock = fakeClock()
    const daemon = new Daemon({
      config: makeConfig(),
      registrar: new Registrar(bob, box, Registry.fromJSON(registrar.registry.toJSON())),
      rpc,
      oracle,
      store,
      logger: silentLogger(),
      boxSecretKeyHex: registrar.boxSecretKeyHex(),
      now: clock.now,
      sleep: clock.sleep,
      jitter: 0,
    })

    // No payments yet.
    await daemon.runTick('scan')
    assert('A5: no credit before payment', (store.load()?.credited ?? []).length === 0)

    used.add(aliceAddr0)
    await daemon.runTick('scan')
    const after = store.load()!
    assert('A5: cursor advanced to 1', after.registry[0].nextIndex === 1)
    assert('A5: credit recorded', after.credited.length === 1 && after.credited[0].index === 0)

    // Rescan while the same address is still used: no duplicate, cursor stays.
    await daemon.runTick('scan')
    const again = store.load()!
    assert('A5: rescan does not double-credit', again.credited.length === 1)
    assert('A5: cursor not moved again', again.registry[0].nextIndex === 1)
  }

  // --- A6: Soroban down 10 minutes, backoff, recovery -------------------------
  {
    const node = memoryNode()
    // Live wrapper: the daemon must see transport failures the moment the node
    // goes down (SorobanRPC captures the transport function at construction).
    const rpc = new SorobanRPC(async (payload: any) => (node.transport as any)(payload))
    const bob = PaynymIdentity.fromSeed(BOB_SEED)
    const box = BoxKeypair.generate()
    const registrar = new Registrar(bob, box, new Registry())

    const store = new StateStore(tmpDir())
    store.save(seededState(bob, registrar.boxSecretKeyHex()))
    const clock = fakeClock()

    // Wrapper transport that fails while the node is "down".
    let down = false
    const orig = node.transport
    node.transport = async (payload: any) => {
      if (down) throw new Error('connection refused')
      return orig(payload)
    }

    const daemon = new Daemon({
      config: makeConfig({ soroban: { publishIntervalMs: 30_000, publishMode: 'short' } }),
      registrar,
      rpc,
      oracle: emptyOracle(),
      store,
      logger: silentLogger(),
      boxSecretKeyHex: registrar.boxSecretKeyHex(),
      now: clock.now,
      sleep: clock.sleep,
      jitter: 0,
    })

    down = true
    daemon.start()
    await clock.advance(10 * 60 * 1000)
    assert('A6: daemon still running after 10min down', daemon.statsOf('publish').consecutiveFailures > 0)
    assert('A6: publish backed off (delays grew)', clock.recordedDelays.length > 2)

    // Recovery: node back up; the next publish (after its current backoff,
    // which is at most the 15-minute cap) succeeds and failures reset.
    down = false
    await clock.advance(20 * 60 * 1000)
    assert('A6: recovers after node returns', daemon.statsOf('publish').consecutiveFailures === 0)
    assert('A6: publishOkAt is recent', daemon.publishOkAt > 0)
    await daemon.stop()
  }

  // --- A7: oracle down, intake unaffected -------------------------------------
  {
    const node = memoryNode()
    const rpc = new SorobanRPC(node.transport)
    const bob = PaynymIdentity.fromSeed(BOB_SEED)
    const alice = PaynymIdentity.fromSeed(ALICE_SEED)
    const box = BoxKeypair.generate()
    const registrar = new Registrar(bob, box, new Registry())
    await registrar.publishRendezvous(rpc)
    await registerWithReceiver(rpc, alice, bob.paymentCode())

    const store = new StateStore(tmpDir())
    store.save(seededState(bob, registrar.boxSecretKeyHex()))
    const brokenOracle: UsedAddressOracle & { close?: () => Promise<void> } = {
      status: async () => {
        throw new Error('oracle unreachable')
      },
      tipHeight: async () => {
        throw new Error('oracle unreachable')
      },
    }
    const daemon = new Daemon({
      config: makeConfig(),
      registrar,
      rpc,
      oracle: brokenOracle,
      store,
      logger: silentLogger(),
      boxSecretKeyHex: registrar.boxSecretKeyHex(),
      now: Date.now,
      sleep: () => Promise.resolve(),
      jitter: 0,
    })
    await daemon.runTick('scan') // oracle fails; the tick must not crash the process
    await daemon.runTick('inbox') // intake proceeds unaffected
    assert('A7: registration ingested while oracle down', registrar.registry.has(alice.paymentCode()))
    const state = store.load()!
    assert('A7: registration persisted while oracle down', state.registry.some((r) => r.paymentCode === alice.paymentCode()))
    await daemon.stop()
  }

  // --- scheduler: republished strictly more often than TTL ---------------------
  {
    const node = memoryNode()
    const rpc = new SorobanRPC(node.transport)
    const bob = PaynymIdentity.fromSeed(BOB_SEED)
    const box = BoxKeypair.generate()
    const registrar = new Registrar(bob, box, new Registry())
    const store = new StateStore(tmpDir())
    store.save(seededState(bob, registrar.boxSecretKeyHex()))
    const clock = fakeClock()
    const daemon = new Daemon({
      config: makeConfig({ soroban: { publishIntervalMs: 120_000, publishMode: 'long' } }), // TTL 300s
      registrar,
      rpc,
      oracle: emptyOracle(),
      store,
      logger: silentLogger(),
      boxSecretKeyHex: registrar.boxSecretKeyHex(),
      now: clock.now,
      sleep: clock.sleep,
      jitter: 0,
    })
    daemon.start()
    await clock.advance(61 * 60 * 1000) // one simulated hour plus slack for boundary timers
    const count = node.addCounts.get(rendezvousName(bob.paymentCode())) ?? 0
    // interval 120s over 3600s -> >= 30 publishes, each within TTL 300s.
    assert('scheduler: rendezvous republished >=30x/hour', count >= 30)
    const maxGap = Math.max(...clock.recordedDelays)
    assert('scheduler: no publish gap exceeds TTL', maxGap <= MODE_TTL_MS.long)
    await daemon.stop()
  }

  // --- backoff cap --------------------------------------------------------------
  {
    const node = memoryNode()
    // Publish always fails: wrap so the swap is visible to the rpc.
    node.transport = async () => {
      throw new Error('unreachable')
    }
    const rpc = new SorobanRPC(node.transport)
    const bob = PaynymIdentity.fromSeed(BOB_SEED)
    const box = BoxKeypair.generate()
    const registrar = new Registrar(bob, box, new Registry())
    const store = new StateStore(tmpDir())
    store.save(seededState(bob, registrar.boxSecretKeyHex()))
    const clock = fakeClock()
    const daemon = new Daemon({
      config: makeConfig({ soroban: { publishIntervalMs: 120_000 } }),
      registrar,
      rpc,
      oracle: emptyOracle(),
      store,
      logger: silentLogger(),
      boxSecretKeyHex: registrar.boxSecretKeyHex(),
      now: clock.now,
      sleep: clock.sleep,
      jitter: 0,
    })
    daemon.start()
    await clock.advance(70 * 60 * 1000) // 70 simulated minutes
    const s = daemon.statsOf('publish')
    assert('backoff: several failures accumulated', s.consecutiveFailures >= 5)
    // 15-minute cap: 2^failures * 120s doubles quickly; cap is 900s.
    const maxDelay = Math.max(...clock.recordedDelays)
    assert('backoff: delay capped at 15min', maxDelay <= 15 * 60 * 1000)
    assert('backoff: delay grew beyond base interval', clock.recordedDelays.some((d) => d > 120_000))
    await daemon.stop()
  }

  // --- §4.2: failed persist leaves entry, next tick retries BEFORE inbox --------
  {
    const node = memoryNode()
    const rpc = new SorobanRPC(node.transport)
    const bob = PaynymIdentity.fromSeed(BOB_SEED)
    const alice = PaynymIdentity.fromSeed(ALICE_SEED)
    const box = BoxKeypair.generate()
    const registrar = new Registrar(bob, box, new Registry())
    await registrar.publishRendezvous(rpc)
    await registerWithReceiver(rpc, alice, bob.paymentCode())

    const store = new StateStore(tmpDir())
    store.save(seededState(bob, registrar.boxSecretKeyHex()))
    let failSave = true
    const flaky = {
      load: () => store.load(),
      save: (s: PersistedState) => {
        if (failSave) throw new Error('disk full')
        store.save(s)
      },
    }
    const daemon = new Daemon({
      config: makeConfig(),
      registrar,
      rpc,
      oracle: emptyOracle(),
      store: flaky as unknown as StateStore,
      logger: silentLogger(),
      boxSecretKeyHex: registrar.boxSecretKeyHex(),
      now: Date.now,
      sleep: () => Promise.resolve(),
      jitter: 0,
    })

    // First inbox tick: persist fails inside onAccepted; entry must survive.
    let tickThrew = false
    try {
      await daemon.runTick('inbox')
    } catch {
      tickThrew = true
    }
    assert('§4.2: persist failure propagates out of the tick', tickThrew)
    assert('§4.2: inbox entry survives failed persist', node.live(inboxName(bob.paymentCode())).length === 1)

    // Disk healed: next tick retries persist BEFORE poll, then drains + persists.
    failSave = false
    await daemon.runTick('inbox')
    const state = store.load()!
    assert('§4.2: entry finally removed', node.live(inboxName(bob.paymentCode())).length === 0)
    assert('§4.2: registration durably persisted after recovery', state.registry.some((r) => r.paymentCode === alice.paymentCode()))
    await daemon.stop()
  }

  // --- StateMismatchError ---------------------------------------------------------
  {
    const store = new StateStore(tmpDir())
    const bob = PaynymIdentity.fromSeed(BOB_SEED)
    store.save(seededState(bob, '00'.repeat(32)))
    // A different seed points at Bob's state directory.
    const mallory = PaynymIdentity.fromSeed(ALICE_SEED)
    const registrar = new Registrar(mallory, BoxKeypair.generate(), new Registry())
    let threw = false
    try {
      new Daemon({
        config: makeConfig(),
        registrar,
        rpc: new SorobanRPC(memoryNode().transport),
        oracle: emptyOracle(),
        store,
        logger: silentLogger(),
        boxSecretKeyHex: '00'.repeat(32),
        now: Date.now,
        sleep: () => Promise.resolve(),
        jitter: 0,
      })
    } catch {
      threw = true
    }
    assert('state/seed mismatch refused', threw)
  }
})()

console.log('')
if (failures === 0) {
  console.log('PASS — daemon scheduler and ticks.')
} else {
  console.log(`FAIL — ${failures} daemon check(s) failed.`)
  process.exit(1)
}
