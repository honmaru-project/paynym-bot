// Atomic, fsync'd, 0600 state store plus a single-instance lockfile.
//
// The state file is the thing that cannot be regenerated: receive keys are a
// function of the seed AND the set of registered sender payment codes, so a
// corrupted or lost state file means unfindable, effectively unspendable
// funds. Durability rules:
//   * Write state.json.tmp in the same directory, fsync the file, rename over
//     the target, then fsync the directory handle. Skipping the directory
//     fsync is the classic way to lose a rename across a power cut.
//   * Never truncate in place — a partially written state file that still
//     parses is worse than one that does not.
//   * Mode 0600 / directory 0700, verified on every open, not just creation.
//   * Schema version from day one, with explicit unknown-version refusal: this
//     file will outlive several versions of the code.
//   * One instance per state directory, enforced by a 'wx'-created lockfile
//     holding the pid. Two daemons interleaving atomic writes to one registry
//     would each silently discard the other's registrations.

import fs from 'node:fs'
import path from 'node:path'
import type { SenderRecord } from './register.ts'

export const STATE_VERSION = 1 as const
export const STATE_FILE = 'state.json'
export const LOCK_FILE = 'paynymd.lock'

export type CreditRecord = {
  paymentCode: string
  index: number
  txid: string
  height: number
}

export type PersistedState = {
  version: typeof STATE_VERSION
  network: 'mainnet' | 'testnet'
  paymentCode: string // ours, for a mismatch check against the seed
  boxSecretKey: string // hex; persisted so in-flight senders survive restarts
  registry: SenderRecord[]
  lastScanHeight?: number
  credited: CreditRecord[]
}

export class UnknownSchemaError extends Error {
  constructor(version: unknown) {
    super(`unknown state schema version ${JSON.stringify(version)}; this build supports version ${STATE_VERSION}`)
    this.name = 'UnknownSchemaError'
  }
}

export class StatePermissionError extends Error {
  constructor(path: string, problem: string) {
    super(`state path ${path}: ${problem}`)
    this.name = 'StatePermissionError'
  }
}

export class LockHeldError extends Error {
  constructor(pid: number, lockPath: string) {
    super(`another paynymd instance is running (pid ${pid}; lock ${lockPath})`)
    this.name = 'LockHeldError'
  }
}

function isPidAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false
  try {
    process.kill(pid, 0)
    return true
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === 'EPERM' // exists but not ours
  }
}

export class StateStore {
  readonly stateDir: string
  private readonly statePath: string
  private readonly tmpPath: string
  private readonly lockPath: string
  private locked = false

  constructor(stateDir: string) {
    this.stateDir = stateDir
    this.statePath = path.join(stateDir, STATE_FILE)
    this.tmpPath = path.join(stateDir, `${STATE_FILE}.tmp`)
    this.lockPath = path.join(stateDir, LOCK_FILE)
  }

  /** Load persisted state. Returns null when no state exists yet. */
  load(): PersistedState | null {
    let raw: string
    try {
      raw = fs.readFileSync(this.statePath, 'utf8')
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === 'ENOENT') return null
      throw e
    }
    let parsed: unknown
    try {
      parsed = JSON.parse(raw)
    } catch {
      throw new Error(`state file ${this.statePath} is not valid JSON; restore from backup`)
    }
    const state = parsed as PersistedState
    if (state.version !== STATE_VERSION) throw new UnknownSchemaError(state.version)
    this.verifyPermissions()
    return state
  }

  /** Atomically persist state: tmp + fsync + rename + directory fsync. */
  save(state: PersistedState): void {
    fs.mkdirSync(this.stateDir, { recursive: true, mode: 0o700 })
    const fd = fs.openSync(this.tmpPath, 'w', 0o600)
    try {
      fs.writeSync(fd, JSON.stringify(state, null, 2))
      fs.fsyncSync(fd)
    } finally {
      fs.closeSync(fd)
    }
    fs.chmodSync(this.tmpPath, 0o600)
    fs.renameSync(this.tmpPath, this.statePath)
    // fsync the directory so the rename itself is durable across a power cut.
    const dirfd = fs.openSync(this.stateDir, 'r')
    try {
      fs.fsyncSync(dirfd)
    } finally {
      fs.closeSync(dirfd)
    }
  }

  /** Remove any stray tmp file left by a crash mid-write. Returns true if found. */
  cleanStrayTmp(): boolean {
    try {
      fs.accessSync(this.tmpPath)
    } catch {
      return false
    }
    fs.rmSync(this.tmpPath, { force: true })
    return true
  }

  /** Acquire the single-instance lock. Throws LockHeldError if another live
   *  instance holds it; breaks a stale lock (dead pid) with a warning. */
  acquireLock(notifyStale: (msg: string) => void = () => {}): void {
    fs.mkdirSync(this.stateDir, { recursive: true, mode: 0o700 })
    try {
      const fd = fs.openSync(this.lockPath, 'wx')
      fs.writeSync(fd, `${process.pid}\n`)
      fs.closeSync(fd)
      this.locked = true
      return
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e
    }
    // Lock exists. Is the holder alive?
    let pid: number | null = null
    try {
      pid = Number.parseInt(fs.readFileSync(this.lockPath, 'utf8').trim(), 10)
    } catch {
      pid = null
    }
    if (pid !== null && isPidAlive(pid)) throw new LockHeldError(pid, this.lockPath)
    notifyStale(`lock ${this.lockPath} held by dead pid ${pid}; breaking stale lock`)
    fs.rmSync(this.lockPath, { force: true })
    const fd = fs.openSync(this.lockPath, 'wx')
    fs.writeSync(fd, `${process.pid}\n`)
    fs.closeSync(fd)
    this.locked = true
  }

  /** Release the lock. Only deletes it if we own it (never a replaced lock). */
  releaseLock(): void {
    if (!this.locked) return
    try {
      const pid = Number.parseInt(fs.readFileSync(this.lockPath, 'utf8').trim(), 10)
      if (pid === process.pid) fs.rmSync(this.lockPath, { force: true })
    } catch {
      // already gone
    }
    this.locked = false
  }

  /** Verify 0700 directory / 0600 state file on every open, not just creation. */
  private verifyPermissions(): void {
    const dirSt = fs.statSync(this.stateDir)
    if (dirSt.mode & 0o077) {
      throw new StatePermissionError(this.stateDir, `directory must be 0700, is ${octal(dirSt.mode)}`)
    }
    const st = fs.statSync(this.statePath)
    if (st.mode & 0o077) {
      throw new StatePermissionError(this.statePath, `file must be 0600, is ${octal(st.mode)}`)
    }
  }
}

function octal(mode: number): string {
  return (mode & 0o777).toString(8)
}
