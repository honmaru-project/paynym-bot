// In-memory Soroban node for offline tests.
//
// Models soroban internal/memory/memory.go semantics closely enough to exercise
// the daemon:
//   * directory.Add of an identical (Name, Entry) REFRESHES the TTL rather than
//     appending a duplicate — mirrors soroban internal/memory/memory.go.
//   * Entries expire after the mode TTL, so scheduler tests can observe a
//     rendezvous lapse without any network.
//
// The node owns a fake clock, so tests can advance time deterministically.

import type { Mode } from '../src/soroban.ts'
import type { RpcTransport } from '../src/soroban.ts'

// TTLs per Mode, from soroban internal/common/ttl.go.
export const MODE_TTL_MS: Record<Mode, number> = {
  fast: 15_000,
  short: 60_000,
  default: 180_000,
  normal: 180_000,
  long: 300_000,
}

type Entry = { value: string; expireOn: number }

export class MemoryNode {
  readonly transport: RpcTransport
  private dirs = new Map<string, Entry[]>()
  private nowMs = 0
  /** directory.Add calls per directory key, for scheduler tests. */
  readonly addCounts = new Map<string, number>()

  constructor() {
    this.transport = async (payload: any) => {
      const { method, params } = payload
      const a = params[0]
      if (method === 'directory.Add') {
        const list = this.dirs.get(a.Name) ?? []
        const ttl = MODE_TTL_MS[a.Mode as Mode] ?? MODE_TTL_MS.default
        const existing = list.find((e) => e.value === a.Entry)
        if (existing) existing.expireOn = this.nowMs + ttl
        else list.push({ value: a.Entry, expireOn: this.nowMs + ttl })
        this.dirs.set(a.Name, list)
        this.addCounts.set(a.Name, (this.addCounts.get(a.Name) ?? 0) + 1)
        return { result: { Status: 'success' } }
      }
      if (method === 'directory.List') {
        return { result: { Name: a.Name, Entries: this.live(a.Name) } }
      }
      if (method === 'directory.Remove') {
        const list = this.live(a.Name)
        const next = list.filter((e) => e !== a.Entry)
        this.dirs.set(a.Name, next.map((e) => ({ value: e, expireOn: 0 })))
        return { result: { Status: 'success' } }
      }
      return { result: null }
    }
  }

  /** Live (non-expired) entries for a directory, in insertion order. */
  live(name: string): string[] {
    const list = this.dirs.get(name) ?? []
    return list.filter((e) => e.expireOn > this.nowMs).map((e) => e.value)
  }

  /** Raw entries (including expired ones) for introspection in tests. */
  entries(name: string): Entry[] {
    return this.dirs.get(name) ?? []
  }

  /** Advance the fake clock. */
  advance(ms: number): void {
    this.nowMs += ms
  }

  /** Rewind the fake clock. */
  rewind(ms: number): void {
    this.nowMs -= ms
  }

  /** Current fake clock reading. */
  now(): number {
    return this.nowMs
  }
}

export function memoryNode(): MemoryNode {
  return new MemoryNode()
}
