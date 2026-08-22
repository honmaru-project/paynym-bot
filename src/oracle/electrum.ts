// Used-address oracle over your own electrs node, reached through the same
// SOCKS5 dialer as Soroban.
//
// The Electrum protocol is newline-delimited JSON-RPC over TCP (not HTTP), so
// it goes through socksConnect but not through the HTTP layer. We keep one
// persistent connection with a heartbeat (server.ping) rather than
// reconnecting per scan: a new circuit per scan would be both slow and a
// distinctive traffic pattern.
//
// Scripthash derivation — the step everyone forgets — is the reverse:
//   script    = 76 a9 14 <hash160(pubkey)> 88 ac   (P2PKH)
//   scripthash = reverse( SHA256(script) )
// BIP47 v1 receive addresses are P2PKH by construction, so this single script
// template covers the whole watch set.
//
// The endpoint must be the operator's OWN electrs over Tor. The watch set is
// the complete counterparty graph; handing it to a public server would
// surrender exactly the privacy the notification-less design exists to keep.

import type { Socket } from 'node:net'
import { sha256 } from '@noble/hashes/sha256'
import { base58check as base58checkFactory } from '@scure/base'
import type { AddressStatus, UsedAddressOracle } from '../watcher.ts'

const base58check = base58checkFactory(sha256)

/** Compute the Electrum scripthash for a P2PKH address. */
export function scripthashOfAddress(address: string): string {
  const payload = base58check.decode(address)
  if (payload.length !== 21) throw new Error(`not a P2PKH address: ${address}`)
  const hash160 = payload.subarray(1) // strip the version byte
  const script = Buffer.concat([
    Buffer.from([0x76, 0xa9, 0x14]),
    Buffer.from(hash160),
    Buffer.from([0x88, 0xac]),
  ])
  return Buffer.from(sha256(script)).reverse().toString('hex')
}

export type ElectrumDialer = () => Promise<Socket>

export type ElectrumOptions = {
  /** Opens the tunneled connection (e.g. socksConnect to the onion endpoint). */
  dialer: ElectrumDialer
  requestTimeoutMs?: number
  /** Keep batches modest (25-50) so one bad response does not cost a rescan. */
  batchSize?: number
  pingIntervalMs?: number
}

type Pending = {
  resolve: (v: unknown) => void
  reject: (e: Error) => void
  timer: NodeJS.Timeout
}

export class ElectrumClient {
  private readonly opts: Required<Pick<ElectrumOptions, 'requestTimeoutMs' | 'batchSize' | 'pingIntervalMs'>> &
    ElectrumOptions
  private socket: Socket | null = null
  private pending = new Map<number, Pending>()
  private nextId = 1
  private buffer = ''
  private pingTimer: NodeJS.Timeout | null = null

  constructor(opts: ElectrumOptions) {
    this.opts = { requestTimeoutMs: 15_000, batchSize: 50, pingIntervalMs: 60_000, ...opts }
  }

  async request(method: string, params: unknown[] = []): Promise<unknown> {
    const socket = await this.ensureSocket()
    const id = this.nextId++
    const p = new Promise<unknown>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id)
        this.markDead('request timeout')
        reject(new Error(`electrum ${method} timed out after ${this.opts.requestTimeoutMs}ms`))
      }, this.opts.requestTimeoutMs)
      this.pending.set(id, { resolve, reject, timer })
    })
    socket.write(`${JSON.stringify({ id, method, params })}\n`)
    return p
  }

  /** Treat a dead connection as a transient error, not a fatal one: the next
   *  request simply re-dials. */
  private markDead(reason: string): void {
    for (const [id, p] of this.pending) {
      this.pending.delete(id)
      clearTimeout(p.timer)
      p.reject(new Error(`electrum connection lost: ${reason}`))
    }
    if (this.socket) {
      this.socket.destroy()
      this.socket = null
    }
    if (this.pingTimer) clearInterval(this.pingTimer)
    this.pingTimer = null
  }

  async close(): Promise<void> {
    if (this.pingTimer) clearInterval(this.pingTimer)
    this.pingTimer = null
    if (this.socket) {
      const s = this.socket
      this.socket = null
      s.destroy()
    }
  }

  private async ensureSocket(): Promise<Socket> {
    if (this.socket && !this.socket.destroyed) return this.socket
    const socket = await this.opts.dialer()
    socket.on('data', (chunk) => this.onData(chunk.toString('utf8')))
    socket.on('close', () => this.markDead('connection closed'))
    socket.on('error', () => {})
    this.socket = socket
    this.startPing()
    return socket
  }

  private onData(text: string): void {
    this.buffer += text
    let idx: number
    while ((idx = this.buffer.indexOf('\n')) >= 0) {
      const line = this.buffer.slice(0, idx)
      this.buffer = this.buffer.slice(idx + 1)
      if (!line.trim()) continue
      let msg: any
      try {
        msg = JSON.parse(line)
      } catch {
        continue
      }
      if (msg && typeof msg.id === 'number') {
        const p = this.pending.get(msg.id)
        if (p) {
          this.pending.delete(msg.id)
          clearTimeout(p.timer)
          if (msg.error) p.reject(new Error(`electrum ${msg.error.message ?? JSON.stringify(msg.error)}`))
          else p.resolve(msg.result)
        }
      }
    }
  }

  private startPing(): void {
    if (this.pingTimer) clearInterval(this.pingTimer)
    this.pingTimer = setInterval(() => {
      if (this.socket && !this.socket.destroyed) {
        this.request('server.ping').catch(() => {})
      }
    }, this.opts.pingIntervalMs)
    if (this.pingTimer.unref) this.pingTimer.unref()
  }
}

export class ElectrumOracle implements UsedAddressOracle {
  private readonly client: ElectrumClient
  private readonly batchSize: number

  constructor(opts: ElectrumOptions) {
    this.client = new ElectrumClient(opts)
    this.batchSize = opts.batchSize ?? 50
  }

  async status(addresses: string[]): Promise<AddressStatus[]> {
    const out: AddressStatus[] = []
    for (let i = 0; i < addresses.length; i += this.batchSize) {
      const chunk = addresses.slice(i, i + this.batchSize)
      const scripthashes = chunk.map((a) => scripthashOfAddress(a))
      const results = await Promise.all(
        scripthashes.map(async (sh) => {
          const history = (await this.client.request('blockchain.scripthash.get_history', [sh])) as
            | { tx_hash: string; height: number }[]
            | undefined
          return { sh, history: Array.isArray(history) ? history : [] }
        }),
      )
      const bySh = new Map(results.map((r) => [r.sh, r.history]))
      for (const address of chunk) {
        const history = bySh.get(scripthashOfAddress(address)) ?? []
        const used = history.length > 0
        const confirmedHeights = history
          .map((h) => h.height)
          .filter((h): h is number => typeof h === 'number' && h > 0)
        out.push({
          address,
          used,
          txids: used ? history.map((h) => h.tx_hash) : undefined,
          height: confirmedHeights.length ? Math.min(...confirmedHeights) : undefined,
        })
      }
    }
    return out
  }

  async tipHeight(): Promise<number> {
    const sub = (await this.client.request('blockchain.headers.subscribe', [])) as
      | { height: number }
      | undefined
    return typeof sub?.height === 'number' ? sub.height : 0
  }

  async close(): Promise<void> {
    await this.client.close()
  }
}
