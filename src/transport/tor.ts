// Zero-dependency Tor transport: raw SOCKS5 + minimal HTTP/1.1 over node:net.
//
// Node's global fetch has no SOCKS support, and undici's ProxyAgent speaks
// HTTP CONNECT rather than SOCKS5, so neither can reach a .onion through the
// Tor daemon. Soroban nodes are served plain HTTP over the onion — the hidden
// service already provides encryption and endpoint authentication — so the
// whole client is small enough to hand-roll while preserving the repository's
// dependency posture (audited noble/scure family plus tweetnacl).
//
// Wire details (soroban services/directory.go + reference clients):
//   * SOCKS5: never resolve the destination locally. A .onion name is passed
//     as ATYP-3 (DOMAINNAME) so Tor resolves it — required for onion
//     addressing and the reason no DNS leak is possible.
//   * HTTP: one unauthenticated POST of a small JSON body to a fixed path,
//     Content-Length computed in BYTES (Buffer.byteLength), User-Agent
//     "HotJava/1.1.2 FCS" for parity with the reference clients.
//   * One overall deadline per request covering connect, handshake, write and
//     read. Onion round trips of 10-30s are normal; a stuck circuit that never
//     times out is what wedges a daemon.
//   * The socket is destroyed on every path, including timeout and parse
//     failure. Never fall back to global fetch.

import { connect, isIP } from 'node:net'
import type { Socket } from 'node:net'
import type { RpcTransport } from '../soroban.ts'
import type { SocksCredentials } from './isolation.ts'

export type TorOptions = {
  socksHost?: string
  socksPort?: number
  requestTimeoutMs?: number
  /** Extra HTTP headers (e.g. Bitcoin Core's Authorization). */
  headers?: Record<string, string>
  /**
   * SOCKS username/password for stream isolation. A getter is supported so the
   * caller (CircuitManager) can rotate credentials between requests; the
   * transport resolves it once per request, so rotation never happens
   * mid-request.
   */
  credentials?: SocksCredentials | (() => SocksCredentials)
}

export function torTransport(url: string, opts: TorOptions = {}): RpcTransport {
  const parsed = new URL(url)
  const destHost = parsed.hostname
  const destPort = parsed.port ? Number(parsed.port) : 80
  const path = `${parsed.pathname}${parsed.search}`
  const socksHost = opts.socksHost ?? '127.0.0.1'
  const socksPort = opts.socksPort ?? 9050
  const requestTimeoutMs = opts.requestTimeoutMs ?? 60_000

  return async (payload: unknown): Promise<any> => {
    const body = Buffer.from(JSON.stringify(payload), 'utf8')
    const credentials =
      typeof opts.credentials === 'function' ? opts.credentials() : opts.credentials
    let socket: Socket | undefined
    try {
      socket = await socksConnect(destHost, destPort, {
        socksHost,
        socksPort,
        credentials,
        timeoutMs: requestTimeoutMs,
      })
      return await httpRequest(socket, destHost, destPort, path, body, requestTimeoutMs, opts.headers)
    } finally {
      socket?.destroy()
    }
  }
}

// --- SOCKS5 ---------------------------------------------------------------

export type TunnelOptions = {
  socksHost: string
  socksPort: number
  credentials?: SocksCredentials
  timeoutMs: number
}

const SOCKS_REPLIES: Record<number, string> = {
  0x01: 'general failure',
  0x02: 'connection not allowed by ruleset',
  0x03: 'network unreachable',
  0x04: 'host unreachable',
  0x05: 'connection refused by destination host',
  0x06: 'TTL expired',
  0x07: 'command not supported',
  0x08: 'address type not supported',
}

/**
 * Open a TCP tunnel through the SOCKS5 proxy to `destHost:destPort` and run
 * the handshake. The caller owns the returned Socket and must destroy it. The
 * destination hostname is passed as ATYP-3 so Tor resolves it — no local DNS.
 */
export async function socksConnect(destHost: string, destPort: number, opts: TunnelOptions): Promise<Socket> {
  const socket = connect(opts.socksPort, opts.socksHost)
  // A Socket with no 'error' listener that emits 'error' would crash the
  // process. Transport failures surface through the reader (via 'close') or
  // the explicit throws below; this listener keeps them from being fatal.
  socket.on('error', () => {})

  const handshake = (async () => {
    await new Promise<void>((resolve, reject) => {
      socket.once('connect', () => resolve())
      socket.once('error', (err) => reject(err))
    })

    const reader = new SocketReader(socket)
    const hasAuth = opts.credentials !== undefined

    // greeting: VER(5) NMETHODS(1) METHODS(NOAUTH=0 | USER/PASS=2)
    socket.write(Buffer.from([0x05, 0x01, hasAuth ? 0x02 : 0x00]))
    const greet = await reader.readExactly(2)
    if (greet[0] !== 0x05) throw new Error(`SOCKS5: unexpected version ${greet[0]} in greeting reply`)
    const method = greet[1]
    if (method === 0xff) throw new Error('SOCKS5: no acceptable authentication method')

    if (method === 0x02) {
      if (!opts.credentials) {
        throw new Error('SOCKS5: proxy requires username/password auth but none configured')
      }
      const user = Buffer.from(opts.credentials.username, 'utf8')
      const pass = Buffer.from(opts.credentials.password, 'utf8')
      socket.write(Buffer.concat([Buffer.from([0x01, user.length]), user, Buffer.from([pass.length]), pass]))
      const auth = await reader.readExactly(2)
      if (auth[0] !== 0x01 || auth[1] !== 0x00) {
        throw new Error(`SOCKS5: username/password auth rejected (status 0x${auth[1].toString(16)})`)
      }
    } else if (method !== 0x00) {
      throw new Error(`SOCKS5: unsupported authentication method 0x${method.toString(16)}`)
    }

    // connect: VER(5) CMD(1) RSV(0) ATYP(3) <addr> <port>
    socket.write(buildConnectRequest(destHost, destPort))
    const reply = await reader.readExactly(4)
    if (reply[0] !== 0x05) throw new Error(`SOCKS5: unexpected version ${reply[0]} in connect reply`)
    const rep = reply[1]
    if (rep !== 0x00) {
      const reason = SOCKS_REPLIES[rep] ?? `unknown REP 0x${rep.toString(16)}`
      throw new Error(`SOCKS5: connect to ${destHost}:${destPort} failed: ${reason}`)
    }
    const atyp = reply[3]
    const addrLen = atyp === 0x01 ? 4 : atyp === 0x04 ? 16 : atyp === 0x03 ? (await reader.readExactly(1))[0] : null
    if (addrLen === null) throw new Error(`SOCKS5: unexpected bind address type 0x${atyp.toString(16)}`)
    await reader.readExactly(addrLen + 2) // BND.ADDR + BND.PORT, unused
    return socket
  })()

  return withTimeout(handshake, opts.timeoutMs, () => socket.destroy(), 'SOCKS5 handshake').catch((err) => {
    socket.destroy() // never leave a half-open connection to a hidden service
    throw err
  })
}

function buildConnectRequest(host: string, port: number): Buffer {
  const parts: Buffer[] = [Buffer.from([0x05, 0x01, 0x00])]
  const ip = isIP(host)
  if (ip === 4) {
    parts.push(Buffer.from([0x01]), Buffer.from(host.split('.').map(Number)))
  } else if (ip === 6) {
    // Not needed by the daemon (.onion hosts are ATYP-3); reject rather than
    // half-support it.
    throw new Error('SOCKS5: IPv6 destinations not supported')
  } else {
    const h = Buffer.from(host, 'utf8')
    if (h.length > 255) throw new Error('SOCKS5: hostname too long')
    parts.push(Buffer.from([0x03, h.length]), h)
  }
  parts.push(Buffer.from([(port >> 8) & 0xff, port & 0xff]))
  return Buffer.concat(parts)
}

// --- minimal HTTP/1.1 ------------------------------------------------------

async function httpRequest(
  socket: Socket,
  host: string,
  port: number,
  path: string,
  body: Buffer,
  timeoutMs: number,
  extraHeaders: Record<string, string> = {},
): Promise<any> {
  const lines = [
    `POST ${path} HTTP/1.1`,
    `Host: ${port === 80 ? host : `${host}:${port}`}`,
    'Content-Type: application/json',
    `Content-Length: ${body.length}`,
    'User-Agent: HotJava/1.1.2 FCS',
    'Connection: close',
  ]
  for (const [k, v] of Object.entries(extraHeaders)) lines.push(`${k}: ${v}`)
  lines.push('', '')
  const head = lines.join('\r\n')
  socket.write(Buffer.concat([Buffer.from(head, 'utf8'), body]))

  const reader = new SocketReader(socket)
  const response = await withTimeout(readResponse(reader), timeoutMs, () => socket.destroy(), 'HTTP request')
  return response
}

async function readResponse(reader: SocketReader): Promise<any> {
  const head = await reader.readUntilCrlfCrlf()
  const headerBlock = head.toString('utf8')
  const [statusLine, ...headerLines] = headerBlock.split('\r\n')
  const statusMatch = /^HTTP\/\d\.\d\s+(\d{3})/.exec(statusLine)
  if (!statusMatch) throw new Error('Soroban RPC HTTP: malformed status line')
  const status = statusMatch[1]

  const headers = new Map<string, string>()
  for (const line of headerLines) {
    const idx = line.indexOf(':')
    if (idx > 0) headers.set(line.slice(0, idx).trim().toLowerCase(), line.slice(idx + 1).trim())
  }

  // Same error shape as fetchTransport so callers stay uniform.
  if (!/^2\d\d$/.test(status)) throw new Error(`Soroban RPC HTTP ${status}`)

  const transfer = headers.get('transfer-encoding')
  if (transfer && /chunked/i.test(transfer)) {
    throw new Error('Soroban RPC HTTP: chunked transfer-encoding not supported')
  }

  let body: Buffer
  const contentLength = headers.get('content-length')
  if (contentLength !== undefined) {
    body = await reader.readExactly(Number(contentLength))
  } else {
    body = await reader.readUntilClose()
  }
  return JSON.parse(body.toString('utf8'))
}

// --- buffered reader over a socket ----------------------------------------

type Wait = { n: number; resolve: (b: Buffer) => void; reject: (e: Error) => void }

class SocketReader {
  private buffer = Buffer.alloc(0)
  private closed = false
  private waiters: Wait[] = []
  private headerWaiters: Array<() => void> = []
  private closeWaiters: Array<() => void> = []

  constructor(socket: Socket) {
    socket.on('data', (chunk) => {
      this.buffer = Buffer.concat([this.buffer, chunk])
      this.flush()
    })
    socket.on('close', () => {
      this.closed = true
      for (const h of this.headerWaiters.splice(0)) h()
      for (const w of this.waiters.splice(0)) w.reject(new Error('connection closed before reply complete'))
      for (const c of this.closeWaiters.splice(0)) c()
    })
  }

  readExactly(n: number): Promise<Buffer> {
    if (n === 0) return Promise.resolve(Buffer.alloc(0))
    if (this.buffer.length >= n) return Promise.resolve(this.take(n))
    return new Promise((resolve, reject) => this.waiters.push({ n, resolve, reject }))
  }

  readUntilCrlfCrlf(): Promise<Buffer> {
    const idx = this.buffer.indexOf('\r\n\r\n')
    if (idx >= 0) return Promise.resolve(this.take(idx + 4))
    return new Promise((resolve, reject) => {
      this.headerWaiters.push(() => {
        const i = this.buffer.indexOf('\r\n\r\n')
        if (i >= 0) resolve(this.take(i + 4))
        else reject(new Error('connection closed before headers complete'))
      })
    })
  }

  readUntilClose(): Promise<Buffer> {
    if (this.closed) return Promise.resolve(this.takeAll())
    return new Promise((resolve) => this.closeWaiters.push(() => resolve(this.takeAll())))
  }

  private flush(): void {
    while (this.waiters.length > 0 && this.buffer.length >= this.waiters[0].n) {
      const w = this.waiters.shift()!
      w.resolve(this.take(w.n))
    }
    while (this.headerWaiters.length > 0 && this.buffer.includes('\r\n\r\n')) {
      this.headerWaiters.shift()!()
    }
  }

  private take(n: number): Buffer {
    const out = this.buffer.subarray(0, n)
    this.buffer = this.buffer.subarray(n)
    return out
  }

  private takeAll(): Buffer {
    const out = this.buffer
    this.buffer = Buffer.alloc(0)
    return out
  }
}

// --- deadline helper ------------------------------------------------------

function withTimeout<T>(
  promise: Promise<T>,
  ms: number,
  onTimeout: () => void,
  label: string,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      onTimeout()
      reject(new Error(`${label} timed out after ${ms}ms`))
    }, ms)
    promise.then(
      (v) => {
        clearTimeout(timer)
        resolve(v)
      },
      (e) => {
        clearTimeout(timer)
        reject(e)
      },
    )
  })
}
