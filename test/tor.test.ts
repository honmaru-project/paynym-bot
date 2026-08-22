// SOCKS5 + minimal HTTP/1.1 transport tests against a fake proxy on 127.0.0.1.
//
// The fake proxy asserts the exact greeting / auth / connect byte sequences and
// scripts each reply so the error paths are exercised: every documented SOCKS
// failure REP code, non-2xx HTTP statuses, Content-Length framing (byte length
// vs character length), read-to-close bodies, explicit chunked rejection, and
// the overall per-request deadline. No network beyond loopback.
// Run: npm run tor

import { createServer } from 'node:net'
import type { Server, Socket } from 'node:net'
import { torTransport } from '../src/transport/tor.ts'

// 56-char v3 onion
const ONION = `${'a'.repeat(56)}.onion`
const URL = `http://${ONION}/rpc`

const JSON_RPC_OK = { jsonrpc: '2.0', id: 1, result: { Status: 'success' } }
const OK_BODY = JSON.stringify(JSON_RPC_OK)
const RESPONSE_WITH_LENGTH = `HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(OK_BODY)}\r\nConnection: close\r\n\r\n${OK_BODY}`

type ProxyScript = {
  greetingReply?: number[]
  authReply?: number[]
  connectReply?: number[] | null // null = never complete the handshake
  repCode?: number
  httpResponse?: string
}

type Transcript = {
  greeting: Buffer | null
  auth: Buffer | null
  connect: Buffer | null
  requestHead: string | null
  requestBody: string | null
}

// --- fake SOCKS5 proxy -----------------------------------------------------

function bufferedSocket(socket: Socket) {
  let buffer = Buffer.alloc(0)
  const waiters: Array<{ n: number; resolve: (b: Buffer) => void }> = []
  const headerWaiters: Array<() => void> = []
  socket.on('data', (c) => {
    buffer = Buffer.concat([buffer, c])
    while (waiters.length && buffer.length >= waiters[0].n) {
      const w = waiters.shift()!
      w.resolve(buffer.subarray(0, w.n))
      buffer = buffer.subarray(w.n)
    }
    while (headerWaiters.length && buffer.includes('\r\n\r\n')) headerWaiters.shift()!()
  })
  return {
    read: (n: number): Promise<Buffer> => {
      if (buffer.length >= n) {
        const out = buffer.subarray(0, n)
        buffer = buffer.subarray(n)
        return Promise.resolve(out)
      }
      return new Promise((resolve) => waiters.push({ n, resolve }))
    },
    readHeaders: (): Promise<string> => {
      const i = buffer.indexOf('\r\n\r\n')
      if (i >= 0) {
        const out = buffer.subarray(0, i + 4).toString('utf8')
        buffer = buffer.subarray(i + 4)
        return Promise.resolve(out)
      }
      return new Promise((resolve) =>
        headerWaiters.push(() => {
          const j = buffer.indexOf('\r\n\r\n')
          resolve(buffer.subarray(0, j + 4).toString('utf8'))
          buffer = buffer.subarray(j + 4)
        }),
      )
    },
  }
}

async function runScript(server: Server, socket: Socket, script: ProxyScript, t: Transcript): Promise<void> {
  const b = bufferedSocket(socket)
  const greeting = await b.read(3)
  t.greeting = greeting
  // Select an auth method consistent with the client's greeting: reply 0x02
  // (user/pass) iff the client offered it, else 0x00 (no auth).
  const requested = greeting[2]
  const selected = script.greetingReply ?? (requested === 0x02 ? [0x05, 0x02] : [0x05, 0x00])
  socket.write(Buffer.from(selected))
  const method = selected[1]
  if (method === 0x02) {
    const head = await b.read(2) // VER, ULEN
    const user = await b.read(head[1])
    const plen = (await b.read(1))[0]
    const pass = await b.read(plen)
    t.auth = Buffer.concat([head, user, Buffer.from([plen]), pass])
    socket.write(Buffer.from(script.authReply ?? [0x01, 0x00]))
  }
  const connectHead = await b.read(4) // VER CMD RSV ATYP
  const atyp = connectHead[3]
  let addr: Buffer
  if (atyp === 0x03) addr = await b.read((await b.read(1))[0])
  else if (atyp === 0x01) addr = await b.read(4)
  else if (atyp === 0x04) addr = await b.read(16)
  else throw new Error(`fake proxy: unexpected ATYP ${atyp}`)
  const port = await b.read(2)
  t.connect = Buffer.concat([connectHead, addr, port])

  if (script.repCode !== undefined) {
    socket.write(Buffer.from([0x05, script.repCode, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
    socket.end()
    return
  }
  if (script.connectReply === null) return // silent: leave the client hanging

  socket.write(Buffer.from(script.connectReply ?? [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))

  // Now the tunnel is transparent: read the HTTP request.
  t.requestHead = await b.readHeaders()
  const m = /^Content-Length:\s*(\d+)/im.exec(t.requestHead)
  if (m) t.requestBody = (await b.read(Number(m[1]))).toString('utf8')

  if (script.httpResponse !== undefined) socket.write(Buffer.from(script.httpResponse, 'utf8'))
  socket.end()
}

function startFakeProxy(script: ProxyScript = {}): Promise<{
  port: number
  close: () => Promise<void>
  transcript: Transcript
}> {
  const transcript: Transcript = { greeting: null, auth: null, connect: null, requestHead: null, requestBody: null }
  return new Promise((resolve, reject) => {
    const server = createServer((socket) => {
      runScript(server, socket, script, transcript).catch(() => socket.destroy())
    })
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () =>
      resolve({
        port: (server.address() as { port: number }).port,
        close: () => new Promise((r) => server.close(() => r())),
        transcript,
      }),
    )
  })
}

// --- test driver -----------------------------------------------------------

let failures = 0
function assert(name: string, cond: boolean): void {
  if (!cond) failures++
  console.log(`${cond ? 'ok  ' : 'FAIL'}  ${name}`)
}

const PAYLOAD = { jsonrpc: '2.0', id: 1, method: 'directory.Add', params: [{ Name: 'n', Entry: 'e', Mode: 'long' }] }

try {
  await (async () => {
  // --- NOAUTH handshake + successful round trip ---------------------------------------------------------------
  {
    const proxy = await startFakeProxy({ httpResponse: RESPONSE_WITH_LENGTH })
    const transport = torTransport(URL, { socksPort: proxy.port })
    const result = await transport(PAYLOAD)
    assert('returns the parsed JSON-RPC response', JSON.stringify(result) === JSON.stringify(JSON_RPC_OK))
    assert('greeting is VER=5 NMETHODS=1 NOAUTH', proxy.transcript.greeting?.equals(Buffer.from([0x05, 0x01, 0x00])) ?? false)
    assert('no auth frame sent', proxy.transcript.auth === null)
    assert('connect uses ATYP-3 (domain)', proxy.transcript.connect?.[3] === 0x03)
    assert('onion hostname passed verbatim, not resolved', proxy.transcript.connect?.subarray(4, 4 + ONION.length).toString('utf8') === ONION)
    assert('request targets POST /rpc', proxy.transcript.requestHead?.startsWith('POST /rpc HTTP/1.1') ?? false)
    assert('Host header is the onion', proxy.transcript.requestHead?.includes(`Host: ${ONION}`) ?? false)
    assert('User-Agent parity with reference clients', /HotJava\/1\.1\.2 FCS/.test(proxy.transcript.requestHead ?? '') )
    await proxy.close()
  }

  // --- username/password auth byte sequence --------------------------------------------------------------------
  {
    const proxy = await startFakeProxy({ httpResponse: RESPONSE_WITH_LENGTH })
    const transport = torTransport(URL, { socksPort: proxy.port, credentials: { username: 'u', password: 'p' } })
    await transport(PAYLOAD)
    assert('greeting requests USER/PASS auth', proxy.transcript.greeting?.equals(Buffer.from([0x05, 0x01, 0x02])) ?? false)
    assert(
      'auth frame is VER=1 ULEN user PLEN pass',
      proxy.transcript.auth?.equals(Buffer.concat([Buffer.from([0x01, 0x01]), Buffer.from('u'), Buffer.from([0x01]), Buffer.from('p')])) ?? false,
    )
    await proxy.close()
  }

  // --- auth rejected -------------------------------------------------------------------------------------------
  {
    const proxy = await startFakeProxy({ authReply: [0x01, 0xff] })
    const transport = torTransport(URL, { socksPort: proxy.port, credentials: { username: 'u', password: 'p' } })
    let threw = false
    try {
      await transport(PAYLOAD)
    } catch {
      threw = true
    }
    assert('auth rejection throws', threw)
    await proxy.close()
  }

  // --- every documented failure REP code -----------------------------------------------------------------------
  {
    const cases: Array<[number, string]> = [
      [0x01, 'general failure'],
      [0x02, 'connection not allowed by ruleset'],
      [0x03, 'network unreachable'],
      [0x04, 'host unreachable'],
      [0x05, 'connection refused by destination host'],
      [0x06, 'TTL expired'],
      [0x07, 'command not supported'],
      [0x08, 'address type not supported'],
    ]
    for (const [rep, reason] of cases) {
      const proxy = await startFakeProxy({ repCode: rep })
      const transport = torTransport(URL, { socksPort: proxy.port })
      let threw = false
      let msg = ''
      try {
        await transport(PAYLOAD)
      } catch (e) {
        threw = true
        msg = (e as Error).message
      }
      assert(`REP 0x0${rep} surfaces "${reason}"`, threw && msg.includes(reason))
      await proxy.close()
    }
  }

  // --- non-2xx HTTP status -------------------------------------------------------------------------------------
  {
    const proxy = await startFakeProxy({ httpResponse: 'HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n' })
    const transport = torTransport(URL, { socksPort: proxy.port })
    let threw = false
    let msg = ''
    try {
      await transport(PAYLOAD)
    } catch (e) {
      threw = true
      msg = (e as Error).message
    }
    assert('non-2xx throws "Soroban RPC HTTP 500"', threw && msg === 'Soroban RPC HTTP 500')
    await proxy.close()
  }

  // --- Content-Length in BYTES (multibyte body) -----------------------------------------------------------------
  {
    const multibyte = { jsonrpc: '2.0', id: 1, method: 'directory.Add', params: [{ Name: 'x', Entry: 'héllo 🚀' }] }
    const proxy = await startFakeProxy({ httpResponse: RESPONSE_WITH_LENGTH })
    const transport = torTransport(URL, { socksPort: proxy.port })
    await transport(multibyte)
    const sent = JSON.stringify(multibyte)
    const m = /^Content-Length:\s*(\d+)/im.exec(proxy.transcript.requestHead ?? '')
    assert('Content-Length present', m !== null)
    assert('Content-Length equals BYTE length', m !== null && Number(m[1]) === Buffer.byteLength(sent))
    assert('byte length exceeds character length', Buffer.byteLength(sent) > sent.length)
    await proxy.close()
  }

  // --- read-to-close when no Content-Length ---------------------------------------------------------------------
  {
    const body = `HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n${OK_BODY}`
    const proxy = await startFakeProxy({ httpResponse: body })
    const transport = torTransport(URL, { socksPort: proxy.port })
    const result = await transport(PAYLOAD)
    assert('response body parsed from read-to-close', JSON.stringify(result) === JSON.stringify(JSON_RPC_OK))
    await proxy.close()
  }

  // --- chunked responses rejected explicitly --------------------------------------------------------------------
  {
    const proxy = await startFakeProxy({ httpResponse: 'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n10\r\n{"a":"b"}\r\n0\r\n\r\n' })
    const transport = torTransport(URL, { socksPort: proxy.port })
    let threw = false
    let msg = ''
    try {
      await transport(PAYLOAD)
    } catch (e) {
      threw = true
      msg = (e as Error).message
    }
    assert('chunked transfer-encoding rejected', threw && msg.includes('chunked transfer-encoding not supported'))
    await proxy.close()
  }

  // --- overall deadline fires and destroys the socket -----------------------------------------------------------
  {
    const proxy = await startFakeProxy({ connectReply: null })
    const transport = torTransport(URL, { socksPort: proxy.port, requestTimeoutMs: 150 })
    let threw = false
    let msg = ''
    try {
      await transport(PAYLOAD)
    } catch (e) {
      threw = true
      msg = (e as Error).message
    }
    assert('handshake deadline fires', threw && /timed out after 150ms/.test(msg))
    await proxy.close()
  }
  })()
} catch (e) {
  failures++
  console.log(`FAIL  unhandled error in test suite: ${(e as Error).message}`)
}

console.log('')
if (failures === 0) {
  console.log('PASS — SOCKS5 + HTTP transport.')
} else {
  console.log(`FAIL — ${failures} transport check(s) failed.`)
  process.exit(1)
}
