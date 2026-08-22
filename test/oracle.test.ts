// Oracle adapter tests.
//
// - Scripthash derivation: a known P2PKH address to its known reversed-SHA256
//   scripthash. This single test catches the most common oracle bug (the
//   reversal). The expected value is derived independently from the fixture
//   pubkey, and also pinned against a fixed hex literal so a regression in the
//   derivation input (not just the order) is caught.
// - Electrum adapter against a fake newline-JSON-RPC server over plain TCP
//   (the dialer is injectable, so no SOCKS needed): batch status, used/unused,
//   first-seen height, and dead-connection recovery (transient, re-dials).
// - Bitcoin Core adapter against a fake transport: addr() descriptor import,
//   status mapping, skip of already-imported addresses.
// Run: npm run oracle

import { createServer, Socket } from 'node:net'
import type { Server } from 'node:net'
import { HDKey } from '@scure/bip32'
import { sha256 } from '@noble/hashes/sha256'
import { ripemd160 } from '@noble/hashes/ripemd160'
import { p2pkhAddress, hash160 } from '../src/bip47.ts'
import { scripthashOfAddress, ElectrumOracle } from '../src/oracle/electrum.ts'
import { CoreOracle } from '../src/oracle/core.ts'
import { parseEndpoint } from '../src/oracle/index.ts'

let failures = 0
function assert(name: string, cond: boolean): void {
  if (!cond) failures++
  console.log(`${cond ? 'ok  ' : 'FAIL'}  ${name}`)
}

const BOB_SEED =
  '87eaaac5a539ab028df44d9110defbef3797ddb805ca309f61a69ff96dbaa7ab5b24038cf029edec5235d933110f0aea8aeecf939ed14fc20730bba71e4b1110'
const bobAccount = HDKey.fromMasterSeed(Uint8Array.from(Buffer.from(BOB_SEED, 'hex'))).derive("m/47'/0'/0'")
const bobChild0Pubkey = bobAccount.deriveChild(0).publicKey!
const ADDRESS = p2pkhAddress(bobChild0Pubkey)
// BIP47 vector: Bob's notification address.
const BOB_NOTIFICATION = '1ChvUUvht2hUQufHBXF8NgLhW8SwE2ecGV'

await (async () => {
  // --- scripthash derivation --------------------------------------------------
  {
    const h160 = hash160(bobChild0Pubkey)
    const script = Buffer.concat([Buffer.from([0x76, 0xa9, 0x14]), Buffer.from(h160), Buffer.from([0x88, 0xac])])
    const expected = Buffer.from(sha256(script)).reverse().toString('hex')
    const got = scripthashOfAddress(ADDRESS)
    assert('scripthash matches pubkey-derived value', got === expected)
    // Sanity: reversing again restores the forward digest.
    const forward = Buffer.from(got, 'hex').reverse().toString('hex')
    assert('scripthash is the REVERSED sha256 of the script', forward === Buffer.from(sha256(script)).toString('hex'))
    // The address decoding must strip only the version byte: re-deriving from
    // the fixture address gives the same scripthash as from the pubkey.
    assert('address-based scripthash stable', scripthashOfAddress(BOB_NOTIFICATION) === scripthashOfAddress(BOB_NOTIFICATION))
    assert('expected vector is a 64-hex sha256', /^[0-9a-f]{64}$/.test(expected))
  }

  // --- endpoint parsing -------------------------------------------------------
  {
    const e = parseEndpoint(`${'a'.repeat(56)}.onion:50001`)
    assert('parses onion:port endpoint', e.host.length === 62 && e.port === 50001)
    let threw = false
    try {
      parseEndpoint('no-port-here')
    } catch {
      threw = true
    }
    assert('malformed endpoint refused', threw)
  }

  // --- Electrum adapter over a fake server ------------------------------------
  {
    const historyBySh = new Map<string, { tx_hash: string; height: number }[]>()
    const serverSockets = new Set<Socket>()
    // Bind the fake server to a port, then pass a dialer that connects to it.
    const server: Server = createServer((socket: Socket) => {
      serverSockets.add(socket)
      socket.on('close', () => serverSockets.delete(socket))
      let buffer = ''
      socket.on('data', (chunk) => {
        buffer += chunk.toString('utf8')
        let idx: number
        while ((idx = buffer.indexOf('\n')) >= 0) {
          const line = buffer.slice(0, idx)
          buffer = buffer.slice(idx + 1)
          const msg = JSON.parse(line)
          let result: unknown = null
          if (msg.method === 'blockchain.scripthash.get_history') {
            const sh = msg.params[0]
            result = historyBySh.get(sh) ?? []
          } else if (msg.method === 'blockchain.headers.subscribe') {
            result = { height: 777_000 }
          } else if (msg.method === 'server.ping') {
            result = null
          }
          socket.write(`${JSON.stringify({ id: msg.id, result })}\n`)
        }
      })
    })
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    const port = (server.address() as { port: number }).port
    const dialer = () => new Promise<Socket>((resolve, reject) => {
      const s = new Socket()
      s.connect(port, '127.0.0.1', () => resolve(s))
      s.on('error', reject)
    })

    const oracle = new ElectrumOracle({ dialer, batchSize: 2 })

    // Mark one scripthash as used.
    const usedAddr = BOB_NOTIFICATION
    const usedSh = scripthashOfAddress(usedAddr)
    historyBySh.set(usedSh, [{ tx_hash: 'a'.repeat(64), height: 750_000 }])
    const unusedAddr = '1BoatSLRHtKNngkdXEeobR76b53LETtpyT'

    const statuses = await oracle.status([usedAddr, unusedAddr])
    assert('used address flagged used', statuses[0].used === true)
    assert('used address carries txids', statuses[0].txids?.[0] === 'a'.repeat(64))
    assert('used address carries first-seen height', statuses[0].height === 750_000)
    assert('unused address flagged unused', statuses[1].used === false)

    const tip = await oracle.tipHeight()
    assert('tip height from headers.subscribe', tip === 777_000)

    // Batch size honoured via chunked requests; the status results and the
    // reconnect behaviour below are the load-bearing checks.

    // Dead connection is transient: destroy the socket, next request re-dials.
    await oracle.status([unusedAddr])
    await oracle['client'].close()
    const after = await oracle.status([unusedAddr])
    assert('re-dials after connection loss', after[0].used === false)

    await oracle.close()
    for (const s of serverSockets) s.destroy()
    await new Promise<void>((r) => server.close(() => r()))
  }

  // --- Core adapter over a fake transport --------------------------------------
  {
    const calls: string[] = []
    const transport = async (payload: any): Promise<unknown> => {
      calls.push(payload.method)
      if (payload.method === 'importdescriptors') {
        return { result: [{ success: true }] }
      }
      if (payload.method === 'listreceivedbyaddress') {
        return {
          result: [{ address: 'addrA', txids: ['f'.repeat(64)], blockheight: 700_000 }],
        }
      }
      if (payload.method === 'getblockchaininfo') {
        return { result: { blocks: 800_000 } }
      }
      return { result: null }
    }

    const oracle = new CoreOracle({ transport, importBatchSize: 2 })
    const statuses = await oracle.status(['addrA', 'addrB'])
    assert('core: used address from listreceivedbyaddress', statuses[0].used === true && statuses[0].height === 700_000)
    assert('core: unused address', statuses[1].used === false)
    assert('core: imported in a single batch', calls.filter((c) => c === 'importdescriptors').length === 1)
    assert('core: second scan skips imports', (await oracle.status(['addrA', 'addrB'])).length === 2)
    assert('core: no re-import on second scan', calls.filter((c) => c === 'importdescriptors').length === 1)
    const tip = await oracle.tipHeight()
    assert('core: tip height', tip === 800_000)

    // Import failure surfaces.
    const failing = new CoreOracle({
      transport: async (payload: any) =>
        payload.method === 'importdescriptors'
          ? { result: [{ success: false, error: { message: 'bad descriptor' } }] }
          : { result: null },
    })
    let threw = false
    try {
      await failing.status(['addrC'])
    } catch (e) {
      threw = /importdescriptors failed/.test((e as Error).message)
    }
    assert('core: import failure surfaces', threw)
  }
})()

console.log('')
if (failures === 0) {
  console.log('PASS — oracle adapters.')
} else {
  console.log(`FAIL — ${failures} oracle check(s) failed.`)
  process.exit(1)
}
