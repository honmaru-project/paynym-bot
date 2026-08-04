// Live wiring example against a real Soroban node. This is illustrative, not a
// daemon: it runs one receiver poll loop and one sender registration in the same
// process so you can watch a notification-less registration happen over a real
// node.
//
// Usage:
//   node --experimental-strip-types example.ts --soroban http://<node>.onion/rpc
//
// Tor: Node's global fetch does not speak SOCKS. To reach a .onion node, pass a
// transport built on undici + socks-proxy-agent instead of SorobanRPC.forUrl,
// e.g.:
//
//   import { ProxyAgent } from 'undici'
//   const dispatcher = new ProxyAgent('socks5://127.0.0.1:9050') // needs a SOCKS-capable agent
//   const transport = async (payload) => (await fetch(url, { dispatcher, method:'POST', ... })).json()
//   const rpc = new SorobanRPC(transport)
//
// For a clearnet test node you can use SorobanRPC.forUrl(url) directly.

import { parseArgs } from 'node:util'
import { randomBytes } from 'node:crypto'
import { PaynymIdentity } from './src/identity.ts'
import { SorobanRPC, BoxKeypair } from './src/soroban.ts'
import { Registrar, Registry, registerWithReceiver } from './src/register.ts'
import { watchWindow } from './src/watcher.ts'

const { values } = parseArgs({
  options: { soroban: { type: 'string', short: 's' } },
})
const url = values.soroban
if (!url) {
  console.error('pass --soroban http://<node>/rpc')
  process.exit(1)
}

const rpc = SorobanRPC.forUrl(url)

// Fresh identities for the demo. In production the receiver's seed is fixed and
// backed up alongside its registry.
const receiver = PaynymIdentity.fromSeed(randomBytes(32))
const sender = PaynymIdentity.fromSeed(randomBytes(32))

const registrar = new Registrar(receiver, BoxKeypair.generate(), new Registry())

console.log('receiver payment code:', receiver.paymentCode())
console.log('publishing rendezvous...')
await registrar.publishRendezvous(rpc)

console.log('sender registering (no notification tx)...')
await registerWithReceiver(rpc, sender, receiver.paymentCode())

console.log('receiver polling inbox...')
const added = await registrar.poll(rpc)
console.log('newly registered senders:', added)

for (const w of watchWindow(receiver, registrar.registry)) {
  const match = sender.sendAddress(receiver.paymentCode(), w.index) === w.address
  console.log(`  watch[${w.index}] ${w.address}  sender-agrees=${match}`)
}
