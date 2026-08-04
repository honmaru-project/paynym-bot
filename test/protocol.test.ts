// Offline end-to-end test of the notification-less registration protocol.
// Uses an in-memory Soroban node (implementing directory.Add/List/Remove) so
// the full sender -> Soroban -> receiver flow runs with no network. Run:
//   npm run protocol

import { PaynymIdentity } from '../src/identity.ts'
import { SorobanRPC, BoxKeypair } from '../src/soroban.ts'
import type { RpcTransport } from '../src/soroban.ts'
import {
  Registrar,
  Registry,
  registerWithReceiver,
  buildRegisterEnvelope,
} from '../src/register.ts'
import { watchWindow } from '../src/watcher.ts'

// --- In-memory Soroban node -------------------------------------------------
function memoryNode(): RpcTransport {
  const dirs = new Map<string, string[]>()
  return async (payload: any) => {
    const { method, params } = payload
    const a = params[0]
    if (method === 'directory.Add') {
      const list = dirs.get(a.Name) ?? []
      if (!list.includes(a.Entry)) list.push(a.Entry)
      dirs.set(a.Name, list)
      return { result: { Status: 'success' } }
    }
    if (method === 'directory.List') {
      return { result: { Name: a.Name, Entries: dirs.get(a.Name) ?? [] } }
    }
    if (method === 'directory.Remove') {
      const list = (dirs.get(a.Name) ?? []).filter((e) => e !== a.Entry)
      dirs.set(a.Name, list)
      return { result: { Status: 'success' } }
    }
    return { result: null }
  }
}

const fromHex = (h: string) => Uint8Array.from(Buffer.from(h, 'hex'))

let failures = 0
function assert(name: string, cond: boolean): void {
  if (!cond) failures++
  console.log(`${cond ? 'ok  ' : 'FAIL'}  ${name}`)
}

const ALICE_SEED = fromHex(
  '64dca76abc9c6f0cf3d212d248c380c4622c8f93b2c425ec6a5567fd5db57e10d3e6f94a2f6af4ac2edb8998072aad92098db73558c323777abf5bd1082d970a',
)
const BOB_SEED = fromHex(
  '87eaaac5a539ab028df44d9110defbef3797ddb805ca309f61a69ff96dbaa7ab5b24038cf029edec5235d933110f0aea8aeecf939ed14fc20730bba71e4b1110',
)

const rpc = new SorobanRPC(memoryNode())

// Bob is the always-online receiver; Alice is the sender.
const bob = PaynymIdentity.fromSeed(BOB_SEED)
const alice = PaynymIdentity.fromSeed(ALICE_SEED)

const registrar = new Registrar(bob, BoxKeypair.generate(), new Registry())

await (async () => {
  // Receiver comes online and publishes its rendezvous box key.
  await registrar.publishRendezvous(rpc)

  // Registry starts empty; nothing to watch.
  assert('registry empty before registration', registrar.registry.all().length === 0)

  // Sender registers with the receiver — no notification transaction.
  const posted = await registerWithReceiver(rpc, alice, bob.paymentCode())
  assert('sender posted registration', posted)

  // Receiver drains its inbox.
  const added = await registrar.poll(rpc)
  assert('receiver registered exactly one sender', added.length === 1)
  assert('registered code is alice', added[0] === alice.paymentCode())

  // The payoff: receiver's watch address == sender's pay address, from payment
  // codes alone. This is what makes the on-chain payment work with no notif tx.
  const window = watchWindow(bob, registrar.registry)
  let allMatch = window.length > 0
  for (const w of window) {
    if (alice.sendAddress(bob.paymentCode(), w.index) !== w.address) allMatch = false
  }
  assert('watch addresses == sender pay addresses', allMatch)

  // Polling again must not double-register (idempotent intake).
  const again = await registrar.poll(rpc)
  assert('re-poll registers nothing new', again.length === 0)

  // A forged envelope (valid JSON, signature over a DIFFERENT payment code) is
  // rejected: the signature must be by the submitted code's own identity key.
  const forged = buildRegisterEnvelope(alice)
  forged.paymentCode = bob.paymentCode() // claim Bob's code, keep Alice's signature
  const box = BoxKeypair.generate()
  const sealed = `${box.publicKeyHex()}:${box.encrypt(JSON.stringify(forged), fromHex(registrar.boxPublicKeyHex()))}`
  assert('forged registration rejected', registrar.ingest(sealed) === null)
})()

console.log('')
if (failures === 0) {
  console.log('PASS — notification-less registration works end-to-end.')
} else {
  console.log(`FAIL — ${failures} protocol check(s) failed.`)
  process.exit(1)
}
