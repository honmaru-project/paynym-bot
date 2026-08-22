// Regression tests for the two §4 defects (implementation handoff).
//
// A2 (§4.1): two senders register back-to-back against one online receiver with
//   NO intervening publish tick. Both must succeed — the first sender's read of
//   the rendezvous key must not consume it. Fails against the pre-fix code,
//   which used waitAndRemove on a deliberately long-lived broadcast entry.
//
// A3 (§4.2): a crash between accepting a registration and removing its inbox
//   entry must lose nothing. We inject a throw inside `onAccepted`; the entry
//   must survive in the inbox, and a "restart" (fresh Registrar + Registry from
//   the same state) must re-ingest it and finally remove it.
//
// Plus: the persisted box-key case from §10.2 — a sender that fetched the
//   rendezvous key, then restarts the daemon with the SAME box keypair, must
//   still be able to decrypt when the envelope is finally posted.

import { PaynymIdentity } from '../src/identity.ts'
import { SorobanRPC, BoxKeypair } from '../src/soroban.ts'
import {
  Registrar,
  Registry,
  registerWithReceiver,
  buildRegisterEnvelope,
  rendezvousName,
  inboxName,
} from '../src/register.ts'
import { memoryNode } from './memory-node.ts'

const fromHex = (h: string) => Uint8Array.from(Buffer.from(h, 'hex'))

// Same fixture seeds as the protocol test.
const ALICE_SEED = fromHex(
  '64dca76abc9c6f0cf3d212d248c380c4622c8f93b2c425ec6a5567fd5db57e10d3e6f94a2f6af4ac2edb8998072aad92098db73558c323777abf5bd1082d970a',
)
const BOB_SEED = fromHex(
  '87eaaac5a539ab028df44d9110defbef3797ddb805ca309f61a69ff96dbaa7ab5b24038cf029edec5235d933110f0aea8aeecf939ed14fc20730bba71e4b1110',
)
const CAROL_SEED = fromHex('02'.repeat(32))

let failures = 0
function assert(name: string, cond: boolean): void {
  if (!cond) failures++
  console.log(`${cond ? 'ok  ' : 'FAIL'}  ${name}`)
}

await (async () => {
  // --- A2: two senders, one publish, no intervening publish tick ------------
  {
    const node = memoryNode()
    const rpc = new SorobanRPC(node.transport)
    const bob = PaynymIdentity.fromSeed(BOB_SEED)
    const alice = PaynymIdentity.fromSeed(ALICE_SEED)
    const carol = PaynymIdentity.fromSeed(CAROL_SEED)
    const registrar = new Registrar(bob, BoxKeypair.generate(), new Registry())

    await registrar.publishRendezvous(rpc)

    // Sender A registers, then sender B registers. With the §4.1 fix the
    // rendezvous key is still there for B (no intervening publish tick).
    const aPosted = await registerWithReceiver(rpc, alice, bob.paymentCode())
    const bPosted = await registerWithReceiver(rpc, carol, bob.paymentCode())
    assert('A2: both senders posted', aPosted && bPosted)

    const added = await registrar.poll(rpc)
    assert('A2: both senders registered', added.length === 2)
    assert('A2: alice in registry', registrar.registry.has(alice.paymentCode()))
    assert('A2: carol in registry', registrar.registry.has(carol.paymentCode()))

    // The rendezvous key must still be published (non-destructive read).
    const rv = node.live(rendezvousName(bob.paymentCode()))
    assert('A2: rendezvous key survives reads', rv.length === 1)
  }

  // --- A3: crash between accept and remove ----------------------------------
  {
    const node = memoryNode()
    const rpc = new SorobanRPC(node.transport)
    const bob = PaynymIdentity.fromSeed(BOB_SEED)
    const alice = PaynymIdentity.fromSeed(ALICE_SEED)
    const box = BoxKeypair.generate() // persisted box key, survives "restart"
    const inbox = inboxName(bob.paymentCode())

    const registrar = new Registrar(bob, box, new Registry())
    await registrar.publishRendezvous(rpc)
    await registerWithReceiver(rpc, alice, bob.paymentCode())

    // First poll: onAccepted throws (e.g. state write failed). The exception
    // must propagate and the inbox entry must stay put.
    let threw = false
    try {
      await registrar.poll(rpc, {
        onAccepted: async () => {
          throw new Error('disk full')
        },
      })
    } catch {
      threw = true
    }
    assert('A3: onAccepted failure propagates', threw)
    assert('A3: inbox entry survives the crash', node.live(inbox).length === 1)

    // "Restart": fresh Registrar and fresh Registry from the same state
    // directory (nothing was persisted, because onAccepted threw). The entry
    // is re-ingested, registered, and finally removed.
    const restarted = new Registrar(bob, box, new Registry())
    const added = await restarted.poll(rpc)
    assert('A3: registration picked up on restart', added.length === 1 && added[0] === alice.paymentCode())
    assert('A3: inbox entry finally removed', node.live(inbox).length === 0)

    // Re-ingestion is idempotent: a re-poll registers nothing new.
    const again = await restarted.poll(rpc)
    assert('A3: re-poll registers nothing new', again.length === 0)
  }

  // --- Persisted box key: in-flight senders survive restarts ---------------
  {
    const node = memoryNode()
    const rpc = new SorobanRPC(node.transport)
    const bob = PaynymIdentity.fromSeed(BOB_SEED)
    const alice = PaynymIdentity.fromSeed(ALICE_SEED)
    const box = BoxKeypair.generate()

    const registrar = new Registrar(bob, box, new Registry())
    await registrar.publishRendezvous(rpc)

    // Sender fetches the rendezvous key, then takes a while to post its
    // envelope (simulated: daemon "restarts" in between).
    const entries = await rpc.list(rendezvousName(bob.paymentCode()))
    const receiverBoxHex = entries[entries.length - 1]
    const senderBox = BoxKeypair.generate()
    const sealed = `${senderBox.publicKeyHex()}:${senderBox.encrypt(
      JSON.stringify(buildRegisterEnvelope(alice)),
      fromHex(receiverBoxHex),
    )}`

    // Restart with the SAME box keypair; the envelope must still decrypt.
    const restarted = new Registrar(bob, box, new Registry())
    await rpc.add(inboxName(bob.paymentCode()), sealed, 'long')
    const added = await restarted.poll(rpc)
    assert('persisted box key decrypts in-flight registration', added.length === 1 && added[0] === alice.paymentCode())
  }
})()

console.log('')
if (failures === 0) {
  console.log('PASS — §4 regression tests (A2, A3, persisted box key).')
} else {
  console.log(`FAIL — ${failures} regression check(s) failed.`)
  process.exit(1)
}
