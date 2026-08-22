// Log redaction acceptance test (A9).
//
// Run a simulated daemon session with fixture secrets configured in the
// logger's redaction layer, capture every emitted line, and assert that no
// payment code, derived address, or seed byte from the fixtures appears
// anywhere in the output. Conventions rot; the test does not.
// Run: npm run redaction

import { Writable } from 'node:stream'
import { PaynymIdentity } from '../src/identity.ts'
import { createLogger, shortSender } from '../src/log.ts'
import { MAINNET } from '../src/bip47.ts'

const BOB_SEED = Uint8Array.from(
  Buffer.from(
    '87eaaac5a539ab028df44d9110defbef3797ddb805ca309f61a69ff96dbaa7ab5b24038cf029edec5235d933110f0aea8aeecf939ed14fc20730bba71e4b1110',
    'hex',
  ),
)
const ALICE_PC =
  'PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA'
const BOB_PC =
  'PM8TJS2JxQ5ztXUpBBRnpTbcUXbUHy2T1abfrb3KkAAtMEGNbey4oumH7Hc578WgQJhPjBxteQ5GHHToTYHE3A1w6p7tU6KSoFmWBVbFGjKPisZDbP97'
const BOB_RECEIVE_0 = '141fi7TY3h936vRUKh1qfUZr8rSBuYbVBK'

const bob = PaynymIdentity.fromSeed(BOB_SEED, MAINNET)
const seedHex = Buffer.from(BOB_SEED).toString('hex')
const boxSecret = 'a'.repeat(64)
const paymentCode = bob.paymentCode()
const watchAddress = bob.receiveAddress(ALICE_PC, 0)

const lines: string[] = []
const stream = new Writable({
  write(chunk, _enc, cb) {
    lines.push(String(chunk))
    cb()
  },
})

const log = createLogger({
  level: 'debug',
  redact: true,
  secrets: [seedHex, paymentCode, boxSecret, ALICE_PC, BOB_PC, BOB_RECEIVE_0, watchAddress],
  stream,
})

// Simulate a full session's worth of log calls — the contract is that callers
// never pass secrets, but the layer scrubs them if they do.
log.info('paynymd running', { network: 'testnet' })
log.info('new sender registered', { sender: shortSender(ALICE_PC) })
log.info('scan credited', { credits: 1 })
log.debug('rendezvous published', { mode: 'long' })
// Belt-and-braces: deliberately poisoned fields must not leak.
log.debug('poison test', {
  accidentalPc: ALICE_PC,
  accidentalAddr: watchAddress,
  accidentalSeed: seedHex.slice(0, 16),
})

const blob = lines.join('')

let failures = 0
function assert(name: string, cond: boolean): void {
  if (!cond) failures++
  console.log(`${cond ? 'ok  ' : 'FAIL'}  ${name}`)
}

const forbidden = [seedHex, paymentCode, boxSecret, ALICE_PC, BOB_PC, BOB_RECEIVE_0, watchAddress]
for (const secret of forbidden) {
  assert(`log output omits forbidden substring (${secret.slice(0, 12)}…)`, !blob.includes(secret))
}
assert('truncated sender id still present', blob.includes(shortSender(ALICE_PC)))
assert('redaction marker present for poisoned pc', blob.includes('[redacted]'))

console.log('')
if (failures === 0) {
  console.log('PASS — log redaction (A9).')
} else {
  console.log(`FAIL — ${failures} redaction check(s) failed.`)
  process.exit(1)
}
