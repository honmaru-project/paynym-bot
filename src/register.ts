// Notification-less BIP47 registration over Soroban.
//
// The BIP47 notification transaction does two jobs, both pure transport:
//   1. deliver the sender's payment code to the receiver, and
//   2. blind it so chain observers can't read it.
// This module does both off-chain: the sender hands their payment code to the
// receiver inside a Soroban message that is encrypted to the receiver's box key
// (job 2) and delivered to a directory derived from the receiver's payment code
// (job 1). No on-chain OP_RETURN is broadcast.
//
// Authentication note (the correction to the "Soroban self-authenticates"
// assumption): a Soroban channel is keyed with EPHEMERAL Curve25519 box keys,
// not the BIP47 secp256k1 payment-code keys, so decrypting a message proves
// nothing about payment-code control. We therefore make the sender SIGN the
// registration with the payment code's own identity key (secp256k1 child-0),
// and the receiver verifies that signature against the pubkey embedded in the
// submitted payment code. That is what actually binds "this message" to "the
// holder of this payment code".

import { nodeFromPaymentCode } from './bip47.ts'
import { PaynymIdentity, verifyIdentitySignature } from './identity.ts'
import { SorobanRPC, BoxKeypair, encodeDirectory, hex, unhex } from './soroban.ts'
import type { ConfidentialAuth, Mode } from './soroban.ts'

export const PROTOCOL = 'paynym.register'
export const PROTOCOL_VERSION = 1

// Replay window for a registration envelope.
const MAX_SKEW_MS = 6 * 60 * 60 * 1000 // 6 hours

export type RegisterEnvelope = {
  v: number
  type: string
  paymentCode: string
  ts: number
  sig: string // secp256k1 DER hex over sha256(signedMessage)
}

function signedMessage(paymentCode: string, ts: number): Uint8Array {
  return new TextEncoder().encode(`${PROTOCOL}|${paymentCode}|${ts}`)
}

/** Identity pubkey (hex) that must have signed a registration for `paymentCode`. */
function identityKeyOf(paymentCode: string): string {
  return hex(nodeFromPaymentCode(paymentCode).deriveChild(0).publicKey!)
}

/** Sender: build a signed registration envelope disclosing our payment code. */
export function buildRegisterEnvelope(sender: PaynymIdentity, ts = Date.now()): RegisterEnvelope {
  const paymentCode = sender.paymentCode()
  return {
    v: PROTOCOL_VERSION,
    type: PROTOCOL,
    paymentCode,
    ts,
    sig: sender.signIdentity(signedMessage(paymentCode, ts)),
  }
}

/** Receiver: validate an envelope. Returns the payment code, or null if invalid. */
export function verifyRegisterEnvelope(env: RegisterEnvelope, now = Date.now()): string | null {
  if (!env || env.type !== PROTOCOL || env.v !== PROTOCOL_VERSION) return null
  if (typeof env.paymentCode !== 'string' || typeof env.sig !== 'string') return null
  if (typeof env.ts !== 'number' || Math.abs(now - env.ts) > MAX_SKEW_MS) return null
  let identityKey: string
  try {
    identityKey = identityKeyOf(env.paymentCode)
  } catch {
    return null
  }
  const ok = verifyIdentitySignature(identityKey, signedMessage(env.paymentCode, env.ts), env.sig)
  return ok ? env.paymentCode : null
}

// --- Directory addressing ---------------------------------------------------
//
// Two schemes. `plain` works on any public node (contents are box-encrypted so
// listers see only ciphertext). `confidential` additionally hides the queue
// itself behind the node's `soroban.register-queue.*` confidential prefix, so
// only the receiver (holding the configured ed25519 key) can even List it —
// this requires the node operator to add the receiver's key to confidential.yml.

export type Scheme = 'plain' | 'confidential'

export function rendezvousName(receiverPaymentCode: string, scheme: Scheme = 'plain'): string {
  if (scheme === 'confidential') {
    // Raw prefix so the node's regex can match; hashed id so the PC isn't leaked.
    return `soroban.register-queue.rv.${encodeDirectory(receiverPaymentCode)}`
  }
  return encodeDirectory(`${PROTOCOL}.rendezvous.${receiverPaymentCode}`)
}

export function inboxName(receiverPaymentCode: string, scheme: Scheme = 'plain'): string {
  if (scheme === 'confidential') {
    return `soroban.register-queue.in.${encodeDirectory(receiverPaymentCode)}`
  }
  return encodeDirectory(`${PROTOCOL}.inbox.${receiverPaymentCode}`)
}

// --- Registry ---------------------------------------------------------------

export type SenderRecord = {
  paymentCode: string
  label?: string
  firstSeen: number
  nextIndex: number // next receive index we expect to be unused
}

/**
 * The set of senders that have registered with us. This is key material: the
 * receive keys cannot be re-derived from the seed alone without these payment
 * codes. Persist it (toJSON / fromJSON) alongside the seed.
 */
export class Registry {
  private records = new Map<string, SenderRecord>()

  has(paymentCode: string): boolean {
    return this.records.has(paymentCode)
  }
  get(paymentCode: string): SenderRecord | undefined {
    return this.records.get(paymentCode)
  }
  all(): SenderRecord[] {
    return [...this.records.values()]
  }
  /** Add a sender if new. Returns true if this was a new registration. */
  add(paymentCode: string, label?: string, now = Date.now()): boolean {
    if (this.records.has(paymentCode)) return false
    this.records.set(paymentCode, { paymentCode, label, firstSeen: now, nextIndex: 0 })
    return true
  }
  /** Advance a sender's cursor after crediting a payment at `index`. */
  advance(paymentCode: string, usedIndex: number): void {
    const rec = this.records.get(paymentCode)
    if (rec && usedIndex >= rec.nextIndex) rec.nextIndex = usedIndex + 1
  }

  toJSON(): SenderRecord[] {
    return this.all()
  }
  static fromJSON(records: SenderRecord[]): Registry {
    const r = new Registry()
    for (const rec of records) r.records.set(rec.paymentCode, rec)
    return r
  }
}

// --- Sender side ------------------------------------------------------------

/**
 * Register our payment code with a receiver so they can watch for our payments,
 * with no notification transaction. Fetches the receiver's rendezvous box key,
 * encrypts a signed envelope to it, and posts it to the receiver's inbox.
 * Returns true if the inbox Add succeeded.
 */
export async function registerWithReceiver(
  rpc: SorobanRPC,
  sender: PaynymIdentity,
  receiverPaymentCode: string,
  opts: { scheme?: Scheme; mode?: Mode; tries?: number } = {},
): Promise<boolean> {
  const scheme = opts.scheme ?? 'plain'
  const box = BoxKeypair.generate()

  const receiverBoxHex = await rpc.waitAndRemove(rendezvousName(receiverPaymentCode, scheme), {
    tries: opts.tries ?? 25,
  })
  if (!receiverBoxHex) throw new Error('receiver rendezvous key not found (is the receiver online?)')

  const envelope = JSON.stringify(buildRegisterEnvelope(sender))
  // Prepend our ephemeral box pubkey so the receiver can open the box.
  const sealed = `${box.publicKeyHex()}:${box.encrypt(envelope, unhex(receiverBoxHex))}`
  return rpc.add(inboxName(receiverPaymentCode, scheme), sealed, opts.mode ?? 'long')
}

// --- Receiver side ----------------------------------------------------------

/**
 * The always-online receiver. Holds a persistent box keypair (for decrypting
 * inbound envelopes) and the sender registry. Call publishRendezvous() on a
 * timer so senders can always find our box key, and poll() to intake pending
 * registrations.
 */
export class Registrar {
  readonly identity: PaynymIdentity
  readonly registry: Registry
  private readonly box: BoxKeypair
  private readonly scheme: Scheme
  private readonly auth?: ConfidentialAuth

  constructor(
    identity: PaynymIdentity,
    box: BoxKeypair,
    registry: Registry = new Registry(),
    opts: { scheme?: Scheme; auth?: ConfidentialAuth } = {},
  ) {
    this.identity = identity
    this.box = box
    this.registry = registry
    this.scheme = opts.scheme ?? 'plain'
    if (this.scheme === 'confidential' && !opts.auth) {
      throw new Error('confidential scheme requires a ConfidentialAuth (node ed25519 key)')
    }
    this.auth = opts.auth
  }

  boxPublicKeyHex(): string {
    return this.box.publicKeyHex()
  }

  /** Re-publish our rendezvous box key. Call on a timer (Soroban TTL <= 15m). */
  async publishRendezvous(rpc: SorobanRPC, mode: Mode = 'long'): Promise<boolean> {
    return rpc.add(rendezvousName(this.identity.paymentCode(), this.scheme), this.box.publicKeyHex(), mode)
  }

  /**
   * Drain the inbox: decrypt, verify signatures, register new senders.
   * Returns the payment codes newly added to the registry this call.
   */
  async poll(rpc: SorobanRPC, opts: { tries?: number } = {}): Promise<string[]> {
    const name = inboxName(this.identity.paymentCode(), this.scheme)
    const entries = await rpc.list(name, this.auth)
    const added: string[] = []
    for (const entry of entries) {
      const paymentCode = this.ingest(entry)
      if (paymentCode && this.registry.add(paymentCode)) added.push(paymentCode)
      // Always remove processed entries so the queue stays small.
      await rpc.remove(name, entry)
    }
    return added
  }

  /** Decrypt + verify a single sealed inbox entry. Returns the payment code or null. */
  ingest(sealed: string): string | null {
    const sep = sealed.indexOf(':')
    if (sep < 0) return null
    const senderBoxHex = sealed.slice(0, sep)
    const ciphertext = sealed.slice(sep + 1)
    let plaintext: string | null
    try {
      plaintext = this.box.decrypt(ciphertext, unhex(senderBoxHex))
    } catch {
      return null
    }
    if (!plaintext) return null
    let env: RegisterEnvelope
    try {
      env = JSON.parse(plaintext)
    } catch {
      return null
    }
    return verifyRegisterEnvelope(env)
  }
}
