// Stream isolation for Tor.
//
// Tor's IsolateSOCKSAuth is on by default: connections presenting different
// SOCKS username/password pairs travel over different circuits. We use that to
// (1) keep the Soroban stream and the oracle stream on separate circuits, so an
// exit-side observer cannot correlate "who registered" with "which addresses
// were then queried" — the two streams together would leak exactly the link the
// notification-less design exists to hide — and (2) rotate the Soroban
// credential on a timer and on hard transport errors, so a long-lived daemon
// is not one long-lived circuit.

import { randomBytes } from 'node:crypto'

export type StreamLabel = 'soroban' | 'oracle'

export type SocksCredentials = {
  username: string
  password: string
}

function generateCredentials(): SocksCredentials {
  // Unpredictable, but NOT secret material (they travel in cleartext to the
  // local Tor daemon). They must never be derived from any payment code.
  return {
    username: randomBytes(8).toString('hex'),
    password: randomBytes(8).toString('hex'),
  }
}

/**
 * Owns the SOCKS credentials for each stream. Rotation swaps the credential
 * the NEXT connection presents; it never affects an in-flight request.
 */
export class CircuitManager {
  private readonly rotateMs: number
  private readonly creds: Record<StreamLabel, SocksCredentials>
  private lastRotate = Date.now()

  constructor(rotateMs = 900_000) {
    this.rotateMs = rotateMs
    this.creds = {
      soroban: generateCredentials(),
      oracle: generateCredentials(),
    }
  }

  credentials(label: StreamLabel): SocksCredentials {
    return this.creds[label]
  }

  /** Rotate one stream's credential immediately (e.g. after a hard error). */
  rotate(label: StreamLabel): void {
    this.creds[label] = generateCredentials()
  }

  /** Rotate the Soroban credential once the rotation interval has elapsed. */
  maybeRotate(now = Date.now()): void {
    if (now - this.lastRotate >= this.rotateMs) {
      this.creds.soroban = generateCredentials()
      this.lastRotate = now
    }
  }

  get nextRotationAt(): number {
    return this.lastRotate + this.rotateMs
  }
}
