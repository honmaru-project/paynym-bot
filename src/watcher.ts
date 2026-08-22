// Turn the registry into the concrete set of addresses to watch.
//
// For each registered sender we watch a window of receive addresses starting at
// the sender's cursor (nextIndex) up to a gap limit. When an address is seen
// funded, credit it and advance the cursor. Address lookup is pluggable so this
// stays independent of how you talk to your own indexer (electrs, Bitcoin Core
// scantxoutset, etc.). Point it only at YOUR node over Tor — never a public
// explorer, since the watch list is your counterparty graph.

import type { PaynymIdentity } from './identity.ts'
import type { Registry } from './register.ts'

export const DEFAULT_GAP = 5
export const DEFAULT_TRAILING = 0

export type WatchAddress = {
  paymentCode: string
  index: number
  address: string
}

/**
 * Build the current watch window across all registered senders.
 *
 * Window is [max(0, nextIndex - trailingWindow), nextIndex + gap). The
 * trailing window exists so a sender that skipped or reused an index (or whose
 * transaction was abandoned before broadcast) is still seen — watching a
 * little history costs one cheap oracle query. `trailingWindow` defaults to 0
 * to preserve the historical single-purpose signature; the daemon passes its
 * configured value.
 */
export function watchWindow(
  identity: PaynymIdentity,
  registry: Registry,
  gap = DEFAULT_GAP,
  trailingWindow = DEFAULT_TRAILING,
): WatchAddress[] {
  const out: WatchAddress[] = []
  for (const rec of registry.all()) {
    const from = Math.max(0, rec.nextIndex - trailingWindow)
    for (let i = from; i < rec.nextIndex + gap; i++) {
      out.push({ paymentCode: rec.paymentCode, index: i, address: identity.receiveAddress(rec.paymentCode, i) })
    }
  }
  return out
}

/**
 * Used-address oracle contract. Implementations query ONLY the
 * operator's own node over Tor — the watch set is the complete counterparty
 * graph and must never reach a public explorer. Batch status so one slow
 * round trip serves a whole window.
 */
export type AddressStatus = {
  address: string
  used: boolean
  txids?: string[]
  height?: number // first-seen height, for confirmation counting
}

export interface UsedAddressOracle {
  status(addresses: string[]): Promise<AddressStatus[]>
  tipHeight?(): Promise<number>
}

/** A funded-address oracle backed by your own node. Returns true if used. */
export type UsedChecker = (address: string) => Promise<boolean>

export type Credit = WatchAddress & { spendKey: string }

/**
 * Scan the watch window once, crediting any used addresses and advancing
 * cursors so the window slides forward. Returns the credits found this pass.
 *
 * Legacy single-address adapter over the batch oracle; the daemon's scanTick
 * drives the batch interface directly.
 */
export async function scanOnce(
  identity: PaynymIdentity,
  registry: Registry,
  isUsed: UsedChecker,
  gap = DEFAULT_GAP,
): Promise<Credit[]> {
  const credits: Credit[] = []
  for (const w of watchWindow(identity, registry, gap)) {
    if (await isUsed(w.address)) {
      credits.push({ ...w, spendKey: identity.receivePrivateKey(w.paymentCode, w.index) })
      registry.advance(w.paymentCode, w.index)
    }
  }
  return credits
}
