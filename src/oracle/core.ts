// Alternative used-address oracle over Bitcoin Core's RPC, same interface as
// the Electrum adapter.
//
// For operators who run Core but not electrs: the watch set is imported into a
// dedicated watch-only wallet as addr(...) descriptors (importdescriptors),
// then read back with listreceivedbyaddress. New addresses require a fresh
// import; we keep timestamp: 'now' so a gap extension never triggers a full
// rescan. Tradeoff versus electrs: no extra indexer to run, but imports and
// rescans make it materially slower to notice a payment.
//
// The endpoint is the operator's OWN Core node over Tor. The watch set is the
// complete counterparty graph; it must never reach a public node.

import type { RpcTransport } from '../soroban.ts'
import type { AddressStatus, UsedAddressOracle } from '../watcher.ts'

export type CoreOptions = {
  /** RPC transport (torTransport over the onion endpoint with auth header). */
  transport: RpcTransport
  /** Keep imports modest so one bad descriptor does not cost a rescan. */
  importBatchSize?: number
}

type ListReceivedByAddressEntry = {
  address: string
  txids?: string[]
  blockheight?: number
  confirmations?: number
}

export class CoreOracle implements UsedAddressOracle {
  private readonly transport: RpcTransport
  private readonly importBatchSize: number
  private imported = new Set<string>()

  constructor(opts: CoreOptions) {
    this.transport = opts.transport
    this.importBatchSize = opts.importBatchSize ?? 50
  }

  async status(addresses: string[]): Promise<AddressStatus[]> {
    await this.importMissing(addresses)
    const received = await this.listReceivedByAddress()

    // listreceivedbyaddress returns entries for addresses that have received
    // at least once; everything else is unused.
    const byAddress = new Map(received.map((r) => [r.address, r]))
    return addresses.map((address) => {
      const entry = byAddress.get(address)
      const used = entry !== undefined && (entry.txids?.length ?? 0) > 0
      return {
        address,
        used,
        txids: used ? entry?.txids : undefined,
        height: entry?.blockheight,
      }
    })
  }

  async tipHeight(): Promise<number> {
    const info = (await this.call('getblockchaininfo')) as { blocks?: number } | undefined
    return typeof info?.blocks === 'number' ? info.blocks : 0
  }

  private async importMissing(addresses: string[]): Promise<void> {
    const fresh = addresses.filter((a) => !this.imported.has(a))
    for (let i = 0; i < fresh.length; i += this.importBatchSize) {
      const batch = fresh.slice(i, i + this.importBatchSize)
      const descriptors = batch.map((address) => ({
        desc: `addr(${address})`,
        timestamp: 'now', // never rescan history; only future payments matter
        watchonly: true,
        label: 'paynymd',
      }))
      const result = (await this.call('importdescriptors', [descriptors])) as
        | { success?: boolean; error?: { message?: string } }[]
        | undefined
      if (Array.isArray(result)) {
        for (let j = 0; j < result.length; j++) {
          const r = result[j]
          if (!r?.success) {
            // A failed import must not silently drop the address from the
            // watch set — surface it. Re-importing an existing descriptor is
            // normally a no-op in Core, so failures here are unexpected.
            throw new Error(
              `core importdescriptors failed for ${batch[j]}: ${r?.error?.message ?? 'unknown error'}`,
            )
          }
        }
      }
      // Mark even failed ones as attempted: the next scan retries them because
      // we throw before reaching this line on failure.
      for (const a of batch) this.imported.add(a)
    }
  }

  private async listReceivedByAddress(): Promise<ListReceivedByAddressEntry[]> {
    const result = (await this.call('listreceivedbyaddress', [0, true])) as
      | ListReceivedByAddressEntry[]
      | undefined
    return Array.isArray(result) ? result : []
  }

  private async call(method: string, params: unknown[] = []): Promise<unknown> {
    const resp = (await this.transport({
      jsonrpc: '1.0',
      id: 'paynymd',
      method,
      params,
    })) as { result?: unknown; error?: { message?: string } }
    if (resp.error) throw new Error(`core ${method}: ${resp.error.message ?? JSON.stringify(resp.error)}`)
    return resp.result
  }
}
