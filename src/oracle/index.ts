// Construct a used-address oracle from configuration.
//
// The endpoint is the operator's OWN node, reached over Tor. The watch set is
// a complete list of who pays this receiver and when; handing it to a public
// Electrum server or a block explorer would surrender exactly the privacy the
// notification-less design was built to gain.

import type { Config } from '../config.ts'
import { torTransport, socksConnect } from '../transport/tor.ts'
import type { CircuitManager } from '../transport/isolation.ts'
import type { UsedAddressOracle } from '../watcher.ts'
import { CoreOracle } from './core.ts'
import { ElectrumOracle } from './electrum.ts'

export type Oracle = UsedAddressOracle & { close?: () => Promise<void> }

export function createOracle(config: Config, circuits: CircuitManager): Oracle {
  const tunnel = {
    socksHost: config.tor.socksHost,
    socksPort: config.tor.socksPort,
    requestTimeoutMs: config.tor.requestTimeoutMs,
    // The oracle stream gets its own SOCKS credential so Soroban traffic and
    // chain queries never share a circuit.
    credentials: () => circuits.credentials('oracle'),
  }

  if (config.oracle.kind === 'core') {
    const url = new URL(config.oracle.endpoint)
    const auth =
      url.username || url.password
        ? `Basic ${Buffer.from(`${decodeURIComponent(url.username)}:${decodeURIComponent(url.password)}`).toString('base64')}`
        : undefined
    const transport = torTransport(config.oracle.endpoint, {
      ...tunnel,
      ...(auth ? { headers: { Authorization: auth } } : {}),
    })
    return new CoreOracle({ transport })
  }

  // Electrum endpoint is "<host>:<port>", a bare TCP target rather than a URL.
  const { host, port } = parseEndpoint(config.oracle.endpoint)
  return new ElectrumOracle({
    dialer: () => socksConnect(host, port, { ...tunnel, credentials: tunnel.credentials() }),
    batchSize: 50,
  })
}

export function parseEndpoint(endpoint: string): { host: string; port: number } {
  const idx = endpoint.lastIndexOf(':')
  if (idx < 0) throw new Error(`oracle endpoint "${endpoint}" must be host:port`)
  const host = endpoint.slice(0, idx)
  const port = Number(endpoint.slice(idx + 1))
  if (!host || !Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(`oracle endpoint "${endpoint}" must be host:port`)
  }
  return { host, port }
}
