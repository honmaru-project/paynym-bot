// Configuration parsing and validation for paynymd.
//
// Config comes from a JSON file plus command-line overrides. Secrets never
// appear in the config file or in argv: the seed is referenced by path. The
// result of loadConfig() is a frozen, fully-defaulted object, so nothing
// downstream can mutate it. Contradictory configs are refused at startup, not
// at the first tick.

import { readFileSync, statSync } from 'node:fs'
import path from 'node:path'

export type Network = 'mainnet' | 'testnet'
export type PublishMode = 'fast' | 'short' | 'default' | 'normal' | 'long'
export type LogLevel = 'error' | 'warn' | 'info' | 'debug'

// Soroban entry TTL per mode, from the companion repo's internal/common/ttl.go.
// The node caps entries at 15 minutes; these are the per-mode values.
export const MODE_TTL_MS: Record<PublishMode, number> = {
  fast: 15_000,
  short: 60_000,
  default: 180_000,
  normal: 180_000,
  long: 300_000,
}

export type SorobanConfig = {
  url: string
  scheme: 'plain' | 'confidential'
  confidentialKeyFile?: string
  publishIntervalMs: number
  publishMode: PublishMode
  inboxIntervalMs: number
}

export type OracleConfig = {
  kind: 'electrum' | 'core'
  endpoint: string
  scanIntervalMs: number
  gapLimit: number
  trailingWindow: number
}

export type TorConfig = {
  socksHost: string
  socksPort: number
  requestTimeoutMs: number
  isolateStreams: boolean
  rotateCircuitMs: number
}

export type LogConfig = {
  level: LogLevel
  redact: boolean
}

export type Config = {
  network: Network
  seedFile: string
  stateDir: string
  allowClearnet: boolean
  soroban: SorobanConfig
  oracle: OracleConfig
  tor: TorConfig
  log: LogConfig
}

export const DEFAULTS: Config = {
  network: 'testnet',
  seedFile: '',
  stateDir: '',
  allowClearnet: false,
  soroban: {
    url: '',
    scheme: 'plain',
    publishIntervalMs: 120_000,
    publishMode: 'long',
    inboxIntervalMs: 60_000,
  },
  oracle: {
    kind: 'electrum',
    endpoint: '',
    scanIntervalMs: 300_000,
    gapLimit: 5,
    trailingWindow: 20,
  },
  tor: {
    socksHost: '127.0.0.1',
    socksPort: 9050, // NOT 9150 — that is Tor Browser's isolated proxy
    requestTimeoutMs: 60_000,
    isolateStreams: true,
    rotateCircuitMs: 900_000,
  },
  log: {
    level: 'info',
    redact: true,
  },
}

// Raw shape accepted from the config file and CLI overrides. Numbers and
// strings are validated in loadConfig; booleans may be strings ("true").
type RawConfig = {
  network?: string
  seedFile?: string
  stateDir?: string
  allowClearnet?: boolean | string
  soroban?: {
    url?: string
    scheme?: string
    confidentialKeyFile?: string
    publishIntervalMs?: number
    publishMode?: string
    inboxIntervalMs?: number
  }
  oracle?: {
    kind?: string
    endpoint?: string
    scanIntervalMs?: number
    gapLimit?: number
    trailingWindow?: number
  }
  tor?: {
    socksHost?: string
    socksPort?: number
    requestTimeoutMs?: number
    isolateStreams?: boolean | string
    rotateCircuitMs?: number
  }
  log?: { level?: string; redact?: boolean | string }
}

export class ConfigError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ConfigError'
  }
}

function asBool(v: boolean | string | undefined, fallback: boolean): boolean {
  if (v === undefined) return fallback
  if (typeof v === 'boolean') return v
  if (v === 'true') return true
  if (v === 'false') return false
  throw new ConfigError(`expected boolean, got "${v}"`)
}

function requireValue(v: string | undefined, key: string): string {
  if (!v || v.length === 0) throw new ConfigError(`missing required config: ${key}`)
  return v
}

/**
 * Parse and validate configuration, returning a frozen, fully-defaulted object.
 * `file` is a JSON config path; `overrides` are CLI-level fields applied last.
 */
export function loadConfig(file: string | undefined, overrides: RawConfig = {}): Config {
  const fromFile: RawConfig = file
    ? (JSON.parse(readFileSync(file, 'utf8')) as RawConfig)
    : {}
  const raw: RawConfig = deepMerge(fromFile, overrides)

  const network = normalizeNetwork(raw.network)
  const seedFile = requireValue(raw.seedFile, 'seedFile')
  const stateDir = requireValue(raw.stateDir, 'stateDir')
  const publishMode = normalizePublishMode(raw.soroban?.publishMode)
  const scheme = raw.soroban?.scheme === 'confidential' ? 'confidential' : 'plain'
  const url = requireValue(raw.soroban?.url, 'soroban.url')
  const allowClearnet = asBool(raw.allowClearnet, false)

  if (!allowClearnet) {
    // Fail closed: the daemon is Tor-only. The flag exists only for the local
    // integration test and must be accompanied by a prominent warning.
    const host = new URL(url).hostname
    if (!host.endsWith('.onion')) {
      throw new ConfigError(
        `soroban.url host "${host}" does not end in .onion; refusing to run over clearnet ` +
          `(pass --allow-clearnet only for the local integration test)`,
      )
    }
  }

  const publishIntervalMs = raw.soroban?.publishIntervalMs ?? DEFAULTS.soroban.publishIntervalMs
  const ttl = MODE_TTL_MS[publishMode]
  if (publishIntervalMs >= ttl) {
    throw new ConfigError(
      `soroban.publishIntervalMs (${publishIntervalMs}) must be strictly less than the ` +
        `${publishMode} TTL (${ttl}ms); a config that under-publishes is a config that silently ` +
        `stops receiving`,
    )
  }

  if (scheme === 'confidential') {
    const keyFile = raw.soroban?.confidentialKeyFile
    if (!keyFile) {
      throw new ConfigError('scheme "confidential" requires soroban.confidentialKeyFile')
    }
  }

  const config: Config = {
    network,
    seedFile,
    stateDir,
    allowClearnet,
    soroban: {
      url,
      scheme,
      ...(raw.soroban?.confidentialKeyFile
        ? { confidentialKeyFile: raw.soroban.confidentialKeyFile }
        : {}),
      publishIntervalMs,
      publishMode,
      inboxIntervalMs: raw.soroban?.inboxIntervalMs ?? DEFAULTS.soroban.inboxIntervalMs,
    },
    oracle: {
      kind: raw.oracle?.kind === 'core' ? 'core' : 'electrum',
      endpoint: requireValue(raw.oracle?.endpoint, 'oracle.endpoint'),
      scanIntervalMs: raw.oracle?.scanIntervalMs ?? DEFAULTS.oracle.scanIntervalMs,
      gapLimit: raw.oracle?.gapLimit ?? DEFAULTS.oracle.gapLimit,
      trailingWindow: raw.oracle?.trailingWindow ?? DEFAULTS.oracle.trailingWindow,
    },
    tor: {
      socksHost: raw.tor?.socksHost ?? DEFAULTS.tor.socksHost,
      socksPort: raw.tor?.socksPort ?? DEFAULTS.tor.socksPort,
      requestTimeoutMs: raw.tor?.requestTimeoutMs ?? DEFAULTS.tor.requestTimeoutMs,
      isolateStreams: asBool(raw.tor?.isolateStreams, DEFAULTS.tor.isolateStreams),
      rotateCircuitMs: raw.tor?.rotateCircuitMs ?? DEFAULTS.tor.rotateCircuitMs,
    },
    log: {
      level: normalizeLogLevel(raw.log?.level),
      redact: asBool(raw.log?.redact, DEFAULTS.log.redact),
    },
  }

  return deepFreeze(config)
}

function normalizeNetwork(v: string | undefined): Network {
  if (v === undefined) return DEFAULTS.network // testnet stays the default
  if (v === 'testnet' || v === 'mainnet') return v
  throw new ConfigError(
    `invalid network "${v}"; mainnet must be an explicit, deliberate choice in the config file`,
  )
}

function normalizePublishMode(v: string | undefined): PublishMode {
  if (v === undefined) return DEFAULTS.soroban.publishMode
  if (v === 'fast' || v === 'short' || v === 'default' || v === 'normal' || v === 'long') return v
  throw new ConfigError(`invalid publishMode "${v}"`)
}

function normalizeLogLevel(v: string | undefined): LogLevel {
  if (v === undefined) return DEFAULTS.log.level
  if (v === 'error' || v === 'warn' || v === 'info' || v === 'debug') return v
  throw new ConfigError(`invalid log.level "${v}"`)
}

/**
 * Refuse to start on a world-readable seed or confidential key: both are
 * credentials. Modes are verified at startup, not just at creation.
 */
export function validateSecretFile(file: string, label: string): void {
  const st = statSync(file)
  if (st.mode & 0o077) {
    throw new ConfigError(`${label} "${file}" is group/world-readable (mode ${octal(st.mode)}); chmod 600`)
  }
  if (st.uid !== process.getuid?.()) {
    throw new ConfigError(`${label} "${file}" is not owned by the running user`)
  }
}

function octal(mode: number): string {
  return (mode & 0o777).toString(8)
}

export function deepFreeze<T>(o: T): T {
  if (o && typeof o === 'object') {
    for (const v of Object.values(o as Record<string, unknown>)) deepFreeze(v)
    Object.freeze(o)
  }
  return o
}

function deepMerge(a: RawConfig, b: RawConfig): RawConfig {
  const out: Record<string, unknown> = { ...a }
  for (const [k, v] of Object.entries(b)) {
    if (v !== undefined) out[k] = v
  }
  return out as RawConfig
}

/** Parse a seed file: hex string (64 chars) or a plain byte string. */
export function readSeedFile(seedFile: string): Uint8Array {
  const text = readFileSync(seedFile, 'utf8').trim()
  if (/^[0-9a-fA-F]{64}$/.test(text)) return Uint8Array.from(Buffer.from(text, 'hex'))
  if (/^[0-9a-fA-F]{128}$/.test(text)) return Uint8Array.from(Buffer.from(text, 'hex'))
  throw new ConfigError(
    `seed file "${path.basename(seedFile)}" is neither 32 bytes of hex nor a supported format`,
  )
}
