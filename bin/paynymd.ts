#!/usr/bin/env node
// paynymd — always-online BIP47 receiver daemon.
//
// Usage:
//   paynymd run --config ./paynymd.json
//   paynymd status --config ./paynymd.json
//   paynymd export --config ./paynymd.json --out backup.json
//   paynymd import --config ./paynymd.json --in backup.json
//   paynymd address --config ./paynymd.json --sender <paymentCode>
//
// The seed is read once at startup. Node cannot guarantee the bytes are zeroed
// afterward — mitigate at the process boundary (MemoryDenyWriteExecute, no
// swap, ProtectHome) rather than pretending otherwise in JavaScript.

import { connect } from 'node:net'
import { parseArgs } from 'node:util'
import { readFileSync, writeFileSync } from 'node:fs'
import { MAINNET, TESTNET } from '../src/bip47.ts'
import { PaynymIdentity } from '../src/identity.ts'
import { loadConfig, readSeedFile, validateSecretFile, ConfigError } from '../src/config.ts'
import { Daemon, StateMismatchError } from '../src/daemon.ts'
import { createLogger } from '../src/log.ts'
import { createOracle } from '../src/oracle/index.ts'
import { Registrar, Registry } from '../src/register.ts'
import { SorobanRPC, BoxKeypair, naclSigner, unhex } from '../src/soroban.ts'
import { StateStore, LockHeldError, STATE_VERSION } from '../src/store.ts'
import type { PersistedState } from '../src/store.ts'
import { CircuitManager } from '../src/transport/isolation.ts'
import { torTransport } from '../src/transport/tor.ts'

const EXIT_OK = 0
const EXIT_CONFIG = 2
const EXIT_LOCK = 3
const EXIT_MISMATCH = 4
const EXIT_TOR = 5
const EXIT_SIGNAL = 130

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    config: { type: 'string', short: 'c' },
    'allow-clearnet': { type: 'boolean', default: false },
    'show-payment-code': { type: 'boolean', default: false },
    out: { type: 'string' },
    in: { type: 'string' },
    sender: { type: 'string' },
  },
})

const sub = positionals[0]
if (!sub || !['run', 'status', 'export', 'import', 'address'].includes(sub)) {
  console.error('usage: paynymd <run|status|export|import|address> --config <file>')
  process.exit(EXIT_CONFIG)
}

let config
try {
  config = loadConfig(values.config, { allowClearnet: values['allow-clearnet'] ?? false })
} catch (e) {
  console.error((e as Error).message)
  process.exit(EXIT_CONFIG)
}

function networkOf() {
  return config.network === 'mainnet' ? MAINNET : TESTNET
}

function loadIdentity(): PaynymIdentity {
  validateSecretFile(config.seedFile, 'seedFile')
  const seed = readSeedFile(config.seedFile)
  return PaynymIdentity.fromSeed(seed, networkOf())
}

function loadStore(): StateStore {
  const store = new StateStore(config.stateDir)
  if (store.cleanStrayTmp()) {
    console.error(`removed stray ${config.stateDir}/state.json.tmp from an interrupted write`)
  }
  return store
}

function confidentialAuth() {
  if (config.soroban.scheme !== 'confidential') return undefined
  const keyFile = config.soroban.confidentialKeyFile!
  validateSecretFile(keyFile, 'soroban.confidentialKeyFile')
  return naclSigner(unhex(readFileSync(keyFile, 'utf8').trim()))
}

function buildRegistrar(identity: PaynymIdentity, state: PersistedState | null): {
  registrar: Registrar
  boxSecretHex: string
} {
  const registry = state ? Registry.fromJSON(state.registry) : new Registry()
  let box: BoxKeypair
  let boxSecretHex: string
  if (state?.boxSecretKey) {
    boxSecretHex = state.boxSecretKey
    box = BoxKeypair.fromSecretKey(unhex(boxSecretHex))
  } else {
    box = BoxKeypair.generate()
    boxSecretHex = Buffer.from(box.secretKey).toString('hex')
  }
  const registrar = new Registrar(identity, box, registry, {
    scheme: config.soroban.scheme,
    auth: confidentialAuth(),
  })
  return { registrar, boxSecretHex }
}

async function probeTor(): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const socket = connect({ host: config.tor.socksHost, port: config.tor.socksPort })
    const timer = setTimeout(() => {
      socket.destroy()
      reject(new Error('timeout'))
    }, 5_000)
    socket.once('connect', () => {
      clearTimeout(timer)
      socket.destroy()
      resolve()
    })
    socket.once('error', (e) => {
      clearTimeout(timer)
      reject(e)
    })
  })
}

async function cmdStatus(identity: PaynymIdentity, store: StateStore): Promise<void> {
  const state = store.load()
  if (!state) {
    console.log(JSON.stringify({ initialized: false, paymentCode: identity.paymentCode() }, null, 2))
    return
  }
  console.log(
    JSON.stringify(
      {
        initialized: true,
        network: state.network,
        senders: state.registry.length,
        registry: state.registry.map((r) => ({
          nextIndex: r.nextIndex,
          firstSeen: r.firstSeen,
          label: r.label,
        })),
        credits: state.credited.length,
        lastScanHeight: state.lastScanHeight ?? null,
      },
      null,
      2,
    ),
  )
}

async function cmdExport(identity: PaynymIdentity, store: StateStore): Promise<void> {
  const out = values.out
  if (!out) {
    console.error('export requires --out <file>')
    process.exit(EXIT_CONFIG)
  }
  const state = store.load()
  if (!state) {
    console.error('no state to export')
    process.exit(EXIT_CONFIG)
  }
  // Full-state backup: the registry is the load-bearing part, but the box
  // key (in-flight senders encrypted to it) and credit ledger must survive a
  // restore too. The file is a complete credential set — 0600, never logged.
  writeFileSync(out, JSON.stringify(state, null, 2), { mode: 0o600 })
  console.log(`exported ${state.registry.length} sender(s) and box key to ${out}`)
}

async function cmdImport(identity: PaynymIdentity, store: StateStore): Promise<void> {
  const input = values.in
  if (!input) {
    console.error('import requires --in <file>')
    process.exit(EXIT_CONFIG)
  }
  const backup = JSON.parse(readFileSync(input, 'utf8')) as Partial<PersistedState>
  if (!Array.isArray(backup.registry)) {
    console.error('backup file must contain a registry array')
    process.exit(EXIT_CONFIG)
  }
  if (backup.paymentCode && backup.paymentCode !== identity.paymentCode()) {
    console.error('backup payment code does not match the seed; import refused')
    process.exit(EXIT_MISMATCH)
  }
  const incoming = Registry.fromJSON(backup.registry)
  const existing = store.load()
  const { boxSecretHex } = buildRegistrar(identity, existing)
  const merged = existing ? Registry.fromJSON(existing.registry) : new Registry()
  let added = 0
  for (const rec of incoming.all()) {
    if (merged.add(rec.paymentCode, rec.label, rec.firstSeen)) added++
  }
  const state: PersistedState = existing ?? {
    version: STATE_VERSION,
    network: config.network,
    paymentCode: identity.paymentCode(),
    boxSecretKey: backup.boxSecretKey ?? boxSecretHex,
    registry: [],
    credited: backup.credited ?? [],
  }
  if (state.paymentCode !== identity.paymentCode()) {
    console.error('state payment code does not match seed; import refused')
    process.exit(EXIT_MISMATCH)
  }
  state.registry = merged.toJSON()
  store.save(state)
  console.log(`import merged ${added} new sender(s); ${merged.all().length} total`)
}

async function cmdAddress(identity: PaynymIdentity, store: StateStore): Promise<void> {
  const sender = values.sender
  if (!sender) {
    console.error('address requires --sender <paymentCode>')
    process.exit(EXIT_CONFIG)
  }
  const state = store.load()
  const rec = state?.registry.find((r) => r.paymentCode === sender)
  const index = rec?.nextIndex ?? 0
  console.log(identity.receiveAddress(sender, index))
}

async function cmdRun(identity: PaynymIdentity, store: StateStore): Promise<void> {
  if (values['show-payment-code']) {
    // stdout only — never through the logger.
    console.log(identity.paymentCode())
  }

  try {
    await probeTor()
  } catch {
    console.error(
      `Tor SOCKS proxy unreachable at ${config.tor.socksHost}:${config.tor.socksPort}; refusing to start`,
    )
    process.exit(EXIT_TOR)
  }

  const state = store.load()
  const { registrar, boxSecretHex } = buildRegistrar(identity, state)

  const seedBytes = readSeedFile(config.seedFile)
  const logger = createLogger({
    level: config.log.level,
    redact: config.log.redact,
    secrets: [
      Buffer.from(seedBytes).toString('hex'),
      identity.paymentCode(),
      boxSecretHex,
    ],
  })

  logger.info(
    'the seed alone is not a backup — back up state.json alongside it; the registry changes every time a new sender registers',
  )

  store.acquireLock((msg) => logger.warn(msg))

  const circuits = new CircuitManager(config.tor.rotateCircuitMs)
  const rpc = new SorobanRPC(
    torTransport(config.soroban.url, {
      socksHost: config.tor.socksHost,
      socksPort: config.tor.socksPort,
      requestTimeoutMs: config.tor.requestTimeoutMs,
      credentials: () => {
        circuits.maybeRotate()
        return circuits.credentials('soroban')
      },
    }),
  )
  const oracle = createOracle(config, circuits)

  let daemon: Daemon
  try {
    daemon = new Daemon({
      config,
      registrar,
      rpc,
      oracle,
      store,
      logger,
      boxSecretKeyHex: boxSecretHex,
    })
  } catch (e) {
    if (e instanceof StateMismatchError) {
      console.error(e.message)
      store.releaseLock()
      process.exit(EXIT_MISMATCH)
    }
    throw e
  }

  let signalCount = 0
  const onSignal = async () => {
    signalCount++
    if (signalCount > 1) {
      store.releaseLock()
      process.exit(EXIT_SIGNAL)
    }
    logger.info('shutting down')
    await daemon.stop()
    store.releaseLock()
    process.exit(EXIT_OK)
  }
  process.on('SIGINT', onSignal)
  process.on('SIGTERM', onSignal)

  daemon.start()
  logger.info('paynymd running', { network: config.network })
}

try {
  const identity = loadIdentity()
  const store = loadStore()

  if (sub === 'status') await cmdStatus(identity, store)
  else if (sub === 'export') await cmdExport(identity, store)
  else if (sub === 'import') await cmdImport(identity, store)
  else if (sub === 'address') await cmdAddress(identity, store)
  else await cmdRun(identity, store)
} catch (e) {
  if (e instanceof ConfigError) {
    console.error(e.message)
    process.exit(EXIT_CONFIG)
  }
  if (e instanceof LockHeldError) {
    console.error(e.message)
    process.exit(EXIT_LOCK)
  }
  throw e
}
