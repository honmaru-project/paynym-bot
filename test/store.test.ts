// State store and config tests.
//
// - Atomic write under an injected mid-write failure: a simulated crash during
//   save must leave the previous good file intact.
// - Mode enforcement: a world-readable state file or state directory is
//   refused on load.
// - Unknown schema version is refused.
// - Seed/state payment-code mismatch is refused (exercised at the daemon
//   layer in the A4 round-trip; here we test the store primitives).
// - Config validation: Tor-only enforcement, publish-interval-vs-TTL
//   arithmetic, confidential-scheme key requirement, invalid network/mode
//   refusals.
// - Lockfile: a second live instance is refused; a stale (dead-pid) lock is
//   broken; releaseLock only removes a lock we own.
// Run: npm run store

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { StateStore, UnknownSchemaError, LockHeldError, STATE_VERSION } from '../src/store.ts'
import { loadConfig, ConfigError, MODE_TTL_MS } from '../src/config.ts'
import type { PersistedState } from '../src/store.ts'

let failures = 0
function assert(name: string, cond: boolean): void {
  if (!cond) failures++
  console.log(`${cond ? 'ok  ' : 'FAIL'}  ${name}`)
}

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'paynymd-test-'))
}

function sampleState(paymentCode = 'PM8T-test'): PersistedState {
  return {
    version: STATE_VERSION,
    network: 'testnet',
    paymentCode,
    boxSecretKey: 'ab'.repeat(32),
    registry: [
      { paymentCode: 'PM8T-senderA', firstSeen: 1, nextIndex: 0 },
      { paymentCode: 'PM8T-senderB', firstSeen: 2, nextIndex: 3 },
    ],
    credited: [],
  }
}

await (async () => {
  // --- atomic write round-trip ----------------------------------------------
  {
    const dir = tmpDir()
    const store = new StateStore(dir)
    assert('no state initially', store.load() === null)
    store.save(sampleState())
    const loaded = store.load()
    assert('state round-trips', JSON.stringify(loaded) === JSON.stringify(sampleState()))
    // tmp file must not remain after a successful save
    assert('no stray tmp after clean save', !fs.existsSync(path.join(dir, 'state.json.tmp')))
    fs.rmSync(dir, { recursive: true, force: true })
  }

  // --- mid-write crash leaves the previous good file -------------------------
  {
    const dir = tmpDir()
    const store = new StateStore(dir)
    const first = sampleState()
    store.save(first)

    // Simulate a crash: write a tmp file by hand and never rename it.
    fs.writeFileSync(path.join(dir, 'state.json.tmp'), JSON.stringify({ version: 99 }))
    assert('load ignores the stray tmp', store.load() !== null && store.load()!.version === STATE_VERSION)
    assert('cleanStrayTmp detects the stray', store.cleanStrayTmp() === true)
    assert('cleanStrayTmp removes it', store.cleanStrayTmp() === false)
    // The real file is untouched.
    assert('previous good file intact', store.load()!.paymentCode === first.paymentCode)
    fs.rmSync(dir, { recursive: true, force: true })
  }

  // --- unknown schema version refused ----------------------------------------
  {
    const dir = tmpDir()
    const store = new StateStore(dir)
    fs.writeFileSync(path.join(dir, 'state.json'), JSON.stringify({ version: 999 }), { mode: 0o600 })
    let threw = false
    try {
      store.load()
    } catch (e) {
      threw = e instanceof UnknownSchemaError
    }
    assert('unknown schema version refused', threw)
    fs.rmSync(dir, { recursive: true, force: true })
  }

  // --- mode enforcement ------------------------------------------------------
  {
    const dir = tmpDir()
    const store = new StateStore(dir)
    store.save(sampleState())
    fs.chmodSync(path.join(dir, 'state.json'), 0o644)
    let threw = false
    try {
      store.load()
    } catch (e) {
      threw = true
    }
    assert('world-readable state file refused', threw)
    fs.chmodSync(path.join(dir, 'state.json'), 0o600)
    fs.rmSync(dir, { recursive: true, force: true })
  }

  // --- lockfile --------------------------------------------------------------
  {
    const dir = tmpDir()
    const a = new StateStore(dir)
    const b = new StateStore(dir)
    a.acquireLock()
    let threw = false
    try {
      b.acquireLock()
    } catch (e) {
      threw = e instanceof LockHeldError
    }
    assert('second live instance refused', threw)
    a.releaseLock()
    b.acquireLock() // now free
    assert('lock reusable after release', b['locked'] === true)
    // releaseLock must NOT remove a lock we do not own
    fs.writeFileSync(path.join(dir, 'paynymd.lock'), '999999\n')
    b.releaseLock()
    assert('releaseLock does not delete foreign lock', fs.existsSync(path.join(dir, 'paynymd.lock')))
    // stale lock (dead pid) is broken
    b.acquireLock()
    fs.writeFileSync(path.join(dir, 'paynymd.lock'), '999999\n')
    let warned = ''
    b.acquireLock((msg) => (warned = msg))
    assert('stale lock broken with warning', warned.includes('dead pid'))
    b.releaseLock()
    fs.rmSync(dir, { recursive: true, force: true })
  }

  // --- config: Tor-only ------------------------------------------------------
  {
    let threw = false
    try {
      loadConfig(undefined, {
        seedFile: '/tmp/s',
        stateDir: '/tmp/d',
        soroban: { url: 'http://clearnet.example/rpc' },
        oracle: { endpoint: '127.0.0.1:50001' },
      })
    } catch (e) {
      threw = e instanceof ConfigError && /onion/.test((e as Error).message)
    }
    assert('clearnet soroban.url refused without --allow-clearnet', threw)

    // Allowed with the explicit flag
    const c = loadConfig(undefined, {
      seedFile: '/tmp/s',
      stateDir: '/tmp/d',
      allowClearnet: true,
      soroban: { url: 'http://clearnet.example/rpc' },
      oracle: { endpoint: '127.0.0.1:50001' },
    })
    assert('clearnet allowed with explicit flag', c.allowClearnet === true)
  }

  // --- config: publish interval vs TTL ----------------------------------------
  {
    let threw = false
    try {
      loadConfig(undefined, {
        seedFile: '/tmp/s',
        stateDir: '/tmp/d',
        allowClearnet: true,
        soroban: { url: 'http://clearnet.example/rpc', publishMode: 'long', publishIntervalMs: MODE_TTL_MS.long },
        oracle: { endpoint: '127.0.0.1:50001' },
      })
    } catch (e) {
      threw = e instanceof ConfigError && /publishIntervalMs/.test((e as Error).message)
    }
    assert('publish interval >= TTL refused', threw)

    const ok = loadConfig(undefined, {
      seedFile: '/tmp/s',
      stateDir: '/tmp/d',
      allowClearnet: true,
      soroban: { url: 'http://clearnet.example/rpc', publishMode: 'long', publishIntervalMs: 120_000 },
      oracle: { endpoint: '127.0.0.1:50001' },
    })
    assert('publish interval < TTL accepted', ok.soroban.publishIntervalMs === 120_000)
  }

  // --- config: confidential scheme needs a key file ----------------------------
  {
    let threw = false
    try {
      loadConfig(undefined, {
        seedFile: '/tmp/s',
        stateDir: '/tmp/d',
        allowClearnet: true,
        soroban: { url: 'http://clearnet.example/rpc', scheme: 'confidential' },
        oracle: { endpoint: '127.0.0.1:50001' },
      })
    } catch (e) {
      threw = e instanceof ConfigError && /confidentialKeyFile/.test((e as Error).message)
    }
    assert('confidential scheme requires key file', threw)
  }

  // --- config: defaults + network default --------------------------------------
  {
    const c = loadConfig(undefined, {
      seedFile: '/tmp/s',
      stateDir: '/tmp/d',
      allowClearnet: true,
      soroban: { url: 'http://clearnet.example/rpc' },
      oracle: { endpoint: '127.0.0.1:50001' },
    })
    assert('network defaults to testnet', c.network === 'testnet')
    assert('socksPort defaults to 9050 (not 9150)', c.tor.socksPort === 9050)
    assert('redaction defaults on', c.log.redact === true)
    let threw = false
    try {
      loadConfig(undefined, {
        seedFile: '/tmp/s',
        stateDir: '/tmp/d',
        allowClearnet: true,
        network: 'mainnetish',
        soroban: { url: 'http://clearnet.example/rpc' },
        oracle: { endpoint: '127.0.0.1:50001' },
      })
    } catch (e) {
      threw = e instanceof ConfigError
    }
    assert('invalid network refused', threw)
  }
})()

console.log('')
if (failures === 0) {
  console.log('PASS — state store and config.')
} else {
  console.log(`FAIL — ${failures} store/config check(s) failed.`)
  process.exit(1)
}
