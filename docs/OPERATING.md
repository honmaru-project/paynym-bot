# Operating paynymd

This daemon receives BIP47 payments without an on-chain notification transaction. The sender's payment code is delivered over Soroban (Tor-only); the daemon watches derived receive addresses on your own chain indexer.

## What to back up

**The seed alone is not a backup.**

Receive keys are a function of the seed **and** the set of registered sender payment codes. Lose a payment code and the corresponding addresses become unfindable — for practical purposes, funds sent to them become unspendable-by-search.

Back up together:

1. The seed file (`chmod 600`, owned by the daemon user).
2. `state.json` in the state directory (same permissions on the directory: `0700`).

The registry changes every time a new sender registers. A daily encrypted copy of `state.json` is the minimum responsible posture.

Supported round-trip (full `state.json` shape — registry, box key, and credit ledger):

```bash
paynymd export --config /etc/paynymd/paynymd.json --out backup.json
paynymd import --config /etc/paynymd/paynymd.json --in backup.json
```

Import merges new senders; it refuses to clobber when the backup payment code does not match the seed.

## Prerequisites

- Node 22+ with `--experimental-strip-types` (no build step).
- Tor system service listening on `127.0.0.1:9050` (not Tor Browser's `9150`).
- Your own Soroban node reachable as an `.onion` URL.
- Your own electrs or Bitcoin Core instance, also reachable over Tor.

The daemon refuses to start if the SOCKS proxy is unreachable. It never falls back to clearnet unless you pass `--allow-clearnet` (integration testing only).

## Configuration

Use a JSON config file. Secrets never appear in the config — only paths:

```json
{
  "network": "testnet",
  "seedFile": "/etc/paynymd/seed",
  "stateDir": "/var/lib/paynymd",
  "soroban": {
    "url": "http://YOUR56CHARONION.onion/rpc",
    "scheme": "plain",
    "publishIntervalMs": 120000,
    "publishMode": "long",
    "inboxIntervalMs": 60000
  },
  "oracle": {
    "kind": "electrum",
    "endpoint": "YOUR56CHARONION.onion:50001",
    "scanIntervalMs": 300000,
    "gapLimit": 5,
    "trailingWindow": 20
  },
  "tor": {
    "socksHost": "127.0.0.1",
    "socksPort": 9050
  }
}
```

`publishIntervalMs` must be strictly less than the TTL implied by `publishMode` (`long` = 5 minutes). Mainnet must be an explicit `"network": "mainnet"` in the file — testnet is the default.

## Commands

```bash
paynymd run --config ./paynymd.json
paynymd status --config ./paynymd.json
paynymd export --config ./paynymd.json --out backup.json
paynymd import --config ./paynymd.json --in backup.json
paynymd address --config ./paynymd.json --sender PM8T...
```

Show your payment code once at startup (stdout only, never logged):

```bash
paynymd run --config ./paynymd.json --show-payment-code
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Clean shutdown |
| 2 | Invalid config |
| 3 | Another instance holds the lock |
| 4 | State/seed payment-code mismatch |
| 5 | Tor proxy unreachable at startup |
| 130 | Second signal during shutdown |

## systemd

Install the unit from `contrib/paynymd.service`. It hardens the service (no home access, strict filesystem, memory W^X) and waits for `tor.service`.

Place config at `/etc/paynymd/paynymd.json` and the seed at a `0600` path referenced by `seedFile`.

## Hot-wallet reality

The bot is hot by construction: ECDH needs the account private key. The daemon runs forever, so keep float small and sweep to cold storage on a schedule. Treat the host as compromised-if-reachable.

This milestone does **not** implement spending, sweeping, or signing.

## Clock discipline

Registration envelopes reject timestamps outside a ±6 hour window. Confidential Soroban listing signs a nanosecond timestamp the node checks. Host clock drift presents as mysteriously rejected registrations — keep NTP enabled.

## Privacy

- Never point the oracle at a public Electrum server or block explorer. The watch set is your complete counterparty graph.
- Default logging redacts seed bytes, payment codes, and addresses. Do not disable redaction in production.

## Testnet first

Run on testnet until you have verified registration, payment detection, and restart durability. Flip `"network": "mainnet"` only when deliberate.
