# paynym-bot — always-online BIP47 receiver, no notification transaction

A self-custody BIP47 receiver that accepts payments **without** the sender first
broadcasting an on-chain notification (OP_RETURN) transaction. The sender's
payment code is delivered over [Soroban](https://github.com/linkinparkrulz/soroban)
— an encrypted, Tor-based directory — instead of over the chain.

This is built for **your own funds**: you control both the sender tool and the
receiver bot. It is not a service that receives on behalf of other people.

## Why this works (and it isn't a hack)

A BIP47 receive address is a pure function of the two parties' payment codes.
Nothing in the derivation references a txid, an outpoint, or any on-chain data
— verify this in [`src/bip47.ts`](src/bip47.ts): it never sees the chain.

The notification transaction does exactly two jobs, both pure transport:

1. **deliver** the sender's payment code to the receiver, and
2. **blind** that code so chain observers can't link the two parties.

Deliver the code over an encrypted channel instead and both jobs disappear — the
resulting on-chain payment is a plain P2PKH send, byte-for-byte identical to any
other BIP47 payment. The BIP47 spec even reserves a features bit for non-chain
notification, so this is anticipated, not worked around.

The one hard constraint: **both ends must run notification-skipping code.** A
stock wallet only looks for your addresses after it has seen a notification, so
it would never find these. Since you run both sides, that's fully in hand.

## The derivation (the load-bearing math)

For a payment from sender to receiver at index `i`:

```
S_i = a_0 · B_i = b_i · A_0      (ECDH; symmetric — each side computes it from
                                  the other's payment code alone)
s_i = SHA256(S_i.x)              (32-byte big-endian x-coordinate; NOT HMAC)
addr_i = P2PKH(B_i + s_i·G)
```

where `a_0` / `A_0` are the **sender's child-0** key (`m/47'/0'/0'/0`, the
notification key) and `b_i` / `B_i` are the **receiver's child-i** key. The
sender fixes its index at 0; the receiver varies its own index `i`.

Two mistakes to avoid, both of which the vectors catch:

- The tweak is `SHA256(S.x)`, applied additively. There is **no HMAC** in the
  address tweak (that's BIP32 CKD logic, which does not belong here).
- The sender uses its key at **child index 0**, not the account node key. Those
  are different keys; using the account node reproduces neither the vectors nor
  the receiver's address.

Verified against the official BIP47 test vectors (Alice & Bob) — payment codes,
notification address, and all 10 receive addresses reproduce, and the sender's
computed pay address equals the receiver's watch address for every index:

```
npm install
npm test          # runs the full suite: vectors, protocol, daemon, transport,
                  # store/config, oracle, and redaction tests
```

Do not trust anything downstream until `npm run vectors` prints `PASS`.

## How Soroban carries the payment code

Grounded in Soroban's actual wire protocol (`services/directory.go`,
`internal/common/ttl.go`, and the reference clients under `clients/` in the
[Soroban repo](https://github.com/linkinparkrulz/soroban)):

- JSON-RPC 2.0 over HTTP POST to a node's `/rpc` (usually a `.onion` over Tor).
  Methods: `directory.List` / `directory.Add` / `directory.Remove`.
- A "directory" is just a key string, addressed by its **SHA256 hex** so the
  node never sees the readable name.
- Entries are opaque strings with a TTL by `Mode`: `fast`=15s, `short`=1m,
  `long`=5m, `default`=3m (node caps at 15m). An always-online receiver just
  re-publishes on a timer.

### Registration flow ([`src/register.ts`](src/register.ts))

1. Receiver publishes its **rendezvous box key** to a directory derived from its
   own payment code, and re-publishes on a timer.
2. Sender fetches that box key, wraps a signed registration envelope
   (`{ paymentCode, ts, sig }`) in a NaCl box to the receiver, and `Add`s it to
   the receiver's inbox directory. No transaction is broadcast.
3. Receiver drains the inbox, decrypts, verifies, and records the sender.
4. From then on the receiver watches a window of receive addresses per sender
   — from `max(0, nextIndex − trailingWindow)` through `nextIndex + gap − 1`
   (defaults: gap 5, trailing window 20) — and the sender pays the identical
   `sendAddress(receiverCode, i)`.

### Correction: Soroban does **not** authenticate payment codes

A Soroban channel is keyed with **ephemeral Curve25519 box keys**, not the
BIP47 secp256k1 payment-code keys. Decrypting a Soroban message proves the peer
holds the ephemeral box key and says *nothing* about who controls a payment
code. So the registration envelope is **signed with the payment code's own
identity key** (secp256k1 child-0), and the receiver verifies that signature
against the pubkey embedded in the submitted code. That app-layer signature —
not the transport — is what binds a registration to the holder of the code.
`test/protocol.test.ts` includes a forged-envelope case to prove a mismatched
signature is rejected.

### Optional: confidential inbox

By default the inbox works on any public node and its contents are box-encrypted
(listers see only ciphertext). Soroban also ships a confidential prefix,
`soroban.register-queue.*` in its `confidential.yml`, whose `List` requires an
Ed25519 signature — so only the receiver can even enumerate the queue. To use
it, run your own node, replace that prefix's `publickey` with your Ed25519 key,
and construct the `Registrar` with `scheme: 'confidential'` and a
`naclSigner(...)` auth. See `ConfidentialAuth` in [`src/soroban.ts`](src/soroban.ts).

## Module map

| File | Role |
|------|------|
| `src/bip47.ts` | Derivation core: payment codes, notification address, `receiveAddress` / `sendAddress` / `receivePrivateKey`. Verified against the vectors. |
| `src/identity.ts` | `PaynymIdentity` — seed → account, payment code, identity signing. |
| `src/soroban.ts` | Soroban JSON-RPC client, `encodeDirectory`, NaCl box channel, Ed25519 confidential auth. Matches the reference clients' wire format. |
| `src/register.ts` | Notification-less registration protocol (sender + `Registrar`) and the sender `Registry`. |
| `src/watcher.ts` | Turns the registry into the gap-limited address set to watch, with a pluggable used-address oracle. |
| `src/config.ts` | Configuration parsing and validation for paynymd. |
| `src/store.ts` | Atomic state store and single-instance lockfile. |
| `src/daemon.ts` | Scheduler and the publish / inbox / scan ticks. |
| `src/log.ts` | JSONL structured logging with a mandatory redaction layer. |
| `src/transport/tor.ts` | Zero-dependency SOCKS5 + HTTP/1.1 client for Soroban over Tor. |
| `src/oracle/` | Used-address oracles for electrs and Bitcoin Core over Tor. |
| `bin/paynymd.ts` | Daemon entrypoint (`run`, `status`, `export`, `import`, `address`). |
| `test/vectors.test.ts` | The BIP47 vector gate. |
| `test/protocol.test.ts` | Offline end-to-end protocol test over an in-memory node. |
| `test/register-fixes.test.ts` | Rendezvous durability + inbox intake regressions. |
| `test/tor.test.ts` | SOCKS5 + HTTP/1.1 transport tests against a fake proxy. |
| `test/store.test.ts` | State store, lockfile, and config tests. |
| `test/oracle.test.ts` | Electrum and Core oracle tests (scripthash, batching, reconnect). |
| `test/daemon.test.ts` | Scheduler, tick, and fault-injection tests. |
| `test/redaction.test.ts` | Log redaction acceptance test. |
| `example.ts` | One-shot live wiring against a real node. |
| `docs/OPERATING.md` | Deployment, backup, and restore runbook. |

## Operating the receiver

- **Your own indexer only.** Point `watcher`'s used-address oracle at your own
  Bitcoin Core / electrs over Tor. The watch list is your counterparty graph —
  never hand it to a public explorer.
- **Back up the registry with the seed.** Receive keys cannot be re-derived from
  the seed alone; they also need the registered sender payment codes
  (`Registry.toJSON` / `fromJSON`).
- **The bot is hot by construction** (ECDH needs the account private key). Keep
  the float small and sweep to cold storage.
- **testnet first:** `PaynymIdentity.fromSeed(seed, TESTNET)`, then flip to
  `MAINNET`.

## Status

- Derivation: verified against official vectors (0–9), both directions. ✅
- Registration protocol: offline end-to-end incl. forgery rejection. ✅
- Rendezvous durability fixes (non-destructive read, durable inbox intake) with regression tests. ✅
- `paynymd` daemon: Tor-only transport, atomic state store, electrs/Core oracle,
  publish/inbox/scan scheduler, CLI, log redaction tests. ✅
- Manual: testnet soak and live Tor verification before production use.

## Requirements

Node 22+ (uses built-in TypeScript type stripping via
`--experimental-strip-types`; no build step). Dependencies are the audited
noble/scure family plus tweetnacl — see `package.json`.

## License

GNU General Public License v3.0 only. See [LICENSE](LICENSE).
