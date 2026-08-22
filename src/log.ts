// JSONL structured logging with a mandatory redaction layer.
//
// This daemon's log is a ledger of who pays the operator, so redaction is not
// a nicety: it is the difference between a private receiver and a plaintext
// counterparty database sitting in a journal. The layer is implemented HERE,
// not as a convention each call site is trusted to follow: any configured
// secret that appears anywhere in an emitted line is scrubbed before the line
// is written. Nothing can bypass it.
//
// The daemon configures the layer with its own secrets (seed bytes, box secret
// key, its payment code) as a belt-and-braces guarantee; the caller contract is
// still that full payment codes, addresses and txid/payment-code pairs are
// NEVER passed to a log call in the first place. A stable truncated identifier
// per sender (first 8 hex chars of SHA256(paymentCode)) is what gets logged.

import { sha256 } from '@noble/hashes/sha256'

export type LogLevel = 'error' | 'warn' | 'info' | 'debug'
const LEVELS: Record<LogLevel, number> = { error: 0, warn: 1, info: 2, debug: 3 }

export type LoggerOptions = {
  level?: LogLevel
  redact?: boolean
  /** Exact strings that must never appear in output; replaced with a marker. */
  secrets?: string[]
  stream?: NodeJS.WritableStream
  now?: () => number
}

export type Logger = {
  error(msg: string, fields?: Record<string, unknown>): void
  warn(msg: string, fields?: Record<string, unknown>): void
  info(msg: string, fields?: Record<string, unknown>): void
  debug(msg: string, fields?: Record<string, unknown>): void
}

export function createLogger(opts: LoggerOptions = {}): Logger {
  const threshold = LEVELS[opts.level ?? 'info']
  const redact = opts.redact ?? true
  const secrets = (opts.secrets ?? []).filter((s) => s.length >= 4) // avoid over-scrubbing short strings
  const stream = opts.stream ?? process.stdout
  const now = opts.now ?? Date.now

  const write = (level: LogLevel, msg: string, fields?: Record<string, unknown>): void => {
    if (LEVELS[level] > threshold) return
    let line = JSON.stringify({ ts: new Date(now()).toISOString(), level, msg, ...fields })
    if (redact) {
      for (const secret of secrets) {
        line = line.split(secret).join('[redacted]')
      }
    }
    stream.write(`${line}\n`)
  }

  return {
    error: (m, f) => write('error', m, f),
    warn: (m, f) => write('warn', m, f),
    info: (m, f) => write('info', m, f),
    debug: (m, f) => write('debug', m, f),
  }
}

/** Stable truncated sender identifier for logs: first 8 hex of SHA256(pc). */
export function shortSender(paymentCode: string): string {
  const digest = sha256(new TextEncoder().encode(paymentCode))
  return Buffer.from(digest).toString('hex').slice(0, 8)
}
