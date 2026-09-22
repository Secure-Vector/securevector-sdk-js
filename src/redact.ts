// SPDX-License-Identifier: Apache-2.0
/**
 * Secret redaction and preview capping.
 *
 * Previews leave the process, so they are masked first and capped second. The
 * leak shapes are the ones the agent-runtime plugins already mask with
 * (`lib/redact.js` in the threat monitor), kept in one list here so a shape
 * added on one side is not silently missed on the other. The caps are the
 * Python SDK's numbers: 8192 for a stored preview, 102400 for a scan body.
 *
 * The app redacts again on its side. This pass is about not putting a
 * credential on the wire in the first place.
 */

import { PREVIEW_LIMIT, SCAN_LIMIT } from './config.js';

/**
 * Conservative, highest-blast-radius-first credential shapes.
 *
 * Every pattern is global, and every pattern with a capture group captures the
 * label prefix so the masked text still reads like the original.
 */
export const SECRET_PATTERNS: RegExp[] = [
  // OpenAI project key (sk-proj-...)
  /\bsk-proj-[A-Za-z0-9_-]{20,}/g,
  // Stripe live / test keys
  /\bsk_(?:live|test)_[A-Za-z0-9]{20,}\b/g,
  // OpenAI / Anthropic sk- / pk-
  /(?:sk|pk)-[A-Za-z0-9_-]{20,}/g,
  // GitHub PAT / OAuth / user / server / refresh
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g,
  // AWS Access Key ID
  /\bAKIA[0-9A-Z]{16}\b/g,
  // AWS Secret Access Key (40-char base64)
  /\b(?:aws_secret_access_key\s*[:=]\s*['"]?)[A-Za-z0-9/+=]{40}\b/gi,
  // JWT
  /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
  // PEM private keys, any flavour. Body bounded to 8 KB to cap the worst case
  // on input that has a BEGIN line and no END line.
  /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY-----[\s\S]{1,8192}?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY-----/g,
  // Labelled key/value pairs. Deliberately unbounded: a bound leaves the tail
  // of a longer value in the clear, and a greedy negated character class has
  // nothing to backtrack into, so there is no ReDoS here to cap.
  /(["']?(?:password|secret|token|api[_-]?key|bearer|auth[_-]?token|access[_-]?token|client[_-]?secret)["']?\s*[:=]\s*["']?)[^"'\s,}\]]{6,}/gi,
  // Slack bot / app / user / refresh tokens
  /\bxox[baprs]-[A-Za-z0-9-]{10,}/g,
  // Google API key
  /\bAIza[0-9A-Za-z_-]{35}\b/g,
  // npm automation / publish token
  /\bnpm_[A-Za-z0-9]{36}\b/g,
  // GitLab personal access token
  /\bglpat-[A-Za-z0-9_-]{20,}/g,
  // SendGrid API key
  /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/g,
];

/**
 * Mask every known credential shape in `text`.
 *
 * `String.prototype.replace` with a global regex resets `lastIndex` itself, so
 * calling this repeatedly in one process is safe.
 */
export function redactForScan(text: unknown): string {
  if (typeof text !== 'string' || text.length === 0) return '';
  let out = text;
  for (const pattern of SECRET_PATTERNS) {
    out = out.replace(pattern, (_match: string, prefix?: string) =>
      prefix ? `${prefix}[REDACTED]` : '[REDACTED]',
    );
  }
  return out;
}

/**
 * Does `text` carry at least one credential shape?
 *
 * Reuses the same list as the redactor, so "is this worth scanning" can never
 * drift from "what do we mask". `RegExp.prototype.test` on a global regex
 * advances `lastIndex`, so it is reset around each probe.
 */
export function hasCredentialMarkers(text: unknown): boolean {
  if (typeof text !== 'string' || text.length === 0) return false;
  for (const pattern of SECRET_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(text)) {
      pattern.lastIndex = 0;
      return true;
    }
  }
  return false;
}

/** Mask, then cap. `limit` defaults to the stored-preview cap. */
export function redact(value: unknown, limit: number = PREVIEW_LIMIT): string {
  if (value === null || value === undefined || value === '') return '';
  return redactForScan(toText(value)).slice(0, limit);
}

/** Mask, then cap at the /analyze body limit. */
export function scanText(value: unknown): string {
  return redact(value, SCAN_LIMIT);
}

/**
 * Best-effort text for any value: strings pass through, everything else is
 * JSON, and a value that will not serialise degrades instead of throwing.
 */
export function toText(value: unknown): string {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string') return value;
  try {
    const json = JSON.stringify(value, jsonReplacer);
    if (json !== undefined) return json;
  } catch {
    // falls through to the String() attempt below
  }
  try {
    return String(value);
  } catch {
    return `<${typeof value}: unserialisable>`;
  }
}

function jsonReplacer(_key: string, value: unknown): unknown {
  if (typeof value === 'bigint') return value.toString();
  if (value instanceof Error) return `${value.name}: ${value.message}`;
  if (typeof value === 'function') return `<function ${value.name || 'anonymous'}>`;
  if (typeof value === 'symbol') return value.toString();
  if (value instanceof Map) return Object.fromEntries(value);
  if (value instanceof Set) return Array.from(value);
  return value;
}
