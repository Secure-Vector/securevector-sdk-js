// SPDX-License-Identifier: Apache-2.0
/**
 * The three HTTP routes this SDK needs, on the platform `fetch`.
 *
 * Fail-open is the whole contract: a timeout, a refused connection, a non-2xx
 * or a body that is not JSON must never reach the caller and must never stop a
 * tool from running. Every failure is swallowed here and reported once per
 * process as a single warning.
 */

import { RUNTIME_KIND, SCAN_LIMIT, type GuardConfig } from './config.js';
import type { Verdict } from './errors.js';
import { scanText } from './redact.js';
import { emit, setWarner, type Warner } from './warn.js';

export { setWarner, type Warner };

/** Which way the text is travelling, as the engine names it. */
export type Direction = 'outgoing' | 'incoming' | 'llm_response';

/** The verdict the app records for a call. */
export type AuditAction = 'block' | 'allow' | 'log_only';

/** Body of POST /api/tool-permissions/call-audit. */
export interface AuditFields {
  tool_id: string;
  function_name: string;
  action: AuditAction;
  risk?: string | null;
  reason?: string | null;
  is_essential?: boolean;
  args_preview?: string | null;
  runtime_kind?: string | null;
  session_id?: string | null;
  request_id?: string | null;
  span_id?: string | null;
  parent_span_id?: string | null;
}

interface AnalyzeResponse {
  is_threat?: boolean;
  threat_type?: string | null;
  risk_score?: number | null;
  redacted_text?: string | null;
}

/** Thrown internally when the engine answers with a non-2xx status. */
class HttpStatusError extends Error {
  readonly status: number;
  constructor(status: number, statusText: string) {
    super(`HTTP ${status} ${statusText}`.trim());
    this.name = 'HttpStatusError';
    this.status = status;
  }
}


/** Short, useful name for whatever went wrong on the wire. */
function describe(err: unknown): string {
  if (!(err instanceof Error)) return typeof err;
  const cause = (err as { cause?: unknown }).cause;
  if (cause !== null && cause !== undefined && typeof cause === 'object') {
    const code = (cause as { code?: unknown }).code;
    if (typeof code === 'string' && code) return code;
    if (cause instanceof Error && cause.name) return cause.name;
  }
  return err.name || 'Error';
}

/**
 * Read a response body, stopping at the cap instead of after it.
 *
 * `res.text()` allocates the whole body first and any length check then
 * happens too late to prevent anything: a hostile engine answering with a
 * multi-gigabyte reply exhausts memory before the check runs. Reading through
 * the stream lets the read be abandoned the moment it grows past the cap.
 * Falls back to `text()` only when the runtime exposes no body stream.
 */
async function readCapped(res: Response): Promise<string> {
  const body = res.body;
  if (!body || typeof body.getReader !== 'function') {
    const whole = await res.text();
    if (whole.length > MAX_RESPONSE_BYTES) {
      throw new HttpStatusError(res.status, `response larger than ${MAX_RESPONSE_BYTES} bytes`);
    }
    return whole;
  }
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let out = '';
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      out += decoder.decode(value, { stream: true });
      if (out.length > MAX_RESPONSE_BYTES) {
        await reader.cancel().catch(() => undefined);
        throw new HttpStatusError(res.status, `response larger than ${MAX_RESPONSE_BYTES} bytes`);
      }
    }
  } finally {
    reader.releaseLock?.();
  }
  return out + decoder.decode();
}

/** Largest engine reply this client will hold in memory. */
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;

export class AppTransport {
  readonly cfg: GuardConfig;
  private warned = false;

  constructor(cfg: GuardConfig) {
    this.cfg = cfg;
  }

  /** True once the unreachable warning has been emitted. Test hook. */
  get hasWarned(): boolean {
    return this.warned;
  }

  /** POST JSON and parse the JSON answer. Throws on transport or status error. */
  async post(path: string, body: unknown): Promise<unknown> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    };
    if (this.cfg.apiKey) headers.Authorization = `Bearer ${this.cfg.apiKey}`;

    const res = await fetch(this.cfg.baseUrl + path, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(this.cfg.timeoutMs),
      // A 307 or 308 preserves the method AND the body, so a redirect is a
      // way for whatever answers the endpoint to forward prompts and tool
      // arguments somewhere else. There is no legitimate reason for the
      // engine to redirect, so refuse rather than follow.
      redirect: 'error',
    });
    if (!res.ok) {
      // Drain so the socket is released even on an error status, but bounded:
      // an error status is not a promise that the body is small.
      await readCapped(res).catch(() => '');
      throw new HttpStatusError(res.status, res.statusText);
    }
    const raw = await readCapped(res);
    return raw ? (JSON.parse(raw) as unknown) : null;
  }

  /** One warning per process, per endpoint. Never throws. */
  warnOnce(err: unknown): void {
    if (this.warned) return;
    this.warned = true;
    try {
      if (err instanceof HttpStatusError) {
        emit(
          `SecureVector engine at ${this.cfg.baseUrl} answered HTTP ${err.status}; ` +
            'guarded calls run unscanned. Check SECUREVECTOR_ENGINE_ENDPOINT and SECUREVECTOR_API_KEY.',
        );
        return;
      }
      // `fetch` reports a refused connection as a bare TypeError and puts the
      // useful part (ECONNREFUSED, ENOTFOUND) on `cause`. A timeout arrives as
      // a TimeoutError. Report whichever actually says what went wrong.
      const kind = describe(err);
      emit(
        `SecureVector app not reachable at ${this.cfg.baseUrl} (${kind}); ` +
          'guarded calls run unscanned. Start it with `securevector-app` or set SECUREVECTOR_ENGINE_ENDPOINT.',
      );
    } catch {
      // A warning sink that throws must not break the agent either.
    }
  }

  /**
   * Scan one piece of text. Returns a verdict, or null when the engine could
   * not be reached, which callers treat as "no opinion, proceed".
   */
  async analyze(
    value: unknown,
    direction: Direction,
    opts: { sessionId: string; requestId: string },
  ): Promise<Verdict | null> {
    const text = scanText(value);
    if (!text) {
      return { finding: false, riskScore: 0, reason: 'empty', rule: 'empty', direction };
    }
    const body = {
      text: text.slice(0, SCAN_LIMIT),
      direction,
      source: RUNTIME_KIND,
      session_id: opts.sessionId.slice(0, 64),
      request_id: opts.requestId.slice(0, 64),
    };
    let res: unknown;
    try {
      res = await this.post('/analyze', body);
    } catch (err) {
      this.warnOnce(err);
      return null;
    }
    if (res === null || typeof res !== 'object') {
      return { finding: false, riskScore: 0, reason: 'no-result', rule: 'no-result', direction };
    }
    const r = res as AnalyzeResponse;
    const risk = Number.parseInt(String(r.risk_score ?? 0), 10) || 0;
    const isThreat = Boolean(r.is_threat);
    // redacted_text is set only when the engine actually masked a secret.
    // action_taken is not a finding signal: it reads "blocked" on every
    // response, clean or not, whenever the block-threats setting is on.
    const hasSecret = Boolean(r.redacted_text);
    const rule = r.threat_type || (hasSecret ? 'secret' : 'clean');
    return {
      finding: isThreat || hasSecret,
      riskScore: risk,
      reason: `${direction} ${rule} risk=${risk}`,
      rule,
      direction,
    };
  }

  /**
   * Record one tool-call decision. Never throws: a failed post is warned about
   * once and swallowed. `guard()` awaits it so the row is on its way before the
   * wrapped call returns, which is what keeps the audit chain in call order.
   */
  async recordAudit(fields: AuditFields): Promise<void> {
    try {
      await this.post('/api/tool-permissions/call-audit', { is_essential: false, ...fields });
    } catch (err) {
      // An audit that did not land must not break the agent.
      this.warnOnce(err);
    }
  }
}

const transports = new Map<string, AppTransport>();

/**
 * One transport per (endpoint, key, timeout), so the unreachable warning really
 * is once per process rather than once per guarded function.
 */
export function getTransport(cfg: GuardConfig): AppTransport {
  const key = `${cfg.baseUrl}\u0000${cfg.apiKey}\u0000${cfg.timeoutMs}`;
  let t = transports.get(key);
  if (t === undefined) {
    t = new AppTransport(cfg);
    transports.set(key, t);
  }
  return t;
}

/** Drop the cached transports. Test hook. */
export function resetTransports(): void {
  transports.clear();
}
