// SPDX-License-Identifier: Apache-2.0
/**
 * @securevector/sdk
 *
 * Security and observability for AI agents, for Node. Three calls:
 *
 *   guard(fn, { toolId })        every tool call scanned and audited
 *   session(id, opts, fn)        one agent run, one identity
 *   generation({ model, input }) every model call traced, with cost and verdict
 *
 * Zero runtime dependencies. The platform `fetch`, `node:async_hooks` and
 * `node:crypto`, and nothing else.
 */

export { guard, type GuardOptions, type Guarded, type AnyFn } from './guard.js';
export { GuardBlocked, type Verdict } from './errors.js';
export {
  session,
  setIdentity,
  clearIdentity,
  currentSession,
  currentGenerationSpan,
  identity,
  type Identity,
  type SessionOptions,
} from './session.js';
export {
  generation,
  Generation,
  Tracer,
  getTracer,
  setTracer,
  flush,
  encodeOtlp,
  normalizeUsage,
  traceIdFor,
  newSpanId,
  FLUSH_INTERVAL_MS,
  FLUSH_MAX_SPANS,
  SDK_VERSION,
  type GenerationOptions,
  type GenerationEnd,
  type Span,
  type SpanEvent,
  type SpanKind,
  type Usage,
} from './tracing.js';
export {
  configFromEnv,
  getConfig,
  setConfig,
  DEFAULT_APP_URL,
  DEFAULT_RISK_THRESHOLD,
  DEFAULT_TIMEOUT_MS,
  PREVIEW_LIMIT,
  RUNTIME_KIND,
  SCAN_LIMIT,
  type GuardConfig,
  type ConfigOverrides,
  isRemoteEndpoint,
  type Mode,
} from './config.js';
export {
  redact,
  redactForScan,
  hasCredentialMarkers,
  scanText,
  toText,
  SECRET_PATTERNS,
} from './redact.js';
export { setWarner, resetWarnings, type Warner } from './warn.js';
export {
  AppTransport,
  getTransport,
  resetTransports,
  type Direction,
  type AuditAction,
  type AuditFields,
} from './transport.js';
