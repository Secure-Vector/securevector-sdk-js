// SPDX-License-Identifier: Apache-2.0
/**
 * Model-run tracing for any Node agent.
 *
 * Every model call becomes a generation span and lands in the local app's
 * Traces page next to the guarded tool calls of the same run: model, tokens,
 * cost, input and output previews, duration and a verdict.
 *
 * Spans are encoded as OTLP/HTTP JSON with the OpenTelemetry GenAI semantic
 * convention attributes and posted in batches to `POST /v1/traces`. The same
 * endpoint accepts traces from any OpenTelemetry exporter, so an agent that is
 * already instrumented needs none of this.
 *
 * Fail-open: if the app is down the model call runs unchanged and one warning
 * is logged per process.
 */

import { createHash, randomUUID } from 'node:crypto';

import {
  PREVIEW_LIMIT,
  RUNTIME_KIND,
  SCAN_LIMIT,
  getConfig,
  type GuardConfig,
  type Mode,
} from './config.js';
import { GuardBlocked, type Verdict } from './errors.js';
import { redact, scanText, toText } from './redact.js';
import {
  closeGeneration,
  currentSession,
  identity,
  openGeneration,
  type GenerationToken,
  type Liveness,
} from './session.js';
import { AppTransport, getTransport } from './transport.js';

/** Flush at most this often. Same number as the Python SDK (0.2 s). */
export const FLUSH_INTERVAL_MS = 200;

/** Flush immediately once the buffer holds this many spans. */
export const FLUSH_MAX_SPANS = 200;

/** The scope version reported in every batch. */
export const SDK_VERSION = '6.0.1';

/** What a span represents. Generation maps to CLIENT, tool to INTERNAL. */
export type SpanKind = 'generation' | 'tool';

/** One span, before OTLP encoding. */
export interface Span {
  traceId: string;
  spanId: string;
  name: string;
  kind: SpanKind;
  parentSpanId?: string | null;
  startNs: bigint;
  endNs: bigint;
  attributes: Record<string, unknown>;
  events: SpanEvent[];
  statusError?: string | null;
}

export interface SpanEvent {
  name: string;
  timeNs?: bigint;
  attributes?: Record<string, unknown>;
}

const SPAN_KIND_CODE: Record<SpanKind, number> = { generation: 3, tool: 1 };

/** How many un-posted batches may wait at once before the oldest is dropped. */
const MAX_QUEUED_BATCHES = 20;

/** Consecutive failed posts after which the tracer stops trying. */
const MAX_CONSECUTIVE_FAILURES = 5;

/**
 * Deterministic 32-hex OTel trace id for a session, so spans flushed in
 * different batches, or from different processes, share one trace. Matches the
 * app's own derivation: sha256("<runtime kind>:<session id>") truncated to 32.
 */
export function traceIdFor(sessionId: string): string {
  return createHash('sha256')
    .update(`${RUNTIME_KIND}:${sessionId}`, 'utf8')
    .digest('hex')
    .slice(0, 32);
}

/** A fresh 16-hex span id. */
export function newSpanId(): string {
  return randomUUID().replace(/-/g, '').slice(0, 16);
}

/**
 * The span clock. `Date.now()` alone quantises every duration to a whole
 * millisecond, so a sub-millisecond model call or tool call reports 0. The
 * elapsed part comes from the monotonic high-resolution clock instead, anchored
 * once to a wall-clock reading so absolute timestamps still line up with the
 * app's own and never step backwards over a clock adjustment. Matches the
 * Python SDK's `time.time_ns()` resolution.
 */
const hrClock: (() => bigint) | null =
  typeof process?.hrtime?.bigint === 'function' ? process.hrtime.bigint.bind(process.hrtime) : null;
const WALL_ORIGIN_NS = BigInt(Date.now()) * 1_000_000n;
const HR_ORIGIN_NS = hrClock === null ? 0n : hrClock();

function nowNs(): bigint {
  if (hrClock === null) return BigInt(Date.now()) * 1_000_000n;
  return WALL_ORIGIN_NS + (hrClock() - HR_ORIGIN_NS);
}

// --------------------------------------------------------------------------- //
// OTLP JSON encoding                                                          //
// --------------------------------------------------------------------------- //

function anyValue(v: unknown): Record<string, unknown> {
  if (typeof v === 'boolean') return { boolValue: v };
  if (typeof v === 'bigint') return { intValue: v.toString() };
  if (typeof v === 'number') {
    return Number.isInteger(v) ? { intValue: String(v) } : { doubleValue: v };
  }
  if (Array.isArray(v)) return { arrayValue: { values: v.map(anyValue) } };
  return { stringValue: typeof v === 'string' ? v : toText(v) };
}

function kv(attrs: Record<string, unknown>): Array<Record<string, unknown>> {
  const out: Array<Record<string, unknown>> = [];
  for (const [key, value] of Object.entries(attrs)) {
    if (value === null || value === undefined) continue;
    out.push({ key, value: anyValue(value) });
  }
  return out;
}

/** An OTLP/HTTP JSON `ExportTraceServiceRequest` for one batch of spans. */
export function encodeOtlp(
  spans: Span[],
  serviceName: string = RUNTIME_KIND,
  resource: Record<string, unknown> = {},
): Record<string, unknown> {
  const resourceAttrs = { 'service.name': serviceName, ...resource };
  const out = spans.map((s) => {
    const fallback = s.endNs || s.startNs;
    const span: Record<string, unknown> = {
      traceId: s.traceId,
      spanId: s.spanId,
      name: s.name,
      kind: SPAN_KIND_CODE[s.kind] ?? 1,
      startTimeUnixNano: s.startNs.toString(),
      endTimeUnixNano: fallback.toString(),
      attributes: kv(s.attributes),
      events: s.events.map((e) => ({
        timeUnixNano: (e.timeNs ?? fallback).toString(),
        name: e.name,
        attributes: kv(e.attributes ?? {}),
      })),
    };
    if (s.parentSpanId) span.parentSpanId = s.parentSpanId;
    if (s.statusError) span.status = { code: 2, message: s.statusError };
    return span;
  });
  return {
    resourceSpans: [
      {
        resource: { attributes: kv(resourceAttrs) },
        scopeSpans: [
          { scope: { name: 'securevector', version: SDK_VERSION }, spans: out },
        ],
      },
    ],
  };
}

// --------------------------------------------------------------------------- //
// Tracer: buffer and flush                                                    //
// --------------------------------------------------------------------------- //

/**
 * Per-process span buffer. Flushes at most every 200 ms, on 200 spans, and when
 * the event loop drains at the end of the process. Never throws.
 */
export class Tracer {
  readonly cfg: GuardConfig;
  readonly transport: AppTransport;
  private buffer: Span[] = [];
  private timer: NodeJS.Timeout | null = null;
  private inFlight: Promise<number> = Promise.resolve(0);
  private queued = 0;
  private failures = 0;
  private dropped = 0;

  constructor(cfg?: GuardConfig, transport?: AppTransport) {
    this.cfg = cfg ?? getConfig();
    this.transport = transport ?? getTransport(this.cfg);
    // Every tracer flushes at exit, not only the one getTracer() built. A
    // tracer handed in through setTracer() or generation({ tracer }) buffers
    // spans the same way and would otherwise lose them. Matches the Python
    // SDK, which registers atexit in Tracer.__init__.
    registerTracer(this);
  }

  /** Buffer one span. Returns immediately; the flush is scheduled. */
  record(span: Span): void {
    if (!this.cfg.enabled) return;
    this.buffer.push(span);
    if (this.buffer.length >= FLUSH_MAX_SPANS) {
      this.timer = clearTimer(this.timer);
      void this.flush();
      return;
    }
    if (this.timer === null) {
      this.timer = setTimeout(() => {
        this.timer = null;
        void this.flush();
      }, FLUSH_INTERVAL_MS);
      // The buffer must not keep an otherwise-finished process alive.
      this.timer.unref?.();
    }
  }

  /**
   * Send everything buffered. Resolves with the number of spans sent.
   *
   * Two things bound this so a long outage cannot grow without limit. The
   * chain is what serialises posts, and each link holds its batch alive until
   * it resolves; with the app down every post waits the full timeout, so
   * batches arrive faster than they drain. `queued` caps how many may be
   * waiting at once, and past that the OLDEST is dropped: recent spans are the
   * ones someone is looking at. Separately, after `MAX_CONSECUTIVE_FAILURES`
   * the tracer stops posting until something succeeds again, so an agent left
   * running overnight against a dead engine does not spend the night
   * retrying. Telemetry is the thing that yields; the agent keeps working.
   */
  flush(): Promise<number> {
    this.timer = clearTimer(this.timer);
    const spans = this.buffer;
    this.buffer = [];
    if (spans.length === 0) return this.inFlight.then(() => 0);
    if (this.failures >= MAX_CONSECUTIVE_FAILURES) {
      this.dropped += spans.length;
      return this.inFlight.then(() => 0);
    }
    if (this.queued >= MAX_QUEUED_BATCHES) {
      this.dropped += spans.length;
      return this.inFlight.then(() => 0);
    }
    this.queued += 1;
    // Chain so two flushes never interleave their posts out of order.
    this.inFlight = this.inFlight.then(async () => {
      try {
        await this.transport.post('/v1/traces', encodeOtlp(spans));
        this.failures = 0;
        return spans.length;
      } catch (err) {
        this.failures += 1;
        this.transport.warnOnce(err);
        return 0;
      } finally {
        this.queued -= 1;
      }
    });
    return this.inFlight;
  }

  /** Spans thrown away because the engine was unreachable. Test hook. */
  get droppedSpans(): number {
    return this.dropped;
  }

  /** How many spans are waiting. Test hook. */
  get pending(): number {
    return this.buffer.length;
  }
}

function clearTimer(t: NodeJS.Timeout | null): null {
  if (t !== null) clearTimeout(t);
  return null;
}

let tracer: Tracer | null = null;
let exitHookInstalled = false;

/**
 * Every tracer built in this process, weakly, so the exit hook can flush them
 * all without keeping a discarded tracer alive.
 */
const liveTracers = new Set<WeakRef<Tracer>>();

function registerTracer(t: Tracer): void {
  liveTracers.add(new WeakRef(t));
  installExitHook();
}

/** The process tracer, created on first use. */
export function getTracer(): Tracer {
  if (tracer === null) tracer = new Tracer();
  return tracer;
}

/** Replace the process tracer. Test hook. */
export function setTracer(next: Tracer | null): void {
  tracer = next;
}

/**
 * Send everything buffered now. Call this before a short-lived process exits if
 * you want the last spans guaranteed on disk, rather than relying on the
 * best-effort exit hook.
 */
export async function flush(): Promise<number> {
  if (tracer === null) return 0;
  return tracer.flush();
}

function installExitHook(): void {
  if (exitHookInstalled) return;
  if (typeof process?.once !== 'function') return;
  exitHookInstalled = true;
  // One hook for the whole process, however many tracers there are: N hooks
  // for N tracers would be its own bug. `once` rather than `on`, because the
  // flush it starts is async work that makes beforeExit fire again, and the
  // handler never awaits, so a shutdown is never held up by it.
  process.once('beforeExit', () => {
    for (const ref of liveTracers) {
      const t = ref.deref();
      if (t === undefined) liveTracers.delete(ref);
      else void t.flush();
    }
  });
}

// --------------------------------------------------------------------------- //
// Usage normalisation                                                         //
// --------------------------------------------------------------------------- //

/** Token counts, however the provider spells them. */
export interface Usage {
  input: number;
  output: number;
  cacheRead: number;
}

function pick(obj: unknown, ...names: string[]): unknown {
  if (obj === null || obj === undefined || typeof obj !== 'object') return undefined;
  const rec = obj as Record<string, unknown>;
  for (const n of names) {
    const v = rec[n];
    if (v !== null && v !== undefined) return v;
  }
  return undefined;
}

/**
 * Accept the plain `{ input, output, cacheRead }` shape, the OpenAI usage object
 * (`prompt_tokens` ...), the Anthropic one (`input_tokens` ...) and Bedrock's
 * (`inputTokens` ...). Missing counts come back as 0.
 */
export function normalizeUsage(usage: unknown): Usage {
  if (usage === null || usage === undefined) return { input: 0, output: 0, cacheRead: 0 };
  const input = pick(usage, 'input', 'input_tokens', 'prompt_tokens', 'inputTokens');
  const output = pick(usage, 'output', 'output_tokens', 'completion_tokens', 'outputTokens');
  let cached = pick(
    usage,
    'cacheRead',
    'cache_read',
    'input_cached',
    'cache_read_input_tokens',
    'cacheReadInputTokens',
  );
  if (cached === undefined) {
    const details = pick(usage, 'prompt_tokens_details', 'input_tokens_details');
    cached = pick(details, 'cached_tokens', 'cachedTokens');
  }
  const toInt = (v: unknown): number => {
    const n = Number.parseInt(String(v ?? 0), 10);
    return Number.isFinite(n) ? n : 0;
  };
  return { input: toInt(input), output: toInt(output), cacheRead: toInt(cached) };
}

// --------------------------------------------------------------------------- //
// Generation span                                                             //
// --------------------------------------------------------------------------- //

/** Options for one model call. */
export interface GenerationOptions {
  /** The model id as the provider names it. */
  model?: string;
  /** The provider or system: openai, anthropic, bedrock, ollama ... */
  provider?: string;
  /** The prompt, messages array, or anything else that serialises. */
  input?: unknown;
  /** Span name. Defaults to "<operation> <model>". */
  name?: string;
  /** Overrides the configured mode for this one call. */
  mode?: Mode;
  /** chat (default), text_completion, generate_content, embeddings. */
  operation?: string;
  /** Test hook: use this tracer instead of the process one. */
  tracer?: Tracer;
}

/** What a model call returned. */
export interface GenerationEnd {
  output?: unknown;
  usage?: unknown;
  error?: unknown;
  finishReason?: string;
  responseModel?: string;
}

/** One model call, open until `.end()` is called. */
export class Generation {
  readonly model: string;
  readonly provider: string | undefined;
  readonly name: string;
  readonly operation: string;
  readonly sessionId: string;
  readonly requestId: string;
  readonly spanId: string;
  readonly mode: Mode;
  readonly tracer: Tracer;
  /** The prompt verdict, when enforce mode scanned one. */
  verdict: Verdict | null = null;
  span: Span | null = null;
  private ended = false;
  /** Shared with the context frame, so a closed turn stops being "current". */
  private readonly live: Liveness = { ended: false };
  private token: GenerationToken | null = null;

  constructor(opts: GenerationOptions = {}) {
    this.model = opts.model || 'unknown';
    this.provider = opts.provider;
    this.operation = opts.operation || 'chat';
    this.name = opts.name || `${this.operation} ${this.model}`;
    this.tracer = opts.tracer ?? getTracer();
    this.mode = opts.mode === 'observe' || opts.mode === 'enforce' ? opts.mode : this.tracer.cfg.mode;
    this.sessionId = currentSession();
    this.requestId = newSpanId();
    this.spanId = newSpanId();
  }

  /**
   * Open the span. In enforce mode the prompt is scanned first and a finding at
   * or above the threshold throws `GuardBlocked` before the model is called.
   */
  async start(input: unknown): Promise<this> {
    const cfg = this.tracer.cfg;
    if (!cfg.enabled) return this;

    // scanText masks and THEN caps. Capping first would cut a secret that
    // straddles the limit into two halves that no longer match their pattern,
    // and the mangled remainder would ship verbatim. Never slice before this.
    const prompt = input === null || input === undefined ? '' : scanText(input);
    if (this.mode === 'enforce' && prompt) {
      const v = await this.tracer.transport.analyze(prompt, 'outgoing', {
        sessionId: this.sessionId,
        requestId: this.requestId,
      });
      this.verdict = v;
      if (v !== null && v.finding && v.riskScore >= cfg.threatRiskThreshold) {
        throw new GuardBlocked(this.name, v);
      }
    }

    const ident = identity();
    const attributes: Record<string, unknown> = {
      'gen_ai.operation.name': this.operation,
      'gen_ai.request.model': this.model,
      'session.id': this.sessionId,
      'securevector.request_id': this.requestId,
    };
    if (this.provider) attributes['gen_ai.system'] = this.provider;
    if (ident.userId) attributes['user.id'] = ident.userId;
    if (ident.tags && ident.tags.length > 0) attributes['session.tags'] = ident.tags;
    for (const [k, v] of Object.entries(ident.metadata ?? {})) {
      attributes[`session.metadata.${k}`] = v;
    }

    const startNs = nowNs();
    // Set this generation as the open one for this async context, and keep the
    // token so `.end()` restores exactly the layer this call entered, even if
    // a concurrent generation ends first.
    this.token = openGeneration(this.spanId, this.live);
    this.span = {
      traceId: traceIdFor(this.sessionId),
      spanId: this.spanId,
      name: this.name,
      kind: 'generation',
      parentSpanId: this.token.parentSpanId,
      startNs,
      endNs: 0n,
      attributes,
      events: [],
    };
    if (prompt) {
      this.span.events.push({
        name: 'gen_ai.content.prompt',
        timeNs: startNs,
        attributes: { 'gen_ai.prompt': prompt },
      });
    }
    return this;
  }

  /**
   * Close the span and hand it to the tracer. Safe to call more than once;
   * later calls are ignored. Never throws.
   */
  async end(result: GenerationEnd = {}): Promise<void> {
    if (this.ended || this.span === null) return;
    this.ended = true;
    const s = this.span;
    s.endNs = nowNs();

    const u = normalizeUsage(result.usage);
    s.attributes['gen_ai.usage.input_tokens'] = u.input;
    s.attributes['gen_ai.usage.output_tokens'] = u.output;
    if (u.cacheRead) s.attributes['gen_ai.usage.cache_read.input_tokens'] = u.cacheRead;
    if (result.responseModel) s.attributes['gen_ai.response.model'] = result.responseModel;
    if (result.finishReason) s.attributes['gen_ai.response.finish_reasons'] = [result.finishReason];

    if (result.output !== null && result.output !== undefined) {
      s.events.push({
        name: 'gen_ai.content.completion',
        timeNs: s.endNs,
        attributes: {
          'gen_ai.completion': scanText(result.output),
        },
      });
    }
    if (result.error !== null && result.error !== undefined) {
      const err = result.error;
      const name = err instanceof Error ? err.constructor.name : typeof err;
      const message = err instanceof Error ? err.message : String(err);
      s.statusError = `${name}: ${message}`.slice(0, PREVIEW_LIMIT);
      s.attributes['error.type'] = name;
    }

    this.live.ended = true;
    if (this.token !== null) closeGeneration(this.token);
    this.tracer.record(s);
  }
}

/**
 * Open a generation span for one model call.
 *
 * ```ts
 * const gen = await generation({ model: 'gpt-4o', provider: 'openai', input: messages });
 * const res = await openai.chat.completions.create({ ... });
 * await gen.end({ output: res.choices[0].message, usage: res.usage });
 * ```
 *
 * Awaiting is what lets enforce mode scan the prompt and block before the model
 * is called. In observe mode it resolves without a round trip.
 */
export async function generation(opts: GenerationOptions = {}): Promise<Generation> {
  const gen = new Generation(opts);
  return gen.start(opts.input);
}
