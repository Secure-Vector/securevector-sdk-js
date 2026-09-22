// SPDX-License-Identifier: Apache-2.0
/**
 * One wrapper that puts any function under SecureVector.
 *
 * ```ts
 * import { guard } from '@securevector/sdk';
 *
 * const searchWeb = guard(async (query: string) => { ... }, { toolId: 'search.web' });
 * const runSql = guard(rawRunSql, { toolId: 'db.query', mode: 'enforce' });
 * ```
 *
 * Every call is scanned on the way in, as user-to-tool text, and on the way
 * out, as fetched context heading back to the model. Each call lands as one row
 * in the running local app: Tool Activity, Agent Runs and the tamper-evident
 * audit chain, grouped by session.
 *
 * Fail-open by default. If the app is not running the wrapped function still
 * runs and nothing is thrown; one warning is logged per process. In enforce
 * mode a finding on the arguments stops the call with `GuardBlocked`; a finding
 * on the output is always recorded, never thrown, because the result already
 * exists by then.
 */

import { RUNTIME_KIND, getConfig, type GuardConfig, type Mode } from './config.js';
import { GuardBlocked, type Verdict } from './errors.js';
import { redact, toText } from './redact.js';
import { currentGenerationSpan, currentSession } from './session.js';
import { newSpanId } from './tracing.js';
import { AppTransport, getTransport, type AuditAction } from './transport.js';

/** Options for `guard()`. */
export interface GuardOptions {
  /** Stable id for this tool. Defaults to the function's name. */
  toolId?: string;
  /** Overrides the configured mode for this one function. */
  mode?: Mode;
  /** False skips the return-value scan, for large or binary results. */
  scanOutput?: boolean;
  /** Config overrides for this one function. */
  config?: GuardConfig;
  /** Test hook: use this transport. */
  transport?: AppTransport;
}

/** Any function the SDK can wrap. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type AnyFn = (...args: any[]) => any;

/** The wrapped function: same arguments, always a promise. */
export type Guarded<F extends AnyFn> = (...args: Parameters<F>) => Promise<Awaited<ReturnType<F>>>;

interface CallContext {
  sessionId: string;
  requestId: string;
  preview: string;
  verdict: Verdict | null;
  parentSpanId: string | null;
}

/**
 * Best-effort named arguments. Parsing a function's parameter names from its
 * source is unreliable across transpilers and minifiers, so a single object
 * argument is reported as-is and everything else as a positional list. Either
 * way the engine sees the same text the function sees.
 */
function argsText(args: unknown[]): string {
  if (args.length === 1 && isPlainObject(args[0])) return toText(args[0]);
  if (args.length === 0) return '';
  return toText(args);
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v) as object | null;
  return proto === Object.prototype || proto === null;
}

class GuardRunner {
  constructor(
    private readonly fnName: string,
    readonly toolId: string,
    readonly cfg: GuardConfig,
    readonly transport: AppTransport,
    private readonly scanOutput: boolean,
  ) {}

  private blocks(verdict: Verdict | null): boolean {
    return (
      verdict !== null &&
      verdict.finding &&
      this.cfg.mode === 'enforce' &&
      verdict.riskScore >= this.cfg.threatRiskThreshold
    );
  }

  /** Scan the arguments. Throws GuardBlocked in enforce mode on a finding. */
  async before(args: unknown[]): Promise<CallContext> {
    const text = argsText(args);
    const ctx: CallContext = {
      sessionId: currentSession(),
      requestId: newSpanId(),
      preview: redact(text),
      verdict: null,
      parentSpanId: currentGenerationSpan(),
    };
    if (!this.cfg.enabled) return ctx;

    ctx.verdict = await this.transport.analyze(text, 'outgoing', {
      sessionId: ctx.sessionId,
      requestId: ctx.requestId,
    });
    if (this.blocks(ctx.verdict)) {
      const v = ctx.verdict as Verdict;
      await this.audit(ctx, 'block', v.reason, v.riskScore);
      throw new GuardBlocked(this.toolId, v);
    }
    return ctx;
  }

  /** Scan the result and record the row. Never throws. */
  async after(ctx: CallContext, result: unknown): Promise<void> {
    if (!this.cfg.enabled) return;
    let out: Verdict | null = null;
    if (this.scanOutput) {
      out = await this.transport.analyze(result, 'incoming', {
        sessionId: ctx.sessionId,
        requestId: ctx.requestId,
      });
    }
    const findings = [ctx.verdict, out].filter((v): v is Verdict => v !== null && v.finding);
    if (findings.length > 0) {
      const worst = findings.reduce((a, b) => (b.riskScore > a.riskScore ? b : a));
      await this.audit(ctx, 'log_only', worst.reason, worst.riskScore);
    } else {
      await this.audit(ctx, 'allow', null, null);
    }
  }

  /** Record a call that threw. Never throws. */
  async failed(ctx: CallContext, err: unknown): Promise<void> {
    if (!this.cfg.enabled) return;
    const name = err instanceof Error ? err.constructor.name : typeof err;
    await this.audit(ctx, 'allow', `raised ${name}`, null);
  }

  private async audit(
    ctx: CallContext,
    action: AuditAction,
    reason: string | null,
    risk: number | null,
  ): Promise<void> {
    await this.transport.recordAudit({
      tool_id: this.toolId,
      function_name: this.fnName,
      runtime_kind: RUNTIME_KIND,
      action,
      risk: risk === null ? null : String(risk),
      reason,
      args_preview: ctx.preview,
      session_id: ctx.sessionId,
      request_id: ctx.requestId,
      span_id: ctx.requestId,
      parent_span_id: ctx.parentSpanId,
    });
  }
}

/**
 * Run one instrumentation step. `GuardBlocked` passes through; any other error
 * inside the SDK is swallowed so the wrapped call is unaffected.
 */
async function safe<T>(step: () => Promise<T>): Promise<T | null> {
  try {
    return await step();
  } catch (err) {
    if (err instanceof GuardBlocked) throw err;
    return null;
  }
}

/**
 * Wrap a function so every call is scanned and audited.
 *
 * The wrapper is always async, because the scan is a network call. Sync
 * functions are wrapped fine; their result comes back as a resolved promise.
 */
export function guard<F extends AnyFn>(fn: F, options: GuardOptions = {}): Guarded<F> {
  if (typeof fn !== 'function') {
    throw new TypeError('guard(fn, options): fn must be a function');
  }
  let cfg = options.config ?? getConfig();
  if ((options.mode === 'observe' || options.mode === 'enforce') && options.mode !== cfg.mode) {
    cfg = { ...cfg, mode: options.mode };
  }
  const fnName = fn.name || 'anonymous';
  const toolId = options.toolId || fnName;
  const runner = new GuardRunner(
    fnName,
    toolId,
    cfg,
    options.transport ?? getTransport(cfg),
    options.scanOutput !== false,
  );

  const wrapper = async function (this: unknown, ...args: Parameters<F>): Promise<Awaited<ReturnType<F>>> {
    const ctx = await safe(() => runner.before(args));
    let result: Awaited<ReturnType<F>>;
    try {
      result = (await fn.apply(this, args)) as Awaited<ReturnType<F>>;
    } catch (err) {
      if (ctx !== null) await safe(() => runner.failed(ctx, err));
      throw err;
    }
    if (ctx !== null) await safe(() => runner.after(ctx, result));
    return result;
  };

  Object.defineProperty(wrapper, 'name', { value: fnName, configurable: true });
  Object.defineProperty(wrapper, 'securevectorToolId', { value: toolId, enumerable: false });
  return wrapper as Guarded<F>;
}
