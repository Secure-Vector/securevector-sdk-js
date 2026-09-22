// SPDX-License-Identifier: Apache-2.0
/** The one error this SDK throws on purpose. */

/** A verdict from the engine about one piece of text. */
export interface Verdict {
  /** True when the engine found a threat or a secret. */
  finding: boolean;
  /** 0 to 100. */
  riskScore: number;
  /** Human-readable, of the form "outgoing prompt_injection risk=92". */
  reason: string;
  /** The rule or threat type that fired, or "clean" / "secret". */
  rule: string;
  /** Which direction was scanned: outgoing, incoming or llm_response. */
  direction: string;
}

/**
 * Raised in enforce mode when the arguments of a guarded call, or the prompt of
 * a generation, are a finding at or above the risk threshold.
 *
 * The wrapped function has not run when this is thrown.
 */
export class GuardBlocked extends Error {
  /** The tool id, or the generation name for a blocked prompt. */
  readonly toolId: string;
  /** The rule that fired. */
  readonly rule: string;
  /** Long-form reason, the same string the app records. */
  readonly reason: string;
  /** 0 to 100. */
  readonly riskScore: number;
  /** The full verdict, when one was available. */
  readonly verdict: Verdict | null;

  constructor(toolId: string, verdict: Verdict | null, reason?: string, riskScore?: number) {
    const why = reason ?? verdict?.reason ?? 'blocked';
    super(`SecureVector blocked ${toolId}: ${why}`);
    this.name = 'GuardBlocked';
    this.toolId = toolId;
    this.verdict = verdict ?? null;
    this.rule = verdict?.rule ?? 'unknown';
    this.reason = why;
    this.riskScore = riskScore ?? verdict?.riskScore ?? 0;
    Object.setPrototypeOf(this, GuardBlocked.prototype);
  }
}
