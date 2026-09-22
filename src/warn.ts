// SPDX-License-Identifier: Apache-2.0
/**
 * Where the SDK's warnings go, and the memo that keeps them to one each.
 *
 * There is exactly one sink for the whole package. Two would mean a test that
 * captures warnings still misses half of them, and an operator who redirects
 * the SDK's output still finds some of it on stderr.
 *
 * Every warning here is about the SDK failing quietly: an engine it cannot
 * reach, a mode string it did not understand, previews leaving the machine.
 * Those are the cases where saying nothing is the actual danger, so the sink
 * never throws and never blocks, but it is never silent either.
 */

export type Warner = (message: string) => void;

const consoleWarner: Warner = (message: string) => {
  // eslint-disable-next-line no-console
  console.warn(message);
};

let warner: Warner = consoleWarner;
const seen = new Set<string>();

/** Replace where warnings go. `null` restores console.warn. */
export function setWarner(fn: Warner | null): void {
  warner = fn ?? consoleWarner;
}

/** Forget which warnings have been emitted. Test seam. */
export function resetWarnings(): void {
  seen.clear();
}

/** Emit `message` once per process. Never throws. */
export function warnOnce(message: string): void {
  if (seen.has(message)) return;
  seen.add(message);
  emit(message);
}

/** Emit `message`. Never throws: a broken sink must not break the agent. */
export function emit(message: string): void {
  try {
    warner(message);
  } catch {
    /* a warning is never worth an exception in someone else's agent */
  }
}
