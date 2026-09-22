// SPDX-License-Identifier: Apache-2.0
/**
 * Run identity: which session a call belongs to, and who is behind it.
 *
 * `AsyncLocalStorage` is the Node equivalent of the Python SDK's context
 * variables: everything awaited inside `session(...)` sees the same store, and
 * two concurrent agent runs in one process never read each other's identity.
 *
 * Identity and the generation pointer are held separately, because they have
 * different lifetimes. Identity is set once for a run and read; the generation
 * pointer changes on every model call and must behave like a context variable,
 * so it lives in its own storage as an immutable frame that each async context
 * replaces for itself rather than as a field mutated in place on a shared
 * object. See `openGeneration` for why that distinction matters.
 */

import { AsyncLocalStorage } from 'node:async_hooks';
import { randomUUID } from 'node:crypto';

/** Who and what a run is. Carried by every span opened inside the session. */
export interface Identity {
  userId?: string;
  tags?: string[];
  metadata?: Record<string, unknown>;
}

/** Options accepted by `session()` and `setIdentity()`. */
export interface SessionOptions extends Identity {
  /** Only meaningful to `setIdentity`, which can also set the session id. */
  sessionId?: string;
}

interface Store extends Identity {
  sessionId: string;
}

const storage = new AsyncLocalStorage<Store>();

/** Used when nothing calls `session()`: one id for the life of the process. */
const processSession = `node-${randomUUID().replace(/-/g, '').slice(0, 12)}`;

/**
 * The store in effect outside any `session()` block. A real store from module
 * load, not null: a process that never calls `session()` still opens
 * generations and still needs its tool calls to link to them.
 */
let ambient: Store = { sessionId: processSession };

function store(): Store {
  return storage.getStore() ?? ambient;
}

/** The session id in effect: the enclosing session, else the process id. */
export function currentSession(): string {
  return store().sessionId;
}

/** The identity in effect. Always a fresh object, safe to mutate. */
export function identity(): Identity {
  const s = store();
  const out: Identity = {};
  if (s.userId) out.userId = s.userId;
  if (s.tags && s.tags.length > 0) out.tags = [...s.tags];
  if (s.metadata && Object.keys(s.metadata).length > 0) out.metadata = { ...s.metadata };
  return out;
}

// --------------------------------------------------------------------------- //
// The generation pointer                                                      //
// --------------------------------------------------------------------------- //

/** Shared with the `Generation` object so a frame can tell whether it closed. */
export interface Liveness {
  ended: boolean;
}

/**
 * One layer of the generation pointer. Frames are immutable and chained: a new
 * one is entered when a generation opens or closes, and the layer it covered is
 * kept on `under` so a sibling can look past it.
 */
interface GenFrame {
  /** The generation opened in this frame, if any. */
  readonly spanId: string | null;
  /** Whether that generation is still open. */
  readonly live: Liveness | null;
  /** The last generation that ended in this context. */
  readonly last: string | null;
  /** The frame this one replaced. */
  readonly under: GenFrame | null;
}

const ROOT_FRAME: GenFrame = { spanId: null, live: null, last: null, under: null };

const genStorage = new AsyncLocalStorage<GenFrame>();

/**
 * The frame entered during the current synchronous turn, if any.
 *
 * An async function does not get its own async context until its first `await`,
 * so two model calls started side by side, as `Promise.all` over two functions
 * that both reach `generation()` before yielding, run their opening code in one
 * shared context. Without this the second would read the first's frame and nest
 * under it. They are siblings, so the second looks past the frame its sibling
 * just entered. Cleared on the next microtask, by which point every branch has
 * its own context and ordinary nesting reads correctly again.
 */
let turnFrame: GenFrame | null = null;
let turnClearScheduled = false;

function enterFrame(frame: GenFrame, sameTurn: boolean): void {
  genStorage.enterWith(frame);
  if (!sameTurn) return;
  turnFrame = frame;
  if (turnClearScheduled) return;
  turnClearScheduled = true;
  queueMicrotask(() => {
    turnClearScheduled = false;
    turnFrame = null;
  });
}

/** The frame this context inherited, ignoring a sibling's same-turn entry. */
function inherited(): GenFrame {
  const f = genStorage.getStore() ?? ROOT_FRAME;
  if (f === turnFrame) return f.under ?? ROOT_FRAME;
  return f;
}

function openSpanOf(f: GenFrame): string | null {
  if (f.spanId === null || f.live === null || f.live.ended) return null;
  return f.spanId;
}

/**
 * Span id of the model turn a tool call belongs to: the generation open in this
 * context, else the most recent one that ended in this session.
 */
export function currentGenerationSpan(): string | null {
  const f = inherited();
  return openSpanOf(f) ?? f.last;
}

/** What `openGeneration` hands back, to be returned to `closeGeneration`. */
export interface GenerationToken {
  readonly spanId: string;
  /** The turn this generation nests under, or null if it is a root turn. */
  readonly parentSpanId: string | null;
  /** The frame to restore when it closes. */
  readonly under: GenFrame;
}

/**
 * Internal: mark a generation as the open turn for this async context.
 *
 * Entering a frame rather than mutating one is what keeps concurrent model
 * calls apart. Each branch of a `Promise.all` gets its own frame, so neither
 * sees the other's generation as a parent and neither leaves the other's span
 * behind as the current turn once both have finished.
 */
export function openGeneration(spanId: string, live: Liveness): GenerationToken {
  const under = inherited();
  const parentSpanId = openSpanOf(under);
  enterFrame({ spanId, live, last: under.last, under }, true);
  return { spanId, parentSpanId, under };
}

/**
 * Internal: the generation closed. Hands the pointer back to the turn it nested
 * under and records it as the last one to end, so a tool call that runs after
 * the model returned still links to it.
 *
 * Keyed by the token the matching `openGeneration` returned, so generations
 * that end out of order each restore their own layer instead of the top one.
 */
export function closeGeneration(token: GenerationToken): void {
  const under = token.under;
  enterFrame(
    { spanId: under.spanId, live: under.live, last: token.spanId, under: inherited() },
    false,
  );
}

function resetGenerations(under: GenFrame): void {
  enterFrame({ spanId: null, live: null, last: null, under }, false);
}

function newStore(sessionId: string, opts: SessionOptions): Store {
  const s: Store = { sessionId: String(sessionId) };
  if (opts.userId) s.userId = String(opts.userId);
  if (opts.tags && opts.tags.length > 0) s.tags = opts.tags.map(String);
  if (opts.metadata && Object.keys(opts.metadata).length > 0) s.metadata = { ...opts.metadata };
  return s;
}

/**
 * Group every guarded call and model call inside `fn` under one agent run.
 *
 * `userId`, `tags` and `metadata` are set once here and carried by every
 * generation span opened inside. The return value of `fn` is passed through,
 * and an error thrown inside `fn` propagates unchanged.
 *
 * ```ts
 * await session('checkout-42', { userId: 'u_9' }, async () => {
 *   const gen = await generation({ model: 'gpt-4o', input: messages });
 *   ...
 * });
 * ```
 */
export function session<T>(sessionId: string, fn: () => T): T;
export function session<T>(sessionId: string, opts: SessionOptions, fn: () => T): T;
export function session<T>(
  sessionId: string,
  optsOrFn: SessionOptions | (() => T),
  maybeFn?: () => T,
): T {
  const opts: SessionOptions = typeof optsOrFn === 'function' ? {} : optsOrFn;
  const fn = (typeof optsOrFn === 'function' ? optsOrFn : maybeFn) as () => T;
  if (typeof fn !== 'function') {
    throw new TypeError('session(sessionId, [options], fn): fn must be a function');
  }
  // A run starts with no open turn, and anything the run opens stays inside it.
  return storage.run(newStore(sessionId, opts), () => genStorage.run(ROOT_FRAME, fn));
}

/**
 * Set the identity without nesting, for code that cannot wrap its work in a
 * callback. Matches the Python SDK's `set_identity`.
 *
 * Inside a `session()` block this updates that session. Outside one it sets a
 * process-wide identity that every later call picks up. Returns a function that
 * restores whatever was in effect before.
 */
export function setIdentity(opts: SessionOptions = {}): () => void {
  const inSession = storage.getStore();
  const beforeFrame = genStorage.getStore() ?? ROOT_FRAME;
  // A new identity starts a new run boundary: tool calls must never link to
  // a model turn from the previous identity.
  resetGenerations(beforeFrame);
  if (inSession !== undefined) {
    const before: Store = { ...inSession };
    if (opts.sessionId) inSession.sessionId = String(opts.sessionId);
    if (opts.userId !== undefined) inSession.userId = opts.userId ? String(opts.userId) : undefined;
    if (opts.tags !== undefined) inSession.tags = opts.tags ? opts.tags.map(String) : undefined;
    if (opts.metadata !== undefined) inSession.metadata = opts.metadata ? { ...opts.metadata } : undefined;
    return () => {
      Object.assign(inSession, before);
      enterFrame(beforeFrame, false);
    };
  }
  const before = ambient;
  ambient = newStore(opts.sessionId ?? currentSession(), opts);
  return () => {
    ambient = before;
    enterFrame(beforeFrame, false);
  };
}

/** Clear any process-wide identity set by `setIdentity()`. Test hook. */
export function clearIdentity(): void {
  ambient = { sessionId: processSession };
  enterFrame(ROOT_FRAME, false);
}
