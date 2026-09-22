// SPDX-License-Identifier: Apache-2.0
/**
 * The generation frame stack, under the shapes that broke the version before it.
 *
 * The first implementation kept the current generation on one mutable object
 * shared by everything inside a `session()`. Two generations started under
 * `Promise.all` therefore made the second a child of the first, and after both
 * ended the pointer still named the first, so every later tool call was
 * audited under a closed model turn. Python does not have this problem because
 * `contextvars` copy per task.
 *
 * The replacement is a second `AsyncLocalStorage` holding immutable frames
 * popped by span id, plus a guard for the case where two branches both reach
 * `generation()` before their first `await` and so share one async context.
 * That guard is the subtle part, so these are the cases worth keeping: a
 * sibling must never nest, a real nesting must still nest, and an out-of-order
 * `end()` must not leave a closed span current.
 *
 * Hermetic: observe mode does not scan, and the flush fails open against a
 * port nothing is listening on, so no app is required.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  session,
  generation,
  configFromEnv,
  setConfig,
  setWarner,
  currentGenerationSpan,
} from '../dist/esm/index.js';

setWarner(() => {});
setConfig(configFromEnv({ baseUrl: 'http://127.0.0.1:1', mode: 'observe', timeoutMs: 50 }));

const end = (g) => g.end({ output: 'o', usage: { prompt_tokens: 1, completion_tokens: 1 } });

test('five concurrent generations that never yield first are all siblings', async () => {
  await session('stress-1', {}, async () => {
    const gs = await Promise.all(
      [1, 2, 3, 4, 5].map(async (n) => generation({ model: `m${n}`, provider: 'p', input: 'x' })),
    );
    const ids = new Set(gs.map((g) => g.spanId));
    assert.equal(ids.size, 5, 'span ids must be distinct');
    for (const g of gs) {
      assert.ok(
        !ids.has(g.span.parentSpanId),
        `${g.model} is parented to a sibling (${g.span.parentSpanId})`,
      );
    }
    await Promise.all(gs.map(end));
  });
});

test('concurrent generations that yield before starting are also siblings', async () => {
  await session('stress-2', {}, async () => {
    const gs = await Promise.all(
      [1, 2, 3].map(async (n) => {
        await new Promise((r) => setTimeout(r, n * 3));
        return generation({ model: `a${n}`, provider: 'p', input: 'x' });
      }),
    );
    const ids = new Set(gs.map((g) => g.spanId));
    for (const g of gs) {
      assert.ok(!ids.has(g.span.parentSpanId), `${g.model} is parented to a sibling`);
    }
    await Promise.all(gs.map(end));
  });
});

test('ending out of order does not leave a closed span as the current turn', async () => {
  await session('stress-3', {}, async () => {
    const a = await generation({ model: 'A', provider: 'p', input: 'x' });
    const b = await generation({ model: 'B', provider: 'p', input: 'x' });
    await end(a); // the OUTER one first, which a plain stack would mishandle
    await end(b);
    const current = currentGenerationSpan();
    assert.notEqual(current, a.spanId, 'a closed span must never be the current turn');
  });
});

test('a genuine nesting still nests, so the fix is not linking turned off', async () => {
  await session('stress-4', {}, async () => {
    const outer = await generation({ model: 'outer', provider: 'p', input: 'x' });
    await new Promise((r) => setTimeout(r, 1));
    const inner = await generation({ model: 'inner', provider: 'p', input: 'x' });
    assert.equal(inner.span.parentSpanId, outer.spanId, 'a real nesting must nest');
    await end(inner);
    await end(outer);
  });
});

test('concurrent sessions keep their own identity throughout', async () => {
  await Promise.all(
    ['u1', 'u2', 'u3'].map(async (userId) =>
      session(`sess-${userId}`, { userId }, async () => {
        const g = await generation({ model: 'm', provider: 'p', input: 'x' });
        await new Promise((r) => setTimeout(r, 5 + Math.random() * 10));
        assert.equal(
          g.span.attributes['user.id'],
          userId,
          'identity crossed between concurrently running sessions',
        );
        await end(g);
      }),
    ),
  );
});
