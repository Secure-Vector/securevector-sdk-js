// SPDX-License-Identifier: Apache-2.0
/**
 * Regression tests for span linking, tracer lifecycle and the span clock.
 *
 * Each test here pins one defect found by execution: concurrent generations
 * mis-parenting and leaving a closed span as the current turn, linking being
 * inert outside session(), the exit flush hook installing on one path only,
 * and the millisecond span clock.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { promisify } from 'node:util';

import {
  AppTransport,
  Tracer,
  clearIdentity,
  configFromEnv,
  currentGenerationSpan,
  generation,
  session,
} from '../dist/esm/index.js';
import { startFakeApp } from './helpers/fake-app.mjs';

const run = promisify(execFile);
const DIST = new URL('../dist/esm/index.js', import.meta.url).href;
const SRC = (name) => new URL(`../src/${name}`, import.meta.url);

function tracerFor(url, over = {}) {
  const cfg = configFromEnv({ baseUrl: url, ...over }, {});
  return new Tracer(cfg, new AppTransport(cfg));
}

function spansOf(app) {
  return app
    .find('/v1/traces')
    .flatMap((r) => r.body.resourceSpans)
    .flatMap((rs) => rs.scopeSpans)
    .flatMap((ss) => ss.spans);
}

function byName(app) {
  return Object.fromEntries(spansOf(app).map((s) => [s.name, s]));
}

const tick = () => new Promise((resolve) => setTimeout(resolve, 2));

// --------------------------------------------------------------------------- //
// H2: linking must work with no session() anywhere                            //
// --------------------------------------------------------------------------- //

test('H2: a generation is linkable with no session() at all', async (t) => {
  clearIdentity();
  const app = await startFakeApp();
  t.after(() => {
    clearIdentity();
    return app.close();
  });
  const tracer = tracerFor(app.url);

  assert.equal(currentGenerationSpan(), null, 'nothing open yet');

  const gen = await generation({ model: 'flat', input: 'x', tracer });
  assert.equal(
    currentGenerationSpan(),
    gen.spanId,
    'an open generation is the current turn even outside session()',
  );

  await gen.end({ output: 'y' });
  assert.equal(
    currentGenerationSpan(),
    gen.spanId,
    'after it ends it is still the turn a following tool call belongs to',
  );
});

// --------------------------------------------------------------------------- //
// H1: concurrent generations are siblings, and leave no dangling pointer      //
// --------------------------------------------------------------------------- //

test('H1: concurrent generations are siblings and leave a clean pointer', async (t) => {
  const app = await startFakeApp();
  t.after(() => app.close());
  const tracer = tracerFor(app.url);

  let pointerAfter = 'never-set';
  let idA = null;
  let idB = null;

  await session('parallel-run', async () => {
    // Both branches reach generation() in the same synchronous turn, which is
    // what a plain Promise.all over two model calls does.
    const [a, b] = await Promise.all([
      (async () => {
        const g = await generation({ model: 'model-a', input: 'a', tracer });
        await tick();
        await g.end({ output: 'a' });
        return g;
      })(),
      (async () => {
        const g = await generation({ model: 'model-b', input: 'b', tracer });
        await tick();
        await g.end({ output: 'b' });
        return g;
      })(),
    ]);
    idA = a.spanId;
    idB = b.spanId;
    pointerAfter = currentGenerationSpan();
  });
  await tracer.flush();

  const spans = byName(app);
  const a = spans['chat model-a'];
  const b = spans['chat model-b'];
  assert.ok(a && b, 'both generations were recorded');

  assert.notEqual(a.parentSpanId, idB, 'A must not nest under its sibling B');
  assert.notEqual(b.parentSpanId, idA, 'B must not nest under its sibling A');
  assert.equal(a.parentSpanId, undefined, 'A is a root turn');
  assert.equal(b.parentSpanId, undefined, 'B is a root turn');

  assert.equal(
    pointerAfter,
    null,
    'after both ended the current turn must not point at a closed span',
  );
});

test('H1: sequential generations still nest, so linking is not simply off', async (t) => {
  const app = await startFakeApp();
  t.after(() => app.close());
  const tracer = tracerFor(app.url);

  let innerId = null;
  await session('sequential-run', async () => {
    const outer = await generation({ model: 'outer', input: 'plan', tracer });
    const inner = await generation({ model: 'inner', input: 'work', tracer });
    innerId = inner.spanId;
    assert.equal(currentGenerationSpan(), inner.spanId, 'the inner turn is current');
    await inner.end({ output: 'done' });
    assert.equal(
      currentGenerationSpan(),
      outer.spanId,
      'closing the inner turn hands the pointer back to the outer one',
    );
    await outer.end({ output: 'done' });
    assert.equal(currentGenerationSpan(), outer.spanId, 'the last turn stays linkable');
  });
  await tracer.flush();

  const spans = byName(app);
  assert.equal(spans['chat inner'].parentSpanId, spans['chat outer'].spanId);
  assert.equal(spans['chat outer'].parentSpanId, undefined);
  assert.equal(spans['chat inner'].spanId, innerId);
});

// --------------------------------------------------------------------------- //
// M1: every tracer flushes at exit, not only the one getTracer() built        //
// --------------------------------------------------------------------------- //

test('M1: a tracer built directly still flushes its buffer at exit', async (t) => {
  const app = await startFakeApp();
  t.after(() => app.close());

  // A child process so a real 'beforeExit' can run. It never calls flush() and
  // never calls getTracer(): the span lands only if the Tracer itself carries
  // the exit hook.
  const script = `
    import { Tracer, AppTransport, configFromEnv, generation } from ${JSON.stringify(DIST)};
    const cfg = configFromEnv({ baseUrl: process.env.SV_APP_URL }, {});
    const tracer = new Tracer(cfg, new AppTransport(cfg));
    const gen = await generation({ model: 'exit-hook', input: 'x', tracer });
    await gen.end({ output: 'y' });
  `;
  await run(process.execPath, ['--input-type=module', '-e', script], {
    env: { ...process.env, SV_APP_URL: app.url },
    timeout: 20000,
  });

  const names = spansOf(app).map((s) => s.name);
  assert.deepEqual(names, ['chat exit-hook'], 'the buffered span was flushed at exit');

  // Installing one hook per tracer would be its own bug.
  const before = process.listenerCount('beforeExit');
  const held = [tracerFor(app.url), tracerFor(app.url), tracerFor(app.url)];
  assert.equal(held.length, 3);
  assert.ok(
    process.listenerCount('beforeExit') - before <= 1,
    'the exit hook is installed at most once for the whole process',
  );
});

// --------------------------------------------------------------------------- //
// M2: the span clock must resolve below a millisecond                         //
// --------------------------------------------------------------------------- //

test('M2: span timestamps are sub-millisecond and still wall-clock correct', async (t) => {
  const app = await startFakeApp();
  t.after(() => app.close());
  const tracer = tracerFor(app.url);

  for (let i = 0; i < 8; i += 1) {
    const gen = await generation({ model: `m${i}`, input: 'x', tracer });
    await gen.end({ output: 'y' });
  }
  await tracer.flush();

  const spans = spansOf(app);
  assert.equal(spans.length, 8);

  const starts = spans.map((s) => BigInt(s.startTimeUnixNano));
  const subMs = starts.filter((ns) => ns % 1_000_000n !== 0n);
  assert.ok(
    subMs.length > 0,
    'a Date.now() clock quantises every timestamp to a whole millisecond',
  );

  for (const s of spans) {
    const start = BigInt(s.startTimeUnixNano);
    const end = BigInt(s.endTimeUnixNano);
    assert.ok(end >= start, 'the clock never goes backwards inside one span');
    const driftMs = Math.abs(Number(start / 1_000_000n) - Date.now());
    assert.ok(driftMs < 60_000, `absolute timestamps stay wall-clock correct (${driftMs} ms off)`);
  }
});

// --------------------------------------------------------------------------- //
// M3: the recordAudit comment must match the code                             //
// --------------------------------------------------------------------------- //

test('M3: the recordAudit comment does not contradict its only caller', async () => {
  const transport = await readFile(SRC('transport.ts'), 'utf8');
  const guardSrc = await readFile(SRC('guard.ts'), 'utf8');

  assert.ok(
    /await this\.transport\.recordAudit\(/.test(guardSrc),
    'guard() awaits recordAudit, which is the behaviour the comment must describe',
  );
  assert.ok(
    !/never awaited/i.test(transport),
    'the recordAudit comment must not claim it is never awaited',
  );
});
