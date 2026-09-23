// SPDX-License-Identifier: Apache-2.0
/**
 * The security review's findings, each pinned by the case that proved it.
 *
 * Every test here failed before the fix beside it. They are grouped in one
 * file on purpose: these are the behaviours that make this package safe to put
 * in someone else's agent, and a reviewer should be able to read the whole set
 * without opening five files.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  AppTransport,
  Tracer,
  generation,
  configFromEnv,
  isRemoteEndpoint,
  redactForScan,
  setWarner,
  resetWarnings,
  getTransport,
  resetTransports,
  SCAN_LIMIT,
} from '../dist/esm/index.js';
import { startFakeApp, cleanBody } from './helpers/fake-app.mjs';

function captureWarnings() {
  const seen = [];
  resetWarnings();
  setWarner((m) => seen.push(m));
  return {
    seen,
    done() {
      setWarner(null);
      resetWarnings();
    },
  };
}

// --- a secret that straddles the scan cap ------------------------------------
//
// redact() masks and then caps. Capping FIRST cut a JWT's third segment down
// to five characters, below the ten the pattern needs, so the mangled token
// went out verbatim inside gen_ai.content.prompt.

test('a secret straddling the scan cap is masked, not cut in half and shipped', async () => {
  const jwt = `eyJ${'A'.repeat(30)}.${'B'.repeat(30)}.${'C'.repeat(30)}`;
  const input = 'x'.repeat(SCAN_LIMIT - 70) + jwt;

  // The property the fix rests on, stated directly.
  assert.ok(redactForScan(input).includes('[REDACTED]'), 'full text should mask');
  assert.ok(!redactForScan(input).includes('CCCCC'), 'no tail should survive');

  const app = await startFakeApp(() => cleanBody());
  try {
    const cfg = configFromEnv({ baseUrl: app.url, mode: 'observe' });
    const tracer = new Tracer(cfg, new AppTransport(cfg));
    const gen = await generation({ model: 'm', provider: 'p', input, tracer });
    await gen.end({ output: 'ok', usage: { prompt_tokens: 1, completion_tokens: 1 } });
    await tracer.flush();

    const traces = app.requests.filter((r) => r.path === '/v1/traces');
    assert.equal(traces.length, 1, 'one batch should have been posted');
    const wire = JSON.stringify(traces[0].body);
    assert.ok(!wire.includes('eyJAAAA'), 'the JWT head must not reach the wire');
    assert.ok(!wire.includes('CCCCCCCCCC'), 'nor its tail');
    assert.ok(wire.includes('[REDACTED]'), 'it should be masked instead');
  } finally {
    await app.close();
  }
});

test('a completion that straddles the cap is masked too', async () => {
  const key = `sk-proj-${'Z'.repeat(40)}`;
  const output = 'y'.repeat(SCAN_LIMIT - 20) + key;
  const app = await startFakeApp(() => cleanBody());
  try {
    const cfg = configFromEnv({ baseUrl: app.url, mode: 'observe' });
    const tracer = new Tracer(cfg, new AppTransport(cfg));
    const gen = await generation({ model: 'm', provider: 'p', input: 'hello', tracer });
    await gen.end({ output, usage: { prompt_tokens: 1, completion_tokens: 1 } });
    await tracer.flush();
    const wire = JSON.stringify(app.requests.filter((r) => r.path === '/v1/traces')[0].body);
    assert.ok(!wire.includes('sk-proj-ZZZZ'), 'the key must not reach the wire');
  } finally {
    await app.close();
  }
});

// --- a mode that is not a mode ----------------------------------------------
//
// SECUREVECTOR_SDK_MODE=enfroce used to resolve to observe with nothing said,
// so an operator who believed enforce was on had no way to find out.

test('a misspelled mode falls back to observe and says so', () => {
  const w = captureWarnings();
  try {
    const cfg = configFromEnv({}, { SECUREVECTOR_SDK_MODE: 'enfroce' });
    assert.equal(cfg.mode, 'observe');
    assert.equal(w.seen.length, 1, `expected one warning, got ${JSON.stringify(w.seen)}`);
    assert.match(w.seen[0], /enfroce/);
    assert.match(w.seen[0], /nothing will be blocked/);
  } finally {
    w.done();
  }
});

test('an unset mode is the default and warns about nothing', () => {
  const w = captureWarnings();
  try {
    assert.equal(configFromEnv({}, {}).mode, 'observe');
    assert.deepEqual(w.seen, []);
  } finally {
    w.done();
  }
});

test('the two real modes are accepted in any casing, silently', () => {
  const w = captureWarnings();
  try {
    assert.equal(configFromEnv({}, { SECUREVECTOR_SDK_MODE: 'ENFORCE' }).mode, 'enforce');
    assert.equal(configFromEnv({}, { SECUREVECTOR_SDK_MODE: ' observe ' }).mode, 'observe');
    assert.deepEqual(w.seen, []);
  } finally {
    w.done();
  }
});

// --- previews leaving the machine -------------------------------------------
//
// Pointing at a self-hosted engine is supported. Doing it without anyone
// noticing is what an env var written by a hostile repository would look like.

test('a remote endpoint is announced, once, naming the host', () => {
  const w = captureWarnings();
  try {
    configFromEnv({}, { SECUREVECTOR_ENGINE_ENDPOINT: 'https://engine.example.com' });
    assert.equal(w.seen.length, 1);
    assert.match(w.seen[0], /engine\.example\.com/);
    assert.match(w.seen[0], /not this machine/);
    configFromEnv({}, { SECUREVECTOR_ENGINE_ENDPOINT: 'https://engine.example.com' });
    assert.equal(w.seen.length, 1, 'the same warning should not repeat');
  } finally {
    w.done();
  }
});

test('a remote endpoint on plain HTTP says the previews travel in the clear', () => {
  const w = captureWarnings();
  try {
    configFromEnv({}, { SECUREVECTOR_ENGINE_ENDPOINT: 'http://attacker.tld' });
    assert.match(w.seen[0], /in the clear/);
  } finally {
    w.done();
  }
});

test('loopback in every spelling stays quiet', () => {
  const w = captureWarnings();
  try {
    for (const url of ['http://127.0.0.1:8741', 'http://localhost:8741', 'http://[::1]:8741']) {
      configFromEnv({}, { SECUREVECTOR_ENGINE_ENDPOINT: url });
      assert.equal(isRemoteEndpoint(url), false, url);
    }
    assert.deepEqual(w.seen, []);
  } finally {
    w.done();
  }
});

// --- a redirect is a forwarding address --------------------------------------
//
// 307 and 308 preserve the method AND the body, so following one hands the
// prompt to whatever the engine names.

test('the client refuses a redirect rather than forwarding the body', async () => {
  const app = await startFakeApp((record) => {
    if (record.path === '/analyze') {
      return { status: 307, headers: { Location: 'http://127.0.0.1:1/steal' } };
    }
    return cleanBody();
  });
  try {
    resetTransports();
    const transport = getTransport(configFromEnv({ baseUrl: app.url }));
    await assert.rejects(() => transport.post('/analyze', { text: 'hello' }));
  } finally {
    resetTransports();
    await app.close();
  }
});

// --- an engine that answers with a lake --------------------------------------

test('an oversized engine reply is refused instead of held in memory', async () => {
  const app = await startFakeApp(() => ({ status: 200, body: { pad: 'a'.repeat(9 * 1024 * 1024) } }));
  try {
    resetTransports();
    const transport = getTransport(configFromEnv({ baseUrl: app.url }));
    await assert.rejects(() => transport.post('/analyze', { text: 'hello' }), /larger than/);
  } finally {
    resetTransports();
    await app.close();
  }
});

// --- an engine that is gone for an hour --------------------------------------

test('a dead engine stops being retried, and the spans are dropped not queued', async () => {
  const cfg = configFromEnv({ baseUrl: 'http://127.0.0.1:1', mode: 'observe', timeoutMs: 50 });
  const tracer = new Tracer(cfg, new AppTransport(cfg));
  const w = captureWarnings();
  try {
    for (let i = 0; i < 40; i += 1) {
      tracer.record({
        kind: 'tool',
        name: `t${i}`,
        startNs: 1,
        endNs: 2,
        attributes: {},
        events: [],
        sessionId: 's',
        requestId: 'r',
        spanId: `00000000000000${String(i).padStart(2, '0')}`,
      });
      await tracer.flush();
    }
    assert.ok(tracer.droppedSpans > 0, 'spans should be dropped once the engine is gone');
    assert.equal(tracer.pending, 0, 'nothing should still be buffered');
  } finally {
    w.done();
  }
});

// --- the shapes the list was missing ------------------------------------------

test('the leak shapes added after review are masked with no residue', () => {
  const cases = {
    'a long labelled value': `password=${'a'.repeat(300)}`,
    // Assembled at runtime, never a literal: GitHub push protection matches
    // the Slack shape without a checksum, so a fake written out in full is
    // indistinguishable from a real one and blocks the push. The Stripe
    // fixture below it has always been built this way for the same reason.
    slack: ['xoxb', '1234567890', 'abcdefghijklmnop'].join('-'),
    google: `AIza${'A'.repeat(35)}`,
    npm: `npm_${'a'.repeat(36)}`,
    gitlab: `glpat-${'a'.repeat(22)}`,
    sendgrid: `SG.${'a'.repeat(20)}.${'b'.repeat(20)}`,
  };
  for (const [name, input] of Object.entries(cases)) {
    const out = redactForScan(input);
    assert.ok(out.includes('[REDACTED]'), `${name} should be masked, got ${out}`);
    const residue = out.replace('[REDACTED]', '').replace(/^[a-z=_.]*/i, '');
    assert.equal(residue, '', `${name} left ${JSON.stringify(residue)} in the clear`);
  }
});

test('an unbounded labelled value is still linear to redact', () => {
  const started = Date.now();
  redactForScan(`password=${'x'.repeat(400000)}`);
  assert.ok(Date.now() - started < 1000, 'redaction should not blow up on a long value');
});

test('an endpoint that is not a URL falls back to the local app, as the plugins do', () => {
  // The two halves used to differ: the plugins fell back and said so, the SDK
  // kept the garbage string and let every request fail against it.
  const w = captureWarnings();
  try {
    const cfg = configFromEnv({}, { SECUREVECTOR_ENGINE_ENDPOINT: 'not a url at all' });
    assert.equal(cfg.baseUrl, 'http://127.0.0.1:8741');
    assert.match(w.seen[0], /is not a URL/);
  } finally {
    w.done();
  }
});
