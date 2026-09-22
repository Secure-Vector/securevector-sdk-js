// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import {
  encodeOtlp,
  normalizeUsage,
  traceIdFor,
  newSpanId,
  RUNTIME_KIND,
  FLUSH_INTERVAL_MS,
  FLUSH_MAX_SPANS,
} from '../dist/esm/index.js';

function attr(span, key) {
  const found = span.attributes.find((a) => a.key === key);
  return found ? found.value : undefined;
}

const sampleSpan = {
  traceId: traceIdFor('sess-1'),
  spanId: 'aaaaaaaaaaaaaaaa',
  name: 'chat gpt-4o',
  kind: 'generation',
  parentSpanId: null,
  startNs: 1_700_000_000_000_000_000n,
  endNs: 1_700_000_000_500_000_000n,
  attributes: {
    'gen_ai.operation.name': 'chat',
    'gen_ai.request.model': 'gpt-4o',
    'gen_ai.system': 'openai',
    'session.id': 'sess-1',
    'gen_ai.usage.input_tokens': 120,
    'gen_ai.usage.output_tokens': 42,
    'session.tags': ['prod', 'checkout'],
    'securevector.dropped': null,
  },
  events: [{ name: 'gen_ai.content.prompt', timeNs: 1_700_000_000_000_000_000n, attributes: { 'gen_ai.prompt': 'hi' } }],
  statusError: null,
};

test('otlp: the batch envelope has the shape the ingest route expects', () => {
  const body = encodeOtlp([sampleSpan]);
  assert.ok(Array.isArray(body.resourceSpans));
  const rs = body.resourceSpans[0];
  const serviceName = rs.resource.attributes.find((a) => a.key === 'service.name');
  assert.equal(serviceName.value.stringValue, RUNTIME_KIND);
  assert.equal(rs.scopeSpans[0].scope.name, 'securevector');
  assert.equal(rs.scopeSpans[0].spans.length, 1);
});

test('otlp: span fields are strings for nanos and an int code for kind', () => {
  const span = encodeOtlp([sampleSpan]).resourceSpans[0].scopeSpans[0].spans[0];
  assert.equal(span.traceId, sampleSpan.traceId);
  assert.equal(span.spanId, 'aaaaaaaaaaaaaaaa');
  assert.equal(span.name, 'chat gpt-4o');
  assert.equal(span.kind, 3); // CLIENT
  assert.equal(span.startTimeUnixNano, '1700000000000000000');
  assert.equal(span.endTimeUnixNano, '1700000000500000000');
  assert.equal(span.parentSpanId, undefined);
  assert.equal(span.status, undefined);
});

test('otlp: a tool span is INTERNAL and an error span carries status code 2', () => {
  const [tool] = encodeOtlp([{ ...sampleSpan, kind: 'tool' }]).resourceSpans[0].scopeSpans[0].spans;
  assert.equal(tool.kind, 1);
  const [errored] = encodeOtlp([{ ...sampleSpan, statusError: 'TypeError: nope' }]).resourceSpans[0]
    .scopeSpans[0].spans;
  assert.deepEqual(errored.status, { code: 2, message: 'TypeError: nope' });
});

test('otlp: AnyValue typing matches the Python encoder', () => {
  const span = encodeOtlp([sampleSpan]).resourceSpans[0].scopeSpans[0].spans[0];
  // Ints are strings inside intValue, exactly as OTLP/JSON requires.
  assert.deepEqual(attr(span, 'gen_ai.usage.input_tokens'), { intValue: '120' });
  assert.deepEqual(attr(span, 'gen_ai.request.model'), { stringValue: 'gpt-4o' });
  assert.deepEqual(attr(span, 'session.tags'), {
    arrayValue: { values: [{ stringValue: 'prod' }, { stringValue: 'checkout' }] },
  });
  // Null attributes are dropped rather than encoded.
  assert.equal(attr(span, 'securevector.dropped'), undefined);
});

test('otlp: floats and booleans get their own AnyValue keys', () => {
  const span = encodeOtlp([
    { ...sampleSpan, attributes: { ratio: 0.25, cached: true, whole: 7 } },
  ]).resourceSpans[0].scopeSpans[0].spans[0];
  assert.deepEqual(attr(span, 'ratio'), { doubleValue: 0.25 });
  assert.deepEqual(attr(span, 'cached'), { boolValue: true });
  assert.deepEqual(attr(span, 'whole'), { intValue: '7' });
});

test('otlp: events carry their own timestamp and attributes', () => {
  const span = encodeOtlp([sampleSpan]).resourceSpans[0].scopeSpans[0].spans[0];
  assert.equal(span.events.length, 1);
  assert.equal(span.events[0].name, 'gen_ai.content.prompt');
  assert.equal(span.events[0].timeUnixNano, '1700000000000000000');
  assert.deepEqual(span.events[0].attributes[0], {
    key: 'gen_ai.prompt',
    value: { stringValue: 'hi' },
  });
});

test('otlp: an unfinished span falls back to its start time', () => {
  const span = encodeOtlp([{ ...sampleSpan, endNs: 0n }]).resourceSpans[0].scopeSpans[0].spans[0];
  assert.equal(span.endTimeUnixNano, span.startTimeUnixNano);
});

test('otlp: the whole body is JSON-serialisable, with nanos as digit strings', () => {
  // JSON.stringify throws on a bigint, so this passing is the proof that every
  // nanosecond value was converted to a string before encoding.
  const body = encodeOtlp([sampleSpan]);
  const json = assert.doesNotThrow(() => JSON.stringify(body)) ?? JSON.stringify(body);
  assert.ok(json.includes('"resourceSpans"'));
  const span = JSON.parse(json).resourceSpans[0].scopeSpans[0].spans[0];
  assert.match(span.startTimeUnixNano, /^\d+$/);
  assert.match(span.endTimeUnixNano, /^\d+$/);
  assert.match(span.events[0].timeUnixNano, /^\d+$/);
});

test('trace id: matches the app derivation sha256("<runtime>:<session>")[:32]', () => {
  const expected = createHash('sha256').update(`${RUNTIME_KIND}:sess-1`, 'utf8').digest('hex').slice(0, 32);
  assert.equal(traceIdFor('sess-1'), expected);
  assert.equal(traceIdFor('sess-1').length, 32);
  assert.equal(newSpanId().length, 16);
  assert.match(newSpanId(), /^[0-9a-f]{16}$/);
});

test('flush constants match the Python tracer', () => {
  assert.equal(FLUSH_INTERVAL_MS, 200); // FLUSH_INTERVAL_S = 0.2
  assert.equal(FLUSH_MAX_SPANS, 200);
});

test('usage: every provider spelling normalises to the same three counts', () => {
  assert.deepEqual(normalizeUsage(null), { input: 0, output: 0, cacheRead: 0 });
  assert.deepEqual(normalizeUsage({ input: 3, output: 4 }), { input: 3, output: 4, cacheRead: 0 });
  assert.deepEqual(normalizeUsage({ prompt_tokens: 10, completion_tokens: 2 }), {
    input: 10,
    output: 2,
    cacheRead: 0,
  });
  assert.deepEqual(normalizeUsage({ input_tokens: 9, output_tokens: 1, cache_read_input_tokens: 5 }), {
    input: 9,
    output: 1,
    cacheRead: 5,
  });
  assert.deepEqual(normalizeUsage({ inputTokens: 6, outputTokens: 7 }), {
    input: 6,
    output: 7,
    cacheRead: 0,
  });
  assert.deepEqual(
    normalizeUsage({ prompt_tokens: 8, completion_tokens: 0, prompt_tokens_details: { cached_tokens: 4 } }),
    { input: 8, output: 0, cacheRead: 4 },
  );
});
