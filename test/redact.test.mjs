// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  redact,
  redactForScan,
  hasCredentialMarkers,
  scanText,
  toText,
  PREVIEW_LIMIT,
  SCAN_LIMIT,
} from '../dist/esm/index.js';

test('redaction caps match the Python SDK numbers', () => {
  assert.equal(PREVIEW_LIMIT, 8192);
  assert.equal(SCAN_LIMIT, 102400);
});

test('redact caps a preview at PREVIEW_LIMIT', () => {
  const long = 'a'.repeat(PREVIEW_LIMIT * 2);
  assert.equal(redact(long).length, PREVIEW_LIMIT);
  assert.equal(redact(long, 100).length, 100);
});

test('scanText caps at SCAN_LIMIT, the app /analyze body cap', () => {
  const long = 'b'.repeat(SCAN_LIMIT + 5000);
  assert.equal(scanText(long).length, SCAN_LIMIT);
});

test('redact masks before it caps, so a secret at the tail cannot survive', () => {
  const secret = 'AKIA' + 'A'.repeat(16);
  const out = redact('x'.repeat(50) + ' ' + secret, 200);
  assert.ok(!out.includes(secret));
  assert.ok(out.includes('[REDACTED]'));
});

test('every leak shape from the plugin redactor is masked', () => {
  const cases = [
    ['sk-proj-' + 'A'.repeat(24), 'openai project key'],
    ['sk_live_' + 'b'.repeat(24), 'stripe live key'],
    ['sk-' + 'c'.repeat(24), 'openai / anthropic key'],
    ['ghp_' + 'd'.repeat(24), 'github pat'],
    ['AKIA' + 'E'.repeat(16), 'aws access key id'],
    ['aws_secret_access_key = "' + 'f'.repeat(40) + '"', 'aws secret'],
    ['eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.SflKxwRJSMeKKF2QT4', 'jwt'],
    ['password: hunter2hunter2', 'labelled kv pair'],
    ['api_key = "topsecretvalue123"', 'labelled api key'],
  ];
  for (const [raw, label] of cases) {
    const out = redactForScan(`before ${raw} after`);
    assert.ok(out.includes('[REDACTED]'), `${label} not masked: ${out}`);
    assert.ok(out.startsWith('before '), `${label} lost surrounding text`);
    assert.ok(hasCredentialMarkers(raw), `${label} not detected by hasCredentialMarkers`);
  }
});

test('a PEM private key block is masked whole', () => {
  const pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIB\n-----END RSA PRIVATE KEY-----';
  const out = redactForScan(`key=${pem}`);
  assert.ok(!out.includes('MIIEowIB'));
});

test('a labelled pair keeps its label so the preview still reads', () => {
  assert.equal(redactForScan('password: hunter2hunter2'), 'password: [REDACTED]');
});

test('hasCredentialMarkers is stateless across repeated calls', () => {
  const text = 'ghp_' + 'z'.repeat(24);
  for (let i = 0; i < 5; i += 1) {
    assert.equal(hasCredentialMarkers(text), true, `call ${i}`);
    assert.ok(redactForScan(text).includes('[REDACTED]'), `call ${i}`);
  }
});

test('clean text passes through untouched and non-strings degrade safely', () => {
  assert.equal(redactForScan('select 1 from dual'), 'select 1 from dual');
  assert.equal(hasCredentialMarkers('select 1 from dual'), false);
  assert.equal(redactForScan(null), '');
  assert.equal(redactForScan(42), '');
  assert.equal(hasCredentialMarkers(undefined), false);
});

test('toText serialises objects, handles cycles, and never throws', () => {
  assert.equal(toText('plain'), 'plain');
  assert.equal(toText(null), '');
  assert.equal(toText({ a: 1 }), '{"a":1}');
  const cyclic = { name: 'loop' };
  cyclic.self = cyclic;
  assert.doesNotThrow(() => toText(cyclic));
  assert.doesNotThrow(() => toText(new Map([['k', 'v']])));
  assert.equal(toText(new Map([['k', 'v']])), '{"k":"v"}');
  const angry = {
    toJSON() {
      throw new Error('no');
    },
  };
  assert.doesNotThrow(() => toText(angry));
});

test('redact serialises a structured argument before masking it', () => {
  const out = redact({ query: 'hi', token: 'supersecretvalue' });
  assert.ok(out.includes('[REDACTED]'));
  assert.ok(!out.includes('supersecretvalue'));
});
