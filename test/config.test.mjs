// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  configFromEnv,
  DEFAULT_APP_URL,
  DEFAULT_RISK_THRESHOLD,
  DEFAULT_TIMEOUT_MS,
} from '../dist/esm/index.js';

test('config: defaults when the environment is empty', () => {
  const cfg = configFromEnv({}, {});
  assert.equal(cfg.baseUrl, DEFAULT_APP_URL);
  assert.equal(cfg.mode, 'observe');
  assert.equal(cfg.timeoutMs, DEFAULT_TIMEOUT_MS);
  assert.equal(cfg.threatRiskThreshold, DEFAULT_RISK_THRESHOLD);
  assert.equal(cfg.enabled, true);
  assert.equal(cfg.apiKey, '');
});

test('config: ENGINE_ENDPOINT wins over SDK_APP_URL', () => {
  const cfg = configFromEnv(
    {},
    {
      SECUREVECTOR_ENGINE_ENDPOINT: 'https://engine.example/',
      SECUREVECTOR_SDK_APP_URL: 'http://127.0.0.1:9999',
    },
  );
  assert.equal(cfg.baseUrl, 'https://engine.example');
});

test('config: SDK_APP_URL is used when ENGINE_ENDPOINT is absent or empty', () => {
  assert.equal(
    configFromEnv({}, { SECUREVECTOR_SDK_APP_URL: 'http://host:1/' }).baseUrl,
    'http://host:1',
  );
  assert.equal(
    configFromEnv(
      {},
      { SECUREVECTOR_ENGINE_ENDPOINT: '', SECUREVECTOR_SDK_APP_URL: 'http://host:2' },
    ).baseUrl,
    'http://host:2',
  );
});

test('config: mode is normalised and an unknown mode falls back to observe', () => {
  assert.equal(configFromEnv({}, { SECUREVECTOR_SDK_MODE: '  ENFORCE ' }).mode, 'enforce');
  assert.equal(configFromEnv({}, { SECUREVECTOR_SDK_MODE: 'paranoid' }).mode, 'observe');
});

test('config: SDK_DISABLED accepts the same truthy spellings as Python', () => {
  for (const v of ['1', 'true', 'YES', ' on ']) {
    assert.equal(configFromEnv({}, { SECUREVECTOR_SDK_DISABLED: v }).enabled, false, v);
  }
  for (const v of ['0', 'false', '', 'no']) {
    assert.equal(configFromEnv({}, { SECUREVECTOR_SDK_DISABLED: v }).enabled, true, v);
  }
});

test('config: numeric vars parse, and garbage falls back to the default', () => {
  const cfg = configFromEnv(
    {},
    { SECUREVECTOR_SDK_TIMEOUT_MS: '500', SECUREVECTOR_SDK_RISK_THRESHOLD: '90' },
  );
  assert.equal(cfg.timeoutMs, 500);
  assert.equal(cfg.threatRiskThreshold, 90);
  assert.equal(configFromEnv({}, { SECUREVECTOR_SDK_TIMEOUT_MS: 'soon' }).timeoutMs, DEFAULT_TIMEOUT_MS);
});

test('config: the API key is read and explicit overrides beat the environment', () => {
  const cfg = configFromEnv(
    { mode: 'enforce', timeoutMs: 1234 },
    { SECUREVECTOR_API_KEY: 'svet_abc', SECUREVECTOR_SDK_MODE: 'observe' },
  );
  assert.equal(cfg.apiKey, 'svet_abc');
  assert.equal(cfg.mode, 'enforce');
  assert.equal(cfg.timeoutMs, 1234);
});

test('trailing slashes are trimmed in linear time', async () => {
  const { trimTrailingSlashes } = await import('../dist/esm/config.js');
  assert.equal(trimTrailingSlashes('http://127.0.0.1:8741///'), 'http://127.0.0.1:8741');
  assert.equal(trimTrailingSlashes('http://127.0.0.1:8741'), 'http://127.0.0.1:8741');
  assert.equal(trimTrailingSlashes('///'), '');
  const hostile = 'http://h' + '/'.repeat(200000) + 'x';
  const t0 = process.hrtime.bigint();
  assert.equal(trimTrailingSlashes(hostile), hostile);
  assert.ok(Number(process.hrtime.bigint() - t0) / 1e6 < 50, 'should be linear');
});
