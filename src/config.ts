// SPDX-License-Identifier: Apache-2.0
/**
 * Configuration, read once from the environment.
 *
 * The variable names and the precedence between them are the same as the
 * Python SDK and the per-framework SDKs, so an agent that mixes runtimes is
 * configured once for all of them.
 *
 *   SECUREVECTOR_ENGINE_ENDPOINT / SECUREVECTOR_SDK_APP_URL  app or self-hosted engine URL
 *   SECUREVECTOR_SDK_MODE            observe (default) | enforce
 *   SECUREVECTOR_SDK_RISK_THRESHOLD  risk score at or above which enforce blocks (70)
 *   SECUREVECTOR_SDK_TIMEOUT_MS      per-request timeout (3000)
 *   SECUREVECTOR_SDK_DISABLED        1 turns the SDK into a no-op
 *   SECUREVECTOR_API_KEY             optional; sent as a bearer token only when set, for a public endpoint gated with an inbound token
 */

import { warnOnce } from './warn.js';

/** Where the local app listens by default. */
export const DEFAULT_APP_URL = 'http://127.0.0.1:8741';

/**
 * Which agent runtime emitted a row. Namespaces the derived trace id server
 * side, so a Node session and a Python session can never collide on the same
 * session string. Also the OTLP `service.name` of every batch.
 */
export const RUNTIME_KIND = 'node';

/** Cap on a preview stored by the app. Same number as the Python SDK. */
export const PREVIEW_LIMIT = 8192;

/** Cap on a body sent to /analyze. Same number as the app's own limit. */
export const SCAN_LIMIT = 102400;

/** Default per-request timeout in milliseconds. */
export const DEFAULT_TIMEOUT_MS = 3000;

/** Default risk score at or above which enforce mode blocks. */
export const DEFAULT_RISK_THRESHOLD = 70;

/** observe records and always proceeds. enforce can block before the call. */
export type Mode = 'observe' | 'enforce';

export interface GuardConfig {
  /** Base URL of the local app or a self-hosted engine, no trailing slash. */
  baseUrl: string;
  mode: Mode;
  timeoutMs: number;
  threatRiskThreshold: number;
  /** False turns every entry point into a no-op. */
  enabled: boolean;
  /** Sent as `Authorization: Bearer` when non-empty. */
  apiKey: string;
}

/** Fields a caller may override on top of the environment. */
export type ConfigOverrides = Partial<GuardConfig>;

type Env = Record<string, string | undefined>;

function truthy(value: string | undefined): boolean {
  if (value === undefined) return false;
  return ['1', 'true', 'yes', 'on'].includes(String(value).trim().toLowerCase());
}

const LOOPBACK = new Set(['127.0.0.1', 'localhost', '::1', '[::1]', '0.0.0.0']);

/** True when the endpoint is not on this machine. */
export function isRemoteEndpoint(baseUrl: string): boolean {
  try {
    return !LOOPBACK.has(new URL(baseUrl).hostname.replace(/^\[|\]$/g, '') || '');
  } catch {
    return false;
  }
}

/**
 * Say out loud, once, that previews are leaving this machine.
 *
 * Pointing the SDK at a self-hosted engine is a supported thing to do, so this
 * does not refuse. It does refuse to be quiet: prompts and tool arguments go
 * to the named host, and plain HTTP to a remote host sends them in the clear.
 */
function noteEndpoint(baseUrl: string): string {
  let url: URL;
  try {
    url = new URL(baseUrl);
  } catch {
    // Same answer the plugins give: a value that is not a URL is a
    // misconfiguration, and falling back to the local app with a word about
    // it beats failing every request against a string nothing can parse.
    warnOnce(
      `the SecureVector endpoint "${baseUrl}" is not a URL. Falling back to ${DEFAULT_APP_URL}.`,
    );
    return DEFAULT_APP_URL;
  }
  if (!isRemoteEndpoint(baseUrl)) return baseUrl;
  const insecure = url.protocol !== 'https:';
  warnOnce(
    `prompts and tool arguments are being sent to ${url.host}, which is not this machine. ` +
      (insecure ? 'The connection is plain HTTP, so they travel in the clear. ' : '') +
      'Unset SECUREVECTOR_ENGINE_ENDPOINT to keep everything local.',
  );
  return baseUrl;
}

function intOr(value: string | undefined, fallback: number): number {
  if (value === undefined || value === '') return fallback;
  const n = Number.parseInt(String(value).trim(), 10);
  return Number.isFinite(n) ? n : fallback;
}

/**
 * Build a config from the environment, then apply `overrides`.
 *
 * Precedence for the endpoint matches the Python SDK exactly: a non-empty
 * `SECUREVECTOR_ENGINE_ENDPOINT` wins, otherwise `SECUREVECTOR_SDK_APP_URL` is
 * used when it is set at all, otherwise the local app default.
 */
export function configFromEnv(overrides: ConfigOverrides = {}, env: Env = process.env): GuardConfig {
  const engine = env.SECUREVECTOR_ENGINE_ENDPOINT;
  const appUrl = env.SECUREVECTOR_SDK_APP_URL;
  const baseUrl = engine ? engine : appUrl !== undefined ? appUrl : DEFAULT_APP_URL;

  const cfg: GuardConfig = {
    baseUrl,
    mode: (env.SECUREVECTOR_SDK_MODE ?? 'observe').trim().toLowerCase() as Mode,
    timeoutMs: intOr(env.SECUREVECTOR_SDK_TIMEOUT_MS, DEFAULT_TIMEOUT_MS),
    threatRiskThreshold: intOr(env.SECUREVECTOR_SDK_RISK_THRESHOLD, DEFAULT_RISK_THRESHOLD),
    enabled: !truthy(env.SECUREVECTOR_SDK_DISABLED),
    apiKey: env.SECUREVECTOR_API_KEY ?? '',
  };

  for (const [key, value] of Object.entries(overrides)) {
    if (value !== undefined && value !== null && key in cfg) {
      (cfg as unknown as Record<string, unknown>)[key] = value;
    }
  }

  if (cfg.mode !== 'observe' && cfg.mode !== 'enforce') {
    const given = env.SECUREVECTOR_SDK_MODE;
    if (given !== undefined && String(given).trim() !== '') {
      warnOnce(
        `SECUREVECTOR_SDK_MODE is "${String(given).trim()}", which is not a mode. ` +
          'Falling back to observe, so nothing will be blocked. Set it to observe or enforce.',
      );
    }
    cfg.mode = 'observe';
  }
  cfg.baseUrl = cfg.baseUrl.replace(/\/+$/, '');
  cfg.baseUrl = noteEndpoint(cfg.baseUrl);
  return cfg;
}

let processConfig: GuardConfig | null = null;

/** The process-wide config. Read from the environment on first use. */
export function getConfig(): GuardConfig {
  if (processConfig === null) processConfig = configFromEnv();
  return processConfig;
}

/**
 * Replace the process-wide config, for code that configures the SDK itself
 * rather than through the environment. Pass nothing to re-read the environment
 * on the next call.
 */
export function setConfig(cfg?: GuardConfig | null): void {
  processConfig = cfg ?? null;
}
