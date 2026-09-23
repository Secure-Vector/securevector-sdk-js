# Changelog

All notable changes to `@securevector/sdk` are documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

## [6.0.2]

### Security

- **Endpoint slash trimming no longer backtracks.** Trailing slashes on
  `SECUREVECTOR_ENGINE_ENDPOINT` / `SECUREVECTOR_SDK_APP_URL` were removed with
  `/\/+$/`, which runs in quadratic time on a long run of slashes that is not at
  the end of the value (CodeQL `js/polynomial-redos`). It is a linear loop now.
  The input is a local environment variable, so the practical exposure was
  small.

### Added

- `SECURITY.md` with private reporting and how to verify provenance with
  `npm audit signatures`.

## [6.0.1]

Documentation and release plumbing. No change to what the SDK does at runtime.

### Changed

- **Requirements first.** The README now opens with what the SDK needs: Node 20
  or newer, and the SecureVector app running (`npx @securevector/cli` or
  `pip install "securevector-ai-monitor[app]"`), or a self-hosted engine.
- **`SECUREVECTOR_API_KEY` is documented as optional.** It is only for a public
  endpoint gated with an inbound token; the local app and a private endpoint
  need no key. The README explains how to create one for an engine hosted in
  your own cloud.
- **Publishing goes through GitHub Actions with trusted publishing and a manual
  approval**, from `main` only, with provenance on every release from this one on.

### Fixed

- The README's app install command was missing the `[app]` extra, and Quick
  start named `securevector` (this package's alias) as the command that starts
  the app.

## [6.0.0]

First release. Ships with SecureVector 6.0.0, and the version number tracks the
rest of the release so `@securevector/sdk@X` and the app at version X mean the
same thing.

### Added

- **`guard(fn, { toolId, mode, scanOutput })`** puts any function under
  SecureVector. Arguments are scanned outgoing, results incoming, and each call
  lands as one row in the local app's Tool Activity, Agent Runs and the
  tamper-evident audit chain. Sync and async functions are both accepted; the
  wrapper is always async.
- **`observe` and `enforce` modes.** `observe` records and always proceeds.
  `enforce` scans before the tool body runs and throws `GuardBlocked` on a
  finding at or above the risk threshold, so the tool never executes. A finding
  on the result is recorded, never thrown.
- **`GuardBlocked`** carries the tool id, the rule that fired, the risk score
  and the full verdict.
- **`session(id, { userId, tags, metadata }, fn)`** groups every guarded call
  and model call inside under one agent run, on `AsyncLocalStorage`, so two
  concurrent runs in one process never read each other's identity.
  **`setIdentity()`** does the same without nesting and returns a restore
  function.
- **`generation({ model, provider, input })`** with `.end({ output, usage })`
  traces a model call as an OTLP/HTTP JSON span using the OpenTelemetry GenAI
  semantic conventions, posted to `POST /v1/traces`. Tokens, cost, previews,
  duration, finish reason and a verdict land in Traces. Usage normalises from
  the OpenAI, Anthropic and Bedrock shapes as well as plain counts. A tool call
  made after a model turn nests under it.
- **Batched flushing** every 200 ms, at 200 buffered spans, and when the event
  loop drains. `flush()` is exported for short-lived processes.
- **Fail-open everywhere.** A timeout, a refused connection, a non-2xx or a
  malformed answer never throws and never blocks; one warning is logged per
  process, per endpoint.
- **Credential masking before anything leaves the process**, capped at 8192
  characters for a stored preview and 102400 for a scan body. The masked shapes
  match the agent-runtime plugins: API keys, GitHub and AWS credentials, JWTs,
  PEM private keys and labelled secret assignments.
- **Configuration from the environment**, using the same variable names and the
  same precedence as the Python SDK: `SECUREVECTOR_ENGINE_ENDPOINT`,
  `SECUREVECTOR_SDK_APP_URL`, `SECUREVECTOR_SDK_MODE`,
  `SECUREVECTOR_SDK_RISK_THRESHOLD`, `SECUREVECTOR_SDK_TIMEOUT_MS`,
  `SECUREVECTOR_SDK_DISABLED`, `SECUREVECTOR_API_KEY`. Every value can be
  overridden per call.
- **Dual ESM and CommonJS build with type declarations**, from TypeScript's own
  compiler with no bundler, so the published output can be read against the
  source.
- **Zero runtime dependencies.** The platform `fetch`, `node:async_hooks` and
  `node:crypto`, and nothing else.
- **`securevector`**, an unscoped one-line re-export of this package, so both
  spellings resolve. Source in `packages/alias/`.
