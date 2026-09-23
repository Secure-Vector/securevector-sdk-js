# SecureVector SDK for Node

[![npm](https://img.shields.io/npm/v/@securevector/sdk)](https://www.npmjs.com/package/@securevector/sdk)
[![Node](https://img.shields.io/badge/node-20%2B-blue)](https://nodejs.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)

> Security and observability for AI agents, for TypeScript and JavaScript.
> Every tool call gets a verdict, every model call gets a trace with tokens and
> cost, and both land in the SecureVector local app grouped by agent run.
> One import, no OpenTelemetry setup, **zero runtime dependencies**.

```bash
npm install @securevector/sdk
```

## Requirements

| | |
|---|---|
| **Node** | 20 or newer |
| **The SecureVector app, running** | This package is a client. Verdicts, rules, the audit chain and the Traces page live in the app at `http://127.0.0.1:8741`. Start it with `npx @securevector/cli` (needs Python 3.10+ on PATH) or `pip install "securevector-ai-monitor[app]" && securevector-app --web`. Or point `SECUREVECTOR_ENGINE_ENDPOINT` at your own engine. |

With no app listening, the SDK fails open: your agent runs normally, unscanned,
and one warning is logged. Details in [The app must be running](#the-app-must-be-running).

## Zero runtime dependencies

This package declares no `dependencies`. Installing it adds exactly one package
to your tree, which you can check yourself:

```bash
npm install @securevector/sdk
npm ls --all @securevector/sdk
```

Everything it uses ships with Node: the platform `fetch`, `node:async_hooks`
for run context, and `node:crypto` for span ids. TypeScript and `@types/node`
are development dependencies of this repo and are not installed with the
package. That matters because this is a security control: a control with a
transitive dependency tree is a control with someone else's supply chain
attached to it.

## Quick start

With the app running (see [Requirements](#requirements)), three calls. Nothing
else is required.

```ts
import { guard, session, generation } from '@securevector/sdk';

// 1. Put a tool under SecureVector. Arguments are scanned on the way in,
//    results on the way out, and each call becomes one audited row.
const searchInvoices = guard(
  async ({ customer }: { customer: string }) => db.query(customer),
  { toolId: 'billing.search', mode: 'enforce' },
);

// 2. Group one agent run under one id and one identity.
await session('run-2026-0142', { userId: 'u_918', tags: ['prod'] }, async () => {
  // 3. Trace the model call. Tokens, cost, previews, duration and a verdict.
  const gen = await generation({
    model: 'gpt-4o',
    provider: 'openai',
    input: messages,
  });

  const res = await openai.chat.completions.create({ model: 'gpt-4o', messages });

  await gen.end({
    output: res.choices[0].message,
    usage: res.usage,
    finishReason: res.choices[0].finish_reason,
  });

  // The tool call nests under the model turn that asked for it.
  await searchInvoices({ customer: 'acme' });
});
```

Open the local app and the run is there: the model turn with its cost, the tool
call underneath it, and a verdict on each.

### observe and enforce

`mode` is `observe` by default.

- **observe** records the call and always lets it proceed. Use it first, on
  everything, to see what your agent actually does.
- **enforce** scans before the tool body runs. A finding at or above the risk
  threshold throws `GuardBlocked` and the tool never executes. A finding on the
  *result* is always recorded and never thrown, because the result already
  exists by then.

```ts
import { GuardBlocked } from '@securevector/sdk';

try {
  await runShell({ command: userSuppliedCommand });
} catch (err) {
  if (err instanceof GuardBlocked) {
    console.error(`blocked by ${err.rule} at risk ${err.riskScore}`);
  } else {
    throw err;
  }
}
```

### Fail-open, always

If the app is not running, times out, or answers with an error, the SDK logs one
warning per process and gets out of the way. Your agent finishes normally. A
security control that takes the agent down when it cannot reach its backend is
worse than no control at all, so this is a hard rule, not a setting.

`GuardBlocked` is the only error this SDK throws on purpose.

### Identity without nesting

When wrapping the work in a callback is not possible, set the identity directly:

```ts
import { setIdentity } from '@securevector/sdk';

const restore = setIdentity({ sessionId: 'run-2026-0142', userId: 'u_918' });
// ... run the agent ...
restore();
```

### Flushing

Spans are batched and flushed every 200 ms, at 200 spans, and when the event
loop drains at the end of the process. A process that calls `process.exit()` skips that last one, so flush
explicitly in a short-lived script or a serverless handler:

```ts
import { flush } from '@securevector/sdk';
await flush();
```

## The app must be running

The SDK is a thin interception layer. The detection engine, the rules, the
tamper-evident audit chain and the Traces page all live in the SecureVector
local app, which must be running at `http://127.0.0.1:8741`:

```bash
npx @securevector/cli                 # Node route, needs Python 3.10+ on PATH
# or
pip install "securevector-ai-monitor[app]"
securevector-app --web
```

Pointing at a self-hosted engine instead of a local app needs one variable:

```bash
export SECUREVECTOR_ENGINE_ENDPOINT=https://your-securevector-endpoint
# Only if that endpoint is publicly exposed and gated with an inbound token.
export SECUREVECTOR_API_KEY=<SecureVector account key or SVET token>
```

## Environment variables

| Variable | Default | What it does |
| --- | --- | --- |
| `SECUREVECTOR_ENGINE_ENDPOINT` | unset | App or self-hosted engine URL. Wins over `SECUREVECTOR_SDK_APP_URL`. |
| `SECUREVECTOR_SDK_APP_URL` | `http://127.0.0.1:8741` | Same thing, used when the one above is unset or empty. |
| `SECUREVECTOR_SDK_MODE` | `observe` | `observe` or `enforce`. Any other value falls back to `observe` and logs a warning saying so. |
| `SECUREVECTOR_SDK_RISK_THRESHOLD` | `70` | Risk score at or above which enforce mode blocks. |
| `SECUREVECTOR_SDK_TIMEOUT_MS` | `3000` | Per-request timeout. A timeout is a fail-open, never a block. |
| `SECUREVECTOR_SDK_DISABLED` | unset | `1`, `true`, `yes` or `on` turns the whole SDK into a pass-through. |
| `SECUREVECTOR_API_KEY` | unset | Sent as `Authorization: Bearer` to a self-hosted engine. |

The names and their precedence match the Python SDK and the per-framework SDKs,
so one set of variables configures an agent fleet that mixes runtimes.

Anything set in the environment can be overridden per call:

```ts
const tool = guard(fn, { toolId: 'db.query', mode: 'enforce', scanOutput: false });
```

## What goes on the wire

Previews are masked for credential shapes, then capped, before they leave the
process: 8192 characters for a stored preview, 102400 for a scan body. The
masked shapes are API keys, GitHub and AWS credentials, JWTs, PEM private keys
and labelled secret assignments, the same list the agent-runtime plugins use.
The app masks again on its side.

Traffic goes only to the local app or to the endpoint you set. The SDK has no
telemetry of its own. When that endpoint is not this machine, the SDK names the
host in a warning before the first preview leaves, and says so again if the
connection is plain HTTP.

## API

| Export | What it is |
| --- | --- |
| `guard(fn, opts)` | Wrap a function. Returns an async function with the same arguments. |
| `GuardBlocked` | The error enforce mode throws. Carries `toolId`, `rule`, `reason`, `riskScore`, `verdict`. |
| `session(id, [opts], fn)` | Run `fn` with one session id, and optionally `userId` and `tags`. |
| `setIdentity(opts)`, `clearIdentity()` | The same, without nesting. `setIdentity` returns a restore function. |
| `generation(opts)` | Open a model-call span. Await it, then `.end({ output, usage })`. |
| `flush()` | Send buffered spans now. |
| `currentSession()`, `currentGenerationSpan()`, `identity()` | Read the run context. |
| `encodeOtlp()`, `normalizeUsage()`, `traceIdFor()` | The encoder internals, exported for testing. |
| `configFromEnv()`, `getConfig()`, `setConfig()` | Configure in code instead of the environment. |
| `redact()`, `redactForScan()`, `hasCredentialMarkers()` | The masking used on previews. |

Spans are OTLP/HTTP JSON using the OpenTelemetry GenAI semantic conventions and
are posted to `POST /v1/traces`. The same endpoint accepts traces from any
OpenTelemetry exporter, so an agent that is already instrumented can skip
`generation()` entirely and keep its existing pipeline.

## The unscoped name

`securevector` on npm is a one-line re-export of this package, so both spellings
resolve:

```bash
npm install securevector
```

The scoped `@securevector/sdk` is the real package and the owner lock. Prefer it
in new projects. The alias source is in `packages/alias/` in this repo.

Install one or the other, never both. Two copies of the module means two
`AsyncLocalStorage` instances, so a `session()` opened through one spelling is
invisible to a `guard()` called through the other: the call is still audited,
but without the session and user it belonged to, and nothing throws to tell you.

## Development

```bash
npm install
npm run build     # ESM, CJS and .d.ts, from TypeScript's own compiler
npm test          # builds, then runs the unit suite on node --test
npm run test:live # end to end against a running local app, skips if none
```

The dual build uses two tsconfigs and no bundler, so the published output is the
compiler's and can be read line by line against the source.

Apache-2.0.
