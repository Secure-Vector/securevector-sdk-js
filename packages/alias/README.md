# securevector

Unscoped alias for [`@securevector/sdk`](https://www.npmjs.com/package/@securevector/sdk).

```bash
npm install securevector
```

```js
import { guard, session, generation } from 'securevector';
```

This package contains three one-line files and a dependency on the scoped
package, so both spellings resolve to the same code. The scope is the owner
lock, so prefer `@securevector/sdk` in new projects. Everything, including the
docs, lives there.

## Install one, not both

Pick a spelling and keep it. Installing `securevector` **and**
`@securevector/sdk` in the same project can load two copies of the module: the
alias resolves through its own dependency, and a bundler or a mixed
ESM-and-CommonJS import graph can end up with one instance per entry point.

That matters more here than it would in most packages, because the state that
would be duplicated is the state that carries identity. Each copy gets its own
`AsyncLocalStorage`, its own config, its own tracer and its own transport, so a
`session()` opened through one spelling is invisible to a `guard()` called
through the other: the tool call still runs and is still audited, but it is
filed without the session and user it belonged to, and it will not nest under
its model turn. Nothing throws, so the only symptom is rows that look oddly
orphaned in the app.

If you have inherited both, drop the alias and import `@securevector/sdk`.

Apache-2.0.
