// SPDX-License-Identifier: Apache-2.0
//
// The package is "type": "module", so every .js file under dist/ is treated as
// ESM by default. The CommonJS build needs the opposite marker. One tiny
// package.json in each output folder is the standard way to say so, and it
// keeps the dual build honest without a bundler.
import { writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

const markers = [
  ['dist/cjs', { type: 'commonjs' }],
  ['dist/esm', { type: 'module' }],
];

for (const [dir, body] of markers) {
  const abs = join(root, dir);
  if (!existsSync(abs)) mkdirSync(abs, { recursive: true });
  writeFileSync(join(abs, 'package.json'), JSON.stringify(body, null, 2) + '\n');
  process.stdout.write(`wrote ${dir}/package.json (${body.type})\n`);
}
