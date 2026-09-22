// SPDX-License-Identifier: Apache-2.0
/**
 * A stand-in for the local app: the three routes the SDK talks to, on a
 * loopback port, recording every request so a test can assert on the wire
 * shape rather than on the SDK's own idea of what it sent.
 */
import { createServer } from 'node:http';

export async function startFakeApp(handler) {
  const requests = [];
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
    });
    req.on('end', () => {
      let parsed = null;
      try {
        parsed = body ? JSON.parse(body) : null;
      } catch {
        parsed = null;
      }
      const record = { path: req.url, headers: req.headers, body: parsed };
      requests.push(record);
      const out = handler ? handler(record) : null;
      const status = out?.status ?? 200;
      const payload = out?.body ?? { ok: true };
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  return {
    url: `http://127.0.0.1:${port}`,
    requests,
    find: (path) => requests.filter((r) => r.path === path),
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

/** An /analyze answer that reads as a high-risk finding. */
export function threatBody(threatType = 'prompt_injection', risk = 95) {
  return { is_threat: true, threat_type: threatType, risk_score: risk, confidence: 0.99, matched_rules: [] };
}

/** An /analyze answer that reads as clean. */
export function cleanBody() {
  return { is_threat: false, threat_type: null, risk_score: 0, confidence: 1, matched_rules: [] };
}

/** A port nothing is listening on, for the fail-open tests. */
export async function deadPort() {
  const server = createServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  await new Promise((resolve) => server.close(resolve));
  return `http://127.0.0.1:${port}`;
}
