// Runs the real probes against local servers, so no internet access is needed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { probeCors, probeSecurityTxt, probeTls } from '../src/probes.js';
import { scan } from '../src/scan.js';
import { PROBE_ORIGIN } from '../src/checks.js';

function listen(server) {
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
}

test('probes read CORS headers and security.txt from a local server', async (t) => {
  const server = http.createServer((req, res) => {
    if (req.url === '/.well-known/security.txt') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      return res.end('Contact: mailto:sec@example.com\nExpires: 2099-01-01T00:00:00Z\n');
    }
    const headers = { 'content-type': 'text/html' };
    if (req.headers.origin) {
      headers['access-control-allow-origin'] = req.headers.origin;
      headers['access-control-allow-credentials'] = 'true';
    }
    res.writeHead(200, headers);
    res.end('<h1>hi</h1>');
  });
  const port = await listen(server);
  t.after(() => server.close());
  const origin = `http://127.0.0.1:${port}`;

  assert.deepEqual(await probeCors(new URL(origin), { timeoutMs: 2000 }), { allowOrigin: PROBE_ORIGIN, allowCredentials: 'true' });
  const txt = await probeSecurityTxt(origin, { timeoutMs: 2000 });
  assert.equal(txt.status, 200);
  assert.match(txt.body, /Contact: mailto:sec@example.com/);

  const result = await scan(origin, { timeoutMs: 2000 });
  const byId = Object.fromEntries(result.siteFindings.map((f) => [f.id, f]));
  assert.equal(byId.cors.status, 'fail');
  assert.equal(byId.tls.status, 'fail');
  assert.equal(byId['security-txt'].status, 'pass');

  const headersOnly = await scan(origin, { timeoutMs: 2000, headersOnly: true });
  assert.deepEqual(headersOnly.siteFindings, []);
});

let openssl = true;
try {
  execFileSync('openssl', ['version'], { stdio: 'ignore' });
} catch {
  openssl = false;
}

test('probeTls reports protocol and an untrusted self-signed certificate', { skip: !openssl && 'openssl not installed' }, async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'shc-tls-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost',
    '-keyout', join(dir, 'key.pem'), '-out', join(dir, 'cert.pem')], { stdio: 'ignore' });
  const server = https.createServer({ key: readFileSync(join(dir, 'key.pem')), cert: readFileSync(join(dir, 'cert.pem')) }, (req, res) => res.end('ok'));
  const port = await listen(server);
  t.after(() => server.close());

  const info = await probeTls(`https://127.0.0.1:${port}`, { timeoutMs: 2000 });
  assert.equal(info.authorized, false);
  assert.match(info.authorizationError, /SELF_SIGNED/);
  assert.match(info.protocol, /^TLSv1\.[23]$/);
  assert.ok(info.validTo);
});

test('probeTls returns an error instead of throwing when nothing listens', async () => {
  const server = http.createServer();
  const port = await listen(server);
  await new Promise((r) => server.close(r));
  const info = await probeTls(`https://127.0.0.1:${port}`, { timeoutMs: 2000 });
  assert.ok(info.error);
});
