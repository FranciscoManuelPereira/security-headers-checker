import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  checkHttpsRedirect,
  checkTls,
  checkCors,
  checkSecurityTxt,
  parseSecurityTxt,
  analyzeSite,
  PROBE_ORIGIN,
} from '../src/checks.js';

const NOW = Date.parse('2026-11-11T12:00:00Z');

test('HTTPS redirect: permanent redirect passes, temporary warns, none fails', () => {
  assert.equal(checkHttpsRedirect({ status: 301, location: 'https://example.com/' }).status, 'pass');
  assert.equal(checkHttpsRedirect({ status: 308, location: 'https://example.com/' }).status, 'pass');
  assert.equal(checkHttpsRedirect({ status: 302, location: 'https://example.com/' }).points, 7);
  assert.equal(checkHttpsRedirect({ status: 200, location: null }).status, 'fail');
  assert.equal(checkHttpsRedirect({ status: 301, location: '/elsewhere' }).status, 'fail');
});

test('HTTPS redirect: plain HTTP not reachable is fine', () => {
  const f = checkHttpsRedirect({ error: 'ECONNREFUSED' });
  assert.equal(f.status, 'pass');
  assert.match(f.message, /ECONNREFUSED/);
});

test('TLS: a valid modern certificate passes', () => {
  const f = checkTls({ protocol: 'TLSv1.3', authorized: true, validTo: 'Feb 10 12:00:00 2027 GMT', issuer: "Let's Encrypt" }, { now: NOW });
  assert.equal(f.status, 'pass');
  assert.equal(f.points, 15);
  assert.match(f.message, /Let's Encrypt/);
});

test('TLS: untrusted certificate fails, expiring soon and old protocols warn', () => {
  assert.equal(checkTls({ authorized: false, authorizationError: 'DEPTH_ZERO_SELF_SIGNED_CERT' }, { now: NOW }).status, 'fail');
  const expiring = checkTls({ protocol: 'TLSv1.3', authorized: true, validTo: 'Nov 20 12:00:00 2026 GMT' }, { now: NOW });
  assert.equal(expiring.status, 'warn');
  assert.match(expiring.message, /expires in 9 day/);
  assert.equal(checkTls({ protocol: 'TLSv1', authorized: true, validTo: 'Feb 10 12:00:00 2027 GMT' }, { now: NOW }).points, 5);
});

test('TLS: plain HTTP fails, a failed handshake is not scored', () => {
  assert.equal(checkTls(null, { isHttps: false }).status, 'fail');
  const f = checkTls({ error: 'timed out' });
  assert.equal(f.status, 'info');
  assert.equal(f.max, 0);
});

test('CORS: reflected origin with credentials fails', () => {
  assert.equal(checkCors({ allowOrigin: PROBE_ORIGIN, allowCredentials: 'true' }).status, 'fail');
  assert.equal(checkCors({ allowOrigin: 'null', allowCredentials: 'true' }).status, 'fail');
  assert.equal(checkCors({ allowOrigin: PROBE_ORIGIN, allowCredentials: null }).status, 'warn');
});

test('CORS: no header, a fixed origin or a public * pass', () => {
  assert.equal(checkCors({ allowOrigin: null }).status, 'pass');
  assert.equal(checkCors({ allowOrigin: 'https://app.example.com' }).status, 'pass');
  assert.equal(checkCors({ allowOrigin: '*' }).status, 'pass');
  assert.equal(checkCors({ allowOrigin: '*', allowCredentials: 'true' }).status, 'warn');
});

test('parseSecurityTxt reads fields case-insensitively and ignores comments', () => {
  const fields = parseSecurityTxt('# comment\nContact: mailto:sec@example.com\ncontact: https://example.com/report\nExpires: 2027-01-01T00:00:00Z\n');
  assert.deepEqual(fields.get('contact'), ['mailto:sec@example.com', 'https://example.com/report']);
  assert.equal(fields.get('expires')[0], '2027-01-01T00:00:00Z');
});

test('security.txt: valid file passes, missing or expired warns, never scored', () => {
  const body = 'Contact: mailto:sec@example.com\nExpires: 2027-01-01T00:00:00Z\n';
  const ok = checkSecurityTxt({ status: 200, contentType: 'text/plain; charset=utf-8', body }, { now: NOW });
  assert.equal(ok.status, 'pass');
  assert.equal(ok.max, 0);
  assert.equal(checkSecurityTxt({ status: 404, contentType: 'text/html', body: '' }, { now: NOW }).status, 'warn');
  // Single page apps often answer every path with their HTML page.
  assert.equal(checkSecurityTxt({ status: 200, contentType: 'text/html', body: '<html>Contact: x</html>' }, { now: NOW }).status, 'warn');
  const expired = checkSecurityTxt({ status: 200, contentType: 'text/plain', body: 'Contact: mailto:a@b.c\nExpires: 2025-01-01T00:00:00Z' }, { now: NOW });
  assert.match(expired.message, /expired/);
});

test('analyzeSite returns the four site checks in order', () => {
  const ids = analyzeSite({ httpRedirect: null, tls: null, cors: null, securityTxt: null }).map((f) => f.id);
  assert.deepEqual(ids, ['https-redirect', 'tls', 'cors', 'security-txt']);
});
