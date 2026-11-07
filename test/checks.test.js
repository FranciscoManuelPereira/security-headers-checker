import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  analyze,
  grade,
  parseCsp,
  parseCookie,
  checkCsp,
  checkHsts,
  checkFraming,
  checkReferrerPolicy,
  checkCookies,
  checkInfoDisclosure,
} from '../src/checks.js';
import { toUrl } from '../src/scan.js';

const h = (obj) => new Headers(obj);

const STRONG = {
  'content-security-policy': "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
  'strict-transport-security': 'max-age=63072000; includeSubDomains; preload',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'camera=(), microphone=()',
  'cross-origin-opener-policy': 'same-origin',
};

test('a well configured site gets an A', () => {
  const findings = analyze(h(STRONG));
  assert.deepEqual(grade(findings), { score: 100, letter: 'A' });
  assert.ok(findings.every((f) => f.status === 'pass' || f.status === 'info'));
});

test('a site with no security headers gets an F', () => {
  const findings = analyze(h({}));
  assert.equal(grade(findings).letter, 'F');
});

test('parseCsp reads directives and keeps the first duplicate', () => {
  const csp = parseCsp("script-src 'self' cdn.example; script-src *; object-src 'none'");
  assert.deepEqual(csp.get('script-src'), ["'self'", 'cdn.example']);
  assert.deepEqual(csp.get('object-src'), ["'none'"]);
});

test("CSP with 'unsafe-inline' is a warning", () => {
  const f = checkCsp(h({ 'content-security-policy': "script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'" }));
  assert.equal(f.status, 'warn');
  assert.match(f.message, /unsafe-inline/);
});

test("'unsafe-inline' is ignored when a nonce is present", () => {
  const f = checkCsp(h({ 'content-security-policy': "script-src 'nonce-abc' 'unsafe-inline'; object-src 'none'; base-uri 'self'" }));
  assert.equal(f.status, 'pass');
});

test('report-only CSP is not enforced', () => {
  const f = checkCsp(h({ 'content-security-policy-report-only': "default-src 'self'" }));
  assert.equal(f.status, 'fail');
  assert.equal(f.points, 5);
});

test('HSTS: short max-age and missing subdomains are warnings', () => {
  assert.equal(checkHsts(h({ 'strict-transport-security': 'max-age=300' })).status, 'warn');
  assert.equal(checkHsts(h({ 'strict-transport-security': 'max-age=31536000' })).points, 15);
  assert.equal(checkHsts(h(STRONG), { isHttps: false }).status, 'fail');
});

test('framing is protected by either frame-ancestors or X-Frame-Options', () => {
  assert.equal(checkFraming(h({ 'x-frame-options': 'DENY' })).status, 'pass');
  assert.equal(checkFraming(h({ 'content-security-policy': "frame-ancestors 'self'" })).status, 'pass');
  assert.equal(checkFraming(h({ 'x-frame-options': 'ALLOW-FROM https://a.example' })).status, 'fail');
});

test('Referrer-Policy uses the last listed value', () => {
  assert.equal(checkReferrerPolicy(h({ 'referrer-policy': 'unsafe-url' })).status, 'fail');
  assert.equal(checkReferrerPolicy(h({ 'referrer-policy': 'no-referrer, strict-origin-when-cross-origin' })).status, 'pass');
});

test('cookie flags are parsed case-insensitively', () => {
  assert.deepEqual(parseCookie('sid=abc; Path=/; secure; HTTPONLY; SameSite=Strict'), {
    name: 'sid',
    secure: true,
    httpOnly: true,
    sameSite: 'strict',
  });
});

test('insecure cookies are reported by name', () => {
  const f = checkCookies(['sid=1; Secure; HttpOnly; SameSite=Lax', 'tracking=2']);
  assert.equal(f.status, 'warn');
  assert.equal(f.points, 5);
  assert.match(f.message, /tracking lacks Secure, HttpOnly, SameSite/);
});

test('SameSite=None without Secure is flagged', () => {
  const f = checkCookies(['a=1; HttpOnly; SameSite=None'], { isHttps: false });
  assert.match(f.message, /required with SameSite=None/);
});

test('version numbers in Server and X-Powered-By are flagged', () => {
  assert.equal(checkInfoDisclosure(h({ server: 'nginx' })).status, 'pass');
  const f = checkInfoDisclosure(h({ server: 'Apache/2.4.41 (Ubuntu)', 'x-powered-by': 'Express' }));
  assert.equal(f.status, 'warn');
  assert.match(f.message, /Apache\/2\.4\.41/);
});

test('toUrl adds https and rejects other schemes', () => {
  assert.equal(toUrl('example.com').href, 'https://example.com/');
  assert.equal(toUrl('http://example.com/a').href, 'http://example.com/a');
  assert.throws(() => toUrl('file:///etc/passwd'), /Only http and https/);
});
