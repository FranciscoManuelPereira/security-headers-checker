// Pure analysis functions: they take response headers and return findings.
// No network access here, so everything is easy to unit test.

/**
 * @typedef {'pass' | 'warn' | 'fail' | 'info'} Status
 * @typedef {{ id: string, title: string, status: Status, points: number, max: number, message: string, fix?: string }} Finding
 */

const SIX_MONTHS = 15552000;

/** Parse a CSP string into a Map of directive -> array of sources. */
export function parseCsp(value) {
  const directives = new Map();
  for (const part of value.split(';')) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (tokens.length === 0) continue;
    const name = tokens[0].toLowerCase();
    if (!directives.has(name)) directives.set(name, tokens.slice(1));
  }
  return directives;
}

/** @param {Headers} headers @returns {Finding} */
export function checkHsts(headers, { isHttps = true } = {}) {
  const base = { id: 'hsts', title: 'Strict-Transport-Security', max: 20 };
  const fix = 'Strict-Transport-Security: max-age=31536000; includeSubDomains';
  if (!isHttps) {
    return { ...base, status: 'fail', points: 0, message: 'Site is served over plain HTTP, so HSTS cannot protect it.', fix: 'Serve the site over HTTPS, then add ' + fix };
  }
  const value = headers.get('strict-transport-security');
  if (!value) {
    return { ...base, status: 'fail', points: 0, message: 'Missing. Browsers may connect over HTTP and be downgraded by an attacker.', fix };
  }
  const maxAge = Number(/max-age\s*=\s*"?(\d+)/i.exec(value)?.[1] ?? 0);
  const subdomains = /includesubdomains/i.test(value);
  if (maxAge < SIX_MONTHS) {
    return { ...base, status: 'warn', points: 10, message: `max-age is ${maxAge}s, shorter than the recommended 6 months.`, fix };
  }
  if (!subdomains) {
    return { ...base, status: 'warn', points: 15, message: 'Present, but subdomains are not covered.', fix };
  }
  return { ...base, status: 'pass', points: 20, message: `Enabled for ${Math.round(maxAge / 86400)} days, including subdomains.` };
}

/** @param {Headers} headers @returns {Finding} */
export function checkCsp(headers) {
  const base = { id: 'csp', title: 'Content-Security-Policy', max: 25 };
  const value = headers.get('content-security-policy');
  if (!value) {
    const reportOnly = headers.get('content-security-policy-report-only');
    return {
      ...base,
      status: 'fail',
      points: reportOnly ? 5 : 0,
      message: reportOnly
        ? 'Only a report-only policy is set, so nothing is enforced yet.'
        : 'Missing. Injected scripts (XSS) can run without restriction.',
      fix: "Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
    };
  }
  const csp = parseCsp(value);
  const scriptSrc = csp.get('script-src') ?? csp.get('default-src');
  const problems = [];
  let points = 25;
  if (!scriptSrc) {
    problems.push('no script-src or default-src, so scripts are unrestricted');
    points -= 15;
  } else {
    const usesNonceOrHash = scriptSrc.some((s) => /^'(nonce-|sha256-|sha384-|sha512-)/i.test(s));
    const strictDynamic = scriptSrc.includes("'strict-dynamic'");
    if (scriptSrc.includes("'unsafe-inline'") && !usesNonceOrHash && !strictDynamic) {
      problems.push("script-src allows 'unsafe-inline'");
      points -= 10;
    }
    if (scriptSrc.includes("'unsafe-eval'")) {
      problems.push("script-src allows 'unsafe-eval'");
      points -= 5;
    }
    if (scriptSrc.some((s) => s === '*' || /^https?:$/i.test(s))) {
      problems.push('script-src allows any host');
      points -= 10;
    }
  }
  if (!csp.has('object-src') && !csp.has('default-src')) {
    problems.push('object-src is not restricted');
    points -= 3;
  }
  if (!csp.has('base-uri')) {
    problems.push('base-uri is not set');
    points -= 2;
  }
  points = Math.max(points, 5);
  if (problems.length === 0) {
    return { ...base, status: 'pass', points, message: 'Present and restricts scripts.' };
  }
  return { ...base, status: 'warn', points, message: `Present, but ${problems.join('; ')}.`, fix: "Remove unsafe sources and add object-src 'none'; base-uri 'self'" };
}

/** @param {Headers} headers @returns {Finding} */
export function checkFraming(headers) {
  const base = { id: 'framing', title: 'Clickjacking protection', max: 10 };
  const xfo = headers.get('x-frame-options');
  const csp = headers.get('content-security-policy');
  const frameAncestors = csp ? parseCsp(csp).get('frame-ancestors') : undefined;
  if (frameAncestors) {
    return { ...base, status: 'pass', points: 10, message: `CSP frame-ancestors is ${frameAncestors.join(' ') || "'none'"}.` };
  }
  if (xfo && /^(deny|sameorigin)$/i.test(xfo.trim())) {
    return { ...base, status: 'pass', points: 10, message: `X-Frame-Options is ${xfo.trim().toUpperCase()}.` };
  }
  return {
    ...base,
    status: 'fail',
    points: 0,
    message: 'Other sites can load this page in a frame and trick users into clicking (clickjacking).',
    fix: "Content-Security-Policy: frame-ancestors 'none' (or X-Frame-Options: DENY)",
  };
}

/** @param {Headers} headers @returns {Finding} */
export function checkContentTypeOptions(headers) {
  const base = { id: 'xcto', title: 'X-Content-Type-Options', max: 10 };
  const value = headers.get('x-content-type-options');
  if (value?.trim().toLowerCase() === 'nosniff') {
    return { ...base, status: 'pass', points: 10, message: 'nosniff is set.' };
  }
  return { ...base, status: 'fail', points: 0, message: 'Browsers may guess (sniff) content types and run files as scripts.', fix: 'X-Content-Type-Options: nosniff' };
}

const SAFE_REFERRER = ['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin'];

/** @param {Headers} headers @returns {Finding} */
export function checkReferrerPolicy(headers) {
  const base = { id: 'referrer', title: 'Referrer-Policy', max: 10 };
  const value = headers.get('referrer-policy');
  const fix = 'Referrer-Policy: strict-origin-when-cross-origin';
  if (!value) {
    return { ...base, status: 'warn', points: 5, message: 'Not set. Modern browsers default to strict-origin-when-cross-origin, but being explicit is safer.', fix };
  }
  // The header may list fallbacks; the last value the browser understands wins.
  const policy = value.split(',').map((v) => v.trim().toLowerCase()).filter(Boolean).at(-1);
  if (SAFE_REFERRER.includes(policy)) {
    return { ...base, status: 'pass', points: 10, message: `${policy}.` };
  }
  return { ...base, status: 'fail', points: 0, message: `${policy} can leak full URLs (with tokens or IDs) to other sites.`, fix };
}

/** @param {Headers} headers @returns {Finding} */
export function checkPermissionsPolicy(headers) {
  const base = { id: 'permissions', title: 'Permissions-Policy', max: 5 };
  if (headers.get('permissions-policy')) {
    return { ...base, status: 'pass', points: 5, message: 'Set, browser features are restricted.' };
  }
  return { ...base, status: 'warn', points: 0, message: 'Not set. Camera, microphone and geolocation are not explicitly disabled.', fix: 'Permissions-Policy: camera=(), microphone=(), geolocation=()' };
}

/** @param {Headers} headers @returns {Finding} */
export function checkCoop(headers) {
  const base = { id: 'coop', title: 'Cross-Origin-Opener-Policy', max: 5 };
  const value = headers.get('cross-origin-opener-policy')?.trim().toLowerCase();
  if (value === 'same-origin' || value === 'same-origin-allow-popups') {
    return { ...base, status: 'pass', points: 5, message: `${value}.` };
  }
  return { ...base, status: 'warn', points: 0, message: 'Not set. Pages opened from this site can keep a reference to it.', fix: 'Cross-Origin-Opener-Policy: same-origin' };
}

/** @param {Headers} headers @returns {Finding} */
export function checkInfoDisclosure(headers) {
  const base = { id: 'disclosure', title: 'Server information disclosure', max: 5 };
  const leaks = [];
  const server = headers.get('server');
  if (server && /\d/.test(server)) leaks.push(`Server: ${server}`);
  for (const name of ['x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version']) {
    const v = headers.get(name);
    if (v) leaks.push(`${name}: ${v}`);
  }
  if (leaks.length === 0) {
    return { ...base, status: 'pass', points: 5, message: 'No software versions exposed.' };
  }
  return { ...base, status: 'warn', points: 0, message: `Exposes ${leaks.join(', ')}. Attackers use versions to look up known vulnerabilities.`, fix: 'Remove X-Powered-By and version numbers from the Server header.' };
}

/** Parse one Set-Cookie header value. */
export function parseCookie(setCookie) {
  const [pair, ...attrs] = setCookie.split(';');
  const name = pair.split('=')[0].trim();
  const flags = {};
  for (const attr of attrs) {
    const [k, ...v] = attr.trim().split('=');
    flags[k.toLowerCase()] = v.join('=').trim() || true;
  }
  return { name, secure: Boolean(flags.secure), httpOnly: Boolean(flags.httponly), sameSite: typeof flags.samesite === 'string' ? flags.samesite.toLowerCase() : undefined };
}

/** @param {string[]} setCookies @returns {Finding} */
export function checkCookies(setCookies, { isHttps = true } = {}) {
  const base = { id: 'cookies', title: 'Cookies', max: 10 };
  if (setCookies.length === 0) {
    return { ...base, status: 'info', points: 10, message: 'No cookies set on this response.' };
  }
  const problems = [];
  for (const c of setCookies.map(parseCookie)) {
    const missing = [];
    if (isHttps && !c.secure) missing.push('Secure');
    if (!c.httpOnly) missing.push('HttpOnly');
    if (!c.sameSite) missing.push('SameSite');
    else if (c.sameSite === 'none' && !c.secure) missing.push('Secure (required with SameSite=None)');
    if (missing.length) problems.push(`${c.name} lacks ${missing.join(', ')}`);
  }
  if (problems.length === 0) {
    return { ...base, status: 'pass', points: 10, message: `${setCookies.length} cookie(s), all with Secure, HttpOnly and SameSite.` };
  }
  const points = Math.round(10 * (1 - problems.length / setCookies.length));
  return {
    ...base,
    status: points === 0 ? 'fail' : 'warn',
    points,
    message: problems.join('; ') + '.',
    fix: 'Set-Cookie: name=value; Secure; HttpOnly; SameSite=Lax (HttpOnly only if JavaScript does not need to read it)',
  };
}

/** Run every check. */
export function analyze(headers, { isHttps = true } = {}) {
  const setCookies = typeof headers.getSetCookie === 'function' ? headers.getSetCookie() : [];
  return [
    checkCsp(headers),
    checkHsts(headers, { isHttps }),
    checkFraming(headers),
    checkContentTypeOptions(headers),
    checkReferrerPolicy(headers),
    checkCookies(setCookies, { isHttps }),
    checkPermissionsPolicy(headers),
    checkCoop(headers),
    checkInfoDisclosure(headers),
  ];
}

/** Turn findings into a 0-100 score and a letter grade. */
export function grade(findings) {
  const max = findings.reduce((s, f) => s + f.max, 0);
  const got = findings.reduce((s, f) => s + f.points, 0);
  const score = Math.round((got / max) * 100);
  const letter = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 45 ? 'D' : score >= 30 ? 'E' : 'F';
  return { score, letter };
}

// ---------------------------------------------------------------------------
// Site checks. These need extra requests, which scan.js makes (see probes.js).
// The functions below stay pure: they take what the probes found.
// ---------------------------------------------------------------------------

/**
 * @param {{ error?: string, status?: number, location?: string | null } | null} probe
 *   Result of requesting the http:// version of the site without following redirects.
 * @returns {Finding}
 */
export function checkHttpsRedirect(probe) {
  const base = { id: 'https-redirect', title: 'HTTP to HTTPS redirect', max: 10 };
  const fix = 'Redirect every http:// request to https:// with a 301 or 308.';
  if (!probe || probe.error) {
    // Port 80 closed or refusing connections means nobody can be served over plain HTTP.
    return { ...base, status: 'pass', points: 10, message: `Plain HTTP is not reachable${probe?.error ? ` (${probe.error})` : ''}, so there is nothing to downgrade to.` };
  }
  const isRedirect = probe.status >= 300 && probe.status < 400;
  let target;
  try {
    target = probe.location ? new URL(probe.location, 'http://placeholder.invalid') : undefined;
  } catch {
    target = undefined;
  }
  if (isRedirect && target?.protocol === 'https:') {
    const permanent = probe.status === 301 || probe.status === 308;
    return permanent
      ? { ...base, status: 'pass', points: 10, message: `http:// answers ${probe.status} and redirects to HTTPS.` }
      : { ...base, status: 'warn', points: 7, message: `http:// redirects to HTTPS, but with a temporary ${probe.status}.`, fix };
  }
  if (isRedirect) {
    return { ...base, status: 'fail', points: 0, message: `http:// redirects to ${probe.location ?? 'nowhere'}, not to HTTPS.`, fix };
  }
  return { ...base, status: 'fail', points: 0, message: `http:// serves content directly (HTTP ${probe.status}), so first visits can be intercepted.`, fix };
}

const DAY = 86400000;

/**
 * @param {{ error?: string, protocol?: string | null, authorized?: boolean, authorizationError?: string | null,
 *   validTo?: string, issuer?: string } | null} probe Result of a TLS handshake with the site.
 * @returns {Finding}
 */
export function checkTls(probe, { isHttps = true, now = Date.now() } = {}) {
  const base = { id: 'tls', title: 'TLS certificate and protocol', max: 15 };
  if (!isHttps) {
    return { ...base, status: 'fail', points: 0, message: 'Site is served over plain HTTP, traffic is not encrypted.', fix: 'Get a free certificate (for example from Let’s Encrypt) and serve the site over HTTPS.' };
  }
  if (!probe || probe.error) {
    return { ...base, status: 'info', points: 0, max: 0, message: `Could not inspect TLS${probe?.error ? `: ${probe.error}` : ''}. Not counted in the score.` };
  }
  if (!probe.authorized) {
    return { ...base, status: 'fail', points: 0, message: `Certificate is not trusted (${probe.authorizationError ?? 'unknown reason'}). Browsers will show a warning.`, fix: 'Install a valid certificate for this hostname, including the intermediate chain.' };
  }
  const problems = [];
  let points = 15;
  const daysLeft = Math.floor((Date.parse(probe.validTo ?? '') - now) / DAY);
  if (Number.isFinite(daysLeft) && daysLeft < 14) {
    problems.push(`certificate expires in ${daysLeft} day(s)`);
    points -= 5;
  }
  if (probe.protocol && !['TLSv1.2', 'TLSv1.3'].includes(probe.protocol)) {
    problems.push(`negotiated ${probe.protocol}, which is deprecated`);
    points -= 10;
  }
  const summary = `${probe.protocol ?? 'TLS'}, certificate${probe.issuer ? ` from ${probe.issuer}` : ''} valid for ${daysLeft} more day(s)`;
  if (problems.length === 0) {
    return { ...base, status: 'pass', points, message: `${summary}.` };
  }
  return { ...base, status: 'warn', points: Math.max(points, 0), message: `${summary}, but ${problems.join('; ')}.`, fix: 'Renew the certificate automatically and allow only TLS 1.2 and 1.3.' };
}

/** Origin sent by the CORS probe. `.invalid` is reserved, so it can never be a real site. */
export const PROBE_ORIGIN = 'https://shc-cors-check.invalid';

/**
 * @param {{ error?: string, allowOrigin?: string | null, allowCredentials?: string | null } | null} probe
 *   CORS headers returned when the page is requested with `Origin: PROBE_ORIGIN`.
 * @returns {Finding}
 */
export function checkCors(probe) {
  const base = { id: 'cors', title: 'CORS (cross-origin access)', max: 10 };
  if (!probe || probe.error) {
    return { ...base, status: 'info', points: 0, max: 0, message: `Could not test CORS${probe?.error ? `: ${probe.error}` : ''}. Not counted in the score.` };
  }
  const origin = probe.allowOrigin?.trim();
  const credentials = probe.allowCredentials?.trim().toLowerCase() === 'true';
  const fix = 'Only return Access-Control-Allow-Origin for an explicit list of trusted origins.';
  if (!origin) {
    return { ...base, status: 'pass', points: 10, message: 'No Access-Control-Allow-Origin for an unknown origin, so other sites cannot read responses.' };
  }
  if (origin === PROBE_ORIGIN || origin === 'null') {
    return credentials
      ? { ...base, status: 'fail', points: 0, message: `Any origin is trusted (${origin === 'null' ? '"null"' : 'the request Origin is reflected'}) with credentials. Other sites could read users’ data while they are logged in.`, fix }
      : { ...base, status: 'warn', points: 5, message: 'The request Origin is reflected back, so any site can read these responses.', fix };
  }
  if (origin === '*') {
    return credentials
      ? { ...base, status: 'warn', points: 5, message: 'Access-Control-Allow-Origin is * together with Allow-Credentials. Browsers reject this, which suggests a misconfiguration.', fix }
      : { ...base, status: 'pass', points: 10, message: 'Access-Control-Allow-Origin is *, fine for public content that needs no login.' };
  }
  return { ...base, status: 'pass', points: 10, message: `Only ${origin} is allowed, not unknown origins.` };
}

/** Parse security.txt (RFC 9116) into lower-cased field -> values. */
export function parseSecurityTxt(text) {
  const fields = new Map();
  for (const line of text.split(/\r?\n/)) {
    const m = /^([A-Za-z-]+):\s*(.+)$/.exec(line.trim());
    if (!m) continue;
    const key = m[1].toLowerCase();
    fields.set(key, [...(fields.get(key) ?? []), m[2].trim()]);
  }
  return fields;
}

/**
 * Not scored: it is good practice, not a protection.
 * @param {{ error?: string, status?: number, contentType?: string | null, body?: string } | null} probe
 * @returns {Finding}
 */
export function checkSecurityTxt(probe, { now = Date.now() } = {}) {
  const base = { id: 'security-txt', title: 'security.txt', max: 0, points: 0 };
  const fix = 'Publish /.well-known/security.txt with Contact: and Expires: fields (see securitytxt.org).';
  if (!probe || probe.error) {
    return { ...base, status: 'info', message: `Could not fetch /.well-known/security.txt${probe?.error ? `: ${probe.error}` : ''}.` };
  }
  const isText = /^text\/plain/i.test(probe.contentType ?? '');
  const fields = probe.status === 200 && isText ? parseSecurityTxt(probe.body ?? '') : new Map();
  if (!fields.has('contact')) {
    return { ...base, status: 'warn', message: 'No security.txt, so researchers have no clear way to report a vulnerability.', fix };
  }
  const expires = Date.parse(fields.get('expires')?.[0] ?? '');
  if (!Number.isFinite(expires)) {
    return { ...base, status: 'warn', message: 'security.txt has a Contact but no valid Expires field, which the standard requires.', fix };
  }
  if (expires < now) {
    return { ...base, status: 'warn', message: 'security.txt has expired, so it should no longer be trusted.', fix: 'Update the Expires: date in security.txt.' };
  }
  return { ...base, status: 'pass', message: `Present. Contact: ${fields.get('contact')[0]}.` };
}

/** Run the checks that need extra requests. */
export function analyzeSite(probes, { isHttps = true, now = Date.now() } = {}) {
  return [
    checkHttpsRedirect(probes.httpRedirect),
    checkTls(probes.tls, { isHttps, now }),
    checkCors(probes.cors),
    checkSecurityTxt(probes.securityTxt, { now }),
  ];
}
