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
