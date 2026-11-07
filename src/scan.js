import { analyze, grade } from './checks.js';

/** Normalise user input into a URL, defaulting to https. */
export function toUrl(input) {
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(input) ? input : `https://${input}`;
  const url = new URL(withScheme);
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error(`Only http and https URLs are supported, got ${url.protocol}`);
  }
  return url;
}

/** Fetch a URL (following redirects) and analyse the final response's headers. */
export async function scan(input, { timeoutMs = 10000 } = {}) {
  const url = toUrl(input);
  const res = await fetch(url, {
    method: 'GET',
    redirect: 'follow',
    signal: AbortSignal.timeout(timeoutMs),
    headers: { 'user-agent': 'security-headers-checker (+https://github.com/FranciscoManuelPereira/security-headers-checker)' },
  });
  // We only need headers; stop downloading the body.
  await res.body?.cancel();
  const finalUrl = new URL(res.url || url);
  const findings = analyze(res.headers, { isHttps: finalUrl.protocol === 'https:' });
  return { url: url.href, finalUrl: finalUrl.href, status: res.status, findings, ...grade(findings) };
}
