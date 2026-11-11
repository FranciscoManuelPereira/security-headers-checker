import { analyze, analyzeSite, grade } from './checks.js';
import { runProbes, USER_AGENT } from './probes.js';

/** Normalise user input into a URL, defaulting to https. */
export function toUrl(input) {
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(input) ? input : `https://${input}`;
  const url = new URL(withScheme);
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error(`Only http and https URLs are supported, got ${url.protocol}`);
  }
  return url;
}

/**
 * Fetch a URL (following redirects) and analyse the final response's headers.
 * Unless `headersOnly` is set, also run the site checks (HTTPS redirect, TLS, CORS, security.txt),
 * which make a few more read-only requests to the same site.
 */
export async function scan(input, { timeoutMs = 10000, headersOnly = false } = {}) {
  const url = toUrl(input);
  const res = await fetch(url, {
    method: 'GET',
    redirect: 'follow',
    signal: AbortSignal.timeout(timeoutMs),
    headers: { 'user-agent': USER_AGENT },
  });
  // We only need headers; stop downloading the body.
  await res.body?.cancel();
  const finalUrl = new URL(res.url || url);
  const isHttps = finalUrl.protocol === 'https:';
  const findings = analyze(res.headers, { isHttps });
  const siteFindings = headersOnly ? [] : analyzeSite(await runProbes(finalUrl, { timeoutMs }), { isHttps });
  const all = [...findings, ...siteFindings];
  return { url: url.href, finalUrl: finalUrl.href, status: res.status, findings, siteFindings, ...grade(all) };
}
