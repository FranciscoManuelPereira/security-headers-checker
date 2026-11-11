// Extra requests used by the site checks. Each one is a normal, read-only request
// (the kind a browser makes), and each probe returns { error } instead of throwing,
// so one failing probe never stops the rest of the report.
import net from 'node:net';
import tls from 'node:tls';
import { PROBE_ORIGIN } from './checks.js';

export const USER_AGENT = 'security-headers-checker (+https://github.com/FranciscoManuelPereira/security-headers-checker)';
const MAX_SECURITY_TXT_BYTES = 32 * 1024;

function reason(err) {
  if (err?.name === 'TimeoutError') return 'timed out';
  return err?.cause?.code ?? err?.code ?? err?.cause?.message ?? err?.message ?? String(err);
}

async function get(url, { timeoutMs, headers = {}, redirect = 'follow' }) {
  return fetch(url, { method: 'GET', redirect, signal: AbortSignal.timeout(timeoutMs), headers: { 'user-agent': USER_AGENT, ...headers } });
}

/** Request the http:// version of the origin without following the redirect. */
export async function probeHttpRedirect(origin, { timeoutMs }) {
  const url = new URL(origin);
  if (url.protocol === 'https:') {
    url.protocol = 'http:';
    url.port = ''; // Plain HTTP lives on port 80, whatever port HTTPS uses.
  }
  try {
    const res = await get(url, { timeoutMs, redirect: 'manual' });
    await res.body?.cancel();
    return { status: res.status, location: res.headers.get('location') };
  } catch (err) {
    return { error: reason(err) };
  }
}

/** Open a TLS connection, read the negotiated protocol and certificate, then close it. */
export function probeTls(origin, { timeoutMs }) {
  const url = new URL(origin);
  const host = url.hostname.replace(/^\[|\]$/g, '');
  return new Promise((resolve) => {
    const socket = tls.connect({
      host,
      port: Number(url.port || 443),
      servername: net.isIP(host) ? undefined : host,
      rejectUnauthorized: false, // We want to report a bad certificate, not crash on it.
      timeout: timeoutMs,
    });
    const done = (result) => {
      socket.destroy();
      resolve(result);
    };
    socket.once('secureConnect', () => {
      const cert = socket.getPeerCertificate();
      done({
        protocol: socket.getProtocol(),
        authorized: socket.authorized,
        authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
        validTo: cert?.valid_to,
        issuer: cert?.issuer?.O ?? cert?.issuer?.CN,
      });
    });
    socket.once('timeout', () => done({ error: 'timed out' }));
    socket.once('error', (err) => done({ error: reason(err) }));
  });
}

/** Request the page again with an unknown Origin and read the CORS headers. */
export async function probeCors(url, { timeoutMs }) {
  try {
    const res = await get(url, { timeoutMs, headers: { origin: PROBE_ORIGIN } });
    await res.body?.cancel();
    return {
      allowOrigin: res.headers.get('access-control-allow-origin'),
      allowCredentials: res.headers.get('access-control-allow-credentials'),
    };
  } catch (err) {
    return { error: reason(err) };
  }
}

async function readLimited(res, limit) {
  const reader = res.body?.getReader();
  if (!reader) return '';
  const chunks = [];
  let size = 0;
  while (size < limit) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    size += value.length;
  }
  await reader.cancel();
  return Buffer.concat(chunks).subarray(0, limit).toString('utf8');
}

/** Fetch /.well-known/security.txt (RFC 9116), reading at most 32 KB. */
export async function probeSecurityTxt(origin, { timeoutMs }) {
  try {
    const res = await get(new URL('/.well-known/security.txt', origin), { timeoutMs });
    const contentType = res.headers.get('content-type');
    const body = res.status === 200 && /^text\/plain/i.test(contentType ?? '') ? await readLimited(res, MAX_SECURITY_TXT_BYTES) : '';
    if (!body) await res.body?.cancel();
    return { status: res.status, contentType, body };
  } catch (err) {
    return { error: reason(err) };
  }
}

/** Run every probe in parallel. */
export async function runProbes(finalUrl, { timeoutMs }) {
  const url = new URL(finalUrl);
  const [httpRedirect, tlsInfo, cors, securityTxt] = await Promise.all([
    probeHttpRedirect(url.origin, { timeoutMs }),
    url.protocol === 'https:' ? probeTls(url.origin, { timeoutMs }) : null,
    probeCors(url, { timeoutMs }),
    probeSecurityTxt(url.origin, { timeoutMs }),
  ]);
  return { httpRedirect, tls: tlsInfo, cors, securityTxt };
}
