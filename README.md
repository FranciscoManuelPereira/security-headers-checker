# security-headers-checker

A small command-line tool that checks a website's **HTTP security headers and cookies**, plus a few basics around them (HTTPS redirect, TLS certificate, CORS and `security.txt`). It gives the site a grade from A to F and tells you what to add to fix each problem.

It is a quick first check, not a full security audit or a vulnerability scanner.

No dependencies: it uses Node.js's built-in `fetch`.

```
$ shc example.com

  Security headers report  https://example.com/

  Grade C  ·  score 63/100  ·  HTTP 200

  ✔ Content-Security-Policy          25/25
      Present and restricts scripts.
  ✘ Clickjacking protection           0/10
      Other sites can load this page in a frame and trick users into clicking (clickjacking).
      fix: Content-Security-Policy: frame-ancestors 'none' (or X-Frame-Options: DENY)
  ...
```

## Install

Requires Node.js 20 or newer.

```sh
git clone https://github.com/FranciscoManuelPereira/security-headers-checker.git
cd security-headers-checker
npm link        # makes the `shc` command available
```

Or run it without installing: `node bin/shc.js example.com`.

## Usage

```sh
shc example.com                     # human-readable report
shc https://example.com --json      # machine-readable output
shc example.com --fail-under 75     # exit code 1 if the score is below 75 (for CI)
shc example.com --headers-only      # one request, headers only, skip the site checks
```

## What it checks

| Check | Points | Why it matters |
| --- | --- | --- |
| Content-Security-Policy | 25 | Limits where scripts can load from, the main defence against XSS. Flags `'unsafe-inline'`, `'unsafe-eval'`, wildcards, missing `object-src` and `base-uri`. |
| Strict-Transport-Security | 20 | Forces HTTPS so an attacker on the network cannot downgrade the connection. Checks `max-age` ≥ 6 months and `includeSubDomains`. |
| Clickjacking protection | 10 | `frame-ancestors` or `X-Frame-Options` stops other sites framing your pages. |
| X-Content-Type-Options | 10 | `nosniff` stops browsers running uploaded files as scripts. |
| Referrer-Policy | 10 | Stops full URLs (which may hold tokens) leaking to other sites. |
| Cookies | 10 | Every cookie should have `Secure`, `HttpOnly` and `SameSite`. |
| Permissions-Policy | 5 | Turns off browser features the site does not use. |
| Cross-Origin-Opener-Policy | 5 | Isolates the page from windows it opens. |
| Server information disclosure | 5 | Version numbers in `Server` or `X-Powered-By` help attackers find known vulnerabilities. |

### Site checks

These need a few extra requests to the same site (see below). Skip them with `--headers-only`.

| Check | Points | Why it matters |
| --- | --- | --- |
| HTTP to HTTPS redirect | 10 | `http://` should answer with a permanent redirect (301/308) to `https://`, so the first visit is not left unencrypted. |
| TLS certificate and protocol | 15 | The certificate must be trusted for the hostname and not about to expire (14 days), and the connection should use TLS 1.2 or 1.3. |
| CORS | 10 | Sends a request with a made-up `Origin`. If the site echoes it back, especially with `Access-Control-Allow-Credentials: true`, other websites could read its responses. |
| security.txt | not scored | `/.well-known/security.txt` ([RFC 9116](https://www.rfc-editor.org/rfc/rfc9116)) tells researchers how to report a vulnerability. Checks for `Contact` and a valid `Expires`. |

If the TLS or CORS check cannot run (for example a timeout), it is shown as information and left out of the score instead of counting as a failure.

The score is the points earned out of the points available, scaled to 100. Grades: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 45, E ≥ 30, F below.

## What requests it sends

Only scan sites you own or have permission to test. Everything it sends is an ordinary, read-only request, the same kind a browser makes:

1. `GET` the URL you gave, following redirects (headers only, the body is not downloaded).
2. `GET` the `http://` version of the site, without following the redirect.
3. A TLS handshake to read the certificate and protocol, then the connection is closed.
4. `GET` the page again with the header `Origin: https://shc-cors-check.invalid`.
5. `GET /.well-known/security.txt` (at most 32 KB is read).

With `--headers-only` only request 1 is sent. It does not try logins, payloads, port scans or anything that changes data on the server.

## Development

```sh
npm test
```

The checks in `src/checks.js` are pure functions that take a `Headers` object or the result of a probe, so they are tested without network access. The requests themselves live in `src/probes.js` and are tested against local servers started by the tests (the TLS test needs `openssl` and is skipped without it).

## Limitations

- Only the headers of the final page after redirects are checked, not every page of the site.
- The TLS check only looks at the connection Node.js negotiates. It does not list every protocol or cipher the server accepts, so a server that still allows old TLS versions may pass. Use a dedicated tool such as SSL Labs or testssl.sh for that.
- The CORS check only tests the page you scan, not API endpoints elsewhere on the site.
- It does not look at the content of the page (mixed content, third-party scripts, and so on).

## License

MIT
