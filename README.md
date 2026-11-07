# security-headers-checker

A small command-line tool that checks a website's **HTTP security headers and cookies**, gives it a grade from A to F, and tells you exactly what to add to fix each problem.

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

Grades: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 45, E ≥ 30, F below.

Only scan sites you own or have permission to test. The tool sends a single normal `GET` request, the same as opening the page in a browser.

## Development

```sh
npm test
```

The checks in `src/checks.js` are pure functions that take a `Headers` object, so they are tested without network access.

## Limitations

- Only the headers of the final page after redirects are checked, not every page of the site.
- It does not test TLS configuration or the content of the page.

## License

MIT
