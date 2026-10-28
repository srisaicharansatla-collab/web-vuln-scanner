# Viva / demo cheat-sheet

## 5-minute demo script
1. `python scanner.py http://127.0.0.1:8081` -> refuses (consent gate). Add `--i-have-permission` after starting `python labs/vulnerable_lab.py --port 8081`.
2. Show console summary, then `samples/report_vulnlab.json` (evidence, severity, OWASP, fix per finding).
3. Scan `labs/hardened_lab.py` (200 for every path) -> only 3 findings: proves signature-based false-positive control.
4. `python -m pytest -q` (32 tests). 5. `python tools/evaluate.py` for precision/recall.

## How each check works and how to fix it
| Check | How it works | Fix |
|---|---|---|
| A01-CSRF | POST form with no hidden field named csrf/token/nonce... | per-session CSRF token, SameSite cookies |
| A01-REDIR | sends `https://vulnscan-canary.invalid/...` in params like next/url/redirect; vulnerable if `Location` host == canary (redirect is not followed) | relative paths or host allow-list |
| A01-CORS | sends `Origin: https://evil.vulnscan.invalid`; reflected origin (+credentials = High), `*` = Low | strict origin allow-list |
| A01-TRAV | `../../../../../../etc/passwd` in file-like params; match `root:x:0:0:` absent from baseline; file contents never stored | allow-list, canonical path check |
| A02-HTTP/HSTS/MIXED | scheme, `Strict-Transport-Security` header, `http://` resources on https pages | TLS everywhere, HSTS, upgrade-insecure-requests |
| A02-COOKIE-SECURE, A07-COOKIE-FLAGS | parse `Set-Cookie` attributes (Secure, HttpOnly, SameSite) | add the attributes |
| A03-SQLI | append `'`/`"`; DB error regex (MySQL, PostgreSQL, SQLite, Oracle, MSSQL) must appear only after payload | prepared statements |
| A03-XSS | unique random marker + `<b>`; vulnerable if reflected raw in HTML | output encoding, CSP |
| A05-HEADERS | CSP, X-Frame-Options/frame-ancestors, nosniff, Referrer-Policy present on HTML pages | add headers |
| A05-FILES | probes 13 paths; needs content signature, differs from soft-404 body, not HTML for text files | remove files, deny dotfiles, rotate secrets |
| A05-DIRLIST / A05-TRACE | "Index of /" signature; stack-trace regexes on crawled pages | `Options -Indexes`, disable debug |
| A06-VERSION | version number in Server/X-Powered-By; small offline CVE hint table | hide banners, patch |
| A07-LOGIN-HTTP | password input on http page/action | HTTPS only |
| A08-SRI | third-party script/css without `integrity=` | add SRI hash or self-host |

## Likely questions
* **Why not just HTTP 200 for .env?** SPAs return 200 for every path -> we need content signature + soft-404 comparison.
* **Why is it non-destructive?** GET only, harmless markers, never follows canary redirects, redacts secrets, request cap + delay.
* **What can't it find?** Blind SQLi, DOM XSS, IDOR, business logic, SSRF, anything behind login, JS-rendered content.
* **Why no A09/A10?** Server-side only / needs out-of-band callbacks that could harm third parties.
* **Is precision 1.0 realistic?** No - labs were written with the scanner; it is an upper bound.
