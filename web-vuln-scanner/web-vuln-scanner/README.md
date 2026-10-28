# vulnscan – Lightweight Web Vulnerability Scanner

A small, **non-destructive** command-line scanner that crawls a website and reports security
weaknesses mapped to the **OWASP Top 10 (2021)**. For every finding it prints the **evidence,
severity, OWASP category and a recommended fix**, and writes a JSON report (plus an optional HTML report).

* Python 3.9+, only `requests` and `beautifulsoup4` at runtime
* 18 modular checks (one class each) covering 7 OWASP categories: A01, A02, A03, A05, A06, A07, A08
* Read-only: GET requests and harmless markers only (no exploitation, no data extraction)
* Fully offline demo: two bundled local lab apps, unit + integration tests, evaluation script

> ## Legal / ethical use
> Scan **only** your own localhost or intentionally vulnerable labs (OWASP Juice Shop, DVWA, WebGoat, bWAPP).
> Scanning any other site without **written permission** is illegal.
> The tool refuses to run without `--i-have-permission`, and refuses non-local/private targets unless you
> additionally pass `--allow-remote`.

## Quick start

```bash
git clone <your-repo-url> && cd web-vuln-scanner
python -m venv .venv && source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 1) run a lab target (pick one)
docker run -p 3000:3000 bkimminich/juice-shop             # OWASP Juice Shop
python labs/vulnerable_lab.py --port 8081                 # bundled, deliberately vulnerable (no Docker needed)

# 2) scan it
python scanner.py http://localhost:3000 --i-have-permission -o report.json --html report.html
python scanner.py http://127.0.0.1:8081 --i-have-permission -o samples/my_scan.json
```

Without the consent flag the tool exits with code 1 and sends no requests:

```
$ python scanner.py http://localhost:3000
[!] REFUSING TO RUN: pass --i-have-permission to confirm you own this target ...
```

## Options

| Option | Meaning |
|---|---|
| `--i-have-permission` | **Required** consent gate |
| `-o, --output FILE` | JSON report path (default `report.json`) |
| `--html FILE` | Also write an HTML report with a severity chart (bonus) |
| `--delay S` | Seconds between requests (default 0.5) |
| `--timeout S` | Per-request timeout (default 10) |
| `--max-pages N`, `--max-depth N` | Crawl limits (default 30 pages, depth 3) |
| `--max-requests N` | Hard cap on total requests (default 600) |
| `--checks IDS`, `--skip IDS` | Comma-separated check IDs to run / skip |
| `--list-checks` | Show all checks |
| `--allow-post` | Also send harmless marker values to POST forms (off by default) |
| `--insecure` | Do not verify TLS certificates (self-signed labs) |
| `--allow-remote` | Permit non-local targets (needs written permission) |
| `--fail-on LEVEL` | Exit code 3 if a finding ≥ LEVEL exists (CI use, bonus) |
| `-v` | Verbose crawl log |

Safety defaults: clear `User-Agent`, 0.5 s delay, page/depth/request limits, timeouts, 1 MB response cap,
same-host crawling only, redirects to other hosts are never analysed.

## Checks and OWASP mapping

| Check ID | OWASP 2021 | Technique | Guard against false positives |
|---|---|---|---|
| `A01-CSRF` | A01 | POST form without token-like hidden field | token name heuristics; GET forms ignored |
| `A01-REDIR` | A01 | external canary URL in redirect-like params | `Location` must point at canary host; never followed |
| `A01-CORS` | A01 | arbitrary `Origin` header, inspect `Access-Control-*` | reflected vs `*` vs credentials graded separately |
| `A01-TRAV` | A01 | `../` payload in file-like params | needs `/etc/passwd` / `win.ini` signature absent from baseline |
| `A02-HTTP` | A02 | target scheme is `http` | – |
| `A02-HSTS` | A02 | HTTPS without / with weak `Strict-Transport-Security` | only evaluated on HTTPS pages |
| `A02-MIXED` | A02 | `http://` sub-resources on HTTPS pages | active vs passive severity |
| `A02-COOKIE-SECURE` | A02 | `Set-Cookie` without `Secure` | severity depends on HTTPS + session-like name |
| `A03-SQLI` | A03 | `'` / `"` appended to GET params | DB-specific error regex that is **absent in baseline** |
| `A03-XSS` | A03 | unique marker + `<b>` | raw reflection required, HTML content-type only |
| `A05-HEADERS` | A05 | CSP, X-Frame-Options / `frame-ancestors`, nosniff, Referrer-Policy | aggregated per site, CSP frame-ancestors accepted |
| `A05-FILES` | A05 | 13 sensitive paths (`.git`, `.env`, `phpinfo`, SQL dumps ...) | content signature + soft-404 hash + non-HTML; secrets redacted |
| `A05-DIRLIST` | A05 | "Index of /" listings | title + parent-link signature |
| `A05-TRACE` | A05 | framework stack traces / debug pages | 9 specific error signatures |
| `A06-VERSION` | A06 | `Server` / `X-Powered-By` version banners + local CVE hints | hints are labelled "verify" |
| `A07-COOKIE-FLAGS` | A07 | cookie without `HttpOnly` / `SameSite` | one finding per cookie |
| `A07-LOGIN-HTTP` | A07 | password field on non-HTTPS form | – |
| `A08-SRI` | A08 | third-party `<script>`/stylesheet without `integrity` | same-origin resources ignored |

**Not safely testable remotely:** A04 Insecure Design, A09 Logging & Monitoring Failures, A10 SSRF.
Explained in the report (section 6) and in every JSON report under `not_tested`.

## Project layout

```
scanner.py               entry point
vulnscan/
  cli.py                 arguments, consent gate, local-target guard
  core.py                Finding, HttpClient (delay/timeout/cap), ScanContext
  crawler.py             same-site BFS crawler (links, forms, parameters)
  engine.py              run checks in isolation, de-duplicate, build report dict
  report.py              console / JSON / HTML writers
  checks/                one class per check (transport, headers, exposure, access, injection)
labs/                    vulnerable_lab.py (planted flaws), hardened_lab.py (SPA catch-all, for false positives)
tests/                   pytest unit + integration + CLI tests
tools/evaluate.py        scan both labs, write samples/, score TP/FP/FN against ground truth
tools/build_report.py    regenerate docs/architecture.png and docs/Project_Report.pdf
samples/                 two sample JSON reports (+ HTML) and evaluation.json
docs/                    Project_Report.pdf, architecture.png, VIVA_NOTES.md
```

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest -q          # 32 tests: every check unit-tested, labs integration, CLI/consent gate
python tools/evaluate.py     # regenerates samples/ and prints precision / recall
python tools/build_report.py --authors "Your Name (Roll no)" --course "Web / Application Security"
```

## Adding a check

1. Create a class deriving from `vulnscan.checks.base.Check` with `id`, `owasp`, `run(ctx) -> [Finding]`.
2. Add it to `ALL_CHECKS` in `vulnscan/checks/__init__.py`.
3. Add a unit test with a fabricated `Page` or a fake client (see `tests/test_checks.py`).

## Limitations

Static HTML crawler (JavaScript SPAs such as Juice Shop expose few links/forms), GET-only by default,
no authentication, no blind/time-based SQLi, DOM XSS, IDOR or business-logic detection.
Compare against an OWASP ZAP baseline scan to see the difference. See `docs/Project_Report.pdf`.

## CI (bonus)

`.github/workflows/ci.yml` runs the tests and then scans the bundled HardenedLab with `--fail-on high`,
failing the build if a High/Critical finding appears.
