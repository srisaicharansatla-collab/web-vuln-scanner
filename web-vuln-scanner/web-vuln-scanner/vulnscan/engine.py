"""Scan orchestration: crawl -> run checks (isolated) -> de-duplicate -> sort."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from . import __version__
from .checks import select_checks
from .core import ScanContext, SEVERITY_ORDER
from .crawler import Crawler

NOT_TESTED = [
    {"category": "A04:2021 Insecure Design",
     "reason": "Design flaws and business-logic abuse need understanding of intended behaviour; a generic scanner cannot judge them."},
    {"category": "A09:2021 Security Logging and Monitoring Failures",
     "reason": "Logging, alerting and incident response happen server-side and are invisible to a remote, read-only client. "
               "Review log configuration and alert rules manually."},
    {"category": "A10:2021 Server-Side Request Forgery",
     "reason": "SSRF needs an out-of-band callback server or a harmful internal target to confirm safely; "
               "this tool does not send such payloads."},
]

LIMITATIONS = [
    "Static HTML crawler: JavaScript-rendered single-page apps (e.g. Juice Shop) expose few links/forms.",
    "Only GET parameters and GET forms are fuzzed by default (POST needs --allow-post).",
    "No authentication, so everything behind a login is out of scope.",
    "Blind/time-based SQLi, DOM-based XSS, IDOR and business-logic flaws are not detected.",
    "Signature-based detection can miss custom error pages and may flag documentation pages that quote error text.",
]


def deduplicate(findings):
    seen, out = set(), []
    for f in findings:
        k = f.dedup_key()
        if k in seen:
            continue
        seen.add(k)
        out.append(f)
    return out


def run_scan(base_url, client, checks=None, max_pages=30, max_depth=3, allow_post=False, verbose=False, log=print):
    checks = checks if checks is not None else select_checks()
    started = datetime.now(timezone.utc)
    t0 = time.monotonic()

    log(f"[*] Crawling {base_url} (max {max_pages} pages, depth {max_depth})")
    crawler = Crawler(client, max_pages=max_pages, max_depth=max_depth,
                      log=(lambda m: log(f"    [v] {m}")) if verbose else (lambda m: None))
    pages = crawler.crawl(base_url)
    log(f"[*] Crawled {len(pages)} page(s), {sum(len(p.forms) for p in pages)} form(s)")

    ctx = ScanContext(base_url=base_url, client=client, pages=pages, allow_post=allow_post, verbose=verbose)
    findings, check_errors = [], []
    for chk in checks:
        before = len(findings)
        try:
            findings.extend(chk.run(ctx))
        except Exception as exc:                       # one broken check must not stop the scan
            check_errors.append({"check": chk.id, "error": f"{type(exc).__name__}: {exc}"})
            log(f"    [!] {chk.id} failed: {exc}")
            continue
        log(f"    [+] {chk.id:<18} {len(findings) - before} finding(s)")

    findings = deduplicate(findings)
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.check_id, f.url))

    by_sev = {s: 0 for s in ("Critical", "High", "Medium", "Low", "Info")}
    by_owasp = {}
    for f in findings:
        by_sev[f.severity] += 1
        by_owasp[f.owasp] = by_owasp.get(f.owasp, 0) + 1

    return {
        "tool": {"name": "vulnscan", "version": __version__},
        "target": base_url,
        "started_at": started.isoformat(timespec="seconds"),
        "duration_seconds": round(time.monotonic() - t0, 2),
        "stats": {"pages_crawled": len(pages), "requests_sent": client.request_count,
                  "request_errors": len(client.errors), "checks_run": [c.id for c in checks]},
        "summary": {"total": len(findings), "by_severity": by_sev, "by_owasp": by_owasp},
        "findings": [f.to_dict() for f in findings],
        "not_tested": NOT_TESTED,
        "limitations": LIMITATIONS,
        "check_errors": check_errors,
        "request_error_samples": client.errors[:10],
    }
