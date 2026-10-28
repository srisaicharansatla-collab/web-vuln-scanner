#!/usr/bin/env python3
"""Scan both bundled labs, write sample reports, and score results against planted ground truth.

    python tools/evaluate.py          # writes samples/*.json, samples/*.html and samples/evaluation.json

Ground truth = the flaws that were deliberately planted in labs/*.py. A finding that matches no
truth item is counted as a false positive; a truth item with no finding is a false negative.
"""
import json
import os
import sys
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from labs import vulnerable_lab, hardened_lab          # noqa: E402
from vulnscan.core import HttpClient                   # noqa: E402
from vulnscan.engine import run_scan                   # noqa: E402
from vulnscan.report import write_json, write_html     # noqa: E402

# (check_id, [substrings that must all appear in title+url+parameter]) -> a flaw the scanner SHOULD find
VULN_TRUTH = [
    ("A01-CSRF", ["/comment"]), ("A01-CSRF", ["/login"]), ("A01-REDIR", ["next"]), ("A01-CORS", ["/api/data"]),
    ("A01-TRAV", ["file"]), ("A02-HTTP", []), ("A02-COOKIE-SECURE", ["PHPSESSID"]), ("A02-COOKIE-SECURE", ["theme"]),
    ("A03-SQLI", ["id"]), ("A03-XSS", ["q"]),
    ("A05-HEADERS", ["Content-Security-Policy"]), ("A05-HEADERS", ["Clickjacking"]), ("A05-HEADERS", ["nosniff"]),
    ("A05-HEADERS", ["Referrer"]), ("A05-FILES", [".git/HEAD"]), ("A05-FILES", [".env"]), ("A05-FILES", ["phpinfo"]),
    ("A05-DIRLIST", ["/uploads/"]), ("A05-TRACE", ["/error"]),
    ("A06-VERSION", ["Server"]), ("A06-VERSION", ["X-Powered-By"]),
    ("A07-COOKIE-FLAGS", ["PHPSESSID", "HttpOnly"]), ("A07-COOKIE-FLAGS", ["PHPSESSID", "SameSite"]),
    ("A07-COOKIE-FLAGS", ["theme", "HttpOnly"]), ("A07-COOKIE-FLAGS", ["theme", "SameSite"]),
    ("A07-LOGIN-HTTP", ["/login"]), ("A08-SRI", ["lib.js"]),
]
# planted flaws that a lightweight, unauthenticated, signature-based scanner cannot see -> expected false negatives
VULN_UNDETECTABLE = [
    ("IDOR on /order?id=", "A01 - needs two accounts / knowledge of object ownership"),
    ("Blind boolean SQLi on /blind?id=", "A03 - no error text; needs differential/time-based testing"),
    ("DOM-based XSS on /dom#", "A03 - sink is client-side JavaScript; needs a JS-executing browser"),
]
HARD_TRUTH = [("A02-HTTP", []), ("A01-CORS", ["/api/public"]), ("A05-HEADERS", ["Referrer"])]


def match(findings, truth):
    used, tp, fn = set(), [], []
    for cid, subs in truth:
        hit = next((i for i, f in enumerate(findings) if i not in used and f["check_id"] == cid and
                    all(s.lower() in (f["title"] + " " + f["url"] + " " + (f["parameter"] or "")).lower() for s in subs)), None)
        if hit is None:
            fn.append((cid, subs))
        else:
            used.add(hit)
            tp.append((cid, subs))
    fp = [findings[i] for i in range(len(findings)) if i not in used]
    return tp, fp, fn


def serve(module, port):
    srv = module.make_server(port)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def main():
    os.makedirs(os.path.join(ROOT, "samples"), exist_ok=True)
    summary = {}
    for name, module, port, truth, undetect in (
            ("vulnlab", vulnerable_lab, 8081, VULN_TRUTH, VULN_UNDETECTABLE),
            ("hardenedlab", hardened_lab, 8082, HARD_TRUTH, [])):
        srv = serve(module, port)
        url = f"http://127.0.0.1:{port}"
        res = run_scan(url, HttpClient(delay=0.05, timeout=5), log=lambda m: None)
        srv.shutdown()
        base = os.path.join(ROOT, "samples", f"report_{name}")
        write_json(res, base + ".json")
        write_html(res, base + ".html")
        tp, fp, fn = match(res["findings"], truth)
        n_fn_total = len(fn) + len(undetect)
        summary[name] = {
            "target": url, "findings": len(res["findings"]), "by_severity": res["summary"]["by_severity"],
            "pages_crawled": res["stats"]["pages_crawled"], "requests": res["stats"]["requests_sent"],
            "duration_s": res["duration_seconds"],
            "owasp_categories": sorted({f["owasp"][:3] for f in res["findings"]}),
            "truth_items": len(truth), "true_positives": len(tp), "false_positives": len(fp),
            "false_negatives_detectable": len(fn), "false_negatives_by_design": [u[0] for u in undetect],
            "precision": round(len(tp) / max(1, len(tp) + len(fp)), 3),
            "recall_detectable": round(len(tp) / max(1, len(truth)), 3),
            "recall_overall": round(len(tp) / max(1, len(truth) + len(undetect)), 3),
            "fp_details": [f"{f['check_id']}: {f['title']}" for f in fp],
            "fn_details": [f"{c}: {s}" for c, s in fn],
        }
        print(f"\n== {name} ({url}) ==")
        print(f"  findings={len(res['findings'])}  TP={len(tp)}  FP={len(fp)}  FN(detectable)={len(fn)}  "
              f"FN(by design)={len(undetect)}  precision={summary[name]['precision']}  "
              f"recall(detectable)={summary[name]['recall_detectable']}  recall(overall)={summary[name]['recall_overall']}")
        for f in fp:
            print("  FP ->", f["check_id"], f["title"])
        for c, s in fn:
            print("  FN ->", c, s)
    with open(os.path.join(ROOT, "samples", "evaluation.json"), "w") as fh:
        json.dump(summary, fh, indent=2)
    print("\nWrote samples/report_vulnlab.json, samples/report_hardenedlab.json (+ .html) and samples/evaluation.json")


if __name__ == "__main__":
    main()
