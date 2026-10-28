#!/usr/bin/env python3
"""Build docs/architecture.png and docs/Project_Report.pdf from samples/ (run tools/evaluate.py first).

    python tools/build_report.py --authors "Alice (R101), Bob (R102)" --course "Web / Application Security"
"""
import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt                                   # noqa: E402
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch    # noqa: E402
from reportlab.lib import colors                                  # noqa: E402
from reportlab.lib.pagesizes import A4                            # noqa: E402
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle  # noqa: E402
from reportlab.lib.units import mm                                # noqa: E402
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image,  # noqa: E402
                                KeepTogether)

from vulnscan.checks import ALL_CHECKS                            # noqa: E402

DOCS = os.path.join(ROOT, "docs")


def draw_architecture(path):
    fig, ax = plt.subplots(figsize=(9.2, 4.1), dpi=200)
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 47)
    ax.axis("off")
    n_pass = sum(1 for c in ALL_CHECKS if c.kind == "passive")
    n_probe = len(ALL_CHECKS) - n_pass

    def box(x, y, w, h, title, sub, fc):
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.4,rounding_size=1.2", fc=fc, ec="#334155", lw=1))
        ax.text(x + w / 2, y + h - 3.0, title, ha="center", va="center", fontsize=7.6, fontweight="bold", color="#0f172a")
        ax.text(x + w / 2, y + h / 2 - 2.0, sub, ha="center", va="center", fontsize=6.0, color="#1e293b", linespacing=1.4)

    def arrow(x1, y1, x2, y2, rad=0.0):
        ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=9, lw=1.1, color="#475569",
                                     connectionstyle=f"arc3,rad={rad}"))

    top, th = 25, 13
    box(1, top, 17, th, "CLI  scanner.py", "args, --i-have-permission\nconsent gate, local-target\nguard, delay / page limits", "#dbeafe")
    box(22, top, 17, th, "HttpClient", "User-Agent, delay, timeout\nrequest budget, 1 MB cap\nerrors never crash scan", "#e0e7ff")
    box(43, top, 17, th, "Crawler", "same-site BFS (GET only)\nlinks, forms, parameters\nPage / Form model", "#dcfce7")
    box(64, top, 17, th, "ScanContext", "pages, forms\ninjection points\nbaseline cache", "#fef9c3")
    box(85, top, 14, th, "Target", "localhost / lab\n(authorised only)", "#fee2e2")
    for x1, x2 in ((18.6, 21.4), (39.6, 42.4), (60.6, 63.4)):
        arrow(x1, top + th / 2, x2, top + th / 2)
    arrow(30.5, top + th + 0.6, 92, top + th + 0.6, rad=-0.15)
    ax.text(61, 44.8, "read-only GET requests (crawler + probing checks)", ha="center", fontsize=6.2, color="#475569", style="italic")

    ax.add_patch(FancyBboxPatch((0.6, 1.2), 52.6, 19.2, boxstyle="round,pad=0.3,rounding_size=1", fc="none", ec="#7c3aed", lw=1, ls="--"))
    ax.text(27, 18.6, f"Check modules ({len(ALL_CHECKS)} classes, one per check)", ha="center", fontsize=6.6, fontweight="bold", color="#6d28d9")
    box(2, 2.5, 24, 13, f"Passive ({n_pass})", "headers, cookies, HSTS, mixed\ncontent, SRI, CSRF, version\nbanner, login over HTTP", "#ede9fe")
    box(28, 2.5, 24, 13, f"Probing ({n_probe})", "sensitive files, dir listing, traces\nCORS, redirect, traversal,\nSQLi, XSS (benign markers)", "#fae8ff")
    box(58, 2.5, 17, 13, "Engine", "isolated try/except\nde-duplicate + sort\nseverity, OWASP map", "#ccfbf1")
    box(80, 2.5, 19, 13, "Reports", "console summary\nJSON (evidence, severity,\nOWASP, fix) | HTML", "#ffedd5")
    arrow(72.5, top - 0.4, 40, 20.9, rad=0.0)
    arrow(53.8, 9, 57.2, 9)
    arrow(75.6, 9, 79.2, 9)
    fig.savefig(path, bbox_inches="tight", facecolor="white")
    plt.close(fig)


CHECK_DETAIL = {
    "A02-HTTP": ("Passive", "URL scheme is http", "Medium"),
    "A02-HSTS": ("Passive", "No / short Strict-Transport-Security on HTTPS", "Medium"),
    "A02-MIXED": ("Passive", "http:// sub-resources on https pages", "Low-Med"),
    "A02-COOKIE-SECURE": ("Passive", "Set-Cookie without Secure", "Low-Med"),
    "A07-COOKIE-FLAGS": ("Passive", "Set-Cookie without HttpOnly / SameSite", "Low-Med"),
    "A07-LOGIN-HTTP": ("Passive", "password input on non-HTTPS form", "High"),
    "A05-HEADERS": ("Passive", "CSP, X-Frame-Options/frame-ancestors, nosniff, Referrer-Policy absent", "Low-Med"),
    "A05-FILES": ("Probe", "13 paths; content signature + soft-404 hash + non-HTML", "Med-Crit"),
    "A05-DIRLIST": ("Probe", "'Index of /' signature on crawled/common dirs", "Medium"),
    "A05-TRACE": ("Probe", "9 framework error signatures (traceback, PHP, .NET...)", "Medium"),
    "A06-VERSION": ("Passive", "Server / X-Powered-By version + local CVE hints", "Low-Med"),
    "A08-SRI": ("Passive", "3rd-party script/style without integrity=", "Low-Med"),
    "A01-CSRF": ("Passive", "POST form lacking token-like hidden field", "Medium"),
    "A01-REDIR": ("Probe", "external canary in redirect params; Location checked, never followed", "Medium"),
    "A01-CORS": ("Probe", "Origin reflected / wildcard / with credentials", "Low-High"),
    "A01-TRAV": ("Probe", "../ in file-like params; /etc/passwd or win.ini signature", "High"),
    "A03-SQLI": ("Probe", "' and \" ; DB error regex absent from baseline", "High"),
    "A03-XSS": ("Probe", "unique marker + &lt;b&gt; reflected unescaped in HTML", "High"),
}


def build_pdf(path, authors, course):
    ss = getSampleStyleSheet()
    base = ParagraphStyle("b", parent=ss["Normal"], fontName="Helvetica", fontSize=9.4, leading=12.6, spaceAfter=4)
    small = ParagraphStyle("s", parent=base, fontSize=8.2, leading=10, spaceAfter=0)
    h1 = ParagraphStyle("h1", parent=ss["Heading1"], fontSize=18, leading=22, spaceAfter=2, textColor=colors.HexColor("#0f172a"))
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontSize=11.5, leading=14, spaceBefore=9, spaceAfter=4, textColor=colors.HexColor("#1d4ed8"))
    bullet = ParagraphStyle("bl", parent=base, leftIndent=9, bulletIndent=0, spaceAfter=1.2)

    ev = json.load(open(os.path.join(ROOT, "samples", "evaluation.json")))
    v, h = ev["vulnlab"], ev["hardenedlab"]
    P = lambda t, s=base: Paragraph(t, s)
    B = lambda t: Paragraph(t, bullet, bulletText="\u2022")

    def table(data, widths, header=True, fs=8.2, zebra=True):
        rows = [[Paragraph(str(c), ParagraphStyle("c", parent=small, fontSize=fs, leading=fs + 1.5,
                                                  fontName="Helvetica-Bold" if (header and i == 0) else "Helvetica"))
                 for c in r] for i, r in enumerate(data)]
        t = Table(rows, colWidths=[w * mm for w in widths], repeatRows=1 if header else 0)
        st = [("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")), ("VALIGN", (0, 0), (-1, -1), "TOP"),
              ("TOPPADDING", (0, 0), (-1, -1), 2.4), ("BOTTOMPADDING", (0, 0), (-1, -1), 2.4),
              ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3)]
        if header:
            st.append(("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")))
        if zebra:
            for i in range(2 if header else 1, len(rows), 2):
                st.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#f8fafc")))
        t.setStyle(TableStyle(st))
        return t

    story = [
        P("Lightweight Web Vulnerability Scanner", h1),
        P(f"<b>{course}</b> &nbsp;|&nbsp; Team: {authors} &nbsp;|&nbsp; Python 3, requests, beautifulsoup4", small),
        Spacer(1, 4),
        P("1. Overview and ethics", h2),
        P(f"<b>vulnscan</b> is a command-line scanner that crawls one website, runs <b>{len(ALL_CHECKS)} modular checks</b> covering "
          "<b>7 OWASP Top 10 (2021) categories</b> (A01, A02, A03, A05, A06, A07, A08) and reports, for every finding, the "
          "evidence, severity, OWASP category and a recommended fix, as a console summary and a JSON report (plus an HTML "
          "report). It is <b>non-destructive</b>: only GET requests (POST forms are skipped unless <i>--allow-post</i>), "
          "harmless markers, no data extraction. Safety controls: mandatory <i>--i-have-permission</i> gate; refusal of "
          "non-local targets unless <i>--allow-remote</i>; <i>--delay</i> (default 0.5 s), page limit, depth limit, "
          "hard request cap, per-request timeout, 1 MB body cap and an explicit User-Agent. Only authorised labs may be "
          "scanned (localhost, Juice Shop, DVWA, WebGoat, bWAPP)."),
        P("2. Architecture", h2),
    ]
    arch = os.path.join(DOCS, "architecture.png")
    story.append(Image(arch, width=172 * mm, height=172 * mm * 4.1 / 9.2 * 0.93))
    story += [
        P("<b>Flow.</b> The CLI validates consent and scope, builds the <i>HttpClient</i> and runs the <i>Crawler</i> (same-host "
          "breadth-first, deduplicating URLs by path + parameter names). Pages, forms and unique injection points are held in a "
          "<i>ScanContext</i>. Each check is one class (<font face='Courier'>checks/*.py</font>) with <font face='Courier'>"
          "run(ctx) -&gt; [Finding]</font>; the engine runs them in isolation (an exception in one check is logged and the scan "
          "continues), de-duplicates findings on (check, title, path, parameter), sorts by severity and writes the reports. "
          "Adding a check = adding a class to the registry.", base),
        P("3. Check-to-OWASP mapping", h2),
    ]
    rows = [["Check ID", "OWASP 2021", "Type", "Technique / false-positive guard", "Severity"]]
    for c in sorted(ALL_CHECKS, key=lambda c: (c.owasp, c.id)):
        typ, tech, sev = CHECK_DETAIL[c.id]
        rows.append([c.id, c.owasp, typ, tech, sev])
    rows += [["(not tested)", "A04, A09, A10", "Discussion", "See section 6: not safely/meaningfully testable by a remote read-only scanner", "-"]]
    story.append(table(rows, [34, 20, 20, 83, 17]))

    story += [P("4. Scan results on two lab targets", h2),
              P("Targets are the two intentionally vulnerable/hardened lab apps bundled in <font face='Courier'>labs/</font> "
                "(<b>VulnLab</b>: deliberately vulnerable; <b>HardenedLab</b>: well configured, but returns HTTP 200 + an HTML shell for "
                "<i>every</i> unknown path like a single-page app, to provoke false positives). Both run on 127.0.0.1. "
                "Reports: <font face='Courier'>samples/report_vulnlab.json</font>, <font face='Courier'>samples/report_hardenedlab.json</font>. "
                "Reproduce with <font face='Courier'>python tools/evaluate.py</font>.", base)]
    def sev(d):
        s = d["by_severity"]
        return f"{s['Critical']} / {s['High']} / {s['Medium']} / {s['Low']}"
    story.append(table([
        ["Target", "Pages", "Requests", "Time", "Findings", "Crit / High / Med / Low", "OWASP categories hit"],
        ["VulnLab :8081", v["pages_crawled"], v["requests"], f"{v['duration_s']} s", v["findings"], sev(v), ", ".join(v["owasp_categories"])],
        ["HardenedLab :8082", h["pages_crawled"], h["requests"], f"{h['duration_s']} s", h["findings"], sev(h), ", ".join(h["owasp_categories"])],
    ], [30, 13, 18, 14, 17, 40, 46]))
    story.append(Spacer(1, 3))
    vr = json.load(open(os.path.join(ROOT, "samples", "report_vulnlab.json")))
    top = [f for f in vr["findings"] if f["severity"] in ("Critical", "High")]
    rows = [["Severity", "Finding (VulnLab)", "Where", "OWASP"]]
    for f in top:
        rows.append([f["severity"], f["title"], f["url"].replace("http://127.0.0.1:8081", "") + (f" [{f['parameter']}]" if f["parameter"] else ""), f["owasp"][:3]])
    story.append(table(rows, [16, 84, 62, 17]))
    story.append(P(f"HardenedLab reported only its three genuine weaknesses: HTTP instead of HTTPS (A02), wildcard CORS on a public "
                   f"endpoint (A01, Low) and a missing Referrer-Policy header (A05, Low). The remaining {vr['summary']['total'] - len(top)} "
                   "VulnLab findings are Medium/Low misconfigurations (missing headers, cookie flags, version banners, SRI, CSRF, traceback, "
                   "directory listing, phpinfo).", base))

    fp_rows = [["Target", "Planted / real issues", "True positives", "False positives", "False negatives", "Precision", "Recall"],
               ["VulnLab", v["truth_items"] + len(v["false_negatives_by_design"]), v["true_positives"], v["false_positives"],
                f"{v['false_negatives_detectable'] + len(v['false_negatives_by_design'])} (by design)", v["precision"], v["recall_overall"]],
               ["HardenedLab", h["truth_items"], h["true_positives"], h["false_positives"], h["false_negatives_detectable"], h["precision"], h["recall_overall"]]]
    story += [P("5. False positive / false negative analysis", h2), table(fp_rows, [24, 32, 24, 25, 32, 20, 15]), Spacer(1, 3),
              P("<b>Important caveat:</b> the labs were written together with the scanner, so these numbers are an <i>upper bound</i> "
                "that shows the checks work as designed; they are not an estimate of real-world accuracy. Running the tool on Juice Shop, "
                "DVWA and an OWASP ZAP baseline scan is the recommended next validation step.", base),
              P("<b>False-positive controls built in:</b>", base),
              B("<b>Content signatures, not status codes:</b> .git/HEAD must start with <i>ref: refs/</i>, .env must contain KEY=VALUE lines, "
                "phpinfo must contain <i>PHP Version</i>, SQL errors must match DB-specific regexes."),
              B("<b>Soft-404 baseline:</b> a random non-existent path is fetched first; identical bodies (SPA catch-all) are discarded, and "
                "text files that come back as HTML are ignored. HardenedLab (200 for every path) therefore yields 0 false positives."),
              B("<b>Baseline comparison:</b> SQLi/traversal findings require the signature to appear <i>only</i> after the payload; XSS requires the unique "
                "marker plus un-encoded <i>&lt;b&gt;</i> in an HTML content type (JSON reflection is ignored; encoded reflection is safe)."),
              B("<b>Open redirect</b> is confirmed only when the <i>Location</i> header points to the canary host; the redirect is never followed. "
                "<b>Deduplication</b> collapses repeats per (check, title, path, parameter)."),
              P("<b>False negatives (expected):</b> VulnLab contains three flaws the scanner misses by design: an <b>IDOR</b> (/order?id=), a "
                "<b>blind boolean SQL injection</b> (no error text) and a <b>DOM-based XSS</b> (client-side sink). Others: JavaScript-rendered pages "
                "(static crawler), POST-only parameters (read-only mode), custom error pages without known signatures, parameters named unusually "
                "for traversal/redirect checks, anything behind a login. Compared with an OWASP ZAP baseline scan, a lightweight scanner will not "
                "match ZAP's AJAX spider, passive rule set breadth or active scan depth, and cannot find business-logic flaws, blind/time-based "
                "injection, SSRF or access-control bugs behind authentication.", base),
              P("6. Limitations (including A04, A09, A10)", h2),
              B("<b>A09 Logging and Monitoring Failures:</b> logging, alerting and incident response occur server-side and leave no signal a remote "
                "read-only client can observe. Assess by reviewing log configuration, retention and alert rules."),
              B("<b>A10 SSRF:</b> confirming SSRF safely needs an out-of-band callback server or access to internal services; sending such payloads "
                "would risk harming third parties, so it is intentionally excluded. <b>A04 Insecure Design</b> needs threat modelling, not probing."),
              B("No authentication, no JavaScript execution, GET-only by default, single host scope, 1 MB body cap, and signature matching can both "
                "miss custom messages and flag pages that merely quote error text. HTTPS-only checks (HSTS, mixed content, Secure on HTTPS) are covered "
                "by unit tests with fabricated HTTPS pages because the labs run over HTTP. Version-to-CVE hints use a tiny offline table and must "
                "be verified because distributions back-port fixes."),
              P("7. Remediation advice", h2)]
    story.append(table([
        ["Issue", "Recommended fix"],
        ["SQL injection (A03)", "Parameterised queries / ORM bind variables; validate types; least-privilege DB account; generic error pages."],
        ["Reflected XSS (A03)", "Context-aware output encoding, auto-escaping templates, strict CSP (no unsafe-inline), HttpOnly cookies."],
        ["Path traversal / open redirect (A01)", "Map IDs to files via allow-list and canonicalise paths; redirect only to relative paths or allow-listed hosts."],
        ["CORS / CSRF (A01)", "Allow-list origins, never reflect Origin with credentials; per-session CSRF tokens + SameSite=Lax/Strict."],
        ["No HTTPS / HSTS / cookie flags (A02, A07)", "TLS 1.2+ everywhere, 301 to HTTPS, HSTS max-age>=1 year; Secure, HttpOnly, SameSite on session cookies."],
        ["Exposed .git/.env/phpinfo/listing/traces (A05)", "Deny dotfiles and backups in the web server, remove debug pages, Options -Indexes, disable debug mode, rotate leaked secrets."],
        ["Missing security headers (A05)", "CSP, X-Frame-Options or frame-ancestors, X-Content-Type-Options: nosniff, Referrer-Policy."],
        ["Version banners (A06)", "ServerTokens Prod / server_tokens off / expose_php=Off; patch or upgrade EOL components; track CVEs with an SCA tool."],
        ["Missing SRI (A08)", "Add integrity=\"sha384-...\" + crossorigin, pin versions or self-host third-party scripts."],
    ], [58, 116]))
    story.append(Spacer(1, 6))
    story.append(P("<b>Bonus items implemented:</b> HTML report with severity chart (<i>--html</i>), version-to-CVE lookup from local data, CI step "
                   "failing on High findings (<i>--fail-on high</i>, GitHub Actions workflow). <b>Tests:</b> 32 pytest tests (unit tests for every check "
                   "with fabricated pages, integration tests against the labs, CLI/consent-gate tests).", base))

    doc = SimpleDocTemplate(path, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
                            title="Lightweight Web Vulnerability Scanner - Project Report", author=authors)
    doc.build(story)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--authors", default="[Student name(s) / roll no(s)]")
    ap.add_argument("--course", default="Web / Application Security")
    a = ap.parse_args()
    os.makedirs(DOCS, exist_ok=True)
    draw_architecture(os.path.join(DOCS, "architecture.png"))
    out = os.path.join(DOCS, "Project_Report.pdf")
    build_pdf(out, a.authors, a.course)
    print("wrote", out)
