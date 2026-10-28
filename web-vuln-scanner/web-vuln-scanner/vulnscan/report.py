"""Console, JSON and HTML (bonus) report writers."""
from __future__ import annotations

import html
import json
import sys

SEV_COLORS = {"Critical": "\033[1;41m", "High": "\033[91m", "Medium": "\033[93m", "Low": "\033[94m", "Info": "\033[90m"}
RESET = "\033[0m"
HTML_COLORS = {"Critical": "#7b0d1e", "High": "#d62828", "Medium": "#f59e0b", "Low": "#2563eb", "Info": "#6b7280"}


def print_console(result, color=None, out=sys.stdout):
    color = out.isatty() if color is None else color

    def c(sev, text):
        return f"{SEV_COLORS[sev]}{text}{RESET}" if color else text

    p = lambda s="": print(s, file=out)
    p()
    p("=" * 78)
    p(f" Scan summary for {result['target']}")
    p("=" * 78)
    st = result["stats"]
    p(f" Pages crawled: {st['pages_crawled']}   Requests: {st['requests_sent']}   "
      f"Errors: {st['request_errors']}   Time: {result['duration_seconds']}s")
    p(f" Findings: {result['summary']['total']}   " +
      "  ".join(c(s, f"{s}: {n}") for s, n in result["summary"]["by_severity"].items() if n or s != "Info"))
    p("-" * 78)
    for f in result["findings"]:
        loc = f["url"] + (f"  [param: {f['parameter']}]" if f.get("parameter") else "")
        p(f" {c(f['severity'], '[' + f['severity'].upper() + ']'):<22} {f['title']}")
        p(f"     OWASP : {f['owasp']}   Check: {f['check_id']}")
        p(f"     Where : {loc}")
        p(f"     Proof : {f['evidence'][:200]}")
        p(f"     Fix   : {f['recommendation'][:200]}")
        p()
    if result["check_errors"]:
        p(" Checks that failed: " + ", ".join(e["check"] for e in result["check_errors"]))
    p(" Not testable remotely: " + "; ".join(n["category"].split(" ")[0] for n in result["not_tested"]) +
      " (see report 'not_tested' section)")
    p("=" * 78)


def write_json(result, path):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, ensure_ascii=False)


def write_html(result, path):
    e = html.escape
    total = max(1, result["summary"]["total"])
    bars = "".join(
        f'<div class="row"><span class="lbl">{s}</span><div class="bar" style="width:{n / total * 100:.0f}%;'
        f'background:{HTML_COLORS[s]}"></div><span class="n">{n}</span></div>'
        for s, n in result["summary"]["by_severity"].items())
    owasp_rows = "".join(f"<tr><td>{e(k)}</td><td>{v}</td></tr>" for k, v in sorted(result["summary"]["by_owasp"].items()))
    cards = ""
    for f in result["findings"]:
        param = f" &middot; parameter <code>{e(f['parameter'])}</code>" if f.get("parameter") else ""
        cards += (f'<div class="card" style="border-left-color:{HTML_COLORS[f["severity"]]}">'
                  f'<h3><span class="sev" style="background:{HTML_COLORS[f["severity"]]}">{e(f["severity"])}</span> '
                  f'{e(f["title"])}</h3><p class="meta">{e(f["owasp"])} &middot; {e(f["check_id"])}</p>'
                  f'<p><b>Where:</b> <code>{e(f["url"])}</code>{param}</p>'
                  f'<p><b>Evidence:</b> {e(f["evidence"])}</p><p><b>Fix:</b> {e(f["recommendation"])}</p></div>')
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>VulnScan report</title><style>
body{{font-family:system-ui,Segoe UI,Arial,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;color:#111}}
.row{{display:flex;align-items:center;gap:.5rem;margin:.2rem 0}}.lbl{{width:70px}}.bar{{height:16px;border-radius:3px;min-width:2px}}
.card{{border:1px solid #ddd;border-left:6px solid;border-radius:6px;padding:.5rem 1rem;margin:1rem 0}}
.sev{{color:#fff;border-radius:4px;padding:1px 8px;font-size:.8rem}}.meta{{color:#555;margin-top:-.5rem}}
code{{background:#f3f4f6;padding:1px 4px;border-radius:3px;word-break:break-all}}table{{border-collapse:collapse}}
td{{border:1px solid #ddd;padding:2px 10px}}</style></head><body>
<h1>VulnScan report</h1><p>Target: <code>{e(result['target'])}</code><br>Started: {e(result['started_at'])} &middot;
Duration: {result['duration_seconds']}s &middot; Pages: {result['stats']['pages_crawled']} &middot;
Requests: {result['stats']['requests_sent']}</p>
<h2>Findings by severity ({result['summary']['total']})</h2>{bars}
<h2>By OWASP category</h2><table>{owasp_rows}</table><h2>Findings</h2>{cards}
<h2>Not testable remotely</h2><ul>{''.join(f"<li><b>{e(n['category'])}</b>: {e(n['reason'])}</li>" for n in result['not_tested'])}</ul>
<h2>Limitations</h2><ul>{''.join(f'<li>{e(l)}</li>' for l in result['limitations'])}</ul>
</body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
