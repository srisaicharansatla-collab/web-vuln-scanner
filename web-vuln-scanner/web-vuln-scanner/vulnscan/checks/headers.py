"""A05 security headers, A06 version disclosure (+ local CVE hints), A08 SRI."""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from .base import Check

# Small local, offline hint table (bonus: version -> advisory lookup).
# Indicative only: distributions often back-port fixes, so every hit says "verify".
CVE_HINTS = [
    # (product regex, predicate(version tuple), advisory text)
    (r"apache", lambda v: v in ((2, 4, 49), (2, 4, 50)),
     "Apache httpd 2.4.49/2.4.50: CVE-2021-41773 / CVE-2021-42013 (path traversal, possible RCE)"),
    (r"nginx", lambda v: v <= (1, 20, 0),
     "nginx <= 1.20.0: CVE-2021-23017 (resolver off-by-one)"),
    (r"php", lambda v: v < (7, 4),
     "PHP < 7.4 is end-of-life and no longer receives security fixes"),
    (r"microsoft-iis", lambda v: v <= (6, 0),
     "IIS 6.0: CVE-2017-7269 (WebDAV buffer overflow) and end-of-life"),
    (r"openssl", lambda v: v < (1, 1, 1),
     "OpenSSL < 1.1.1 is end-of-life"),
]


def parse_version(text: str):
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", text)
    if not m:
        return None
    return tuple(int(x) if x else 0 for x in m.groups())


class SecurityHeaders(Check):
    id = "A05-HEADERS"
    name = "Missing security headers"
    owasp = "A05"
    description = "CSP, X-Frame-Options (or frame-ancestors), X-Content-Type-Options, Referrer-Policy."

    def run(self, ctx):
        pages = [p for p in ctx.html_pages() if p.status == 200]
        if not pages:
            return []
        out = []

        def missing(pred):
            return [p for p in pages if not pred(p)]

        def ev(name, bad):
            return f"Header '{name}' absent on {len(bad)}/{len(pages)} HTML pages (e.g. {bad[0].url})."

        bad = missing(lambda p: p.header("Content-Security-Policy"))
        if bad:
            out.append(self.finding(
                "Content-Security-Policy header missing", "Medium", ctx.base_url, ev("Content-Security-Policy", bad),
                "Define a restrictive CSP (e.g. default-src 'self'; object-src 'none'; frame-ancestors 'none') "
                "to limit the impact of XSS."))
        else:
            weak = [p for p in pages if re.search(r"'unsafe-(inline|eval)'", p.header("Content-Security-Policy") or "")]
            if weak:
                out.append(self.finding(
                    "Content-Security-Policy allows unsafe-inline/unsafe-eval", "Low", ctx.base_url,
                    f"CSP on {weak[0].url}: {weak[0].header('Content-Security-Policy')[:200]}",
                    "Remove 'unsafe-inline'/'unsafe-eval'; use nonces or hashes for required inline scripts."))

        bad = missing(lambda p: p.header("X-Frame-Options") or
                      re.search(r"frame-ancestors", p.header("Content-Security-Policy") or "", re.I))
        if bad:
            out.append(self.finding(
                "Clickjacking protection missing (X-Frame-Options / frame-ancestors)", "Medium", ctx.base_url,
                ev("X-Frame-Options", bad),
                "Send 'X-Frame-Options: DENY' (or SAMEORIGIN) or CSP 'frame-ancestors'."))

        bad = missing(lambda p: (p.header("X-Content-Type-Options") or "").lower() == "nosniff")
        if bad:
            out.append(self.finding(
                "X-Content-Type-Options: nosniff missing", "Low", ctx.base_url, ev("X-Content-Type-Options", bad),
                "Send 'X-Content-Type-Options: nosniff' to stop MIME-type sniffing."))

        bad = missing(lambda p: p.header("Referrer-Policy"))
        if bad:
            out.append(self.finding(
                "Referrer-Policy header missing", "Low", ctx.base_url, ev("Referrer-Policy", bad),
                "Send 'Referrer-Policy: strict-origin-when-cross-origin' (or stricter)."))
        return out


class VersionDisclosure(Check):
    id = "A06-VERSION"
    name = "Server / framework version disclosure"
    owasp = "A06"
    description = "Server, X-Powered-By, X-AspNet-Version, X-Generator headers revealing versions."

    HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator")

    def run(self, ctx):
        out, seen = [], set()
        for page in ctx.pages:
            for h in self.HEADERS:
                val = page.header(h)
                if not val or (h, val) in seen:
                    continue
                version = parse_version(val)
                if not version:
                    continue
                seen.add((h, val))
                hint = ""
                for prod, pred, text in CVE_HINTS:
                    if re.search(prod, val, re.I) and pred(version):
                        hint = f" Known issue hint (verify, may be back-ported): {text}."
                        break
                sev = "Medium" if hint else "Low"
                out.append(self.finding(
                    f"Version disclosed in '{h}' header", sev, page.url, f"{h}: {val}.{hint}",
                    "Hide version banners (Apache: ServerTokens Prod; nginx: server_tokens off; PHP: expose_php=Off) "
                    "and keep components patched.", parameter=h))
        return out


class MissingSri(Check):
    id = "A08-SRI"
    name = "External scripts without Subresource Integrity"
    owasp = "A08"
    description = "Cross-origin <script>/<link rel=stylesheet> lacking an integrity attribute."

    def run(self, ctx):
        out, seen = [], set()
        for page in ctx.html_pages():
            if page.soup is None:
                continue
            host = urlsplit(page.url).netloc.lower()
            elems = [(el, "src", "script") for el in page.soup.find_all("script", src=True)]
            elems += [(el, "href", "stylesheet") for el in page.soup.find_all("link", href=True)
                      if "stylesheet" in " ".join(el.get("rel", [])).lower()]
            for el, attr, kind in elems:
                val = el[attr].strip()
                if val.startswith("//"):
                    val = urlsplit(page.url).scheme + ":" + val
                if not re.match(r"https?://", val, re.I):
                    continue
                if urlsplit(val).netloc.lower() == host or el.get("integrity") or val in seen:
                    continue
                seen.add(val)
                out.append(self.finding(
                    f"External {kind} loaded without Subresource Integrity", "Medium" if kind == "script" else "Low",
                    page.url, f"{val} has no 'integrity' attribute (included from {page.url}).",
                    "Add integrity=\"sha384-...\" and crossorigin=\"anonymous\" to third-party resources, or self-host them.",
                    parameter=val))
        return out
