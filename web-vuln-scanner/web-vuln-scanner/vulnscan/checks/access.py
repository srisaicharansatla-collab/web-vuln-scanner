"""A01 Broken Access Control: CSRF token, open redirect, CORS, path traversal indicator."""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from .base import Check

CSRF_NAME = re.compile(r"(csrf|xsrf|token|authenticity|nonce|anti-?forgery|__requestverificationtoken|_wpnonce)", re.I)
CANARY_HOST = "vulnscan-canary.invalid"            # .invalid never resolves; we never follow redirects
CANARY_URL = f"https://{CANARY_HOST}/redirect-test"


class MissingCsrfToken(Check):
    id = "A01-CSRF"
    name = "State-changing form without CSRF token"
    owasp = "A01"
    description = "POST forms with no hidden anti-CSRF token field."

    def run(self, ctx):
        out, seen = [], set()
        for page in ctx.pages:
            for form in page.forms:
                if form.method != "POST":
                    continue
                key = (urlsplit(form.action).path, tuple(sorted(i["name"] for i in form.inputs)))
                if key in seen:
                    continue
                seen.add(key)
                if any(CSRF_NAME.search(i["name"]) for i in form.inputs):
                    continue
                fields = ", ".join(i["name"] for i in form.inputs) or "none"
                out.append(self.finding(
                    "POST form has no anti-CSRF token", "Medium", form.action,
                    f"Form on {page.url} (method=POST, fields: {fields}) contains no field resembling a CSRF token.",
                    "Add a per-session unpredictable CSRF token validated on the server (or use the double-submit "
                    "cookie pattern) and set SameSite=Lax/Strict on session cookies."))
        return out


REDIRECT_PARAMS = re.compile(r"^(next|url|redirect|redirect_uri|redirect_url|return|returnurl|return_to|dest|destination|"
                             r"continue|goto|target|r|u|link|forward|callback)$", re.I)


class OpenRedirect(Check):
    id = "A01-REDIR"
    name = "Open redirect"
    owasp = "A01"
    kind = "probe"
    description = "Sends an external canary URL in redirect-like parameters (redirect is NOT followed)."

    def run(self, ctx):
        out = []
        for pt in ctx.injection_points():
            if pt.method != "GET":
                continue
            for name, val in pt.params.items():
                if not (REDIRECT_PARAMS.match(name) or re.match(r"https?://", val or "")):
                    continue
                params = dict(pt.params, **{name: CANARY_URL})
                r = ctx.client.get(pt.url, params=params, allow_redirects=False)
                if r is None or r.status_code not in (301, 302, 303, 307, 308):
                    continue
                loc = r.headers.get("Location", "")
                if urlsplit(loc).netloc.lower() == CANARY_HOST:
                    out.append(self.finding(
                        "Open redirect via parameter", "Medium", pt.url,
                        f"HTTP {r.status_code} with Location: {loc} when '{name}' was set to an external canary URL.",
                        "Only redirect to relative paths or to an allow-list of hosts; never trust a user-supplied URL.",
                        parameter=name))
        return out


class CorsMisconfiguration(Check):
    id = "A01-CORS"
    name = "Permissive CORS policy"
    owasp = "A01"
    kind = "probe"
    description = "Sends an arbitrary Origin header and inspects Access-Control-Allow-* response headers."

    EVIL = "https://evil.vulnscan.invalid"

    def _targets(self, ctx):
        urls = [ctx.base_url]
        for p in ctx.pages:
            if "json" in p.content_type or "/api" in urlsplit(p.url).path.lower():
                if p.url not in urls:
                    urls.append(p.url)
        return urls[:8]

    def run(self, ctx):
        out = []
        for url in self._targets(ctx):
            r = ctx.client.get(url, headers={"Origin": self.EVIL}, allow_redirects=False)
            if r is None:
                continue
            acao = r.headers.get("Access-Control-Allow-Origin")
            acac = (r.headers.get("Access-Control-Allow-Credentials") or "").lower() == "true"
            if not acao:
                continue
            if acao == self.EVIL:
                sev = "High" if acac else "Medium"
                out.append(self.finding(
                    "CORS reflects arbitrary Origin" + (" with credentials" if acac else ""), sev, url,
                    f"Origin: {self.EVIL} -> Access-Control-Allow-Origin: {acao}; Allow-Credentials: {acac}",
                    "Validate Origin against a strict allow-list; never combine reflected origins with credentials."))
            elif acao == "*":
                out.append(self.finding(
                    "CORS allows any origin (wildcard)", "Low", url,
                    "Access-Control-Allow-Origin: * (acceptable only for fully public, non-credentialed data).",
                    "Restrict to the origins that need access if the response is not public."))
        return out


TRAVERSAL_PARAMS = re.compile(r"(file|path|page|doc|document|template|include|inc|dir|folder|load|read|view|name|download|lang)", re.I)
TRAVERSAL_PAYLOADS = [
    ("../../../../../../etc/passwd", re.compile(r"root:[x*!]?:0:0:")),
    ("..\\..\\..\\..\\..\\..\\windows\\win.ini", re.compile(r"\[(fonts|extensions|mci extensions)\]", re.I)),
]


class PathTraversalIndicator(Check):
    id = "A01-TRAV"
    name = "Path traversal indicator"
    owasp = "A01"
    kind = "probe"
    description = "Sends ../ sequences in file-like parameters and looks for a standard OS file signature."

    def run(self, ctx):
        out = []
        for pt in ctx.injection_points():
            if pt.method != "GET":
                continue
            base = ctx.baseline(pt)
            base_text = base.text if base is not None else ""
            for name in pt.params:
                if not TRAVERSAL_PARAMS.search(name):
                    continue
                for payload, sig in TRAVERSAL_PAYLOADS:
                    r = ctx.send(pt, name, payload)
                    if r is None or not sig.search(r.text) or sig.search(base_text):
                        continue
                    out.append(self.finding(
                        "Path traversal indicator (OS file signature in response)", "High", pt.url,
                        f"Parameter '{name}' with '{payload}' returned content matching the signature "
                        f"{sig.pattern!r}. (File contents are intentionally not stored in this report.)",
                        "Never build file paths from user input; map IDs to files via an allow-list, canonicalise the "
                        "path and verify it stays inside the intended base directory.", parameter=name))
                    break
        return out
