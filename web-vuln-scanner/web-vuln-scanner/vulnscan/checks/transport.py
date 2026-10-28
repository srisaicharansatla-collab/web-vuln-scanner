"""A02 Cryptographic Failures + A07 Authentication checks that are purely passive."""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from .base import Check

SESSION_NAME = re.compile(r"(sess|sid|auth|token|jwt|login|remember)", re.I)


class HttpInsteadOfHttps(Check):
    id = "A02-HTTP"
    name = "Site served over plain HTTP"
    owasp = "A02"
    description = "Target URL uses http:// so all traffic is readable/modifiable on the network."

    def run(self, ctx):
        if ctx.is_https:
            return []
        host = ctx.parts.hostname or ""
        note = " (expected for a local lab, critical for a production site)" if host in ("localhost", "127.0.0.1", "::1") else ""
        return [self.finding(
            "Site is served over HTTP instead of HTTPS", "Medium", ctx.base_url,
            f"Scheme of target is 'http'{note}. Credentials, cookies and content travel unencrypted.",
            "Serve the whole site over HTTPS (TLS 1.2+), redirect HTTP to HTTPS with a 301 and enable HSTS.")]


class MissingHsts(Check):
    id = "A02-HSTS"
    name = "Missing / weak HSTS header"
    owasp = "A02"
    description = "HTTPS responses must send Strict-Transport-Security."

    def run(self, ctx):
        out = []
        https_pages = [p for p in ctx.html_pages() if p.url.startswith("https://")]
        if not https_pages:
            return out
        missing = [p for p in https_pages if not p.header("Strict-Transport-Security")]
        if missing:
            out.append(self.finding(
                "HTTP Strict-Transport-Security (HSTS) header missing", "Medium", ctx.base_url,
                f"Header absent on {len(missing)}/{len(https_pages)} HTTPS pages (e.g. {missing[0].url}).",
                "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to every HTTPS response."))
        else:
            val = https_pages[0].header("Strict-Transport-Security") or ""
            m = re.search(r"max-age=(\d+)", val, re.I)
            if m and int(m.group(1)) < 15552000:
                out.append(self.finding(
                    "HSTS max-age is too short", "Low", ctx.base_url,
                    f"Strict-Transport-Security: {val}", "Use max-age of at least 15552000 (180 days), ideally 31536000."))
        return out


class MixedContent(Check):
    id = "A02-MIXED"
    name = "Mixed content on HTTPS pages"
    owasp = "A02"
    description = "HTTPS page loading sub-resources over http://."

    ACTIVE = (("script", "src"), ("iframe", "src"), ("link", "href"), ("object", "data"), ("embed", "src"))
    PASSIVE = (("img", "src"), ("audio", "src"), ("video", "src"), ("source", "src"))

    def run(self, ctx):
        out = []
        for page in ctx.html_pages():
            if not page.url.startswith("https://") or page.soup is None:
                continue
            for group, sev in ((self.ACTIVE, "Medium"), (self.PASSIVE, "Low")):
                hits = []
                for tag, attr in group:
                    for el in page.soup.find_all(tag):
                        if tag == "link" and "stylesheet" not in " ".join(el.get("rel", [])).lower():
                            continue
                        val = (el.get(attr) or "").strip()
                        if val.lower().startswith("http://"):
                            hits.append(val)
                if hits:
                    kind = "active (scripts/frames/styles)" if sev == "Medium" else "passive (images/media)"
                    out.append(self.finding(
                        f"Mixed content: {kind} loaded over HTTP", sev, page.url,
                        f"{len(hits)} insecure resource(s), e.g. {hits[0]}",
                        "Load every sub-resource over https:// (or protocol-relative/relative URLs) and add a CSP "
                        "'upgrade-insecure-requests' directive."))
        return out


def parse_cookie(raw: str):
    parts = [p.strip() for p in raw.split(";")]
    name, _, value = parts[0].partition("=")
    attrs = {}
    for p in parts[1:]:
        k, _, v = p.partition("=")
        attrs[k.strip().lower()] = v.strip()
    return name.strip(), value, attrs


class CookieSecureFlag(Check):
    id = "A02-COOKIE-SECURE"
    name = "Cookie without Secure flag"
    owasp = "A02"
    description = "Cookies lacking Secure can be sent over plain HTTP."

    def run(self, ctx):
        out, seen = [], set()
        for page in ctx.pages:
            for raw in page.set_cookies:
                name, _, attrs = parse_cookie(raw)
                if name in seen or "secure" in attrs:
                    continue
                seen.add(name)
                https = page.url.startswith("https://")
                sev = "Medium" if (https and SESSION_NAME.search(name)) else "Low"
                out.append(self.finding(
                    f"Cookie '{name}' set without Secure flag", sev, page.url,
                    f"Set-Cookie: {name}=<redacted>; " + "; ".join(attrs) if attrs else f"Set-Cookie: {name}=<redacted>",
                    "Add the 'Secure' attribute so the cookie is only sent over HTTPS.", parameter=name))
        return out


class CookieAuthFlags(Check):
    id = "A07-COOKIE-FLAGS"
    name = "Cookie without HttpOnly / SameSite"
    owasp = "A07"
    description = "Session cookies should be HttpOnly (XSS theft) and SameSite (CSRF)."

    def run(self, ctx):
        out, seen = [], set()
        for page in ctx.pages:
            for raw in page.set_cookies:
                name, _, attrs = parse_cookie(raw)
                sess = bool(SESSION_NAME.search(name))
                if "httponly" not in attrs and (name, "h") not in seen:
                    seen.add((name, "h"))
                    out.append(self.finding(
                        f"Cookie '{name}' set without HttpOnly flag", "Medium" if sess else "Low", page.url,
                        f"Set-Cookie attributes seen: {', '.join(attrs) or 'none'}",
                        "Add 'HttpOnly' so JavaScript (and therefore XSS payloads) cannot read the cookie.",
                        parameter=name))
                if "samesite" not in attrs and (name, "s") not in seen:
                    seen.add((name, "s"))
                    out.append(self.finding(
                        f"Cookie '{name}' set without SameSite attribute", "Medium" if sess else "Low", page.url,
                        f"Set-Cookie attributes seen: {', '.join(attrs) or 'none'}",
                        "Add 'SameSite=Lax' (or Strict) to limit cross-site sending and reduce CSRF risk.",
                        parameter=name))
        return out


class LoginFormOverHttp(Check):
    id = "A07-LOGIN-HTTP"
    name = "Login form over HTTP"
    owasp = "A07"
    description = "Password field on a page or posting to a URL that is not HTTPS."

    def run(self, ctx):
        out, seen = [], set()
        for page in ctx.pages:
            for form in page.forms:
                if not form.has_password:
                    continue
                insecure = page.url.startswith("http://") or form.action.startswith("http://")
                key = (urlsplit(form.action).netloc, urlsplit(form.action).path)
                if insecure and key not in seen:
                    seen.add(key)
                    out.append(self.finding(
                        "Login form transmits credentials over HTTP", "High", page.url,
                        f"Form with password field (action={form.action}, method={form.method}) is not protected by TLS.",
                        "Serve the login page and the form action over HTTPS only and redirect all HTTP requests."))
        return out
