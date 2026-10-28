"""A05 Security Misconfiguration: exposed files, directory listing, stack traces.

All three use *content signatures* (not just HTTP 200) so catch-all/SPA servers
that answer 200 for every path do not cause false positives.
"""
from __future__ import annotations

import hashlib
import re
import secrets
from urllib.parse import urlsplit

from .base import Check


def _is_html(resp) -> bool:
    return "html" in resp.headers.get("Content-Type", "").lower()


# (path, severity, label, signature function(resp)->bool, requires_non_html)
def _env_sig(r):
    lines = re.findall(r"(?m)^[A-Z][A-Z0-9_]{2,}\s*=\s*\S+", r.text)
    return len(lines) >= 2 or (len(lines) >= 1 and re.search(r"(PASS|SECRET|KEY|TOKEN|DB_)", r.text))


SENSITIVE = [
    ("/.git/HEAD", "High", "Git repository metadata", lambda r: re.match(r"\s*ref:\s*refs/", r.text) is not None, True),
    ("/.git/config", "High", "Git configuration", lambda r: "[core]" in r.text, True),
    ("/.env", "Critical", "Environment file with secrets", _env_sig, True),
    ("/phpinfo.php", "Medium", "phpinfo() page", lambda r: "phpinfo()" in r.text or "PHP Version" in r.text, False),
    ("/info.php", "Medium", "phpinfo() page", lambda r: "phpinfo()" in r.text or "PHP Version" in r.text, False),
    ("/.htpasswd", "High", "Apache password file", lambda r: re.search(r"(?m)^[\w.@-]+:(\$apr1\$|\{SHA\}|\$2[aby]\$|[A-Za-z0-9./]{13}$)", r.text) is not None, True),
    ("/.DS_Store", "Low", "macOS directory metadata", lambda r: "Bud1" in r.text[:64], True),
    ("/server-status", "Medium", "Apache server-status page", lambda r: "Apache Server Status" in r.text, False),
    ("/actuator/env", "High", "Spring Boot actuator environment", lambda r: '"propertySources"' in r.text, True),
    ("/WEB-INF/web.xml", "High", "Java web.xml descriptor", lambda r: "<web-app" in r.text, True),
    ("/backup.sql", "Critical", "Database dump", lambda r: re.search(r"(?i)CREATE TABLE|INSERT INTO", r.text) is not None, True),
    ("/dump.sql", "Critical", "Database dump", lambda r: re.search(r"(?i)CREATE TABLE|INSERT INTO", r.text) is not None, True),
    ("/config.php.bak", "High", "PHP config backup (source disclosure)", lambda r: "<?php" in r.text, True),
]


class SensitiveFiles(Check):
    id = "A05-FILES"
    name = "Exposed sensitive files"
    owasp = "A05"
    kind = "probe"
    description = "Probes ~13 well-known paths (.git, .env, phpinfo ...) and validates content signatures."

    def run(self, ctx):
        out = []
        # soft-404 baseline: what does the server return for a path that cannot exist?
        rnd = ctx.client.get(f"{ctx.origin}/vulnscan-{secrets.token_hex(6)}", allow_redirects=False)
        soft404 = None
        if rnd is not None and rnd.status_code == 200:
            soft404 = hashlib.sha256(rnd.content).hexdigest()
        for path, sev, label, sig, non_html in SENSITIVE:
            r = ctx.client.get(ctx.origin + path, allow_redirects=False)
            if r is None or r.status_code != 200 or not r.content:
                continue
            if soft404 and hashlib.sha256(r.content).hexdigest() == soft404:
                continue                                    # catch-all page, not the file
            if non_html and _is_html(r):
                continue                                    # SPA fallback / error page
            try:
                matched = sig(r)
            except Exception:
                matched = False
            if not matched:
                continue
            note = "values redacted" if path in ("/.env", "/.htpasswd") else "signature matched"
            out.append(self.finding(
                f"Exposed {label}", sev, ctx.origin + path,
                f"HTTP 200, Content-Type '{r.headers.get('Content-Type', '?')}', {len(r.content)} bytes, "
                f"content signature for '{label}' matched ({note}).",
                "Remove the file from the web root or deny access in the web server config; rotate any secrets "
                "that were exposed."))
        return out


DIR_SIGS = (
    re.compile(r"<title>\s*Index of /", re.I),
    re.compile(r"<h1>\s*Index of /", re.I),
    re.compile(r"Directory listing for /", re.I),
    re.compile(r"<title>\s*Directory Listing For", re.I),
)
COMMON_DIRS = ["/uploads/", "/images/", "/static/", "/assets/", "/backup/", "/files/", "/logs/", "/tmp/"]


def is_dir_listing(text: str) -> bool:
    if not any(s.search(text) for s in DIR_SIGS):
        return False
    return bool(re.search(r"Parent Directory|href=\"\.\./?\"|\[To Parent Directory\]|<a href=\"\.\.", text, re.I)
                or "Directory listing for /" in text or text.lower().count("<a href=") >= 2)


class DirectoryListing(Check):
    id = "A05-DIRLIST"
    name = "Directory listing enabled"
    owasp = "A05"
    kind = "probe"
    description = "Fetches directories seen in crawled URLs and common folders, matches 'Index of /' signatures."

    def run(self, ctx):
        dirs = []
        for p in ctx.pages:
            path = urlsplit(p.url).path
            for link in [p.url] + p.links:
                if urlsplit(link).netloc != ctx.parts.netloc:
                    continue
                lp = urlsplit(link).path
                if lp.endswith("/") and lp != "/" and lp not in dirs:
                    dirs.append(lp)
        for d in COMMON_DIRS:
            if d not in dirs:
                dirs.append(d)
        out = []
        for d in dirs[:15]:
            r = ctx.client.get(ctx.origin + d, allow_redirects=False)
            if r is not None and r.status_code == 200 and _is_html(r) and is_dir_listing(r.text):
                out.append(self.finding(
                    "Directory listing enabled", "Medium", ctx.origin + d,
                    "Response contains an 'Index of /' style listing of files.",
                    "Disable auto-indexing (Apache: Options -Indexes; nginx: autoindex off) and add an index file."))
        return out


TRACE_SIGS = [
    ("Python traceback", re.compile(r"Traceback \(most recent call last\)")),
    ("Java stack trace", re.compile(r"\bat [\w.$]+\([\w$]+\.java:\d+\)")),
    ("Java exception", re.compile(r"Exception in thread \"")),
    ("PHP error", re.compile(r"(Warning|Fatal error|Notice|Parse error): .{3,200} in \S+ on line \d+")),
    ("ASP.NET error", re.compile(r"Server Error in '[^']*' Application")),
    (".NET stack trace", re.compile(r"\bat System\.[\w.]+\(")),
    ("Node.js stack trace", re.compile(r"\bat [\w.<>$ ]+ \((?:/|[A-Za-z]:\\)[^)\n]+:\d+:\d+\)")),
    ("Django debug page", re.compile(r"You're seeing this error because you have DEBUG = True")),
    ("Rails error page", re.compile(r"ActionController::RoutingError|Rails\.root:")),
]


class StackTraceDisclosure(Check):
    id = "A05-TRACE"
    name = "Verbose error / stack trace disclosure"
    owasp = "A05"
    kind = "probe"
    description = "Looks for framework error signatures in crawled pages and in an error-provoking request."

    def run(self, ctx):
        out, seen = [], set()
        bodies = [(p.url, p.text) for p in ctx.pages if p.text]
        # one benign probe: a very long, odd-looking path often triggers framework error pages
        r = ctx.client.get(f"{ctx.origin}/vulnscan-%25{secrets.token_hex(4)}%00", allow_redirects=False)
        if r is not None and r.text:
            bodies.append((f"{ctx.origin}/vulnscan-error-probe", r.text))
        for url, text in bodies:
            for label, rx in TRACE_SIGS:
                m = rx.search(text)
                if m and (label, urlsplit(url).path) not in seen:
                    seen.add((label, urlsplit(url).path))
                    out.append(self.finding(
                        f"{label} disclosed in response", "Medium", url,
                        f"Signature '{label}' matched: \"{m.group(0)[:80]}\"",
                        "Disable debug mode, return generic error pages and log details server-side only."))
        return out
