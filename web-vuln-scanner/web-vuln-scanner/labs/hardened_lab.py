#!/usr/bin/env python3
"""HardenedLab - a mostly well-configured app used to measure FALSE POSITIVES.

Like many single-page apps (and OWASP Juice Shop) it answers HTTP 200 + the same HTML shell
for *every unknown path*, which is exactly the situation that fools naive "status == 200" scanners.

    python labs/hardened_lab.py --port 8082
"""
import argparse
import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

SECURE_HEADERS = [
    ("Content-Security-Policy", "default-src 'self'; script-src 'self' https://cdn.example.com; frame-ancestors 'none'"),
    ("X-Frame-Options", "DENY"),
    ("X-Content-Type-Options", "nosniff"),
    # Referrer-Policy intentionally missing  (1 real, minor weakness)
]

SHELL = """<!doctype html><html><head><title>HardenedLab</title>
<script src="https://cdn.example.com/lib.js" integrity="sha384-FAKEHASHFORTESTING" crossorigin="anonymous"></script></head><body>
<h1>Hardened shop</h1>
<a href="/search?q=test">Search</a> <a href="/product?id=1">Product</a> <a href="/view?file=readme">View</a>
<a href="/redirect?next=/home">Home</a> <a href="/api/public">Public API</a>
<form action="/contact" method="post"><input type="hidden" name="csrf_token" value="a1b2c3d4"><input name="message"><input type="submit"></form>
</body></html>"""

ALLOWED_FILES = {"readme", "terms", "privacy"}


class Handler(BaseHTTPRequestHandler):
    def version_string(self):
        return "webserver"

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None, security=True):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        if security:
            for k, v in SECURE_HEADERS:
                self.send_header(k, v)
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self._send(200, "<html><body>Received</body></html>")

    def do_GET(self):
        sp = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(sp.query, keep_blank_values=True).items()}
        p = sp.path
        if p == "/":
            self._send(200, SHELL, extra=[("Set-Cookie", "sid=xyz789; Path=/; Secure; HttpOnly; SameSite=Strict")])
        elif p == "/search":                                       # output properly encoded
            self._send(200, f"<html><body><p>Results for: {html.escape(q.get('q', ''))}</p></body></html>")
        elif p == "/product":                                      # strict input validation
            pid = q.get("id", "")
            if pid.isdigit():
                self._send(200, f"<html><body>Product {pid}</body></html>")
            else:
                self._send(400, "<html><body>Bad request</body></html>")
        elif p == "/view":                                         # allow-list
            f = q.get("file", "")
            self._send(200 if f in ALLOWED_FILES else 404, f"<html><body>{html.escape(f) if f in ALLOWED_FILES else 'Not found'}</body></html>")
        elif p == "/redirect":                                     # relative targets only
            t = q.get("next", "/")
            self._send(302, "", extra=[("Location", t if t.startswith("/") and not t.startswith("//") else "/")])
        elif p == "/api/public":                                   # public data, wildcard CORS (accepted risk)
            self._send(200, json.dumps({"public": True}), "application/json", extra=[("Access-Control-Allow-Origin", "*")])
        else:                                                      # SPA catch-all: 200 + shell for ANY path
            self._send(200, SHELL)


def make_server(port=8082, host="127.0.0.1"):
    return ThreadingHTTPServer((host, port), Handler)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8082)
    a = ap.parse_args()
    print(f"HardenedLab on http://127.0.0.1:{a.port}  - Ctrl+C to stop")
    make_server(a.port).serve_forever()
