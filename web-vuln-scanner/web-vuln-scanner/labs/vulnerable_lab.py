#!/usr/bin/env python3
"""VulnLab - a tiny, DELIBERATELY VULNERABLE web app for testing the scanner offline.

Binds to 127.0.0.1 only. Everything is simulated (fake DB errors, fake passwd/.env content);
nothing here touches the real filesystem or a real database.

    python labs/vulnerable_lab.py --port 8081
"""
import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

HOME = """<!doctype html><html><head><title>VulnLab</title>
<script src="https://cdn.example.com/lib.js"></script></head><body>
<h1>VulnLab shop</h1>
<ul>
 <li><a href="/search?q=test">Search</a></li>
 <li><a href="/product?id=1">Product 1</a></li>
 <li><a href="/view?file=readme.txt">View file</a></li>
 <li><a href="/redirect?next=/home">Go home</a></li>
 <li><a href="/login">Login</a></li>
 <li><a href="/error">Error page</a></li>
 <li><a href="/api/data">API</a></li>
 <li><a href="/uploads/">Uploads</a></li>
 <li><a href="/order?id=1001">My order (IDOR)</a></li>
 <li><a href="/blind?id=1">Blind item</a></li>
 <li><a href="/dom">DOM page</a></li>
</ul>
<form action="/comment" method="post"><input name="author"><textarea name="text"></textarea><input type="submit"></form>
</body></html>"""

LISTING = """<html><head><title>Index of /uploads</title></head><body><h1>Index of /uploads</h1>
<a href="../">Parent Directory</a><br><a href="invoice.pdf">invoice.pdf</a><br><a href="notes.txt">notes.txt</a></body></html>"""

TRACE = """<html><body><h1>Internal Server Error</h1><pre>Traceback (most recent call last):
  File "app.py", line 42, in handle_request
    price = items[user_id]
KeyError: 'user_id'</pre></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def version_string(self):
        return "Apache/2.4.49 (Unix)"          # deliberately outdated banner

    def log_message(self, *a):                  # keep the console quiet
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Powered-By", "PHP/5.6.40")
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(n)
        self._send(200, "<html><body>Thanks (nothing stored)</body></html>")

    def do_GET(self):
        sp = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(sp.query, keep_blank_values=True).items()}
        path = sp.path
        if path == "/":
            self._send(200, HOME, extra=[("Set-Cookie", "PHPSESSID=abc123; Path=/"), ("Set-Cookie", "theme=dark; Path=/")])
        elif path == "/search":                                     # reflected XSS
            self._send(200, f"<html><body><p>Results for: {q.get('q', '')}</p></body></html>")
        elif path == "/product":                                    # error-based SQLi (simulated)
            pid = q.get("id", "1")
            if "'" in pid or '"' in pid:
                self._send(500, "<html><body>You have an error in your SQL syntax; check the manual that corresponds to "
                                "your MySQL server version for the right syntax to use near ''' at line 1</body></html>")
            else:
                self._send(200, f"<html><body><h2>Product {pid[:20]}</h2></body></html>")
        elif path == "/view":                                       # path traversal (simulated)
            f = q.get("file", "")
            if ".." in f and "etc/passwd" in f.replace("\\", "/"):
                self._send(200, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n", "text/plain")
            else:
                self._send(200, "<html><body>File: " + f.replace("<", "&lt;") + "</body></html>")
        elif path == "/redirect":                                   # open redirect
            self._send(302, "", extra=[("Location", q.get("next", "/"))])
        elif path == "/login":
            self._send(200, '<html><body><form action="/login" method="post"><input name="user">'
                            '<input type="password" name="pass"><input type="submit"></form></body></html>')
        elif path == "/error":
            self._send(500, TRACE)
        elif path == "/api/data":                                   # CORS reflects Origin + credentials
            self._send(200, json.dumps({"items": [1, 2, 3]}), "application/json",
                       extra=[("Access-Control-Allow-Origin", self.headers.get("Origin", "*")),
                              ("Access-Control-Allow-Credentials", "true")])
        elif path == "/.git/HEAD":
            self._send(200, "ref: refs/heads/main\n", "text/plain")
        elif path == "/.env":
            self._send(200, "APP_ENV=production\nDB_PASSWORD=not-a-real-secret\nAPP_KEY=base64:FAKEFAKEFAKE\n", "text/plain")
        elif path == "/phpinfo.php":
            self._send(200, "<html><head><title>phpinfo()</title></head><body><h1>PHP Version 5.6.40</h1></body></html>")
        elif path == "/uploads/":
            self._send(200, LISTING)
        # ---- planted flaws a lightweight scanner is EXPECTED to miss (false negatives) ----
        elif path == "/order":                                      # IDOR: any id returns an order
            self._send(200, f"<html><body>Order {q.get('id', '')[:10]} belongs to another customer</body></html>")
        elif path == "/blind":                                      # blind boolean SQLi: no error text
            self._send(200, "<html><body>Item found</body></html>" if "'" not in q.get("id", "") else "<html><body>Item not found</body></html>")
        elif path == "/dom":                                        # DOM XSS: sink is in JS, nothing is reflected server-side
            self._send(200, "<html><body><div id=o></div><script>document.getElementById('o').innerHTML=location.hash.slice(1)</script></body></html>")
        else:
            self._send(404, "<html><body>Not Found</body></html>")


def make_server(port=8081, host="127.0.0.1"):
    return ThreadingHTTPServer((host, port), Handler)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8081)
    a = ap.parse_args()
    print(f"VulnLab (deliberately vulnerable) on http://127.0.0.1:{a.port}  - Ctrl+C to stop")
    make_server(a.port).serve_forever()
