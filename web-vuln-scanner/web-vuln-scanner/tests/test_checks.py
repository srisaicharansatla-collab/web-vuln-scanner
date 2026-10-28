"""Unit tests - each check is exercised with fabricated pages / a fake HTTP client (no network)."""
import os
import sys

import pytest
from requests.structures import CaseInsensitiveDict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vulnscan.core import ScanContext, Finding                      # noqa: E402
from vulnscan.crawler import Page                                   # noqa: E402
from vulnscan.engine import deduplicate                             # noqa: E402
from vulnscan.checks.transport import (HttpInsteadOfHttps, MissingHsts, MixedContent, CookieSecureFlag,  # noqa: E402
                                       CookieAuthFlags, LoginFormOverHttp, parse_cookie)
from vulnscan.checks.headers import SecurityHeaders, VersionDisclosure, MissingSri, parse_version  # noqa: E402
from vulnscan.checks.exposure import SensitiveFiles, DirectoryListing, StackTraceDisclosure, is_dir_listing  # noqa: E402
from vulnscan.checks.access import MissingCsrfToken, OpenRedirect, CorsMisconfiguration, PathTraversalIndicator  # noqa: E402
from vulnscan.checks.injection import SqlInjectionError, ReflectedXss, sql_error_signature  # noqa: E402


class FakeResp:
    def __init__(self, text="", status=200, headers=None, url="http://t.test/"):
        self.text = text
        self.content = text.encode()
        self.status_code = status
        self.headers = CaseInsensitiveDict(headers or {"Content-Type": "text/html"})
        self.url = url


class FakeClient:
    """handler(url, params, headers) -> FakeResp | None"""
    def __init__(self, handler=lambda u, p, h: FakeResp("", 404)):
        self.handler = handler
        self.request_count = 0
        self.errors = []

    def get(self, url, params=None, headers=None, allow_redirects=True):
        self.request_count += 1
        return self.handler(url, params or {}, headers or {})

    post = None


def ctx_for(pages, base="http://t.test/", handler=None):
    return ScanContext(base_url=base, client=FakeClient(handler) if handler else FakeClient(), pages=pages)


def page(html="<html></html>", url="http://t.test/", **kw):
    return Page.from_html(url, html, **kw)


def ids(findings):
    return [f.check_id for f in findings]


# ------------------------------------------------------------------ passive checks
def test_http_instead_of_https_flags_http_only():
    assert ids(HttpInsteadOfHttps().run(ctx_for([], "http://t.test/"))) == ["A02-HTTP"]
    assert HttpInsteadOfHttps().run(ctx_for([], "https://t.test/")) == []


def test_hsts_missing_present_and_weak():
    url = "https://t.test/"
    assert ids(MissingHsts().run(ctx_for([page(url=url)], url))) == ["A02-HSTS"]
    good = page(url=url, headers={"Strict-Transport-Security": "max-age=31536000; includeSubDomains"})
    assert MissingHsts().run(ctx_for([good], url)) == []
    weak = page(url=url, headers={"Strict-Transport-Security": "max-age=60"})
    assert MissingHsts().run(ctx_for([weak], url))[0].severity == "Low"
    assert MissingHsts().run(ctx_for([page()], "http://t.test/")) == []   # not applicable on HTTP


def test_mixed_content_active_vs_passive():
    html = '<script src="http://cdn.x/a.js"></script><img src="http://cdn.x/i.png"><img src="https://ok/i.png">'
    f = MixedContent().run(ctx_for([page(html, "https://t.test/")], "https://t.test/"))
    assert sorted(x.severity for x in f) == ["Low", "Medium"]
    assert MixedContent().run(ctx_for([page(html, "http://t.test/")])) == []     # only on HTTPS pages


def test_cookie_flags_detected_and_clean_cookie_passes():
    bad = page(set_cookies=["PHPSESSID=abc; Path=/"])
    f1 = CookieSecureFlag().run(ctx_for([bad]))
    f2 = CookieAuthFlags().run(ctx_for([bad]))
    assert len(f1) == 1 and len(f2) == 2
    assert {x.title.split(" set without ")[1] for x in f2} == {"HttpOnly flag", "SameSite attribute"}
    good = page(set_cookies=["sid=1; Path=/; Secure; HttpOnly; SameSite=Strict"])
    assert CookieSecureFlag().run(ctx_for([good])) == [] and CookieAuthFlags().run(ctx_for([good])) == []


def test_parse_cookie():
    n, v, a = parse_cookie("a=b=c; Path=/; HttpOnly; SameSite=Lax")
    assert (n, v) == ("a", "b=c") and "httponly" in a and a["samesite"] == "Lax"


def test_login_form_over_http_only_when_password_field():
    html = '<form action="/l" method="post"><input name="u"><input type="password" name="p"></form>'
    assert ids(LoginFormOverHttp().run(ctx_for([page(html)]))) == ["A07-LOGIN-HTTP"]
    assert LoginFormOverHttp().run(ctx_for([page(html, "https://t.test/")])) == []
    assert LoginFormOverHttp().run(ctx_for([page('<form><input name="q"></form>')])) == []


def test_security_headers_missing_and_complete():
    f = SecurityHeaders().run(ctx_for([page()]))
    titles = " | ".join(x.title for x in f)
    assert "Content-Security-Policy" in titles and "Clickjacking" in titles and "nosniff" in titles and "Referrer" in titles
    full = page(headers={"Content-Security-Policy": "default-src 'self'", "X-Frame-Options": "DENY",
                         "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"})
    assert SecurityHeaders().run(ctx_for([full])) == []
    # frame-ancestors in CSP is an acceptable substitute for X-Frame-Options
    csp = page(headers={"Content-Security-Policy": "frame-ancestors 'none'", "X-Content-Type-Options": "nosniff",
                        "Referrer-Policy": "no-referrer"})
    assert SecurityHeaders().run(ctx_for([csp])) == []


def test_version_disclosure_and_cve_hint():
    f = VersionDisclosure().run(ctx_for([page(headers={"Server": "Apache/2.4.49 (Unix)", "X-Powered-By": "Express"})]))
    assert len(f) == 1 and "CVE-2021-41773" in f[0].evidence and f[0].severity == "Medium"
    assert VersionDisclosure().run(ctx_for([page(headers={"Server": "nginx"})])) == []   # no version -> no finding
    assert parse_version("PHP/7.4.3") == (7, 4, 3) and parse_version("nginx") is None


def test_sri_only_for_third_party_without_integrity():
    html = ('<script src="https://cdn.x/a.js"></script>'
            '<script src="https://cdn.x/b.js" integrity="sha384-abc" crossorigin="anonymous"></script>'
            '<script src="/local.js"></script><script src="//cdn.y/c.js"></script>'
            '<link rel="stylesheet" href="https://cdn.x/s.css">')
    f = MissingSri().run(ctx_for([page(html)]))
    assert {x.parameter for x in f} == {"https://cdn.x/a.js", "https://cdn.x/s.css", "http://cdn.y/c.js"}


def test_csrf_token_detection():
    bad = '<form method="post" action="/a"><input name="x"></form>'
    good = '<form method="post" action="/b"><input type="hidden" name="csrf_token" value="1"><input name="x"></form>'
    get_form = '<form method="get" action="/c"><input name="q"></form>'
    f = MissingCsrfToken().run(ctx_for([page(bad + good + get_form)]))
    assert len(f) == 1 and f[0].url.endswith("/a")


# ------------------------------------------------------------------ probing checks (fake client)
def test_sensitive_files_requires_signature_and_ignores_soft_404():
    def handler(url, params, headers):
        if url.endswith("/.git/HEAD"):
            return FakeResp("ref: refs/heads/main\n", headers={"Content-Type": "text/plain"})
        if url.endswith("/.env"):                   # looks like 200 but is an HTML SPA shell -> must be ignored
            return FakeResp("<html>app</html>")
        if url.endswith("/phpinfo.php"):            # 200 but wrong content -> ignored
            return FakeResp("<html>Welcome</html>")
        return FakeResp("<html>app</html>")         # catch-all 200 for everything else
    f = SensitiveFiles().run(ctx_for([], handler=handler))
    assert [x.url.rsplit("/", 1)[-1] for x in f] == ["HEAD"]


def test_sensitive_files_soft404_hash_blocks_matching_body():
    body = "ref: refs/heads/main"                    # same body for every path -> identical to soft-404 -> skip
    f = SensitiveFiles().run(ctx_for([], handler=lambda u, p, h: FakeResp(body, headers={"Content-Type": "text/plain"})))
    assert f == []


def test_env_file_redacts_values():
    def handler(url, params, headers):
        if url.endswith("/.env"):
            return FakeResp("DB_PASSWORD=hunter2\nAPP_KEY=abc\n", headers={"Content-Type": "text/plain"})
        return FakeResp("nope", 404)
    f = SensitiveFiles().run(ctx_for([], handler=handler))
    assert len(f) == 1 and f[0].severity == "Critical" and "hunter2" not in f[0].evidence


def test_directory_listing_signature():
    listing = "<html><title>Index of /uploads</title><h1>Index of /uploads</h1><a href=\"../\">Parent Directory</a></html>"
    assert is_dir_listing(listing)
    assert not is_dir_listing("<html><title>Index of products</title></html>")

    def handler(url, params, headers):
        return FakeResp(listing) if url.endswith("/uploads/") else FakeResp("<html>nothing</html>", 404)
    f = DirectoryListing().run(ctx_for([], handler=handler))
    assert len(f) == 1 and f[0].url.endswith("/uploads/")


def test_stack_trace_signatures():
    tb = page("<pre>Traceback (most recent call last):\n  File \"a.py\", line 1\nKeyError</pre>", "http://t.test/err")
    f = StackTraceDisclosure().run(ctx_for([tb], handler=lambda u, p, h: FakeResp("ok", 404)))
    assert ids(f) == ["A05-TRACE"] and "Python" in f[0].title
    assert StackTraceDisclosure().run(ctx_for([page("<p>hello</p>")], handler=lambda u, p, h: FakeResp("ok"))) == []


def test_open_redirect_detects_only_external_location():
    html = '<a href="/go?next=/home">x</a><a href="/safe?next=/home">y</a>'

    def handler(url, params, headers):
        if url.endswith("/go"):
            return FakeResp("", 302, {"Location": params["next"]})
        if url.endswith("/safe"):
            return FakeResp("", 302, {"Location": "/"})
        return FakeResp("", 404)
    pages = [page(html), page("", "http://t.test/go?next=/home"), page("", "http://t.test/safe?next=/home")]
    f = OpenRedirect().run(ctx_for(pages, handler=handler))
    assert len(f) == 1 and f[0].parameter == "next" and f[0].url.endswith("/go")


def test_cors_reflection_wildcard_and_safe():
    def mk(acao, creds=None):
        def h(url, params, headers):
            hd = {"Content-Type": "application/json"}
            if acao == "reflect":
                hd["Access-Control-Allow-Origin"] = headers.get("Origin", "")
            elif acao:
                hd["Access-Control-Allow-Origin"] = acao
            if creds:
                hd["Access-Control-Allow-Credentials"] = "true"
            return FakeResp("{}", headers=hd)
        return h
    f = CorsMisconfiguration().run(ctx_for([], handler=mk("reflect", True)))
    assert f[0].severity == "High"
    assert CorsMisconfiguration().run(ctx_for([], handler=mk("reflect")))[0].severity == "Medium"
    assert CorsMisconfiguration().run(ctx_for([], handler=mk("*")))[0].severity == "Low"
    assert CorsMisconfiguration().run(ctx_for([], handler=mk("https://good.example"))) == []
    assert CorsMisconfiguration().run(ctx_for([], handler=mk(None))) == []


def test_path_traversal_needs_signature_not_just_200():
    pg = page("", "http://t.test/view?file=a.txt")

    def vuln(url, params, headers):
        f = params.get("file", "")
        return FakeResp("root:x:0:0:root:/root:/bin/bash\n" if "etc/passwd" in f else "File")

    def always_200(url, params, headers):
        return FakeResp("<html>some page</html>")
    assert ids(PathTraversalIndicator().run(ctx_for([pg], handler=vuln))) == ["A01-TRAV"]
    assert PathTraversalIndicator().run(ctx_for([pg], handler=always_200)) == []


def test_sqli_error_based_baseline_comparison():
    pg = page("", "http://t.test/p?id=1")

    def vuln(url, params, headers):
        if "'" in params.get("id", ""):
            return FakeResp("You have an error in your SQL syntax near ''' at line 1", 500)
        return FakeResp("Product 1")

    def page_that_always_shows_error(url, params, headers):   # error text also in baseline -> not attributable
        return FakeResp("Docs: You have an error in your SQL syntax is a common message")
    f = SqlInjectionError().run(ctx_for([pg], handler=vuln))
    assert ids(f) == ["A03-SQLI"] and f[0].parameter == "id"
    assert SqlInjectionError().run(ctx_for([pg], handler=page_that_always_shows_error)) == []
    assert SqlInjectionError().run(ctx_for([pg], handler=lambda u, p, h: FakeResp("Product 1"))) == []
    assert sql_error_signature("ORA-00933: SQL command not properly ended")[0] == "Oracle"


def test_reflected_xss_requires_unescaped_reflection():
    pg = page("", "http://t.test/s?q=a")
    raw = lambda u, p, h: FakeResp(f"<p>{p['q']}</p>")
    import html as _h
    esc = lambda u, p, h: FakeResp(f"<p>{_h.escape(p['q'])}</p>")
    json_ct = lambda u, p, h: FakeResp(p["q"], headers={"Content-Type": "application/json"})
    assert ids(ReflectedXss().run(ctx_for([pg], handler=raw))) == ["A03-XSS"]
    assert ReflectedXss().run(ctx_for([pg], handler=esc)) == []
    assert ReflectedXss().run(ctx_for([pg], handler=json_ct)) == []        # not HTML -> not exploitable XSS


# ------------------------------------------------------------------ engine quality
def test_deduplicate_removes_identical_findings_but_keeps_distinct_params():
    mk = lambda param, q="": Finding("X", "t", "Low", "A01", f"http://a/x{q}", "e", "r", param)
    out = deduplicate([mk("a"), mk("a", "?v=2"), mk("b")])      # same path/param with different query -> duplicate
    assert [f.parameter for f in out] == ["a", "b"]
