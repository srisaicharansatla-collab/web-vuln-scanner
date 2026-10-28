"""Core data model: findings, HTTP client wrapper, scan context."""
from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional
from urllib.parse import urlsplit

import requests

from . import USER_AGENT

SEVERITY_ORDER = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}

OWASP_NAMES = {
    "A01": "A01:2021 Broken Access Control",
    "A02": "A02:2021 Cryptographic Failures",
    "A03": "A03:2021 Injection",
    "A04": "A04:2021 Insecure Design",
    "A05": "A05:2021 Security Misconfiguration",
    "A06": "A06:2021 Vulnerable and Outdated Components",
    "A07": "A07:2021 Identification and Authentication Failures",
    "A08": "A08:2021 Software and Data Integrity Failures",
    "A09": "A09:2021 Security Logging and Monitoring Failures",
    "A10": "A10:2021 Server-Side Request Forgery",
}

MAX_BODY_BYTES = 1_000_000  # never read more than ~1 MB of any response


@dataclass
class Finding:
    check_id: str
    title: str
    severity: str
    owasp: str
    url: str
    evidence: str
    recommendation: str
    parameter: Optional[str] = None

    def dedup_key(self):
        p = urlsplit(self.url)
        return (self.check_id, self.title, f"{p.scheme}://{p.netloc}{p.path}", self.parameter)

    def to_dict(self):
        return asdict(self)


class HttpClient:
    """requests.Session wrapper: delay, timeout, UA, body-size cap, request budget.

    Every network error is swallowed and recorded (returns None) so one flaky
    page can never crash a scan.
    """

    def __init__(self, delay: float = 0.5, timeout: float = 10.0, max_requests: int = 600,
                 verify: bool = True, user_agent: str = USER_AGENT):
        self.delay = delay
        self.timeout = timeout
        self.max_requests = max_requests
        self.request_count = 0
        self.errors: List[str] = []
        self._last = 0.0
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent, "Accept": "*/*"})
        self.session.verify = verify
        if not verify:
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except Exception:  # pragma: no cover
                pass

    def _throttle(self) -> bool:
        if self.request_count >= self.max_requests:
            return False
        wait = self.delay - (time.monotonic() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()
        self.request_count += 1
        return True

    def get(self, url, params=None, headers=None, allow_redirects=True):
        """Read-only GET. Returns a Response (body capped) or None on failure/budget exhausted."""
        if not self._throttle():
            return None
        try:
            r = self.session.get(url, params=params, headers=headers, timeout=self.timeout,
                                 allow_redirects=allow_redirects, stream=True)
            data = bytearray()
            for chunk in r.iter_content(65536):
                data.extend(chunk)
                if len(data) >= MAX_BODY_BYTES:
                    break
            r._content = bytes(data)
            r._content_consumed = True
            r.close()
            return r
        except requests.RequestException as exc:
            self.errors.append(f"{url}: {type(exc).__name__}: {exc}"[:300])
            return None

    def post(self, url, data=None):
        """Only used when --allow-post is given (harmless marker values only)."""
        if not self._throttle():
            return None
        try:
            return self.session.post(url, data=data, timeout=self.timeout, allow_redirects=False)
        except requests.RequestException as exc:
            self.errors.append(f"POST {url}: {type(exc).__name__}: {exc}"[:300])
            return None


@dataclass
class InjectionPoint:
    method: str          # "GET" (or "POST" with --allow-post)
    url: str             # URL without query string
    params: Dict[str, str]
    source: str          # "query" | "form"

    def signature(self):
        p = urlsplit(self.url)
        return (self.method, p.netloc, p.path, tuple(sorted(self.params)))


@dataclass
class ScanContext:
    base_url: str
    client: object
    pages: list = field(default_factory=list)
    allow_post: bool = False
    verbose: bool = False
    _baseline: dict = field(default_factory=dict)

    @property
    def parts(self):
        return urlsplit(self.base_url)

    @property
    def origin(self) -> str:
        return f"{self.parts.scheme}://{self.parts.netloc}"

    @property
    def is_https(self) -> bool:
        return self.parts.scheme == "https"

    def log(self, msg):
        if self.verbose:
            print(f"    [v] {msg}")

    def html_pages(self):
        return [p for p in self.pages if p.is_html and p.status and p.status < 400]

    def forms(self):
        return [f for p in self.pages for f in p.forms]

    def injection_points(self, limit: int = 40) -> List[InjectionPoint]:
        """Unique (method, path, param-names) points taken from crawled URLs and forms."""
        seen, points = set(), []

        def add(pt):
            if pt.params and pt.signature() not in seen and len(points) < limit:
                seen.add(pt.signature())
                points.append(pt)

        for pg in self.pages:
            if pg.params:
                sp = urlsplit(pg.request_url or pg.url)
                add(InjectionPoint("GET", f"{sp.scheme}://{sp.netloc}{sp.path}", dict(pg.params), "query"))
            for f in pg.forms:
                if f.method == "POST" and not self.allow_post:
                    continue
                params = {}
                for i in f.inputs:
                    if i["type"] in ("submit", "button", "image", "reset", "file"):
                        continue
                    params[i["name"]] = i["value"] or ("test" if i["type"] != "hidden" else "")
                sp = urlsplit(f.action)
                add(InjectionPoint(f.method, f"{sp.scheme}://{sp.netloc}{sp.path}", params, "form"))
        return points

    def send(self, point: InjectionPoint, name: str, value: str):
        """Send the point with one parameter replaced by `value`."""
        params = dict(point.params)
        params[name] = value
        if point.method == "GET":
            return self.client.get(point.url, params=params)
        return self.client.post(point.url, data=params)

    def baseline(self, point: InjectionPoint):
        key = point.signature()
        if key not in self._baseline:
            if point.method == "GET":
                self._baseline[key] = self.client.get(point.url, params=point.params)
            else:
                self._baseline[key] = self.client.post(point.url, data=point.params)
        return self._baseline[key]
