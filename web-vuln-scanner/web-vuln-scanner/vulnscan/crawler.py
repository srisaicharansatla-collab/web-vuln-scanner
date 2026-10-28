"""Same-site breadth-first crawler collecting links, forms and URL parameters."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urljoin, urldefrag, urlsplit, parse_qsl

from bs4 import BeautifulSoup

STATIC_EXT = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp", ".css", ".js", ".map",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp3", ".mp4", ".avi", ".mov", ".webm",
    ".pdf", ".zip", ".gz", ".tar", ".rar", ".7z", ".exe", ".dmg", ".iso", ".doc", ".docx",
    ".xls", ".xlsx", ".ppt", ".pptx",
)


@dataclass
class Form:
    page_url: str
    action: str
    method: str
    inputs: List[Dict[str, str]] = field(default_factory=list)

    @property
    def has_password(self) -> bool:
        return any(i["type"] == "password" for i in self.inputs)


@dataclass
class Page:
    url: str
    status: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    text: str = ""
    set_cookies: List[str] = field(default_factory=list)
    links: List[str] = field(default_factory=list)
    forms: List[Form] = field(default_factory=list)
    params: Dict[str, str] = field(default_factory=dict)
    soup: Optional[BeautifulSoup] = field(default=None, repr=False)
    request_url: Optional[str] = None   # URL originally requested (differs from url after a redirect)

    @property
    def content_type(self) -> str:
        for k, v in self.headers.items():
            if k.lower() == "content-type":
                return v.lower()
        return ""

    def header(self, name: str) -> Optional[str]:
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return None

    @property
    def is_html(self) -> bool:
        return "html" in self.content_type or (not self.content_type and "<html" in self.text[:500].lower())

    @classmethod
    def from_html(cls, url, html, headers=None, status=200, set_cookies=None):
        """Build a Page from raw HTML (used by the crawler and by unit tests)."""
        headers = {"Content-Type": "text/html; charset=utf-8", **(headers or {})}
        pg = cls(url=url, status=status, headers=headers, text=html, set_cookies=list(set_cookies or []),
                 params=dict(parse_qsl(urlsplit(url).query, keep_blank_values=True)))
        pg.soup = BeautifulSoup(html, "html.parser")
        pg.links, pg.forms = extract_links_and_forms(pg.soup, url)
        return pg


def extract_links_and_forms(soup, base_url):
    links, forms = [], []
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href.lower().startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
            continue
        links.append(urldefrag(urljoin(base_url, href))[0])
    for f in soup.find_all("form"):
        action = urljoin(base_url, f.get("action") or base_url)
        method = (f.get("method") or "GET").upper()
        inputs = []
        for tag in f.find_all(["input", "textarea", "select"]):
            name = tag.get("name")
            if not name:
                continue
            if tag.name == "input":
                typ, val = (tag.get("type") or "text").lower(), tag.get("value", "")
            elif tag.name == "textarea":
                typ, val = "textarea", tag.text or ""
            else:
                opt = tag.find("option")
                typ, val = "select", (opt.get("value", opt.text) if opt else "")
            inputs.append({"name": name, "type": typ, "value": val})
        forms.append(Form(page_url=base_url, action=urldefrag(action)[0], method=method, inputs=inputs))
    return links, forms


def same_origin(url: str, base: str) -> bool:
    return urlsplit(url).netloc.lower() == urlsplit(base).netloc.lower()


class Crawler:
    """BFS crawler. Stays on the start host, GET only, bounded by pages/depth."""

    def __init__(self, client, max_pages: int = 30, max_depth: int = 3, log=lambda m: None):
        self.client = client
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.log = log

    @staticmethod
    def _param_signature(url: str):
        sp = urlsplit(url)
        return (sp.netloc, sp.path, tuple(sorted(k for k, _ in parse_qsl(sp.query, keep_blank_values=True))))

    def crawl(self, start_url: str) -> List[Page]:
        pages: List[Page] = []
        queue = deque([(start_url, 0)])
        seen_urls, seen_sigs = {start_url}, {self._param_signature(start_url)}
        while queue and len(pages) < self.max_pages:
            url, depth = queue.popleft()
            resp = self.client.get(url)
            if resp is None:
                continue
            final_url = resp.url or url
            if not same_origin(final_url, start_url):  # redirected off-site: don't analyse
                self.log(f"skip off-site redirect {final_url}")
                continue
            headers = dict(resp.headers)
            cookies = []
            try:
                cookies = list(resp.raw.headers.getlist("Set-Cookie"))
            except Exception:
                if "Set-Cookie" in resp.headers:
                    cookies = [resp.headers["Set-Cookie"]]
            ctype = resp.headers.get("Content-Type", "").lower()
            text = resp.text if ("html" in ctype or "json" in ctype or "text" in ctype or "xml" in ctype or not ctype) else ""
            if "html" in ctype or (not ctype and "<html" in text[:500].lower()):
                page = Page.from_html(final_url, text, headers=headers, status=resp.status_code, set_cookies=cookies)
            else:
                page = Page(url=final_url, status=resp.status_code, headers=headers, text=text, set_cookies=cookies,
                            params=dict(parse_qsl(urlsplit(final_url).query, keep_blank_values=True)))
            page.request_url = url
            if url != final_url:  # keep the parameters of the requested URL (e.g. /redirect?next=...)
                page.params = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))
            pages.append(page)
            self.log(f"crawled [{resp.status_code}] {final_url}")
            if depth >= self.max_depth:
                continue
            candidates = list(page.links) + [f.action for f in page.forms if f.method == "GET"]
            for link in candidates:
                if not same_origin(link, start_url) or urlsplit(link).path.lower().endswith(STATIC_EXT):
                    continue
                if urlsplit(link).scheme not in ("http", "https"):
                    continue
                sig = self._param_signature(link)
                if link in seen_urls or sig in seen_sigs:
                    continue
                seen_urls.add(link)
                seen_sigs.add(sig)
                queue.append((link, depth + 1))
        return pages
