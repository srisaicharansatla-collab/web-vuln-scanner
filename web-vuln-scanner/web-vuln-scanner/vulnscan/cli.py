"""Command-line interface with the mandatory consent gate."""
from __future__ import annotations

import argparse
import ipaddress
import socket
import sys
from urllib.parse import urlsplit

from . import __version__, USER_AGENT
from .checks import ALL_CHECKS, select_checks
from .core import HttpClient, SEVERITY_ORDER
from .engine import run_scan
from .report import print_console, write_json, write_html

BANNER = f"vulnscan {__version__} - lightweight, non-destructive web vulnerability scanner"


def build_parser():
    p = argparse.ArgumentParser(prog="scanner.py", description=BANNER,
                                epilog="Scan ONLY systems you own or have written permission to test "
                                       "(localhost, OWASP Juice Shop, DVWA, WebGoat, bWAPP).")
    p.add_argument("url", nargs="?", help="Target URL, e.g. http://localhost:3000")
    p.add_argument("--i-have-permission", action="store_true", dest="permission",
                   help="REQUIRED consent gate: confirms you are authorised to scan this target")
    p.add_argument("-o", "--output", default="report.json", help="JSON report path (default: report.json)")
    p.add_argument("--html", metavar="FILE", help="also write an HTML report (bonus)")
    p.add_argument("--delay", type=float, default=0.5, help="seconds between requests (default 0.5)")
    p.add_argument("--timeout", type=float, default=10, help="per-request timeout in seconds (default 10)")
    p.add_argument("--max-pages", type=int, default=30, help="crawl page limit (default 30)")
    p.add_argument("--max-depth", type=int, default=3, help="crawl depth limit (default 3)")
    p.add_argument("--max-requests", type=int, default=600, help="hard cap on total requests (default 600)")
    p.add_argument("--checks", help="comma-separated check IDs to run (default: all)")
    p.add_argument("--skip", help="comma-separated check IDs to skip")
    p.add_argument("--list-checks", action="store_true", help="list available checks and exit")
    p.add_argument("--insecure", action="store_true", help="do not verify TLS certificates (self-signed labs)")
    p.add_argument("--allow-post", action="store_true",
                   help="also send harmless marker values to POST forms (off by default: read-only mode)")
    p.add_argument("--allow-remote", action="store_true",
                   help="permit non-local targets (extra confirmation; you need WRITTEN permission)")
    p.add_argument("--fail-on", choices=["low", "medium", "high", "critical"],
                   help="exit with code 3 if a finding of at least this severity exists (CI use)")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--version", action="version", version=BANNER)
    return p


def is_local_target(host: str) -> bool:
    if not host:
        return False
    if host.lower() in ("localhost", "host.docker.internal"):
        return True
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not (ip.is_loopback or ip.is_private):
            return False
    return True


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_checks:
        print(f"{'ID':<20}{'OWASP':<7}{'TYPE':<9}DESCRIPTION")
        for c in ALL_CHECKS:
            print(f"{c.id:<20}{c.owasp:<7}{c.kind:<9}{c.description}")
        return 0

    print(BANNER)
    if not args.url:
        print("error: a target URL is required (see --help)", file=sys.stderr)
        return 2

    # ---- consent gate -------------------------------------------------------
    if not args.permission:
        print("\n[!] REFUSING TO RUN: pass --i-have-permission to confirm you own this target or have written\n"
              "    authorisation to test it. Scanning other systems is illegal.", file=sys.stderr)
        return 1

    parts = urlsplit(args.url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        print("error: URL must start with http:// or https://", file=sys.stderr)
        return 2
    if not is_local_target(parts.hostname) and not args.allow_remote:
        print(f"\n[!] REFUSING TO RUN: '{parts.hostname}' is not a local/private address.\n"
              "    This tool is for localhost and intentionally vulnerable labs. If you hold WRITTEN permission,\n"
              "    add --allow-remote.", file=sys.stderr)
        return 1
    if args.delay < 0 or args.max_pages < 1:
        print("error: --delay must be >= 0 and --max-pages >= 1", file=sys.stderr)
        return 2

    try:
        checks = select_checks(args.checks.split(",") if args.checks else None,
                               args.skip.split(",") if args.skip else None)
    except Exception as exc:  # pragma: no cover
        print(f"error selecting checks: {exc}", file=sys.stderr)
        return 2
    if not checks:
        print("error: no checks selected (see --list-checks)", file=sys.stderr)
        return 2

    print(f"[*] User-Agent: {USER_AGENT}\n[*] Delay: {args.delay}s | timeout: {args.timeout}s | "
          f"page limit: {args.max_pages} | request cap: {args.max_requests} | mode: "
          f"{'GET+POST(marker)' if args.allow_post else 'read-only (GET)'}")
    client = HttpClient(delay=args.delay, timeout=args.timeout, max_requests=args.max_requests,
                        verify=not args.insecure)
    try:
        result = run_scan(args.url, client, checks, args.max_pages, args.max_depth, args.allow_post, args.verbose)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user", file=sys.stderr)
        return 130

    print_console(result)
    write_json(result, args.output)
    print(f"[*] JSON report written to {args.output}")
    if args.html:
        write_html(result, args.html)
        print(f"[*] HTML report written to {args.html}")

    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on.capitalize()]
        if any(SEVERITY_ORDER[f["severity"]] >= threshold for f in result["findings"]):
            print(f"[!] Findings at or above '{args.fail_on}' present -> exit code 3")
            return 3
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
