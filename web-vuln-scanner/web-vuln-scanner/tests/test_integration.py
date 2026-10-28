"""Integration tests: real HTTP against the bundled local labs, plus CLI behaviour."""
import json
import os
import sys
import threading

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from labs import vulnerable_lab, hardened_lab      # noqa: E402
from vulnscan.cli import main                      # noqa: E402
from vulnscan.core import HttpClient               # noqa: E402
from vulnscan.engine import run_scan               # noqa: E402


def _serve(module):
    srv = module.make_server(0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


@pytest.fixture(scope="module")
def vuln_url():
    srv, url = _serve(vulnerable_lab)
    yield url
    srv.shutdown()


@pytest.fixture(scope="module")
def hard_url():
    srv, url = _serve(hardened_lab)
    yield url
    srv.shutdown()


def scan(url):
    return run_scan(url, HttpClient(delay=0, timeout=5), log=lambda m: None)


def test_vulnerable_lab_all_planted_issues_found(vuln_url):
    res = scan(vuln_url)
    found = {f["check_id"] for f in res["findings"]}
    expected = {"A01-CSRF", "A01-REDIR", "A01-CORS", "A01-TRAV", "A02-HTTP", "A02-COOKIE-SECURE", "A03-SQLI",
                "A03-XSS", "A05-HEADERS", "A05-FILES", "A05-DIRLIST", "A05-TRACE", "A06-VERSION",
                "A07-COOKIE-FLAGS", "A07-LOGIN-HTTP", "A08-SRI"}
    assert expected <= found
    assert res["check_errors"] == []
    owasp = {f["owasp"][:3] for f in res["findings"]}
    assert len(owasp) >= 6                                  # assignment: >= 6 OWASP categories
    assert len(res["stats"]["checks_run"]) >= 10            # assignment: >= 10 checks


def test_hardened_lab_catch_all_200_causes_no_false_positives(hard_url):
    res = scan(hard_url)
    assert {f["check_id"] for f in res["findings"]} <= {"A02-HTTP", "A01-CORS", "A05-HEADERS"}
    assert not [f for f in res["findings"] if f["severity"] in ("High", "Critical")]


def test_no_duplicate_findings_in_report(vuln_url):
    res = scan(vuln_url)
    keys = [(f["check_id"], f["title"], f["url"].split("?")[0], f["parameter"]) for f in res["findings"]]
    assert len(keys) == len(set(keys))


def test_scanner_survives_dead_target():
    res = run_scan("http://127.0.0.1:9", HttpClient(delay=0, timeout=1), log=lambda m: None)
    assert res["stats"]["pages_crawled"] == 0 and res["stats"]["request_errors"] > 0
    assert res["check_errors"] == []


def test_request_budget_is_enforced(vuln_url):
    client = HttpClient(delay=0, max_requests=10)
    run_scan(vuln_url, client, log=lambda m: None)
    assert client.request_count <= 10


def test_every_finding_has_required_fields(vuln_url):
    for f in scan(vuln_url)["findings"]:
        for k in ("check_id", "title", "severity", "owasp", "url", "evidence", "recommendation"):
            assert f[k]


# ----------------------------------------------------------------------- CLI
def test_cli_refuses_without_permission_flag(vuln_url, capsys, tmp_path):
    out = tmp_path / "r.json"
    assert main([vuln_url, "-o", str(out)]) == 1
    assert not out.exists()
    assert "--i-have-permission" in capsys.readouterr().err


def test_cli_refuses_remote_target_without_allow_remote(capsys, tmp_path):
    assert main(["http://8.8.8.8/", "--i-have-permission", "-o", str(tmp_path / "r.json")]) == 1
    assert "not a local" in capsys.readouterr().err


def test_cli_writes_json_and_html_and_fail_on(vuln_url, tmp_path):
    j, h = tmp_path / "r.json", tmp_path / "r.html"
    code = main([vuln_url, "--i-have-permission", "--delay", "0", "-o", str(j), "--html", str(h), "--fail-on", "high"])
    assert code == 3
    data = json.loads(j.read_text())
    assert data["summary"]["total"] == len(data["findings"]) > 10
    assert "<html" in h.read_text() and "not_tested" in data


def test_cli_checks_selection_and_list(vuln_url, tmp_path, capsys):
    j = tmp_path / "r.json"
    assert main([vuln_url, "--i-have-permission", "--delay", "0", "--checks", "A03-SQLI,A03-XSS", "-o", str(j)]) == 0
    assert {f["check_id"] for f in json.loads(j.read_text())["findings"]} == {"A03-SQLI", "A03-XSS"}
    assert main(["--list-checks"]) == 0
    assert "A05-FILES" in capsys.readouterr().out


def test_cli_rejects_bad_url(capsys):
    assert main(["ftp://localhost/", "--i-have-permission"]) == 2
