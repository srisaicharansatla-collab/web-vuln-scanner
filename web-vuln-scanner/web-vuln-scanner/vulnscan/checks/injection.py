"""A03 Injection: error-based SQLi and reflected XSS (benign probes only).

SQLi: a single quote / double quote is sent; a finding needs a *database error
signature* that is NOT present in the baseline response.
XSS : a unique random marker followed by '<b>' is sent; a finding needs the
marker AND the raw, un-encoded '<b>' to be reflected in an HTML response.
Nothing is ever exfiltrated or modified.
"""
from __future__ import annotations

import re
import secrets

from .base import Check

SQL_ERRORS = [
    ("MySQL", re.compile(r"You have an error in your SQL syntax|check the manual that corresponds to your (MySQL|MariaDB)|mysqli?_(fetch|query|num_rows)|MySQLSyntaxErrorException", re.I)),
    ("PostgreSQL", re.compile(r"unterminated quoted string at or near|PG::SyntaxError|pg_query\(\)|org\.postgresql\.util\.PSQLException", re.I)),
    ("SQLite", re.compile(r"SQLITE_ERROR|sqlite3\.OperationalError|SQLite3::SQLException|unrecognized token: \"'", re.I)),
    ("Oracle", re.compile(r"ORA-\d{5}", re.I)),
    ("MSSQL", re.compile(r"Unclosed quotation mark after the character string|Microsoft OLE DB Provider for SQL Server|\[SQL Server\]|System\.Data\.SqlClient\.SqlException", re.I)),
    ("Generic", re.compile(r"SQLSTATE\[\w+\]|quoted string not properly terminated|SQL syntax.*error", re.I)),
]


def sql_error_signature(text: str):
    for db, rx in SQL_ERRORS:
        m = rx.search(text or "")
        if m:
            return db, m.group(0)
    return None


class SqlInjectionError(Check):
    id = "A03-SQLI"
    name = "Error-based SQL injection"
    owasp = "A03"
    kind = "probe"
    description = "Injects ' and \" into every GET parameter and matches DB error signatures absent from the baseline."

    PAYLOADS = ["'", '"']

    def run(self, ctx):
        out = []
        for pt in ctx.injection_points():
            base = ctx.baseline(pt)
            base_text = base.text if base is not None else ""
            for name in pt.params:
                for payload in self.PAYLOADS:
                    r = ctx.send(pt, name, (pt.params.get(name) or "1") + payload)
                    if r is None:
                        continue
                    sig = sql_error_signature(r.text)
                    if sig and not sql_error_signature(base_text):
                        out.append(self.finding(
                            f"Possible SQL injection ({sig[0]} error message)", "High", pt.url,
                            f"Appending {payload!r} to '{name}' produced a database error: \"{sig[1][:90]}\" "
                            f"(HTTP {r.status_code}); the baseline response had no such error.",
                            "Use parameterised queries / prepared statements, validate input types, and show generic "
                            "error pages.", parameter=name))
                        break
        return out


class ReflectedXss(Check):
    id = "A03-XSS"
    name = "Reflected XSS (marker reflection)"
    owasp = "A03"
    kind = "probe"
    description = "Sends a unique harmless marker plus <b> and checks it is reflected without HTML encoding."

    def run(self, ctx):
        out = []
        for pt in ctx.injection_points():
            for name in pt.params:
                marker = "vsx" + secrets.token_hex(4)
                payload = f'{marker}<b>"\''
                r = ctx.send(pt, name, payload)
                if r is None or "html" not in r.headers.get("Content-Type", "").lower():
                    continue
                if f"{marker}<b>" in r.text:
                    out.append(self.finding(
                        "Reflected XSS: input echoed without HTML encoding", "High", pt.url,
                        f"Marker '{marker}<b>' sent in '{name}' was reflected unescaped in an HTML response "
                        f"(HTTP {r.status_code}). Only a harmless marker was used.",
                        "Contextually HTML-encode all output, use an auto-escaping template engine and add a "
                        "restrictive Content-Security-Policy.", parameter=name))
        return out
