"""Base class every check derives from (one class per check)."""
from __future__ import annotations

from typing import List

from ..core import Finding, OWASP_NAMES


class Check:
    id = ""            # e.g. "A05-HEADERS"
    name = ""          # human readable
    owasp = "A05"      # key into OWASP_NAMES
    kind = "passive"   # "passive" (analyses crawled data) | "probe" (extra benign GETs)
    description = ""

    def run(self, ctx) -> List[Finding]:  # pragma: no cover - interface
        raise NotImplementedError

    def finding(self, title, severity, url, evidence, recommendation, parameter=None) -> Finding:
        return Finding(
            check_id=self.id, title=title, severity=severity, owasp=OWASP_NAMES[self.owasp],
            url=url, evidence=evidence, recommendation=recommendation, parameter=parameter,
        )
