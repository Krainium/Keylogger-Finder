from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

@dataclass
class Finding:
    severity: str
    category: str
    title: str
    detail: str = ""

    def rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 0)

@dataclass
class ScanResult:
    os_name: str
    started_at: datetime
    finished_at: datetime
    checks_run: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    errors: list = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()

    @property
    def highest_severity(self) -> str:
        if not self.findings:
            return "info"
        return max(self.findings, key=lambda f: f.rank()).severity

    @property
    def verdict(self) -> str:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        if counts["critical"] or counts["high"] >= 2:
            return "LIKELY INFECTED"
        if counts["high"] or counts["medium"]:
            return "SUSPICIOUS"
        if counts["low"]:
            return "MOSTLY CLEAN"
        return "CLEAN"

    def findings_by_severity(self) -> list:
        return sorted(self.findings, key=lambda f: f.rank(), reverse=True)
