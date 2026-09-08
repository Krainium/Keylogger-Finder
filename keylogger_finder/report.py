from __future__ import annotations

import json
from pathlib import Path

from .finding import ScanResult

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"

def _timestamp_slug(result: ScanResult) -> str:
    return result.started_at.strftime("%Y%m%d_%H%M%S")

def save_report(result: ScanResult):
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    slug = _timestamp_slug(result)

    json_path = REPORTS_DIR / f"scan_{slug}.json"
    payload = {
        "os_name": result.os_name,
        "started_at": result.started_at.isoformat(),
        "finished_at": result.finished_at.isoformat(),
        "duration_seconds": result.duration_seconds,
        "verdict": result.verdict,
        "checks_run": result.checks_run,
        "errors": result.errors,
        "findings": [
            {
                "severity": f.severity,
                "category": f.category,
                "title": f.title,
                "detail": f.detail,
            }
            for f in result.findings_by_severity()
        ],
    }
    json_path.write_text(json.dumps(payload, indent=2))

    text_path = REPORTS_DIR / f"scan_{slug}.txt"
    lines = [
        "KEYLOGGER FINDER REPORT",
        "=" * 40,
        f"Operating system : {result.os_name}",
        f"Started          : {result.started_at.isoformat(timespec='seconds')}",
        f"Finished         : {result.finished_at.isoformat(timespec='seconds')}",
        f"Duration         : {result.duration_seconds:.2f}s",
        f"Verdict          : {result.verdict}",
        f"Checks run       : {', '.join(result.checks_run) or 'none'}",
        "",
    ]
    if result.errors:
        lines.append("Checks that could not run:")
        lines.extend(f"  {e}" for e in result.errors)
        lines.append("")

    if not result.findings:
        lines.append("No findings. Nothing matched a known keylogger footprint.")
    else:
        lines.append(f"Findings ({len(result.findings)}):")
        for f in result.findings_by_severity():
            lines.append(f"  [{f.severity.upper():>8}] {f.category}: {f.title}")
            if f.detail:
                lines.append(f"             {f.detail}")
    text_path.write_text("\n".join(lines))

    return json_path, text_path

def list_reports():
    if not REPORTS_DIR.exists():
        return []
    return sorted(REPORTS_DIR.glob("scan_*.json"), reverse=True)
