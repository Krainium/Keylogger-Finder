from __future__ import annotations

import platform
from datetime import datetime

from .finding import ScanResult
from .platforms import common_checks

SCAN_LEVELS = {"quick", "full"}

def _platform_checks(os_system: str):
    if os_system == "Windows":
        from .platforms import windows_checks as mod
        return mod.CHECKS
    if os_system == "Darwin":
        from .platforms import macos_checks as mod
        return mod.CHECKS
    if os_system == "Linux":
        from .platforms import linux_checks as mod
        return mod.CHECKS
    return []

def detected_os_label() -> str:
    system = platform.system()
    if system == "Darwin":
        return "macOS"
    return system or "Unknown"

def run_scan(level: str = "full", progress_callback=None) -> ScanResult:
    if level not in SCAN_LEVELS:
        raise ValueError(f"Unknown scan level: {level}")

    os_system = platform.system()
    started_at = datetime.now()
    findings = []
    errors = []
    checks_run = []

    checks = [("Known keylogger signatures", common_checks.check_known_signatures)]
    if level == "full":
        checks += [
            ("Processes in temp folders", common_checks.check_suspicious_locations),
            ("Suspicious process naming", common_checks.check_suspicious_keywords),
        ]
        checks += _platform_checks(os_system)

    total = len(checks)
    for index, (label, func) in enumerate(checks, start=1):
        if progress_callback:
            progress_callback(label, index, total)
        try:
            findings.extend(func())
        except Exception as exc:
            errors.append(f"{label}: {exc}")
        checks_run.append(label)

    finished_at = datetime.now()
    return ScanResult(
        os_name=detected_os_label(),
        started_at=started_at,
        finished_at=finished_at,
        checks_run=checks_run,
        findings=findings,
        errors=errors,
    )
