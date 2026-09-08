from __future__ import annotations

import os

import psutil

from ..finding import Finding
from ..signatures import KNOWN_KEYLOGGER_NAMES, SUSPICIOUS_KEYWORDS

OWN_PID = os.getpid()

TEMP_MARKERS = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "appdata\\local\\temp",
    "windows\\temp",
)


def _process_haystack(info: dict) -> str:
    name = info.get("name") or ""
    exe = info.get("exe") or ""
    cmdline = " ".join(info.get("cmdline") or [])
    return " ".join([name, exe, cmdline]).lower()


def check_known_signatures() -> list:
    findings = []
    seen_pids = set()
    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
        try:
            info = proc.info
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        if info.get("pid") == OWN_PID:
            continue
        haystack = _process_haystack(info)
        if not haystack.strip():
            continue
        for sig in KNOWN_KEYLOGGER_NAMES:
            if sig in haystack and info["pid"] not in seen_pids:
                seen_pids.add(info["pid"])
                findings.append(
                    Finding(
                        severity="critical",
                        category="Known signature",
                        title=f"Running process matches known keylogger name '{sig}'",
                        detail=f"pid {info.get('pid')} | {info.get('name')} | {info.get('exe') or 'path hidden'}",
                    )
                )
                break
    return findings


def check_suspicious_locations() -> list:
    findings = []
    for proc in psutil.process_iter(["pid", "name", "exe"]):
        try:
            if proc.info.get("pid") == OWN_PID:
                continue
            exe = proc.info.get("exe") or ""
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        low = exe.lower()
        if low and any(marker in low for marker in TEMP_MARKERS):
            findings.append(
                Finding(
                    severity="low",
                    category="Unusual location",
                    title=f"'{proc.info.get('name')}' is running from a temporary folder",
                    detail=exe,
                )
            )
    return findings


def check_suspicious_keywords() -> list:
    findings = []
    seen_pids = set()
    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
        try:
            info = proc.info
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        if info.get("pid") == OWN_PID:
            continue
        haystack = _process_haystack(info)
        if not haystack.strip():
            continue
        if any(sig in haystack for sig in KNOWN_KEYLOGGER_NAMES):
            continue
        for word in SUSPICIOUS_KEYWORDS:
            if word in haystack and info["pid"] not in seen_pids:
                seen_pids.add(info["pid"])
                findings.append(
                    Finding(
                        severity="medium",
                        category="Suspicious naming",
                        title=f"Process name or path mentions '{word}'",
                        detail=f"pid {info.get('pid')} | {info.get('name')} | {info.get('exe') or 'path hidden'}",
                    )
                )
                break
    return findings


CHECKS = [
    ("Known keylogger signatures", check_known_signatures),
    ("Processes running from temp folders", check_suspicious_locations),
    ("Suspicious process naming", check_suspicious_keywords),
]
