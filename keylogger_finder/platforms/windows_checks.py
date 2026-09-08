from __future__ import annotations

import os
import subprocess
from pathlib import Path

from ..finding import Finding
from ..signatures import KNOWN_KEYLOGGER_NAMES, SUSPICIOUS_KEYWORDS

try:
    import winreg                
except ImportError:
    winreg = None

RUN_KEY_LOCATIONS = [
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
]

_HIVES = {}
if winreg is not None:
    _HIVES = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}

def _flag(name: str, value: str, source: str):
    haystack = f"{name} {value}".lower()
    for sig in KNOWN_KEYLOGGER_NAMES:
        if sig in haystack:
            return Finding(
                severity="critical",
                category="Known signature",
                title=f"{source} entry '{name}' matches known keylogger name '{sig}'",
                detail=value,
            )
    for word in SUSPICIOUS_KEYWORDS:
        if word in haystack:
            return Finding(
                severity="medium",
                category="Suspicious naming",
                title=f"{source} entry '{name}' mentions '{word}'",
                detail=value,
            )
    if "\\appdata\\local\\temp\\" in haystack or "\\windows\\temp\\" in haystack:
        return Finding(
            severity="low",
            category="Unusual location",
            title=f"{source} entry '{name}' launches from a temp folder",
            detail=value,
        )
    return None

def check_registry_run_keys() -> list:
    findings = []
    if winreg is None:
        return findings

    for hive_name, subkey in RUN_KEY_LOCATIONS:
        hive = _HIVES[hive_name]
        try:
            key = winreg.OpenKey(hive, subkey)
        except OSError:
            continue
        try:
            index = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, index)
                except OSError:
                    break
                finding = _flag(name, str(value), f"{hive_name}\\{subkey}")
                if finding:
                    findings.append(finding)
                index += 1
        finally:
            winreg.CloseKey(key)
    return findings

def check_startup_folders() -> list:
    findings = []
    candidates = []
    appdata = os.environ.get("APPDATA")
    programdata = os.environ.get("PROGRAMDATA")
    if appdata:
        candidates.append(Path(appdata) / "Microsoft/Windows/Start Menu/Programs/Startup")
    if programdata:
        candidates.append(Path(programdata) / "Microsoft/Windows/Start Menu/Programs/Startup")

    for folder in candidates:
        if not folder.is_dir():
            continue
        try:
            items = list(folder.iterdir())
        except OSError:
            continue
        for item in items:
            finding = _flag(item.name, str(item), "Startup folder")
            if finding:
                findings.append(finding)
    return findings

def check_scheduled_tasks() -> list:
    findings = []
    try:
        result = subprocess.run(
            ["schtasks", "/query", "/fo", "LIST", "/v"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return findings

    if result.returncode != 0:
        return findings

    keywords = KNOWN_KEYLOGGER_NAMES + SUSPICIOUS_KEYWORDS
    current_task = "unknown task"
    for line in result.stdout.splitlines():
        if line.strip().lower().startswith("taskname:"):
            current_task = line.split(":", 1)[1].strip()
        low = line.lower()
        for word in keywords:
            if word in low:
                findings.append(
                    Finding(
                        severity="medium",
                        category="Scheduled task",
                        title=f"Scheduled task '{current_task}' mentions '{word}'",
                        detail=line.strip(),
                    )
                )
                break
    return findings

CHECKS = [
    ("Registry Run keys", check_registry_run_keys),
    ("Startup folder", check_startup_folders),
    ("Scheduled tasks", check_scheduled_tasks),
]
