from __future__ import annotations

import plistlib
import sqlite3
from pathlib import Path

from ..finding import Finding
from ..signatures import KNOWN_KEYLOGGER_NAMES, SUSPICIOUS_KEYWORDS

LAUNCH_LOCATIONS = [
    Path.home() / "Library/LaunchAgents",
    Path("/Library/LaunchAgents"),
    Path("/Library/LaunchDaemons"),
]

APPLE_PREFIXES = ("com.apple.",)

TCC_DB = Path.home() / "Library/Application Support/com.apple.TCC/TCC.db"

WATCHED_TCC_SERVICES = ("kTCCServiceAccessibility", "kTCCServiceListenEvent")

def check_launch_agents() -> list:
    findings = []
    keywords = KNOWN_KEYLOGGER_NAMES + SUSPICIOUS_KEYWORDS

    for folder in LAUNCH_LOCATIONS:
        if not folder.is_dir():
            continue
        try:
            plist_files = list(folder.glob("*.plist"))
        except OSError:
            continue
        for plist_path in plist_files:
            label = plist_path.stem
            if label.startswith(APPLE_PREFIXES):
                continue
            haystack = label.lower()
            program_args = ""
            try:
                with plist_path.open("rb") as handle:
                    data = plistlib.load(handle)
                program_args = " ".join(data.get("ProgramArguments", []) or [])
                haystack += " " + program_args.lower()
            except (OSError, plistlib.InvalidFileException):
                pass

            for word in keywords:
                if word in haystack:
                    severity = "critical" if word in KNOWN_KEYLOGGER_NAMES else "medium"
                    findings.append(
                        Finding(
                            severity=severity,
                            category="Persistent launch item",
                            title=f"{plist_path.name} mentions '{word}'",
                            detail=program_args or str(plist_path),
                        )
                    )
                    break
    return findings

def check_input_permissions() -> list:
    if not TCC_DB.exists():
        return [
            Finding(
                severity="info",
                category="Permissions",
                title="Could not read the macOS permissions database",
                detail=(
                    "TCC.db was not found, or Terminal does not have Full Disk "
                    "Access. Open System Settings, then Privacy and Security, "
                    "then Accessibility and Input Monitoring, and review the "
                    "list by hand."
                ),
            )
        ]

    try:
        connection = sqlite3.connect(f"file:{TCC_DB}?mode=ro", uri=True)
        cursor = connection.cursor()
        cursor.execute(
            "SELECT service, client FROM access WHERE service IN (?, ?) AND auth_value = 2",
            WATCHED_TCC_SERVICES,
        )
        rows = cursor.fetchall()
        connection.close()
    except sqlite3.Error:
        return [
            Finding(
                severity="info",
                category="Permissions",
                title="Could not read the macOS permissions database",
                detail=(
                    "Terminal needs Full Disk Access to check this "
                    "automatically. Open System Settings, then Privacy and "
                    "Security, then Accessibility and Input Monitoring, and "
                    "review the list by hand."
                ),
            )
        ]

    findings = []
    for service, client in rows:
        haystack = client.lower()
        matched_known = any(sig in haystack for sig in KNOWN_KEYLOGGER_NAMES)
        permission_name = (
            "Accessibility" if service == "kTCCServiceAccessibility" else "Input Monitoring"
        )
        findings.append(
            Finding(
                severity="critical" if matched_known else "info",
                category="Permissions",
                title=f"'{client}' has {permission_name} access",
                detail=(
                    "This permission lets an app read keystrokes system wide. "
                    "Review it if you do not recognize the app."
                ),
            )
        )
    return findings

CHECKS = [
    ("Launch agents and daemons", check_launch_agents),
    ("Accessibility and Input Monitoring grants", check_input_permissions),
]
