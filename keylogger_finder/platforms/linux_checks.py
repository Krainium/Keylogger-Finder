from __future__ import annotations

import os
import subprocess
from pathlib import Path

from ..finding import Finding
from ..signatures import KNOWN_KEYLOGGER_NAMES, SUSPICIOUS_KEYWORDS

SAFE_INPUT_READERS = {
    "Xorg",
    "Xorg.wrap",
    "Xwayland",
    "libinput",
    "systemd-logind",
    "gnome-shell",
    "kwin_wayland",
    "weston",
}

def check_raw_input_access() -> list:
    findings = []
    proc_root = Path("/proc")
    if not proc_root.exists():
        return findings

    for pid_dir in proc_root.iterdir():
        if not pid_dir.name.isdigit():
            continue
        fd_dir = pid_dir / "fd"
        try:
            fds = list(fd_dir.iterdir())
        except (PermissionError, FileNotFoundError, NotADirectoryError):
            continue

        try:
            comm = (pid_dir / "comm").read_text().strip()
        except OSError:
            comm = "unknown"
        if comm in SAFE_INPUT_READERS:
            continue

        for fd in fds:
            try:
                target = os.readlink(fd)
            except OSError:
                continue
            if "/dev/input/event" in target or "/dev/input/mice" in target:
                try:
                    cmdline = (
                        (pid_dir / "cmdline")
                        .read_bytes()
                        .replace(b"\x00", b" ")
                        .decode(errors="replace")
                        .strip()
                    )
                except OSError:
                    cmdline = ""
                findings.append(
                    Finding(
                        severity="high",
                        category="Raw input access",
                        title=f"Process '{comm}' (pid {pid_dir.name}) holds a raw keyboard device open",
                        detail=cmdline or target,
                    )
                )
                break
    return findings

def check_ld_preload() -> list:
    findings = []
    preload_file = Path("/etc/ld.so.preload")
    if preload_file.exists():
        try:
            content = preload_file.read_text().strip()
        except OSError:
            content = ""
        if content:
            findings.append(
                Finding(
                    severity="critical",
                    category="Library injection",
                    title="/etc/ld.so.preload is not empty",
                    detail=content,
                )
            )

    env_preload = os.environ.get("LD_PRELOAD", "").strip()
    if env_preload:
        findings.append(
            Finding(
                severity="medium",
                category="Library injection",
                title="LD_PRELOAD is set in the current environment",
                detail=env_preload,
            )
        )
    return findings

def check_cron_jobs() -> list:
    findings = []
    candidates = []

    try:
        result = subprocess.run(
            ["crontab", "-l"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            candidates.append(("user crontab", result.stdout))
    except (OSError, subprocess.SubprocessError):
        pass

    for cron_dir in ("/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly"):
        path = Path(cron_dir)
        if not path.is_dir():
            continue
        try:
            items = list(path.iterdir())
        except OSError:
            continue
        for item in items:
            try:
                candidates.append((str(item), item.read_text()))
            except OSError:
                continue

    keywords = KNOWN_KEYLOGGER_NAMES + SUSPICIOUS_KEYWORDS
    for source, content in candidates:
        low = content.lower()
        for word in keywords:
            if word in low:
                findings.append(
                    Finding(
                        severity="medium",
                        category="Scheduled task",
                        title=f"Cron entry in {source} mentions '{word}'",
                        detail=content.strip()[:300],
                    )
                )
                break
    return findings

def check_systemd_services() -> list:
    findings = []
    try:
        result = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager"],
            capture_output=True,
            text=True,
            timeout=8,
        )
    except (OSError, subprocess.SubprocessError):
        return findings

    if result.returncode != 0:
        return findings

    keywords = KNOWN_KEYLOGGER_NAMES + SUSPICIOUS_KEYWORDS
    for line in result.stdout.splitlines():
        low = line.lower()
        for word in keywords:
            if word in low:
                findings.append(
                    Finding(
                        severity="medium",
                        category="System service",
                        title=f"systemd unit mentions '{word}'",
                        detail=line.strip(),
                    )
                )
                break
    return findings

CHECKS = [
    ("Raw keyboard device access", check_raw_input_access),
    ("Library injection (LD_PRELOAD)", check_ld_preload),
    ("Cron jobs", check_cron_jobs),
    ("systemd services", check_systemd_services),
]
