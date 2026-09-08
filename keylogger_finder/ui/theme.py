from __future__ import annotations

import pyfiglet
from rich.theme import Theme

THEME = Theme(
    {
        "brand": "bold bright_cyan",
        "muted": "grey62",
        "ok": "bold spring_green2",
        "info": "bold deep_sky_blue1",
        "low": "bold khaki1",
        "medium": "bold orange3",
        "high": "bold orange_red1",
        "critical": "bold white on red3",
        "verdict.clean": "bold white on green4",
        "verdict.mostly": "bold black on khaki1",
        "verdict.suspicious": "bold white on dark_orange3",
        "verdict.infected": "bold white on red3",
    }
)

SEVERITY_STYLE = {
    "info": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}

VERDICT_STYLE = {
    "CLEAN": "verdict.clean",
    "MOSTLY CLEAN": "verdict.mostly",
    "SUSPICIOUS": "verdict.suspicious",
    "LIKELY INFECTED": "verdict.infected",
}

def banner_text() -> str:
    return pyfiglet.figlet_format("Keylogger Finder", font="small")
