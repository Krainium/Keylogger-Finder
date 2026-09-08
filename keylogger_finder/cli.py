from __future__ import annotations

import sys

from rich.align import Align
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from . import __version__
from .report import list_reports, save_report
from .scanner import detected_os_label, run_scan
from .ui.theme import SEVERITY_STYLE, THEME, VERDICT_STYLE, banner_text

console = Console(theme=THEME)

MENU = """
[brand]1[/brand]  Quick scan     - running processes only, a few seconds
[brand]2[/brand]  Full scan      - processes, startup items, and persistence checks
[brand]3[/brand]  View last report
[brand]4[/brand]  Show saved reports
[brand]5[/brand]  About and safety notes
[brand]0[/brand]  Exit
"""

_last_result = None

def print_header() -> None:
    console.print(Align.center(banner_text()), style="brand")
    console.print(
        Align.center(
            f"v{__version__}  |  Operating system detected: {detected_os_label()}"
        ),
        style="muted",
    )
    console.rule(style="grey35")

def print_menu() -> None:
    console.print(Panel(MENU.strip("\n"), title="Main menu", border_style="grey42", expand=False))

def render_result(result) -> None:
    table = Table(title="Findings", show_lines=False, expand=True)
    table.add_column("Severity", width=10)
    table.add_column("Category", width=22)
    table.add_column("Detail")

    if not result.findings:
        console.print(
            Panel(
                "No findings. Nothing on this system matched a known keylogger footprint.",
                title="Findings",
                border_style="ok",
            )
        )
    else:
        for f in result.findings_by_severity():
            style = SEVERITY_STYLE.get(f.severity, "info")
            title = escape(f.title)
            detail = f"\n[muted]{escape(f.detail)}[/muted]" if f.detail else ""
            table.add_row(
                f"[{style}]{f.severity.upper()}[/{style}]",
                escape(f.category),
                f"{title}{detail}",
            )
        console.print(table)

    if result.errors:
        console.print(
            Panel(
                "\n".join(escape(e) for e in result.errors),
                title="Checks that could not run",
                border_style="medium",
            )
        )

    verdict_style = VERDICT_STYLE.get(result.verdict, "info")
    console.print()
    console.print(
        Align.center(
            Panel(f" VERDICT: {result.verdict} ", border_style=verdict_style, style=verdict_style)
        )
    )
    console.print(
        Align.center(f"{len(result.checks_run)} checks run in {result.duration_seconds:.1f}s"),
        style="muted",
    )

def run_scan_flow(level: str) -> None:
    global _last_result
    console.print()
    steps = []

    def progress(label, index, total):
        steps.append(label)

    with console.status(f"Running {level} scan...", spinner="dots12", spinner_style="brand"):
        result = run_scan(level=level, progress_callback=progress)

    for label in steps:
        console.print(f"  checked: {escape(label)}", style="muted")
    console.print()
    render_result(result)
    _last_result = result

    default = "y" if result.verdict in ("SUSPICIOUS", "LIKELY INFECTED") else "n"
    save = Prompt.ask("\nSave this report to a file?", choices=["y", "n"], default=default)
    if save == "y":
        _json_path, text_path = save_report(result)
        console.print(f"Saved: {text_path}", style="ok")

def show_last_report() -> None:
    if _last_result is None:
        console.print("No scan has been run yet this session.", style="muted")
        return
    render_result(_last_result)

def show_reports_folder() -> None:
    reports = list_reports()
    if not reports:
        console.print("No saved reports yet. Run a scan and choose to save it.", style="muted")
        return
    table = Table(title="Saved reports")
    table.add_column("File")
    for path in reports[:15]:
        table.add_row(str(path))
    console.print(table)

def show_about() -> None:
    console.print(
        Panel(
            "Keylogger Finder looks for common, publicly documented signs of "
            "keylogger and spyware activity: known process names, startup "
            "entries, permission grants and raw input access.\n\n"
            "It never records a single keystroke. Every check only reads "
            "information your operating system already exposes to any local "
            "user or admin.\n\n"
            "A clean result is a good sign, not a guarantee. Sophisticated or "
            "brand new malware can avoid every check here. Keep your system "
            "updated and pair this with a trusted antivirus for full coverage.",
            title="About Keylogger Finder",
            border_style="brand",
        )
    )

def main() -> None:
    if console.is_terminal:
        console.clear()
    print_header()
    try:
        while True:
            print_menu()
            choice = Prompt.ask("Choose an option", default="1")
            if choice == "1":
                run_scan_flow("quick")
            elif choice == "2":
                run_scan_flow("full")
            elif choice == "3":
                show_last_report()
            elif choice == "4":
                show_reports_folder()
            elif choice == "5":
                show_about()
            elif choice == "0":
                console.print("\nStay safe. Goodbye.\n", style="brand")
                break
            else:
                console.print("Not a valid option, try again.", style="medium")
            console.print()
    except (KeyboardInterrupt, EOFError):
        console.print("\nStopped. Goodbye.", style="brand")
        sys.exit(0)

if __name__ == "__main__":
    main()
