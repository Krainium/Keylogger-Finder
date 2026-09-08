\
\
\
\
\
\
\
\
\
\
\
   

from __future__ import annotations

import json
import os
import subprocess
from html import escape
from pathlib import Path

SCREENSHOTS_DIR = Path(__file__).resolve().parent
CAPTURES_DIR = SCREENSHOTS_DIR / "_captures"

CHROMIUM = os.environ.get("CHROMIUM_PATH", "chromium")

BG = "#0f172a"
FG = "#e2e8f0"

STANDARD_COLORS = {
    "black": "#000000",
    "red": "#800000",
    "green": "#008000",
    "brown": "#808000",
    "blue": "#000080",
    "magenta": "#800080",
    "cyan": "#008080",
    "white": "#c0c0c0",
    "brightblack": "#808080",
    "brightred": "#ff0000",
    "brightgreen": "#00ff00",
    "brightbrown": "#ffff00",
    "brightblue": "#0000ff",
    "brightmagenta": "#ff00ff",
    "brightcyan": "#00ffff",
    "brightwhite": "#ffffff",
}

def resolve_color(value: str, default: str) -> str:
    if value == "default":
        return default
    if value in STANDARD_COLORS:
        return STANDARD_COLORS[value]
    if len(value) == 6:
        try:
            int(value, 16)
            return f"#{value}"
        except ValueError:
            pass
    return default

def cell_style(cell: dict) -> tuple:
    fg = resolve_color(cell["fg"], FG)
    bg = resolve_color(cell["bg"], BG)
    if cell.get("reverse"):
        fg, bg = bg, fg
    return (fg, bg, bool(cell.get("bold")), bool(cell.get("underscore")))

def row_to_html(cells: list) -> str:
    parts = []
    run_style = None
    run_chars = []

    def flush():
        if not run_chars:
            return
        fg, bg, bold, underscore = run_style
        text = escape("".join(run_chars))
        styles = [f"color:{fg}"]
        if bg != BG:
            styles.append(f"background-color:{bg}")
        if bold:
            styles.append("font-weight:bold")
        if underscore:
            styles.append("text-decoration:underline")
        parts.append(f'<span style="{";".join(styles)}">{text}</span>')

    for cell in cells:
        style = cell_style(cell)
        if style != run_style:
            flush()
            run_style = style
            run_chars = [cell["ch"]]
        else:
            run_chars.append(cell["ch"])
    flush()
    return "".join(parts) or " "

def capture_to_html(capture: dict) -> str:
    lines = [row_to_html(row) for row in capture["cells"]]
    body = "\n".join(lines)
    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<style>
  body {{ margin: 0; background: {BG}; }}
  pre {{
    margin: 0;
    padding: 24px;
    background: {BG};
    color: {FG};
    font-family: "DejaVu Sans Mono", "Cascadia Mono", Menlo, Consolas, monospace;
    font-size: 15px;
    line-height: 1.35;
    white-space: pre;
    display: inline-block;
  }}
</style>
</head>
<body><pre>{body}</pre></body>
</html>"""

def html_to_png(html_path: Path, png_path: Path, window_width: int = 1040, window_height: int = 900) -> None:
    subprocess.run(
        [
            CHROMIUM,
            "--headless=new",
            "--no-sandbox",
            "--disable-dev-shm-usage",
            f"--window-size={window_width},{window_height}",
            f"--screenshot={png_path}",
            f"--default-background-color={BG.lstrip('#')}",
            str(html_path),
        ],
        check=True,
        capture_output=True,
    )

def main() -> None:
    capture_paths = sorted(CAPTURES_DIR.glob("*.json"))
    if not capture_paths:
        raise SystemExit(f"no captures found in {CAPTURES_DIR}")
    for capture_path in capture_paths:
        name = capture_path.stem
        capture = json.loads(capture_path.read_text())
        html = capture_to_html(capture)
        html_path = SCREENSHOTS_DIR / f"_{name}.html"
        png_path = SCREENSHOTS_DIR / f"{name}.png"
        html_path.write_text(html)
        cols = capture["cols"]
        rows = len(capture["cells"])
        html_to_png(
            html_path,
            png_path,
            window_width=min(cols * 10 + 60, 1400),
            window_height=rows * 21 + 60,
        )
        html_path.unlink()
        print(f"saved {png_path.relative_to(SCREENSHOTS_DIR.parent)}")

if __name__ == "__main__":
    main()
