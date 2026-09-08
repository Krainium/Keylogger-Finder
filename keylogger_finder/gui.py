from __future__ import annotations

import queue
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from .report import save_report
from .scanner import detected_os_label, run_scan

SEVERITY_COLORS = {
    "info": "#3b82f6",
    "low": "#eab308",
    "medium": "#f97316",
    "high": "#ef4444",
    "critical": "#b91c1c",
}

VERDICT_COLORS = {
    "CLEAN": "#16a34a",
    "MOSTLY CLEAN": "#65a30d",
    "SUSPICIOUS": "#ea580c",
    "LIKELY INFECTED": "#b91c1c",
}

LIGHT_TEXT_VERDICTS = ("CLEAN", "MOSTLY CLEAN")

_BG      = "#0f172a"
_BG2     = "#1e293b"
_FG      = "#e2e8f0"
_BORDER  = "#334155"
_ACCENT  = "#38bdf8"
_SEL_BG  = "#1e3a5f"

class KeyloggerFinderApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Keylogger Finder")
        self.geometry("760x620")
        self.minsize(640, 480)
        self.configure(bg=_BG)

        self._apply_dark_style()

        self._queue = queue.Queue()
        self._last_result = None
        self._scanning = False
        self._finding_map = {}

        self._build_layout()
        self.after(150, self._poll_queue)

    def _apply_dark_style(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure(".", background=_BG, foreground=_FG, font=("Segoe UI", 10))

        style.configure(
            "Treeview",
            background=_BG2,
            foreground=_FG,
            fieldbackground=_BG2,
            bordercolor=_BORDER,
            rowheight=26,
        )
        style.configure(
            "Treeview.Heading",
            background=_BORDER,
            foreground=_FG,
            bordercolor=_BORDER,
            relief="flat",
        )
        style.map(
            "Treeview",
            background=[("selected", _SEL_BG)],
            foreground=[("selected", "#ffffff")],
        )
        style.map(
            "Treeview.Heading",
            background=[("active", "#475569")],
        )

        style.configure(
            "TRadiobutton",
            background=_BG,
            foreground=_FG,
            focuscolor=_BG,
        )
        style.map(
            "TRadiobutton",
            background=[("active", _BG)],
            foreground=[("active", _ACCENT)],
        )

        style.configure(
            "TProgressbar",
            background=_ACCENT,
            troughcolor=_BG2,
            bordercolor=_BORDER,
        )

        style.configure(
            "TScrollbar",
            background=_BG2,
            troughcolor=_BG,
            bordercolor=_BORDER,
            arrowcolor=_FG,
        )
        style.map("TScrollbar", background=[("active", "#475569")])

    def _build_layout(self) -> None:
        header = tk.Frame(self, bg=_BG)
        header.pack(fill="x", padx=24, pady=(20, 8))

        tk.Label(
            header,
            text="Keylogger Finder",
            font=("Segoe UI", 20, "bold"),
            fg=_ACCENT,
            bg=_BG,
        ).pack(side="left")

        tk.Label(
            header,
            text=f"OS detected: {detected_os_label()}",
            font=("Segoe UI", 10),
            fg="#94a3b8",
            bg=_BG,
        ).pack(side="right")

        controls = tk.Frame(self, bg=_BG)
        controls.pack(fill="x", padx=24, pady=8)

        self.scan_type = tk.StringVar(value="full")
        ttk.Radiobutton(controls, text="Quick scan", value="quick", variable=self.scan_type).pack(
            side="left"
        )
        ttk.Radiobutton(controls, text="Full scan", value="full", variable=self.scan_type).pack(
            side="left", padx=(12, 0)
        )

        self.scan_button = tk.Button(
            controls,
            text="Scan now",
            command=self._start_scan,
            bg=_ACCENT,
            fg=_BG,
            activebackground="#0ea5e9",
            font=("Segoe UI", 11, "bold"),
            relief="flat",
            padx=18,
            pady=6,
            cursor="hand2",
        )
        self.scan_button.pack(side="right")

        self.save_button = tk.Button(
            controls,
            text="Save report",
            command=self._save_report,
            state="disabled",
            bg=_BORDER,
            fg=_FG,
            activebackground="#475569",
            activeforeground=_FG,
            disabledforeground="#64748b",
            relief="flat",
            padx=14,
            pady=6,
        )
        self.save_button.pack(side="right", padx=(0, 10))

        self.status_var = tk.StringVar(value="Ready")
        self.status_label = tk.Label(
            self,
            textvariable=self.status_var,
            font=("Segoe UI", 11, "bold"),
            fg=_FG,
            bg=_BG2,
            anchor="w",
            padx=16,
            pady=10,
        )
        self.status_label.pack(fill="x", padx=24)

        self.progress = ttk.Progressbar(self, mode="indeterminate")
        self.progress.pack(fill="x", padx=24, pady=(6, 12))

        results_frame = tk.Frame(self, bg=_BG)
        results_frame.pack(fill="both", expand=True, padx=24, pady=(0, 20))

        columns = ("severity", "category", "title")
        self.tree = ttk.Treeview(results_frame, columns=columns, show="headings", height=12)
        self.tree.heading("severity", text="Severity")
        self.tree.heading("category", text="Category")
        self.tree.heading("title", text="Finding")
        self.tree.column("severity", width=90, anchor="center")
        self.tree.column("category", width=170)
        self.tree.column("title", width=420)
        self.tree.pack(fill="both", expand=True, side="left")

        scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(fill="y", side="right")
        self.tree.bind("<<TreeviewSelect>>", self._on_row_select)

        for severity, color in SEVERITY_COLORS.items():
            self.tree.tag_configure(severity, foreground=color)

        detail_frame = tk.Frame(self, bg=_BG2)
        detail_frame.pack(fill="x", padx=24, pady=(4, 12))
        tk.Label(
            detail_frame,
            text="Path / detail:",
            fg="#94a3b8",
            bg=_BG2,
            font=("Segoe UI", 9),
            padx=8,
            pady=4,
        ).pack(anchor="w")
        self._detail_var = tk.StringVar(value="Select a finding to see its path or detail.")
        tk.Label(
            detail_frame,
            textvariable=self._detail_var,
            fg=_FG,
            bg=_BG2,
            font=("Segoe UI", 9),
            anchor="w",
            wraplength=700,
            justify="left",
            padx=8,
            pady=(0, 6),
        ).pack(anchor="w", fill="x")

    def _start_scan(self) -> None:
        if self._scanning:
            return
        self._scanning = True
        self.scan_button.config(state="disabled")
        self.save_button.config(state="disabled")
        self.status_var.set("Scanning...")
        self.status_label.config(bg=_BG2, fg=_FG)
        for row in self.tree.get_children():
            self.tree.delete(row)
        self.progress.start(12)

        level = self.scan_type.get()
        thread = threading.Thread(target=self._run_scan_worker, args=(level,), daemon=True)
        thread.start()

    def _run_scan_worker(self, level: str) -> None:
        def progress(label, index, total):
            self._queue.put(("progress", f"Checking: {label} ({index}/{total})"))

        try:
            result = run_scan(level=level, progress_callback=progress)
            self._queue.put(("done", result))
        except Exception as exc:
            self._queue.put(("error", str(exc)))

    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self._queue.get_nowait()
                if kind == "progress":
                    self.status_var.set(payload)
                elif kind == "done":
                    self._on_scan_done(payload)
                elif kind == "error":
                    self._on_scan_error(payload)
        except queue.Empty:
            pass
        self.after(150, self._poll_queue)

    def _on_scan_done(self, result) -> None:
        self._scanning = False
        self._last_result = result
        self.progress.stop()
        self.scan_button.config(state="normal")
        self.save_button.config(state="normal")

        self._finding_map = {}
        self._detail_var.set("Select a finding to see its path or detail.")
        for finding in result.findings_by_severity():
            iid = self.tree.insert(
                "",
                "end",
                values=(finding.severity.upper(), finding.category, finding.title),
                tags=(finding.severity,),
            )
            self._finding_map[iid] = finding.detail

        color = VERDICT_COLORS.get(result.verdict, "#334155")
        self.status_var.set(
            f"Verdict: {result.verdict}   |   {len(result.findings)} finding(s)   |   "
            f"{result.duration_seconds:.1f}s"
        )
        text_color = _BG if result.verdict in LIGHT_TEXT_VERDICTS else "#ffffff"
        self.status_label.config(bg=color, fg=text_color)

        if not result.findings:
            messagebox.showinfo(
                "Scan complete", "No findings. Nothing matched a known keylogger footprint."
            )

    def _on_row_select(self, event) -> None:
        sel = self.tree.selection()
        if sel:
            detail = self._finding_map.get(sel[0], "")
            self._detail_var.set(detail or "No further detail available.")

    def _on_scan_error(self, message: str) -> None:
        self._scanning = False
        self.progress.stop()
        self.scan_button.config(state="normal")
        self.status_var.set("Scan failed")
        self.status_label.config(bg="#b91c1c", fg="#ffffff")
        messagebox.showerror("Scan failed", message)

    def _save_report(self) -> None:
        if self._last_result is None:
            return
        _json_path, text_path = save_report(self._last_result)
        messagebox.showinfo("Report saved", f"Saved to:\n{text_path}")

def main() -> None:
    app = KeyloggerFinderApp()
    app.mainloop()

if __name__ == "__main__":
    main()
