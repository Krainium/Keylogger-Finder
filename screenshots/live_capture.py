from __future__ import annotations

import fcntl
import json
import os
import re
import select
import struct
import sys
import termios
import time
from pathlib import Path

import pyte

COLS = 104
ROWS = 50

CAPTURES_DIR = Path(__file__).resolve().parent / "_captures"

def set_winsize(fd: int, rows: int, cols: int) -> None:
    winsize = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)

def screen_to_dict(screen: pyte.Screen) -> dict:
    last_used_row = 0
    rows_out = []
    for y in range(screen.lines):
        line = screen.buffer[y]
        cells = []
        row_has_content = False
        for x in range(screen.columns):
            char = line[x]
            if char.data != " ":
                row_has_content = True
            cells.append(
                {
                    "ch": char.data,
                    "fg": char.fg,
                    "bg": char.bg,
                    "bold": char.bold,
                    "underscore": char.underscore,
                    "reverse": char.reverse,
                }
            )
        rows_out.append(cells)
        if row_has_content:
            last_used_row = y
    return {
        "cols": screen.columns,
        "rows": screen.lines,
        "last_used_row": last_used_row,
        "cursor": {
            "x": screen.cursor.x,
            "y": screen.cursor.y,
            "hidden": screen.cursor.hidden,
        },
        "cells": rows_out[: last_used_row + 1],
    }

class LiveSession:
    def __init__(self, cmd, cwd, env=None):
        self.cmd = cmd
        self.cwd = cwd
        self.env = env or os.environ.copy()
        self.screen = pyte.Screen(COLS, ROWS)
        self.stream = pyte.ByteStream(self.screen)
        self.pid = None
        self.fd = None
        self._pending = b""

    def start(self) -> None:
        pid, fd = os.forkpty()
        if pid == 0:
            os.chdir(self.cwd)
            try:
                os.execvpe(self.cmd[0], self.cmd, self.env)
            except Exception as exc:
                sys.stderr.write(f"exec failed: {exc}\n")
                os._exit(1)
        self.pid = pid
        self.fd = fd
        set_winsize(fd, ROWS, COLS)

    def _pump(self, budget: float) -> bool:
        deadline = time.monotonic() + budget
        got_any = False
        if self._pending:
            self.stream.feed(self._pending)
            self._pending = b""
            got_any = True
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return got_any
            r, _, _ = select.select([self.fd], [], [], min(remaining, 0.05))
            if self.fd not in r:
                continue
            try:
                data = os.read(self.fd, 512)
            except OSError:
                return got_any
            if not data:
                return got_any
            self.stream.feed(data)
            got_any = True

    def _matches(self, rx, forbid_rx) -> "bool | None":
        text = "\n".join(self.screen.display)
        if forbid_rx and forbid_rx.search(text):
            return False
        if rx.search(text):
            return True
        return None

    def wait_for(self, pattern: str, timeout: float = 15.0, forbid: str | None = None) -> bool:
        rx = re.compile(pattern)
        forbid_rx = re.compile(forbid) if forbid else None

        while self._pending:
            b, self._pending = self._pending[:1], self._pending[1:]
            self.stream.feed(b)
            verdict = self._matches(rx, forbid_rx)
            if verdict is not None:
                return verdict

        verdict = self._matches(rx, forbid_rx)
        if verdict is not None:
            return verdict

        start = time.monotonic()
        while time.monotonic() - start < timeout:
            r, _, _ = select.select([self.fd], [], [], 0.05)
            if self.fd not in r:
                continue
            try:
                data = os.read(self.fd, 4096)
            except OSError:
                return False
            if not data:
                return False
            for i in range(len(data)):
                self.stream.feed(data[i : i + 1])
                verdict = self._matches(rx, forbid_rx)
                if verdict is not None:
                    self._pending = data[i + 1 :]
                    return verdict
        return False

    def send(self, data: bytes) -> None:
        os.write(self.fd, data)

    def snapshot(self) -> dict:
        return screen_to_dict(self.screen)

    def settle(self, quiet_for: float = 0.3, timeout: float = 5.0) -> None:
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            if not self._pump(quiet_for):
                return

    def close(self) -> None:
        try:
            self.send(b"0\n")
        except OSError:
            pass
        self.settle(quiet_for=0.2, timeout=1.5)
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
        if self.pid is not None:
            try:
                os.kill(self.pid, 15)
                os.waitpid(self.pid, 0)
            except (ProcessLookupError, ChildProcessError):
                pass

def save_capture(name: str, screen_dict: dict) -> Path:
    CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
    path = CAPTURES_DIR / f"{name}.json"
    path.write_text(json.dumps(screen_dict))
    return path
