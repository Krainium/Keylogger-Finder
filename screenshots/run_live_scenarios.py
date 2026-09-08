from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from live_capture import LiveSession, save_capture

PLANTED_BINARY = "/tmp/ardamax"

def child_env() -> dict:
    env = os.environ.copy()
    env["TERM"] = "xterm-256color"
    env["COLORTERM"] = "truecolor"
    env["PYTHONUNBUFFERED"] = "1"
    return env

def run_menu_and_about() -> None:
    session = LiveSession([sys.executable, "run.py"], str(PROJECT_ROOT), env=child_env())
    session.start()
    try:
        assert session.wait_for(r"Choose an option"), "menu never appeared"
        save_capture("01_main_menu", session.snapshot())
        print("captured 01_main_menu")

        session.send(b"5\n")
        assert session.wait_for(r"About Keylogger Finder"), "about screen never appeared"
        session.settle(quiet_for=0.2, timeout=1.0)
        save_capture("05_about", session.snapshot())
        print("captured 05_about")
    finally:
        session.close()

def run_clean_scans() -> None:
    session = LiveSession([sys.executable, "run.py"], str(PROJECT_ROOT), env=child_env())
    session.start()
    try:
        assert session.wait_for(r"Choose an option"), "menu never appeared"

        session.send(b"2\n")
        assert session.wait_for(r"Running full scan", forbid=r"VERDICT"), "spinner never appeared"
        save_capture("02_scanning_in_progress", session.snapshot())
        print("captured 02_scanning_in_progress")

        assert session.wait_for(r"VERDICT"), "full scan never finished"
        assert session.wait_for(r"Save this report"), "save prompt never appeared"
        session.send(b"n\n")

        assert session.wait_for(r"Choose an option"), "menu never returned"
        session.send(b"1\n")
        assert session.wait_for(r"VERDICT"), "quick scan never finished"
        session.settle(quiet_for=0.2, timeout=1.0)
        save_capture("03_quick_scan_result", session.snapshot())
        print("captured 03_quick_scan_result")

        assert session.wait_for(r"Save this report"), "save prompt never appeared"
        session.send(b"n\n")
        assert session.wait_for(r"Choose an option"), "menu never returned"
    finally:
        session.close()

def plant_detectable_process() -> None:
                                                                         
                                                                        
                                                                         
                                                                      
                                                                     
                                                            
    subprocess.run(["cp", "/bin/bash", PLANTED_BINARY], check=True)
    subprocess.Popen(
        [PLANTED_BINARY, "-c", "sleep 600; :"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    time.sleep(0.3)

def cleanup_detectable_process() -> None:
    subprocess.run(["pkill", "-f", PLANTED_BINARY], check=False)
    time.sleep(0.2)
    try:
        os.remove(PLANTED_BINARY)
    except OSError:
        pass

def run_detection_scan() -> None:
    plant_detectable_process()
    session = LiveSession([sys.executable, "run.py"], str(PROJECT_ROOT), env=child_env())
    try:
        session.start()
        assert session.wait_for(r"Choose an option"), "menu never appeared"

        session.send(b"2\n")
        assert session.wait_for(r"VERDICT"), "full scan never finished"
        session.settle(quiet_for=0.2, timeout=1.0)
        save_capture("04_example_detection", session.snapshot())
        print("captured 04_example_detection")

        assert session.wait_for(r"Save this report"), "save prompt never appeared"
        session.send(b"n\n")
        assert session.wait_for(r"Choose an option"), "menu never returned"
    finally:
        session.close()
        cleanup_detectable_process()

SCENARIOS = {
    "menu": run_menu_and_about,
    "clean": run_clean_scans,
    "detection": run_detection_scan,
}

def main() -> None:
    names = sys.argv[1:] or ["menu", "clean", "detection"]
    for name in names:
        if name not in SCENARIOS:
            print(f"unknown scenario: {name}", file=sys.stderr)
            sys.exit(1)
    for name in names:
        print(f"--- running scenario: {name} ---")
        SCENARIOS[name]()

if __name__ == "__main__":
    main()
