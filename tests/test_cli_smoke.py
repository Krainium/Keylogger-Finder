\
\
   

import subprocess
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

class CliSmokeTests(unittest.TestCase):
    def _run_cli(self, stdin_text: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "keylogger_finder"],
            input=stdin_text,
            capture_output=True,
            text=True,
            cwd=PROJECT_ROOT,
            timeout=60,
        )

    def test_quick_scan_then_exit(self):
        result = self._run_cli("1\nn\n0\n")
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("Main menu", result.stdout)
        self.assertIn("VERDICT", result.stdout)

    def test_full_scan_and_save_report(self):
        result = self._run_cli("2\ny\n4\n0\n")
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("Saved:", result.stdout)

    def test_invalid_menu_choice_does_not_crash(self):
        result = self._run_cli("9\n0\n")
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("Not a valid option", result.stdout)

    def test_about_screen(self):
        result = self._run_cli("5\n0\n")
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("About Keylogger Finder", result.stdout)

if __name__ == "__main__":
    unittest.main()
