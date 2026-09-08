import tempfile
import unittest
from pathlib import Path

from keylogger_finder.platforms import linux_checks

class LinuxChecksSmokeTests(unittest.TestCase):
                                                                             

    def test_raw_input_access_runs_without_crashing(self):
        findings = linux_checks.check_raw_input_access()
        self.assertIsInstance(findings, list)

    def test_ld_preload_runs_without_crashing(self):
        findings = linux_checks.check_ld_preload()
        self.assertIsInstance(findings, list)

    def test_cron_jobs_runs_without_crashing(self):
        findings = linux_checks.check_cron_jobs()
        self.assertIsInstance(findings, list)

    def test_systemd_services_runs_without_crashing(self):
        findings = linux_checks.check_systemd_services()
        self.assertIsInstance(findings, list)

    def test_ld_preload_flags_a_non_empty_file(self):
        original_path = linux_checks.Path
        with tempfile.TemporaryDirectory() as tmp:
            fake_preload = Path(tmp) / "ld.so.preload"
            fake_preload.write_text("/tmp/evil.so\n")

            def patched_path(value):
                if value == "/etc/ld.so.preload":
                    return fake_preload
                return original_path(value)

            linux_checks.Path = patched_path
            try:
                findings = linux_checks.check_ld_preload()
            finally:
                linux_checks.Path = original_path

        self.assertTrue(any(f.severity == "critical" for f in findings))

if __name__ == "__main__":
    unittest.main()
