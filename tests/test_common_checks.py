import unittest
from unittest.mock import patch

from keylogger_finder.platforms import common_checks

class FakeProcess:
    def __init__(self, info):
        self.info = info

def fake_iter(processes):
    def _iter(attrs=None):
        return [FakeProcess(p) for p in processes]

    return _iter

class CommonChecksTests(unittest.TestCase):
    def test_known_signature_is_flagged(self):
        processes = [
            {
                "pid": 101,
                "name": "ardamax.exe",
                "exe": "C:/Program Files/ardamax/ardamax.exe",
                "cmdline": ["ardamax.exe"],
            },
            {
                "pid": 102,
                "name": "chrome.exe",
                "exe": "C:/Program Files/chrome/chrome.exe",
                "cmdline": ["chrome.exe"],
            },
        ]
        with patch("keylogger_finder.platforms.common_checks.psutil.process_iter", fake_iter(processes)):
            findings = common_checks.check_known_signatures()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "critical")
        self.assertIn("101", findings[0].detail)

    def test_clean_process_list_has_no_findings(self):
        processes = [{"pid": 1, "name": "bash", "exe": "/usr/bin/bash", "cmdline": ["bash"]}]
        with patch("keylogger_finder.platforms.common_checks.psutil.process_iter", fake_iter(processes)):
            self.assertEqual(common_checks.check_known_signatures(), [])
            self.assertEqual(common_checks.check_suspicious_locations(), [])
            self.assertEqual(common_checks.check_suspicious_keywords(), [])

    def test_temp_folder_process_is_flagged(self):
        processes = [{"pid": 5, "name": "updater", "exe": "/tmp/updater", "cmdline": ["/tmp/updater"]}]
        with patch("keylogger_finder.platforms.common_checks.psutil.process_iter", fake_iter(processes)):
            findings = common_checks.check_suspicious_locations()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "low")

    def test_generic_keyword_is_flagged_once(self):
        processes = [
            {"pid": 9, "name": "totally_normal_keylog_tool", "exe": "/opt/app/tool", "cmdline": []}
        ]
        with patch("keylogger_finder.platforms.common_checks.psutil.process_iter", fake_iter(processes)):
            findings = common_checks.check_suspicious_keywords()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "medium")

    def test_known_signature_not_double_counted_as_keyword(self):
        processes = [
            {
                "pid": 55,
                "name": "ardamax keylogger.exe",
                "exe": "C:/Program Files/ardamax/keylogger.exe",
                "cmdline": [],
            }
        ]
        with patch("keylogger_finder.platforms.common_checks.psutil.process_iter", fake_iter(processes)):
            signature_findings = common_checks.check_known_signatures()
            keyword_findings = common_checks.check_suspicious_keywords()
        self.assertEqual(len(signature_findings), 1)
        self.assertEqual(len(keyword_findings), 0)

if __name__ == "__main__":
    unittest.main()
