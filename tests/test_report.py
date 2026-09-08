import json
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from keylogger_finder import report as report_module
from keylogger_finder.finding import Finding, ScanResult

class ReportTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._original_dir = report_module.REPORTS_DIR
        report_module.REPORTS_DIR = Path(self._tmp.name)

    def tearDown(self):
        report_module.REPORTS_DIR = self._original_dir
        self._tmp.cleanup()

    def test_save_report_writes_valid_json_and_text(self):
        start = datetime(2026, 1, 1, 9, 0, 0)
        result = ScanResult(
            os_name="Linux",
            started_at=start,
            finished_at=start + timedelta(seconds=3),
            checks_run=["Known keylogger signatures"],
            findings=[Finding("critical", "Known signature", "Example finding", "detail here")],
        )
        json_path, text_path = report_module.save_report(result)

        self.assertTrue(json_path.exists())
        self.assertTrue(text_path.exists())

        payload = json.loads(json_path.read_text())
        self.assertEqual(payload["verdict"], "LIKELY INFECTED")
        self.assertEqual(len(payload["findings"]), 1)

        text = text_path.read_text()
        self.assertIn("LIKELY INFECTED", text)
        self.assertIn("Example finding", text)

    def test_list_reports_returns_saved_files_newest_first(self):
        start = datetime(2026, 1, 1, 9, 0, 0)
        first = ScanResult(os_name="Linux", started_at=start, finished_at=start, checks_run=[], findings=[])
        second = ScanResult(
            os_name="Linux",
            started_at=start + timedelta(minutes=1),
            finished_at=start + timedelta(minutes=1),
            checks_run=[],
            findings=[],
        )
        report_module.save_report(first)
        report_module.save_report(second)

        reports = report_module.list_reports()
        self.assertEqual(len(reports), 2)
        self.assertTrue(reports[0].name > reports[1].name)

if __name__ == "__main__":
    unittest.main()
