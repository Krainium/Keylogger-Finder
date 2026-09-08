import unittest
from datetime import datetime, timedelta

from keylogger_finder.finding import Finding, ScanResult

class VerdictTests(unittest.TestCase):
    def _result(self, findings):
        start = datetime(2026, 1, 1, 12, 0, 0)
        return ScanResult(
            os_name="Linux",
            started_at=start,
            finished_at=start + timedelta(seconds=2),
            checks_run=["test"],
            findings=findings,
        )

    def test_clean_when_no_findings(self):
        self.assertEqual(self._result([]).verdict, "CLEAN")

    def test_mostly_clean_on_low_only(self):
        findings = [Finding("low", "cat", "title")]
        self.assertEqual(self._result(findings).verdict, "MOSTLY CLEAN")

    def test_suspicious_on_single_medium(self):
        findings = [Finding("medium", "cat", "title")]
        self.assertEqual(self._result(findings).verdict, "SUSPICIOUS")

    def test_suspicious_on_single_high(self):
        findings = [Finding("high", "cat", "title")]
        self.assertEqual(self._result(findings).verdict, "SUSPICIOUS")

    def test_infected_on_critical(self):
        findings = [Finding("critical", "cat", "title")]
        self.assertEqual(self._result(findings).verdict, "LIKELY INFECTED")

    def test_infected_on_two_highs(self):
        findings = [Finding("high", "cat", "a"), Finding("high", "cat", "b")]
        self.assertEqual(self._result(findings).verdict, "LIKELY INFECTED")

    def test_findings_sorted_by_severity(self):
        findings = [Finding("low", "c", "a"), Finding("critical", "c", "b"), Finding("medium", "c", "c")]
        ordered = self._result(findings).findings_by_severity()
        self.assertEqual([f.severity for f in ordered], ["critical", "medium", "low"])

if __name__ == "__main__":
    unittest.main()
