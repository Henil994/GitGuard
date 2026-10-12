import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from history import record_report, history, findings_for_scan

class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "history.sqlite3"
        self.report = {
            "profile": "test-user",
            "generated_at_utc": "2026-10-13T00:00:00Z",
            "public_non_fork_repositories_discovered": 1,
            "repositories_completed": 1,
            "risk_summary": {"high": 1},
            "results": [{
                "name": "demo",
                "findings": [{
                    "rule": "generic-api-key",
                    "category": "API Key",
                    "risk_level": "HIGH",
                    "risk_score": 90,
                    "file": "config.yaml",
                    "correlation_status": "HISTORICAL_ONLY",
                    "Secret": "MUST_NEVER_BE_STORED",
                    "Match": "MUST_NEVER_BE_STORED",
                }]
            }]
        }

    def tearDown(self):
        self.tmp.cleanup()

    def test_records_scan_and_safe_finding_metadata(self):
        result = record_report(self.report, db_path=self.db)
        self.assertEqual(result["new"], 1)
        self.assertEqual(len(history(self.db)), 1)
        findings = findings_for_scan(result["scan_id"], self.db)
        self.assertEqual(len(findings), 1)
        self.assertNotIn("Secret", findings[0])
        self.assertNotIn("Match", findings[0])
        self.assertNotIn("MUST_NEVER_BE_STORED", str(findings))

    def test_second_scan_tracks_recurring_and_resolved(self):
        first = record_report(self.report, db_path=self.db)
        second_report = dict(self.report)
        second_report["generated_at_utc"] = "2026-10-14T00:00:00Z"
        second = record_report(second_report, db_path=self.db)
        self.assertEqual(second["recurring"], 1)
        self.assertEqual(second["new"], 0)
        self.assertEqual(second["resolved"], 0)
        second_report["results"] = [{"name": "demo", "findings": []}]
        third = record_report(second_report, db_path=self.db)
        self.assertEqual(third["resolved"], 1)

if __name__ == "__main__":
    unittest.main()
