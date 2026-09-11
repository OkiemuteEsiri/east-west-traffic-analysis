import unittest
from datetime import datetime, timezone
from src.analyzer import analyze, metrics
from src.models import Flow


def flow(i, src="A", dst="B", sz="user", dz="server", port=443, bytes_out=1000, approved=False):
    return Flow(i, datetime(2026,1,1,tzinfo=timezone.utc), src, dst, sz, dz, "tcp", port, bytes_out, "lab", approved)


class AnalyzerTests(unittest.TestCase):
    def test_sensitive_zone(self):
        self.assertTrue(any("sensitive internal zone" in f.title.lower() for f in analyze([flow("1", dz="database")])))

    def test_approved_sensitive_suppressed(self):
        self.assertFalse(analyze([flow("1", dz="database", approved=True)]))

    def test_admin_fanout(self):
        rows=[flow("1",dst="S1",port=3389),flow("2",dst="S2",port=3389),flow("3",dst="S3",port=22)]
        self.assertTrue(any("fan-out" in f.title for f in analyze(rows)))

    def test_user_to_database(self):
        self.assertTrue(any("database-zone" in f.title for f in analyze([flow("1",dz="database",port=5432)])))

    def test_bulk_transfer(self):
        self.assertTrue(any("high-volume" in f.title for f in analyze([flow("1",bytes_out=60_000_000)])))

    def test_backup_bulk_suppressed(self):
        self.assertFalse(any("high-volume" in f.title for f in analyze([flow("1",sz="backup",dz="backup",bytes_out=60_000_000)])))

    def test_scores_bounded(self):
        self.assertTrue(all(0 <= f.score <= 100 for f in analyze([flow("1",dz="database")])) )

    def test_deterministic_ids(self):
        rows=[flow("1",dz="database")]
        self.assertEqual(analyze(rows)[0].finding_id, analyze(rows)[0].finding_id)

    def test_metrics(self):
        fs=analyze([flow("1",dz="database")])
        self.assertEqual(metrics(fs)["findings"], len(fs))

    def test_priority_order(self):
        rows=[flow("1",dst="S1",port=3389),flow("2",dst="S2",port=3389),flow("3",dst="S3",port=22),flow("4",src="C",bytes_out=60_000_000)]
        fs=analyze(rows)
        self.assertGreaterEqual(fs[0].score, fs[-1].score)


if __name__ == "__main__": unittest.main()
