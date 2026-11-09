import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("audit_history", Path(__file__).parents[1] / "tools/audit_history.py")
audit_history = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit_history)


class HistoryAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.database = self.root / "snapshot.sqlite3"
        self.receipts = self.root / "receipts"
        self.receipts.mkdir()
        with sqlite3.connect(self.database) as db:
            db.executescript("""
                CREATE TABLE items(id TEXT,url TEXT,payload TEXT,first_seen TEXT,last_seen TEXT,status TEXT,story_id TEXT,attempts INTEGER,last_error TEXT,priority_score INTEGER);
                CREATE TABLE analyses(created_at TEXT);
                CREATE TABLE stories(id TEXT);
                CREATE TABLE source_state(id TEXT);
                CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT);
            """)

    def item(self, identifier, created, updated, seen, *, last_seen=None, status="published", kind="gitlab_issue"):
        payload = {"kind": kind, "published_at": created, "updated_at": updated, "content": "PRIVATE RAW SOURCE SHOULD NOT APPEAR"}
        with sqlite3.connect(self.database) as db:
            db.execute("INSERT INTO items VALUES(?,?,?,?,?,?,?,?,?,?)", (identifier, "https://example.org/" + identifier,
                       json.dumps(payload), seen, last_seen or seen, status, identifier if status == "published" else None, 0, None, 15))
            if status == "published":
                db.execute("INSERT INTO stories VALUES(?)", (identifier,))

    def receipt(self, filename, date, stories):
        (self.receipts / filename).write_text(json.dumps({"published_at": date, "manifest": {"news/" + identifier + "/index.html": "hash" for identifier in stories}}))

    def test_initial_backfill_is_not_used_as_fresh_news_latency(self):
        self.item("old", "2020-01-01T00:00:00Z", "2026-11-08T00:00:00Z", "2026-11-09T08:00:00Z")
        self.item("new", "2026-11-09T09:01:00Z", "2026-11-09T09:01:00Z", "2026-11-09T09:05:00Z")
        self.receipt("a.json", "2026-11-09T09:08:00Z", ["old", "new"])
        result = audit_history.audit(self.database, self.receipts, captured_at="2026-11-09T10:00:00Z", immutable=True)
        timings = result["publication"]["first_seen_to_publication"]
        self.assertEqual(timings["fresh_source_item"]["p50_seconds"], 180)
        self.assertEqual(timings["initial_or_historical_backfill"]["p50_seconds"], 4080)
        self.assertFalse(result["methodology"]["source_availability_recorded"])
        self.assertNotIn("PRIVATE RAW SOURCE", json.dumps(result))

    def test_old_issue_updated_today_is_a_resurfaced_update(self):
        self.item("seed", "2026-11-08T00:00:00Z", "2026-11-08T00:00:00Z", "2026-11-09T08:00:00Z", status="ignored")
        self.item("resurfaced", "2021-03-01T00:00:00Z", "2026-11-09T09:00:00Z", "2026-11-09T09:03:00Z")
        self.receipt("pub.json", "2026-11-09T09:04:00Z", ["resurfaced"])
        result = audit_history.audit(self.database, self.receipts, captured_at="2026-11-09T10:00:00Z", immutable=True)
        row = result["publication"]["samples"][0]
        self.assertEqual(row["cohort"], "resurfaced_source_update")
        self.assertEqual(row["source_update_to_publication_proxy_seconds"], 240)
        self.assertNotIn("fresh_source_item", result["publication"]["first_seen_to_publication"])

    def test_new_clock_marker_distinguishes_post_fetch_observations(self):
        self.item("new", "2026-11-09T09:00:00Z", "2026-11-09T09:00:00Z", "2026-11-09T09:03:00Z")
        self.receipt("pub.json", "2026-11-09T09:04:00Z", ["new"])
        with sqlite3.connect(self.database) as db:
            db.execute("INSERT INTO metadata VALUES(?,?)", ("fetch_completion_clock_since", "2026-11-09T09:00:00Z"))
        result = audit_history.audit(self.database, self.receipts, captured_at="2026-11-09T10:00:00Z", immutable=True)
        self.assertEqual(result["publication"]["samples"][0]["observation_clock"], "post_fetch")
        self.assertIn("older rows retain", result["methodology"]["first_seen_semantics"])

    def test_changed_payload_timestamp_does_not_rewrite_first_discovery(self):
        self.item("old", "2026-11-01T00:00:00Z", "2026-11-09T10:00:00Z", "2026-11-09T08:00:00Z", last_seen="2026-11-09T10:01:00Z")
        self.receipt("early.json", "2026-11-09T08:10:00Z", ["old"])
        result = audit_history.audit(self.database, self.receipts, captured_at="2026-11-09T11:00:00Z", immutable=True)
        self.assertIsNone(result["publication"]["samples"][0]["source_update_to_publication_proxy_seconds"])
        self.assertEqual(result["methodology"]["changed_source_payloads_excluded_from_first_discovery_proxy"], 1)
        self.assertEqual(result["publication"]["unchanged_payload_first_seen_to_publication"], {})

    def test_receipts_use_times_not_uuid_filename_order(self):
        self.receipt("aaa.json", "2026-11-09T09:00:00Z", ["story"])
        self.receipt("zzz.json", "2026-11-09T08:00:00Z", ["story"])
        first, _ = audit_history.publication_history(self.receipts)
        self.assertEqual(audit_history.iso(first["story"]), "2026-11-09T08:00:00Z")
        with self.assertRaisesRegex(ValueError, "Receipt limit"):
            audit_history.publication_history(self.receipts, maximum=1)

    def test_receipts_after_snapshot_cutoff_are_not_backdated_into_measurement(self):
        self.item("item", "2026-11-01T00:00:00Z", "2026-11-01T00:00:00Z", "2026-11-09T08:00:00Z")
        self.receipt("future.json", "2026-11-09T12:00:00Z", ["item"])
        result = audit_history.audit(self.database, self.receipts, captured_at="2026-11-09T10:00:00Z", immutable=True, poll_seconds=60)
        self.assertEqual(result["publication"]["valid_receipts"], 0)
        self.assertEqual(result["publication"]["skipped_receipts"], 1)
        self.assertEqual(result["healthy_polling_model"]["mean_detection_seconds"], 30)

    def test_read_only_audit_and_gzip_sample_leave_database_unchanged(self):
        self.item("one", "2026-11-01T00:00:00Z", "2026-11-01T00:00:00Z", "2026-11-09T08:00:00Z")
        before = hashlib.sha256(self.database.read_bytes()).digest()
        result = audit_history.audit(self.database, self.receipts, immutable=True, compression=True)
        self.assertEqual(hashlib.sha256(self.database.read_bytes()).digest(), before)
        self.assertLess(result["storage"]["gzip_database_bytes"], result["storage"]["database_bytes"])
        self.assertEqual(result["publication"]["valid_receipts"], 0)

    def test_clock_jitter_can_skip_a_whole_scheduler_cycle(self):
        original = audit_history.simulate_polling()
        tolerant = audit_history.simulate_polling(tolerance_seconds=5)
        self.assertEqual(original["fetches"], 12)
        self.assertEqual(original["fetch_gaps"]["p50_seconds"], 600)
        self.assertEqual(tolerant["fetches"], 24)
        self.assertLessEqual(tolerant["fetch_gaps"]["max_seconds"], 301)

    def test_invalid_naive_timestamps_and_negative_durations_are_not_measurements(self):
        self.assertIsNone(audit_history.instant("2026-11-09T08:00:00"))
        self.assertEqual(audit_history.distribution([-10, float("nan"), 5])["count"], 1)
        self.assertIsNone(audit_history.distribution([])["p95_seconds"])


if __name__ == "__main__":
    unittest.main()
