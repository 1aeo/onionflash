#!/usr/bin/env python3
"""Read-only latency/storage audit of SQLite and verified publication receipts.

Use a consistent SQLite backup, not a raw copy of a live WAL database. Receipt
times are verified-publication observations, not the source's availability time.
This tool makes no network requests and never writes to the database.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from contextlib import closing
from datetime import datetime, timedelta, timezone
import gzip
import json
import math
from pathlib import Path
import re
import sqlite3

UTC = timezone.utc
STORY_PATH = re.compile(r"news/([A-Za-z0-9_-]{1,64})/index\.html\Z")


def instant(value):
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return result.astimezone(UTC) if result.tzinfo else None
    except ValueError:
        return None


def iso(value):
    return value.isoformat().replace("+00:00", "Z") if value else None


def distribution(values):
    values = sorted(v for v in values if isinstance(v, (int, float)) and math.isfinite(v) and v >= 0)
    def percentile(fraction):
        position = (len(values) - 1) * fraction
        lower = int(position)
        upper = min(lower + 1, len(values) - 1)
        return round(values[lower] + (values[upper] - values[lower]) * (position - lower), 3)
    if not values:
        return {"count": 0, "p50_seconds": None, "p95_seconds": None, "max_seconds": None}
    return {"count": len(values), "p50_seconds": percentile(.5), "p95_seconds": percentile(.95),
            "max_seconds": round(values[-1], 3), "small_sample": len(values) < 20}


def publication_history(directory, maximum=10000, until=None):
    """Return earliest receipt containing each permalink, independent of UUID order."""
    paths = sorted(Path(directory).glob("*.json"))
    if len(paths) > maximum:
        raise ValueError("Receipt limit exceeded; increase --max-receipts rather than silently truncating history")
    first, observations, skipped = {}, [], 0
    for path in paths:
        if path.is_symlink() or path.stat().st_size > 16 * 1024 * 1024:
            raise ValueError("Receipt must be a regular JSON file no larger than 16 MiB")
        receipt = json.loads(path.read_text())
        published = instant(receipt.get("published_at"))
        manifest = receipt.get("manifest")
        if not published or not isinstance(manifest, dict) or (until and published > until):
            skipped += 1
            continue
        observations.append(published)
        for name in manifest:
            match = STORY_PATH.fullmatch(name)
            if match:
                story = match.group(1)
                first[story] = min(first.get(story, published), published)
    return first, {"valid_receipts": len(observations), "skipped_receipts": skipped,
                   "first_verified_publication": iso(min(observations)) if observations else None,
                   "last_verified_publication": iso(max(observations)) if observations else None}


def cohort(item, start, startup_seconds):
    seen, updated = instant(item["first_seen"]), instant(item["payload"].get("updated_at"))
    if not seen or not updated:
        return "unknown"
    if seen <= start + timedelta(seconds=startup_seconds) or updated < start:
        return "initial_or_historical_backfill"
    created = instant(item["payload"].get("published_at"))
    return "fresh_source_item" if created and created >= start else "resurfaced_source_update"


def gzip_size(path):
    class CounterSink:
        size = 0
        def write(self, data):
            self.size += len(data)
            return len(data)
        def flush(self):
            pass
    sink = CounterSink()
    with path.open("rb") as source, gzip.GzipFile(fileobj=sink, mode="wb", mtime=0) as output:
        for chunk in iter(lambda: source.read(65536), b""):
            output.write(chunk)
    return sink.size


def simulate_polling(interval_seconds=300, starts=24, jitter_seconds=(2, 1), tolerance_seconds=0):
    """Controlled simulation, not a reconstruction of unrecorded real fetches."""
    if interval_seconds <= 0 or starts < 2 or not jitter_seconds or tolerance_seconds < 0:
        raise ValueError("Invalid simulation parameters")
    checks, due = [], -math.inf
    for number in range(starts):
        observed = number * interval_seconds + jitter_seconds[number % len(jitter_seconds)]
        if observed + tolerance_seconds >= due:
            checks.append(observed)
            due = observed + interval_seconds
    return {"assumptions": "Periodic scheduler; alternating start offsets; healthy sources; no work overlap or retries",
            "scheduler_interval_seconds": interval_seconds, "start_offsets_seconds": list(jitter_seconds),
            "tolerance_seconds": tolerance_seconds, "scheduled_starts": starts, "fetches": len(checks),
            "fetch_gaps": distribution([b - a for a, b in zip(checks, checks[1:])])}


def audit(database, receipts, *, captured_at=None, startup_seconds=1800, immutable=False,
          compression=False, samples=5, max_receipts=10000, poll_seconds=300):
    if poll_seconds <= 0:
        raise ValueError("Polling interval must be positive")
    database = Path(database).resolve()
    captured = instant(captured_at) or datetime.now(UTC)
    uri = database.as_uri() + "?mode=ro" + ("&immutable=1" if immutable else "")
    with closing(sqlite3.connect(uri, uri=True)) as connection:
        connection.row_factory = sqlite3.Row
        rows = []
        for record in connection.execute("SELECT id,url,payload,first_seen,last_seen,status,story_id,attempts,last_error,priority_score FROM items"):
            item = dict(record)
            payload = json.loads(item["payload"])
            # Do not retain source bodies or model evidence in audit memory/output.
            item["payload"] = {key: payload.get(key) for key in ("kind", "published_at", "updated_at")}
            rows.append(item)
        starts = [instant(x["first_seen"]) for x in rows if instant(x["first_seen"])]
        start = min(starts) if starts else captured
        pages = {name: connection.execute("PRAGMA " + name).fetchone()[0]
                 for name in ["page_size", "page_count", "freelist_count", "journal_mode", "auto_vacuum"]}
        counts = {table: connection.execute("SELECT count(*) FROM " + table).fetchone()[0]
                  for table in ["items", "analyses", "stories", "source_state", "metadata"]}
        table_bytes = []
        try:
            table_bytes = [dict(row) for row in connection.execute(
                "SELECT name,sum(pgsize) bytes,sum(payload) payload_bytes,sum(unused) unused_bytes,count(*) pages FROM dbstat GROUP BY name ORDER BY bytes DESC")]
        except sqlite3.OperationalError:
            pass
        analysis_range = connection.execute("SELECT min(created_at),max(created_at) FROM analyses").fetchone()
        clock_row = connection.execute("SELECT value FROM metadata WHERE key='fetch_completion_clock_since'").fetchone()
        completion_clock_since = instant(clock_row[0]) if clock_row else None
    first_published, publication = publication_history(receipts, max_receipts, captured)
    by_story = defaultdict(list)
    source_delays = defaultdict(list)
    cohorts = Counter()
    pending = defaultdict(list)
    excluded_changed_versions = 0
    negative_timestamp_proxies = 0
    for item in rows:
        name = cohort(item, start, startup_seconds)
        cohorts[name] += 1
        first_seen = instant(item["first_seen"])
        updated = instant(item["payload"].get("updated_at"))
        if item["story_id"]:
            by_story[item["story_id"]].append(item)
        if item["status"] == "pending" and first_seen:
            pending[item["payload"].get("kind", "unknown")].append((captured - first_seen).total_seconds())
        # Current source payload cannot establish what its timestamp was at first discovery
        # if the cached item changed in between. Do not mix versions in the timing metric.
        if item["last_seen"] != item["first_seen"]:
            excluded_changed_versions += 1
        elif first_seen and updated:
            delay = (first_seen - updated).total_seconds()
            if delay < 0:
                negative_timestamp_proxies += 1
            else:
                source_delays[name].append(delay)
    story_timings, delays, unchanged_delays = [], defaultdict(list), defaultdict(list)
    for story_id, published in first_published.items():
        available = [item for item in by_story[story_id] if instant(item["first_seen"]) and instant(item["first_seen"]) <= published]
        if not available:
            continue
        anchor = min(available, key=lambda item: (instant(item["first_seen"]), item["url"]))
        seen = instant(anchor["first_seen"])
        name = cohort(anchor, start, startup_seconds)
        wait = (published - seen).total_seconds()
        delays[name].append(wait)
        source_updated = instant(anchor["payload"].get("updated_at"))
        unchanged = anchor["last_seen"] == anchor["first_seen"]
        if unchanged:
            unchanged_delays[name].append(wait)
        proxy = (published - source_updated).total_seconds() if unchanged and source_updated and source_updated <= published else None
        story_timings.append({"story_id": story_id, "source_url": anchor["url"],
                              "kind": anchor["payload"].get("kind"), "cohort": name,
                              "source_published_at": anchor["payload"].get("published_at"),
                              "source_updated_at_current_payload": anchor["payload"].get("updated_at"),
                              "source_payload_unchanged_since_first_seen": unchanged,
                              "first_seen": iso(seen), "earliest_recorded_verified_publication": iso(published),
                              "observation_clock": "post_fetch" if completion_clock_since and seen >= completion_clock_since else "cycle_start",
                              "first_seen_to_publication_seconds": round(wait, 3),
                              "source_update_to_publication_proxy_seconds": round(proxy, 3) if proxy is not None else None})
    db_bytes = pages["page_size"] * pages["page_count"]
    per_item = db_bytes / len(rows) if rows else None
    compressed = gzip_size(database) if compression else None
    post_start_rows = sum(bool(instant(x["first_seen"]) and instant(x["first_seen"]) > start + timedelta(seconds=startup_seconds)) for x in rows)
    report = {
        "captured_at": iso(captured), "first_collection_at": iso(start),
        "methodology": {
            "source_availability_recorded": False,
            "source_timestamp_is_proxy": True,
            "first_seen_semantics": (f"Items first observed from {iso(completion_clock_since)} use post-fetch observation time; older rows retain collection-cycle start markers." if completion_clock_since else "The audited baseline assigns the collection cycle's start time, not each HTTP fetch completion, to items.first_seen."),
            "fetch_completion_clock_since": iso(completion_clock_since),
            "upstream_timestamp_caveat": "GitLab issue created_at can be years older than a current update; Atom tag updated may be commit time rather than tag creation or first feed availability.",
            "publication_measurement": "Earliest supplied verified publication receipt containing the story permalink; earlier missing receipts cannot be reconstructed.",
            "startup_grace_seconds": startup_seconds,
            "changed_source_payloads_excluded_from_first_discovery_proxy": excluded_changed_versions,
            "negative_timestamp_proxies_excluded": negative_timestamp_proxies,
            "limitations": ["No comprehensive fetch-attempt history or source-first-available timestamp is stored.",
                            "No per-item analysis-finished timestamp or public revision history is stored.",
                            "Initial backlog and manual prepublication validation are not steady-state latency.",
                            "A resurfaced issue update is not proof that a new incident just occurred."]},
        "storage": {**pages, "audited_file_is_immutable_snapshot": immutable, "database_bytes": db_bytes,
                    "file_bytes": {p.name: p.stat().st_size for p in [database, Path(str(database)+"-wal"), Path(str(database)+"-shm")] if p.exists()},
                    "freelist_bytes": pages["freelist_count"] * pages["page_size"], "rows": counts,
                    "tables": table_bytes, "bytes_per_item_at_current_mix": round(per_item, 2) if per_item else None,
                    "gzip_database_bytes": compressed,
                    "gzip_ratio": round(compressed / database.stat().st_size, 4) if compressed and database.stat().st_size else None,
                    "growth_scenarios": [{"new_items_per_day": rate, "estimated_added_bytes_per_year": round(rate * 365 * per_item)} for rate in [25, 100, 500]] if per_item else [],
                    "growth_caveat": "Scenarios hold the current payload/cache/index/story mix constant; they are not forecasts. Updated items add cached analyses without adding item rows; larger sources and policy changes alter growth."},
        "collection": {"cohort_counts": dict(cohorts), "post_start_items_observed": post_start_rows,
                       "observation_hours": round((captured - start).total_seconds()/3600, 3),
                       "source_update_to_first_seen_proxy": {key: distribution(values) for key, values in source_delays.items()}},
        "queue": {"statuses": dict(Counter(x["status"] for x in rows)),
                  "pending_age_by_kind": {key: distribution(values) for key, values in pending.items()},
                  "pending_errors": dict(Counter(x["last_error"] or "not attempted" for x in rows if x["status"] == "pending")),
                  "max_pending_attempts": max((x["attempts"] for x in rows if x["status"] == "pending"), default=0),
                  "tag_statuses": dict(Counter(x["status"] for x in rows if x["payload"].get("kind") == "tag")),
                  "analysis_cache_first_created_at": analysis_range[0], "analysis_cache_last_created_at": analysis_range[1]},
        "publication": {**publication,
                        "first_seen_to_publication": {key: distribution(values) for key, values in delays.items()},
                        "unchanged_payload_first_seen_to_publication": {key: distribution(values) for key, values in unchanged_delays.items()},
                        "samples": sorted(story_timings, key=lambda x: (x["cohort"] == "initial_or_historical_backfill", -instant(x["earliest_recorded_verified_publication"]).timestamp()))[:samples]},
        "healthy_polling_model": {"assumptions": "New item becomes visible at a uniformly random phase; exact configured interval; no missed poll, network delay, queue, LLM time or publish time.",
                                  "interval_seconds": poll_seconds, "mean_detection_seconds": poll_seconds / 2,
                                  "p95_detection_seconds": poll_seconds * .95, "max_detection_seconds_exclusive": poll_seconds},
        "scheduler_jitter_simulations": [simulate_polling(interval_seconds=poll_seconds),
                                         simulate_polling(interval_seconds=poll_seconds, tolerance_seconds=min(5, poll_seconds / 10))],
    }
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--receipts", required=True, type=Path)
    parser.add_argument("--captured-at", help="UTC capture time for a historical snapshot")
    parser.add_argument("--startup-seconds", type=int, default=1800)
    parser.add_argument("--immutable-snapshot", action="store_true", help="Only for an offline, consistent backup with all committed WAL data already included")
    parser.add_argument("--compression-sample", action="store_true", help="Measure streaming gzip size of this snapshot; does not modify it")
    parser.add_argument("--samples", type=int, default=5)
    parser.add_argument("--max-receipts", type=int, default=10000)
    parser.add_argument("--poll-seconds", type=int, default=300, help="Polling interval for the explicitly hypothetical healthy/jitter models")
    args = parser.parse_args()
    if args.startup_seconds < 0 or args.samples < 0 or args.max_receipts < 1 or args.poll_seconds < 1:
        parser.error("Limits must be nonnegative and max-receipts positive")
    print(json.dumps(audit(args.database, args.receipts, captured_at=args.captured_at,
                           startup_seconds=args.startup_seconds, immutable=args.immutable_snapshot,
                           compression=args.compression_sample, samples=args.samples, max_receipts=args.max_receipts,
                           poll_seconds=args.poll_seconds), indent=2))


if __name__ == "__main__":
    main()
