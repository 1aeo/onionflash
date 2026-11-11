"""Durable collection, retry queue, analysis records, and stable story identities."""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path

from .util import after, backoff_seconds, digest, item_cluster, item_identity
from . import candidate, editorial, monitoring, render
from .candidate import ReviewRequired, StaleCandidate


def backup_database(source: str | Path, destination: str | Path) -> None:
    """Copy committed WAL data into a new, private, validated SQLite file."""
    source, destination = Path(source).resolve(strict=True), Path(destination)
    try:
        descriptor = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        raise ValueError("Backup destination must be new") from None
    os.close(descriptor)
    try:
        with closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)) as origin:
            with closing(sqlite3.connect(destination)) as target:
                origin.backup(target, pages=128)
                if target.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    raise ValueError("Database backup validation failed")
    except BaseException:
        destination.unlink(missing_ok=True)
        raise


TAG_PRIORITY = 5  # queue floor for deterministic tag notices
POLL_TOLERANCE_SECONDS = 5  # absorbs scheduler start jitter after a successful poll


def source_due(state: dict, observed: str) -> bool:
    due = state.get("next_fetch_at")
    return not due or due <= observed


def item_priority(item: dict) -> int:
    words = (
        item["title"]
        + " "
        + item["content"][:1500]
        + " "
        + " ".join(item.get("labels", []))
    ).lower()
    score = sum(
        weight
        for word, weight in [
            ("compromis", 30),
            ("security", 15),
            ("attack", 10),
            ("denial", 10),
            ("dirauth", 8),
            ("released", 5),
        ]
        if word in words
    )
    return max(score, TAG_PRIORITY if item["kind"] == "tag" else 0)




class Store:
    def __init__(self, path: str | Path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if path.is_symlink():
            raise ValueError("Database must not be a symlink")
        self.db = sqlite3.connect(path, timeout=10)
        os.chmod(path, 0o600)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS source_state (
                id TEXT PRIMARY KEY, url TEXT NOT NULL, active_url TEXT, watermark TEXT,
                etag TEXT, last_modified TEXT, last_success TEXT, error TEXT,
                failures INTEGER NOT NULL DEFAULT 0, next_fetch_at TEXT
            );
            CREATE TABLE IF NOT EXISTS items (
                id TEXT PRIMARY KEY, url TEXT UNIQUE NOT NULL, source_id TEXT NOT NULL,
                payload TEXT NOT NULL, content_hash TEXT NOT NULL, cluster_key TEXT NOT NULL,
                first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at TEXT, last_error TEXT, priority_score INTEGER NOT NULL DEFAULT 0,
                story_id TEXT
            );
            CREATE INDEX IF NOT EXISTS items_pending ON items(status, next_attempt_at, priority_score);
            DROP INDEX IF EXISTS items_cluster;
            CREATE TABLE IF NOT EXISTS analyses (
                cache_key TEXT PRIMARY KEY, result TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS stories (
                id TEXT PRIMARY KEY, cluster_key TEXT UNIQUE NOT NULL, payload TEXT NOT NULL,
                published_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        """)
        monitoring.initialize(self.db)
        editorial.initialize(self.db)
        analysis_columns = {row[1] for row in self.db.execute("PRAGMA table_info(analyses)")}
        for name, kind in (("source_payload", "TEXT"), ("source_item_id", "TEXT"), ("input_chars", "INTEGER"), ("review_record", "TEXT")):
            if name not in analysis_columns:
                self.db.execute(f"ALTER TABLE analyses ADD COLUMN {name} {kind}")
        self.db.execute("CREATE INDEX IF NOT EXISTS analyses_source_snapshot ON analyses(source_item_id,created_at DESC,cache_key DESC)")
        if "rejections" not in {row[1] for row in self.db.execute("PRAGMA table_info(items)")}:
            self.db.execute("ALTER TABLE items ADD COLUMN rejections INTEGER NOT NULL DEFAULT 0")
        self.db.commit()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *args) -> None:
        self.db.close()

    def source(self, source: dict) -> dict:
        row = self.db.execute(
            "SELECT * FROM source_state WHERE id=?", (source["id"],)
        ).fetchone()
        if row and row["url"] == source["url"]:
            return dict(row)
        with self.db:
            self.db.execute("DELETE FROM source_state WHERE id=?", (source["id"],))
            self.db.execute(
                "INSERT INTO source_state(id,url) VALUES(?,?)",
                (source["id"], source["url"]),
            )
        return dict(
            self.db.execute(
                "SELECT * FROM source_state WHERE id=?", (source["id"],)
            ).fetchone()
        )

    def source_success(
        self,
        source: dict,
        result: dict,
        observed: str,
        *,
        schedule_from: str | None = None,
    ) -> None:
        with self.db:
            self.db.execute(
                """UPDATE source_state SET active_url=?, watermark=COALESCE(?,watermark),
                etag=?,last_modified=?,last_success=?,error=NULL,failures=0,next_fetch_at=?
                WHERE id=?""",
                (
                    result.get("url"),
                    result.get("watermark"),
                    result.get("etag"),
                    result.get("last_modified"),
                    observed,
                    # Only a success is rescheduled slightly early: failure and
                    # catching-up cooldowns are never shortened.
                    after(source["interval_seconds"] - min(POLL_TOLERANCE_SECONDS, source["interval_seconds"] / 10),
                          schedule_from or observed),
                    source["id"],
                ),
            )

    def source_failure(
        self,
        source: dict,
        error: str,
        collection: dict,
        observed: str,
        watermark: str | None = None,
        catching_up: bool = False,
    ) -> None:
        state = self.source(source)
        failures = state["failures"] + 1
        delay = (
            source["interval_seconds"]
            if catching_up
            else backoff_seconds(
                failures,
                collection["failure_backoff_base_seconds"],
                collection["failure_backoff_cap_seconds"],
            )
        )
        fields = {
            "failures": 0 if catching_up else failures,
            "error": error[:160],
            "next_fetch_at": after(delay, observed),
        }
        if watermark:  # a GitLab scan resumes from the last row it saw
            fields["watermark"] = watermark
        # Column names are only the literal keys above, never source data.
        assignments = ",".join(f"{name}=?" for name in fields)
        with self.db:
            self.db.execute(
                f"UPDATE source_state SET {assignments} WHERE id=?",
                (*fields.values(), source["id"]),
            )

    def ingest(self, item: dict, observed: str) -> bool:
        item_id = digest(item_identity(item))[:24]
        item["id"] = item_id
        content_hash = digest(
            {
                k: item.get(k)
                for k in (
                    "title",
                    "content",
                    "kind",
                    "product",
                    "labels",
                    "authority",
                    "upstream_state",
                )
            }
        )
        cluster = item_cluster(item)
        row = self.db.execute(
            "SELECT content_hash,payload FROM items WHERE id=?", (item_id,)
        ).fetchone()
        if row and row["content_hash"] == content_hash:
            # An upstream updated_at edit alone is not a new news event.
            return False
        if row and item["updated_at"] < json.loads(row["payload"])["updated_at"]:
            # A stale cache/fallback must not roll a newer incident back in time.
            return False
        score = item_priority(item)
        with self.db:
            self.db.execute(
                """INSERT INTO items(id,url,source_id,payload,content_hash,cluster_key,first_seen,last_seen,priority_score)
                VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
                url=excluded.url,source_id=excluded.source_id,payload=excluded.payload,content_hash=excluded.content_hash,
                cluster_key=excluded.cluster_key,last_seen=excluded.last_seen,status='pending',attempts=0,rejections=0,
                next_attempt_at=NULL,last_error=NULL,priority_score=excluded.priority_score""",
                (
                    item_id,
                    item["url"],
                    item["source_id"],
                    json.dumps(item, ensure_ascii=False),
                    content_hash,
                    cluster,
                    observed,
                    observed,
                    score,
                ),
            )
        return True

    def pending(self, limit: int, observed: str) -> list[dict]:
        rows = self.db.execute(
            """SELECT * FROM items WHERE status='pending'
            AND (next_attempt_at IS NULL OR next_attempt_at<=?)
            ORDER BY priority_score DESC,last_seen DESC,id LIMIT ?""",
            (observed, limit),
        )
        return [dict(row) for row in rows]

    def pending_count(self) -> int:
        return self.db.execute(
            "SELECT COUNT(*) FROM items WHERE status='pending'"
        ).fetchone()[0]

    def defer(self, item_id: str, error: str, llm: dict, observed: str, *, terminal: bool = False) -> None:
        """Retry later; after three failures caused by the item itself, stop retrying.

        A rejected item is queued again only when its source content changes.
        """
        row = self.db.execute(
            "SELECT attempts, rejections FROM items WHERE id=? AND status='pending'", (item_id,)
        ).fetchone()
        if row is None:
            return
        attempts, rejections = row[0] + 1, row[1] + terminal
        delay = backoff_seconds(
            attempts, llm["retry_base_seconds"], llm["retry_cap_seconds"]
        )
        with self.db:
            self.db.execute(
                "UPDATE items SET status=?,attempts=?,rejections=?,last_error=?,next_attempt_at=? "
                "WHERE id=? AND status='pending'",
                ("rejected" if rejections >= 3 else "pending",
                 attempts, rejections, error[:160], after(delay, observed), item_id),
            )

    def rejected_count(self) -> int:
        return self.db.execute("SELECT COUNT(*) FROM items WHERE status='rejected'").fetchone()[0]

    def record_analysis(self, row: dict, result: dict, cache_key: str, observed: str, *,
                        input_chars: int | None = None, review_record: dict | None = None) -> str:
        """Append immutable private evidence; the caller owns the transaction."""
        result_json = json.dumps(result, ensure_ascii=False, sort_keys=True, allow_nan=False)
        record_json = json.dumps(review_record, ensure_ascii=False, sort_keys=True, allow_nan=False) if review_record is not None else None
        values = (result_json, row["payload"], row["id"], input_chars, record_json)
        previous = self.db.execute("SELECT result,source_payload,source_item_id,input_chars,review_record FROM analyses WHERE cache_key=?", (cache_key,)).fetchone()
        if previous is not None:
            if tuple(previous) == values:
                return cache_key
            cache_key = digest(["analysis-audit", cache_key, values, observed])
        self.db.execute("""INSERT OR IGNORE INTO analyses
            (cache_key,result,created_at,source_payload,source_item_id,input_chars,review_record)
            VALUES(?,?,?,?,?,?,?)""", (cache_key, result_json, observed, row["payload"], row["id"], input_chars, record_json))
        return cache_key

    def prepare_candidate(self, row: dict, result: dict, observed: str, *, input_chars: int | None = None,
                          review_settings: dict | None = None) -> dict:
        return candidate.prepare(self.db, row, result, observed, input_chars=input_chars, review_settings=review_settings)

    def _clear_review_job(self, item_id: str) -> None:
        if self.db.execute("SELECT 1 FROM sqlite_master WHERE name='review_jobs' AND type='table'").fetchone():
            self.db.execute("DELETE FROM review_jobs WHERE item_id=?", (item_id,))

    def commit_candidate(self, prepared: dict, approved_candidate: dict | None, cache_key: str, observed: str, *,
                         approval_key: str | None = None, policy_hash: str | None = None,
                         review_record: dict | None = None) -> dict:
        """Publish the approved bytes after CAS checks, without merging again."""
        if self.db.in_transaction:
            raise ValueError("Candidate commit requires a fresh transaction")
        self.db.execute("BEGIN IMMEDIATE")
        with self.db:
            candidate.assert_current(self.db, prepared)
            binding = prepared["binding"]
            if (digest(binding) != prepared["binding_hash"] or digest(prepared["packet"]) != prepared["source_hash"]
                    or digest(prepared["candidate"]) != prepared["candidate_hash"]
                    or binding["candidate_hash"] != prepared["candidate_hash"] or binding["packet_hash"] != prepared["source_hash"]
                    or digest(prepared["payload"]) != binding["payload_hash"]):
                raise StaleCandidate("Prepared candidate or evidence changed after assembly")
            row, result = prepared["row"], prepared["result"]
            existing = candidate.existing_story(self.db, row)
            story_id = existing["id"] if existing else digest(row["cluster_key"])[:24]
            cluster = existing["cluster_key"] if existing else row["cluster_key"]
            locked = editorial.is_locked(self.db, story_id)
            payload = None
            if result["publish"] and not locked:
                original = prepared["candidate"]
                if not isinstance(approved_candidate, dict) or set(approved_candidate) != set(original):
                    raise ReviewRequired("Approval must identify the complete public candidate")
                if any(approved_candidate[key] != original[key] for key in original if key not in candidate.SEMANTIC_FIELDS):
                    raise ReviewRequired("Review cannot change story identity, sources, dates or editorial metadata")
                normalized = render._prepare_story(approved_candidate, editorial=original.get("editorial"))
                if normalized != approved_candidate:
                    raise ReviewRequired("The approved candidate must already be normalized")
                payload = json.loads(json.dumps(prepared["payload"]))
                if not candidate.wholly_deterministic(self.db, row, payload, approved_candidate):
                    if prepared["missing_sources"]:
                        raise ReviewRequired("Required source material is unavailable")
                    if not approval_key or not policy_hash or not self.db.execute("SELECT 1 FROM sqlite_master WHERE name='review_approvals'").fetchone():
                        raise ReviewRequired("Exact final candidate needs a recorded review approval")
                    receipt = self.db.execute("SELECT * FROM review_approvals WHERE key=?", (approval_key,)).fetchone()
                    if receipt is None or any(receipt[key] != expected for key, expected in (
                            ("candidate_hash", digest(approved_candidate)), ("source_hash", prepared["source_hash"]),
                            ("policy_hash", policy_hash), ("binding_hash", prepared["binding_hash"]))):
                        raise ReviewRequired("Review approval does not match this candidate and its sources")
                    from .review import validate_review
                    verdict = validate_review(json.loads(receipt["result_json"]), prepared["packet"])
                    if verdict["verdict"] != "approve":
                        raise ReviewRequired("Final review did not approve publication")
                    if review_record is None:
                        review_record = json.loads(receipt["review_record_json"])
                    self.db.execute("UPDATE review_approvals SET last_used_at=? WHERE key=?", (observed, approval_key))
                elif approved_candidate != original:
                    raise ReviewRequired("A deterministic notice cannot accept an unreviewed repair")
                payload.update({key: approved_candidate[key] for key in candidate.SEMANTIC_FIELDS})
                if existing is None:  # Date a new story when it is published, not when it was first drafted.
                    payload["added_at"] = observed
            if review_record is None and self.db.execute("SELECT 1 FROM sqlite_master WHERE name='review_jobs'").fetchone():
                job = self.db.execute("SELECT record_json FROM review_jobs WHERE item_id=?", (row["id"],)).fetchone()
                review_record = json.loads(job[0]) if job else None
            analysis_key = self.record_analysis(row, result, cache_key, observed,
                                                input_chars=prepared["input_chars"], review_record=review_record)
            if payload is not None:
                if payload.get("editorial_item") == row["id"]:
                    payload["editorial_analysis_key"] = analysis_key
                changed = self.db.execute("""INSERT INTO stories(id,cluster_key,payload,published_at,updated_at)
                    VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,updated_at=excluded.updated_at""",
                    (story_id, cluster, json.dumps(payload, ensure_ascii=False, allow_nan=False), payload["published_at"], payload["updated_at"]))
                if changed.rowcount != 1:
                    raise StaleCandidate("Story became editorially protected before publication")
            elif locked and result["publish"]:
                editorial.record_held(self.db, story_id, observed)
            mapped_id = story_id if result["publish"] else row.get("story_id")
            self.db.execute("UPDATE items SET status=?,story_id=?,next_attempt_at=NULL,last_error=NULL WHERE id=?",
                            ("published" if result["publish"] else "ignored", mapped_id, row["id"]))
            self._clear_review_job(row["id"])
        return {"story_id": mapped_id, "status": "locked" if locked and result["publish"] else "published" if result["publish"] else "ignored"}

    def finish(self, row: dict, result: dict, cache_key: str, observed: str, *, input_chars: int | None = None) -> None:
        """Only ignored, locked or wholly deterministic notices bypass review."""
        prepared = self.prepare_candidate(row, result, observed, input_chars=input_chars)
        if prepared["requires_review"]:
            raise ReviewRequired("Automatic publication requires the final review gate")
        self.commit_candidate(prepared, prepared["candidate"], cache_key, observed)

    def stories(self, limit: int = -1) -> list[dict]:
        """Stored stories, newest activity first (all of them by default)."""
        return [
            json.loads(row[0])
            for row in self.db.execute(
                "SELECT payload FROM stories ORDER BY updated_at DESC,id LIMIT ?",
                (limit,),
            )
        ]

    def ingest_alerts(self, source: dict, items: list[dict], observed: str) -> dict:
        return monitoring.ingest(self.db, source, items, observed)

    def story_count(self, limit: int = -1) -> int:
        return self.db.execute(
            "SELECT COUNT(*) FROM (SELECT 1 FROM stories LIMIT ?)", (limit,)
        ).fetchone()[0]

    def health(
        self, sources: list[dict], stale_seconds: int, observed: str
    ) -> list[dict]:
        """Read-only: a source without state for its current URL has not succeeded yet."""
        result = []
        for source in sources:
            if not source["enabled"]:
                continue
            row = self.db.execute(
                "SELECT url,last_success,error FROM source_state WHERE id=?", (source["id"],)
            ).fetchone()
            state = dict(row) if row and row["url"] == source["url"] else {"last_success": None, "error": None}
            stale = (
                not state["last_success"]
                or after(stale_seconds, state["last_success"]) < observed
            )
            result.append(
                {
                    "id": source["id"],
                    "name": source["name"],
                    "website_url": source.get("website_url"),
                    "last_success": state["last_success"],
                    "error": state["error"],
                    "stale": bool(stale),
                }
            )
        return result

    def get_meta(self, key: str) -> str | None:
        row = self.db.execute(
            "SELECT value FROM metadata WHERE key=?", (key,)
        ).fetchone()
        return row[0] if row else None

    def set_meta(self, **values: str) -> None:
        """Write one or more metadata values in a single transaction."""
        with self.db:
            self.db.executemany(
                "INSERT INTO metadata(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                values.items(),
            )

