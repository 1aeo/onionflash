"""Durable collection, retry queue, analysis cache, and stable story identities."""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path

from .util import after, backoff_seconds, digest, item_cluster


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


def source_due(source: dict, state: dict, collection: dict, observed: str) -> bool:
    """Forgive small scheduler skew only after a completed successful poll."""
    due = state.get("next_fetch_at")
    if not due or due <= observed:
        return True
    healthy = (
        bool(state.get("last_success"))
        and state.get("error") is None
        and not state.get("failures")
        and not state.get("scan_upper")
        and not state.get("scan_page")
    )
    if not healthy:
        return False
    tolerance = min(
        collection["healthy_poll_tolerance_seconds"], source["interval_seconds"] / 10
    )
    return after(tolerance, observed) >= due


def item_priority(item: dict, tag_priority_score: int = 5) -> int:
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
    return max(score, tag_priority_score if item["kind"] == "tag" else 0)


class Store:
    def __init__(self, path: str | Path):
        path = Path(path)
        self.path = path.absolute()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if path.is_symlink():
            raise ValueError("Database must not be a symlink")
        self.db = sqlite3.connect(path, timeout=10)
        os.chmod(path, 0o600)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA busy_timeout=10000")
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
            CREATE INDEX IF NOT EXISTS items_cluster ON items(cluster_key);
            CREATE TABLE IF NOT EXISTS analyses (
                cache_key TEXT PRIMARY KEY, result TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS stories (
                id TEXT PRIMARY KEY, cluster_key TEXT UNIQUE NOT NULL, payload TEXT NOT NULL,
                published_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        """)
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(source_state)")}
        for name, kind in [
            ("scan_lower", "TEXT"),
            ("scan_upper", "TEXT"),
            ("scan_page", "INTEGER"),
            ("scan_cursor", "TEXT"),
            ("scan_reconcile", "INTEGER"),
            ("last_reconciled", "TEXT"),
        ]:
            if name not in columns:
                self.db.execute(f"ALTER TABLE source_state ADD COLUMN {name} {kind}")
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
                etag=?,last_modified=?,last_success=?,error=NULL,failures=0,next_fetch_at=?,
                scan_lower=NULL,scan_upper=NULL,scan_page=NULL,scan_cursor=NULL,scan_reconcile=NULL,
                last_reconciled=CASE WHEN ? THEN ? ELSE last_reconciled END WHERE id=?""",
                (
                    result.get("url"),
                    result.get("watermark"),
                    result.get("etag"),
                    result.get("last_modified"),
                    observed,
                    after(source["interval_seconds"], schedule_from or observed),
                    bool(result.get("reconciled")),
                    result.get("watermark"),
                    source["id"],
                ),
            )

    def source_failure(
        self,
        source: dict,
        error: str,
        collection: dict,
        observed: str,
        checkpoint: dict | None = None,
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
        if checkpoint:
            fields.update({
                "scan_lower": checkpoint["lower"],
                "scan_upper": checkpoint["upper"],
                "scan_page": checkpoint["page"],
                "scan_cursor": checkpoint.get("cursor"),
                "scan_reconcile": bool(checkpoint.get("reconcile")),
            })
        # Column names are only the literal keys above, never source data.
        assignments = ",".join(f"{name}=?" for name in fields)
        with self.db:
            self.db.execute(
                f"UPDATE source_state SET {assignments} WHERE id=?",
                (*fields.values(), source["id"]),
            )

    def ingest(self, item: dict, observed: str, *, tag_priority_score: int = 5) -> bool:
        item_id = digest(item["url"])[:24]
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
        score = item_priority(item, tag_priority_score)
        with self.db:
            self.db.execute(
                """INSERT INTO items(id,url,source_id,payload,content_hash,cluster_key,first_seen,last_seen,priority_score)
                VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
                source_id=excluded.source_id,payload=excluded.payload,content_hash=excluded.content_hash,
                cluster_key=excluded.cluster_key,last_seen=excluded.last_seen,status='pending',attempts=0,
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

    def cached(self, cache_key: str) -> dict | None:
        row = self.db.execute(
            "SELECT result FROM analyses WHERE cache_key=?", (cache_key,)
        ).fetchone()
        return json.loads(row[0]) if row else None

    def defer(self, item_id: str, error: str, llm: dict, observed: str) -> None:
        row = self.db.execute(
            "SELECT attempts FROM items WHERE id=? AND status='pending'", (item_id,)
        ).fetchone()
        if row is None:
            return
        attempts = row[0] + 1
        delay = backoff_seconds(
            attempts, llm["retry_base_seconds"], llm["retry_cap_seconds"]
        )
        with self.db:
            self.db.execute(
                "UPDATE items SET attempts=?,last_error=?,next_attempt_at=? WHERE id=? AND status='pending'",
                (attempts, error[:160], after(delay, observed), item_id),
            )

    def finish(self, row: dict, result: dict, cache_key: str, observed: str) -> None:
        item = json.loads(row["payload"])
        with self.db:
            self.db.execute(
                "INSERT OR IGNORE INTO analyses(cache_key,result,created_at) VALUES(?,?,?)",
                (cache_key, json.dumps(result, ensure_ascii=False), observed),
            )
            story_id = row.get("story_id")
            if result["publish"]:
                existing = None
                if story_id:
                    existing = self.db.execute(
                        "SELECT * FROM stories WHERE id=?", (story_id,)
                    ).fetchone()
                if existing is None:
                    existing = self.db.execute(
                        "SELECT * FROM stories WHERE cluster_key=?",
                        (row["cluster_key"],),
                    ).fetchone()
                previous = json.loads(existing["payload"]) if existing else None
                story_id = (
                    existing["id"] if existing else digest(row["cluster_key"])[:24]
                )
                source = {
                    "id": item["id"],
                    "url": item["url"],
                    "title": item["title"],
                    "published_at": item["published_at"],
                }
                source_map = {s["url"]: s for s in (previous or {}).get("sources", [])}
                source_map[source["url"]] = source
                data = {
                    key: result[key]
                    for key in (
                        "title",
                        "summary",
                        "why_it_matters",
                        "category",
                        "products",
                        "priority",
                        "confidence",
                        "state",
                        "tags",
                    )
                }
                if previous and (
                    item["updated_at"] < previous["updated_at"]
                    or (item["kind"] == "tag" and previous["state"] != "tagged")
                ):
                    # A newly discovered older mirror adds corroborating links, not an
                    # editorial rollback. The evidence still remains in the private cache.
                    data = {key: previous[key] for key in data}
                if previous:
                    data["products"] = sorted(
                        set(data["products"]) | set(previous["products"])
                    )
                data.update(
                    {
                        "id": story_id,
                        "sources": sorted(source_map.values(), key=lambda s: s["url"]),
                        "published_at": previous["published_at"]
                        if previous
                        else item["published_at"],
                        "updated_at": max(
                            item["updated_at"],
                            previous["updated_at"]
                            if previous
                            else item["published_at"],
                        ),
                    }
                )
                # Keep the earliest already-published timestamp, including across mirrors.
                # The private evidence remains in analyses; only selected fields go public.
                cluster = existing["cluster_key"] if existing else row["cluster_key"]
                self.db.execute(
                    """INSERT INTO stories(id,cluster_key,payload,published_at,updated_at) VALUES(?,?,?,?,?)
                    ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,updated_at=excluded.updated_at""",
                    (
                        story_id,
                        cluster,
                        json.dumps(data, ensure_ascii=False),
                        data["published_at"],
                        data["updated_at"],
                    ),
                )
            self.db.execute(
                "UPDATE items SET status=?,story_id=?,next_attempt_at=NULL,last_error=NULL WHERE id=?",
                ("published" if result["publish"] else "ignored", story_id, row["id"]),
            )

    def stories(self, limit: int) -> list[dict]:
        return [
            json.loads(row[0])
            for row in self.db.execute(
                "SELECT payload FROM stories ORDER BY updated_at DESC,id LIMIT ?",
                (limit,),
            )
        ]

    def story_count(self, limit: int) -> int:
        return self.db.execute(
            "SELECT COUNT(*) FROM (SELECT 1 FROM stories LIMIT ?)", (limit,)
        ).fetchone()[0]

    def health(
        self, sources: list[dict], stale_seconds: int, observed: str
    ) -> list[dict]:
        result = []
        for source in sources:
            if not source["enabled"]:
                continue
            state = self.source(source)
            stale = (
                not state["last_success"]
                or after(stale_seconds, state["last_success"]) < observed
            )
            result.append(
                {
                    "id": source["id"],
                    "name": source["name"],
                    "website_url": source.get("website_url", source["url"]),
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

    def set_meta(self, key: str, value: str) -> None:
        with self.db:
            self.db.execute(
                "INSERT INTO metadata(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    def backup(self, destination: str | Path) -> None:
        backup_database(self.path, destination)
