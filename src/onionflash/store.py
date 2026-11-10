"""Durable collection, retry queue, analysis records, and stable story identities."""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path

from .util import after, backoff_seconds, canonical_url, digest, format_utc, item_cluster, item_identity, normalize_evidence, parse_utc
from . import editorial, monitoring


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


def _rank(kind: str, confidence: str, updated_at: str) -> tuple:
    return ({"tag": 0, "metrics_timeline": 1}.get(kind, 2), confidence == "confirmed", updated_at)


def _comment_sources(item: dict, result: dict, input_chars: int | None, observed: str) -> list[dict]:
    if type(input_chars) is not int or input_chars <= 0 or not item.get("public_comments"):
        return []
    from .comments import analysis_context, parse_note_id
    try:
        _, supplied = analysis_context(item, input_chars)
    except (ValueError, TypeError, KeyError, AttributeError):
        return []
    evidence = [normalize_evidence(quote) for quote in result.get("evidence", []) if isinstance(quote, str)]
    evidence = [quote for quote in evidence if len(quote) >= 8]
    sources = []
    for note in supplied:
        try:
            identifier = parse_note_id(note["id"])
            url = canonical_url(note["url"])
            if identifier is None or url != canonical_url(item["url"]).split("#", 1)[0] + "#note_" + identifier:
                continue
            body = normalize_evidence(note["body"])
            if not any(quote in body for quote in evidence):
                continue
            created = format_utc(parse_utc(note["created_at"]))
            updated = format_utc(parse_utc(note["updated_at"]))
            if not created <= updated <= observed:
                continue
            sources.append({"id": item["id"] + ":" + note["id"], "source_item_id": item["id"],
                            "url": url, "title": note["title"], "published_at": created, "updated_at": updated})
        except (KeyError, TypeError, ValueError, UnicodeError):
            continue
    return sources


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
        for name, kind in (("source_payload", "TEXT"), ("source_item_id", "TEXT"), ("input_chars", "INTEGER")):
            if name not in analysis_columns:
                self.db.execute(f"ALTER TABLE analyses ADD COLUMN {name} {kind}")
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

    def finish(self, row: dict, result: dict, cache_key: str, observed: str, *, input_chars: int | None = None) -> None:
        item = json.loads(row["payload"])
        with self.db:
            self.db.execute(
                """INSERT OR IGNORE INTO analyses
                (cache_key,result,created_at,source_payload,source_item_id,input_chars) VALUES(?,?,?,?,?,?)""",
                (cache_key, json.dumps(result, ensure_ascii=False), observed, row["payload"], row["id"], input_chars),
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
                if existing is not None and editorial.is_locked(self.db, story_id):
                    # Keep the new source analysis privately and its grouping
                    # relationship, but do not overwrite an operator decision.
                    editorial.record_held(self.db, story_id, observed)
                    self.db.execute("UPDATE items SET status='published',story_id=?,next_attempt_at=NULL,last_error=NULL WHERE id=?", (story_id, row["id"]))
                    return
                source = {
                    "id": item["id"],
                    "url": item["url"],
                    "title": item["title"],
                    "published_at": item["published_at"],
                }
                comments = _comment_sources(item, result, input_chars, observed)
                effective_updated = max([item["updated_at"], *(s["updated_at"] for s in comments)])
                source_map = {s["url"]: s for s in (previous or {}).get("sources", []) if s.get("id") != item["id"] and s.get("source_item_id") != item["id"]}
                source_map[source["url"]] = source
                source_map.update({comment["url"]: comment for comment in comments})
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
                data["editorial_kind"], data["editorial_item"] = item["kind"], item["id"]
                data["editorial_updated_at"] = effective_updated
                writer = (previous or {}).get("editorial_item")
                if previous and writer is None and len(previous.get("sources", [])) == 1:
                    writer = previous["sources"][0].get("id")  # an older story's only source wrote it
                if previous and writer != item["id"]:
                    # Another item already wrote this story. It keeps the text when it
                    # ranks higher: tag notice < Metrics timeline < primary report, then
                    # a confirmed account, then the newer item. The loser only adds a link.
                    kind = previous.get("editorial_kind") or ("tag" if previous["state"] == "tagged" else "")
                    stamp = previous.get("editorial_updated_at") or previous["updated_at"]
                    if _rank(kind, previous["confidence"], stamp) > _rank(
                        item["kind"], data["confidence"], effective_updated
                    ):
                        data = {key: previous.get(key) for key in data}
                        # Older stories lack the editorial fields; keep usable values.
                        data.update(editorial_kind=kind, editorial_item=writer, editorial_updated_at=stamp)
                data.update(
                    {
                        "id": story_id,
                        "sources": sorted(source_map.values(), key=lambda s: s["url"]),
                        "published_at": previous["published_at"]
                        if previous
                        else item["published_at"],
                        "added_at": previous.get("added_at", previous["published_at"])
                        if previous
                        else observed,
                        "updated_at": max(
                            effective_updated,
                            previous["updated_at"]
                            if previous
                            else item["published_at"],
                        ),
                    }
                )
                # Keep the story's first published_at. The private evidence stays in
                # analyses; only selected fields go public.
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

