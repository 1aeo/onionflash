"""Durable collection, retry queue, analysis records, and stable story identities."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from contextlib import closing, contextmanager
import copy
from itertools import islice
import json
import logging
import os
from pathlib import Path
import re
import sqlite3

from . import candidate, decisions, doctor, editorial, publication, render
from .candidate import ReviewRequired, item_source
from .comments import analysis_context
from .util import (
    after, backoff_until, canonical_json, digest, is_dirauth_item, is_hackerone_item,
    is_pt_high_impact, is_tor_core_item, is_trove_item, item_cluster, item_identity,
    safe_canonical_url, saved_object, strict_json, valid_note_list,
)

TAG_PRIORITY = 5  # queue floor for deterministic tag notices
TRUSTED_OPERATOR_PRIORITY = 15  # queue boost for verified large AROI relay-family operators
PT_SECURITY_PRIORITY = 20  # queue boost for high-impact pluggable-transport reports
TOR_CORE_PRIORITY = 25  # queue boost for core Tor Project GitLab contributors
HACKERONE_PRIORITY = 35  # queue boost so HackerOne disclosures run ahead of ordinary items
DIRAUTH_PRIORITY = 35  # queue boost so directory-authority tickets and replies run first
TROVE_PRIORITY = 40  # queue boost so verified TROVE advisories run ahead of ordinary items
POLL_TOLERANCE_SECONDS = 5  # absorbs scheduler start jitter after a successful poll
MIN_REFRESH_UPDATES = 3
MIN_NEW_UPDATES_FOR_REFRESH = 2

_RETENTION_TABLES = {"item": ("items", "id"), "analysis": ("analyses", "cache_key")}
_RETENTION_SCHEMA = """
    CREATE TABLE IF NOT EXISTS private_archive_refs (
        kind TEXT NOT NULL, record_id TEXT NOT NULL, record_hash TEXT NOT NULL,
        object_key TEXT NOT NULL, object_sha256 TEXT NOT NULL,
        archived_at TEXT NOT NULL, destination_json TEXT NOT NULL,
        PRIMARY KEY(kind, record_id, record_hash)
    );
    CREATE INDEX IF NOT EXISTS retention_items_age ON items(last_seen,id) WHERE status='ignored' AND story_id IS NULL;
    CREATE INDEX IF NOT EXISTS retention_analyses_age ON analyses(created_at,cache_key);
"""
_RETENTION_QUERIES = (
    ("item", """SELECT rowid,CAST(id AS BLOB) FROM items INDEXED BY retention_items_age
        WHERE status='ignored' AND story_id IS NULL AND last_seen<?
        AND CASE WHEN typeof(payload)='text' AND json_valid(payload) THEN json_type(payload)='object'
            AND json_extract(payload,'$.kind') IS NOT 'gitlab_issue' END
        AND NOT EXISTS (SELECT 1 FROM private_archive_refs a WHERE a.kind='item'
            AND a.record_id=items.id AND a.record_hash=items.content_hash)
        ORDER BY last_seen,id"""),
    ("analysis", """SELECT rowid,CAST(cache_key AS BLOB) FROM analyses INDEXED BY retention_analyses_age
        WHERE created_at<?
        AND NOT EXISTS (SELECT 1 FROM items i WHERE i.id=analyses.source_item_id
            AND (i.status!='ignored' OR i.story_id IS NOT NULL))
        ORDER BY created_at,cache_key"""),
)


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


def get_meta(db, key: str, default: str | None = None) -> str | None:
    """Read one metadata value by key, or return `default` when absent."""
    row = db.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
    return row[0] if row is not None else default


def set_meta(db, **values: str) -> None:
    """Upsert one or more key-value entries in the metadata table."""
    db.executemany(
        "INSERT INTO metadata(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        values.items(),
    )


def bump_meta(db, key: str) -> int:
    """Increment an integer counter in metadata and return its new value."""
    value = int(get_meta(db, key) or 0) + 1
    set_meta(db, **{key: str(value)})
    return value


@contextmanager
def immediate_transaction(db, busy_message: str = "Database transaction already active"):
    """Run a block inside a `BEGIN IMMEDIATE` write transaction."""
    if db.in_transaction:
        raise ValueError(busy_message)
    db.execute("BEGIN IMMEDIATE")
    with db:
        yield


ITEM_SAFE_COLUMNS = (
    "id,url,source_id,content_hash,cluster_key,first_seen,last_seen,status,attempts,"
    "rejections,next_attempt_at,last_error,priority_score,story_id,"
    "typeof(payload) AS _payload_type,CAST(payload AS BLOB) AS _payload_blob"
)


def decode_item_row(row) -> tuple[dict | None, dict | None]:
    """Decode a UTF-8-safe `ITEM_SAFE_COLUMNS` row into `(entry_dict, payload_dict)` or `(None, None)`."""
    if row is None or row["_payload_type"] != "text" or (payload := saved_object(row["_payload_blob"])) is None:
        return None, None
    entry = {k: row[k] for k in row.keys() if not k.startswith("_")}
    entry["payload"] = str(row["_payload_blob"], "utf-8")
    return entry, payload


def set_job_stage(db, item_id: str, stage: str, record: object, observed: str) -> int:
    """Update an existing review job's stage, serialized audit record, and timestamp."""
    return db.execute(
        "UPDATE review_jobs SET stage=?,record_json=?,approval_key=NULL,updated_at=? WHERE item_id=?",
        (stage, strict_json(record), observed, item_id),
    ).rowcount


def upsert_story(db, story_id: str, cluster_key: str, payload_json: str, published_at: str, updated_at: str) -> int:
    """Insert a story or update its payload and `updated_at` in place, returning `rowcount`."""
    return db.execute(
        "INSERT INTO stories(id,cluster_key,payload,published_at,updated_at) VALUES(?,?,?,?,?)"
        " ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,updated_at=excluded.updated_at",
        (story_id, cluster_key, payload_json, published_at, updated_at),
    ).rowcount


def _table_columns(db, table: str) -> list[str]:
    return [info[1] for info in db.execute(f"PRAGMA table_info({table})")]


def retained_analysis_keys(db) -> set[str]:
    """Return analysis cache keys referenced by live stories and not safe to evict."""
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='stories'").fetchone():
        return set()
    pinned: set[str] = set()
    for (raw,) in db.execute("SELECT CAST(payload AS BLOB) FROM stories WHERE typeof(payload)='text'"):
        if (payload := saved_object(raw)) and isinstance(payload.get("editorial_analysis_key"), str):
            pinned.add(payload["editorial_analysis_key"])
    return pinned


def _decode_table_row(db, table: str, columns: list[str], where: str, param, *, key_col: str) -> dict | None:
    expr = ",".join(
        f'typeof("{c}"),CAST("{c}" AS BLOB),CASE WHEN typeof("{c}") IN (\'integer\',\'real\') THEN "{c}" END'
        for c in columns
    )
    raw = db.execute(f'SELECT {expr} FROM "{table}" WHERE {where}', (param,)).fetchone()
    if raw is None:
        return None
    decoded = {}
    for index, name in enumerate(columns):
        kind, blob, number = raw[index * 3 : index * 3 + 3]
        if kind == "null":
            decoded[name] = None
        elif kind in ("integer", "real"):
            decoded[name] = number
        elif kind == "text":
            decoded[name] = str(blob, "utf-8")
        else:
            raise ValueError(f"Unexpected {kind} column {name}")
    if not isinstance(decoded.get(key_col), str):
        raise ValueError(f"Missing string {key_col}")
    canonical_json(decoded).encode("utf-8")
    if table == "items":
        canonical_json(json.loads(decoded["payload"])).encode("utf-8")
    return decoded


def select_retention_candidates(
    db,
    *,
    cutoff: str,
    batch_size: int,
    max_bundle_bytes: int,
    base_overhead: int,
    record_overhead: Callable[[dict], int] | None = None,
    logger: logging.Logger | None = None,
) -> tuple[list[dict], int]:
    """Select one bounded batch of cold private item and analysis rows safe to archive."""
    log = logger or logging.getLogger("onionflash.deploy")
    db.executescript(_RETENTION_SCHEMA)
    pinned_keys = retained_analysis_keys(db)
    records: list[dict] = []
    over_limit = 0
    size = base_overhead

    def scan(kind: str, query: str):
        """Stream decoded cold item or analysis rows eligible for archival."""
        table, key_col = _RETENTION_TABLES[kind]
        columns = _table_columns(db, table)
        for rowid, raw_key in db.execute(query, (cutoff,)):
            try:
                key = raw_key.decode("utf-8") if isinstance(raw_key, bytes) else raw_key
                if kind == "analysis" and key in pinned_keys:
                    continue
                row = _decode_table_row(db, table, columns, "rowid=?", rowid, key_col=key_col)
            except (UnicodeError, ValueError, RecursionError) as error:
                label = raw_key.decode("utf-8", errors="replace") if isinstance(raw_key, bytes) else raw_key
                log.warning("Skipping damaged retention %s %r (%s)", kind, label, type(error).__name__)
                continue
            if row is not None:
                yield row

    for kind, query in _RETENTION_QUERIES:
        for row in islice(scan(kind, query), batch_size - len(records)):
            record = {"kind": kind, "row": dict(row)}
            amount = record_overhead(record) if record_overhead is not None else len(canonical_json(record).encode("utf-8")) + 1
            if size + amount > max_bundle_bytes:
                over_limit += 1
                continue
            size += amount
            records.append(record)
    return records, over_limit


def compact_retained_rows(
    db,
    records: list[dict],
    *,
    uploaded_key: str,
    uploaded_sha256: str,
    archived_at: str,
    destination_json: str,
) -> dict:
    """Record private archive locators and compact/evict rows unchanged since selection."""
    counts = {"records_archived": 0, "items_compacted": 0, "analyses_evicted": 0, "changed_records_preserved": 0}
    with immediate_transaction(db):
        pinned_keys = retained_analysis_keys(db)
        cols_by_kind = {kind: _table_columns(db, table) for kind, (table, _) in _RETENTION_TABLES.items()}
        for record in records:
            kind, row = record["kind"], record["row"]
            table, key_col = _RETENTION_TABLES[kind]
            try:
                current = _decode_table_row(db, table, cols_by_kind[kind], f"{key_col}=?", row[key_col], key_col=key_col)
            except (UnicodeError, ValueError, RecursionError):
                current = None
            if current is None or current != row:
                counts["changed_records_preserved"] += 1
                continue
            if kind == "analysis" and (
                row["cache_key"] in pinned_keys
                or (row.get("source_item_id") and db.execute(
                    "SELECT 1 FROM items WHERE id=? AND (status!='ignored' OR story_id IS NOT NULL)",
                    (row["source_item_id"],),
                ).fetchone())
            ):
                counts["changed_records_preserved"] += 1
                continue
            record_hash = row["content_hash"] if kind == "item" else digest(row)
            db.execute(
                "INSERT INTO private_archive_refs VALUES(?,?,?,?,?,?,?) ON CONFLICT DO NOTHING",
                (kind, row[key_col], record_hash, uploaded_key, uploaded_sha256, archived_at, destination_json),
            )
            if kind == "item":
                payload = json.loads(row["payload"])
                if payload.pop("content", None) is not None:
                    db.execute("UPDATE items SET payload=? WHERE id=?", (json.dumps(payload, ensure_ascii=False), row["id"]))
                    counts["items_compacted"] += 1
            else:
                db.execute("DELETE FROM analyses WHERE cache_key=?", (row["cache_key"],))
                counts["analyses_evicted"] += 1
            counts["records_archived"] += 1
    return counts


def source_due(state: dict, observed: str) -> bool:
    """Return whether a source's next scheduled fetch time has arrived."""
    due = state.get("next_fetch_at")
    return not due or due <= observed


def story_refresh_hash(payload: dict) -> str:
    """Return a stable digest of a story's accumulated updates and source citations."""
    return digest({"updates": payload.get("updates") or [], "sources": payload.get("sources") or []})


def item_priority(
    item: dict,
    dirauth_users: Iterable[str] | None = None,
    tor_core_users: Iterable[str] | None = None,
) -> int:
    """Score a collected item so TROVE, HackerOne, directory-authority, Tor-core and security reports run first."""
    words = (item["title"] + " " + item["content"][:1500] + " " + " ".join(item.get("labels", []))).lower()
    score = sum(
        weight
        for word, weight in [("compromis", 30), ("security", 15), ("attack", 10), ("denial", 10), ("dirauth", 8), ("released", 5)]
        if word in words
    )
    if is_trove_item(item):
        score += TROVE_PRIORITY
    if is_hackerone_item(item):
        score += HACKERONE_PRIORITY
    if is_pt_high_impact(item):
        score += PT_SECURITY_PRIORITY
    if is_dirauth_item(item, dirauth_users):
        score += DIRAUTH_PRIORITY
    elif is_tor_core_item(item, tor_core_users):
        score += TOR_CORE_PRIORITY
    elif item.get("authority") == "trusted-operator":
        score += TRUSTED_OPERATOR_PRIORITY
    return max(score, TAG_PRIORITY if item["kind"] == "tag" else 0)


def _valid_saved_item(old: object) -> bool:
    if not isinstance(old, dict) or not all(isinstance(old.get(k), str) for k in ("title", "content", "updated_at")):
        return False
    if "source_content" in old and not isinstance(old["source_content"], str):
        return False
    if any(old.get(k) is not None and not isinstance(old[k], str) for k in ("author", "sender_domain")):
        return False
    if "comments_truncated" in old and type(old["comments_truncated"]) is not bool:
        return False
    labels = old.get("labels")
    if labels is not None and (not isinstance(labels, list) or any(not isinstance(entry, str) for entry in labels)):
        return False
    return (
        valid_note_list(old.get("public_comments"), ("id", "url", "title", "author", "created_at", "body"))
        and valid_note_list(old.get("dirauth_notes"), ("id", "author", "created_at"))
    )


def _valid_pending_payload(entry: dict | None, payload: dict | None) -> bool:
    return (
        entry is not None
        and _valid_saved_item(payload)
        and all(isinstance(payload.get(k), str) and bool(payload[k]) for k in ("id", "url", "kind", "published_at"))
        and payload["id"] == entry["id"]
        and payload["url"] == entry["url"]
    )


def _is_compacted_saved_item(db, item_id: str, row, old: object) -> bool:
    if isinstance(row, str):
        record_hash = row
    else:
        if row["status"] != "ignored" or row["story_id"] is not None:
            return False
        record_hash = row["content_hash"]
    if not isinstance(old, dict) or "content" in old or not isinstance(record_hash, str) or not _valid_saved_item({**old, "content": ""}):
        return False
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='private_archive_refs'").fetchone():
        return False
    return bool(db.execute(
        """SELECT 1 FROM private_archive_refs
           WHERE kind='item' AND record_id=? AND record_hash=?
           AND typeof(object_key)='text' AND object_key!=''
           AND typeof(object_sha256)='text' AND length(object_sha256)=64
           AND typeof(archived_at)='text' AND archived_at!=''
           AND typeof(destination_json)='text' AND json_valid(destination_json)
           AND json_type(destination_json)='object'""",
        (item_id, record_hash),
    ).fetchone())


def item_hash_fields(item: dict, *, include_sender_domain: bool = True) -> dict:
    """Build the canonical field mapping hashed by `item_hash` for `item`."""
    fields = {k: item.get(k) for k in ("title", "content", "kind", "product", "labels", "authority", "upstream_state")}
    fields["content"] = item.get("source_content", item.get("content"))
    if item.get("author"):
        fields["author"] = item["author"]
    if include_sender_domain and item.get("sender_domain"):
        fields["sender_domain"] = item["sender_domain"]
    if item.get("public_comments"):
        fields["public_comments"] = analysis_context(item)[1]
    return fields


def item_hash(item: dict) -> str:
    """A digest of the fields that make a new revision of an item."""
    return digest(item_hash_fields(item))


def _uncommented_hash(old: dict, item: dict) -> str:
    base_old = {k: v for k, v in old.items() if k not in {"public_comments", "dirauth_notes", "comments_truncated"}}
    if base_old.get("authority") in {"dirauth-operator", "tor-core"} and item.get("authority") == "development":
        base_old["authority"] = "development"
    return item_hash(base_old)


def _unchanged_non_pending(target: dict, item: dict, content_hash: str, *, check_requested: bool) -> bool:
    return (check_requested and item_hash(target) == content_hash) or (
        "comments_source_key" not in item
        and (target.get("public_comments") or target.get("dirauth_notes"))
        and _uncommented_hash(target, item) == content_hash
    )


def _updated_closed_at(old: dict, item: dict) -> str | None:
    closed_at = item.get("closed_at")
    if (
        item.get("kind") == "gitlab_issue"
        and item.get("upstream_state") == "closed"
        and isinstance(closed_at, str)
        and closed_at
        and isinstance(item.get("updated_at"), str)
        and item["updated_at"] >= old["updated_at"]
        and (closed_at != old.get("closed_at") or item["updated_at"] > old["updated_at"])
    ):
        return closed_at
    return None


class Store:
    """SQLite state store for sources, queued items, analyses and published stories."""

    def __init__(
        self,
        path: str | Path,
        *,
        dirauth_users: Iterable[str] | None = None,
        tor_core_users: Iterable[str] | None = None,
    ):
        """Open persistent state and apply idempotent schema maintenance before use."""
        self.dirauth_users = tuple(dirauth_users) if dirauth_users is not None else None
        self.tor_core_users = tuple(tor_core_users) if tor_core_users is not None else None
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
                rejections INTEGER NOT NULL DEFAULT 0,
                next_attempt_at TEXT, last_error TEXT, priority_score INTEGER NOT NULL DEFAULT 0,
                story_id TEXT
            );
            CREATE INDEX IF NOT EXISTS items_pending ON items(status, next_attempt_at, priority_score);
            DROP INDEX IF EXISTS items_cluster;
            CREATE INDEX IF NOT EXISTS items_cluster_story ON items(cluster_key) WHERE story_id IS NOT NULL;
            CREATE TABLE IF NOT EXISTS analyses (
                cache_key TEXT PRIMARY KEY, result TEXT NOT NULL, created_at TEXT NOT NULL,
                source_payload TEXT, source_item_id TEXT, review_record TEXT
            );
            CREATE TABLE IF NOT EXISTS stories (
                id TEXT PRIMARY KEY, cluster_key TEXT UNIQUE NOT NULL, payload TEXT NOT NULL,
                published_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS story_refreshes (
                story_id TEXT PRIMARY KEY, last_refreshed_at TEXT NOT NULL,
                update_count INTEGER NOT NULL DEFAULT 0, refreshed_hash TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'refreshed'
            );
            CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS comment_cache (
                item_id TEXT PRIMARY KEY, source_key TEXT NOT NULL, checked_at TEXT NOT NULL,
                next_fetch_at TEXT NOT NULL, failures INTEGER NOT NULL DEFAULT 0, error TEXT
            );
            CREATE INDEX IF NOT EXISTS comment_cache_checked ON comment_cache(checked_at);
            CREATE TABLE IF NOT EXISTS comment_sources (
                source_id TEXT PRIMARY KEY, source_key TEXT NOT NULL, failures INTEGER NOT NULL DEFAULT 0,
                next_fetch_at TEXT, error TEXT, rotation_cursor TEXT NOT NULL DEFAULT '',
                recent_first INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS comment_history_rotation ON items(source_id,id) WHERE story_id IS NOT NULL;
            CREATE INDEX IF NOT EXISTS comment_recent_pending ON items(source_id,priority_score DESC,last_seen DESC,id) WHERE status='pending';
            CREATE TABLE IF NOT EXISTS review_jobs (
                item_id TEXT PRIMARY KEY, writer_key TEXT NOT NULL,
                policy_hash TEXT NOT NULL, stage TEXT NOT NULL,
                draft_json TEXT, envelope_json TEXT, record_json TEXT NOT NULL,
                approval_key TEXT, prepared_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS review_approvals (
                key TEXT PRIMARY KEY, candidate_hash TEXT NOT NULL,
                source_hash TEXT NOT NULL, policy_hash TEXT NOT NULL,
                binding_hash TEXT NOT NULL, result_json TEXT NOT NULL,
                review_record_json TEXT NOT NULL, created_at TEXT NOT NULL,
                last_used_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS review_approvals_used ON review_approvals(last_used_at,key);
            CREATE TABLE IF NOT EXISTS rejection_actions (
                action_id INTEGER PRIMARY KEY AUTOINCREMENT, item_id TEXT NOT NULL,
                content_hash TEXT NOT NULL, action TEXT NOT NULL CHECK(action IN ('retry','dismiss')),
                reason TEXT NOT NULL, created_at TEXT NOT NULL,
                before_status TEXT NOT NULL, before_attempts INTEGER NOT NULL,
                before_rejections INTEGER NOT NULL, before_error TEXT, before_next_attempt_at TEXT,
                superseded_analysis_key TEXT, superseded_analysis_json TEXT
            );
            CREATE INDEX IF NOT EXISTS rejection_actions_item ON rejection_actions(item_id,action_id);
            CREATE TABLE IF NOT EXISTS decision_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT, decided_at TEXT NOT NULL, subject TEXT NOT NULL,
                item_id TEXT, content_hash TEXT, source_id TEXT, story_id TEXT,
                code TEXT NOT NULL, detail_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS decision_log_time ON decision_log(decided_at);
            CREATE INDEX IF NOT EXISTS decision_log_item ON decision_log(item_id,id);
        """)
        editorial.initialize(self.db)
        publication.initialize(self.db)
        doctor.initialize(self.db)
        if self.db.execute("PRAGMA user_version").fetchone()[0] < 1:
            analysis_columns = set(_table_columns(self.db, "analyses"))
            for name in ("source_payload", "source_item_id", "review_record"):
                if name not in analysis_columns:
                    self.db.execute(f"ALTER TABLE analyses ADD COLUMN {name} TEXT")
            if "rejections" not in _table_columns(self.db, "items"):
                self.db.execute("ALTER TABLE items ADD COLUMN rejections INTEGER NOT NULL DEFAULT 0")
            self.db.execute("PRAGMA user_version = 1")
        self.db.execute("CREATE INDEX IF NOT EXISTS analyses_source_snapshot ON analyses(source_item_id,created_at DESC,cache_key DESC)")
        if get_meta(self.db, "publication_build_pending") is None and not self.db.execute("SELECT 1 FROM public_artifacts LIMIT 1").fetchone():
            set_meta(self.db, publication_build_pending="1")
        self._comment_requests: dict[str, str] = {}
        self.db.commit()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *args) -> None:
        self.db.close()

    def source(self, source: dict) -> dict:
        """Load or initialize persistent polling state for a configured source."""
        row = self.db.execute("SELECT * FROM source_state WHERE id=?", (source["id"],)).fetchone()
        if row and row["url"] == source["url"]:
            return dict(row)
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO source_state(id,url) VALUES(?,?)", (source["id"], source["url"]))
        return dict(self.db.execute("SELECT * FROM source_state WHERE id=?", (source["id"],)).fetchone())

    def source_success(self, source: dict, result: dict, observed: str, *, schedule_from: str | None = None) -> None:
        """Record a successful poll, cache validators and next fetch timestamp."""
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
                    after(
                        source["interval_seconds"] - min(POLL_TOLERANCE_SECONDS, source["interval_seconds"] / 10),
                        schedule_from or observed,
                    ),
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
        """Record a failed or catching-up poll with bounded retry backoff."""
        state = self.source(source)
        failures = state["failures"] + 1
        next_fetch = (
            after(source["interval_seconds"], observed)
            if catching_up
            else backoff_until(failures, collection["failure_backoff_base_seconds"], collection["failure_backoff_cap_seconds"], observed)
        )
        fields = {"failures": 0 if catching_up else failures, "error": error[:160], "next_fetch_at": next_fetch}
        if watermark:
            fields["watermark"] = watermark
        assignments = ",".join(f"{name}=?" for name in fields)
        with self.db:
            self.db.execute(f"UPDATE source_state SET {assignments} WHERE id=?", (*fields.values(), source["id"]))

    def ingest(
        self,
        item: dict,
        observed: str,
        *,
        dirauth_users: Iterable[str] | None = None,
        tor_core_users: Iterable[str] | None = None,
    ) -> bool:
        """Store a new or updated source item and return whether it was queued."""
        item_id = digest(item_identity(item))[:24]
        item["id"] = item_id
        content_hash = item_hash(item)
        cluster = item_cluster(item)
        check_requested = (item.get("kind") == "gitlab_issue" and "comments_source_key" not in item
                           and self._comment_requests.pop(item_id, None) == observed)
        row = self.db.execute(
            """SELECT content_hash,status,story_id,cluster_key,
               CASE WHEN typeof(payload)='text' THEN CAST(payload AS BLOB) END AS payload FROM items WHERE id=?""",
            (item_id,),
        ).fetchone()
        if row is not None:
            old = saved_object(row["payload"])
            requested = "SELECT 1 FROM comment_cache WHERE item_id=? AND (failures>0 OR next_fetch_at<=checked_at)"
            if _is_compacted_saved_item(self.db, item_id, row, old):
                body = item.get("source_content", item.get("content"))
                rehydrated = {**old, "content": body} if isinstance(body, str) else None
                same_body = rehydrated is not None and item_hash(rehydrated) == row["content_hash"]
                if (
                    row["content_hash"] == content_hash
                    or item["updated_at"] < old["updated_at"]
                    or (same_body and _unchanged_non_pending(rehydrated, item, content_hash, check_requested=check_requested))
                ):
                    closed_at = _updated_closed_at(old, item) if row["content_hash"] == content_hash else None
                    if (
                        item.get("kind") == "gitlab_issue"
                        and (same_body or (row["content_hash"] == content_hash and item["updated_at"] >= old["updated_at"]))
                        and self.db.execute(requested, (item_id,)).fetchone()
                    ):
                        restored = rehydrated if same_body else item
                        if closed_at is not None and restored is rehydrated:
                            restored = {**restored, "closed_at": closed_at, "updated_at": item["updated_at"]}
                        with self.db:
                            self.db.execute(
                                "UPDATE items SET payload=? WHERE id=?",
                                (json.dumps(restored, ensure_ascii=False), item_id),
                            )
                    elif closed_at is not None:
                        with self.db:
                            self.db.execute(
                                "UPDATE items SET payload=? WHERE id=?",
                                (json.dumps({**old, "closed_at": closed_at, "updated_at": item["updated_at"]}, ensure_ascii=False), item_id),
                            )
                    return False
            elif not _valid_saved_item(old):
                logging.getLogger(__name__).warning("Replacing damaged saved item %s", item_id)
                if row["content_hash"] == content_hash or (row["status"] != "pending" and check_requested
                                                           and self.db.execute(requested, (item_id,)).fetchone()):
                    with self.db:
                        self.db.execute("UPDATE items SET payload=? WHERE id=?", (json.dumps(item, ensure_ascii=False), item_id))
                    return False
            elif (
                row["content_hash"] == content_hash
                or item["updated_at"] < old["updated_at"]
                or (row["status"] != "pending" and _unchanged_non_pending(old, item, content_hash, check_requested=check_requested))
            ):
                if row["content_hash"] == content_hash and (closed_at := _updated_closed_at(old, item)) is not None:
                    with self.db:
                        self.db.execute(
                            "UPDATE items SET payload=? WHERE id=?",
                            (json.dumps({**old, "closed_at": closed_at, "updated_at": item["updated_at"]}, ensure_ascii=False), item_id),
                        )
                return False
            alias = editorial.retired(self.db, story_id=row["story_id"], cluster_key=row["cluster_key"])
            if alias is not None and alias[1] is None:
                cluster = self.db.execute("SELECT cluster_key FROM story_aliases WHERE story_id=?", (alias[0],)).fetchone()[0]
        effective_users = self.dirauth_users if dirauth_users is None else dirauth_users
        effective_tor_core = self.tor_core_users if tor_core_users is None else tor_core_users
        score = item_priority(item, effective_users, effective_tor_core)
        try:
            with self.db:
                self.db.execute(
                    f"""INSERT INTO items(id,url,source_id,payload,content_hash,cluster_key,first_seen,last_seen,priority_score)
                        VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
                        url=excluded.url,source_id=excluded.source_id,payload=excluded.payload,content_hash=excluded.content_hash,
                        cluster_key=excluded.cluster_key,last_seen=excluded.last_seen,{editorial.RESET_PENDING_SQL},
                        priority_score=excluded.priority_score""",
                    (item_id, item["url"], item["source_id"], json.dumps(item, ensure_ascii=False), content_hash, cluster, observed, observed, score),
                )
        except sqlite3.IntegrityError:
            logging.getLogger(__name__).warning("Skipping item %s with duplicate URL", item_id)
            return False
        return True

    def pending(self, limit: int, observed: str) -> list[dict]:
        """Due items, best first, after those waiting for a verification or a release-label repair."""
        rows = self.db.execute(
            f"""SELECT {ITEM_SAFE_COLUMNS} FROM items
                WHERE status='pending' AND (next_attempt_at IS NULL OR next_attempt_at<=?)
                ORDER BY id IN (SELECT item_id FROM review_jobs WHERE stage IN ('verify','repair')) DESC,
                priority_score DESC,last_seen DESC,id LIMIT ?""",
            (observed, limit),
        ).fetchall()
        return [
            entry if _valid_pending_payload(entry, payload) else {"id": row["id"], "damaged": True}
            for row in rows
            for entry, payload in (decode_item_row(row),)
        ]

    def pending_count(self) -> int:
        """Return the total number of items currently in pending status."""
        return self.db.execute("SELECT COUNT(*) FROM items WHERE status='pending'").fetchone()[0]

    def require_pending_item(self, row: dict, message: str) -> dict:
        """Read the complete source/association identity under the caller's write transaction."""
        if not isinstance(row, dict) or not isinstance(row.get("id"), str):
            raise candidate.StaleCandidate(message)
        if not self.db.in_transaction:
            self.db.execute("BEGIN IMMEDIATE")
        raw = self.db.execute(f"SELECT {ITEM_SAFE_COLUMNS} FROM items WHERE id=?", (row["id"],)).fetchone()
        current, payload = decode_item_row(raw)
        try:
            row_payload = saved_object(row["payload"].encode("utf-8")) if isinstance(row.get("payload"), str) else None
            same = (
                _valid_pending_payload(current, payload)
                and _valid_pending_payload(row, row_payload)
                and current["status"] == "pending"
                and candidate.item_fingerprint(current) == candidate.item_fingerprint(row)
            )
        except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError):
            same = False
        if not same:
            raise candidate.StaleCandidate(message)
        return current

    def defer(self, item_id: str, error: str, llm: dict, observed: str, *, terminal: bool = False,
              code: str = "app.unexpected", expected_row: dict | None = None) -> bool:
        """Retry later, or stop after three item failures; return false if the expected work is stale.

        Callers with a captured source row must not apply its failure to a newer
        revision or association. Callers without one retain item-ID semantics.
        """
        if expected_row is not None and (not isinstance(expected_row, dict) or expected_row.get("id") != item_id):
            return False
        with self.db:
            if not self.db.in_transaction:
                self.db.execute("BEGIN IMMEDIATE")
            if expected_row is not None:
                try:
                    row = self.require_pending_item(expected_row, "Source item changed before deferral")
                except candidate.StaleCandidate:
                    return False
            else:
                row = self.db.execute("SELECT attempts,rejections FROM items WHERE id=? AND status='pending'",
                                      (item_id,)).fetchone()
            if row is None:
                return False
            attempts, rejections = row["attempts"] + 1, row["rejections"] + terminal
            if rejections >= 3:
                self.reject(item_id, error, "failed." + code, observed)
                return True
            next_at = backoff_until(attempts, llm["retry_base_seconds"], llm["retry_cap_seconds"], observed)
            return bool(self.db.execute(
                "UPDATE items SET attempts=?,rejections=?,last_error=?,next_attempt_at=? "
                "WHERE id=? AND status='pending'",
                (attempts, rejections, error[:160], next_at, item_id),
            ).rowcount)

    def reject(self, item_id: str, error: str, code: str, observed: str) -> None:
        """Stop retrying a pending item, after its third failure or because its saved copy is damaged."""
        with self.db:
            if self.db.execute(
                """UPDATE items SET status='rejected',attempts=attempts+1,rejections=MAX(rejections,3),
                   next_attempt_at=NULL,last_error=? WHERE id=? AND status='pending'""",
                (error[:160], item_id),
            ).rowcount:
                decisions.record(self.db, item_id, code, observed, error=error[:160])

    def rejected_count(self) -> int:
        """Return the total number of items currently in rejected status."""
        return self.db.execute("SELECT COUNT(*) FROM items WHERE status='rejected'").fetchone()[0]

    def record_analysis(self, row: dict, result: dict, cache_key: str, observed: str, *,
                        review_record: dict | None = None) -> str:
        """Append immutable private evidence; the caller owns the transaction."""
        result_json = strict_json(result)
        record_json = strict_json(review_record) if review_record is not None else None
        values = (result_json, row["payload"], row["id"], record_json)
        previous = self.db.execute(
            """SELECT result,source_payload,source_item_id,review_record,
               rowid=(SELECT MAX(rowid) FROM analyses WHERE source_item_id=?) FROM analyses WHERE cache_key=?""",
            (row["id"], cache_key),
        ).fetchone()
        if previous is not None:
            if tuple(previous) == (*values, 1):
                return cache_key
            cache_key = digest(["analysis-audit", cache_key, values, observed])
        self.db.execute(
            """INSERT OR IGNORE INTO analyses
               (cache_key,result,created_at,source_payload,source_item_id,review_record)
               VALUES(?,?,?,?,?,?)""",
            (cache_key, result_json, observed, row["payload"], row["id"], record_json),
        )
        return cache_key

    def prepare_candidate(
        self,
        row: dict,
        result: dict,
        observed: str,
        *,
        dirauth_users: Iterable[str] | None = None,
        tor_core_users: Iterable[str] | None = None,
    ) -> dict:
        """Assemble a read-only publication candidate and source bindings for `row`."""
        effective_users = self.dirauth_users if dirauth_users is None else dirauth_users
        effective_tor_core = self.tor_core_users if tor_core_users is None else tor_core_users
        return candidate.prepare(
            self.db,
            row,
            result,
            observed,
            dirauth_users=effective_users,
            tor_core_users=effective_tor_core,
        )

    def _append_citation(self, story_id: str, story_payload: dict, source: dict) -> None:
        if "editorial_item" not in story_payload:
            w_id, w_kind, w_auth = candidate.writer_info(story_payload, self.db)
            if w_id is not None:
                story_payload["editorial_item"] = w_id
                if w_kind and "editorial_kind" not in story_payload:
                    story_payload["editorial_kind"] = w_kind
                if w_auth and "editorial_authority" not in story_payload:
                    story_payload["editorial_authority"] = w_auth
        source_map = {entry["url"]: entry for entry in story_payload.get("sources", [])}
        source_map[source["url"]] = source
        story_payload["sources"] = sorted(source_map.values(), key=lambda entry: entry["url"])
        cursor = self.db.execute(
            "UPDATE stories SET payload=? WHERE id=?",
            (json.dumps(story_payload, ensure_ascii=False, allow_nan=False), story_id),
        )
        if not cursor.rowcount:
            raise editorial.RetiredStory("Story is retired")

    def add_citation(self, row: dict, story_id: str, observed: str) -> dict:
        """Attach a corroborating tag source without model calls or moving updated_at."""
        with immediate_transaction(self.db, "Citation commit requires a fresh transaction"):
            current = self.require_pending_item(row, "Source item changed before citation committed")
            story_row = self.db.execute(
                "SELECT id,cluster_key,CASE WHEN typeof(payload)='text' THEN CAST(payload AS BLOB) END AS payload FROM stories WHERE id=?",
                (story_id,),
            ).fetchone()
            if editorial.retired(self.db, story_id=story_id, cluster_key=story_row["cluster_key"] if story_row else None) is not None:
                raise editorial.RetiredStory("Story is retired")
            if story_row is None or (story_payload := saved_object(story_row["payload"])) is None:
                raise candidate.StaleCandidate("Target story is no longer available")
            locked = editorial.is_locked(self.db, story_id)
            source = item_source(json.loads(current["payload"]))
            if not safe_canonical_url(source["url"]):
                raise candidate.StaleCandidate("Source item URL is invalid")
            cache_key = digest(["citation", current["id"], current["content_hash"], story_id])
            review_record = {"schema_version": 1, "writer": None, "input_hash": current["content_hash"], "reviews": [],
                             "outcome": "locked" if locked else "cited", "story_id": story_id}
            analysis_key = self.record_analysis(current, {"citation": source["url"], "story_id": story_id},
                                                cache_key, observed, review_record=review_record)
            if locked:
                editorial.record_held(self.db, story_id)
                code = "held.gate.story_locked"
            else:
                self._append_citation(story_id, story_payload, source)
                code = "published.update"
            self.db.execute(
                "UPDATE items SET status='published',story_id=?,next_attempt_at=NULL,last_error=NULL WHERE id=?",
                (story_id, current["id"]),
            )
            if not locked:
                self.db.execute("DELETE FROM review_jobs WHERE item_id=?", (current["id"],))
            decisions.record(self.db, current["id"], code, observed, review=review_record)
        return {"story_id": story_id, "status": "locked" if locked else "cited", "analysis_key": analysis_key}

    def commit_candidate(self, prepared: dict, approved_candidate: dict | None, cache_key: str, observed: str, *,
                         approval_key: str | None = None, policy_hash: str | None = None,
                         review_record: dict | None = None, decision: str = "approve",
                         operator: bool = False) -> dict:
        """Apply an exact reviewed publication or skip decision and delete its receipt."""
        with immediate_transaction(self.db, "Candidate commit requires a fresh transaction"):
            row, result, story_id, locked = prepared["row"], prepared["result"], prepared["story_id"], prepared["locked"]
            payload = skipped = operator_reason = None
            code = "held.gate.story_locked"
            if operator and locked:
                raise ReviewRequired("Its story is editorially locked")
            if not locked:
                mode = prepared.get("mode", "story")
                editable_fields = candidate.validate_approved(prepared["candidate"], approved_candidate, mode)
                if prepared["packet"]["missing_sources"]:
                    raise ReviewRequired("Required source material is unavailable")
                if operator:
                    approval_meta = review_record.get("operator_approval") if isinstance(review_record, dict) else None
                    if (decision != "approve" or not isinstance(approval_meta, dict)
                            or review_record.get("outcome") != "operator_approved"
                            or not isinstance(approval_meta.get("reason"), str) or not approval_meta["reason"]):
                        raise ReviewRequired("Operator approval requires an operator_approval audit record")
                    effective_users = prepared["dirauth_users"] if "dirauth_users" in prepared else self.dirauth_users
                    effective_tor_core = prepared["tor_core_users"] if "tor_core_users" in prepared else self.tor_core_users
                    current = candidate.prepare(
                        self.db, row, result, prepared["observed"], dirauth_users=effective_users, tor_core_users=effective_tor_core
                    )
                    held_job = self.db.execute("SELECT stage FROM review_jobs WHERE item_id=?", (row["id"],)).fetchone()
                    item_state = self.db.execute("SELECT status FROM items WHERE id=?", (row["id"],)).fetchone()
                    if (current["locked"] or current["binding_hash"] != prepared["binding_hash"]
                            or held_job is None or held_job["stage"] != "held"
                            or item_state is None or item_state["status"] != "rejected"):
                        raise candidate.StaleCandidate("Item or coverage changed before approval committed")
                    operator_reason = approval_meta["reason"]
                else:
                    from . import review_gate
                    from .review import validate_review

                    receipt = self.db.execute("SELECT * FROM review_approvals WHERE key=?", (approval_key,)).fetchone()
                    if receipt is not None:
                        if any(receipt[key] != expected for key, expected in (
                                ("candidate_hash", digest(approved_candidate)), ("source_hash", prepared["source_hash"]),
                                ("policy_hash", policy_hash), ("binding_hash", prepared["binding_hash"]))):
                            raise ReviewRequired("Review decision does not match this candidate and its context")
                        verdict = validate_review(json.loads(receipt["result_json"]), prepared["packet"],
                                                  update=mode == "update", coverage=prepared["coverage"])
                        if verdict["verdict"] != decision:
                            raise ReviewRequired("Final review did not authorize this decision")
                        if review_record is None:
                            review_record = json.loads(receipt["review_record_json"])
                        self.db.execute("DELETE FROM review_approvals WHERE key=?", (approval_key,))
                    else:
                        expected_key = digest([digest(approved_candidate), prepared["source_hash"], policy_hash, prepared["binding_hash"]])
                        job_row = (
                            self.db.execute(
                                "SELECT stage,policy_hash,approval_key FROM review_jobs WHERE item_id=?",
                                (row["id"],),
                            ).fetchone()
                            if decision == "approve"
                            and isinstance(review_record, dict)
                            and approval_key == expected_key
                            and review_record.get("policy_hash") == policy_hash
                            and review_record.get("reviews")
                            else None
                        )
                        if (
                            job_row is None
                            or job_row["stage"] != "approved"
                            or job_row["policy_hash"] != policy_hash
                            or job_row["approval_key"] != approval_key
                        ):
                            raise ReviewRequired("Review decision does not match this candidate and its context")
                        review_gate.validate_review_state(
                            review_record, "approved", approved_candidate, prepared, allow_cached=False
                        )
                        rev_specs = review_record.get("specialists", 1)
                        step_action, step_value = (
                            review_gate.next_step(
                                review_record["reviews"],
                                approved_candidate,
                                prepared,
                                specialists=rev_specs,
                            )
                            if type(rev_specs) is int and rev_specs > 1
                            else review_gate.next_step(review_record["reviews"], approved_candidate, prepared)
                        )
                        if step_action != "approve" or step_value != approved_candidate:
                            raise ReviewRequired("Final review did not authorize this decision")
                        verdict = validate_review(
                            review_record["reviews"][-1]["result"],
                            prepared["packet"],
                            update=mode == "update",
                            coverage=prepared["coverage"],
                        )
            if not operator:
                candidate.verify_prepared_binding(self.db, prepared)
            cited_on_skip = False
            if not locked:
                if decision == "approve":
                    payload = copy.deepcopy(prepared["payload"])
                    payload.update({key: approved_candidate[key] for key in editable_fields})
                    new = self.db.execute("SELECT 1 FROM stories WHERE id=?", (story_id,)).fetchone() is None
                    if new:
                        payload["added_at"] = observed
                    code = "operator.approved" if operator else ("published.new" if new else "published.update")
                else:
                    failed_criteria = list(decisions.failed_criteria(verdict["criteria"]))
                    skipped = ("Final review skipped: " + ", ".join(failed_criteria))[:160]
                    code = decisions.skip_code(review_record, verdict)
                    item_obj = json.loads(row["payload"])
                    if (
                        failed_criteria == ["new_information"]
                        and ((row.get("cluster_key") or "").startswith("release:") or item_obj.get("kind") == "metrics_timeline")
                        and story_id in verdict["criteria"]["new_information"]["reason"]
                        and not editorial.is_locked(self.db, story_id)
                    ):
                        existing_row = self.db.execute("SELECT payload FROM stories WHERE id=?", (story_id,)).fetchone()
                        if existing_row is not None:
                            self._append_citation(story_id, json.loads(existing_row[0]), item_source(item_obj))
                            cited_on_skip = True
            analysis_key = self.record_analysis(row, result, cache_key, observed, review_record=review_record)
            if payload is not None:
                if prepared.get("mode", "story") == "story" and payload.get("editorial_item") == row["id"]:
                    payload["editorial_analysis_key"] = analysis_key
                if not upsert_story(
                    self.db,
                    story_id,
                    prepared["cluster_key"],
                    json.dumps(payload, ensure_ascii=False, allow_nan=False),
                    payload["published_at"],
                    payload["updated_at"],
                ):
                    raise editorial.RetiredStory("Story is retired")
            elif locked:
                editorial.record_held(self.db, story_id)
            published = decision == "approve"
            if published or cited_on_skip:
                mapped_id = story_id
            elif row.get("story_id"):
                prior_story_id = row["story_id"]
                keep_mapping = bool(
                    self.db.execute(
                        """SELECT 1 FROM decision_log
                           WHERE item_id=? AND (code GLOB 'published.*' OR code IN ('operator.approved','held.gate.story_locked'))""",
                        (row["id"],),
                    ).fetchone()
                )
                if not keep_mapping:
                    story_row = self.db.execute("SELECT CAST(payload AS BLOB) FROM stories WHERE id=?", (prior_story_id,)).fetchone()
                    story_obj = saved_object(story_row[0] if story_row else None)
                    keep_mapping = story_obj is not None and candidate.story_cites_item(story_obj, row["id"], row.get("url"))
                mapped_id = prior_story_id if keep_mapping else None
            else:
                mapped_id = None
            self.db.execute("UPDATE items SET status=?,story_id=?,next_attempt_at=NULL,last_error=? WHERE id=?",
                            ("published" if published else "ignored", mapped_id, skipped, row["id"]))
            if locked and self.db.execute("SELECT 1 FROM review_jobs WHERE item_id=?", (row["id"],)).fetchone():
                from .review_gate import validate_review_state
                validate_review_state(review_record, "locked", None, prepared)
                # Unlocking or transferring a held update changes its context,
                # but must not replenish attempts already spent before the lock.
                set_job_stage(self.db, row["id"], "locked", review_record, observed)
            else:
                self.db.execute("DELETE FROM review_jobs WHERE item_id=?", (row["id"],))
            decisions.record(self.db, row["id"], code, observed, review=review_record, reason=operator_reason)
        return {"story_id": mapped_id, "status": "locked" if locked and published else "published" if published else "ignored",
                "analysis_key": analysis_key}

    def stories(self, limit: int = -1) -> list[dict]:
        """Stored stories, newest activity first (all of them by default)."""
        return [json.loads(row[0]) for row in self.db.execute("SELECT payload FROM stories ORDER BY updated_at DESC,id LIMIT ?", (limit,))]

    def health(self, sources: list[dict], stale_seconds: int, observed: str) -> list[dict]:
        """Read-only: a source without state for its current URL has not succeeded yet."""
        result = []
        for source in sources:
            if not source["enabled"]:
                continue
            row = self.db.execute("SELECT url,last_success,error FROM source_state WHERE id=?", (source["id"],)).fetchone()
            state = dict(row) if row and row["url"] == source["url"] else {"last_success": None, "error": None}
            stale = not state["last_success"] or after(stale_seconds, state["last_success"]) < observed
            result.append({
                "id": source["id"],
                "name": source["name"],
                "website_url": source.get("website_url"),
                "last_success": state["last_success"],
                "error": state["error"],
                "stale": bool(stale),
            })
        return result

    def get_meta(self, key: str) -> str | None:
        """Read one metadata value by key from this store."""
        return get_meta(self.db, key)

    def set_meta(self, **values: str) -> None:
        """Write one or more metadata values in a single transaction."""
        with self.db:
            set_meta(self.db, **values)

    def refresh_candidates(self, limit: int = 2) -> list[dict]:
        """Select eligible live multi-update stories needing a cohesive summary refresh."""
        if limit <= 0:
            return []
        rows = self.db.execute(
            """SELECT s.id, s.cluster_key, s.published_at, s.updated_at,
                      CASE WHEN typeof(s.payload)='text' THEN CAST(s.payload AS BLOB) END AS payload_blob,
                      sr.last_refreshed_at, sr.update_count AS sr_update_count,
                      sr.refreshed_hash AS sr_refreshed_hash, sr.status AS sr_status
               FROM stories s
               LEFT JOIN editorial_controls e ON e.story_id=s.id
               LEFT JOIN story_refreshes sr ON sr.story_id=s.id
               WHERE COALESCE(e.retracted, 0) != 1
                 AND COALESCE(e.locked, 0) != 1
                 AND NOT EXISTS (
                     SELECT 1 FROM story_aliases a
                     WHERE a.story_id=s.id OR a.cluster_key=s.cluster_key
                 )
               ORDER BY s.updated_at DESC, s.id"""
        ).fetchall()
        selected: list[dict] = []
        for row in rows:
            if editorial.retired(self.db, story_id=row["id"], cluster_key=row["cluster_key"]) is not None:
                continue
            payload = saved_object(row["payload_blob"])
            if payload is None or payload.get("origin") == "network-health":
                continue
            updates = payload.get("updates")
            if not isinstance(updates, list) or len(updates) < MIN_REFRESH_UPDATES:
                continue
            current_hash = story_refresh_hash(payload)
            prev_count = row["sr_update_count"]
            if prev_count is not None:
                if not (
                    prev_count < len(updates)
                    and (len(updates) - prev_count) >= MIN_NEW_UPDATES_FOR_REFRESH
                    and row["sr_refreshed_hash"] != current_hash
                ):
                    continue
            selected.append({
                "id": row["id"],
                "story_id": row["id"],
                "cluster_key": row["cluster_key"],
                "published_at": row["published_at"],
                "updated_at": row["updated_at"],
                "payload": payload,
                "update_count": len(updates),
                "refreshed_hash": current_hash,
                "previous_refresh": (
                    {
                        "last_refreshed_at": row["last_refreshed_at"],
                        "update_count": prev_count,
                        "refreshed_hash": row["sr_refreshed_hash"],
                        "status": row["sr_status"],
                    }
                    if prev_count is not None
                    else None
                ),
            })
            if len(selected) >= limit:
                break
        return selected

    def record_refresh_status(
        self,
        story_id: str,
        *,
        update_count: int,
        refreshed_hash: str,
        status: str,
        observed: str,
    ) -> None:
        """Record a non-committed refresh outcome so unrefreshable stories are not retried every run."""
        with immediate_transaction(self.db, "Refresh status update requires a fresh transaction"):
            self.db.execute(
                """INSERT INTO story_refreshes(story_id,last_refreshed_at,update_count,refreshed_hash,status)
                   VALUES(?,?,?,?,?)
                   ON CONFLICT(story_id) DO UPDATE SET
                   last_refreshed_at=excluded.last_refreshed_at,
                   update_count=excluded.update_count,
                   refreshed_hash=excluded.refreshed_hash,
                   status=excluded.status""",
                (story_id, observed, update_count, refreshed_hash, status),
            )

    def commit_story_refresh(
        self,
        story_id: str,
        updated_payload: dict,
        update_count: int,
        refreshed_hash: str,
        observed: str,
        *,
        base_prose: dict,
    ) -> dict:
        """Atomically update refreshed prose fields while preserving dates, sources, updates, and labels."""
        with immediate_transaction(self.db, "Story refresh commit requires a fresh transaction"):
            story_row = self.db.execute(
                """SELECT id,cluster_key,published_at,updated_at,
                          CASE WHEN typeof(payload)='text' THEN CAST(payload AS BLOB) END AS payload_blob
                   FROM stories WHERE id=?""",
                (story_id,),
            ).fetchone()
            if editorial.retired(
                self.db,
                story_id=story_id,
                cluster_key=story_row["cluster_key"] if story_row else None,
            ) is not None:
                raise editorial.RetiredStory("Story is retired")
            if story_row is None or (current_payload := saved_object(story_row["payload_blob"])) is None:
                raise candidate.StaleCandidate("Target story is no longer available")
            ctrl = self.db.execute(
                "SELECT locked,retracted FROM editorial_controls WHERE story_id=?",
                (story_id,),
            ).fetchone()
            if (ctrl is not None and (ctrl["locked"] == 1 or ctrl["retracted"] == 1)) or editorial.is_locked(
                self.db, story_id
            ):
                raise candidate.StaleCandidate("Story is editorially locked or retracted")
            current_updates = current_payload.get("updates")
            if (
                not isinstance(current_updates, list)
                or len(current_updates) < MIN_REFRESH_UPDATES
                or len(current_updates) != update_count
                or story_refresh_hash(current_payload) != refreshed_hash
                or any(
                    (current_payload.get(field) if isinstance(current_payload.get(field), str) else "")
                    != (base_prose.get(field) if isinstance(base_prose.get(field), str) else "")
                    for field in ("title", "summary", "why_it_matters")
                )
            ):
                raise candidate.StaleCandidate("Story changed before refresh committed")
            merged = copy.deepcopy(current_payload)
            if isinstance(updated_payload.get("title"), str) and updated_payload["title"].strip():
                merged["title"] = updated_payload["title"]
            if not isinstance(updated_payload.get("summary"), str) or not updated_payload["summary"].strip():
                raise ReviewRequired("Refreshed story summary must be non-empty")
            merged["summary"] = updated_payload["summary"]
            if "why_it_matters" in updated_payload:
                if not isinstance(updated_payload["why_it_matters"], str):
                    raise ReviewRequired("Refreshed why_it_matters must be a string")
                merged["why_it_matters"] = updated_payload["why_it_matters"]
            merged["id"] = story_row["id"]
            merged["published_at"] = current_payload.get("published_at") or story_row["published_at"]
            merged["updated_at"] = current_payload.get("updated_at") or story_row["updated_at"]
            if "added_at" in current_payload:
                merged["added_at"] = current_payload["added_at"]
            merged["sources"] = copy.deepcopy(current_payload["sources"])
            merged["updates"] = copy.deepcopy(current_updates)
            public = render.prepare_story(merged, editorial=editorial.public_metadata(self.db, story_id))
            for field in ("title", "summary", "why_it_matters"):
                merged[field] = public[field]
            if not upsert_story(
                self.db,
                story_id,
                story_row["cluster_key"],
                json.dumps(merged, ensure_ascii=False, allow_nan=False),
                story_row["published_at"],
                story_row["updated_at"],
            ):
                raise editorial.RetiredStory("Story is retired")
            set_meta(self.db, publication_build_pending="1")
            ref_hash = story_refresh_hash(merged)
            self.db.execute(
                """INSERT INTO story_refreshes(story_id,last_refreshed_at,update_count,refreshed_hash,status)
                   VALUES(?,?,?,?,?)
                   ON CONFLICT(story_id) DO UPDATE SET
                   last_refreshed_at=excluded.last_refreshed_at,
                   update_count=excluded.update_count,
                   refreshed_hash=excluded.refreshed_hash,
                   status=excluded.status""",
                (story_id, observed, len(current_updates), ref_hash, "refreshed"),
            )
            return {
                "story_id": story_id,
                "status": "refreshed",
                "update_count": len(current_updates),
                "refreshed_hash": ref_hash,
            }
