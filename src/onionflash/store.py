"""Durable collection, retry queue, analysis records, and stable story identities."""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from contextlib import closing
from pathlib import Path

from .util import after, backoff_seconds, digest, item_cluster, item_identity, saved_object
from . import candidate, decisions, doctor, editorial, render
from .comments import analysis_context
from .candidate import ReviewRequired


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


def item_hash(item: dict) -> str:
    """A digest of the fields that make a new revision of an item."""
    fields = {k: item.get(k) for k in ("title", "content", "kind", "product", "labels", "authority", "upstream_state")}
    if item.get("public_comments"):
        # Notes as the writer sees them, so a reaction that moves only a note's
        # update time, or a verification time, never requeues an item.
        fields["public_comments"] = analysis_context(item)[1]
    return digest(fields)




class Store:
    def __init__(self, path: str | Path):
        """Open persistent state and apply idempotent schema maintenance before use."""
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
            CREATE INDEX IF NOT EXISTS items_cluster_story ON items(cluster_key) WHERE story_id IS NOT NULL;
            CREATE TABLE IF NOT EXISTS analyses (
                cache_key TEXT PRIMARY KEY, result TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS stories (
                id TEXT PRIMARY KEY, cluster_key TEXT UNIQUE NOT NULL, payload TEXT NOT NULL,
                published_at TEXT NOT NULL, updated_at TEXT NOT NULL
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
                -- No longer written; earlier releases still read and write them after a code rollback.
                superseded_analysis_key TEXT, superseded_analysis_json TEXT
            );
            CREATE INDEX IF NOT EXISTS rejection_actions_item ON rejection_actions(item_id,action_id);
            -- One row per terminal decision (see decisions.py); subject is the item ID or another decision's key.
            CREATE TABLE IF NOT EXISTS decision_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT, decided_at TEXT NOT NULL, subject TEXT NOT NULL,
                item_id TEXT, content_hash TEXT, source_id TEXT, story_id TEXT,
                code TEXT NOT NULL, detail_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS decision_log_time ON decision_log(decided_at);
            CREATE INDEX IF NOT EXISTS decision_log_item ON decision_log(item_id,id);
        """)
        editorial.initialize(self.db)
        doctor.initialize(self.db)
        analysis_columns = {row[1] for row in self.db.execute("PRAGMA table_info(analyses)")}
        for name, kind in (("source_payload", "TEXT"), ("source_item_id", "TEXT"), ("review_record", "TEXT")):
            if name not in analysis_columns:
                self.db.execute(f"ALTER TABLE analyses ADD COLUMN {name} {kind}")
        self.db.execute("CREATE INDEX IF NOT EXISTS analyses_source_snapshot ON analyses(source_item_id,created_at DESC,cache_key DESC)")
        if "rejections" not in {row[1] for row in self.db.execute("PRAGMA table_info(items)")}:
            self.db.execute("ALTER TABLE items ADD COLUMN rejections INTEGER NOT NULL DEFAULT 0")
        self._comment_requests: dict[str, str] = {}
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
        content_hash = item_hash(item)
        cluster = item_cluster(item)
        check_requested = (item.get("kind") == "gitlab_issue" and "comments_source_key" not in item
                           and self._comment_requests.pop(item_id, None) == observed)
        row = self.db.execute(
            """SELECT content_hash,status,story_id,cluster_key,typeof(payload) AS payload_type,
               CAST(payload AS BLOB) AS payload FROM items WHERE id=?""",
            (item_id,),
        ).fetchone()
        old = saved_object(row["payload"]) if row and row["payload_type"] == "text" else None
        if row and not isinstance((old or {}).get("updated_at"), str):
            # A damaged saved copy counts as absent, so recollecting replaces it. The same revision is
            # only restored, and so is an issue that is not pending while merge_cached_comments just
            # requested a comment check for it: the item keeps its queue state and operator decision,
            # and the first check that succeeds compares the notes with the kept hash.
            logging.getLogger(__name__).warning("Replacing damaged saved item %s", item_id)
            requested = "SELECT 1 FROM comment_cache WHERE item_id=? AND (failures>0 OR next_fetch_at<=checked_at)"
            if row["content_hash"] == content_hash or (row["status"] != "pending" and check_requested
                                                       and self.db.execute(requested, (item_id,)).fetchone()):
                with self.db:
                    self.db.execute("UPDATE items SET payload=? WHERE id=?", (json.dumps(item, ensure_ascii=False), item_id))
                return False
        elif row and row["content_hash"] == content_hash:
            # An upstream updated_at edit alone is not a new news event.
            return False
        elif (
            row
            and item["updated_at"] < old["updated_at"]
            and not (item.get("kind") == "metrics_timeline" and item.get("url") != old.get("url"))
        ):
            # A stale cache/fallback must not roll a newer incident back in time.
            return False
        elif row and row["status"] != "pending" and check_requested and item_hash(old) == content_hash:
            # The same revision as a copy restored above without its notes, listed again before a check
            # succeeded: the kept hash still holds the notes, so this is no change.
            return False
        elif (
            row
            and row["status"] != "pending"
            and "comments_source_key" not in item
            and not check_requested
            and old.get("public_comments")
            and item_hash({k: v for k, v in old.items() if k != "public_comments"}) == content_hash
        ):
            # Disabling comment enrichment must not drop verified notes or requeue unchanged issues.
            return False
        if row is not None:
            alias = editorial.retired(self.db, story_id=row["story_id"], cluster_key=row["cluster_key"])
            if alias is not None and alias[1] is None:
                # Keep a retired item's original cluster key across body edits so process_item still ignores it.
                cluster = self.db.execute("SELECT cluster_key FROM story_aliases WHERE story_id=?", (alias[0],)).fetchone()[0]
        score = item_priority(item)
        try:
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
        except sqlite3.IntegrityError:
            logging.getLogger(__name__).warning("Skipping item %s with duplicate URL", item_id)
            return False
        return True

    def pending(self, limit: int, observed: str) -> list[dict]:
        """Due items, best first, after those waiting for a verification or a release-label repair, so a
        fix loop that a run's deadline cut short finishes first. An item whose saved copy is damaged,
        which reading the whole row could fail on, is only its id and damaged=True, for the caller to reject."""
        rows = []
        for item_id, kind, payload in self.db.execute(
            """SELECT id,typeof(payload),CAST(payload AS BLOB) FROM items WHERE status='pending'
            AND (next_attempt_at IS NULL OR next_attempt_at<=?)
            ORDER BY id IN (SELECT item_id FROM review_jobs WHERE stage IN ('verify','repair')) DESC,
            priority_score DESC,last_seen DESC,id LIMIT ?""",
            (observed, limit),
        ).fetchall():
            if kind == "text" and saved_object(payload) is not None:
                rows.append(dict(self.db.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()))
            else:
                rows.append({"id": item_id, "damaged": True})
        return rows

    def pending_count(self) -> int:
        return self.db.execute(
            "SELECT COUNT(*) FROM items WHERE status='pending'"
        ).fetchone()[0]

    def defer(self, item_id: str, error: str, llm: dict, observed: str, *, terminal: bool = False,
              code: str = "app.unexpected") -> None:
        """Retry later; after three failures caused by the item itself, stop retrying and log `failed.<code>`.

        A rejected item is queued again only when its source content changes.
        """
        row = self.db.execute(
            "SELECT attempts, rejections FROM items WHERE id=? AND status='pending'", (item_id,)
        ).fetchone()
        if row is None:
            return
        attempts, rejections = row[0] + 1, row[1] + terminal
        if rejections >= 3:
            self.reject(item_id, error, "failed." + code, observed)
            return
        delay = backoff_seconds(
            attempts, llm["retry_base_seconds"], llm["retry_cap_seconds"]
        )
        with self.db:
            self.db.execute(
                "UPDATE items SET attempts=?,rejections=?,last_error=?,next_attempt_at=? "
                "WHERE id=? AND status='pending'",
                (attempts, rejections, error[:160], after(delay, observed), item_id),
            )

    def reject(self, item_id: str, error: str, code: str, observed: str) -> None:
        """Stop retrying a pending item, after its third failure or because its saved copy is damaged."""
        with self.db:
            if self.db.execute("""UPDATE items SET status='rejected',attempts=attempts+1,rejections=MAX(rejections,3),
                    next_attempt_at=NULL,last_error=? WHERE id=? AND status='pending'""", (error[:160], item_id)).rowcount:
                decisions.record(self.db, item_id, code, observed, error=error[:160])

    def rejected_count(self) -> int:
        return self.db.execute("SELECT COUNT(*) FROM items WHERE status='rejected'").fetchone()[0]

    def record_analysis(self, row: dict, result: dict, cache_key: str, observed: str, *,
                        review_record: dict | None = None) -> str:
        """Append immutable private evidence; the caller owns the transaction."""
        result_json = json.dumps(result, ensure_ascii=False, sort_keys=True, allow_nan=False)
        record_json = json.dumps(review_record, ensure_ascii=False, sort_keys=True, allow_nan=False) if review_record is not None else None
        values = (result_json, row["payload"], row["id"], record_json)
        previous = self.db.execute("""SELECT result,source_payload,source_item_id,review_record,
            rowid=(SELECT MAX(rowid) FROM analyses WHERE source_item_id=?) FROM analyses WHERE cache_key=?""",
            (row["id"], cache_key)).fetchone()
        if previous is not None:
            if tuple(previous) == (*values, 1):  # an exact repeat of the item's newest record
                return cache_key
            cache_key = digest(["analysis-audit", cache_key, values, observed])
        self.db.execute("""INSERT OR IGNORE INTO analyses
            (cache_key,result,created_at,source_payload,source_item_id,review_record)
            VALUES(?,?,?,?,?,?)""", (cache_key, result_json, observed, row["payload"], row["id"], record_json))
        return cache_key

    def prepare_candidate(self, row: dict, result: dict, observed: str) -> dict:
        return candidate.prepare(self.db, row, result, observed)

    def add_citation(self, row: dict, story_id: str, observed: str) -> dict:
        """Attach a corroborating tag source without model calls or moving updated_at."""
        if self.db.in_transaction:
            raise ValueError("Citation commit requires a fresh transaction")
        self.db.execute("BEGIN IMMEDIATE")
        with self.db:
            current = self.db.execute("SELECT * FROM items WHERE id=?", (row["id"],)).fetchone()
            if (current is None or current["status"] != "pending"
                    or candidate.item_fingerprint(dict(current)) != candidate.item_fingerprint(row)):
                raise candidate.StaleCandidate("Source item changed before citation committed")
            story_row = self.db.execute("SELECT * FROM stories WHERE id=?", (story_id,)).fetchone()
            if story_row is None:
                if editorial.retired(self.db, story_id=story_id) is not None:
                    raise editorial.RetiredStory("Story is retired")
                raise candidate.StaleCandidate("Target story is no longer available")
            if editorial.retired(self.db, story_id=story_id, cluster_key=story_row["cluster_key"]) is not None:
                raise editorial.RetiredStory("Story is retired")
            locked = editorial.is_locked(self.db, story_id)
            item = json.loads(row["payload"])
            source = {key: item[key] for key in ("id", "url", "title", "published_at")}
            cache_key = digest(["citation", row["id"], row["content_hash"], story_id])
            review_record = {"schema_version": 1, "writer": None, "input_row": row, "reviews": [],
                             "outcome": "locked" if locked else "cited", "story_id": story_id}
            analysis_key = self.record_analysis(row, {"citation": source["url"], "story_id": story_id},
                                                cache_key, observed, review_record=review_record)
            if locked:
                editorial.record_held(self.db, story_id)
                code = "held.gate.story_locked"
            else:
                payload = json.loads(story_row["payload"])
                if "editorial_item" not in payload:
                    w_id, w_kind, w_auth = candidate._writer_info(payload, self.db)
                    if w_id is not None:
                        payload["editorial_item"] = w_id
                        if w_kind and "editorial_kind" not in payload:
                            payload["editorial_kind"] = w_kind
                        if w_auth and "editorial_authority" not in payload:
                            payload["editorial_authority"] = w_auth
                source_map = {entry["url"]: entry for entry in payload.get("sources", [])}
                source_map[source["url"]] = source
                payload["sources"] = sorted(source_map.values(), key=lambda entry: entry["url"])
                cursor = self.db.execute(
                    "UPDATE stories SET payload=? WHERE id=?",
                    (json.dumps(payload, ensure_ascii=False, allow_nan=False), story_id),
                )
                if not cursor.rowcount:
                    raise editorial.RetiredStory("Story is retired")
                code = "published.update"
            self.db.execute(
                "UPDATE items SET status='published',story_id=?,next_attempt_at=NULL,last_error=NULL WHERE id=?",
                (story_id, row["id"]),
            )
            self.db.execute("DELETE FROM review_jobs WHERE item_id=?", (row["id"],))
            decisions.record(self.db, row["id"], code, observed, review=review_record)
        return {"story_id": story_id, "status": "locked" if locked else "cited", "analysis_key": analysis_key}

    def commit_candidate(self, prepared: dict, approved_candidate: dict | None, cache_key: str, observed: str, *,
                         approval_key: str | None = None, policy_hash: str | None = None,
                         review_record: dict | None = None, decision: str = "approve",
                         operator: bool = False) -> dict:
        """Apply an exact reviewed publication or skip decision and delete its receipt."""
        if self.db.in_transaction:
            raise ValueError("Candidate commit requires a fresh transaction")
        self.db.execute("BEGIN IMMEDIATE")
        with self.db:
            row, result, story_id, locked = prepared["row"], prepared["result"], prepared["story_id"], prepared["locked"]
            payload = skipped = operator_reason = None
            code = "held.gate.story_locked"  # the item maps to its story, and the update waits for the operator
            if operator and locked:
                raise ReviewRequired("Its story is editorially locked")
            if not locked:
                original = prepared["candidate"]
                mode = prepared.get("mode", "story")
                editable_fields = candidate.UPDATE_FIELDS if mode == "update" else candidate.SEMANTIC_FIELDS
                if not isinstance(approved_candidate, dict) or set(approved_candidate) != set(original):
                    raise ReviewRequired("Approval must identify the complete public candidate")
                if any(approved_candidate[key] != original[key] for key in original if key not in editable_fields):
                    raise ReviewRequired("Review cannot change story identity, sources, dates or editorial metadata")
                if mode == "update":
                    orig_updates, app_updates = original.get("updates") or [], approved_candidate.get("updates") or []
                    if (len(app_updates) != len(orig_updates) or not orig_updates
                            or app_updates[:-1] != orig_updates[:-1]
                            or app_updates[-1]["at"] != orig_updates[-1]["at"]
                            or app_updates[-1]["sources"] != orig_updates[-1]["sources"]):
                        raise ReviewRequired("Update review cannot change earlier updates or the new update's date or citations")
                normalized = render._prepare_story(approved_candidate, editorial=original.get("editorial"))
                if normalized != approved_candidate:
                    raise ReviewRequired("The approved candidate must already be normalized")
                if prepared["packet"]["missing_sources"]:
                    raise ReviewRequired("Required source material is unavailable")
                if operator:
                    approval_meta = review_record.get("operator_approval") if isinstance(review_record, dict) else None
                    if (decision != "approve" or not isinstance(approval_meta, dict)
                            or review_record.get("outcome") != "operator_approved"
                            or not isinstance(approval_meta.get("reason"), str) or not approval_meta["reason"]):
                        raise ReviewRequired("Operator approval requires an operator_approval audit record")
                    current = candidate.prepare(self.db, row, result, prepared["observed"])
                    held_job = self.db.execute("SELECT stage FROM review_jobs WHERE item_id=?", (row["id"],)).fetchone()
                    item_state = self.db.execute("SELECT status FROM items WHERE id=?", (row["id"],)).fetchone()
                    if (current["locked"] or current["binding_hash"] != prepared["binding_hash"]
                            or held_job is None or held_job["stage"] != "held"
                            or item_state is None or item_state["status"] != "rejected"):
                        raise candidate.StaleCandidate("Item or coverage changed before approval committed")
                    operator_reason = approval_meta["reason"]
                else:
                    receipt = self.db.execute("SELECT * FROM review_approvals WHERE key=?", (approval_key,)).fetchone()
                    if receipt is None or any(receipt[key] != expected for key, expected in (
                            ("candidate_hash", digest(approved_candidate)), ("source_hash", prepared["source_hash"]),
                            ("policy_hash", policy_hash), ("binding_hash", prepared["binding_hash"]))):
                        raise ReviewRequired("Review decision does not match this candidate and its context")
                    from .review import validate_review
                    verdict = validate_review(json.loads(receipt["result_json"]), prepared["packet"],
                                              update=mode == "update", coverage=prepared["coverage"])
                    if verdict["verdict"] != decision:
                        raise ReviewRequired("Final review did not authorize this decision")
                    if review_record is None:
                        review_record = json.loads(receipt["review_record_json"])
                    self.db.execute("DELETE FROM review_approvals WHERE key=?", (approval_key,))
            if not operator:
                if editorial.retired(self.db, story_id=story_id, cluster_key=prepared["cluster_key"]) is not None:
                    raise editorial.RetiredStory("Story is retired")
                current_item = self.db.execute("SELECT * FROM items WHERE id=?", (row["id"],)).fetchone()
                expected_fp = (prepared.get("binding") or {}).get("item") or candidate.item_fingerprint(row)
                if (current_item is None or current_item["status"] != "pending"
                        or candidate.item_fingerprint(dict(current_item)) != expected_fp):
                    raise candidate.StaleCandidate("Source item changed before candidate committed")
                if editorial.is_locked(self.db, story_id) != bool(locked):
                    raise candidate.StaleCandidate("Editorial lock state changed before candidate committed")
                expected_lock = (prepared.get("binding") or {}).get("lock")
                if expected_lock is not None and candidate.control_fingerprint(self.db, story_id) != expected_lock:
                    raise candidate.StaleCandidate("Editorial controls changed before candidate committed")
                expected_prior = (prepared.get("binding") or {}).get("prior_story")
                if expected_prior is not None and digest(candidate.existing_story(self.db, dict(current_item))) != expected_prior:
                    raise candidate.StaleCandidate("Target story changed before candidate committed")
            if not locked:
                cited_on_skip = False
                if decision == "approve":
                    payload = json.loads(json.dumps(prepared["payload"]))
                    payload.update({key: approved_candidate[key] for key in editable_fields})
                    new = self.db.execute("SELECT 1 FROM stories WHERE id=?", (story_id,)).fetchone() is None
                    if new:  # Date publication, not the first draft.
                        payload["added_at"] = observed
                    code = "operator.approved" if operator else ("published.new" if new else "published.update")
                else:
                    failed_criteria = {name for name, check in verdict["criteria"].items() if check["outcome"] != "pass"}
                    skipped = ("Final review skipped: " + ", ".join(
                        name for name, check in verdict["criteria"].items() if check["outcome"] != "pass"))[:160]
                    code = decisions.skip_code(review_record, verdict)
                    item_obj = json.loads(row["payload"])
                    if (
                        failed_criteria == {"new_information"}
                        and ((row.get("cluster_key") or "").startswith("release:") or item_obj.get("kind") == "metrics_timeline")
                        and story_id in verdict["criteria"]["new_information"]["reason"]
                        and not editorial.is_locked(self.db, story_id)
                    ):
                        existing_row = self.db.execute("SELECT payload FROM stories WHERE id=?", (story_id,)).fetchone()
                        if existing_row is not None:
                            story_payload = json.loads(existing_row[0])
                            if "editorial_item" not in story_payload:
                                w_id, w_kind, w_auth = candidate._writer_info(story_payload, self.db)
                                if w_id is not None:
                                    story_payload["editorial_item"] = w_id
                                    if w_kind and "editorial_kind" not in story_payload:
                                        story_payload["editorial_kind"] = w_kind
                                    if w_auth and "editorial_authority" not in story_payload:
                                        story_payload["editorial_authority"] = w_auth
                            cite_source = {key: item_obj[key] for key in ("id", "url", "title", "published_at")}
                            source_map = {entry["url"]: entry for entry in story_payload.get("sources", [])}
                            source_map[cite_source["url"]] = cite_source
                            story_payload["sources"] = sorted(source_map.values(), key=lambda entry: entry["url"])
                            cursor = self.db.execute(
                                "UPDATE stories SET payload=? WHERE id=?",
                                (json.dumps(story_payload, ensure_ascii=False, allow_nan=False), story_id),
                            )
                            if not cursor.rowcount:
                                raise editorial.RetiredStory("Story is retired")
                            cited_on_skip = True
            else:
                cited_on_skip = False
            analysis_key = self.record_analysis(row, result, cache_key, observed, review_record=review_record)
            if payload is not None:
                if prepared.get("mode", "story") == "story" and payload.get("editorial_item") == row["id"]:
                    payload["editorial_analysis_key"] = analysis_key
                cursor = self.db.execute("""INSERT INTO stories(id,cluster_key,payload,published_at,updated_at)
                    VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,updated_at=excluded.updated_at""",
                    (story_id, prepared["cluster_key"], json.dumps(payload, ensure_ascii=False, allow_nan=False), payload["published_at"], payload["updated_at"]))
                if not cursor.rowcount:
                    raise editorial.RetiredStory("Story is retired")
            elif locked:
                if editorial.retired(self.db, story_id=story_id, cluster_key=prepared["cluster_key"]) is not None:
                    raise editorial.RetiredStory("Story is retired")
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
                    story_obj = saved_object(story_row[0]) if story_row is not None else None
                    if isinstance(story_obj, dict):
                        item_url = row.get("url")
                        keep_mapping = any(
                            isinstance(s, dict) and (s.get("id") == row["id"] or s.get("source_item_id") == row["id"] or s.get("url") == item_url)
                            for s in (story_obj.get("sources") or ())
                        ) or any(
                            isinstance(cs, dict) and (cs.get("url") == item_url or str(cs.get("url") or "").startswith(str(item_url) + "#"))
                            for u in (story_obj.get("updates") or ())
                            if isinstance(u, dict)
                            for cs in (u.get("sources") or ())
                        )
                mapped_id = prior_story_id if keep_mapping else None
            else:
                mapped_id = None
            self.db.execute("UPDATE items SET status=?,story_id=?,next_attempt_at=NULL,last_error=? WHERE id=?",
                            ("published" if published else "ignored", mapped_id, skipped, row["id"]))
            self.db.execute("DELETE FROM review_jobs WHERE item_id=?", (row["id"],))
            decisions.record(self.db, row["id"], code, observed, review=review_record, reason=operator_reason)
        return {"story_id": mapped_id, "status": "locked" if locked and published else "published" if published else "ignored",
                "analysis_key": analysis_key}

    def stories(self, limit: int = -1) -> list[dict]:
        """Stored stories, newest activity first (all of them by default)."""
        return [
            json.loads(row[0])
            for row in self.db.execute(
                "SELECT payload FROM stories ORDER BY updated_at DESC,id LIMIT ?",
                (limit,),
            )
        ]

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

