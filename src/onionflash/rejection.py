"""Small, private operator controls for terminally rejected source items.

The CLI must hold the application run lock for retry/dismiss. These actions do
not call a model, publish a story, or change editorial correction state.
"""

from __future__ import annotations

import json
import re

from .analyze import cache_key
from .schema import PRODUCTS
from .util import canonical_url, format_utc, now_iso, parse_utc


MAX_LIMIT = 200
MAX_PAYLOAD_BYTES = 1048576
HISTORY_LIMIT = 20


def _identifier(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{24}", value):
        raise ValueError("Item ID must be its 24-character lowercase hexadecimal identity")
    return value


def _text(value, limit):
    if not isinstance(value, str):
        return ""
    return " ".join("".join(char if char.isprintable() else " " if char.isspace() else ""
                           for char in value).split())[:limit]


def _payload(row):
    raw = row["payload"]
    if not isinstance(raw, str):
        raise ValueError("Stored source item is not readable JSON")
    try:
        if len(raw) > MAX_PAYLOAD_BYTES or len(raw.encode("utf-8")) > MAX_PAYLOAD_BYTES:
            raise ValueError("Stored source item exceeds the display limit")
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("Stored source item is not an object")
        json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ValueError("Stored source item cannot be decoded safely") from None
    return payload


def _summary(row):
    result = {key: row[key] for key in ("id", "content_hash", "source_id", "status", "attempts", "rejections", "next_attempt_at", "story_id")}
    result["source_url"] = _text(row["url"], 4096)
    result["rejection_reason"] = _text(row["last_error"], 160)
    try:
        payload = _payload(row)
        result["title"] = _text(payload.get("title"), 500)
    except ValueError:
        result["title"] = ""
        result["saved_item_error"] = "Stored source item cannot be decoded safely"
    return result


def list_items(store, *, status="rejected", limit=50, after=None) -> dict:
    """Bounded, stable ID pagination; transient pending failures are excluded."""
    if not isinstance(status, str) or status not in {"rejected", "dismissed"}:
        raise ValueError("List status must be rejected or dismissed")
    if type(limit) is not int or not 1 <= limit <= MAX_LIMIT:
        raise ValueError(f"List limit must be between 1 and {MAX_LIMIT}")
    cursor = "" if after is None else _identifier(after)
    rows = store.db.execute("SELECT * FROM items WHERE status=? AND id>? ORDER BY id LIMIT ?",
                            (status, cursor, limit + 1)).fetchall()
    shown = rows[:limit]
    return {"items": [_summary(row) for row in shown],
            "next_cursor": shown[-1]["id"] if len(rows) > limit else None}


def show_item(store, item_id) -> dict:
    """Explicit inspection may include the saved source, but never raw model output."""
    row = store.db.execute("SELECT * FROM items WHERE id=?", (_identifier(item_id),)).fetchone()
    if row is None:
        raise ValueError("Source item was not found")
    result = _summary(row)
    try:
        result["saved_item"] = _payload(row)
    except ValueError:
        result["saved_item"] = None
    result["actions"] = []
    if store.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='rejection_actions'").fetchone():
        result["actions"] = [dict(action) for action in store.db.execute(
            """SELECT action_id,action,content_hash,reason,created_at,before_status,
                before_attempts,before_rejections,superseded_analysis_key
                FROM rejection_actions WHERE item_id=? ORDER BY action_id DESC LIMIT ?""",
            (item_id, HISTORY_LIMIT),
        )]
    return result


def _initialize(db):
    db.execute("""CREATE TABLE IF NOT EXISTS rejection_actions (
        action_id INTEGER PRIMARY KEY AUTOINCREMENT, item_id TEXT NOT NULL,
        content_hash TEXT NOT NULL, action TEXT NOT NULL CHECK(action IN ('retry','dismiss')),
        reason TEXT NOT NULL, created_at TEXT NOT NULL,
        before_status TEXT NOT NULL, before_attempts INTEGER NOT NULL,
        before_rejections INTEGER NOT NULL, before_error TEXT,
        before_next_attempt_at TEXT, superseded_analysis_key TEXT,
        superseded_analysis_json TEXT
    )""")
    db.execute("CREATE INDEX IF NOT EXISTS rejection_actions_item ON rejection_actions(item_id,action_id)")


def _request(item_id, expected_hash, reason, observed):
    _identifier(item_id)
    if not isinstance(expected_hash, str) or not re.fullmatch(r"[a-f0-9]{64}", expected_hash):
        raise ValueError("Expected content hash must be its 64-character lowercase hexadecimal value")
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 1000:
        raise ValueError("An operator reason of 1–1000 characters is required")
    try:
        reason.encode("utf-8")
    except UnicodeError:
        raise ValueError("Operator reason must be valid UTF-8") from None
    if any(ord(char) < 32 and char not in "\n\t" for char in reason):
        raise ValueError("Operator reason contains a control character")
    return reason.strip(), format_utc(parse_utc(observed or now_iso()))


def _checked(db, item_id, expected_hash):
    row = db.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
    if row is None:
        raise ValueError("Source item was not found")
    if row["content_hash"] != expected_hash:
        raise ValueError("Source content changed; inspect the current item before acting")
    if row["status"] != "rejected":
        raise ValueError("Only a terminally rejected item can be retried or dismissed")
    return dict(row)


def _retry_key(row, llm):
    """Refuse to queue a structurally unreadable/cold item for model analysis."""
    payload = _payload(row)
    try:
        if payload.get("id") != row["id"]:
            raise ValueError
        for key in ("title", "content", "kind"):
            if not isinstance(payload.get(key), str) or (key != "content" and not payload[key]):
                raise ValueError
        if payload.get("product") not in PRODUCTS:
            raise ValueError
        canonical_url(payload["url"])
        parse_utc(payload["published_at"])
        parse_utc(payload["updated_at"])
        return cache_key(row, llm)
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise ValueError("Stored source item is not ready for analysis; restore or recollect it first") from None


def _act(store, item_id, expected_hash, reason, action, llm, observed):
    reason, stamp = _request(item_id, expected_hash, reason, observed)
    db = store.db
    with db:
        row = _checked(db, item_id, expected_hash)
        key = _retry_key(row, llm) if action == "retry" else None
        previous_analysis = db.execute("SELECT * FROM analyses WHERE cache_key=?", (key,)).fetchone() if key else None
        snapshot = json.dumps(dict(previous_analysis), ensure_ascii=False, allow_nan=False) if previous_analysis else None
        if snapshot is not None:
            snapshot.encode("utf-8")
        _initialize(db)
        if action == "retry":
            changed = db.execute("""UPDATE items SET status='pending',attempts=0,rejections=0,
                next_attempt_at=NULL,last_error=NULL
                WHERE id=? AND content_hash=? AND payload=? AND status='rejected'""",
                (item_id, expected_hash, row["payload"])).rowcount
        else:
            changed = db.execute("""UPDATE items SET status='dismissed',next_attempt_at=NULL
                WHERE id=? AND content_hash=? AND payload=? AND status='rejected'""",
                (item_id, expected_hash, row["payload"])).rowcount
        if changed != 1:
            raise ValueError("Source item changed during the action; inspect it again")
        event = db.execute("""INSERT INTO rejection_actions
            (item_id,content_hash,action,reason,created_at,before_status,before_attempts,
             before_rejections,before_error,before_next_attempt_at,superseded_analysis_key,superseded_analysis_json)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (item_id, expected_hash, action, reason, stamp, row["status"], row["attempts"],
             row["rejections"], row["last_error"], row["next_attempt_at"], key if previous_analysis else None, snapshot))
        if previous_analysis:
            db.execute("DELETE FROM analyses WHERE cache_key=?", (key,))
    return {"item_id": item_id, "content_hash": expected_hash, "action": action,
            "status": "pending" if action == "retry" else "dismissed", "action_id": event.lastrowid}


def retry_item(store, item_id, expected_hash, reason, llm, observed=None) -> dict:
    """Queue one rejected revision and retain its superseded analysis for audit."""
    return _act(store, item_id, expected_hash, reason, "retry", llm, observed)


def dismiss_item(store, item_id, expected_hash, reason, observed=None) -> dict:
    """Stop this revision; a genuinely changed upstream payload may queue again."""
    return _act(store, item_id, expected_hash, reason, "dismiss", None, observed)
