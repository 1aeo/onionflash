"""Private operator controls for failed, dismissed or ignored source items.

The CLI must hold the application run lock for retry/dismiss. These actions do
not call a model, publish a story, or change editorial correction state.
"""

from __future__ import annotations

import json
import re

from . import editorial
from .schema import PRODUCTS
from .util import canonical_url, format_utc, now_iso, parse_utc


MAX_LIMIT = 200
HISTORY_LIMIT = 20


def _identifier(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{24}", value):
        raise ValueError("Item ID must be its 24-character lowercase hexadecimal identity")
    return value


# The payload is read as bytes, so a value that is not even UTF-8 reaches _object instead of failing the query.
_COLUMNS = "id,content_hash,source_id,status,attempts,rejections,next_attempt_at,story_id,url,last_error,CAST(payload AS BLOB) AS payload"


def _object(value):
    """A saved JSON object read as bytes, or None when it is damaged, so one bad row cannot hide
    the others. Decoding is strict UTF-8, as when the pipeline reads the row, not json.loads'
    lenient bytes mode."""
    try:
        value = json.loads(str(value, "utf-8"))
    except (ValueError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def _text(value):
    return value if isinstance(value, str) else None


def _summary(row):
    result = {key: row[key] for key in ("id", "content_hash", "source_id", "status", "attempts", "rejections", "next_attempt_at", "story_id")}
    # The CLI escapes printed text, so stored values are shown as the app wrote them.
    result.update(source_url=row["url"], rejection_reason=row["last_error"], title=_text((_object(row["payload"]) or {}).get("title")))
    return result


def list_items(store, *, status="rejected", limit=50, after=None) -> dict:
    """Bounded, stable ID pagination; transient pending failures are excluded."""
    if not isinstance(status, str) or status not in {"rejected", "dismissed", "ignored"}:
        raise ValueError("List status must be rejected, dismissed or ignored")
    if type(limit) is not int or not 1 <= limit <= MAX_LIMIT:
        raise ValueError(f"List limit must be between 1 and {MAX_LIMIT}")
    cursor = "" if after is None else _identifier(after)
    rows = store.db.execute(f"SELECT {_COLUMNS} FROM items WHERE status=? AND id>? ORDER BY id LIMIT ?",
                            (status, cursor, limit + 1)).fetchall()
    shown = rows[:limit]
    return {"items": [_summary(row) for row in shown],
            "next_cursor": shown[-1]["id"] if len(rows) > limit else None}


def show_item(store, item_id) -> dict:
    """Inspect saved source and structured final review, never raw provider output."""
    row = store.db.execute(f"SELECT {_COLUMNS} FROM items WHERE id=?", (_identifier(item_id),)).fetchone()
    if row is None:
        raise ValueError("Source item was not found")
    result = _summary(row)
    result["saved_item"] = _object(row["payload"])
    result["final_review"] = _final_review(store, item_id)
    result["actions"] = [dict(action) for action in store.db.execute(
        """SELECT action_id,action,content_hash,reason,created_at,before_status,before_attempts,before_rejections
            FROM rejection_actions WHERE item_id=? ORDER BY action_id DESC LIMIT ?""", (item_id, HISTORY_LIMIT))]
    return result


def _final_review(store, item_id):
    """The current job or, once a commit finished the current revision, the decision that commit recorded, if any
    (stage "finished"): its candidate, source packet, coverage and latest verdict, as saved."""
    # Only a commit sets these statuses, and it writes the item's newest audit row.
    row = store.db.execute("SELECT stage,CAST(record_json AS BLOB) AS record_json FROM review_jobs WHERE item_id=?",
                           (item_id,)).fetchone() or store.db.execute(
        """SELECT 'finished' AS stage,CAST(review_record AS BLOB) AS record_json FROM analyses WHERE source_item_id=?1
        AND (SELECT status FROM items WHERE id=?1) IN ('ignored','published') ORDER BY rowid DESC LIMIT 1""", (item_id,)).fetchone()
    if row is None or row["record_json"] is None:
        return None
    record = _object(row["record_json"])
    try:
        prepared = record.get("prepared", {})
        reviews = record.get("reviews") or record.get("approval", {}).get("reviews", [])
        latest = reviews[-1] if reviews else None
        return {"stage": row["stage"], "candidate": record.get("candidate", prepared.get("candidate")),
                "source_packet": prepared.get("packet"), "coverage": prepared.get("coverage"),
                "latest_review": latest and {**latest["result"], "phase": latest["stage"],
                                             "candidate_hash": latest["candidate_hash"]}}
    except (TypeError, KeyError, AttributeError):
        # A damaged record must not hide the item and its actions.
        return {"stage": row["stage"], "error": "Saved review record cannot be read"}


def _request(item_id, expected_hash, reason, observed):
    _identifier(item_id)
    if not isinstance(expected_hash, str) or not editorial._HASH.fullmatch(expected_hash):
        raise ValueError("Expected content hash must be its 64-character lowercase hexadecimal value")
    return editorial._text(reason, "operator reason", 1000), format_utc(parse_utc(observed or now_iso()))


def _checked(db, item_id, expected_hash, *, statuses):
    """Require the inspected source revision and a queue state the action applies to."""
    row = db.execute(f"SELECT {_COLUMNS} FROM items WHERE id=?", (item_id,)).fetchone()
    if row is None:
        raise ValueError("Source item was not found")
    if row["content_hash"] != expected_hash:
        raise ValueError("Source content changed; inspect the current item before acting")
    failed_pending = (row["status"] == "pending" and type(row["attempts"]) is int
                      and row["attempts"] > 0 and isinstance(row["last_error"], str)
                      and bool(row["last_error"].strip()))
    if row["status"] not in statuses and not failed_pending:
        raise ValueError("Only a terminally rejected or previously failed pending item can be retried or dismissed, "
                         "or a dismissed or ignored one retried")
    return dict(row)


def _ready(row):
    """Refuse to queue a structurally unreadable/cold item for model analysis."""
    payload = _object(row["payload"]) or {}
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
    except (ValueError, KeyError):
        raise ValueError("Stored source item is incomplete or unreadable and cannot be retried") from None


def _act(store, item_id, expected_hash, reason, action, observed):
    """Apply one guarded queue action and record its audit in the same transaction."""
    reason, stamp = _request(item_id, expected_hash, reason, observed)
    db = store.db
    with db:
        # Retry also undoes a dismissal or reconsiders an ignored item;
        # dismissing applies only to a rejected or previously failed revision.
        statuses = {"rejected", "dismissed", "ignored"} if action == "retry" else {"rejected"}
        row = _checked(db, item_id, expected_hash, statuses=statuses)
        if action == "retry":
            _ready(row)
        update = ("status='pending',attempts=0,rejections=0,next_attempt_at=NULL,last_error=NULL"
                  if action == "retry" else "status='dismissed',next_attempt_at=NULL")
        changed = db.execute(f"""UPDATE items SET {update}
            WHERE id=? AND content_hash=? AND CAST(payload AS BLOB)=? AND status=? AND attempts=?
            AND rejections=? AND last_error IS ? AND next_attempt_at IS ?""",
            (item_id, expected_hash, row["payload"], row["status"], row["attempts"],
             row["rejections"], row["last_error"], row["next_attempt_at"])).rowcount
        if changed != 1:
            raise ValueError("Source item changed during the action; inspect it again")
        event = db.execute("""INSERT INTO rejection_actions
            (item_id,content_hash,action,reason,created_at,before_status,before_attempts,
             before_rejections,before_error,before_next_attempt_at) VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (item_id, expected_hash, action, reason, stamp, row["status"], row["attempts"],
             row["rejections"], row["last_error"], row["next_attempt_at"]))
        if action == "retry":
            from .review_gate import reset_review_work
            reset_review_work(store, item_id)
    return {"item_id": item_id, "content_hash": expected_hash, "action": action,
            "status": "pending" if action == "retry" else "dismissed", "action_id": event.lastrowid}


def retry_item(store, item_id, expected_hash, reason, observed=None) -> dict:
    """Queue one failed, dismissed or ignored revision again."""
    return _act(store, item_id, expected_hash, reason, "retry", observed)


def dismiss_item(store, item_id, expected_hash, reason, observed=None) -> dict:
    """Stop this revision; a genuinely changed upstream payload may queue again."""
    return _act(store, item_id, expected_hash, reason, "dismiss", observed)
