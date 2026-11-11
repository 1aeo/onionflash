"""Private operator controls for failed, dismissed or explicitly reconsidered source items.

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


# The payload is read as bytes, so a value that is not even UTF-8 reaches _payload instead of failing the query.
_COLUMNS = "id,content_hash,source_id,status,attempts,rejections,next_attempt_at,story_id,url,last_error,CAST(payload AS BLOB) AS payload"


def _payload(row):
    """The saved item, or None when its JSON is damaged, so one bad row cannot hide the others."""
    try:
        payload = json.loads(row["payload"])
    except (TypeError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def _summary(row):
    result = {key: row[key] for key in ("id", "content_hash", "source_id", "status", "attempts", "rejections", "next_attempt_at", "story_id")}
    # The CLI escapes printed text, so stored values are shown as the app wrote them.
    result.update(source_url=row["url"], rejection_reason=row["last_error"], title=(_payload(row) or {}).get("title"))
    return result


def list_items(store, *, status="rejected", limit=50, after=None) -> dict:
    """Bounded, stable ID pagination; transient pending failures are excluded."""
    if not isinstance(status, str) or status not in {"rejected", "dismissed"}:
        raise ValueError("List status must be rejected or dismissed")
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
    result["saved_item"] = _payload(row)
    result["final_review"] = _final_review(store, item_id)
    result["actions"] = [dict(action) for action in store.db.execute(
        """SELECT action_id,action,content_hash,reason,created_at,before_status,before_attempts,before_rejections
            FROM rejection_actions WHERE item_id=? ORDER BY action_id DESC LIMIT ?""", (item_id, HISTORY_LIMIT))]
    return result


def _final_review(store, item_id):
    """The current job's stage, candidate, source packet and latest verdict, as saved."""
    row = store.db.execute("SELECT stage,record_json FROM review_jobs WHERE item_id=?", (item_id,)).fetchone()
    if row is None:
        return None
    try:
        record = json.loads(row["record_json"])
        prepared = record.get("prepared", {})
        reviews = record.get("reviews") or record.get("approval", {}).get("reviews", [])
        latest = reviews[-1] if reviews else None
        return {"stage": row["stage"], "candidate": record.get("candidate", prepared.get("candidate")),
                "source_packet": prepared.get("packet"),
                "latest_review": latest and {**latest["result"], "phase": latest["stage"],
                                             "candidate_hash": latest["candidate_hash"]}}
    except (ValueError, TypeError, KeyError, AttributeError):
        # A damaged record must not hide the item and its actions.
        return {"stage": row["stage"], "error": "Saved review record cannot be read"}


def _request(item_id, expected_hash, reason, observed):
    _identifier(item_id)
    if not isinstance(expected_hash, str) or not editorial._HASH.fullmatch(expected_hash):
        raise ValueError("Expected content hash must be its 64-character lowercase hexadecimal value")
    return editorial._text(reason, "operator reason", 1000), format_utc(parse_utc(observed or now_iso()))


def _checked(db, item_id, expected_hash, *, statuses, retired_source_ids=()):
    """Require the inspected source revision and a queue state the action applies to."""
    row = db.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
    if row is None:
        raise ValueError("Source item was not found")
    if row["content_hash"] != expected_hash:
        raise ValueError("Source content changed; inspect the current item before acting")
    if row["source_id"] in retired_source_ids:
        raise ValueError("Retired alert sources cannot be retried")
    failed_pending = (row["status"] == "pending" and type(row["attempts"]) is int
                      and row["attempts"] > 0 and isinstance(row["last_error"], str)
                      and bool(row["last_error"].strip()))
    if row["status"] not in statuses and not failed_pending:
        raise ValueError("Only a terminally rejected or previously failed pending item can be retried or dismissed, "
                         "or a dismissed one retried; ignored items require retry --reconsider-ignored")
    return dict(row)


def _ready(row):
    """Refuse to queue a structurally unreadable/cold item for model analysis."""
    try:
        payload = json.loads(row["payload"])
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
    except (ValueError, TypeError, KeyError, AttributeError):
        raise ValueError("Stored source item is not ready for analysis; restore or recollect it first") from None


def _act(store, item_id, expected_hash, reason, action, observed, *, reconsider_ignored=False, retired_source_ids=()):
    """Apply one guarded queue action and record its audit in the same transaction."""
    if type(reconsider_ignored) is not bool or (reconsider_ignored and action != "retry"):
        raise ValueError("Reconsidering ignored items is an explicit retry option")
    reason, stamp = _request(item_id, expected_hash, reason, observed)
    db = store.db
    with db:
        # Retry also undoes a dismissal, and reconsiders an ignored item only on explicit request;
        # dismissing applies only to a rejected or previously failed revision.
        statuses = ({"rejected", "dismissed", *(["ignored"] if reconsider_ignored else [])}
                    if action == "retry" else {"rejected"})
        row = _checked(db, item_id, expected_hash, statuses=statuses, retired_source_ids=retired_source_ids)
        if action == "retry":
            _ready(row)
        update = ("status='pending',attempts=0,rejections=0,next_attempt_at=NULL,last_error=NULL"
                  if action == "retry" else "status='dismissed',next_attempt_at=NULL")
        changed = db.execute(f"""UPDATE items SET {update}
            WHERE id=? AND source_id=? AND content_hash=? AND payload=? AND status=? AND attempts=?
            AND rejections=? AND last_error IS ? AND next_attempt_at IS ?""",
            (item_id, row["source_id"], expected_hash, row["payload"], row["status"], row["attempts"],
             row["rejections"], row["last_error"], row["next_attempt_at"])).rowcount
        if changed != 1:
            raise ValueError("Source item changed during the action; inspect it again")
        event = db.execute("""INSERT INTO rejection_actions
            (item_id,content_hash,action,reason,created_at,before_status,before_attempts,
             before_rejections,before_error,before_next_attempt_at) VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (item_id, expected_hash, action, reason, stamp, row["status"], row["attempts"],
             row["rejections"], row["last_error"], row["next_attempt_at"]))
        if action == "retry":
            from .review_gate import discard_review_decisions, reset_review_work
            if row["status"] == "ignored":
                discard_review_decisions(store, item_id)
            reset_review_work(store, item_id)
    return {"item_id": item_id, "content_hash": expected_hash, "action": action,
            "status": "pending" if action == "retry" else "dismissed", "action_id": event.lastrowid}


def retry_item(store, item_id, expected_hash, reason, observed=None, *, reconsider_ignored=False,
               retired_source_ids=()) -> dict:
    """Queue one failed or dismissed revision again, unless its configured source is retired."""
    return _act(store, item_id, expected_hash, reason, "retry", observed,
                reconsider_ignored=reconsider_ignored, retired_source_ids=retired_source_ids)


def dismiss_item(store, item_id, expected_hash, reason, observed=None) -> dict:
    """Stop this revision; a genuinely changed upstream payload may queue again."""
    return _act(store, item_id, expected_hash, reason, "dismiss", observed)
