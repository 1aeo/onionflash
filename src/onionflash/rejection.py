"""Private operator controls for failed, dismissed or ignored source items.

The CLI must hold the application run lock for retry, dismiss and approve.
These actions never call a model or change editorial correction state; only
approve commits a story, publishing a held candidate exactly as reviewed.
"""

from __future__ import annotations

from . import decisions, editorial, review_gate
from .schema import ITEM_ID_RE, PRODUCTS, SHA256_RE
from .store import _valid_saved_item
from .util import canonical_url, digest, format_utc, now_iso, parse_utc, saved_object

MAX_LIMIT = 200
HISTORY_LIMIT = 20
_COLUMNS = (
    "id,content_hash,source_id,status,attempts,rejections,next_attempt_at,story_id,url,last_error,"
    "typeof(payload) AS payload_type,CAST(payload AS BLOB) AS payload"
)


def _identifier(value: str) -> str:
    if not isinstance(value, str) or not ITEM_ID_RE.fullmatch(value):
        raise ValueError("Item ID must be its 24-character lowercase hexadecimal identity")
    return value


def _saved_payload(row) -> dict | None:
    return saved_object(row["payload"]) if row["payload_type"] == "text" else None


def _summary(row) -> dict:
    result = {key: row[key] for key in ("id", "content_hash", "source_id", "status", "attempts", "rejections", "next_attempt_at", "story_id")}
    title = (_saved_payload(row) or {}).get("title")
    result.update(source_url=row["url"], rejection_reason=row["last_error"], title=title if isinstance(title, str) else None)
    return result


def list_items(store, *, status: str = "rejected", limit: int = 50, after: str | None = None) -> dict:
    """Bounded, stable ID pagination; transient pending failures are excluded."""
    if not isinstance(status, str) or status not in {"rejected", "dismissed", "ignored"}:
        raise ValueError("List status must be rejected, dismissed or ignored")
    if type(limit) is not int or not 1 <= limit <= MAX_LIMIT:
        raise ValueError(f"List limit must be between 1 and {MAX_LIMIT}")
    cursor = "" if after is None else _identifier(after)
    rows = store.db.execute(
        f"SELECT {_COLUMNS} FROM items WHERE status=? AND id>? ORDER BY id LIMIT ?",
        (status, cursor, limit + 1),
    ).fetchall()
    shown = rows[:limit]
    return {"items": [_summary(row) for row in shown], "next_cursor": shown[-1]["id"] if len(rows) > limit else None}


def show_item(store, item_id: str, config: dict | None = None) -> dict:
    """Inspect saved source and structured final review, never raw provider output."""
    row = store.db.execute(f"SELECT {_COLUMNS} FROM items WHERE id=?", (_identifier(item_id),)).fetchone()
    if row is None:
        raise ValueError("Source item was not found")
    result = _summary(row)
    result["saved_item"] = _saved_payload(row)
    result["final_review"] = _final_review(store, item_id, config=config)
    result["actions"] = [dict(action) for action in store.db.execute(
        """SELECT action_id,action,content_hash,reason,created_at,before_status,before_attempts,before_rejections
           FROM rejection_actions WHERE item_id=? ORDER BY action_id DESC LIMIT ?""",
        (item_id, HISTORY_LIMIT),
    )]
    result["decisions"] = decisions.for_item(store.db, item_id)
    return result


def _final_review(store, item_id: str, *, config: dict | None = None):
    row = store.db.execute(
        "SELECT stage,typeof(record_json) AS record_type,CAST(record_json AS BLOB) AS record_json FROM review_jobs WHERE item_id=?",
        (item_id,),
    ).fetchone() or store.db.execute(
        """SELECT 'finished' AS stage,typeof(review_record) AS record_type,CAST(review_record AS BLOB) AS record_json
           FROM analyses WHERE source_item_id=?1
           AND EXISTS(SELECT 1 FROM items WHERE id=?1 AND (status='published'
               OR (status='ignored' AND last_error GLOB 'Final review skipped:*'))) ORDER BY rowid DESC LIMIT 1""",
        (item_id,),
    ).fetchone()
    if row is None or row["record_json"] is None:
        return None
    record = saved_object(row["record_json"]) if row["record_type"] == "text" else None
    extra = {"approval": review_gate.approval(config, store, item_id)} if config is not None and row["stage"] == "held" else {}
    if record is None:
        return {"stage": row["stage"], "error": "Saved review record cannot be read", **extra}
    try:
        prepared = record.get("prepared", {})
        approval = record.get("approval")
        reviews = record.get("reviews") or (approval.get("reviews", []) if isinstance(approval, dict) else [])
        if not isinstance(prepared, dict) or not isinstance(reviews, list):
            raise TypeError
        latest = reviews[-1] if reviews else None
        candidate = record.get("candidate", prepared.get("candidate"))
        return {
            "stage": row["stage"], "hold_code": record.get("hold_code"),
            "candidate": candidate, "candidate_hash": digest(candidate) if isinstance(candidate, dict) else None,
            "base_candidate": prepared.get("candidate"), "source_packet": prepared.get("packet"),
            "coverage": prepared.get("coverage"),
            "reviews": [{
                "phase": entry["stage"], **({"issue": entry["issue"]} if "issue" in entry else {}),
                "verdict": entry["result"]["verdict"], "candidate_hash": entry["candidate_hash"],
                "failed": {n: f"{c['outcome']}: {c['reason']}" for n, c in entry["result"]["criteria"].items() if c["outcome"] != "pass"},
                "repair": entry["result"]["repair"],
            } for entry in reviews],
            "latest_review": latest and {**latest["result"], "phase": latest["stage"], "candidate_hash": latest["candidate_hash"]},
            **({"operator_approval": record["operator_approval"]} if "operator_approval" in record else {}),
            **extra,
        }
    except (TypeError, KeyError, AttributeError):
        return {"stage": row["stage"], "error": "Saved review record cannot be read", **extra}


def _request(item_id: str, expected_hash: str, reason: str, observed: str | None, *,
             hash_label: str = "Expected content hash") -> tuple[str, str]:
    _identifier(item_id)
    if not isinstance(expected_hash, str) or not SHA256_RE.fullmatch(expected_hash):
        raise ValueError(f"{hash_label} must be its 64-character lowercase hexadecimal value")
    return editorial._text(reason, "operator reason", 1000), format_utc(parse_utc(observed or now_iso()))


def _checked(db, item_id: str, expected_hash: str, *, statuses: set[str]) -> dict:
    row = db.execute(f"SELECT {_COLUMNS} FROM items WHERE id=?", (item_id,)).fetchone()
    if row is None:
        raise ValueError("Source item was not found")
    if row["content_hash"] != expected_hash:
        raise ValueError("Source content changed; inspect the current item before acting")
    failed_pending = (row["status"] == "pending" and type(row["attempts"]) is int and row["attempts"] > 0
                      and isinstance(row["last_error"], str) and bool(row["last_error"].strip()))
    if row["status"] not in statuses and not failed_pending:
        raise ValueError("Only a terminally rejected or previously failed pending item can be retried or dismissed, "
                         "or a dismissed or ignored one retried")
    return dict(row)


def _ready(row: dict) -> None:
    payload = _saved_payload(row) or {}
    try:
        if payload.get("id") != row["id"] or not _valid_saved_item(payload):
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


def _act(store, item_id: str, expected_hash: str, reason: str, action: str, observed: str | None) -> dict:
    reason, stamp = _request(item_id, expected_hash, reason, observed)
    db = store.db
    with db:
        statuses = {"rejected", "dismissed", "ignored"} if action == "retry" else {"rejected"}
        row = _checked(db, item_id, expected_hash, statuses=statuses)
        if action == "retry":
            _ready(row)
        update = editorial.RESET_PENDING_SQL if action == "retry" else "status='dismissed',next_attempt_at=NULL"
        changed = db.execute(
            f"""UPDATE items SET {update}
                WHERE id=? AND content_hash=? AND CAST(payload AS BLOB) IS ? AND status=? AND attempts=?
                AND rejections=? AND last_error IS ? AND next_attempt_at IS ?""",
            (item_id, expected_hash, row["payload"], row["status"], row["attempts"],
             row["rejections"], row["last_error"], row["next_attempt_at"]),
        ).rowcount
        if changed != 1:
            raise ValueError("Source item changed during the action; inspect it again")
        event = db.execute(
            """INSERT INTO rejection_actions
               (item_id,content_hash,action,reason,created_at,before_status,before_attempts,
                before_rejections,before_error,before_next_attempt_at) VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (item_id, expected_hash, action, reason, stamp, row["status"], row["attempts"],
             row["rejections"], row["last_error"], row["next_attempt_at"]),
        )
        code = "operator.dismissed" if action == "dismiss" else (
            "operator.reconsidered" if row["status"] == "ignored" else "operator.retried"
        )
        decisions.record(db, item_id, code, stamp, reason=reason, before_status=row["status"], before_error=row["last_error"])
        if action == "retry":
            review_gate.reset_review_work(store, item_id)
        else:
            db.execute("UPDATE review_jobs SET approval_key=NULL WHERE item_id=?", (item_id,))
    return {"item_id": item_id, "content_hash": expected_hash, "action": action,
            "status": "pending" if action == "retry" else "dismissed", "action_id": event.lastrowid}


def retry_item(store, item_id: str, expected_hash: str, reason: str, observed: str | None = None) -> dict:
    """Reset a rejected, dismissed, ignored or failed-pending item back to pending."""
    return _act(store, item_id, expected_hash, reason, "retry", observed)


def dismiss_item(store, item_id: str, expected_hash: str, reason: str, observed: str | None = None) -> dict:
    """Mark a rejected or failed-pending item dismissed and audit the action."""
    return _act(store, item_id, expected_hash, reason, "dismiss", observed)


def approve_item(config, store, item_id: str, approval_hash: str, reason: str, observed: str | None = None) -> dict:
    """Publish a held item whose verified candidate matches `approval_hash`."""
    _identifier(item_id)
    if config is None:
        raise ValueError("Configuration is required to approve a held item")
    reason, stamp = _request(item_id, approval_hash, reason, observed, hash_label="Approval hash")
    return review_gate.approve(config, store, item_id, approval_hash, reason, stamp)
