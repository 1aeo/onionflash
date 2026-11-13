"""A private log of every terminal decision, and the summary built from it.

Each outcome writes its row in the transaction that applies it, so the log and the
item states cannot disagree. The log never reaches public output. See
docs/DECISIONS.md, which lists every code.
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict

from .util import after, format_utc, parse_utc, saved_object

CODES = frozenset({
    "published.new", "published.update",
    *(f"skipped.{stage}.{reason}" for stage in ("review", "verification")
      for reason in ("news_value", "new_information", "new_information_and_news_value")),
    "skipped.gate.not_recent", "skipped.gate.retired_story", "skipped.gate.no_new_content",
    "held.gate.missing_sources", "held.gate.repeat_hold", "held.gate.story_locked",
    *(f"held.{stage}.{reason}" for stage in ("review", "verification")
      for reason in ("model_hold", "tag_repair", "unusable_repair", "repeated_repair", "disagreed_news", "release_labels")),
    "held.verification.official_not_news", "held.verification.repairs_exhausted",
    *(f"held.final_check.{reason}" for reason in ("completed_action", "compromise_headline", "confirmed_source", "merge_state")),
    *(f"failed.writer.{reason}" for reason in ("invalid_output", "evidence_too_short", "evidence_not_exact",
                                               "no_literal_evidence", "invalid_input", "truncated", "invalid_json")),
    *(f"failed.review.{reason}" for reason in ("invalid_reply", "invalid_input", "truncated", "invalid_json")),
    "failed.app.invalid_tag_name", "failed.app.unexpected", "failed.app.damaged_item", "failed.app.damaged_job",
    "operator.retried", "operator.reconsidered", "operator.dismissed", "operator.approved",
})
EDITORIAL = ("new_information", "news_value")
EXAMPLES = 3  # newest examples per code in the summary
AWAITING = 20  # rejected items the summary lists, oldest decision first
MAX_LIMIT = 200
HISTORY_LIMIT = 20
# The deployment refuses to upload a file over 10 MiB; feed.xml grows with the stories it carries,
# so the summary asks for a split by year at half that.
FEED_LIMIT_BYTES = 10 * 1024 * 1024
FEED_SPLIT_BYTES = FEED_LIMIT_BYTES // 2
_PREFIX = re.compile(r"[a-z_]+(?:\.[a-z_]+){0,2}\Z")
_COLUMNS = "id,decided_at,code,subject,item_id,content_hash,source_id,story_id,CAST(detail_json AS BLOB) AS detail"


def _reviews(record) -> list:
    """The reviews behind a decision: those of a reused approval, or the record's own."""
    if not isinstance(record, dict):
        return []
    approval = record.get("approval")
    approved = approval.get("reviews") if isinstance(approval, dict) else None
    reviews = approved if isinstance(approved, list) and approved else record.get("reviews")
    return reviews if isinstance(reviews, list) else []


def skip_code(record, verdict: dict) -> str:
    """A skip's code: the stage of the review that decided it and its failed editorial criteria."""
    reviews = _reviews(record)
    stage = "verification" if reviews and isinstance(reviews[-1], dict) and reviews[-1].get("stage") == "verification" else "review"
    failed = [name for name in EDITORIAL if verdict["criteria"][name]["outcome"] != "pass"]
    return f"skipped.{stage}.{'_and_'.join(failed)}"


def _title(payload) -> str | None:
    title = (saved_object(payload) or {}).get("title")
    return title[:200] if isinstance(title, str) else None


def _detail(row, code, review, extra) -> dict:
    detail = {"title": _title(row["payload"]), "url": row["url"]} if row else {"title": None, "url": None}
    try:
        reviews = _reviews(review)
        verdicts = [f"{entry['stage']}:{entry['result']['verdict']}" for entry in reviews]
        criteria = {name: f"{check['outcome']}: {check['reason']}"
                    for name, check in reviews[-1]["result"]["criteria"].items() if check["outcome"] != "pass"
                    } if reviews and code.startswith(("skipped.", "held.")) else None
    except (TypeError, KeyError, AttributeError):  # a damaged record keeps the title and URL
        verdicts, criteria = [], None
    if verdicts:
        detail["verdicts"] = verdicts
    if criteria:
        detail["criteria"] = criteria
    writer = review.get("writer") if isinstance(review, dict) else None
    if isinstance(writer, dict) and writer.get("clears") and code.startswith(("published.", "skipped.", "held.")):
        detail["writer_clears"] = writer["clears"]
    prepared = review.get("prepared") if isinstance(review, dict) else None
    if isinstance(prepared, dict) and prepared.get("mode") in {"story", "update"}:
        detail["scope"] = prepared["mode"]
    detail.update((key, value[:300] if isinstance(value, str) else value) for key, value in extra.items() if value is not None)
    return detail


def record(db, item_id: str, code: str, observed: str, *, review: dict | None = None, **extra) -> None:
    """Append one decision about an item to the caller's transaction.

    Only a database error raises: detail that cannot be read is left out, so an
    unexpected record never undoes the outcome it describes."""
    row = db.execute("SELECT content_hash,source_id,story_id,url,CAST(payload AS BLOB) AS payload FROM items WHERE id=?",
                     (item_id,)).fetchone()
    try:
        detail = json.dumps(_detail(row, code, review, extra), ensure_ascii=False, sort_keys=True, allow_nan=False)
        detail.encode("utf-8")
    except Exception:  # never let the log's own detail stop the outcome
        detail = "{}"
    columns = (row["content_hash"], row["source_id"], row["story_id"]) if row else (None, None, None)
    db.execute("""INSERT INTO decision_log(decided_at,subject,item_id,content_hash,source_id,story_id,code,detail_json)
        VALUES(?,?,?,?,?,?,?,?)""", (observed, item_id, item_id, *columns, code, detail))


def latest_id(db) -> int:
    return db.execute("SELECT COALESCE(MAX(id),0) FROM decision_log").fetchone()[0]


def codes_after(db, first: int) -> dict:
    """Decisions logged after id `first`, by code: what one run decided."""
    return dict(db.execute("SELECT code,COUNT(*) FROM decision_log WHERE id>? GROUP BY code ORDER BY code", (first,)))


def recent(db, observed: str) -> dict:
    """Decisions of the last 24 hours, by outcome."""
    return dict(db.execute("""SELECT substr(code,1,instr(code,'.')-1) AS outcome,COUNT(*) FROM decision_log
        WHERE decided_at>=? GROUP BY outcome ORDER BY outcome""", (after(-86400, observed),)))


def window(text: str, observed: str | None = None) -> str:
    """The start of a --since window: hours or days before now (such as 7d), or an aware timestamp."""
    match = re.fullmatch(r"([1-9][0-9]{0,4})([hd])", text) if isinstance(text, str) else None
    if match:
        return after(-int(match[1]) * (3600 if match[2] == "h" else 86400), observed)
    try:
        return format_utc(parse_utc(text))
    except ValueError:
        raise ValueError("--since must be hours or days, such as 7d, or a timestamp with a time zone") from None


def _entry(row) -> dict:
    entry = dict(row)
    entry["detail"] = saved_object(entry.pop("detail"))
    return entry


def list_entries(db, since: str, *, code: str | None = None, source: str | None = None,
                 limit: int = 50, after: int | None = None) -> dict:
    """Decisions since `since`, newest first, by code or dotted code prefix and source, with a cursor."""
    if type(limit) is not int or not 1 <= limit <= MAX_LIMIT:
        raise ValueError(f"List limit must be between 1 and {MAX_LIMIT}")
    if code is not None and not _PREFIX.fullmatch(code):
        raise ValueError("Code must be a decision code or its dotted prefix, such as held.review")
    if after is not None and (type(after) is not int or after < 1):
        raise ValueError("Cursor must be the next_cursor of the previous list")
    rows = db.execute(f"""SELECT {_COLUMNS} FROM decision_log WHERE decided_at>=?1
        AND (?2 IS NULL OR code=?2 OR substr(code,1,length(?2)+1)=?2||'.') AND (?3 IS NULL OR source_id=?3)
        AND (?4 IS NULL OR id<?4) ORDER BY id DESC LIMIT ?5""", (since, code, source, after, limit + 1)).fetchall()
    shown = rows[:limit]
    return {"decisions": [_entry(row) for row in shown], "next_cursor": shown[-1]["id"] if len(rows) > limit else None}


def for_item(db, item_id: str) -> list[dict]:
    """An item's newest decisions, which keep its history after collection clears last_error."""
    return [_entry(row) for row in db.execute(
        f"SELECT {_COLUMNS} FROM decision_log WHERE item_id=? ORDER BY id DESC LIMIT ?", (item_id, HISTORY_LIMIT))]


def feed_size(db) -> dict:
    """feed.xml's size in the publication ledger, against the deployment's per-file limit."""
    size = None
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='public_artifacts'").fetchone():
        row = db.execute("SELECT size FROM public_artifacts WHERE path='feed.xml'").fetchone()
        size = row[0] if row else None
    return {"path": "feed.xml", "bytes": size, "limit_bytes": FEED_LIMIT_BYTES,
            "action": "ACTION: split the feeds by year" if size is not None and size >= FEED_SPLIT_BYTES else None}


def summary(db, since: str) -> dict:
    """Decisions since `since` with examples, what awaits the operator, and the feed size."""
    outcomes, codes, sources, examples, clears = Counter(), Counter(), defaultdict(Counter), defaultdict(list), 0
    for row in db.execute(f"SELECT {_COLUMNS} FROM decision_log WHERE decided_at>=? ORDER BY id DESC", (since,)):
        code, detail = row["code"], _entry(row)["detail"] or {}
        outcome = code.split(".", 1)[0]
        outcomes[outcome] += 1
        codes[code] += 1
        sources[row["source_id"]][outcome] += 1
        if len(examples[code]) < EXAMPLES:
            examples[code].append({"item_id": row["item_id"], "decided_at": row["decided_at"], **detail})
        clears += detail.get("writer_clears", 0)
    rejected = [{"item_id": item_id, "title": _title(payload), "code": code, "decided_at": decided_at, "reason": reason}
                for item_id, payload, code, decided_at, reason in db.execute(
                    """SELECT i.id,CAST(i.payload AS BLOB),d.code,d.decided_at,i.last_error FROM items i
                    LEFT JOIN decision_log d ON d.id=(SELECT MAX(id) FROM decision_log WHERE item_id=i.id)
                    WHERE i.status='rejected' ORDER BY d.id,i.id LIMIT ?""", (AWAITING,))]
    return {
        "since": since,
        "outcomes": dict(sorted(outcomes.items())),
        "codes": dict(sorted(codes.items())),
        "sources": {source: dict(sorted(counts.items())) for source, counts in sorted(sources.items(), key=lambda pair: str(pair[0]))},
        "examples": dict(sorted(examples.items())),
        "awaiting_operator": {
            "rejected": db.execute("SELECT COUNT(*) FROM items WHERE status='rejected'").fetchone()[0],
            "items": rejected,
            # Updates held while a story was locked. Unlocking does not apply them, so a story waits until
            # an update of it publishes after its latest hold; held_updates is the story's lifetime count.
            "held_updates": [{"story_id": story_id, "held_updates": held, "locked": bool(locked)} for story_id, held, locked
                             in db.execute("""SELECT story_id,held_updates,locked FROM editorial_controls c WHERE held_updates>0
                                 AND NOT EXISTS (SELECT 1 FROM decision_log WHERE story_id=c.story_id
                                 AND (code GLOB 'published.*' OR code='operator.approved')
                                 AND id>(SELECT COALESCE(MAX(id),0) FROM decision_log WHERE story_id=c.story_id
                                         AND code='held.gate.story_locked')) ORDER BY story_id""")],
        },
        "retrying": db.execute("SELECT COUNT(*) FROM items WHERE status='pending' AND attempts>0").fetchone()[0],
        "story_actions": dict(db.execute("SELECT action,COUNT(*) FROM editorial_revisions WHERE created_at>=? GROUP BY action ORDER BY action", (since,))),
        "feed": feed_size(db),
        "writer_clears": clears,
    }
