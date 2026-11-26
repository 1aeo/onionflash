"""Trusted local corrections, retractions and their durable revision record.

Public history contains accepted public snapshots only.
"""

from __future__ import annotations

import hashlib
import json

from .config import DEFAULTS
from .render import (
    _date,
    _iso,
    _sources as _render_sources,
    _text,
    _update,
    pointer_json,
    prepare_story,
    public_json_text,
)
from .schema import (
    CATEGORIES,
    CONFIDENCES,
    FIELD_LIMITS,
    PRIORITIES,
    PRODUCTS,
    PUBLIC_STATES,
    SEMANTIC_FIELDS,
    SHA256_RE,
    STORY_ID_RE,
    UPDATE_CHARS,
)
from .util import (
    _SURROGATE_RE, canonical_url, digest, gitlab_url_variants, has_invalid_text_chars,
    now_iso, saved_object, strict_json, timestamp,
)

FIELDS = frozenset({*SEMANTIC_FIELDS, "sources", "updates"})
_PUBLIC_HISTORY_ACTIONS = frozenset({"correct", "retract", "restore", "unlock"})
PUBLIC_HISTORY_LIMIT = 20
MAX_ALIAS_HOPS = 16
RESET_PENDING_SQL = "status='pending',attempts=0,rejections=0,next_attempt_at=NULL,last_error=NULL"


class RetiredStory(ValueError):
    """A story ID or cluster key recorded as retired cannot be created or edited."""


def retracted_fields(reason: str) -> dict:
    """Public replacement fields shown after an operator retracts a story."""
    return {
        "title": "Retracted story",
        "summary": "This story has been retracted by the publisher. " + reason,
        "why_it_matters": "",
        "priority": "low",
    }


def initialize(db) -> None:
    """Create permanent editorial control, revision, and alias tables and triggers."""
    db.executescript("""
        CREATE TABLE IF NOT EXISTS editorial_controls (
            story_id TEXT PRIMARY KEY, revision INTEGER NOT NULL,
            locked INTEGER NOT NULL, retracted INTEGER NOT NULL,
            notice_action TEXT NOT NULL, notice_reason TEXT NOT NULL, notice_at TEXT NOT NULL,
            held_updates INTEGER NOT NULL DEFAULT 0,
            last_held_at TEXT  -- unused; earlier releases write it after a code rollback
        );
        CREATE TABLE IF NOT EXISTS editorial_revisions (
            story_id TEXT NOT NULL, revision INTEGER NOT NULL,
            action TEXT NOT NULL, reason TEXT NOT NULL, created_at TEXT NOT NULL,
            before_story_json TEXT NOT NULL, before_public_json TEXT,
            after_story_json TEXT NOT NULL, after_public_json TEXT NOT NULL,
            before_hash TEXT NOT NULL, after_hash TEXT NOT NULL,
            PRIMARY KEY(story_id,revision)
        );
        CREATE TABLE IF NOT EXISTS story_aliases (
            story_id TEXT PRIMARY KEY, cluster_key TEXT NOT NULL UNIQUE,
            survivor_id TEXT, reason TEXT NOT NULL, created_at TEXT NOT NULL,
            story_json TEXT
        );
        CREATE TRIGGER IF NOT EXISTS story_aliases_no_replace BEFORE INSERT ON story_aliases
            WHEN EXISTS (SELECT 1 FROM story_aliases WHERE story_id=NEW.story_id OR cluster_key=NEW.cluster_key)
            BEGIN SELECT RAISE(ABORT, 'Story aliases are permanent'); END;
        CREATE TRIGGER IF NOT EXISTS story_aliases_no_update BEFORE UPDATE ON story_aliases
            BEGIN SELECT RAISE(ABORT, 'Story aliases are permanent'); END;
        CREATE TRIGGER IF NOT EXISTS story_aliases_no_delete BEFORE DELETE ON story_aliases
            BEGIN SELECT RAISE(ABORT, 'Story aliases are permanent'); END;
        CREATE TRIGGER IF NOT EXISTS stories_never_recreated BEFORE INSERT ON stories
            WHEN EXISTS (SELECT 1 FROM story_aliases WHERE story_id=NEW.id OR cluster_key=NEW.cluster_key)
            BEGIN SELECT RAISE(IGNORE); END;
        CREATE TRIGGER IF NOT EXISTS editorial_revisions_permanent BEFORE DELETE ON editorial_revisions BEGIN
            SELECT RAISE(ABORT, 'Editorial history is permanent');
        END;
        CREATE TRIGGER IF NOT EXISTS editorial_revisions_unchanged BEFORE UPDATE ON editorial_revisions BEGIN
            SELECT RAISE(ABORT, 'Editorial history is permanent');
        END;
        CREATE TRIGGER IF NOT EXISTS editorial_revisions_append_only BEFORE INSERT ON editorial_revisions
            WHEN EXISTS (SELECT 1 FROM editorial_revisions WHERE story_id=NEW.story_id AND revision=NEW.revision) BEGIN
            SELECT RAISE(ABORT, 'Editorial history is permanent');
        END;
        CREATE TRIGGER IF NOT EXISTS editorial_controls_permanent BEFORE DELETE ON editorial_controls BEGIN
            SELECT RAISE(ABORT, 'Editorial history is permanent');
        END;
        -- Story guards of earlier releases call a function only those releases register,
        -- so left in place they fail every other story write. Automation checks locks itself.
        DROP TRIGGER IF EXISTS editorial_story_insert;
        DROP TRIGGER IF EXISTS editorial_story_update;
        DROP TRIGGER IF EXISTS editorial_story_delete;
    """)
    if db.execute("PRAGMA user_version").fetchone()[0] < 1:
        if "story_json" not in {row[1] for row in db.execute("PRAGMA table_info(story_aliases)")}:
            db.execute("ALTER TABLE story_aliases ADD COLUMN story_json TEXT")


def retired(db, *, story_id: str | None = None, cluster_key: str | None = None) -> tuple[str, str | None] | None:
    """Resolve a retired or merged story ID or cluster key to (first_id, final_survivor_or_None)."""
    row = (db.execute("SELECT story_id,survivor_id FROM story_aliases WHERE story_id=?", (story_id,)).fetchone()
           if story_id else None)
    if row is None and cluster_key:
        row = db.execute("SELECT story_id,survivor_id FROM story_aliases WHERE cluster_key=?", (cluster_key,)).fetchone()
    if row is None:
        return None
    first_id, survivor = row["story_id"], row["survivor_id"]
    seen = {first_id}
    for _ in range(MAX_ALIAS_HOPS):
        if survivor is None:
            return first_id, None
        if survivor in seen:
            raise ValueError("Story alias loop")
        seen.add(survivor)
        next_row = db.execute("SELECT survivor_id FROM story_aliases WHERE story_id=?", (survivor,)).fetchone()
        if next_row is None:
            return first_id, survivor
        survivor = next_row["survivor_id"]
    raise ValueError("Story alias loop")


def _id(value: str) -> str:
    if not isinstance(value, str) or not STORY_ID_RE.fullmatch(value):
        raise ValueError("Invalid story ID")
    return value


def _require_expect_hash(expect_hash: object) -> None:
    if not isinstance(expect_hash, str) or not SHA256_RE.fullmatch(expect_hash):
        raise ValueError("A current expected story hash is required")


def clean_text(value: object, name: str, limit: int, *, empty: bool = False) -> str:
    """Validate and strip bounded operator or public text, rejecting XML-unsafe characters."""
    # Reasons reach XML feeds as written, and XML cannot carry U+FFFE or U+FFFF.
    if not isinstance(value, str) or len(value) > limit or has_invalid_text_chars(value):
        raise ValueError(f"Invalid {name}")
    value = value.strip()
    if not value and not empty:
        raise ValueError(f"{name} must not be empty")
    return value


def _strip_surrogates(value: object):
    if isinstance(value, str):
        return _SURROGATE_RE.sub("", value)
    if isinstance(value, list):
        return [_strip_surrogates(item) for item in value]
    if isinstance(value, dict):
        return {(_strip_surrogates(k) if isinstance(k, str) else k): _strip_surrogates(v) for k, v in value.items()}
    return value


def _decode_utf8(blob: bytes | None, *, replace: bool = False) -> str | None:
    if blob is None:
        return None
    try:
        return str(blob, "utf-8")
    except UnicodeError:
        return blob.decode("utf-8", "replace") if replace else None


def _begin_tx(db):
    from .store import immediate_transaction

    return immediate_transaction(db, "Editorial action needs a fresh transaction")


def _enqueue_render(db, story_id: str) -> None:
    db.execute("DELETE FROM public_render_queue WHERE story_id=?", (story_id,))
    db.execute("INSERT INTO public_render_queue(rowid,story_id) SELECT IFNULL(MIN(rowid),0)-1,? FROM public_render_queue", (story_id,))


def _held_item_ids(db, story_id: str, cluster_key: str | None = None) -> list[str]:
    where = "story_id=?" if cluster_key is None else "(story_id=? OR (story_id IS NULL AND cluster_key=?))"
    params = (story_id, story_id) if cluster_key is None else (story_id, cluster_key, story_id)
    return [
        r[0]
        for r in db.execute(
            f"""SELECT id FROM items WHERE status='published' AND {where}
                AND EXISTS (SELECT 1 FROM decision_log d
                    WHERE d.id=(SELECT MAX(id) FROM decision_log WHERE item_id=items.id)
                    AND d.story_id=? AND d.code='held.gate.story_locked'
                    AND d.content_hash=items.content_hash)""",
            params,
        ).fetchall()
    ]


def requeue_items(db, item_ids: list[str]) -> None:
    """Requeue held work while retaining its durable review budget."""
    if not item_ids:
        return
    marks = ",".join("?" * len(item_ids))
    db.execute(f"UPDATE items SET {RESET_PENDING_SQL} WHERE id IN ({marks})", item_ids)


def _published(db, story_id: str) -> dict | None:
    row = db.execute(
        "SELECT CASE WHEN typeof(public_json)='text' THEN CAST(public_json AS BLOB) END AS public_json,json_sha256 "
        "FROM public_catalog WHERE story_id=?",
        (story_id,),
    ).fetchone()
    if row is None:
        return None
    raw_blob = row["public_json"]
    if raw_blob is None or hashlib.sha256(raw_blob).hexdigest() != row["json_sha256"]:
        raise ValueError("Published story snapshot failed its integrity check")
    if (raw_text := _decode_utf8(raw_blob)) is None:
        raise ValueError("Published story snapshot failed its integrity check")
    try:
        public = json.loads(raw_text)
    except (ValueError, RecursionError) as exc:
        raise ValueError("Published story snapshot failed its integrity check") from exc
    if not isinstance(public, dict):
        raise ValueError("Published story snapshot failed its integrity check")
    public = _strip_surrogates(public)
    public.pop("editorial", None)  # Revision history is stored separately, never recursively.
    return public


def _legacy_public(published: object, story_id: str) -> dict:
    if not isinstance(published, dict) or published.get("id") != story_id:
        raise ValueError("Story has no valid public snapshot to correct")
    title = _text(published.get("title"), FIELD_LIMITS["title"])
    summary = _text(published.get("summary"), FIELD_LIMITS["summary"])
    raw_sources = published.get("sources")
    if not title or not summary or not isinstance(raw_sources, list):
        raise ValueError("Story has no valid public snapshot to correct")
    published_dt = _date(published.get("published_at"))
    updated_dt = max(published_dt, _date(published.get("updated_at")))
    added_dt = _date(published.get("added_at") or published.get("published_at"))
    category = published.get("category", "network")
    safe_sources = _render_sources(raw_sources, FIELD_LIMITS["max_sources"])
    kept_sources = safe_sources or [
        {"url": s["url"], "title": _text(s.get("title"), FIELD_LIMITS["source_title"]) or s["url"]}
        for s in raw_sources[:FIELD_LIMITS["max_sources"]]
        if isinstance(s, dict) and isinstance(s.get("url"), str) and s["url"]
    ]
    raw_tags = published.get("tags")
    tags = list(dict.fromkeys(
        tag for tag in [category, *(raw_tags if isinstance(raw_tags, list) else [])]
        if isinstance(tag, str) and tag in CATEGORIES
    ))
    raw_products = published.get("products")
    products = list(dict.fromkeys(
        p for p in (raw_products if isinstance(raw_products, list) else [])
        if isinstance(p, str) and p in PRODUCTS
    ))
    public = {
        "id": story_id,
        "title": title,
        "summary": summary,
        "why_it_matters": _text(published.get("why_it_matters"), FIELD_LIMITS["why_it_matters"]),
        "category": category,
        "priority": published.get("priority", "normal"),
        "confidence": published.get("confidence", "reported"),
        "state": published.get("state", "developing"),
        "tags": tags,
        "sources": kept_sources,
        "products": products,
        "published_at": _iso(published_dt),
        "updated_at": _iso(updated_dt),
        "added_at": _iso(added_dt),
    }
    raw_updates = published.get("updates")
    updates = [entry for entry in map(_update, raw_updates if isinstance(raw_updates, list) else []) if entry]
    if updates:
        public["updates"] = updates
    raw_notes = published.get("alert_notes")
    notes = [
        note for note in (_text(item, 600) for item in (raw_notes if isinstance(raw_notes, list) else [])[:FIELD_LIMITS["max_alert_notes"]])
        if note
    ]
    if notes:
        public["alert_notes"] = list(dict.fromkeys(notes))
    if published.get("origin") == "network-health":
        public["origin"] = "network-health"
    return public


def _snapshot(db, story_id: str, expect_hash: str | None = None) -> dict:
    _id(story_id)
    alias = retired(db, story_id=story_id)
    if alias is not None:
        raise RetiredStory(f"Story was merged into {alias[1]}" if alias[1] else "Story is retired")
    row = db.execute(
        "SELECT id,cluster_key,typeof(payload) AS payload_type,CAST(payload AS BLOB) AS payload_blob,published_at,updated_at FROM stories WHERE id=?",
        (story_id,),
    ).fetchone()
    if row is None:
        raise ValueError("Unknown story; restore its stored record before editing")
    payload_text = None
    if row["payload_type"] == "text":
        try:
            payload_text = str(row["payload_blob"], "utf-8")
        except UnicodeError:
            payload_text = None
    record = {
        "id": row["id"],
        "cluster_key": row["cluster_key"],
        "payload": payload_text if payload_text is not None else strict_json({"damaged_payload_hex": row["payload_blob"].hex()}),
        "published_at": row["published_at"],
        "updated_at": row["updated_at"],
    }
    control_row = db.execute(
        """SELECT story_id,revision,locked,retracted,held_updates,
                  CASE WHEN typeof(notice_action)='text' THEN CAST(notice_action AS BLOB) END AS _notice_action,
                  CASE WHEN typeof(notice_reason)='text' THEN CAST(notice_reason AS BLOB) END AS _notice_reason,
                  CASE WHEN typeof(notice_at)='text' THEN CAST(notice_at AS BLOB) END AS _notice_at
           FROM editorial_controls WHERE story_id=?""",
        (story_id,),
    ).fetchone()
    control = (
        {
            "story_id": control_row["story_id"],
            "revision": control_row["revision"],
            "locked": control_row["locked"],
            "retracted": control_row["retracted"],
            "held_updates": control_row["held_updates"],
            "notice_action": _decode_utf8(control_row["_notice_action"]),
            "notice_reason": _decode_utf8(control_row["_notice_reason"]),
            "notice_at": _decode_utf8(control_row["_notice_at"]),
        }
        if control_row
        else None
    )
    is_retracted = bool(control and control["retracted"])
    published = _published(db, story_id)
    fallback = False
    try:
        if row["payload_type"] != "text" or (original := saved_object(row["payload_blob"])) is None:
            raise ValueError("Damaged story payload")
        public = prepare_story(original, allow_empty_sources=is_retracted)
        if public["id"] != story_id:
            raise ValueError("Story identity differs from its database row")
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        if published is None or published.get("id") != story_id:
            raise ValueError("Story has no valid public snapshot to correct") from None
        original = {}
        try:
            public = prepare_story(published, allow_empty_sources=is_retracted)
        except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
            public = _legacy_public(published, story_id)
        if public["id"] != story_id:
            raise ValueError("Story has no valid public snapshot to correct") from None
        fallback = True
    revision = control["revision"] if control else 0
    fingerprint_parts = [record, revision, bool(control and control["locked"]), bool(control and control["retracted"])]
    if fallback:
        fingerprint_parts.append(public)
    fingerprint = digest(fingerprint_parts)
    if expect_hash is not None and fingerprint != expect_hash:
        raise ValueError("Story changed since it was reviewed; refresh its hash before editing")
    return {"record": record, "raw": original, "public": public, "published": published,
            "control": control, "revision": revision, "hash": fingerprint, "fallback": fallback}


def show(db, story_id: str) -> dict:
    """Return the current editorial state, compare-and-swap hash, and snapshots for a story."""
    current = _snapshot(db, story_id)
    control = current["control"] or {}
    return {"story_id": story_id, "revision": current["revision"], "hash": current["hash"],
            "locked": bool(control.get("locked")), "retracted": bool(control.get("retracted")),
            "held_updates": control.get("held_updates", 0), "story": current["public"],
            "published_story": current["published"], "using_last_published_snapshot": current["fallback"]}


def history(db, story_id: str) -> dict:
    """Return the append-only editorial revision history for `story_id`, newest first."""
    revisions = []
    for row in db.execute(
        """SELECT story_id,revision,
                  typeof(action) AS _action_t,CAST(action AS BLOB) AS _action_b,
                  typeof(reason) AS _reason_t,CAST(reason AS BLOB) AS _reason_b,
                  typeof(created_at) AS _created_at_t,CAST(created_at AS BLOB) AS _created_at_b,
                  typeof(before_story_json) AS _before_story_t,CAST(before_story_json AS BLOB) AS _before_story_b,
                  typeof(before_public_json) AS _before_public_t,CAST(before_public_json AS BLOB) AS _before_public_b,
                  typeof(after_story_json) AS _after_story_t,CAST(after_story_json AS BLOB) AS _after_story_b,
                  typeof(after_public_json) AS _after_public_t,CAST(after_public_json AS BLOB) AS _after_public_b,
                  typeof(before_hash) AS _before_hash_t,CAST(before_hash AS BLOB) AS _before_hash_b,
                  typeof(after_hash) AS _after_hash_t,CAST(after_hash AS BLOB) AS _after_hash_b
           FROM editorial_revisions WHERE story_id=? ORDER BY revision DESC""",
        (_id(story_id),),
    ):
        record = {"story_id": row["story_id"], "revision": row["revision"]}
        for col in ("action", "reason", "created_at", "before_hash", "after_hash"):
            kind, blob = row[f"_{col}_t"], row[f"_{col}_b"]
            if kind == "null" or blob is None:
                record[col] = None
            elif kind == "text":
                record[col] = _strip_surrogates(_decode_utf8(blob, replace=True))
            else:
                record[col] = blob.hex() if isinstance(blob, (bytes, bytearray)) else str(blob)
        for col in ("before_story", "before_public", "after_story", "after_public"):
            kind, blob = row[f"_{col}_t"], row[f"_{col}_b"]
            if kind == "null" or blob is None:
                value = None
            elif kind != "text":
                value = {"unparseable_record": blob.hex() if isinstance(blob, (bytes, bytearray)) else str(blob)}
            elif (raw_text := _decode_utf8(blob)) is None:
                value = {"unparseable_record": _decode_utf8(blob, replace=True)}
            else:
                try:
                    value = _strip_surrogates(json.loads(raw_text))
                except (ValueError, RecursionError):
                    value = {"unparseable_record": _strip_surrogates(raw_text)}
            record[col] = value
        revisions.append(record)
    return {"story_id": story_id, "revisions": revisions}


def is_locked(db, story_id: str) -> bool:
    """Whether `story_id` is currently editorially locked or retracted."""
    return bool(db.execute("SELECT 1 FROM editorial_controls WHERE story_id=? AND (locked=1 OR retracted=1)", (story_id,)).fetchone())


def record_held(db, story_id: str) -> None:
    """Increment the held-update counter for an editorially locked story."""
    db.execute("UPDATE editorial_controls SET held_updates=held_updates+1 WHERE story_id=?", (story_id,))


def _clean_history_updates(raw_updates: object) -> list[dict]:
    if not isinstance(raw_updates, list):
        return []
    cleaned = []
    for upd in raw_updates:
        if not isinstance(upd, dict):
            continue
        try:
            at = timestamp(upd.get("at"))
        except ValueError:
            continue
        if text := _text(upd.get("text"), UPDATE_CHARS):
            cleaned.append({"at": at, "text": text})
    return cleaned


def public_metadata(db, story_id: str) -> dict | None:
    """Build bounded public editorial notice and revision metadata for rendering."""
    control = db.execute(
        """SELECT revision,locked,retracted,
                  CASE WHEN typeof(notice_action)='text' THEN CAST(notice_action AS BLOB) END AS notice_action,
                  CASE WHEN typeof(notice_at)='text' THEN CAST(notice_at AS BLOB) END AS notice_at,
                  CASE WHEN typeof(notice_reason)='text' THEN CAST(notice_reason AS BLOB) END AS notice_reason
           FROM editorial_controls WHERE story_id=?""",
        (story_id,),
    ).fetchone()
    if control is None:
        return None
    if (
        (notice_action := _decode_utf8(control["notice_action"])) is None
        or (notice_at := _decode_utf8(control["notice_at"])) is None
        or (raw_notice_reason := _decode_utf8(control["notice_reason"])) is None
    ):
        raise ValueError("Invalid editorial notice reason")
    notice_reason = _text(raw_notice_reason, 1000)
    rows = db.execute(
        """SELECT revision,
                  CASE WHEN typeof(action)='text' THEN CAST(action AS BLOB) END AS action,
                  CASE WHEN typeof(created_at)='text' THEN CAST(created_at AS BLOB) END AS created_at,
                  CASE WHEN typeof(reason)='text' THEN CAST(reason AS BLOB) END AS reason,
                  CASE WHEN typeof(before_public_json)='text' THEN CAST(before_public_json AS BLOB) END AS before_public_json,
                  CASE WHEN typeof(after_public_json)='text' THEN CAST(after_public_json AS BLOB) END AS after_public_json
           FROM editorial_revisions WHERE story_id=? ORDER BY revision DESC LIMIT ?""",
        (story_id, PUBLIC_HISTORY_LIMIT),
    ).fetchall()
    entries = []
    for row in rows:
        is_current = row["revision"] == control["revision"]
        action = _decode_utf8(row["action"])
        created_at = _decode_utf8(row["created_at"])
        if action is None or created_at is None or action not in _PUBLIC_HISTORY_ACTIONS:
            if not is_current:
                continue
            raise ValueError("Invalid editorial revision")
        if control["retracted"] and not is_current:
            reason_text = ""
        elif (raw_reason := _decode_utf8(row["reason"])) is None:
            if control["retracted"]:
                raise ValueError("Invalid editorial revision reason")
            reason_text = ""
        else:
            reason_text = _text(raw_reason, 1000)
        entry = {"revision": row["revision"], "action": action, "reason": reason_text, "created_at": created_at}
        if row["before_public_json"] is not None and action != "unlock" and not control["retracted"]:
            before = saved_object(row["before_public_json"], allow_surrogates=True)
            if before is not None and before.get("id") == story_id:
                entry["superseded"] = {
                    key: _text(before.get(key, ""), FIELD_LIMITS[key])
                    for key in ("title", "summary", "why_it_matters")
                }
                if (
                    action != "retract"
                    and (after_obj := saved_object(row["after_public_json"], allow_surrogates=True)) is not None
                    and after_obj.get("id") == story_id
                ):
                    kept = {(u["at"], u["text"]) for u in _clean_history_updates(after_obj.get("updates"))}
                    if replaced := [u for u in _clean_history_updates(before.get("updates")) if (u["at"], u["text"]) not in kept]:
                        entry["superseded"]["updates"] = replaced
        entries.append(entry)
    return {"status": "retracted" if control["retracted"] else "corrected", "revision": control["revision"],
            "action": notice_action, "reason": notice_reason, "at": notice_at,
            "history": entries, "history_total": control["revision"]}


def _sources(value, limit: int) -> list[dict]:
    if not isinstance(value, list) or not 1 <= len(value) <= limit:
        raise ValueError(f"Between one and {limit} public sources are required")
    sources = []
    for source in value:
        if not isinstance(source, dict) or set(source) != {"url", "title"}:
            raise ValueError("Sources require only url and title")
        sources.append({"url": canonical_url(source["url"]), "title": clean_text(source["title"], "source title", FIELD_LIMITS["source_title"])})
    if len({s["url"] for s in sources}) != len(sources):
        raise ValueError("Duplicate source URL")
    return sources


def _validated_patch(patch: dict) -> dict:
    if not isinstance(patch, dict) or not patch or set(patch) - FIELDS:
        raise ValueError("Patch must contain only editable story fields")
    clean = dict(patch)
    for field in ("title", "summary", "why_it_matters"):
        if field in clean:
            clean[field] = clean_text(clean[field], field, FIELD_LIMITS[field], empty=field == "why_it_matters")
    for field, allowed in (("category", CATEGORIES), ("priority", PRIORITIES), ("confidence", CONFIDENCES), ("state", PUBLIC_STATES)):
        if field in clean and (not isinstance(clean[field], str) or clean[field] not in allowed):
            raise ValueError(f"Invalid {field}")
    for field, allowed in (("products", PRODUCTS), ("tags", CATEGORIES)):
        if field in clean:
            value = clean[field]
            if not isinstance(value, list) or len(value) > len(allowed) or any(not isinstance(v, str) or v not in allowed for v in value):
                raise ValueError(f"Invalid {field}")
            clean[field] = list(dict.fromkeys(value))
    if "sources" in clean:
        clean["sources"] = _sources(clean["sources"], FIELD_LIMITS["max_sources"])
    if "updates" in clean:
        if not isinstance(clean["updates"], list):
            raise ValueError("Updates must be a list")
        updates = []
        for update in clean["updates"]:
            if not isinstance(update, dict) or set(update) != {"at", "text", "sources"}:
                raise ValueError("Updates require only at, text and sources")
            updates.append({"at": timestamp(update["at"]), "text": clean_text(update["text"], "update text", UPDATE_CHARS),
                            "sources": _sources(update["sources"], FIELD_LIMITS["max_update_sources"])})
        clean["updates"] = updates
    return clean


def _apply(db, story_id: str, action: str, *, reason: str, expect_hash: str,
           patch: dict | None = None, revision: int | None = None, observed: str | None = None) -> dict:
    _id(story_id)
    reason = clean_text(reason, "public reason", 1000)
    _require_expect_hash(expect_hash)
    stamp = timestamp(observed or now_iso())
    with _begin_tx(db):
        current = _snapshot(db, story_id, expect_hash)
        if stamp < current["public"]["updated_at"]:
            raise ValueError("Editorial timestamp must not precede the current story update")
        control = current["control"] or {}
        public = dict(current["public"])
        retracted, locked = bool(control.get("retracted")), True
        notice_action, notice_reason, notice_at = action, reason, stamp
        if action == "correct":
            if retracted:
                raise ValueError("Restore a retracted story before correcting it")
            clean = _validated_patch(patch)
            if "category" in clean and "tags" not in clean and clean["category"] != current["public"]["category"]:
                public["tags"] = [t for t in public.get("tags", []) if t != current["public"]["category"]]
            public.update(clean)
            if prepare_story(public) == current["public"]:
                raise ValueError("Correction does not change any public field")
        elif action == "retract":
            public.update(retracted_fields(reason))
            if not isinstance(public.get("category"), str) or public["category"] not in CATEGORIES:
                public["category"] = "network"
            if not isinstance(public.get("confidence"), str) or public["confidence"] not in CONFIDENCES:
                public["confidence"] = "reported"
            if not isinstance(public.get("state"), str) or public["state"] not in PUBLIC_STATES:
                public["state"] = "developing"
            retracted = True
        elif action == "restore":
            if type(revision) is not int or not 0 <= revision < current["revision"]:
                raise ValueError("Restore requires an earlier revision number (zero is the original accepted text)")
            if revision == 0:
                row = db.execute(
                    """SELECT CASE WHEN typeof(before_public_json)='text' THEN CAST(before_public_json AS BLOB) END,
                              CASE WHEN typeof(before_story_json)='text' THEN CAST(before_story_json AS BLOB) END
                       FROM editorial_revisions WHERE story_id=? AND revision=1""",
                    (story_id,),
                ).fetchone()
            else:
                row = db.execute(
                    """SELECT CASE WHEN typeof(after_public_json)='text' THEN CAST(after_public_json AS BLOB) END
                       FROM editorial_revisions WHERE story_id=? AND revision=? AND action!='retract'""",
                    (story_id, revision),
                ).fetchone()
            previous = None
            candidates = (row[0], row[1]) if revision == 0 and row else ((row[0],) if row else ())
            for raw_candidate in candidates:
                if (cand_obj := saved_object(raw_candidate, allow_surrogates=True)) is None:
                    continue
                cleaned = _strip_surrogates(cand_obj)
                if cleaned.get("id") != story_id:
                    continue
                try:
                    prepared = prepare_story(cleaned)
                except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
                    continue
                if prepared["id"] == story_id:
                    previous = prepared
                    break
            if previous is None:
                raise ValueError("That revision has no accepted public text to restore")
            public.update({key: previous[key] for key in FIELDS - {"updates"}})
            retracted = False
        elif action == "unlock":
            if not control.get("locked"):
                raise ValueError("Story is not editorially locked")
            if retracted:
                raise ValueError("Explicitly restore a retracted story before resuming automation")
            if any(not isinstance(control.get(k), str) for k in ("notice_action", "notice_reason", "notice_at")):
                raise ValueError("Invalid editorial notice reason")
            locked = False
            notice_action, notice_reason, notice_at = control["notice_action"], control["notice_reason"], control["notice_at"]
        else:
            raise ValueError("Unknown editorial action")
        public["updated_at"] = stamp
        public = prepare_story(public, allow_empty_sources=retracted)
        after_public = {k: v for k, v in public.items() if k not in ("updates", "alert_notes")} if retracted else public
        candidate = dict(current["raw"])
        candidate.pop("editorial", None)
        candidate.pop("updates", None)
        candidate.update(public)
        previous_sources: dict[str, dict] = {}
        for src in current["raw"].get("sources", []):
            if isinstance(src, dict) and isinstance(src.get("url"), str):
                for variant in {src["url"], *gitlab_url_variants(src["url"])}:
                    previous_sources.setdefault(variant, src)
        candidate["sources"] = [{**previous_sources.get(s["url"], {}), **s} for s in public["sources"]]
        next_revision = current["revision"] + 1
        after_story = strict_json(candidate)
        held_updates = 0 if action == "unlock" else control.get("held_updates", 0)
        db.execute("UPDATE stories SET payload=?,updated_at=? WHERE id=?", (after_story, stamp, story_id))
        db.execute("""INSERT INTO editorial_controls(story_id,revision,locked,retracted,notice_action,notice_reason,notice_at,held_updates)
            VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(story_id) DO UPDATE SET revision=excluded.revision,
            locked=excluded.locked,retracted=excluded.retracted,notice_action=excluded.notice_action,
            notice_reason=excluded.notice_reason,notice_at=excluded.notice_at,held_updates=excluded.held_updates""",
            (story_id, next_revision, int(locked), int(retracted), notice_action, notice_reason, notice_at, held_updates))
        after_hash = _snapshot(db, story_id)["hash"]
        before_public_json = None
        if current["published"] is not None and current["published"].get("id") == story_id:
            try:
                before_public_json = strict_json(_strip_surrogates(current["published"]))
            except (ValueError, TypeError, RecursionError):
                before_public_json = None
        db.execute("""INSERT INTO editorial_revisions(story_id,revision,action,reason,created_at,
            before_story_json,before_public_json,after_story_json,after_public_json,before_hash,after_hash)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (story_id, next_revision, action, reason, stamp, current["record"]["payload"],
             before_public_json,
             after_story, strict_json(after_public), current["hash"], after_hash))
        if action == "unlock":
            requeue_items(db, _held_item_ids(db, story_id))
        _enqueue_render(db, story_id)
    return {"story_id": story_id, "revision": next_revision, "hash": after_hash,
            "action": action, "locked": locked, "retracted": retracted, "updated_at": stamp}


def correct(db, story_id: str, patch: dict, *, reason: str, expect_hash: str, observed: str | None = None) -> dict:
    """Apply an operator correction to `story_id` and lock automated updates."""
    return _apply(db, story_id, "correct", patch=patch, reason=reason, expect_hash=expect_hash, observed=observed)


def retract(db, story_id: str, *, reason: str, expect_hash: str, observed: str | None = None) -> dict:
    """Retract `story_id` with a public reason and lock automated updates."""
    return _apply(db, story_id, "retract", reason=reason, expect_hash=expect_hash, observed=observed)


def unlock(db, story_id: str, *, reason: str, expect_hash: str, observed: str | None = None) -> dict:
    """Unlock `story_id`, reset its held-update count, and re-queue held items."""
    return _apply(db, story_id, "unlock", reason=reason, expect_hash=expect_hash, observed=observed)


def restore(db, story_id: str, revision: int, *, reason: str, expect_hash: str, observed: str | None = None) -> dict:
    """Restore `story_id` to an earlier accepted revision while keeping it locked."""
    return _apply(db, story_id, "restore", revision=revision, reason=reason, expect_hash=expect_hash, observed=observed)


def merge(db, story_id: str, survivor_id: str, *, reason: str, expect_hash: str | None = None,
          base_url: str = DEFAULTS["site"]["base_url"], observed: str | None = None,
          automatic: bool = False, _guard=None, _complete=None) -> dict:
    """Permanently merge published duplicate `story_id` into `survivor_id` as a pointer."""
    from . import decisions, doctor

    _id(story_id)
    _id(survivor_id)
    if story_id == survivor_id:
        raise ValueError("Cannot merge a story into itself")
    reason = clean_text(reason, "merge reason", 1000)
    if not automatic:
        _require_expect_hash(expect_hash)
    base = canonical_url(base_url).rstrip("/") + "/"
    stamp = timestamp(observed or now_iso())
    with _begin_tx(db):
        if _guard is not None:
            _guard(db)
        dup = _snapshot(db, story_id, expect_hash)
        surv = _snapshot(db, survivor_id)
        if (dup["control"] and dup["control"]["retracted"]) or (surv["control"] and surv["control"]["retracted"]):
            raise ValueError("Cannot merge a retracted story")
        if dup["published"] is None or surv["published"] is None:
            raise ValueError("Both stories must already be published before merging")
        prepare_story(surv["published"])
        if db.execute("SELECT 1 FROM public_render_queue WHERE story_id=? AND last_error IS NOT NULL", (survivor_id,)).fetchone():
            raise ValueError("Survivor story has a quarantined render error")
        db.execute(
            "INSERT INTO story_aliases(story_id,cluster_key,survivor_id,reason,created_at,story_json) VALUES(?,?,?,?,?,?)",
            (story_id, dup["record"]["cluster_key"], survivor_id, reason, stamp, dup["record"]["payload"]),
        )
        db.execute("DELETE FROM stories WHERE id=?", (story_id,))
        db.execute("UPDATE editorial_controls SET locked=0,held_updates=0 WHERE story_id=?", (story_id,))
        surv_locked = bool(surv["control"] and surv["control"]["locked"])
        transferred_network = bool(dup["raw"].get("network")) and doctor.transfer_attached(
            db,
            story_id=story_id,
            dup_raw=dup["raw"],
            survivor_id=survivor_id,
            surv_raw=surv["raw"],
            surv_fallback=surv["fallback"],
            surv_locked=surv_locked,
        )
        held_ids = _held_item_ids(db, story_id, dup["record"]["cluster_key"])
        remapped = db.execute(
            "UPDATE items SET story_id=? WHERE story_id=? OR (story_id IS NULL AND cluster_key=?)",
            (survivor_id, story_id, dup["record"]["cluster_key"]),
        ).rowcount
        if held_ids:
            if surv_locked:
                for hid in held_ids:
                    record_held(db, survivor_id)
                    decisions.record(db, hid, "held.gate.story_locked", stamp, merged_from=story_id)
            else:
                requeue_items(db, held_ids)
        for (aid,) in db.execute(
            "SELECT a.story_id FROM story_aliases a JOIN public_catalog c ON c.story_id=a.story_id ORDER BY a.story_id"
        ).fetchall():
            resolved = retired(db, story_id=aid)
            if resolved is None or resolved[1] != survivor_id:
                continue
            pjson = public_json_text(pointer_json(base, aid, survivor_id))
            psha = hashlib.sha256(pjson.encode("utf-8")).hexdigest()
            db.execute(
                "UPDATE public_catalog SET updated_at=?,template_hash='',json_sha256=?,public_json=? WHERE story_id=?",
                (stamp, psha, pjson, aid),
            )
            db.execute("DELETE FROM public_story_topics WHERE story_id=?", (aid,))
            if db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='public_story_software'"
            ).fetchone():
                db.execute("DELETE FROM public_story_software WHERE story_id=?", (aid,))
            _enqueue_render(db, aid)
        if transferred_network:
            _enqueue_render(db, survivor_id)
        decisions.record_subject(
            db,
            story_id,
            "merged.auto.same_event" if automatic else "operator.merged",
            stamp,
            story_id=survivor_id,
            once=False,
            duplicate_id=story_id,
            merged_into=survivor_id,
            remapped_items=remapped,
            reason=reason,
        )
        if _complete is not None:
            _complete(db)
    return {"story_id": story_id, "merged_into": survivor_id, "remapped_items": remapped, "updated_at": stamp}
