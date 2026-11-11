"""Trusted local corrections, retractions and their durable revision record.

Only this module grants a connection-local write permit, and only within an
operator transaction. The database guard also protects against monitoring's
direct story updates. Public history contains accepted public snapshots only.
"""

from __future__ import annotations

import json
import hashlib
import re
from contextlib import contextmanager

from .schema import CATEGORIES, CONFIDENCES, PRIORITIES, PRODUCTS, STATES
from .util import canonical_url, digest, format_utc, now_iso, parse_utc


FIELDS = frozenset({"title", "summary", "why_it_matters", "category", "priority", "confidence", "state", "products", "tags", "sources"})
PUBLIC_HISTORY_LIMIT = 20
_ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_HASH = re.compile(r"[a-f0-9]{64}\Z")


def initialize(db) -> None:
    # A raw/older connection without this function cannot bypass the guard.
    db.create_function("onionflash_editorial_permit", 1, lambda story_id: 0)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS editorial_controls (
            story_id TEXT PRIMARY KEY, revision INTEGER NOT NULL,
            locked INTEGER NOT NULL, retracted INTEGER NOT NULL,
            notice_action TEXT NOT NULL, notice_reason TEXT NOT NULL, notice_at TEXT NOT NULL,
            held_updates INTEGER NOT NULL DEFAULT 0, last_held_at TEXT
        );
        CREATE TABLE IF NOT EXISTS editorial_revisions (
            story_id TEXT NOT NULL, revision INTEGER NOT NULL,
            action TEXT NOT NULL, reason TEXT NOT NULL, created_at TEXT NOT NULL,
            before_story_json TEXT NOT NULL, before_public_json TEXT,
            after_story_json TEXT NOT NULL, after_public_json TEXT NOT NULL,
            before_hash TEXT NOT NULL, after_hash TEXT NOT NULL,
            PRIMARY KEY(story_id,revision)
        );
        CREATE TRIGGER IF NOT EXISTS editorial_story_insert BEFORE INSERT ON stories
        WHEN EXISTS(SELECT 1 FROM stories s JOIN editorial_controls e ON e.story_id=s.id
                    WHERE e.locked=1 AND (s.id=NEW.id OR s.cluster_key=NEW.cluster_key)
                    AND onionflash_editorial_permit(s.id)=0)
        BEGIN SELECT RAISE(IGNORE); END;
        DROP TRIGGER IF EXISTS editorial_story_update;
        CREATE TRIGGER editorial_story_update BEFORE UPDATE ON stories
        WHEN EXISTS(SELECT 1 FROM stories s JOIN editorial_controls e ON e.story_id=s.id
                    WHERE e.locked=1 AND (s.id=OLD.id OR s.id=NEW.id OR s.cluster_key=NEW.cluster_key)
                    AND onionflash_editorial_permit(s.id)=0)
        BEGIN SELECT RAISE(IGNORE); END;
        CREATE TRIGGER IF NOT EXISTS editorial_story_delete BEFORE DELETE ON stories
        WHEN EXISTS(SELECT 1 FROM editorial_controls WHERE story_id=OLD.id AND locked=1)
             AND onionflash_editorial_permit(OLD.id)=0
        BEGIN SELECT RAISE(IGNORE); END;
    """)


def _id(value: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError("Invalid story ID")
    return value


def _json(value) -> str:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False)
    text.encode("utf-8")
    return text


def _text(value, name: str, limit: int, *, empty: bool = False) -> str:
    if not isinstance(value, str) or len(value) > limit or any(ord(c) < 32 and c not in "\n\t" for c in value):
        raise ValueError(f"Invalid {name}")
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise ValueError(f"Invalid {name}") from None
    value = value.strip()
    if not value and not empty:
        raise ValueError(f"{name} must not be empty")
    return value


def _public(value: dict) -> dict:
    from .render import _prepare_story
    return _prepare_story(value)


def _published(db, story_id: str) -> dict | None:
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='public_catalog'").fetchone():
        return None
    row = db.execute("SELECT public_json,json_sha256 FROM public_catalog WHERE story_id=?", (story_id,)).fetchone()
    if row is None:
        return None
    if hashlib.sha256(row[0].encode("utf-8")).hexdigest() != row[1]:
        raise ValueError("Published story snapshot failed its integrity check")
    public = json.loads(row[0])
    public.pop("editorial", None)  # Revision history is stored separately, never recursively.
    return public


def _snapshot(db, story_id: str) -> dict:
    _id(story_id)
    row = db.execute("SELECT * FROM stories WHERE id=?", (story_id,)).fetchone()
    if row is None:
        raise ValueError("Unknown story; restore its stored record before editing")
    record = dict(row)
    control_row = db.execute("SELECT * FROM editorial_controls WHERE story_id=?", (story_id,)).fetchone()
    control = dict(control_row) if control_row else None
    published = _published(db, story_id)
    fallback = False
    try:
        original = json.loads(record["payload"])
        public = _public(original)
        if public["id"] != story_id:
            raise ValueError("Story identity differs from its database row")
    except (ValueError, TypeError, KeyError, AttributeError):
        if published is None:
            raise ValueError("Story has no valid public snapshot to correct") from None
        original = {}
        public, fallback = _public(published), True
    revision = control["revision"] if control else 0
    fingerprint = digest([record, revision, bool(control and control["locked"]), bool(control and control["retracted"])])
    return {"record": record, "raw": original, "public": public, "published": published,
            "control": control, "revision": revision, "hash": fingerprint, "fallback": fallback}


def show(db, story_id: str) -> dict:
    current = _snapshot(db, story_id)
    control = current["control"] or {}
    return {"story_id": story_id, "revision": current["revision"], "hash": current["hash"],
            "locked": bool(control.get("locked")), "retracted": bool(control.get("retracted")),
            "held_updates": control.get("held_updates", 0), "story": current["public"],
            "published_story": current["published"], "using_last_published_snapshot": current["fallback"]}


def history(db, story_id: str, *, limit: int = 20, before: int | None = None) -> dict:
    _id(story_id)
    if type(limit) is not int or not 1 <= limit <= 100 or (before is not None and (type(before) is not int or before < 1)):
        raise ValueError("History requires limit 1..100 and a positive before revision")
    where, parameters = "story_id=?", [story_id]
    if before is not None:
        where += " AND revision<?"
        parameters.append(before)
    rows = db.execute(f"SELECT * FROM editorial_revisions WHERE {where} ORDER BY revision DESC LIMIT ?", (*parameters, limit + 1)).fetchall()
    more = len(rows) > limit
    revisions = []
    for row in rows[:limit]:
        record = dict(row)
        for name in ("before_story_json", "before_public_json", "after_story_json", "after_public_json"):
            raw = record.pop(name)
            try:
                value = json.loads(raw) if raw is not None else None
            except ValueError:
                value = {"unparseable_record": raw}
            record[name.removesuffix("_json")] = value
        revisions.append(record)
    return {"story_id": story_id, "revisions": revisions, "has_more": more,
            "next_before": revisions[-1]["revision"] if more else None}


def is_locked(db, story_id: str) -> bool:
    return bool(db.execute("SELECT 1 FROM editorial_controls WHERE story_id=? AND locked=1", (story_id,)).fetchone())


def record_held(db, story_id: str, observed: str) -> None:
    db.execute("UPDATE editorial_controls SET held_updates=held_updates+1,last_held_at=? WHERE story_id=?", (observed, story_id))


def public_metadata(db, story_id: str) -> dict | None:
    control = db.execute("SELECT * FROM editorial_controls WHERE story_id=?", (story_id,)).fetchone()
    if control is None:
        return None
    rows = db.execute("SELECT revision,action,reason,created_at,before_public_json FROM editorial_revisions WHERE story_id=? ORDER BY revision DESC LIMIT ?", (story_id, PUBLIC_HISTORY_LIMIT)).fetchall()
    entries = []
    for row in rows:
        entry = {key: row[key] for key in ("revision", "action", "reason", "created_at")}
        if control["retracted"] and row["revision"] != control["revision"]:
            entry["reason"] = ""  # an earlier reason may quote the withdrawn text
        if row["before_public_json"] is not None and row["action"] != "unlock" and not control["retracted"]:
            before = json.loads(row["before_public_json"])
            entry["superseded"] = {key: before.get(key, "") for key in ("title", "summary", "why_it_matters")}
        entries.append(entry)
    return {"status": "retracted" if control["retracted"] else "corrected", "revision": control["revision"],
            "action": control["notice_action"], "reason": control["notice_reason"], "at": control["notice_at"],
            "history": entries, "history_total": control["revision"]}


def _validated_patch(patch: dict) -> dict:
    if not isinstance(patch, dict) or not patch or set(patch) - FIELDS:
        raise ValueError("Patch must contain only editable story fields")
    clean = dict(patch)
    for field, limit in (("title", 180), ("summary", 1600), ("why_it_matters", 800)):
        if field in clean:
            clean[field] = _text(clean[field], field, limit, empty=field == "why_it_matters")
    for field, allowed in (("category", CATEGORIES), ("priority", PRIORITIES), ("confidence", CONFIDENCES), ("state", STATES)):
        if field in clean and (not isinstance(clean[field], str) or clean[field] not in allowed):
            raise ValueError(f"Invalid {field}")
    for field, allowed in (("products", PRODUCTS), ("tags", CATEGORIES)):
        if field in clean:
            value = clean[field]
            if not isinstance(value, list) or len(value) > len(allowed) or any(not isinstance(v, str) or v not in allowed for v in value):
                raise ValueError(f"Invalid {field}")
            clean[field] = list(dict.fromkeys(value))
    if "sources" in clean:
        if not isinstance(clean["sources"], list) or not 1 <= len(clean["sources"]) <= 20:
            raise ValueError("A story requires between one and twenty public sources")
        sources = []
        for source in clean["sources"]:
            if not isinstance(source, dict) or set(source) != {"url", "title"}:
                raise ValueError("Sources require only url and title")
            sources.append({"url": canonical_url(source["url"]), "title": _text(source["title"], "source title", 200)})
        if len({s["url"] for s in sources}) != len(sources):
            raise ValueError("Duplicate source URL")
        clean["sources"] = sources
    return clean


@contextmanager
def _operator_transaction(db, story_id: str):
    if db.in_transaction:
        raise ValueError("Editorial action needs a fresh transaction")
    db.execute("BEGIN IMMEDIATE")
    try:
        db.create_function("onionflash_editorial_permit", 1, lambda candidate: int(candidate == story_id))
        try:
            yield
        finally:
            # Reset before COMMIT; an exception or process exit cannot leave a
            # durable authorization flag for a later automatic writer.
            db.create_function("onionflash_editorial_permit", 1, lambda candidate: 0)
        db.commit()
    except BaseException:
        db.rollback()
        raise


def _apply(db, story_id: str, action: str, *, reason: str, expect_hash: str,
           patch: dict | None = None, revision: int | None = None, observed: str | None = None) -> dict:
    _id(story_id)
    reason = _text(reason, "public reason", 1000)
    if not isinstance(expect_hash, str) or not _HASH.fullmatch(expect_hash):
        raise ValueError("A current expected story hash is required")
    stamp = format_utc(parse_utc(observed or now_iso()))
    with _operator_transaction(db, story_id):
        current = _snapshot(db, story_id)
        if current["hash"] != expect_hash:
            raise ValueError("Story changed since it was reviewed; refresh its hash before editing")
        if stamp < current["public"]["updated_at"]:
            raise ValueError("Editorial timestamp must not precede the current story update")
        control = current["control"] or {}
        public = dict(current["public"])
        retracted, locked = bool(control.get("retracted")), True
        notice_action, notice_reason, notice_at = action, reason, stamp
        if action == "correct":
            if retracted:
                raise ValueError("Restore a retracted story before correcting it")
            public.update(_validated_patch(patch))
            if _public(public) == current["public"]:
                raise ValueError("Correction does not change any public field")
        elif action == "retract":
            public.update(title="Retracted story", summary="This story has been retracted by the publisher. " + reason,
                          why_it_matters="", priority="low")
            retracted = True
        elif action == "restore":
            if type(revision) is not int or not 0 <= revision < current["revision"]:
                raise ValueError("Restore requires an earlier revision number (zero is the original accepted text)")
            if revision == 0:
                row = db.execute("SELECT before_public_json FROM editorial_revisions WHERE story_id=? AND revision=1", (story_id,)).fetchone()
            else:
                row = db.execute("SELECT after_public_json FROM editorial_revisions WHERE story_id=? AND revision=? AND action!='retract'", (story_id, revision)).fetchone()
            if row is None or row[0] is None:
                raise ValueError("That revision has no accepted public text to restore")
            previous = _public(json.loads(row[0]))
            public.update({key: previous[key] for key in FIELDS})
            retracted = False
        elif action == "unlock":
            if not control.get("locked"):
                raise ValueError("Story is not editorially locked")
            if retracted:
                raise ValueError("Explicitly restore a retracted story before resuming automation")
            locked = False
            notice_action, notice_reason, notice_at = control["notice_action"], control["notice_reason"], control["notice_at"]
        else:
            raise ValueError("Unknown editorial action")
        public["updated_at"] = stamp
        public = _public(public)
        candidate = dict(current["raw"])
        candidate.pop("editorial", None)
        candidate.update(public)
        # Reuse collection identities only where an operator keeps that exact URL.
        previous_sources = {s.get("url"): s for s in current["raw"].get("sources", []) if isinstance(s, dict)}
        candidate["sources"] = [{**previous_sources.get(s["url"], {}), **s} for s in public["sources"]]
        next_revision = current["revision"] + 1
        after_story = _json(candidate)
        changed = db.execute("UPDATE stories SET payload=?,updated_at=? WHERE id=?", (after_story, stamp, story_id))
        if changed.rowcount != 1:
            raise ValueError("Editorial update did not replace the expected story")
        db.execute("""INSERT INTO editorial_controls(story_id,revision,locked,retracted,notice_action,notice_reason,notice_at)
            VALUES(?,?,?,?,?,?,?) ON CONFLICT(story_id) DO UPDATE SET revision=excluded.revision,
            locked=excluded.locked,retracted=excluded.retracted,notice_action=excluded.notice_action,
            notice_reason=excluded.notice_reason,notice_at=excluded.notice_at""",
            (story_id, next_revision, int(locked), int(retracted), notice_action, notice_reason, notice_at))
        after_hash = _snapshot(db, story_id)["hash"]
        db.execute("""INSERT INTO editorial_revisions(story_id,revision,action,reason,created_at,
            before_story_json,before_public_json,after_story_json,after_public_json,before_hash,after_hash)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (story_id, next_revision, action, reason, stamp, current["record"]["payload"],
             _json(current["published"]) if current["published"] is not None else None,
             after_story, _json(public), current["hash"], after_hash))
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='public_render_queue'").fetchone():
            # Like a changed story, an editorial action renders before any rebuild backlog.
            db.execute("INSERT OR REPLACE INTO public_render_queue(rowid,story_id) SELECT IFNULL(MIN(rowid),0)-1,? FROM public_render_queue", (story_id,))
    return {"story_id": story_id, "revision": next_revision, "hash": after_hash,
            "action": action, "locked": locked, "retracted": retracted, "updated_at": stamp}


def correct(db, story_id: str, patch: dict, *, reason: str, expect_hash: str, observed: str | None = None) -> dict:
    return _apply(db, story_id, "correct", patch=patch, reason=reason, expect_hash=expect_hash, observed=observed)


def retract(db, story_id: str, *, reason: str, expect_hash: str, observed: str | None = None) -> dict:
    return _apply(db, story_id, "retract", reason=reason, expect_hash=expect_hash, observed=observed)


def unlock(db, story_id: str, *, reason: str, expect_hash: str, observed: str | None = None) -> dict:
    return _apply(db, story_id, "unlock", reason=reason, expect_hash=expect_hash, observed=observed)


def restore(db, story_id: str, revision: int, *, reason: str, expect_hash: str, observed: str | None = None) -> dict:
    return _apply(db, story_id, "restore", revision=revision, reason=reason, expect_hash=expect_hash, observed=observed)
