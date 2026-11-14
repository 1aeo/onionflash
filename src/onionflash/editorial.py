"""Trusted local corrections, retractions and their durable revision record.

Public history contains accepted public snapshots only.
"""

from __future__ import annotations

import json
import hashlib
import re

from .config import DEFAULTS
from .schema import CATEGORIES, CONFIDENCES, PRIORITIES, PRODUCTS, PUBLIC_STATES, UPDATE_CHARS
from .util import canonical_url, digest, format_utc, now_iso, parse_utc, saved_object


FIELDS = frozenset({"title", "summary", "why_it_matters", "category", "priority", "confidence", "state", "products", "tags", "sources", "updates"})
PUBLIC_HISTORY_LIMIT = 20
MAX_ALIAS_HOPS = 16
_ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_HASH = re.compile(r"[a-f0-9]{64}\Z")


class RetiredStory(ValueError):
    """A story ID or cluster key recorded as retired cannot be created or edited."""


def initialize(db) -> None:
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
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError("Invalid story ID")
    return value


def _json(value) -> str:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False)
    text.encode("utf-8")
    return text


def _text(value, name: str, limit: int, *, empty: bool = False) -> str:
    # Reasons reach XML feeds as written, and XML cannot carry U+FFFE or U+FFFF.
    if not isinstance(value, str) or len(value) > limit or any((ord(c) < 32 and c not in "\n\t") or c in "\ufffe\uffff" for c in value):
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
            payload_text.encode("utf-8")
        except UnicodeError:
            payload_text = None
    record = {
        "id": row["id"],
        "cluster_key": row["cluster_key"],
        "payload": payload_text if payload_text is not None else _json({"damaged_payload_hex": row["payload_blob"].hex()}),
        "published_at": row["published_at"],
        "updated_at": row["updated_at"],
    }
    control_row = db.execute("SELECT * FROM editorial_controls WHERE story_id=?", (story_id,)).fetchone()
    control = dict(control_row) if control_row else None
    published = _published(db, story_id)
    fallback = False
    try:
        if row["payload_type"] != "text":
            raise ValueError("Damaged story payload")
        original = saved_object(row["payload_blob"])
        if original is None:
            raise ValueError("Damaged story payload")
        public = _public(original)
        if public["id"] != story_id:
            raise ValueError("Story identity differs from its database row")
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
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


def history(db, story_id: str) -> dict:
    revisions = []
    for row in db.execute("SELECT * FROM editorial_revisions WHERE story_id=? ORDER BY revision DESC", (_id(story_id),)):
        record = dict(row)
        for name in ("before_story_json", "before_public_json", "after_story_json", "after_public_json"):
            raw = record.pop(name)
            try:
                value = json.loads(raw) if raw is not None else None
            except ValueError:
                value = {"unparseable_record": raw}
            record[name.removesuffix("_json")] = value
        revisions.append(record)
    return {"story_id": story_id, "revisions": revisions}


def is_locked(db, story_id: str) -> bool:
    return bool(db.execute("SELECT 1 FROM editorial_controls WHERE story_id=? AND (locked=1 OR retracted=1)", (story_id,)).fetchone())


def record_held(db, story_id: str) -> None:
    db.execute("UPDATE editorial_controls SET held_updates=held_updates+1 WHERE story_id=?", (story_id,))


def public_metadata(db, story_id: str) -> dict | None:
    control = db.execute("SELECT * FROM editorial_controls WHERE story_id=?", (story_id,)).fetchone()
    if control is None:
        return None
    rows = db.execute("SELECT revision,action,reason,created_at,before_public_json,after_public_json FROM editorial_revisions WHERE story_id=? ORDER BY revision DESC LIMIT ?", (story_id, PUBLIC_HISTORY_LIMIT)).fetchall()
    entries = []
    for row in rows:
        entry = {key: row[key] for key in ("revision", "action", "reason", "created_at")}
        if control["retracted"] and row["revision"] != control["revision"]:
            entry["reason"] = ""  # an earlier reason may quote the withdrawn text
        if row["before_public_json"] is not None and row["action"] != "unlock" and not control["retracted"]:
            before = json.loads(row["before_public_json"])
            entry["superseded"] = {key: before.get(key, "") for key in ("title", "summary", "why_it_matters")}
            # Of the dated updates, only those this revision removed or whose date or text it changed.
            kept = {(update["at"], update["text"]) for update in json.loads(row["after_public_json"]).get("updates", [])}
            if replaced := [{"at": update["at"], "text": update["text"]} for update in before.get("updates", []) if (update["at"], update["text"]) not in kept]:
                entry["superseded"]["updates"] = replaced
        entries.append(entry)
    # history_total repeats revision; earlier releases require it, so a rollback still builds.
    return {"status": "retracted" if control["retracted"] else "corrected", "revision": control["revision"],
            "action": control["notice_action"], "reason": control["notice_reason"], "at": control["notice_at"],
            "history": entries, "history_total": control["revision"]}


def _sources(value, limit: int) -> list[dict]:
    if not isinstance(value, list) or not 1 <= len(value) <= limit:
        raise ValueError(f"Between one and {limit} public sources are required")
    sources = []
    for source in value:
        if not isinstance(source, dict) or set(source) != {"url", "title"}:
            raise ValueError("Sources require only url and title")
        sources.append({"url": canonical_url(source["url"]), "title": _text(source["title"], "source title", 200)})
    if len({s["url"] for s in sources}) != len(sources):
        raise ValueError("Duplicate source URL")
    return sources


def _validated_patch(patch: dict) -> dict:
    if not isinstance(patch, dict) or not patch or set(patch) - FIELDS:
        raise ValueError("Patch must contain only editable story fields")
    clean = dict(patch)
    for field, limit in (("title", 180), ("summary", 1600), ("why_it_matters", 800)):
        if field in clean:
            clean[field] = _text(clean[field], field, limit, empty=field == "why_it_matters")
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
        clean["sources"] = _sources(clean["sources"], 20)
    if "updates" in clean:  # the whole list replaces the stored one
        if not isinstance(clean["updates"], list):
            raise ValueError("Updates must be a list")
        updates = []
        for update in clean["updates"]:
            if not isinstance(update, dict) or set(update) != {"at", "text", "sources"}:
                raise ValueError("Updates require only at, text and sources")
            updates.append({"at": format_utc(parse_utc(update["at"])), "text": _text(update["text"], "update text", UPDATE_CHARS),
                            "sources": _sources(update["sources"], 3)})
        clean["updates"] = updates
    return clean


def _apply(db, story_id: str, action: str, *, reason: str, expect_hash: str,
           patch: dict | None = None, revision: int | None = None, observed: str | None = None) -> dict:
    _id(story_id)
    reason = _text(reason, "public reason", 1000)
    if not isinstance(expect_hash, str) or not _HASH.fullmatch(expect_hash):
        raise ValueError("A current expected story hash is required")
    stamp = format_utc(parse_utc(observed or now_iso()))
    if db.in_transaction:
        raise ValueError("Editorial action needs a fresh transaction")
    db.execute("BEGIN IMMEDIATE")
    with db:
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
            clean = _validated_patch(patch)
            if "category" in clean and "tags" not in clean and clean["category"] != current["public"]["category"]:
                old_category = current["public"]["category"]
                public["tags"] = [t for t in public.get("tags", []) if t != old_category]
            public.update(clean)
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
                row = db.execute("SELECT before_public_json,before_story_json FROM editorial_revisions WHERE story_id=? AND revision=1", (story_id,)).fetchone()
                raw_prev = row[0] if row else None
                if raw_prev is None and row and row[1]:
                    try:
                        raw_prev = _json(_public(json.loads(row[1])))
                    except (ValueError, TypeError, KeyError, AttributeError):
                        raw_prev = None
            else:
                row = db.execute("SELECT after_public_json FROM editorial_revisions WHERE story_id=? AND revision=? AND action!='retract'", (story_id, revision)).fetchone()
                raw_prev = row[0] if row else None
            if raw_prev is None:
                raise ValueError("That revision has no accepted public text to restore")
            previous = _public(json.loads(raw_prev))
            # Dated updates stay as they are: automated ones have no revision to restore.
            public.update({key: previous[key] for key in FIELDS - {"updates"}})
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
        after_public = {k: v for k, v in public.items() if k not in ("updates", "alert_notes")} if retracted else public
        candidate = dict(current["raw"])
        candidate.pop("editorial", None)
        candidate.pop("updates", None)  # public leaves out an empty list
        candidate.update(public)
        # Reuse collection identities only where an operator keeps that URL (raw or canonical).
        previous_sources: dict[str, dict] = {}
        for src in current["raw"].get("sources", []):
            if isinstance(src, dict) and isinstance(src.get("url"), str):
                previous_sources.setdefault(src["url"], src)
                try:
                    previous_sources.setdefault(canonical_url(src["url"]), src)
                except ValueError:
                    pass
        candidate["sources"] = [{**previous_sources.get(s["url"], {}), **s} for s in public["sources"]]
        next_revision = current["revision"] + 1
        after_story = _json(candidate)
        db.execute("UPDATE stories SET payload=?,updated_at=? WHERE id=?", (after_story, stamp, story_id))
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
             after_story, _json(after_public), current["hash"], after_hash))
        if action == "unlock" and {r[0] for r in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('items','decision_log','review_jobs')")} == {
                "items", "decision_log", "review_jobs"}:
            requeued = [r[0] for r in db.execute("""
                SELECT id FROM items WHERE status='published' AND story_id=?
                AND EXISTS (SELECT 1 FROM decision_log d
                    WHERE d.id=(SELECT MAX(id) FROM decision_log WHERE item_id=items.id)
                    AND d.story_id=? AND d.code='held.gate.story_locked'
                    AND d.content_hash=items.content_hash)""", (story_id, story_id)).fetchall()]
            if requeued:
                marks = ",".join("?" * len(requeued))
                db.execute(f"UPDATE items SET status='pending',attempts=0,rejections=0,next_attempt_at=NULL,last_error=NULL WHERE id IN ({marks})", requeued)
                db.execute(f"DELETE FROM review_jobs WHERE item_id IN ({marks})", requeued)
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


def merge(db, story_id: str, survivor_id: str, *, reason: str, expect_hash: str | None = None,
          base_url: str = DEFAULTS["site"]["base_url"], observed: str | None = None,
          automatic: bool = False, _guard=None, _complete=None) -> dict:
    """Permanently merge published duplicate `story_id` into `survivor_id` as a pointer."""
    from . import decisions
    from .render import pointer_json

    _id(story_id)
    _id(survivor_id)
    if story_id == survivor_id:
        raise ValueError("Cannot merge a story into itself")
    reason = _text(reason, "merge reason", 1000)
    if not automatic and (not isinstance(expect_hash, str) or not _HASH.fullmatch(expect_hash)):
        raise ValueError("A current expected story hash is required")
    base = canonical_url(base_url).rstrip("/") + "/"
    stamp = format_utc(parse_utc(observed or now_iso()))
    if db.in_transaction:
        raise ValueError("Editorial action needs a fresh transaction")
    db.execute("BEGIN IMMEDIATE")
    with db:
        if _guard is not None:
            _guard(db)
        dup = _snapshot(db, story_id)
        surv = _snapshot(db, survivor_id)
        if expect_hash is not None and dup["hash"] != expect_hash:
            raise ValueError("Story changed since it was reviewed; refresh its hash before editing")
        if (dup["control"] and dup["control"]["retracted"]) or (surv["control"] and surv["control"]["retracted"]):
            raise ValueError("Cannot merge a retracted story")
        if dup["published"] is None or surv["published"] is None:
            raise ValueError("Both stories must already be published before merging")
        _public(surv["published"])
        if (db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='public_render_queue'").fetchone()
                and db.execute("SELECT 1 FROM public_render_queue WHERE story_id=? AND last_error IS NOT NULL",
                               (survivor_id,)).fetchone()):
            raise ValueError("Survivor story has a quarantined render error")
        db.execute(
            "INSERT INTO story_aliases(story_id,cluster_key,survivor_id,reason,created_at,story_json) VALUES(?,?,?,?,?,?)",
            (story_id, dup["record"]["cluster_key"], survivor_id, reason, stamp, dup["record"]["payload"]),
        )
        db.execute("DELETE FROM stories WHERE id=?", (story_id,))
        db.execute("UPDATE editorial_controls SET locked=0,held_updates=0 WHERE story_id=?", (story_id,))
        dup_network = [e for e in (dup["raw"].get("network") or []) if isinstance(e, dict) and isinstance(e.get("key"), str)]
        surv_locked = bool(surv["control"] and (surv["control"]["locked"] or surv["control"]["retracted"]))
        transferred_network = False
        if dup_network and dup["raw"].get("origin") != "network-health" and not surv["fallback"] and not surv_locked:
            surv_raw = json.loads(_json(surv["raw"]))
            existing_net = [e for e in (surv_raw.get("network") or []) if isinstance(e, dict)]
            seen_keys = {e.get("key") for e in existing_net}
            for entry in dup_network:
                if entry["key"] not in seen_keys:
                    existing_net.append({**entry, "story_id": survivor_id})
                    seen_keys.add(entry["key"])
                    transferred_network = True
            if transferred_network:
                if surv_raw.get("editorial_item") is None:
                    item_sources = [s for s in surv_raw.get("sources", []) if isinstance(s, dict) and s.get("id") and not s.get("network_key")]
                    if len(item_sources) == 1:
                        surv_raw["editorial_item"] = item_sources[0]["id"]
                surv_raw["network"] = existing_net
                dup_notes = [n for n in (dup["raw"].get("alert_notes") or []) if isinstance(n, str)]
                if dup_notes:
                    surv_notes = [n for n in (surv_raw.get("alert_notes") or []) if isinstance(n, str)]
                    surv_raw["alert_notes"] = list(dict.fromkeys([*surv_notes, *dup_notes]))[:3]
                dup_net_urls = {
                    s.get("url")
                    for s in (dup["raw"].get("sources") or ())
                    if isinstance(s, dict) and s.get("network_key") and isinstance(s.get("url"), str)
                }
                for entry in dup_network:
                    for url_key in ("first_url", "opened_url"):
                        if isinstance(entry.get(url_key), str):
                            dup_net_urls.add(entry[url_key])
                candidate_urls = sorted({
                    s["url"]
                    for upd in (dup["raw"].get("updates") or ())
                    if isinstance(upd, dict)
                    for s in (upd.get("sources") or ())
                    if isinstance(s, dict) and isinstance(s.get("url"), str) and s["url"]
                } - dup_net_urls)
                if candidate_urls and db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='network_reports'").fetchone():
                    placeholders = ",".join("?" for _ in candidate_urls)
                    dup_net_urls.update(
                        r[0] for r in db.execute(f"SELECT url FROM network_reports WHERE url IN ({placeholders})", candidate_urls)
                    )
                surv_updates = list(surv_raw.get("updates") or [])
                seen_updates = {(u.get("at"), u.get("text")) for u in surv_updates if isinstance(u, dict)}
                added_stamps = []
                for upd in dup["raw"].get("updates") or []:
                    if not isinstance(upd, dict) or (upd.get("at"), upd.get("text")) in seen_updates:
                        continue
                    upd_urls = [s.get("url", "") for s in (upd.get("sources") or ()) if isinstance(s, dict)]
                    if not upd_urls or not all(u in dup_net_urls for u in upd_urls):
                        continue
                    matched_rekeys: list[tuple[dict, str]] = []
                    for net_entry in existing_net:
                        if net_entry.get("key") not in {e.get("key") for e in dup_network}:
                            continue
                        known_uids = set(net_entry.get("update_ids") or ())
                        kinds = {
                            slot.split(":", 1)[1]
                            for slot in (net_entry.get("slots") or ())
                            if isinstance(slot, str) and ":" in slot
                        }
                        for kind in kinds:
                            for u in upd_urls:
                                if digest([duplicate_id, kind, u])[:24] in known_uids:
                                    matched_rekeys.append((net_entry, digest([survivor_id, kind, u])[:24]))
                    if matched_rekeys:
                        for net_entry, surv_uid in matched_rekeys:
                            uids = list(net_entry.get("update_ids") or [])
                            if surv_uid not in uids:
                                net_entry["update_ids"] = [*uids, surv_uid]
                        surv_updates.append(dict(upd))
                        seen_updates.add((upd.get("at"), upd.get("text")))
                        if isinstance(upd.get("at"), str):
                            added_stamps.append(upd["at"])
                if surv_updates:
                    surv_raw["updates"] = surv_updates
                surv_sources = list(surv_raw.get("sources") or [])
                seen_urls = {s.get("url") for s in surv_sources if isinstance(s, dict)}
                for src in dup["raw"].get("sources") or []:
                    if isinstance(src, dict) and src.get("network_key") and src.get("url") not in seen_urls and len(surv_sources) < 20:
                        surv_sources.append(dict(src))
                        seen_urls.add(src.get("url"))
                surv_raw["sources"] = surv_sources
                if added_stamps:
                    surv_raw["updated_at"] = max([surv_raw["updated_at"], *added_stamps])
                db.execute(
                    "UPDATE stories SET payload=?, updated_at=? WHERE id=?",
                    (_json(surv_raw), surv_raw["updated_at"], survivor_id),
                )
        remapped = 0
        has_item_tables = {
            r[0]
            for r in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('items','decision_log','review_jobs')"
            )
        } == {"items", "decision_log", "review_jobs"}
        held_ids = (
            [
                r[0]
                for r in db.execute(
                    """SELECT id FROM items WHERE status='published'
                       AND (story_id=? OR (story_id IS NULL AND cluster_key=?))
                       AND EXISTS (SELECT 1 FROM decision_log d
                           WHERE d.id=(SELECT MAX(id) FROM decision_log WHERE item_id=items.id)
                           AND d.story_id=? AND d.code='held.gate.story_locked'
                           AND d.content_hash=items.content_hash)""",
                    (story_id, dup["record"]["cluster_key"], story_id),
                ).fetchall()
            ]
            if has_item_tables
            else []
        )
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='items'").fetchone():
            remapped = db.execute(
                "UPDATE items SET story_id=? WHERE story_id=? OR (story_id IS NULL AND cluster_key=?)",
                (survivor_id, story_id, dup["record"]["cluster_key"]),
            ).rowcount
        if held_ids:
            marks = ",".join("?" * len(held_ids))
            db.execute(f"DELETE FROM review_jobs WHERE item_id IN ({marks})", held_ids)
            if surv["control"] and surv["control"]["locked"]:
                for hid in held_ids:
                    record_held(db, survivor_id)
                    decisions.record(db, hid, "held.gate.story_locked", stamp, merged_from=story_id)
            else:
                db.execute(
                    f"UPDATE items SET status='pending',attempts=0,rejections=0,next_attempt_at=NULL,last_error=NULL WHERE id IN ({marks})",
                    held_ids,
                )
        has_topics = bool(db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='public_story_topics'").fetchone())
        has_queue = bool(db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='public_render_queue'").fetchone())
        for (aid,) in db.execute(
            "SELECT a.story_id FROM story_aliases a JOIN public_catalog c ON c.story_id=a.story_id ORDER BY a.story_id"
        ).fetchall():
            resolved = retired(db, story_id=aid)
            if resolved is None or resolved[1] != survivor_id:
                continue
            pjson = json.dumps(pointer_json(base, aid, survivor_id), ensure_ascii=False, sort_keys=True) + "\n"
            psha = hashlib.sha256(pjson.encode("utf-8")).hexdigest()
            db.execute(
                "UPDATE public_catalog SET updated_at=?,template_hash='',json_sha256=?,public_json=? WHERE story_id=?",
                (stamp, psha, pjson, aid),
            )
            if has_topics:
                db.execute("DELETE FROM public_story_topics WHERE story_id=?", (aid,))
            if has_queue:
                db.execute("DELETE FROM public_render_queue WHERE story_id=?", (aid,))
                db.execute(
                    "INSERT INTO public_render_queue(rowid,story_id) SELECT IFNULL(MIN(rowid),0)-1,? FROM public_render_queue",
                    (aid,),
                )
        if transferred_network and has_queue:
            db.execute("DELETE FROM public_render_queue WHERE story_id=?", (survivor_id,))
            db.execute(
                "INSERT INTO public_render_queue(rowid,story_id) SELECT IFNULL(MIN(rowid),0)-1,? FROM public_render_queue",
                (survivor_id,),
            )
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='decision_log'").fetchone():
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
