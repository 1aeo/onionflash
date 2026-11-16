"""Read-only final-story assembly and immutable publication bindings."""

from __future__ import annotations

from collections.abc import Iterable
import json
import re

from . import editorial, render, source_packet
from .analyze import MIN_EVIDENCE_CHARS
from .comments import analysis_context, is_budget_clipped_prefix, note_key, prior_notes
from .llm import strip_unreleased_tag, unquoted_text
from .schema import SEMANTIC_FIELDS, UPDATE_FIELDS
from .util import (after, digest, gitlab_refs, gitlab_url_variants, normalize_evidence,
                   release_mentions, safe_canonical_url, saved_object, story_cluster, thread_subject)


UNVERIFIED_ROUTE = "Attached to an existing story for update review"
COVERAGE_ROWS = 32
COVERAGE_CHARS = 12000
COVERAGE_SUMMARY_CHARS = 200
RELATED_SUMMARY_CHARS = 400
RELATED_LIMIT = 6
THREAD_WINDOW_DAYS = 45
_UNSET = object()


class ReviewRequired(ValueError):
    """Raised when an unapproved or non-normalized candidate cannot be committed."""


class StaleCandidate(ValueError):
    """Raised when source, story, or editorial state changed after candidate assembly."""


def _norm_url(raw: object) -> str | None:
    return safe_canonical_url(raw) or (raw if isinstance(raw, str) and raw else None)


def _url_matches(url: object, bases: set[str]) -> bool:
    clean = _norm_url(url)
    return bool(clean and any(clean == base or clean.startswith(base + "#") for base in bases))


def story_cites_item(story: dict, item: dict | str | None = None, *urls: str | None,
                     item_id: str | None = None, url: str | None = None) -> bool:
    """Return whether `story` cites `item` in its top-level sources or dated update sources."""
    if isinstance(item, dict):
        item_id = item_id or item.get("id")
        urls = (item.get("url"), *urls)
    elif isinstance(item, str):
        item_id = item_id or item
    bases = {u for u in (_norm_url(raw) for raw in (*urls, url)) if u}
    return any(
        isinstance(s, dict)
        and ((item_id and (s.get("id") == item_id or s.get("source_item_id") == item_id)) or _url_matches(s.get("url"), bases))
        for s in (story.get("sources") or ())
    ) or any(
        isinstance(cs, dict) and _url_matches(cs.get("url"), bases)
        for u in (story.get("updates") or ())
        if isinstance(u, dict)
        for cs in (u.get("sources") or ())
    )


def _retracted_title(db, row) -> str:
    rev = db.execute(
        """SELECT CAST(before_public_json AS BLOB),CAST(before_story_json AS BLOB)
           FROM editorial_revisions WHERE story_id=? AND action='retract' ORDER BY revision DESC LIMIT 1""",
        (row["id"],),
    ).fetchone()
    payload = row["payload"]
    raw_blob = payload.encode("utf-8") if isinstance(payload, str) else payload
    for blob in (*(rev or ()), raw_blob):
        if blob is not None and isinstance(obj := saved_object(blob), dict) and isinstance(obj.get("title"), str) and obj["title"].strip():
            return obj["title"].strip()[:180]
    return "Retracted story"


def coverage_background(db, prior: dict | None, *, related_rows: list[tuple[str, str]] | tuple[tuple[str, str], ...] = (),
                        earlier_ids: list[str] | tuple[str, ...] = (), associated: bool = False) -> dict:
    """Bounded committed coverage for editorial comparison, never source evidence."""
    def public_text(row):
        """Normalize public coverage fields and reject mismatched stored identities."""
        public = render.prepare_story(json.loads(row["payload"]))
        if public["id"] != row["id"]:
            raise ValueError("Coverage identity differs from its stored story")
        out = {key: public[key] for key in ("id", *SEMANTIC_FIELDS, "published_at", "updated_at", "added_at")}
        for optional in ("updates", "origin"):
            if optional in public:
                out[optional] = public[optional]
        return out

    def compact_entry(row, *, summary_limit: int = COVERAGE_SUMMARY_CHARS, reason: str | None = None) -> dict:
        if row["retracted"]:
            return {"id": row["id"], "title": _retracted_title(db, row), "retracted": True}
        current = public_text(row)
        compact = {key: current[key] for key in ("id", "title", "summary", "category", "state", "updated_at")}
        compact["summary"] = current["summary"][:summary_limit]
        compact["summary_truncated"] = len(current["summary"]) > summary_limit
        compact["products"] = current["products"]
        if current.get("updates"):
            compact["latest_update"] = current["updates"][-1]["text"][:COVERAGE_SUMMARY_CHARS]
        if "origin" in current:
            compact["origin"] = current["origin"]
        if reason is not None:
            compact["related"] = reason
        return compact

    previous = public_text(prior) if prior else None
    if previous is not None and associated:
        previous["associated"] = True
    result = {"prior_story": previous, "recent": [], "truncated": False}
    seen_ids = {prior["id"]} if prior else set()

    def try_add(row, *, summary_limit: int = COVERAGE_SUMMARY_CHARS, reason: str | None = None) -> bool:
        try:
            entry = compact_entry(row, summary_limit=summary_limit, reason=reason)
        except (ValueError, TypeError, KeyError, AttributeError, UnicodeError):
            result["truncated"] = True
            return True
        if (len(result["recent"]) + bool(previous) >= COVERAGE_ROWS
                or len(json.dumps({**result, "recent": [*result["recent"], entry]}, ensure_ascii=False)) > COVERAGE_CHARS):
            result["truncated"] = True
            return False
        result["recent"].append(entry)
        seen_ids.add(entry["id"])
        return True

    pinned = [
        *((sid, RELATED_SUMMARY_CHARS, reason) for sid, reason in list(related_rows)[:RELATED_LIMIT]),
        *((sid, COVERAGE_SUMMARY_CHARS, "earlier decision") for sid in earlier_ids),
    ]
    for story_id, limit, reason in pinned:
        if story_id in seen_ids:
            continue
        pinned_row = db.execute(
            """SELECT s.id,s.payload,COALESCE(e.retracted,0) AS retracted
               FROM stories s LEFT JOIN editorial_controls e ON e.story_id=s.id WHERE s.id=?""",
            (story_id,),
        ).fetchone()
        if pinned_row is not None and not pinned_row["retracted"] and not try_add(pinned_row, summary_limit=limit, reason=reason):
            return result

    for row in db.execute(
        """SELECT s.id,s.payload,COALESCE(e.retracted,0) AS retracted
           FROM stories s LEFT JOIN editorial_controls e ON e.story_id=s.id
           ORDER BY MAX(s.updated_at, COALESCE(json_extract(s.payload, '$.added_at'), s.published_at)) DESC, s.rowid DESC
           LIMIT ?""",
        (COVERAGE_ROWS + 1,),
    ).fetchall():
        if row["id"] not in seen_ids and not try_add(row):
            break
    return result


def writer_info(previous: dict | None, db=None) -> tuple[str | None, str, str]:
    """Return `(editorial_item_id, editorial_kind, editorial_authority)` for `previous`."""
    if not previous:
        return None, "", ""
    writer = previous.get("editorial_item")
    if writer is None:
        item_sources = [s for s in previous.get("sources", []) if isinstance(s, dict) and not s.get("network_key")]
        if len(item_sources) == 1:
            writer = item_sources[0].get("id")
    kind = previous.get("editorial_kind") or ("tag" if previous.get("state") == "tagged" else "")
    authority = previous.get("editorial_authority")
    if authority is None and db is not None and writer:
        writer_row = db.execute("SELECT CAST(payload AS BLOB) FROM items WHERE id=?", (writer,)).fetchone()
        if writer_row is not None:
            saved = saved_object(writer_row[0])
            if isinstance(saved, dict) and isinstance(saved.get("authority"), str):
                authority = saved["authority"]
    if authority is None:
        authority = "official" if kind in {"feed", ""} and previous.get("confidence") == "confirmed" else ""
    return writer, kind, authority


def relation(previous: dict | None, item: dict, db=None) -> str:
    """Determine how `item` relates to `previous`: new, citation, upgrade, own, or update."""
    if previous is None:
        return "new"
    writer, kind, authority = writer_info(previous, db)
    item_kind = item.get("kind") or ""
    if previous.get("origin") == "network-health":
        return "citation" if item_kind == "tag" else "update"
    if item_kind == "tag":
        if item.get("id") == writer:
            return "own"
        return "citation" if previous.get("state") in {"tagged", "released"} else "update"
    prev_tier = {"tag": 0, "metrics_timeline": 1}.get(kind, 2)
    item_tier = {"tag": 0, "metrics_timeline": 1}.get(item_kind, 2)
    if prev_tier < 2 and (
        item_tier > prev_tier
        or (item_tier == prev_tier and item.get("authority") == "official" and authority != "official")
    ):
        return "upgrade"
    if kind == "metrics_timeline" and item_kind == "metrics_timeline" and item.get("id") == writer:
        return "own"
    return "update"


def _mode(previous: dict | None, item: dict, db=None) -> str:
    """Story scope creates or upgrades a story (or corrects a timeline row); prose follow-ups run in update scope."""
    return "story" if relation(previous, item, db) in {"new", "upgrade", "own"} else "update"


def _latest_published_source(db, item_id: str, analysis_key: str | None) -> dict | None:
    for snap_payload, record_blob in db.execute(
            """SELECT CAST(source_payload AS BLOB),CAST(review_record AS BLOB)
            FROM analyses WHERE source_item_id=? ORDER BY rowid DESC""", (item_id,)).fetchall():
        snap = saved_object(snap_payload)
        if snap is None:
            continue
        if record_blob is None:
            return snap
        rec = saved_object(record_blob)
        if isinstance(rec, dict) and rec.get("outcome") in {"approved", "operator_approved"}:
            return snap
    if analysis_key:
        row = db.execute("SELECT CAST(source_payload AS BLOB) FROM analyses WHERE cache_key=?", (analysis_key,)).fetchone()
        if row is not None:
            return saved_object(row[0])
    return None


def _source_cutoff(db, previous: dict, old_item: dict | None, item: dict | None = None) -> str:
    item_id = (item or old_item or {}).get("id") or previous.get("editorial_item")
    own_urls = {u for u in (_norm_url((item or {}).get("url")), _norm_url((old_item or {}).get("url"))) if u}

    def is_own_source(entry: dict) -> bool:
        return bool(
            (item_id and (entry.get("id") == item_id or entry.get("source_item_id") == item_id))
            or _url_matches(entry.get("url"), own_urls)
        )

    initial_at = (old_item or {}).get("published_at") or (item or {}).get("published_at") or previous["published_at"]
    dates = [
        initial_at,
        *(s["published_at"] for s in previous.get("sources", []) if isinstance(s, dict) and s.get("published_at") and is_own_source(s)),
        *(
            u["at"]
            for u in previous.get("updates") or []
            if isinstance(u, dict)
            and u.get("at")
            and any(isinstance(cs, dict) and _url_matches(cs.get("url"), own_urls) for cs in (u.get("sources") or []))
        ),
    ]
    if old_item is not None:
        if old_item.get("kind") != "gitlab_issue":
            dates.append(old_item["updated_at"])
        dates += [n["created_at"] for n in old_item.get("public_comments") or []]
    elif (
        db.execute("SELECT 1 FROM editorial_controls WHERE story_id=?", (previous["id"],)).fetchone() is None
        and all(is_own_source(s) for s in previous.get("sources", []) if isinstance(s, dict) and not s.get("network_key"))
        and all(
            any(isinstance(cs, dict) and _url_matches(cs.get("url"), own_urls) for cs in (u.get("sources") or []))
            for u in (previous.get("updates") or [])
            if isinstance(u, dict)
        )
    ):
        dates.append(previous["updated_at"])
    return max(dates)


def _changed_note_ids(old_item: dict | None, item: dict) -> set[str]:
    seen_notes = prior_notes((old_item or {}).get("public_comments"))
    notes = item.get("public_comments") or []
    clipped_tail = is_budget_clipped_prefix(seen_notes, notes)
    return {
        nkey
        for index, note in enumerate(notes)
        if "id" in note
        and (old_note := seen_notes.get(nkey := note_key(note["id"]))) is not None
        and not (clipped_tail and index == len(notes) - 1)
        and unquoted_text(str(old_note.get("body") or "")).strip() != unquoted_text(note["body"]).strip()
    }


def _own_diff(db, previous: dict, item: dict, writer: str | None, *, item_id: str | None = None):
    """Resolve prior snapshot, cutoff, edited note IDs, and body change for an update item."""
    own_id = item_id or item["id"]
    prior_snap = _latest_published_source(db, item["id"], previous.get("editorial_analysis_key") if own_id == writer else None)
    if not (own_id == writer or (item.get("kind") == "gitlab_issue" and prior_snap is not None)):
        return False, None, None, frozenset(), True
    cutoff = _source_cutoff(db, previous, prior_snap, item)
    changed_ids = _changed_note_ids(prior_snap, item)
    if prior_snap is None:
        note_max = max((n.get("edited_at") or n["created_at"] for n in item.get("public_comments") or []), default="")
        body_changed = item["updated_at"] > max(cutoff, note_max)
    else:
        body_changed = any(
            unquoted_text(str(item.get(k) or "")).strip() != unquoted_text(str(prior_snap.get(k) or "")).strip()
            for k in ("title", "upstream_state")
        ) or (
            unquoted_text(str(item.get("source_content", item.get("content")) or "")).strip()
            != unquoted_text(str(prior_snap.get("source_content", prior_snap.get("content")) or "")).strip()
        )
    return True, prior_snap, cutoff, changed_ids, body_changed


_QUOTE_HEADER = re.compile(
    r"^(?:on\s+.+\bwrote:|am\s+.+\bschrieb\b.*:|le\s+.+\ba\s+écrit\s*:|\d{4}-\d{2}-\d{2}\b.+:)$",
    re.I,
)
_REPLY_SUBJECT = re.compile(r"(?:^|\])\s*re:", re.I)


def _unquoted_reply(text: str) -> str:
    """Drop >-quoted lines and quote-attribution headers immediately preceding them."""
    lines = text.splitlines()
    keep = [not line.lstrip().startswith(">") for line in lines]
    for index, line in enumerate(lines):
        if not keep[index] or not _QUOTE_HEADER.match(line.strip()):
            continue
        probe = index + 1
        while probe < len(lines) and not lines[probe].strip():
            probe += 1
        if probe < len(lines) and not keep[probe]:
            keep[index] = False
    return "\n".join(line for line, ok in zip(lines, keep) if ok)


def own_update_input(db, row: dict, item: dict, *, existing=_UNSET) -> tuple[str, dict]:
    """Filter own-item and mailing-list reply updates to unquoted text; skip when nothing new exists."""
    if existing is _UNSET:
        existing = existing_story(db, row)
    if existing is None:
        return "story", item
    previous = json.loads(existing["payload"])
    writer, _, _ = writer_info(previous, db)
    mode = _mode(previous, item, db)
    if row["id"] == writer and item.get("kind") == "tag":
        return "skip", item
    if mode == "story":
        return "story", item
    is_own, old_item, cutoff, changed_ids, body_changed = _own_diff(db, previous, item, writer, item_id=row["id"])
    if not is_own:
        raw = item.get("source_content", item.get("content")) or ""
        is_reply = bool(_REPLY_SUBJECT.search(item.get("title") or ""))
        if (
            "/hyperkitty/list/" in (item.get("url") or "")
            or item.get("kind") == "pipermail"
            or (item.get("kind") in {"feed", "rss"} and is_reply and "\n>" in ("\n" + raw))
        ):
            stripped = _unquoted_reply(raw)
            if stripped != raw:
                filtered = json.loads(json.dumps(item))
                filtered.pop("source_content", None)
                filtered["content"] = stripped
                if (is_reply or not normalize_evidence(item.get("title") or "")) and len(normalize_evidence(stripped)) < MIN_EVIDENCE_CHARS:
                    return "skip", filtered
                return mode, filtered
        return mode, item
    seen_bodies = {note_key(n["id"]): n.get("body") for n in (old_item or {}).get("public_comments") or [] if "id" in n}
    new_notes = [
        {**note, "body": stripped}
        for note in item.get("public_comments") or []
        if ((note["created_at"] > cutoff and note_key(note.get("id")) not in seen_bodies)
            or note_key(note.get("id")) in changed_ids)
        and (stripped := unquoted_text(note["body"]).strip())
    ]
    filtered = json.loads(json.dumps(item))
    filtered["public_comments"] = new_notes
    filtered["title"] = (unquoted_text(item["title"]).strip() or item["title"]) if body_changed else ""
    description = filtered.pop("source_content", filtered.get("content", ""))
    filtered["content"] = unquoted_text(description) if body_changed else ""
    desc, kept_notes = analysis_context(filtered)
    texts = [filtered["title"], desc, *(note["body"] for note in kept_notes)] if body_changed else [note["body"] for note in kept_notes]
    if not any(len(normalize_evidence(text)) >= MIN_EVIDENCE_CHARS for text in texts):
        return "skip", filtered
    return "update", filtered


def update_target(db, row: dict, *, existing=_UNSET) -> dict | None:
    """Normalized public story that an incoming item updates, or None in story scope."""
    if existing is _UNSET:
        existing = existing_story(db, row)
    if existing is None:
        return None
    previous = json.loads(existing["payload"])
    if _mode(previous, json.loads(row["payload"]), db) != "update":
        return None
    return render.prepare_story(previous, editorial=editorial.public_metadata(db, existing["id"]))


def _comment_sources(item: dict, result: dict, *, after_at: str | None = None, include_body: bool = True,
                     changed_ids: set[str] | frozenset[str] = frozenset()) -> list[dict]:
    """Cite the earliest note stating each quote that the title and description do not.

    Only a verified fetch writes notes, so their fields need no checks here.
    """
    if not item.get("public_comments"):
        return []
    description, _ = analysis_context(item)
    described = normalize_evidence(item["title"] + "\n" + description) if include_body else ""
    quotes = {q for quote in result["evidence"] if len(q := normalize_evidence(quote)) >= MIN_EVIDENCE_CHARS and q not in described}
    sources = []
    for note in sorted(item["public_comments"], key=lambda note: note["created_at"]):
        if after_at is not None and note["created_at"] <= after_at and note_key(note.get("id")) not in changed_ids:
            continue
        normalized = normalize_evidence(unquoted_text(note["body"]) if after_at is not None else note["body"])
        found = {quote for quote in quotes if quote in normalized}
        author = note.get("author") or ""
        short_named = (
            "update" in result
            and bool(author)
            and len(normalized) < MIN_EVIDENCE_CHARS
            and bool(re.search(rf"(?<![A-Za-z0-9_-])@?{re.escape(author)}(?![A-Za-z0-9_-])", result["update"], re.I))
        )
        if found or short_named:
            quotes -= found
            sources.append({"id": item["id"] + ":" + note["id"], "source_item_id": item["id"], "url": note["url"],
                            "title": note["title"], "published_at": note["created_at"]})
    return sources


def item_fingerprint(row: dict) -> str:
    """Return a deterministic digest binding item queue metadata and source content."""
    return digest([{key: row.get(key) for key in ("id", "url", "source_id", "content_hash", "cluster_key", "story_id", "status")},
                   source_packet.source_fingerprint(json.loads(row["payload"]))])


def _lookup_story(db, *, story_id: str | None = None, cluster_key: str | None = None,
                  raise_retired: bool = True) -> tuple[dict | None, str | None]:
    """Resolve `story_id` and/or `cluster_key` to `(live_story_dict, match_kind)`."""
    def follow(alias: tuple[str, str | None]) -> dict | None:
        target = db.execute("SELECT * FROM stories WHERE id=?", (alias[1],)).fetchone() if alias[1] else None
        if target is not None:
            calias = editorial.retired(db, story_id=target["id"], cluster_key=target["cluster_key"])
            if calias is None:
                return dict(target)
            target = db.execute("SELECT * FROM stories WHERE id=?", (calias[1],)).fetchone() if calias[1] else None
        if target is None and raise_retired:
            raise editorial.RetiredStory("Story is retired")
        return dict(target) if target is not None else None

    for col, val, kw, label in (
        ("id", story_id, {"story_id": story_id}, "story_id"),
        ("cluster_key", cluster_key, {"cluster_key": cluster_key}, "cluster"),
    ):
        if not val:
            continue
        if (alias := editorial.retired(db, **kw)) is not None:
            target = follow(alias)
            return (target, "alias") if target else (None, None)
        if (row := db.execute(f"SELECT * FROM stories WHERE {col}=?", (val,)).fetchone()) is not None:
            if (second := editorial.retired(db, story_id=row["id"], cluster_key=row["cluster_key"])) is not None:
                target = follow(second)
                return (target, label) if target else (None, None)
            return dict(row), label
    return None, None


def _live_story(db, story_id: str | None) -> dict | None:
    return _lookup_story(db, story_id=story_id, raise_retired=False)[0]


_MAPPED_PREDICATE = "story_id IS NOT NULL AND NOT (status IS 'pending' AND last_error IS ?)"


def _mapped_stories(db, where: str, *params) -> list[dict]:
    seen, found = set(), []
    for (sid,) in db.execute(
        f"SELECT DISTINCT story_id FROM items WHERE ({where}) AND {_MAPPED_PREDICATE}",
        (*params, UNVERIFIED_ROUTE),
    ).fetchall():
        live = _live_story(db, sid)
        if live and live["id"] not in seen:
            seen.add(live["id"])
            found.append(live)
    return found


def _stories_for_urls(db, urls: list[str]) -> list[dict]:
    seen, found = set(), []
    for url in urls:
        variants = tuple(v.lower() for v in (gitlab_url_variants(url) or {url}))
        placeholders = ",".join("?" for _ in variants)
        for live in _mapped_stories(db, f"LOWER(url) IN ({placeholders})", *variants):
            if live["id"] not in seen:
                seen.add(live["id"])
                found.append(live)
    return found


def _thread_matches(db, row: dict, item: dict, subject: str) -> list[dict]:
    earliest = after(-THREAD_WINDOW_DAYS * 86400, item["published_at"])
    seen, found = set(), []
    for sid, payload_blob in db.execute(
        f"SELECT story_id,CAST(payload AS BLOB) FROM items WHERE source_id=? AND id!=? AND {_MAPPED_PREDICATE}",
        (row["source_id"], row.get("id") or "", UNVERIFIED_ROUTE),
    ).fetchall():
        other = saved_object(payload_blob)
        if (not isinstance(other, dict) or not isinstance(other.get("published_at"), str)
                or not (earliest <= other["published_at"] <= item["published_at"])
                or thread_subject(other)[0] != subject):
            continue
        live = _live_story(db, sid)
        if live and live["id"] not in seen:
            seen.add(live["id"])
            found.append(live)
    return found


def associate(db, row: dict) -> tuple[dict | None, str | None]:
    """Attach an item to at most one live story using deterministic identities."""
    matched, how = _lookup_story(db, story_id=row.get("story_id"))
    if matched is not None:
        return matched, how
    payload = row.get("payload")
    item = saved_object(payload.encode("utf-8") if isinstance(payload, str) else payload) if isinstance(payload, (str, bytes)) else None
    cluster = row["cluster_key"]
    # Release versions are coverage hints for new prose, not an automatic article
    # assignment. Explicit prior mappings and permanent aliases still take precedence.
    if (isinstance(item, dict) and item.get("kind") == "feed" and cluster.startswith("release:")
            and editorial.retired(db, cluster_key=cluster) is None):
        legacy, _ = _lookup_story(db, cluster_key=cluster)
        if legacy is not None:
            public = saved_object(legacy["payload"].encode("utf-8") if isinstance(legacy["payload"], str) else legacy["payload"])
            if isinstance(public, dict) and story_cites_item(public, item):
                return legacy, "source"
        cluster = story_cluster(item)
    matched, how = _lookup_story(db, cluster_key=cluster)
    if matched is not None:
        return matched, how
    cluster_matches = _mapped_stories(db, "cluster_key=?", cluster)
    if isinstance(item, dict) and item.get("kind") == "tag" and cluster.startswith("release:"):
        cluster_matches = [story for story in cluster_matches
                           if isinstance(public := saved_object(story["payload"].encode("utf-8")
                                                                if isinstance(story["payload"], str) else story["payload"]), dict)
                           and public.get("state") in {"tagged", "released"}]
    if len(cluster_matches) == 1:
        return cluster_matches[0], "item_cluster"
    if len(cluster_matches) > 1:
        return None, None
    if not isinstance(item, dict):
        return None, None
    if item.get("kind") == "gitlab_mr" and item.get("upstream_state") == "merged":
        closing, _ = gitlab_refs(item)
        if closing:
            closing_matches = _stories_for_urls(db, closing)
            if len(closing_matches) == 1:
                return closing_matches[0], "closing_ref"
            if len(closing_matches) > 1:
                return None, None
    if row.get("source_id"):
        subject, is_reply = thread_subject(item)
        if subject and is_reply:
            thread_matches = _thread_matches(db, row, item, subject)
            if len(thread_matches) == 1:
                return thread_matches[0], "thread"
    return None, None


def existing_story(db, row: dict):
    """Return the single live story associated with `row`, or `None` if unassociated."""
    return associate(db, row)[0]


def related(db, row: dict, item: dict, exclude: set[str] | frozenset[str] = frozenset()) -> list[tuple[str, str]]:
    """Up to 6 active related (story_id, reason) pairs for coverage comparison."""
    seen = set(exclude)
    pairs: list[tuple[str, str]] = []

    def add(story_id: str | None, reason: str) -> None:
        if len(pairs) >= RELATED_LIMIT or not story_id or story_id in seen:
            return
        live = _live_story(db, story_id)
        if live is None or live["id"] in seen:
            return
        if db.execute("SELECT 1 FROM editorial_controls WHERE story_id=? AND retracted=1", (live["id"],)).fetchone():
            return
        seen.add(live["id"])
        pairs.append((live["id"], reason))

    closing, mentioned = gitlab_refs(item)
    for ref in (*closing, *mentioned):
        number = ref.rsplit("/", 1)[-1]
        marker = f"!{number}" if "/-/merge_requests/" in ref else f"#{number}"
        for match in _stories_for_urls(db, [ref]):
            add(match["id"], f"references {marker}")
    release_keys = release_mentions(item)
    if (row.get("cluster_key") or "").startswith("release:") and row["cluster_key"] not in release_keys:
        release_keys.insert(0, row["cluster_key"])
    for key in release_keys:
        _, prod, ver = key.split(":", 2)
        reason = f"mentions {prod.replace('-', ' ')} {ver}"
        if (rel_story := _lookup_story(db, cluster_key=key, raise_retired=False)[0]) is not None:
            add(rel_story["id"], reason)
        for match in _mapped_stories(db, "cluster_key=?", key):
            add(match["id"], reason)
    if row.get("source_id"):
        subject, is_reply = thread_subject(item)
        if subject and is_reply:
            for match in _thread_matches(db, row, item, subject):
                add(match["id"], "same thread")
    return pairs


def _earlier_decision_ids(db, row: dict, exclude: set[str] | frozenset[str] = frozenset()) -> list[str]:
    """Story IDs that a retried skipped revision was previously compared against."""
    if not row.get("id") or not row.get("content_hash") or not db.execute(
        "SELECT 1 FROM rejection_actions WHERE item_id=? AND content_hash=? AND action='retry' AND before_status='ignored'",
        (row["id"], row["content_hash"]),
    ).fetchone():
        return []
    seen, found = set(exclude), []

    def push(story_id: str | None) -> None:
        if story_id and story_id not in seen and (live := _live_story(db, story_id)) and live["id"] not in seen:
            seen.add(live["id"])
            found.append(live["id"])

    for (record_blob,) in db.execute(
        "SELECT CAST(review_record AS BLOB) FROM analyses WHERE source_item_id=? ORDER BY rowid DESC",
        (row["id"],),
    ).fetchall():
        rec = saved_object(record_blob)
        if not isinstance(rec, dict) or rec.get("outcome") != "skipped":
            continue
        for rev in rec.get("reviews") or ():
            if not (isinstance(rev, dict) and isinstance(rev.get("result"), dict)):
                continue
            res = rev["result"]
            push(res.get("same_story"))
            reason = ((res.get("criteria") or {}).get("new_information") or {}).get("reason")
            if isinstance(reason, str):
                for cited_id in re.findall(r"\b[0-9a-f]{24}\b", reason):
                    push(cited_id)
        cov = (rec.get("prepared") or {}).get("coverage") or rec.get("coverage")
        if isinstance(cov, dict):
            if isinstance(cov.get("prior_story"), dict):
                push(cov["prior_story"].get("id"))
            if not found:
                for entry in (cov.get("recent") or ())[:8]:
                    if isinstance(entry, dict):
                        push(entry.get("id"))
        break
    return found


def control_fingerprint(db, story_id: str) -> str:
    """Return a deterministic digest of the current editorial controls row for `story_id`."""
    row = db.execute("SELECT revision,locked,retracted,notice_action,notice_reason,notice_at FROM editorial_controls WHERE story_id=?", (story_id,)).fetchone()
    return digest(dict(row) if row else None)


def verify_prepared_binding(db, prepared: dict) -> None:
    """Verify item, lock, editorial controls, and target story still match `prepared`."""
    row, story_id = prepared["row"], prepared["story_id"]
    if editorial.retired(db, story_id=story_id, cluster_key=prepared["cluster_key"]) is not None:
        raise editorial.RetiredStory("Story is retired")
    binding = prepared.get("binding") or {}
    current = db.execute("SELECT * FROM items WHERE id=?", (row["id"],)).fetchone()
    expected_fp = binding.get("item") or item_fingerprint(row)
    if current is None or current["status"] != "pending" or item_fingerprint(dict(current)) != expected_fp:
        raise StaleCandidate("Source item changed before candidate committed")
    if editorial.is_locked(db, story_id) != bool(prepared.get("locked")):
        raise StaleCandidate("Editorial lock state changed before candidate committed")
    expected_lock = binding.get("lock")
    if expected_lock is not None and control_fingerprint(db, story_id) != expected_lock:
        raise StaleCandidate("Editorial controls changed before candidate committed")
    expected_prior = binding.get("prior_story")
    if expected_prior is not None and digest(existing_story(db, dict(current))) != expected_prior:
        raise StaleCandidate("Target story changed before candidate committed")


def validate_approved(original: dict, approved: object, mode: str = "story") -> tuple[str, ...]:
    """Validate an approved public candidate against `original` and return editable fields."""
    editable = UPDATE_FIELDS if mode == "update" else SEMANTIC_FIELDS
    if not isinstance(approved, dict) or set(approved) != set(original):
        raise ReviewRequired("Approval must identify the complete public candidate")
    if any(approved[key] != original[key] for key in original if key not in editable):
        raise ReviewRequired("Review cannot change story identity, sources, dates or editorial metadata")
    if mode == "update":
        orig_updates, app_updates = original.get("updates"), approved.get("updates")
        if (not isinstance(orig_updates, list) or not isinstance(app_updates, list)
                or len(app_updates) != len(orig_updates) or not orig_updates
                or app_updates[:-1] != orig_updates[:-1]
                or not isinstance(app_updates[-1], dict) or not isinstance(orig_updates[-1], dict)
                or "at" not in app_updates[-1] or "sources" not in app_updates[-1]
                or app_updates[-1]["at"] != orig_updates[-1].get("at")
                or app_updates[-1]["sources"] != orig_updates[-1].get("sources")):
            raise ReviewRequired("Update review cannot change earlier updates or the new update's date or citations")
    try:
        normalized = render.prepare_story(approved, editorial=original.get("editorial"))
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise ReviewRequired("The approved candidate must already be normalized") from exc
    if normalized != approved:
        raise ReviewRequired("The approved candidate must already be normalized")
    return editable


def prepare(
    db, row: dict, result: dict, observed: str, *, dirauth_users: Iterable[str] | None = None
) -> dict:
    """Assemble the exact candidate and bind all state needed for its guarded commit."""
    # Copy caller-owned values so later repairs cannot mutate the original draft.
    row, result = json.loads(json.dumps(row)), json.loads(json.dumps(result))
    current = db.execute("SELECT * FROM items WHERE id=?", (row["id"],)).fetchone()
    if current is None or item_fingerprint(dict(current)) != item_fingerprint(row):
        raise StaleCandidate("Source item changed before candidate preparation")
    item = json.loads(row["payload"])
    existing, how = associate(db, row)
    cluster = existing["cluster_key"] if existing else (story_cluster(item) if item.get("kind") == "feed" else row["cluster_key"])
    story_id = existing["id"] if existing else digest(cluster)[:24]
    if existing is None and editorial.retired(db, story_id=story_id, cluster_key=cluster) is not None:
        raise editorial.RetiredStory("Story is retired")
    locked = editorial.is_locked(db, story_id)
    previous = json.loads(existing["payload"]) if existing else None
    mode = _mode(previous, item, db)
    binding = {"item": item_fingerprint(row), "prior_story": digest(existing),
               "lock": control_fingerprint(db, story_id), "mode": mode, "sources": []}
    envelope = {"row": row, "result": result, "story_id": story_id,
                "cluster_key": cluster,
                "mode": mode, "how": how, "candidate": None, "payload": None,
                "packet": {"sources": [], "missing_sources": [], "truncated": False},
                "binding": binding, "locked": locked, "coverage": None,
                "observed": observed}
    if dirauth_users is not None:
        envelope["dirauth_users"] = list(dirauth_users)
    if not locked:
        if ("update" in result) != (mode == "update"):
            raise StaleCandidate("Draft scope does not match current story state")
        source = {key: item[key] for key in ("id", "url", "title", "published_at")}
        writer, kind, authority = writer_info(previous, db)
        if mode == "update":
            _, old_item, cutoff, changed_ids, body_changed = _own_diff(db, previous, item, writer)
            state_changed = bool(old_item and item.get("upstream_state") != old_item.get("upstream_state"))
            comments = _comment_sources(item, result, after_at=cutoff, include_body=body_changed, changed_ids=changed_ids)
            note_edits = {
                note_key(n["id"]): n["edited_at"]
                for n in item.get("public_comments") or []
                if isinstance(n.get("id"), str) and isinstance(n.get("edited_at"), str) and n["edited_at"]
            }
            fallback_edit_at = max(d for d in (item["updated_at"], item.get("comments_checked_at")) if isinstance(d, str) and d)
            dates = [
                *(note_edits.get(nid, max(fallback_edit_at, c["published_at"]))
                  if (nid := note_key(c["id"].removeprefix(item["id"] + ":"))) in changed_ids else c["published_at"]
                  for c in comments),
                *([item["updated_at"]] if state_changed else []),
            ]
            if not dates and changed_ids and not body_changed:
                dates = [note_edits.get(nid, fallback_edit_at) for nid in changed_ids]
            at = max(dates) if dates else item["updated_at"]
            comment_links = list({c["url"]: {"url": c["url"], "title": c["title"]}
                                  for c in comments if c["url"] != source["url"]}.values())
            entry_sources = ([{"url": source["url"], "title": source["title"]}, *comment_links[-2:]]
                             if state_changed else (comment_links[-3:] or [{"url": source["url"], "title": source["title"]}]))
            kept_sources = previous.get("sources", [])
            data = {key: previous.get(key) for key in SEMANTIC_FIELDS}
            fixed_alert = previous.get("origin") == "network-health"
            data.update(confidence=previous["confidence"] if fixed_alert else result["confidence"],
                        state=previous["state"] if fixed_alert else result["state"],
                        editorial_kind=kind, editorial_item=writer,
                        updates=[*(previous.get("updates") or []), {"at": at, "text": result["update"], "sources": entry_sources}])
            if authority:
                data["editorial_authority"] = authority
            strip_unreleased_tag(data)
            if previous.get("editorial_analysis_key"):
                data["editorial_analysis_key"] = previous["editorial_analysis_key"]
            effective_updated = max(previous["updated_at"], at)
        else:
            # Only a newly cited note moves the story's date, to the time it was written.
            comments = _comment_sources(item, result)
            effective_updated = max([item["updated_at"], *(c["published_at"] for c in comments),
                                     previous["updated_at"] if previous else item["published_at"]])
            kept_sources = [entry for entry in (previous or {}).get("sources", [])
                            if entry.get("id") != item["id"] and entry.get("source_item_id") != item["id"]]
            data = {key: result[key] for key in SEMANTIC_FIELDS}
            data.update(editorial_kind=item["kind"], editorial_item=item["id"],
                        editorial_authority=item.get("authority") or "")
            if previous and previous.get("updates"):  # a new draft never drops the story's dated updates
                data["updates"] = previous["updates"]
        source_map = {entry["url"]: entry for entry in kept_sources}
        source_map[source["url"]] = source
        source_map.update({comment["url"]: comment for comment in comments})
        for extra in ("origin", "alert_notes", "network"):
            if previous and previous.get(extra):
                data[extra] = previous[extra]
        data.update(id=story_id, sources=sorted(source_map.values(), key=lambda entry: entry["url"]),
                    published_at=previous["published_at"] if previous else item["published_at"],
                    added_at=previous.get("added_at", previous["published_at"]) if previous else observed,
                    updated_at=effective_updated)
        public = render.prepare_story(data, editorial=editorial.public_metadata(db, story_id))
        # Store exactly the normalized reviewed display fields while retaining
        # collection identities privately for future grouping and source lookup.
        data.update({key: value for key, value in public.items() if key not in {"sources", "editorial"}})
        associated = existing is not None and writer != item["id"]
        excluded = {story_id} if existing else frozenset()
        related_rows = related(db, row, item, excluded)
        earlier_ids = _earlier_decision_ids(db, row, excluded | {sid for sid, _ in related_rows})
        writer = data["editorial_item"]
        packet, bindings = source_packet.build_packet(
            db, item, data, public, writer, update=mode == "update", dirauth_users=dirauth_users
        )
        binding["sources"] = bindings
        envelope.update(candidate=public, payload=data, packet=packet,
                        coverage=coverage_background(db, existing, related_rows=related_rows,
                                                     earlier_ids=earlier_ids, associated=associated))
    candidate_hash = digest(envelope["candidate"])
    packet_hash = digest(envelope["packet"])
    coverage_hash = digest(envelope["coverage"])
    binding.update(payload_hash=digest(envelope["payload"]), candidate_hash=candidate_hash,
                   packet_hash=packet_hash, coverage_hash=coverage_hash)
    envelope.update(candidate_hash=candidate_hash, source_hash=packet_hash,
                    coverage_hash=coverage_hash, binding_hash=digest(binding))
    return envelope
