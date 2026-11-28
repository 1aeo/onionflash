"""Read-only final-story assembly and immutable publication bindings."""

from __future__ import annotations

from collections.abc import Iterable
import copy
import json
import math
import re

from . import editorial, render, source_packet
from .analyze import MIN_EVIDENCE_CHARS
from .comments import analysis_context, budget_unchanged_note_ids, note_key, prior_notes
from .llm import is_quoted_list_post, strip_unreleased_tag, unquoted_mail_text, unquoted_text
from .schema import SEMANTIC_FIELDS, UPDATE_FIELDS
from .util import (
    DIRAUTH_NICKNAME_RE, _PRODUCT_NAMES, _RELEASE_MENTION, _url_host, after, cve_ids, digest,
    duplicate_issue_refs, gitlab_refs, gitlab_url_variants, is_protected_duplicate_issue,
    item_cluster, item_identity, item_pt_family, normalize_evidence, plain_text, release_mentions,
    safe_canonical_url, saved_object, story_cluster, thread_subject, trove_ids,
)


UNVERIFIED_ROUTE = "Attached to an existing story for update review"
COVERAGE_ROWS = 40
COVERAGE_CHARS = 18000
COVERAGE_SUMMARY_CHARS = 300
RELATED_SUMMARY_CHARS = 400
RELATED_LIMIT = 10
THREAD_WINDOW_DAYS = 45
LEXICAL_WINDOW_DAYS = 90
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


def item_source(item: dict) -> dict:
    """Return the canonical four-field citation entry for `item`."""
    return {key: item[key] for key in ("id", "url", "title", "published_at")}


def _source_matches(entry: object, item_id: str | None, bases: set[str]) -> bool:
    return isinstance(entry, dict) and bool(
        (item_id and (entry.get("id") == item_id or entry.get("source_item_id") == item_id))
        or _url_matches(entry.get("url"), bases)
    )


def _update_cites(update_entry: object, bases: set[str]) -> bool:
    return isinstance(update_entry, dict) and any(
        isinstance(cs, dict) and _url_matches(cs.get("url"), bases) for cs in (update_entry.get("sources") or ())
    )


def story_cites_item(story: dict, item_id: str | None, *urls: str | None) -> bool:
    """Return whether `story` cites `item_id` or `urls` in its top-level or dated update sources."""
    bases = {u for raw in urls if (u := _norm_url(raw))}
    return (
        any(_source_matches(s, item_id, bases) for s in (story.get("sources") or ()))
        or any(_update_cites(u, bases) for u in (story.get("updates") or ()))
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
        if (obj := saved_object(blob)) and isinstance(obj.get("title"), str) and obj["title"].strip():
            return obj["title"].strip()[:180]
    return "Retracted story"


def coverage_background(db, prior: dict | None, *, related_rows: list[tuple[str, str]] | tuple[tuple[str, str], ...] = (),
                        earlier_ids: list[str] | tuple[str, ...] = (), associated: bool = False) -> dict:
    """Bounded committed coverage for editorial comparison, never source evidence."""
    def public_text(row):
        """Normalize public coverage fields and reject mismatched stored identities."""
        raw_payload = row["payload"]
        decoded = saved_object(raw_payload.encode("utf-8") if isinstance(raw_payload, str) else raw_payload)
        if decoded is None:
            raise ValueError("Damaged story payload")
        public = render.prepare_story(decoded)
        if public["id"] != row["id"]:
            raise ValueError("Coverage identity differs from its stored story")
        out = {key: public[key] for key in ("id", *SEMANTIC_FIELDS, "published_at", "updated_at", "added_at")}
        for optional in ("updates", "origin"):
            if optional in public:
                out[optional] = public[optional]
        return out

    def _compact_entry(row, *, summary_limit: int = COVERAGE_SUMMARY_CHARS, reason: str | None = None) -> dict:
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

    def _try_add(row, *, summary_limit: int = COVERAGE_SUMMARY_CHARS, reason: str | None = None) -> bool:
        try:
            entry = _compact_entry(row, summary_limit=summary_limit, reason=reason)
        except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError):
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
    story_sql = (
        "SELECT s.id,CASE WHEN typeof(s.payload)='text' THEN CAST(s.payload AS BLOB) END AS payload,"
        "COALESCE(e.retracted,0) AS retracted FROM stories s LEFT JOIN editorial_controls e ON e.story_id=s.id"
    )
    for story_id, limit, reason in pinned:
        if story_id in seen_ids:
            continue
        pinned_row = db.execute(f"{story_sql} WHERE s.id=?", (story_id,)).fetchone()
        if pinned_row is not None and not pinned_row["retracted"] and not _try_add(pinned_row, summary_limit=limit, reason=reason):
            return result

    added_expr = (
        "CASE WHEN typeof(s.payload)='text' AND json_valid(s.payload) AND json_type(s.payload, '$.added_at')='text' "
        "THEN json_extract(s.payload, '$.added_at') END"
    )
    for row in db.execute(
        f"{story_sql} ORDER BY MAX(s.updated_at, COALESCE({added_expr}, s.published_at)) DESC, s.rowid DESC LIMIT ?",
        (COVERAGE_ROWS + 1,),
    ).fetchall():
        if row["id"] not in seen_ids and not _try_add(row):
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
        if (saved := saved_object(writer_row[0] if writer_row else None)) and isinstance(saved.get("authority"), str):
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
        if previous.get("state") in {"tagged", "released"}:
            return "update" if item.get("tag_enriched") is True else "citation"
        return "update"
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
        if (rec := saved_object(record_blob)) and rec.get("outcome") in {"approved", "operator_approved"}:
            return snap
    if analysis_key and (row := db.execute("SELECT CAST(source_payload AS BLOB) FROM analyses WHERE cache_key=?", (analysis_key,)).fetchone()):
        return saved_object(row[0])
    return None


def _source_cutoff(db, previous: dict, old_item: dict | None, item: dict | None = None) -> str:
    item_id = (item or old_item or {}).get("id") or previous.get("editorial_item")
    own_urls = {u for u in (_norm_url((item or {}).get("url")), _norm_url((old_item or {}).get("url"))) if u}
    initial_at = (old_item or {}).get("published_at") or (item or {}).get("published_at") or previous["published_at"]
    dates = [
        initial_at,
        *(s["published_at"] for s in previous.get("sources", []) if _source_matches(s, item_id, own_urls) and s.get("published_at")),
        *(u["at"] for u in previous.get("updates") or () if _update_cites(u, own_urls) and u.get("at")),
    ]
    if old_item is not None:
        if old_item.get("kind") != "gitlab_issue":
            dates.append(old_item["updated_at"])
        dates += [n["created_at"] for n in old_item.get("public_comments") or []]
    elif (
        db.execute("SELECT 1 FROM editorial_controls WHERE story_id=?", (previous["id"],)).fetchone() is None
        and all(_source_matches(s, item_id, own_urls) for s in previous.get("sources", []) if isinstance(s, dict) and not s.get("network_key"))
        and all(_update_cites(u, own_urls) for u in (previous.get("updates") or ()) if isinstance(u, dict))
    ):
        dates.append(previous["updated_at"])
    return max(dates)


def _changed_note_ids(old_item: dict | None, item: dict) -> set[str]:
    prev_comments = (old_item or {}).get("public_comments")
    seen_notes = prior_notes(prev_comments)
    notes = item.get("public_comments") or []
    budget_unchanged = budget_unchanged_note_ids(prev_comments, notes)
    return {
        nkey
        for note in notes
        if "id" in note
        and (old_note := seen_notes.get(nkey := note_key(note["id"]))) is not None
        and nkey not in budget_unchanged
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
        _unq = lambda v: unquoted_text(str(v or "")).strip()
        _fields = lambda d: (_unq(d.get("title")), _unq(d.get("upstream_state")), _unq(d.get("source_content", d.get("content"))))
        body_changed = _fields(item) != _fields(prior_snap)
    return True, prior_snap, cutoff, changed_ids, body_changed


_REPLY_SUBJECT = re.compile(r"(?:^|\])\s*re:", re.I)


def own_update_input(db, row: dict, item: dict, *, existing=_UNSET) -> tuple[str, dict]:
    """Filter own-item and mailing-list reply updates to unquoted text; skip when nothing new exists."""
    if existing is _UNSET:
        existing = existing_story(db, row)
    if existing is None:
        root = _thread_root_item(db, row, item)
        return ("story", {**item, "thread_root": root}) if root is not None else ("story", item)
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
            any(ln.lstrip().startswith(">") for ln in raw.splitlines())
            and ("/hyperkitty/list/" in (item.get("url") or "") or item.get("kind") == "pipermail" or (item.get("kind") in {"feed", "rss"} and is_reply))
            and (stripped := unquoted_mail_text(raw)) != raw
        ):
            filtered = copy.deepcopy(item)
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
    filtered = copy.deepcopy(item)
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


_STORY_SAFE_COLUMNS = (
    "id,cluster_key,typeof(payload) AS _payload_type,"
    "CAST(payload AS BLOB) AS _payload_blob,published_at,updated_at"
)


def _decode_story_row(row, *, raise_retired: bool) -> dict | None:
    if row is None:
        return None
    if row["_payload_type"] != "text" or saved_object(row["_payload_blob"]) is None:
        if raise_retired:
            raise ValueError("Damaged story payload")
        return None
    return {
        "id": row["id"],
        "cluster_key": row["cluster_key"],
        "payload": str(row["_payload_blob"], "utf-8"),
        "published_at": row["published_at"],
        "updated_at": row["updated_at"],
    }


def _lookup_story(db, *, story_id: str | None = None, cluster_key: str | None = None,
                  raise_retired: bool = True) -> tuple[dict | None, str | None]:
    """Resolve `story_id` and/or `cluster_key` to `(live_story_dict, match_kind)`."""
    def _follow_id(sid: str | None):
        return db.execute(f"SELECT {_STORY_SAFE_COLUMNS} FROM stories WHERE id=?", (sid,)).fetchone() if sid else None

    def _resolve(row, *, allow_second: bool = True) -> dict | None:
        if row is not None and (alias := editorial.retired(db, story_id=row["id"], cluster_key=row["cluster_key"])) is not None:
            row = _follow_id(alias[1])
            if allow_second and row is not None and (calias := editorial.retired(db, story_id=row["id"], cluster_key=row["cluster_key"])) is not None:
                row = _follow_id(calias[1])
        if row is None and raise_retired:
            raise editorial.RetiredStory("Story is retired")
        return _decode_story_row(row, raise_retired=raise_retired)

    for col, val, label in (("id", story_id, "story_id"), ("cluster_key", cluster_key, "cluster")):
        if not val:
            continue
        if (alias := editorial.retired(db, **{label if label == "story_id" else "cluster_key": val})) is not None:
            return (target, "alias") if (target := _resolve(_follow_id(alias[1]), allow_second=False)) else (None, None)
        if (row := db.execute(f"SELECT {_STORY_SAFE_COLUMNS} FROM stories WHERE {col}=?", (val,)).fetchone()) is not None:
            return (target, label) if (target := _resolve(row)) else (None, None)
    return None, None


def _live_story(db, story_id: str | None) -> dict | None:
    return _lookup_story(db, story_id=story_id, raise_retired=False)[0]


_MAPPED_PREDICATE = "story_id IS NOT NULL AND NOT (status IS 'pending' AND last_error IS ?)"


def _unique_live_stories(db, story_ids: Iterable[str | None]) -> list[dict]:
    seen, found = set(), []
    for sid in story_ids:
        if (live := _live_story(db, sid)) and live["id"] not in seen:
            seen.add(live["id"])
            found.append(live)
    return found


def _mapped_stories(db, where: str, *params) -> list[dict]:
    rows = db.execute(f"SELECT DISTINCT story_id FROM items WHERE ({where}) AND {_MAPPED_PREDICATE}",
                      (*params, UNVERIFIED_ROUTE)).fetchall()
    return _unique_live_stories(db, (sid for (sid,) in rows))


def _stories_for_urls(db, urls: list[str]) -> list[dict]:
    variants = tuple(dict.fromkeys(v.lower() for url in urls for v in (gitlab_url_variants(url) or {url})))
    return _mapped_stories(db, f"LOWER(url) IN ({','.join('?' * len(variants))})", *variants) if variants else []


def _thread_candidates(db, row: dict, item: dict, *, mapped_only: bool) -> list[tuple[str | None, dict, bool]]:
    if db is None or not isinstance(item, dict) or not row.get("source_id") or not isinstance(item.get("published_at"), str):
        return []
    subject, is_reply = thread_subject(item)
    if not (subject and is_reply):
        return []
    try:
        earliest = after(-THREAD_WINDOW_DAYS * 86400, item["published_at"])
    except ValueError:
        return []
    where = "source_id=? AND id!=?" + (f" AND {_MAPPED_PREDICATE}" if mapped_only else "")
    params = (row["source_id"], row.get("id") or item.get("id") or "", *([UNVERIFIED_ROUTE] if mapped_only else ()))
    rows = db.execute(f"SELECT story_id,CAST(payload AS BLOB) FROM items WHERE {where}", params).fetchall()
    out: list[tuple[str | None, dict, bool]] = []
    for sid, payload_blob in rows:
        other = saved_object(payload_blob)
        if not (isinstance(other, dict) and isinstance(other.get("published_at"), str)):
            continue
        if not (earliest <= other["published_at"] <= item["published_at"]):
            continue
        other_subj, other_is_reply = thread_subject(other)
        if other_subj == subject:
            out.append((sid, other, other_is_reply))
    return out


def _thread_matches(db, row: dict, item: dict) -> list[dict]:
    return _unique_live_stories(db, (sid for sid, _, _ in _thread_candidates(db, row, item, mapped_only=True)))


def _thread_root_item(db, row: dict, item: dict) -> dict | None:
    """Return bounded parent-thread metadata from the earliest same-list item matching `item`'s reply subject."""
    candidates = _thread_candidates(db, row, item, mapped_only=False)
    if not candidates:
        return None
    _, other, _ = min(candidates, key=lambda entry: (entry[1]["published_at"], entry[2], str(entry[1].get("url") or "")))
    raw_body = other.get("source_content") if isinstance(other.get("source_content"), str) else (other.get("content") or "")
    unquoted = unquoted_mail_text(raw_body) if raw_body else ""
    return {
        "title": plain_text(other.get("title") or "", 200, html=False),
        "published_at": other["published_at"],
        "url": safe_canonical_url(other.get("url")) or str(other.get("url") or ""),
        "excerpt": plain_text(unquoted, 360, html=False),
    }


def _stories_closed_by_mr(db, item: dict) -> list[dict]:
    """Return live stories mapped to merged MRs whose closing refs explicitly target `item`'s URL."""
    item_variants = {v.lower() for v in gitlab_url_variants(item.get("url"))}
    if not item_variants:
        return []
    rows = db.execute(
        f"""SELECT story_id, CAST(payload AS BLOB) AS payload
            FROM items
            WHERE {_MAPPED_PREDICATE}
              AND (typeof(payload)!='text'
                   OR (json_valid(payload) AND json_type(payload)='object'
                       AND json_extract(payload,'$.kind')='gitlab_mr'))""",
        (UNVERIFIED_ROUTE,),
    ).fetchall()
    matching_sids: list[str] = []
    for sid, payload_blob in rows:
        mr = saved_object(payload_blob)
        if not isinstance(mr, dict) or mr.get("kind") != "gitlab_mr" or mr.get("upstream_state") != "merged":
            continue
        closing, _ = gitlab_refs(mr)
        if any(ref.lower() in item_variants for ref in closing):
            matching_sids.append(sid)
    return _unique_live_stories(db, matching_sids)


def associate(db, row: dict) -> tuple[dict | None, str | None]:
    """Attach an item to at most one live story using deterministic identities."""
    matched, how = _lookup_story(db, story_id=row.get("story_id"))
    if matched is not None:
        return matched, how
    payload = row.get("payload")
    item = saved_object(payload.encode("utf-8") if isinstance(payload, str) else payload) if isinstance(payload, (str, bytes)) else None
    cluster = row["cluster_key"]
    release_tag = isinstance(item, dict) and item.get("kind") == "tag" and cluster.startswith("release:")

    def tagged_or_released(story):
        """Return whether `story` is currently in a `tagged` or `released` state."""
        public = saved_object(story["payload"].encode("utf-8") if isinstance(story["payload"], str) else story["payload"])
        return isinstance(public, dict) and public.get("state") in {"tagged", "released"}

    # Release versions are coverage hints for new prose, not an automatic article
    # assignment. Explicit prior mappings and permanent aliases still take precedence.
    if (isinstance(item, dict) and item.get("kind") == "feed" and cluster.startswith("release:")
            and editorial.retired(db, cluster_key=cluster) is None):
        legacy, _ = _lookup_story(db, cluster_key=cluster)
        if legacy is not None:
            public = saved_object(legacy["payload"].encode("utf-8") if isinstance(legacy["payload"], str) else legacy["payload"])
            if isinstance(public, dict) and story_cites_item(public, item.get("id"), item.get("url")):
                return legacy, "source"
        cluster = story_cluster(item)
    matched, how = _lookup_story(db, cluster_key=cluster)
    if matched is not None and (not release_tag or how == "alias" or tagged_or_released(matched)):
        return matched, how
    cluster_matches = _mapped_stories(db, "cluster_key=?", cluster)
    if release_tag:
        cluster_matches = [story for story in cluster_matches if tagged_or_released(story)]
    if len(cluster_matches) == 1:
        return cluster_matches[0], "item_cluster"
    if len(cluster_matches) > 1:
        return None, None
    if not isinstance(item, dict):
        return None, None
    if item.get("kind") == "gitlab_mr" and item.get("upstream_state") == "merged":
        closing, _ = gitlab_refs(item)
        if closing and (matches := _stories_for_urls(db, closing)):
            return (matches[0], "closing_ref") if len(matches) == 1 else (None, None)
    if item.get("kind") == "gitlab_issue":
        if is_protected_duplicate_issue(item) and (dup_refs := duplicate_issue_refs(item)):
            if matches := _stories_for_urls(db, dup_refs):
                return (matches[0], "duplicate_ref") if len(matches) == 1 else (None, None)
        if matches := _stories_closed_by_mr(db, item):
            return (matches[0], "closed_by_mr") if len(matches) == 1 else (None, None)
    if matches := _thread_matches(db, row, item):
        return (matches[0], "thread") if len(matches) == 1 else (None, None)
    return None, None


def existing_story(db, row: dict):
    """Return the single live story associated with `row`, or `None` if unassociated."""
    return associate(db, row)[0]


def _stories_for_identifier(db, identifier: str, extractor) -> list[dict]:
    """Return live stories whose content or mapped source items explicitly cite `identifier`."""
    pattern = f"%{identifier}%"
    ids: list[str] = []
    for story_row in db.execute(
        "SELECT id,CASE WHEN typeof(payload)='text' THEN CAST(payload AS BLOB) END AS payload "
        "FROM stories WHERE payload LIKE ? ORDER BY updated_at DESC,id",
        (pattern,),
    ).fetchall():
        story = saved_object(story_row["payload"])
        if not story:
            continue
        text = "\n".join(str(story.get(k) or "") for k in ("title", "summary", "why_it_matters", "latest_update"))
        updates = "\n".join(str(u.get("text") or "") for u in (story.get("updates") or ()) if isinstance(u, dict))
        if identifier in extractor({"title": text, "content": updates}):
            ids.append(story_row["id"])
    for item_row in db.execute(
        f"SELECT story_id,CASE WHEN typeof(payload)='text' THEN CAST(payload AS BLOB) END AS payload "
        f"FROM items WHERE payload LIKE ? AND {_MAPPED_PREDICATE}",
        (pattern, UNVERIFIED_ROUTE),
    ).fetchall():
        mapped_item = saved_object(item_row["payload"])
        if mapped_item and identifier in extractor(mapped_item):
            ids.append(item_row["story_id"])
    return _unique_live_stories(db, ids)


def _stories_for_trove(db, trove_id: str) -> list[dict]:
    """Return live stories whose content or mapped source items explicitly cite `trove_id`."""
    return _stories_for_identifier(db, trove_id, trove_ids)


_RARE_TOKEN_RE = re.compile(r"(?=[a-z0-9]*[a-z])[a-z0-9]{4,}")
_LEXICAL_STOPWORDS = frozenset({
    "tor", "arti", "tails", "browser", "onion", "flash", "project", "release", "released", "releases",
    "update", "updated", "updates", "issue", "issues", "ticket", "tickets", "merge", "merged", "merges",
    "request", "requests", "requested", "fix", "fixes", "fixed", "fixing", "patch", "patches", "patched",
    "version", "versions", "client", "clients", "server", "servers", "network", "networks",
    "relay", "relays", "change", "changes", "changed", "support", "supported", "supports",
    "default", "defaults", "service", "services", "report", "reported", "reports", "reporting",
    "security", "status", "state", "upstream", "downstream", "operator", "operators",
    "maintainer", "maintainers", "developer", "developers", "author", "authors", "user", "users",
    "thread", "threads", "reply", "replies", "message", "messages", "comment", "comments",
    "post", "posted", "posts", "announcement", "announced", "announces", "notice", "notices",
    "summary", "detail", "details", "description", "section", "directory", "authority", "authorities",
    "about", "above", "across", "after", "again", "against", "already", "also", "among", "another",
    "around", "because", "before", "being", "below", "between", "both", "case", "cases", "could",
    "date", "dates", "does", "doing", "done", "down", "during", "each", "either", "else", "even",
    "every", "find", "first", "following", "found", "from", "full", "further", "give", "given",
    "gives", "good", "have", "having", "hello", "here", "high", "however", "into", "just", "keep",
    "keeps", "kept", "known", "last", "later", "less", "like", "likely", "long", "made", "make",
    "makes", "many", "month", "months", "more", "most", "much", "must", "near", "need", "needs",
    "never", "next", "none", "normal", "note", "noted", "notes", "only", "open", "opened", "other",
    "others", "over", "part", "parts", "past", "perhaps", "please", "possible", "prior", "public",
    "rather", "recent", "recently", "regards", "said", "same", "says", "second", "seem", "seems",
    "several", "short", "should", "show", "shown", "shows", "since", "some", "soon", "still",
    "such", "take", "takes", "than", "thank", "thanks", "that", "their", "them", "then", "there",
    "these", "they", "third", "this", "those", "though", "three", "through", "time", "times",
    "today", "under", "until", "used", "using", "various", "very", "want", "wants", "week",
    "weeks", "well", "were", "what", "when", "where", "which", "while", "will", "with", "within",
    "without", "work", "worked", "working", "works", "would", "year", "years",
    "https", "http", "gitlab", "torproject", "lists", "mailman3", "hyperkitty", "html", "mail",
    "blog", "forum",
})


def _normalize_rare_token(token: str) -> str:
    if len(token) >= 5 and token.endswith("s") and not token.endswith(("ss", "us", "is", "as", "os")):
        return token[:-1]
    return token


def _rare_tokens(text: str) -> set[str]:
    tokens = (_normalize_rare_token(tok) for tok in _RARE_TOKEN_RE.findall(text.casefold()))
    return {tok for tok in tokens if tok not in _LEXICAL_STOPWORDS}


def _item_search_text(item: dict) -> str:
    title = item.get("title") if isinstance(item.get("title"), str) else ""
    body = item.get("source_content") if isinstance(item.get("source_content"), str) else (item.get("content") or "")
    if is_quoted_list_post(item.get("url"), body):
        body = unquoted_mail_text(body)
    comments = "\n".join(
        str(note.get("body") or "")
        for note in (item.get("public_comments") or ())
        if isinstance(note, dict)
    )
    return "\n".join((title, body, comments))


def _story_search_text(story: dict) -> str:
    fields = [str(story.get(k) or "") for k in ("title", "summary", "why_it_matters", "latest_update")]
    updates = [str(u.get("text") or "") for u in (story.get("updates") or ()) if isinstance(u, dict)]
    return "\n".join((*fields, *updates))


_PT_FAMILY_TOKENS = frozenset({"snowflake", "webtunnel", "lyrebird", "obfs4", "obfs4proxy", "conjure"})
_PT_GENERIC_TOKENS = frozenset(_normalize_rare_token(tok) for tok in (
    "pluggable", "transport", "transports", "bridge", "bridges", "proxy", "proxies",
))
_PT_PROJECT_SCOPE_RE = re.compile(
    r"^https://gitlab\.torproject\.org/([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+?)/-/",
    re.I,
)


def _source_repo_scopes(entries: Iterable[dict]) -> set[str]:
    scopes: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        url = str(entry.get("url") or "")
        if match := _PT_PROJECT_SCOPE_RE.match(url):
            scopes.add(f"gitlab:{match.group(1).lower()}")
        elif host := _url_host(url):
            scopes.add(f"host:{host}")
        for field in ("source_id", "source_name", "feed", "stream", "project"):
            val = entry.get(field)
            if isinstance(val, str) and val.strip():
                scopes.add(f"src:{val.strip().lower()}")
    return scopes


def _story_pt_family(story: dict) -> str | None:
    tags = story.get("tags") if isinstance(story.get("tags"), list) else ()
    generic_fallback: str | None = None
    for src in (story.get("sources") or ()):
        if isinstance(src, dict):
            if family := item_pt_family({"url": src.get("url") or "", "title": src.get("title") or "", "tags": tags}):
                if family != "pluggable-transports":
                    return family
                generic_fallback = family
    text_family = item_pt_family({"title": story.get("title") or "", "content": _story_search_text(story), "tags": tags})
    if text_family and text_family != "pluggable-transports":
        return text_family
    return generic_fallback or text_family


_RELEASE_PROD_PATTERNS = {**_PRODUCT_NAMES, "tails": "tails"}
_SENTENCE_SPLIT_RE = re.compile(r"\n+|(?<!\d)\.(?!\d)(?:\s+|$)|[!?]+")


def release_story_key(cluster_key: str, story_obj: dict) -> str | None:
    """Return a canonical `release:<product>:<version>` key for a release/tag story, or None."""
    if isinstance(cluster_key, str) and cluster_key.startswith("release:"):
        return cluster_key
    if story_obj.get("state") not in {"released", "tagged"} and story_obj.get("category") != "release":
        return None
    title = str(story_obj.get("title") or "")
    products = story_obj.get("products") or ()
    software = [p for p in products if p != "network"]
    inferred_prod = (
        "tails"
        if ("tails" in products or re.match(r"^\s*(?:new\s+release\s*:\s*)?tails\b", title, re.I))
        else (software[0] if len(software) == 1 else "network")
    )
    clustered = item_cluster({"kind": "feed", "title": title, "content": "", "url": "", "product": inferred_prod})
    if clustered.startswith("release:"):
        return clustered
    versions = release_mentions({"title": title})
    return versions[0] if versions else None


def _other_product_version_spans(item_text: str, prod: str, ver: str) -> list[tuple[int, int]]:
    if not item_text or not prod or not ver:
        return []
    ver_fold = ver.lower()
    return [
        (
            m.start(2) - 1 if m.start(2) > m.start(1) and item_text[m.start(2) - 1].lower() == "v" else m.start(2),
            m.end(2),
        )
        for m in _RELEASE_MENTION.finditer(item_text)
        if m.group(2).lower() == ver_fold
        and ("tor-browser" if m.group(1).lower() in {"tor-browser", "tor browser"} else m.group(1).lower()) != prod
    ]


def version_claimed_by_other_product(item_text: str, prod: str, ver: str) -> bool:
    """Return whether `_RELEASE_MENTION` attributes `ver` to a product other than `prod`."""
    return bool(_other_product_version_spans(item_text, prod, ver))


def item_mentions_product_version(item_text: str, prod: str, ver: str) -> bool:
    """Return whether `item_text` mentions `ver` alongside `prod` without another product claiming it."""
    prod_pat = _RELEASE_PROD_PATTERNS.get(prod)
    if not prod_pat or not ver:
        return False
    claimed_other = _other_product_version_spans(item_text, prod, ver)
    ver_pat = re.compile(rf"(?<![\w.])v?{re.escape(ver)}(?!\.\d)(?!\w)", re.I)
    prod_re = re.compile(rf"\b{prod_pat}\b" + (r"(?!\s+project\b)" if prod == "tor" else ""), re.I)
    is_ctor_ver = prod == "tor" and ver.startswith("0.") and ver.count(".") >= 3
    last_end = 0
    for sep in (*_SENTENCE_SPLIT_RE.finditer(item_text), None):
        seg_end = sep.start() if sep is not None else len(item_text)
        sentence = item_text[last_end:seg_end]
        if (is_ctor_ver or prod_re.search(sentence)) and any(
            not any(s <= (last_end + m.start()) <= e for s, e in claimed_other)
            for m in ver_pat.finditer(sentence)
        ):
            return True
        if sep is not None:
            last_end = sep.end()
    return False


def related(db, row: dict, item: dict, exclude: set[str] | frozenset[str] = frozenset()) -> list[tuple[str, str]]:
    """Up to `RELATED_LIMIT` active related `(story_id, reason)` pairs for coverage comparison."""
    seen = set(exclude)
    pairs: list[tuple[str, str]] = []

    def _add(story_id: str | None, reason: str) -> None:
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
            _add(match["id"], f"references {marker}")
    for tid in trove_ids(item):
        for match in _stories_for_trove(db, tid):
            _add(match["id"], f"references {tid}")
    for cid in cve_ids(item):
        for match in _stories_for_identifier(db, cid, cve_ids):
            _add(match["id"], f"references {cid}")
    release_keys = release_mentions(item)
    if (row.get("cluster_key") or "").startswith("release:") and row["cluster_key"] not in release_keys:
        release_keys.insert(0, row["cluster_key"])
    for key in release_keys:
        _, prod, ver = key.split(":", 2)
        reason = f"mentions {prod.replace('-', ' ')} {ver}"
        if (rel_story := _lookup_story(db, cluster_key=key, raise_retired=False)[0]) is not None:
            _add(rel_story["id"], reason)
        for match in _mapped_stories(db, "cluster_key=?", key):
            _add(match["id"], reason)
    for match in _thread_matches(db, row, item):
        _add(match["id"], "same thread")
    if len(pairs) < RELATED_LIMIT:
        item_text = _item_search_text(item)
        candidates: list[tuple[str, str, str, str, dict]] = []
        for srow in db.execute(
            "SELECT s.id,s.cluster_key,s.updated_at,CASE WHEN typeof(s.payload)='text' THEN CAST(s.payload AS BLOB) END AS payload "
            "FROM stories s LEFT JOIN editorial_controls e ON e.story_id=s.id "
            "WHERE COALESCE(e.retracted,0)=0 ORDER BY s.updated_at DESC,s.id"
        ).fetchall():
            if srow["id"] in seen:
                continue
            if story_obj := saved_object(srow["payload"]):
                candidates.append((srow["id"], srow["cluster_key"], srow["updated_at"], _story_search_text(story_obj), story_obj))
        release_key_set = set(release_keys)
        for sid, scluster, _, _, story_obj in candidates:
            if (rel_key := release_story_key(scluster, story_obj)) is None:
                continue
            _, prod, ver = rel_key.split(":", 2)
            if rel_key in release_key_set or item_mentions_product_version(item_text, prod, ver):
                _add(sid, f"mentions {prod.replace('-', ' ')} {ver}")
                if len(pairs) >= RELATED_LIMIT:
                    break
        item_auths = {m.group(0).casefold() for m in DIRAUTH_NICKNAME_RE.finditer(item_text)}
        item_tokens = _rare_tokens(item_text)
        item_pt = item_pt_family(item)
        pub_stamp = item.get("published_at") or item.get("updated_at")
        cutoff_90d = None
        if isinstance(pub_stamp, str) and pub_stamp:
            try:
                cutoff_90d = after(-LEXICAL_WINDOW_DAYS * 86400, pub_stamp)
            except ValueError:
                cutoff_90d = None
        if len(pairs) < RELATED_LIMIT and (item_auths or ((len(item_tokens) >= 2 or item_pt is not None) and cutoff_90d is not None)):
            if item_auths:
                for sid, _, _, stext, _ in candidates:
                    if item_auths & {m.group(0).casefold() for m in DIRAUTH_NICKNAME_RE.finditer(stext)}:
                        _add(sid, "shared authority")
                        if len(pairs) >= RELATED_LIMIT:
                            break
            if len(pairs) < RELATED_LIMIT and len(item_tokens) >= 2 and cutoff_90d is not None:
                window_entries = [
                    (sid, upd_at, _rare_tokens(stext))
                    for sid, _, upd_at, stext, _ in candidates
                    if sid not in seen and isinstance(upd_at, str) and upd_at >= cutoff_90d
                ]
                df: dict[str, int] = {}
                for _, _, stoks in window_entries:
                    for tok in stoks:
                        df[tok] = df.get(tok, 0) + 1
                max_df = max(3, len(window_entries) // 3) if len(window_entries) >= 8 else len(window_entries) + 1
                rare_item = {t for t in item_tokens if df.get(t, 0) <= max_df}
                if len(rare_item) >= 2:
                    scored: list[tuple[float, int, str, str]] = []
                    for sid, upd_at, stoks in window_entries:
                        rare_story = {t for t in stoks if df.get(t, 0) <= max_df}
                        shared = rare_item & rare_story
                        if len(shared) >= 2:
                            overlap = len(shared) / min(len(rare_item), len(rare_story))
                            if overlap >= 0.12 or len(shared) >= 4:
                                idf_score = sum(math.log((len(window_entries) + 1) / (df.get(t, 0) + 1)) for t in shared)
                                scored.append((idf_score, len(shared), upd_at, sid))
                    scored.sort(reverse=True)
                    for _, _, _, sid in scored:
                        _add(sid, "shared technical terms")
                        if len(pairs) >= RELATED_LIMIT:
                            break
            if len(pairs) < RELATED_LIMIT and item_pt is not None and cutoff_90d is not None:
                item_scopes = _source_repo_scopes((item,))
                pt_scored: list[tuple[int, int, str, str]] = []
                for sid, _, upd_at, stext, story_obj in candidates:
                    if sid in seen or not (isinstance(upd_at, str) and upd_at >= cutoff_90d):
                        continue
                    if _story_pt_family(story_obj) != item_pt:
                        continue
                    story_scopes = _source_repo_scopes(story_obj.get("sources") or ())
                    cross_repo = bool(item_scopes and story_scopes and item_scopes.isdisjoint(story_scopes))
                    shared_non_pt = len((item_tokens & _rare_tokens(stext)) - (_PT_FAMILY_TOKENS | _PT_GENERIC_TOKENS))
                    if (item_pt != "pluggable-transports" and (cross_repo or shared_non_pt >= 1)) or (
                        item_pt == "pluggable-transports" and shared_non_pt >= 1
                    ):
                        pt_scored.append((int(cross_repo), shared_non_pt, upd_at, sid))
                pt_scored.sort(reverse=True)
                for _, _, _, sid in pt_scored:
                    _add(sid, f"related {item_pt} transport")
                    if len(pairs) >= RELATED_LIMIT:
                        break
    return pairs


def _earlier_decision_ids(db, row: dict, exclude: set[str] | frozenset[str] = frozenset()) -> list[str]:
    """Story IDs that a retried skipped revision was previously compared against."""
    if not row.get("id") or not row.get("content_hash") or not db.execute(
        "SELECT 1 FROM rejection_actions WHERE item_id=? AND content_hash=? AND action='retry' AND before_status='ignored'",
        (row["id"], row["content_hash"]),
    ).fetchone():
        return []
    seen, found = set(exclude), []

    def _push(story_id: str | None) -> None:
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
            _push(res.get("same_story"))
            reason = ((res.get("criteria") or {}).get("new_information") or {}).get("reason")
            if isinstance(reason, str):
                for cited_id in re.findall(r"\b[0-9a-f]{24}\b", reason):
                    _push(cited_id)
        cov = (rec.get("prepared") or {}).get("coverage") or rec.get("coverage")
        if isinstance(cov, dict):
            if isinstance(cov.get("prior_story"), dict):
                _push(cov["prior_story"].get("id"))
            if not found:
                for entry in (cov.get("recent") or ())[:8]:
                    if isinstance(entry, dict):
                        _push(entry.get("id"))
        break
    return found


def control_fingerprint(db, story_id: str) -> str:
    """Return a deterministic digest of the current editorial controls row for `story_id`."""
    row = db.execute(
        """SELECT revision,locked,retracted,
                  typeof(notice_action) AS _na_t,CAST(notice_action AS BLOB) AS _na_b,
                  typeof(notice_reason) AS _nr_t,CAST(notice_reason AS BLOB) AS _nr_b,
                  typeof(notice_at) AS _nat_t,CAST(notice_at AS BLOB) AS _nat_b
           FROM editorial_controls WHERE story_id=?""",
        (story_id,),
    ).fetchone()
    if row is None:
        return digest(None)

    def _val(kind: str, blob):
        if kind == "null" or blob is None:
            return None
        if kind == "text":
            try:
                return str(blob, "utf-8")
            except UnicodeError:
                return {"invalid_utf8_hex": blob.hex()}
        return (
            {"sqlite_type": kind, "hex": bytes(blob).hex()}
            if isinstance(blob, (bytes, bytearray, memoryview))
            else {"sqlite_type": kind, "value": blob}
        )

    return digest({
        "revision": row["revision"],
        "locked": row["locked"],
        "retracted": row["retracted"],
        "notice_action": _val(row["_na_t"], row["_na_b"]),
        "notice_reason": _val(row["_nr_t"], row["_nr_b"]),
        "notice_at": _val(row["_nat_t"], row["_nat_b"]),
    })


def verify_prepared_binding(db, prepared: dict) -> None:
    """Verify item, lock, editorial controls, and target story still match `prepared`."""
    from .store import ITEM_SAFE_COLUMNS, decode_item_row

    row, story_id = prepared["row"], prepared["story_id"]
    if editorial.retired(db, story_id=story_id, cluster_key=prepared["cluster_key"]) is not None:
        raise editorial.RetiredStory("Story is retired")
    binding = prepared.get("binding") or {}
    raw_current = db.execute(f"SELECT {ITEM_SAFE_COLUMNS} FROM items WHERE id=?", (row["id"],)).fetchone()
    current, _ = decode_item_row(raw_current)
    try:
        expected_fp = binding.get("item") or item_fingerprint(row)
        current_fp = item_fingerprint(current) if current is not None else None
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise StaleCandidate("Source item changed before candidate committed") from None
    if current is None or current["status"] != "pending" or current_fp != expected_fp:
        raise StaleCandidate("Source item changed before candidate committed")
    if editorial.is_locked(db, story_id) != bool(prepared.get("locked")):
        raise StaleCandidate("Editorial lock state changed before candidate committed")
    expected_lock = binding.get("lock")
    if expected_lock is not None and control_fingerprint(db, story_id) != expected_lock:
        raise StaleCandidate("Editorial controls changed before candidate committed")
    expected_prior = binding.get("prior_story")
    if expected_prior is not None and digest(existing_story(db, current)) != expected_prior:
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
                or {k: v for k, v in app_updates[-1].items() if k != "text"}
                != {k: v for k, v in orig_updates[-1].items() if k != "text"}):
            raise ReviewRequired("Update review cannot change earlier updates or the new update's date or citations")
    try:
        normalized = render.prepare_story(approved, editorial=original.get("editorial"))
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise ReviewRequired("The approved candidate must already be normalized") from exc
    if normalized != approved:
        raise ReviewRequired("The approved candidate must already be normalized")
    return editable


def prepare(
    db,
    row: dict,
    result: dict,
    observed: str,
    *,
    dirauth_users: Iterable[str] | None = None,
    tor_core_users: Iterable[str] | None = None,
) -> dict:
    """Assemble the exact candidate and bind all state needed for its guarded commit."""
    from .store import ITEM_SAFE_COLUMNS, decode_item_row

    # Copy caller-owned values so later repairs cannot mutate the original draft.
    row, result = copy.deepcopy(row), copy.deepcopy(result)
    raw_current = db.execute(f"SELECT {ITEM_SAFE_COLUMNS} FROM items WHERE id=?", (row["id"],)).fetchone()
    current, _ = decode_item_row(raw_current)
    try:
        same_item = current is not None and item_fingerprint(current) == item_fingerprint(row)
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        same_item = False
    if not same_item:
        raise StaleCandidate("Source item changed before candidate preparation")
    item = json.loads(row["payload"])
    existing, how = associate(db, row)
    cluster = existing["cluster_key"] if existing else (story_cluster(item) if item.get("kind") == "feed" else row["cluster_key"])
    if (existing is None and item.get("kind") == "tag" and cluster.startswith("release:")
            and db.execute("SELECT 1 FROM stories WHERE cluster_key=?", (cluster,)).fetchone() is not None):
        # A legacy response article can occupy this release key without covering
        # the tag. Review the tag separately while preserving the older article.
        cluster = "url:" + digest(item_identity(item))
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
    if tor_core_users is not None:
        envelope["tor_core_users"] = list(tor_core_users)
    if not locked:
        if ("update" in result) != (mode == "update"):
            raise StaleCandidate("Draft scope does not match current story state")
        source = item_source(item)
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
        thread_root = _thread_root_item(db, row, item) if existing is None else None
        packet, bindings = source_packet.build_packet(
            db, item, data, public, writer, update=mode == "update", dirauth_users=dirauth_users,
            tor_core_users=tor_core_users, thread_root=thread_root,
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
