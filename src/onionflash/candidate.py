"""Read-only final-story assembly and immutable publication bindings."""

from __future__ import annotations

import contextlib
import json
import re

from . import editorial, render, source_packet
from .analyze import MIN_EVIDENCE_CHARS, unquoted_text
from .comments import analysis_context
from .util import after, canonical_url, digest, gitlab_refs, normalize_evidence, release_mentions, saved_object, thread_subject


# Writer fields a review may repair; their order is part of the review policy hash.
SEMANTIC_FIELDS = ("title", "summary", "why_it_matters", "category", "priority", "confidence", "state", "products", "tags")
LABEL_FIELDS = SEMANTIC_FIELDS[3:]
UPDATE_FIELDS = (*LABEL_FIELDS, "updates")
COVERAGE_ROWS = 32
COVERAGE_CHARS = 12000
COVERAGE_SUMMARY_CHARS = 200
RELATED_SUMMARY_CHARS = 400
RELATED_LIMIT = 6
THREAD_WINDOW_DAYS = 45


def _retracted_title(db, row) -> str:
    rev = db.execute(
        """SELECT CAST(before_public_json AS BLOB),CAST(before_story_json AS BLOB)
           FROM editorial_revisions WHERE story_id=? AND action='retract' ORDER BY revision DESC LIMIT 1""",
        (row["id"],),
    ).fetchone()
    if rev is not None:
        for blob in (rev[0], rev[1]):
            if blob is not None:
                before = saved_object(blob)
                if isinstance(before, dict) and isinstance(before.get("title"), str) and before["title"].strip():
                    return before["title"].strip()[:180]
    payload = row["payload"]
    raw = saved_object(payload.encode("utf-8") if isinstance(payload, str) else payload)
    if isinstance(raw, dict) and isinstance(raw.get("title"), str) and raw["title"].strip():
        return raw["title"].strip()[:180]
    return "Retracted story"


def coverage_background(db, prior: dict | None, *, related_rows: list[tuple[str, str]] | tuple[tuple[str, str], ...] = (),
                        earlier_ids: list[str] | tuple[str, ...] = (), associated: bool = False) -> dict:
    """Bounded committed coverage for editorial comparison, never source evidence."""
    def public_text(row):
        """Normalize public coverage fields and reject mismatched stored identities."""
        public = render._prepare_story(json.loads(row["payload"]))
        if public["id"] != row["id"]:
            raise ValueError("Coverage identity differs from its stored story")
        out = {key: public[key] for key in ("id", *SEMANTIC_FIELDS, "published_at", "updated_at", "added_at")}
        if "updates" in public:
            out["updates"] = public["updates"]
        return out

    def compact_entry(row, *, summary_limit: int = COVERAGE_SUMMARY_CHARS, reason: str | None = None) -> dict | None:
        if row["retracted"]:
            return {"id": row["id"], "title": _retracted_title(db, row), "retracted": True}
        current = public_text(row)
        compact = {key: current[key] for key in ("id", "title", "summary", "category", "state", "updated_at")}
        compact["summary"] = current["summary"][:summary_limit]
        compact["summary_truncated"] = len(current["summary"]) > summary_limit
        compact["products"] = current["products"]
        if current.get("updates"):
            compact["latest_update"] = current["updates"][-1]["text"][:COVERAGE_SUMMARY_CHARS]
        if reason is not None:
            compact["related"] = reason
        return compact

    previous = public_text(prior) if prior else None
    if previous is not None and associated:
        previous["associated"] = True
    result = {"prior_story": previous, "recent": [], "truncated": False}
    seen_ids = {prior["id"]} if prior else set()

    def append_entry(entry: dict) -> bool:
        if (len(result["recent"]) + bool(previous) >= COVERAGE_ROWS
                or len(json.dumps({**result, "recent": [*result["recent"], entry]}, ensure_ascii=False)) > COVERAGE_CHARS):
            result["truncated"] = True
            return False
        result["recent"].append(entry)
        seen_ids.add(entry["id"])
        return True

    for story_id, reason in list(related_rows)[:RELATED_LIMIT]:
        if story_id in seen_ids:
            continue
        rel_row = db.execute(
            """SELECT s.id,s.payload,COALESCE(e.retracted,0) AS retracted
               FROM stories s LEFT JOIN editorial_controls e ON e.story_id=s.id WHERE s.id=?""",
            (story_id,),
        ).fetchone()
        if rel_row is None or rel_row["retracted"]:
            continue
        try:
            compact = compact_entry(rel_row, summary_limit=RELATED_SUMMARY_CHARS, reason=reason)
        except (ValueError, TypeError, KeyError, AttributeError, UnicodeError):
            result["truncated"] = True
            continue
        if not append_entry(compact):
            return result

    for story_id in earlier_ids:
        if story_id in seen_ids:
            continue
        early_row = db.execute(
            """SELECT s.id,s.payload,COALESCE(e.retracted,0) AS retracted
               FROM stories s LEFT JOIN editorial_controls e ON e.story_id=s.id WHERE s.id=?""",
            (story_id,),
        ).fetchone()
        if early_row is None or early_row["retracted"]:
            continue
        try:
            compact = compact_entry(early_row, reason="earlier decision")
        except (ValueError, TypeError, KeyError, AttributeError, UnicodeError):
            result["truncated"] = True
            continue
        if not append_entry(compact):
            return result

    rows = db.execute(
        """SELECT s.id,s.payload,COALESCE(e.retracted,0) AS retracted
           FROM stories s LEFT JOIN editorial_controls e ON e.story_id=s.id
           ORDER BY MAX(s.updated_at, COALESCE(json_extract(s.payload, '$.added_at'), s.published_at)) DESC, s.rowid DESC
           LIMIT ?""",
        (COVERAGE_ROWS + 1,),
    ).fetchall()
    for row in rows:
        if row["id"] in seen_ids:
            continue
        try:
            compact = compact_entry(row)
        except (ValueError, TypeError, KeyError, AttributeError, UnicodeError):
            result["truncated"] = True
            continue
        if not append_entry(compact):
            break
    return result


class ReviewRequired(ValueError):
    pass


class StaleCandidate(ValueError):
    pass


def _writer_info(previous: dict | None, db=None) -> tuple[str | None, str, str]:
    if not previous:
        return None, "", ""
    writer = previous.get("editorial_item")
    if writer is None and len(previous.get("sources", [])) == 1:
        writer = previous["sources"][0].get("id")
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
    writer, kind, authority = _writer_info(previous, db)
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

    def norm_url(raw: object) -> str | None:
        if not isinstance(raw, str) or not raw:
            return None
        with contextlib.suppress(ValueError, TypeError, UnicodeError):
            return canonical_url(raw)
        return raw

    own_urls = {u for u in (norm_url((item or {}).get("url")), norm_url((old_item or {}).get("url"))) if u}

    def is_own_url(url: object) -> bool:
        clean = norm_url(url)
        return bool(clean and any(clean == base or clean.startswith(base + "#") for base in own_urls))

    def is_own_source(entry: dict) -> bool:
        return bool(
            (item_id and (entry.get("id") == item_id or entry.get("source_item_id") == item_id))
            or is_own_url(entry.get("url"))
        )

    initial_at = (
        (old_item or {}).get("published_at")
        or (item or {}).get("published_at")
        or previous["published_at"]
    )
    dates = [
        initial_at,
        *(s["published_at"] for s in previous.get("sources", []) if isinstance(s, dict) and s.get("published_at") and is_own_source(s)),
        *(
            u["at"]
            for u in previous.get("updates") or []
            if isinstance(u, dict)
            and u.get("at")
            and any(isinstance(cs, dict) and is_own_url(cs.get("url")) for cs in (u.get("sources") or []))
        ),
    ]
    if old_item is not None:
        dates.append(old_item["updated_at"])
        dates += [n["created_at"] for n in old_item.get("public_comments") or []]
    elif (
        db.execute("SELECT 1 FROM editorial_controls WHERE story_id=?", (previous["id"],)).fetchone() is None
        and all(is_own_source(s) for s in previous.get("sources", []) if isinstance(s, dict))
        and all(
            any(isinstance(cs, dict) and is_own_url(cs.get("url")) for cs in (u.get("sources") or []))
            for u in (previous.get("updates") or [])
            if isinstance(u, dict)
        )
    ):
        dates.append(previous["updated_at"])
    return max(dates)


def _changed_note_ids(old_item: dict | None, item: dict) -> set[str]:
    seen_bodies = {n["id"]: n.get("body") for n in (old_item or {}).get("public_comments") or [] if "id" in n}
    return {
        note["id"]
        for note in item.get("public_comments") or []
        if "id" in note
        and note["id"] in seen_bodies
        and unquoted_text(str(seen_bodies[note["id"]] or "")).strip() != unquoted_text(note["body"]).strip()
    }


def _own_body_changed(db, previous: dict, item: dict) -> bool:
    old_item = _latest_published_source(db, item["id"], previous.get("editorial_analysis_key"))
    if old_item is None:
        return not item.get("public_comments") and item["updated_at"] > _source_cutoff(db, previous, None, item)
    return any(unquoted_text(str(item.get(key) or "")).strip() != unquoted_text(str(old_item.get(key) or "")).strip()
               for key in ("title", "content", "upstream_state"))


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


def own_update_input(db, row: dict, item: dict) -> tuple[str, dict]:
    """Filter own-item and mailing-list reply updates to unquoted text; skip when nothing new exists."""
    existing = existing_story(db, row)
    if existing is None:
        return "story", item
    previous = json.loads(existing["payload"])
    writer, _, _ = _writer_info(previous, db)
    mode = _mode(previous, item, db)
    if row["id"] != writer:
        raw = item.get("content") or ""
        is_reply = bool(_REPLY_SUBJECT.search(item.get("title") or ""))
        if mode == "update" and (
            "/hyperkitty/list/" in (item.get("url") or "")
            or item.get("kind") == "pipermail"
            or (item.get("kind") in {"feed", "rss"} and is_reply and "\n>" in ("\n" + raw))
        ):
            stripped = _unquoted_reply(raw)
            if stripped != raw:
                filtered = json.loads(json.dumps(item))
                filtered["content"] = stripped
                if (is_reply or not normalize_evidence(item.get("title") or "")) and len(normalize_evidence(stripped)) < MIN_EVIDENCE_CHARS:
                    return "skip", filtered
                return mode, filtered
        return mode, item
    if item["kind"] == "tag":
        return "skip", item
    if mode == "story":
        return "story", item
    old_item = _latest_published_source(db, item["id"], previous.get("editorial_analysis_key"))
    cutoff = _source_cutoff(db, previous, old_item, item)
    seen_bodies = {n["id"]: n.get("body") for n in (old_item or {}).get("public_comments") or [] if "id" in n}
    changed_ids = _changed_note_ids(old_item, item)
    new_notes = []
    for note in item.get("public_comments") or []:
        if (note["created_at"] > cutoff and note.get("id") not in seen_bodies) or note.get("id") in changed_ids:
            stripped = unquoted_text(note["body"]).strip()
            if stripped:
                new_notes.append({**note, "body": stripped})
    body_changed = _own_body_changed(db, previous, item)
    filtered = json.loads(json.dumps(item))
    filtered["public_comments"] = new_notes
    if body_changed:
        filtered["title"] = unquoted_text(item["title"]).strip() or item["title"]
        filtered["content"] = unquoted_text(item["content"])
    else:
        filtered["title"] = ""
        filtered["content"] = ""
    desc, kept_notes = analysis_context(filtered)
    texts = [filtered["title"], desc, *(note["body"] for note in kept_notes)] if body_changed else [note["body"] for note in kept_notes]
    if not any(len(normalize_evidence(text)) >= MIN_EVIDENCE_CHARS for text in texts):
        return "skip", filtered
    return "update", filtered


def update_target(db, row: dict) -> dict | None:
    """Normalized public story that an incoming item updates, or None in story scope."""
    existing = existing_story(db, row)
    if existing is None:
        return None
    previous = json.loads(existing["payload"])
    item = json.loads(row["payload"])
    if _mode(previous, item, db) != "update":
        return None
    return render._prepare_story(previous, editorial=editorial.public_metadata(db, existing["id"]))


def _comment_sources(item: dict, result: dict, *, after_at: str | None = None, include_body: bool = True,
                     changed_ids: set[str] | frozenset[str] = frozenset()) -> list[dict]:
    """Cite the earliest note stating each quote that the title and description do not.

    Only a verified fetch writes notes, so their fields need no checks here.
    """
    if not item.get("public_comments"):
        return []
    description, _ = analysis_context(item)
    described = normalize_evidence(item["title"] + "\n" + description) if include_body else ""
    quotes = {normalize_evidence(quote) for quote in result["evidence"]}
    quotes = {quote for quote in quotes if len(quote) >= MIN_EVIDENCE_CHARS and quote not in described}
    sources = []
    for note in sorted(item["public_comments"], key=lambda note: note["created_at"]):
        if after_at is not None and note["created_at"] <= after_at and note.get("id") not in changed_ids:
            continue
        body = unquoted_text(note["body"]) if after_at is not None else note["body"]
        normalized = normalize_evidence(body)
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
    return digest([{key: row.get(key) for key in ("id", "url", "source_id", "content_hash", "cluster_key", "story_id", "status")},
                   source_packet.source_fingerprint(json.loads(row["payload"]))])


def _resolve_alias(db, *, story_id: str | None = None, cluster_key: str | None = None) -> dict | None:
    alias = editorial.retired(db, story_id=story_id, cluster_key=cluster_key)
    if alias is None:
        return None
    if alias[1] is None:
        raise editorial.RetiredStory("Story is retired")
    target = db.execute("SELECT * FROM stories WHERE id=?", (alias[1],)).fetchone()
    if target is None:
        raise editorial.RetiredStory("Story is retired")
    return dict(target)


def _live_story(db, story_id: str | None) -> dict | None:
    if not story_id:
        return None
    alias = editorial.retired(db, story_id=story_id)
    if alias is not None:
        if alias[1] is None:
            return None
        story_id = alias[1]
    row = db.execute("SELECT * FROM stories WHERE id=?", (story_id,)).fetchone()
    if row is None:
        return None
    alias = editorial.retired(db, cluster_key=row["cluster_key"])
    if alias is not None:
        if alias[1] is None:
            return None
        row = db.execute("SELECT * FROM stories WHERE id=?", (alias[1],)).fetchone()
    return dict(row) if row is not None else None


def _url_variants(url: str) -> tuple[str, str]:
    alt = url.replace("/-/work_items/", "/-/issues/") if "/-/work_items/" in url else url.replace("/-/issues/", "/-/work_items/")
    return url, alt


def _stories_for_urls(db, urls: list[str]) -> list[dict]:
    seen, found = set(), []
    for url in urls:
        u1, u2 = _url_variants(url)
        for (sid,) in db.execute("SELECT story_id FROM items WHERE url IN (?,?) AND story_id IS NOT NULL", (u1, u2)).fetchall():
            live = _live_story(db, sid)
            if live and live["id"] not in seen:
                seen.add(live["id"])
                found.append(live)
    return found


def _thread_matches(db, row: dict, item: dict, subject: str) -> list[dict]:
    earliest = after(-THREAD_WINDOW_DAYS * 86400, item["published_at"])
    seen, found = set(), []
    for sid, payload_blob in db.execute(
        "SELECT story_id,CAST(payload AS BLOB) FROM items WHERE source_id=? AND story_id IS NOT NULL AND id!=?",
        (row["source_id"], row.get("id") or ""),
    ).fetchall():
        other = saved_object(payload_blob)
        if not isinstance(other, dict) or not isinstance(other.get("published_at"), str):
            continue
        if not (earliest <= other["published_at"] <= item["published_at"]):
            continue
        if thread_subject(other)[0] != subject:
            continue
        live = _live_story(db, sid)
        if live and live["id"] not in seen:
            seen.add(live["id"])
            found.append(live)
    return found


def associate(db, row: dict) -> tuple[dict | None, str | None]:
    """Attach an item to at most one live story using deterministic identities."""
    if row.get("story_id"):
        if resolved := _resolve_alias(db, story_id=row["story_id"]):
            return resolved, "alias"
        existing = db.execute("SELECT * FROM stories WHERE id=?", (row["story_id"],)).fetchone()
        if existing is not None:
            return _resolve_alias(db, cluster_key=existing["cluster_key"]) or dict(existing), "story_id"
    if resolved := _resolve_alias(db, cluster_key=row["cluster_key"]):
        return resolved, "alias"
    existing = db.execute("SELECT * FROM stories WHERE cluster_key=?", (row["cluster_key"],)).fetchone()
    if existing is not None:
        return _resolve_alias(db, story_id=existing["id"]) or dict(existing), "cluster"
    cluster_matches, seen = [], set()
    for (sid,) in db.execute(
        "SELECT DISTINCT story_id FROM items WHERE story_id IS NOT NULL AND cluster_key=?",
        (row["cluster_key"],),
    ).fetchall():
        live = _live_story(db, sid)
        if live and live["id"] not in seen:
            seen.add(live["id"])
            cluster_matches.append(live)
    if len(cluster_matches) == 1:
        return cluster_matches[0], "item_cluster"
    if len(cluster_matches) > 1:
        return None, None
    payload = row.get("payload")
    item = saved_object(payload.encode("utf-8") if isinstance(payload, str) else payload) if isinstance(payload, (str, bytes)) else None
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
            if len(thread_matches) > 1:
                return None, None
    return None, None


def existing_story(db, row: dict):
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
        retracted = db.execute("SELECT 1 FROM editorial_controls WHERE story_id=? AND retracted=1", (live["id"],)).fetchone()
        if retracted is not None:
            return
        seen.add(live["id"])
        pairs.append((live["id"], reason))

    closing, mentioned = gitlab_refs(item)
    for ref in (*closing, *mentioned):
        number = ref.rsplit("/", 1)[-1]
        marker = f"!{number}" if "/-/merge_requests/" in ref else f"#{number}"
        for match in _stories_for_urls(db, [ref]):
            add(match["id"], f"references {marker}")
    for key in release_mentions(item):
        _, prod, ver = key.split(":", 2)
        reason = f"mentions {prod.replace('-', ' ')} {ver}"
        for (sid,) in db.execute("SELECT id FROM stories WHERE cluster_key=?", (key,)).fetchall():
            add(sid, reason)
        alias = editorial.retired(db, cluster_key=key)
        if alias and alias[1]:
            add(alias[1], reason)
        for (sid,) in db.execute("SELECT DISTINCT story_id FROM items WHERE story_id IS NOT NULL AND cluster_key=?", (key,)).fetchall():
            add(sid, reason)
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
        if not story_id or story_id in seen:
            return
        live = _live_story(db, story_id)
        if live is None or live["id"] in seen:
            return
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
    row = db.execute("SELECT revision,locked,retracted,notice_action,notice_reason,notice_at FROM editorial_controls WHERE story_id=?", (story_id,)).fetchone()
    return digest(dict(row) if row else None)


def prepare(db, row: dict, result: dict, observed: str) -> dict:
    # Copy caller-owned values so later repairs cannot mutate the original draft.
    """Assemble the exact candidate and bind all state needed for its guarded commit."""
    row, result = json.loads(json.dumps(row)), json.loads(json.dumps(result))
    current = db.execute("SELECT * FROM items WHERE id=?", (row["id"],)).fetchone()
    if current is None or item_fingerprint(dict(current)) != item_fingerprint(row):
        raise StaleCandidate("Source item changed before candidate preparation")
    item = json.loads(row["payload"])
    existing, how = associate(db, row)
    story_id = existing["id"] if existing else digest(row["cluster_key"])[:24]
    if existing is None and editorial.retired(db, story_id=story_id, cluster_key=row["cluster_key"]) is not None:
        raise editorial.RetiredStory("Story is retired")
    locked = editorial.is_locked(db, story_id)
    previous = json.loads(existing["payload"]) if existing else None
    mode = _mode(previous, item, db)
    binding = {"item": item_fingerprint(row), "prior_story": digest(existing),
               "lock": control_fingerprint(db, story_id), "mode": mode, "sources": []}
    envelope = {"row": row, "result": result, "story_id": story_id,
                "cluster_key": existing["cluster_key"] if existing else row["cluster_key"],
                "mode": mode, "how": how, "candidate": None, "payload": None,
                "packet": {"sources": [], "missing_sources": [], "truncated": False},
                "binding": binding, "locked": locked, "coverage": None,
                "observed": observed}
    if not locked:
        if ("update" in result) != (mode == "update"):
            raise StaleCandidate("Draft scope does not match current story state")
        source = {key: item[key] for key in ("id", "url", "title", "published_at")}
        writer, kind, authority = _writer_info(previous, db)
        if mode == "update":
            is_own = writer == item["id"]
            old_item = _latest_published_source(db, item["id"], previous.get("editorial_analysis_key")) if is_own else None
            state_changed = bool(old_item and item.get("upstream_state") != old_item.get("upstream_state"))
            cutoff = _source_cutoff(db, previous, old_item, item) if is_own else None
            changed_ids = _changed_note_ids(old_item, item) if is_own else frozenset()
            body_changed = _own_body_changed(db, previous, item) if is_own else True
            comments = _comment_sources(item, result, after_at=cutoff, include_body=body_changed, changed_ids=changed_ids)
            dates = [
                *(
                    item["updated_at"] if comment["id"].removeprefix(item["id"] + ":") in changed_ids else comment["published_at"]
                    for comment in comments
                ),
                *([item["updated_at"]] if state_changed else []),
            ]
            at = max(dates) if dates else item["updated_at"]
            comment_links = list({comment["url"]: {"url": comment["url"], "title": comment["title"]}
                                  for comment in comments if comment["url"] != source["url"]}.values())
            if state_changed:
                entry_sources = [{"url": source["url"], "title": source["title"]}, *comment_links[-2:]]
            else:
                entry_sources = comment_links[-3:] or [{"url": source["url"], "title": source["title"]}]
            source_map = {entry["url"]: entry for entry in previous.get("sources", [])}
            source_map[source["url"]] = source
            source_map.update({comment["url"]: comment for comment in comments})
            data = {key: previous.get(key) for key in SEMANTIC_FIELDS}
            fixed_alert = previous.get("origin") == "network-health"
            data.update(confidence=previous["confidence"] if fixed_alert else result["confidence"],
                        state=previous["state"] if fixed_alert else result["state"],
                        editorial_kind=kind, editorial_item=writer)
            if authority:
                data["editorial_authority"] = authority
            if data["category"] != "release" and "release" in (data.get("tags") or []) and data["state"] not in {"released", "tagged"}:
                data["tags"] = [tag for tag in data["tags"] if tag != "release"]
            if previous.get("editorial_analysis_key"):
                data["editorial_analysis_key"] = previous["editorial_analysis_key"]
            for extra in ("origin", "alert_notes", "network"):
                if previous.get(extra):
                    data[extra] = previous[extra]
            data.update(id=story_id, sources=sorted(source_map.values(), key=lambda entry: entry["url"]),
                        published_at=previous["published_at"],
                        added_at=previous.get("added_at", previous["published_at"]),
                        updated_at=max(previous["updated_at"], at),
                        updates=[*(previous.get("updates") or []),
                                 {"at": at, "text": result["update"], "sources": entry_sources}])
        else:
            # Only a newly cited note moves the story's date, to the time it was written.
            comments = _comment_sources(item, result)
            effective_updated = max([item["updated_at"], *(comment["published_at"] for comment in comments)])
            source_map = {entry["url"]: entry for entry in (previous or {}).get("sources", [])
                          if entry.get("id") != item["id"] and entry.get("source_item_id") != item["id"]}
            source_map[source["url"]] = source
            source_map.update({comment["url"]: comment for comment in comments})
            data = {key: result[key] for key in SEMANTIC_FIELDS}
            data.update(editorial_kind=item["kind"], editorial_item=item["id"],
                        editorial_authority=item.get("authority") or "")
            for extra in ("origin", "alert_notes", "network"):
                if previous and previous.get(extra):
                    data[extra] = previous[extra]
            data.update(id=story_id, sources=sorted(source_map.values(), key=lambda entry: entry["url"]),
                        published_at=previous["published_at"] if previous else item["published_at"],
                        added_at=previous.get("added_at", previous["published_at"]) if previous else observed,
                        updated_at=max(effective_updated, previous["updated_at"] if previous else item["published_at"]))
            if previous and previous.get("updates"):  # a new draft never drops the story's dated updates
                data["updates"] = previous["updates"]
        public = render._prepare_story(data, editorial=editorial.public_metadata(db, story_id))
        # Store exactly the normalized reviewed display fields while retaining
        # collection identities privately for future grouping and source lookup.
        data.update({key: value for key, value in public.items() if key not in {"sources", "editorial"}})
        associated = existing is not None and writer != item["id"]
        excluded = {story_id} if existing else frozenset()
        related_rows = related(db, row, item, excluded)
        earlier_ids = _earlier_decision_ids(db, row, excluded | {sid for sid, _ in related_rows})
        writer = data["editorial_item"]
        packet, bindings = source_packet.build_packet(db, item, data, public, writer, update=mode == "update")
        binding["sources"] = bindings
        envelope.update(candidate=public, payload=data, packet=packet,
                        coverage=coverage_background(db, existing, related_rows=related_rows,
                                                     earlier_ids=earlier_ids, associated=associated))
    binding.update(payload_hash=digest(envelope["payload"]), candidate_hash=digest(envelope["candidate"]), packet_hash=digest(envelope["packet"]))
    binding["coverage_hash"] = digest(envelope["coverage"])
    envelope.update(candidate_hash=digest(envelope["candidate"]), source_hash=digest(envelope["packet"]),
                    coverage_hash=binding["coverage_hash"], binding_hash=digest(binding))
    return envelope

