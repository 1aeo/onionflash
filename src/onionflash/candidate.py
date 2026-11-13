"""Read-only final-story assembly and immutable publication bindings."""

from __future__ import annotations

import json
import re

from . import editorial, render, source_packet
from .analyze import MIN_EVIDENCE_CHARS, unquoted_text
from .comments import analysis_context
from .util import digest, normalize_evidence, saved_object


# Writer fields a review may repair; their order is part of the review policy hash.
SEMANTIC_FIELDS = ("title", "summary", "why_it_matters", "category", "priority", "confidence", "state", "products", "tags")
LABEL_FIELDS = SEMANTIC_FIELDS[3:]
UPDATE_FIELDS = (*LABEL_FIELDS, "updates")
COVERAGE_ROWS = 32
COVERAGE_CHARS = 12000
COVERAGE_SUMMARY_CHARS = 200


def coverage_background(db, prior: dict | None) -> dict:
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

    previous = public_text(prior) if prior else None
    result = {"prior_story": previous, "recent": [], "truncated": False}
    rows = db.execute("""SELECT s.id,s.payload,COALESCE(e.retracted,0) AS retracted
        FROM stories s LEFT JOIN editorial_controls e ON e.story_id=s.id
        ORDER BY s.rowid DESC LIMIT ?""", (COVERAGE_ROWS,)).fetchall()
    result["truncated"] = len(rows) == COVERAGE_ROWS
    for row in rows:
        if row["retracted"] or (prior and row["id"] == prior["id"]):
            continue
        try:
            current = public_text(row)
        except (ValueError, TypeError, KeyError, AttributeError, UnicodeError):
            result["truncated"] = True
            continue
        compact = {key: current[key] for key in ("id", "title", "summary", "category", "state", "updated_at")}
        compact["summary"] = compact["summary"][:COVERAGE_SUMMARY_CHARS]
        compact["summary_truncated"] = len(current["summary"]) > COVERAGE_SUMMARY_CHARS
        if current.get("updates"):
            compact["latest_update"] = current["updates"][-1]["text"][:COVERAGE_SUMMARY_CHARS]
        result["truncated"] |= compact["summary_truncated"]
        if len(result["recent"]) + bool(previous) >= COVERAGE_ROWS or len(json.dumps({**result, "recent": [*result["recent"], compact]}, ensure_ascii=False)) > COVERAGE_CHARS:
            result["truncated"] = True
            break
        result["recent"].append(compact)
    return result


class ReviewRequired(ValueError):
    pass


class StaleCandidate(ValueError):
    pass


def _writer_info(previous: dict | None) -> tuple[str | None, str]:
    if not previous:
        return None, ""
    writer = previous.get("editorial_item")
    if writer is None and len(previous.get("sources", [])) == 1:
        writer = previous["sources"][0].get("id")
    kind = previous.get("editorial_kind") or ("tag" if previous.get("state") == "tagged" else "")
    return writer, kind


def _mode(previous: dict | None, item: dict) -> str:
    """Story scope replaces only literal tag notices and timeline-written stories; prose stories gain updates."""
    if previous is None:
        return "story"
    writer, kind = _writer_info(previous)
    tier = {"tag": 0, "metrics_timeline": 1}.get(kind, 2)
    item_tier = {"tag": 0, "metrics_timeline": 1}.get(item["kind"], 2)
    if kind in {"tag", "metrics_timeline"} and (
            item_tier > tier or (kind == "metrics_timeline" and item["kind"] == "metrics_timeline" and item.get("id") == writer)):
        return "story"
    return "update"


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


def _source_cutoff(db, previous: dict, old_item: dict | None) -> str:
    dates = [previous["published_at"],
             *(s["published_at"] for s in previous.get("sources", []) if isinstance(s, dict) and s.get("published_at")),
             *(u["at"] for u in previous.get("updates") or [] if isinstance(u, dict) and u.get("at"))]
    if old_item is not None:
        dates.append(old_item["updated_at"])
        dates += [n["created_at"] for n in old_item.get("public_comments") or []]
    elif db.execute("SELECT 1 FROM editorial_controls WHERE story_id=?", (previous["id"],)).fetchone() is None:
        dates.append(previous["updated_at"])
    return max(dates)


def _own_body_changed(db, previous: dict, item: dict) -> bool:
    old_item = _latest_published_source(db, item["id"], previous.get("editorial_analysis_key"))
    if old_item is None:
        return not item.get("public_comments") and item["updated_at"] > _source_cutoff(db, previous, None)
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
    writer, _ = _writer_info(previous)
    mode = _mode(previous, item)
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
    cutoff = _source_cutoff(db, previous, old_item)
    seen_ids = {n["id"] for n in (old_item or {}).get("public_comments") or [] if "id" in n}
    new_notes = []
    for note in item.get("public_comments") or []:
        if note["created_at"] > cutoff and note.get("id") not in seen_ids:
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
    if _mode(previous, item) != "update":
        return None
    return render._prepare_story(previous, editorial=editorial.public_metadata(db, existing["id"]))


def _comment_sources(item: dict, result: dict, *, after_at: str | None = None, include_body: bool = True) -> list[dict]:
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
        if after_at is not None and note["created_at"] <= after_at:
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


def existing_story(db, row: dict):
    def resolve(story_id: str | None = None, cluster_key: str | None = None):
        alias = editorial.retired(db, story_id=story_id, cluster_key=cluster_key)
        if alias is None:
            return None
        if alias[1] is None:
            raise editorial.RetiredStory("Story is retired")
        target = db.execute("SELECT * FROM stories WHERE id=?", (alias[1],)).fetchone()
        if target is None:
            raise editorial.RetiredStory("Story is retired")
        return dict(target)

    if row.get("story_id"):
        if resolved := resolve(story_id=row["story_id"]):
            return resolved
        existing = db.execute("SELECT * FROM stories WHERE id=?", (row["story_id"],)).fetchone()
        if existing is not None:
            return resolve(cluster_key=existing["cluster_key"]) or dict(existing)
    if resolved := resolve(cluster_key=row["cluster_key"]):
        return resolved
    existing = db.execute("SELECT * FROM stories WHERE cluster_key=?", (row["cluster_key"],)).fetchone()
    if existing is None:
        return None
    return resolve(story_id=existing["id"]) or dict(existing)


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
    existing = existing_story(db, row)
    story_id = existing["id"] if existing else digest(row["cluster_key"])[:24]
    if existing is None and editorial.retired(db, story_id=story_id, cluster_key=row["cluster_key"]) is not None:
        raise editorial.RetiredStory("Story is retired")
    locked = editorial.is_locked(db, story_id)
    previous = json.loads(existing["payload"]) if existing else None
    mode = _mode(previous, item)
    binding = {"item": item_fingerprint(row), "prior_story": digest(existing),
               "lock": control_fingerprint(db, story_id), "mode": mode, "sources": []}
    envelope = {"row": row, "result": result, "story_id": story_id,
                "cluster_key": existing["cluster_key"] if existing else row["cluster_key"],
                "mode": mode, "candidate": None, "payload": None,
                "packet": {"sources": [], "missing_sources": [], "truncated": False},
                "binding": binding, "locked": locked, "coverage": None,
                "observed": observed}
    if not locked:
        if ("update" in result) != (mode == "update"):
            raise StaleCandidate("Draft scope does not match current story state")
        source = {key: item[key] for key in ("id", "url", "title", "published_at")}
        writer, kind = _writer_info(previous)
        if mode == "update":
            is_own = writer == item["id"]
            old_item = _latest_published_source(db, item["id"], previous.get("editorial_analysis_key")) if is_own else None
            state_changed = bool(old_item and item.get("upstream_state") != old_item.get("upstream_state"))
            cutoff = _source_cutoff(db, previous, old_item) if is_own else None
            body_changed = _own_body_changed(db, previous, item) if is_own else True
            comments = _comment_sources(item, result, after_at=cutoff, include_body=body_changed)
            dates = [*(comment["published_at"] for comment in comments), *([item["updated_at"]] if state_changed else [])]
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
            data.update(confidence=result["confidence"], state=result["state"],
                        editorial_kind=kind, editorial_item=writer)
            if data["category"] != "release" and "release" in (data.get("tags") or []) and data["state"] not in {"released", "tagged"}:
                data["tags"] = [tag for tag in data["tags"] if tag != "release"]
            if previous.get("editorial_analysis_key"):
                data["editorial_analysis_key"] = previous["editorial_analysis_key"]
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
            data.update(editorial_kind=item["kind"], editorial_item=item["id"])
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
        writer = data["editorial_item"]
        packet, bindings = source_packet.build_packet(db, item, data, public, writer, update=mode == "update")
        binding["sources"] = bindings
        envelope.update(candidate=public, payload=data, packet=packet,
                        coverage=coverage_background(db, existing))
    binding.update(payload_hash=digest(envelope["payload"]), candidate_hash=digest(envelope["candidate"]), packet_hash=digest(envelope["packet"]))
    binding["coverage_hash"] = digest(envelope["coverage"])
    envelope.update(candidate_hash=digest(envelope["candidate"]), source_hash=digest(envelope["packet"]),
                    coverage_hash=binding["coverage_hash"], binding_hash=digest(binding))
    return envelope

