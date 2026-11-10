"""Read-only final-story assembly and immutable publication bindings."""

from __future__ import annotations

import json

from . import editorial, render, source_packet
from .util import canonical_url, digest, format_utc, normalize_evidence, parse_utc


SEMANTIC_FIELDS = ("title", "summary", "why_it_matters", "category", "products", "priority", "confidence", "state", "tags")
REPAIR_FIELDS = frozenset(SEMANTIC_FIELDS)


class ReviewRequired(ValueError):
    pass


class StaleCandidate(ValueError):
    pass


def _rank(kind: str, confidence: str, updated_at: str) -> tuple:
    return ({"tag": 0, "metrics_timeline": 1}.get(kind, 2), confidence == "confirmed", updated_at)


def _comment_sources(item: dict, result: dict, input_chars: int | None, observed: str) -> list[dict]:
    if type(input_chars) is not int or input_chars <= 0 or not item.get("public_comments"):
        return []
    from .comments import analysis_context, parse_note_id
    try:
        _, supplied = analysis_context(item, input_chars)
    except (ValueError, TypeError, KeyError, AttributeError):
        return []
    evidence = [normalize_evidence(quote) for quote in result.get("evidence", []) if isinstance(quote, str)]
    evidence = [quote for quote in evidence if len(quote) >= 8]
    sources = []
    for note in supplied:
        try:
            identifier = parse_note_id(note["id"])
            url = canonical_url(note["url"])
            if identifier is None or url != canonical_url(item["url"]).split("#", 1)[0] + "#note_" + identifier:
                continue
            body = normalize_evidence(note["body"])
            if not any(quote in body for quote in evidence):
                continue
            created = format_utc(parse_utc(note["created_at"]))
            updated = format_utc(parse_utc(note["updated_at"]))
            if not created <= updated <= observed:
                continue
            sources.append({"id": item["id"] + ":" + note["id"], "source_item_id": item["id"],
                            "url": url, "title": note["title"], "published_at": created, "updated_at": updated})
        except (KeyError, TypeError, ValueError, UnicodeError):
            continue
    return sources


def item_fingerprint(row: dict) -> str:
    return digest([{key: row.get(key) for key in ("id", "url", "source_id", "content_hash", "cluster_key", "story_id", "status")},
                   source_packet.source_fingerprint(json.loads(row["payload"]))])


def existing_story(db, row: dict):
    existing = db.execute("SELECT * FROM stories WHERE id=?", (row.get("story_id"),)).fetchone() if row.get("story_id") else None
    if existing is None:
        existing = db.execute("SELECT * FROM stories WHERE cluster_key=?", (row["cluster_key"],)).fetchone()
    return dict(existing) if existing is not None else None


def control_fingerprint(db, story_id: str) -> str:
    row = db.execute("SELECT revision,locked,retracted,notice_action,notice_reason,notice_at FROM editorial_controls WHERE story_id=?", (story_id,)).fetchone()
    return digest(dict(row) if row else None)


def assert_current(db, prepared: dict) -> None:
    binding, row = prepared["binding"], prepared["row"]
    current = db.execute("SELECT * FROM items WHERE id=?", (row["id"],)).fetchone()
    if current is None or item_fingerprint(dict(current)) != binding["item"] or item_fingerprint(row) != binding["item"]:
        raise StaleCandidate("Source item changed since candidate preparation")
    if digest(existing_story(db, row)) != binding["prior_story"]:
        raise StaleCandidate("Published story changed since candidate preparation")
    if control_fingerprint(db, prepared["story_id"]) != binding["lock"]:
        raise StaleCandidate("Editorial decision changed since candidate preparation")
    if any(not source_packet.binding_current(db, source) for source in binding["sources"]):
        raise StaleCandidate("Supporting source changed since candidate preparation")


def wholly_deterministic(db, row: dict, payload: dict, public: dict) -> bool:
    if payload.get("editorial_kind") != "tag":
        return False
    from .analyze import tag_notice
    writer = payload.get("editorial_item")
    item = json.loads(row["payload"])
    writer_item = item if writer == item["id"] else None
    if writer_item is None:
        writer_source = next((source for source in payload["sources"] if source.get("id") == writer), None)
        loaded = source_packet._load(db, writer, writer_source["url"], payload.get("editorial_analysis_key")) if writer_source else None
        writer_item = loaded[0] if loaded else None
    if writer_item is None or writer_item.get("kind") != "tag":
        return False
    literal = tag_notice(writer_item)
    return all(public[key] == literal[key] for key in SEMANTIC_FIELDS)


def prepare(db, row: dict, result: dict, observed: str, *, input_chars: int | None = None, review_settings: dict | None = None) -> dict:
    # Copy caller-owned values so later repairs cannot mutate the original draft.
    row, result = json.loads(json.dumps(row)), json.loads(json.dumps(result))
    if type(result.get("publish")) is not bool:
        raise ValueError("Draft publication decision must be boolean")
    current = db.execute("SELECT * FROM items WHERE id=?", (row["id"],)).fetchone()
    if current is None or item_fingerprint(dict(current)) != item_fingerprint(row):
        raise StaleCandidate("Source item changed before candidate preparation")
    item = json.loads(row["payload"])
    if item.get("id") != row["id"]:
        raise ValueError("Source identity differs from its stored item")
    existing = existing_story(db, row)
    story_id = existing["id"] if existing else digest(row["cluster_key"])[:24]
    locked = editorial.is_locked(db, story_id)
    binding = {"item": item_fingerprint(row), "prior_story": digest(existing),
               "lock": control_fingerprint(db, story_id), "sources": []}
    envelope = {"row": row, "result": result, "input_chars": input_chars, "story_id": story_id,
                "cluster_key": existing["cluster_key"] if existing else row["cluster_key"],
                "candidate": None, "payload": None, "packet": {"sources": [], "missing_sources": [], "truncated": False},
                "binding": binding, "locked": locked, "requires_review": False, "wholly_deterministic": False,
                "writer_item_id": None, "observed": observed}
    if result["publish"] and not locked:
        previous = json.loads(existing["payload"]) if existing else None
        source = {key: item[key] for key in ("id", "url", "title", "published_at")}
        comments = _comment_sources(item, result, input_chars, observed)
        effective_updated = max([item["updated_at"], *(source["updated_at"] for source in comments)])
        source_map = {source["url"]: source for source in (previous or {}).get("sources", [])
                      if source.get("id") != item["id"] and source.get("source_item_id") != item["id"]}
        source_map[source["url"]] = source
        source_map.update({comment["url"]: comment for comment in comments})
        data = {key: result[key] for key in SEMANTIC_FIELDS}
        data.update(editorial_kind=item["kind"], editorial_item=item["id"], editorial_updated_at=effective_updated)
        writer = (previous or {}).get("editorial_item")
        if previous and writer is None and len(previous.get("sources", [])) == 1:
            writer = previous["sources"][0].get("id")
        if previous and writer != item["id"]:
            kind = previous.get("editorial_kind") or ("tag" if previous["state"] == "tagged" else "")
            stamp = previous.get("editorial_updated_at") or previous["updated_at"]
            if _rank(kind, previous["confidence"], stamp) > _rank(item["kind"], data["confidence"], effective_updated):
                data = {key: previous.get(key) for key in data}
                data.update(editorial_kind=kind, editorial_item=writer, editorial_updated_at=stamp)
                if previous.get("editorial_analysis_key"):
                    data["editorial_analysis_key"] = previous["editorial_analysis_key"]
        data.update(id=story_id, sources=sorted(source_map.values(), key=lambda source: source["url"]),
                    published_at=previous["published_at"] if previous else item["published_at"],
                    added_at=previous.get("added_at", previous["published_at"]) if previous else observed,
                    updated_at=max(effective_updated, previous["updated_at"] if previous else item["published_at"]))
        public = render._prepare_story(data, editorial=editorial.public_metadata(db, story_id))
        # Store exactly the normalized reviewed display fields while retaining
        # collection identities privately for future grouping and source lookup.
        data.update({key: value for key, value in public.items() if key not in {"sources", "editorial"}})
        writer = data["editorial_item"]
        packet, bindings = source_packet.build_packet(db, item, data, public, writer, review_settings)
        deterministic = wholly_deterministic(db, row, data, public)
        binding["sources"] = bindings
        envelope.update(candidate=public, payload=data, packet=packet, writer_item_id=writer,
                        wholly_deterministic=deterministic, requires_review=not deterministic)
    binding.update(payload_hash=digest(envelope["payload"]), candidate_hash=digest(envelope["candidate"]), packet_hash=digest(envelope["packet"]))
    envelope.update(candidate_hash=digest(envelope["candidate"]), source_hash=digest(envelope["packet"]),
                    binding_hash=digest(binding), missing_sources=envelope["packet"]["missing_sources"])
    return envelope

