"""Read-only final-story assembly and immutable publication bindings."""

from __future__ import annotations

import json

from . import editorial, render, source_packet
from .comments import analysis_context
from .util import digest, normalize_evidence


# Writer fields a review may repair; their order is part of the review policy hash.
SEMANTIC_FIELDS = ("title", "summary", "why_it_matters", "category", "priority", "confidence", "state", "products", "tags")
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
        return {key: public[key] for key in ("id", *SEMANTIC_FIELDS, "published_at", "updated_at", "added_at")}

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


def _rank(kind: str, confidence: str, updated_at: str) -> tuple:
    return ({"tag": 0, "metrics_timeline": 1}.get(kind, 2), confidence == "confirmed", updated_at)


def _comment_sources(item: dict, result: dict) -> list[dict]:
    """Cite the earliest note stating each quote that the title and description do not.

    Only a verified fetch writes notes, so their fields need no checks here.
    """
    if not item.get("public_comments"):
        return []
    description, _ = analysis_context(item)
    described = normalize_evidence(item["title"] + "\n" + description)
    quotes = {normalize_evidence(quote) for quote in result["evidence"]}
    quotes = {quote for quote in quotes if len(quote) >= 8 and quote not in described}
    sources = []
    for note in sorted(item["public_comments"], key=lambda note: note["created_at"]):
        found = {quote for quote in quotes if quote in normalize_evidence(note["body"])}
        if found:
            quotes -= found
            sources.append({"id": item["id"] + ":" + note["id"], "source_item_id": item["id"], "url": note["url"],
                            "title": note["title"], "published_at": note["created_at"]})
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
    locked = editorial.is_locked(db, story_id)
    binding = {"item": item_fingerprint(row), "prior_story": digest(existing),
               "lock": control_fingerprint(db, story_id), "sources": []}
    envelope = {"row": row, "result": result, "story_id": story_id,
                "cluster_key": existing["cluster_key"] if existing else row["cluster_key"],
                "candidate": None, "payload": None, "packet": {"sources": [], "missing_sources": [], "truncated": False},
                "binding": binding, "locked": locked, "coverage": None,
                "observed": observed}
    if not locked:
        previous = json.loads(existing["payload"]) if existing else None
        source = {key: item[key] for key in ("id", "url", "title", "published_at")}
        # Only a newly cited note moves the story's date, to the time it was written.
        comments = _comment_sources(item, result)
        effective_updated = max([item["updated_at"], *(source["published_at"] for source in comments)])
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
        packet, bindings = source_packet.build_packet(db, item, data, public, writer)
        binding["sources"] = bindings
        envelope.update(candidate=public, payload=data, packet=packet,
                        coverage=coverage_background(db, existing))
    binding.update(payload_hash=digest(envelope["payload"]), candidate_hash=digest(envelope["candidate"]), packet_hash=digest(envelope["packet"]))
    binding["coverage_hash"] = digest(envelope["coverage"])
    envelope.update(candidate_hash=digest(envelope["candidate"]), source_hash=digest(envelope["packet"]),
                    coverage_hash=binding["coverage_hash"], binding_hash=digest(binding))
    return envelope

