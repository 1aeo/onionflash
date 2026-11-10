"""Bounded, numbered evidence for final-story review; never generated prose."""

from __future__ import annotations

import json

from .util import canonical_url, digest


DEFAULT_LIMITS = {"max_sources": 8, "max_source_chars": 24000, "max_passages": 64, "passage_chars": 1800}
SOURCE_FIELDS = ("id", "source_id", "url", "title", "content", "source_content", "kind", "authority", "product",
                 "published_at", "updated_at", "labels", "upstream_state", "public_comments")


def source_fingerprint(item: dict) -> str:
    """Polling receipts and scheduling metadata do not change evidence identity."""
    return digest({key: item.get(key) for key in SOURCE_FIELDS})


def _decode(value):
    try:
        item = json.loads(value)
        if not isinstance(item, dict) or not isinstance(item.get("title"), str):
            return None
        body = item.get("source_content", item.get("content"))
        if not isinstance(body, str) or (not body.strip() and item.get("kind") != "tag"):
            return None
        return item
    except (ValueError, TypeError):
        return None


def _lookup_fingerprint(row):
    if row is None:
        return None
    try:
        item = json.loads(row["payload"])
        return source_fingerprint(item) if isinstance(item, dict) else digest(row["payload"])
    except (ValueError, TypeError):
        return digest(row["payload"])


def _matches_citation(item, source_id, url):
    if item is None or (source_id and item.get("id") != source_id):
        return False
    try:
        return canonical_url(item["url"]) == canonical_url(url)
    except (KeyError, TypeError, ValueError):
        return False


def _load(db, source_id: str | None, url: str, analysis_key: str | None = None):
    row = db.execute("SELECT id,payload FROM items WHERE id=?", (source_id,)).fetchone() if source_id else None
    if row is None:
        row = db.execute("SELECT id,payload FROM items WHERE url=?", (url,)).fetchone()
    lookup = {"table": "item_lookup", "key": row["id"] if row else source_id or url,
              "by": "id" if row or source_id else "url", "hash": _lookup_fingerprint(row)}
    if row is not None:
        item = _decode(row["payload"])
        if _matches_citation(item, source_id, url):
            return item, [lookup], "current", None
    # Stable repository-entry IDs can move to a different immutable commit URL.
    # Keep the retained citation tied to its actual bytes, never the newer entry.
    def snapshot(row):
        if row is None:
            return None
        item = _decode(row["source_payload"])
        if _matches_citation(item, source_id, url):
            return item, [lookup, {"table": "analyses", "key": row["cache_key"], "hash": source_fingerprint(item)}], "historical-analysis", row["created_at"]
        return None

    if analysis_key:
        saved = snapshot(db.execute("SELECT cache_key,source_payload,created_at FROM analyses WHERE cache_key=?", (analysis_key,)).fetchone())
        if saved:
            return saved
    if source_id:
        # Stream this one source's indexed history; a later snapshot at a
        # different URL must not hide an older exact citation match.
        for row in db.execute("""SELECT cache_key,source_payload,created_at FROM analyses
                WHERE source_item_id=? AND source_payload IS NOT NULL
                ORDER BY created_at DESC,cache_key DESC""", (source_id,)):
            saved = snapshot(row)
            if saved:
                return saved
    return None


def binding_current(db, binding: dict) -> bool:
    table = binding["table"]
    if table == "item_lookup":
        if binding["by"] not in {"id", "url"}:
            return False
        row = db.execute("SELECT payload FROM items WHERE " + binding["by"] + "=?", (binding["key"],)).fetchone()
        return _lookup_fingerprint(row) == binding["hash"]
    if table == "items":
        row = db.execute("SELECT payload FROM items WHERE id=?", (binding["key"],)).fetchone()
    elif table == "analyses":
        row = db.execute("SELECT source_payload FROM analyses WHERE cache_key=?", (binding["key"],)).fetchone()
    else:
        return False
    item = _decode(row[0]) if row else None
    return item is not None and source_fingerprint(item) == binding["hash"]


def build_packet(db, incoming: dict, payload: dict, public: dict, writer_id: str | None, settings: dict | None):
    limits = {key: (settings or {}).get(key, value) for key, value in DEFAULT_LIMITS.items()}
    if any(type(value) is not int or value < 1 for value in limits.values()):
        raise ValueError("Review source limits must be positive integers")
    missing, bindings, units, truncated = [], {}, [], False
    required_ids = {incoming["id"], writer_id}
    # Legacy grouped stories may predate writer provenance. Their complete
    # collected source set can still support a fresh review of the final prose;
    # every source then becomes required, with the same configured bounds.
    require_all = writer_id is None
    # Incoming evidence and the retained prose writer come first, so old optional
    # citation links cannot consume their context allowance.
    references = list(payload["sources"])
    references.sort(key=lambda source: (source.get("source_item_id", source.get("id")) not in required_ids,
                                        source.get("source_item_id", source.get("id")) != writer_id,
                                        source["url"]))
    public_urls = {source["url"] for source in public["sources"]}
    seen = set()
    for source in references:
        source_id = source.get("source_item_id", source.get("id"))
        required = require_all or source_id in required_ids
        if not required and source["url"] not in public_urls:
            continue
        if source["url"] in seen:
            continue
        seen.add(source["url"])
        if source_id == incoming["id"]:
            loaded = (incoming, [{"table": "items", "key": incoming["id"], "hash": source_fingerprint(incoming)}], "current", None)
        else:
            loaded = _load(db, source_id, source["url"].split("#note_", 1)[0],
                           payload.get("editorial_analysis_key") if source_id == writer_id else None)
        if loaded is None:
            truncated = True
            if required:
                missing.append(source["url"])
            continue
        item, source_bindings, snapshot, captured = loaded
        body = item.get("source_content", item.get("content", ""))
        unit = {key: item.get(key) for key in ("kind", "authority", "product", "published_at", "updated_at", "upstream_state")}
        unit.update(url=canonical_url(item["url"]), title=item["title"], snapshot=snapshot)
        if captured:
            unit["captured_at"] = captured
        if source.get("source_item_id"):
            note = next((note for note in item.get("public_comments", []) if note.get("url") == source["url"]), None)
            if note is None or not isinstance(note.get("body"), str) or not note["body"].strip():
                truncated = True
                if required:
                    missing.append(source["url"])
                continue
            # All available verified notes are supplied under their parent
            # source, independently of which quotes the writer selected.
            continue
        if not isinstance(body, str) or (not body.strip() and item.get("kind") != "tag"):
            truncated = True
            if required:
                missing.append(source["url"])
            continue
        # Metadata is bounded separately from evidence passages.
        truncated |= any(isinstance(value, str) and key != "url" and len(value) > 500 for key, value in unit.items())
        unit = {key: value[:500] if isinstance(value, str) and key != "url" else value for key, value in unit.items()}
        units.append((unit, item, required, source_bindings))
    if writer_id and not any(ref.get("source_item_id", ref.get("id")) == writer_id for ref in references):
        missing.append("retained-writer-source-unavailable")
    cap = min(limits["max_sources"], limits["max_passages"] // 2, limits["max_source_chars"] // 2)
    for unit, item, required, _ in units[cap:]:
        if required:
            missing.append(unit["url"])
    truncated |= len(units) > cap
    units = units[:cap]
    sources, remaining_chars, remaining_passages = [], limits["max_source_chars"], limits["max_passages"]
    for index, (unit, item, required, source_bindings) in enumerate(units):
        for binding in source_bindings:
            bindings[(binding["table"], binding["key"])] = binding
        source_id = f"S{index + 1}"
        allowance = remaining_chars // (len(units) - index)
        passage_allowance = remaining_passages // (len(units) - index)
        title = unit["title"][:min(limits["passage_chars"], max(1, allowance // 4))]
        passages = [{"id": source_id + ":P1", "text": title}] if title.strip() else []
        available = min(allowance - len(title), (passage_allowance - 1) * limits["passage_chars"])
        from .comments import analysis_context
        body = item.get("source_content", item.get("content", ""))
        bounded, notes = analysis_context(item, available)
        supplied_description = len(bounded) if not notes else len(bounded.split("\n\nPublic issue comments", 1)[0])
        all_notes = [note for note in item.get("public_comments", []) if note.get("body")]
        truncated |= (supplied_description < len(body) or len(notes) < len(all_notes)
                      or any(len(note["body"]) < len(original["body"]) for note, original in zip(notes, all_notes)))
        for offset in range(0, len(bounded), limits["passage_chars"]):
            text = bounded[offset:offset + limits["passage_chars"]]
            if text.strip():
                passages.append({"id": f"{source_id}:P{len(passages) + 1}", "text": text})
        if body and not bounded and required:
            missing.append(unit["url"])
        truncated |= len(title) < len(unit["title"])
        remaining_chars -= sum(len(p["text"]) for p in passages)
        remaining_passages -= len(passages)
        sources.append({"id": source_id, **unit, "passages": passages})
    return {"sources": sources, "missing_sources": list(dict.fromkeys(missing)), "truncated": truncated}, list(bindings.values())
