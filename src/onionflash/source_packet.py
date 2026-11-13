"""Bounded, numbered evidence for final-story review; never generated prose."""

from __future__ import annotations

from .comments import analysis_context
from .util import canonical_url, digest, plain_text, saved_object


# The review packet's fixed bounds.
LIMITS = {"max_sources": 8, "max_source_chars": 24000, "max_passages": 64, "passage_chars": 1800}
SOURCE_FIELDS = ("id", "source_id", "url", "title", "content", "source_content", "kind", "authority", "product",
                 "published_at", "updated_at", "labels", "upstream_state", "public_comments")


def source_fingerprint(item: dict) -> str:
    """Polling receipts and scheduling metadata do not change evidence identity."""
    return digest({key: item.get(key) for key in SOURCE_FIELDS})


def _decode(value):
    item = saved_object(value)
    if item is None or not isinstance(item.get("title"), str):
        return None
    body = item.get("source_content", item.get("content"))
    # An explicit empty body is a valid title-only source. An absent body
    # is a compacted/missing snapshot, not evidence of an empty document.
    if not isinstance(body, str) or not (body.strip() or item["title"].strip()):
        return None
    return item


def _lookup_fingerprint(row):
    if row is None:
        return None
    item = saved_object(row["payload"])
    return source_fingerprint(item) if item is not None else digest(row["payload"].hex())


def _matches_citation(item, source_id, url):
    if item is None or (source_id and item.get("id") != source_id):
        return False
    try:
        return canonical_url(item["url"]) == canonical_url(url)
    except (KeyError, TypeError, ValueError):
        return False


def _load(db, source_id: str | None, url: str, analysis_key: str | None = None):
    # Saved copies are read as bytes, so a damaged one reads as missing instead of failing the query.
    query = "SELECT id,CAST(payload AS BLOB) AS payload FROM items WHERE "
    row = db.execute(query + "id=?", (source_id,)).fetchone() if source_id else None
    if row is None:
        row = db.execute(query + "url=?", (url,)).fetchone()
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
        saved = snapshot(db.execute("SELECT cache_key,CAST(source_payload AS BLOB) AS source_payload,created_at FROM analyses "
                                    "WHERE cache_key=?", (analysis_key,)).fetchone())
        if saved:
            return saved
    if source_id:
        # Stream this one source's indexed history; a later snapshot at a
        # different URL must not hide an older exact citation match.
        for row in db.execute("""SELECT cache_key,CAST(source_payload AS BLOB) AS source_payload,created_at FROM analyses
                WHERE source_item_id=? AND source_payload IS NOT NULL
                ORDER BY created_at DESC,cache_key DESC""", (source_id,)):
            saved = snapshot(row)
            if saved:
                return saved
    return None


def _labels(value) -> list[str]:
    if not isinstance(value, list):
        return []
    return [text for label in value[:30] if isinstance(label, str) and (text := plain_text(label, 100, html=False))]


def _passages(text, size, **note):
    """Split text into passages of at most size characters; a note's passages name it."""
    return [{**note, "text": text[start:start + size]} for start in range(0, len(text), size) if text[start:start + size].strip()]


def _shares(needs, floors, budget):
    """Split budget smallest need first, so a source that needs less leaves the rest to the
    others. A source with a floor goes first, gets at least it and takes what the others
    leave; every source keeps two."""
    shares, order = [0] * len(needs), sorted(range(len(needs)), key=lambda index: (not floors[index], needs[index]))
    for rank, index in enumerate(order):
        later = len(needs) - rank - 1
        shares[index] = min(needs[index], max(budget // (later + 1), min(floors[index], budget - 2 * later)))
        budget -= shares[index]
    if order and floors[order[0]]:
        shares[order[0]] += min(needs[order[0]] - shares[order[0]], budget)
    return shares


def build_packet(db, incoming: dict, payload: dict, public: dict, writer_id: str | None, *, update: bool = False):
    missing, bindings, units, truncated = [], {}, [], False
    required_ids = {incoming["id"], writer_id}
    # Legacy grouped stories may predate writer provenance. Their complete
    # collected source set can still support a fresh review of the final prose;
    # every source then becomes required, within the same bounds.
    require_all = writer_id is None and payload.get("origin") != "network-health"
    # Required sources come first, so the max_sources cap below drops optional links before them.
    references = sorted(payload["sources"], key=lambda source: (
        source.get("source_item_id", source.get("id")) not in required_ids,
        source.get("source_item_id", source.get("id")) != writer_id, source["url"]))
    public_urls = {source["url"] for source in public["sources"]}
    update_urls = {source["url"] for source in public["updates"][-1]["sources"]} if update and public.get("updates") else set()
    for source in references:
        source_id = source.get("source_item_id", source.get("id"))
        required = require_all or source_id in required_ids
        if not required and source["url"] not in public_urls:
            continue
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
        body = item.get("source_content", item.get("content"))
        unit = {key: item.get(key) for key in ("kind", "authority", "product", "published_at", "updated_at", "upstream_state")}
        unit.update(labels=_labels(item.get("labels")), url=canonical_url(item["url"]), title=item["title"], snapshot=snapshot)
        if item.get("closed_at"):
            unit["closed_at"] = item["closed_at"]
        if captured:
            unit["captured_at"] = captured
        if source.get("source_item_id"):
            # A cited note is supplied with the text of its parent issue.
            if not any(note["url"] == source["url"] for note in item.get("public_comments", [])):
                truncated = True
                if required and (not update or require_all or source["url"] in update_urls):
                    missing.append(source["url"])
            continue
        if not isinstance(body, str) or not (body.strip() or item["title"].strip()):
            truncated = True
            if required:
                missing.append(source["url"])
            continue
        # First the text a writer sees for this item: its title, every note and its
        # description window; then the rest of the description. A share too small
        # for the whole source cuts description text before any note.
        description, _ = analysis_context(item)
        size = LIMITS["passage_chars"]
        view = _passages(item["title"], size) + [
            passage for note in item.get("public_comments", [])
            for passage in _passages(note["body"], size, author=note["author"], created_at=note["created_at"], url=note["url"])
        ] + _passages(description, size)
        units.append((unit, view + _passages(body[len(description):], size), required, source_bindings,
                      view if writer_id and item.get("id") == writer_id else []))
    if writer_id and not any(ref.get("source_item_id", ref.get("id")) == writer_id for ref in references):
        missing.append("retained-writer-source-unavailable")
    cap = min(LIMITS["max_sources"], LIMITS["max_passages"] // 2, LIMITS["max_source_chars"] // 2)
    for unit, _, required, *_ in units[cap:]:
        if required:
            missing.append(unit["url"])
    truncated |= len(units) > cap
    units = units[:cap]
    # The source that wrote the story keeps at least the text its writer saw, and the
    # room the others leave. They share passages, then characters, each smallest need
    # first, so a source with many short notes keeps them while longer ones fill the
    # characters.
    counts = _shares([len(unit[1]) for unit in units], [len(unit[4]) for unit in units], LIMITS["max_passages"])
    chars = _shares([sum(len(passage["text"]) for passage in unit[1][:count]) for unit, count in zip(units, counts)],
                    [sum(len(passage["text"]) for passage in unit[4]) for unit in units], LIMITS["max_source_chars"])
    sources = []
    for index, (unit, evidence, _, source_bindings, _) in enumerate(units):
        for binding in source_bindings:
            bindings[(binding["table"], binding["key"])] = binding
        passages, left = [], chars[index]
        for passage in evidence[:counts[index]]:
            if left <= 0:
                break
            passages.append({**passage, "text": passage["text"][:left]})
            left -= len(passages[-1]["text"])
        truncated |= passages != evidence
        source_id = f"S{index + 1}"
        sources.append({"id": source_id, **unit, "passages": [
            {"id": f"{source_id}:P{number}", **passage} for number, passage in enumerate(passages, 1)]})
    return {"sources": sources, "missing_sources": list(dict.fromkeys(missing)), "truncated": truncated}, list(bindings.values())
