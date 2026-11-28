"""Bounded, numbered evidence for final-story review; never generated prose."""

from __future__ import annotations

from collections.abc import Iterable
import re

from .comments import analysis_context
from .llm import is_quoted_list_post, unquoted_mail_text
from .util import (
    GITLAB_PROJECT_PATH, canonical_url, digest, effective_authority, gitlab_url_variants,
    mandatory_news_rule, plain_text, safe_canonical_url, saved_object, tag_enrichment_kind,
)


# The review packet's fixed bounds.
LIMITS = {"max_sources": 8, "max_source_chars": 24000, "max_passages": 64, "passage_chars": 1800}
BASE_SOURCE_FIELDS = (
    "id", "source_id", "url", "title", "content", "source_content", "kind", "authority", "product",
    "published_at", "updated_at", "labels", "upstream_state", "public_comments",
)
OPTIONAL_SOURCE_FIELDS = ("author", "sender_domain")


def source_fingerprint(item: dict) -> str:
    """Polling receipts and scheduling metadata do not change evidence identity."""
    extra = {}
    if item.get("tag_enriched") is True:
        extra["tag_enriched"] = True
    if kind := tag_enrichment_kind(item):
        extra["tag_enrichment_kind"] = kind
    return digest({**{key: item.get(key) for key in BASE_SOURCE_FIELDS},
                   **{opt: item[opt] for opt in OPTIONAL_SOURCE_FIELDS if item.get(opt)},
                   **extra})


def _source_body(item: dict | None) -> str | None:
    if item is None or not isinstance(item.get("title"), str):
        return None
    body = item.get("source_content", item.get("content"))
    # An explicit empty body is a valid title-only source. An absent body
    # is a compacted/missing snapshot, not evidence of an empty document.
    return body if isinstance(body, str) and (body.strip() or item["title"].strip()) else None


def _safe_canonical(url: str) -> str:
    return safe_canonical_url(url) or url


_GITLAB_PROJECT_PREFIX_RE = re.compile(rf"^(https://gitlab\.torproject\.org/)({GITLAB_PROJECT_PATH})(/-/.*)$")


def _citation_url_key(url: object) -> str:
    canon = safe_canonical_url(url)
    if not canon:
        return ""
    if match := _GITLAB_PROJECT_PREFIX_RE.match(canon):
        return f"{match.group(1)}{match.group(2).lower()}{match.group(3)}"
    return canon


def _matches_citation(item, source_id, url) -> bool:
    return (_source_body(item) is not None and (not source_id or item.get("id") == source_id)
            and bool(cu := _citation_url_key(url)) and _citation_url_key(item.get("url")) == cu)


def _load(db, source_id: str | None, url: str, analysis_key: str | None = None):
    # Saved copies are read as bytes, so a damaged one reads as missing instead of failing the query.
    query = "SELECT id,CAST(payload AS BLOB) AS payload FROM items WHERE "
    row = db.execute(query + "id=?", (source_id,)).fetchone() if source_id else None
    if row is None:
        variants = gitlab_url_variants(url)
        exact = tuple({url, *variants})
        row = db.execute(f"{query}url IN ({','.join('?' * len(exact))})", exact).fetchone()
        if row is None and any(_GITLAB_PROJECT_PREFIX_RE.match(v) for v in variants):
            lower = tuple({v.lower() for v in variants})
            target_key = _citation_url_key(url)
            candidates = db.execute(
                f"SELECT id,CASE WHEN typeof(url)='text' THEN url END AS url,CAST(payload AS BLOB) AS payload "
                f"FROM items WHERE LOWER(url) IN ({','.join('?' * len(lower))})",
                lower,
            ).fetchall()
            row = next((c for c in candidates if _citation_url_key(c["url"]) == target_key), None)
    raw_item = saved_object(row["payload"]) if row is not None else None
    lookup = {"table": "item_lookup", "key": row["id"] if row else source_id or url, "by": "id" if row or source_id else "url",
              "hash": None if row is None else (source_fingerprint(raw_item) if raw_item is not None else digest(row["payload"].hex()))}
    if _matches_citation(raw_item, source_id, url):
        return raw_item, [lookup], "current", None
    resolved_id = source_id or (row["id"] if row is not None else None)

    # Stable repository-entry IDs can move to a different immutable commit URL.
    # Keep the retained citation tied to its actual bytes, never the newer entry.
    def snapshot(analysis_row):
        """Decode and verify a historical analysis snapshot matching the requested citation."""
        if analysis_row is not None and _matches_citation(
            item := saved_object(analysis_row["source_payload"]), resolved_id, url
        ):
            return (
                item,
                [lookup, {"table": "analyses", "key": analysis_row["cache_key"], "hash": source_fingerprint(item)}],
                "historical-analysis",
                analysis_row["created_at"],
            )
        return None

    if analysis_key and (saved := snapshot(db.execute(
            "SELECT cache_key,CAST(source_payload AS BLOB) AS source_payload,created_at FROM analyses WHERE cache_key=?",
            (analysis_key,)).fetchone())):
        return saved
    if resolved_id:
        # Stream this one source's indexed history; a later snapshot at a
        # different URL must not hide an older exact citation match.
        for analysis_row in db.execute("""SELECT cache_key,CAST(source_payload AS BLOB) AS source_payload,created_at FROM analyses
                WHERE source_item_id=? AND source_payload IS NOT NULL
                ORDER BY created_at DESC,cache_key DESC""", (resolved_id,)):
            if saved := snapshot(analysis_row):
                return saved
    return None


def normalize_labels(value) -> list[str]:
    """Normalize at most 30 plain-text GitLab labels without stripping angle-bracket text."""
    if not isinstance(value, list):
        return []
    return [text for label in value[:30] if isinstance(label, str) and (text := plain_text(label, 100, html=False))]


def number_sources(entries: list[tuple[dict, list]]) -> list[dict]:
    """Assign sequential `S<i>` and `S<i>:P<j>` identifiers to sources and passages."""
    return [{**unit, "id": f"S{i}", "passages": [
        {**(p if isinstance(p, dict) else {"text": p}), "id": f"S{i}:P{j}"} for j, p in enumerate(passages, 1)]}
        for i, (unit, passages) in enumerate(entries, 1)]


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


def _thread_context_metadata(thread_root: dict | None) -> dict | None:
    if not isinstance(thread_root, dict):
        return None
    ctx = {
        "title": plain_text(thread_root.get("title") or "", 200, html=False),
        "published_at": plain_text(thread_root.get("published_at") or "", 64, html=False),
        "url": safe_canonical_url(thread_root.get("url")) or plain_text(thread_root.get("url") or "", 500, html=False),
        "excerpt": plain_text(thread_root.get("excerpt") or "", 360, html=False),
    }
    return ctx if any(ctx.values()) else None


def build_packet(
    db,
    incoming: dict,
    payload: dict,
    public: dict,
    writer_id: str | None,
    *,
    update: bool = False,
    dirauth_users: Iterable[str] | None = None,
    tor_core_users: Iterable[str] | None = None,
    thread_root: dict | None = None,
):
    """Assemble the bounded numbered source packet and durable bindings for final review."""
    missing, bindings, units, truncated = [], {}, [], False
    loaded_cache: dict[tuple[str | None, str, str | None], tuple | None] = {}
    required_ids = {incoming["id"], writer_id}
    # Legacy grouped stories may predate writer provenance. Their complete
    # collected source set can still support a fresh review of the final prose;
    # every source then becomes required, within the same bounds.
    require_all = writer_id is None and payload.get("origin") != "network-health"
    # Required sources come first, so the max_sources cap below drops optional links before them.
    references = sorted(payload["sources"], key=lambda source: (
        source.get("source_item_id", source.get("id")) not in required_ids,
        source.get("source_item_id", source.get("id")) != writer_id, source["url"]))
    public_urls = {_safe_canonical(source["url"]) for source in public["sources"]}
    update_urls = {_safe_canonical(source["url"]) for source in public["updates"][-1]["sources"]} if update and public.get("updates") else set()
    bare_parent_ids = {
        ref.get("id")
        for ref in references
        if not ref.get("network_key")
        and not ref.get("source_item_id")
        and ref.get("id")
        and (require_all or ref.get("id") in required_ids or _safe_canonical(ref["url"]) in public_urls)
    }
    emitted_ids: set[str] = set()
    for source in references:
        if source.get("network_key"):
            continue
        source_id = source.get("source_item_id", source.get("id"))
        required = require_all or source_id in required_ids
        if not required and _safe_canonical(source["url"]) not in public_urls:
            continue
        if source_id == incoming["id"]:
            loaded = (incoming, [{"table": "items", "key": incoming["id"], "hash": source_fingerprint(incoming)}], "current", None)
        else:
            load_key = (source_id, source["url"].split("#note_", 1)[0],
                        payload.get("editorial_analysis_key") if source_id == writer_id else None)
            if load_key not in loaded_cache:
                loaded_cache[load_key] = _load(db, *load_key)
            loaded = loaded_cache[load_key]
        if loaded is None:
            truncated = True
            if required:
                missing.append(source["url"])
            continue
        item, source_bindings, snapshot, captured = loaded
        if not source.get("source_item_id") and item.get("id") in emitted_ids:
            continue
        if source.get("source_item_id"):
            # A cited note is supplied with the text of its parent issue.
            source_canon = _safe_canonical(source["url"])
            source_key = _citation_url_key(source["url"]) or source_canon
            if not any((_citation_url_key(note["url"]) or _safe_canonical(note["url"])) == source_key
                       for note in item.get("public_comments", [])):
                truncated = True
                if required and (not update or require_all or source_canon in update_urls):
                    missing.append(source["url"])
            if source_id in bare_parent_ids or source_id in emitted_ids or item.get("id") in emitted_ids:
                continue
        body = _source_body(item)
        if body is None:
            truncated = True
            if required:
                missing.append(source["url"])
            continue
        if source_id:
            emitted_ids.add(source_id)
        if item.get("id"):
            emitted_ids.add(item["id"])
        auth = effective_authority(item, dirauth_users, tor_core_users)
        rule = mandatory_news_rule({**item, "authority": auth})
        unit = {
            **{key: item.get(key) for key in ("kind", "product", "published_at", "updated_at", "upstream_state")},
            "authority": auth, "labels": normalize_labels(item.get("labels")),
            "url": canonical_url(item["url"]), "title": item["title"], "snapshot": snapshot,
            **{opt: item[opt] for opt in OPTIONAL_SOURCE_FIELDS if isinstance(item.get(opt), str) and item[opt]},
        }
        if item.get("kind") == "tag" and item.get("tag_enriched") is True:
            unit["tag_enriched"] = True
            if kind := tag_enrichment_kind(item):
                unit["tag_enrichment_kind"] = kind
        if rule is not None:
            unit["mandatory_news_rule"] = rule
        if item.get("closed_at"):
            unit["closed_at"] = item["closed_at"]
        if captured:
            unit["captured_at"] = captured
        if is_quoted_list_post(unit["url"], body) and (unquoted := unquoted_mail_text(body)):
            unit["unquoted_content"] = plain_text(unquoted, LIMITS["max_source_chars"], html=False)
        if item.get("id") == incoming.get("id") and (thread_ctx := _thread_context_metadata(thread_root)) is not None:
            unit["thread_context"] = thread_ctx
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
    trimmed = []
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
        trimmed.append((unit, passages))
    return {"sources": number_sources(trimmed), "missing_sources": list(dict.fromkeys(missing)), "truncated": truncated}, list(bindings.values())
