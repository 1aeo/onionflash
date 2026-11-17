"""Verbatim source reminders for checking the current text, never approval evidence."""

from __future__ import annotations

from collections import Counter
import copy
import re

from .util import parse_utc, safe_canonical_url


# Advance when reminder construction changes, so prior approvals cannot reuse it.
EVIDENCE_POLICY = 4
_WORDS = re.compile(r"\w+", re.UNICODE)
_STOP = frozenset("a an and are as at be been but by for from has have in is it its of on or that the this to was were with".split())
_MAX_ANCHORS = 3


def supplied_tag_sources(packet: dict) -> list[dict]:
    """Point to literal tag metadata without deciding relevance or news value."""
    return [{"source_ref": source["id"], **{
        key: copy.deepcopy(source[key]) for key in ("kind", "authority", "title", "published_at") if key in source}}
        for source in packet["sources"] if source.get("kind") == "tag"]


def source_date_comparisons(packet: dict) -> list[dict]:
    """Compare supplied dates without inferring event eligibility or retry state."""
    comparisons = []
    for source in packet["sources"]:
        dates = [{"ref": source["id"], "field": "published_at", "value": source.get("published_at")}]
        if source.get("kind") == "gitlab_issue":
            dates.extend({"ref": passage["id"], "field": "created_at", "value": passage["created_at"]}
                         for passage in source["passages"] if "created_at" in passage)
            if source.get("upstream_state") == "closed" and "closed_at" in source:
                dates.append({"ref": source["id"], "field": "closed_at", "value": source["closed_at"]})
        try:
            updated = parse_utc(source.get("updated_at"))
            moments = [parse_utc(date["value"]) for date in dates]
        except ValueError:
            continue  # Incomplete or invalid dates cannot establish the newest development.
        latest = max(moments)
        elapsed = (updated - latest).total_seconds()
        comparisons.append({"source_ref": source["id"], "kind": source.get("kind"),
                            "authority": source.get("authority"), "labels": copy.deepcopy(source.get("labels", [])),
                            "source_updated_at": source["updated_at"], "date_evidence": dates,
                            "latest_date_evidence": [copy.deepcopy(date) for date, moment in zip(dates, moments)
                                                     if moment == latest],
                            "elapsed_seconds": elapsed, "elapsed_days": elapsed / 86400})
    return comparisons if any(row["elapsed_seconds"] for row in comparisons) else []


def _words(text: str) -> set[str]:
    """Keep literal technical tokens; do not invent aliases or identify people."""
    return {word for word in _WORDS.findall(text.casefold()) if word not in _STOP}


def _date(passage: dict):
    """Use only a valid supplied comment date when choosing later context."""
    try:
        return parse_utc(passage["created_at"])
    except (KeyError, TypeError, ValueError):
        return None


def evidence_context(candidate: dict, packet: dict, *, update: bool = False) -> dict:
    """Map target fields to whole matching passages while retaining their context.

    The caller still supplies the complete, unchanged packet. A missing match has
    no factual meaning. These deterministic lexical matches are untrusted data,
    and cannot authorize a claim, an edit, a role or a publication.
    """
    if update:
        latest = candidate.get("updates", [])[-1:] or [{}]
        targets = [("updates[-1].text", latest[0].get("text", ""))]
        cited = {url for source in latest[0].get("sources", [])
                 if (url := safe_canonical_url(source.get("url")))}
    else:
        targets = [(key, candidate.get(key, "")) for key in ("title", "summary", "why_it_matters")]
        cited = None
    units = []
    for source in packet["sources"]:
        whole_source = cited is None or safe_canonical_url(source.get("url")) in cited
        for position, passage in enumerate(source["passages"]):
            if not whole_source and safe_canonical_url(passage.get("url")) not in cited:
                continue
            units.append({"source": source["id"], "position": position, "passage": passage,
                          "words": _words(passage["text"] + " " + passage.get("author", "")),
                          "title": position == 0})
    frequency = Counter(word for unit in units for word in unit["words"])
    fields, selected = [], []
    for field, text in targets:
        if not text:
            continue
        queries = [_words(text), *(_words(part) for part in re.split(r"(?<=[.!?])\s+", text))]

        def score(unit):
            scores = []
            for query in queries:
                shared = query & unit["words"]
                scores.append(sum(1 / frequency[word] for word in shared) /
                              max(sum(1 / max(frequency[word], 1) for word in query), 1))
            return max(scores, default=0)

        ranked = sorted((unit for unit in units if score(unit) > 0), key=score, reverse=True)
        # An abbreviated title must not hide the body's hedge or qualification.
        body = [unit for unit in ranked if not unit["title"]]
        anchors, authors = [], set()
        for unit in body:
            author = unit["passage"].get("author", "").lstrip("@").casefold()
            if (author and author not in authors
                    and re.search(r"(?<!\w)" + re.escape(author) + r"(?!\w)", text.casefold())):
                # A named speaker's own comment must be available beside the
                # attribution; ranking only prose can hide a short disagreement.
                anchors.append(unit)
                authors.add(author)
        anchors.extend(unit for unit in body[:2] if unit not in anchors)
        anchors.extend(unit for unit in ranked if unit not in anchors)
        anchors = anchors[:_MAX_ANCHORS]
        refs = [unit["passage"]["id"] for unit in anchors]
        fields.append({"field": field, "matching_passage_refs": refs})
        for unit in anchors:
            if unit not in selected:
                selected.append(unit)
    primary = list(selected)
    # Keep every available chunk of the same comment or description. A correction
    # can be several chunks after the matched words. The packet already bounds
    # this data; repeat each passage at most once rather than cutting context again.
    for anchor in primary:
        for unit in units:
            same_note = all(unit["passage"].get(key) == anchor["passage"].get(key)
                            for key in ("author", "created_at", "url"))
            if (unit["source"] == anchor["source"] and not unit["title"] and same_note
                    and unit not in selected):
                selected.append(unit)
    later = []
    for source_id in dict.fromkeys(unit["source"] for unit in primary):
        dated = [(date, unit) for unit in units if unit["source"] == source_id
                 if (date := _date(unit["passage"])) is not None]
        if dated:
            latest_date = max(date for date, _ in dated)
            for date, unit in dated:
                if date == latest_date:
                    later.append(unit["passage"]["id"])
                    if unit not in selected:
                        selected.append(unit)
    return {"fields": fields, "passages": [copy.deepcopy(unit["passage"]) for unit in selected],
            "latest_comment_refs": later, "packet_truncated": bool(packet.get("truncated"))}
