"""Bounded feed/GitLab collectors; fallback URLs must describe the same stream."""

from __future__ import annotations

import calendar
import json
import re
from datetime import datetime, timedelta
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from xml.parsers import expat

import feedparser

from .transport import FetchError, HttpClient
from .util import (
    UTC, after, canonical_url, format_utc, parse_utc, plain_text, timestamp,
)


class CollectionError(Exception):
    def __init__(
        self,
        message: str,
        items: list[dict] | None = None,
        checkpoint: dict | None = None,
        catching_up: bool = False,
    ):
        super().__init__(message)
        self.items = items or []
        self.checkpoint = checkpoint
        self.catching_up = catching_up


def _entry_time(entry: dict, name: str, fallback: str) -> str:
    parsed = dict.get(entry, name + "_parsed")
    if parsed:
        try:
            return format_utc(datetime.fromtimestamp(calendar.timegm(parsed), UTC))
        except (ValueError, OverflowError, TypeError):
            pass
    return fallback


def _item(
    source: dict,
    url: str,
    title: str,
    content: str,
    published: str,
    updated: str,
    labels: list | None = None,
    upstream_state: str = "",
    *,
    title_html: bool = True,
    observed: str | None = None,
) -> dict:
    if observed and not source.get("alert_format"):
        # A future date (a typo or a scheduled event) must not pin a story to the
        # top or block later corrections. Alert parsers judge future dates themselves.
        # All three are format_utc strings, so string order is time order.
        published, updated = min(published, observed), min(updated, observed)
    return {
        "source_id": source["id"],
        "url": canonical_url(url),
        "title": plain_text(title, 500, html=title_html),
        "content": content,
        "published_at": published,
        "updated_at": max(updated, published),
        "kind": source["kind"],
        "product": source["product"],
        "authority": source["authority"],
        "labels": [plain_text(str(x), 100, html=False) for x in (labels or [])[:30]],
        "upstream_state": upstream_state
        if upstream_state in {"opened", "closed", "merged"}
        else "",
    }


def _get(client: HttpClient, url: str, state: dict):
    """GET with the cache validators saved for this exact URL."""
    headers = {}
    if state.get("active_url") == url:
        if state.get("etag"):
            headers["If-None-Match"] = state["etag"]
        if state.get("last_modified"):
            headers["If-Modified-Since"] = state["last_modified"]
    return client.request("GET", url, headers=headers)


def _feed(
    client: HttpClient,
    source: dict,
    url: str,
    state: dict,
    settings: dict,
    started: str,
) -> dict:
    response = _get(client, url, state)
    if response.status == 304:
        return {
            "items": [],
            "url": url,
            "etag": state.get("etag"),
            "last_modified": state.get("last_modified"),
        }
    # Expat recognizes the actual XML encoding (including UTF-16). A raw byte
    # regexp misses encoded declarations and is not a security boundary.
    parser = expat.ParserCreate()

    def reject_declaration(*args):
        raise CollectionError("Feed contains disallowed XML declarations")

    parser.StartDoctypeDeclHandler = reject_declaration
    parser.EntityDeclHandler = reject_declaration
    parser.ExternalEntityRefHandler = reject_declaration
    depth = elements = 0

    def start_element(name, attributes):
        nonlocal depth, elements
        depth += 1
        elements += 1
        if depth > settings["max_xml_depth"] or elements > settings["max_xml_elements"]:
            raise CollectionError("Feed XML structure exceeds configured limits")

    def end_element(name):
        nonlocal depth
        depth -= 1

    parser.StartElementHandler = start_element
    parser.EndElementHandler = end_element
    try:
        parser.Parse(response.body, True)
    except expat.ExpatError as exc:
        raise CollectionError("Invalid RSS/Atom XML") from exc
    feed = feedparser.parse(response.body, sanitize_html=False, resolve_relative_uris=False)
    if not feed.get("version") or feed.get("bozo"):
        raise CollectionError("Invalid RSS/Atom document")
    cutoff = after(-settings["lookback_days"] * 86400, started)
    items = []
    identities, conflicts, skipped = {}, set(), 0
    for entry in feed.entries:
        if source.get("alert_format") and not (entry.get("published_parsed") or entry.get("updated_parsed")):
            # A poll's clock must never manufacture a new monitoring observation.
            skipped += 1
            continue
        published = _entry_time(
            entry, "published", _entry_time(entry, "updated", started)
        )
        updated = _entry_time(entry, "updated", published)
        if updated < cutoff:
            continue
        content_parts = entry.get("content") or []
        text = plain_text(
            content_parts[0].get("value", "") if content_parts else entry.get("summary", ""),
            settings["content_chars"],
        )
        # Some curated feeds put their complete description in an Atom title.
        title = entry.get("title", "")
        if isinstance(title, str) and len(title) > 500:
            full_title = plain_text(title, settings["content_chars"])
            if len(full_title) > 500:
                text = (text + "\n" + full_title)[: settings["content_chars"]]
        # feedparser already uses an Atom entry's id as its link when no alternate
        # link exists; an RSS guid that is not a permalink is never a citation.
        link = entry.get("link", "")
        title_detail = entry.get("title_detail") or {}
        try:
            item = _item(
                source,
                link,
                title,
                text,
                published,
                updated,
                # Only an explicit text/plain title keeps its angle brackets;
                # HTML and XHTML titles are stripped.
                title_html=title_detail.get("type", "text/html") != "text/plain",
                observed=started,
            )
        except ValueError:
            continue
        if not item["title"]:
            continue
        # Some Atom archives omit alternate links and reuse an ID for distinct
        # events. Do not silently choose one event when that fallback is ambiguous.
        if feed.version.startswith("atom") and not entry.get("links") and entry.get("id") == link:
            identity = (item["url"], item["updated_at"])
            content = (item["title"], item["content"])
            if identity in identities and identities[identity] != content:
                conflicts.add(identity)
            identities[identity] = content
        items.append(item)
    if conflicts:
        unambiguous = [item for item in items if (item["url"], item["updated_at"]) not in conflicts]
        skipped += len(items) - len(unambiguous)
        items = unambiguous
    # An archive feed is bounded by its newest entries, whatever order it lists them in.
    items = sorted(items, key=lambda item: item["updated_at"], reverse=True)[: source["max_items"]]
    # Skipped entries are counted in the run report instead of leaving a healthy
    # feed in a permanent error state that also discards its ETag.
    return {
        "items": items,
        "skipped": skipped,
        "url": url,
        "etag": response.headers.get("etag"),
        "last_modified": response.headers.get("last-modified"),
    }


def _gitlab(
    client: HttpClient,
    source: dict,
    url: str,
    state: dict,
    settings: dict,
    started: str,
) -> dict:
    upper = parse_utc(state.get("scan_upper") or started)
    watermark = state.get("watermark")
    last_reconciled = state.get("last_reconciled")
    reconcile = (
        not last_reconciled
        or (
            upper - parse_utc(last_reconciled)
        ).total_seconds()
        >= settings["reconcile_seconds"]
    )
    lower = (
        parse_utc(watermark)
        - timedelta(seconds=settings["overlap_seconds"])
        if watermark and not reconcile
        else upper - timedelta(days=settings["lookback_days"])
    )
    if state.get("scan_lower"):
        lower = parse_utc(state["scan_lower"])
        reconcile = bool(state.get("scan_reconcile"))
    page_size = min(settings["page_size"], source["max_items"])
    page_budget = min(source["max_pages"], max(1, source["max_items"] // page_size))
    start_page = state.get("scan_page") or 1
    cursor = state.get("scan_cursor")
    parsed = urlsplit(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    params.update(
        {
            "scope": "all",
            "state": "merged" if source["kind"] == "gitlab_mr" else "all",
            "order_by": "updated_at",
            "sort": "asc",
            "updated_after": lower.isoformat(),
            "updated_before": upper.isoformat(),
            "per_page": str(page_size),
        }
    )
    if source["kind"] == "gitlab_issue":
        params["pagination"] = "keyset"
    items = []
    for page in range(start_page, start_page + page_budget):
        checkpoint = {
            "lower": lower.isoformat(),
            "upper": upper.isoformat(),
            "page": page,
            "cursor": cursor,
            "reconcile": reconcile,
        }
        if cursor:
            params["cursor"] = cursor
            params.pop("page", None)
        else:
            params["page"] = str(page)
            params.pop("cursor", None)
        request_url = urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path, urlencode(params), "")
        )
        try:
            response = client.request("GET", request_url)
        except FetchError as exc:
            raise CollectionError(str(exc), items, checkpoint) from exc
        try:
            records = json.loads(response.body)
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise CollectionError(
                "GitLab returned invalid JSON", items, checkpoint
            ) from exc
        if not isinstance(records, list) or any(
            not isinstance(r, dict) for r in records
        ):
            raise CollectionError(
                "GitLab returned an unexpected response", items, checkpoint
            )
        if len(records) > page_size:
            raise CollectionError(
                "GitLab ignored configured page size", items, checkpoint
            )
        for record in records:
            if source["kind"] == "gitlab_mr" and record.get("state") != "merged":
                continue
            try:
                published = timestamp(
                    record.get("merged_at")
                    if source["kind"] == "gitlab_mr"
                    else record.get("created_at"),
                    started,
                )
                updated = timestamp(record.get("updated_at"), published)
                item = _item(
                    source,
                    record["web_url"],
                    record.get("title", ""),
                    plain_text(
                        record.get("description", ""), settings["content_chars"]
                    ),
                    published,
                    updated,
                    record.get("labels"),
                    record.get("state", ""),
                    title_html=False,
                    observed=started,
                )
            except (KeyError, ValueError, TypeError):
                continue
            if item["title"]:
                items.append(item)
        # Keyset pagination survives edits that remove earlier rows from the fixed
        # window. Only extract the opaque cursor; never fetch a supplied Link URL.
        next_cursor = None
        match = re.search(
            r'<([^>]+)>\s*;\s*rel=["\']?next\b', response.headers.get("link", ""), re.I
        )
        if match:
            link = urlsplit(match.group(1))
            if (link.scheme, link.netloc, link.path) != (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
            ):
                raise CollectionError(
                    "GitLab pagination link changed destination", items, checkpoint
                )
            cursors = [v for k, v in parse_qsl(link.query) if k == "cursor"]
            if cursors:
                if len(cursors) != 1 or len(cursors[0]) > 8192:
                    raise CollectionError(
                        "Invalid GitLab pagination cursor", items, checkpoint
                    )
                next_cursor = cursors[0]
        next_page = response.headers.get("x-next-page")
        if source["kind"] == "gitlab_issue" and next_page is None:
            # GitLab keyset pagination has no offset headers. Absence of the
            # next Link is terminal even when the final page is exactly full;
            # inventing page=N would restart the keyset scan at its first page.
            complete = not match
        else:
            # Older/offset endpoints explicitly advertise their next page, or
            # require an empty/short-page check when those headers are absent.
            complete = not match and (
                (next_page == "") or (next_page is None and len(records) < page_size)
            )
        if complete:
            return {
                "items": items,
                "url": url,
                "watermark": format_utc(upper),
                "reconciled": reconcile,
            }
        cursor = next_cursor
    checkpoint = {
        "lower": lower.isoformat(),
        "upper": upper.isoformat(),
        "page": start_page + page_budget,
        "cursor": cursor,
        "reconcile": reconcile,
    }
    raise CollectionError(
        "GitLab scan catching up; watermark retained",
        items,
        checkpoint,
        catching_up=True,
    )


def collect_source(
    client: HttpClient, source: dict, state: dict, settings: dict, started: str
) -> dict:
    errors: list[str] = []
    partial: list[dict] = []
    checkpoint = None
    catching_up = False
    for url in [source["url"], *source["fallback_urls"]]:
        try:
            if source["kind"] in {"feed", "tag"}:
                return _feed(client, source, url, state, settings, started)
            if source["kind"] == "metrics_timeline":
                from .timeline import collect_timeline
                return collect_timeline(client, source, url, state, settings, started)
            return _gitlab(client, source, url, state, settings, started)
        except CollectionError as exc:
            errors.append(str(exc))
            partial.extend(exc.items)
            if exc.checkpoint:
                checkpoint = exc.checkpoint
            catching_up = exc.catching_up
            if exc.catching_up:
                # Another mirror cannot make this bounded scan finish faster.
                break
        except FetchError as exc:
            # Transport error strings are sanitized; do not expose request headers/body.
            errors.append(str(exc))
    raise CollectionError(
        errors[-1] if errors else "All source endpoints failed",
        partial,
        checkpoint,
        catching_up=catching_up,
    )
