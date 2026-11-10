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
    UTC, BudgetExceeded, after, canonical_url, format_utc, parse_utc, plain_text, timestamp,
)


class CollectionError(Exception):
    def __init__(
        self,
        message: str,
        items: list[dict] | None = None,
        checkpoint: dict | None = None,
        catching_up: bool = False,
        timed_out: bool = False,
    ):
        super().__init__(message)
        self.items = items or []
        self.checkpoint = checkpoint
        self.catching_up = catching_up
        self.timed_out = timed_out


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
) -> dict:
    return {
        "source_id": source["id"],
        "source_name": source["name"],
        "url": canonical_url(url),
        "title": plain_text(title, 500),
        "content": content,
        "published_at": published,
        "updated_at": max(updated, published),
        "kind": source["kind"],
        "product": source["product"],
        "authority": source["authority"],
        "labels": [str(x)[:100] for x in (labels or [])[:30]],
        "upstream_state": upstream_state
        if upstream_state in {"opened", "closed", "merged"}
        else "",
    }


def _feed(
    client: HttpClient,
    source: dict,
    url: str,
    state: dict,
    settings: dict,
    started: str,
) -> dict:
    headers = {}
    if state.get("active_url") == url:
        if state.get("etag"):
            headers["If-None-Match"] = state["etag"]
        if state.get("last_modified"):
            headers["If-Modified-Since"] = state["last_modified"]
    response = client.request("GET", url, headers=headers)
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
    feed = feedparser.parse(response.body)
    if not feed.get("version") or feed.get("bozo"):
        raise CollectionError("Invalid RSS/Atom document")
    cutoff = after(-settings["lookback_days"] * 86400, started)
    items = []
    identities, conflicts = {}, set()
    undated_alert = False
    for entry in feed.entries[: source["max_items"]]:
        if source.get("alert_format") and not (entry.get("published_parsed") or entry.get("updated_parsed")):
            # A poll's clock must never manufacture a new monitoring observation.
            undated_alert = True
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
        link = entry.get("link") or entry.get("id", "")
        try:
            item = _item(
                source,
                link,
                title,
                text,
                published,
                updated,
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
    if undated_alert:
        raise CollectionError("Undated monitoring messages skipped", items, catching_up=True)
    if conflicts:
        unambiguous = [item for item in items if (item["url"], item["updated_at"]) not in conflicts]
        raise CollectionError(
            "Feed has conflicting entries with the same URL and timestamp; ambiguous entries skipped",
            unambiguous, catching_up=True,
        )
    # Oversized feed windows are visible as a coverage warning, never silently truncated.
    if len(feed.entries) > source["max_items"]:
        raise CollectionError(
            "Feed item limit reached; increase source max_items", items, catching_up=True
        )
    return {
        "items": items,
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
        except BudgetExceeded as exc:
            raise CollectionError(
                "Source time budget exceeded", items, checkpoint, timed_out=True
            ) from exc
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
                return collect_timeline(client, {**source, "url": url}, state, settings, started)
            return _gitlab(client, source, url, state, settings, started)
        except CollectionError as exc:
            errors.append(str(exc))
            partial.extend(exc.items)
            if exc.checkpoint:
                checkpoint = exc.checkpoint
            catching_up = exc.catching_up
            if exc.catching_up or exc.timed_out:
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
