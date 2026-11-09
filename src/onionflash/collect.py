"""Bounded feed/GitLab collectors; fallback URLs must describe the same stream."""

from __future__ import annotations

import calendar
import json
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from xml.parsers import expat

import feedparser

from .transport import FetchError, HttpClient
from .util import BudgetExceeded, canonical_url, plain_text, timestamp


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
            return (
                datetime.fromtimestamp(calendar.timegm(parsed), timezone.utc)
                .isoformat(timespec="seconds")
                .replace("+00:00", "Z")
            )
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
    depth = elements = entries = 0

    def start_element(name, attributes):
        nonlocal depth, elements, entries
        depth += 1
        elements += 1
        if name.rsplit(":", 1)[-1] in {"item", "entry"}:
            entries += 1
        if depth > settings["max_xml_depth"] or elements > settings["max_xml_elements"]:
            raise CollectionError("Feed XML structure exceeds configured limits")
        if entries > source["max_items"]:
            raise CollectionError("Feed item limit reached; increase source max_items")

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
    cutoff = datetime.fromisoformat(started.replace("Z", "+00:00")) - timedelta(
        days=settings["lookback_days"]
    )
    items = []
    for entry in feed.entries[: source["max_items"]]:
        content_parts = entry.get("content") or []
        text = (
            content_parts[0].get("value", "")
            if content_parts
            else entry.get("summary", "")
        )
        text = plain_text(text, settings["content_chars"])
        published = _entry_time(
            entry, "published", _entry_time(entry, "updated", started)
        )
        updated = _entry_time(entry, "updated", published)
        if datetime.fromisoformat(updated.replace("Z", "+00:00")) < cutoff:
            continue
        try:
            item = _item(
                source,
                entry.get("link", ""),
                entry.get("title", ""),
                text,
                published,
                updated,
            )
        except ValueError:
            continue
        if not item["title"]:
            continue
        items.append(item)
    # Oversized feed windows are visible as a coverage warning, never silently truncated.
    if len(feed.entries) > source["max_items"]:
        raise CollectionError(
            "Feed item limit reached; increase source max_items", items
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
    upper = datetime.fromisoformat(
        (state.get("scan_upper") or started).replace("Z", "+00:00")
    )
    watermark = state.get("watermark")
    last_reconciled = state.get("last_reconciled")
    reconcile = (
        not last_reconciled
        or (
            upper - datetime.fromisoformat(last_reconciled.replace("Z", "+00:00"))
        ).total_seconds()
        >= settings["reconcile_seconds"]
    )
    lower = (
        datetime.fromisoformat(watermark.replace("Z", "+00:00"))
        - timedelta(seconds=settings["overlap_seconds"])
        if watermark and not reconcile
        else upper - timedelta(days=settings["lookback_days"])
    )
    if state.get("scan_lower"):
        lower = datetime.fromisoformat(state["scan_lower"].replace("Z", "+00:00"))
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
        except (ValueError, UnicodeError) as exc:
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
                "watermark": timestamp(upper.isoformat()),
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
