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


MAX_FEED_ELEMENTS, MAX_FEED_DEPTH, MAX_FEED_BASE_CHARS = 50000, 128, 8_000_000
# "scheme://..." or "//...": resolving it replaces the inherited base instead of extending it.
ABSOLUTE_BASE = re.compile(r"(?:[A-Za-z][A-Za-z0-9+.-]*:)?//")
LIST_ARCHIVE_HOST = "lists.torproject.org"
# HyperKitty's RSS <author> writes the archived From address with @ as U+FF20,
# optionally followed by the display name in parentheses; only that address counts.
HYPERKITTY_AUTHOR = re.compile(r"[^@\s()＠]+＠[^@\s()＠]+(?: \(.*\))?\Z", re.DOTALL)
PROJECT_SENDER = re.compile(r"[a-z0-9._+-]+@torproject\.org")


def _hyperkitty_address(author: object) -> str | None:
    if not isinstance(author, str) or not HYPERKITTY_AUTHOR.match(author):
        return None
    return author.partition(" (")[0].replace("＠", "@")


def _project_sender(author: object) -> bool:
    address = _hyperkitty_address(author)
    return address is not None and address.isascii() and PROJECT_SENDER.fullmatch(address.lower()) is not None


class CollectionError(Exception):
    def __init__(
        self,
        message: str,
        items: list[dict] | None = None,
        watermark: str | None = None,
        catching_up: bool = False,
    ):
        super().__init__(message)
        self.items = items or []
        self.watermark = watermark
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
    """Normalize one collected record and clamp future timestamps to observation time."""
    if observed:
        # A future date (a typo or a scheduled event) must not pin a story to the
        # top or block later corrections.
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
    parser = expat.ParserCreate(namespace_separator="\n")

    def reject_declaration(*args):
        raise CollectionError("Feed contains disallowed XML declarations")

    # Without a DTD there are no entities to expand.
    parser.StartDoctypeDeclHandler = reject_declaration
    parser.EntityDeclHandler = reject_declaration
    parser.ExternalEntityRefHandler = reject_declaration
    # Bytes alone do not bound what feedparser builds: tiny elements are cheap to
    # send, and every element gets its own copy of the current xml:base (or base),
    # kept in the parse stack and in each detail object. A closed element's base can
    # stay current for later siblings, and a new base does not always replace it
    # (feedparser keeps the old one when the new scheme is not accepted), so the
    # bound only grows: the longest base feedparser could hold by then is an absolute
    # value, or the longest so far plus a relative one and a separator. Every element
    # is charged that bound, and the sum bounds every copy.
    elements = base_chars = longest = item_authors = 0
    stack: list[str] = []
    rss_authors: list[str | None] = []
    plain_author = False
    author_buf: list[str] = []

    def start_element(name, attributes):
        nonlocal elements, base_chars, longest, item_authors, plain_author, author_buf
        elements += 1
        stack.append(name)
        for key, value in attributes.items():
            if key.lower().rsplit("\n", 1)[-1].rpartition(":")[2] == "base":
                # +16 covers the scheme that urljoin adds to "//host" values.
                grown = len(value) + 16 if ABSOLUTE_BASE.match(value) else longest + len(value) + 1
                longest = max(longest, grown)
        base_chars += longest
        if elements > MAX_FEED_ELEMENTS:
            raise CollectionError("Feed has too many XML elements")
        if len(stack) > MAX_FEED_DEPTH:
            raise CollectionError("Feed XML is nested too deeply")
        if base_chars > MAX_FEED_BASE_CHARS:
            raise CollectionError("Feed xml:base text exceeds the limit")
        if stack == ["rss", "channel", "item"]:
            item_authors, plain_author, author_buf = 0, True, []
        elif stack == ["rss", "channel", "item", "author"]:
            item_authors += 1
        elif stack[:4] == ["rss", "channel", "item", "author"]:
            plain_author = False

    def char_data(data):
        if stack == ["rss", "channel", "item", "author"] and item_authors == 1 and sum(map(len, author_buf)) < 1000:
            author_buf.append(data[:1000])

    def end_element(name):
        if stack == ["rss", "channel", "item"]:
            text = "".join(author_buf).strip()
            rss_authors.append(text if item_authors == 1 and plain_author and len(text) < 1000 else None)
        stack.pop()

    parser.StartElementHandler = start_element
    parser.CharacterDataHandler = char_data
    parser.EndElementHandler = end_element
    try:
        parser.Parse(response.body, True)
    except expat.ExpatError as exc:
        raise CollectionError("Invalid RSS/Atom XML") from exc
    feed = feedparser.parse(response.body, sanitize_html=False, resolve_relative_uris=False)
    if not feed.get("version") or feed.get("bozo"):
        raise CollectionError("Invalid RSS/Atom document")
    archive_senders = (
        source["authority"] != "official"
        and urlsplit(response.url).hostname == LIST_ARCHIVE_HOST
        and feed.version == "rss20"
        and len(rss_authors) == len(feed.entries) > 0
        and all(
            raw is not None
            and [raw] == [a.get("name") for a in (entry.get("authors") or ()) if set(a) == {"name"}]
            and _hyperkitty_address(raw) is not None
            for raw, entry in zip(rss_authors, feed.entries)
        )
    )
    cutoff = after(-settings["lookback_days"] * 86400, started)
    items = []
    identities, conflicts, skipped = {}, set(), 0
    for index, entry in enumerate(feed.entries):
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
        # Only an explicit text/plain title keeps its angle brackets; HTML and
        # XHTML titles are stripped.
        title_html = (entry.get("title_detail") or {}).get("type", "text/html") != "text/plain"
        # Some curated feeds put their complete description in an Atom title.
        title = entry.get("title", "")
        if isinstance(title, str) and len(title) > 500:
            full_title = plain_text(title, settings["content_chars"], html=title_html)
            if len(full_title) > 500:
                text = (text + "\n" + full_title)[: settings["content_chars"]]
        # feedparser already uses an Atom entry's id as its link when no alternate
        # link exists; an RSS guid that is not a permalink is never a citation.
        link = entry.get("link", "")
        try:
            item = _item(
                source,
                link,
                title,
                text,
                published,
                updated,
                title_html=title_html,
                observed=started,
            )
        except ValueError:
            continue
        if not item["title"]:
            continue
        if archive_senders and _project_sender(rss_authors[index]):
            item["authority"] = "project-sender"
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
    """Seek through updated_at in ascending order from one inclusive watermark.

    The watermark is the next updated_after: after a complete scan, the poll start
    minus the visibility overlap; while catching up, the last row seen. Each
    request is page 1 of a fresh query, so edits that move rows cannot shift an
    offset; only a full page that shares a single timestamp is stepped by page,
    and a run spent entirely inside one timestamp skips the rest of it.
    updated_before excludes rows dated after the poll started.
    """
    page_size = min(settings["page_size"], source["max_items"])
    parsed = urlsplit(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    params.update({
        "scope": "all",
        "state": "merged" if source["kind"] == "gitlab_mr" else "all",
        "order_by": "updated_at",
        "sort": "asc",
        "updated_after": state.get("watermark") or after(-settings["lookback_days"] * 86400, started),
        "updated_before": started,
        "per_page": str(page_size),
        "page": "1",
    })
    items, start = [], params["updated_after"]
    for _ in range(min(source["max_pages"], max(1, source["max_items"] // page_size))):
        request_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(params), ""))
        # A failed request keeps the rows already read, and a later run resumes where it began.
        resume = params["updated_after"] if params["updated_after"] != start else None
        try:
            records = json.loads(client.request("GET", request_url).body)
        except FetchError as exc:  # including a deadline cutoff
            raise CollectionError(str(exc), items, resume) from exc
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise CollectionError("GitLab returned invalid JSON", items, resume) from exc
        if not isinstance(records, list) or any(not isinstance(r, dict) for r in records) or len(records) > page_size:
            raise CollectionError("GitLab returned an unexpected response", items, resume)
        for record in records:
            if source["kind"] == "gitlab_mr" and record.get("state") != "merged":
                continue
            try:
                published = timestamp(
                    record.get("merged_at") if source["kind"] == "gitlab_mr" else record.get("created_at"),
                    started,
                )
                item = _item(
                    source,
                    record["web_url"],
                    record.get("title", ""),
                    plain_text(record.get("description", ""), settings["content_chars"]),
                    published,
                    timestamp(record.get("updated_at"), published),
                    record.get("labels"),
                    record.get("state", ""),
                    title_html=False,
                    observed=started,
                )
            except (KeyError, ValueError, TypeError):
                continue
            if item["title"]:
                items.append(item)
        if len(records) < page_size:
            return {"items": items, "url": url, "watermark": after(-settings["overlap_seconds"], started)}
        last = records[-1].get("updated_at")
        try:
            moved = parse_utc(last) > parse_utc(params["updated_after"])
        except (TypeError, ValueError):
            raise CollectionError("GitLab returned an invalid timestamp", items, resume) from None
        # A full page that shares one timestamp is a tie group: step through it by page.
        params.update({"updated_after": last, "page": "1"} if moved else {"page": str(int(params["page"]) + 1)})
    if params["page"] != "1" and params["updated_after"] == start:
        # The whole budget stayed inside one timestamp, so the next run would restart
        # this tie at page 1 forever: skip the rest of it (GitLab dates carry milliseconds).
        resume = (parse_utc(start) + timedelta(milliseconds=1)).isoformat(timespec="milliseconds")
        raise CollectionError("GitLab scan skipped part of a large same-timestamp group", items,
                              resume.replace("+00:00", "Z"), catching_up=True)
    raise CollectionError("GitLab scan catching up", items, params["updated_after"], catching_up=True)


def collect_source(
    client: HttpClient, source: dict, state: dict, settings: dict, started: str
) -> dict:
    errors: list[str] = []
    partial: list[dict] = []
    watermark = None
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
            if exc.watermark:
                watermark = exc.watermark
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
        watermark,
        catching_up=catching_up,
    )
