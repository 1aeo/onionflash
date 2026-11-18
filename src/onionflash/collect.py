"""Bounded feed/GitLab collectors; fallback URLs must describe the same stream."""

from __future__ import annotations

import calendar
from collections.abc import Iterable
import re
from datetime import datetime, timedelta
from html import unescape
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from xml.parsers import expat

import feedparser

from .transport import FetchError, HttpClient
from .util import (
    UTC, after, canonical_url, format_utc, is_dirauth_item, is_hackerone_item, parse_utc, plain_text, timestamp,
)


MAX_FEED_ELEMENTS, MAX_FEED_DEPTH, MAX_FEED_BASE_CHARS = 50000, 128, 8_000_000
# "scheme://..." or "//...": resolving it replaces the inherited base instead of extending it.
ABSOLUTE_BASE = re.compile(r"(?:[A-Za-z][A-Za-z0-9+.-]*:)?//")
LIST_ARCHIVE_HOST = "lists.torproject.org"
# HyperKitty's RSS <author> writes the archived From address with @ as U+FF20,
# optionally followed by the display name in parentheses; only that address counts.
HYPERKITTY_AUTHOR = re.compile(r"[^@\s()＠]+＠[^@\s()＠]+(?: \(.*\))?\Z", re.DOTALL)
PROJECT_SENDER = re.compile(r"[a-z0-9._+-]+@torproject\.org")
SENDER_DOMAIN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+")
SENDER_ADDRESS = re.compile(rf"[a-z0-9._+-]+@({SENDER_DOMAIN.pattern})")
_GITLAB_AUTHOR_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}")
DISCOURSE_NAMESPACE = "http://www.discourse.org/"
_DISCOURSE_FOOTER = re.compile(
    r"<p>\s*<small>\s*[0-9]+ posts? - [0-9]+ participants?\s*</small>\s*</p>\s*"
    r"<p>\s*<a\s+href\s*=\s*(?P<quote>[\"'])(?P<url>[^\"'<>\r\n]{1,4096})(?P=quote)\s*>"
    r"Read full topic</a>\s*</p>\s*\Z", re.I,
)


def _without_discourse_footer(value: str, entry_url: str) -> str:
    """Remove only Discourse's complete generated trailer for this exact topic."""
    match = _DISCOURSE_FOOTER.search(value)
    if match is not None:
        try:
            if canonical_url(unescape(match["url"])) == canonical_url(entry_url):
                return value[:match.start()].rstrip()
        except ValueError:
            pass
    return value


def _hyperkitty_address(author: object) -> str | None:
    if not isinstance(author, str) or not HYPERKITTY_AUTHOR.match(author):
        return None
    return author.partition(" (")[0].replace("＠", "@")


def _sender_authority(author: object, trusted_domains: list[str] | tuple[str, ...] = ()) -> str | None:
    address = _hyperkitty_address(author)
    if address is None or not address.isascii():
        return None
    match = SENDER_ADDRESS.fullmatch(address.lower())
    if match is None or len(domain := match.group(1)) > 253 or not SENDER_DOMAIN.fullmatch(domain):
        return None
    if domain == "torproject.org":
        return "project-sender"
    if domain.endswith(".torproject.org"):
        return None
    for raw in trusted_domains:
        if isinstance(raw, str) and (td := raw.strip().lower()) and td != "torproject.org":
            if domain == td or domain.endswith("." + td):
                return "trusted-operator"
    return None


def _project_sender(author: object) -> bool:
    return _sender_authority(author) == "project-sender"


class CollectionError(Exception):
    """Source collection failure, carrying any partial items or resume watermark."""

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


def make_item(
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
    author: str = "",
    dirauth_users: Iterable[str] | None = None,
) -> dict:
    """Normalize one collected record and clamp future timestamps to observation time."""
    if observed:
        # A future date (a typo or a scheduled event) must not pin a story to the
        # top or block later corrections. format_utc strings sort chronologically.
        published, updated = min(published, observed), min(updated, observed)
    item = {
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
        "upstream_state": upstream_state if upstream_state in {"opened", "closed", "merged"} else "",
    }
    clean_author = plain_text(author, 100, html=False)
    if clean_author and _GITLAB_AUTHOR_RE.fullmatch(clean_author) and ".." not in clean_author and not clean_author.endswith("."):
        item["author"] = clean_author
    if item["authority"] == "development":
        if is_hackerone_item(item):
            item["authority"] = "hackerone"
        elif is_dirauth_item(item, dirauth_users):
            item["authority"] = "dirauth-operator"
    return item


def fetch_cached(client: HttpClient, url: str, state: dict):
    """GET with the cache validators saved for this exact URL."""
    headers = {}
    if state.get("active_url") == url:
        if state.get("etag"):
            headers["If-None-Match"] = state["etag"]
        if state.get("last_modified"):
            headers["If-Modified-Since"] = state["last_modified"]
    return client.request("GET", url, headers=headers)


_item = make_item
_get = fetch_cached


def _scan_feed_xml(body: bytes) -> list[str | None]:
    """Reject DTDs/entities and unbounded xml:base growth via Expat, and extract raw RSS <author> values."""
    parser = expat.ParserCreate(namespace_separator="\n")
    stack: list[str] = []
    rss_authors: list[str | None] = []
    author_buf: list[str] = []
    state = {"elements": 0, "base_chars": 0, "longest": 0, "item_authors": 0, "plain_author": False}

    def reject_declaration(*_args):
        """Refuse DOCTYPE and XML entity declarations in untrusted feeds."""
        raise CollectionError("Feed contains disallowed XML declarations")

    def start_element(name, attributes):
        """Enforce XML element, nesting, and `xml:base` limits while tracking RSS `<author>`."""
        state["elements"] += 1
        stack.append(name)
        for key, value in attributes.items():
            if key.lower().rsplit("\n", 1)[-1].rpartition(":")[2] == "base":
                # +16 covers the scheme that urljoin adds to "//host" values.
                grown = len(value) + 16 if ABSOLUTE_BASE.match(value) else state["longest"] + len(value) + 1
                state["longest"] = max(state["longest"], grown)
        state["base_chars"] += state["longest"]
        if state["elements"] > MAX_FEED_ELEMENTS:
            raise CollectionError("Feed has too many XML elements")
        if len(stack) > MAX_FEED_DEPTH:
            raise CollectionError("Feed XML is nested too deeply")
        if state["base_chars"] > MAX_FEED_BASE_CHARS:
            raise CollectionError("Feed xml:base text exceeds the limit")
        if stack == ["rss", "channel", "item"]:
            state["item_authors"], state["plain_author"] = 0, True
            author_buf.clear()
        elif stack == ["rss", "channel", "item", "author"]:
            state["item_authors"] += 1
        elif stack[:4] == ["rss", "channel", "item", "author"]:
            state["plain_author"] = False

    def char_data(data):
        """Accumulate bounded character data for a single plain RSS `<author>` element."""
        if stack == ["rss", "channel", "item", "author"] and state["item_authors"] == 1 and sum(map(len, author_buf)) < 1000:
            author_buf.append(data[:1000])

    def end_element(_name):
        """Record each RSS `<item>`'s verified plain `<author>` text on element close."""
        if stack == ["rss", "channel", "item"]:
            text = "".join(author_buf).strip()
            rss_authors.append(text if state["item_authors"] == 1 and state["plain_author"] and len(text) < 1000 else None)
        stack.pop()

    parser.StartDoctypeDeclHandler = parser.EntityDeclHandler = parser.ExternalEntityRefHandler = reject_declaration
    parser.StartElementHandler = start_element
    parser.CharacterDataHandler = char_data
    parser.EndElementHandler = end_element
    try:
        parser.Parse(body, True)
    except expat.ExpatError as exc:
        raise CollectionError("Invalid RSS/Atom XML") from exc
    return rss_authors


def _feed(
    client: HttpClient,
    source: dict,
    url: str,
    state: dict,
    settings: dict,
    started: str,
) -> dict:
    response = fetch_cached(client, url, state)
    if response.status == 304:
        return {"items": [], "url": url, "etag": state.get("etag"), "last_modified": state.get("last_modified")}
    rss_authors = _scan_feed_xml(response.body)
    feed = feedparser.parse(response.body, sanitize_html=False, resolve_relative_uris=False)
    if not feed.get("version") or feed.get("bozo"):
        raise CollectionError("Invalid RSS/Atom document")
    discourse_feed = feed.version == "rss20" and DISCOURSE_NAMESPACE in feed.get("namespaces", {}).values()
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
    staged: list[tuple[dict, tuple[str, str] | None]] = []
    fallback_contents: dict[tuple[str, str], tuple[str, str] | None] = {}
    skipped = 0
    for index, entry in enumerate(feed.entries):
        published = _entry_time(entry, "published", _entry_time(entry, "updated", ""))
        if not published:
            if source.get("alert_format"):
                skipped += 1
                continue
            published = started
        updated = _entry_time(entry, "updated", published)
        if updated < cutoff:
            continue
        content_parts = entry.get("content") or []
        content = content_parts[0].get("value", "") if content_parts else entry.get("summary", "")
        if discourse_feed and isinstance(content, str) and isinstance(entry.get("link"), str):
            content = _without_discourse_footer(content, entry["link"])
        text = plain_text(content, settings["content_chars"])
        # Only an explicit text/plain title keeps its angle brackets; HTML/XHTML titles are stripped.
        title_html = (entry.get("title_detail") or {}).get("type", "text/html") != "text/plain"
        # Some curated feeds put their complete description in an Atom title.
        title = entry.get("title", "")
        if isinstance(title, str) and len(title) > 500:
            full_title = plain_text(title, settings["content_chars"], html=title_html)
            if len(full_title) > 500:
                text = (text + "\n" + full_title)[: settings["content_chars"]]
        # feedparser already uses an Atom entry's id as its link when no alternate
        # link exists; an RSS guid that is not a permalink is never a citation.
        try:
            item = make_item(
                source, entry.get("link", ""), title, text, published, updated,
                title_html=title_html, observed=started,
            )
        except ValueError:
            continue
        if not item["title"]:
            continue
        if archive_senders and (
            sender_auth := _sender_authority(rss_authors[index], settings.get("trusted_operator_domains", ()))
        ) is not None:
            item["authority"] = sender_auth
            if sender_auth in {"project-sender", "trusted-operator"} and (
                sender_addr := _hyperkitty_address(rss_authors[index])
            ):
                item["sender_domain"] = sender_addr.lower().partition("@")[2]
        # Some Atom archives omit alternate links and reuse an ID for distinct
        # events. Do not silently choose one event when that fallback is ambiguous.
        has_alternate = any(
            isinstance(link_obj, dict)
            and link_obj.get("rel", "alternate") == "alternate"
            and str(link_obj.get("type") if "type" in link_obj else "text/html").lower()
            in {"text/html", "application/xhtml+xml", "html", "xhtml"}
            and bool(link_obj.get("href"))
            for link_obj in (entry.get("links") or ())
        )
        fallback_key = None
        if feed.version.startswith("atom") and not has_alternate and entry.get("id"):
            fallback_key = (item["url"], item["updated_at"])
            content = (item["title"], item["content"])
            if fallback_contents.setdefault(fallback_key, content) != content:
                fallback_contents[fallback_key] = None
        staged.append((item, fallback_key))
    items = [item for item, key in staged if key is None or fallback_contents[key] is not None]
    skipped += len(staged) - len(items)
    # An archive feed is bounded by its newest entries, whatever order it lists them in.
    items = sorted(items, key=lambda item: item["updated_at"], reverse=True)[: source["max_items"]]
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
            records = client.request("GET", request_url).json()
        except FetchError as exc:  # including a deadline cutoff or invalid JSON
            raise CollectionError(str(exc), items, resume) from exc
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
                raw_author = record.get("author")
                username = (
                    raw_author.get("username", "")
                    if isinstance(raw_author, dict) and isinstance(raw_author.get("username"), str)
                    else ""
                )
                item = make_item(
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
                    author=username,
                    dirauth_users=settings.get("dirauth_gitlab_users"),
                )
            except (KeyError, ValueError, TypeError):
                continue
            # Closing is a dated development of an issue; an invalid date is left out, never the item.
            closed = timestamp(record.get("closed_at"), "") if source["kind"] == "gitlab_issue" and item["upstream_state"] == "closed" else ""
            if closed:
                item["closed_at"] = min(closed, started)
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
    """Collect items from a source URL or its fallbacks within configured bounds."""
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
