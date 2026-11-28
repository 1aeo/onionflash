"""Bounded feed/GitLab collectors; fallback URLs must describe the same stream."""

from __future__ import annotations

import calendar
from collections.abc import Iterable
import re
from datetime import datetime, timedelta
from html import unescape
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit
from xml.parsers import expat

import feedparser

from .transport import FetchError, HttpClient
from .util import (
    LIST_ARCHIVE_HOST, UTC, after, canonical_url, effective_authority, format_utc,
    is_valid_domain, is_valid_gitlab_user, parse_utc, plain_text, safe_canonical_url, timestamp,
)


MAX_FEED_ELEMENTS, MAX_FEED_DEPTH, MAX_FEED_BASE_CHARS = 50000, 128, 8_000_000
# "scheme://..." or "//...": resolving it replaces the inherited base instead of extending it.
ABSOLUTE_BASE = re.compile(r"(?:[A-Za-z][A-Za-z0-9+.-]*:)?//")
# HyperKitty's RSS <author> writes the archived From address with @ as U+FF20,
# optionally followed by the display name in parentheses; only that address counts.
HYPERKITTY_AUTHOR = re.compile(r"[^@\s()＠]+＠[^@\s()＠]+(?: \(.*\))?\Z", re.DOTALL)
_SENDER_LOCAL_RE = re.compile(r"[a-z0-9._+-]+")
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


def _sender_authority(author: object, trusted_domains: Iterable[str] = ()) -> str | None:
    address = _hyperkitty_address(author)
    local, _, domain = address.lower().partition("@") if address and address.isascii() else ("", "", "")
    if not _SENDER_LOCAL_RE.fullmatch(local) or not is_valid_domain(domain):
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
    tor_core_users: Iterable[str] | None = None,
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
    if is_valid_gitlab_user(clean_author):
        item["author"] = clean_author
    item["authority"] = effective_authority(item, dirauth_users, tor_core_users)
    return item


def fetch_cached(client: HttpClient, url: str, state: dict, *, request_url: str | None = None):
    """GET with the cache validators saved for this exact canonical URL."""
    headers = {}
    if state.get("active_url") == url:
        if state.get("etag"):
            headers["If-None-Match"] = state["etag"]
        if state.get("last_modified"):
            headers["If-Modified-Since"] = state["last_modified"]
    return client.request("GET", request_url or url, headers=headers)


def cached_result(url: str, response, state: dict, items: Iterable[dict] = (), **extra) -> dict:
    """Build a collection result preserving validators on HTTP 304 or updating from headers."""
    hit = response.status == 304
    return {"items": [] if hit else list(items), "url": url,
            "etag": state.get("etag") if hit else response.headers.get("etag"),
            "last_modified": state.get("last_modified") if hit else response.headers.get("last-modified"), **extra}


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


_GITLAB_HOST = "gitlab.torproject.org"
_PGP_SIGNATURE_RE = re.compile(
    r"-----BEGIN PGP SIGNATURE-----.*?-----END PGP SIGNATURE-----",
    re.DOTALL,
)
_RELEASE_CLI_BOILERPLATE_RE = re.compile(r"^\s*created using the release-cli\.?\s*$", re.IGNORECASE)
_TRIVIAL_TAG_MSG_RE = re.compile(
    r"^(?:(?:bump|set|update)\s+(?:the\s+)?(?:version(?:\s+of\s+\S+)?\s+to|to)|"
    r"(?:release|tag|prepare|version))\s+"
    r"(?:[a-z0-9_.-]+-)?v?\d+(?:\.\d+)+(?:[-.~+][a-z0-9._-]+)*\.?$",
    re.IGNORECASE,
)
_TAG_VERSION_RE = re.compile(
    r"^(?P<prefix>.*?)(?P<version>\d+(?:\.\d+)+)(?P<pre>(?:[-.~]?(?:alpha|beta|pre|rc|dev)\S*))?$",
    re.IGNORECASE,
)
_MAX_TAG_COMPARE_CALLS = 5
_MAX_TAG_COMPARE_COMMITS = 20
_MAX_TAG_ENRICHED_CHARS = 3500


def _gitlab_tags_project_path(url: str) -> str | None:
    """Extract the GitLab project path from a `https://gitlab.torproject.org/<project>/-/tags` feed URL."""
    parts = urlsplit(url)
    if parts.scheme.lower() != "https" or (parts.hostname or "").lower() != _GITLAB_HOST:
        return None
    path = parts.path.rstrip("/")
    for suffix in ("/-/tags.atom", "/-/tags"):
        if path.endswith(suffix):
            project = path[: -len(suffix)].strip("/")
            return project or None
    return None


def _clean_tag_message(raw: object) -> str:
    """Strip inline PGP signature blocks from a tag annotation message."""
    if not isinstance(raw, str):
        return ""
    stripped = _PGP_SIGNATURE_RE.sub("", raw)
    return "\n".join(line.rstrip() for line in stripped.splitlines()).strip()


def _clean_release_description(tag_obj: dict) -> str:
    """Return substantive `release.description` text after stripping release-cli boilerplate."""
    rel = tag_obj.get("release")
    if not isinstance(rel, dict):
        return ""
    desc = rel.get("description")
    if not isinstance(desc, str):
        return ""
    kept = [ln.rstrip() for ln in desc.splitlines() if ln.strip() and not _RELEASE_CLI_BOILERPLATE_RE.match(ln)]
    return "\n".join(kept).strip()


def _bare_tag_names(tag_name: str, item_title: str) -> set[str]:
    norm = lambda s: re.sub(r"[\s._-]+", "", s.lower()).removeprefix("v")
    return {norm(tag_name), norm(item_title)}


def _is_trivial_tag_line(line: str, bare_names: set[str]) -> bool:
    norm_line = re.sub(r"[\s._-]+", "", line.lower()).removeprefix("v")
    return bool(
        _RELEASE_CLI_BOILERPLATE_RE.match(line)
        or _TRIVIAL_TAG_MSG_RE.match(line)
        or norm_line in bare_names
    )


def _strip_trivial_tag_lines(message: str, tag_name: str, item_title: str) -> str:
    if not message:
        return ""
    bare_names = _bare_tag_names(tag_name, item_title)
    return "\n".join(
        ln.rstrip()
        for ln in message.splitlines()
        if ln.strip() and not _is_trivial_tag_line(ln.strip(), bare_names)
    ).strip()


def _is_substantive_tag_message(message: str, tag_name: str, item_title: str) -> bool:
    """Return whether `message` carries notes beyond bare tag names or version-bump lines."""
    if not message:
        return False
    lines = [ln.strip() for ln in message.splitlines() if ln.strip()]
    if not lines:
        return False
    bare_names = _bare_tag_names(tag_name, item_title)
    return any(not _is_trivial_tag_line(ln, bare_names) for ln in lines)


def _parse_tag_version(name: str) -> tuple[str, tuple[int, ...], str] | None:
    match = _TAG_VERSION_RE.match(name.strip())
    if match is None:
        return None
    try:
        nums = tuple(int(part) for part in match.group("version").split("."))
    except ValueError:
        return None
    return (match.group("prefix").lower(), nums, (match.group("pre") or "").lower())


def _pre_order_key(pre: str) -> tuple[tuple[int, object], ...]:
    """Return a comparable sort key for prerelease suffixes such as `-rc1` < `-rc2` < `-rc10`."""
    return tuple((0, int(tok)) if tok.isdigit() else (1, tok) for tok in re.findall(r"\d+|[a-z]+", pre.lower()))


def _preceding_tag_name(tags: list[dict], tag_idx: int, tag_name: str) -> str | None:
    """Find the immediately preceding tag on the same release line from GitLab's tags list."""
    parsed = _parse_tag_version(tag_name)
    if parsed is not None:
        prefix, ver, pre = parsed
        is_pre = bool(pre)
        ver_key = (ver, 0 if is_pre else 1, _pre_order_key(pre))
        candidates: list[tuple[tuple[int, tuple[int, ...], int, tuple[tuple[int, object], ...], int], str]] = []
        for idx, entry in enumerate(tags):
            cand_name = entry.get("name")
            if idx == tag_idx or not isinstance(cand_name, str) or not cand_name or cand_name == tag_name:
                continue
            cand_parsed = _parse_tag_version(cand_name)
            if cand_parsed is None:
                continue
            c_prefix, c_ver, c_pre = cand_parsed
            c_is_pre = bool(c_pre)
            if not is_pre and c_is_pre:
                continue
            c_key = (c_ver, 0 if c_is_pre else 1, _pre_order_key(c_pre))
            if c_prefix != prefix or c_key >= ver_key:
                continue
            same_branch = 1 if (len(ver) >= 3 and len(c_ver) == len(ver) and c_ver[:-1] == ver[:-1]) else 0
            same_pre = 1 if (c_is_pre == is_pre) else 0
            candidates.append(((same_branch, c_ver, 0 if c_is_pre else 1, _pre_order_key(c_pre), same_pre), cand_name))
        if candidates:
            candidates.sort(key=lambda pair: pair[0], reverse=True)
            return candidates[0][1]
        return None
    for nxt in tags[tag_idx + 1 :]:
        cand_name = nxt.get("name")
        if isinstance(cand_name, str) and cand_name and cand_name != tag_name:
            return cand_name
    return None


def _bound_enriched_content(header: str, body: str, limit: int) -> str:
    text = f"{header}\n{body}".strip()
    cap = min(max(limit, 200), _MAX_TAG_ENRICHED_CHARS) if limit > 0 else _MAX_TAG_ENRICHED_CHARS
    if len(text) <= cap:
        return text
    clipped = text[:cap].rsplit("\n", 1)[0].rstrip()
    if len(clipped) > len(header) + 1:
        return clipped
    fallback = text[:cap].rstrip()
    return fallback if len(fallback) > len(header) + 1 else ""


def _enrich_gitlab_tags(client: HttpClient, feed_url: str, items: list[dict], settings: dict) -> None:
    """Fail-soft enrich GitLab tag items with substantive notes or compare commit shortlogs."""
    project_path = _gitlab_tags_project_path(feed_url)
    if project_path is None or not items:
        return
    encoded_project = quote(project_path, safe="")
    tags_api = f"https://{_GITLAB_HOST}/api/v4/projects/{encoded_project}/repository/tags?per_page=15"
    try:
        tags_raw = client.request("GET", tags_api).json()
    except (FetchError, ValueError, TypeError, AttributeError):
        return
    if not isinstance(tags_raw, list) or not tags_raw:
        return
    tags = [entry for entry in tags_raw if isinstance(entry, dict) and isinstance(entry.get("name"), str)]
    by_name: dict[str, tuple[int, dict]] = {}
    for idx, entry in enumerate(tags):
        by_name.setdefault(entry["name"], (idx, entry))
    compare_calls = 0
    content_limit = int(settings.get("content_chars") or _MAX_TAG_ENRICHED_CHARS)

    for item in items:
        item_url = str(item.get("url") or "")
        url_parts = urlsplit(item_url)
        if url_parts.scheme.lower() != "https" or (url_parts.hostname or "").lower() != _GITLAB_HOST:
            continue
        if "/-/tags/" in url_parts.path:
            item_project, raw_ref = url_parts.path.split("/-/tags/", 1)
            if item_project.strip("/") != project_path:
                continue
            tag_ref = unquote(raw_ref.rstrip("/"))
            matched = by_name.get(tag_ref)
        else:
            norm_path = url_parts.path.strip("/")
            if norm_path != project_path and not norm_path.startswith(f"{project_path}/"):
                continue
            matched = by_name.get(str(item.get("title") or "").strip())
        if matched is None:
            continue
        tag_idx, tag_obj = matched
        tag_name = tag_obj["name"]
        item_title = str(item.get("title") or "")
        rel_notes = _strip_trivial_tag_lines(_clean_release_description(tag_obj), tag_name, item_title)
        clean_msg = _strip_trivial_tag_lines(_clean_tag_message(tag_obj.get("message")), tag_name, item_title)

        parts = [
            p for p in (
                rel_notes if _is_substantive_tag_message(rel_notes, tag_name, item_title) else "",
                clean_msg if clean_msg != rel_notes and _is_substantive_tag_message(clean_msg, tag_name, item_title) else "",
            )
            if p
        ]
        if parts:
            header = f"Release notes for {tag_name}:"
            bounded = _bound_enriched_content(header, "\n\n".join(parts), content_limit)
            if bounded and _is_substantive_tag_message(bounded.removeprefix(header).strip(), tag_name, item_title):
                item["content"] = bounded
                item["tag_enriched"] = True
                item["tag_enrichment_kind"] = "release_notes"
                continue

        if compare_calls >= _MAX_TAG_COMPARE_CALLS:
            continue
        prev_name = _preceding_tag_name(tags, tag_idx, tag_name)
        if not prev_name:
            continue
        compare_url = (
            f"https://{_GITLAB_HOST}/api/v4/projects/{encoded_project}/repository/compare"
            f"?from={quote(prev_name, safe='')}&to={quote(tag_name, safe='')}"
        )
        compare_calls += 1
        try:
            cmp_data = client.request("GET", compare_url).json()
        except (FetchError, ValueError, TypeError, AttributeError):
            continue
        if not isinstance(cmp_data, dict):
            continue
        commits = cmp_data.get("commits")
        if not isinstance(commits, list):
            continue
        titles: list[str] = []
        seen_titles: set[str] = set()
        for commit in commits:
            if not isinstance(commit, dict) or not isinstance(commit.get("title"), str):
                continue
            title = " ".join(commit["title"].split())
            if not title or title in seen_titles:
                continue
            seen_titles.add(title)
            titles.append(title)
            if len(titles) >= _MAX_TAG_COMPARE_COMMITS:
                break
        if not titles:
            continue
        shortlog = "\n".join(f"- {title}" for title in titles)
        bounded = _bound_enriched_content(
            f"Release commits ({prev_name}..{tag_name}):", shortlog, content_limit,
        )
        if bounded:
            item["content"] = bounded
            item["tag_enriched"] = True
            item["tag_enrichment_kind"] = "compare"


def _feed(
    client: HttpClient,
    source: dict,
    url: str,
    state: dict,
    settings: dict,
    started: str,
    *,
    request_url: str | None = None,
) -> dict:
    response = fetch_cached(client, url, state, request_url=request_url)
    if response.status == 304:
        return cached_result(url, response, state)
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
            and entry.get("author") == raw
            and isinstance(entry.get("authors"), list)
            and len(entry["authors"]) == 1
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
        alternate_href = next(
            (
                canon
                for link_obj in (entry.get("links") or ())
                if isinstance(link_obj, dict)
                and link_obj.get("rel", "alternate") == "alternate"
                and str(link_obj.get("type") if "type" in link_obj else "text/html").partition(";")[0].strip().lower()
                in {"text/html", "application/xhtml+xml", "html", "xhtml"}
                and (canon := safe_canonical_url(link_obj.get("href")))
            ),
            None,
        )
        has_alternate = alternate_href is not None
        try:
            entry_url = alternate_href if has_alternate else canonical_url(entry.get("link", ""))
        except ValueError:
            continue
        content_parts = entry.get("content") or []
        content = content_parts[0].get("value", "") if content_parts else entry.get("summary", "")
        if discourse_feed and isinstance(content, str):
            content = _without_discourse_footer(content, entry_url)
        text = plain_text(
            content,
            settings["content_chars"],
            mark_blockquotes=urlsplit(entry_url).hostname == LIST_ARCHIVE_HOST,
        )
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
                source, alternate_href if has_alternate else entry.get("link", ""), title, text, published, updated,
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
            item["sender_domain"] = _hyperkitty_address(rss_authors[index]).lower().partition("@")[2]
        # Some Atom archives omit alternate links and reuse an ID for distinct
        # events. Do not silently choose one event when that fallback is ambiguous.
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
    if source.get("kind") == "tag" and items:
        _enrich_gitlab_tags(client, url, items, settings)
    return cached_result(url, response, state, items, skipped=skipped)


def _gitlab(
    client: HttpClient,
    source: dict,
    url: str,
    state: dict,
    settings: dict,
    started: str,
    *,
    request_url: str | None = None,
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
    parsed = urlsplit(request_url or url)
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
    upper = parse_utc(started)
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
        page_error = None
        stamps: list[datetime] = []
        valid_records: list[dict] = []
        if records:
            try:
                floor = parse_utc(params["updated_after"])
            except (TypeError, ValueError):
                raise CollectionError("GitLab returned an invalid timestamp", items, resume) from None
            for record in records:
                try:
                    stamp = parse_utc(record.get("updated_at"))
                except (TypeError, ValueError):
                    page_error = "GitLab returned an invalid timestamp"
                    continue
                stamps.append(stamp)
                if floor <= stamp <= upper:
                    valid_records.append(record)
            if page_error is None:
                if stamps[0] < floor or any(b < a for a, b in zip(stamps, stamps[1:])):
                    page_error = "GitLab returned out-of-order timestamps"
                elif stamps[-1] > upper:
                    page_error = "GitLab returned an out-of-range timestamp"
        for record in valid_records:
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
                    tor_core_users=settings.get("tor_core_gitlab_users"),
                )
            except (KeyError, ValueError, TypeError):
                continue
            # Closing is a dated development of an issue; an invalid date is left out, never the item.
            closed = timestamp(record.get("closed_at"), "") if source["kind"] == "gitlab_issue" and item["upstream_state"] == "closed" else ""
            if closed:
                item["closed_at"] = min(closed, started)
            if item["title"]:
                items.append(item)
        if page_error is not None:
            raise CollectionError(page_error, items, resume)
        if len(records) < page_size:
            return {"items": items, "url": url, "watermark": after(-settings["overlap_seconds"], started)}
        moved = stamps[-1] > floor
        # A full page that shares one timestamp is a tie group: step through it by page.
        params.update({"updated_after": records[-1]["updated_at"], "page": "1"} if moved else {"page": str(int(params["page"]) + 1)})
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
    last_error = ""
    partial: list[dict] = []
    watermark = None
    catching_up = False
    request_urls = source.get("_request_urls") or {}
    for url in [source["url"], *source["fallback_urls"]]:
        request_url = request_urls.get(url, url)
        try:
            if source["kind"] in {"feed", "tag"}:
                return _feed(client, source, url, state, settings, started, request_url=request_url)
            if source["kind"] == "metrics_timeline":
                from .timeline import collect_timeline
                return collect_timeline(client, source, url, state, settings, started, request_url=request_url)
            return _gitlab(client, source, url, state, settings, started, request_url=request_url)
        except CollectionError as exc:
            last_error = str(exc)
            partial.extend(exc.items)
            if exc.watermark:
                watermark = exc.watermark
            catching_up = exc.catching_up
            if exc.catching_up or getattr(client, "deadline_reached", False):
                # Another mirror cannot make this bounded scan finish faster.
                break
        except FetchError as exc:
            # Transport error strings are sanitized; do not expose request headers/body.
            last_error = str(exc)
            if getattr(client, "deadline_reached", False):
                break
    raise CollectionError(last_error, partial, watermark, catching_up=catching_up)
