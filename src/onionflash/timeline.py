"""Read the maintained Metrics Timeline data without executing upstream code."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from datetime import datetime, timezone
from pathlib import PurePosixPath
from urllib.parse import quote, unquote, urlsplit, urlunsplit

from .util import after, canonical_url, digest, format_utc, parse_utc, plain_text


_COLUMNS = ("start date", "end date", "places", "protocols", "description", "links", "?")
_ESCAPABLE = frozenset("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")


def _cells(line: str) -> list[str]:
    """Split pipes, honoring Markdown escapes including backslash parity."""
    line = line.strip()
    if not line.startswith("|"):
        raise ValueError("Expected a timeline table row")
    cells, current = [], []
    index = 1
    while index < len(line):
        char = line[index]
        if char == "\\" and index + 1 < len(line) and line[index + 1] in _ESCAPABLE:
            current.append(line[index + 1])
            index += 2
            continue
        if char == "|":
            cells.append("".join(current).strip())
            current = []
        else:
            current.append(char)
        index += 1
    if current or len(cells) != 7 or not line.endswith("|"):
        raise ValueError("Timeline rows must have seven pipe-terminated cells")
    return cells


def _date(value: str) -> str:
    if not re.fullmatch(r"~?\d{4}-\d{2}-\d{2}(?: \d{2}:\d{2}(?::\d{2})?)?", value):
        raise ValueError("Invalid timeline event date")
    # These are event-date sort keys, not asserted publication times. The raw
    # precision and unspecified timezone remain explicit in the item context.
    return format_utc(datetime.fromisoformat(value.removeprefix("~")).replace(tzinfo=timezone.utc))


def _scope(value: str, *, places: bool = False) -> list[str]:
    tokens = value.split()
    pattern = r"[A-Za-z]{2}" if places else r"[A-Za-z0-9][A-Za-z0-9_-]{0,39}"
    if len(tokens) > 100 or any(not re.fullmatch(pattern, token) for token in tokens):
        raise ValueError("Invalid timeline scope")
    return sorted({token.lower() for token in tokens})


def _document(record: object) -> tuple[str, str, str]:
    if not isinstance(record, dict) or record.get("encoding") != "base64":
        raise ValueError("Expected GitLab file metadata with base64 content")
    size, content = record.get("size"), record.get("content")
    if type(size) is not int or size <= 0 or not isinstance(content, str):
        raise ValueError("Invalid timeline file size or content")
    checksum, revision, path = (record.get(key) for key in ("content_sha256", "last_commit_id", "file_path"))
    if not isinstance(checksum, str) or not re.fullmatch(r"[0-9a-f]{64}", checksum):
        raise ValueError("Invalid timeline content hash")
    if not isinstance(revision, str) or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", revision):
        raise ValueError("Invalid timeline revision")
    if (
        not isinstance(path, str) or not path or len(path) > 1024
        or path.startswith("/") or "\\" in path or any(ord(c) < 33 for c in path)
        or path != str(PurePosixPath(path))
        or any(part in {".", ".."} for part in unquote(path).split("/"))
    ):
        raise ValueError("Invalid timeline file path")
    raw = base64.b64decode(content, validate=True)
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != checksum:
        raise ValueError("Timeline file size or content hash mismatch")
    return raw.decode("utf-8"), revision, path


def _rows(text: str, limit: int):
    lines = text.splitlines()
    headings = [index for index, line in enumerate(lines) if line.strip() == "## Timeline"]
    if len(headings) != 1:
        raise ValueError("Expected exactly one Timeline section")
    rows = ((index + 1, line) for index, line in enumerate(lines) if index > headings[0] and line.strip())
    _, header = next(rows, (0, ""))
    if tuple(_cells(header)) != _COLUMNS:
        raise ValueError("Unexpected timeline columns")
    _, separator = next(rows, (0, ""))
    if any(not re.fullmatch(r":?-{3,}:?", cell) for cell in _cells(separator)):
        raise ValueError("Invalid timeline table separator")
    count = 0
    for line_number, line in rows:
        if line.lstrip().startswith("#"):
            break
        count += 1
        if count > limit:
            raise ValueError("Timeline row limit reached; increase source max_items")
        yield line_number, _cells(line)
    if not count:
        raise ValueError("Timeline table has no events")


def _revision_time(client, url: str, revision: str, started: str) -> str:
    parsed = urlsplit(url)
    project = re.fullmatch(r"(/api/v4/projects/[^/]+)/repository/files/.+", parsed.path)
    if not project:
        raise ValueError("Expected a GitLab repository-file API URL")
    commit_url = urlunsplit((parsed.scheme, parsed.netloc, project[1] + "/repository/commits/" + revision, "", ""))
    record = client.request("GET", commit_url).json()
    if not isinstance(record, dict) or record.get("id") != revision:
        raise ValueError("Timeline commit metadata does not match its file revision")
    stamp = format_utc(parse_utc(record.get("committed_date")))
    if stamp > started:
        raise ValueError("Timeline repository revision is future-dated")
    return stamp


def collect_timeline(client, source: dict, state: dict, settings: dict, started: str) -> dict:
    """Collect a validated repository snapshot; only recent event dates qualify.

    A recent explicit end date can qualify an older range. Neither an ongoing
    marker nor a repository commit/fetch timestamp makes a historical row new.
    """
    from .collect import CollectionError, _item

    try:
        url = canonical_url(source["url"])
    except (KeyError, ValueError, TypeError, UnicodeError):
        raise CollectionError("Invalid Metrics Timeline source URL") from None
    headers = {}
    if state.get("active_url") == url:
        if state.get("etag"):
            headers["If-None-Match"] = state["etag"]
        if state.get("last_modified"):
            headers["If-Modified-Since"] = state["last_modified"]
    response = client.request("GET", url, headers=headers)
    if response.status == 304:
        if not headers:
            raise CollectionError("Unexpected unconditioned Metrics Timeline 304 response")
        return {"items": [], "url": url, "etag": state.get("etag"), "last_modified": state.get("last_modified")}
    try:
        repository = canonical_url(source["website_url"]).rstrip("/")
        parsed_repository = urlsplit(repository)
        if parsed_repository.query or parsed_repository.fragment or any(part in {".", ".."} for part in unquote(parsed_repository.path).split("/")):
            raise ValueError("Timeline website_url must be a clean repository URL")
        text, revision, path = _document(response.json())
        now = format_utc(parse_utc(started))
        revision_time = _revision_time(client, url, revision, now)
        cutoff = after(-settings["lookback_days"] * 86400, now)
        identities = {}
        for line, row in _rows(text, source["max_items"]):
            start, end, places, protocols, description, references, unknown = row
            published = _date(start)
            updated = _date(end) if end not in {"", "ongoing"} else published
            if updated < published or unknown not in {"", "X"} or not description:
                raise ValueError("Invalid timeline event range, unknown marker or description")
            countries, transports = _scope(places, places=True), _scope(protocols)
            entry_id = digest([repository, path, published, countries, transports])
            fingerprint = digest([start, end, countries, transports, description, references, unknown])
            recent = cutoff <= updated <= now and published <= now
            previous = identities.get(entry_id)
            if previous:
                previous["ambiguous"] |= fingerprint != previous["fingerprint"]
                previous["recent"] |= recent
                continue
            item = None
            if recent:
                context = (
                    "Historical Metrics Timeline entry. Event dates are not publication timestamps; "
                    "date-only values and unspecified timezones are normalized only for ordering. "
                    "Repository revision time is not event time. "
                    "An old ongoing marker is not proof that conditions continue today.\n"
                    f"Start date as supplied: {start}\nEnd date as supplied: {end or 'point event'}\n"
                    f"Places: {places or 'not specified'}\nProtocols: {protocols or 'not specified'}\n"
                    f"Unknown cause: {'Yes; preserve this uncertainty' if unknown == 'X' else 'not marked unknown'}\n"
                    f"Description: {description}\nReferences: {references or 'none listed'}"
                )
                citation = repository + "/-/blob/" + revision + "/" + quote(path, safe="/") + "?plain=1#L" + str(line)
                item = _item(source, citation, description, plain_text(context, settings["content_chars"]), published, max(published, revision_time))
                if not item["title"]:
                    raise ValueError("Timeline event has no readable description")
                item["source_entry_id"] = entry_id
            identities[entry_id] = {"fingerprint": fingerprint, "recent": recent, "ambiguous": False, "item": item}
    except (ValueError, TypeError, UnicodeError, binascii.Error) as exc:
        raise CollectionError("Invalid Metrics Timeline snapshot: " + str(exc)) from None
    items = [entry["item"] for entry in identities.values() if entry["item"] and not entry["ambiguous"]]
    if any(entry["ambiguous"] and entry["recent"] for entry in identities.values()):
        raise CollectionError("Ambiguous recent timeline identities skipped", items, catching_up=True)
    return {"items": items, "url": url, "etag": response.headers.get("etag"), "last_modified": response.headers.get("last-modified")}
