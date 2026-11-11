"""Read the maintained Metrics Timeline data without executing upstream code."""

from __future__ import annotations

import base64
import binascii
import re
from datetime import datetime, timezone
from urllib.parse import quote, unquote, urlsplit, urlunsplit

from .collect import CollectionError, _get, _item
from .util import after, digest, format_utc, parse_utc, plain_text


_COLUMNS = ("start date", "end date", "places", "protocols", "description", "links", "?")
_ROW = re.compile(r"\|(?:(?:\\.|[^\\|])*\|){7}")
_CELL = re.compile(r"((?:\\.|[^\\|])*)\|")


def _cells(line: str) -> list[str]:
    """Split on unescaped pipes (honoring backslash parity), then undo Markdown escapes."""
    line = line.strip()
    if not _ROW.fullmatch(line):
        raise ValueError("Timeline rows must have seven pipe-terminated cells")
    return [re.sub(r"\\([!-/:-@\[-`{-~])", r"\1", cell).strip() for cell in _CELL.findall(line, 1)]


def _date(value: str) -> str:
    if not re.fullmatch(r"~?\d{4}-\d{2}-\d{2}(?: \d{2}:\d{2}(?::\d{2})?)?", value):
        raise ValueError("Invalid timeline event date")
    # Unspecified timezones are read as UTC; the raw value stays in the item context.
    return format_utc(datetime.fromisoformat(value.removeprefix("~")).replace(tzinfo=timezone.utc))


def _rows(text: str):
    lines = text.split("\n")  # GitLab numbers lines by LF only.
    headings = [index for index, line in enumerate(lines) if line.strip() == "## Timeline"]
    if len(headings) != 1:
        raise ValueError("Expected exactly one Timeline section")
    rows = ((index + 1, line) for index, line in enumerate(lines) if index > headings[0] and line.strip())
    if tuple(_cells(next(rows, (0, ""))[1])) != _COLUMNS:
        raise ValueError("Unexpected timeline columns")
    if any(not re.fullmatch(r":?-{3,}:?", cell) for cell in _cells(next(rows, (0, ""))[1])):
        raise ValueError("Invalid timeline table separator")
    for line_number, line in rows:
        if line.lstrip().startswith("#"):
            break
        yield line_number, _cells(line)


def collect_timeline(client, source: dict, url: str, state: dict, settings: dict, started: str) -> dict:
    """Collect a validated repository snapshot; only recent event dates qualify.

    A recent start or explicit end qualifies a row and dates its item. Neither an
    ongoing marker nor a repository commit/fetch timestamp makes a historical row new.
    """
    response = _get(client, url, state)
    if response.status == 304:
        return {"items": [], "url": url, "etag": state.get("etag"), "last_modified": state.get("last_modified")}
    try:
        api = urlsplit(url)
        match = re.fullmatch(r"(/api/v4/projects/[^/]+)/repository/files/([^/]+)", api.path)
        record = response.json()
        if not match or not isinstance(record, dict) or record.get("encoding") != "base64":
            raise ValueError("Expected GitLab repository-file metadata with base64 content")
        project, path, revision = match[1], unquote(match[2]), record.get("last_commit_id")
        if record.get("file_path") != path or not re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", str(revision)):
            raise ValueError("Invalid timeline file path or revision")
        text = base64.b64decode(record["content"], validate=True).decode("utf-8")
        commit = client.request("GET", urlunsplit((api.scheme, api.netloc, project + "/repository/commits/" + revision, "", ""))).json()
        if not isinstance(commit, dict) or commit.get("id") != revision:
            raise ValueError("Timeline commit metadata does not match its file revision")
        # Revision time orders corrections; a skewed committer clock cannot postdate items.
        revision_time = min(format_utc(parse_utc(commit.get("committed_date"))), started)
        repository = source["website_url"].rstrip("/")
        cutoff = after(-settings["lookback_days"] * 86400, started)
        identities = {}
        for line, row in _rows(text):
            start, end, places, protocols, description, references, unknown = row
            published = _date(start)
            updated = _date(end) if end not in {"", "ongoing"} else published
            countries, transports = sorted(set(places.lower().split())), sorted(set(protocols.lower().split()))
            entry_id = digest([repository, path, published, countries, transports])
            fingerprint = digest([start, end, countries, transports, description, references, unknown])
            start_recent = cutoff <= published <= started
            recent = start_recent or cutoff <= updated <= started
            if recent and updated < published:
                raise ValueError("Invalid timeline event range")
            previous = identities.get(entry_id)
            if previous:
                previous["ambiguous"] |= fingerprint != previous["fingerprint"]
                previous["recent"] |= recent
                continue
            item = None
            if recent:
                context = (
                    "Metrics Timeline entry. Event dates are not publication timestamps; "
                    "date-only values and unspecified timezones are normalized only for ordering. "
                    "Repository revision time is not event time. "
                    "An old ongoing marker is not proof that conditions continue today.\n"
                    f"Start date as supplied: {start}\nEnd date as supplied: {end or 'point event'}\n"
                    f"Places: {places or 'not specified'}\nProtocols: {protocols or 'not specified'}\n"
                    f"Unknown cause: {'Yes; preserve this uncertainty' if unknown else 'not marked unknown'}\n"
                    f"Description: {description}\nReferences: {references or 'none listed'}"
                )
                citation = repository + "/-/blob/" + revision + "/" + quote(path, safe="/") + "?plain=1#L" + str(line)
                item = _item(source, citation, description, plain_text(context, settings["content_chars"]),
                             published if start_recent else updated, revision_time)
                if not item["title"]:
                    raise ValueError("Timeline event has no readable description")
                item["source_entry_id"] = entry_id
            identities[entry_id] = {"fingerprint": fingerprint, "recent": recent, "ambiguous": False, "item": item}
    except (ValueError, TypeError, KeyError, UnicodeError, binascii.Error) as exc:
        raise CollectionError("Invalid Metrics Timeline snapshot: " + str(exc)) from None
    items = [entry["item"] for entry in identities.values() if entry["item"] and not entry["ambiguous"]]
    if any(entry["ambiguous"] and entry["recent"] for entry in identities.values()):
        raise CollectionError("Ambiguous recent timeline identities skipped", items, catching_up=True)
    return {"items": items, "url": url, "etag": response.headers.get("etag"), "last_modified": response.headers.get("last-modified")}
