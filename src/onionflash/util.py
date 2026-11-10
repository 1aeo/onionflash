"""Small shared helpers; untrusted source content stays plain text."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

UTC = timezone.utc


class BudgetExceeded(Exception):
    """Control-flow deadline, deliberately not an OSError/network retry error."""


def now_iso() -> str:
    return format_utc(datetime.now(UTC))


def parse_utc(value: str) -> datetime:
    """Read an aware ISO timestamp and normalize its timezone to UTC."""
    try:
        if not isinstance(value, str):
            raise ValueError
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if moment.tzinfo is None:
            raise ValueError
        return moment.astimezone(UTC)
    except (ValueError, TypeError, OverflowError):
        raise ValueError("Missing or invalid timezone-aware timestamp") from None


def format_utc(moment: datetime) -> str:
    if moment.tzinfo is None:
        raise ValueError("Missing or invalid timezone-aware timestamp")
    return moment.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def after(seconds: float, start: str | None = None) -> str:
    return format_utc(parse_utc(start or now_iso()) + timedelta(seconds=seconds))


def backoff_seconds(attempt: int, base: float, cap: float) -> float:
    """Persisted cooldown for a one-based attempt count; no sleeping here."""
    return min(cap, base * 2 ** min(max(attempt - 1, 0), 20))


def timestamp(value: str | None, fallback: str | None = None) -> str:
    """Normalize a supplied aware timestamp, without inventing changing dates."""
    try:
        return format_utc(parse_utc(value))
    except ValueError:
        pass
    if fallback is not None:
        return fallback
    raise ValueError("Missing or invalid timezone-aware timestamp")


def digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, ensure_ascii=False, separators=(",", ":")
        ).encode()
    ).hexdigest()


class _TextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.hidden = 0

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag in {"script", "style", "noscript", "template"}:
            self.hidden += 1
        elif tag in {"p", "br", "div", "li", "h1", "h2", "h3", "pre"}:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript", "template"}:
            self.hidden = max(0, self.hidden - 1)
        elif tag in {"p", "div", "li", "pre"}:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self.hidden:
            self.parts.append(data)


def plain_text(value: object, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    parser = _TextParser()
    parser.feed(value[: limit * 4])
    pending, parts, hidden = parser.rawdata, len(parser.parts), parser.hidden
    parser.close()
    # Some Python versions silently discard a final incomplete tag such as
    # '<word', even on close(). Keep that literal text, not comments or scripts.
    if not hidden and len(parser.parts) == parts and re.fullmatch(r"</?[A-Za-z][^>]*", pending):
        parser.parts.append(pending)
    text = "".join(parser.parts).replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[\ud800-\udfff]", "\ufffd", text)
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    return re.sub(r"[ \t]+", " ", re.sub(r"\n{3,}", "\n\n", text)).strip()[:limit]


def canonical_url(value: str) -> str:
    """Validate public citation syntax, and unify known GitLab issue aliases.

    Fetch-time DNS and connection checks are separately enforced by transport.
    """
    if (
        not isinstance(value, str)
        or len(value) > 4096
        or "\\" in value
        or any(ord(c) < 33 or ord(c) == 127 for c in value)
    ):
        raise ValueError("Invalid source URL")
    value.encode("utf-8")  # Reject invalid Unicode URLs before persistence.
    parsed = urlsplit(value)
    host = (parsed.hostname or "").lower().rstrip(".")
    if (
        parsed.scheme != "https"
        or not host
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError("Source URLs must be public HTTPS URLs without credentials")
    if (
        host == "localhost"
        or host.endswith((".localhost", ".local", ".internal"))
        or "." not in host
    ):
        raise ValueError("Local source URL is not allowed")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if all(
            re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)", part) for part in host.split(".")
        ):
            raise ValueError("Ambiguous numeric source host is not allowed")
    else:
        if not address.is_global or address.is_multicast:
            raise ValueError("Private source URL is not allowed")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid URL port") from exc
    authority = f"[{host}]" if ":" in host else host
    if port and port != 443:
        authority += f":{port}"
    path = parsed.path or "/"
    if host == "gitlab.torproject.org":
        path = re.sub(r"/-/issues/(\d+)(?=/|$)", r"/-/work_items/\1", path)
    query = urlencode(
        [
            (k, v)
            for k, v in parse_qsl(parsed.query, keep_blank_values=True)
            if not k.lower().startswith("utm_")
        ]
    )
    return urlunsplit(("https", authority, path, query, parsed.fragment))


def item_identity(item: dict) -> str:
    """Keep repository entries stable while their immutable citation changes."""
    if item.get("kind") == "metrics_timeline":
        identity = item.get("source_entry_id")
        if not isinstance(identity, str) or not re.fullmatch(r"[a-f0-9]{64}", identity):
            raise ValueError("Timeline item needs a stable source entry identity")
        return "timeline:" + identity
    return item["url"]


def item_cluster(item: dict) -> str:
    """Only merge strong matches: canonical identity, identical body, release version.

    Semantic similarity alone never merges independent incidents.
    """
    title = item["title"].lower()
    product = item.get("product", "network")
    if product == "network":
        if re.search(r"\btor browser\b", title):
            product = "tor-browser"
        elif re.search(r"\barti\b", title):
            product = "arti"
        elif re.search(r"\btor\b", title):
            product = "tor"
    if item.get("kind") == "tag" or re.search(r"\breleas(?:e|ed|ing)\b", title):
        match = re.search(
            r"\b(?:tor[- ]|arti[- ]v?|version\s+)?(\d+\.\d+\.\d+(?:\.\d+)?(?:[-.](?:alpha|beta|rc)\d*)?)\b",
            title,
        )
        if match and product in {"tor", "arti", "tor-browser"}:
            return f"release:{product}:{match.group(1)}"
    body = re.sub(r"\s+", " ", item["content"]).strip().lower()
    if len(body) >= 180 and item.get("kind") in {"gitlab_issue", "gitlab_mr"}:
        clean_title = re.sub(r"\s+", " ", title).strip()
        clean_title = re.sub(
            r"^(?:dirauth|authority|security|tor|arti):\s*", "", clean_title
        )
        return "body:" + digest([clean_title, body])
    return "url:" + digest(item_identity(item))
