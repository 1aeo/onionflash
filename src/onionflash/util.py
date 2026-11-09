"""Small shared helpers; untrusted source content stays plain text."""

from __future__ import annotations

import hashlib
import html
import ipaddress
import json
import re
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

UTC = timezone.utc


class BudgetExceeded(Exception):
    """Control-flow deadline, deliberately not an OSError/network retry error."""


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def timestamp(value: str | None, fallback: str | None = None) -> str:
    """Normalize a supplied aware timestamp, without inventing changing dates."""
    if isinstance(value, str) and value:
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if dt.tzinfo is not None:
                return (
                    dt.astimezone(UTC)
                    .isoformat(timespec="seconds")
                    .replace("+00:00", "Z")
                )
        except (ValueError, TypeError):
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
    text = "".join(parser.parts)
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
        or any(ord(c) < 33 for c in value)
    ):
        raise ValueError("Invalid source URL")
    parsed = urlsplit(html.unescape(value))
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
    return "url:" + digest(item["url"])
