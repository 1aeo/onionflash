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


MAX_SAVED_DEPTH = 64  # the app's own records nest a few levels; deeper is damage the CLI could not print


def _reject_constant(_: str):
    raise ValueError("Non-finite JSON constant")


def saved_object(value):
    """A saved JSON object read as bytes, or None when it is NULL or damaged, so one bad row cannot
    stop a run or hide the others. Decoding is strict UTF-8, as when the pipeline reads the row, not
    json.loads' lenient bytes mode, and non-finite numbers or an escaped lone surrogate, which no
    saved text can hold and the writer refuses, are damage too."""
    try:
        value = json.loads(str(value, "utf-8"), parse_constant=_reject_constant)
        json.dumps(value, ensure_ascii=False, allow_nan=False).encode()
    except (TypeError, ValueError, RecursionError):
        return None
    return value if isinstance(value, dict) and _within(value, MAX_SAVED_DEPTH) else None


def _within(value, depth):
    if isinstance(value, (dict, list)):
        return depth > 0 and all(_within(child, depth - 1) for child in (value.values() if isinstance(value, dict) else value))
    return True


def digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, ensure_ascii=False, separators=(",", ":")
        ).encode()
    ).hexdigest()


_TYPOGRAPHY = str.maketrans({"\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"', "\u2013": "-", "\u2014": "-"})


def normalize_evidence(text: str) -> str:
    """Use identical quote matching for validation and deterministic citations."""
    return " ".join(text.translate(_TYPOGRAPHY).split()).casefold()


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


def plain_text(value: object, limit: int, *, html: bool = True) -> str:
    """Normalize untrusted text; with html=True, also strip markup.

    Plain-text fields (such as GitLab titles) keep literal text like "Vec<u8>".
    """
    if not isinstance(value, str):
        return ""
    if not html:
        text = value[: limit * 4].replace("\r\n", "\n").replace("\r", "\n")
        text = re.sub(r"[\ud800-\udfff]", "\ufffd", text)
        text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
        return re.sub(r"[ \t]+", " ", re.sub(r"\n{3,}", "\n\n", text)).strip()[:limit]
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
        # XML feeds cannot carry U+FFFE or U+FFFF, which draft text also rejects.
        or any(ord(c) < 33 or ord(c) == 127 or c in "\ufffe\uffff" for c in value)
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
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
        raise ValueError("Local source URL is not allowed")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if "." not in host:
            raise ValueError("Local source URL is not allowed")
        if all(
            re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)", part) for part in host.split(".")
        ):
            raise ValueError("Ambiguous numeric source host is not allowed")
    else:
        from .transport import AddressPolicy

        if not AddressPolicy().permits(str(address)):
            raise ValueError("Private source URL is not allowed")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid URL port") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Invalid URL port")
    authority = f"[{host}]" if ":" in host else host
    if port is not None and port != 443:
        authority += f":{port}"
    path = parsed.path or "/"
    if host == "gitlab.torproject.org":
        path = re.sub(r"/-/issues/(\d+)/?\Z", r"/-/work_items/\1", path)
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
    return "timeline:" + item["source_entry_id"] if item.get("kind") == "metrics_timeline" else item["url"]


_PRODUCT_NAMES = {"tor": "tor", "arti": "arti", "tor-browser": r"tor[- ]browser"}
_VERSION = re.compile(r"\d+\.\d+(?:\.\d+){0,2}(?:[-.]?(?:alpha|beta|rc|a)\.?\d*)?")
_RELEASE_QUALIFIERS = r"(?:(?:new|stable|alpha|beta|security|bugfix|release|version)\s+)*"
_RELEASE_AFTER = re.compile(r"\s+(?:is\s+)?(?:now\s+)?available\b")
_RELEASE_EOL = re.compile(r"\b(?:end[- ]of[- ]life|eol|out of support|no longer supported)\b")
_GITLAB_OWN = re.compile(r"^(https://[^/?#]+)/(.+?)/-/(?:issues|work_items|merge_requests|tags|blob)/\S+")
_GITLAB_URL_REF = re.compile(r"^(https://[^/?#]+)/(.+?)/-/(issues|work_items|merge_requests)/(\d+)(?:/|$)")
_GITLAB_SHORT_REF = re.compile(r"^(?:([a-z0-9_.-]+(?:/[a-z0-9_.-]+)+))?([#!])(\d+)$", re.I)
_CLOSING_SPAN = re.compile(
    r"\b(?:clos(?:e|es|ed|ing)|fix(?:|es|ed|ing)|resolv(?:e|es|ed|ing))\s*:?\s+("
    r"(?:https://[^\s<>()\[\]\"']+|(?<![\w/#!])(?:[a-z0-9_.-]+(?:/[a-z0-9_.-]+)+)?[#!]\d+\b)"
    r"(?:\s*(?:,|and)\s*(?:https://[^\s<>()\[\]\"']+|(?<![\w/#!])(?:[a-z0-9_.-]+(?:/[a-z0-9_.-]+)+)?[#!]\d+\b))*)",
    re.I,
)
_ANY_REF = re.compile(
    r"(?:https://[^\s<>()\[\]\"']+|(?<![\w/#!])(?:[a-z0-9_.-]+(?:/[a-z0-9_.-]+)+)?[#!]\d+\b)",
    re.I,
)
_RELEASE_MENTION = re.compile(
    r"\b(tor[- ]browser|arti|tor)[- ](?:v|(?:(?:new|stable|alpha|beta|security|bugfix|release|version)\s+)*)?(\d+\.\d+(?:[\w.-]*\w)?)(?!(?:\w|\.\w))",
    re.I,
)


def item_cluster(item: dict) -> str:
    """Only merge strong matches: canonical identity, identical body, release version.

    Semantic similarity alone never merges independent incidents.
    """
    title = item["title"].lower()
    product = item.get("product", "network")
    if product == "network":
        if re.search(r"\btor[- ]browser\b", title):
            product = "tor-browser"
        elif re.search(r"\barti\b", title):
            product = "arti"
        elif re.search(r"\btor\b", title):
            product = "tor"
    if product in _PRODUCT_NAMES:
        # Only the first version in the title, and only when it follows the product
        # name, directly or after release qualifiers ("Tor Browser 16.0", "arti-v2.8.0",
        # "Tor stable release 0.4.8.19"); titles such as "Tails 7.16 ... Tor Browser
        # 16.0" keep their own identity, and so do delay and end-of-life notices.
        match = re.search(r"(?<![\w.])v?(\d+\.\d+(?:[\w.-]*\w)?)", title)
        if (
            match
            and _VERSION.fullmatch(match.group(1))
            and (
                item.get("kind") == "tag"
                or re.search(r"\breleas(?:e|ed|ing)\b", title)
                or _RELEASE_AFTER.match(title[match.end() :])
            )
            and re.search(r"\b" + _PRODUCT_NAMES[product] + r"[- ]" + _RELEASE_QUALIFIERS + "$", title[: match.start()])
            and (re.search(r"\breleased\b", title) or not re.search(r"\b(?:delayed|postponed)\b", title))
            and not _RELEASE_EOL.search(title)
        ):
            return f"release:{product}:{match.group(1)}"
    body = re.sub(r"\s+", " ", item["content"]).strip().lower()
    if len(body) >= 180 and item.get("kind") in {"gitlab_issue", "gitlab_mr"}:
        clean_title = re.sub(r"\s+", " ", title).strip()
        clean_title = re.sub(
            r"^(?:dirauth|authority|security|tor|arti):\s*", "", clean_title
        )
        return "body:" + digest([clean_title, body])
    return "url:" + digest(item_identity(item))


def gitlab_refs(item: dict) -> tuple[list[str], list[str]]:
    """Extract canonical closing and mentioned GitLab issue and merge-request URLs."""
    own_url = str(item.get("url") or "")
    own_match = _GITLAB_OWN.match(own_url)
    origin = own_match.group(1) if own_match else "https://gitlab.torproject.org"
    own_project = own_match.group(2) if own_match else None

    def normalize_ref(token: str) -> str | None:
        cleaned = token.rstrip(".,;:!?)>]").split("#", 1)[0].split("?", 1)[0] if token.startswith("https://") else token
        if cleaned.startswith("https://"):
            match = _GITLAB_URL_REF.match(cleaned)
            if not match:
                return None
            ref_origin, project, kind_seg, number = match.groups()
            if ref_origin not in {"https://gitlab.torproject.org", origin}:
                return None
            seg = "work_items" if kind_seg in {"issues", "work_items"} else "merge_requests"
            raw = f"{ref_origin}/{project.lower()}/-/{seg}/{number}"
            if ref_origin != "https://gitlab.torproject.org":
                return raw
            try:
                return canonical_url(raw)
            except ValueError:
                return None
        short = _GITLAB_SHORT_REF.match(token)
        if not short:
            return None
        project = (short.group(1) or own_project or "").lower() or None
        if not project:
            return None
        seg = "work_items" if short.group(2) == "#" else "merge_requests"
        raw = f"{origin}/{project}/-/{seg}/{short.group(3)}"
        if origin != "https://gitlab.torproject.org":
            return raw
        try:
            return canonical_url(raw)
        except ValueError:
            return None

    own_canonical = normalize_ref(own_url) if own_url.startswith("https://") else None
    closing, mentioned = [], []
    header_text = f"{item.get('title') or ''}\n{item.get('content') or ''}"
    for span in _CLOSING_SPAN.finditer(header_text):
        for ref_match in _ANY_REF.finditer(span.group(1)):
            resolved = normalize_ref(ref_match.group(0))
            if resolved and resolved != own_canonical and resolved not in closing:
                closing.append(resolved)
    full_text = "\n".join([header_text, *(str(note.get("body") or "") for note in item.get("public_comments") or [])])
    for ref_match in _ANY_REF.finditer(full_text):
        resolved = normalize_ref(ref_match.group(0))
        if resolved and resolved != own_canonical and resolved not in closing and resolved not in mentioned:
            mentioned.append(resolved)
    return closing, mentioned


def release_mentions(item: dict) -> list[str]:
    """Extract release:<product>:<version> keys explicitly named with their product."""
    texts = [str(item.get("title") or ""), str(item.get("content") or ""),
             *(str(note.get("body") or "") for note in item.get("public_comments") or [])]
    found = []
    for match in _RELEASE_MENTION.finditer("\n".join(texts)):
        raw_prod, raw_ver = match.group(1).lower(), match.group(2).lower()
        version = raw_ver.removeprefix("v")
        if not _VERSION.fullmatch(version):
            continue
        product = "tor-browser" if raw_prod.startswith("tor") and len(raw_prod) > 3 else raw_prod
        key = f"release:{product}:{version}"
        if key not in found:
            found.append(key)
    return found


def thread_subject(item: dict) -> tuple[str | None, bool]:
    """Normalized subject for HyperKitty list items (>= 3 words) and whether it is a reply."""
    if "/hyperkitty/list/" not in str(item.get("url") or ""):
        return None, False
    text = re.sub(r"\s+", " ", str(item.get("title") or "")).strip()
    is_reply = False
    while text:
        if tag_match := re.match(r"^\[[^\]]+\]\s*", text):
            text = text[tag_match.end() :]
        elif reply_match := re.match(r"^(?:re|aw|sv)(?:\[\d+\])?\s*[:.]\s*", text, re.I):
            is_reply = True
            text = text[reply_match.end() :]
        elif fwd_match := re.match(r"^(?:fwd?\s*:\s*|\(fwd\)\s*)", text, re.I):
            text = text[fwd_match.end() :]
        else:
            break
    cleaned = text.strip().lower()
    return (cleaned if len(cleaned.split()) >= 3 else None), is_reply
