"""Small shared helpers; untrusted source content stays plain text."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

UTC = timezone.utc


def now_iso() -> str:
    """Return the current UTC timestamp formatted as a second-precision `Z` string."""
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
    """Format an aware datetime as a second-precision UTC ISO-8601 `Z` string."""
    if moment.tzinfo is None:
        raise ValueError("Missing or invalid timezone-aware timestamp")
    return moment.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def after(seconds: float, start: str | None = None) -> str:
    """Return the UTC timestamp `seconds` after `start`, or after now when omitted."""
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
_SURROGATE_RE = re.compile(r"[\ud800-\udfff]")


def _reject_constant(_: str):
    raise ValueError("Non-finite JSON constant")


def saved_object(value, *, allow_surrogates: bool = False):
    """A saved JSON object read as bytes, or None when it is NULL or damaged, so one bad row cannot
    stop a run or hide the others. Decoding is strict UTF-8, as when the pipeline reads the row, not
    json.loads' lenient bytes mode, and non-finite numbers or an escaped lone surrogate, which no
    saved text can hold and the writer refuses, are damage too."""
    try:
        value = json.loads(str(value, "utf-8"), parse_constant=_reject_constant)
    except (TypeError, ValueError, RecursionError):
        return None
    return value if isinstance(value, dict) and _within(value, MAX_SAVED_DEPTH, allow_surrogates) else None


def _within(value, depth: int, allow_surrogates: bool = False) -> bool:
    if isinstance(value, dict):
        return depth > 0 and all(
            (allow_surrogates or not _SURROGATE_RE.search(k)) and _within(v, depth - 1, allow_surrogates)
            for k, v in value.items()
        )
    if isinstance(value, list):
        return depth > 0 and all(_within(v, depth - 1, allow_surrogates) for v in value)
    if isinstance(value, float):
        return math.isfinite(value)
    return allow_surrogates or not (isinstance(value, str) and _SURROGATE_RE.search(value))


def canonical_json(value: object, *, sort_keys: bool = True) -> str:
    """Serialize `value` to deterministic UTF-8 JSON without NaN or Inf constants."""
    return json.dumps(value, ensure_ascii=False, sort_keys=sort_keys, separators=(",", ":"), allow_nan=False)


def digest(value: object) -> str:
    """Return the hex SHA-256 digest of `canonical_json(value)`."""
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


_TYPOGRAPHY = str.maketrans({"\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"', "\u2013": "-", "\u2014": "-"})


def normalize_evidence(text: str) -> str:
    """Use identical quote matching for validation and deterministic citations."""
    return " ".join(text.translate(_TYPOGRAPHY).split()).casefold()


class _TextParser(HTMLParser):
    def __init__(self, limit: int, *, mark_blockquotes: bool = False) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.hidden = 0
        self.mark_blockquotes = mark_blockquotes
        self.quote_depth = 0
        self.line_start = True
        self.quote_remaining = limit

    def _append(self, text: str) -> None:
        """Keep inline text together while marking each visible quoted line."""
        if not self.mark_blockquotes:
            self.parts.append(text)
            return
        if self.quote_remaining <= 0:
            return
        for part in text.replace("\r\n", "\n").replace("\r", "\n").splitlines(keepends=True):
            if self.line_start and self.quote_depth and part.strip("\n"):
                count = min(self.quote_depth, self.quote_remaining)
                self.parts.append(">" * count)
                self.quote_remaining -= count
                # These markers survive all later whitespace/control cleanup.
                # Once their count reaches the output limit, no suffix can
                # enter the truncated text, even if earlier whitespace collapses.
                if not self.quote_remaining:
                    return
                self.parts.append(" ")
            self.parts.append(part)
            self.line_start = part.endswith(("\n", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"))

    def handle_starttag(self, tag: str, attrs: list) -> None:
        """Track hidden markup blocks and emit line breaks around block elements."""
        if tag in {"script", "style", "noscript", "template"}:
            self.hidden += 1
        elif self.mark_blockquotes and self.hidden:
            return
        elif tag == "blockquote" and self.mark_blockquotes:
            self._append("\n")
            self.quote_depth += 1
        elif tag in {"p", "br", "div", "li", "h1", "h2", "h3", "pre", "blockquote"}:
            self._append("\n")

    def handle_endtag(self, tag: str) -> None:
        """Exit hidden markup blocks and close block-level paragraphs."""
        if tag in {"script", "style", "noscript", "template"}:
            self.hidden = max(0, self.hidden - 1)
        elif self.mark_blockquotes and self.hidden:
            return
        elif tag == "blockquote" and self.mark_blockquotes:
            self._append("\n")
            self.quote_depth = max(0, self.quote_depth - 1)
        elif tag in {"p", "div", "li", "pre", "blockquote"}:
            self._append("\n")

    def handle_data(self, data: str) -> None:
        """Collect visible character data outside hidden script or style tags."""
        if not self.hidden:
            self._append(data)


def plain_text(value: object, limit: int, *, html: bool = True, mark_blockquotes: bool = False) -> str:
    """Normalize untrusted text; with html=True, also strip markup.

    Plain-text fields (such as GitLab titles) keep literal text like "Vec<u8>".
    Mailing-list body conversion may preserve HTML blockquotes as quote markers.
    """
    if not isinstance(value, str):
        return ""
    text = value[: limit * 4]
    if html:
        parser = _TextParser(limit, mark_blockquotes=mark_blockquotes)
        parser.feed(text)
        pending, parts, hidden = parser.rawdata, len(parser.parts), parser.hidden
        parser.close()
        # Some Python versions silently discard a final incomplete tag such as
        # '<word', even on close(). Keep that literal text, not comments or scripts.
        if not hidden and len(parser.parts) == parts and re.fullmatch(r"</?[A-Za-z][^>]*", pending):
            parser.handle_data(pending)
        text = "".join(parser.parts)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _SURROGATE_RE.sub("\ufffd", text)
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
    if parsed.scheme != "https" or not host or parsed.username is not None or parsed.password is not None:
        raise ValueError("Source URLs must be public HTTPS URLs without credentials")
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
        raise ValueError("Local source URL is not allowed")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if "." not in host:
            raise ValueError("Local source URL is not allowed")
        if all(re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)", part) for part in host.split(".")):
            raise ValueError("Ambiguous numeric source host is not allowed")
    else:
        from . import transport

        policy = getattr(transport, "PUBLIC_ADDRESS_POLICY", None) or transport.AddressPolicy()
        if not policy.permits(str(address)):
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
    query = urlencode([(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True) if not k.lower().startswith("utm_")])
    return urlunsplit(("https", authority, path, query, parsed.fragment))


def safe_canonical_url(url: object) -> str:
    """Return canonical_url(url) for a valid public HTTPS URL string, or empty string otherwise."""
    if not isinstance(url, str) or not url:
        return ""
    try:
        return canonical_url(url)
    except (TypeError, ValueError, UnicodeError):
        return ""


def gitlab_url_variants(url: object) -> set[str]:
    """Return canonical URL plus its GitLab /issues/ <-> /work_items/ alias when applicable."""
    canon = safe_canonical_url(url)
    if not canon:
        return set()
    if "/-/work_items/" in canon:
        return {canon, canon.replace("/-/work_items/", "/-/issues/")}
    if "/-/issues/" in canon:
        return {canon, canon.replace("/-/issues/", "/-/work_items/")}
    return {canon}


def item_identity(item: dict) -> str:
    """Keep repository entries stable while their immutable citation changes."""
    return "timeline:" + item["source_entry_id"] if item.get("kind") == "metrics_timeline" else item["url"]


_HACKERONE_REPORT_RE = re.compile(
    r"https?://(?:www\.)?hackerone\.com/reports/\d+\b|\breported\s+via\s+\[?hackerone\b",
    re.IGNORECASE,
)


def is_hackerone_item(item: dict) -> bool:
    """Return whether `item` is an authoritative HackerOne disclosure or GitLab report."""
    if not isinstance(item, dict):
        return False
    if item.get("authority") == "hackerone":
        return True
    raw_url = item.get("url", "")
    if isinstance(raw_url, str) and raw_url:
        host = (urlsplit(raw_url).hostname or "").lower().rstrip(".")
        if host == "hackerone.com" or host.endswith(".hackerone.com"):
            return True
    if item.get("authority") != "community" and item.get("kind") in {"gitlab_issue", "gitlab_mr"}:
        labels = item.get("labels") or ()
        if isinstance(labels, (list, tuple, set, frozenset)):
            for label in labels:
                if isinstance(label, str):
                    folded = label.strip().casefold()
                    if folded == "hackerone" or folded.startswith("hackerone::"):
                        return True
        title = item.get("title", "") if isinstance(item.get("title"), str) else ""
        body = (
            item["source_content"]
            if isinstance(item.get("source_content"), str)
            else (item.get("content", "") if isinstance(item.get("content"), str) else "")
        )
        if _HACKERONE_REPORT_RE.search(f"{title}\n{body}"):
            return True
    return False


DIRAUTH_GITLAB_USERS = (
    "andreas",    # dannenberg
    "arma",       # moria1
    "gman999",    # Serge (bridge authority)
    "linus",      # maatuska
    "micah",      # longclaw
    "sebastian",  # gabelmoo
    "sina",       # faravahar
    "stefani",    # bastet / sekhmet
    "usura",      # dizum
    "weasel",     # tor26
)
_DIRAUTH_LABELS = frozenset({"directory authority (dirauth)", "dirauth"})


def is_dirauth_item(item: dict, dirauth_users: Iterable[str] | None = None) -> bool:
    """Return whether `item` is a Tor GitLab ticket or MR from or with a directory-authority operator."""
    if not isinstance(item, dict):
        return False
    if item.get("authority") == "dirauth-operator":
        return True
    if item.get("authority") == "community" or item.get("kind") not in {"gitlab_issue", "gitlab_mr"}:
        return False
    raw_url = item.get("url")
    if not isinstance(raw_url, str) or not raw_url:
        return False
    try:
        host = (urlsplit(raw_url).hostname or "").lower().rstrip(".")
    except ValueError:
        return False
    if host != "gitlab.torproject.org":
        return False
    labels = item.get("labels") or ()
    if isinstance(labels, (list, tuple, set, frozenset)):
        for label in labels:
            if isinstance(label, str) and label.strip().casefold() in _DIRAUTH_LABELS:
                return True
    users = {
        u.strip().lower()
        for u in (DIRAUTH_GITLAB_USERS if dirauth_users is None else dirauth_users)
        if isinstance(u, str) and u.strip()
    }
    author = item.get("author")
    if isinstance(author, str) and author.strip().lower() in users:
        return True
    for field in ("public_comments", "dirauth_notes"):
        notes = item.get(field)
        if isinstance(notes, list) and any(
            isinstance(note, dict) and isinstance(note.get("author"), str) and note["author"].strip().lower() in users
            for note in notes
        ):
            return True
    return False


_PRODUCT_NAMES = {"tor-browser": r"tor[- ]browser", "arti": "arti", "tor": "tor"}
_VERSION = re.compile(r"\d+\.\d+(?:\.\d+){0,2}(?:[-.]?(?:alpha|beta|rc|a)\.?\d*)?")
_RELEASE_QUALIFIERS = r"(?:(?:new|stable|alpha|beta|security|bugfix|releases?|version)\s+)*"
_RELEASE_AFTER = re.compile(r"\s+(?:is\s+)?(?:now\s+)?available\b")
_RELEASE_EOL = re.compile(r"\b(?:end[- ]of[- ]life|eol|out of support|no longer supported)\b")
_GITLAB_OWN = re.compile(r"^(https://[^/?#]+)/(.+?)/-/(?:issues|work_items|merge_requests|tags|blob)/\S+")
_GITLAB_URL_REF = re.compile(r"^(https://[^/?#]+)/(.+?)/-/(issues|work_items|merge_requests)/(\d+)(?:/|$)")
_GITLAB_SHORT_REF = re.compile(r"^(?:([a-z0-9_.-]+(?:/[a-z0-9_.-]+)+))?([#!])(\d+)$", re.I)
_REF_TOKEN = r"(?:https://[^\s<>()\[\]\"']+|(?<![\w/#!])(?:[a-z0-9_.-]+(?:/[a-z0-9_.-]+)+)?[#!]\d+\b)"
_CLOSING_SPAN = re.compile(
    rf"\b(?:clos(?:e|es|ed|ing)|fix(?:|es|ed|ing)|resolv(?:e|es|ed|ing))\s*:?\s+({_REF_TOKEN}(?:\s*(?:,|and)\s*{_REF_TOKEN})*)",
    re.I,
)
_ANY_REF = re.compile(_REF_TOKEN, re.I)
_RELEASE_MENTION = re.compile(
    rf"\b(tor[- ]browser|arti|tor)[- ]{_RELEASE_QUALIFIERS}v?(\d+\.\d+(?:[\w.-]*\w)?)(?!(?:\w|\.\w))",
    re.I,
)


def item_cluster(item: dict) -> str:
    """Index canonical identities, identical bodies and release-version hints.

    A release hint relates prose announcements without deciding their novelty.
    """
    title = item["title"].lower()
    product = item.get("product", "network")
    if product == "network":
        product = next((name for name, pat in _PRODUCT_NAMES.items() if re.search(rf"\b{pat}\b", title)), product)
    if product in _PRODUCT_NAMES:
        # Only the first version in the title, and only when it follows the product
        # name, directly or after release qualifiers ("Tor Browser 16.0", "arti-v2.8.0",
        # "Tor stable release 0.4.8.19"); titles such as "Tails 7.16 ... Tor Browser
        # 16.0" keep their own identity, and so do delay and end-of-life notices.
        # A product-scoped feed may omit the product ("Security Release 0.4.9.17").
        match = re.search(r"(?<![\w.])v?(\d+\.\d+(?:[\w.-]*\w)?)", title)
        if (
            match
            and _VERSION.fullmatch(match.group(1))
            and (
                item.get("kind") == "tag"
                or re.search(r"\breleas(?:e|es|ed|ing)\b", title)
                or _RELEASE_AFTER.match(title[match.end() :])
            )
            and (
                re.search(r"\b" + _PRODUCT_NAMES[product] + r"[- ]" + _RELEASE_QUALIFIERS + "$", title[: match.start()])
                or (item.get("kind") == "feed" and item.get("product") in _PRODUCT_NAMES
                    and re.fullmatch(_RELEASE_QUALIFIERS, title[: match.start()]))
            )
            and (re.search(r"\breleased\b", title) or not re.search(r"\b(?:delayed|postponed)\b", title))
            and not _RELEASE_EOL.search(title)
        ):
            return f"release:{product}:{match.group(1)}"
    body = re.sub(r"\s+", " ", item["content"]).strip().lower()
    if len(body) >= 180 and item.get("kind") in {"gitlab_issue", "gitlab_mr"}:
        clean_title = re.sub(r"^(?:dirauth|authority|security|tor|arti):\s*", "", re.sub(r"\s+", " ", title).strip())
        return "body:" + digest([clean_title, body])
    return "url:" + digest(item_identity(item))


def story_cluster(item: dict) -> str:
    """Give prose feeds their own identity so review can distinguish new developments."""
    return "url:" + digest(item_identity(item)) if item.get("kind") == "feed" else item_cluster(item)


def gitlab_refs(item: dict) -> tuple[list[str], list[str]]:
    """Extract canonical closing and mentioned GitLab issue and merge-request URLs."""
    own_url = str(item.get("url") or "")
    own_match = _GITLAB_OWN.match(own_url)
    origin = own_match.group(1) if own_match else "https://gitlab.torproject.org"
    own_project = own_match.group(2) if own_match else None

    def normalize_ref(token: str) -> str | None:
        """Resolve one full or shorthand GitLab issue or merge-request token."""
        if token.startswith("https://"):
            match = _GITLAB_URL_REF.match(token.rstrip(".,;:!?)>]").split("#", 1)[0].split("?", 1)[0])
            if not match:
                return None
            ref_origin, project, kind_seg, number = match.groups()
            if ref_origin not in {"https://gitlab.torproject.org", origin}:
                return None
            seg = "work_items" if kind_seg in {"issues", "work_items"} else "merge_requests"
        else:
            short = _GITLAB_SHORT_REF.match(token)
            project = (short.group(1) or own_project or "") if short else ""
            if not project:
                return None
            ref_origin, seg, number = origin, ("work_items" if short.group(2) == "#" else "merge_requests"), short.group(3)
        raw = f"{ref_origin}/{project.lower()}/-/{seg}/{number}"
        return (safe_canonical_url(raw) or None) if ref_origin == "https://gitlab.torproject.org" else raw

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
