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


def backoff_until(attempt: int, base: float, cap: float, start: str | None = None) -> str:
    """Return the UTC cooldown timestamp for one-based `attempt` after `start`."""
    return after(backoff_seconds(attempt, base, cap), start)


def timestamp(value: str | None, fallback: str | None = None) -> str:
    """Normalize a supplied aware timestamp, without inventing changing dates."""
    try:
        return format_utc(parse_utc(value))
    except ValueError:
        if fallback is not None:
            return fallback
        raise


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


def strict_json(value: object, *, sort_keys: bool = True) -> str:
    """Serialize `value` to UTF-8 JSON without NaN, Infinity, or lone surrogates."""
    text = json.dumps(value, ensure_ascii=False, sort_keys=sort_keys, allow_nan=False)
    text.encode("utf-8")
    return text


def digest(value: object) -> str:
    """Return the hex SHA-256 digest of `canonical_json(value)`."""
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def has_invalid_text_chars(value: str) -> bool:
    """Reject ASCII control characters (other than tab/newline), DEL, surrogates, and XML noncharacters."""
    return any(
        (ord(c) < 32 and c not in "\n\t") or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF or c in "\ufffe\uffff"
        for c in value
    )


DOMAIN_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+")
_GITLAB_USER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}")
LIST_ARCHIVE_HOST = "lists.torproject.org"


def _valid_domain_label(label: str) -> bool:
    if not label.startswith("xn--"):
        return True
    import idna

    try:
        return idna.encode(idna.decode(label)).decode("ascii") == label
    except UnicodeError:
        return False


def is_valid_domain(value: object) -> bool:
    """Return whether `value` is a valid lowercase ASCII DNS domain name."""
    return (
        isinstance(value, str)
        and len(value) <= 253
        and bool(DOMAIN_RE.fullmatch(value))
        and not value.rsplit(".", 1)[-1].isdigit()
        and all(_valid_domain_label(lbl) for lbl in value.split("."))
    )


def is_valid_gitlab_user(value: object) -> bool:
    """Return whether `value` is a syntactically valid GitLab username."""
    return isinstance(value, str) and ".." not in value and not value.endswith(".") and bool(_GITLAB_USER_RE.fullmatch(value))


def valid_note_list(notes: object, fields: tuple[str, ...], *, allow_none: bool = True) -> bool:
    """Return whether `notes` is a list of dicts carrying string values for `fields`."""
    return (allow_none and notes is None) or (
        isinstance(notes, list)
        and all(
            isinstance(n, dict)
            and all(isinstance(n.get(f), str) for f in fields)
            and ("edited_at" not in n or isinstance(n["edited_at"], str))
            for n in notes
        )
    )


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
        """Track hidden markup blocks and emit line breaks around block elements."""
        if tag in {"script", "style", "noscript", "template"}:
            self.hidden += 1
        elif tag in {"p", "br", "div", "li", "h1", "h2", "h3", "pre", "blockquote"}:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        """Exit hidden markup blocks and close block-level paragraphs."""
        if tag in {"script", "style", "noscript", "template"}:
            self.hidden = max(0, self.hidden - 1)
        elif tag in {"p", "div", "li", "pre", "blockquote"}:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        """Collect visible character data outside hidden script or style tags."""
        if not self.hidden:
            self.parts.append(data)


def plain_text(value: object, limit: int, *, html: bool = True) -> str:
    """Normalize untrusted text; with html=True, also strip markup.

    Plain-text fields (such as GitLab titles) keep literal text like "Vec<u8>".
    """
    if not isinstance(value, str):
        return ""
    truncated_raw = len(value) > limit * 4
    text = value[: limit * 4]
    if html:
        parser = _TextParser()
        parser.feed(text)
        pending, parts, hidden = parser.rawdata, len(parser.parts), parser.hidden
        if pending.startswith("<") and (truncated_raw or re.match(r"</?(?:script|style|noscript|template)\b", pending, re.I)):
            parser.rawdata = pending = ""
        parser.close()
        # Some Python versions silently discard a final incomplete tag such as
        # '<word', even on close(). Keep that literal text, not comments or scripts.
        if not hidden and len(parser.parts) == parts and re.fullmatch(r"</?[A-Za-z][A-Za-z0-9_-]*", pending):
            parser.parts.append(pending)
        text = "".join(parser.parts)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _SURROGATE_RE.sub("\ufffd", text)
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\ufffe\uffff]", "", text)
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
    raw_host = parsed.hostname or ""
    if (
        parsed.scheme != "https"
        or not raw_host
        or "%" in raw_host
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError("Source URLs must be public HTTPS URLs without credentials")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid URL port") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Invalid URL port")
    import httpx

    try:
        decoded_host = httpx.URL(urlunsplit(("https", parsed.netloc, "/", "", ""))).raw_host.decode("ascii").lower()
    except (httpx.InvalidURL, UnicodeError, ValueError) as exc:
        raise ValueError("Invalid source URL") from exc
    if "%" in decoded_host or decoded_host.endswith(".."):
        raise ValueError("Invalid source URL")
    host = decoded_host[:-1] if decoded_host.endswith(".") else decoded_host
    if not host or host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
        raise ValueError("Local source URL is not allowed")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if "." not in host:
            raise ValueError("Local source URL is not allowed")
        if all(re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)", part) for part in host.split(".")):
            raise ValueError("Ambiguous numeric source host is not allowed")
        if not is_valid_domain(host):
            raise ValueError("Invalid source URL")
    else:
        if host != decoded_host:
            raise ValueError("Invalid source URL")
        from . import transport

        if not transport.PUBLIC_ADDRESS_POLICY.permits(address):
            raise ValueError("Private source URL is not allowed")
    authority = f"[{host}]" if ":" in host else host
    if port is not None and port != 443:
        authority += f":{port}"
    path = parsed.path or "/"
    if host == "gitlab.torproject.org":
        path = re.sub(r"/-/issues/(\d+)/?\Z", r"/-/work_items/\1", path, flags=re.I)
    query = urlencode([(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True) if not k.lower().startswith("utm_")])
    return urlunsplit(("https", authority, path, query, parsed.fragment))


def safe_canonical_url(url: object) -> str:
    """Return canonical_url(url) for a valid public HTTPS URL string, or empty string otherwise."""
    try:
        return canonical_url(url) if url else ""
    except ValueError:
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


def _url_host(url: object) -> str:
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".") if isinstance(url, str) and url else ""
    except ValueError:
        return ""


def folded_labels(item: dict) -> set[str]:
    """Return stripped case-folded string labels from `item`, or an empty set."""
    labels = item.get("labels") if isinstance(item, dict) else None
    return {s.strip().casefold() for s in labels if isinstance(s, str)} if isinstance(labels, (list, tuple, set, frozenset)) else set()


def dirauth_user_set(users: Iterable[str] | None = None) -> set[str]:
    """Normalize configured or default directory-authority GitLab usernames to lowercase."""
    return {u.strip().lower() for u in (DIRAUTH_GITLAB_USERS if users is None else users) if isinstance(u, str) and u.strip()}


def is_hackerone_item(item: dict) -> bool:
    """Return whether `item` is an authoritative HackerOne disclosure or GitLab report."""
    if not isinstance(item, dict):
        return False
    if item.get("authority") == "hackerone":
        return True
    if item.get("authority") == "community":
        return False
    host = _url_host(item.get("url"))
    if host == "hackerone.com" or host.endswith(".hackerone.com"):
        return True
    if item.get("kind") not in {"gitlab_issue", "gitlab_mr"}:
        return False
    if any(f == "hackerone" or f.startswith("hackerone::") for f in folded_labels(item)):
        return True
    title = item["title"] if isinstance(item.get("title"), str) else ""
    body = next((item[k] for k in ("source_content", "content") if isinstance(item.get(k), str)), "")
    return bool(_HACKERONE_REPORT_RE.search(f"{title}\n{body}"))


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
    if item.get("authority") == "community" or item.get("kind") not in {"gitlab_issue", "gitlab_mr"} or _url_host(item.get("url")) != "gitlab.torproject.org":
        return False
    if folded_labels(item) & _DIRAUTH_LABELS:
        return True
    users = dirauth_user_set(dirauth_users)
    if isinstance(author := item.get("author"), str) and author.strip().lower() in users:
        return True
    return any(
        isinstance(notes := item.get(field), list)
        and any(isinstance(n, dict) and isinstance(n.get("author"), str) and n["author"].strip().lower() in users for n in notes)
        for field in ("public_comments", "dirauth_notes")
    )


def effective_authority(item: dict, dirauth_users: Iterable[str] | None = None) -> str | None:
    """Return `item`'s authority after promoting HackerOne or directory-authority development items."""
    if item.get("authority") != "development":
        return item.get("authority")
    return "hackerone" if is_hackerone_item(item) else "dirauth-operator" if is_dirauth_item(item, dirauth_users) else "development"


_PRODUCT_NAMES = {"tor-browser": r"tor[- ]browser", "arti": "arti", "tor": "tor"}
_VERSION = re.compile(r"\d+\.\d+(?:\.\d+){0,2}(?:[-.]?(?:alpha|beta|rc|a)\.?\d*)?")
_RELEASE_QUALIFIERS = r"(?:(?:new|stable|alpha|beta|security|bugfix|releases?|version)\s+)*"
_RELEASE_AFTER = re.compile(r"\s+(?:is\s+)?(?:now\s+)?available\b")
_RELEASE_EOL = re.compile(r"\b(?:end[- ]of[- ]life|eol|out of support|no longer supported)\b")
GITLAB_PROJECT_PATH = r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+"
_GITLAB_OWN = re.compile(rf"^(https://[^/?#]+)/({GITLAB_PROJECT_PATH})/-/(?:issues|work_items|merge_requests|tags|blob)/\S+", re.I)
_GITLAB_URL_REF = re.compile(rf"^(https://[^/?#]+)/({GITLAB_PROJECT_PATH})/-/(issues|work_items|merge_requests)/(\d+)(?:/|$)", re.I)
_GITLAB_SHORT_REF = re.compile(rf"^(?:({GITLAB_PROJECT_PATH}))?([#!])(\d+)$")
_REF_TOKEN = rf"(?:https://[^\s<>()\[\]\"']+|(?<![\w/#!.-]){GITLAB_PROJECT_PATH}[#!]\d+\b|(?<![\w/#!])[#!]\d+\b)"
_CLOSING_SPAN = re.compile(
    rf"\b(?:clos(?:e|es|ed|ing)|fix(?:|es|ed|ing)|resolv(?:e|es|ed|ing))\s*:?\s+({_REF_TOKEN}(?:\s*(?:,|and)\s*{_REF_TOKEN})*)",
    re.I,
)
_ANY_REF = re.compile(_REF_TOKEN, re.I)
_RELEASE_MENTION = re.compile(
    rf"\b({'|'.join(_PRODUCT_NAMES.values())})[- ]{_RELEASE_QUALIFIERS}v?(\d+\.\d+(?:[\w.-]*\w)?)(?!(?:\w|\.\w))",
    re.I,
)
_SUBJECT_NOISE_RE = re.compile(r"^(?:\[[^\]]+\]|fwd?\s*:|\(fwd\))\s*", re.I)
_SUBJECT_REPLY_RE = re.compile(r"^(?:re|aw|sv)(?:\[\d+\])?\s*[:.]\s*", re.I)


def _item_texts(item: dict) -> tuple[str, str]:
    header = f"{item.get('title') or ''}\n{item.get('content') or ''}"
    comments = (str(note.get("body") or "") for note in item.get("public_comments") or ())
    return header, "\n".join((header, *comments))


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
    origin = own_match.group(1).lower() if own_match else "https://gitlab.torproject.org"
    own_project = (
        own_match.group(2)
        if own_match and not any(p in {".", ".."} for p in own_match.group(2).split("/"))
        else None
    )

    def normalize_ref(token: str) -> str | None:
        """Resolve one full or shorthand GitLab issue or merge-request token."""
        if token.lower().startswith("https://"):
            match = _GITLAB_URL_REF.match(token.rstrip(".,;:!?)>]").split("#", 1)[0].split("?", 1)[0])
            if not match:
                return None
            ref_origin, project, kind_seg, number = match.groups()
            ref_origin, kind_seg = ref_origin.lower(), kind_seg.lower()
            if ref_origin not in {"https://gitlab.torproject.org", origin}:
                return None
            seg = "work_items" if kind_seg in {"issues", "work_items"} else "merge_requests"
        else:
            short = _GITLAB_SHORT_REF.match(token)
            project = (short.group(1) or own_project or "") if short else ""
            if not project:
                return None
            ref_origin, seg, number = origin, ("work_items" if short.group(2) == "#" else "merge_requests"), short.group(3)
        if any(p in {".", ".."} for p in project.split("/")):
            return None
        raw = f"{ref_origin}/{project.lower()}/-/{seg}/{number}"
        return safe_canonical_url(raw) or None

    own_canonical = normalize_ref(own_url) if own_url.lower().startswith("https://") else None
    header_text, full_text = _item_texts(item)
    closing = list(dict.fromkeys(
        resolved
        for span in _CLOSING_SPAN.finditer(header_text)
        for ref_match in _ANY_REF.finditer(span.group(1))
        if (resolved := normalize_ref(ref_match.group(0))) and resolved != own_canonical
    ))
    mentioned = list(dict.fromkeys(
        resolved
        for ref_match in _ANY_REF.finditer(full_text)
        if (resolved := normalize_ref(ref_match.group(0))) and resolved != own_canonical and resolved not in closing
    ))
    return closing, mentioned


def release_mentions(item: dict) -> list[str]:
    """Extract release:<product>:<version> keys explicitly named with their product."""
    found = []
    for match in _RELEASE_MENTION.finditer(_item_texts(item)[1]):
        raw_prod, version = match.group(1).lower(), match.group(2).lower()
        if _VERSION.fullmatch(version):
            product = "tor-browser" if raw_prod.startswith("tor") and len(raw_prod) > 3 else raw_prod
            found.append(f"release:{product}:{version}")
    return list(dict.fromkeys(found))


def thread_subject(item: dict) -> tuple[str | None, bool]:
    """Normalized subject for HyperKitty list items (>= 3 words) and whether it is a reply."""
    if "/hyperkitty/list/" not in str(item.get("url") or ""):
        return None, False
    text = re.sub(r"\s+", " ", str(item.get("title") or "")).strip()
    is_reply = False
    while text:
        if match := _SUBJECT_NOISE_RE.match(text):
            text = text[match.end() :]
        elif match := _SUBJECT_REPLY_RE.match(text):
            is_reply = True
            text = text[match.end() :]
        else:
            break
    cleaned = text.strip().lower()
    return (cleaned if len(cleaned.split()) >= 3 else None), is_reply
