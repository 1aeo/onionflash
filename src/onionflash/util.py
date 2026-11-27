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
    def __init__(self, limit: int, *, mark_blockquotes: bool = False) -> None:
        """Initialize HTML text extractor with optional bounded blockquote markers."""
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
    truncated_raw = len(value) > limit * 4
    text = value[: limit * 4]
    if html:
        parser = _TextParser(limit, mark_blockquotes=mark_blockquotes)
        parser.feed(text)
        pending, hidden = parser.rawdata, parser.hidden
        literal_tail = ""
        if pending.startswith("<"):
            # Discard incomplete markup before close(), since some Python versions
            # emit unfinished tags or comments as text; keep bare literal '<word'.
            if not truncated_raw and (
                pending in {"<", "</"}
                or (
                    re.fullmatch(r"</?[A-Za-z][A-Za-z0-9_-]*", pending)
                    and not re.match(r"</?(?:script|style|noscript|template)\b", pending, re.I)
                )
            ):
                literal_tail = pending
            parser.rawdata = ""
        parser.close()
        if not hidden and literal_tail:
            parser.handle_data(literal_tail)
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
    canonical = urlunsplit(("https", authority, path, query, parsed.fragment))
    # Saved citations must remain valid when packet and publication readers
    # validate them again; query escaping can expand a shorter supplied URL.
    if len(canonical) > 4096:
        raise ValueError("Invalid source URL")
    return canonical


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
DIRAUTH_NICKNAMES = (
    "maatuska", "bastet", "moria1", "dannenberg", "dizum",
    "faravahar", "gabelmoo", "longclaw", "sekhmet", "tor26", "serge",
)
DIRAUTH_NICKNAME_RE = re.compile(r"\b(?:" + "|".join(DIRAUTH_NICKNAMES) + r")\b", re.I)
_DIRAUTH_LABELS = frozenset({"directory authority (dirauth)", "dirauth"})
DEFAULT_TOR_CORE_USERS: tuple[str, ...] = (
    "acute", "agix", "agrabeli", "ahf", "alsmith", "anadahz", "anarcat", "andreas", "anonym",
    "antonela", "arlolra", "arma", "arthuredelstein", "arturo", "asn", "atagar", "bdavila",
    "biella", "boklm", "bokonon", "boyska", "brizental", "christian", "clairehurst", "cohosh",
    "cve", "dan_b", "dennis_jackson", "dgoulet", "diana", "dianamtor", "diziet", "djackson",
    "donuts", "drwhax", "egypcio", "elshrek", "emmapeel", "esraa", "eta", "flexlibris", "gaba",
    "gabi", "gazebook", "geko", "ggus", "gk", "gman999", "groente", "groentor", "gunner",
    "haxxpop", "hc", "hellais", "hiro", "iang", "iangoldberg", "inf0", "intrigeri", "irl",
    "isabela", "jacobo", "jnewsome", "juga", "julius", "jvoisin", "karsten", "kat", "kat5",
    "kevun", "kushal", "lavamind", "lelutin", "linus", "ma1", "mattlav", "meejah", "meskio",
    "micah", "micahflee", "morgan", "morganava", "mtigas", "n8fr8", "nadya", "nah", "narrira",
    "nickm", "nicob", "nvjacobo", "ohmygodel", "opara", "pastly", "pavel", "phw", "pierov",
    "pulls", "q", "qbi", "ramy", "rgdd", "rhatto", "robgjansen", "sajolida", "sanketh",
    "sarah", "sarthikg", "sebastian", "sengler", "shelikhoo", "sjmurdoch", "stefani",
    "syverson", "teor", "theenbyperor", "thorin", "tjr", "trinity-1686a", "weasel",
    "wesleyac", "wseltzer", "wshackleton", "yawningangel", "zen-fu",
)
TROVE_RE = re.compile(r"\bTROVE-\d{4}-\d{3,5}\b", re.I)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_RELEASE_ANNOUNCE_TITLE_RE = re.compile(
    r"\b(?:new release|security release|tor (?:stable|alpha|release)\b|\[release\])",
    re.I,
)
_LIST_ARCHIVE_THREAD_PATH_RE = re.compile(
    r"^/(?:mailman3/hyperkitty/list/[^/]+/(?:message|thread)/[^/]+"
    r"|archives/list/[^/]+/(?:message|thread)/[^/]+"
    r"|pipermail/[^/]+/[^/]+/[^/]+"
    r"|m/[^/]+/?\Z)",
    re.I,
)


def tor_core_user_set(users: Iterable[str] | None = None) -> set[str]:
    """Normalize configured or default Tor Project GitLab usernames to lowercase."""
    return {u.strip().lower() for u in (DEFAULT_TOR_CORE_USERS if users is None else users) if isinstance(u, str) and u.strip()}


def _has_gitlab_user_activity(item: dict, users: set[str]) -> bool:
    """Return whether a Tor GitLab issue/MR author or note author belongs to `users`."""
    if not users:
        return False
    if isinstance(author := item.get("author"), str) and author.strip().lower() in users:
        return True
    return any(
        isinstance(notes := item.get(field), list)
        and any(isinstance(n, dict) and isinstance(n.get("author"), str) and n["author"].strip().lower() in users for n in notes)
        for field in ("public_comments", "dirauth_notes")
    )


def trove_ids(item: dict) -> list[str]:
    """Extract deduplicated uppercase `TROVE-YYYY-NNN` identifiers from title and body."""
    if not isinstance(item, dict):
        return []
    title = item["title"] if isinstance(item.get("title"), str) else ""
    body = next((item[k] for k in ("source_content", "content") if isinstance(item.get(k), str)), None)
    if body is None and isinstance(item.get("passages"), list):
        body = "\n".join(
            p["text"]
            for p in item["passages"]
            if isinstance(p, dict) and "author" not in p and isinstance(p.get("text"), str)
        )
    return list(dict.fromkeys(m.upper() for m in TROVE_RE.findall(f"{title}\n{body or ''}")))


def cve_ids(item: dict) -> list[str]:
    """Extract deduplicated uppercase `CVE-YYYY-NNNN` identifiers from title, body, and comments."""
    if not isinstance(item, dict):
        return []
    title = item["title"] if isinstance(item.get("title"), str) else ""
    body = next((item[k] for k in ("source_content", "content") if isinstance(item.get(k), str)), "")
    comments = (
        str(note.get("body") or "")
        for note in (item.get("public_comments") if isinstance(item.get("public_comments"), list) else ())
        if isinstance(note, dict)
    )
    return list(dict.fromkeys(m.upper() for m in CVE_RE.findall("\n".join((title, body, *comments)))))


def is_trove_item(item: dict) -> bool:
    """Return whether `item` is a verified official, project, or Tor GitLab TROVE advisory."""
    return (
        isinstance(item, dict)
        and bool(trove_ids(item))
        and (
            item.get("authority") in {"official", "project-sender", "hackerone", "dirauth-operator", "tor-core"}
            or (
                item.get("authority") != "community"
                and item.get("kind") in {"gitlab_issue", "gitlab_mr"}
                and _url_host(item.get("url")) == "gitlab.torproject.org"
            )
        )
    )


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
    return _has_gitlab_user_activity(item, dirauth_user_set(dirauth_users))


def is_tor_core_item(item: dict, tor_core_users: Iterable[str] | None = None) -> bool:
    """Return whether `item` is a Tor GitLab ticket or MR from or with a Tor core contributor."""
    if not isinstance(item, dict):
        return False
    if item.get("authority") == "tor-core":
        return True
    if item.get("authority") == "community" or item.get("kind") not in {"gitlab_issue", "gitlab_mr"} or _url_host(item.get("url")) != "gitlab.torproject.org":
        return False
    return _has_gitlab_user_activity(item, tor_core_user_set(tor_core_users))


def effective_authority(
    item: dict,
    dirauth_users: Iterable[str] | None = None,
    tor_core_users: Iterable[str] | None = None,
) -> str | None:
    """Return `item`'s authority after promoting HackerOne, dirauth-operator, or tor-core development items."""
    if item.get("authority") != "development":
        return item.get("authority")
    if is_hackerone_item(item):
        return "hackerone"
    if is_dirauth_item(item, dirauth_users):
        return "dirauth-operator"
    if is_tor_core_item(item, tor_core_users):
        return "tor-core"
    return "development"


_PRODUCT_NAMES = {
    "tor-browser": r"tor[- ]browser",
    "snowflake": "snowflake",
    "webtunnel": "webtunnel",
    "lyrebird": "lyrebird",
    "arti": "arti",
    "tor": "tor",
}
_VERSION = re.compile(r"\d+\.\d+(?:\.\d+){0,2}(?:[-.]?(?:alpha|beta|rc|a)\.?\d*)?")
_RELEASE_QUALIFIERS = r"(?:(?:new|stable|alpha|beta|security|bugfix|releases?|version)\s+)*"
_RELEASE_AFTER = re.compile(r"\s+(?:is\s+)?(?:now\s+)?available\b")
_RELEASE_EOL = re.compile(r"\b(?:end[- ]of[- ]life|eol|out of support|no longer supported)\b")
GITLAB_PROJECT_PATH = r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+"
GITLAB_SOFTWARE_PROJECTS = {
    "tpo/core/tor": "tor",
    "tpo/core/arti": "arti",
    "tpo/applications/tor-browser": "tor-browser",
    "tpo/anti-censorship/pluggable-transports/snowflake": "snowflake",
    "tpo/anti-censorship/pluggable-transports/webtunnel": "webtunnel",
    "tpo/anti-censorship/pluggable-transports/lyrebird": "lyrebird",
    "tpo/core/torspec": "torspec",
    "tpo/tails/tails": "tails",
}
_GITLAB_TORPROJECT_URL = re.compile(
    r"^https://gitlab\.torproject\.org/([^?#]+?)/-/(?:issues|work_items|merge_requests|tags|blob|releases|commit)/\S+",
    re.I,
)
_GITLAB_PROJECT_FULL = re.compile(GITLAB_PROJECT_PATH)
_BLOG_RELEASE_PREFIXES = (
    ("/new-release-tor-browser-", "tor-browser"),
    ("/new-release-tails-", "tails"),
    ("/new-release-arti-", "arti"),
    ("/new-release-tor-", "tor"),
)
_GITLAB_OWN = re.compile(rf"^(https://[^/?#]+)/({GITLAB_PROJECT_PATH})/-/(?:issues|work_items|merge_requests|tags|blob)/\S+", re.I)
_GITLAB_URL_REF = re.compile(rf"^(https://[^/?#]+)/({GITLAB_PROJECT_PATH})/-/(issues|work_items|merge_requests)/(\d+)(?:/|$)", re.I)
_GITLAB_SHORT_REF = re.compile(rf"^(?:({GITLAB_PROJECT_PATH}))?([#!])(\d+)$")
_REF_TOKEN = rf"(?:https://[^\s<>()\[\]\"']+|(?<![\w/#!.-]){GITLAB_PROJECT_PATH}[#!]\d+\b|(?<![\w/#!])[#!]\d+\b)"
_CLOSING_SPAN = re.compile(
    rf"\b(?:clos(?:e|es|ed|ing)|fix(?:|es|ed|ing)|resolv(?:e|es|ed|ing))\s*:?\s+({_REF_TOKEN}(?:\s*(?:,|and)\s*{_REF_TOKEN})*)",
    re.I,
)
_ANY_REF = re.compile(_REF_TOKEN, re.I)
DUP_SECURITY_GUARD_RE = re.compile(
    r"\b(?:vulnerabilit\w*|exploit\w*|null[- ]?(?:pointer[- ]|ptr[- ])?deref\w*|use[- ]after[- ]free|buffer\s+overflow|"
    r"out[- ]of[- ]bounds|remote\s+code(?:\s+execution)?)\b",
    re.I,
)
_DUP_LABELS = frozenset({"duplicate", "status::duplicate"})
_NOT_DUP_RE = re.compile(
    r"\b(?:(?:is|was|are|were)n['’]?t\s+(?:a\s+)?|not\s+(?:a\s+)?|no\s+|non[- ]?)(?:duplicates?\b|dup\b)",
    re.I,
)
_DUPLICATE_ISSUE_SPAN_RE = re.compile(
    rf"\b(?:closed\s+as\s+(?:a\s+)?duplicate(?:\s+of)?|dup(?:licate)?\s+of|dup\s*:|duplicates?)\s*:?\s*"
    rf"({_REF_TOKEN}(?:\s*(?:,|and)\s*{_REF_TOKEN})*)",
    re.I,
)
_DIRAUTH_SECURITY_OR_DOS_RE = re.compile(
    r"\b(?:vulnerabilit\w*|exploit\w*|compromis\w*|hack(?:ed|ing)?|breach\w*|tamper\w*|deanonymiz\w*|"
    r"ddos|dos|denial[- ]of[- ]service|flood(?:ing|ed|s)?|attack(?:ed|ing|s|ers?)?|"
    r"overflow|use[- ]after[- ]free|out[- ]of[- ]bounds|null[- ]?(?:pointer|ptr)[- ]?deref\w*|"
    r"rce|remote\s+code|malicious|evasion|bypass\w*)\b",
    re.I,
)
_DIRAUTH_OPERATIONAL_TOPIC_RE = re.compile(
    r"\b(?:dirauth|directory\s+authorit\w*|bridge\s+authorit\w*|dirvote|consensus|vot(?:e|es|ing)|"
    r"bwauth|bandwidth\s+authorit\w*|v3ident|signing\s+key|identity\s+key|authority\s+key|"
    r"authority\s+list|dirauth\s+list|default\s+authorit\w*|ipv[46]|dual[- ]stack|subnet|"
    r"migrat(?:e|ion|ing)|ip\s+(?:change|address|migrat\w*)|address\s+change|outage|offline|"
    r"unreachable|overload\w*|hardware|descriptor\s+upload|shared[- ]random|srv|guard\s+flags?|"
    r"missing\s+from\s+(?:the\s+)?consensus)\b",
    re.I,
)
_DIRAUTH_TITLE_OP_RE = re.compile(
    r"\b(?:address|ipv[46]|dual[- ]stack|subnet|migrat\w*|ip\b|keys?|v3ident|cert(?:ificate)?|"
    r"rotat\w*|retir\w*|remov\w*|add(?:s|ed|ing)?|list|vot(?:e|es|ing)|consensus|dirvote|bwauth|"
    r"overload\w*|outage|offline|unreachable|degrad\w*|timeout\w*|upload\w*|guard\s+flags?|"
    r"srv|shared[- ]random|stale|missing|replac\w*|hardware|operational)\b",
    re.I,
)
_DIRAUTH_CHORE_RE = re.compile(
    r"\b(?:spelling\s+typo|comment\s+typo|minor\s+formatting|formatting\s+note)\b",
    re.I,
)
_RELEASE_MENTION = re.compile(
    rf"\b({'|'.join(_PRODUCT_NAMES.values())})[- ]{_RELEASE_QUALIFIERS}v?(\d+\.\d+(?:[\w.-]*\w)?)(?!(?:\w|\.\w))",
    re.I,
)
_SUBJECT_NOISE_RE = re.compile(r"^(?:\[[^\]]+\]|fwd?\s*:|\(fwd\))\s*", re.I)
_SUBJECT_REPLY_RE = re.compile(r"^(?:re|aw|sv)(?:\[\d+\])?\s*[:.]\s*", re.I)


def _item_texts(item: dict) -> tuple[str, str]:
    body = item.get("source_content") if isinstance(item.get("source_content"), str) else item.get("content")
    header = f"{item.get('title') or ''}\n{body or ''}"
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


def gitlab_project_path(url: object) -> str | None:
    """Extract the lowercase project path from a Tor Project GitLab URL."""
    if not isinstance(url, str):
        return None
    match = _GITLAB_TORPROJECT_URL.match(url.strip())
    if not match:
        return None
    project = match.group(1)
    if not _GITLAB_PROJECT_FULL.fullmatch(project) or any(part in {".", ".."} for part in project.split("/")):
        return None
    return project.lower()


def gitlab_repo_name(url: object) -> str | None:
    """Return the lowercase repository leaf name from a Tor Project GitLab URL."""
    path = gitlab_project_path(url)
    return path.rsplit("/", 1)[-1] if path else None


def software_from_url(url: object) -> str | None:
    """Map an upstream Tor Project GitLab or blog release URL to a software slug."""
    path = gitlab_project_path(url)
    if path is not None:
        return GITLAB_SOFTWARE_PROJECTS.get(path)
    if not isinstance(url, str):
        return None
    raw = url.strip()
    if not raw:
        return None
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return None
    if parsed.scheme.lower() != "https" or parsed.netloc.lower() != "blog.torproject.org":
        return None
    blog_path = parsed.path.lower()
    for prefix, software in _BLOG_RELEASE_PREFIXES:
        if blog_path.startswith(prefix):
            return software
    return None


def software_from_sources(sources: Iterable[object]) -> list[str]:
    """Return deduplicated software slugs extracted from source entries or URLs."""
    if not sources:
        return []
    found: list[str] = []
    for entry in sources:
        url = entry.get("url") if isinstance(entry, dict) else entry
        software = software_from_url(url)
        if software and software not in found:
            found.append(software)
    return found


def release_mentions(item: dict) -> list[str]:
    """Extract release:<product>:<version> keys explicitly named with their product."""
    found = []
    for match in _RELEASE_MENTION.finditer(_item_texts(item)[1]):
        raw_prod, version = match.group(1).lower(), match.group(2).lower()
        if _VERSION.fullmatch(version):
            product = "tor-browser" if raw_prod in {"tor-browser", "tor browser"} else raw_prod
            found.append(f"release:{product}:{version}")
    return list(dict.fromkeys(found))


def _strip_subject_prefixes(title: object) -> tuple[str, bool]:
    text = re.sub(r"\s+", " ", str(title or "")).strip()
    is_reply = False
    while text:
        if match := _SUBJECT_NOISE_RE.match(text):
            text = text[match.end() :]
        elif match := _SUBJECT_REPLY_RE.match(text):
            is_reply = True
            text = text[match.end() :]
        else:
            break
    return text.strip().lower(), is_reply


def thread_subject(item: dict) -> tuple[str | None, bool]:
    """Normalized subject for HyperKitty list items (>= 3 words) and whether it is a reply."""
    if "/hyperkitty/list/" not in str(item.get("url") or ""):
        return None, False
    cleaned, is_reply = _strip_subject_prefixes(item.get("title"))
    return (cleaned if len(cleaned.split()) >= 3 else None), is_reply


def is_official_release_announcement(item: dict) -> bool:
    """Return whether `item` is an official Tor Project release announcement feed entry."""
    if not isinstance(item, dict) or item.get("authority") != "official" or item.get("kind") != "feed":
        return False
    title = str(item.get("title") or "")
    _, is_reply = _strip_subject_prefixes(title)
    if is_reply:
        return False
    if _RELEASE_ANNOUNCE_TITLE_RE.search(title):
        return True
    probe = {
        "title": title,
        "content": str(item.get("content") or item.get("source_content") or ""),
        "kind": item["kind"],
        "url": str(item.get("url") or ""),
        **({"product": item["product"]} if item.get("product") else {}),
    }
    return item_cluster(probe).startswith("release:")


def is_torproject_new_thread(item: dict) -> bool:
    """Return whether `item` opens a new mailing-list thread from an official or @torproject.org sender."""
    if not isinstance(item, dict) or _url_host(item.get("url")) != LIST_ARCHIVE_HOST:
        return False
    try:
        path = urlsplit(str(item["url"])).path or ""
    except ValueError:
        return False
    if not _LIST_ARCHIVE_THREAD_PATH_RE.match(path):
        return False
    if item.get("authority") not in {"project-sender", "official"}:
        return False
    cleaned, is_reply = _strip_subject_prefixes(item.get("title"))
    return bool(cleaned) and not is_reply


def mandatory_news_rule(item: dict) -> str | None:
    """Return the mandatory news-value rule satisfied by `item`, or None."""
    if is_trove_item(item):
        return "trove"
    if is_official_release_announcement(item):
        return "release_announcement"
    if is_torproject_new_thread(item):
        return "torproject_new_thread"
    return None


def is_protected_duplicate_issue(item: dict) -> bool:
    """Return whether a duplicate GitLab issue carries security cues that bar fast-skipping."""
    if not isinstance(item, dict):
        return False
    if (
        "security" in folded_labels(item)
        or is_hackerone_item(item)
        or is_trove_item(item)
        or bool(cve_ids(item))
        or bool(trove_ids(item))
    ):
        return True
    _, full_text = _item_texts(item)
    return bool(DUP_SECURITY_GUARD_RE.search(full_text))


def duplicate_issue_refs(item: dict) -> list[str]:
    """Extract canonical GitLab URLs targeted by a closed duplicate issue, or `[]` when negated or ambiguous."""
    if not isinstance(item, dict) or item.get("kind") != "gitlab_issue" or item.get("upstream_state") != "closed":
        return []
    _, full_text = _item_texts(item)
    if _NOT_DUP_RE.search(full_text):
        return []
    matches = list(_DUPLICATE_ISSUE_SPAN_RE.finditer(full_text))
    if matches:
        dup_snippet = "\n".join(m.group(1) for m in matches)
        closing, mentioned = gitlab_refs(
            {**item, "title": "", "content": dup_snippet, "source_content": dup_snippet, "public_comments": []}
        )
        return list(dict.fromkeys([*closing, *mentioned]))
    if folded_labels(item) & _DUP_LABELS:
        closing, mentioned = gitlab_refs(item)
        all_refs = list(dict.fromkeys([*closing, *mentioned]))
        return all_refs if len(all_refs) == 1 else []
    return []


def should_confirm_merged_mr(sources: Iterable[dict] | None) -> bool:
    """Return whether `sources` consists solely of merged GitLab merge requests."""
    items = list(sources) if sources is not None else []
    return bool(items) and all(
        isinstance(s, dict)
        and s.get("kind") == "gitlab_mr"
        and s.get("upstream_state") == "merged"
        and s.get("authority") != "community"
        for s in items
    )


def _source_full_text(source: dict) -> str:
    title = source.get("title") if isinstance(source.get("title"), str) else ""
    body = next((source[k] for k in ("source_content", "content", "unquoted_content") if isinstance(source.get(k), str)), "")
    if not body and isinstance(source.get("passages"), list):
        body = "\n".join(
            str(p.get("text") or "")
            for p in source["passages"]
            if isinstance(p, dict) and isinstance(p.get("text"), str)
        )
    comments = (
        str(note.get("body") or "")
        for note in (source.get("public_comments") if isinstance(source.get("public_comments"), list) else ())
        if isinstance(note, dict)
    )
    return "\n".join((title, body, *comments))


_DIRAUTH_SIGNAL_RE = re.compile(
    r"\b(?:dirauth|directory[- ]authorit\w*|bridge[- ]authorit\w*|bwauth|"
    r"bandwidth[- ]authorit\w*|dirvote|v3ident|consensus|vot(?:e|es|ing))\b",
    re.I,
)


def has_dirauth_signal(source: dict) -> bool:
    """Return whether `source` explicitly carries a directory-authority label, host nickname, or voting/consensus term."""
    if not isinstance(source, dict):
        return False
    if folded_labels(source) & (_DIRAUTH_LABELS | {"directory authority"}):
        return True
    text = _source_full_text(source)
    return bool(DIRAUTH_NICKNAME_RE.search(text) or _DIRAUTH_SIGNAL_RE.search(text))


def is_dirauth_category_story(sources: Iterable[dict] | None) -> bool:
    """Return whether `sources` describes non-security, non-release directory-authority operations."""
    items = list(sources) if sources is not None else []
    if not items or not all(isinstance(s, dict) for s in items):
        return False
    texts = [_source_full_text(s) for s in items]
    for s, text in zip(items, texts):
        labels = folded_labels(s)
        probe = {**s, "content": text} if "content" not in s and "source_content" not in s else s
        if (
            s.get("kind") == "tag"
            or s.get("mandatory_news_rule") in {"trove", "release_announcement"}
            or is_trove_item(probe)
            or bool(trove_ids(s))
            or bool(CVE_RE.search(text))
            or is_hackerone_item(probe)
            or is_official_release_announcement(probe)
            or (s.get("kind") == "feed" and item_cluster({
                "title": str(s.get("title") or ""), "content": text, "kind": "feed",
                "url": str(s.get("url") or ""), **({"product": s["product"]} if s.get("product") else {}),
            }).startswith("release:"))
            or "security" in labels
            or "dos" in labels
            or "ddos" in labels
            or any(lbl.startswith("severity::") for lbl in labels)
            or bool(_DIRAUTH_SECURITY_OR_DOS_RE.search(text))
        ):
            return False
    for s, text in zip(items, texts):
        labels = folded_labels(s)
        if labels & (_DIRAUTH_LABELS | {"directory authority"}):
            return True
        if _DIRAUTH_CHORE_RE.search(text):
            continue
        if s.get("authority") == "dirauth-operator" and has_dirauth_signal(s) and _DIRAUTH_OPERATIONAL_TOPIC_RE.search(text):
            return True
        title = str(s.get("title") or "")
        if DIRAUTH_NICKNAME_RE.search(title) or re.search(r"\b(?:dirauth|directory\s+authorit\w*|bridge\s+authorit\w*)\b", title, re.I):
            if _DIRAUTH_TITLE_OP_RE.search(title):
                return True
    return False


_PROTECTED_HOUSEKEEPING_LABELS = frozenset({
    "security", "regression", "critical", "severity::high", "severity::critical",
})
_HOUSEKEEPING_SECURITY_SIGNAL_RE = re.compile(
    r"(?:"
    r"\[security\]"
    r"|\b(?:RUSTSEC-\d{4}-\d{4,}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|CVE-\d{4}-\d{4,7}|TROVE-\d{4}-\d{3,5})\b"
    r"|\bsecurity\s+(?:fix(?:es)?|patch(?:es)?|updat(?:e|es|ing)|bump|releas(?:e|es)|advisor(?:y|ies)|issue|vulnerabilit\w*)\b"
    r"|\b(?:vulnerabilit\w*|exploit\w*|deanonymiz\w*|out[- ]of[- ]bounds|use[- ]after[- ]free|buffer\s+overflow|remote\s+code(?:\s+execution)?)\b"
    r"|\b(?:auth(?:entication|orization)?[- ]bypass\w*|access[- ]control[- ]bypass\w*|privilege\s+escalation)\b"
    r"|\bbypass(?:es|ed|ing)?\s+(?:[a-z0-9_-]+\s+){0,2}(?:auth(?:entication|orization)?|access[- ]control)\b"
    r"|\bunauthenticated\s+(?:clients?|users?|requests?)?\s*access\b"
    r")",
    re.I,
)
_HOUSEKEEPING_RUNTIME_GUARD_RE = re.compile(
    r"\b(?:"
    r"panic\w*|crash(?:es|ed|ing)?|deadlock\w*|oom|out[- ]of[- ]memory|exhaust\w*|ddos|dos|"
    r"denial[- ]of[- ]service|data\s+loss|corrupt(?:ion|ed)?|compromis\w*|regress(?:ion|es)|"
    r"broken\s+(?:for\s+users?|downloads?|signatures?|verification)"
    r")\b",
    re.I,
)
_HOUSEKEEPING_TITLE_PAT_RE = re.compile(
    r"(?:"
    r"\brelease\s+checklist\b|\bversion\s+bump\b|\bbump(?:ing)?\s+(?:version|deps|dependencies)\b"
    r"|\bforward[- ]port\b.*\bchangelogs?\b|^update\s+changelogs?\b|^clean\s*up\s+comments?\b"
    r"|^fix\s+(?:whitespace|formatting|lint(?:ing)?|clippy)\b|^bump\s+(?:cargo\.lock|lockfile)\b"
    r"|\b(?:cargo|package|yarn|poetry|uv)\.lock\b|\blockfile\b"
    r"|\b(?:dependabot|renovate)\b|^(?:chore|ci|typo|housekeeping|l10n|i18n|translations?)\s*:"
    r")|\bminor\s+typo\b|\bfix(?:es|ing)?\s+(?:a\s+)?typo\b",
    re.I,
)
_DEPENDENCY_CHORE_RE = re.compile(
    r"(?:"
    r"^(?:chore|build|fix|ci|deps)\(deps(?:-dev)?\)\s*:"
    r"|\b(?:dependabot|renovate)(?:\[bot\])?\b"
    r"|^(?:bump|update|upgrade)\s+dependencies\b"
    r"|\bautomated\s+dependency\s+(?:update|bump)\b"
    r")",
    re.I,
)
_CI_PIPELINE_CHORE_RE = re.compile(
    r"(?:"
    r"\bgoreleaser\s+job\b"
    r"|\b(?:broken|fix(?:es|ing)?|update|skip|disable|repair)\s+(?:the\s+)?(?:ci(?:/cd)?|gitlab[- ]ci|github\s+actions?|pipeline)\s+"
    r"(?:job|runner|stage|step|script|config|action)\b"
    r"|\b(?:ci(?:/cd)?|gitlab[- ]ci|pipeline)\s+job\s+(?:fails?|failing|broken)\b"
    r"|^ci(?:\([^)]+\))?\s*:"
    r")",
    re.I,
)
_BOT_DEP_AUTHORS = frozenset({"dependabot", "dependabot[bot]", "renovate", "renovate[bot]"})
_TEST_CHORE_RE = re.compile(
    r"^(?:(?!(?:security|advisory)\s*:)(?:[a-z0-9_./-]+:\s+)?)?"
    r"(?:tests?(?:\([^)]+\))?\s*:"
    r"|(?:improve|add|fix|update|refactor|clean\s*up)\s+(?:default\s+)?(?:unit\s+|integration\s+|dirauth\s+)?tests?\b)"
    r"(?!.*\b(?:and\s+fix(?:es|ed)?|bugfix|cve|trove|regression|vulnerabilit\w*|leak)\b)",
    re.I,
)
_INTERNAL_CLEANUP_RE = re.compile(
    r"^(?!(?:security|advisory)\s*:)(?:[a-z0-9_./-]+:\s+)?"
    r"(?:"
    r"(?:fix(?:ing)?|clean\s*up|resolve|remove)\s+(?:the\s+)?(?:\w+\s+){0,3}todos?\b"
    r"|(?:refactor|clean\s*up)\s+internal\b"
    r")(?!.*\b(?:security|vulnerabilit\w*|regression|api\s+break|breaking|bug)\b)",
    re.I,
)
_HOUSEKEEPING_BEHAVIOR_CHANGE_RE = re.compile(
    r"\b(?:"
    r"by\s+default|new\s+default|"
    r"default\s+(?:behaviou?r|setting|config(?:uration)?|mode|value|enabled|disabled)|"
    r"(?:chang|switch|alter)\w*\s+(?:the\s+)?default|"
    r"behaviou?r\s+change|breaking\s+change|api\s+break|"
    r"(?:user|operator)[- ]visible|"
    r"add\s+support\s+for|"
    r"ship(?:s|ped|ping)?\s+(?:\w+\s+){0,3}(?:feature|capability|option|command|flag|transport)"
    r")\b",
    re.I,
)
_TITLE_COMPOUND_CHANGE_RE = re.compile(
    r"(?:\band\b|[,;+])\s*"
    r"(?:enabl|disabl|support|implement|add|introduc|ship|chang|switch|dropp?|deprecat|migrat|fix|patch|resolv|expos|allow|block|limit|enforc)\w*\b",
    re.I,
)

_PT_FAMILY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("snowflake", re.compile(r"\bsnowflake\b", re.I)),
    ("webtunnel", re.compile(r"\bwebtunnel\b", re.I)),
    ("lyrebird", re.compile(r"\blyrebird\b", re.I)),
    ("obfs4", re.compile(r"\bobfs4(?:proxy)?\b", re.I)),
    ("conjure", re.compile(r"\bconjure\b", re.I)),
)
_PT_REPO_PATH_RE = re.compile(r"anti-censorship/pluggable-transports(?:/([a-z0-9_.-]+))?", re.I)
_PT_GENERIC_RE = re.compile(r"\bpluggable[- ]transports?\b", re.I)
_PT_HIGH_IMPACT_RE = re.compile(
    r"\b(?:"
    r"security|vulnerabilit\w*|exploit\w*|panic\w*|crash(?:es|ed|ing)?|exhaust\w*|ddos|dos|"
    r"denial[- ]of[- ]service|oom|out[- ]of[- ]memory|deadlock\w*|outage\w*|unreachable|nginx|"
    r"handshake\s+(?:fail\w*|stall\w*|broken|timeout\w*)|"
    r"websocket\s+(?:fail\w*|stall\w*|broken|timeout\w*)|"
    r"censorship|block(?:ed|ing)\b|regression\b|leak\w*|ttp"
    r")\b",
    re.I,
)


def _match_pt_family(text: str) -> str | None:
    for family, pattern in _PT_FAMILY_PATTERNS:
        if pattern.search(text):
            return family
    return None


def item_pt_family(item: dict) -> str | None:
    """Return the normalized pluggable-transport family for `item`, or None."""
    if not isinstance(item, dict):
        return None
    url = str(item.get("url") or "")
    if repo_match := _PT_REPO_PATH_RE.search(url):
        if repo_match.group(1):
            norm_repo = "obfs4" if repo_match.group(1).lower() == "obfs4proxy" else repo_match.group(1).lower()
            if norm_repo in {"snowflake", "webtunnel", "lyrebird", "obfs4", "conjure"}:
                return norm_repo
    meta_text = " ".join(
        str(v)
        for v in (
            *(item.get("labels") or ()),
            *(item.get("tags") or ()),
            item.get("title") or "",
        )
        if isinstance(v, str) and v
    )
    if family := _match_pt_family(meta_text):
        return family
    body = next((item[k] for k in ("unquoted_content", "source_content", "content") if isinstance(item.get(k), str)), "")
    if not body and isinstance(item.get("passages"), list):
        body = "\n".join(
            str(p.get("text") or "")
            for p in item["passages"]
            if isinstance(p, dict) and isinstance(p.get("text"), str)
        )
    if body and _url_host(url) == LIST_ARCHIVE_HOST:
        body = "\n".join(ln for ln in body.splitlines() if not ln.lstrip().startswith(">"))
    if family := _match_pt_family(body):
        return family
    if _PT_REPO_PATH_RE.search(url) or _PT_GENERIC_RE.search(meta_text):
        return "pluggable-transports"
    return None


def is_housekeeping_item(item: dict) -> tuple[str, str] | None:
    """Return a deterministic housekeeping skip `(code, reason)` when safe, else None."""
    if not isinstance(item, dict) or item.get("kind") == "tag" or item.get("origin") == "network-health":
        return None
    if item.get("public_comments"):
        return None
    labels = folded_labels(item)
    if (
        labels & _PROTECTED_HOUSEKEEPING_LABELS
        or any(lbl.startswith("severity::") for lbl in labels)
        or mandatory_news_rule(item) is not None
        or is_hackerone_item(item)
        or is_trove_item(item)
        or bool(cve_ids(item))
        or bool(trove_ids(item))
    ):
        return None
    full_text = _source_full_text(item)
    if (
        _HOUSEKEEPING_SECURITY_SIGNAL_RE.search(full_text)
        or _HOUSEKEEPING_RUNTIME_GUARD_RE.search(full_text)
        or (item_pt_family(item) is not None and _PT_HIGH_IMPACT_RE.search(full_text))
    ):
        return None
    if is_dirauth_item(item) and _DIRAUTH_OPERATIONAL_TOPIC_RE.search(full_text) and not _DIRAUTH_CHORE_RE.search(full_text):
        return None
    cleaned_title, _ = _strip_subject_prefixes(item.get("title"))
    author = str(item.get("author") or "").strip().lower()
    if _DEPENDENCY_CHORE_RE.search(cleaned_title) or author in _BOT_DEP_AUTHORS:
        return "skipped.gate.housekeeping", "Routine non-security dependency update"
    if _CI_PIPELINE_CHORE_RE.search(cleaned_title):
        return "skipped.gate.housekeeping", "Routine CI or build pipeline housekeeping item"
    if _HOUSEKEEPING_TITLE_PAT_RE.search(cleaned_title):
        return "skipped.gate.housekeeping", "Routine checklist or housekeeping item"
    has_behavior_change = bool(
        _HOUSEKEEPING_BEHAVIOR_CHANGE_RE.search(full_text) or _TITLE_COMPOUND_CHANGE_RE.search(cleaned_title)
    )
    if not has_behavior_change and _TEST_CHORE_RE.search(cleaned_title):
        return "skipped.gate.housekeeping", "Routine test suite housekeeping item"
    if not has_behavior_change and _INTERNAL_CLEANUP_RE.search(cleaned_title):
        return "skipped.gate.housekeeping", "Routine internal refactor or TODO cleanup item"
    return None


def is_pt_high_impact(item: dict) -> bool:
    """Return whether `item` involves a pluggable transport with a security, crash, or availability signal."""
    if not isinstance(item, dict) or item_pt_family(item) is None:
        return False
    if is_housekeeping_item(item) is not None:
        return False
    labels = folded_labels(item)
    if (
        labels & _PROTECTED_HOUSEKEEPING_LABELS
        or any(lbl.startswith("severity::") for lbl in labels)
        or is_hackerone_item(item)
        or is_trove_item(item)
        or bool(cve_ids(item))
        or bool(trove_ids(item))
    ):
        return True
    full_text = _source_full_text(item)
    return bool(_HOUSEKEEPING_SECURITY_SIGNAL_RE.search(full_text) or _PT_HIGH_IMPACT_RE.search(full_text))
