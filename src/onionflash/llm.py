"""Shared model completion client, error contract and schema/text validators."""

from __future__ import annotations

import codecs
import json
import os
import re
import threading
import time
import unicodedata
from collections.abc import Iterable

from .config import completion_budget_seconds
from .schema import CATEGORIES, CONFIDENCES, STATES
from .transport import DeadlineReached, FetchError, HttpClient, Response, is_event_stream

_HTTP_CLIENT_CLASS = HttpClient
from .util import (  # noqa: E402
    LIST_ARCHIVE_HOST, _url_host, has_invalid_text_chars, is_dirauth_category_story, is_trove_item,
    should_confirm_merged_mr, should_confirm_official_feed, strict_json,
)

_ACRONYM_ALLOWLIST = frozenset({
    "TOR", "ARTI", "TCP", "UDP", "TLS", "SSL", "DNS", "HTTP", "HTTPS", "SOCKS", "SOCKS4",
    "SOCKS5", "CPU", "RAM", "POW", "DOS", "DDOS", "HSDIR", "HSDIRS", "IPV4", "IPV6", "OR",
    "ORPORT", "DIRPORT", "DIRAUTH", "AROI", "RFC", "IETF", "CVE", "TROVE", "API", "CLI",
    "GUI", "VPN", "NAT", "ASN", "BGP", "BSD", "GNU", "SSH", "GPG", "PGP", "RSA", "SHA",
    "AES", "KDF", "KEM", "CIRC", "SYN", "ACK", "RST", "FIN", "SNI", "ALPN", "QUIC",
    "JSON", "TOML", "YAML", "HTML", "XML", "RSS", "REST", "SQL", "URL", "URI", "UUID",
    "GID", "OID", "MAC", "HMAC", "AEAD", "NTOR", "CONFLUX", "VANGUARDS", "EXIT", "GUARD",
    "PF", "NAT64", "ICMP", "OS", "IO", "CI", "MR", "PR", "ID", "IP", "AS", "UTC", "GMT",
    "EOF", "OOM", "PID", "UID", "FD", "FIFO", "LRU", "TTL", "MTU", "MSS", "RTT", "BPS",
    "KB", "MB", "GB", "TB", "KIB", "MIB", "GIB",
})
_UPPER_WORD = r"(?:[A-Z][A-Z0-9]*'[A-Z]+|[A-Z]{2,}[0-9]*)"
_UPPER_WORD_RE = re.compile(rf"(?<![A-Za-z0-9_]){_UPPER_WORD}(?![A-Za-z0-9_])")
_SHOUT_RUN_RE = re.compile(
    rf"(?<![A-Za-z0-9_]){_UPPER_WORD}"
    rf"(?:[\s&/+|-]+(?:[A-Z](?![A-Za-z0-9_])[\s&/+|-]+)*{_UPPER_WORD}){{2,}}(?![A-Za-z0-9_])"
)
_MALFORMED_TOR_VERSION_RE = re.compile(
    r"(?:"
    r"(?:tor\s+(?:v|version\s+|release\s+|stable\s+|alpha\s+)?|(?:post|pre|since|after|before|to|from|running|on)[- ])"
    r"v?0\.[34]\.[1-9][0-9]\b(?!\.\d)"
    r"|"
    r"(?<![\w.])v?0\.[34]\.[1-9][0-9](?!\.\d)\s+(?:upgrade|upgrades|release|releases|relay|relays|branch|build|daemon)\b"
    r")",
    re.IGNORECASE,
)
_SIC_PREFIX_RE = re.compile(
    r"\b(?:written(?:\s+literally)?\s+as|spelled\s+as|quoted\s+as|misspelled(?:\s+as)?|"
    r"(?:version\s+)?typo(?:\s+(?:for|of|in)|\s*[:,])?)\s+[\"'“‘`]?(?:(?:c[-\s]?)?tor\s+v?)?$",
    re.IGNORECASE,
)
_SIC_SUFFIX_RE = re.compile(
    r"^\s*[\"'”’`]?(?:\s+(?:release|upgrade|version))?\s*"
    r"(?:\[\s*sic\s*\]|\(\s*sic\s*\)|,\s*sic\b|typo\b|\([^()\n]{0,35}\b(?:sic|typo)\b[^()\n]{0,35}\))",
    re.IGNORECASE,
)


class AnalysisError(Exception):
    """Non-publishing writer or review error with retryability and decision code."""

    code = "writer.invalid_output"  # logged as failed.<code> when it is the item's third failure

    def __init__(self, message: str, retryable: bool = False, *, code: str | None = None):
        super().__init__(message)
        self.retryable = retryable
        if code is not None:
            self.code = code


class CompletionDeferred(Exception):
    """No request was sent because the run no longer admits completions."""


class RequestObserver:
    """A reservation callback may also persist transport outcomes before parsing."""

    def __call__(self, delta: int) -> None:
        raise NotImplementedError

    def response_received(self) -> None:
        """Record that an HTTP response arrived before parsing completion output."""

    def transport_failed(self) -> None:
        """Record that transport failed before an HTTP completion response arrived."""


def has_shouting_caps(text: str) -> bool:
    """Return whether text contains a 3+ word ALL-CAPS run beyond technical acronyms."""
    for match in _SHOUT_RUN_RE.finditer(text):
        words = _UPPER_WORD_RE.findall(match.group(0))
        if len(words) >= 3 and sum(1 for word in words if word not in _ACRONYM_ALLOWLIST) >= 2:
            return True
    return False


def has_malformed_tor_version(text: str, products: list[str] | tuple[str, ...] = ()) -> bool:
    """Return whether text cites a nonexistent three-part C-Tor version such as 0.4.17."""
    if products and "tor" not in products and "network" not in products:
        return False
    return any(
        not (_SIC_PREFIX_RE.search(text[max(0, m.start() - 48) : m.start()])
             or _SIC_SUFFIX_RE.search(text[m.end() : m.end() + 80]))
        for m in _MALFORMED_TOR_VERSION_RE.finditer(text)
    )


def validate_text(value: object, maximum: int, *, empty: bool = False,
                  error: type[Exception] = AnalysisError, message: str = "Invalid model text") -> str:
    """Strip and bound model text while rejecting control or noncharacter code points."""
    if not isinstance(value, str) or len(value) > maximum or has_invalid_text_chars(value):
        raise error(message)
    stripped = value.strip()
    if not stripped and not empty:
        raise error(message)
    return stripped


def validate_schema_field(value: object, rule: dict, *, empty: bool = False,
                          error: type[Exception] = AnalysisError, message: str = "Invalid model field"):
    """Validate and normalize one string, boolean, enum, or string-array schema property."""
    kind = rule.get("type")
    if kind == "string":
        if "enum" in rule:
            if not isinstance(value, str) or value not in rule["enum"]:
                raise error(message)
            return value
        return validate_text(value, rule["maxLength"], empty=empty, error=error, message=message)
    if kind == "array":
        member = rule["items"]
        if (
            not isinstance(value, list)
            or len(value) > rule["maxItems"]
            or any(
                not isinstance(v, str)
                or (v not in member["enum"] if "enum" in member else len(v) > member["maxLength"] or has_invalid_text_chars(v))
                for v in value
            )
        ):
            raise error(message)
        return list(dict.fromkeys(value)) if "enum" in member else value
    if kind == "boolean":
        if type(value) is not bool or ("enum" in rule and value not in rule["enum"]):
            raise error(message)
        return value
    raise ValueError(f"Unsupported schema rule type: {kind!r}")


def is_complete_sentence(text: str) -> bool:
    """Return whether stripped text contains alphanumeric content and terminal punctuation."""
    stripped = text.strip()
    return bool(stripped) and stripped[-1] in '.!?"\')”’' and any(c.isalnum() for c in stripped)


def tag_name(item: dict) -> str:
    """Extract and bound a non-empty tag title for deterministic tag notices."""
    name = item["title"].strip()
    if not name or len(name) > 500:
        raise AnalysisError("Invalid tag name", code="app.invalid_tag_name")
    return name


def strip_unreleased_tag(story: dict) -> None:
    """Remove a redundant release tag when a draft is neither a release nor tagged/released."""
    if (story.get("category") != "release" and story.get("state") not in {"released", "tagged"}
            and "release" in (story.get("tags") or ())):
        story["tags"] = [tag for tag in story["tags"] if tag != "release"]


def unquoted_text(text: str) -> str:
    """Drop >-quoted reply lines so own-item updates use only unquoted prose."""
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith(">"))


_MAIL_QUOTE_INTRO_RE = re.compile(
    r"^(?:on\s+.+\bwrote\s*:|am\s+.+\bschrieb\b.*:|le\s+.+\ba\s+écrit\s*:|[- ]*original message[- ]*)$",
    re.IGNORECASE,
)
_ORIGINAL_MSG_RE = re.compile(r"^[- ]*original message[- ]*$", re.IGNORECASE)
_DATED_QUOTE_INTRO_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}\b.+\b(?:wrote\s*:|schrieb\b.*:|a\s+écrit\s*:)$",
    re.IGNORECASE,
)
_FROM_HEADER_RE = re.compile(r"^from:\s+.+$", re.IGNORECASE)
_FORWARDED_HEADER_RE = re.compile(r"^(?:sent|date|to|cc|bcc|reply-to|subject):\s+.+$", re.IGNORECASE)
_QUOTE_ATTRIBUTION_END_RE = re.compile(r"\b(?:wrote\s*:|schrieb\b.*:|a\s+écrit\s*:)$", re.IGNORECASE)
_QUOTE_WEEKDAY_PREFIX_RE = re.compile(
    r"^(?:on|am|le)\s+(?:mon(?:day)?|tue(?:sday)?|wed(?:nesday)?|thu(?:rsday)?|fri(?:day)?|"
    r"sat(?:urday)?|sun(?:day)?|montag|dienstag|mittwoch|donnerstag|freitag|samstag|sonntag|"
    r"lundi|mardi|mercredi|jeudi|vendredi|samedi|dimanche),?$",
    re.IGNORECASE,
)
_NON_BOUNDARY_SUFFIX_RE = re.compile(
    r"(?:"
    r"\b\d{1,2}:\d{2}(?::\d{2})?:$"
    r"|(?:^|[\s.(])[A-Za-z]\.$"
    r"|\b(?:janv?|feb|févr|fevr|mar|märz?|apr|avr|may|mai|jun|juin|jul|juil|aug|août|aout|"
    r"sept?|oct|okt|nov|dec|déc|dez|mon|tue|tues|wed|thu|thur|thurs|fri|sat|sun|"
    r"lun|mar|mer|jeu|ven|sam|dim|mr|mrs|ms|dr|prof|st|jr|sr)\.$"
    r")",
    re.IGNORECASE,
)


def _is_standalone_quote_header(line: str) -> bool:
    norm = unicodedata.normalize("NFC", line)
    return bool(
        _MAIL_QUOTE_INTRO_RE.match(norm)
        or _FROM_HEADER_RE.match(norm)
        or _DATED_QUOTE_INTRO_RE.match(norm)
    )


def _is_span_boundary(line: str) -> bool:
    return bool(line) and line[-1] in ".!?:" and not _NON_BOUNDARY_SUFFIX_RE.search(line)


def _dropped_dated_attribution(norm_lines: list[str], drop: list[bool], quoted: list[bool], start: int) -> bool:
    if not re.match(r"^\d{4}-\d{2}-\d{2}\b", norm_lines[start]):
        return False
    end = start
    while end < len(norm_lines) and drop[end] and not quoted[end] and norm_lines[end]:
        end += 1
    return end > start and bool(_QUOTE_ATTRIBUTION_END_RE.search(norm_lines[end - 1]))


def _forwarded_header_block_end(
    norm_lines: list[str],
    drop: list[bool],
    quoted: list[bool],
    nonblank,
    start: int,
    *,
    has_original_marker: bool,
) -> int | None:
    end = start + 1
    while end < len(norm_lines) and norm_lines[end] and _FORWARDED_HEADER_RE.match(norm_lines[end]):
        end += 1
    if end <= start + 1:
        return None
    after = nonblank(end)
    if after < len(norm_lines) and (quoted[after] or (has_original_marker and drop[after])):
        return end
    return None


def unquoted_mail_text(text: str) -> str:
    """Strip >-quoted reply lines and quote-attribution headers preceding them."""
    lines = text.splitlines()
    norm_lines = [unicodedata.normalize("NFC", line).strip() for line in lines]
    quoted = [line.lstrip().startswith(">") for line in lines]
    drop = list(quoted)
    nonblank = lambda start: next((i for i in range(start, len(lines)) if norm_lines[i]), len(lines))
    prev_nonblank = lambda before: next((i for i in range(before - 1, -1, -1) if norm_lines[i]), -1)
    for index in range(len(lines) - 1, -1, -1):
        if drop[index] or not (stripped := norm_lines[index]):
            continue
        probe = nonblank(index + 1)
        if _FROM_HEADER_RE.match(stripped):
            prev = prev_nonblank(index)
            has_orig = prev >= 0 and bool(_ORIGINAL_MSG_RE.match(norm_lines[prev]))
            if block_end := _forwarded_header_block_end(
                norm_lines, drop, quoted, nonblank, index, has_original_marker=has_orig
            ):
                for k in range(index, block_end):
                    drop[k] = True
                continue
            if probe < len(lines) and (quoted[probe] or (has_orig and drop[probe])):
                drop[index] = True
                continue
        if (
            ((probe == len(lines) or drop[probe]) and _MAIL_QUOTE_INTRO_RE.match(stripped))
            or (probe < len(lines) and quoted[probe] and _DATED_QUOTE_INTRO_RE.match(stripped))
            or (
                probe < len(lines)
                and drop[probe]
                and not quoted[probe]
                and _QUOTE_WEEKDAY_PREFIX_RE.match(stripped)
                and _dropped_dated_attribution(norm_lines, drop, quoted, probe)
            )
        ):
            drop[index] = True
            continue
        if _is_span_boundary(stripped):
            continue
        for span_len in (2, 3):
            end = index + span_len
            if end > len(lines):
                continue
            cont = norm_lines[index + 1 : end]
            if any(
                not cont[offset]
                or drop[index + 1 + offset]
                or _is_standalone_quote_header(cont[offset])
                or (offset < span_len - 2 and _is_span_boundary(cont[offset]))
                for offset in range(span_len - 1)
            ):
                continue
            after_span = nonblank(end)
            joined = " ".join([stripped, *cont])
            if (
                (after_span == len(lines) or drop[after_span]) and _MAIL_QUOTE_INTRO_RE.match(joined)
            ) or (after_span < len(lines) and quoted[after_span] and _DATED_QUOTE_INTRO_RE.match(joined)):
                for k in range(index, end):
                    drop[k] = True
                break
    kept = "\n".join(line for line, remove in zip(lines, drop) if not remove)
    return re.sub(r"\n{3,}", "\n\n", kept).strip()


def is_quoted_list_post(url: object, text: str) -> bool:
    """Return whether `text` is a `lists.torproject.org` post containing `>`-quoted lines."""
    return _url_host(url) == LIST_ARCHIVE_HOST and any(ln.lstrip().startswith(">") for ln in text.splitlines())


_TRAILING_VERSION_FRAGMENT_RE = re.compile(
    r"(?:(?<![A-Za-z0-9.])0\.\d+(?:\.\d+)?\.|\bv?\d+\.\d+(?:\.\d+)*\.[A-Za-z]|[<>]=?\s*(?:v?\d+(?:\.\d+)*\.[xX]\.?|v?\d+\.|\.?))$"
)
_TRAILING_INCOMPLETE_WORD_RE = re.compile(
    r"(?:\b(?i:and|or|but|for|with|to|of|from|that|which|because|since|while|when|if|the)\b|\b(?:a|an)\b)\s*[.!]?$"
)
_CONCRETE_QUALIFIER_AHEAD = (
    r"(?!(?:\s+(?:by|when|against|from|because|after|during|where|under)\b"
    r"|\s+of\s+(?!the\s+(?:tor\s+)?network\b)\w+))"
)
_GENERIC_FILLER_RE = re.compile(
    r"(?:"
    r"\b(?:helps?\s+)?protect(?:s|ing)?\s+users?['’]?\s+privacy\b" + _CONCRETE_QUALIFIER_AHEAD
    + r"|\b(?:helps?\s+)?improv(?:e|es|ing)\s+(?:overall\s+)?(?:security|privacy|reliability)(?:\s*(?:,|and|or|/)\s*(?:security|privacy|reliability|stability))*" + _CONCRETE_QUALIFIER_AHEAD
    + r"|\b(?:helps?\s+)?enhanc(?:e|es|ing)\s+(?:overall\s+)?(?:security|privacy|reliability)(?:\s*(?:,|and|or|/)\s*(?:security|privacy|reliability|stability))*" + _CONCRETE_QUALIFIER_AHEAD
    + r"|\bmaintain\s+privacy\s+and\s+security\b" + _CONCRETE_QUALIFIER_AHEAD
    + r"|\bmaintain\s+network\s+stability\s+and\s+prevent\s+widespread\s+service\s+disruption\b"
    r"|\bupdated\s+security\s+components\s+and\s+bug\s+fixes\b"
    r"|\bscope\s+and\s+consequences\s+remain\s+subject\s+to\b"
    r")",
    re.IGNORECASE,
)
_UNMATCHED_IMPACT_DELIMITERS = (("(", ")"), ("[", "]"), ("“", "”"))
_META_LINK_CTA_RE = re.compile(
    r"(?:"
    r"\bclick\s+here\b"
    r"|\blink(?:s)?\s+below\b"
    r"|\blinked\s+(?:below|above)\b"
    r"|\bfollow\s+(?:the|this)\s+link\b"
    r"|\bvisit\s+(?:the|this)\s+link\b"
    r"|\b(?:see|check|read|refer\s+to|view|open)\s+(?:the\s+)?linked?\b"
    r"|\b(?:complete|fill\s+out|take|participate\s+in)\s+(?:the\s+)?survey\s+(?:via|using|at|through)\s+(?:the|this)\s+link\b"
    r"|\b(?:respond|reply|submit)\s+(?:via|using|at|through)\s+(?:the|this)\s+link\b"
    r"|\b(?:via|using|through)\s+(?:the|this)\s+link\b"
    r"|\bdirects?\s+readers?\s+to\s+(?:read|visit|see|check|view|follow|click)\b"
    r")",
    re.IGNORECASE,
)
_CONCRETE_IMPACT_RE = re.compile(
    r"\b(?:"
    r"crash\w*|panic\w*|leak\w*|bypass\w*|compromis\w*|dos|ddos|denial[- ]of[- ]service|"
    r"outage\w*|unreachable|corrupt\w*|truncat\w*|exhaust\w*|deanonymiz\w*|vulnerabilit\w*|"
    r"exploit\w*|stall\w*|fail(?:s|ed|ing|ure)?|cannot\s+connect|unable\s+to|evict\w*|"
    r"degrad\w*|overload\w*|hang\w*|deadlock\w*|memory\s+exhaust\w*|"
    r"upgrade\s+to\s+v?\d+\.\d+"
    r")\b",
    re.IGNORECASE,
)


def is_incomplete_or_filler_impact(text: str) -> str | None:
    """Detect incomplete sentence fragments or generic/meta-CTA boilerplate filler in `why_it_matters`."""
    if not isinstance(text, str):
        return None
    stripped = text.strip()
    if not stripped:
        return None
    if stripped.endswith("?") or stripped.endswith("..") or stripped.endswith("…"):
        return "incomplete_impact"
    if not is_complete_sentence(stripped):
        return "incomplete_impact"
    if any(stripped.count(left) != stripped.count(right) for left, right in _UNMATCHED_IMPACT_DELIMITERS):
        return "incomplete_impact"
    if stripped.count('"') % 2 != 0 or stripped.count("`") % 2 != 0:
        return "incomplete_impact"
    if _TRAILING_VERSION_FRAGMENT_RE.search(stripped) or _TRAILING_INCOMPLETE_WORD_RE.search(stripped):
        return "incomplete_impact"
    if _GENERIC_FILLER_RE.search(stripped):
        return "filler_impact"
    if _META_LINK_CTA_RE.search(stripped) and not _CONCRETE_IMPACT_RE.search(stripped):
        return "filler_impact"
    return None


_URL_OR_COMMIT_SHA_RE = re.compile(
    r"(https?://(?:[^\s<>\"'()]+|\([^\s<>\"'()]*\))+)|(?<![0-9A-Za-z_$-])([0-9a-f]{40})(?![0-9A-Za-z_-])"
)
_NON_COMMIT_HEX_PREFIX_RE = re.compile(
    r"(?:\b(?:fingerprints?|v3ident|relay(?:\s+id(?:entity)?)?|identity(?:\s+key)?|signing(?:\s+key)?|"
    r"rsa|ed25519|digests?|sha-?256|sha-?1)(?:\s*(?:is|are|=|:))?[\s`\"'(\[]*"
    r"(?:[0-9a-f]{40}(?:\s*(?:,|and|or|/)\s*|[`\"')\]\s]+))*|(?<![a-z])[a-z0-9_.-]+=\s*[`\"'(\[]?)$",
    re.IGNORECASE,
)
_COMMIT_SHA_ALLOWED_PREFIX_RE = re.compile(
    r"(?:^|[\s(`\[@,]|\b(?:commit|revision|rev|at)\s*(?:[:=#]|\s+)?)$",
    re.IGNORECASE,
)
_TRACKER_OPENER_RE = re.compile(
    r"^(?:"
    r"(?:an?\s+)?(?:opened\s+|open\s+|closed\s+|merged\s+|new\s+)?"
    r"(?:(?:tor(?:\s+browser|\s+project)?|arti|tails|snowflake|webtunnel|lyrebird|orbot|oniux|torspec)\s+)?"
    r"(?:gitlab\s+)?(?:issue|ticket|merge\s+request|mr|pull\s+request|pr)(?:\s+#?\d+)?\s+"
    r"(?:reports?|says?|states?|notes?|describes?|requests?|proposes?|flags?|warns?|highlights?|"
    r"details?|discusses?|asks?|suggests?|raises?|identifies?|opens?|tracks?|alleges?|claims?|announces?)\b"
    r"|(?:an?\s+)?opened\s+(?:tor(?:\s+browser|\s+project)?|arti|tails|snowflake|webtunnel|lyrebird|orbot|oniux|torspec|gitlab)\s+"
    r"(?:issue|ticket|merge\s+request|mr)\b"
    r"|(?:(?:tor(?:\s+browser|\s+project)?|arti|tails|snowflake|webtunnel|lyrebird|orbot|oniux|torspec)\s+)?"
    r"(?:gitlab\s+)?(?:issue|ticket)\s+#?\d+\s*:"
    r")",
    re.IGNORECASE,
)


def shorten_commit_hashes(text: str) -> str:
    """Shorten standalone 40-hex lowercase git commit SHAs to 8 chars without altering URLs or relay fingerprints."""
    if not isinstance(text, str) or not text:
        return text

    def _replace(match: re.Match[str]) -> str:
        url, sha = match.group(1), match.group(2)
        if url is not None:
            return url
        prefix = text[max(0, match.start() - 240) : match.start()]
        if _NON_COMMIT_HEX_PREFIX_RE.search(prefix) or not _COMMIT_SHA_ALLOWED_PREFIX_RE.search(prefix):
            return sha
        return sha[:8]

    return _URL_OR_COMMIT_SHA_RE.sub(_replace, text)


def has_tracker_opener(title: str) -> bool:
    """Return whether `title` opens with boilerplate tracker-log phrasing instead of the event."""
    if not isinstance(title, str):
        return False
    stripped = title.strip()
    return bool(stripped) and bool(_TRACKER_OPENER_RE.match(stripped))


def _source_item_unquoted_text(source: dict) -> str:
    url = str(source.get("url") or "")
    parts = [source["title"]] if isinstance(source.get("title"), str) and source["title"] else []
    body_key = next((k for k in ("source_content", "content", "unquoted_content") if isinstance(source.get(k), str)), None)
    body = source[body_key] if body_key is not None else ""
    passages = source.get("passages") if isinstance(source.get("passages"), list) else ()
    if not body and passages:
        p_texts = []
        for p in passages:
            txt = p if isinstance(p, str) else (p.get("text") if isinstance(p, dict) else "")
            if isinstance(txt, str) and txt:
                p_texts.append(txt)
        body = "\n".join(p_texts)
    if body:
        parts.append(unquoted_mail_text(body) if is_quoted_list_post(url, body) else body)
    if body_key == "unquoted_content" and passages:
        for p in passages:
            if isinstance(p, dict) and p.get("author") and isinstance(p.get("text"), str) and p["text"]:
                parts.append(p["text"])
    for note in (source.get("public_comments") if isinstance(source.get("public_comments"), list) else ()):
        if isinstance(note, dict) and isinstance(note.get("body"), str) and note["body"]:
            parts.append(note["body"])
    return "\n".join(parts)


def _unquoted_source_text(packet_or_item: dict) -> str:
    if not isinstance(packet_or_item, dict):
        return ""
    if isinstance(packet_or_item.get("sources"), list):
        return "\n".join(
            _source_item_unquoted_text(src)
            for src in packet_or_item["sources"]
            if isinstance(src, dict)
        )
    return _source_item_unquoted_text(packet_or_item)


_INTENDED_CONFIG_RE = re.compile(r"\bintended\s+(?:configuration|config|settings?|policy)\b", re.IGNORECASE)
_SRC_CONFIG_RE = re.compile(r"\b(?:intended\s+(?:configuration|config|settings?|policy)|configured\s+\w+|torrc)\b", re.IGNORECASE)
_LEXICAL_ADVICE_CHECKS = (
    (re.compile(r"\badvis(?:e|ed|es|ing)\b|\badvice\b", re.IGNORECASE), re.compile(r"\badvis(?:e|ed|es|ing)\b|\badvice\b", re.IGNORECASE)),
    (re.compile(r"\binstruct(?:ed|s|ing)\b", re.IGNORECASE), re.compile(r"\binstruct(?:ed|s|ing)\b", re.IGNORECASE)),
    (re.compile(r"\brecommend(?:ed|s|ing)\b", re.IGNORECASE), re.compile(r"\brecommend(?:ed|s|ing|ation)\b", re.IGNORECASE)),
)
_DIRECTIVE_TARGET_RE = re.compile(
    r"\b(?:"
    r"(?:users?|operators?|maintainers?|admins?|developers?|relays?|clients?)\s+"
    r"(?:(?:on|for|under|with|using|running)\s+(?:[a-z0-9._-]+\s+){1,5})?"
    r"(?:(?:are|were|is)\s+)?(?:(?:being|strongly|explicitly)\s+)?"
    r"(?:asked|required|told|advised|instructed|encouraged|recommended)\s+to"
    r"|(?:announcement|post|report|issue|notice|maintainers?|developers?)\s+"
    r"(?:asks?|ask|encourages?|recommends?|advises?|instructs?|requires?)\s+"
    r"(?:[\w-]+\s+){0,5}?(?:to\s+)?(?:upgrad\w*|updat\w*|switch\w*|install\w*|configur\w*|edit\w*|replac\w*|enabl\w*|disabl\w*|remov\w*|treat\w*|handl\w*|apply|us(?:e|ing))"
    r"|(?:users?|operators?|maintainers?|admins?|developers?|relays?|clients?)\s+"
    r"(?:(?:on|for|under|with|using|running)\s+(?:[a-z0-9._-]+\s+){1,5})?"
    r"(?:should|must|need\s+to)\s+(?:(?:\w+\s+){0,2})?"
    r"(?:upgrade|update|switch|install|configure|edit|replace|enable|disable|remove|handle|treat|apply)"
    r"|requir(?:es?|ing)\s+(?:[\w-]+\s+){0,3}(?:users?|operators?|relays?)\s+"
    r"(?:(?:on|for|under|with|using|running)\s+(?:[a-z0-9._-]+\s+){1,5})?to\s+\w+"
    r")\b",
    re.IGNORECASE,
)
_SRC_DIRECTIVE_CUE_RE = re.compile(
    r"(?:"
    r"(?:^|[.!?\n]\s*)(?:please\s+)?(?:upgrade|update|switch|install|configure|edit|replace|enable|disable|remove|treat|handle|apply)(?:\s+(?:to|your|the|now|as|immediately|away|over|it|them|this|that)\b)"
    r"|\b(?:"
    r"asks?|asked|asking"
    r"|please\s+(?:upgrade|update|switch|install|configure|edit|replace|enable|disable|remove|treat|handle|apply)"
    r"|encourag(?:e|es|ed|ing)"
    r"|recommend(?:s|ed|ing|ation)?"
    r"|advis(?:e|es|ed|ing)|advice"
    r"|instruct(?:s|ed|ing)"
    r"|requir(?:e|es|ed|ing)\s+(?:[\w-]+\s+){0,3}(?:users?|operators?|relays?|them|you|all)\s+to"
    r"|must\s+(?!-\s*fix)(?:upgrade|update|switch|install|configure|edit|replace|enable|disable|remove|treat|handle|apply)"
    r"|should\s+(?!be\s+(?:affected|able\s+to)\b)(?:upgrade|update|switch|install|configure|edit|replace|enable|disable|remove|treat|handle|apply)"
    r")\b"
    r")",
    re.IGNORECASE,
)
_ACTION_IN_TEXT_RE = re.compile(
    r"\b(?:to|should|must|encourages?|recommends?)\s+(?:\w+\s+){0,2}?"
    r"(upgrade|upgrading|update|updating|switch|switching|install|installing|configure|configuring|"
    r"edit|editing|replace|replacing|enable|enabling|disable|disabling|remove|removing|treat|treating|handle|handling|apply|applying)\b",
    re.IGNORECASE,
)
_SRC_ACTION_WORDS_RE = re.compile(
    r"\b(upgrade|upgrading|update|updating|switch|switching|install|installing|configure|configuring|"
    r"edit|editing|replace|replacing|enable|enabling|disable|disabling|remove|removing|treat|treating|handle|handling|apply|applying)\b",
    re.IGNORECASE,
)


_DIRECTIVE_CUE_PREFIX = (
    r"(?:please|ask(?:s|ed|ing)?|encourag\w*|recommend\w*|advis\w*|instruct\w*|"
    r"should(?:\s+also)?(?!\s+be\s+(?:affected|able\s+to)\b)|must(?!-\s*fix))"
)
_EXPLICIT_IMPERATIVE_CUE_PREFIX = (
    r"(?:please|ask(?:s|ed|ing)?|encourag\w*|instruct\w*|"
    r"should(?:\s+also)?(?!\s+be\s+(?:affected|able\s+to)\b)|must(?!-\s*fix))"
)
_CLAUSE_STOP_RE = re.compile(
    r"[.!?;,\n]|\s+(?:to\s+(?:prevent|avoid|receive|maintain|ensure|protect|mitigate|keep)|because|since|so\s+that|which|that|if|when|while|after|before)\b|—|--",
    re.IGNORECASE,
)
_DIRECTIVE_OBJ_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9._-]*")
_DIRECTIVE_OBJ_STOPWORDS = frozenset({
    "a", "an", "the", "this", "that", "these", "those", "it", "them", "their", "your", "our", "its",
    "to", "for", "of", "in", "on", "at", "by", "with", "from", "as", "into", "over", "away", "up", "out",
    "and", "or", "all", "any", "new", "latest", "newest", "current", "existing", "immediately", "now", "soon",
    "asap", "explicitly", "properly", "carefully", "users", "user", "operators", "operator", "maintainers",
    "maintainer", "admins", "admin", "developers", "developer", "relays", "relay", "clients", "client",
    "bridges", "bridge", "authorities", "authority", "possible", "affected", "tor", "arti", "report",
    "reports", "issue", "issues", "story", "notice", "release", "releases", "version", "versions", "channel",
    "default", "defaults", "mode", "setting", "settings", "option", "options", "flag", "flags", "output",
})
_SCOPE_QUALIFIER_ALIASES = {
    "windows": "windows", "win32": "windows", "win64": "windows",
    "macos": "macos", "osx": "macos", "darwin": "macos",
    "linux": "linux", "android": "android", "ios": "ios",
    "bsd": "bsd", "freebsd": "freebsd", "openbsd": "openbsd", "netbsd": "netbsd",
    "debian": "debian", "ubuntu": "ubuntu", "fedora": "fedora", "rhel": "rhel", "centos": "centos", "alpine": "alpine",
    "tails": "tails", "whonix": "whonix",
    "arm64": "arm64", "aarch64": "arm64", "x86_64": "x86_64", "amd64": "x86_64", "32-bit": "32-bit", "64-bit": "64-bit",
    "exit": "exit", "exits": "exit", "guard": "guard", "guards": "guard",
    "bridge": "bridge", "bridges": "bridge", "relay": "relay", "relays": "relay",
    "snowflake": "snowflake", "webtunnel": "webtunnel", "obfs4": "obfs4", "obfs4proxy": "obfs4",
    "lyrebird": "lyrebird", "conjure": "conjure",
    "dirauth": "dirauth", "dirauths": "dirauth", "authority": "dirauth", "authorities": "dirauth",
    "onion": "onion", "fallback": "fallback", "fallbacks": "fallback",
    "docker": "container", "container": "container", "containers": "container",
    "sandbox": "sandbox", "ipv6": "ipv6", "ipv4": "ipv4",
    "experimental": "experimental", "opt-in": "opt-in", "nightly": "nightly", "alpha": "alpha", "beta": "beta",
}
_SCOPE_PHRASE_PATTERNS = (
    (re.compile(r"\bos\s+x\b", re.IGNORECASE), "macos"),
    (re.compile(r"\bdirectory\s+authorit(?:y|ies)\b", re.IGNORECASE), "dirauth"),
    (re.compile(r"\b(?:hidden|onion)\s+services?\b", re.IGNORECASE), "onion"),
)
_HARD_CLAUSE_STOP_RE = re.compile(r"\.(?!\d)|[!?;:\n]|—|--")
_INDEP_CLAUSE_SPLIT_RE = re.compile(r",\s+(?:and|but|while|whereas|however|meanwhile)\b", re.IGNORECASE)
_GOVERNING_INTRO_RE = re.compile(
    r"^\s*(?:if|when|for|on|under|in|with|using|running|unless|where|only)\b",
    re.IGNORECASE,
)
_TAIL_SCOPE_COND_RE = re.compile(
    r"\b(?:on|for|under|with|using|running|if|when)\s+((?:[^.!?;,\n]|\.(?=\d)){1,60})",
    re.IGNORECASE,
)


def _extract_scope_qualifiers(text: str) -> set[str]:
    """Extract canonical audience, platform, and deployment scope qualifiers from `text`."""
    qualifiers = {canon for pattern, canon in _SCOPE_PHRASE_PATTERNS if pattern.search(text)}
    for raw in _DIRECTIVE_OBJ_TOKEN_RE.findall(text.lower()):
        cleaned = raw.strip("._-")
        if canon := _SCOPE_QUALIFIER_ALIASES.get(cleaned):
            qualifiers.add(canon)
    return qualifiers


def _directive_scope_qualifiers(text: str, start: int, action_end: int) -> set[str]:
    """Return canonical qualifiers from the matched directive clause and governing conditions only."""
    left_matches = list(_HARD_CLAUSE_STOP_RE.finditer(text, 0, start))
    hard_left = left_matches[-1].end() if left_matches else 0
    right_match = _HARD_CLAUSE_STOP_RE.search(text, action_end)
    hard_right = right_match.start() if right_match else len(text)
    prefix = _INDEP_CLAUSE_SPLIT_RE.split(text[hard_left:action_end])[-1]
    parts = prefix.split(",")
    qualifiers = _extract_scope_qualifiers(parts[-1])
    for leading in parts[:-1]:
        if _GOVERNING_INTRO_RE.match(leading):
            qualifiers.update(_extract_scope_qualifiers(leading))
    tail = _INDEP_CLAUSE_SPLIT_RE.split(text[action_end:hard_right], 1)[0]
    for prep_match in _TAIL_SCOPE_COND_RE.finditer(tail):
        qualifiers.update(_extract_scope_qualifiers(prep_match.group(1)))
    return qualifiers


def _action_stem(action: str) -> str:
    if action.startswith("upgrad"):
        return "upgrad"
    if action.startswith("updat"):
        return "updat"
    if action.startswith("appl"):
        return "appl"
    return action[:5]


def _normalize_obj_token(token: str) -> str:
    if len(token) > 4 and token.endswith("ing"):
        base = token[:-3]
        if len(base) >= 3 and base[-1] == base[-2]:
            base = base[:-1]
        return base
    if len(token) > 4 and token.endswith("ation"):
        return token[:-5]
    if len(token) > 4 and token.endswith("ed"):
        return token[:-2]
    if len(token) > 3 and token.endswith("s"):
        return token[:-1]
    return token


def _directive_obj_tokens(fragment: str) -> list[str]:
    clause = _CLAUSE_STOP_RE.split(fragment, 1)[0]
    tokens: list[str] = []
    for raw in _DIRECTIVE_OBJ_TOKEN_RE.findall(clause.lower()):
        cleaned = raw.strip("._-")
        if not cleaned or cleaned in _DIRECTIVE_OBJ_STOPWORDS:
            continue
        if cleaned not in tokens:
            tokens.append(cleaned)
    return tokens


def _obj_tokens_match(draft_tok: str, src_tok: str) -> bool:
    if draft_tok == src_tok:
        return True
    norm_d, norm_s = _normalize_obj_token(draft_tok), _normalize_obj_token(src_tok)
    if norm_d == norm_s:
        return True
    if min(len(norm_d), len(norm_s)) >= 4 and (norm_d.startswith(norm_s) or norm_s.startswith(norm_d)):
        return True
    return False


def _has_near_imperative_cue(
    src: str,
    stem: str,
    cue_prefix: str,
    obj_tokens: tuple[str, ...] | list[str] = (),
    draft_quals: frozenset[str] | set[str] = frozenset(),
) -> bool:
    cue_near = re.compile(
        r"(?:\b" + cue_prefix + r"\b[^.!?\n]{0,60}\b" + stem + r"[a-z]*\b(?!\s+checks?\b)"
        r"|(?:^|[.!?\n]\s*)(?:please\s+)?" + stem + r"[a-z]*\b(?=\s+(?:to|your|the|now|as|immediately|away|over|it|them|this|that)\b))"
        r"(?P<tail>[^.!?\n]{0,120})",
        re.IGNORECASE,
    )
    matches = list(cue_near.finditer(src))
    if not matches:
        return False
    for match in matches:
        matched = match.group(0)
        lead = len(matched) - len(matched.lstrip(".!?").lstrip())
        src_quals = _directive_scope_qualifiers(src, match.start() + lead, match.start("tail"))
        if src_quals and not src_quals.issubset(draft_quals):
            continue
        if not obj_tokens:
            return True
        src_tokens = _directive_obj_tokens(match.group("tail"))
        if all(any(_obj_tokens_match(d_tok, s_tok) for s_tok in src_tokens) for d_tok in obj_tokens):
            return True
    return False


def _directive_actions_supported(
    text: str,
    src: str,
    *,
    require_all_near: bool = False,
    cue_prefix: str = _DIRECTIVE_CUE_PREFIX,
) -> bool:
    if not _SRC_DIRECTIVE_CUE_RE.search(src):
        return False
    src_actions = [word.lower() for word in _SRC_ACTION_WORDS_RE.findall(src)]
    matched_action = False
    for action_match in _ACTION_IN_TEXT_RE.finditer(text):
        matched_action = True
        action = action_match.group(1).lower()
        stem = _action_stem(action)
        if not any(word.startswith(stem) for word in src_actions):
            return False
        obj_tokens = _directive_obj_tokens(text[action_match.end() :])
        draft_quals = _directive_scope_qualifiers(text, action_match.start(), action_match.end())
        if not _has_near_imperative_cue(src, stem, cue_prefix, obj_tokens=obj_tokens, draft_quals=draft_quals):
            return False
    return matched_action or not require_all_near


def has_unattributed_advice(text: str, packet_or_item: dict) -> bool:
    """Return whether `text` invents operator/user directives or configuration claims absent from unquoted source text."""
    if not isinstance(text, str) or not text.strip():
        return False
    src = _unquoted_source_text(packet_or_item)
    if _INTENDED_CONFIG_RE.search(text) and not _SRC_CONFIG_RE.search(src):
        return True
    has_directive = bool(_DIRECTIVE_TARGET_RE.search(text))
    if has_directive and not _directive_actions_supported(text, src):
        return True
    if any(claim_re.search(text) and not src_re.search(src) for claim_re, src_re in _LEXICAL_ADVICE_CHECKS):
        if not (
            has_directive
            and _directive_actions_supported(
                text,
                src,
                require_all_near=True,
                cue_prefix=_EXPLICIT_IMPERATIVE_CUE_PREFIX,
            )
        ):
            return True
    return False


_DONE_EXCUSED_PREFIX_RE = re.compile(
    r"\b(?:should|must|will|would|could|may|might|to|be|not|never|yet|no|without|asks?|"
    r"requests?|proposes?|wants?|plans?|needs?)\s+(?:(?:yet|been|be|being|to|kept|left)\s+)*$"
)
_DONE_UNPROVEN_PREFIX_RE = re.compile(
    r"\b(?:not|never|cannot|should|must|will|would|could|may|might|to|no)\b(?:\s+\w+){0,3}\s*$"
)
_DONE_CLAUSE_BOUNDARY_RE = re.compile(
    r"(?:\.(?=\s|$)|[!?;\n]|\b(?:while|whereas|because|since|although|though|when|where|if|unless|that|and|but|or)\b)"
)
_EXT_DEP_CORE_NAMES = (
    r"openssl|libressl|boringssl|wolfssl|mbedtls|gnutls|nss|rustls|"
    r"zlib|zstd|brotli|sqlite|libevent|jemalloc|glibc|musl|"
    r"firefox|gecko|chromium|webkit|noscript|"
    r"rustc|cargo|rust\s+v?\d+(?:\.\d+|\.x)*\+?|"
    r"golang|go\s+v?\d+(?:\.\d+|\.x)*\+?|"
    r"python|nodejs|node\.js|llvm|clang|gcc|systemd|"
    r"linux|debian|ubuntu|fedora|alpine|rhel|centos|freebsd|openbsd|netbsd|macos|os\s+x|darwin|windows|android|ios|"
    r"(?:(?:the|an?|this|upstream)\s+)?(?:(?:underlying|host|target|upstream)\s+)?"
    r"(?:library|libraries|dependency|dependencies|kernel|compiler|runtime|operating\s+system|libc)"
)
_EXT_DAEMON_NAMES = r"nginx|apache|haproxy|unbound|caddy|envoy"
_DEP_VERSION_TAIL = (
    r"(?:\s+v?\d+(?:\.\d+|\.x)*[a-z0-9.+-]*)?"
    r"(?:\s*\([^()\n]{1,40}\))?"
    r"(?:,?\s+(?:which|that))?"
    r"(?:\s+(?:also|now|already|always|effectively|silently|typically|generally|by\s+default))*"
)
_EXT_DEP_CORE_SUBJECT_RE = re.compile(rf"\b(?:{_EXT_DEP_CORE_NAMES})\b{_DEP_VERSION_TAIL}\s+$")
_EXT_DAEMON_SUBJECT_RE = re.compile(rf"\b(?:{_EXT_DAEMON_NAMES})\b{_DEP_VERSION_TAIL}\s+$")
_DEFAULT_BEHAVIOR_CUE_RE = re.compile(
    r"\b(?:by\s+default|at\s+compile[- ]time|at\s+build[- ]time|in\s+default\s+(?:builds?|config(?:uration)?)|"
    r"in\s+its\s+default\s+(?:config(?:uration)?|build)|out\s+of\s+the\s+box|default\s+builds?)\b"
)
_EXT_ANY_DEP_IN_CLAUSE_RE = re.compile(rf"\b(?:{_EXT_DEP_CORE_NAMES}|{_EXT_DAEMON_NAMES})\b")
_TOR_ACTOR_SUBJECT_RE = re.compile(
    r"\b(?:tor(?:\s+browser)?|arti|snowflake|webtunnel|lyrebird|tails|orbot|oniux|"
    r"developers?|maintainers?|operators?)(?:\s+(?:has|have|had))?(?:\s+(?:already|now|also))?\s+$"
)

_DONE_SENTENCE_SPLIT_RE = re.compile(r"(?:\.(?=\s|$)|[!?]|;)")
_REQUEST_OR_NEG_PREFIX_RE = re.compile(
    r"\b(?:asks?|asked|requests?|requested|proposes?|proposed|suggests?|suggested|recommends?|recommended|"
    r"wants?|wanted|plans?|planned|needs?|needed|tries?|tried|attempts?|attempted|"
    r"instead\s+of|avoid(?:s|ed)?|prevent(?:s|ed)?|refus(?:e|es|ed)|fail(?:s|ed)?\s+to|without)\b(?:\s+\w+){0,3}\s*$"
)
_WHAT_DID_WAS_RE = re.compile(r"\bwhat\s+(?:i|we|they|he|she|@?[a-z0-9_-]+)\s+did\s+was\b")
_DID_COMPLETED_RE = re.compile(
    r"\b(?:i|we|they|he|she|@?[a-z0-9_-]+)\s+did\s+(?!not\b|never\b)"
    r"(?:(?:in\s+fact|indeed|already|actually)\s+)?$"
)
_DID_COMPOUND_RE = re.compile(
    r"\b(?:i|we|they|he|she|@?[a-z0-9_-]+)\s+did\s+(?!not\b|never\b)"
    r"(?:(?:in\s+fact|indeed|already|actually)\s+)?[a-z]+\b[^.!?;\n]{0,180}\band\s+$"
)
_AFTER_DID_BLOCKED_RE = re.compile(
    r"^\s*(?:not|never)\b|"
    r"\b(?:asks?|asked|requests?|requested|proposes?|proposed|suggests?|suggested|recommends?|recommended|"
    r"wants?|wanted|plans?|planned|needs?|needed|tries?|tried|attempts?|attempted|"
    r"whether|if|how|why|can|could|should|would|will|may|might|must)\b"
)
_APPLIED_GERUND_RE = re.compile(
    r"(?:"
    r"\b(?P<verb>applied|implemented|mitigated|resolved|fixed|completed|finished|performed|executed)\b[^.!?;]{0,60}\b(?:of|by)\s+$"
    r"|\b(?P<verb2>completed|finished)\s+$"
    r")"
)
_BASE_ING_FORMS = {
    "remove": "removing",
    "fix": "fixing",
    "patch": "patching",
    "resolve": "resolving",
    "deploy": "deploying",
    "disable": "disabling",
    "revoke": "revoking",
    "rotate": "rotating",
    "ship": "shipping",
    "merge": "merging",
}
STRICT_DONE_EQUIV_FORMS = {
    "removed": ("removed", "removes"),
    "removes": ("removes", "removed"),
    "resolved": ("resolved", "resolves"),
    "resolves": ("resolves", "resolved"),
    "deployed": ("deployed", "deploys"),
    "deploys": ("deploys", "deployed"),
    "disabled": ("disabled", "disables"),
    "disables": ("disables", "disabled"),
    "revoked": ("revoked", "revokes"),
    "revokes": ("revokes", "revoked"),
    "rotated": ("rotated", "rotates"),
    "rotates": ("rotates", "rotated"),
    "shipped": ("shipped",),
    "ships": ("ships", "shipped"),
    "merged": ("merged", "merges"),
    "merges": ("merges", "merged"),
}


def is_excused_done_verb(text: str, start: int, end: int, word: str) -> bool:
    """Return whether normalized `text[start:end]` (`word`) is modal/negated or descriptive dependency behavior."""
    if _DONE_EXCUSED_PREFIX_RE.search(text[max(0, start - 90) : start]):
        return True
    left_win = text[max(0, start - 120) : start]
    clause_before = _DONE_CLAUSE_BOUNDARY_RE.split(left_win)[-1]
    right_win = text[end : min(len(text), end + 120)]
    clause_after = _DONE_CLAUSE_BOUNDARY_RE.split(right_win, 1)[0]
    if word in {"disables", "removes", "ships"}:
        if _EXT_DEP_CORE_SUBJECT_RE.search(clause_before):
            return True
        if _EXT_DAEMON_SUBJECT_RE.search(clause_before) and _DEFAULT_BEHAVIOR_CUE_RE.search(
            clause_before + word + clause_after
        ):
            return True
    if word in {"disabled", "removed", "shipped"} and not _TOR_ACTOR_SUBJECT_RE.search(clause_before):
        clause_full = clause_before + word + clause_after
        if _DEFAULT_BEHAVIOR_CUE_RE.search(clause_full) and _EXT_ANY_DEP_IN_CLAUSE_RE.search(clause_full):
            return True
    return False


def _sentence_bounds(text: str, start: int, end: int) -> tuple[int, int]:
    sent_start = 0
    for sep in _DONE_SENTENCE_SPLIT_RE.finditer(text, 0, start):
        sent_start = sep.end()
    next_sep = _DONE_SENTENCE_SPLIT_RE.search(text, end)
    sent_end = next_sep.start() if next_sep else len(text)
    return sent_start, sent_end


def _is_factual_sentence(text: str, sent_start: int, sent_end: int, start: int, end: int | None = None) -> bool:
    if sent_end < len(text) and text[sent_end : sent_end + 1] == "?":
        return False
    sent_before = text[sent_start:start].lstrip()
    if sent_before.startswith(("if ", "whether ", "unless ")):
        return False
    clause_before = sent_before.rsplit(",", 1)[-1].lstrip()
    if re.search(r"(?<!-)\b(?:if|whether|unless)\s+", clause_before) is not None:
        return False
    sent_after = text[start if end is None else end : sent_end]
    clause_after = re.split(r",\s*(?:and|but|so|yet|while|whereas)\b", sent_after, maxsplit=1)[0]
    return re.search(r"(?<!-)\b(?:if|whether|unless)(?!-)\b", clause_after) is None


def is_action_stated_in_source(source_plain: str, word: str, *, base_forms: dict[str, str]) -> bool:
    """Return whether `word` is stated in normalized `source_plain` without negation, modal, or request framing."""
    for form in STRICT_DONE_EQUIV_FORMS.get(word, (word,)):
        for match in re.finditer(rf"\b{form}\b(?!-)", source_plain):
            prev45 = source_plain[max(0, match.start() - 45) : match.start()]
            if _DONE_UNPROVEN_PREFIX_RE.search(prev45) or _REQUEST_OR_NEG_PREFIX_RE.search(prev45):
                continue
            sent_start, sent_end = _sentence_bounds(source_plain, match.start(), match.end())
            if not _is_factual_sentence(source_plain, sent_start, sent_end, match.start(), match.end()):
                continue
            return True
    base = base_forms.get(word)
    if base is None:
        return False
    for match in re.finditer(rf"\b{base}\b(?!-)", source_plain):
        prev45 = source_plain[max(0, match.start() - 45) : match.start()]
        if _DONE_UNPROVEN_PREFIX_RE.search(prev45) or _REQUEST_OR_NEG_PREFIX_RE.search(prev45):
            continue
        sent_start, sent_end = _sentence_bounds(source_plain, match.start(), match.end())
        if not _is_factual_sentence(source_plain, sent_start, sent_end, match.start(), match.end()):
            continue
        sent_before = source_plain[sent_start : match.start()]
        was_matches = list(_WHAT_DID_WAS_RE.finditer(sent_before))
        if was_matches:
            after_was = sent_before[was_matches[-1].end() :]
            if not _AFTER_DID_BLOCKED_RE.search(after_was):
                return True
        if _DID_COMPLETED_RE.search(sent_before):
            return True
        if _DID_COMPOUND_RE.search(sent_before) and not _AFTER_DID_BLOCKED_RE.search(sent_before):
            return True
    if (ing := _BASE_ING_FORMS.get(base)) is not None:
        for match in re.finditer(rf"\b{ing}\b(?!-)", source_plain):
            sent_start, sent_end = _sentence_bounds(source_plain, match.start(), match.end())
            if not _is_factual_sentence(source_plain, sent_start, sent_end, match.start(), match.end()):
                continue
            sent_before = source_plain[sent_start : match.start()]
            clause = sent_before[-90:]
            if (ger_match := _APPLIED_GERUND_RE.search(clause)) is not None:
                v_offset = ger_match.start("verb") if ger_match.group("verb") is not None else ger_match.start("verb2")
                v_pos = max(0, len(sent_before) - len(clause)) + v_offset + sent_start
                v_prev = source_plain[max(0, v_pos - 45) : v_pos]
                if not _DONE_UNPROVEN_PREFIX_RE.search(v_prev) and not _REQUEST_OR_NEG_PREFIX_RE.search(v_prev):
                    return True
    return False


def label_limits(sources: list[dict]) -> dict:
    """The confidence, state and category labels a story told by these sources may carry: confirmed
    needs an official source that is not a tag, or a merged merge request; tagged needs a tag
    source; a story told only by merge requests is merged and not a release; issues or merge
    requests alone may not carry state released; and verified TROVE advisories must stay
    categorized as security."""
    confirmable = any((source.get("authority") == "official" and source.get("kind") != "tag")
                      or (source.get("kind") == "gitlab_mr" and source.get("upstream_state") == "merged")
                      for source in sources)
    tagged = any(source.get("kind") == "tag" for source in sources)
    merges = bool(sources) and all(source.get("kind") == "gitlab_mr" for source in sources)
    gitlab_only = bool(sources) and all(source.get("kind") in {"gitlab_issue", "gitlab_mr"} for source in sources)
    trove = any(is_trove_item(source) or source.get("mandatory_news_rule") == "trove" for source in sources)
    allowed_tags = [value for value in CATEGORIES if not merges or value != "release"]
    if merges:
        allowed_states = ["merged"]
    else:
        allowed_states = [
            value for value in STATES
            if (tagged or value != "tagged") and (not gitlab_only or value != "released")
        ]
    return {
        "confidence": [value for value in CONFIDENCES if confirmable or value != "confirmed"],
        "state": allowed_states,
        "category": ["security"] if trove else allowed_tags,
        "tags": allowed_tags,
    }


def widen_release_state_for_update(limits: dict, prior: dict | None) -> dict:
    """Preserve `'released'` in update state `limits` only when `prior` already has `state == 'released'`."""
    if not isinstance(limits, dict) or not isinstance(prior, dict):
        return limits
    if prior.get("state") == "released":
        allowed = set(limits.get("state") or ())
        allowed.add("released")
        limits["state"] = [value for value in STATES if value in allowed]
    return limits


def apply_label_limits(properties: dict, limits: dict, *, nullable: bool = False) -> None:
    """Restrict schema enum choices in place to the labels allowed by source limits."""
    def rule(field: str) -> dict:
        """Select the target property schema dictionary for nullable or required fields."""
        return properties[field]["anyOf"][0] if nullable else properties[field]

    for key, allowed in limits.items():
        if key != "tags" and key in properties:
            rule(key)["enum"] = list(allowed)
    if "tags" in properties and ("tags" in limits or "category" in limits):
        tags_allowed = limits.get("tags") or limits["category"]
        rule("tags")["items"]["enum"] = list(tags_allowed)


def repair_schema(fields: dict, required: tuple[str, ...]) -> dict:
    """Build a strict nullable JSON schema for minimal semantic review repairs."""
    return {"anyOf": [{"type": "null"}, {"type": "object", "additionalProperties": False,
        "properties": {key: {"anyOf": [rule, {"type": "null"}]} for key, rule in fields.items()},
        "required": list(required)}]}


def json_object(text: str, code: str = "writer.invalid_json") -> dict:
    """Parse a strict UTF-8 JSON object without duplicate keys, surrogates or NaNs."""
    def _unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON field")
            result[key] = value
        return result

    try:
        result = json.loads(text, object_pairs_hook=_unique)
        strict_json(result)
    except (ValueError, TypeError, RecursionError) as exc:
        raise AnalysisError("Model returned invalid JSON", code=code) from exc
    if not isinstance(result, dict):
        raise AnalysisError("Model response is not an object", code=code)
    return result


def generation_options(settings: dict) -> dict:
    """The declared generation fields sent to the completion endpoint, without credentials."""
    options = {"temperature": settings.get("temperature", 0), "max_tokens": settings["max_output_tokens"]}
    for key in ("top_p", "top_k", "min_p", "presence_penalty", "repetition_penalty", "reasoning_effort"):
        if key in settings:
            options[key] = settings[key]
    if settings["send_chat_template_kwargs"]:
        options["chat_template_kwargs"] = {"enable_thinking": settings["enable_thinking"]}
    return options


SSE_WIRE_MULTIPLIER = 16
MIN_SSE_WIRE_BYTES = 32 * 1024 * 1024
MIN_SSE_LINE_BYTES = 262144


def parse_sse_completion(chunks: Iterable[bytes], *, max_content_bytes: int) -> bytes:
    """Assemble an OpenAI-compatible SSE chat completion stream into strict JSON bytes."""
    decoder = codecs.getincrementaldecoder("utf-8")(errors="strict")
    line_limit = max(max_content_bytes, MIN_SSE_LINE_BYTES)
    line_parts: list[str] = []
    line_bytes = 0
    data_lines: list[str] = []
    parts: list[str] = []
    content_bytes = 0
    saw_content_str = False
    finish_reason: str | None = None
    skip_lf = False
    done = False

    def flush_event() -> bool:
        """Decode one accumulated SSE event payload; return False on [DONE]."""
        nonlocal content_bytes, saw_content_str, finish_reason
        if not data_lines:
            return True
        payload_str = "\n".join(data_lines)
        data_lines.clear()
        if payload_str.strip() == "[DONE]":
            return False
        try:
            chunk = json.loads(payload_str)
        except (ValueError, RecursionError):
            raise FetchError("invalid SSE response") from None
        if not isinstance(chunk, dict):
            raise FetchError("invalid SSE response")
        if chunk.get("error"):
            raise FetchError("upstream stream error")
        choices = chunk.get("choices")
        if choices == []:
            return True
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            raise FetchError("invalid SSE response")
        choice = choices[0]
        delta = choice.get("delta")
        if delta is not None:
            if not isinstance(delta, dict):
                raise FetchError("invalid SSE response")
            piece = delta.get("content")
            if piece is not None:
                if not isinstance(piece, str):
                    raise FetchError("invalid SSE response")
                saw_content_str = True
                try:
                    content_bytes += len(piece.encode("utf-8"))
                except UnicodeEncodeError:
                    raise FetchError("invalid SSE response") from None
                if content_bytes > max_content_bytes:
                    raise FetchError("response exceeds configured byte limit")
                parts.append(piece)
        reason = choice.get("finish_reason")
        if reason is not None:
            if not isinstance(reason, str):
                raise FetchError("invalid SSE response")
            if reason:
                finish_reason = reason
        return True

    def finish_line() -> bool:
        """Consume the current buffered SSE line and reset line state."""
        nonlocal line_bytes
        line = "".join(line_parts)
        line_parts.clear()
        line_bytes = 0
        if not line:
            return flush_event()
        if line.startswith(":"):
            return True
        field, sep, value = line.partition(":")
        if sep and value.startswith(" "):
            value = value[1:]
        if field == "data":
            data_lines.append(value)
        return True

    def append_segment(segment: str) -> None:
        """Append decoded text to the active SSE line within the per-line byte bound."""
        nonlocal line_bytes
        if not segment:
            return
        seg_bytes = len(segment.encode("utf-8"))
        if line_bytes + seg_bytes > line_limit:
            raise FetchError("response exceeds configured byte limit")
        line_bytes += seg_bytes
        line_parts.append(segment)

    def feed_text(text: str) -> None:
        """Split decoded UTF-8 text into CRLF/LF/CR SSE lines across chunk boundaries."""
        nonlocal skip_lf, done
        pos = 0
        total = len(text)
        while pos < total and not done:
            if skip_lf:
                skip_lf = False
                if text[pos] == "\n":
                    pos += 1
                    continue
            cr = text.find("\r", pos)
            lf = text.find("\n", pos)
            if cr == -1 and lf == -1:
                append_segment(text[pos:])
                break
            if cr != -1 and (lf == -1 or cr < lf):
                append_segment(text[pos:cr])
                if not finish_line():
                    done = True
                    return
                if cr + 1 < total and text[cr + 1] == "\n":
                    pos = cr + 2
                else:
                    skip_lf = cr + 1 == total
                    pos = cr + 1
            else:
                append_segment(text[pos:lf])
                if not finish_line():
                    done = True
                    return
                pos = lf + 1

    try:
        for raw_chunk in chunks:
            feed_text(decoder.decode(raw_chunk, final=False))
            if done:
                break
        if not done:
            feed_text(decoder.decode(b"", final=True))
    except UnicodeDecodeError:
        raise FetchError("invalid SSE response") from None

    if not done and line_parts and not finish_line():
        done = True
    if not done and data_lines:
        flush_event()

    if finish_reason is None:
        raise FetchError("incomplete SSE completion")
    body = {"choices": [{"finish_reason": finish_reason, "message": {"content": "".join(parts) if saw_content_str else None}}]}
    try:
        return strict_json(body, sort_keys=False).encode("utf-8")
    except (UnicodeEncodeError, ValueError, TypeError):
        raise FetchError("invalid SSE response") from None


class CompletionClient:
    """Shared chat-completion HTTP client with active endpoint pooling, failover and schema enforcement."""

    stage = "writer"
    POOL_COOLDOWN_SECONDS = 60.0
    REQUEST_POLICY = {"transport": {"retry_attempts": 1, "max_redirects": 0},
                      "deadline_refund": "before_dispatch_only",
                      "run_deadline": "admission_before_and_after_reservation"}

    _pool_lock = threading.Lock()
    _pool_state: dict[tuple[str, ...], dict] = {}

    @classmethod
    def _reset_pool_state(cls) -> None:
        """Clear shared endpoint pool counters (intended for unit tests)."""
        with cls._pool_lock:
            cls._pool_state.clear()

    @classmethod
    def _pool_urls(cls, llm_cfg: dict) -> tuple[str, ...]:
        pool = [u for u in (llm_cfg.get("pool_base_urls") or ()) if isinstance(u, str) and u]
        if not pool:
            return ()
        base = llm_cfg.get("base_url")
        raw = [base, *pool] if isinstance(base, str) and base else pool
        return tuple(dict.fromkeys(raw))

    @classmethod
    def _pool_claim_next(
        cls,
        pool_urls: tuple[str, ...],
        fallbacks_only: list[str],
        tried: set[str],
        now: float,
    ) -> tuple[str, int | None]:
        """Atomically select and claim the least-loaded healthy untried pool endpoint and its cooldown generation."""
        has_untried_fallback = any(fb not in tried for fb in fallbacks_only)
        with cls._pool_lock:
            entry = cls._pool_state.setdefault(
                pool_urls,
                {
                    "in_flight": {url: 0 for url in pool_urls},
                    "unhealthy_until": {},
                    "gen": {url: 0 for url in pool_urls},
                    "rr": 0,
                },
            )
            in_flight = entry["in_flight"]
            unhealthy = entry["unhealthy_until"]
            gens = entry["gen"]
            n = len(pool_urls)
            start = entry["rr"]
            rotated = [
                (idx, (start + idx) % n, url)
                for idx in range(n)
                if (url := pool_urls[(start + idx) % n]) not in tried
            ]
            if rotated:
                healthy = [(in_flight.get(url, 0), idx, pos, url) for idx, pos, url in rotated if unhealthy.get(url, 0.0) <= now]
                if healthy:
                    _, _, chosen_pos, chosen = min(healthy)
                    entry["rr"] = (chosen_pos + 1) % n
                    in_flight[chosen] = in_flight.get(chosen, 0) + 1
                    return chosen, gens.get(chosen, 0)
                if not has_untried_fallback:
                    _, _, _, chosen_pos, chosen = min(
                        (unhealthy[url], in_flight.get(url, 0), idx, pos, url) for idx, pos, url in rotated
                    )
                    entry["rr"] = (chosen_pos + 1) % n
                    in_flight[chosen] = in_flight.get(chosen, 0) + 1
                    return chosen, gens.get(chosen, 0)
        for fb in fallbacks_only:
            if fb not in tried:
                return fb, None
        raise RuntimeError("No untried endpoint available in pool")

    @classmethod
    def _pool_release(
        cls,
        pool_urls: tuple[str, ...],
        url: str,
        *,
        healthy: bool | None = None,
        now: float = 0.0,
        claim_gen: int | None = None,
    ) -> None:
        if not pool_urls or url not in pool_urls:
            return
        with cls._pool_lock:
            entry = cls._pool_state.get(pool_urls)
            if entry is None:
                return
            entry["in_flight"][url] = max(0, entry["in_flight"].get(url, 0) - 1)
            gens = entry.setdefault("gen", {u: 0 for u in pool_urls})
            if healthy is True:
                if claim_gen is None or gens.get(url, 0) == claim_gen:
                    entry["unhealthy_until"].pop(url, None)
            elif healthy is False:
                entry["unhealthy_until"][url] = max(
                    entry["unhealthy_until"].get(url, 0.0),
                    now + cls.POOL_COOLDOWN_SECONDS,
                )
                gens[url] = gens.get(url, 0) + 1

    def __init__(self, config: dict, deadline: float | None = None):
        self.deadline = deadline  # absolute monotonic admission boundary, not a transport cutoff
        self.clock = time.monotonic
        self.llm = config["llm"]
        # Each endpoint gets one metered request. Redirect hops cannot bypass
        # reservations; only explicitly configured fallbacks may send again.
        self.http_settings = {
            **config["http"],
            **{k: v for k, v in self.llm.items() if k in config["http"]},
            # The fixed total must not cut short a longer configured response timeout.
            "total_timeout_seconds": completion_budget_seconds(self.llm),
            **self.REQUEST_POLICY["transport"],
        }
        self.client: HttpClient | None = None
        self.calls = 0  # requests sent, for the run report
        self.dirauth_users = (config.get("collection") or {}).get("dirauth_gitlab_users")
        self.tor_core_users = (config.get("collection") or {}).get("tor_core_gitlab_users")

    def __enter__(self) -> CompletionClient:
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def close(self) -> None:
        """Close the underlying HTTP client if one was opened."""
        if self.client is not None:
            self.client.close()

    def _admit(self, failure: AnalysisError | None = None) -> None:
        if self.deadline is not None and self.clock() >= self.deadline:
            if failure is not None:
                raise failure
            raise CompletionDeferred("Run completion admission window has ended")

    def complete(self, prompt: str, payload: dict, schema: dict, name: str, *, on_request=None) -> dict:
        """One fresh request; drafting, review and link checks share transport policy."""
        self._admit()
        pool_configured = bool(self._pool_urls(self.llm))
        if not self.llm["base_url"] and not pool_configured:
            raise AnalysisError("LLM endpoint is not configured", retryable=True)
        key = os.environ.get(self.llm["api_key_env"], "")
        if not key:
            raise AnalysisError("LLM credential environment variable is missing", retryable=True)
        if self.client is None:
            self.client = HttpClient(
                self.http_settings,
                allowed_networks=self.llm["allowed_networks"],
                allow_http=self.llm["allow_http"],
                clock=self.clock,
            )
        try:
            content = strict_json(payload, sort_keys=False)
        except (ValueError, TypeError, RecursionError) as exc:
            raise AnalysisError("Model input is not valid UTF-8 JSON", code=self.stage + ".invalid_input") from exc
        options = generation_options(self.llm)
        request = {
            "model": self.llm["model"],
            "messages": [{"role": "system", "content": prompt}, {"role": "user", "content": content}],
            "temperature": options["temperature"],
            "max_tokens": options["max_tokens"],
            "response_format": {"type": "json_schema", "json_schema": {"name": name, "strict": True, "schema": schema}},
            **options,
            "stream": True,
        }
        max_bytes = int(self.http_settings.get("max_response_bytes", 4 * 1024 * 1024))
        stream_limit = max(max_bytes * SSE_WIRE_MULTIPLIER, MIN_SSE_WIRE_BYTES)
        req_headers = {"Authorization": "Bearer " + key, "Accept-Encoding": "identity"}
        fallbacks = [u for u in (self.llm.get("fallback_base_urls") or ()) if isinstance(u, str) and u]
        pool_urls = self._pool_urls(self.llm)
        if pool_urls:
            fallbacks_only = [u for u in dict.fromkeys(fallbacks) if u not in pool_urls]
            total_attempts = len(pool_urls) + len(fallbacks_only)
        else:
            fallbacks_only = []
            legacy_endpoints = iter([self.llm["base_url"], *fallbacks])
            total_attempts = 1 + len(fallbacks)
        tried: set[str] = set()
        failure = None
        for _ in range(total_attempts):
            self._admit(failure)
            if on_request is not None:
                on_request(1)  # Reserve durably before any endpoint attempt.
            try:
                self._admit(failure)
            except (CompletionDeferred, AnalysisError):
                if on_request is not None:
                    on_request(-1)
                raise
            base_url, claim_gen = (
                self._pool_claim_next(pool_urls, fallbacks_only, tried, self.clock())
                if pool_urls
                else (next(legacy_endpoints), None)
            )
            tried.add(base_url)
            self.calls += 1
            healthy: bool | None = None
            try:
                if isinstance(self.client, _HTTP_CLIENT_CLASS):
                    response = self.client.request(
                        "POST",
                        base_url + "/chat/completions",
                        headers=req_headers,
                        json_body=request,
                        stream_reader=lambda chunks: parse_sse_completion(chunks, max_content_bytes=max_bytes),
                        stream_limit=stream_limit,
                    )
                else:
                    response = self.client.request(
                        "POST",
                        base_url + "/chat/completions",
                        headers=req_headers,
                        json_body=request,
                    )
                    if is_event_stream(response.headers):
                        response = Response(
                            response.status,
                            parse_sse_completion((response.body,), max_content_bytes=max_bytes),
                            response.headers,
                            response.url,
                        )
                healthy = True
                break
            except FetchError as exc:
                if not isinstance(exc, DeadlineReached):
                    healthy = False
                # An endpoint or credential problem is not this item's fault.
                current_failure = AnalysisError(
                    "LLM request failed" + (f" (HTTP {exc.status})" if exc.status else ""),
                    retryable=True,
                )
                if isinstance(exc, DeadlineReached) and not exc.request_started:
                    # Only refusal before dispatch proves the reservation unused.
                    self.calls -= 1
                    if on_request is not None:
                        on_request(-1)
                if isinstance(on_request, RequestObserver):
                    on_request.transport_failed()
                if isinstance(exc, DeadlineReached):
                    raise failure or current_failure from None
                failure = current_failure
            finally:
                if pool_urls:
                    self._pool_release(
                        pool_urls,
                        base_url,
                        healthy=healthy,
                        now=self.clock() if healthy is False else 0.0,
                        claim_gen=claim_gen,
                    )
        else:
            raise failure
        if isinstance(on_request, RequestObserver):
            on_request.response_received()
        try:
            choice = response.json()["choices"][0]
            finished, content = choice["finish_reason"], choice["message"]["content"]
        except (FetchError, KeyError, IndexError, TypeError):
            raise AnalysisError("LLM returned an unexpected response", retryable=True) from None
        if finished != "stop":
            raise AnalysisError("Model completion was truncated or refused", code=self.stage + ".truncated")
        if not isinstance(content, str):
            raise AnalysisError("Model returned no textual completion", retryable=True)
        return json_object(content, self.stage + ".invalid_json")
