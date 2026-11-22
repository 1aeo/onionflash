"""Shared model completion client, error contract and schema/text validators."""

from __future__ import annotations

import codecs
import json
import os
import re
import time
import unicodedata
from collections.abc import Iterable

from .config import completion_budget_seconds
from .schema import CATEGORIES, CONFIDENCES, STATES
from .transport import DeadlineReached, FetchError, HttpClient, Response, is_event_stream

_HTTP_CLIENT_CLASS = HttpClient
from .util import LIST_ARCHIVE_HOST, _url_host, has_invalid_text_chars, is_trove_item, strict_json

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


def label_limits(sources: list[dict]) -> dict:
    """The confidence, state and category labels a story told by these sources may carry: confirmed
    needs an official source that is not a tag, or a merged merge request; tagged needs a tag
    source; a story told only by merge requests is merged and not a release; and verified TROVE
    advisories must stay categorized as security."""
    confirmable = any((source.get("authority") == "official" and source.get("kind") != "tag")
                      or (source.get("kind") == "gitlab_mr" and source.get("upstream_state") == "merged")
                      for source in sources)
    tagged = any(source.get("kind") == "tag" for source in sources)
    merges = bool(sources) and all(source.get("kind") == "gitlab_mr" for source in sources)
    trove = any(is_trove_item(source) or source.get("mandatory_news_rule") == "trove" for source in sources)
    allowed_tags = [value for value in CATEGORIES if not merges or value != "release"]
    return {
        "confidence": [value for value in CONFIDENCES if confirmable or value != "confirmed"],
        "state": ["merged"] if merges else [value for value in STATES if tagged or value != "tagged"],
        "category": ["security"] if trove else allowed_tags,
        "tags": allowed_tags,
    }


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
                content_bytes += len(piece.encode("utf-8"))
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
            if done:
                break
            feed_text(decoder.decode(raw_chunk, final=False))
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
    return strict_json(body, sort_keys=False).encode("utf-8")


class CompletionClient:
    """Shared chat-completion HTTP client with endpoint failover and schema enforcement."""

    stage = "writer"
    REQUEST_POLICY = {"transport": {"retry_attempts": 1, "max_redirects": 0},
                      "deadline_refund": "before_dispatch_only",
                      "run_deadline": "admission_before_and_after_reservation"}

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
        if not self.llm["base_url"]:
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
        failure = None
        for base_url in [self.llm["base_url"], *self.llm["fallback_base_urls"]]:
            self._admit(failure)
            if on_request is not None:
                on_request(1)  # Reserve durably before any endpoint attempt.
            try:
                self._admit(failure)
            except (CompletionDeferred, AnalysisError):
                if on_request is not None:
                    on_request(-1)
                raise
            self.calls += 1
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
                break
            except FetchError as exc:
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
