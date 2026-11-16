"""Shared model completion client, error contract and schema/text validators."""

from __future__ import annotations

import json
import os
import re
import time

from .config import completion_budget_seconds
from .schema import CATEGORIES, CONFIDENCES, STATES
from .transport import DeadlineReached, FetchError, HttpClient

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
        pass

    def transport_failed(self) -> None:
        """Record that transport failed before an HTTP completion response arrived."""
        pass


def has_invalid_text_chars(value: str) -> bool:
    """Reject ASCII control characters (other than tab/newline) and XML noncharacters."""
    return any((ord(c) < 32 and c not in "\n\t") or c in "\ufffe\uffff" for c in value)


def has_shouting_caps(text: str) -> bool:
    """Return whether text contains a 3+ word ALL-CAPS run beyond technical acronyms."""
    for match in _SHOUT_RUN_RE.finditer(text):
        words = _UPPER_WORD_RE.findall(match.group(0))
        if len(words) >= 3 and sum(1 for word in words if word not in _ACRONYM_ALLOWLIST) >= 2:
            return True
    return False


def _is_sic_annotated(text: str, match: re.Match[str]) -> bool:
    prefix = text[max(0, match.start() - 48) : match.start()]
    suffix = text[match.end() : match.end() + 80]
    return bool(_SIC_PREFIX_RE.search(prefix) or _SIC_SUFFIX_RE.search(suffix))


def has_malformed_tor_version(text: str, products: list[str] | tuple[str, ...] = ()) -> bool:
    """Return whether text cites a nonexistent three-part C-Tor version such as 0.4.17."""
    if products and "tor" not in products and "network" not in products:
        return False
    return any(not _is_sic_annotated(text, match) for match in _MALFORMED_TOR_VERSION_RE.finditer(text))


def validate_text(value: object, maximum: int, *, empty: bool = False,
                  error: type[Exception] = AnalysisError, message: str = "Invalid model text") -> str:
    """Strip and bound model text while rejecting control or noncharacter code points."""
    if not isinstance(value, str) or len(value) > maximum or has_invalid_text_chars(value):
        raise error(message)
    stripped = value.strip()
    if not stripped and not empty:
        raise error(message)
    return stripped


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
    r"^(?:on\s+.+\bwrote:|am\s+.+\bschrieb\b.*:|le\s+.+\ba\s+écrit\s*:|[- ]*original message[- ]*|from:\s+.+)$",
    re.IGNORECASE,
)


def unquoted_mail_text(text: str) -> str:
    """Strip >-quoted reply lines and quote-attribution headers preceding them."""
    lines = text.splitlines()
    drop = [line.lstrip().startswith(">") for line in lines]
    for index in range(len(lines) - 1, -1, -1):
        if drop[index] or not (stripped := lines[index].strip()):
            continue
        probe = index + 1
        while probe < len(lines) and not lines[probe].strip():
            probe += 1
        if (probe == len(lines) or drop[probe]) and _MAIL_QUOTE_INTRO_RE.match(stripped):
            drop[index] = True
            continue
        if index + 1 < len(lines) and not drop[index + 1] and (next_line := lines[index + 1].strip()):
            probe2 = index + 2
            while probe2 < len(lines) and not lines[probe2].strip():
                probe2 += 1
            if (probe2 == len(lines) or drop[probe2]) and re.match(
                r"^on\s+.+\bwrote:$", f"{stripped} {next_line}", re.IGNORECASE
            ):
                drop[index] = drop[index + 1] = True
    kept = "\n".join(line for line, remove in zip(lines, drop) if not remove)
    return re.sub(r"\n{3,}", "\n\n", kept).strip()


def label_limits(sources: list[dict]) -> dict:
    """The confidence, state and category labels a story told by these sources may carry: confirmed
    needs an official source that is not a tag, or a merged merge request; tagged needs a tag
    source; and a story told only by merge requests is merged and not a release."""
    confirmable = any((source.get("authority") == "official" and source.get("kind") != "tag")
                      or (source.get("kind") == "gitlab_mr" and source.get("upstream_state") == "merged")
                      for source in sources)
    tagged = any(source.get("kind") == "tag" for source in sources)
    merges = bool(sources) and all(source.get("kind") == "gitlab_mr" for source in sources)
    return {"confidence": [value for value in CONFIDENCES if confirmable or value != "confirmed"],
            "state": ["merged"] if merges else [value for value in STATES if tagged or value != "tagged"],
            "category": [value for value in CATEGORIES if not merges or value != "release"]}


def apply_label_limits(properties: dict, limits: dict, *, nullable: bool = False) -> None:
    """Restrict schema enum choices in place to the labels allowed by source limits."""
    def rule(field: str) -> dict:
        """Select the target property schema dictionary for nullable or required fields."""
        return properties[field]["anyOf"][0] if nullable else properties[field]

    for key, allowed in limits.items():
        if key in properties:
            rule(key)["enum"] = list(allowed)
    if "tags" in properties and "category" in properties:
        rule("tags")["items"]["enum"] = list(rule("category")["enum"])


def repair_schema(fields: dict, required: tuple[str, ...]) -> dict:
    """Build a strict nullable JSON schema for minimal semantic review repairs."""
    return {"anyOf": [{"type": "null"}, {"type": "object", "additionalProperties": False,
        "properties": {key: {"anyOf": [rule, {"type": "null"}]} for key, rule in fields.items()},
        "required": list(required)}]}


def json_object(text: str, code: str = "writer.invalid_json") -> dict:
    """Parse a strict UTF-8 JSON object without duplicate keys, surrogates or NaNs."""
    def unique(pairs):
        """Reject duplicate object keys while constructing a JSON dictionary."""
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON field")
            result[key] = value
        return result

    try:
        result = json.loads(text, object_pairs_hook=unique)
        # Stored analyses must be standard UTF-8 JSON: reject unpaired surrogate
        # escapes and non-finite numbers (NaN, Infinity, 1e999) before a malformed
        # model response reaches the queue.
        json.dumps(result, ensure_ascii=False, allow_nan=False).encode("utf-8")
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

    def __enter__(self) -> CompletionClient:
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def close(self) -> None:
        """Close the underlying HTTP client if one was opened."""
        if self.client is not None:
            self.client.close()

    def _fail_retryable(self, message: str) -> AnalysisError:
        return AnalysisError(message, retryable=True)

    def _admit(self, failure: AnalysisError | None = None) -> None:
        if self.deadline is not None and self.clock() >= self.deadline:
            if failure is not None:
                raise failure
            raise CompletionDeferred("Run completion admission window has ended")

    def complete(self, prompt: str, payload: dict, schema: dict, name: str, *, on_request=None) -> dict:
        """One fresh request; drafting, review and link checks share transport policy."""
        self._admit()
        if not self.llm["base_url"]:
            raise self._fail_retryable("LLM endpoint is not configured")
        key = os.environ.get(self.llm["api_key_env"], "")
        if not key:
            raise self._fail_retryable("LLM credential environment variable is missing")
        if self.client is None:
            self.client = HttpClient(
                self.http_settings,
                allowed_networks=self.llm["allowed_networks"],
                allow_http=self.llm["allow_http"],
                clock=self.clock,
            )
        try:
            content = json.dumps(payload, ensure_ascii=False, allow_nan=False)
            content.encode("utf-8")
        except (ValueError, TypeError, RecursionError) as exc:
            raise AnalysisError("Model input is not valid UTF-8 JSON", code=self.stage + ".invalid_input") from exc
        options = generation_options(self.llm)
        request = {
            "model": self.llm["model"],
            "messages": [{"role": "system", "content": prompt}, {"role": "user", "content": content}],
            "temperature": options.pop("temperature"),
            "max_tokens": options.pop("max_tokens"),
            "response_format": {"type": "json_schema", "json_schema": {"name": name, "strict": True, "schema": schema}},
        }
        request.update(options)
        return self._complete(request, key, **({"on_request": on_request} if on_request is not None else {}))

    def _complete(self, request: dict, key: str, *, on_request=None) -> dict:
        """POST one chat completion; only transport failures move on to a fallback."""
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
                response = self.client.request(
                    "POST",
                    base_url + "/chat/completions",
                    headers={"Authorization": "Bearer " + key},
                    json_body=request,
                )
                break
            except FetchError as exc:
                # An endpoint or credential problem is not this item's fault.
                current_failure = AnalysisError(
                    "LLM request failed" + (f" (HTTP {exc.status})" if exc.status else ""),
                    retryable=True,
                )
                if isinstance(exc, DeadlineReached):
                    # Only refusal before dispatch proves the reservation unused.
                    # A timed-out request may already have reached the endpoint.
                    if not exc.request_started:
                        self.calls -= 1
                        if on_request is not None:
                            on_request(-1)
                    if isinstance(on_request, RequestObserver):
                        on_request.transport_failed()
                    raise failure or current_failure from None
                if isinstance(on_request, RequestObserver):
                    on_request.transport_failed()
                failure = current_failure
        else:
            raise failure
        if isinstance(on_request, RequestObserver):
            on_request.response_received()
        try:
            choice = response.json()["choices"][0]
            finished, content = choice["finish_reason"], choice["message"]["content"]
        except (FetchError, KeyError, IndexError, TypeError):
            raise self._fail_retryable("LLM returned an unexpected response") from None
        if finished != "stop":
            raise AnalysisError("Model completion was truncated or refused", code=self.stage + ".truncated")
        if not isinstance(content, str):
            raise self._fail_retryable("Model returned no textual completion")
        return json_object(content, self.stage + ".invalid_json")
