"""Shared model completion client, error contract and schema/text validators."""

from __future__ import annotations

import json
import os

from .schema import CATEGORIES, CONFIDENCES, STATES
from .transport import DeadlineReached, FetchError, HttpClient


class AnalysisError(Exception):
    code = "writer.invalid_output"  # logged as failed.<code> when it is the item's third failure

    def __init__(self, message: str, retryable: bool = False, *, code: str | None = None):
        super().__init__(message)
        self.retryable = retryable
        if code is not None:
            self.code = code


class RequestObserver:
    """A reservation callback may also persist transport outcomes before parsing."""

    def __call__(self, delta: int) -> None:
        raise NotImplementedError

    def response_received(self) -> None:
        pass

    def transport_failed(self) -> None:
        pass


def has_invalid_text_chars(value: str) -> bool:
    """Reject ASCII control characters (other than tab/newline) and XML noncharacters."""
    return any((ord(c) < 32 and c not in "\n\t") or c in "\ufffe\uffff" for c in value)


def validate_text(value: object, maximum: int, *, empty: bool = False,
                  error: type[Exception] = AnalysisError, message: str = "Invalid model text") -> str:
    if not isinstance(value, str) or len(value) > maximum or has_invalid_text_chars(value):
        raise error(message)
    stripped = value.strip()
    if not stripped and not empty:
        raise error(message)
    return stripped


def is_complete_sentence(text: str) -> bool:
    stripped = text.strip()
    return bool(stripped) and stripped[-1] in '.!?"\')”’' and any(c.isalnum() for c in stripped)


def tag_name(item: dict) -> str:
    name = item["title"].strip()
    if not name or len(name) > 500:
        raise AnalysisError("Invalid tag name", code="app.invalid_tag_name")
    return name


def strip_unreleased_tag(story: dict) -> None:
    if (story.get("category") != "release" and story.get("state") not in {"released", "tagged"}
            and "release" in (story.get("tags") or ())):
        story["tags"] = [tag for tag in story["tags"] if tag != "release"]


def unquoted_text(text: str) -> str:
    """Drop >-quoted reply lines so own-item updates use only unquoted prose."""
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith(">"))


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
    def rule(field: str) -> dict:
        return properties[field]["anyOf"][0] if nullable else properties[field]

    for key, allowed in limits.items():
        if key in properties:
            rule(key)["enum"] = list(allowed)
    if "tags" in properties and "category" in properties:
        rule("tags")["items"]["enum"] = list(rule("category")["enum"])


def repair_schema(fields: dict, required: tuple[str, ...]) -> dict:
    return {"anyOf": [{"type": "null"}, {"type": "object", "additionalProperties": False,
        "properties": {key: {"anyOf": [rule, {"type": "null"}]} for key, rule in fields.items()},
        "required": list(required)}]}


def json_object(text: str, code: str = "writer.invalid_json") -> dict:
    def unique(pairs):
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


class CompletionClient:
    stage = "writer"

    def __init__(self, config: dict, deadline: float | None = None):
        self.deadline = deadline  # absolute time.monotonic() limit for model requests
        self.llm = config["llm"]
        # One attempt per endpoint: the fallback endpoints are the retry, and a
        # failed item backs off to a later run instead of stretching this one.
        self.http_settings = {
            **config["http"],
            **{k: v for k, v in self.llm.items() if k in config["http"]},
            # The fixed total must not cut short a longer configured response timeout.
            "total_timeout_seconds": max(
                self.llm["total_timeout_seconds"],
                self.llm["timeout_seconds"] + self.llm["connect_timeout_seconds"],
            ),
            "retry_attempts": 1,
        }
        self.client: HttpClient | None = None
        self.calls = 0  # requests sent, for the run report

    def __enter__(self) -> CompletionClient:
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def close(self) -> None:
        if self.client is not None:
            self.client.close()

    def _fail_retryable(self, message: str) -> AnalysisError:
        return AnalysisError(message, retryable=True)

    def complete(self, prompt: str, payload: dict, schema: dict, name: str, *, on_request=None) -> dict:
        """One fresh request; drafting, review and link checks share transport policy."""
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
            )
            self.client.deadline = self.deadline
        try:
            content = json.dumps(payload, ensure_ascii=False, allow_nan=False)
            content.encode("utf-8")
        except (ValueError, TypeError, RecursionError) as exc:
            raise AnalysisError("Model input is not valid UTF-8 JSON", code=self.stage + ".invalid_input") from exc
        request = {
            "model": self.llm["model"],
            "messages": [{"role": "system", "content": prompt}, {"role": "user", "content": content}],
            "temperature": 0,
            "max_tokens": self.llm["max_output_tokens"],
            "response_format": {"type": "json_schema", "json_schema": {"name": name, "strict": True, "schema": schema}},
        }
        if self.llm["send_chat_template_kwargs"]:
            request["chat_template_kwargs"] = {"enable_thinking": self.llm["enable_thinking"]}
        return self._complete(request, key, **({"on_request": on_request} if on_request is not None else {}))

    def _complete(self, request: dict, key: str, *, on_request=None) -> dict:
        """POST one chat completion; only transport failures move on to a fallback."""
        failure = AnalysisError("All LLM endpoints failed", retryable=True)
        for base_url in [self.llm["base_url"], *self.llm["fallback_base_urls"]]:
            if on_request is not None:
                on_request(1)  # Reserve durably before any endpoint attempt.
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
                failure = AnalysisError(
                    "LLM request failed" + (f" (HTTP {exc.status})" if exc.status else ""),
                    retryable=True,
                )
                if isinstance(exc, DeadlineReached):  # refused unsent, as every later endpoint would be
                    self.calls -= 1
                    if on_request is not None:
                        on_request(-1)
                    if isinstance(on_request, RequestObserver):
                        on_request.transport_failed()
                    raise failure from None
                if isinstance(on_request, RequestObserver):
                    on_request.transport_failed()
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
