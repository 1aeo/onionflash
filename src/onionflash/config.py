"""TOML configuration with explicit resource bounds and safe path resolution."""

from __future__ import annotations

import copy
import ipaddress
import logging
import os
import re
import tomllib
from pathlib import Path
from urllib.parse import unquote, urlsplit, urlunsplit

from .schema import PRODUCTS
from .util import canonical_url

DEFAULTS = {
    "site": {
        "title": "Onion Flash",
        "base_url": "https://1aeo.com/onionflash/",
        "description": "Important Tor news, distilled.",
        "repository_url": "https://github.com/1aeo/onionflash",
        "page_size": 100,
    },
    "storage": {
        "database": "state/onionflash.sqlite3",
        "output_dir": "build/public",
        "render_batch_size": 250,
    },
    "collection": {
        "lookback_days": 14,
        "overlap_seconds": 900,
        "max_pages": 5,
        "page_size": 50,
        "max_items_per_source": 250,
        "content_chars": 20000,
        "stale_after_seconds": 7200,
        "failure_backoff_base_seconds": 300,
        "failure_backoff_cap_seconds": 21600,
        "run_budget_seconds": 240,
        "source_budget_seconds": 60,
        "analysis_reserve_fraction": 0.5,
    },
    "http": {
        "timeout_seconds": 30,
        "connect_timeout_seconds": 10,
        "total_timeout_seconds": 90,
        "retry_attempts": 3,
        "backoff_base_seconds": 1,
        "backoff_cap_seconds": 30,
        "backoff_jitter": 0.25,
        "max_retry_after_seconds": 60,
        "max_redirects": 4,
        "max_response_bytes": 2097152,
        "user_agent": "OnionFlash (+https://github.com/1aeo/onionflash)",
    },
    "comments": {"enabled": False},
    "llm": {
        "base_url": "",
        "fallback_base_urls": [],
        "model": "qwen3.8-27b",
        "api_key_env": "ONIONFLASH_LLM_API_KEY",
        "allowed_networks": [],
        "allow_http": False,
        "timeout_seconds": 120,
        "connect_timeout_seconds": 10,
        "total_timeout_seconds": 180,
        "max_response_bytes": 65536,
        "max_output_tokens": 1200,
        "max_items_per_run": 12,
        "retry_base_seconds": 300,
        "retry_cap_seconds": 21600,
        "enable_thinking": False,
        "writer_reasoning": False,
        "send_chat_template_kwargs": True,
    },
    "review": {"model": ""},
    "sources": [],
}

BOUNDS = {
    "timeout_seconds": (1, 600),
    "max_pages": (1, 100),
    "page_size": (1, 100),
    "max_items_per_source": (1, 10000),
    "max_items_per_run": (1, 1000),
}

OPERATOR_SETTINGS = {
    "collection": set(),
    "http": set(),
    "llm": {
        "base_url", "fallback_base_urls", "model", "allowed_networks",
        "allow_http", "send_chat_template_kwargs", "max_items_per_run", "timeout_seconds", "writer_reasoning",
    },
    "storage": {"database", "output_dir"},
}

SECTION_SPECS = {
    "comments": {"bools": ("enabled",)},
    "site": {
        "ints": {"page_size": BOUNDS["page_size"]},
        "strings": {"title": (0, 300), "description": (0, 300)},
    },
    "llm": {
        "bools": ("allow_http", "send_chat_template_kwargs", "writer_reasoning"),
        "ints": {"max_items_per_run": BOUNDS["max_items_per_run"]},
        "numbers": {"timeout_seconds": BOUNDS["timeout_seconds"]},
        "strings": {"model": (1, 200)},
        "lists": ("fallback_base_urls", "allowed_networks"),
    },
}

_SOURCE_DEFAULTS = {
    "kind": "feed", "fallback_urls": [], "product": "network",
    "authority": "community", "enabled": True, "interval_seconds": 300,
}
_SOURCE_KEYS = {
    "id", "name", "url", "website_url", "alert_format", "publish",
    "gitlab_project", "max_pages", "max_items", *_SOURCE_DEFAULTS,
}


def _check_range(value: object, low: int, high: int, *, allow_float: bool = False) -> bool:
    ok_type = type(value) in (int, float) if allow_float else type(value) is int
    return ok_type and low <= value <= high


def _expand(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Configuration value must be a string")

    def sub(match: re.Match) -> str:
        name = match.group(1)
        if name not in os.environ:
            raise ValueError(f"Required environment variable {name} is missing")
        return os.environ[name]

    return re.sub(r"\$\{([A-Z_][A-Z0-9_]*)\}", sub, value)


def _clean_endpoint_url(url: str, *, allow_http: bool, trailing_slash: bool, error: str) -> str:
    parsed = urlsplit(url)
    try:
        port = parsed.port
    except ValueError:
        raise ValueError(error) from None
    if (
        parsed.scheme not in ({"https", "http"} if allow_http else {"https"})
        or not parsed.hostname
        or port == 0
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or "\\" in url
        or any(ord(c) < 33 or ord(c) == 127 for c in url)
        or (trailing_slash and any(p in {".", ".."} for p in unquote(parsed.path).split("/")))
    ):
        raise ValueError(error)
    if trailing_slash:
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/") + "/", "", ""))
    return url.rstrip("/")


def load_config(path: str | Path) -> dict:
    """Merge defaults and validate operator configuration."""
    path = Path(path).expanduser().resolve(strict=True)
    with path.open("rb") as stream:
        raw = tomllib.load(stream)
    config = copy.deepcopy(DEFAULTS)
    if unknown := set(raw) - set(DEFAULTS):
        raise ValueError(f"Unknown config sections: {', '.join(sorted(unknown))}")
    for section, values in raw.items():
        if section == "sources":
            config[section] = values
            continue
        if not isinstance(values, dict):
            raise ValueError(f"{section} must be a table")
        fixed = set(DEFAULTS[section]) - OPERATOR_SETTINGS[section] if section in OPERATOR_SETTINGS else set()
        for key in sorted(set(values) & fixed):
            logging.getLogger(__name__).warning("Ignoring setting %s.%s: it is no longer configurable and can be deleted", section, key)
        values = {k: v for k, v in values.items() if k not in fixed}
        if unknown := set(values) - set(DEFAULTS[section]):
            raise ValueError(f"Unknown {section} settings: {', '.join(sorted(unknown))}")
        config[section].update(values)

    for section, spec in SECTION_SPECS.items():
        table = config[section]
        for key in spec.get("bools", ()):
            if not isinstance(table[key], bool):
                raise ValueError(f"{section}.{key} must be a boolean")
        for key, (low, high) in spec.get("ints", {}).items():
            if not _check_range(table[key], low, high):
                raise ValueError(f"{section}.{key} must be an integer between {low} and {high}")
        for key, (low, high) in spec.get("numbers", {}).items():
            if not _check_range(table[key], low, high, allow_float=True):
                raise ValueError(f"{section}.{key} must be between {low} and {high}")
        for key, (min_len, max_len) in spec.get("strings", {}).items():
            if not isinstance(table[key], str) or not min_len <= len(table[key]) <= max_len:
                raise ValueError(f"{section}.{key} must be a valid string")
        for key in spec.get("lists", ()):
            if not isinstance(table[key], list):
                raise ValueError(f"{section}.{key} must be an array")

    config["site"]["base_url"] = _clean_endpoint_url(
        _expand(config["site"]["base_url"]),
        allow_http=True,
        trailing_slash=True,
        error="site.base_url must be a clean absolute HTTP(S) URL",
    )
    config["site"]["repository_url"] = canonical_url(config["site"]["repository_url"])

    for key in ("database", "output_dir"):
        value = Path(_expand(config["storage"][key])).expanduser()
        candidate = value if value.is_absolute() else path.parent / value
        if candidate.is_symlink():
            raise ValueError(f"storage.{key} must not be a symlink")
        config["storage"][key] = str(candidate.resolve())
    output, database = Path(config["storage"]["output_dir"]), Path(config["storage"]["database"])
    if output == path.parent or output in path.parents or output == Path(output.anchor):
        raise ValueError("Output must be a dedicated generated directory")
    if database == output or output in database.parents:
        raise ValueError("Database must be outside public output")

    llm = config["llm"]
    if llm["writer_reasoning"] and not llm["send_chat_template_kwargs"]:
        raise ValueError("llm.writer_reasoning requires llm.send_chat_template_kwargs")
    llm["base_url"] = _expand(llm["base_url"]).rstrip("/")
    llm["fallback_base_urls"] = [_expand(u).rstrip("/") if isinstance(u, str) else "" for u in llm["fallback_base_urls"]]
    if any(not u.strip() for u in llm["fallback_base_urls"]):
        raise ValueError("Each LLM fallback base URL must be a nonempty URL")
    for network in llm["allowed_networks"]:
        if not isinstance(network, str) or ipaddress.ip_network(network, strict=True).prefixlen == 0:
            raise ValueError("Each allowed_networks entry must be a non-default CIDR string")
    llm_error = "Invalid LLM base URL; credentials belong in its environment variable"
    for url in (llm["base_url"], *llm["fallback_base_urls"]):
        if url:
            _clean_endpoint_url(url, allow_http=llm["allow_http"], trailing_slash=False, error=llm_error)

    review = config["review"]
    if not isinstance(review["model"], str) or len(review["model"]) > 200 or any(ord(c) < 32 for c in review["model"]):
        raise ValueError("review.model must be a short model identifier, or empty to inherit llm.model")
    review["model"] = review["model"].strip()

    sources = config["sources"]
    if not isinstance(sources, list) or not 1 <= len(sources) <= 100:
        raise ValueError("Configure between 1 and 100 sources")
    ids: set[str] = set()
    for source in sources:
        if not isinstance(source, dict) or set(source) - _SOURCE_KEYS:
            raise ValueError("Invalid source keys")
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", source.get("id", "")) or source["id"] in ids:
            raise ValueError("Source IDs must be unique short lowercase identifiers")
        ids.add(source["id"])
        source.setdefault("name", source["id"])
        for key, default in _SOURCE_DEFAULTS.items():
            source.setdefault(key, copy.deepcopy(default))
        alert_format = source.get("alert_format", "")
        if not isinstance(alert_format, str) or alert_format not in {"", "consensus"}:
            raise ValueError("Invalid source alert_format")
        if "publish" in source and alert_format != "consensus":
            raise ValueError("source.publish requires alert_format = 'consensus'")
        if alert_format == "consensus":
            source.setdefault("publish", False)
            if not isinstance(source["publish"], bool):
                raise ValueError("source.publish must be a boolean")
            if source["kind"] != "feed":
                raise ValueError("Consensus alert sources require kind = 'feed'")
        if source["kind"] not in {"feed", "tag", "gitlab_issue", "gitlab_mr", "metrics_timeline"}:
            raise ValueError("Unsupported source kind")
        if source["authority"] not in {"official", "community", "development", "telemetry"}:
            raise ValueError("Unsupported source authority")
        if source["product"] not in PRODUCTS:
            raise ValueError("Unsupported source product")
        if not isinstance(source["enabled"], bool) or not _check_range(source["interval_seconds"], 30, 604800):
            raise ValueError("Invalid source enabled/interval_seconds")
        if not isinstance(source["fallback_urls"], list) or len(source["fallback_urls"]) > 5:
            raise ValueError("At most five fallback URLs per source")
        source["url"] = canonical_url(source["url"])
        if "website_url" in source:
            source["website_url"] = canonical_url(source["website_url"])
        if source["kind"] == "metrics_timeline" or alert_format == "consensus":
            label = "Timeline" if source["kind"] == "metrics_timeline" else "Consensus"
            if "website_url" not in source:
                raise ValueError(f"{label} sources need website_url")
            website = urlsplit(source["website_url"])
            if website.query or website.fragment or not website.path.strip("/"):
                raise ValueError(f"{label} website_url must be a clean URL")
        source["fallback_urls"] = [canonical_url(u) for u in source["fallback_urls"]]
        if "gitlab_project" in source:
            if source["kind"] != "gitlab_issue":
                raise ValueError("Comment configuration requires a GitLab issue source")
            from .comments import CommentError, _identity

            try:
                _identity(source)
            except (CommentError, ValueError) as exc:
                raise ValueError("Invalid anonymous GitLab comments configuration") from exc
        for key, global_key in (("max_pages", "max_pages"), ("max_items", "max_items_per_source")):
            source.setdefault(key, config["collection"][global_key])
            if not _check_range(source[key], *BOUNDS[global_key]):
                raise ValueError(f"Invalid source {key}")
    if sum(1 for s in sources if s.get("alert_format") == "consensus" and s["enabled"]) > 1:
        raise ValueError("At most one enabled consensus alert source is supported")
    config["_config_path"] = str(path)
    return config
