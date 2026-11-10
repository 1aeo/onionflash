"""TOML configuration with explicit resource bounds and safe path resolution."""

from __future__ import annotations

import copy
import ipaddress
import os
import re
import tomllib
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .util import canonical_url
from .schema import PRODUCTS

DEFAULTS = {
    "site": {
        "title": "Onion Flash",
        "base_url": "https://1aeo.com/onionflash/",
        "description": "Important Tor news, distilled.",
        "repository_url": "https://github.com/1aeo/onionflash",
        "page_size": 100,
        "feed_size": 50,
    },
    "storage": {
        "database": "state/onionflash.sqlite3",
        "output_dir": "build/public",
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
        "reconcile_seconds": 86400,
        "max_xml_depth": 128,
        "max_xml_elements": 50000,
        "healthy_poll_tolerance_seconds": 5,
        "tag_priority_score": 5,
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
        "requests_per_minute": 30,
        "user_agent": "OnionFlash (+https://github.com/1aeo/onionflash)",
    },
    "monitoring": {
        "min_reports": 2,
        "min_span_seconds": 3600,
        "window_seconds": 172800,
        "stale_after_seconds": 259200,
        "retention_days": 30,
        "max_observations": 10000,
        "max_groups": 2000,
        "max_source_links": 3,
        "max_alerts_per_item": 100,
        "max_future_seconds": 300,
    },
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
        "retry_attempts": 2,
        "max_response_bytes": 65536,
        "max_output_tokens": 1200,
        "max_input_chars": 14000,
        "max_items_per_run": 12,
        "retry_base_seconds": 300,
        "retry_cap_seconds": 21600,
        "enable_thinking": False,
        "send_chat_template_kwargs": True,
    },
    "sources": [],
}

# Values are bounded even for operator-owned config: an accidental zero must not
# disable timeouts or turn retry loops into a busy loop.
BOUNDS = {
    "timeout_seconds": (1, 600),
    "connect_timeout_seconds": (1, 120),
    "total_timeout_seconds": (1, 600),
    "retry_attempts": (1, 8),
    "backoff_base_seconds": (0.1, 120),
    "backoff_cap_seconds": (0.1, 600),
    "backoff_jitter": (0, 1),
    "max_retry_after_seconds": (0, 600),
    "max_redirects": (0, 10),
    "max_response_bytes": (1024, 16777216),
    "requests_per_minute": (1, 600),
    "lookback_days": (1, 365),
    "overlap_seconds": (0, 86400),
    "max_pages": (1, 100),
    "page_size": (1, 100),
    "max_items_per_source": (1, 10000),
    "content_chars": (1000, 100000),
    "stale_after_seconds": (300, 604800),
    "failure_backoff_base_seconds": (1, 3600),
    "failure_backoff_cap_seconds": (1, 604800),
    "max_output_tokens": (128, 8192),
    "max_input_chars": (1000, 100000),
    "max_items_per_run": (1, 1000),
    "retry_base_seconds": (1, 3600),
    "retry_cap_seconds": (1, 604800),
    "run_budget_seconds": (30, 3600),
    "source_budget_seconds": (5, 600),
    "analysis_reserve_fraction": (0.1, 0.9),
    "feed_size": (1, 500),
    "reconcile_seconds": (300, 604800),
    "max_xml_depth": (8, 256),
    "max_xml_elements": (100, 100000),
    "healthy_poll_tolerance_seconds": (0, 60),
    "tag_priority_score": (0, 20),
    "min_reports": (2, 100),
    "min_span_seconds": (300, 604800),
    "window_seconds": (600, 2592000),
    "retention_days": (1, 365),
    "max_observations": (100, 100000),
    "max_groups": (10, 10000),
    "max_source_links": (2, 10),
    "max_alerts_per_item": (1, 1000),
    "max_future_seconds": (0, 3600),
}


# Settings that older configuration files may still contain. They are accepted
# and ignored, so a deployment can delete them at its own pace.
RETIRED = {"storage": {"max_stories"}}


def _expand(value: str) -> str:
    def sub(match: re.Match) -> str:
        name = match.group(1)
        if name not in os.environ:
            raise ValueError(f"Required environment variable {name} is missing")
        return os.environ[name]

    return re.sub(r"\$\{([A-Z_][A-Z0-9_]*)\}", sub, value)


def load_config(path: str | Path) -> dict:
    path = Path(path).expanduser().resolve(strict=True)
    with path.open("rb") as stream:
        raw = tomllib.load(stream)
    config = copy.deepcopy(DEFAULTS)
    unknown = set(raw) - set(DEFAULTS)
    if unknown:
        raise ValueError(f"Unknown config sections: {', '.join(sorted(unknown))}")
    for section, values in raw.items():
        if section == "sources":
            config[section] = values
        else:
            if not isinstance(values, dict):
                raise ValueError(f"{section} must be a table")
            values = {k: v for k, v in values.items() if k not in RETIRED.get(section, ())}
            unknown = set(values) - set(DEFAULTS[section])
            if unknown:
                raise ValueError(
                    f"Unknown {section} settings: {', '.join(sorted(unknown))}"
                )
            config[section].update(values)
    for section in ("http", "collection", "llm", "storage", "site", "monitoring"):
        for key, value in config[section].items():
            if key in BOUNDS:
                low, high = BOUNDS[key]
                if (
                    isinstance(value, bool)
                    or not isinstance(value, (int, float))
                    or not low <= value <= high
                ):
                    raise ValueError(
                        f"{section}.{key} must be between {low} and {high}"
                    )
                if key not in {
                    "timeout_seconds",
                    "connect_timeout_seconds",
                    "backoff_base_seconds",
                    "backoff_cap_seconds",
                    "backoff_jitter",
                    "max_retry_after_seconds",
                    "analysis_reserve_fraction",
                } and not isinstance(value, int):
                    raise ValueError(f"{section}.{key} must be an integer")
    if config["http"]["backoff_cap_seconds"] < config["http"]["backoff_base_seconds"]:
        raise ValueError("HTTP backoff cap must be at least its base")
    monitoring = config["monitoring"]
    if not monitoring["min_span_seconds"] <= monitoring["window_seconds"] <= monitoring["retention_days"] * 86400:
        raise ValueError("Monitoring window must cover the minimum span and fit within retention")
    base_url = _expand(config["site"]["base_url"])
    parsed_site = urlsplit(base_url)
    if (
        parsed_site.scheme not in {"http", "https"}
        or not parsed_site.hostname
        or parsed_site.username is not None
        or parsed_site.password is not None
        or parsed_site.query
        or parsed_site.fragment
        or "\\" in base_url
        or any(ord(c) < 33 for c in base_url)
        or any(p in {".", ".."} for p in unquote(parsed_site.path).split("/"))
    ):
        raise ValueError("site.base_url must be a clean absolute HTTP(S) URL")
    _ = parsed_site.port
    config["site"]["base_url"] = base_url.rstrip("/") + "/"
    config["site"]["repository_url"] = canonical_url(config["site"]["repository_url"])
    for key in ("title", "description"):
        if not isinstance(config["site"][key], str) or len(config["site"][key]) > 300:
            raise ValueError(f"site.{key} must be a short string")
    for key in ("database", "output_dir"):
        value = Path(_expand(config["storage"][key])).expanduser()
        candidate = value if value.is_absolute() else path.parent / value
        if candidate.is_symlink():
            raise ValueError(f"storage.{key} must not be a symlink")
        config["storage"][key] = str(candidate.resolve())
    output = Path(config["storage"]["output_dir"])
    database = Path(config["storage"]["database"])
    if output == path.parent or output in path.parents or output == Path(output.anchor):
        raise ValueError("Output must be a dedicated generated directory")
    if database == output or output in database.parents:
        raise ValueError("Database must be outside public output")
    llm = config["llm"]
    for key in ("allow_http", "enable_thinking", "send_chat_template_kwargs"):
        if not isinstance(llm[key], bool):
            raise ValueError(f"llm.{key} must be a boolean")
    llm["base_url"] = _expand(llm["base_url"]).rstrip("/")
    if not isinstance(llm["fallback_base_urls"], list) or not isinstance(
        llm["allowed_networks"], list
    ):
        raise ValueError("LLM fallback_base_urls and allowed_networks must be arrays")
    llm["fallback_base_urls"] = [
        _expand(u).rstrip("/") for u in llm["fallback_base_urls"]
    ]
    for network in llm["allowed_networks"]:
        parsed_network = ipaddress.ip_network(network, strict=True)
        if parsed_network.prefixlen == 0:
            raise ValueError(
                "LLM private-network allowlist must not include a default route"
            )
    for url in [llm["base_url"], *llm["fallback_base_urls"]]:
        if not url:
            continue
        parsed = urlsplit(url)
        if (
            parsed.scheme not in ({"https", "http"} if llm["allow_http"] else {"https"})
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "Invalid LLM base URL; credentials belong in its environment variable"
            )
    if not isinstance(llm["api_key_env"], str) or not re.fullmatch(
        r"[A-Z_][A-Z0-9_]*", llm["api_key_env"]
    ):
        raise ValueError("llm.api_key_env must name an environment variable")
    if not isinstance(llm["model"], str) or not llm["model"] or len(llm["model"]) > 200:
        raise ValueError("llm.model must be a nonempty model identifier")
    sources = config["sources"]
    if not isinstance(sources, list) or not sources or len(sources) > 100:
        raise ValueError("Configure between 1 and 100 sources")
    ids: set[str] = set()
    for source in sources:
        allowed = {
            "id",
            "name",
            "kind",
            "url",
            "website_url",
            "fallback_urls",
            "product",
            "authority",
            "enabled",
            "max_pages",
            "max_items",
            "interval_seconds",
            "alert_format",
            "monitor_id",
        }
        if not isinstance(source, dict) or set(source) - allowed:
            raise ValueError("Invalid source keys")
        if (
            not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", source.get("id", ""))
            or source["id"] in ids
        ):
            raise ValueError("Source IDs must be unique short lowercase identifiers")
        ids.add(source["id"])
        source.setdefault("name", source["id"])
        source.setdefault("kind", "feed")
        source.setdefault("fallback_urls", [])
        source.setdefault("product", "network")
        source.setdefault("authority", "community")
        source.setdefault("enabled", True)
        source.setdefault("interval_seconds", 300)
        source.setdefault("alert_format", "")
        source.setdefault("monitor_id", source["id"])
        if not isinstance(source["alert_format"], str) or source["alert_format"] not in {"", "consensus", "censorship"}:
            raise ValueError("Unsupported alert format")
        if not isinstance(source["monitor_id"], str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", source["monitor_id"]):
            raise ValueError("Invalid monitor identity")
        if source["alert_format"] and (source["kind"] != "feed" or source["authority"] != "telemetry"):
            raise ValueError("Alert parsers require a feed classified as telemetry")
        if source["kind"] not in {"feed", "tag", "gitlab_issue", "gitlab_mr", "metrics_timeline"}:
            raise ValueError("Unsupported source kind")
        if source["authority"] not in {
            "official",
            "community",
            "development",
            "telemetry",
        }:
            raise ValueError("Unsupported source authority")
        if source["product"] not in PRODUCTS:
            raise ValueError("Unsupported source product")
        if (
            not isinstance(source["enabled"], bool)
            or not isinstance(source["interval_seconds"], int)
            or not 30 <= source["interval_seconds"] <= 604800
        ):
            raise ValueError("Invalid source enabled/interval_seconds")
        if (
            not isinstance(source["fallback_urls"], list)
            or len(source["fallback_urls"]) > 5
        ):
            raise ValueError("At most five fallback URLs per source")
        source["url"] = canonical_url(source["url"])
        source["website_url"] = canonical_url(source.get("website_url", source["url"]))
        if source["kind"] == "metrics_timeline":
            website = urlsplit(source["website_url"])
            if website.query or website.fragment or not website.path.strip("/"):
                raise ValueError("Timeline website_url must be a clean repository URL")
        source["fallback_urls"] = [canonical_url(u) for u in source["fallback_urls"]]
        for key, global_key in [
            ("max_pages", "max_pages"),
            ("max_items", "max_items_per_source"),
        ]:
            source.setdefault(key, config["collection"][global_key])
            low, high = BOUNDS[global_key]
            if (
                not isinstance(source[key], int)
                or isinstance(source[key], bool)
                or not low <= source[key] <= high
            ):
                raise ValueError(f"Invalid source {key}")
    config["_config_path"] = str(path)
    return config
