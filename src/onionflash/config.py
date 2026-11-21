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
from .util import DIRAUTH_GITLAB_USERS, canonical_url, is_valid_domain, is_valid_gitlab_user

DEFAULT_TRUSTED_OPERATOR_DOMAINS = [
    "1aeo.com",
    "applied-privacy.net",
    "appliedprivacy.net",
    "artikel10.org",
    "dfri.se",
    "nothingtohide.nl",
    "prsv.ch",
    "quintex.com",
    "unredacted.org",
]

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
        "trusted_operator_domains": DEFAULT_TRUSTED_OPERATOR_DOMAINS,
        "dirauth_gitlab_users": list(DIRAUTH_GITLAB_USERS),
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
    "timeout_seconds": (1, 3600),
    "max_pages": (1, 100),
    "page_size": (1, 100),
    "max_items_per_source": (1, 10000),
    "max_items_per_run": (1, 1000),
}

OPERATOR_SETTINGS = {
    "collection": {"trusted_operator_domains", "dirauth_gitlab_users"},
    "http": set(),
    "llm": {
        "base_url", "fallback_base_urls", "model", "allowed_networks",
        "allow_http", "send_chat_template_kwargs", "max_items_per_run", "timeout_seconds", "writer_reasoning",
    },
    "storage": {"database", "output_dir"},
}

SECTION_SPECS = {
    "collection": {"lists": ("trusted_operator_domains", "dirauth_gitlab_users")},
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


def completion_budget_seconds(llm: dict) -> float:
    """Transport allowance for one admitted completion, including connection time."""
    return max(llm["total_timeout_seconds"], llm["timeout_seconds"] + llm["connect_timeout_seconds"])


def run_command_budget_seconds(config: dict) -> float:
    """Run admission window plus the last admitted completion's transport allowance.

    Wrappers should add their own allowance for build and cleanup work.
    """
    return config["collection"]["run_budget_seconds"] + completion_budget_seconds(config["llm"])


def enabled_consensus_sources(sources: list[dict], *, check_single: bool = False) -> list[dict]:
    """Return enabled consensus-alert sources, optionally enforcing at most one."""
    active = [s for s in sources if s.get("alert_format") == "consensus" and s.get("enabled")]
    if check_single and len(active) > 1:
        raise ValueError("At most one enabled consensus alert source is supported")
    return active


def _clean_ident_list(raw: list, limit: int, pred, error: str, *, limit_error: str | None = None, skip: str = "") -> list[str]:
    if len(raw) > limit:
        raise ValueError(limit_error or error)
    cleaned: list[str] = []
    for entry in raw:
        if not isinstance(entry, str) or not pred(ident := entry.strip().lower()):
            raise ValueError(error)
        if ident != skip and ident not in cleaned:
            cleaned.append(ident)
    return cleaned


def _check_range(value: object, low: int, high: int, *, allow_float: bool = False) -> bool:
    ok_type = type(value) in (int, float) if allow_float else type(value) is int
    return ok_type and low <= value <= high


def _expand(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Configuration value must be a string")

    def sub(match: re.Match) -> str:
        """Resolve a `${NAME}` placeholder from the current process environment."""
        name = match.group(1)
        if name not in os.environ:
            raise ValueError(f"Required environment variable {name} is missing")
        return os.environ[name]

    return re.sub(r"\$\{([A-Z_][A-Z0-9_]*)\}", sub, value)


def _dns_request_url(raw: str, canonical: str) -> str:
    """Preserve a single configured trailing FQDN dot on the host for DNS lookup only."""
    raw_host = urlsplit(raw).hostname or ""
    if not raw_host.endswith("."):
        return canonical
    parsed = urlsplit(canonical)
    host = parsed.hostname or ""
    if not host or ":" in host:
        return canonical
    netloc = f"{host}.:{parsed.port}" if parsed.port is not None else f"{host}."
    return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))


def _clean_endpoint_url(
    url: str,
    *,
    allow_http: bool,
    trailing_slash: bool,
    error: str,
    allow_local: bool = False,
    address_policy=None,
) -> str:
    if not isinstance(url, str):
        raise ValueError(error)
    try:
        url.encode("utf-8")
        parsed = urlsplit(url)
        port = parsed.port
    except (UnicodeError, ValueError):
        raise ValueError(error) from None
    if (
        parsed.scheme not in ({"https", "http"} if allow_http else {"https"})
        or not parsed.hostname
        or "%" in parsed.hostname
        or (port is not None and not 1 <= port <= 65535)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (not trailing_slash and ("?" in url or "#" in url))
        or "\\" in url
        or any(ord(c) < 33 or ord(c) == 127 or c in "\ufffe\uffff" for c in url)
        or any(p in {".", ".."} for p in unquote(parsed.path).split("/"))
    ):
        raise ValueError(error)
    import httpx

    try:
        parsed_url = httpx.URL(urlunsplit((parsed.scheme, parsed.netloc, "/", "", "")))
        raw_host = parsed_url.raw_host.decode("ascii").lower()
    except (httpx.InvalidURL, UnicodeError, ValueError):
        raise ValueError(error) from None
    if not raw_host or "%" in raw_host or raw_host.endswith(".."):
        raise ValueError(error)
    clean_host = raw_host[:-1] if raw_host.endswith(".") else raw_host
    if not clean_host:
        raise ValueError(error)
    if not allow_local and (
        clean_host == "localhost" or clean_host.endswith((".localhost", ".local", ".internal"))
    ):
        raise ValueError(error)
    try:
        ip = ipaddress.ip_address(clean_host)
    except ValueError:
        if all(re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)", part) for part in clean_host.split(".")):
            raise ValueError(error) from None
        if "." in clean_host:
            if not is_valid_domain(clean_host):
                raise ValueError(error) from None
        elif not (allow_local and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", clean_host)):
            raise ValueError(error) from None
    else:
        if (
            clean_host != raw_host
            or ip.is_unspecified
            or ip.is_multicast
            or (isinstance(ip, ipaddress.IPv6Address) and ip.scope_id is not None)
        ):
            raise ValueError(error)
        if address_policy is not None:
            if not address_policy.permits(ip):
                raise ValueError(error)
        elif not allow_local:
            from . import transport

            if not transport.PUBLIC_ADDRESS_POLICY.permits(ip):
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

    domain_err = "Each trusted_operator_domains entry must be a valid domain name"
    config["collection"]["trusted_operator_domains"] = _clean_ident_list(
        config["collection"]["trusted_operator_domains"], 500, is_valid_domain, domain_err,
        limit_error=f"{domain_err} (at most 500 entries)", skip="torproject.org",
    )
    config["collection"]["dirauth_gitlab_users"] = _clean_ident_list(
        config["collection"]["dirauth_gitlab_users"], 200, is_valid_gitlab_user,
        "Each dirauth_gitlab_users entry must be a valid GitLab username",
    )

    config["site"]["base_url"] = _clean_endpoint_url(
        _expand(config["site"]["base_url"]),
        allow_http=True,
        trailing_slash=True,
        error="site.base_url must be a clean absolute HTTP(S) URL",
        allow_local=True,
    )
    config["site"]["repository_url"] = canonical_url(config["site"]["repository_url"])

    for key in ("database", "output_dir"):
        expanded = _expand(config["storage"][key])
        if not expanded.strip():
            raise ValueError(f"storage.{key} must not be empty")
        value = Path(expanded).expanduser()
        candidate = value if value.is_absolute() else path.parent / value
        if candidate.is_symlink():
            raise ValueError(f"storage.{key} must not be a symlink")
        config["storage"][key] = str(candidate.resolve())
    output, database = Path(config["storage"]["output_dir"]), Path(config["storage"]["database"])
    if output == path.parent or output in path.parents or output == Path(output.anchor):
        raise ValueError("Output must be a dedicated generated directory")
    if database == path or database == path.parent or database in path.parents or database.is_dir():
        raise ValueError("Database must be a file path outside config and directory roots")
    if database == output or output in database.parents or database in output.parents:
        raise ValueError("Database must be outside public output")

    llm = config["llm"]
    if any(ord(c) < 32 or ord(c) == 127 for c in llm["model"]) or not (llm_model := llm["model"].strip()):
        raise ValueError("llm.model must be a valid model identifier")
    llm["model"] = llm_model
    if llm["writer_reasoning"] and not llm["send_chat_template_kwargs"]:
        raise ValueError("llm.writer_reasoning requires llm.send_chat_template_kwargs")
    llm["base_url"] = _expand(llm["base_url"])
    llm["fallback_base_urls"] = [_expand(u) if isinstance(u, str) else "" for u in llm["fallback_base_urls"]]
    if any(not u.strip().rstrip("/") for u in llm["fallback_base_urls"]):
        raise ValueError("Each LLM fallback base URL must be a nonempty URL")
    for network in llm["allowed_networks"]:
        if not isinstance(network, str) or ipaddress.ip_network(network, strict=True).prefixlen == 0:
            raise ValueError("Each allowed_networks entry must be a non-default CIDR string")
    llm_error = "Invalid LLM base URL; credentials belong in its environment variable"
    from . import transport

    llm_policy = transport.AddressPolicy(llm["allowed_networks"]) if llm["allowed_networks"] else transport.PUBLIC_ADDRESS_POLICY
    allow_llm_local = bool(llm["allowed_networks"])
    if llm["base_url"]:
        llm["base_url"] = _clean_endpoint_url(
            llm["base_url"],
            allow_http=llm["allow_http"],
            trailing_slash=False,
            error=llm_error,
            allow_local=allow_llm_local,
            address_policy=llm_policy,
        )
    llm["fallback_base_urls"] = [
        _clean_endpoint_url(
            url,
            allow_http=llm["allow_http"],
            trailing_slash=False,
            error=llm_error,
            allow_local=allow_llm_local,
            address_policy=llm_policy,
        )
        for url in llm["fallback_base_urls"]
    ]

    review = config["review"]
    if not isinstance(review["model"], str) or len(review["model"]) > 200 or any(ord(c) < 32 or ord(c) == 127 for c in review["model"]):
        raise ValueError("review.model must be a short model identifier, or empty to inherit llm.model")
    review["model"] = review["model"].strip()

    sources = config["sources"]
    if not isinstance(sources, list) or not 1 <= len(sources) <= 100:
        raise ValueError("Configure between 1 and 100 sources")
    ids: set[str] = set()
    for source in sources:
        if not isinstance(source, dict) or set(source) - _SOURCE_KEYS:
            raise ValueError("Invalid source keys")
        source_id = source.get("id")
        if not isinstance(source_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", source_id) or source_id in ids:
            raise ValueError("Source IDs must be unique short lowercase identifiers")
        ids.add(source_id)
        source.setdefault("name", source_id)
        if (
            not isinstance(source["name"], str)
            or not 1 <= len(source["name"].strip()) <= 200
            or any(ord(c) < 32 or ord(c) == 127 for c in source["name"])
        ):
            raise ValueError("Invalid source name")
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
        if not isinstance(source["kind"], str) or source["kind"] not in {"feed", "tag", "gitlab_issue", "gitlab_mr", "metrics_timeline"}:
            raise ValueError("Unsupported source kind")
        if not isinstance(source["authority"], str) or source["authority"] not in {"official", "community", "development", "telemetry", "hackerone"}:
            raise ValueError("Unsupported source authority")
        if not isinstance(source["product"], str) or source["product"] not in PRODUCTS:
            raise ValueError("Unsupported source product")
        if not isinstance(source["enabled"], bool) or not _check_range(source["interval_seconds"], 30, 604800):
            raise ValueError("Invalid source enabled/interval_seconds")
        if not isinstance(source["fallback_urls"], list) or len(source["fallback_urls"]) > 5:
            raise ValueError("At most five fallback URLs per source")
        if not isinstance(source.get("url"), str):
            raise ValueError("Invalid source URL")
        raw_url = source["url"]
        source["url"] = canonical_url(raw_url)
        if "website_url" in source:
            source["website_url"] = canonical_url(source["website_url"])
        if source["kind"] == "metrics_timeline" or alert_format == "consensus":
            label = "Timeline" if source["kind"] == "metrics_timeline" else "Consensus"
            if "website_url" not in source:
                raise ValueError(f"{label} sources need website_url")
            website = urlsplit(source["website_url"])
            if website.query or website.fragment or not website.path.strip("/"):
                raise ValueError(f"{label} website_url must be a clean URL")
        raw_fallbacks = list(source["fallback_urls"])
        source["fallback_urls"] = [canonical_url(u) for u in raw_fallbacks]
        request_urls = {
            canon: req
            for raw_u, canon in ((raw_url, source["url"]), *zip(raw_fallbacks, source["fallback_urls"]))
            if (req := _dns_request_url(raw_u, canon)) != canon
        }
        if request_urls:
            source["_request_urls"] = request_urls
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
    enabled_consensus_sources(sources, check_single=True)
    return config
