"""Synced deterministic identity registries for Tor contributors, AROI operators, and authorities."""

from __future__ import annotations

import base64
import binascii
import json
import re
import time
from typing import Any
from urllib.parse import urlencode

from .transport import DeadlineReached, FetchError, HttpClient
from .util import (
    DEFAULT_TOR_CORE_USERS,
    canonical_json,
    has_invalid_text_chars,
    is_valid_domain,
    is_valid_gitlab_user,
    parse_utc,
    plain_text,
    timestamp,
)

TPO_PEOPLE_TREE_URL = "https://gitlab.torproject.org/api/v4/projects/tpo%2Fweb%2Ftpo/repository/tree"
TPO_GRAPHQL_URL = "https://gitlab.torproject.org/api/graphql"
AUTH_DIRS_FILE_URL = (
    "https://gitlab.torproject.org/api/v4/projects/tpo%2Fcore%2Ftor/"
    "repository/files/src%2Fapp%2Fconfig%2Fauth_dirs.inc?ref=main"
)
AROI_VALIDATOR_URL = "https://aroivalidator.1aeo.com/latest.json"

AROI_MIN_VALID_RELAYS = 100
AROI_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
REFRESH_INTERVAL_SECONDS = 86400
RUN_BUDGET_SECONDS = 15
MAX_IDENTITIES = 500
MIN_CORE_USERS = 20

_TREE_PAGE_SIZE = 100
_MAX_TREE_PAGES = 10
_GRAPHQL_CHUNK_SIZE = 40
_MIN_AUTH_DIR_NICKS = 5

_META_TOR_CORE = "registry.tor_core_users"
_META_TRUSTED_DOMAINS = "registry.trusted_operator_domains"
_META_AUTH_DIRS = "registry.auth_dirs_nicknames"
_META_LAST_REFRESH = "registry.last_refresh_at"
_META_LAST_ERROR = "registry.last_error"

_TPO_PEOPLE_QUERY = (
    'query($paths: [String!]!) { project(fullPath: "tpo/web/tpo") '
    "{ repository { blobs(paths: $paths) { nodes { path rawBlob } } } } }"
)
_LEKTOR_KEY_RE = re.compile(r"[A-Za-z0-9_.-]+")
_TREE_SLUG_RE = re.compile(r"[A-Za-z0-9_.-]+")
_AUTH_DIR_NICK_RE = re.compile(r'^\s*"([A-Za-z0-9_-]+)\s+orport=', re.MULTILINE)


class RegistryError(ValueError):
    """Sanitized validation error raised when a remote registry payload fails closed."""


def _reject_constant(_: str) -> None:
    """Reject non-finite JSON constants such as NaN or Infinity."""
    raise ValueError("Non-finite JSON constant")


def _header_ci(headers: dict[str, str], name: str) -> str | None:
    """Return a response header value matching `name` case-insensitively, or None."""
    target = name.lower()
    for key, value in headers.items():
        if isinstance(key, str) and key.lower() == target:
            return str(value)
    return None


def _request_json(client: HttpClient, method: str, url: str, **kwargs: Any) -> tuple[Any, Any]:
    """Perform one bounded request, enforce HTTP 200, and decode JSON fail-closed."""
    response = client.request(method, url, **kwargs)
    if response.status != 200:
        raise RegistryError(f"HTTP {response.status}")
    try:
        return response, response.json()
    except FetchError:
        raise RegistryError("invalid JSON response") from None


def _is_torproject_domain(domain: str) -> bool:
    """Return whether `domain` is `torproject.org` or a subdomain of it."""
    return domain == "torproject.org" or domain.endswith(".torproject.org")


def parse_lektor_fields(raw_blob: str) -> dict[str, str]:
    """Parse a Lektor `contents.lr` document separated by `---` lines into key/value strings."""
    if not isinstance(raw_blob, str):
        raise RegistryError("Lektor blob must be text")
    fields: dict[str, str] = {}
    lines = raw_blob.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    chunks: list[list[str]] = []
    current: list[str] = []
    for line in lines:
        if line.strip() == "---":
            chunks.append(current)
            current = []
        else:
            current.append(line)
    chunks.append(current)
    for chunk in chunks:
        while chunk and not chunk[0].strip():
            chunk.pop(0)
        if not chunk:
            continue
        key, sep, first_val = chunk[0].partition(":")
        key = key.strip()
        if not sep or not _LEKTOR_KEY_RE.fullmatch(key):
            continue
        inline = first_val.strip()
        rest = "\n".join(chunk[1:]).strip()
        if inline and rest:
            value = f"{inline}\n{rest}"
        else:
            value = inline or rest
        fields[key] = value
    return fields


def fetch_tor_core_users(client: HttpClient) -> list[str]:
    """Fetch and validate Tor Project core GitLab usernames from `tpo/web/tpo`."""
    slugs: list[str] = []
    seen_slugs: set[str] = set()
    for page in range(1, _MAX_TREE_PAGES + 1):
        query = urlencode({"path": "content/about/people", "per_page": _TREE_PAGE_SIZE, "page": page})
        response, entries = _request_json(
            client, "GET", f"{TPO_PEOPLE_TREE_URL}?{query}", headers={"Accept": "application/json"},
        )
        if not isinstance(entries, list):
            raise RegistryError("Unexpected GitLab tree payload")
        for entry in entries:
            if not isinstance(entry, dict):
                raise RegistryError("Invalid GitLab tree entry")
            if entry.get("type") != "tree":
                continue
            name = entry.get("name")
            if (
                isinstance(name, str)
                and name not in {".", ".."}
                and ".." not in name
                and _TREE_SLUG_RE.fullmatch(name)
                and name not in seen_slugs
            ):
                seen_slugs.add(name)
                slugs.append(name)
        next_page = _header_ci(response.headers, "x-next-page")
        if next_page is not None:
            next_str = next_page.strip()
            if not next_str or not next_str.isdigit() or int(next_str) != page + 1:
                break
        elif len(entries) < _TREE_PAGE_SIZE:
            break

    if not slugs:
        raise RegistryError("No people entries found in repository tree")

    users: set[str] = set()
    for offset in range(0, len(slugs), _GRAPHQL_CHUNK_SIZE):
        chunk = slugs[offset : offset + _GRAPHQL_CHUNK_SIZE]
        path_to_slug = {f"content/about/people/{slug}/contents.lr": slug for slug in chunk}
        _, payload = _request_json(
            client,
            "POST",
            TPO_GRAPHQL_URL,
            headers={"Accept": "application/json"},
            json_body={"query": _TPO_PEOPLE_QUERY, "variables": {"paths": list(path_to_slug)}},
        )
        if not isinstance(payload, dict) or payload.get("errors"):
            raise RegistryError("GraphQL error response")
        data = payload.get("data")
        project = data.get("project") if isinstance(data, dict) else None
        repo = project.get("repository") if isinstance(project, dict) else None
        blobs = repo.get("blobs") if isinstance(repo, dict) else None
        nodes = blobs.get("nodes") if isinstance(blobs, dict) else None
        if not isinstance(nodes, list):
            raise RegistryError("Missing GraphQL blob nodes")
        for node in nodes:
            if not isinstance(node, dict):
                raise RegistryError("Invalid GraphQL blob node")
            path = node.get("path")
            if not isinstance(path, str) or path not in path_to_slug:
                raise RegistryError("Unexpected GraphQL blob path")
            raw_blob = node.get("rawBlob")
            if raw_blob is None:
                continue
            if not isinstance(raw_blob, str):
                raise RegistryError("Invalid GraphQL blob content")
            slug = path_to_slug[path]
            fields = {k.lower(): v for k, v in parse_lektor_fields(raw_blob).items()}
            if fields.get("role", "").strip().casefold() != "core":
                continue
            nickname = fields.get("nickname", "").strip().lower()
            if is_valid_gitlab_user(nickname):
                users.add(nickname)
            slug_lower = slug.strip().lower()
            if not slug_lower.endswith("-core") and is_valid_gitlab_user(slug_lower):
                users.add(slug_lower)

    if len(users) < MIN_CORE_USERS:
        raise RegistryError(f"Insufficient Tor core users ({len(users)})")
    return sorted(users)


def fetch_trusted_operator_domains(
    client: HttpClient, *, min_valid_relays: int = AROI_MIN_VALID_RELAYS,
) -> list[str]:
    """Fetch and validate AROI operator domains meeting the minimum valid-relay threshold."""
    if type(min_valid_relays) is not int or min_valid_relays < 1:
        raise ValueError("min_valid_relays must be a positive integer")
    _, payload = _request_json(client, "GET", AROI_VALIDATOR_URL, headers={"Accept": "application/json"})
    if not isinstance(payload, dict):
        raise RegistryError("Unexpected AROI payload")
    results = payload.get("results")
    if not isinstance(results, list) or len(results) < AROI_MIN_VALID_RELAYS:
        raise RegistryError("Insufficient AROI validator results")
    counts: dict[str, int] = {}
    for row in results:
        if not isinstance(row, dict) or row.get("valid") is not True:
            continue
        raw_domain = row.get("domain")
        if not isinstance(raw_domain, str):
            continue
        domain = raw_domain.strip().lower().removeprefix("www.")
        if not is_valid_domain(domain) or _is_torproject_domain(domain):
            continue
        counts[domain] = counts.get(domain, 0) + 1
    kept = sorted(domain for domain, count in counts.items() if count >= min_valid_relays)[:MAX_IDENTITIES]
    if not kept:
        raise RegistryError("No trusted operator domains met threshold")
    return kept


def fetch_auth_dir_nicknames(client: HttpClient) -> list[str]:
    """Fetch and parse Tor directory authority nicknames from `auth_dirs.inc`."""
    _, record = _request_json(client, "GET", AUTH_DIRS_FILE_URL, headers={"Accept": "application/json"})
    if (
        not isinstance(record, dict)
        or record.get("encoding") != "base64"
        or not isinstance(record.get("content"), str)
    ):
        raise RegistryError("Unexpected GitLab file metadata")
    try:
        decoded = base64.b64decode("".join(record["content"].splitlines()), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        raise RegistryError("Invalid base64 auth_dirs content") from None
    stripped = re.sub(r"/\*.*?\*/", "", decoded, flags=re.S)
    nicknames = sorted(set(_AUTH_DIR_NICK_RE.findall(stripped)))
    if len(nicknames) < _MIN_AUTH_DIR_NICKS:
        raise RegistryError("Insufficient directory authority nicknames")
    return nicknames


def _conn(db: Any) -> Any:
    """Resolve either a SQLite connection or a `Store` instance to its connection."""
    return getattr(db, "db", db)


def _read_meta_text(conn: Any, key: str) -> str | None:
    """Read one metadata entry strictly as valid UTF-8 text, returning None if absent or damaged."""
    row = conn.execute("SELECT typeof(value), CAST(value AS BLOB) FROM metadata WHERE key=?", (key,)).fetchone()
    if row is None or row[0] != "text":
        return None
    try:
        return str(row[1], "utf-8")
    except UnicodeDecodeError:
        return None


def _parse_meta_list(raw: str | None) -> list[Any]:
    """Decode a JSON array from metadata, returning an empty list on damaged input."""
    if raw is None:
        return []
    try:
        parsed = json.loads(raw, parse_constant=_reject_constant)
    except (ValueError, TypeError, RecursionError):
        return []
    return parsed if isinstance(parsed, list) else []


def _valid_operator_domain(domain: str) -> bool:
    """Return whether `domain` is a valid non-TorProject operator domain."""
    return is_valid_domain(domain) and not _is_torproject_domain(domain)


def _is_valid_nickname(value: str) -> bool:
    """Return whether `value` is a clean single-line directory authority nickname."""
    return bool(value) and len(value) <= 100 and not has_invalid_text_chars(value) and "\n" not in value and "\t" not in value


def _dedup_identities(sequences: tuple[Any, ...], pred: Any, *, lowercase: bool = True, limit: int = MAX_IDENTITIES) -> list[str]:
    """Collect up to `limit` unique normalized strings satisfying `pred` across `sequences`."""
    result: list[str] = []
    seen: set[str] = set()
    for seq in sequences:
        if not isinstance(seq, (list, tuple, set, frozenset)):
            continue
        for entry in seq:
            if len(result) >= limit:
                return result
            if isinstance(entry, str):
                ident = entry.strip().lower() if lowercase else entry.strip()
                if ident and pred(ident) and ident not in seen:
                    seen.add(ident)
                    result.append(ident)
    return result


def load_cached(db: Any) -> dict[str, Any]:
    """Load and fail-closed validate cached registry metadata from SQLite."""
    empty: dict[str, Any] = {
        "tor_core_users": [],
        "trusted_operator_domains": [],
        "auth_dirs_nicknames": [],
        "last_refresh_at": None,
        "last_error": None,
    }
    if db is None:
        return empty
    conn = _conn(db)
    if not conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='metadata'").fetchone():
        return empty

    core_users = _dedup_identities((_parse_meta_list(_read_meta_text(conn, _META_TOR_CORE)),), is_valid_gitlab_user)
    domains = _dedup_identities((_parse_meta_list(_read_meta_text(conn, _META_TRUSTED_DOMAINS)),), _valid_operator_domain)
    nicknames = _dedup_identities(
        (_parse_meta_list(_read_meta_text(conn, _META_AUTH_DIRS)),),
        _is_valid_nickname,
        lowercase=False,
    )

    raw_refresh = _read_meta_text(conn, _META_LAST_REFRESH)
    try:
        last_refresh_at = timestamp(raw_refresh) if raw_refresh is not None else None
    except ValueError:
        last_refresh_at = None

    raw_error = _read_meta_text(conn, _META_LAST_ERROR)
    clean_error = plain_text(raw_error, 160, html=False)[:160] if isinstance(raw_error, str) else ""

    return {
        "tor_core_users": core_users,
        "trusted_operator_domains": domains,
        "auth_dirs_nicknames": nicknames,
        "last_refresh_at": last_refresh_at,
        "last_error": clean_error or None,
    }


def effective_identities(config: dict, db: Any) -> tuple[list[str], list[str]]:
    """Merge configured and cached Tor core users and trusted domains, capped at `MAX_IDENTITIES`."""
    collection = config.get("collection") or {}
    cached = load_cached(db)
    users = _dedup_identities(
        (collection.get("tor_core_gitlab_users", DEFAULT_TOR_CORE_USERS), sorted(cached["tor_core_users"])),
        is_valid_gitlab_user,
    )
    domains = _dedup_identities(
        (collection.get("trusted_operator_domains", ()), sorted(cached["trusted_operator_domains"])),
        _valid_operator_domain,
    )
    return users, domains


def refresh_if_due(
    config: dict,
    store: Any,
    observed: str,
    *,
    deadline: float | None = None,
    client: HttpClient | None = None,
) -> dict[str, Any]:
    """Refresh remote registries when enabled and due, preserving valid cache on errors."""
    enabled = bool((config.get("registry") or {}).get("enabled", False))
    if not enabled:
        return {"enabled": False, "due": False, "refreshed": False, "updated": {}}

    observed_ts = timestamp(observed)
    cached = load_cached(store.db)
    last_refresh_at = cached["last_refresh_at"]
    if last_refresh_at is not None:
        elapsed = (parse_utc(observed_ts) - parse_utc(last_refresh_at)).total_seconds()
        if 0 <= elapsed < REFRESH_INTERVAL_SECONDS:
            return {
                "enabled": True,
                "due": False,
                "refreshed": False,
                "updated": {},
                "last_refresh_at": last_refresh_at,
                "last_error": cached["last_error"],
                "tor_core_count": len(cached["tor_core_users"]),
                "trusted_domains_count": len(cached["trusted_operator_domains"]),
                "auth_dirs_nicknames": cached["auth_dirs_nicknames"],
            }

    effective_deadline = min(
        deadline if deadline is not None else float("inf"),
        time.monotonic() + RUN_BUDGET_SECONDS,
    )
    owns_client = client is None
    if owns_client:
        http_cfg = dict(config.get("http") or {})
        http_cfg["max_response_bytes"] = max(int(http_cfg.get("max_response_bytes", 0)), AROI_MAX_RESPONSE_BYTES)
        active_client = HttpClient(http_cfg)
        active_client.deadline = effective_deadline
        had_deadline, prev_deadline = False, None
    else:
        active_client = client
        had_deadline = hasattr(active_client, "deadline")
        prev_deadline = getattr(active_client, "deadline", None)
        if had_deadline:
            active_client.deadline = (
                min(prev_deadline, effective_deadline) if prev_deadline is not None else effective_deadline
            )

    updates: dict[str, str] = {}
    updated_counts: dict[str, int] = {}
    errors: list[str] = []
    budget_reached = False
    fetchers = (
        ("tor_core_users", _META_TOR_CORE, fetch_tor_core_users),
        ("trusted_operator_domains", _META_TRUSTED_DOMAINS, fetch_trusted_operator_domains),
        ("auth_dirs_nicknames", _META_AUTH_DIRS, fetch_auth_dir_nicknames),
    )

    try:
        for field_name, meta_key, fetcher in fetchers:
            if time.monotonic() >= effective_deadline:
                errors.append(f"{field_name}: request deadline reached")
                budget_reached = True
                break
            try:
                values = fetcher(active_client)
            except DeadlineReached:
                errors.append(f"{field_name}: request deadline reached")
                budget_reached = True
                break
            except (FetchError, RegistryError, ValueError, TypeError, KeyError) as exc:
                reason = plain_text(str(exc), 120, html=False) or type(exc).__name__
                errors.append(f"{field_name}: {reason}")
                if getattr(active_client, "deadline_reached", False):
                    budget_reached = True
                    break
            else:
                updates[meta_key] = canonical_json(values)
                updated_counts[field_name] = len(values)
    finally:
        if owns_client:
            active_client.close()
        elif had_deadline:
            active_client.deadline = prev_deadline

    from .store import set_meta

    with store.db:
        if updates:
            writes = {**updates, _META_LAST_REFRESH: observed_ts}
            if errors:
                writes[_META_LAST_ERROR] = plain_text("; ".join(errors), 160, html=False)[:160]
            set_meta(store.db, **writes)
            if not errors:
                store.db.execute("DELETE FROM metadata WHERE key=?", (_META_LAST_ERROR,))
        elif errors:
            set_meta(store.db, **{_META_LAST_ERROR: plain_text("; ".join(errors), 160, html=False)[:160]})

    final = load_cached(store.db)
    return {
        "enabled": True,
        "due": True,
        "refreshed": bool(updates),
        "updated": updated_counts,
        "errors": errors,
        "budget_reached": budget_reached,
        "last_refresh_at": final["last_refresh_at"],
        "last_error": final["last_error"],
        "tor_core_count": len(final["tor_core_users"]),
        "trusted_domains_count": len(final["trusted_operator_domains"]),
        "auth_dirs_nicknames": final["auth_dirs_nicknames"],
    }


def status(db: Any, config: dict) -> dict[str, Any]:
    """Return read-only registry synchronization status and cached counts."""
    cached = load_cached(db)
    return {
        "enabled": bool((config.get("registry") or {}).get("enabled", False)),
        "last_refresh_at": cached["last_refresh_at"],
        "last_error": cached["last_error"],
        "tor_core_count": len(cached["tor_core_users"]),
        "trusted_domains_count": len(cached["trusted_operator_domains"]),
        "auth_dirs_nicknames": cached["auth_dirs_nicknames"],
    }
