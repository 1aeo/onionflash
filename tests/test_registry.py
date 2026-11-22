"""Unit tests for synced deterministic identity registries."""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
import sqlite3
import time

import httpx
import pytest

from helpers import (
    ApprovingReviewer, FakeClient, Writer, invoke_cli, make_config, patch_cli_pipeline,
    public_dns, response, write_toml,
)
from onionflash import cli, registry
from onionflash.config import DEFAULTS, load_config
from onionflash.store import Store, get_meta, set_meta
from onionflash.transport import DeadlineReached, FetchError
from onionflash.util import is_valid_gitlab_user

NOW = "2026-11-21T12:00:00Z"

SAMPLE_AUTH_DIRS = """\
/* Directory authority list */
"moria1 orport=9201 "
  "v3ident=F533C81CEF0BC0267857C99B2F471ADF249FA232 "
  "128.31.0.39:9231 1A25C6358DB91342AA51720A5038B72742732498",
"tor26 orport=443 "
  "217.196.147.77:80 FAA4 BCA4 A6AC 0FB4 CA2F 8AD5 A11D 9E12 2BA8 94F6",
"dizum orport=443 "
  "45.66.35.11:80 7EA6 EAD6 FD83 083C 538F 4403 8BBF A077 587D D755",
"Serge orport=9001 bridge "
  "66.111.2.131:9030 BA44 A889 E64B 93FA A2B1 14E0 2C2A 279A 8555 C533",
"gabelmoo orport=443 "
  "131.188.40.189:80 F204 4413 DAC2 E02E 3D6B CF47 35A1 9BCA 1DE9 7281",
"dannenberg orport=443 "
  "193.23.244.244:80 7BE6 83E6 5D48 1413 21C5 ED92 F075 C553 64AC 7123",
"maatuska orport=80 "
  "91.223.231.13:443 BD6A 8292 55CB 08E6 6FBE 7D37 4836 3586 E46B 3810",
"longclaw orport=443 "
  "199.58.81.140:80 74A9 1064 6BCE EFBC D2E8 74FC 1DC9 9743 0F96 8145",
"faravahar orport=443 "
  "216.218.219.41:80 E3E4 2D35 F801 C9D5 AB23 584E 0025 D56F E2B3 3396",
"sekhmet orport=443 "
  "204.13.164.118:80 2732 6CD9 AF0C 3925 9CFB 383C AFC5 0F5C EB0D 8906",
/*
"commentedout orport=443 "
*/
"""


def _lektor_blob(role: str = "core", nickname: str = "", extra: str = "") -> str:
    """Build a synthetic Lektor `contents.lr` document."""
    parts = ["_model: person", f"role: {role}"]
    if nickname:
        parts.append(f"nickname: {nickname}")
    if extra:
        parts.append(extra)
    return "\n---\n".join(parts) + "\n"


def _people_blobs(slugs: list[str], *, role: str = "core") -> dict[str, str]:
    """Build synthetic `contents.lr` payloads keyed by repository blob path."""
    return {
        f"content/about/people/{slug}/contents.lr": _lektor_blob(role=role, nickname=slug)
        for slug in slugs
    }


def _graphql_response(paths: list[str], blob_map: dict[str, str | None]) -> bytes:
    """Encode a GraphQL repository blobs response for the requested `paths`."""
    nodes = [
        {"path": path, "rawBlob": blob_map[path]}
        for path in paths
        if path in blob_map
    ]
    return json.dumps({"data": {"project": {"repository": {"blobs": {"nodes": nodes}}}}}).encode("utf-8")


def _auth_dirs_json(raw_text: str = SAMPLE_AUTH_DIRS, *, wrap_lines: bool = False, encoding: str = "base64") -> bytes:
    """Encode a GitLab repository file metadata payload for `auth_dirs.inc`."""
    encoded = base64.b64encode(raw_text.encode("utf-8")).decode("ascii")
    if wrap_lines:
        encoded = "\n".join(encoded[i : i + 40] for i in range(0, len(encoded), 40)) + "\n"
    return json.dumps({"file_name": "auth_dirs.inc", "encoding": encoding, "content": encoded}).encode("utf-8")


def _aroi_payload(counts: dict[str, int], *, invalid_rows: int = 0) -> bytes:
    """Build a synthetic AROI validator `latest.json` payload."""
    rows = [{"domain": domain, "valid": True} for domain, count in counts.items() for _ in range(count)]
    rows.extend({"domain": "unverified.example.org", "valid": False} for _ in range(invalid_rows))
    return json.dumps({"results": rows}).encode("utf-8")


def test_default_tor_core_users_invariants():
    """Verify `DEFAULT_TOR_CORE_USERS` normalization, size, exclusions, and required handles."""
    users = registry.DEFAULT_TOR_CORE_USERS
    assert isinstance(users, tuple)
    assert len(users) >= 100
    assert users == tuple(sorted(set(users)))
    assert all(u == u.lower() and is_valid_gitlab_user(u) for u in users)
    assert "_hc" not in users and "hc" in users
    for excluded_slug in ("alissa-cooper-core", "biella-core", "dees-core", "julius-core", "kendra-core", "ramy-core"):
        assert excluded_slug not in users
    for included_nick in ("biella", "julius", "ramy"):
        assert included_nick in users
    required = {
        "nickm", "dgoulet", "ahf", "arma", "gaba", "gk", "geko", "boklm",
        "meskio", "cohosh", "diziet", "opara", "morgan", "ma1", "ggus",
        "linus", "weasel", "sebastian", "micah", "andreas", "shelikhoo", "eta",
    }
    assert required <= set(users)


def test_parse_lektor_fields_handles_multiline_crlf_and_ignores_prose():
    """Parse standard and multiline Lektor fields while ignoring non-field HTML or prose."""
    raw = (
        "\r\n---\r\n_model: person\r\n---\r\nrole: core\r\n---\r\n"
        "nickname: nickm\r\n---\r\ndescription:\r\n\r\nMaintains core Tor.\r\nSecond line.\r\n"
        "---\r\n<h1>Error: 404</h1>\r\n---\r\nempty:\r\n"
    )
    parsed = registry.parse_lektor_fields(raw)
    assert parsed == {
        "_model": "person",
        "role": "core",
        "nickname": "nickm",
        "description": "Maintains core Tor.\nSecond line.",
        "empty": "",
    }
    assert registry.parse_lektor_fields("role: core\n---\nnickname: \n  dgoulet\n") == {
        "role": "core",
        "nickname": "dgoulet",
    }
    with pytest.raises(ValueError):
        registry.parse_lektor_fields(123)  # type: ignore[arg-type]


def test_fetch_tor_core_users_pagination_chunking_and_filtering():
    """Page tree entries, chunk GraphQL queries by 40, and filter core contributor handles."""
    slugs = [f"user{i:02d}" for i in range(42)] + ["hc", "biella-core", "retired-dev", "bad..slug"]
    tree_page1 = [{"name": s, "type": "tree"} for s in slugs[:30]] + [{"name": "README.md", "type": "blob"}]
    tree_page2 = [{"name": s, "type": "tree"} for s in slugs[30:]] + [{"name": "..", "type": "tree"}]

    blobs = _people_blobs([f"user{i:02d}" for i in range(42)])
    blobs["content/about/people/hc/contents.lr"] = _lektor_blob(role="Core", nickname="_hc")
    blobs["content/about/people/biella-core/contents.lr"] = _lektor_blob(role="core", nickname="Biella")
    blobs["content/about/people/retired-dev/contents.lr"] = _lektor_blob(role="emeritus", nickname="retired-dev")

    valid_requested = [s for s in slugs if s != "bad..slug"]
    chunk1_paths = [f"content/about/people/{s}/contents.lr" for s in valid_requested[:40]]
    chunk2_paths = [f"content/about/people/{s}/contents.lr" for s in valid_requested[40:]]

    client = FakeClient([
        response(json.dumps(tree_page1).encode(), {"X-Next-Page": "2"}),
        response(json.dumps(tree_page2).encode(), {"X-Next-Page": ""}),
        response(_graphql_response(chunk1_paths, blobs)),
        response(_graphql_response(chunk2_paths, blobs)),
    ])
    users = registry.fetch_tor_core_users(client)
    assert len(client.calls) == 4
    assert "page=1" in client.calls[0][1] and "per_page=100" in client.calls[0][1]
    assert "page=2" in client.calls[1][1]
    assert len(client.calls[2][2]["json_body"]["variables"]["paths"]) == 40
    assert len(client.calls[3][2]["json_body"]["variables"]["paths"]) == len(valid_requested) - 40
    assert "hc" in users and "_hc" not in users
    assert "biella" in users and "biella-core" not in users
    assert "retired-dev" not in users
    assert len(users) == 44

    full_100 = [{"name": f"dev{i:03d}", "type": "tree"} for i in range(100)]
    tail_5 = [{"name": f"dev{i:03d}", "type": "tree"} for i in range(100, 105)]
    all_105 = [f"dev{i:03d}" for i in range(105)]
    blobs_105 = _people_blobs(all_105)
    client_no_hdr = FakeClient([
        response(json.dumps(full_100).encode()),
        response(json.dumps(tail_5).encode()),
        response(_graphql_response([f"content/about/people/{s}/contents.lr" for s in all_105[:40]], blobs_105)),
        response(_graphql_response([f"content/about/people/{s}/contents.lr" for s in all_105[40:80]], blobs_105)),
        response(_graphql_response([f"content/about/people/{s}/contents.lr" for s in all_105[80:]], blobs_105)),
    ])
    assert len(registry.fetch_tor_core_users(client_no_hdr)) == 105

    # Explicit rawBlob=None for one requested entry succeeds when remaining nodes are complete.
    all_25 = [f"m{i:02d}" for i in range(25)]
    blobs_with_none = {**{f"content/about/people/{s}/contents.lr": _lektor_blob(nickname=s) for s in all_25[:-1]},
                       f"content/about/people/{all_25[-1]}/contents.lr": None}
    assert len(registry.fetch_tor_core_users(FakeClient([
        response(json.dumps([{"name": s, "type": "tree"} for s in all_25]).encode()),
        response(_graphql_response([f"content/about/people/{s}/contents.lr" for s in all_25], blobs_with_none)),
    ]))) == 24


@pytest.mark.parametrize("responses", [
    [response(b"error", status=502)],
    [response(b"<html>not json</html>")],
    [response(b"{}")],
    [response(b"[]")],
    [response(json.dumps([{"name": "onlyone", "type": "tree"}]).encode()), response(b"error", status=500)],
    [response(json.dumps([{"name": "onlyone", "type": "tree"}]).encode()), response(json.dumps({"errors": [{"message": "bad"}]}).encode())],
    [response(json.dumps([{"name": "onlyone", "type": "tree"}]).encode()), response(json.dumps({"data": None}).encode())],
    [
        response(json.dumps([{"name": f"u{i:02d}", "type": "tree"} for i in range(25)]).encode(), {"X-Next-Page": "3"}),
        response(_graphql_response(
            [f"content/about/people/u{i:02d}/contents.lr" for i in range(25)],
            _people_blobs([f"u{i:02d}" for i in range(25)]),
        )),
    ],
    [
        response(json.dumps([{"name": f"u{i:02d}", "type": "tree"} for i in range(25)]).encode(), {"X-Next-Page": "bad"}),
    ],
    [
        response(json.dumps([{"name": f"u{i:02d}", "type": "tree"} for i in range(25)]).encode()),
        response(json.dumps({"data": {"project": {"repository": {"blobs": {"nodes": [
            {"path": "content/about/people/unexpected/contents.lr", "rawBlob": _lektor_blob(nickname="unexpected")},
        ]}}}}}).encode()),
    ],
    [
        response(json.dumps([{"name": f"u{i:02d}", "type": "tree"} for i in range(25)]).encode()),
        response(json.dumps({"data": {"project": {"repository": {"blobs": {"nodes": [
            {"path": f"content/about/people/u{i:02d}/contents.lr", "rawBlob": _lektor_blob(nickname=f"u{i:02d}")}
            for i in range(20)
        ]}}}}}).encode()),
    ],
    [
        response(json.dumps([{"name": f"u{i:02d}", "type": "tree"} for i in range(25)]).encode()),
        response(json.dumps({"data": {"project": {"repository": {"blobs": {"nodes": [
            {"path": "content/about/people/u00/contents.lr", "rawBlob": _lektor_blob(nickname="u00")},
            *[
                {"path": f"content/about/people/u{i:02d}/contents.lr", "rawBlob": _lektor_blob(nickname=f"u{i:02d}")}
                for i in range(25)
            ],
        ]}}}}}).encode()),
    ],
    [
        response(json.dumps([{"name": f"u{i:02d}", "type": "tree"} for i in range(10)]).encode()),
        response(_graphql_response(
            [f"content/about/people/u{i:02d}/contents.lr" for i in range(10)],
            _people_blobs([f"u{i:02d}" for i in range(10)]),
        )),
    ],
])
def test_fetch_tor_core_users_fails_closed(responses):
    """Fail closed with `RegistryError` on HTTP, GraphQL, shape, or minimum-count failures."""
    with pytest.raises(registry.RegistryError):
        registry.fetch_tor_core_users(FakeClient(responses))


def test_fetch_trusted_operator_domains_normalization_threshold_and_exclusions():
    """Strip `www.`, exclude `torproject.org`, enforce relay thresholds, and fail closed."""
    payload = _aroi_payload(
        {
            "WWW.1aeo.com": 60,
            "1aeo.com": 45,
            "www.quintex.com": 100,
            "small-op.example.org": 99,
            "torproject.org": 250,
            "www.torproject.org": 150,
            "relays.torproject.org": 150,
            "bad..domain": 150,
            "127.0.0.1": 150,
        },
        invalid_rows=100,
    )
    domains = registry.fetch_trusted_operator_domains(FakeClient([response(payload)]))
    assert domains == ["1aeo.com", "quintex.com"]

    many_counts = {f"op{i:03d}.example.org": 1 for i in range(510)}
    capped = registry.fetch_trusted_operator_domains(
        FakeClient([response(_aroi_payload(many_counts))]), min_valid_relays=1,
    )
    assert len(capped) == registry.MAX_IDENTITIES and capped[0] == "op000.example.org"

    for bad_resp in (
        response(b"unavailable", status=503),
        response(b"not-json"),
        response(b"[]"),
        response(json.dumps({"results": [{"domain": "1aeo.com", "valid": True}] * 99}).encode()),
        response(_aroi_payload({"torproject.org": 150, "small.example.org": 49})),
        response(_aroi_payload({"unverified.example.org": 0}, invalid_rows=150)),
    ):
        with pytest.raises(registry.RegistryError):
            registry.fetch_trusted_operator_domains(FakeClient([bad_resp]), min_valid_relays=50)

    with pytest.raises(registry.RegistryError):
        registry.fetch_trusted_operator_domains(
            FakeClient([response(_aroi_payload({"torproject.org": 150, "small.example.org": 99}))])
        )

    with pytest.raises(ValueError):
        registry.fetch_trusted_operator_domains(FakeClient([]), min_valid_relays=0)


def test_fetch_auth_dir_nicknames_parsing_and_fail_closed():
    """Parse directory authority nicknames from base64 `auth_dirs.inc` while preserving case."""
    for wrap in (False, True):
        nicks = registry.fetch_auth_dir_nicknames(FakeClient([response(_auth_dirs_json(wrap_lines=wrap))]))
        assert nicks == [
            "Serge", "dannenberg", "dizum", "faravahar", "gabelmoo",
            "longclaw", "maatuska", "moria1", "sekhmet", "tor26",
        ]

    for bad_resp in (
        response(b"missing", status=404),
        response(b"<html>bad</html>"),
        response(_auth_dirs_json(encoding="text")),
        response(json.dumps({"encoding": "base64", "content": "not!base64"}).encode()),
        response(json.dumps({"encoding": "base64", "content": base64.b64encode(b"\xff\xfe").decode()}).encode()),
        response(_auth_dirs_json('"moria1 orport=9201 "\n"tor26 orport=443 "\n')),
    ):
        with pytest.raises(registry.RegistryError):
            registry.fetch_auth_dir_nicknames(FakeClient([bad_resp]))


def test_load_cached_and_effective_identities_fail_closed_and_merge_order(tmp_path):
    """Ignore damaged metadata entries and merge config-first then sorted cached additions."""
    bare_db = sqlite3.connect(":memory:")
    assert registry.load_cached(bare_db) == {
        "tor_core_users": [],
        "trusted_operator_domains": [],
        "auth_dirs_nicknames": [],
        "last_refresh_at": None,
        "last_error": None,
    }
    bare_db.close()

    with Store(tmp_path / "state.sqlite3") as store:
        with store.db:
            set_meta(
                store.db,
                **{
                    "registry.tor_core_users": json.dumps(["nickm", "_hc", 123, "extra-core", "bad..user"]),
                    "registry.trusted_operator_domains": json.dumps(["1aeo.com", "torproject.org", "sub.torproject.org", "bad domain", "zeta.example.org", "alpha.example.org"]),
                    "registry.auth_dirs_nicknames": json.dumps(["moria1", "", 42, "bad\x00nick", "Serge"]),
                    "registry.last_refresh_at": "not-a-utc-timestamp",
                    "registry.last_error": "x" * 200,
                },
            )
        cached = registry.load_cached(store.db)
        assert cached["tor_core_users"] == ["nickm", "extra-core"]
        assert cached["trusted_operator_domains"] == ["1aeo.com", "zeta.example.org", "alpha.example.org"]
        assert cached["auth_dirs_nicknames"] == ["moria1", "Serge"]
        assert cached["last_refresh_at"] is None
        assert cached["last_error"] == "x" * 160

        with store.db:
            store.db.execute("INSERT OR REPLACE INTO metadata(key,value) VALUES(?,?)", ("registry.tor_core_users", b"\xff\xfe"))
            store.db.execute("INSERT OR REPLACE INTO metadata(key,value) VALUES(?,?)", ("registry.trusted_operator_domains", '{"not":"a-list"}'))
            store.db.execute("INSERT OR REPLACE INTO metadata(key,value) VALUES(?,?)", ("registry.auth_dirs_nicknames", "[NaN]"))
        damaged = registry.load_cached(store.db)
        assert damaged["tor_core_users"] == []
        assert damaged["trusted_operator_domains"] == []
        assert damaged["auth_dirs_nicknames"] == []

        with store.db:
            set_meta(
                store.db,
                **{
                    "registry.tor_core_users": json.dumps(["zeta_user", "alpha_user", "nickm"]),
                    "registry.trusted_operator_domains": json.dumps(["zeta.example.org", "alpha.example.org", "1aeo.com"]),
                },
            )
        cfg = {
            **copy.deepcopy(DEFAULTS),
            "collection": {
                **DEFAULTS["collection"],
                "tor_core_gitlab_users": ["nickm", "arma"],
                "trusted_operator_domains": ["1aeo.com", "torproject.org", "relays.torproject.org"],
            },
        }
        eff_users, eff_domains = registry.effective_identities(cfg, store.db)
        assert eff_users == ["nickm", "arma", "alpha_user", "zeta_user"]
        assert eff_domains == ["1aeo.com", "alpha.example.org", "zeta.example.org"]
        assert registry.effective_identities(cfg, None) == (["nickm", "arma"], ["1aeo.com"])

        with store.db:
            set_meta(
                store.db,
                **{
                    "registry.tor_core_users": json.dumps([f"c{i:03d}" for i in range(600)]),
                    "registry.trusted_operator_domains": json.dumps([f"d{i:03d}.example.org" for i in range(600)]),
                },
            )
        capped_users, capped_domains = registry.effective_identities(cfg, store.db)
        assert len(capped_users) == registry.MAX_IDENTITIES and capped_users[:2] == ["nickm", "arma"]
        assert len(capped_domains) == registry.MAX_IDENTITIES and capped_domains[0] == "1aeo.com"


def _valid_sync_responses() -> list:
    """Return a valid sequence of HTTP responses for all three registry fetchers."""
    slugs = [f"core{i:02d}" for i in range(25)]
    tree = [{"name": s, "type": "tree"} for s in slugs]
    blobs = _people_blobs(slugs)
    paths = [f"content/about/people/{s}/contents.lr" for s in slugs]
    aroi = _aroi_payload({"www.alpha.example.org": 120, "torproject.org": 200})
    return [
        response(json.dumps(tree).encode()),
        response(_graphql_response(paths, blobs)),
        response(aroi),
        response(_auth_dirs_json()),
    ]


def test_refresh_if_due_lifecycle_cooldown_and_fail_closed_preservation(tmp_path):
    """Verify disabled no-op, 24h cooldown, partial/total error preservation, and read-only status."""
    cfg = make_config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        disabled = registry.refresh_if_due(cfg, store, NOW, client=FakeClient([]))
        assert disabled == {"enabled": False, "due": False, "refreshed": False, "updated": {}}
        assert get_meta(store.db, "registry.last_refresh_at") is None

        cfg["registry"]["enabled"] = True
        first = registry.refresh_if_due(cfg, store, NOW, client=FakeClient(_valid_sync_responses()))
        assert first["enabled"] is True and first["due"] is True and first["refreshed"] is True
        assert first["updated"] == {
            "tor_core_users": 25,
            "trusted_operator_domains": 1,
            "auth_dirs_nicknames": 10,
        }
        assert first["last_refresh_at"] == NOW and first["last_error"] is None

        st = registry.status(store.db, cfg)
        assert st == {
            "enabled": True,
            "last_refresh_at": NOW,
            "last_error": None,
            "tor_core_count": 25,
            "trusted_domains_count": 1,
            "auth_dirs_nicknames": [
                "Serge", "dannenberg", "dizum", "faravahar", "gabelmoo",
                "longclaw", "maatuska", "moria1", "sekhmet", "tor26",
            ],
        }

        # Within 24h cooldown: must not hit HTTP client.
        too_soon = "2026-11-22T11:59:59Z"
        skipped = registry.refresh_if_due(cfg, store, too_soon, client=FakeClient([]))
        assert skipped["due"] is False and skipped["refreshed"] is False and skipped["tor_core_count"] == 25

        # Partial failure after 24h: keeps cached AROI domain, updates core users and auth_dirs, records bounded error.
        next_day = "2026-11-22T12:00:00Z"
        slugs2 = [f"next{i:02d}" for i in range(22)]
        partial_client = FakeClient([
            response(json.dumps([{"name": s, "type": "tree"} for s in slugs2]).encode()),
            response(_graphql_response([f"content/about/people/{s}/contents.lr" for s in slugs2], _people_blobs(slugs2))),
            FetchError("upstream " + ("x" * 200), status=503, retryable=True),
            response(_auth_dirs_json()),
        ])
        partial = registry.refresh_if_due(cfg, store, next_day, client=partial_client)
        assert partial["refreshed"] is True
        assert partial["last_refresh_at"] == next_day
        assert partial["tor_core_count"] == 22
        assert partial["trusted_domains_count"] == 1
        assert partial["last_error"] is not None and len(partial["last_error"]) <= 160
        assert registry.load_cached(store.db)["trusted_operator_domains"] == ["alpha.example.org"]

        # Total failure after another 24h: preserves all cached lists and previous last_refresh_at.
        day_three = "2026-11-23T12:00:00Z"
        all_fail_client = FakeClient([
            FetchError("tree unavailable"),
            FetchError("aroi unavailable"),
            FetchError("auth_dirs unavailable"),
        ])
        total_fail = registry.refresh_if_due(cfg, store, day_three, client=all_fail_client)
        assert total_fail["refreshed"] is False
        assert total_fail["last_refresh_at"] == next_day
        assert total_fail["tor_core_count"] == 22 and total_fail["trusted_domains_count"] == 1
        assert len(total_fail["auth_dirs_nicknames"]) == 10

        # DeadlineReached halts remaining fetchers without touching cached entries.
        dl_client = FakeClient([DeadlineReached()])
        dl_res = registry.refresh_if_due(cfg, store, day_three, client=dl_client)
        assert dl_res["refreshed"] is False and dl_res["budget_reached"] is True
        assert len(dl_client.calls) == 1
        assert registry.load_cached(store.db)["tor_core_users"] == [f"next{i:02d}" for i in range(22)]

        # Expired deadline before starting skips all fetchers immediately.
        expired = registry.refresh_if_due(cfg, store, day_three, deadline=time.monotonic() - 1, client=FakeClient([]))
        assert expired["refreshed"] is False and expired["budget_reached"] is True

        # Full recovery clears prior last_error.
        recovered = registry.refresh_if_due(cfg, store, day_three, client=FakeClient(_valid_sync_responses()))
        assert recovered["refreshed"] is True and recovered["last_error"] is None
        assert get_meta(store.db, "registry.last_error") is None

    # status() remains strictly read-only even on a ?mode=ro connection under a concurrent write lock.
    writer = sqlite3.connect(cfg["storage"]["database"], isolation_level=None)
    writer.execute("BEGIN IMMEDIATE")
    try:
        ro_conn = sqlite3.connect(Path(cfg["storage"]["database"]).as_uri() + "?mode=ro", uri=True)
        try:
            ro_status = registry.status(ro_conn, cfg)
            assert ro_status["tor_core_count"] == 25
        finally:
            ro_conn.close()
    finally:
        writer.close()


def test_refresh_if_due_raises_max_response_bytes_for_aroi_client(tmp_path, monkeypatch):
    """Construct `HttpClient` with `max_response_bytes >= AROI_MAX_RESPONSE_BYTES` and honor deadline."""
    cfg = make_config(tmp_path)
    cfg["registry"]["enabled"] = True
    assert cfg["http"]["max_response_bytes"] < registry.AROI_MAX_RESPONSE_BYTES

    slugs = [f"core{i:02d}" for i in range(22)]
    tree_bytes = json.dumps([{"name": s, "type": "tree"} for s in slugs]).encode()
    gql_bytes = _graphql_response(
        [f"content/about/people/{s}/contents.lr" for s in slugs],
        _people_blobs(slugs),
    )
    padding = " " * (3 * 1024 * 1024)
    aroi_large = (
        json.dumps({"results": [{"domain": "www.1aeo.com", "valid": True, "pad": padding}] + [{"domain": "www.1aeo.com", "valid": True}] * 119})
    ).encode()
    assert len(aroi_large) > cfg["http"]["max_response_bytes"]
    auth_bytes = _auth_dirs_json()

    def _handler(req: httpx.Request) -> httpx.Response:
        """Serve synthetic GitLab and oversized AROI responses."""
        if req.url.host == "aroivalidator.1aeo.com":
            return httpx.Response(200, content=aroi_large)
        if req.url.path == "/api/graphql":
            return httpx.Response(200, content=gql_bytes)
        if "auth_dirs.inc" in req.url.path:
            return httpx.Response(200, content=auth_bytes)
        return httpx.Response(200, content=tree_bytes)

    real_client = registry.HttpClient
    captured_settings: list[dict] = []

    def _patched_client(settings, **kw):
        """Capture `HttpClient` settings and wire in `MockTransport`."""
        captured_settings.append(dict(settings))
        return real_client(settings, transport=httpx.MockTransport(_handler), resolver=public_dns)

    monkeypatch.setattr(registry, "HttpClient", _patched_client)
    with Store(cfg["storage"]["database"]) as store:
        res = registry.refresh_if_due(cfg, store, NOW, deadline=time.monotonic() + 30)
        assert res["refreshed"] is True
        assert res["errors"] == []
        assert captured_settings and captured_settings[0]["max_response_bytes"] >= registry.AROI_MAX_RESPONSE_BYTES
        assert registry.load_cached(store.db)["trusted_operator_domains"] == ["1aeo.com"]


def test_cli_run_and_status_wire_registry_identities(tmp_path, monkeypatch, capsys):
    """Merge synced registry identities into `cli.run` phases, restore `store`, and expose `status`."""
    monkeypatch.setenv("ONIONFLASH_LLM_BASE_URL", "https://model.example/v1")
    cfg_path = write_toml(
        tmp_path,
        '[registry]\nenabled = true\n'
        '[collection]\n'
        'tor_core_gitlab_users = ["cfg_core"]\n'
        'trusted_operator_domains = ["cfg.example.org"]\n'
        '[[sources]]\n'
        'id = "tor-issues"\n'
        'name = "Tor issues"\n'
        'url = "https://gitlab.torproject.org/api/v4/projects/426/issues"\n'
        'kind = "gitlab_issue"\n'
        'gitlab_project = "tpo/core/tor"\n'
        'authority = "development"\n'
        'product = "tor"\n',
        with_source=False,
    )
    cfg = load_config(cfg_path)

    slugs = [f"synccore{i:02d}" for i in range(25)]
    tree_bytes = json.dumps([{"name": s, "type": "tree"} for s in slugs]).encode()
    gql_bytes = _graphql_response(
        [f"content/about/people/{s}/contents.lr" for s in slugs],
        _people_blobs(slugs),
    )
    aroi_bytes = _aroi_payload({"www.syncedop.example.org": 120})
    auth_bytes = _auth_dirs_json()

    def _handler(req: httpx.Request) -> httpx.Response:
        """Serve mock registry endpoints for Tor people, AROI, and auth_dirs."""
        if req.url.host == "aroivalidator.1aeo.com":
            return httpx.Response(200, content=aroi_bytes)
        if req.url.path == "/api/graphql":
            return httpx.Response(200, content=gql_bytes)
        if "auth_dirs.inc" in req.url.path:
            return httpx.Response(200, content=auth_bytes)
        return httpx.Response(200, content=tree_bytes)

    real_client = registry.HttpClient
    monkeypatch.setattr(
        registry,
        "HttpClient",
        lambda settings, **kw: real_client(settings, transport=httpx.MockTransport(_handler), resolver=public_dns),
    )
    monkeypatch.setattr(cli, "HttpClient", FakeClient.factory([]))

    seen: dict[str, object] = {}

    def _collect(client, stream, state, coll, observed):
        """Capture effective collection settings and yield a synced-core issue."""
        seen["collect_users"] = list(coll["tor_core_gitlab_users"])
        seen["collect_domains"] = list(coll["trusted_operator_domains"])
        seen["store_during_collect"] = store.tor_core_users
        return {
            "url": stream["url"],
            "items": [{
                "id": "sync-item-1",
                "source_id": stream["id"],
                "url": "https://gitlab.torproject.org/tpo/core/tor/-/work_items/60001",
                "title": "Relay scheduler investigation",
                "content": "Investigates relay scheduler latency under load.",
                "published_at": NOW,
                "updated_at": NOW,
                "kind": "gitlab_issue",
                "product": "tor",
                "authority": "tor-core" if "synccore00" in coll["tor_core_gitlab_users"] else "development",
                "labels": [],
                "author": "synccore00",
            }],
            "skipped": 0,
        }

    def _enrich(run_cfg, store_arg, observed, deadline=None):
        """Capture effective collection settings during comment enrichment."""
        seen["comments_users"] = list(run_cfg["collection"]["tor_core_gitlab_users"])
        seen["comments_domains"] = list(run_cfg["collection"]["trusted_operator_domains"])
        return {"enabled": False, "checked": 0, "changed": 0, "failed": 0, "skipped": 0, "budget_reached": False}

    def _process(run_cfg, store_arg, row, writer, reviewer, observed, allow_network=True):
        """Capture merged identities and process via stubbed approval outcome."""
        seen["process_users"] = list(run_cfg["collection"]["tor_core_gitlab_users"])
        seen["process_domains"] = list(run_cfg["collection"]["trusted_operator_domains"])
        seen["row_authority"] = json.loads(row["payload"])["authority"]
        return {"status": "ignored", "cache_hit": False}

    patch_cli_pipeline(monkeypatch, now=NOW, analyzer=Writer.factory(), reviewer=ApprovingReviewer, collect=_collect)
    monkeypatch.setattr(cli, "enrich_comments", _enrich)
    monkeypatch.setattr(cli, "process_item", _process)

    with Store(cfg["storage"]["database"], tor_core_users=("initial_core",)) as store:
        report = cli.run(cfg, store)
        assert store.tor_core_users == ("initial_core",)

    assert report["registry"]["refreshed"] is True
    assert report["registry"]["tor_core_count"] == 25
    assert report["registry"]["trusted_domains_count"] == 1
    assert "synccore00" in seen["collect_users"] and "cfg_core" in seen["collect_users"]
    assert "syncedop.example.org" in seen["collect_domains"] and "cfg.example.org" in seen["collect_domains"]
    assert "synccore00" in seen["store_during_collect"]
    assert seen["comments_users"] == seen["collect_users"] == seen["process_users"]
    assert seen["comments_domains"] == seen["collect_domains"] == seen["process_domains"]
    assert seen["row_authority"] == "tor-core"

    status_out = invoke_cli(capsys, "status", "--config", str(cfg_path))
    assert status_out["registry"] == {
        "enabled": True,
        "last_refresh_at": NOW,
        "last_error": None,
        "tor_core_count": 25,
        "trusted_domains_count": 1,
        "auth_dirs_nicknames": [
            "Serge", "dannenberg", "dizum", "faravahar", "gabelmoo",
            "longclaw", "maatuska", "moria1", "sekhmet", "tor26",
        ],
    }


def test_cli_operator_commands_resolve_cached_registry_identities(tmp_path, monkeypatch, capsys):
    """Resolve cached registry identities network-free for `rejected show` and `rejected approve`."""
    from helpers import DATE, Reviewer, pending, run_gate, verdict

    monkeypatch.setenv("ONIONFLASH_LLM_BASE_URL", "https://model.example/v1")
    cfg_path = write_toml(
        tmp_path,
        '[registry]\nenabled = true\n'
        '[collection]\ntor_core_gitlab_users = ["cfg_core"]\n'
        '[[sources]]\n'
        'id = "tor-blog"\n'
        'name = "Tor Blog"\n'
        'url = "https://blog.torproject.org/feed.xml"\n'
        'kind = "feed"\n'
        'authority = "official"\n'
        'product = "tor"\n',
        with_source=False,
    )
    cfg = load_config(cfg_path)
    monkeypatch.setattr(
        registry, "HttpClient",
        lambda *_a, **_kw: (_ for _ in ()).throw(AssertionError("Operator CLI commands must not open HttpClient")),
    )
    with Store(cfg["storage"]["database"], dirauth_users=cfg["collection"]["dirauth_gitlab_users"]) as store:
        with store.db:
            set_meta(store.db, **{"registry.tor_core_users": json.dumps(["synced_core_user"])})
        eff_cfg, eff_users = cli._effective_config(cfg, store)
        assert eff_users == ["cfg_core", "synced_core_user"]
        row = pending(store, {
            "source_id": "tor-blog",
            "url": "https://blog.torproject.org/routine-report-1/",
            "title": "Routine official community roundup",
            "content": "Monthly roundup of community events and translations.",
            "published_at": DATE,
            "updated_at": DATE,
            "kind": "feed",
            "product": "tor",
            "authority": "official",
            "labels": [],
        })
        draft = {
            "publish": True,
            "title": "Tor Blog posts monthly roundup",
            "summary": "Monthly roundup of community events and translations.",
            "why_it_matters": "",
            "category": "feature",
            "priority": "normal",
            "confidence": "confirmed",
            "state": "released",
            "products": ["tor"],
            "tags": ["feature"],
            "evidence": ["Monthly roundup of community events and translations."],
        }
        held = run_gate(
            eff_cfg, store, row,
            Writer(draft),
            Reviewer(verdict("skip", criterion="news_value"), verdict("skip", criterion="news_value")),
            DATE,
        )
        assert held["status"] == "held"
        item_id = row["id"]

    shown = invoke_cli(capsys, "rejected", "show", "--config", str(cfg_path), "--item", item_id)
    approval = shown["final_review"]["approval"]
    assert approval["eligible"] is True and isinstance(approval["hash"], str)

    approved = invoke_cli(
        capsys,
        "rejected", "approve",
        "--config", str(cfg_path),
        "--item", item_id,
        "--approval-hash", approval["hash"],
        "--reason", "Operator approves held official item after registry sync.",
    )
    assert approved["action"] == "approve" and approved["status"] == "published"
