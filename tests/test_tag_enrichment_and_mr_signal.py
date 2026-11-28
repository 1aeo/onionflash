"""Tests for GitLab tag enrichment, routing, and tightened internal MR signal filtering."""

from __future__ import annotations

import copy
import json
from types import SimpleNamespace

from onionflash import analyze, collect, config, review, review_gate, util


DATE = "2026-11-10T12:00:00Z"


class _FakeHttpResponse:
    def __init__(self, url: str, body: bytes, *, status: int = 200, headers: dict | None = None):
        self.url = url
        self.body = body
        self.status = status
        self.headers = headers or {}

    def json(self):
        return json.loads(self.body.decode("utf-8"))


class _FakeHttpClient:
    def __init__(self, routes: dict[str, object]):
        self.routes = routes
        self.calls: list[str] = []

    def request(self, method: str, url: str, headers: dict | None = None):
        assert method == "GET"
        self.calls.append(url)
        handler = self.routes.get(url)
        if isinstance(handler, Exception):
            raise handler
        if callable(handler):
            return handler(url)
        if handler is None:
            raise collect.FetchError(f"Unexpected URL: {url}")
        return handler


def _tag_atom_xml(*tag_entries: tuple[str, str, str]) -> bytes:
    entries = "\n".join(
        f"""  <entry>
    <id>{url}</id>
    <link rel="alternate" type="text/html" href="{url}"/>
    <title>{tag}</title>
    <updated>{updated}</updated>
    <summary type="html">{tag}</summary>
  </entry>"""
        for tag, url, updated in tag_entries
    )
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Tags</title>
{entries}
</feed>
""".encode("utf-8")


def _tag_source(project: str = "tpo/anti-censorship/pluggable-transports/snowflake", *, product: str = "snowflake") -> dict:
    return {
        "id": f"{product}-tags",
        "kind": "tag",
        "product": product,
        "authority": "official",
        "url": f"https://gitlab.torproject.org/{project}/-/tags",
        "max_items": 10,
    }


def _feed_settings() -> dict:
    return {
        "lookback_days": 30,
        "content_chars": 4000,
        "trusted_operator_domains": (),
    }


def test_housekeeping_filters_internal_helper_moves_mock_stubs_and_scaffolds_safely():
    """Filter obvious internal helper/stub/scaffold chores while never filtering security/DoS/protocol/capability MRs."""
    chores = [
        "Extract helper functions between internal modules",
        "tor-netdoc: Move internal helper functions out of parser module",
        "Add mock client stub for internal harness",
        "Add dummy stub for transport metrics",
        "Scaffold prep for future directory module",
        "Initial scaffold for internal state machine",
    ]
    for title in chores:
        res = util.is_housekeeping_item({
            "kind": "gitlab_mr",
            "upstream_state": "merged",
            "title": title,
            "content": "Internal code organization without behavior changes.",
            "labels": [],
            "url": "https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/4100",
        })
        assert res == ("skipped.gate.housekeeping", "Routine internal refactor or TODO cleanup item"), title

    protected = [
        ("Extract helper functions to fix crash in descriptor parser", "Fixes null pointer crash."),
        ("Add mock stub and fix DoS memory exhaustion in smux", "Bounds smux streams to stop DoS."),
        ("Scaffold prep for new security mitigation against circuit flood", "Addresses denial of service."),
        ("Extract helper functions and enable experimental DoS defense by default", "Changes default behavior."),
        ("Extract dirauth voting helper to fix consensus quorum anomaly", "Directory authority voting fix."),
    ]
    for title, content in protected:
        res = util.is_housekeeping_item({
            "kind": "gitlab_mr",
            "upstream_state": "merged",
            "title": title,
            "content": content,
            "labels": [],
            "url": "https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/4101",
        })
        assert res is None, title


def test_collect_gitlab_tag_enrichment_strips_pgp_and_release_cli_and_compares():
    """Enrich GitLab tags with substantive notes or compare commits, capping commits/calls and failing soft."""
    project = "tpo/anti-censorship/pluggable-transports/snowflake"
    enc_project = "tpo%2Fanti-censorship%2Fpluggable-transports%2Fsnowflake"
    feed_url = f"https://gitlab.torproject.org/{project}/-/tags"
    tags_api = f"https://gitlab.torproject.org/api/v4/projects/{enc_project}/repository/tags?per_page=15"
    cmp_2154 = f"https://gitlab.torproject.org/api/v4/projects/{enc_project}/repository/compare?from=v2.15.3&to=v2.15.4"

    xml_body = _tag_atom_xml(
        ("v2.15.4", f"{feed_url}/v2.15.4", "2026-11-09T12:00:00Z"),
        ("v2.15.2", f"{feed_url}/v2.15.2", "2026-11-08T12:00:00Z"),
    )
    tags_json = json.dumps([
        {
            "name": "v2.15.4",
            "message": "Bump version to v2.15.4\n-----BEGIN PGP SIGNATURE-----\niQIzBAABCAAd\n-----END PGP SIGNATURE-----",
            "release": {"tag_name": "v2.15.4", "description": "Created using the release-cli"},
        },
        {
            "name": "v2.15.3",
            "message": "Bump version to v2.15.3",
            "release": {"tag_name": "v2.15.3", "description": "Created using the release-cli"},
        },
        {
            "name": "v2.15.2",
            "message": "Tag v2.15.2\n-----BEGIN PGP SIGNATURE-----\nabc\n-----END PGP SIGNATURE-----",
            "release": {
                "tag_name": "v2.15.2",
                "description": "Created using the release-cli\nFixes broker queue timeout and improves proxy logging.",
            },
        },
    ]).encode("utf-8")
    many_commits = [{"title": f"Commit fix #{i}"} for i in range(1, 26)]
    many_commits[0]["title"] = "Server: Fix remote bridge crash due to ClientID map eviction"
    many_commits[1]["title"] = "Server: Bound creation of smux streams"
    cmp_json = json.dumps({"commits": many_commits}).encode("utf-8")

    client = _FakeHttpClient({
        feed_url: _FakeHttpResponse(feed_url, xml_body),
        tags_api: _FakeHttpResponse(tags_api, tags_json),
        cmp_2154: _FakeHttpResponse(cmp_2154, cmp_json),
    })
    out = collect._feed(client, _tag_source(), feed_url, {}, _feed_settings(), DATE)
    by_title = {it["title"]: it for it in out["items"]}

    v2154 = by_title["v2.15.4"]
    assert v2154.get("tag_enriched") is True
    assert "BEGIN PGP SIGNATURE" not in v2154["content"]
    assert "release-cli" not in v2154["content"]
    assert "Release commits (v2.15.3..v2.15.4):" in v2154["content"]
    assert "Server: Fix remote bridge crash due to ClientID map eviction" in v2154["content"]
    assert "Server: Bound creation of smux streams" in v2154["content"]
    assert "Commit fix #20" in v2154["content"]
    assert "Commit fix #21" not in v2154["content"]  # capped at <= 20 commit titles

    v2152 = by_title["v2.15.2"]
    assert v2152.get("tag_enriched") is True
    assert "Created using the release-cli" not in v2152["content"]
    assert "BEGIN PGP SIGNATURE" not in v2152["content"]
    assert "Fixes broker queue timeout and improves proxy logging." in v2152["content"]

    # Tags API called at most once per _feed run; compare only for v2.15.4 (not v2.15.2 which had release notes).
    assert client.calls == [feed_url, tags_api, cmp_2154]
    assert v2154["tag_enrichment_kind"] == "compare"
    assert v2152["tag_enrichment_kind"] == "release_notes"


def test_collect_gitlab_tag_enrichment_compare_cap_and_fail_soft():
    """Cap compare requests at 5 per feed run and fail soft on API errors leaving unenriched tags untouched."""
    project = "tpo/core/tor"
    enc_project = "tpo%2Fcore%2Ftor"
    feed_url = f"https://gitlab.torproject.org/{project}/-/tags"
    tags_api = f"https://gitlab.torproject.org/api/v4/projects/{enc_project}/repository/tags?per_page=15"

    # 7 trivial tags in feed + 1 preceding tag -> at most 5 compare calls executed.
    tag_names = [f"tor-0.4.9.{i}" for i in range(17, 9, -1)]
    xml_body = _tag_atom_xml(*(
        (name, f"{feed_url}/{name}", f"2026-11-0{max(1, i)}T12:00:00Z")
        for i, name in enumerate(tag_names[:7], 1)
    ))
    tags_json = json.dumps([
        {"name": name, "message": f"Tor 0.4.9.{17 - idx}", "release": None}
        for idx, name in enumerate(tag_names)
    ]).encode("utf-8")

    routes: dict[str, object] = {
        feed_url: _FakeHttpResponse(feed_url, xml_body),
        tags_api: _FakeHttpResponse(tags_api, tags_json),
    }
    for cur, prev in zip(tag_names, tag_names[1:]):
        cmp_url = f"https://gitlab.torproject.org/api/v4/projects/{enc_project}/repository/compare?from={prev}&to={cur}"
        routes[cmp_url] = _FakeHttpResponse(cmp_url, json.dumps({"commits": [{"title": f"Fix {cur}"}]}).encode("utf-8"))

    client = _FakeHttpClient(routes)
    out = collect._feed(client, _tag_source(project, product="tor"), feed_url, {}, _feed_settings(), DATE)
    enriched = [it for it in out["items"] if it.get("tag_enriched")]
    unenriched = [it for it in out["items"] if not it.get("tag_enriched")]
    assert len(enriched) == 5 and len(unenriched) == 2
    assert sum(1 for c in client.calls if "/repository/compare?" in c) == 5

    # Fail-soft when API fails with FetchError.
    failing_client = _FakeHttpClient({
        feed_url: _FakeHttpResponse(feed_url, xml_body),
        tags_api: collect.FetchError("upstream 503", status=503),
    })
    soft_out = collect._feed(failing_client, _tag_source(project, product="tor"), feed_url, {}, _feed_settings(), DATE)
    assert len(soft_out["items"]) == 7
    assert all(not it.get("tag_enriched") for it in soft_out["items"])


def test_enriched_tag_routes_to_llm_and_allows_confirmed_while_unenriched_stays_literal(monkeypatch):
    """Enriched official tags skip tag_notice/_literal_tag and allow confirmed+tagged+release; unenriched tags do not."""
    cfg = copy.deepcopy(config.DEFAULTS)
    unenriched_item = {
        "source_id": "snowflake-tags",
        "url": "https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/-/tags/v2.15.4",
        "title": "v2.15.4",
        "content": "",
        "published_at": DATE,
        "updated_at": DATE,
        "kind": "tag",
        "product": "snowflake",
        "authority": "official",
        "labels": [],
        "upstream_state": "",
    }
    enriched_item = {
        **unenriched_item,
        "tag_enriched": True,
        "content": (
            "Release commits (v2.15.3..v2.15.4):\n"
            "- Server: Fix remote bridge crash due to ClientID map eviction\n"
            "- Server: Bound creation of smux streams"
        ),
    }

    # Unenriched tag stays deterministic via tag_notice (0 LLM calls).
    monkeypatch.setattr(analyze.CompletionClient, "complete", lambda *a, **kw: (_ for _ in ()).throw(AssertionError("LLM called")))
    writer = analyze.Analyzer(cfg)
    assert writer.analyze(unenriched_item)["title"] == "Snowflake tag observed: v2.15.4"
    assert review_gate._literal_tag({
        "mode": "story",
        "payload": {"editorial_kind": "tag"},
        "row": {"payload": json.dumps(unenriched_item)},
    }) is True

    # Enriched tag routes through LLM drafting and allows confirmed/tagged/release.
    captured_schemas: list[dict] = []

    def _fake_complete(self, system_prompt, payload, schema, schema_name, **_kw):
        captured_schemas.append(copy.deepcopy(schema))
        return {
            "publish": True,
            "title": "Snowflake v2.15.4 tag fixes bridge crash and bounds smux streams",
            "summary": "The Snowflake v2.15.4 upstream tag includes fixes for a remote bridge ClientID map eviction crash and bounds smux stream creation.",
            "why_it_matters": "",
            "category": "release",
            "priority": "normal",
            "confidence": "confirmed",
            "state": "tagged",
            "products": ["snowflake"],
            "tags": ["release", "security", "dos"],
            "evidence": ["Server: Fix remote bridge crash due to ClientID map eviction"],
        }

    monkeypatch.setattr(analyze.CompletionClient, "complete", _fake_complete)
    draft = writer.analyze(enriched_item)
    assert len(captured_schemas) == 1
    assert "confirmed" in captured_schemas[0]["properties"]["confidence"]["enum"]
    assert "tagged" in captured_schemas[0]["properties"]["state"]["enum"]
    assert "release" in captured_schemas[0]["properties"]["category"]["enum"]
    assert draft["confidence"] == "confirmed" and draft["state"] == "tagged" and draft["category"] == "release"
    assert review_gate._literal_tag({
        "mode": "story",
        "payload": {"editorial_kind": "tag"},
        "row": {"payload": json.dumps(enriched_item)},
    }) is False

    # final_holds and repair_limits allow confirmed for enriched official tags, while still blocking unenriched official tags.
    enriched_pkt = {"sources": [{
        "id": "S1",
        "url": enriched_item["url"],
        "title": "v2.15.4",
        "kind": "tag",
        "authority": "official",
        "tag_enriched": True,
        "product": "snowflake",
        "published_at": DATE,
        "updated_at": DATE,
        "labels": [],
        "passages": [{"id": "S1:P1", "text": enriched_item["content"]}],
    }], "missing_sources": [], "truncated": False}
    assert "confirmed" in review.repair_limits(enriched_pkt)["confidence"]
    assert review.final_holds(
        {
            "title": draft["title"],
            "summary": draft["summary"],
            "why_it_matters": "",
            "category": "release",
            "tags": ["release"],
            "confidence": "confirmed",
            "state": "tagged",
            "products": ["snowflake"],
        },
        {"packet": enriched_pkt, "payload": {"editorial_kind": "tag"}, "row": {"payload": json.dumps(enriched_item)}},
    ) == []


def test_review_prompts_cover_multisource_badge_repair_and_preverdict_check():
    """Verify REVIEW_VERSION, multi-source S1..Sn check, badge-repair rule, internal MR exclusions, and pre-verdict check."""
    assert review.REVIEW_VERSION == "onionflash-review-21"
    for prompt in (review.SYSTEM_PROMPT, review.UPDATE_SYSTEM_PROMPT, review.SPECIALIST_PROMPTS["novelty_news"]):
        assert "S1..Sn" in prompt
        assert "revise" in prompt.lower()
    assert "pre-verdict consistency check" in review._SHARED_VERDICT_RULES.lower()
    assert "pre-verdict consistency check" in review.VALIDATION_REASK_PROMPT.lower()
    assert "helper function extractions or moves" in review.SYSTEM_PROMPT
    assert "mock/dummy test" in review.SPECIALIST_PROMPTS["novelty_news"]
    assert "scaffold prep" in review.NEWS_TIEBREAK_PROMPT
    assert "inconsistent" in review.INCONSISTENT_VERDICT.lower()
    assert "tag_enriched" in review.SYSTEM_PROMPT and "tag_enriched" in review.UPDATE_SYSTEM_PROMPT
    assert "prior_story" in review.UPDATE_SYSTEM_PROMPT


def test_tag_preceding_prerelease_version_sort_no_list_fallback_and_trivial_release_description():
    """Cover prerelease version comparison, no update-order fallback on parsed tags, and trivial release descriptions."""
    # Prerelease ordering: v2.0.0-rc1 precedes v2.0.0-rc2 ahead of v1.9.0, while stable skips prereleases.
    tags = [
        {"name": "v2.0.0-rc2", "message": "", "release": None},
        {"name": "v1.9.0", "message": "", "release": None},
        {"name": "v2.0.0-rc1", "message": "", "release": None},
        {"name": "v2.0.0", "message": "", "release": None},
    ]
    assert collect._preceding_tag_name(tags, 0, "v2.0.0-rc2") == "v2.0.0-rc1"
    assert collect._preceding_tag_name(tags, 3, "v2.0.0") == "v1.9.0"

    # Parsed version with only newer prerelease after it in update order must NOT fall back to update order.
    newer_pre_after = [
        {"name": "v2.0.0", "message": "", "release": None},
        {"name": "v2.1.0-rc1", "message": "", "release": None},
    ]
    assert collect._preceding_tag_name(newer_pre_after, 0, "v2.0.0") is None

    # Unparsed tag names still keep list-order fallback.
    unparsed = [{"name": "release-custom-2"}, {"name": "release-custom-1"}]
    assert collect._preceding_tag_name(unparsed, 0, "release-custom-2") == "release-custom-1"

    # Trivial release.description ("v2.15.4") + trivial annotation must still fall back to compare shortlog.
    project = "tpo/anti-censorship/pluggable-transports/snowflake"
    enc_project = "tpo%2Fanti-censorship%2Fpluggable-transports%2Fsnowflake"
    feed_url = f"https://gitlab.torproject.org/{project}/-/tags"
    tags_api = f"https://gitlab.torproject.org/api/v4/projects/{enc_project}/repository/tags?per_page=15"
    cmp_url = f"https://gitlab.torproject.org/api/v4/projects/{enc_project}/repository/compare?from=v2.15.3&to=v2.15.4"
    xml_body = _tag_atom_xml(("v2.15.4", f"{feed_url}/v2.15.4", "2026-11-20T12:00:00Z"))
    tags_json = json.dumps([
        {"name": "v2.15.4", "message": "Bump version to v2.15.4", "release": {"description": "Created using the release-cli\nv2.15.4"}},
        {"name": "v2.15.3", "message": "", "release": None},
    ]).encode("utf-8")
    cmp_json = json.dumps({"commits": [{"title": "Server: Fix remote crash"}]}).encode("utf-8")
    client = _FakeHttpClient({
        feed_url: _FakeHttpResponse(feed_url, xml_body),
        tags_api: _FakeHttpResponse(tags_api, tags_json),
        cmp_url: _FakeHttpResponse(cmp_url, cmp_json),
    })
    out = collect._feed(client, _tag_source(project), feed_url, {}, _feed_settings(), DATE)
    it = out["items"][0]
    assert client.calls == [feed_url, tags_api, cmp_url]
    assert it["tag_enriched"] is True and it["tag_enrichment_kind"] == "compare"
    assert "Server: Fix remote crash" in it["content"]


def test_tag_state_released_exclusion_heading_spoof_guard_relation_and_prefix_protection():
    """Enforce tag-only released gating, heading-only non-confirmation, enriched tag relation, and protected MR prefixes."""
    from onionflash import candidate as candidate_mod, source_packet

    # 1. Protected term in MR prefix is NOT treated as housekeeping, while `util: Extract helpers` IS.
    assert util.is_housekeeping_item({
        "kind": "gitlab_mr",
        "title": "protocol: Extract helpers",
        "content": "Clients now accept a new handshake message.",
        "labels": [],
        "author": "alice",
    }) is None
    assert util.is_housekeeping_item({
        "kind": "gitlab_mr",
        "title": "util: Extract helpers",
        "content": "Move string formatting helpers internally.",
        "labels": [],
        "author": "alice",
    }) is not None

    # 2. Enriched tag routes to "update" (not "citation") on tagged/released stories, while unenriched stays "citation".
    tagged_story = {"id": "s" * 24, "state": "tagged", "sources": [{"url": "https://gitlab.torproject.org/tpo/core/tor/-/tags/tor-0.4.9.16", "id": "other"}]}
    released_story = {**tagged_story, "state": "released"}
    bare_tag = {"id": "t2", "kind": "tag", "url": "https://gitlab.torproject.org/tpo/core/tor/-/tags/tor-0.4.9.17"}
    rich_tag = {**bare_tag, "tag_enriched": True}
    assert candidate_mod.relation(tagged_story, bare_tag) == "citation"
    assert candidate_mod.relation(released_story, bare_tag) == "citation"
    assert candidate_mod.relation(tagged_story, rich_tag) == "update"
    assert candidate_mod.relation(released_story, rich_tag) == "update"

    # 3. Unenriched tag whose feed text starts with "Release notes for v2.15.4:" stays "reported" (not confirmed).
    spoof_src = {
        "id": "S1",
        "url": "https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/-/tags/v2.15.4",
        "title": "v2.15.4",
        "kind": "tag",
        "authority": "official",
        "product": "snowflake",
        "published_at": DATE,
        "updated_at": DATE,
        "labels": [],
        "passages": [{"id": "S1:P1", "text": "Release notes for v2.15.4:\nSome feed text."}],
    }
    pkt = {"sources": [spoof_src], "missing_sources": [], "truncated": False}
    assert "confirmed" not in review.repair_limits(pkt)["confidence"]
    assert "released" not in review.repair_limits(pkt)["state"]
    assert "confirmed_source" in review.final_holds(
        {"title": "Snowflake v2.15.4", "summary": "S.", "why_it_matters": "", "category": "release",
         "tags": ["release"], "confidence": "confirmed", "state": "tagged", "products": ["snowflake"]},
        {"packet": pkt, "payload": {"editorial_kind": "tag"}, "row": {"payload": json.dumps({"url": spoof_src["url"]})}},
    )

    # 4. Tag-only packets cannot introduce state="released" in writer schema or review final_holds/repair_limits,
    #    unless prior story already carries state="released".
    rich_pkt = {"sources": [{**spoof_src, "tag_enriched": True, "tag_enrichment_kind": "compare"}], "missing_sources": [], "truncated": False}
    assert "released" not in review.repair_limits(rich_pkt)["state"]
    assert "release_state" in review.final_holds(
        {"title": "Snowflake v2.15.4", "summary": "S.", "why_it_matters": "", "category": "release",
         "tags": ["release"], "confidence": "confirmed", "state": "released", "products": ["snowflake"]},
        {"packet": rich_pkt, "payload": {"editorial_kind": "tag"}, "row": {"payload": json.dumps({"url": spoof_src["url"], "tag_enriched": True})}},
    )
    upd_released = review.repair_limits(rich_pkt, {"prior_story": {"state": "released", "confidence": "confirmed"}}, update=True)
    assert "released" in upd_released["state"]
    upd_tagged = review.repair_limits(rich_pkt, {"prior_story": {"state": "tagged", "confidence": "confirmed"}}, update=True)
    assert "released" not in upd_tagged["state"]

    # source_fingerprint distinguishes tag_enriched / tag_enrichment_kind cleanly.
    base_item = {"id": "t1", "source_id": "s1", "url": spoof_src["url"], "title": "v2.15.4", "content": "x", "kind": "tag", "authority": "official", "product": "snowflake", "published_at": DATE, "updated_at": DATE, "labels": [], "upstream_state": "", "public_comments": []}
    assert source_packet.source_fingerprint(base_item) != source_packet.source_fingerprint({**base_item, "tag_enriched": True, "tag_enrichment_kind": "compare"})

    # Writer schema omits "released" for compare-only enriched tag standalone and prior=tagged, preserves on prior=released.
    w_schema_new = analyze._writer_schema({"title": "v2.15.4", "content": "Release commits:\n- Fix", "kind": "tag", "authority": "official", "tag_enriched": True, "tag_enrichment_kind": "compare"})
    assert "released" not in w_schema_new["properties"]["state"]["enum"]
    assert "confirmed" in w_schema_new["properties"]["confidence"]["enum"]
    w_schema_rel = analyze._writer_schema(
        {"title": "v2.15.4", "content": "Release commits:\n- Fix", "kind": "tag", "authority": "official", "tag_enriched": True, "tag_enrichment_kind": "compare"},
        analyze.UPDATE_SCHEMA,
        prior={"title": "P", "summary": "S", "why_it_matters": "", "confidence": "confirmed", "state": "released", "updated_at": DATE, "category": "release"},
    )
    assert "released" in w_schema_rel["properties"]["state"]["enum"]


def test_tag_enrichment_edge_cases_store_identity_and_mr_body_signal(tmp_path):
    """Cover -pre versions, multiline boilerplate, heading-only cap, cross-project isolation, non-str kind, and MR body protocol signals."""
    from onionflash import source_packet, store as store_mod

    # 1. `-pre` prerelease tags resolve predecessor on version line instead of falling back to update order.
    pre_tags = [
        {"name": "v2.0.0-pre2", "message": "", "release": None},
        {"name": "v2.1.0", "message": "", "release": None},
        {"name": "v2.0.0-pre1", "message": "", "release": None},
    ]
    assert collect._preceding_tag_name(pre_tags, 0, "v2.0.0-pre2") == "v2.0.0-pre1"

    # 2. Multiline boilerplate-only annotations are rejected; single-component tags (v1) strip boilerplate while dependency/protocol updates stay.
    assert not collect._is_substantive_tag_message("v2.15.4\nBump version to v2.15.4\nCreated using the release-cli.", "v2.15.4", "v2.15.4")
    assert not collect._is_substantive_tag_message("Bump version to v1", "v1", "v1")
    assert collect._is_substantive_tag_message("Created using the release-cli.\nFix directory authority quorum timeout.", "v2.15.4", "v2.15.4")
    assert collect._strip_trivial_tag_lines("Bump version to v2.15.4\nUpdate to openssl-3.0.0\nUpdate to HTTP/2.\nFix relay startup crash.", "v2.15.4", "v2.15.4") == "Update to openssl-3.0.0\nUpdate to HTTP/2.\nFix relay startup crash."

    # 3. Heading-only truncation returns empty string so item is not falsely marked enriched.
    long_tag = "v" + ("2." * 95) + "0"
    assert collect._bound_enriched_content(f"Release notes for {long_tag}:", "Important fix.", 100) == ""

    # 4. Cross-project tag link is NOT enriched with another project's notes, while slash refs match exact full ref.
    project = "tpo/anti-censorship/pluggable-transports/snowflake"
    enc_project = "tpo%2Fanti-censorship%2Fpluggable-transports%2Fsnowflake"
    feed_url = f"https://gitlab.torproject.org/{project}/-/tags"
    tags_api = f"https://gitlab.torproject.org/api/v4/projects/{enc_project}/repository/tags?per_page=15"
    xml_body = _tag_atom_xml(
        ("v2.0.0", "https://gitlab.torproject.org/tpo/core/tor/-/tags/v2.0.0", "2026-11-20T12:00:00Z"),
        ("v2.0.0", f"{feed_url}/release/v2.0.0", "2026-11-20T11:00:00Z"),
    )
    tags_json = json.dumps([
        {"name": "v2.0.0", "message": "Snowflake notes should stay in snowflake.", "release": None},
        {"name": "release/v2.0.0", "message": "Fixes WebRTC ICE stall on relay startup.", "release": None},
    ]).encode("utf-8")
    client = _FakeHttpClient({
        feed_url: _FakeHttpResponse(feed_url, xml_body),
        tags_api: _FakeHttpResponse(tags_api, tags_json),
    })
    out = collect._feed(client, _tag_source(project), feed_url, {}, _feed_settings(), DATE)
    by_url = {it["url"]: it for it in out["items"]}
    assert by_url["https://gitlab.torproject.org/tpo/core/tor/-/tags/v2.0.0"].get("tag_enriched") is not True
    assert by_url[f"{feed_url}/release/v2.0.0"].get("tag_enriched") is True
    assert "Fixes WebRTC ICE stall" in by_url[f"{feed_url}/release/v2.0.0"]["content"]

    # 4b. Cross-project root URL without /-/ cannot title-match; 500 trivial lines before a real note still keep the real note.
    cross_root_xml = _tag_atom_xml(
        ("v2.0.0", "https://gitlab.torproject.org/tpo/core/tor", "2026-11-20T12:00:00Z"),
        ("v2.0.1", f"{feed_url}/v2.0.1", "2026-11-20T10:00:00Z"),
    )
    noisy_notes = "\n".join(["v2.0.1"] * 500 + ["Fixes circuit padding cell leak under heavy load."])
    tags_noisy_json = json.dumps([
        {"name": "v2.0.0", "message": "Snowflake notes should stay in snowflake.", "release": None},
        {"name": "v2.0.1", "message": "", "release": {"description": noisy_notes}},
    ]).encode("utf-8")
    client2 = _FakeHttpClient({
        feed_url: _FakeHttpResponse(feed_url, cross_root_xml),
        tags_api: _FakeHttpResponse(tags_api, tags_noisy_json),
    })
    out2 = collect._feed(client2, _tag_source(project), feed_url, {}, _feed_settings(), DATE)
    by_url2 = {it["url"]: it for it in out2["items"]}
    assert by_url2["https://gitlab.torproject.org/tpo/core/tor"].get("tag_enriched") is not True
    assert by_url2[f"{feed_url}/v2.0.1"].get("tag_enriched") is True
    assert "Fixes circuit padding cell leak" in by_url2[f"{feed_url}/v2.0.1"]["content"]

    # 5. Non-string tag_enrichment_kind (e.g. []) never raises TypeError in source_fingerprint / build_packet.
    malformed_tag = {
        "id": "t-bad-kind", "source_id": "s1", "url": f"{feed_url}/v2.0.0",
        "title": "v2.0.0", "content": "Release notes for v2.0.0:\nFix", "kind": "tag",
        "authority": "official", "product": "snowflake", "published_at": DATE, "updated_at": DATE,
        "labels": [], "upstream_state": "", "public_comments": [],
        "tag_enriched": True, "tag_enrichment_kind": [],
    }
    assert source_packet.source_fingerprint(malformed_tag)

    # 6. Marker-only enrichment changes item_hash, updates stored payload, and changes writer cache_key.
    db = store_mod.Store(tmp_path / "tag.db")
    base_tag = {
        "source_id": "snowflake-tags", "url": f"{feed_url}/v2.15.4",
        "title": "v2.15.4", "content": "Upstream tag observed: v2.15.4", "kind": "tag",
        "authority": "official", "product": "snowflake", "published_at": DATE, "updated_at": DATE,
        "labels": [], "upstream_state": "",
    }
    assert db.ingest(dict(base_tag), DATE) is True
    row_lit = dict(db.db.execute("SELECT * FROM items WHERE url=?", (base_tag["url"],)).fetchone())
    enriched_same_body = {**base_tag, "tag_enriched": True, "tag_enrichment_kind": "release_notes"}
    assert db.ingest(enriched_same_body, DATE) is True
    row_rich = dict(db.db.execute("SELECT * FROM items WHERE url=?", (base_tag["url"],)).fetchone())
    assert row_rich["content_hash"] != row_lit["content_hash"]
    assert json.loads(row_rich["payload"])["tag_enrichment_kind"] == "release_notes"
    llm_cfg = config.DEFAULTS["llm"]
    assert analyze.cache_key(row_rich, llm_cfg) != analyze.cache_key(row_lit, llm_cfg)

    # 7. Material wire-protocol body prevents helper-extraction skip; pure extraction still skips.
    assert util.is_housekeeping_item({
        "kind": "gitlab_mr",
        "upstream_state": "merged",
        "title": "Extract helper functions",
        "content": "Clients now accept a new handshake message. This changes the wire protocol.",
        "labels": [],
        "url": "https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/4200",
    }) is None
    assert util.is_housekeeping_item({
        "kind": "gitlab_mr",
        "upstream_state": "merged",
        "title": "util: Extract helpers",
        "content": "Move string formatting helpers without changing behavior.",
        "labels": [],
        "url": "https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/4201",
    }) == ("skipped.gate.housekeeping", "Routine internal refactor or TODO cleanup item")
