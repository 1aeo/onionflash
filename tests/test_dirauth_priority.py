"""Unit tests for directory-authority GitLab ticket and reply prioritization."""

from __future__ import annotations

import json
from unittest import mock

import pytest

from helpers import FakeClient, FakeLLM, Reviewer, Writer, analysis, completion, item, make_config, make_tag, response, source, verdict
from onionflash import analyze, collect, comments, config as config_mod, decisions, llm, review, review_gate, source_packet
from onionflash.comments import _compose, enrich_comments, merge_cached_comments
from onionflash.store import DIRAUTH_PRIORITY, HACKERONE_PRIORITY, Store, item_priority
from onionflash.transport import Response
from onionflash.util import DIRAUTH_GITLAB_USERS, is_dirauth_item


def _write_toml(tmp_path, collection_extra: str = ""):
    """Write a minimal valid TOML configuration with optional `[collection]` settings."""
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text(
        f"""
[collection]
{collection_extra}

[[sources]]
id = "tor-issues"
name = "Tor issues"
url = "https://gitlab.torproject.org/api/v4/projects/426/issues"
kind = "gitlab_issue"
authority = "development"
product = "tor"
""",
        encoding="utf-8",
    )
    return cfg_path


def test_config_dirauth_gitlab_users_defaults_and_validation(tmp_path):
    """Validate default directory and bridge authority handles and reject malformed handle lists."""
    assert list(DIRAUTH_GITLAB_USERS) == [
        "andreas",
        "arma",
        "gman999",
        "linus",
        "micah",
        "sebastian",
        "sina",
        "stefani",
        "usura",
        "weasel",
    ]
    loaded_default = config_mod.load_config(_write_toml(tmp_path))
    assert loaded_default["collection"]["dirauth_gitlab_users"] == list(DIRAUTH_GITLAB_USERS)

    custom_path = _write_toml(
        tmp_path,
        'dirauth_gitlab_users = ["  Stefani ", "LINUS", "stefani", "relay_op-1.test"]',
    )
    loaded_custom = config_mod.load_config(custom_path)
    assert loaded_custom["collection"]["dirauth_gitlab_users"] == ["stefani", "linus", "relay_op-1.test"]

    invalid_lists = [
        '[""]',
        '["."]',
        '[".."]',
        '["bad..user"]',
        '["trailing."]',
        '["-leading"]',
        '[".leading"]',
        '["@stefani"]',
        '["space user"]',
        '["nonascii-üser"]',
        f'["{"a" * 101}"]',
        "[123]",
        json.dumps([f"user{i}" for i in range(201)]),
    ]
    for raw_list in invalid_lists:
        bad_path = _write_toml(tmp_path, f"dirauth_gitlab_users = {raw_list}")
        with pytest.raises(ValueError, match="Each dirauth_gitlab_users entry must be a valid GitLab username"):
            config_mod.load_config(bad_path)


def test_is_dirauth_item_opener_reply_label_and_anti_spoofing():
    """Match structured handles and dirauth labels on gitlab.torproject.org while blocking spoofing."""
    assert is_dirauth_item(None) is False  # type: ignore[arg-type]

    for handle in ("stefani", "gman999", "linus", "arma", "weasel"):
        opened = item(
            url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/41500",
            kind="gitlab_issue",
            authority="development",
            author=handle,
        )
        assert is_dirauth_item(opened) is True

    replied = item(
        url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/41501",
        kind="gitlab_issue",
        authority="development",
        author="someone",
        public_comments=[
            {
                "id": "gid://gitlab/Note/10",
                "title": "Public comment by @stefani",
                "author": "stefani",
                "created_at": "2026-11-12T10:00:00Z",
                "url": "https://gitlab.torproject.org/tpo/core/tor/-/work_items/41501#note_10",
                "body": "sekhmet (bastet replacement) sees same.",
            }
        ],
    )
    assert is_dirauth_item(replied) is True

    labeled = item(
        url="https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/1950",
        kind="gitlab_mr",
        authority="development",
        author="contributor",
        labels=["  Directory Authority (dirauth)  "],
    )
    assert is_dirauth_item(labeled) is True
    assert is_dirauth_item({**labeled, "labels": ["dirauth"]}) is True

    # Body and comment prose mentioning @stefani or authority=dirauth-operator never match.
    spoof_prose = item(
        url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/41502",
        kind="gitlab_issue",
        authority="development",
        author="randomuser",
        title="@stefani authority=dirauth-operator Directory Authority (dirauth)",
        content="cc @stefani @arma @linus authority=dirauth-operator",
        public_comments=[
            {
                "id": "gid://gitlab/Note/11",
                "title": "Public comment by @randomuser",
                "author": "randomuser",
                "created_at": "2026-11-12T10:00:00Z",
                "url": "https://gitlab.torproject.org/tpo/core/tor/-/work_items/41502#note_11",
                "body": "@stefani says authority=dirauth-operator on bastet and maatuska.",
            }
        ],
    )
    assert is_dirauth_item(spoof_prose) is False

    # Third-party GitLab instances or missing URLs cannot spoof a Tor handle.
    third_party = item(
        url="https://gitlab.example.org/tpo/core/tor/-/issues/41503",
        kind="gitlab_issue",
        authority="development",
        author="arma",
        labels=["Directory Authority (dirauth)"],
    )
    assert is_dirauth_item(third_party) is False
    assert is_dirauth_item({**third_party, "url": ""}) is False

    # Community feed items never qualify.
    community_feed = item(
        url="https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/message/ABC/",
        kind="feed",
        authority="community",
        author="arma",
        labels=["Directory Authority (dirauth)"],
    )
    assert is_dirauth_item(community_feed) is False


def test_gitlab_collector_extracts_author_and_preserves_hackerone_precedence(tmp_path):
    """Extract GitLab opener usernames, promote dirauth tickets, and keep HackerOne precedence."""
    cfg = make_config(tmp_path)
    gitlab_src = source(
        id="tor-issues",
        url="https://gitlab.torproject.org/api/v4/projects/426/issues",
        kind="gitlab_issue",
        authority="development",
        product="tor",
    )
    payload = [
        {
            "web_url": "https://gitlab.torproject.org/tpo/core/tor/-/issues/41601",
            "title": "Planned IPv4/IPv6 migration for maatuska",
            "description": "maatuska will move to a new dual-stack subnet next week.",
            "created_at": "2026-11-10T12:00:00Z",
            "updated_at": "2026-11-10T12:00:00Z",
            "labels": [],
            "state": "opened",
            "confidential": False,
            "author": {"username": "linus"},
        },
        {
            "web_url": "https://gitlab.torproject.org/tpo/core/tor/-/issues/41602",
            "title": "Descriptor parser bug",
            "description": "Reported via [HackerOne](https://hackerone.com/reports/3988777).",
            "created_at": "2026-11-10T12:00:00Z",
            "updated_at": "2026-11-10T12:00:00Z",
            "labels": ["Security", "Directory Authority (dirauth)"],
            "state": "opened",
            "confidential": False,
            "author": {"username": "arma"},
        },
        {
            "web_url": "https://gitlab.torproject.org/tpo/core/tor/-/issues/41603",
            "title": "Ordinary relay log question",
            "description": "Question about heartbeat log output.",
            "created_at": "2026-11-10T12:00:00Z",
            "updated_at": "2026-11-10T12:00:00Z",
            "labels": [],
            "state": "opened",
            "confidential": False,
            "author": {"username": "ordinary_user"},
        },
    ]
    client = FakeClient([response(json.dumps(payload).encode(), url=gitlab_src["url"])])
    collected = collect.collect_source(client, gitlab_src, {}, cfg["collection"], "2026-11-10T12:05:00Z")
    by_url = {entry["url"]: entry for entry in collected["items"]}

    maatuska = by_url["https://gitlab.torproject.org/tpo/core/tor/-/work_items/41601"]
    assert maatuska["author"] == "linus"
    assert maatuska["authority"] == "dirauth-operator"

    both = by_url["https://gitlab.torproject.org/tpo/core/tor/-/work_items/41602"]
    assert both["author"] == "arma"
    assert both["authority"] == "hackerone"
    assert item_priority(both) >= HACKERONE_PRIORITY + DIRAUTH_PRIORITY

    ordinary = by_url["https://gitlab.torproject.org/tpo/core/tor/-/work_items/41603"]
    assert ordinary["author"] == "ordinary_user"
    assert ordinary["authority"] == "development"

    feed_item = collect.make_item(
        source(id="blog", url="https://blog.torproject.org/feed", kind="feed", authority="official", product="tor"),
        "https://blog.torproject.org/post-1",
        "Release post",
        "Body",
        "2026-11-10T12:00:00Z",
        "2026-11-10T12:00:00Z",
    )
    assert "author" not in feed_item


def test_comment_promotion_priority_and_uncommented_rest_refresh_invariant(tmp_path):
    """Promote issues on dirauth replies, boost priority by +35, and avoid clobbering on bare REST refreshes."""
    assert DIRAUTH_PRIORITY == 35
    project = "tpo/core/tor"
    origin = "https://gitlab.torproject.org"
    issue_url = f"{origin}/{project}/-/work_items/41700"
    gql_endpoint = f"{origin}/api/graphql"
    gitlab_src = source(
        id="tor-issues",
        kind="gitlab_issue",
        gitlab_project=project,
        url=f"{origin}/api/v4/projects/426/issues",
        authority="development",
        product="tor",
    )
    cfg = {**make_config(tmp_path), "sources": [gitlab_src], "comments": {"enabled": True}}

    serge_opened = collect.make_item(
        gitlab_src,
        f"{origin}/{project}/-/work_items/41699",
        "Non-fatal assertion in conn_update_on_close on Serge",
        "After upgrading Serge to Tor 0.4.9.17, src/core/or/dos.c:745 logs non-fatal warnings.",
        "2026-11-12T09:00:00Z",
        "2026-11-12T09:00:00Z",
        labels=["Bug"],
        upstream_state="opened",
        title_html=False,
        author="gman999",
    )
    assert serge_opened["authority"] == "dirauth-operator"
    assert item_priority(serge_opened) >= DIRAUTH_PRIORITY

    bare_issue = collect.make_item(
        gitlab_src,
        issue_url,
        "Non-fatal assertion in conn_update_on_close on guard relay",
        "After upgrading to Tor 0.4.9.17, src/core/or/dos.c:745 logs non-fatal warnings.",
        "2026-11-12T09:00:00Z",
        "2026-11-12T09:00:00Z",
        labels=["Bug"],
        upstream_state="opened",
        title_html=False,
        author="relay_reporter",
    )
    assert bare_issue["authority"] == "development"
    base_score = item_priority(bare_issue)
    assert base_score < DIRAUTH_PRIORITY

    gql_data = {
        "data": {
            "project": {
                "id": "gid://gitlab/Project/426",
                "fullPath": project,
                "visibility": "public",
                "webUrl": f"{origin}/{project}",
                "issue": {
                    "iid": "41700",
                    "confidential": False,
                    "webUrl": issue_url,
                    "notes": {
                        "nodes": [
                            {
                                "id": "gid://gitlab/Note/88",
                                "body": "sekhmet (bastet replacement) sees same: Non-fatal assertion !(conn->type != CONN_TYPE_OR) at dos.c:745.",
                                "internal": False,
                                "system": False,
                                "createdAt": "2026-11-12T10:30:00Z",
                                "url": f"{issue_url}#note_88",
                                "author": {"username": "stefani"},
                            }
                        ]
                    },
                },
            }
        }
    }

    with Store(cfg["storage"]["database"]) as store:
        assert store.ingest(dict(bare_issue), "2026-11-12T09:05:00Z") is True
        row_initial = store.db.execute("SELECT id, source_id FROM items WHERE url=?", (issue_url,)).fetchone()
        with store.db:
            store.db.execute("UPDATE items SET status='ignored' WHERE url=?", (issue_url,))
            comments.request_check(store.db, cfg, dict(row_initial), "2026-11-12T09:05:00Z")

        gql_client = FakeClient([Response(200, json.dumps(gql_data).encode(), {}, gql_endpoint)])
        gql_client.close = lambda: None
        with mock.patch("onionflash.comments.HttpClient", lambda _settings: gql_client):
            rep = enrich_comments(cfg, store, "2026-11-12T10:35:00Z")
        assert rep["checked"] == 1
        assert rep["changed"] == 1

        # Re-queued in pending with +35 DIRAUTH_PRIORITY ahead of compromise/security/tag items.
        tag_item = make_tag(url="https://gitlab.torproject.org/tpo/core/tor/-/tags/tor-0.4.9.17")
        compromise = item(
            url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/41701",
            authority="development",
            title="Plausible relay compromise report",
            content="The operator reported a plausible compromise.",
            labels=[],
        )
        store.ingest(tag_item, "2026-11-12T10:36:00Z")
        store.ingest(compromise, "2026-11-12T10:36:00Z")
        queued = store.pending(10, "2026-11-12T10:36:00Z")
        assert queued[0]["url"] == issue_url
        assert queued[0]["priority_score"] == base_score + DIRAUTH_PRIORITY
        stored_enriched = json.loads(queued[0]["payload"])
        assert stored_enriched["authority"] == "dirauth-operator"
        assert stored_enriched["author"] == "relay_reporter"

        # Mark non-pending (published) and verify an un-enriched bare REST refresh does NOT clobber or re-queue.
        with store.db:
            store.db.execute("UPDATE items SET status='published', story_id='story-serge' WHERE url=?", (issue_url,))

        refreshed_bare = dict(bare_issue)
        refreshed_bare["updated_at"] = "2026-11-12T11:00:00Z"
        assert refreshed_bare["authority"] == "development"
        assert "comments_source_key" not in refreshed_bare

        assert store.ingest(dict(refreshed_bare), "2026-11-12T11:05:00Z") is False
        after_row = store.db.execute("SELECT status, priority_score, payload FROM items WHERE url=?", (issue_url,)).fetchone()
        assert after_row["status"] == "published"
        after_payload = json.loads(after_row["payload"])
        assert after_payload["authority"] == "dirauth-operator"
        assert len(after_payload["public_comments"]) == 1

        # Also verify merge_cached_comments preserves dirauth-operator when comments remain enabled.
        merged = merge_cached_comments(
            store,
            dict(refreshed_bare),
            gitlab_src,
            "2026-11-12T11:10:00Z",
            dirauth_users=cfg["collection"]["dirauth_gitlab_users"],
        )
        assert merged["authority"] == "dirauth-operator"
        assert store.ingest(merged, "2026-11-12T11:10:00Z") is False

        # If comments are disabled AND the upstream REST body actually changes, Store.ingest still queues the revision.
        edited_bare = {**refreshed_bare, "content": bare_issue["content"] + " Follow-up edit in description."}
        assert store.ingest(edited_bare, "2026-11-12T11:15:00Z") is True

    # Verify _compose demotes comment-derived dirauth-operator if the dirauth comment is later deleted.
    demoted = _compose(stored_enriched, [], "2026-11-12T12:00:00Z", source_key="verified")
    assert demoted["authority"] == "development"


def test_source_packet_and_analyzer_expose_author_and_upgrade_legacy_dirauth(tmp_path):
    """Upgrade legacy development dirauth items in source_packet and Analyzer while passing author metadata."""
    cfg = make_config(tmp_path)
    observed = "2026-11-12T12:00:00Z"
    legacy = item(
        url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/41800",
        kind="gitlab_issue",
        authority="development",
        author="linus",
        title="Planned IPv4/IPv6 migration for maatuska",
        content="maatuska will migrate to a new dual-stack address block on 2026-11-20.",
        published_at="2026-11-12T11:00:00Z",
        updated_at="2026-11-12T11:00:00Z",
        labels=[],
    )
    draft = analysis(
        title="Planned IPv4 and IPv6 migration for maatuska directory authority",
        summary="Ticket #41800 outlines a planned dual-stack address migration for the maatuska directory authority.",
        why_it_matters="",
        products=["tor"],
        confidence="reported",
        evidence=["maatuska will migrate to a new dual-stack address block on 2026-11-20."],
    )
    with Store(tmp_path / "packet.sqlite3") as store:
        store.ingest(dict(legacy), observed)
        [row] = store.pending(1, observed)
        prepared = store.prepare_candidate(row, draft, observed)
        src_meta = prepared["packet"]["sources"][0]
        assert src_meta["authority"] == "dirauth-operator"
        assert src_meta["author"] == "linus"

    client = FakeLLM(completion(draft))
    writer = analyze.Analyzer(cfg)
    writer.client = client
    os_key = cfg["llm"]["api_key_env"]
    with mock.patch.dict("os.environ", {os_key: "test-secret"}):
        writer.llm = {**cfg["llm"], "base_url": "https://llm.example.org/v1"}
        out = writer.analyze(dict(legacy))
    assert out["confidence"] == "reported"
    sent_user = json.loads(client.requests[0][1]["messages"][1]["content"])
    assert sent_user["authority"] == "dirauth-operator"
    assert sent_user["author"] == "linus"

    issue_limits = llm.label_limits([{"authority": "dirauth-operator", "kind": "gitlab_issue", "upstream_state": "opened"}])
    assert "confirmed" not in issue_limits["confidence"]
    mr_limits = llm.label_limits([{"authority": "dirauth-operator", "kind": "gitlab_mr", "upstream_state": "merged"}])
    assert "confirmed" in mr_limits["confidence"]


def test_review_gate_holds_dirauth_not_news_and_approves_valid_dirauth_ticket(tmp_path):
    """Hold dirauth-operator tickets on official_not_news instead of skipping, and publish verified approvals."""
    cfg = make_config(tmp_path)
    observed = "2026-11-12T12:10:00Z"

    chore_ticket = collect.make_item(
        source(
            id="tor-issues",
            url="https://gitlab.torproject.org/api/v4/projects/426/issues",
            kind="gitlab_issue",
            authority="development",
            product="tor",
        ),
        "https://gitlab.torproject.org/tpo/core/tor/-/issues/41901",
        "Minor comment typo in dirvote header",
        "There is a spelling typo in a code comment inside dirvote.h.",
        "2026-11-12T11:30:00Z",
        "2026-11-12T11:30:00Z",
        labels=[],
        upstream_state="opened",
        title_html=False,
        author="weasel",
    )
    assert chore_ticket["authority"] == "dirauth-operator"
    chore_draft = analysis(
        title="Code comment typo reported in dirvote.h",
        summary="A Tor GitLab issue notes a spelling typo in a code comment in dirvote.h.",
        why_it_matters="",
        confidence="reported",
        evidence=["There is a spelling typo in a code comment inside dirvote.h."],
    )
    skip_news_only = verdict("skip", criterion="news_value")

    with Store(tmp_path / "hold.sqlite3") as store:
        store.ingest(chore_ticket, observed)
        [row] = store.pending(1, observed)
        res = review_gate.process_item(
            cfg,
            store,
            row,
            Writer(chore_draft),
            Reviewer(skip_news_only, skip_news_only),
            observed,
        )
        assert res["status"] == "held"
        assert res["review_calls"] == 2
        codes = [entry["code"] for entry in decisions.for_item(store.db, row["id"])]
        assert "held.verification.official_not_news" in codes
        eligibility = review_gate.approval(cfg, store, row["id"])
        assert eligibility["eligible"] is True

    valid_ticket = collect.make_item(
        source(
            id="tor-issues",
            url="https://gitlab.torproject.org/api/v4/projects/426/issues",
            kind="gitlab_issue",
            authority="development",
            product="tor",
        ),
        "https://gitlab.torproject.org/tpo/core/tor/-/issues/41902",
        "Planned IPv4/IPv6 migration for maatuska",
        "maatuska will migrate to a new dual-stack address block on 2026-11-20.",
        "2026-11-12T11:30:00Z",
        "2026-11-12T11:30:00Z",
        labels=["Directory Authority (dirauth)"],
        upstream_state="opened",
        title_html=False,
        author="linus",
    )
    valid_draft = analysis(
        title="Planned IPv4 and IPv6 migration for maatuska directory authority",
        summary="A GitLab issue opened by linus reports a planned dual-stack IP migration for maatuska.",
        why_it_matters="",
        confidence="reported",
        evidence=["maatuska will migrate to a new dual-stack address block on 2026-11-20."],
    )
    approve_reply = verdict("approve")

    with Store(tmp_path / "publish.sqlite3") as store:
        store.ingest(valid_ticket, observed)
        [row] = store.pending(1, observed)
        res = review_gate.process_item(
            cfg,
            store,
            row,
            Writer(valid_draft),
            Reviewer(approve_reply, approve_reply),
            observed,
        )
        assert res["status"] == "published"
        stories = store.stories(5)
        assert len(stories) == 1
        assert stories[0]["confidence"] == "reported"
