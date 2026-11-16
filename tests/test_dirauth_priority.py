"""Unit tests for directory-authority GitLab ticket and reply prioritization."""

from __future__ import annotations

import json
from unittest import mock

import pytest

from helpers import FakeClient, FakeLLM, Reviewer, Writer, analysis, completion, item, make_config, make_tag, response, source, verdict
from onionflash import analyze, collect, comments, config as config_mod, decisions, llm, rejection, review, review_gate, source_packet
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


def test_evicted_dirauth_reply_retains_authority_while_deleted_reply_demotes(tmp_path):
    """Preserve dirauth-operator when 40+ newer replies evict an authority note, but demote on deletion."""
    cfg = make_config(tmp_path)
    cfg["comments"]["enabled"] = True
    issue_url = "https://gitlab.torproject.org/tpo/core/tor/-/issues/41950"
    gitlab_src = {
        "id": "tor-issues",
        "name": "Tor issues",
        "url": "https://gitlab.torproject.org/api/v4/projects/tpo%2Fcore%2Ftor/issues",
        "gitlab_project": "tpo/core/tor",
        "kind": "gitlab_issue",
        "authority": "development",
        "product": "tor",
        "enabled": True,
    }
    cfg["sources"] = [gitlab_src]

    bare = item(
        id="tor-issues-41950",
        source_id="tor-issues",
        url=issue_url,
        kind="gitlab_issue",
        authority="development",
        author="ordinary_reporter",
        title="Consensus bandwidth weight discrepancy",
        content="Observed a discrepancy in bandwidth weights across relays.",
        published_at="2026-11-12T08:00:00Z",
        updated_at="2026-11-12T08:05:00Z",
        labels=[],
    )

    def gql_nodes(node_list):
        """Build a canned GitLab GraphQL issue-notes response."""
        return Response(
            200,
            json.dumps({
                "data": {
                    "project": {
                        "id": "gid://gitlab/Project/426",
                        "fullPath": "tpo/core/tor",
                        "visibility": "public",
                        "webUrl": "https://gitlab.torproject.org/tpo/core/tor",
                        "issue": {
                            "iid": "41950",
                            "confidential": False,
                            "webUrl": issue_url,
                            "notes": {"nodes": node_list},
                        },
                    }
                }
            }).encode("utf-8"),
            {"content-type": "application/json"},
            "https://gitlab.torproject.org/api/graphql",
        )

    def make_node(num: int, username: str, created_at: str, body: str):
        """Construct one public GitLab GraphQL note node."""
        return {
            "id": f"gid://gitlab/Note/{num}",
            "body": body,
            "createdAt": created_at,
            "lastEditedAt": None,
            "internal": False,
            "system": False,
            "url": f"{issue_url}#note_{num}",
            "author": {"username": username},
        }

    stefani_node = make_node(1, "stefani", "2026-11-12T08:05:00Z", "Confirmed on bastet authority logs.")
    forty_newer = [
        make_node(i, f"commenter_{i}", f"2026-11-12T09:{i - 2:02d}:00Z", f"Follow-up discussion comment {i}.")
        for i in range(2, 42)
    ]
    assert len(forty_newer) == comments.NOTE_WINDOW

    with Store(tmp_path / "eviction.sqlite3") as store:
        assert store.ingest(dict(bare), "2026-11-12T08:06:00Z") is True
        with mock.patch("onionflash.comments.HttpClient", return_value=FakeClient([gql_nodes([stefani_node])])):
            rep1 = enrich_comments(cfg, store, "2026-11-12T08:10:00Z")
        assert rep1["checked"] == 1 and rep1["changed"] == 1

        saved1 = json.loads(store.db.execute("SELECT payload FROM items WHERE url=?", (issue_url,)).fetchone()[0])
        assert saved1["authority"] == "dirauth-operator"
        assert saved1["comments_truncated"] is False
        assert saved1["dirauth_notes"] == [
            {"id": "gid://gitlab/Note/1", "author": "stefani", "created_at": "2026-11-12T08:05:00Z"}
        ]

        # Force immediate re-check when 40 newer ordinary comments have evicted @stefani's note from NOTE_WINDOW.
        with store.db:
            store.db.execute("UPDATE comment_cache SET next_fetch_at='2026-11-12T09:50:00Z' WHERE item_id=?", (saved1["id"],))
        with mock.patch("onionflash.comments.HttpClient", return_value=FakeClient([gql_nodes(forty_newer)])):
            rep2 = enrich_comments(cfg, store, "2026-11-12T10:00:00Z")
        assert rep2["checked"] == 1

        saved2 = json.loads(store.db.execute("SELECT payload FROM items WHERE url=?", (issue_url,)).fetchone()[0])
        assert all(n["author"] != "stefani" for n in saved2["public_comments"])
        assert saved2["comments_truncated"] is True
        assert saved2["dirauth_notes"] == [
            {"id": "gid://gitlab/Note/1", "author": "stefani", "created_at": "2026-11-12T08:05:00Z"}
        ]
        assert saved2["authority"] == "dirauth-operator"

        # Mark published and verify both merge_cached_comments and bare REST refresh keep dirauth-operator.
        with store.db:
            store.db.execute("UPDATE items SET status='published', story_id='story-41950' WHERE url=?", (issue_url,))
        refreshed = {**bare, "updated_at": "2026-11-12T10:05:00Z"}
        merged = merge_cached_comments(
            store, dict(refreshed), gitlab_src, "2026-11-12T10:06:00Z", dirauth_users=cfg["collection"]["dirauth_gitlab_users"]
        )
        assert merged["authority"] == "dirauth-operator"
        assert merged["comments_truncated"] is True
        assert merged["dirauth_notes"] == saved2["dirauth_notes"]
        assert store.ingest(merged, "2026-11-12T10:06:00Z") is False
        assert store.ingest(dict(refreshed), "2026-11-12T10:07:00Z") is False

    # Actual deletion in a non-truncated fetch drops dirauth_notes and demotes authority.
    remaining_two = [
        {
            "id": "gid://gitlab/Note/2",
            "url": f"{issue_url}#note_2",
            "title": "Public comment by @commenter_2",
            "author": "commenter_2",
            "created_at": "2026-11-12T09:00:00Z",
            "body": "Follow-up discussion comment 2.",
        }
    ]
    demoted_full = _compose(saved2, remaining_two, "2026-11-12T11:00:00Z", source_key="verified", window_truncated=False)
    assert "dirauth_notes" not in demoted_full
    assert demoted_full["authority"] == "development"

    # Actual deletion of a newer authority note inside a truncated window (created_at > window floor) also demotes.
    newer_auth = _compose(
        bare,
        [
            {
                "id": "gid://gitlab/Note/99",
                "url": f"{issue_url}#note_99",
                "title": "Public comment by @stefani",
                "author": "stefani",
                "created_at": "2026-11-12T09:35:00Z",
                "body": "Recent note later deleted.",
            },
            *saved2["public_comments"][:5],
        ],
        "2026-11-12T09:36:00Z",
        source_key="verified",
        window_truncated=True,
    )
    assert newer_auth["authority"] == "dirauth-operator"
    demoted_trunc = _compose(
        newer_auth,
        saved2["public_comments"],
        "2026-11-12T11:05:00Z",
        source_key="verified",
        window_truncated=True,
    )
    assert "dirauth_notes" not in demoted_trunc
    assert demoted_trunc["authority"] == "development"


def test_custom_dirauth_gitlab_users_threads_through_queue_packet_and_gate(tmp_path):
    """Honor custom dirauth_gitlab_users (including empty and custom handles) across queue, packet, and gate."""
    observed = "2026-11-12T12:00:00Z"
    linus_issue = item(
        url="https://gitlab.torproject.org/tpo/core/tor/-/issues/41960",
        kind="gitlab_issue",
        authority="development",
        author="linus",
        title="Minor comment cleanup in test helper",
        content="Clean up an unused variable comment in a unit test helper.",
        published_at="2026-11-12T11:00:00Z",
        updated_at="2026-11-12T11:00:00Z",
        labels=[],
    )
    draft_linus = analysis(
        title="Minor comment cleanup in test helper",
        summary="A GitLab issue suggests cleaning up an unused variable comment in a unit test helper.",
        why_it_matters="",
        confidence="reported",
        evidence=["Clean up an unused variable comment in a unit test helper."],
    )
    skip_news = verdict("skip", criterion="news_value")

    cfg_empty = make_config(tmp_path / "empty")
    cfg_empty["collection"]["dirauth_gitlab_users"] = []
    assert item_priority(linus_issue, []) == 0
    with Store(tmp_path / "empty.sqlite3", dirauth_users=[]) as store_empty:
        store_empty.ingest(dict(linus_issue), observed)
        [row_empty] = store_empty.pending(1, observed)
        assert row_empty["priority_score"] == 0
        prep_empty = store_empty.prepare_candidate(row_empty, draft_linus, observed)
        assert prep_empty["packet"]["sources"][0]["authority"] == "development"
        res_empty = review_gate.process_item(
            cfg_empty, store_empty, row_empty, Writer(draft_linus), Reviewer(skip_news), observed
        )
        assert res_empty["status"] == "ignored"
        assert res_empty["review_calls"] == 1
        codes_empty = [entry["code"] for entry in decisions.for_item(store_empty.db, row_empty["id"])]
        assert codes_empty == ["skipped.review.news_value"]

    custom_issue = item(
        url="https://gitlab.torproject.org/tpo/core/tor/-/issues/41961",
        kind="gitlab_issue",
        authority="development",
        author="custom_auth",
        title="Minor formatting note on custom authority host",
        content="Formatting note opened by a custom configured authority handle.",
        published_at="2026-11-12T11:10:00Z",
        updated_at="2026-11-12T11:10:00Z",
        labels=[],
    )
    draft_custom = analysis(
        title="Minor formatting note on custom authority host",
        summary="A GitLab issue notes a minor formatting detail on a configured authority host.",
        why_it_matters="",
        confidence="reported",
        evidence=["Formatting note opened by a custom configured authority handle."],
    )
    cfg_custom = make_config(tmp_path / "custom")
    cfg_custom["collection"]["dirauth_gitlab_users"] = ["custom_auth"]
    assert item_priority(custom_issue, ["custom_auth"]) == DIRAUTH_PRIORITY
    with Store(tmp_path / "custom.sqlite3", dirauth_users=["custom_auth"]) as store_custom:
        store_custom.ingest(dict(custom_issue), observed)
        [row_custom] = store_custom.pending(1, observed)
        assert row_custom["priority_score"] == DIRAUTH_PRIORITY
        prep_custom = store_custom.prepare_candidate(row_custom, draft_custom, observed)
        assert prep_custom["packet"]["sources"][0]["authority"] == "dirauth-operator"
        res_custom = review_gate.process_item(
            cfg_custom, store_custom, row_custom, Writer(draft_custom), Reviewer(skip_news, skip_news), observed
        )
        assert res_custom["status"] == "held"
        assert res_custom["review_calls"] == 2
        codes_custom = [entry["code"] for entry in decisions.for_item(store_custom.db, row_custom["id"])]
        assert "held.verification.official_not_news" in codes_custom
        elig_custom = review_gate.approval(cfg_custom, store_custom, row_custom["id"])
        assert elig_custom["eligible"] is True
        approved_custom = rejection.approve_item(
            cfg_custom, store_custom, row_custom["id"], elig_custom["hash"], "Approve custom authority", observed="2026-11-12T12:15:00Z"
        )
        assert approved_custom["status"] == "published"


def test_numeric_note_ids_reconcile_same_timestamp_deletions_and_evictions():
    """Compare numeric GitLab note IDs by integer value during same-timestamp deletion and floor checks."""
    stamp = "2026-11-12T12:00:00Z"
    window_60_to_99 = [
        {
            "id": f"gid://gitlab/Note/{nid}",
            "url": f"https://gitlab.torproject.org/tpo/core/tor/-/issues/41990#note_{nid}",
            "title": "Public comment by @user",
            "author": "user",
            "created_at": stamp,
            "body": f"Comment {nid}",
        }
        for nid in range(99, 59, -1)
    ]
    deleted_100 = {
        "kind": "gitlab_issue",
        "authority": "dirauth-operator",
        "url": "https://gitlab.torproject.org/tpo/core/tor/-/issues/41990",
        "title": "Consensus timeout report",
        "content": "Initial report.",
        "published_at": "2026-11-12T11:00:00Z",
        "updated_at": stamp,
        "labels": [],
        "dirauth_notes": [{"id": "gid://gitlab/Note/100", "author": "stefani", "created_at": stamp}],
    }
    after_del = _compose(deleted_100, window_60_to_99, "2026-11-12T12:05:00Z", source_key="verified", window_truncated=True)
    assert "dirauth_notes" not in after_del
    assert after_del["authority"] == "development"

    evicted_50 = {
        **deleted_100,
        "dirauth_notes": [{"id": "gid://gitlab/Note/50", "author": "stefani", "created_at": stamp}],
    }
    window_with_101 = [
        {
            "id": "gid://gitlab/Note/101",
            "url": "https://gitlab.torproject.org/tpo/core/tor/-/issues/41990#note_101",
            "title": "Public comment by @user",
            "author": "user",
            "created_at": stamp,
            "body": "Comment 101",
        },
        *window_60_to_99,
    ]
    after_evict = _compose(evicted_50, window_with_101, "2026-11-12T12:05:00Z", source_key="verified", window_truncated=True)
    assert after_evict["authority"] == "dirauth-operator"
    assert [n["id"] for n in after_evict["dirauth_notes"]] == ["gid://gitlab/Note/50"]


def test_author_changes_update_item_hash_ingest_source_fingerprint_and_analyzer(tmp_path):
    """Refresh stored payloads and fingerprints when a development item's author is added or changed."""
    from onionflash.store import item_hash

    cfg = make_config(tmp_path)
    observed = "2026-11-12T12:00:00Z"
    base_issue = item(
        url="https://gitlab.torproject.org/tpo/core/tor/-/issues/41970",
        kind="gitlab_issue",
        authority="development",
        title="Relay descriptor upload retry delay",
        content="Descriptor upload retries wait 60 seconds after transient EOF.",
        published_at="2026-11-12T10:00:00Z",
        updated_at="2026-11-12T10:00:00Z",
        labels=[],
    )
    base_issue.pop("author", None)
    with_first = {**base_issue, "author": "ordinary_user", "updated_at": "2026-11-12T10:05:00Z"}
    with_second = {**base_issue, "author": "second_user", "updated_at": "2026-11-12T10:10:00Z"}

    h0, h1, h2 = item_hash(base_issue), item_hash(with_first), item_hash(with_second)
    assert len({h0, h1, h2}) == 3
    fp0 = source_packet.source_fingerprint(base_issue)
    fp1 = source_packet.source_fingerprint(with_first)
    fp2 = source_packet.source_fingerprint(with_second)
    assert len({fp0, fp1, fp2}) == 3

    draft = analysis(
        title="Relay descriptor upload retry delay",
        summary="Ticket #41970 reports a 60-second descriptor upload retry delay after transient EOF.",
        why_it_matters="",
        confidence="reported",
        evidence=["Descriptor upload retries wait 60 seconds after transient EOF."],
    )

    with Store(tmp_path / "author.sqlite3") as store:
        assert store.ingest(dict(base_issue), observed) is True
        [row0] = store.pending(1, observed)
        assert "author" not in json.loads(row0["payload"])
        prep0 = store.prepare_candidate(row0, draft, observed)
        assert "author" not in prep0["packet"]["sources"][0]

        assert store.ingest(dict(with_first), "2026-11-12T12:05:00Z") is True
        [row1] = store.pending(1, "2026-11-12T12:05:00Z")
        payload1 = json.loads(row1["payload"])
        assert payload1["author"] == "ordinary_user"
        prep1 = store.prepare_candidate(row1, draft, "2026-11-12T12:05:00Z")
        assert prep1["packet"]["sources"][0]["author"] == "ordinary_user"

        assert store.ingest(dict(with_second), "2026-11-12T12:10:00Z") is True
        [row2] = store.pending(1, "2026-11-12T12:10:00Z")
        payload2 = json.loads(row2["payload"])
        assert payload2["author"] == "second_user"
        prep2 = store.prepare_candidate(row2, draft, "2026-11-12T12:10:00Z")
        assert prep2["packet"]["sources"][0]["author"] == "second_user"

    client = FakeLLM(completion(draft))
    writer = analyze.Analyzer(cfg)
    writer.client = client
    with mock.patch.dict("os.environ", {cfg["llm"]["api_key_env"]: "secret"}):
        writer.llm = {**cfg["llm"], "base_url": "https://llm.example.org/v1"}
        writer.analyze(dict(payload2))
    sent_user = json.loads(client.requests[0][1]["messages"][1]["content"])
    assert sent_user["author"] == "second_user"


def test_dirauth_notes_backfill_keeps_item_hash_and_legacy_review_jobs_remain_valid(tmp_path):
    """Avoid spurious item_hash changes on dirauth_notes backfill and accept pre-#53 and transitional saved envelopes."""
    from onionflash import candidate as candidate_mod
    from onionflash.store import item_hash
    from onionflash.util import digest

    cfg = make_config(tmp_path)
    cfg["comments"]["enabled"] = True
    issue_url = "https://gitlab.torproject.org/tpo/core/tor/-/issues/41980"
    gitlab_src = {
        "id": "tor-issues",
        "name": "Tor issues",
        "url": "https://gitlab.torproject.org/api/v4/projects/tpo%2Fcore%2Ftor/issues",
        "gitlab_project": "tpo/core/tor",
        "kind": "gitlab_issue",
        "authority": "development",
        "product": "tor",
        "enabled": True,
    }
    cfg["sources"] = [gitlab_src]
    observed = "2026-11-12T12:00:00Z"

    arma_comment = {
        "id": "gid://gitlab/Note/77",
        "url": "https://gitlab.torproject.org/tpo/core/tor/-/work_items/41980#note_77",
        "title": "Public comment by @arma",
        "author": "arma",
        "created_at": "2026-11-12T10:00:00Z",
        "body": "Triaged on moria1; low severity.",
    }
    h1_with_arma = item(
        id="tor-issues-41980",
        source_id="tor-issues",
        url=issue_url,
        kind="gitlab_issue",
        authority="hackerone",
        title="Descriptor bounds check reported via HackerOne",
        content="Reported via [HackerOne](https://hackerone.com/reports/3990001).",
        published_at="2026-11-12T09:00:00Z",
        updated_at="2026-11-12T10:00:00Z",
        labels=["Security"],
        public_comments=[arma_comment],
    )
    backfilled = {
        **h1_with_arma,
        "dirauth_notes": [{"id": "gid://gitlab/Note/77", "author": "arma", "created_at": "2026-11-12T10:00:00Z"}],
    }
    assert item_hash(h1_with_arma) == item_hash(backfilled)
    assert source_packet.source_fingerprint(h1_with_arma) == source_packet.source_fingerprint(backfilled)

    # 1. Pre-#53 held review_jobs row (binding["item"] computed with BASE_SOURCE_FIELDS, no author/dirauth_notes).
    legacy_issue = item(
        source_id="tor-issues",
        url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/41981",
        kind="gitlab_issue",
        authority="development",
        title="Authority consensus fetch warning",
        content="Observed a transient warning during consensus fetch.",
        published_at="2026-11-12T09:00:00Z",
        updated_at="2026-11-12T09:00:00Z",
        labels=["Bug"],
    )
    legacy_issue.pop("author", None)
    legacy_issue.pop("dirauth_notes", None)
    initial_draft = analysis(
        title="Authority consensus fetch warning",
        summary="Ticket #41981 notes a transient warning during consensus fetch.",
        why_it_matters="",
        confidence="reported",
        evidence=["Observed a transient warning during consensus fetch."],
    )
    updated_draft = analysis(
        title="Bastet authority operator corroborates consensus fetch warning",
        summary="Ticket #41981 and @stefani report a consensus fetch warning on bastet.",
        why_it_matters="",
        confidence="reported",
        evidence=["Observed a transient warning during consensus fetch."],
    )

    with Store(tmp_path / "legacy-job.sqlite3") as store:
        assert store.ingest(dict(legacy_issue), observed) is True
        [held_row] = store.pending(1, observed)
        res_hold = review_gate.process_item(
            cfg, store, held_row, Writer(initial_draft), Reviewer(verdict("hold")), observed
        )
        assert res_hold["status"] == "held"

        # Rewrite binding["item"] with explicit BASE_SOURCE_FIELDS formula to model a pre-#53 saved envelope.
        job_row = store.db.execute("SELECT envelope_json FROM review_jobs WHERE item_id=?", (held_row["id"],)).fetchone()
        env = json.loads(job_row["envelope_json"])
        saved_payload = json.loads(env["row"]["payload"])
        meta = {k: env["row"].get(k) for k in ("id", "url", "source_id", "content_hash", "cluster_key", "story_id", "status")}
        pre53_fp = digest([meta, digest({k: saved_payload.get(k) for k in source_packet.BASE_SOURCE_FIELDS})])
        assert pre53_fp == candidate_mod.item_fingerprint(env["row"])
        env["binding"]["item"] = pre53_fp
        with store.db:
            store.db.execute("UPDATE review_jobs SET envelope_json=? WHERE item_id=?", (json.dumps(env), held_row["id"]))

        # Now comment rotation adds @stefani's dirauth reply + dirauth_notes -> new content_hash, status='pending'.
        stefani_note = {
            "id": "gid://gitlab/Note/88",
            "url": "https://gitlab.torproject.org/tpo/core/tor/-/work_items/41981#note_88",
            "title": "Public comment by @stefani",
            "author": "stefani",
            "created_at": "2026-11-12T11:30:00Z",
            "body": "Confirmed on bastet.",
        }
        enriched_rev = _compose(dict(saved_payload), [stefani_note], "2026-11-12T12:05:00Z", source_key="verified")
        assert enriched_rev["authority"] == "dirauth-operator"
        assert "dirauth_notes" in enriched_rev
        assert store.ingest(enriched_rev, "2026-11-12T12:05:00Z") is True
        [requeued_row] = store.pending(1, "2026-11-12T12:05:00Z")

        loaded_job, _, _, _, same_source = review_gate._saved_job(store, requeued_row, cfg)
        assert loaded_job is not None and same_source is False

        res_pub = review_gate.process_item(
            cfg,
            store,
            requeued_row,
            Writer(updated_draft),
            Reviewer(verdict("approve"), verdict("approve")),
            "2026-11-12T12:06:00Z",
        )
        assert res_pub["status"] == "published"

    # 2. Transitional #53 held review_jobs row (saved with author/dirauth_notes in SOURCE_FIELDS and dirauth_notes in item_hash).
    with Store(tmp_path / "transitional-job.sqlite3") as store2:
        trans_item = {
            **legacy_issue,
            "authority": "dirauth-operator",
            "public_comments": [arma_comment],
            "dirauth_notes": [{"id": "gid://gitlab/Note/77", "author": "arma", "created_at": "2026-11-12T10:00:00Z"}],
        }
        assert store2.ingest(dict(trans_item), observed) is True
        [t_row] = store2.pending(1, observed)
        assert review_gate.process_item(cfg, store2, t_row, Writer(initial_draft), Reviewer(verdict("hold")), observed)["status"] == "held"

        # Rewrite saved envelope + record + items row with transitional #53 hashes (including dirauth_notes).
        t_job = store2.db.execute("SELECT envelope_json, record_json FROM review_jobs WHERE item_id=?", (t_row["id"],)).fetchone()
        t_env = json.loads(t_job["envelope_json"])
        t_rec = json.loads(t_job["record_json"])
        t_payload = json.loads(t_env["row"]["payload"])
        trans_fields = {k: t_payload.get(k) for k in ("title", "content", "kind", "product", "labels", "authority", "upstream_state")}
        trans_fields["content"] = t_payload.get("source_content", t_payload.get("content"))
        trans_fields["public_comments"] = comments.analysis_context(t_payload)[1]
        trans_fields["dirauth_notes"] = t_payload["dirauth_notes"]
        trans_hash = digest(trans_fields)
        t_env["row"]["content_hash"] = trans_hash
        t_rec["input_hash"] = trans_hash
        t_meta = {k: t_env["row"].get(k) for k in ("id", "url", "source_id", "content_hash", "cluster_key", "story_id", "status")}
        t_src_fp = digest({k: t_payload.get(k) for k in (*source_packet.BASE_SOURCE_FIELDS, "author", "dirauth_notes")})
        t_env["binding"]["item"] = digest([t_meta, t_src_fp])
        t_env["binding_hash"] = digest(t_env["binding"])
        t_rec["prepared"]["binding_hash"] = t_env["binding_hash"]
        for rev_entry in t_rec["reviews"]:
            rev_entry["binding_hash"] = t_env["binding_hash"]
        with store2.db:
            store2.db.execute("UPDATE review_jobs SET envelope_json=?, record_json=? WHERE item_id=?",
                              (json.dumps(t_env), json.dumps(t_rec), t_row["id"]))

        next_rev = {**t_payload, "content": t_payload["content"] + " Updated authority details.", "updated_at": "2026-11-12T12:10:00Z"}
        assert store2.ingest(next_rev, "2026-11-12T12:10:00Z") is True
        [next_row] = store2.pending(1, "2026-11-12T12:10:00Z")
        loaded_t_job, _, _, _, t_same = review_gate._saved_job(store2, next_row, cfg)
        assert loaded_t_job is not None and t_same is False
        assert review_gate.process_item(
            cfg, store2, next_row, Writer(updated_draft), Reviewer(verdict("approve"), verdict("approve")), "2026-11-12T12:11:00Z"
        )["status"] == "published"
