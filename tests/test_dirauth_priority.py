"""Unit tests for directory-authority and HackerOne GitLab promotion, priority, and gating."""

import json

import pytest

from helpers import (
    FakeClient, Reviewer, Writer, analysis, decision_codes, enrich_with_client, gitlab_source, gql_note,
    gql_notes_response, item, job, make_config, make_note, patch_job, pending, response, run_gate,
    saved_audit, source, tag, verdict, wire_analyzer, write_toml,
)
from onionflash import (
    analyze, candidate as candidate_mod, collect, comments, config as config_mod, llm, rejection, review,
    review_gate, source_packet,
)
from onionflash.comments import _compose, merge_cached_comments
from onionflash.store import (
    DIRAUTH_PRIORITY, HACKERONE_PRIORITY, TOR_CORE_PRIORITY, Store, item_hash, item_hash_fields,
    item_priority,
)
from onionflash.util import DIRAUTH_GITLAB_USERS, digest, is_dirauth_item, is_hackerone_item


def _gl_issue(iid, title, description, author, labels=()):
    return {"web_url": f"https://gitlab.torproject.org/tpo/core/tor/-/issues/{iid}", "title": title,
            "description": description, "created_at": "2026-11-10T12:00:00Z", "updated_at": "2026-11-10T12:00:00Z",
            "labels": list(labels), "state": "opened", "confidential": False, "author": {"username": author}}


def test_config_dirauth_gitlab_users_defaults_and_validation(tmp_path):
    """Validate default directory and bridge authority handles and reject malformed handle lists."""
    assert list(DIRAUTH_GITLAB_USERS) == [
        "andreas", "arma", "gman999", "linus", "micah",
        "sebastian", "sina", "stefani", "usura", "weasel",
    ]
    loaded_default = config_mod.load_config(write_toml(tmp_path))
    assert loaded_default["collection"]["dirauth_gitlab_users"] == list(DIRAUTH_GITLAB_USERS)

    custom_path = write_toml(
        tmp_path,
        '[collection]\ndirauth_gitlab_users = ["  Stefani ", "LINUS", "stefani", "relay_op-1.test"]',
    )
    loaded_custom = config_mod.load_config(custom_path)
    assert loaded_custom["collection"]["dirauth_gitlab_users"] == ["stefani", "linus", "relay_op-1.test"]

    invalid_lists = [
        '[""]', '["."]', '[".."]', '["bad..user"]', '["trailing."]', '["-leading"]',
        '[".leading"]', '["@stefani"]', '["space user"]', '["nonascii-üser"]',
        f'["{"a" * 101}"]', "[123]", json.dumps([f"user{i}" for i in range(201)]),
    ]
    for raw_list in invalid_lists:
        bad_path = write_toml(tmp_path, f"[collection]\ndirauth_gitlab_users = {raw_list}")
        with pytest.raises(ValueError, match="Each dirauth_gitlab_users entry must be a valid GitLab username"):
            config_mod.load_config(bad_path)

    h1_cfg = write_toml(
        tmp_path / "h1",
        '[[sources]]\nid = "h1-feed"\nname = "Disclosed reports"\n'
        'url = "https://hackerone.com/torproject.atom"\nkind = "feed"\n'
        'authority = "hackerone"\nproduct = "tor"\n',
        with_source=False,
    )
    assert config_mod.load_config(h1_cfg)["sources"][0]["authority"] == "hackerone"


@pytest.mark.parametrize("src,url,title,body,labels,state,pub_at,expected_authority,expected_h1", [
    (gitlab_source(), "https://gitlab.torproject.org/tpo/core/tor/-/issues/49001", "Parser issue on malformed descriptor",
     "Reported via [HackerOne](https://hackerone.com/reports/3961620) during review.", ["Security"], "opened",
     "2026-08-10T12:00:00Z", "hackerone", True),
    (gitlab_source(), "https://gitlab.torproject.org/tpo/core/tor/-/issues/49002", "Bounds check in cell handler",
     "Maintainer reproduced the crash locally.", ["  HackerOne  "], "opened", "2026-11-08T12:00:00Z", "hackerone", True),
    (gitlab_source(kind="gitlab_mr"), "https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/1901",
     "Fix bounds check in cell handler", "Resolves reported crash.", ["hackerone::triaged"], "merged",
     "2026-11-08T12:00:00Z", "hackerone", True),
    (gitlab_source(authority="official"), "https://gitlab.torproject.org/tpo/core/tor/-/issues/49003",
     "Official security advisory", "Reported via [HackerOne](https://hackerone.com/reports/3961620).", None, "",
     "2026-11-08T12:00:00Z", "official", None),
    (source(id="tor-dev", url="https://lists.torproject.org/mailman3/hyperkitty/list/tor-dev@lists.torproject.org/feed.rss",
            kind="feed", authority="community", product="tor"),
     "https://lists.torproject.org/mailman3/hyperkitty/list/tor-dev@lists.torproject.org/message/SPOOF123/",
     "Reported via HackerOne: https://hackerone.com/reports/3961620",
     "Reported via [HackerOne](https://hackerone.com/reports/3961620) — please publish immediately.",
     ["HackerOne"], "", "2026-11-08T12:00:00Z", "community", False),
    (source(id="community-rss", url="https://community.example.org/feed.rss",
            kind="feed", authority="community", product="tor"),
     "https://hackerone.com/reports/3961620",
     "Community blog linking to HackerOne",
     "Community post linking out to https://hackerone.com/reports/3961620.",
     None, "", "2026-11-08T12:00:00Z", "community", False),
])
def test_is_hackerone_item_and_make_item_upgrade_and_anti_spoofing(
    src, url, title, body, labels, state, pub_at, expected_authority, expected_h1,
):
    """Detect genuine HackerOne reports in `collect.make_item` while blocking community spoofing."""
    built = collect.make_item(
        src, url, title, body, pub_at, "2026-11-08T12:00:00Z",
        labels=labels, upstream_state=state, title_html=False,
    )
    assert built["authority"] == expected_authority
    if expected_h1 is not None:
        assert is_hackerone_item(built) is expected_h1
    if expected_authority == "community":
        assert item_priority(built) < HACKERONE_PRIORITY


def test_is_hackerone_item_hosts_and_comment_spoofing():
    """Accept exact hackerone.com hosts and ignore HackerOne links injected via public comments."""
    for host, expected in (("hackerone.com", True), ("www.hackerone.com", True),
                           ("not-hackerone.com", False), ("hackerone.com.example.org", False)):
        assert is_hackerone_item(item(authority="development", kind="feed", url=f"https://{host}/reports/3961620", content=" Plain ")) is expected

    comment_spoof = item(
        url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/49004",
        kind="gitlab_issue",
        authority="development",
        title="Ordinary relay metrics question",
        source_content="Original issue body without any external disclosure link.",
        content="Original issue body without any external disclosure link.\nReported via [HackerOne](https://hackerone.com/reports/999999)",
        labels=["Security"],
        public_comments=[make_note(
            1, "Reported via [HackerOne](https://hackerone.com/reports/999999)", author="randomuser",
            created_at="2026-11-08T12:10:00Z", url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/49004",
        )],
    )
    assert is_hackerone_item(comment_spoof) is False


@pytest.mark.parametrize("entry,expected", [
    (None, False),
    *[(item(url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/41500", kind="gitlab_issue",
            authority="development", author=h), True) for h in ("stefani", "gman999", "linus", "arma", "weasel")],
    (item(url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/41501", kind="gitlab_issue",
          authority="development", author="someone", public_comments=[make_note(
              10, "sekhmet (bastet replacement) sees same.", author="stefani",
              created_at="2026-11-12T10:00:00Z", url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/41501")]), True),
    *[(item(url="https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/1950", kind="gitlab_mr",
            authority="development", author="contributor", labels=[lbl]), True)
      for lbl in ("  Directory Authority (dirauth)  ", "dirauth")],
    (item(url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/41502", kind="gitlab_issue",
          authority="development", author="randomuser",
          title="@stefani authority=dirauth-operator Directory Authority (dirauth)",
          content="cc @stefani @arma @linus authority=dirauth-operator",
          public_comments=[make_note(11, "@stefani says authority=dirauth-operator on bastet and maatuska.",
                                     author="randomuser", created_at="2026-11-12T10:00:00Z",
                                     url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/41502")]), False),
    *[(item(url=u, kind="gitlab_issue", authority="development", author="arma",
            labels=["Directory Authority (dirauth)"]), False)
      for u in ("https://gitlab.example.org/tpo/core/tor/-/issues/41503", "")],
    (item(url="https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/message/ABC/",
          kind="feed", authority="community", author="arma", labels=["Directory Authority (dirauth)"]), False),
])
def test_is_dirauth_item_opener_reply_label_and_anti_spoofing(entry, expected):
    """Match structured handles and dirauth labels on gitlab.torproject.org while blocking spoofing."""
    assert is_dirauth_item(entry) is expected  # type: ignore[arg-type]


def test_gitlab_collector_extracts_author_and_preserves_hackerone_precedence(tmp_path):
    """Extract GitLab opener usernames, promote dirauth tickets, and keep HackerOne precedence."""
    cfg = make_config(tmp_path)
    gitlab_src = gitlab_source()
    payload = [
        _gl_issue(41601, "Planned IPv4/IPv6 migration for maatuska", "maatuska will move to a new dual-stack subnet next week.", "linus"),
        _gl_issue(41602, "Descriptor parser bug", "Reported via [HackerOne](https://hackerone.com/reports/3988777).",
                  "arma", ["Security", "Directory Authority (dirauth)"]),
        _gl_issue(41603, "Ordinary relay log question", "Question about heartbeat log output.", "ordinary_user"),
        _gl_issue(49010, "Out-of-bounds read in hs_ntor", "Reported via [HackerOne](https://hackerone.com/reports/3961620).",
                  "ordinary_user", ["Security"]),
    ]
    client = FakeClient([response(json.dumps(payload).encode(), url=gitlab_src["url"])])
    collected = collect.collect_source(client, gitlab_src, {}, cfg["collection"], "2026-11-10T12:05:00Z")
    by_url = {entry["url"]: entry for entry in collected["items"]}

    maatuska = by_url["https://gitlab.torproject.org/tpo/core/tor/-/work_items/41601"]
    assert maatuska["author"] == "linus" and maatuska["authority"] == "dirauth-operator"

    both = by_url["https://gitlab.torproject.org/tpo/core/tor/-/work_items/41602"]
    assert both["author"] == "arma" and both["authority"] == "hackerone"
    assert item_priority(both) >= HACKERONE_PRIORITY + DIRAUTH_PRIORITY

    ordinary = by_url["https://gitlab.torproject.org/tpo/core/tor/-/work_items/41603"]
    assert ordinary["author"] == "ordinary_user" and ordinary["authority"] == "development"

    h1_only = by_url["https://gitlab.torproject.org/tpo/core/tor/-/work_items/49010"]
    assert h1_only["authority"] == "hackerone" and is_hackerone_item(h1_only) is True

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
    issue_url = "https://gitlab.torproject.org/tpo/core/tor/-/work_items/41700"
    gitlab_src = gitlab_source()
    cfg = {**make_config(tmp_path), "sources": [gitlab_src], "comments": {"enabled": True}}

    def _make_issue(url, title, body, author):
        return collect.make_item(gitlab_src, url, title, body, "2026-11-12T09:00:00Z", "2026-11-12T09:00:00Z",
                                 labels=["Bug"], upstream_state="opened", title_html=False, author=author)

    serge_opened = _make_issue(
        "https://gitlab.torproject.org/tpo/core/tor/-/work_items/41699",
        "Non-fatal assertion in conn_update_on_close on Serge",
        "After upgrading Serge to Tor 0.4.9.17, src/core/or/dos.c:745 logs non-fatal warnings.",
        "gman999",
    )
    assert serge_opened["authority"] == "dirauth-operator" and item_priority(serge_opened) >= DIRAUTH_PRIORITY

    bare_issue = _make_issue(
        issue_url,
        "Non-fatal assertion in conn_update_on_close on guard relay",
        "After upgrading to Tor 0.4.9.17, src/core/or/dos.c:745 logs non-fatal warnings.",
        "relay_reporter",
    )
    assert bare_issue["authority"] == "development"
    base_score = item_priority(bare_issue)
    assert base_score < DIRAUTH_PRIORITY

    gql_resp = gql_notes_response(
        [gql_note("88", "sekhmet (bastet replacement) sees same: Non-fatal assertion !(conn->type != CONN_TYPE_OR) at dos.c:745.",
                  author="stefani", created_at="2026-11-12T10:30:00Z", iid="41700", url=issue_url)],
        iid="41700", issue_url=issue_url,
    )

    with Store(cfg["storage"]["database"]) as store:
        assert store.ingest(dict(bare_issue), "2026-11-12T09:05:00Z") is True
        row_initial = store.db.execute("SELECT id, source_id FROM items WHERE url=?", (issue_url,)).fetchone()
        with store.db:
            store.db.execute("UPDATE items SET status='ignored' WHERE url=?", (issue_url,))
            comments.request_check(store.db, cfg, dict(row_initial), "2026-11-12T09:05:00Z")

        rep = enrich_with_client(cfg, store, FakeClient([gql_resp]), "2026-11-12T10:35:00Z")
        assert rep["checked"] == 1 and rep["changed"] == 1

        tag_item = tag(url="https://gitlab.torproject.org/tpo/core/tor/-/tags/tor-0.4.9.17")
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

        with store.db:
            store.db.execute("UPDATE items SET status='published', story_id='story-serge' WHERE url=?", (issue_url,))

        refreshed_bare = {**bare_issue, "updated_at": "2026-11-12T11:00:00Z"}
        assert refreshed_bare["authority"] == "development" and "comments_source_key" not in refreshed_bare
        assert store.ingest(dict(refreshed_bare), "2026-11-12T11:05:00Z") is False
        after_row = store.db.execute("SELECT status, priority_score, payload FROM items WHERE url=?", (issue_url,)).fetchone()
        assert after_row["status"] == "published"
        after_payload = json.loads(after_row["payload"])
        assert after_payload["authority"] == "dirauth-operator" and len(after_payload["public_comments"]) == 1

        merged = merge_cached_comments(
            store, dict(refreshed_bare), gitlab_src, "2026-11-12T11:10:00Z", dirauth_users=cfg["collection"]["dirauth_gitlab_users"]
        )
        assert merged["authority"] == "dirauth-operator"
        assert store.ingest(merged, "2026-11-12T11:10:00Z") is False

        edited_bare = {**refreshed_bare, "content": bare_issue["content"] + " Follow-up edit in description."}
        assert store.ingest(edited_bare, "2026-11-12T11:15:00Z") is True

    demoted = _compose(stored_enriched, [], "2026-11-12T12:00:00Z", source_key="verified")
    assert demoted["authority"] == "development"


@pytest.mark.parametrize("expected_prio,promoted_kw", [
    (HACKERONE_PRIORITY, {"authority": "hackerone"}),
    (DIRAUTH_PRIORITY, {"authority": "dirauth-operator", "author": "linus"}),
])
def test_authority_priority_outranks_compromise_security_and_tag_items(store, expected_prio, promoted_kw):
    """Boost HackerOne and dirauth items by +35 so Store.pending schedules them first."""
    assert expected_prio == 35
    promoted = item(url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/49101",
                    title="Descriptor parser differential", content="A relay descriptor field is parsed differently.",
                    labels=[], **promoted_kw)
    compromise_item = item(url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/49102", authority="development",
                           title="Plausible relay compromise report", content="The operator reported a plausible compromise.", labels=[])
    security_item = item(url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/49103", authority="development",
                         title="Memory safety bug", content="Buffer handling bug.", labels=["Security"])
    tag_item = tag(url="https://gitlab.torproject.org/tpo/core/tor/-/tags/tor-0.4.9.16")
    assert item_priority(promoted) >= 35
    assert item_priority(promoted) > item_priority(compromise_item) > item_priority(security_item) > item_priority(tag_item)
    for candidate_item in (tag_item, security_item, compromise_item, promoted):
        assert store.ingest(candidate_item, "2026-11-08T12:00:00Z") is True
    assert [r["url"] for r in store.pending(10, "2026-11-08T12:00:00Z")] == [
        promoted["url"], compromise_item["url"], security_item["url"], tag_item["url"],
    ]


@pytest.mark.parametrize("expected_auth,legacy_kw,draft_kw", [
    ("dirauth-operator",
     {"url": "https://gitlab.torproject.org/tpo/core/tor/-/work_items/41800", "author": "linus",
      "title": "Planned IPv4/IPv6 migration for maatuska",
      "content": "maatuska will migrate to a new dual-stack address block on 2026-11-20.", "labels": []},
     {"title": "Planned IPv4 and IPv6 migration for maatuska directory authority",
      "summary": "Ticket #41800 outlines a planned dual-stack address migration for the maatuska directory authority.",
      "products": ["tor"], "evidence": ["maatuska will migrate to a new dual-stack address block on 2026-11-20."]}),
    ("hackerone",
     {"url": "https://gitlab.torproject.org/tpo/core/arti/-/work_items/2680", "product": "arti",
      "title": "Protover parser differential",
      "content": "Reported via [HackerOne](https://hackerone.com/reports/3959033) not verified by me.", "labels": ["Security"]},
     {"title": "Reported Arti protover parser differential",
      "summary": "A HackerOne report describes a protover parser differential between C Tor and Arti.",
      "products": ["arti"], "evidence": ["Reported via [HackerOne](https://hackerone.com/reports/3959033)"]}),
])
def test_source_packet_analyzer_and_label_limits_upgrade_legacy_authority(
    context, monkeypatch, expected_auth, legacy_kw, draft_kw,
):
    """Upgrade legacy development items to dirauth-operator or hackerone across packet, Analyzer, and label_limits."""
    cfg, store = context
    observed = "2026-11-12T12:00:00Z"
    legacy = item(kind="gitlab_issue", authority="development", published_at="2026-09-02T13:50:00Z",
                  updated_at="2026-11-08T12:00:00Z", **legacy_kw)
    draft = analysis(why_it_matters="", confidence="reported", **draft_kw)
    row = pending(store, dict(legacy), at=observed, ready=observed)
    prepared = store.prepare_candidate(row, draft, observed)
    src_meta = prepared["packet"]["sources"][0]
    assert src_meta["authority"] == expected_auth and src_meta.get("author") == legacy_kw.get("author")
    packet, _ = source_packet.build_packet(
        store.db, json.loads(row["payload"]), prepared["payload"], prepared["candidate"], prepared["payload"].get("editorial_item"),
    )
    assert packet["sources"][0]["authority"] == expected_auth

    writer = wire_analyzer(monkeypatch, draft, cfg=cfg)
    assert writer.analyze(dict(legacy))["confidence"] == "reported"
    sent_user = json.loads(writer.client.requests[0][1]["messages"][1]["content"])
    assert sent_user["authority"] == expected_auth and sent_user.get("author") == legacy_kw.get("author")

    issue_limits = llm.label_limits([{"authority": expected_auth, "kind": "gitlab_issue", "upstream_state": "opened"}])
    assert issue_limits["confidence"] == ["reported", "suspected", "observed-anomaly"]
    mr_limits = llm.label_limits([{"authority": expected_auth, "kind": "gitlab_mr", "upstream_state": "merged"}])
    assert "confirmed" in mr_limits["confidence"]


@pytest.mark.parametrize("ticket,expected_authority,draft_title,draft_summary,evidence,verdict_args,expected_status", [
    (item(url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/49300", kind="gitlab_issue",
          authority="hackerone", title="Disclosed HackerOne parser edge case",
          content="Reported via [HackerOne](https://hackerone.com/reports/3961620). Maintainers rated the edge case low severity.",
          published_at="2026-11-08T10:00:00Z", updated_at="2026-11-08T12:00:00Z",
          labels=["Security"], comments_source_key="verified"),
     "hackerone", "Reported parser edge case disclosed via HackerOne",
     "A HackerOne report describes a parser edge case that maintainers rated low severity.",
     "Maintainers rated the edge case low severity.", ("skip", {"criterion": "news_value"}), "held"),
    (item(url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/49301", kind="gitlab_issue",
          authority="development", title="Disclosed HackerOne parser edge case",
          content="Reported via [HackerOne](https://hackerone.com/reports/3961620). Maintainers rated the edge case low severity.",
          published_at="2026-11-08T10:00:00Z", updated_at="2026-11-08T12:00:00Z",
          labels=["Security"], comments_source_key="verified"),
     "hackerone", "Reported parser edge case disclosed via HackerOne",
     "A HackerOne report describes a parser edge case that maintainers rated low severity.",
     "Maintainers rated the edge case low severity.", ("skip", {"criterion": "news_value"}), "held"),
    (collect.make_item(gitlab_source(), "https://gitlab.torproject.org/tpo/core/tor/-/issues/41901",
                       "Minor comment typo in dirvote header", "There is a spelling typo in a code comment inside dirvote.h.",
                       "2026-11-12T11:30:00Z", "2026-11-12T11:30:00Z", labels=[], upstream_state="opened",
                       title_html=False, author="weasel"),
     "dirauth-operator", "Code comment typo reported in dirvote.h",
     "A Tor GitLab issue notes a spelling typo in a code comment in dirvote.h.",
     "There is a spelling typo in a code comment inside dirvote.h.", ("skip", {"criterion": "news_value"}), "held"),
    (collect.make_item(gitlab_source(), "https://gitlab.torproject.org/tpo/core/tor/-/issues/41902",
                       "Planned IPv4/IPv6 migration for maatuska", "maatuska will migrate to a new dual-stack address block on 2026-11-20.",
                       "2026-11-12T11:30:00Z", "2026-11-12T11:30:00Z", labels=["Directory Authority (dirauth)"],
                       upstream_state="opened", title_html=False, author="linus"),
     "dirauth-operator", "Planned IPv4 and IPv6 migration for maatuska directory authority",
     "A GitLab issue opened by linus reports a planned dual-stack IP migration for maatuska.",
     "maatuska will migrate to a new dual-stack address block on 2026-11-20.", ("approve", {}), "published"),
])
def test_review_gate_holds_official_not_news_and_approves_valid_tickets(
    context, ticket, expected_authority, draft_title, draft_summary, evidence, verdict_args, expected_status,
):
    """Hold HackerOne and dirauth tickets as official_not_news on news_value skip, and publish verified approvals."""
    cfg, store = context
    observed = "2026-11-12T12:10:00Z"
    draft = analysis(title=draft_title, summary=draft_summary, why_it_matters="", confidence="reported", evidence=[evidence])
    reply = verdict(verdict_args[0], **verdict_args[1])
    row = pending(store, dict(ticket), at=observed, ready=observed)
    checker = Reviewer(reply, reply)
    res = run_gate(cfg, store, row, Writer(draft), checker, observed)
    assert res["status"] == expected_status and res["review_calls"] == 2
    assert [call[2] for call in checker.calls] == [False, True]
    assert checker.calls[0][1]["sources"][0]["authority"] == expected_authority
    if expected_status == "held":
        assert decision_codes(store, row["id"]) == ["held.verification.official_not_news"]
        record = saved_audit(store, row["id"])
        assert (record["hold_code"], record["verified_facts"]) == ("official_not_news", True)
        assert review_gate.approval(cfg, store, row["id"])["eligible"] is True
    else:
        stories = store.stories(5)
        assert len(stories) == 1 and stories[0]["confidence"] == "reported"


def test_ninety_day_unembargoed_hackerone_issue_bypasses_not_recent_while_normal_issue_skips(context):
    """Allow newly unembargoed 90-day-old HackerOne Security issues past _not_recent while skipping ordinary ones."""
    cfg, store = context
    observed = "2026-11-08T12:05:00Z"
    h1_old = item(
        url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/49201",
        kind="gitlab_issue", authority="development", title="Descriptor parsing flaw on malformed line",
        content="Reported via [HackerOne](https://hackerone.com/reports/3999111). A malformed descriptor field triggers an assertion failure.",
        published_at="2026-08-10T12:00:00Z", updated_at="2026-11-08T12:00:00Z",
        labels=["Security"], comments_source_key="verified",
    )
    ordinary_old = {
        **h1_old, "url": "https://gitlab.torproject.org/tpo/core/tor/-/work_items/49202",
        "title": "Old unlabeled-severity security ticket",
        "content": "A malformed descriptor field triggers an assertion failure.",
    }
    draft = analysis(
        title="Reported descriptor parsing assertion failure in Tor",
        summary="A disclosed HackerOne report describes a malformed descriptor field that triggers an assertion failure.",
        why_it_matters="", confidence="reported", evidence=["A malformed descriptor field triggers an assertion failure."],
    )
    ordinary_row = pending(store, ordinary_old, at=observed, ready=observed)
    h1_row = pending(store, h1_old, at=observed, ready=observed)

    ordinary_writer = Writer(draft)
    assert run_gate(cfg, store, ordinary_row, ordinary_writer, Reviewer(verdict()), observed)["status"] == "ignored"
    assert len(ordinary_writer.calls) == 0 and decision_codes(store, ordinary_row["id"])[0] == "skipped.gate.not_recent"

    h1_writer = Writer(draft)
    assert run_gate(cfg, store, h1_row, h1_writer, Reviewer(verdict()), observed)["status"] == "published"
    assert len(h1_writer.calls) == 1


def test_prompt_versions_and_hackerone_and_tordev_trusted_operator_rules():
    """Verify bumped prompt versions and presence of HackerOne, tor-core, TROVE, and tor-dev rules."""
    assert analyze.PROMPT_VERSION == "onionflash-22"
    assert review.REVIEW_VERSION == "onionflash-review-18"
    assert "hackerone" in review_gate.OFFICIAL_AUTHORITIES
    assert "dirauth-operator" in review_gate.OFFICIAL_AUTHORITIES
    analyze_prompt = " ".join(analyze.SYSTEM_PROMPT.split())
    review_prompt = " ".join(review.SYSTEM_PROMPT.split())
    update_prompt = " ".join(review.UPDATE_SYSTEM_PROMPT.split())
    assert "including hackerone, dirauth-operator, trusted-operator and project-sender" in analyze_prompt
    assert "tor-core" in analyze_prompt and "category=security" in analyze_prompt
    assert "cite HackerOne in prose when the source text itself references HackerOne" in analyze_prompt
    assert "hackerone marks a disclosed HackerOne report" in review_prompt
    assert "tor-core marks a listed Tor Project GitLab account" in review_prompt
    assert "mandatory_news_rule" in review_prompt
    assert "unless source authority is hackerone, a gitlab_issue in the packet cites hackerone.com/reports/" in review_prompt
    assert "Disclosed HackerOne reports (authority=hackerone or a gitlab_issue citing hackerone.com/reports/)" in review_prompt
    assert "authority=project-sender or authority=trusted-operator" in review_prompt
    assert "substantive technical critique, protocol review, or empirical multi-relay measurement" in review_prompt
    assert "Community, issue, hackerone, dirauth-operator, project-sender and trusted-operator" in update_prompt
    assert "tor-core" in update_prompt


def test_evicted_dirauth_reply_retains_authority_while_deleted_reply_demotes(tmp_path):
    """Preserve dirauth-operator when 40+ newer replies evict an authority note, but demote on deletion."""
    cfg = make_config(tmp_path)
    cfg["comments"]["enabled"] = True
    issue_url = "https://gitlab.torproject.org/tpo/core/tor/-/issues/41950"
    gitlab_src = gitlab_source(url="https://gitlab.torproject.org/api/v4/projects/tpo%2Fcore%2Ftor/issues")
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
    stefani_node = gql_note(
        1, "Confirmed on bastet authority logs.", author="stefani", created_at="2026-11-12T08:05:00Z", iid="41950", url=issue_url
    )
    forty_newer = [
        gql_note(
            i, f"Follow-up discussion comment {i}.", author=f"commenter_{i}",
            created_at=f"2026-11-12T09:{i - 2:02d}:00Z", iid="41950", url=issue_url,
        )
        for i in range(2, 42)
    ]
    assert len(forty_newer) == comments.NOTE_WINDOW

    with Store(tmp_path / "eviction.sqlite3") as store:
        assert store.ingest(dict(bare), "2026-11-12T08:06:00Z") is True
        resp1 = gql_notes_response([stefani_node], iid="41950", issue_url=issue_url)
        rep1 = enrich_with_client(cfg, store, FakeClient([resp1]), "2026-11-12T08:10:00Z")
        assert rep1["checked"] == 1 and rep1["changed"] == 1

        saved1 = json.loads(store.db.execute("SELECT payload FROM items WHERE url=?", (issue_url,)).fetchone()[0])
        assert saved1["authority"] == "dirauth-operator" and saved1["comments_truncated"] is False
        assert saved1["dirauth_notes"] == [{"id": "gid://gitlab/Note/1", "author": "stefani", "created_at": "2026-11-12T08:05:00Z"}]

        with store.db:
            store.db.execute("UPDATE comment_cache SET next_fetch_at='2026-11-12T09:50:00Z' WHERE item_id=?", (saved1["id"],))
        resp2 = gql_notes_response(forty_newer, iid="41950", issue_url=issue_url)
        assert enrich_with_client(cfg, store, FakeClient([resp2]), "2026-11-12T10:00:00Z")["checked"] == 1

        saved2 = json.loads(store.db.execute("SELECT payload FROM items WHERE url=?", (issue_url,)).fetchone()[0])
        assert all(n["author"] != "stefani" for n in saved2["public_comments"])
        assert saved2["comments_truncated"] is True and saved2["authority"] == "dirauth-operator"
        assert saved2["dirauth_notes"] == [{"id": "gid://gitlab/Note/1", "author": "stefani", "created_at": "2026-11-12T08:05:00Z"}]

        with store.db:
            store.db.execute("UPDATE items SET status='published', story_id='story-41950' WHERE url=?", (issue_url,))
        refreshed = {**bare, "updated_at": "2026-11-12T10:05:00Z"}
        merged = merge_cached_comments(
            store, dict(refreshed), gitlab_src, "2026-11-12T10:06:00Z", dirauth_users=cfg["collection"]["dirauth_gitlab_users"]
        )
        assert merged["authority"] == "dirauth-operator" and merged["comments_truncated"] is True
        assert merged["dirauth_notes"] == saved2["dirauth_notes"]
        assert store.ingest(merged, "2026-11-12T10:06:00Z") is False
        assert store.ingest(dict(refreshed), "2026-11-12T10:07:00Z") is False

    remaining_two = [make_note(2, "Follow-up discussion comment 2.", author="commenter_2", created_at="2026-11-12T09:00:00Z", url=issue_url)]
    demoted_full = _compose(saved2, remaining_two, "2026-11-12T11:00:00Z", source_key="verified", window_truncated=False)
    assert "dirauth_notes" not in demoted_full and demoted_full["authority"] == "development"

    newer_auth = _compose(
        bare,
        [make_note(99, "Recent note later deleted.", author="stefani", created_at="2026-11-12T09:35:00Z", url=issue_url), *saved2["public_comments"][:5]],
        "2026-11-12T09:36:00Z",
        source_key="verified",
        window_truncated=True,
    )
    assert newer_auth["authority"] == "dirauth-operator"
    demoted_trunc = _compose(newer_auth, saved2["public_comments"], "2026-11-12T11:05:00Z", source_key="verified", window_truncated=True)
    assert "dirauth_notes" not in demoted_trunc and demoted_trunc["authority"] == "development"

    mid_url = "https://gitlab.torproject.org/tpo/core/tor/-/issues/41951"
    mid_bare = {**bare, "id": "tor-issues-41951", "url": mid_url}
    mid_stefani = gql_note(1, "Authority bastet logs match.", author="stefani",
                           created_at="2026-11-12T08:05:00Z", iid="41951", url=mid_url)
    thirteen_other = [
        gql_note(i, f"User reply {i}.", author=f"user_{i}",
                 created_at=f"2026-11-12T09:{i - 2:02d}:00Z", iid="41951", url=mid_url)
        for i in range(2, 15)
    ]
    with Store(tmp_path / "mid-window.sqlite3") as store:
        assert store.ingest(dict(mid_bare), "2026-11-12T08:06:00Z") is True
        resp_mid1 = gql_notes_response([mid_stefani, *thirteen_other[:12]], iid="41951", issue_url=mid_url)
        assert enrich_with_client(cfg, store, FakeClient([resp_mid1]), "2026-11-12T09:30:00Z")["changed"] == 1
        mid_saved1 = json.loads(store.db.execute("SELECT payload FROM items").fetchone()[0])
        assert len(mid_saved1["public_comments"]) == comments.MAX_COMMENTS
        assert all(n["author"] != "stefani" for n in mid_saved1["public_comments"])
        assert mid_saved1["authority"] == "dirauth-operator" and mid_saved1["comments_truncated"] is True
        assert mid_saved1["dirauth_notes"] == [{"id": "gid://gitlab/Note/1", "author": "stefani", "created_at": "2026-11-12T08:05:00Z"}]
        mid_merged = merge_cached_comments(
            store, {**mid_bare, "updated_at": "2026-11-12T09:31:00Z"}, gitlab_src, "2026-11-12T09:32:00Z",
            dirauth_users=cfg["collection"]["dirauth_gitlab_users"],
        )
        assert mid_merged["authority"] == "dirauth-operator" and mid_merged["dirauth_notes"] == mid_saved1["dirauth_notes"]

        with store.db:
            store.db.execute("UPDATE comment_cache SET next_fetch_at='2026-11-12T09:35:00Z'")
        resp_mid2 = gql_notes_response(thirteen_other, iid="41951", issue_url=mid_url)
        assert enrich_with_client(cfg, store, FakeClient([resp_mid2]), "2026-11-12T09:40:00Z")["changed"] == 1
        mid_saved2 = json.loads(store.db.execute("SELECT payload FROM items").fetchone()[0])
        assert "dirauth_notes" not in mid_saved2 and mid_saved2["authority"] == "development"


@pytest.mark.parametrize(
    ("users", "tor_core_users", "author", "expected_prio", "expected_authority", "expected_status", "expected_calls", "expected_code"),
    [
        ([], [], "linus", 0, "development", "ignored", 1, "skipped.review.news_value"),
        ([], None, "linus", TOR_CORE_PRIORITY, "tor-core", "ignored", 1, "skipped.review.news_value"),
        (["custom_auth"], [], "custom_auth", DIRAUTH_PRIORITY, "dirauth-operator", "held", 2, "held.verification.official_not_news"),
    ],
)
def test_custom_dirauth_gitlab_users_threads_through_queue_packet_and_gate(
    tmp_path, users, tor_core_users, author, expected_prio, expected_authority, expected_status, expected_calls, expected_code
):
    """Honor custom dirauth_gitlab_users and tor_core_gitlab_users across queue, packet, and gate."""
    observed = "2026-11-12T12:00:00Z"
    body = "Minor formatting note opened on a configured authority ticket."
    suffix = f"{len(users)}-{0 if tor_core_users is None else len(tor_core_users)}-{author}"
    issue = item(
        url=f"https://gitlab.torproject.org/tpo/core/tor/-/issues/4196{len(users)}{0 if tor_core_users is None else 1}",
        kind="gitlab_issue",
        authority="development",
        author=author,
        title="Minor formatting note on authority host",
        content=body,
        published_at="2026-11-12T11:00:00Z",
        updated_at="2026-11-12T11:00:00Z",
        labels=[],
    )
    draft = analysis(
        title="Minor formatting note on authority host",
        summary="A GitLab issue notes a minor formatting detail on an authority host.",
        why_it_matters="",
        confidence="reported",
        evidence=[body],
    )
    skip_news = verdict("skip", criterion="news_value")
    cfg = make_config(tmp_path / suffix)
    cfg["collection"]["dirauth_gitlab_users"] = users
    if tor_core_users is not None:
        cfg["collection"]["tor_core_gitlab_users"] = tor_core_users
    assert item_priority(issue, users, tor_core_users) == expected_prio

    with Store(tmp_path / f"{suffix}.sqlite3", dirauth_users=users, tor_core_users=tor_core_users) as store:
        store.ingest(dict(issue), observed)
        [row] = store.pending(1, observed)
        assert row["priority_score"] == expected_prio
        prep = store.prepare_candidate(row, draft, observed)
        assert prep["packet"]["sources"][0]["authority"] == expected_authority
        replies = (skip_news,) * expected_calls
        res = review_gate.process_item(cfg, store, row, Writer(draft), Reviewer(*replies), observed)
        assert res["status"] == expected_status and res["review_calls"] == expected_calls
        assert expected_code in decision_codes(store, row["id"])
        if expected_status == "held":
            elig = review_gate.approval(cfg, store, row["id"])
            assert elig["eligible"] is True
            approved = rejection.approve_item(
                cfg, store, row["id"], elig["hash"], "Approve custom authority", observed="2026-11-12T12:15:00Z"
            )
            assert approved["status"] == "published"


def test_numeric_note_ids_reconcile_same_timestamp_deletions_and_evictions():
    """Compare numeric GitLab note IDs by integer value during same-timestamp deletion and floor checks."""
    stamp = "2026-11-12T12:00:00Z"
    issue_url = "https://gitlab.torproject.org/tpo/core/tor/-/issues/41990"
    window_60_to_99 = [make_note(nid, f"Comment {nid}", author="user", created_at=stamp, url=issue_url) for nid in range(99, 59, -1)]
    deleted_100 = {
        "kind": "gitlab_issue",
        "authority": "dirauth-operator",
        "url": issue_url,
        "title": "Consensus timeout report",
        "content": "Initial report.",
        "published_at": "2026-11-12T11:00:00Z",
        "updated_at": stamp,
        "labels": [],
        "dirauth_notes": [{"id": "gid://gitlab/Note/100", "author": "stefani", "created_at": stamp}],
    }
    after_del = _compose(deleted_100, window_60_to_99, "2026-11-12T12:05:00Z", source_key="verified", window_truncated=True)
    assert "dirauth_notes" not in after_del and after_del["authority"] == "development"

    evicted_50 = {**deleted_100, "dirauth_notes": [{"id": "gid://gitlab/Note/50", "author": "stefani", "created_at": stamp}]}
    window_with_101 = [make_note(101, "Comment 101", author="user", created_at=stamp, url=issue_url), *window_60_to_99]
    after_evict = _compose(evicted_50, window_with_101, "2026-11-12T12:05:00Z", source_key="verified", window_truncated=True)
    assert after_evict["authority"] == "dirauth-operator"
    assert [n["id"] for n in after_evict["dirauth_notes"]] == ["gid://gitlab/Note/50"]


def test_author_changes_update_item_hash_ingest_source_fingerprint_and_analyzer(tmp_path, monkeypatch):
    """Refresh stored payloads and fingerprints when a development item's author is added or changed."""
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

    assert len({item_hash(base_issue), item_hash(with_first), item_hash(with_second)}) == 3
    assert len({source_packet.source_fingerprint(x) for x in (base_issue, with_first, with_second)}) == 3

    draft = analysis(
        title="Relay descriptor upload retry delay",
        summary="Ticket #41970 reports a 60-second descriptor upload retry delay after transient EOF.",
        why_it_matters="",
        confidence="reported",
        evidence=["Descriptor upload retries wait 60 seconds after transient EOF."],
    )

    with Store(tmp_path / "author.sqlite3") as store:
        for incoming, stamp, expected_author in (
            (base_issue, observed, None),
            (with_first, "2026-11-12T12:05:00Z", "ordinary_user"),
            (with_second, "2026-11-12T12:10:00Z", "second_user"),
        ):
            assert store.ingest(dict(incoming), stamp) is True
            [row] = store.pending(1, stamp)
            payload = json.loads(row["payload"])
            assert payload.get("author") == expected_author
            prep = store.prepare_candidate(row, draft, stamp)
            assert prep["packet"]["sources"][0].get("author") == expected_author

    writer = wire_analyzer(monkeypatch, draft, cfg=cfg)
    writer.analyze(dict(payload))
    sent_user = json.loads(writer.client.requests[0][1]["messages"][1]["content"])
    assert sent_user["author"] == "second_user"


def test_dirauth_notes_backfill_keeps_item_hash_and_legacy_review_jobs_remain_valid(tmp_path):
    """Avoid spurious item_hash changes on dirauth_notes backfill and accept pre-#53 and transitional saved envelopes."""
    cfg = make_config(tmp_path)
    cfg["comments"]["enabled"] = True
    issue_url = "https://gitlab.torproject.org/tpo/core/tor/-/issues/41980"
    cfg["sources"] = [gitlab_source(url="https://gitlab.torproject.org/api/v4/projects/tpo%2Fcore%2Ftor/issues")]
    observed = "2026-11-12T12:00:00Z"

    arma_comment = make_note(
        77,
        "Triaged on moria1; low severity.",
        author="arma",
        created_at="2026-11-12T10:00:00Z",
        url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/41980",
    )
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

    def _stage_held_job(db_name, seed_item, mutate, next_fn, next_stamp, pub_stamp):
        with Store(tmp_path / db_name) as store:
            held = pending(store, dict(seed_item), at=observed, ready=observed)
            assert run_gate(cfg, store, held, Writer(initial_draft), Reviewer(verdict("hold")), observed)["status"] == "held"
            saved = job(store, held["id"])
            env, rec = json.loads(saved["envelope_json"]), json.loads(saved["record_json"])
            payload = json.loads(env["row"]["payload"])
            mutate(env, rec, payload)
            patch_job(store, held["id"], envelope=env, record=rec)
            requeued = pending(store, next_fn(payload), at=next_stamp, ready=next_stamp)
            loaded_job, _, _, _, same_source = review_gate._saved_job(store, requeued, cfg)
            assert loaded_job is not None and same_source is False
            assert run_gate(cfg, store, requeued, Writer(updated_draft), Reviewer(verdict()), pub_stamp)["status"] == "published"

    def _mutate_pre53(env, _rec, saved_payload):
        meta = {k: env["row"].get(k) for k in ("id", "url", "source_id", "content_hash", "cluster_key", "story_id", "status")}
        pre53_fp = digest([meta, digest({k: saved_payload.get(k) for k in source_packet.BASE_SOURCE_FIELDS})])
        assert pre53_fp == candidate_mod.item_fingerprint(env["row"])
        env["binding"]["item"] = pre53_fp

    def _next_pre53(saved_payload):
        stefani_note = make_note(88, "Confirmed on bastet.", author="stefani", created_at="2026-11-12T11:30:00Z",
                                 url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/41981")
        enriched = _compose(dict(saved_payload), [stefani_note], "2026-11-12T12:05:00Z", source_key="verified")
        assert enriched["authority"] == "dirauth-operator" and "dirauth_notes" in enriched
        return enriched

    _stage_held_job("legacy-job.sqlite3", legacy_issue, _mutate_pre53, _next_pre53,
                    "2026-11-12T12:05:00Z", "2026-11-12T12:06:00Z")

    def _mutate_transitional(t_env, t_rec, t_payload):
        trans_hash = digest({**item_hash_fields(t_payload), "dirauth_notes": t_payload["dirauth_notes"]})
        t_env["row"]["content_hash"] = t_rec["input_hash"] = trans_hash
        t_meta = {k: t_env["row"].get(k) for k in ("id", "url", "source_id", "content_hash", "cluster_key", "story_id", "status")}
        t_src_fp = digest({k: t_payload.get(k) for k in (*source_packet.BASE_SOURCE_FIELDS, "author", "dirauth_notes")})
        t_env["binding"]["item"] = digest([t_meta, t_src_fp])
        t_env["binding_hash"] = t_rec["prepared"]["binding_hash"] = digest(t_env["binding"])
        for rev_entry in t_rec["reviews"]:
            rev_entry["binding_hash"] = t_env["binding_hash"]

    trans_item = {
        **legacy_issue, "authority": "dirauth-operator", "public_comments": [arma_comment],
        "dirauth_notes": [{"id": "gid://gitlab/Note/77", "author": "arma", "created_at": "2026-11-12T10:00:00Z"}],
    }
    _stage_held_job(
        "transitional-job.sqlite3", trans_item, _mutate_transitional,
        lambda p: {**p, "content": p["content"] + " Updated authority details.", "updated_at": "2026-11-12T12:10:00Z"},
        "2026-11-12T12:10:00Z", "2026-11-12T12:11:00Z",
    )


@pytest.mark.parametrize("with_newer_public", [True, False])
def test_deleted_dirauth_note_evicts_when_older_system_notes_fill_graphql_window(tmp_path, with_newer_public):
    """Evict deleted dirauth markers inside the 40-node GraphQL window when older system notes establish the floor."""
    cfg = make_config(tmp_path)
    cfg["comments"]["enabled"] = True
    issue_url = "https://gitlab.torproject.org/tpo/core/tor/-/issues/41995"
    cfg["sources"] = [gitlab_source(url="https://gitlab.torproject.org/api/v4/projects/tpo%2Fcore%2Ftor/issues")]
    bare = item(
        id="tor-issues-41995",
        source_id="tor-issues",
        url=issue_url,
        kind="gitlab_issue",
        authority="development",
        author="ordinary_reporter",
        title="Consensus voting log check",
        content="Checking authority log output.",
        published_at="2026-11-12T10:00:00Z",
        updated_at="2026-11-12T10:05:00Z",
        labels=[],
    )
    arma_node = gql_note(
        10, "Observed on moria1.", author="arma", createdAt="2026-11-12T10:05:00Z", iid="41995", url=issue_url
    )
    system_count = 39 if with_newer_public else 40
    older_system = [
        {**gql_note(100 + i, f"changed label {i}", author="bot", createdAt="2026-11-12T10:01:00Z", iid="41995", url=issue_url),
         "system": True}
        for i in range(1, system_count + 1)
    ]
    tail = (
        [gql_note(50, "Public follow-up.", author="user_50", createdAt="2026-11-12T10:10:00Z", iid="41995", url=issue_url)]
        if with_newer_public
        else []
    )
    poll_b_nodes = [*older_system, *tail]
    assert len(poll_b_nodes) == comments.NOTE_WINDOW

    with Store(tmp_path / f"sysfloor-{with_newer_public}.sqlite3") as store:
        assert store.ingest(dict(bare), "2026-11-12T10:06:00Z") is True
        assert enrich_with_client(cfg, store, FakeClient([gql_notes_response([arma_node], iid="41995", issue_url=issue_url)]),
                                  "2026-11-12T10:06:00Z")["changed"] == 1
        promoted = json.loads(store.db.execute("SELECT payload FROM items").fetchone()[0])
        assert promoted["authority"] == "dirauth-operator" and len(promoted["dirauth_notes"]) == 1

        with store.db:
            store.db.execute("UPDATE comment_cache SET next_fetch_at='2026-11-12T10:11:00Z'")
        assert enrich_with_client(cfg, store, FakeClient([gql_notes_response(poll_b_nodes, iid="41995", issue_url=issue_url)]),
                                  "2026-11-12T10:12:00Z")["changed"] == 1
        demoted = json.loads(store.db.execute("SELECT payload FROM items").fetchone()[0])
        assert "dirauth_notes" not in demoted and demoted["authority"] == "development"
