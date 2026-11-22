"""Tests for deterministic collection, authority, TROVE/CVE, and review-gate rules."""

import copy
import json

import pytest

from helpers import (
    DATE, DEFAULTS, LATER, FakeClient, Response, Reviewer, Writer, analysis, decision_codes,
    enrich_with_client, gitlab_source, gql_note, gql_notes_response, insert_approval, item_row,
    list_rss, make_config, make_note, pending, public_dns, run_gate, seed_source_story, source,
    verdict,
)
from onionflash import (
    analyze, candidate as candidate_mod, collect, comments, editorial, llm, rejection, review,
    review_gate, source_packet,
)
from onionflash.schema import CATEGORIES
from onionflash.store import (
    DIRAUTH_PRIORITY, HACKERONE_PRIORITY, TOR_CORE_PRIORITY, TROVE_PRIORITY,
    TRUSTED_OPERATOR_PRIORITY, ReviewRequired, Store, item_priority,
)
from onionflash.util import (
    DEFAULT_TOR_CORE_USERS, cve_ids, digest, effective_authority, is_official_release_announcement,
    is_tor_core_item, is_torproject_new_thread, is_trove_item, mandatory_news_rule,
    tor_core_user_set, trove_ids,
)


def _collect_feed(xml_bytes, *, src_url="https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/feed/", trusted_domains=("torproject.org", "1aeo.com")):
    """Parse one RSS feed response offline through `collect.collect_source`."""
    src = source(id="tor-relays", url=src_url, authority="community")

    class _Client:
        """Minimal offline HTTP client yielding a single prepared RSS response."""

        def request(self, _method, url, **_kw):
            """Return the prepared RSS 2.0 response."""
            return Response(200, xml_bytes, {}, url)

    settings = {
        **DEFAULTS["collection"],
        "content_chars": 8000,
        "lookback_days": 14,
        "trusted_sender_domains": list(trusted_domains),
    }
    return collect.collect_source(_Client(), src, {}, settings, "2026-11-10T12:00:00Z")["items"]


def _story_item(**kw):
    """Build a test source item dictionary with minimal defaults."""
    return {
        "id": "example-item",
        "source_id": "tor-issues",
        "url": "https://gitlab.torproject.org/tpo/core/tor/-/work_items/50001",
        "title": "Minor code cleanup",
        "content": "Routine repository maintenance note with ordinary wording.",
        "published_at": DATE,
        "updated_at": DATE,
        "kind": "gitlab_issue",
        "product": "tor",
        "authority": "development",
        "labels": [],
        **kw,
    }


def _story_draft(**kw):
    """Build a story-mode draft dictionary with matching default evidence."""
    defaults = {
        "title": "Minor cleanup noted",
        "summary": "A GitLab issue records a minor maintenance detail.",
        "why_it_matters": "",
        "category": "network",
        "priority": "normal",
        "confidence": "reported",
        "state": "developing",
        "tags": ["network"],
        "evidence": ["Routine repository maintenance note"],
    }
    return analysis(**{**defaults, **kw})


def test_hyperkitty_rss_email_split_authors_promote_project_and_trusted_senders(monkeypatch):
    """Promote single-author HyperKitty RSS items even when feedparser splits `email` into `authors`."""
    monkeypatch.setattr("onionflash.transport.socket.getaddrinfo", public_dns)
    rss = list_rss(
        {
            "title": "[Tor-relays] Consensus notice",
            "link": "https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/message/ABC1/",
            "author": "dev＠torproject.org (dev@torproject.org)",
            "description": "Important update for relay operators.",
        },
        {
            "title": "[Tor-relays] Operator telemetry note",
            "link": "https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/message/ABC2/",
            "author": "ops＠1aeo.com (ops@1aeo.com)",
            "description": "Measured exit capacity across family.",
        },
        {
            "title": "[Tor-relays] Mixed external post",
            "link": "https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/message/ABC3/",
            "author": "user＠example.com (user@example.com)",
            "description": "External question.",
        },
        list_name="tor-relays",
    )
    items = _collect_feed(rss)
    assert [(i["authority"], i.get("sender_domain")) for i in items] == [
        ("project-sender", "torproject.org"),
        ("trusted-operator", "1aeo.com"),
        ("community", None),
    ]

    multi_author_rss = list_rss(
        {
            "title": "Spoofed dual-author entry",
            "link": "https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/message/ABC4/",
            "xml": "<author>dev＠torproject.org (dev@torproject.org)</author><dc:creator>spoof@example.org</dc:creator>",
            "description": "Should stay community when multiple authors appear.",
        },
        list_name="tor-relays",
    )
    assert _collect_feed(multi_author_rss)[0]["authority"] == "community"


def test_gitlab_collection_threads_tor_core_and_authority_precedence(monkeypatch):
    """Promote GitLab contributors to tor-core while respecting hackerone > dirauth > tor-core."""
    records = [
        {
            "iid": 10,
            "web_url": "https://gitlab.torproject.org/tpo/core/tor/-/issues/10",
            "title": "Core contributor performance note",
            "description": "Investigates scheduler latency.",
            "created_at": DATE,
            "updated_at": DATE,
            "labels": [],
            "state": "opened",
            "confidential": False,
            "author": {"username": "gk"},
        },
        {
            "iid": 11,
            "web_url": "https://gitlab.torproject.org/tpo/core/tor/-/issues/11",
            "title": "Authority report from shared handle",
            "description": "Checks consensus timing.",
            "created_at": DATE,
            "updated_at": DATE,
            "labels": [],
            "state": "opened",
            "confidential": False,
            "author": {"username": "linus"},
        },
        {
            "iid": 12,
            "web_url": "https://gitlab.torproject.org/tpo/core/tor/-/issues/12",
            "title": "Custom tor-core user ticket",
            "description": "Custom team handle test.",
            "created_at": DATE,
            "updated_at": DATE,
            "labels": [],
            "state": "opened",
            "confidential": False,
            "author": {"username": "custom_core"},
        },
    ]

    class _Client:
        """Minimal offline HTTP client yielding GitLab issue pages."""

        def request(self, _method, url, **_kw):
            """Return one GitLab JSON page followed by an empty stop page."""
            return Response(200, json.dumps(records if "page=1" in url else []).encode(), {}, url)

    settings = {
        **DEFAULTS["collection"],
        "content_chars": 8000,
        "lookback_days": 14,
        "dirauth_gitlab_users": ["linus"],
        "tor_core_gitlab_users": ["gk", "linus", "custom_core"],
    }
    collected = collect.collect_source(_Client(), gitlab_source(), {}, settings, "2026-11-10T12:00:00Z")["items"]
    assert [entry["authority"] for entry in collected] == ["tor-core", "dirauth-operator", "tor-core"]


def test_trove_cve_extraction_tor_core_and_mandatory_news_predicates():
    """Verify TROVE/CVE extraction, tor-core promotion, release detection, and mandatory rules."""
    assert {"gk", "linus", "shelikhoo", "eta", "arma", "nickm", "dgoulet"} <= set(DEFAULT_TOR_CORE_USERS)
    assert tor_core_user_set([" GK ", ""]) == {"gk"}

    issue = _story_item(
        title="Fix crash (trove-2026-001)",
        content="Tracks CVE-2026-12345 and TROVE-2026-001 mitigation.",
        public_comments=[{"author": "gk", "created_at": DATE, "url": "https://example.org/n/1", "body": "Also CVE-2026-99999 and TROVE-2026-002"}],
        author="outsider",
    )
    assert trove_ids(issue) == ["TROVE-2026-001"]
    assert cve_ids(issue) == ["CVE-2026-12345", "CVE-2026-99999"]
    assert is_trove_item(issue) is True
    assert is_tor_core_item(issue) is True
    assert effective_authority(issue) == "tor-core"
    assert mandatory_news_rule(issue) == "trove"

    comm_trove = _story_item(
        kind="feed",
        authority="community",
        url="https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/message/M1/",
        title="Question about TROVE-2026-001",
        content="Community member asks about TROVE-2026-001.",
        public_comments=[],
    )
    assert is_trove_item(comm_trove) is False
    assert mandatory_news_rule(comm_trove) is None

    comment_only_trove = _story_item(
        title="Parser crash in relay module",
        content="Details of parser crash.",
        public_comments=[{"author": "outsider", "created_at": DATE, "url": "https://example.org/n/2", "body": "Mentions TROVE-2026-003"}],
        author="outsider",
    )
    assert trove_ids(comment_only_trove) == []
    assert is_trove_item(comment_only_trove) is False

    rel_feed = {
        "kind": "feed",
        "authority": "official",
        "source_id": "tor-announce",
        "url": "https://lists.torproject.org/pipermail/tor-announce/2026/001.html",
        "title": "[tor-announce] Maintenance note",
        "content": "Release package note.",
    }
    blog_digest = {
        "kind": "feed",
        "authority": "official",
        "source_id": "tor-blog",
        "url": "https://blog.torproject.org/weekly-digest/",
        "title": "Community digest and monthly roundup",
        "content": "Summary of recent events.",
    }
    assert is_official_release_announcement(rel_feed) is True
    assert mandatory_news_rule(rel_feed) == "release_announcement"
    assert is_official_release_announcement(blog_digest) is False
    assert mandatory_news_rule(blog_digest) is None

    new_thread = {
        "kind": "feed",
        "authority": "project-sender",
        "url": "https://lists.torproject.org/mailman3/hyperkitty/list/tor-dev@lists.torproject.org/message/N1/",
        "title": "[tor-dev] Relay schedule",
        "content": "Opening a new discussion thread.",
    }
    reply_thread = {**new_thread, "title": "[tor-dev] Re: Relay schedule"}
    assert is_torproject_new_thread(new_thread) is True
    assert mandatory_news_rule(new_thread) == "torproject_new_thread"
    assert is_torproject_new_thread(reply_thread) is False
    assert mandatory_news_rule(reply_thread) is None


def test_trove_label_limits_analyzer_and_final_holds(tmp_path):
    """Force TROVE category to `security` while keeping valid multi-tag choices and holding mismatches."""
    trove_src = _story_item(
        title="Security advisory TROVE-2026-004",
        content="Verified TROVE-2026-004 relay denial-of-service fix.",
        author="gk",
    )
    limits = llm.label_limits([trove_src])
    assert limits["category"] == ["security"]
    assert set(limits["tags"]) == set(CATEGORIES)

    schema = copy.deepcopy(analyze.SCHEMA)
    llm.apply_label_limits(schema["properties"], limits)
    assert schema["properties"]["category"]["enum"] == ["security"]
    assert "enum" not in schema["properties"]["tags"]
    assert schema["properties"]["tags"]["items"]["enum"] == list(CATEGORIES)

    assert review.within_label_limits({"category": "security", "tags": ["security", "dos"]}, limits) is True
    assert review.within_label_limits({"category": "dos", "tags": ["dos"]}, limits) is False

    cfg = make_config(tmp_path)
    recorded_payloads = []

    class _RecordingAnalyzer(analyze.Analyzer):
        """Stub analyzer capturing bounded payloads sent to `complete`."""

        def complete(self, _prompt, payload, schema_obj, _schema_name):
            """Record bounded payload and assert schema enforces category=security."""
            recorded_payloads.append(payload)
            assert schema_obj["properties"]["category"]["enum"] == ["security"]
            return {
                "publish": True,
                "title": "Security advisory TROVE-2026-004 fixes relay crash",
                "summary": "A Tor advisory addresses TROVE-2026-004 relay crash.",
                "why_it_matters": "",
                "category": "security",
                "priority": "high",
                "confidence": "reported",
                "state": "developing",
                "products": ["tor"],
                "tags": ["security", "dos"],
                "evidence": ["Verified TROVE-2026-004 relay denial-of-service fix."],
            }

    analyzer_inst = _RecordingAnalyzer(cfg)
    analyzer_inst.analyze(trove_src)
    assert recorded_payloads[0]["authority"] == "tor-core"
    assert recorded_payloads[0]["mandatory_news_rule"] == "trove"

    with Store(tmp_path / "trove-hold.sqlite3") as store:
        row = pending(store, trove_src)
        bad_draft = _story_draft(
            title="TROVE-2026-004 relay crash",
            summary="A Tor advisory addresses TROVE-2026-004.",
            category="dos",
            tags=["dos"],
            evidence=["Verified TROVE-2026-004 relay denial-of-service fix."],
        )
        prep = store.prepare_candidate(row, bad_draft, LATER)
        assert prep["packet"]["sources"][0]["mandatory_news_rule"] == "trove"
        assert "trove_category" in review.final_holds(prep["candidate"], prep)

        approve_res = run_gate(cfg, store, row, Writer(bad_draft), Reviewer(verdict(), verdict()), LATER)
        assert approve_res["status"] == "held"
        assert decision_codes(store, row) == ["held.final_check.trove_category"]


def test_store_priority_ranking_and_trove_clustering(tmp_path):
    """Rank TROVE > HackerOne/Dirauth > Tor-core > Trusted-operator, and relate TROVE stories."""
    trove_issue = _story_item(url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/51001", title="Advisory TROVE-2026-010", content="Advisory notice.", author="gk")
    h1_issue = _story_item(url="https://hackerone.com/reports/51002", title="Plain bug", content="Plain text.", authority="hackerone")
    dir_issue = _story_item(url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/51003", title="Plain ticket", content="Plain text.", author="weasel")
    core_issue = _story_item(url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/51004", title="Plain core", content="Plain text.", author="gk")
    trusted_post = _story_item(kind="feed", url="https://lists.torproject.org/m/51005/", authority="trusted-operator", title="Plain op", content="Plain text.")
    dev_issue = _story_item(url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/51006", title="Plain dev", content="Plain text.", author="outsider")

    assert item_priority(trove_issue) == TROVE_PRIORITY + TOR_CORE_PRIORITY
    assert item_priority(h1_issue) == HACKERONE_PRIORITY
    assert item_priority(dir_issue) == DIRAUTH_PRIORITY
    assert item_priority(core_issue) == TOR_CORE_PRIORITY
    assert item_priority(trusted_post) == TRUSTED_OPERATOR_PRIORITY
    assert item_priority(dev_issue) == 0

    with Store(tmp_path / "cluster.sqlite3") as store:
        existing_story = seed_source_story(
            store,
            _story_item(
                url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/51010",
                title="Relay issue for TROVE-2026-020",
                content="Advisory TROVE-2026-020 details.",
            ),
            draft=analysis(
                title="Advisory TROVE-2026-020 fixes relay issue",
                summary="Details for TROVE-2026-020.",
                why_it_matters="",
                category="security",
                tags=["security"],
                evidence=["Advisory TROVE-2026-020 details."],
            ),
        )
        related_ann = {
            "id": "ann-trove",
            "url": "https://blog.torproject.org/trove-2026-020/",
            "title": "Follow-up on TROVE-2026-020",
            "content": "Further background on TROVE-2026-020.",
            "published_at": LATER,
            "updated_at": LATER,
        }
        rel = candidate_mod.related(store.db, {"id": "ann-trove"}, related_ann)
        assert (existing_story["id"], "references TROVE-2026-020") in rel
        assert review_gate._specific_story_overlap(
            {"title": "Story A", "summary": "Fixes TROVE-2026-020.", "products": ["tor"], "sources": []},
            {"title": "Story B", "summary": "Patch for TROVE-2026-020.", "products": ["tor"], "sources": []},
        )

        # commit_candidate rejects unbacked commits even when mandatory_news_rule is present
        trove_row = pending(store, trove_issue)
        good_draft = _story_draft(
            title="Advisory TROVE-2026-010",
            summary="Advisory notice for TROVE-2026-010.",
            category="security",
            tags=["security"],
            evidence=["Advisory notice."],
        )
        prep = store.prepare_candidate(trove_row, good_draft, LATER)
        with pytest.raises(ReviewRequired):
            store.commit_candidate(prep, prep["candidate"], "wk", LATER, approval_key="bad", policy_hash="p")


def test_mandatory_news_bypass_recency_exemption_and_cache_safety(tmp_path):
    """Override `news_value` skips cleanly for mandatory items while preserving duplicate skips and cache safety."""
    cfg = make_config(tmp_path)
    trove_old = _story_item(
        url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/52001",
        title="Delayed disclosure TROVE-2026-030",
        content="Advisory TROVE-2026-030 disclosed after embargo.",
        published_at="2026-08-01T12:00:00Z",
        updated_at=LATER,
        author="outsider",
    )
    trove_draft = _story_draft(
        title="Delayed disclosure TROVE-2026-030",
        summary="Advisory TROVE-2026-030 addresses an embargoed issue.",
        category="security",
        tags=["security"],
        evidence=["Advisory TROVE-2026-030 disclosed after embargo."],
    )
    rel_ann = {
        "source_id": "tor-announce",
        "kind": "feed",
        "authority": "official",
        "product": "tor",
        "url": "https://lists.torproject.org/pipermail/tor-announce/2026/002.html",
        "title": "[RELEASE] Tor 0.4.9.99 is released",
        "content": "Tor 0.4.9.99 is now available with relay fixes.",
        "published_at": DATE,
        "updated_at": DATE,
    }
    rel_draft = _story_draft(
        title="Tor 0.4.9.99 released",
        summary="Tor 0.4.9.99 is now available with relay fixes.",
        category="release",
        confidence="confirmed",
        state="released",
        tags=["release"],
        evidence=["Tor 0.4.9.99 is now available with relay fixes."],
    )
    new_list_post = {
        "source_id": "tor-dev",
        "kind": "feed",
        "authority": "project-sender",
        "url": "https://lists.torproject.org/mailman3/hyperkitty/list/tor-dev@lists.torproject.org/message/THREAD1/",
        "title": "[tor-dev] New policy",
        "content": "Opening a project discussion on relay requirements.",
        "published_at": DATE,
        "updated_at": DATE,
    }
    list_draft = _story_draft(
        title="Tor Project developer opens relay policy thread",
        summary="A project sender opens a discussion on relay requirements.",
        evidence=["Opening a project discussion on relay requirements."],
    )

    with Store(tmp_path / "mandatory.sqlite3") as store:
        skip_news = verdict("skip", criterion="news_value")
        # 1. Old TROVE bypasses _not_recent, overrides two news_value skips, and avoids caching a skip receipt
        r_trove = pending(store, trove_old, at=LATER, ready=LATER)
        res_trove = run_gate(cfg, store, r_trove, Writer(trove_draft), Reviewer(skip_news, skip_news), LATER)
        assert res_trove["status"] == "published" and res_trove["review_calls"] == 2
        assert decision_codes(store, r_trove) == ["published.new"]
        assert store.db.execute("SELECT COUNT(*) FROM review_approvals").fetchone()[0] == 0
        # Unbacked mandatory commit still raises ReviewRequired
        bare_row = pending(store, {**trove_old, "url": "https://gitlab.torproject.org/tpo/core/tor/-/work_items/52999", "id": "bare-trove"}, at=LATER, ready=LATER)
        bare_prep = store.prepare_candidate(bare_row, trove_draft, LATER)
        with pytest.raises(ReviewRequired):
            store.commit_candidate(bare_prep, bare_prep["candidate"], "wk", LATER, approval_key="bad", policy_hash="p")

        # 2. Release announcement overrides verification news_value veto after initial approve
        r_rel = pending(store, rel_ann)
        res_rel = run_gate(cfg, store, r_rel, Writer(rel_draft), Reviewer(verdict(), skip_news), DATE)
        assert res_rel["status"] == "published" and res_rel["review_calls"] == 2

        # 3. Short-subject torproject new thread is mandatory when new_information passes,
        # and stale cached skip receipts are evicted rather than honored
        r_thread = pending(store, new_list_post)
        prep_t = store.prepare_candidate(r_thread, list_draft, DATE)
        insert_approval(store, prep_t, policy=review.policy_hash(cfg), result=skip_news)
        res_thread = run_gate(cfg, store, r_thread, Writer(list_draft), Reviewer(skip_news, verdict()), DATE)
        assert res_thread["status"] == "published" and res_thread["cache_hit"] is False and res_thread["review_calls"] == 2

        # 4. Duplicate new_information fail still skips a mandatory item cleanly
        covered_id = digest(candidate_mod.story_cluster(rel_ann))[:24]
        seed_source_story(store, {**trove_old, "url": "https://example.org/dup-src", "id": "dup-seed", "title": "Covered", "content": "Covered base."})
        new_thread_dup = {
            **new_list_post,
            "url": "https://lists.torproject.org/mailman3/hyperkitty/list/tor-dev@lists.torproject.org/message/THREAD2/",
            "title": "[tor-dev] Repeat schedule",
        }
        r_dup = pending(store, new_thread_dup)
        res_dup = run_gate(
            cfg,
            store,
            r_dup,
            Writer(list_draft),
            Reviewer(verdict("skip", criterion="new_information", reason=f"Already covered in {covered_id}.")),
            DATE,
        )
        assert res_dup["status"] == "ignored" and res_dup["review_calls"] == 1
        assert decision_codes(store, r_dup) == ["skipped.review.new_information"]


def test_deterministic_pre_llm_skips_and_safety_guards(tmp_path):
    """Skip quoted-only replies, housekeeping, and covered duplicates before LLM calls without false positives."""
    cfg = make_config(tmp_path)
    list_base = "https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/message/"

    with Store(tmp_path / "skips.sqlite3") as store:
        # 1. Quoted-only mailing-list reply
        quoted = _story_item(
            kind="feed",
            authority="community",
            url=list_base + "QONLY1/",
            title="[tor-relays] Re: Consensus changes",
            content="On Sun, Nov 08, 2026 at 12:00 PM, alice wrote:\n\n> Previous message line one.",
        )
        r_q = pending(store, quoted)
        out_q = run_gate(cfg, store, r_q, Writer(), Reviewer(), LATER)
        assert out_q == {"status": "ignored", "writer_calls": 0, "review_calls": 0, "cache_hit": False}
        assert decision_codes(store, r_q) == ["skipped.gate.quoted_only"]

        # 2. Housekeeping pure acknowledgment (even after quoted history) + checklist/bump/typo titles
        ack = _story_item(
            kind="feed",
            authority="community",
            url=list_base + "ACK1/",
            title="[tor-relays] Re: Consensus changes",
            content="Me too, thanks!\n\nOn Sun, Nov 08, 2026, alice wrote:\n> Older text.",
        )
        r_ack = pending(store, ack)
        assert run_gate(cfg, store, r_ack, Writer(), Reviewer(), LATER)["writer_calls"] == 0
        assert decision_codes(store, r_ack) == ["skipped.gate.housekeeping"]

        for idx, title in enumerate((
            "Tor 0.4.9.10 release checklist",
            "chore: version bump Cargo.lock",
            "Minor typo in README guide",
        ), 1):
            hk = _story_item(
                url=f"https://gitlab.torproject.org/tpo/core/tor/-/work_items/5300{idx}",
                title=title,
                content="Routine repository housekeeping steps.",
                author="outsider",
            )
            r_hk = pending(store, hk)
            assert run_gate(cfg, store, r_hk, Writer(), Reviewer(), LATER)["writer_calls"] == 0
            assert decision_codes(store, r_hk) == ["skipped.gate.housekeeping"]

        # Safety: security-labeled chore/CVE/TROVE/torproject_new_thread must NOT skip at housekeeping gate
        sec_chore = _story_item(
            url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/53099",
            title="chore: fix CVE-2026-44444 in descriptor parser",
            content="Fixes CVE-2026-44444 regression.",
            labels=["Security"],
            author="outsider",
        )
        r_sec = pending(store, sec_chore)
        sec_draft = _story_draft(
            title="Fix for CVE-2026-44444 in descriptor parser",
            summary="Fixes CVE-2026-44444 in the descriptor parser.",
            category="security",
            tags=["security"],
            evidence=["Fixes CVE-2026-44444 regression."],
        )
        assert run_gate(cfg, store, r_sec, Writer(sec_draft), Reviewer(verdict(), verdict()), LATER)["status"] == "published"

        # 3. Covered duplicate GitLab issue skips before LLM calls; "not a duplicate" or uncovered ref does NOT skip
        orig_url = "https://gitlab.torproject.org/tpo/core/tor/-/work_items/54001"
        seed_source_story(
            store,
            _story_item(url=orig_url, title="Descriptor stall fix", content="Tracks #54001 stall fix."),
            draft=_story_draft(title="Descriptor stall fix", summary="Tracks #54001 stall fix.", evidence=["Tracks #54001 stall fix."]),
        )
        dup_issue = _story_item(
            url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/54002",
            title="Same descriptor crash",
            content="Closing: duplicate of #54001.",
            upstream_state="closed",
            author="outsider",
        )
        r_dup = pending(store, dup_issue)
        out_dup = run_gate(cfg, store, r_dup, Writer(), Reviewer(), LATER)
        assert out_dup == {"status": "ignored", "writer_calls": 0, "review_calls": 0, "cache_hit": False}
        assert decision_codes(store, r_dup) == ["skipped.gate.duplicate_issue"]

        not_dup = _story_item(
            url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/54003",
            title="Distinct relay parser defect",
            content="Investigated carefully; this is not a duplicate of #54001 and exposes a new crash.",
            author="outsider",
        )
        r_nd = pending(store, not_dup)
        nd_draft = _story_draft(
            title="Distinct relay parser defect",
            summary="Exposes a distinct relay parser defect unrelated to #54001.",
            evidence=["exposes a new crash."],
        )
        assert run_gate(cfg, store, r_nd, Writer(nd_draft), Reviewer(verdict(), verdict()), LATER)["status"] == "published"


def test_narrower_official_not_news_skips_tor_core_project_replies_and_non_dirauth_tickets(tmp_path):
    """Skip non-mandatory `tor-core`, `project-sender` replies, and unrelated dirauth-author issues on `news_value` fail."""
    cfg = make_config(tmp_path)
    skip_news = verdict("skip", criterion="news_value")

    with Store(tmp_path / "narrow.sqlite3") as store:
        # 1. tor-core routine issue failing news_value -> skip cleanly
        core_item = _story_item(
            url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/55001",
            title="Refactor internal helper naming",
            content="Refactors internal helper variable naming for clarity.",
            author="gk",
        )
        r_core = pending(store, core_item)
        out_core = run_gate(
            cfg, store, r_core,
            Writer(_story_draft(evidence=["Refactors internal helper variable naming for clarity."])),
            Reviewer(skip_news), LATER,
        )
        assert out_core["status"] == "ignored" and out_core["review_calls"] == 1
        assert decision_codes(store, r_core) == ["skipped.review.news_value"]

        # 2. project-sender reply failing news_value -> skip cleanly
        ps_reply = {
            "source_id": "tor-relays",
            "kind": "feed",
            "authority": "project-sender",
            "url": "https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/message/PSREPLY1/",
            "title": "[tor-relays] Re: Monthly check-in",
            "content": "Follow-up reply noting schedule availability.",
            "published_at": DATE,
            "updated_at": DATE,
        }
        r_ps = pending(store, ps_reply)
        out_ps = run_gate(
            cfg, store, r_ps,
            Writer(_story_draft(evidence=["Follow-up reply noting schedule availability."])),
            Reviewer(skip_news), LATER,
        )
        assert out_ps["status"] == "ignored" and out_ps["review_calls"] == 1
        assert decision_codes(store, r_ps) == ["skipped.review.news_value"]

        # 3. dirauth author on non-dirauth-operational issue -> skip cleanly (no hold!)
        non_op_dirauth = _story_item(
            url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/55002",
            title="Clean up internal test helper",
            content="Simplifies unit test fixture construction inside local harness.",
            author="linus",
            labels=[],
        )
        r_nonop = pending(store, non_op_dirauth)
        out_nonop = run_gate(
            cfg, store, r_nonop,
            Writer(_story_draft(evidence=["Simplifies unit test fixture construction inside local harness."])),
            Reviewer(skip_news), LATER,
        )
        assert out_nonop["status"] == "ignored" and out_nonop["review_calls"] == 1
        assert decision_codes(store, r_nonop) == ["skipped.review.news_value"]

        # 4. dirauth-operational issue still holds as official_not_news
        op_dirauth = _story_item(
            url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/55003",
            title="Authority consensus timing note",
            content="Minor timing observation on consensus vote interval.",
            author="linus",
            labels=["Directory Authority (dirauth)"],
        )
        r_op = pending(store, op_dirauth)
        out_op = run_gate(
            cfg, store, r_op,
            Writer(_story_draft(evidence=["Minor timing observation on consensus vote interval."])),
            Reviewer(skip_news, skip_news), LATER,
        )
        assert out_op["status"] == "held" and out_op["review_calls"] == 2
        assert decision_codes(store, r_op) == ["held.verification.official_not_news"]


def test_comments_compose_and_enrich_recompute_tor_core(tmp_path):
    """Promote and demote `tor-core` via public comments in `_compose` and `enrich_comments`."""
    issue_url = "https://gitlab.torproject.org/tpo/core/tor/-/work_items/56001"
    base = _story_item(
        url=issue_url,
        title="Relay connection scheduling analysis",
        content="Investigates relay scheduler latency.",
        author="outsider",
        public_comments=[],
    )
    core_note = make_note(1, "Confirmed on main relay build.", author="gk", url=issue_url)
    promoted = comments._compose(base, [core_note], LATER, source_key="k1", tor_core_users=["gk"])
    assert promoted["authority"] == "tor-core"

    demoted = comments._compose(promoted, [], LATER, source_key="k1", tor_core_users=["gk"])
    assert demoted["authority"] == "development"

    h1_promoted = comments._compose(
        {**base, "authority": "hackerone"}, [core_note], LATER, source_key="k1", tor_core_users=["gk"]
    )
    assert h1_promoted["authority"] == "hackerone"

    cfg = make_config(tmp_path, sources=[gitlab_source()], comments={"enabled": True})
    cfg["collection"]["tor_core_gitlab_users"] = ["custom_core_dev"]
    gql_reply = gql_notes_response(
        [gql_note("11", "Confirmed core reproduction details.", author="custom_core_dev", iid="56001", url=issue_url)],
        iid="56001",
    )
    with Store(tmp_path / "comments-core.sqlite3") as store:
        store.ingest(dict(base), DATE)
        rep = enrich_with_client(cfg, store, FakeClient([gql_reply]), LATER)
        assert rep["checked"] == 1 and rep["changed"] == 1
        row = store.db.execute("SELECT priority_score, CAST(payload AS BLOB) FROM items WHERE url=?", (issue_url,)).fetchone()
        saved = json.loads(row[1])
        assert saved["authority"] == "tor-core"
        assert row[0] == TOR_CORE_PRIORITY


def test_deterministic_skip_operator_retry_short_quoted_arma_and_security_dup(tmp_path):
    """Honor operator retries, skip <8-char quoted replies & arma chores, and protect security duplicates."""
    cfg = make_config(tmp_path)
    list_base = "https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/message/"

    with Store(tmp_path / "edge-skips.sqlite3") as store:
        # 1. Operator retry bypasses deterministic fast-skip gates
        retry_hk = _story_item(
            url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/57001",
            title="chore: minor typo check",
            content="Routine wording fix.",
            author="outsider",
        )
        store.ingest(retry_hk, DATE)
        with store.db:
            store.db.execute(
                "UPDATE items SET status='rejected', last_error='Held previously' WHERE id=?",
                (retry_hk["id"],),
            )
        r_hk = item_row(store, retry_hk)
        assert rejection.retry_item(store, retry_hk["id"], r_hk["content_hash"], "Operator wants LLM check")["status"] == "pending"
        retried_row = item_row(store, retry_hk)
        out_retried = run_gate(
            cfg, store, retried_row,
            Writer(_story_draft(evidence=["Routine wording fix."])),
            Reviewer(verdict("skip", criterion="news_value")), LATER,
        )
        assert out_retried["writer_calls"] == 1 and out_retried["review_calls"] == 1
        assert decision_codes(store, retried_row) == ["operator.retried", "skipped.review.news_value"]

        # 2. Quoted list reply with < MIN_EVIDENCE_CHARS of unquoted text skips as quoted_only
        for suffix, short_text in (("QSHORT1/", "+1"), ("QSHORT2/", "ok")):
            short_q = _story_item(
                kind="feed",
                authority="community",
                url=list_base + suffix,
                title="[tor-relays] Re: Consensus timing",
                content=f"{short_text}\n\nOn Sun, Nov 08, 2026 at 12:00 PM, alice wrote:\n> Original detailed post.",
            )
            rq = pending(store, short_q)
            out_q = run_gate(cfg, store, rq, Writer(), Reviewer(), LATER)
            assert out_q == {"status": "ignored", "writer_calls": 0, "review_calls": 0, "cache_hit": False}
            assert decision_codes(store, rq) == ["skipped.gate.quoted_only"]

        # 3. Dirauth author housekeeping (non-operational) skips cleanly; dirauth-operational stays protected
        for idx, title in enumerate((
            "forward-port 0.4.9.12 through 0.4.9.17 changelogs",
            "clean up comments from recent commits",
        ), 1):
            arma_chore = _story_item(
                url=f"https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/5710{idx}",
                title=title,
                content="Merges release branch changelog entries cleanly.",
                author="arma",
                labels=[],
            )
            ra = pending(store, arma_chore)
            assert run_gate(cfg, store, ra, Writer(), Reviewer(), LATER)["writer_calls"] == 0
            assert decision_codes(store, ra) == ["skipped.gate.housekeeping"]

        arma_op = _story_item(
            url="https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/57199",
            title="clean up comments in consensus vote parser",
            content="Updates dirauth consensus voting comments.",
            author="arma",
            labels=[],
        )
        rop = pending(store, arma_op)
        assert run_gate(
            cfg, store, rop,
            Writer(_story_draft(evidence=["Updates dirauth consensus voting comments."])),
            Reviewer(verdict(), verdict()), LATER,
        )["status"] == "published"

        # 4. Duplicate issue guards: vulnerability wording & Security label do NOT fast-skip; status::duplicate DOES skip
        orig_url = "https://gitlab.torproject.org/tpo/core/tor/-/work_items/57201"
        seed_source_story(
            store,
            _story_item(url=orig_url, title="Relay crash handling", content="Tracks #57201 relay crash."),
            draft=_story_draft(title="Relay crash handling", summary="Tracks #57201 relay crash.", evidence=["Tracks #57201 relay crash."]),
        )
        vuln_dup = _story_item(
            url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/57202",
            title="Relay cell crash report",
            content="Closing: duplicate of #57201 after reproducing NULL pointer dereference.",
            upstream_state="closed",
            author="outsider",
        )
        r_vuln = pending(store, vuln_dup)
        assert run_gate(
            cfg, store, r_vuln,
            Writer(_story_draft(evidence=["NULL pointer dereference."])),
            Reviewer(verdict(), verdict()), LATER,
        )["status"] == "published"

        sec_label_dup = _story_item(
            url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/57203",
            title="Duplicate security ticket",
            content="See #57201.",
            labels=["Security", "status::duplicate"],
            upstream_state="closed",
            author="outsider",
        )
        r_sec_dup = pending(store, sec_label_dup)
        assert run_gate(
            cfg, store, r_sec_dup,
            Writer(_story_draft(evidence=["See #57201."])),
            Reviewer(verdict(), verdict()), LATER,
        )["status"] == "published"

        status_dup = _story_item(
            url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/57204",
            title="Repeated build flag report",
            content="Same question as #57201.",
            labels=["status::duplicate"],
            upstream_state="closed",
            author="outsider",
        )
        r_status_dup = pending(store, status_dup)
        assert run_gate(cfg, store, r_status_dup, Writer(), Reviewer(), LATER)["writer_calls"] == 0
        assert decision_codes(store, r_status_dup) == ["skipped.gate.duplicate_issue"]


def test_mandatory_revise_verification_paths_and_legacy_review_job_compat(tmp_path):
    """Approve mandatory revise->skip(news_value) with refs, hold empty refs or new_information, and tolerate legacy jobs."""
    cfg = make_config(tmp_path)
    base_thread = {
        "source_id": "tor-dev",
        "kind": "feed",
        "authority": "project-sender",
        "title": "[tor-dev] Relay advisory discussion",
        "content": "Project sender announces new relay measurement guidance.",
        "published_at": DATE,
        "updated_at": DATE,
    }
    draft = _story_draft(
        title="Project announces relay measurement guidance",
        summary="A project sender outlines updated relay measurement guidance.",
        evidence=["Project sender announces new relay measurement guidance."],
    )
    revise_v = verdict("revise", repair={"summary": "Revised relay measurement guidance from project sender."})
    skip_nv = verdict("skip", criterion="news_value")
    skip_nv_no_refs = verdict("skip", criterion="news_value", criteria={"source_support": {"source_refs": []}})
    skip_ni = verdict("skip", criterion="new_information")

    with Store(tmp_path / "mandatory-revise.sqlite3") as store:
        # 1. revise -> verification skip(news_value) with source_refs auto-approves mandatory thread
        r1 = pending(store, {**base_thread, "url": "https://lists.torproject.org/mailman3/hyperkitty/list/tor-dev@lists.torproject.org/message/MR1/"})
        res1 = run_gate(cfg, store, r1, Writer(draft), Reviewer(revise_v, skip_nv), DATE)
        assert res1["status"] == "published" and res1["review_calls"] == 2
        assert decision_codes(store, r1) == ["published.new"]

        # 2. revise -> verification skip(news_value) with empty source_refs holds (model_hold)
        r2 = pending(store, {**base_thread, "url": "https://lists.torproject.org/mailman3/hyperkitty/list/tor-dev@lists.torproject.org/message/MR2/"})
        res2 = run_gate(cfg, store, r2, Writer(draft), Reviewer(revise_v, skip_nv_no_refs), DATE)
        assert res2["status"] == "held" and res2["review_calls"] == 2
        assert decision_codes(store, r2) == ["held.verification.model_hold"]

        # 3. revise -> verification skip(new_information) disagrees with initial revise -> disagreed_news hold
        r3 = pending(store, {**base_thread, "url": "https://lists.torproject.org/mailman3/hyperkitty/list/tor-dev@lists.torproject.org/message/MR3/"})
        res3 = run_gate(cfg, store, r3, Writer(draft), Reviewer(revise_v, skip_ni), DATE)
        assert res3["status"] == "held" and res3["review_calls"] == 2
        assert decision_codes(store, r3) == ["held.verification.disagreed_news"]

        # 4. Legacy review_jobs row lacking `tor_core_users` in envelope/prepared runs cleanly without damaged_job
        r4 = pending(store, _story_item(url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/58001", author="outsider"))
        run_gate(cfg, store, r4, Writer(draft), Reviewer(revise_v, verdict("hold")), LATER)
        job_row = store.db.execute("SELECT envelope_json, record_json FROM review_jobs WHERE item_id=?", (r4["id"],)).fetchone()
        env_obj = json.loads(job_row[0])
        rec_obj = json.loads(job_row[1])
        env_obj.pop("tor_core_users", None)
        rec_obj["prepared"].pop("tor_core_users", None)
        rec_obj["reviews"] = rec_obj["reviews"][:1]
        rec_obj["request_budget"]["reserved"] = 1
        rec_obj.pop("outcome", None)
        rec_obj.pop("hold_code", None)
        rec_obj.pop("hold_reason", None)
        with store.db:
            store.db.execute("UPDATE items SET status='pending', attempts=0 WHERE id=?", (r4["id"],))
            store.db.execute(
                "UPDATE review_jobs SET stage='verify', envelope_json=?, record_json=? WHERE item_id=?",
                (json.dumps(env_obj), json.dumps(rec_obj), r4["id"]),
            )
        assert review_gate.approval(cfg, store, r4["id"])["eligible"] is False
        requeued = item_row(store, r4)
        res4 = run_gate(cfg, store, requeued, Writer(draft), Reviewer(verdict(), verdict()), LATER)
        assert res4["status"] == "published"
