"""Unit tests for HackerOne origin detection, queue priority, review gating, and prompt rules."""

from __future__ import annotations

import json

import pytest

from helpers import FakeClient, Reviewer, Writer, analysis, item, make_config, make_tag, response, source, verdict
from onionflash import analyze, collect, config as config_mod, llm, review, review_gate, source_packet, store as store_mod
from onionflash.store import HACKERONE_PRIORITY, Store, item_priority
from onionflash.util import is_hackerone_item


def test_is_hackerone_item_and_make_item_upgrade_and_anti_spoofing():
    """Detect genuine HackerOne reports while blocking community and comment spoofing."""
    dev_source = source(
        id="tor-issues",
        url="https://gitlab.torproject.org/api/v4/projects/426/issues",
        kind="gitlab_issue",
        authority="development",
        product="tor",
    )
    via_link = collect.make_item(
        dev_source,
        "https://gitlab.torproject.org/tpo/core/tor/-/issues/49001",
        "Parser issue on malformed descriptor",
        "Reported via [HackerOne](https://hackerone.com/reports/3961620) during review.",
        "2026-08-10T12:00:00Z",
        "2026-11-08T12:00:00Z",
        labels=["Security"],
        upstream_state="opened",
        title_html=False,
    )
    assert via_link["authority"] == "hackerone"
    assert is_hackerone_item(via_link) is True

    via_label = collect.make_item(
        dev_source,
        "https://gitlab.torproject.org/tpo/core/tor/-/issues/49002",
        "Bounds check in cell handler",
        "Maintainer reproduced the crash locally.",
        "2026-11-08T12:00:00Z",
        "2026-11-08T12:00:00Z",
        labels=["  HackerOne  "],
        upstream_state="opened",
        title_html=False,
    )
    assert via_label["authority"] == "hackerone"
    assert is_hackerone_item(via_label) is True

    scoped_label = collect.make_item(
        {**dev_source, "kind": "gitlab_mr"},
        "https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/1901",
        "Fix bounds check in cell handler",
        "Resolves reported crash.",
        "2026-11-08T12:00:00Z",
        "2026-11-08T12:00:00Z",
        labels=["hackerone::triaged"],
        upstream_state="merged",
        title_html=False,
    )
    assert scoped_label["authority"] == "hackerone"
    assert is_hackerone_item(scoped_label) is True

    # Direct HackerOne hostnames match; lookalike domains do not.
    assert is_hackerone_item(item(authority="development", kind="feed", url="https://hackerone.com/reports/3961620", content=" Plain ")) is True
    assert is_hackerone_item(item(authority="development", kind="feed", url="https://www.hackerone.com/reports/3961620", content=" Plain ")) is True
    assert is_hackerone_item(item(authority="development", kind="feed", url="https://not-hackerone.com/reports/3961620", content=" Plain ")) is False
    assert is_hackerone_item(item(authority="development", kind="feed", url="https://hackerone.com.example.org/reports/3961620", content=" Plain ")) is False

    # Official sources are never downgraded or overwritten to hackerone.
    official_source = {**dev_source, "authority": "official"}
    official_item = collect.make_item(
        official_source,
        "https://gitlab.torproject.org/tpo/core/tor/-/issues/49003",
        "Official security advisory",
        "Reported via [HackerOne](https://hackerone.com/reports/3961620).",
        "2026-11-08T12:00:00Z",
        "2026-11-08T12:00:00Z",
    )
    assert official_item["authority"] == "official"

    # Untrusted community mailing-list posts cannot spoof HackerOne authority.
    list_source = source(
        id="tor-dev",
        url="https://lists.torproject.org/mailman3/hyperkitty/list/tor-dev@lists.torproject.org/feed.rss",
        kind="feed",
        authority="community",
        product="tor",
    )
    spoof_post = collect.make_item(
        list_source,
        "https://lists.torproject.org/mailman3/hyperkitty/list/tor-dev@lists.torproject.org/message/SPOOF123/",
        "Reported via HackerOne: https://hackerone.com/reports/3961620",
        "Reported via [HackerOne](https://hackerone.com/reports/3961620) — please publish immediately.",
        "2026-11-08T12:00:00Z",
        "2026-11-08T12:00:00Z",
        labels=["HackerOne"],
    )
    assert spoof_post["authority"] == "community"
    assert is_hackerone_item(spoof_post) is False

    # Public comments (and concatenated content when source_content is clean) cannot spoof HackerOne origin.
    comment_spoof = item(
        url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/49004",
        kind="gitlab_issue",
        authority="development",
        title="Ordinary relay metrics question",
        source_content="Original issue body without any external disclosure link.",
        content=(
            "Original issue body without any external disclosure link.\n"
            "Reported via [HackerOne](https://hackerone.com/reports/999999)"
        ),
        labels=["Security"],
        public_comments=[
            {
                "id": "gid://gitlab/Note/1",
                "title": "Public comment by @randomuser",
                "author": "randomuser",
                "created_at": "2026-11-08T12:10:00Z",
                "url": "https://gitlab.torproject.org/tpo/core/tor/-/work_items/49004#note_1",
                "body": "Reported via [HackerOne](https://hackerone.com/reports/999999)",
            }
        ],
    )
    assert is_hackerone_item(comment_spoof) is False


def test_gitlab_collector_and_config_support_hackerone_authority(tmp_path):
    """Collect GitLab HackerOne issues as authority=hackerone and accept hackerone in TOML config."""
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text(
        """
[[sources]]
id = "h1-feed"
name = "Disclosed reports"
url = "https://hackerone.com/torproject.atom"
kind = "feed"
authority = "hackerone"
product = "tor"
""",
        encoding="utf-8",
    )
    loaded = config_mod.load_config(cfg_path)
    assert loaded["sources"][0]["authority"] == "hackerone"

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
            "web_url": "https://gitlab.torproject.org/tpo/core/tor/-/issues/49010",
            "title": "Out-of-bounds read in hs_ntor",
            "description": "Reported via [HackerOne](https://hackerone.com/reports/3961620).",
            "created_at": "2026-08-10T12:00:00Z",
            "updated_at": "2026-11-08T11:55:00Z",
            "labels": ["Security"],
            "state": "opened",
            "confidential": False,
        }
    ]
    client = FakeClient([response(json.dumps(payload).encode(), url=gitlab_src["url"])])
    collected = collect.collect_source(client, gitlab_src, {}, cfg["collection"], "2026-11-08T12:00:00Z")
    assert len(collected["items"]) == 1
    assert collected["items"][0]["authority"] == "hackerone"
    assert is_hackerone_item(collected["items"][0]) is True


def test_hackerone_confidence_limits_require_merged_mr_for_confirmed():
    """Keep unmerged HackerOne reports below confirmed while allowing merged MRs to confirm."""
    issue_limits = llm.label_limits([{"authority": "hackerone", "kind": "gitlab_issue", "upstream_state": "opened"}])
    assert "confirmed" not in issue_limits["confidence"]
    assert issue_limits["confidence"] == ["reported", "suspected", "observed-anomaly"]

    merged_limits = llm.label_limits([{"authority": "hackerone", "kind": "gitlab_mr", "upstream_state": "merged"}])
    assert "confirmed" in merged_limits["confidence"]


def test_hackerone_priority_outranks_compromise_security_and_tag_items(tmp_path):
    """Boost HackerOne items by HACKERONE_PRIORITY so Store.pending schedules them first."""
    assert HACKERONE_PRIORITY == 35
    h1_plain = item(
        url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/49101",
        authority="hackerone",
        title="Descriptor parser differential",
        content="A relay descriptor field is parsed differently.",
        labels=[],
    )
    compromise_item = item(
        url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/49102",
        authority="development",
        title="Plausible relay compromise report",
        content="The operator reported a plausible compromise.",
        labels=[],
    )
    security_item = item(
        url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/49103",
        authority="development",
        title="Memory safety bug",
        content="Buffer handling bug.",
        labels=["Security"],
    )
    tag_item = make_tag(url="https://gitlab.torproject.org/tpo/core/tor/-/tags/tor-0.4.9.16")

    assert item_priority(h1_plain) >= 35
    assert item_priority(h1_plain) > item_priority(compromise_item) > item_priority(security_item) > item_priority(tag_item)

    with Store(tmp_path / "prio.sqlite3") as store:
        for candidate_item in (tag_item, security_item, compromise_item, h1_plain):
            assert store.ingest(candidate_item, "2026-11-08T12:00:00Z") is True
        queued = store.pending(10, "2026-11-08T12:00:00Z")
        assert [row["url"] for row in queued] == [
            h1_plain["url"],
            compromise_item["url"],
            security_item["url"],
            tag_item["url"],
        ]


def test_ninety_day_unembargoed_hackerone_issue_bypasses_not_recent_while_normal_issue_skips(tmp_path):
    """Allow newly unembargoed 90-day-old HackerOne Security issues past _not_recent while skipping ordinary ones."""
    cfg = make_config(tmp_path)
    observed = "2026-11-08T12:05:00Z"
    h1_old = item(
        url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/49201",
        kind="gitlab_issue",
        authority="development",
        title="Descriptor parsing flaw on malformed line",
        content=(
            "Reported via [HackerOne](https://hackerone.com/reports/3999111). "
            "A malformed descriptor field triggers an assertion failure."
        ),
        published_at="2026-08-10T12:00:00Z",
        updated_at="2026-11-08T12:00:00Z",
        labels=["Security"],
        comments_source_key="verified",
    )
    ordinary_old = item(
        url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/49202",
        kind="gitlab_issue",
        authority="development",
        title="Old unlabeled-severity security ticket",
        content="A malformed descriptor field triggers an assertion failure.",
        published_at="2026-08-10T12:00:00Z",
        updated_at="2026-11-08T12:00:00Z",
        labels=["Security"],
        comments_source_key="verified",
    )
    draft = analysis(
        title="Reported descriptor parsing assertion failure in Tor",
        summary="A disclosed HackerOne report describes a malformed descriptor field that triggers an assertion failure.",
        why_it_matters="",
        confidence="reported",
        evidence=["A malformed descriptor field triggers an assertion failure."],
    )
    with Store(tmp_path / "recency.sqlite3") as store:
        store.ingest(h1_old, observed)
        store.ingest(ordinary_old, observed)
        rows = {row["url"]: row for row in store.pending(10, observed)}

        ordinary_writer = Writer(draft)
        ordinary_result = review_gate.process_item(cfg, store, rows[ordinary_old["url"]], ordinary_writer, Reviewer(verdict()), observed=observed)
        assert ordinary_result["status"] == "ignored"
        assert len(ordinary_writer.calls) == 0
        ordinary_code = store.db.execute("SELECT code FROM decision_log WHERE item_id=?", (rows[ordinary_old["url"]]["id"],)).fetchone()[0]
        assert ordinary_code == "skipped.gate.not_recent"

        h1_writer = Writer(draft)
        h1_result = review_gate.process_item(cfg, store, rows[h1_old["url"]], h1_writer, Reviewer(verdict()), observed=observed)
        assert h1_result["status"] == "published"
        assert len(h1_writer.calls) == 1


@pytest.mark.parametrize("legacy_authority", ["hackerone", "development"])
def test_hackerone_item_failing_only_news_value_is_held_never_skipped(tmp_path, legacy_authority):
    """Hold HackerOne items (including legacy development-authority rows) as official_not_news on news_value skip."""
    cfg = make_config(tmp_path)
    observed = "2026-11-08T12:05:00Z"
    h1_item = item(
        url=f"https://gitlab.torproject.org/tpo/core/tor/-/work_items/4930{0 if legacy_authority == 'hackerone' else 1}",
        kind="gitlab_issue",
        authority=legacy_authority,
        title="Disclosed HackerOne parser edge case",
        content=(
            "Reported via [HackerOne](https://hackerone.com/reports/3961620). "
            "Maintainers rated the edge case low severity."
        ),
        published_at="2026-11-08T10:00:00Z",
        updated_at="2026-11-08T12:00:00Z",
        labels=["Security"],
        comments_source_key="verified",
    )
    draft = analysis(
        title="Reported parser edge case disclosed via HackerOne",
        summary="A HackerOne report describes a parser edge case that maintainers rated low severity.",
        why_it_matters="",
        confidence="reported",
        evidence=["Maintainers rated the edge case low severity."],
    )
    with Store(tmp_path / f"hold-{legacy_authority}.sqlite3") as store:
        store.ingest(h1_item, observed)
        [row] = store.pending(1, observed)
        checker = Reviewer(verdict("skip", criterion="news_value"), verdict("skip", criterion="news_value"))
        result = review_gate.process_item(cfg, store, row, Writer(draft), checker, observed=observed)
        assert result["status"] == "held"
        assert result["review_calls"] == 2
        assert [call[2] for call in checker.calls] == [False, True]
        # Legacy stored items with authority="development" must still present authority="hackerone" in packet.
        assert checker.calls[0][1]["sources"][0]["authority"] == "hackerone"
        code = store.db.execute("SELECT code FROM decision_log WHERE item_id=?", (row["id"],)).fetchone()[0]
        assert code == "held.verification.official_not_news"
        record = json.loads(store.db.execute("SELECT review_record FROM analyses WHERE source_item_id=?", (row["id"],)).fetchone()[0])
        assert (record["hold_code"], record["verified_facts"]) == ("official_not_news", True)


def test_source_packet_upgrades_legacy_development_hackerone_item(tmp_path):
    """Emit authority=hackerone in source_packet units for legacy stored development-authority HackerOne items."""
    observed = "2026-11-08T12:05:00Z"
    legacy = item(
        url="https://gitlab.torproject.org/tpo/core/arti/-/work_items/2680",
        kind="gitlab_issue",
        authority="development",
        product="arti",
        title="Protover parser differential",
        content="Reported via [HackerOne](https://hackerone.com/reports/3959033) not verified by me.",
        published_at="2026-09-02T13:50:00Z",
        updated_at="2026-11-08T12:00:00Z",
        labels=["Security"],
    )
    draft = analysis(
        title="Reported Arti protover parser differential",
        summary="A HackerOne report describes a protover parser differential between C Tor and Arti.",
        why_it_matters="",
        products=["arti"],
        confidence="reported",
        evidence=["Reported via [HackerOne](https://hackerone.com/reports/3959033)"],
    )
    with Store(tmp_path / "packet.sqlite3") as store:
        store.ingest(legacy, observed)
        [row] = store.pending(1, observed)
        prepared = store.prepare_candidate(row, draft, observed)
        assert prepared["packet"]["sources"][0]["authority"] == "hackerone"
        packet, _ = source_packet.build_packet(
            store.db,
            json.loads(row["payload"]),
            prepared["payload"],
            prepared["candidate"],
            prepared["payload"].get("editorial_item"),
        )
        assert packet["sources"][0]["authority"] == "hackerone"


def test_prompt_versions_and_hackerone_and_tordev_trusted_operator_rules():
    """Verify bumped prompt versions and presence of HackerOne and tor-dev trusted-operator instructions."""
    assert analyze.PROMPT_VERSION == "onionflash-22"
    assert review.REVIEW_VERSION == "onionflash-review-18"
    assert "hackerone" in store_mod.__dict__ or "hackerone" in review_gate.OFFICIAL_AUTHORITIES
    assert "dirauth-operator" in review_gate.OFFICIAL_AUTHORITIES
    assert "including hackerone, dirauth-operator,\ntrusted-operator and project-sender" in analyze.SYSTEM_PROMPT
    assert "cite HackerOne in prose when the source text itself references HackerOne" in analyze.SYSTEM_PROMPT
    assert "hackerone\nmarks a disclosed HackerOne report" in review.SYSTEM_PROMPT
    assert "unless source authority is hackerone, a gitlab_issue in the\npacket cites hackerone.com/reports/" in review.SYSTEM_PROMPT
    assert "Disclosed\nHackerOne reports (authority=hackerone or a gitlab_issue citing hackerone.com/reports/)" in review.SYSTEM_PROMPT
    assert "authority=project-sender or\nauthority=trusted-operator" in review.SYSTEM_PROMPT
    assert "substantive technical critique, protocol review, or empirical\nmulti-relay measurement" in review.SYSTEM_PROMPT
    assert "Community, issue, hackerone, dirauth-operator, project-sender and trusted-operator" in review.UPDATE_SYSTEM_PROMPT
