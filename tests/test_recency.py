"""An item whose newest dated development is old cannot start a new story, whatever its updated_at says."""

import copy
import json

import pytest

from helpers import (
    FakeClient, Reviewer, Writer, analysis, decision_codes, decision_rows, editorial_act, gitlab_source,
    item, make_note, response, run_gate, seed_source_story, seed_story, source, verdict, wire_analyzer,
)
from onionflash import analyze, candidate, comments, editorial, rejection, review_gate
from onionflash.collect import collect_source
from onionflash.config import DEFAULTS
from onionflash.source_packet import build_packet, source_fingerprint
from onionflash.store import item_hash

ISSUES = "https://gitlab.torproject.org/tpo/core/tor/-/work_items/"
COLLECTED = "2026-11-11T15:00:00Z"
SKIPPED = "skipped.gate.not_recent"


def _verified(**fields):
    return item(comments_checked_at=COLLECTED, comments_source_key="key", **fields)


CROSS_CANCELLATION = _verified(
    url=ISSUES + "41412", title="Circuit cross-cancellation can still blame channels",
    content="Our fix for #41360, #41365, and #41366 prevents remotely-induced Guard rotation cases.",
    labels=["Security", "Severity::medium"], upstream_state="closed",
    published_at="2026-09-23T15:01:31Z", updated_at="2026-11-11T14:48:45Z", public_comments=[
        make_note(3476175, "Scheduled for making public in a week, on Oct 15.", author="arma",
                  created_at="2026-10-07T17:17:10Z", url=ISSUES + "41412"),
        make_note(3476174, "Closing the ticket because it is fixed in today's 0.4.9.14 release.", author="arma",
                  created_at="2026-10-07T17:16:54Z", url=ISSUES + "41412"),
    ])
CIRCUIT_FAILURES = _verified(
    url=ISSUES + "41420", title="Frequent Circuit Build Failures after 4.9.13 update.",
    content="Some of my tor instances becoming unreachable via all their onion services every day since 4.9.13 update.",
    labels=[], upstream_state="closed",
    published_at="2026-09-30T16:22:39Z", updated_at="2026-11-11T14:49:36Z", public_comments=[
        make_note(3477912, "Hi, I hope it's okay to ask questions here about the new 0.4.9.14 log entry added in !1057.",
                  author="legoktm", created_at="2026-10-14T14:52:35Z", url=ISSUES + "41420"),
        make_note(3476172, "I'm going to close this ticket, as we list it as being fixed in today's 0.4.9.14 release.",
                  author="arma", created_at="2026-10-07T17:14:17Z", url=ISSUES + "41420"),
    ])


def _process(cfg, store, writer=None, checker=None, observed=COLLECTED):
    return run_gate(cfg, store, store.pending(1, observed)[0], writer, checker, observed)


@pytest.mark.parametrize("incoming,developed", [(CROSS_CANCELLATION, "2026-10-07T17:17:10Z"),
                                                (CIRCUIT_FAILURES, "2026-10-14T14:52:35Z")])
def test_an_issue_edited_weeks_after_its_last_note_cannot_start_a_story(context, incoming, developed):
    """Skip issues edited weeks after their newest note and clear any stale held review jobs."""
    cfg, store = context
    cfg["comments"]["enabled"] = True
    cfg["sources"] = [gitlab_source(id="test")]
    earlier = {**copy.deepcopy(incoming), "content": incoming["content"] + " Earlier text.", "updated_at": developed}
    store.ingest(earlier, developed)
    _process(cfg, store, checker=Reviewer(verdict("hold")), observed=developed)
    assert rejection.show_item(store, earlier["id"])["final_review"]["stage"] == "held"
    store.ingest(copy.deepcopy(incoming), COLLECTED)
    writer, checker = Writer(), Reviewer()
    result = _process(cfg, store, writer, checker, "2026-11-11T15:05:00Z")
    assert result["status"] == "ignored" and result["writer_calls"] == result["review_calls"] == 0
    assert writer.calls == [] and checker.calls == []
    status, error, story = store.db.execute("SELECT status,last_error,story_id FROM items").fetchone()
    assert status == "ignored" and developed in error and story is None
    assert store.stories() == [] and store.db.execute("SELECT COUNT(*) FROM review_jobs").fetchone()[0] == 0
    assert store.db.execute("SELECT COUNT(*) FROM comment_cache").fetchone()[0] == 0
    assert rejection.show_item(store, earlier["id"])["final_review"] is None
    rows = decision_rows(store)
    assert [r["code"] for r in rows] == ["held.review.model_hold", SKIPPED]
    assert (rows[-1]["detail"]["developed_at"], rows[-1]["detail"]["collected_at"]) == (developed, COLLECTED)


def test_a_fresh_public_comment_on_an_old_issue_reaches_review(context):
    """Allow an old issue with a fresh `public_comments` timestamp through the recency guard."""
    cfg, store = context
    fresh = make_note(7, "The keys were rotated today.", author="maintainer",
                      created_at="2026-11-11T14:40:00Z", url="https://example.org/news/1")
    store.ingest(_verified(published_at="2015-01-10T12:32:24Z", updated_at="2026-11-11T14:40:00Z", public_comments=[fresh]), COLLECTED)
    writer = Writer()
    assert _process(cfg, store, writer)["status"] == "published"
    assert len(writer.calls) == 1 and decision_codes(store) == ["published.new"]


def test_an_unverified_old_issue_gets_a_comment_check_and_a_fresh_note_queues_it_again(context):
    """Schedule a comment check on unverified old issues and requeue when a fresh note arrives."""
    cfg, store = context
    cfg["comments"]["enabled"] = True
    cfg["sources"] = [gitlab_source(id="test")]
    store.ingest(item(url=ISSUES + "1", published_at="2015-01-10T12:32:24Z", updated_at=COLLECTED), COLLECTED)
    row = store.pending(1, COLLECTED)[0]
    assert _process(cfg, store)["status"] == "ignored"
    checked, due = store.db.execute("SELECT checked_at,next_fetch_at FROM comment_cache WHERE item_id=?", (row["id"],)).fetchone()
    assert due <= checked
    later = "2026-11-11T15:10:00Z"
    fresh = [make_note(9, "Reopening: seen again.", author="maintainer", created_at="2026-11-11T14:45:00Z", url=ISSUES + "1")]
    saved = json.loads(store.db.execute("SELECT payload FROM items").fetchone()[0])
    assert store.ingest(comments._compose(saved, fresh, later, source_key=comments._source_key(cfg["sources"][0])), later)
    writer = Writer()
    _process(cfg, store, writer, Reviewer(verdict("skip", criterion="news_value")), later)
    assert len(writer.calls) == 1 and decision_codes(store) == [SKIPPED, "skipped.review.news_value"]
    for comments_on, source_on, suffix in ((False, True, "2"), (True, False, "3")):
        cfg["comments"]["enabled"] = comments_on
        cfg["sources"][0]["enabled"] = source_on
        store.ingest(item(url=ISSUES + suffix, published_at="2015-01-10T12:32:24Z", updated_at=COLLECTED), COLLECTED)
        row = store.pending(1, COLLECTED)[0]
        assert _process(cfg, store)["status"] == "ignored"
        assert store.db.execute("SELECT 1 FROM comment_cache WHERE item_id=?", (row["id"],)).fetchone() is None


def test_a_closed_issue_is_dated_by_its_closing_only_while_closed(context):
    """Use `closed_at` for recency only when `upstream_state == 'closed'`."""
    cfg, store = context
    store.ingest(item(url=ISSUES + "10", published_at="2015-01-10T12:32:24Z", updated_at=COLLECTED,
                      upstream_state="closed", closed_at="2026-11-11T14:30:00Z"), COLLECTED)
    writer = Writer()
    _process(cfg, store, writer, Reviewer(verdict("skip", criterion="news_value")))
    assert len(writer.calls) == 1
    store.ingest(item(url=ISSUES + "11", published_at="2015-01-10T12:32:24Z", updated_at=COLLECTED,
                      upstream_state="opened", closed_at="2026-11-11T14:30:00Z"), COLLECTED)
    assert _process(cfg, store)["status"] == "ignored"


@pytest.mark.parametrize(
    ("item_kw", "observed", "code"),
    [
        ({"kind": "gitlab_mr", "upstream_state": "merged", "labels": [], "published_at": "2026-11-11T14:50:00Z", "updated_at": "2026-11-11T14:50:31Z"}, COLLECTED, "skipped.review.news_value"),
        ({"kind": "gitlab_mr", "upstream_state": "merged", "labels": [], "published_at": "2026-10-20T14:32:27Z", "updated_at": "2026-11-11T14:50:31Z"}, COLLECTED, SKIPPED),
        ({"kind": "feed", "title": "Tor 0.4.9.16 is released", "published_at": "2026-11-04T19:53:47Z", "updated_at": "2026-11-04T19:53:47Z"}, "2026-11-04T20:00:00Z", "skipped.review.news_value"),
        ({"kind": "feed", "title": "Tor 0.4.9.16 is released", "published_at": "2026-09-01T00:00:00Z", "updated_at": "2026-11-04T19:53:47Z"}, "2026-11-04T20:00:00Z", SKIPPED),
    ],
)
def test_merges_and_posts_are_dated_by_event_time_not_last_edit(context, item_kw, observed, code):
    """Date merged MRs and feed posts by their merge/publication time rather than `updated_at`."""
    cfg, store = context
    store.ingest(item(**item_kw), observed)
    _process(cfg, store, checker=Reviewer(verdict("skip", criterion="news_value")), observed=observed)
    assert decision_codes(store) == [code]


def test_a_first_poll_of_a_new_source_skips_only_its_old_developments_and_pins_the_boundary(context):
    """Pin the 14-day recency boundary to the exact second on initial source collection."""
    cfg, store = context
    batch = {
        "recent": "2026-11-05T00:00:00Z", "inside": "2026-10-28T15:00:01Z", "exact": "2026-10-28T15:00:00Z",
        "outside": "2026-10-28T14:59:59Z", "ancient": "2016-01-27T17:17:19Z",
    }
    for name, published in batch.items():
        store.ingest(item(url="https://example.org/" + name, published_at=published, updated_at="2026-11-10T00:00:00Z"), COLLECTED)
    writer = Writer()
    for _ in batch:
        _process(cfg, store, writer, Reviewer(verdict("skip", criterion="news_value")))
    assert {r["detail"]["url"].rsplit("/", 1)[1]: r["code"] for r in decision_rows(store)} == {
        "recent": "skipped.review.news_value", "inside": "skipped.review.news_value",
        "exact": "skipped.review.news_value", "outside": SKIPPED, "ancient": SKIPPED,
    }
    assert len(writer.calls) == 3


def test_the_window_runs_from_collection_not_from_a_late_run(context):
    """Measure the recency window against `first_seen` collection time rather than late run time."""
    cfg, store = context
    store.ingest(item(published_at="2026-10-29T15:00:00Z", updated_at="2026-10-29T15:00:00Z"), COLLECTED)
    writer = Writer()
    _process(cfg, store, writer, Reviewer(verdict("skip", criterion="news_value")), "2026-11-20T00:00:00Z")
    assert len(writer.calls) == 1


def test_an_update_of_an_existing_story_still_reaches_review_and_a_locked_story_still_holds(context):
    """Bypass the new-story recency guard for updates to existing unlocked or locked stories."""
    cfg, store = context
    title = "Tor 0.4.9.16 is released"
    story_id = seed_story(store, item(kind="feed", url="https://example.org/announce", title=title),
                          analysis(), key="key", at=COLLECTED)["id"]
    store.ingest(item(kind="feed", url="https://example.org/old-post", title=title, content="Old post.",
                      published_at="2026-09-01T00:00:00Z", updated_at=COLLECTED), COLLECTED)
    # Seed an existing association; the test checks recency of known updates.
    with store.db:
        store.db.execute("UPDATE items SET story_id=? WHERE url=?",
                         (store.stories()[0]["id"], "https://example.org/old-post"))
    writer = Writer()
    _process(cfg, store, writer, Reviewer(verdict("skip", criterion="news_value")))
    assert len(writer.calls) == 1 and decision_codes(store)[-1] == "skipped.review.news_value"
    editorial_act(editorial.correct, store, story_id, {"why_it_matters": "Operator-reviewed wording."},
                  reason="Corrected wording.", observed=COLLECTED)
    store.ingest(item(kind="feed", url="https://example.org/old-post", title=title, content="Old post, edited.",
                      published_at="2026-09-01T00:00:00Z", updated_at=COLLECTED), COLLECTED)
    with store.db:
        store.db.execute("UPDATE items SET story_id=? WHERE url=?", (story_id, "https://example.org/old-post"))
    assert _process(cfg, store)["status"] == "locked"
    assert decision_codes(store)[-1] == "held.gate.story_locked"


def test_an_operator_retry_lets_that_exact_old_revision_reach_review(context):
    """Allow an operator-retried old revision through recency once while blocking subsequent edits."""
    cfg, store = context
    store.ingest(copy.deepcopy(CROSS_CANCELLATION), COLLECTED)
    _process(cfg, store)
    row = dict(store.db.execute("SELECT id,content_hash FROM items").fetchone())
    rejection.retry_item(store, row["id"], row["content_hash"], "Embargoed fix worth recording", COLLECTED)
    writer = Writer()
    _process(cfg, store, writer, Reviewer(verdict("skip", criterion="news_value")))
    assert len(writer.calls) == 1
    assert decision_codes(store) == [SKIPPED, "operator.reconsidered", "skipped.review.news_value"]
    edited = {**copy.deepcopy(CROSS_CANCELLATION), "content": CROSS_CANCELLATION["content"] + " Typo fix.",
              "updated_at": "2026-11-11T15:10:00Z"}
    assert store.ingest(edited, "2026-11-11T15:15:00Z")
    assert _process(cfg, store, observed="2026-11-11T15:15:00Z")["status"] == "ignored"


@pytest.mark.parametrize("kind,labels,reaches_review", [
    ("gitlab_issue", ["Security", "Severity::high"], True),
    ("gitlab_issue", [" security ", "severity::critical"], True),
    ("gitlab_issue", ["Security", "Severity::medium"], False),
    ("gitlab_issue", ["Security", "Severity::low"], False),
    ("gitlab_issue", ["Security"], False),
    ("gitlab_issue", ["Security", "Priority::High"], False),
    ("gitlab_issue", ["Security", "Apps::Impact::High"], False),
    ("gitlab_issue", ["Severity::critical"], False),
    ("gitlab_mr", ["Security", "Severity::critical"], False),
])
def test_only_a_high_or_critical_security_issue_bypasses_the_recency_guard(context, kind, labels, reaches_review):
    """Exempt only high/critical `Security` GitLab issues from the recency guard."""
    cfg, store = context
    store.ingest(_verified(kind=kind, labels=labels, published_at="2026-09-01T00:00:00Z", updated_at=COLLECTED), COLLECTED)
    writer = Writer()
    if reaches_review:
        result = _process(cfg, store, writer, Reviewer(verdict("skip", criterion="news_value")))
        assert result["status"] == "ignored" and len(writer.calls) == 1 and decision_codes(store) == ["skipped.review.news_value"]
    else:
        result = _process(cfg, store, writer)
        assert result["status"] == "ignored" and writer.calls == [] and decision_codes(store) == [SKIPPED]


def test_concurrent_item_change_during_recency_check_returns_stale(context):
    """Return `stale` without logging a decision if `content_hash` changes mid-recency check."""
    cfg, store = context
    store.ingest(copy.deepcopy(CROSS_CANCELLATION), COLLECTED)
    stale_row = store.pending(1, COLLECTED)[0]
    with store.db:
        store.db.execute("UPDATE items SET content_hash='changed' WHERE id=?", (stale_row["id"],))
    assert review_gate.process_item(cfg, store, stale_row, Writer(), Reviewer(), COLLECTED) == {
        "status": "stale", "writer_calls": 0, "review_calls": 0, "cache_hit": False}
    assert decision_rows(store) == []


def test_closed_issues_keep_their_closing_date_without_changing_hashes_or_writer_input(monkeypatch):
    """Store sanitized `closed_at` on closed issues without altering `item_hash` or writer prompts."""
    issues = gitlab_source()
    records = [{"web_url": ISSUES + str(n), "title": f"Report {n}", "description": "Body text long enough for literal evidence.",
                "state": state, "created_at": "2026-09-23T15:01:31Z", "updated_at": "2026-11-08T11:00:00Z", "closed_at": closed}
               for n, (state, closed) in enumerate([("closed", "2026-10-07T17:16:54Z"), ("closed", "not a date"),
                                                    ("closed", "2099-01-01T00:00:00Z"), ("opened", "2026-10-07T17:16:54Z")])]
    result = collect_source(FakeClient([response(json.dumps(records).encode())]), issues, {}, DEFAULTS["collection"], "2026-11-08T12:00:00Z")
    assert [entry.get("closed_at") for entry in result["items"]] == ["2026-10-07T17:16:54Z", None, "2026-11-08T12:00:00Z", None]
    mrs = source(kind="gitlab_mr", url="https://gitlab.torproject.org/api/v4/projects/426/merge_requests")
    mr_record = [{"web_url": "https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/1", "title": "Merge 1",
                  "description": "Body", "state": "merged", "created_at": "2026-09-23T15:01:31Z",
                  "merged_at": "2026-11-08T10:00:00Z", "updated_at": "2026-11-08T11:00:00Z", "closed_at": "2026-11-08T10:00:00Z"}]
    mr_items = collect_source(FakeClient([response(json.dumps(mr_record).encode())]), mrs, {}, DEFAULTS["collection"], "2026-11-08T12:00:00Z")["items"]
    assert "closed_at" not in mr_items[0]
    with_closed = result["items"][0]
    without_closed = {key: value for key, value in with_closed.items() if key != "closed_at"}
    assert item_hash(with_closed) == item_hash(without_closed)
    assert source_fingerprint(with_closed) == source_fingerprint(without_closed)
    assert analyze.cache_key({"content_hash": item_hash(with_closed)}, DEFAULTS["llm"]) == analyze.cache_key(
        {"content_hash": item_hash(without_closed)}, DEFAULTS["llm"])
    writer = wire_analyzer(
        monkeypatch,
        analysis(title="Report 0", summary="Body text long enough for literal evidence.", why_it_matters="",
                 confidence="reported", state="developing", evidence=["Body text long enough for literal evidence."]),
    )
    writer.analyze(with_closed)
    assert "closed_at" not in json.loads(writer.client.requests[0][1]["messages"][1]["content"])
    closed_item = {"id": "a" * 24, **with_closed}
    unclosed_item = {"id": "a" * 24, **without_closed}
    none_closed_item = {"id": "a" * 24, **without_closed, "closed_at": None}
    refs = {"sources": [{"id": closed_item["id"], "url": closed_item["url"]}]}
    closed_packet, closed_bindings = build_packet(None, closed_item, refs, {"sources": []}, closed_item["id"])
    unclosed_packet, unclosed_bindings = build_packet(None, unclosed_item, refs, {"sources": []}, unclosed_item["id"])
    none_packet, _ = build_packet(None, none_closed_item, refs, {"sources": []}, none_closed_item["id"])
    assert closed_packet["sources"][0]["closed_at"] == "2026-10-07T17:16:54Z"
    assert "closed_at" not in unclosed_packet["sources"][0] and "closed_at" not in none_packet["sources"][0]
    assert closed_bindings == unclosed_bindings


def test_old_closed_security_duplicate_attaches_and_bypasses_not_recent_while_uncovered_skips(context):
    """Attach old closed `Security` duplicates via `duplicate_ref` while skipping uncovered old tickets."""
    cfg, store = context
    canon_url = ISSUES + "41240"
    canon = seed_source_story(
        store,
        _verified(
            url=canon_url,
            labels=["Security"],
            title="Canonical security issue",
            content="Tracks #41240 security defect.",
            published_at="2026-08-01T00:00:00Z",
            updated_at="2026-11-05T00:00:00Z",
        ),
        at=COLLECTED,
    )
    old_sec_dup = _verified(
        url=ISSUES + "41244",
        labels=["Security", "Severity::medium"],
        upstream_state="closed",
        closed_at="2026-09-01T00:00:00Z",
        published_at="2026-08-01T00:00:00Z",
        updated_at=COLLECTED,
        title="Duplicate security issue",
        content="Closed as a duplicate of #41240.",
    )
    store.ingest(old_sec_dup, COLLECTED)
    row_dup = store.pending(5, COLLECTED)[0]
    assert candidate.associate(store.db, row_dup)[1] == "duplicate_ref"
    res_dup = run_gate(cfg, store, row_dup, Writer(), Reviewer(verdict(), verdict()), COLLECTED)
    assert res_dup["status"] == "published" and len(store.stories()) == 1
    assert store.stories()[0]["id"] == canon["id"]

    old_uncovered = _verified(
        url=ISSUES + "41249",
        labels=["Security", "Severity::medium"],
        upstream_state="closed",
        closed_at="2026-09-01T00:00:00Z",
        published_at="2026-08-01T00:00:00Z",
        updated_at=COLLECTED,
        title="Uncovered duplicate security issue",
        content="Closed as a duplicate of #99999.",
    )
    store.ingest(old_uncovered, COLLECTED)
    row_uncov = store.pending(5, COLLECTED)[0]
    assert candidate.associate(store.db, row_uncov) == (None, None)
    writer_uncov = Writer()
    assert run_gate(cfg, store, row_uncov, writer_uncov, Reviewer(), COLLECTED)["status"] == "ignored"
    assert writer_uncov.calls == [] and decision_codes(store, row_uncov)[-1] == SKIPPED
