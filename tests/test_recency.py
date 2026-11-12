"""An item whose newest dated development is old cannot start a new story, whatever its updated_at says."""

import json

import pytest

from approval_helpers import finish_reviewed, verdict
from onionflash import analyze, comments, editorial, rejection, review_gate
from onionflash.collect import collect_source
from onionflash.config import DEFAULTS
from onionflash.source_packet import source_fingerprint
from onionflash.store import Store, item_hash
from test_analyze import FakeLLM, completion
from test_core import FakeClient, analysis, config, item, response, source
from test_review_gate import Reviewer, Writer

ISSUES = "https://gitlab.torproject.org/tpo/core/tor/-/work_items/"
COLLECTED = "2026-11-11T15:00:00Z"
SKIPPED = "skipped.gate.not_recent"


@pytest.fixture
def context(tmp_path):
    cfg = config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        yield cfg, store


def note(issue, number, created, author, body):
    return {"id": f"gid://gitlab/Note/{number}", "url": f"{ISSUES}{issue}#note_{number}",
            "title": "Public comment by @" + author, "author": author, "created_at": created, "body": body}


def verified(**fields):
    """An issue as a verified comment check saved it."""
    return item(comments_checked_at=COLLECTED, comments_source_key="key", **fields)


# Two public Tor issues fixed in 0.4.9.14 on October 7, 2026, whose updated_at moved in November
# without a new public comment.
CROSS_CANCELLATION = verified(
    url=ISSUES + "41412", title="Circuit cross-cancellation can still blame channels",
    content="Our fix for #41360, #41365, and #41366 prevents remotely-induced Guard rotation cases.",
    labels=["Security", "Severity::medium"], upstream_state="closed",
    published_at="2026-09-23T15:01:31Z", updated_at="2026-11-11T14:48:45Z", public_comments=[
        note(41412, 3476175, "2026-10-07T17:17:10Z", "arma", "Scheduled for making public in a week, on Oct 15."),
        note(41412, 3476174, "2026-10-07T17:16:54Z", "arma",
             "Closing the ticket because it is fixed in today's 0.4.9.14 release.")])
CIRCUIT_FAILURES = verified(
    url=ISSUES + "41420", title="Frequent Circuit Build Failures after 4.9.13 update.",
    content="Some of my tor instances becoming unreachable via all their onion services every day since 4.9.13 update.",
    labels=[], upstream_state="closed",
    published_at="2026-09-30T16:22:39Z", updated_at="2026-11-11T14:49:36Z", public_comments=[
        note(41420, 3477912, "2026-10-14T14:52:35Z", "legoktm",
             "Hi, I hope it's okay to ask questions here about the new 0.4.9.14 log entry added in !1057."),
        note(41420, 3476172, "2026-10-07T17:14:17Z", "arma",
             "I'm going to close this ticket, as we list it as being fixed in today's 0.4.9.14 release.")])


def process(cfg, store, writer, checker, observed):
    return review_gate.process_item(cfg, store, store.pending(1, observed)[0], writer, checker, observed)


def logged(store):
    return [(code, json.loads(detail)) for code, detail in store.db.execute("SELECT code,detail_json FROM decision_log ORDER BY id")]


@pytest.mark.parametrize("incoming,developed", [(CROSS_CANCELLATION, "2026-10-07T17:17:10Z"),
                                                (CIRCUIT_FAILURES, "2026-10-14T14:52:35Z")])
def test_an_issue_edited_weeks_after_its_last_note_cannot_start_a_story(context, incoming, developed):
    cfg, store = context
    cfg["comments"]["enabled"] = True
    cfg["sources"] = [source(kind="gitlab_issue", url="https://gitlab.torproject.org/api/v4/projects/426/issues",
                             gitlab_project="tpo/core/tor")]
    # Even if an earlier revision left an analysis audit row, a pre-model recency skip shows no finished review.
    earlier = {**json.loads(json.dumps(incoming)), "content": incoming["content"] + " Earlier text.",
               "updated_at": developed}
    store.ingest(earlier, developed)
    process(cfg, store, Writer(), Reviewer(verdict("hold")), developed)
    assert rejection.show_item(store, earlier["id"])["final_review"]["stage"] == "held"
    store.ingest(json.loads(json.dumps(incoming)), COLLECTED)
    writer, checker = Writer(), Reviewer()  # a strict reviewer: any call fails the test
    result = process(cfg, store, writer, checker, "2026-11-11T15:05:00Z")
    assert result["status"] == "ignored" and result["writer_calls"] == result["review_calls"] == 0
    assert writer.calls == [] and checker.calls == []
    status, error, story = store.db.execute("SELECT status,last_error,story_id FROM items").fetchone()
    assert status == "ignored" and developed in error and story is None
    assert store.stories() == [] and store.db.execute("SELECT COUNT(*) FROM review_jobs").fetchone()[0] == 0
    assert store.db.execute("SELECT COUNT(*) FROM comment_cache").fetchone()[0] == 0
    assert rejection.show_item(store, earlier["id"])["final_review"] is None
    assert [code for code, _ in logged(store)] == ["held.review.model_hold", SKIPPED]
    assert (logged(store)[-1][1]["developed_at"], logged(store)[-1][1]["collected_at"]) == (developed, COLLECTED)


def test_a_fresh_public_comment_on_an_old_issue_reaches_review(context):
    cfg, store = context
    fresh = {"id": "gid://gitlab/Note/7", "url": "https://example.org/news/1#note_7", "author": "maintainer",
             "title": "Public comment by @maintainer", "created_at": "2026-11-11T14:40:00Z",
             "body": "The keys were rotated today."}
    store.ingest(verified(published_at="2015-01-10T12:32:24Z", updated_at="2026-11-11T14:40:00Z",
                          public_comments=[fresh]), COLLECTED)
    writer = Writer()
    assert process(cfg, store, writer, Reviewer(verdict()), COLLECTED)["status"] == "published"
    assert len(writer.calls) == 1 and [code for code, _ in logged(store)] == ["published.new"]


def test_an_unverified_old_issue_gets_a_comment_check_and_a_fresh_note_queues_it_again(context):
    cfg, store = context
    cfg["comments"]["enabled"] = True
    cfg["sources"] = [source(kind="gitlab_issue", url="https://gitlab.torproject.org/api/v4/projects/426/issues",
                             gitlab_project="tpo/core/tor")]
    store.ingest(item(url=ISSUES + "1", published_at="2015-01-10T12:32:24Z", updated_at=COLLECTED), COLLECTED)
    row = store.pending(1, COLLECTED)[0]
    assert process(cfg, store, Writer(), Reviewer(), COLLECTED)["status"] == "ignored"
    checked, due = store.db.execute("SELECT checked_at,next_fetch_at FROM comment_cache WHERE item_id=?", (row["id"],)).fetchone()
    assert due <= checked  # a request, which the next comments phase serves whatever the item's status
    # That check finds a public note written minutes ago: the new revision is queued and reviewed.
    later = "2026-11-11T15:10:00Z"
    fresh = [{"id": "gid://gitlab/Note/9", "url": ISSUES + "1#note_9", "author": "maintainer",
              "title": "Public comment by @maintainer", "created_at": "2026-11-11T14:45:00Z", "body": "Reopening: seen again."}]
    saved = json.loads(store.db.execute("SELECT payload FROM items").fetchone()[0])
    assert store.ingest(comments._compose(saved, fresh, later, source_key=comments._source_key(cfg["sources"][0])), later)
    writer = Writer()
    process(cfg, store, writer, Reviewer(verdict("skip", criterion="news_value")), later)
    assert len(writer.calls) == 1 and [code for code, _ in logged(store)] == [SKIPPED, "skipped.review.news_value"]
    # When comments or the source are disabled, an unverified old issue adds no comment_cache request.
    for comments_on, source_on, suffix in ((False, True, "2"), (True, False, "3")):
        cfg["comments"]["enabled"] = comments_on
        cfg["sources"][0]["enabled"] = source_on
        store.ingest(item(url=ISSUES + suffix, published_at="2015-01-10T12:32:24Z", updated_at=COLLECTED), COLLECTED)
        row = store.pending(1, COLLECTED)[0]
        assert process(cfg, store, Writer(), Reviewer(), COLLECTED)["status"] == "ignored"
        assert store.db.execute("SELECT 1 FROM comment_cache WHERE item_id=?", (row["id"],)).fetchone() is None


def test_a_closed_issue_is_dated_by_its_closing_only_while_closed(context):
    cfg, store = context
    store.ingest(item(url=ISSUES + "10", published_at="2015-01-10T12:32:24Z", updated_at=COLLECTED,
                      upstream_state="closed", closed_at="2026-11-11T14:30:00Z"), COLLECTED)
    writer = Writer()
    process(cfg, store, writer, Reviewer(verdict("skip", criterion="news_value")), COLLECTED)
    assert len(writer.calls) == 1
    # An opened issue cannot borrow an old or leftover closed_at field.
    store.ingest(item(url=ISSUES + "11", published_at="2015-01-10T12:32:24Z", updated_at=COLLECTED,
                      upstream_state="opened", closed_at="2026-11-11T14:30:00Z"), COLLECTED)
    assert process(cfg, store, Writer(), Reviewer(), COLLECTED)["status"] == "ignored"


@pytest.mark.parametrize("merged,code", [("2026-11-11T14:50:00Z", "skipped.review.news_value"),
                                         ("2026-10-20T14:32:27Z", SKIPPED)])
def test_a_merge_is_dated_by_its_merge_not_its_last_edit(context, merged, code):
    cfg, store = context
    store.ingest(item(kind="gitlab_mr", upstream_state="merged", labels=[], published_at=merged,
                      updated_at="2026-11-11T14:50:31Z"), COLLECTED)
    process(cfg, store, Writer(), Reviewer(verdict("skip", criterion="news_value")), COLLECTED)
    assert [entry for entry, _ in logged(store)] == [code]


@pytest.mark.parametrize("published,code", [("2026-11-04T19:53:47Z", "skipped.review.news_value"),
                                            ("2026-09-01T00:00:00Z", SKIPPED)])
def test_a_post_is_dated_by_its_publication_not_its_edit(context, published, code):
    cfg, store = context
    store.ingest(item(kind="feed", title="Tor 0.4.9.16 is released", published_at=published,
                      updated_at="2026-11-04T19:53:47Z"), "2026-11-04T20:00:00Z")
    process(cfg, store, Writer(), Reviewer(verdict("skip", criterion="news_value")), "2026-11-04T20:00:00Z")
    assert [entry for entry, _ in logged(store)] == [code]


def test_a_first_poll_of_a_new_source_skips_only_its_old_developments_and_pins_the_boundary(context):
    cfg, store = context
    # Exactly 14 days before COLLECTED (2026-11-11T15:00:00Z) is 2026-10-28T15:00:00Z.
    batch = {
        "recent": "2026-11-05T00:00:00Z",
        "inside": "2026-10-28T15:00:01Z",
        "exact": "2026-10-28T15:00:00Z",
        "outside": "2026-10-28T14:59:59Z",
        "ancient": "2016-01-27T17:17:19Z",
    }
    for name, published in batch.items():
        store.ingest(item(url="https://example.org/" + name, published_at=published, updated_at="2026-11-10T00:00:00Z"),
                     COLLECTED)
    writer = Writer()
    for _ in batch:
        process(cfg, store, writer, Reviewer(verdict("skip", criterion="news_value")), COLLECTED)
    codes = {detail["url"].rsplit("/", 1)[1]: code for code, detail in logged(store)}
    assert codes == {
        "recent": "skipped.review.news_value",
        "inside": "skipped.review.news_value",
        "exact": "skipped.review.news_value",
        "outside": SKIPPED,
        "ancient": SKIPPED,
    }
    assert len(writer.calls) == 3


def test_the_window_runs_from_collection_not_from_a_late_run(context):
    cfg, store = context
    # Collected 13 days after it was written, then delayed in the queue: still reviewed.
    store.ingest(item(published_at="2026-10-29T15:00:00Z", updated_at="2026-10-29T15:00:00Z"), COLLECTED)
    writer = Writer()
    process(cfg, store, writer, Reviewer(verdict("skip", criterion="news_value")), "2026-11-20T00:00:00Z")
    assert len(writer.calls) == 1


def test_an_update_of_an_existing_story_still_reaches_review_and_a_locked_story_still_holds(context):
    cfg, store = context
    title = "Tor 0.4.9.16 is released"
    store.ingest(item(kind="feed", url="https://example.org/announce", title=title), COLLECTED)
    finish_reviewed(store, store.pending(1, COLLECTED)[0], analysis(), "key", COLLECTED)
    # An old post in the same release cluster updates that story, so recency does not apply.
    store.ingest(item(kind="feed", url="https://example.org/old-post", title=title, content="Old post.",
                      published_at="2026-09-01T00:00:00Z", updated_at=COLLECTED), COLLECTED)
    writer = Writer()
    process(cfg, store, writer, Reviewer(verdict("skip", criterion="news_value")), COLLECTED)
    assert len(writer.calls) == 1 and logged(store)[-1][0] == "skipped.review.news_value"
    story_id = store.stories()[0]["id"]
    editorial.correct(store.db, story_id, {"why_it_matters": "Operator-reviewed wording."}, reason="Corrected wording.",
                      expect_hash=editorial.show(store.db, story_id)["hash"], observed=COLLECTED)
    store.ingest(item(kind="feed", url="https://example.org/old-post", title=title, content="Old post, edited.",
                      published_at="2026-09-01T00:00:00Z", updated_at=COLLECTED), COLLECTED)
    assert process(cfg, store, Writer(), Reviewer(), COLLECTED)["status"] == "locked"
    assert logged(store)[-1][0] == "held.gate.story_locked"


def test_an_operator_retry_lets_that_exact_old_revision_reach_review(context):
    cfg, store = context
    store.ingest(json.loads(json.dumps(CROSS_CANCELLATION)), COLLECTED)
    process(cfg, store, Writer(), Reviewer(), COLLECTED)
    row = dict(store.db.execute("SELECT id,content_hash FROM items").fetchone())
    rejection.retry_item(store, row["id"], row["content_hash"], "Embargoed fix worth recording", COLLECTED)
    writer = Writer()
    process(cfg, store, writer, Reviewer(verdict("skip", criterion="news_value")), COLLECTED)
    assert len(writer.calls) == 1
    assert [code for code, _ in logged(store)] == [SKIPPED, "operator.reconsidered", "skipped.review.news_value"]
    # A later revision with a different content_hash does not inherit the earlier retry bypass.
    edited = {**json.loads(json.dumps(CROSS_CANCELLATION)), "content": CROSS_CANCELLATION["content"] + " Typo fix.",
              "updated_at": "2026-11-11T15:10:00Z"}
    assert store.ingest(edited, "2026-11-11T15:15:00Z")
    assert process(cfg, store, Writer(), Reviewer(), "2026-11-11T15:15:00Z")["status"] == "ignored"


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
    cfg, store = context
    store.ingest(verified(kind=kind, labels=labels, published_at="2026-09-01T00:00:00Z", updated_at=COLLECTED), COLLECTED)
    writer = Writer()
    if reaches_review:
        result = process(cfg, store, writer, Reviewer(verdict("skip", criterion="news_value")), COLLECTED)
        assert result["status"] == "ignored" and len(writer.calls) == 1
        assert [code for code, _ in logged(store)] == ["skipped.review.news_value"]
    else:
        result = process(cfg, store, writer, Reviewer(), COLLECTED)
        assert result["status"] == "ignored" and writer.calls == []
        assert [code for code, _ in logged(store)] == [SKIPPED]


def test_concurrent_item_change_during_recency_check_returns_stale(context):
    cfg, store = context
    store.ingest(json.loads(json.dumps(CROSS_CANCELLATION)), COLLECTED)
    stale_row = store.pending(1, COLLECTED)[0]
    with store.db:
        store.db.execute("UPDATE items SET content_hash='changed' WHERE id=?", (stale_row["id"],))
    result = review_gate.process_item(cfg, store, stale_row, Writer(), Reviewer(), COLLECTED)
    assert result == {"status": "stale", "writer_calls": 0, "review_calls": 0, "cache_hit": False}
    assert logged(store) == []


def test_closed_issues_keep_their_closing_date_without_changing_hashes_or_writer_input(monkeypatch):
    issues = source(kind="gitlab_issue", url="https://gitlab.torproject.org/api/v4/projects/426/issues")
    records = [{"web_url": ISSUES + str(n), "title": f"Report {n}", "description": "Body text long enough for literal evidence.",
                "state": state, "created_at": "2026-09-23T15:01:31Z", "updated_at": "2026-11-08T11:00:00Z", "closed_at": closed}
               for n, (state, closed) in enumerate([("closed", "2026-10-07T17:16:54Z"), ("closed", "not a date"),
                                                    ("closed", "2099-01-01T00:00:00Z"), ("opened", "2026-10-07T17:16:54Z")])]
    result = collect_source(FakeClient([response(json.dumps(records).encode())]), issues, {}, DEFAULTS["collection"],
                            "2026-11-08T12:00:00Z")
    assert [entry.get("closed_at") for entry in result["items"]] == [
        "2026-10-07T17:16:54Z", None, "2026-11-08T12:00:00Z", None]
    # Merge requests never store closed_at.
    mrs = source(kind="gitlab_mr", url="https://gitlab.torproject.org/api/v4/projects/426/merge_requests")
    mr_record = [{"web_url": "https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/1", "title": "Merge 1",
                  "description": "Body", "state": "merged", "created_at": "2026-09-23T15:01:31Z",
                  "merged_at": "2026-11-08T10:00:00Z", "updated_at": "2026-11-08T11:00:00Z",
                  "closed_at": "2026-11-08T10:00:00Z"}]
    mr_items = collect_source(FakeClient([response(json.dumps(mr_record).encode())]), mrs, {}, DEFAULTS["collection"],
                              "2026-11-08T12:00:00Z")["items"]
    assert "closed_at" not in mr_items[0]
    # closed_at never enters item_hash, source_fingerprint, cache_key, or the writer's bounded payload.
    with_closed = result["items"][0]
    without_closed = {key: value for key, value in with_closed.items() if key != "closed_at"}
    assert item_hash(with_closed) == item_hash(without_closed)
    assert source_fingerprint(with_closed) == source_fingerprint(without_closed)
    assert analyze.cache_key({"content_hash": item_hash(with_closed)}, DEFAULTS["llm"]) == analyze.cache_key(
        {"content_hash": item_hash(without_closed)}, DEFAULTS["llm"])
    monkeypatch.setenv("ONIONFLASH_LLM_API_KEY", "unit-test-secret")
    cfg = {**DEFAULTS, "llm": {**DEFAULTS["llm"], "base_url": "https://llm.example/v1"}}
    writer = analyze.Analyzer(cfg)
    writer.client = FakeLLM(completion(analysis(
        title="Report 0", summary="Body text long enough for literal evidence.", why_it_matters="",
        confidence="reported", state="developing", evidence=["Body text long enough for literal evidence."])))
    writer.analyze(with_closed)
    sent = json.loads(writer.client.requests[0][1]["messages"][1]["content"])
    assert "closed_at" not in sent
