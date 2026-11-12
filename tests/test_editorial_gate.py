"""Editorial decisions use bounded live coverage without turning it into evidence."""

import json

import pytest

from approval_helpers import approve, verdict
from onionflash import candidate
from onionflash.analyze import Analyzer, AnalysisError, tag_notice
from onionflash.store import ReviewRequired
from test_core import DATE, analysis, item
from test_review_gate import LATER, Reviewer, Writer, context, job, pending, run, seed_legacy


def add_coverage(store, identity="other-story", **changes):
    public = {"id": identity, "title": "A previous report", "summary": "The source reported an event.",
              "why_it_matters": "", "category": "network", "priority": "normal", "confidence": "reported",
              "state": "developing", "products": ["tor"], "tags": ["network"],
              "sources": [{"url": "https://example.org/" + identity, "title": "Original source"}],
              "published_at": DATE, "updated_at": DATE, "added_at": DATE, **changes}
    with store.db:
        store.db.execute("INSERT INTO stories VALUES(?,?,?,?,?)", (identity, identity, json.dumps(public),
                         public["published_at"], public["updated_at"]))
    return public


def skipped(criterion="new_information"):
    return verdict("skip", criterion=criterion)


def test_editorial_skip_is_audited_and_does_not_change_existing_article(context):
    """Record the skip while preserving the existing article."""
    cfg, store = context
    original, story_id = seed_legacy(store)
    row = pending(store, {**original, "content": original["content"] + " A routine acknowledgment.", "updated_at": LATER})
    stories = [tuple(r) for r in store.db.execute("SELECT * FROM stories")]
    result = run(cfg, store, row, Writer(), Reviewer(skipped()))
    assert result["status"] == "ignored" and job(store) is None
    assert [tuple(r) for r in store.db.execute("SELECT * FROM stories")] == stories
    saved = store.db.execute("SELECT status,story_id FROM items WHERE id=?", (row["id"],)).fetchone()
    assert tuple(saved) == ("ignored", story_id)
    record = json.loads(store.db.execute("SELECT review_record FROM analyses").fetchone()[0])
    assert record["outcome"] == "skipped" and record["reviews"][0]["result"]["verdict"] == "skip"
    assert record["prepared"]["coverage"]["prior_story"]["id"] == story_id


def test_second_item_sees_coverage_committed_in_the_same_cycle_before_build(context):
    """Expose newly accepted coverage to later items without waiting for rendering."""
    cfg, store = context
    first = pending(store)
    assert run(cfg, store, first, Writer(), Reviewer(verdict()))["status"] == "published"
    first_story = store.stories()[0]
    assert not store.db.execute("SELECT 1 FROM sqlite_master WHERE name='public_catalog'").fetchone()
    second = pending(store, item(kind="feed", url="https://example.org/reply", content="A quoted repetition of the earlier report."))
    checker = Reviewer(skipped())
    result = run(cfg, store, second, Writer(), checker)
    assert result["status"] == "ignored" and len(store.stories()) == 1
    assert checker.coverages[0]["recent"][0]["id"] == first_story["id"]
    assert first_story["summary"] not in json.dumps(checker.calls[0][1])


def test_material_known_issue_followup_updates_same_article_after_review(context):
    """Keep the established story identity when a reviewed follow-up adds information."""
    cfg, store = context
    original, story_id = seed_legacy(store)
    before = store.stories()[0]
    add_coverage(store)
    row = pending(store, {**original, "content": original["content"] + " A substantive later result.", "updated_at": LATER})
    checker = Reviewer(verdict())
    result = run(cfg, store, row, Writer(analysis(summary="The source reports a substantive later result.")), checker)
    assert result["status"] == "published" and len(store.stories()) == 2
    after = store.stories()[0]
    assert after["id"] == story_id and after["published_at"] == before["published_at"]
    assert after["summary"] == "The source reports a substantive later result."
    assert checker.coverages[0]["prior_story"]["summary"] == before["summary"]
    assert story_id not in {entry["id"] for entry in checker.coverages[0]["recent"]} and checker.coverages[1] == checker.coverages[0]


def test_routine_tag_has_local_draft_but_requires_editorial_review(context):
    """Require a news-value decision even when drafting the tag needs no model call."""
    cfg, store = context
    tag = item(kind="tag", title="data-refresh", content="A routine data snapshot tag.")
    row = pending(store, tag)
    with Analyzer(cfg) as writer:
        result = run(cfg, store, row, writer, Reviewer(skipped("news_value")))
        assert writer.client is None
    assert result["status"] == "ignored" and result["writer_calls"] == 0 and result["review_calls"] == 1
    assert store.stories() == []
    row = pending(store, item(kind="tag", title="another-tag", url="https://example.org/another-tag"))
    prepared = store.prepare_candidate(row, tag_notice(json.loads(row["payload"])), LATER)
    with pytest.raises(ReviewRequired):
        store.commit_candidate(prepared, prepared["candidate"], "not-reviewed", LATER)


def test_skip_requires_a_valid_recorded_skip_and_cannot_apply_approve_receipt(context):
    """Prevent a publication receipt from authorizing a different editorial decision."""
    _, store = context
    row = pending(store)
    prepared = store.prepare_candidate(row, analysis(), LATER)
    receipt = approve(store, prepared)
    with pytest.raises(ReviewRequired, match="authorize this decision"):
        store.commit_candidate(prepared, prepared["candidate"], "wrong-decision", LATER, decision="skip", **receipt)
    assert store.pending_count() == 1 and store.stories() == []


def test_coverage_is_bounded_but_keeps_exact_prior_visible_text(context):
    """Bound recent context while preserving the known prior article without truncation."""
    cfg, store = context
    original, prior_id = seed_legacy(store, result=analysis(summary="Prior text. " * 100, why_it_matters="Prior consequence. " * 25))
    previous = store.stories()[0]
    for number in range(40):
        add_coverage(store, f"background-{number:02d}", summary="Background detail. " * 80)
    row = pending(store, {**original, "content": original["content"] + " A current change.", "updated_at": LATER})
    prepared = store.prepare_candidate(row, analysis(), LATER)
    background = prepared["coverage"]
    assert background["prior_story"]["id"] == prior_id
    assert background["prior_story"]["summary"] == previous["summary"]
    assert background["prior_story"]["why_it_matters"] == previous["why_it_matters"]
    assert len(background["recent"]) + 1 <= candidate.COVERAGE_ROWS
    assert len(json.dumps(background, ensure_ascii=False)) <= candidate.COVERAGE_CHARS
    assert background["truncated"]
    assert all(len(row["summary"]) <= candidate.COVERAGE_SUMMARY_CHARS for row in background["recent"])


def test_recent_query_does_not_scan_unbounded_history_to_replace_retracted_rows(context):
    """Keep the database scan bounded even when all recent stories are retracted."""
    _, store = context
    for number in range(40):
        add_coverage(store, f"background-{number:02d}")
        if number >= 8:
            with store.db:
                store.db.execute("""INSERT INTO editorial_controls
                    (story_id,revision,locked,retracted,notice_action,notice_reason,notice_at)
                    VALUES(?,1,1,1,'retract','Withdrawn',?)""", (f"background-{number:02d}", LATER))
    background = candidate.coverage_background(store.db, None)
    assert background["recent"] == [] and background["truncated"]


@pytest.mark.parametrize("final", ["hold", "skip"])
def test_initial_approval_cannot_publish_when_fresh_verification_refuses(context, final):
    """Make the final verdict authoritative when the first review approved the draft."""
    cfg, store = context
    row = pending(store)
    response = skipped() if final == "skip" else verdict("hold")
    checker = Reviewer(verdict(), response)
    result = run(cfg, store, row, Writer(), checker)
    assert result["status"] == ("ignored" if final == "skip" else "held")
    assert result["writer_calls"] == 1 and result["review_calls"] == 2
    assert [call[2] for call in checker.calls] == [False, True]
    assert checker.calls[0][:2] == checker.calls[1][:2]
    assert store.stories() == []
    if final == "hold":
        # The hold's text names no stage; its decision code does.
        assert store.db.execute("SELECT last_error FROM items").fetchone()[0] == "Final review held: review did not approve the candidate"
        assert store.db.execute("SELECT code FROM decision_log").fetchone()[0] == "held.verification.model_hold"


def test_interrupted_verification_restarts_the_critique_when_coverage_changes(context):
    """A story published in the meantime restarts the critique without repeating the draft."""
    cfg, store = context
    row = pending(store)
    checker = Reviewer(verdict(), AnalysisError("verification unavailable", retryable=True))
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), checker)
    assert job(store)["stage"] == "verify"
    assert store.db.execute("SELECT COUNT(*) FROM review_approvals").fetchone()[0] == 0
    assert store.stories() == []
    add_coverage(store)
    resumed = Reviewer(verdict())
    result = run(cfg, store, row, Writer(), resumed)
    assert result["status"] == "published" and result["writer_calls"] == 0 and result["review_calls"] == 2
    assert [call[2] for call in resumed.calls] == [False, True]


@pytest.mark.parametrize("change", ["coverage", "policy"])
def test_recorded_decision_is_not_reused_after_its_context_changes(context, monkeypatch, change):
    """A decision recorded before a crash is reviewed again once its coverage or policy changes."""
    cfg, store = context
    row = pending(store)
    commit = store.commit_candidate
    monkeypatch.setattr(store, "commit_candidate", lambda *args, **kw: (_ for _ in ()).throw(RuntimeError("simulated crash before commit")))
    with pytest.raises(RuntimeError, match="simulated crash"):
        run(cfg, store, row, Writer(), Reviewer(verdict()))
    monkeypatch.setattr(store, "commit_candidate", commit)
    if change == "coverage":
        add_coverage(store)
    else:
        cfg["review"]["model"] = "different-review-model"
    checker = Reviewer(verdict())
    assert run(cfg, store, row, Writer(), checker)["status"] == "published"
    assert [call[2] for call in checker.calls] == [False, True]
