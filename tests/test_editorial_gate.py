"""Editorial decisions use bounded live coverage without turning it into evidence."""

import copy
import json

import pytest

from approval_helpers import approve, verdict
from onionflash import candidate, editorial, rejection, review, review_gate
from onionflash.analyze import Analyzer, AnalysisError, tag_notice
from onionflash.store import ReviewRequired, StaleCandidate
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


def test_editorial_skip_is_audited_and_does_not_change_existing_article_or_controls(context):
    """Record the skip while preserving the existing article and editorial controls."""
    cfg, store = context
    original, story_id = seed_legacy(store)
    row = pending(store, {**original, "content": original["content"] + " A routine acknowledgment.", "updated_at": LATER})
    stories = [tuple(r) for r in store.db.execute("SELECT * FROM stories")]
    controls = [tuple(r) for r in store.db.execute("SELECT * FROM editorial_controls")]
    result = run(cfg, store, row, Writer(), Reviewer(skipped()))
    assert result["status"] == "ignored" and job(store) is None
    assert [tuple(r) for r in store.db.execute("SELECT * FROM stories")] == stories
    assert [tuple(r) for r in store.db.execute("SELECT * FROM editorial_controls")] == controls
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
    row = pending(store, {**original, "content": original["content"] + " A substantive later result.", "updated_at": LATER})
    checker = Reviewer(verdict())
    result = run(cfg, store, row, Writer(analysis(summary="The source reports a substantive later result.")), checker)
    assert result["status"] == "published" and len(store.stories()) == 1
    after = store.stories()[0]
    assert after["id"] == story_id and after["published_at"] == before["published_at"]
    assert after["summary"] == "The source reports a substantive later result."
    assert checker.coverages[0]["prior_story"]["summary"] == before["summary"]


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
    with pytest.raises(ReviewRequired):
        row = pending(store, item(kind="tag", title="another-tag", url="https://example.org/another-tag"))
        store.finish(row, tag_notice(json.loads(row["payload"])), "not-reviewed", LATER)


def test_editorial_skip_may_include_factual_defects_without_requesting_a_pointless_repair(context):
    """Allow non-news to be discarded without repairing claims that cannot publish."""
    cfg, store = context
    row = pending(store)
    response = skipped("news_value")
    response["criteria"]["source_support"]["outcome"] = "fail"
    response["issues"].append({"criterion": "source_support", "source_refs": ["S1"], "explanation": "The draft also overstates this routine item."})
    result = run(cfg, store, row, Writer(), Reviewer(response))
    assert result["status"] == "ignored" and store.rejected_count() == 0 and store.stories() == []


@pytest.mark.parametrize("decision", ["approve", "skip"])
def test_coverage_change_during_review_invalidates_publication_and_skip(context, decision):
    """Invalidate both publication and skip decisions made against stale coverage."""
    cfg, store = context
    row = pending(store)
    def changed_coverage():
        """Simulate another committed article arriving while the model is reviewing."""
        add_coverage(store)
        return verdict() if decision == "approve" else skipped()
    result = run(cfg, store, row, Writer(), Reviewer(changed_coverage))
    assert result["status"] == "stale"
    assert len(store.stories()) == 1 and store.pending_count() == 1
    checker = Reviewer(skipped())
    resumed = run(cfg, store, row, Writer(), checker)
    assert resumed["status"] == "ignored" and resumed["writer_calls"] == 0 and resumed["review_calls"] == 1
    assert not resumed["cache_hit"] and checker.coverages[0]["recent"][0]["id"] == "other-story"


def test_completed_skip_resumes_from_bound_receipt_without_a_model_call(context, monkeypatch):
    """Commit an interrupted skip from its exact durable receipt without reanalysis."""
    cfg, store = context
    row = pending(store)
    commit = store.skip_candidate
    monkeypatch.setattr(store, "skip_candidate", lambda *args, **kw: (_ for _ in ()).throw(RuntimeError("interrupted before skip commit")))
    with pytest.raises(RuntimeError):
        run(cfg, store, row, Writer(), Reviewer(skipped()))
    assert job(store)["stage"] == "skipped" and store.pending_count() == 1
    monkeypatch.setattr(store, "skip_candidate", commit)
    result = run(cfg, store, row, Writer(), Reviewer(), allow_network=False)
    assert result["status"] == "ignored" and result["cache_hit"] and result["review_calls"] == 0
    assert job(store) is None and store.stories() == []


def test_skip_requires_a_valid_recorded_skip_and_cannot_apply_approve_receipt(context):
    """Prevent a publication receipt from authorizing a different editorial decision."""
    _, store = context
    row = pending(store)
    prepared = store.prepare_candidate(row, analysis(), LATER)
    receipt = approve(store, prepared)
    with pytest.raises(ReviewRequired, match="authorize this decision"):
        store.skip_candidate(prepared, prepared["candidate"], "wrong-decision", LATER, **receipt)
    assert store.pending_count() == 1 and store.stories() == []


def test_coverage_is_bounded_but_keeps_exact_prior_visible_text(context):
    """Bound recent context while preserving the known prior article without truncation."""
    cfg, store = context
    original, prior_id = seed_legacy(store, result=analysis(summary="Prior text. " * 100, why_it_matters="Prior consequence. " * 25))
    previous = store.stories()[0]
    for number in range(40):
        add_coverage(store, f"background-{number:02d}", summary="Background detail. " * 80)
    row = pending(store, {**original, "content": original["content"] + " A current change.", "updated_at": LATER})
    prepared = store.prepare_candidate(row, analysis(), LATER, review_settings=cfg["review"])
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
    background = candidate.coverage_background(store.db, None, candidate.COVERAGE_CHARS)
    assert background["recent"] == [] and background["truncated"]


def test_corrupted_prepared_background_cannot_be_committed(context):
    """Reject changed background bytes even when the original receipt still exists."""
    _, store = context
    add_coverage(store)
    row = pending(store)
    prepared = store.prepare_candidate(row, analysis(), LATER)
    receipt = approve(store, prepared)
    prepared["coverage"]["recent"][0]["summary"] = "Unreviewed replacement background."
    with pytest.raises(StaleCandidate):
        store.commit_candidate(prepared, prepared["candidate"], "bad-background", LATER, **receipt)
    assert store.pending_count() == 1 and len(store.stories()) == 1


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


def test_initial_approval_resumes_only_final_verification_after_interruption(context):
    """Resume the uncompleted verification without repeating the draft or critique."""
    cfg, store = context
    row = pending(store)
    checker = Reviewer(verdict(), AnalysisError("verification unavailable", retryable=True))
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), checker)
    assert job(store)["stage"] == "verify"
    assert store.db.execute("SELECT COUNT(*) FROM review_approvals").fetchone()[0] == 0
    assert store.stories() == []
    resumed = Reviewer(verdict())
    result = run(cfg, store, row, Writer(), resumed)
    assert result["status"] == "published" and result["writer_calls"] == 0 and result["review_calls"] == 1
    assert [call[2] for call in resumed.calls] == [True]


@pytest.mark.parametrize("final", ["approve", "hold"])
def test_reconciled_critique_still_requires_fresh_verification(context, final):
    """Repairing a contradictory critique never substitutes for final approval."""
    cfg, store = context
    row = pending(store)
    critique = verdict("revise", criterion="technical_details", repair={"tags": ["release"]})
    critique["criteria"]["technical_details"]["outcome"] = "pass"
    checker = Reviewer(critique, verdict(final))
    draft = analysis(category="release", tags=["release", "security"], why_it_matters="")
    result = run(cfg, store, row, Writer(draft), checker)
    assert result["review_calls"] == 2 and [call[2] for call in checker.calls] == [False, True]
    assert checker.calls[1][0]["tags"] == ["release"]
    assert result["status"] == ("published" if final == "approve" else "held")
    assert len(store.stories()) == (1 if final == "approve" else 0)
    record = json.loads(store.db.execute("SELECT review_record FROM analyses").fetchone()[0])
    assert record["reviews"][0]["result"]["criteria"]["technical_details"]["outcome"] == "fail"


def test_store_refuses_an_approval_receipt_without_final_verification(context):
    """Enforce fresh verification at the store boundary as well as in the worker."""
    _, store = context
    row = pending(store)
    prepared = store.prepare_candidate(row, analysis(), LATER)
    receipt = approve(store, prepared)
    with store.db:
        audit = json.loads(store.db.execute("SELECT review_record_json FROM review_approvals WHERE key=?", (receipt["approval_key"],)).fetchone()[0])
        audit["reviews"] = audit["reviews"][:1]
        store.db.execute("UPDATE review_approvals SET review_record_json=? WHERE key=?", (json.dumps(audit), receipt["approval_key"]))
    with pytest.raises(ReviewRequired, match="final verification"):
        store.commit_candidate(prepared, prepared["candidate"], "first-pass-only", LATER, **receipt)
    assert store.stories() == [] and store.pending_count() == 1


def test_incomplete_cached_verification_is_replaced_by_fresh_review_not_a_stale_loop(context, monkeypatch):
    """Recover from an incomplete receipt by replacing its review history."""
    cfg, store = context
    row = pending(store)
    commit = store.commit_candidate
    monkeypatch.setattr(store, "commit_candidate", lambda *args, **kw: (_ for _ in ()).throw(RuntimeError("interrupted")))
    with pytest.raises(RuntimeError):
        run(cfg, store, row, Writer(), Reviewer(verdict()))
    saved = job(store)
    with store.db:
        proof = json.loads(store.db.execute("SELECT review_record_json FROM review_approvals WHERE key=?", (saved["approval_key"],)).fetchone()[0])
        proof["reviews"] = proof["reviews"][:1]
        store.db.execute("UPDATE review_approvals SET review_record_json=? WHERE key=?", (json.dumps(proof), saved["approval_key"]))
    monkeypatch.setattr(store, "commit_candidate", commit)
    checker = Reviewer(verdict())
    result = run(cfg, store, row, Writer(), checker)
    assert result["status"] == "published" and not result["cache_hit"] and result["writer_calls"] == 0
    assert [call[2] for call in checker.calls] == [False, True]


@pytest.mark.parametrize("damaged", ["missing", "verdict", "binding"])
def test_store_requires_a_complete_matching_initial_review_as_well_as_final_approval(context, damaged):
    """Require both review stages to prove the exact source and candidate transition."""
    _, store = context
    row = pending(store)
    prepared = store.prepare_candidate(row, analysis(), LATER)
    receipt = approve(store, prepared)
    with store.db:
        audit = json.loads(store.db.execute("SELECT review_record_json FROM review_approvals WHERE key=?", (receipt["approval_key"],)).fetchone()[0])
        if damaged == "missing":
            audit["reviews"][0] = {"stage": "review"}
        elif damaged == "verdict":
            audit["reviews"][0]["result"] = {"verdict": "approve"}
        else:
            audit["reviews"][0]["coverage_hash"] = "different-context"
        store.db.execute("UPDATE review_approvals SET review_record_json=? WHERE key=?", (json.dumps(audit), receipt["approval_key"]))
    with pytest.raises(ReviewRequired, match="final verification"):
        store.commit_candidate(prepared, prepared["candidate"], "damaged-first-review", LATER, **receipt)
    assert store.stories() == [] and store.pending_count() == 1


def alter_receipt_input(proof, change):
    """Vary stored provenance without changing the receipt's decision or hashes."""
    if change == "missing":
        proof.pop("input_row")
    elif change == "non-object":
        proof["input_row"] = []
    elif change == "wrong-item":
        proof["input_row"]["id"] = "another-item"
    elif change == "invalid-json":
        proof["input_row"]["payload"] = "{"
    elif change == "non-object-payload":
        proof["input_row"]["payload"] = "[]"
    elif change == "changed-source":
        payload = json.loads(proof["input_row"]["payload"])
        payload["content"] += " A different source claim."
        proof["input_row"]["payload"] = json.dumps(payload)
    else:
        assert change == "queue-progress"
        proof["input_row"].update(attempts=7, rejections=2, next_attempt_at=LATER)


@pytest.mark.parametrize("decision", ["approve", "skip"])
@pytest.mark.parametrize("change", ["missing", "non-object", "wrong-item", "invalid-json",
                                     "non-object-payload", "changed-source", "queue-progress"])
def test_cached_decision_requires_matching_input_provenance_but_allows_queue_progress(context, monkeypatch, decision, change):
    """Damaged provenance forces fresh review; scheduling progress preserves valid recovery."""
    cfg, store = context
    row = pending(store)
    method = "commit_candidate" if decision == "approve" else "skip_candidate"
    commit = getattr(store, method)
    monkeypatch.setattr(store, method, lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("interrupted")))
    reply = verdict() if decision == "approve" else skipped()
    with pytest.raises(RuntimeError):
        run(cfg, store, row, Writer(), Reviewer(reply))
    saved = job(store)
    with store.db:
        proof = json.loads(store.db.execute("SELECT review_record_json FROM review_approvals WHERE key=?",
                                           (saved["approval_key"],)).fetchone()[0])
        alter_receipt_input(proof, change)
        store.db.execute("UPDATE review_approvals SET review_record_json=? WHERE key=?",
                         (json.dumps(proof), saved["approval_key"]))
    monkeypatch.setattr(store, method, commit)
    if change != "queue-progress":
        prepared = json.loads(saved["envelope_json"])
        with pytest.raises(ReviewRequired, match="final verification or skip record"):
            commit(prepared, prepared["candidate"], saved["writer_key"], LATER,
                   approval_key=saved["approval_key"], policy_hash=saved["policy_hash"])
    checker = Reviewer(reply)
    result = run(cfg, store, row, Writer(), checker)
    assert result["status"] == ("published" if decision == "approve" else "ignored")
    assert result["writer_calls"] == 0
    assert result["cache_hit"] is (change == "queue-progress")
    assert result["review_calls"] == (0 if change == "queue-progress" else 2 if decision == "approve" else 1)


@pytest.mark.parametrize("change", ["missing", "non-object", "wrong-item"])
def test_unidentified_skip_receipt_cannot_bypass_explicit_reconsideration(context, change):
    """A receipt that cannot be identified for invalidation cannot authorize another skip."""
    cfg, store = context
    row = pending(store)
    assert run(cfg, store, row, Writer(), Reviewer(skipped()))["status"] == "ignored"
    saved = store.db.execute("SELECT key,review_record_json FROM review_approvals").fetchone()
    with store.db:
        proof = json.loads(saved["review_record_json"])
        alter_receipt_input(proof, change)
        store.db.execute("UPDATE review_approvals SET review_record_json=? WHERE key=?",
                         (json.dumps(proof), saved["key"]))
    rejection.retry_item(store, row["id"], row["content_hash"], "Reconsider the inspected item", cfg["llm"], LATER,
                         reconsider_ignored=True)
    # Invalidation deliberately cannot infer ownership from the damaged record.
    assert store.db.execute("SELECT 1 FROM review_approvals WHERE key=?", (saved["key"],)).fetchone()
    result = run(cfg, store, store.pending(1, LATER)[0], Writer(), Reviewer(verdict()))
    assert result["status"] == "published" and result["review_calls"] == 2 and not result["cache_hit"]
