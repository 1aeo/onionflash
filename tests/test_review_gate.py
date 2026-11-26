"""The final-candidate gate resumes completed stages and never publishes unchecked."""

import json
import sqlite3
import threading

import pytest

from helpers import (
    DAMAGE, DATE, LATER, ApprovingReviewer, FakeLLM, Reviewer, Writer, add_coverage, analysis, damage_item,
    damaged, decision_codes as codes, downgrade_job_v1, editorial_act, inconsistent, insert_approval, item, item_row,
    job, job_record, make_config, make_note, mapped_item, patch_cli_pipeline, pending, queued_row, raise_once,
    run_gate as run, saved_audit as audit, seed_legacy, seed_story, tag, update_analysis, verdict, wire_reviewer,
)
from onionflash import candidate, cli, editorial, rejection, review, review_gate
from onionflash.analyze import AnalysisError, Analyzer, cache_key, tag_notice
from onionflash.comments import _compose
from onionflash.llm import CompletionDeferred
from onionflash.store import ReviewRequired, Store
from onionflash.transport import FetchError
from onionflash.util import digest, item_cluster


def test_approved_exact_candidate_commits_dates_story_and_keeps_audit(context, monkeypatch):
    """Commit an approved story candidate with current `added_at` and full two-stage audit."""
    cfg, store = context
    row = pending(store)
    writer, checker = Writer(), Reviewer(verdict())
    monkeypatch.setattr(review_gate, "now_iso", lambda: "2026-11-11T00:01:00Z")
    result = review_gate.process_item(cfg, store, row, writer, checker, "2026-11-10T23:59:00Z")
    assert result == {"status": "published", "writer_calls": 1, "review_calls": 2, "cache_hit": False}
    assert job(store) is None and store.stories()[0]["added_at"] == "2026-11-11T00:01:00Z"
    assert store.stories()[0]["summary"] == checker.calls[0][0]["summary"]
    saved = store.db.execute("SELECT result,review_record FROM analyses").fetchone()
    rec = json.loads(saved[1])
    assert json.loads(saved[0]) == analysis() and rec["writer"] == {"key": cache_key(row, cfg["llm"])}
    assert rec["prepared"]["packet"]["sources"] and [r["stage"] for r in rec["reviews"]] == ["review", "verification"]
    assert rec["outcome"] == "approved"


@pytest.mark.parametrize("failure", [AnalysisError("timeout", retryable=True), {}])
def test_review_timeout_or_malformed_verdict_resumes_without_regenerating_writer(context, failure):
    """Resume a failed or malformed review from `review` stage without re-calling the writer."""
    cfg, store = context
    row = pending(store)
    with pytest.raises(AnalysisError) as caught:
        run(cfg, store, row, Writer(), Reviewer(failure))
    assert caught.value.retryable == isinstance(failure, AnalysisError) and job(store)["stage"] == "review"
    assert len(store.stories()) == 0
    paused = Reviewer(verdict())
    assert run(cfg, store, row, Writer(), paused, allow_network=False)["status"] == "deferred"
    assert paused.calls == [] and job(store)["stage"] == "review"
    next_writer, next_checker = Writer(), Reviewer(verdict())
    result = run(cfg, store, row, next_writer, next_checker)
    assert result["status"] == "published" and result["writer_calls"] == 0
    assert next_writer.calls == [] and len(next_checker.calls) == 2


def test_repair_requires_fresh_verification_and_resumes_that_exact_stage(context):
    """Persist repaired candidates in `verify` stage and resume verification without re-drafting."""
    cfg, store = context
    row = pending(store)
    first = Reviewer(verdict("revise", repair={"why_it_matters": ""}), AnalysisError("timeout", retryable=True))
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(analysis(why_it_matters="Operators must edit their relay configuration.")), first)
    assert [c[2] for c in first.calls] == [False, True] and job(store)["stage"] == "verify" and len(store.stories()) == 0
    repaired = first.calls[1][0]
    assert repaired["why_it_matters"] == ""
    second = Reviewer(verdict())
    result = run(cfg, store, row, Writer(), second)
    assert result["writer_calls"] == 0 and result["review_calls"] == 1
    assert second.calls == [(repaired, first.calls[1][1], True)]
    assert [e["stage"] for e in audit(store)["reviews"]] == ["review", "verification"]


def test_verification_repairs_are_verified_fresh(context):
    """Verify iterative repairs fresh and commit the final approved summary."""
    cfg, store = context
    row = pending(store)
    checker = Reviewer(verdict(), verdict("revise", repair={"summary": "A first repair."}),
                       verdict("revise", repair={"summary": "A second repair."}), verdict())
    result = run(cfg, store, row, Writer(), checker)
    assert result == {"status": "published", "writer_calls": 1, "review_calls": 4, "cache_hit": False}
    assert [c[2] for c in checker.calls] == [False, True, True, True]
    assert [c[0]["summary"] for c in checker.calls[1:]] == [checker.calls[0][0]["summary"], "A first repair.", "A second repair."]
    assert all(c[1] == checker.calls[0][1] for c in checker.calls) and all(c == checker.coverages[0] for c in checker.coverages)
    assert store.stories()[0]["summary"] == "A second repair."
    assert [e["stage"] for e in audit(store)["reviews"]] == ["review", "verification", "verification", "verification"]
    assert audit(store)["outcome"] == "approved"


def test_verification_repairs_stop_after_max_requests(context):
    """Raise `ReviewLimitReached` once iterative verification repairs exhaust `MAX_REVIEW_REQUESTS`."""
    cfg, store = context
    row = pending(store)
    repairs = [verdict("revise", repair={"summary": f"Repair number {n}."}) for n in range(7)]
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), Reviewer(*repairs[:4], AnalysisError("timeout", retryable=True)))
    assert job(store)["stage"] == "verify"
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), Reviewer(AnalysisError("timeout", retryable=True)))
    assert job(store)["stage"] == "verify"
    writer, checker = Writer(), Reviewer(*repairs[4:])
    with pytest.raises(review.ReviewLimitReached):
        run(cfg, store, row, writer, checker)
    assert writer.calls == [] and [c[2] for c in checker.calls] == [True, True]
    assert codes(store, row) == ["failed.review.request_limit"] and store.stories() == []
    assert job_record(store)["request_budget"]["reserved"] == review_gate.MAX_REVIEW_REQUESTS
    shown = rejection.show_item(store, row["id"])["final_review"]
    assert shown["candidate"]["summary"] == "Repair number 5."
    assert shown["base_candidate"]["summary"] == analysis()["summary"]
    assert [(e["phase"], e["verdict"]) for e in shown["reviews"]] == [("review", "revise")] + [("verification", "revise")] * 5
    assert all(e["failed"] == {"operational_advice": "fail: The source does not support this claim."} for e in shown["reviews"])
    assert [e["repair"]["summary"] for e in shown["reviews"]] == [f"Repair number {n}." for n in range(6)]


@pytest.mark.parametrize("case", ["hold", "revise-without-repair", "repeated-text", "tag-notice"])
def test_verification_refusal_that_cannot_be_repaired_holds(context, case):
    """Hold items when verification returns hold, empty repair, repeated text, or tag edits."""
    cfg, store = context
    tag_item = item(url="https://example.org/tags/tor-0.4.9.16", title="tor-0.4.9.16", kind="tag", content="")
    incoming, draft = (tag_item, tag_notice(tag_item)) if case == "tag-notice" else (item(), analysis())
    first = verdict() if case == "tag-notice" else verdict("revise", repair={"summary": "A shorter summary."})
    second, reason = {"hold": (verdict("hold"), "model_hold"),
                      "revise-without-repair": (verdict("revise"), "unusable_repair"),
                      "repeated-text": (verdict("revise", repair={"summary": analysis()["summary"]}), "repeated_repair"),
                      "tag-notice": (verdict("revise", repair={"title": "Tor 0.4.9.16 released"}), "tag_repair")}[case]
    row = pending(store, incoming)
    result = run(cfg, store, row, Writer(draft), Reviewer(first, second))
    assert result["status"] == "held" and result["review_calls"] == 2
    assert store.pending_count() == 0 and store.rejected_count() == 1 and store.stories() == [] and job(store)["stage"] == "held"
    assert store.db.execute("SELECT last_error FROM items").fetchone()[0] == "Final review held: " + review_gate.HOLDS[reason]
    assert codes(store, row) == ["held.verification." + reason]
    assert (audit(store)["outcome"], audit(store)["hold_code"], len(audit(store)["reviews"]), audit(store)["verified_facts"]) == ("held", reason, 2, False)


@pytest.mark.parametrize("replies,status", [
    ([verdict(), verdict("hold", criterion="news_value")], "held"),
    ([verdict(), verdict("skip", criterion="new_information")], "held"),
    ([verdict("revise", criteria=("news_value", "operational_advice"), repair={"summary": "A shorter summary."}), verdict()], "held"),
    ([verdict(), verdict("revise", criteria=("news_value", "operational_advice"), repair={"summary": "A shorter summary."})], "held"),
    ([verdict("revise", criteria=("news_value", "operational_advice"), repair={"summary": "A shorter summary."}),
      verdict("skip", criterion="news_value")], "ignored"),
])
def test_reviews_that_disagree_on_news_value_hold(context, replies, status):
    """Hold when critique and verification disagree on news value, or ignore when both skip."""
    cfg, store = context
    row = pending(store)
    checker = Reviewer(*replies)
    result = run(cfg, store, row, Writer(), checker)
    assert (result["status"], result["review_calls"]) == (status, 2) and store.stories() == []
    assert [c[2] for c in checker.calls] == [False, True]
    assert store.db.execute("SELECT last_error FROM items").fetchone()[0] == (
        "Final review held: the reviews disagree on news value" if status == "held" else "Final review skipped: news_value")
    assert codes(store, row) == (["held.verification.disagreed_news"] if status == "held" else ["skipped.verification.news_value"])


OFFICIAL = {"authority": "official", "kind": "feed"}
COVERED = {"url": "https://example.org/covered-story", "content": "Earlier distinct report."}
COVERED_ID = digest(item_cluster(item(**COVERED)))[:24]


@pytest.mark.parametrize("src,replies,status,code", [
    (OFFICIAL, [verdict("skip", criterion="news_value")] * 2, "held", "held.verification.official_not_news"),
    (OFFICIAL, [verdict("skip", criterion="news_value"),
                verdict("revise", criteria=("news_value", "operational_advice"), repair={"summary": "A shorter summary."}),
                verdict("skip", criterion="news_value")], "held", "held.verification.official_not_news"),
    (OFFICIAL, [verdict("revise", criterion="news_value"), verdict("skip", criterion="news_value")],
     "held", "held.verification.official_not_news"),
    (OFFICIAL, [verdict("revise", criterion="news_value"), verdict("revise", criteria=("news_value", "operational_advice"))],
     "held", "held.verification.unusable_repair"),
    (OFFICIAL, [verdict("skip", criterion="new_information", reason=f"Already covered in {COVERED_ID}.")],
     "ignored", "skipped.review.new_information"),
    (OFFICIAL, [verdict("skip", criteria=("new_information", "news_value"), reason=f"Already covered in {COVERED_ID}.")],
     "ignored", "skipped.review.new_information_and_news_value"),
    (OFFICIAL, [verdict("skip", criterion="news_value",
                        criteria={"new_information": {"reason": "Coverage is truncated.", "source_refs": [], "outcome": "insufficient"}})],
     "held", "held.review.model_hold"),
    (OFFICIAL, [verdict("skip", criterion="news_value"),
                verdict("skip", criterion="new_information", reason=f"Already covered in {COVERED_ID}.")],
     "ignored", "skipped.verification.new_information"),
    ({}, [verdict("skip", criterion="news_value")], "ignored", "skipped.review.news_value"),
    ({**OFFICIAL, "kind": "tag", "title": "tor-0.4.9.16", "content": ""}, [verdict("skip", criterion="news_value")],
     "ignored", "skipped.review.news_value"),
])
def test_official_item_failing_news_value_is_held_not_skipped(context, src, replies, status, code):
    """Hold non-tag official items failing `news_value` while allowing verified duplicate skips."""
    cfg, store = context
    _, covered_id = seed_legacy(store, item(**COVERED))
    assert covered_id == COVERED_ID
    row = pending(store, item(**src))
    checker = Reviewer(*replies)
    result = run(cfg, store, row, Writer(), checker)
    assert (result["status"], result["review_calls"]) == (status, len(replies)) and codes(store, row) == [code]
    if status == "ignored":
        assert review._skip_stands(audit(store)["reviews"][-1]["result"]["criteria"], checker.coverages[-1])
    if status == "held":
        reason = code.rsplit(".", 1)[1]
        assert [c[2] for c in checker.calls] == [False] + [True] * (len(replies) - 1)
        assert (audit(store)["hold_code"], audit(store)["verified_facts"]) == (reason, reason == "official_not_news")
        assert store.db.execute("SELECT last_error FROM items WHERE id=?", (row["id"],)).fetchone()[0] == (
            "Final review held: " + review_gate.HOLDS[reason])


def test_a_hold_whose_verification_cites_no_source_does_not_record_verified_facts(context):
    """Require source citations on verification passes before marking `verified_facts` true."""
    cfg, store = context
    uncited = verdict("skip", criterion="news_value", criteria={"source_support": {"source_refs": []}})
    row = pending(store, item(**OFFICIAL))
    assert run(cfg, store, row, Writer(), Reviewer(verdict("skip", criterion="news_value"), uncited))["status"] == "held"
    assert (audit(store)["hold_code"], audit(store)["verified_facts"]) == ("official_not_news", False)


@pytest.mark.parametrize("draft,replies,flags,status,code", [
    ({"category": "release", "tags": ["release"]},
     [verdict(), verdict("revise", repair={"category": "security", "tags": ["security"]}, criterion="status"), verdict()],
     [False, False, True], "published", None),
    ({}, [verdict(), verdict("revise", repair={"category": "release"}), verdict(),
          verdict("revise", repair={"category": "feature", "tags": ["feature"]}, criterion="status"), verdict()],
     [False, True, True, False, True], "published", None),
    ({"category": "release", "tags": ["release"]}, [verdict(), verdict()], [False, False], "held", "held.review.release_labels"),
    ({"category": "release", "tags": ["release"]}, [verdict(), verdict("revise", repair={"summary": "A shorter summary."})],
     [False, False], "held", "held.review.release_labels"),
    ({"category": "release", "tags": ["release"]}, [verdict(), verdict("hold", criterion="status")],
     [False, False], "held", "held.review.release_labels"),
    ({"category": "release", "tags": ["release"]}, [verdict(), verdict("skip", criterion="news_value")],
     [False, False], "held", "held.review.disagreed_news"),
])
def test_release_labels_on_an_unreleased_story_get_a_repair_request_then_a_fresh_verification(context, draft, replies, flags, status, code):
    """Send a targeted `release_labels` repair pass and verify fresh when release labels mismatch state."""
    cfg, store = context
    row = pending(store)
    checker = Reviewer(*replies)
    result = run(cfg, store, row, Writer(analysis(**draft)), checker)
    assert result["status"] == status and [c[2] for c in checker.calls] == flags
    repair_idx = flags.index(False, 1)
    assert checker.issues == [review.RELEASE_ISSUE if n == repair_idx else None for n in range(len(flags))]
    assert audit(store)["reviews"][repair_idx]["issue"] == "release_labels"
    if status == "published":
        assert store.stories()[0]["category"] != "release" and "release" not in store.stories()[0]["tags"]
    else:
        assert codes(store, row) == [code] and audit(store)["verified_facts"] is False


FIVE_REPAIRS = [verdict("revise", repair={"summary": f"Repair number {n}."}) for n in range(5)]


@pytest.mark.parametrize("replies,code", [
    ([verdict("revise", repair={"summary": "A first repair."}), *FIVE_REPAIRS[:4], verdict()], "held.verification.release_labels"),
    ([verdict("revise", repair={"summary": "A first repair."}), *FIVE_REPAIRS, verdict()], "held.verification.release_labels"),
    ([verdict(), verdict("revise", repair={"category": "security", "tags": ["security"]}, criterion="status"), *FIVE_REPAIRS],
     "held.verification.repairs_exhausted"),
])
def test_an_item_gets_at_most_seven_review_requests(context, replies, code):
    """Hold items cleanly once repair/release-label passes exhaust the 7-request cap."""
    cfg, store = context
    row = pending(store)
    result = run(cfg, store, row, Writer(analysis(category="release", tags=["release"])), Reviewer(*replies))
    assert (result["status"], result["review_calls"]) == ("held", len(replies)) and codes(store, row) == [code]


def test_receipt_resume_context_invalidation_and_pruning(context, monkeypatch):
    """Resume cached approvals across crashes, invalidate on context drift, and pin active keys."""
    cfg, store = context
    row = pending(store)
    commit = store.commit_candidate
    monkeypatch.setattr(store, "commit_candidate", raise_once(RuntimeError("simulated crash")))
    with pytest.raises(RuntimeError):
        run(cfg, store, row, Writer(), Reviewer(verdict("revise", repair={"summary": "A first repair."}),
                                                verdict("revise", repair={"summary": "A second repair."}), verdict()))
    monkeypatch.setattr(store, "commit_candidate", commit)
    w0, r0 = Writer(), Reviewer()
    res = run(cfg, store, row, w0, r0, allow_network=False)
    assert res["status"] == "published" and res["cache_hit"] and w0.calls == r0.calls == []
    assert store.stories()[0]["summary"] == "A second repair."

    for idx, change in enumerate(("coverage", "policy")):
        row_c = pending(store, item(url=f"https://example.org/ctx-{idx}", content=f"Context change {idx} Compromise report."))
        monkeypatch.setattr(store, "commit_candidate", raise_once(RuntimeError("simulated crash")))
        with pytest.raises(RuntimeError):
            run(cfg, store, row_c, Writer(analysis(evidence=[f"Context change {idx}"])), Reviewer(verdict()))
        monkeypatch.setattr(store, "commit_candidate", commit)
        if change == "coverage":
            add_coverage(store, f"cov-{idx}")
        else:
            cfg["review"]["model"] = "different-review-model"
        chk = Reviewer(verdict())
        assert run(cfg, store, row_c, Writer(), chk)["status"] == "published" and [c[2] for c in chk.calls] == [False, True]

    monkeypatch.setattr(review_gate, "MAX_APPROVALS", 1)
    row_p = pending(store, item(url="https://example.org/pin", content="Pinned approval test report."))
    monkeypatch.setattr(store, "commit_candidate", raise_once(RuntimeError("crash")))
    with pytest.raises(RuntimeError):
        run(cfg, store, row_p, Writer(analysis(evidence=["Pinned approval test report."])), Reviewer(verdict()))
    active = job(store, row_p["id"])["approval_key"]
    monkeypatch.setattr(store, "commit_candidate", commit)
    for n in range(3):
        insert_approval(store, key=f"unused-{n}", candidate_hash="c", source_hash="s", policy="p", binding_hash="b",
                        result={}, record={}, created_at=DATE, last_used_at="2099-01-01T00:00:00Z")
    review_gate._prune(store, 1)
    assert store.db.execute("SELECT 1 FROM review_approvals WHERE key=?", (active,)).fetchone()
    assert store.db.execute("SELECT COUNT(*) FROM review_approvals").fetchone()[0] == 2

    save = review_gate._save
    monkeypatch.setattr(review_gate, "_save", lambda *a, **kw: (save(*a, **kw), raise_once(RuntimeError("crash after save"))()))
    with pytest.raises(RuntimeError):
        run(cfg, store, row_p, Writer(), Reviewer(), allow_network=False)
    assert job(store, row_p["id"])["approval_key"] == active
    insert_approval(store, key="newer-unused", candidate_hash="c", source_hash="s", policy="p", binding_hash="b",
                    result={}, record={}, created_at=LATER, last_used_at="2099-02-01T00:00:00Z")
    review_gate._prune(store, 1)
    assert store.db.execute("SELECT 1 FROM review_approvals WHERE key=?", (active,)).fetchone()
    monkeypatch.setattr(review_gate, "_save", save)
    assert run(cfg, store, row_p, Writer(), Reviewer(), allow_network=False)["status"] == "published"


@pytest.mark.parametrize("column", ["draft_json", "envelope_json", "record_json"])
@pytest.mark.parametrize("kind", DAMAGE)
def test_a_damaged_review_job_fails_the_item_and_is_never_reviewed_afresh(context, column, kind):
    """Fail closed with `app.damaged_job` on corrupted `review_jobs` columns without new calls."""
    cfg, store = context
    row = pending(store)
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), Reviewer(verdict(), AnalysisError("timeout", retryable=True)))
    with store.db:
        store.db.execute(f"UPDATE review_jobs SET {column}=CAST(? AS TEXT)", (damaged(job(store)[column], kind),))
    writer, checker = Writer(), Reviewer()
    with pytest.raises(AnalysisError, match="Saved review job is damaged") as caught:
        run(cfg, store, row, writer, checker)
    assert (caught.value.retryable, caught.value.code) == (False, "app.damaged_job") and writer.calls == checker.calls == []


def test_a_damaged_review_job_never_stops_the_run(context, monkeypatch):
    """Strike-reject a damaged `review_jobs` row across `cli.run` cycles without aborting the run."""
    cfg, store = context
    cfg["sources"] = []
    row = pending(store)
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), Reviewer(AnalysisError("timeout", retryable=True)))
    with store.db:
        store.db.execute("UPDATE review_jobs SET record_json=CAST(? AS TEXT)", (b'{"\xff"',))
    monkeypatch.setattr(cli, "build", lambda *a: {})
    for _ in range(3):
        assert cli.run(cfg, store)["analysis_failed"] == 1
        with store.db:
            store.db.execute("UPDATE items SET next_attempt_at=NULL")
    assert tuple(store.db.execute("SELECT status,last_error FROM items").fetchone()) == ("rejected", "Saved review job is damaged")
    assert codes(store, row) == ["failed.app.damaged_job"]


@pytest.mark.parametrize("draft,stage", [({}, "verify"), ({"category": "release", "tags": ["release"]}, "repair")])
def test_pending_resumes_an_unfinished_verification_or_repair_before_new_work(context, draft, stage):
    """Prioritize items with unfinished `verify` or `repair` jobs ahead of fresh pending items."""
    cfg, store = context
    store.ingest(item(), DATE)
    store.ingest(item(url="https://example.org/routine", title="A routine report", labels=[]), DATE)
    first, routine = store.pending(2, LATER)
    assert routine["url"].endswith("/routine")
    with pytest.raises(AnalysisError):
        run(cfg, store, routine, Writer(analysis(**draft)), Reviewer(verdict(), AnalysisError("timeout", retryable=True)))
    assert job(store)["stage"] == stage and [r["url"] for r in store.pending(2, LATER)] == [routine["url"], first["url"]]


@pytest.mark.parametrize("repair", [None, {"title": analysis()["title"]}, {"title": ""}],
                         ids=["missing", "unchanged", "invalid"])
def test_unusable_repair_holds_after_one_call_for_operator_inspection(context, repair):
    """Hold unusable critique repairs after one call and expose them via `rejection.show_item`."""
    cfg, store = context
    row = pending(store)
    result = run(cfg, store, row, Writer(), Reviewer(verdict("revise", repair=repair)))
    assert result["status"] == "held" and result["review_calls"] == 1
    assert [e["id"] for e in rejection.list_items(store)["items"]] == [row["id"]]
    assert rejection.show_item(store, row["id"])["final_review"]["latest_review"]["verdict"] == "revise"


@pytest.mark.parametrize("decision", ["approve", "skip"])
def test_completed_decision_resumes_after_crash_without_any_model_call(context, monkeypatch, decision):
    """Resume a recorded `approve` or `skip` decision across commit crashes with zero LLM calls."""
    cfg, store = context
    row = pending(store)
    commit = store.commit_candidate
    monkeypatch.setattr(store, "commit_candidate", raise_once(RuntimeError("simulated crash")))
    with pytest.raises(RuntimeError):
        run(cfg, store, row, Writer(), Reviewer(verdict(decision, criterion="news_value")))
    assert job(store)["stage"] == ("approved" if decision == "approve" else "skipped") and len(store.stories()) == 0
    store.defer(row["id"], "Unexpected RuntimeError", cfg["llm"], LATER, terminal=True)
    row = item_row(store, row)
    monkeypatch.setattr(store, "commit_candidate", commit)
    other = pending(store, item(url="https://example.org/other-report", content="A routine reply."))
    assert run(cfg, store, other, Writer(), Reviewer(verdict("skip", criterion="news_value")))["status"] == "ignored"
    writer, checker = Writer(), Reviewer()
    result = run(cfg, store, row, writer, checker, allow_network=False)
    assert result["status"] == ("published" if decision == "approve" else "ignored") and result["cache_hit"]
    assert writer.calls == checker.calls == [] and job(store) is None
    assert len(store.stories()) == (1 if decision == "approve" else 0)
    assert not store.db.execute("SELECT 1 FROM review_approvals").fetchone()


@pytest.mark.parametrize("receipt", ["damaged", "missing"])
def test_a_recorded_decision_without_a_usable_receipt_reviews_the_draft_again(context, monkeypatch, receipt):
    """Re-review the saved draft when a recorded decision lacks a readable approval receipt."""
    cfg, store = context
    row = pending(store)
    commit = store.commit_candidate
    monkeypatch.setattr(store, "commit_candidate", raise_once(RuntimeError("simulated crash")))
    first = Reviewer(verdict("revise", repair={"why_it_matters": ""}), verdict())
    with pytest.raises(RuntimeError):
        run(cfg, store, row, Writer(analysis(why_it_matters="Operators must edit their relay configuration.")), first)
    monkeypatch.setattr(store, "commit_candidate", commit)
    with store.db:
        store.db.execute("UPDATE review_approvals SET review_record_json='{'" if receipt == "damaged" else "DELETE FROM review_approvals")
    checker = Reviewer(verdict())
    assert run(cfg, store, row, Writer(), checker)["status"] == "published"
    assert [c[0] for c in checker.calls] == [first.calls[0][0]] * 2
    assert [e["stage"] for e in audit(store)["reviews"]] == ["review", "verification"]


FINAL_CHECKS = {
    "completed_action": ({}, {"title": "Tor authority bastet removed from source after reported compromise"}),
    "compromise_headline": ({}, {"title": "Bastet directory authority compromised"}),
    "confirmed_source": ({}, {"confidence": "confirmed"}),
    "merge_state": ({"kind": "gitlab_mr", "upstream_state": "merged"}, {"state": "released"}),
}


@pytest.mark.parametrize("reason", FINAL_CHECKS)
def test_verified_approval_failing_a_final_check_is_held_with_its_code(context, reason):
    """Hold verified candidates that trip deterministic `final_holds` guards without caching receipts."""
    cfg, store = context
    src, draft = FINAL_CHECKS[reason]
    row = pending(store, item(**src))
    result = run(cfg, store, row, Writer(analysis(**draft)), Reviewer(verdict()))
    assert result["status"] == "held" and result["review_calls"] == 2
    assert store.db.execute("SELECT last_error FROM items").fetchone()[0] == "Final review held: " + review_gate.HOLDS[reason]
    assert codes(store, row) == [f"held.final_check.{reason}"]
    assert store.stories() == [] and not store.db.execute("SELECT 1 FROM review_approvals").fetchone()
    other = pending(store, item(**src, url="https://example.org/news/2"))
    assert run(cfg, store, other, Writer(analysis(**draft)), Reviewer(verdict("skip", criterion="news_value")))["status"] == "ignored"


def test_resumed_final_check_source_and_policy_invalidation(context, monkeypatch):
    """Re-run `final_holds` on resumed approvals and invalidate drafts/reviews appropriately."""
    cfg, store = context
    row = pending(store)
    commit, check = store.commit_candidate, review.final_holds
    monkeypatch.setattr(store, "commit_candidate", raise_once(RuntimeError("simulated crash")))
    monkeypatch.setattr(review, "final_holds", lambda candidate, prepared: [])
    with pytest.raises(RuntimeError):
        run(cfg, store, row, Writer(analysis(confidence="confirmed")), Reviewer(verdict()))
    monkeypatch.setattr(store, "commit_candidate", commit)
    monkeypatch.setattr(review, "final_holds", check)
    w0, r0 = Writer(), Reviewer()
    res = run(cfg, store, row, w0, r0, allow_network=False)
    assert res["status"] == "held" and res["cache_hit"] and w0.calls == r0.calls == []
    assert codes(store, row) == ["held.final_check.confirmed_source"]
    assert rejection.show_item(store, row["id"])["final_review"]["latest_review"]["verdict"] == "approve"

    row2 = pending(store, item(url="https://example.org/src-change"))
    with pytest.raises(AnalysisError):
        run(cfg, store, row2, Writer(), Reviewer(AnalysisError("timeout", retryable=True)))
    store.ingest(item(url="https://example.org/src-change", content=item()["content"] + " Correction.", updated_at=LATER), LATER)
    changed = queued_row(store, "https://example.org/src-change")
    assert changed["content_hash"] != row2["content_hash"]
    w2 = Writer()
    assert run(cfg, store, changed, w2, Reviewer(verdict()))["writer_calls"] == len(w2.calls) == 1

    row3 = pending(store, item(url="https://example.org/pol-change"))
    with pytest.raises(AnalysisError):
        run(cfg, store, row3, Writer(), Reviewer(verdict(), AnalysisError("timeout", retryable=True)))
    cfg["review"]["model"] = "different-review-model"
    res3 = run(cfg, store, row3, Writer(), Reviewer(verdict()))
    assert res3["writer_calls"] == 0 and res3["review_calls"] == 2 and not res3["cache_hit"]


def test_writer_mode_change_redrafts_without_resetting_review_spend(context):
    """Redraft when `writer_reasoning` changes `writer_key` while carrying forward spent review budget."""
    config, store = context
    row = pending(store)
    writer = Writer(analysis(why_it_matters=""))
    with pytest.raises(AnalysisError):
        run(config, store, row, writer, Reviewer(AnalysisError("Temporary endpoint failure", retryable=True)))
    before = job(store)
    assert job_record(store)["request_budget"]["reserved"] == 1
    config["llm"]["writer_reasoning"] = True
    next_writer = Writer(analysis(why_it_matters=""))
    with pytest.raises(AnalysisError):
        run(config, store, row, next_writer, Reviewer(AnalysisError("Temporary endpoint failure", retryable=True)))
    after = job(store)
    assert len(next_writer.calls) == 1 and before["writer_key"] != after["writer_key"]
    assert before["policy_hash"] == after["policy_hash"]
    assert job_record(store)["request_budget"]["reserved"] == 2
    assert store.stories() == []


def test_update_review_repairs_human_lock_and_missing_retained_source(context):
    """Verify update-mode repairs, operator lock preservation, and missing-retained-source holds."""
    cfg, store = context
    prior_why = "The report requests removal of the old directory-authority keys."
    original = item(content=item()["content"] * 3, updated_at="2026-11-09T12:00:00Z")
    _, story_id = seed_legacy(store, original, analysis(why_it_matters=prior_why))
    incoming = item(url="https://example.org/news/mirror", source_id="mirror", content=original["content"])
    row = pending(store, incoming)
    checker = Reviewer(verdict("revise", repair={"update": "A second mirror reported the key issue."}, update=True),
                       verdict(update=True))
    draft = update_analysis(update="Operators must reconfigure now; a second mirror reported the key issue.")
    result = run(cfg, store, row, Writer(draft), checker)
    reviewed, evidence, _ = checker.calls[0]
    passages = [p["text"] for s in evidence["sources"] for p in s["passages"]]
    assert reviewed["why_it_matters"] == prior_why and len(evidence["sources"]) == 2
    assert original["content"] in passages and not any(prior_why in text for text in passages) and result["status"] == "published"
    story = store.stories()[0]
    assert story["why_it_matters"] == prior_why and len(store.stories()) == 1
    assert story["updates"] == [{"at": incoming["updated_at"], "text": "A second mirror reported the key issue.",
                                 "sources": [{"url": incoming["url"], "title": incoming["title"]}]}]

    row_lock = pending(store, {**original, "content": original["content"] + " A later report.", "updated_at": LATER})
    with pytest.raises(AnalysisError):
        run(cfg, store, row_lock, Writer(), Reviewer(AnalysisError("timeout", retryable=True)))
    downgrade_job_v1(store, row_lock)
    editorial_act(editorial.correct, store, story_id, {"why_it_matters": "Operator-reviewed wording."},
                  reason="Corrected unsupported advice.")
    second = run(cfg, store, row_lock, Writer(), Reviewer(), allow_network=False)
    assert second["status"] == "locked" and second["writer_calls"] == second["review_calls"] == 0
    assert store.stories()[0]["why_it_matters"] == "Operator-reviewed wording."
    editorial_act(editorial.unlock, store, story_id, reason="Reopen briefly.", observed="2026-11-10T12:05:00Z")
    row_lock_v2 = pending(store, {**original, "content": original["content"] + " A second follow-up.", "updated_at": "2026-11-10T12:10:00Z"},
                          at="2026-11-10T12:10:00Z", ready="2026-11-10T12:10:00Z")
    with pytest.raises(AnalysisError):
        run(cfg, store, row_lock_v2, Writer(), Reviewer(AnalysisError("timeout", retryable=True)))
    editorial_act(editorial.correct, store, story_id, {"why_it_matters": "Re-locked operator wording."},
                  reason="Re-lock.", observed="2026-11-10T12:15:00Z")
    row_lock_v3 = pending(store, {**original, "content": original["content"] + " A third follow-up.", "updated_at": "2026-11-10T12:20:00Z"},
                          at="2026-11-10T12:20:00Z", ready="2026-11-10T12:20:00Z")
    assert run(cfg, store, row_lock_v3, Writer(), Reviewer(), allow_network=False)["status"] == "deferred"

    orig2 = item(url="https://example.org/miss-orig", content="Distinct missing source body text long enough to cluster. " * 5, updated_at="2026-11-09T12:00:00Z")
    seed_legacy(store, orig2, analysis(evidence=["Distinct missing source body text"]))
    damage_item(store.db, orig2["id"], "compacted")
    row_miss = pending(store, item(url="https://example.org/miss-mirror", source_id="mirror", content=orig2["content"]))
    res_miss = run(cfg, store, row_miss, Writer(), Reviewer())
    assert res_miss["status"] == "held" and res_miss["review_calls"] == 0
    assert store.db.execute("SELECT status FROM items WHERE id=?", (orig2["id"],)).fetchone()[0] == "published"

    row_net = pending(store, item(url="https://example.org/net-off"))
    w_net, c_net = Writer(), Reviewer()
    assert run(cfg, store, row_net, w_net, c_net, allow_network=False)["status"] == "deferred"
    assert w_net.calls == c_net.calls == []


def test_tag_notices_citations_updates_and_repair_holds(context, monkeypatch):
    """Gate literal tag notices, zero-call release citations, and pre-release tag updates."""
    cfg, store = context
    t0 = item(title="tor-0.4.9.15", kind="tag", url="https://example.org/tags/0.4.9.15", content="")
    r0 = pending(store, t0)
    assert run(cfg, store, r0, Writer(tag_notice(t0)), Reviewer(), allow_network=False)["status"] == "deferred"
    assert run(cfg, store, r0, Writer(tag_notice(t0)), Reviewer(verdict()))["status"] == "published"

    t_hold = item(title="tor-0.4.9.14", kind="tag", url="https://example.org/tags/0.4.9.14", content="")
    r_hold = pending(store, t_hold)
    res_hold = run(cfg, store, r_hold, Writer(tag_notice(t_hold)),
                   Reviewer(verdict("revise", repair={"title": "Tor 0.4.9.14 released", "state": "released"}), verdict()))
    assert res_hold["status"] == "held" and res_hold["review_calls"] == 1
    assert "editing a literal tag notice" in store.db.execute("SELECT last_error FROM items WHERE id=?", (r_hold["id"],)).fetchone()[0]

    r_routine = pending(store, item(kind="tag", title="data-refresh", url="https://example.org/tags/refresh", content="Routine"))
    with Analyzer(cfg) as writer:
        res_skip = run(cfg, store, r_routine, writer, Reviewer(verdict("skip", criterion="news_value")))
        assert writer.client is None and res_skip["status"] == "ignored" and res_skip["writer_calls"] == 0
    r_unrev = pending(store, item(kind="tag", title="another-tag", url="https://example.org/another-tag"))
    prep_unrev = store.prepare_candidate(r_unrev, tag_notice(json.loads(r_unrev["payload"])), LATER)
    with pytest.raises(ReviewRequired):
        store.commit_candidate(prep_unrev, prep_unrev["candidate"], "not-reviewed", LATER)

    for idx, state in enumerate(("tagged", "released")):
        ver = f"0.4.9.{20 + idx}"
        ex_item = item(kind="feed", product="tor", title=f"Tor {ver} release update", url=f"https://example.org/rel-{ver}")
        seed_story(store, ex_item, analysis(title=f"Detailed {ver} update", state=state), key=f"det-{ver}", at=DATE)
        before_upd = next(s for s in store.stories(20) if ver in s["title"])["updated_at"]
        later_tag = tag(title=f"tor-{ver}", url=f"https://gitlab.torproject.org/tpo/core/tor/-/tags/tor-{ver}", updated_at="2026-11-09T16:00:00Z")
        out = run(cfg, store, pending(store, later_tag), observed=DATE)
        st = next(s for s in store.stories(20) if ver in s["title"])
        assert out["status"] == "cited" and out["writer_calls"] == out["review_calls"] == 0
        assert st["state"] == state and st["updated_at"] == before_upd and len(st["sources"]) == 2

    # An associated tag on a pre-release story runs update review without writer LLM calls.
    monkeypatch.setattr(Analyzer, "complete", raise_once(AssertionError("writer LLM forbidden")))
    for idx, state in enumerate(("developing", "fixed", "resolved", "mitigation-available", "merged")):
        ver = f"0.4.9.{30 + idx}"
        ex = item(kind="feed", product="tor", title=f"Tor {ver} release preparation", url=f"https://example.org/prep-{ver}")
        prepared_story = seed_story(store, ex, analysis(title=f"Prep {ver}", state=state), key=f"prep-{ver}", at=DATE)
        if state == "merged":
            bad_tag = tag(title=f"tor-{ver}", url=f"https://example.org/bad-tag-{ver}", updated_at="2026-11-09T16:00:00Z")
            bad_row = mapped_item(store, pending(store, bad_tag), prepared_story["id"])
            held = run(cfg, store, bad_row, Analyzer(cfg), Reviewer(verdict("revise", update=True, repair={"state": "released"})))
            assert held["status"] == "held" and held["review_calls"] == 1
        t_item = tag(title=f"tor-{ver}", url=f"https://gitlab.torproject.org/tpo/core/tor/-/tags/tor-{ver}", updated_at="2026-11-09T16:00:00Z")
        tag_row = mapped_item(store, pending(store, t_item), prepared_story["id"])
        with Analyzer(cfg) as real_writer:
            out = review_gate.process_item(cfg, store, tag_row, real_writer, ApprovingReviewer(cfg), "2026-11-09T16:05:00Z")
        st = next(s for s in store.stories(20) if f"Prep {ver}" == s["title"])
        assert out["status"] == "published" and out["writer_calls"] == 0 and out["review_calls"] == 2
        assert st["state"] == ("tagged" if state == "merged" else state)
        assert st["updates"][-1]["text"] == f"The upstream feed lists the tag “tor-{ver}”."


def test_editorial_coverage_skips_followups_and_bounds(context, monkeypatch):
    """Expose same-cycle coverage, preserve stories on skipped follow-ups, and bound coverage size."""
    cfg, store = context
    monkeypatch.setattr(review_gate, "now_iso", lambda: "2026-11-11T00:00:00Z")
    first_row = pending(store, item(url="https://example.org/cov-first"))
    assert run(cfg, store, first_row, Writer(), Reviewer(verdict()))["status"] == "published"
    first_story = store.stories()[0]
    assert store.db.execute("SELECT COUNT(*) FROM public_catalog").fetchone()[0] == 0
    rec_first = audit(store)
    assert rec_first["input_hash"] == first_row["content_hash"] and "input_row" not in rec_first
    second_row = pending(store, item(kind="feed", url="https://example.org/cov-reply", content="A quoted repetition."))
    chk = Reviewer(verdict("skip", criterion="new_information"))
    assert run(cfg, store, second_row, Writer(), chk)["status"] == "ignored" and len(store.stories()) == 1
    assert chk.coverages[0]["recent"][0]["id"] == first_story["id"]
    assert first_story["summary"] not in json.dumps(chk.calls[0][1])

    orig, sid = seed_legacy(store, item(url="https://example.org/known", content="Known issue Compromise report. " * 3),
                            analysis(summary="Prior text. " * 100, why_it_matters="Prior consequence. " * 25,
                                     evidence=["Known issue Compromise report."]))
    before_stories = [tuple(r) for r in store.db.execute("SELECT * FROM stories")]
    r_ack = pending(store, {**orig, "content": orig["content"] + " Routine ack.", "updated_at": LATER})
    assert run(cfg, store, r_ack, Writer(), Reviewer(verdict("skip", criterion="new_information")))["status"] == "ignored"
    assert [tuple(r) for r in store.db.execute("SELECT * FROM stories")] == before_stories
    assert tuple(store.db.execute("SELECT status,story_id FROM items WHERE id=?", (r_ack["id"],)).fetchone()) == ("ignored", sid)
    assert audit(store)["prepared"]["coverage"]["prior_story"]["id"] == sid

    r_sub = pending(store, {**orig, "content": orig["content"] + " A substantive later result.", "updated_at": "2026-11-10T13:00:00Z"})
    chk_u = Reviewer(verdict(update=True))
    assert run(cfg, store, r_sub, Writer(update_analysis(update="The source reports a substantive later result.",
                                                         evidence=["A substantive later result."])), chk_u)["status"] == "published"
    updated = next(s for s in store.stories(10) if s["id"] == sid)
    assert updated["updates"][-1]["text"] == "The source reports a substantive later result."
    assert sid not in {e["id"] for e in chk_u.coverages[0]["recent"]} and chk_u.coverages[1] == chk_u.coverages[0]

    r_int = pending(store, item(url="https://example.org/interrupted"))
    with pytest.raises(AnalysisError):
        run(cfg, store, r_int, Writer(), Reviewer(verdict(), AnalysisError("unavailable", retryable=True)))
    add_coverage(store, "mid-flight")
    resumed = Reviewer(verdict())
    res_int = run(cfg, store, r_int, Writer(), resumed)
    assert res_int["status"] == "published" and res_int["writer_calls"] == 0 and [c[2] for c in resumed.calls] == [False, True]

    r_wrong = pending(store, item(url="https://example.org/wrong-decision"))
    prep_w = store.prepare_candidate(r_wrong, analysis(), LATER)
    rec_w = insert_approval(store, prep_w)
    with pytest.raises(ReviewRequired, match="authorize this decision"):
        store.commit_candidate(prep_w, prep_w["candidate"], "wrong", LATER, decision="skip", **rec_w)

    for n in range(48):
        add_coverage(store, f"bg-{n:02d}", summary="Background detail. " * 80,
                     added_at="2026-11-15T00:00:00Z", updated_at="2026-11-15T00:00:00Z")
        if n >= 8:
            with store.db:
                store.db.execute("""INSERT INTO editorial_controls
                    (story_id,revision,locked,retracted,notice_action,notice_reason,notice_at)
                    VALUES(?,1,1,1,'retract','Withdrawn',?)""", (f"bg-{n:02d}", LATER))
    r_cov = pending(store, {**orig, "content": orig["content"] + " Current change.", "updated_at": "2026-11-10T14:00:00Z"})
    bg = store.prepare_candidate(r_cov, update_analysis(evidence=["Current change."]), LATER)["coverage"]
    assert bg["prior_story"]["id"] == sid and len(bg["prior_story"]["summary"]) > candidate.COVERAGE_SUMMARY_CHARS
    assert len(bg["recent"]) + 1 <= candidate.COVERAGE_ROWS and len(json.dumps(bg, ensure_ascii=False)) <= candidate.COVERAGE_CHARS
    assert bg["truncated"]
    bg_ret = candidate.coverage_background(store.db, None)
    assert len(bg_ret["recent"]) == candidate.COVERAGE_ROWS and all(r.get("retracted") is True and "summary" not in r for r in bg_ret["recent"])


@pytest.mark.parametrize("cached", [{"verdict": "approve"}, verdict("hold")], ids=["incomplete-approval", "hold"])
def test_cache_reviews_again_unless_the_receipt_is_a_complete_decision(context, cached):
    """Ignore cached `review_approvals` rows whose verdict is incomplete or a hold."""
    cfg, store = context
    row = pending(store)
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), Reviewer(AnalysisError("timeout", retryable=True)))
    saved = job(store)
    insert_approval(store, json.loads(saved["envelope_json"]), policy=saved["policy_hash"], result=cached)
    result = run(cfg, store, row, Writer(), Reviewer(verdict()))
    assert result["review_calls"] == 2 and not result["cache_hit"]


def test_status_retry_reverted_hold_and_rejected_show_views(context, monkeypatch):
    """Report stage counts, preserve DB state on `show_item`, and handle reverted holds and retries."""
    cfg, store = context
    assert review_gate.status(store) == {"stages": {}, "approval_cache_entries": 0}
    row = pending(store)
    before_dump = list(store.db.iterdump())
    assert rejection.show_item(store, row["id"])["final_review"] is None
    assert list(store.db.iterdump()) == before_dump

    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), Reviewer(verdict("revise", repair={"why_it_matters": ""}),
                                                AnalysisError("timeout", retryable=True)))
    assert review_gate.status(store) == {"stages": {"verify": 1}, "approval_cache_entries": 0}
    shown_v = rejection.show_item(store, row["id"])["final_review"]
    assert shown_v["stage"] == "verify" and shown_v["candidate"]["why_it_matters"] == ""
    assert shown_v["latest_review"]["verdict"] == "revise" and shown_v["latest_review"]["candidate_hash"] != digest(shown_v["candidate"])

    assert run(cfg, store, row, Writer(), Reviewer(verdict("hold")))["status"] == "held"
    assert review_gate.status(store) == {"stages": {"held": 1}, "approval_cache_entries": 0}

    store.ingest(item(content=item()["content"] + " Edited."), DATE)
    assert run(cfg, store, store.pending(1, LATER)[0], Writer(), Reviewer(), allow_network=False)["status"] == "deferred"
    store.ingest(item(), DATE)
    chk_rev = Reviewer(verdict())
    assert run(cfg, store, store.pending(1, LATER)[0], Writer(), chk_rev)["status"] == "held" and chk_rev.calls == []

    snap = list(store.db.iterdump())
    monkeypatch.setattr(review, "CRITERIA", (*review.CRITERIA, "a_later_criterion"))
    shown_h = rejection.show_item(store, row["id"])["final_review"]
    assert shown_h["stage"] == "held" and shown_h["candidate"]["title"] == analysis()["title"]
    assert shown_h["latest_review"]["criteria"]["operational_advice"]["outcome"] == "fail"
    assert shown_h["source_packet"]["sources"][0]["passages"][0]["id"] == "S1:P1"
    assert list(store.db.iterdump()) == snap
    monkeypatch.undo()

    rejection.retry_item(store, row["id"], row["content_hash"], "The review prompt was revised", LATER)
    assert audit(store)["outcome"] == "held" and job(store)["stage"] == "drafted"
    w_ret = Writer()
    assert run(cfg, store, store.pending(1, LATER)[0], w_ret, Reviewer(verdict()))["status"] == "published"
    assert w_ret.calls == [] and audit(store)["outcome"] == "approved"

    row_int = pending(store, item(url="https://example.org/int-show"))
    monkeypatch.setattr(store, "commit_candidate", raise_once(RuntimeError("crash")))
    with pytest.raises(RuntimeError):
        run(cfg, store, row_int, Writer(), Reviewer(verdict()))
    with store.db:
        review_gate.reset_review_work(store, row_int["id"])
    with pytest.raises(RuntimeError):
        run(cfg, store, row_int, Writer(), Reviewer())
    shown_app = rejection.show_item(store, row_int["id"])["final_review"]
    assert shown_app["stage"] == "approved" and shown_app["latest_review"]["verdict"] == "approve"


@pytest.mark.parametrize("kind", [*DAMAGE, "review-not-an-object", "review-without-result"])
def test_rejected_show_and_retry_survive_damaged_record_or_draft(context, kind):
    """Surface damaged held review records cleanly in `show_item` and recover on `retry_item`."""
    cfg, store = context
    row = pending(store)
    assert run(cfg, store, row, Writer(), Reviewer(verdict("hold")))["status"] == "held"
    saved = job(store)
    shapes = {"review-not-an-object": b'{"reviews": [1]}', "review-without-result": b'{"reviews": [{"stage": "held"}]}'}
    with store.db:
        val = shapes.get(kind) or damaged(saved["record_json"], kind)
        store.db.execute("UPDATE review_jobs SET record_json=CAST(? AS TEXT) WHERE item_id=?", (val, row["id"]))
        if kind in DAMAGE:
            store.db.execute("UPDATE review_jobs SET draft_json=CAST(? AS TEXT) WHERE item_id=?",
                             (damaged(saved["draft_json"], kind), row["id"]))
    shown = rejection.show_item(store, row["id"])
    assert shown["final_review"] == {"stage": "held", "error": "Saved review record cannot be read"} and shown["saved_item"] is not None
    rejection.retry_item(store, row["id"], row["content_hash"], "Retry after inspection", LATER)
    writer = Writer()
    assert run(cfg, store, store.pending(1, LATER)[0], writer, Reviewer(verdict()))["status"] == "published"
    assert len(writer.calls) == (1 if kind in DAMAGE else 0)


def test_atomic_rollbacks_db_errors_and_run_reports(context, monkeypatch):
    """Roll back failed job/hold writes atomically and avoid striking items on `OperationalError`."""
    cfg, store = context
    cfg["sources"] = []
    row = pending(store)
    store.db.execute("CREATE TRIGGER fail_held_job BEFORE UPDATE ON review_jobs WHEN NEW.stage='held' BEGIN SELECT RAISE(ABORT,'hold unavailable'); END")
    store.db.execute("CREATE TRIGGER fail_approved_job BEFORE INSERT ON review_jobs WHEN NEW.stage='approved' BEGIN SELECT RAISE(ABORT,'job save unavailable'); END")
    store.db.commit()
    with pytest.raises(sqlite3.IntegrityError, match="hold unavailable"):
        run(cfg, store, row, Writer(), Reviewer(verdict("hold")))
    assert store.db.execute("SELECT COUNT(*) FROM analyses").fetchone()[0] == 0 and job(store)["stage"] == "review"
    store.db.execute("DROP TRIGGER fail_held_job")
    with pytest.raises(sqlite3.IntegrityError, match="job save unavailable"):
        run(cfg, store, row, Writer(), Reviewer(verdict()))
    assert store.db.execute("SELECT COUNT(*) FROM review_approvals").fetchone()[0] == 0 and job(store)["stage"] == "verify"
    store.db.execute("DROP TRIGGER fail_approved_job")
    store.db.commit()
    assert run(cfg, store, row, Writer(), Reviewer(verdict()))["status"] == "published"

    store.ingest(item(url="https://example.org/locked"), DATE)
    monkeypatch.setattr(cli, "process_item", raise_once(sqlite3.OperationalError("database is locked")))
    with pytest.raises(sqlite3.OperationalError):
        cli.run(cfg, store)
    assert tuple(store.db.execute("SELECT status,rejections FROM items WHERE url='https://example.org/locked'").fetchone()) == ("pending", 0)
    monkeypatch.undo()


def test_run_report_counts_outcomes_model_calls_and_isolates_invalid_outputs(tmp_path, monkeypatch):
    """Aggregate run outcome counters, meter failed review calls, and isolate per-item exceptions."""
    cfg = make_config(tmp_path / "r1", sources=[])
    with Store(cfg["storage"]["database"]) as store:
        outcomes = iter([("held", False), ("stale", False), ("published", True), ("ignored", False), ("ignored", True)])
        monkeypatch.setattr(cli, "process_item", lambda *a, **kw: dict(zip(("status", "cache_hit"), next(outcomes))))
        patch_cli_pipeline(monkeypatch, now=None, reviewer=None, build=lambda *a: {})
        for name in ("one", "two", "three", "four", "five"):
            store.ingest(item(url="https://example.org/" + name), DATE)
        rep = cli.run(cfg, store)
        assert [rep[k] for k in ("analyzed", "analysis_failed", "review_stale", "review_cache_hits")] == [4, 0, 1, 2]
        assert rep["decisions"] == {} and "review_held" not in rep and "review_skipped" not in rep
    monkeypatch.undo()

    cfg2 = make_config(tmp_path / "r2", llm={"base_url": "https://llm.example/v1"}, sources=[])
    monkeypatch.setenv(cfg2["llm"]["api_key_env"], "test-key")
    reply_fn = lambda *_a, json_body=None, **_kw: (
        analysis(why_it_matters="")
        if json_body["response_format"]["json_schema"]["name"] == "onionflash_news"
        else {"winner": 1, "reason": "Selected candidate."}
        if json_body["response_format"]["json_schema"]["name"] == "onionflash_select"
        else FetchError("network request failed", retryable=True)
    )
    monkeypatch.setattr("onionflash.llm.HttpClient", lambda *a, **kw: FakeLLM(*([reply_fn] * 12)))
    patch_cli_pipeline(monkeypatch, now=None, reviewer=None, build=lambda *a: {})
    with Store(cfg2["storage"]["database"]) as store:
        for name in ("one", "two"):
            store.ingest(item(url="https://example.org/" + name), DATE)
        rep2 = cli.run(cfg2, store)
        assert (rep2["analysis_failed"], rep2["model_calls"]) == (2, 10)
    monkeypatch.undo()

    cfg3 = make_config(tmp_path / "r3", sources=[])
    built = []
    patch_cli_pipeline(
        monkeypatch,
        now=None,
        analyzer=Writer.factory(lambda inc: analysis(title="\uffff") if inc["url"].endswith("/draft") else analysis()),
        reviewer=Reviewer.factory(lambda _cand, pkt, **_kw: {} if "/reply" in pkt["sources"][0]["url"] else verdict()),
        build=lambda *a: built.append(True) or {},
    )
    with Store(cfg3["storage"]["database"]) as store:
        for name in ("reply-1", "reply-2", "draft"):
            store.ingest(item(url="https://example.org/" + name), DATE)
        store.ingest(item(url="https://example.org/good", title="A routine report", labels=[]), DATE)
        rep3 = cli.run(cfg3, store)
        states = {u.rsplit("/", 1)[1]: (st, rej, err) for u, st, rej, err in store.db.execute("SELECT url,status,rejections,last_error FROM items")}
    assert built == [True] and rep3["analysis_failed"] == 3
    st, rej, err = states.pop("draft")
    assert (st, rej) == ("pending", 1) and err.startswith("Unexpected ValueError at render.py:")
    assert states == {"reply-1": ("pending", 1, "Review response fields do not match schema"),
                      "reply-2": ("pending", 1, "Review response fields do not match schema"),
                      "good": ("published", 0, None)}


def test_own_item_newness_skips_unchanged_or_quoted_and_unlock_requeues_locked_updates(context):
    """Skip quoted/unchanged follow-ups, defer updates on locked stories, and requeue upon unlock."""
    cfg, store = context
    url = "https://gitlab.torproject.org/tpo/core/tor/-/work_items/41499"
    n1 = make_note(1, "Initial report details for the relay issue.", author="alice", url=url)
    issue = _compose(item(url=url, updated_at=DATE), [n1], DATE, source_key="k")
    assert run(cfg, store, pending(store, issue), Writer(analysis(evidence=["Initial report details for the relay issue."])),
               Reviewer(verdict()))["status"] == "published"
    story_id = store.stories()[0]["id"]

    n2 = make_note(2, "> Initial report details for the relay issue.\n> Agreed.", author="bob", created_at=LATER, url=url)
    assert store.ingest(_compose(issue, [n1, n2], LATER, source_key="k"), LATER)
    assert run(cfg, store, store.pending(1, LATER)[0], Writer(), Reviewer()) == {
        "status": "ignored", "writer_calls": 0, "review_calls": 0, "cache_hit": False}
    assert codes(store)[-1] == "skipped.gate.no_new_content"

    t99 = item(kind="tag", title="tor-0.4.9.99", url="https://example.org/tags/tor-0.4.9.99", content="")
    store.ingest(t99, DATE)
    assert run(cfg, store, queued_row(store, t99, DATE), Writer(), Reviewer(verdict()))["status"] == "published"
    assert store.ingest({**t99, "content": "new annotation", "updated_at": LATER}, LATER)
    assert run(cfg, store, queued_row(store, t99, LATER), Writer(), Reviewer()) == {
        "status": "ignored", "writer_calls": 0, "review_calls": 0, "cache_hit": False}

    editorial_act(editorial.correct, store, story_id, {"priority": "normal"}, reason="Lower priority.")
    later2 = "2026-11-10T14:00:00Z"
    n3 = make_note(3, "Maintainers merged the fix into main.", author="maint", created_at=later2, url=url)
    assert store.ingest(_compose(issue, [n1, n2, n3], later2, source_key="k"), later2)
    w_locked = Writer(update_analysis(update="Maintainers merged the fix.", state="merged", evidence=["Maintainers merged the fix into main."]))
    assert run(cfg, store, queued_row(store, issue, later2), w_locked, Reviewer())["status"] == "locked"
    assert w_locked.calls[0]["content"] == "" and [n["url"] for n in w_locked.calls[0]["public_comments"]] == [url + "#note_3"]
    assert store.pending(5, later2) == []

    editorial_act(editorial.unlock, store, story_id, reason="Allow queued updates.", observed="2026-11-10T15:00:00Z")
    requeued = [r for r in store.pending(5, "2026-11-10T15:00:00Z") if r["id"] == issue["id"]]
    assert len(requeued) == 1
    assert run(cfg, store, requeued[0], Writer(update_analysis(update="Maintainers merged the fix.", state="merged",
                                                               evidence=["Maintainers merged the fix into main."])),
               Reviewer(verdict(update=True)))["status"] == "published"
    assert next(s for s in store.stories(5) if s["id"] == story_id)["updates"] == [
        {"at": later2, "text": "Maintainers merged the fix.", "sources": [{"url": url + "#note_3", "title": n3["title"]}]}]

    later3, later4 = "2026-11-10T16:00:00Z", "2026-11-10T17:00:00Z"
    list_base = "https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/message/"
    store.ingest(item(kind="feed", url=list_base + "MSG0/", source_id="tor-relays", title="[tor-relays] Tor 0.4.9.15 released",
                      content="Initial report details for the relay issue.", updated_at=DATE), DATE)
    assert run(cfg, store, store.pending(1, DATE)[0], Writer(analysis(evidence=["Initial report details for the relay issue."])),
               Reviewer(verdict()))["status"] == "published"
    store.ingest(item(kind="feed", url=list_base + "MSG1/", source_id="tor-relays", title="[tor-relays] Re: Tor 0.4.9.15 released",
                      content="On Wed, Nov 10, 2026 at 09:00 AM, alice via tor-relays wrote:\n\n> Initial report details for the relay issue.\n>> Older nested quote with 53-day-old relay numbers.",
                      updated_at=later3), later3)
    assert run(cfg, store, store.pending(1, later3)[0], Writer(), Reviewer()) == {
        "status": "ignored", "writer_calls": 0, "review_calls": 0, "cache_hit": False}
    store.ingest(item(kind="feed", url=list_base + "MSG2/", source_id="tor-relays", title="[tor-relays] Re: Tor 0.4.9.15 released",
                      content="Operator observed three dropped circuits.\n\nOn Wed, Nov 10, 2026 at 09:00 AM, alice via tor-relays wrote:\n\n> Quoted 53-day-old relay backstory.",
                      updated_at=later4), later4)
    w_reply = Writer(update_analysis(update="An operator observed three dropped circuits.", state="developing",
                                     evidence=["Operator observed three dropped circuits."]))
    assert run(cfg, store, store.pending(1, later4)[0], w_reply, Reviewer(verdict(update=True)))["status"] == "published"
    assert w_reply.calls[0]["content"].strip() == "Operator observed three dropped circuits."
    assert "53-day-old" not in w_reply.calls[0]["content"] and "wrote:" not in w_reply.calls[0]["content"]


def test_pending_update_rewrites_and_own_comment_cutoff_admits_edited_notes(context):
    """Regenerate stale update drafts after concurrent updates and admit substantive note edits."""
    cfg, store = context
    _, release_id = seed_legacy(store, item(title="Tor 0.4.9.16 released", kind="feed", authority="official", content="Tor 0.4.9.16 was released with fixes."),
                               analysis(title="Tor 0.4.9.16 released", state="released", confidence="confirmed"))
    m1 = item(title="Tor 0.4.9.16 released", kind="feed", url="https://example.org/m1", source_id="m1",
              content="Debian packages for Tor 0.4.9.16 are live.", updated_at=LATER)
    m2 = item(title="Tor 0.4.9.16 released", kind="feed", url="https://example.org/m2", source_id="m2",
              content="RPM packages for Tor 0.4.9.16 are live.", updated_at="2026-11-10T13:00:00Z")
    store.ingest(m1, LATER)
    store.ingest(m2, LATER)
    rows = {r["url"]: mapped_item(store, r, release_id) for r in store.pending(5, LATER)}
    w1 = Writer(update_analysis(update="Debian packages are live.", confidence="confirmed", state="released",
                                evidence=["Debian packages for Tor 0.4.9.16 are live."]))
    with pytest.raises(AnalysisError):
        run(cfg, store, rows["https://example.org/m1"], w1, Reviewer(AnalysisError("timeout", retryable=True)))
    assert len(w1.calls) == 1
    assert run(cfg, store, rows["https://example.org/m2"],
               Writer(update_analysis(update="RPM packages are live.", confidence="confirmed", state="released",
                                      evidence=["RPM packages for Tor 0.4.9.16 are live."])),
               Reviewer(verdict(update=True)))["status"] == "published"
    res = run(cfg, store, rows["https://example.org/m1"], w1, Reviewer(verdict(update=True)))
    assert res["status"] == "published" and res["writer_calls"] == 1 and len(w1.calls) == 2 and len(store.stories()[0]["updates"]) == 2

    issue_url = "https://gitlab.torproject.org/tpo/core/tor/-/issues/49500"
    canonical_issue_url = "https://gitlab.torproject.org/tpo/core/tor/-/work_items/49500"
    issue_a = item(id="gitlab:49500", kind="gitlab_issue", url=issue_url, title="Tor 0.4.9.30 relay descriptor stall",
                   content="Initial report of descriptor stall in Tor 0.4.9.30.", published_at="2026-11-08T10:00:00Z",
                   updated_at="2026-11-08T10:00:00Z", public_comments=[])
    assert run(
        cfg, store, pending(store, issue_a),
        Writer(analysis(title="Descriptor stall reported in Tor 0.4.9.30", summary="Initial report of descriptor stall in Tor 0.4.9.30.",
                        state="developing", evidence=["Initial report of descriptor stall in Tor 0.4.9.30."])),
        Reviewer(verdict()), "2026-11-08T10:05:00Z",
    )["status"] == "published"
    story_id = next(s for s in store.stories(10) if "0.4.9.30" in s["title"])["id"]

    other_src = item(kind="gitlab_mr", url="https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/1950",
                     title="Investigate descriptor stall (closes #49500)", content="Closes #49500 with diagnostic logging.",
                     upstream_state="merged", published_at="2026-11-10T12:00:00Z", updated_at="2026-11-10T12:00:00Z")
    assert run(
        cfg, store, pending(store, other_src),
        Writer(update_analysis(update="A merge request added diagnostic logging for the stall.", state="merged",
                               evidence=["Closes #49500 with diagnostic logging."])),
        Reviewer(verdict(update=True)), "2026-11-10T12:05:00Z",
    )["status"] == "published"

    note_v1 = make_note("501", "Root cause narrowed to malformed extra-info lines.", author="maintainer",
                        created_at="2026-11-09T09:00:00Z", url=issue_url, note_id="501", title="Comment by maintainer")
    assert store.ingest({**issue_a, "updated_at": "2026-11-09T09:00:00Z", "public_comments": [note_v1]}, "2026-11-11T08:00:00Z")
    w_nov9 = Writer(update_analysis(update="Maintainers narrowed the root cause to malformed extra-info lines.",
                                    state="merged", evidence=["Root cause narrowed to malformed extra-info lines."]))
    assert run(cfg, store, store.pending(1, "2026-11-11T08:00:00Z")[0], w_nov9,
               Reviewer(verdict(update=True)), "2026-11-11T08:00:00Z")["status"] == "published"
    assert len(w_nov9.calls) == 1
    assert next(s for s in store.stories(10) if s["id"] == story_id)["updates"][-1]["sources"] == [
        {"url": canonical_issue_url + "#note_501", "title": "Comment by maintainer"}]

    note_v2 = {**note_v1, "body": "Correction: extra-info parsing was unaffected; bug is in routerstatus retry."}
    issue_a_edited = {**issue_a, "updated_at": "2026-11-12T14:00:00Z", "public_comments": [note_v2]}
    assert store.ingest(issue_a_edited, "2026-11-12T14:05:00Z")
    w_edit = Writer(update_analysis(update="A corrected maintainer note places the bug in routerstatus retry.",
                                    state="merged", evidence=["Correction: extra-info parsing was unaffected; bug is in routerstatus retry."]))
    assert run(cfg, store, store.pending(1, "2026-11-12T14:05:00Z")[0], w_edit,
               Reviewer(verdict(update=True)), "2026-11-12T14:05:00Z")["status"] == "published"
    st_edit = next(s for s in store.stories(10) if s["id"] == story_id)
    assert st_edit["updates"][-1]["at"] == "2026-11-12T14:00:00Z"

    note_v2_quoted = {**note_v2, "body": note_v2["body"] + "\n\n> Earlier quoted context."}
    assert store.ingest({**issue_a, "updated_at": "2026-11-12T15:00:00Z", "public_comments": [note_v2_quoted]}, "2026-11-12T15:05:00Z")
    res_same = run(cfg, store, store.pending(1, "2026-11-12T15:05:00Z")[0], observed="2026-11-12T15:05:00Z")
    assert res_same["status"] == "ignored" and res_same["writer_calls"] == res_same["review_calls"] == 0
    assert review_gate.candidate_mod._source_cutoff(store.db, st_edit, None, issue_a_edited) == "2026-11-12T14:00:00Z"


def test_trusted_operator_vs_community_list_incidents_in_gate(context):
    """Distinguish trusted-operator reports, untrusted community claims, and numbered Tor proposals."""
    cfg, store = context
    list_base = "https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/message/"
    tordev_base = "https://lists.torproject.org/mailman3/hyperkitty/list/tor-dev@lists.torproject.org/message/"

    def _proposal(num, subject, action_clause):
        head = f"Proposal {num}: {subject}"
        row = pending(store, item(url=f"{tordev_base}prop{num}/", kind="feed", authority="community",
                                  title=f"[tor-dev] {head}",
                                  content=f"Proposal {num} {action_clause} circuit flooding and DoS attacks."))
        draft = analysis(title=head, summary=f"Proposal {num} on tor-dev {action_clause} circuit flooding and DoS attacks.",
                         category="protocol", tags=["protocol", "dos"], confidence="reported", state="developing",
                         evidence=[f"Proposal {num} {action_clause} circuit flooding"])
        return row, draft

    chat = pending(store, item(url=list_base + "chat1/", kind="feed", authority="trusted-operator",
                               content="Routine relay operator question about bandwidth."))
    assert run(cfg, store, chat, Writer(analysis(confidence="reported", category="relay", tags=["relay"],
                                                 title="Operator asks about relay bandwidth",
                                                 summary="An operator asks a routine question about relay bandwidth.",
                                                 evidence=["Routine relay operator question"])),
               Reviewer(verdict("skip", criterion="news_value")))["status"] == "ignored"
    assert codes(store, chat) == ["skipped.review.news_value"]

    trusted_inc = pending(store, item(url=list_base + "trusted1/", kind="feed", authority="trusted-operator",
                                      content="Large relay family observed sustained SYN flood across exit relays."))
    trusted_draft = analysis(title="Relay family reports sustained SYN flood on exit relays",
                             summary="A large relay operator reports a sustained SYN flood across exit relays.",
                             category="dos", tags=["dos"], confidence="reported", state="developing",
                             evidence=["Large relay family observed sustained SYN flood"])
    assert run(cfg, store, trusted_inc, Writer(trusted_draft), Reviewer(verdict()))["status"] == "published"

    untrusted_inc = pending(store, item(url=list_base + "comm1/", kind="feed", authority="community",
                                        content="Single operator claims relays face deanonymization attack."))
    untrusted_draft = analysis(title="Single operator claims relays face deanonymization attack",
                               summary="A mailing-list post claims relays face a deanonymization attack.",
                               category="security", tags=["security"], confidence="reported", state="developing",
                               evidence=["Single operator claims relays face deanonymization attack."])
    assert run(cfg, store, untrusted_inc, Writer(untrusted_draft), Reviewer(verdict()))["status"] == "held"
    assert codes(store, untrusted_inc) == ["held.final_check.untrusted_operator_claim"]

    prop_item, prop_draft = _proposal(375, "Rate-limiting circuit flooding", "specifies rate limits to defend against")
    assert run(cfg, store, prop_item, Writer(prop_draft), Reviewer(verdict()))["status"] == "published"

    prop_disputed, prop_disputed_draft = _proposal(376, "Circuit flood defense parameters", "adjusts rate-limiting parameters to mitigate")
    assert run(cfg, store, prop_disputed, Writer(prop_disputed_draft),
               Reviewer(verdict(), verdict("hold", criterion="news_value")))["status"] == "held"
    assert codes(store, prop_disputed) == ["held.verification.disagreed_news"]
    elig = review_gate.approval(cfg, store, prop_disputed["id"])
    assert elig["eligible"] is True
    approved = rejection.approve_item(cfg, store, prop_disputed["id"], elig["hash"], "Publish Tor proposal", observed=LATER)
    assert approved["status"] == "published"


@pytest.mark.parametrize("corruption", ["invalid_utf8", "nan", "surrogate", "deep"])
def test_process_item_evicts_damaged_review_approvals_and_completes_live_review(context, corruption):
    """Evict damaged `review_approvals` rows across invalid UTF-8, NaN, surrogates, and deep nesting."""
    cfg, store = context
    row = pending(store)
    prepared = store.prepare_candidate(row, analysis(), LATER)
    key = insert_approval(store, prepared, policy=review.policy_hash(cfg))["approval_key"]
    rec_text = store.db.execute("SELECT review_record_json FROM review_approvals WHERE key=?", (key,)).fetchone()[0]
    with store.db:
        if corruption == "invalid_utf8":
            store.db.execute("UPDATE review_approvals SET result_json=CAST(X'fffe' AS TEXT) WHERE key=?", (key,))
        elif corruption == "nan":
            store.db.execute("UPDATE review_approvals SET review_record_json=? WHERE key=?",
                             ('{"extra":NaN,' + rec_text[1:], key))
        elif corruption == "surrogate":
            store.db.execute("UPDATE review_approvals SET review_record_json=? WHERE key=?",
                             ('{"extra":"\\ud800",' + rec_text[1:], key))
        else:
            store.db.execute("UPDATE review_approvals SET result_json=? WHERE key=?", ("[" * 100 + "]" * 100, key))

    evicted_before_live = []

    def _check_and_approve(*_args, **_kwargs):
        evicted_before_live.append(
            store.db.execute("SELECT COUNT(*) FROM review_approvals WHERE key=?", (key,)).fetchone()[0]
        )
        return verdict()

    out = run(cfg, store, row, Writer(), Reviewer(_check_and_approve), LATER)
    assert out == {"status": "published", "writer_calls": 1, "review_calls": 2, "cache_hit": False}
    assert evicted_before_live == [0, 0]
    assert len(store.stories()) == 1


def test_coverage_background_skips_damaged_stories_and_source_packet_recovers_compacted_and_note_sources(context):
    """Skip damaged `stories` rows in `coverage_background` and recover URL-only compacted or note-only writer sources."""
    from onionflash import source_packet

    cfg, store = context
    valid_story = seed_story(store, item(url="https://example.org/valid-story"), analysis(), key="valid-1", at=DATE)
    with store.db:
        store.db.execute(
            "INSERT INTO stories(id,cluster_key,payload,published_at,updated_at) VALUES(?,?,?,?,?)",
            ("b" * 24, "damaged:json", "{malformed", DATE, LATER),
        )
        store.db.execute(
            "INSERT INTO stories(id,cluster_key,payload,published_at,updated_at) VALUES(?,?,CAST(X'fffe' AS TEXT),?,?)",
            ("c" * 24, "damaged:utf8", DATE, LATER),
        )
    cov = candidate.coverage_background(store.db, None)
    assert cov["truncated"] is True and [e["id"] for e in cov["recent"]] == [valid_story["id"]]
    next_row = pending(store, item(url="https://example.org/fresh-after-damaged", content="A fresh independent report."))
    assert run(cfg, store, next_row, Writer(analysis(evidence=["A fresh independent report."])), Reviewer(verdict()))["status"] == "published"

    comp_item = item(url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/49501",
                     title="Compacted historical ticket", content="Historical ticket body retained in analyses.")
    comp_story = seed_story(
        store, comp_item, analysis(title="Compacted historical ticket", summary="Historical ticket summary.",
                                   evidence=["Historical ticket body retained in analyses."]),
        key="comp-key", at=DATE,
    )
    comp_id = comp_story["editorial_item"]
    raw_stored = json.loads(store.db.execute("SELECT payload FROM items WHERE id=?", (comp_id,)).fetchone()[0])
    raw_stored.pop("content", None)
    with store.db:
        store.db.execute("UPDATE items SET payload=? WHERE id=?", (json.dumps(raw_stored), comp_id))
    loaded = source_packet._load(store.db, None, comp_item["url"], analysis_key=None)
    assert loaded is not None and loaded[2] == "historical-analysis"
    url_only_payload = {
        **json.loads(store.db.execute("SELECT payload FROM stories WHERE id=?", (comp_story["id"],)).fetchone()[0]),
        "sources": [{"url": comp_item["url"], "title": comp_item["title"]}],
    }
    url_only_payload.pop("editorial_item", None)
    pkt_comp, _ = source_packet.build_packet(
        store.db, {**comp_item, "id": "incoming-other", "url": "https://example.org/other"}, url_only_payload, url_only_payload, None
    )
    assert pkt_comp["missing_sources"] == [] and pkt_comp["truncated"] is False

    note_issue_url = "https://gitlab.torproject.org/tpo/core/tor/-/work_items/49502"
    note_entry = make_note(7, "Maintainer triage note with concrete reproduction details.", author="arma", url=note_issue_url)
    note_item = item(url=note_issue_url, kind="gitlab_issue", title="Issue with note-only citation",
                     content="Parent issue description text.", public_comments=[note_entry])
    note_story = seed_story(
        store, note_item, analysis(title="Issue with note-only citation", summary="Summary citing triage note.",
                                   evidence=["Maintainer triage note with concrete reproduction details."]),
        key="note-key", at=DATE,
    )
    writer_id = note_story["editorial_item"]
    note_only_src = {
        "id": f"{writer_id}:{note_entry['id']}",
        "source_item_id": writer_id,
        "url": note_entry["url"],
        "title": note_entry["title"],
        "published_at": note_entry["created_at"],
    }
    raw_note_story = {
        **json.loads(store.db.execute("SELECT payload FROM stories WHERE id=?", (note_story["id"],)).fetchone()[0]),
        "sources": [note_only_src],
    }
    pub_note_story = {**note_story, "sources": [{"url": note_entry["url"], "title": note_entry["title"]}]}
    incoming_follow = {**item(url="https://example.org/follow-49502", content="Follow-up report."), "id": "f" * 24}
    pkt_note, _ = source_packet.build_packet(
        store.db, incoming_follow, raw_note_story, pub_note_story, writer_id, update=True
    )
    assert pkt_note["missing_sources"] == [] and pkt_note["truncated"] is False
    assert any(s["url"] == note_issue_url for s in pkt_note["sources"])


def test_auto_merge_update_without_compact_overlap_and_mr_cap_update_states(context):
    """Avoid invalid `routed` handoffs when compact coverage lacks source URLs, and preserve update states across MR caps."""
    from onionflash import publication

    cfg, store = context
    padding = (
        "Operators observed sustained circuit setup delays across multiple independent vantage points "
        "during peak consensus intervals while investigating relay descriptor propagation behavior across "
        "affected network segments and recording hourly telemetry samples for comparison."
    )
    surv_src = item(
        url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/49200",
        kind="gitlab_issue",
        title="Sustained circuit setup delays across relays",
        content=padding,
        published_at="2026-11-08T10:00:00Z",
        updated_at="2026-11-08T10:00:00Z",
    )
    surv_story = seed_story(
        store,
        surv_src,
        analysis(
            title="Sustained circuit setup delays across relays",
            summary=padding,
            why_it_matters="",
            category="relay",
            tags=["relay"],
            confidence="reported",
            state="developing",
            evidence=["Operators observed sustained circuit setup delays"],
        ),
        key="surv-49200",
        at="2026-11-08T10:05:00Z",
    )
    dup_src = item(
        url="https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/message/DUP49200/",
        kind="feed",
        authority="trusted-operator",
        title="Follow-up notes on ticket",
        content="Independent log review for #49200 found matching symptoms on two BSD guards.",
        published_at="2026-11-08T11:00:00Z",
        updated_at="2026-11-08T11:00:00Z",
    )
    dup_story = seed_story(
        store,
        dup_src,
        analysis(
            title="Follow-up notes on guard symptoms",
            summary="Independent log review for #49200 found matching symptoms on two BSD guards.",
            why_it_matters="",
            category="relay",
            tags=["relay"],
            confidence="reported",
            state="developing",
            evidence=["Independent log review for #49200 found matching symptoms"],
        ),
        key="dup-49200",
        at="2026-11-08T11:05:00Z",
    )
    publication.build(cfg, store)

    upd_src = item(
        url="https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/message/UPD49200/",
        kind="feed",
        authority="trusted-operator",
        title="Additional guard telemetry",
        content="Additional guard telemetry confirms the BSD socket buffer threshold.",
        published_at="2026-11-08T12:00:00Z",
        updated_at="2026-11-08T12:00:00Z",
    )
    upd_row = pending(store, upd_src, at="2026-11-08T12:05:00Z", ready="2026-11-08T12:05:00Z")
    with store.db:
        store.db.execute("UPDATE items SET story_id=? WHERE id=?", (dup_story["id"], upd_row["id"]))
    upd_row = item_row(store, upd_row)
    upd_draft = update_analysis(
        update="Additional guard telemetry reports a BSD socket buffer threshold.",
        confidence="reported",
        state="developing",
        evidence=["Additional guard telemetry confirms the BSD socket buffer threshold."],
    )
    same_reply = {**verdict(update=True), "same_story": surv_story["id"]}
    res = run(cfg, store, upd_row, Writer(upd_draft), Reviewer(same_reply, same_reply), "2026-11-08T12:10:00Z")
    assert res["status"] == "published" and job(store, upd_row) is None

    mr1 = item(
        url="https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/801",
        kind="gitlab_mr",
        upstream_state="merged",
        title="Initial merge for 0.4.9.6",
        content="Merged initial patch for 0.4.9.6.",
    )
    mr_story = seed_story(
        store,
        mr1,
        analysis(
            title="Initial merge for 0.4.9.6",
            summary="Maintainers merged the initial patch.",
            why_it_matters="",
            category="feature",
            tags=["feature"],
            confidence="confirmed",
            state="merged",
            evidence=["Merged initial patch for 0.4.9.6."],
        ),
        key="mr-801",
        at="2026-11-08T08:00:00Z",
    )
    tag_item = tag(url="https://gitlab.torproject.org/tpo/core/tor/-/tags/tor-0.4.9.6", title="tor-0.4.9.6",
                   updated_at="2026-11-08T09:00:00Z")
    tag_row = pending(store, tag_item, at="2026-11-08T09:00:00Z", ready="2026-11-08T09:00:00Z")
    with store.db:
        store.db.execute("UPDATE items SET story_id=? WHERE id=?", (mr_story["id"], tag_row["id"]))
    assert run(cfg, store, item_row(store, tag_row), Writer(), Reviewer(verdict(update=True)), "2026-11-08T09:05:00Z")["status"] == "published"
    tagged_story = next(s for s in store.stories() if s["id"] == mr_story["id"])
    assert tagged_story["state"] == "tagged"
    for idx in range(2, 9):
        mr_i = item(
            url=f"https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/{800 + idx}",
            kind="gitlab_mr",
            upstream_state="merged",
            title=f"Follow-up merge {idx}",
            content=f"Merged follow-up patch {idx} into main.",
            updated_at=f"2026-11-08T09:{10 + idx:02d}:00Z",
        )
        r_i = pending(store, mr_i, at=mr_i["updated_at"], ready=mr_i["updated_at"])
        with store.db:
            store.db.execute("UPDATE items SET story_id=? WHERE id=?", (mr_story["id"], r_i["id"]))
        assert run(
            cfg, store, item_row(store, r_i),
            Writer(update_analysis(update=f"Follow-up merge {idx} landed.", confidence="confirmed", state="tagged",
                                   evidence=[f"Merged follow-up patch {idx} into main."])),
            Reviewer(verdict(update=True)), mr_i["updated_at"],
        )["status"] == "published"
    mr_9 = item(
        url="https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/809",
        kind="gitlab_mr",
        upstream_state="merged",
        title="Follow-up merge 9",
        content="Merged follow-up patch 9 into main.",
        updated_at="2026-11-08T10:30:00Z",
    )
    r_9 = pending(store, mr_9, at=mr_9["updated_at"], ready=mr_9["updated_at"])
    with store.db:
        store.db.execute("UPDATE items SET story_id=? WHERE id=?", (mr_story["id"], r_9["id"]))
    res_9 = run(
        cfg, store, item_row(store, r_9),
        Writer(update_analysis(update="Follow-up merge 9 landed.", confidence="confirmed", state="tagged",
                               evidence=["Merged follow-up patch 9 into main."])),
        Reviewer(verdict(update=True)), mr_9["updated_at"],
    )
    assert res_9["status"] == "published"
    reloaded_story = next(s for s in store.stories() if s["id"] == mr_story["id"])
    assert reloaded_story["state"] == "tagged"
    assert reloaded_story["updates"][-1]["text"] == "Follow-up merge 9 landed."


def test_related_lookup_skips_damaged_story_payloads_and_associate_raises_value_error(context):
    """Skip damaged `stories` rows during related lookups while failing damaged direct associations cleanly."""
    cfg, store = context
    damaged_src = item(
        url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/499",
        kind="gitlab_issue",
        title="Damaged referenced ticket #499",
        content="Initial description for ticket #499.",
    )
    damaged_story = seed_story(
        store,
        damaged_src,
        analysis(title="Damaged referenced ticket #499", summary="Initial summary for #499.",
                 evidence=["Initial description for ticket #499."]),
        key="damaged-499",
        at=DATE,
    )
    with store.db:
        store.db.execute(
            "UPDATE stories SET payload=CAST(X'7b22626164223afffe7d' AS TEXT) WHERE id=?",
            (damaged_story["id"],),
        )
    mapped_row = store.db.execute("SELECT * FROM items WHERE url=?", (damaged_src["url"],)).fetchone()
    with pytest.raises(ValueError, match="Damaged story payload"):
        candidate.associate(store.db, dict(mapped_row))

    followup_src = item(
        url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/500",
        kind="gitlab_issue",
        title="Follow-up investigation on relay memory",
        content="Investigation referencing #499 reports independent heap findings.",
        published_at=LATER,
        updated_at=LATER,
    )
    row = pending(store, followup_src, at=LATER, ready=LATER)
    draft = analysis(
        title="Independent heap findings reported in #500",
        summary="Ticket #500 reports independent heap findings referencing #499.",
        evidence=["Investigation referencing #499 reports independent heap findings."],
    )
    res = run(cfg, store, row, Writer(draft), Reviewer(verdict()), LATER)
    assert res["status"] == "published"


def test_official_duplicate_update_skips_and_auto_merges_without_holding(context):
    """Allow verified official duplicate `update` skips to auto-merge or ignore rather than holding."""
    from onionflash import publication

    cfg, store = context
    early_at = "2026-11-08T10:00:00Z"
    mid_at = "2026-11-08T14:00:00Z"
    older = seed_story(
        store,
        item(
            url="https://blog.torproject.org/tor-04988-release/",
            kind="feed",
            authority="official",
            product="tor",
            title="New Release: Tor 0.4.9.88",
            content="Tor 0.4.9.88 fixes a relay descriptor stall.",
            published_at=early_at,
            updated_at=early_at,
        ),
        analysis(
            title="Tor 0.4.9.88 released",
            summary="Tor 0.4.9.88 fixes a relay descriptor stall.",
            why_it_matters="",
            category="release",
            tags=["release"],
            confidence="confirmed",
            state="released",
            products=["tor"],
            evidence=["Tor 0.4.9.88 fixes a relay descriptor stall."],
        ),
        key="older-04988",
        at=early_at,
    )
    newer_dup = seed_story(
        store,
        item(
            url="https://lists.torproject.org/tor-announce/tor-04988-note/",
            kind="feed",
            authority="official",
            product="tor",
            title="Relay descriptor stall notice for 0.4.9.88",
            content="Official announcement summarizing the 0.4.9.88 descriptor stall.",
            published_at=mid_at,
            updated_at=mid_at,
        ),
        analysis(
            title="Official notice on Tor 0.4.9.88 descriptor stall",
            summary="Official notice describes the Tor 0.4.9.88 descriptor stall.",
            why_it_matters="",
            category="release",
            tags=["release"],
            confidence="confirmed",
            state="released",
            products=["tor"],
            evidence=["Official announcement summarizing the 0.4.9.88 descriptor stall."],
        ),
        key="newer-04988",
        at=mid_at,
    )
    reported_older = seed_story(
        store,
        item(
            url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/49880",
            kind="gitlab_issue",
            authority="development",
            product="tor",
            title="Descriptor parsing defect on 0.4.9.89",
            content="Issue #49880 tracks a descriptor parsing defect on 0.4.9.89.",
            published_at=early_at,
            updated_at=early_at,
        ),
        analysis(
            title="Descriptor parsing defect tracked for 0.4.9.89",
            summary="Issue #49880 tracks a descriptor parsing defect on 0.4.9.89.",
            why_it_matters="",
            confidence="reported",
            state="developing",
            products=["tor"],
            evidence=["Issue #49880 tracks a descriptor parsing defect on 0.4.9.89."],
        ),
        key="rep-49880",
        at=early_at,
    )
    confirmed_dup = seed_story(
        store,
        item(
            url="https://blog.torproject.org/tor-04989-notice/",
            kind="feed",
            authority="official",
            product="tor",
            title="Official note on 0.4.9.89 descriptor parsing defect",
            content="Official notice covering #49880 descriptor parsing defect on 0.4.9.89.",
            published_at=mid_at,
            updated_at=mid_at,
        ),
        analysis(
            title="Official note on 0.4.9.89 descriptor parsing defect",
            summary="Official note covers #49880 descriptor parsing defect on 0.4.9.89.",
            why_it_matters="",
            confidence="confirmed",
            state="developing",
            products=["tor"],
            evidence=["Official notice covering #49880 descriptor parsing defect on 0.4.9.89."],
        ),
        key="conf-49880",
        at=mid_at,
    )
    publication.build(cfg, store)

    upd_row = pending(
        store,
        item(
            url="https://lists.torproject.org/tor-announce/tor-04988-mirror/",
            kind="feed",
            authority="official",
            product="tor",
            title="Mirror announcement for Tor 0.4.9.88",
            content="Tor 0.4.9.88 fixes a relay descriptor stall (mirror copy).",
            published_at=LATER,
            updated_at=LATER,
        ),
        at=LATER,
        ready=LATER,
    )
    with store.db:
        store.db.execute("UPDATE items SET story_id=? WHERE id=?", (newer_dup["id"], upd_row["id"]))
    upd_row = item_row(store, upd_row)
    skip_same = verdict(
        "skip",
        criterion="new_information",
        update=True,
        same_story=older["id"],
        reason=f"Already covered in {older['id']}.",
    )
    res_auto = run(
        cfg, store, upd_row,
        Writer(update_analysis(
            update="Tor 0.4.9.88 fixes a relay descriptor stall.",
            confidence="confirmed",
            state="released",
            evidence=["Tor 0.4.9.88 fixes a relay descriptor stall (mirror copy)."],
        )),
        Reviewer(skip_same, skip_same),
        LATER,
    )
    assert res_auto["status"] == "routed" and res_auto["review_calls"] == 2
    assert editorial.retired(store.db, story_id=newer_dup["id"]) == (newer_dup["id"], older["id"])

    upd_lossy = pending(
        store,
        item(
            url="https://lists.torproject.org/tor-announce/tor-04989-mirror/",
            kind="feed",
            authority="official",
            product="tor",
            title="Mirror announcement for 0.4.9.89",
            content="Mirror note covering #49880 descriptor parsing defect on 0.4.9.89.",
            published_at=LATER,
            updated_at=LATER,
        ),
        at=LATER,
        ready=LATER,
    )
    with store.db:
        store.db.execute("UPDATE items SET story_id=? WHERE id=?", (confirmed_dup["id"], upd_lossy["id"]))
    upd_lossy = item_row(store, upd_lossy)
    skip_lossy = verdict(
        "skip",
        criterion="new_information",
        update=True,
        same_story=reported_older["id"],
        reason=f"Already covered in {reported_older['id']}.",
    )
    res_lossy = run(
        cfg, store, upd_lossy,
        Writer(update_analysis(
            update="Mirror note covers the 0.4.9.89 descriptor parsing defect.",
            confidence="confirmed",
            state="developing",
            evidence=["Mirror note covering #49880 descriptor parsing defect on 0.4.9.89."],
        )),
        Reviewer(skip_lossy, skip_lossy),
        LATER,
    )
    assert res_lossy["status"] == "ignored" and res_lossy["review_calls"] == 2
    assert codes(store, upd_lossy) == ["skipped.verification.new_information"]


def test_source_packet_deduplicates_note_source_and_bare_parent_without_id(context):
    """Emit only one source unit when a `#note_` `source_item_id` entry coexists with an id-less parent link."""
    from onionflash import publication, source_packet

    cfg, store = context
    issue_url = "https://gitlab.torproject.org/tpo/core/tor/-/work_items/49550"
    note_entry = make_note(15, "Maintainer confirmed the root cause in cell handling.", author="arma", url=issue_url)
    parent_item = item(
        url=issue_url,
        kind="gitlab_issue",
        title="Cell handling issue #49550",
        content="Initial parent issue body for #49550.",
        public_comments=[note_entry],
    )
    seeded = seed_story(
        store,
        parent_item,
        analysis(
            title="Cell handling issue #49550",
            summary="Maintainer confirmed the root cause in cell handling.",
            evidence=["Maintainer confirmed the root cause in cell handling."],
        ),
        key="key-49550",
        at=DATE,
    )
    writer_id = seeded["editorial_item"]
    note_src = {
        "id": f"{writer_id}:{note_entry['id']}",
        "source_item_id": writer_id,
        "url": note_entry["url"],
        "title": note_entry["title"],
        "published_at": note_entry["created_at"],
    }
    raw_payload = json.loads(store.db.execute("SELECT payload FROM stories WHERE id=?", (seeded["id"],)).fetchone()[0])
    raw_payload["sources"] = [note_src]
    with store.db:
        store.db.execute("UPDATE stories SET payload=? WHERE id=?", (json.dumps(raw_payload), seeded["id"]))
    publication.build(cfg, store)

    shown = editorial.show(store.db, seeded["id"])
    editorial.correct(
        store.db,
        seeded["id"],
        {
            "sources": [
                {"url": note_entry["url"], "title": note_entry["title"]},
                {"url": issue_url, "title": parent_item["title"]},
            ]
        },
        reason="Add parent issue URL alongside cited note.",
        expect_hash=shown["hash"],
        observed=LATER,
    )
    corrected_payload = json.loads(store.db.execute("SELECT payload FROM stories WHERE id=?", (seeded["id"],)).fetchone()[0])
    corrected_public = editorial.show(store.db, seeded["id"])["story"]
    assert any(s.get("source_item_id") == writer_id and "#note_" in s["url"] for s in corrected_payload["sources"])
    assert any(s["url"] == issue_url and "id" not in s and "source_item_id" not in s for s in corrected_payload["sources"])

    followup = {
        **item(url="https://example.org/follow-49550", content="Follow-up report on #49550."),
        "id": "e" * 24,
    }
    pkt, _ = source_packet.build_packet(
        store.db, followup, corrected_payload, corrected_public, writer_id, update=True
    )
    assert pkt["missing_sources"] == [] and pkt["truncated"] is False
    assert [s["id"] for s in pkt["sources"]] == ["S1"]
    assert [s["url"] for s in pkt["sources"]] == [issue_url]
    assert any(
        p.get("url") == note_entry["url"] and note_entry["body"] in p.get("text", "")
        for p in pkt["sources"][0]["passages"]
    )


def test_control_fingerprint_distinguishes_blob_and_non_text_editorial_values(context):
    """Distinguish SQLite BLOB and integer editorial controls from matching hex text in binding verification."""
    _, store = context
    src = item(url="https://example.org/control-fp", content="Initial relay operational notice.")
    seeded = seed_story(store, src, analysis(summary=src["content"], evidence=[src["content"]]), key="ctrl-fp", at=DATE)
    followup = item(url="https://example.org/control-fp-follow", content="Follow-up operational notice.", updated_at=LATER)
    row = pending(store, followup, at=LATER, ready=LATER)
    with store.db:
        store.db.execute("UPDATE items SET story_id=? WHERE id=?", (seeded["id"], row["id"]))
        store.db.execute(
            "INSERT INTO editorial_controls(story_id,revision,locked,retracted,notice_action,notice_reason,notice_at) "
            "VALUES(?,1,0,0,'correct','cafe',?)",
            (seeded["id"], DATE),
        )
    text_fp = candidate.control_fingerprint(store.db, seeded["id"])
    prepared = candidate.prepare(
        store.db, item_row(store, row),
        update_analysis(update=followup["content"], evidence=[followup["content"]]), LATER,
    )
    candidate.verify_prepared_binding(store.db, prepared)

    with store.db:
        store.db.execute("UPDATE editorial_controls SET notice_reason=X'cafe' WHERE story_id=?", (seeded["id"],))
    blob_fp = candidate.control_fingerprint(store.db, seeded["id"])
    assert blob_fp != text_fp
    with pytest.raises(candidate.StaleCandidate, match="Editorial controls changed"):
        candidate.verify_prepared_binding(store.db, prepared)

    with store.db:
        store.db.execute("UPDATE editorial_controls SET notice_reason='313233' WHERE story_id=?", (seeded["id"],))
    text_digits_fp = candidate.control_fingerprint(store.db, seeded["id"])
    with store.db:
        store.db.execute("UPDATE editorial_controls SET notice_reason=123 WHERE story_id=?", (seeded["id"],))
    int_fp = candidate.control_fingerprint(store.db, seeded["id"])
    with store.db:
        store.db.execute("UPDATE editorial_controls SET notice_reason=X'313233' WHERE story_id=?", (seeded["id"],))
    blob_digits_fp = candidate.control_fingerprint(store.db, seeded["id"])
    assert len({text_digits_fp, int_fp, blob_digits_fp}) == 3

    with store.db:
        store.db.execute("UPDATE editorial_controls SET notice_reason='cafe' WHERE story_id=?", (seeded["id"],))
    assert candidate.control_fingerprint(store.db, seeded["id"]) == text_fp


def test_route_rejects_blob_typed_target_story_payload(context):
    """Refuse to attach a routed item to a target story whose `stories.payload` is stored as BLOB."""
    cfg, store = context
    target = seed_story(
        store,
        item(url="https://example.org/blob-route-target", title="Authority overload report",
             content="Operators report directory authority overload."),
        analysis(title="Authority overload report", summary="Operators report directory authority overload.",
                 evidence=["Operators report directory authority overload."]),
        key="blob-route-target",
        at=DATE,
    )
    followup_row = pending(
        store,
        item(url="https://example.org/blob-route-followup", title="Follow-up authority report",
             content="Follow-up report on directory authority overload.", published_at=LATER, updated_at=LATER),
        at=LATER,
        ready=LATER,
    )
    orig_route = review_gate._route

    def _mutate_target_to_blob(st, *args, **kwargs):
        with st.db:
            st.db.execute("UPDATE stories SET payload=CAST(payload AS BLOB) WHERE id=?", (target["id"],))
        return orig_route(st, *args, **kwargs)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(review_gate, "_route", _mutate_target_to_blob)
        res = run(
            cfg, store, followup_row, Writer(),
            Reviewer(verdict(same_story=target["id"])), LATER,
        )
    assert res["status"] == "stale"
    assert store.db.execute("SELECT story_id FROM items WHERE id=?", (followup_row["id"],)).fetchone()[0] is None


def test_source_packet_matches_gitlab_project_case_while_keeping_blob_paths_case_sensitive(context):
    """Match GitLab project-path case on current and historical citations without equating distinct blob paths."""
    from onionflash import source_packet

    _, store = context
    stored_issue_url = "https://gitlab.torproject.org/tpo/core/tor/-/work_items/49777"
    mixed_issue_url = "https://gitlab.torproject.org/TPO/Core/Tor/-/issues/49777"
    issue_item = item(
        url=stored_issue_url,
        kind="gitlab_issue",
        title="Relay circuit scheduling regression #49777",
        content="Relay circuit scheduling regression details for #49777.",
    )
    store.ingest(issue_item, DATE)

    blob_lower_url = "https://gitlab.torproject.org/tpo/core/tor/-/blob/main/readme.md"
    blob_upper_url = "https://gitlab.torproject.org/tpo/core/tor/-/blob/main/README.md"
    mixed_blob_upper_url = "https://gitlab.torproject.org/TPO/Core/Tor/-/blob/main/README.md"
    blob_lower = item(url=blob_lower_url, kind="feed", title="Lowercase readme", content="Lowercase blob text.")
    blob_upper = item(url=blob_upper_url, kind="feed", title="Uppercase README", content="Uppercase blob text.")
    store.ingest(blob_lower, DATE)
    store.ingest(blob_upper, DATE)

    incoming = {**item(url="https://example.org/incoming-49777", content="Incoming follow-up."), "id": "f" * 24}
    payload = {
        "sources": [
            {"id": incoming["id"], "url": incoming["url"]},
            {"url": mixed_issue_url, "title": issue_item["title"]},
            {"url": mixed_blob_upper_url, "title": blob_upper["title"]},
        ]
    }
    public = {"sources": [{"url": mixed_issue_url}, {"url": mixed_blob_upper_url}]}
    pkt, _ = source_packet.build_packet(store.db, incoming, payload, public, None)
    assert pkt["missing_sources"] == [] and pkt["truncated"] is False
    urls = [s["url"] for s in pkt["sources"]]
    assert stored_issue_url in urls and blob_upper_url in urls
    assert any("Uppercase blob text." in p["text"] for s in pkt["sources"] if s["url"] == blob_upper_url for p in s["passages"])

    # A citation to a missing uppercase blob path must not match a stored lowercase blob path.
    only_lower_url = "https://gitlab.torproject.org/tpo/core/tor/-/blob/main/notes.md"
    wrong_case_url = "https://gitlab.torproject.org/TPO/Core/Tor/-/blob/main/NOTES.md"
    store.ingest(item(url=only_lower_url, kind="feed", title="notes.md", content="Lowercase notes text."), DATE)
    pkt_mismatch, _ = source_packet.build_packet(
        store.db, incoming,
        {"sources": [{"id": incoming["id"], "url": incoming["url"]}, {"url": wrong_case_url, "title": "NOTES.md"}]},
        {"sources": [{"url": wrong_case_url}]},
        None,
    )
    assert wrong_case_url in pkt_mismatch["missing_sources"]

    # Historical analysis snapshots also match across GitLab project-path case differences.
    hist_item = {**issue_item, "content": "Historical issue snapshot text for #49777."}
    with store.db:
        store.db.execute(
            "INSERT INTO analyses(cache_key,result,created_at,source_payload,source_item_id) "
            "VALUES(?,?,?,?,?)",
            ("hist-case-key", "{}", DATE, json.dumps(hist_item), issue_item["id"]),
        )
        store.db.execute(
            "UPDATE items SET payload=? WHERE id=?",
            (json.dumps({**issue_item, "content": "", "title": ""}), issue_item["id"]),
        )
    pkt_hist, _ = source_packet.build_packet(
        store.db, incoming,
        {"sources": [{"id": incoming["id"], "url": incoming["url"]}, {"url": mixed_issue_url, "title": issue_item["title"]}]},
        {"sources": [{"url": mixed_issue_url}]},
        None,
    )
    assert pkt_hist["missing_sources"] == []
    hist_unit = next(s for s in pkt_hist["sources"] if s["url"] == stored_issue_url)
    assert hist_unit["snapshot"] == "historical-analysis"
    assert any("Historical issue snapshot text" in p["text"] for p in hist_unit["passages"])


@pytest.mark.parametrize("replies", [
    [verdict(), verdict("skip", criterion="news_value"), verdict("skip", criterion="news_value")],
    [verdict(), verdict("skip", criterion="news_value"), verdict("hold", criterion="news_value")],
    [verdict(), verdict("skip", criterion="news_value"),
     verdict("revise", criterion="news_value", repair={"summary": "Concise operational details."})],
])
def test_tiebreak_three_vote_skip_outcomes(context, replies):
    """Skip non-official items after a 2-1 news-value vote regardless of tiebreak hold or revise action."""
    cfg, store = context
    row = pending(store)
    checker = Reviewer(*replies)
    result = run(cfg, store, row, Writer(), checker)
    assert result["status"] == "ignored" and result["review_calls"] == 3
    assert [c[2] for c in checker.calls] == [False, True, True]
    assert codes(store, row) == ["skipped.verification.news_value"] and store.stories() == []
    assert store.db.execute("SELECT last_error FROM items WHERE id=?", (row["id"],)).fetchone()[0] == "Final review skipped: news_value"
    rec = audit(store)
    assert rec["outcome"] == "skipped" and rec["approval_key"]
    assert len(rec["reviews"]) == 3
    assert "tiebreaker" not in rec["reviews"][0] and "tiebreaker" not in rec["reviews"][1]
    assert rec["reviews"][2]["tiebreaker"] is True


@pytest.mark.parametrize("official,replies,expected_calls", [
    (False, [verdict(), verdict("skip", criterion="news_value"), verdict()], 3),
    (True, [verdict("skip", criterion="news_value"), verdict(), verdict()], 3),
    (False, [verdict(), verdict("skip", criterion="news_value"),
             verdict("revise", criterion="operational_advice", repair={"summary": "Repaired after tiebreak."}),
             verdict()], 4),
    (True, [verdict("skip", criterion="news_value"), verdict(),
            verdict("revise", criterion="operational_advice", repair={"summary": "Official repaired after tiebreak."}),
            verdict()], 4),
])
def test_tiebreak_three_vote_approve_and_repair_paths(context, official, replies, expected_calls):
    """Approve or repair-and-verify cleanly when 2 of 3 news-value votes find an item newsworthy."""
    cfg, store = context
    row = pending(store, item(id="https://example.org/tie-approve", url="https://example.org/tie-approve",
                              **({"authority": "official"} if official else {})))
    checker = Reviewer(*replies)
    result = run(cfg, store, row, Writer(), checker)
    assert result["status"] == "published" and result["review_calls"] == expected_calls
    assert [c[2] for c in checker.calls] == [False] + [True] * (expected_calls - 1)
    assert codes(store, row) == ["published.new"] and len(store.stories()) == 1
    rec = audit(store)
    assert len(rec["reviews"]) == expected_calls and rec["reviews"][2]["tiebreaker"] is True
    if expected_calls == 4:
        assert "tiebreaker" not in rec["reviews"][3]
        assert store.stories()[0]["summary"] == replies[2]["repair"]["summary"]


def test_tiebreak_official_not_news_hold_preservation(context):
    """Preserve `official_not_news` holds and operator approval eligibility on 2-1 not-newsworthy official votes."""
    cfg, store = context
    for idx, replies in enumerate([
        [verdict(), verdict("skip", criterion="news_value"), verdict("skip", criterion="news_value")],
        [verdict("skip", criterion="news_value"), verdict(), verdict("skip", criterion="news_value")],
    ]):
        row = pending(store, item(id=f"https://example.org/official-tie-{idx}",
                                  url=f"https://example.org/official-tie-{idx}", authority="official"))
        checker = Reviewer(*replies)
        result = run(cfg, store, row, Writer(), checker)
        assert result["status"] == "held" and result["review_calls"] == 3
        assert codes(store, row) == ["held.verification.official_not_news"]
        rec = audit(store, row["id"])
        assert rec["hold_code"] == "official_not_news" and rec["reviews"][2]["tiebreaker"] is True
        assert rec["verified_facts"] is True
        app = review_gate.approval(cfg, store, row["id"])
        assert app["eligible"] is True and app["hash"]
        approved = rejection.approve_item(cfg, store, row["id"], app["hash"],
                                          "Editorial override after tiebreak", observed=LATER)
        assert approved["story_id"] and codes(store, row) == ["held.verification.official_not_news", "operator.approved"]
    assert len(store.stories()) == 2


def test_tiebreak_factual_fail_and_new_information_hold(context):
    """Hold cleanly when a tiebreaker fails factual criteria or `new_information`."""
    cfg, store = context
    cases = [
        ([verdict(), verdict("skip", criterion="news_value"), verdict("hold", criterion="source_support")],
         "held.verification.model_hold", False, False, 3),
        ([verdict(), verdict("skip", criterion="news_value"),
          verdict("revise", criterion="source_support", repair={"summary": "Operational details edited for facts."}),
          verdict("hold", criterion="source_support")],
         "held.verification.model_hold", False, False, 4),
        ([verdict(), verdict("skip", criterion="news_value"), verdict("skip", criterion="new_information")],
         "held.verification.disagreed_news", False, True, 3),
        ([verdict(), verdict("skip", criterion="news_value"),
          verdict("hold", criterion="news_value", criteria={"news_value": {"outcome": "insufficient", "reason": "Inconclusive news value."}})],
         "held.verification.disagreed_news", True, True, 3),
    ]
    for idx, (replies, expected_code, can_approve, expected_facts, expected_calls) in enumerate(cases):
        row = pending(store, item(id=f"https://example.org/tie-fail-{idx}", url=f"https://example.org/tie-fail-{idx}"))
        checker = Reviewer(*replies)
        result = run(cfg, store, row, Writer(), checker)
        assert result["status"] == "held" and result["review_calls"] == expected_calls
        assert codes(store, row) == [expected_code]
        assert audit(store, row["id"])["verified_facts"] is expected_facts
        app = review_gate.approval(cfg, store, row["id"])
        assert app["eligible"] is can_approve
        if not can_approve:
            with pytest.raises(ValueError, match="source_support|new_information"):
                rejection.approve_item(cfg, store, row["id"], "0" * 64,
                                       "Cannot bypass failed verification", observed=LATER)


def test_tiebreak_interrupted_recovery_and_damaged_tiebreaker(context):
    """Resume interrupted `tiebreak` jobs safely and fail closed on tampered `tiebreaker` state."""
    cfg, store = context
    row = pending(store)
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), Reviewer(verdict(), verdict("skip", criterion="news_value"),
                                                AnalysisError("timeout", retryable=True)))
    assert job(store)["stage"] == "tiebreak"
    assert job_record(store)["request_budget"]["reserved"] == 3
    assert len(job_record(store)["reviews"]) == 2
    assert run(cfg, store, row, Writer(), ApprovingReviewer(), allow_network=False)["status"] == "deferred"
    resumed = Reviewer(verdict())
    result = run(cfg, store, row, Writer(), resumed)
    assert result["status"] == "published" and result["review_calls"] == 1
    assert [c[2] for c in resumed.calls] == [True]
    assert audit(store)["reviews"][2]["tiebreaker"] is True and len(store.stories()) == 1

    bad_row = pending(store, item(id="https://example.org/tie-bad", url="https://example.org/tie-bad"))
    with pytest.raises(AnalysisError):
        run(cfg, store, bad_row, Writer(), Reviewer(verdict(), verdict("skip", criterion="news_value"),
                                                    AnalysisError("timeout", retryable=True)))
    rec = job_record(store, bad_row["id"])
    rec["reviews"][1]["tiebreaker"] = True
    with store.db:
        store.db.execute("UPDATE review_jobs SET record_json=? WHERE item_id=?", (json.dumps(rec), bad_row["id"]))
    with pytest.raises(AnalysisError) as exc:
        run(cfg, store, bad_row, Writer(), ApprovingReviewer())
    assert exc.value.code == "app.damaged_job"


def test_tiebreak_validation_reask_and_untrusted_proposal(llm_context):
    """Handle validation re-ask and untrusted proposal verification cleanly during `tiebreak`."""
    cfg, store = llm_context
    row = pending(store)
    reask_checker = wire_reviewer(cfg, verdict(), verdict("skip", criterion="news_value"),
                                  inconsistent({"summary": analysis()["summary"]}), verdict())
    result = run(cfg, store, row, Writer(), reask_checker)
    assert result["status"] == "published" and reask_checker.calls == 4 and len(store.stories()) == 1
    rec = audit(store)
    assert len(rec["reviews"]) == 3 and rec["reviews"][2]["tiebreaker"] is True and rec["reviews"][2]["reask_response"]

    row_prop = pending(store, item(id="https://example.org/tie-prop", url="https://example.org/tie-prop"))
    prop_checker = wire_reviewer(cfg, verdict(), verdict("skip", criterion="news_value"),
                                 inconsistent(), verdict("skip", criterion="news_value"))
    res_prop = run(cfg, store, row_prop, Writer(), prop_checker)
    assert res_prop["status"] == "ignored" and prop_checker.calls == 4
    assert codes(store, row_prop) == ["skipped.verification.news_value"]


def test_parallel_verify_speculative_hit_and_tiebreak(context):
    """Run initial review and speculative verification concurrently on two threads and continue cleanly to tiebreak."""
    cfg, store = context
    row = pending(store)
    barrier = threading.Barrier(2, timeout=5)
    replies = {False: verdict(), True: verdict()}

    def _factory():
        """Create an isolated reviewer waiting on the parallel barrier on the first two calls."""
        class _ParallelReviewer:
            """Thread-safe scripted reviewer proving simultaneous initial and verify execution."""

            def review(self, cand, packet, *, coverage=None, verification=False, update=False,
                       prior_reviews=(), on_request=None, **kwargs):
                """Return scripted response after charging request budget and joining parallel barrier."""
                if on_request:
                    on_request(1)
                barrier.wait()
                return replies[verification]

        return _ParallelReviewer()

    result = review_gate.process_item(cfg, store, row, Writer(), ApprovingReviewer(),
                                      parallel_verify=True, reviewer_factory=_factory)
    assert result["status"] == "published" and len(store.stories()) == 1
    assert audit(store, row["id"])["request_budget"]["reserved"] == 2

    row2 = pending(store, item(id="https://example.org/pv-tie", url="https://example.org/pv-tie"))
    barrier2 = threading.Barrier(2, timeout=5)
    call_count = {"n": 0}
    lock = threading.Lock()
    tie_replies = {False: verdict(), True: verdict("skip", criterion="news_value")}

    def _tie_factory():
        """Create a reviewer running first two calls across a barrier then a sequential tiebreak."""
        class _TieParallelReviewer:
            """Scripted reviewer covering parallel speculative hit followed by sequential tiebreaker."""

            def review(self, cand, packet, *, coverage=None, verification=False, update=False,
                       prior_reviews=(), on_request=None, **kwargs):
                """Synchronize first two calls via barrier, then serve tiebreak verdict sequentially."""
                if on_request:
                    on_request(1)
                with lock:
                    call_count["n"] += 1
                    n = call_count["n"]
                if n <= 2:
                    barrier2.wait()
                    return tie_replies[verification]
                return verdict()

        return _TieParallelReviewer()

    result2 = review_gate.process_item(cfg, store, row2, Writer(), _tie_factory(),
                                       parallel_verify=True, reviewer_factory=_tie_factory)
    assert result2["status"] == "published" and len(store.stories()) == 2
    rec2 = audit(store, row2["id"])
    assert rec2["reviews"][2]["tiebreaker"] is True and rec2["request_budget"]["reserved"] == 3


def test_parallel_verify_revise_and_skip_discard_paths(context):
    """Discard stale or failing speculative verification when the initial review revises or skips."""
    cfg, store = context
    row_revise = pending(store)
    seq_calls = []
    repaired_text = "Updated mitigation details after initial review."

    def _revise_factory():
        """Return revise on initial review and a fatal hold on pre-repair speculative verify."""
        class _ReviseReviewer:
            """Reviewer checking candidate text on sequential verify after stale speculative verify."""

            def review(self, cand, packet, *, coverage=None, verification=False, update=False,
                       prior_reviews=(), on_request=None, **kwargs):
                """Discard speculative hold when review proposes a repair, then approve repaired text."""
                if on_request:
                    on_request(1)
                if not verification:
                    return {**verdict("revise"), "repair": {"summary": repaired_text}}
                if cand["summary"] != repaired_text:
                    return verdict("hold", criterion="source_support")
                seq_calls.append(cand["summary"])
                return verdict()

        return _ReviseReviewer()

    res_rev = review_gate.process_item(cfg, store, row_revise, Writer(), _revise_factory(),
                                       parallel_verify=True, reviewer_factory=_revise_factory)
    assert res_rev["status"] == "published" and seq_calls == [repaired_text]
    assert audit(store, row_revise["id"])["request_budget"]["reserved"] == 3

    row_skip = pending(store, item(id="https://example.org/pv-skip", url="https://example.org/pv-skip"))

    def _skip_factory():
        """Return skip on initial review and raise FetchError on speculative verify."""
        class _SkipErrorReviewer:
            """Reviewer whose speculative verify error must be isolated when initial review skips."""

            def review(self, cand, packet, *, coverage=None, verification=False, update=False,
                       prior_reviews=(), on_request=None, **kwargs):
                """Raise transport failure on verification thread while initial review skips cleanly."""
                if on_request:
                    on_request(1)
                if verification:
                    raise FetchError("speculative verify error", status=500)
                return verdict("skip", criterion="news_value")

        return _SkipErrorReviewer()

    res_skip = review_gate.process_item(cfg, store, row_skip, Writer(), ApprovingReviewer(),
                                        parallel_verify=True, reviewer_factory=_skip_factory)
    assert res_skip["status"] == "ignored" and codes(store, row_skip) == ["skipped.review.news_value"]
    assert audit(store, row_skip["id"])["request_budget"]["reserved"] == 2


def test_parallel_verify_partial_failures_and_budget_guard(context):
    """Persist stage state accurately on partial parallel failures and enforce slot budgets."""
    cfg, store = context
    row1 = pending(store)

    def _verify_fails_factory():
        """Approve initial review while failing speculative verification with a retryable error."""
        class _VerifyFailsReviewer:
            """Reviewer failing only the verification call."""

            def review(self, cand, packet, *, coverage=None, verification=False, update=False,
                       prior_reviews=(), on_request=None, **kwargs):
                """Charge slot and fail only when `verification=True`."""
                if on_request:
                    on_request(1)
                if verification:
                    raise AnalysisError("verify timeout", retryable=True)
                return verdict()

        return _VerifyFailsReviewer()

    with pytest.raises(AnalysisError):
        review_gate.process_item(cfg, store, row1, Writer(), ApprovingReviewer(),
                                 parallel_verify=True, reviewer_factory=_verify_fails_factory)
    assert job(store, row1["id"])["stage"] == "verify"
    assert len(job_record(store, row1["id"])["reviews"]) == 1
    assert job_record(store, row1["id"])["request_budget"]["reserved"] == 2
    assert run(cfg, store, row1, Writer(), ApprovingReviewer())["status"] == "published"
    assert audit(store, row1["id"])["request_budget"]["reserved"] == 3

    row2 = pending(store, item(id="https://example.org/pv-revfail", url="https://example.org/pv-revfail"))

    def _review_fails_factory():
        """Fail initial review while speculative verification would succeed."""
        class _ReviewFailsReviewer:
            """Reviewer failing initial review so speculative verification cannot advance stage."""

            def review(self, cand, packet, *, coverage=None, verification=False, update=False,
                       prior_reviews=(), on_request=None, **kwargs):
                """Charge slot and raise retryable AnalysisError when `verification=False`."""
                if on_request:
                    on_request(1)
                if not verification:
                    raise AnalysisError("review timeout", retryable=True)
                return verdict()

        return _ReviewFailsReviewer()

    with pytest.raises(AnalysisError):
        review_gate.process_item(cfg, store, row2, Writer(), ApprovingReviewer(),
                                 parallel_verify=True, reviewer_factory=_review_fails_factory)
    assert job(store, row2["id"])["stage"] == "review" and job_record(store, row2["id"])["reviews"] == []
    assert job_record(store, row2["id"])["request_budget"]["reserved"] == 2
    assert run(cfg, store, row2, Writer(), ApprovingReviewer())["status"] == "published"
    assert audit(store, row2["id"])["request_budget"]["reserved"] == 4

    row3 = pending(store, item(id="https://example.org/pv-guard", url="https://example.org/pv-guard"))
    for _ in range(review_gate.MAX_REVIEW_REQUESTS - 2):
        with pytest.raises(AnalysisError):
            run(cfg, store, row3, Writer(), Reviewer(AnalysisError("timeout", retryable=True)))
    factory_called = []

    def _guard_factory():
        """Record if parallel factory is invoked when fewer than three slots remain."""
        factory_called.append(True)
        return ApprovingReviewer()

    res_seq_repair = review_gate.process_item(
        cfg, store, row3, Writer(),
        Reviewer({**verdict("revise"), "repair": {"summary": "Repaired cleanly within last two slots."}}, verdict()),
        parallel_verify=True, reviewer_factory=_guard_factory,
    )
    assert res_seq_repair["status"] == "published" and factory_called == []
    assert audit(store, row3["id"])["request_budget"]["reserved"] == review_gate.MAX_REVIEW_REQUESTS

    # With three slots remaining (reserved == MAX_REVIEW_REQUESTS - 3), initial parallel verify is permitted.
    row3b = pending(store, item(id="https://example.org/pv-guard-3slots", url="https://example.org/pv-guard-3slots"))
    for _ in range(review_gate.MAX_REVIEW_REQUESTS - 3):
        with pytest.raises(AnalysisError):
            run(cfg, store, row3b, Writer(), Reviewer(AnalysisError("timeout", retryable=True)))
    three_slot_factory_calls = []

    def _three_slot_factory():
        """Record that parallel factory is permitted when three slots remain."""
        three_slot_factory_calls.append(True)
        return ApprovingReviewer()

    res_par3 = review_gate.process_item(
        cfg, store, row3b, Writer(), ApprovingReviewer(),
        parallel_verify=True, reviewer_factory=_three_slot_factory,
    )
    assert res_par3["status"] == "published" and len(three_slot_factory_calls) == 2
    assert audit(store, row3b["id"])["request_budget"]["reserved"] == review_gate.MAX_REVIEW_REQUESTS - 1

    row4 = pending(store, item(id="https://example.org/pv-defer", url="https://example.org/pv-defer"))

    def _defer_factory():
        """Reserve then refund pre-dispatch slot on CompletionDeferred."""
        class _DeferReviewer:
            """Reviewer simulating unsent CompletionDeferred refunds."""

            def review(self, cand, packet, *, coverage=None, verification=False, update=False,
                       prior_reviews=(), on_request=None, **kwargs):
                """Charge and immediately refund request slot before raising CompletionDeferred."""
                if on_request:
                    on_request(1)
                    on_request(-1)
                raise CompletionDeferred("budget exhausted")

        return _DeferReviewer()

    res_defer = review_gate.process_item(cfg, store, row4, Writer(), ApprovingReviewer(),
                                         parallel_verify=True, reviewer_factory=_defer_factory)
    assert res_defer["status"] == "deferred"
    assert job_record(store, row4["id"])["request_budget"]["reserved"] == 0


def test_parallel_specialist_gate_approves_records_metadata_and_commits(context):
    """process_item(..., specialists=3) fans out all 3 specialist lenses, validates state, and publishes."""
    cfg, store = context
    row = pending(store, item(id="https://example.org/spec3-approve", url="https://example.org/spec3-approve"))

    seen_calls = []
    lock = threading.Lock()
    barrier = threading.Barrier(4, timeout=5)

    def _factory():
        class _ConcurrentReviewer:
            """Reviewer checking concurrency across initial + 3 specialist passes."""

            def review(self, cand, packet, *, coverage=None, verification=False, update=False,
                       specialist=None, validation_error=None, on_request=None):
                if on_request:
                    on_request(1)
                with lock:
                    seen_calls.append((threading.get_ident(), verification, specialist))
                barrier.wait()
                return verdict("approve", update=update)

        return _ConcurrentReviewer()

    res = review_gate.process_item(
        cfg,
        store,
        row,
        Writer(),
        ApprovingReviewer(),
        parallel_verify=True,
        reviewer_factory=_factory,
        specialists=3,
    )
    assert res["status"] == "published"
    rec = audit(store)
    assert rec["specialists"] == 3
    assert rec["request_budget"]["reserved"] == 4
    assert [s["specialist"] for s in rec["reviews"][1]["specialists"]] == list(review.SPECIALISTS)
    assert len(store.stories()) == 1
    initial_specs = [s for _, _, s in seen_calls]
    assert None in initial_specs
    assert {s for s in initial_specs if s is not None} == set(review.SPECIALISTS)


def test_parallel_specialist_verify_repairs_and_uses_specialist_budget(context):
    """Multi-wave specialist verification runs all 3 lenses per verify wave within MAX_SPECIALIST_REVIEW_REQUESTS."""
    cfg, store = context
    assert review_gate.MAX_REVIEW_REQUESTS == 8
    assert review_gate.MAX_SPECIALIST_REVIEW_REQUESTS == 20

    row = pending(store, item(id="https://example.org/spec3-repair", url="https://example.org/spec3-repair"))
    verify_calls = []
    lock = threading.Lock()

    def _repair_factory():
        class _RepairSpecialistReviewer:
            """Reviewer requiring three verify waves before all 3 specialist lenses approve."""

            def review(self, cand, packet, *, coverage=None, verification=False, update=False,
                       specialist=None, validation_error=None, on_request=None):
                if on_request:
                    on_request(1)
                if not verification:
                    if specialist is None:
                        raw = verdict(
                            "revise",
                            criterion="scope_timing",
                            reason="Clarify timing wording.",
                            repair={"why_it_matters": "Release timing depends on the upstream review outcome."},
                        )
                        return review.validate_review(raw, packet, update=update, coverage=coverage)
                    return verdict("approve", update=update)

                with lock:
                    verify_calls.append((specialist, cand.get("why_it_matters")))
                impact = cand.get("why_it_matters")
                if impact == "Release timing depends on the upstream review outcome.":
                    if specialist == "attribution_scope_advice":
                        raw = verdict(
                            "revise",
                            criterion="scope_timing",
                            reason="Refine maintenance timing.",
                            repair={"why_it_matters": "Downstream tracking waits for maintainer sign-off."},
                        )
                        return review.validate_review(raw, packet, update=update, coverage=coverage)
                    return verdict("approve", update=update)
                if impact == "Downstream tracking waits for maintainer sign-off.":
                    if specialist == "grounding_status":
                        raw = verdict(
                            "revise",
                            criterion="source_support",
                            reason="Clear draft impact line.",
                            repair={"why_it_matters": ""},
                        )
                        return review.validate_review(raw, packet, update=update, coverage=coverage)
                    return verdict("approve", update=update)
                return verdict("approve", update=update)

        return _RepairSpecialistReviewer()

    res = review_gate.process_item(
        cfg,
        store,
        row,
        Writer(),
        ApprovingReviewer(),
        parallel_verify=True,
        reviewer_factory=_repair_factory,
        specialists=3,
    )
    assert res["status"] == "published"
    rec = audit(store)
    # Initial parallel wave (4) + three specialist verify waves (3 * 3 = 9) = 13 > MAX_REVIEW_REQUESTS (8).
    assert rec["request_budget"]["reserved"] == 13
    assert [s for s, _ in verify_calls].count("attribution_scope_advice") == 4
    assert store.stories()[0]["why_it_matters"] == ""

    # Tampered specialist count fails closed with app.damaged_job.
    bad_rec = json.loads(json.dumps(rec))
    bad_rec["specialists"] = 9
    repaired_cand = {**rec["prepared"]["candidate"], "why_it_matters": ""}
    with pytest.raises(AnalysisError) as exc_info:
        review_gate.validate_review_state(bad_rec, "verify", repaired_cand, rec["prepared"])
    assert exc_info.value.code == "app.damaged_job"


def test_parallel_specialist_resume_and_reask_paths(context):
    """Deferred specialist verify stage resumes cleanly and hands InconsistentReview to validation reask."""
    cfg, store = context
    row = pending(store, item(id="https://example.org/spec3-resume", url="https://example.org/spec3-resume"))
    phase = {"step": 1}

    reasked_specialists = []

    def _resume_factory():
        class _ResumeReviewer:
            """Triggers CompletionDeferred inside verify wave 1, then InconsistentReview on wave 2."""

            def review(self, cand, packet, *, coverage=None, verification=False, update=False,
                       specialist=None, validation_error=None, on_request=None):
                if on_request:
                    on_request(1)
                if not verification:
                    if specialist is None:
                        raw = verdict(
                            "revise",
                            criterion="scope_timing",
                            reason="Clear why_it_matters.",
                            repair={"why_it_matters": ""},
                        )
                        return review.validate_review(raw, packet, update=update, coverage=coverage)
                    return verdict("approve", update=update)
                if phase["step"] == 1:
                    if specialist == "novelty_news":
                        raise CompletionDeferred("transient verify pause")
                    return verdict("approve", update=update)
                if phase["step"] == 2 and specialist == "grounding_status":
                    if validation_error is None:
                        raise review.InconsistentReview()
                    if on_request and hasattr(on_request, "response_received"):
                        on_request.response_received()
                    reasked_specialists.append((specialist, validation_error))
                return verdict("approve", update=update)

        return _ResumeReviewer()

    reask_checker = ApprovingReviewer()
    first = review_gate.process_item(
        cfg,
        store,
        row,
        Writer(),
        reask_checker,
        parallel_verify=True,
        reviewer_factory=_resume_factory,
        specialists=3,
    )
    assert first["status"] == "deferred"
    saved_job = job(store)
    assert saved_job["stage"] == "verify"
    env = json.loads(saved_job["envelope_json"])
    rec1 = json.loads(saved_job["record_json"])
    review_gate.validate_review_state(rec1, saved_job["stage"], rec1["candidate"], env)

    phase["step"] = 2
    second = review_gate.process_item(
        cfg,
        store,
        queued_row(store, row["id"]),
        Writer(),
        reask_checker,
        parallel_verify=True,
        reviewer_factory=_resume_factory,
        specialists=3,
    )
    assert second["status"] == "published"
    assert ("grounding_status", review.INCONSISTENT_VERDICT) in reasked_specialists


def test_evaluate_review_specialists_3_cli_and_draft_mode(tmp_path, monkeypatch):
    """evaluate_review.py --specialists 3 exercises 3-lens merge in both candidate and --draft modes."""
    from helpers import _ClientBase, load_evaluator

    eval_mod = load_evaluator()
    cases_path = tmp_path / "cases.json"
    cfg_path = tmp_path / "cfg.toml"
    cfg_path.write_text("", encoding="utf-8")
    out_cand = tmp_path / "out_cand.jsonl"
    out_draft = tmp_path / "out_draft.jsonl"
    corpus = {
        "defaults": {
            "why_it_matters": "",
            "priority": "normal",
            "confidence": "reported",
            "state": "developing",
            "products": ["tor"],
            "published_at": DATE,
            "updated_at": DATE,
            "added_at": DATE,
        },
        "packets": {
            "clean-pkt": {
                "sources": [{
                    "url": "https://blog.torproject.org/tor-04812-released/",
                    "title": "Tor 0.4.8.12 released",
                    "kind": "rss",
                    "authority": "official",
                    "product": "tor",
                    "published_at": DATE,
                    "updated_at": DATE,
                    "passages": ["Tor Project released Tor 0.4.8.12 to fix a crash bug."],
                }]
            },
            "flawed-pkt": {
                "sources": [{
                    "url": "https://gitlab.torproject.org/tpo/core/tor/-/issues/49999",
                    "title": "Relay bug report",
                    "kind": "gitlab_issue",
                    "authority": "development",
                    "product": "tor",
                    "published_at": DATE,
                    "updated_at": DATE,
                    "upstream_state": "opened",
                    "passages": ["A user reported a relay crash on startup."],
                }]
            },
        },
        "cases": [
            {
                "id": "case-clean",
                "packet": "clean-pkt",
                "expected": "approve",
                "candidate": {
                    "id": "111111111111111111111111",
                    "title": "Tor 0.4.8.12 fixes crash bug",
                    "summary": "Tor Project released Tor 0.4.8.12 to fix a crash bug.",
                    "category": "release",
                    "confidence": "confirmed",
                    "state": "released",
                },
            },
            {
                "id": "case-flawed",
                "packet": "flawed-pkt",
                "expected": "not_approve",
                "unsupported": ["fixed the relay crash"],
                "candidate": {
                    "id": "222222222222222222222222",
                    "title": "Relay crash fixed",
                    "summary": "Tor Project fixed the relay crash.",
                    "category": "security",
                    "confidence": "reported",
                    "state": "developing",
                },
            },
        ],
    }
    cases_path.write_text(json.dumps(corpus), encoding="utf-8")

    class _StubAnalyzer(_ClientBase):
        """Minimal Analyzer stub producing draft candidates from writer items."""

        def __init__(self, *args, **kwargs):
            pass

        def analyze(self, writer_src):
            is_release = "0.4.8.12" in writer_src["title"]
            return {
                "title": "Tor 0.4.8.12 fixes crash bug" if is_release else "Relay crash fixed",
                "summary": (
                    "Tor Project released Tor 0.4.8.12 to fix a crash bug."
                    if is_release else "Tor Project fixed the relay crash."
                ),
                "why_it_matters": "",
                "category": "release" if is_release else "security",
                "priority": "normal",
                "confidence": "confirmed" if is_release else "reported",
                "state": "released" if is_release else "developing",
                "products": ["tor"],
                "tags": [],
            }

    seen_specialists = []
    spec_lock = threading.Lock()

    class _StubEvalReviewer(_ClientBase):
        """Reviewer checking specialist kwarg propagation under evaluate_review."""

        last_decoded = None

        def __init__(self, *args, **kwargs):
            pass

        def review(self, cand, packet, *, coverage=None, verification=False, update=False,
                   specialist=None, validation_error=None, on_request=None):
            if on_request:
                on_request(1)
            with spec_lock:
                seen_specialists.append(specialist)
            if "49999" in packet["sources"][0]["url"] and specialist == "grounding_status":
                return verdict(
                    "hold",
                    criterion="status",
                    reason="Issue is still open; fix not shipped.",
                )
            return verdict("approve", update=update)

    monkeypatch.setattr(eval_mod, "Analyzer", _StubAnalyzer)
    monkeypatch.setattr(eval_mod, "EvaluationReviewer", _StubEvalReviewer)
    monkeypatch.setattr(eval_mod, "load_config", lambda *args, **kwargs: make_config(tmp_path))

    rc = eval_mod.main([
        "--config", str(cfg_path),
        "--cases", str(cases_path),
        "--output", str(out_cand),
        "--specialists", "3",
    ])
    assert rc == 0
    cand_lines = [json.loads(line) for line in out_cand.read_text(encoding="utf-8").splitlines()]
    assert cand_lines[-1]["summary"]["cases"] == 2
    assert cand_lines[-1]["summary"]["matched"] == 2
    assert cand_lines[-1]["summary"]["errors"] == 0
    assert cand_lines[-1]["summary"]["incomplete"] is False
    assert set(review.SPECIALISTS) <= set(seen_specialists)

    seen_specialists.clear()
    rc_draft = eval_mod.main([
        "--config", str(cfg_path),
        "--cases", str(cases_path),
        "--output", str(out_draft),
        "--draft",
        "--specialists", "3",
    ])
    assert rc_draft == 0
    draft_lines = [json.loads(line) for line in out_draft.read_text(encoding="utf-8").splitlines()]
    assert draft_lines[-1]["summary"]["cases"] == 2
    assert draft_lines[-1]["summary"]["matched"] == 2
    assert draft_lines[-1]["summary"]["errors"] == 0
    assert set(review.SPECIALISTS) <= set(seen_specialists)


def test_specialist_gate_validation_preserve_hold_no_downgrade_and_factory_guard(context):
    """Enforce unique specialist requests, factory specialist support, preserved holds, cache isolation, and fail-closed budget holds."""
    cfg, store = context

    # 1) Factory returning non-specialist ApprovingReviewer is rejected cleanly.
    row_bad = pending(store, item(id="https://example.org/spec3-bad-fac", url="https://example.org/spec3-bad-fac"))
    with pytest.raises(TypeError, match="specialist"):
        review_gate.process_item(
            cfg, store, row_bad, Writer(), ApprovingReviewer(),
            parallel_verify=True, reviewer_factory=lambda: ApprovingReviewer(), specialists=3,
        )

    # 2) Specialist reask keeps another lens's hold instead of dropping it.
    row_hold = pending(store, item(id="https://example.org/spec3-hold", url="https://example.org/spec3-hold"))

    def _hold_factory():
        class _HoldReaskReviewer:
            """Throws InconsistentReview on grounding_status and holds on attribution_scope_advice."""

            def review(self, cand, packet, *, coverage=None, verification=False, update=False,
                       specialist=None, validation_error=None, on_request=None):
                if on_request:
                    on_request(1)
                if not verification:
                    return verdict("approve", update=update)
                if specialist == "grounding_status":
                    if validation_error is None:
                        raise review.InconsistentReview()
                    if on_request and hasattr(on_request, "response_received"):
                        on_request.response_received()
                    return verdict("approve", update=update)
                if specialist == "attribution_scope_advice":
                    return verdict("hold", criterion="actor_and_action", reason="Unsupported actor.", update=update)
                return verdict("approve", update=update)

        return _HoldReaskReviewer()

    res_hold = review_gate.process_item(
        cfg, store, row_hold, Writer(), ApprovingReviewer(),
        parallel_verify=True, reviewer_factory=_hold_factory, specialists=3,
    )
    assert res_hold["status"] == "held"
    assert store.stories() == []

    # 3) Duplicate specialist request numbers fail validate_review_state.
    row_ok = pending(store, item(id="https://example.org/spec3-dup-req", url="https://example.org/spec3-dup-req"))

    def _ok_factory():
        class _OkSpec:
            """Specialist reviewer approving all lenses."""

            def review(self, cand, packet, *, coverage=None, verification=False, update=False,
                       specialist=None, validation_error=None, on_request=None):
                """Approve one lens call."""
                if on_request:
                    on_request(1)
                return verdict("approve", update=update)

        return _OkSpec()

    assert review_gate.process_item(
        cfg, store, row_ok, Writer(), ApprovingReviewer(),
        parallel_verify=True, reviewer_factory=_ok_factory, specialists=3,
    )["status"] == "published"
    good_rec = audit(store)
    bad_rec = json.loads(json.dumps(good_rec))
    bad_rec["reviews"][1]["specialists"][1]["request"] = bad_rec["reviews"][1]["specialists"][0]["request"]
    with pytest.raises(AnalysisError) as dup_exc:
        review_gate.validate_review_state(bad_rec, "approved", good_rec["candidate"], good_rec["prepared"], allow_cached=False)
    assert dup_exc.value.code == "app.damaged_job"

    # 4) A cached 1-verifier receipt is preserved in review_approvals but not reused for specialists=3.
    import copy
    from helpers import insert_approval
    cfg2 = copy.deepcopy(cfg)
    item_shared = item(id="https://example.org/spec3-cache-1", url="https://example.org/spec3-cache-1")
    row_c1 = pending(store, item_shared)
    prepared_c1 = review_gate._prepare(store, cfg2, row_c1, analysis(), DATE)
    insert_approval(store, prepared_c1, policy=review.policy_hash(cfg2))
    assert store.db.execute("SELECT COUNT(*) FROM review_approvals").fetchone()[0] == 1
    res_defer_c3 = review_gate.process_item(
        cfg2, store, queued_row(store, row_c1["id"]), Writer(), ApprovingReviewer(),
        allow_network=False, parallel_verify=True, reviewer_factory=_ok_factory, specialists=3,
    )
    assert res_defer_c3["status"] == "deferred" and res_defer_c3["cache_hit"] is False
    assert store.db.execute("SELECT COUNT(*) FROM review_approvals").fetchone()[0] == 1
    res_c3 = review_gate.process_item(
        cfg2, store, queued_row(store, row_c1["id"]), Writer(), ApprovingReviewer(),
        parallel_verify=True, reviewer_factory=_ok_factory, specialists=3,
    )
    assert res_c3["status"] == "published" and res_c3["cache_hit"] is False and res_c3["review_calls"] >= 4

    # 5) Resumed specialists=3 verify stage holds with specialist_budget when budget/reviewer cannot run all 3 lenses.
    row_low = pending(store, item(id="https://example.org/spec3-low", url="https://example.org/spec3-low"))
    assert review_gate.process_item(
        cfg, store, row_low, Writer(), ApprovingReviewer(), allow_network=True,
        parallel_verify=False, reviewer_factory=None, specialists=3,
    )["status"] == "held"
    low_job = job(store, row_low)
    assert json.loads(low_job["record_json"])["hold_code"] == "specialist_budget"
