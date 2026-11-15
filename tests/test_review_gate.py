"""The final-candidate gate resumes completed stages and never publishes unchecked."""

import contextlib
import json
import sqlite3

import pytest

from helpers import (DAMAGE, DATE, LATER, ApprovingReviewer, Reviewer, Writer, analysis, approve,
                     damaged, finish_reviewed, insert_approval, item, job, pending, run_gate as run,
                     seed_legacy, tag, update_analysis, verdict)
from onionflash import candidate, cli, decisions, editorial, rejection, review, review_gate
from onionflash.analyze import AnalysisError, Analyzer, cache_key, tag_notice
from onionflash.comments import _compose
from onionflash.store import ReviewRequired
from onionflash.transport import FetchError, Response
from onionflash.util import digest, item_cluster


def failing(action, *criteria, repair=None):
    reply = verdict(action, repair=repair, criterion=criteria[0])
    for name in criteria[1:]:
        reply["criteria"][name].update(reason="The source does not support this claim.", outcome="fail")
    return reply


def audit(store):
    return json.loads(store.db.execute("SELECT review_record FROM analyses ORDER BY rowid DESC").fetchone()[0])


def codes(store, row):
    return [entry["code"] for entry in decisions.for_item(store.db, row["id"])]


def add_coverage(store, identity="other-story", **changes):
    public = {"id": identity, "title": "A previous report", "summary": "The source reported an event.",
              "why_it_matters": "", "category": "network", "priority": "normal", "confidence": "reported",
              "state": "developing", "products": ["tor"], "tags": ["network"],
              "sources": [{"url": "https://example.org/" + identity, "title": "Original source"}],
              "published_at": DATE, "updated_at": DATE, "added_at": DATE, **changes}
    with store.db:
        store.db.execute("INSERT INTO stories VALUES(?,?,?,?,?)",
                         (identity, identity, json.dumps(public), public["published_at"], public["updated_at"]))
    return public


def test_approved_exact_candidate_commits_dates_story_and_keeps_audit(context, monkeypatch):
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


def test_verification_repairs_are_verified_fresh_and_stop_after_five(tmp_path):
    from onionflash.config import DEFAULTS
    from onionflash.store import Store

    cfg = {**DEFAULTS, "storage": {"database": str(tmp_path / "ok.db"), "output_dir": str(tmp_path / "pub")}, "sources": []}
    with Store(cfg["storage"]["database"]) as store:
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

    with Store(tmp_path / "cap.db") as store:
        row = pending(store)
        repairs = [verdict("revise", repair={"summary": f"Repair number {n}."}) for n in range(7)]
        with pytest.raises(AnalysisError):
            run(cfg, store, row, Writer(), Reviewer(*repairs[:4], AnalysisError("timeout", retryable=True)))
        assert job(store)["stage"] == "verify"
        writer, checker = Writer(), Reviewer(*repairs[4:])
        with pytest.raises(review.ReviewLimitReached):
            run(cfg, store, row, writer, checker)
        assert writer.calls == [] and [c[2] for c in checker.calls] == [True, True]
        assert codes(store, row) == ["failed.review.request_limit"] and store.stories() == []
        assert json.loads(job(store)["record_json"])["request_budget"]["reserved"] == 7
        shown = rejection.show_item(store, row["id"])["final_review"]
        assert shown["candidate"]["summary"] == "Repair number 5."
        assert shown["base_candidate"]["summary"] == analysis()["summary"]
        assert [(e["phase"], e["verdict"]) for e in shown["reviews"]] == [("review", "revise")] + [("verification", "revise")] * 5
        assert all(e["failed"] == {"operational_advice": "fail: The source does not support this claim."} for e in shown["reviews"])
        assert [e["repair"]["summary"] for e in shown["reviews"]] == [f"Repair number {n}." for n in range(6)]


@pytest.mark.parametrize("case", ["hold", "revise-without-repair", "repeated-text", "tag-notice"])
def test_verification_refusal_that_cannot_be_repaired_holds(context, case):
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
    ([verdict(), verdict("skip", criterion="news_value")], "held"),
    ([verdict(), verdict("skip", criterion="new_information")], "held"),
    ([failing("revise", "news_value", "operational_advice", repair={"summary": "A shorter summary."}), verdict()], "held"),
    ([verdict(), failing("revise", "news_value", "operational_advice", repair={"summary": "A shorter summary."})], "held"),
    ([failing("revise", "news_value", "operational_advice", repair={"summary": "A shorter summary."}),
      verdict("skip", criterion="news_value")], "ignored"),
])
def test_reviews_that_disagree_on_news_value_hold(context, replies, status):
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


def duplicate_skip(*extra_criteria):
    reply = failing("skip", "new_information", *extra_criteria)
    reply["criteria"]["new_information"]["reason"] = f"Already covered in {COVERED_ID}."
    return reply


@pytest.mark.parametrize("src,replies,status,code", [
    (OFFICIAL, [verdict("skip", criterion="news_value")] * 2, "held", "held.verification.official_not_news"),
    (OFFICIAL, [verdict("skip", criterion="news_value"),
                failing("revise", "news_value", "operational_advice", repair={"summary": "A shorter summary."}),
                verdict("skip", criterion="news_value")], "held", "held.verification.official_not_news"),
    (OFFICIAL, [verdict("revise", criterion="news_value"), verdict("skip", criterion="news_value")],
     "held", "held.verification.official_not_news"),
    (OFFICIAL, [verdict("revise", criterion="news_value"), failing("revise", "news_value", "operational_advice")],
     "held", "held.verification.unusable_repair"),
    (OFFICIAL, [duplicate_skip()], "ignored", "skipped.review.new_information"),
    (OFFICIAL, [duplicate_skip("news_value")], "ignored", "skipped.review.new_information_and_news_value"),
    (OFFICIAL, [{**verdict("skip", criterion="news_value"),
                 "criteria": {**verdict("skip", criterion="news_value")["criteria"],
                              "new_information": {"reason": "Coverage is truncated.", "source_refs": [], "outcome": "insufficient"}}}],
     "held", "held.review.model_hold"),
    (OFFICIAL, [verdict("skip", criterion="news_value"), duplicate_skip()],
     "ignored", "skipped.verification.new_information"),
    ({}, [verdict("skip", criterion="news_value")], "ignored", "skipped.review.news_value"),
    ({**OFFICIAL, "kind": "tag", "title": "tor-0.4.9.16", "content": ""}, [verdict("skip", criterion="news_value")],
     "ignored", "skipped.review.news_value"),
])
def test_official_item_failing_news_value_is_held_not_skipped(context, src, replies, status, code):
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
    cfg, store = context
    uncited = verdict("skip", criterion="news_value")
    uncited["criteria"]["source_support"]["source_refs"] = []
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
    cfg, store = context
    row = pending(store)
    result = run(cfg, store, row, Writer(analysis(category="release", tags=["release"])), Reviewer(*replies))
    assert (result["status"], result["review_calls"]) == ("held", len(replies)) and codes(store, row) == [code]


def test_receipt_resume_context_invalidation_and_pruning(context, monkeypatch):
    cfg, store = context
    row = pending(store)
    commit = store.commit_candidate
    monkeypatch.setattr(store, "commit_candidate", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("simulated crash")))
    with pytest.raises(RuntimeError):
        run(cfg, store, row, Writer(), Reviewer(verdict("revise", repair={"summary": "A first repair."}),
                                                verdict("revise", repair={"summary": "A second repair."}), verdict()))
    monkeypatch.setattr(store, "commit_candidate", commit)
    w0, r0 = Writer(), Reviewer()
    res = run(cfg, store, row, w0, r0, allow_network=False)
    assert res["status"] == "published" and res["cache_hit"] and w0.calls == r0.calls == []
    assert store.stories()[0]["summary"] == "A second repair."

    # Context changes (coverage or policy) invalidate recorded receipt before commit.
    for idx, change in enumerate(("coverage", "policy")):
        row_c = pending(store, item(url=f"https://example.org/ctx-{idx}", content=f"Context change {idx} Compromise report."))
        monkeypatch.setattr(store, "commit_candidate", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("simulated crash")))
        with pytest.raises(RuntimeError):
            run(cfg, store, row_c, Writer(analysis(evidence=[f"Context change {idx}"])), Reviewer(verdict()))
        monkeypatch.setattr(store, "commit_candidate", commit)
        if change == "coverage":
            add_coverage(store, f"cov-{idx}")
        else:
            cfg["review"]["model"] = "different-review-model"
        chk = Reviewer(verdict())
        assert run(cfg, store, row_c, Writer(), chk)["status"] == "published" and [c[2] for c in chk.calls] == [False, True]

    # Cache pruning retains active approval jobs and resuming never temporarily unpins receipt.
    monkeypatch.setattr(review_gate, "MAX_APPROVALS", 1)
    row_p = pending(store, item(url="https://example.org/pin", content="Pinned approval test report."))
    monkeypatch.setattr(store, "commit_candidate", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("crash")))
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
    monkeypatch.setattr(review_gate, "_save", lambda *a, **kw: (save(*a, **kw), (_ for _ in ()).throw(RuntimeError("crash after save"))))
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
    cfg, store = context
    row = pending(store)
    result = run(cfg, store, row, Writer(), Reviewer(verdict("revise", repair=repair)))
    assert result["status"] == "held" and result["review_calls"] == 1
    assert [e["id"] for e in rejection.list_items(store)["items"]] == [row["id"]]
    assert rejection.show_item(store, row["id"])["final_review"]["latest_review"]["verdict"] == "revise"


@pytest.mark.parametrize("decision", ["approve", "skip"])
def test_completed_decision_resumes_after_crash_without_any_model_call(context, monkeypatch, decision):
    cfg, store = context
    row = pending(store)
    commit = store.commit_candidate
    monkeypatch.setattr(store, "commit_candidate", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("simulated crash")))
    with pytest.raises(RuntimeError):
        run(cfg, store, row, Writer(), Reviewer(verdict(decision, criterion="news_value")))
    assert job(store)["stage"] == ("approved" if decision == "approve" else "skipped") and len(store.stories()) == 0
    store.defer(row["id"], "Unexpected RuntimeError", cfg["llm"], LATER, terminal=True)
    row = dict(store.db.execute("SELECT * FROM items WHERE id=?", (row["id"],)).fetchone())
    monkeypatch.setattr(store, "commit_candidate", commit)
    store.ingest(item(url="https://example.org/other-report", content="A routine reply."), DATE)
    other = dict(store.db.execute("SELECT * FROM items WHERE url=?", ("https://example.org/other-report",)).fetchone())
    assert run(cfg, store, other, Writer(), Reviewer(verdict("skip", criterion="news_value")))["status"] == "ignored"
    writer, checker = Writer(), Reviewer()
    result = run(cfg, store, row, writer, checker, allow_network=False)
    assert result["status"] == ("published" if decision == "approve" else "ignored") and result["cache_hit"]
    assert writer.calls == checker.calls == [] and job(store) is None
    assert len(store.stories()) == (1 if decision == "approve" else 0)
    assert not store.db.execute("SELECT 1 FROM review_approvals").fetchone()


@pytest.mark.parametrize("receipt", ["damaged", "missing"])
def test_a_recorded_decision_without_a_usable_receipt_reviews_the_draft_again(context, monkeypatch, receipt):
    cfg, store = context
    row = pending(store)
    commit = store.commit_candidate
    monkeypatch.setattr(store, "commit_candidate", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("simulated crash")))
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
    cfg, store = context
    row = pending(store)
    commit, check = store.commit_candidate, review.final_holds
    monkeypatch.setattr(store, "commit_candidate", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("simulated crash")))
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

    # Changed source invalidates staged draft; policy change reuses draft but requires fresh review.
    row2 = pending(store, item(url="https://example.org/src-change"))
    with pytest.raises(AnalysisError):
        run(cfg, store, row2, Writer(), Reviewer(AnalysisError("timeout", retryable=True)))
    store.ingest(item(url="https://example.org/src-change", content=item()["content"] + " Correction.", updated_at=LATER), LATER)
    changed = next(r for r in store.pending(5, LATER) if r["url"] == "https://example.org/src-change")
    assert changed["content_hash"] != row2["content_hash"]
    w2 = Writer()
    assert run(cfg, store, changed, w2, Reviewer(verdict()))["writer_calls"] == len(w2.calls) == 1

    row3 = pending(store, item(url="https://example.org/pol-change"))
    with pytest.raises(AnalysisError):
        run(cfg, store, row3, Writer(), Reviewer(verdict(), AnalysisError("timeout", retryable=True)))
    cfg["review"]["model"] = "different-review-model"
    res3 = run(cfg, store, row3, Writer(), Reviewer(verdict()))
    assert res3["writer_calls"] == 0 and res3["review_calls"] == 2 and not res3["cache_hit"]


def test_update_review_repairs_human_lock_and_missing_retained_source(context):
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

    # Human lock during review preserves operator text, honors legacy input_row, and rejects stale drafts on newer edits.
    row_lock = pending(store, {**original, "content": original["content"] + " A later report.", "updated_at": LATER})
    with pytest.raises(AnalysisError):
        run(cfg, store, row_lock, Writer(), Reviewer(AnalysisError("timeout", retryable=True)))
    with store.db:
        saved = job(store)
        legacy = json.loads(saved["record_json"])
        for field in ("request_budget", "untrusted_proposals", "input_proof", "input_row"):
            legacy.pop(field, None)
        legacy["schema_version"] = 1
        legacy["policy_hash"] = "a" * 64
        store.db.execute("UPDATE review_jobs SET policy_hash=?,record_json=? WHERE item_id=?",
                         (legacy["policy_hash"], json.dumps(legacy), row_lock["id"]))
    locked_rev = editorial.correct(store.db, story_id, {"why_it_matters": "Operator-reviewed wording."},
                                   reason="Corrected unsupported advice.", expect_hash=editorial.show(store.db, story_id)["hash"], observed=LATER)
    second = run(cfg, store, row_lock, Writer(), Reviewer(), allow_network=False)
    assert second["status"] == "locked" and second["writer_calls"] == second["review_calls"] == 0
    assert store.stories()[0]["why_it_matters"] == "Operator-reviewed wording."
    editorial.unlock(store.db, story_id, reason="Reopen briefly.", expect_hash=locked_rev["hash"], observed="2026-11-10T12:05:00Z")
    row_lock_v2 = pending(store, {**original, "content": original["content"] + " A second follow-up.", "updated_at": "2026-11-10T12:10:00Z"},
                          at="2026-11-10T12:10:00Z", ready="2026-11-10T12:10:00Z")
    with pytest.raises(AnalysisError):
        run(cfg, store, row_lock_v2, Writer(), Reviewer(AnalysisError("timeout", retryable=True)))
    editorial.correct(store.db, story_id, {"why_it_matters": "Re-locked operator wording."},
                      reason="Re-lock.", expect_hash=editorial.show(store.db, story_id)["hash"], observed="2026-11-10T12:15:00Z")
    row_lock_v3 = pending(store, {**original, "content": original["content"] + " A third follow-up.", "updated_at": "2026-11-10T12:20:00Z"},
                          at="2026-11-10T12:20:00Z", ready="2026-11-10T12:20:00Z")
    assert run(cfg, store, row_lock_v3, Writer(), Reviewer(), allow_network=False)["status"] == "deferred"

    # Missing retained source holds without a review call; network disabled defers cleanly.
    orig2 = item(url="https://example.org/miss-orig", content="Distinct missing source body text long enough to cluster. " * 5, updated_at="2026-11-09T12:00:00Z")
    seed_legacy(store, orig2, analysis(evidence=["Distinct missing source body text"]))
    with store.db:
        store.db.execute("UPDATE items SET payload=json_remove(payload,'$.content') WHERE url=?", (orig2["url"],))
    row_miss = pending(store, item(url="https://example.org/miss-mirror", source_id="mirror", content=orig2["content"]))
    res_miss = run(cfg, store, row_miss, Writer(), Reviewer())
    assert res_miss["status"] == "held" and res_miss["review_calls"] == 0
    assert store.db.execute("SELECT status FROM items WHERE id=?", (orig2["id"],)).fetchone()[0] == "published"

    row_net = pending(store, item(url="https://example.org/net-off"))
    w_net, c_net = Writer(), Reviewer()
    assert run(cfg, store, row_net, w_net, c_net, allow_network=False)["status"] == "deferred"
    assert w_net.calls == c_net.calls == []


def test_tag_notices_citations_updates_and_repair_holds(context, monkeypatch):
    cfg, store = context
    # Defer an unreviewed tag when network is disabled; hold if review proposes editing literal tag notice.
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

    # Routine tag uses local draft (no HTTP client) and requires editorial review; unreviewed commit raises ReviewRequired.
    r_routine = pending(store, item(kind="tag", title="data-refresh", url="https://example.org/tags/refresh", content="Routine"))
    with Analyzer(cfg) as writer:
        res_skip = run(cfg, store, r_routine, writer, Reviewer(verdict("skip", criterion="news_value")))
        assert writer.client is None and res_skip["status"] == "ignored" and res_skip["writer_calls"] == 0
    r_unrev = pending(store, item(kind="tag", title="another-tag", url="https://example.org/another-tag"))
    prep_unrev = store.prepare_candidate(r_unrev, tag_notice(json.loads(r_unrev["payload"])), LATER)
    with pytest.raises(ReviewRequired):
        store.commit_candidate(prep_unrev, prep_unrev["candidate"], "not-reviewed", LATER)

    # Tag never replaces richer tagged or released story in same release cluster (cites with 0 calls).
    for idx, state in enumerate(("tagged", "released")):
        ver = f"0.4.9.{20 + idx}"
        ex_item = item(kind="feed", product="tor", title=f"Tor {ver} release update", url=f"https://example.org/rel-{ver}")
        finish_reviewed(store, pending(store, ex_item), analysis(title=f"Detailed {ver} update", state=state), f"det-{ver}", DATE)
        before_upd = next(s for s in store.stories(20) if ver in s["title"])["updated_at"]
        later_tag = tag(title=f"tor-{ver}", url=f"https://gitlab.torproject.org/tpo/core/tor/-/tags/tor-{ver}", updated_at="2026-11-09T16:00:00Z")
        out = review_gate.process_item(cfg, store, pending(store, later_tag), Writer(), Reviewer(), DATE)
        st = next(s for s in store.stories(20) if ver in s["title"])
        assert out["status"] == "cited" and out["writer_calls"] == out["review_calls"] == 0
        assert st["state"] == state and st["updated_at"] == before_upd and len(st["sources"]) == 2

    # Tag on pre-release story runs update review without calling writer LLM, and holds if review repairs tag update.
    monkeypatch.setattr(Analyzer, "complete", lambda *a, **kw: (_ for _ in ()).throw(AssertionError("writer LLM forbidden")))
    for idx, state in enumerate(("developing", "fixed", "resolved", "mitigation-available", "merged")):
        ver = f"0.4.9.{30 + idx}"
        ex = item(kind="feed", product="tor", title=f"Tor {ver} release preparation", url=f"https://example.org/prep-{ver}")
        finish_reviewed(store, pending(store, ex), analysis(title=f"Prep {ver}", state=state), f"prep-{ver}", DATE)
        if state == "merged":
            bad_tag = tag(title=f"tor-{ver}", url=f"https://example.org/bad-tag-{ver}", updated_at="2026-11-09T16:00:00Z")
            held = run(cfg, store, pending(store, bad_tag), Analyzer(cfg), Reviewer(verdict("revise", update=True, repair={"state": "released"})))
            assert held["status"] == "held" and held["review_calls"] == 1
        t_item = tag(title=f"tor-{ver}", url=f"https://gitlab.torproject.org/tpo/core/tor/-/tags/tor-{ver}", updated_at="2026-11-09T16:00:00Z")
        with Analyzer(cfg) as real_writer:
            out = review_gate.process_item(cfg, store, pending(store, t_item), real_writer, ApprovingReviewer(cfg), "2026-11-09T16:05:00Z")
        st = next(s for s in store.stories(20) if f"Prep {ver}" == s["title"])
        assert out["status"] == "published" and out["writer_calls"] == 0 and out["review_calls"] == 2
        assert st["state"] == ("tagged" if state == "merged" else state)
        assert st["updates"][-1]["text"] == f"The upstream feed lists the tag “tor-{ver}”."


def test_editorial_coverage_skips_followups_and_bounds(context, monkeypatch):
    cfg, store = context
    # Publication times must stay inside the scenario's fixed chronology.
    monkeypatch.setattr(review_gate, "now_iso", lambda: "2026-11-11T00:00:00Z")
    # Same-cycle coverage before build is visible to second item without entering evidence packet.
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

    # Editorial skip on follow-up preserves existing article; material follow-up updates same article.
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

    # Interrupted verification restarts critique when coverage changes; approve receipt cannot authorize skip.
    r_int = pending(store, item(url="https://example.org/interrupted"))
    with pytest.raises(AnalysisError):
        run(cfg, store, r_int, Writer(), Reviewer(verdict(), AnalysisError("unavailable", retryable=True)))
    add_coverage(store, "mid-flight")
    resumed = Reviewer(verdict())
    res_int = run(cfg, store, r_int, Writer(), resumed)
    assert res_int["status"] == "published" and res_int["writer_calls"] == 0 and [c[2] for c in resumed.calls] == [False, True]

    r_wrong = pending(store, item(url="https://example.org/wrong-decision"))
    prep_w = store.prepare_candidate(r_wrong, analysis(), LATER)
    rec_w = approve(store, prep_w)
    with pytest.raises(ReviewRequired, match="authorize this decision"):
        store.commit_candidate(prep_w, prep_w["candidate"], "wrong", LATER, decision="skip", **rec_w)

    # Bounded coverage keeps exact prior visible text and bounded retracted rows.
    for n in range(40):
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
    cfg, store = context
    row = pending(store)
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), Reviewer(AnalysisError("timeout", retryable=True)))
    saved = job(store)
    approve(store, json.loads(saved["envelope_json"]), policy=saved["policy_hash"], result=cached)
    result = run(cfg, store, row, Writer(), Reviewer(verdict()))
    assert result["review_calls"] == 2 and not result["cache_hit"]


def test_status_retry_reverted_hold_and_rejected_show_views(context, monkeypatch):
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

    # Reverted held revision holds again without calling reviewer.
    store.ingest(item(content=item()["content"] + " Edited."), DATE)
    assert run(cfg, store, store.pending(1, LATER)[0], Writer(), Reviewer(), allow_network=False)["status"] == "deferred"
    store.ingest(item(), DATE)
    chk_rev = Reviewer(verdict())
    assert run(cfg, store, store.pending(1, LATER)[0], Writer(), chk_rev)["status"] == "held" and chk_rev.calls == []

    # Structured hold stays readable after a later rubric change without mutating DB.
    snap = list(store.db.iterdump())
    monkeypatch.setattr(review, "CRITERIA", (*review.CRITERIA, "a_later_criterion"))
    shown_h = rejection.show_item(store, row["id"])["final_review"]
    assert shown_h["stage"] == "held" and shown_h["candidate"]["title"] == analysis()["title"]
    assert shown_h["latest_review"]["criteria"]["operational_advice"]["outcome"] == "fail"
    assert shown_h["source_packet"]["sources"][0]["passages"][0]["id"] == "S1:P1"
    assert list(store.db.iterdump()) == snap
    monkeypatch.undo()

    # Operator retry preserves held audit and reuses completed draft.
    rejection.retry_item(store, row["id"], row["content_hash"], "The review prompt was revised", LATER)
    assert audit(store)["outcome"] == "held" and job(store)["stage"] == "drafted"
    w_ret = Writer()
    assert run(cfg, store, store.pending(1, LATER)[0], w_ret, Reviewer(verdict()))["status"] == "published"
    assert w_ret.calls == [] and audit(store)["outcome"] == "approved"

    # Reused approval after interrupted commit is readable in show_item.
    row_int = pending(store, item(url="https://example.org/int-show"))
    monkeypatch.setattr(store, "commit_candidate", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("crash")))
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

    # Database OperationalError is not an item strike.
    store.ingest(item(url="https://example.org/locked"), DATE)
    monkeypatch.setattr(cli, "process_item", lambda *a, **kw: (_ for _ in ()).throw(sqlite3.OperationalError("database is locked")))
    with pytest.raises(sqlite3.OperationalError):
        cli.run(cfg, store)
    assert tuple(store.db.execute("SELECT status,rejections FROM items WHERE url='https://example.org/locked'").fetchone()) == ("pending", 0)
    monkeypatch.undo()


def test_run_report_counts_outcomes_model_calls_and_isolates_invalid_outputs(tmp_path, monkeypatch):
    from onionflash.config import DEFAULTS
    from onionflash.store import Store

    cfg = {**DEFAULTS, "storage": {"database": str(tmp_path / "r1.db"), "output_dir": str(tmp_path / "p1")}, "sources": []}
    with Store(cfg["storage"]["database"]) as store:
        outcomes = iter([("held", False), ("stale", False), ("published", True), ("ignored", False), ("ignored", True)])
        monkeypatch.setattr(cli, "process_item", lambda *a, **kw: dict(zip(("status", "cache_hit"), next(outcomes))))
        monkeypatch.setattr(cli, "build", lambda *a: {})
        for name in ("one", "two", "three", "four", "five"):
            store.ingest(item(url="https://example.org/" + name), DATE)
        rep = cli.run(cfg, store)
        assert [rep[k] for k in ("analyzed", "analysis_failed", "review_stale", "review_cache_hits")] == [4, 0, 1, 2]
        assert rep["decisions"] == {} and "review_held" not in rep and "review_skipped" not in rep
    monkeypatch.undo()

    cfg2 = {**DEFAULTS, "llm": {**DEFAULTS["llm"], "base_url": "https://llm.example/v1"},
            "storage": {"database": str(tmp_path / "r2.db"), "output_dir": str(tmp_path / "p2")}, "sources": []}
    monkeypatch.setenv(cfg2["llm"]["api_key_env"], "test-key")

    class Transport:
        def request(self, method, url, headers=None, json_body=None):
            if json_body["response_format"]["json_schema"]["name"] != "onionflash_news":
                raise FetchError("network request failed", retryable=True)
            body = {"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(analysis(why_it_matters=""))}}]}
            return Response(200, json.dumps(body).encode(), {}, url)

        def close(self):
            pass

    monkeypatch.setattr("onionflash.llm.HttpClient", lambda *a, **kw: Transport())
    monkeypatch.setattr(cli, "build", lambda *a: {})
    with Store(cfg2["storage"]["database"]) as store:
        for name in ("one", "two"):
            store.ingest(item(url="https://example.org/" + name), DATE)
        rep2 = cli.run(cfg2, store)
        assert (rep2["analysis_failed"], rep2["model_calls"]) == (2, 4)
    monkeypatch.undo()

    cfg3 = {**DEFAULTS, "storage": {"database": str(tmp_path / "r3.db"), "output_dir": str(tmp_path / "p3")}, "sources": []}
    built = []
    monkeypatch.setattr(cli, "Analyzer", lambda *a, **kw: contextlib.nullcontext(
        Writer(lambda inc: analysis(title="\uffff") if inc["url"].endswith("/draft") else analysis())))
    class Replies:
        calls = 0
        def review(self, cand, pkt, *, on_request=None, **kwargs):
            if on_request is not None:
                on_request(1)
            return review.validate_review({} if "/reply" in pkt["sources"][0]["url"] else verdict(), pkt)
    monkeypatch.setattr(cli, "Reviewer", lambda *a, **kw: contextlib.nullcontext(Replies()))
    monkeypatch.setattr(cli, "build", lambda *a: built.append(True) or {})
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
    cfg, store = context
    url = "https://gitlab.torproject.org/tpo/core/tor/-/work_items/41499"
    n1 = {"id": "gid://gitlab/Note/1", "url": url + "#note_1", "title": "Public comment by @alice",
          "author": "alice", "created_at": DATE, "body": "Initial report details for the relay issue."}
    issue = _compose(item(url=url, updated_at=DATE), [n1], DATE, source_key="k")
    assert run(cfg, store, pending(store, issue), Writer(analysis(evidence=["Initial report details for the relay issue."])),
               Reviewer(verdict()))["status"] == "published"
    story_id = store.stories()[0]["id"]

    n2 = {"id": "gid://gitlab/Note/2", "url": url + "#note_2", "title": "Public comment by @bob",
          "author": "bob", "created_at": LATER, "body": "> Initial report details for the relay issue.\n> Agreed."}
    assert store.ingest(_compose(issue, [n1, n2], LATER, source_key="k"), LATER)
    assert run(cfg, store, store.pending(1, LATER)[0], Writer(), Reviewer()) == {
        "status": "ignored", "writer_calls": 0, "review_calls": 0, "cache_hit": False}
    assert store.db.execute("SELECT code FROM decision_log ORDER BY id DESC LIMIT 1").fetchone()[0] == "skipped.gate.no_new_content"

    t99 = item(kind="tag", title="tor-0.4.9.99", url="https://example.org/tags/tor-0.4.9.99", content="")
    store.ingest(t99, DATE)
    assert run(cfg, store, next(r for r in store.pending(5, DATE) if r["id"] == t99["id"]), Writer(), Reviewer(verdict()))["status"] == "published"
    assert store.ingest({**t99, "content": "new annotation", "updated_at": LATER}, LATER)
    assert run(cfg, store, next(r for r in store.pending(5, LATER) if r["id"] == t99["id"]), Writer(), Reviewer()) == {
        "status": "ignored", "writer_calls": 0, "review_calls": 0, "cache_hit": False}

    locked = editorial.correct(store.db, story_id, {"priority": "normal"}, reason="Lower priority.",
                               expect_hash=editorial.show(store.db, story_id)["hash"], observed=LATER)
    later2 = "2026-11-10T14:00:00Z"
    n3 = {"id": "gid://gitlab/Note/3", "url": url + "#note_3", "title": "Public comment by @maint",
          "author": "maint", "created_at": later2, "body": "Maintainers merged the fix into main."}
    assert store.ingest(_compose(issue, [n1, n2, n3], later2, source_key="k"), later2)
    w_locked = Writer(update_analysis(update="Maintainers merged the fix.", state="merged", evidence=["Maintainers merged the fix into main."]))
    assert run(cfg, store, next(r for r in store.pending(5, later2) if r["id"] == issue["id"]), w_locked, Reviewer())["status"] == "locked"
    assert w_locked.calls[0]["content"] == "" and [n["url"] for n in w_locked.calls[0]["public_comments"]] == [url + "#note_3"]
    assert store.pending(5, later2) == []

    editorial.unlock(store.db, story_id, reason="Allow queued updates.", expect_hash=locked["hash"], observed="2026-11-10T15:00:00Z")
    requeued = [r for r in store.pending(5, "2026-11-10T15:00:00Z") if r["id"] == issue["id"]]
    assert len(requeued) == 1
    assert run(cfg, store, requeued[0], Writer(update_analysis(update="Maintainers merged the fix.", state="merged",
                                                               evidence=["Maintainers merged the fix into main."])),
               Reviewer(verdict(update=True)))["status"] == "published"
    assert next(s for s in store.stories(5) if s["id"] == story_id)["updates"] == [
        {"at": later2, "text": "Maintainers merged the fix.", "sources": [{"url": url + "#note_3", "title": n3["title"]}]}]

    later3, later4 = "2026-11-10T16:00:00Z", "2026-11-10T17:00:00Z"
    list_base = "https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/message/"
    store.ingest(item(kind="feed", url=list_base + "MSG0/", source_id="msg-0", title="[tor-announce] Tor 0.4.9.15 released",
                      content="Initial report details for the relay issue.", updated_at=DATE), DATE)
    assert run(cfg, store, store.pending(1, DATE)[0], Writer(analysis(evidence=["Initial report details for the relay issue."])),
               Reviewer(verdict()))["status"] == "published"
    store.ingest(item(kind="feed", url=list_base + "MSG1/", source_id="msg-1", title="[tor-relays] Re: Tor 0.4.9.15 released",
                      content="On Wed, Nov 10, 2026 at 09:00 AM, alice via tor-relays wrote:\n\n> Initial report details for the relay issue.\n>> Older nested quote with 53-day-old relay numbers.",
                      updated_at=later3), later3)
    assert run(cfg, store, store.pending(1, later3)[0], Writer(), Reviewer()) == {
        "status": "ignored", "writer_calls": 0, "review_calls": 0, "cache_hit": False}
    store.ingest(item(kind="feed", url=list_base + "MSG2/", source_id="msg-2", title="[tor-relays] Re: Tor 0.4.9.15 released",
                      content="Operator observed three dropped circuits.\n\nOn Wed, Nov 10, 2026 at 09:00 AM, alice via tor-relays wrote:\n\n> Quoted 53-day-old relay backstory.",
                      updated_at=later4), later4)
    w_reply = Writer(update_analysis(update="An operator observed three dropped circuits.", state="developing",
                                     evidence=["Operator observed three dropped circuits."]))
    assert run(cfg, store, store.pending(1, later4)[0], w_reply, Reviewer(verdict(update=True)))["status"] == "published"
    assert w_reply.calls[0]["content"].strip() == "Operator observed three dropped circuits."
    assert "53-day-old" not in w_reply.calls[0]["content"] and "wrote:" not in w_reply.calls[0]["content"]


def test_pending_update_rewrites_and_own_comment_cutoff_admits_edited_notes(context):
    cfg, store = context
    seed_legacy(store, item(title="Tor 0.4.9.16 released", kind="feed", authority="official", content="Tor 0.4.9.16 was released with fixes."),
                analysis(title="Tor 0.4.9.16 released", state="released", confidence="confirmed"))
    m1 = item(title="Tor 0.4.9.16 released", kind="feed", url="https://example.org/m1", source_id="m1",
              content="Debian packages for Tor 0.4.9.16 are live.", updated_at=LATER)
    m2 = item(title="Tor 0.4.9.16 released", kind="feed", url="https://example.org/m2", source_id="m2",
              content="RPM packages for Tor 0.4.9.16 are live.", updated_at="2026-11-10T13:00:00Z")
    store.ingest(m1, LATER)
    store.ingest(m2, LATER)
    rows = {r["url"]: r for r in store.pending(5, LATER)}
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
    assert review_gate.process_item(
        cfg, store, pending(store, issue_a),
        Writer(analysis(title="Descriptor stall reported in Tor 0.4.9.30", summary="Initial report of descriptor stall in Tor 0.4.9.30.",
                        state="developing", evidence=["Initial report of descriptor stall in Tor 0.4.9.30."])),
        Reviewer(verdict(), verdict()), "2026-11-08T10:05:00Z",
    )["status"] == "published"
    story_id = next(s for s in store.stories(10) if "0.4.9.30" in s["title"])["id"]

    other_src = item(kind="gitlab_mr", url="https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/1950",
                     title="Investigate descriptor stall (closes #49500)", content="Closes #49500 with diagnostic logging.",
                     upstream_state="merged", published_at="2026-11-10T12:00:00Z", updated_at="2026-11-10T12:00:00Z")
    assert review_gate.process_item(
        cfg, store, pending(store, other_src),
        Writer(update_analysis(update="A merge request added diagnostic logging for the stall.", state="merged",
                               evidence=["Closes #49500 with diagnostic logging."])),
        Reviewer(verdict(update=True), verdict(update=True)), "2026-11-10T12:05:00Z",
    )["status"] == "published"

    note_v1 = {"id": "501", "author": "maintainer", "title": "Comment by maintainer",
               "created_at": "2026-11-09T09:00:00Z", "url": issue_url + "#note_501",
               "body": "Root cause narrowed to malformed extra-info lines."}
    assert store.ingest({**issue_a, "updated_at": "2026-11-09T09:00:00Z", "public_comments": [note_v1]}, "2026-11-11T08:00:00Z")
    w_nov9 = Writer(update_analysis(update="Maintainers narrowed the root cause to malformed extra-info lines.",
                                    state="merged", evidence=["Root cause narrowed to malformed extra-info lines."]))
    assert review_gate.process_item(cfg, store, store.pending(1, "2026-11-11T08:00:00Z")[0], w_nov9,
                                    Reviewer(verdict(update=True), verdict(update=True)), "2026-11-11T08:00:00Z")["status"] == "published"
    assert len(w_nov9.calls) == 1
    assert next(s for s in store.stories(10) if s["id"] == story_id)["updates"][-1]["sources"] == [
        {"url": canonical_issue_url + "#note_501", "title": "Comment by maintainer"}]

    note_v2 = {**note_v1, "body": "Correction: extra-info parsing was unaffected; bug is in routerstatus retry."}
    issue_a_edited = {**issue_a, "updated_at": "2026-11-12T14:00:00Z", "public_comments": [note_v2]}
    assert store.ingest(issue_a_edited, "2026-11-12T14:05:00Z")
    w_edit = Writer(update_analysis(update="A corrected maintainer note places the bug in routerstatus retry.",
                                    state="merged", evidence=["Correction: extra-info parsing was unaffected; bug is in routerstatus retry."]))
    assert review_gate.process_item(cfg, store, store.pending(1, "2026-11-12T14:05:00Z")[0], w_edit,
                                    Reviewer(verdict(update=True), verdict(update=True)), "2026-11-12T14:05:00Z")["status"] == "published"
    st_edit = next(s for s in store.stories(10) if s["id"] == story_id)
    assert st_edit["updates"][-1]["at"] == "2026-11-12T14:00:00Z"

    note_v2_quoted = {**note_v2, "body": note_v2["body"] + "\n\n> Earlier quoted context."}
    assert store.ingest({**issue_a, "updated_at": "2026-11-12T15:00:00Z", "public_comments": [note_v2_quoted]}, "2026-11-12T15:05:00Z")
    res_same = review_gate.process_item(cfg, store, store.pending(1, "2026-11-12T15:05:00Z")[0], Writer(), Reviewer(), "2026-11-12T15:05:00Z")
    assert res_same["status"] == "ignored" and res_same["writer_calls"] == res_same["review_calls"] == 0
    assert review_gate.candidate_mod._source_cutoff(store.db, st_edit, None, issue_a_edited) == "2026-11-12T14:00:00Z"


def test_trusted_operator_vs_community_list_incidents_in_gate(context):
    cfg, store = context
    list_base = "https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/message/"

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
    assert run(cfg, store, trusted_inc, Writer(trusted_draft), Reviewer(verdict(), verdict()))["status"] == "published"

    untrusted_inc = pending(store, item(url=list_base + "comm1/", kind="feed", authority="community",
                                        content="Single operator claims relays face deanonymization attack."))
    untrusted_draft = analysis(title="Single operator claims relays face deanonymization attack",
                               summary="A mailing-list post claims relays face a deanonymization attack.",
                               category="security", tags=["security"], confidence="reported", state="developing",
                               evidence=["Single operator claims relays face deanonymization attack."])
    assert run(cfg, store, untrusted_inc, Writer(untrusted_draft), Reviewer(verdict(), verdict()))["status"] == "held"
    assert codes(store, untrusted_inc) == ["held.final_check.untrusted_operator_claim"]

    tordev_base = "https://lists.torproject.org/mailman3/hyperkitty/list/tor-dev@lists.torproject.org/message/"
    prop_item = pending(store, item(
        url=tordev_base + "prop375/",
        kind="feed",
        authority="community",
        title="[tor-dev] Proposal 375: Rate-limiting circuit flooding",
        content="Proposal 375 specifies rate limits to defend against circuit flooding and DoS attacks.",
    ))
    prop_draft = analysis(
        title="Proposal 375: Rate-limiting circuit flooding",
        summary="Proposal 375 on tor-dev specifies rate limits to defend against circuit flooding and DoS attacks.",
        category="protocol",
        tags=["protocol", "dos"],
        confidence="reported",
        state="developing",
        evidence=["Proposal 375 specifies rate limits to defend against circuit flooding"],
    )
    assert run(cfg, store, prop_item, Writer(prop_draft), Reviewer(verdict(), verdict()))["status"] == "published"

    prop_disputed = pending(store, item(
        url=tordev_base + "prop376/",
        kind="feed",
        authority="community",
        title="[tor-dev] Proposal 376: Circuit flood defense parameters",
        content="Proposal 376 adjusts rate-limiting parameters to mitigate circuit flooding and DoS attacks.",
    ))
    prop_disputed_draft = analysis(
        title="Proposal 376: Circuit flood defense parameters",
        summary="Proposal 376 on tor-dev adjusts rate-limiting parameters to mitigate circuit flooding and DoS attacks.",
        category="protocol",
        tags=["protocol", "dos"],
        confidence="reported",
        state="developing",
        evidence=["Proposal 376 adjusts rate-limiting parameters to mitigate circuit flooding"],
    )
    assert run(
        cfg, store, prop_disputed, Writer(prop_disputed_draft),
        Reviewer(verdict(), verdict("skip", criterion="news_value")),
    )["status"] == "held"
    assert codes(store, prop_disputed) == ["held.verification.disagreed_news"]
    elig = review_gate.approval(cfg, store, prop_disputed["id"])
    assert elig["eligible"] is True
    approved = rejection.approve_item(cfg, store, prop_disputed["id"], elig["hash"], "Publish Tor proposal", observed=LATER)
    assert approved["status"] == "published"
