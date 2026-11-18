"""A repaired release refusal needs two fresh approvals of the exact same text."""
import copy
import json

import pytest

from helpers import DATE, Reviewer, Writer, job, pending, run_gate, verdict
from onionflash import review, review_gate, source_quote
from onionflash.config import DEFAULTS
from onionflash.llm import AnalysisError
from onionflash.util import digest
from test_release_framing_repair import REPAIR, TITLE, audit, draft, incoming, prepared, step
from test_review_request_budget import context, reviewer


def first_reply(repair=None):
    result = verdict("revise", criterion="news_value", repair=REPAIR if repair is None else repair)
    result["criteria"]["source_support"]["outcome"] = "fail"
    return result


def history(prepared, count=2, repair=None):
    original = prepared["candidate"]
    first = review.validate_review(first_reply(repair), prepared["packet"], coverage=prepared["coverage"])
    repaired = review.apply_repair(original, first["repair"], packet=prepared["packet"])
    bound = review_gate._context(prepared, review.policy_hash(DEFAULTS))
    entries = [{"stage": "review", "candidate_hash": digest(original), "request": 1, "result": first, **bound}]
    entries += [{"stage": "verification", "candidate_hash": digest(repaired), "request": n,
                 "result": review.validate_review(verdict(), prepared["packet"]), **bound}
                for n in range(2, count + 1)]
    return entries, repaired


def test_recovery_requires_another_fresh_full_request(context, prepared):
    cfg, store = context
    original = copy.deepcopy(prepared["candidate"])
    record = audit(prepared, cfg)
    requests = review_gate.ReviewRequests(record)
    checker = reviewer(cfg, first_reply(), verdict(), verdict())
    action, repaired = step(checker, "review", original, prepared, record, requests)
    assert action == "verify" and repaired != original
    action, same = step(checker, action, repaired, prepared, record, requests)
    assert action == "verify" and same == repaired and requests.actual == 2
    review_gate.validate_review_state(record, "verify", same, prepared)
    action, approved = step(checker, action, same, prepared, record, requests)
    assert action == "approve" and approved == repaired and requests.actual == 3
    assert record["reviews"][0]["result"]["criteria"]["news_value"]["outcome"] == "fail"
    wire = [json.loads(r["messages"][1]["content"]) for r in checker.client.requests]
    assert [p["candidate"] for p in wire] == [original, repaired, repaired]
    assert wire[1] == wire[2]
    assert "previous_review" not in wire[2] and "criteria" not in wire[2]
    assert review.VERIFY_PROMPT in checker.client.requests[2]["messages"][0]["content"]
    record.update(candidate=approved, outcome="approved",
                  approval_key=review_gate._approval_key(approved, prepared, record["policy_hash"]))
    review_gate.validate_review_state(record, "approved", approved, prepared)
    assert not store.stories()


@pytest.mark.parametrize("damage", [
    "historical", "missing-snapshot", "uncited", "unofficial", "multiple", "different-release",
    "old", "future", "missing-date", "incomplete", "prior-story", "existing-story", "association",
    "update", "tag", "missing-packet",
])
def test_recovery_does_not_widen_the_release_anchor(prepared, damage):
    entries, repaired = history(prepared)
    feed = prepared["packet"]["sources"][0]
    if damage == "historical": feed["snapshot"] = "historical"
    elif damage == "missing-snapshot": feed.pop("snapshot")
    elif damage == "uncited": feed["url"] = "https://example.org/uncited"
    elif damage == "unofficial": feed["authority"] = "community"
    elif damage == "multiple": prepared["packet"]["sources"].append(copy.deepcopy(feed))
    elif damage == "different-release": feed["title"] = "Tor Browser 18.0 released"
    elif damage in {"old", "future", "missing-date"}:
        feed["published_at"] = {"old": "2026-10-01T12:00:00Z", "future": "2026-12-01T12:00:00Z",
                                "missing-date": None}[damage]
    elif damage == "incomplete": prepared["packet"]["truncated"] = True
    elif damage == "prior-story": prepared["coverage"]["prior_story"] = {"id": "covered"}
    elif damage == "existing-story": prepared["row"]["story_id"] = "covered"
    elif damage == "association": prepared["how"] = "source"
    elif damage == "update": prepared["mode"] = "update"
    elif damage == "tag": prepared["payload"]["editorial_kind"] = "tag"
    elif damage == "missing-packet": prepared["packet"] = None
    assert review_gate.next_step(entries, repaired, prepared) == ("hold", ("verification", "disagreed_news"))


@pytest.mark.parametrize("damage", [
    "initial-skip", "initial-hold", "initial-approve", "initial-verification", "initial-label-repair",
    "news-insufficient", "novelty-fail", "novelty-insufficient", "initial-route", "initial-hash",
    "current-hash", "first-verification-hash", "source-hash", "coverage-hash", "binding-hash", "policy-hash",
    "first-verification-repair", "first-verification-route", "first-verification-label-repair", "extra-review",
])
def test_recovery_requires_the_exact_bounded_review_history(prepared, damage):
    entries, repaired = history(prepared, count=3)
    initial, verified = entries[0], entries[1]
    if damage.startswith("initial-") and damage.split("-", 1)[1] in {"skip", "hold", "approve"}:
        initial["result"]["verdict"] = damage.split("-", 1)[1]
    elif damage == "initial-verification": initial["stage"] = "verification"
    elif damage == "initial-label-repair": initial["issue"] = "release_labels"
    elif damage == "news-insufficient": initial["result"]["criteria"]["news_value"]["outcome"] = "insufficient"
    elif damage.startswith("novelty-"):
        initial["result"]["criteria"]["new_information"]["outcome"] = damage.split("-", 1)[1]
    elif damage == "initial-route": initial["result"]["same_story"] = "a" * 24
    elif damage == "initial-hash": initial["candidate_hash"] = "0" * 64
    elif damage == "current-hash": repaired["summary"] += " Extra detail."
    elif damage == "first-verification-hash": verified["candidate_hash"] = "0" * 64
    elif damage in {"source-hash", "coverage-hash", "binding-hash", "policy-hash"}:
        verified[damage.replace("-", "_")] = "0" * 64
    elif damage == "first-verification-repair": verified["result"]["repair"] = {"summary": "A different statement."}
    elif damage == "first-verification-route": verified["result"]["same_story"] = "a" * 24
    elif damage == "first-verification-label-repair": verified["issue"] = "release_labels"
    elif damage == "extra-review": entries.append(copy.deepcopy(entries[-1]))
    assert review_gate.next_step(entries, repaired, prepared) == ("hold", ("verification", "disagreed_news"))


@pytest.mark.parametrize("repair", [{"title": TITLE}, {"title": "  " + TITLE + "  "},
                                    {"why_it_matters": ""}, {**REPAIR, "state": "released"},
                                    {**REPAIR, "category": "release"}, {**REPAIR, "tags": ["release"]}])
def test_unchanged_prose_or_other_edits_cannot_recover(prepared, repair):
    entries, repaired = history(prepared)
    entries[0]["result"]["repair"] = repair
    try:
        repaired = review.apply_repair(prepared["candidate"], repair, packet=prepared["packet"])
    except review.ReviewError:
        repaired = prepared["candidate"]
    entries[1]["candidate_hash"] = digest(repaired)
    assert review_gate.next_step(entries, repaired, prepared) == ("hold", ("verification", "disagreed_news"))


@pytest.mark.parametrize("refusal", [verdict("hold", criterion="source_support"),
                                    verdict("skip", criterion="new_information"),
                                    verdict("revise", criterion="source_support", repair=REPAIR)])
def test_another_refusal_never_retries_the_recovery(context, prepared, refusal):
    cfg, _ = context
    record = audit(prepared, cfg)
    requests = review_gate.ReviewRequests(record)
    checker = Reviewer(first_reply(), verdict(), refusal)
    stage, public = step(checker, "review", prepared["candidate"], prepared, record, requests)
    stage, public = step(checker, stage, public, prepared, record, requests)
    assert stage == "verify"
    assert step(checker, stage, public, prepared, record, requests)[0] == "hold"
    assert requests.actual == 3


def test_request_budget_cannot_be_replenished_by_recovery(context, prepared):
    cfg, _ = context
    record = audit(prepared, cfg)
    requests = review_gate.ReviewRequests(record)
    checker = Reviewer(first_reply(), verdict(), verdict())
    stage, public = step(checker, "review", prepared["candidate"], prepared, record, requests)
    stage, public = step(checker, stage, public, prepared, record, requests)
    record["request_budget"]["reserved"] = 7
    with pytest.raises(review.ReviewLimitReached):
        step(checker, stage, public, prepared, record, requests)
    assert requests.actual == 2 and len(checker.calls) == 2


def test_recovery_keeps_final_checks_and_release_label_checks(context, prepared):
    cfg, _ = context
    for changes, expected in [({"summary": "Tor Browser 17.2 fixed the connection failure."},
                                ("hold", ("final_check", "completed_action"))),
                               ({}, None)]:
        value = copy.deepcopy(prepared)
        if expected is None:
            value["candidate"].update(category="release", tags=["release"], state="developing")
        else:
            value["payload"]["editorial_kind"] = "gitlab_issue"
        entries, repaired = history(value, count=3, repair={**REPAIR, **changes})
        action = review_gate.next_step(entries, repaired, value)
        assert action == (expected or ("repair", repaired))


@pytest.mark.parametrize("impact", ["keep", "clear", "quote"])
def test_native_recovery_preserves_the_ordinary_impact_rules(context, impact):
    cfg, store = context
    sentence = "Users can install the update through the existing application menu."
    row = pending(store, {**incoming(), "content": incoming()["content"] + "\n\n" + sentence + "\n\nFurther release notes."})
    original = {**draft(), "why_it_matters": "Users can install the update from the application menu."}
    edits = {**REPAIR}
    if impact == "clear": edits["why_it_matters"] = ""
    elif impact == "quote": edits["why_it_matters"] = source_quote.PREFIX + sentence + "”"
    checker = reviewer(cfg, first_reply(edits), verdict(), verdict())
    result = run_gate(cfg, store, row, Writer(original), checker)
    assert result["status"] == "published" and result["review_calls"] == 3
    proof = json.loads(store.db.execute("SELECT review_record FROM analyses").fetchone()[0])
    target = proof["candidate"]
    assert target["why_it_matters"] == edits.get("why_it_matters", original["why_it_matters"])
    assert [entry["candidate_hash"] for entry in proof["reviews"]] == [
        digest(proof["prepared"]["candidate"]), digest(target), digest(target)]
    assert proof["request_budget"]["reserved"] == 3 and job(store) is None
    assert store.stories()[0]["why_it_matters"] == target["why_it_matters"]


def test_native_recovery_pending_verification_resumes_without_writer(context):
    cfg, store = context
    row = pending(store, incoming())
    checker = reviewer(cfg, first_reply(), verdict(), AnalysisError("interrupted", retryable=True))
    with pytest.raises(AnalysisError):
        run_gate(cfg, store, row, Writer(draft()), checker)
    saved, _, envelope, record, same_source = review_gate._saved_job(store, row, cfg)
    assert same_source and saved["stage"] == "verify" and len(record["reviews"]) == 2
    assert record["request_budget"]["reserved"] == 3
    review_gate.validate_review_state(record, "verify", record["candidate"], envelope)
    resumed = reviewer(cfg, verdict())
    result = run_gate(cfg, store, row, Writer(draft()), resumed)
    assert result == {"status": "published", "writer_calls": 0, "review_calls": 1, "cache_hit": False}
    proof = json.loads(store.db.execute("SELECT review_record FROM analyses").fetchone()[0])
    assert [entry["request"] for entry in proof["reviews"]] == [1, 2, 4]


def test_native_recovery_approved_receipt_survives_commit_interruption(context, monkeypatch):
    from onionflash.candidate import StaleCandidate

    cfg, store = context
    row = pending(store, incoming())
    commit = store.commit_candidate

    def interrupted(*args, **kwargs):
        raise StaleCandidate("Commit interrupted")

    monkeypatch.setattr(store, "commit_candidate", interrupted)
    assert run_gate(cfg, store, row, Writer(draft()), reviewer(cfg, first_reply(), verdict(), verdict()))["status"] == "stale"
    saved, _, envelope, record, _ = review_gate._saved_job(store, row, cfg)
    assert saved["stage"] == "approved" and len(record["reviews"]) == 3
    review_gate.validate_review_state(record, "approved", record["candidate"], envelope)
    monkeypatch.setattr(store, "commit_candidate", commit)
    checker = reviewer(cfg, verdict())
    assert run_gate(cfg, store, row, Writer(draft()), checker) == {
        "status": "published", "writer_calls": 0, "review_calls": 0, "cache_hit": True}
    assert not checker.client.requests
