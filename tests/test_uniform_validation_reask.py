"""Invalid replies cannot change the text that the bounded correction reviews."""
import copy
import json

import pytest

from helpers import Writer, analysis, pending, run_gate as run, verdict
from onionflash import review, review_gate
from onionflash.analyze import AnalysisError
from onionflash.transport import FetchError
from test_review_request_budget import context, inconsistent, record, reviewer, saved_audit
from test_review_scope_budget import untrusted_update, update_case


def payloads(checker):
    return [json.loads(request["messages"][1]["content"]) for request in checker.client.requests]


@pytest.mark.parametrize("edit", [
    {"summary": "A different account that has not been validated."},
    {"why_it_matters": ""},
    {"confidence": "suspected"},
])
def test_usable_invalid_edits_are_discarded_before_initial_correction(context, edit):
    cfg, store = context
    row = pending(store)
    draft = analysis(why_it_matters="The report describes the stated consequence.")
    checker = reviewer(cfg, inconsistent(edit), verdict(), verdict())
    assert run(cfg, store, row, Writer(draft), checker)["status"] == "published"
    bodies = payloads(checker)
    assert checker.calls == 3
    assert bodies[1] == {**bodies[0], "validation_error": review.INCONSISTENT_VERDICT}
    assert bodies[2]["candidate"] == bodies[0]["candidate"]
    audit = saved_audit(store)
    event = audit["untrusted_proposals"][0]
    assert event["repair"] is None and event["candidate_after_hash"] is None
    assert event["changed_fields"] == [] and not event["accepted"]
    assert event["reask_trigger"] and event["disposition"] == "unusable"
    assert [(r["request"], r["stage"]) for r in audit["reviews"]] == [(2, "review"), (3, "verification")]
    assert "UNTRUSTED_PREVIOUS_CRITERIA_SENTINEL" not in json.dumps(checker.client.requests)


def test_valid_corrective_repair_still_requires_its_fresh_verification(context):
    cfg, store = context
    row = pending(store)
    accepted = {"summary": "The source describes a qualified observation."}
    checker = reviewer(cfg, inconsistent({"summary": "An unvalidated different assertion."}),
                       verdict("revise", criterion="source_support", repair=accepted), verdict())
    assert run(cfg, store, row, Writer(), checker)["status"] == "published"
    bodies = payloads(checker)
    assert bodies[1]["candidate"] == bodies[0]["candidate"]
    assert bodies[2]["candidate"]["summary"] == accepted["summary"]
    audit = saved_audit(store)
    assert checker.calls == 3 and audit["reviews"][0]["reask_response"]
    assert audit["reviews"][0]["result"]["verdict"] == "revise"
    assert audit["reviews"][-1]["stage"] == "verification"
    assert all(not p["accepted"] for p in audit["untrusted_proposals"])


@pytest.mark.parametrize("first_verdict", ["revise", "hold", "skip"])
def test_second_invalid_reply_cannot_apply_a_different_usable_edit(context, first_verdict):
    cfg, store = context
    row = pending(store)
    checker = reviewer(cfg, inconsistent(action=first_verdict),
                       inconsistent({"summary": "A second unvalidated assertion."}), verdict(), verdict())
    with pytest.raises(review.InconsistentReview):
        run(cfg, store, row, Writer(), checker)
    assert checker.calls == 2 and not store.stories()
    audit = record(store)
    assert audit["reviews"] == [] and audit["request_budget"]["reserved"] == 2
    assert [p["accepted"] for p in audit["untrusted_proposals"]] == [False, False]
    assert audit["request_budget"]["validation_reask"]["response"] == 2
    idle = reviewer(cfg, verdict(), verdict())
    with pytest.raises(review.InconsistentReview):
        run(cfg, store, row, Writer(), idle)
    assert idle.calls == 0


def test_verification_correction_uses_same_candidate_and_remains_verification(context):
    cfg, store = context
    row = pending(store)
    checker = reviewer(cfg, verdict(), inconsistent({"summary": "Unvalidated verification rewrite."}), verdict())
    assert run(cfg, store, row, Writer(), checker)["status"] == "published"
    bodies = payloads(checker)
    assert bodies[2] == {**bodies[1], "validation_error": review.INCONSISTENT_VERDICT}
    assert bodies[0]["candidate"] == bodies[2]["candidate"]
    audit = saved_audit(store)
    assert audit["reviews"][-1]["stage"] == "verification"
    assert audit["reviews"][-1]["reask_response"] and checker.calls == 3


def test_update_invalid_edit_cannot_change_latest_text_or_readonly_history(context):
    cfg, _ = context
    case, prepared = update_case()
    original = review.personal_attribution.normalize(case["candidate"], update=True)
    prepared = {**prepared, "candidate": original}
    audit = {"candidate": original, "reviews": [], "policy_hash": review.policy_hash(cfg),
             **review_gate.initial_review_state()}
    requests = review_gate.ReviewRequests(audit)
    checker = reviewer(cfg, untrusted_update({"update": "An unsupported new update."}),
                       verdict(update=True), verdict(update=True))
    stage, target = review_gate.advance_review(checker, "review", original, prepared, audit, requests)
    assert stage == "verify" and target == original and checker.calls == 2
    action, target = review_gate.advance_review(checker, stage, target, prepared, audit, requests)
    assert action == "approve" and target == original and checker.calls == 3
    bodies = payloads(checker)
    assert bodies[1] == {**bodies[0], "validation_error": review.INCONSISTENT_VERDICT}
    assert bodies[2]["candidate"] == original


def test_discarded_valid_edit_correction_transport_resume_retains_target_and_charge(context):
    cfg, store = context
    row = pending(store)
    first = reviewer(cfg, inconsistent({"summary": "An unvalidated assertion."}), FetchError("temporary", status=500))
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), first)
    before = copy.deepcopy(record(store))
    assert before["request_budget"]["reserved"] == 2
    assert before["request_budget"]["validation_reask"]["transport_failed"]
    resumed = reviewer(cfg, verdict(), verdict())
    assert run(cfg, store, row, Writer(), resumed)["status"] == "published"
    assert payloads(resumed)[0] == payloads(first)[1]
    audit = saved_audit(store)
    assert audit["request_budget"]["reserved"] == 4
    assert audit["request_budget"]["validation_reask"]["attempts"] == [2, 3]
    assert all(not p["accepted"] for p in audit["untrusted_proposals"])


def test_recovery_dispatch_policy_is_in_cache_identity(context, monkeypatch):
    cfg, _ = context
    before = review.policy_hash(cfg)
    monkeypatch.setattr(review, "INVALID_REVIEW_POLICY", "different-invalid-review-policy")
    assert review.policy_hash(cfg) != before
