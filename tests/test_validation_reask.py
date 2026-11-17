"""A validation correction spends one durable slot and never trusts the rejected reply."""
import copy
import json
from types import SimpleNamespace

import pytest

from helpers import approve, update_analysis, verdict
from onionflash import review, review_gate
from onionflash.analyze import AnalysisError
from onionflash.transport import DeadlineReached, FetchError
from helpers import seed_source_story as _publish
from helpers import analysis, make_item as item
from helpers import LATER, Writer, job, pending, run_gate as run
from test_review_request_budget import add_coverage, context, inconsistent, record, reviewer, saved_audit
from test_review_scope_budget import untrusted_update, update_case


def unusable():
    return inconsistent({})


def correction(audit):
    return audit["request_budget"]["validation_reask"]


def test_correction_is_fresh_initial_review_then_independent_verification(context):
    cfg, store = context
    row = pending(store)
    snapshots = []
    checker = reviewer(cfg, unusable(), verdict(), verdict(),
                       before=lambda: snapshots.append(json.loads(job(store)["record_json"])))
    result = run(cfg, store, row, Writer(), checker)
    assert result["status"] == "published" and checker.calls == 3
    requests = checker.client.requests
    payloads = [json.loads(request["messages"][1]["content"]) for request in requests]
    assert payloads[1] == {**payloads[0], "validation_error": review.INCONSISTENT_VERDICT}
    assert requests[1]["response_format"] == requests[0]["response_format"]
    assert requests[1]["messages"][0]["content"] == requests[0]["messages"][0]["content"] + review.VALIDATION_REASK_PROMPT
    assert "validation_error" not in payloads[2]
    assert requests[2]["messages"][0]["content"] == review.VERIFY_PROMPT
    assert "UNTRUSTED_PREVIOUS_CRITERIA_SENTINEL" not in json.dumps(requests)
    assert snapshots[1]["reviews"] == []
    assert correction(snapshots[1]) == {"trigger": 1, "attempts": [2], "response": None, "transport_failed": False}
    audit = saved_audit(store)
    assert correction(audit) == {"trigger": 1, "attempts": [2], "response": 2, "transport_failed": False}
    assert [(entry["request"], entry["stage"]) for entry in audit["reviews"]] == [(2, "review"), (3, "verification")]
    assert audit["reviews"][0]["reask_response"] is True
    assert audit["untrusted_proposals"][0]["reask_trigger"] is True
    assert not audit["untrusted_proposals"][0]["accepted"]
    status = review_gate.recovery_status(audit)
    assert status["raw_inconsistency_count"] == 1 and not status["unresolved_inconsistency"]


def test_second_invalid_reply_is_terminal_across_resume(context):
    cfg, store = context
    row = pending(store)
    checker = reviewer(cfg, unusable(), unusable())
    with pytest.raises(review.InconsistentReview):
        run(cfg, store, row, Writer(), checker)
    assert checker.calls == 2 and store.stories() == []
    audit = record(store)
    assert correction(audit)["response"] == 2
    assert [event["reask_response"] for event in audit["untrusted_proposals"]] == [False, True]
    again = reviewer(cfg, verdict(), verdict())
    with pytest.raises(review.InconsistentReview):
        run(cfg, store, row, Writer(), again)
    assert again.calls == 0 and record(store) == audit


def test_valid_refusal_is_not_reasked(context):
    cfg, store = context
    row = pending(store)
    checker = reviewer(cfg, verdict("hold", criterion="source_support"))
    assert run(cfg, store, row, Writer(), checker)["status"] == "held"
    assert checker.calls == 1 and correction(record(store)) is None


def test_corrective_refusal_does_not_use_invalid_news_as_an_anchor(context):
    cfg, store = context
    row = pending(store)
    checker = reviewer(cfg, unusable(), verdict("skip", criterion="news_value"))
    result = run(cfg, store, row, Writer(), checker)
    assert result["status"] == "ignored" and checker.calls == 2 and store.stories() == []
    audit = saved_audit(store)
    assert len(audit["reviews"]) == 1 and audit["reviews"][0]["result"]["verdict"] == "skip"
    assert not review_gate.recovery_status(audit)["unresolved_inconsistency"]


def test_corrective_verification_keeps_genuine_prior_disagreement(context):
    cfg, store = context
    row = pending(store)
    checker = reviewer(cfg, verdict(), unusable(), verdict("skip", criterion="news_value"))
    assert run(cfg, store, row, Writer(), checker)["status"] == "held"
    audit = saved_audit(store)
    assert audit["hold_code"] == "disagreed_news" and len(audit["reviews"]) == 2
    assert audit["reviews"][-1]["stage"] == "verification" and audit["reviews"][-1]["reask_response"]
    assert checker.calls == 3 and store.stories() == []


def test_transport_fallbacks_share_one_logical_correction(context):
    cfg, store = context
    cfg["llm"]["fallback_base_urls"] = ["https://fallback.example/v1"]
    row = pending(store)
    checker = reviewer(cfg, unusable(), FetchError("temporary", status=500), verdict(), verdict())
    assert run(cfg, store, row, Writer(), checker)["status"] == "published"
    audit = saved_audit(store)
    assert checker.calls == audit["request_budget"]["reserved"] == 4
    assert correction(audit) == {"trigger": 1, "attempts": [2, 3], "response": 3, "transport_failed": False}
    assert checker.client.requests[1] == checker.client.requests[2]
    assert len([entry for entry in audit["reviews"] if entry.get("reask_response")]) == 1


@pytest.mark.parametrize("failure", [FetchError("temporary", status=500), DeadlineReached()])
def test_confirmed_transport_failure_resumes_same_correction(context, failure):
    cfg, store = context
    row = pending(store)
    checker = reviewer(cfg, unusable(), failure)
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), checker)
    before = record(store)
    unsent = isinstance(failure, DeadlineReached)
    assert correction(before) == {"trigger": 1, "attempts": [] if unsent else [2],
                                  "response": None, "transport_failed": True}
    assert before["request_budget"]["reserved"] == (1 if unsent else 2)
    resumed = reviewer(cfg, verdict(), verdict())
    assert run(cfg, store, row, Writer(), resumed)["status"] == "published"
    audit = saved_audit(store)
    assert audit["request_budget"]["reserved"] == (3 if unsent else 4)
    assert correction(audit)["attempts"] == ([2] if unsent else [2, 3])
    assert json.loads(resumed.client.requests[0]["messages"][1]["content"])["validation_error"] == review.INCONSISTENT_VERDICT


def test_unknown_inflight_correction_is_not_reissued(context, monkeypatch):
    cfg, store = context
    row = pending(store)
    original = review_gate._save
    def interrupted(*args, **kwargs):
        original(*args, **kwargs)
        state = args[7]["request_budget"]["validation_reask"]
        if state and state["attempts"] and state["response"] is None:
            raise RuntimeError("reserved correction")
    checker = reviewer(cfg, unusable(), verdict())
    with monkeypatch.context() as scoped:
        scoped.setattr(review_gate, "_save", interrupted)
        with pytest.raises(RuntimeError, match="reserved correction"):
            run(cfg, store, row, Writer(), checker)
    assert checker.calls == 1 and record(store)["request_budget"]["reserved"] == 2
    resumed = reviewer(cfg, verdict(), verdict())
    with pytest.raises(review.ReviewError, match="Interrupted validation correction"):
        run(cfg, store, row, Writer(), resumed)
    assert resumed.calls == 0 and store.stories() == []


def test_received_response_crash_never_reissues_correction(context, monkeypatch):
    cfg, store = context
    row = pending(store)
    original = review_gate._save
    def interrupted(*args, **kwargs):
        original(*args, **kwargs)
        state = args[7]["request_budget"]["validation_reask"]
        if state and state["response"] is not None and not args[7]["reviews"]:
            raise RuntimeError("received correction")
    checker = reviewer(cfg, unusable(), verdict())
    with monkeypatch.context() as scoped:
        scoped.setattr(review_gate, "_save", interrupted)
        with pytest.raises(RuntimeError, match="received correction"):
            run(cfg, store, row, Writer(), checker)
    assert checker.calls == 2 and correction(record(store))["response"] == 2
    resumed = reviewer(cfg, verdict(), verdict())
    with pytest.raises(review.ReviewError, match="did not yield a usable"):
        run(cfg, store, row, Writer(), resumed)
    assert resumed.calls == 0 and store.stories() == []


def test_malformed_received_answer_consumes_correction(context):
    cfg, store = context
    row = pending(store)
    checker = reviewer(cfg, unusable(), "not an object")
    with pytest.raises(AnalysisError, match="not an object"):
        run(cfg, store, row, Writer(), checker)
    assert correction(record(store))["response"] == 2
    resumed = reviewer(cfg, verdict(), verdict())
    with pytest.raises(review.ReviewError, match="did not yield a usable"):
        run(cfg, store, row, Writer(), resumed)
    assert resumed.calls == 0 and store.stories() == []


def test_correction_prompt_is_part_of_policy_identity(context, monkeypatch):
    cfg, _ = context
    before = review.policy_hash(cfg)
    monkeypatch.setattr(review, "VALIDATION_REASK_PROMPT", review.VALIDATION_REASK_PROMPT + "\nA different instruction.")
    assert review.policy_hash(cfg) != before


@pytest.mark.parametrize("envelope", [False, True])
def test_successful_transport_is_recorded_before_either_json_parser(context, envelope):
    cfg, store = context
    row = pending(store)
    checker = reviewer(cfg, unusable(), verdict())
    original_request = checker.client.request
    def malformed(*args, **kwargs):
        response = original_request(*args, **kwargs)
        if len(checker.client.requests) != 2:
            return response
        if envelope:
            def bad_json():
                raise FetchError("invalid response JSON")
            return SimpleNamespace(json=bad_json)
        return SimpleNamespace(json=lambda: {"choices": [{"finish_reason": "stop", "message": {"content": '{"{"criteria":{}}'}}]})
    checker.client.request = malformed
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), checker)
    assert checker.calls == 2 and correction(record(store))["response"] == 2
    resumed = reviewer(cfg, verdict(), verdict())
    with pytest.raises(review.ReviewError, match="did not yield a usable"):
        run(cfg, store, row, Writer(), resumed)
    assert resumed.calls == 0 and not store.stories()


def test_later_invalid_verification_cannot_allocate_a_second_correction(context):
    cfg, store = context
    row = pending(store)
    checker = reviewer(cfg, unusable(), verdict(), unusable())
    with pytest.raises(review.InconsistentReview):
        run(cfg, store, row, Writer(), checker)
    assert checker.calls == 3 and correction(record(store))["attempts"] == [2]
    assert [event["reask_trigger"] for event in record(store)["untrusted_proposals"]] == [True, False]
    resumed = reviewer(cfg, verdict())
    with pytest.raises(review.InconsistentReview):
        run(cfg, store, row, Writer(), resumed)
    assert resumed.calls == 0 and not store.stories()


def test_valid_repair_then_invalid_verification_reasks_the_exact_repaired_candidate(context):
    cfg, store = context
    row = pending(store)
    changed = "A changed source-bound summary."
    checker = reviewer(cfg, verdict("revise", criterion="source_support", repair={"summary": changed}),
                       inconsistent({"summary": "An unvalidated replacement summary."}), verdict())
    assert run(cfg, store, row, Writer(), checker)["status"] == "published"
    payloads = [json.loads(request["messages"][1]["content"]) for request in checker.client.requests]
    assert payloads[0]["candidate"]["summary"] != changed
    assert payloads[1]["candidate"]["summary"] == payloads[2]["candidate"]["summary"] == changed
    assert payloads[2] == {**payloads[1], "validation_error": review.INCONSISTENT_VERDICT}
    assert checker.client.requests[1]["messages"][0]["content"] == review.VERIFY_PROMPT
    assert checker.client.requests[2]["messages"][0]["content"] == review.VERIFY_PROMPT + review.VALIDATION_REASK_PROMPT
    audit = saved_audit(store)
    assert [(r["request"], r["stage"]) for r in audit["reviews"]] == [(1, "review"), (3, "verification")]
    assert audit["candidate"] == payloads[2]["candidate"]
    assert audit["untrusted_proposals"][0]["disposition"] == "unusable"
    assert audit["untrusted_proposals"][0]["repair"] is None
    assert not audit["untrusted_proposals"][0]["accepted"]
    assert correction(audit)["trigger"] == 2 and checker.calls == 3


@pytest.mark.parametrize("double", ["scripted", "approving"])
def test_reviewer_doubles_validate_feedback_before_charging_and_record_it(double):
    from helpers import ApprovingReviewer, ScriptedReviewer
    checker = ScriptedReviewer(verdict()) if double == "scripted" else ApprovingReviewer()
    packet = {"sources": [{"id": "S1", "passages": []}]}
    events = []
    class Observer:
        def __call__(self, delta):
            events.append(("reserved", delta))
        def response_received(self):
            events.append(("response", None))
    observer = Observer()
    with pytest.raises(review.ReviewError, match="Unknown review validation feedback"):
        checker.review({}, packet, validation_error="An unknown error", on_request=observer)
    assert events == [] and checker.validation_errors == []
    result = checker.review({}, packet, validation_error=review.INCONSISTENT_VERDICT, on_request=observer)
    assert result["verdict"] == "approve"
    assert events == [("reserved", 1), ("response", None)]
    assert checker.validation_errors == [review.INCONSISTENT_VERDICT]


def test_update_correction_keeps_scope_readonly_history_and_ordered_inputs(context):
    cfg, _ = context
    case, prepared = update_case()
    original = review.personal_attribution.normalize(case["candidate"], update=True)
    prepared = {**prepared, "candidate": original}
    audit = {"candidate": original, "reviews": [], "policy_hash": review.policy_hash(cfg), **review_gate.initial_review_state()}
    requests = review_gate.ReviewRequests(audit)
    checker = reviewer(cfg, untrusted_update({}), verdict(update=True), verdict(update=True))
    stage, candidate = review_gate.advance_review(checker, "review", original, prepared, audit, requests)
    assert stage == "verify" and candidate == original and checker.calls == 2
    action, candidate = review_gate.advance_review(checker, stage, candidate, prepared, audit, requests)
    assert action == "approve" and candidate == original and checker.calls == 3
    bodies = [json.loads(request["messages"][1]["content"]) for request in checker.client.requests]
    assert bodies[1] == {**bodies[0], "validation_error": review.INCONSISTENT_VERDICT}
    assert bodies[1]["review_scope"] == "latest_update"
    assert checker.client.requests[0]["response_format"] == checker.client.requests[1]["response_format"]
    assert checker.client.requests[1]["messages"][0]["content"] == review.UPDATE_SYSTEM_PROMPT + review.VALIDATION_REASK_PROMPT


def test_context_change_abandons_pending_feedback_without_replenishing_slot(context):
    cfg, store = context
    row = pending(store)
    first = reviewer(cfg, unusable(), FetchError("temporary", status=500))
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), first)
    previous = copy.deepcopy(correction(record(store)))
    add_coverage(store)
    changed = reviewer(cfg, unusable())
    with pytest.raises(review.InconsistentReview):
        run(cfg, store, row, Writer(), changed)
    assert changed.calls == 1 and correction(record(store)) == previous
    body = json.loads(changed.client.requests[0]["messages"][1]["content"])
    assert "validation_error" not in body
    assert record(store)["untrusted_proposals"][0]["disposition"] == "discarded_context"
    assert record(store)["request_budget"]["reserved"] == 3 and len(store.stories()) == 1


def test_route_carries_consumed_slot_and_operator_reset_starts_a_new_ledger(context):
    cfg, store = context
    target = _publish(store, item(url="https://example.org/incident", title="Directory authority overload",
                                  content="Operators report a directory authority overload."))
    incoming = item(url="https://example.org/followup", authority="official", title="An overload mitigation",
                    content="A new consensus method mitigates the authority overload.")
    row = pending(store, incoming)
    draft = analysis(title=incoming["title"], summary=incoming["content"], why_it_matters="", evidence=[incoming["content"]])
    routed = reviewer(cfg, unusable(), verdict(same_story=target["id"]))
    assert run(cfg, store, row, Writer(draft), routed)["status"] == "routed"
    assert routed.calls == 2 and correction(record(store))["response"] == 2
    queued = next(value for value in store.pending(10, LATER) if value["id"] == row["id"])
    update = update_analysis(update=incoming["content"], evidence=[incoming["content"]])
    checker = reviewer(cfg, untrusted_update({}))
    with pytest.raises(review.InconsistentReview):
        run(cfg, store, queued, Writer(update), checker)
    assert checker.calls == 1 and record(store)["request_budget"]["reserved"] == 3
    assert correction(record(store))["response"] == 2
    assert "validation_error" not in json.loads(checker.client.requests[0]["messages"][1]["content"])
    assert record(store)["untrusted_proposals"][0]["disposition"] == "discarded_context"
    with store.db:
        review_gate.reset_review_work(store, row["id"])
        store.db.execute("UPDATE items SET status='pending',attempts=0,rejections=0 WHERE id=?", (row["id"],))
    reset = next(value for value in store.pending(10, LATER) if value["id"] == row["id"])
    assert correction(record(store)) is None
    fresh = reviewer(cfg, untrusted_update({}), verdict(update=True), verdict(update=True))
    assert run(cfg, store, reset, Writer(update), fresh)["status"] == "published"
    assert fresh.calls == 3 and correction(saved_audit(store))["trigger"] == 1


def test_correction_transport_attempts_stop_at_seven(context):
    cfg, store = context
    cfg["llm"]["fallback_base_urls"] = [f"https://fallback{n}.example/v1" for n in range(7)]
    row = pending(store)
    checker = reviewer(cfg, unusable(), *(FetchError("temporary", status=500) for _ in range(6)))
    with pytest.raises(review.ReviewLimitReached):
        run(cfg, store, row, Writer(), checker)
    assert checker.calls == len(checker.client.requests) == 7
    assert record(store)["request_budget"]["reserved"] == 7
    assert correction(record(store))["attempts"] == [2, 3, 4, 5, 6, 7]
    assert not store.stories()


def test_last_slot_valid_correction_cannot_publish_without_verification(context):
    cfg, store = context
    cfg["llm"]["fallback_base_urls"] = [f"https://fallback{n}.example/v1" for n in range(5)]
    row = pending(store)
    checker = reviewer(cfg, *(FetchError("temporary", status=500) for _ in range(5)), unusable(), verdict())
    with pytest.raises(review.ReviewLimitReached):
        run(cfg, store, row, Writer(), checker)
    audit = record(store)
    assert checker.calls == 7 and correction(audit)["response"] == 7
    assert len(audit["reviews"]) == 1 and audit["reviews"][0]["stage"] == "review"
    assert not store.stories()


@pytest.mark.parametrize("damage", ["missing-slot", "erase-slot", "wrong-trigger", "erase-trigger-marker", "erase-trigger",
                                    "erase-attempts", "response-bool", "wrong-response", "response-retry", "context", "candidate",
                                    "second-trigger", "semantic-transport-attempt"])
def test_correction_ledger_damage_fails_before_models_or_cached_approval(context, damage):
    cfg, store = context
    row = pending(store)
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), reviewer(cfg, unusable(), FetchError("temporary", status=500)))
    audit = record(store)
    prepared = json.loads(job(store)["envelope_json"])
    approve(store, prepared, policy=review.policy_hash(cfg))
    idle = reviewer(cfg)
    assert run(cfg, store, row, Writer(), idle, allow_network=False)["status"] == "deferred"
    assert idle.calls == 0 and not store.stories()
    state = correction(audit)
    if damage == "missing-slot": audit["request_budget"].pop("validation_reask")
    elif damage == "erase-slot": audit["request_budget"]["validation_reask"] = None
    elif damage == "wrong-trigger": state["trigger"] = 2
    elif damage == "erase-trigger-marker": audit["untrusted_proposals"][0]["reask_trigger"] = False
    elif damage == "erase-trigger": audit["untrusted_proposals"] = []; audit["request_budget"]["inconsistent_requests"] = []
    elif damage == "erase-attempts": state["attempts"] = []
    elif damage == "response-bool": state["response"] = True
    elif damage == "wrong-response": state["response"] = 1
    elif damage == "response-retry": state["response"] = 2
    elif damage == "context": audit["untrusted_proposals"][0]["context"]["source_hash"] = "0" * 64
    elif damage == "candidate": audit["untrusted_proposals"][0]["candidate_before_hash"] = "0" * 64
    else:
        extra = copy.deepcopy(audit["untrusted_proposals"][0]); extra["request"] = 2
        extra["reask_trigger"] = damage == "second-trigger"
        audit["untrusted_proposals"].append(extra); audit["request_budget"]["inconsistent_requests"].append(2)
    with store.db:store.db.execute("UPDATE review_jobs SET record_json=? WHERE item_id=?", (json.dumps(audit), row["id"]))
    checker, writer = reviewer(cfg, verdict(), verdict()), Writer()
    with pytest.raises(AnalysisError) as error:
        run(cfg, store, row, writer, checker)
    assert error.value.code == "app.damaged_job" and checker.calls == 0 and writer.calls == [] and not store.stories()


def test_new_record_cannot_reset_a_damaged_ledger_on_policy_change(context):
    cfg, store = context
    row = pending(store)
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), reviewer(cfg, unusable(), FetchError("temporary", status=500)))
    audit = record(store); old_policy = "e" * 64
    assert old_policy != review.policy_hash(cfg)
    audit["policy_hash"] = old_policy
    audit["request_budget"].pop("validation_reask")
    for event in audit["untrusted_proposals"]:
        event["context"]["policy_hash"] = old_policy
        event.pop("reask_trigger"); event.pop("reask_response")
    with store.db:store.db.execute("UPDATE review_jobs SET policy_hash=?,record_json=? WHERE item_id=?",
                                  (old_policy, json.dumps(audit), row["id"]))
    before = job(store)
    checker, writer = reviewer(cfg), Writer()
    with pytest.raises(AnalysisError) as error:
        run(cfg, store, row, writer, checker)
    assert error.value.code == "app.damaged_job"
    assert writer.calls == [] and checker.calls == 0 and job(store) == before


@pytest.mark.parametrize("damage", [False, True])
def test_nested_cached_correction_proof_is_validated_without_another_request(context, monkeypatch, damage):
    cfg, store = context
    row = pending(store)
    with monkeypatch.context() as scoped:
        scoped.setattr(store, "commit_candidate", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("before commit")))
        with pytest.raises(RuntimeError, match="before commit"):
            run(cfg, store, row, Writer(), reviewer(cfg, unusable(), verdict(), verdict()))
        with store.db:review_gate.reset_review_work(store, row["id"])
        idle = reviewer(cfg)
        with pytest.raises(RuntimeError, match="before commit"):
            run(cfg, store, row, Writer(), idle, allow_network=False)
        assert idle.calls == 0
    audit = record(store)
    assert correction(audit) is None and correction(audit["approval"])["response"] == 2
    if damage:
        audit["approval"]["request_budget"]["validation_reask"] = None
        with store.db:store.db.execute("UPDATE review_jobs SET record_json=? WHERE item_id=?", (json.dumps(audit), row["id"]))
    idle = reviewer(cfg)
    if damage:
        with pytest.raises(AnalysisError) as error:
            run(cfg, store, row, Writer(), idle, allow_network=False)
        assert error.value.code == "app.damaged_job" and not store.stories()
    else:
        result = run(cfg, store, row, Writer(), idle, allow_network=False)
        assert result["status"] == "published" and result["cache_hit"]
    assert idle.calls == 0


def test_correction_keeps_release_label_repair_issue_and_requires_verification(context):
    cfg, store = context
    incoming = item(kind="gitlab_mr", upstream_state="merged", title="Add an optional capability",
                    content="The optional capability was merged.")
    row = pending(store, incoming)
    draft = analysis(title="The release is available", summary=incoming["content"], why_it_matters="",
                     category="release", state="merged", confidence="confirmed", tags=["release", "feature"])
    fixed = {"title": "An optional capability was merged", "category": "feature", "tags": ["feature"]}
    checker = reviewer(cfg, verdict(), unusable(), verdict("revise", repair=fixed, criterion="status"), verdict())
    assert run(cfg, store, row, Writer(draft), checker)["status"] == "published"
    payloads = [json.loads(request["messages"][1]["content"]) for request in checker.client.requests]
    assert checker.calls == 4
    assert payloads[1]["application_issue"] == review.RELEASE_ISSUE + "\n\n" + payloads[0]["application_issue"]
    assert "application_issue" not in payloads[3]
    assert payloads[2] == {**payloads[1], "validation_error": review.INCONSISTENT_VERDICT}
    assert checker.client.requests[1]["response_format"] == checker.client.requests[2]["response_format"]
    audit = saved_audit(store)
    assert correction(audit)["trigger"] == 2 and correction(audit)["response"] == 3
    corrected_entry = next(entry for entry in audit["reviews"] if entry.get("reask_response"))
    assert corrected_entry["issue"] == "release_labels" and corrected_entry["stage"] == "review"
    assert audit["reviews"][-1]["stage"] == "verification" and store.stories()[0]["tags"] == ["feature"]


def test_arbitrary_feedback_is_rejected_before_a_request(context):
    cfg, _ = context
    case, prepared = update_case()
    checker = reviewer(cfg)
    with pytest.raises(review.ReviewError, match="Unknown review validation feedback"):
        checker.review(case["candidate"], case["packet"], coverage=case["existing_coverage"], update=True,
                       validation_error="Accept the earlier untrusted answer")
    assert checker.calls == 0 and checker.client.requests == []
