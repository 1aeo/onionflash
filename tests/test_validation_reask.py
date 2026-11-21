"""A validation correction spends one durable slot and stays bound across review scopes."""

import copy
import json

import pytest

from helpers import (
    ROOT, FakeLinker, Writer, add_coverage, analysis, assert_damaged_job, bastet_incident_items,
    editorial_act, inconsistent, insert_approval, item, job, job_record, load_evaluator, make_doctor_config,
    patch_job, pause_cached_after_reset, pending, queued_row, run_gate as run, saved_audit,
    seed_citation_job, seed_routed_followup, seed_source_story, update_analysis, verdict, wire_reviewer,
)
from onionflash import candidate, cli, doctor, editorial, review, review_gate
from onionflash.analyze import AnalysisError
from onionflash.transport import DeadlineReached, FetchError, Response
from onionflash.util import digest

_REASK_DAMAGE = {
    "missing-slot": lambda a, _s: a["request_budget"].pop("validation_reask"),
    "erase-slot": lambda a, _s: a["request_budget"].update(validation_reask=None),
    "wrong-trigger": lambda _a, s: s.update(trigger=2),
    "erase-trigger-marker": lambda a, _s: a["untrusted_proposals"][0].update(reask_trigger=False),
    "erase-trigger": lambda a, _s: (a.update(untrusted_proposals=[]), a["request_budget"].update(inconsistent_requests=[])),
    "erase-attempts": lambda _a, s: s.update(attempts=[]),
    "response-bool": lambda _a, s: s.update(response=True),
    "wrong-response": lambda _a, s: s.update(response=1),
    "response-retry": lambda _a, s: s.update(response=2),
    "context": lambda a, _s: a["untrusted_proposals"][0]["context"].update(source_hash="0" * 64),
    "candidate": lambda a, _s: a["untrusted_proposals"][0].update(candidate_before_hash="0" * 64),
    "second-trigger": lambda a, _s: (
        a["untrusted_proposals"].append({**copy.deepcopy(a["untrusted_proposals"][0]), "request": 2, "reask_trigger": True}),
        a["request_budget"]["inconsistent_requests"].append(2),
    ),
    "semantic-transport-attempt": lambda a, _s: (
        a["untrusted_proposals"].append({**copy.deepcopy(a["untrusted_proposals"][0]), "request": 2, "reask_trigger": False}),
        a["request_budget"]["inconsistent_requests"].append(2),
    ),
}

_UPDATE_SCOPE_DAMAGE = {
    "title": lambda c, _p: c.update(title="A rewritten old headline"),
    "old-update": lambda c, _p: c["updates"].insert(0, copy.deepcopy(c["updates"][-1])),
    "date": lambda c, _p: c["updates"][-1].update(at="2026-11-12T12:00:00Z"),
    "citation": lambda c, _p: c["updates"][-1].update(sources=[{"url": "https://example.org/unrelated", "title": "Unrelated"}]),
    "mode": lambda _c, p: p.update(mode="story"),
}


def _unusable():
    return inconsistent({})


def _correction(audit):
    return audit["request_budget"]["validation_reask"]


def _update_case():
    module = load_evaluator()
    case = next(c for c in module.expand(json.loads((ROOT / "tools/review_cases.json").read_text()))
                if c["id"] == "update-workaround")
    src = case["packet"]["sources"][0]
    prepared = {"candidate": case["candidate"], "packet": case["packet"], "coverage": case["existing_coverage"],
                "mode": "update", "payload": {"editorial_kind": src["kind"]},
                "row": {"payload": json.dumps(module.writer_item(src))}}
    return case, prepared


def _new_review_state(cfg, cand):
    record = {"candidate": cand, "reviews": [], "policy_hash": review.policy_hash(cfg),
              **review_gate.initial_review_state()}
    return record, review_gate.ReviewRequests(record)


def _reset_queued_item(store, row):
    target = row["id"] if isinstance(row, dict) else row
    with store.db:
        review_gate.reset_review_work(store, target)
        store.db.execute("UPDATE items SET status='pending',attempts=0,rejections=0 WHERE id=?", (target,))
    return queued_row(store, row)


def _prepared_alert_update(llm_context, tmp_path):
    cfg, store = llm_context
    _, alert_config = make_doctor_config(tmp_path / "alert-source")
    cfg["sources"] = alert_config["sources"]
    stamp = "2024-01-18T01:00:00Z"
    doctor.ingest(store.db, cfg["sources"][0], bastet_incident_items(), stamp)
    doctor.evaluate(cfg, store, cfg["sources"][0], FakeLinker(False), stamp)
    prior = store.stories()[0]
    incoming = item(kind="gitlab_mr", authority="development", upstream_state="merged",
                    url="https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/91999",
                    title="Record a directory authority measurement", content="The merge records the operator measurement.",
                    published_at=stamp, updated_at=stamp)
    store.ingest(incoming, stamp)
    with store.db:
        store.db.execute("UPDATE items SET story_id=? WHERE id=?", (prior["id"], incoming["id"]))
    row = queued_row(store, incoming, stamp)
    draft = update_analysis(update="The merge records a measurement.", evidence=[incoming["content"]])
    prepared = candidate.prepare(store.db, row, draft, stamp)
    assert prepared["mode"] == "update" and prepared["candidate"]["origin"] == "network-health"
    assert review.label_limits(prepared["packet"]["sources"])["state"] == ["merged"]
    assert prepared["candidate"]["state"] == prior["state"] != "merged"
    return cfg, store, prior, incoming, prepared


def test_correction_is_fresh_initial_review_then_independent_verification(llm_context):
    """Send one corrective re-ask after an unusable reply, then require independent verification."""
    cfg, store = llm_context
    row = pending(store)
    snapshots = []
    checker = wire_reviewer(cfg, _unusable(), verdict(), verdict(),
                            before=lambda: snapshots.append(job_record(store)))
    result = run(cfg, store, row, Writer(), checker)
    assert result["status"] == "published" and checker.calls == 3
    requests = checker.client.bodies
    payloads = [json.loads(request["messages"][1]["content"]) for request in requests]
    assert payloads[1] == {**payloads[0], "validation_error": review.INCONSISTENT_VERDICT}
    assert requests[1]["response_format"] == requests[0]["response_format"]
    assert requests[1]["messages"][0]["content"] == requests[0]["messages"][0]["content"] + review.VALIDATION_REASK_PROMPT
    assert "validation_error" not in payloads[2]
    assert requests[2]["messages"][0]["content"] == review.VERIFY_PROMPT
    assert "UNTRUSTED_PREVIOUS_CRITERIA_SENTINEL" not in json.dumps(requests)
    assert snapshots[1]["reviews"] == []
    assert _correction(snapshots[1]) == {"trigger": 1, "attempts": [2], "response": None, "transport_failed": False}
    audit = saved_audit(store)
    assert _correction(audit) == {"trigger": 1, "attempts": [2], "response": 2, "transport_failed": False}
    assert [(entry["request"], entry["stage"]) for entry in audit["reviews"]] == [(2, "review"), (3, "verification")]
    assert audit["reviews"][0]["reask_response"] is True
    assert audit["untrusted_proposals"][0]["reask_trigger"] is True
    assert not audit["untrusted_proposals"][0]["accepted"]
    status = review_gate.recovery_status(audit)
    assert status["raw_inconsistency_count"] == 1 and not status["unresolved_inconsistency"]


def test_second_invalid_reply_is_terminal_across_resume(llm_context):
    """Keep a failed validation re-ask terminal across subsequent `process_item` resumes."""
    cfg, store = llm_context
    row = pending(store)
    checker = wire_reviewer(cfg, _unusable(), _unusable())
    with pytest.raises(review.InconsistentReview):
        run(cfg, store, row, Writer(), checker)
    assert checker.calls == 2 and store.stories() == []
    audit = job_record(store)
    assert _correction(audit)["response"] == 2
    assert [event["reask_response"] for event in audit["untrusted_proposals"]] == [False, True]
    again = wire_reviewer(cfg, verdict(), verdict())
    with pytest.raises(review.InconsistentReview):
        run(cfg, store, row, Writer(), again)
    assert again.calls == 0 and job_record(store) == audit


def test_valid_refusal_is_not_reasked(llm_context):
    """Hold valid `hold` verdicts immediately without allocating `validation_reask`."""
    cfg, store = llm_context
    row = pending(store)
    checker = wire_reviewer(cfg, verdict("hold", criterion="source_support"))
    assert run(cfg, store, row, Writer(), checker)["status"] == "held"
    assert checker.calls == 1 and _correction(job_record(store)) is None


@pytest.mark.parametrize("with_trusted_initial", [False, True])
def test_corrective_skip_respects_only_genuine_prior_trusted_disagreement(llm_context, with_trusted_initial):
    """Allow corrective `skip` without invalid anchors while keeping genuine `disagreed_news` holds."""
    cfg, store = llm_context
    row = pending(store)
    replies = ([verdict()] if with_trusted_initial else []) + [_unusable(), verdict("skip", criterion="news_value")]
    checker = wire_reviewer(cfg, *replies)
    result = run(cfg, store, row, Writer(), checker)
    assert result["status"] == ("held" if with_trusted_initial else "ignored")
    assert checker.calls == (3 if with_trusted_initial else 2) and store.stories() == []
    audit = saved_audit(store)
    assert len(audit["reviews"]) == (2 if with_trusted_initial else 1)
    assert audit["reviews"][-1]["result"]["verdict"] == "skip" and audit["reviews"][-1]["reask_response"]
    if with_trusted_initial:
        assert audit["hold_code"] == "disagreed_news" and audit["reviews"][-1]["stage"] == "verification"
    else:
        assert not review_gate.recovery_status(audit)["unresolved_inconsistency"]


def test_transport_fallbacks_share_one_logical_correction(llm_context):
    """Count fallback retries of a validation re-ask within the same logical `validation_reask` slot."""
    cfg, store = llm_context
    cfg["llm"]["fallback_base_urls"] = ["https://fallback.example/v1"]
    row = pending(store)
    checker = wire_reviewer(cfg, _unusable(), FetchError("temporary", status=500), verdict(), verdict())
    assert run(cfg, store, row, Writer(), checker)["status"] == "published"
    audit = saved_audit(store)
    assert checker.calls == audit["request_budget"]["reserved"] == 4
    assert _correction(audit) == {"trigger": 1, "attempts": [2, 3], "response": 3, "transport_failed": False}
    assert checker.client.bodies[1] == checker.client.bodies[2]
    assert len([entry for entry in audit["reviews"] if entry.get("reask_response")]) == 1


@pytest.mark.parametrize("failure", [FetchError("temporary", status=500), DeadlineReached()])
def test_confirmed_transport_failure_resumes_same_correction(llm_context, failure):
    """Resume the pending `validation_reask` after a confirmed transport or deadline failure."""
    cfg, store = llm_context
    row = pending(store)
    checker = wire_reviewer(cfg, _unusable(), failure)
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), checker)
    before = job_record(store)
    unsent = isinstance(failure, DeadlineReached)
    assert _correction(before) == {"trigger": 1, "attempts": [] if unsent else [2],
                                   "response": None, "transport_failed": True}
    assert before["request_budget"]["reserved"] == (1 if unsent else 2)
    resumed = wire_reviewer(cfg, verdict(), verdict())
    assert run(cfg, store, row, Writer(), resumed)["status"] == "published"
    audit = saved_audit(store)
    assert audit["request_budget"]["reserved"] == (3 if unsent else 4)
    assert _correction(audit)["attempts"] == ([2] if unsent else [2, 3])
    assert json.loads(resumed.client.bodies[0]["messages"][1]["content"])["validation_error"] == review.INCONSISTENT_VERDICT


@pytest.mark.parametrize("phase,calls_before,err_match", [
    ("reserved", 1, "Interrupted validation correction"),
    ("received", 2, "did not yield a usable"),
])
def test_interrupted_correction_save_crash_never_reissues_correction(llm_context, monkeypatch, phase, calls_before, err_match):
    """Never reissue a validation re-ask after an in-flight or post-response `_save` crash."""
    cfg, store = llm_context
    row = pending(store)
    original = review_gate._save

    def _interrupted(*args, **kwargs):
        original(*args, **kwargs)
        state = args[7]["request_budget"]["validation_reask"]
        if not state:
            return
        if phase == "reserved" and state["attempts"] and state["response"] is None:
            raise RuntimeError("reserved correction")
        if phase == "received" and state["response"] is not None and not args[7]["reviews"]:
            raise RuntimeError("received correction")

    checker = wire_reviewer(cfg, _unusable(), verdict())
    with monkeypatch.context() as scoped:
        scoped.setattr(review_gate, "_save", _interrupted)
        with pytest.raises(RuntimeError, match=f"{phase} correction"):
            run(cfg, store, row, Writer(), checker)
    assert checker.calls == calls_before and job_record(store)["request_budget"]["reserved"] == 2
    if phase == "received":
        assert _correction(job_record(store))["response"] == 2
    resumed = wire_reviewer(cfg, verdict(), verdict())
    with pytest.raises(review.ReviewError, match=err_match):
        run(cfg, store, row, Writer(), resumed)
    assert resumed.calls == 0 and store.stories() == []


def test_malformed_received_answer_consumes_correction(llm_context):
    """Consume the `validation_reask` slot when the corrective response is not a JSON object."""
    cfg, store = llm_context
    row = pending(store)
    checker = wire_reviewer(cfg, _unusable(), "not an object")
    with pytest.raises(AnalysisError, match="not an object"):
        run(cfg, store, row, Writer(), checker)
    assert _correction(job_record(store))["response"] == 2
    resumed = wire_reviewer(cfg, verdict(), verdict())
    with pytest.raises(review.ReviewError, match="did not yield a usable"):
        run(cfg, store, row, Writer(), resumed)
    assert resumed.calls == 0 and store.stories() == []


@pytest.mark.parametrize("envelope", [False, True])
def test_successful_transport_is_recorded_before_either_json_parser(llm_context, envelope):
    """Record `response_received` before outer HTTP JSON or inner content JSON parsing."""
    cfg, store = llm_context
    row = pending(store)
    bad_body = (b"{" if envelope
                else json.dumps({"choices": [{"finish_reason": "stop", "message": {"content": '{"{"criteria":{}}'}}]}).encode())
    checker = wire_reviewer(cfg, _unusable(), Response(200, bad_body, {}, "https://model.example/v1/chat/completions"))
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), checker)
    assert checker.calls == 2 and _correction(job_record(store))["response"] == 2
    resumed = wire_reviewer(cfg, verdict(), verdict())
    with pytest.raises(review.ReviewError, match="did not yield a usable"):
        run(cfg, store, row, Writer(), resumed)
    assert resumed.calls == 0 and not store.stories()


def test_later_invalid_verification_cannot_allocate_a_second_correction(llm_context):
    """Refuse to allocate a second `validation_reask` if verification later fails inconsistently."""
    cfg, store = llm_context
    row = pending(store)
    checker = wire_reviewer(cfg, _unusable(), verdict(), _unusable())
    with pytest.raises(review.InconsistentReview):
        run(cfg, store, row, Writer(), checker)
    assert checker.calls == 3 and _correction(job_record(store))["attempts"] == [2]
    assert [event["reask_trigger"] for event in job_record(store)["untrusted_proposals"]] == [True, False]
    resumed = wire_reviewer(cfg, verdict())
    with pytest.raises(review.InconsistentReview):
        run(cfg, store, row, Writer(), resumed)
    assert resumed.calls == 0 and not store.stories()


def test_pending_untrusted_edit_is_verified_using_the_current_edited_candidate(llm_context):
    """Re-ask verification against the edited candidate rather than reverting to the initial draft."""
    cfg, store = llm_context
    row = pending(store)
    checker = wire_reviewer(cfg, inconsistent({"summary": "A changed source-bound summary."}), _unusable(), verdict())
    assert run(cfg, store, row, Writer(), checker)["status"] == "published"
    payloads = [json.loads(request["messages"][1]["content"]) for request in checker.client.bodies]
    assert payloads[1]["candidate"]["summary"] == payloads[2]["candidate"]["summary"] == "A changed source-bound summary."
    assert payloads[2] == {**payloads[1], "validation_error": review.INCONSISTENT_VERDICT}
    audit = saved_audit(store)
    assert len(audit["reviews"]) == 1 and audit["reviews"][0]["stage"] == "verification"
    assert audit["untrusted_proposals"][0]["disposition"] == "checked_approve"
    assert _correction(audit)["trigger"] == 2 and checker.calls == 3


def test_update_correction_keeps_scope_readonly_history_and_ordered_inputs(llm_context):
    """Preserve `latest_update` scope, schema, and prompt order during update validation re-asks."""
    cfg, _ = llm_context
    case, prepared = _update_case()
    original = copy.deepcopy(case["candidate"])
    audit, requests = _new_review_state(cfg, original)
    checker = wire_reviewer(cfg, inconsistent({}, update=True), verdict(update=True), verdict(update=True))
    stage, cand = review_gate.advance_review(checker, "review", original, prepared, audit, requests)
    assert stage == "verify" and cand == original and checker.calls == 2
    action, cand = review_gate.advance_review(checker, stage, cand, prepared, audit, requests)
    assert action == "approve" and cand == original and checker.calls == 3
    bodies = [json.loads(request["messages"][1]["content"]) for request in checker.client.bodies]
    assert bodies[1] == {**bodies[0], "validation_error": review.INCONSISTENT_VERDICT}
    assert bodies[1]["review_scope"] == "latest_update"
    assert checker.client.bodies[0]["response_format"] == checker.client.bodies[1]["response_format"]
    assert checker.client.bodies[1]["messages"][0]["content"] == review.UPDATE_SYSTEM_PROMPT + review.VALIDATION_REASK_PROMPT


def test_context_change_abandons_pending_feedback_without_replenishing_slot(llm_context):
    """Drop `validation_error` feedback on context change without resetting the consumed re-ask slot."""
    cfg, store = llm_context
    row = pending(store)
    first = wire_reviewer(cfg, _unusable(), FetchError("temporary", status=500))
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), first)
    previous = copy.deepcopy(_correction(job_record(store)))
    add_coverage(store)
    changed = wire_reviewer(cfg, _unusable())
    with pytest.raises(review.InconsistentReview):
        run(cfg, store, row, Writer(), changed)
    assert changed.calls == 1 and _correction(job_record(store)) == previous
    assert "validation_error" not in json.loads(changed.client.bodies[0]["messages"][1]["content"])
    assert job_record(store)["untrusted_proposals"][0]["disposition"] == "discarded_context"
    assert job_record(store)["request_budget"]["reserved"] == 3 and len(store.stories()) == 1


def test_route_carries_consumed_slot_and_operator_reset_starts_a_new_ledger(llm_context):
    """Carry consumed `validation_reask` state across `same_story` routing until operator reset."""
    cfg, store = llm_context
    _, _, row, update = seed_routed_followup(cfg, store, replies=[_unusable(), "route"])
    assert _correction(job_record(store))["response"] == 2
    checker = wire_reviewer(cfg, inconsistent({}, update=True))
    with pytest.raises(review.InconsistentReview):
        run(cfg, store, queued_row(store, row), Writer(update), checker)
    assert checker.calls == 1 and job_record(store)["request_budget"]["reserved"] == 3
    assert _correction(job_record(store))["response"] == 2
    assert "validation_error" not in json.loads(checker.client.bodies[0]["messages"][1]["content"])
    assert job_record(store)["untrusted_proposals"][0]["disposition"] == "discarded_context"
    reset = _reset_queued_item(store, row)
    assert _correction(job_record(store)) is None
    fresh = wire_reviewer(cfg, inconsistent({}, update=True), verdict(update=True), verdict(update=True))
    assert run(cfg, store, reset, Writer(update), fresh)["status"] == "published"
    assert fresh.calls == 3 and _correction(saved_audit(store))["trigger"] == 1


def test_correction_transport_attempts_stop_at_seven(llm_context):
    """Enforce the 7-request ceiling across repeated validation re-ask fallback failures."""
    cfg, store = llm_context
    cfg["llm"]["fallback_base_urls"] = [f"https://fallback{n}.example/v1" for n in range(7)]
    row = pending(store)
    checker = wire_reviewer(cfg, _unusable(), *(FetchError("temporary", status=500) for _ in range(6)))
    with pytest.raises(review.ReviewLimitReached):
        run(cfg, store, row, Writer(), checker)
    assert checker.calls == len(checker.client.requests) == 7
    assert job_record(store)["request_budget"]["reserved"] == 7
    assert _correction(job_record(store))["attempts"] == [2, 3, 4, 5, 6, 7]
    assert not store.stories()


def test_last_slot_valid_correction_cannot_publish_without_verification(llm_context):
    """Raise `ReviewLimitReached` when a 7th-slot corrective approval leaves no slot for verification."""
    cfg, store = llm_context
    cfg["llm"]["fallback_base_urls"] = [f"https://fallback{n}.example/v1" for n in range(5)]
    row = pending(store)
    checker = wire_reviewer(cfg, *(FetchError("temporary", status=500) for _ in range(5)), _unusable(), verdict())
    with pytest.raises(review.ReviewLimitReached):
        run(cfg, store, row, Writer(), checker)
    audit = job_record(store)
    assert checker.calls == 7 and _correction(audit)["response"] == 7
    assert len(audit["reviews"]) == 1 and audit["reviews"][0]["stage"] == "review"
    assert not store.stories()


@pytest.mark.parametrize("damage", list(_REASK_DAMAGE))
def test_correction_ledger_damage_fails_before_models_or_cached_approval(llm_context, damage):
    """Fail with `app.damaged_job` on any `validation_reask` ledger tampering before model or cache."""
    cfg, store = llm_context
    row = pending(store)
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), wire_reviewer(cfg, _unusable(), FetchError("temporary", status=500)))
    audit = job_record(store)
    prepared = json.loads(job(store)["envelope_json"])
    insert_approval(store, prepared, policy=review.policy_hash(cfg))
    idle = wire_reviewer(cfg)
    assert run(cfg, store, row, Writer(), idle, allow_network=False)["status"] == "deferred"
    assert idle.calls == 0 and not store.stories()
    _REASK_DAMAGE[damage](audit, _correction(audit))
    patch_job(store, row, record=audit)
    assert_damaged_job(cfg, store, row, replies=(verdict(), verdict()))
    assert not store.stories()


def test_new_record_cannot_reset_a_damaged_ledger_on_policy_change(llm_context):
    """Reject damaged `validation_reask` ledgers even when `policy_hash` changes."""
    cfg, store = llm_context
    row = pending(store)
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), wire_reviewer(cfg, _unusable(), FetchError("temporary", status=500)))
    audit = job_record(store)
    old_policy = "e" * 64
    assert old_policy != review.policy_hash(cfg)
    audit["policy_hash"] = old_policy
    audit["request_budget"].pop("validation_reask")
    for event in audit["untrusted_proposals"]:
        event["context"]["policy_hash"] = old_policy
        event.pop("reask_trigger")
        event.pop("reask_response")
    patch_job(store, row, policy_hash=old_policy, record=audit)
    assert_damaged_job(cfg, store, row)


@pytest.mark.parametrize("damage", [False, True])
def test_nested_cached_correction_proof_is_validated_without_another_request(llm_context, monkeypatch, damage):
    """Validate nested `validation_reask` proofs inside cached approval receipts without new calls."""
    cfg, store = llm_context
    row = pending(store)
    audit = pause_cached_after_reset(cfg, store, row, monkeypatch, replies=(_unusable(), verdict(), verdict()))
    assert _correction(audit) is None and _correction(audit["approval"])["response"] == 2
    if damage:
        audit["approval"]["request_budget"]["validation_reask"] = None
        patch_job(store, row, record=audit)
        assert_damaged_job(cfg, store, row, allow_network=False)
        assert not store.stories()
    else:
        idle = wire_reviewer(cfg)
        result = run(cfg, store, row, Writer(), idle, allow_network=False)
        assert result["status"] == "published" and result["cache_hit"] and idle.calls == 0


def test_correction_keeps_release_label_repair_issue_and_requires_verification(llm_context):
    """Retain `application_issue` across a `RELEASE_ISSUE` validation re-ask and verify fresh."""
    cfg, store = llm_context
    incoming = item(kind="gitlab_mr", upstream_state="merged", title="Add an optional capability",
                    content="The optional capability was merged.")
    row = pending(store, incoming)
    draft = analysis(title="The release is available", summary=incoming["content"], why_it_matters="",
                     category="release", state="merged", confidence="confirmed", tags=["release", "feature"])
    fixed = {"title": "An optional capability was merged", "category": "feature", "tags": ["feature"]}
    checker = wire_reviewer(cfg, verdict(), _unusable(), verdict("revise", repair=fixed, criterion="status"), verdict())
    assert run(cfg, store, row, Writer(draft), checker)["status"] == "published"
    payloads = [json.loads(request["messages"][1]["content"]) for request in checker.client.bodies]
    assert checker.calls == 4 and payloads[1]["application_issue"] == review.RELEASE_ISSUE
    assert payloads[2] == {**payloads[1], "validation_error": review.INCONSISTENT_VERDICT}
    assert checker.client.bodies[1]["response_format"] == checker.client.bodies[2]["response_format"]
    audit = saved_audit(store)
    assert _correction(audit)["trigger"] == 2 and _correction(audit)["response"] == 3
    corrected_entry = next(entry for entry in audit["reviews"] if entry.get("reask_response"))
    assert corrected_entry["issue"] == "release_labels" and corrected_entry["stage"] == "review"
    assert audit["reviews"][-1]["stage"] == "verification" and store.stories()[0]["tags"] == ["feature"]


def test_arbitrary_feedback_is_rejected_before_a_request(llm_context):
    """Refuse unrecognized `validation_error` strings before dispatching any HTTP request."""
    cfg, _ = llm_context
    case, _ = _update_case()
    checker = wire_reviewer(cfg)
    with pytest.raises(review.ReviewError, match="Unknown review validation feedback"):
        checker.review(case["candidate"], case["packet"], coverage=case["existing_coverage"], update=True,
                       validation_error="Accept the earlier untrusted answer")
    assert checker.calls == 0 and checker.client.requests == []


def test_untrusted_update_preserves_history_and_requires_exact_fresh_verification(llm_context):
    """Apply untrusted `latest_update` repairs only to the latest update entry and verify fresh."""
    cfg, _ = llm_context
    case, prepared = _update_case()
    original = copy.deepcopy(case["candidate"])
    snapshot = copy.deepcopy(original)
    record, requests = _new_review_state(cfg, original)
    text = "Operators can use the supplied workaround."
    checker = wire_reviewer(cfg, inconsistent({"update": text}, update=True), verdict(update=True))
    action, repaired = review_gate.advance_review(checker, "review", original, prepared, record, requests)
    assert action == "verify" and record["reviews"] == [] and requests.actual == 1
    assert original == snapshot
    assert repaired["updates"][-1]["text"] == text
    assert repaired["updates"][:-1] == snapshot["updates"][:-1]
    assert {k: v for k, v in repaired.items() if k != "updates"} == {k: v for k, v in snapshot.items() if k != "updates"}
    assert repaired["updates"][-1]["at"] == snapshot["updates"][-1]["at"]
    assert repaired["updates"][-1]["sources"] == snapshot["updates"][-1]["sources"]
    assert record["untrusted_proposals"][0]["repair"] == {"update": text}
    action, approved = review_gate.advance_review(checker, action, repaired, prepared, record, requests)
    assert action == "approve" and approved == repaired and requests.actual == 2
    wire = [json.loads(r["messages"][1]["content"]) for r in checker.client.bodies]
    assert wire[0]["review_scope"] == wire[1]["review_scope"] == "latest_update"
    assert json.dumps(wire[0]["packet"]) == json.dumps(wire[1]["packet"])
    assert json.dumps(wire[0]["coverage_background"]) == json.dumps(wire[1]["coverage_background"])
    assert wire[1]["candidate"] == repaired
    assert checker.client.bodies[1]["messages"][0]["content"] == review.UPDATE_VERIFY_PROMPT
    record.update(candidate=repaired, outcome="approved",
                  approval_key=digest([digest(repaired), digest(prepared["packet"]), record["policy_hash"],
                                       review_gate._context(prepared, record["policy_hash"])["binding_hash"]]))
    review_gate.validate_review_state(record, "approved", repaired, prepared)


@pytest.mark.parametrize("damage", list(_UPDATE_SCOPE_DAMAGE))
def test_update_recovery_proof_cannot_be_replayed_for_history_or_another_scope(llm_context, damage):
    """Reject update recovery proofs if prior fields, history, timestamps, citations, or scope drift."""
    cfg, _ = llm_context
    case, prepared = _update_case()
    record, requests = _new_review_state(cfg, case["candidate"])
    checker = wire_reviewer(cfg, inconsistent({"update": "Operators can use the supplied workaround."}, update=True))
    stage, cand = review_gate.advance_review(checker, "review", case["candidate"], prepared, record, requests)
    _UPDATE_SCOPE_DAMAGE[damage](cand, prepared)
    with pytest.raises(AnalysisError, match="damaged"):
        review_gate.advance_review(checker, stage, cand, prepared, record, review_gate.ReviewRequests(record))
    assert checker.calls == 1


def test_invalid_route_identity_never_enters_untrusted_recovery(llm_context):
    """Raise `ReviewError` immediately when an inconsistent reply cites an unlisted `same_story`."""
    cfg, _ = llm_context
    case, prepared = _update_case()
    record, requests = _new_review_state(cfg, case["candidate"])
    checker = wire_reviewer(cfg, inconsistent({"update": "A proposed update."}, update=True, same_story="unlisted-target"))
    with pytest.raises(review.ReviewError, match="same_story"):
        review_gate.advance_review(checker, "review", case["candidate"], prepared, record, requests)
    assert record["reviews"] == record["untrusted_proposals"] == []
    assert record["request_budget"]["reserved"] == checker.calls == 1


def test_untrusted_merge_request_release_tag_is_not_applied_during_correction(llm_context):
    """Refuse untrusted `release` tag additions on merged merge-request drafts."""
    cfg, store = llm_context
    row = pending(store, item(kind="gitlab_mr", upstream_state="merged"))
    checker = wire_reviewer(cfg, inconsistent({"summary": "A revised merged change.", "tags": ["release"]}),
                            verdict("hold", criterion="source_support"))
    assert run(cfg, store, row, Writer(analysis(state="merged")), checker)["status"] == "held"
    assert job_record(store)["untrusted_proposals"][0]["disposition"] == "labels"
    assert checker.calls == 2 and not store.stories()
    payloads = [json.loads(request["messages"][1]["content"]) for request in checker.client.bodies]
    assert payloads[1]["candidate"] == payloads[0]["candidate"]


def test_route_update_fallbacks_share_one_budget_and_operator_retry_starts_new_review(llm_context):
    """Carry fallback spend across `same_story` routing and reset only on `reset_review_work`."""
    cfg, store = llm_context
    _, _, row, update = seed_routed_followup(cfg, store, fallbacks=4)
    assert job(store)["stage"] == "routed" and job_record(store)["request_budget"]["reserved"] == 6
    checker = wire_reviewer(cfg, verdict(update=True), verdict(update=True))
    with pytest.raises(review.ReviewLimitReached):
        run(cfg, store, queued_row(store, row), Writer(update), checker)
    assert checker.calls == 1 and len(checker.client.requests) == 1
    assert job_record(store)["request_budget"]["reserved"] == 7
    assert len(store.stories()) == 1 and not store.stories()[0].get("updates")
    reset = _reset_queued_item(store, row)
    assert job_record(store)["request_budget"]["reserved"] == 0
    assert run(cfg, store, reset, Writer(update), wire_reviewer(cfg, verdict(update=True), verdict(update=True)))["status"] == "published"
    assert saved_audit(store)["request_budget"]["reserved"] == 2


@pytest.mark.parametrize("transfer", ["unlock", "merge", "locked-survivor"])
@pytest.mark.parametrize("with_correction", [False, True])
def test_routed_budget_survives_locked_commit_unlock_and_held_transfer(llm_context, transfer, with_correction):
    """Preserve routed spend and `validation_reask` state across locked holds, merges, and unlocks."""
    cfg, store = llm_context
    target = seed_source_story(store, item(url="https://example.org/locked-incident", title="Authority overload report",
                                           content="Operators report directory authority overload."))
    survivor = (seed_source_story(store, item(url="https://example.org/earlier-incident", title="Earlier authority report",
                                              content="An earlier report describes directory authority overload."))
                if transfer != "unlock" else None)
    cli.build(cfg, store)
    editorial_act(editorial.correct, store, target["id"], {"priority": "normal"}, reason="Review this account.")
    if transfer == "locked-survivor":
        editorial_act(editorial.correct, store, survivor["id"], {"priority": "normal"}, reason="Review this account.")
    replies = ([inconsistent({})] if with_correction else []) + ["route"]
    _, incoming, row, update = seed_routed_followup(cfg, store, target=target, replies=replies)
    spent = 2 if with_correction else 1
    assert run(cfg, store, queued_row(store, row), Writer(update), wire_reviewer(cfg))["status"] == "locked"
    held_record = job_record(store)
    assert job(store)["stage"] == "locked" and held_record["request_budget"]["reserved"] == spent
    if with_correction:
        assert held_record["request_budget"]["validation_reask"]["response"] == 2
    assert held_record["reviews"] == [] and not held_record.get("approval")
    destination = target
    if survivor is not None:
        editorial_act(editorial.merge, store, target["id"], survivor["id"],
                      reason="Combine duplicate accounts.", base_url=cfg["site"]["base_url"])
        destination = survivor
        assert job_record(store) == held_record
    if transfer != "merge":
        editorial_act(editorial.unlock, store, destination["id"], reason="Allow this update.")
        assert job_record(store) == held_record
    checker = wire_reviewer(cfg, verdict(update=True), verdict(update=True))
    assert run(cfg, store, queued_row(store, row), Writer(update), checker)["status"] == "published"
    assert checker.calls == 2 and saved_audit(store)["request_budget"]["reserved"] == spent + 2
    assert saved_audit(store)["request_budget"]["validation_reask"] == held_record["request_budget"]["validation_reask"]
    assert not job(store)
    final = next(s for s in store.stories() if s["id"] == destination["id"])
    assert final["updates"][-1]["text"] == incoming["content"]


def test_damaged_locked_ledger_does_not_reset_on_unlock(llm_context):
    """Refuse to reset or bypass a damaged `request_budget` ledger when unlocking a target story."""
    cfg, store = llm_context
    target = seed_source_story(store, item(url="https://example.org/locked", title="An incident report"))
    editorial_act(editorial.correct, store, target["id"], {"priority": "normal"}, reason="Review this report.")
    row = pending(store, item(url="https://example.org/followup-note", title="New incident information"))
    assert run(cfg, store, row, Writer(), wire_reviewer(cfg, verdict(same_story=target["id"])))["status"] == "routed"
    assert run(cfg, store, queued_row(store, row), Writer(update_analysis()), wire_reviewer(cfg))["status"] == "locked"
    broken = job_record(store)
    broken.pop("request_budget")
    patch_job(store, row, record=broken)
    editorial_act(editorial.unlock, store, target["id"], reason="Resume work.")
    assert_damaged_job(cfg, store, queued_row(store, row), draft=update_analysis(), match="ledger")
    assert not store.stories()[0].get("updates")


def test_untrusted_route_waits_for_fresh_reply_and_carries_journal_into_update(llm_context):
    """Hold `same_story` association until verified and carry the proposal journal into update review."""
    cfg, store = llm_context
    target = seed_source_story(store, item(url="https://example.org/incident-account", title="An authority incident"))
    invalid = inconsistent({"summary": "An operator reports a lower queue depth after mitigation."}, same_story=target["id"])
    associations = []
    _, _, row, update = seed_routed_followup(
        cfg,
        store,
        target=target,
        replies=[invalid, "route"],
        before=lambda: associations.append(
            store.db.execute("SELECT story_id FROM items WHERE url='https://example.org/followup'").fetchone()[0]
        ),
    )
    assert associations == [None, None]
    assert job_record(store)["request_budget"]["reserved"] == 2
    assert len(job_record(store)["reviews"]) == 1
    assert job_record(store)["untrusted_proposals"][0]["disposition"] == "checked_approve"
    assert run(cfg, store, queued_row(store, row), Writer(update),
               wire_reviewer(cfg, verdict(update=True), verdict(update=True)))["status"] == "published"
    audit = saved_audit(store)
    assert audit["request_budget"]["reserved"] == 4
    assert audit["untrusted_proposals"][0]["mode"] == "story"
    assert audit["untrusted_proposals"][0]["disposition"] == "discarded_context"
    assert len(audit["reviews"]) == 2 and audit["reviews"][0]["request"] == 3


def test_text_only_alert_update_recovery_preserves_fixed_labels_outside_incoming_limits(llm_context, tmp_path):
    """Preserve fixed `network-health` labels during text-only untrusted update recovery."""
    cfg, _, prior, incoming, prepared = _prepared_alert_update(llm_context, tmp_path)
    expected = review.apply_repair(prepared["candidate"], {"update": incoming["content"]}, update=True)
    assert review.final_holds(expected, prepared) == []
    audit, requests = _new_review_state(cfg, prepared["candidate"])
    checker = wire_reviewer(cfg, inconsistent({"update": incoming["content"]}, update=True), verdict(update=True))
    stage, after = review_gate.advance_review(checker, "review", prepared["candidate"], prepared, audit, requests)
    assert stage == "verify" and after == expected
    action, after = review_gate.advance_review(checker, stage, after, prepared, audit, requests)
    assert action == "approve" and checker.calls == 2
    assert after["updates"][-1]["text"] == incoming["content"]
    assert all(after[field] == prior[field] for field in candidate.SEMANTIC_FIELDS)


def test_untrusted_alert_label_change_is_rejected_and_cannot_poison_later_proof(llm_context, tmp_path):
    """Reject untrusted `state` edits on `network-health` alerts without poisoning subsequent proof."""
    cfg, _, prior, incoming, prepared = _prepared_alert_update(llm_context, tmp_path)
    original = copy.deepcopy(prepared["candidate"])
    audit, requests = _new_review_state(cfg, original)
    checker = wire_reviewer(cfg, inconsistent({"update": incoming["content"], "state": "merged"}, update=True),
                            verdict(update=True), verdict(update=True))
    stage, unchanged = review_gate.advance_review(checker, "review", original, prepared, audit, requests)
    assert stage == "verify" and unchanged == original
    assert checker.calls == 2 and len(audit["reviews"]) == 1 and review_gate.pending_proposal(audit) is None
    assert audit["untrusted_proposals"][0]["accepted"] is False
    assert audit["candidate"] == original and original["state"] == prior["state"]
    assert not review_gate.proposal_needs_check(audit)
    action, unchanged = review_gate.advance_review(checker, stage, unchanged, prepared, audit, requests)
    assert action == "approve" and unchanged == original and checker.calls == 3
    assert not review_gate.proposal_needs_check(audit)
    audit.update(outcome="approved", approval_key=review_gate._approval_key(original, prepared, audit["policy_hash"]))
    review_gate.validate_review_state(audit, "approved", original, prepared)


def test_locked_citation_transition_retains_existing_budget_until_deterministic_commit(llm_context):
    """Retain existing review spend while locked and clear the job upon deterministic citation commit."""
    cfg, store = llm_context
    target, row = seed_citation_job(cfg, store)
    before = job_record(store)
    assert run(cfg, store, row, Writer(), wire_reviewer(cfg))["status"] == "locked"
    assert job_record(store) == before
    editorial_act(editorial.unlock, store, target["id"], reason="Allow citation updates.")
    assert job_record(store) == before
    checker = wire_reviewer(cfg)
    assert run(cfg, store, queued_row(store, row), Writer(), checker)["status"] == "cited"
    assert checker.calls == 0 and job(store) is None


def test_duplicate_only_products_repair_triggers_validation_reask_instead_of_verification(llm_context):
    """Treat an all-pass `verdict='revise'` with `products=['tor', 'tor']` as an unusable no-op proposal."""
    cfg, store = llm_context
    row = pending(store)
    checker = wire_reviewer(cfg, inconsistent({"products": ["tor", "tor"]}), verdict(), verdict())
    assert run(cfg, store, row, Writer(), checker)["status"] == "published"
    audit = saved_audit(store)
    assert checker.calls == 3
    assert audit["untrusted_proposals"][0]["accepted"] is False
    assert audit["untrusted_proposals"][0]["disposition"] == "unusable"
    assert _correction(audit)["trigger"] == 1 and _correction(audit)["response"] == 2
    assert store.stories()[0]["products"] == ["tor"]


def test_untrusted_mr_only_update_category_proposal_replays_inherited_release_tag(llm_context):
    """Persist and replay proposed edits separately from normalization-inherited tags on MR-only updates."""
    from onionflash import render

    cfg, _ = llm_context
    mr_url = "https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/951"
    mr_src = {
        "id": "S1",
        "url": mr_url,
        "title": "Fix relay security parsing",
        "kind": "gitlab_mr",
        "authority": "development",
        "product": "tor",
        "published_at": "2026-11-08T12:00:00Z",
        "updated_at": "2026-11-09T12:00:00Z",
        "upstream_state": "merged",
        "labels": [],
        "passages": [
            {"id": "S1:P1", "text": "Fix relay security parsing"},
            {"id": "S1:P2", "text": "Merged a security fix for relay descriptor parsing."},
        ],
    }
    cand = render.prepare_story({
        "id": "a" * 24,
        "title": "Tor 0.4.9.10 released",
        "summary": "Tor 0.4.9.10 shipped with network updates.",
        "why_it_matters": "",
        "category": "network",
        "priority": "normal",
        "confidence": "confirmed",
        "state": "released",
        "products": ["tor"],
        "tags": ["network", "release"],
        "published_at": "2026-11-08T12:00:00Z",
        "updated_at": "2026-11-09T12:00:00Z",
        "added_at": "2026-11-08T12:00:00Z",
        "sources": [{"url": mr_url, "title": mr_src["title"]}],
        "updates": [{
            "at": "2026-11-09T12:00:00Z",
            "text": "Maintainers merged !951 with a security fix.",
            "sources": [{"url": mr_url, "title": mr_src["title"]}],
        }],
    })
    prepared = {
        "candidate": cand,
        "packet": {"sources": [mr_src], "missing_sources": [], "truncated": False},
        "coverage": {
            "prior_story": {"id": cand["id"], "state": "released", "confidence": "confirmed", "updated_at": "2026-11-08T12:00:00Z"},
            "recent": [],
            "truncated": False,
        },
        "mode": "update",
        "payload": {"editorial_kind": "gitlab_mr"},
        "row": {
            "payload": json.dumps({
                "kind": "gitlab_mr",
                "authority": "development",
                "upstream_state": "merged",
                "url": mr_url,
                "title": mr_src["title"],
                "content": "Merged a security fix for relay descriptor parsing.",
                "published_at": "2026-11-08T12:00:00Z",
                "updated_at": "2026-11-09T12:00:00Z",
            })
        },
    }
    limits = review.repair_limits(prepared["packet"], prepared["coverage"], update=True, candidate_sources=cand["sources"])
    assert "release" not in limits["category"] and "security" in limits["category"]

    record, requests = _new_review_state(cfg, copy.deepcopy(cand))
    checker = wire_reviewer(cfg, inconsistent({"category": "security"}, update=True), verdict(update=True))
    stage, repaired = review_gate.advance_review(checker, "review", copy.deepcopy(cand), prepared, record, requests)
    assert stage == "verify"
    assert repaired["category"] == "security" and repaired["tags"] == ["security", "release"]
    event = record["untrusted_proposals"][0]
    assert event["accepted"] is True
    assert event["repair"] == {"category": "security"}
    assert event["changed_fields"] == ["category", "tags"]
    review_gate.validate_review_state(record, "verify", repaired, prepared)

    action, approved = review_gate.advance_review(checker, stage, repaired, prepared, record, requests)
    assert action == "approve" and approved == repaired and checker.calls == 2
    record.update(
        candidate=repaired,
        outcome="approved",
        approval_key=digest([
            digest(repaired), digest(prepared["packet"]), record["policy_hash"],
            review_gate._context(prepared, record["policy_hash"])["binding_hash"],
        ]),
    )
    review_gate.validate_review_state(record, "approved", repaired, prepared)

    explicit_record, explicit_requests = _new_review_state(cfg, copy.deepcopy(cand))
    explicit_checker = wire_reviewer(
        cfg,
        inconsistent({"category": "security", "tags": ["security", "release"]}, update=True),
        verdict("hold", criterion="source_support", update=True),
    )
    action2, _ = review_gate.advance_review(
        explicit_checker, "review", copy.deepcopy(cand), prepared, explicit_record, explicit_requests
    )
    assert action2 == "hold"
    assert explicit_record["untrusted_proposals"][0]["accepted"] is False
    assert explicit_record["untrusted_proposals"][0]["disposition"] == "labels"
    assert explicit_record["untrusted_proposals"][0]["repair"] == {"category": "security", "tags": ["security", "release"]}
