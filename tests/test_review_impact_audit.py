"""Deletion audits preserve source-supported text without replacing verification."""

import copy
import json

import pytest

from helpers import (LATER, FakeLLM, Writer, analysis, approve, completion, item, job, pending,
                     run_gate as run, update_analysis, verdict)
from onionflash import review, review_gate
from onionflash.analyze import tag_notice
from onionflash.llm import AnalysisError
from onionflash.store import ReviewRequired
from onionflash.transport import FetchError, Response
from onionflash.util import digest
from test_review_gate import add_coverage
from test_review_request_budget import context, inconsistent, record, reviewer, saved_audit


IMPACT = "The report says interrupted connections prevent the operator from collecting diagnostics."
SUMMARY = "The source reports a narrower availability problem."


def assessed(outcome="supported"):
    return {"outcome": outcome, "reason": "The source assessment considers the concrete consequence.",
            "source_refs": ["S1"] if outcome == "supported" else []}


def proposed(kind, **extra):
    edits = {"why_it_matters": "", **extra}
    return inconsistent(edits) if kind == "proposal" else verdict("revise", repair=edits, criterion="source_support")


def writer():
    return Writer(analysis(why_it_matters=IMPACT))


def payloads(checker):
    return [json.loads(request["messages"][-1]["content"]) for request in checker.client.requests]


def schemas(checker):
    return [request["response_format"]["json_schema"]["name"] for request in checker.client.requests]


class Interrupted(BaseException):
    pass


def pause_audit(cfg, store, row, monkeypatch, *, at="pending", kind="review", outcome="supported"):
    save = review_gate._save

    def checkpoint(*args, **kwargs):
        save(*args, **kwargs)
        audits = args[7].get("impact_audits", [])
        if audits and audits[-1]["status"] == at:
            raise Interrupted(at)

    checker = reviewer(cfg, proposed(kind), assessed(outcome))
    with monkeypatch.context() as scoped:
        scoped.setattr(review_gate, "_save", checkpoint)
        with pytest.raises(Interrupted, match=at):
            run(cfg, store, row, writer(), checker)
    return record(store), checker


@pytest.mark.parametrize("kind", ["review", "proposal"])
@pytest.mark.parametrize("outcome", ["supported", "unsupported"])
def test_audited_deletion_always_gets_exact_fresh_verification(context, kind, outcome):
    cfg, store = context
    row = pending(store)
    snapshots = []
    checker = reviewer(cfg, proposed(kind), assessed(outcome), verdict(),
                       before=lambda: snapshots.append(copy.deepcopy(job(store))))
    result = run(cfg, store, row, writer(), checker)
    assert result["status"] == "published" and result["review_calls"] == checker.calls == 3
    assert schemas(checker) == ["onionflash_review", "onionflash_impact_audit", "onionflash_review"]
    first, audit_payload, verification = payloads(checker)
    assert audit_payload == {"original_impact": IMPACT, "proposed_impact": "", "packet": first["packet"]}
    assert verification["candidate"]["why_it_matters"] == (IMPACT if outcome == "supported" else "")
    assert checker.client.requests[-1]["messages"][0]["content"] == review.VERIFY_PROMPT
    assert "UNTRUSTED_PREVIOUS_CRITERIA_SENTINEL" not in json.dumps(audit_payload)
    assert "UNTRUSTED_PREVIOUS_CRITERIA_SENTINEL" not in json.dumps(verification)
    before_audit = json.loads(snapshots[1]["record_json"])
    assert before_audit["schema_version"] == 3 and before_audit["impact_audits"][0]["status"] == "sent"
    assert before_audit["request_budget"]["reserved"] == 2
    assert before_audit["reviews"] == [] and before_audit["untrusted_proposals"] == []
    saved = saved_audit(store)
    assert len(saved["impact_audits"]) == 1 and saved["impact_audits"][0]["result"] == assessed(outcome)
    assert saved["impact_audits"][0]["effective_hash"] == digest(verification["candidate"])
    assert saved["request_budget"]["reserved"] == 3
    assert len(saved["reviews"]) == (2 if kind == "review" else 1)
    assert saved["reviews"][-1]["stage"] == "verification"
    assert saved["reviews"][-1]["request"] == 3


@pytest.mark.parametrize("kind", ["review", "proposal"])
def test_supported_sentence_veto_drops_only_the_deletion(context, kind):
    cfg, store = context
    row = pending(store)
    checker = reviewer(cfg, proposed(kind, summary=SUMMARY), assessed(), verdict())
    assert run(cfg, store, row, writer(), checker)["status"] == "published"
    exact = payloads(checker)[-1]["candidate"]
    assert exact["why_it_matters"] == IMPACT and exact["summary"] == SUMMARY
    assert store.stories()[0]["why_it_matters"] == IMPACT
    assert store.stories()[0]["summary"] == SUMMARY


@pytest.mark.parametrize("kind", ["review", "proposal"])
def test_audit_support_cannot_overrule_a_failed_fresh_verification(context, kind):
    cfg, store = context
    row = pending(store)
    checker = reviewer(cfg, proposed(kind), assessed(), verdict("hold", criterion="source_support"))
    assert run(cfg, store, row, writer(), checker)["status"] == "held"
    assert checker.calls == 3 and not store.stories()
    saved = record(store)
    assert saved["impact_audits"][0]["result"]["outcome"] == "supported"
    assert saved["reviews"][-1]["stage"] == "verification"
    assert saved["reviews"][-1]["result"]["verdict"] == "hold"
    assert saved["verified_facts"] is False
    assert not review_gate.approval(cfg, store, row["id"])["eligible"]


@pytest.mark.parametrize("kind", ["review", "proposal"])
@pytest.mark.parametrize("response,status", [
    (assessed("insufficient"), "complete"),
    ({**assessed(), "source_refs": []}, "failed"),
    (FetchError("Temporarily unavailable", status=503, retryable=True), "failed"),
])
def test_audit_refusal_or_error_holds_without_applying_or_resampling(context, kind, response, status):
    cfg, store = context
    row = pending(store)
    checker = reviewer(cfg, proposed(kind), response)
    assert run(cfg, store, row, writer(), checker)["status"] == "held"
    assert checker.calls == 2 and schemas(checker)[-1] == "onionflash_impact_audit"
    saved = record(store)
    assert saved["hold_code"] == "impact_audit" and saved["verified_facts"] is False
    assert saved["impact_audits"][0]["status"] == status
    assert saved["impact_audits"][0]["effective_hash"] is None
    retained = saved.get("candidate", json.loads(job(store)["envelope_json"])["candidate"])
    assert retained["why_it_matters"] == IMPACT and not store.stories()
    assert not review_gate.approval(cfg, store, row["id"])["eligible"]
    idle = reviewer(cfg)
    assert run(cfg, store, row, writer(), idle)["status"] in {"held", "stale"}
    assert idle.calls == 0 and record(store)["impact_audits"][0]["status"] == status


@pytest.mark.parametrize("response,code", [
    (completion(assessed(), finish_reason="length"), "review.truncated"),
    (Response(200, json.dumps({"choices": [{"finish_reason": "stop", "message": {"content": "{"}}]}).encode(),
              {}, "https://model.example/v1/chat/completions"), "review.invalid_json"),
])
def test_native_audit_completion_failure_is_held_with_its_original_code(context, response, code):
    cfg, store = context
    row = pending(store)
    checker = review.Reviewer(cfg)
    checker.client = FakeLLM(completion(proposed("review")), response)
    assert run(cfg, store, row, writer(), checker)["status"] == "held"
    saved = record(store)
    assert saved["impact_audits"][0]["error"]["code"] == code
    assert saved["impact_audits"][0]["status"] == "failed"
    assert saved["request_budget"]["reserved"] == checker.calls == 2
    assert saved["verified_facts"] is False and not store.stories()


@pytest.mark.parametrize("kind", ["review", "proposal"])
def test_pending_origin_resumes_audit_without_repeating_original_review(context, monkeypatch, kind):
    cfg, store = context
    row = pending(store)
    saved, first = pause_audit(cfg, store, row, monkeypatch, kind=kind)
    assert first.calls == 1 and saved["request_budget"]["reserved"] == 1
    assert saved["impact_audits"][0]["request"] is None
    assert saved["impact_audits"][0]["origin"]["request"] == 1
    assert saved["reviews"] == [] and saved["untrusted_proposals"] == []
    second_writer, checker = Writer(), reviewer(cfg, assessed(), verdict())
    assert run(cfg, store, row, second_writer, checker)["status"] == "published"
    assert not second_writer.calls and checker.calls == 2
    assert schemas(checker) == ["onionflash_impact_audit", "onionflash_review"]
    assert saved_audit(store)["request_budget"]["reserved"] == 3


@pytest.mark.parametrize("kind", ["review", "proposal"])
def test_unknown_dispatched_audit_is_not_resampled_after_restart(context, monkeypatch, kind):
    cfg, store = context
    row = pending(store)
    saved, _ = pause_audit(cfg, store, row, monkeypatch, at="sent", kind=kind)
    assert saved["request_budget"]["reserved"] == saved["impact_audits"][0]["request"] == 2
    checker = reviewer(cfg)
    assert run(cfg, store, row, Writer(), checker)["status"] == "held"
    assert checker.calls == 0 and not store.stories()
    final = record(store)
    assert final["impact_audits"][0]["status"] == "failed"
    assert final["impact_audits"][0]["error"]["type"] == "InterruptedAudit"
    assert final["request_budget"]["reserved"] == 2


@pytest.mark.parametrize("kind", ["review", "proposal"])
@pytest.mark.parametrize("outcome", ["supported", "unsupported"])
def test_durable_completed_audit_resumes_only_the_required_verification(context, monkeypatch, kind, outcome):
    cfg, store = context
    row = pending(store)
    saved, first = pause_audit(cfg, store, row, monkeypatch, at="complete", kind=kind, outcome=outcome)
    assert first.calls == saved["request_budget"]["reserved"] == 2
    checker = reviewer(cfg, verdict())
    assert run(cfg, store, row, Writer(), checker)["status"] == "published"
    assert checker.calls == 1 and schemas(checker) == ["onionflash_review"]
    assert payloads(checker)[0]["candidate"]["why_it_matters"] == (IMPACT if outcome == "supported" else "")
    assert saved_audit(store)["request_budget"]["reserved"] == 3


@pytest.mark.parametrize("kind", ["review", "proposal"])
def test_completed_unverified_audit_blocks_operator_and_cached_approval(context, monkeypatch, kind):
    cfg, store = context
    row = pending(store)
    pause_audit(cfg, store, row, monkeypatch, at="complete", kind=kind)
    prepared = json.loads(job(store)["envelope_json"])
    approve(store, prepared, prepared["candidate"], policy=review.policy_hash(cfg))
    assert not review_gate.approval(cfg, store, row["id"])["eligible"]
    checker = reviewer(cfg)
    result = run(cfg, store, row, Writer(), checker, allow_network=False)
    assert result["status"] == "deferred" and not result["cache_hit"]
    assert checker.calls == 0 and not store.stories()
    checker = reviewer(cfg, verdict())
    assert run(cfg, store, row, Writer(), checker)["status"] == "published"
    assert checker.calls == 1 and saved_audit(store)["request_budget"]["reserved"] == 3


@pytest.mark.parametrize("spent,expected", [(4, "published"), (5, "held")])
def test_audit_reserves_room_for_verification_within_seven_total_requests(context, spent, expected):
    cfg, store = context
    row = pending(store)
    for _ in range(spent):
        with pytest.raises(AnalysisError):
            run(cfg, store, row, writer(), reviewer(cfg, FetchError("Unavailable", status=503)))
    checker = reviewer(cfg, proposed("review"), assessed(), verdict())
    assert run(cfg, store, row, Writer(), checker)["status"] == expected
    final = saved_audit(store) if expected == "published" else record(store)
    assert final["request_budget"]["reserved"] == (7 if expected == "published" else 6)
    assert checker.calls == (3 if expected == "published" else 1)
    if expected == "held":
        assert schemas(checker) == ["onionflash_review"]
        assert final["impact_audits"][0]["error"]["type"] == "VerificationSlotUnavailable"
        assert not store.stories()


def test_audit_fallback_cannot_spend_the_last_verification_slot(context):
    cfg, store = context
    cfg["llm"]["fallback_base_urls"] = ["https://backup.example/v1"]
    row = pending(store)
    for _ in range(2):
        checker = reviewer(cfg, FetchError("Unavailable", status=503), FetchError("Unavailable", status=503))
        with pytest.raises(AnalysisError):
            run(cfg, store, row, writer(), checker)
        assert checker.calls == 2
    assert record(store)["request_budget"]["reserved"] == 4
    checker = reviewer(cfg, proposed("review"), FetchError("Unavailable", status=503), assessed(), verdict())
    assert run(cfg, store, row, Writer(), checker)["status"] == "held"
    assert checker.calls == 2 and record(store)["request_budget"]["reserved"] == 6
    assert not store.stories()


@pytest.mark.parametrize("kind", ["review", "proposal"])
def test_same_deletion_is_not_audited_again_after_a_veto(context, kind):
    cfg, store = context
    row = pending(store)
    checker = reviewer(cfg, proposed(kind), assessed(), proposed("review"))
    assert run(cfg, store, row, writer(), checker)["status"] == "held"
    assert checker.calls == 3 and schemas(checker).count("onionflash_impact_audit") == 1
    assert record(store)["impact_audits"][-1]["error"]["type"] == "RepeatedImpactAudit"
    assert not store.stories()


def test_context_change_discards_audit_authority_without_refunding_attempts(context, monkeypatch):
    cfg, store = context
    row = pending(store)
    saved, _ = pause_audit(cfg, store, row, monkeypatch, at="complete")
    assert saved["request_budget"]["reserved"] == 2
    add_coverage(store, identity="a" * 24, title="A separate source report")
    checker = reviewer(cfg, verdict(), verdict())
    assert run(cfg, store, row, Writer(), checker)["status"] == "published"
    final = saved_audit(store)
    assert checker.calls == 2 and schemas(checker) == ["onionflash_review"] * 2
    assert final["request_budget"]["reserved"] == 4
    assert final["impact_audits"][0]["status"] == "discarded_context"
    assert final["candidate"]["why_it_matters"] == IMPACT


@pytest.mark.parametrize("decision", ["approve", "skip"])
def test_no_deletion_does_not_add_an_audit_or_force_factual_repairs(context, decision):
    cfg, store = context
    row = pending(store)
    replies = [verdict(), verdict()] if decision == "approve" else [verdict("skip", criterion="news_value")]
    checker = reviewer(cfg, *replies)
    assert run(cfg, store, row, writer(), checker)["status"] == ("published" if decision == "approve" else "ignored")
    assert checker.calls == len(replies) and "onionflash_impact_audit" not in schemas(checker)
    assert saved_audit(store)["impact_audits"] == []


@pytest.mark.parametrize("damage", [None, "missing-list", "source-ref", "reason", "context", "input-hash", "effective-hash", "missing-result"])
def test_completed_audit_receipt_cannot_be_forged_or_bypassed_by_cached_approval(context, monkeypatch, damage):
    cfg, store = context
    row = pending(store)
    with monkeypatch.context() as scoped:
        def stop(*_args, **_kwargs):
            raise Interrupted("before commit")
        scoped.setattr(store, "commit_candidate", stop)
        with pytest.raises(Interrupted, match="before commit"):
            run(cfg, store, row, writer(), reviewer(cfg, proposed("review"), assessed(), verdict()))
    saved = record(store)
    assert job(store)["stage"] == "approved" and saved["impact_audits"][0]["status"] == "complete"
    if damage == "missing-list":
        saved.pop("impact_audits")
    elif damage == "source-ref":
        saved["impact_audits"][0]["result"]["source_refs"] = ["S9:P9"]
    elif damage == "reason":
        saved["impact_audits"][0]["result"]["reason"] = "abc" * 30
    elif damage == "context":
        saved["impact_audits"][0]["context"]["source_hash"] = "0" * 64
    elif damage == "input-hash":
        saved["impact_audits"][0]["input_hash"] = "0" * 64
    elif damage == "effective-hash":
        saved["impact_audits"][0]["effective_hash"] = "0" * 64
    elif damage == "missing-result":
        saved["impact_audits"][0]["result"] = None
    with store.db:
        store.db.execute("UPDATE review_jobs SET record_json=? WHERE item_id=?", (json.dumps(saved), row["id"]))
    checker = reviewer(cfg)
    if damage:
        with pytest.raises(AnalysisError) as caught:
            run(cfg, store, row, Writer(), checker, allow_network=False)
        assert caught.value.code == "app.damaged_job" and not store.stories()
    else:
        result = run(cfg, store, row, Writer(), checker, allow_network=False)
        assert result["status"] == "published" and result["cache_hit"]
    assert checker.calls == 0


@pytest.mark.parametrize("damage", [None, "audit-on-v2", "missing-v3-list", "current-policy-v2"])
def test_old_version_two_records_require_a_new_policy_and_cannot_claim_audits(context, damage):
    cfg, store = context
    row = pending(store)
    with pytest.raises(AnalysisError):
        run(cfg, store, row, writer(), reviewer(cfg, FetchError("Unavailable", status=503)))
    saved = record(store)
    if damage != "missing-v3-list":
        saved["schema_version"] = 2
    if damage != "audit-on-v2":
        saved.pop("impact_audits")
    if damage != "current-policy-v2":
        saved["policy_hash"] = digest(["previous review policy"])
    with store.db:
        store.db.execute("UPDATE review_jobs SET policy_hash=?,record_json=? WHERE item_id=?",
                         (saved["policy_hash"], json.dumps(saved), row["id"]))
    checker, next_writer = reviewer(cfg, verdict(), verdict()), Writer()
    if damage:
        with pytest.raises(AnalysisError) as caught:
            run(cfg, store, row, next_writer, checker)
        assert caught.value.code == "app.damaged_job" and checker.calls == 0
    else:
        assert run(cfg, store, row, next_writer, checker)["status"] == "published"
        final = saved_audit(store)
        assert final["schema_version"] == 3 and final["impact_audits"] == []
        assert checker.calls == 2
    assert not next_writer.calls


@pytest.mark.parametrize("boundary", ["cache", "commit"])
@pytest.mark.parametrize("damage", ["empty-receipts", "missing-list"])
def test_mixed_proposal_cannot_lose_its_required_audit_receipt(context, monkeypatch, boundary, damage):
    cfg, store = context
    row = pending(store)
    with monkeypatch.context() as scoped:
        def stop(*_args, **_kwargs):
            raise Interrupted("before commit")
        scoped.setattr(store, "commit_candidate", stop)
        with pytest.raises(Interrupted, match="before commit"):
            run(cfg, store, row, writer(), reviewer(cfg, proposed("proposal", summary=SUMMARY), assessed(), verdict()))
    saved, saved_job = record(store), job(store)
    prepared = json.loads(saved_job["envelope_json"])
    proposal = saved["untrusted_proposals"][0]
    assert proposal["accepted"] is True and proposal["impact_audit"] is True
    assert proposal["repair"] == {"summary": SUMMARY}
    if damage == "empty-receipts":
        saved["impact_audits"] = []
    else:
        saved.pop("impact_audits")
    with store.db:
        store.db.execute("UPDATE review_jobs SET record_json=? WHERE item_id=?", (json.dumps(saved), row["id"]))
        store.db.execute("UPDATE review_approvals SET review_record_json=? WHERE key=?",
                         (json.dumps(saved), saved["approval_key"]))
    if boundary == "cache":
        checker = reviewer(cfg)
        with pytest.raises(AnalysisError):
            run(cfg, store, row, Writer(), checker, allow_network=False)
        assert checker.calls == 0
    else:
        with pytest.raises((AnalysisError, ReviewRequired)):
            store.commit_candidate(prepared, saved["candidate"], saved_job["writer_key"], LATER,
                                   approval_key=saved["approval_key"], policy_hash=review.policy_hash(cfg))
    assert not store.stories()


@pytest.mark.parametrize("marker", [None, 2])
def test_current_job_prevents_downgrading_cached_audit_proof_at_commit(context, monkeypatch, marker):
    cfg, store = context
    row = pending(store)
    with monkeypatch.context() as scoped:
        def stop(*_args, **_kwargs):
            raise Interrupted("before commit")
        scoped.setattr(store, "commit_candidate", stop)
        with pytest.raises(Interrupted, match="before commit"):
            run(cfg, store, row, writer(), reviewer(cfg, proposed("proposal", summary=SUMMARY), assessed(), verdict()))
    saved, saved_job = record(store), job(store)
    assert saved["schema_version"] == 3 and saved["impact_audits"]
    damaged = copy.deepcopy(saved)
    damaged.pop("impact_audits")
    if marker is None:
        damaged.pop("schema_version")
    else:
        damaged["schema_version"] = marker
    with store.db:
        store.db.execute("UPDATE review_approvals SET review_record_json=? WHERE key=?",
                         (json.dumps(damaged), saved["approval_key"]))
    with pytest.raises((AnalysisError, ReviewRequired)):
        store.commit_candidate(json.loads(saved_job["envelope_json"]), saved["candidate"], saved_job["writer_key"], LATER,
                               approval_key=saved["approval_key"], policy_hash=review.policy_hash(cfg))
    assert record(store)["schema_version"] == 3 and not store.stories()


@pytest.mark.parametrize("kind", ["review", "proposal"])
def test_existing_validation_reask_then_impact_audit_uses_one_correction_slot(context, kind):
    cfg, store = context
    row = pending(store)
    checker = reviewer(cfg, inconsistent(action="hold"), proposed(kind), assessed(), verdict())
    assert run(cfg, store, row, writer(), checker)["status"] == "published"
    assert checker.calls == 4
    assert schemas(checker) == ["onionflash_review", "onionflash_review", "onionflash_impact_audit", "onionflash_review"]
    messages = payloads(checker)
    assert messages[1]["validation_error"] == review.INCONSISTENT_VERDICT
    assert "validation_error" not in messages[2] and "validation_error" not in messages[3]
    saved = saved_audit(store)
    assert saved["request_budget"]["reserved"] == 4
    assert saved["request_budget"]["validation_reask"] == {
        "trigger": 1, "attempts": [2], "response": 2, "transport_failed": False,
    }
    assert saved["impact_audits"][0]["origin"]["request"] == 2
    assert saved["impact_audits"][0]["request"] == 3
    assert saved["reviews"][-1]["request"] == 4


@pytest.mark.parametrize("waiting_proposal", [False, True])
def test_unsent_audit_admission_rollback_remains_pending_and_resumes_without_spending(context, monkeypatch, waiting_proposal):
    cfg, store = context
    row = pending(store)
    leading = [inconsistent({"summary": SUMMARY})] if waiting_proposal else []
    checker = reviewer(cfg, *leading, proposed("review"))
    clock = [0]
    checker.clock, checker.deadline = lambda: clock[0], 10
    save = review_gate._save

    def expire_after_reservation(*args, **kwargs):
        save(*args, **kwargs)
        audits = args[7].get("impact_audits", [])
        if audits and audits[-1]["status"] == "sent":
            clock[0] = 10

    with monkeypatch.context() as scoped:
        scoped.setattr(review_gate, "_save", expire_after_reservation)
        deferred = run(cfg, store, row, writer(), checker)
    assert deferred["status"] == "deferred" and deferred["budget_reached"]
    assert checker.calls == len(checker.client.requests) == 1 + len(leading)
    saved = record(store)
    assert saved["request_budget"]["reserved"] == 1 + len(leading)
    if waiting_proposal:
        assert saved["untrusted_proposals"][0]["disposition"] == "pending"
    assert saved["impact_audits"][0]["status"] == "pending"
    assert saved["impact_audits"][0]["request"] is None
    assert saved["impact_audits"][0]["result"] is saved["impact_audits"][0]["error"] is None
    resumed = reviewer(cfg, assessed(), verdict())
    assert run(cfg, store, row, Writer(), resumed)["status"] == "published"
    assert resumed.calls == 2 and schemas(resumed) == ["onionflash_impact_audit", "onionflash_review"]
    assert saved_audit(store)["request_budget"]["reserved"] == 3 + len(leading)


def test_latest_update_repair_leaves_prior_impact_outside_audit_scope(context):
    cfg, store = context
    first = pending(store)
    assert run(cfg, store, first, writer(), reviewer(cfg, verdict(), verdict()))["status"] == "published"
    revised = json.loads(first["payload"])
    revised.update(content=revised["content"] + " A later report describes a narrower observation.", updated_at=LATER)
    store.ingest(revised, LATER)
    row = dict(store.db.execute("SELECT * FROM items WHERE id=?", (first["id"],)).fetchone())
    checker = reviewer(cfg, verdict("revise", update=True, repair={"update": "The source reports a narrower observation."}),
                       verdict(update=True))
    assert run(cfg, store, row, Writer(update_analysis()), checker)["status"] == "published"
    assert checker.calls == 2 and schemas(checker) == ["onionflash_review"] * 2
    assert payloads(checker)[0]["review_scope"] == "latest_update"
    assert store.stories()[0]["why_it_matters"] == IMPACT
    assert saved_audit(store)["impact_audits"] == []


def test_literal_tag_repair_is_rejected_before_any_impact_audit(context):
    cfg, store = context
    source = item(kind="tag", title="tor-0.4.9.15", url="https://example.org/tags/0.4.9.15", content="")
    row = pending(store, source)
    checker = reviewer(cfg, verdict("revise", repair={"title": "A changed tag notice", "why_it_matters": ""}))
    assert run(cfg, store, row, Writer(tag_notice(source)), checker)["status"] == "held"
    assert checker.calls == 1 and record(store)["impact_audits"] == []
    assert record(store)["hold_code"] == "tag_repair"


@pytest.mark.parametrize("repair", [None, {"why_it_matters": "", "title": "x" * 181}])
def test_unusable_repair_does_not_spend_an_impact_audit(context, repair):
    cfg, store = context
    row = pending(store)
    checker = reviewer(cfg, verdict("revise", repair=repair))
    assert run(cfg, store, row, writer(), checker)["status"] == "held"
    assert checker.calls == 1 and record(store)["impact_audits"] == []
    assert record(store)["hold_code"] == "unusable_repair"


def test_revise_without_impact_clear_keeps_original_two_request_path(context):
    cfg, store = context
    row = pending(store)
    checker = reviewer(cfg, verdict("revise", repair={"summary": SUMMARY}), verdict())
    assert run(cfg, store, row, writer(), checker)["status"] == "published"
    assert checker.calls == 2 and schemas(checker) == ["onionflash_review"] * 2
    assert saved_audit(store)["impact_audits"] == []
    assert store.stories()[0]["why_it_matters"] == IMPACT


@pytest.mark.parametrize("first_kind", ["review", "proposal"])
@pytest.mark.parametrize("second_kind", ["review", "proposal"])
def test_unrelated_repairs_cannot_resample_the_same_impact_input(context, first_kind, second_kind):
    cfg, store = context
    first = proposed(first_kind, title="The report describes a narrower issue")
    second = proposed(second_kind, summary="The supplied source describes the same issue more precisely.")
    checker = reviewer(cfg, first, assessed("supported"), second, assessed("unsupported"), verdict())
    result = run(cfg, store, pending(store), writer(), checker)
    assert result["status"] == "held" and checker.calls == 3 and not store.stories()
    assert schemas(checker) == ["onionflash_review", "onionflash_impact_audit", "onionflash_review"]
    first_audit, blocked = record(store)["impact_audits"]
    assert first_audit["before_hash"] != blocked["before_hash"]
    assert first_audit["proposed_hash"] != blocked["proposed_hash"]
    assert first_audit["input_hash"] == blocked["input_hash"]
    assert first_audit["result"]["outcome"] == "supported"
    assert blocked["status"] == "failed" and blocked["request"] is None
    assert blocked["error"]["type"] == "RepeatedImpactAudit"
    assert record(store)["request_budget"]["reserved"] == 3
    assert record(store)["candidate"]["why_it_matters"] == IMPACT


@pytest.mark.parametrize("kind", ["review", "proposal"])
@pytest.mark.parametrize("field", ["title", "summary", "products", "confidence", "normalized-summary"])
def test_supported_veto_removes_unchanged_effective_fields_before_verification(context, kind, field):
    cfg, store = context
    original = analysis(why_it_matters=IMPACT)
    key = "summary" if field == "normalized-summary" else field
    value = original[key]
    if field == "normalized-summary":
        value = value.replace(" ", "  ")
    checker = reviewer(cfg, proposed(kind, **{key: value}), assessed("supported"), verdict())
    result = run(cfg, store, pending(store), writer(), checker)
    assert result["status"] == "published" and checker.calls == 3
    bodies = payloads(checker)
    assert bodies[2]["candidate"] == bodies[0]["candidate"]
    assert store.stories()[0]["why_it_matters"] == IMPACT
    audit = saved_audit(store)["impact_audits"][0]
    assert audit["status"] == "complete" and audit["before_hash"] == audit["effective_hash"]
    assert saved_audit(store)["reviews"][-1]["stage"] == "verification"


@pytest.mark.parametrize("kind", ["review", "proposal"])
@pytest.mark.parametrize("outcome", ["supported", "unsupported"])
def test_corrupted_impact_audit_holds_without_editing_verifying_or_reasking(context, kind, outcome):
    cfg, store = context
    row = pending(store)
    response = {**assessed(outcome), "reason": "abc" * 30}
    checker = reviewer(cfg, proposed(kind), response, verdict())
    assert run(cfg, store, row, writer(), checker)["status"] == "held"
    assert checker.calls == 2 and schemas(checker) == ["onionflash_review", "onionflash_impact_audit"]
    saved = record(store)
    audit = saved["impact_audits"][0]
    assert audit["status"] == "failed" and audit["result"] is None and audit["effective_hash"] is None
    assert audit["error"] == {"type": "AuditError", "code": "review.impact_audit"}
    assert saved["request_budget"]["reserved"] == 2 and saved["request_budget"]["validation_reask"] is None
    retained = saved.get("candidate", json.loads(job(store)["envelope_json"])["candidate"])
    assert retained["why_it_matters"] == IMPACT and not store.stories()
    assert not review_gate.approval(cfg, store, row["id"])["eligible"]


@pytest.mark.parametrize("phase", ["pending", "sent", "complete"])
def test_pending_proposal_verification_audit_resumes_without_losing_its_origin(context, monkeypatch, phase):
    cfg, store = context
    row = pending(store)
    save = review_gate._save

    def checkpoint(*args, **kwargs):
        save(*args, **kwargs)
        audits = args[7].get("impact_audits", [])
        if audits and audits[-1]["status"] == phase:
            raise Interrupted(phase)

    first = reviewer(cfg, inconsistent({"summary": SUMMARY}), proposed("review"), assessed(), verdict())
    with monkeypatch.context() as patch:
        patch.setattr(review_gate, "_save", checkpoint)
        with pytest.raises(Interrupted, match=phase):
            run(cfg, store, row, writer(), first)
    saved = record(store)
    assert saved["reviews"] == []
    assert saved["impact_audits"][0]["origin"]["request"] == 2
    next_replies = (assessed(), verdict()) if phase == "pending" else (verdict(),) if phase == "complete" else ()
    resumed = reviewer(cfg, *next_replies)
    result = run(cfg, store, row, Writer(), resumed)
    assert result["status"] == ("held" if phase == "sent" else "published")
    final = record(store) if phase == "sent" else saved_audit(store)
    assert final["untrusted_proposals"][0]["disposition"] == "checked_revise"
    assert final["reviews"][0]["request"] == 2
    assert final["request_budget"]["reserved"] == (3 if phase == "sent" else 4)
    assert resumed.calls == (2 if phase == "pending" else 1 if phase == "complete" else 0)
    if phase == "sent":
        assert not store.stories()
    else:
        assert final["reviews"][-1]["stage"] == "verification"
        assert final["reviews"][-1]["request"] == 4
        assert store.stories()[0]["why_it_matters"] == IMPACT
