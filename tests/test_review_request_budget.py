"""Untrusted edits, durable ledgers, and saved identity proofs never bypass review."""

import copy
import json

import pytest

from helpers import (
    LATER, REPAIRED, FakeLLM, Writer, add_coverage, analysis, assert_damaged_job, downgrade_job_v1,
    editorial_act, inconsistent, insert_approval, item, item_row, job, job_record, load_evaluator, patch_job,
    pause_cached_after_reset, pending, queued_row, raise_once, run_gate as run, saved_audit,
    seed_citation_job, seed_routed_followup, update_analysis, verdict, wire_reviewer,
)
from onionflash import editorial, rejection, review, review_gate
from onionflash.analyze import AnalysisError, tag_notice
from onionflash.llm import CompletionClient
from onionflash.transport import DeadlineReached, FetchError
from onionflash.util import digest

_BAD_PROPOSALS = {
    "missing-field": lambda b: {**b, "repair": {k: v for k, v in b["repair"].items() if k != "tags"}},
    "extra-field": lambda b: {**b, "repair": {**b["repair"], "unknown": "value"}},
    "bad-type": lambda b: {**b, "repair": {**b["repair"], "summary": 4}},
    "immutable": lambda b: {**b, "repair": {**b["repair"], "sources": []}},
    "null-only": lambda b: {**b, "repair": {key: None for key in review.EDITABLE}},
    "no-op": lambda _b: inconsistent({"summary": analysis()["summary"]}),
    "hold": lambda _b: inconsistent(action="hold"),
    "skip": lambda _b: inconsistent(action="skip"),
}

_CACHE_PROOF_DAMAGE = {
    None: lambda _a: None,
    "proof-shape": lambda a: a.update(approval={}),
    "proof-key": lambda a: a["approval"].update(approval_key="0" * 64),
    "proof-context": lambda a: a["approval"]["reviews"][-1].update(source_hash="0" * 64),
    "proof-candidate": lambda a: a["approval"]["reviews"][-1].update(candidate_hash="0" * 64),
    "proof-text": lambda a: a["approval"]["candidate"].update(summary="A different saved candidate."),
    "proof-policy": lambda a: a["approval"].update(policy_hash="0" * 64),
    "nested-chain": lambda a: a["approval"].update(approval=copy.deepcopy(a["approval"])),
    "job-key": lambda a: a.update(approval_key="0" * 64),
    "nonterminal": lambda _a: None,
}

_BUDGET_DAMAGE = {
    "counter-bool": lambda a: a["request_budget"].update(reserved=True),
    "counter-too-large": lambda a: a["request_budget"].update(reserved=review_gate.MAX_REVIEW_REQUESTS + 1),
    "missing-budget": lambda a: a.pop("request_budget"),
    "audit-shape": lambda a: a.update(untrusted_proposals={}),
    "after-hash": lambda a: a["untrusted_proposals"][0].update(candidate_after_hash="0" * 64),
    "context-hash": lambda a: a["untrusted_proposals"][0]["context"].update(source_hash="0" * 64),
    "accepted-flag": lambda a: a["untrusted_proposals"][0].update(accepted=False),
    "fake-checked": lambda a: a["untrusted_proposals"][0].update(disposition="checked_approve"),
    "fake-discard": lambda a: a["untrusted_proposals"][0].update(disposition="discarded_context"),
    "changed-repair": lambda a: a["untrusted_proposals"][0]["repair"].update(summary="Different saved text."),
    "wrong-stage": lambda _a: None,
    "invalid-trusted": lambda a: a.update(reviews=[{"stage": "verification", "candidate_hash": digest(a["candidate"]), "result": inconsistent()}]),
    "erase-both": lambda a: (a.pop("untrusted_proposals"), a.pop("request_budget")),
    "empty-ledgers": lambda a: (a.update(untrusted_proposals=[]), a["request_budget"].update(inconsistent_requests=[])),
}

_HANDOFF_DAMAGE = {
    "invalid-json": lambda _a, _e: None,
    "non-object": lambda _a, _e: None,
    "missing-row": lambda _a, e: e.pop("row"),
    "missing-hash": lambda _a, e: e["row"].pop("content_hash"),
    "wrong-hash": lambda _a, e: e["row"].update(content_hash="f" * 64),
    "wrong-id": lambda _a, e: e["row"].update(id="f" * 24),
    "wrong-payload": lambda _a, e: e["row"].update(
        payload=json.dumps({**json.loads(e["row"]["payload"]),
                            "content": json.loads(e["row"]["payload"])["content"] + " An invented revision."})
    ),
    "conflicting-snapshot": lambda a, e: a.update(input_row={**e["row"], "story_id": "f" * 24}),
    "binding-item": lambda _a, e: e["binding"].update(item="f" * 64),
    "missing-marker": lambda a, _e: a.pop("input_proof"),
    "boolean-marker": lambda a, _e: a.update(input_proof=True),
    "missing-input-hash": lambda a, _e: a.pop("input_hash"),
    "wrong-input-hash": lambda a, _e: a.update(input_hash="f" * 64),
}

_SCHEMA_V2_DAMAGE = {
    "downgrade-markers": lambda d: [d.pop(f) for f in ("input_proof", "request_budget", "untrusted_proposals")],
    "missing-marker": lambda d: d.pop("input_proof"),
    "missing-version": lambda d: d.pop("schema_version"),
    "boolean-version": lambda d: d.update(schema_version=True),
    "unknown-version": lambda d: d.update(schema_version=99),
    "request_budget": lambda d: d.pop("request_budget"),
    "untrusted_proposals": lambda d: d.pop("untrusted_proposals"),
}


def _pause_before_prepare(cfg, store, row, monkeypatch):
    with monkeypatch.context() as scoped:
        scoped.setattr(store, "prepare_candidate", raise_once(RuntimeError("Draft was saved before preparation")))
        with pytest.raises(RuntimeError, match="before preparation"):
            run(cfg, store, row, Writer(), wire_reviewer(cfg))
    return copy.deepcopy(job(store))


def _pause_proposal(cfg, store, row, monkeypatch, repair=None, *, leading=(), draft=None):
    original = review_gate._save

    def _crash(*args, **kwargs):
        original(*args, **kwargs)
        if args[4] == "verify" and review_gate.pending_proposal(args[7]):
            raise RuntimeError("after durable pending proposal")

    checker = wire_reviewer(cfg, *leading, inconsistent(repair))
    with monkeypatch.context() as scoped:
        scoped.setattr(review_gate, "_save", _crash)
        with pytest.raises(RuntimeError, match="durable pending"):
            run(cfg, store, row, Writer(draft), checker)
    assert checker.calls == len(leading) + 1 and job(store)["stage"] == "verify"
    return job_record(store)


def test_invalid_criteria_stay_outside_reviews_and_proposal_is_persisted_before_verification(llm_context):
    """Persist untrusted proposals in `verify` stage while keeping invalid criteria outside `reviews`."""
    cfg, store = llm_context
    row = pending(store)
    snapshots = []
    checker = wire_reviewer(cfg, inconsistent(), verdict(), before=lambda: snapshots.append(copy.deepcopy(job(store))))
    result = run(cfg, store, row, Writer(), checker)
    assert result["status"] == "published" and result["review_calls"] == checker.calls == 2
    before_verify = json.loads(snapshots[1]["record_json"])
    assert snapshots[1]["stage"] == "verify" and before_verify["candidate"]["summary"] == REPAIRED
    assert before_verify["request_budget"]["reserved"] == 2
    assert before_verify["reviews"] == [] and review_gate.pending_proposal(before_verify)
    payloads = [json.loads(req["messages"][1]["content"]) for req in checker.client.bodies]
    assert payloads[1]["candidate"]["summary"] == REPAIRED
    assert payloads[1]["packet"] == payloads[0]["packet"]
    assert set(payloads[1]) == {"candidate", "packet", "coverage_background"}
    assert checker.client.bodies[1]["messages"][0]["content"] == review.VERIFY_PROMPT
    assert "UNTRUSTED_PREVIOUS_CRITERIA_SENTINEL" not in json.dumps(checker.client.bodies)
    audit = saved_audit(store)
    assert len(audit["reviews"]) == 1 and audit["reviews"][0]["stage"] == "verification"
    assert "UNTRUSTED_PREVIOUS_CRITERIA_SENTINEL" not in json.dumps(audit)
    event = audit["untrusted_proposals"][0]
    assert event["candidate_before_hash"] == digest(payloads[0]["candidate"])
    assert event["candidate_after_hash"] == digest(payloads[1]["candidate"])
    assert event["error"] == review.INCONSISTENT_VERDICT and event["disposition"] == "checked_approve"
    assert event["repair"] == {"summary": REPAIRED} and event["accepted"]
    assert review_gate.recovery_status(audit) == {"raw_inconsistency_count": 1, "accepted_proposal_count": 1,
                                                  "unresolved_inconsistency": False}


def test_unsupported_proposal_rejected_by_fresh_verification_cannot_publish_or_be_operator_approved(llm_context):
    """Hold unsupported untrusted proposals on verification refusal and block operator approval."""
    cfg, store = llm_context
    row = pending(store)
    checker = wire_reviewer(cfg, inconsistent({"summary": "An unsupported claim about a wider incident."}),
                            verdict("hold", criterion="source_support"))
    result = run(cfg, store, row, Writer(), checker)
    assert result["status"] == "held" and checker.calls == 2 and store.stories() == []
    audit = job_record(store)
    assert audit["verified_facts"] is False
    assert audit["untrusted_proposals"][0]["disposition"] == "checked_hold"
    assert not review_gate.approval(cfg, store, row["id"])["eligible"]
    assert review_gate.recovery_status(audit)["unresolved_inconsistency"] is False


@pytest.mark.parametrize("kind", list(_BAD_PROPOSALS))
def test_nonproposals_are_never_applied_and_a_second_invalid_reply_stops(llm_context, kind):
    """Reject malformed or non-edit inconsistent replies and stop after a second invalid response."""
    cfg, store = llm_context
    row = pending(store)
    bad = _BAD_PROPOSALS[kind](inconsistent())
    checker = wire_reviewer(cfg, bad, copy.deepcopy(bad))
    with pytest.raises(review.InconsistentReview):
        run(cfg, store, row, Writer(), checker)
    assert checker.calls == 2 and store.stories() == [] and job_record(store)["reviews"] == []
    payloads = [json.loads(request["messages"][1]["content"]) for request in checker.client.bodies]
    assert payloads[1] == {**payloads[0], "validation_error": review.INCONSISTENT_VERDICT}
    event = job_record(store)["untrusted_proposals"][0]
    assert not event["accepted"] and event["disposition"] == "unusable"
    assert review_gate.recovery_status(job_record(store))["unresolved_inconsistency"]


@pytest.mark.parametrize("disposition,edits", [
    ("labels", {"confidence": "confirmed"}),
    ("literal_tag", {"title": "Changed literal tag"}),
])
def test_packet_disallowed_labels_and_literal_tag_edits_never_enter_recovery(llm_context, disposition, edits):
    """Refuse untrusted label escalations and literal tag notice edits before recovery."""
    cfg, store = llm_context
    tag_src = item(kind="tag", title="tor-0.4.9.5", content="", url="https://example.org/tags/tor-0.4.9.5")
    is_tag = disposition == "literal_tag"
    row = pending(store, tag_src if is_tag else None)
    checker = wire_reviewer(cfg, inconsistent(edits), inconsistent(edits))
    with pytest.raises(review.InconsistentReview):
        run(cfg, store, row, Writer(tag_notice(tag_src)) if is_tag else Writer(), checker)
    assert checker.calls == 2 and job_record(store)["untrusted_proposals"][0]["disposition"] == disposition
    assert store.stories() == []


@pytest.mark.parametrize("with_trusted_initial", [False, True])
def test_invalid_news_criteria_are_not_an_anchor_but_existing_trusted_disagreement_remains(llm_context, with_trusted_initial):
    """Ignore news-value criteria from invalid replies while keeping genuine prior trusted anchors."""
    cfg, store = llm_context
    row = pending(store)
    replies = ([verdict()] if with_trusted_initial else []) + [inconsistent(), verdict("skip", criterion="news_value")]
    if with_trusted_initial:
        replies.append(verdict("skip", criterion="new_information"))
    checker = wire_reviewer(cfg, *replies)
    result = run(cfg, store, row, Writer(), checker)
    assert result["status"] == ("held" if with_trusted_initial else "ignored")
    audit = saved_audit(store)
    assert len(audit["reviews"]) == (3 if with_trusted_initial else 1)
    if with_trusted_initial:
        assert audit["hold_code"] == "disagreed_news" and audit["reviews"][2]["tiebreaker"] is True
    assert store.stories() == []


def test_official_news_dispute_uses_only_the_real_fresh_verification(llm_context):
    """Base `official_not_news` holds strictly on the fresh verification pass."""
    cfg, store = llm_context
    row = pending(store, item(kind="feed", authority="official"))
    checker = wire_reviewer(cfg, inconsistent(), verdict("skip", criterion="news_value"))
    result = run(cfg, store, row, Writer(), checker)
    assert result["status"] == "held" and job_record(store)["hold_code"] == "official_not_news"
    assert job_record(store)["verified_facts"] is True
    assert len(job_record(store)["reviews"]) == 1 and job_record(store)["reviews"][0]["stage"] == "verification"


def test_second_changed_untrusted_proposal_still_needs_fresh_verification(llm_context):
    """Require another fresh verification when verification itself returns an untrusted edit."""
    cfg, store = llm_context
    row = pending(store)
    checker = wire_reviewer(cfg, inconsistent(), inconsistent({"summary": "Another changed report requiring verification."}), verdict())
    assert run(cfg, store, row, Writer(), checker)["status"] == "published"
    audit = saved_audit(store)
    assert checker.calls == 3 and len(audit["reviews"]) == 1
    assert [p["disposition"] for p in audit["untrusted_proposals"]] == ["superseded_unverified", "checked_approve"]
    assert audit["request_budget"] == {"reserved": 3, "inconsistent_requests": [1, 2], "validation_reask": None}


def test_untrusted_and_valid_repair_cycles_are_both_stopped(llm_context):
    """Stop repair loops whether proposed by untrusted recovery or validated repairs."""
    cfg, store = llm_context
    row = pending(store)
    checker = wire_reviewer(cfg, inconsistent(), inconsistent({"summary": analysis()["summary"]}), FetchError("temporary", status=500))
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), checker)
    assert job_record(store)["untrusted_proposals"][-1]["disposition"] == "repeated"
    assert review_gate.pending_proposal(job_record(store)) and store.stories() == []
    next_checker = wire_reviewer(cfg, verdict("revise", repair={"summary": analysis()["summary"]}))
    result = run(cfg, store, row, Writer(), next_checker)
    assert result["status"] == "held" and job_record(store)["hold_code"] == "repeated_repair"
    assert review_gate.recovery_status(job_record(store))["unresolved_inconsistency"] and store.stories() == []


def test_pending_proposal_survives_restart_and_bypasses_matching_cached_approval(llm_context, monkeypatch):
    """Bypass cached approvals until a persisted pending untrusted proposal is freshly verified."""
    cfg, store = llm_context
    row = pending(store)
    audit = _pause_proposal(cfg, store, row, monkeypatch)
    prepared = json.loads(job(store)["envelope_json"])
    insert_approval(store, prepared, audit["candidate"], policy=review.policy_hash(cfg))
    idle = wire_reviewer(cfg)
    assert run(cfg, store, row, Writer(), idle, allow_network=False)["status"] == "deferred"
    assert idle.calls == 0 and store.stories() == []
    assert not review_gate.approval(cfg, store, row["id"])["eligible"]
    checker = wire_reviewer(cfg, verdict())
    assert run(cfg, store, row, Writer(), checker)["status"] == "published" and checker.calls == 1
    assert checker.client.bodies[0]["messages"][0]["content"] == review.VERIFY_PROMPT
    assert saved_audit(store)["request_budget"]["reserved"] == 2


def test_pending_label_repair_cannot_borrow_an_earlier_verifications_facts(llm_context, monkeypatch):
    """Do not carry `verified_facts` across an unverified pending label repair."""
    cfg, store = llm_context
    row = pending(store)
    draft = analysis(category="release", state="merged", tags=["release"])
    audit = _pause_proposal(cfg, store, row, monkeypatch, {"category": "security", "tags": ["security"]},
                           leading=(verdict("revise", repair={"summary": "An earlier repaired summary."}), verdict()), draft=draft)
    assert review_gate._verified(audit["reviews"])
    assert audit["reviews"][-1]["candidate_hash"] != digest(audit["candidate"])
    prepared = json.loads(job(store)["envelope_json"])
    insert_approval(store, prepared, audit["candidate"], policy=review.policy_hash(cfg))
    idle = wire_reviewer(cfg)
    assert run(cfg, store, row, Writer(), idle, allow_network=False)["status"] == "deferred"
    assert idle.calls == 0 and store.stories() == []
    state = job_record(store)
    review_gate._hold(store, row, draft, job(store)["writer_key"], state, LATER, "review", "model_hold")
    assert job_record(store)["verified_facts"] is False
    assert review_gate.recovery_status(job_record(store))["unresolved_inconsistency"]
    assert not review_gate.approval(cfg, store, row["id"])["eligible"]
    with pytest.raises(ValueError):
        rejection.approve_item(cfg, store, row["id"], "0" * 64, "Try an unverified proposal", LATER)
    assert store.stories() == []


def test_partial_release_label_edit_requires_correction_and_fresh_verification(llm_context):
    """Follow a partial untrusted release-label edit with `RELEASE_ISSUE` repair and verification."""
    cfg, store = llm_context
    row = pending(store, item(kind="feed", authority="official", upstream_state=""))
    draft = analysis(category="release", state="developing", tags=["release"])
    partial = inconsistent({"title": "An opt-in capability was merged", "category": "feature", "tags": ["feature", "release"]})
    correction = verdict("revise", repair={"tags": ["feature"]}, criterion="status")
    checker = wire_reviewer(cfg, partial, verdict(), correction, verdict())
    assert run(cfg, store, row, Writer(draft), checker)["status"] == "published" and checker.calls == 4
    payloads = [json.loads(call["messages"][1]["content"]) for call in checker.client.bodies]
    assert payloads[2]["application_issue"] == review.RELEASE_ISSUE
    assert checker.client.bodies[1]["messages"][0]["content"] == review.VERIFY_PROMPT
    assert checker.client.bodies[3]["messages"][0]["content"] == review.VERIFY_PROMPT
    assert "release" in payloads[1]["candidate"]["tags"]
    assert "release" not in payloads[3]["candidate"]["tags"]
    assert "release" not in store.stories()[0]["tags"]
    assert len(saved_audit(store)["reviews"]) == 3


def test_legitimate_context_change_discards_proposal_and_preserves_budget(llm_context, monkeypatch):
    """Discard pending untrusted proposals on coverage change while retaining spent request counts."""
    cfg, store = llm_context
    row = pending(store)
    _pause_proposal(cfg, store, row, monkeypatch)
    add_coverage(store)
    checker = wire_reviewer(cfg, verdict(), verdict())
    assert run(cfg, store, row, Writer(), checker)["status"] == "published"
    first = json.loads(checker.client.bodies[0]["messages"][1]["content"])
    assert first["candidate"]["summary"] == analysis()["summary"]
    assert checker.client.bodies[0]["messages"][0]["content"] == review.SYSTEM_PROMPT + review.ROUTING_PROMPT
    audit = saved_audit(store)
    assert audit["untrusted_proposals"][0]["disposition"] == "discarded_context"
    assert audit["request_budget"]["reserved"] == 3 and checker.calls == 2


def test_a_new_source_revision_starts_from_its_new_draft_not_the_pending_proposal(llm_context, monkeypatch):
    """Start from a fresh writer draft when the upstream source item changes."""
    cfg, store = llm_context
    row = pending(store)
    _pause_proposal(cfg, store, row, monkeypatch)
    changed = json.loads(row["payload"])
    changed.update(content=changed["content"] + " A new public source detail.", updated_at=LATER)
    store.ingest(changed, LATER)
    writer = Writer(analysis(summary="A fresh summary of the revised source."))
    checker = wire_reviewer(cfg, verdict(), verdict())
    assert run(cfg, store, item_row(store, row), writer, checker)["status"] == "published"
    first = json.loads(checker.client.bodies[0]["messages"][1]["content"])
    assert first["candidate"]["summary"] == "A fresh summary of the revised source."
    assert checker.client.bodies[0]["messages"][0]["content"] == review.SYSTEM_PROMPT
    assert saved_audit(store)["request_budget"]["reserved"] == 2
    assert not saved_audit(store).get("untrusted_proposals")


def test_verified_recovery_receipt_resumes_after_commit_crash_without_another_request(llm_context, monkeypatch):
    """Resume a verified recovery receipt across a commit crash without spending another request."""
    cfg, store = llm_context
    row = pending(store)
    checker = wire_reviewer(cfg, inconsistent(), verdict())
    with monkeypatch.context() as scoped:
        scoped.setattr(store, "commit_candidate", raise_once(RuntimeError("before commit")))
        with pytest.raises(RuntimeError, match="before commit"):
            run(cfg, store, row, Writer(), checker)
    assert job(store)["stage"] == "approved" and not review_gate.proposal_needs_check(job_record(store))
    idle = wire_reviewer(cfg)
    result = run(cfg, store, row, Writer(), idle, allow_network=False)
    assert result["status"] == "published" and result["cache_hit"] and idle.calls == 0
    assert saved_audit(store)["request_budget"]["reserved"] == 2


@pytest.mark.parametrize("damage", list(_CACHE_PROOF_DAMAGE))
def test_terminal_cache_hit_after_reset_resumes_only_with_exact_nested_proof(llm_context, monkeypatch, damage):
    """Require an intact nested `approval` proof when resuming a cached decision after reset."""
    cfg, store = llm_context
    row = pending(store)
    audit = pause_cached_after_reset(cfg, store, row, monkeypatch)
    _CACHE_PROOF_DAMAGE[damage](audit)
    patch_job(store, row, record=audit, stage="verify" if damage == "nonterminal" else None)
    if damage:
        assert_damaged_job(cfg, store, row, allow_network=False)
        assert store.stories() == []
    else:
        idle = wire_reviewer(cfg)
        result = run(cfg, store, row, Writer(), idle, allow_network=False)
        assert result["status"] == "published" and result["cache_hit"] and idle.calls == 0


def test_nested_proof_without_its_matching_receipt_cannot_publish(llm_context, monkeypatch):
    """Defer when `review_approvals` lacks the receipt referenced by a nested approval proof."""
    cfg, store = llm_context
    row = pending(store)
    pause_cached_after_reset(cfg, store, row, monkeypatch)
    with store.db:
        store.db.execute("DELETE FROM review_approvals")
    idle = wire_reviewer(cfg)
    result = run(cfg, store, row, Writer(), idle, allow_network=False)
    assert result["status"] == "deferred" and not result["cache_hit"]
    assert idle.calls == 0 and store.stories() == []


@pytest.mark.parametrize("damage", list(_BUDGET_DAMAGE))
def test_saved_budget_or_proposal_corruption_fails_before_model_or_cache(llm_context, monkeypatch, damage):
    """Fail with `app.damaged_job` when saved budget counters or proposal records are tampered with."""
    cfg, store = llm_context
    row = pending(store)
    audit = _pause_proposal(cfg, store, row, monkeypatch)
    prepared = json.loads(job(store)["envelope_json"])
    insert_approval(store, prepared, audit["candidate"], policy=review.policy_hash(cfg))
    _BUDGET_DAMAGE[damage](audit)
    patch_job(store, row, record=audit, stage="approved" if damage == "wrong-stage" else None)
    assert_damaged_job(cfg, store, row, replies=(verdict(),))
    assert store.stories() == []


@pytest.mark.parametrize("mode", ["proposals", "fallbacks"])
def test_request_cap_counts_all_invalid_proposals_and_fallbacks(llm_context, mode):
    """Count every invalid untrusted proposal and HTTP fallback attempt against the `MAX_REVIEW_REQUESTS` cap."""
    cfg, store = llm_context
    row = pending(store)
    cap = review_gate.MAX_REVIEW_REQUESTS
    if mode == "proposals":
        checker = wire_reviewer(cfg, *(inconsistent({"summary": f"Different unverified proposal {n}."}) for n in range(cap)))
    else:
        cfg["llm"]["fallback_base_urls"] = [f"https://fallback{n}.example/v1" for n in range(cap + 2)]
        checker = wire_reviewer(cfg, *(FetchError("unavailable", status=500) for _ in range(cap + 3)))
    with pytest.raises(review.ReviewLimitReached):
        run(cfg, store, row, Writer(), checker)
    assert checker.calls == len(checker.client.requests) == cap and store.stories() == []
    if mode == "proposals":
        assert len(job_record(store)["untrusted_proposals"]) == cap
        assert job_record(store)["request_budget"]["reserved"] == cap and job_record(store)["reviews"] == []
        assert review_gate.recovery_status(job_record(store))["unresolved_inconsistency"]


def test_local_failures_and_unsent_deadline_do_not_spend_requests(llm_context, monkeypatch):
    """Leave `reserved` at zero on missing credentials or unsent `DeadlineReached` errors."""
    cfg, store = llm_context
    row = pending(store)
    checker = wire_reviewer(cfg, DeadlineReached())
    monkeypatch.delenv("REVIEW_TEST_KEY")
    with pytest.raises(AnalysisError, match="credential"):
        run(cfg, store, row, Writer(), checker)
    assert checker.calls == 0 and job_record(store)["request_budget"]["reserved"] == 0
    monkeypatch.setenv("REVIEW_TEST_KEY", "synthetic-fixture-value")
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), checker)
    assert checker.calls == 0 and job_record(store)["request_budget"]["reserved"] == 0
    assert job_record(store)["reviews"] == [] and not job_record(store).get("untrusted_proposals")


@pytest.mark.parametrize("replies,error,unresolved,expected,raw_count", [
    ([inconsistent(), verdict()], None, False, "approve", 1),
    ([inconsistent({}), inconsistent({})], "InconsistentReview", True, None, 2),
    ([inconsistent(), verdict("hold", criterion="source_support")], None, False, "hold", 1),
    ([inconsistent(), verdict("revise", repair={"summary": "ORIGINAL"})], None, True, "hold", 1),
])
def test_evaluator_uses_same_recovery_and_separates_raw_errors_from_terminal_outcomes(
        llm_context, tmp_path, monkeypatch, replies, error, unresolved, expected, raw_count):
    """Exercise `evaluate_review` recovery accounting across resolved and unresolved inconsistencies."""
    cfg, _ = llm_context
    module = load_evaluator()
    raw = json.loads((module.Path(module.__file__).parent / "review_cases.json").read_text())
    case = next(c for c in module.expand(raw) if c["id"] == "bastet-corrected")
    replies = copy.deepcopy(replies)
    if replies[-1].get("repair") and replies[-1]["repair"].get("summary") == "ORIGINAL":
        replies[-1]["repair"]["summary"] = case["candidate"]["summary"]
    client = FakeLLM(*replies)
    monkeypatch.setattr("onionflash.llm.HttpClient", lambda *a, **kw: client)
    path = tmp_path / "evaluation.jsonl"
    result = module.evaluate(cfg, [case], path)
    found = json.loads(path.read_text().splitlines()[0])
    assert found["review_request_count"] == len(client.requests) == len(replies)
    assert found.get("error") == error and result["errors"] == bool(error)
    assert found["raw_inconsistency_count"] == raw_count and result["raw_inconsistencies"] == raw_count
    assert found["unresolved_inconsistency"] is unresolved
    assert result["unresolved_inconsistencies"] == int(unresolved)
    assert found.get("final_verdict") == expected
    if expected != "approve":
        assert found.get("published_candidate") is None
    assert all(entry["result"]["criteria"]["source_support"]["reason"] != "UNTRUSTED_PREVIOUS_CRITERIA_SENTINEL"
               for entry in found["reviews"])


@pytest.mark.parametrize("transition", ["routed", "locked", "unlocked"])
@pytest.mark.parametrize("damage", list(_HANDOFF_DAMAGE))
def test_corrupt_handoff_identity_fails_before_drafting_or_spending(llm_context, transition, damage):
    """Fail with `app.damaged_job` before drafting or spending when handoff identity is corrupted."""
    cfg, store = llm_context
    target, incoming, row, _ = seed_routed_followup(cfg, store, fallbacks=4)
    assert job_record(store)["request_budget"]["reserved"] == 6
    if transition != "routed":
        editorial_act(editorial.correct, store, target["id"], {"priority": "normal"}, reason="Inspect this account.")
        assert run(cfg, store, queued_row(store, row), Writer(update_analysis()), wire_reviewer(cfg))["status"] == "locked"
        if transition == "unlocked":
            editorial_act(editorial.unlock, store, target["id"], reason="Resume this account.")
        else:
            with store.db:
                store.db.execute("UPDATE items SET status='pending' WHERE id=?", (row["id"],))
    audit = job_record(store)
    envelope = json.loads(job(store)["envelope_json"])
    assert audit["input_proof"] == 1 and "input_row" not in audit
    _HANDOFF_DAMAGE[damage](audit, envelope)
    encoded = "{" if damage == "invalid-json" else "[]" if damage == "non-object" else audit
    patch_job(store, row, record=encoded, envelope=envelope)
    assert_damaged_job(cfg, store, queued_row(store, row), draft=update_analysis(update=incoming["content"]), match="damaged")
    assert not store.stories()[0].get("updates")


@pytest.mark.parametrize("change", ["source", "policy", "request-policy"])
def test_coherent_new_source_or_policy_still_starts_a_new_review(llm_context, monkeypatch, change):
    """Allow coherent new source content or review policy changes to start a fresh 2-call review."""
    cfg, store = llm_context
    _, incoming, row, _ = seed_routed_followup(cfg, store, fallbacks=4)
    if change == "source":
        incoming = {**incoming, "content": incoming["content"] + " A later measurement is also available.", "updated_at": LATER}
        assert store.ingest(incoming, LATER)
    elif change == "policy":
        cfg["review"]["model"] = "another-review-model"
    else:
        monkeypatch.setitem(CompletionClient.REQUEST_POLICY, "deadline_refund", "another-contract")
    writer = Writer(update_analysis(update=incoming["content"], evidence=[incoming["content"]]))
    checker = wire_reviewer(cfg, verdict(update=True), verdict(update=True))
    assert run(cfg, store, queued_row(store, row), writer, checker)["status"] == "published"
    assert len(writer.calls) == 1 and checker.calls == 2
    assert saved_audit(store)["request_budget"]["reserved"] == 2


def test_new_transport_policy_does_not_erase_corrupt_old_policy_evidence(llm_context, monkeypatch):
    """Fail closed when saved review entries contain mismatched policy hashes even across policy updates."""
    cfg, store = llm_context
    _, _, row, _ = seed_routed_followup(cfg, store, fallbacks=4)
    audit = job_record(store)
    audit["reviews"][0]["policy_hash"] = "f" * 64
    patch_job(store, row, record=audit)
    monkeypatch.setitem(CompletionClient.REQUEST_POLICY, "deadline_refund", "another-contract")
    assert_damaged_job(cfg, store, queued_row(store, row), draft=update_analysis(), match="damaged")


def test_corrupt_job_is_not_silently_erased_by_a_citation_transition(llm_context):
    """Refuse to erase a corrupted `review_jobs` row during a deterministic citation transition."""
    cfg, store = llm_context
    _, row = seed_citation_job(cfg, store)
    patch_job(store, row, record="{")
    assert_damaged_job(cfg, store, row, match="damaged")


@pytest.mark.parametrize("retained", ["review", "proposal", "cached-header", "cached-review", "cached-proposal"])
def test_outer_policy_spoof_cannot_hide_retained_policy_evidence(llm_context, monkeypatch, retained):
    """Detect outer `policy_hash` spoofing when inner review, proposal, or cached proofs disagree."""
    cfg, store = llm_context
    if retained == "review":
        _, _, row, _ = seed_routed_followup(cfg, store, fallbacks=4)
    else:
        row = pending(store)
        if retained == "proposal":
            _pause_proposal(cfg, store, row, monkeypatch)
        else:
            if retained == "cached-proposal":
                with pytest.raises(AnalysisError):
                    run(cfg, store, row, Writer(), wire_reviewer(cfg, inconsistent({}), FetchError("temporary", status=500)))
            pause_cached_after_reset(cfg, store, row, monkeypatch)
    audit = job_record(store)
    authentic, spoofed = audit["policy_hash"], "e" * 64
    assert authentic != spoofed
    audit["policy_hash"] = spoofed
    if retained in {"cached-review", "cached-proposal"}:
        audit["approval"]["policy_hash"] = spoofed
        if retained == "cached-proposal":
            for entry in audit["approval"]["reviews"]:
                entry["policy_hash"] = spoofed
            assert audit["approval"]["untrusted_proposals"][0]["context"]["policy_hash"] == authentic
    patch_job(store, row, policy_hash=spoofed, record=audit)
    assert_damaged_job(cfg, store, queued_row(store, row), draft=update_analysis(), match="damaged")


def test_genuine_policy_change_accepts_coherent_nested_old_proof(llm_context, monkeypatch):
    """Accept a coherent nested old-policy proof and re-review cleanly after a genuine policy change."""
    cfg, store = llm_context
    row = pending(store)
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), wire_reviewer(cfg, inconsistent({}), FetchError("temporary", status=500)))
    pause_cached_after_reset(cfg, store, row, monkeypatch)
    cfg["review"]["model"] = "another-review-policy"
    writer, checker = Writer(), wire_reviewer(cfg, verdict(), verdict())
    assert run(cfg, store, row, writer, checker)["status"] == "published"
    assert not writer.calls and checker.calls == 2
    assert saved_audit(store)["request_budget"]["reserved"] == 2


def test_new_jobs_keep_one_source_snapshot_in_the_active_owner(llm_context, monkeypatch):
    """Store `input_row` on un-prepared drafts and move it solely into `envelope_json` once prepared."""
    cfg, store = llm_context
    row = pending(store)
    drafted = _pause_before_prepare(cfg, store, row, monkeypatch)
    draft_record = json.loads(drafted["record_json"])
    assert drafted["envelope_json"] is None
    assert draft_record["schema_version"] == review_gate.REVIEW_STATE_VERSION == 2
    assert draft_record["input_proof"] == 1 and draft_record["input_row"] == row
    assert draft_record["input_hash"] == row["content_hash"]
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), wire_reviewer(cfg, FetchError("Temporary error", status=500)))
    prepared = job(store)
    assert job_record(store)["input_proof"] == 1 and "input_row" not in job_record(store)
    assert json.loads(prepared["envelope_json"])["row"] == row
    assert job_record(store)["request_budget"]["reserved"] == 1


@pytest.mark.parametrize("legacy", ["compact", "full"])
def test_legacy_source_proof_is_validated_before_policy_reset(llm_context, legacy):
    """Validate schema-v1 compact and full legacy source proofs before upgrading on policy reset."""
    cfg, store = llm_context
    row = pending(store)
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), wire_reviewer(cfg, FetchError("Temporary error", status=500)))
    downgrade_job_v1(store, row, policy_hash=digest(["legacy review policy"]), full=(legacy == "full"))
    writer, checker = Writer(), wire_reviewer(cfg, verdict(), verdict())
    assert run(cfg, store, row, writer, checker)["status"] == "published"
    assert not writer.calls and checker.calls == 2
    final = saved_audit(store)
    assert final["input_proof"] == 1 and final["input_hash"] == row["content_hash"]
    assert "input_row" not in final and final["request_budget"]["reserved"] == 2


def test_compact_draft_without_source_proof_requires_explicit_retry(llm_context, monkeypatch):
    """Require explicit `reset_review_work` when a legacy compact draft lacks `input_row`."""
    cfg, store = llm_context
    row = pending(store)
    _pause_before_prepare(cfg, store, row, monkeypatch)
    before = downgrade_job_v1(store, row, policy_hash=digest(["legacy draft policy"]))
    writer, checker = Writer(), wire_reviewer(cfg)
    with pytest.raises(AnalysisError, match="explicit retry") as error:
        run(cfg, store, row, writer, checker)
    assert error.value.code == "app.source_proof_unavailable"
    assert not writer.calls and checker.calls == 0 and job(store) == before
    with store.db:
        review_gate.reset_review_work(store, row["id"])
    assert job_record(store)["input_row"] == row and job_record(store)["input_proof"] == 1
    assert run(cfg, store, row, Writer(), wire_reviewer(cfg, verdict(), verdict()))["status"] == "published"


@pytest.mark.parametrize("phase,damage,policy_change", [
    ("prepared", "downgrade-markers", False),
    ("prepared", "downgrade-markers", True),
    ("draft", "missing-marker", False),
    ("draft", "missing-marker", True),
    ("prepared", "missing-version", True),
    ("prepared", "boolean-version", True),
    ("prepared", "unknown-version", True),
    ("prepared", "request_budget", True),
    ("prepared", "untrusted_proposals", True),
])
def test_schema_v2_marker_and_ledger_corruption_fails_closed(llm_context, monkeypatch, phase, damage, policy_change):
    """Fail with `app.damaged_job` when v2 schema markers or ledgers are stripped or invalid."""
    cfg, store = llm_context
    row = pending(store)
    if phase == "draft":
        _pause_before_prepare(cfg, store, row, monkeypatch)
    else:
        with pytest.raises(AnalysisError):
            run(cfg, store, row, Writer(), wire_reviewer(cfg, FetchError("Temporary error", status=500)))
    damaged = job_record(store)
    _SCHEMA_V2_DAMAGE[damage](damaged)
    patch_job(store, row, record=damaged)
    if policy_change:
        cfg["review"]["model"] = "changed-review-policy"
    assert_damaged_job(cfg, store, row)


def test_saved_job_validates_prepared_at_and_reset_review_work_guards_draft_and_revision(llm_context, monkeypatch):
    """Reject corrupt `prepared_at` in `_saved_job` and drop stale or malformed drafts in `reset_review_work`."""
    cfg, store = llm_context
    row = pending(store)
    _pause_before_prepare(cfg, store, row, monkeypatch)
    with store.db:
        store.db.execute("UPDATE review_jobs SET prepared_at='not-a-timestamp' WHERE item_id=?", (row["id"],))
    assert_damaged_job(cfg, store, row)

    row_empty = pending(store, item(url="https://example.org/empty-draft"))
    _pause_before_prepare(cfg, store, row_empty, monkeypatch)
    with store.db:
        store.db.execute("UPDATE review_jobs SET draft_json='{}' WHERE item_id=?", (row_empty["id"],))
        review_gate.reset_review_work(store, row_empty["id"])
    assert job(store, row_empty) is None

    row_corrupt_rec = pending(store, item(url="https://example.org/corrupt-rec"))
    _pause_before_prepare(cfg, store, row_corrupt_rec, monkeypatch)
    with store.db:
        store.db.execute("UPDATE review_jobs SET record_json='{' WHERE item_id=?", (row_corrupt_rec["id"],))
        review_gate.reset_review_work(store, row_corrupt_rec["id"])
    assert job(store, row_corrupt_rec) is not None and job_record(store, row_corrupt_rec)["input_hash"] == row_corrupt_rec["content_hash"]

    for idx, bad_hash in enumerate(([], {}, "not-a-sha256")):
        row_bad_hash = pending(store, item(url=f"https://example.org/bad-input-hash-{idx}"))
        _pause_before_prepare(cfg, store, row_bad_hash, monkeypatch)
        damaged_rec = {**job_record(store, row_bad_hash), "input_hash": bad_hash}
        patch_job(store, row_bad_hash, record=damaged_rec)
        with store.db:
            review_gate.reset_review_work(store, row_bad_hash["id"])
        assert job(store, row_bad_hash) is None

    row_valid_hash = pending(store, item(url="https://example.org/valid-input-hash"))
    _pause_before_prepare(cfg, store, row_valid_hash, monkeypatch)
    with store.db:
        review_gate.reset_review_work(store, row_valid_hash["id"])
    assert job(store, row_valid_hash) is not None and job_record(store, row_valid_hash)["input_hash"] == row_valid_hash["content_hash"]

    target, incoming, routed_row, _ = seed_routed_followup(cfg, store)
    assert run(cfg, store, queued_row(store, routed_row), Writer(update_analysis()), wire_reviewer(cfg, verdict("hold", update=True)))["status"] == "held"
    revised_incoming = {**incoming, "content": "Completely revised follow-up report.", "updated_at": LATER}
    assert store.ingest(revised_incoming, LATER) is True
    editorial_act(editorial.correct, store, target["id"], {"priority": "normal"}, reason="Lock target story.")
    with store.db:
        review_gate.reset_review_work(store, routed_row["id"])
    assert job(store, routed_row) is None
