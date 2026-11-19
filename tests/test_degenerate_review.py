"""Corrupted reasons cannot authorize publication, edits, or a trusted rejection."""
import copy
import json

import pytest

from helpers import Writer, job, pending, run_gate as run, verdict
from onionflash import decisions, review, review_gate
from onionflash.analyze import AnalysisError
from onionflash.transport import DeadlineReached, FetchError
from test_review_request_budget import context, inconsistent, record, reviewer, saved_audit
from test_review_scope_budget import update_case


def corrupt(action="approve", *, update=False):
    reply = verdict(action, criterion="news_value" if action == "skip" else "source_support",
                    repair={"update" if update else "summary": "An untrusted replacement changes the report."}
                    if action == "revise" else None, update=update)
    for name in ("source_support", "actor_and_action"):
        reply["criteria"][name]["reason"] = "αβγ" * 70
    return reply


@pytest.mark.parametrize("action", ["approve", "skip", "revise"])
def test_corrupted_verdict_is_reasked_without_trusting_edits_or_rejection(context, action):
    cfg, store = context
    row = pending(store)
    checker = reviewer(cfg, corrupt(action), verdict(), verdict())
    assert run(cfg, store, row, Writer(), checker)["status"] == "published"
    audit = saved_audit(store)
    bodies = [json.loads(r["messages"][1]["content"]) for r in checker.client.requests]
    assert checker.calls == 3
    assert bodies[1] == {**bodies[0], "validation_error": review.DEGENERATE_REASONS}
    assert bodies[2] == bodies[0]
    assert "untrusted replacement" not in json.dumps(bodies)
    assert [r["request"] for r in audit["reviews"]] == [2, 3]
    event = audit["untrusted_proposals"][0]
    assert event["error"] == review.DEGENERATE_REASONS
    assert event["repair"] is None and event["candidate_after_hash"] is None
    assert event["changed_fields"] == [] and event["accepted"] is False
    assert event["reask_trigger"] is True
    assert review_gate.recovery_status(audit) == {
        "raw_inconsistency_count": 0, "raw_degenerate_count": 1, "raw_attribution_count": 0, "accepted_proposal_count": 0,
        "unresolved_inconsistency": False, "unresolved_degenerate": False, "unresolved_attribution": False}


def test_corrupted_approval_cannot_anchor_disagreement_with_corrective_skip(context):
    cfg, store = context
    checker = reviewer(cfg, corrupt(), verdict("skip", criterion="news_value"))
    assert run(cfg, store, pending(store), Writer(), checker)["status"] == "ignored"
    audit = saved_audit(store)
    assert checker.calls == 2 and len(audit["reviews"]) == 1 and not store.stories()


def test_corrupted_verification_preserves_genuine_prior_disagreement(context):
    cfg, store = context
    checker = reviewer(cfg, verdict(), corrupt(), verdict("skip", criterion="news_value"))
    assert run(cfg, store, pending(store), Writer(), checker)["status"] == "held"
    audit = saved_audit(store)
    assert audit["hold_code"] == "disagreed_news" and checker.calls == 3
    assert len(audit["reviews"]) == 2 and audit["reviews"][-1]["stage"] == "verification"


def test_second_corrupted_reply_is_terminal_and_resuming_spends_nothing(context):
    cfg, store = context
    row = pending(store)
    checker = reviewer(cfg, corrupt("revise"), corrupt("skip"))
    with pytest.raises(review.DegenerateReview) as error:
        run(cfg, store, row, Writer(), checker)
    assert error.value.code == "review.degenerate_reasons"
    assert "failed." + error.value.code in decisions.CODES
    audit = record(store)
    assert checker.calls == 2 and audit["request_budget"]["validation_reask"]["response"] == 2
    assert review_gate.recovery_status(audit)["raw_degenerate_count"] == 2
    resumed = reviewer(cfg, verdict(), verdict())
    with pytest.raises(review.DegenerateReview):
        run(cfg, store, row, Writer(), resumed)
    assert resumed.calls == 0 and record(store) == audit and not store.stories()


@pytest.mark.parametrize("first,second,error_type", [
    (corrupt(), inconsistent({}), review.InconsistentReview),
    (inconsistent({}), corrupt(), review.DegenerateReview),
])
def test_different_validation_errors_share_one_correction_slot(context, first, second, error_type):
    cfg, store = context
    row = pending(store)
    checker = reviewer(cfg, first, second)
    with pytest.raises(error_type):
        run(cfg, store, row, Writer(), checker)
    audit = record(store)
    assert checker.calls == 2 and audit["request_budget"]["validation_reask"]["attempts"] == [2]
    status = review_gate.recovery_status(audit)
    assert status["raw_inconsistency_count"] == status["raw_degenerate_count"] == 1
    resumed = reviewer(cfg, verdict(), verdict())
    with pytest.raises(error_type):
        run(cfg, store, row, Writer(), resumed)
    assert resumed.calls == 0


@pytest.mark.parametrize("failure", [FetchError("temporary", status=500), DeadlineReached()])
def test_corruption_correction_transport_resume_preserves_spending_and_fixed_feedback(context, failure):
    cfg, store = context
    row = pending(store)
    first = reviewer(cfg, corrupt(), failure)
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), first)
    before = record(store)
    unsent = isinstance(failure, DeadlineReached)
    assert before["request_budget"]["reserved"] == (1 if unsent else 2)
    second = reviewer(cfg, verdict(), verdict())
    assert run(cfg, store, row, Writer(), second)["status"] == "published"
    audit = saved_audit(store)
    assert audit["request_budget"]["reserved"] == (3 if unsent else 4)
    assert audit["request_budget"]["validation_reask"]["attempts"] == ([2] if unsent else [2, 3])
    body = json.loads(second.client.requests[0]["messages"][1]["content"])
    assert body["validation_error"] == review.DEGENERATE_REASONS


def test_corruption_correction_fallbacks_cannot_exceed_shared_cap(context):
    cfg, store = context
    cfg["llm"]["fallback_base_urls"] = [f"https://fallback-{n}.example/v1" for n in range(8)]
    checker = reviewer(cfg, corrupt(), *[FetchError("temporary", status=500) for _ in range(8)])
    with pytest.raises(review.ReviewLimitReached):
        run(cfg, store, pending(store), Writer(), checker)
    audit = record(store)
    assert checker.calls == audit["request_budget"]["reserved"] == 7
    assert audit["request_budget"]["validation_reask"]["attempts"] == [2, 3, 4, 5, 6, 7]
    assert not audit["reviews"] and not store.stories()


def test_last_slot_corruption_correction_cannot_skip_fresh_verification(context):
    cfg, store = context
    cfg["llm"]["fallback_base_urls"] = [f"https://fallback-{n}.example/v1" for n in range(5)]
    checker = reviewer(cfg, *[FetchError("temporary", status=500) for _ in range(5)], corrupt(), verdict())
    with pytest.raises(review.ReviewLimitReached):
        run(cfg, store, pending(store), Writer(), checker)
    audit = record(store)
    assert checker.calls == 7 and audit["request_budget"]["validation_reask"]["response"] == 7
    assert len(audit["reviews"]) == 1 and audit["reviews"][0]["stage"] == "review"
    assert not store.stories()


def test_unknown_inflight_corruption_correction_is_not_reissued(context, monkeypatch):
    cfg, store = context
    row = pending(store)
    original = review_gate._save
    def interrupted(*args, **kwargs):
        original(*args, **kwargs)
        slot = args[7]["request_budget"]["validation_reask"]
        if slot and slot["attempts"] and slot["response"] is None:
            raise RuntimeError("after reservation")
    checker = reviewer(cfg, corrupt(), verdict())
    with monkeypatch.context() as scoped:
        scoped.setattr(review_gate, "_save", interrupted)
        with pytest.raises(RuntimeError, match="after reservation"):
            run(cfg, store, row, Writer(), checker)
    resumed = reviewer(cfg, verdict(), verdict())
    with pytest.raises(review.ReviewError, match="Interrupted validation correction"):
        run(cfg, store, row, Writer(), resumed)
    assert checker.calls == 1 and resumed.calls == 0 and record(store)["request_budget"]["reserved"] == 2


def test_update_corruption_recovery_keeps_prior_text_and_exact_current_scope(context):
    cfg, _ = context
    case, prepared = update_case()
    original = review.personal_attribution.normalize(case["candidate"], update=True)
    prepared = {**prepared, "candidate": original}
    audit = {"candidate": original, "reviews": [], "policy_hash": review.policy_hash(cfg),
             **review_gate.initial_review_state()}
    requests = review_gate.ReviewRequests(audit)
    checker = reviewer(cfg, corrupt("revise", update=True), verdict(update=True), verdict(update=True))
    stage, candidate = review_gate.advance_review(checker, "review", original, prepared, audit, requests)
    assert stage == "verify" and candidate == original and checker.calls == 2
    action, candidate = review_gate.advance_review(checker, stage, candidate, prepared, audit, requests)
    assert action == "approve" and candidate == original and checker.calls == 3
    bodies = [json.loads(r["messages"][1]["content"]) for r in checker.client.requests]
    assert bodies[1] == {**bodies[0], "validation_error": review.DEGENERATE_REASONS}
    assert all(body["candidate"] == bodies[0]["candidate"] for body in bodies)
    assert all(body["review_scope"] == "latest_update" for body in bodies)


def test_old_policy_schema_two_corrupted_reviews_are_readable_but_never_reused(context, monkeypatch):
    cfg, store = context
    row = pending(store)
    old = reviewer(cfg, corrupt(), FetchError("temporary", status=500))
    with monkeypatch.context() as scoped:
        scoped.setattr(review, "REVIEW_VERSION", "onionflash-review-15")
        scoped.setattr(review, "_repetitive_reason", lambda _: False)
        with pytest.raises(AnalysisError):
            run(cfg, store, row, Writer(), old)
    old_record = record(store)
    assert old_record["schema_version"] == 2 and len(old_record["reviews"]) == 1
    assert set(old_record["request_budget"]) == {"reserved", "inconsistent_requests", "validation_reask"}
    fresh = reviewer(cfg, verdict(), verdict())
    assert run(cfg, store, row, Writer(), fresh)["status"] == "published"
    audit = saved_audit(store)
    assert fresh.calls == 2 and len(audit["reviews"]) == 2
    assert audit["policy_hash"] != old_record["policy_hash"]
    assert all(entry["result"] != old_record["reviews"][0]["result"] for entry in audit["reviews"])


@pytest.mark.parametrize("damage", ["accepted", "repair", "changed_fields", "error"])
def test_corruption_event_cannot_be_promoted_to_a_proposal_on_resume(context, damage):
    cfg, store = context
    row = pending(store)
    checker = reviewer(cfg, corrupt(), FetchError("temporary", status=500))
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), checker)
    audit = record(store)
    event = audit["untrusted_proposals"][0]
    event[damage] = {"accepted": True, "repair": {"summary": "Changed report."},
                     "changed_fields": ["summary"], "error": "arbitrary feedback"}[damage]
    store.db.execute("UPDATE review_jobs SET record_json=?", (json.dumps(audit),))
    store.db.commit()
    resumed = reviewer(cfg, verdict(), verdict())
    with pytest.raises(AnalysisError, match="damaged"):
        run(cfg, store, row, Writer(), resumed)
    assert resumed.calls == 0 and not store.stories()


def test_language_quotes_and_repeated_criterion_words_are_not_corruption(context):
    cfg, store = context
    reply = verdict()
    reply["criteria"]["source_support"]["reason"] = "引用された報告では、変更の対象と条件が明示されており、要約はその範囲を保っています。"
    reply["criteria"]["actor_and_action"]["reason"] = "Le rapport attribue précisément les observations à leur auteur et conserve les conditions annoncées."
    # One long quoted fragment is not evidence of a response-wide generation loop.
    reply["criteria"]["technical_details"]["reason"] = 'The source contains the literal test input "' + "abc" * 40 + '".'
    checker = reviewer(cfg, reply, verdict())
    assert run(cfg, store, pending(store), Writer(), checker)["status"] == "published"
    assert checker.calls == 2 and not saved_audit(store)["untrusted_proposals"]


@pytest.mark.parametrize("reason", ["abc" * 20, "abc" * 22 + " The source states the conditions and scope, and the summary preserves both without adding claims."])
def test_short_or_non_dominating_repetition_is_not_rejected(context, reason):
    cfg, store = context
    reply = verdict()
    for name in ("source_support", "actor_and_action"):
        reply["criteria"][name]["reason"] = reason
    checker = reviewer(cfg, reply, verdict())
    assert run(cfg, store, pending(store), Writer(), checker)["status"] == "published"
    assert checker.calls == 2


def test_repetition_policy_is_bound_to_review_cache_identity(context, monkeypatch):
    cfg, _ = context
    old = review.policy_hash(cfg)
    monkeypatch.setitem(review.REASON_REPETITION_POLICY, "criteria", 3)
    assert review.policy_hash(cfg) != old


@pytest.mark.parametrize("reason,expected", [
    ("a" * 32 + "|" + "b" * 32, True),  # 64 covered characters; neither span is long enough alone.
    ("a" * 31 + "|" + "b" * 32, False),  # 63 covered characters.
    ("abc" * 8 + "/" + "def" * 8 + "/" + "ghi" * 8, True),
    ("abc" * 7 + "/" + "def" * 7 + "/" + "ghi" * 7 + "/" + "jkl" * 7, False),
    ("a" * 33 + "|" + "b" * 33 + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!?.,:;_", True),  # 66 / 110.
    ("a" * 33 + "|" + "b" * 33 + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!?.,:;_-", False),  # 66 / 111.
    ("ab" * 32 + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!?", False),
    ("ab" * 40 + "Distinct conditions.", True),
    ("abcdefghijklmnopqrstuvwx" * 8, True),
    ("abcdefghijklmnopqrstuvwxy" * 8, False),
    ("The source repeats a short quoted input: abcabcabcabc. The summary preserves its conditions.", False),
    ("観測結果を報告した人物と、ソースに記載された条件および対象範囲を正確に保持しています。", False),
])
def test_repeated_span_coverage_boundaries_and_overlap(reason, expected):
    assert review._repetitive_reason(reason) is expected


@pytest.mark.parametrize("affected", [1, 2])
def test_fragmented_reasons_require_multiple_criteria_and_use_existing_correction(context, affected):
    cfg, store = context
    reply = verdict()
    for criterion in ("source_support", "actor_and_action")[:affected]:
        reply["criteria"][criterion]["reason"] = "abc" * 12 + "|" + "xyz" * 12
    checker = reviewer(cfg, reply, verdict(), verdict())
    assert run(cfg, store, pending(store), Writer(), checker)["status"] == "published"
    audit = saved_audit(store)
    assert checker.calls == (3 if affected == 2 else 2)
    assert len(audit["untrusted_proposals"]) == (1 if affected == 2 else 0)
    if affected == 2:
        assert audit["request_budget"]["validation_reask"]["attempts"] == [2]
        assert audit["request_budget"]["reserved"] == 3
        assert review_gate.recovery_status(audit)["raw_degenerate_count"] == 1


def test_span_aggregation_mode_is_bound_to_review_policy(context, monkeypatch):
    cfg, _ = context
    current = review.policy_hash(cfg)
    monkeypatch.setitem(review.REASON_REPETITION_POLICY, "aggregation", "single-span")
    assert review.policy_hash(cfg) != current


def test_current_policy_saved_corrupted_review_cannot_reach_cached_approval(context):
    cfg, store = context
    row = pending(store)
    checker = reviewer(cfg, verdict(), FetchError("temporary", status=500))
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), checker)
    audit = record(store)
    audit["reviews"][0]["result"] = corrupt()
    store.db.execute("UPDATE review_jobs SET record_json=?", (json.dumps(audit),))
    store.db.commit()
    resumed = reviewer(cfg, verdict(), verdict())
    with pytest.raises(AnalysisError, match="damaged"):
        run(cfg, store, row, Writer(), resumed)
    assert resumed.calls == 0 and not store.stories()


def test_corrupted_correction_response_is_recorded_before_validation(context, monkeypatch):
    cfg, store = context
    row = pending(store)
    original = review_gate._save
    def interrupted(*args, **kwargs):
        original(*args, **kwargs)
        slot = args[7]["request_budget"]["validation_reask"]
        if slot and slot["response"] is not None:
            raise RuntimeError("after received response")
    checker = reviewer(cfg, corrupt(), corrupt())
    with monkeypatch.context() as scoped:
        scoped.setattr(review_gate, "_save", interrupted)
        with pytest.raises(RuntimeError, match="after received response"):
            run(cfg, store, row, Writer(), checker)
    assert checker.calls == 2 and record(store)["request_budget"]["validation_reask"]["response"] == 2
    resumed = reviewer(cfg, verdict(), verdict())
    with pytest.raises(review.ReviewError, match="did not yield a usable"):
        run(cfg, store, row, Writer(), resumed)
    assert resumed.calls == 0 and not store.stories()
