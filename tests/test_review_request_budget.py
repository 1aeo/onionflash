"""Untrusted edits never become approval evidence; each must pass a fresh review."""
import copy
import json
from types import SimpleNamespace

import pytest

from approval_helpers import approve, verdict
from onionflash import rejection, review, review_gate
from onionflash.analyze import AnalysisError, tag_notice
from onionflash.store import Store
from onionflash.transport import DeadlineReached, FetchError
from onionflash.util import digest
from test_core import analysis, config, item
from test_review_gate import DATE, LATER, Writer, job, pending, run
from test_review_eval import evaluator


REPAIRED = "A revised report describes the source's concerns."


def inconsistent(repair=None, *, action="revise"):
    reply = verdict()
    reply["verdict"] = action
    reply["criteria"]["source_support"]["reason"] = "UNTRUSTED_PREVIOUS_CRITERIA_SENTINEL"
    if action == "revise":
        edits = {"summary": REPAIRED} if repair is None else repair
        reply["repair"] = {key: edits.get(key) for key in review.EDITABLE}
    return reply


class Responses:
    def __init__(self, *replies, before=None):
        self.replies, self.requests, self.before = list(replies), [], before

    def request(self, method, url, *, headers, json_body):
        if self.before:
            self.before()
        self.requests.append(copy.deepcopy(json_body))
        reply = self.replies.pop(0)
        if isinstance(reply, BaseException):
            raise reply
        return SimpleNamespace(json=lambda: {"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(reply)}}]})

    def close(self):
        pass


def reviewer(cfg, *replies, before=None):
    result = review.Reviewer(cfg)
    result.client = Responses(*replies, before=before)
    return result


@pytest.fixture
def context(tmp_path, monkeypatch):
    cfg = config(tmp_path)
    cfg["llm"].update(base_url="https://model.example/v1", fallback_base_urls=[], api_key_env="REVIEW_TEST_KEY")
    monkeypatch.setenv("REVIEW_TEST_KEY", "synthetic-fixture-value")
    with Store(cfg["storage"]["database"]) as store:
        yield cfg, store


def record(store):
    return json.loads(job(store)["record_json"])


def saved_audit(store):
    return json.loads(store.db.execute('SELECT review_record FROM analyses ORDER BY rowid DESC').fetchone()[0])


def pause_proposal(cfg, store, row, monkeypatch, repair=None, *, leading=(), draft=None):
    original = review_gate._save
    def crash(*args, **kwargs):
        original(*args, **kwargs)
        if args[4] == "verify" and review_gate.pending_proposal(args[7]):
            raise RuntimeError("after durable pending proposal")
    checker = reviewer(cfg, *leading, inconsistent(repair))
    with monkeypatch.context() as scoped:
        scoped.setattr(review_gate, "_save", crash)
        with pytest.raises(RuntimeError, match="durable pending"):
            run(cfg, store, row, Writer(draft), checker)
    assert checker.calls == len(leading) + 1 and job(store)["stage"] == "verify"
    return record(store)


def test_invalid_criteria_stay_outside_reviews_and_proposal_is_persisted_before_verification(context):
    cfg, store = context
    row = pending(store)
    snapshots = []
    checker = reviewer(cfg, inconsistent(), verdict(), before=lambda: snapshots.append(copy.deepcopy(job(store))))
    result = run(cfg, store, row, Writer(), checker)
    assert result["status"] == "published" and result["review_calls"] == checker.calls == 2
    before_verify = json.loads(snapshots[1]["record_json"])
    assert snapshots[1]["stage"] == "verify" and before_verify["candidate"]["summary"] == REPAIRED
    assert before_verify["request_budget"]["reserved"] == 2
    assert before_verify["reviews"] == [] and review_gate.pending_proposal(before_verify)
    payloads = [json.loads(req["messages"][1]["content"]) for req in checker.client.requests]
    assert payloads[1]["candidate"]["summary"] == REPAIRED
    assert payloads[1]["packet"] == payloads[0]["packet"]
    assert set(payloads[1]) == {"candidate", "packet", "coverage_background", "label_bounds"}
    assert payloads[1]["label_bounds"] == review.label_limits(payloads[1]["packet"]["sources"])
    assert checker.client.requests[1]["messages"][0]["content"] == review.VERIFY_PROMPT
    assert "UNTRUSTED_PREVIOUS_CRITERIA_SENTINEL" not in json.dumps(checker.client.requests)
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


def test_unsupported_proposal_rejected_by_fresh_verification_cannot_publish_or_be_operator_approved(context):
    cfg, store = context
    row = pending(store)
    checker = reviewer(cfg, inconsistent({"summary": "An unsupported claim about a wider incident."}),
                       verdict("hold", criterion="source_support"))
    result = run(cfg, store, row, Writer(), checker)
    assert result["status"] == "held" and checker.calls == 2 and store.stories() == []
    audit = record(store)
    assert audit["verified_facts"] is False
    assert audit["untrusted_proposals"][0]["disposition"] == "checked_hold"
    assert not review_gate.approval(cfg, store, row["id"])["eligible"]
    assert review_gate.recovery_status(audit)["unresolved_inconsistency"] is False  # valid refusal, not a lost error


@pytest.mark.parametrize("kind", ["missing-field", "extra-field", "bad-type", "immutable", "null-only", "no-op", "hold", "skip"])
def test_nonproposals_and_malformed_repairs_fail_without_a_followup(context, kind):
    cfg, store = context
    row = pending(store)
    bad = inconsistent()
    if kind == "missing-field": bad["repair"].pop("tags")
    elif kind == "extra-field": bad["repair"]["unknown"] = "value"
    elif kind == "bad-type": bad["repair"]["summary"] = 4
    elif kind == "immutable": bad["repair"]["sources"] = []
    elif kind == "null-only": bad["repair"] = {key: None for key in review.EDITABLE}
    elif kind == "no-op": bad = inconsistent({"summary": analysis()["summary"]})
    else: bad = inconsistent(action=kind)
    checker = reviewer(cfg, bad)
    with pytest.raises(review.InconsistentReview): run(cfg, store, row, Writer(), checker)
    assert checker.calls == 1 and store.stories() == [] and record(store)["reviews"] == []
    event = record(store)["untrusted_proposals"][0]
    assert not event["accepted"] and event["disposition"] == "unusable"
    assert review_gate.recovery_status(record(store))["unresolved_inconsistency"]


def test_packet_disallowed_labels_and_literal_tag_edits_never_enter_recovery(context):
    cfg, store = context
    row = pending(store)
    checker = reviewer(cfg, inconsistent({"confidence": "confirmed"}))
    with pytest.raises(review.InconsistentReview): run(cfg, store, row, Writer(), checker)
    assert record(store)["untrusted_proposals"][0]["disposition"] == "labels" and checker.calls == 1
    with store.db: store.db.execute("DELETE FROM review_jobs"); store.db.execute("DELETE FROM items")
    tag = item(kind="tag", title="tor-0.4.9.5", content="", url="https://example.org/tags/tor-0.4.9.5")
    row = pending(store, tag)
    checker = reviewer(cfg, inconsistent({"title": "Changed literal tag"}))
    with pytest.raises(review.InconsistentReview): run(cfg, store, row, Writer(tag_notice(tag)), checker)
    assert checker.calls == 1 and record(store)["untrusted_proposals"][0]["disposition"] == "literal_tag"
    assert store.stories() == []


@pytest.mark.parametrize("with_trusted_initial", [False, True])
def test_invalid_news_criteria_are_not_an_anchor_but_existing_trusted_disagreement_remains(context, with_trusted_initial):
    cfg, store = context
    row = pending(store)
    replies = ([verdict()] if with_trusted_initial else []) + [inconsistent(), verdict("skip", criterion="news_value")]
    checker = reviewer(cfg, *replies)
    result = run(cfg, store, row, Writer(), checker)
    assert result["status"] == ("held" if with_trusted_initial else "ignored")
    audit = saved_audit(store)
    assert len(audit["reviews"]) == (2 if with_trusted_initial else 1)
    if with_trusted_initial: assert audit["hold_code"] == "disagreed_news"
    assert store.stories() == []


def test_official_news_dispute_uses_only_the_real_fresh_verification(context):
    cfg, store = context
    row = pending(store, item(kind="feed", authority="official"))
    checker = reviewer(cfg, inconsistent(), verdict("skip", criterion="news_value"))
    result = run(cfg, store, row, Writer(), checker)
    assert result["status"] == "held" and record(store)["hold_code"] == "official_not_news"
    assert record(store)["verified_facts"] is True
    assert len(record(store)["reviews"]) == 1 and record(store)["reviews"][0]["stage"] == "verification"


def test_second_changed_untrusted_proposal_still_needs_fresh_verification(context):
    cfg, store = context
    row = pending(store)
    checker = reviewer(cfg, inconsistent(), inconsistent({"summary": "Another changed report requiring verification."}), verdict())
    assert run(cfg, store, row, Writer(), checker)["status"] == "published"
    audit = saved_audit(store)
    assert checker.calls == 3 and len(audit["reviews"]) == 1
    assert [p["disposition"] for p in audit["untrusted_proposals"]] == ["superseded_unverified", "checked_approve"]
    assert audit["request_budget"] == {"reserved": 3, "inconsistent_requests": [1, 2]}


def test_untrusted_and_valid_repair_cycles_are_both_stopped(context):
    cfg, store = context
    row = pending(store)
    checker = reviewer(cfg, inconsistent(), inconsistent({"summary": analysis()["summary"]}))
    with pytest.raises(review.InconsistentReview): run(cfg, store, row, Writer(), checker)
    assert record(store)["untrusted_proposals"][-1]["disposition"] == "repeated"
    assert review_gate.pending_proposal(record(store)) and store.stories() == []
    # A genuinely validated repair back to the initial text is also a loop.
    next_checker = reviewer(cfg, verdict("revise", repair={"summary": analysis()["summary"]}))
    result = run(cfg, store, row, Writer(), next_checker)
    assert result["status"] == "held" and record(store)["hold_code"] == "repeated_repair"
    assert review_gate.recovery_status(record(store))["unresolved_inconsistency"] and store.stories() == []


def test_pending_proposal_survives_restart_and_bypasses_matching_cached_approval(context, monkeypatch):
    cfg, store = context
    row = pending(store)
    audit = pause_proposal(cfg, store, row, monkeypatch)
    prepared = json.loads(job(store)["envelope_json"])
    approve(store, prepared, audit["candidate"], policy=review.policy_hash(cfg))
    idle = reviewer(cfg)
    assert run(cfg, store, row, Writer(), idle, allow_network=False)["status"] == "deferred"
    assert idle.calls == 0 and store.stories() == []
    assert not review_gate.approval(cfg, store, row["id"])["eligible"]
    checker = reviewer(cfg, verdict())
    assert run(cfg, store, row, Writer(), checker)["status"] == "published" and checker.calls == 1
    assert checker.client.requests[0]["messages"][0]["content"] == review.VERIFY_PROMPT
    assert saved_audit(store)["request_budget"]["reserved"] == 2


def test_pending_label_repair_cannot_borrow_an_earlier_verifications_facts(context, monkeypatch):
    cfg, store = context
    row = pending(store)
    draft = analysis(category="release", state="merged", tags=["release"])
    audit = pause_proposal(cfg, store, row, monkeypatch, {"category": "security", "tags": ["security"]},
                           leading=(verdict("revise", repair={"summary": "An earlier repaired summary."}), verdict()), draft=draft)
    assert review_gate._verified(audit["reviews"])  # these facts concern the earlier candidate only
    assert audit["reviews"][-1]["candidate_hash"] != digest(audit["candidate"])
    prepared = json.loads(job(store)["envelope_json"])
    approve(store, prepared, audit["candidate"], policy=review.policy_hash(cfg))
    idle = reviewer(cfg)
    assert run(cfg, store, row, Writer(), idle, allow_network=False)["status"] == "deferred"
    assert idle.calls == 0 and store.stories() == []
    state = record(store)
    review_gate._hold(store, row, draft, job(store)["writer_key"], state, LATER, "review", "model_hold")
    assert record(store)["verified_facts"] is False
    assert review_gate.recovery_status(record(store))["unresolved_inconsistency"]
    assert not review_gate.approval(cfg, store, row["id"])["eligible"]
    with pytest.raises(ValueError):
        rejection.approve_item(cfg, store, row["id"], "0" * 64, "Try an unverified proposal", LATER)
    assert store.stories() == []


def test_partial_release_label_edit_requires_correction_and_fresh_verification(context):
    cfg, store = context
    incoming = item(kind="gitlab_mr", upstream_state="merged")
    row = pending(store, incoming)
    draft = analysis(category="release", state="merged", tags=["release"])
    partial = inconsistent({"title": "An opt-in capability was merged", "category": "feature", "tags": ["feature", "release"]})
    correction = verdict("revise", repair={"tags": ["feature"]}, criterion="status")
    checker = reviewer(cfg, partial, verdict(), correction, verdict())
    result = run(cfg, store, row, Writer(draft), checker)
    assert result["status"] == "published" and checker.calls == 4
    payloads = [json.loads(call["messages"][1]["content"]) for call in checker.client.requests]
    assert payloads[2]["application_issue"] == review.RELEASE_ISSUE
    assert checker.client.requests[1]["messages"][0]["content"] == review.VERIFY_PROMPT
    assert checker.client.requests[3]["messages"][0]["content"] == review.VERIFY_PROMPT
    assert "release" in payloads[1]["candidate"]["tags"]
    assert "release" not in payloads[3]["candidate"]["tags"]
    assert "release" not in store.stories()[0]["tags"]
    assert len(saved_audit(store)["reviews"]) == 3


def add_coverage(store):
    incoming = item(url="https://example.org/other-story", title="A separate report")
    store.ingest(incoming, DATE)
    row = dict(store.db.execute('SELECT * FROM items WHERE url=?', (incoming["url"],)).fetchone())
    prepared = store.prepare_candidate(row, analysis(title="A separate report"), LATER)
    value = prepared["payload"]
    with store.db:
        store.db.execute('INSERT INTO stories VALUES(?,?,?,?,?)', (prepared["story_id"], prepared["cluster_key"], json.dumps(value), value["published_at"], value["updated_at"]))
        store.db.execute("UPDATE items SET status='published',story_id=? WHERE id=?", (prepared["story_id"], row["id"]))


def test_legitimate_context_change_discards_proposal_and_preserves_budget(context, monkeypatch):
    cfg, store = context
    row = pending(store)
    pause_proposal(cfg, store, row, monkeypatch)
    add_coverage(store)
    checker = reviewer(cfg, verdict(), verdict())
    assert run(cfg, store, row, Writer(), checker)["status"] == "published"
    first = json.loads(checker.client.requests[0]["messages"][1]["content"])
    assert first["candidate"]["summary"] == analysis()["summary"]
    assert checker.client.requests[0]["messages"][0]["content"] == review.SYSTEM_PROMPT
    audit = saved_audit(store)
    assert audit["untrusted_proposals"][0]["disposition"] == "discarded_context"
    assert audit["request_budget"]["reserved"] == 3 and checker.calls == 2


def test_a_new_source_revision_starts_from_its_new_draft_not_the_pending_proposal(context, monkeypatch):
    cfg, store = context
    row = pending(store)
    pause_proposal(cfg, store, row, monkeypatch)
    changed = json.loads(row["payload"])
    changed.update(content=changed["content"] + " A new public source detail.", updated_at=LATER)
    store.ingest(changed, LATER)
    current = dict(store.db.execute('SELECT * FROM items WHERE id=?', (row["id"],)).fetchone())
    writer = Writer(analysis(summary="A fresh summary of the revised source."))
    checker = reviewer(cfg, verdict(), verdict())
    assert run(cfg, store, current, writer, checker)["status"] == "published"
    first = json.loads(checker.client.requests[0]["messages"][1]["content"])
    assert first["candidate"]["summary"] == "A fresh summary of the revised source."
    assert checker.client.requests[0]["messages"][0]["content"] == review.SYSTEM_PROMPT
    assert saved_audit(store)["request_budget"]["reserved"] == 2
    assert not saved_audit(store).get("untrusted_proposals")


def test_verified_recovery_receipt_resumes_after_commit_crash_without_another_request(context, monkeypatch):
    cfg, store = context
    row = pending(store)
    checker = reviewer(cfg, inconsistent(), verdict())
    commit = store.commit_candidate
    with monkeypatch.context() as scoped:
        scoped.setattr(store, "commit_candidate", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("before commit")))
        with pytest.raises(RuntimeError, match="before commit"):
            run(cfg, store, row, Writer(), checker)
    assert job(store)["stage"] == "approved" and not review_gate.proposal_needs_check(record(store))
    idle = reviewer(cfg)
    result = run(cfg, store, row, Writer(), idle, allow_network=False)
    assert result["status"] == "published" and result["cache_hit"] and idle.calls == 0
    assert saved_audit(store)["request_budget"]["reserved"] == 2


def pause_cached_after_reset(cfg, store, row, monkeypatch):
    with monkeypatch.context() as scoped:
        scoped.setattr(store, "commit_candidate", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("before commit")))
        with pytest.raises(RuntimeError, match="before commit"):
            run(cfg, store, row, Writer(), reviewer(cfg, verdict(), verdict()))
        with store.db:
            review_gate.reset_review_work(store, row["id"])
        idle = reviewer(cfg)
        with pytest.raises(RuntimeError, match="before commit"):
            run(cfg, store, row, Writer(), idle, allow_network=False)
        assert idle.calls == 0
    audit = record(store)
    assert audit["reviews"] == [] and audit["request_budget"]["reserved"] == 0
    assert job(store)["stage"] == "approved" and audit["approval"]["reviews"]
    return audit


@pytest.mark.parametrize("damage", [None, "proof-shape", "proof-key", "proof-context", "proof-candidate", "proof-text", "proof-policy", "nested-chain", "job-key", "nonterminal"])
def test_terminal_cache_hit_after_reset_resumes_only_with_exact_nested_proof(context, monkeypatch, damage):
    cfg, store = context
    row = pending(store)
    audit = pause_cached_after_reset(cfg, store, row, monkeypatch)
    if damage == "proof-shape": audit["approval"] = {}
    elif damage == "proof-key": audit["approval"]["approval_key"] = "0" * 64
    elif damage == "proof-context": audit["approval"]["reviews"][-1]["source_hash"] = "0" * 64
    elif damage == "proof-candidate": audit["approval"]["reviews"][-1]["candidate_hash"] = "0" * 64
    elif damage == "proof-text": audit["approval"]["candidate"]["summary"] = "A different saved candidate."
    elif damage == "proof-policy": audit["approval"]["policy_hash"] = "0" * 64
    elif damage == "nested-chain": audit["approval"]["approval"] = copy.deepcopy(audit["approval"])
    elif damage == "job-key": audit["approval_key"] = "0" * 64
    with store.db:
        store.db.execute('UPDATE review_jobs SET record_json=? WHERE item_id=?', (json.dumps(audit), row["id"]))
        if damage == "nonterminal": store.db.execute("UPDATE review_jobs SET stage='verify' WHERE item_id=?", (row["id"],))
    idle = reviewer(cfg)
    if damage:
        with pytest.raises(AnalysisError) as error:
            run(cfg, store, row, Writer(), idle, allow_network=False)
        assert error.value.code == "app.damaged_job" and store.stories() == []
    else:
        result = run(cfg, store, row, Writer(), idle, allow_network=False)
        assert result["status"] == "published" and result["cache_hit"]
    assert idle.calls == 0


def test_nested_proof_without_its_matching_receipt_cannot_publish(context, monkeypatch):
    cfg, store = context
    row = pending(store)
    pause_cached_after_reset(cfg, store, row, monkeypatch)
    with store.db:
        store.db.execute('DELETE FROM review_approvals')
    idle = reviewer(cfg)
    result = run(cfg, store, row, Writer(), idle, allow_network=False)
    assert result["status"] == "deferred" and not result["cache_hit"]
    assert idle.calls == 0 and store.stories() == []


@pytest.mark.parametrize("damage", ["counter-bool", "counter-too-large", "missing-budget", "audit-shape", "after-hash",
                                    "context-hash", "accepted-flag", "fake-checked", "fake-discard", "changed-repair", "wrong-stage", "invalid-trusted",
                                    "erase-both", "empty-ledgers"])
def test_saved_budget_or_proposal_corruption_fails_before_model_or_cache(context, monkeypatch, damage):
    cfg, store = context
    row = pending(store)
    audit = pause_proposal(cfg, store, row, monkeypatch)
    prepared = json.loads(job(store)["envelope_json"])
    approve(store, prepared, audit["candidate"], policy=review.policy_hash(cfg))
    if damage == "counter-bool": audit["request_budget"]["reserved"] = True
    elif damage == "counter-too-large": audit["request_budget"]["reserved"] = 8
    elif damage == "missing-budget": audit.pop("request_budget")
    elif damage == "audit-shape": audit["untrusted_proposals"] = {}
    elif damage == "after-hash": audit["untrusted_proposals"][0]["candidate_after_hash"] = "0" * 64
    elif damage == "context-hash": audit["untrusted_proposals"][0]["context"]["source_hash"] = "0" * 64
    elif damage == "accepted-flag": audit["untrusted_proposals"][0]["accepted"] = False
    elif damage == "fake-checked": audit["untrusted_proposals"][0]["disposition"] = "checked_approve"
    elif damage == "fake-discard": audit["untrusted_proposals"][0]["disposition"] = "discarded_context"
    elif damage == "changed-repair": audit["untrusted_proposals"][0]["repair"]["summary"] = "Different saved text."
    elif damage == "invalid-trusted": audit["reviews"] = [{"stage": "verification", "candidate_hash": digest(audit["candidate"]), "result": inconsistent()}]
    elif damage == "erase-both": audit.pop("untrusted_proposals"); audit.pop("request_budget")
    elif damage == "empty-ledgers": audit["untrusted_proposals"] = []; audit["request_budget"]["inconsistent_requests"] = []
    with store.db:
        store.db.execute('UPDATE review_jobs SET record_json=? WHERE item_id=?', (json.dumps(audit), row["id"]))
        if damage == "wrong-stage": store.db.execute("UPDATE review_jobs SET stage='approved' WHERE item_id=?", (row["id"],))
    checker = reviewer(cfg, verdict())
    with pytest.raises(AnalysisError) as error: run(cfg, store, row, Writer(), checker)
    assert error.value.code == "app.damaged_job" and checker.calls == 0 and store.stories() == []


def test_request_cap_counts_all_invalid_proposals_and_fallbacks(context):
    cfg, store = context
    row = pending(store)
    checker = reviewer(cfg, *(inconsistent({"summary": f"Different unverified proposal {n}."}) for n in range(7)))
    with pytest.raises(review.ReviewLimitReached): run(cfg, store, row, Writer(), checker)
    assert checker.calls == 7 and len(record(store)["untrusted_proposals"]) == 7
    assert record(store)["request_budget"]["reserved"] == 7 and record(store)["reviews"] == []
    assert review_gate.recovery_status(record(store))["unresolved_inconsistency"] and store.stories() == []
    with store.db: store.db.execute('DELETE FROM review_jobs'); store.db.execute('DELETE FROM items')
    cfg["llm"]["fallback_base_urls"] = [f"https://fallback{n}.example/v1" for n in range(9)]
    row = pending(store)
    checker = reviewer(cfg, *(FetchError("unavailable", status=500) for _ in range(10)))
    with pytest.raises(review.ReviewLimitReached): run(cfg, store, row, Writer(), checker)
    assert checker.calls == len(checker.client.requests) == 7 and store.stories() == []


def test_local_failures_and_unsent_deadline_do_not_spend_requests(context, monkeypatch):
    cfg, store = context
    row = pending(store)
    checker = reviewer(cfg, DeadlineReached())
    monkeypatch.delenv("REVIEW_TEST_KEY")
    with pytest.raises(AnalysisError, match="credential"): run(cfg, store, row, Writer(), checker)
    assert checker.calls == 0 and record(store)["request_budget"]["reserved"] == 0
    monkeypatch.setenv("REVIEW_TEST_KEY", "synthetic-fixture-value")
    with pytest.raises(AnalysisError): run(cfg, store, row, Writer(), checker)
    assert checker.calls == 0 and record(store)["request_budget"]["reserved"] == 0
    assert record(store)["reviews"] == [] and not record(store).get("untrusted_proposals")


@pytest.mark.parametrize("replies,error,unresolved,expected", [
    ([inconsistent(), verdict()], None, False, "approve"),
    ([inconsistent({}),], "InconsistentReview", True, None),
    ([inconsistent(), verdict("hold", criterion="source_support")], None, False, "hold"),
    ([inconsistent(), verdict("revise", repair={"summary": "ORIGINAL"})], None, True, "hold"),
])
def test_evaluator_uses_same_recovery_and_separates_raw_errors_from_terminal_outcomes(context, tmp_path, monkeypatch, replies, error, unresolved, expected):
    cfg, _ = context
    module = evaluator()
    raw = json.loads((module.Path(module.__file__).parent/'review_cases.json').read_text())
    case = next(c for c in module.expand(raw) if c['id'] == 'bastet-corrected')
    replies = copy.deepcopy(replies)
    if replies[-1].get('repair') and replies[-1]['repair'].get('summary') == 'ORIGINAL': replies[-1]['repair']['summary'] = case['candidate']['summary']
    client = Responses(*replies)
    base = module.EvaluationReviewer
    class Checker(base):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs); self.client = client
    monkeypatch.setattr(module, 'EvaluationReviewer', Checker)
    path = tmp_path/'evaluation.jsonl'
    result = module.evaluate(cfg, [case], path)
    found = json.loads(path.read_text().splitlines()[0])
    assert found['review_request_count'] == len(client.requests) == len(replies)
    assert found.get('error') == error and result['errors'] == bool(error)
    assert found['raw_inconsistency_count'] == 1 and result['raw_inconsistencies'] == 1
    assert found['unresolved_inconsistency'] is unresolved
    assert result['unresolved_inconsistencies'] == int(unresolved)
    assert found.get('final_verdict') == expected
    if expected != 'approve': assert found.get('published_candidate') is None
    assert all(entry['result']['criteria']['source_support']['reason'] != 'UNTRUSTED_PREVIOUS_CRITERIA_SENTINEL' for entry in found['reviews'])
