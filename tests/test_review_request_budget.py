"""Untrusted edits never become approval evidence; each must pass a fresh review."""
import copy
import json
from types import SimpleNamespace

import pytest

from helpers import approve, verdict
from onionflash import rejection, review, review_gate
from onionflash.analyze import AnalysisError, tag_notice
from onionflash.store import Store
from onionflash.transport import DeadlineReached, FetchError
from onionflash.util import digest
from helpers import analysis, make_config as config, make_item as item
from helpers import DATE, LATER, Writer, job, pending, run_gate as run
from helpers import load_evaluator as evaluator


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


def load_legacy_proposal(cfg, store, row, monkeypatch, repair=None, *, leading=(), draft=None):
    """Exercise the retained reader using a genuine earlier native receipt."""
    from legacy_review_records import install_legacy_pending

    label_repair = bool(leading)
    if label_repair:
        assert repair == {"category": "security", "tags": ["security"]}
        assert leading == (verdict("revise", repair={"summary": "An earlier repaired summary."}), verdict())
        assert draft == analysis(category="release", state="merged", tags=["release"])
    else:
        assert repair is None and draft is None
    return install_legacy_pending(cfg, store, row, monkeypatch, label_repair=label_repair)


def test_invalid_criteria_and_edits_stay_outside_the_corrected_review(context):
    cfg, store = context
    row = pending(store)
    snapshots = []
    invalid_text = "An unvalidated rewrite must never become the candidate."
    checker = reviewer(cfg, inconsistent({"summary": invalid_text}),
                       verdict("revise", criterion="source_support", repair={"summary": REPAIRED}), verdict(),
                       before=lambda: snapshots.append(copy.deepcopy(job(store))))
    result = run(cfg, store, row, Writer(), checker)
    assert result["status"] == "published" and result["review_calls"] == checker.calls == 3
    correction = json.loads(snapshots[1]["record_json"])
    assert snapshots[1]["stage"] == "review" and correction["reviews"] == []
    assert correction["request_budget"]["reserved"] == 2 and not review_gate.pending_proposal(correction)
    assert invalid_text not in json.dumps(correction)
    payloads = [json.loads(req["messages"][1]["content"]) for req in checker.client.requests]
    assert payloads[1] == {**payloads[0], "validation_error": review.INCONSISTENT_VERDICT}
    assert payloads[2]["candidate"]["summary"] == REPAIRED
    assert payloads[2]["packet"] == payloads[0]["packet"]
    assert all(p["candidate"]["summary"] != invalid_text for p in payloads)
    assert checker.client.requests[2]["messages"][0]["content"] == review.VERIFY_PROMPT
    assert "UNTRUSTED_PREVIOUS_CRITERIA_SENTINEL" not in json.dumps(checker.client.requests)
    audit = saved_audit(store)
    assert [(e["request"], e["stage"]) for e in audit["reviews"]] == [(2, "review"), (3, "verification")]
    assert audit["reviews"][0]["reask_response"]
    event = audit["untrusted_proposals"][0]
    assert event["candidate_before_hash"] == digest(payloads[0]["candidate"])
    assert event["candidate_after_hash"] is None and event["repair"] is None and event["changed_fields"] == []
    assert event["error"] == review.INCONSISTENT_VERDICT and event["disposition"] == "unusable"
    assert not event["accepted"] and event["reask_trigger"]
    assert review_gate.recovery_status(audit) == {"raw_inconsistency_count": 1, "raw_degenerate_count": 0, "raw_attribution_count": 0,
        "accepted_proposal_count": 0, "unresolved_inconsistency": False, "unresolved_degenerate": False, "unresolved_attribution": False}

def test_discarded_edit_and_corrective_hold_cannot_publish_or_be_operator_approved(context):
    cfg, store = context
    row = pending(store)
    unsafe = "An unsupported claim about a wider incident."
    checker = reviewer(cfg, inconsistent({"summary": unsafe}), verdict("hold", criterion="source_support"))
    result = run(cfg, store, row, Writer(), checker)
    assert result["status"] == "held" and checker.calls == 2 and store.stories() == []
    payloads = [json.loads(r["messages"][1]["content"]) for r in checker.client.requests]
    assert payloads[1] == {**payloads[0], "validation_error": review.INCONSISTENT_VERDICT}
    assert unsafe not in json.dumps(payloads)
    audit = record(store)
    assert audit["verified_facts"] is False
    assert audit["untrusted_proposals"][0]["disposition"] == "unusable"
    assert not audit["untrusted_proposals"][0]["accepted"]
    assert not review_gate.approval(cfg, store, row["id"])["eligible"]
    assert review_gate.recovery_status(audit)["unresolved_inconsistency"] is False

@pytest.mark.parametrize("kind", ["missing-field", "extra-field", "bad-type", "immutable", "null-only", "no-op", "hold", "skip"])
def test_nonproposals_are_never_applied_and_a_second_invalid_reply_stops(context, kind):
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
    checker = reviewer(cfg, bad, copy.deepcopy(bad))
    with pytest.raises(review.InconsistentReview): run(cfg, store, row, Writer(), checker)
    assert checker.calls == 2 and store.stories() == [] and record(store)["reviews"] == []
    payloads = [json.loads(request["messages"][1]["content"]) for request in checker.client.requests]
    assert payloads[1] == {**payloads[0], "validation_error": review.INCONSISTENT_VERDICT}
    event = record(store)["untrusted_proposals"][0]
    assert not event["accepted"] and event["disposition"] == "unusable"
    assert review_gate.recovery_status(record(store))["unresolved_inconsistency"]


def test_invalid_disallowed_labels_and_literal_tag_edits_never_change_the_target(context):
    cfg, store = context
    row = pending(store)
    checker = reviewer(cfg, inconsistent({"confidence": "confirmed"}), inconsistent({"confidence": "confirmed"}))
    with pytest.raises(review.InconsistentReview):
        run(cfg, store, row, Writer(), checker)
    payloads = [json.loads(r["messages"][1]["content"]) for r in checker.client.requests]
    assert payloads[1] == {**payloads[0], "validation_error": review.INCONSISTENT_VERDICT}
    assert all(p["candidate"]["confidence"] == "reported" for p in payloads)
    assert all(p["repair"] is None and not p["accepted"] for p in record(store)["untrusted_proposals"])
    assert checker.calls == 2
    with store.db:
        store.db.execute("DELETE FROM review_jobs")
        store.db.execute("DELETE FROM items")
    tag = item(kind="tag", title="tor-0.4.9.5", content="", url="https://example.org/tags/tor-0.4.9.5")
    row = pending(store, tag)
    checker = reviewer(cfg, inconsistent({"title": "Changed literal tag"}), inconsistent({"title": "Changed literal tag"}))
    with pytest.raises(review.InconsistentReview):
        run(cfg, store, row, Writer(tag_notice(tag)), checker)
    payloads = [json.loads(r["messages"][1]["content"]) for r in checker.client.requests]
    assert payloads[1] == {**payloads[0], "validation_error": review.INCONSISTENT_VERDICT}
    assert all(p["candidate"]["title"] != "Changed literal tag" for p in payloads)
    assert all(p["repair"] is None and not p["accepted"] for p in record(store)["untrusted_proposals"])
    assert checker.calls == 2 and store.stories() == []

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


def test_official_news_dispute_requires_corrective_review_and_fresh_verification(context):
    cfg, store = context
    row = pending(store, item(kind="feed", authority="official"))
    checker = reviewer(cfg, inconsistent(), verdict("skip", criterion="news_value"), verdict("skip", criterion="news_value"))
    result = run(cfg, store, row, Writer(), checker)
    audit = record(store)
    assert result["status"] == "held" and audit["hold_code"] == "official_not_news"
    assert audit["verified_facts"] is True and checker.calls == 3
    assert [(e["request"], e["stage"]) for e in audit["reviews"]] == [(2, "review"), (3, "verification")]
    payloads = [json.loads(r["messages"][1]["content"]) for r in checker.client.requests]
    assert payloads[0]["candidate"] == payloads[1]["candidate"] == payloads[2]["candidate"]
    assert not audit["untrusted_proposals"][0]["accepted"]

def test_second_changed_invalid_edit_is_terminal_without_candidate_mutation(context):
    cfg, store = context
    row = pending(store)
    checker = reviewer(cfg, inconsistent(), inconsistent({"summary": "Another unvalidated report."}), verdict())
    with pytest.raises(review.InconsistentReview):
        run(cfg, store, row, Writer(), checker)
    audit = record(store)
    assert checker.calls == 2 and audit["reviews"] == [] and not store.stories()
    assert len(checker.client.replies) == 1
    assert all(p["repair"] is None and not p["accepted"] for p in audit["untrusted_proposals"])
    assert audit["request_budget"]["validation_reask"]["response"] == 2
    payloads = [json.loads(r["messages"][1]["content"]) for r in checker.client.requests]
    assert payloads[1] == {**payloads[0], "validation_error": review.INCONSISTENT_VERDICT}

def test_valid_corrective_repair_cannot_cycle_back_to_an_earlier_candidate(context):
    cfg, store = context
    row = pending(store)
    checker = reviewer(cfg, inconsistent({"summary": "An invalid proposed summary."}),
                       verdict("revise", repair={"summary": REPAIRED}), FetchError("temporary", status=500))
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), checker)
    audit = record(store)
    assert audit["candidate"]["summary"] == REPAIRED and audit["request_budget"]["reserved"] == 3
    assert not review_gate.pending_proposal(audit) and not audit["untrusted_proposals"][0]["accepted"]
    assert audit["request_budget"]["validation_reask"]["response"] == 2
    next_checker = reviewer(cfg, verdict("revise", repair={"summary": analysis()["summary"]}))
    result = run(cfg, store, row, Writer(), next_checker)
    assert result["status"] == "held" and record(store)["hold_code"] == "repeated_repair"
    assert record(store)["request_budget"]["reserved"] == 4 and next_checker.calls == 1
    assert review_gate.recovery_status(record(store))["unresolved_inconsistency"] and not store.stories()

def test_legacy_pending_proposal_survives_restart_and_bypasses_matching_cached_approval(context, monkeypatch):
    cfg, store = context
    row = pending(store)
    audit = load_legacy_proposal(cfg, store, row, monkeypatch)
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


def test_legacy_pending_label_repair_cannot_borrow_an_earlier_verifications_facts(context, monkeypatch):
    cfg, store = context
    row = pending(store)
    draft = analysis(category="release", state="merged", tags=["release"])
    audit = load_legacy_proposal(cfg, store, row, monkeypatch, {"category": "security", "tags": ["security"]},
                           leading=(verdict("revise", repair={"summary": "An earlier repaired summary."}), verdict()), draft=draft)
    assert review_gate._verified(audit["reviews"])  # these facts concern the earlier candidate only
    assert audit["reviews"][-1]["candidate_hash"] != digest(audit["candidate"])
    prepared = json.loads(job(store)["envelope_json"])
    approve(store, prepared, audit["candidate"], policy=review.policy_hash(cfg))
    idle = reviewer(cfg)
    assert run(cfg, store, row, Writer(), idle, allow_network=False)["status"] == "deferred"
    assert idle.calls == 0 and store.stories() == []
    state = record(store)
    assert state["request_budget"]["reserved"] == 3
    assert review_gate.pending_proposal(state) and len(state["reviews"]) == 2
    review_gate._hold(store, row, draft, job(store)["writer_key"], state, LATER, "review", "model_hold")
    assert record(store)["verified_facts"] is False
    assert review_gate.recovery_status(record(store))["unresolved_inconsistency"]
    assert not review_gate.approval(cfg, store, row["id"])["eligible"]
    with pytest.raises(ValueError):
        rejection.approve_item(cfg, store, row["id"], "0" * 64, "Try an unverified proposal", LATER)
    assert store.stories() == []


def test_real_policy_change_reuses_writer_but_discards_legacy_edit_and_approval(context):
    from legacy_review_records import install_for_policy_upgrade

    cfg, store = context
    row = pending(store)
    current_policy = review.policy_hash(cfg)
    old = install_for_policy_upgrade(cfg, store, row)
    prepared = json.loads(job(store)["envelope_json"])
    approve(store, prepared, old["candidate"], policy=old["policy_hash"])
    checker, writer = reviewer(cfg, verdict(), verdict()), Writer()
    result = run(cfg, store, row, writer, checker)
    assert result["status"] == "published" and result["cache_hit"] is False
    assert writer.calls == [] and checker.calls == 2
    payloads = [json.loads(r["messages"][1]["content"]) for r in checker.client.requests]
    assert payloads[0]["candidate"] == payloads[1]["candidate"] == old["prepared"]["candidate"]
    assert payloads[0]["candidate"] != old["candidate"]
    saved = saved_audit(store)
    assert saved["writer"]["key"] == old["writer"]["key"]
    assert saved["policy_hash"] == current_policy != old["policy_hash"]
    assert saved["schema_version"] == 2 and saved["request_budget"]["reserved"] == 2
    assert saved["untrusted_proposals"] == []
    assert [(e["request"], e["stage"]) for e in saved["reviews"]] == [(1, "review"), (2, "verification")]


def test_discarded_partial_label_edit_does_not_change_what_the_real_repair_must_fix(context):
    cfg, store = context
    incoming = item(kind="feed", authority="official", upstream_state="")
    row = pending(store, incoming)
    draft = analysis(category="release", state="developing", tags=["release"])
    partial = inconsistent({"title": "An unvalidated capability was merged", "category": "feature", "tags": ["feature", "release"]})
    correction = verdict("revise", repair={"category": "security", "tags": ["security"]}, criterion="status")
    checker = reviewer(cfg, partial, verdict(), correction, verdict())
    result = run(cfg, store, row, Writer(draft), checker)
    assert result["status"] == "published" and checker.calls == 4
    payloads = [json.loads(call["messages"][1]["content"]) for call in checker.client.requests]
    assert payloads[1] == {**payloads[0], "validation_error": review.INCONSISTENT_VERDICT}
    assert payloads[2]["candidate"] == payloads[0]["candidate"]
    assert payloads[2]["application_issue"] == review.RELEASE_ISSUE
    assert payloads[3]["candidate"]["category"] == "security" and payloads[3]["candidate"]["tags"] == ["security"]
    assert all(p["candidate"]["title"] != "An unvalidated capability was merged" for p in payloads)
    assert checker.client.requests[3]["messages"][0]["content"] == review.VERIFY_PROMPT
    assert "release" not in store.stories()[0]["tags"]
    assert [(e["request"], e["stage"]) for e in saved_audit(store)["reviews"]] == [(2, "review"), (3, "review"), (4, "verification")]

def add_coverage(store):
    incoming = item(url="https://example.org/other-story", title="A separate report")
    store.ingest(incoming, DATE)
    row = dict(store.db.execute('SELECT * FROM items WHERE url=?', (incoming["url"],)).fetchone())
    prepared = store.prepare_candidate(row, analysis(title="A separate report"), LATER)
    value = prepared["payload"]
    with store.db:
        store.db.execute('INSERT INTO stories VALUES(?,?,?,?,?)', (prepared["story_id"], prepared["cluster_key"], json.dumps(value), value["published_at"], value["updated_at"]))
        store.db.execute("UPDATE items SET status='published',story_id=? WHERE id=?", (prepared["story_id"], row["id"]))


def test_legacy_legitimate_context_change_discards_proposal_and_preserves_budget(context, monkeypatch):
    cfg, store = context
    row = pending(store)
    load_legacy_proposal(cfg, store, row, monkeypatch)
    add_coverage(store)
    checker = reviewer(cfg, verdict(), verdict())
    assert run(cfg, store, row, Writer(), checker)["status"] == "published"
    first = json.loads(checker.client.requests[0]["messages"][1]["content"])
    assert first["candidate"]["summary"] == "The operator reported a plausible compromise and stopped trusting the affected keys."
    assert checker.client.requests[0]["messages"][0]["content"] == review.SYSTEM_PROMPT + review.ROUTING_PROMPT
    audit = saved_audit(store)
    assert audit["untrusted_proposals"][0]["disposition"] == "discarded_context"
    assert audit["request_budget"]["reserved"] == 3 and checker.calls == 2


def test_legacy_a_new_source_revision_starts_from_its_new_draft_not_the_pending_proposal(context, monkeypatch):
    cfg, store = context
    row = pending(store)
    load_legacy_proposal(cfg, store, row, monkeypatch)
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


def test_verified_corrective_repair_resumes_after_commit_crash_without_another_request(context, monkeypatch):
    cfg, store = context
    row = pending(store)
    checker = reviewer(cfg, inconsistent({"summary": "Discard this invalid edit."}),
                       verdict("revise", repair={"summary": REPAIRED}), verdict())
    with monkeypatch.context() as scoped:
        scoped.setattr(store, "commit_candidate", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("before commit")))
        with pytest.raises(RuntimeError, match="before commit"):
            run(cfg, store, row, Writer(), checker)
    assert job(store)["stage"] == "approved" and not review_gate.proposal_needs_check(record(store))
    assert record(store)["candidate"]["summary"] == REPAIRED
    assert record(store)["reviews"][-1]["stage"] == "verification"
    idle = reviewer(cfg)
    result = run(cfg, store, row, Writer(), idle, allow_network=False)
    assert result["status"] == "published" and result["cache_hit"] and idle.calls == 0
    assert saved_audit(store)["request_budget"]["reserved"] == 3 and checker.calls == 3

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
def test_legacy_saved_budget_or_proposal_corruption_fails_before_model_or_cache(context, monkeypatch, damage):
    cfg, store = context
    row = pending(store)
    audit = load_legacy_proposal(cfg, store, row, monkeypatch)
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
    before = job(store)
    checked = []
    original_ledger = review_gate.ReviewRequests.__init__
    original_state = review_gate.validate_review_state

    def checked_ledger(self, *args, **kwargs):
        checked.append("ledger")
        return original_ledger(self, *args, **kwargs)

    def checked_state(*args, **kwargs):
        checked.append("state")
        return original_state(*args, **kwargs)

    monkeypatch.setattr(review_gate.ReviewRequests, "__init__", checked_ledger)
    monkeypatch.setattr(review_gate, "validate_review_state", checked_state)
    checker = reviewer(cfg, verdict())
    with pytest.raises(AnalysisError) as error: run(cfg, store, row, Writer(), checker)
    assert error.value.code == "app.damaged_job" and checker.calls == 0 and store.stories() == []
    assert "ledger" in checked and job(store) == before
    if damage not in {"counter-bool", "counter-too-large", "missing-budget", "audit-shape", "erase-both"}:
        assert "state" in checked  # The damaged proof, not a policy reset, was checked.


def test_request_cap_counts_invalid_reply_and_correction_fallbacks_together(context):
    cfg, store = context
    cfg["llm"]["fallback_base_urls"] = [f"https://fallback{n}.example/v1" for n in range(6)]
    row = pending(store)
    checker = reviewer(cfg, inconsistent({"summary": "Never apply this invalid edit."}),
                       *(FetchError("unavailable", status=500) for _ in range(6)))
    with pytest.raises(review.ReviewLimitReached):
        run(cfg, store, row, Writer(), checker)
    audit = record(store)
    assert checker.calls == len(checker.client.requests) == audit["request_budget"]["reserved"] == 7
    assert len(audit["untrusted_proposals"]) == 1 and not audit["untrusted_proposals"][0]["accepted"]
    assert audit["request_budget"]["validation_reask"]["attempts"] == [2, 3, 4, 5, 6, 7]
    assert audit["reviews"] == [] and not store.stories()
    payloads = [json.loads(r["messages"][1]["content"]) for r in checker.client.requests]
    assert all(p["candidate"] == payloads[0]["candidate"] for p in payloads)
    assert all(p["validation_error"] == review.INCONSISTENT_VERDICT for p in payloads[1:])
    with store.db:
        store.db.execute("DELETE FROM review_jobs")
        store.db.execute("DELETE FROM items")
    cfg["llm"]["fallback_base_urls"] = [f"https://fallback{n}.example/v1" for n in range(9)]
    row = pending(store)
    checker = reviewer(cfg, *(FetchError("unavailable", status=500) for _ in range(10)))
    with pytest.raises(review.ReviewLimitReached):
        run(cfg, store, row, Writer(), checker)
    assert checker.calls == len(checker.client.requests) == 7 and not store.stories()

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


@pytest.mark.parametrize("replies,error,unresolved,expected,raw_count", [
    ([inconsistent(), verdict(), verdict()], None, False, "approve", 1),
    ([inconsistent({}), inconsistent({})], "InconsistentReview", True, None, 2),
    ([inconsistent(), verdict("hold", criterion="source_support")], None, False, "hold", 1),
    ([inconsistent(), verdict("revise", repair={"summary": "ORIGINAL"})], None, True, "hold", 1),
])
def test_evaluator_uses_same_recovery_and_separates_raw_errors_from_terminal_outcomes(context, tmp_path, monkeypatch, replies, error, unresolved, expected, raw_count):
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
    assert found['raw_inconsistency_count'] == raw_count and result['raw_inconsistencies'] == raw_count
    assert found['unresolved_inconsistency'] is unresolved
    assert result['unresolved_inconsistencies'] == int(unresolved)
    assert found.get('final_verdict') == expected
    if expected != 'approve': assert found.get('published_candidate') is None
    assert all(entry['result']['criteria']['source_support']['reason'] != 'UNTRUSTED_PREVIOUS_CRITERIA_SENTINEL' for entry in found['reviews'])
    assert found['accepted_proposal_count'] == 0
    assert all(not event['accepted'] and event['repair'] is None for event in found['untrusted_proposals'])
    if expected == 'approve':
        assert found['reviews'][-1]['stage'] == 'verification'
        assert found['published_candidate'] == found['review_candidate']
