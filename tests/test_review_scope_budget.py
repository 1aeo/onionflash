"""Recovery proof and request budgets remain bound across automatic review scopes."""
import copy
import json

import pytest

from helpers import update_analysis, verdict
from onionflash import cli, editorial, review, review_gate
from onionflash.analyze import AnalysisError
from onionflash.transport import FetchError
from onionflash.util import digest
from helpers import seed_source_story as _publish
from helpers import analysis, make_item as item
from helpers import ROOT, load_evaluator as evaluator
from helpers import LATER, Writer, job, pending, run_gate as run
from test_review_request_budget import context, inconsistent, record, reviewer, saved_audit


def update_case():
    module = evaluator()
    case = next(c for c in module.expand(json.loads((ROOT / "tools/review_cases.json").read_text()))
                if c["id"] == "update-workaround")
    source = case["packet"]["sources"][0]
    prepared = {"candidate": case["candidate"], "packet": case["packet"], "coverage": case["existing_coverage"],
                "mode": "update", "payload": {"editorial_kind": source["kind"]},
                "row": {"payload": json.dumps(module.writer_item(source))}}
    return case, prepared


def untrusted_update(edits, *, same_story=None):
    reply = verdict(update=True, same_story=same_story)
    reply.update(verdict="revise", repair={field: edits.get(field) for field in review.UPDATE_EDITABLE})
    return reply


def test_untrusted_update_preserves_history_and_requires_exact_fresh_verification(context):
    cfg, _ = context
    case, prepared = update_case()
    original = copy.deepcopy(case["candidate"])
    record = {"candidate": original, "reviews": [], "policy_hash": review.policy_hash(cfg),
              **review_gate.initial_review_state()}
    requests = review_gate.ReviewRequests(record)
    text = "Operators can use the supplied workaround."
    checker = reviewer(cfg, untrusted_update({"update": text}), verdict(update=True))
    action, repaired = review_gate.advance_review(checker, "review", original, prepared, record, requests)
    assert action == "verify" and record["reviews"] == [] and requests.actual == 1
    assert repaired["updates"][-1]["text"] == text
    assert repaired["updates"][:-1] == original["updates"][:-1]
    assert {k:v for k,v in repaired.items() if k != "updates"} == {k:v for k,v in original.items() if k != "updates"}
    assert repaired["updates"][-1]["at"] == original["updates"][-1]["at"]
    assert repaired["updates"][-1]["sources"] == original["updates"][-1]["sources"]
    assert record["untrusted_proposals"][0]["repair"] == {"update": text}
    action, approved = review_gate.advance_review(checker, action, repaired, prepared, record, requests)
    assert action == "approve" and approved == repaired and requests.actual == 2
    wire = [json.loads(r["messages"][1]["content"]) for r in checker.client.requests]
    assert wire[0]["review_scope"] == wire[1]["review_scope"] == "latest_update"
    assert json.dumps(wire[0]["packet"]) == json.dumps(wire[1]["packet"])
    assert json.dumps(wire[0]["coverage_background"]) == json.dumps(wire[1]["coverage_background"])
    assert wire[1]["candidate"] == repaired
    assert checker.client.requests[1]["messages"][0]["content"] == review.UPDATE_VERIFY_PROMPT
    record.update(candidate=repaired, outcome="approved",
                  approval_key=digest([digest(repaired), digest(prepared["packet"]), record["policy_hash"],
                                       review_gate._context(prepared, record["policy_hash"])["binding_hash"]]))
    review_gate.validate_review_state(record, "approved", repaired, prepared)


@pytest.mark.parametrize("damage", ["title", "old-update", "date", "citation", "mode"])
def test_update_recovery_proof_cannot_be_replayed_for_history_or_another_scope(context, damage):
    cfg, _ = context
    case, prepared = update_case()
    record = {"candidate": case["candidate"], "reviews": [], "policy_hash": review.policy_hash(cfg),
              **review_gate.initial_review_state()}
    checker = reviewer(cfg, untrusted_update({"update": "Operators can use the supplied workaround."}))
    stage, candidate = review_gate.advance_review(checker, "review", case["candidate"], prepared, record,
                                                  review_gate.ReviewRequests(record))
    if damage == "title":
        candidate["title"] = "A rewritten old headline"
    elif damage == "old-update":
        candidate["updates"].insert(0, copy.deepcopy(candidate["updates"][-1]))
    elif damage == "date":
        candidate["updates"][-1]["at"] = "2026-11-12T12:00:00Z"
    elif damage == "citation":
        candidate["updates"][-1]["sources"] = [{"url": "https://example.org/unrelated", "title": "Unrelated"}]
    else:
        prepared["mode"] = "story"
    with pytest.raises(AnalysisError, match="damaged"):
        review_gate.advance_review(checker, stage, candidate, prepared, record, review_gate.ReviewRequests(record))
    assert checker.calls == 1


def test_invalid_route_identity_never_enters_untrusted_recovery(context):
    cfg, _ = context
    case, prepared = update_case()
    record = {"candidate": case["candidate"], "reviews": [], "policy_hash": review.policy_hash(cfg),
              **review_gate.initial_review_state()}
    checker = reviewer(cfg, untrusted_update({"update": "A proposed update."}, same_story="unlisted-target"))
    with pytest.raises(review.ReviewError, match="same_story"):
        review_gate.advance_review(checker, "review", case["candidate"], prepared, record,
                                  review_gate.ReviewRequests(record))
    assert record["reviews"] == record["untrusted_proposals"] == []
    assert record["request_budget"]["reserved"] == checker.calls == 1


def test_untrusted_merge_request_release_tag_is_rejected_before_followup(context):
    cfg, store = context
    row = pending(store, item(kind="gitlab_mr", upstream_state="merged"))
    checker = reviewer(cfg, inconsistent({"summary": "A revised merged change.", "tags": ["release"]}))
    with pytest.raises(review.InconsistentReview):
        run(cfg, store, row, Writer(analysis(state="merged")), checker)
    assert record(store)["untrusted_proposals"][0]["disposition"] == "labels"
    assert checker.calls == 1 and not store.stories()


def test_route_update_fallbacks_share_one_budget_and_operator_retry_starts_new_review(context):
    cfg, store = context
    target = _publish(store, item(url="https://example.org/incident", title="Directory authority overload",
                                  content="Operators report a directory authority overload."))
    incoming = item(url="https://example.org/followup", authority="official", title="An overload mitigation",
                    content="A new consensus method mitigates the authority overload.")
    row = pending(store, incoming)
    draft = analysis(title=incoming["title"], summary=incoming["content"], why_it_matters="",
                     evidence=[incoming["content"]])
    cfg["llm"]["fallback_base_urls"] = [f"https://fallback{n}.example/v1" for n in range(4)]
    failed = reviewer(cfg, *(FetchError("unavailable", status=500) for _ in range(5)))
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(draft), failed)
    assert record(store)["request_budget"]["reserved"] == 5
    # Keep the same policy identity while exercising a successful primary response.
    routed = reviewer(cfg, verdict(same_story=target["id"]))
    assert run(cfg, store, row, Writer(draft), routed)["status"] == "routed"
    assert job(store)["stage"] == "routed" and record(store)["request_budget"]["reserved"] == 6
    requeued = next(r for r in store.pending(10, LATER) if r["id"] == row["id"])
    update = update_analysis(update=incoming["content"], evidence=[incoming["content"]])
    checker = reviewer(cfg, verdict(update=True), verdict(update=True))
    with pytest.raises(review.ReviewLimitReached):
        run(cfg, store, requeued, Writer(update), checker)
    assert checker.calls == 1 and len(checker.client.requests) == 1
    assert record(store)["request_budget"]["reserved"] == 7
    assert len(store.stories()) == 1 and not store.stories()[0].get("updates")
    with store.db:
        review_gate.reset_review_work(store, row["id"])
        store.db.execute("UPDATE items SET status='pending',attempts=0,rejections=0 WHERE id=?", (row["id"],))
    reset = next(r for r in store.pending(10, LATER) if r["id"] == row["id"])
    assert record(store)["request_budget"]["reserved"] == 0
    assert run(cfg, store, reset, Writer(update), reviewer(cfg, verdict(update=True), verdict(update=True)))["status"] == "published"
    assert saved_audit(store)["request_budget"]["reserved"] == 2


@pytest.mark.parametrize("transfer", ["unlock", "merge", "locked-survivor"])
def test_routed_budget_survives_locked_commit_unlock_and_held_transfer(context, transfer):
    cfg, store = context
    target = _publish(store, item(url="https://example.org/locked-incident", title="Authority overload report",
                                  content="Operators report directory authority overload."))
    survivor = None
    if transfer != "unlock":
        survivor = _publish(store, item(url="https://example.org/earlier-incident", title="Earlier authority report",
                                        content="An earlier report describes directory authority overload."))
    cli.build(cfg, store)
    def lock(story):
        shown = editorial.show(store.db, story["id"])
        return editorial.correct(store.db, story["id"], {"priority": "normal"}, reason="Review this account.",
                                 expect_hash=shown["hash"], observed=LATER)
    lock(target)
    if transfer == "locked-survivor":
        lock(survivor)
    incoming = item(url="https://example.org/locked-followup", authority="official", title="A mitigation observation",
                    content="A new consensus method mitigates the authority overload.")
    row = pending(store, incoming)
    draft = analysis(title=incoming["title"], summary=incoming["content"], why_it_matters="",
                     evidence=[incoming["content"]])
    assert run(cfg, store, row, Writer(draft), reviewer(cfg, verdict(same_story=target["id"])))["status"] == "routed"
    routed = next(r for r in store.pending(10, LATER) if r["id"] == row["id"])
    update = update_analysis(update=incoming["content"], evidence=[incoming["content"]])
    assert run(cfg, store, routed, Writer(update), reviewer(cfg))["status"] == "locked"
    held_record = record(store)
    assert job(store)["stage"] == "locked" and held_record["request_budget"]["reserved"] == 1
    assert held_record["reviews"] == [] and not held_record.get("approval")
    destination = target
    if survivor is not None:
        editorial.merge(store.db, target["id"], survivor["id"], reason="Combine duplicate accounts.",
                        expect_hash=editorial.show(store.db, target["id"])["hash"],
                        base_url=cfg["site"]["base_url"], observed=LATER)
        destination = survivor
        assert record(store) == held_record
    if transfer != "merge":
        editorial.unlock(store.db, destination["id"], reason="Allow this update.",
                         expect_hash=editorial.show(store.db, destination["id"])["hash"], observed=LATER)
        assert record(store) == held_record
    resumed = next(r for r in store.pending(10, LATER) if r["id"] == row["id"])
    checker = reviewer(cfg, verdict(update=True), verdict(update=True))
    assert run(cfg, store, resumed, Writer(update), checker)["status"] == "published"
    assert checker.calls == 2 and saved_audit(store)["request_budget"]["reserved"] == 3
    assert not job(store)
    final = next(s for s in store.stories() if s["id"] == destination["id"])
    assert final["updates"][-1]["text"] == incoming["content"]


def test_damaged_locked_ledger_does_not_reset_on_unlock(context):
    cfg, store = context
    target = _publish(store, item(url="https://example.org/locked", title="An incident report"))
    shown = editorial.show(store.db, target["id"])
    editorial.correct(store.db, target["id"], {"priority": "normal"}, reason="Review this report.",
                      expect_hash=shown["hash"], observed=LATER)
    row = pending(store, item(url="https://example.org/followup-note", title="New incident information"))
    assert run(cfg, store, row, Writer(), reviewer(cfg, verdict(same_story=target["id"])))["status"] == "routed"
    routed = next(r for r in store.pending(10, LATER) if r["id"] == row["id"])
    assert run(cfg, store, routed, Writer(update_analysis()), reviewer(cfg))["status"] == "locked"
    broken = record(store)
    broken.pop("request_budget")
    with store.db:
        store.db.execute("UPDATE review_jobs SET record_json=? WHERE item_id=?", (json.dumps(broken), row["id"]))
    editorial.unlock(store.db, target["id"], reason="Resume work.",
                     expect_hash=editorial.show(store.db, target["id"])["hash"], observed=LATER)
    resumed = next(r for r in store.pending(10, LATER) if r["id"] == row["id"])
    checker = reviewer(cfg)
    with pytest.raises(AnalysisError, match="ledger"):
        run(cfg, store, resumed, Writer(update_analysis()), checker)
    assert checker.calls == 0 and not store.stories()[0].get("updates")


def test_untrusted_route_waits_for_fresh_reply_and_carries_journal_into_update(context):
    cfg, store = context
    target = _publish(store, item(url="https://example.org/incident-account", title="An authority incident"))
    incoming = item(url="https://example.org/incident-observation", title="A mitigation observation",
                    content="An operator reports a lower queue depth after mitigation.")
    row = pending(store, incoming)
    invalid = inconsistent({"summary": incoming["content"]})
    invalid["same_story"] = target["id"]
    associations = []
    checker = reviewer(cfg, invalid, verdict(same_story=target["id"]),
                       before=lambda: associations.append(store.db.execute("SELECT story_id FROM items WHERE id=?",
                                                                           (row["id"],)).fetchone()[0]))
    assert run(cfg, store, row, Writer(), checker)["status"] == "routed"
    assert associations == [None, None]
    assert record(store)["request_budget"]["reserved"] == 2
    assert len(record(store)["reviews"]) == 1
    assert record(store)["untrusted_proposals"][0]["disposition"] == "checked_approve"
    routed = next(r for r in store.pending(10, LATER) if r["id"] == row["id"])
    update = update_analysis(update=incoming["content"], evidence=[incoming["content"]])
    assert run(cfg, store, routed, Writer(update), reviewer(cfg, verdict(update=True), verdict(update=True)))["status"] == "published"
    audit = saved_audit(store)
    assert audit["request_budget"]["reserved"] == 4
    assert audit["untrusted_proposals"][0]["mode"] == "story"
    assert audit["untrusted_proposals"][0]["disposition"] == "discarded_context"
    assert len(audit["reviews"]) == 2 and audit["reviews"][0]["request"] == 3
