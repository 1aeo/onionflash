"""Corrupted saved identity cannot turn an automatic handoff into a new budget."""
import json

import pytest

from helpers import update_analysis, verdict
from onionflash import editorial, review_gate
from onionflash.analyze import AnalysisError
from onionflash.transport import FetchError
from helpers import seed_source_story as _publish
from helpers import analysis, make_item as item
from helpers import LATER, Writer, job, pending, run_gate as run
from test_review_request_budget import context, record, reviewer, saved_audit


def routed_with_spent_requests(cfg, store):
    target = _publish(store, item(url="https://example.org/account", title="An authority incident"))
    incoming = item(url="https://example.org/followup", title="Authority mitigation observation",
                    content="An operator reports lower queue depth after mitigation.", authority="official")
    row = pending(store, incoming)
    draft = analysis(title=incoming["title"], summary=incoming["content"], why_it_matters="",
                     evidence=[incoming["content"]])
    cfg["llm"]["fallback_base_urls"] = [f"https://fallback{n}.example/v1" for n in range(4)]
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(draft), reviewer(cfg, *(FetchError("unavailable", status=500) for _ in range(5))))
    assert run(cfg, store, row, Writer(draft), reviewer(cfg, verdict(same_story=target["id"])))["status"] == "routed"
    assert record(store)["request_budget"]["reserved"] == 6
    return target, incoming, row


@pytest.mark.parametrize("transition", ["routed", "locked", "unlocked"])
@pytest.mark.parametrize("damage", ["invalid-json", "non-object", "missing-row", "missing-hash", "wrong-hash",
                                    "wrong-id", "wrong-payload", "conflicting-snapshot", "binding-item",
                                    "missing-marker", "boolean-marker", "missing-input-hash", "wrong-input-hash"])
def test_corrupt_handoff_identity_fails_before_drafting_or_spending(context, transition, damage):
    cfg, store = context
    target, incoming, row = routed_with_spent_requests(cfg, store)
    if transition != "routed":
        editorial.correct(store.db, target["id"], {"priority": "normal"}, reason="Inspect this account.",
                          expect_hash=editorial.show(store.db, target["id"])["hash"], observed=LATER)
        current = next(r for r in store.pending(10, LATER) if r["id"] == row["id"])
        assert run(cfg, store, current, Writer(update_analysis()), reviewer(cfg))["status"] == "locked"
        if transition == "unlocked":
            editorial.unlock(store.db, target["id"], reason="Resume this account.",
                             expect_hash=editorial.show(store.db, target["id"])["hash"], observed=LATER)
        else:
            with store.db:
                store.db.execute("UPDATE items SET status='pending' WHERE id=?", (row["id"],))
    audit = record(store)
    envelope = json.loads(job(store)["envelope_json"])
    assert audit["input_proof"] == 1 and "input_row" not in audit
    if damage == "missing-row":
        envelope.pop("row")
    elif damage == "missing-hash":
        envelope["row"].pop("content_hash")
    elif damage == "wrong-hash":
        envelope["row"]["content_hash"] = "f" * 64
    elif damage == "wrong-id":
        envelope["row"]["id"] = "f" * 24
    elif damage == "wrong-payload":
        payload = json.loads(envelope["row"]["payload"])
        payload["content"] += " An invented revision."
        envelope["row"]["payload"] = json.dumps(payload)
    elif damage == "conflicting-snapshot":
        audit["input_row"] = {**envelope["row"], "story_id": "f" * 24}
    elif damage == "binding-item":
        envelope["binding"]["item"] = "f" * 64
    elif damage == "missing-marker":
        audit.pop("input_proof")
    elif damage == "boolean-marker":
        audit["input_proof"] = True
    elif damage == "missing-input-hash":
        audit.pop("input_hash")
    elif damage == "wrong-input-hash":
        audit["input_hash"] = "f" * 64
    encoded = "{" if damage == "invalid-json" else "[]" if damage == "non-object" else json.dumps(audit)
    with store.db:
        store.db.execute("UPDATE review_jobs SET record_json=?,envelope_json=? WHERE item_id=?",
                         (encoded, json.dumps(envelope), row["id"]))
    before = job(store)
    current = next(r for r in store.pending(10, LATER) if r["id"] == row["id"])
    writer, checker = Writer(update_analysis(update=incoming["content"])), reviewer(cfg)
    with pytest.raises(AnalysisError, match="damaged") as error:
        run(cfg, store, current, writer, checker)
    assert error.value.code == "app.damaged_job" and not writer.calls and checker.calls == 0
    assert job(store) == before and not store.stories()[0].get("updates")


@pytest.mark.parametrize("change", ["source", "policy"])
def test_coherent_new_source_or_policy_still_starts_a_new_review(context, change):
    cfg, store = context
    _, incoming, row = routed_with_spent_requests(cfg, store)
    if change == "source":
        incoming = {**incoming, "content": incoming["content"] + " A later measurement is also available.", "updated_at": LATER}
        assert store.ingest(incoming, LATER)
    else:
        cfg["review"]["model"] = "another-review-model"
    current = next(r for r in store.pending(10, LATER) if r["id"] == row["id"])
    writer = Writer(update_analysis(update=incoming["content"], evidence=[incoming["content"]]))
    checker = reviewer(cfg, verdict(update=True), verdict(update=True))
    assert run(cfg, store, current, writer, checker)["status"] == "published"
    assert len(writer.calls) == 1 and checker.calls == 2
    assert saved_audit(store)["request_budget"]["reserved"] == 2


def test_corrupt_job_is_not_silently_erased_by_a_citation_transition(context):
    cfg, store = context
    target = _publish(store, item(kind="gitlab_mr", upstream_state="merged", title="Add a guard scheduling option"),
                      draft=analysis(state="merged"))
    tag = item(kind="tag", authority="official", url="https://example.org/tags/tor-0.4.9.99",
               title="tor-0.4.9.99", content="")
    row = pending(store, tag)
    with store.db:
        store.db.execute("UPDATE items SET story_id=? WHERE id=?", (target["id"], row["id"]))
    row = next(r for r in store.pending(10, LATER) if r["id"] == row["id"])
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), reviewer(cfg, FetchError("unavailable", status=500)))
    editorial.correct(store.db, target["id"], {"state": "released", "category": "release", "tags": ["release"]},
                      reason="Record release status.", expect_hash=editorial.show(store.db, target["id"])["hash"], observed=LATER)
    with store.db:
        store.db.execute("UPDATE review_jobs SET record_json='{' WHERE item_id=?", (row["id"],))
    before = job(store)
    checker = reviewer(cfg)
    with pytest.raises(AnalysisError, match="damaged"):
        run(cfg, store, row, Writer(), checker)
    assert checker.calls == 0 and job(store) == before
