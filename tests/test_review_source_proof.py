"""Source proof stays verifiable without duplicating a prepared source snapshot."""
import copy
import json

import pytest

from helpers import LATER, Writer, job, pending, run_gate as run, verdict
from onionflash import review_gate
from onionflash.llm import AnalysisError
from onionflash.transport import FetchError
from onionflash.util import digest
from test_review_request_budget import context, record, reviewer, saved_audit


def pause_before_prepare(cfg, store, row, monkeypatch):
    def pause(*_args):
        raise RuntimeError("Draft was saved before preparation")
    with monkeypatch.context() as patch:
        patch.setattr(store, "prepare_candidate", pause)
        with pytest.raises(RuntimeError, match="before preparation"):
            run(cfg, store, row, Writer(), reviewer(cfg))
    return copy.deepcopy(job(store))


def test_new_jobs_keep_one_source_snapshot_in_the_active_owner(context, monkeypatch):
    cfg, store = context
    row = pending(store)
    drafted = pause_before_prepare(cfg, store, row, monkeypatch)
    draft_record = json.loads(drafted["record_json"])
    assert drafted["envelope_json"] is None
    assert draft_record["schema_version"] == review_gate.REVIEW_STATE_VERSION == 3
    assert draft_record["impact_audits"] == []
    assert draft_record["input_proof"] == 1 and draft_record["input_row"] == row
    assert draft_record["input_hash"] == row["content_hash"]
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), reviewer(cfg, FetchError("Temporary error", status=500)))
    prepared = job(store)
    assert record(store)["input_proof"] == 1 and "input_row" not in record(store)
    assert json.loads(prepared["envelope_json"])["row"] == row
    assert record(store)["request_budget"]["reserved"] == 1


@pytest.mark.parametrize("legacy", ["compact", "full"])
def test_legacy_source_proof_is_validated_before_policy_reset(context, legacy):
    cfg, store = context
    row = pending(store)
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), reviewer(cfg, FetchError("Temporary error", status=500)))
    old = record(store)
    for field in ("input_proof", "request_budget", "untrusted_proposals", "impact_audits"):
        old.pop(field)
    if legacy == "full":
        old["input_row"] = json.loads(job(store)["envelope_json"])["row"]
        old.pop("input_hash")
    old["schema_version"] = 1
    old["policy_hash"] = digest(["legacy review policy"])
    with store.db:
        store.db.execute("UPDATE review_jobs SET policy_hash=?,record_json=? WHERE item_id=?",
                         (old["policy_hash"], json.dumps(old), row["id"]))
    writer, checker = Writer(), reviewer(cfg, verdict(), verdict())
    assert run(cfg, store, row, writer, checker)["status"] == "published"
    assert not writer.calls and checker.calls == 2
    final = saved_audit(store)
    assert final["input_proof"] == 1 and final["input_hash"] == row["content_hash"]
    assert "input_row" not in final and final["request_budget"]["reserved"] == 2


def test_compact_draft_without_source_proof_requires_explicit_retry(context, monkeypatch):
    cfg, store = context
    row = pending(store)
    pause_before_prepare(cfg, store, row, monkeypatch)
    old = record(store)
    for field in ("input_proof", "input_row", "request_budget", "untrusted_proposals", "impact_audits"):
        old.pop(field)
    old["schema_version"] = 1
    old_policy = digest(["legacy draft policy"])
    with store.db:
        store.db.execute("UPDATE review_jobs SET policy_hash=?,record_json=? WHERE item_id=?",
                         (old_policy, json.dumps(old), row["id"]))
    before = job(store)
    writer, checker = Writer(), reviewer(cfg)
    with pytest.raises(AnalysisError, match="explicit retry") as error:
        run(cfg, store, row, writer, checker)
    assert error.value.code == "app.source_proof_unavailable"
    assert not writer.calls and checker.calls == 0 and job(store) == before
    with store.db:
        review_gate.reset_review_work(store, row["id"])
    assert record(store)["input_row"] == row and record(store)["input_proof"] == 1
    assert run(cfg, store, row, Writer(), reviewer(cfg, verdict(), verdict()))["status"] == "published"


@pytest.mark.parametrize("policy_change", [False, True])
def test_removing_new_format_markers_cannot_downgrade_to_compact_legacy(context, policy_change):
    cfg, store = context
    row = pending(store)
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), reviewer(cfg, FetchError("Temporary error", status=500)))
    damaged = record(store)
    for field in ("input_proof", "request_budget", "untrusted_proposals"):
        damaged.pop(field)
    with store.db:
        store.db.execute("UPDATE review_jobs SET record_json=? WHERE item_id=?", (json.dumps(damaged), row["id"]))
    before = job(store)
    if policy_change:
        cfg["review"]["model"] = "changed-review-policy"
    writer, checker = Writer(), reviewer(cfg)
    with pytest.raises(AnalysisError, match="damaged") as error:
        run(cfg, store, row, writer, checker)
    assert error.value.code == "app.damaged_job"
    assert not writer.calls and checker.calls == 0 and job(store) == before


@pytest.mark.parametrize("policy_change", [False, True])
def test_new_draft_missing_marker_is_not_a_full_legacy_record(context, monkeypatch, policy_change):
    cfg, store = context
    row = pending(store)
    pause_before_prepare(cfg, store, row, monkeypatch)
    damaged = record(store)
    damaged.pop("input_proof")
    with store.db:
        store.db.execute("UPDATE review_jobs SET record_json=? WHERE item_id=?", (json.dumps(damaged), row["id"]))
    before = job(store)
    if policy_change:
        cfg["review"]["model"] = "changed-review-policy"
    writer, checker = Writer(), reviewer(cfg)
    with pytest.raises(AnalysisError, match="damaged") as error:
        run(cfg, store, row, writer, checker)
    assert error.value.code == "app.damaged_job"
    assert not writer.calls and checker.calls == 0 and job(store) == before


@pytest.mark.parametrize("damage", ["missing-version", "boolean-version", "unknown-version", "request_budget", "untrusted_proposals"])
def test_new_record_identity_and_ledgers_are_required_across_policy_changes(context, damage):
    cfg, store = context
    row = pending(store)
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), reviewer(cfg, FetchError("Temporary error", status=500)))
    damaged = record(store)
    if damage == "missing-version":
        damaged.pop("schema_version")
    elif damage == "boolean-version":
        damaged["schema_version"] = True
    elif damage == "unknown-version":
        damaged["schema_version"] = 99
    else:
        damaged.pop(damage)
    with store.db:
        store.db.execute("UPDATE review_jobs SET record_json=? WHERE item_id=?", (json.dumps(damaged), row["id"]))
    before = job(store)
    cfg["review"]["model"] = "changed-review-policy"
    writer, checker = Writer(), reviewer(cfg)
    with pytest.raises(AnalysisError) as error:
        run(cfg, store, row, writer, checker)
    assert error.value.code == "app.damaged_job"
    assert not writer.calls and checker.calls == 0 and job(store) == before
