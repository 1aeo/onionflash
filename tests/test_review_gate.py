"""The final-candidate gate resumes completed stages and never publishes unchecked."""

import contextlib
import copy
import json
import sqlite3

import pytest

from onionflash import editorial, rejection, review, review_gate
from onionflash.analyze import AnalysisError, tag_notice
from onionflash.store import Store
from onionflash.util import digest
from test_core import DATE, analysis, config, item


LATER = "2026-11-10T12:00:00Z"


def verdict(action="approve", *, repair=None):
    checks = {name: {"outcome": "pass", "source_refs": ["S1"], "reason": "Supported by the supplied source."}
              for name in review.CRITERIA}
    issues = []
    if action != "approve":
        checks["operational_advice"]["outcome"] = "fail"
        issues = [{"criterion": "operational_advice", "source_refs": ["S1"],
                   "explanation": "The source does not instruct relay operators to change configuration."}]
    return {"verdict": action, "criteria": checks, "issues": issues, "repair": repair}


class Writer:
    def __init__(self, result=None):
        self.result, self.calls = result or analysis(), []

    def analyze(self, incoming):
        self.calls.append(copy.deepcopy(incoming))
        return copy.deepcopy(self.result)


class Reviewer:
    """Returns validated verdicts, as review.Reviewer does."""
    def __init__(self, *responses):
        self.responses, self.calls = list(responses), []

    def review(self, candidate, packet, *, verification=False):
        self.calls.append((copy.deepcopy(candidate), copy.deepcopy(packet), verification))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return review.validate_review(response() if callable(response) else copy.deepcopy(response), packet)


@pytest.fixture
def context(tmp_path):
    cfg = config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        yield cfg, store


def pending(store, incoming=None):
    store.ingest(incoming or item(), DATE)
    return store.pending(1, LATER)[0]


def run(cfg, store, row, writer, checker, **kwargs):
    return review_gate.process_item(cfg, store, row, writer, checker, LATER, **kwargs)


def job(store):
    row = store.db.execute("SELECT * FROM review_jobs").fetchone()
    return dict(row) if row else None


def seed_legacy(store, incoming=None, result=None):
    incoming = incoming or item(content=item()["content"] * 3)
    store.ingest(incoming, incoming["updated_at"])
    row = store.pending(1, LATER)[0]
    prepared = store.prepare_candidate(row, result or analysis(), DATE)
    data = prepared["payload"]
    with store.db:
        store.db.execute("INSERT INTO stories VALUES(?,?,?,?,?)", (data["id"], prepared["cluster_key"],
                         json.dumps(data), data["published_at"], data["updated_at"]))
        store.db.execute("UPDATE items SET status='published',story_id=? WHERE id=?", (data["id"], row["id"]))
    return incoming, data["id"]


def test_approved_exact_candidate_commits_and_keeps_private_complete_audit(context):
    cfg, store = context
    row = pending(store)
    writer, checker = Writer(), Reviewer(verdict())
    result = run(cfg, store, row, writer, checker)
    assert result == {"status": "published", "writer_calls": 1, "review_calls": 1, "cache_hit": False}
    assert job(store) is None
    assert store.stories()[0]["summary"] == checker.calls[0][0]["summary"]
    saved = store.db.execute("SELECT review_record FROM analyses").fetchone()[0]
    audit = json.loads(saved)
    assert audit["writer"]["result"] == analysis()
    assert audit["prepared"]["packet"]["sources"]
    assert len(audit["reviews"]) == 1 and audit["outcome"] == "approved"


def test_a_new_story_is_dated_when_the_review_commits_not_when_the_item_started(context, monkeypatch):
    cfg, store = context
    row = pending(store)
    # The item starts before midnight; the review returns and commits after it.
    monkeypatch.setattr(review_gate, "now_iso", lambda: "2026-11-11T00:01:00Z")
    review_gate.process_item(cfg, store, row, Writer(), Reviewer(verdict()), "2026-11-10T23:59:00Z")
    assert store.stories()[0]["added_at"] == "2026-11-11T00:01:00Z"


@pytest.mark.parametrize("failure", [AnalysisError("timeout", retryable=True), {}])
def test_review_timeout_or_malformed_verdict_resumes_without_regenerating_writer(context, failure):
    cfg, store = context
    row = pending(store)
    writer, checker = Writer(), Reviewer(failure)
    with pytest.raises(AnalysisError) as caught:
        run(cfg, store, row, writer, checker)
    # A timeout backs off; a malformed verdict is one of the item's three strikes.
    assert caught.value.retryable == isinstance(failure, AnalysisError) and job(store)["stage"] == "review"
    assert len(store.stories()) == 0
    paused = Reviewer(verdict())
    assert run(cfg, store, row, Writer(), paused, allow_network=False)["status"] == "deferred"
    assert paused.calls == [] and job(store)["stage"] == "review"
    next_writer, next_checker = Writer(), Reviewer(verdict())
    result = run(cfg, store, row, next_writer, next_checker)
    assert result["status"] == "published" and result["writer_calls"] == 0
    assert next_writer.calls == [] and len(next_checker.calls) == 1


def test_repair_requires_fresh_verification_and_resumes_that_exact_stage(context):
    cfg, store = context
    row = pending(store)
    writer = Writer(analysis(why_it_matters="Operators must edit their relay configuration."))
    first = Reviewer(verdict("revise", repair={"why_it_matters": ""}), AnalysisError("timeout", retryable=True))
    with pytest.raises(AnalysisError):
        run(cfg, store, row, writer, first)
    assert [call[2] for call in first.calls] == [False, True]
    assert job(store)["stage"] == "verify" and len(store.stories()) == 0
    repaired = first.calls[1][0]
    assert repaired["why_it_matters"] == ""
    second = Reviewer(verdict())
    result = run(cfg, store, row, Writer(), second)
    assert result["writer_calls"] == 0 and result["review_calls"] == 1
    assert second.calls == [(repaired, first.calls[1][1], True)]
    audit = json.loads(store.db.execute("SELECT review_record FROM analyses").fetchone()[0])
    assert [entry["stage"] for entry in audit["reviews"]] == ["review", "verification"]


@pytest.mark.parametrize("second", [verdict("hold"), verdict("revise", repair={"summary": "A different proposed rewrite."}),
                                    verdict("revise")], ids=["hold", "revise", "revise-without-repair"])
def test_second_nonapproval_holds_once_and_never_rewrites_again(context, second):
    cfg, store = context
    row = pending(store)
    checker = Reviewer(verdict("revise", repair={"why_it_matters": ""}), second)
    result = run(cfg, store, row, Writer(), checker)
    assert result["status"] == "held" and result["review_calls"] == 2
    assert store.pending_count() == 0 and store.rejected_count() == 1 and len(store.stories()) == 0
    assert job(store)["stage"] == "held"
    audit = json.loads(store.db.execute("SELECT review_record FROM analyses").fetchone()[0])
    assert audit["outcome"] == "held" and len(audit["reviews"]) == 2


def test_zero_repairs_holds_and_explicit_retry_reuses_writer(context):
    cfg, store = context
    cfg["review"]["max_repairs"] = 0
    row = pending(store)
    result = run(cfg, store, row, Writer(), Reviewer(verdict("revise", repair={"why_it_matters": ""})))
    assert result["status"] == "held" and result["review_calls"] == 1
    with store.db:
        store.db.execute("UPDATE items SET status='pending',attempts=0,rejections=0 WHERE id=?", (row["id"],))
        review_gate.reset_review_work(store, row["id"])
    retry = dict(store.db.execute("SELECT * FROM items WHERE id=?", (row["id"],)).fetchone())
    writer = Writer()
    result = run(cfg, store, retry, writer, Reviewer(verdict()))
    assert result["status"] == "published" and writer.calls == []


@pytest.mark.parametrize("repair", [None, {"title": analysis()["title"]}, {"title": ""}],
                         ids=["missing", "unchanged", "invalid"])
def test_unusable_repair_holds_after_one_call_for_operator_inspection(context, repair):
    cfg, store = context
    row = pending(store)
    result = run(cfg, store, row, Writer(), Reviewer(verdict("revise", repair=repair)))
    assert result["status"] == "held" and result["review_calls"] == 1
    assert [entry["id"] for entry in rejection.list_items(store)["items"]] == [row["id"]]
    assert rejection.show_item(store, row["id"])["final_review"]["latest_review"]["verdict"] == "revise"


def test_completed_approval_resumes_after_crash_without_any_model_call(context, monkeypatch):
    cfg, store = context
    row = pending(store)
    commit = store.commit_candidate
    monkeypatch.setattr(store, "commit_candidate", lambda *args, **kw: (_ for _ in ()).throw(RuntimeError("simulated crash before commit")))
    with pytest.raises(RuntimeError, match="simulated crash"):
        run(cfg, store, row, Writer(), Reviewer(verdict()))
    assert job(store)["stage"] == "approved" and len(store.stories()) == 0
    monkeypatch.setattr(store, "commit_candidate", commit)
    writer, checker = Writer(), Reviewer()
    result = run(cfg, store, row, writer, checker, allow_network=False)
    assert result["status"] == "published" and result["cache_hit"]
    assert writer.calls == checker.calls == [] and job(store) is None


def test_changed_source_invalidates_staged_draft_and_prior_approval(context, monkeypatch):
    cfg, store = context
    row = pending(store)
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), Reviewer(AnalysisError("timeout", retryable=True)))
    incoming = item(content=item()["content"] + " A later source correction.", updated_at=LATER)
    store.ingest(incoming, LATER)
    changed = store.pending(1, LATER)[0]
    assert changed["content_hash"] != row["content_hash"]
    writer = Writer()
    result = run(cfg, store, changed, writer, Reviewer(verdict()))
    assert result["writer_calls"] == 1 and len(writer.calls) == 1


def test_source_change_during_review_fails_commit_cas(context):
    cfg, store = context
    row = pending(store)
    def change_source():
        store.ingest(item(content="Changed while the final reviewer was running.", updated_at=LATER), LATER)
        return verdict()
    result = run(cfg, store, row, Writer(), Reviewer(change_source))
    assert result["status"] == "stale" and len(store.stories()) == 0


def test_policy_change_reuses_writer_but_requires_a_new_review(context):
    cfg, store = context
    row = pending(store)
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), Reviewer(AnalysisError("timeout", retryable=True)))
    cfg["review"]["model"] = "different-review-model"
    result = run(cfg, store, row, Writer(), Reviewer(verdict()))
    assert result["writer_calls"] == 0 and result["review_calls"] == 1 and not result["cache_hit"]


def test_final_merge_reviews_retained_old_bad_text_and_commits_only_the_verified_repair(context):
    cfg, store = context
    wrong = "Operators must update their configurations to exclude the node."
    original = item(content=item()["content"] * 3, updated_at="2026-11-09T12:00:00Z")
    seed_legacy(store, original, analysis(why_it_matters=wrong))
    incoming = item(url="https://example.org/news/mirror", source_id="mirror", content=original["content"])
    row = pending(store, incoming)
    checker = Reviewer(verdict("revise", repair={"why_it_matters": ""}), verdict())
    result = run(cfg, store, row, Writer(analysis(why_it_matters="The report concerns old keys.")), checker)
    assert checker.calls[0][0]["why_it_matters"] == wrong
    assert len(checker.calls[0][1]["sources"]) == 2
    assert result["status"] == "published" and store.stories()[0]["why_it_matters"] == ""
    assert len(store.stories()) == 1


def test_human_lock_during_review_invalidates_approval_and_preserves_operator_text(context):
    cfg, store = context
    original, story_id = seed_legacy(store)
    row = pending(store, {**original, "content": original["content"] + " A later report.", "updated_at": LATER})
    def human_edit():
        editorial.correct(store.db, story_id, {"why_it_matters": "Operator-reviewed wording."},
                          reason="Corrected unsupported advice.", expect_hash=editorial.show(store.db, story_id)["hash"], observed=LATER)
        return verdict()
    result = run(cfg, store, row, Writer(), Reviewer(human_edit))
    assert result["status"] == "stale"
    assert store.stories()[0]["why_it_matters"] == "Operator-reviewed wording."
    second = run(cfg, store, row, Writer(), Reviewer(), allow_network=False)
    assert second["status"] == "locked" and second["writer_calls"] == second["review_calls"] == 0


def test_tag_exemption_depends_on_final_candidate_not_incoming_kind(context):
    cfg, store = context
    original = item(title="Tor 0.4.9.16 released", kind="feed", content="Tor 0.4.9.16 was released with an announced change.")
    seed_legacy(store, original, analysis(title="Tor release announcement"))
    tag = item(url="https://example.org/tags/tor-0.4.9.16", title="tor-0.4.9.16", kind="tag", content="")
    row = pending(store, tag)
    checker = Reviewer(verdict())
    result = run(cfg, store, row, Writer(tag_notice(tag)), checker)
    assert result["review_calls"] == 1 and checker.calls[0][0]["title"] == "Tor release announcement"


def test_fully_deterministic_tag_can_finish_with_network_disabled(context):
    cfg, store = context
    tag = item(title="tor-0.4.9.16", kind="tag", content="")
    row = pending(store, tag)
    checker = Reviewer()
    result = run(cfg, store, row, Writer(tag_notice(tag)), checker, allow_network=False)
    assert result["status"] == "deterministic" and checker.calls == []


def test_network_disabled_defers_new_network_work_without_failure(context):
    cfg, store = context
    row = pending(store)
    writer, checker = Writer(), Reviewer()
    result = run(cfg, store, row, writer, checker, allow_network=False)
    assert result["status"] == "deferred" and writer.calls == checker.calls == []
    assert store.pending_count() == 1 and store.rejected_count() == 0


def test_missing_retained_source_holds_without_a_review_call(context):
    cfg, store = context
    original = item(content=item()["content"] * 3, updated_at="2026-11-09T12:00:00Z")
    seed_legacy(store, original)
    with store.db:
        body = json.loads(store.db.execute("SELECT payload FROM items WHERE id=?", (original["id"],)).fetchone()[0])
        body.pop("content")
        store.db.execute("UPDATE items SET payload=? WHERE id=?", (json.dumps(body), original["id"]))
    row = pending(store, item(url="https://example.org/news/mirror", source_id="mirror", content=original["content"]))
    result = run(cfg, store, row, Writer(), Reviewer())
    assert result["status"] == "held" and result["review_calls"] == 0


def test_cache_cannot_treat_an_approve_boolean_as_seven_passing_checks(context):
    cfg, store = context
    row = pending(store)
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), Reviewer(AnalysisError("timeout", retryable=True)))
    saved = job(store)
    prepared = json.loads(saved["envelope_json"])
    key = review_gate._approval_key(prepared["candidate"], prepared, saved["policy_hash"])
    with store.db:
        store.db.execute("INSERT INTO review_approvals VALUES(?,?,?,?,?,?,?,?,?)", (
            key, prepared["candidate_hash"], prepared["source_hash"], saved["policy_hash"], prepared["binding_hash"],
            json.dumps({"verdict": "approve"}), "{}", LATER, LATER))
    result = run(cfg, store, row, Writer(), Reviewer(verdict()))
    assert result["review_calls"] == 1 and not result["cache_hit"]


def test_cache_pruning_retains_active_approval_jobs(context, monkeypatch):
    cfg, store = context
    cfg["review"]["max_cache_entries"] = 1
    row = pending(store)
    monkeypatch.setattr(store, "commit_candidate", lambda *args, **kw: (_ for _ in ()).throw(RuntimeError("crash")))
    with pytest.raises(RuntimeError):
        run(cfg, store, row, Writer(), Reviewer(verdict()))
    active = job(store)["approval_key"]
    with store.db:
        for n in range(3):
            store.db.execute("INSERT INTO review_approvals VALUES(?,?,?,?,?,?,?,?,?)", (
                f"unused-{n}", "c", "s", "p", "b", "{}", "{}", DATE, DATE))
    review_gate._prune(store, 1)
    assert store.db.execute("SELECT 1 FROM review_approvals WHERE key=?", (active,)).fetchone()
    assert store.db.execute("SELECT COUNT(*) FROM review_approvals").fetchone()[0] == 2
    assert job(store)["stage"] == "approved"


def test_status_reads_stage_counts_without_creating_tables_or_exposing_audit(context):
    cfg, store = context
    assert review_gate.status(store) == {"stages": {}, "approval_cache_entries": 0}
    assert not store.db.execute("SELECT 1 FROM sqlite_master WHERE name='review_jobs'").fetchone()
    row = pending(store)
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), Reviewer(AnalysisError("timeout", retryable=True)))
    assert review_gate.status(store) == {"stages": {"review": 1}, "approval_cache_entries": 0}
    run(cfg, store, row, Writer(), Reviewer(verdict("hold")))
    assert review_gate.status(store) == {"stages": {"held": 1}, "approval_cache_entries": 0}


def test_operator_retry_preserves_held_audit_and_reuses_the_completed_draft(context):
    cfg, store = context
    row = pending(store)
    assert run(cfg, store, row, Writer(), Reviewer(verdict("hold")))["status"] == "held"
    rejection.retry_item(store, row["id"], row["content_hash"], "Reviewed new validation policy", cfg["llm"], LATER)
    previous = json.loads(store.db.execute("SELECT superseded_analysis_json FROM rejection_actions").fetchone()[0])
    audit = json.loads(previous["review_record"])
    assert audit["outcome"] == "held" and audit["reviews"][0]["result"]["verdict"] == "hold"
    assert job(store)["stage"] == "drafted"
    retry = store.pending(1, LATER)[0]
    writer = Writer()
    assert run(cfg, store, retry, writer, Reviewer(verdict()))["status"] == "published"
    assert writer.calls == []


def test_a_source_that_reverts_to_a_held_revision_is_held_again_without_a_review(context):
    cfg, store = context
    assert run(cfg, store, pending(store), Writer(), Reviewer(verdict("hold")))["status"] == "held"
    store.ingest(item(content=item()["content"] + " Edited."), DATE)  # a revision that is never drafted
    assert run(cfg, store, store.pending(1, LATER)[0], Writer(), Reviewer(), allow_network=False)["status"] == "deferred"
    store.ingest(item(), DATE)
    checker = Reviewer(verdict())
    assert run(cfg, store, store.pending(1, LATER)[0], Writer(), checker)["status"] == "held"
    assert checker.calls == []


def test_ignored_writer_result_cannot_overwrite_a_concurrent_source_update(context):
    cfg, store = context
    row = pending(store)
    class ChangingWriter:
        def analyze(self, _item):
            store.ingest(item(content="Changed source while writer was running.", updated_at=LATER), LATER)
            return analysis(publish=False)
    result = run(cfg, store, row, ChangingWriter(), Reviewer())
    assert result["status"] == "stale" and store.pending_count() == 1
    assert store.db.execute("SELECT COUNT(*) FROM analyses").fetchone()[0] == 0


def test_rejected_show_explains_structured_hold_with_the_actual_candidate_and_passages(context):
    cfg, store = context
    row = pending(store)
    assert run(cfg, store, row, Writer(), Reviewer(verdict("hold")))["status"] == "held"
    before = list(store.db.iterdump())
    shown = rejection.show_item(store, row["id"])["final_review"]
    assert shown["stage"] == "held"
    assert shown["candidate"]["title"] == analysis()["title"]
    assert shown["latest_review"]["verdict"] == "hold"
    assert shown["latest_review"]["criteria"]["operational_advice"]["outcome"] == "fail"
    assert shown["latest_review"]["issues"][0]["source_refs"] == ["S1"]
    assert shown["source_packet"]["sources"][0]["passages"][0]["id"] == "S1:P1"
    assert list(store.db.iterdump()) == before


def test_rejected_show_displays_repaired_candidate_pending_independent_verification(context):
    cfg, store = context
    row = pending(store)
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), Reviewer(verdict("revise", repair={"why_it_matters": ""}),
                                               AnalysisError("timeout", retryable=True)))
    shown = rejection.show_item(store, row["id"])["final_review"]
    assert shown["stage"] == "verify" and shown["candidate"]["why_it_matters"] == ""
    assert shown["latest_review"]["verdict"] == "revise"
    assert shown["latest_review"]["candidate_hash"] != digest(shown["candidate"])


def test_rejected_show_excludes_unrelated_provider_and_private_audit_fields(context):
    cfg, store = context
    row = pending(store)
    run(cfg, store, row, Writer(), Reviewer(verdict("hold")))
    saved = job(store)
    record = json.loads(saved["record_json"])
    source = record["prepared"]["packet"]["sources"][0]
    for target in (record, source, source["passages"][0]):
        target["provider_response"] = "DO NOT PRINT PROVIDER RESPONSE"
    for change in ({}, {"api_key": "DO NOT PRINT CREDENTIAL"}):
        record["prepared"]["candidate"].update(change)
        with store.db:
            store.db.execute("UPDATE review_jobs SET record_json=?", (json.dumps(record),))
        shown = rejection.show_item(store, row["id"])["final_review"]
        # Unknown fields are dropped; a malformed candidate hash fails closed.
        assert "DO NOT PRINT" not in json.dumps(shown) and ("error" in shown) == bool(change)


@pytest.mark.parametrize("saved", ["not JSON", '{"bad":NaN}', '{"bad":"\\ud800"}', "oversized"])
def test_rejected_show_bounds_and_safely_rejects_bad_review_records(context, saved):
    cfg, store = context
    row = pending(store)
    run(cfg, store, row, Writer(), Reviewer(verdict("hold")))
    if saved == "oversized":
        saved = json.dumps({"private": "x" * (rejection.MAX_PAYLOAD_BYTES + 1)})
    with store.db:
        store.db.execute("UPDATE review_jobs SET record_json=?", (saved,))
    shown = rejection.show_item(store, row["id"])
    assert shown["final_review"] == {"error": "Saved final review cannot be decoded safely"}


def test_rejected_show_without_a_current_job_stays_read_only(context):
    _, store = context
    row = pending(store)
    assert rejection.show_item(store, row["id"])["final_review"] is None
    assert not store.db.execute("SELECT 1 FROM sqlite_master WHERE name='review_jobs'").fetchone()


@pytest.mark.parametrize("change", ["source", "candidate", "policy"])
def test_superseded_verification_preserves_its_exact_old_source_and_stage(context, change):
    cfg, store = context
    row = pending(store)
    wrong = "Superseded instruction: operators must edit their configuration."
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(analysis(why_it_matters=wrong)),
            Reviewer(verdict("revise", repair={"why_it_matters": ""}), AnalysisError("timeout", retryable=True)))
    old = job(store)
    envelope = json.loads(old["envelope_json"])
    assert old["stage"] == "verify"
    if change == "source":
        store.ingest(item(content="A different source revision after the paused verification.", updated_at=LATER), LATER)
        row = store.pending(1, LATER)[0]
    elif change == "policy":
        cfg["review"]["model"] = "a-new-review-policy-model"
    else:
        data = copy.deepcopy(envelope["payload"])
        data["updated_at"] = "2026-11-09T12:00:00Z"
        with store.db:
            store.db.execute("INSERT INTO stories VALUES(?,?,?,?,?)", (data["id"], envelope["cluster_key"],
                             json.dumps(data), data["published_at"], data["updated_at"]))
    checker = Reviewer(verdict("revise", repair={"why_it_matters": ""}), verdict())
    assert run(cfg, store, row, Writer(analysis(why_it_matters=wrong)), checker)["status"] == "published"
    assert job(store) is None
    records = [json.loads(r[0]) for r in store.db.execute("SELECT review_record FROM analyses WHERE review_record IS NOT NULL")]
    preserved = next(r for r in records if r.get("outcome") == "superseded")
    assert preserved["stage"] == "verify"
    assert preserved["writer"]["result"]["why_it_matters"] == wrong
    assert preserved["candidate"]["why_it_matters"] == ""
    assert preserved["reviews"][0]["result"]["verdict"] == "revise"
    assert preserved["source_envelope"] == envelope
    assert preserved["source_envelope"]["row"]["payload"] == old_source_payload(old)


def old_source_payload(saved):
    return json.loads(saved["envelope_json"])["row"]["payload"]


def test_reset_of_pending_review_preserves_the_stage_before_reusing_draft(context):
    cfg, store = context
    row = pending(store)
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), Reviewer(verdict("revise", repair={"why_it_matters": ""}),
                                               AnalysisError("timeout", retryable=True)))
    before = job(store)
    with store.db:
        review_gate.reset_review_work(store, row["id"])
    audit = json.loads(store.db.execute("SELECT review_record FROM analyses").fetchone()[0])
    assert audit["stage"] == "verify" and audit["superseded_reason"] == "explicit operator retry"
    assert audit["source_envelope"]["row"]["payload"] == old_source_payload(before)
    assert job(store)["stage"] == "drafted" and job(store)["draft_json"] == before["draft_json"]


def test_hold_takes_write_lock_before_checks_and_blocks_a_concurrent_revision(context, monkeypatch):
    cfg, store = context
    row = pending(store)
    original = store.record_analysis
    reached = []
    def at_audit_boundary(*args, **kwargs):
        reached.append(store.db.in_transaction)
        assert store.db.in_transaction
        with sqlite3.connect(cfg["storage"]["database"], timeout=0.01) as other:
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                other.execute("UPDATE items SET content_hash=? WHERE id=?", ("f" * 64, row["id"]))
        return original(*args, **kwargs)
    monkeypatch.setattr(store, "record_analysis", at_audit_boundary)
    result = run(cfg, store, row, Writer(), Reviewer(verdict("hold")))
    assert result["status"] == "held" and reached == [True]
    current = store.db.execute("SELECT content_hash,status FROM items WHERE id=?", (row["id"],)).fetchone()
    assert tuple(current) == (row["content_hash"], "rejected")
    assert not store.db.in_transaction


def test_hold_final_update_guard_rolls_back_an_in_transaction_source_change(context, monkeypatch):
    cfg, store = context
    row = pending(store)
    original = store.record_analysis
    def change_inside_audit(*args, **kwargs):
        store.db.execute("UPDATE items SET content_hash=? WHERE id=?", ("f" * 64, row["id"]))
        return original(*args, **kwargs)
    monkeypatch.setattr(store, "record_analysis", change_inside_audit)
    result = run(cfg, store, row, Writer(), Reviewer(verdict("hold")))
    assert result["status"] == "stale"
    current = store.db.execute("SELECT content_hash,status FROM items WHERE id=?", (row["id"],)).fetchone()
    assert tuple(current) == (row["content_hash"], "pending")
    assert store.db.execute("SELECT COUNT(*) FROM analyses").fetchone()[0] == 0


def test_approval_receipt_and_job_pin_roll_back_together_if_job_save_fails(context):
    cfg, store = context
    row = pending(store)
    review_gate.initialize(store)
    store.db.execute("""CREATE TRIGGER fail_approved_job BEFORE INSERT ON review_jobs
        WHEN NEW.stage='approved' BEGIN SELECT RAISE(ABORT,'job save unavailable'); END""")
    store.db.commit()
    with pytest.raises(sqlite3.IntegrityError, match="job save unavailable"):
        run(cfg, store, row, Writer(), Reviewer(verdict()))
    assert store.db.execute("SELECT COUNT(*) FROM review_approvals").fetchone()[0] == 0
    assert job(store)["stage"] == "review" and job(store)["approval_key"] is None
    assert len(store.stories()) == 0
    store.db.execute("DROP TRIGGER fail_approved_job")
    store.db.commit()
    result = run(cfg, store, row, Writer(), Reviewer(verdict()))
    assert result["status"] == "published" and result["writer_calls"] == 0


def test_resuming_approved_job_never_temporarily_unpins_its_receipt(context, monkeypatch):
    cfg, store = context
    cfg["review"]["max_cache_entries"] = 1
    row = pending(store)
    commit = store.commit_candidate
    monkeypatch.setattr(store, "commit_candidate", lambda *args, **kw: (_ for _ in ()).throw(RuntimeError("crash before commit")))
    with pytest.raises(RuntimeError):
        run(cfg, store, row, Writer(), Reviewer(verdict()))
    key = job(store)["approval_key"]
    monkeypatch.setattr(store, "commit_candidate", commit)
    save = review_gate._save
    def crash_during_resume(*args, **kwargs):
        save(*args, **kwargs)
        raise RuntimeError("crash after initial resume save")
    monkeypatch.setattr(review_gate, "_save", crash_during_resume)
    with pytest.raises(RuntimeError):
        run(cfg, store, row, Writer(), Reviewer(), allow_network=False)
    assert job(store)["approval_key"] == key
    with store.db:
        store.db.execute("INSERT INTO review_approvals VALUES(?,?,?,?,?,?,?,?,?)", (
            "newer-unused", "c", "s", "p", "b", "{}", "{}", LATER, "2099-01-01T00:00:00Z"))
    review_gate._prune(store, 1)
    assert store.db.execute("SELECT 1 FROM review_approvals WHERE key=?", (key,)).fetchone()
    monkeypatch.setattr(review_gate, "_save", save)
    result = run(cfg, store, row, Writer(), Reviewer(), allow_network=False)
    assert result["status"] == "published" and result["cache_hit"] and result["review_calls"] == 0


def test_a_database_error_during_analysis_is_not_an_item_strike(context, monkeypatch):
    import sqlite3
    from onionflash import cli
    cfg, store = context
    cfg["sources"] = []

    def locked(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(cli, "process_item", locked)
    store.ingest(item(url="https://example.org/locked"), DATE)
    with pytest.raises(sqlite3.OperationalError):
        cli.run(cfg, store)
    assert tuple(store.db.execute("SELECT status,rejections FROM items").fetchone()) == ("pending", 0)


def test_run_report_counts_held_stale_and_cached_reviews(context, monkeypatch):
    from onionflash import cli
    cfg, store = context
    cfg["sources"] = []
    outcomes = iter([("held", False), ("stale", False), ("published", True)])
    monkeypatch.setattr(cli, "process_item", lambda *args, **kwargs: dict(zip(("status", "cache_hit"), next(outcomes))))
    monkeypatch.setattr(cli, "build", lambda *args: {})
    for name in ("one", "two", "three"):
        store.ingest(item(url="https://example.org/" + name), DATE)
    report = cli.run(cfg, store)
    counts = [report[key] for key in ("analyzed", "analysis_failed", "review_held", "review_stale", "review_cache_hits")]
    assert counts == [2, 1, 1, 1, 1]


def test_unusable_replies_and_drafts_take_strikes_and_the_run_still_builds(context, monkeypatch):
    from onionflash import cli
    cfg, store = context
    cfg["sources"] = []

    class Drafts:
        def analyze(self, incoming):
            # Publishing drops U+FFFF, so this draft cannot form a public story.
            return analysis(title="\uffff") if incoming["url"].endswith("/draft") else analysis()

    class Replies:
        def review(self, candidate, packet, *, verification=False):
            return review.validate_review({} if "/reply" in packet["sources"][0]["url"] else verdict(), packet)

    built = []
    monkeypatch.setattr(cli, "Analyzer", lambda *args, **kwargs: contextlib.nullcontext(Drafts()))
    monkeypatch.setattr(cli, "Reviewer", lambda *args, **kwargs: contextlib.nullcontext(Replies()))
    monkeypatch.setattr(cli, "build", lambda *args: built.append(True) or {})
    for name in ("reply-1", "reply-2", "draft"):
        store.ingest(item(url="https://example.org/" + name), DATE)
    # No security title or label, so this item sorts after both unusable replies.
    store.ingest(item(url="https://example.org/good", title="A routine report", labels=[]), DATE)
    report = cli.run(cfg, store)
    states = {url.rsplit("/", 1)[1]: (status, rejections, error)
              for url, status, rejections, error in store.db.execute("SELECT url,status,rejections,last_error FROM items")}
    assert built == [True] and report["analysis_failed"] == 3
    status, rejections, error = states.pop("draft")
    assert (status, rejections) == ("pending", 1) and error.startswith("Unexpected ValueError at render.py:")
    assert states == {"reply-1": ("pending", 1, "Review response fields do not match schema"),
                      "reply-2": ("pending", 1, "Review response fields do not match schema"),
                      "good": ("published", 0, None)}
