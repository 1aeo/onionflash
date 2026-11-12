"""The final-candidate gate resumes completed stages and never publishes unchecked."""

import contextlib
import copy
import json
import sqlite3

import pytest

from approval_helpers import approve, verdict
from onionflash import editorial, rejection, review, review_gate
from onionflash.analyze import AnalysisError, cache_key, tag_notice
from onionflash.store import Store
from onionflash.util import digest
from test_core import DAMAGE, DATE, analysis, config, damaged, item


LATER = "2026-11-10T12:00:00Z"


class Writer:
    def __init__(self, result=None):
        self.result, self.calls = result or analysis(), []

    def analyze(self, incoming):
        self.calls.append(copy.deepcopy(incoming))
        return copy.deepcopy(self.result)


class Reviewer:
    """Returns validated verdicts, as review.Reviewer does."""
    def __init__(self, *responses):
        """Script reviewer responses, adding final approval only for approval shorthand."""
        self.responses, self.calls, self.coverages = list(responses), [], []
        # A shorthand approval includes an independent final approval. Empty
        # and failure scripts remain strict, so unexpected calls still fail.
        if len(responses) == 1 and (callable(responses[0]) or
                isinstance(responses[0], dict) and responses[0].get("verdict") == "approve"):
            self.responses.append(verdict())

    def review(self, candidate, packet, *, coverage=None, verification=False):
        """Capture exact review inputs and validate or raise the next scripted response."""
        self.calls.append((copy.deepcopy(candidate), copy.deepcopy(packet), verification))
        self.coverages.append(copy.deepcopy(coverage))
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
    """Publish reviewed text and retain both stages with their evidence privately."""
    cfg, store = context
    row = pending(store)
    writer, checker = Writer(), Reviewer(verdict())
    result = run(cfg, store, row, writer, checker)
    assert result == {"status": "published", "writer_calls": 1, "review_calls": 2, "cache_hit": False}
    assert job(store) is None
    assert store.stories()[0]["summary"] == checker.calls[0][0]["summary"]
    saved = store.db.execute("SELECT result,review_record FROM analyses").fetchone()
    audit = json.loads(saved[1])
    assert json.loads(saved[0]) == analysis() and audit["writer"] == {"key": cache_key(row, cfg["llm"])}
    assert audit["prepared"]["packet"]["sources"]
    assert [r["stage"] for r in audit["reviews"]] == ["review", "verification"] and audit["outcome"] == "approved"


def test_a_new_story_is_dated_when_the_review_commits_not_when_the_item_started(context, monkeypatch):
    cfg, store = context
    row = pending(store)
    # The item starts before midnight; the review returns and commits after it.
    monkeypatch.setattr(review_gate, "now_iso", lambda: "2026-11-11T00:01:00Z")
    review_gate.process_item(cfg, store, row, Writer(), Reviewer(verdict()), "2026-11-10T23:59:00Z")
    assert store.stories()[0]["added_at"] == "2026-11-11T00:01:00Z"


@pytest.mark.parametrize("failure", [AnalysisError("timeout", retryable=True), {}])
def test_review_timeout_or_malformed_verdict_resumes_without_regenerating_writer(context, failure):
    """Resume the unfinished review while retaining its already completed writer draft."""
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
    assert next_writer.calls == [] and len(next_checker.calls) == 2


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


@pytest.mark.parametrize("repair", [None, {"title": analysis()["title"]}, {"title": ""}],
                         ids=["missing", "unchanged", "invalid"])
def test_unusable_repair_holds_after_one_call_for_operator_inspection(context, repair):
    cfg, store = context
    row = pending(store)
    result = run(cfg, store, row, Writer(), Reviewer(verdict("revise", repair=repair)))
    assert result["status"] == "held" and result["review_calls"] == 1
    assert [entry["id"] for entry in rejection.list_items(store)["items"]] == [row["id"]]
    assert rejection.show_item(store, row["id"])["final_review"]["latest_review"]["verdict"] == "revise"


@pytest.mark.parametrize("decision", ["approve", "skip"])
def test_completed_decision_resumes_after_crash_without_any_model_call(context, monkeypatch, decision):
    cfg, store = context
    row = pending(store)
    commit = store.commit_candidate
    monkeypatch.setattr(store, "commit_candidate", lambda *args, **kw: (_ for _ in ()).throw(RuntimeError("simulated crash before commit")))
    with pytest.raises(RuntimeError, match="simulated crash"):
        run(cfg, store, row, Writer(), Reviewer(verdict(decision, criterion="news_value")))
    assert job(store)["stage"] == ("approved" if decision == "approve" else "skipped") and len(store.stories()) == 0
    store.defer(row["id"], "Unexpected RuntimeError", cfg["llm"], LATER, terminal=True)  # as the run loop does
    row = dict(store.db.execute("SELECT * FROM items WHERE id=?", (row["id"],)).fetchone())
    monkeypatch.setattr(store, "commit_candidate", commit)
    # Another item's commit leaves the receipt that this job pins.
    store.ingest(item(url="https://example.org/other-report", content="A routine reply."), DATE)
    other = dict(store.db.execute("SELECT * FROM items WHERE url=?", ("https://example.org/other-report",)).fetchone())
    assert run(cfg, store, other, Writer(), Reviewer(verdict("skip", criterion="news_value")))["status"] == "ignored"
    writer, checker = Writer(), Reviewer()
    result = run(cfg, store, row, writer, checker, allow_network=False)
    assert result["status"] == ("published" if decision == "approve" else "ignored") and result["cache_hit"]
    assert writer.calls == checker.calls == [] and job(store) is None
    assert len(store.stories()) == (1 if decision == "approve" else 0)
    assert not store.db.execute("SELECT 1 FROM review_approvals").fetchone()


@pytest.mark.parametrize("receipt", ["damaged", "missing"])
def test_a_recorded_decision_without_a_usable_receipt_reviews_the_draft_again(context, monkeypatch, receipt):
    """The repaired text is not reviewed as a first draft, so it cannot be repaired a second time."""
    cfg, store = context
    row = pending(store)
    commit = store.commit_candidate
    monkeypatch.setattr(store, "commit_candidate", lambda *args, **kw: (_ for _ in ()).throw(RuntimeError("simulated crash before commit")))
    first = Reviewer(verdict("revise", repair={"why_it_matters": ""}), verdict())
    with pytest.raises(RuntimeError, match="simulated crash"):
        run(cfg, store, row, Writer(analysis(why_it_matters="Operators must edit their relay configuration.")), first)
    monkeypatch.setattr(store, "commit_candidate", commit)
    with store.db:
        store.db.execute("UPDATE review_approvals SET review_record_json='{'" if receipt == "damaged" else "DELETE FROM review_approvals")
    checker = Reviewer(verdict())
    assert run(cfg, store, row, Writer(), checker)["status"] == "published"
    assert [call[0] for call in checker.calls] == [first.calls[0][0]] * 2
    audit = json.loads(store.db.execute("SELECT review_record FROM analyses").fetchone()[0])
    assert [entry["stage"] for entry in audit["reviews"]] == ["review", "verification"]


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


def test_policy_change_reuses_writer_but_requires_a_new_review(context):
    """Invalidate review approval on policy change without discarding the source draft."""
    cfg, store = context
    row = pending(store)
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), Reviewer(verdict(), AnalysisError("timeout", retryable=True)))
    cfg["review"]["model"] = "different-review-model"
    result = run(cfg, store, row, Writer(), Reviewer(verdict()))
    assert result["writer_calls"] == 0 and result["review_calls"] == 2 and not result["cache_hit"]


def test_final_merge_reviews_retained_old_bad_text_and_commits_only_the_verified_repair(context):
    cfg, store = context
    wrong = "Operators must update their configurations to exclude the node."
    original = item(content=item()["content"] * 3, updated_at="2026-11-09T12:00:00Z")
    seed_legacy(store, original, analysis(why_it_matters=wrong))
    incoming = item(url="https://example.org/news/mirror", source_id="mirror", content=original["content"])
    row = pending(store, incoming)
    checker = Reviewer(verdict("revise", repair={"why_it_matters": ""}), verdict())
    result = run(cfg, store, row, Writer(analysis(why_it_matters="The report concerns old keys.")), checker)
    reviewed, evidence, _ = checker.calls[0]
    passages = [p["text"] for source in evidence["sources"] for p in source["passages"]]
    assert reviewed["why_it_matters"] == wrong and len(evidence["sources"]) == 2
    # The evidence is collected source text, never the retained generated sentence.
    assert original["content"] in passages and not any(wrong in text for text in passages)
    assert result["status"] == "published" and store.stories()[0]["why_it_matters"] == ""
    assert len(store.stories()) == 1


def test_human_lock_during_review_preserves_operator_text(context):
    cfg, store = context
    original, story_id = seed_legacy(store)
    row = pending(store, {**original, "content": original["content"] + " A later report.", "updated_at": LATER})
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), Reviewer(AnalysisError("timeout", retryable=True)))
    editorial.correct(store.db, story_id, {"why_it_matters": "Operator-reviewed wording."},
                      reason="Corrected unsupported advice.", expect_hash=editorial.show(store.db, story_id)["hash"], observed=LATER)
    second = run(cfg, store, row, Writer(), Reviewer(), allow_network=False)
    assert second["status"] == "locked" and second["writer_calls"] == second["review_calls"] == 0
    assert store.stories()[0]["why_it_matters"] == "Operator-reviewed wording."


def test_tag_update_still_reviews_the_existing_prose_it_retains(context):
    """Review and repair inherited prose even when a locally drafted tag triggers the candidate."""
    cfg, store = context
    original = item(title="Tor 0.4.9.16 released", kind="feed", content="Tor 0.4.9.16 was released with an announced change.")
    seed_legacy(store, original, analysis(title="Tor release announcement", state="tagged"))
    tag = item(url="https://example.org/tags/tor-0.4.9.16", title="tor-0.4.9.16", kind="tag", content="")
    row = pending(store, tag)
    checker = Reviewer(verdict("revise", repair={"title": "Tor 0.4.9.16 release announcement"}), verdict())
    result = run(cfg, store, row, Writer(tag_notice(tag)), checker)
    assert result["review_calls"] == 2 and checker.calls[0][0]["title"] == "Tor release announcement"
    assert result["status"] == "published" and store.stories()[0]["title"] == "Tor 0.4.9.16 release announcement"


def test_tag_draft_requires_final_review_and_waits_when_network_is_disabled(context):
    """Defer an unreviewed tag until both publication reviews can run."""
    cfg, store = context
    tag = item(title="tor-0.4.9.16", kind="tag", content="")
    row = pending(store, tag)
    checker = Reviewer()
    result = run(cfg, store, row, Writer(tag_notice(tag)), checker, allow_network=False)
    assert result["status"] == "deferred" and checker.calls == []
    assert result["writer_calls"] == 0 and store.stories() == []
    reviewed = run(cfg, store, row, Writer(tag_notice(tag)), Reviewer(verdict()))
    assert reviewed["status"] == "published" and reviewed["writer_calls"] == 0 and reviewed["review_calls"] == 2


def test_tag_notice_stays_literal_when_review_proposes_a_repair(context):
    """Hold a tag notice that review would edit, even when verification would approve the edit."""
    cfg, store = context
    tag = item(title="tor-0.4.9.16", kind="tag", content="")
    row = pending(store, tag)
    checker = Reviewer(verdict("revise", repair={"title": "Tor 0.4.9.16 released", "state": "released"}), verdict())
    result = run(cfg, store, row, Writer(tag_notice(tag)), checker)
    assert result["status"] == "held" and result["review_calls"] == 1 and store.stories() == []
    assert store.db.execute("SELECT last_error FROM items").fetchone()[0] == "Final review held: review proposed editing a literal tag notice"


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
    assert store.db.execute("SELECT status FROM items WHERE id=?", (original["id"],)).fetchone()[0] == "published"


@pytest.mark.parametrize("cached", [{"verdict": "approve"}, verdict("hold")], ids=["incomplete-approval", "hold"])
def test_cache_reviews_again_unless_the_receipt_is_a_complete_decision(context, cached):
    """Neither an incomplete approval nor a cached hold can stand in for a fresh review."""
    cfg, store = context
    row = pending(store)
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), Reviewer(AnalysisError("timeout", retryable=True)))
    saved = job(store)
    approve(store, json.loads(saved["envelope_json"]), policy=saved["policy_hash"], result=cached)
    result = run(cfg, store, row, Writer(), Reviewer(verdict()))
    assert result["review_calls"] == 2 and not result["cache_hit"]


def test_cache_pruning_retains_active_approval_jobs(context, monkeypatch):
    cfg, store = context
    monkeypatch.setattr(review_gate, "MAX_APPROVALS", 1)
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


def test_status_reads_stage_counts_without_exposing_audit(context):
    cfg, store = context
    assert review_gate.status(store) == {"stages": {}, "approval_cache_entries": 0}
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
    assert store.db.execute("SELECT last_error FROM items").fetchone()[0] == "Final review held: review did not approve the candidate"
    rejection.retry_item(store, row["id"], row["content_hash"], "The review prompt was revised", LATER)
    audit = json.loads(store.db.execute("SELECT review_record FROM analyses WHERE cache_key=?",
                                        (cache_key(row, cfg["llm"]),)).fetchone()[0])
    assert audit["outcome"] == "held" and audit["reviews"][0]["result"]["verdict"] == "hold"  # retry keeps it
    assert job(store)["stage"] == "drafted"
    retry = store.pending(1, LATER)[0]
    writer = Writer()
    assert run(cfg, store, retry, writer, Reviewer(verdict()))["status"] == "published"
    assert writer.calls == []
    final = json.loads(store.db.execute("SELECT review_record FROM analyses ORDER BY rowid DESC").fetchone()[0])
    assert final["outcome"] == "approved" and final["writer"] == {"key": cache_key(row, cfg["llm"])}
    shown = rejection.show_item(store, row["id"])["final_review"]
    assert shown["latest_review"]["verdict"] == "approve" and shown["source_packet"]["sources"] and shown["coverage"] is not None


def test_a_source_that_reverts_to_a_held_revision_is_held_again_without_a_review(context):
    cfg, store = context
    assert run(cfg, store, pending(store), Writer(), Reviewer(verdict("hold")))["status"] == "held"
    store.ingest(item(content=item()["content"] + " Edited."), DATE)  # a revision that is never drafted
    assert run(cfg, store, store.pending(1, LATER)[0], Writer(), Reviewer(), allow_network=False)["status"] == "deferred"
    store.ingest(item(), DATE)
    checker = Reviewer(verdict())
    assert run(cfg, store, store.pending(1, LATER)[0], Writer(), checker)["status"] == "held"
    assert checker.calls == []


def test_rejected_show_explains_structured_hold_with_the_actual_candidate_and_passages(context, monkeypatch):
    cfg, store = context
    row = pending(store)
    assert run(cfg, store, row, Writer(), Reviewer(verdict("hold")))["status"] == "held"
    before = list(store.db.iterdump())
    # A hold waits for an operator, so its saved verdict stays readable after a later rubric change.
    monkeypatch.setattr(review, "CRITERIA", (*review.CRITERIA, "a_later_criterion"))
    shown = rejection.show_item(store, row["id"])["final_review"]
    assert shown["stage"] == "held"
    assert shown["candidate"]["title"] == analysis()["title"]
    assert shown["latest_review"]["verdict"] == "hold"
    assert shown["latest_review"]["criteria"]["operational_advice"]["outcome"] == "fail"
    assert shown["latest_review"]["criteria"]["operational_advice"]["source_refs"] == ["S1"]
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


def test_rejected_show_reads_a_reused_approval_after_an_interrupted_commit(context, monkeypatch):
    cfg, store = context
    row = pending(store)
    monkeypatch.setattr(store, "commit_candidate", lambda *args, **kw: (_ for _ in ()).throw(RuntimeError("simulated crash")))
    with pytest.raises(RuntimeError):
        run(cfg, store, row, Writer(), Reviewer(verdict()))
    with store.db:  # an operator retry starts a new record without reviews of its own
        review_gate.reset_review_work(store, row["id"])
    with pytest.raises(RuntimeError):  # the saved approval is reused, and the commit is interrupted again
        run(cfg, store, row, Writer(), Reviewer())
    shown = rejection.show_item(store, row["id"])["final_review"]
    assert shown["stage"] == "approved" and shown["latest_review"]["verdict"] == "approve"


@pytest.mark.parametrize("kind", [*DAMAGE, "review-not-an-object", "review-without-result"])
def test_rejected_show_and_retry_survive_a_damaged_review_record(context, kind):
    cfg, store = context
    row = pending(store)
    assert run(cfg, store, row, Writer(), Reviewer(verdict("hold")))["status"] == "held"
    # Besides the damaged() kinds, a record can be a valid object of the wrong shape.
    shapes = {"review-not-an-object": b'{"reviews": [1]}', "review-without-result": b'{"reviews": [{"stage": "held"}]}'}
    with store.db:
        value = shapes.get(kind) or damaged(job(store)["record_json"], kind)
        store.db.execute("UPDATE review_jobs SET record_json=CAST(? AS TEXT) WHERE item_id=?", (value, row["id"]))
    shown = rejection.show_item(store, row["id"])
    assert shown["final_review"] == {"stage": "held", "error": "Saved review record cannot be read"}
    assert shown["saved_item"] is not None
    rejection.retry_item(store, row["id"], row["content_hash"], "Retry after inspection", LATER)
    assert job(store)["stage"] == "drafted"


@pytest.mark.parametrize("kind", DAMAGE)
def test_retry_drops_a_damaged_draft_and_the_writer_drafts_again(context, kind):
    cfg, store = context
    row = pending(store)
    assert run(cfg, store, row, Writer(), Reviewer(verdict("hold")))["status"] == "held"
    with store.db:
        store.db.execute("UPDATE review_jobs SET draft_json=CAST(? AS TEXT)", (damaged(job(store)["draft_json"], kind),))
    rejection.retry_item(store, row["id"], row["content_hash"], "Retry after inspection", LATER)
    writer = Writer()
    assert run(cfg, store, store.pending(1, LATER)[0], writer, Reviewer(verdict()))["status"] == "published"
    assert len(writer.calls) == 1


def test_rejected_show_without_a_current_job_stays_read_only(context):
    _, store = context
    row = pending(store)
    before = list(store.db.iterdump())
    assert rejection.show_item(store, row["id"])["final_review"] is None
    assert list(store.db.iterdump()) == before


def test_hold_audit_and_rejection_roll_back_together_if_job_update_fails(context):
    cfg, store = context
    row = pending(store)
    store.db.execute("""CREATE TRIGGER fail_held_job BEFORE UPDATE ON review_jobs
        WHEN NEW.stage='held' BEGIN SELECT RAISE(ABORT,'hold unavailable'); END""")
    store.db.commit()
    with pytest.raises(sqlite3.IntegrityError, match="hold unavailable"):
        run(cfg, store, row, Writer(), Reviewer(verdict("hold")))
    assert store.db.execute("SELECT COUNT(*) FROM analyses").fetchone()[0] == 0
    assert store.pending_count() == 1 and job(store)["stage"] == "review"


def test_approval_receipt_and_job_pin_roll_back_together_if_job_save_fails(context):
    """Persist the receipt and its unfinished-job pin atomically."""
    cfg, store = context
    row = pending(store)
    store.db.execute("""CREATE TRIGGER fail_approved_job BEFORE INSERT ON review_jobs
        WHEN NEW.stage='approved' BEGIN SELECT RAISE(ABORT,'job save unavailable'); END""")
    store.db.commit()
    with pytest.raises(sqlite3.IntegrityError, match="job save unavailable"):
        run(cfg, store, row, Writer(), Reviewer(verdict()))
    assert store.db.execute("SELECT COUNT(*) FROM review_approvals").fetchone()[0] == 0
    assert job(store)["stage"] == "verify" and job(store)["approval_key"] is None
    assert len(store.stories()) == 0
    store.db.execute("DROP TRIGGER fail_approved_job")
    store.db.commit()
    result = run(cfg, store, row, Writer(), Reviewer(verdict()))
    assert result["status"] == "published" and result["writer_calls"] == 0


def test_resuming_approved_job_never_temporarily_unpins_its_receipt(context, monkeypatch):
    cfg, store = context
    monkeypatch.setattr(review_gate, "MAX_APPROVALS", 1)
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


def test_run_report_counts_review_outcomes(context, monkeypatch):
    from onionflash import cli
    cfg, store = context
    cfg["sources"] = []
    outcomes = iter([("held", False), ("stale", False), ("published", True), ("ignored", False), ("ignored", True)])
    monkeypatch.setattr(cli, "process_item", lambda *args, **kwargs: dict(zip(("status", "cache_hit"), next(outcomes))))
    monkeypatch.setattr(cli, "build", lambda *args: {})
    for name in ("one", "two", "three", "four", "five"):
        store.ingest(item(url="https://example.org/" + name), DATE)
    report = cli.run(cfg, store)
    counts = [report[key] for key in ("analyzed", "analysis_failed", "review_stale", "review_cache_hits")]
    # A hold is a decision, not a failure. Holds and skips are counted by code under decisions, and
    # this stand-in for the gate logs none, on a database that has no decisions yet.
    assert counts == [4, 0, 1, 2] and report["decisions"] == {}
    assert "review_held" not in report and "review_skipped" not in report


def test_run_report_counts_the_model_requests_of_items_that_fail(context, monkeypatch):
    from onionflash import analyze, cli
    from onionflash.transport import FetchError, Response
    cfg, store = context
    cfg["sources"] = []
    cfg["llm"]["base_url"] = "https://llm.example/v1"
    monkeypatch.setenv(cfg["llm"]["api_key_env"], "test-key")

    class Transport:  # the writer's requests succeed; every review request fails in transport
        def request(self, method, url, headers=None, json_body=None):
            if json_body["response_format"]["json_schema"]["name"] != "onionflash_news":
                raise FetchError("network request failed", retryable=True)
            body = {"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(analysis(why_it_matters=""))}}]}
            return Response(200, json.dumps(body).encode(), {}, url)
        def close(self):
            pass

    monkeypatch.setattr(analyze, "HttpClient", lambda *args, **kwargs: Transport())
    monkeypatch.setattr(cli, "build", lambda *args: {})
    for name in ("one", "two"):
        store.ingest(item(url="https://example.org/" + name), DATE)
    report = cli.run(cfg, store)
    # Each item's writer request and failed review request count.
    assert (report["analysis_failed"], report["model_calls"]) == (2, 4)


def test_unusable_replies_and_drafts_take_strikes_and_the_run_still_builds(context, monkeypatch):
    """Isolate invalid model output so other queued work and the site build continue."""
    from onionflash import cli
    cfg, store = context
    cfg["sources"] = []

    class Drafts:
        calls = 0
        def analyze(self, incoming):
            # Publishing drops U+FFFF, so this draft cannot form a public story.
            return analysis(title="\uffff") if incoming["url"].endswith("/draft") else analysis()

    class Replies:
        calls = 0
        def review(self, candidate, packet, *, coverage=None, verification=False):
            """Return malformed replies only for the designated failure fixtures."""
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
