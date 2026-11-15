"""Automatic review work must not replace a newer source association or ledger."""
import copy
import json
import sqlite3

import pytest

from helpers import update_analysis, verdict
from onionflash import candidate, cli, editorial, review, review_gate
from onionflash.analyze import cache_key
from onionflash.llm import AnalysisError
from onionflash.transport import FetchError
from helpers import seed_source_story as _publish
from helpers import analysis, make_item as item
from helpers import LATER, Writer, job, pending, run_gate as run
from test_review_request_budget import context, record, reviewer


@pytest.mark.parametrize("outcome", ["approve", "hold"])
@pytest.mark.parametrize("changed_during", ["writer", "reservation", "reply"])
@pytest.mark.parametrize("association_field", ["story_id", "cluster_key"])
def test_newer_association_job_and_spent_requests_survive_stale_work(context, outcome, changed_during, association_field):
    cfg, store = context
    target = _publish(store, item(url="https://example.org/another-report", title="A separate network report",
                                  content="The source reports a separate network observation."))
    source = item(url="https://example.org/follow-up", title="A follow-up observation",
                  content="The source reports a further network observation.")
    row = pending(store, source)
    outer = reviewer(cfg, *([verdict(), verdict()] if outcome == "approve"
                            else [verdict("hold", criterion="source_support")]))
    inner = reviewer(cfg, FetchError("Temporary transport error", status=500))
    saved = {}
    association = target["id"] if association_field == "story_id" else "reassociated:" + row["cluster_key"]
    draft = analysis(title=source["title"], summary=source["content"], why_it_matters="", evidence=[source["content"]])

    def replace_association_and_review_job():
        if saved:
            return
        with store.db:
            store.db.execute(f"UPDATE items SET {association_field}=? WHERE id=?", (association, row["id"]))
        current = dict(store.db.execute("SELECT * FROM items WHERE id=?", (row["id"],)).fetchone())
        assert current["content_hash"] == row["content_hash"] and current["status"] == "pending"
        newer_draft = (update_analysis(update=source["content"], evidence=[source["content"]])
                       if association_field == "story_id" else draft)
        with pytest.raises(AnalysisError):
            run(cfg, store, current, Writer(newer_draft), inner)
        saved.update(job=copy.deepcopy(job(store)), record=record(store))

    class RacingWriter(Writer):
        def analyze(self, incoming, prior=None):
            draft = super().analyze(incoming)
            if changed_during == "writer":
                replace_association_and_review_job()
            return draft

    class RacingReviewer:
        @property
        def calls(self):
            return outer.calls

        def review(self, *args, **kwargs):
            if changed_during == "reservation":
                replace_association_and_review_job()
            result = outer.review(*args, **kwargs)
            if changed_during == "reply":
                replace_association_and_review_job()
            return result

    result = run(cfg, store, row, RacingWriter(draft), RacingReviewer())
    assert result["status"] == "stale"
    assert outer.calls == (1 if changed_during == "reply" else 0)
    assert inner.calls == 1
    assert job(store) == saved["job"]
    assert record(store)["request_budget"]["reserved"] == saved["record"]["request_budget"]["reserved"] == outer.calls + inner.calls
    assert json.loads(job(store)["envelope_json"])["row"][association_field] == association
    current = store.db.execute(f"SELECT status,{association_field} FROM items WHERE id=?", (row["id"],)).fetchone()
    assert tuple(current) == ("pending", association)
    assert len(store.stories()) == 1


@pytest.mark.parametrize("payload", [None, "{", "[]", "null",
                                     pytest.param("[" * 2000 + "]" * 2000, id="deeply-nested")])
def test_missing_or_malformed_current_source_never_recreates_review_work(context, payload):
    cfg, store = context
    row = pending(store)

    class RemovedWriter(Writer):
        def analyze(self, incoming, prior=None):
            draft = super().analyze(incoming)
            with store.db:
                if payload is None:
                    store.db.execute("DELETE FROM items WHERE id=?", (row["id"],))
                else:
                    store.db.execute("UPDATE items SET payload=? WHERE id=?", (payload, row["id"]))
            return draft

    checker = reviewer(cfg, verdict(), verdict())
    assert run(cfg, store, row, RemovedWriter(), checker)["status"] == "stale"
    assert checker.calls == 0
    assert store.db.execute("SELECT COUNT(*) FROM review_jobs WHERE item_id=?", (row["id"],)).fetchone()[0] == 0


@pytest.mark.parametrize("decision", ["recency", "own_content", "retired"])
def test_early_skip_cannot_remove_a_newer_associated_job(context, monkeypatch, decision):
    cfg, store = context
    target = _publish(store, item(url="https://example.org/existing", title="Existing observation",
                                  content="The source reports an existing observation."))
    source = item(url="https://example.org/earlier", title="An earlier observation",
                  content="The source reports an earlier observation.",
                  **({"published_at": "2026-09-01T12:00:00Z", "updated_at": "2026-09-01T12:00:00Z"}
                     if decision == "recency" else {}))
    row = pending(store, source)
    inner = reviewer(cfg, FetchError("Current associated item unavailable", status=500))
    saved = {}
    fired = False
    seen = 0

    def reassociate():
        nonlocal fired
        fired = True
        with store.db:
            store.db.execute("UPDATE items SET story_id=? WHERE id=?", (target["id"], row["id"]))
        current = dict(store.db.execute("SELECT * FROM items WHERE id=?", (row["id"],)).fetchone())
        with pytest.raises(AnalysisError):
            run(cfg, store, current, Writer(update_analysis(update=source["content"], evidence=[source["content"]])), inner)
        saved.update(job=copy.deepcopy(job(store)), item=current)

    original_existing, original_own = candidate.existing_story, candidate.own_update_input
    original_recency = review_gate._not_recent

    def existing(db, incoming):
        nonlocal seen
        previous = original_existing(db, incoming)
        if incoming["id"] == row["id"] and not fired:
            seen += 1
            if decision == "retired":
                reassociate()
                raise editorial.RetiredStory("Old lookup found a retired story")
        return previous

    def own(db, incoming, payload, **kwargs):
        if incoming["id"] == row["id"] and decision == "own_content" and not fired:
            reassociate()
            return "skip", payload
        return original_own(db, incoming, payload, **kwargs)

    def recency(config, database, incoming, payload, observed, **kwargs):
        if decision == "recency" and not fired:
            reassociate()
        return original_recency(config, database, incoming, payload, observed, **kwargs)

    monkeypatch.setattr(review_gate, "_not_recent", recency)
    monkeypatch.setattr(candidate, "existing_story", existing)
    monkeypatch.setattr(candidate, "own_update_input", own)
    outer = reviewer(cfg)
    assert run(cfg, store, row, Writer(), outer)["status"] == "stale"
    assert outer.calls == 0 and inner.calls == 1
    assert job(store) == saved["job"]
    assert record(store)["request_budget"]["reserved"] == 1
    assert tuple(store.db.execute("SELECT status,story_id FROM items WHERE id=?", (row["id"],)).fetchone()) == ("pending", target["id"])


def test_new_closing_date_prevents_an_obsolete_recency_skip(context, monkeypatch):
    cfg, store = context
    source = item(kind="gitlab_issue", upstream_state="closed", published_at="2026-09-01T12:00:00Z",
                  updated_at="2026-09-01T12:00:00Z")
    row = pending(store, source)
    original = review_gate._not_recent

    def closing_date_arrives(config, database, incoming, payload, observed, **kwargs):
        updated = {**source, "closed_at": LATER}
        with database.db:
            database.db.execute("UPDATE items SET payload=? WHERE id=?", (json.dumps(updated), row["id"]))
        return original(config, database, incoming, payload, observed, **kwargs)

    monkeypatch.setattr(review_gate, "_not_recent", closing_date_arrives)
    checker = reviewer(cfg)
    assert run(cfg, store, row, Writer(), checker)["status"] == "stale"
    assert checker.calls == 0
    assert store.db.execute("SELECT status FROM items WHERE id=?", (row["id"],)).fetchone()[0] == "pending"


def test_polling_metadata_without_new_evidence_does_not_invalidate_review(context):
    cfg, store = context
    row = pending(store)

    class RefreshedWriter(Writer):
        def analyze(self, incoming, prior=None):
            draft = super().analyze(incoming)
            payload = json.loads(row["payload"])
            payload["comments_checked_at"] = LATER
            with store.db:
                store.db.execute("UPDATE items SET payload=?,last_seen=? WHERE id=?",
                                 (json.dumps(payload), LATER, row["id"]))
            return draft

    checker = reviewer(cfg, verdict(), verdict())
    assert run(cfg, store, row, RefreshedWriter(), checker)["status"] == "published"
    assert checker.calls == 2


def test_routing_cannot_replace_a_newer_cluster_job(context):
    cfg, store = context
    target = _publish(store, item(url="https://example.org/route-target"))
    row = pending(store, item(url="https://example.org/route-source"))
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), reviewer(cfg, FetchError("Temporary error", status=500)))
    old_record, old_job = record(store), job(store)
    with store.db:
        store.db.execute("UPDATE items SET cluster_key=? WHERE id=?", ("new:" + row["cluster_key"], row["id"]))
    current = dict(store.db.execute("SELECT * FROM items WHERE id=?", (row["id"],)).fetchone())
    with pytest.raises(AnalysisError):
        run(cfg, store, current, Writer(), reviewer(cfg, FetchError("Temporary error", status=500)))
    newer = copy.deepcopy(job(store))
    assert record(store)["request_budget"]["reserved"] == 2
    with pytest.raises(candidate.StaleCandidate):
        review_gate._route(store, row, analysis(), old_job["writer_key"], old_record, LATER, target["id"], "review")
    assert job(store) == newer
    assert tuple(store.db.execute("SELECT story_id,cluster_key FROM items WHERE id=?", (row["id"],)).fetchone()) == (None, current["cluster_key"])


def test_stale_request_limit_does_not_reject_a_newer_revision(context):
    cfg, store = context
    source = item()
    row = pending(store, source)
    for _ in range(review_gate.MAX_REVIEW_REQUESTS):
        with pytest.raises(AnalysisError):
            run(cfg, store, row, Writer(), reviewer(cfg, FetchError("Temporary transport error", status=500)))
    assert record(store)["request_budget"]["reserved"] == review_gate.MAX_REVIEW_REQUESTS
    checker = reviewer(cfg, verdict())
    inner = reviewer(cfg, FetchError("Temporary transport error", status=500))
    saved = {}

    class NewRevisionReviewer:
        @property
        def calls(self):
            return checker.calls

        def review(self, *args, **kwargs):
            updated = {**source, "content": "A newly supplied report changes the evidence."}
            assert store.ingest(updated, LATER)
            current = dict(store.db.execute("SELECT * FROM items WHERE id=?", (row["id"],)).fetchone())
            assert current["content_hash"] != row["content_hash"]
            with pytest.raises(AnalysisError):
                run(cfg, store, current, Writer(analysis(summary=updated["content"], evidence=[updated["content"]])), inner)
            saved.update(job=copy.deepcopy(job(store)), row=current)
            return checker.review(*args, **kwargs)

    assert run(cfg, store, row, Writer(), NewRevisionReviewer())["status"] == "stale"
    assert checker.calls == 0 and inner.calls == 1
    assert job(store) == saved["job"]
    assert record(store)["request_budget"]["reserved"] == 1
    current = dict(store.db.execute("SELECT * FROM items WHERE id=?", (row["id"],)).fetchone())
    assert current["status"] == "pending" and current["content_hash"] == saved["row"]["content_hash"]
    assert not store.db.execute("SELECT 1 FROM decision_log WHERE code='failed.review.request_limit'").fetchone()


@pytest.mark.parametrize("mutation", ["association", "content"])
@pytest.mark.parametrize("error_kind", ["retryable", "terminal", "unexpected"])
def test_cli_does_not_apply_an_obsolete_failure_to_new_work(context, monkeypatch, mutation, error_kind):
    cfg, store = context
    cfg["sources"] = []
    target = _publish(store, item(url="https://example.org/target", title="An existing account",
                                  content="An existing reported observation."))
    source = item(url="https://example.org/current-item", title="A current account",
                  content="The source reports a further observation.")
    old = pending(store, source)
    saved = {}

    class ObsoleteWriter:
        calls = 0

        def __init__(self, *_args, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def analyze(self, incoming, prior=None):
            self.calls += 1
            if mutation == "association":
                with store.db:
                    store.db.execute("UPDATE items SET story_id=? WHERE id=?", (target["id"], old["id"]))
                draft = update_analysis(update=source["content"], evidence=[source["content"]])
            else:
                updated = {**source, "content": source["content"] + " A new revision adds detail.", "updated_at": LATER}
                assert store.ingest(updated, LATER)
                draft = analysis(summary=updated["content"], evidence=[updated["content"]])
            current = dict(store.db.execute("SELECT * FROM items WHERE id=?", (old["id"],)).fetchone())
            inner = reviewer(cfg, FetchError("Current revision transport error", status=500))
            with pytest.raises(AnalysisError):
                run(cfg, store, current, Writer(draft), inner)
            if error_kind != "retryable":
                with store.db:
                    store.db.execute("UPDATE items SET rejections=2 WHERE id=?", (old["id"],))
            saved.update(item=dict(store.db.execute("SELECT * FROM items WHERE id=?", (old["id"],)).fetchone()),
                         job=copy.deepcopy(job(store)), calls=inner.calls)
            if error_kind == "unexpected":
                raise RuntimeError("Obsolete processing failed")
            raise AnalysisError("Obsolete writer failed", retryable=error_kind == "retryable")

    monkeypatch.setattr(cli, "Analyzer", ObsoleteWriter)
    monkeypatch.setattr(cli, "build", lambda *_args: {})
    monkeypatch.setattr(cli, "now_iso", lambda: LATER)
    report = cli.run(cfg, store)
    assert dict(store.db.execute("SELECT * FROM items WHERE id=?", (old["id"],)).fetchone()) == saved["item"]
    assert job(store) == saved["job"] and saved["calls"] == 1
    assert record(store)["request_budget"]["reserved"] == 1
    assert report["analysis_failed"] == 0 and report["review_stale"] == 1


@pytest.mark.parametrize("terminal", [False, True])
def test_expected_row_deferral_preserves_legitimate_and_item_id_callers(context, terminal):
    cfg, store = context
    row = pending(store)
    assert store.defer(row["id"], "Current failure", cfg["llm"], LATER, terminal=terminal, expected_row=row)
    current = dict(store.db.execute("SELECT * FROM items WHERE id=?", (row["id"],)).fetchone())
    assert current["attempts"] == 1 and current["rejections"] == int(terminal)
    assert current["status"] == "pending" and current["last_error"] == "Current failure"
    assert store.defer(row["id"], "Explicit item failure", cfg["llm"], LATER, terminal=terminal)
    current = dict(store.db.execute("SELECT * FROM items WHERE id=?", (row["id"],)).fetchone())
    assert current["attempts"] == 2 and current["rejections"] == 2 * int(terminal)


def test_cli_counts_current_review_limit_rejection_once(context, monkeypatch):
    cfg, store = context
    cfg["sources"] = []
    row = pending(store)
    for _ in range(review_gate.MAX_REVIEW_REQUESTS):
        with pytest.raises(AnalysisError):
            run(cfg, store, row, Writer(), reviewer(cfg, FetchError("Temporary transport error", status=500)))
    checker = reviewer(cfg, verdict())
    monkeypatch.setattr(cli, "Reviewer", lambda *_args, **_kwargs: checker)
    monkeypatch.setattr(cli, "build", lambda *_args: {})
    monkeypatch.setattr(cli, "now_iso", lambda: LATER)
    report = cli.run(cfg, store)
    assert checker.calls == 0
    assert report["analysis_failed"] == 1 and report["review_stale"] == 0
    assert store.db.execute("SELECT status FROM items WHERE id=?", (row["id"],)).fetchone()[0] == "rejected"
    assert store.db.execute("SELECT COUNT(*) FROM decision_log WHERE code='failed.review.request_limit'").fetchone()[0] == 1


def test_save_source_check_holds_the_write_transaction(context):
    cfg, store = context
    row = pending(store)
    actual = store.db
    attempted = []

    class ConcurrentAssociation:
        def __getattr__(self, name):
            return getattr(actual, name)

        def __enter__(self):
            actual.__enter__()
            return self

        def __exit__(self, *args):
            return actual.__exit__(*args)

        def execute(self, sql, parameters=()):
            cursor = actual.execute(sql, parameters)
            if sql.lstrip().startswith("SELECT") and "FROM items WHERE id=" in sql and not attempted:
                with sqlite3.connect(cfg["storage"]["database"], timeout=0) as other:
                    try:
                        other.execute("UPDATE items SET cluster_key='changed-association' WHERE id=?", (row["id"],))
                    except sqlite3.OperationalError as error:
                        assert "locked" in str(error)
                        attempted.append("blocked")
                    else:
                        attempted.append("committed")
            return cursor

    store.db = ConcurrentAssociation()
    try:
        key = cache_key(row, cfg["llm"])
        state = {"schema_version": 1, "writer": {"key": key}, "input_row": row, "reviews": [],
                 **review_gate.initial_review_state()}
        review_gate._save(store, row, key, review.policy_hash(cfg), "drafted", analysis(), None, state,
                          LATER, prepared_at=LATER)
    finally:
        store.db = actual
    assert attempted == ["blocked"]
    assert actual.execute("SELECT cluster_key FROM items WHERE id=?", (row["id"],)).fetchone()[0] == row["cluster_key"]
