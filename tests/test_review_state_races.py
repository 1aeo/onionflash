"""Automatic review work must not replace a newer source association or ledger."""

import copy
import json
import sqlite3

import pytest

from helpers import (
    LATER, Writer, analysis, decision_codes, editorial_act, item, item_row, job, job_record, patch_cli_pipeline,
    pending, run_gate as run, seed_source_story, update_analysis, verdict, wire_reviewer,
)
from onionflash import candidate, cli, editorial, publication, review, review_gate
from onionflash.analyze import cache_key
from onionflash.llm import AnalysisError
from onionflash.store import _RETENTION_SCHEMA
from onionflash.transport import FetchError


def _exhaust_budget(cfg, store, row):
    for _ in range(review_gate.MAX_REVIEW_REQUESTS):
        with pytest.raises(AnalysisError):
            run(cfg, store, row, Writer(), wire_reviewer(cfg, FetchError("Temporary transport error", status=500)))


@pytest.mark.parametrize("changed_during", ["writer", "reservation"])
def test_stale_review_work_preserves_newer_job_before_any_request(llm_context, changed_during):
    """Abort stale review work without replacing a newer `review_jobs` row or spending requests."""
    cfg, store = llm_context
    row = pending(store, item())

    def _replace_with_newer_work():
        with store.db:
            store.db.execute("UPDATE items SET content_hash='newer-source',status='rejected' WHERE id=?", (row["id"],))
            store.db.execute(
                """INSERT OR REPLACE INTO review_jobs
                   (item_id,writer_key,policy_hash,stage,record_json,approval_key,prepared_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (row["id"], "newer-writer", "newer-policy", "held", '{"newer":true}', "newer-approval", LATER, LATER),
            )

    class _RacingReviewer:
        calls = 0

        def review(self, *_args, on_request=None, **_kwargs):
            """Inject newer work right before request reservation when configured."""
            if changed_during == "reservation" and not self.calls:
                _replace_with_newer_work()
            on_request(1)
            self.calls += 1
            return verdict()

    writer = Writer(lambda _inc: (_replace_with_newer_work() if changed_during == "writer" else None) or analysis())
    checker = _RacingReviewer()
    result = run(cfg, store, row, writer, checker)
    assert result["status"] == "stale" and checker.calls == 0
    saved = job(store, row)
    assert (saved["writer_key"], saved["stage"], saved["record_json"], saved["approval_key"]) == (
        "newer-writer", "held", '{"newer":true}', "newer-approval"
    )
    assert not store.stories()


@pytest.mark.parametrize("outcome", ["approve", "hold"])
@pytest.mark.parametrize("changed_during", ["writer", "reservation", "reply"])
@pytest.mark.parametrize("association_field", ["story_id", "cluster_key"])
def test_newer_association_job_and_spent_requests_survive_stale_work(llm_context, outcome, changed_during, association_field):
    """Preserve newer item associations and spent budgets when concurrent work supersedes an item."""
    cfg, store = llm_context
    target = seed_source_story(store, item(url="https://example.org/another-report", title="A separate network report",
                                           content="The source reports a separate network observation."))
    src = item(url="https://example.org/follow-up", title="A follow-up observation",
               content="The source reports a further network observation.")
    row = pending(store, src)
    outer = wire_reviewer(cfg, *([verdict(), verdict()] if outcome == "approve"
                                 else [verdict("hold", criterion="source_support")]))
    inner = wire_reviewer(cfg, FetchError("Temporary transport error", status=500))
    saved = {}
    association = target["id"] if association_field == "story_id" else "reassociated:" + row["cluster_key"]
    draft = analysis(title=src["title"], summary=src["content"], why_it_matters="", evidence=[src["content"]])

    def _replace_association_and_review_job():
        if saved:
            return
        with store.db:
            store.db.execute(f"UPDATE items SET {association_field}=? WHERE id=?", (association, row["id"]))
        current = item_row(store, row)
        assert current["content_hash"] == row["content_hash"] and current["status"] == "pending"
        newer_draft = (update_analysis(update=src["content"], evidence=[src["content"]])
                       if association_field == "story_id" else draft)
        with pytest.raises(AnalysisError):
            run(cfg, store, current, Writer(newer_draft), inner)
        saved.update(job=copy.deepcopy(job(store)), record=job_record(store))

    class _RacingReviewer:
        @property
        def calls(self):
            """Delegate recorded call count to `outer`."""
            return outer.calls

        def review(self, *args, **kwargs):
            """Replace association and job state around `outer.review` when configured."""
            if changed_during == "reservation":
                _replace_association_and_review_job()
            result = outer.review(*args, **kwargs)
            if changed_during == "reply":
                _replace_association_and_review_job()
            return result

    writer = Writer(lambda _inc: (_replace_association_and_review_job() if changed_during == "writer" else None) or copy.deepcopy(draft))
    result = run(cfg, store, row, writer, _RacingReviewer())
    assert result["status"] == "stale"
    assert outer.calls == (1 if changed_during == "reply" else 0)
    assert inner.calls == 1
    assert job(store) == saved["job"]
    assert job_record(store)["request_budget"]["reserved"] == saved["record"]["request_budget"]["reserved"] == outer.calls + inner.calls
    assert json.loads(job(store)["envelope_json"])["row"][association_field] == association
    current = item_row(store, row)
    assert (current["status"], current[association_field]) == ("pending", association)
    assert len(store.stories()) == 1


@pytest.mark.parametrize("payload", [None, "{", "[]", "null",
                                     pytest.param("[" * 2000 + "]" * 2000, id="deeply-nested")])
def test_missing_or_malformed_current_source_never_recreates_review_work(llm_context, payload):
    """Return `stale` without creating `review_jobs` when the item disappears or corrupts mid-draft."""
    cfg, store = llm_context
    row = pending(store)

    def _remove_or_corrupt(_incoming):
        with store.db:
            if payload is None:
                store.db.execute("DELETE FROM items WHERE id=?", (row["id"],))
            else:
                store.db.execute("UPDATE items SET payload=? WHERE id=?", (payload, row["id"]))
        return analysis()

    checker = wire_reviewer(cfg, verdict(), verdict())
    assert run(cfg, store, row, Writer(_remove_or_corrupt), checker)["status"] == "stale"
    assert checker.calls == 0 and job(store, row) is None


@pytest.mark.parametrize("decision", ["recency", "own_content", "retired"])
def test_early_skip_cannot_remove_a_newer_associated_job(llm_context, monkeypatch, decision):
    """Prevent obsolete early-skip paths from deleting a newer associated `review_jobs` row."""
    cfg, store = llm_context
    target = seed_source_story(store, item(url="https://example.org/existing", title="Existing observation",
                                           content="The source reports an existing observation."))
    src = item(url="https://example.org/earlier", title="An earlier observation",
               content="The source reports an earlier observation.",
               **({"published_at": "2026-09-01T12:00:00Z", "updated_at": "2026-09-01T12:00:00Z"}
                  if decision == "recency" else {}))
    row = pending(store, src)
    inner = wire_reviewer(cfg, FetchError("Current associated item unavailable", status=500))
    saved = {}
    fired = False

    def _reassociate():
        nonlocal fired
        fired = True
        with store.db:
            store.db.execute("UPDATE items SET story_id=? WHERE id=?", (target["id"], row["id"]))
        current = item_row(store, row)
        with pytest.raises(AnalysisError):
            run(cfg, store, current, Writer(update_analysis(update=src["content"], evidence=[src["content"]])), inner)
        saved.update(job=copy.deepcopy(job(store)), item=current)

    original_existing, original_own = candidate.existing_story, candidate.own_update_input
    original_recency = review_gate._not_recent

    def _existing(db, incoming):
        previous = original_existing(db, incoming)
        if incoming["id"] == row["id"] and not fired and decision == "retired":
            _reassociate()
            raise editorial.RetiredStory("Old lookup found a retired story")
        return previous

    def _own(db, incoming, payload, **kwargs):
        if incoming["id"] == row["id"] and decision == "own_content" and not fired:
            _reassociate()
            return "skip", payload
        return original_own(db, incoming, payload, **kwargs)

    def _recency(config, database, incoming, payload, observed, **kwargs):
        if decision == "recency" and not fired:
            _reassociate()
        return original_recency(config, database, incoming, payload, observed, **kwargs)

    monkeypatch.setattr(review_gate, "_not_recent", _recency)
    monkeypatch.setattr(candidate, "existing_story", _existing)
    monkeypatch.setattr(candidate, "own_update_input", _own)
    outer = wire_reviewer(cfg)
    assert run(cfg, store, row, Writer(), outer)["status"] == "stale"
    assert outer.calls == 0 and inner.calls == 1
    assert job(store) == saved["job"]
    assert job_record(store)["request_budget"]["reserved"] == 1
    current = item_row(store, row)
    assert (current["status"], current["story_id"]) == ("pending", target["id"])


def test_new_closing_date_prevents_an_obsolete_recency_skip(llm_context, monkeypatch):
    """Return `stale` instead of skipping when a newly ingested `closed_at` arrives mid-check."""
    cfg, store = llm_context
    src = item(kind="gitlab_issue", upstream_state="closed", published_at="2026-09-01T12:00:00Z",
               updated_at="2026-09-01T12:00:00Z")
    row = pending(store, src)
    original = review_gate._not_recent

    def _closing_date_arrives(config, database, incoming, payload, observed, **kwargs):
        updated = {**src, "closed_at": LATER}
        assert database.ingest(updated, LATER) is False
        return original(config, database, incoming, payload, observed, **kwargs)

    monkeypatch.setattr(review_gate, "_not_recent", _closing_date_arrives)
    checker = wire_reviewer(cfg)
    assert run(cfg, store, row, Writer(), checker)["status"] == "stale"
    refreshed = item_row(store, row)
    assert checker.calls == 0
    assert refreshed["status"] == "pending"
    assert refreshed["content_hash"] == row["content_hash"]
    assert refreshed["attempts"] == 0 and refreshed["rejections"] == 0
    assert json.loads(refreshed["payload"])["closed_at"] == LATER


def test_polling_metadata_without_new_evidence_does_not_invalidate_review(llm_context):
    """Allow `comments_checked_at` and `last_seen` refreshes without invalidating in-flight review."""
    cfg, store = llm_context
    row = pending(store)

    def _refresh_poll_metadata(_incoming):
        payload = {**json.loads(row["payload"]), "comments_checked_at": LATER}
        with store.db:
            store.db.execute("UPDATE items SET payload=?,last_seen=? WHERE id=?",
                             (json.dumps(payload), LATER, row["id"]))
        return analysis()

    checker = wire_reviewer(cfg, verdict(), verdict())
    assert run(cfg, store, row, Writer(_refresh_poll_metadata), checker)["status"] == "published"
    assert checker.calls == 2


def test_routing_cannot_replace_a_newer_cluster_job(llm_context):
    """Raise `StaleCandidate` if `_route` races with a newer `cluster_key` assignment."""
    cfg, store = llm_context
    target = seed_source_story(store, item(url="https://example.org/route-target"))
    row = pending(store, item(url="https://example.org/route-source"))
    with pytest.raises(AnalysisError):
        run(cfg, store, row, Writer(), wire_reviewer(cfg, FetchError("Temporary error", status=500)))
    old_record, old_job = job_record(store), job(store)
    with store.db:
        store.db.execute("UPDATE items SET cluster_key=? WHERE id=?", ("new:" + row["cluster_key"], row["id"]))
    current = item_row(store, row)
    with pytest.raises(AnalysisError):
        run(cfg, store, current, Writer(), wire_reviewer(cfg, FetchError("Temporary error", status=500)))
    newer = copy.deepcopy(job(store))
    assert job_record(store)["request_budget"]["reserved"] == 2
    with pytest.raises(candidate.StaleCandidate):
        review_gate._route(store, row, analysis(), old_job["writer_key"], old_record, LATER, target["id"], "review")
    assert job(store) == newer
    refreshed = item_row(store, row)
    assert (refreshed["story_id"], refreshed["cluster_key"]) == (None, current["cluster_key"])


def test_stale_request_limit_does_not_reject_a_newer_revision(llm_context):
    """Return `stale` without rejecting a newer revision when an obsolete job hits the request cap."""
    cfg, store = llm_context
    src = item()
    row = pending(store, src)
    _exhaust_budget(cfg, store, row)
    assert job_record(store)["request_budget"]["reserved"] == review_gate.MAX_REVIEW_REQUESTS
    checker = wire_reviewer(cfg, verdict())
    inner = wire_reviewer(cfg, FetchError("Temporary transport error", status=500))
    saved = {}

    class _NewRevisionReviewer:
        @property
        def calls(self):
            """Delegate recorded call count to `checker`."""
            return checker.calls

        def review(self, *args, **kwargs):
            """Ingest and run a newer revision before delegating to `checker.review`."""
            updated = {**src, "content": "A newly supplied report changes the evidence."}
            assert store.ingest(updated, LATER)
            current = item_row(store, row)
            assert current["content_hash"] != row["content_hash"]
            with pytest.raises(AnalysisError):
                run(cfg, store, current, Writer(analysis(summary=updated["content"], evidence=[updated["content"]])), inner)
            saved.update(job=copy.deepcopy(job(store)), row=current)
            return checker.review(*args, **kwargs)

    assert run(cfg, store, row, Writer(), _NewRevisionReviewer())["status"] == "stale"
    assert checker.calls == 0 and inner.calls == 1
    assert job(store) == saved["job"]
    assert job_record(store)["request_budget"]["reserved"] == 1
    current = item_row(store, row)
    assert current["status"] == "pending" and current["content_hash"] == saved["row"]["content_hash"]
    assert "failed.review.request_limit" not in decision_codes(store)


@pytest.mark.parametrize("mutation", ["association", "content"])
@pytest.mark.parametrize("error_kind", ["retryable", "terminal", "unexpected"])
def test_cli_does_not_apply_an_obsolete_failure_to_new_work(llm_context, monkeypatch, mutation, error_kind):
    """Count obsolete writer/pipeline failures as `review_stale` without deferring the new item state."""
    cfg, store = llm_context
    cfg["sources"] = []
    target = seed_source_story(store, item(url="https://example.org/target", title="An existing account",
                                           content="An existing reported observation."))
    src = item(url="https://example.org/current-item", title="A current account",
               content="The source reports a further observation.")
    old = pending(store, src)
    saved = {}

    def _obsolete(_incoming, _prior=None):
        if mutation == "association":
            with store.db:
                store.db.execute("UPDATE items SET story_id=? WHERE id=?", (target["id"], old["id"]))
            draft = update_analysis(update=src["content"], evidence=[src["content"]])
        else:
            updated = {**src, "content": src["content"] + " A new revision adds detail.", "updated_at": LATER}
            assert store.ingest(updated, LATER)
            draft = analysis(summary=updated["content"], evidence=[updated["content"]])
        current = item_row(store, old)
        inner = wire_reviewer(cfg, FetchError("Current revision transport error", status=500))
        with pytest.raises(AnalysisError):
            run(cfg, store, current, Writer(draft), inner)
        if error_kind != "retryable":
            with store.db:
                store.db.execute("UPDATE items SET rejections=2 WHERE id=?", (old["id"],))
        saved.update(item=item_row(store, old), job=copy.deepcopy(job(store)), calls=inner.calls)
        if error_kind == "unexpected":
            raise RuntimeError("Obsolete processing failed")
        raise AnalysisError("Obsolete writer failed", retryable=error_kind == "retryable")

    patch_cli_pipeline(monkeypatch, now=LATER, analyzer=Writer.factory(_obsolete), reviewer=None, build=lambda *_args: {})
    report = cli.run(cfg, store)
    assert item_row(store, old) == saved["item"]
    assert job(store) == saved["job"] and saved["calls"] == 1
    assert job_record(store)["request_budget"]["reserved"] == 1
    assert report["analysis_failed"] == 0 and report["review_stale"] == 1


@pytest.mark.parametrize("terminal", [False, True])
def test_expected_row_deferral_preserves_legitimate_and_item_id_callers(llm_context, terminal):
    """Apply `store.defer` strikes normally when `expected_row` matches or is omitted."""
    cfg, store = llm_context
    row = pending(store)
    assert store.defer(row["id"], "Current failure", cfg["llm"], LATER, terminal=terminal, expected_row=row)
    current = item_row(store, row)
    assert current["attempts"] == 1 and current["rejections"] == int(terminal)
    assert current["status"] == "pending" and current["last_error"] == "Current failure"
    assert store.defer(row["id"], "Explicit item failure", cfg["llm"], LATER, terminal=terminal)
    current = item_row(store, row)
    assert current["attempts"] == 2 and current["rejections"] == 2 * int(terminal)


def test_cli_counts_current_review_limit_rejection_once(llm_context, monkeypatch):
    """Reject an item once with `failed.review.request_limit` when `cli.run` hits the request cap."""
    cfg, store = llm_context
    cfg["sources"] = []
    row = pending(store)
    _exhaust_budget(cfg, store, row)
    checker = wire_reviewer(cfg, verdict())
    patch_cli_pipeline(monkeypatch, now=LATER, analyzer=Writer.factory(), reviewer=lambda *_args, **_kwargs: checker, build=lambda *_args: {})
    report = cli.run(cfg, store)
    assert checker.calls == 0
    assert report["analysis_failed"] == 1 and report["review_stale"] == 0
    assert item_row(store, row)["status"] == "rejected"
    assert decision_codes(store) == ["failed.review.request_limit"]


def test_save_source_check_holds_the_write_transaction(llm_context):
    """Hold the SQLite write lock across `_save` source freshness checks."""
    cfg, store = llm_context
    row = pending(store)
    actual = store.db
    attempted = []

    class _ConcurrentAssociation:
        def __getattr__(self, name):
            return getattr(actual, name)

        def __enter__(self):
            actual.__enter__()
            return self

        def __exit__(self, *args):
            return actual.__exit__(*args)

        def execute(self, sql, parameters=()):
            """Attempt a concurrent SQLite write while `_save` holds the transaction."""
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

    store.db = _ConcurrentAssociation()
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


@pytest.mark.parametrize("concurrent_action", ["retract", "merge"])
def test_route_target_retracted_or_merged_mid_flight_returns_stale_and_reprepares(llm_context, concurrent_action):
    """Return `stale` without corrupting `review_jobs` when a `same_story` routing target is retracted or merged."""
    cfg, store = llm_context
    target = seed_source_story(
        store,
        item(url="https://example.org/route-race-target", product="tor", title="Existing relay crash report",
             content="Operators reported an existing relay crash on Tor."),
    )
    survivor = seed_source_story(
        store,
        item(url="https://example.org/route-race-survivor", product="tor", title="Primary relay crash report",
             content="Primary tracking report for the relay crash on Tor."),
    )
    publication.build(cfg, store)
    src = item(url="https://example.org/route-race-incoming", product="tor", title="Follow-up relay crash note",
               content="Additional note on the relay crash.")
    row = pending(store, src)
    draft = analysis(title=src["title"], summary=src["content"], why_it_matters="", evidence=[src["content"]])

    class _RetractOrMergeBeforeRoute:
        calls = 0

        def review(self, *_args, on_request=None, **_kwargs):
            """Retract or merge `target` during the initial review before `_route` executes."""
            if on_request is not None:
                on_request(1)
            self.calls += 1
            if concurrent_action == "retract":
                editorial_act(editorial.retract, store, target["id"], reason="Withdrawn target.", observed=LATER)
            else:
                editorial_act(editorial.merge, store, target["id"], survivor["id"], reason="Merged target.",
                              base_url=cfg["site"]["base_url"], observed=LATER)
            return verdict("skip", criterion="new_information", same_story=target["id"],
                           reason=f"Already covered by {target['id']}.")

    first = run(cfg, store, row, Writer(draft), _RetractOrMergeBeforeRoute())
    assert first["status"] == "stale"
    current = item_row(store, row)
    assert current["status"] == "pending" and current["rejections"] == 0
    saved = review_gate._saved_job(store, current, cfg)
    assert saved[0] is not None and saved[3]["request_budget"]["reserved"] == 1

    second_checker = wire_reviewer(cfg, verdict(), verdict())
    second = run(cfg, store, current, Writer(draft), second_checker)
    assert second["status"] == "published" and second_checker.calls == 2


def test_invalid_utf8_item_payload_raises_stale_candidate_without_sqlite_decode_error(llm_context):
    """Raise `StaleCandidate` cleanly without `sqlite3.OperationalError` or payload leaks when `items.payload` has invalid UTF-8."""
    cfg, store = llm_context
    secret_marker = "PRIVATE_SOURCE_SENTINEL_TEXT"
    row = pending(store, item(url="https://example.org/utf8-race", content=f"Valid prefix {secret_marker}."))
    prepared = candidate.prepare(store.db, row, analysis(evidence=[f"Valid prefix {secret_marker}."]), LATER)
    with store.db:
        store.db.execute("UPDATE items SET payload=replace(payload, 'Valid', CAST(x'fffe' AS TEXT)) WHERE id=?", (row["id"],))
    for fn in (
        lambda: candidate.verify_prepared_binding(store.db, prepared),
        lambda: candidate.prepare(store.db, row, analysis(evidence=[f"Valid prefix {secret_marker}."]), LATER),
    ):
        with pytest.raises(candidate.StaleCandidate) as caught:
            fn()
        assert secret_marker not in str(caught.value)


def test_same_hash_closed_at_update_preserves_queue_state_and_rejects_older_regression(llm_context):
    """Persist newer `closed_at` and freshness timestamp on same-hash ingest without allowing intermediate regressions."""
    cfg, store = llm_context
    src = item(kind="gitlab_issue", upstream_state="closed", published_at="2026-09-01T12:00:00Z",
               updated_at="2026-11-09T12:00:00Z")
    row = pending(store, src)
    assert store.defer(row["id"], "Temporary error", cfg["llm"], LATER, terminal=True, expected_row=row) is True
    before = item_row(store, row)
    assert (before["attempts"], before["rejections"], before["status"]) == (1, 1, "pending")

    nov12 = "2026-11-12T00:00:00Z"
    assert store.ingest({**src, "updated_at": nov12, "closed_at": nov12}, nov12) is False
    after_update = item_row(store, row)
    assert after_update["content_hash"] == before["content_hash"]
    assert (after_update["attempts"], after_update["rejections"], after_update["status"]) == (1, 1, "pending")
    assert after_update["last_error"] == before["last_error"]
    saved_after = json.loads(after_update["payload"])
    assert saved_after["closed_at"] == nov12 and saved_after["updated_at"] == nov12

    # A delayed intermediate poll (Nov 11, newer than original Nov 9 but older than Nov 12) must not overwrite closed_at.
    nov11 = "2026-11-11T00:00:00Z"
    assert store.ingest({**src, "updated_at": nov11, "closed_at": nov11}, nov12) is False
    after_mid = json.loads(item_row(store, row)["payload"])
    assert after_mid["closed_at"] == nov12 and after_mid["updated_at"] == nov12

    # An older REST poll must not regress the stored closed_at either.
    assert store.ingest({**src, "updated_at": "2026-11-08T00:00:00Z", "closed_at": "2026-10-01T00:00:00Z"}, nov12) is False
    assert json.loads(item_row(store, row)["payload"])["closed_at"] == nov12


def test_same_hash_confirming_closed_at_poll_advances_freshness_against_delayed_intermediate(llm_context):
    """Advance freshness when a newer poll confirms the same `closed_at` so delayed intermediate polls cannot overwrite it."""
    cfg, store = llm_context
    nov9 = "2026-11-09T12:00:00Z"
    nov11 = "2026-11-11T00:00:00Z"
    nov12 = "2026-11-12T00:00:00Z"
    src = item(
        kind="gitlab_issue",
        upstream_state="closed",
        published_at="2026-09-01T12:00:00Z",
        updated_at=nov9,
        closed_at=nov9,
    )
    row = pending(store, src)
    assert store.defer(row["id"], "Temporary error", cfg["llm"], LATER, terminal=True, expected_row=row) is True
    before = item_row(store, row)

    # Newer poll confirms the same closed_at -> advances stored updated_at while preserving hash and queue state.
    assert store.ingest({**src, "updated_at": nov12, "closed_at": nov9}, nov12) is False
    confirmed = item_row(store, row)
    assert confirmed["content_hash"] == before["content_hash"]
    assert (confirmed["attempts"], confirmed["rejections"], confirmed["status"]) == (1, 1, "pending")
    assert confirmed["last_error"] == before["last_error"]
    confirmed_payload = json.loads(confirmed["payload"])
    assert confirmed_payload["closed_at"] == nov9 and confirmed_payload["updated_at"] == nov12

    # Delayed intermediate poll (Nov 11) with a different closed_at must not overwrite the Nov 12 confirmed value.
    assert store.ingest({**src, "updated_at": nov11, "closed_at": nov11}, nov12) is False
    after_delayed = json.loads(item_row(store, row)["payload"])
    assert after_delayed["closed_at"] == nov9 and after_delayed["updated_at"] == nov12

    # Compacted closed issue follows the same freshness invariant when a newer poll confirms closed_at.
    store.db.executescript(_RETENTION_SCHEMA)
    comp_src = item(
        url="https://gitlab.torproject.org/tpo/core/tor/-/issues/999",
        kind="gitlab_issue",
        upstream_state="closed",
        published_at="2026-09-01T12:00:00Z",
        updated_at=nov9,
        closed_at=nov9,
    )
    comp_row = pending(store, comp_src)
    comp_payload = {k: v for k, v in json.loads(comp_row["payload"]).items() if k != "content"}
    with store.db:
        store.db.execute(
            "UPDATE items SET status='ignored',payload=? WHERE id=?",
            (json.dumps(comp_payload, ensure_ascii=False), comp_row["id"]),
        )
        store.db.execute(
            "INSERT INTO private_archive_refs VALUES('item',?,?,?,?,?,?)",
            (comp_row["id"], comp_row["content_hash"], "archive/batch-closed.jsonl.zst", "a" * 64, nov9, '{"bucket":"cold"}'),
        )
    assert store.ingest({**comp_src, "updated_at": nov12, "closed_at": nov9}, nov12) is False
    comp_confirmed_row = item_row(store, comp_row)
    comp_confirmed = json.loads(comp_confirmed_row["payload"])
    assert comp_confirmed_row["status"] == "ignored" and "content" not in comp_confirmed
    assert comp_confirmed["closed_at"] == nov9 and comp_confirmed["updated_at"] == nov12
    assert store.ingest({**comp_src, "updated_at": nov11, "closed_at": nov11}, nov12) is False
    comp_after_row = item_row(store, comp_row)
    comp_after = json.loads(comp_after_row["payload"])
    assert comp_after_row["status"] == "ignored" and "content" not in comp_after
    assert comp_after["closed_at"] == nov9 and comp_after["updated_at"] == nov12
