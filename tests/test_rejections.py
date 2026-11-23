"""One-item operator decisions preserve story state and the private audit trail."""

import copy
import json
import sqlite3

import pytest

from helpers import (
    DAMAGE, DATE, LATER, TOR_WORK_ITEM_URL, FakeClient, Reviewer, Writer, analysis, damage_item, decision_codes,
    editorial_act, enrich_with_client, finish_reviewed, gitlab_source, gql_note, gql_notes_response, invoke_cli, item,
    item_row, job, job_record, make_config, pending, queued_row, run_gate, seed_ignored, seed_rejected, seed_story,
    verdict, write_toml,
)
from onionflash import cli, editorial, rejection, review, review_gate
from onionflash.analyze import AnalysisError, cache_key
from onionflash.config import DEFAULTS
from onionflash.store import Store
from onionflash.util import after


def _failed_pending(store, *, terminal=False):
    src = item(url="https://example.org/failed-pending")
    store.ingest(src, DATE)
    store.defer(src["id"], "Saved analysis failed", DEFAULTS["llm"], DATE, terminal=terminal)
    return src, item_row(store, src)


def _analysis_result(store, key):
    row = store.db.execute("SELECT result FROM analyses WHERE cache_key=?", (key,)).fetchone()
    return json.loads(row[0]) if row is not None else None


def _actions(store):
    return [dict(row) for row in store.db.execute("SELECT * FROM rejection_actions ORDER BY action_id")]


@pytest.mark.parametrize("kind", [*DAMAGE, "blob"])
def test_a_damaged_saved_item_stays_inspectable_and_dismissable_but_not_retried(store, kind):
    """List, inspect, and dismiss damaged strike-rejected payloads while refusing `retry_item`."""
    _, row = seed_rejected(store, 0)
    _, intact = seed_rejected(store, 1)
    damage_item(store.db, row["id"], kind)
    listed = {entry["id"]: entry["title"] for entry in rejection.list_items(store)["items"]}
    assert listed == {row["id"]: None, intact["id"]: json.loads(intact["payload"])["title"]}
    shown = rejection.show_item(store, row["id"])
    assert shown["saved_item"] is None and shown["content_hash"] == row["content_hash"]
    with pytest.raises(ValueError, match="incomplete or unreadable"):
        rejection.retry_item(store, row["id"], row["content_hash"], "try again")
    assert rejection.dismiss_item(store, row["id"], row["content_hash"], "damaged copy")["status"] == "dismissed"


@pytest.mark.parametrize("title", [[1], {"a": 1}, 5, True])
def test_only_text_is_listed_as_a_title(store, title):
    """Coerce non-string stored titles to `None` in `rejection.list_items`."""
    _, row = seed_rejected(store)
    store.db.execute("UPDATE items SET payload=? WHERE id=?",
                     (json.dumps({**json.loads(row["payload"]), "title": title}), row["id"]))
    store.db.commit()
    assert rejection.list_items(store)["items"][0]["title"] is None


def test_list_excludes_transient_failures_and_is_bounded_with_stable_pagination(store):
    """Exclude transient retries from `list_items` and paginate terminally rejected rows stably."""
    transient = item(url="https://example.org/transient")
    store.ingest(transient, DATE)
    for _ in range(5):
        store.defer(transient["id"], "LLM request failed (HTTP 503)", DEFAULTS["llm"], DATE)
    expected = [seed_rejected(store, number)[0]["id"] for number in range(5)]
    first = rejection.list_items(store, limit=2)
    second = rejection.list_items(store, limit=2, after=first["next_cursor"])
    third = rejection.list_items(store, limit=2, after=second["next_cursor"])
    entries = first["items"] + second["items"] + third["items"]
    assert [entry["id"] for entry in entries] == sorted(expected)
    assert third["next_cursor"] is None
    assert all(e["attempts"] == 3 and e["rejections"] == 3 and e["next_attempt_at"] is None for e in entries)
    assert all(e["rejection_reason"] == "Model evidence is not present in source" for e in entries)
    assert all(e["source_url"].startswith("https://example.org/news/") for e in entries)
    assert "The operator reported" not in json.dumps(first)
    assert not _actions(store)
    queued = queued_row(store, transient["id"], after(86400, DATE))
    assert queued["attempts"] == 5 and queued["rejections"] == 0


def test_show_is_explicit_source_inspection(store):
    """Return full saved item content and empty action history on initial `show_item`."""
    src, row = seed_rejected(store)
    shown = rejection.show_item(store, src["id"])
    assert shown["saved_item"]["content"] == src["content"]
    assert shown["content_hash"] == row["content_hash"] and shown["actions"] == []


def test_retry_queues_the_revision_and_leaves_analysis_records_unchanged(store, capsys):
    """Requeue a rejected item cleanly via `retry_item` without mutating prior `analyses` rows."""
    _, row = seed_rejected(store)
    key = cache_key(row, DEFAULTS["llm"])
    with store.db:
        store.record_analysis(row, analysis(), key, DATE)
    before = [tuple(record) for record in store.db.execute("SELECT * FROM analyses")]
    result = rejection.retry_item(store, row["id"], row["content_hash"], "Grounding rule was repaired", DATE)
    [queued] = store.pending(10, DATE)
    assert (queued["status"], queued["attempts"], queued["rejections"], queued["next_attempt_at"], queued["last_error"]) == (
        "pending", 0, 0, None, None
    )
    assert [tuple(record) for record in store.db.execute("SELECT * FROM analyses")] == before
    assert store.stories() == []
    audit = _actions(store)[0]
    assert (audit["before_status"], audit["before_attempts"], audit["before_rejections"]) == ("rejected", 3, 3)
    assert audit["reason"] == "Grounding rule was repaired"
    assert "content" not in result and "reason" not in result and capsys.readouterr().out == ""
    finish_reviewed(store, queued, analysis(summary="A supported account after retry."), key, after(60, DATE))
    assert store.pending_count() == 0
    story = store.stories()[0]
    assert story["summary"] == "A supported account after retry."
    assert _analysis_result(store, key) == analysis()
    assert _analysis_result(store, story["editorial_analysis_key"])["summary"] == "A supported account after retry."
    assert len(_actions(store)) == 1


def test_retry_undoes_a_mistaken_dismissal(store):
    """Allow `retry_item` to requeue a dismissed item and refuse duplicate actions."""
    _, row = seed_rejected(store)
    rejection.dismiss_item(store, row["id"], row["content_hash"], "Dismissed by mistake", DATE)
    with pytest.raises(ValueError, match="terminally rejected"):
        rejection.dismiss_item(store, row["id"], row["content_hash"], "Again", DATE)
    assert rejection.retry_item(store, row["id"], row["content_hash"], "A real report", DATE)["status"] == "pending"
    assert store.pending_count() == 1
    for operation in (rejection.retry_item, rejection.dismiss_item):
        with pytest.raises(ValueError, match="terminally rejected"):
            operation(store, row["id"], row["content_hash"], "Again", DATE)
    assert [(a["action"], a["before_status"]) for a in _actions(store)] == [("dismiss", "rejected"), ("retry", "dismissed")]


def test_dismissal_stops_unchanged_and_timestamp_only_replays_but_new_content_requeues(store):
    """Keep dismissed items suppressed across unchanged polls until upstream content changes."""
    src, row = seed_rejected(store)
    key = cache_key(row, DEFAULTS["llm"])
    with store.db:
        store.db.execute("INSERT INTO analyses(cache_key,result,created_at) VALUES(?,?,?)", (key, "{}", DATE))
    assert rejection.dismiss_item(store, row["id"], row["content_hash"], "Routine discussion with no news", DATE)["status"] == "dismissed"
    assert _analysis_result(store, key) == {}
    assert store.pending_count() == 0 and store.rejected_count() == 0
    assert not store.ingest(copy.deepcopy(src), after(60, DATE))
    assert not store.ingest({**src, "updated_at": after(120, DATE)}, after(120, DATE))
    store.defer(row["id"], "late failure", DEFAULTS["llm"], after(120, DATE), terminal=True)
    shown = rejection.show_item(store, row["id"])
    assert shown["status"] == "dismissed" and shown["rejections"] == 3
    assert rejection.list_items(store)["items"] == []
    assert rejection.list_items(store, status="dismissed")["items"][0]["id"] == row["id"]
    assert store.ingest({**src, "content": "A genuinely changed source report.", "updated_at": after(180, DATE)}, after(180, DATE))
    current = rejection.show_item(store, row["id"])
    assert current["status"] == "pending" and current["content_hash"] != row["content_hash"]
    assert current["attempts"] == current["rejections"] == 0
    assert current["actions"][0]["content_hash"] == row["content_hash"]


def test_dismiss_clears_held_job_approval_key_and_active_stage(store):
    """Clear `approval_key` and active held stage in `review_jobs` when dismissing a held item."""
    row = pending(store, item(url="https://example.org/held-dismiss"), ready=DATE)
    with store.db:
        store.db.execute(
            "INSERT INTO review_jobs(item_id,writer_key,policy_hash,stage,record_json,approval_key,prepared_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
            (row["id"], "wk", "ph", "held", "{}", "app-key-1", DATE, DATE),
        )
    store.reject(row["id"], "Held for operator review", "held.review.model_hold", after(30, DATE))
    assert review_gate.status(store)["stages"] == {"held": 1}
    rejection.dismiss_item(store, row["id"], row["content_hash"], "Not needed.", observed=after(60, DATE))
    assert review_gate.status(store)["stages"] == {} and job(store, row)["approval_key"] is None


def test_stale_hash_and_new_pending_actions_are_rejected_without_audit(store):
    """Refuse stale `content_hash` values and untouched pending revisions without recording audits."""
    src, row = seed_rejected(store)
    store.ingest({**src, "content": "Changed source", "updated_at": after(60, DATE)}, after(60, DATE))
    with pytest.raises(ValueError, match="content changed"):
        rejection.dismiss_item(store, row["id"], row["content_hash"], "Old view", DATE)
    current = rejection.show_item(store, row["id"])
    with pytest.raises(ValueError, match="terminally rejected"):
        rejection.retry_item(store, row["id"], current["content_hash"], "New source revision", DATE)
    assert _actions(store) == []


@pytest.mark.parametrize("failures", [1, 3])
@pytest.mark.parametrize("locked", [False, True])
def test_retry_and_dismiss_do_not_mutate_an_existing_story_or_editorial_state(store, failures, locked):
    """Preserve existing story text and editorial lock state across item retries and dismissals."""
    src = item()
    original = seed_story(store, src, analysis(), at=DATE)
    original_story_id = original["id"]
    if locked:
        editorial_act(editorial.correct, store, original_story_id, {"why_it_matters": "Operator-corrected text."},
                      reason="Operator correction", observed=DATE)
    store.ingest({**src, "content": src["content"] + " A disputed later revision.", "updated_at": after(60, DATE)}, after(60, DATE))
    for _ in range(failures):
        store.defer(src["id"], "Unsupported later claim", DEFAULTS["llm"], DATE, terminal=True)
    before = editorial.show(store.db, original_story_id)
    current = rejection.show_item(store, src["id"])
    assert current["final_review"] is None
    rejection.retry_item(store, src["id"], current["content_hash"], "Check repaired reviewer", DATE)
    for _ in range(failures):
        store.defer(src["id"], "Still unsupported", DEFAULTS["llm"], DATE, terminal=True)
    rejection.dismiss_item(store, src["id"], current["content_hash"], "Keep the earlier accepted account", DATE)
    assert editorial.show(store.db, original_story_id) == before and before["locked"] == locked
    assert rejection.show_item(store, src["id"])["story_id"] == original_story_id


@pytest.mark.parametrize("field", ["content", "url", "updated_at", "public_comments"])
def test_retry_refuses_an_incomplete_saved_item_but_dismiss_still_works(store, field):
    """Refuse `retry_item` when required item fields or `public_comments` are malformed, while allowing dismiss."""
    _, row = seed_rejected(store)
    payload = json.loads(row["payload"])
    if field == "public_comments":
        payload["public_comments"] = [{"author": "op"}]
    else:
        payload.pop(field)
    with store.db:
        store.db.execute("UPDATE items SET payload=? WHERE id=?", (json.dumps(payload), row["id"]))
    with pytest.raises(ValueError, match="incomplete or unreadable"):
        rejection.retry_item(store, row["id"], row["content_hash"], "Try again", DATE)
    assert _actions(store) == []
    rejection.dismiss_item(store, row["id"], row["content_hash"], "No usable stored body", DATE)
    assert rejection.show_item(store, row["id"])["status"] == "dismissed"


@pytest.mark.parametrize("is_pending", [False, True])
def test_failed_audit_insert_rolls_back_the_action(store, is_pending):
    """Roll back item state changes if inserting into `rejection_actions` fails."""
    _, row = _failed_pending(store) if is_pending else seed_rejected(store)
    with store.db:
        store.db.execute("""CREATE TRIGGER fail_rejection_audit BEFORE INSERT ON rejection_actions
                         BEGIN SELECT RAISE(ABORT,'audit unavailable'); END""")
    with pytest.raises(sqlite3.IntegrityError):
        rejection.retry_item(store, row["id"], row["content_hash"], "Retry", DATE)
    assert rejection.show_item(store, row["id"])["status"] == row["status"] and _actions(store) == []


def test_an_earlier_release_can_still_use_the_audit_table(store):
    """Accept legacy `rejection_actions` rows carrying `NULL` superseded-analysis columns."""
    _, row = seed_rejected(store)
    with store.db:
        store.db.execute(
            """INSERT INTO rejection_actions(item_id,content_hash,action,reason,created_at,before_status,
               before_attempts,before_rejections,before_error,before_next_attempt_at,superseded_analysis_key,superseded_analysis_json)
               VALUES(?,?,'dismiss','Reviewed',?,'rejected',3,3,NULL,NULL,NULL,NULL)""",
            (row["id"], row["content_hash"], DATE),
        )
    assert store.db.execute("SELECT superseded_analysis_key FROM rejection_actions").fetchone()[0] is None
    assert rejection.show_item(store, row["id"])["actions"][0]["reason"] == "Reviewed"


def test_content_changed_during_retry_does_not_get_overwritten(store, monkeypatch):
    """Abort `retry_item` if a concurrent writer updates `content_hash` after validation."""
    _, row = seed_rejected(store)
    ready = rejection._ready
    database = store.db.execute("PRAGMA database_list").fetchone()[2]

    def _concurrent_change(current):
        ready(current)
        with sqlite3.connect(database) as writer:
            writer.execute("UPDATE items SET content_hash=? WHERE id=?", ("f" * 64, row["id"]))

    monkeypatch.setattr(rejection, "_ready", _concurrent_change)
    with pytest.raises(ValueError, match="changed during"):
        rejection.retry_item(store, row["id"], row["content_hash"], "Reviewed", DATE)
    current = rejection.show_item(store, row["id"])
    assert current["status"] == "rejected" and current["content_hash"] == "f" * 64 and _actions(store) == []


@pytest.mark.parametrize("reason", ["", "   ", "x" * 1001, "bad\x1bvalue", "bad\ud800value"])
def test_reason_is_required_and_bounded(store, reason):
    """Reject empty, overlong, control-character, or surrogate operator action reasons."""
    _, row = seed_rejected(store)
    with pytest.raises(ValueError, match="reason"):
        rejection.dismiss_item(store, row["id"], row["content_hash"], reason, DATE)
    assert rejection.show_item(store, row["id"])["status"] == "rejected" and _actions(store) == []


@pytest.mark.parametrize("kwargs", [{"limit": 0}, {"limit": True}, {"limit": 201}, {"after": "../bad"}, {"status": "pending"}])
def test_list_arguments_are_bounded(store, kwargs):
    """Validate `limit`, `after`, and `status` bounds in `rejection.list_items`."""
    with pytest.raises(ValueError):
        rejection.list_items(store, **kwargs)


@pytest.mark.parametrize("action", ["retry", "dismiss"])
@pytest.mark.parametrize("terminal", [False, True])
def test_failed_pending_actions_preserve_audit_and_do_not_repeat(store, action, terminal):
    """Allow retrying or dismissing failed pending items once with full before-state audit."""
    src, row = _failed_pending(store, terminal=terminal)
    key = cache_key(row, DEFAULTS["llm"])
    with store.db:
        store.db.execute("INSERT INTO analyses(cache_key,result,created_at) VALUES(?,?,?)", (key, "{}", DATE))
    operation = (lambda: rejection.retry_item(store, row["id"], row["content_hash"], "Reviewed failure", DATE)) if action == "retry" else (
        lambda: rejection.dismiss_item(store, row["id"], row["content_hash"], "Redundant source revision", DATE))
    result = operation()
    current = rejection.show_item(store, row["id"])
    audit = _actions(store)[0]
    assert audit["before_status"] == "pending" and audit["before_attempts"] == 1
    assert audit["before_rejections"] == int(terminal) and audit["before_error"] == "Saved analysis failed"
    assert audit["before_next_attempt_at"] == row["next_attempt_at"]
    assert current["next_attempt_at"] is None and store.stories() == []
    assert set(result) == {"item_id", "content_hash", "action", "status", "action_id"}
    assert _analysis_result(store, key) == {}
    if action == "retry":
        assert current["status"] == "pending" and current["attempts"] == current["rejections"] == 0
        assert current["rejection_reason"] is None
    else:
        assert current["status"] == "dismissed"
        assert not store.ingest(copy.deepcopy(src), after(60, DATE))
        assert not store.ingest({**src, "updated_at": after(120, DATE)}, after(120, DATE))
        assert store.pending_count() == 0
    with pytest.raises(ValueError, match="previously failed pending"):
        operation()
    assert len(_actions(store)) == 1


@pytest.mark.parametrize("action,status,attempts,error", [(action, *case) for action in ("retry", "dismiss") for case in [
    ("pending", 0, None), ("pending", 0, "old error"), ("pending", 1, None),
    ("pending", 1, "  \t"), ("pending", -1, "old error"),
    ("published", 2, "old error"), ("ignored", 2, "old error"), ("dismissed", 2, "old error"),
] if action == "dismiss" or case[0] not in {"dismissed", "ignored"}])
def test_new_or_completed_items_cannot_be_acted_on(store, action, status, attempts, error):
    """Refuse operator retry/dismiss actions on fresh pending or already published items."""
    _, row = _failed_pending(store)
    with store.db:
        store.db.execute("UPDATE items SET status=?,attempts=?,last_error=? WHERE id=?", (status, attempts, error, row["id"]))
    before = item_row(store, row)
    with pytest.raises(ValueError, match="previously failed pending"):
        getattr(rejection, action + "_item")(store, row["id"], row["content_hash"], "Reviewed", DATE)
    assert item_row(store, row) == before and _actions(store) == []


def test_pending_retry_restarts_review_and_reuses_draft(store):
    """Reset saved review work on `retry_item` while reusing the saved writer draft."""
    row = pending(store, ready=DATE)
    with pytest.raises(AnalysisError):
        run_gate(DEFAULTS, store, row, checker=Reviewer(AnalysisError("Request timed out", retryable=True)), observed=DATE)
    store.defer(row["id"], "Final review request failed", DEFAULTS["llm"], DATE)
    rejection.retry_item(store, row["id"], row["content_hash"], "Review policy repaired", DATE)
    assert job(store, row)["stage"] == "drafted" and job_record(store, row)["reviews"] == []
    writer = Writer()
    result = run_gate(DEFAULTS, store, store.pending(1, DATE)[0], writer, observed=DATE)
    assert result["status"] == "published" and writer.calls == []
    assert _actions(store)[0]["before_status"] == "pending"


def test_dismissed_failed_pending_revision_only_requeues_on_source_change(store):
    """Requeue a dismissed failed-pending item only when upstream source text changes."""
    src, row = _failed_pending(store)
    rejection.dismiss_item(store, row["id"], row["content_hash"], "Already covered", DATE)
    assert store.ingest({**src, "content": src["content"] + " Additional source evidence.", "updated_at": after(60, DATE)},
                        after(60, DATE))
    fresh = rejection.show_item(store, row["id"])
    assert fresh["status"] == "pending" and fresh["attempts"] == 0
    with pytest.raises(ValueError, match="content changed"):
        rejection.dismiss_item(store, row["id"], row["content_hash"], "Stale inspection", DATE)
    with pytest.raises(ValueError, match="previously failed pending"):
        rejection.dismiss_item(store, row["id"], fresh["content_hash"], "New evidence not analyzed", DATE)
    assert len(_actions(store)) == 1


@pytest.mark.parametrize("action", ["retry", "dismiss"])
@pytest.mark.parametrize("change", [
    "status='published'", "attempts=attempts+1", "rejections=rejections+1",
    "last_error=NULL", "next_attempt_at=NULL", "payload='{\"other\": 1}'",
    "payload=replace(payload, 'title', 'título')", "payload=CAST(x'7b22ff22' AS TEXT)",
])
def test_concurrent_pending_queue_change_is_not_overwritten(store, monkeypatch, action, change):
    """Abort failed-pending retry/dismiss if any queue column changes concurrently after `_checked`."""
    _, row = _failed_pending(store)
    original = rejection._checked
    database = store.db.execute("PRAGMA database_list").fetchone()[2]

    def _changed_after_read(db, item_id, expected_hash, **kwargs):
        captured = original(db, item_id, expected_hash, **kwargs)
        with sqlite3.connect(database) as other:
            other.execute(f"UPDATE items SET {change} WHERE id=?", (item_id,))
        return captured

    monkeypatch.setattr(rejection, "_checked", _changed_after_read)
    with pytest.raises(ValueError, match="changed during"):
        getattr(rejection, action + "_item")(store, row["id"], row["content_hash"], "Reviewed", DATE)
    current = store.db.execute("SELECT content_hash,status FROM items WHERE id=?", (row["id"],)).fetchone()
    assert current["content_hash"] == row["content_hash"]
    assert current["status"] != "dismissed" and _actions(store) == []


def test_ignored_reconsideration_is_explicit_audited_and_one_item_only(store):
    """Reconsider a single `ignored` item via `retry_item` while leaving sibling items untouched."""
    _, row = seed_ignored(store)
    _, other = seed_ignored(store, 1)
    key = cache_key(row, DEFAULTS["llm"])
    with pytest.raises(ValueError, match="previously failed pending"):
        rejection.dismiss_item(store, row["id"], row["content_hash"], "Reviewed selection", DATE)
    assert _actions(store) == []
    result = rejection.retry_item(store, row["id"], row["content_hash"], "Reviewed selection", DATE)
    assert result["status"] == "pending" and store.stories() == []
    current = item_row(store, row)
    assert current["attempts"] == current["rejections"] == 0
    assert current["last_error"] is None and current["next_attempt_at"] is None
    for field in ("payload", "content_hash", "source_id", "url", "first_seen", "last_seen", "story_id"):
        assert current[field] == row[field]
    assert item_row(store, other) == other
    audit = _actions(store)[0]
    assert audit["before_status"] == "ignored" and audit["action"] == "retry" and audit["reason"] == "Reviewed selection"
    assert audit["superseded_analysis_key"] is None and audit["superseded_analysis_json"] is None
    assert _analysis_result(store, key) == analysis()
    with pytest.raises(ValueError, match="previously failed pending"):
        rejection.retry_item(store, row["id"], row["content_hash"], "Duplicate retry", DATE)
    assert len(_actions(store)) == 1


def _reviewed_skip(store):
    if not store.stories():
        seed_story(store, item(url="https://example.org/earlier-report", content="An earlier distinct report on the topic."),
                   analysis(), at=DATE)
    covered_id = store.stories()[0]["id"]
    reply = verdict("skip", criterion="new_information", reason=f"Already covered in {covered_id}.")
    row = pending(store, item(url="https://example.org/reconsidered-report"), ready=DATE)
    checker = Reviewer(reply)
    assert run_gate(DEFAULTS, store, row, checker=checker, observed=DATE)["status"] == "ignored"
    assert review._skip_stands(reply["criteria"], checker.coverages[0])
    assert job(store, row) is None and not store.db.execute("SELECT 1 FROM review_approvals").fetchone()
    return row, checker.calls[0][0]


def test_a_skip_is_listed_with_its_reason_and_shows_its_decision_and_coverage(store):
    """Display skip criteria and coverage context for `ignored` items in `list_items` and `show_item`."""
    seed_story(store, item(url="https://example.org/earlier-report"), analysis(), at=DATE)
    row, _ = _reviewed_skip(store)
    listed = rejection.list_items(store, status="ignored")["items"]
    assert [(e["id"], e["story_id"], e["rejection_reason"]) for e in listed] == [
        (row["id"], None, "Final review skipped: new_information")
    ]
    shown = rejection.show_item(store, row["id"])["final_review"]
    assert shown["stage"] == "finished" and shown["latest_review"]["criteria"]["new_information"]["outcome"] == "fail"
    assert [entry["id"] for entry in shown["coverage"]["recent"]] == [store.stories()[0]["id"]]
    with store.db:
        store.record_analysis(row, analysis(), "commit-without-a-record", DATE)
    assert rejection.show_item(store, row["id"])["final_review"] is None


def test_explicit_reconsideration_gets_a_fresh_decision(store):
    """Run fresh review and verification calls without cache hits when an ignored item is retried."""
    row, candidate = _reviewed_skip(store)
    rejection.retry_item(store, row["id"], row["content_hash"], "Reconsider this editorial decision", DATE)
    checker = Reviewer(verdict())
    result = run_gate(DEFAULTS, store, store.pending(1, DATE)[0], checker=checker, observed=DATE)
    assert result["status"] == "published" and not result["cache_hit"]
    assert result["review_calls"] == 2 and checker.calls[0][0] == candidate
    assert [call[2] for call in checker.calls] == [False, True]


def test_show_prints_a_skip_that_repeats_the_first_decision_after_a_hold(store):
    """Show the latest `skip` review record when a retried held item skips again."""
    row, _ = _reviewed_skip(store)
    rejection.retry_item(store, row["id"], row["content_hash"], "Reconsider this editorial decision", DATE)
    assert run_gate(DEFAULTS, store, store.pending(1, DATE)[0], checker=Reviewer(verdict("hold")), observed=DATE)["status"] == "held"
    rejection.retry_item(store, row["id"], row["content_hash"], "Retry the held item", DATE)
    _reviewed_skip(store)
    assert rejection.show_item(store, row["id"])["final_review"]["latest_review"]["verdict"] == "skip"


def test_rejected_cli_retry_has_no_publication_or_model_call(tmp_path, store, capsys):
    """List, escape bidi controls in `show`, dismiss, and retry rejected items via CLI."""
    cfg_path = write_toml(tmp_path)
    story_id = seed_story(store, item(), analysis(), key="seed", at=DATE)["id"]
    _, row = seed_rejected(store, content="Rejected source \u202e text")
    listed = invoke_cli(capsys, "rejected", "list", "--config", cfg_path)
    assert len(listed["items"]) == 1 and listed["items"][0]["attempts"] == 3
    assert invoke_cli(capsys, "rejected", "list", "--config", cfg_path, "--status", "ignored")["items"] == []
    assert cli.main(["rejected", "show", "--config", str(cfg_path), "--item", row["id"]]) == 0
    raw = capsys.readouterr().out
    assert "\\u202e" in raw and "\u202e" not in raw
    assert invoke_cli(capsys, "rejected", "dismiss", "--config", cfg_path, "--item", row["id"], "--expect-hash",
                      row["content_hash"], "--reason", "Dismissed by mistake")["status"] == "dismissed"
    retried = invoke_cli(capsys, "rejected", "retry", "--config", cfg_path, "--item", row["id"],
                         "--expect-hash", row["content_hash"], "--reason", "Review rule corrected")
    assert retried["status"] == "pending"
    assert store.pending_count() == 1 and len(store.stories()) == 1 and store.stories()[0]["id"] == story_id


@pytest.mark.parametrize("record_damage", [
    b"\x80",
    b'{"prepared":1}',
    '{"x":"\\ud800"}',
    "{" + '"a":' * 70 + "1" + "}" * 70,
    '{"prepared": [], "reviews": "bad"}',
    '{"prepared": {}, "reviews": {}}',
    '{"prepared": {}, "reviews": [], "approval": {"reviews": {}}}',
    '{"prepared": {}, "reviews": [], "approval": "bad"}',
])
def test_rejected_controls_and_cli_handle_blobs_surrogates_deep_json_and_damaged_records(tmp_path, store, capsys, record_damage):
    """Handle raw blobs, surrogates, deep JSON, and damaged `record_json` cleanly in `rejected` CLI."""
    cfg_path = write_toml(tmp_path)
    _, row = seed_rejected(store, 0)
    store.db.execute("UPDATE items SET payload=X'80' WHERE id=?", (row["id"],))
    store.db.execute(
        "INSERT INTO review_jobs(item_id,writer_key,policy_hash,stage,prepared_at,record_json,updated_at) VALUES(?,?,?,?,?,?,?)",
        (row["id"], "wk", "ph", "held", DATE, record_damage, DATE),
    )
    store.db.commit()

    shown = rejection.show_item(store, row["id"], DEFAULTS)
    assert shown["saved_item"] is None
    assert shown["final_review"]["error"] == "Saved review record cannot be read"
    assert shown["final_review"]["approval"]["eligible"] is False
    with pytest.raises(ValueError, match="incomplete or unreadable"):
        rejection.retry_item(store, row["id"], row["content_hash"], "cannot retry raw blob", DATE)

    capsys.readouterr()
    listed_out = invoke_cli(capsys, "rejected", "list", "--config", cfg_path)
    assert listed_out["items"][0]["id"] == row["id"] and listed_out["items"][0]["title"] is None

    shown_out = invoke_cli(capsys, "rejected", "show", "--item", row["id"], "--config", cfg_path)
    assert shown_out["saved_item"] is None and shown_out["final_review"]["error"] == "Saved review record cannot be read"
    assert rejection.dismiss_item(store, row["id"], row["content_hash"], "dismiss raw blob", DATE)["status"] == "dismissed"


@pytest.mark.parametrize("bad_cols", [
    {"writer_key": b"blob"},
    {"writer_key": "wk"},
    {"writer_key": "corrupt", "policy_hash": "corrupt"},
    {"policy_hash": "ph"},
    {"prepared_at": "not-a-timestamp"},
])
def test_retry_item_clears_damaged_review_jobs_columns_and_publishes_cleanly(store, bad_cols):
    """Delete damaged `review_jobs` rows during `rejection.retry_item` so `process_item` recovers cleanly."""
    _, row = seed_rejected(store, 0)
    prepared = store.prepare_candidate(row, analysis(), DATE)
    valid_wk = cache_key(row, DEFAULTS["llm"])
    valid_ph = review.policy_hash(DEFAULTS)
    rec = review_gate._new_record(dict(row), {"key": valid_wk}, policy_hash=valid_ph)
    cols = {
        "writer_key": valid_wk,
        "policy_hash": valid_ph,
        "prepared_at": DATE,
        **bad_cols,
    }
    with store.db:
        store.db.execute(
            """INSERT INTO review_jobs(item_id,writer_key,policy_hash,stage,prepared_at,draft_json,envelope_json,record_json,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (row["id"], cols["writer_key"], cols["policy_hash"], "review", cols["prepared_at"],
             json.dumps(analysis()), json.dumps(prepared), json.dumps(rec), DATE),
        )
    retried = rejection.retry_item(store, row["id"], row["content_hash"], "Recover damaged review job", DATE)
    assert retried["status"] == "pending" and job(store, row["id"]) is None
    res = review_gate.process_item(DEFAULTS, store, queued_row(store, row["id"], DATE), Writer(), Reviewer(verdict()), DATE)
    assert res["status"] == "published" and len(store.stories()) == 1


def test_retracted_recent_story_and_damaged_criteria_do_not_crash_rejected_show_or_approve(tmp_path, store, capsys):
    """Handle retracted stories in `new_coverage` and malformed `criteria` cleanly in `rejected show` and `approve`."""
    cfg_path = write_toml(tmp_path)
    cfg = copy.deepcopy(DEFAULTS)
    cfg["storage"]["database"] = str(tmp_path / "state.sqlite3")
    cfg["storage"]["output_dir"] = str(tmp_path / "public")

    unrelated = seed_story(store, item(url="https://example.org/unrelated-story", content="Unrelated report text."),
                           analysis(evidence=["Unrelated report text."]), key="unrel-1", at=DATE)
    off_src = item(url="https://example.org/official-held", kind="feed", authority="official",
                   title="Official maintenance notice", content="Official maintenance notice for relay operators.")
    off_draft = analysis(title="Official maintenance notice", summary="Official maintenance notice for relay operators.",
                         why_it_matters="", confidence="confirmed", evidence=["Official maintenance notice for relay operators."])
    held_row = pending(store, off_src, at=DATE, ready=DATE)
    skip_news = verdict("skip", criterion="news_value")
    assert run_gate(cfg, store, held_row, Writer(off_draft), Reviewer(skip_news, skip_news), DATE)["status"] == "held"

    editorial_act(editorial.retract, store, unrelated["id"], reason="Retracted unrelated story.", observed=after(30, DATE))
    shown = rejection.show_item(store, held_row["id"], config=cfg)
    elig = shown["final_review"]["approval"]
    assert elig["eligible"] is True
    assert elig["new_coverage"] == [{"id": unrelated["id"], "title": unrelated["title"], "updated_at": None, "retracted": True}]

    cli_shown = invoke_cli(capsys, "rejected", "show", "--config", cfg_path, "--item", held_row["id"])
    assert cli_shown["final_review"]["approval"]["hash"] == elig["hash"]
    cli_approved = invoke_cli(
        capsys, "rejected", "approve", "--config", cfg_path, "--item", held_row["id"],
        "--approval-hash", elig["hash"], "--reason", "Publish verified official notice",
    )
    assert cli_approved["status"] == "published"

    bad_src = item(url="https://example.org/official-bad-criteria", kind="feed", authority="official",
                   title="Second official notice", content="Second official maintenance notice.")
    bad_draft = analysis(title="Second official notice", summary="Second official maintenance notice.",
                         why_it_matters="", confidence="confirmed", evidence=["Second official maintenance notice."])
    bad_row = pending(store, bad_src, at=DATE, ready=DATE)
    assert run_gate(cfg, store, bad_row, Writer(bad_draft), Reviewer(skip_news, skip_news), DATE)["status"] == "held"
    rec = job_record(store, bad_row["id"])
    rec["reviews"][0]["result"]["criteria"] = None
    with store.db:
        store.db.execute("UPDATE review_jobs SET record_json=? WHERE item_id=?", (json.dumps(rec), bad_row["id"]))
    assert review_gate.approval(cfg, store, bad_row["id"])["eligible"] is False
    assert review_gate._new_coverage({"recent": "bad"}, {"recent": [123, {"id": 1}, {"id": "x", "title": "T", "retracted": True}]}) == [
        {"id": "x", "title": "T", "updated_at": None, "retracted": True}
    ]


def test_retry_item_evicts_corrupt_draft_json_and_stale_revision_draft_on_locked_story(store):
    """Clear `review_jobs` on `retry_item` when `draft_json` is malformed or belongs to a prior `content_hash`."""
    from helpers import update_analysis

    _, corrupt_row = seed_rejected(store, 0)
    valid_wk = cache_key(corrupt_row, DEFAULTS["llm"])
    valid_ph = review.policy_hash(DEFAULTS)
    with store.db:
        store.db.execute(
            """INSERT INTO review_jobs(item_id,writer_key,policy_hash,stage,prepared_at,draft_json,record_json,updated_at)
               VALUES(?,?,?,?,?,?,?,?)""",
            (corrupt_row["id"], valid_wk, valid_ph, "drafted", DATE, '{"corrupt": 1}', "{", DATE),
        )
    rejection.retry_item(store, corrupt_row["id"], corrupt_row["content_hash"], "Clear corrupt draft", DATE)
    assert job(store, corrupt_row["id"]) is None
    fresh_writer = Writer()
    assert review_gate.process_item(
        DEFAULTS, store, queued_row(store, corrupt_row["id"], DATE), fresh_writer, Reviewer(verdict()), DATE
    )["status"] == "published"
    assert len(fresh_writer.calls) == 1

    host_src = item(url="https://example.org/locked-host", content="Initial host story body.")
    host_story = seed_story(store, host_src, analysis(evidence=["Initial host story body."]), key="host-k", at=DATE)
    follow_v1 = item(url="https://example.org/locked-followup", content="First follow-up revision body.")
    r_v1 = pending(store, follow_v1, at=after(10, DATE), ready=after(10, DATE))
    with store.db:
        store.db.execute("UPDATE items SET story_id=? WHERE id=?", (host_story["id"], r_v1["id"]))
    r_v1 = item_row(store, r_v1)
    v1_draft = update_analysis(update="First revision stale draft sentence.", evidence=["First follow-up revision body."])
    assert run_gate(DEFAULTS, store, r_v1, Writer(v1_draft), Reviewer(verdict("hold", update=True)), after(15, DATE))["status"] == "held"

    follow_v2 = {**follow_v1, "content": "Completely different second revision body.", "updated_at": after(30, DATE)}
    assert store.ingest(follow_v2, after(30, DATE)) is True
    for _ in range(3):
        store.defer(r_v1["id"], "Model returned invalid JSON", DEFAULTS["llm"], after(35, DATE), terminal=True)
    editorial_act(editorial.correct, store, host_story["id"], {"why_it_matters": "Locked by operator."},
                  reason="Lock host story", observed=after(40, DATE))
    r_v2 = item_row(store, r_v1)
    rejection.retry_item(store, r_v2["id"], r_v2["content_hash"], "Retry second revision", after(45, DATE))
    assert job(store, r_v2["id"]) is None

    v2_draft = update_analysis(update="Second revision fresh draft sentence.", evidence=["Completely different second revision body."])
    v2_writer = Writer(v2_draft)
    locked_out = review_gate.process_item(
        DEFAULTS, store, queued_row(store, r_v2["id"], after(50, DATE)), v2_writer, Reviewer(), after(50, DATE)
    )
    assert locked_out["status"] == "locked" and len(v2_writer.calls) == 1
    saved_res, saved_src = store.db.execute(
        "SELECT result, source_payload FROM analyses WHERE source_item_id=? ORDER BY rowid DESC LIMIT 1", (r_v2["id"],)
    ).fetchone()
    assert json.loads(saved_res)["update"] == "Second revision fresh draft sentence."
    assert json.loads(saved_src)["content"] == "Completely different second revision body."


def test_operator_retry_survives_gitlab_comment_enrichment_and_same_second_race(tmp_path):
    """Preserve operator retry recency exemption after GitLab comment enrichment alters content_hash."""
    cfg = make_config(tmp_path, sources=[gitlab_source()], comments={"enabled": True})
    with Store(cfg["storage"]["database"]) as store:
        old_ts = "2026-01-01T00:00:00Z"
        src = item(source_id="tor-issues", url=TOR_WORK_ITEM_URL, kind="gitlab_issue",
                   published_at=old_ts, updated_at=old_ts, collected_at=DATE)
        store.ingest(src, DATE)
        row = item_row(store, src["id"])
        assert run_gate(cfg, store, row, Writer(), Reviewer(verdict(), verdict()))["status"] == "ignored"
        assert decision_codes(store, row) == ["skipped.gate.not_recent"]

        retry_at = LATER
        rejection.retry_item(store, row["id"], row["content_hash"], "Please check discussion comments", observed=retry_at)
        old_hash = store.db.execute("SELECT content_hash FROM items WHERE id=?", (row["id"],)).fetchone()[0]

        enrich_ts = after(60, retry_at)
        resp = gql_notes_response([gql_note("1", createdAt="2026-01-02T00:00:00Z",
                                            body="Detailed old upstream comment triggering content hash change.")])
        assert enrich_with_client(cfg, store, FakeClient([resp]), enrich_ts)["changed"] == 1
        enriched = item_row(store, row["id"])
        assert enriched["content_hash"] != old_hash
        assert json.loads(enriched["payload"])["comments_checked_at"] == enrich_ts
        assert review_gate._has_operator_retry(store.db, enriched) is True
        assert review_gate._not_recent(cfg, store, enriched, json.loads(enriched["payload"]), after(60, enrich_ts)) is None

        result = run_gate(cfg, store, enriched, Writer(), Reviewer(verdict(), verdict()))
        assert result["status"] == "published" and len(store.stories()) == 1

        # Same-second enrichment (comments_checked_at == retry_at) also qualifies while pre-retry skips stay ignored.
    cfg2 = make_config(tmp_path / "same_second", sources=[gitlab_source()], comments={"enabled": True})
    with Store(cfg2["storage"]["database"]) as store2:
        old_ts = "2026-01-01T00:00:00Z"
        src2 = item(source_id="tor-issues", url=TOR_WORK_ITEM_URL,
                    kind="gitlab_issue", published_at=old_ts, updated_at=old_ts, collected_at=DATE)
        store2.ingest(src2, DATE)
        row2 = item_row(store2, src2["id"])
        assert run_gate(cfg2, store2, row2, Writer(), Reviewer(verdict(), verdict()))["status"] == "ignored"
        same_ts = after(120, LATER)
        rejection.retry_item(store2, row2["id"], row2["content_hash"], "Retry same second", observed=same_ts)
        resp2 = gql_notes_response([gql_note("2", createdAt="2026-01-03T00:00:00Z",
                                             body="Same-second enriched comment text.")])
        assert enrich_with_client(cfg2, store2, FakeClient([resp2]), same_ts)["changed"] == 1
        enriched2 = item_row(store2, row2["id"])
        assert review_gate._has_operator_retry(store2.db, enriched2) is True
        assert run_gate(cfg2, store2, enriched2, Writer(), Reviewer(verdict(), verdict()))["status"] == "published"


def test_operator_retry_exemption_clears_after_terminal_decision_and_skips_stale_or_non_gitlab(tmp_path, monkeypatch):
    """Stop exempting once a post-retry terminal decision logs, or when enrichment is stale or non-GitLab."""
    from onionflash import comments

    monkeypatch.setattr(comments, "INTERVAL_SECONDS", 30)
    cfg = make_config(tmp_path, sources=[gitlab_source()], comments={"enabled": True})
    with Store(cfg["storage"]["database"]) as store:
        old_ts = "2026-01-01T00:00:00Z"
        src = item(source_id="tor-issues", url=TOR_WORK_ITEM_URL, kind="gitlab_issue",
                   published_at=old_ts, updated_at=old_ts, collected_at=DATE)
        store.ingest(src, DATE)
        row = item_row(store, src["id"])
        assert run_gate(cfg, store, row, Writer(), Reviewer(verdict(), verdict()))["status"] == "ignored"

        retry_at = LATER
        rejection.retry_item(store, row["id"], row["content_hash"], "Re-evaluate once", observed=retry_at)
        enrich_ts = after(60, retry_at)
        resp = gql_notes_response([gql_note("10", createdAt="2026-01-02T00:00:00Z", body="Enriched once.")])
        assert enrich_with_client(cfg, store, FakeClient([resp]), enrich_ts)["changed"] == 1
        enriched = item_row(store, row["id"])

        skip_result = run_gate(cfg, store, enriched, Writer(), Reviewer(verdict("skip", criterion="news_value")))
        assert skip_result["status"] == "ignored"
        assert review_gate._has_operator_retry(store.db, item_row(store, row["id"])) is False

        later_ts = after(120, retry_at)
        edited_src = {**src, "content": "Minor upstream wording fix after terminal skip.", "updated_at": after(120, old_ts)}
        merged = comments.merge_cached_comments(store, edited_src, gitlab_source(), later_ts)
        assert store.ingest(merged, later_ts)
        resp_later = gql_notes_response([gql_note("11", createdAt="2026-01-03T00:00:00Z", body="Second edit.")])
        assert enrich_with_client(cfg, store, FakeClient([resp_later]), after(60, later_ts))["changed"] == 1
        after_terminal = item_row(store, row["id"])
        assert review_gate._has_operator_retry(store.db, after_terminal) is False

        stale = dict(after_terminal)
        payload = json.loads(stale["payload"])
        payload["comments_checked_at"] = "2026-01-05T00:00:00Z"
        stale["payload"] = json.dumps(payload)
        assert review_gate._has_operator_retry(store.db, stale) is False

        feed_src = item(id="https://example.org/feed-item", url="https://example.org/feed-item",
                        kind="feed", published_at=old_ts, updated_at=old_ts, collected_at=DATE)
        store.ingest(feed_src, DATE)
        feed_row = item_row(store, feed_src["id"])
        run_gate(cfg, store, feed_row, Writer(), Reviewer(verdict(), verdict()))
        feed_ignored = item_row(store, feed_src["id"])
        rejection.retry_item(store, feed_ignored["id"], feed_ignored["content_hash"], "Retry feed", observed=retry_at)
        feed_retried = item_row(store, feed_src["id"])
        feed_payload = json.loads(feed_retried["payload"])
        feed_payload["comments_checked_at"] = enrich_ts
        mutated_feed = {**feed_retried, "content_hash": "f" * 64, "payload": json.dumps(feed_payload)}
        assert review_gate._has_operator_retry(store.db, mutated_feed) is False
