"""One-item operator decisions preserve story state and the private audit trail."""

import copy
import json
import sqlite3

import pytest

from helpers import (
    DAMAGE, DATE, Reviewer, Writer, analysis, damage_item, finish_reviewed, item,
    seed_ignored, seed_rejected, seed_story, verdict,
)
from onionflash import editorial, rejection, review, review_gate
from onionflash.analyze import AnalysisError, cache_key
from onionflash.config import DEFAULTS
from onionflash.util import after


def failed_pending(store, *, terminal=False):
    src = item(url="https://example.org/failed-pending")
    store.ingest(src, DATE)
    store.defer(src["id"], "Saved analysis failed", DEFAULTS["llm"], DATE, terminal=terminal)
    return src, dict(store.db.execute("SELECT * FROM items WHERE id=?", (src["id"],)).fetchone())


def analysis_result(store, key):
    """Inspect the stored analysis audit directly; runtime analysis has no cache."""
    row = store.db.execute("SELECT result FROM analyses WHERE cache_key=?", (key,)).fetchone()
    return json.loads(row[0]) if row is not None else None


def actions(store):
    return [dict(row) for row in store.db.execute("SELECT * FROM rejection_actions ORDER BY action_id")]


@pytest.mark.parametrize("kind", [*DAMAGE, "blob"])
def test_a_damaged_saved_item_stays_listable_and_inspectable(store, kind):
    _, row = seed_rejected(store, 0)
    _, intact = seed_rejected(store, 1)
    damage_item(store.db, row["id"], kind)
    listed = {entry["id"]: entry["title"] for entry in rejection.list_items(store)["items"]}
    assert listed == {row["id"]: None, intact["id"]: json.loads(intact["payload"])["title"]}
    shown = rejection.show_item(store, row["id"])
    assert shown["saved_item"] is None and shown["content_hash"] == row["content_hash"]


@pytest.mark.parametrize("kind", [*DAMAGE, "blob"])
def test_a_damaged_saved_item_can_be_dismissed_but_not_retried(store, kind):
    _, row = seed_rejected(store)
    damage_item(store.db, row["id"], kind)
    with pytest.raises(ValueError, match="incomplete or unreadable"):
        rejection.retry_item(store, row["id"], row["content_hash"], "try again")
    assert rejection.dismiss_item(store, row["id"], row["content_hash"], "damaged copy")["status"] == "dismissed"


@pytest.mark.parametrize("title", [[1], {"a": 1}, 5, True])
def test_only_text_is_listed_as_a_title(store, title):
    _, row = seed_rejected(store)
    store.db.execute("UPDATE items SET payload=? WHERE id=?",
                     (json.dumps({**json.loads(row["payload"]), "title": title}), row["id"]))
    store.db.commit()
    assert rejection.list_items(store)["items"][0]["title"] is None


def test_list_excludes_transient_failures_and_is_bounded_with_stable_pagination(store):
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
    assert not actions(store)
    queued = next(row for row in store.pending(20, after(86400, DATE)) if row["id"] == transient["id"])
    assert queued["attempts"] == 5 and queued["rejections"] == 0


def test_show_is_explicit_source_inspection(store):
    src, row = seed_rejected(store)
    shown = rejection.show_item(store, src["id"])
    assert shown["saved_item"]["content"] == src["content"]
    assert shown["content_hash"] == row["content_hash"] and shown["actions"] == []


def test_retry_queues_the_revision_and_leaves_analysis_records_unchanged(store, capsys):
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
    audit = actions(store)[0]
    assert (audit["before_status"], audit["before_attempts"], audit["before_rejections"]) == ("rejected", 3, 3)
    assert audit["reason"] == "Grounding rule was repaired"
    assert "content" not in result and "reason" not in result and capsys.readouterr().out == ""
    finish_reviewed(store, queued, analysis(summary="A supported account after retry."), key, after(60, DATE))
    assert store.pending_count() == 0
    story = store.stories()[0]
    assert story["summary"] == "A supported account after retry."
    assert analysis_result(store, key) == analysis()
    assert analysis_result(store, story["editorial_analysis_key"])["summary"] == "A supported account after retry."
    assert len(actions(store)) == 1


def test_retry_undoes_a_mistaken_dismissal(store):
    _, row = seed_rejected(store)
    rejection.dismiss_item(store, row["id"], row["content_hash"], "Dismissed by mistake", DATE)
    assert rejection.retry_item(store, row["id"], row["content_hash"], "A real report", DATE)["status"] == "pending"
    assert store.pending_count() == 1
    for operation in (rejection.retry_item, rejection.dismiss_item):
        with pytest.raises(ValueError, match="terminally rejected"):
            operation(store, row["id"], row["content_hash"], "Again", DATE)
    assert [(a["action"], a["before_status"]) for a in actions(store)] == [("dismiss", "rejected"), ("retry", "dismissed")]


def test_dismissal_stops_unchanged_and_timestamp_only_replays_but_new_content_requeues(store):
    src, row = seed_rejected(store)
    key = cache_key(row, DEFAULTS["llm"])
    with store.db:
        store.db.execute("INSERT INTO analyses(cache_key,result,created_at) VALUES(?,?,?)", (key, "{}", DATE))
    assert rejection.dismiss_item(store, row["id"], row["content_hash"], "Routine discussion with no news", DATE)["status"] == "dismissed"
    assert analysis_result(store, key) == {}
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
    inc = item(url="https://example.org/held-dismiss")
    store.ingest(inc, DATE)
    row = store.pending(1, DATE)[0]
    with store.db:
        store.db.execute(
            "INSERT INTO review_jobs(item_id,writer_key,policy_hash,stage,record_json,approval_key,prepared_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
            (row["id"], "wk", "ph", "held", "{}", "app-key-1", DATE, DATE),
        )
    store.reject(row["id"], "Held for operator review", "held.review.model_hold", after(30, DATE))
    assert review_gate.status(store)["stages"] == {"held": 1}
    rejection.dismiss_item(store, row["id"], row["content_hash"], "Not needed.", observed=after(60, DATE))
    assert review_gate.status(store)["stages"] == {}
    assert store.db.execute("SELECT approval_key FROM review_jobs WHERE item_id=?", (row["id"],)).fetchone()[0] is None


@pytest.mark.parametrize("action", ["retry", "dismiss"])
def test_repeated_action_is_not_applied_twice(store, action):
    _, row = seed_rejected(store)
    operation = getattr(rejection, action + "_item")
    operation(store, row["id"], row["content_hash"], "Reviewed", DATE)
    with pytest.raises(ValueError, match="terminally rejected"):
        operation(store, row["id"], row["content_hash"], "Reviewed", DATE)
    assert len(actions(store)) == 1


def test_stale_hash_and_new_pending_actions_are_rejected_without_audit(store):
    src, row = seed_rejected(store)
    store.ingest({**src, "content": "Changed source", "updated_at": after(60, DATE)}, after(60, DATE))
    with pytest.raises(ValueError, match="content changed"):
        rejection.dismiss_item(store, row["id"], row["content_hash"], "Old view", DATE)
    current = rejection.show_item(store, row["id"])
    with pytest.raises(ValueError, match="terminally rejected"):
        rejection.retry_item(store, row["id"], current["content_hash"], "New source revision", DATE)
    assert actions(store) == []


@pytest.mark.parametrize("failures", [1, 3])
@pytest.mark.parametrize("locked", [False, True])
def test_retry_and_dismiss_do_not_mutate_an_existing_story_or_editorial_state(store, failures, locked):
    src = item()
    original = seed_story(store, src, analysis(), at=DATE)
    original_story_id = original["id"]
    if locked:
        editorial.correct(store.db, original_story_id, {"why_it_matters": "Operator-corrected text."},
                          reason="Operator correction", expect_hash=editorial.show(store.db, original_story_id)["hash"],
                          observed=DATE)
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


@pytest.mark.parametrize("field", ["content", "url", "updated_at"])
def test_retry_refuses_an_incomplete_saved_item_but_dismiss_still_works(store, field):
    _, row = seed_rejected(store)
    payload = json.loads(row["payload"])
    payload.pop(field)
    with store.db:
        store.db.execute("UPDATE items SET payload=? WHERE id=?", (json.dumps(payload), row["id"]))
    with pytest.raises(ValueError, match="incomplete or unreadable"):
        rejection.retry_item(store, row["id"], row["content_hash"], "Try again", DATE)
    assert actions(store) == []
    rejection.dismiss_item(store, row["id"], row["content_hash"], "No usable stored body", DATE)
    assert rejection.show_item(store, row["id"])["status"] == "dismissed"


@pytest.mark.parametrize("is_pending", [False, True])
def test_failed_audit_insert_rolls_back_the_action(store, is_pending):
    _, row = failed_pending(store) if is_pending else seed_rejected(store)
    with store.db:
        store.db.execute("""CREATE TRIGGER fail_rejection_audit BEFORE INSERT ON rejection_actions
                         BEGIN SELECT RAISE(ABORT,'audit unavailable'); END""")
    with pytest.raises(sqlite3.IntegrityError):
        rejection.retry_item(store, row["id"], row["content_hash"], "Retry", DATE)
    assert rejection.show_item(store, row["id"])["status"] == row["status"] and actions(store) == []


def test_an_earlier_release_can_still_use_the_audit_table(store):
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
    _, row = seed_rejected(store)
    ready = rejection._ready
    database = store.db.execute("PRAGMA database_list").fetchone()[2]

    def concurrent_change(current):
        ready(current)
        with sqlite3.connect(database) as writer:
            writer.execute("UPDATE items SET content_hash=? WHERE id=?", ("f" * 64, row["id"]))

    monkeypatch.setattr(rejection, "_ready", concurrent_change)
    with pytest.raises(ValueError, match="changed during"):
        rejection.retry_item(store, row["id"], row["content_hash"], "Reviewed", DATE)
    current = rejection.show_item(store, row["id"])
    assert current["status"] == "rejected" and current["content_hash"] == "f" * 64 and actions(store) == []


@pytest.mark.parametrize("reason", ["", "   ", "x" * 1001, "bad\x1bvalue", "bad\ud800value"])
def test_reason_is_required_and_bounded(store, reason):
    _, row = seed_rejected(store)
    with pytest.raises(ValueError, match="reason"):
        rejection.dismiss_item(store, row["id"], row["content_hash"], reason, DATE)
    assert rejection.show_item(store, row["id"])["status"] == "rejected" and actions(store) == []


@pytest.mark.parametrize("kwargs", [{"limit": 0}, {"limit": True}, {"limit": 201}, {"after": "../bad"}, {"status": "pending"}])
def test_list_arguments_are_bounded(store, kwargs):
    with pytest.raises(ValueError):
        rejection.list_items(store, **kwargs)


@pytest.mark.parametrize("action", ["retry", "dismiss"])
@pytest.mark.parametrize("terminal", [False, True])
def test_failed_pending_actions_preserve_audit_and_do_not_repeat(store, action, terminal):
    src, row = failed_pending(store, terminal=terminal)
    key = cache_key(row, DEFAULTS["llm"])
    with store.db:
        store.db.execute("INSERT INTO analyses(cache_key,result,created_at) VALUES(?,?,?)", (key, "{}", DATE))
    operation = (lambda: rejection.retry_item(store, row["id"], row["content_hash"], "Reviewed failure", DATE)) if action == "retry" else (
        lambda: rejection.dismiss_item(store, row["id"], row["content_hash"], "Redundant source revision", DATE))
    result = operation()
    current = rejection.show_item(store, row["id"])
    audit = actions(store)[0]
    assert audit["before_status"] == "pending" and audit["before_attempts"] == 1
    assert audit["before_rejections"] == int(terminal) and audit["before_error"] == "Saved analysis failed"
    assert audit["before_next_attempt_at"] == row["next_attempt_at"]
    assert current["next_attempt_at"] is None and store.stories() == []
    assert set(result) == {"item_id", "content_hash", "action", "status", "action_id"}
    assert analysis_result(store, key) == {}
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
    assert len(actions(store)) == 1


@pytest.mark.parametrize("action,status,attempts,error", [(action, *case) for action in ("retry", "dismiss") for case in [
    ("pending", 0, None), ("pending", 0, "old error"), ("pending", 1, None),
    ("pending", 1, "  \t"), ("pending", -1, "old error"),
    ("published", 2, "old error"), ("ignored", 2, "old error"), ("dismissed", 2, "old error"),
] if action == "dismiss" or case[0] not in {"dismissed", "ignored"}])
def test_new_or_completed_items_cannot_be_acted_on(store, action, status, attempts, error):
    _, row = failed_pending(store)
    with store.db:
        store.db.execute("UPDATE items SET status=?,attempts=?,last_error=? WHERE id=?", (status, attempts, error, row["id"]))
    before = dict(store.db.execute("SELECT * FROM items WHERE id=?", (row["id"],)).fetchone())
    with pytest.raises(ValueError, match="previously failed pending"):
        getattr(rejection, action + "_item")(store, row["id"], row["content_hash"], "Reviewed", DATE)
    assert dict(store.db.execute("SELECT * FROM items WHERE id=?", (row["id"],)).fetchone()) == before
    assert actions(store) == []


def test_pending_retry_restarts_review_and_reuses_draft(store):
    store.ingest(item(), DATE)
    row = store.pending(1, DATE)[0]
    with pytest.raises(AnalysisError):
        review_gate.process_item(DEFAULTS, store, row, Writer(),
                                 Reviewer(AnalysisError("Request timed out", retryable=True)), DATE)
    store.defer(row["id"], "Final review request failed", DEFAULTS["llm"], DATE)
    rejection.retry_item(store, row["id"], row["content_hash"], "Review policy repaired", DATE)
    saved_job = store.db.execute("SELECT stage,record_json FROM review_jobs WHERE item_id=?", (row["id"],)).fetchone()
    assert saved_job["stage"] == "drafted" and json.loads(saved_job["record_json"])["reviews"] == []
    writer = Writer()
    result = review_gate.process_item(DEFAULTS, store, store.pending(1, DATE)[0], writer, Reviewer(verdict()), DATE)
    assert result["status"] == "published" and writer.calls == []
    assert actions(store)[0]["before_status"] == "pending"


def test_dismissed_failed_pending_revision_only_requeues_on_source_change(store):
    src, row = failed_pending(store)
    rejection.dismiss_item(store, row["id"], row["content_hash"], "Already covered", DATE)
    assert store.ingest({**src, "content": src["content"] + " Additional source evidence.", "updated_at": after(60, DATE)},
                        after(60, DATE))
    fresh = rejection.show_item(store, row["id"])
    assert fresh["status"] == "pending" and fresh["attempts"] == 0
    with pytest.raises(ValueError, match="content changed"):
        rejection.dismiss_item(store, row["id"], row["content_hash"], "Stale inspection", DATE)
    with pytest.raises(ValueError, match="previously failed pending"):
        rejection.dismiss_item(store, row["id"], fresh["content_hash"], "New evidence not analyzed", DATE)
    assert len(actions(store)) == 1


@pytest.mark.parametrize("action", ["retry", "dismiss"])
@pytest.mark.parametrize("change", [
    "status='published'", "attempts=attempts+1", "rejections=rejections+1",
    "last_error=NULL", "next_attempt_at=NULL", "payload='{\"other\": 1}'",
    "payload=replace(payload, 'title', 'título')", "payload=CAST(x'7b22ff22' AS TEXT)",
])
def test_concurrent_pending_queue_change_is_not_overwritten(store, monkeypatch, action, change):
    _, row = failed_pending(store)
    original = rejection._checked
    database = store.db.execute("PRAGMA database_list").fetchone()[2]

    def changed_after_read(db, item_id, expected_hash, **kwargs):
        captured = original(db, item_id, expected_hash, **kwargs)
        with sqlite3.connect(database) as other:
            other.execute(f"UPDATE items SET {change} WHERE id=?", (item_id,))
        return captured

    monkeypatch.setattr(rejection, "_checked", changed_after_read)
    with pytest.raises(ValueError, match="changed during"):
        getattr(rejection, action + "_item")(store, row["id"], row["content_hash"], "Reviewed", DATE)
    current = store.db.execute("SELECT content_hash,status FROM items WHERE id=?", (row["id"],)).fetchone()
    assert current["content_hash"] == row["content_hash"]
    assert current["status"] != "dismissed" and actions(store) == []


def test_ignored_reconsideration_is_explicit_audited_and_one_item_only(store):
    _, row = seed_ignored(store)
    _, other = seed_ignored(store, 1)
    key = cache_key(row, DEFAULTS["llm"])
    with pytest.raises(ValueError, match="previously failed pending"):
        rejection.dismiss_item(store, row["id"], row["content_hash"], "Reviewed selection", DATE)
    assert actions(store) == []
    result = rejection.retry_item(store, row["id"], row["content_hash"], "Reviewed selection", DATE)
    assert result["status"] == "pending" and store.stories() == []
    current = dict(store.db.execute("SELECT * FROM items WHERE id=?", (row["id"],)).fetchone())
    assert current["attempts"] == current["rejections"] == 0
    assert current["last_error"] is None and current["next_attempt_at"] is None
    for field in ("payload", "content_hash", "source_id", "url", "first_seen", "last_seen", "story_id"):
        assert current[field] == row[field]
    assert dict(store.db.execute("SELECT * FROM items WHERE id=?", (other["id"],)).fetchone()) == other
    audit = actions(store)[0]
    assert audit["before_status"] == "ignored" and audit["action"] == "retry" and audit["reason"] == "Reviewed selection"
    assert audit["superseded_analysis_key"] is None and audit["superseded_analysis_json"] is None
    assert analysis_result(store, key) == analysis()
    with pytest.raises(ValueError, match="previously failed pending"):
        rejection.retry_item(store, row["id"], row["content_hash"], "Duplicate retry", DATE)
    assert len(actions(store)) == 1


def reviewed_skip(store):
    if not store.stories():
        seed_story(store, item(url="https://example.org/earlier-report", content="An earlier distinct report on the topic."),
                   analysis(), at=DATE)
    covered_id = store.stories()[0]["id"]
    reply = verdict("skip", criterion="new_information")
    reply["criteria"]["new_information"]["reason"] = f"Already covered in {covered_id}."
    store.ingest(item(url="https://example.org/reconsidered-report"), DATE)
    row = store.pending(1, DATE)[0]
    checker = Reviewer(reply)
    assert review_gate.process_item(DEFAULTS, store, row, Writer(), checker, DATE)["status"] == "ignored"
    assert review._skip_stands(reply["criteria"], checker.coverages[0])
    assert not store.db.execute("SELECT 1 FROM review_jobs WHERE item_id=?", (row["id"],)).fetchone()
    assert not store.db.execute("SELECT 1 FROM review_approvals").fetchone()
    return row, checker.calls[0][0]


def test_a_skip_is_listed_with_its_reason_and_shows_its_decision_and_coverage(store):
    seed_story(store, item(url="https://example.org/earlier-report"), analysis(), at=DATE)
    row, _ = reviewed_skip(store)
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
    row, candidate = reviewed_skip(store)
    rejection.retry_item(store, row["id"], row["content_hash"], "Reconsider this editorial decision", DATE)
    checker = Reviewer(verdict())
    result = review_gate.process_item(DEFAULTS, store, store.pending(1, DATE)[0], Writer(), checker, DATE)
    assert result["status"] == "published" and not result["cache_hit"]
    assert result["review_calls"] == 2 and checker.calls[0][0] == candidate
    assert [call[2] for call in checker.calls] == [False, True]


def test_show_prints_a_skip_that_repeats_the_first_decision_after_a_hold(store):
    row, _ = reviewed_skip(store)
    rejection.retry_item(store, row["id"], row["content_hash"], "Reconsider this editorial decision", DATE)
    assert review_gate.process_item(DEFAULTS, store, store.pending(1, DATE)[0], Writer(), Reviewer(verdict("hold")), DATE)["status"] == "held"
    rejection.retry_item(store, row["id"], row["content_hash"], "Retry the held item", DATE)
    reviewed_skip(store)
    assert rejection.show_item(store, row["id"])["final_review"]["latest_review"]["verdict"] == "skip"


@pytest.mark.parametrize("record_damage", [
    b"\x80",
    b'{"prepared":1}',
    '{"x":"\\ud800"}',
    "{" + '"a":' * 70 + "1" + "}" * 70,
    '{"prepared": [], "reviews": "bad"}',
])
def test_rejected_controls_and_cli_handle_blobs_surrogates_deep_json_and_damaged_records(tmp_path, capsys, record_damage):
    from onionflash import cli
    from onionflash.store import Store

    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text(
        '[storage]\ndatabase = "state.db"\noutput_dir = "public"\n'
        '[[sources]]\nid = "a"\nurl = "https://example.org/feed.xml"\n'
    )
    with Store(tmp_path / "state.db") as store:
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
    assert cli.main(["rejected", "list", "--config", str(cfg_path)]) == 0
    listed_out = json.loads(capsys.readouterr().out)
    assert listed_out["items"][0]["id"] == row["id"] and listed_out["items"][0]["title"] is None

    assert cli.main(["rejected", "show", "--item", row["id"], "--config", str(cfg_path)]) == 0
    shown_out = json.loads(capsys.readouterr().out)
    assert shown_out["saved_item"] is None and shown_out["final_review"]["error"] == "Saved review record cannot be read"

    with Store(tmp_path / "state.db") as store:
        assert rejection.dismiss_item(store, row["id"], row["content_hash"], "dismiss raw blob", DATE)["status"] == "dismissed"

        _, bad_comments_row = seed_rejected(store, 1)
        bad_payload = json.dumps({**json.loads(bad_comments_row["payload"]), "public_comments": [{"author": "op"}]})
        store.db.execute("UPDATE items SET payload=? WHERE id=?", (bad_payload, bad_comments_row["id"]))
        store.db.commit()
        with pytest.raises(ValueError, match="incomplete or unreadable"):
            rejection.retry_item(store, bad_comments_row["id"], bad_comments_row["content_hash"], "bad comments", DATE)
