"""One-item operator decisions preserve story state and the private audit trail."""

import copy
import json
import sqlite3

import pytest

from onionflash import rejection
from onionflash.analyze import cache_key
from onionflash.config import DEFAULTS
from onionflash.store import Store
from onionflash.util import after
from test_core import DATE, analysis, item


@pytest.fixture
def store(tmp_path):
    with Store(tmp_path / "queue.sqlite3") as value:
        yield value


def rejected(store, number=0, **changes):
    source = item(url=f"https://example.org/news/{number}", **changes)
    assert store.ingest(source, DATE)
    for _ in range(3):
        store.defer(source["id"], "Model evidence is not present in source", DEFAULTS["llm"], DATE, terminal=True)
    return source, dict(store.db.execute("SELECT * FROM items WHERE id=?", (source["id"],)).fetchone())


def analysis_result(store, key):
    """Inspect the stored analysis audit directly; runtime analysis has no cache."""
    row = store.db.execute("SELECT result FROM analyses WHERE cache_key=?", (key,)).fetchone()
    return json.loads(row[0]) if row is not None else None


def actions(store):
    if not store.db.execute("SELECT 1 FROM sqlite_master WHERE name='rejection_actions'").fetchone():
        return []
    return [dict(row) for row in store.db.execute("SELECT * FROM rejection_actions ORDER BY action_id")]


def test_list_excludes_transient_failures_and_is_bounded_with_stable_pagination(store):
    transient = item(url="https://example.org/transient")
    store.ingest(transient, DATE)
    for _ in range(5):
        store.defer(transient["id"], "LLM request failed (HTTP 503)", DEFAULTS["llm"], DATE)
    expected = []
    for number in range(5):
        source, row = rejected(store, number)
        expected.append(source["id"])
    first = rejection.list_items(store, limit=2)
    second = rejection.list_items(store, limit=2, after=first["next_cursor"])
    third = rejection.list_items(store, limit=2, after=second["next_cursor"])
    entries = first["items"] + second["items"] + third["items"]
    assert [entry["id"] for entry in entries] == sorted(expected)
    assert third["next_cursor"] is None
    assert all(entry["attempts"] == 3 and entry["rejections"] == 3 for entry in entries)
    assert all(entry["rejection_reason"] == "Model evidence is not present in source" for entry in entries)
    assert all(entry["source_url"].startswith("https://example.org/news/") for entry in entries)
    assert "The operator reported" not in json.dumps(first)
    assert not actions(store)  # Reading does not create an operator decision.
    pending = next(row for row in store.pending(20, after(86400, DATE)) if row["id"] == transient["id"])
    assert pending["attempts"] == 5 and pending["rejections"] == 0


def test_show_is_explicit_source_inspection_and_handles_malformed_payload(store):
    source, row = rejected(store)
    shown = rejection.show_item(store, source["id"])
    assert shown["saved_item"]["content"] == source["content"]
    assert shown["content_hash"] == row["content_hash"]
    assert shown["actions"] == []
    with store.db:
        store.db.execute("UPDATE items SET payload='broken JSON' WHERE id=?", (source["id"],))
    assert rejection.show_item(store, source["id"])["saved_item"] is None
    assert rejection.list_items(store)["items"][0]["saved_item_error"]


def test_retry_supersedes_only_current_analysis_and_saves_evidence_privately(store, capsys):
    source, row = rejected(store)
    key = cache_key(row, DEFAULTS["llm"])
    previous_result = analysis()
    with store.db:
        store.db.execute("INSERT INTO analyses(cache_key,result,created_at,source_payload,source_item_id) VALUES(?,?,?,?,?)",
                         (key, json.dumps(previous_result), DATE, row["payload"], row["id"]))
        store.db.execute("INSERT INTO analyses(cache_key,result,created_at) VALUES('other','{}',?)", (DATE,))
    result = rejection.retry_item(store, row["id"], row["content_hash"], "Grounding rule was repaired", DEFAULTS["llm"], DATE)
    queued = store.pending(10, DATE)
    assert len(queued) == 1
    assert (queued[0]["status"], queued[0]["attempts"], queued[0]["rejections"], queued[0]["next_attempt_at"], queued[0]["last_error"]) == ("pending", 0, 0, None, None)
    assert analysis_result(store, key) is None and analysis_result(store, "other") == {}
    assert store.stories() == []  # Retrying is not publishing.
    audit = actions(store)[0]
    assert audit["superseded_analysis_key"] == key
    snapshot = json.loads(audit["superseded_analysis_json"])
    assert json.loads(snapshot["result"]) == previous_result
    assert snapshot["source_payload"] == row["payload"]
    assert audit["before_attempts"] == 3 and audit["before_rejections"] == 3
    assert audit["reason"] == "Grounding rule was repaired"
    assert "content" not in result and "reason" not in result and "superseded_analysis_json" not in result
    assert "superseded_analysis_json" not in rejection.show_item(store, row["id"])["actions"][0]
    assert capsys.readouterr().out == ""
    store.finish(queued[0], analysis(summary="A supported account after retry."), key, after(60, DATE))
    assert store.pending_count() == 0
    assert store.stories()[0]["summary"] == "A supported account after retry."
    assert analysis_result(store, key)["summary"] == "A supported account after retry."
    assert len(actions(store)) == 1


def test_dismissal_stops_unchanged_and_timestamp_only_replays_but_new_content_requeues(store):
    source, row = rejected(store)
    key = cache_key(row, DEFAULTS["llm"])
    with store.db:
        store.db.execute("INSERT INTO analyses(cache_key,result,created_at) VALUES(?,?,?)", (key, '{}', DATE))
    result = rejection.dismiss_item(store, row["id"], row["content_hash"], "Routine discussion with no news", DATE)
    assert result["status"] == "dismissed"
    assert analysis_result(store, key) == {}  # Dismiss does not erase analysis evidence.
    assert store.pending_count() == 0 and store.rejected_count() == 0
    assert not store.ingest(copy.deepcopy(source), after(60, DATE))
    assert not store.ingest({**source, "updated_at": after(120, DATE)}, after(120, DATE))
    store.defer(row["id"], "late failure", DEFAULTS["llm"], after(120, DATE), terminal=True)
    shown = rejection.show_item(store, row["id"])
    assert shown["status"] == "dismissed" and shown["rejections"] == 3
    assert rejection.list_items(store)["items"] == []
    assert rejection.list_items(store, status="dismissed")["items"][0]["id"] == row["id"]
    changed = {**source, "content": "A genuinely changed source report.", "updated_at": after(180, DATE)}
    assert store.ingest(changed, after(180, DATE))
    current = rejection.show_item(store, row["id"])
    assert current["status"] == "pending" and current["content_hash"] != row["content_hash"]
    assert current["attempts"] == current["rejections"] == 0
    assert current["actions"][0]["content_hash"] == row["content_hash"]


@pytest.mark.parametrize("action", ["retry", "dismiss"])
def test_repeated_action_is_not_applied_twice(store, action):
    _, row = rejected(store)
    operation = (lambda: rejection.retry_item(store, row["id"], row["content_hash"], "Reviewed", DEFAULTS["llm"], DATE)) if action == "retry" else (
        lambda: rejection.dismiss_item(store, row["id"], row["content_hash"], "Reviewed", DATE))
    operation()
    with pytest.raises(ValueError, match="terminally rejected"):
        operation()
    assert len(actions(store)) == 1


def test_stale_hash_and_transient_pending_actions_are_rejected_without_audit(store):
    source, row = rejected(store)
    changed = {**source, "content": "Changed source", "updated_at": after(60, DATE)}
    store.ingest(changed, after(60, DATE))
    with pytest.raises(ValueError, match="content changed"):
        rejection.dismiss_item(store, row["id"], row["content_hash"], "Old view", DATE)
    current = rejection.show_item(store, row["id"])
    with pytest.raises(ValueError, match="terminally rejected"):
        rejection.retry_item(store, row["id"], current["content_hash"], "Transient failure", DEFAULTS["llm"], DATE)
    assert actions(store) == []


def test_retry_and_dismiss_do_not_mutate_an_existing_story_or_editorial_state(store):
    source = item()
    store.ingest(source, DATE)
    first = store.pending(1, DATE)[0]
    store.finish(first, analysis(), cache_key(first, DEFAULTS["llm"]), DATE)
    original_story_id = store.stories()[0]["id"]
    changed = {**source, "content": source["content"] + " A disputed later revision.", "updated_at": after(60, DATE)}
    store.ingest(changed, after(60, DATE))
    for _ in range(3):
        store.defer(source["id"], "Unsupported later claim", DEFAULTS["llm"], DATE, terminal=True)
    before = [tuple(row) for row in store.db.execute("SELECT * FROM stories")]
    with store.db:
        store.db.execute("CREATE TABLE operator_override_fixture(story_id TEXT,value TEXT)")
        store.db.execute("INSERT INTO operator_override_fixture VALUES('story','must remain locked')")
    current = rejection.show_item(store, source["id"])
    rejection.retry_item(store, source["id"], current["content_hash"], "Check repaired reviewer", DEFAULTS["llm"], DATE)
    for _ in range(3):
        store.defer(source["id"], "Still unsupported", DEFAULTS["llm"], DATE, terminal=True)
    rejection.dismiss_item(store, source["id"], current["content_hash"], "Keep the earlier accepted account", DATE)
    assert [tuple(row) for row in store.db.execute("SELECT * FROM stories")] == before
    assert store.db.execute("SELECT value FROM operator_override_fixture").fetchone()[0] == "must remain locked"
    assert rejection.show_item(store, source["id"])["story_id"] == original_story_id


def test_retry_refuses_missing_source_body_but_dismiss_still_works(store):
    _, row = rejected(store)
    payload = json.loads(row["payload"])
    payload.pop("content")
    with store.db:
        store.db.execute("UPDATE items SET payload=? WHERE id=?", (json.dumps(payload), row["id"]))
    with pytest.raises(ValueError, match="restore or recollect"):
        rejection.retry_item(store, row["id"], row["content_hash"], "Try again", DEFAULTS["llm"], DATE)
    assert actions(store) == []
    rejection.dismiss_item(store, row["id"], row["content_hash"], "No usable stored body", DATE)
    assert rejection.show_item(store, row["id"])["status"] == "dismissed"


def test_failed_audit_insert_rolls_back_queue_and_analysis_changes(store):
    _, row = rejected(store)
    key = cache_key(row, DEFAULTS["llm"])
    with store.db:
        store.db.execute("INSERT INTO analyses(cache_key,result,created_at) VALUES(?,?,?)", (key, '{}', DATE))
        rejection._initialize(store.db)
        store.db.execute("""CREATE TRIGGER fail_rejection_audit BEFORE INSERT ON rejection_actions
                         BEGIN SELECT RAISE(ABORT,'audit unavailable'); END""")
    with pytest.raises(sqlite3.IntegrityError):
        rejection.retry_item(store, row["id"], row["content_hash"], "Retry", DEFAULTS["llm"], DATE)
    assert rejection.show_item(store, row["id"])["status"] == "rejected"
    assert analysis_result(store, key) == {} and actions(store) == []


def test_content_changed_during_retry_does_not_get_overwritten(store, monkeypatch):
    _, row = rejected(store)
    key = cache_key(row, DEFAULTS["llm"])
    with store.db:
        store.db.execute("INSERT INTO analyses(cache_key,result,created_at) VALUES(?,?,?)", (key, '{}', DATE))
    original_key = rejection._retry_key
    database = store.db.execute("PRAGMA database_list").fetchone()[2]

    def concurrent_change(current, llm):
        result = original_key(current, llm)
        with sqlite3.connect(database) as writer:
            writer.execute("UPDATE items SET content_hash=? WHERE id=?", ("f" * 64, row["id"]))
        return result

    monkeypatch.setattr(rejection, "_retry_key", concurrent_change)
    with pytest.raises(ValueError, match="changed during"):
        rejection.retry_item(store, row["id"], row["content_hash"], "Reviewed", DEFAULTS["llm"], DATE)
    current = rejection.show_item(store, row["id"])
    assert current["status"] == "rejected" and current["content_hash"] == "f" * 64
    assert analysis_result(store, key) == {} and actions(store) == []


@pytest.mark.parametrize("reason", ["", "   ", "x" * 1001, "bad\x1bvalue", "bad\ud800value"])
def test_reason_is_required_and_bounded(store, reason):
    _, row = rejected(store)
    with pytest.raises(ValueError, match="reason"):
        rejection.dismiss_item(store, row["id"], row["content_hash"], reason, DATE)
    assert rejection.show_item(store, row["id"])["status"] == "rejected"
    assert actions(store) == []


@pytest.mark.parametrize("kwargs", [{"limit": 0}, {"limit": True}, {"limit": 201}, {"after": "../bad"}, {"status": "pending"}])
def test_list_arguments_are_bounded(store, kwargs):
    with pytest.raises(ValueError):
        rejection.list_items(store, **kwargs)
