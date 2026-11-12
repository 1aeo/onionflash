"""One-item operator decisions preserve story state and the private audit trail."""

from approval_helpers import finish_reviewed
import copy
import json
import sqlite3

import pytest

from onionflash import editorial, rejection
from onionflash.analyze import AnalysisError, cache_key
from onionflash.config import DEFAULTS
from onionflash.store import Store
from onionflash.util import after
from test_core import DAMAGE, DATE, analysis, damage_item, item


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


def failed_pending(store, *, terminal=False):
    source = item(url="https://example.org/failed-pending")
    store.ingest(source, DATE)
    store.defer(source["id"], "Saved analysis failed", DEFAULTS["llm"], DATE, terminal=terminal)
    return source, dict(store.db.execute("SELECT * FROM items WHERE id=?", (source["id"],)).fetchone())


def ignored(store, number=0):
    source = item(url=f"https://example.org/ignored/{number}")
    store.ingest(source, DATE)
    row = store.pending(1, DATE)[0]
    finish_reviewed(store, row, analysis(), cache_key(row, DEFAULTS["llm"]), DATE, decision="skip")
    return source, dict(store.db.execute("SELECT * FROM items WHERE id=?", (source["id"],)).fetchone())


def analysis_result(store, key):
    """Inspect the stored analysis audit directly; runtime analysis has no cache."""
    row = store.db.execute("SELECT result FROM analyses WHERE cache_key=?", (key,)).fetchone()
    return json.loads(row[0]) if row is not None else None


def actions(store):
    return [dict(row) for row in store.db.execute("SELECT * FROM rejection_actions ORDER BY action_id")]


@pytest.mark.parametrize("kind", DAMAGE)
def test_a_damaged_saved_item_stays_listable_and_inspectable(store, kind):
    _, row = rejected(store, 0)
    _, intact = rejected(store, 1)
    damage_item(store.db, row["id"], kind)
    listed = {entry["id"]: entry["title"] for entry in rejection.list_items(store)["items"]}
    assert listed == {row["id"]: None, intact["id"]: json.loads(intact["payload"])["title"]}
    shown = rejection.show_item(store, row["id"])
    assert shown["saved_item"] is None and shown["content_hash"] == row["content_hash"]


@pytest.mark.parametrize("kind", [*DAMAGE, "blob"])  # the pipeline reads a payload only as text
def test_a_damaged_saved_item_can_be_dismissed_but_not_retried(store, kind):
    _, row = rejected(store)
    damage_item(store.db, row["id"], kind)
    with pytest.raises(ValueError, match="incomplete or unreadable"):
        rejection.retry_item(store, row["id"], row["content_hash"], "try again")
    assert rejection.dismiss_item(store, row["id"], row["content_hash"], "damaged copy")["status"] == "dismissed"


@pytest.mark.parametrize("title", [[1], {"a": 1}, 5, True])
def test_only_text_is_listed_as_a_title(store, title):
    """A saved title of another type never reaches the printed list, which could not print one nested deeply enough."""
    _, row = rejected(store)
    store.db.execute("UPDATE items SET payload=? WHERE id=?", (json.dumps({**json.loads(row["payload"]), "title": title}), row["id"]))
    store.db.commit()
    assert rejection.list_items(store)["items"][0]["title"] is None


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
    assert all(entry["attempts"] == 3 and entry["rejections"] == 3 and entry["next_attempt_at"] is None for entry in entries)
    assert all(entry["rejection_reason"] == "Model evidence is not present in source" for entry in entries)
    assert all(entry["source_url"].startswith("https://example.org/news/") for entry in entries)
    assert "The operator reported" not in json.dumps(first)
    assert not actions(store)  # Reading does not create an operator decision.
    pending = next(row for row in store.pending(20, after(86400, DATE)) if row["id"] == transient["id"])
    assert pending["attempts"] == 5 and pending["rejections"] == 0


def test_show_is_explicit_source_inspection(store):
    source, row = rejected(store)
    shown = rejection.show_item(store, source["id"])
    assert shown["saved_item"]["content"] == source["content"]
    assert shown["content_hash"] == row["content_hash"]
    assert shown["actions"] == []


def test_retry_queues_the_revision_and_leaves_analysis_records_unchanged(store, capsys):
    source, row = rejected(store)
    key = cache_key(row, DEFAULTS["llm"])
    with store.db:  # a record under the same key, from an identical revision or another item with the same content
        store.record_analysis(row, analysis(), key, DATE)
    before = [tuple(record) for record in store.db.execute("SELECT * FROM analyses")]
    result = rejection.retry_item(store, row["id"], row["content_hash"], "Grounding rule was repaired", DATE)
    queued = store.pending(10, DATE)
    assert len(queued) == 1
    assert (queued[0]["status"], queued[0]["attempts"], queued[0]["rejections"], queued[0]["next_attempt_at"], queued[0]["last_error"]) == ("pending", 0, 0, None, None)
    assert [tuple(record) for record in store.db.execute("SELECT * FROM analyses")] == before
    assert store.stories() == []  # Retrying is not publishing.
    audit = actions(store)[0]
    assert (audit["before_status"], audit["before_attempts"], audit["before_rejections"]) == ("rejected", 3, 3)
    assert audit["reason"] == "Grounding rule was repaired"
    assert "content" not in result and "reason" not in result
    assert capsys.readouterr().out == ""
    finish_reviewed(store, queued[0], analysis(summary="A supported account after retry."), key, after(60, DATE))
    assert store.pending_count() == 0
    story = store.stories()[0]
    assert story["summary"] == "A supported account after retry."
    assert analysis_result(store, key) == analysis()  # the earlier record stays; the new attempt adds its own
    assert analysis_result(store, story["editorial_analysis_key"])["summary"] == "A supported account after retry."
    assert len(actions(store)) == 1


def test_retry_undoes_a_mistaken_dismissal(store):
    _, row = rejected(store)
    rejection.dismiss_item(store, row["id"], row["content_hash"], "Dismissed by mistake", DATE)
    assert rejection.retry_item(store, row["id"], row["content_hash"], "A real report", DATE)["status"] == "pending"
    assert store.pending_count() == 1
    for operation in (rejection.retry_item, rejection.dismiss_item):  # neither applies to the queued revision
        with pytest.raises(ValueError, match="terminally rejected"):
            operation(store, row["id"], row["content_hash"], "Again", DATE)
    assert [(audit["action"], audit["before_status"]) for audit in actions(store)] == [("dismiss", "rejected"), ("retry", "dismissed")]


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
    operation = getattr(rejection, action + "_item")
    operation(store, row["id"], row["content_hash"], "Reviewed", DATE)
    with pytest.raises(ValueError, match="terminally rejected"):
        operation(store, row["id"], row["content_hash"], "Reviewed", DATE)
    assert len(actions(store)) == 1


def test_stale_hash_and_new_pending_actions_are_rejected_without_audit(store):
    source, row = rejected(store)
    changed = {**source, "content": "Changed source", "updated_at": after(60, DATE)}
    store.ingest(changed, after(60, DATE))
    with pytest.raises(ValueError, match="content changed"):
        rejection.dismiss_item(store, row["id"], row["content_hash"], "Old view", DATE)
    current = rejection.show_item(store, row["id"])
    with pytest.raises(ValueError, match="terminally rejected"):
        rejection.retry_item(store, row["id"], current["content_hash"], "New source revision", DATE)
    assert actions(store) == []


@pytest.mark.parametrize("failures", [1, 3])
@pytest.mark.parametrize("locked", [False, True])
def test_retry_and_dismiss_do_not_mutate_an_existing_story_or_editorial_state(store, failures, locked):
    source = item()
    store.ingest(source, DATE)
    first = store.pending(1, DATE)[0]
    finish_reviewed(store, first, analysis(), cache_key(first, DEFAULTS["llm"]), DATE)
    original_story_id = store.stories()[0]["id"]
    if locked:  # an operator correction locks the story
        editorial.correct(store.db, original_story_id, {"why_it_matters": "Operator-corrected text."}, reason="Operator correction",
                          expect_hash=editorial.show(store.db, original_story_id)["hash"], observed=DATE)
    changed = {**source, "content": source["content"] + " A disputed later revision.", "updated_at": after(60, DATE)}
    store.ingest(changed, after(60, DATE))
    for _ in range(failures):
        store.defer(source["id"], "Unsupported later claim", DEFAULTS["llm"], DATE, terminal=True)
    before = editorial.show(store.db, original_story_id)  # its hash covers the story row, revision, lock and retraction
    current = rejection.show_item(store, source["id"])
    assert current["final_review"] is None  # the earlier revision's decision is not this one's
    rejection.retry_item(store, source["id"], current["content_hash"], "Check repaired reviewer", DATE)
    for _ in range(failures):
        store.defer(source["id"], "Still unsupported", DEFAULTS["llm"], DATE, terminal=True)
    rejection.dismiss_item(store, source["id"], current["content_hash"], "Keep the earlier accepted account", DATE)
    assert editorial.show(store.db, original_story_id) == before and before["locked"] == locked
    assert rejection.show_item(store, source["id"])["story_id"] == original_story_id


@pytest.mark.parametrize("field", ["content", "url", "updated_at"])
def test_retry_refuses_an_incomplete_saved_item_but_dismiss_still_works(store, field):
    _, row = rejected(store)
    payload = json.loads(row["payload"])
    payload.pop(field)
    with store.db:
        store.db.execute("UPDATE items SET payload=? WHERE id=?", (json.dumps(payload), row["id"]))
    with pytest.raises(ValueError, match="incomplete or unreadable"):
        rejection.retry_item(store, row["id"], row["content_hash"], "Try again", DATE)
    assert actions(store) == []
    rejection.dismiss_item(store, row["id"], row["content_hash"], "No usable stored body", DATE)
    assert rejection.show_item(store, row["id"])["status"] == "dismissed"


@pytest.mark.parametrize("pending", [False, True])
def test_failed_audit_insert_rolls_back_the_action(store, pending):
    _, row = failed_pending(store) if pending else rejected(store)
    with store.db:
        store.db.execute("""CREATE TRIGGER fail_rejection_audit BEFORE INSERT ON rejection_actions
                         BEGIN SELECT RAISE(ABORT,'audit unavailable'); END""")
    with pytest.raises(sqlite3.IntegrityError):
        rejection.retry_item(store, row["id"], row["content_hash"], "Retry", DATE)
    assert rejection.show_item(store, row["id"])["status"] == row["status"] and actions(store) == []


def test_an_earlier_release_can_still_use_the_audit_table(store):
    """After a code rollback, an earlier release writes and reads two columns this one no longer uses."""
    _, row = rejected(store)
    with store.db:
        store.db.execute("""INSERT INTO rejection_actions(item_id,content_hash,action,reason,created_at,before_status,
            before_attempts,before_rejections,before_error,before_next_attempt_at,superseded_analysis_key,superseded_analysis_json)
            VALUES(?,?,'dismiss','Reviewed',?,'rejected',3,3,NULL,NULL,NULL,NULL)""", (row["id"], row["content_hash"], DATE))
    assert store.db.execute("SELECT superseded_analysis_key FROM rejection_actions").fetchone()[0] is None
    assert rejection.show_item(store, row["id"])["actions"][0]["reason"] == "Reviewed"


def test_content_changed_during_retry_does_not_get_overwritten(store, monkeypatch):
    _, row = rejected(store)
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
    assert current["status"] == "rejected" and current["content_hash"] == "f" * 64
    assert actions(store) == []


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


@pytest.mark.parametrize("action", ["retry", "dismiss"])
@pytest.mark.parametrize("terminal", [False, True])
def test_failed_pending_actions_preserve_audit_and_do_not_repeat(store, action, terminal):
    source, row = failed_pending(store, terminal=terminal)
    key = cache_key(row, DEFAULTS["llm"])
    with store.db:
        store.db.execute("INSERT INTO analyses(cache_key,result,created_at) VALUES(?,?,?)", (key, '{}', DATE))
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
    # Neither action moves the analysis record into the audit.
    assert analysis_result(store, key) == {}
    if action == "retry":
        assert current["status"] == "pending" and current["attempts"] == current["rejections"] == 0
        assert current["rejection_reason"] is None
    else:
        assert current["status"] == "dismissed"
        assert not store.ingest(copy.deepcopy(source), after(60, DATE))
        assert not store.ingest({**source, "updated_at": after(120, DATE)}, after(120, DATE))
        assert store.pending_count() == 0
    with pytest.raises(ValueError, match="previously failed pending"):
        operation()
    assert len(actions(store)) == 1


@pytest.mark.parametrize("action,status,attempts,error", [(action, *case) for action in ("retry", "dismiss") for case in [
    ("pending", 0, None), ("pending", 0, "old error"), ("pending", 1, None),
    ("pending", 1, "  \t"), ("pending", -1, "old error"),
    ("published", 2, "old error"), ("ignored", 2, "old error"), ("dismissed", 2, "old error"),
] if action == "dismiss" or case[0] not in {"dismissed", "ignored"}])  # retry undoes a dismissal or reconsiders an ignored item
def test_new_or_completed_items_cannot_be_acted_on(store, action, status, attempts, error):
    _, row = failed_pending(store)
    with store.db:
        store.db.execute("UPDATE items SET status=?,attempts=?,last_error=? WHERE id=?", (status, attempts, error, row["id"]))
    before = dict(store.db.execute("SELECT * FROM items WHERE id=?", (row["id"],)).fetchone())
    with pytest.raises(ValueError, match="previously failed pending"):
        if action == "retry":
            rejection.retry_item(store, row["id"], row["content_hash"], "Reviewed", DATE)
        else:
            rejection.dismiss_item(store, row["id"], row["content_hash"], "Reviewed", DATE)
    assert dict(store.db.execute("SELECT * FROM items WHERE id=?", (row["id"],)).fetchone()) == before
    assert actions(store) == []


def test_pending_retry_restarts_review_and_reuses_draft(store):
    from onionflash import review_gate
    from test_review_gate import Writer, Reviewer, verdict
    source = item()
    store.ingest(source, DATE)
    row = store.pending(1, DATE)[0]
    with pytest.raises(AnalysisError):
        review_gate.process_item(DEFAULTS, store, row, Writer(),
                                 Reviewer(AnalysisError("Request timed out", retryable=True)), DATE)
    store.defer(row["id"], "Final review request failed", DEFAULTS["llm"], DATE)
    rejection.retry_item(store, row["id"], row["content_hash"], "Review policy repaired", DATE)
    job = store.db.execute("SELECT stage,record_json FROM review_jobs WHERE item_id=?", (row["id"],)).fetchone()
    assert job["stage"] == "drafted" and json.loads(job["record_json"])["reviews"] == []
    writer = Writer()
    result = review_gate.process_item(DEFAULTS, store, store.pending(1, DATE)[0], writer, Reviewer(verdict()), DATE)
    assert result["status"] == "published" and writer.calls == []
    assert actions(store)[0]["before_status"] == "pending"


def test_dismissed_failed_pending_revision_only_requeues_on_source_change(store):
    source, row = failed_pending(store)
    rejection.dismiss_item(store, row["id"], row["content_hash"], "Already covered", DATE)
    changed = {**source, "content": source["content"] + " Additional source evidence.", "updated_at": after(60, DATE)}
    assert store.ingest(changed, after(60, DATE))
    fresh = rejection.show_item(store, row["id"])
    assert fresh["status"] == "pending" and fresh["attempts"] == 0
    with pytest.raises(ValueError, match="content changed"):
        rejection.dismiss_item(store, row["id"], row["content_hash"], "Stale inspection", DATE)
    with pytest.raises(ValueError, match="previously failed pending"):
        rejection.dismiss_item(store, row["id"], fresh["content_hash"], "New evidence not analyzed", DATE)
    assert len(actions(store)) == 1


@pytest.mark.parametrize("action", ["retry", "dismiss"])
@pytest.mark.parametrize("change", ["status='published'", "attempts=attempts+1", "rejections=rejections+1",
                                    "last_error=NULL", "next_attempt_at=NULL",
                                    # Comment refreshes rewrite only the payload, so the swap compares its exact bytes.
                                    "payload='{\"other\": 1}'", "payload=replace(payload, 'title', 'título')",
                                    "payload=CAST(x'7b22ff22' AS TEXT)"])
def test_concurrent_pending_queue_change_is_not_overwritten(store, monkeypatch, action, change):
    """A stale operator action must preserve concurrent queue updates without an audit."""
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
        if action == "retry":
            rejection.retry_item(store, row["id"], row["content_hash"], "Reviewed", DATE)
        else:
            rejection.dismiss_item(store, row["id"], row["content_hash"], "Reviewed", DATE)
    current = store.db.execute("SELECT content_hash,status FROM items WHERE id=?", (row["id"],)).fetchone()
    assert current["content_hash"] == row["content_hash"]
    assert current["status"] != "dismissed" and actions(store) == []


def test_ignored_reconsideration_is_explicit_audited_and_one_item_only(store):
    """Reconsideration resets one inspected ignored revision and records its prior state."""
    _, row = ignored(store)
    _, other = ignored(store, 1)
    key = cache_key(row, DEFAULTS["llm"])
    with pytest.raises(ValueError, match="previously failed pending"):  # only a retry reconsiders it
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
    assert audit["before_status"] == "ignored" and audit["action"] == "retry"
    assert audit["reason"] == "Reviewed selection"
    # The ignored decision's analysis record stays where it is; retry adds no copy of it.
    assert audit["superseded_analysis_key"] is None and audit["superseded_analysis_json"] is None
    assert analysis_result(store, key) == analysis()
    with pytest.raises(ValueError, match="previously failed pending"):
        rejection.retry_item(store, row["id"], row["content_hash"], "Duplicate retry", DATE)
    assert len(actions(store)) == 1


def reviewed_skip(store):
    """Commit a skip for insufficient new information, which leaves neither its job nor its receipt."""
    from onionflash import review_gate
    from test_review_gate import Reviewer, Writer, verdict
    source = item(url="https://example.org/reconsidered-report")
    store.ingest(source, DATE)
    row = store.pending(1, DATE)[0]
    reply = verdict("skip", criterion="new_information")
    reply["criteria"]["new_information"]["outcome"] = "insufficient"
    checker = Reviewer(reply)
    assert review_gate.process_item(DEFAULTS, store, row, Writer(), checker, DATE)["status"] == "ignored"
    assert not store.db.execute("SELECT 1 FROM review_jobs WHERE item_id=?", (row["id"],)).fetchone()
    assert not store.db.execute("SELECT 1 FROM review_approvals").fetchone()
    return row, checker.calls[0][0]


def test_a_skip_is_listed_with_its_reason_and_shows_its_decision_and_coverage(store):
    store.ingest(item(url="https://example.org/earlier-report"), DATE)
    first = store.pending(1, DATE)[0]
    finish_reviewed(store, first, analysis(), cache_key(first, DEFAULTS["llm"]), DATE)
    row, _ = reviewed_skip(store)
    listed = rejection.list_items(store, status="ignored")["items"]
    assert [(entry["id"], entry["story_id"], entry["rejection_reason"]) for entry in listed] == [
        (row["id"], None, "Final review skipped: new_information")]  # a skip maps the item to no story
    shown = rejection.show_item(store, row["id"])["final_review"]
    assert shown["stage"] == "finished" and shown["latest_review"]["criteria"]["new_information"]["outcome"] == "insufficient"
    assert [entry["id"] for entry in shown["coverage"]["recent"]] == [store.stories()[0]["id"]]
    with store.db:  # earlier releases committed some revisions without a review record
        store.record_analysis(row, analysis(), "commit-without-a-record", DATE)
    assert rejection.show_item(store, row["id"])["final_review"] is None


def test_explicit_reconsideration_gets_a_fresh_decision(store):
    """Identical source, draft and context cannot reuse the explicitly rejected skip."""
    from onionflash import review_gate
    from test_review_gate import Reviewer, Writer, verdict
    row, candidate = reviewed_skip(store)
    rejection.retry_item(store, row["id"], row["content_hash"], "Reconsider this editorial decision", DATE)
    checker = Reviewer(verdict())
    result = review_gate.process_item(DEFAULTS, store, store.pending(1, DATE)[0], Writer(), checker, DATE)
    assert result["status"] == "published" and not result["cache_hit"]
    assert result["review_calls"] == 2 and checker.calls[0][0] == candidate
    assert [call[2] for call in checker.calls] == [False, True]


def test_show_prints_a_skip_that_repeats_the_first_decision_after_a_hold(store):
    """An exact repeat of an earlier audit row is saved again once another decision came between them."""
    from onionflash import review_gate
    from test_review_gate import Reviewer, Writer, verdict
    row, _ = reviewed_skip(store)
    rejection.retry_item(store, row["id"], row["content_hash"], "Reconsider this editorial decision", DATE)
    assert review_gate.process_item(DEFAULTS, store, store.pending(1, DATE)[0], Writer(), Reviewer(verdict("hold")), DATE)["status"] == "held"
    rejection.retry_item(store, row["id"], row["content_hash"], "Retry the held item", DATE)
    reviewed_skip(store)  # the first skip again, with an identical record
    assert rejection.show_item(store, row["id"])["final_review"]["latest_review"]["verdict"] == "skip"
