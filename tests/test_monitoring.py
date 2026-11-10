import json
import sqlite3

import pytest

from onionflash import monitoring
from onionflash.util import after


NOW = "2026-11-10T12:00:00Z"
SOURCE = {"id": "health", "monitor_id": "consensus-checker", "alert_format": "consensus", "name": "Tor consensus-health mailing list"}
SETTINGS = {
    "min_reports": 2, "min_span_seconds": 3600, "window_seconds": 172800,
    "retention_days": 30, "max_observations": 10000, "max_groups": 2000,
    "max_source_links": 3, "max_alerts_per_item": 100,
    "stale_after_seconds": 259200, "max_future_seconds": 300,
}


@pytest.fixture
def db():
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute("""CREATE TABLE stories(id TEXT PRIMARY KEY, cluster_key TEXT UNIQUE,
        payload TEXT, published_at TEXT, updated_at TEXT)""")
    monitoring.initialize(connection)
    yield connection
    connection.close()


@pytest.fixture(autouse=True)
def parsed_facts(monkeypatch):
    # Parser grammar has its own real-message tests. Exercise aggregation state here.
    monkeypatch.setattr(monitoring, "parse_alerts", lambda item, name, limit: (item.get("facts", []), item.get("unsupported", 0)))


def fact(target="bastet", condition="authority-missing", kind="document", state="firing"):
    return {"target": target, "condition": condition, "kind": kind, "state": state}


def item(hour=0, *, facts=None, url=None, **extra):
    return {"published_at": after(hour * 3600, NOW), "title": "Consensus health warning",
            "url": url or f"https://example.org/messages/{hour}/", "facts": [fact()] if facts is None else facts, **extra}


def ingest(db, items, *, source=SOURCE, observed=NOW, **settings):
    return monitoring.ingest(db, source, items, {**SETTINGS, **settings}, observed)


def stories(db):
    return [json.loads(row[0]) for row in db.execute("SELECT payload FROM stories ORDER BY published_at,id")]


def test_replay_and_mirrors_do_not_establish_persistence(db):
    first = item(-2)
    assert ingest(db, [first])["observations"] == 1
    assert ingest(db, [first])["duplicates"] == 1
    mirror = {**SOURCE, "id": "mirror", "name": "Mirror"}
    assert ingest(db, [item(-2, url="https://mirror.example/messages/a/")], source=mirror)["duplicates"] == 1
    assert stories(db) == []
    assert monitoring.status(db, SETTINGS, NOW)["observations"] == 1


def test_notifications_must_have_both_count_and_span(db):
    ingest(db, [item(-1), item(-0.5)])
    assert stories(db) == []
    result = ingest(db, [item(0)])
    assert result["published"] == 1
    story = stories(db)[0]
    assert story["confidence"] == "observed-anomaly"
    assert story["priority"] == "normal"
    assert story["published_at"] == after(-3600, NOW)
    assert story["updated_at"] == NOW
    assert story["added_at"] == NOW  # when Onion Flash published it, not the first report
    assert "3 notifications" in story["summary"]
    assert "do not establish a continuous outage" in story["summary"]


def test_newest_first_batch_is_folded_chronologically(db):
    assert ingest(db, [item(0), item(-1), item(-2)])["published"] == 1
    assert stories(db)[0]["published_at"] == after(-7200, NOW)


def test_repeat_counts_new_conditions_and_source_links_do_not_churn_story(db):
    ingest(db, [item(-2), item(-1)])
    before = tuple(db.execute("SELECT * FROM stories").fetchone())
    ingest(db, [item(0, facts=[fact(), fact(condition="descriptor-missing")])])
    assert tuple(db.execute("SELECT * FROM stories").fetchone()) == before
    status = monitoring.status(db, SETTINGS, NOW)
    assert status["observations"] == 4
    assert status["groups"] == 1
    assert status["published"] == 1


def test_one_bundle_is_one_notification_not_multiple_independent_reports(db):
    ingest(db, [item(0, facts=[fact(), fact(condition="descriptor-missing"), fact(condition="signature-missing")])])
    assert stories(db) == []
    assert monitoring.status(db, SETTINGS, NOW)["held"] == 1


def test_different_transient_conditions_cannot_establish_persistence(db):
    ingest(db, [item(-2), item(-1, facts=[fact(condition="descriptor-missing")])])
    assert stories(db) == []
    ingest(db, [item(0)])
    story = stories(db)[0]
    assert "missing authority in a consensus" in story["summary"]
    assert "missing authority descriptor" not in story["summary"]
    assert {link["url"] for link in story["sources"]} == {item(-2)["url"], item(0)["url"]}


def test_public_scope_needs_boundary_citations_within_link_budget(db):
    ingest(db, [item(-4), item(-3, facts=[fact(condition="descriptor-missing")]),
                item(-2, facts=[fact(condition="descriptor-missing")]), item(-1)], max_source_links=2)
    story = stories(db)[0]
    assert len(story["sources"]) == 2
    assert "missing authority descriptor" not in story["summary"]
    assert {link["url"] for link in story["sources"]} == {item(-4)["url"], item(-1)["url"]}


def test_censorship_services_and_monitor_failures_always_stay_private(db):
    source = {**SOURCE, "alert_format": "censorship", "monitor_id": "alertmanager"}
    observations = [fact("china / monitor.example:443", "monitor-offline", "monitor"),
                    fact("https://target.example/", "http-unreachable", "service")]
    ingest(db, [item(-2, facts=observations), item(-1, facts=observations)], source=source)
    status = monitoring.status(db, SETTINGS, NOW)
    assert status["monitor_failures"] == status["service_observations"] == 1
    assert status["held"] == 2
    assert stories(db) == []
    # Even parser output cannot make a censorship feed eligible as consensus evidence.
    assert ingest(db, [item(0)], source=source)["unsupported"] == 1


def test_case_sensitive_http_targets_are_not_merged(db):
    source = {**SOURCE, "alert_format": "censorship"}
    ingest(db, [item(0, facts=[fact("https://target.example/A", "http-unreachable", "service"),
                              fact("https://target.example/a", "http-unreachable", "service")])], source=source)
    assert monitoring.status(db, SETTINGS, NOW)["groups"] == 2


def test_silence_stale_feeds_and_retention_never_resolve_or_republish(db):
    ingest(db, [item(-2), item(-1)])
    before = tuple(db.execute("SELECT * FROM stories").fetchone())
    later = after(31 * 86400, NOW)
    ingest(db, [], observed=later)
    status = monitoring.status(db, SETTINGS, later)
    assert status["stale"] == 1
    assert status["observations"] == 0
    assert status["groups"] == 1
    assert status["resolved"] == 0
    assert tuple(db.execute("SELECT * FROM stories").fetchone()) == before


def test_explicit_recovery_keeps_guid_and_recurrence_starts_new_episode(db):
    ingest(db, [item(-4), item(-3)])
    first = stories(db)[0]
    assert ingest(db, [item(-2, facts=[fact(state="resolved")])])["recovered"] == 1
    recovered = stories(db)[0]
    assert recovered["id"] == first["id"]
    assert recovered["published_at"] == first["published_at"]
    assert recovered["state"] == "resolved"
    assert recovered["sources"][0]["url"] == item(-2)["url"]
    assert ingest(db, [item(-3)])["duplicates"] == 1
    assert len(stories(db)) == 1
    ingest(db, [item(-1), item(0)])
    assert len(stories(db)) == 2
    assert stories(db)[1]["id"] != first["id"]
    assert stories(db)[1]["published_at"] == after(-3600, NOW)


def test_partial_recovery_does_not_clear_other_document_conditions(db):
    conditions = [fact(), fact(condition="signature-missing")]
    ingest(db, [item(-4, facts=conditions), item(-3, facts=conditions)])
    ingest(db, [item(-2, facts=[fact(state="resolved")])])
    assert stories(db)[0]["state"] == "developing"
    ingest(db, [item(-1, facts=[fact(condition="signature-missing", state="resolved")])])
    assert stories(db)[0]["state"] == "resolved"


def test_condition_recovery_resets_its_persistence_even_when_group_stays_open(db):
    ingest(db, [item(-4, facts=[fact(), fact(condition="signature-missing")]),
                item(-3, facts=[fact(state="resolved")]), item(-2)])
    assert stories(db) == []
    ingest(db, [item(-1)])
    story = stories(db)[0]
    assert story["published_at"] == after(-7200, NOW)
    assert "2 notifications" in story["summary"]


def test_same_timestamp_recovery_cannot_override_a_warning(db):
    ingest(db, [item(-2), item(-1)])
    result = ingest(db, [item(-1, facts=[fact(state="resolved")], url="https://example.org/conflicting/")])
    assert result["rejected"] == 1
    assert stories(db)[0]["state"] == "developing"


def test_conflicting_warning_and_recovery_in_one_batch_do_not_resolve(db):
    ingest(db, [item(-3), item(-2)])
    result = ingest(db, [item(-1), item(-1, facts=[fact(state="resolved")], url="https://example.org/conflicting/")])
    assert result["rejected"] == 2
    assert stories(db)[0]["state"] == "developing"


def test_recovery_and_new_document_condition_same_time_preserve_episode(db):
    ingest(db, [item(-3), item(-2)])
    story_before = tuple(db.execute("SELECT * FROM stories").fetchone())
    group_before = tuple(db.execute("SELECT * FROM monitoring_groups").fetchone())
    result = ingest(db, [item(-1, facts=[fact(state="resolved"), fact(condition="signature-missing")])])
    assert result["rejected"] == 2
    assert result["recovered"] == result["observations"] == 0
    assert tuple(db.execute("SELECT * FROM stories").fetchone()) == story_before
    assert tuple(db.execute("SELECT * FROM monitoring_groups").fetchone()) == group_before


def test_timestamps_and_source_links_fail_closed(db):
    invalid = [item(-49), item(1), item(0, published_at="2026-11-10T12:00:00"),
               item(0, published_at="bad"), item(0, url="https://user:secret@example.org/")]
    assert ingest(db, invalid)["rejected"] == len(invalid)
    assert monitoring.status(db, SETTINGS, NOW)["observations"] == 0


def test_capacity_does_not_evict_highwater_or_active_incidents(db):
    ingest(db, [item(-2)], max_groups=1, max_observations=1)
    assert ingest(db, [item(-1)], max_groups=1, max_observations=1)["capacity"] == 1
    later = after(31 * 86400, NOW)
    result = ingest(db, [item(31 * 24, facts=[fact(target="other")])], observed=later, max_groups=1, max_observations=1)
    assert result["capacity"] == 1
    status = monitoring.status(db, {**SETTINGS, "max_groups": 1}, later)
    assert status["groups"] == 1
    assert status["at_capacity"]
    assert stories(db) == []


def test_unknown_and_unallowlisted_document_conditions_stay_private(db):
    result = ingest(db, [item(-2, unsupported=1, facts=[]), item(-1, facts=[fact(condition="invented")])])
    assert result["unsupported"] == 2
    assert monitoring.status(db, SETTINGS, NOW)["unsupported"] == 2
    assert stories(db) == []


def test_failed_publication_rolls_back_observations_and_groups(db):
    db.execute("CREATE TRIGGER reject_story BEFORE INSERT ON stories BEGIN SELECT RAISE(ABORT, 'test failure'); END")
    with pytest.raises(sqlite3.IntegrityError):
        ingest(db, [item(-2), item(-1)])
    status = monitoring.status(db, SETTINGS, NOW)
    assert status["groups"] == status["observations"] == 0
