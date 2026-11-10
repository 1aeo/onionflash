import json
import sqlite3

import pytest

from onionflash import monitoring
from onionflash.util import after


NOW = "2026-11-10T12:00:00Z"
SOURCE = {"id": "health", "monitor_id": "consensus-checker", "alert_format": "consensus", "name": "Tor consensus-health mailing list"}


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
    monkeypatch.setattr(monitoring, "parse_alerts", lambda item, name: (item.get("facts", []), item.get("unsupported", 0)))


def fact(target="bastet", condition="authority-missing", kind="document"):
    return {"target": target, "condition": condition, "kind": kind}


def item(hour=0, *, facts=None, url=None, **extra):
    return {"published_at": after(hour * 3600, NOW), "title": "Consensus health warning",
            "url": url or f"https://example.org/messages/{hour}/", "facts": [fact()] if facts is None else facts, **extra}


def ingest(db, items, *, source=SOURCE, observed=NOW):
    return monitoring.ingest(db, source, items, observed)


def stories(db):
    return [json.loads(row[0]) for row in db.execute("SELECT payload FROM stories ORDER BY published_at,id")]


def test_replay_and_mirrors_do_not_establish_persistence(db):
    first = item(-2)
    assert ingest(db, [first])["observations"] == 1
    assert ingest(db, [first])["duplicates"] == 1
    mirror = {**SOURCE, "id": "mirror", "name": "Mirror"}
    assert ingest(db, [item(-2, url="https://mirror.example/messages/a/")], source=mirror)["duplicates"] == 1
    assert stories(db) == []
    assert monitoring.status(db, NOW)["observations"] == 1


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
    status = monitoring.status(db, NOW)
    assert status["observations"] == 4
    assert status["groups"] == 1
    assert status["published"] == 1


def test_one_bundle_is_one_notification_not_multiple_independent_reports(db):
    ingest(db, [item(0, facts=[fact(), fact(condition="descriptor-missing"), fact(condition="signature-missing")])])
    assert stories(db) == []
    assert monitoring.status(db, NOW)["held"] == 1


def test_different_transient_conditions_cannot_establish_persistence(db):
    ingest(db, [item(-2), item(-1, facts=[fact(condition="descriptor-missing")])])
    assert stories(db) == []
    ingest(db, [item(0)])
    story = stories(db)[0]
    assert "missing authority in a consensus" in story["summary"]
    assert "missing authority descriptor" not in story["summary"]
    assert {link["url"] for link in story["sources"]} == {item(-2)["url"], item(0)["url"]}


def test_public_scope_needs_boundary_citations_within_link_budget(db, monkeypatch):
    monkeypatch.setattr(monitoring, "MAX_SOURCE_LINKS", 2)
    ingest(db, [item(-4), item(-3, facts=[fact(condition="descriptor-missing")]),
                item(-2, facts=[fact(condition="descriptor-missing")]), item(-1)])
    story = stories(db)[0]
    assert len(story["sources"]) == 2
    assert "missing authority descriptor" not in story["summary"]
    assert {link["url"] for link in story["sources"]} == {item(-4)["url"], item(-1)["url"]}


def test_censorship_services_and_monitor_failures_always_stay_private(db):
    source = {**SOURCE, "alert_format": "censorship", "monitor_id": "alertmanager"}
    observations = [fact("china / monitor.example:443", "monitor-offline", "monitor"),
                    fact("https://target.example/", "http-unreachable", "service")]
    ingest(db, [item(-2, facts=observations), item(-1, facts=observations)], source=source)
    status = monitoring.status(db, NOW)
    assert status["monitor_failures"] == status["service_observations"] == 1
    assert status["held"] == 2
    assert stories(db) == []
    # Even parser output cannot make a censorship feed eligible as consensus evidence.
    assert ingest(db, [item(0)], source=source)["unsupported"] == 1


def test_case_sensitive_http_targets_are_not_merged(db):
    source = {**SOURCE, "alert_format": "censorship"}
    ingest(db, [item(0, facts=[fact("https://target.example/A", "http-unreachable", "service"),
                              fact("https://target.example/a", "http-unreachable", "service")])], source=source)
    assert monitoring.status(db, NOW)["groups"] == 2


def test_silence_never_resolves_and_old_notifications_cannot_replay_after_expiry(db):
    ingest(db, [item(-2), item(-1)])
    before = tuple(db.execute("SELECT * FROM stories").fetchone())
    later = after(3 * 86400, NOW)
    assert ingest(db, [item(-2), item(-1)], observed=later)["rejected"] == 2
    assert monitoring.status(db, later)["groups"] == 0
    assert tuple(db.execute("SELECT * FROM stories").fetchone()) == before


def test_recurrence_after_the_window_is_a_new_episode(db):
    ingest(db, [item(-2), item(-1)])
    later = 120 * 24
    ingest(db, [item(later), item(later + 2)], observed=after((later + 2) * 3600, NOW))
    first, second = stories(db)
    assert first["state"] == second["state"] == "developing" and first["id"] != second["id"]
    assert second["published_at"] == after(later * 3600, NOW)


def test_timestamps_and_source_links_fail_closed(db):
    invalid = [item(-49), item(1), item(0, published_at="2026-11-10T12:00:00"),
               item(0, published_at="bad"), item(0, url="https://user:secret@example.org/")]
    assert ingest(db, invalid)["rejected"] == len(invalid)
    assert monitoring.status(db, NOW)["observations"] == 0


def test_capacity_fails_closed_without_evicting_active_groups(db, monkeypatch):
    monkeypatch.setattr(monitoring, "MAX_GROUPS", 1)
    monkeypatch.setattr(monitoring, "MAX_OBSERVATIONS", 1)
    ingest(db, [item(-2)])
    assert ingest(db, [item(-1)])["capacity"] == 1
    assert ingest(db, [item(-1, facts=[fact(target="moria1")])])["capacity"] == 1
    status = monitoring.status(db, NOW)
    assert status["groups"] == 1 and status["at_capacity"]
    assert stories(db) == []


def test_unknown_and_unallowlisted_document_conditions_stay_private(db):
    result = ingest(db, [item(-2, unsupported=1, facts=[]), item(-1, facts=[fact(condition="invented")])])
    assert result["unsupported"] == 2
    assert stories(db) == []


def test_only_known_directory_authorities_can_be_named_publicly(db):
    unknown = [fact(target="not-an-authority")]
    assert ingest(db, [item(-2, facts=unknown), item(-1, facts=unknown)])["unsupported"] == 2
    assert stories(db) == []


def test_failed_publication_rolls_back_observations_and_groups(db):
    db.execute("CREATE TRIGGER reject_story BEFORE INSERT ON stories BEGIN SELECT RAISE(ABORT, 'test failure'); END")
    with pytest.raises(sqlite3.IntegrityError):
        ingest(db, [item(-2), item(-1)])
    status = monitoring.status(db, NOW)
    assert status["groups"] == status["observations"] == 0
