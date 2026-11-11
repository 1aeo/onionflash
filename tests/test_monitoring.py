"""Persistent monitor reports remain private until source-backed news exists."""

import json
import sqlite3

import pytest

from onionflash import monitoring
from onionflash.util import after


NOW = "2026-11-10T12:00:00Z"
SOURCE = {"id": "health", "monitor_id": "consensus-checker", "alert_format": "consensus", "name": "Consensus health"}


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
    # Parser grammar has its own message tests. Exercise aggregation state here.
    monkeypatch.setattr(monitoring, "parse_alerts", lambda item, name: (item.get("facts", []), item.get("unsupported", 0)))


def fact(target="bastet", condition="authority-missing"):
    return {"target": target, "condition": condition}


def item(hour=0, *, facts=None, url=None, **extra):
    return {"published_at": after(hour * 3600, NOW), "title": "Consensus health warning",
            "url": url or f"https://example.org/messages/{hour}/", "facts": [fact()] if facts is None else facts, **extra}


def ingest(db, items, *, source=SOURCE, observed=NOW):
    return monitoring.ingest(db, source, items, observed)


def count(db, table):
    return db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def test_ten_reports_qualify_only_a_private_candidate_with_boundary_evidence(db):
    assert ingest(db, [item(hour) for hour in range(-9, 0)])["candidates"] == 0
    result = ingest(db, [item(0)])
    assert result["candidates"] == 1 and result["published"] == 0
    assert count(db, "stories") == 0
    candidate = monitoring.candidates(db, NOW)[0]
    assert candidate["authority"] == "bastet" and candidate["condition"] == "authority-missing"
    assert candidate["reports"] == 10 and candidate["status"] == "needs-source-context"
    assert candidate["first_report"] == after(-9 * 3600, NOW) and candidate["last_report"] == NOW
    assert candidate["episode_start"] == after(-9 * 3600, NOW) and candidate["story_id"] is None
    assert [source["url"] for source in candidate["sources"]] == [item(-9)["url"], item(0)["url"]]


def test_report_window_is_24_hours_without_shortening_48_hour_retention(db):
    warnings = [item(-24), *[item(hour) for hour in range(-8, 1)]]
    assert ingest(db, warnings)["candidates"] == 1
    assert monitoring.candidates(db, after(1, NOW)) == []
    assert count(db, "monitoring_observations") == 10
    assert ingest(db, [], observed=after(1, NOW))["candidates"] == 0
    assert count(db, "monitoring_groups") == 1
    assert count(db, "monitoring_observations") == 10
    assert count(db, "stories") == 0


def test_ten_burst_messages_still_need_one_hour_span(db):
    assert ingest(db, [item(-minute / 60) for minute in range(0, 60, 6)])["candidates"] == 0
    assert ingest(db, [item(0.1)], observed=after(360, NOW))["candidates"] == 1
    assert count(db, "stories") == 0


def test_timestamps_not_warning_lines_or_mirror_urls_are_counted(db):
    for number in range(12):
        duplicate = item(0, facts=[fact(), fact(), fact(condition="signature-missing")], url=f"https://example.org/copies/{number}")
        result = ingest(db, [duplicate])
        assert result["candidates"] == 0
    assert count(db, "monitoring_observations") == 2
    assert ingest(db, [item(0)], source={**SOURCE, "id": "mirror"})["duplicates"] == 1
    assert monitoring.candidates(db, NOW) == []


def test_different_authorities_conditions_or_monitors_do_not_combine(db):
    assert ingest(db, [item(hour) for hour in range(-9, -4)])["candidates"] == 0
    assert ingest(db, [item(hour, facts=[fact(condition="signature-missing")]) for hour in range(-4, 1)])["candidates"] == 0
    assert ingest(db, [item(hour, facts=[fact(target="moria1")]) for hour in range(-9, -4)])["candidates"] == 0
    assert ingest(db, [item(hour) for hour in range(-4, 1)], source={**SOURCE, "monitor_id": "independent"})["candidates"] == 0
    assert monitoring.candidates(db, NOW) == []


@pytest.mark.parametrize("condition", ["descriptor-missing", *sorted(key for key in monitoring.DOCUMENT_CONDITIONS if key.startswith("flag-"))])
def test_routine_conditions_never_qualify_but_keep_private_episode_continuity(db, condition):
    reports = [item(hour, facts=[fact(condition=condition)]) for hour in range(-19, 1)]
    result = ingest(db, reports)
    assert result["observations"] == 20 and result["candidates"] == result["published"] == 0
    assert count(db, "monitoring_groups") == 1 and count(db, "monitoring_observations") == 20
    assert monitoring.candidates(db, NOW) == [] and count(db, "stories") == 0


def test_qualifying_conditions_remain_separate_and_exclude_routine_scope(db):
    warnings = [item(hour, facts=[fact(), fact(condition="signature-missing"), fact(condition="descriptor-missing")]) for hour in range(-9, 1)]
    result = ingest(db, list(reversed(warnings)))
    assert result["candidates"] == 2 and result["published"] == 0
    candidates = monitoring.candidates(db, NOW)
    assert {candidate["condition"] for candidate in candidates} == {"authority-missing", "signature-missing"}
    assert all(candidate["reports"] == 10 for candidate in candidates)
    assert all(candidate["episode_start"] == after(-9 * 3600, NOW) for candidate in candidates)
    assert ingest(db, warnings)["duplicates"] == 30
    assert count(db, "stories") == 0


def test_existing_group_identity_and_public_article_are_never_changed(db):
    ingest(db, [item(-2)])
    row = db.execute("SELECT * FROM monitoring_groups").fetchone()
    assert row["group_key"] == "6290a2a4af2727d189f59cd40a6fbba7f24b3ec871213c806d48db7affd85f3a"
    original = {"title": "An existing published account", "sources": [{"url": "https://example.org/old-report"}]}
    with db:
        db.execute("INSERT INTO stories VALUES('legacy','legacy-cluster',?,?,?)", (json.dumps(original), NOW, NOW))
        db.execute("UPDATE monitoring_groups SET story_id='legacy' WHERE group_key=?", (row["group_key"],))
    before = tuple(db.execute("SELECT * FROM stories").fetchone())
    # A later condition can qualify privately without rewriting an old article.
    warnings = [item(hour / 10) for hour in range(11)]
    assert ingest(db, warnings, observed=after(3600, NOW))["candidates"] == 1
    assert monitoring.candidates(db, after(3600, NOW))[0]["story_id"] == "legacy"
    assert tuple(db.execute("SELECT * FROM stories").fetchone()) == before
    assert ingest(db, [], observed=after(49 * 3600, NOW))["candidates"] == 0
    # Exactly 48 hours from highwater is still in the established episode.
    assert count(db, "monitoring_groups") == 1
    ingest(db, [], observed=after(49 * 3600 + 1, NOW))
    assert count(db, "monitoring_groups") == 0
    assert tuple(db.execute("SELECT * FROM stories").fetchone()) == before


def test_recurrence_starts_a_new_private_episode_without_replaying_old_reports(db):
    old = [item(hour) for hour in range(-9, 1)]
    assert ingest(db, old)["candidates"] == 1
    original = monitoring.candidates(db, NOW)[0]["episode_start"]
    later = after(4 * 86400, NOW)
    assert ingest(db, old, observed=later)["rejected"] == 10
    assert count(db, "monitoring_groups") == 0
    fresh = [item(hour + 96) for hour in range(-9, 1)]
    assert ingest(db, fresh, observed=later)["candidates"] == 1
    assert monitoring.candidates(db, later)[0]["episode_start"] != original
    assert count(db, "stories") == 0


def test_candidate_inspection_is_read_only_and_filters_expired_windows(db):
    ingest(db, [item(hour) for hour in range(-9, 1)])
    before = list(db.iterdump())
    db.execute("PRAGMA query_only=ON")
    assert len(monitoring.candidates(db, NOW)) == 1
    assert monitoring.candidates(db, NOW, monitor_id="other") == []
    assert monitoring.candidates(db, after(25 * 3600, NOW)) == []
    assert list(db.iterdump()) == before


def test_candidate_view_is_bounded_without_changing_count_gauge(db, monkeypatch):
    monkeypatch.setattr(monitoring, "MAX_CANDIDATE_VIEW", 1)
    notices = [item(hour, facts=[fact(), fact(target="moria1")]) for hour in range(-9, 1)]
    assert ingest(db, notices)["candidates"] == 2
    assert len(monitoring.candidates(db, NOW)) == 1
    assert count(db, "stories") == 0


def test_future_clock_tolerance_does_not_qualify_until_report_time(db):
    warnings = [item(hour) for hour in range(-8, 1)]
    warnings.append(item(1 / 60))
    assert ingest(db, warnings)["observations"] == 10
    assert monitoring.candidates(db, NOW) == []
    assert len(monitoring.candidates(db, after(60, NOW))) == 1


def test_invalid_timestamps_and_urls_fail_closed(db):
    invalid = [item(-49), item(1), item(0, published_at="2026-11-10T12:00:00"),
               item(0, published_at="bad"), item(0, url="https://user:secret@example.org/")]
    assert ingest(db, invalid)["rejected"] == len(invalid)
    assert count(db, "monitoring_observations") == 0


def test_capacity_holds_new_input_without_evicting_existing_observations(db, monkeypatch):
    monkeypatch.setattr(monitoring, "MAX_GROUPS", 1)
    monkeypatch.setattr(monitoring, "MAX_OBSERVATIONS", 1)
    ingest(db, [item(-2)])
    assert ingest(db, [item(-1)])["capacity"] == 1
    assert ingest(db, [item(-1, facts=[fact(target="moria1")])])["capacity"] == 1
    assert count(db, "monitoring_groups") == count(db, "monitoring_observations") == 1


def test_unknown_conditions_targets_and_monitor_failures_stay_unsupported(db):
    warnings = [item(-2, facts=[], unsupported=1), item(-1, facts=[fact(condition="invented")]),
                item(0, facts=[fact(condition="vote-retrieval-failed"), fact(target="not-an-authority")])]
    assert ingest(db, warnings)["unsupported"] == 4
    assert count(db, "monitoring_groups") == count(db, "stories") == 0


def test_ingestion_failure_rolls_back_observations_and_groups(db):
    db.execute("CREATE TRIGGER reject_observation BEFORE INSERT ON monitoring_observations BEGIN SELECT RAISE(ABORT,'test failure'); END")
    with pytest.raises(sqlite3.IntegrityError):
        ingest(db, [item(-1)])
    assert count(db, "monitoring_groups") == count(db, "monitoring_observations") == 0
