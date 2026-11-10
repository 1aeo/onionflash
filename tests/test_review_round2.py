"""Adversarial regressions and shared-helper parity from review round two."""

import copy
import json
from datetime import datetime, timezone

import pytest

from onionflash import cli
from onionflash.analyze import AnalysisError, SCHEMA, tag_notice, validate_analysis
from onionflash.collect import CollectionError, collect_source
from onionflash.config import DEFAULTS
from onionflash.store import Store, after as store_after
from onionflash.util import after, backoff_seconds, format_utc, parse_utc, plain_text, timestamp
from test_core import DATE, FakeClient, analysis, item, response, source
from test_polling_tags import tag


def test_plain_text_flushes_incomplete_html_and_normalizes_line_endings():
    assert plain_text("v1 <word", 100) == "v1 <word"
    assert plain_text("one\r\ntwo\rthree", 100) == "one\ntwo\nthree"
    assert plain_text("v1 &amp", 100) == "v1 &"
    assert plain_text("v1 <!--hidden", 100) == "v1"
    assert plain_text("<script>hidden <word", 100) == ""
    cleaned = plain_text("v1\r\n<word", 100)
    assert tag_notice(tag(title=cleaned, content=""))["evidence"] == [cleaned]


def test_generic_tag_notice_is_independent_of_source_display_name():
    first = tag_notice(tag(source_name="Original label"))
    second = tag_notice(tag(source_name="Renamed label"))
    assert first == second
    assert "upstream feed" in first["summary"]
    assert "Original label" not in json.dumps(first)


@pytest.mark.parametrize("state", ["developing", "fixed", "resolved", "mitigation-available", "merged", "released"])
def test_tag_never_replaces_richer_story_in_same_release_cluster(tmp_path, state):
    existing_item = item(
        kind="feed", product="tor", title="Tor 0.4.9.16 release update",
        url="https://example.org/release-update",
    )
    existing_result = analysis(title="Detailed security release update", state=state)
    with Store(tmp_path / "state.db") as store:
        store.ingest(existing_item, DATE)
        store.finish(store.pending(1, DATE)[0], existing_result, "detailed", DATE)
        later = tag(updated_at="2026-11-09T16:00:00Z")
        store.ingest(later, DATE)
        store.finish(store.pending(1, DATE)[0], tag_notice(later), "tag", DATE)
        story = store.stories(1)[0]
    assert story["title"] == existing_result["title"]
    assert story["summary"] == existing_result["summary"]
    assert story["state"] == state and len(story["sources"]) == 2


def test_oversized_feed_keeps_bounded_items_and_uses_normal_catchup_interval(tmp_path):
    xml = b'''<rss version="2.0"><channel><title>News</title>
    <item><title>First report</title><link>https://example.org/one</link>
    <description>First body</description><pubDate>Sun, 08 Nov 2026 10:00:00 GMT</pubDate></item>
    <item><title>Second report</title><link>https://example.org/two</link>
    <description>Second body</description><pubDate>Sun, 08 Nov 2026 11:00:00 GMT</pubDate></item>
    </channel></rss>'''
    stream = source(max_items=1)
    with pytest.raises(CollectionError, match="item limit") as failure:
        collect_source(FakeClient([response(xml)]), stream, {}, DEFAULTS["collection"], DATE)
    error = failure.value
    assert error.catching_up and len(error.items) == 1
    assert error.items[0]["title"] == "First report"
    with Store(tmp_path / "state.db") as store:
        store.source(stream)
        for _ in range(3):
            store.source_failure(stream, str(error), DEFAULTS["collection"], DATE, error.checkpoint, error.catching_up)
        state = store.source(stream)
    assert state["failures"] == 0
    assert state["next_fetch_at"] == after(stream["interval_seconds"], DATE)


def test_utc_helpers_normalize_offsets_and_preserve_store_after_import():
    assert parse_utc("2026-11-08T04:00:00-08:00") == datetime(2026, 11, 8, 12, tzinfo=timezone.utc)
    assert format_utc(parse_utc("2026-11-08T13:00:00+01:00")) == DATE
    assert timestamp("2026-11-08T13:00:00+01:00") == DATE
    assert timestamp({}, DATE) == DATE
    assert store_after is after
    assert after(2, "2026-11-08T04:00:00-08:00") == "2026-11-08T12:00:02Z"
    with pytest.raises(ValueError):
        parse_utc("2026-11-08T12:00:00")
    with pytest.raises(ValueError):
        format_utc(datetime(2026, 11, 8))
    assert [backoff_seconds(n, 5, 20) for n in (1, 2, 3, 50)] == [5, 10, 20, 20]


def test_feed_cutoff_compares_canonical_utc_dates():
    xml = b'''<rss version="2.0"><channel><title>News</title>
    <item><title>On cutoff</title><link>https://example.org/on</link><pubDate>Sun, 25 Oct 2026 14:00:00 +0200</pubDate></item>
    <item><title>Before cutoff</title><link>https://example.org/before</link><pubDate>Sun, 25 Oct 2026 11:59:59 GMT</pubDate></item>
    </channel></rss>'''
    result = collect_source(FakeClient([response(xml)]), source(), {}, DEFAULTS["collection"], DATE)
    assert [row["title"] for row in result["items"]] == ["On cutoff"]


def test_validator_limits_are_driven_by_schema_before_normalization(monkeypatch):
    monkeypatch.setitem(SCHEMA["properties"]["title"], "maxLength", 10)
    with pytest.raises(AnalysisError, match="Invalid model title"):
        validate_analysis(analysis(title="       short       "), item())
    monkeypatch.setitem(SCHEMA["properties"]["products"], "maxItems", 1)
    with pytest.raises(AnalysisError, match="Invalid model products"):
        validate_analysis(analysis(title="Short", products=["tor", "tor"]), item())
    monkeypatch.setitem(SCHEMA["properties"]["evidence"]["items"], "maxLength", 10)
    with pytest.raises(AnalysisError, match="Invalid model evidence"):
        validate_analysis(analysis(title="Short"), item())


@pytest.mark.parametrize("value", [[], {}, 1, None])
def test_scalar_enum_shape_errors_remain_analysis_errors(value):
    with pytest.raises(AnalysisError, match="Invalid model priority"):
        validate_analysis(analysis(priority=value), item())


def test_array_duplicates_and_evidence_whitespace_preserve_existing_policy():
    quote = "The operator\nreported a plausible\tcompromise"
    accepted = validate_analysis(analysis(products=["tor", "tor"], tags=["security", "security"], evidence=[quote]), item())
    assert accepted["products"] == ["tor"] and accepted["tags"] == ["security"]
    assert accepted["evidence"] == [quote]
    unpublished = validate_analysis(analysis(publish=False, title="", summary="", why_it_matters="", evidence=[], confidence="confirmed", state="released", products=["tor", "tor"]), item(kind="tag"))
    # Ignore decisions publish nothing, so their other fields are returned untouched.
    assert unpublished["state"] == "released" and unpublished["confidence"] == "confirmed"


def test_source_failure_updates_status_and_checkpoint_in_one_statement(tmp_path):
    stream = source()
    checkpoint = {"lower":DATE, "upper":DATE, "page":2, "cursor":"opaque", "reconcile":True}
    with Store(tmp_path / "state.db") as store:
        store.source(stream)
        statements = []
        store.db.set_trace_callback(statements.append)
        store.source_failure(stream, "HTTP 503", DEFAULTS["collection"], DATE, checkpoint)
        assert len([s for s in statements if s.startswith("UPDATE source_state")]) == 1
        state = store.source(stream)
        assert state["scan_cursor"] == "opaque" and state["failures"] == 1
        store.source_failure(stream, "HTTP 503 again", DEFAULTS["collection"], DATE)
        assert store.source(stream)["scan_cursor"] == "opaque"


def test_story_count_does_not_deserialize_payloads(tmp_path):
    with Store(tmp_path / "state.db") as store:
        with store.db:
            for n in range(3):
                store.db.execute("INSERT INTO stories VALUES(?,?,?,?,?)", (str(n),str(n),"not JSON",DATE,DATE))
        assert store.story_count(2) == 2 and store.story_count(5) == 3
        assert store.story_count(0) == 0


def _pipeline_config(tmp_path):
    config = copy.deepcopy(DEFAULTS)
    config["storage"]["database"] = str(tmp_path / "state.db")
    config["sources"] = []
    return config


def _prepare_run(monkeypatch, analyze, cleanup=None):
    class FakeAnalyzer:
        def __init__(self, config):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            if cleanup:
                cleanup()
        def analyze(self, payload):
            return analyze(payload)
    monkeypatch.setattr(cli, "Analyzer", FakeAnalyzer)
    monkeypatch.setattr(cli, "now_iso", lambda: DATE)
    monkeypatch.setattr(cli, "build", lambda *args: {"published_stories": 0, "stories_skipped": 0})


def _budget():
    raise cli.RunBudgetReached()


@pytest.mark.parametrize("cached", [False, True])
def test_cleanup_deadline_never_defers_a_finished_or_cached_row(tmp_path, monkeypatch, cached):
    _prepare_run(monkeypatch, lambda payload: analysis(), cleanup=_budget)
    with Store(tmp_path / "state.db") as store:
        store.ingest(item(), DATE)
        if cached:
            monkeypatch.setattr(store, "cached", lambda key: analysis())
        result = cli.run(_pipeline_config(tmp_path), store)
        row = store.db.execute("SELECT status,attempts,last_error,next_attempt_at FROM items").fetchone()
    assert result["budget_reached"]
    assert row["status"] == "published" and row["attempts"] == 0
    assert row["last_error"] is None and row["next_attempt_at"] is None


def test_real_analysis_deadline_defers_only_the_active_pending_row(tmp_path, monkeypatch):
    _prepare_run(monkeypatch, lambda payload: _budget())
    with Store(tmp_path / "state.db") as store:
        store.ingest(item(), DATE)
        result = cli.run(_pipeline_config(tmp_path), store)
        row = store.db.execute("SELECT status,attempts,last_error FROM items").fetchone()
    assert result["budget_reached"] and row["status"] == "pending"
    assert row["attempts"] == 1 and row["last_error"] == "Analysis run budget reached"


def test_deadline_after_error_deferral_does_not_count_a_second_attempt(tmp_path, monkeypatch):
    def unavailable(payload):
        raise AnalysisError("Unavailable", retryable=True)
    _prepare_run(monkeypatch, unavailable)
    with Store(tmp_path / "state.db") as store:
        store.ingest(item(), DATE)
        defer = store.defer
        calls = []
        def interrupted_defer(*args, **kwargs):
            calls.append(args)
            defer(*args, **kwargs)
            _budget()
        monkeypatch.setattr(store, "defer", interrupted_defer)
        cli.run(_pipeline_config(tmp_path), store)
        row = store.db.execute("SELECT attempts,last_error FROM items").fetchone()
    assert len(calls) == 1 and row["attempts"] == 1
    assert row["last_error"] == "Unavailable"


def test_cleanup_deadline_never_defers_a_skipped_row(tmp_path, monkeypatch):
    def unavailable(payload):
        raise AnalysisError("Unavailable", retryable=True)
    _prepare_run(monkeypatch, unavailable, cleanup=_budget)
    with Store(tmp_path / "state.db") as store:
        store.ingest(item(url="https://example.org/urgent", title="Authority compromised"), DATE)
        store.ingest(item(url="https://example.org/later", title="Other update", labels=[], content=""), DATE)
        cli.run(_pipeline_config(tmp_path), store)
        skipped = store.db.execute("SELECT attempts,last_error,next_attempt_at FROM items WHERE url=?",("https://example.org/later",)).fetchone()
    assert skipped["attempts"] == 0 and skipped["last_error"] is None
    assert skipped["next_attempt_at"] is None


@pytest.mark.parametrize("publish", [True, False])
def test_defer_does_not_change_completed_item_metadata(tmp_path, publish):
    with Store(tmp_path / "state.db") as store:
        store.ingest(item(), DATE)
        row = store.pending(1, DATE)[0]
        store.finish(row, analysis(publish=publish), "cache", DATE)
        before = dict(store.db.execute("SELECT * FROM items").fetchone())
        store.defer(row["id"], "Late timeout", DEFAULTS["llm"], DATE)
        assert dict(store.db.execute("SELECT * FROM items").fetchone()) == before
