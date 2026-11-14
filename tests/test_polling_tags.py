"""Regression checks for release coverage and scheduler-boundary behavior."""

import copy
from pathlib import Path

import pytest

from helpers import ApprovingReviewer, ScriptedAnalyzer, finish_reviewed, make_config, patch_cli_pipeline, publish_stories, tag
from onionflash import cli
from onionflash.analyze import SCHEMA, AnalysisError, Analyzer, cache_key, tag_notice, validate_analysis
from onionflash.config import DEFAULTS, load_config
from onionflash.store import after, item_priority, source_due

DATE = "2026-11-09T15:30:00Z"


def tag_source(**overrides):
    return {
        "id": "tor-tags", "name": "Tor tags", "kind": "tag",
        "url": "https://gitlab.torproject.org/tpo/core/tor/-/tags?format=atom",
        "enabled": True, "interval_seconds": 300, **overrides,
    }


@pytest.mark.parametrize("name", ["tor-0.4.9.15", "tor-0.4.9.16", "arti-v2.8.0", "v1", "a"])
def test_tag_notice_needs_no_model_credential_or_http_client(name, monkeypatch):
    cfg = copy.deepcopy(DEFAULTS)
    cfg["llm"]["base_url"] = cfg["llm"]["model"] = ""
    monkeypatch.delenv(cfg["llm"]["api_key_env"], raising=False)
    monkeypatch.setattr("onionflash.llm.HttpClient", lambda *a, **kw: pytest.fail("HTTP client forbidden"))
    with Analyzer(cfg) as analyzer:
        result = analyzer.analyze(tag(title=name, content=""))
    assert result["publish"] is True and result["state"] == "tagged" and result["category"] == "release"
    assert result["priority"] == "normal" and result["confidence"] == "reported" and result["evidence"] == [name]
    assert "upstream" in result["summary"] and "released" not in result["summary"] and "verified" not in result["summary"]


@pytest.mark.parametrize("product", SCHEMA["properties"]["products"]["items"]["enum"])
def test_literal_tag_notice_still_passes_the_model_output_checks(product):
    raw = tag(product=product)
    notice = tag_notice(raw)
    assert validate_analysis(copy.deepcopy(notice), raw) == notice


def test_tag_notice_preserves_publication_dates_and_escapes_hostile_text(tmp_path, store):
    raw = tag(title='<img src=x onerror="alert(1)">', content="")
    with Analyzer(copy.deepcopy(DEFAULTS)) as analyzer:
        result = analyzer.analyze(raw)
    store.ingest(raw, DATE)
    row = store.pending(1, DATE)[0]
    finish_reviewed(store, row, result, cache_key(row, DEFAULTS["llm"]), DATE)
    story = store.stories(1)[0]
    assert (story["published_at"], story["updated_at"]) == (raw["published_at"], raw["updated_at"])
    output = tmp_path / "public"
    publish_stories([story], output)
    page = (output / "index.html").read_text()
    assert "<img src=x onerror=" not in page and "<script>attack()" not in page
    assert "&lt;img" in page and "attack()" not in page


def test_tag_cannot_downgrade_existing_announced_release(store):
    release_item = tag(kind="feed", product="network", title="Tor 0.4.9.16 released",
                       url="https://example.org/tor-0.4.9.16", content="Tor 0.4.9.16 released.")
    with Analyzer(copy.deepcopy(DEFAULTS)) as analyzer:
        tag_result = analyzer.analyze(tag())
    release_result = {**tag_result, "title": "Tor 0.4.9.16 released", "state": "released"}
    store.ingest(release_item, DATE)
    finish_reviewed(store, store.pending(1, DATE)[0], release_result, "release", DATE)
    store.ingest(tag(updated_at=DATE), DATE)
    finish_reviewed(store, store.pending(1, DATE)[0], tag_result, "tag", DATE)
    story = store.stories(1)[0]
    assert story["state"] == "released" and story["title"] == release_result["title"] and len(story["sources"]) == 2


def test_tags_have_a_fixed_queue_floor_below_serious_security(store):
    assert item_priority(tag()) == 5
    incident = tag(kind="gitlab_issue", title="Directory authority plausibly compromised", content="", labels=["Security"])
    assert item_priority(incident) > item_priority(tag())
    assert item_priority(tag(kind="feed", title="Tor 0.4.9.16 released", content="")) == 5
    store.ingest(tag(), DATE)
    assert store.pending(1, DATE)[0]["priority_score"] == 5


def test_a_success_is_rescheduled_a_few_seconds_early_and_never_more_than_a_tenth(store):
    for interval, expected in [(300, "2026-11-09T15:34:55Z"), (30, "2026-11-09T15:30:27Z")]:
        stream = tag_source(id=f"s{interval}", interval_seconds=interval)
        store.source(stream)
        store.source_success(stream, {"url": stream["url"]}, DATE)
        due = store.source(stream)["next_fetch_at"]
        assert due == expected and not source_due({"next_fetch_at": due}, after(-1, due)) and source_due({"next_fetch_at": due}, due)


def test_failure_and_catching_up_cooldowns_are_never_shortened(store):
    stream = tag_source(interval_seconds=300)
    store.source(stream)
    store.source_failure(stream, "GitLab scan catching up", DEFAULTS["collection"], DATE, catching_up=True)
    assert store.source(stream)["next_fetch_at"] == "2026-11-09T15:35:00Z"
    store.source_failure(stream, "HTTP 429", DEFAULTS["collection"], DATE)
    assert store.source(stream)["next_fetch_at"] == after(DEFAULTS["collection"]["failure_backoff_base_seconds"], DATE)


def test_late_fetch_records_actual_observation_but_keeps_schedule_anchor(tmp_path, store, monkeypatch):
    cfg = make_config(tmp_path, sources=[tag_source()])
    times = iter([DATE, "2026-11-09T15:30:07Z"])
    patch_cli_pipeline(monkeypatch, now=lambda: next(times, "2026-11-09T15:30:08Z"), reviewer=None,
                       collect=lambda *a: {"items": [tag()], "url": tag_source()["url"]})
    cli.run(cfg, store)
    row = store.db.execute("SELECT first_seen,last_seen FROM items").fetchone()
    state = store.source(tag_source())
    assert row["first_seen"] == row["last_seen"] == "2026-11-09T15:30:07Z"
    assert state["last_success"] == "2026-11-09T15:30:07Z"
    assert state["next_fetch_at"] == after(300 - 5, DATE)


def test_inference_outage_does_not_block_a_queued_deterministic_tag(tmp_path, store, monkeypatch):
    cfg = make_config(tmp_path, sources=[tag_source()])
    writer = ScriptedAnalyzer(lambda inc: tag_notice(inc) if inc["kind"] == "tag" else (_ for _ in ()).throw(
        AnalysisError("LLM unavailable", retryable=True)))
    patch_cli_pipeline(monkeypatch, now=DATE, analyzer=lambda *a, **kw: writer, reviewer=ApprovingReviewer)
    store.source(tag_source())
    store.source_success(tag_source(), {"url": tag_source()["url"]}, DATE)
    store.ingest(tag(kind="gitlab_issue", title="Authority plausibly compromised", url="https://example.org/security"), DATE)
    store.ingest(tag(), DATE)
    result = cli.run(cfg, store)
    assert store.stories(1)[0]["state"] == "tagged"
    assert [c["kind"] for c in writer.calls] == ["gitlab_issue", "tag"]
    assert result["analysis_failed"] == 1 and result["analyzed"] == 1


def test_new_settings_and_verified_sources_are_in_example(tmp_path, monkeypatch):
    monkeypatch.setenv("ONIONFLASH_LLM_BASE_URL", "https://model.example/v1")
    path = tmp_path / "config.toml"
    path.write_text((Path(__file__).parents[1] / "config.example.toml").read_text())
    sources = {s["id"]: s for s in load_config(path)["sources"]}
    assert sources["tor-browser-security"]["enabled"] and sources["tor-browser-security"]["authority"] == "development"
    assert sources["anti-censorship-team"]["enabled"] and sources["tor-dev"]["enabled"]
