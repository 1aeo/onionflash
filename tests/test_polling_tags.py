"""Regression checks for release coverage and scheduler-boundary behavior."""

import copy
import json
from pathlib import Path

import pytest

from onionflash.analyze import AnalysisError, Analyzer, TAG_NOTICE_VERSION, cache_key
from onionflash.config import DEFAULTS, load_config
from onionflash.render import render_site
from onionflash.store import Store, after, item_priority, source_due
from onionflash.util import digest


DATE = "2026-11-09T15:30:00Z"


def tag(**overrides):
    return {
        "id": "tag-id",
        "source_id": "tor-tags",
        "source_name": "Tor tags",
        "url": "https://gitlab.torproject.org/tpo/core/tor/-/tags/tor-0.4.9.16",
        "title": "tor-0.4.9.16",
        "content": "Tor 0.4.9.16",
        "published_at": "2026-11-04T13:55:43Z",
        "updated_at": "2026-11-04T13:55:43Z",
        "kind": "tag",
        "product": "tor",
        "authority": "official",
        "labels": [],
        "upstream_state": "",
        **overrides,
    }


def source(**overrides):
    return {
        "id": "tor-tags",
        "name": "Tor tags",
        "kind": "tag",
        "url": "https://gitlab.torproject.org/tpo/core/tor/-/tags?format=atom",
        "enabled": True,
        "interval_seconds": 300,
        **overrides,
    }


def successful_state(**overrides):
    return {
        "last_success": DATE,
        "next_fetch_at": "2026-11-09T15:35:02Z",
        "error": None,
        "failures": 0,
        "scan_upper": None,
        "scan_page": None,
        **overrides,
    }


@pytest.mark.parametrize(
    "name", ["tor-0.4.9.15", "tor-0.4.9.16", "arti-v2.8.0", "v1", "a"]
)
def test_tag_notice_needs_no_model_credential_or_http_client(name, monkeypatch):
    config = copy.deepcopy(DEFAULTS)
    config["llm"]["base_url"] = ""
    config["llm"]["model"] = ""
    monkeypatch.delenv(config["llm"]["api_key_env"], raising=False)

    def forbidden_client(*args, **kwargs):
        pytest.fail("Tag notices must not construct an HTTP client")

    monkeypatch.setattr("onionflash.analyze.HttpClient", forbidden_client)
    with Analyzer(config) as analyzer:
        result = analyzer.analyze(tag(title=name, content=""))
    assert result["publish"] is True
    assert result["state"] == "tagged" and result["category"] == "release"
    assert result["priority"] == "normal" and result["confidence"] == "reported"
    assert result["evidence"] == [name]
    assert "upstream" in result["summary"]
    assert "released" not in result["summary"] and "verified" not in result["summary"]


def test_tag_cache_is_distinct_from_old_llm_decisions_and_model_independent():
    row = {"content_hash": "abc", "payload": json.dumps(tag())}
    assert cache_key(row, {"model": "one"}) == cache_key(row, {"model": "two"})
    assert cache_key(row, {"model": "one"}) == digest(["abc", TAG_NOTICE_VERSION])


def test_tag_notice_preserves_publication_dates_and_escapes_hostile_text(tmp_path):
    payload = '<img src=x onerror="alert(1)">'
    with Analyzer(copy.deepcopy(DEFAULTS)) as analyzer:
        raw = tag(title=payload, content="", source_name="<script>attack()</script>")
        result = analyzer.analyze(raw)
    with Store(tmp_path / "state.db") as store:
        store.ingest(raw, DATE)
        row = store.pending(1, DATE)[0]
        store.finish(row, result, cache_key(row, DEFAULTS["llm"]), DATE)
        story = store.stories(1)[0]
    assert story["published_at"] == raw["published_at"]
    assert story["updated_at"] == raw["updated_at"]
    output = tmp_path / "public"
    output.mkdir()
    render_site(copy.deepcopy(DEFAULTS), [story], [], output)
    page = (output / "index.html").read_text()
    assert "<img src=x onerror=" not in page and "<script>attack()" not in page
    assert "&lt;img" in page and "attack()" not in page


def test_tag_cannot_downgrade_existing_announced_release(tmp_path):
    release_item = tag(
        kind="feed",
        product="network",
        title="Tor 0.4.9.16 released",
        url="https://example.org/tor-0.4.9.16",
        content="Tor 0.4.9.16 released.",
    )
    with Analyzer(copy.deepcopy(DEFAULTS)) as analyzer:
        tag_result = analyzer.analyze(tag())
    release_result = {
        **tag_result,
        "title": "Tor 0.4.9.16 released",
        "state": "released",
    }
    with Store(tmp_path / "state.db") as store:
        store.ingest(release_item, DATE)
        row = store.pending(1, DATE)[0]
        store.finish(row, release_result, "release", DATE)
        later_tag = tag(updated_at=DATE)
        store.ingest(later_tag, DATE)
        row = store.pending(1, DATE)[0]
        store.finish(row, tag_result, "tag", DATE)
        story = store.stories(1)[0]
    assert story["state"] == "released" and story["title"] == release_result["title"]
    assert len(story["sources"]) == 2


def test_tags_have_configurable_queue_floor_below_serious_security(tmp_path):
    assert item_priority(tag()) == 5
    assert item_priority(tag(), 0) == 0
    assert item_priority(tag(), 9) == 9
    incident = tag(
        kind="gitlab_issue",
        title="Directory authority plausibly compromised",
        content="",
        labels=["Security"],
    )
    assert item_priority(incident) > item_priority(tag(), 20)
    announcement = tag(kind="feed", title="Tor 0.4.9.16 released", content="")
    assert item_priority(announcement) == 5
    with Store(tmp_path / "state.db") as store:
        store.ingest(tag(), DATE, tag_priority_score=9)
        assert store.pending(1, DATE)[0]["priority_score"] == 9


def test_healthy_source_is_eligible_two_seconds_early_but_not_far_early():
    settings = DEFAULTS["collection"]
    assert source_due(source(), successful_state(), settings, "2026-11-09T15:35:00Z")
    assert not source_due(
        source(), successful_state(), settings, "2026-11-09T15:34:50Z"
    )
    assert not source_due(
        source(), successful_state(), settings, "2026-11-09T14:35:00Z"
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"error": "HTTP 429", "failures": 2},
        {"error": "GitLab scan catching up", "failures": 0},
        {"error": None, "failures": 1},
        {"scan_upper": DATE, "scan_page": 2},
        {"last_success": None},
    ],
)
def test_failure_and_catching_up_cooldowns_are_never_shortened(changes):
    state = successful_state(**changes)
    assert not source_due(
        source(), state, DEFAULTS["collection"], "2026-11-09T15:35:00Z"
    )
    assert source_due(source(), state, DEFAULTS["collection"], "2026-11-09T15:35:02Z")


def test_zero_tolerance_disables_forgiveness_and_interval_fraction_caps_it():
    settings = {**DEFAULTS["collection"], "healthy_poll_tolerance_seconds": 0}
    assert not source_due(
        source(), successful_state(), settings, "2026-11-09T15:35:00Z"
    )
    settings["healthy_poll_tolerance_seconds"] = 60
    short_source = source(interval_seconds=30)
    assert source_due(
        short_source, successful_state(), settings, "2026-11-09T15:35:00Z"
    )
    assert not source_due(
        short_source, successful_state(), settings, "2026-11-09T15:34:58Z"
    )


def test_late_fetch_records_actual_observation_but_keeps_schedule_anchor(
    tmp_path, monkeypatch
):
    from onionflash import cli

    config = copy.deepcopy(DEFAULTS)
    config["storage"]["database"] = str(tmp_path / "state.db")
    config["storage"]["output_dir"] = str(tmp_path / "public")
    config["sources"] = [source()]
    times = iter([DATE, "2026-11-09T15:30:07Z"])
    monkeypatch.setattr(cli, "now_iso", lambda: next(times, "2026-11-09T15:30:08Z"))
    monkeypatch.setattr(
        cli, "collect_source", lambda *args: {"items": [tag()], "url": source()["url"]}
    )
    monkeypatch.setattr(cli, "build", lambda *args: {"public_changed": False})
    with Store(tmp_path / "state.db") as store:
        cli.run(config, store)
        row = store.db.execute("SELECT first_seen,last_seen FROM items").fetchone()
        state = store.source(source())
    assert row["first_seen"] == row["last_seen"] == "2026-11-09T15:30:07Z"
    assert state["last_success"] == "2026-11-09T15:30:07Z"
    assert state["next_fetch_at"] == after(300, DATE)


def test_inference_outage_does_not_block_a_queued_deterministic_tag(
    tmp_path, monkeypatch
):
    from onionflash import cli

    config = copy.deepcopy(DEFAULTS)
    config["storage"]["database"] = str(tmp_path / "state.db")
    config["sources"] = [source()]
    calls = []

    class UnavailableAnalyzer(Analyzer):
        def analyze(self, item):
            calls.append(item["kind"])
            if item["kind"] != "tag":
                raise AnalysisError("LLM unavailable", retryable=True)
            return super().analyze(item)

    monkeypatch.setattr(cli, "Analyzer", UnavailableAnalyzer)
    monkeypatch.setattr(cli, "now_iso", lambda: DATE)
    monkeypatch.setattr(cli, "build", lambda *args: {"public_changed": False})
    with Store(tmp_path / "state.db") as store:
        store.source(source())
        store.source_success(source(), {"url": source()["url"]}, DATE)
        store.ingest(
            tag(
                kind="gitlab_issue",
                title="Authority plausibly compromised",
                url="https://example.org/security",
            ),
            DATE,
        )
        store.ingest(tag(), DATE)
        result = cli.run(config, store)
        assert store.stories(1)[0]["state"] == "tagged"
    assert calls == ["gitlab_issue", "tag"]
    assert result["analysis_failed"] == 1 and result["analyzed"] == 1


def test_new_settings_and_verified_sources_are_in_example(tmp_path, monkeypatch):
    monkeypatch.setenv("ONIONFLASH_LLM_BASE_URL", "https://model.example/v1")
    example = Path(__file__).parents[1] / "config.example.toml"
    path = tmp_path / "config.toml"
    path.write_text(example.read_text())
    config = load_config(path)
    assert config["collection"]["healthy_poll_tolerance_seconds"] == 5
    assert config["collection"]["tag_priority_score"] == 5
    sources = {s["id"]: s for s in config["sources"]}
    assert sources["tor-browser-security"]["enabled"]
    assert sources["tor-browser-security"]["authority"] == "development"
    assert sources["anti-censorship-team"]["enabled"]
    assert sources["tor-dev"]["enabled"]
    path.write_text(
        example.read_text().replace(
            "healthy_poll_tolerance_seconds = 5", "healthy_poll_tolerance_seconds = 61"
        )
    )
    with pytest.raises(ValueError):
        load_config(path)
