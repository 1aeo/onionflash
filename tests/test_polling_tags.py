"""Regression checks for release coverage and scheduler-boundary behavior."""

from approval_helpers import ApprovingReviewer, finish_reviewed
import copy
from pathlib import Path

import pytest

from onionflash.analyze import SCHEMA, AnalysisError, Analyzer, cache_key, tag_notice, validate_analysis
from onionflash.config import DEFAULTS, load_config
from onionflash.render import render_site
from onionflash.store import Store, after, item_priority, source_due


DATE = "2026-11-09T15:30:00Z"


def tag(**overrides):
    return {
        "id": "tag-id",
        "source_id": "tor-tags",
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


@pytest.mark.parametrize("product", SCHEMA["properties"]["products"]["items"]["enum"])
def test_literal_tag_notice_still_passes_the_model_output_checks(product):
    # tag_notice skips validation, so this catches drift from SCHEMA or its enums.
    item = tag(product=product)
    notice = tag_notice(item)
    assert validate_analysis(copy.deepcopy(notice), item) == notice


def test_tag_notice_preserves_publication_dates_and_escapes_hostile_text(tmp_path):
    payload = '<img src=x onerror="alert(1)">'
    with Analyzer(copy.deepcopy(DEFAULTS)) as analyzer:
        raw = tag(title=payload, content="")
        result = analyzer.analyze(raw)
    with Store(tmp_path / "state.db") as store:
        store.ingest(raw, DATE)
        row = store.pending(1, DATE)[0]
        finish_reviewed(store, row, result, cache_key(row, DEFAULTS["llm"]), DATE)
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
        finish_reviewed(store, row, release_result, "release", DATE)
        later_tag = tag(updated_at=DATE)
        store.ingest(later_tag, DATE)
        row = store.pending(1, DATE)[0]
        finish_reviewed(store, row, tag_result, "tag", DATE)
        story = store.stories(1)[0]
    assert story["state"] == "released" and story["title"] == release_result["title"]
    assert len(story["sources"]) == 2


def test_tags_have_a_fixed_queue_floor_below_serious_security(tmp_path):
    assert item_priority(tag()) == 5
    incident = tag(
        kind="gitlab_issue",
        title="Directory authority plausibly compromised",
        content="",
        labels=["Security"],
    )
    assert item_priority(incident) > item_priority(tag())
    announcement = tag(kind="feed", title="Tor 0.4.9.16 released", content="")
    assert item_priority(announcement) == 5
    with Store(tmp_path / "state.db") as store:
        store.ingest(tag(), DATE)
        assert store.pending(1, DATE)[0]["priority_score"] == 5


def test_a_success_is_rescheduled_a_few_seconds_early_and_never_more_than_a_tenth(tmp_path):
    with Store(tmp_path / "state.db") as store:
        for interval, expected in [(300, "2026-11-09T15:34:55Z"), (30, "2026-11-09T15:30:27Z")]:
            stream = source(id=f"s{interval}", interval_seconds=interval)
            store.source(stream)
            store.source_success(stream, {"url": stream["url"]}, "2026-11-09T15:30:00Z")
            due = store.source(stream)["next_fetch_at"]
            assert due == expected
            assert not source_due({"next_fetch_at": due}, after(-1, due))
            assert source_due({"next_fetch_at": due}, due)


def test_failure_and_catching_up_cooldowns_are_never_shortened(tmp_path):
    stream = source(interval_seconds=300)
    with Store(tmp_path / "state.db") as store:
        store.source(stream)
        store.source_failure(stream, "GitLab scan catching up", DEFAULTS["collection"], "2026-11-09T15:30:00Z",
                             catching_up=True)
        assert store.source(stream)["next_fetch_at"] == "2026-11-09T15:35:00Z"
        store.source_failure(stream, "HTTP 429", DEFAULTS["collection"], "2026-11-09T15:30:00Z")
        backoff = DEFAULTS["collection"]["failure_backoff_base_seconds"]
        assert store.source(stream)["next_fetch_at"] == after(backoff, "2026-11-09T15:30:00Z")


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
    monkeypatch.setattr(cli, "build", lambda *args: {"published_stories": 0, "stories_skipped": 0})
    with Store(tmp_path / "state.db") as store:
        cli.run(config, store)
        row = store.db.execute("SELECT first_seen,last_seen FROM items").fetchone()
        state = store.source(source())
    assert row["first_seen"] == row["last_seen"] == "2026-11-09T15:30:07Z"
    assert state["last_success"] == "2026-11-09T15:30:07Z"
    assert state["next_fetch_at"] == after(300 - 5, DATE)  # anchored to the run start, minus the tolerance


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
    monkeypatch.setattr(cli, "Reviewer", ApprovingReviewer)
    monkeypatch.setattr(cli, "now_iso", lambda: DATE)
    monkeypatch.setattr(cli, "build", lambda *args: {"published_stories": 0, "stories_skipped": 0})
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
    sources = {s["id"]: s for s in config["sources"]}
    assert sources["tor-browser-security"]["enabled"]
    assert sources["tor-browser-security"]["authority"] == "development"
    assert sources["anti-censorship-team"]["enabled"]
    assert sources["tor-dev"]["enabled"]
