"""Retired alert inputs cannot fall through to news; public history survives."""

import json
from pathlib import Path
import xml.etree.ElementTree as ET

import pytest

from onionflash import cli
from onionflash.config import load_config
from onionflash.store import Store
from test_publication import put, settings, story


def legacy_config(tmp_path, alert_format):
    path = tmp_path / "config.toml"
    path.write_text(f'''[storage]
database="state.sqlite3"
output_dir="public"
[monitoring]
min_reports=2
min_span_seconds=3600
window_seconds=172800
[[sources]]
id="legacy-alerts"
url="https://example.org/alerts.xml"
kind="feed"
authority="telemetry"
enabled=true
alert_format="{alert_format}"
monitor_id="old-monitor"
''')
    return path


@pytest.mark.parametrize("alert_format", ["consensus", "censorship", "unknown-alert-format"])
def test_retired_source_is_disabled_before_fetch(tmp_path, monkeypatch, caplog, capsys, alert_format):
    """Legacy alert configuration loads disabled, so it is never fetched or published."""
    path = legacy_config(tmp_path, alert_format)
    cfg = load_config(path)
    assert cfg["monitoring"] == {}
    assert cfg["sources"][0]["enabled"] is False
    assert "monitoring alert collection is retired; remove this source" in caplog.text
    monkeypatch.setattr(cli, "collect_source", lambda *_args: pytest.fail("Retired source was fetched"))
    with Store(cfg["storage"]["database"]) as store:
        assert "alerts" not in cli.run(cfg, store)
    assert cli.main(["status", "--config", str(path)]) == 0
    assert "monitoring_candidates" not in json.loads(capsys.readouterr().out)
    public = Path(cfg["storage"]["output_dir"])
    assert ET.parse(public / "feed.xml").findall("./channel/item") == []
    assert json.loads((public / "feed.json").read_text())["items"] == []


def test_unused_monitor_identity_does_not_disable_an_ordinary_source(tmp_path):
    path = legacy_config(tmp_path, "")
    assert load_config(path)["sources"][0]["enabled"] is True


def test_old_databases_keep_the_unused_monitoring_tables(tmp_path):
    """The tables that earlier releases wrote stay as they were, and those releases' stories still build."""
    cfg = settings(tmp_path)
    value = story(1, confidence="observed-anomaly", state="developing", category="directory-authority")
    with Store(cfg["storage"]["database"]) as store:
        put(store.db, value)
        for table in ("monitoring_groups", "monitoring_observations"):
            store.db.execute(f"CREATE TABLE {table} (group_key TEXT, story_id TEXT)")
            store.db.execute(f"INSERT INTO {table} VALUES('group',?)", (value["id"],))
        store.db.commit()
    with Store(cfg["storage"]["database"]) as store:
        for table in ("monitoring_groups", "monitoring_observations"):
            assert [tuple(row) for row in store.db.execute(f"SELECT * FROM {table}")] == [("group", value["id"])]
        cli.build(cfg, store)
    published = json.loads((Path(cfg["storage"]["output_dir"]) / "news" / value["id"] / "story.json").read_text())
    assert published["id"] == value["id"] and published["confidence"] == "observed-anomaly"
