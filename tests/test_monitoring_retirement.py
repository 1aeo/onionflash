"""Retired alert inputs cannot fall through to news; public history survives."""

import json
import sqlite3
from pathlib import Path
import xml.etree.ElementTree as ET

import pytest

from onionflash import cli, editorial
from onionflash.config import load_config
from onionflash.store import Store
from test_core import DATE, item
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


@pytest.mark.parametrize("alert_format", ["consensus", "censorship"])
def test_retired_source_is_disabled_before_fetch_and_old_queue_never_reaches_model(tmp_path, monkeypatch, caplog, capsys, alert_format):
    path = legacy_config(tmp_path, alert_format)
    cfg = load_config(path)
    assert cfg["monitoring"] == {}
    assert cfg["sources"][0]["enabled"] is False
    assert "monitoring alert collection is retired; remove this source" in caplog.text
    monkeypatch.setattr(cli, "collect_source", lambda *_args: pytest.fail("Retired source was fetched"))
    monkeypatch.setattr(cli.Analyzer, "analyze", lambda *_args: pytest.fail("Retired alert reached the writer"))
    monkeypatch.setattr(cli.Reviewer, "review", lambda *_args: pytest.fail("Retired alert reached review"))
    monkeypatch.setattr(cli, "now_iso", lambda: DATE)
    with Store(cfg["storage"]["database"]) as store:
        saved = item(source_id="legacy-alerts", kind="feed", title="Consensus issues")
        store.ingest(saved, DATE)
        report = cli.run(cfg, store)
        assert report["analyzed"] == 0 and report["pending_analysis"] == 0
        assert "alerts" not in report
        assert store.db.execute("SELECT status FROM items").fetchone()[0] == "ignored"
        assert store.db.execute("SELECT COUNT(*) FROM analyses").fetchone()[0] == 0
        assert store.stories() == []
    assert cli.main(["status", "--config", str(path)]) == 0
    assert "monitoring_candidates" not in json.loads(capsys.readouterr().out)
    public = Path(cfg["storage"]["output_dir"])
    assert ET.parse(public / "feed.xml").findall("./channel/item") == []
    assert json.loads((public / "feed.json").read_text())["items"] == []


def test_retiring_a_queued_alert_does_not_overwrite_a_changed_source_row(tmp_path, monkeypatch):
    cfg = load_config(legacy_config(tmp_path, "consensus"))
    monkeypatch.setattr(cli, "now_iso", lambda: DATE)
    monkeypatch.setattr(cli.Analyzer, "analyze", lambda *_args: pytest.fail("Retired alert reached analysis"))
    with Store(cfg["storage"]["database"]) as store:
        source = item(source_id="legacy-alerts", kind="feed")
        store.ingest(source, DATE)
        original = store.pending
        def changed_pending(*args):
            rows = original(*args)
            store.ingest({**source, "content": "A changed source revision."}, DATE)
            return rows
        monkeypatch.setattr(store, "pending", changed_pending)
        cli.run(cfg, store)
        row = store.db.execute("SELECT status,payload FROM items").fetchone()
        assert row["status"] == "pending"
        assert json.loads(row["payload"])["content"] == "A changed source revision."


def test_unused_monitor_identity_does_not_disable_an_ordinary_source(tmp_path):
    path = legacy_config(tmp_path, "")
    assert load_config(path)["sources"][0]["enabled"] is True


def test_unknown_alert_format_is_rejected_instead_of_becoming_news(tmp_path):
    with pytest.raises(ValueError, match="Unsupported alert format"):
        load_config(legacy_config(tmp_path, "unknown-alert-format"))


@pytest.mark.parametrize("action", ["correct", "retract"])
def test_retiring_private_tables_preserves_legacy_articles_and_editorial_history(tmp_path, monkeypatch, action):
    cfg = settings(tmp_path)
    value = story(1, confidence="observed-anomaly", state="developing", category="directory-authority")
    with Store(cfg["storage"]["database"]) as store:
        put(store.db, value)
        cli.build(cfg, store)
        arguments = {"reason": "Reviewed the fixture's source context.",
                     "expect_hash": editorial.show(store.db, value["id"])["hash"], "observed": "2026-11-09T12:00:00Z"}
        if action == "correct":
            editorial.correct(store.db, value["id"], {"why_it_matters": "The source reports an observation."}, **arguments)
        else:
            editorial.retract(store.db, value["id"], **arguments)
        cli.build(cfg, store)
        accepted = store.db.execute("SELECT payload FROM stories").fetchone()[0]
        revisions = editorial.history(store.db, value["id"])
        control = editorial.show(store.db, value["id"])
        # These are the private schemas created by the removed subsystem.
        store.db.executescript('''
            CREATE TABLE monitoring_groups (
                group_key TEXT PRIMARY KEY, monitor_id TEXT NOT NULL, format TEXT NOT NULL,
                target TEXT NOT NULL, kind TEXT NOT NULL, state TEXT NOT NULL,
                episode_start TEXT NOT NULL, highwater TEXT NOT NULL, conditions TEXT NOT NULL, story_id TEXT);
            CREATE TABLE monitoring_observations (
                group_key TEXT NOT NULL REFERENCES monitoring_groups(group_key), stamp TEXT NOT NULL,
                condition TEXT NOT NULL, state TEXT NOT NULL, url TEXT NOT NULL, title TEXT NOT NULL,
                PRIMARY KEY(group_key,stamp,condition,state));
        ''')
        with store.db:
            store.db.execute("INSERT INTO monitoring_groups VALUES('group','monitor','consensus','authority','document','firing',?,?,'[]',?)", (DATE, DATE, value["id"]))
            store.db.execute("INSERT INTO monitoring_observations VALUES('group',?,'authority-missing','firing','https://example.org/report','Consensus issues')", (DATE,))
    public = Path(cfg["storage"]["output_dir"])
    files = [public / f"news/{value['id']}/index.html", public / f"news/{value['id']}/story.json", public / "feed.xml", public / "feed.json"]
    before = [path.read_bytes() for path in files]
    connect = sqlite3.connect
    def foreign_keys_enabled(*args, **kwargs):
        db = connect(*args, **kwargs)
        db.execute("PRAGMA foreign_keys=ON")
        return db
    monkeypatch.setattr("onionflash.store.sqlite3.connect", foreign_keys_enabled)
    for _ in range(2):  # Upgrade cleanup is idempotent.
        with Store(cfg["storage"]["database"]) as store:
            assert store.db.execute("PRAGMA foreign_keys").fetchone()[0] == 1
            assert not store.db.execute("SELECT 1 FROM sqlite_master WHERE name IN ('monitoring_groups','monitoring_observations')").fetchone()
            assert store.db.execute("PRAGMA foreign_key_check").fetchall() == []
            assert store.db.execute("SELECT payload FROM stories").fetchone()[0] == accepted
            assert editorial.history(store.db, value["id"]) == revisions
            assert editorial.show(store.db, value["id"]) == control
            assert not cli.build(cfg, store)["public_changed"]
        assert [path.read_bytes() for path in files] == before
    guid = ET.parse(public / "feed.xml").findtext("./channel/item/guid")
    assert guid.endswith(f"/news/{value['id']}/")
