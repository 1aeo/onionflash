"""Tests for fixed-text DocTor consensus-health incident summaries and host attachment."""

from __future__ import annotations

import contextlib
import json
import random
import xml.etree.ElementTree as ET
from datetime import timedelta
from pathlib import Path

import pytest

from approval_helpers import finish_reviewed
from onionflash import candidate, cli, collect, decisions, doctor, editorial, render
from onionflash.analyze import AnalysisError
from onionflash.config import load_config
from onionflash.store import Store
from onionflash.transport import Response
from onionflash.util import digest, format_utc, parse_utc
from test_core import analysis, item as make_item

FIXTURES = Path(__file__).parent / "fixtures" / "doctor"
LIST_URL = "https://lists.torproject.org/mailman3/hyperkitty/list/tor-consensus-health@lists.torproject.org/"
FEED_URL = LIST_URL + "feed/"


def load_jsonl(name: str) -> list[dict]:
    return [json.loads(line) for line in (FIXTURES / name).read_text(encoding="utf-8").splitlines() if line.strip()]


def make_config(tmp_path: Path, *, publish: bool = True, enabled: bool = True) -> tuple[Path, dict]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "config.toml"
    path.write_text(
        f'''[storage]
database = "state.sqlite3"
output_dir = "public"
[llm]
base_url = "https://llm.example/v1"
model = "test-model"
[[sources]]
id = "tor-consensus-health"
name = "Tor Project Consensus Health Alerts"
website_url = "{LIST_URL}"
url = "{FEED_URL}"
kind = "feed"
product = "network"
authority = "telemetry"
alert_format = "consensus"
publish = {"true" if publish else "false"}
enabled = {"true" if enabled else "false"}
''',
        encoding="utf-8",
    )
    return path, load_config(path)


def report_item(slug: str, stamp: str, lines: list[str], *, title: str = "[tor-consensus-health] Consensus issues", url: str | None = None) -> dict:
    return {
        "source_id": "tor-consensus-health",
        "url": url or f"{LIST_URL}message/{slug}/",
        "title": title,
        "content": "\n".join(lines),
        "published_at": stamp,
        "updated_at": stamp,
        "kind": "feed",
        "product": "network",
        "authority": "telemetry",
        "labels": [],
        "upstream_state": "",
    }


def decision_rows(store: Store) -> list[dict]:
    return [
        {**dict(row), "detail": json.loads(row["detail_json"])}
        for row in store.db.execute("SELECT * FROM decision_log ORDER BY id")
    ]


class FakeLinker:
    def __init__(self, *answers):
        self.answers = list(answers)
        self.calls = 0
        self.seen: list[tuple[str, str, str]] = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def confirm(self, incident: dict, host: dict) -> bool:
        self.calls += 1
        self.seen.append((incident["rule"], incident["subject"], host["title"]))
        if not self.answers:
            return False
        nxt = self.answers.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        return bool(nxt)


def test_feed_collection_parses_reports_skips_undated_and_logs_non_reports_once(tmp_path):
    _, cfg = make_config(tmp_path)
    source = cfg["sources"][0]
    xml_bytes = (FIXTURES / "feed.xml").read_bytes()

    class DummyHttp:
        def request(self, method, url, headers=None):
            return Response(200, xml_bytes, {}, url)

    collected = collect.collect_source(DummyHttp(), source, {}, cfg["collection"], "2024-01-10T07:00:00Z")
    # The undated entry is skipped and counted rather than stamped with the poll start time.
    assert collected["skipped"] == 1
    assert len(collected["items"]) == 4
    assert all("JAN24FEED_UNDATED_01" not in entry["url"] for entry in collected["items"])

    by_slug = {entry["url"].rstrip("/").rsplit("/", 1)[-1]: entry for entry in collected["items"]}
    parsed_main = doctor.parse(by_slug["JAN24FEED_REPORT_01"], source)
    assert parsed_main is not None
    # Descriptor lines are not authority-missing listings, unknown nicknames are ignored,
    # and WARNING stale lines (<= 3 authorities) do not count as a Rule B miss.
    assert parsed_main["missing"] == ["bastet"]
    assert parsed_main["stale"] is False
    assert parsed_main["srv"] is True
    assert parsed_main["ran"] is True

    parsed_norun = doctor.parse(by_slug["JAN24FEED_NORUN_01"], source)
    assert parsed_norun is not None
    assert parsed_norun["ran"] is False and parsed_norun["missing"] == []

    unprefixed = report_item("JAN24_UNPREFIXED", "2024-01-10T02:05:00Z", ["NOTICE: Valid prefix", "Human commentary line"])
    off_list = report_item("JAN24_OFFLIST", "2024-01-10T01:05:00Z",
                           ["NOTICE: The following directory authorities are not reporting bandwidth scanner results: faravahar"],
                           url="https://example.org/other/message/JAN24_OFFLIST/")

    with Store(cfg["storage"]["database"]) as store:
        added, rejected = doctor.ingest(
            store.db, source, [*collected["items"], unprefixed, off_list], "2024-01-10T07:00:00Z"
        )
        assert (added, rejected) == (2, 4)
        # Re-ingesting the same feed and non-reports neither duplicates reports nor re-logs not_report.
        added2, rejected2 = doctor.ingest(
            store.db, source, [*collected["items"], unprefixed, off_list], "2024-01-10T07:05:00Z"
        )
        assert (added2, rejected2) == (0, 4)
        assert store.db.execute("SELECT COUNT(*) FROM network_reports").fetchone()[0] == 2
        assert store.db.execute("SELECT COUNT(*) FROM items").fetchone()[0] == 0
        not_reports = [row for row in decision_rows(store) if row["code"] == "skipped.network.not_report"]
        assert len(not_reports) == 4


def test_truncated_report_keeps_listings_without_counting_omissions(tmp_path):
    _, cfg = make_config(tmp_path)
    source = cfg["sources"][0]
    start = parse_utc("2024-01-02T00:05:00Z")
    items = [
        report_item(
            f"JAN24_TRUNC_A_{hour:02d}",
            format_utc(start + timedelta(hours=hour * 12)),
            ["WARNING: The following authorities are missing from the consensus: bastet",
             "NOTICE: The following directory authorities are not reporting bandwidth scanner results: faravahar"],
        )
        for hour in range(5)  # 0h, 12h, 24h, 36h, 48h -> opens at 48h
    ]
    # Build a >= 20,000-character report 25h later that omits bastet (while listing gabelmoo) and cuts off mid-line.
    filler = [
        f"NOTICE: Relay vote flag diff line {idx:04d} with extra padding characters to exceed twenty thousand bytes"
        for idx in range(260)
    ]
    long_body = "\n".join(["WARNING: The following authorities are missing from the consensus: gabelmoo", *filler])[:20000]
    assert len(long_body) == 20000
    truncated_item = {
        **report_item("JAN24_TRUNC_CUT", format_utc(start + timedelta(hours=74)), []),
        "content": long_body,
    }
    parsed_trunc = doctor.parse(truncated_item, source, limit=20000)
    assert parsed_trunc is not None
    assert parsed_trunc["missing"] == ["gabelmoo"]
    assert parsed_trunc["ran"] is False

    inc_list, _ = doctor.incidents([doctor.parse(it, source) for it in [*items, truncated_item]])
    bastet = [inc for inc in inc_list if inc["rule"] == "A" and inc["subject"] == "bastet"]
    assert len(bastet) == 1 and bastet[0]["closed"] is None


def test_family_a_positives_negatives_milestones_closing_and_no_resolved_wording(tmp_path):
    _, cfg = make_config(tmp_path, publish=True)
    source = cfg["sources"][0]
    items = load_jsonl("jan2024_authority_cases.jsonl")

    with Store(cfg["storage"]["database"]) as store:
        doctor.evaluate(cfg, store, source, FakeLinker(), "2024-01-10T00:00:00Z")
        added, rejected = doctor.ingest(store.db, source, items, "2024-01-10T00:05:00Z")
        assert (added, rejected) == (len(items), 0)
        res = doctor.evaluate(cfg, store, source, FakeLinker(), "2024-01-25T00:00:00Z")
        assert res["stories_written"] == 2
        # Rerun is completely idempotent: no new stories, updates, or below-threshold log duplicates.
        res2 = doctor.evaluate(cfg, store, source, FakeLinker(), "2024-01-25T00:05:00Z")
        assert res2["stories_written"] == 0 and res2["updates_written"] == 0

        stories = {json.loads(r["payload"])["title"]: json.loads(r["payload"])
                   for r in store.db.execute("SELECT payload FROM stories")}
        assert set(stories) == {
            "Directory authority gabelmoo missing from the Tor consensus",
            "Directory authority longclaw missing from the Tor consensus",
        }
        gab = stories["Directory authority gabelmoo missing from the Tor consensus"]
        assert gab["published_at"] == "2024-01-17T03:09:00Z"
        assert gab["state"] == "no-longer-listed"
        assert gab["confidence"] == "observed-anomaly"
        assert gab["category"] == "directory-authority"
        assert len(gab["updates"]) == 2
        assert "Still listed as missing from the consensus after 7 days" in gab["updates"][0]["text"]
        assert gab["updates"][0]["sources"][0]["url"].endswith("/JAN24AUTH_GAB_WEEK7/")
        assert "No longer listed as missing" in gab["updates"][1]["text"]
        assert "returned or was retired" in gab["updates"][1]["text"]
        # First omitting report (JAN24AUTH_GAB_OMIT1) is cited first; JAN24AUTH_GAB_NORUN did not close it early.
        assert gab["updates"][1]["at"] == "2024-01-24T05:05:00Z"
        assert gab["updates"][1]["sources"][0]["url"].endswith("/JAN24AUTH_GAB_OMIT1/")

        lc = stories["Directory authority longclaw missing from the Tor consensus"]
        assert lc["published_at"] == "2024-01-20T21:07:00Z"
        assert lc["state"] == "no-longer-listed"
        assert lc["updates"][0]["sources"][0]["url"].endswith("/JAN24AUTH_LC_OMIT1/")

        # Negatives (dizum 11h blip, dannenberg 2-omit flap, and dannenberg pre-gap + post-gap) logged once as below_threshold.
        below_rows = [r for r in decision_rows(store) if r["code"] == "skipped.network.below_threshold"]
        assert len(below_rows) == 4
        subjects = {r["detail"]["episode_subject"] for r in below_rows}
        assert "dizum" in subjects and "moria1" not in subjects

        cli.build(cfg, store)
        for path in Path(cfg["storage"]["output_dir"]).rglob("*"):
            if path.is_file() and path.suffix in {".html", ".xml", ".json"}:
                assert "resolved" not in path.read_text(encoding="utf-8").lower()


def test_family_b_missed_consensuses_wording_updates_gaps_and_recurrence(tmp_path):
    _, cfg = make_config(tmp_path, publish=True)
    source = cfg["sources"][0]
    items = load_jsonl("jan2024_stale_and_srv.jsonl")
    parsed = [doctor.parse(it, source) for it in items]
    inc_list, below_list = doctor.incidents(parsed)

    b_stories = [inc for inc in inc_list if inc["rule"] == "B"]
    assert len(b_stories) == 1
    b = b_stories[0]
    assert b["first"]["stamp"] == "2024-01-17T12:05:17Z"
    assert b["opened"]["stamp"] == "2024-01-18T00:05:36Z"
    summary = doctor._story_summary("B", b["open_vars"])
    assert "in 6 separate hours" in summary
    assert [ev["kind"] for ev in b["events"]] == ["B:more", "B:close", "B:reopen", "B:close"]
    assert "6 more separate hours, 12 since 2024-01-17 12:05 UTC" in doctor._event_text(b["events"][0])
    assert "17 separate hours in all" in doctor._event_text(b["events"][1])
    assert "Reported again:" in doctor._event_text(b["events"][2])
    assert "in 6 separate hours" in doctor._event_text(b["events"][2])
    assert "9 separate hours in all" in doctor._event_text(b["events"][3])

    # Verify a pre-window miss (first != w0) names the episode's first miss and 5 misses >24h before stay below threshold.
    stale_line = (
        "ERROR: The consensuses published by the following directory authorities are more than one hour old"
        " and therefore not fresh anymore: bastet, dannenberg, dizum, faravahar"
    )
    ok_line = "NOTICE: The following directory authorities are not reporting bandwidth scanner results: faravahar"
    pre_gap = [
        report_item(f"JAN24_B5_{i}", format_utc(parse_utc("2024-01-01T00:07:00Z") + timedelta(hours=i * 4)), [stale_line])
        for i in range(5)
    ]
    early_miss = [report_item("JAN24_B_FIRST", "2024-01-03T20:07:00Z", [stale_line])]
    mid_miss = [report_item("JAN24_B_MID", "2024-01-04T09:07:00Z", [stale_line])]
    burst = [
        report_item(f"JAN24_B_BURST_{i}", format_utc(parse_utc("2024-01-05T01:07:00Z") + timedelta(hours=i * 2)), [stale_line])
        for i in range(6)
    ]
    quiet = [report_item("JAN24_B_CLOSE", "2024-01-06T12:07:00Z", [ok_line])]
    custom_inc, custom_below = doctor.incidents([doctor.parse(it, source) for it in [*pre_gap, *early_miss, *mid_miss, *burst, *quiet]])
    assert len(custom_below) == 1 and custom_below[0]["rule"] == "B" and custom_below[0]["value"] == 5
    assert len(custom_inc) == 1
    pre_summary = doctor._story_summary("B", custom_inc[0]["open_vars"])
    assert "in 6 separate hours" in pre_summary and "2024-01-03 20:07 UTC" in pre_summary
    assert "8 separate hours in all" in doctor._event_text(custom_inc[0]["events"][-1])


def test_family_c_recurrence_resets_state_to_developing_and_checks_notes(tmp_path):
    _, cfg = make_config(tmp_path, publish=True)
    source = cfg["sources"][0]
    all_items = load_jsonl("jan2024_srv_recurrence.jsonl")
    first_wave = [it for it in all_items if it["published_at"] <= "2024-01-04T02:00:00Z"]
    reopen_wave = [it for it in all_items if "2024-01-04T02:00:00Z" < it["published_at"] <= "2024-01-07T06:00:00Z"]
    final_wave = [it for it in all_items if it["published_at"] > "2024-01-07T06:00:00Z"]

    with Store(cfg["storage"]["database"]) as store:
        doctor.evaluate(cfg, store, source, FakeLinker(), "2024-01-02T00:00:00Z")
        doctor.ingest(store.db, source, first_wave, "2024-01-04T02:05:00Z")
        doctor.evaluate(cfg, store, source, FakeLinker(), "2024-01-04T02:05:00Z")
        [row1] = store.stories()
        assert row1["state"] == "no-longer-listed"

        # Recurrence within 7 days reopens the SAME story and resets state back to developing!
        doctor.ingest(store.db, source, reopen_wave, "2024-01-07T06:05:00Z")
        doctor.evaluate(cfg, store, source, FakeLinker(), "2024-01-07T06:05:00Z")
        [row2] = store.stories()
        assert row2["id"] == row1["id"]
        assert row2["state"] == "developing"
        assert any("missing again" in u["text"] for u in row2["updates"])

        # Closing the recurrence sets state back to no-longer-listed.
        doctor.ingest(store.db, source, final_wave, "2024-01-09T00:00:00Z")
        doctor.evaluate(cfg, store, source, FakeLinker(), "2024-01-09T00:00:00Z")
        [row3] = store.stories()
        assert row3["id"] == row1["id"]
        assert row3["state"] == "no-longer-listed"
        assert len(row3["updates"]) == 3

    # Verify Rule C negatives (< 6 consecutive reports, or > 2h gap) open nothing.
    srv_line = "ERROR: Consensus is missing a current shared random value (shared-rand-current-value)"
    ok_line = "NOTICE: The following directory authorities are not reporting bandwidth scanner results: faravahar"
    short_run = [
        report_item(f"JAN24_C_SHORT_{i}", format_utc(parse_utc("2024-01-10T00:05:00Z") + timedelta(hours=i)), [srv_line])
        for i in range(5)
    ] + [report_item("JAN24_C_SHORT_END", "2024-01-10T05:05:00Z", [ok_line])]
    gapped_run = [
        report_item(f"JAN24_C_GAP_{i}", format_utc(parse_utc("2024-01-11T00:05:00Z") + timedelta(hours=i if i < 3 else i + 3)), [srv_line])
        for i in range(6)
    ] + [report_item("JAN24_C_GAP_END", "2024-01-11T10:05:00Z", [ok_line])]
    neg_inc, neg_below = doctor.incidents([doctor.parse(it, source) for it in [*short_run, *gapped_run]])
    assert neg_inc == [] and len(neg_below) == 3

    # Verify shipped note wording invariants.
    assert "about half were listed for an hour or less" in doctor.NOTES["A"]
    assert "most involved one or two such hours" in doctor.NOTES["B"]
    assert {k: doctor.format_note(k, doctor.ARCHIVE_STATS[k]) for k in ("A", "B", "C")} == doctor.NOTES


def test_no_120_day_prune_order_independence_and_late_older_report_pinning(tmp_path):
    _, cfg = make_config(tmp_path, publish=True)
    source = cfg["sources"][0]

    # 1. Order independence across shuffled ingestion.
    items = load_jsonl("jan2024_authority_cases.jsonl")
    shuffled = list(items)
    random.Random(42).shuffle(shuffled)
    _, cfg_b = make_config(tmp_path / "b", publish=True)
    with Store(cfg["storage"]["database"]) as store_a, Store(cfg_b["storage"]["database"]) as store_b:
        doctor.evaluate(cfg, store_a, source, FakeLinker(), "2024-01-10T00:00:00Z")
        doctor.evaluate(cfg_b, store_b, source, FakeLinker(), "2024-01-10T00:00:00Z")
        doctor.ingest(store_a.db, source, items, "2024-01-10T00:05:00Z")
        doctor.ingest(store_b.db, source, shuffled, "2024-01-10T00:05:00Z")
        doctor.evaluate(cfg, store_a, source, FakeLinker(), "2024-01-25T00:00:00Z")
        doctor.evaluate(cfg_b, store_b, source, FakeLinker(), "2024-01-25T00:00:00Z")
        assert store_a.stories() == store_b.stories()

    # 2. No 120-day prune & late older report after publication keeps pinned story_id, first, opened, and milestones.
    _, cfg_pin = make_config(tmp_path / "pin", publish=True)
    t0 = parse_utc("2024-01-02T11:00:00Z")
    initial_reports = [
        report_item(
            f"JAN24_PIN_{day:03d}_{hour:02d}",
            format_utc(t0 + timedelta(days=day, hours=hour)),
            ["WARNING: The following authorities are missing from the consensus: bastet",
             "NOTICE: The following directory authorities are not reporting bandwidth scanner results: faravahar"],
        )
        for day in range(9)
        for hour in (0, 12)
    ]
    far_future = report_item(
        "JAN24_PIN_DAY190",
        format_utc(t0 + timedelta(days=190)),
        ["NOTICE: The following directory authorities are not reporting bandwidth scanner results: faravahar"],
    )
    late_older = report_item(
        "JAN24_PIN_LATE_OLDER",
        "2024-01-02T10:00:00Z",  # 1 hour BEFORE initial first report!
        ["WARNING: The following authorities are missing from the consensus: bastet",
         "NOTICE: The following directory authorities are not reporting bandwidth scanner results: faravahar"],
    )
    with Store(cfg_pin["storage"]["database"]) as store:
        doctor.ingest(store.db, source, initial_reports, "2024-01-02T00:00:00Z")
        doctor.evaluate(cfg_pin, store, source, FakeLinker(), "2024-01-11T12:00:00Z")
        [before] = store.stories()
        assert len(before["updates"]) == 1  # 7-day milestone

        # Ingesting a report 190 days later prunes NOTHING, and ingesting a late older report shifts nothing!
        doctor.ingest(store.db, source, [late_older, far_future], "2024-07-15T00:00:00Z")
        assert store.db.execute("SELECT COUNT(*) FROM network_reports").fetchone()[0] == len(initial_reports) + 2
        doctor.evaluate(cfg_pin, store, source, FakeLinker(), "2024-07-15T00:00:00Z")
        [after_late] = store.stories()
        assert after_late["id"] == before["id"]
        assert after_late["published_at"] == before["published_at"]
        assert after_late["summary"] == before["summary"]
        assert after_late["state"] == "no-longer-listed"
        # Only the closing update was appended; the 7-day milestone was NOT duplicated!
        assert len(after_late["updates"]) == 2
        assert sum("7 days" in u["text"] for u in after_late["updates"]) == 1


def test_authorities_change_while_incident_is_open(tmp_path, monkeypatch):
    _, cfg = make_config(tmp_path, publish=True)
    source = cfg["sources"][0]
    t0 = parse_utc("2024-01-05T00:00:00Z")
    open_items = [
        report_item(
            f"JAN24_AUTHCHG_{i}",
            format_utc(t0 + timedelta(hours=i * 12)),
            ["WARNING: The following authorities are missing from the consensus: bastet, newauth",
             "NOTICE: The following directory authorities are not reporting bandwidth scanner results: faravahar"],
        )
        for i in range(5)
    ]
    close_items = [
        report_item(
            f"JAN24_AUTHCHG_CLOSE_{i}",
            format_utc(t0 + timedelta(hours=60 + i * 16)),
            ["NOTICE: The following directory authorities are not reporting bandwidth scanner results: faravahar"],
        )
        for i in range(2)
    ]
    with Store(cfg["storage"]["database"]) as store:
        doctor.ingest(store.db, source, open_items, "2024-01-05T00:00:00Z")
        doctor.evaluate(cfg, store, source, FakeLinker(), "2024-01-07T01:00:00Z")
        assert [s["title"] for s in store.stories()] == ["Directory authority bastet missing from the Tor consensus"]

        # Simulate AUTHORITIES growing (append-only) and even an open pinned subject missing from the constant:
        # existing open bastet still closes cleanly, and newauth opens from already-stored raw_missing!
        monkeypatch.setattr(doctor, "AUTHORITIES", tuple(a for a in doctor.AUTHORITIES if a != "bastet") + ("newauth",))
        doctor.ingest(store.db, source, close_items, "2024-01-08T18:00:00Z")
        doctor.evaluate(cfg, store, source, FakeLinker(), "2024-01-08T18:00:00Z")
        by_title = {s["title"]: s for s in store.stories()}
        assert by_title["Directory authority bastet missing from the Tor consensus"]["state"] == "no-longer-listed"
        assert by_title["Directory authority newauth missing from the Tor consensus"]["state"] == "no-longer-listed"


def test_dry_run_status_preview_publish_since_and_on_off_on_transitions(tmp_path, monkeypatch, capsys):
    path, cfg = make_config(tmp_path, publish=False)
    srv_line = "ERROR: Consensus is missing a current shared random value"
    ok_line = "NOTICE: The following directory authorities are not reporting bandwidth scanner results: faravahar"

    # Incident 1 (Jan 3): opens and closes during initial dry run.
    inc1 = [
        report_item(f"JAN24_DRY_1_{h:02d}", format_utc(parse_utc("2024-01-03T00:05:00Z") + timedelta(hours=h)), [srv_line])
        for h in range(6)
    ] + [report_item("JAN24_DRY_1_CLOSE", "2024-01-03T06:05:00Z", [ok_line])]
    # Incident 2 (Jan 15, >7d later so separate story): still open when publish turns True!
    inc2_open = [
        report_item(f"JAN24_DRY_2_{h:02d}", format_utc(parse_utc("2024-01-15T00:05:00Z") + timedelta(hours=h)), [srv_line])
        for h in range(6)
    ]

    batches = [[*inc1, *inc2_open], []]
    monkeypatch.setattr(cli, "now_iso", lambda: "2024-01-15T06:00:00Z")
    monkeypatch.setattr(
        cli,
        "collect_source",
        lambda *_a, **_kw: {"items": batches.pop(0) if batches else [], "skipped": 0, "url": FEED_URL},
    )
    monkeypatch.setattr(cli, "Analyzer", lambda *_a, **_kw: contextlib.nullcontext(type("W", (), {"calls": 0})()))
    monkeypatch.setattr(cli, "Reviewer", lambda *_a, **_kw: contextlib.nullcontext(type("R", (), {"calls": 0})()))

    with Store(cfg["storage"]["database"]) as store:
        rep1 = cli.run(cfg, store)
        assert rep1["network"]["dry_run"] is True and rep1["published_stories"] == 0
        assert store.stories() == []
        # Second dry-run pass does not duplicate held.network.dry_run rows.
        store.db.execute("UPDATE source_state SET next_fetch_at=NULL")
        store.db.commit()
        cli.run(cfg, store)
        dry_rows = [r for r in decision_rows(store) if r["code"] == "held.network.dry_run"]
        assert len(dry_rows) == 2

    assert cli.main(["status", "--config", str(path)]) == 0
    status_payload = json.loads(capsys.readouterr().out)["network_health"]
    assert status_payload["mode"] == "dry_run" and status_payload["reports"] == len(inc1) + len(inc2_open)
    assert len(status_payload["incidents"]) == 2
    assert status_payload["incidents"][0]["title"] == "Tor consensus published without a shared random value"

    # Turn publish ON at 2024-01-15T06:30:00Z: closed inc1 is skipped (before_enable), open inc2 publishes!
    _, cfg_on = make_config(tmp_path, publish=True)
    monkeypatch.setattr(cli, "now_iso", lambda: "2024-01-15T06:30:00Z")
    with Store(cfg_on["storage"]["database"]) as store:
        cli.run(cfg_on, store)
        published = store.stories()
        assert len(published) == 1
        assert published[0]["published_at"] == "2024-01-15T05:05:00Z"
        assert published[0]["state"] == "developing"
        before_rows = [r for r in decision_rows(store) if r["code"] == "skipped.network.before_enable"]
        assert len(before_rows) == 1

        # Check rendered HTML, RSS, and JSON Feed for fixed-wording note and About this alert.
        public_dir = Path(cfg_on["storage"]["output_dir"])
        article = (public_dir / "news" / published[0]["id"] / "index.html").read_text(encoding="utf-8")
        assert "<h2>About this alert</h2>" in article
        assert "This alert uses fixed wording; only the names, times and counts come from the linked DocTor reports." in article
        assert "This is an AI-assisted summary" not in article
        rss_desc = ET.parse(public_dir / "feed.xml").findtext("./channel/item/description")
        assert "<strong>About this alert:</strong>" in rss_desc
        json_feed = json.loads((public_dir / "feed.json").read_text(encoding="utf-8"))
        assert "About this alert: " in json_feed["items"][0]["content_text"]

    # Turn publish OFF while inc3 (Jan 25) opens & closes AND inc2 closes, then turn publish ON again at Jan 26!
    inc2_close = [report_item("JAN24_DRY_2_CLOSE", "2024-01-15T07:05:00Z", [ok_line])]
    inc3_closed = [
        report_item(f"JAN24_DRY_3_{h:02d}", format_utc(parse_utc("2024-01-25T00:05:00Z") + timedelta(hours=h)), [srv_line])
        for h in range(6)
    ] + [report_item("JAN24_DRY_3_CLOSE", "2024-01-25T06:05:00Z", [ok_line])]
    _, cfg_off = make_config(tmp_path, publish=False)
    with Store(cfg_off["storage"]["database"]) as store:
        doctor.ingest(store.db, cfg_off["sources"][0], [*inc2_close, *inc3_closed], "2024-01-25T07:00:00Z")
        doctor.evaluate(cfg_off, store, cfg_off["sources"][0], FakeLinker(), "2024-01-25T07:00:00Z")
        assert len(store.stories()) == 1 and store.stories()[0]["state"] == "developing"

    with Store(cfg_on["storage"]["database"]) as store:
        doctor.evaluate(cfg_on, store, cfg_on["sources"][0], FakeLinker(), "2024-01-26T00:00:00Z")
        # inc3 (closed while off) was NOT backfilled; already-published inc2 updated to no-longer-listed!
        assert len(store.stories()) == 1
        assert store.stories()[0]["state"] == "no-longer-listed"
        assert sum(r["code"] == "skipped.network.before_enable" for r in decision_rows(store)) == 2


def test_preset_publish_since_populates_reports_without_publishing_closed_archive(tmp_path):
    _, cfg = make_config(tmp_path, publish=True)
    source = cfg["sources"][0]
    items = load_jsonl("jan2024_srv_recurrence.jsonl")
    with Store(cfg["storage"]["database"]) as store:
        store.set_meta(publish_since="2024-01-20T00:00:00Z")
        doctor.ingest(store.db, source, items, "2024-01-20T01:00:00Z")
        res = doctor.evaluate(cfg, store, source, FakeLinker(), "2024-01-20T01:00:00Z")
        assert store.db.execute("SELECT COUNT(*) FROM network_reports").fetchone()[0] == len(items)
        assert res["stories_written"] == 0 and store.stories() == []
        assert any(r["code"] == "skipped.network.before_enable" for r in decision_rows(store))


def seed_host(store: Store, *, url: str, title: str, summary: str, published_at: str = "2024-01-14T12:00:00Z",
              category: str = "directory-authority", confidence: str = "confirmed", state: str = "developing") -> str:
    incoming = make_item(url=url, title=title, content=summary + " Exact supporting sentence from the upstream source.",
                         published_at=published_at, updated_at=published_at, authority="official")
    store.ingest(incoming, published_at)
    row = store.pending(1, published_at)[0]
    draft = analysis(
        title=title,
        summary=summary,
        why_it_matters="Operators track directory authority voting keys.",
        category=category,
        priority="high",
        confidence=confidence,
        state=state,
        products=["tor", "network"],
        tags=[category],
        evidence=[summary],
    )
    finish_reviewed(store, row, draft, "seed-" + row["id"], published_at)
    return store.db.execute("SELECT story_id FROM items WHERE id=?", (row["id"],)).fetchone()[0]


def bastet_incident_items(start_iso: str = "2024-01-15T00:05:00Z", *, close: bool = False) -> list[dict]:
    t0 = parse_utc(start_iso)
    items = [
        report_item(
            f"JAN24_ATTACH_BAS_{i}",
            format_utc(t0 + timedelta(hours=i * 12)),
            ["WARNING: The following authorities are missing from the consensus: bastet",
             "NOTICE: The following directory authorities are not reporting bandwidth scanner results: faravahar"],
        )
        for i in range(5)
    ]
    if close:
        items.extend([
            report_item(
                f"JAN24_ATTACH_BAS_CLOSE_{i}",
                format_utc(t0 + timedelta(hours=60 + i * 16)),
                ["NOTICE: The following directory authorities are not reporting bandwidth scanner results: faravahar"],
            )
            for i in range(2)
        ])
    return items


def test_attach_yes_preserves_host_labels_caches_answer_and_survives_later_model_update(tmp_path):
    _, cfg_dry = make_config(tmp_path, publish=False)
    _, cfg_pub = make_config(tmp_path, publish=True)

    with Store(cfg_dry["storage"]["database"]) as store:
        host_id = seed_host(
            store,
            url="https://example.org/bastet-key-removal",
            title="Directory authority bastet removed after reported key compromise",
            summary="Maintainers announced removing directory authority bastet after its operator reported a compromise.",
        )
        before_host = render._prepare_story(json.loads(
            store.db.execute("SELECT payload FROM stories WHERE id=?", (host_id,)).fetchone()[0]
        ))
        open_items = bastet_incident_items(close=False)
        close_only = bastet_incident_items(close=True)[len(open_items):]
        doctor.ingest(store.db, cfg_dry["sources"][0], open_items, "2024-01-17T12:00:00Z")

        # Dry run asks the linker ONCE and persists the answer in network_links.
        linker = FakeLinker(True)
        doctor.evaluate(cfg_dry, store, cfg_dry["sources"][0], linker, "2024-01-17T12:00:00Z")
        assert linker.calls == 1
        assert len(store.stories()) == 1  # no standalone story

        # Turning publish=True reuses the stored (incident_key, host_id, host_hash, DOCTOR_LINK_VERSION) answer with 0 calls!
        linker2 = FakeLinker(pytest.fail)
        doctor.evaluate(cfg_pub, store, cfg_pub["sources"][0], linker2, "2024-01-17T12:05:00Z")
        assert linker2.calls == 0
        assert len(store.stories()) == 1

        # Closing the incident appends the closing update onto the host without changing host state to no-longer-listed!
        doctor.ingest(store.db, cfg_pub["sources"][0], close_only, "2024-01-18T12:00:00Z")
        doctor.evaluate(cfg_pub, store, cfg_pub["sources"][0], linker2, "2024-01-18T12:00:00Z")
        assert linker2.calls == 0
        assert len(store.stories()) == 1

        after_raw = json.loads(store.db.execute("SELECT payload FROM stories WHERE id=?", (host_id,)).fetchone()[0])
        after_host = render._prepare_story(after_raw)
        # Every label and text field of the host story is 100% unchanged — even after the DocTor incident closed!
        for label_field in ("title", "summary", "why_it_matters", "category", "priority", "confidence", "state", "products", "tags"):
            assert after_host[label_field] == before_host[label_field]
        assert len(after_host["updates"]) == 2
        assert after_host["alert_notes"] == [doctor.NOTES["A"]]
        assert len(after_host["sources"]) >= 2

        # A later model update to the host story preserves network, alert_notes, and updates!
        follow = make_item(
            url="https://example.org/bastet-key-removal",
            title="Directory authority bastet removed after reported key compromise",
            content="Maintainers announced removing directory authority bastet after its operator reported a compromise. Release merged.",
            published_at="2024-01-14T12:00:00Z",
            updated_at="2024-01-19T00:00:00Z",
            authority="official",
        )
        store.ingest(follow, "2024-01-19T00:00:00Z")
        follow_row = store.pending(1, "2024-01-19T00:00:00Z")[0]
        prepared = candidate.prepare(
            store.db,
            follow_row,
            {
                "publish": True,
                "update": "A maintenance release completed removing directory authority bastet.",
                "confidence": "confirmed",
                "state": "released",
                "evidence": ["Maintainers announced removing directory authority bastet after its operator reported a compromise."],
            },
            "2024-01-19T00:00:00Z",
        )
        assert prepared["candidate"]["alert_notes"] == [doctor.NOTES["A"]]
        assert len(prepared["candidate"]["updates"]) == 3
        assert prepared["candidate"]["updates"][:2] == after_host["updates"]
        assert prepared["payload"]["network"] == after_raw["network"]


def test_attach_no_locked_host_candidate_cap_and_transient_link_failure(tmp_path):
    # 1. Attach answer False -> standalone story, and model item cannot overwrite network-health headline.
    _, cfg = make_config(tmp_path / "no", publish=True)
    with Store(cfg["storage"]["database"]) as store:
        host_id = seed_host(
            store,
            url="https://example.org/bastet-flags",
            title="Directory authority bastet reports fewer Guard flags in vote",
            summary="Analysts noted directory authority bastet assigned fewer Guard flags than the consensus.",
        )
        doctor.ingest(store.db, cfg["sources"][0], bastet_incident_items(), "2024-01-18T00:00:00Z")
        linker = FakeLinker(False)
        doctor.evaluate(cfg, store, cfg["sources"][0], linker, "2024-01-18T00:00:00Z")
        assert linker.calls == 1
        assert len(store.stories()) == 2
        standalone = [s for s in store.stories() if s["id"] != host_id][0]
        assert standalone["origin"] == "network-health"

        # Verify a model-written item mapped to a network-health story cannot take over its fixed headline or labels.
        mapped = make_item(
            url="https://example.org/follow-note",
            title="Unrelated headline attempt",
            content="Operators discussed a relay flag observation in detail on the mailing list.",
            published_at="2024-01-18T01:00:00Z",
            updated_at="2024-01-18T01:00:00Z",
        )
        store.ingest(mapped, "2024-01-18T01:00:00Z")
        store.db.execute("UPDATE items SET story_id=? WHERE url=?", (standalone["id"], mapped["url"]))
        store.db.commit()
        pending_row = store.pending(1, "2024-01-18T01:00:00Z")[0]
        with pytest.raises(candidate.StaleCandidate):
            candidate.prepare(
                store.db,
                pending_row,
                analysis(
                    title="Model headline trying to overwrite fixed network alert",
                    summary="Operators discussed a relay flag observation in detail on the mailing list.",
                    evidence=["Operators discussed a relay flag observation in detail on the mailing list."],
                ),
                "2024-01-18T01:00:00Z",
            )
        env = candidate.prepare(
            store.db,
            pending_row,
            {
                "publish": True,
                "update": "Operators discussed a relay flag observation in detail on the mailing list.",
                "confidence": "confirmed",
                "state": "released",
                "evidence": ["Operators discussed a relay flag observation in detail on the mailing list."],
            },
            "2024-01-18T01:00:00Z",
        )
        assert env["candidate"]["title"] == standalone["title"]
        assert env["candidate"]["confidence"] == "observed-anomaly"
        assert env["candidate"]["state"] == standalone["state"]
        assert env["candidate"]["origin"] == "network-health"

    # 2. Locked and retracted hosts are excluded with 0 model calls, logged once, and alert publishes standalone.
    _, cfg_lock = make_config(tmp_path / "locked", publish=True)
    with Store(cfg_lock["storage"]["database"]) as store:
        locked_id = seed_host(
            store,
            url="https://example.org/bastet-locked",
            title="Directory authority bastet maintenance notice",
            summary="Operators reported directory authority bastet maintenance.",
        )
        editorial.correct(
            store.db,
            locked_id,
            {"why_it_matters": "Operator-locked context."},
            reason="Clarified context.",
            expect_hash=editorial.show(store.db, locked_id)["hash"],
            observed="2024-01-14T13:00:00Z",
        )
        retracted_id = seed_host(
            store,
            url="https://example.org/bastet-retracted",
            title="Withdrawn bastet report",
            summary="Withdrawn report naming directory authority bastet.",
            published_at="2024-01-14T14:00:00Z",
        )
        editorial.retract(
            store.db,
            retracted_id,
            reason="Withdrawn.",
            expect_hash=editorial.show(store.db, retracted_id)["hash"],
            observed="2024-01-14T15:00:00Z",
        )
        doctor.ingest(store.db, cfg_lock["sources"][0], bastet_incident_items(), "2024-01-18T00:00:00Z")
        linker = FakeLinker(pytest.fail)
        doctor.evaluate(cfg_lock, store, cfg_lock["sources"][0], linker, "2024-01-18T00:00:00Z")
        doctor.evaluate(cfg_lock, store, cfg_lock["sources"][0], linker, "2024-01-18T00:05:00Z")
        assert linker.calls == 0
        assert len(store.stories()) == 3  # standalone published without touching locked or retracted hosts
        host_locked_rows = [r for r in decision_rows(store) if r["code"] == "skipped.network.host_locked"]
        assert len(host_locked_rows) == 1  # retracted host does not even mention bastet in its tombstone; locked host logged once!

    # 3. Transient LLM failure holds as held.network.link_pending, counts endpoint_failures, and succeeds next run!
    _, cfg_fail = make_config(tmp_path / "fail", publish=True)
    with Store(cfg_fail["storage"]["database"]) as store:
        host_id = seed_host(
            store,
            url="https://example.org/bastet-outage",
            title="Directory authority bastet offline during hardware replacement",
            summary="Operators reported directory authority bastet is offline for hardware replacement.",
        )
        # Also verify B/C candidate match cap at 3 when many consensus stories exist.
        for idx in range(5):
            seed_host(
                store,
                url=f"https://example.org/consensus-{idx}",
                title=f"Directory authority consensus voting issue {idx}",
                summary=f"Directory authorities experienced consensus voting delays in report {idx}.",
                published_at=f"2024-01-14T0{idx}:00:00Z",
            )
        b_dummy = {
            "key": "bcap",
            "rule": "B",
            "subject": "network",
            "first": {"stamp": "2024-01-15T00:00:00Z", "url": FEED_URL},
            "opened": {"stamp": "2024-01-15T12:00:00Z", "url": FEED_URL},
            "last": {"stamp": "2024-01-15T12:00:00Z", "url": FEED_URL},
            "closed": None,
        }
        assert len(doctor.candidate_hosts(store.db, b_dummy, log_locked=False)) == 3

        doctor.ingest(store.db, cfg_fail["sources"][0], bastet_incident_items(), "2024-01-18T00:00:00Z")
        failing = FakeLinker(AnalysisError("LLM request failed (HTTP 503)", retryable=True))
        res_fail = doctor.evaluate(cfg_fail, store, cfg_fail["sources"][0], failing, "2024-01-18T00:00:00Z")
        assert res_fail["endpoint_failures"] == 1 and res_fail["held"] == 1
        assert res_fail["stories_written"] == 0 and res_fail["updates_written"] == 0
        assert any(r["code"] == "held.network.link_pending" for r in decision_rows(store))

        # Next run succeeds and attaches cleanly!
        recover = FakeLinker(True)
        res_ok = doctor.evaluate(cfg_fail, store, cfg_fail["sources"][0], recover, "2024-01-18T00:05:00Z")
        assert recover.calls == 1 and res_ok["updates_written"] == 1
        host_after = render._prepare_story(json.loads(
            store.db.execute("SELECT payload FROM stories WHERE id=?", (host_id,)).fetchone()[0]
        ))
        assert len(host_after["updates"]) == 1


def test_unexpected_exception_in_evaluate_does_not_stop_run(tmp_path, monkeypatch):
    _, cfg = make_config(tmp_path, publish=True)
    cfg["sources"].append({
        "id": "tor-tags",
        "name": "Tor Tags",
        "kind": "tag",
        "url": "https://example.org/tags.atom",
        "fallback_urls": [],
        "product": "tor",
        "authority": "official",
        "enabled": False,
        "interval_seconds": 300,
        "max_pages": 1,
        "max_items": 10,
    })
    monkeypatch.setattr(cli, "collect_source", lambda *_a, **_kw: {"items": [], "skipped": 0, "url": FEED_URL})
    monkeypatch.setattr(doctor, "evaluate", lambda *_a, **_kw: (_ for _ in ()).throw(RuntimeError("unexpected failure")))
    monkeypatch.setattr(cli, "Analyzer", lambda *_a, **_kw: contextlib.nullcontext(type("W", (), {"calls": 0})()))
    monkeypatch.setattr(cli, "Reviewer", lambda *_a, **_kw: contextlib.nullcontext(type("R", (), {"calls": 0})()))

    with Store(cfg["storage"]["database"]) as store:
        report = cli.run(cfg, store)
        assert "Unexpected RuntimeError at" in report["network"]["error"]
        assert report["no_browser_js_ready"] is True


def test_multiple_enabled_consensus_sources_rejected_and_rule_c_counts_distinct_hours(tmp_path):
    path, cfg = make_config(tmp_path, publish=True, enabled=True)
    second_disabled = {**cfg["sources"][0], "id": "consensus-mirror", "url": "https://example.org/consensus.xml", "enabled": False}
    extra_toml = (
        '\n[[sources]]\nid = "consensus-mirror"\nname = "Mirror"\n'
        f'website_url = "{LIST_URL}"\nurl = "https://example.org/consensus.xml"\n'
        'kind = "feed"\nproduct = "network"\nauthority = "telemetry"\n'
        'alert_format = "consensus"\npublish = false\nenabled = false\n'
    )
    path.write_text(path.read_text(encoding="utf-8") + extra_toml, encoding="utf-8")
    loaded_ok = load_config(path)
    assert len(loaded_ok["sources"]) == 2

    path.write_text(path.read_text(encoding="utf-8").replace("enabled = false", "enabled = true"), encoding="utf-8")
    with pytest.raises(ValueError, match="At most one enabled consensus alert source is supported"):
        load_config(path)

    cfg_two = {**cfg, "sources": [cfg["sources"][0], {**second_disabled, "enabled": True}]}
    with Store(cfg["storage"]["database"]) as store:
        with pytest.raises(ValueError, match="At most one enabled consensus alert source is supported"):
            cli.run(cfg_two, store)

    # Six SRV reports in the same UTC hour (00:05..00:10) count as one reporting hour, not six.
    srv_line = "NOTICE: Consensus is missing a current shared random value"
    same_hour = [
        report_item(f"srv-same-{i}", f"2024-01-20T00:{5 + i:02d}:00Z", [srv_line])
        for i in range(6)
    ]
    with Store(tmp_path / "srv_same.sqlite3") as store:
        doctor.ingest(store.db, cfg["sources"][0], same_hour, "2024-01-20T01:00:00Z")
        res = doctor.evaluate(cfg, store, cfg["sources"][0], FakeLinker(), "2024-01-20T01:00:00Z")
        assert res["stories_written"] == 0

    six_hours = [
        report_item(f"srv-hr-{i}", f"2024-01-20T{i:02d}:05:00Z", [srv_line])
        for i in range(6)
    ]
    with Store(tmp_path / "srv_hours.sqlite3") as store:
        doctor.ingest(store.db, cfg["sources"][0], six_hours, "2024-01-20T06:00:00Z")
        res_open = doctor.evaluate(cfg, store, cfg["sources"][0], FakeLinker(), "2024-01-20T06:00:00Z")
        assert res_open["stories_written"] == 1


def test_host_updates_drive_matching_invalidate_negative_cache_and_guards_hold(tmp_path):
    # 1) Host story with generic opening prose that names the authority only in a later update:
    #    first run has no authority mention so standalone is avoided only once update arrives;
    #    we also seed a negative cache row before the update to prove _host_hash invalidates it.
    _, cfg = make_config(tmp_path / "host_upd", publish=True)
    with Store(cfg["storage"]["database"]) as store:
        host_id = seed_host(
            store,
            url="https://gitlab.torproject.org/tpo/network-health/analysis/-/issues/990",
            title="Directory consensus voting instability under investigation",
            summary="Operators are investigating intermittent voting instability across the directory.",
            published_at="2024-01-15T06:00:00Z",
        )
        raw_before = json.loads(store.db.execute("SELECT payload FROM stories WHERE id=?", (host_id,)).fetchone()[0])
        pub_before = render._prepare_story(raw_before)

        doctor.ingest(store.db, cfg["sources"][0], bastet_incident_items(close=False), "2024-01-17T12:00:00Z")
        # Before the host story mentions bastet, candidate_hosts is empty.
        replayed = doctor._replay(doctor.load_reports(store.db))[0][0]
        assert doctor.candidate_hosts(store.db, replayed, log_locked=False) == []
        old_hash = doctor._host_hash(pub_before, replayed)
        with store.db:
            store.db.execute(
                "INSERT INTO network_links(incident_key,host_id,host_hash,version,same_incident,decided_at) VALUES(?,?,?,?,0,?)",
                (replayed["key"], host_id, old_hash, doctor.DOCTOR_LINK_VERSION, "2024-01-17T11:30:00Z"),
            )

        # Append an update naming bastet within the incident window: _matches_host matches,
        # _host_hash changes (bypassing the cached 0), and LinkChecker sees updates!
        raw_after = {
            **raw_before,
            "updated_at": "2024-01-16T18:00:00Z",
            "updates": [{
                "at": "2024-01-16T18:00:00Z",
                "text": "Operators traced the missing votes to directory authority bastet.",
                "sources": raw_before["sources"],
            }],
        }
        with store.db:
            store.db.execute(
                "UPDATE stories SET updated_at=?,payload=? WHERE id=?",
                ("2024-01-16T18:00:00Z", json.dumps(raw_after), host_id),
            )
        seen_payloads = []

        class InspectingLinker(doctor.LinkChecker):
            def __init__(self):
                self.calls = 0

            def complete(self, prompt, payload, schema, name):
                self.calls += 1
                seen_payloads.append(payload)
                return {"reason": "Same bastet outage.", "same_incident": True}

        linker = InspectingLinker()
        res_attach = doctor.evaluate(cfg, store, cfg["sources"][0], linker, "2024-01-17T12:00:00Z")
        assert linker.calls == 1 and res_attach["updates_written"] == 1 and res_attach["stories_written"] == 0
        assert seen_payloads[0]["existing_story"]["updates"] == [
            {"at": "2024-01-16T18:00:00Z", "text": "Operators traced the missing votes to directory authority bastet."}
        ]

    # 2) Existing site with early general publish_since (Jan 1) excludes incidents that closed
    #    during dry-run (Jan 4) when network publication is first enabled on Jan 15.
    _, cfg_dry = make_config(tmp_path / "cut", publish=False)
    cfg_pub = {**cfg_dry, "sources": [{**cfg_dry["sources"][0], "publish": True}]}
    with Store(cfg_dry["storage"]["database"]) as store:
        store.set_meta(publish_since="2024-01-01T00:00:00Z")
        closed_dry = bastet_incident_items(start_iso="2024-01-01T06:05:00Z", close=True)
        doctor.ingest(store.db, cfg_dry["sources"][0], closed_dry, "2024-01-05T06:00:00Z")
        assert doctor.evaluate(cfg_dry, store, cfg_dry["sources"][0], FakeLinker(), "2024-01-05T06:00:00Z")["stories_written"] == 0

        res_enable = doctor.evaluate(cfg_pub, store, cfg_pub["sources"][0], FakeLinker(), "2024-01-15T06:30:00Z")
        assert res_enable["stories_written"] == 0
        assert any(r["code"] == "skipped.network.before_enable" for r in decision_rows(store))

    # 3) Standalone write respects a locked editorial_controls row even if the stories row was deleted.
    _, cfg_lock = make_config(tmp_path / "standalone_lock", publish=True)
    with Store(cfg_lock["storage"]["database"]) as store:
        open_items = bastet_incident_items(start_iso="2024-01-19T00:05:00Z", close=False)
        doctor.ingest(store.db, cfg_lock["sources"][0], open_items, "2024-01-22T00:00:00Z")
        assert doctor.evaluate(cfg_lock, store, cfg_lock["sources"][0], FakeLinker(), "2024-01-22T00:00:00Z")["stories_written"] == 1
        standalone_id = store.stories()[0]["id"]
        editorial.correct(
            store.db, standalone_id, {"why_it_matters": "Operator-pinned alert context."},
            reason="Pin alert context", expect_hash=editorial.show(store.db, standalone_id)["hash"], observed="2024-01-22T00:05:00Z",
        )
        with store.db:
            store.db.execute("DELETE FROM stories WHERE id=?", (standalone_id,))
        res_locked = doctor.evaluate(cfg_lock, store, cfg_lock["sources"][0], FakeLinker(), "2024-01-22T00:10:00Z")
        assert res_locked["stories_written"] == 0
        assert store.db.execute("SELECT COUNT(*) FROM stories WHERE id=?", (standalone_id,)).fetchone()[0] == 0
