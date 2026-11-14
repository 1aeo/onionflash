"""Tests for fixed-text DocTor consensus-health incident summaries, host attachment, and retired alerts."""

from __future__ import annotations

import json
import random
import xml.etree.ElementTree as ET
from datetime import timedelta
from pathlib import Path

import pytest

from helpers import (
    ApprovingReviewer, FakeClient, Writer, analysis, finish_reviewed, item as make_item,
    make_story, patch_cli_pipeline, pub_settings, put_story, update_analysis,
)
from onionflash import candidate, cli, collect, decisions, doctor, editorial, publication, render, source_packet
from onionflash.analyze import AnalysisError
from onionflash.config import load_config
from onionflash.store import Store
from onionflash.transport import Response
from onionflash.util import digest, format_utc, parse_utc

FIXTURES = Path(__file__).parent / "fixtures" / "doctor"
LIST_URL = "https://lists.torproject.org/mailman3/hyperkitty/list/tor-consensus-health@lists.torproject.org/"
FEED_URL = LIST_URL + "feed/"
OK_LINE = "NOTICE: The following directory authorities are not reporting bandwidth scanner results: faravahar"
SRV_ERR = "ERROR: Consensus is missing a current shared random value"
BASE_CONSENSUS_TOML = (
    '[storage]\ndatabase="state.sqlite3"\noutput_dir="public"\n[[sources]]\n'
    f'id="consensus-health-alerts"\nurl="{FEED_URL}"\nwebsite_url="{LIST_URL}"\n'
    'kind="feed"\nauthority="telemetry"\nenabled=true\nalert_format="consensus"\n'
)


def load_jsonl(name: str) -> list[dict]:
    return [json.loads(line) for line in (FIXTURES / name).read_text(encoding="utf-8").splitlines() if line.strip()]


def make_config(tmp_path: Path, *, publish: bool = True, enabled: bool = True) -> tuple[Path, dict]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "config.toml"
    path.write_text(
        '[storage]\ndatabase = "state.sqlite3"\noutput_dir = "public"\n[llm]\nbase_url = "https://llm.example/v1"\nmodel = "test-model"\n'
        f'[[sources]]\nid = "tor-consensus-health"\nname = "Tor Project Consensus Health Alerts"\nwebsite_url = "{LIST_URL}"\nurl = "{FEED_URL}"\n'
        f'kind = "feed"\nproduct = "network"\nauthority = "telemetry"\nalert_format = "consensus"\n'
        f'publish = {"true" if publish else "false"}\nenabled = {"true" if enabled else "false"}\n',
        encoding="utf-8",
    )
    return path, load_config(path)


def report_item(slug: str, stamp: str, lines: list[str], *, title: str = "[tor-consensus-health] Consensus issues", url: str | None = None) -> dict:
    return {"source_id": "tor-consensus-health", "url": url or f"{LIST_URL}message/{slug}/", "title": title,
            "content": "\n".join(lines), "published_at": stamp, "updated_at": stamp, "kind": "feed",
            "product": "network", "authority": "telemetry", "labels": [], "upstream_state": ""}


def decision_rows(store: Store) -> list[dict]:
    return [{**dict(r), "detail": json.loads(r["detail_json"])} for r in store.db.execute("SELECT * FROM decision_log ORDER BY id")]


class FakeLinker:
    def __init__(self, *answers):
        self.answers, self.calls, self.seen = list(answers), 0, []

    def __enter__(self): return self
    def __exit__(self, *args): pass

    def confirm(self, incident: dict, host: dict) -> bool:
        self.calls += 1
        self.seen.append((incident["rule"], incident["subject"], host["title"]))
        if not self.answers:
            return False
        nxt = self.answers.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        return bool(nxt)


def seed_host(store: Store, *, url: str, title: str, summary: str, published_at: str = "2024-01-14T12:00:00Z",
              category: str = "directory-authority", confidence: str = "confirmed", state: str = "developing") -> str:
    incoming = make_item(url=url, title=title, content=summary + " Exact supporting sentence from the upstream source.",
                         published_at=published_at, updated_at=published_at, authority="official")
    store.ingest(incoming, published_at)
    row = next(r for r in store.pending(10, published_at) if r["id"] == incoming["id"])
    draft = analysis(title=title, summary=summary, why_it_matters="Operators track directory authority voting keys.",
                     category=category, priority="high", confidence=confidence, state=state,
                     products=["tor", "network"], tags=[category], evidence=[summary])
    finish_reviewed(store, row, draft, "seed-" + row["id"], published_at)
    return store.db.execute("SELECT story_id FROM items WHERE id=?", (row["id"],)).fetchone()[0]


def bastet_incident_items(start_iso: str = "2024-01-15T00:05:00Z", *, close: bool = False) -> list[dict]:
    t0 = parse_utc(start_iso)
    missing = ["WARNING: The following authorities are missing from the consensus: bastet", OK_LINE]
    items = [report_item(f"JAN24_ATTACH_BAS_{i}", format_utc(t0 + timedelta(hours=i * 12)), missing) for i in range(5)]
    if close:
        items += [report_item(f"JAN24_ATTACH_BAS_CLOSE_{i}", format_utc(t0 + timedelta(hours=60 + i * 16)), [OK_LINE]) for i in range(2)]
    return items


def test_feed_collection_parses_reports_skips_undated_and_logs_non_reports_once(tmp_path):
    _, cfg = make_config(tmp_path)
    source = cfg["sources"][0]
    collected = collect.collect_source(FakeClient([Response(200, (FIXTURES / "feed.xml").read_bytes(), {}, FEED_URL)]),
                                       source, {}, cfg["collection"], "2024-01-10T07:00:00Z")
    assert collected["skipped"] == 1 and len(collected["items"]) == 4
    assert all("JAN24FEED_UNDATED_01" not in entry["url"] for entry in collected["items"])

    by_slug = {entry["url"].rstrip("/").rsplit("/", 1)[-1]: entry for entry in collected["items"]}
    parsed_main = doctor.parse(by_slug["JAN24FEED_REPORT_01"], source)
    assert parsed_main is not None and (parsed_main["missing"], parsed_main["stale"], parsed_main["srv"], parsed_main["ran"]) == (["bastet"], False, True, True)
    parsed_norun = doctor.parse(by_slug["JAN24FEED_NORUN_01"], source)
    assert parsed_norun is not None and parsed_norun["ran"] is False and parsed_norun["missing"] == []

    unprefixed = report_item("JAN24_UNPREFIXED", "2024-01-10T02:05:00Z", ["NOTICE: Valid prefix", "Human commentary line"])
    off_list = report_item("JAN24_OFFLIST", "2024-01-10T01:05:00Z", [OK_LINE], url="https://example.org/other/message/JAN24_OFFLIST/")
    batch = [*collected["items"], unprefixed, off_list]
    with Store(cfg["storage"]["database"]) as store:
        assert doctor.ingest(store.db, source, batch, "2024-01-10T07:00:00Z") == (2, 4)
        assert doctor.ingest(store.db, source, batch, "2024-01-10T07:05:00Z") == (0, 4)
        assert store.db.execute("SELECT COUNT(*) FROM network_reports").fetchone()[0] == 2
        assert store.db.execute("SELECT COUNT(*) FROM items").fetchone()[0] == 0
        assert sum(r["code"] == "skipped.network.not_report" for r in decision_rows(store)) == 4


def test_truncated_report_keeps_listings_without_counting_omissions(tmp_path):
    _, cfg = make_config(tmp_path)
    source, start = cfg["sources"][0], parse_utc("2024-01-02T00:05:00Z")
    lines = ["WARNING: The following authorities are missing from the consensus: bastet", OK_LINE]
    items = [report_item(f"JAN24_TRUNC_A_{h:02d}", format_utc(start + timedelta(hours=h * 12)), lines) for h in range(5)]
    filler = [f"NOTICE: Relay vote flag diff line {i:04d} with extra padding characters to exceed twenty thousand bytes" for i in range(260)]
    long_body = "\n".join(["WARNING: The following authorities are missing from the consensus: gabelmoo", *filler])[:20000]
    assert len(long_body) == 20000
    truncated_item = {**report_item("JAN24_TRUNC_CUT", format_utc(start + timedelta(hours=74)), []), "content": long_body}
    parsed_trunc = doctor.parse(truncated_item, source, limit=20000)
    assert parsed_trunc is not None and parsed_trunc["missing"] == ["gabelmoo"] and parsed_trunc["ran"] is False
    inc_list, _ = doctor.incidents([doctor.parse(it, source) for it in [*items, truncated_item]])
    bastet = [inc for inc in inc_list if inc["rule"] == "A" and inc["subject"] == "bastet"]
    assert len(bastet) == 1 and bastet[0]["closed"] is None


def test_family_a_positives_negatives_milestones_closing_and_no_resolved_wording(tmp_path):
    _, cfg = make_config(tmp_path, publish=True)
    source, items = cfg["sources"][0], load_jsonl("jan2024_authority_cases.jsonl")
    with Store(cfg["storage"]["database"]) as store:
        doctor.evaluate(cfg, store, source, FakeLinker(), "2024-01-10T00:00:00Z")
        assert doctor.ingest(store.db, source, items, "2024-01-10T00:05:00Z") == (len(items), 0)
        assert doctor.evaluate(cfg, store, source, FakeLinker(), "2024-01-25T00:00:00Z")["stories_written"] == 2
        res2 = doctor.evaluate(cfg, store, source, FakeLinker(), "2024-01-25T00:05:00Z")
        assert res2["stories_written"] == 0 and res2["updates_written"] == 0

        stories = {json.loads(r["payload"])["title"]: json.loads(r["payload"]) for r in store.db.execute("SELECT payload FROM stories")}
        assert set(stories) == {"Directory authority gabelmoo missing from the Tor consensus", "Directory authority longclaw missing from the Tor consensus"}
        gab = stories["Directory authority gabelmoo missing from the Tor consensus"]
        assert (gab["published_at"], gab["state"], gab["confidence"], gab["category"]) == (
            "2024-01-17T03:09:00Z", "no-longer-listed", "observed-anomaly", "directory-authority")
        assert len(gab["updates"]) == 2 and "Still listed as missing from the consensus after 7 days" in gab["updates"][0]["text"]
        assert gab["updates"][0]["sources"][0]["url"].endswith("/JAN24AUTH_GAB_WEEK7/")
        assert "No longer listed as missing" in gab["updates"][1]["text"] and "returned or was retired" in gab["updates"][1]["text"]
        assert gab["updates"][1]["at"] == "2024-01-24T05:05:00Z" and gab["updates"][1]["sources"][0]["url"].endswith("/JAN24AUTH_GAB_OMIT1/")

        lc = stories["Directory authority longclaw missing from the Tor consensus"]
        assert lc["published_at"] == "2024-01-20T21:07:00Z" and lc["state"] == "no-longer-listed"
        assert lc["updates"][0]["sources"][0]["url"].endswith("/JAN24AUTH_LC_OMIT1/")

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
    [b] = [inc for inc in doctor.incidents([doctor.parse(it, source) for it in load_jsonl("jan2024_stale_and_srv.jsonl")])[0] if inc["rule"] == "B"]
    assert b["first"]["stamp"] == "2024-01-17T12:05:17Z" and b["opened"]["stamp"] == "2024-01-18T00:05:36Z"
    assert "in 6 separate hours" in doctor._story_summary("B", b["open_vars"])
    assert [ev["kind"] for ev in b["events"]] == ["B:more", "B:close", "B:reopen", "B:close"]
    assert "6 more separate hours, 12 since 2024-01-17 12:05 UTC" in doctor._event_text(b["events"][0])
    assert "17 separate hours in all" in doctor._event_text(b["events"][1])
    assert "Reported again:" in doctor._event_text(b["events"][2]) and "in 6 separate hours" in doctor._event_text(b["events"][2])
    assert "9 separate hours in all" in doctor._event_text(b["events"][3])

    stale_line = ("ERROR: The consensuses published by the following directory authorities are more than one hour old"
                  " and therefore not fresh anymore: bastet, dannenberg, dizum, faravahar")
    pre_gap = [report_item(f"JAN24_B5_{i}", format_utc(parse_utc("2024-01-01T00:07:00Z") + timedelta(hours=i * 4)), [stale_line]) for i in range(5)]
    early_miss = [report_item("JAN24_B_FIRST", "2024-01-03T20:07:00Z", [stale_line]), report_item("JAN24_B_MID", "2024-01-04T09:07:00Z", [stale_line])]
    burst = [report_item(f"JAN24_B_BURST_{i}", format_utc(parse_utc("2024-01-05T01:07:00Z") + timedelta(hours=i * 2)), [stale_line]) for i in range(6)]
    quiet = [report_item("JAN24_B_CLOSE", "2024-01-06T12:07:00Z", [OK_LINE])]
    custom_inc, custom_below = doctor.incidents([doctor.parse(it, source) for it in [*pre_gap, *early_miss, *burst, *quiet]])
    assert len(custom_below) == 1 and custom_below[0]["rule"] == "B" and custom_below[0]["value"] == 5 and len(custom_inc) == 1
    pre_summary = doctor._story_summary("B", custom_inc[0]["open_vars"])
    assert "in 6 separate hours" in pre_summary and "2024-01-03 20:07 UTC" in pre_summary
    assert "8 separate hours in all" in doctor._event_text(custom_inc[0]["events"][-1])


def test_family_c_recurrence_resets_state_to_developing_and_checks_notes(tmp_path):
    _, cfg = make_config(tmp_path, publish=True)
    source, all_items = cfg["sources"][0], load_jsonl("jan2024_srv_recurrence.jsonl")
    first_wave = [it for it in all_items if it["published_at"] <= "2024-01-04T02:00:00Z"]
    reopen_wave = [it for it in all_items if "2024-01-04T02:00:00Z" < it["published_at"] <= "2024-01-07T06:00:00Z"]
    final_wave = [it for it in all_items if it["published_at"] > "2024-01-07T06:00:00Z"]

    with Store(cfg["storage"]["database"]) as store:
        doctor.evaluate(cfg, store, source, FakeLinker(), "2024-01-02T00:00:00Z")
        doctor.ingest(store.db, source, first_wave, "2024-01-04T02:05:00Z")
        doctor.evaluate(cfg, store, source, FakeLinker(), "2024-01-04T02:05:00Z")
        [row1] = store.stories()
        assert row1["state"] == "no-longer-listed"

        doctor.ingest(store.db, source, reopen_wave, "2024-01-07T06:05:00Z")
        doctor.evaluate(cfg, store, source, FakeLinker(), "2024-01-07T06:05:00Z")
        [row2] = store.stories()
        assert row2["id"] == row1["id"] and row2["state"] == "developing" and any("missing again" in u["text"] for u in row2["updates"])

        doctor.ingest(store.db, source, final_wave, "2024-01-09T00:00:00Z")
        doctor.evaluate(cfg, store, source, FakeLinker(), "2024-01-09T00:00:00Z")
        [row3] = store.stories()
        assert row3["id"] == row1["id"] and row3["state"] == "no-longer-listed" and len(row3["updates"]) == 3

    srv_line = "ERROR: Consensus is missing a current shared random value (shared-rand-current-value)"
    short_run = [report_item(f"JAN24_C_SHORT_{i}", format_utc(parse_utc("2024-01-10T00:05:00Z") + timedelta(hours=i)), [srv_line])
                 for i in range(5)] + [report_item("JAN24_C_SHORT_END", "2024-01-10T05:05:00Z", [OK_LINE])]
    gapped_run = [report_item(f"JAN24_C_GAP_{i}", format_utc(parse_utc("2024-01-11T00:05:00Z") + timedelta(hours=i if i < 3 else i + 3)), [srv_line])
                  for i in range(6)] + [report_item("JAN24_C_GAP_END", "2024-01-11T10:05:00Z", [OK_LINE])]
    neg_inc, neg_below = doctor.incidents([doctor.parse(it, source) for it in [*short_run, *gapped_run]])
    assert neg_inc == [] and len(neg_below) == 3
    assert set(doctor.NOTES) == {"A", "B", "C"}
    assert "about half were listed for an hour or less" in doctor.NOTES["A"]
    assert "most involved one or two such hours" in doctor.NOTES["B"]
    assert "6 consecutive hourly reports" in doctor.NOTES["C"]


def test_no_120_day_prune_order_independence_and_late_older_report_pinning(tmp_path):
    _, cfg = make_config(tmp_path, publish=True)
    source, items = cfg["sources"][0], load_jsonl("jan2024_authority_cases.jsonl")
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

    _, cfg_pin = make_config(tmp_path / "pin", publish=True)
    t0 = parse_utc("2024-01-02T11:00:00Z")
    missing = ["WARNING: The following authorities are missing from the consensus: bastet", OK_LINE]
    initial_reports = [report_item(f"JAN24_PIN_{d:03d}_{h:02d}", format_utc(t0 + timedelta(days=d, hours=h)), missing) for d in range(9) for h in (0, 12)]
    far_future = report_item("JAN24_PIN_DAY190", format_utc(t0 + timedelta(days=190)), [OK_LINE])
    late_older = report_item("JAN24_PIN_LATE_OLDER", "2024-01-02T10:00:00Z", missing)
    with Store(cfg_pin["storage"]["database"]) as store:
        doctor.ingest(store.db, source, initial_reports, "2024-01-02T00:00:00Z")
        doctor.evaluate(cfg_pin, store, source, FakeLinker(), "2024-01-11T12:00:00Z")
        [before] = store.stories()
        assert len(before["updates"]) == 1

        doctor.ingest(store.db, source, [late_older, far_future], "2024-07-15T00:00:00Z")
        assert store.db.execute("SELECT COUNT(*) FROM network_reports").fetchone()[0] == len(initial_reports) + 2
        doctor.evaluate(cfg_pin, store, source, FakeLinker(), "2024-07-15T00:00:00Z")
        [after_late] = store.stories()
        assert (after_late["id"], after_late["published_at"], after_late["summary"], after_late["state"]) == (
            before["id"], before["published_at"], before["summary"], "no-longer-listed")
        assert len(after_late["updates"]) == 2 and sum("7 days" in u["text"] for u in after_late["updates"]) == 1


def test_authorities_change_while_incident_is_open(tmp_path, monkeypatch):
    _, cfg = make_config(tmp_path, publish=True)
    source, t0 = cfg["sources"][0], parse_utc("2024-01-05T00:00:00Z")
    lines = ["WARNING: The following authorities are missing from the consensus: bastet, newauth", OK_LINE]
    open_items = [report_item(f"JAN24_AUTHCHG_{i}", format_utc(t0 + timedelta(hours=i * 12)), lines) for i in range(5)]
    close_items = [report_item(f"JAN24_AUTHCHG_CLOSE_{i}", format_utc(t0 + timedelta(hours=60 + i * 16)), [OK_LINE]) for i in range(2)]
    with Store(cfg["storage"]["database"]) as store:
        doctor.ingest(store.db, source, open_items, "2024-01-05T00:00:00Z")
        doctor.evaluate(cfg, store, source, FakeLinker(), "2024-01-07T01:00:00Z")
        assert [s["title"] for s in store.stories()] == ["Directory authority bastet missing from the Tor consensus"]

        monkeypatch.setattr(doctor, "AUTHORITIES", tuple(a for a in doctor.AUTHORITIES if a != "bastet") + ("newauth",))
        doctor.ingest(store.db, source, close_items, "2024-01-08T18:00:00Z")
        doctor.evaluate(cfg, store, source, FakeLinker(), "2024-01-08T18:00:00Z")
        by_title = {s["title"]: s for s in store.stories()}
        assert by_title["Directory authority bastet missing from the Tor consensus"]["state"] == "no-longer-listed"
        assert by_title["Directory authority newauth missing from the Tor consensus"]["state"] == "no-longer-listed"


def test_dry_run_status_preview_publish_since_and_on_off_on_transitions(tmp_path, monkeypatch, capsys):
    path, cfg = make_config(tmp_path, publish=False)
    inc1 = [report_item(f"JAN24_DRY_1_{h:02d}", format_utc(parse_utc("2024-01-03T00:05:00Z") + timedelta(hours=h)), [SRV_ERR])
            for h in range(6)] + [report_item("JAN24_DRY_1_CLOSE", "2024-01-03T06:05:00Z", [OK_LINE])]
    inc2_open = [report_item(f"JAN24_DRY_2_{h:02d}", format_utc(parse_utc("2024-01-15T00:05:00Z") + timedelta(hours=h)), [SRV_ERR]) for h in range(6)]

    batches = [[*inc1, *inc2_open], []]
    patch_cli_pipeline(monkeypatch, now="2024-01-15T06:00:00Z", analyzer=Writer.factory(), reviewer=ApprovingReviewer,
                       collect=lambda *_a, **_kw: {"items": batches.pop(0) if batches else [], "skipped": 0, "url": FEED_URL}, no_build=False)
    with Store(cfg["storage"]["database"]) as store:
        rep1 = cli.run(cfg, store)
        assert rep1["network"]["dry_run"] is True and rep1["published_stories"] == 0 and store.stories() == []
        store.db.execute("UPDATE source_state SET next_fetch_at=NULL")
        store.db.commit()
        cli.run(cfg, store)
        assert sum(r["code"] == "held.network.dry_run" for r in decision_rows(store)) == 2

    assert cli.main(["status", "--config", str(path)]) == 0
    status_payload = json.loads(capsys.readouterr().out)["network_health"]
    assert status_payload["mode"] == "dry_run" and status_payload["reports"] == len(inc1) + len(inc2_open) and len(status_payload["incidents"]) == 2
    assert status_payload["incidents"][0]["title"] == "Tor consensus published without a shared random value"

    _, cfg_on = make_config(tmp_path, publish=True)
    monkeypatch.setattr(cli, "now_iso", lambda: "2024-01-15T06:30:00Z")
    with Store(cfg_on["storage"]["database"]) as store:
        cli.run(cfg_on, store)
        [published] = store.stories()
        assert published["published_at"] == "2024-01-15T05:05:00Z" and published["state"] == "developing"
        assert sum(r["code"] == "skipped.network.before_enable" for r in decision_rows(store)) == 1
        public_dir = Path(cfg_on["storage"]["output_dir"])
        article = (public_dir / "news" / published["id"] / "index.html").read_text(encoding="utf-8")
        assert "<h2>About this alert</h2>" in article and "This is an AI-assisted summary" not in article
        assert "This alert uses fixed wording; only the names, times and counts come from the linked DocTor reports." in article
        assert "<strong>About this alert:</strong>" in ET.parse(public_dir / "feed.xml").findtext("./channel/item/description")
        assert "About this alert: " in json.loads((public_dir / "feed.json").read_text(encoding="utf-8"))["items"][0]["content_text"]

    inc2_close = [report_item("JAN24_DRY_2_CLOSE", "2024-01-15T07:05:00Z", [OK_LINE])]
    inc3_closed = [report_item(f"JAN24_DRY_3_{h:02d}", format_utc(parse_utc("2024-01-25T00:05:00Z") + timedelta(hours=h)), [SRV_ERR])
                   for h in range(6)] + [report_item("JAN24_DRY_3_CLOSE", "2024-01-25T06:05:00Z", [OK_LINE])]
    _, cfg_off = make_config(tmp_path, publish=False)
    with Store(cfg_off["storage"]["database"]) as store:
        doctor.ingest(store.db, cfg_off["sources"][0], [*inc2_close, *inc3_closed], "2024-01-25T07:00:00Z")
        doctor.evaluate(cfg_off, store, cfg_off["sources"][0], FakeLinker(), "2024-01-25T07:00:00Z")
        assert len(store.stories()) == 1 and store.stories()[0]["state"] == "developing"

    with Store(cfg_on["storage"]["database"]) as store:
        doctor.evaluate(cfg_on, store, cfg_on["sources"][0], FakeLinker(), "2024-01-26T00:00:00Z")
        assert len(store.stories()) == 1 and store.stories()[0]["state"] == "no-longer-listed"
        assert sum(r["code"] == "skipped.network.before_enable" for r in decision_rows(store)) == 2


def test_preset_publish_since_populates_reports_without_publishing_closed_archive(tmp_path):
    _, cfg = make_config(tmp_path, publish=True)
    source, items = cfg["sources"][0], load_jsonl("jan2024_srv_recurrence.jsonl")
    with Store(cfg["storage"]["database"]) as store:
        store.set_meta(publish_since="2024-01-20T00:00:00Z")
        doctor.ingest(store.db, source, items, "2024-01-20T01:00:00Z")
        res = doctor.evaluate(cfg, store, source, FakeLinker(), "2024-01-20T01:00:00Z")
        assert store.db.execute("SELECT COUNT(*) FROM network_reports").fetchone()[0] == len(items)
        assert res["stories_written"] == 0 and store.stories() == []
        assert any(r["code"] == "skipped.network.before_enable" for r in decision_rows(store))


def test_attach_yes_preserves_host_labels_caches_answer_and_survives_later_model_update(tmp_path):
    _, cfg_dry = make_config(tmp_path, publish=False)
    _, cfg_pub = make_config(tmp_path, publish=True)
    with Store(cfg_dry["storage"]["database"]) as store:
        host_id = seed_host(store, url="https://example.org/bastet-key-removal",
                            title="Directory authority bastet removed after reported key compromise",
                            summary="Maintainers announced removing directory authority bastet after its operator reported a compromise.")
        before_host = render.prepare_story(json.loads(store.db.execute("SELECT payload FROM stories WHERE id=?", (host_id,)).fetchone()[0]))
        open_items = bastet_incident_items(close=False)
        close_only = bastet_incident_items(close=True)[len(open_items):]
        doctor.ingest(store.db, cfg_dry["sources"][0], open_items, "2024-01-17T12:00:00Z")

        linker = FakeLinker(True)
        doctor.evaluate(cfg_dry, store, cfg_dry["sources"][0], linker, "2024-01-17T12:00:00Z")
        assert linker.calls == 1 and len(store.stories()) == 1

        linker2 = FakeLinker(pytest.fail)
        doctor.evaluate(cfg_pub, store, cfg_pub["sources"][0], linker2, "2024-01-17T12:05:00Z")
        assert linker2.calls == 0 and len(store.stories()) == 1
        doctor.ingest(store.db, cfg_pub["sources"][0], close_only, "2024-01-18T12:00:00Z")
        doctor.evaluate(cfg_pub, store, cfg_pub["sources"][0], linker2, "2024-01-18T12:00:00Z")
        assert linker2.calls == 0 and len(store.stories()) == 1

        after_raw = json.loads(store.db.execute("SELECT payload FROM stories WHERE id=?", (host_id,)).fetchone()[0])
        after_host = render.prepare_story(after_raw)
        for field in ("title", "summary", "why_it_matters", "category", "priority", "confidence", "state", "products", "tags"):
            assert after_host[field] == before_host[field]
        assert len(after_host["updates"]) == 2 and after_host["alert_notes"] == [doctor.NOTES["A"]] and len(after_host["sources"]) >= 2

        follow = make_item(url="https://example.org/bastet-key-removal",
                           title="Directory authority bastet removed after reported key compromise",
                           content="Maintainers announced removing directory authority bastet after its operator reported a compromise. Release merged.",
                           published_at="2024-01-14T12:00:00Z", updated_at="2024-01-19T00:00:00Z", authority="official")
        store.ingest(follow, "2024-01-19T00:00:00Z")
        prepared = candidate.prepare(
            store.db, store.pending(1, "2024-01-19T00:00:00Z")[0],
            update_analysis(update="A maintenance release completed removing directory authority bastet.", confidence="confirmed", state="released",
                            evidence=["Maintainers announced removing directory authority bastet after its operator reported a compromise."]),
            "2024-01-19T00:00:00Z",
        )
        assert prepared["candidate"]["alert_notes"] == [doctor.NOTES["A"]] and len(prepared["candidate"]["updates"]) == 3
        assert prepared["candidate"]["updates"][:2] == after_host["updates"] and prepared["payload"]["network"] == after_raw["network"]


def test_attach_no_locked_host_candidate_cap_and_transient_link_failure(tmp_path):
    _, cfg = make_config(tmp_path / "no", publish=True)
    with Store(cfg["storage"]["database"]) as store:
        host_id = seed_host(store, url="https://example.org/bastet-flags",
                            title="Directory authority bastet reports fewer Guard flags in vote",
                            summary="Analysts noted directory authority bastet assigned fewer Guard flags than the consensus.")
        doctor.ingest(store.db, cfg["sources"][0], bastet_incident_items(), "2024-01-18T00:00:00Z")
        linker = FakeLinker(False)
        doctor.evaluate(cfg, store, cfg["sources"][0], linker, "2024-01-18T00:00:00Z")
        assert linker.calls == 1 and len(store.stories()) == 2
        standalone = next(s for s in store.stories() if s["id"] != host_id)
        assert standalone["origin"] == "network-health"

        mapped = make_item(url="https://example.org/follow-note", title="Unrelated headline attempt",
                           content="Operators discussed a relay flag observation in detail on the mailing list.",
                           published_at="2024-01-18T01:00:00Z", updated_at="2024-01-18T01:00:00Z")
        store.ingest(mapped, "2024-01-18T01:00:00Z")
        store.db.execute("UPDATE items SET story_id=? WHERE url=?", (standalone["id"], mapped["url"]))
        store.db.commit()
        pending_row = store.pending(1, "2024-01-18T01:00:00Z")[0]
        with pytest.raises(candidate.StaleCandidate):
            candidate.prepare(store.db, pending_row, analysis(
                title="Model headline trying to overwrite fixed network alert",
                summary="Operators discussed a relay flag observation in detail on the mailing list.",
                evidence=["Operators discussed a relay flag observation in detail on the mailing list."]), "2024-01-18T01:00:00Z")
        env = candidate.prepare(store.db, pending_row, update_analysis(
            update="Operators discussed a relay flag observation in detail on the mailing list.", confidence="confirmed", state="released",
            evidence=["Operators discussed a relay flag observation in detail on the mailing list."]), "2024-01-18T01:00:00Z")
        assert (env["candidate"]["title"], env["candidate"]["confidence"], env["candidate"]["state"], env["candidate"]["origin"]) == (
            standalone["title"], "observed-anomaly", standalone["state"], "network-health")

    _, cfg_lock = make_config(tmp_path / "locked", publish=True)
    with Store(cfg_lock["storage"]["database"]) as store:
        locked_id = seed_host(store, url="https://example.org/bastet-locked", title="Directory authority bastet maintenance notice",
                              summary="Operators reported directory authority bastet maintenance.")
        editorial.correct(store.db, locked_id, {"why_it_matters": "Operator-locked context."}, reason="Clarified context.",
                          expect_hash=editorial.show(store.db, locked_id)["hash"], observed="2024-01-14T13:00:00Z")
        retracted_id = seed_host(store, url="https://example.org/bastet-retracted", title="Withdrawn bastet report",
                                 summary="Withdrawn report naming directory authority bastet.", published_at="2024-01-14T14:00:00Z")
        editorial.retract(store.db, retracted_id, reason="Withdrawn.", expect_hash=editorial.show(store.db, retracted_id)["hash"],
                          observed="2024-01-14T15:00:00Z")
        doctor.ingest(store.db, cfg_lock["sources"][0], bastet_incident_items(), "2024-01-18T00:00:00Z")
        linker = FakeLinker(pytest.fail)
        doctor.evaluate(cfg_lock, store, cfg_lock["sources"][0], linker, "2024-01-18T00:00:00Z")
        doctor.evaluate(cfg_lock, store, cfg_lock["sources"][0], linker, "2024-01-18T00:05:00Z")
        assert linker.calls == 0 and len(store.stories()) == 3
        assert sum(r["code"] == "skipped.network.host_locked" for r in decision_rows(store)) == 1

    _, cfg_fail = make_config(tmp_path / "fail", publish=True)
    with Store(cfg_fail["storage"]["database"]) as store:
        host_id = seed_host(store, url="https://example.org/bastet-outage", title="Directory authority bastet offline during hardware replacement",
                            summary="Operators reported directory authority bastet is offline for hardware replacement.")
        for idx in range(5):
            seed_host(store, url=f"https://example.org/consensus-{idx}", title=f"Directory authority consensus voting issue {idx}",
                      summary=f"Directory authorities experienced consensus voting delays in report {idx}.", published_at=f"2024-01-14T0{idx}:00:00Z")
        b_dummy = {"key": "bcap", "rule": "B", "subject": "network", "first": {"stamp": "2024-01-15T00:00:00Z", "url": FEED_URL},
                   "opened": {"stamp": "2024-01-15T12:00:00Z", "url": FEED_URL}, "last": {"stamp": "2024-01-15T12:00:00Z", "url": FEED_URL}, "closed": None}
        assert len(doctor.candidate_hosts(store.db, b_dummy, log_locked=False)) == 3

        doctor.ingest(store.db, cfg_fail["sources"][0], bastet_incident_items(), "2024-01-18T00:00:00Z")
        res_fail = doctor.evaluate(cfg_fail, store, cfg_fail["sources"][0],
                                   FakeLinker(AnalysisError("LLM request failed (HTTP 503)", retryable=True)), "2024-01-18T00:00:00Z")
        assert (res_fail["endpoint_failures"], res_fail["held"], res_fail["stories_written"], res_fail["updates_written"]) == (1, 1, 0, 0)
        assert any(r["code"] == "held.network.link_pending" for r in decision_rows(store))

        recover = FakeLinker(True)
        res_ok = doctor.evaluate(cfg_fail, store, cfg_fail["sources"][0], recover, "2024-01-18T00:05:00Z")
        assert recover.calls == 1 and res_ok["updates_written"] == 1
        assert len(render.prepare_story(json.loads(store.db.execute("SELECT payload FROM stories WHERE id=?", (host_id,)).fetchone()[0]))["updates"]) == 1


def test_unexpected_exception_in_evaluate_does_not_stop_run(tmp_path, monkeypatch):
    _, cfg = make_config(tmp_path, publish=True)
    cfg["sources"].append({"id": "tor-tags", "name": "Tor Tags", "kind": "tag", "url": "https://example.org/tags.atom",
                           "fallback_urls": [], "product": "tor", "authority": "official", "enabled": False,
                           "interval_seconds": 300, "max_pages": 1, "max_items": 10})
    patch_cli_pipeline(monkeypatch, now=None, analyzer=Writer.factory(), reviewer=ApprovingReviewer,
                       collect=lambda *_a, **_kw: {"items": [], "skipped": 0, "url": FEED_URL}, no_build=False)
    monkeypatch.setattr(doctor, "evaluate", lambda *_a, **_kw: (_ for _ in ()).throw(RuntimeError("unexpected failure")))
    with Store(cfg["storage"]["database"]) as store:
        report = cli.run(cfg, store)
        assert "Unexpected RuntimeError at" in report["network"]["error"] and report["published_stories"] == 0


def test_multiple_enabled_consensus_sources_rejected_and_rule_c_counts_distinct_hours(tmp_path, monkeypatch):
    path, cfg = make_config(tmp_path, publish=True, enabled=True)
    second_disabled = {**cfg["sources"][0], "id": "consensus-mirror", "url": "https://example.org/consensus.xml", "enabled": False}
    extra_toml = (f'\n[[sources]]\nid = "consensus-mirror"\nname = "Mirror"\nwebsite_url = "{LIST_URL}"\n'
                  'url = "https://example.org/consensus.xml"\nkind = "feed"\nproduct = "network"\n'
                  'authority = "telemetry"\nalert_format = "consensus"\npublish = false\nenabled = false\n')
    path.write_text(path.read_text(encoding="utf-8") + extra_toml, encoding="utf-8")
    assert len(load_config(path)["sources"]) == 2

    path.write_text(path.read_text(encoding="utf-8").replace("enabled = false", "enabled = true"), encoding="utf-8")
    with pytest.raises(ValueError, match="At most one enabled consensus alert source is supported"):
        load_config(path)

    monkeypatch.setattr(cli, "HttpClient", lambda *_a, **_kw: (_ for _ in ()).throw(
        AssertionError("HttpClient must not be constructed before consensus-source validation")))
    cfg_two = {**cfg, "sources": [cfg["sources"][0], {**second_disabled, "enabled": True}]}
    with Store(cfg["storage"]["database"]) as store:
        with pytest.raises(ValueError, match="At most one enabled consensus alert source is supported"):
            cli.run(cfg_two, store)
        assert store.db.execute("SELECT COUNT(*) FROM source_state").fetchone()[0] == 0

    srv_line = "NOTICE: Consensus is missing a current shared random value"
    for name, items, expected in (
        ("same", [report_item(f"srv-same-{i}", f"2024-01-20T00:{5 + i:02d}:00Z", [srv_line]) for i in range(6)], 0),
        ("hours", [report_item(f"srv-hr-{i}", f"2024-01-20T{i:02d}:05:00Z", [srv_line]) for i in range(6)], 1),
    ):
        with Store(tmp_path / f"srv_{name}.sqlite3") as store:
            doctor.ingest(store.db, cfg["sources"][0], items, "2024-01-20T06:00:00Z")
            assert doctor.evaluate(cfg, store, cfg["sources"][0], FakeLinker(), "2024-01-20T06:00:00Z")["stories_written"] == expected


def test_host_updates_drive_matching_invalidate_negative_cache_and_guards_hold(tmp_path):
    _, cfg = make_config(tmp_path / "host_upd", publish=True)
    with Store(cfg["storage"]["database"]) as store:
        host_id = seed_host(store, url="https://gitlab.torproject.org/tpo/network-health/analysis/-/issues/990",
                            title="Directory consensus voting instability under investigation",
                            summary="Operators are investigating intermittent voting instability across the directory.",
                            published_at="2024-01-15T06:00:00Z")
        raw_before = json.loads(store.db.execute("SELECT payload FROM stories WHERE id=?", (host_id,)).fetchone()[0])
        doctor.ingest(store.db, cfg["sources"][0], bastet_incident_items(close=False), "2024-01-17T12:00:00Z")
        replayed = doctor._replay(doctor.load_reports(store.db))[0][0]
        assert doctor.candidate_hosts(store.db, replayed, log_locked=False) == []
        old_hash = doctor._host_hash(render.prepare_story(raw_before), replayed)
        with store.db:
            store.db.execute("INSERT INTO network_links(incident_key,host_id,host_hash,version,same_incident,decided_at) VALUES(?,?,?,?,0,?)",
                             (replayed["key"], host_id, old_hash, doctor.DOCTOR_LINK_VERSION, "2024-01-17T11:30:00Z"))
        raw_after = {**raw_before, "updated_at": "2024-01-16T18:00:00Z",
                     "updates": [{"at": "2024-01-16T18:00:00Z", "text": "Operators traced the missing votes to directory authority bastet.",
                                  "sources": raw_before["sources"]}]}
        with store.db:
            store.db.execute("UPDATE stories SET updated_at=?,payload=? WHERE id=?", ("2024-01-16T18:00:00Z", json.dumps(raw_after), host_id))
        seen_payloads = []

        class InspectingLinker(doctor.LinkChecker):
            def __init__(self): self.calls = 0
            def complete(self, prompt, payload, schema, name):
                self.calls += 1; seen_payloads.append(payload)
                return {"reason": "Same bastet outage.", "same_incident": True}

        linker = InspectingLinker()
        res_attach = doctor.evaluate(cfg, store, cfg["sources"][0], linker, "2024-01-17T12:00:00Z")
        assert (linker.calls, res_attach["updates_written"], res_attach["stories_written"]) == (1, 1, 0)
        assert seen_payloads[0]["existing_story"]["updates"] == [
            {"at": "2024-01-16T18:00:00Z", "text": "Operators traced the missing votes to directory authority bastet."}]

    _, cfg_dry = make_config(tmp_path / "cut", publish=False)
    cfg_pub = {**cfg_dry, "sources": [{**cfg_dry["sources"][0], "publish": True}]}
    with Store(cfg_dry["storage"]["database"]) as store:
        store.set_meta(publish_since="2024-01-01T00:00:00Z")
        doctor.ingest(store.db, cfg_dry["sources"][0], bastet_incident_items(start_iso="2024-01-01T06:05:00Z", close=True), "2024-01-05T06:00:00Z")
        assert doctor.evaluate(cfg_dry, store, cfg_dry["sources"][0], FakeLinker(), "2024-01-05T06:00:00Z")["stories_written"] == 0
        assert doctor.evaluate(cfg_pub, store, cfg_pub["sources"][0], FakeLinker(), "2024-01-15T06:30:00Z")["stories_written"] == 0
        assert any(r["code"] == "skipped.network.before_enable" for r in decision_rows(store))

    _, cfg_lock = make_config(tmp_path / "standalone_lock", publish=True)
    with Store(cfg_lock["storage"]["database"]) as store:
        doctor.ingest(store.db, cfg_lock["sources"][0], bastet_incident_items(start_iso="2024-01-19T00:05:00Z", close=False), "2024-01-22T00:00:00Z")
        assert doctor.evaluate(cfg_lock, store, cfg_lock["sources"][0], FakeLinker(), "2024-01-22T00:00:00Z")["stories_written"] == 1
        standalone_id = store.stories()[0]["id"]
        editorial.correct(store.db, standalone_id, {"why_it_matters": "Operator-pinned alert context."},
                          reason="Pin alert context", expect_hash=editorial.show(store.db, standalone_id)["hash"], observed="2024-01-22T00:05:00Z")
        with store.db:
            store.db.execute("DELETE FROM stories WHERE id=?", (standalone_id,))
        assert doctor.evaluate(cfg_lock, store, cfg_lock["sources"][0], FakeLinker(), "2024-01-22T00:10:00Z")["stories_written"] == 0
        assert store.db.execute("SELECT COUNT(*) FROM stories WHERE id=?", (standalone_id,)).fetchone()[0] == 0


def test_merge_host_story_transfers_doctor_network_pins_updates_and_citations(tmp_path):
    _, cfg = make_config(tmp_path, publish=True)
    with Store(cfg["storage"]["database"]) as store:
        host_surv = seed_host(store, url="https://example.org/bastet-main", title="Primary report on directory authority bastet outage",
                              summary="Primary tracking story for the directory authority bastet outage.", published_at="2024-01-14T13:00:00Z")
        host_dup = seed_host(store, url="https://example.org/bastet-dup", title="Directory authority bastet maintenance outage",
                             summary="Operators reported directory authority bastet is offline for maintenance.", published_at="2024-01-14T14:00:00Z")
        doctor.ingest(store.db, cfg["sources"][0], bastet_incident_items(close=False), "2024-01-17T12:00:00Z")
        doctor.evaluate(cfg, store, cfg["sources"][0], FakeLinker(True), "2024-01-17T12:00:00Z")
        publication.build(cfg, store)

        dup_payload = json.loads(store.db.execute("SELECT payload FROM stories WHERE id=?", (host_dup,)).fetchone()[0])
        assert len(dup_payload.get("network") or []) == 1 and len(dup_payload.get("updates") or []) == 1

        b_more_rep = report_item("BMORE_REP_12", "2024-01-17T12:15:00Z", ["ERROR: The consensus is not fresh!"])
        unrelated_rep = report_item("UNRELATED_REP_01", "2024-01-10T00:05:00Z", ["NOTICE: unrelated line"])
        doctor.ingest(store.db, cfg["sources"][0], [b_more_rep, unrelated_rep], "2024-01-17T12:30:00Z")
        b_more_uid = digest([host_dup, "B:more", b_more_rep["url"]])[:24]
        dup_payload["network"][0]["slots"] = [*dup_payload["network"][0]["slots"], "ep1:B:more:12"]
        dup_payload["network"][0]["update_ids"] = [*dup_payload["network"][0]["update_ids"], b_more_uid]
        dup_payload["updates"] = [
            *list(dup_payload.get("updates") or []),
            {"at": "2024-01-17T12:15:00Z", "text": "Stale-consensus errors reached 12 hourly reports.",
             "sources": [{"url": b_more_rep["url"], "title": "DocTor consensus-health report"}]},
            {"at": "2024-01-17T12:30:00Z", "text": "Unrelated report note that was not produced by host_dup's pinned incident.",
             "sources": [{"url": unrelated_rep["url"], "title": "Unrelated report"}]},
        ]
        with store.db:
            store.db.execute("UPDATE stories SET payload=? WHERE id=?", (json.dumps(dup_payload), host_dup))

        editorial.merge(store.db, host_dup, host_surv, reason="Merge duplicate host story.",
                        expect_hash=editorial.show(store.db, host_dup)["hash"], observed="2024-01-17T13:00:00Z")
        guard_linker = FakeLinker(AssertionError("Unexpected linker call"))
        res_next = doctor.evaluate(cfg, store, cfg["sources"][0], guard_linker, "2024-01-17T13:05:00Z")
        assert (guard_linker.calls, res_next["stories_written"], res_next["updates_written"]) == (0, 0, 0)
        assert [s["id"] for s in store.stories()] == [host_surv]
        surv_story = store.stories()[0]
        assert len(surv_story["updates"]) == 2 and any("12 hourly reports" in u["text"] for u in surv_story["updates"])
        assert surv_story["alert_notes"] == [doctor.NOTES["A"]]

    _, cfg_chain = make_config(tmp_path / "chain", publish=True)
    with Store(cfg_chain["storage"]["database"]) as store:
        t0 = parse_utc("2024-02-01T00:05:00Z")
        dual_lines = ["WARNING: The following authorities are missing from the consensus: bastet",
                      "WARNING: The following authorities are missing from the consensus: moria1"]
        dual_items = [report_item(f"CHAIN_DUAL_{i}", format_utc(t0 + timedelta(hours=i * 12)), dual_lines) for i in range(5)]
        doctor.ingest(store.db, cfg_chain["sources"][0], dual_items, "2024-02-03T01:00:00Z")
        inc_bastet = next(inc for inc in doctor.incidents(doctor.load_reports(store.db))[0] if inc["subject"] == "bastet")
        bastet_cluster = "network:" + inc_bastet["key"]
        prev_id, prev_ck = digest(bastet_cluster)[:24], bastet_cluster
        with store.db:
            for hop in range(editorial.MAX_ALIAS_HOPS + 2):
                nxt_id = f"hop{hop:03d}"
                store.db.execute("INSERT INTO story_aliases(story_id,cluster_key,survivor_id,reason,created_at,story_json) VALUES(?,?,?,?,?,NULL)",
                                 (prev_id, prev_ck, nxt_id, "Chain hop.", "2024-02-03T00:00:00Z"))
                prev_id, prev_ck = nxt_id, f"chain:{hop}"
            malformed = {"network": [{"key": "other-key", "rule": "A", "subject": "moria1", "first_url": [], "opened_url": {}}]}
            store.db.execute("INSERT INTO story_aliases(story_id,cluster_key,survivor_id,reason,created_at,story_json) VALUES(?,?,?,?,?,?)",
                             ("malformed_alias", "chain:malformed", None, "Malformed URL fields.", "2024-02-03T00:00:00Z", json.dumps(malformed)))
        assert doctor.evaluate(cfg_chain, store, cfg_chain["sources"][0], FakeLinker(), "2024-02-03T01:00:00Z")["stories_written"] == 1
        assert len(doctor.status(store.db, cfg_chain["sources"])["incidents"]) == 1 and "moria1" in store.stories()[0]["title"]
        assert [r[0] for r in store.db.execute("SELECT code FROM decision_log WHERE subject=?", (inc_bastet["key"],))] == ["skipped.gate.retired_story"]


def test_legacy_host_story_with_doctor_citations_has_no_missing_sources(tmp_path):
    _, cfg = make_config(tmp_path, publish=True)
    with Store(cfg["storage"]["database"]) as store:
        store.ingest(make_item(url="https://example.org/legacy-1", title="Authority bastet maintenance", content="Authority bastet maintenance window."), "2024-01-14T10:00:00Z")
        store.ingest(make_item(url="https://example.org/legacy-2", title="Authority bastet update", content="Follow-up on authority bastet maintenance."), "2024-01-14T11:00:00Z")
        r1, r2 = store.pending(2, "2024-01-14T11:00:00Z")
        host_id = seed_host(store, url="https://example.org/bastet-legacy-host", title="Directory authority bastet planned maintenance",
                            summary="Operators scheduled maintenance on directory authority bastet.")
        raw = json.loads(store.db.execute("SELECT payload FROM stories WHERE id=?", (host_id,)).fetchone()[0])
        raw.pop("editorial_item", None)
        raw["sources"] = [{"id": r1["id"], "url": r1["url"], "title": "Legacy 1", "published_at": "2024-01-14T10:00:00Z"},
                          {"id": r2["id"], "url": r2["url"], "title": "Legacy 2", "published_at": "2024-01-14T11:00:00Z"}]
        with store.db:
            store.db.execute("UPDATE stories SET payload=? WHERE id=?", (json.dumps(raw), host_id))
        doctor.ingest(store.db, cfg["sources"][0], bastet_incident_items(close=False), "2024-01-17T12:00:00Z")
        doctor.evaluate(cfg, store, cfg["sources"][0], FakeLinker(True), "2024-01-17T12:00:00Z")
        pinned_raw = json.loads(store.db.execute("SELECT payload FROM stories WHERE id=?", (host_id,)).fetchone()[0])
        pkt, _ = source_packet.build_packet(store.db, {**json.loads(r1["payload"]), "id": r1["id"]}, pinned_raw, pinned_raw, None)
        assert pkt["missing_sources"] == []


def test_doctor_review_model_non_retryable_strikes_regroup_publish_since_and_retracted_status(tmp_path):
    _, cfg = make_config(tmp_path, publish=True)
    cfg["review"]["model"] = "dedicated-reviewer-model"
    assert doctor.LinkChecker(cfg).llm["model"] == "dedicated-reviewer-model"

    trunc_one = report_item("ONE_LINE_TRUNC", "2024-01-10T00:05:00Z", ["WARNING: The following authorities are missing from the consensus: bastet2"])
    assert doctor.parse(trunc_one, cfg["sources"][0], limit=len(trunc_one["content"])) is None
    assert "more than 24 hours after its last listing" in doctor._event_text({
        "kind": "A:close", "vars": {"authority": "bastet", "first_omit": "2024-01-20T01:00:00Z", "decided": "2024-01-20T01:00:00Z"}})

    ep1 = [report_item(f"PRE_EN_{h}", format_utc(parse_utc("2024-01-03T00:05:00Z") + timedelta(hours=h)), [SRV_ERR])
           for h in range(6)] + [report_item("PRE_EN_CLOSE", "2024-01-03T06:05:00Z", [OK_LINE])]
    ep2 = [report_item(f"POST_EN_{h}", format_utc(parse_utc("2024-01-08T00:05:00Z") + timedelta(hours=h)), [SRV_ERR]) for h in range(6)]
    with Store(tmp_path / "regroup.sqlite3") as store:
        store.set_meta(publish_since="2024-01-06T00:00:00Z")
        doctor.ingest(store.db, cfg["sources"][0], [*ep1, *ep2], "2024-01-08T06:00:00Z")
        assert doctor.evaluate(cfg, store, cfg["sources"][0], FakeLinker(), "2024-01-08T06:00:00Z")["stories_written"] == 1
        assert store.stories()[0]["published_at"] >= "2024-01-08T00:00:00Z"

    with Store(cfg["storage"]["database"]) as store:
        seed_host(store, url="https://example.org/bastet-unrelated", title="Directory authority bastet flag count note",
                  summary="Directory authority bastet flag note.")
        doctor.ingest(store.db, cfg["sources"][0], bastet_incident_items(close=False), "2024-01-18T00:00:00Z")
        bad_err = AnalysisError("Model completion was truncated or refused", code="review.truncated")
        for minute in (0, 5):
            r_hold = doctor.evaluate(cfg, store, cfg["sources"][0], FakeLinker(bad_err), f"2024-01-18T00:{minute:02d}:00Z")
            assert r_hold["held"] == 1 and r_hold["stories_written"] == 0
        r_third = doctor.evaluate(cfg, store, cfg["sources"][0], FakeLinker(bad_err), "2024-01-18T00:10:00Z")
        assert r_third["stories_written"] == 1 and r_third["held"] == 0
        standalone = next(s for s in store.stories() if s.get("origin") == "network-health")

        publication.build(cfg, store)
        editorial.correct(store.db, standalone["id"], {"why_it_matters": "Operator context."}, reason="Lock alert.",
                          expect_hash=editorial.show(store.db, standalone["id"])["hash"], observed="2024-01-18T00:15:00Z")
        doctor.ingest(store.db, cfg["sources"][0], bastet_incident_items(close=True)[5:], "2024-01-18T18:00:00Z")
        doctor.evaluate(cfg, store, cfg["sources"][0], FakeLinker(), "2024-01-18T18:00:00Z")
        doctor.evaluate(cfg, store, cfg["sources"][0], FakeLinker(), "2024-01-18T18:05:00Z")
        assert editorial.show(store.db, standalone["id"])["held_updates"] == 1
        assert decisions.summary(store.db, "2024-01-01T00:00:00Z")["awaiting_operator"]["held_updates"] == [
            {"story_id": standalone["id"], "held_updates": 1, "locked": True}]

        editorial.retract(store.db, standalone["id"], reason="Retract alert.",
                          expect_hash=editorial.show(store.db, standalone["id"])["hash"], observed="2024-01-18T19:00:00Z")
        assert decisions.summary(store.db, "2024-01-01T00:00:00Z")["awaiting_operator"]["held_updates"] == []
        assert doctor.status(store.db, cfg["sources"])["incidents"][0]["target"] == f"retracted:{standalone['id']}"

    _, cfg_multi = make_config(tmp_path / "multi", publish=True)
    with Store(cfg_multi["storage"]["database"]) as store:
        t0 = parse_utc("2024-01-10T00:05:00Z")
        dual_lines = ["WARNING: The following authorities are missing from the consensus: gabelmoo",
                      "WARNING: The following authorities are missing from the consensus: moria1"]
        doctor.ingest(store.db, cfg_multi["sources"][0],
                      [report_item(f"M_BOTH_{i}", format_utc(t0 + timedelta(hours=i * 12)), dual_lines) for i in range(5)],
                      "2024-01-12T01:00:00Z")
        doctor.evaluate(cfg_multi, store, cfg_multi["sources"][0], FakeLinker(), "2024-01-12T01:00:00Z")
        publication.build(cfg_multi, store)
        s_gab = next(s for s in store.stories() if "gabelmoo" in s["title"])["id"]
        s_mor = next(s for s in store.stories() if "moria1" in s["title"])["id"]
        editorial.merge(store.db, s_mor, s_gab, reason="Combine dual authority outage.",
                        expect_hash=editorial.show(store.db, s_mor)["hash"], observed="2024-01-12T01:30:00Z")
        mor_only = [report_item(f"M_MOR_ONLY_{i}", format_utc(t0 + timedelta(hours=60 + i * 16)),
                                ["WARNING: The following authorities are missing from the consensus: moria1"]) for i in range(2)]
        doctor.ingest(store.db, cfg_multi["sources"][0], mor_only, "2024-01-13T18:00:00Z")
        doctor.evaluate(cfg_multi, store, cfg_multi["sources"][0], FakeLinker(), "2024-01-13T18:00:00Z")
        [combined_open] = store.stories()
        assert len(combined_open["network"]) == 2 and combined_open["state"] == "developing"

        bad_net_payload = json.loads(store.db.execute("SELECT payload FROM stories WHERE id=?", (s_gab,)).fetchone()[0])
        bad_net_payload["network"].append({"key": []})
        with store.db:
            store.db.execute("UPDATE stories SET payload=? WHERE id=?", (json.dumps(bad_net_payload), s_gab))
        doctor.ingest(store.db, cfg_multi["sources"][0],
                      [report_item(f"M_CLEAR_{i}", format_utc(t0 + timedelta(hours=92 + i * 16)), [OK_LINE]) for i in range(2)],
                      "2024-01-14T22:00:00Z")
        doctor.evaluate(cfg_multi, store, cfg_multi["sources"][0], FakeLinker(), "2024-01-14T22:00:00Z")
        assert store.stories()[0]["state"] == "no-longer-listed"


@pytest.mark.parametrize("invalid_toml", [
    '[monitoring]\nmin_reports=2\n[[sources]]\nid="a"\nurl="https://example.org/alerts.xml"\n',
    '[[sources]]\nid="a"\nurl="https://example.org/alerts.xml"\nmonitor_id="old-monitor"\n',
    '[[sources]]\nid="a"\nurl="https://example.org/alerts.xml"\nalert_format="censorship"\n',
    '[[sources]]\nid="a"\nurl="https://example.org/alerts.xml"\nalert_format="unknown-alert-format"\n',
    BASE_CONSENSUS_TOML + 'publish="yes"\n',
    BASE_CONSENSUS_TOML.replace('alert_format="consensus"\n', "") + "publish=false\n",
    BASE_CONSENSUS_TOML.replace(f'website_url="{LIST_URL}"\n', ""),
    BASE_CONSENSUS_TOML.replace(f'website_url="{LIST_URL}"', 'website_url="https://lists.torproject.org/mailman3/hyperkitty/?page=1"'),
    BASE_CONSENSUS_TOML.replace('kind="feed"', 'kind="tag"'),
])
def test_consensus_alert_source_rejects_invalid_and_retired_keys(tmp_path, invalid_toml):
    path = tmp_path / "config.toml"
    path.write_text(invalid_toml, encoding="utf-8")
    with pytest.raises(ValueError):
        load_config(path)


def test_consensus_alert_source_loads_enabled_in_dry_run_and_validates_keys(tmp_path, caplog):
    path = tmp_path / "config.toml"
    path.write_text(BASE_CONSENSUS_TOML, encoding="utf-8")
    source = load_config(path)["sources"][0]
    assert source["enabled"] is True and source["publish"] is False
    assert "monitoring alert collection is retired" not in caplog.text


def test_old_databases_keep_the_unused_monitoring_tables(tmp_path):
    """The tables that earlier releases wrote stay as they were, and those releases' stories still build."""
    cfg = pub_settings(tmp_path)
    value = make_story(1, confidence="observed-anomaly", state="developing", category="directory-authority")
    with Store(cfg["storage"]["database"]) as store:
        put_story(store.db, value)
        for table in ("monitoring_groups", "monitoring_observations"):
            store.db.execute(f"CREATE TABLE {table} (group_key TEXT, story_id TEXT)")
            store.db.execute(f"INSERT INTO {table} VALUES('group',?)", (value["id"],))
        store.db.commit()
    with Store(cfg["storage"]["database"]) as store:
        for table in ("monitoring_groups", "monitoring_observations"):
            assert [tuple(row) for row in store.db.execute(f"SELECT * FROM {table}")] == [("group", value["id"])]
        cli.build(cfg, store)
    published = json.loads((Path(cfg["storage"]["output_dir"]) / "news" / value["id"] / "story.json").read_text(encoding="utf-8"))
    assert published["id"] == value["id"] and published["confidence"] == "observed-anomaly"
