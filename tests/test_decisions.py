"""Every terminal decision is logged once, privately, in the transaction that applies it."""

from collections import Counter
import contextlib
import json
from pathlib import Path
import re
import sqlite3

import pytest

from helpers import (DATE, LATER, Reviewer, Writer, analysis, config, damage_item, finish_reviewed,
                     item, pending, run_gate as run, seed_ignored, seed_legacy, seed_rejected, verdict)
from onionflash import analyze, cli, decisions, editorial, rejection, review, review_gate
from onionflash.analyze import AnalysisError, tag_notice, validate_analysis
from onionflash.config import load_config
from onionflash.store import Store
from onionflash.transport import Response
from onionflash.util import after, now_iso


def logged(store):
    return [{**dict(row), "detail": json.loads(row["detail_json"])}
            for row in store.db.execute("SELECT * FROM decision_log ORDER BY id")]


def item_id(store, url):
    return store.db.execute("SELECT id FROM items WHERE url=?", (url,)).fetchone()[0]


def both_editorial():
    reply = verdict("skip", criterion="news_value")
    reply["criteria"]["new_information"]["outcome"] = "fail"
    return reply


def write_config(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text('[storage]\ndatabase = "state.sqlite3"\noutput_dir = "public"\n'
                    '[[sources]]\nid = "test"\nurl = "https://example.org/feed.xml"\n')
    return path, load_config(path)


@pytest.mark.parametrize("replies,code,chain", [
    ([verdict()], "published.new", ["review:approve", "verification:approve"]),
    ([verdict("skip", criterion="news_value")], "skipped.review.news_value", ["review:skip"]),
    ([verdict("revise", repair={"why_it_matters": ""}, criterion="news_value"),
      {"outcome": "unsupported", "reason": "Unsupported impact.", "source_refs": ["S1"]}, both_editorial()],
     "skipped.verification.new_information_and_news_value", ["review:revise", "verification:skip"]),
    ([verdict("hold")], "held.review.model_hold", ["review:hold"]),
    ([verdict("revise", repair={"why_it_matters": ""}),
      {"outcome": "unsupported", "reason": "Unsupported impact.", "source_refs": ["S1"]}, verdict("hold")], "held.verification.model_hold",
     ["review:revise", "verification:hold"]),
    ([verdict("revise", repair={"title": ""})], "held.review.unusable_repair", ["review:revise"]),
], ids=["approve", "skip", "verified-skip", "hold", "verification-refusal", "unusable-repair"])
def test_each_gate_outcome_writes_one_decision_row(context, replies, code, chain):
    cfg, store = context
    row = pending(store)
    run(cfg, store, row, Writer(), Reviewer(*replies))
    [entry] = logged(store)
    status, story_id, error = store.db.execute("SELECT status,story_id,last_error FROM items").fetchone()
    assert (entry["code"], entry["subject"], entry["item_id"], entry["content_hash"], entry["source_id"], entry["story_id"]) == (
        code, row["id"], row["id"], row["content_hash"], "test", story_id)
    assert code in decisions.CODES and entry["detail"]["verdicts"] == chain and entry["detail"]["title"] == item()["title"]
    assert bool(entry["detail"].get("criteria")) == (not code.startswith("published."))
    if code.startswith("held."):
        assert status == "rejected" and error == "Final review held: " + review_gate.HOLDS[code.rsplit(".", 1)[1]]


def test_coded_holds_missing_sources_and_locked_updates(context):
    cfg, store = context
    tag_item = item(url="https://example.org/tags/tor-0.4.9.16", title="tor-0.4.9.16", kind="tag", content="")
    run(cfg, store, pending(store, tag_item), Writer(tag_notice(tag_item)),
        Reviewer(verdict("revise", repair={"title": "Tor 0.4.9.16 released"})))
    run(cfg, store, pending(store), Writer(), Reviewer(verdict("hold")))
    store.ingest(item(content=item()["content"] + " Edited."), DATE)
    assert run(cfg, store, store.pending(1, LATER)[0], Writer(), Reviewer(), allow_network=False)["status"] == "deferred"
    store.ingest(item(), DATE)
    assert run(cfg, store, store.pending(1, LATER)[0], Writer(), Reviewer())["status"] == "held"
    assert [e["code"] for e in logged(store)] == ["held.review.tag_repair", "held.review.model_hold", "held.gate.repeat_hold"]

    orig = item(url="https://example.org/miss", content="Missing source body text long enough to cluster across URLs. " * 5, updated_at="2026-11-09T12:00:00Z")
    seed_legacy(store, orig, analysis(evidence=["Missing source body text long enough"]))
    with store.db:
        store.db.execute("UPDATE items SET payload=json_remove(payload,'$.content') WHERE url=?", (orig["url"],))
    row_m = pending(store, item(url="https://example.org/miss-mirror", source_id="mirror", content=orig["content"]))
    assert run(cfg, store, row_m, Writer(), Reviewer())["status"] == "held"
    assert (logged(store)[-1]["code"], logged(store)[-1]["item_id"]) == ("held.gate.missing_sources", row_m["id"])

    orig_u, story_id = seed_legacy(store, item(url="https://example.org/lock-u", content="Locked story body text long enough. " * 3),
                                   analysis(evidence=["Locked story body text long enough."]))
    rev = {**orig_u, "content": orig_u["content"] + " A later report.", "updated_at": LATER}
    assert run(cfg, store, pending(store, rev), Writer(), Reviewer(verdict()))["status"] == "published"
    editorial.correct(store.db, story_id, {"why_it_matters": "Operator-reviewed wording."}, reason="Corrected wording.",
                      expect_hash=editorial.show(store.db, story_id)["hash"], observed=LATER)
    later = {**rev, "content": rev["content"] + " Another report.", "updated_at": "2026-11-10T13:00:00Z"}
    assert run(cfg, store, pending(store, later), Writer(), Reviewer())["status"] == "locked"
    assert [(e["code"], e["story_id"]) for e in logged(store)[-2:]] == [("published.update", story_id), ("held.gate.story_locked", story_id)]
    assert decisions.summary(store.db, DATE)["awaiting_operator"]["held_updates"] == [{"story_id": story_id, "held_updates": 1, "locked": True}]
    editorial.unlock(store.db, story_id, reason="Automation resumes.", expect_hash=editorial.show(store.db, story_id)["hash"],
                     observed="2026-11-10T14:00:00Z")
    assert editorial.show(store.db, story_id)["held_updates"] == 0
    assert decisions.summary(store.db, DATE)["awaiting_operator"]["held_updates"] == []
    [requeued] = [r for r in store.pending(10, "2026-11-10T14:00:00Z") if r["id"] == orig_u["id"]]
    assert run(cfg, store, requeued, Writer(), Reviewer(verdict("skip", criterion="news_value")))["status"] == "ignored"
    assert editorial.show(store.db, story_id)["held_updates"] == 0
    assert decisions.summary(store.db, DATE)["awaiting_operator"]["held_updates"] == []
    minor = {**later, "content": later["content"] + " A minor note.", "updated_at": "2026-11-10T14:30:00Z"}
    assert run(cfg, store, pending(store, minor), Writer(), Reviewer(verdict("skip", criterion="news_value")))["status"] == "ignored"
    assert decisions.summary(store.db, DATE)["awaiting_operator"]["held_updates"] == []
    final = {**minor, "content": minor["content"] + " A final report.", "updated_at": "2026-11-10T15:00:00Z"}
    assert run(cfg, store, pending(store, final), Writer(), Reviewer(verdict()))["status"] == "published"
    assert decisions.summary(store.db, DATE)["awaiting_operator"]["held_updates"] == []


def test_a_hold_the_log_never_saw_waits_until_an_update_publishes(context):
    cfg, store = context
    original, story_id = seed_legacy(store)
    editorial.correct(store.db, story_id, {"why_it_matters": "Operator-reviewed wording."}, reason="Corrected wording.",
                      expect_hash=editorial.show(store.db, story_id)["hash"], observed=LATER)
    assert decisions.summary(store.db, DATE)["awaiting_operator"]["held_updates"] == []
    with store.db:
        editorial.record_held(store.db, story_id)
    assert decisions.summary(store.db, DATE)["awaiting_operator"]["held_updates"] == [{"story_id": story_id, "held_updates": 1, "locked": True}]
    editorial.unlock(store.db, story_id, reason="Automation resumes.", expect_hash=editorial.show(store.db, story_id)["hash"],
                     observed="2026-11-10T14:00:00Z")
    assert editorial.show(store.db, story_id)["held_updates"] == 0
    assert decisions.summary(store.db, DATE)["awaiting_operator"]["held_updates"] == []
    # Simulate an unlocked row left with held_updates>0 before unlock reset the counter.
    with store.db:
        editorial.record_held(store.db, story_id)
    assert decisions.summary(store.db, DATE)["awaiting_operator"]["held_updates"] == [{"story_id": story_id, "held_updates": 1, "locked": False}]
    minor = {**original, "content": original["content"] + " A minor note.", "updated_at": "2026-11-10T14:30:00Z"}
    assert run(cfg, store, pending(store, minor), Writer(), Reviewer(verdict("skip", criterion="news_value")))["status"] == "ignored"
    assert decisions.summary(store.db, DATE)["awaiting_operator"]["held_updates"] == [{"story_id": story_id, "held_updates": 1, "locked": False}]
    revision = {**minor, "content": minor["content"] + " A later report.", "updated_at": "2026-11-10T15:00:00Z"}
    assert run(cfg, store, pending(store, revision), Writer(), Reviewer(verdict()))["status"] == "published"
    assert decisions.summary(store.db, DATE)["awaiting_operator"]["held_updates"] == []


def test_resumed_commit_and_reused_receipt_log_review_chains(context, monkeypatch):
    cfg, store = context
    row = pending(store)
    commit = store.commit_candidate
    monkeypatch.setattr(store, "commit_candidate", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("crash")))
    with pytest.raises(RuntimeError):
        run(cfg, store, row, Writer(), Reviewer(verdict()))
    monkeypatch.setattr(store, "commit_candidate", commit)
    assert logged(store) == []
    assert run(cfg, store, row, Writer(), Reviewer(), allow_network=False)["cache_hit"]
    assert [(e["code"], e["detail"]["verdicts"]) for e in logged(store)] == [
        ("published.new", ["review:approve", "verification:approve"])]

    row2 = pending(store, item(url="https://example.org/off", authority="official", kind="feed"))
    monkeypatch.setattr(store, "commit_candidate", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("crash")))
    with pytest.raises(RuntimeError):
        run(cfg, store, row2, Writer(), Reviewer(verdict("skip", criterion="news_value"), both_editorial()))
    monkeypatch.setattr(store, "commit_candidate", commit)
    for _ in range(3):
        store.defer(row2["id"], "Unexpected error", cfg["llm"], LATER, terminal=True)
    rejection.retry_item(store, row2["id"], row2["content_hash"], "Retry the item", LATER)
    assert run(cfg, store, store.pending(1, LATER)[0], Writer(), Reviewer(), allow_network=False)["cache_hit"]
    assert [e["code"] for e in logged(store)[1:]] == [
        "failed.app.unexpected", "operator.retried", "skipped.verification.new_information_and_news_value"]
    detail = logged(store)[-1]["detail"]
    assert (detail["verdicts"], list(detail["criteria"])) == (["review:skip", "verification:skip"], ["new_information", "news_value"])

    partial_review = {"stage": "review", "result": verdict("revise", repair={"why_it_matters": ""})}
    cached_skip = {"stage": "verification", "result": both_editorial()}
    reused_record = {"reviews": [partial_review], "approval": {"reviews": [partial_review, cached_skip]}}
    assert decisions.skip_code(reused_record, both_editorial()) == "skipped.verification.new_information_and_news_value"
    with store.db:
        decisions.record(store.db, row2["id"], "skipped.verification.new_information_and_news_value", LATER, review=reused_record)
    reused_detail = logged(store)[-1]["detail"]
    assert reused_detail["verdicts"] == ["review:revise", "verification:skip"]
    assert list(reused_detail["criteria"]) == ["new_information", "news_value"]


def test_decision_rows_roll_back_with_their_outcome(context):
    cfg, store = context
    struck, failing, held, approved = (item(url=f"https://example.org/{name}") for name in ("struck", "failing", "held", "approved"))
    for incoming in (struck, failing, held, approved):
        store.ingest(incoming, DATE)
    for _ in range(3):
        store.defer(struck["id"], "Model returned invalid JSON", cfg["llm"], DATE, terminal=True, code="writer.invalid_json")
    for _ in range(2):
        store.defer(failing["id"], "Model returned invalid JSON", cfg["llm"], DATE, terminal=True, code="writer.invalid_json")
    store.db.execute("CREATE TRIGGER no_log BEFORE INSERT ON decision_log BEGIN SELECT RAISE(ABORT,'log unavailable'); END")
    store.db.commit()
    rows = {inc["id"]: dict(store.db.execute("SELECT * FROM items WHERE id=?", (inc["id"],)).fetchone()) for inc in (struck, held, approved)}
    for attempt in (lambda: run(cfg, store, rows[held["id"]], Writer(), Reviewer(verdict("hold"))),
                    lambda: run(cfg, store, rows[approved["id"]], Writer(), Reviewer(verdict())),
                    lambda: store.defer(failing["id"], "Model returned invalid JSON", cfg["llm"], DATE, terminal=True),
                    lambda: rejection.retry_item(store, struck["id"], rows[struck["id"]]["content_hash"], "Retry", LATER)):
        with pytest.raises(sqlite3.IntegrityError, match="log unavailable"):
            attempt()
    assert dict(store.db.execute("SELECT url,status||':'||rejections FROM items")) == {
        struck["url"]: "rejected:3", failing["url"]: "pending:2", held["url"]: "pending:0", approved["url"]: "pending:0"}
    assert [store.db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            for t in ("analyses", "stories", "rejection_actions", "decision_log")] == [0, 0, 0, 1]


@pytest.mark.parametrize("record", [{"reviews": [1]}, {"reviews": [{"stage": "review"}]}, {"approval": 5}, [1], "text"])
def test_a_damaged_record_or_payload_still_logs_the_decision(store, record):
    intact, broken = item(), item(url="https://example.org/damaged")
    for incoming in (intact, broken):
        store.ingest(incoming, DATE)
    damage_item(store.db, broken["id"], "invalid-utf8")
    with store.db:
        for incoming in (intact, broken):
            decisions.record(store.db, incoming["id"], "held.review.model_hold", LATER, review=record)
        decisions.skip_code(record, verdict("skip", criterion="news_value"))
    assert [e["detail"] for e in logged(store)] == [{"title": item()["title"], "url": item()["url"]}, {"title": None, "url": broken["url"]}]


def run_with(monkeypatch, cfg, store, error=None):
    class Replies:
        calls = 0

        def review(self, candidate, packet, *, coverage=None, verification=False, issue=None, validation_error=None, on_request=None):
            if on_request is not None:
                on_request(1)
                on_request.response_received()
            url = packet["sources"][0]["url"]
            if url.endswith("/fail"):
                raise error
            reply = verdict("skip", criterion="news_value") if url.endswith("/skip") else verdict("hold") if url.endswith("/hold") else verdict()
            return review.validate_review(reply, packet)

    built = []
    monkeypatch.setattr(cli, "Analyzer", lambda *a, **kw: contextlib.nullcontext(Writer()))
    monkeypatch.setattr(cli, "Reviewer", lambda *a, **kw: contextlib.nullcontext(Replies()))
    monkeypatch.setattr(cli, "build", lambda *a: built.append(True) or {})
    report = cli.run(cfg, store)
    assert built == [True]
    return report


@pytest.mark.parametrize("error,code", [
    (AnalysisError("Model evidence quote 1 is not an exact excerpt", code="writer.evidence_not_exact"), "failed.writer.evidence_not_exact"),
    (review.ReviewError("Review response fields do not match schema"), "failed.review.invalid_reply"),
    (review.DegenerateReview(), "failed.review.degenerate_reasons"),
    (AnalysisError("Saved draft source proof is unavailable", code="app.source_proof_unavailable"),
     "failed.app.source_proof_unavailable"),
    (RuntimeError("boom"), "failed.app.unexpected"),
    (AnalysisError("LLM request failed", retryable=True), None),
], ids=["writer", "review", "degenerate-review", "source-proof", "unexpected", "retryable"])
def test_only_the_third_terminal_failure_is_logged(context, monkeypatch, error, code):
    cfg, store = context
    cfg["sources"] = []
    store.ingest(item(url="https://example.org/fail"), DATE)
    failing_id = item_id(store, "https://example.org/fail")
    for _ in range(2):
        store.defer(failing_id, "An earlier invalid draft", cfg["llm"], DATE, terminal=True, code="writer.invalid_output")
    assert logged(store) == []
    report = run_with(monkeypatch, cfg, store, error)
    assert [e["code"] for e in logged(store)] == ([code] if code else [])
    assert code is None or code in decisions.CODES
    assert report["decisions"] == ({code: 1} if code else {}) and report["analysis_failed"] == 1


def test_detail_failures_and_full_run_terminal_decisions(tmp_path, monkeypatch):
    cfg1 = config(tmp_path / "d1", sources=[])
    with Store(cfg1["storage"]["database"]) as store:
        store.ingest(item(url="https://example.org/fail"), DATE)
        for _ in range(2):
            store.defer(item_id(store, "https://example.org/fail"), "An earlier invalid draft", cfg1["llm"], DATE, terminal=True)
        monkeypatch.setattr(decisions, "_detail", lambda *a: (_ for _ in ()).throw(ValueError("unexpected")))
        run_with(monkeypatch, cfg1, store, review.ReviewError("Review response fields do not match schema"))
        assert [(e["code"], e["detail"]) for e in logged(store)] == [("failed.review.invalid_reply", {})]
        assert store.db.execute("SELECT status FROM items").fetchone()[0] == "rejected"
    monkeypatch.undo()

    cfg2 = config(tmp_path / "d2", sources=[])
    with Store(cfg2["storage"]["database"]) as store:
        for name in ("publish", "skip", "hold", "fail", "damaged", "first/fail"):
            store.ingest(item(url="https://example.org/" + name), DATE)
        for _ in range(2):
            store.defer(item_id(store, "https://example.org/fail"), "An earlier invalid reply", cfg2["llm"], DATE, terminal=True)
        damage_item(store.db, item_id(store, "https://example.org/damaged"), "invalid-utf8")
        with store.db:
            decisions.record(store.db, item_id(store, "https://example.org/first/fail"), "operator.retried", DATE)
        before = dict(store.db.execute("SELECT id,status FROM items"))
        report = run_with(monkeypatch, cfg2, store, review.ReviewError("Review response fields do not match schema"))
        changed = {k: st for k, st in store.db.execute("SELECT id,status FROM items") if st != before[k]}
        entries = logged(store)[1:]
        outcome = {"published": ("published",), "ignored": ("skipped",), "rejected": ("held", "failed")}
        assert len(entries) == len(changed) == 5 and {e["item_id"] for e in entries} == set(changed)
        assert all(e["code"].split(".")[0] in outcome[changed[e["item_id"]]] and e["code"] in decisions.CODES for e in entries)
        assert report["decisions"] == dict(Counter(e["code"] for e in entries)) == {
            "failed.app.damaged_item": 1, "failed.review.invalid_reply": 1, "held.review.model_hold": 1,
            "published.new": 1, "skipped.review.news_value": 1}
        assert report["analysis_failed"] == 3


def test_error_codes_name_the_failing_stage(tmp_path, monkeypatch):
    cfg = config(tmp_path, llm={"base_url": "https://llm.example/v1"})
    monkeypatch.setenv(cfg["llm"]["api_key_env"], "test-key")
    replies = []

    class Transport:
        def request(self, method, url, headers=None, json_body=None):
            finished, content = replies.pop(0)
            return Response(200, json.dumps({"choices": [{"finish_reason": finished, "message": {"content": content}}]}).encode(), {}, url)

        def close(self):
            pass

    monkeypatch.setattr("onionflash.llm.HttpClient", lambda *a, **kw: Transport())
    seen = []
    for client in (analyze.Analyzer(cfg), review.Reviewer(cfg)):
        for reply, payload in ((("length", "{}"), {"x": 1}), (("stop", "[1]"), {"x": 1}), (None, {"x": "\ud800"})):
            replies.extend([reply] if reply else [])
            with pytest.raises(AnalysisError) as caught:
                client.complete("prompt", payload, {}, "name")
            seen.append(caught.value.code)
    for attempt in (lambda: tag_notice(item(kind="tag", title=" ")),
                    lambda: validate_analysis(analysis(evidence=["Absent from the source"]), item()),
                    lambda: validate_analysis(analysis(evidence=["short"]), item()),
                    lambda: analyze._writer_schema({"title": "", "content": ""}),
                    lambda: validate_analysis(analysis(publish=False), item())):
        with pytest.raises(AnalysisError) as caught:
            attempt()
        seen.append(caught.value.code)
    assert seen == ["writer.truncated", "writer.invalid_json", "writer.invalid_input",
                    "review.truncated", "review.invalid_json", "review.invalid_input", "app.invalid_tag_name",
                    "writer.evidence_not_exact", "writer.evidence_too_short", "writer.no_literal_evidence", "writer.invalid_output"]
    assert review.ReviewError("Invalid review text").code == "review.invalid_reply"
    assert {"failed." + c for c in [*seen, review.ReviewError.code]} <= decisions.CODES


def test_operator_actions_and_rejected_show_history(context):
    cfg, store = context
    _, failed = seed_rejected(store, 0)
    _, skipped = seed_ignored(store, 1)
    _, other = seed_rejected(store, 2)
    rejection.retry_item(store, failed["id"], failed["content_hash"], "The grounding rule was fixed", LATER)
    rejection.retry_item(store, skipped["id"], skipped["content_hash"], "Worth another look", LATER)
    rejection.dismiss_item(store, other["id"], other["content_hash"], "Routine discussion", LATER)
    with pytest.raises(ValueError):
        rejection.retry_item(store, other["id"], "0" * 64, "A stale hash is refused", LATER)
    entries = logged(store)
    assert [e["code"] for e in entries[:3]] == ["failed.app.unexpected", "skipped.review.news_value", "failed.app.unexpected"]
    assert [(e["code"], e["item_id"], e["decided_at"], e["detail"]["reason"], e["detail"]["before_status"]) for e in entries[3:]] == [
        ("operator.retried", failed["id"], LATER, "The grounding rule was fixed", "rejected"),
        ("operator.reconsidered", skipped["id"], LATER, "Worth another look", "ignored"),
        ("operator.dismissed", other["id"], LATER, "Routine discussion", "rejected")]
    assert entries[3]["detail"]["before_error"] == failed["last_error"]

    row = pending(store, item(url="https://example.org/recollected"))
    run(cfg, store, row, Writer(), Reviewer(verdict("hold")))
    store.ingest(item(url="https://example.org/recollected", content=item()["content"] + " Edited.", updated_at=LATER), LATER)
    shown = rejection.show_item(store, row["id"])
    assert (shown["status"], shown["rejection_reason"]) == ("pending", None)
    [entry] = shown["decisions"]
    assert (entry["code"], entry["content_hash"]) == ("held.review.model_hold", row["content_hash"])
    assert set(entry["detail"]["criteria"]) == {"operational_advice"}
    revised = next(r for r in store.pending(5, LATER) if r["id"] == row["id"])
    assert run(cfg, store, revised, Writer(), Reviewer(verdict()))["status"] == "published"
    assert [(e["code"], e["content_hash"]) for e in rejection.show_item(store, row["id"])["decisions"]] == [
        ("published.new", revised["content_hash"]), ("held.review.model_hold", row["content_hash"])]


def test_summary_list_filters_cli_commands_and_public_privacy(tmp_path, capsys):
    cfg = config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        assert decisions.summary(store.db, DATE)["feed"] == {
            "path": "feed.xml", "bytes": None, "limit_bytes": decisions.FEED_LIMIT_BYTES, "action": None}
        stamps = ["2026-10-01T00:00:00Z", *(f"2026-11-0{day}T00:00:00Z" for day in range(5, 9))]
        for n, stamp in enumerate(stamps):
            store.ingest(item(url=f"https://example.org/damaged/{n}"), DATE)
            store.reject(item_id(store, f"https://example.org/damaged/{n}"), "Stored source item is damaged",
                         "failed.app.damaged_item", stamp)
        store.ingest(item(url="https://example.org/retrying"), DATE)
        store.defer(item_id(store, "https://example.org/retrying"), "LLM request failed", cfg["llm"], DATE)
        store.ingest(item(url="https://example.org/published", title="A published report"), DATE)
        finish_reviewed(store, store.pending(1, DATE)[0], analysis(), "seed", DATE)
        story_id = store.stories()[0]["id"]
        editorial.correct(store.db, story_id, {"why_it_matters": ""}, reason="Removed unsupported impact.",
                          expect_hash=editorial.show(store.db, story_id)["hash"], observed=LATER)
        store.ingest(item(url="https://example.org/queued"), DATE)
        cli.build(cfg, store)
        result = decisions.summary(store.db, "2026-11-02T00:00:00Z")
        damaged_ids = [item_id(store, f"https://example.org/damaged/{n}") for n in range(5)]
        assert result["outcomes"] == {"failed": 4, "published": 1}
        assert result["codes"] == {"failed.app.damaged_item": 4, "published.new": 1}
        assert result["sources"] == {"test": {"failed": 4, "published": 1}}
        assert [ex["item_id"] for ex in result["examples"]["failed.app.damaged_item"]] == damaged_ids[:1:-1]
        assert result["examples"]["failed.app.damaged_item"][0]["error"] == "Stored source item is damaged"
        assert result["examples"]["published.new"][0]["title"] == "A published report"
        awaiting = result["awaiting_operator"]
        assert awaiting["rejected"] == 5 and [e["item_id"] for e in awaiting["items"]] == damaged_ids
        assert awaiting["items"][0]["code"] == "failed.app.damaged_item" and awaiting["held_updates"] == []
        assert (result["retrying"], result["story_actions"], result["writer_clears"]) == (1, {"correct": 1}, 0)
        assert decisions.summary(store.db, "2026-11-11T00:00:00Z")["story_actions"] == {}
        assert result["feed"]["bytes"] == (tmp_path / "public" / "feed.xml").stat().st_size and result["feed"]["action"] is None
        for size, action in ((decisions.FEED_SPLIT_BYTES - 1, None), (decisions.FEED_SPLIT_BYTES, "ACTION: split the feeds by year")):
            with store.db:
                store.db.execute("UPDATE public_artifacts SET size=? WHERE path='feed.xml'", (size,))
            assert decisions.summary(store.db, DATE)["feed"]["action"] == action

    with Store(tmp_path / "list.db") as store:
        code_list = ["skipped.review.news_value", "skipped.verification.news_value", "held.review.model_hold", "operator.retried"]
        for n, code in enumerate(code_list):
            inc = item(url=f"https://example.org/{n}", source_id="odd" if n % 2 else "even")
            store.ingest(inc, DATE)
            with store.db:
                decisions.record(store.db, inc["id"], code, f"2026-11-0{n + 1}T00:00:00Z")
        listed = lambda since="2026-11-01T00:00:00Z", **opt: [e["code"] for e in decisions.list_entries(store.db, since, **opt)["decisions"]]
        assert listed() == code_list[::-1] and listed("2026-11-03T00:00:00Z") == code_list[:1:-1]
        assert listed(code="skipped") == code_list[1::-1] and listed(code="skipped.review") == code_list[:1]
        assert listed(code="skipped.rev") == listed(code="skipped_review") == [] and listed(code=code_list[2]) == code_list[2:3]
        assert listed(source="odd") == [code_list[3], code_list[1]]
        first = decisions.list_entries(store.db, "2026-11-01T00:00:00Z", limit=3)
        rest = decisions.list_entries(store.db, "2026-11-01T00:00:00Z", limit=3, after=first["next_cursor"])
        assert [e["code"] for e in first["decisions"] + rest["decisions"]] == code_list[::-1] and rest["next_cursor"] is None
        assert first["decisions"][0]["detail"] == {"title": item()["title"], "url": "https://example.org/3"}
        for opt in ({"limit": 0}, {"limit": 201}, {"code": "Held"}, {"code": "held..review"}, {"after": 0}):
            with pytest.raises(ValueError):
                decisions.list_entries(store.db, DATE, **opt)
        assert decisions.window("7d", LATER) == "2026-11-03T12:00:00Z" and decisions.window("12h", LATER) == "2026-11-10T00:00:00Z"
        assert decisions.window("2026-11-01T00:00:00+01:00") == "2026-10-31T23:00:00Z"
        for text in ("7", "0d", "7w", "soon", None):
            with pytest.raises(ValueError):
                decisions.window(text)

    (tmp_path / "cli").mkdir(exist_ok=True)
    path, cli_cfg = write_config(tmp_path / "cli")
    with Store(cli_cfg["storage"]["database"]) as store:
        store.ingest(inc := item(title="A report \u202e with a bidi control"), DATE)
        with store.db:
            decisions.record(store.db, inc["id"], "operator.retried", after(-25 * 3600))
            decisions.record(store.db, inc["id"], "held.review.model_hold", now_iso())
    assert cli.main(["status", "--config", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["decisions_24h"] == {"held": 1}
    with cli.run_lock(cli_cfg["storage"]["database"]) as acquired:
        assert acquired
        assert cli.main(["decisions", "list", "--config", str(path), "--code", "held"]) == 0
        out = capsys.readouterr().out
        assert "\u202e" not in out and json.loads(out)["decisions"][0]["detail"]["title"] == "A report \u202e with a bidi control"
        assert cli.main(["decisions", "summary", "--config", str(path), "--since", "1h"]) == 0
        assert json.loads(capsys.readouterr().out)["codes"] == {"held.review.model_hold": 1}
    assert cli.main(["decisions", "summary", "--config", str(path), "--since", "soon"]) == 2
    capsys.readouterr()

    priv_cfg = config(tmp_path / "priv")
    with Store(priv_cfg["storage"]["database"]) as store:
        reply = verdict("skip", criterion="news_value")
        reply["criteria"]["news_value"]["reason"] = "Zebra marker reason."
        run(priv_cfg, store, pending(store, item(title="Quokka marker title")), Writer(), Reviewer(reply))
        sep = item(url="https://example.org/news/2", title="A separate report",
                   content="The operator reported a plausible compromise in a separate report.")
        run(priv_cfg, store, pending(store, sep), Writer(), Reviewer(verdict()))
        cli.build(priv_cfg, store)
        assert [e["code"] for e in logged(store)] == ["skipped.review.news_value", "published.new"]
        assert "Zebra marker reason." in logged(store)[0]["detail"]["criteria"]["news_value"]
        published = [p.read_bytes() for p in Path(priv_cfg["storage"]["output_dir"]).rglob("*") if p.is_file()]
        assert published and not any(m in t for t in published for m in (b"Zebra marker", b"Quokka marker", b"skipped.review", b"published.new"))


def test_the_docs_list_exactly_the_decision_codes():
    text = (Path(__file__).parents[1] / "docs" / "DECISIONS.md").read_text(encoding="utf-8")
    assert set(re.findall(r"^\| `([a-z_.]+)` \|", text, re.M)) == decisions.CODES
