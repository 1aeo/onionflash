"""Every terminal decision is logged once, privately, in the transaction that applies it."""

from collections import Counter
import contextlib
import json
import logging
from pathlib import Path
import re
import sqlite3

import pytest

from helpers import (
    DATE, LATER, TOR_WORK_ITEM_URL, FakeClient, FakeLLM, Reviewer, Writer, analysis, completion, damage_item,
    decision_codes, decision_rows, editorial_act, enrich_with_client, gitlab_source, gql_note,
    gql_notes_response, invoke_cli, item, make_config, patch_cli_pipeline, pending, queued_row,
    raise_once, run_gate as run, seed_ignored, seed_legacy, seed_rejected, seed_story, tag, verdict, write_toml,
)
from onionflash import analyze, candidate, cli, comments, decisions, editorial, rejection, review, review_gate
from onionflash.analyze import AnalysisError, tag_notice, validate_analysis
from onionflash.config import load_config
from onionflash.llm import CompletionDeferred
from onionflash.store import _RETENTION_SCHEMA, Store, compact_retained_rows, select_retention_candidates
from onionflash.util import after, now_iso


def _item_id(store, url):
    return store.db.execute("SELECT id FROM items WHERE url=?", (url,)).fetchone()[0]


def _both_editorial():
    return verdict("skip", criteria=("news_value", "new_information"))


@pytest.mark.parametrize("replies,code,chain", [
    ([verdict()], "published.new", ["review:approve", "verification:approve"]),
    ([verdict("skip", criterion="news_value")], "skipped.review.news_value", ["review:skip"]),
    ([verdict("revise", repair={"why_it_matters": ""}, criterion="news_value"), _both_editorial()],
     "skipped.verification.new_information_and_news_value", ["review:revise", "verification:skip"]),
    ([verdict("hold")], "held.review.model_hold", ["review:hold"]),
    ([verdict("revise", repair={"why_it_matters": ""}), verdict("hold")], "held.verification.model_hold",
     ["review:revise", "verification:hold"]),
    ([verdict("revise", repair={"title": ""})], "held.review.unusable_repair", ["review:revise"]),
], ids=["approve", "skip", "verified-skip", "hold", "verification-refusal", "unusable-repair"])
def test_each_gate_outcome_writes_one_decision_row(context, replies, code, chain):
    """Record one structured `decision_log` row matching the terminal gate outcome and verdict chain."""
    cfg, store = context
    row = pending(store)
    run(cfg, store, row, Writer(), Reviewer(*replies))
    [entry] = decision_rows(store)
    status, story_id, error = store.db.execute("SELECT status,story_id,last_error FROM items").fetchone()
    assert (entry["code"], entry["subject"], entry["item_id"], entry["content_hash"], entry["source_id"], entry["story_id"]) == (
        code, row["id"], row["id"], row["content_hash"], "test", story_id)
    assert code in decisions.CODES and entry["detail"]["verdicts"] == chain and entry["detail"]["title"] == item()["title"]
    assert bool(entry["detail"].get("criteria")) == (not code.startswith("published."))
    if code.startswith("held."):
        assert status == "rejected" and error == "Final review held: " + review_gate.HOLDS[code.rsplit(".", 1)[1]]


def test_coded_holds_missing_sources_and_locked_updates(context):
    """Log coded gate holds (`tag_repair`, `repeat_hold`, `missing_sources`, `story_locked`) accurately."""
    cfg, store = context
    tag_item = item(url="https://example.org/tags/tor-0.4.9.16", title="tor-0.4.9.16", kind="tag", content="")
    run(cfg, store, pending(store, tag_item), Writer(tag_notice(tag_item)),
        Reviewer(verdict("revise", repair={"title": "Tor 0.4.9.16 released"})))
    run(cfg, store, pending(store), Writer(), Reviewer(verdict("hold")))
    store.ingest(item(content=item()["content"] + " Edited."), DATE)
    assert run(cfg, store, store.pending(1, LATER)[0], Writer(), Reviewer(), allow_network=False)["status"] == "deferred"
    store.ingest(item(), DATE)
    assert run(cfg, store, store.pending(1, LATER)[0], Writer(), Reviewer())["status"] == "held"
    assert decision_codes(store) == ["held.review.tag_repair", "held.review.model_hold", "held.gate.repeat_hold"]

    orig = item(url="https://example.org/miss", content="Missing source body text long enough to cluster across URLs. " * 5, updated_at="2026-11-09T12:00:00Z")
    seed_legacy(store, orig, analysis(evidence=["Missing source body text long enough"]))
    with store.db:
        store.db.execute("UPDATE items SET payload=json_remove(payload,'$.content') WHERE url=?", (orig["url"],))
    row_m = pending(store, item(url="https://example.org/miss-mirror", source_id="mirror", content=orig["content"]))
    assert run(cfg, store, row_m, Writer(), Reviewer())["status"] == "held"
    last = decision_rows(store)[-1]
    assert (last["code"], last["item_id"]) == ("held.gate.missing_sources", row_m["id"])

    orig_u, story_id = seed_legacy(store, item(url="https://example.org/lock-u", content="Locked story body text long enough. " * 3),
                                   analysis(evidence=["Locked story body text long enough."]))
    rev = {**orig_u, "content": orig_u["content"] + " A later report.", "updated_at": LATER}
    assert run(cfg, store, pending(store, rev), Writer(), Reviewer(verdict()))["status"] == "published"
    editorial_act(editorial.correct, store, story_id, {"why_it_matters": "Operator-reviewed wording."},
                  reason="Corrected wording.", observed=LATER)
    later = {**rev, "content": rev["content"] + " Another report.", "updated_at": "2026-11-10T13:00:00Z"}
    assert run(cfg, store, pending(store, later), Writer(), Reviewer())["status"] == "locked"
    assert [(e["code"], e["story_id"]) for e in decision_rows(store)[-2:]] == [
        ("published.update", story_id), ("held.gate.story_locked", story_id)
    ]
    assert decisions.summary(store.db, DATE)["awaiting_operator"]["held_updates"] == [{"story_id": story_id, "held_updates": 1, "locked": True}]
    editorial_act(editorial.unlock, store, story_id, reason="Automation resumes.", observed="2026-11-10T14:00:00Z")
    assert editorial.show(store.db, story_id)["held_updates"] == 0
    assert decisions.summary(store.db, DATE)["awaiting_operator"]["held_updates"] == []
    requeued = queued_row(store, orig_u["id"], "2026-11-10T14:00:00Z")
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
    """Keep legacy `held_updates` counters visible until an unlock or a published update clears them."""
    cfg, store = context
    original, story_id = seed_legacy(store)
    editorial_act(editorial.correct, store, story_id, {"why_it_matters": "Operator-reviewed wording."},
                  reason="Corrected wording.", observed=LATER)
    assert decisions.summary(store.db, DATE)["awaiting_operator"]["held_updates"] == []
    with store.db:
        editorial.record_held(store.db, story_id)
    assert decisions.summary(store.db, DATE)["awaiting_operator"]["held_updates"] == [{"story_id": story_id, "held_updates": 1, "locked": True}]
    editorial_act(editorial.unlock, store, story_id, reason="Automation resumes.", observed="2026-11-10T14:00:00Z")
    assert editorial.show(store.db, story_id)["held_updates"] == 0
    assert decisions.summary(store.db, DATE)["awaiting_operator"]["held_updates"] == []
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
    """Preserve full `verdicts` and `criteria` chains when resuming interrupted commits via cached receipts."""
    cfg, store = context

    def _crash_commit(target, *verdicts):
        with monkeypatch.context() as scoped:
            scoped.setattr(store, "commit_candidate", raise_once(RuntimeError("crash")))
            with pytest.raises(RuntimeError):
                run(cfg, store, target, Writer(), Reviewer(*verdicts))

    row = pending(store)
    _crash_commit(row, verdict())
    assert decision_rows(store) == []
    assert run(cfg, store, row, Writer(), Reviewer(), allow_network=False)["cache_hit"]
    assert [(e["code"], e["detail"]["verdicts"]) for e in decision_rows(store)] == [
        ("published.new", ["review:approve", "verification:approve"])]

    row2 = pending(store, item(url="https://example.org/off", authority="official", kind="feed"))
    _crash_commit(row2, verdict("skip", criterion="news_value"), _both_editorial())
    for _ in range(3):
        store.defer(row2["id"], "Unexpected error", cfg["llm"], LATER, terminal=True)
    rejection.retry_item(store, row2["id"], row2["content_hash"], "Retry the item", LATER)
    assert run(cfg, store, store.pending(1, LATER)[0], Writer(), Reviewer(), allow_network=False)["cache_hit"]
    assert decision_codes(store)[1:] == [
        "failed.app.unexpected", "operator.retried", "skipped.verification.new_information_and_news_value"]
    detail = decision_rows(store)[-1]["detail"]
    assert (detail["verdicts"], list(detail["criteria"])) == (["review:skip", "verification:skip"], ["new_information", "news_value"])

    partial_review = {"stage": "review", "result": verdict("revise", repair={"why_it_matters": ""})}
    cached_skip = {"stage": "verification", "result": _both_editorial()}
    reused_record = {"reviews": [partial_review], "approval": {"reviews": [partial_review, cached_skip]}}
    assert decisions.skip_code(reused_record, _both_editorial()) == "skipped.verification.new_information_and_news_value"
    with store.db:
        decisions.record(store.db, row2["id"], "skipped.verification.new_information_and_news_value", LATER, review=reused_record)
    reused_detail = decision_rows(store)[-1]["detail"]
    assert reused_detail["verdicts"] == ["review:revise", "verification:skip"]
    assert list(reused_detail["criteria"]) == ["new_information", "news_value"]


def test_decision_rows_roll_back_with_their_outcome(context):
    """Roll back item, story, and audit writes atomically if `decision_log` insertion fails."""
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
    """Record fallback decision rows even when review records or stored item payloads are malformed."""
    intact, broken = item(), item(url="https://example.org/damaged")
    for incoming in (intact, broken):
        store.ingest(incoming, DATE)
    damage_item(store.db, broken["id"], "invalid-utf8")
    with store.db:
        for incoming in (intact, broken):
            decisions.record(store.db, incoming["id"], "held.review.model_hold", LATER, review=record)
        decisions.skip_code(record, verdict("skip", criterion="news_value"))
    assert [e["detail"] for e in decision_rows(store)] == [{"title": item()["title"], "url": item()["url"]}, {"title": None, "url": broken["url"]}]


def _run_with(monkeypatch, cfg, store, error=None):
    class _Replies:
        calls = 0

        def review(self, candidate, packet, *, coverage=None, verification=False, issue=None, on_request=None):
            """Route scripted review outcomes or errors based on the source URL suffix."""
            if on_request is not None:
                on_request(1)
            url = packet["sources"][0]["url"]
            if url.endswith("/fail"):
                raise error
            reply = verdict("skip", criterion="news_value") if url.endswith("/skip") else verdict("hold") if url.endswith("/hold") else verdict()
            return review.validate_review(reply, packet)

    built = []
    patch_cli_pipeline(
        monkeypatch,
        now=None,
        analyzer=lambda *a, **kw: contextlib.nullcontext(Writer()),
        reviewer=lambda *a, **kw: contextlib.nullcontext(_Replies()),
        build=lambda *a: built.append(True) or {},
    )
    report = cli.run(cfg, store)
    assert built == [True]
    return report


@pytest.mark.parametrize("error,code", [
    (AnalysisError("Model evidence quote 1 is not an exact excerpt", code="writer.evidence_not_exact"), "failed.writer.evidence_not_exact"),
    (review.ReviewError("Review response fields do not match schema"), "failed.review.invalid_reply"),
    (AnalysisError("Saved draft source proof is unavailable", code="app.source_proof_unavailable"),
     "failed.app.source_proof_unavailable"),
    (RuntimeError("boom"), "failed.app.unexpected"),
    (AnalysisError("LLM request failed", retryable=True), None),
], ids=["writer", "review", "source-proof", "unexpected", "retryable"])
def test_only_the_third_terminal_failure_is_logged(context, monkeypatch, error, code):
    """Log `failed.*` decision codes only when an item reaches its third terminal strike."""
    cfg, store = context
    cfg["sources"] = []
    store.ingest(item(url="https://example.org/fail"), DATE)
    failing_id = _item_id(store, "https://example.org/fail")
    for _ in range(2):
        store.defer(failing_id, "An earlier invalid draft", cfg["llm"], DATE, terminal=True, code="writer.invalid_output")
    assert decision_rows(store) == []
    report = _run_with(monkeypatch, cfg, store, error)
    assert decision_codes(store) == ([code] if code else [])
    assert code is None or code in decisions.CODES
    assert report["decisions"] == ({code: 1} if code else {}) and report["analysis_failed"] == 1


def test_detail_failures_and_full_run_terminal_decisions(tmp_path, monkeypatch):
    """Survive `_detail` exceptions and summarize all terminal decisions emitted during `cli.run`."""
    cfg1 = make_config(tmp_path / "d1", sources=[])
    with Store(cfg1["storage"]["database"]) as store:
        store.ingest(item(url="https://example.org/fail"), DATE)
        for _ in range(2):
            store.defer(_item_id(store, "https://example.org/fail"), "An earlier invalid draft", cfg1["llm"], DATE, terminal=True)
        monkeypatch.setattr(decisions, "_detail", raise_once(ValueError("unexpected")))
        _run_with(monkeypatch, cfg1, store, review.ReviewError("Review response fields do not match schema"))
        assert [(e["code"], e["detail"]) for e in decision_rows(store)] == [("failed.review.invalid_reply", {})]
        assert store.db.execute("SELECT status FROM items").fetchone()[0] == "rejected"
    monkeypatch.undo()

    cfg2 = make_config(tmp_path / "d2", sources=[])
    with Store(cfg2["storage"]["database"]) as store:
        for name in ("publish", "skip", "hold", "fail", "damaged", "first/fail"):
            store.ingest(item(url="https://example.org/" + name), DATE)
        for _ in range(2):
            store.defer(_item_id(store, "https://example.org/fail"), "An earlier invalid reply", cfg2["llm"], DATE, terminal=True)
        damage_item(store.db, _item_id(store, "https://example.org/damaged"), "invalid-utf8")
        with store.db:
            decisions.record(store.db, _item_id(store, "https://example.org/first/fail"), "operator.retried", DATE)
        before = dict(store.db.execute("SELECT id,status FROM items"))
        report = _run_with(monkeypatch, cfg2, store, review.ReviewError("Review response fields do not match schema"))
        changed = {k: st for k, st in store.db.execute("SELECT id,status FROM items") if st != before[k]}
        entries = decision_rows(store)[1:]
        outcome = {"published": ("published",), "ignored": ("skipped",), "rejected": ("held", "failed")}
        assert len(entries) == len(changed) == 5 and {e["item_id"] for e in entries} == set(changed)
        assert all(e["code"].split(".")[0] in outcome[changed[e["item_id"]]] and e["code"] in decisions.CODES for e in entries)
        assert report["decisions"] == dict(Counter(e["code"] for e in entries)) == {
            "failed.app.damaged_item": 1, "failed.review.invalid_reply": 1, "held.review.model_hold": 1,
            "published.new": 1, "skipped.review.news_value": 1}
        assert report["analysis_failed"] == 3


def test_error_codes_name_the_failing_stage(tmp_path, monkeypatch):
    """Tag `AnalysisError` and `ReviewError` exceptions with stage-specific `decisions.CODES`."""
    cfg = make_config(tmp_path, llm={"base_url": "https://llm.example/v1"})
    monkeypatch.setenv(cfg["llm"]["api_key_env"], "test-key")
    llm_double = FakeLLM(
        completion({}, finish_reason="length"),
        completion([1]),
        completion({}, finish_reason="length"),
        completion([1]),
    )
    monkeypatch.setattr("onionflash.llm.HttpClient", lambda *a, **kw: llm_double)
    seen = []
    for client in (analyze.Analyzer(cfg), review.Reviewer(cfg)):
        for payload in ({"x": 1}, {"x": 1}, {"x": "\ud800"}):
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
    """Log operator retry/reconsider/dismiss actions and expose item decision history in `show_item`."""
    cfg, store = context
    _, failed = seed_rejected(store, 0)
    _, skipped = seed_ignored(store, 1)
    _, other = seed_rejected(store, 2)
    rejection.retry_item(store, failed["id"], failed["content_hash"], "The grounding rule was fixed", LATER)
    rejection.retry_item(store, skipped["id"], skipped["content_hash"], "Worth another look", LATER)
    rejection.dismiss_item(store, other["id"], other["content_hash"], "Routine discussion", LATER)
    with pytest.raises(ValueError):
        rejection.retry_item(store, other["id"], "0" * 64, "A stale hash is refused", LATER)
    entries = decision_rows(store)
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
    revised = queued_row(store, row["id"], LATER)
    assert run(cfg, store, revised, Writer(), Reviewer(verdict()))["status"] == "published"
    assert [(e["code"], e["content_hash"]) for e in rejection.show_item(store, row["id"])["decisions"]] == [
        ("published.new", revised["content_hash"]), ("held.review.model_hold", row["content_hash"])]


def test_summary_list_filters_cli_commands_and_public_privacy(tmp_path, capsys):
    """Filter and paginate `decisions`, report feed size alerts, and keep private reasons off public files."""
    cfg = make_config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        assert decisions.summary(store.db, DATE)["feed"] == {
            "path": "feed.xml", "bytes": None, "limit_bytes": decisions.FEED_LIMIT_BYTES, "action": None}
        stamps = ["2026-10-01T00:00:00Z", *(f"2026-11-0{day}T00:00:00Z" for day in range(5, 9))]
        for n, stamp in enumerate(stamps):
            store.ingest(item(url=f"https://example.org/damaged/{n}"), DATE)
            store.reject(_item_id(store, f"https://example.org/damaged/{n}"), "Stored source item is damaged",
                         "failed.app.damaged_item", stamp)
        store.ingest(item(url="https://example.org/retrying"), DATE)
        store.defer(_item_id(store, "https://example.org/retrying"), "LLM request failed", cfg["llm"], DATE)
        story_id = seed_story(store, item(url="https://example.org/published", title="A published report"),
                              analysis(), key="seed", at=DATE)["id"]
        editorial_act(editorial.correct, store, story_id, {"why_it_matters": ""},
                      reason="Removed unsupported impact.", observed=LATER)
        store.ingest(item(url="https://example.org/queued"), DATE)
        cli.build(cfg, store)
        result = decisions.summary(store.db, "2026-11-02T00:00:00Z")
        damaged_ids = [_item_id(store, f"https://example.org/damaged/{n}") for n in range(5)]
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

    path = write_toml(tmp_path / "cli")
    cli_cfg = load_config(path)
    with Store(cli_cfg["storage"]["database"]) as store:
        store.ingest(inc := item(title="A report \u202e with a bidi control"), DATE)
        with store.db:
            decisions.record(store.db, inc["id"], "operator.retried", after(-25 * 3600))
            decisions.record(store.db, inc["id"], "held.review.model_hold", now_iso())
    assert invoke_cli(capsys, "status", "--config", path)["decisions_24h"] == {"held": 1}
    with cli.run_lock(cli_cfg["storage"]["database"]) as acquired:
        assert acquired
        assert cli.main(["decisions", "list", "--config", str(path), "--code", "held"]) == 0
        out = capsys.readouterr().out
        assert "\u202e" not in out and json.loads(out)["decisions"][0]["detail"]["title"] == "A report \u202e with a bidi control"
        assert invoke_cli(capsys, "decisions", "summary", "--config", path, "--since", "1h")["codes"] == {"held.review.model_hold": 1}
    invoke_cli(capsys, "decisions", "summary", "--config", path, "--since", "soon", expected=2)

    priv_cfg = make_config(tmp_path / "priv")
    with Store(priv_cfg["storage"]["database"]) as store:
        run(priv_cfg, store, pending(store, item(title="Quokka marker title")), Writer(),
            Reviewer(verdict("skip", criterion="news_value", reason="Zebra marker reason.")))
        sep = item(url="https://example.org/news/2", title="A separate report",
                   content="The operator reported a plausible compromise in a separate report.")
        run(priv_cfg, store, pending(store, sep), Writer(), Reviewer(verdict()))
        cli.build(priv_cfg, store)
        assert decision_codes(store) == ["skipped.review.news_value", "published.new"]
        assert "Zebra marker reason." in decision_rows(store)[0]["detail"]["criteria"]["news_value"]
        published = [p.read_bytes() for p in Path(priv_cfg["storage"]["output_dir"]).rglob("*") if p.is_file()]
        assert published and not any(m in t for t in published for m in (b"Zebra marker", b"Quokka marker", b"skipped.review", b"published.new"))


def test_the_docs_list_exactly_the_decision_codes():
    """Keep `docs/DECISIONS.md` synchronized with `onionflash.decisions.CODES`."""
    text = (Path(__file__).parents[1] / "docs" / "DECISIONS.md").read_text(encoding="utf-8")
    assert set(re.findall(r"^\| `([a-z_.]+)` \|", text, re.M)) == decisions.CODES


def test_ingest_preserves_retention_compacted_items_until_newer_revision(context, caplog):
    """Preserve compacted ignored items on unchanged or stale polls while re-queueing newer revisions."""
    cfg, store = context
    timeline = item(
        url="https://metrics.torproject.org/torperf.html#event-1",
        source_entry_id="timeline-event-1",
        kind="metrics_timeline", product="network", authority="telemetry", labels=[],
        published_at=DATE, updated_at=DATE,
    )
    row = pending(store, timeline)
    assert run(cfg, store, row, Writer(), Reviewer(verdict("skip", criterion="news_value")))["status"] == "ignored"
    records, over = select_retention_candidates(
        store.db, cutoff=LATER, batch_size=10, max_bundle_bytes=100_000, base_overhead=0,
    )
    assert len(records) == 1 and over == 0
    counts = compact_retained_rows(
        store.db, records, uploaded_key="archive/batch.jsonl.zst",
        uploaded_sha256="a" * 64, archived_at=LATER, destination_json="{}",
    )
    assert counts["items_compacted"] == 1
    assert "content" not in json.loads(store.db.execute("SELECT payload FROM items WHERE id=?", (row["id"],)).fetchone()[0])

    with caplog.at_level(logging.WARNING, logger="onionflash.store"):
        assert store.ingest(dict(timeline), LATER) is False
        stale = {**timeline, "content": "Older snapshot text.", "updated_at": "2026-11-07T12:00:00Z"}
        assert store.ingest(stale, LATER) is False
    assert caplog.text == ""
    status_after, payload_after = store.db.execute("SELECT status,payload FROM items WHERE id=?", (row["id"],)).fetchone()
    assert status_after == "ignored" and "content" not in json.loads(payload_after)
    assert select_retention_candidates(
        store.db, cutoff="2026-11-12T00:00:00Z", batch_size=10, max_bundle_bytes=100_000, base_overhead=0,
    ) == ([], 0)

    newer = {**timeline, "content": "Updated timeline event details.", "updated_at": LATER}
    assert store.ingest(newer, LATER) is True
    status_new, payload_new = store.db.execute("SELECT status,payload FROM items WHERE id=?", (row["id"],)).fetchone()
    assert status_new == "pending" and json.loads(payload_new)["content"] == "Updated timeline event details."


def test_cli_run_stops_cleanly_when_process_item_raises_completion_deferred(context, monkeypatch):
    """Stop the pending-item loop without strikes when `process_item` raises `CompletionDeferred`."""
    cfg, store = context
    cfg["sources"] = []
    for suffix in ("deferred-1", "deferred-2"):
        store.ingest(item(url=f"https://example.org/{suffix}"), DATE)
    visited = []

    def _defer_first(_cfg, _store, row, *_args, **_kwargs):
        visited.append(row["id"])
        raise CompletionDeferred("Run budget reached")

    patch_cli_pipeline(monkeypatch, now=LATER, analyzer=Writer.factory(), reviewer=Reviewer.factory())
    monkeypatch.setattr(cli, "process_item", _defer_first)
    report = cli.run(cfg, store)
    assert report["budget_reached"] is True and report["analysis_failed"] == 0 and len(visited) == 1
    rows = store.db.execute("SELECT status,attempts,rejections,last_error FROM items ORDER BY id").fetchall()
    assert [tuple(r) for r in rows] == [("pending", 0, 0, None), ("pending", 0, 0, None)]


@pytest.mark.parametrize("kwargs,message", [
    ({"code": 123}, "Code must be a decision code"),
    ({"code": ["held"]}, "Code must be a decision code"),
    ({"source": 123}, "Source ID must be a string"),
    ({"source": ["test"]}, "Source ID must be a string"),
])
def test_list_entries_rejects_non_string_code_and_source_filters(store, kwargs, message):
    """Raise `ValueError` when `decisions.list_entries` receives non-string `code` or `source` filters."""
    with pytest.raises(ValueError, match=message):
        decisions.list_entries(store.db, DATE, **kwargs)


def test_compacted_gitlab_issue_preserves_comments_rehydrates_and_validates_locators(tmp_path, caplog):
    """Preserve compacted GitLab comments, rehydrate descriptions for enrichment, and validate archive locators."""
    src = gitlab_source()
    cfg = make_config(tmp_path, sources=[src], comments={"enabled": True})
    rest_issue = lambda **kw: item(source_id=src["id"], url=TOR_WORK_ITEM_URL, kind="gitlab_issue", **kw)
    with Store(cfg["storage"]["database"]) as store:
        store.db.executescript(_RETENTION_SCHEMA)
        store.ingest(rest_issue(), DATE)
        note1 = gql_note("1", author="stefani", body="Initial authority observation on consensus fetch.")
        assert enrich_with_client(cfg, store, FakeClient([gql_notes_response([note1])]), DATE)["changed"] == 1
        row = store.pending(1, DATE)[0]
        with store.db:
            store.db.execute("UPDATE items SET status='ignored' WHERE id=?", (row["id"],))
        saved_full = json.loads(store.db.execute("SELECT payload FROM items WHERE id=?", (row["id"],)).fetchone()[0])
        assert len(saved_full["public_comments"]) == 1 and len(saved_full["dirauth_notes"]) == 1
        compacted = {k: v for k, v in saved_full.items() if k != "content"}
        with store.db:
            store.db.execute("UPDATE items SET payload=? WHERE id=?", (json.dumps(compacted), row["id"]))
            store.db.execute(
                "INSERT INTO private_archive_refs VALUES('item',?,?,?,?,?,?)",
                (row["id"], row["content_hash"], "archive/batch-1.jsonl.zst", "b" * 64, LATER, '{"bucket":"cold"}'),
            )

        with caplog.at_level(logging.WARNING, logger="onionflash.store"):
            assert store.ingest(rest_issue(), LATER) is False
            drifted_src = {**src, "url": "https://gitlab.torproject.org/api/v4/projects/tpo%2Fcore%2Ftor/issues"}
            merged_drift = comments.merge_cached_comments(store, rest_issue(), drifted_src, LATER)
            assert store.ingest(merged_drift, LATER) is False
        assert caplog.text == ""
        status_now, payload_now = store.db.execute("SELECT status,payload FROM items WHERE id=?", (row["id"],)).fetchone()
        parsed_now = json.loads(payload_now)
        assert status_now == "ignored" and len(parsed_now["public_comments"]) == 1 and len(parsed_now["dirauth_notes"]) == 1

        with store.db:
            store.db.execute("DELETE FROM comment_cache")
            store.db.execute("UPDATE items SET payload=? WHERE id=?", (json.dumps(compacted), row["id"]))
        bump_at = after(600, LATER)
        merged_bump = comments.merge_cached_comments(store, rest_issue(updated_at=bump_at), src, bump_at)
        assert store.ingest(merged_bump, bump_at) is False
        rehydrated_status, rehydrated_raw = store.db.execute("SELECT status,payload FROM items WHERE id=?", (row["id"],)).fetchone()
        assert rehydrated_status == "ignored" and json.loads(rehydrated_raw)["content"] == rest_issue()["content"]
        note2 = gql_note("2", author="arma", createdAt=bump_at, body="Follow-up note confirming relay behavior.")
        rep = enrich_with_client(cfg, store, FakeClient([gql_notes_response([note1, note2])]), bump_at)
        assert rep["skipped"] == 0 and rep["changed"] == 1
        assert store.db.execute("SELECT status FROM items WHERE id=?", (row["id"],)).fetchone()[0] == "pending"
        assert len(json.loads(store.db.execute("SELECT payload FROM items WHERE id=?", (row["id"],)).fetchone()[0])["public_comments"]) == 2

        for bad_sql in (
            "UPDATE private_archive_refs SET object_key=''",
            "UPDATE private_archive_refs SET object_sha256='short'",
            "UPDATE private_archive_refs SET destination_json='[]'",
            "UPDATE items SET story_id='linked-story'",
            "UPDATE items SET status='pending'",
        ):
            with store.db:
                store.db.execute("DELETE FROM private_archive_refs")
                store.db.execute(
                    "INSERT INTO private_archive_refs VALUES('item',?,?,?,?,?,?)",
                    (row["id"], row["content_hash"], "archive/batch-1.jsonl.zst", "b" * 64, LATER, "{}"),
                )
                store.db.execute("UPDATE items SET status='ignored',story_id=NULL,content_hash=?,payload=? WHERE id=?",
                                 (row["content_hash"], json.dumps(compacted), row["id"]))
                store.db.execute(bad_sql)
            caplog.clear()
            with caplog.at_level(logging.WARNING, logger="onionflash.store"):
                store.ingest(rest_issue(), after(1200, LATER))
            assert "Replacing damaged saved item" in caplog.text


def test_invalid_utf8_and_incomplete_pending_items_fail_closed_without_sqlite_errors(context, monkeypatch):
    """Avoid `sqlite3.OperationalError` on invalid UTF-8 payloads and reject incomplete pending dicts cleanly."""
    cfg, store = context
    cfg["sources"] = []
    secret_body = "PRIVATE_SOURCE_SENTINELValid description text for race probe."
    row = pending(store, item(url="https://example.org/utf8-race", content=secret_body), at=DATE, ready=DATE)
    story_id = seed_story(
        store,
        item(url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/10",
             title="Tor 0.4.9.16 released", content="Tor 0.4.9.16 is now available for operators."),
        analysis(title="Tor 0.4.9.16 released", summary="Tor 0.4.9.16 is now available for operators.",
                 category="release", state="released", tags=["release"],
                 evidence=["Tor 0.4.9.16 is now available for operators."]),
        key="rel-seed", at=DATE,
    )["id"]
    tag_row = pending(store, tag(), at=DATE, ready=DATE)

    with store.db:
        store.db.execute("UPDATE items SET payload=replace(payload,'Valid',CAST(x'fffe' AS TEXT)) WHERE id=?", (row["id"],))
        store.db.execute("UPDATE items SET payload=replace(payload,'Tor',CAST(x'fffe' AS TEXT)) WHERE id=?", (tag_row["id"],))
    with pytest.raises(candidate.StaleCandidate) as exc_req:
        with store.db:
            store.require_pending_item(row, "changed")
    assert "PRIVATE_SOURCE_SENTINEL" not in str(exc_req.value)
    assert store.defer(row["id"], "Model error", cfg["llm"], LATER, expected_row=row) is False
    with pytest.raises(candidate.StaleCandidate):
        store.add_citation(tag_row, story_id, LATER)

    incomplete_payloads = [
        "{}",
        json.dumps({"id": "placeholder", "url": "https://example.org/inc-1", "title": "T", "updated_at": DATE, "kind": "feed", "published_at": DATE}),
        json.dumps({"id": "placeholder", "url": "https://example.org/inc-2", "title": "T", "content": "C", "updated_at": DATE, "kind": "", "published_at": DATE}),
        json.dumps({"id": "placeholder", "url": "https://example.org/inc-3", "title": "T", "content": "C", "updated_at": DATE, "kind": "feed", "published_at": ""}),
    ]
    inc_ids = []
    for idx, raw_json in enumerate(incomplete_payloads):
        r = pending(store, item(url=f"https://example.org/inc-{idx}"), at=DATE, ready=DATE)
        patched = raw_json.replace("placeholder", r["id"]).replace(f"inc-{idx or 1}", f"inc-{idx}")
        with store.db:
            store.db.execute("UPDATE items SET payload=? WHERE id=?", (patched, r["id"]))
        inc_ids.append(r["id"])
    flagged = {entry["id"]: entry for entry in store.pending(20, LATER)}
    for iid in [row["id"], tag_row["id"], *inc_ids]:
        assert flagged[iid] == {"id": iid, "damaged": True}

    patch_cli_pipeline(monkeypatch, now=LATER, analyzer=Writer.factory(), reviewer=Reviewer.factory(), no_build=False)
    report = cli.run(cfg, store)
    assert report["decisions"] == {"failed.app.damaged_item": 6}
    assert report["published_stories"] == 1
    for iid in inc_ids:
        assert tuple(store.db.execute("SELECT status,attempts,rejections FROM items WHERE id=?", (iid,)).fetchone()) == ("rejected", 1, 3)


def test_summary_ignores_non_int_writer_clears_and_preserves_reserved_fields(store):
    """Ignore null, boolean, or string `writer_clears` values and preserve row `item_id` and `decided_at`."""
    inc = item(url="https://example.org/summary-guard")
    store.ingest(inc, DATE)
    bad_details = [
        '{"writer_clears": null}',
        '{"writer_clears": "bad"}',
        '{"writer_clears": true}',
        '{"writer_clears": -3}',
    ]
    with store.db:
        for detail in bad_details:
            store.db.execute(
                "INSERT INTO decision_log(decided_at,subject,item_id,code,detail_json) VALUES(?,?,?,?,?)",
                (DATE, inc["id"], inc["id"], "skipped.review.news_value", detail),
            )
    assert decisions.summary(store.db, DATE)["writer_clears"] == 0

    with store.db:
        store.db.execute(
            "INSERT INTO decision_log(decided_at,subject,item_id,code,detail_json) VALUES(?,?,?,?,?)",
            (LATER, inc["id"], inc["id"], "published.new",
             '{"item_id":"forged-id","decided_at":"1999-01-01T00:00:00Z","writer_clears":2}'),
        )
    res = decisions.summary(store.db, DATE)
    assert res["writer_clears"] == 2
    [example] = res["examples"]["published.new"]
    assert example["item_id"] == inc["id"] and example["decided_at"] == LATER
