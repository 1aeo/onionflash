"""Every terminal decision is logged once, privately, in the transaction that applies it."""

import contextlib
import json
import re
import sqlite3
from collections import Counter
from pathlib import Path

import pytest

from approval_helpers import finish_reviewed, verdict
from onionflash import analyze, cli, decisions, editorial, rejection, review, review_gate
from onionflash.analyze import AnalysisError, tag_notice, validate_analysis
from onionflash.config import load_config
from onionflash.store import Store
from onionflash.transport import Response
from onionflash.util import after, now_iso
from test_core import DATE, analysis, config, damage_item, item
from test_rejections import ignored, rejected
from test_review_gate import LATER, Reviewer, Writer, context, pending, run, seed_legacy  # noqa: F401 (fixture)


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
    ([verdict("revise", repair={"why_it_matters": ""}, criterion="news_value"), both_editorial()],
     "skipped.verification.new_information_and_news_value", ["review:revise", "verification:skip"]),
    ([verdict("hold")], "held.review.model_hold", ["review:hold"]),
    ([verdict("revise", repair={"why_it_matters": ""}), verdict("hold")], "held.verification.model_hold",
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
    assert code in decisions.CODES
    assert entry["detail"]["verdicts"] == chain and entry["detail"]["title"] == item()["title"]
    # Skips and holds keep the failed criteria with the reviewer's reasons; a publication needs none.
    assert bool(entry["detail"].get("criteria")) == (not code.startswith("published."))
    if code.startswith("held."):
        assert status == "rejected" and error == "Final review held: " + review_gate.HOLDS[code.rsplit(".", 1)[1]]


def test_a_tag_repair_and_a_reverted_held_revision_are_coded_holds(context):
    cfg, store = context
    tag = item(url="https://example.org/tags/tor-0.4.9.16", title="tor-0.4.9.16", kind="tag", content="")
    run(cfg, store, pending(store, tag), Writer(tag_notice(tag)),
        Reviewer(verdict("revise", repair={"title": "Tor 0.4.9.16 released"})))
    run(cfg, store, pending(store), Writer(), Reviewer(verdict("hold")))
    store.ingest(item(content=item()["content"] + " Edited."), DATE)  # a revision that is never drafted
    assert run(cfg, store, store.pending(1, LATER)[0], Writer(), Reviewer(), allow_network=False)["status"] == "deferred"
    store.ingest(item(), DATE)
    assert run(cfg, store, store.pending(1, LATER)[0], Writer(), Reviewer())["status"] == "held"
    assert [entry["code"] for entry in logged(store)] == [
        "held.review.tag_repair", "held.review.model_hold", "held.gate.repeat_hold"]


def test_missing_sources_hold_with_its_gate_code(context):
    cfg, store = context
    original = item(content=item()["content"] * 3, updated_at="2026-11-09T12:00:00Z")
    seed_legacy(store, original)
    with store.db:
        store.db.execute("UPDATE items SET payload=json_remove(payload,'$.content') WHERE id=?", (original["id"],))
    row = pending(store, item(url="https://example.org/news/mirror", source_id="mirror", content=original["content"]))
    assert run(cfg, store, row, Writer(), Reviewer())["status"] == "held"
    assert [(entry["code"], entry["item_id"]) for entry in logged(store)] == [("held.gate.missing_sources", row["id"])]


def test_an_update_and_an_update_held_on_a_locked_story_name_their_story(context):
    cfg, store = context
    original, story_id = seed_legacy(store)
    revision = {**original, "content": original["content"] + " A later report.", "updated_at": LATER}
    assert run(cfg, store, pending(store, revision), Writer(), Reviewer(verdict()))["status"] == "published"
    editorial.correct(store.db, story_id, {"why_it_matters": "Operator-reviewed wording."}, reason="Corrected wording.",
                      expect_hash=editorial.show(store.db, story_id)["hash"], observed=LATER)
    later = {**revision, "content": revision["content"] + " Another report.", "updated_at": "2026-11-10T13:00:00Z"}
    assert run(cfg, store, pending(store, later), Writer(), Reviewer())["status"] == "locked"
    # The held update leaves the item mapped to its story; the summary lists the story as waiting.
    assert [(entry["code"], entry["story_id"]) for entry in logged(store)] == [
        ("published.update", story_id), ("held.gate.story_locked", story_id)]
    assert store.db.execute("SELECT status FROM items").fetchone()[0] == "published"
    assert decisions.summary(store.db, DATE)["awaiting_operator"]["held_updates"] == [
        {"story_id": story_id, "held_updates": 1, "locked": True}]
    # Neither unlocking nor a later skip applies the held update; an update published after the hold ends the wait.
    editorial.unlock(store.db, story_id, reason="Automation resumes.", expect_hash=editorial.show(store.db, story_id)["hash"],
                     observed="2026-11-10T14:00:00Z")
    minor = {**later, "content": later["content"] + " A minor note.", "updated_at": "2026-11-10T14:30:00Z"}
    assert run(cfg, store, pending(store, minor), Writer(), Reviewer(verdict("skip", criterion="news_value")))["status"] == "ignored"
    assert (logged(store)[-1]["code"], logged(store)[-1]["story_id"]) == ("skipped.review.news_value", story_id)
    assert decisions.summary(store.db, DATE)["awaiting_operator"]["held_updates"] == [
        {"story_id": story_id, "held_updates": 1, "locked": False}]
    final = {**minor, "content": minor["content"] + " A final report.", "updated_at": "2026-11-10T15:00:00Z"}
    assert run(cfg, store, pending(store, final), Writer(), Reviewer(verdict()))["status"] == "published"
    assert logged(store)[-1]["code"] == "published.update"
    assert decisions.summary(store.db, DATE)["awaiting_operator"]["held_updates"] == []


def test_a_hold_the_log_never_saw_waits_until_an_update_publishes(context):
    cfg, store = context
    original, story_id = seed_legacy(store)  # published before the log existed
    editorial.correct(store.db, story_id, {"why_it_matters": "Operator-reviewed wording."}, reason="Corrected wording.",
                      expect_hash=editorial.show(store.db, story_id)["hash"], observed=LATER)
    assert decisions.summary(store.db, DATE)["awaiting_operator"]["held_updates"] == []  # nothing is held yet
    with store.db:
        editorial.record_held(store.db, story_id)  # as a release without the log holds an update
    assert decisions.summary(store.db, DATE)["awaiting_operator"]["held_updates"] == [
        {"story_id": story_id, "held_updates": 1, "locked": True}]
    editorial.unlock(store.db, story_id, reason="Automation resumes.", expect_hash=editorial.show(store.db, story_id)["hash"],
                     observed="2026-11-10T14:00:00Z")
    revision = {**original, "content": original["content"] + " A later report.", "updated_at": "2026-11-10T15:00:00Z"}
    assert run(cfg, store, pending(store, revision), Writer(), Reviewer(verdict()))["status"] == "published"
    assert decisions.summary(store.db, DATE)["awaiting_operator"]["held_updates"] == []


def test_a_resumed_commit_logs_its_decision_once(context, monkeypatch):
    cfg, store = context
    row = pending(store)
    commit = store.commit_candidate
    monkeypatch.setattr(store, "commit_candidate", lambda *args, **kw: (_ for _ in ()).throw(RuntimeError("crash")))
    with pytest.raises(RuntimeError):
        run(cfg, store, row, Writer(), Reviewer(verdict()))
    monkeypatch.setattr(store, "commit_candidate", commit)
    assert logged(store) == []
    assert run(cfg, store, row, Writer(), Reviewer(), allow_network=False)["cache_hit"]
    assert [(entry["code"], entry["detail"]["verdicts"]) for entry in logged(store)] == [
        ("published.new", ["review:approve", "verification:approve"])]


def test_a_commit_from_a_reused_receipt_logs_the_reviews_behind_it(context, monkeypatch):
    cfg, store = context
    # An official item whose news value alone fails is verified before it can end; this verification also
    # finds it covered already, so it skips.
    row = pending(store, item(authority="official", kind="feed"))
    commit = store.commit_candidate
    monkeypatch.setattr(store, "commit_candidate", lambda *args, **kw: (_ for _ in ()).throw(RuntimeError("crash")))
    with pytest.raises(RuntimeError):
        run(cfg, store, row, Writer(), Reviewer(verdict("skip", criterion="news_value"), both_editorial()))
    monkeypatch.setattr(store, "commit_candidate", commit)
    for _ in range(3):
        store.defer(row["id"], "Unexpected error", cfg["llm"], LATER, terminal=True)
    # The retry clears the job's reviews, but the saved receipt still matches, so the commit reuses it.
    rejection.retry_item(store, row["id"], row["content_hash"], "Retry the item", LATER)
    assert run(cfg, store, store.pending(1, LATER)[0], Writer(), Reviewer(), allow_network=False)["cache_hit"]
    assert [entry["code"] for entry in logged(store)] == [
        "failed.app.unexpected", "operator.retried", "skipped.verification.new_information_and_news_value"]
    detail = logged(store)[-1]["detail"]
    assert (detail["verdicts"], list(detail["criteria"])) == (["review:skip", "verification:skip"], ["new_information", "news_value"])


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
    rows = {incoming["id"]: dict(store.db.execute("SELECT * FROM items WHERE id=?", (incoming["id"],)).fetchone())
            for incoming in (struck, held, approved)}
    for attempt in (lambda: run(cfg, store, rows[held["id"]], Writer(), Reviewer(verdict("hold"))),
                    lambda: run(cfg, store, rows[approved["id"]], Writer(), Reviewer(verdict())),
                    lambda: store.defer(failing["id"], "Model returned invalid JSON", cfg["llm"], DATE, terminal=True),
                    lambda: rejection.retry_item(store, struck["id"], rows[struck["id"]]["content_hash"], "Retry", LATER)):
        with pytest.raises(sqlite3.IntegrityError, match="log unavailable"):
            attempt()
    states = dict(store.db.execute("SELECT url,status||':'||rejections FROM items"))
    assert states == {struck["url"]: "rejected:3", failing["url"]: "pending:2", held["url"]: "pending:0", approved["url"]: "pending:0"}
    assert [store.db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("analyses", "stories", "rejection_actions", "decision_log")] == [0, 0, 0, 1]


@pytest.mark.parametrize("record", [{"reviews": [1]}, {"reviews": [{"stage": "review"}]}, {"approval": 5}, [1], "text"])
def test_a_damaged_record_or_payload_still_logs_the_decision(context, record):
    _, store = context
    intact, damaged = item(), item(url="https://example.org/damaged")
    for incoming in (intact, damaged):
        store.ingest(incoming, DATE)
    damage_item(store.db, damaged["id"], "invalid-utf8")
    with store.db:
        for incoming in (intact, damaged):
            decisions.record(store.db, incoming["id"], "held.review.model_hold", LATER, review=record)
        decisions.skip_code(record, verdict("skip", criterion="news_value"))  # never raises either
    assert [entry["detail"] for entry in logged(store)] == [
        {"title": item()["title"], "url": item()["url"]}, {"title": None, "url": damaged["url"]}]


class Drafts:
    calls = 0

    def analyze(self, incoming):
        return analysis()


class Replies:
    """Review by the item's URL: approve, skip or hold, or fail as the test needs."""
    calls = 0

    def __init__(self, error=None):
        self.error = error

    def review(self, candidate, packet, *, coverage=None, verification=False, issue=None):
        url = packet["sources"][0]["url"]
        if url.endswith("/fail"):
            raise self.error
        reply = verdict("skip", criterion="news_value") if url.endswith("/skip") else verdict("hold") if url.endswith("/hold") else verdict()
        return review.validate_review(reply, packet)


def run_with(monkeypatch, cfg, store, error=None):
    built = []
    monkeypatch.setattr(cli, "Analyzer", lambda *args, **kwargs: contextlib.nullcontext(Drafts()))
    monkeypatch.setattr(cli, "Reviewer", lambda *args, **kwargs: contextlib.nullcontext(Replies(error)))
    monkeypatch.setattr(cli, "build", lambda *args: built.append(True) or {})
    report = cli.run(cfg, store)
    assert built == [True]
    return report


@pytest.mark.parametrize("error,code", [
    (AnalysisError("Model evidence quote 1 is not an exact excerpt", code="writer.evidence_not_exact"), "failed.writer.evidence_not_exact"),
    (review.ReviewError("Review response fields do not match schema"), "failed.review.invalid_reply"),
    (RuntimeError("boom"), "failed.app.unexpected"),
    (AnalysisError("LLM request failed", retryable=True), None),
], ids=["writer", "review", "unexpected", "retryable"])
def test_only_the_third_terminal_failure_is_logged(context, monkeypatch, error, code):
    cfg, store = context
    cfg["sources"] = []
    store.ingest(item(url="https://example.org/fail"), DATE)
    failing = item_id(store, "https://example.org/fail")
    for _ in range(2):
        store.defer(failing, "An earlier invalid draft", cfg["llm"], DATE, terminal=True, code="writer.invalid_output")
    assert logged(store) == []
    report = run_with(monkeypatch, cfg, store, error)
    assert [entry["code"] for entry in logged(store)] == ([code] if code else [])
    assert report["decisions"] == ({code: 1} if code else {}) and report["analysis_failed"] == 1


def test_detail_that_cannot_be_built_never_stops_the_run(context, monkeypatch):
    cfg, store = context
    cfg["sources"] = []
    store.ingest(item(url="https://example.org/fail"), DATE)
    for _ in range(2):
        store.defer(item_id(store, "https://example.org/fail"), "An earlier invalid draft", cfg["llm"], DATE, terminal=True)
    monkeypatch.setattr(decisions, "_detail", lambda *args: (_ for _ in ()).throw(ValueError("unexpected")))
    run_with(monkeypatch, cfg, store, review.ReviewError("Review response fields do not match schema"))
    assert [(entry["code"], entry["detail"]) for entry in logged(store)] == [("failed.review.invalid_reply", {})]
    assert store.db.execute("SELECT status FROM items").fetchone()[0] == "rejected"


def test_a_run_logs_exactly_one_decision_per_terminal_outcome(context, monkeypatch):
    cfg, store = context
    cfg["sources"] = []
    for name in ("publish", "skip", "hold", "fail", "damaged", "first/fail"):
        store.ingest(item(url="https://example.org/" + name), DATE)
    for _ in range(2):  # its third failure ends it; the first failure of first/fail does not
        store.defer(item_id(store, "https://example.org/fail"), "An earlier invalid reply", cfg["llm"], DATE, terminal=True)
    damage_item(store.db, item_id(store, "https://example.org/damaged"), "invalid-utf8")
    with store.db:  # an earlier decision, which the run's report leaves out
        decisions.record(store.db, item_id(store, "https://example.org/first/fail"), "operator.retried", DATE)
    before = dict(store.db.execute("SELECT id,status FROM items"))
    report = run_with(monkeypatch, cfg, store, review.ReviewError("Review response fields do not match schema"))
    changed = {key: status for key, status in store.db.execute("SELECT id,status FROM items") if status != before[key]}
    entries = logged(store)[1:]
    outcome = {"published": ("published",), "ignored": ("skipped",), "rejected": ("held", "failed")}
    assert len(entries) == len(changed) == 5 and {entry["item_id"] for entry in entries} == set(changed)
    assert all(entry["code"].split(".")[0] in outcome[changed[entry["item_id"]]] and entry["code"] in decisions.CODES
               for entry in entries)
    assert report["decisions"] == dict(Counter(entry["code"] for entry in entries)) == {
        "failed.app.damaged_item": 1, "failed.review.invalid_reply": 1, "held.review.model_hold": 1,
        "published.new": 1, "skipped.review.news_value": 1}
    assert report["analysis_failed"] == 3  # the damaged item and both failed replies; the hold is a decision


def test_error_codes_name_the_failing_stage(tmp_path, monkeypatch):
    cfg = config(tmp_path)
    cfg["llm"]["base_url"] = "https://llm.example/v1"
    monkeypatch.setenv(cfg["llm"]["api_key_env"], "test-key")
    replies = []

    class Transport:
        def request(self, method, url, headers=None, json_body=None):
            finished, content = replies.pop(0)
            body = {"choices": [{"finish_reason": finished, "message": {"content": content}}]}
            return Response(200, json.dumps(body).encode(), {}, url)

        def close(self):
            pass

    monkeypatch.setattr(analyze, "HttpClient", lambda *args, **kwargs: Transport())
    codes = []
    for client in (analyze.Analyzer(cfg), review.Reviewer(cfg)):
        for reply, payload in ((("length", "{}"), {"x": 1}), (("stop", "[1]"), {"x": 1}), (None, {"x": "\ud800"})):
            replies.extend([reply] if reply else [])  # input that cannot be encoded is never sent
            with pytest.raises(AnalysisError) as caught:
                client.complete("prompt", payload, {}, "name")
            codes.append(caught.value.code)
    for attempt in (lambda: tag_notice(item(kind="tag", title=" ")),
                    lambda: validate_analysis(analysis(evidence=["Absent from the source"]), item()),
                    lambda: validate_analysis(analysis(evidence=["short"]), item()),
                    lambda: analyze._writer_schema({"title": "", "content": ""}),
                    lambda: validate_analysis(analysis(publish=False), item())):
        with pytest.raises(AnalysisError) as caught:
            attempt()
        codes.append(caught.value.code)
    assert codes == ["writer.truncated", "writer.invalid_json", "writer.invalid_input",
                     "review.truncated", "review.invalid_json", "review.invalid_input", "app.invalid_tag_name",
                     "writer.evidence_not_exact", "writer.evidence_too_short", "writer.no_literal_evidence", "writer.invalid_output"]
    assert review.ReviewError("Invalid review text").code == "review.invalid_reply"
    assert {"failed." + code for code in [*codes, review.ReviewError.code]} <= decisions.CODES


def test_operator_actions_are_logged_with_their_private_reason(tmp_path):
    with Store(tmp_path / "state.sqlite3") as store:
        _, failed = rejected(store, 0)
        _, skipped = ignored(store, 1)
        _, other = rejected(store, 2)
        rejection.retry_item(store, failed["id"], failed["content_hash"], "The grounding rule was fixed", LATER)
        rejection.retry_item(store, skipped["id"], skipped["content_hash"], "Worth another look", LATER)
        rejection.dismiss_item(store, other["id"], other["content_hash"], "Routine discussion", LATER)
        with pytest.raises(ValueError):
            rejection.retry_item(store, other["id"], "0" * 64, "A stale hash is refused", LATER)
        entries = logged(store)
    assert [entry["code"] for entry in entries[:3]] == ["failed.app.unexpected", "skipped.verification.news_value", "failed.app.unexpected"]
    assert [(entry["code"], entry["item_id"], entry["decided_at"], entry["detail"]["reason"], entry["detail"]["before_status"])
            for entry in entries[3:]] == [
        ("operator.retried", failed["id"], LATER, "The grounding rule was fixed", "rejected"),
        ("operator.reconsidered", skipped["id"], LATER, "Worth another look", "ignored"),
        ("operator.dismissed", other["id"], LATER, "Routine discussion", "rejected")]
    assert entries[3]["detail"]["before_error"] == failed["last_error"]


def test_rejected_show_keeps_the_decision_history_after_recollection(context):
    cfg, store = context
    row = pending(store)
    run(cfg, store, row, Writer(), Reviewer(verdict("hold")))
    store.ingest(item(content=item()["content"] + " Edited.", updated_at=LATER), LATER)  # clears last_error
    shown = rejection.show_item(store, row["id"])
    assert (shown["status"], shown["rejection_reason"]) == ("pending", None)
    [entry] = shown["decisions"]
    assert (entry["code"], entry["content_hash"]) == ("held.review.model_hold", row["content_hash"])
    assert set(entry["detail"]["criteria"]) == {"operational_advice"}
    revised = store.pending(1, LATER)[0]
    assert run(cfg, store, revised, Writer(), Reviewer(verdict()))["status"] == "published"
    assert [(entry["code"], entry["content_hash"]) for entry in rejection.show_item(store, row["id"])["decisions"]] == [
        ("published.new", revised["content_hash"]), ("held.review.model_hold", row["content_hash"])]  # newest first


def test_summary_counts_examples_awaiting_work_and_feed_size(tmp_path):
    cfg = config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        assert decisions.summary(store.db, DATE)["feed"] == {
            "path": "feed.xml", "bytes": None, "limit_bytes": decisions.FEED_LIMIT_BYTES, "action": None}
        stamps = ["2026-10-01T00:00:00Z", *(f"2026-11-0{day}T00:00:00Z" for day in range(5, 9))]
        for number, stamp in enumerate(stamps):
            store.ingest(item(url=f"https://example.org/damaged/{number}"), DATE)
            store.reject(item_id(store, f"https://example.org/damaged/{number}"), "Stored source item is damaged",
                         "failed.app.damaged_item", stamp)
        store.ingest(item(url="https://example.org/retrying"), DATE)
        store.defer(item_id(store, "https://example.org/retrying"), "LLM request failed", cfg["llm"], DATE)
        store.ingest(item(url="https://example.org/published", title="A published report"), DATE)
        row = store.pending(1, DATE)[0]
        finish_reviewed(store, row, analysis(), "seed", DATE)
        story_id = store.stories()[0]["id"]
        editorial.correct(store.db, story_id, {"why_it_matters": ""}, reason="Removed unsupported impact.",
                          expect_hash=editorial.show(store.db, story_id)["hash"], observed=LATER)
        store.ingest(item(url="https://example.org/queued"), DATE)  # pending and never tried, so not retrying
        cli.build(cfg, store)
        result = decisions.summary(store.db, "2026-11-02T00:00:00Z")
        damaged = [item_id(store, f"https://example.org/damaged/{number}") for number in range(5)]
        assert result["outcomes"] == {"failed": 4, "published": 1}
        assert result["codes"] == {"failed.app.damaged_item": 4, "published.new": 1}
        assert result["sources"] == {"test": {"failed": 4, "published": 1}}
        assert [example["item_id"] for example in result["examples"]["failed.app.damaged_item"]] == damaged[:1:-1]
        assert result["examples"]["failed.app.damaged_item"][0]["error"] == "Stored source item is damaged"
        assert result["examples"]["published.new"][0]["title"] == "A published report"
        awaiting = result["awaiting_operator"]
        assert awaiting["rejected"] == 5 and [entry["item_id"] for entry in awaiting["items"]] == damaged
        assert awaiting["items"][0]["code"] == "failed.app.damaged_item" and awaiting["held_updates"] == []
        assert (result["retrying"], result["story_actions"], result["writer_clears"]) == (1, {"correct": 1}, 0)
        assert decisions.summary(store.db, "2026-11-11T00:00:00Z")["story_actions"] == {}  # the correction came before
        assert result["feed"]["bytes"] == (tmp_path / "public" / "feed.xml").stat().st_size
        assert result["feed"]["action"] is None
        for size, action in ((decisions.FEED_SPLIT_BYTES - 1, None), (decisions.FEED_SPLIT_BYTES, "ACTION: split the feeds by year")):
            with store.db:
                store.db.execute("UPDATE public_artifacts SET size=? WHERE path='feed.xml'", (size,))
            assert decisions.summary(store.db, DATE)["feed"]["action"] == action


def test_list_filters_by_code_prefix_and_source_and_pages(context):
    _, store = context
    codes = ["skipped.review.news_value", "skipped.verification.news_value", "held.review.model_hold", "operator.retried"]
    for number, code in enumerate(codes):
        incoming = item(url=f"https://example.org/{number}", source_id="odd" if number % 2 else "even")
        store.ingest(incoming, DATE)
        with store.db:
            decisions.record(store.db, incoming["id"], code, f"2026-11-0{number + 1}T00:00:00Z")

    def listed(since="2026-11-01T00:00:00Z", **options):
        return [entry["code"] for entry in decisions.list_entries(store.db, since, **options)["decisions"]]

    assert listed() == codes[::-1] and listed("2026-11-03T00:00:00Z") == codes[:1:-1]
    assert listed(code="skipped") == codes[1::-1] and listed(code="skipped.review") == codes[:1]
    # A prefix ends at a dot, and an underscore matches only itself.
    assert listed(code="skipped.rev") == listed(code="skipped_review") == [] and listed(code=codes[2]) == codes[2:3]
    assert listed(source="odd") == [codes[3], codes[1]]
    first = decisions.list_entries(store.db, "2026-11-01T00:00:00Z", limit=3)
    rest = decisions.list_entries(store.db, "2026-11-01T00:00:00Z", limit=3, after=first["next_cursor"])
    assert [entry["code"] for entry in first["decisions"] + rest["decisions"]] == codes[::-1] and rest["next_cursor"] is None
    assert first["decisions"][0]["detail"] == {"title": item()["title"], "url": "https://example.org/3"}
    for options in ({"limit": 0}, {"limit": 201}, {"code": "Held"}, {"code": "held..review"}, {"after": 0}):
        with pytest.raises(ValueError):
            decisions.list_entries(store.db, DATE, **options)
    assert decisions.window("7d", LATER) == "2026-11-03T12:00:00Z" and decisions.window("12h", LATER) == "2026-11-10T00:00:00Z"
    assert decisions.window("2026-11-01T00:00:00+01:00") == "2026-10-31T23:00:00Z"
    for text in ("7", "0d", "7w", "soon", None):
        with pytest.raises(ValueError):
            decisions.window(text)


def test_status_reports_the_decisions_of_the_last_day(tmp_path, capsys):
    path, cfg = write_config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        store.ingest(incoming := item(), DATE)
        with store.db:
            decisions.record(store.db, incoming["id"], "operator.retried", after(-25 * 3600))
            decisions.record(store.db, incoming["id"], "held.review.model_hold", now_iso())
    assert cli.main(["status", "--config", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["decisions_24h"] == {"held": 1}


def test_decision_commands_are_read_only_and_escape_text(tmp_path, capsys):
    path, cfg = write_config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        store.ingest(incoming := item(title="A report \u202e with a bidi control"), DATE)
        with store.db:
            decisions.record(store.db, incoming["id"], "held.review.model_hold", now_iso())
    with cli.run_lock(cfg["storage"]["database"]) as acquired:
        assert acquired
        assert cli.main(["decisions", "list", "--config", str(path), "--code", "held"]) == 0
        output = capsys.readouterr().out
        assert "\u202e" not in output and json.loads(output)["decisions"][0]["detail"]["title"] == "A report \u202e with a bidi control"
        assert cli.main(["decisions", "summary", "--config", str(path), "--since", "1h"]) == 0
        assert json.loads(capsys.readouterr().out)["codes"] == {"held.review.model_hold": 1}
    assert cli.main(["decisions", "summary", "--config", str(path), "--since", "soon"]) == 2


def test_decision_text_never_reaches_public_output(context):
    cfg, store = context
    reply = verdict("skip", criterion="news_value")
    reply["criteria"]["news_value"]["reason"] = "Zebra marker reason."
    run(cfg, store, pending(store, item(title="Quokka marker title")), Writer(), Reviewer(reply))
    separate = item(url="https://example.org/news/2", title="A separate report",
                    content="The operator reported a plausible compromise in a separate report.")
    run(cfg, store, pending(store, separate), Writer(), Reviewer(verdict()))
    cli.build(cfg, store)
    assert [entry["code"] for entry in logged(store)] == ["skipped.review.news_value", "published.new"]
    assert "Zebra marker reason." in logged(store)[0]["detail"]["criteria"]["news_value"]
    published = [path.read_bytes() for path in Path(cfg["storage"]["output_dir"]).rglob("*") if path.is_file()]
    assert published and not any(marker in text for text in published
                                 for marker in (b"Zebra marker", b"Quokka marker", b"skipped.review", b"published.new"))


def test_the_docs_list_exactly_the_decision_codes():
    text = (Path(__file__).parents[1] / "docs" / "DECISIONS.md").read_text(encoding="utf-8")
    assert set(re.findall(r"^\| `([a-z_.]+)` \|", text, re.M)) == decisions.CODES
