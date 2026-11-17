"""Operator approval of held candidates whose facts passed fresh verification."""

import copy
import json
from pathlib import Path
import re
import sqlite3

import pytest

from helpers import (
    DAMAGE, DATE, LATER, Reviewer, Writer, analysis, approve as seed_receipt, config, damaged,
    finish_reviewed, item, job, pending, run_gate, seed_legacy, seed_story, update_analysis, verdict,
)
from onionflash import cli, decisions, editorial, rejection, review_gate
from onionflash.analyze import AnalysisError, tag_notice
from onionflash.candidate import ReviewRequired, StaleCandidate
from onionflash.store import Store

AFTER_SHOW = "2026-11-10T15:30:00Z"
_TAG_ITEM = item(kind="tag", title="tor-0.4.9.5", content="",
                 url="https://gitlab.torproject.org/tpo/core/tor/-/tags/tor-0.4.9.5")


def hold_news_dispute(cfg, store, incoming=None, draft=None):
    row = pending(store, incoming)
    is_update = isinstance(draft, dict) and "update" in draft
    report = run_gate(
        cfg, store, row, Writer(draft) if draft else Writer(),
        Reviewer(verdict(update=is_update), verdict("hold", criterion="news_value", update=is_update)),
    )
    assert report["status"] == "held"
    return row


def dump_sql(store) -> list[str]:
    return list(store.db.iterdump())


def patched_verdict(action="hold", criterion="news_value", **criteria_updates):
    reply = verdict(action, criterion=criterion)
    for name, fields in criteria_updates.items():
        reply["criteria"][name].update(fields)
    return reply


def assert_unapprovable(cfg, store, item_id: str, expected_reason: str):
    before = dump_sql(store)
    shown = rejection.show_item(store, item_id, config=cfg)
    if shown["final_review"] is not None and "approval" in shown["final_review"]:
        info = shown["final_review"]["approval"]
    else:
        info = review_gate.approval(cfg, store, item_id)
    assert info["eligible"] is False
    assert expected_reason in info["reason"]
    with pytest.raises(ValueError, match=re.escape(expected_reason)):
        rejection.approve_item(cfg, store, item_id, "a" * 64, "Attempt override", observed=AFTER_SHOW)
    assert dump_sql(store) == before


def test_a_held_news_judgment_publishes_exactly_as_reviewed_without_model_calls(context):
    cfg, store = context
    row = hold_news_dispute(cfg, store)
    shown = rejection.show_item(store, row["id"], config=cfg)
    info = shown["final_review"]["approval"]
    assert info["eligible"] is True and info["reason"] is None
    assert info["editorial_failures"] == ["verification:news_value"]
    assert info["new_coverage"] == []
    assert shown["final_review"]["candidate_hash"]

    result = rejection.approve_item(
        cfg, store, row["id"], info["hash"], "Concrete development worth publishing", observed=AFTER_SHOW,
    )
    assert result == {
        "item_id": row["id"], "content_hash": row["content_hash"], "action": "approve",
        "status": "published", "story_id": result["story_id"], "analysis_key": result["analysis_key"],
        "publication_pending": True,
    }
    assert job(store) is None
    assert store.db.execute("SELECT COUNT(*) FROM review_approvals").fetchone()[0] == 0

    [story] = store.stories()
    for field in ("title", "summary", "why_it_matters", "category", "priority", "confidence", "state", "products", "tags"):
        assert story[field] == shown["final_review"]["candidate"][field]
    assert story["added_at"] == AFTER_SHOW
    assert tuple(store.db.execute("SELECT status,story_id,last_error FROM items WHERE id=?", (row["id"],)).fetchone()) == (
        "published", story["id"], None
    )

    audit_row = store.db.execute(
        "SELECT cache_key,review_record FROM analyses WHERE source_item_id=? ORDER BY rowid DESC LIMIT 1", (row["id"],),
    ).fetchone()
    assert audit_row["cache_key"] == result["analysis_key"]
    audit = json.loads(audit_row["review_record"])
    assert audit["outcome"] == "operator_approved"
    assert [entry["stage"] for entry in audit["reviews"]] == ["review", "verification"]
    assert audit["operator_approval"] == {
        "reason": "Concrete development worth publishing", "approved_at": AFTER_SHOW,
        "approval_hash": info["hash"], "new_coverage": [],
    }

    logged = decisions.for_item(store.db, row["id"])
    assert [entry["code"] for entry in logged] == ["operator.approved", "held.verification.disagreed_news"]
    assert logged[0]["detail"]["reason"] == "Concrete development worth publishing"

    finished = rejection.show_item(store, row["id"], config=cfg)["final_review"]
    assert finished["stage"] == "finished" and "approval" not in finished
    assert finished["operator_approval"]["approval_hash"] == info["hash"]

    cli.build(cfg, store)
    permalink = Path(cfg["storage"]["output_dir"]) / "news" / story["id"] / "index.html"
    assert permalink.exists()
    for path in Path(cfg["storage"]["output_dir"]).rglob("*"):
        if path.is_file():
            assert b"Concrete development worth publishing" not in path.read_bytes()


@pytest.mark.parametrize("case,src,replies,expected_title,expected_failures", [
    ("repaired", {}, [verdict("revise", criterion="actor_and_action", repair={"title": "Repaired release report"}),
                      verdict("hold", criterion="news_value")], "Repaired release report", ["verification:news_value"]),
    ("mirror", {}, [verdict("revise", criterion="news_value", repair={"title": "Mirror repaired report"}), verdict()],
     "Mirror repaired report", ["review:news_value"]),
    ("official", {"authority": "official"}, [verdict("skip", criterion="news_value"), verdict("skip", criterion="news_value")],
     None, ["review:news_value", "verification:news_value"]),
])
def test_verified_repair_mirror_official_and_repeat_holds_publish_exact_reviewed_text(
    context, case, src, replies, expected_title, expected_failures,
):
    cfg, store = context
    row = pending(store, item(**src) if src else None)
    run_gate(cfg, store, row, Writer(), Reviewer(*replies))
    if case == "official":
        assert job(store)["stage"] == "held"
        with store.db:
            store.db.execute("UPDATE items SET status='pending' WHERE id=?", (row["id"],))
        assert run_gate(cfg, store, store.pending(1, LATER)[0], Writer(), Reviewer())["status"] == "held"
    shown = rejection.show_item(store, row["id"], config=cfg)["final_review"]
    if case == "official":
        assert shown["hold_code"] == "repeat_hold"
    if expected_title:
        assert shown["candidate"]["title"] == expected_title != shown["base_candidate"]["title"]
    info = shown["approval"]
    assert info["eligible"] is True and info["editorial_failures"] == expected_failures
    rejection.approve_item(cfg, store, row["id"], info["hash"], f"{case} dispute resolved")
    assert len(store.stories()) == 1 and (not expected_title or store.stories()[0]["title"] == expected_title)


@pytest.mark.parametrize("incoming,draft,replies,expected_reason", [
    pytest.param(None, None, [verdict("hold", criterion="news_value")], "No fresh verification reviewed this exact text", id="first_review_hold"),
    pytest.param(None, None, [verdict(), verdict("hold", criterion="status")], "A review failed status; dismiss or retry it", id="verify_status_fail"),
    pytest.param(None, None, [verdict(), patched_verdict(source_support={"outcome": "fail"})], "A review failed source_support; dismiss or retry it", id="verify_source_and_news_fail"),
    pytest.param(None, None, [verdict(), patched_verdict(technical_details={"outcome": "insufficient"})], "A review failed technical_details; dismiss or retry it", id="verify_insufficient_fact"),
    pytest.param(None, None, [verdict(), patched_verdict(source_support={"source_refs": []})], "No fresh verification with cited sources approved the facts", id="empty_source_refs_verify"),
    pytest.param(item(authority="official"), None, [patched_verdict("skip", "news_value", source_support={"source_refs": []}), verdict("skip", criterion="news_value")],
                 "No fresh verification with cited sources approved the facts", id="empty_source_refs_base"),
    pytest.param(None, None, [verdict(), verdict("hold", criterion="new_information")], "A review failed new_information (already covered); dismiss it", id="verify_new_information_fail"),
    pytest.param(None, None, [verdict("revise", criterion="new_information", repair={"title": "Edited duplicate"}), verdict()],
                 "A review failed new_information (already covered); dismiss it", id="mirror_base_new_information_fail"),
    pytest.param(None, None, [verdict("revise", criterion="news_value", repair={"title": analysis()["title"]})], "No fresh verification reviewed this exact text", id="unusable_repair"),
    pytest.param(_TAG_ITEM, tag_notice(_TAG_ITEM), [verdict("revise", criterion="news_value", repair={"title": "Edited tag"})], "No fresh verification reviewed this exact text", id="tag_repair"),
    pytest.param(None, None, [*[verdict("revise", criterion="status", repair={"title": f"Attempt {idx}"}) for idx in range(review_gate.MAX_VERIFY_REPAIRS + 1)],
                              verdict("revise", criterion="status", repair={"title": "Final attempt"})], "A review failed status; dismiss or retry it", id="repairs_exhausted"),
    pytest.param(None, analysis(category="release", state="merged", tags=["tor", "release"]),
                 [verdict("revise", criterion="actor_and_action", repair={"title": "Merged release branch"}), verdict("hold", criterion="news_value")],
                 "release labels need a released or tagged state", id="release_merged_news_hold"),
    pytest.param(item(kind="gitlab_issue", content="Operators report a bug in relay descriptor parsing that needs investigation."),
                 analysis(summary="The relay descriptor parsing bug was fixed for affected operators.",
                          evidence=["Operators report a bug in relay descriptor parsing"], confidence="reported", state="developing"),
                 [verdict(), verdict("hold", criterion="news_value")], "the story reports a completed action that its sources do not", id="final_hold_completed_action"),
    pytest.param(item(kind="gitlab_issue", content="A relay operator reported that the host was plausibly compromised last week."),
                 analysis(title="Relay host compromised last week", summary="A relay operator reported that the host was plausibly compromised last week.",
                          evidence=["reported that the host was plausibly compromised"], confidence="reported", state="developing"),
                 [verdict(), verdict("hold", criterion="news_value")], "the headline drops the sources' doubt about a compromise", id="final_hold_compromise_headline"),
])
def test_unverified_or_fact_failed_holds_cannot_be_approved(context, incoming, draft, replies, expected_reason):
    cfg, store = context
    row = pending(store, incoming)
    run_gate(cfg, store, row, Writer(draft) if draft else Writer(), Reviewer(*replies))
    assert_unapprovable(cfg, store, row["id"], expected_reason)


def _setup_missing_sources_gate_hold(cfg, store):
    seeded, _ = seed_legacy(store, incoming=item(url="https://example.org/release", title="Tor 0.4.9.5 released"))
    with store.db:
        store.db.execute("DELETE FROM items WHERE url=?", (seeded["url"],))
    row = pending(store, item(url="https://example.org/followup", title="Tor 0.4.9.5 released",
                              content="Follow-up details on Tor 0.4.9.5."))
    assert run_gate(cfg, store, row, Writer(update_analysis(evidence=["Follow-up details on Tor 0.4.9.5."])),
                    Reviewer())["status"] == "held"
    return row["id"]


def _setup_missing_retained_source(cfg, store):
    seed_row = pending(store, item(url="https://example.org/release", title="Tor 0.4.9.5 released"), at=DATE, ready=LATER)
    finish_reviewed(store, seed_row, analysis(title="Tor 0.4.9.5 released"), "seed", DATE)
    followup = item(url="https://example.org/followup", title="Tor 0.4.9.5 released",
                    content="Follow-up details on Tor 0.4.9.5.")
    row = hold_news_dispute(cfg, store, incoming=followup,
                            draft=update_analysis(evidence=["Follow-up details on Tor 0.4.9.5."]))
    with store.db:
        store.db.execute("DELETE FROM items WHERE id=?", (seed_row["id"],))
        store.db.execute("UPDATE analyses SET source_payload=NULL WHERE source_item_id=?", (seed_row["id"],))
    return row["id"]


def _setup_legacy_pre_bump_issues(cfg, store):
    row = hold_news_dispute(cfg, store)
    legacy = json.loads(job(store, row["id"])["record_json"])
    legacy["policy_hash"] = "0" * 64
    for entry in legacy["reviews"]:
        entry["policy_hash"] = "0" * 64
        entry["result"]["issues"] = ["legacy field"]
    with store.db:
        store.db.execute("UPDATE review_jobs SET policy_hash=?,record_json=? WHERE item_id=?",
                         ("0" * 64, json.dumps(legacy), row["id"]))
    return row["id"]


@pytest.mark.parametrize(
    "setup_fn,expected_reason",
    [
        pytest.param(_setup_missing_sources_gate_hold, "required source material is unavailable",
                     id="missing_sources_gate_hold"),
        pytest.param(_setup_missing_retained_source, "required source material is unavailable",
                     id="missing_retained_source"),
        pytest.param(_setup_legacy_pre_bump_issues, "An earlier review policy or packet reviewed it; retry it",
                     id="legacy_pre_bump_issues"),
    ],
)
def test_missing_source_and_legacy_policy_holds_cannot_be_approved(context, setup_fn, expected_reason):
    cfg, store = context
    assert_unapprovable(cfg, store, setup_fn(cfg, store), expected_reason)


@pytest.mark.parametrize("state", ["strike_rejected", "ignored", "dismissed", "pending"])
def test_non_held_items_cannot_be_approved(context, state):
    cfg, store = context
    if state == "dismissed":
        row = hold_news_dispute(cfg, store)
        rejection.dismiss_item(store, row["id"], row["content_hash"], "Not news", observed=LATER)
    else:
        row = pending(store)
        if state == "strike_rejected":
            for _ in range(3):
                with pytest.raises(AnalysisError):
                    run_gate(cfg, store, row, Writer(), Reviewer({}))
                store.defer(row["id"], "Invalid review", cfg["llm"], LATER, terminal=True)
        elif state == "ignored":
            run_gate(cfg, store, row, Writer(), Reviewer(verdict("skip", criterion="news_value")))
    assert_unapprovable(cfg, store, row["id"], "Only a held final review can be approved")


def test_the_approval_binds_inspected_text_coverage_story_lock_and_policy(tmp_path):
    cfg = config(tmp_path / "coverage")
    with Store(cfg["storage"]["database"]) as store:
        existing = seed_story(store, item(url="https://example.org/existing", title="Existing coverage",
                                          content="Distinct existing story body. " * 4),
                              analysis(title="Existing coverage", evidence=["Distinct existing story body."]),
                              key="seed1", at=DATE)
        row = hold_news_dispute(cfg, store,
                                incoming=item(url="https://example.org/held", content="Held candidate distinct body. " * 4),
                                draft=analysis(title="Held story", evidence=["Held candidate distinct body."]))
        first_hash = rejection.show_item(store, row["id"], config=cfg)["final_review"]["approval"]["hash"]

        seed_story(store, item(url="https://example.org/existing", title="Existing coverage",
                               content="Distinct existing story body with follow-up. " * 4,
                               updated_at="2026-11-10T13:00:00Z"),
                   analysis(title="Existing coverage updated",
                            evidence=["Distinct existing story body with follow-up."]),
                   key="seed2", at="2026-11-10T13:00:00Z")
        with pytest.raises(ValueError, match="Approval hash does not match"):
            rejection.approve_item(cfg, store, row["id"], first_hash, "Stale coverage", observed=AFTER_SHOW)

        reshown = rejection.show_item(store, row["id"], config=cfg)["final_review"]["approval"]
        assert reshown["eligible"] is True and [entry["id"] for entry in reshown["new_coverage"]] == [existing["id"]]

        seed_story(store, item(url="https://example.org/other", title="Other story",
                               content="Completely separate announcement text. " * 4),
                   analysis(title="Other story", evidence=["Completely separate announcement text."]),
                   key="seed3", at="2026-11-10T14:00:00Z")
        with pytest.raises(ValueError, match="Approval hash does not match"):
            rejection.approve_item(cfg, store, row["id"], reshown["hash"], "Stale again", observed=AFTER_SHOW)

        third = rejection.show_item(store, row["id"], config=cfg)["final_review"]["approval"]
        assert len(third["new_coverage"]) == 2
        assert rejection.approve_item(cfg, store, row["id"], third["hash"], "Checked new coverage",
                                      observed=AFTER_SHOW)["status"] == "published"

    cfg = config(tmp_path / "prior_unlocked")
    with Store(cfg["storage"]["database"]) as store:
        shared_body = "Shared cluster body for grouped story updates. " * 4
        seed_story(store, item(url="https://example.org/s1", content=shared_body),
                   analysis(evidence=["Shared cluster body for grouped story updates."]), key="s1", at=DATE)
        held_row = hold_news_dispute(cfg, store,
                                     incoming=item(url="https://example.org/s2", content=shared_body,
                                                   updated_at="2026-11-10T01:00:00Z"),
                                     draft=analysis(title="Held update",
                                                    evidence=["Shared cluster body for grouped story updates."]))
        old_hash = rejection.show_item(store, held_row["id"], config=cfg)["final_review"]["approval"]["hash"]
        seed_story(store, item(url="https://example.org/s3", content=shared_body, updated_at="2026-11-10T02:00:00Z"),
                   analysis(title="Concurrent update", evidence=["Shared cluster body for grouped story updates."]),
                   key="s3", at="2026-11-10T02:00:00Z")
        with pytest.raises(ValueError, match="Its story or sources changed since the review; retry it"):
            rejection.approve_item(cfg, store, held_row["id"], old_hash, "Stale prior", observed=AFTER_SHOW)

    cfg = config(tmp_path / "locked")
    with Store(cfg["storage"]["database"]) as store:
        shared_body = "Locked story cluster body for testing grouped updates. " * 4
        seeded = seed_story(store, item(url="https://example.org/l1", content=shared_body),
                            analysis(evidence=["Locked story cluster body for testing grouped updates."]),
                            key="l1", at=DATE)
        held_row = hold_news_dispute(cfg, store,
                                     incoming=item(url="https://example.org/l2", content=shared_body,
                                                   updated_at="2026-11-10T01:00:00Z"),
                                     draft=analysis(title="Held update",
                                                    evidence=["Locked story cluster body for testing grouped updates."]))
        old_hash = rejection.show_item(store, held_row["id"], config=cfg)["final_review"]["approval"]["hash"]
        editorial.correct(store.db, seeded["id"], {"title": "Corrected title"}, reason="Manual fix",
                          expect_hash=editorial.show(store.db, seeded["id"])["hash"])
        with pytest.raises(ValueError, match="Its story is editorially locked"):
            rejection.approve_item(cfg, store, held_row["id"], old_hash, "Locked story", observed=AFTER_SHOW)

    cfg = config(tmp_path / "policy_and_retry")
    with Store(cfg["storage"]["database"]) as store:
        row = hold_news_dispute(cfg, store)
        old_hash = rejection.show_item(store, row["id"], config=cfg)["final_review"]["approval"]["hash"]
        changed_cfg = {**copy.deepcopy(cfg), "review": {**cfg["review"], "model": "other-reviewer-model"}}
        with pytest.raises(ValueError, match="An earlier review policy or packet reviewed it; retry it"):
            rejection.approve_item(changed_cfg, store, row["id"], old_hash, "Changed model", observed=AFTER_SHOW)
        with pytest.raises(ValueError, match="64-character lowercase hexadecimal"):
            rejection.approve_item(cfg, store, row["id"], "not-a-hash", "Bad format", observed=AFTER_SHOW)
        with pytest.raises(ValueError, match="Approval hash does not match"):
            rejection.approve_item(cfg, store, row["id"], "0" * 64, "Wrong hash", observed=AFTER_SHOW)

        rejection.retry_item(store, row["id"], row["content_hash"], "Retry review", observed=LATER)
        later_verdict = patched_verdict(news_value={"reason": "Different review wording after retry."})
        run_gate(cfg, store, store.pending(1, LATER)[0], Writer(), Reviewer(verdict(), later_verdict))
        with pytest.raises(ValueError, match="Approval hash does not match"):
            rejection.approve_item(cfg, store, row["id"], old_hash, "Voided hash", observed=AFTER_SHOW)


def test_commit_candidate_guards_and_untouched_receipts(context):
    cfg, store = context
    other_row = pending(store, item(url="https://example.org/other", content="Unrelated receipt item body. " * 4))
    seed_receipt(store, store.prepare_candidate(other_row, analysis(evidence=["Unrelated receipt item body."]), DATE))
    receipts_before = store.db.execute("SELECT * FROM review_approvals").fetchall()
    assert len(receipts_before) == 1

    row = hold_news_dispute(cfg, store)
    prepared = store.prepare_candidate(
        dict(store.db.execute("SELECT * FROM items WHERE id=?", (row["id"],)).fetchone()), analysis(), DATE,
    )
    fake_audit = {
        "outcome": "operator_approved",
        "operator_approval": {"reason": "Attempt bypass", "approved_at": AFTER_SHOW, "approval_hash": "a" * 64, "new_coverage": []},
    }
    with pytest.raises(ReviewRequired, match="Review decision does not match"):
        store.commit_candidate(prepared, prepared["candidate"], "writer-key", AFTER_SHOW, review_record=fake_audit)
    with pytest.raises(ReviewRequired, match="operator_approval"):
        store.commit_candidate(prepared, prepared["candidate"], "writer-key", AFTER_SHOW,
                               review_record={"outcome": "approved"}, operator=True)

    shown = rejection.show_item(store, row["id"], config=cfg)
    assert store.db.execute("SELECT * FROM review_approvals").fetchall() == receipts_before
    rejection.approve_item(cfg, store, row["id"], shown["final_review"]["approval"]["hash"], "Approved", observed=AFTER_SHOW)
    assert store.db.execute("SELECT * FROM review_approvals").fetchall() == receipts_before
    with pytest.raises(StaleCandidate):
        store.commit_candidate(prepared, prepared["candidate"], "writer-key", AFTER_SHOW,
                               review_record=fake_audit, operator=True)


def test_a_failed_write_rolls_back_the_entire_approval(context):
    cfg, store = context
    row = hold_news_dispute(cfg, store)
    approval_hash = rejection.show_item(store, row["id"], config=cfg)["final_review"]["approval"]["hash"]
    store.db.execute(
        "CREATE TRIGGER fail_operator_decision BEFORE INSERT ON decision_log "
        "WHEN NEW.code='operator.approved' BEGIN SELECT RAISE(ABORT, 'simulated failure'); END"
    )
    before = dump_sql(store)
    with pytest.raises(sqlite3.IntegrityError, match="simulated failure"):
        rejection.approve_item(cfg, store, row["id"], approval_hash, "Should roll back", observed=AFTER_SHOW)
    assert dump_sql(store) == before
    assert store.stories() == [] and job(store)["stage"] == "held"


def test_later_source_change_reviews_normally_and_clears_held_updates_summary(context):
    cfg, store = context
    row = hold_news_dispute(cfg, store)
    approval_hash = rejection.show_item(store, row["id"], config=cfg)["final_review"]["approval"]["hash"]
    story_id = rejection.approve_item(cfg, store, row["id"], approval_hash, "Initial approval", observed=LATER)["story_id"]

    locked = editorial.correct(store.db, story_id, {"summary": "Corrected summary."}, reason="Fix wording",
                               expect_hash=editorial.show(store.db, story_id)["hash"])
    assert store.ingest(item(content="Second upstream revision after approval. " * 4, updated_at="2026-11-10T13:00:00Z"),
                        "2026-11-10T13:00:00Z") is True
    writer2 = Writer(analysis(evidence=["Second upstream revision after approval."]))
    assert run_gate(cfg, store, store.pending(1, "2026-11-10T13:05:00Z")[0], writer2, Reviewer())["status"] == "locked"
    assert len(writer2.calls) == 1
    assert decisions.summary(store.db, DATE)["awaiting_operator"]["held_updates"] == [
        {"story_id": story_id, "held_updates": 1, "locked": True}
    ]

    editorial.unlock(store.db, story_id, reason="Resume updates", expect_hash=locked["hash"])
    assert store.ingest(item(content="Third upstream revision disputed on news value. " * 4, updated_at="2026-11-10T14:00:00Z"),
                        "2026-11-10T14:00:00Z") is True
    writer3 = Writer(update_analysis(update="Third revision update.",
                                     evidence=["Third upstream revision disputed on news value."]))
    reviewer3 = Reviewer(verdict(update=True), verdict("hold", criterion="news_value", update=True))
    assert run_gate(cfg, store, store.pending(1, "2026-11-10T14:05:00Z")[0], writer3, reviewer3)["status"] == "held"
    assert len(writer3.calls) == 1 and len(reviewer3.calls) == 2

    upd_hash = rejection.show_item(store, row["id"], config=cfg)["final_review"]["approval"]["hash"]
    rejection.approve_item(cfg, store, row["id"], upd_hash, "Approve follow-up", observed=AFTER_SHOW)
    assert store.stories()[0]["title"] == "Operator reports possible compromise"
    assert store.stories()[0]["updates"][-1]["text"] == "Third revision update."
    assert decisions.summary(store.db, DATE)["awaiting_operator"]["held_updates"] == []


@pytest.mark.parametrize("mutator", [
    None, *[{"damage": kind} for kind in DAMAGE],
    {"record_json": '{"reviews": "not-a-list"}'}, {"record_json": '{"reviews": [{"stage": "bogus"}]}'},
    {"record_json": '{"reviews": [], "policy_hash": "x", "prepared": {"coverage": "bad"}}'}, {"writer_key": ""},
])
def test_show_with_approval_stays_read_only_and_survives_damaged_records(context, mutator):
    cfg, store = context
    row = hold_news_dispute(cfg, store)
    if mutator is not None:
        column, value = next(iter(mutator.items()))
        if column == "damage":
            column, value = "record_json", damaged(job(store, row["id"])["record_json"], value)
        with store.db:
            store.db.execute(f"UPDATE review_jobs SET {column}=? WHERE item_id=?", (value, row["id"]))
    before = dump_sql(store)
    info = rejection.show_item(store, row["id"], config=cfg)["final_review"]["approval"]
    assert dump_sql(store) == before
    assert info["eligible"] is (mutator is None) and (mutator is None or (isinstance(info["reason"], str) and bool(info["reason"])))


@pytest.mark.parametrize("draft_overrides,responses,expected_eligible", [
    ({}, [verdict("revise", criterion="source_support", repair={"summary": "Supported summary."}), verdict("hold", criterion="news_value")], True),
    ({}, [verdict("revise", criterion="news_value", repair={"title": "Qualified report"}), verdict()], True),
    ({}, [verdict(), verdict("hold", criterion="status")], False),
    ({}, [verdict(), verdict("hold", criterion="source_support")], False),
    ({"category": "release", "state": "merged", "tags": ["tor", "release"]},
     [verdict("revise", criterion="actor_and_action", repair={"summary": "Merged branch."}), verdict("hold", criterion="news_value")], False),
])
def test_deterministic_replay_of_saved_dispute_shapes(context, draft_overrides, responses, expected_eligible):
    cfg, store = context
    row = pending(store)
    assert run_gate(cfg, store, row, Writer(analysis(**draft_overrides)), Reviewer(*responses))["status"] == "held"
    assert rejection.show_item(store, row["id"], config=cfg)["final_review"]["approval"]["eligible"] is expected_eligible


@pytest.mark.parametrize("mirror,mutate,expected_reason", [
    (False, lambda env, rec: rec["reviews"][0].update(policy_hash="0" * 64), "An earlier review policy or packet reviewed it; retry it"),
    (False, lambda env, rec: rec["reviews"][0].update(source_hash="0" * 64), "An earlier review policy or packet reviewed it; retry it"),
    (False, lambda env, rec: env["binding"].update(prior_story="0" * 64), "Its story or sources changed since the review; retry it"),
    (False, lambda env, rec: rec.update(verified_facts=False), "No fresh verification with cited sources approved the facts; retry or dismiss it"),
    (True, lambda env, rec: rec.update(candidate=copy.deepcopy(rec["prepared"]["candidate"])), "No fresh verification reviewed this exact text"),
])
def test_single_field_record_and_binding_tampering_refuses(context, mirror, mutate, expected_reason):
    cfg, store = context
    if mirror:
        row = pending(store)
        assert run_gate(cfg, store, row, Writer(), Reviewer(
            verdict("revise", criterion="news_value", repair={"title": "Repaired title"}), verdict(),
        ))["status"] == "held"
    else:
        row = hold_news_dispute(cfg, store)
    saved = job(store, row["id"])
    envelope, record = json.loads(saved["envelope_json"]), json.loads(saved["record_json"])
    mutate(envelope, record)
    with store.db:
        store.db.execute("UPDATE review_jobs SET envelope_json=?,record_json=? WHERE item_id=?",
                         (json.dumps(envelope), json.dumps(record), row["id"]))
    info = review_gate.approval(cfg, store, row["id"])
    assert info["eligible"] is False and expected_reason in info["reason"]


@pytest.mark.parametrize("bad_updates", [[{}], ["malformed"], "not-a-list", [{"at": LATER}]])
def test_malformed_saved_update_entries_refuse_without_raising(context, bad_updates):
    cfg, store = context
    seed_story(store, item(url="https://example.org/orig", title="Initial relay report",
                           content="Initial relay report on directory fetch behavior."),
               analysis(), key="seed-orig", at=DATE)
    row = hold_news_dispute(
        cfg, store,
        incoming=item(url="https://example.org/orig", title="Initial relay report",
                      content="Initial relay report on directory fetch behavior. Later maintainer confirmation.",
                      updated_at=LATER),
        draft=update_analysis(update="Maintainers confirmed the directory fetch behavior.",
                              evidence=["Later maintainer confirmation."]),
    )
    record = json.loads(job(store, row["id"])["record_json"])
    record["candidate"]["updates"] = bad_updates
    with store.db:
        store.db.execute("UPDATE review_jobs SET record_json=? WHERE item_id=?", (json.dumps(record), row["id"]))
    info = review_gate.approval(cfg, store, row["id"])
    assert info["eligible"] is False and info["reason"] == "Saved review record cannot be read"
