"""Operator approval of held candidates whose facts passed fresh verification."""

import copy
import json
from pathlib import Path
import re
import sqlite3

import pytest

from approval_helpers import approve as seed_receipt, finish_reviewed, update_analysis, verdict
from onionflash import cli, decisions, editorial, rejection, review, review_gate
from onionflash.analyze import AnalysisError, tag_notice
from onionflash.candidate import ReviewRequired, StaleCandidate
from onionflash.store import Store
from test_core import DAMAGE, DATE, analysis, config, damaged, item
from test_review_gate import LATER, Reviewer, Writer, job, pending, run


AFTER_SHOW = "2026-11-10T15:30:00Z"


def hold_news_dispute(cfg, store, incoming=None, draft=None):
    row = pending(store, incoming)
    is_update = isinstance(draft, dict) and "update" in draft
    report = run(cfg, store, row, Writer(draft), Reviewer(verdict(update=is_update), verdict("hold", criterion="news_value", update=is_update)))
    assert report["status"] == "held"
    return row


def dump_sql(store) -> list[str]:
    return list(store.db.iterdump())


def test_a_held_news_judgment_publishes_exactly_as_reviewed_without_model_calls(tmp_path):
    cfg = config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        row = hold_news_dispute(cfg, store)
        shown = rejection.show_item(store, row["id"], config=cfg)
        info = shown["final_review"]["approval"]
        assert info["eligible"] is True
        assert info["reason"] is None
        assert info["editorial_failures"] == ["verification:news_value"]
        assert info["new_coverage"] == []
        assert shown["final_review"]["candidate_hash"]

        result = rejection.approve_item(
            cfg,
            store,
            row["id"],
            info["hash"],
            "Concrete development worth publishing",
            observed=AFTER_SHOW,
        )
        assert result == {
            "item_id": row["id"],
            "content_hash": row["content_hash"],
            "action": "approve",
            "status": "published",
            "story_id": result["story_id"],
            "analysis_key": result["analysis_key"],
            "publication_pending": True,
        }
        assert job(store) is None
        assert store.db.execute("SELECT COUNT(*) FROM review_approvals").fetchone()[0] == 0

        stories = store.stories()
        assert len(stories) == 1
        story = stories[0]
        for field in ("title", "summary", "why_it_matters", "category", "priority", "confidence", "state", "products", "tags"):
            assert story[field] == shown["final_review"]["candidate"][field]
        assert story["added_at"] == AFTER_SHOW

        item_row = store.db.execute("SELECT status,story_id,last_error FROM items WHERE id=?", (row["id"],)).fetchone()
        assert tuple(item_row) == ("published", story["id"], None)

        audit_row = store.db.execute(
            "SELECT cache_key,review_record FROM analyses WHERE source_item_id=? ORDER BY rowid DESC LIMIT 1",
            (row["id"],),
        ).fetchone()
        assert audit_row["cache_key"] == result["analysis_key"]
        audit = json.loads(audit_row["review_record"])
        assert audit["outcome"] == "operator_approved"
        assert [entry["stage"] for entry in audit["reviews"]] == ["review", "verification"]
        assert audit["operator_approval"] == {
            "reason": "Concrete development worth publishing",
            "approved_at": AFTER_SHOW,
            "approval_hash": info["hash"],
            "new_coverage": [],
        }

        logged = decisions.for_item(store.db, row["id"])
        assert [entry["code"] for entry in logged] == ["operator.approved", "held.verification.disagreed_news"]
        assert logged[0]["detail"]["reason"] == "Concrete development worth publishing"

        finished = rejection.show_item(store, row["id"], config=cfg)["final_review"]
        assert finished["stage"] == "finished"
        assert "approval" not in finished
        assert finished["operator_approval"]["approval_hash"] == info["hash"]

        cli.build(cfg, store)
        permalink = Path(cfg["storage"]["output_dir"]) / "news" / story["id"] / "index.html"
        assert permalink.exists()
        for path in Path(cfg["storage"]["output_dir"]).rglob("*"):
            if path.is_file():
                assert b"Concrete development worth publishing" not in path.read_bytes()


def test_verified_repair_mirror_official_and_repeat_holds_publish_exact_reviewed_text(tmp_path):
    # 1. Repaired title verified, only news_value disputed in verification.
    cfg = config(tmp_path / "repaired")
    with Store(cfg["storage"]["database"]) as store:
        row = pending(store)
        run(
            cfg,
            store,
            row,
            Writer(),
            Reviewer(
                verdict("revise", criterion="actor_and_action", repair={"title": "Repaired release report"}),
                verdict("hold", criterion="news_value"),
            ),
        )
        shown = rejection.show_item(store, row["id"], config=cfg)
        assert shown["final_review"]["approval"]["eligible"] is True
        assert shown["final_review"]["candidate"]["title"] == "Repaired release report"
        assert shown["final_review"]["base_candidate"]["title"] != "Repaired release report"
        rejection.approve_item(cfg, store, row["id"], shown["final_review"]["approval"]["hash"], "Verified repair")
        assert store.stories()[0]["title"] == "Repaired release report"

    # 2. Mirror hold: first review failed news_value with repair; verification approved the repair.
    cfg = config(tmp_path / "mirror")
    with Store(cfg["storage"]["database"]) as store:
        row = pending(store)
        run(
            cfg,
            store,
            row,
            Writer(),
            Reviewer(
                verdict("revise", criterion="news_value", repair={"title": "Mirror repaired report"}),
                verdict(),
            ),
        )
        shown = rejection.show_item(store, row["id"], config=cfg)
        info = shown["final_review"]["approval"]
        assert info["eligible"] is True
        assert info["editorial_failures"] == ["review:news_value"]
        rejection.approve_item(cfg, store, row["id"], info["hash"], "Mirror dispute resolved")
        assert store.stories()[0]["title"] == "Mirror repaired report"

    # 3. Official item held as official_not_news after fresh verification passed facts; plus repeat hold.
    cfg = config(tmp_path / "official")
    with Store(cfg["storage"]["database"]) as store:
        row = pending(store, item(authority="official"))
        run(
            cfg,
            store,
            row,
            Writer(),
            Reviewer(verdict("skip", criterion="news_value"), verdict("skip", criterion="news_value")),
        )
        assert job(store)["stage"] == "held"
        # Trigger repeat_hold by returning the item to pending without reset_review_work.
        with store.db:
            store.db.execute("UPDATE items SET status='pending' WHERE id=?", (row["id"],))
        requeued = store.pending(1, LATER)[0]
        assert run(cfg, store, requeued, Writer(), Reviewer())["status"] == "held"
        shown = rejection.show_item(store, row["id"], config=cfg)
        assert shown["final_review"]["hold_code"] == "repeat_hold"
        info = shown["final_review"]["approval"]
        assert info["eligible"] is True
        assert info["editorial_failures"] == ["review:news_value", "verification:news_value"]
        rejection.approve_item(cfg, store, row["id"], info["hash"], "Official post worth covering")
        assert len(store.stories()) == 1


@pytest.mark.parametrize(
    "case,expected_reason",
    [
        ("first_review_hold", "No fresh verification reviewed this exact text"),
        ("verify_status_fail", "A review failed status; dismiss or retry it"),
        ("verify_source_and_news_fail", "A review failed source_support; dismiss or retry it"),
        ("verify_insufficient_fact", "A review failed technical_details; dismiss or retry it"),
        ("empty_source_refs_verify", "No fresh verification with cited sources approved the facts"),
        ("empty_source_refs_base", "No fresh verification with cited sources approved the facts"),
        ("verify_new_information_fail", "A review failed new_information (already covered); dismiss it"),
        ("mirror_base_new_information_fail", "A review failed new_information (already covered); dismiss it"),
        ("unusable_repair", "No fresh verification reviewed this exact text"),
        ("tag_repair", "No fresh verification reviewed this exact text"),
        ("repairs_exhausted", "A review failed status; dismiss or retry it"),
        ("release_merged_news_hold", "release labels need a released or tagged state"),
        ("final_hold_completed_action", "the story reports a completed action that its sources do not"),
        ("final_hold_compromise_headline", "the headline drops the sources' doubt about a compromise"),
        ("missing_sources_gate_hold", "required source material is unavailable"),
        ("missing_retained_source", "required source material is unavailable"),
        ("legacy_pre_bump_issues", "An earlier review policy or packet reviewed it; retry it"),
        ("strike_rejected", "Only a held final review can be approved"),
        ("ignored", "Only a held final review can be approved"),
        ("dismissed", "Only a held final review can be approved"),
        ("pending", "Only a held final review can be approved"),
    ],
)
def test_only_holds_whose_reviews_passed_every_factual_check_can_be_approved(tmp_path, case, expected_reason):
    cfg = config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        if case == "first_review_hold":
            row = pending(store)
            run(cfg, store, row, Writer(), Reviewer(verdict("hold", criterion="news_value")))
        elif case == "verify_status_fail":
            row = pending(store)
            run(cfg, store, row, Writer(), Reviewer(verdict(), verdict("hold", criterion="status")))
        elif case == "verify_source_and_news_fail":
            reply = verdict("hold", criterion="news_value")
            reply["criteria"]["source_support"]["outcome"] = "fail"
            row = pending(store)
            run(cfg, store, row, Writer(), Reviewer(verdict(), reply))
        elif case == "verify_insufficient_fact":
            reply = verdict("hold", criterion="news_value")
            reply["criteria"]["technical_details"]["outcome"] = "insufficient"
            row = pending(store)
            run(cfg, store, row, Writer(), Reviewer(verdict(), reply))
        elif case == "empty_source_refs_verify":
            reply = verdict("hold", criterion="news_value")
            reply["criteria"]["source_support"]["source_refs"] = []
            row = pending(store)
            run(cfg, store, row, Writer(), Reviewer(verdict(), reply))
        elif case == "empty_source_refs_base":
            first = verdict("skip", criterion="news_value")
            first["criteria"]["source_support"]["source_refs"] = []
            row = pending(store, item(authority="official"))
            run(cfg, store, row, Writer(), Reviewer(first, verdict("skip", criterion="news_value")))
        elif case == "verify_new_information_fail":
            row = pending(store)
            run(cfg, store, row, Writer(), Reviewer(verdict(), verdict("hold", criterion="new_information")))
        elif case == "mirror_base_new_information_fail":
            row = pending(store)
            run(
                cfg,
                store,
                row,
                Writer(),
                Reviewer(
                    verdict("revise", criterion="new_information", repair={"title": "Edited duplicate"}),
                    verdict(),
                ),
            )
        elif case == "unusable_repair":
            row = pending(store)
            noop = verdict("revise", criterion="news_value", repair={"title": analysis()["title"]})
            run(cfg, store, row, Writer(), Reviewer(noop))
        elif case == "tag_repair":
            tag_item = item(kind="tag", title="tor-0.4.9.5", content="", url="https://gitlab.torproject.org/tpo/core/tor/-/tags/tor-0.4.9.5")
            row = pending(store, tag_item)
            run(
                cfg,
                store,
                row,
                Writer(tag_notice(tag_item)),
                Reviewer(verdict("revise", criterion="news_value", repair={"title": "Edited tag"})),
            )
        elif case == "repairs_exhausted":
            row = pending(store)
            replies = [
                verdict("revise", criterion="status", repair={"title": f"Attempt {idx}"})
                for idx in range(review_gate.MAX_VERIFY_REPAIRS + 1)
            ]
            replies.append(verdict("revise", criterion="status", repair={"title": "Final attempt"}))
            run(cfg, store, row, Writer(), Reviewer(*replies))
        elif case == "release_merged_news_hold":
            # A revise review bypasses Reviewer's approve-only conversion, then verification holds on news_value.
            draft = analysis(category="release", state="merged", tags=["tor", "release"])
            row = pending(store)
            run(
                cfg,
                store,
                row,
                Writer(draft),
                Reviewer(
                    verdict("revise", criterion="actor_and_action", repair={"title": "Merged release branch"}),
                    verdict("hold", criterion="news_value"),
                ),
            )
        elif case == "final_hold_completed_action":
            issue = item(
                kind="gitlab_issue",
                content="Operators report a bug in relay descriptor parsing that needs investigation.",
            )
            draft = analysis(
                summary="The relay descriptor parsing bug was fixed for affected operators.",
                evidence=["Operators report a bug in relay descriptor parsing"],
                confidence="reported",
                state="developing",
            )
            row = pending(store, issue)
            run(cfg, store, row, Writer(draft), Reviewer(verdict(), verdict("hold", criterion="news_value")))
        elif case == "final_hold_compromise_headline":
            hedged = item(
                kind="gitlab_issue",
                content="A relay operator reported that the host was plausibly compromised last week.",
            )
            draft = analysis(
                title="Relay host compromised last week",
                summary="A relay operator reported that the host was plausibly compromised last week.",
                evidence=["reported that the host was plausibly compromised"],
                confidence="reported",
                state="developing",
            )
            row = pending(store, hedged)
            run(cfg, store, row, Writer(draft), Reviewer(verdict(), verdict("hold", criterion="news_value")))
        elif case == "missing_sources_gate_hold":
            from test_review_gate import seed_legacy
            seeded, _ = seed_legacy(store, incoming=item(url="https://example.org/release", title="Tor 0.4.9.5 released"))
            with store.db:
                store.db.execute("DELETE FROM items WHERE url=?", (seeded["url"],))
            followup = item(url="https://example.org/followup", title="Tor 0.4.9.5 released", content="Follow-up details on Tor 0.4.9.5.")
            row = pending(store, followup)
            assert run(cfg, store, row, Writer(update_analysis(evidence=["Follow-up details on Tor 0.4.9.5."])), Reviewer())["status"] == "held"
        elif case == "missing_retained_source":
            seed = item(url="https://example.org/release", title="Tor 0.4.9.5 released")
            store.ingest(seed, DATE)
            seed_row = store.pending(1, LATER)[0]
            finish_reviewed(store, seed_row, analysis(title="Tor 0.4.9.5 released"), "seed", DATE)
            followup = item(url="https://example.org/followup", title="Tor 0.4.9.5 released", content="Follow-up details on Tor 0.4.9.5.")
            row = hold_news_dispute(cfg, store, incoming=followup, draft=update_analysis(evidence=["Follow-up details on Tor 0.4.9.5."]))
            with store.db:
                store.db.execute("DELETE FROM items WHERE id=?", (seed_row["id"],))
                store.db.execute("UPDATE analyses SET source_payload=NULL WHERE source_item_id=?", (seed_row["id"],))
        elif case == "legacy_pre_bump_issues":
            row = hold_news_dispute(cfg, store)
            saved_job = store.db.execute("SELECT record_json FROM review_jobs WHERE item_id=?", (row["id"],)).fetchone()
            legacy = json.loads(saved_job["record_json"])
            legacy["policy_hash"] = "0" * 64
            for entry in legacy["reviews"]:
                entry["policy_hash"] = "0" * 64
                entry["result"]["issues"] = ["legacy field"]
            with store.db:
                store.db.execute(
                    "UPDATE review_jobs SET policy_hash=?,record_json=? WHERE item_id=?",
                    ("0" * 64, json.dumps(legacy), row["id"]),
                )
        elif case == "strike_rejected":
            row = pending(store)
            for _ in range(3):
                with pytest.raises(AnalysisError):
                    run(cfg, store, row, Writer(), Reviewer({}))
                store.defer(row["id"], "Invalid review", cfg["llm"], LATER, terminal=True)
        elif case == "ignored":
            row = pending(store)
            run(cfg, store, row, Writer(), Reviewer(verdict("skip", criterion="news_value")))
        elif case == "dismissed":
            row = hold_news_dispute(cfg, store)
            rejection.dismiss_item(store, row["id"], row["content_hash"], "Not news", observed=LATER)
        elif case == "pending":
            row = pending(store)

        before = dump_sql(store)
        shown = rejection.show_item(store, row["id"], config=cfg)
        if shown["final_review"] is not None and "approval" in shown["final_review"]:
            assert shown["final_review"]["approval"]["eligible"] is False
            assert expected_reason in shown["final_review"]["approval"]["reason"]
        else:
            info = review_gate.approval(cfg, store, row["id"])
            assert info["eligible"] is False
            assert expected_reason in info["reason"]
        with pytest.raises(ValueError, match=re.escape(expected_reason)):
            rejection.approve_item(cfg, store, row["id"], "a" * 64, "Attempt override", observed=AFTER_SHOW)
        assert dump_sql(store) == before


def test_the_approval_binds_inspected_text_coverage_story_lock_and_policy(tmp_path):
    # 1. Coverage change: both a new story and an updated existing story invalidate the hash and appear in new_coverage.
    cfg = config(tmp_path / "coverage")
    with Store(cfg["storage"]["database"]) as store:
        existing_src = item(url="https://example.org/existing", title="Existing coverage", content="Distinct existing story body. " * 4)
        store.ingest(existing_src, DATE)
        existing_row = store.pending(1, LATER)[0]
        finish_reviewed(store, existing_row, analysis(title="Existing coverage", evidence=["Distinct existing story body."]), "seed1", DATE)
        existing_id = store.stories()[0]["id"]

        row = hold_news_dispute(cfg, store, incoming=item(url="https://example.org/held", content="Held candidate distinct body. " * 4),
                                draft=analysis(title="Held story", evidence=["Held candidate distinct body."]))
        first_hash = rejection.show_item(store, row["id"], config=cfg)["final_review"]["approval"]["hash"]

        # Update the already-covered story (same id, newer updated_at).
        updated_src = item(
            url="https://example.org/existing",
            title="Existing coverage",
            content="Distinct existing story body with follow-up. " * 4,
            updated_at="2026-11-10T13:00:00Z",
        )
        store.ingest(updated_src, LATER)
        upd_row = store.pending(1, LATER)[0]
        finish_reviewed(store, upd_row, analysis(title="Existing coverage updated", evidence=["Distinct existing story body with follow-up."]), "seed2", "2026-11-10T13:00:00Z")

        with pytest.raises(ValueError, match="Approval hash does not match"):
            rejection.approve_item(cfg, store, row["id"], first_hash, "Stale coverage", observed=AFTER_SHOW)

        reshown = rejection.show_item(store, row["id"], config=cfg)["final_review"]["approval"]
        assert reshown["eligible"] is True
        assert [entry["id"] for entry in reshown["new_coverage"]] == [existing_id]

        # Commit a brand-new story as well.
        other_src = item(url="https://example.org/other", title="Other story", content="Completely separate announcement text. " * 4)
        store.ingest(other_src, LATER)
        other_row = store.pending(1, LATER)[0]
        finish_reviewed(store, other_row, analysis(title="Other story", evidence=["Completely separate announcement text."]), "seed3", "2026-11-10T14:00:00Z")

        with pytest.raises(ValueError, match="Approval hash does not match"):
            rejection.approve_item(cfg, store, row["id"], reshown["hash"], "Stale again", observed=AFTER_SHOW)

        third = rejection.show_item(store, row["id"], config=cfg)["final_review"]["approval"]
        assert len(third["new_coverage"]) == 2
        assert rejection.approve_item(cfg, store, row["id"], third["hash"], "Checked new coverage", observed=AFTER_SHOW)["status"] == "published"

    # 2. Prior story updated by another item while unlocked -> refused as changed.
    cfg = config(tmp_path / "prior_unlocked")
    with Store(cfg["storage"]["database"]) as store:
        shared_body = "Shared cluster body for grouped story updates. " * 4
        seed = item(url="https://example.org/s1", content=shared_body)
        store.ingest(seed, DATE)
        finish_reviewed(store, store.pending(1, LATER)[0], analysis(evidence=["Shared cluster body for grouped story updates."]), "s1", DATE)

        held_row = hold_news_dispute(
            cfg,
            store,
            incoming=item(url="https://example.org/s2", content=shared_body, updated_at="2026-11-10T01:00:00Z"),
            draft=analysis(title="Held update", evidence=["Shared cluster body for grouped story updates."]),
        )
        old_hash = rejection.show_item(store, held_row["id"], config=cfg)["final_review"]["approval"]["hash"]

        # Another item in the same cluster updates the unlocked prior story.
        third_item = item(url="https://example.org/s3", content=shared_body, updated_at="2026-11-10T02:00:00Z")
        store.ingest(third_item, LATER)
        finish_reviewed(
            store,
            store.pending(1, LATER)[0],
            analysis(title="Concurrent update", evidence=["Shared cluster body for grouped story updates."]),
            "s3",
            "2026-11-10T02:00:00Z",
        )
        with pytest.raises(ValueError, match="Its story or sources changed since the review; retry it"):
            rejection.approve_item(cfg, store, held_row["id"], old_hash, "Stale prior", observed=AFTER_SHOW)

    # 3. Prior story corrected (locked) or retracted -> refused as locked.
    cfg = config(tmp_path / "locked")
    with Store(cfg["storage"]["database"]) as store:
        shared_body = "Locked story cluster body for testing grouped updates. " * 4
        store.ingest(item(url="https://example.org/l1", content=shared_body), DATE)
        finish_reviewed(store, store.pending(1, LATER)[0], analysis(evidence=["Locked story cluster body for testing grouped updates."]), "l1", DATE)
        story_id = store.stories()[0]["id"]
        held_row = hold_news_dispute(
            cfg,
            store,
            incoming=item(url="https://example.org/l2", content=shared_body, updated_at="2026-11-10T01:00:00Z"),
            draft=analysis(title="Held update", evidence=["Locked story cluster body for testing grouped updates."]),
        )
        old_hash = rejection.show_item(store, held_row["id"], config=cfg)["final_review"]["approval"]["hash"]
        current = editorial.show(store.db, story_id)
        editorial.correct(store.db, story_id, {"title": "Corrected title"}, reason="Manual fix", expect_hash=current["hash"])
        with pytest.raises(ValueError, match="Its story is editorially locked"):
            rejection.approve_item(cfg, store, held_row["id"], old_hash, "Locked story", observed=AFTER_SHOW)

    # 4. review.model changed, wrong hash, and retry + new hold voiding older hash.
    cfg = config(tmp_path / "policy_and_retry")
    with Store(cfg["storage"]["database"]) as store:
        row = hold_news_dispute(cfg, store)
        old_hash = rejection.show_item(store, row["id"], config=cfg)["final_review"]["approval"]["hash"]

        changed_cfg = copy.deepcopy(cfg)
        changed_cfg["review"]["model"] = "other-reviewer-model"
        with pytest.raises(ValueError, match="An earlier review policy or packet reviewed it; retry it"):
            rejection.approve_item(changed_cfg, store, row["id"], old_hash, "Changed model", observed=AFTER_SHOW)

        with pytest.raises(ValueError, match="64-character lowercase hexadecimal"):
            rejection.approve_item(cfg, store, row["id"], "not-a-hash", "Bad format", observed=AFTER_SHOW)
        with pytest.raises(ValueError, match="Approval hash does not match"):
            rejection.approve_item(cfg, store, row["id"], "0" * 64, "Wrong hash", observed=AFTER_SHOW)

        rejection.retry_item(store, row["id"], row["content_hash"], "Retry review", observed=LATER)
        retried_row = store.pending(1, LATER)[0]
        later_verdict = verdict("hold", criterion="news_value")
        later_verdict["criteria"]["news_value"]["reason"] = "Different review wording after retry."
        run(cfg, store, retried_row, Writer(), Reviewer(verdict(), later_verdict))
        with pytest.raises(ValueError, match="Approval hash does not match"):
            rejection.approve_item(cfg, store, row["id"], old_hash, "Voided hash", observed=AFTER_SHOW)


def test_commit_candidate_guards_and_untouched_receipts(tmp_path):
    cfg = config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        # Seed an unrelated receipt in review_approvals and confirm neither show nor approve touches it.
        other_src = item(url="https://example.org/other", content="Unrelated receipt item body. " * 4)
        store.ingest(other_src, DATE)
        other_row = store.pending(1, LATER)[0]
        other_prep = store.prepare_candidate(other_row, analysis(evidence=["Unrelated receipt item body."]), DATE)
        seed_receipt(store, other_prep)
        receipts_before = store.db.execute("SELECT * FROM review_approvals").fetchall()
        assert len(receipts_before) == 1

        row = hold_news_dispute(cfg, store)
        prepared = store.prepare_candidate(
            dict(store.db.execute("SELECT * FROM items WHERE id=?", (row["id"],)).fetchone()),
            analysis(),
            DATE,
        )
        fake_audit = {
            "outcome": "operator_approved",
            "operator_approval": {"reason": "Attempt bypass", "approved_at": AFTER_SHOW, "approval_hash": "a" * 64, "new_coverage": []},
        }
        # Default commit_candidate path still requires a receipt even if review_record carries operator_approval.
        with pytest.raises(ReviewRequired, match="Review decision does not match"):
            store.commit_candidate(prepared, prepared["candidate"], "writer-key", AFTER_SHOW, review_record=fake_audit)

        # Operator path requires operator_approval and outcome == 'operator_approved'.
        with pytest.raises(ReviewRequired, match="operator_approval"):
            store.commit_candidate(prepared, prepared["candidate"], "writer-key", AFTER_SHOW, review_record={"outcome": "approved"}, operator=True)

        shown = rejection.show_item(store, row["id"], config=cfg)
        assert store.db.execute("SELECT * FROM review_approvals").fetchall() == receipts_before
        rejection.approve_item(cfg, store, row["id"], shown["final_review"]["approval"]["hash"], "Approved", observed=AFTER_SHOW)
        assert store.db.execute("SELECT * FROM review_approvals").fetchall() == receipts_before

        # Once published and job deleted, a repeat operator commit raises StaleCandidate.
        with pytest.raises(StaleCandidate):
            store.commit_candidate(prepared, prepared["candidate"], "writer-key", AFTER_SHOW, review_record=fake_audit, operator=True)


def test_a_failed_write_rolls_back_the_entire_approval(tmp_path):
    cfg = config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
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
        assert store.stories() == []
        assert job(store)["stage"] == "held"


def test_later_source_change_reviews_normally_and_clears_held_updates_summary(tmp_path):
    cfg = config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        row = hold_news_dispute(cfg, store)
        approval_hash = rejection.show_item(store, row["id"], config=cfg)["final_review"]["approval"]["hash"]
        approved = rejection.approve_item(cfg, store, row["id"], approval_hash, "Initial approval", observed=LATER)
        story_id = approved["story_id"]

        # Lock, hold an update while locked, unlock, then approve a subsequent held update -> clears held_updates.
        current = editorial.show(store.db, story_id)
        locked = editorial.correct(store.db, story_id, {"summary": "Corrected summary."}, reason="Fix wording", expect_hash=current["hash"])
        rev2 = item(content="Second upstream revision after approval. " * 4, updated_at="2026-11-10T13:00:00Z")
        assert store.ingest(rev2, "2026-11-10T13:00:00Z") is True
        writer2, reviewer2 = Writer(analysis(evidence=["Second upstream revision after approval."])), Reviewer()
        assert run(cfg, store, store.pending(1, "2026-11-10T13:05:00Z")[0], writer2, reviewer2)["status"] == "locked"
        assert len(writer2.calls) == 1
        assert decisions.summary(store.db, DATE)["awaiting_operator"]["held_updates"] == [
            {"story_id": story_id, "held_updates": 1, "locked": True}
        ]

        editorial.unlock(store.db, story_id, reason="Resume updates", expect_hash=locked["hash"])
        rev3 = item(content="Third upstream revision disputed on news value. " * 4, updated_at="2026-11-10T14:00:00Z")
        assert store.ingest(rev3, "2026-11-10T14:00:00Z") is True
        writer3 = Writer(update_analysis(update="Third revision update.", evidence=["Third upstream revision disputed on news value."]))
        reviewer3 = Reviewer(verdict(update=True), verdict("hold", criterion="news_value", update=True))
        assert run(cfg, store, store.pending(1, "2026-11-10T14:05:00Z")[0], writer3, reviewer3)["status"] == "held"
        assert len(writer3.calls) == 1 and len(reviewer3.calls) == 2

        upd_hash = rejection.show_item(store, row["id"], config=cfg)["final_review"]["approval"]["hash"]
        rejection.approve_item(cfg, store, row["id"], upd_hash, "Approve follow-up", observed=AFTER_SHOW)
        assert store.stories()[0]["title"] == "Operator reports possible compromise"
        assert store.stories()[0]["updates"][-1]["text"] == "Third revision update."
        assert decisions.summary(store.db, DATE)["awaiting_operator"]["held_updates"] == []


@pytest.mark.parametrize(
    "mutator",
    [
        None,
        *[{"damage": kind} for kind in DAMAGE],
        {"record_json": '{"reviews": "not-a-list"}'},
        {"record_json": '{"reviews": [{"stage": "bogus"}]}'},
        {"record_json": '{"reviews": [], "policy_hash": "x", "prepared": {"coverage": "bad"}}'},
        {"writer_key": ""},
    ],
)
def test_show_with_approval_stays_read_only_and_survives_damaged_records(tmp_path, mutator):
    cfg = config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        row = hold_news_dispute(cfg, store)
        if mutator is not None:
            column, value = next(iter(mutator.items()))
            if column == "damage":
                saved_record = store.db.execute("SELECT record_json FROM review_jobs WHERE item_id=?", (row["id"],)).fetchone()[0]
                column, value = "record_json", damaged(saved_record, value)
            with store.db:
                store.db.execute(f"UPDATE review_jobs SET {column}=? WHERE item_id=?", (value, row["id"]))
        before = dump_sql(store)
        shown = rejection.show_item(store, row["id"], config=cfg)
        assert dump_sql(store) == before
        info = shown["final_review"]["approval"]
        if mutator is None:
            assert info["eligible"] is True
        else:
            assert info["eligible"] is False
            assert isinstance(info["reason"], str) and info["reason"]


@pytest.mark.parametrize(
    "draft_overrides,responses,expected_eligible",
    [
        # Repaired text verified, only news_value failed (invented-impact shape).
        ({}, [verdict("revise", criterion="source_support", repair={"summary": "Supported summary."}),
              verdict("hold", criterion="news_value")], True),
        # Mirror hold: first review failed news_value with repair, verification approved (one-probe / badexit).
        ({}, [verdict("revise", criterion="news_value", repair={"title": "Qualified report"}),
              verdict()], True),
        # Not approvable: verification failed status (merged-as-released / requested-as-done).
        ({}, [verdict(), verdict("hold", criterion="status")], False),
        # Not approvable: verification failed source_support (wrong-advice-audience).
        ({}, [verdict(), verdict("hold", criterion="source_support")], False),
        # Not approvable: synthetic release-label conversion (category release, state merged).
        ({"category": "release", "state": "merged", "tags": ["tor", "release"]},
         [verdict("revise", criterion="actor_and_action", repair={"summary": "Merged branch."}),
          verdict("hold", criterion="news_value")], False),
    ],
)
def test_deterministic_replay_of_saved_dispute_shapes(tmp_path, draft_overrides, responses, expected_eligible):
    cfg = config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        row = pending(store)
        draft = analysis(**draft_overrides)
        assert run(cfg, store, row, Writer(draft), Reviewer(*responses))["status"] == "held"
        info = rejection.show_item(store, row["id"], config=cfg)["final_review"]["approval"]
        assert info["eligible"] is expected_eligible


@pytest.mark.parametrize(
    "tamper,expected_reason",
    [
        ("review_entry_policy_hash", "An earlier review policy or packet reviewed it; retry it"),
        ("review_entry_source_hash", "An earlier review policy or packet reviewed it; retry it"),
        ("envelope_prior_story_binding", "Its story or sources changed since the review; retry it"),
        ("verified_facts_flag", "No fresh verification with cited sources approved the facts; retry or dismiss it"),
        ("base_candidate_verified_only_as_review", "No fresh verification reviewed this exact text"),
    ],
)
def test_single_field_record_and_binding_tampering_refuses(tmp_path, tamper, expected_reason):
    cfg = config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        if tamper == "base_candidate_verified_only_as_review":
            row = pending(store)
            assert run(
                cfg,
                store,
                row,
                Writer(),
                Reviewer(
                    verdict("revise", criterion="news_value", repair={"title": "Repaired title"}),
                    verdict(),
                ),
            )["status"] == "held"
        else:
            row = hold_news_dispute(cfg, store)
        saved = store.db.execute(
            "SELECT envelope_json,record_json FROM review_jobs WHERE item_id=?",
            (row["id"],),
        ).fetchone()
        envelope = json.loads(saved["envelope_json"])
        record = json.loads(saved["record_json"])
        if tamper == "review_entry_policy_hash":
            record["reviews"][0]["policy_hash"] = "0" * 64
        elif tamper == "review_entry_source_hash":
            record["reviews"][0]["source_hash"] = "0" * 64
        elif tamper == "envelope_prior_story_binding":
            envelope["binding"]["prior_story"] = "0" * 64
        elif tamper == "verified_facts_flag":
            record["verified_facts"] = False
        elif tamper == "base_candidate_verified_only_as_review":
            record["candidate"] = copy.deepcopy(record["prepared"]["candidate"])
        with store.db:
            store.db.execute(
                "UPDATE review_jobs SET envelope_json=?,record_json=? WHERE item_id=?",
                (json.dumps(envelope), json.dumps(record), row["id"]),
            )
        info = review_gate.approval(cfg, store, row["id"])
        assert info["eligible"] is False
        assert expected_reason in info["reason"]


@pytest.mark.parametrize("bad_updates", [[{}], ["malformed"], "not-a-list", [{"at": LATER}]])
def test_malformed_saved_update_entries_refuse_without_raising(tmp_path, bad_updates):
    cfg = config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        first = item(
            url="https://example.org/orig",
            title="Initial relay report",
            content="Initial relay report on directory fetch behavior.",
        )
        store.ingest(first, DATE)
        finish_reviewed(store, store.pending(1, DATE)[0], analysis(), "seed-orig", DATE)

        follow = item(
            url="https://example.org/orig",
            title="Initial relay report",
            content="Initial relay report on directory fetch behavior. Later maintainer confirmation.",
            updated_at=LATER,
        )
        row = hold_news_dispute(
            cfg,
            store,
            incoming=follow,
            draft=update_analysis(
                update="Maintainers confirmed the directory fetch behavior.",
                evidence=["Later maintainer confirmation."],
            ),
        )
        saved = store.db.execute("SELECT record_json FROM review_jobs WHERE item_id=?", (row["id"],)).fetchone()
        record = json.loads(saved["record_json"])
        record["candidate"]["updates"] = bad_updates
        with store.db:
            store.db.execute("UPDATE review_jobs SET record_json=? WHERE item_id=?", (json.dumps(record), row["id"]))
        info = review_gate.approval(cfg, store, row["id"])
        assert info["eligible"] is False
        assert info["reason"] == "Saved review record cannot be read"
