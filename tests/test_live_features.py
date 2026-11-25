"""Tests for living story refresh, sliding-window overlapped pipeline, PT priority, and live eval harvester."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import sys
import threading

import httpx
import pytest

from helpers import (
    DATE,
    LATER,
    ApprovingReviewer,
    Writer,
    analysis,
    finish_reviewed,
    item,
    make_config,
    patch_cli_pipeline,
    pending,
    public_dns,
    seed_story,
    update_analysis,
    verdict,
)
from onionflash import cli, editorial, llm, refresh, review, review_gate
from onionflash.analyze import AnalysisError, cache_key
from onionflash.config import DEFAULTS
from onionflash.store import PT_SECURITY_PRIORITY, Store, item_priority
from onionflash.transport import HttpClient
from onionflash.util import after, digest

ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = ROOT / "tools"


def _load_tool(name: str):
    path = TOOLS_DIR / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _add_story_updates(
    store: Store, story_id: str, count: int, *, base_date: str = DATE, start_idx: int = 1
) -> list[dict]:
    """Attach `count` real item-backed updates to `story_id` and return the update source items."""
    created: list[dict] = []
    for idx in range(start_idx, start_idx + count):
        ts = after(idx * 3600, base_date)
        upd_item = item(
            url=f"https://example.org/story-upd/{story_id}/{idx}",
            title=f"Follow-up milestone {idx}",
            content=f"Follow-up milestone {idx} provides concrete verification details for {story_id}.",
            published_at=ts,
            updated_at=ts,
        )
        row = pending(store, upd_item, at=ts, ready=ts, target=story_id)
        upd_draft = update_analysis(
            update=f"Milestone {idx} added concrete operational verification.",
            evidence=[upd_item["content"]],
        )
        finish_reviewed(store, row, upd_draft, cache_key(row, DEFAULTS["llm"]), ts)
        created.append(upd_item)
    return created


def test_story_refresh_eligibility_commit_preservation_and_re_eligibility(tmp_path):
    """Select eligible >=3-update stories, preserve immutable fields on commit, and re-trigger only on +2 new updates."""
    db_path = tmp_path / "refresh.sqlite3"
    with Store(db_path) as store:
        # Story columns must stay unchanged for onionflash-deploy compatibility.
        story_cols = [r[1] for r in store.db.execute("PRAGMA table_info(stories)").fetchall()]
        assert story_cols == ["id", "cluster_key", "payload", "published_at", "updated_at"]
        sr_cols = {r[1] for r in store.db.execute("PRAGMA table_info(story_refreshes)").fetchall()}
        assert sr_cols == {"story_id", "last_refreshed_at", "update_count", "refreshed_hash", "status"}

        s1_item = item(url="https://example.org/s1", title="Initial issue 1", content="Initial issue one body.")
        s1 = seed_story(store, s1_item, analysis(title="Initial issue 1", summary="Initial issue one body.", evidence=["Initial issue one body."]))
        _add_story_updates(store, s1["id"], 2)  # only 2 updates -> ineligible
        assert store.refresh_candidates(limit=5) == []

        _add_story_updates(store, s1["id"], 1, start_idx=3)  # now 3 updates -> eligible
        cands = store.refresh_candidates(limit=5)
        assert [c["story_id"] for c in cands] == [s1["id"]]
        before = json.loads(store.db.execute("SELECT payload FROM stories WHERE id=?", (s1["id"],)).fetchone()[0])
        before_row = store.db.execute("SELECT published_at, updated_at FROM stories WHERE id=?", (s1["id"],)).fetchone()

        # Commit refreshed title, summary, why_it_matters.
        res = store.commit_story_refresh(
            s1["id"],
            {
                "title": "Initial issue 1 progresses through three milestones",
                "summary": "Initial issue one was reported and subsequently verified through three follow-up milestones.",
                "why_it_matters": "Operators track three verified follow-up milestones.",
            },
            3,
            LATER,
        )
        assert res["status"] == "refreshed" and res["update_count"] == 3
        after_row = store.db.execute("SELECT published_at, updated_at, payload FROM stories WHERE id=?", (s1["id"],)).fetchone()
        after_payload = json.loads(after_row["payload"])

        assert (after_row["published_at"], after_row["updated_at"]) == (before_row["published_at"], before_row["updated_at"])
        for preserved in ("id", "published_at", "updated_at", "added_at", "sources", "updates", "category", "priority", "confidence", "state", "products", "tags"):
            assert after_payload[preserved] == before[preserved]
        assert after_payload["summary"].startswith("Initial issue one was reported")
        assert store.get_meta("publication_build_pending") == "1"
        assert store.refresh_candidates(limit=5) == []

        # Adding only +1 update (total 4) is NOT enough for re-refresh.
        _add_story_updates(store, s1["id"], 1, start_idx=4)
        assert store.refresh_candidates(limit=5) == []

        # Adding a 2nd additional update (total 5, +2 since last refresh) makes it eligible again.
        _add_story_updates(store, s1["id"], 1, start_idx=5)
        re_cands = store.refresh_candidates(limit=5)
        assert len(re_cands) == 1 and re_cands[0]["update_count"] == 5


def test_story_refresh_excludes_locked_retracted_retired_and_missing_bodies(tmp_path):
    """Bail cleanly on missing cited bodies and never refresh locked, retracted, or retired stories."""
    cfg = make_config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        # 1) Story with 3 updates whose 2nd update body gets compacted/deleted -> skipped in story_refreshes.
        s_missing = seed_story(store, item(url="https://example.org/missing-src"), analysis())
        upd_items = _add_story_updates(store, s_missing["id"], 3)
        with store.db:
            store.db.execute("DELETE FROM items WHERE url=?", (upd_items[1]["url"],))
            store.db.execute("DELETE FROM analyses WHERE source_payload LIKE ?", (f"%{upd_items[1]['url']}%",))

        class _NeverCalledRefresher:
            calls = 0

            def synthesize(self, *_a):
                raise AssertionError("Refresher LLM must not be called when cited body is missing")

        cand = store.refresh_candidates(limit=5)[0]
        outcome = refresh.refresh_story(store, cand, _NeverCalledRefresher(), ApprovingReviewer(), LATER)
        assert outcome["status"] == "skipped" and outcome["reason"] == "missing_cited_body"
        sr = store.db.execute("SELECT status FROM story_refreshes WHERE story_id=?", (s_missing["id"],)).fetchone()
        assert sr["status"] == "skipped"
        # Not retried endlessly on subsequent runs.
        assert store.refresh_candidates(limit=5) == []

        # 2) Locked story (via editorial.correct -> auto-locks, or manual lock) excluded from candidates & commit.
        s_locked = seed_story(store, item(url="https://example.org/locked-src", content="Locked body content."), analysis(evidence=["Locked body content."]))
        _add_story_updates(store, s_locked["id"], 3)
        editorial.correct(
            store.db,
            s_locked["id"],
            {"title": "Operator corrected locked title"},
            reason="Lock test",
            expect_hash=editorial.show(store.db, s_locked["id"])["hash"],
            observed=LATER,
        )
        assert store.refresh_candidates(limit=5) == []
        with pytest.raises(Exception):
            store.commit_story_refresh(s_locked["id"], {"title": "X", "summary": "Y.", "why_it_matters": ""}, 3, LATER)

        # 3) Retracted/retired story excluded from candidates.
        s_ret = seed_story(store, item(url="https://example.org/retracted-src", content="Retracted body."), analysis(evidence=["Retracted body."]))
        _add_story_updates(store, s_ret["id"], 3)
        editorial.retract(
            store.db,
            s_ret["id"],
            reason="Retracted",
            expect_hash=editorial.show(store.db, s_ret["id"])["hash"],
            observed=LATER,
        )
        assert store.refresh_candidates(limit=5) == []


def test_story_refresh_fail_closed_verification_and_cli_run_wiring(tmp_path, monkeypatch):
    """Fail-closed on non-approve verification, commit approved refreshes in cli.run, and keep report keys exact."""
    cfg = make_config(tmp_path)
    cfg["sources"] = []
    cfg["llm"].update(base_url="https://llm.example/v1", api_key_env="REFRESH_TEST_KEY")
    monkeypatch.setenv("REFRESH_TEST_KEY", "synthetic-fixture-value")
    patch_cli_pipeline(monkeypatch, now=DATE, reviewer=None, no_build=False)

    with Store(cfg["storage"]["database"]) as store:
        # Story A: reviewer rejects with 'hold' -> must NOT modify story and must record 'held'.
        s_hold = seed_story(store, item(url="https://example.org/hold-story", content="Initial report A."), analysis(title="Initial A", summary="Initial report A.", evidence=["Initial report A."]))
        _add_story_updates(store, s_hold["id"], 3)

        # Story B: reviewer approves -> must commit and build into public HTML/JSON!
        s_ok = seed_story(store, item(url="https://example.org/ok-story", content="Initial report B."), analysis(title="Initial B", summary="Initial report B.", evidence=["Initial report B."]))
        _add_story_updates(store, s_ok["id"], 3, base_date=after(5000, DATE))

        seen_schemas: list[str] = []
        seen_verifications: list[bool] = []

        def _handle(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            schema_name = body["response_format"]["json_schema"]["name"]
            seen_schemas.append(schema_name)
            if schema_name == "onionflash_refresh":
                user_msg = json.loads(body["messages"][1]["content"])
                title = user_msg["current_story"]["title"]
                reply = {
                    "title": f"{title} updated",
                    "summary": "The initial report was followed by three verified operational updates.",
                    "why_it_matters": "Operators track the combined lifecycle across three verified updates.",
                }
            else:
                user_msg = json.loads(body["messages"][1]["content"])
                seen_verifications.append("Fresh verification" in body["messages"][0]["content"] or "adversarial" in body["messages"][0]["content"].lower())
                if user_msg["candidate"]["id"] == s_hold["id"]:
                    reply = verdict("hold", criterion="source_support", reason="Refreshed narrative lacks exact support.")
                else:
                    reply = verdict("approve")
            return httpx.Response(200, json={"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(reply)}}]})

        monkeypatch.setattr(
            llm,
            "HttpClient",
            lambda settings, **kwargs: HttpClient(
                settings, **kwargs, transport=httpx.MockTransport(_handle), resolver=public_dns
            ),
        )

        report = cli.run(cfg, store)
        assert set(report) == {
            "sources_ok", "sources_failed", "items_changed", "analyzed", "analysis_failed",
            "budget_reached", "entries_skipped", "review_cache_hits", "review_stale",
            "review_routed", "model_calls", "registry", "comments", "decisions",
            "pending_analysis", "rejected_analysis", "final_review",
            "public_changed", "published_stories", "stories_skipped",
        }
        assert "onionflash_refresh" in seen_schemas
        assert seen_verifications and all(seen_verifications)
        assert report["model_calls"] >= 4

        held_payload = json.loads(store.db.execute("SELECT payload FROM stories WHERE id=?", (s_hold["id"],)).fetchone()[0])
        assert held_payload["summary"] == "Initial report A."
        assert store.db.execute("SELECT status FROM story_refreshes WHERE story_id=?", (s_hold["id"],)).fetchone()[0] == "held"

        ok_payload = json.loads(store.db.execute("SELECT payload FROM stories WHERE id=?", (s_ok["id"],)).fetchone()[0])
        assert ok_payload["summary"] == "The initial report was followed by three verified operational updates."
        assert store.db.execute("SELECT status FROM story_refreshes WHERE story_id=?", (s_ok["id"],)).fetchone()[0] == "refreshed"

        pub_story = json.loads((Path(cfg["storage"]["output_dir"]) / "news" / s_ok["id"] / "story.json").read_text())
        assert pub_story["summary"] == "The initial report was followed by three verified operational updates."
        meta_summary = json.loads(store.get_meta("story_refresh_last"))
        assert meta_summary == {"at": DATE, "attempted": 2, "refreshed": 1, "held": 1, "skipped": 0}


def test_story_refresh_retryable_error_and_specialist_verification(tmp_path):
    """Keep story_refreshes clean on retryable errors and support optional specialist verification."""
    cfg = make_config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        s1 = seed_story(store, item(url="https://example.org/spec-story", content="Spec story body."), analysis(evidence=["Spec story body."]))
        _add_story_updates(store, s1["id"], 3)
        cand = store.refresh_candidates(limit=2)[0]

        class _RetryableRefresher:
            calls = 1

            def synthesize(self, *_a):
                raise AnalysisError("HTTP 503", retryable=True)

        stats = refresh.refresh_due_stories(cfg, store, ApprovingReviewer(), LATER, refresher=_RetryableRefresher())
        assert stats["endpoint_failures"] == 1
        assert store.db.execute("SELECT COUNT(*) FROM story_refreshes").fetchone()[0] == 0

        class _GoodRefresher:
            calls = 1

            def synthesize(self, story_payload, _pkt):
                return {
                    "title": story_payload["title"],
                    "summary": "Synthesized summary across all three updates.",
                    "why_it_matters": "",
                }

        seen_specs: list[str | None] = []

        class _SpecReviewer:
            def review(self, candidate_public, packet, *, verification=False, coverage=None, specialist=None):
                seen_specs.append(specialist)
                return verdict("approve")

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(review, "SPECIALISTS", ("grounding_status", "attribution_scope_advice", "novelty_news"), raising=False)
            mp.setattr(
                review,
                "merge_specialist_verdicts",
                lambda verdicts, cand_pub, pkt: verdict("approve") if all(v["verdict"] == "approve" for v in verdicts) else verdict("hold"),
                raising=False,
            )
            out = refresh.refresh_story(
                store,
                cand,
                _GoodRefresher(),
                _SpecReviewer(),
                LATER,
                reviewer_factory=lambda: _SpecReviewer(),
                specialists=3,
            )
        assert out["status"] == "refreshed"
        assert set(seen_specs) == {"grounding_status", "attribution_scope_advice", "novelty_news"}


def test_sliding_window_overlaps_draft_and_review_and_skips_deterministic_before_draft(tmp_path, monkeypatch):
    """Overlap review of completed drafts with next draft dispatch, bounded to MAX_CONCURRENT_LLM_ITEMS, skipping deterministic items pre-LLM."""
    cfg = make_config(tmp_path)
    cfg["sources"] = []
    cfg["llm"].update(base_url="https://llm.example/v1", api_key_env="SLIDING_KEY", max_items_per_run=12)
    monkeypatch.setenv("SLIDING_KEY", "synthetic-fixture-value")
    patch_cli_pipeline(monkeypatch, now=DATE, reviewer=None, build=lambda *_a: {})

    with Store(cfg["storage"]["database"]) as store:
        # Two deterministic skips that must NEVER trigger an LLM draft call.
        old_item = item(
            url="https://example.org/sw-old",
            title="Old defect report",
            content="Old issue body.",
            published_at="2026-09-01T00:00:00Z",
            updated_at="2026-09-01T00:00:00Z",
            labels=[],
        )
        ack_item = item(
            url="https://example.org/sw-ack",
            title="Re: thread",
            content="Thanks!",
            labels=[],
        )
        store.ingest(old_item, DATE)
        store.ingest(ack_item, DATE)

        # Six eligible items: window=4 means 0..3 start first; fast item 0 completes and immediately triggers
        # BOTH item 4's draft dispatch AND item 0's review while items 1..3 are still drafting!
        eligible_items = [
            item(
                url=f"https://example.org/sw-item-{i}",
                title=f"Sliding window report {i}",
                content=f"Distinct verifiable network defect {i} reported.",
                priority="high",
            )
            for i in range(6)
        ]
        # Give item 0 highest priority so it enters the initial window of 4.
        for i, entry in enumerate(eligible_items):
            store.ingest(entry, DATE)
            with store.db:
                store.db.execute("UPDATE items SET priority_score=? WHERE url=?", (100 - i, entry["url"]))

        lock = threading.Lock()
        in_flight = 0
        max_in_flight = 0
        drafted_titles: list[str] = []
        hold_slow_drafts = threading.Event()
        fifth_draft_started = threading.Event()
        first_review_started = threading.Event()
        initial_three_entered = 0
        three_slow_ready = threading.Event()

        def _handle(request: httpx.Request) -> httpx.Response:
            nonlocal in_flight, max_in_flight, initial_three_entered
            body = json.loads(request.content)
            schema_name = body["response_format"]["json_schema"]["name"]
            if schema_name == "onionflash_news":
                user_payload = json.loads(body["messages"][1]["content"])
                title = user_payload["title"]
                with lock:
                    in_flight += 1
                    max_in_flight = max(max_in_flight, in_flight)
                    drafted_titles.append(title)
                    is_fast = title.endswith(" 0")
                    is_followup = title.endswith((" 4", " 5"))
                    if not is_fast and not is_followup:
                        initial_three_entered += 1
                        if initial_three_entered >= 3:
                            three_slow_ready.set()
                    if is_followup:
                        fifth_draft_started.set()
                try:
                    if not is_fast and not is_followup:
                        three_slow_ready.wait(timeout=5.0)
                        hold_slow_drafts.wait(timeout=5.0)
                    reply = analysis(
                        title=title,
                        summary=user_payload["content"],
                        why_it_matters="",
                        evidence=[user_payload["content"]],
                    )
                finally:
                    with lock:
                        in_flight -= 1
            elif schema_name == "onionflash_polish":
                draft = json.loads(body["messages"][1]["content"])["draft"]
                reply = {k: draft[k] for k in ("title", "summary", "why_it_matters")}
            else:
                first_review_started.set()
                if fifth_draft_started.is_set() and first_review_started.is_set():
                    hold_slow_drafts.set()
                reply = verdict("approve")
            return httpx.Response(200, json={"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(reply)}}]})

        monkeypatch.setattr(
            llm,
            "HttpClient",
            lambda settings, **kwargs: HttpClient(
                settings, **kwargs, transport=httpx.MockTransport(_handle), resolver=public_dns
            ),
        )

        report = cli.run(cfg, store)
        assert max_in_flight <= cli.MAX_CONCURRENT_LLM_ITEMS
        assert max_in_flight == 4
        assert fifth_draft_started.is_set()
        assert first_review_started.is_set()
        assert all(t.startswith("Sliding window report") for t in drafted_titles)
        assert len(drafted_titles) == 6
        assert len(store.stories()) == 6
        assert report["analyzed"] == 8  # 6 published + 2 deterministic skips
        assert report["analysis_failed"] == 0


def test_harvest_eval_readonly_all_buckets_sanitization_and_eval_compatibility(tmp_path):
    """Harvest all 5 buckets read-only into a sanitized dataset compatible with evaluate_review and run_suite1."""
    harvest_eval = _load_tool("harvest_eval")
    evaluate_review = _load_tool("evaluate_review")

    db_path = tmp_path / "live.sqlite3"
    out_path = tmp_path / "harvested.json"

    with Store(db_path) as store:
        # 1) Held review job item (with secret-like pattern to verify redaction).
        held_it = item(
            url="https://example.org/held-1",
            title="Held item Authorization: Bearer supersecret_token_999999",
            content="The report mentions glpat-abcdefghijklmnop123456 in logs.",
        )
        held_row = pending(store, held_it, at=DATE, ready=DATE)
        review_gate.process_item(
            make_config(tmp_path),
            store,
            held_row,
            Writer(analysis(title="Held candidate", summary="Held summary.", evidence=[held_it["content"]])),
            __import__("helpers").Reviewer(verdict("hold")),
            DATE,
        )

        # 2) Rejection action item.
        rej_it = item(url="https://example.org/rej-1", title="Rejected item", content="Rejected content body.")
        store.ingest(rej_it, DATE)
        for _ in range(3):
            store.defer(rej_it["id"], "Bad draft", make_config(tmp_path)["llm"], DATE, terminal=True)
        from onionflash import rejection

        show_rej = rejection.show_item(store, rej_it["id"])
        rejection.retry_item(store, rej_it["id"], show_rej["content_hash"], "Retry after fix", LATER)

        # 3) Editorial revision story.
        ed_it = item(url="https://example.org/ed-1", title="Editorial story", content="Editorial story content.")
        ed_story = seed_story(store, ed_it, analysis(title="Editorial story", summary="Initial editorial summary.", evidence=["Editorial story content."]))
        editorial.correct(
            store.db,
            ed_story["id"],
            {"summary": "Corrected editorial summary."},
            reason="Clarify scope",
            expect_hash=editorial.show(store.db, ed_story["id"])["hash"],
            observed=LATER,
        )

        # 4) High-comment item (>= 8 comments).
        hc_comments = [
            {
                "id": f"gid://gitlab/Note/{i}",
                "url": f"https://gitlab.torproject.org/tpo/core/tor/-/work_items/900#note_{i}",
                "title": f"Public comment by @user{i}",
                "author": f"user{i}",
                "created_at": after(i * 60, DATE),
                "body": f"Comment body {i} with technical note.",
            }
            for i in range(1, 10)
        ]
        hc_it = item(
            url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/900",
            title="High comment issue",
            content="Long discussion thread issue body.",
            public_comments=hc_comments,
        )
        seed_story(store, hc_it, analysis(title="High comment issue", summary="Long discussion summary.", evidence=["Long discussion thread issue body."]))

        # 5) Multi-update story (>= 3 updates).
        mu_it = item(url="https://example.org/mu-1", title="Multi-update story", content="Multi-update initial body.")
        mu_story = seed_story(store, mu_it, analysis(title="Multi-update story", summary="Multi-update summary.", evidence=["Multi-update initial body."]))
        _add_story_updates(store, mu_story["id"], 3)

    # Lock source DB read-only and verify hash does not change.
    before_bytes = db_path.read_bytes()
    before_sha = hashlib.sha256(before_bytes).hexdigest()
    os.chmod(db_path, 0o444)
    try:
        rc = harvest_eval.main([
            "--db", str(db_path),
            "--output", str(out_path),
            "--limit", "50",
            "--max-per-bucket", "5",
            "--include-updates",
        ])
        assert rc == 0
    finally:
        os.chmod(db_path, 0o600)

    assert hashlib.sha256(db_path.read_bytes()).hexdigest() == before_sha

    raw_text = out_path.read_text(encoding="utf-8")
    assert "supersecret_token_999999" not in raw_text
    assert "glpat-abcdefghijklmnop123456" not in raw_text
    dataset = json.loads(raw_text)

    assert {"items", "packets", "buckets", "cases", "defaults", "background_stories"} <= set(dataset)
    for bucket_name in ("held_review_jobs", "rejection_actions", "editorial_revisions", "high_comment_items", "multi_update_stories"):
        assert len(dataset["buckets"][bucket_name]) >= 1

    # Verify evaluate_review.py compatibility (story + latest_update + draft_cases).
    expanded = evaluate_review.expand(dataset)
    evaluate_review._validate_cases(expanded)
    assert any(c["scope"] == "latest_update" for c in expanded)
    drafted = evaluate_review.draft_cases(dataset)
    evaluate_review._validate_cases(drafted, draft=True)
    for c in expanded:
        first_src = c["packet"]["sources"][0]
        w_item = evaluate_review.writer_item(first_src)
        assert isinstance(w_item["content"], str)

    # Verify run_suite1.py compatibility (all items are replay-ready pending rows).
    assert len(dataset["items"]) >= 4
    for entry in dataset["items"]:
        assert {"group", "item_id", "item_row", "seed_analyses", "seed_rejection_actions", "exclude_story_ids"} <= set(entry)
        assert entry["item_row"]["status"] == "pending"
        assert entry["item_row"]["next_attempt_at"] is None
        assert len(json.loads(entry["item_row"]["payload"])["title"]) > 0

    # Verify --limit and --max-per-bucket bounds.
    bounded_out = tmp_path / "bounded.json"
    assert harvest_eval.main(["--db", str(db_path), "--output", str(bounded_out), "--limit", "3", "--max-per-bucket", "1"]) == 0
    bounded = json.loads(bounded_out.read_text())
    assert len(bounded["cases"]) <= 3
    assert all(len(v) <= 1 for v in bounded["buckets"].values())
