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
    make_note,
    patch_cli_pipeline,
    pending,
    public_dns,
    seed_story,
    update_analysis,
    verdict,
)
from onionflash import candidate as candidate_mod, cli, editorial, llm, refresh, review, review_gate
from onionflash.analyze import AnalysisError, Analyzer, cache_key
from onionflash.config import DEFAULTS
from onionflash.store import PT_SECURITY_PRIORITY, Store, item_priority, story_refresh_hash
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
            cands[0]["refreshed_hash"],
            LATER,
            base_prose={k: before.get(k, "") for k in ("title", "summary", "why_it_matters")},
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
                """Fail immediately if called when cited source bodies are missing."""
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
        s_unlocked = seed_story(store, item(url="https://example.org/unlocked-src", content="Unlocked body content."), analysis(evidence=["Unlocked body content."]))
        _add_story_updates(store, s_unlocked["id"], 3)
        editorial.correct(
            store.db,
            s_locked["id"],
            {"title": "Operator corrected locked title"},
            reason="Lock test",
            expect_hash=editorial.show(store.db, s_locked["id"])["hash"],
            observed=LATER,
        )
        locked_payload = json.loads(store.db.execute("SELECT payload FROM stories WHERE id=?", (s_locked["id"],)).fetchone()[0])
        unlocked_payload = json.loads(store.db.execute("SELECT payload FROM stories WHERE id=?", (s_unlocked["id"],)).fetchone()[0])
        valid_refresh = {
            "title": "Valid refreshed summary title",
            "summary": "Consolidated updates report verified progress.",
            "why_it_matters": "",
        }
        assert [c["story_id"] for c in store.refresh_candidates(limit=5)] == [s_unlocked["id"]]
        with pytest.raises(candidate_mod.StaleCandidate, match="locked"):
            store.commit_story_refresh(
                s_locked["id"],
                valid_refresh,
                3,
                story_refresh_hash(locked_payload),
                LATER,
                base_prose={k: locked_payload.get(k, "") for k in ("title", "summary", "why_it_matters")},
            )
        assert store.commit_story_refresh(
            s_unlocked["id"],
            valid_refresh,
            3,
            story_refresh_hash(unlocked_payload),
            LATER,
            base_prose={k: unlocked_payload.get(k, "") for k in ("title", "summary", "why_it_matters")},
        )["status"] == "refreshed"

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
                """Raise a retryable AnalysisError."""
                raise AnalysisError("HTTP 503", retryable=True)

        stats = refresh.refresh_due_stories(cfg, store, ApprovingReviewer(), LATER, refresher=_RetryableRefresher())
        assert stats["endpoint_failures"] == 1
        assert store.db.execute("SELECT COUNT(*) FROM story_refreshes").fetchone()[0] == 0

        class _GoodRefresher:
            calls = 1

            def synthesize(self, story_payload, _pkt):
                """Return a valid refreshed summary across updates."""
                return {
                    "title": story_payload["title"],
                    "summary": "Synthesized summary across all three updates.",
                    "why_it_matters": "",
                }

        seen_specs: list[str | None] = []

        class _SpecReviewer:
            def review(self, candidate_public, packet, *, verification=False, coverage=None, specialist=None):
                """Record requested specialist name and approve."""
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
        saw_blocked_draft_during_review = False
        wait_timeouts: list[str] = []

        def _handle(request: httpx.Request) -> httpx.Response:
            nonlocal in_flight, max_in_flight, initial_three_entered, saw_blocked_draft_during_review
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
                        if not three_slow_ready.wait(timeout=5.0):
                            with lock:
                                wait_timeouts.append("three_slow_ready")
                        if not hold_slow_drafts.wait(timeout=5.0):
                            with lock:
                                wait_timeouts.append("hold_slow_drafts")
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
                with lock:
                    if in_flight > 0:
                        saw_blocked_draft_during_review = True
                if fifth_draft_started.is_set() and first_review_started.is_set():
                    hold_slow_drafts.set()
                reply = verdict("approve")
            return httpx.Response(200, json={"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(reply)}}]})

        monkeypatch.setattr(
            cli,
            "_new_analyzer",
            lambda c, *, deadline=None, request_semaphore=None: cli.Analyzer(
                c, deadline=deadline, editorial_polish=True, best_of=1, quote_digest=False, request_semaphore=request_semaphore
            ),
        )
        monkeypatch.setattr(
            llm,
            "HttpClient",
            lambda settings, **kwargs: HttpClient(
                settings, **kwargs, transport=httpx.MockTransport(_handle), resolver=public_dns
            ),
        )

        try:
            report = cli.run(cfg, store)
        finally:
            three_slow_ready.set()
            hold_slow_drafts.set()
        assert not wait_timeouts
        assert saw_blocked_draft_during_review
        assert max_in_flight <= cli.MAX_CONCURRENT_LLM_ITEMS
        assert fifth_draft_started.is_set()
        assert first_review_started.is_set()
        assert all(t.startswith("Sliding window report") for t in drafted_titles)
        assert len(drafted_titles) == 6
        assert len(store.stories()) == 6
        assert report["analyzed"] == 8  # 6 published + 2 deterministic skips
        assert report["analysis_failed"] == 0


def test_sliding_window_bounds_concurrent_http_under_best_of_3_and_specialists_3(context, monkeypatch):
    """Bound concurrent writer HTTP calls to MAX_CONCURRENT_LLM_ITEMS even when best_of=3 and specialists=3 run."""
    cfg, store = context
    cfg["sources"] = []
    cfg["llm"].update(base_url="https://llm.example/v1", api_key_env="SW_SEM_KEY")
    monkeypatch.setenv("SW_SEM_KEY", "synthetic-fixture-value")
    patch_cli_pipeline(monkeypatch, now=DATE, reviewer=None, build=lambda *_a: {})

    for i in range(4):
        store.ingest(
            item(
                url=f"https://example.org/sw-sem-{i}",
                title=f"Sliding bounded report {i}",
                content=f"Sliding bounded content {i} describing a relay consensus event.",
            ),
            DATE,
        )

    lock = threading.Lock()
    in_flight = 0
    max_in_flight = 0
    counts = {"news": 0, "select": 0, "polish": 0, "review": 0}
    barrier = threading.Barrier(4, timeout=5.0)

    def _handle(request: httpx.Request) -> httpx.Response:
        nonlocal in_flight, max_in_flight
        body = json.loads(request.content)
        schema_name = body["response_format"]["json_schema"]["name"]
        if schema_name == "onionflash_news":
            user_payload = json.loads(body["messages"][1]["content"])
            with lock:
                in_flight += 1
                max_in_flight = max(max_in_flight, in_flight)
                counts["news"] += 1
                first_wave = counts["news"] <= 4
            try:
                if first_wave:
                    barrier.wait()
                reply = analysis(
                    title=user_payload["title"],
                    summary=user_payload["content"],
                    why_it_matters="",
                    evidence=[user_payload["content"]],
                )
            finally:
                with lock:
                    in_flight -= 1
        elif schema_name == "onionflash_select":
            with lock:
                counts["select"] += 1
            reply = {"winner": 1, "reason": "Best candidate."}
        elif schema_name == "onionflash_polish":
            with lock:
                counts["polish"] += 1
            draft = json.loads(body["messages"][1]["content"])["draft"]
            reply = {k: draft[k] for k in ("title", "summary", "why_it_matters")}
        else:
            with lock:
                counts["review"] += 1
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
    assert max_in_flight == cli.MAX_CONCURRENT_LLM_ITEMS == 4
    assert counts == {"news": 12, "select": 4, "polish": 4, "review": 16}
    assert report["model_calls"] == 36
    assert report["analyzed"] == 4
    assert len(store.stories()) == 4


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


def test_draft_cache_parity_stale_failure_guard_refresh_errors_and_harvester_safety(tmp_path, monkeypatch):
    """Cover CLI/gate cache parity, stale draft failure protection, refresh fault isolation, and harvester safety guards."""
    harvest_eval = _load_tool("harvest_eval")
    cfg = make_config(tmp_path)
    cfg["sources"] = []

    with Store(cfg["storage"]["database"]) as store:
        # 1) _classify_pending_row uses best_of=3 / quote_digest=True cache key matching Writer/Analyzer(3, True).
        shared_cluster = "release:tor:0.4.9.99"
        row_it = item(
            url="https://example.org/cache-parity",
            title="Tor 0.4.9.99 announcement",
            content="Tor 0.4.9.99 release candidate.",
            kind="gitlab_mr",
            upstream_state="merged",
        )
        store.ingest(row_it, DATE)
        with store.db:
            store.db.execute("UPDATE items SET cluster_key=? WHERE id=?", (shared_cluster, row_it["id"]))
        row = store.pending(10, DATE)[0]
        kind, payload = cli._classify_pending_row(cfg, store, row, review.policy_hash(cfg), execute_gates=False)
        assert kind == "draft"
        expected_k = cache_key(row, cfg["llm"], None, best_of=3, quote_digest=True)
        assert payload[3] == expected_k and len(payload) == 6

        # 2) Stale-context draft failure increments review_stale without charging attempts/rejections.
        dispatch_ctx = payload[5]
        report = {
            "analysis_failed": 0, "review_stale": 0, "analyzed": 0,
            "review_cache_hits": 0, "review_routed": 0,
        }
        prior_src = item(url="https://example.org/cache-parity-prior", title="Tor 0.4.9.99 blog", content="Prior body.")
        store.ingest(prior_src, DATE)
        with store.db:
            store.db.execute("UPDATE items SET cluster_key=? WHERE id=?", (shared_cluster, prior_src["id"]))
        seed_story(
            store,
            {**prior_src, "cluster_key": shared_cluster},
            analysis(title="Tor 0.4.9.99 blog", summary="Prior body.", evidence=["Prior body."]),
        )
        outcome, _ = cli._persist_draft_outcome(
            cfg, store, report, review.policy_hash(cfg), row, expected_k, None,
            None, 0, AnalysisError("Bad reply", retryable=False),
            observed=LATER, dispatch_context=dispatch_ctx, best_of=3, quote_digest=True,
        )
        assert outcome == "handled" and report["review_stale"] == 1 and report["analysis_failed"] == 0
        cur_row = store.db.execute("SELECT status, attempts, rejections FROM items WHERE id=?", (row["id"],)).fetchone()
        assert tuple(cur_row) == ("pending", 0, 0)

    # 3) **kwargs reviewer adapter triggers specialist merge; non-retryable refresh errors don't abort cli.run build; commit rejects stale prose/sources.
    with Store(tmp_path / "refresh_hardening.sqlite3") as store:
        s1_item = item(url="https://example.org/ref-hard-1", title="Refresh story 1", content="Initial body 1.")
        s1 = seed_story(store, s1_item, analysis(title="Refresh story 1", summary="Initial body 1.", evidence=["Initial body 1."]))
        _add_story_updates(store, s1["id"], 3)
        s2_item = item(url="https://example.org/ref-hard-2", title="Refresh story 2", content="Initial body 2.")
        s2 = seed_story(store, s2_item, analysis(title="Refresh story 2", summary="Initial body 2.", evidence=["Initial body 2."]))
        _add_story_updates(store, s2["id"], 3)

        seen_kwarg_specs = []

        class _KwargsReviewer:
            """Reviewer forwarding **kwargs to verify specialist activation in refresh."""

            def review(self, cand_pub, pkt, **kwargs):
                """Record forwarded specialist kwarg and approve."""
                seen_kwarg_specs.append(kwargs.get("specialist"))
                return verdict("approve")

        class _MixedRefresher:
            """Raise non-retryable AnalysisError on story 1 and succeed on story 2."""

            calls = 0

            def close(self):
                """No-op close for cli.run lifecycle cleanup."""

            def synthesize(self, story_payload, pkt):
                """Fail story 1 non-retryably and refresh story 2."""
                self.calls += 1
                if story_payload["id"] == s1["id"]:
                    raise AnalysisError("Non-retryable refresh failure", retryable=False)
                return {"title": "Refreshed story 2", "summary": "Verified across three updates.", "why_it_matters": ""}

        cands = store.refresh_candidates(limit=5)
        assert len(cands) == 2
        pkt = {"sources": [{"id": "S1", "url": "https://example.org/x", "kind": "rss", "authority": "official", "product": "tor", "published_at": DATE, "updated_at": DATE, "passages": [{"id": "S1:P1", "text": "Text."}]}], "missing_sources": [], "truncated": False}
        assert refresh.verify_refreshed_story(_KwargsReviewer(), {**s1, "title": "T"}, pkt, specialists=3)["verdict"] == "approve"
        assert set(seen_kwarg_specs) == set(review.SPECIALISTS)

        with monkeypatch.context() as mp:
            mp.setattr(refresh, "refresh_story", lambda st, ent, *_a, **_kw: (_ for _ in ()).throw(AnalysisError("Bad envelope", retryable=False)) if ent["story_id"] == s1["id"] else {"story_id": ent["story_id"], "status": "refreshed"})
            stats = refresh.refresh_due_stories(cfg, store, _KwargsReviewer(), LATER, refresher=_MixedRefresher())
            assert stats["held"] == 1 and stats["refreshed"] == 1

            # Verify cli.run() still runs build() even when refresh_story raises non-retryable AnalysisError.
            built = []
            cfg_cli = copy.deepcopy(cfg)
            cfg_cli["llm"].update(base_url="https://llm.example/v1", api_key_env="KEY")
            monkeypatch.setenv("KEY", "synthetic-fixture-value")
            mp.setattr(cli, "Analyzer", Analyzer)
            mp.setattr(cli, "Reviewer", ApprovingReviewer)
            mp.setattr(cli, "build", lambda *_a: built.append(True) or {"published_stories": 2})
            mp.setattr(refresh, "StoryRefresher", lambda *_a, **_kw: _MixedRefresher())
            cli_report = cli.run(cfg_cli, store)
            assert built == [True] and cli_report["published_stories"] == 2

        # commit_story_refresh rejects edited prose and source additions via add_citation.
        before_s1 = json.loads(store.db.execute("SELECT payload FROM stories WHERE id=?", (s1["id"],)).fetchone()[0])
        h_s1 = story_refresh_hash(before_s1)
        s1_cluster = store.db.execute("SELECT cluster_key FROM stories WHERE id=?", (s1["id"],)).fetchone()[0]
        cite_it = item(url="https://example.org/cite-extra", title="Cite extra", content="Extra citation.")
        store.ingest(cite_it, LATER)
        with store.db:
            store.db.execute("UPDATE items SET cluster_key=? WHERE id=?", (s1_cluster, cite_it["id"]))
        cite_row = store.db.execute("SELECT * FROM items WHERE id=?", (cite_it["id"],)).fetchone()
        store.add_citation(dict(cite_row), s1["id"], LATER)
        with pytest.raises(candidate_mod.StaleCandidate):
            store.commit_story_refresh(
                s1["id"], {"title": "New", "summary": "New summary.", "why_it_matters": ""}, 3, h_s1, LATER,
                base_prose={k: before_s1.get(k, "") for k in ("title", "summary", "why_it_matters")},
            )
        before_s2 = json.loads(store.db.execute("SELECT payload FROM stories WHERE id=?", (s2["id"],)).fetchone()[0])
        h_s2 = story_refresh_hash(before_s2)
        with store.db:
            updated_s2 = {**before_s2, "title": "Manually edited title"}
            store.db.execute("UPDATE stories SET payload=? WHERE id=?", (json.dumps(updated_s2), s2["id"]))
        with pytest.raises(candidate_mod.StaleCandidate):
            store.commit_story_refresh(
                s2["id"], {"title": "New", "summary": "New summary.", "why_it_matters": ""}, 3, h_s2, LATER,
                base_prose={k: before_s2.get(k, "") for k in ("title", "summary", "why_it_matters")},
            )

    # 4) harvest_eval surrogates, row URL secret redaction, packet isolation, comment URL preservation, held update jobs, and --output==--db guard.
    assert harvest_eval.sanitize_text("Bad\ud800text") == "Bad\ufffdtext"
    json.dumps(harvest_eval.sanitize_text("Bad\ud800text"), ensure_ascii=False).encode("utf-8")

    # 3b) Refresh isolates malformed source packets, forwards specialist subset count, and enforces final_holds on refresh prose.
    with Store(tmp_path / "refresh_guards.sqlite3") as store:
        rg_item = item(
            url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/7701",
            title="Issue under investigation",
            content="Initial investigation details without completion.",
            kind="gitlab_issue",
        )
        rg_story = seed_story(
            store, rg_item,
            analysis(title="Issue under investigation", summary="Initial investigation details without completion.", evidence=["Initial investigation details without completion."]),
        )
        _add_story_updates(store, rg_story["id"], 3)
        cands_rg = store.refresh_candidates(limit=5)
        assert len(cands_rg) == 1

        spec2_pkt = {
            "sources": [{"id": "S1", "url": rg_item["url"], "title": rg_item["title"], "kind": "gitlab_issue", "authority": "development", "product": "tor", "published_at": DATE, "updated_at": DATE, "passages": [{"id": "S1:P1", "text": rg_item["content"]}]}],
            "missing_sources": [], "truncated": False,
        }
        seen_specs2 = []

        class _Spec2Reviewer:
            """Reviewer supporting specialist keyword verification."""

            def review(self, cand_pub, pkt, *, specialist=None, **_kw):
                """Record specialist name and approve."""
                seen_specs2.append(specialist)
                return verdict("approve")

        assert refresh.verify_refreshed_story(_Spec2Reviewer(), rg_story, spec2_pkt, specialists=2)["verdict"] == "approve"
        assert len(seen_specs2) == 2

        class _OverclaimRefresher:
            """Synthesize an unsupported fixed claim on an unmerged issue."""

            calls = 0

            def close(self):
                """No-op close."""

            def synthesize(self, story_payload, pkt):
                """Return claim failing final_holds completed_action."""
                self.calls += 1
                return {"title": "Defect fixed in branch", "summary": "The defect was fixed.", "why_it_matters": ""}

        held_out = refresh.refresh_due_stories(cfg, store, _Spec2Reviewer(), LATER, refresher=_OverclaimRefresher())
        assert held_out["held"] == 1 and held_out["refreshed"] == 0

        broken_item = item(url="https://example.org/broken-refresh", title="Broken refresh source", content="Text.")
        broken_story = seed_story(store, broken_item, analysis(title="Broken refresh source", summary="Text.", evidence=["Text."]))
        _add_story_updates(store, broken_story["id"], 3)
        with monkeypatch.context() as mp:
            mp.setattr(refresh, "build_story_refresh_packet", lambda *_a, **_kw: (_ for _ in ()).throw(AttributeError("None source")))
            bad_pkt_res = refresh.refresh_due_stories(cfg, store, _Spec2Reviewer(), LATER, refresher=_OverclaimRefresher())
            assert bad_pkt_res["held"] >= 1

    db_h = tmp_path / "harvest_safety.sqlite3"
    with Store(db_h) as store:
        sec_it = item(
            url="https://example.org/item?token=secret_value_12345",
            title="Held and rejected item",
            content="Body content.",
            public_comments=[make_note(123, "Note comment body with detail.", author="alice", created_at=DATE, url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/1")],
        )
        store.ingest(sec_it, DATE)
        row_h = store.pending(10, DATE)[0]
        from onionflash import rejection
        for _ in range(3):
            store.defer(sec_it["id"], "Bad", cfg["llm"], DATE, terminal=True)
        rejection.retry_item(store, sec_it["id"], row_h["content_hash"], "Retry", LATER)
        with store.db:
            store.db.execute(
                "INSERT INTO review_jobs(item_id,writer_key,policy_hash,stage,draft_json,envelope_json,record_json,prepared_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    sec_it["id"], "k" * 64, review.policy_hash(cfg), "held",
                    json.dumps(analysis()),
                    json.dumps({"packet": {"sources": [{"url": "https://example.org/held-snap", "title": "Held snapshot", "kind": "rss", "authority": "official", "product": "tor", "published_at": DATE, "updated_at": DATE, "passages": ["Held snapshot body."]}], "missing_sources": [], "truncated": False}}),
                    json.dumps({"hold": ["review", "model_hold"], "candidate": analysis()}),
                    DATE, DATE,
                ),
            )
        upd_prior = seed_story(store, item(url="https://example.org/upd-prior", title="Prior Update Base", content="Base story body."), analysis(title="Prior Update Base", summary="Base summary.", evidence=["Base story body."]))
        upd_it = item(url="https://example.org/upd-follow", title="Follow-up note", content="Follow-up event body.")
        store.ingest(upd_it, LATER)
        with store.db:
            store.db.execute("UPDATE items SET story_id=? WHERE id=?", (upd_prior["id"], upd_it["id"]))
            upd_cand = {
                **upd_prior,
                "updates": [{"at": LATER, "text": "Follow-up event update.", "sources": [{"url": "https://example.org/upd-follow", "title": "Follow-up"}]}],
            }
            upd_pkt = {"sources": [{"url": "https://example.org/upd-follow", "title": "Follow-up", "kind": "rss", "authority": "official", "product": "tor", "published_at": LATER, "updated_at": LATER, "passages": ["Follow-up event body."]}], "missing_sources": [], "truncated": False}
            upd_cov = {"prior_story": upd_prior, "recent": [], "truncated": False}
            store.db.execute(
                "INSERT INTO review_jobs(item_id,writer_key,policy_hash,stage,draft_json,envelope_json,record_json,prepared_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    upd_it["id"], "u" * 64, review.policy_hash(cfg), "held",
                    json.dumps(update_analysis()),
                    json.dumps({"mode": "update", "story_id": upd_prior["id"], "packet": upd_pkt, "coverage": upd_cov, "candidate": upd_cand}),
                    json.dumps({"hold": ["review", "model_hold"], "candidate": upd_cand}),
                    LATER, LATER,
                ),
            )
    ds = harvest_eval.harvest_database(db_h, include_updates=True)
    held_pkt = next(c["packet"] for c in ds["cases"] if c["id"] == f"held:{sec_it['id']}")
    rej_pkt = next(c["packet"] for c in ds["cases"] if c["id"] == f"rej:{sec_it['id']}")
    assert held_pkt != rej_pkt
    assert ds["packets"][held_pkt] != ds["packets"][rej_pkt]
    assert "#note_123" in ds["packets"][rej_pkt]["sources"][0]["passages"][0]["url"]
    upd_case = next(c for c in ds["cases"] if c["id"] == f"held:{upd_it['id']}")
    assert upd_case["scope"] == "latest_update" and upd_case["coverage_set"] in ds["coverage_sets"]
    evaluate_review = _load_tool("evaluate_review")
    evaluate_review._validate_cases(evaluate_review.expand(ds))
    assert "secret_value_12345" not in json.dumps(ds, ensure_ascii=False)
    with pytest.raises(SystemExit):
        harvest_eval.main(["--db", str(db_h), "--output", str(db_h)])
