"""Tests for living story refresh observability, `decision_log` payloads, and atomicity."""

from __future__ import annotations

import json

import pytest

from helpers import DATE, LATER, ApprovingReviewer, analysis, finish_reviewed, item, pending, seed_story, update_analysis, verdict
from onionflash import decisions, editorial, refresh
from onionflash.analyze import AnalysisError, cache_key
from onionflash.config import DEFAULTS
from onionflash.store import Store, story_refresh_hash
from onionflash.util import after


def _seed_refreshable_story(store: Store, *, slug: str = "obs-story", updates: int = 3) -> dict:
    """Create a published story with `updates` real item-backed updates eligible for refresh."""
    base_item = item(
        url=f"https://example.org/{slug}/base",
        title=f"Base story {slug}",
        content=f"Base verified content for {slug}.",
    )
    seeded = seed_story(
        store,
        base_item,
        analysis(
            title=f"Base story {slug}",
            summary=f"Base verified content for {slug}.",
            why_it_matters="",
            evidence=[f"Base verified content for {slug}."],
        ),
    )
    for idx in range(1, updates + 1):
        ts = after(idx * 3600, DATE)
        upd_item = item(
            url=f"https://example.org/{slug}/upd/{idx}",
            title=f"Follow-up milestone {idx}",
            content=f"Milestone {idx} confirms investigation details for {slug}.",
            published_at=ts,
            updated_at=ts,
        )
        row = pending(store, upd_item, at=ts, ready=ts, target=seeded["id"])
        upd_draft = update_analysis(
            update=f"Milestone {idx} added verified investigation progress.",
            evidence=[upd_item["content"]],
        )
        finish_reviewed(store, row, upd_draft, cache_key(row, DEFAULTS["llm"]), ts)
    return store.refresh_candidates(limit=5)[0]


def _refresh_logs(store: Store, story_id: str | None = None) -> list[dict]:
    """Return `decision_log` rows ordered by insertion id, optionally filtered to `story_id`."""
    rows = [
        r
        for r in decisions.list_entries(store.db, "2000-01-01T00:00:00Z", limit=200)["decisions"]
        if str(r["subject"]).startswith("refresh:")
    ]
    rows.reverse()
    if story_id is not None:
        return [r for r in rows if r["story_id"] == story_id]
    return rows


class _ValidRefresher:
    """Deterministic refresher producing grounded, normalized summary prose."""

    def synthesize(self, story_payload, packet):
        """Return valid refreshed prose fields."""
        return {
            "title": f"Refreshed: {story_payload['title']}",
            "summary": "Consolidated updates summarize ongoing verified progress across milestones.",
            "why_it_matters": "",
        }


def test_refresh_observability_logs_all_outcome_codes_and_details(tmp_path, monkeypatch):
    """Record every terminal refresh outcome and structured detail in `decision_log`."""
    db_path = tmp_path / "refresh_obs.sqlite3"
    with Store(db_path) as store:
        # 1) refreshed.summary
        c_ok = _seed_refreshable_story(store, slug="ok-story")
        out_ok = refresh.refresh_story(store, c_ok, _ValidRefresher(), ApprovingReviewer(), LATER)
        assert out_ok["status"] == "refreshed"
        logs_ok = _refresh_logs(store, c_ok["story_id"])
        assert len(logs_ok) == 1
        entry_ok = logs_ok[0]
        assert entry_ok["code"] == "refreshed.summary"
        assert entry_ok["subject"] == f"refresh:{c_ok['story_id']}:{out_ok['update_count']}:{out_ok['refreshed_hash'][:12]}"
        assert entry_ok["detail"] == {
            "title": f"Refreshed: Base story ok-story",
            "update_count": 3,
            "reason": "refreshed",
        }

        # 2) skipped.refresh.ineligible
        fake_nh = {
            "story_id": "a" * 24,
            "payload": {
                "id": "a" * 24,
                "title": "Consensus health incident",
                "summary": "Network outage detected.",
                "why_it_matters": "",
                "category": "network",
                "confidence": "confirmed",
                "state": "ongoing",
                "origin": "network-health",
                "published_at": DATE,
                "updated_at": DATE,
                "products": ["network"],
                "tags": [],
                "sources": [],
                "updates": [{"at": DATE, "text": "x", "sources": []}] * 3,
            },
            "update_count": 3,
            "refreshed_hash": "b" * 64,
        }
        out_inel = refresh.refresh_story(store, fake_nh, _ValidRefresher(), ApprovingReviewer(), LATER)
        assert out_inel == {"story_id": "a" * 24, "status": "skipped", "reason": "ineligible_story"}
        logs_inel = _refresh_logs(store, "a" * 24)
        assert logs_inel[0]["code"] == "skipped.refresh.ineligible"
        assert logs_inel[0]["detail"]["reason"] == "ineligible_story"
        assert logs_inel[0]["detail"]["update_count"] == 3

        # 3) skipped.refresh.missing_sources
        c_miss = _seed_refreshable_story(store, slug="miss-story")
        with store.db:
            store.db.execute("DELETE FROM items")
            store.db.execute("DELETE FROM analyses")
        out_miss = refresh.refresh_story(store, c_miss, _ValidRefresher(), ApprovingReviewer(), LATER)
        assert out_miss["status"] == "skipped" and out_miss["reason"] == "missing_sources"
        logs_miss = _refresh_logs(store, c_miss["story_id"])
        assert logs_miss[0]["code"] == "skipped.refresh.missing_sources"
        assert logs_miss[0]["detail"]["reason"] == "missing_sources"

        # 4) held.refresh.invalid_packet
        c_pkt = _seed_refreshable_story(store, slug="pkt-err")
        with monkeypatch.context() as mp:
            mp.setattr(refresh, "build_story_refresh_packet", lambda *_a, **_kw: (_ for _ in ()).throw(ValueError("bad pkt")))
            out_pkt = refresh.refresh_story(store, c_pkt, _ValidRefresher(), ApprovingReviewer(), LATER)
        assert out_pkt == {"story_id": c_pkt["story_id"], "status": "held", "reason": "invalid_packet"}
        logs_pkt = _refresh_logs(store, c_pkt["story_id"])
        assert logs_pkt[0]["code"] == "held.refresh.invalid_packet"
        assert logs_pkt[0]["detail"]["hold_code"] == "invalid_packet"
        assert logs_pkt[0]["detail"]["reason"] == "invalid_packet"

        # 5) held.refresh.invalid_output (both AnalysisError and ValueError during render)
        c_out1 = _seed_refreshable_story(store, slug="bad-out1")

        class _ErrRefresher:
            """Raise non-retryable refresh output error."""

            def synthesize(self, *_a):
                """Raise AnalysisError for invalid output."""
                raise AnalysisError("Incomplete summary.", code="refresh.incomplete_sentence", retryable=False)

        out_bad1 = refresh.refresh_story(store, c_out1, _ErrRefresher(), ApprovingReviewer(), LATER)
        assert out_bad1 == {"story_id": c_out1["story_id"], "status": "held", "reason": "refresh.incomplete_sentence"}
        logs_bad1 = _refresh_logs(store, c_out1["story_id"])
        assert logs_bad1[0]["code"] == "held.refresh.invalid_output"
        assert logs_bad1[0]["detail"]["hold_code"] == "refresh.incomplete_sentence"

        c_out2 = _seed_refreshable_story(store, slug="bad-out2")
        with monkeypatch.context() as mp:
            real_prepare = refresh.render.prepare_story
            calls = {"n": 0}

            def _fail_second_prepare(*args, **kwargs):
                calls["n"] += 1
                if calls["n"] >= 2:
                    raise ValueError("Malformed rendered story")
                return real_prepare(*args, **kwargs)

            mp.setattr(refresh.render, "prepare_story", _fail_second_prepare)
            out_bad2 = refresh.refresh_story(store, c_out2, _ValidRefresher(), ApprovingReviewer(), LATER)
        assert out_bad2 == {"story_id": c_out2["story_id"], "status": "held", "reason": "invalid_candidate"}
        logs_bad2 = _refresh_logs(store, c_out2["story_id"])
        assert logs_bad2[0]["code"] == "held.refresh.invalid_output"
        assert logs_bad2[0]["detail"]["hold_code"] == "invalid_candidate"

        # 6) skipped.refresh.review_skip
        c_rskip = _seed_refreshable_story(store, slug="rev-skip")

        class _SkipReviewer:
            """Return skip(news_value) on refresh verification."""

            def review(self, *_a, **_kw):
                """Return skip verdict."""
                return verdict("skip", criterion="news_value", reason="Insufficient significance.")

        out_rskip = refresh.refresh_story(store, c_rskip, _ValidRefresher(), _SkipReviewer(), LATER)
        assert out_rskip == {"story_id": c_rskip["story_id"], "status": "skipped", "reason": "review_skip"}
        logs_rskip = _refresh_logs(store, c_rskip["story_id"])
        assert logs_rskip[0]["code"] == "skipped.refresh.review_skip"
        assert logs_rskip[0]["detail"]["verdict"] == "skip"
        assert logs_rskip[0]["detail"]["criteria"] == {"news_value": "fail: Insufficient significance."}

        # 7) held.refresh.review_rejected (both verdict reject with criteria and AnalysisError)
        c_rhold = _seed_refreshable_story(store, slug="rev-hold")

        class _RejectReviewer:
            """Return hold verdict failing source_support."""

            def review(self, *_a, **_kw):
                """Return hold verdict."""
                return verdict("hold", criterion="source_support", reason="Claim exceeds packet text.")

        out_rhold = refresh.refresh_story(store, c_rhold, _ValidRefresher(), _RejectReviewer(), LATER)
        assert out_rhold == {"story_id": c_rhold["story_id"], "status": "held", "reason": "review_hold"}
        logs_rhold = _refresh_logs(store, c_rhold["story_id"])
        assert logs_rhold[0]["code"] == "held.refresh.review_rejected"
        assert logs_rhold[0]["detail"]["verdict"] == "hold"
        assert logs_rhold[0]["detail"]["criteria"] == {"source_support": "fail: Claim exceeds packet text."}

        c_rerr = _seed_refreshable_story(store, slug="rev-err")

        class _ErrReviewer:
            """Raise non-retryable review failure."""

            def review(self, *_a, **_kw):
                """Raise non-retryable review AnalysisError."""
                raise AnalysisError("Invalid JSON from verifier.", code="review.invalid_json", retryable=False)

        out_rerr = refresh.refresh_story(store, c_rerr, _ValidRefresher(), _ErrReviewer(), LATER)
        assert out_rerr == {"story_id": c_rerr["story_id"], "status": "held", "reason": "review.invalid_json"}
        logs_rerr = _refresh_logs(store, c_rerr["story_id"])
        assert logs_rerr[0]["code"] == "held.refresh.review_rejected"
        assert logs_rerr[0]["detail"]["hold_code"] == "review.invalid_json"

        # 8) held.refresh.final_check
        c_fc = _seed_refreshable_story(store, slug="final-chk")

        class _ShoutingRefresher:
            """Return unnormalized shouting caps caught by `final_holds`."""

            def synthesize(self, *_a):
                """Return text failing shouting_caps final hold."""
                return {
                    "title": "CRITICAL RELAY WARNING UPDATE",
                    "summary": "Consolidated updates describe CRITICAL RELAY behavior.",
                    "why_it_matters": "",
                }

        out_fc = refresh.refresh_story(store, c_fc, _ShoutingRefresher(), ApprovingReviewer(), LATER)
        assert out_fc == {"story_id": c_fc["story_id"], "status": "held", "reason": "final_check_shouting_caps"}
        logs_fc = _refresh_logs(store, c_fc["story_id"])
        assert logs_fc[0]["code"] == "held.refresh.final_check"
        assert logs_fc[0]["detail"]["hold_code"] == "shouting_caps"
        assert logs_fc[0]["detail"]["reason"] == "final_check_shouting_caps"

        # 9) skipped.refresh.stale_or_locked (does NOT write story_refreshes)
        c_stale = _seed_refreshable_story(store, slug="stale-lock")
        editorial.correct(
            store.db,
            c_stale["story_id"],
            {"title": "Locked title"},
            reason="Lock before commit",
            expect_hash=editorial.show(store.db, c_stale["story_id"])["hash"],
            observed=LATER,
        )
        out_stale = refresh.refresh_story(store, c_stale, _ValidRefresher(), ApprovingReviewer(), LATER)
        assert out_stale == {"story_id": c_stale["story_id"], "status": "skipped", "reason": "stale_or_locked"}
        assert store.db.execute("SELECT 1 FROM story_refreshes WHERE story_id=?", (c_stale["story_id"],)).fetchone() is None
        logs_stale = _refresh_logs(store, c_stale["story_id"])
        assert logs_stale[0]["code"] == "skipped.refresh.stale_or_locked"
        assert logs_stale[0]["detail"]["reason"] == "stale_or_locked"


def test_record_refresh_status_compat_and_transaction_atomicity(tmp_path, monkeypatch):
    """Preserve legacy `record_refresh_status` calls and roll back `story_refreshes` if decision logging fails."""
    with Store(tmp_path / "refresh_atom.sqlite3") as store:
        cand = _seed_refreshable_story(store, slug="atom-story")
        sid = cand["story_id"]
        h = cand["refreshed_hash"]

        # Legacy keyword-only call without code/reason/extra still works and writes story_refreshes.
        store.record_refresh_status(
            sid,
            update_count=3,
            refreshed_hash=h,
            status="held",
            observed=LATER,
        )
        assert store.db.execute("SELECT status FROM story_refreshes WHERE story_id=?", (sid,)).fetchone()[0] == "held"
        assert _refresh_logs(store, sid) == []

        # Call with code & extra (without explicit title) looks up story title and filters reserved kwargs.
        store.record_refresh_status(
            sid,
            update_count=3,
            refreshed_hash=h,
            status="skipped",
            observed=LATER,
            code="skipped.refresh.missing_sources",
            reason="missing_cited_body",
            extra={"subject": "tampered", "story_id": "tampered", "once": True},
        )
        logs = _refresh_logs(store, sid)
        assert len(logs) == 1
        assert logs[0]["code"] == "skipped.refresh.missing_sources"
        assert logs[0]["story_id"] == sid
        assert logs[0]["detail"]["title"] == "Base story atom-story"
        assert logs[0]["detail"]["reason"] == "missing_cited_body"

        # Atomicity: if record_subject fails inside record_refresh_status or commit_story_refresh, DB changes roll back.
        with store.db:
            store.db.execute("DELETE FROM story_refreshes WHERE story_id=?", (sid,))
        with monkeypatch.context() as mp:
            mp.setattr(decisions, "record_subject", lambda *_a, **_kw: (_ for _ in ()).throw(RuntimeError("boom")))
            with pytest.raises(RuntimeError, match="boom"):
                store.record_refresh_status(
                    sid,
                    update_count=3,
                    refreshed_hash=h,
                    status="held",
                    observed=LATER,
                    code="held.refresh.invalid_packet",
                    reason="invalid_packet",
                )
            assert store.db.execute("SELECT 1 FROM story_refreshes WHERE story_id=?", (sid,)).fetchone() is None

            payload_before = store.db.execute("SELECT payload FROM stories WHERE id=?", (sid,)).fetchone()[0]
            with pytest.raises(RuntimeError, match="boom"):
                store.commit_story_refresh(
                    sid,
                    {
                        "title": "Should rollback title",
                        "summary": "Consolidated rollback check summary sentence.",
                        "why_it_matters": "",
                    },
                    3,
                    story_refresh_hash(json.loads(payload_before)),
                    LATER,
                    base_prose={k: json.loads(payload_before).get(k, "") for k in ("title", "summary", "why_it_matters")},
                )
            assert store.db.execute("SELECT 1 FROM story_refreshes WHERE story_id=?", (sid,)).fetchone() is None
            assert store.db.execute("SELECT payload FROM stories WHERE id=?", (sid,)).fetchone()[0] == payload_before
