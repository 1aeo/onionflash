"""Regression tests for adversarial security, correctness, concurrency, and state-machine fixes."""

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import json
import sqlite3
import zlib
from datetime import timedelta
from pathlib import Path

import httpx
import pytest

from approval_helpers import finish_reviewed
from onionflash import (
    analyze,
    candidate,
    collect,
    comments,
    config as config_mod,
    decisions,
    doctor,
    editorial,
    publication,
    rejection,
    render,
    review,
    review_gate,
    source_packet,
)
from onionflash.analyze import AnalysisError
from onionflash.store import Store, retained_analysis_keys
from onionflash.transport import AddressPolicy, DeadlineReached, FetchError, HttpClient, Response
from onionflash.util import canonical_url, digest, format_utc, gitlab_refs, item_cluster, parse_utc
from test_core import DATE, analysis, config as make_core_config, item as make_item
from test_doctor import FEED_URL, FakeLinker, LIST_URL, bastet_incident_items, make_config as make_doc_config, report_item, seed_host
from test_review import verdict as make_verdict

LATER = "2026-11-08T13:00:00Z"


def _seed_story(store: Store, *, url: str = "https://example.org/post-1", title: str = "Tor 0.4.9.5 released",
                summary: str = "Maintainers published a new Tor release.", category: str = "release",
                confidence: str = "confirmed", state: str = "released", authority: str = "official",
                kind: str = "feed", published_at: str = DATE, products: list[str] | None = None) -> tuple[dict, str]:
    inc = make_item(
        url=url,
        kind=kind,
        title=title,
        content=summary + " Supporting upstream release details for operators.",
        published_at=published_at,
        updated_at=published_at,
        authority=authority,
        product=(products or ["tor"])[0],
    )
    store.ingest(inc, published_at)
    row = [r for r in store.pending(10, published_at) if r["url"] == canonical_url(url)][0]
    draft = analysis(
        title=title,
        summary=summary,
        why_it_matters="Operators track supported Tor releases.",
        category=category,
        confidence=confidence,
        state=state,
        products=products or ["tor"],
        tags=[category],
        evidence=[summary],
    )
    finish_reviewed(store, row, draft, "seed-" + row["id"], published_at)
    story_id = store.db.execute("SELECT story_id FROM items WHERE id=?", (row["id"],)).fetchone()[0]
    return row, story_id


def test_null_tombstone_story_alias_removes_story_and_handles_chained_merges(tmp_path):
    cfg = make_core_config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        _, s1 = _seed_story(store, url="https://example.org/s1", title="First incident report", summary="First incident details.")
        _, s2 = _seed_story(store, url="https://example.org/s2", title="Second incident report", summary="Second incident details.")
        publication.build(cfg, store)
        out = Path(cfg["storage"]["output_dir"])
        assert (out / "news" / s1 / "index.html").exists()

        editorial.merge(
            store.db, s1, s2,
            reason="Consolidate duplicate reports.",
            expect_hash=editorial.show(store.db, s1)["hash"],
            observed=LATER,
        )
        # Hard-delete s2 with a NULL survivor tombstone in story_aliases.
        s2_row = store.db.execute("SELECT cluster_key, payload FROM stories WHERE id=?", (s2,)).fetchone()
        with store.db:
            store.db.execute(
                "INSERT INTO story_aliases(story_id,cluster_key,survivor_id,reason,created_at,story_json) VALUES(?,?,NULL,?,?,?)",
                (s2, s2_row["cluster_key"], "Hard-deleted story.", LATER, s2_row["payload"]),
            )
            store.db.execute("DELETE FROM stories WHERE id=?", (s2,))

        res = publication.build(cfg, store)
        assert res["stories_skipped"] == 0
        assert res["published_stories"] == 0
        assert store.db.execute("SELECT COUNT(*) FROM public_story_topics").fetchone()[0] == 0
        for rel in ("index.html", "topics/release/index.html", "feed.xml", "feed.json"):
            rendered = (out / rel).read_text(encoding="utf-8")
            assert s1 not in rendered and s2 not in rendered

        # Retire s1/s2 artifacts as in a hard-delete (leaving s1's alias catalog row with template_hash='')
        # while a live story s3 and legacy app.js exist: build reaches migration readiness, while an
        # unmigrated archived alias artifact still blocks retirement.
        _, s3 = _seed_story(store, url="https://example.org/s3", title="Third active notice", summary="Active notice details.")
        for gone in (s1, s2):
            for suffix in ("index.html", "story.json"):
                (out / "news" / gone / suffix).unlink(missing_ok=True)
            with store.db:
                store.db.execute("DELETE FROM public_artifacts WHERE path LIKE ?", (f"news/{gone}/%",))
        script_bytes = b"legacy browser script"
        (out / "app.js").write_bytes(script_bytes)
        with store.db:
            store.db.execute(
                "INSERT INTO public_artifacts(path,sha256,size,content_type,updated_at) VALUES('app.js',?,?, 'text/javascript', ?)",
                (hashlib.sha256(script_bytes).hexdigest(), len(script_bytes), DATE),
            )
            store.db.execute("DELETE FROM metadata WHERE key='publication_no_browser_js_ready'")
            # Seed an archived alias artifact with stale template_hash='' -> defers script retirement without raising:
            store.db.execute(
                "INSERT INTO public_artifacts(path,sha256,size,content_type,updated_at) VALUES(?,?,10,'text/html',?)",
                (f"news/{s1}/index.html", "0" * 64, DATE),
            )
        deferred_res = publication.build(cfg, store)
        assert deferred_res["no_browser_js_ready"] is False
        assert (out / "app.js").exists()

        # Whereas an uncatalogued orphan artifact still raises ValueError:
        with store.db:
            store.db.execute("DELETE FROM public_artifacts WHERE path=?", (f"news/{s1}/index.html",))
            store.db.execute(
                "INSERT INTO public_artifacts(path,sha256,size,content_type,updated_at) VALUES('news/orphan999999/index.html',?,10,'text/html',?)",
                ("0" * 64, DATE),
            )
        with pytest.raises(ValueError, match="Unverified article artifact"):
            publication.build(cfg, store)
        assert (out / "app.js").exists()

        # Once the retired alias has no rendered/archived artifact and no orphan exists, its catalog row (template_hash='') does not block readiness:
        with store.db:
            store.db.execute("DELETE FROM public_artifacts WHERE path='news/orphan999999/index.html'")
        ready_res = publication.build(cfg, store)
        assert ready_res["no_browser_js_ready"] is True
        assert not (out / "app.js").exists()


def test_prebuild_retract_restores_cleanly_and_deleted_story_keeps_pending_retraction(tmp_path):
    cfg = make_core_config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        _, sid = _seed_story(store, url="https://example.org/prebuild", title="Drafted notice", summary="Initial notice text.")
        # Retract BEFORE first publication.build() -> restore(revision=0) must recover cleanly without deadlocking.
        shown = editorial.show(store.db, sid)
        editorial.retract(store.db, sid, reason="Retracted before build.", expect_hash=shown["hash"], observed=LATER)
        hist = editorial.history(store.db, sid)["revisions"][0]
        assert "updates" not in (hist["after_public"] or {})
        assert "alert_notes" not in (hist["after_public"] or {})
        restored = editorial.restore(
            store.db, sid, 0,
            reason="Restore pre-build story.",
            expect_hash=editorial.show(store.db, sid)["hash"],
            observed="2026-11-10T13:30:00Z",
        )
        assert restored["retracted"] is False
        publication.build(cfg, store)

        # Now retract an already-published story and delete its stories row before build():
        # publication.build() must still render the retraction tombstone instead of serving stale public_catalog prose!
        editorial.retract(
            store.db, sid,
            reason="Withdrawn after verification.",
            expect_hash=editorial.show(store.db, sid)["hash"],
            observed="2026-11-10T14:00:00Z",
        )
        with store.db:
            store.db.execute("DELETE FROM stories WHERE id=?", (sid,))
        publication.build(cfg, store)
        html = (Path(cfg["storage"]["output_dir"]) / "news" / sid / "index.html").read_text(encoding="utf-8")
        assert "Retracted story" in html
        assert "Initial notice text." not in html


def test_editorial_triggers_damaged_story_fallback_category_tags_and_empty_output_dir(tmp_path):
    cfg = make_core_config(tmp_path)
    out = Path(cfg["storage"]["output_dir"])
    out.mkdir(parents=True, exist_ok=True)  # pre-created empty directory before first build

    with Store(cfg["storage"]["database"]) as store:
        # Permanence triggers exist immediately on Store init (before publication.build()).
        triggers = {
            r[0] for r in store.db.execute("SELECT name FROM sqlite_master WHERE type='trigger'")
        }
        assert {
            "editorial_revisions_append_only",
            "editorial_revisions_permanent",
            "editorial_revisions_unchanged",
            "editorial_controls_permanent",
        } <= triggers

        _, sid = _seed_story(
            store,
            url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/777",
            title="Relay memory spike",
            summary="Operators observed higher relay memory use.",
            category="network",
        )
        # Pre-created empty output_dir still triggers full build of articles and feeds.
        rep = publication.build(cfg, store)
        assert rep["published_stories"] == 1
        assert (out / "news" / sid / "index.html").exists()

        # Correcting category without specifying tags strips the old category tag.
        res = editorial.correct(
            store.db, sid,
            {"category": "security"},
            reason="Reclassify as security.",
            expect_hash=editorial.show(store.db, sid)["hash"],
            observed=LATER,
        )
        assert res["locked"] is True
        shown = editorial.show(store.db, sid)
        assert shown["story"]["category"] == "security"
        assert "network" not in shown["story"]["tags"]
        assert "security" in shown["story"]["tags"]

        # Corrupt stories.payload into a SQLite BLOB: editorial.show and publication.build fall back to public_catalog.
        publication.build(cfg, store)
        with store.db:
            store.db.execute("UPDATE stories SET payload=? WHERE id=?", (b"\xff\xfeinvalid", sid))
        fallback_view = editorial.show(store.db, sid)
        assert fallback_view["using_last_published_snapshot"] is True
        build_after = publication.build(cfg, store)
        assert build_after["published_stories"] == 1


def test_merge_host_story_transfers_doctor_network_pins_updates_and_citations(tmp_path):
    _, cfg = make_doc_config(tmp_path, publish=True)
    with Store(cfg["storage"]["database"]) as store:
        host_dup = seed_host(
            store,
            url="https://example.org/bastet-dup",
            title="Directory authority bastet maintenance outage",
            summary="Operators reported directory authority bastet is offline for maintenance.",
        )
        host_surv = seed_host(
            store,
            url="https://example.org/bastet-main",
            title="Primary report on directory authority bastet outage",
            summary="Primary tracking story for the directory authority bastet outage.",
            published_at="2024-01-14T13:00:00Z",
        )
        doctor.ingest(store.db, cfg["sources"][0], bastet_incident_items(close=False), "2024-01-17T12:00:00Z")
        doctor.evaluate(cfg, store, cfg["sources"][0], FakeLinker(True), "2024-01-17T12:00:00Z")
        publication.build(cfg, store)

        # Seed an unrelated report in network_reports and inject an update on host_dup citing it:
        # editorial.merge must transfer ONLY host_dup's genuine DocTor update, not the unrelated one!
        unrelated_rep = report_item("UNRELATED_REP_01", "2024-01-10T00:05:00Z", ["NOTICE: unrelated line"])
        doctor.ingest(store.db, cfg["sources"][0], [unrelated_rep], "2024-01-17T12:30:00Z")
        dup_payload = json.loads(store.db.execute("SELECT payload FROM stories WHERE id=?", (host_dup,)).fetchone()[0])
        dup_payload["updates"] = [
            *list(dup_payload.get("updates") or []),
            {
                "at": "2024-01-17T12:30:00Z",
                "text": "Unrelated report note that was not produced by host_dup's pinned incident.",
                "sources": [{"url": unrelated_rep["url"], "title": "Unrelated report"}],
            },
        ]
        with store.db:
            store.db.execute("UPDATE stories SET payload=? WHERE id=?", (json.dumps(dup_payload), host_dup))

        # Merge host_dup into host_surv: network pin + DocTor update + alert_notes transfer, and next evaluate writes 0 duplicate stories!
        editorial.merge(
            store.db, host_dup, host_surv,
            reason="Merge duplicate host story.",
            expect_hash=editorial.show(store.db, host_dup)["hash"],
            observed="2024-01-17T13:00:00Z",
        )
        guard_linker = FakeLinker(AssertionError("Unexpected linker call"))
        res_next = doctor.evaluate(cfg, store, cfg["sources"][0], guard_linker, "2024-01-17T13:05:00Z")
        assert guard_linker.calls == 0
        assert res_next["stories_written"] == 0 and res_next["updates_written"] == 0
        assert [s["id"] for s in store.stories()] == [host_surv]
        surv_story = store.stories()[0]
        assert len(surv_story["updates"]) == 1
        assert surv_story["alert_notes"] == [doctor.NOTES["A"]]


def test_auto_merge_blocks_lossy_merges_and_official_unroutable_skip_verifies(tmp_path):
    cfg = make_core_config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        # 1. Auto-merge refuses when duplicate has dated updates or confirmed > reported confidence.
        _, surv_id = _seed_story(
            store,
            url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/501",
            kind="gitlab_issue",
            title="Relay descriptor parsing issue #501",
            summary="Initial report of relay descriptor parsing issue.",
            confidence="reported",
            state="developing",
        )
        _, dup_id = _seed_story(
            store,
            url="https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/502",
            kind="gitlab_mr",
            title="Fix relay descriptor parsing issue #501",
            summary="Maintainers merged a fix for #501.",
            confidence="confirmed",
            state="merged",
        )
        publication.build(cfg, store)
        assert review_gate._auto_merge_pair(store, surv_id, dup_id) is None

        # 2. Official release item whose skip+same_story is blocked by _can_route goes to verify (then hold), never dropped unverified!
        rel_item = make_item(
            url="https://blog.torproject.org/new-release-tor-0499/",
            title="New Release: Tor 0.4.9.9",
            content="Tor 0.4.9.9 fixes a relay crash tracked in #501.",
            published_at=LATER,
            updated_at=LATER,
            authority="official",
            product="tor",
        )
        store.ingest(rel_item, LATER)
        rel_row = [r for r in store.pending(10, LATER) if "0499" in r["url"]][0]
        assert rel_row["cluster_key"] == "release:tor:0.4.9.9"
        rel_draft = analysis(
            title="Tor 0.4.9.9 released",
            summary="Tor 0.4.9.9 fixes a relay crash.",
            why_it_matters="",
            category="release",
            confidence="confirmed",
            state="released",
            products=["tor"],
            tags=["release"],
            evidence=["Tor 0.4.9.9 fixes a relay crash"],
        )
        prepared = store.prepare_candidate(rel_row, rel_draft, LATER)
        skip_res = make_verdict("skip", criterion="new_information")
        skip_res["same_story"] = surv_id
        skip_res["criteria"]["new_information"]["reason"] = f"Already covered in {surv_id}."
        rev1 = {"stage": "review", "candidate_hash": digest(prepared["candidate"]), "result": skip_res}
        action1, _ = review_gate.next_step([rev1], prepared["candidate"], prepared)
        assert action1 == "verify"
        rev2 = {"stage": "verification", "candidate_hash": digest(prepared["candidate"]), "result": skip_res}
        action2, hold_info = review_gate.next_step([rev1, rev2], prepared["candidate"], prepared)
        assert action2 == "hold" and hold_info == ("verification", "model_hold")


def test_final_holds_confirmed_updates_uncited_notes_and_punctuation_repairs():
    # 1. Updates to already-confirmed stories may keep confidence="confirmed" even on reported follow-up sources.
    cand = {
        "title": "Tor 0.4.9.5 released",
        "summary": "Tor 0.4.9.5 is out.",
        "why_it_matters": "",
        "category": "release",
        "priority": "normal",
        "confidence": "confirmed",
        "state": "released",
        "products": ["tor"],
        "tags": ["release"],
        "sources": [{"url": "https://gitlab.torproject.org/tpo/core/tor/-/work_items/99", "title": "Issue 99"}],
        "updates": [{
            "at": LATER,
            "text": "Operators reported packaging progress in comments.",
            "sources": [{"url": "https://gitlab.torproject.org/tpo/core/tor/-/work_items/99", "title": "Issue 99"}],
        }],
    }
    prep = {
        "mode": "update",
        "coverage": {"prior_story": {"id": "a" * 24, "confidence": "confirmed"}},
        "limits": {"confidence": {"reported"}, "states": {"reported", "developing", "released"}, "merge_verified": False},
        "packet": {
            "sources": [{
                "id": "S1",
                "url": "https://gitlab.torproject.org/tpo/core/tor/-/work_items/99",
                "authority": "development",
                "kind": "gitlab_issue",
                "passages": [
                    {"id": "S1.P1", "text": "Issue body text without completed verbs."},
                    # Uncited comment claims "merged" while update sources cite only the issue URL (no #note_ fragment):
                    {"id": "S1.N1", "url": "https://gitlab.torproject.org/tpo/core/tor/-/work_items/99#note_1", "text": "We merged and deployed the fix."},
                ],
            }],
        },
    }
    assert review.final_holds(cand, prep) == []

    # If the update text falsely claims "deployed" while citing only the issue URL, S1.N1 must NOT excuse it!
    cand_bad = {
        **cand,
        "updates": [{
            "at": LATER,
            "text": "Maintainers deployed the fix.",
            "sources": [{"url": "https://gitlab.torproject.org/tpo/core/tor/-/work_items/99", "title": "Issue 99"}],
        }],
    }
    assert "completed_action" in review.final_holds(cand_bad, prep)

    # Likewise, if a comment-only update cites ONLY #note_2, a done-word in the uncited parent issue body must NOT excuse it!
    prep_parent_done = {
        **prep,
        "packet": {
            "sources": [{
                "id": "S1",
                "url": "https://gitlab.torproject.org/tpo/core/tor/-/work_items/99",
                "authority": "development",
                "kind": "gitlab_issue",
                "passages": [
                    {"id": "S1.P1", "text": "Earlier release fixed an older unrelated crash."},
                    {"id": "S1.N2", "url": "https://gitlab.torproject.org/tpo/core/tor/-/work_items/99#note_2", "text": "Still investigating this regression."},
                ],
            }],
        },
    }
    cand_note_only = {
        **cand,
        "updates": [{
            "at": LATER,
            "text": "Maintainers fixed the regression.",
            "sources": [{"url": "https://gitlab.torproject.org/tpo/core/tor/-/work_items/99#note_2", "title": "Comment"}],
        }],
    }
    assert "completed_action" in review.final_holds(cand_note_only, prep_parent_done)

    # 2. Noncharacters in review._text and punctuation-only "." update repairs/drafts are rejected.
    with pytest.raises(review.ReviewError):
        review._text("Bad\ufffechar", 100)
    with pytest.raises(review.ReviewError):
        review.apply_repair(cand, {"update": "."}, update=True)
    with pytest.raises(AnalysisError):
        analyze.validate_analysis(
            {"publish": True, "update": ".", "confidence": "reported", "state": "developing", "evidence": ["exact words here"]},
            make_item(content="Some exact words here in the item."),
            schema=analyze.UPDATE_SCHEMA,
        )


def test_gitlab_note_gid_promotion_budget_clipping_and_unseen_comments_before_rest_updated_at(tmp_path):
    cfg = make_core_config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        note_url = "https://gitlab.torproject.org/tpo/core/tor/-/work_items/42#note_10"
        initial = {
            **make_item(
                url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/42",
                kind="gitlab_issue",
                title="Consensus weight calculation bug",
                content="Initial bug description with supporting evidence.",
                published_at="2026-11-10T10:00:00Z",
                updated_at="2026-11-10T10:00:00Z",
            ),
            "comments_source_key": "k1",
            "comments_checked_at": "2026-11-10T10:05:00Z",
            "public_comments": [{
                "id": "gid://gitlab/Note/10",
                "url": note_url,
                "title": "Public comment by @alice",
                "author": "alice",
                "created_at": "2026-11-10T10:02:00Z",
                "body": "Initial workaround note.",
            }],
        }
        store.ingest(initial, "2026-11-10T10:05:00Z")
        row0 = store.pending(1, "2026-11-10T10:05:00Z")[0]
        draft0 = analysis(
            title="Consensus weight calculation bug",
            summary="Initial bug description with supporting evidence.",
            evidence=["Initial bug description with supporting evidence."],
        )
        finish_reviewed(store, row0, draft0, "w0", "2026-11-10T10:06:00Z")

        # Promote GID from Note/10 to DiscussionNote/10 AND edit its body without changing created_at:
        promoted = {
            **initial,
            "updated_at": "2026-11-10T11:00:00Z",
            "comments_checked_at": "2026-11-10T11:05:00Z",
            "public_comments": [{
                "id": "gid://gitlab/DiscussionNote/10",
                "url": note_url,
                "title": "Public comment by @alice",
                "author": "alice",
                "created_at": "2026-11-10T10:02:00Z",
                "edited_at": "2026-11-10T11:00:00Z",
                "body": "Updated workaround: upgrade to 0.4.9.6 immediately.",
            }],
        }
        assert store.ingest(promoted, "2026-11-10T11:05:00Z") is True
        row1 = store.pending(1, "2026-11-10T11:05:00Z")[0]
        state1, writer_input1 = candidate.own_update_input(store.db, row1, json.loads(row1["payload"]))
        assert state1 == "update"
        assert "upgrade to 0.4.9.6" in writer_input1["public_comments"][0]["body"]

    # Budget clipping of an unedited tail comment must NOT stamp edited_at or trigger _changed_note_ids.
    newer_notes = [
        {
            "id": f"gid://gitlab/Note/{i}",
            "url": f"https://gitlab.torproject.org/tpo/core/tor/-/work_items/1#note_{i}",
            "title": "Public comment by @bob",
            "author": "bob",
            "created_at": f"2026-11-10T10:0{i}:00Z",
            "body": f"Comment {i} " + ("x" * 1790),
        }
        for i in range(5, 1, -1)
    ]
    tail_full = {
        "id": "gid://gitlab/Note/1",
        "url": "https://gitlab.torproject.org/tpo/core/tor/-/work_items/1#note_1",
        "title": "Public comment by @bob",
        "author": "bob",
        "created_at": "2026-11-10T10:01:00Z",
        "body": "Comment 1 " + ("z" * 1200),
    }
    newest_note = {
        "id": "gid://gitlab/Note/6",
        "url": "https://gitlab.torproject.org/tpo/core/tor/-/work_items/1#note_6",
        "title": "Public comment by @bob",
        "author": "bob",
        "created_at": "2026-11-10T10:06:00Z",
        "body": "Comment 6 " + ("y" * 290),
    }
    base_issue = make_item(url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/1", kind="gitlab_issue")
    rem1 = comments.TOTAL_CHARS - sum(len(n["body"]) for n in newer_notes)
    rem2 = comments.TOTAL_CHARS - len(newest_note["body"]) - sum(len(n["body"]) for n in newer_notes)
    poll1 = comments._compose(
        base_issue,
        [*newer_notes, {**tail_full, "body": tail_full["body"][:rem1]}],
        "2026-11-10T10:10:00Z",
        source_key="k",
    )
    poll2 = comments._compose(
        poll1,
        [newest_note, *newer_notes, {**tail_full, "body": tail_full["body"][:rem2]}],
        "2026-11-10T10:20:00Z",
        source_key="k",
    )
    assert "edited_at" not in poll2["public_comments"][-1]
    assert candidate._changed_note_ids(poll1, poll2) == set()

    # Same guarantee when the tail comment was edited once historically (edited_at unchanged across polls):
    tail_edited = {**tail_full, "edited_at": "2026-11-10T10:01:30Z"}
    poll1_ed = comments._compose(
        base_issue,
        [*newer_notes, {**tail_edited, "body": tail_edited["body"][:rem1]}],
        "2026-11-10T10:10:00Z",
        source_key="k",
    )
    poll2_ed = comments._compose(
        poll1_ed,
        [newest_note, *newer_notes, {**tail_edited, "body": tail_edited["body"][:rem2]}],
        "2026-11-10T10:20:00Z",
        source_key="k",
    )
    assert poll2_ed["public_comments"][-1]["edited_at"] == "2026-11-10T10:01:30Z"
    assert candidate._changed_note_ids(poll1_ed, poll2_ed) == set()


def test_comments_deadline_budget_damaged_merge_and_disabled_comments_keep_status(tmp_path, monkeypatch):
    cfg = make_core_config(tmp_path)
    cfg["comments"]["enabled"] = True
    src = {
        "id": "tor-gitlab",
        "name": "Tor GitLab",
        "kind": "gitlab_issue",
        "url": "https://gitlab.torproject.org/api/v4/projects/426/issues",
        "gitlab_project": "tpo/core/tor",
        "fallback_urls": [],
        "product": "tor",
        "authority": "development",
        "enabled": True,
        "interval_seconds": 300,
        "max_pages": 1,
        "max_items": 10,
    }
    cfg["sources"] = [src]
    key = comments._source_key(src)

    with Store(cfg["storage"]["database"]) as store:
        # 1. Partially damaged saved JSON missing comments_checked_at does not crash merge_cached_comments.
        issue_url = "https://gitlab.torproject.org/tpo/core/tor/-/work_items/88"
        bad_json = json.dumps({"url": issue_url, "kind": "gitlab_issue", "comments_source_key": key, "updated_at": DATE})
        with store.db:
            store.db.execute(
                "INSERT INTO items(id,url,source_id,payload,content_hash,cluster_key,first_seen,last_seen,status) VALUES(?,?,?,?,?,?,?,?,?)",
                ("id88", issue_url, "tor-gitlab", bad_json, "h", "ck88", DATE, DATE, "pending"),
            )
        merged = comments.merge_cached_comments(store, make_item(url=issue_url, kind="gitlab_issue"), src, LATER)
        assert "comments_checked_at" not in merged

        # 2. DeadlineReached during enrich_comments marks budget_reached=True without backing off project or item!
        enriched_item = {
            **make_item(url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/89", kind="gitlab_issue", source_id="tor-gitlab"),
            "comments_source_key": key,
            "comments_checked_at": DATE,
            "public_comments": [{
                "id": "gid://gitlab/Note/1",
                "url": "https://gitlab.torproject.org/tpo/core/tor/-/work_items/89#note_1",
                "title": "Public comment by @dev",
                "author": "dev",
                "created_at": DATE,
                "body": "Some public comment.",
            }],
        }
        store.ingest(enriched_item, DATE)
        row89 = store.db.execute("SELECT * FROM items WHERE url=?", (enriched_item["url"],)).fetchone()
        with store.db:
            comments.request_check(store.db, cfg, row89, DATE)
        monkeypatch.setattr(comments, "fetch_comments", lambda *_a, **_kw: (_ for _ in ()).throw(DeadlineReached()))
        rep = comments.enrich_comments(cfg, store, LATER, deadline=999999999.0)
        assert rep["budget_reached"] is True and rep["failed"] == 0
        cs = store.db.execute("SELECT failures FROM comment_sources WHERE source_id='tor-gitlab'").fetchone()
        assert cs["failures"] == 0

        # 3. Disabling comments.enabled does NOT reset a dismissed issue back to pending when REST body is unchanged!
        item_89_id = store.db.execute("SELECT id FROM items WHERE url=?", (enriched_item["url"],)).fetchone()[0]
        with store.db:
            store.db.execute("UPDATE items SET status='dismissed' WHERE id=?", (item_89_id,))
        rest_only = make_item(url=enriched_item["url"], kind="gitlab_issue", source_id="tor-gitlab", updated_at=LATER)
        assert store.ingest(rest_only, LATER) is False
        assert store.db.execute("SELECT status FROM items WHERE id=?", (item_89_id,)).fetchone()[0] == "dismissed"


def test_source_packet_skips_doctor_citations_and_store_handles_timeline_clock_skew_and_dismiss(tmp_path):
    _, cfg = make_doc_config(tmp_path, publish=True)
    with Store(cfg["storage"]["database"]) as store:
        # Legacy multi-source host story (editorial_item omitted) with attached DocTor citations must not fail missing_sources!
        i1 = make_item(url="https://example.org/legacy-1", title="Authority bastet maintenance", content="Authority bastet maintenance window.")
        i2 = make_item(url="https://example.org/legacy-2", title="Authority bastet update", content="Follow-up on authority bastet maintenance.")
        store.ingest(i1, "2024-01-14T10:00:00Z")
        store.ingest(i2, "2024-01-14T11:00:00Z")
        r1, r2 = store.pending(2, "2024-01-14T11:00:00Z")
        host_id = seed_host(
            store,
            url="https://example.org/bastet-legacy-host",
            title="Directory authority bastet planned maintenance",
            summary="Operators scheduled maintenance on directory authority bastet.",
        )
        # Convert host_id into a legacy 2-source story with no editorial_item, then attach DocTor:
        raw = json.loads(store.db.execute("SELECT payload FROM stories WHERE id=?", (host_id,)).fetchone()[0])
        raw.pop("editorial_item", None)
        raw["sources"] = [
            {"id": r1["id"], "url": r1["url"], "title": "Legacy 1", "published_at": "2024-01-14T10:00:00Z"},
            {"id": r2["id"], "url": r2["url"], "title": "Legacy 2", "published_at": "2024-01-14T11:00:00Z"},
        ]
        with store.db:
            store.db.execute("UPDATE stories SET payload=? WHERE id=?", (json.dumps(raw), host_id))
        doctor.ingest(store.db, cfg["sources"][0], bastet_incident_items(close=False), "2024-01-17T12:00:00Z")
        doctor.evaluate(cfg, store, cfg["sources"][0], FakeLinker(True), "2024-01-17T12:00:00Z")
        pinned_raw = json.loads(store.db.execute("SELECT payload FROM stories WHERE id=?", (host_id,)).fetchone()[0])
        pkt, _ = source_packet.build_packet(
            store.db,
            {**json.loads(r1["payload"]), "id": r1["id"]},
            pinned_raw,
            pinned_raw,
            None,
        )
        assert pkt["missing_sources"] == []

        # Stale timeline fallback with older committed_date is rejected, while a rebase with >= committed_date ingests!
        tl_v1 = {
            **make_item(
                url="https://gitlab.torproject.org/tpo/metrics/timeline/-/blob/aaa111/README.md?plain=1#L10",
                kind="metrics_timeline",
                title="Relay censorship event",
                content="Initial timeline description.",
                published_at="2024-01-15T00:00:00Z",
                updated_at="2024-01-15T12:00:00Z",
            ),
            "source_entry_id": "entry-1",
        }
        tl_stale_fallback = {
            **tl_v1,
            "url": "https://gitlab.torproject.org/tpo/metrics/timeline/-/blob/000999/README.md?plain=1#L9",
            "content": "Superseded older fallback description.",
            "updated_at": "2024-01-15T11:55:00Z",
        }
        tl_v2 = {
            **tl_v1,
            "url": "https://gitlab.torproject.org/tpo/metrics/timeline/-/blob/bbb222/README.md?plain=1#L10",
            "content": "Corrected timeline description from rebased commit.",
            "updated_at": "2024-01-15T12:00:00Z",
        }
        assert store.ingest(tl_v1, "2024-01-15T12:05:00Z") is True
        assert store.ingest(tl_stale_fallback, "2024-01-15T12:06:00Z") is False
        assert store.ingest(tl_v2, "2024-01-15T12:10:00Z") is True
        assert retained_analysis_keys(store.db) != set()

        # Dismissing a rejected item clears approval_key and excludes it from active review_gate.status() stages.
        tl_row = [r for r in store.pending(10, "2024-01-15T12:10:00Z") if r["url"] == tl_v2["url"]][0]
        with store.db:
            store.db.execute(
                "INSERT INTO review_jobs(item_id,writer_key,policy_hash,stage,record_json,approval_key,prepared_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                (tl_row["id"], "wk", "ph", "held", "{}", "app-key-1", DATE, DATE),
            )
        store.reject(tl_row["id"], "Held for operator review", "held.review.model_hold", "2024-01-15T12:15:00Z")
        assert review_gate.status(store)["stages"] == {"held": 1}
        rejection.dismiss_item(store, tl_row["id"], tl_row["content_hash"], "Not needed.", observed="2024-01-15T12:20:00Z")
        assert review_gate.status(store)["stages"] == {}
        assert store.db.execute("SELECT approval_key FROM review_jobs WHERE item_id=?", (tl_row["id"],)).fetchone()[0] is None


def test_doctor_review_model_non_retryable_strikes_regroup_publish_since_and_retracted_status(tmp_path):
    _, cfg = make_doc_config(tmp_path, publish=True)
    cfg["review"]["model"] = "dedicated-reviewer-model"
    checker = doctor.LinkChecker(cfg)
    assert checker.llm["model"] == "dedicated-reviewer-model"

    # 1-line truncated report returns None instead of fabricating a partial authority name.
    trunc_one = report_item("ONE_LINE_TRUNC", "2024-01-10T00:05:00Z", ["WARNING: The following authorities are missing from the consensus: bastet2"])
    assert doctor.parse(trunc_one, cfg["sources"][0], limit=len(trunc_one["content"])) is None

    # Single-omission close >= 24h after last listing produces non-contradictory prose.
    single_close_text = doctor._event_text({
        "kind": "A:close",
        "vars": {"authority": "bastet", "first_omit": "2024-01-20T01:00:00Z", "decided": "2024-01-20T01:00:00Z"},
    })
    assert "more than 24 hours after its last listing" in single_close_text

    # Unpinned closed episode before publish_since does NOT regroup a post-enable recurrence within 7 days!
    srv_line = "ERROR: Consensus is missing a current shared random value"
    ok_line = "NOTICE: The following directory authorities are not reporting bandwidth scanner results: faravahar"
    ep1 = [
        report_item(f"PRE_EN_{h}", format_utc(parse_utc("2024-01-03T00:05:00Z") + timedelta(hours=h)), [srv_line])
        for h in range(6)
    ] + [report_item("PRE_EN_CLOSE", "2024-01-03T06:05:00Z", [ok_line])]
    ep2 = [
        report_item(f"POST_EN_{h}", format_utc(parse_utc("2024-01-08T00:05:00Z") + timedelta(hours=h)), [srv_line])
        for h in range(6)
    ]
    with Store(tmp_path / "regroup.sqlite3") as store:
        store.set_meta(publish_since="2024-01-06T00:00:00Z")
        doctor.ingest(store.db, cfg["sources"][0], [*ep1, *ep2], "2024-01-08T06:00:00Z")
        res = doctor.evaluate(cfg, store, cfg["sources"][0], FakeLinker(), "2024-01-08T06:00:00Z")
        assert res["stories_written"] == 1
        [story] = store.stories()
        assert story["published_at"] >= "2024-01-08T00:00:00Z"

    # 3 non-retryable LinkChecker strikes fall back to standalone instead of stalling forever!
    with Store(cfg["storage"]["database"]) as store:
        seed_host(
            store,
            url="https://example.org/bastet-unrelated",
            title="Directory authority bastet flag count note",
            summary="Directory authority bastet flag note.",
        )
        doctor.ingest(store.db, cfg["sources"][0], bastet_incident_items(close=False), "2024-01-18T00:00:00Z")
        bad_err = AnalysisError("Model completion was truncated or refused", code="review.truncated")
        for minute in (0, 5):
            r_hold = doctor.evaluate(cfg, store, cfg["sources"][0], FakeLinker(bad_err), f"2024-01-18T00:{minute:02d}:00Z")
            assert r_hold["held"] == 1 and r_hold["stories_written"] == 0
        r_third = doctor.evaluate(cfg, store, cfg["sources"][0], FakeLinker(bad_err), "2024-01-18T00:10:00Z")
        assert r_third["stories_written"] == 1 and r_third["held"] == 0
        standalone = [s for s in store.stories() if s.get("origin") == "network-health"][0]

        # Lock standalone story, ingest close reports: held.network.story_locked increments held_updates once!
        publication.build(cfg, store)
        editorial.correct(
            store.db, standalone["id"],
            {"why_it_matters": "Operator context."},
            reason="Lock alert.",
            expect_hash=editorial.show(store.db, standalone["id"])["hash"],
            observed="2024-01-18T00:15:00Z",
        )
        close_only = bastet_incident_items(close=True)[5:]
        doctor.ingest(store.db, cfg["sources"][0], close_only, "2024-01-18T18:00:00Z")
        doctor.evaluate(cfg, store, cfg["sources"][0], FakeLinker(), "2024-01-18T18:00:00Z")
        doctor.evaluate(cfg, store, cfg["sources"][0], FakeLinker(), "2024-01-18T18:05:00Z")
        assert editorial.show(store.db, standalone["id"])["held_updates"] == 1
        assert decisions.summary(store.db, "2024-01-01T00:00:00Z")["awaiting_operator"]["held_updates"] == [
            {"story_id": standalone["id"], "held_updates": 1, "locked": True}
        ]

        # Retract standalone story: held_updates is hidden for permanently retracted stories and status reports retracted:<id>!
        editorial.retract(
            store.db, standalone["id"],
            reason="Retract alert.",
            expect_hash=editorial.show(store.db, standalone["id"])["hash"],
            observed="2024-01-18T19:00:00Z",
        )
        assert decisions.summary(store.db, "2024-01-01T00:00:00Z")["awaiting_operator"]["held_updates"] == []
        st = doctor.status(store.db, cfg["sources"])
        assert st["incidents"][0]["target"] == f"retracted:{standalone['id']}"

    # Multi-incident standalone network-health story stays "developing" while ANY held incident remains open,
    # regardless of incident loop order, and becomes "no-longer-listed" only after all held incidents close.
    _, cfg_multi = make_doc_config(tmp_path / "multi", publish=True)
    with Store(cfg_multi["storage"]["database"]) as store:
        t0 = parse_utc("2024-01-10T00:05:00Z")
        gab_and_mor_open = [
            report_item(
                f"M_BOTH_{i}",
                format_utc(t0 + timedelta(hours=i * 12)),
                [
                    "WARNING: The following authorities are missing from the consensus: gabelmoo",
                    "WARNING: The following authorities are missing from the consensus: moria1",
                ],
            )
            for i in range(5)
        ]
        doctor.ingest(store.db, cfg_multi["sources"][0], gab_and_mor_open, "2024-01-12T01:00:00Z")
        doctor.evaluate(cfg_multi, store, cfg_multi["sources"][0], FakeLinker(), "2024-01-12T01:00:00Z")
        publication.build(cfg_multi, store)
        s_gab = [s for s in store.stories() if "gabelmoo" in s["title"]][0]["id"]
        s_mor = [s for s in store.stories() if "moria1" in s["title"]][0]["id"]
        # Merge s_mor into s_gab so one standalone network-health story holds both incidents:
        editorial.merge(
            store.db, s_mor, s_gab,
            reason="Combine dual authority outage.",
            expect_hash=editorial.show(store.db, s_mor)["hash"],
            observed="2024-01-12T01:30:00Z",
        )
        # Now moria1 stays missing while gabelmoo recovers (>24h without gabelmoo missing):
        mor_only = [
            report_item(
                f"M_MOR_ONLY_{i}",
                format_utc(t0 + timedelta(hours=60 + i * 16)),
                ["WARNING: The following authorities are missing from the consensus: moria1"],
            )
            for i in range(2)
        ]
        doctor.ingest(store.db, cfg_multi["sources"][0], mor_only, "2024-01-13T18:00:00Z")
        doctor.evaluate(cfg_multi, store, cfg_multi["sources"][0], FakeLinker(), "2024-01-13T18:00:00Z")
        [combined_open] = store.stories()
        assert len(combined_open["network"]) == 2
        assert combined_open["state"] == "developing"

        # Now moria1 also recovers (>24h clean reports): even if a malformed {"key": []} entry exists
        # in the saved network list, evaluate skips it without raising TypeError and marks "no-longer-listed".
        bad_net_payload = json.loads(store.db.execute("SELECT payload FROM stories WHERE id=?", (s_gab,)).fetchone()[0])
        bad_net_payload["network"].append({"key": []})
        with store.db:
            store.db.execute("UPDATE stories SET payload=? WHERE id=?", (json.dumps(bad_net_payload), s_gab))
        all_clear = [
            report_item(f"M_CLEAR_{i}", format_utc(t0 + timedelta(hours=92 + i * 16)), [ok_line])
            for i in range(2)
        ]
        doctor.ingest(store.db, cfg_multi["sources"][0], all_clear, "2024-01-14T22:00:00Z")
        doctor.evaluate(cfg_multi, store, cfg_multi["sources"][0], FakeLinker(), "2024-01-14T22:00:00Z")
        [combined_closed] = store.stories()
        assert combined_closed["state"] == "no-longer-listed"


def test_collect_atom_related_links_transport_compression_deadline_and_url_config_guards(tmp_path):
    # 1. Atom duplicate-ID conflict detection works even when entries carry <link rel="related"/>!
    atom_xml = b"""<?xml version="1.0" encoding="utf-8"?>
    <feed xmlns="http://www.w3.org/2005/Atom">
      <title>Feed</title>
      <entry>
        <id>https://example.org/entry-1</id>
        <title>Event A</title>
        <updated>2026-11-10T12:00:00Z</updated>
        <link rel="related" href="https://example.org/ref-a"/>
        <summary>First distinct body.</summary>
      </entry>
      <entry>
        <id>https://example.org/entry-1</id>
        <title>Event B</title>
        <updated>2026-11-10T12:00:00Z</updated>
        <link rel="related" href="https://example.org/ref-b"/>
        <summary>Second conflicting body.</summary>
      </entry>
    </feed>"""

    class AtomHttp:
        def request(self, method, url, headers=None):
            return Response(200, atom_xml, {}, url)

    cfg = make_core_config(tmp_path)
    feed_res = collect.collect_source(AtomHttp(), cfg["sources"][0], {}, cfg["collection"], "2026-11-10T12:05:00Z")
    assert feed_res["items"] == [] and feed_res["skipped"] == 2

    # Same conflict detection when entries only provide <link rel="alternate" type="application/pdf"/>,
    # which feedparser 6.0.11 does not select as entry.link (falling back to the shared HTTPS entry ID)!
    atom_pdf_xml = atom_xml.replace(
        b'rel="related" href="https://example.org/ref-',
        b'rel="alternate" type="application/pdf" href="https://example.org/doc-',
    )

    class AtomPdfHttp:
        def request(self, method, url, headers=None):
            return Response(200, atom_pdf_xml, {}, url)

    pdf_res = collect.collect_source(AtomPdfHttp(), cfg["sources"][0], {}, cfg["collection"], "2026-11-10T12:05:00Z")
    assert pdf_res["items"] == [] and pdf_res["skipped"] == 2

    # Whereas an entry with a valid HTML <link rel="alternate"/> to that same URL and timestamp is preserved!
    atom_mixed_xml = atom_xml.replace(
        b"</feed>",
        b"""  <entry>
        <id>tag:example.org,2026:explicit</id>
        <title>Explicit Alternate Event</title>
        <updated>2026-11-10T12:00:00Z</updated>
        <link rel="alternate" type="text/html" href="https://example.org/entry-1"/>
        <summary>Explicitly linked body.</summary>
      </entry>
    </feed>""",
    )

    class AtomMixedHttp:
        def request(self, method, url, headers=None):
            return Response(200, atom_mixed_xml, {}, url)

    mixed_res = collect.collect_source(AtomMixedHttp(), cfg["sources"][0], {}, cfg["collection"], "2026-11-10T12:05:00Z")
    assert len(mixed_res["items"]) == 1 and mixed_res["items"][0]["title"] == "Explicit Alternate Event"
    assert mixed_res["skipped"] == 2

    # 2. AddressPolicy blocks 6to4 relay anycast and private ISATAP while allowing public IPv6.
    pol = AddressPolicy()
    assert pol.permits("192.88.99.1") is False
    assert pol.permits("2001:db8::1") is False
    assert pol.permits("2606:4700::200:5efe:127.0.0.1") is False
    assert pol.permits("2606:4700:4700::1111") is True

    # 3. HttpClient decodes multi-member gzip + raw RFC 1951 deflate, and raises DeadlineReached on final-attempt timeout!
    multi_gzip = gzip.compress(b"hello ") + gzip.compress(b"world")
    raw_comp = zlib.compressobj(level=6, wbits=-zlib.MAX_WBITS)
    raw_deflate = raw_comp.compress(b"raw deflate payload") + raw_comp.flush()

    class Streamed(httpx.SyncByteStream):
        def __init__(self, payload: bytes):
            self.payload = payload

        def __iter__(self):
            yield self.payload[:4]
            yield self.payload[4:]

    now = [100.0]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/gzip":
            return httpx.Response(200, headers={"content-encoding": "gzip"}, stream=Streamed(multi_gzip))
        if request.url.path == "/deflate":
            return httpx.Response(200, headers={"content-encoding": "deflate"}, stream=Streamed(raw_deflate))
        now[0] = 200.0
        raise httpx.ReadTimeout("deadline expired")

    resolver = lambda *_a, **_kw: [(0, 0, 0, "", ("93.184.216.34", 443))]
    with HttpClient(
        {**cfg["http"], "retry_attempts": 1},
        transport=httpx.MockTransport(handler),
        resolver=resolver,
        clock=lambda: now[0],
    ) as client:
        assert client.request("GET", "https://example.org/gzip").body == b"hello world"
        assert client.request("GET", "https://example.org/deflate").body == b"raw deflate payload"
        client.deadline = 150.0
        with pytest.raises(DeadlineReached):
            client.request("GET", "https://example.org/slow")
        assert client.deadline_reached is True

    # 4. canonical_url, item_cluster (tor-browser-<ver>), gitlab_refs (?query), and load_config validation!
    for bad_url in ("https://[::127.0.0.1]/", "https://[64:ff9b::127.0.0.1]/", "https://example.org:0/feed.xml"):
        with pytest.raises(ValueError):
            canonical_url(bad_url)
    assert canonical_url("https://[2606:4700:4700::1111]/feed.xml") == "https://[2606:4700:4700::1111]/feed.xml"
    assert (
        canonical_url("https://gitlab.torproject.org/tpo/core/tor/-/issues/123/designs")
        == "https://gitlab.torproject.org/tpo/core/tor/-/issues/123/designs"
    )
    assert (
        item_cluster({"title": "tor-browser-16.0.4", "content": "Tag", "kind": "tag", "product": "tor-browser"})
        == "release:tor-browser:16.0.4"
    )
    closing, _ = gitlab_refs({
        "url": "https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/10",
        "title": "Fix crash",
        "content": "Closes https://gitlab.torproject.org/tpo/core/tor/-/issues/41473?iid_path=true",
    })
    assert closing == ["https://gitlab.torproject.org/tpo/core/tor/-/work_items/41473"]

    bad_cfg = tmp_path / "bad.toml"
    bad_cfg.write_text('site = { base_url = 123 }\n', encoding="utf-8")
    with pytest.raises(ValueError):
        config_mod.load_config(bad_cfg)

    bad_net = tmp_path / "bad_net.toml"
    bad_net.write_text(
        '[llm]\nbase_url = "https://llm.example/v1"\nmodel = "m"\nallowed_networks = [true]\n'
        '[[sources]]\nid = "s"\nurl = "https://example.org/feed.xml"\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        config_mod.load_config(bad_net)


def test_retired_story_mid_gate_commit_recheck_unverified_route_cleanup_and_evaluator_routes(tmp_path, monkeypatch):
    cfg = make_core_config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        # 1. RetiredStory raised mid-process_item converts cleanly to ignored + skipped.gate.retired_story.
        inc = make_item(url="https://example.org/retire-mid", title="Mid-run retired story", content="Mid-run retired story details.")
        store.ingest(inc, DATE)
        row = store.pending(1, DATE)[0]

        class DummyWriter:
            calls = 0

            def analyze(self, item, prior=None):
                return analysis(
                    title="Mid-run retired story",
                    summary="Mid-run retired story details.",
                    evidence=["Mid-run retired story details."],
                )

        monkeypatch.setattr(store, "prepare_candidate", lambda *_a, **_kw: (_ for _ in ()).throw(editorial.RetiredStory("retired mid-run")))
        res = review_gate.process_item(cfg, store, row, DummyWriter(), object(), DATE)
        assert res["status"] == "ignored"
        assert store.db.execute("SELECT status FROM items WHERE id=?", (row["id"],)).fetchone()[0] == "ignored"
        assert store.db.execute("SELECT code FROM decision_log WHERE item_id=?", (row["id"],)).fetchone()[0] == "skipped.gate.retired_story"

    # 2. store.commit_candidate(operator=False) rejects stale lock changes, and unverified-routed pending items
    #    neither poison _stories_for_urls nor retain a dangling story_id if skipped!
    cfg2 = make_core_config(tmp_path / "c2")
    with Store(cfg2["storage"]["database"]) as store:
        _, host_id = _seed_story(
            store,
            url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/700",
            kind="gitlab_issue",
            title="Relay circuit timeout bug #700",
            summary="Operators reported relay circuit timeout bug.",
            category="network",
        )
        # Lock host_id AFTER prepare_candidate(locked=False): commit_candidate(operator=False) must raise StaleCandidate!
        upd_item = {
            **make_item(
                url="https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/701",
                kind="gitlab_mr",
                title="Fix relay circuit timeout",
                content="Closes #700 with a circuit timeout fix.",
                published_at=LATER,
                updated_at=LATER,
            ),
            "upstream_state": "merged",
        }
        store.ingest(upd_item, LATER)
        upd_row = [r for r in store.pending(10, LATER) if "701" in r["url"]][0]
        upd_draft = {
            "publish": True,
            "update": "A merge request merged a fix for the circuit timeout.",
            "confidence": "confirmed",
            "state": "merged",
            "evidence": ["Closes #700 with a circuit timeout fix."],
        }
        prepared = store.prepare_candidate(upd_row, upd_draft, LATER)
        pol = review.policy_hash(cfg2)
        app_key = digest(["ak", upd_row["id"]])
        ok_rev = make_verdict("approve", update=True)
        with store.db:
            store.db.execute(
                """INSERT INTO review_approvals(key,candidate_hash,source_hash,policy_hash,binding_hash,result_json,review_record_json,created_at,last_used_at)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (app_key, digest(prepared["candidate"]), prepared["source_hash"], pol, prepared["binding_hash"],
                 json.dumps(ok_rev), "{}", LATER, LATER),
            )
        editorial.correct(
            store.db, host_id,
            {"why_it_matters": "Locked mid-flight."},
            reason="Lock before commit.",
            expect_hash=editorial.show(store.db, host_id)["hash"],
            observed=LATER,
        )
        with pytest.raises(candidate.StaleCandidate):
            store.commit_candidate(prepared, prepared["candidate"], "wk", LATER, approval_key=app_key, policy_hash=pol)

        # Unlock host_id, simulate an unverified-routed pending item pointing at host_id:
        editorial.unlock(
            store.db, host_id,
            reason="Unlock for routing test.",
            expect_hash=editorial.show(store.db, host_id)["hash"],
            observed="2026-11-10T13:05:00Z",
        )
        unrel = make_item(
            url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/999",
            kind="gitlab_issue",
            title="Unrelated issue 999",
            content="Completely unrelated discussion text for testing.",
            published_at=LATER,
            updated_at=LATER,
        )
        store.ingest(unrel, LATER)
        unrel_row = [r for r in store.pending(10, LATER) if "999" in r["url"]][0]
        with store.db:
            store.db.execute(
                "UPDATE items SET story_id=?, last_error=? WHERE id=?",
                (host_id, candidate._UNVERIFIED_ROUTE, unrel_row["id"]),
            )
        # Pending unverified-routed item 999 must NOT associate other items mentioning #999 to host_id!
        assert candidate._stories_for_urls(store.db, [unrel_row["url"]]) == []
        # Conversely, requeuing published issue #700 (status='pending', last_error=NULL, story_id=host_id)
        # MUST preserve its association across _stories_for_urls!
        requeued_700 = make_item(
            url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/700",
            kind="gitlab_issue",
            title="Relay circuit timeout bug #700",
            content="Operators reported relay circuit timeout bug with follow-up reproduction steps.",
            published_at=DATE,
            updated_at="2026-11-10T13:06:00Z",
        )
        assert store.ingest(requeued_700, "2026-11-10T13:06:00Z") is True
        row_700 = store.db.execute(
            "SELECT status, last_error, story_id FROM items WHERE url=?", (requeued_700["url"],)
        ).fetchone()
        assert tuple(row_700) == ("pending", None, host_id)
        assert [s["id"] for s in candidate._stories_for_urls(store.db, [requeued_700["url"]])] == [host_id]

        # When unrel_row is skipped in update mode, its dangling story_id is cleared to NULL!
        unrel_row = [r for r in store.pending(10, LATER) if r["id"] == unrel_row["id"]][0]
        skip_prep = store.prepare_candidate(unrel_row, upd_draft, "2026-11-10T13:10:00Z")
        skip_rev = make_verdict("skip", criterion="new_information", update=True)
        skip_key = digest(["sk", unrel_row["id"]])
        with store.db:
            store.db.execute(
                """INSERT INTO review_approvals(key,candidate_hash,source_hash,policy_hash,binding_hash,result_json,review_record_json,created_at,last_used_at)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (skip_key, digest(skip_prep["candidate"]), skip_prep["source_hash"], pol, skip_prep["binding_hash"],
                 json.dumps(skip_rev), json.dumps({"reviews": [{"stage": "review", "result": skip_rev}]}), LATER, LATER),
            )
        store.commit_candidate(skip_prep, skip_prep["candidate"], "wk-skip", "2026-11-10T13:10:00Z",
                               decision="skip", approval_key=skip_key, policy_hash=pol)
        assert store.db.execute("SELECT story_id FROM items WHERE id=?", (unrel_row["id"],)).fetchone()[0] is None

    # 3. tools/evaluate_review.py only counts matched_routes when next_step actually routes (action == "route"),
    #    never when a skip to an unroutable network-health story falls back to plain skip.
    spec = importlib.util.spec_from_file_location(
        "evaluate_review_mod", Path(__file__).resolve().parents[1] / "tools" / "evaluate_review.py"
    )
    eval_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(eval_mod)

    target_id = "a" * 24
    eval_case = {
        "id": "route-to-network-health-blocked",
        "expected": "skip",
        "expected_same_story": target_id,
        "candidate": {
            "title": "Authority bastet unreachable",
            "summary": "Operators noticed authority bastet unreachable.",
            "why_it_matters": "",
            "category": "network",
            "priority": "normal",
            "confidence": "reported",
            "state": "developing",
            "products": ["network-health"],
            "tags": ["network"],
            "sources": [{"url": "https://gitlab.torproject.org/tpo/core/tor/-/work_items/321", "title": "Issue 321"}],
        },
        "packet": {
            "sources": [{
                "id": "S1",
                "url": "https://gitlab.torproject.org/tpo/core/tor/-/work_items/321",
                "title": "Issue 321",
                "kind": "gitlab_issue",
                "authority": "development",
                "product": "network-health",
                "published_at": DATE,
                "updated_at": DATE,
                "passages": [{"id": "S1.P1", "text": "Operators noticed authority bastet unreachable."}],
            }],
        },
        "existing_coverage": {
            "prior_story": None,
            "recent": [{
                "id": target_id,
                "origin": "network-health",
                "title": "Directory authority bastet missing from consensus",
                "summary": "DocTor reported bastet missing.",
                "category": "network",
                "state": "developing",
                "published_at": DATE,
                "updated_at": DATE,
                "sources": [],
            }],
        },
    }
    fake_skip = make_verdict("skip", criterion="new_information")
    fake_skip["same_story"] = target_id
    fake_skip["criteria"]["new_information"]["reason"] = f"Duplicate of {target_id}."

    class FakeEvalReviewer:
        last_decoded = None

        def __init__(self, *_a, **_kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

        def review(self, *_a, **_kw):
            return fake_skip

    monkeypatch.setattr(eval_mod, "EvaluationReviewer", FakeEvalReviewer)
    eval_summary = eval_mod.evaluate(cfg2, [eval_case], tmp_path / "eval_out.jsonl")
    assert eval_summary["matched_routes"] == 0
    assert eval_summary["wrong_routes"] == 1
    assert eval_summary["matched"] == 0

    # 4. Stale duplicate-merge completion in review_gate.process_item aborts atomically when the source item
    #    changed during verification, preserving both the newer held review_job and the unmerged story!
    cfg3 = make_core_config(tmp_path / "c3")
    with Store(cfg3["storage"]["database"]) as store:
        _, surv_story_id = _seed_story(
            store,
            url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/810",
            kind="gitlab_issue",
            title="Relay onion-service circuit issue #810",
            summary="Operators reported onion-service circuit issue #810.",
            category="network",
            confidence="reported",
            state="developing",
            published_at="2026-11-08T10:00:00Z",
        )
        dup_item_row, dup_story_id = _seed_story(
            store,
            url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/811",
            kind="gitlab_issue",
            title="Duplicate report of issue #810",
            summary="Follow-up report referencing #810.",
            category="network",
            confidence="reported",
            state="developing",
            published_at="2026-11-08T11:00:00Z",
        )
        publication.build(cfg3, store)
        # Requeue dup_item_row with a revision mentioning #810 so _auto_merge_pair(dup_story_id, surv_story_id) is eligible:
        dup_update_item = make_item(
            url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/811",
            kind="gitlab_issue",
            title="Duplicate report of issue #810",
            content="Follow-up report referencing https://gitlab.torproject.org/tpo/core/tor/-/work_items/810 with details.",
            published_at="2026-11-08T11:00:00Z",
            updated_at=LATER,
        )
        assert store.ingest(dup_update_item, LATER) is True
        dup_pending = [r for r in store.pending(10, LATER) if r["id"] == dup_item_row["id"]][0]

        class DupWriter:
            clears = 0

            def analyze(self, _item, prior=None):
                return {
                    "publish": True,
                    "update": "Follow-up report referencing work_items/810 with details.",
                    "confidence": "reported",
                    "state": "developing",
                    "evidence": ["Follow-up report referencing"],
                }

        class RacingReviewer:
            def __init__(self):
                self.calls = 0

            def review(self, _cand, _pkt, *, verification=False, issue=None, update=False, coverage=None):
                self.calls += 1
                res = make_verdict("approve", update=True)
                res["same_story"] = surv_story_id
                if verification:
                    # Simulate a concurrent worker ingesting and holding a newer revision of dup_pending!
                    with store.db:
                        store.db.execute(
                            "UPDATE items SET content_hash='newer-hash', status='rejected' WHERE id=?",
                            (dup_pending["id"],),
                        )
                        store.db.execute(
                            """INSERT OR REPLACE INTO review_jobs
                               (item_id,writer_key,policy_hash,stage,record_json,approval_key,prepared_at,updated_at)
                               VALUES(?,?,?,?,?,?,?,?)""",
                            (dup_pending["id"], "newer-wk", "ph", "held", '{"held":true}', "held-ak", LATER, LATER),
                        )
                return res

        race_out = review_gate.process_item(cfg3, store, dup_pending, DupWriter(), RacingReviewer(), LATER)
        assert race_out["status"] == "stale"
        assert editorial.retired(store.db, story_id=dup_story_id) is None
        kept_job = store.db.execute("SELECT writer_key, stage FROM review_jobs WHERE item_id=?", (dup_pending["id"],)).fetchone()
        assert tuple(kept_job) == ("newer-wk", "held")

        # Post-commit automatic merge on the survivor story also rechecks _auto_merge_pair inside the merge
        # transaction: if a concurrent writer adds a dated update to dup_story_id during verification, the
        # survivor update still commits cleanly while the stale duplicate merge is skipped!
        surv_update_item = make_item(
            url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/810",
            kind="gitlab_issue",
            title="Relay onion-service circuit issue #810",
            content="Operators reported onion-service circuit issue #810 with a follow-up reproduction.",
            published_at="2026-11-08T10:00:00Z",
            updated_at=LATER,
        )
        assert store.ingest(surv_update_item, LATER) is True
        surv_pending = [r for r in store.pending(10, LATER) if "810" in r["url"]][0]

        class SurvWriter:
            clears = 0

            def analyze(self, _item, prior=None):
                return {
                    "publish": True,
                    "update": "Operators reported onion-service circuit issue with a follow-up reproduction.",
                    "confidence": "reported",
                    "state": "developing",
                    "evidence": ["with a follow-up reproduction"],
                }

        class SurvRacingReviewer:
            def review(self, _cand, _pkt, *, verification=False, issue=None, update=False, coverage=None):
                res = make_verdict("approve", update=True)
                res["same_story"] = dup_story_id
                if verification:
                    dup_raw = json.loads(store.db.execute("SELECT payload FROM stories WHERE id=?", (dup_story_id,)).fetchone()[0])
                    dup_raw["updates"] = [{
                        "at": LATER,
                        "text": "Concurrent dated update on the duplicate story.",
                        "sources": dup_raw["sources"],
                    }]
                    with store.db:
                        store.db.execute("UPDATE stories SET payload=?, updated_at=? WHERE id=?", (json.dumps(dup_raw), LATER, dup_story_id))
                return res

        assert review_gate._auto_merge_pair(store, surv_story_id, dup_story_id) == (dup_story_id, surv_story_id)
        surv_out = review_gate.process_item(cfg3, store, surv_pending, SurvWriter(), SurvRacingReviewer(), LATER)
        assert surv_out["status"] == "published"
        assert editorial.retired(store.db, story_id=dup_story_id) is None
