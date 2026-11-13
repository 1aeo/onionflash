"""Permanent story aliases, duplicate pointer merges, rollback safety, and agreed duplicate auto-merge."""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import xml.etree.ElementTree as ET

import pytest

from approval_helpers import finish_reviewed, update_analysis, verdict
from onionflash import candidate, cli, decisions, editorial, publication, rejection, review, review_gate
from onionflash.store import Store
from onionflash.util import digest, item_cluster
from test_core import DATE, analysis, config, item
from test_review_gate import Reviewer, Writer


EARLY = "2026-11-08T10:00:00Z"
MID = "2026-11-08T14:00:00Z"
LATER = "2026-11-09T10:00:00Z"


def pending(store: Store, src_item: dict, observed: str = DATE) -> dict:
    store.ingest(src_item, observed)
    return next(r for r in store.pending(20, observed) if r["id"] == src_item["id"])


def run(cfg: dict, store: Store, row: dict, writer, checker, *, observed: str = LATER) -> dict:
    return review_gate.process_item(cfg, store, row, writer, checker, observed)


def _config_path(tmp_path: Path, cfg: dict) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(
        f'[site]\ntitle="Onion Flash"\ndescription="Tor news"\nbase_url="{cfg["site"]["base_url"]}"\n'
        f'repository_url="https://github.com/1aeo/onionflash"\npage_size={cfg["site"]["page_size"]}\n'
        f'[storage]\ndatabase="{cfg["storage"]["database"]}"\noutput_dir="{cfg["storage"]["output_dir"]}"\n'
        f'render_batch_size={cfg["storage"]["render_batch_size"]}\n'
        '[[sources]]\nid="example"\nurl="https://example.org/feed.xml"\nkind="feed"\nauthority="community"\nenabled=false\n',
        encoding="utf-8",
    )
    return path


def _publish(store: Store, src_item: dict, *, draft: dict | None = None, observed: str = DATE) -> dict:
    row = pending(store, src_item, observed)
    text = src_item["content"]
    snippet = text[: min(len(text), 48)]
    used = draft or analysis(
        title=src_item["title"],
        summary=f"{src_item['title']}: {snippet}",
        why_it_matters="",
        evidence=[snippet],
    )
    finish_reviewed(store, row, used, f"seed-{row['id']}", observed)
    story_id = store.db.execute("SELECT story_id FROM items WHERE id=?", (row["id"],)).fetchone()[0]
    story_row = store.db.execute("SELECT payload FROM stories WHERE id=?", (story_id,)).fetchone()
    return {"id": story_id, **json.loads(story_row[0])}


def test_story_aliases_are_permanent_and_block_recreation(tmp_path):
    cfg = config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        live = _publish(store, item(
            url="https://example.org/live-story",
            title="Live authority maintenance report",
            content="Operators reported planned maintenance on a synthetic authority host.",
        ), observed=EARLY)
        store.db.execute(
            "INSERT INTO story_aliases(story_id,cluster_key,survivor_id,reason,created_at,story_json) VALUES(?,?,?,?,?,?)",
            ("retired_story_alpha", "body:retired_cluster_alpha", None, "Removed duplicate notice", MID, '{"id":"retired_story_alpha"}'),
        )
        store.db.commit()

        with pytest.raises(sqlite3.IntegrityError, match="Story aliases are permanent"):
            store.db.execute("UPDATE story_aliases SET reason='changed' WHERE story_id='retired_story_alpha'")
        with pytest.raises(sqlite3.IntegrityError, match="Story aliases are permanent"):
            store.db.execute("DELETE FROM story_aliases WHERE story_id='retired_story_alpha'")
        with pytest.raises(sqlite3.IntegrityError, match="Story aliases are permanent"):
            store.db.execute(
                "INSERT OR REPLACE INTO story_aliases(story_id,cluster_key,survivor_id,reason,created_at) VALUES(?,?,?,?,?)",
                ("retired_story_alpha", "body:other", None, "replace", LATER),
            )

        # Direct INSERT or upsert with retired ID or cluster key is ignored by stories_never_recreated; live upsert works.
        c_id = store.db.execute(
            """INSERT INTO stories(id,cluster_key,payload,published_at,updated_at) VALUES(?,?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET payload=excluded.payload""",
            ("retired_story_alpha", "body:fresh", "{}", LATER, LATER),
        )
        c_ck = store.db.execute(
            """INSERT INTO stories(id,cluster_key,payload,published_at,updated_at) VALUES(?,?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET payload=excluded.payload""",
            ("brand_new_story", "body:retired_cluster_alpha", "{}", LATER, LATER),
        )
        assert c_id.rowcount == 0 and c_ck.rowcount == 0
        assert store.db.execute("SELECT COUNT(*) FROM stories WHERE id IN ('retired_story_alpha','brand_new_story')").fetchone()[0] == 0

        updated_payload = json.dumps({**live, "summary": "Updated summary on live story."})
        c_live = store.db.execute(
            """INSERT INTO stories(id,cluster_key,payload,published_at,updated_at) VALUES(?,?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,updated_at=excluded.updated_at""",
            (live["id"], f"url:{live['sources'][0]['url']}", updated_payload, live["published_at"], LATER),
        )
        assert c_live.rowcount == 1


def test_commit_candidate_raises_when_trigger_ignores_retired_upsert(tmp_path):
    cfg = config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        src = item(
            url="https://example.org/race-retired",
            title="Synthetic relay descriptor notice",
            content="Synthetic relay descriptor notice with literal text for candidate preparation.",
        )
        row = pending(store, src, EARLY)
        draft = analysis(
            title=src["title"],
            summary="Synthetic relay descriptor notice with literal text.",
            why_it_matters="",
            evidence=["Synthetic relay descriptor notice with literal text"],
        )
        prepared = store.prepare_candidate(row, draft, EARLY)
        policy = "policy-1"
        key = review_gate._approval_key(prepared["candidate"], prepared, policy)
        valid_reply = verdict("approve")
        with store.db:
            store.db.execute(
                """INSERT INTO review_approvals
                   (key,candidate_hash,source_hash,policy_hash,binding_hash,result_json,review_record_json,created_at,last_used_at)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (key, digest(prepared["candidate"]), prepared["source_hash"], policy, prepared["binding_hash"],
                 json.dumps(valid_reply), json.dumps({"schema_version": 1, "reviews": []}), EARLY, EARLY),
            )
            # Retire the story ID after prepare_candidate and before commit_candidate.
            store.db.execute(
                "INSERT INTO story_aliases(story_id,cluster_key,survivor_id,reason,created_at) VALUES(?,?,?,?,?)",
                (prepared["story_id"], prepared["cluster_key"], None, "Retired concurrently", MID),
            )
        with pytest.raises(editorial.RetiredStory):
            store.commit_candidate(
                prepared,
                prepared["candidate"],
                "writer-1",
                MID,
                approval_key=key,
                policy_hash=policy,
                decision="approve",
            )
        # Transaction rolled back: item is still pending, not falsely marked published.
        status_row = store.db.execute("SELECT status,story_id FROM items WHERE id=?", (row["id"],)).fetchone()
        assert tuple(status_row) == ("pending", None)


def test_tombstoned_and_uncataloged_aliases_never_call_models_or_render_pointers(tmp_path):
    cfg = config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        survivor = _publish(store, item(
            url="https://example.org/survivor-release",
            title="Tor Browser 99.0 released",
            content="Tor Browser 99.0 is released with synthetic transport updates.",
        ), observed=EARLY)
        cli.build(cfg, store)

        # Seed two aliases without public_catalog rows (uncataloged alias + tombstone).
        dup_item = item(
            kind="feed",
            url="https://example.org/uncataloged-dup",
            title="Follow-up note on Tor Browser 99.0",
            content="Follow-up note confirming Linux builds of Tor Browser 99.0 completed.",
        )
        tomb_item = item(
            kind="feed",
            url="https://example.org/historical-tombstone",
            title="Retired synthetic notice",
            content="Retired synthetic notice body text that must never hit a model.",
        )
        dup_ck = item_cluster(dup_item)
        dup_id = digest(dup_ck)[:24]
        tomb_ck = item_cluster(tomb_item)
        tomb_id = digest(tomb_ck)[:24]
        with store.db:
            store.db.execute(
                "INSERT INTO story_aliases(story_id,cluster_key,survivor_id,reason,created_at) VALUES(?,?,?,?,?)",
                (dup_id, dup_ck, survivor["id"], "Uncataloged duplicate", MID),
            )
            store.db.execute(
                "INSERT INTO story_aliases(story_id,cluster_key,survivor_id,reason,created_at) VALUES(?,?,?,?,?)",
                (tomb_id, tomb_ck, None, "Uncataloged retired notice", MID),
            )
            # Even if queued, an alias without a public_catalog row must not render a pointer page.
            store.db.execute("INSERT INTO public_render_queue(story_id) VALUES(?)", (dup_id,))

        cli.build(cfg, store)
        out_root = Path(cfg["storage"]["output_dir"])
        assert not (out_root / "news" / dup_id).exists()
        assert not (out_root / "news" / tomb_id).exists()

        # Feeding a tombstoned item ignores it with 0 writer and 0 review calls; retry repeats at 0 cost.
        tomb_row = pending(store, tomb_item, LATER)
        res = run(cfg, store, tomb_row, Writer(), Reviewer())
        assert res["status"] == "ignored" and res["writer_calls"] == 0 and res["review_calls"] == 0
        rejection.retry_item(store, tomb_row["id"], tomb_row["content_hash"], "Operator check")
        retried_row = store.pending(1, LATER)[0]
        res2 = run(cfg, store, retried_row, Writer(), Reviewer())
        assert res2["status"] == "ignored" and res2["writer_calls"] == 0 and res2["review_calls"] == 0

        # Feeding an item matching the uncataloged duplicate's cluster key updates the survivor without creating dup_id.
        dup_row = pending(store, dup_item, LATER)
        res_dup = run(
            cfg,
            store,
            dup_row,
            Writer(update_analysis(
                update="Linux builds of Tor Browser 99.0 completed.",
                evidence=["Linux builds of Tor Browser 99.0 completed"],
            )),
            Reviewer(verdict(update=True), verdict(update=True)),
            observed=LATER,
        )
        assert res_dup["status"] == "published"
        assert store.db.execute("SELECT story_id FROM items WHERE id=?", (dup_row["id"],)).fetchone()[0] == survivor["id"]
        assert store.db.execute("SELECT 1 FROM stories WHERE id=?", (dup_id,)).fetchone() is None
        cli.build(cfg, store)
        assert not (out_root / "news" / dup_id).exists()


def test_merge_publishes_pointer_remaps_items_chains_and_preserves_catalog_permanence(tmp_path):
    cfg = config(tmp_path)
    cfg["site"]["page_size"] = 1
    with Store(cfg["storage"]["database"]) as store:
        publication.initialize(store.db)
        # Install permanent catalog triggers so merge compatibility is pinned directly.
        store.db.executescript("""
            CREATE TRIGGER IF NOT EXISTS public_catalog_permanent BEFORE DELETE ON public_catalog BEGIN
                SELECT RAISE(ABORT, 'Published stories are permanent; correct or retract them instead');
            END;
            CREATE TRIGGER IF NOT EXISTS editorial_controls_permanent BEFORE DELETE ON editorial_controls BEGIN
                SELECT RAISE(ABORT, 'Editorial history is permanent');
            END;
        """)
        s_one = _publish(store, item(
            url="https://example.org/event-dup",
            title="Distinct Duplicate Title Alpha",
            content=" synthetic-overload-alpha initial report on directory authority load.",
        ), draft=analysis(
            title="Distinct Duplicate Title Alpha",
            summary="Initial report on directory authority load.",
            category="directory-authority",
            tags=["directory-authority", "relay"],
            why_it_matters="",
            evidence=["synthetic-overload-alpha initial report on directory authority load"],
        ), observed=EARLY)
        s_two = _publish(store, item(
            url="https://example.org/event-surv",
            title="Canonical Survivor Title Beta",
            content=" synthetic-overload-beta fuller report on directory authority load.",
        ), draft=analysis(
            title="Canonical Survivor Title Beta",
            summary="Fuller report on directory authority load.",
            category="directory-authority",
            tags=["directory-authority"],
            why_it_matters="",
            evidence=["synthetic-overload-beta fuller report on directory authority load"],
        ), observed=MID)
        # Add an unlinked item sharing s_one's cluster_key to verify unlinked cluster remap.
        s_one_ck = store.db.execute("SELECT cluster_key FROM stories WHERE id=?", (s_one["id"],)).fetchone()[0]
        store.db.execute(
            """INSERT INTO items(id,url,source_id,payload,content_hash,cluster_key,first_seen,last_seen,status,story_id)
               VALUES('unlinked_same_ck','https://example.org/unlinked','example','{}','h1',?,?,?,'ignored',NULL)""",
            (s_one_ck, EARLY, EARLY),
        )
        store.db.commit()
        first_build = cli.build(cfg, store)
        assert first_build["published_stories"] == 2

        dup_hash = editorial.show(store.db, s_one["id"])["hash"]
        merged = editorial.merge(
            store.db,
            s_one["id"],
            s_two["id"],
            expect_hash=dup_hash,
            reason="Private audit reason: duplicate of Beta.",
            base_url=cfg["site"]["base_url"],
            observed=LATER,
        )
        assert merged == {
            "story_id": s_one["id"],
            "merged_into": s_two["id"],
            "remapped_items": 2,
            "updated_at": LATER,
        }
        # Private stories row moved into story_aliases.story_json; catalog row kept; items remapped.
        assert store.db.execute("SELECT 1 FROM stories WHERE id=?", (s_one["id"],)).fetchone() is None
        saved_json = store.db.execute("SELECT story_json FROM story_aliases WHERE story_id=?", (s_one["id"],)).fetchone()[0]
        assert json.loads(saved_json)["title"] == "Distinct Duplicate Title Alpha"
        mapped = {r[0] for r in store.db.execute("SELECT story_id FROM items").fetchall()}
        assert mapped == {s_two["id"]}
        log_row = store.db.execute("SELECT code,subject,story_id FROM decision_log WHERE code='operator.merged'").fetchone()
        assert tuple(log_row) == ("operator.merged", s_one["id"], s_two["id"])

        # Coverage background excludes merged stories.
        cov = candidate.coverage_background(store.db, None)
        assert [entry["id"] for entry in cov["recent"]] == [s_two["id"]]

        # Editorial commands refuse the merged story and name the survivor.
        for fn, args in (
            (editorial.show, (store.db, s_one["id"])),
            (editorial.retract, (store.db, s_one["id"])),
            (editorial.unlock, (store.db, s_one["id"])),
        ):
            kw = {} if fn is editorial.show else {"expect_hash": dup_hash, "reason": "r"}
            with pytest.raises(editorial.RetiredStory, match=s_two["id"]):
                fn(*args, **kw)

        # Build renders the pointer HTML and story.json, removes D from views/topics/feeds/counts, and is idempotent.
        built = cli.build(cfg, store)
        assert built["published_stories"] == 1 and built["stories_skipped"] == 0 and built["no_browser_js_ready"] is True
        root = Path(cfg["storage"]["output_dir"])
        pointer_page = (root / "news" / s_one["id"] / "index.html").read_text(encoding="utf-8")
        survivor_url = f'{cfg["site"]["base_url"].rstrip("/")}/news/{s_two["id"]}/'
        assert f'<link rel="canonical" href="{survivor_url}">' in pointer_page
        assert f'<meta http-equiv="refresh" content="0; url={survivor_url}">' in pointer_page
        assert "noindex" not in pointer_page
        assert "This story has moved" in pointer_page
        assert "Read the combined story" in pointer_page
        assert "Distinct Duplicate Title Alpha" not in pointer_page
        assert "Canonical Survivor Title Beta" not in pointer_page
        assert "Private audit reason" not in pointer_page
        assert json.loads((root / "news" / s_one["id"] / "story.json").read_text(encoding="utf-8")) == {
            "id": s_one["id"],
            "merged_into": s_two["id"],
            "url": survivor_url,
        }
        assert s_one["id"] not in (root / "index.html").read_text(encoding="utf-8")
        assert not (root / "page" / "2" / "index.html").exists()
        assert s_one["id"] not in (root / "topics" / "relay" / "index.html").read_text(encoding="utf-8")
        assert s_one["id"] not in (root / "feed.xml").read_text(encoding="utf-8")
        assert s_one["id"] not in (root / "feed.json").read_text(encoding="utf-8")
        assert s_one["id"] not in (root / "tags" / "relay.xml").read_text(encoding="utf-8")
        artifacts = {r[0] for r in store.db.execute("SELECT path FROM public_artifacts").fetchall()}
        assert f"news/{s_one['id']}/index.html" in artifacts and f"news/{s_one['id']}/story.json" in artifacts
        second = cli.build(cfg, store)
        assert second["public_changed"] is False and second["published_stories"] == 1

        # Chained merge (s_one -> s_two, then s_two -> s_three) re-points both pointers to s_three!
        s_three = _publish(store, item(
            url="https://example.org/event-final",
            title="Final Combined Story Gamma",
            content=" synthetic-overload-gamma complete incident summary.",
        ), observed=LATER)
        cli.build(cfg, store)
        s_two_hash = editorial.show(store.db, s_two["id"])["hash"]
        editorial.merge(
            store.db,
            s_two["id"],
            s_three["id"],
            expect_hash=s_two_hash,
            reason="Chained into Gamma.",
            base_url=cfg["site"]["base_url"],
            observed=LATER,
        )
        assert editorial.retired(store.db, story_id=s_one["id"]) == (s_one["id"], s_three["id"])
        cli.build(cfg, store)
        final_url = f'{cfg["site"]["base_url"].rstrip("/")}/news/{s_three["id"]}/'
        assert json.loads((root / "news" / s_one["id"] / "story.json").read_text(encoding="utf-8"))["merged_into"] == s_three["id"]
        assert json.loads((root / "news" / s_two["id"] / "story.json").read_text(encoding="utf-8"))["merged_into"] == s_three["id"]
        assert final_url in (root / "news" / s_one["id"] / "index.html").read_text(encoding="utf-8")

        # Template rebuild re-renders pointers cleanly and keeps no_browser_js_ready True.
        rebuilt = cli.build(cfg, store, force=True)
        assert rebuilt["published_stories"] == 1 and rebuilt["stories_skipped"] == 0 and rebuilt["no_browser_js_ready"] is True


def test_rollback_simulation_older_builder_keeps_merged_story_out_of_views_and_preserves_pointer(tmp_path):
    """Simulate an earlier release's builder over a merged database: pointer files stay intact and D stays out of views."""
    cfg = config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        dup = _publish(store, item(
            url="https://example.org/rb-dup",
            title="Rollback Duplicate Story",
            content="Rollback duplicate body text with enough literal evidence.",
        ), observed=EARLY)
        surv = _publish(store, item(
            url="https://example.org/rb-surv",
            title="Rollback Survivor Story",
            content="Rollback survivor body text with enough literal evidence.",
        ), observed=MID)
        cli.build(cfg, store)
        editorial.merge(
            store.db,
            dup["id"],
            surv["id"],
            expect_hash=editorial.show(store.db, dup["id"])["hash"],
            reason="Merged before simulated rollback",
            base_url=cfg["site"]["base_url"],
            observed=LATER,
        )
        cli.build(cfg, store)
        root = Path(cfg["storage"]["output_dir"])
        pointer_html_before = (root / "news" / dup["id"] / "index.html").read_bytes()
        pointer_json_before = (root / "news" / dup["id"] / "story.json").read_bytes()

        # Simulate an earlier release's build behavior: template_identity changes, no _pointer branch, no story_aliases filter in _accepted.
        old_identity = "earlier-release-template-hash"
        with store.db:
            store.db.execute(
                "INSERT INTO public_render_queue(story_id) SELECT id FROM stories UNION SELECT story_id FROM public_catalog "
                "WHERE true ON CONFLICT(story_id) DO UPDATE SET last_error=NULL"
            )
            publication._set_meta(store.db, "publication_template", old_identity)
        # Run the candidate render check on dup["id"] (payload is None since stories row was deleted; catalog has pointer JSON).
        accepted = store.db.execute("SELECT * FROM public_catalog WHERE story_id=?", (dup["id"],)).fetchone()
        with pytest.raises(ValueError, match="Published stories require a title and summary"):
            publication._public_story(accepted)
        # And the view reader (_public_story with current=old_identity) returns None instead of crashing or listing dup.
        assert publication._public_story(accepted, old_identity) is None
        assert (root / "news" / dup["id"] / "index.html").read_bytes() == pointer_html_before
        assert (root / "news" / dup["id"] / "story.json").read_bytes() == pointer_json_before


def test_merge_refusals_and_cli_end_to_end(tmp_path, capsys):
    cfg = config(tmp_path)
    cfg_path = _config_path(tmp_path, cfg)
    with Store(cfg["storage"]["database"]) as store:
        pub_a = _publish(store, item(
            url="https://example.org/ref-a",
            title="Published Story A",
            content="Published story A content with literal support.",
        ), observed=EARLY)
        pub_b = _publish(store, item(
            url="https://example.org/ref-b",
            title="Published Story B",
            content="Published story B content with literal support.",
        ), observed=MID)
        cli.build(cfg, store)
        unbuilt = _publish(store, item(
            url="https://example.org/ref-unbuilt",
            title="Unbuilt Story C",
            content="Unbuilt story C content not yet rendered into public_catalog.",
        ), observed=LATER)
        hash_a = editorial.show(store.db, pub_a["id"])["hash"]
        hash_unbuilt = editorial.show(store.db, unbuilt["id"])["hash"]

        # Self-merge, unknown ID, stale hash, unpublished duplicate, unpublished survivor.
        with pytest.raises(ValueError, match="into itself"):
            editorial.merge(store.db, pub_a["id"], pub_a["id"], expect_hash=hash_a, reason="r")
        with pytest.raises(ValueError, match="Unknown story"):
            editorial.merge(store.db, "missing_story", pub_b["id"], expect_hash=hash_a, reason="r")
        with pytest.raises(ValueError, match="refresh its hash"):
            editorial.merge(store.db, pub_a["id"], pub_b["id"], expect_hash="0" * 64, reason="r")
        with pytest.raises(ValueError, match="already be published"):
            editorial.merge(store.db, unbuilt["id"], pub_b["id"], expect_hash=hash_unbuilt, reason="r")
        with pytest.raises(ValueError, match="already be published"):
            editorial.merge(store.db, pub_a["id"], unbuilt["id"], expect_hash=hash_a, reason="r")

        # Quarantined survivor refused.
        store.db.execute("INSERT OR REPLACE INTO public_render_queue(story_id,last_error) VALUES(?,'ValueError')", (pub_b["id"],))
        store.db.commit()
        with pytest.raises(ValueError, match="quarantined"):
            editorial.merge(store.db, pub_a["id"], pub_b["id"], expect_hash=hash_a, reason="r")
        store.db.execute("DELETE FROM public_render_queue WHERE story_id=?", (pub_b["id"],))
        store.db.commit()

        # Retracted story refused.
        editorial.retract(store.db, pub_b["id"], expect_hash=editorial.show(store.db, pub_b["id"])["hash"], reason="Withdrawn.", observed=LATER)
        with pytest.raises(ValueError, match="retracted"):
            editorial.merge(store.db, pub_a["id"], pub_b["id"], expect_hash=hash_a, reason="r")
        editorial.restore(store.db, pub_b["id"], 0, expect_hash=editorial.show(store.db, pub_b["id"])["hash"], reason="Restored.", observed=LATER)
        cli.build(cfg, store)

    # CLI story merge end-to-end (including lock contention returning 75).
    with cli.run_lock(cfg["storage"]["database"]):
        rc_locked = cli.main([
            "story", "merge", "--config", str(cfg_path),
            "--story", pub_a["id"], "--into", pub_b["id"],
            "--expect-hash", hash_a, "--reason", "locked check",
        ])
    assert rc_locked == 75
    assert json.loads(capsys.readouterr().out) == {"status": "already-running"}

    rc = cli.main([
        "story", "merge", "--config", str(cfg_path),
        "--story", pub_a["id"], "--into", pub_b["id"],
        "--expect-hash", hash_a, "--reason", "CLI merge check",
    ])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["story_id"] == pub_a["id"] and out["merged_into"] == pub_b["id"] and out["publication_pending"] is True


def test_automatic_published_duplicate_merge_and_safety_guards(tmp_path):
    """When both review and fresh verification agree on same_story in update mode, auto-merge newer into older."""
    cfg = config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        orig = _publish(store, item(
            url="https://gitlab.torproject.org/tpo/core/tor/-/issues/49001",
            kind="gitlab_issue",
            product="tor",
            title="Directory authority overload on 0.4.9.99",
            content="Issue #49001 tracks directory authority overload in Tor 0.4.9.99.",
        ), draft=analysis(
            title="Directory authority overload reported in Tor 0.4.9.99",
            summary="Issue #49001 tracks directory authority overload in Tor 0.4.9.99.",
            products=["tor"],
            why_it_matters="",
            evidence=["Issue #49001 tracks directory authority overload in Tor 0.4.9.99"],
        ), observed=EARLY)
        newer_dup = _publish(store, item(
            url="https://lists.torproject.org/archives/list/tor-relays@lists.torproject.org/message/DUP49001/",
            product="tor",
            title="[tor-relays] Directory authority overload in Tor 0.4.9.99",
            content="Mailing list report on issue #49001 directory authority overload in Tor 0.4.9.99.",
        ), draft=analysis(
            title="Mailing list report on Tor 0.4.9.99 authority overload",
            summary="Operators discussed issue #49001 directory authority overload in Tor 0.4.9.99.",
            products=["tor"],
            why_it_matters="",
            evidence=["issue #49001 directory authority overload in Tor 0.4.9.99"],
        ), observed=MID)
        unrelated = _publish(store, item(
            url="https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/9901",
            kind="gitlab_mr",
            upstream_state="merged",
            product="arti",
            title="Refactor Arti channel padding timer",
            content="Merged refactor for Arti channel padding timer.",
        ), draft=analysis(
            title="Arti channel padding timer refactored",
            summary="Merged refactor for Arti channel padding timer.",
            state="merged",
            confidence="confirmed",
            products=["arti"],
            why_it_matters="",
            evidence=["Merged refactor for Arti channel padding timer"],
        ), observed=MID)
        cli.build(cfg, store)

        # 1. Single-round disagreement (review names newer_dup, verification leaves same_story=None): NO merge.
        followup_1 = item(
            url="https://gitlab.torproject.org/tpo/core/tor/-/issues/49001",
            kind="gitlab_issue",
            product="tor",
            title="Directory authority overload on 0.4.9.99",
            content="Issue #49001 tracks directory authority overload in Tor 0.4.9.99.",
            updated_at=LATER,
            public_comments=[{
                "id": "101",
                "author": "maint",
                "title": "Comment by maint",
                "created_at": LATER,
                "url": "https://gitlab.torproject.org/tpo/core/tor/-/issues/49001#note_101",
                "body": "Maintainers narrowed the overload trigger to extra-info fetches.",
            }],
        )
        row_1 = pending(store, followup_1, LATER)
        res_1 = run(
            cfg,
            store,
            row_1,
            Writer(update_analysis(
                update="Maintainers narrowed the overload trigger to extra-info fetches.",
                evidence=["Maintainers narrowed the overload trigger to extra-info fetches"],
            )),
            Reviewer(
                verdict("approve", update=True, same_story=newer_dup["id"]),
                verdict("approve", update=True, same_story=None),
            ),
            observed=LATER,
        )
        assert res_1["status"] == "published"
        assert editorial.retired(store.db, story_id=newer_dup["id"]) is None

        # 2. Hallucinated same_story pointing at unrelated Arti story: deterministic overlap guard blocks merge.
        followup_2 = {
            **followup_1,
            "updated_at": "2026-11-09T11:00:00Z",
            "public_comments": [
                *followup_1["public_comments"],
                {
                    "id": "102",
                    "author": "maint",
                    "title": "Comment by maint",
                    "created_at": "2026-11-09T11:00:00Z",
                    "url": "https://gitlab.torproject.org/tpo/core/tor/-/issues/49001#note_102",
                    "body": "A patch is queued for review.",
                },
            ],
        }
        row_2 = pending(store, followup_2, "2026-11-09T11:00:00Z")
        res_2 = run(
            cfg,
            store,
            row_2,
            Writer(update_analysis(
                update="A patch is queued for review.",
                evidence=["A patch is queued for review"],
            )),
            Reviewer(
                verdict("approve", update=True, same_story=unrelated["id"]),
                verdict("approve", update=True, same_story=unrelated["id"]),
            ),
            observed="2026-11-09T11:00:00Z",
        )
        assert res_2["status"] == "published"
        assert editorial.retired(store.db, story_id=unrelated["id"]) is None

        # 3. Both review AND verification agree newer_dup is the same event as orig: newer_dup auto-merges into orig!
        followup_3 = {
            **followup_2,
            "updated_at": "2026-11-09T12:00:00Z",
            "public_comments": [
                *followup_2["public_comments"],
                {
                    "id": "103",
                    "author": "maint",
                    "title": "Comment by maint",
                    "created_at": "2026-11-09T12:00:00Z",
                    "url": "https://gitlab.torproject.org/tpo/core/tor/-/issues/49001#note_103",
                    "body": "Fix merged for Tor 0.4.9.99 overload.",
                },
            ],
        }
        row_3 = pending(store, followup_3, "2026-11-09T12:00:00Z")
        res_3 = run(
            cfg,
            store,
            row_3,
            Writer(update_analysis(
                update="Fix merged for Tor 0.4.9.99 overload.",
                evidence=["Fix merged for Tor 0.4.9.99 overload"],
            )),
            Reviewer(
                verdict("approve", update=True, same_story=newer_dup["id"]),
                verdict("approve", update=True, same_story=newer_dup["id"]),
            ),
            observed="2026-11-09T12:00:00Z",
        )
        assert res_3["status"] == "published"
        assert editorial.retired(store.db, story_id=newer_dup["id"]) == (newer_dup["id"], orig["id"])
        auto_log = store.db.execute("SELECT code,subject,story_id FROM decision_log WHERE code='merged.auto.same_event'").fetchone()
        assert tuple(auto_log) == ("merged.auto.same_event", newer_dup["id"], orig["id"])
        summary = decisions.summary(store.db, EARLY)
        assert summary["codes"]["merged.auto.same_event"] == 1
        assert summary["outcomes"]["merged"] == 1
        assert None not in summary["sources"]
        assert json.loads(json.dumps(summary, sort_keys=True))["outcomes"]["merged"] == 1
        assert "operator.merged" not in summary["codes"]


def test_auto_merge_when_update_arrives_on_newer_duplicate_requeues_onto_original(tmp_path):
    """When the incoming update is attached to the newer duplicate, merge newer -> older and re-queue the item onto older."""
    cfg = config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        older = _publish(store, item(
            url="https://gitlab.torproject.org/tpo/core/tor/-/issues/49100",
            kind="gitlab_issue",
            product="tor",
            title="Relay consensus stall in Tor 0.4.9.88",
            content="Issue #49100 reports relay consensus stall in Tor 0.4.9.88.",
        ), draft=analysis(
            title="Relay consensus stall reported in Tor 0.4.9.88",
            summary="Issue #49100 reports relay consensus stall in Tor 0.4.9.88.",
            products=["tor"],
            why_it_matters="",
            evidence=["Issue #49100 reports relay consensus stall in Tor 0.4.9.88"],
        ), observed=EARLY)
        newer = _publish(store, item(
            url="https://gitlab.torproject.org/tpo/core/tor/-/issues/49101",
            kind="gitlab_issue",
            product="tor",
            title="Duplicate report for Tor 0.4.9.88 consensus stall",
            content="Follow-on report referencing #49100 on Tor 0.4.9.88 consensus stall.",
        ), draft=analysis(
            title="Follow-on report on Tor 0.4.9.88 consensus stall",
            summary="Follow-on report referencing #49100 on Tor 0.4.9.88 consensus stall.",
            products=["tor"],
            why_it_matters="",
            evidence=["Follow-on report referencing #49100 on Tor 0.4.9.88 consensus stall"],
        ), observed=MID)
        cli.build(cfg, store)

        # Update arrives on `newer`; both review and verification skip or approve naming `older` in same_story.
        upd = item(
            url="https://gitlab.torproject.org/tpo/core/tor/-/issues/49101",
            kind="gitlab_issue",
            product="tor",
            title="Duplicate report for Tor 0.4.9.88 consensus stall",
            content="Follow-on report referencing #49100 on Tor 0.4.9.88 consensus stall.",
            updated_at=LATER,
            public_comments=[{
                "id": "201",
                "author": "dev",
                "title": "Comment by dev",
                "created_at": LATER,
                "url": "https://gitlab.torproject.org/tpo/core/tor/-/issues/49101#note_201",
                "body": "Confirmed the stall only occurs when DirCache is disabled.",
            }],
        )
        row_upd = pending(store, upd, LATER)
        skip_same = verdict("skip", criterion="new_information", update=True, same_story=older["id"])
        skip_same["criteria"]["new_information"]["reason"] = f"Same event as {older['id']}."
        res_routed = run(
            cfg,
            store,
            row_upd,
            Writer(update_analysis(
                update="The stall only occurs when DirCache is disabled.",
                evidence=["Confirmed the stall only occurs when DirCache is disabled"],
            )),
            Reviewer(skip_same, skip_same),
            observed=LATER,
        )
        assert res_routed["status"] == "routed" and res_routed["review_calls"] == 2
        assert editorial.retired(store.db, story_id=newer["id"]) == (newer["id"], older["id"])
        requeued = store.pending(1, LATER)[0]
        assert requeued["id"] == row_upd["id"] and requeued["story_id"] == older["id"]

        # Next cycle processes the re-queued item cleanly as an update of `older`!
        res_final = run(
            cfg,
            store,
            requeued,
            Writer(update_analysis(
                update="The stall only occurs when DirCache is disabled.",
                evidence=["Confirmed the stall only occurs when DirCache is disabled"],
            )),
            Reviewer(verdict("approve", update=True), verdict("approve", update=True)),
            observed=LATER,
        )
        assert res_final["status"] == "published"
        older_payload = json.loads(store.db.execute("SELECT payload FROM stories WHERE id=?", (older["id"],)).fetchone()[0])
        assert older_payload["updates"][-1]["text"] == "The stall only occurs when DirCache is disabled."
