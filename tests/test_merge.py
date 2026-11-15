"""Permanent story aliases, duplicate pointer merges, rollback safety, and agreed duplicate auto-merge."""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3

import pytest

from helpers import (
    DATE,
    Reviewer,
    Writer,
    analysis,
    config,
    finish_reviewed,
    insert_approval,
    item,
    update_analysis,
    verdict,
)
from onionflash import candidate, cli, decisions, editorial, publication, rejection, review_gate
from onionflash.analyze import AnalysisError
from onionflash.store import Store
from onionflash.util import digest, item_cluster

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
    snippet = src_item["content"][: min(len(src_item["content"]), 48)]
    used = draft or analysis(title=src_item["title"], summary=f"{src_item['title']}: {snippet}",
                             why_it_matters="", evidence=[snippet])
    finish_reviewed(store, row, used, f"seed-{row['id']}", observed)
    story_id = store.db.execute("SELECT story_id FROM items WHERE id=?", (row["id"],)).fetchone()[0]
    story_row = store.db.execute("SELECT payload FROM stories WHERE id=?", (story_id,)).fetchone()
    return {"id": story_id, **json.loads(story_row[0])}


def test_story_aliases_are_permanent_and_block_recreation(context):
    _, store = context
    live = _publish(store, item(
        url="https://example.org/live-story", title="Live authority maintenance report",
        content="Operators reported planned maintenance on a synthetic authority host.",
    ), observed=EARLY)
    store.db.execute(
        "INSERT INTO story_aliases(story_id,cluster_key,survivor_id,reason,created_at,story_json) VALUES(?,?,?,?,?,?)",
        ("retired_story_alpha", "body:retired_cluster_alpha", None, "Removed duplicate notice", MID, '{"id":"retired_story_alpha"}'),
    )
    store.db.commit()

    for sql, params in (
        ("UPDATE story_aliases SET reason='changed' WHERE story_id='retired_story_alpha'", ()),
        ("DELETE FROM story_aliases WHERE story_id='retired_story_alpha'", ()),
        ("INSERT OR REPLACE INTO story_aliases(story_id,cluster_key,survivor_id,reason,created_at) VALUES(?,?,?,?,?)",
         ("retired_story_alpha", "body:other", None, "replace", LATER)),
    ):
        with pytest.raises(sqlite3.IntegrityError, match="Story aliases are permanent"):
            store.db.execute(sql, params)

    upsert = "INSERT INTO stories(id,cluster_key,payload,published_at,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload"
    c_id = store.db.execute(upsert, ("retired_story_alpha", "body:fresh", "{}", LATER, LATER))
    c_ck = store.db.execute(upsert, ("brand_new_story", "body:retired_cluster_alpha", "{}", LATER, LATER))
    assert c_id.rowcount == 0 and c_ck.rowcount == 0
    assert store.db.execute("SELECT COUNT(*) FROM stories WHERE id IN ('retired_story_alpha','brand_new_story')").fetchone()[0] == 0

    updated_payload = json.dumps({**live, "summary": "Updated summary on live story."})
    c_live = store.db.execute(
        """INSERT INTO stories(id,cluster_key,payload,published_at,updated_at) VALUES(?,?,?,?,?)
           ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,updated_at=excluded.updated_at""",
        (live["id"], f"url:{live['sources'][0]['url']}", updated_payload, live["published_at"], LATER),
    )
    assert c_live.rowcount == 1


def test_commit_candidate_raises_when_trigger_ignores_retired_upsert(context):
    _, store = context
    src = item(url="https://example.org/race-retired", title="Synthetic relay descriptor notice",
               content="Synthetic relay descriptor notice with literal text for candidate preparation.")
    row = pending(store, src, EARLY)
    draft = analysis(title=src["title"], summary="Synthetic relay descriptor notice with literal text.",
                     why_it_matters="", evidence=["Synthetic relay descriptor notice with literal text"])
    prepared = store.prepare_candidate(row, draft, EARLY)
    receipt = insert_approval(store, prepared, policy="policy-1", created_at=EARLY)
    with store.db:
        store.db.execute(
            "INSERT INTO story_aliases(story_id,cluster_key,survivor_id,reason,created_at) VALUES(?,?,?,?,?)",
            (prepared["story_id"], prepared["cluster_key"], None, "Retired concurrently", MID),
        )
    with pytest.raises(editorial.RetiredStory):
        store.commit_candidate(prepared, prepared["candidate"], "writer-1", MID, decision="approve", **receipt)
    assert tuple(store.db.execute("SELECT status,story_id FROM items WHERE id=?", (row["id"],)).fetchone()) == ("pending", None)


def test_tombstoned_and_uncataloged_aliases_never_call_models_or_render_pointers(context):
    cfg, store = context
    survivor = _publish(store, item(
        url="https://example.org/survivor-release", title="Tor Browser 99.0 released",
        content="Tor Browser 99.0 is released with synthetic transport updates.",
    ), observed=EARLY)
    cli.build(cfg, store)

    dup_item = item(kind="feed", url="https://example.org/uncataloged-dup", title="Follow-up note on Tor Browser 99.0",
                    content="Follow-up note confirming Linux builds of Tor Browser 99.0 completed.")
    tomb_item = item(kind="feed", url="https://example.org/historical-tombstone", title="Retired synthetic notice",
                     content="Retired synthetic notice body text that must never hit a model.")
    dup_ck, tomb_ck = item_cluster(dup_item), item_cluster(tomb_item)
    dup_id, tomb_id = digest(dup_ck)[:24], digest(tomb_ck)[:24]
    with store.db:
        store.db.execute("INSERT INTO story_aliases(story_id,cluster_key,survivor_id,reason,created_at) VALUES(?,?,?,?,?)",
                         (dup_id, dup_ck, survivor["id"], "Uncataloged duplicate", MID))
        store.db.execute("INSERT INTO story_aliases(story_id,cluster_key,survivor_id,reason,created_at) VALUES(?,?,?,?,?)",
                         (tomb_id, tomb_ck, None, "Uncataloged retired notice", MID))
        store.db.execute("INSERT INTO public_render_queue(story_id) VALUES(?)", (dup_id,))

    cli.build(cfg, store)
    out_root = Path(cfg["storage"]["output_dir"])
    assert not (out_root / "news" / dup_id).exists() and not (out_root / "news" / tomb_id).exists()

    tomb_row = pending(store, tomb_item, LATER)
    res = run(cfg, store, tomb_row, Writer(), Reviewer())
    assert (res["status"], res["writer_calls"], res["review_calls"]) == ("ignored", 0, 0)
    rejection.retry_item(store, tomb_row["id"], tomb_row["content_hash"], "Operator check")
    res2 = run(cfg, store, store.pending(1, LATER)[0], Writer(), Reviewer())
    assert (res2["status"], res2["writer_calls"], res2["review_calls"]) == ("ignored", 0, 0)

    dup_row = pending(store, dup_item, LATER)
    res_dup = run(
        cfg, store, dup_row,
        Writer(update_analysis(update="Linux builds of Tor Browser 99.0 completed.",
                               evidence=["Linux builds of Tor Browser 99.0 completed"])),
        Reviewer(verdict(update=True), verdict(update=True)), observed=LATER,
    )
    assert res_dup["status"] == "published"
    assert store.db.execute("SELECT story_id FROM items WHERE id=?", (dup_row["id"],)).fetchone()[0] == survivor["id"]
    assert store.db.execute("SELECT 1 FROM stories WHERE id=?", (dup_id,)).fetchone() is None
    cli.build(cfg, store)
    assert not (out_root / "news" / dup_id).exists()


def test_merge_publishes_pointer_remaps_items_chains_and_preserves_catalog_permanence(context):
    cfg, store = context
    cfg["site"]["page_size"] = 1
    publication.initialize(store.db)
    store.db.executescript("""
        CREATE TRIGGER IF NOT EXISTS public_catalog_permanent BEFORE DELETE ON public_catalog BEGIN
            SELECT RAISE(ABORT, 'Published stories are permanent; correct or retract them instead');
        END;
        CREATE TRIGGER IF NOT EXISTS editorial_controls_permanent BEFORE DELETE ON editorial_controls BEGIN
            SELECT RAISE(ABORT, 'Editorial history is permanent');
        END;
    """)
    s_one = _publish(store, item(
        url="https://example.org/event-dup", title="Distinct Duplicate Title Alpha",
        content=" synthetic-overload-alpha initial report on directory authority load.",
    ), draft=analysis(
        title="Distinct Duplicate Title Alpha", summary="Initial report on directory authority load.",
        category="directory-authority", tags=["directory-authority", "relay"], why_it_matters="",
        evidence=["synthetic-overload-alpha initial report on directory authority load"],
    ), observed=EARLY)
    s_two = _publish(store, item(
        url="https://example.org/event-surv", title="Canonical Survivor Title Beta",
        content=" synthetic-overload-beta fuller report on directory authority load.",
    ), draft=analysis(
        title="Canonical Survivor Title Beta", summary="Fuller report on directory authority load.",
        category="directory-authority", tags=["directory-authority"], why_it_matters="",
        evidence=["synthetic-overload-beta fuller report on directory authority load"],
    ), observed=MID)
    s_one_ck = store.db.execute("SELECT cluster_key FROM stories WHERE id=?", (s_one["id"],)).fetchone()[0]
    store.db.execute(
        """INSERT INTO items(id,url,source_id,payload,content_hash,cluster_key,first_seen,last_seen,status,story_id)
           VALUES('unlinked_same_ck','https://example.org/unlinked','example','{}','h1',?,?,?,'ignored',NULL)""",
        (s_one_ck, EARLY, EARLY),
    )
    store.db.commit()
    assert cli.build(cfg, store)["published_stories"] == 2

    dup_hash = editorial.show(store.db, s_one["id"])["hash"]
    merged = editorial.merge(
        store.db, s_one["id"], s_two["id"], expect_hash=dup_hash,
        reason="Private audit reason: duplicate of Beta.", base_url=cfg["site"]["base_url"], observed=LATER,
    )
    assert merged == {"story_id": s_one["id"], "merged_into": s_two["id"], "remapped_items": 2, "updated_at": LATER}
    assert store.db.execute("SELECT 1 FROM stories WHERE id=?", (s_one["id"],)).fetchone() is None
    saved_json = store.db.execute("SELECT story_json FROM story_aliases WHERE story_id=?", (s_one["id"],)).fetchone()[0]
    assert json.loads(saved_json)["title"] == "Distinct Duplicate Title Alpha"
    assert {r[0] for r in store.db.execute("SELECT story_id FROM items").fetchall()} == {s_two["id"]}
    log_row = store.db.execute("SELECT code,subject,story_id FROM decision_log WHERE code='operator.merged'").fetchone()
    assert tuple(log_row) == ("operator.merged", s_one["id"], s_two["id"])
    assert [e["id"] for e in candidate.coverage_background(store.db, None)["recent"]] == [s_two["id"]]

    for fn in (editorial.show, editorial.retract, editorial.unlock):
        kw = {} if fn is editorial.show else {"expect_hash": dup_hash, "reason": "r"}
        with pytest.raises(editorial.RetiredStory, match=s_two["id"]):
            fn(store.db, s_one["id"], **kw)

    built = cli.build(cfg, store)
    assert (built["published_stories"], built["stories_skipped"]) == (1, 0)
    root = Path(cfg["storage"]["output_dir"])
    pointer_page = (root / "news" / s_one["id"] / "index.html").read_text(encoding="utf-8")
    survivor_url = f'{cfg["site"]["base_url"].rstrip("/")}/news/{s_two["id"]}/'
    assert f'<link rel="canonical" href="{survivor_url}">' in pointer_page
    assert f'<meta http-equiv="refresh" content="0; url={survivor_url}">' in pointer_page
    assert "noindex" not in pointer_page
    assert "This story has moved" in pointer_page and "Read the combined story" in pointer_page
    for secret in ("Distinct Duplicate Title Alpha", "Canonical Survivor Title Beta", "Private audit reason"):
        assert secret not in pointer_page
    assert json.loads((root / "news" / s_one["id"] / "story.json").read_text(encoding="utf-8")) == {
        "id": s_one["id"], "merged_into": s_two["id"], "url": survivor_url,
    }
    assert not (root / "page" / "2" / "index.html").exists()
    for rel in ("index.html", "topics/relay/index.html", "feed.xml", "feed.json", "tags/relay.xml"):
        assert s_one["id"] not in (root / rel).read_text(encoding="utf-8")
    artifacts = {r[0] for r in store.db.execute("SELECT path FROM public_artifacts").fetchall()}
    assert {f"news/{s_one['id']}/index.html", f"news/{s_one['id']}/story.json"} <= artifacts
    second = cli.build(cfg, store)
    assert second["public_changed"] is False and second["published_stories"] == 1

    s_three = _publish(store, item(
        url="https://example.org/event-final", title="Final Combined Story Gamma",
        content=" synthetic-overload-gamma complete incident summary.",
    ), observed=LATER)
    cli.build(cfg, store)
    editorial.merge(
        store.db, s_two["id"], s_three["id"], expect_hash=editorial.show(store.db, s_two["id"])["hash"],
        reason="Chained into Gamma.", base_url=cfg["site"]["base_url"], observed=LATER,
    )
    assert editorial.retired(store.db, story_id=s_one["id"]) == (s_one["id"], s_three["id"])
    cli.build(cfg, store)
    final_url = f'{cfg["site"]["base_url"].rstrip("/")}/news/{s_three["id"]}/'
    assert json.loads((root / "news" / s_one["id"] / "story.json").read_text(encoding="utf-8"))["merged_into"] == s_three["id"]
    assert json.loads((root / "news" / s_two["id"] / "story.json").read_text(encoding="utf-8"))["merged_into"] == s_three["id"]
    assert final_url in (root / "news" / s_one["id"] / "index.html").read_text(encoding="utf-8")

    rebuilt = cli.build(cfg, store, force=True)
    assert (rebuilt["published_stories"], rebuilt["stories_skipped"]) == (1, 0)


def test_null_tombstone_story_alias_removes_story_and_handles_chained_merges(context):
    cfg, store = context
    s1 = _publish(store, item(url="https://example.org/s1", title="First incident report",
                              content="First incident details with supporting upstream text."),
                  draft=analysis(title="First incident report", summary="First incident details.",
                                 category="release", tags=["release"], evidence=["First incident details."]))["id"]
    s2 = _publish(store, item(url="https://example.org/s2", title="Second incident report",
                              content="Second incident details with supporting upstream text."),
                  draft=analysis(title="Second incident report", summary="Second incident details.",
                                 category="release", tags=["release"], evidence=["Second incident details."]))["id"]
    publication.build(cfg, store)
    out = Path(cfg["storage"]["output_dir"])
    assert (out / "news" / s1 / "index.html").exists()

    editorial.merge(store.db, s1, s2, reason="Consolidate duplicate reports.",
                    expect_hash=editorial.show(store.db, s1)["hash"], observed=LATER)
    s2_row = store.db.execute("SELECT cluster_key, payload FROM stories WHERE id=?", (s2,)).fetchone()
    with store.db:
        store.db.execute(
            "INSERT INTO story_aliases(story_id,cluster_key,survivor_id,reason,created_at,story_json) VALUES(?,?,NULL,?,?,?)",
            (s2, s2_row["cluster_key"], "Hard-deleted story.", LATER, s2_row["payload"]),
        )
        store.db.execute("DELETE FROM stories WHERE id=?", (s2,))

    res = publication.build(cfg, store)
    assert res["stories_skipped"] == 0 and res["published_stories"] == 0
    assert store.db.execute("SELECT COUNT(*) FROM public_story_topics").fetchone()[0] == 0
    for rel in ("index.html", "topics/release/index.html", "feed.xml", "feed.json"):
        rendered = (out / rel).read_text(encoding="utf-8")
        assert s1 not in rendered and s2 not in rendered

    s3 = _publish(store, item(url="https://example.org/s3", title="Third active notice",
                              content="Active notice details with supporting upstream text."))["id"]
    res_next = publication.build(cfg, store)
    assert res_next["published_stories"] == 1 and s3 in (out / "index.html").read_text(encoding="utf-8")


def test_rollback_simulation_older_builder_keeps_merged_story_out_of_views_and_preserves_pointer(context):
    """Simulate an earlier release's builder over a merged database: pointer files stay intact and D stays out of views."""
    from onionflash.store import set_meta

    cfg, store = context
    dup = _publish(store, item(url="https://example.org/rb-dup", title="Rollback Duplicate Story",
                               content="Rollback duplicate body text with enough literal evidence."), observed=EARLY)
    surv = _publish(store, item(url="https://example.org/rb-surv", title="Rollback Survivor Story",
                                content="Rollback survivor body text with enough literal evidence."), observed=MID)
    cli.build(cfg, store)
    editorial.merge(
        store.db, dup["id"], surv["id"], expect_hash=editorial.show(store.db, dup["id"])["hash"],
        reason="Merged before simulated rollback", base_url=cfg["site"]["base_url"], observed=LATER,
    )
    cli.build(cfg, store)
    root = Path(cfg["storage"]["output_dir"])
    pointer_html_before = (root / "news" / dup["id"] / "index.html").read_bytes()
    pointer_json_before = (root / "news" / dup["id"] / "story.json").read_bytes()

    old_identity = "earlier-release-template-hash"
    with store.db:
        store.db.execute(
            "INSERT INTO public_render_queue(story_id) SELECT id FROM stories UNION SELECT story_id FROM public_catalog "
            "WHERE true ON CONFLICT(story_id) DO UPDATE SET last_error=NULL"
        )
        set_meta(store.db, publication_template=old_identity)
    accepted = store.db.execute("SELECT * FROM public_catalog WHERE story_id=?", (dup["id"],)).fetchone()
    with pytest.raises(ValueError, match="Published stories require a title and summary"):
        publication._public_story(accepted)
    assert publication._public_story(accepted, old_identity) is None
    assert (root / "news" / dup["id"] / "index.html").read_bytes() == pointer_html_before
    assert (root / "news" / dup["id"] / "story.json").read_bytes() == pointer_json_before


def test_merge_refusals_and_cli_end_to_end(tmp_path, capsys):
    cfg = config(tmp_path)
    cfg_path = _config_path(tmp_path, cfg)
    with Store(cfg["storage"]["database"]) as store:
        pub_a = _publish(store, item(url="https://example.org/ref-a", title="Published Story A",
                                     content="Published story A content with literal support."), observed=EARLY)
        pub_b = _publish(store, item(url="https://example.org/ref-b", title="Published Story B",
                                     content="Published story B content with literal support."), observed=MID)
        cli.build(cfg, store)
        unbuilt = _publish(store, item(url="https://example.org/ref-unbuilt", title="Unbuilt Story C",
                                       content="Unbuilt story C content not yet rendered into public_catalog."), observed=LATER)
        hash_a = editorial.show(store.db, pub_a["id"])["hash"]
        hash_unbuilt = editorial.show(store.db, unbuilt["id"])["hash"]

        for dup_id, surv_id, h, match in (
            (pub_a["id"], pub_a["id"], hash_a, "into itself"),
            ("missing_story", pub_b["id"], hash_a, "Unknown story"),
            (pub_a["id"], pub_b["id"], "0" * 64, "refresh its hash"),
            (unbuilt["id"], pub_b["id"], hash_unbuilt, "already be published"),
            (pub_a["id"], unbuilt["id"], hash_a, "already be published"),
        ):
            with pytest.raises(ValueError, match=match):
                editorial.merge(store.db, dup_id, surv_id, expect_hash=h, reason="r")

        store.db.execute("INSERT OR REPLACE INTO public_render_queue(story_id,last_error) VALUES(?,'ValueError')", (pub_b["id"],))
        store.db.commit()
        with pytest.raises(ValueError, match="quarantined"):
            editorial.merge(store.db, pub_a["id"], pub_b["id"], expect_hash=hash_a, reason="r")
        store.db.execute("DELETE FROM public_render_queue WHERE story_id=?", (pub_b["id"],))
        store.db.commit()

        editorial.retract(store.db, pub_b["id"], expect_hash=editorial.show(store.db, pub_b["id"])["hash"],
                          reason="Withdrawn.", observed=LATER)
        with pytest.raises(ValueError, match="retracted"):
            editorial.merge(store.db, pub_a["id"], pub_b["id"], expect_hash=hash_a, reason="r")
        editorial.restore(store.db, pub_b["id"], 0, expect_hash=editorial.show(store.db, pub_b["id"])["hash"],
                          reason="Restored.", observed=LATER)
        cli.build(cfg, store)

    with cli.run_lock(cfg["storage"]["database"]):
        rc_locked = cli.main(["story", "merge", "--config", str(cfg_path), "--story", pub_a["id"],
                              "--into", pub_b["id"], "--expect-hash", hash_a, "--reason", "locked check"])
    assert rc_locked == 75 and json.loads(capsys.readouterr().out) == {"status": "already-running"}

    rc = cli.main(["story", "merge", "--config", str(cfg_path), "--story", pub_a["id"],
                   "--into", pub_b["id"], "--expect-hash", hash_a, "--reason", "CLI merge check"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0 and (out["story_id"], out["merged_into"], out["publication_pending"]) == (pub_a["id"], pub_b["id"], True)


def test_automatic_published_duplicate_merge_and_safety_guards(context):
    """When both review and fresh verification agree on same_story in update mode, auto-merge newer into older."""
    cfg, store = context
    orig = _publish(store, item(
        url="https://gitlab.torproject.org/tpo/core/tor/-/issues/49001", kind="gitlab_issue", product="tor",
        title="Directory authority overload on 0.4.9.99",
        content="Issue #49001 tracks directory authority overload in Tor 0.4.9.99.",
    ), draft=analysis(
        title="Directory authority overload reported in Tor 0.4.9.99",
        summary="Issue #49001 tracks directory authority overload in Tor 0.4.9.99.",
        products=["tor"], why_it_matters="",
        evidence=["Issue #49001 tracks directory authority overload in Tor 0.4.9.99"],
    ), observed=EARLY)
    newer_dup = _publish(store, item(
        url="https://lists.torproject.org/archives/list/tor-relays@lists.torproject.org/message/DUP49001/", product="tor",
        title="[tor-relays] Directory authority overload in Tor 0.4.9.99",
        content="Mailing list report on issue #49001 directory authority overload in Tor 0.4.9.99.",
    ), draft=analysis(
        title="Mailing list report on Tor 0.4.9.99 authority overload",
        summary="Operators discussed issue #49001 directory authority overload in Tor 0.4.9.99.",
        products=["tor"], why_it_matters="",
        evidence=["issue #49001 directory authority overload in Tor 0.4.9.99"],
    ), observed=MID)
    unrelated = _publish(store, item(
        url="https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/9901", kind="gitlab_mr",
        upstream_state="merged", product="arti", title="Refactor Arti channel padding timer",
        content="Merged refactor for Arti channel padding timer.",
    ), draft=analysis(
        title="Arti channel padding timer refactored", summary="Merged refactor for Arti channel padding timer.",
        state="merged", confidence="confirmed", products=["arti"], why_it_matters="",
        evidence=["Merged refactor for Arti channel padding timer"],
    ), observed=MID)
    cli.build(cfg, store)

    def note(cid: str, at: str, body: str) -> dict:
        return {"id": cid, "author": "maint", "title": "Comment by maint", "created_at": at,
                "url": f"https://gitlab.torproject.org/tpo/core/tor/-/issues/49001#note_{cid}", "body": body}

    c1 = note("101", LATER, "Maintainers narrowed the overload trigger to extra-info fetches.")
    followup_1 = item(
        url="https://gitlab.torproject.org/tpo/core/tor/-/issues/49001", kind="gitlab_issue", product="tor",
        title="Directory authority overload on 0.4.9.99",
        content="Issue #49001 tracks directory authority overload in Tor 0.4.9.99.",
        updated_at=LATER, public_comments=[c1],
    )
    res_1 = run(
        cfg, store, pending(store, followup_1, LATER),
        Writer(update_analysis(update=c1["body"], evidence=[c1["body"][:-1]])),
        Reviewer(verdict("approve", update=True, same_story=newer_dup["id"]),
                 verdict("approve", update=True, same_story=None)),
        observed=LATER,
    )
    assert res_1["status"] == "published" and editorial.retired(store.db, story_id=newer_dup["id"]) is None

    c2 = note("102", "2026-11-09T11:00:00Z", "A patch is queued for review.")
    followup_2 = {**followup_1, "updated_at": c2["created_at"], "public_comments": [c1, c2]}
    res_2 = run(
        cfg, store, pending(store, followup_2, c2["created_at"]),
        Writer(update_analysis(update=c2["body"], evidence=[c2["body"][:-1]])),
        Reviewer(verdict("approve", update=True, same_story=unrelated["id"]),
                 verdict("approve", update=True, same_story=unrelated["id"])),
        observed=c2["created_at"],
    )
    assert res_2["status"] == "published" and editorial.retired(store.db, story_id=unrelated["id"]) is None

    c3 = note("103", "2026-11-09T12:00:00Z", "Fix merged for Tor 0.4.9.99 overload.")
    followup_3 = {**followup_2, "updated_at": c3["created_at"], "public_comments": [c1, c2, c3]}
    res_3 = run(
        cfg, store, pending(store, followup_3, c3["created_at"]),
        Writer(update_analysis(update=c3["body"], evidence=[c3["body"][:-1]])),
        Reviewer(verdict("approve", update=True, same_story=newer_dup["id"]),
                 verdict("approve", update=True, same_story=newer_dup["id"])),
        observed=c3["created_at"],
    )
    assert res_3["status"] == "published"
    assert editorial.retired(store.db, story_id=newer_dup["id"]) == (newer_dup["id"], orig["id"])
    auto_log = store.db.execute("SELECT code,subject,story_id FROM decision_log WHERE code='merged.auto.same_event'").fetchone()
    assert tuple(auto_log) == ("merged.auto.same_event", newer_dup["id"], orig["id"])
    summary = decisions.summary(store.db, EARLY)
    assert summary["codes"]["merged.auto.same_event"] == 1 and summary["outcomes"]["merged"] == 1
    assert None not in summary["sources"]
    assert json.loads(json.dumps(summary, sort_keys=True))["outcomes"]["merged"] == 1
    assert "operator.merged" not in summary["codes"]


def test_auto_merge_blocks_lossy_merges(context):
    cfg, store = context
    surv = _publish(store, item(
        url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/501", kind="gitlab_issue",
        title="Relay descriptor parsing issue #501",
        content="Initial report of relay descriptor parsing issue with supporting details.",
    ), draft=analysis(
        title="Relay descriptor parsing issue #501", summary="Initial report of relay descriptor parsing issue.",
        confidence="reported", state="developing", evidence=["Initial report of relay descriptor parsing issue."],
    ), observed=EARLY)
    dup = _publish(store, item(
        url="https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/502", kind="gitlab_mr",
        title="Fix relay descriptor parsing issue #501",
        content="Maintainers merged a fix for #501 with supporting details.", authority="official",
    ), draft=analysis(
        title="Fix relay descriptor parsing issue #501", summary="Maintainers merged a fix for #501.",
        confidence="confirmed", state="merged", evidence=["Maintainers merged a fix for #501."],
    ), observed=MID)
    publication.build(cfg, store)
    assert review_gate._auto_merge_pair(store, surv["id"], dup["id"]) is None


@pytest.mark.parametrize("retire_target", ["duplicate", "survivor"])
def test_concurrent_auto_merge_race_aborts_safely(context, retire_target):
    cfg, store = context
    surv = _publish(store, item(
        url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/810", kind="gitlab_issue",
        title="Relay onion-service circuit issue #810",
        content="Operators reported onion-service circuit issue #810 with upstream details.",
    ), draft=analysis(
        title="Relay onion-service circuit issue #810",
        summary="Operators reported onion-service circuit issue #810.",
        category="network", confidence="reported", state="developing",
        evidence=["Operators reported onion-service circuit issue #810."],
    ), observed=EARLY)
    dup = _publish(store, item(
        url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/811", kind="gitlab_issue",
        title="Duplicate report of issue #810",
        content="Follow-up report referencing https://gitlab.torproject.org/tpo/core/tor/-/work_items/810 with details.",
    ), draft=analysis(
        title="Duplicate report of issue #810", summary="Follow-up report referencing #810.",
        category="network", confidence="reported", state="developing",
        evidence=["Follow-up report referencing"],
    ), observed=MID)
    publication.build(cfg, store)
    assert review_gate._auto_merge_pair(store, surv["id"], dup["id"]) == (dup["id"], surv["id"])

    if retire_target == "duplicate":
        row = pending(store, item(
            url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/811", kind="gitlab_issue",
            title="Duplicate report of issue #810",
            content="Follow-up report referencing https://gitlab.torproject.org/tpo/core/tor/-/work_items/810 with new details.",
            published_at=MID, updated_at=LATER,
        ), LATER)
        draft = update_analysis(update="Follow-up report referencing work_items/810 with new details.",
                                evidence=["Follow-up report referencing"])
        same_target = surv["id"]
        prepared_dup = store.prepare_candidate(row, draft, LATER)
        editorial.correct(store.db, surv["id"], {"why_it_matters": "Operator-pinned context."},
                          reason="Lock survivor before merge guard", expect_hash=editorial.show(store.db, surv["id"])["hash"],
                          observed=MID)
        with pytest.raises(candidate.StaleCandidate):
            review_gate._try_auto_merge(
                cfg, store, (dup["id"], surv["id"]), propagate=True, prepared=prepared_dup,
                draft=draft, writer_key="wk", record={}, observed=LATER,
            )
        assert editorial.retired(store.db, story_id=dup["id"]) is None
        editorial.unlock(store.db, surv["id"], reason="Restore auto-merge eligibility",
                         expect_hash=editorial.show(store.db, surv["id"])["hash"], observed=MID)

        def race_on_verify(*_a, **_kw):
            with store.db:
                store.db.execute("UPDATE items SET content_hash='newer-hash', status='rejected' WHERE id=?", (row["id"],))
                store.db.execute(
                    """INSERT OR REPLACE INTO review_jobs
                       (item_id,writer_key,policy_hash,stage,record_json,approval_key,prepared_at,updated_at)
                       VALUES(?,?,?,?,?,?,?,?)""",
                    (row["id"], "newer-wk", "ph", "held", '{"held":true}', "held-ak", LATER, LATER),
                )
            return verdict("approve", update=True, same_story=same_target)
    else:
        row = pending(store, item(
            url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/810", kind="gitlab_issue",
            title="Relay onion-service circuit issue #810",
            content="Operators reported onion-service circuit issue #810 with a follow-up reproduction.",
            published_at=EARLY, updated_at=LATER,
        ), LATER)
        draft = update_analysis(update="Operators reported onion-service circuit issue with a follow-up reproduction.",
                                evidence=["with a follow-up reproduction"])
        same_target = dup["id"]

        def race_on_verify(*_a, **_kw):
            dup_raw = json.loads(store.db.execute("SELECT payload FROM stories WHERE id=?", (dup["id"],)).fetchone()[0])
            dup_raw["updates"] = [{"at": LATER, "text": "Concurrent dated update on the duplicate story.",
                                   "sources": dup_raw["sources"]}]
            with store.db:
                store.db.execute("UPDATE stories SET payload=?, updated_at=? WHERE id=?",
                                 (json.dumps(dup_raw), LATER, dup["id"]))
            return verdict("approve", update=True, same_story=same_target)

    out = run(cfg, store, row, Writer(draft), Reviewer(verdict("approve", update=True, same_story=same_target), race_on_verify),
              observed=LATER)
    assert editorial.retired(store.db, story_id=dup["id"]) is None
    if retire_target == "duplicate":
        assert out["status"] == "stale"
        kept_job = store.db.execute("SELECT writer_key, stage FROM review_jobs WHERE item_id=?", (row["id"],)).fetchone()
        assert tuple(kept_job) == ("newer-wk", "held")
    else:
        assert out["status"] == "published"


@pytest.mark.parametrize("fail_handoff", [False, True])
def test_auto_merge_when_update_arrives_on_newer_duplicate_requeues_onto_original(context, monkeypatch, fail_handoff):
    """When the incoming update is attached to the newer duplicate, merge newer -> older and re-queue the item onto older."""
    cfg, store = context
    older = _publish(store, item(
        url="https://gitlab.torproject.org/tpo/core/tor/-/issues/49100", kind="gitlab_issue", product="tor",
        title="Relay consensus stall in Tor 0.4.9.88",
        content="Issue #49100 reports relay consensus stall in Tor 0.4.9.88.",
    ), draft=analysis(
        title="Relay consensus stall reported in Tor 0.4.9.88",
        summary="Issue #49100 reports relay consensus stall in Tor 0.4.9.88.",
        products=["tor"], why_it_matters="", evidence=["Issue #49100 reports relay consensus stall in Tor 0.4.9.88"],
    ), observed=EARLY)
    newer = _publish(store, item(
        url="https://gitlab.torproject.org/tpo/core/tor/-/issues/49101", kind="gitlab_issue", product="tor",
        title="Duplicate report for Tor 0.4.9.88 consensus stall",
        content="Follow-on report referencing #49100 on Tor 0.4.9.88 consensus stall.",
    ), draft=analysis(
        title="Follow-on report on Tor 0.4.9.88 consensus stall",
        summary="Follow-on report referencing #49100 on Tor 0.4.9.88 consensus stall.",
        products=["tor"], why_it_matters="", evidence=["Follow-on report referencing #49100 on Tor 0.4.9.88 consensus stall"],
    ), observed=MID)
    cli.build(cfg, store)

    upd = item(
        url="https://gitlab.torproject.org/tpo/core/tor/-/issues/49101", kind="gitlab_issue", product="tor",
        title="Duplicate report for Tor 0.4.9.88 consensus stall",
        content="Follow-on report referencing #49100 on Tor 0.4.9.88 consensus stall.", updated_at=LATER,
        public_comments=[{
            "id": "201", "author": "dev", "title": "Comment by dev", "created_at": LATER,
            "url": "https://gitlab.torproject.org/tpo/core/tor/-/issues/49101#note_201",
            "body": "Confirmed the stall only occurs when DirCache is disabled.",
        }],
    )
    row_upd = pending(store, upd, LATER)
    skip_same = verdict("skip", criterion="new_information", update=True, same_story=older["id"])
    skip_same["criteria"]["new_information"]["reason"] = f"Same event as {older['id']}."
    draft_upd = update_analysis(update="The stall only occurs when DirCache is disabled.",
                                evidence=["Confirmed the stall only occurs when DirCache is disabled"])
    writer, checker = Writer(draft_upd), Reviewer(skip_same, skip_same)
    if fail_handoff:
        def cannot_save_handoff(*_args):
            raise sqlite3.OperationalError("Review handoff could not be persisted")

        monkeypatch.setattr(review_gate, "_save_handoff", cannot_save_handoff)
        before_stories = list(store.db.execute("SELECT id,payload FROM stories ORDER BY id"))
        before_analyses = store.db.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
        with pytest.raises(sqlite3.OperationalError, match="handoff"):
            run(cfg, store, row_upd, writer, checker, observed=LATER)
        # The merge and association must roll back together if the durable
        # budget cannot be handed to the survivor. Physical calls stay spent.
        assert list(store.db.execute("SELECT id,payload FROM stories ORDER BY id")) == before_stories
        assert editorial.retired(store.db, story_id=newer["id"]) is None
        unchanged = store.db.execute("SELECT status,story_id FROM items WHERE id=?", (row_upd["id"],)).fetchone()
        assert tuple(unchanged) == ("pending", newer["id"])
        assert store.db.execute("SELECT COUNT(*) FROM analyses").fetchone()[0] == before_analyses
        saved = store.db.execute("SELECT stage,record_json FROM review_jobs WHERE item_id=?", (row_upd["id"],)).fetchone()
        assert saved["stage"] == "verify"
        assert json.loads(saved["record_json"])["request_budget"]["reserved"] == len(checker.calls) == 2
        return
    res_routed = run(cfg, store, row_upd, writer, checker, observed=LATER)
    assert res_routed["status"] == "routed" and res_routed["review_calls"] == 2
    saved = store.db.execute("SELECT stage,record_json FROM review_jobs WHERE item_id=?", (row_upd["id"],)).fetchone()
    assert saved["stage"] == "routed" and json.loads(saved["record_json"])["request_budget"]["reserved"] == 2
    assert editorial.retired(store.db, story_id=newer["id"]) == (newer["id"], older["id"])
    requeued = store.pending(1, LATER)[0]
    assert requeued["id"] == row_upd["id"] and requeued["story_id"] == older["id"]

    res_final = run(cfg, store, requeued, Writer(draft_upd),
                    Reviewer(verdict("approve", update=True), verdict("approve", update=True)), observed=LATER)
    assert res_final["status"] == "published"
    audit = json.loads(store.db.execute("SELECT review_record FROM analyses WHERE source_item_id=? ORDER BY rowid DESC", (row_upd["id"],)).fetchone()[0])
    assert audit["request_budget"]["reserved"] == 4
    older_payload = json.loads(store.db.execute("SELECT payload FROM stories WHERE id=?", (older["id"],)).fetchone()[0])
    assert older_payload["updates"][-1]["text"] == "The stall only occurs when DirCache is disabled."


def test_merge_transfers_or_requeues_story_locked_held_updates(context):
    cfg, store = context
    surv_a = _publish(store, item(
        url="https://example.org/surv-a", title="Primary guard selection report",
        content="Primary report covering guard selection anomaly in Tor 0.4.9.90.",
    ), observed=EARLY)
    dup_a_item = item(
        url="https://example.org/dup-a", title="Secondary guard selection report",
        content="Secondary report covering guard selection anomaly in Tor 0.4.9.90.", updated_at=EARLY,
    )
    dup_a = _publish(store, dup_a_item, observed=EARLY)
    cli.build(cfg, store)
    row_held_a = pending(store, {**dup_a_item, "content": dup_a_item["content"] + " Follow-up confirmation.", "updated_at": LATER}, LATER)
    with pytest.raises(AnalysisError):
        run(cfg, store, row_held_a, Writer(update_analysis(update="Follow-up confirmation.", evidence=["Follow-up confirmation."])),
            Reviewer(AnalysisError("timeout", retryable=True)), observed=LATER)
    assert store.db.execute("SELECT 1 FROM review_jobs WHERE item_id=?", (row_held_a["id"],)).fetchone() is not None
    editorial.correct(store.db, dup_a["id"], {"why_it_matters": "Operator-pinned context."},
                      reason="Pin context", expect_hash=editorial.show(store.db, dup_a["id"])["hash"], observed=MID)
    assert run(cfg, store, row_held_a, Writer(), Reviewer(), observed=LATER)["status"] == "locked"
    assert editorial.show(store.db, dup_a["id"])["held_updates"] == 1

    editorial.merge(store.db, dup_a["id"], surv_a["id"], reason="Consolidate duplicate report",
                    expect_hash=editorial.show(store.db, dup_a["id"])["hash"], observed=LATER)
    assert tuple(store.db.execute("SELECT status,story_id FROM items WHERE id=?", (row_held_a["id"],)).fetchone()) == ("pending", surv_a["id"])
    held_job = store.db.execute("SELECT stage,record_json FROM review_jobs WHERE item_id=?", (row_held_a["id"],)).fetchone()
    held_proof = json.loads(held_job["record_json"])
    assert held_job["stage"] == "locked" and held_proof["request_budget"]["reserved"] == 1
    assert held_proof["reviews"] == [] and not held_proof.get("approval")

    surv_b = _publish(store, item(
        url="https://example.org/surv-b", title="Primary bridge reachability report",
        content="Primary report covering bridge reachability issue in Tor 0.4.9.91.",
    ), observed=EARLY)
    dup_b_item = item(
        url="https://example.org/dup-b", title="Secondary bridge reachability report",
        content="Secondary report covering bridge reachability issue in Tor 0.4.9.91.", updated_at=EARLY,
    )
    dup_b = _publish(store, dup_b_item, observed=EARLY)
    cli.build(cfg, store)
    for sid, note in ((surv_b["id"], "Survivor operator note."), (dup_b["id"], "Duplicate operator note.")):
        editorial.correct(store.db, sid, {"why_it_matters": note}, reason="Lock story",
                          expect_hash=editorial.show(store.db, sid)["hash"], observed=MID)
    row_held_b = pending(store, {**dup_b_item, "content": dup_b_item["content"] + " Additional bridge telemetry.", "updated_at": LATER}, LATER)
    assert run(cfg, store, row_held_b, Writer(), Reviewer(), observed=LATER)["status"] == "locked"

    editorial.merge(store.db, dup_b["id"], surv_b["id"], reason="Consolidate into locked survivor",
                    expect_hash=editorial.show(store.db, dup_b["id"])["hash"], observed=LATER)
    surv_b_shown = editorial.show(store.db, surv_b["id"])
    assert surv_b_shown["held_updates"] == 1
    unlocked = editorial.unlock(store.db, surv_b["id"], reason="Resume automated updates",
                                expect_hash=surv_b_shown["hash"], observed="2026-11-09T12:00:00Z")
    assert unlocked["locked"] is False
    assert tuple(store.db.execute("SELECT status,story_id FROM items WHERE id=?", (row_held_b["id"],)).fetchone()) == ("pending", surv_b["id"])


def test_gitlab_refs_are_project_qualified_in_auto_merge_and_routing(context):
    cfg, store = context
    tor_story = _publish(store, item(
        kind="gitlab_mr", product="tor", url="https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/123",
        title="Backport circuit padding cleanup", content="Backport !123 cleanup for C Tor relays.",
    ), draft=analysis(
        title="C Tor backports circuit padding cleanup in !123", summary="Merge request !123 cleans up circuit padding timers.",
        products=["tor"], evidence=["Backport !123 cleanup for C Tor relays."],
    ), observed=EARLY)
    arti_story = _publish(store, item(
        kind="gitlab_mr", product="arti", url="https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/123",
        title="Refactor channel handshake state", content="Refactor !123 channel handshake state in Arti.",
    ), draft=analysis(
        title="Arti refactors channel handshake state in !123", summary="Merge request !123 refactors channel handshake state.",
        products=["arti"], evidence=["Refactor !123 channel handshake state in Arti."],
    ), observed=MID)
    cli.build(cfg, store)
    assert review_gate._auto_merge_pair(store, tor_story["id"], arti_story["id"]) is None

    same_issue = _publish(store, item(
        kind="gitlab_issue", product="tor", url="https://gitlab.torproject.org/tpo/core/tor/-/issues/49200",
        title="Guard sample persistence glitch", content="Guard sample file fails atomic rename under load.",
    ), draft=analysis(
        title="Guard sample persistence glitch under load", summary="Guard sample file fails atomic rename under load.",
        products=["tor"], evidence=["Guard sample file fails atomic rename under load."],
    ), observed=EARLY)
    same_mr = _publish(store, item(
        kind="gitlab_mr", product="tor", url="https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/1090",
        title="Fix atomic rename for #49200", content="Fixes #49200 atomic rename handling.",
    ), draft=analysis(
        title="Merge request fixes #49200 guard persistence", summary="Fixes #49200 atomic rename handling.",
        products=["tor"], evidence=["Fixes #49200 atomic rename handling."],
    ), observed=MID)
    cli.build(cfg, store)
    assert review_gate._auto_merge_pair(store, same_issue["id"], same_mr["id"]) == (same_mr["id"], same_issue["id"])
