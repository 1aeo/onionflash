"""Duplicate pointer merges, retired story aliases, rollback safety, and auto-merge."""

import copy
import json
from pathlib import Path
import sqlite3

import pytest

from helpers import (
    DATE, DOCTOR_OK_LINE, FakeLinker, Reviewer, Writer, analysis, bastet_incident_items, decision_codes,
    doctor_report_item, editorial_act, gitlab_source, insert_approval, invoke_cli, item, item_row, job,
    job_record, make_doctor_config, make_note, pending, raise_once, run_gate as run, saved_audit,
    seed_source_story as _publish, seed_story, story_payload, update_analysis, verdict, write_toml,
)
from onionflash import candidate, cli, decisions, doctor, editorial, publication, rejection, review_gate
from onionflash.analyze import AnalysisError
from onionflash.store import Store, set_meta
from onionflash.util import after, digest, item_cluster

EARLY = "2026-11-08T10:00:00Z"
MID = "2026-11-08T14:00:00Z"
LATER = "2026-11-09T10:00:00Z"
SKIPPED = "skipped.gate.retired_story"
LONG_BODY = (
    "A detailed public report describing circuit padding behavior across multiple hops "
    "with reproducible measurements from a local test network and exact packet counts "
    "recorded over several minutes of testing."
)


def _add_alias(db, story_id: str, cluster_key: str, survivor_id: str | None = None, *, story_json: str | None = None):
    with db:
        db.execute("INSERT INTO story_aliases(story_id,cluster_key,survivor_id,reason,created_at,story_json) VALUES(?,?,?,?,?,?)",
                   (story_id, cluster_key, survivor_id, "Retired fixture", DATE, story_json))


def _seed_consensus_stall_pair(cfg, store, comment_body="Confirmed the stall only occurs when DirCache is disabled."):
    older = _publish(store, item(
        url="https://gitlab.torproject.org/tpo/core/tor/-/issues/49100", kind="gitlab_issue", product="tor",
        title="Relay consensus stall in Tor 0.4.9.88",
        content="Issue #49100 reports relay consensus stall in Tor 0.4.9.88.",
    ), draft=analysis(
        title="Relay consensus stall reported in Tor 0.4.9.88",
        summary="Issue #49100 reports relay consensus stall in Tor 0.4.9.88.",
        products=["tor"], why_it_matters="", evidence=["Issue #49100 reports relay consensus stall in Tor 0.4.9.88"],
    ), at=EARLY)
    newer = _publish(store, item(
        url="https://gitlab.torproject.org/tpo/core/tor/-/issues/49101", kind="gitlab_issue", product="tor",
        title="Duplicate report for Tor 0.4.9.88 consensus stall",
        content="Follow-on report referencing #49100 on Tor 0.4.9.88 consensus stall.",
    ), draft=analysis(
        title="Follow-on report on Tor 0.4.9.88 consensus stall",
        summary="Follow-on report referencing #49100 on Tor 0.4.9.88 consensus stall.",
        products=["tor"], why_it_matters="", evidence=["Follow-on report referencing #49100 on Tor 0.4.9.88 consensus stall"],
    ), at=MID)
    cli.build(cfg, store)

    upd = item(
        url="https://gitlab.torproject.org/tpo/core/tor/-/issues/49101", kind="gitlab_issue", product="tor",
        title="Duplicate report for Tor 0.4.9.88 consensus stall",
        content="Follow-on report referencing #49100 on Tor 0.4.9.88 consensus stall.", updated_at=LATER,
        public_comments=[make_note("201", comment_body, author="dev", created_at=LATER,
                                   url="https://gitlab.torproject.org/tpo/core/tor/-/issues/49101",
                                   note_id="201", title="Comment by dev")],
    )
    row_upd = pending(store, upd, at=LATER, ready=LATER)
    skip_same = verdict("skip", criterion="new_information", update=True, same_story=older["id"],
                        reason=f"Same event as {older['id']}.")
    return older, newer, row_upd, skip_same


def test_tombstoned_and_uncataloged_aliases_never_call_models_or_render_pointers(context):
    """Ignore tombstoned aliases with zero model calls and skip rendering uncataloged pointers."""
    cfg, store = context
    survivor = _publish(store, item(
        url="https://example.org/survivor-release", title="Tor Browser 99.0 released",
        content="Tor Browser 99.0 is released with synthetic transport updates.",
    ), at=EARLY)
    cli.build(cfg, store)

    dup_item = item(kind="feed", url="https://example.org/uncataloged-dup", title="Follow-up note on Tor Browser 99.0",
                    content="Follow-up note confirming Linux builds of Tor Browser 99.0 completed.")
    tomb_item = item(kind="feed", url="https://example.org/historical-tombstone", title="Retired synthetic notice",
                     content="Retired synthetic notice body text that must never hit a model.")
    dup_ck, tomb_ck = item_cluster(dup_item), item_cluster(tomb_item)
    dup_id, tomb_id = digest(dup_ck)[:24], digest(tomb_ck)[:24]
    _add_alias(store.db, dup_id, dup_ck, survivor["id"])
    _add_alias(store.db, tomb_id, tomb_ck)
    with store.db:
        store.db.execute("INSERT INTO public_render_queue(story_id) VALUES(?)", (dup_id,))

    cli.build(cfg, store)
    out_root = Path(cfg["storage"]["output_dir"])
    assert not (out_root / "news" / dup_id).exists() and not (out_root / "news" / tomb_id).exists()

    tomb_row = pending(store, tomb_item, at=LATER, ready=LATER)
    res = run(cfg, store, tomb_row, Writer(), Reviewer())
    assert (res["status"], res["writer_calls"], res["review_calls"]) == ("ignored", 0, 0)
    rejection.retry_item(store, tomb_row["id"], tomb_row["content_hash"], "Operator check")
    res2 = run(cfg, store, store.pending(1, LATER)[0], Writer(), Reviewer())
    assert (res2["status"], res2["writer_calls"], res2["review_calls"]) == ("ignored", 0, 0)

    dup_row = pending(store, dup_item, at=LATER, ready=LATER)
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
    """Render canonical redirect pointers, remap items, follow merge chains, and scrub private reasons."""
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
    ), at=EARLY)
    s_two = _publish(store, item(
        url="https://example.org/event-surv", title="Canonical Survivor Title Beta",
        content=" synthetic-overload-beta fuller report on directory authority load.",
    ), draft=analysis(
        title="Canonical Survivor Title Beta", summary="Fuller report on directory authority load.",
        category="directory-authority", tags=["directory-authority"], why_it_matters="",
        evidence=["synthetic-overload-beta fuller report on directory authority load"],
    ), at=MID)
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
    ), at=LATER)
    cli.build(cfg, store)
    editorial_act(editorial.merge, store, s_two["id"], s_three["id"],
                  reason="Chained into Gamma.", base_url=cfg["site"]["base_url"], observed=LATER)
    assert editorial.retired(store.db, story_id=s_one["id"]) == (s_one["id"], s_three["id"])
    cli.build(cfg, store)
    final_url = f'{cfg["site"]["base_url"].rstrip("/")}/news/{s_three["id"]}/'
    assert json.loads((root / "news" / s_one["id"] / "story.json").read_text(encoding="utf-8"))["merged_into"] == s_three["id"]
    assert json.loads((root / "news" / s_two["id"] / "story.json").read_text(encoding="utf-8"))["merged_into"] == s_three["id"]
    assert final_url in (root / "news" / s_one["id"] / "index.html").read_text(encoding="utf-8")

    rebuilt = cli.build(cfg, store, force=True)
    assert (rebuilt["published_stories"], rebuilt["stories_skipped"]) == (1, 0)


def test_null_tombstone_story_alias_removes_story_and_handles_chained_merges(context):
    """Omit stories chained into a null tombstone alias from public views and topic tables."""
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

    editorial_act(editorial.merge, store, s1, s2, reason="Consolidate duplicate reports.", observed=LATER)
    s2_row = store.db.execute("SELECT cluster_key, payload FROM stories WHERE id=?", (s2,)).fetchone()
    _add_alias(store.db, s2, s2_row["cluster_key"], story_json=s2_row["payload"])
    with store.db:
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
    """Keep merged pointer files intact and excluded from views under an older release template."""
    cfg, store = context
    dup = _publish(store, item(url="https://example.org/rb-dup", title="Rollback Duplicate Story",
                               content="Rollback duplicate body text with enough literal evidence."), at=EARLY)
    surv = _publish(store, item(url="https://example.org/rb-surv", title="Rollback Survivor Story",
                                content="Rollback survivor body text with enough literal evidence."), at=MID)
    cli.build(cfg, store)
    editorial_act(editorial.merge, store, dup["id"], surv["id"],
                  reason="Merged before simulated rollback", base_url=cfg["site"]["base_url"], observed=LATER)
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


def test_merge_refusals_and_cli_end_to_end(context, tmp_path, capsys):
    """Refuse self, unknown, stale-hash, unbuilt, quarantined, or retracted merges and execute CLI merges."""
    cfg, store = context
    cfg_path = write_toml(tmp_path, '[[sources]]\nid="example"\nurl="https://example.org/feed.xml"\nenabled=false',
                          with_source=False)
    pub_a = _publish(store, item(url="https://example.org/ref-a", title="Published Story A",
                                 content="Published story A content with literal support."), at=EARLY)
    pub_b = _publish(store, item(url="https://example.org/ref-b", title="Published Story B",
                                 content="Published story B content with literal support."), at=MID)
    cli.build(cfg, store)
    unbuilt = _publish(store, item(url="https://example.org/ref-unbuilt", title="Unbuilt Story C",
                                   content="Unbuilt story C content not yet rendered into public_catalog."), at=LATER)
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

    editorial_act(editorial.retract, store, pub_b["id"], reason="Withdrawn.", observed=LATER)
    with pytest.raises(ValueError, match="retracted"):
        editorial.merge(store.db, pub_a["id"], pub_b["id"], expect_hash=hash_a, reason="r")
    editorial_act(editorial.restore, store, pub_b["id"], 0, reason="Restored.", observed=LATER)
    cli.build(cfg, store)

    with cli.run_lock(cfg["storage"]["database"]):
        busy = invoke_cli(capsys, "story", "merge", "--config", cfg_path, "--story", pub_a["id"],
                          "--into", pub_b["id"], "--expect-hash", hash_a, "--reason", "locked check", expected=75)
    assert busy == {"status": "already-running"}

    out = invoke_cli(capsys, "story", "merge", "--config", cfg_path, "--story", pub_a["id"],
                     "--into", pub_b["id"], "--expect-hash", hash_a, "--reason", "CLI merge check")
    assert (out["story_id"], out["merged_into"], out["publication_pending"]) == (pub_a["id"], pub_b["id"], True)


def test_automatic_published_duplicate_merge_and_safety_guards(context):
    """Auto-merge newer duplicates into older stories only when both review passes agree on `same_story`."""
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
    ), at=EARLY)
    newer_dup = _publish(store, item(
        url="https://lists.torproject.org/archives/list/tor-relays@lists.torproject.org/message/DUP49001/", product="tor",
        title="[tor-relays] Directory authority overload in Tor 0.4.9.99",
        content="Mailing list report on issue #49001 directory authority overload in Tor 0.4.9.99.",
    ), draft=analysis(
        title="Mailing list report on Tor 0.4.9.99 authority overload",
        summary="Operators discussed issue #49001 directory authority overload in Tor 0.4.9.99.",
        products=["tor"], why_it_matters="",
        evidence=["issue #49001 directory authority overload in Tor 0.4.9.99"],
    ), at=MID)
    unrelated = _publish(store, item(
        url="https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/9901", kind="gitlab_mr",
        upstream_state="merged", product="arti", title="Refactor Arti channel padding timer",
        content="Merged refactor for Arti channel padding timer.",
    ), draft=analysis(
        title="Arti channel padding timer refactored", summary="Merged refactor for Arti channel padding timer.",
        state="merged", confidence="confirmed", products=["arti"], why_it_matters="",
        evidence=["Merged refactor for Arti channel padding timer"],
    ), at=MID)
    cli.build(cfg, store)

    issue_url = "https://gitlab.torproject.org/tpo/core/tor/-/issues/49001"
    c1 = make_note("101", "Maintainers narrowed the overload trigger to extra-info fetches.",
                   author="maint", created_at=LATER, url=issue_url, note_id="101", title="Comment by maint")
    followup_1 = item(
        url=issue_url, kind="gitlab_issue", product="tor",
        title="Directory authority overload on 0.4.9.99",
        content="Issue #49001 tracks directory authority overload in Tor 0.4.9.99.",
        updated_at=LATER, public_comments=[c1],
    )
    res_1 = run(
        cfg, store, pending(store, followup_1, at=LATER, ready=LATER),
        Writer(update_analysis(update=c1["body"], evidence=[c1["body"][:-1]])),
        Reviewer(verdict("approve", update=True, same_story=newer_dup["id"]),
                 verdict("approve", update=True, same_story=None)),
        observed=LATER,
    )
    assert res_1["status"] == "published" and editorial.retired(store.db, story_id=newer_dup["id"]) is None

    c2 = make_note("102", "A patch is queued for review.", author="maint", created_at="2026-11-09T11:00:00Z",
                   url=issue_url, note_id="102", title="Comment by maint")
    followup_2 = {**followup_1, "updated_at": c2["created_at"], "public_comments": [c1, c2]}
    res_2 = run(
        cfg, store, pending(store, followup_2, at=c2["created_at"], ready=c2["created_at"]),
        Writer(update_analysis(update=c2["body"], evidence=[c2["body"][:-1]])),
        Reviewer(verdict("approve", update=True, same_story=unrelated["id"]),
                 verdict("approve", update=True, same_story=unrelated["id"])),
        observed=c2["created_at"],
    )
    assert res_2["status"] == "published" and editorial.retired(store.db, story_id=unrelated["id"]) is None

    c3 = make_note("103", "Fix merged for Tor 0.4.9.99 overload.", author="maint", created_at="2026-11-09T12:00:00Z",
                   url=issue_url, note_id="103", title="Comment by maint")
    followup_3 = {**followup_2, "updated_at": c3["created_at"], "public_comments": [c1, c2, c3]}
    res_3 = run(
        cfg, store, pending(store, followup_3, at=c3["created_at"], ready=c3["created_at"]),
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
    """Refuse auto-merging when the duplicate holds higher confidence or merge state than the survivor."""
    cfg, store = context
    surv = _publish(store, item(
        url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/501", kind="gitlab_issue",
        title="Relay descriptor parsing issue #501",
        content="Initial report of relay descriptor parsing issue with supporting details.",
    ), draft=analysis(
        title="Relay descriptor parsing issue #501", summary="Initial report of relay descriptor parsing issue.",
        confidence="reported", state="developing", evidence=["Initial report of relay descriptor parsing issue."],
    ), at=EARLY)
    dup = _publish(store, item(
        url="https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/502", kind="gitlab_mr",
        title="Fix relay descriptor parsing issue #501",
        content="Maintainers merged a fix for #501 with supporting details.", authority="official",
    ), draft=analysis(
        title="Fix relay descriptor parsing issue #501", summary="Maintainers merged a fix for #501.",
        confidence="confirmed", state="merged", evidence=["Maintainers merged a fix for #501."],
    ), at=MID)
    publication.build(cfg, store)
    assert review_gate._auto_merge_pair(store, surv["id"], dup["id"]) is None


@pytest.mark.parametrize("retire_target", ["duplicate", "survivor"])
def test_concurrent_auto_merge_race_aborts_safely(context, retire_target):
    """Abort auto-merge cleanly if either story locks or updates concurrently during verification."""
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
    ), at=EARLY)
    dup = _publish(store, item(
        url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/811", kind="gitlab_issue",
        title="Duplicate report of issue #810",
        content="Follow-up report referencing https://gitlab.torproject.org/tpo/core/tor/-/work_items/810 with details.",
    ), draft=analysis(
        title="Duplicate report of issue #810", summary="Follow-up report referencing #810.",
        category="network", confidence="reported", state="developing",
        evidence=["Follow-up report referencing"],
    ), at=MID)
    publication.build(cfg, store)
    assert review_gate._auto_merge_pair(store, surv["id"], dup["id"]) == (dup["id"], surv["id"])

    if retire_target == "duplicate":
        row = pending(store, item(
            url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/811", kind="gitlab_issue",
            title="Duplicate report of issue #810",
            content="Follow-up report referencing https://gitlab.torproject.org/tpo/core/tor/-/work_items/810 with new details.",
            published_at=MID, updated_at=LATER,
        ), at=LATER, ready=LATER)
        draft = update_analysis(update="Follow-up report referencing work_items/810 with new details.",
                                evidence=["Follow-up report referencing"])
        same_target = surv["id"]
        prepared_dup = store.prepare_candidate(row, draft, LATER)
        editorial_act(editorial.correct, store, surv["id"], {"why_it_matters": "Operator-pinned context."},
                      reason="Lock survivor before merge guard", observed=MID)
        with pytest.raises(candidate.StaleCandidate):
            review_gate._try_auto_merge(
                cfg, store, (dup["id"], surv["id"]), propagate=True, prepared=prepared_dup,
                draft=draft, writer_key="wk", record={}, observed=LATER,
            )
        assert editorial.retired(store.db, story_id=dup["id"]) is None
        editorial_act(editorial.unlock, store, surv["id"], reason="Restore auto-merge eligibility", observed=MID)

        def _race_on_verify(*_a, **_kw):
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
        ), at=LATER, ready=LATER)
        draft = update_analysis(update="Operators reported onion-service circuit issue with a follow-up reproduction.",
                                evidence=["with a follow-up reproduction"])
        same_target = dup["id"]

        def _race_on_verify(*_a, **_kw):
            dup_raw = story_payload(store, dup["id"])
            dup_raw["updates"] = [{"at": LATER, "text": "Concurrent dated update on the duplicate story.",
                                   "sources": dup_raw["sources"]}]
            with store.db:
                store.db.execute("UPDATE stories SET payload=?, updated_at=? WHERE id=?",
                                 (json.dumps(dup_raw), LATER, dup["id"]))
            return verdict("approve", update=True, same_story=same_target)

    out = run(cfg, store, row, Writer(draft), Reviewer(verdict("approve", update=True, same_story=same_target), _race_on_verify),
              observed=LATER)
    assert editorial.retired(store.db, story_id=dup["id"]) is None
    if retire_target == "duplicate":
        assert out["status"] == "stale"
        kept_job = job(store, row["id"])
        assert (kept_job["writer_key"], kept_job["stage"]) == ("newer-wk", "held")
    else:
        assert out["status"] == "published"


@pytest.mark.parametrize("fail_handoff", [False, True])
def test_auto_merge_when_update_arrives_on_newer_duplicate_requeues_onto_original(context, monkeypatch, fail_handoff):
    """Merge newer duplicate into older survivor on update skip and roll back atomically if handoff fails."""
    cfg, store = context
    older, newer, row_upd, skip_same = _seed_consensus_stall_pair(cfg, store)
    draft_upd = update_analysis(update="The stall only occurs when DirCache is disabled.",
                                evidence=["Confirmed the stall only occurs when DirCache is disabled"])
    writer, checker = Writer(draft_upd), Reviewer(skip_same, skip_same)
    if fail_handoff:
        monkeypatch.setattr(review_gate, "_save_handoff", raise_once(sqlite3.OperationalError("Review handoff could not be persisted")))
        before_stories = list(store.db.execute("SELECT id,payload FROM stories ORDER BY id"))
        before_analyses = store.db.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
        with pytest.raises(sqlite3.OperationalError, match="handoff"):
            run(cfg, store, row_upd, writer, checker, observed=LATER)
        assert list(store.db.execute("SELECT id,payload FROM stories ORDER BY id")) == before_stories
        assert editorial.retired(store.db, story_id=newer["id"]) is None
        unchanged = store.db.execute("SELECT status,story_id FROM items WHERE id=?", (row_upd["id"],)).fetchone()
        assert tuple(unchanged) == ("pending", newer["id"])
        assert store.db.execute("SELECT COUNT(*) FROM analyses").fetchone()[0] == before_analyses
        assert job(store, row_upd["id"])["stage"] == "verify"
        assert job_record(store, row_upd["id"])["request_budget"]["reserved"] == len(checker.calls) == 2
        return
    res_routed = run(cfg, store, row_upd, writer, checker, observed=LATER)
    assert res_routed["status"] == "routed" and res_routed["review_calls"] == 2
    assert job(store, row_upd["id"])["stage"] == "routed"
    assert job_record(store, row_upd["id"])["request_budget"]["reserved"] == 2
    assert editorial.retired(store.db, story_id=newer["id"]) == (newer["id"], older["id"])
    requeued = store.pending(1, LATER)[0]
    assert requeued["id"] == row_upd["id"] and requeued["story_id"] == older["id"]

    res_final = run(cfg, store, requeued, Writer(draft_upd),
                    Reviewer(verdict("approve", update=True), verdict("approve", update=True)), observed=LATER)
    assert res_final["status"] == "published"
    assert saved_audit(store, row_upd["id"])["request_budget"]["reserved"] == 4
    assert story_payload(store, older["id"])["updates"][-1]["text"] == "The stall only occurs when DirCache is disabled."


@pytest.mark.parametrize("change", ["survivor_lock", "survivor_retraction", "survivor_content", "pair_order"])
def test_newer_duplicate_merge_rechecks_pair_inside_transaction(context, monkeypatch, change):
    """Re-verify auto-merge pair eligibility inside the transaction and abort as `stale` on drift."""
    cfg, store = context
    comment_body = "The stall only occurs with caching disabled."
    older, newer, row, reply = _seed_consensus_stall_pair(cfg, store, comment_body=comment_body)
    original_merge = editorial.merge
    saved = {}

    def _changed_survivor(db, duplicate, survivor, **kwargs):
        assert kwargs["automatic"] and (duplicate, survivor) == (newer["id"], older["id"])
        assert not saved
        if change in {"survivor_lock", "survivor_retraction"}:
            with db:
                db.execute(
                    """INSERT INTO editorial_controls
                       (story_id,revision,locked,retracted,notice_action,notice_reason,notice_at,held_updates)
                       VALUES(?,0,1,?,'lock','Concurrent editorial change',?,0)""",
                    (survivor, int(change == "survivor_retraction"), LATER),
                )
        else:
            payload = story_payload(store, survivor)
            if change == "pair_order":
                payload["added_at"] = "2026-11-12T12:00:00Z"
            else:
                payload.update(title="Unrelated application observation", summary="A different application reports another event.",
                               products=["arti"], sources=[{"url": "https://example.org/unrelated", "title": "Unrelated report"}])
            with db:
                db.execute("UPDATE stories SET payload=? WHERE id=?", (json.dumps(payload), survivor))
        fresh = review_gate._auto_merge_pair(store, duplicate, survivor)
        assert fresh != (duplicate, survivor)
        if change == "pair_order":
            assert fresh == (survivor, duplicate)
        saved.update(job=copy.deepcopy(job(store)), pair=fresh)
        return original_merge(db, duplicate, survivor, **kwargs)

    monkeypatch.setattr(editorial, "merge", _changed_survivor)
    checker = Reviewer(reply, reply)
    result = run(cfg, store, row, Writer(update_analysis(update=comment_body, evidence=[comment_body])), checker, observed=LATER)
    assert result["status"] == "stale" and len(checker.calls) == 2
    assert job(store) == saved["job"] and job_record(store)["request_budget"]["reserved"] == 2
    assert editorial.retired(store.db, story_id=newer["id"]) is None
    assert editorial.retired(store.db, story_id=older["id"]) is None
    assert store.db.execute("SELECT COUNT(*) FROM stories").fetchone()[0] == 2
    assert tuple(store.db.execute("SELECT status,story_id FROM items WHERE id=?", (row["id"],)).fetchone()) == ("pending", newer["id"])


@pytest.mark.parametrize("survivor_locked", [False, True])
def test_merge_transfers_or_requeues_story_locked_held_updates(context, survivor_locked):
    """Requeue locked held updates onto unlocked survivors or transfer `held_updates` onto locked ones."""
    cfg, store = context
    surv = _publish(store, item(url="https://example.org/surv", title="Primary guard selection report",
                                content="Primary report covering guard selection anomaly in Tor 0.4.9.90."), at=EARLY)
    dup_item = item(url="https://example.org/dup", title="Secondary guard selection report",
                    content="Secondary report covering guard selection anomaly in Tor 0.4.9.90.", updated_at=EARLY)
    dup = _publish(store, dup_item, at=EARLY)
    cli.build(cfg, store)

    row_held = pending(store, {**dup_item, "content": dup_item["content"] + " Follow-up confirmation.", "updated_at": LATER},
                       at=LATER, ready=LATER)
    if not survivor_locked:
        with pytest.raises(AnalysisError):
            run(cfg, store, row_held, Writer(update_analysis(update="Follow-up confirmation.", evidence=["Follow-up confirmation."])),
                Reviewer(AnalysisError("timeout", retryable=True)), observed=LATER)
        assert job(store, row_held["id"]) is not None
    else:
        editorial_act(editorial.correct, store, surv["id"], {"why_it_matters": "Survivor operator note."}, reason="Lock story", observed=MID)
    editorial_act(editorial.correct, store, dup["id"], {"why_it_matters": "Duplicate operator note."}, reason="Pin context", observed=MID)
    assert run(cfg, store, row_held, Writer(), Reviewer(), observed=LATER)["status"] == "locked"
    assert editorial.show(store.db, dup["id"])["held_updates"] == 1

    editorial_act(editorial.merge, store, dup["id"], surv["id"], reason="Consolidate duplicate report", observed=LATER)
    if survivor_locked:
        assert editorial.show(store.db, surv["id"])["held_updates"] == 1
        unlocked = editorial_act(editorial.unlock, store, surv["id"], reason="Resume automated updates", observed="2026-11-09T12:00:00Z")
        assert unlocked["locked"] is False
    else:
        assert job(store, row_held["id"])["stage"] == "locked"
        held_proof = job_record(store, row_held["id"])
        assert held_proof["request_budget"]["reserved"] == 1 and held_proof["reviews"] == [] and not held_proof.get("approval")
    assert tuple(store.db.execute("SELECT status,story_id FROM items WHERE id=?", (row_held["id"],)).fetchone()) == ("pending", surv["id"])


def test_gitlab_refs_are_project_qualified_in_auto_merge_and_routing(context):
    """Match `#<iid>` and `!<iid>` GitLab references only within the same GitLab project."""
    cfg, store = context
    tor_story = _publish(store, item(
        kind="gitlab_mr", product="tor", url="https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/123",
        title="Backport circuit padding cleanup", content="Backport !123 cleanup for C Tor relays.",
    ), draft=analysis(
        title="C Tor backports circuit padding cleanup in !123", summary="Merge request !123 cleans up circuit padding timers.",
        products=["tor"], evidence=["Backport !123 cleanup for C Tor relays."],
    ), at=EARLY)
    arti_story = _publish(store, item(
        kind="gitlab_mr", product="arti", url="https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/123",
        title="Refactor channel handshake state", content="Refactor !123 channel handshake state in Arti.",
    ), draft=analysis(
        title="Arti refactors channel handshake state in !123", summary="Merge request !123 refactors channel handshake state.",
        products=["arti"], evidence=["Refactor !123 channel handshake state in Arti."],
    ), at=MID)
    cli.build(cfg, store)
    assert review_gate._auto_merge_pair(store, tor_story["id"], arti_story["id"]) is None

    same_issue = _publish(store, item(
        kind="gitlab_issue", product="tor", url="https://gitlab.torproject.org/tpo/core/tor/-/issues/49200",
        title="Guard sample persistence glitch", content="Guard sample file fails atomic rename under load.",
    ), draft=analysis(
        title="Guard sample persistence glitch under load", summary="Guard sample file fails atomic rename under load.",
        products=["tor"], evidence=["Guard sample file fails atomic rename under load."],
    ), at=EARLY)
    same_mr = _publish(store, item(
        kind="gitlab_mr", product="tor", url="https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/1090",
        title="Fix atomic rename for #49200", content="Fixes #49200 atomic rename handling.",
    ), draft=analysis(
        title="Merge request fixes #49200 guard persistence", summary="Fixes #49200 atomic rename handling.",
        products=["tor"], evidence=["Fixes #49200 atomic rename handling."],
    ), at=MID)
    cli.build(cfg, store)
    assert review_gate._auto_merge_pair(store, same_issue["id"], same_mr["id"]) == (same_mr["id"], same_issue["id"])


def test_story_aliases_are_insert_only_and_permanent(store):
    """Enforce SQLite triggers preventing updates, deletes, or replacements on `story_aliases`."""
    _add_alias(store.db, "retired-story-1", "url:retired-cluster-1", story_json='{"id":"retired-story-1"}')
    with pytest.raises(sqlite3.IntegrityError, match="Story aliases are permanent"):
        store.db.execute("UPDATE story_aliases SET reason='changed' WHERE story_id='retired-story-1'")
    with pytest.raises(sqlite3.IntegrityError, match="Story aliases are permanent"):
        store.db.execute("DELETE FROM story_aliases WHERE story_id='retired-story-1'")
    for sid, ckey in (("retired-story-1", "url:other"), ("retired-story-2", "url:retired-cluster-1")):
        with pytest.raises(sqlite3.IntegrityError, match="Story aliases are permanent"):
            store.db.execute(
                "INSERT OR REPLACE INTO story_aliases(story_id,cluster_key,survivor_id,reason,created_at) VALUES(?,?,NULL,?,?)",
                (sid, ckey, "replace", DATE),
            )
        with pytest.raises(sqlite3.IntegrityError):
            _add_alias(store.db, sid, ckey)


def test_stories_never_recreated_trigger_and_commit_candidate_rowcount(store):
    """Block retired story upserts via SQLite triggers and raise `RetiredStory` in `commit_candidate`."""
    live_id = seed_story(store, item(url="https://example.org/live", title="Live story"),
                         analysis(title="Live story"), at=DATE)["id"]
    _add_alias(store.db, "retired-id", "url:retired-key")
    _add_alias(store.db, "merged-id", "url:merged-key", live_id)

    upsert = """INSERT INTO stories(id,cluster_key,payload,published_at,updated_at)
        VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,updated_at=excluded.updated_at"""
    for sid, ckey in (("retired-id", "url:another-key"), ("another-id", "url:retired-key"),
                      ("merged-id", "url:another-merged"), ("another-merged-id", "url:merged-key")):
        assert store.db.execute(upsert, (sid, ckey, "{}", DATE, DATE)).rowcount == 0
        assert store.db.execute("SELECT 1 FROM stories WHERE id=?", (sid,)).fetchone() is None
    live_cluster = store.db.execute("SELECT cluster_key,payload FROM stories WHERE id=?", (live_id,)).fetchone()
    assert store.db.execute(upsert, (live_id, live_cluster[0], live_cluster[1], DATE, after(60, DATE))).rowcount == 1
    assert len(store.stories()) == 1

    raced_row = pending(store, item(url="https://example.org/raced", title="Raced story"), at=DATE, ready=DATE)
    draft = analysis(title="Raced story")
    prepared = store.prepare_candidate(raced_row, draft, DATE)
    record = {"schema_version": 1, "writer": {"key": "w"}, "input_row": raced_row, "reviews": []}
    receipt = insert_approval(store, prepared, policy="policy", result=verdict(), record=record, created_at=DATE)
    _add_alias(store.db, prepared["story_id"], "url:unmatched-retired-cluster")
    with pytest.raises(editorial.RetiredStory, match="retired"):
        store.commit_candidate(prepared, prepared["candidate"], "w", DATE, **receipt,
                               review_record=record, decision="approve")
    after_race = item_row(store, raced_row)
    assert (after_race["status"], after_race["story_id"]) == ("pending", None)
    assert store.db.execute("SELECT 1 FROM stories WHERE id=?", (prepared["story_id"],)).fetchone() is None

    editorial_act(editorial.correct, store, live_id, {"why_it_matters": "Reviewed note."},
                  reason="Correction", observed=DATE)
    later_stamp = after(120, DATE)
    locked_row = pending(store, item(url="https://example.org/live", title="Live story",
                                     content="Updated body text for lock test.", updated_at=later_stamp),
                         at=later_stamp, ready=later_stamp)
    locked_prepared = store.prepare_candidate(locked_row, draft, later_stamp)
    assert locked_prepared["locked"] is True
    _add_alias(store.db, live_id, live_cluster[0])
    with pytest.raises(editorial.RetiredStory, match="retired"):
        store.commit_candidate(locked_prepared, locked_prepared["candidate"], "w2", later_stamp, review_record=record)


def test_retired_resolver_follows_chains_and_guards_loops_and_editorial_actions(store, tmp_path):
    """Resolve multi-hop `story_aliases` chains, reject loops, and refuse editorial mutations on retired IDs."""
    assert issubclass(editorial.RetiredStory, ValueError)
    assert editorial.retired(store.db) is None
    assert editorial.retired(store.db, story_id="missing", cluster_key="url:missing") is None
    _add_alias(store.db, "dead-1", "url:dead-1", None)
    _add_alias(store.db, "merged-a", "url:merged-a", "merged-b")
    _add_alias(store.db, "merged-b", "url:merged-b", "live-target")
    _add_alias(store.db, "to-dead", "url:to-dead", "dead-1")
    assert editorial.retired(store.db, story_id="dead-1") == ("dead-1", None)
    assert editorial.retired(store.db, cluster_key="url:dead-1") == ("dead-1", None)
    assert editorial.retired(store.db, story_id="unknown", cluster_key="url:dead-1") == ("dead-1", None)
    assert editorial.retired(store.db, story_id="merged-a") == ("merged-a", "live-target")
    assert editorial.retired(store.db, cluster_key="url:merged-a") == ("merged-a", "live-target")
    assert editorial.retired(store.db, story_id="to-dead") == ("to-dead", None)

    for index in range(editorial.MAX_ALIAS_HOPS):
        _add_alias(store.db, f"hop-{index}", f"url:hop-{index}",
                   "final-hop" if index + 1 == editorial.MAX_ALIAS_HOPS else f"hop-{index + 1}")
    assert editorial.retired(store.db, story_id="hop-0") == ("hop-0", "final-hop")
    _add_alias(store.db, "final-hop", "url:final-hop", "too-far")
    with pytest.raises(ValueError, match="loop"):
        editorial.retired(store.db, story_id="hop-0")

    _add_alias(store.db, "self-loop", "url:self-loop", "self-loop")
    with pytest.raises(ValueError, match="loop"):
        editorial.retired(store.db, story_id="self-loop")

    with pytest.raises(editorial.RetiredStory, match="Story is retired"):
        editorial.show(store.db, "dead-1")
    with pytest.raises(editorial.RetiredStory, match="merged into live-target"):
        editorial.show(store.db, "merged-a")
    with pytest.raises(editorial.RetiredStory, match="Story is retired"):
        editorial.retract(store.db, "dead-1", reason="Retract", expect_hash="0" * 64, observed=DATE)
    cfg_path = write_toml(tmp_path, '[site]\ntitle="T"\ndescription="D"\nbase_url="https://example.org"',
                          name="cli-config.toml", with_source=False)
    assert cli.main(["story", "show", "--config", str(cfg_path), "--story", "dead-1"]) == 2
    assert editorial.history(store.db, "dead-1") == {"story_id": "dead-1", "revisions": []}


def test_retired_item_and_cluster_are_ignored_with_zero_model_calls_across_recollections(context):
    """Ignore retired items and body-cluster matches across edits and retries with zero LLM calls."""
    cfg, store = context
    cfg["comments"]["enabled"] = True
    cfg["sources"] = [gitlab_source()]
    first_item = item(kind="gitlab_issue", url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/999",
                      title="Routine test cleanup", content=LONG_BODY)
    assert item_cluster(first_item).startswith("body:")
    story_id = seed_story(store, first_item, analysis(title="Routine test cleanup", summary=LONG_BODY, evidence=[LONG_BODY]), at=DATE)["id"]
    row = store.db.execute("SELECT id, cluster_key FROM items").fetchone()
    retired_cluster = row["cluster_key"]

    with store.db:
        store.db.execute("UPDATE items SET status='ignored',story_id=NULL WHERE id=?", (row["id"],))
        store.db.execute("DELETE FROM stories WHERE id=?", (story_id,))
    _add_alias(store.db, story_id, retired_cluster)
    assert rejection.show_item(store, row["id"])["final_review"] is None
    assert store.ingest({**first_item, "updated_at": after(60, DATE)}, after(60, DATE)) is False

    label_edited = {**first_item, "labels": ["cleanup"], "updated_at": after(120, DATE)}
    pending_row = pending(store, label_edited, at=after(120, DATE), ready=after(120, DATE))
    store.db.execute("""INSERT INTO review_jobs(item_id,writer_key,policy_hash,stage,record_json,prepared_at,updated_at)
        VALUES(?,?,?,?,?,?,?)""", (pending_row["id"], "old", "old", "drafted", "{}", DATE, DATE))
    writer, checker = Writer(), Reviewer()
    result = run(cfg, store, pending_row, writer, checker, after(120, DATE))
    assert result == {"status": "ignored", "writer_calls": 0, "review_calls": 0, "cache_hit": False}
    assert writer.calls == [] and checker.calls == []
    ignored_row = item_row(store, row["id"])
    assert (ignored_row["status"], ignored_row["story_id"], ignored_row["last_error"]) == (
        "ignored", None, "Retired story; never recreated")
    assert store.db.execute("SELECT COUNT(*) FROM review_jobs").fetchone()[0] == 0
    assert store.db.execute("SELECT COUNT(*) FROM comment_cache").fetchone()[0] == 0
    assert decision_codes(store)[-1] == SKIPPED

    for step in (1, 2):
        stamp = after(120 + step * 60, DATE)
        body_edited = {**label_edited, "content": f"{LONG_BODY} Revision {step}.", "updated_at": stamp}
        assert item_cluster(body_edited) != retired_cluster
        queued = pending(store, body_edited, at=stamp, ready=stamp)
        assert queued["cluster_key"] == retired_cluster
        res = run(cfg, store, queued, observed=stamp)
        assert res["status"] == "ignored" and res["writer_calls"] == res["review_calls"] == 0

    same_body_other_url = item(kind="gitlab_issue", url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/1000",
                               title="Routine test cleanup", content=LONG_BODY, updated_at=after(300, DATE))
    assert item_cluster(same_body_other_url) == retired_cluster
    other_row = pending(store, same_body_other_url, at=after(300, DATE), ready=after(300, DATE))
    assert run(cfg, store, other_row, observed=after(300, DATE))["status"] == "ignored"

    current = item_row(store, other_row)
    rejection.retry_item(store, current["id"], current["content_hash"], "Attempt retry", after(360, DATE))
    retried = store.pending(1, after(360, DATE))[0]
    assert run(cfg, store, retried, observed=after(360, DATE))["status"] == "ignored"
    assert store.stories() == []


def test_computed_retired_story_id_and_concurrent_change_are_refused(context):
    """Refuse candidates whose derived `story_id` is retired while yielding `stale` on concurrent edits."""
    cfg, store = context
    row = pending(store, item(url="https://example.org/fresh-item", title="Fresh item"), at=DATE, ready=DATE)
    _add_alias(store.db, digest(row["cluster_key"])[:24], "url:different-cluster")
    with pytest.raises(editorial.RetiredStory):
        candidate.prepare(store.db, row, analysis(), DATE)
    stale_copy = dict(row)
    with store.db:
        store.db.execute("UPDATE items SET content_hash='concurrently-changed' WHERE id=?", (row["id"],))
    assert run(cfg, store, stale_copy, observed=DATE)["status"] == "stale"
    assert decision_codes(store) == []
    with store.db:
        store.db.execute("UPDATE items SET content_hash=? WHERE id=?", (row["content_hash"], row["id"]))
    assert run(cfg, store, row, observed=DATE)["status"] == "ignored"
    assert decision_codes(store) == [SKIPPED]


def test_retired_story_raised_mid_gate_marks_item_ignored_and_logs_skip(context, monkeypatch):
    """Convert `RetiredStory` raised during `prepare_candidate` into an `ignored` skip decision."""
    cfg, store = context
    row = pending(store, item(url="https://example.org/retire-mid", title="Mid-run retired story",
                              content="Mid-run retired story details."), at=DATE, ready=DATE)
    draft = analysis(title="Mid-run retired story", summary="Mid-run retired story details.",
                     evidence=["Mid-run retired story details."])
    monkeypatch.setattr(store, "prepare_candidate", raise_once(editorial.RetiredStory("retired mid-run")))
    assert run(cfg, store, row, Writer(draft), Reviewer(), DATE)["status"] == "ignored"
    assert item_row(store, row)["status"] == "ignored"
    assert decision_codes(store, row) == [SKIPPED]


def test_merged_alias_resolves_to_live_survivor_or_refuses_missing_survivor(store):
    """Resolve merged `story_id`/`cluster_key` aliases to live survivors and fail when retired."""
    survivor = seed_story(store, item(url="https://example.org/survivor", title="Survivor story"),
                          analysis(title="Survivor story"), at=DATE)
    survivor_cluster = store.db.execute("SELECT cluster_key FROM stories WHERE id=?", (survivor["id"],)).fetchone()[0]
    _add_alias(store.db, "merged-dup", "url:merged-dup-cluster", survivor["id"])

    f_row = pending(store, item(url="https://example.org/followup", title="Followup"), at=DATE, ready=DATE)
    with store.db:
        store.db.execute("UPDATE items SET story_id='merged-dup' WHERE id=?", (f_row["id"],))
    by_id = item_row(store, f_row)
    assert candidate.existing_story(store.db, by_id)["id"] == survivor["id"]
    prepared = candidate.prepare(store.db, by_id, update_analysis(update="Followup"), after(60, DATE))
    assert (prepared["story_id"], prepared["cluster_key"]) == (survivor["id"], survivor_cluster)

    with store.db:
        store.db.execute("UPDATE items SET story_id=NULL,cluster_key='url:merged-dup-cluster' WHERE id=?", (f_row["id"],))
    assert candidate.existing_story(store.db, item_row(store, f_row))["id"] == survivor["id"]

    _add_alias(store.db, "dangling-dup", "url:dangling-cluster", "missing-survivor")
    with pytest.raises(editorial.RetiredStory):
        candidate.existing_story(store.db, {"story_id": None, "cluster_key": "url:dangling-cluster"})

    for slug, label, by_story_id in (("a", "Secondary A", False), ("b", "Secondary B", True)):
        sec_id = seed_story(store, item(url=f"https://example.org/secondary-{slug}", title=label),
                            analysis(title=label), at=DATE)["id"]
        sec_cluster = store.db.execute("SELECT cluster_key FROM stories WHERE id=?", (sec_id,)).fetchone()[0]
        if by_story_id:
            _add_alias(store.db, f"retired-other-{slug}", sec_cluster)
            probe = {"story_id": sec_id, "cluster_key": "url:unrelated"}
        else:
            _add_alias(store.db, sec_id, f"url:retired-other-{slug}")
            probe = {"story_id": None, "cluster_key": sec_cluster}
        with pytest.raises(editorial.RetiredStory):
            candidate.existing_story(store.db, probe)


def test_held_candidate_cannot_be_approved_after_story_retirement(context):
    """Invalidate operator approval eligibility once the target story identity is retired."""
    cfg, store = context
    row = pending(store, item(kind="feed", authority="official", url="https://example.org/official-held",
                              title="Official post"), at=DATE, ready=DATE)
    checker = Reviewer(verdict("skip", criterion="news_value"), verdict("skip", criterion="news_value"))
    assert run(cfg, store, row, checker=checker, observed=DATE)["status"] == "held"
    before = review_gate.approval(cfg, store, row["id"])
    assert before["eligible"] is True and before["hash"]
    _add_alias(store.db, digest(row["cluster_key"])[:24], row["cluster_key"])
    after_retire = review_gate.approval(cfg, store, row["id"])
    assert after_retire["eligible"] is False and "changed since the review" in after_retire["reason"]
    with pytest.raises(ValueError, match="changed since the review"):
        rejection.approve_item(cfg, store, row["id"], before["hash"], "Approve retired candidate", after(60, DATE))
    assert store.stories() == []


def test_merge_partially_slotted_doctor_pin_and_standalone_survivor_guard(tmp_path):
    """Preserve slotless pre-upgrade DocTor updates on host merges and skip transfer onto standalone alerts."""
    _, cfg = make_doctor_config(tmp_path, publish=True)
    src = cfg["sources"][0]
    moria_lines = ["WARNING: The following authorities are missing from the consensus: moria1", DOCTOR_OK_LINE]
    moria_items = [doctor_report_item(f"MOR_STANDALONE_{i}", after(i * 12 * 3600, "2024-01-02T00:05:00Z"), moria_lines) for i in range(5)]
    with Store(cfg["storage"]["database"]) as store:
        doctor.ingest(store.db, src, moria_items, "2024-01-05T00:00:00Z")
        doctor.evaluate(cfg, store, src, FakeLinker(), "2024-01-05T00:00:00Z")
        standalone_id = store.stories()[0]["id"]

        dup_host = _publish(store, item(
            url="https://example.org/bastet-host-dup", title="Directory authority bastet offline report",
            content="Operators reported directory authority bastet is offline for maintenance.",
            published_at="2024-01-14T14:00:00Z", updated_at="2024-01-14T14:00:00Z", authority="official",
        ), draft=analysis(
            title="Directory authority bastet offline report",
            summary="Operators reported directory authority bastet is offline for maintenance.",
            category="directory-authority", tags=["directory-authority"],
            evidence=["Operators reported directory authority bastet is offline for maintenance."],
        ), at="2024-01-14T14:00:00Z")["id"]
        open_items = bastet_incident_items(close=False)
        close_items = bastet_incident_items(close=True)[len(open_items):]
        doctor.ingest(store.db, src, open_items, "2024-01-17T12:00:00Z")
        doctor.evaluate(cfg, store, src, FakeLinker(True), "2024-01-17T12:00:00Z")
        dup_raw = story_payload(store, dup_host)
        dup_raw["network"][0]["slots"] = []
        with store.db:
            store.db.execute("UPDATE stories SET payload=? WHERE id=?", (json.dumps(dup_raw), dup_host))
        doctor.ingest(store.db, src, close_items, "2024-01-18T12:00:00Z")
        doctor.evaluate(cfg, store, src, FakeLinker(), "2024-01-18T12:00:00Z")
        publication.build(cfg, store)
        standalone_before = story_payload(store, standalone_id)

        editorial_act(editorial.merge, store, dup_host, standalone_id,
                      reason="Merge host into standalone alert.", observed="2024-01-18T13:00:00Z")
        assert story_payload(store, standalone_id) == standalone_before
