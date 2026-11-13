"""Deterministic item-to-story association, coverage background, and same_story routing."""

import json

import pytest

from approval_helpers import finish_reviewed, update_analysis, verdict
from onionflash import candidate, editorial, rejection, review, review_gate
from onionflash.analyze import tag_notice
from onionflash.store import Store
from onionflash.util import digest, gitlab_refs, item_cluster, release_mentions, thread_subject
from test_core import DATE, analysis, config, item
from test_review_gate import LATER, Reviewer, Writer, pending, run


LIST_BASE = "https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/message/"
OTHER_LIST_BASE = "https://lists.torproject.org/mailman3/hyperkitty/list/tor-dev@lists.torproject.org/message/"


def _publish(store, incoming, draft=None, *, observed=DATE):
    store.ingest(incoming, observed)
    row = next(r for r in store.pending(20, observed) if r["id"] == incoming["id"])
    draft = draft or (tag_notice(incoming) if incoming.get("kind") == "tag" else analysis(
        title=incoming["title"][:120],
        summary=incoming["content"][:220] or incoming["title"],
        evidence=[incoming["content"][:80] or incoming["title"]],
    ))
    finish_reviewed(store, row, draft, f"k-{incoming['id']}", observed)
    sid = store.db.execute("SELECT story_id FROM items WHERE id=?", (incoming["id"],)).fetchone()[0]
    return json.loads(store.db.execute("SELECT payload FROM stories WHERE id=?", (sid,)).fetchone()[0])


def test_pure_reference_release_mention_and_thread_helpers():
    mr = item(
        kind="gitlab_mr",
        url="https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/1080",
        title="Fix relay crash (closes #41339, resolves tpo/core/arti#99)",
        content="Follow-up to !1075 and https://gitlab.torproject.org/tpo/core/tor/-/issues/41466.",
        public_comments=[{
            "id": "n1",
            "author": "dev",
            "created_at": DATE,
            "url": "https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/1080#note_1",
            "title": "Comment",
            "body": "Closes #99999 in a comment is only a mention, not an MR header close.",
        }],
    )
    closing, mentioned = gitlab_refs(mr)
    assert closing == [
        "https://gitlab.torproject.org/tpo/core/tor/-/work_items/41339",
        "https://gitlab.torproject.org/tpo/core/arti/-/work_items/99",
    ]
    assert mentioned == [
        "https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/1075",
        "https://gitlab.torproject.org/tpo/core/tor/-/work_items/41466",
        "https://gitlab.torproject.org/tpo/core/tor/-/work_items/99999",
    ]

    mentions_item = item(
        title="Authority timeline update",
        content="Operators upgraded to tor-0.4.9.16 alongside Tor Browser 16.0; bare 9.9.9 is ignored.",
        public_comments=[{
            "id": "n1",
            "author": "op",
            "created_at": DATE,
            "url": "https://gitlab.torproject.org/tpo/network-health/analysis/-/issues/1#note_1",
            "title": "Comment",
            "body": "Also tested arti 2.8.0 and Tor 0.4.9.16 on staging.",
        }],
    )
    assert release_mentions(mentions_item) == [
        "release:tor:0.4.9.16",
        "release:tor-browser:16.0",
        "release:arti:2.8.0",
    ]
    assert release_mentions(item(title="", content="Operators upgraded to Tor 0.4.9.16.")) == [
        "release:tor:0.4.9.16"
    ]
    assert release_mentions(item(title="", content="Operators upgraded to Tor Browser 16.0.1.")) == [
        "release:tor-browser:16.0.1"
    ]
    assert release_mentions(item(title="", content="Malformed build Tor 0.4.9.16.1.")) == []

    assert thread_subject(item(url=LIST_BASE + "ABC/", title="[tor-relays] Re: re. Guard flag drop across relays")) == (
        "guard flag drop across relays",
        True,
    )
    assert thread_subject(item(url=LIST_BASE + "DEF/", title="[tor-relays] Fwd: Guard flag drop across relays")) == (
        "guard flag drop across relays",
        False,
    )
    assert thread_subject(item(url=LIST_BASE + "SHORT/", title="[tor-relays] Re: Short subject")) == (None, True)
    assert thread_subject(item(url="https://blog.torproject.org/post/", title="Re: Guard flag drop across relays")) == (None, False)


def test_associate_precedence_and_ambiguous_fallbacks(tmp_path):
    with Store(tmp_path / "state.db") as store:
        s1 = _publish(store, item(url=LIST_BASE + "M1/", source_id="tor-relays", title="[tor-relays] Consensus bandwidth drop across relays"))
        s2 = _publish(store, item(url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/41339", kind="gitlab_issue",
                                  title="Relay crash in circuit padding", content="Crash details " + "x" * 200))
        s3 = _publish(store, item(url="https://example.org/s3", title="Tor 1.2.3 released"))
        s4 = _publish(store, item(url="https://example.org/s4", title="Distinct story four"))

        # 6: thread match -> 5: closing_ref beats thread -> 4: item_cluster beats closing_ref ->
        # 3: stories.cluster_key beats item_cluster -> 2: alias beats stories.cluster_key -> 1: story_id wins.
        probe = item(
            kind="gitlab_mr",
            upstream_state="merged",
            source_id="tor-relays",
            url=LIST_BASE + "M2/",
            title="[tor-relays] Re: Consensus bandwidth drop across relays",
            content="Closes tpo/core/tor#41339 with full details.",
            published_at="2026-11-09T12:00:00Z",
            updated_at="2026-11-09T12:00:00Z",
        )
        # Without MR closing ref, reply matches thread s1.
        reply_only = item(
            kind="feed",
            source_id="tor-relays",
            url=LIST_BASE + "M2A/",
            title="[tor-relays] Re: Consensus bandwidth drop across relays",
            content="Closes tpo/core/tor#41339 with full details.",
            published_at="2026-11-09T12:00:00Z",
            updated_at="2026-11-09T12:00:00Z",
        )
        store.ingest(reply_only, LATER)
        r_thread = next(r for r in store.pending(20, LATER) if r["url"] == reply_only["url"])
        assert candidate.associate(store.db, r_thread) == (dict(store.db.execute("SELECT * FROM stories WHERE id=?", (s1["id"],)).fetchone()), "thread")

        # Merged MR with closing ref beats thread and matches s2.
        store.ingest(probe, LATER)
        r_close = next(r for r in store.pending(20, LATER) if r["id"] == probe["id"])
        matched, how = candidate.associate(store.db, r_close)
        assert matched["id"] == s2["id"] and how == "closing_ref"

        # Mapped-item cluster_key beats closing_ref.
        with store.db:
            store.db.execute("UPDATE items SET cluster_key='custom:shared' WHERE story_id=?", (s4["id"],))
        matched, how = candidate.associate(store.db, {**r_close, "cluster_key": "custom:shared"})
        assert matched["id"] == s4["id"] and how == "item_cluster"

        # stories.cluster_key beats mapped-item cluster_key.
        matched, how = candidate.associate(store.db, {**r_close, "cluster_key": "release:tor:1.2.3"})
        assert matched["id"] == s3["id"] and how == "cluster"

        # Alias beats stories.cluster_key, and story_id comes first.
        with store.db:
            store.db.execute(
                "INSERT INTO story_aliases(story_id,cluster_key,survivor_id,reason,created_at) VALUES(?,?,?,?,?)",
                ("retired00000000000000000", "alias:key", s4["id"], "merged", LATER),
            )
        matched, how = candidate.associate(store.db, {**r_close, "cluster_key": "alias:key"})
        assert matched["id"] == s4["id"] and how == "alias"
        matched, how = candidate.associate(store.db, {**r_close, "story_id": s1["id"], "cluster_key": "alias:key"})
        assert matched["id"] == s1["id"] and how == "story_id"

        # Ambiguous matches (2 distinct stories) return (None, None) rather than guessing.
        s5 = _publish(store, item(url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/41340", kind="gitlab_issue",
                                  title="Second crash issue", content="Different crash " + "y" * 200))
        ambig_mr = item(
            kind="gitlab_mr",
            upstream_state="merged",
            url="https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/1099",
            title="Fix two crashes (closes #41339 and #41340)",
            content="Fixes #41339, #41340.",
        )
        store.ingest(ambig_mr, LATER)
        r_ambig = next(r for r in store.pending(20, LATER) if r["id"] == ambig_mr["id"])
        assert candidate.associate(store.db, r_ambig) == (None, None)
        rel_ids = [sid for sid, _ in candidate.related(store.db, r_ambig, ambig_mr)]
        assert s2["id"] in rel_ids and s5["id"] in rel_ids


def test_remapped_item_cluster_associates_to_survivor_without_recreating_removed_id(tmp_path):
    body = "Operators report sustained descriptor upload timeouts across multiple directory authorities " + ("detail " * 20)
    first = item(kind="gitlab_issue", url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/501",
                 title="authority: Descriptor upload timeouts", content=body)
    dup_source = item(kind="gitlab_issue", url="https://gitlab.torproject.org/tpo/network-health/team/-/work_items/88",
                      title="dirauth: Descriptor upload timeouts", content=body)
    assert item_cluster(first) == item_cluster(dup_source) and item_cluster(first).startswith("body:")
    removed_id = digest("url:synthetic-removed-duplicate")[:24]

    with Store(tmp_path / "state.db") as store:
        survivor = _publish(store, item(url="https://example.org/survivor", title="Directory authority upload timeouts"))
        # Simulate a remapped item whose body cluster differs from stories.cluster_key.
        store.ingest(first, DATE)
        with store.db:
            store.db.execute("UPDATE items SET status='published',story_id=? WHERE id=?", (survivor["id"], first["id"]))
        store.ingest(dup_source, LATER)
        row = next(r for r in store.pending(10, LATER) if r["id"] == dup_source["id"])
        matched, how = candidate.associate(store.db, row)
        assert matched["id"] == survivor["id"] and how == "item_cluster"
        prepared = store.prepare_candidate(row, update_analysis(update="Follow-up details.", evidence=["sustained descriptor upload timeouts"]), LATER)
        assert prepared["candidate"]["id"] == survivor["id"] != removed_id


def test_mr_closing_and_list_reply_association_boundaries(tmp_path):
    with Store(tmp_path / "state.db") as store:
        issue_story = _publish(store, item(
            kind="gitlab_issue",
            url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/41339",
            title="Relay crash on malformed cell",
            content="A malformed cell triggers an assertion failure in relay handling.",
        ))
        other_issue = _publish(store, item(
            kind="gitlab_issue",
            url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/41466",
            title="Separate metrics counter bug",
            content="Metrics counters wrap on 32-bit targets.",
        ))
        closing_mr = item(
            kind="gitlab_mr",
            upstream_state="merged",
            url="https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/2001",
            title="Fix relay crash (closes #41339)",
            content="Resolves the assertion failure when parsing cells.",
        )
        store.ingest(closing_mr, LATER)
        mr_row = next(r for r in store.pending(10, LATER) if r["id"] == closing_mr["id"])
        prepared = store.prepare_candidate(
            mr_row,
            update_analysis(update="Merged fix for #41339.", state="merged", confidence="confirmed", evidence=["Resolves the assertion failure"]),
            LATER,
        )
        assert prepared["coverage"]["prior_story"]["id"] == issue_story["id"]
        assert prepared["coverage"]["prior_story"]["associated"] is True

        mention_only = item(
            kind="gitlab_mr",
            upstream_state="merged",
            url="https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/2002",
            title="Refactor counter helpers",
            content="Because of #41466 we keep 64-bit counters here.",
        )
        store.ingest(mention_only, LATER)
        m_row = next(r for r in store.pending(10, LATER) if r["id"] == mention_only["id"])
        m_prep = store.prepare_candidate(m_row, analysis(title="Counter refactor", summary="64-bit counters.", evidence=["Because of #41466 we keep 64-bit counters"]), LATER)
        assert m_prep["coverage"]["prior_story"] is None
        assert (other_issue["id"], "references #41466") in [(e["id"], e.get("related")) for e in m_prep["coverage"]["recent"]]

        # List thread boundaries: reply within 45d on same list associates; non-reply, other list, or >45d does not.
        thread_story = _publish(store, item(
            source_id="tor-relays",
            url=LIST_BASE + "ROOT1/",
            title="[tor-relays] Exit relay throughput regression on Linux",
            published_at="2026-09-20T10:00:00Z",
            updated_at="2026-09-20T10:00:00Z",
        ), observed="2026-09-20T10:05:00Z")

        good_reply = item(
            source_id="tor-relays",
            url=LIST_BASE + "REP1/",
            title="[tor-relays] Re: re. Exit relay throughput regression on Linux",
            published_at="2026-10-25T10:00:00Z",
            updated_at="2026-10-25T10:00:00Z",
        )
        store.ingest(good_reply, "2026-10-25T10:05:00Z")
        good_row = next(r for r in store.pending(10, "2026-10-25T10:05:00Z") if r["id"] == good_reply["id"])
        assert candidate.associate(store.db, good_row)[0]["id"] == thread_story["id"]

        for bad in (
            item(source_id="tor-relays", url=LIST_BASE + "NONREP/", title="[tor-relays] Exit relay throughput regression on Linux",
                 published_at="2026-10-25T10:00:00Z", updated_at="2026-10-25T10:00:00Z"),
            item(source_id="tor-dev", url=OTHER_LIST_BASE + "OTHER/", title="[tor-dev] Re: Exit relay throughput regression on Linux",
                 published_at="2026-10-25T10:00:00Z", updated_at="2026-10-25T10:00:00Z"),
            item(source_id="tor-relays", url=LIST_BASE + "OLD/", title="[tor-relays] Re: Exit relay throughput regression on Linux",
                 published_at="2026-11-10T10:00:00Z", updated_at="2026-11-10T10:00:00Z"),
        ):
            store.ingest(bad, bad["updated_at"])
            bad_row = next(r for r in store.pending(10, bad["updated_at"]) if r["id"] == bad["id"])
            assert candidate.associate(store.db, bad_row) == (None, None)


def test_relations_tag_citation_locked_hold_upgrade_and_update(tmp_path):
    cfg = config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        # Tag first -> community post upgrades tag in story scope -> official announcement updates
        # published prose in update scope without replacing title/summary -> reported follow-up
        # appends another update -> late tag on locked story records held update.
        tag_first = item(kind="tag", authority="official", title="tor-0.4.9.20", content="",
                         url="https://gitlab.torproject.org/tpo/core/tor/-/tags/tor-0.4.9.20")
        row = pending(store, tag_first)
        assert run(cfg, store, row, Writer(tag_notice(tag_first)), Reviewer(verdict()))["status"] == "published"
        assert store.stories()[0]["state"] == "tagged"

        community_post = item(kind="feed", authority="community", title="Tor 0.4.9.20 released",
                              url="https://forum.example.org/tor-0-4-9-20",
                              content="Community summary of Tor 0.4.9.20 changes.")
        row = pending(store, community_post)
        comm_draft = analysis(title="Community note on Tor 0.4.9.20", summary="Community summary of Tor 0.4.9.20 changes.",
                              why_it_matters="Operators can review the reported Tor 0.4.9.20 changes.",
                              confidence="reported", state="released", category="release", tags=["tor", "release"],
                              evidence=["Community summary of Tor 0.4.9.20 changes."])
        assert run(cfg, store, row, Writer(comm_draft), Reviewer(verdict()))["status"] == "published"
        assert store.stories()[0]["title"] == "Community note on Tor 0.4.9.20"

        official_ann = item(kind="feed", authority="official", title="[tor-announce] [RELEASE] Tor release 0.4.9.20",
                            url="https://lists.torproject.org/tor-announce/0.4.9.20",
                            content="Official Tor 0.4.9.20 release announcement with security fixes.")
        row = pending(store, official_ann)
        ann_upd = update_analysis(update="Official announcement confirms Tor 0.4.9.20 with security fixes.",
                                  confidence="confirmed", state="released",
                                  evidence=["Official Tor 0.4.9.20 release announcement with security fixes."])
        assert run(cfg, store, row, Writer(ann_upd), Reviewer(verdict(update=True)))["status"] == "published"
        after_ann = store.stories()[0]
        assert after_ann["title"] == "Community note on Tor 0.4.9.20"
        assert after_ann["summary"] == "Community summary of Tor 0.4.9.20 changes."
        assert after_ann["why_it_matters"] == "Operators can review the reported Tor 0.4.9.20 changes."
        assert after_ann["confidence"] == "confirmed"
        assert after_ann["updates"][-1]["text"] == "Official announcement confirms Tor 0.4.9.20 with security fixes."

        followup = item(kind="feed", authority="community", title="Tor 0.4.9.20 released: operator notes",
                        url="https://lists.torproject.org/tor-relays/0.4.9.20-notes",
                        content="Relay operators report clean upgrades on Debian bookworm.")
        row = pending(store, followup)
        upd_draft = update_analysis(update="Relay operators report clean upgrades on Debian bookworm.",
                                    confidence="confirmed", state="released",
                                    evidence=["Relay operators report clean upgrades on Debian bookworm."])
        assert run(cfg, store, row, Writer(upd_draft), Reviewer(verdict(update=True)))["status"] == "published"
        after_upd = store.stories()[0]
        assert after_upd["title"] == "Community note on Tor 0.4.9.20"
        assert len(after_upd["updates"]) == 2
        assert after_upd["updates"][-1]["text"] == "Relay operators report clean upgrades on Debian bookworm."

        # Lock the story: a second tag holds as held.gate.story_locked rather than mutating sources.
        shown = editorial.show(store.db, after_upd["id"])
        editorial.correct(store.db, after_upd["id"], {"title": after_upd["title"] + " (verified)"},
                          reason="Pin headline", expect_hash=shown["hash"])
        mirror_tag = item(kind="tag", authority="official", title="tor-0.4.9.20", content="",
                          url="https://gitlab.torproject.org/tpo/core/tor-mirror/-/tags/tor-0.4.9.20")
        row = pending(store, mirror_tag)
        locked_out = run(cfg, store, row, Writer(), Reviewer())
        assert locked_out["status"] == "locked" and locked_out["writer_calls"] == 0 and locked_out["review_calls"] == 0
        assert editorial.show(store.db, after_upd["id"])["held_updates"] == 1

        # A metrics_timeline entry (tier 1) IS upgraded in story scope by a prose release post (tier 2).
        timeline_item = item(kind="metrics_timeline", authority="official", title="Tor 0.4.9.21 released",
                             source_entry_id="tl-0.4.9.21",
                             url="https://gitlab.torproject.org/tpo/network-health/metrics/timeline/-/blob/main/README.md#21",
                             content="Timeline entry noting Tor 0.4.9.21.")
        row_tl = pending(store, timeline_item)
        tl_draft = analysis(title="Timeline entry for Tor 0.4.9.21", summary="Timeline entry noting Tor 0.4.9.21.",
                            confidence="confirmed", state="released", category="release", tags=["tor", "release"],
                            evidence=["Timeline entry noting Tor 0.4.9.21."])
        assert run(cfg, store, row_tl, Writer(tl_draft), Reviewer(verdict()))["status"] == "published"
        prose_after_tl = item(kind="feed", authority="community", title="Tor 0.4.9.21 released",
                              url="https://forum.example.org/tor-0-4-9-21",
                              content="Full release prose covering Tor 0.4.9.21 relay changes.")
        row_prose = pending(store, prose_after_tl)
        prose_draft = analysis(title="Tor 0.4.9.21 brings relay changes",
                               summary="Full release prose covering Tor 0.4.9.21 relay changes.",
                               confidence="confirmed", state="released", category="release", tags=["tor", "release"],
                               evidence=["Full release prose covering Tor 0.4.9.21 relay changes."])
        assert run(cfg, store, row_prose, Writer(prose_draft), Reviewer(verdict()))["status"] == "published"
        tl_story = next(s for s in store.stories() if "0.4.9.21" in s["title"])
        assert tl_story["title"] == "Tor 0.4.9.21 brings relay changes"


def test_coverage_activity_order_retracted_markers_truncation_and_reconsideration(tmp_path):
    cfg = config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        first = _publish(store, item(url="https://example.org/old-active", title="Old story later updated",
                                     published_at="2026-10-01T00:00:00Z", updated_at="2026-10-01T00:00:00Z"),
                         observed="2026-10-01T00:00:00Z")
        stories = []
        for idx in range(31):
            stamp = f"2026-10-{idx + 2:02d}T00:00:00Z" if idx < 29 else f"2026-11-0{idx - 28}T00:00:00Z"
            stories.append(_publish(store, item(url=f"https://example.org/s-{idx}", title=f"Story {idx:02d}",
                                                published_at=stamp, updated_at=stamp), observed=stamp))
        # Exactly 32 stories -> truncated is False.
        bg32 = candidate.coverage_background(store.db, None)
        assert len(bg32["recent"]) == 32 and bg32["truncated"] is False

        # Updating `first` moves it to the top of activity-ordered recent, and a 33rd story sets truncated=True.
        with store.db:
            store.db.execute("UPDATE stories SET updated_at='2026-11-10T18:00:00Z' WHERE id=?", (first["id"],))
        old_dated_new_run = _publish(
            store,
            item(url="https://example.org/added-now", title="Backfilled report added now",
                 published_at="2026-10-03T00:00:00Z", updated_at="2026-10-03T00:00:00Z"),
            observed="2026-11-10T19:00:00Z",
        )
        bg33 = candidate.coverage_background(store.db, None)
        assert bg33["truncated"] is True
        assert bg33["recent"][0]["id"] == old_dated_new_run["id"]
        assert bg33["recent"][1]["id"] == first["id"]

        # prior_story is never duplicated in recent.
        prior_row = dict(store.db.execute("SELECT * FROM stories WHERE id=?", (first["id"],)).fetchone())
        bg_prior = candidate.coverage_background(store.db, prior_row)
        assert bg_prior["prior_story"]["id"] == first["id"]
        assert all(entry["id"] != first["id"] for entry in bg_prior["recent"])

        # Retracted story becomes compact marker with pre-retraction title and no summary.
        shown = editorial.show(store.db, stories[-1]["id"])
        editorial.retract(store.db, stories[-1]["id"], reason="Withdrawn upstream", expect_hash=shown["hash"], observed="2026-11-10T19:30:00Z")
        bg_ret = candidate.coverage_background(store.db, None)
        marker = next(entry for entry in bg_ret["recent"] if entry["id"] == stories[-1]["id"])
        assert marker == {"id": stories[-1]["id"], "title": stories[-1]["title"], "retracted": True}

        # Reconsidered ignored item keeps its earlier decision's story even after 40 newer stories,
        # without displacing 6 related reference/version rows.
        skipped_item = item(url="https://example.org/reconsider-me", title="Follow-up report on relays",
                            content="Routine follow-up mentioning Tor 0.4.9.16.")
        row = pending(store, skipped_item)
        skip_reply = verdict("skip", criterion="new_information")
        skip_reply["criteria"]["new_information"]["reason"] = f"Already covered by {stories[0]['id']}."
        with store.db:
            store.db.execute("UPDATE stories SET updated_at='2026-11-10T20:00:00Z' WHERE id=?", (stories[0]["id"],))
        assert run(cfg, store, row, Writer(), Reviewer(skip_reply))["status"] == "ignored"

        for idx in range(40):
            stamp = f"2026-11-11T00:{idx:02d}:00Z"
            _publish(store, item(url=f"https://example.org/newer-{idx}", title=f"Newer story {idx}",
                                 published_at=stamp, updated_at=stamp), observed=stamp)
        cur = store.db.execute("SELECT content_hash FROM items WHERE id=?", (skipped_item["id"],)).fetchone()
        rejection.retry_item(store, skipped_item["id"], cur["content_hash"], "Check again")
        retried_row = next(r for r in store.pending(10, "2026-11-12T00:00:00Z") if r["id"] == skipped_item["id"])
        prep = store.prepare_candidate(retried_row, analysis(), "2026-11-12T00:00:00Z")
        earlier = [e for e in prep["coverage"]["recent"] if e.get("related") == "earlier decision"]
        assert any(e["id"] == stories[0]["id"] for e in earlier)


        # Subsequent non-retried upstream revision does not carry earlier-decision markers or starve newer stories.
        skipped_rev2 = {**skipped_item, "content": "Updated upstream note mentioning Tor 0.4.9.16 with new logs."}
        row_rev2 = pending(store, skipped_rev2)
        prep_rev2 = store.prepare_candidate(row_rev2, analysis(), "2026-11-12T01:00:00Z")
        assert not [e for e in prep_rev2["coverage"]["recent"] if e.get("related") == "earlier decision"]
        assert any(e["title"] == "Newer story 39" for e in prep_rev2["coverage"]["recent"])


def test_same_story_routing_overlap_guards_and_cite_on_skip(tmp_path):
    cfg = config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        target = _publish(store, item(
            authority="official",
            url="https://lists.torproject.org/tor-relays/incident-1",
            product="tor",
            title="Directory authority overload on maatuska",
            content="Operators report sustained overload on directory authority maatuska.",
        ))
        unrelated = _publish(store, item(
            url="https://blog.torproject.org/tor-browser-ui-localization",
            product="tor-browser",
            title="Tor Browser interface translation update",
            content="New localization strings landed for Tor Browser mobile users.",
        ), draft=analysis(
            title="Tor Browser interface translation update",
            summary="New localization strings landed for Tor Browser mobile users.",
            products=["tor-browser"],
            why_it_matters="",
            evidence=["New localization strings landed for Tor Browser mobile users"],
        ))

        # 1. Approve naming same_story on an official item still routes instead of publishing a second headline!
        cross_channel = item(
            authority="official",
            product="tor",
            url="https://blog.torproject.org/maatuska-followup",
            title="Update on maatuska directory authority load",
            content="Tor 0.4.9.16 mitigated the maatuska authority overload with a new consensus method.",
        )
        row = pending(store, cross_channel)
        route_approve = verdict("approve", same_story=target["id"])
        out1 = run(cfg, store, row, Writer(analysis(
            title="Maatuska overload mitigated",
            summary="Tor 0.4.9.16 mitigated the maatuska authority overload.",
            evidence=["mitigated the maatuska authority overload"],
        )), Reviewer(route_approve))
        assert out1["status"] == "routed" and len(store.stories(10)) == 2
        requeued = next(r for r in store.pending(10, LATER) if r["id"] == cross_channel["id"])
        assert requeued["story_id"] == target["id"]

        # Second pass prepares against target in update scope and publishes an update entry.
        out2 = run(
            cfg,
            store,
            requeued,
            Writer(update_analysis(
                update="Tor 0.4.9.16 mitigated the maatuska authority overload.",
                evidence=["mitigated the maatuska authority overload"],
            )),
            Reviewer(verdict("approve", update=True)),
        )
        assert out2["status"] == "published"
        updated_target = json.loads(store.db.execute("SELECT payload FROM stories WHERE id=?", (target["id"],)).fetchone()[0])
        assert updated_target["updates"][-1]["text"] == "Tor 0.4.9.16 mitigated the maatuska authority overload."

        # 2. Deterministic _can_route guard rejects same_story when product/refs/versions/title have zero overlap.
        distinct_tor = item(
            product="arti",
            url="https://gitlab.torproject.org/tpo/core/arti/-/work_items/777",
            title="Arti RPC socket permission check on BSD",
            content="Arti RPC sockets reject group-writable directories on FreeBSD.",
        )
        row_distinct = pending(store, distinct_tor)
        bad_route = verdict("skip", criterion="new_information", same_story=unrelated["id"])
        bad_route["criteria"]["new_information"]["reason"] = f"Covered by {unrelated['id']}."
        out_bad = run(cfg, store, row_distinct, Writer(analysis(
            title="Arti RPC socket check",
            summary="Arti RPC sockets reject group-writable directories.",
            products=["arti"],
            evidence=["Arti RPC sockets reject group-writable directories"],
        )), Reviewer(bad_route))
        assert out_bad["status"] == "ignored"
        assert store.db.execute("SELECT story_id FROM items WHERE id=?", (distinct_tor["id"],)).fetchone()[0] is None

        # 3. Validation rejects unlisted same_story IDs and ignores same_story when prior_story is present.
        pkt = {"sources": [{"id": "S1", "passages": [{"id": "S1:P1", "text": "Evidence"}]}]}
        with pytest.raises(review.ReviewError, match="same_story"):
            review.validate_review(
                verdict("skip", criterion="new_information", ref="S1:P1", same_story="not-in-coverage"),
                pkt,
                coverage={"prior_story": None, "recent": [{"id": target["id"], "title": "T", "summary": "S"}]},
            )
        ignored_same = review.validate_review(
            verdict("skip", criterion="new_information", ref="S1:P1", update=True, same_story=target["id"]),
            pkt,
            update=True,
            coverage={"prior_story": {"id": target["id"], "title": "T", "summary": "S"}, "recent": []},
        )
        assert ignored_same["same_story"] is None

        # 4. Cite-on-skip: release-cluster skip failing ONLY new_information adds citation; failing news_value too adds nothing.
        rel_story = _publish(store, item(
            authority="official",
            url="https://lists.torproject.org/tor-announce/tor-1.9.0",
            title="[tor-announce] [RELEASE] Tor release 1.9.0",
            content="Tor 1.9.0 is released with relay stability fixes.",
        ))
        before_updated = rel_story["updated_at"]
        mirror_ok = item(
            authority="official",
            url="https://blog.torproject.org/tor-1-9-0",
            title="New Release: Tor 1.9.0",
            content="Tor 1.9.0 is now available with relay stability fixes.",
        )
        row_ok = pending(store, mirror_ok)
        skip_dup = verdict("skip", criterion="new_information", update=True)
        skip_dup["criteria"]["new_information"]["reason"] = f"Already covered in {rel_story['id']}."
        assert run(cfg, store, row_ok, Writer(update_analysis(evidence=["Tor 1.9.0 is now available"])), Reviewer(skip_dup))["status"] == "ignored"
        after_ok = json.loads(store.db.execute("SELECT payload FROM stories WHERE id=?", (rel_story["id"],)).fetchone()[0])
        assert len(after_ok["sources"]) == 2 and after_ok["updated_at"] == before_updated

        mirror_low = item(
            authority="community",
            url="https://forum.example.org/tor-1-9-0",
            title="Tor 1.9.0 released",
            content="Short mirror repost of Tor 1.9.0.",
        )
        row_low = pending(store, mirror_low)
        skip_both = verdict("skip", criterion="new_information", update=True)
        skip_both["criteria"]["new_information"]["reason"] = f"Already covered in {rel_story['id']}."
        skip_both["criteria"]["news_value"]["outcome"] = "fail"
        assert run(cfg, store, row_low, Writer(update_analysis(evidence=["Short mirror repost of Tor 1.9.0."])), Reviewer(skip_both))["status"] == "ignored"
        after_low = json.loads(store.db.execute("SELECT payload FROM stories WHERE id=?", (rel_story["id"],)).fetchone()[0])
        assert len(after_low["sources"]) == 2

        # Non-release item attached/routed to a release story does NOT get cited when skipped on new_information.
        routed_q = item(
            authority="community",
            url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/99190",
            kind="gitlab_issue",
            product="tor",
            title="Question after upgrading relay",
            content="Thanks +1, everything works fine on my BSD box.",
        )
        row_q = pending(store, routed_q)
        with store.db:
            store.db.execute("UPDATE items SET story_id=? WHERE id=?", (rel_story["id"], routed_q["id"]))
        row_q = next(r for r in store.pending(10, LATER) if r["id"] == routed_q["id"])
        skip_q = verdict("skip", criterion="new_information", update=True)
        skip_q["criteria"]["new_information"]["reason"] = f"Routine question on {rel_story['id']}."
        assert run(cfg, store, row_q, Writer(update_analysis(evidence=["everything works fine on my BSD box"])), Reviewer(skip_q))["status"] == "ignored"
        after_q = json.loads(store.db.execute("SELECT payload FROM stories WHERE id=?", (rel_story["id"],)).fetchone()[0])
        assert len(after_q["sources"]) == 2


def test_gitlab_refs_ignore_malformed_urls_and_normalize_project_case():
    from onionflash.util import gitlab_refs

    closing, mentioned = gitlab_refs({
        "url": "https://gitlab.torproject.org/tpo/core/tor/-/work_items/1",
        "title": "Fixes TPO/Core/Tor#123",
        "content": (
            "Closes https://gitlab.torproject.org/TPO/Core/Tor/-/issues/123. "
            "Related to TPO/Core/Tor#789, https://gitlab.torproject.org/TPO/Core/Tor/-/issues/789, "
            "and https://gitlab.torproject.org/foo\\bar/-/issues/456."
        ),
    })
    assert closing == ["https://gitlab.torproject.org/tpo/core/tor/-/work_items/123"]
    assert mentioned == ["https://gitlab.torproject.org/tpo/core/tor/-/work_items/789"]


def test_wire_reviewer_populates_same_story_from_single_duplicate_reason_and_holds_retracted_mirror(monkeypatch):
    from test_review import candidate as story_candidate, completion, packet, reviewer as wire_reviewer

    live_id = "1d0b897c21b1d07101efff97"
    retracted_id = "db4deae2b06e4b086d6ef8a2"
    cov = {
        "prior_story": None,
        "recent": [
            {"id": live_id, "title": "Protocol crash reported", "summary": "Crash in parser.",
             "category": "security", "state": "developing", "updated_at": LATER,
             "summary_truncated": False, "products": ["tor"]},
            {"id": retracted_id, "title": "Withdrawn mirror claim", "retracted": True},
        ],
        "truncated": False,
    }

    dup_skip = verdict("skip", criterion="new_information")
    dup_skip["criteria"]["new_information"]["reason"] = f"Already covered by {live_id}."
    res_dup = wire_reviewer(monkeypatch, completion(dup_skip)).review(story_candidate(), packet(), coverage=cov)
    assert res_dup["verdict"] == "skip"
    assert res_dup["same_story"] == live_id

    ret_skip = verdict("skip", criterion="new_information")
    ret_skip["criteria"]["news_value"]["outcome"] = "fail"
    ret_skip["criteria"]["new_information"]["reason"] = f"Repeats retracted story {retracted_id}."
    res_ret = wire_reviewer(monkeypatch, completion(ret_skip)).review(story_candidate(), packet(), coverage=cov)
    assert res_ret["verdict"] == "hold"
    assert res_ret["model_verdict"] == "skip"
    assert res_ret["same_story"] is None
