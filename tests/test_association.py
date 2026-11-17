"""Deterministic item-to-story association, coverage background, and same_story routing."""

import json

import pytest

from helpers import (
    DATE, LATER, FakeLLM, Reviewer, Writer, analysis, completion, finish_reviewed,
    insert_approval, item, pending, run_gate, update_analysis, verdict,
)
from onionflash import candidate, editorial, rejection, review, review_gate
from onionflash.analyze import tag_notice
from onionflash.config import DEFAULTS
from onionflash.util import digest, gitlab_refs, item_cluster, release_mentions, story_cluster, thread_subject

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
            "id": "n1", "author": "dev", "created_at": DATE,
            "url": "https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/1080#note_1",
            "title": "Comment", "body": "Closes #99999 in a comment is only a mention, not an MR header close.",
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
            "id": "n1", "author": "op", "created_at": DATE,
            "url": "https://gitlab.torproject.org/tpo/network-health/analysis/-/issues/1#note_1",
            "title": "Comment", "body": "Also tested arti 2.8.0 and Tor 0.4.9.16 on staging.",
        }],
    )
    assert release_mentions(mentions_item) == ["release:tor:0.4.9.16", "release:tor-browser:16.0", "release:arti:2.8.0"]
    assert release_mentions(item(title="", content="Operators upgraded to Tor 0.4.9.16.")) == ["release:tor:0.4.9.16"]
    assert release_mentions(item(title="", content="Operators upgraded to Tor Browser 16.0.1.")) == ["release:tor-browser:16.0.1"]
    assert release_mentions(item(title="", content="Malformed build Tor 0.4.9.16.1.")) == []

    assert thread_subject(item(url=LIST_BASE + "ABC/", title="[tor-relays] Re: re. Guard flag drop across relays")) == (
        "guard flag drop across relays", True
    )
    assert thread_subject(item(url=LIST_BASE + "DEF/", title="[tor-relays] Fwd: Guard flag drop across relays")) == (
        "guard flag drop across relays", False
    )
    assert thread_subject(item(url=LIST_BASE + "SHORT/", title="[tor-relays] Re: Short subject")) == (None, True)
    assert thread_subject(item(url="https://blog.torproject.org/post/", title="Re: Guard flag drop across relays")) == (None, False)


def test_gitlab_refs_ignore_malformed_urls_and_normalize_project_case():
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


def test_associate_precedence_and_ambiguous_fallbacks(store):
    s1 = _publish(store, item(url=LIST_BASE + "M1/", source_id="tor-relays", title="[tor-relays] Consensus bandwidth drop across relays"))
    s2 = _publish(store, item(url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/41339", kind="gitlab_issue",
                              title="Relay crash in circuit padding", content="Crash details " + "x" * 200))
    s3 = _publish(store, item(url="https://example.org/s3", title="Tor 1.2.3 released"))
    s4 = _publish(store, item(url="https://example.org/s4", title="Distinct story four"))

    reply_only = item(kind="feed", source_id="tor-relays", url=LIST_BASE + "M2A/",
                      title="[tor-relays] Re: Consensus bandwidth drop across relays",
                      content="Closes tpo/core/tor#41339 with full details.",
                      published_at="2026-11-09T12:00:00Z", updated_at="2026-11-09T12:00:00Z")
    store.ingest(reply_only, LATER)
    r_thread = next(r for r in store.pending(20, LATER) if r["url"] == reply_only["url"])
    assert candidate.associate(store.db, r_thread) == (
        dict(store.db.execute("SELECT * FROM stories WHERE id=?", (s1["id"],)).fetchone()), "thread"
    )

    probe = item(kind="gitlab_mr", upstream_state="merged", source_id="tor-relays", url=LIST_BASE + "M2/",
                 title="[tor-relays] Re: Consensus bandwidth drop across relays",
                 content="Closes tpo/core/tor#41339 with full details.",
                 published_at="2026-11-09T12:00:00Z", updated_at="2026-11-09T12:00:00Z")
    store.ingest(probe, LATER)
    r_close = next(r for r in store.pending(20, LATER) if r["id"] == probe["id"])
    matched, how = candidate.associate(store.db, r_close)
    assert matched["id"] == s2["id"] and how == "closing_ref"

    with store.db:
        store.db.execute("UPDATE items SET cluster_key='custom:shared' WHERE story_id=?", (s4["id"],))
    matched, how = candidate.associate(store.db, {**r_close, "cluster_key": "custom:shared"})
    assert matched["id"] == s4["id"] and how == "item_cluster"

    matched, how = candidate.associate(store.db, {**r_close, "cluster_key": "release:tor:1.2.3"})
    assert matched["id"] == s3["id"] and how == "cluster"

    with store.db:
        store.db.execute(
            "INSERT INTO story_aliases(story_id,cluster_key,survivor_id,reason,created_at) VALUES(?,?,?,?,?)",
            ("retired00000000000000000", "alias:key", s4["id"], "merged", LATER),
        )
    matched, how = candidate.associate(store.db, {**r_close, "cluster_key": "alias:key"})
    assert matched["id"] == s4["id"] and how == "alias"
    matched, how = candidate.associate(store.db, {**r_close, "story_id": s1["id"], "cluster_key": "alias:key"})
    assert matched["id"] == s1["id"] and how == "story_id"

    second_crash = _publish(store, item(url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/41340", kind="gitlab_issue",
                                        title="Second crash issue", content="Different crash " + "y" * 200))
    ambig_mr = item(kind="gitlab_mr", upstream_state="merged",
                    url="https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/1099",
                    title="Fix two crashes (closes #41339 and #41340)", content="Fixes #41339, #41340.")
    store.ingest(ambig_mr, LATER)
    r_ambig = next(r for r in store.pending(20, LATER) if r["id"] == ambig_mr["id"])
    assert candidate.associate(store.db, r_ambig) == (None, None)
    rel_ids = [sid for sid, _ in candidate.related(store.db, r_ambig, ambig_mr)]
    assert s2["id"] in rel_ids and second_crash["id"] in rel_ids


def test_remapped_item_cluster_associates_to_survivor_without_recreating_removed_id(store):
    body = "Operators report sustained descriptor upload timeouts across multiple directory authorities " + ("detail " * 20)
    first = item(kind="gitlab_issue", url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/501",
                 title="authority: Descriptor upload timeouts", content=body)
    dup_source = item(kind="gitlab_issue", url="https://gitlab.torproject.org/tpo/network-health/team/-/work_items/88",
                      title="dirauth: Descriptor upload timeouts", content=body)
    assert item_cluster(first) == item_cluster(dup_source) and item_cluster(first).startswith("body:")
    removed_id = digest("url:synthetic-removed-duplicate")[:24]

    survivor = _publish(store, item(url="https://example.org/survivor", title="Directory authority upload timeouts"))
    store.ingest(first, DATE)
    with store.db:
        store.db.execute("UPDATE items SET status='published',story_id=? WHERE id=?", (survivor["id"], first["id"]))
    store.ingest(dup_source, LATER)
    row = next(r for r in store.pending(10, LATER) if r["id"] == dup_source["id"])
    matched, how = candidate.associate(store.db, row)
    assert matched["id"] == survivor["id"] and how == "item_cluster"
    prepared = store.prepare_candidate(row, update_analysis(update="Follow-up details.",
                                                            evidence=["sustained descriptor upload timeouts"]), LATER)
    assert prepared["candidate"]["id"] == survivor["id"] != removed_id


@pytest.mark.parametrize("title", ["Security Release 0.4.9.17", "Tor 0.4.9.17 released"])
def test_release_announcement_can_publish_distinct_incident_development(context, title):
    cfg, store = context
    tag = item(kind="tag", authority="official", title="tor-0.4.9.17", content="",
               url="https://gitlab.torproject.org/tpo/core/tor/-/tags/tor-0.4.9.17")
    release = _publish(store, tag)
    incoming = item(kind="feed", authority="official", product="tor", title=title,
                    url="https://forum.torproject.org/t/security-release-0-4-9-17/22454",
                    content="The announcement describes an ongoing relay attack and evaluation of further defenses.")
    row = pending(store, incoming)
    assert row["cluster_key"] == "release:tor:0.4.9.17"
    assert candidate.associate(store.db, row) == (None, None)
    draft = analysis(title="Tor evaluates additional defenses against relay attack", summary=incoming["content"],
                     why_it_matters="", category="dos", tags=["dos"], confidence="confirmed",
                     evidence=[incoming["content"]])
    prepared = store.prepare_candidate(row, draft, LATER)
    assert prepared["coverage"]["prior_story"] is None
    assert prepared["cluster_key"] == story_cluster(incoming)
    assert prepared["cluster_key"].startswith("url:")
    assert (release["id"], "mentions tor 0.4.9.17") in candidate.related(store.db, row, incoming)
    assert run_gate(cfg, store, row, Writer(draft), Reviewer(verdict()))["status"] == "published"
    assert len(store.stories()) == 2
    original = next(s for s in store.stories() if s["id"] == release["id"])
    assert original == release


def test_feed_first_release_hints_find_release_but_never_attach_tag_to_response_story(store):
    response = item(kind="feed", authority="official", product="tor", title="Security Release 0.4.9.17",
                    url="https://example.org/response", content="Additional relay defenses are under evaluation.")
    response_story = _publish(store, response, analysis(title="Further relay defenses under evaluation",
                              summary=response["content"], why_it_matters="", category="dos", tags=["dos"],
                              evidence=[response["content"]]))
    tag = item(kind="tag", authority="official", title="tor-0.4.9.17", content="",
               url="https://gitlab.torproject.org/tpo/core/tor/-/tags/tor-0.4.9.17")
    row = pending(store, tag)
    assert candidate.associate(store.db, row) == (None, None)
    assert (response_story["id"], "mentions tor 0.4.9.17") in candidate.related(store.db, row, tag)

    release = item(kind="feed", authority="official", product="tor", title="Tor 0.4.9.17 released",
                   url="https://example.org/release", content="Tor 0.4.9.17 is available with security fixes.")
    release_story = _publish(store, release, analysis(title=release["title"], summary=release["content"],
                             why_it_matters="", category="release", tags=["release"], state="released",
                             confidence="confirmed", evidence=[release["content"]]))
    matched, how = candidate.associate(store.db, row)
    assert matched["id"] == release_story["id"] and how == "item_cluster"

    repost = item(kind="feed", authority="official", product="tor", title="Security Release 0.4.9.17",
                  url="https://example.org/repost", content=release["content"])
    repost_row = pending(store, repost)
    assert candidate.associate(store.db, repost_row) == (None, None)
    assert {sid for sid, _ in candidate.related(store.db, repost_row, repost)} == {
        release_story["id"], response_story["id"]}


def test_tag_reviews_separately_when_legacy_response_owns_release_identity(context):
    cfg, store = context
    response = item(kind="feed", authority="official", title="Tor 0.4.9.17 released",
                    url="https://example.org/response", content="Additional relay defenses are under evaluation.")
    original = _publish(store, response, analysis(title="Further relay defenses under evaluation",
                        summary=response["content"], why_it_matters="", category="dos", tags=["dos"],
                        evidence=[response["content"]]))
    with store.db:
        store.db.execute("UPDATE stories SET cluster_key=? WHERE id=?", (item_cluster(response), original["id"]))
    tag = item(kind="tag", authority="official", title="tor-0.4.9.17", content="",
               url="https://gitlab.torproject.org/tpo/core/tor/-/tags/tor-0.4.9.17")
    row = pending(store, tag)
    assert candidate.associate(store.db, row) == (None, None)
    prepared = store.prepare_candidate(row, tag_notice(tag), LATER)
    assert prepared["cluster_key"].startswith("url:")
    assert prepared["story_id"] != original["id"] and prepared["coverage"]["prior_story"] is None
    assert run_gate(cfg, store, row, Writer(tag_notice(tag)), Reviewer(verdict()))["status"] == "published"
    assert len(store.stories()) == 2
    assert next(s for s in store.stories() if s["id"] == original["id"]) == original
    tagged = next(s for s in store.stories() if s["id"] != original["id"])
    assert tagged["state"] == "tagged"

    mirror = {**tag, "url": "https://example.org/mirror-tag"}
    mirror_row = pending(store, mirror)
    assert candidate.associate(store.db, mirror_row)[0]["id"] == tagged["id"]
    outcome = run_gate(cfg, store, mirror_row, Writer(), Reviewer())
    assert outcome["status"] == "cited" and len(store.stories()) == 2


def test_tag_explicit_mapping_and_retirement_alias_preserve_existing_lifecycle(store):
    prior = _publish(store, item(url="https://example.org/merged-fix", kind="gitlab_mr", upstream_state="merged",
                                title="Merge relay defense", content="A relay defense was merged."),
                     analysis(title="Relay defense merged", summary="A relay defense was merged.",
                              state="merged", confidence="confirmed", why_it_matters=""))
    tag = item(kind="tag", authority="official", title="tor-0.4.9.17", content="",
               url="https://example.org/tag17")
    row = pending(store, tag)
    with store.db:
        store.db.execute("UPDATE items SET story_id=? WHERE id=?", (prior["id"], row["id"]))
    mapped = {**row, "story_id": prior["id"]}
    assert candidate.associate(store.db, mapped)[0]["id"] == prior["id"]
    with store.db:
        store.db.execute("UPDATE items SET story_id=NULL WHERE id=?", (row["id"],))
        store.db.execute(
            "INSERT INTO story_aliases(story_id,cluster_key,survivor_id,reason,created_at) VALUES(?,?,?,?,?)",
            ("a" * 24, row["cluster_key"], prior["id"], "Merged fixture", DATE))
    matched, how = candidate.associate(store.db, row)
    assert matched["id"] == prior["id"] and how == "alias"


@pytest.mark.parametrize("title", ["Tor 0.4.9.17 released", "Security Release 0.4.9.17"])
def test_announcement_repost_routes_to_reviewed_release_and_adds_only_citation(context, title):
    cfg, store = context
    release = item(kind="feed", authority="official", product="tor", title=title,
                   url="https://example.org/release", content="Tor 0.4.9.17 is available with security fixes.")
    draft = analysis(title=release["title"], summary=release["content"], why_it_matters="", category="release",
                     tags=["release"], state="released", confidence="confirmed", evidence=[release["content"]])
    original = _publish(store, release, draft)
    repost = item(kind="feed", authority="official", product="tor", title="Security Release 0.4.9.17",
                  url="https://example.org/repost", content=release["content"])
    reply = verdict("skip", criterion="new_information", same_story=original["id"])
    reply["criteria"]["new_information"]["reason"] = f"The release is already covered by {original['id']}."
    assert run_gate(cfg, store, pending(store, repost), Writer(draft), Reviewer(reply))["status"] == "routed"
    row = next(r for r in store.pending(20, LATER) if r["id"] == repost["id"])
    skip = verdict("skip", criterion="new_information", update=True)
    skip["criteria"]["new_information"]["reason"] = reply["criteria"]["new_information"]["reason"]
    update = update_analysis(update="Another announcement reports Tor 0.4.9.17 is available.",
                             state="released", confidence="confirmed", evidence=[release["content"]])
    assert run_gate(cfg, store, row, Writer(update), Reviewer(skip))["status"] == "ignored"
    assert len(store.stories()) == 1
    current = store.stories()[0]
    assert current["title"] == original["title"] and current["summary"] == original["summary"]
    assert not current.get("updates")
    assert {s["url"] for s in current["sources"]} == {release["url"], repost["url"]}


@pytest.mark.parametrize("summary", ["Tor 0.4.9.18 is available.", "Tor 0.4.9.18 supersedes Tor 0.4.9.17."])
@pytest.mark.parametrize("title", ["Tor 0.4.9.18 released", "Security Release 0.4.9.18",
                                   "Tor 0.4.9.18 released after Tor 0.4.9.17", "Tor security update"])
def test_release_announcement_cannot_route_to_a_different_released_version(context, summary, title):
    cfg, store = context
    older = item(kind="feed", authority="official", title=title,
                 url="https://example.org/release18", content=summary)
    target = _publish(store, older, analysis(title=older["title"], summary=older["content"],
                      why_it_matters="", category="release", tags=["release"], state="released",
                      confidence="confirmed", evidence=[older["content"]]))
    newer = item(kind="feed", authority="official", title="Tor 0.4.9.17 released",
                 url="https://example.org/release17", content="Tor 0.4.9.17 is available.")
    draft = analysis(title=newer["title"], summary=newer["content"], why_it_matters="", category="release",
                     tags=["release"], state="released", confidence="confirmed", evidence=[newer["content"]])
    outcome = run_gate(cfg, store, pending(store, newer), Writer(draft),
                       Reviewer(verdict(same_story=target["id"])))
    assert outcome["status"] == "published"
    assert len(store.stories()) == 2
    assert next(s for s in store.stories() if s["id"] == target["id"]) == target


@pytest.mark.parametrize("hint_stage", ["initial-approve", "late-approve", "late-revise"])
def test_material_official_announcement_stays_separate_despite_release_routing_hint(context, hint_stage):
    cfg, store = context
    release = item(kind="feed", authority="official", title="Tor 0.4.9.17 released",
                   url="https://example.org/release", content="Tor 0.4.9.17 is available with security fixes.")
    original = _publish(store, release, analysis(title=release["title"], summary=release["content"],
                        why_it_matters="", category="release", tags=["release"], state="released",
                        confidence="confirmed", evidence=[release["content"]]))
    incoming = item(kind="feed", authority="official", title="Security Release 0.4.9.17",
                    url="https://example.org/response", content="Additional defenses are being evaluated against the ongoing relay attack.")
    draft = analysis(title="Tor evaluates further relay attack defenses", summary=incoming["content"],
                     why_it_matters="", category="dos", tags=["dos"], state="developing",
                     confidence="confirmed", evidence=[incoming["content"]])
    hinted = verdict(same_story=original["id"])
    if hint_stage == "initial-approve":
        replies = [hinted, verdict()]
    elif hint_stage == "late-approve":
        replies = [verdict(), hinted]
    else:
        replies = [verdict(), verdict("revise", criterion="source_support", same_story=original["id"],
                                     repair={"summary": "Tor is evaluating further defenses against the continuing relay attack."}), hinted]
    row = pending(store, incoming)
    result = run_gate(cfg, store, row, Writer(draft), Reviewer(*replies))
    assert result["status"] == "published" and len(store.stories()) == 2
    assert next(s for s in store.stories() if s["id"] == original["id"]) == original
    fresh = next(s for s in store.stories() if s["id"] != original["id"])
    assert fresh["title"] == draft["title"] and fresh["state"] == "developing"
    assert not fresh.get("updates")
    assert store.db.execute("SELECT story_id FROM items WHERE id=?", (row["id"],)).fetchone()[0] == fresh["id"]


def test_later_novelty_disagreement_holds_before_same_story_routing(context):
    cfg, store = context
    release = item(kind="feed", authority="official", title="Tor 0.4.9.17 released",
                   url="https://example.org/release", content="Tor 0.4.9.17 is available with security fixes.")
    original = _publish(store, release, analysis(title=release["title"], summary=release["content"],
                        why_it_matters="", category="release", tags=["release"], state="released",
                        confidence="confirmed", evidence=[release["content"]]))
    incoming = item(kind="feed", authority="official", title="Security Release 0.4.9.17",
                    url="https://example.org/response", content="Additional defenses are being evaluated against the ongoing relay attack.")
    draft = analysis(title="Tor evaluates further relay attack defenses", summary=incoming["content"],
                     why_it_matters="", category="dos", tags=["dos"], state="developing",
                     confidence="confirmed", evidence=[incoming["content"]])
    duplicate = verdict("skip", criterion="new_information", same_story=original["id"])
    duplicate["criteria"]["new_information"]["reason"] = f"Already covered by {original['id']}."
    row = pending(store, incoming)
    result = run_gate(cfg, store, row, Writer(draft), Reviewer(verdict(), duplicate))
    assert result["status"] == "held" and store.stories() == [original]
    assert store.db.execute("SELECT story_id FROM items WHERE id=?", (row["id"],)).fetchone()[0] is None
    assert store.db.execute("SELECT code FROM decision_log WHERE item_id=? ORDER BY id DESC LIMIT 1",
                            (row["id"],)).fetchone()[0] == "held.verification.disagreed_news"


def test_mr_closing_and_list_reply_association_boundaries(store):
    issue_story = _publish(store, item(
        kind="gitlab_issue", url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/41339",
        title="Relay crash on malformed cell", content="A malformed cell triggers an assertion failure in relay handling.",
    ))
    other_issue = _publish(store, item(
        kind="gitlab_issue", url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/41466",
        title="Separate metrics counter bug", content="Metrics counters wrap on 32-bit targets.",
    ))
    closing_mr = item(kind="gitlab_mr", upstream_state="merged",
                      url="https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/2001",
                      title="Fix relay crash (closes #41339)", content="Resolves the assertion failure when parsing cells.")
    store.ingest(closing_mr, LATER)
    mr_row = next(r for r in store.pending(10, LATER) if r["id"] == closing_mr["id"])
    prepared = store.prepare_candidate(
        mr_row,
        update_analysis(update="Merged fix for #41339.", state="merged", confidence="confirmed",
                        evidence=["Resolves the assertion failure"]),
        LATER,
    )
    assert prepared["coverage"]["prior_story"]["id"] == issue_story["id"]
    assert prepared["coverage"]["prior_story"]["associated"] is True

    mention_only = item(kind="gitlab_mr", upstream_state="merged",
                        url="https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/2002",
                        title="Refactor counter helpers", content="Because of #41466 we keep 64-bit counters here.")
    store.ingest(mention_only, LATER)
    m_row = next(r for r in store.pending(10, LATER) if r["id"] == mention_only["id"])
    m_prep = store.prepare_candidate(
        m_row, analysis(title="Counter refactor", summary="64-bit counters.",
                        evidence=["Because of #41466 we keep 64-bit counters"]), LATER,
    )
    assert m_prep["coverage"]["prior_story"] is None
    assert (other_issue["id"], "references #41466") in [(e["id"], e.get("related")) for e in m_prep["coverage"]["recent"]]

    thread_story = _publish(store, item(
        source_id="tor-relays", url=LIST_BASE + "ROOT1/",
        title="[tor-relays] Exit relay throughput regression on Linux",
        published_at="2026-09-20T10:00:00Z", updated_at="2026-09-20T10:00:00Z",
    ), observed="2026-09-20T10:05:00Z")

    good_reply = item(source_id="tor-relays", url=LIST_BASE + "REP1/",
                      title="[tor-relays] Re: re. Exit relay throughput regression on Linux",
                      published_at="2026-10-25T10:00:00Z", updated_at="2026-10-25T10:00:00Z")
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


def test_relations_tag_citation_locked_hold_upgrade_and_update(context):
    cfg, store = context

    def route(incoming, draft, target_id):
        outcome = run_gate(cfg, store, pending(store, incoming), Writer(draft),
                           Reviewer(verdict(same_story=target_id)))
        assert outcome["status"] == "routed"
        return next(r for r in store.pending(20, LATER) if r["id"] == incoming["id"])

    tag_first = item(kind="tag", authority="official", title="tor-0.4.9.20", content="",
                     url="https://gitlab.torproject.org/tpo/core/tor/-/tags/tor-0.4.9.20")
    assert run_gate(cfg, store, pending(store, tag_first), Writer(tag_notice(tag_first)), Reviewer(verdict()))["status"] == "published"
    assert store.stories()[0]["state"] == "tagged"
    release_id = store.stories()[0]["id"]

    community_post = item(kind="feed", authority="community", title="Tor 0.4.9.20 released",
                          url="https://forum.example.org/tor-0-4-9-20", content="Community summary of Tor 0.4.9.20 changes.")
    comm_draft = analysis(title="Community note on Tor 0.4.9.20", summary="Community summary of Tor 0.4.9.20 changes.",
                          why_it_matters="Operators can review the reported Tor 0.4.9.20 changes.",
                          confidence="reported", state="released", category="release", tags=["tor", "release"],
                          evidence=["Community summary of Tor 0.4.9.20 changes."])
    assert run_gate(cfg, store, route(community_post, comm_draft, release_id),
                    Writer(comm_draft), Reviewer(verdict()))["status"] == "published"
    assert store.stories()[0]["title"] == "Community note on Tor 0.4.9.20"

    official_ann = item(kind="feed", authority="official", title="[tor-announce] [RELEASE] Tor release 0.4.9.20",
                        url="https://lists.torproject.org/tor-announce/0.4.9.20",
                        content="Official Tor 0.4.9.20 release announcement with security fixes.")
    ann_upd = update_analysis(update="Official announcement confirms Tor 0.4.9.20 with security fixes.",
                              confidence="confirmed", state="released",
                              evidence=["Official Tor 0.4.9.20 release announcement with security fixes."])
    # This downstream confidence-update check starts from a previously mapped source.
    ann_row = pending(store, official_ann)
    with store.db:
        store.db.execute("UPDATE items SET story_id=? WHERE id=?", (release_id, ann_row["id"]))
    ann_row["story_id"] = release_id
    assert run_gate(cfg, store, ann_row,
                    Writer(ann_upd), Reviewer(verdict(update=True)))["status"] == "published"
    after_ann = store.stories()[0]
    assert after_ann["title"] == "Community note on Tor 0.4.9.20"
    assert after_ann["summary"] == "Community summary of Tor 0.4.9.20 changes."
    assert after_ann["why_it_matters"] == "Operators can review the reported Tor 0.4.9.20 changes."
    assert after_ann["confidence"] == "confirmed"
    assert after_ann["updates"][-1]["text"] == "Official announcement confirms Tor 0.4.9.20 with security fixes."

    followup = item(kind="feed", authority="community", title="Tor 0.4.9.20 released: operator notes",
                    url="https://lists.torproject.org/tor-relays/0.4.9.20-notes",
                    content="Relay operators report clean upgrades on Debian bookworm.")
    upd_draft = update_analysis(update="Relay operators report clean upgrades on Debian bookworm.",
                                confidence="confirmed", state="released",
                                evidence=["Relay operators report clean upgrades on Debian bookworm."])
    followup_draft = analysis(title="Operator upgrade report", summary=followup["content"], why_it_matters="",
                              evidence=[followup["content"]])
    assert run_gate(cfg, store, route(followup, followup_draft, release_id),
                    Writer(upd_draft), Reviewer(verdict(update=True)))["status"] == "published"
    after_upd = store.stories()[0]
    assert after_upd["title"] == "Community note on Tor 0.4.9.20" and len(after_upd["updates"]) == 2
    assert after_upd["updates"][-1]["text"] == "People report clean upgrades on Debian bookworm."

    editorial.correct(store.db, after_upd["id"], {"title": after_upd["title"] + " (verified)"},
                      reason="Pin headline", expect_hash=editorial.show(store.db, after_upd["id"])["hash"])
    mirror_tag = item(kind="tag", authority="official", title="tor-0.4.9.20", content="",
                      url="https://gitlab.torproject.org/tpo/core/tor-mirror/-/tags/tor-0.4.9.20")
    locked_out = run_gate(cfg, store, pending(store, mirror_tag), Writer(), Reviewer())
    assert locked_out["status"] == "locked" and locked_out["writer_calls"] == 0 and locked_out["review_calls"] == 0
    assert editorial.show(store.db, after_upd["id"])["held_updates"] == 1

    timeline_item = item(kind="metrics_timeline", authority="official", title="Tor 0.4.9.21 released",
                         source_entry_id="tl-0.4.9.21",
                         url="https://gitlab.torproject.org/tpo/network-health/metrics/timeline/-/blob/main/README.md#21",
                         content="Timeline entry noting Tor 0.4.9.21.")
    tl_draft = analysis(title="Timeline entry for Tor 0.4.9.21", summary="Timeline entry noting Tor 0.4.9.21.",
                        confidence="confirmed", state="released", category="release", tags=["tor", "release"],
                        evidence=["Timeline entry noting Tor 0.4.9.21."])
    assert run_gate(cfg, store, pending(store, timeline_item), Writer(tl_draft), Reviewer(verdict()))["status"] == "published"
    timeline_id = next(s for s in store.stories() if "0.4.9.21" in s["title"])["id"]
    prose_after_tl = item(kind="feed", authority="community", title="Tor 0.4.9.21 released",
                          url="https://forum.example.org/tor-0-4-9-21",
                          content="Full release prose covering Tor 0.4.9.21 relay changes.")
    prose_draft = analysis(title="Tor 0.4.9.21 brings relay changes",
                           summary="Full release prose covering Tor 0.4.9.21 relay changes.",
                           confidence="confirmed", state="released", category="release", tags=["tor", "release"],
                           evidence=["Full release prose covering Tor 0.4.9.21 relay changes."])
    assert run_gate(cfg, store, route(prose_after_tl, prose_draft, timeline_id),
                    Writer(prose_draft), Reviewer(verdict()))["status"] == "published"
    assert next(s for s in store.stories() if "0.4.9.21" in s["title"])["title"] == "Tor 0.4.9.21 brings relay changes"


def test_coverage_activity_order_retracted_markers_truncation_and_reconsideration(context):
    cfg, store = context
    first = _publish(store, item(url="https://example.org/old-active", title="Old story later updated",
                                 published_at="2026-10-01T00:00:00Z", updated_at="2026-10-01T00:00:00Z"),
                     observed="2026-10-01T00:00:00Z")
    stories = []
    for idx in range(31):
        stamp = f"2026-10-{idx + 2:02d}T00:00:00Z" if idx < 29 else f"2026-11-0{idx - 28}T00:00:00Z"
        stories.append(_publish(store, item(url=f"https://example.org/s-{idx}", title=f"Story {idx:02d}",
                                            published_at=stamp, updated_at=stamp), observed=stamp))
    bg32 = candidate.coverage_background(store.db, None)
    assert len(bg32["recent"]) == 32 and bg32["truncated"] is False

    with store.db:
        store.db.execute("UPDATE stories SET updated_at='2026-11-10T18:00:00Z' WHERE id=?", (first["id"],))
    old_dated_new_run = _publish(
        store,
        item(url="https://example.org/added-now", title="Backfilled report added now",
             published_at="2026-10-03T00:00:00Z", updated_at="2026-10-03T00:00:00Z"),
        observed="2026-11-10T19:00:00Z",
    )
    bg33 = candidate.coverage_background(store.db, None)
    assert bg33["truncated"] is True and bg33["recent"][0]["id"] == old_dated_new_run["id"]
    assert bg33["recent"][1]["id"] == first["id"]

    prior_row = dict(store.db.execute("SELECT * FROM stories WHERE id=?", (first["id"],)).fetchone())
    bg_prior = candidate.coverage_background(store.db, prior_row)
    assert bg_prior["prior_story"]["id"] == first["id"]
    assert all(entry["id"] != first["id"] for entry in bg_prior["recent"])

    editorial.retract(store.db, stories[-1]["id"], reason="Withdrawn upstream",
                      expect_hash=editorial.show(store.db, stories[-1]["id"])["hash"], observed="2026-11-10T19:30:00Z")
    bg_ret = candidate.coverage_background(store.db, None)
    marker = next(entry for entry in bg_ret["recent"] if entry["id"] == stories[-1]["id"])
    assert marker == {"id": stories[-1]["id"], "title": stories[-1]["title"], "retracted": True}

    skipped_item = item(url="https://example.org/reconsider-me", title="Follow-up report on relays",
                        content="Routine follow-up mentioning Tor 0.4.9.16.")
    row = pending(store, skipped_item)
    skip_reply = verdict("skip", criterion="new_information")
    skip_reply["criteria"]["new_information"]["reason"] = f"Already covered by {stories[0]['id']}."
    with store.db:
        store.db.execute("UPDATE stories SET updated_at='2026-11-10T20:00:00Z' WHERE id=?", (stories[0]["id"],))
    assert run_gate(cfg, store, row, Writer(), Reviewer(skip_reply))["status"] == "ignored"

    for idx in range(40):
        stamp = f"2026-11-11T00:{idx:02d}:00Z"
        _publish(store, item(url=f"https://example.org/newer-{idx}", title=f"Newer story {idx}",
                             published_at=stamp, updated_at=stamp), observed=stamp)
    cur = store.db.execute("SELECT content_hash FROM items WHERE id=?", (skipped_item["id"],)).fetchone()
    rejection.retry_item(store, skipped_item["id"], cur["content_hash"], "Check again")
    retried_row = next(r for r in store.pending(10, "2026-11-12T00:00:00Z") if r["id"] == skipped_item["id"])
    prep = store.prepare_candidate(retried_row, analysis(), "2026-11-12T00:00:00Z")
    assert any(e["id"] == stories[0]["id"] for e in prep["coverage"]["recent"] if e.get("related") == "earlier decision")

    row_rev2 = pending(store, {**skipped_item, "content": "Updated upstream note mentioning Tor 0.4.9.16 with new logs."})
    prep_rev2 = store.prepare_candidate(row_rev2, analysis(), "2026-11-12T01:00:00Z")
    assert not [e for e in prep_rev2["coverage"]["recent"] if e.get("related") == "earlier decision"]
    assert any(e["title"] == "Newer story 39" for e in prep_rev2["coverage"]["recent"])


def test_same_story_routing_overlap_guards_and_cite_on_skip(context):
    cfg, store = context
    target = _publish(store, item(
        authority="official", url="https://lists.torproject.org/tor-relays/incident-1", product="tor",
        title="Directory authority overload on maatuska",
        content="Operators report sustained overload on directory authority maatuska.",
    ))
    unrelated = _publish(store, item(
        url="https://blog.torproject.org/tor-browser-ui-localization", product="tor-browser",
        title="Tor Browser interface translation update",
        content="New localization strings landed for Tor Browser mobile users.",
    ), draft=analysis(
        title="Tor Browser interface translation update",
        summary="New localization strings landed for Tor Browser mobile users.",
        products=["tor-browser"], why_it_matters="",
        evidence=["New localization strings landed for Tor Browser mobile users"],
    ))

    cross_channel = item(
        authority="official", product="tor", url="https://blog.torproject.org/maatuska-followup",
        title="Update on maatuska directory authority load",
        content="Tor 0.4.9.16 mitigated the maatuska authority overload with a new consensus method.",
    )
    out1 = run_gate(cfg, store, pending(store, cross_channel), Writer(analysis(
        title="Maatuska overload mitigated", summary="Tor 0.4.9.16 mitigated the maatuska authority overload.",
        evidence=["mitigated the maatuska authority overload"],
    )), Reviewer(verdict("approve", same_story=target["id"])))
    assert out1["status"] == "routed" and len(store.stories(10)) == 2
    requeued = next(r for r in store.pending(10, LATER) if r["id"] == cross_channel["id"])
    assert requeued["story_id"] == target["id"]

    out2 = run_gate(
        cfg, store, requeued,
        Writer(update_analysis(update="Tor 0.4.9.16 mitigated the maatuska authority overload.",
                               evidence=["mitigated the maatuska authority overload"])),
        Reviewer(verdict("approve", update=True)),
    )
    assert out2["status"] == "published"
    updated_target = json.loads(store.db.execute("SELECT payload FROM stories WHERE id=?", (target["id"],)).fetchone()[0])
    assert updated_target["updates"][-1]["text"] == "Tor 0.4.9.16 mitigated the maatuska authority overload."

    distinct_tor = item(product="arti", url="https://gitlab.torproject.org/tpo/core/arti/-/work_items/777",
                        title="Arti RPC socket permission check on BSD",
                        content="Arti RPC sockets reject group-writable directories on FreeBSD.")
    bad_route = verdict("skip", criterion="new_information", same_story=unrelated["id"])
    bad_route["criteria"]["new_information"]["reason"] = f"Covered by {unrelated['id']}."
    out_bad = run_gate(cfg, store, pending(store, distinct_tor), Writer(analysis(
        title="Arti RPC socket check", summary="Arti RPC sockets reject group-writable directories.",
        products=["arti"], evidence=["Arti RPC sockets reject group-writable directories"],
    )), Reviewer(bad_route))
    assert out_bad["status"] == "ignored"
    assert store.db.execute("SELECT story_id FROM items WHERE id=?", (distinct_tor["id"],)).fetchone()[0] is None

    pkt = {"sources": [{"id": "S1", "passages": [{"id": "S1:P1", "text": "Evidence"}]}]}
    with pytest.raises(review.ReviewError, match="same_story"):
        review.validate_review(
            verdict("skip", criterion="new_information", ref="S1:P1", same_story="not-in-coverage"), pkt,
            coverage={"prior_story": None, "recent": [{"id": target["id"], "title": "T", "summary": "S"}]},
        )
    ignored_same = review.validate_review(
        verdict("skip", criterion="new_information", ref="S1:P1", update=True, same_story=target["id"]), pkt,
        update=True, coverage={"prior_story": {"id": target["id"], "title": "T", "summary": "S"}, "recent": []},
    )
    assert ignored_same["same_story"] is None

    rel_story = _publish(store, item(
        authority="official", url="https://lists.torproject.org/tor-announce/tor-1.9.0",
        title="[tor-announce] [RELEASE] Tor release 1.9.0", content="Tor 1.9.0 is released with relay stability fixes.",
    ))
    before_updated = rel_story["updated_at"]
    mirror_ok = item(authority="official", url="https://blog.torproject.org/tor-1-9-0",
                     title="New Release: Tor 1.9.0", content="Tor 1.9.0 is now available with relay stability fixes.")
    skip_dup = verdict("skip", criterion="new_information", update=True)
    skip_dup["criteria"]["new_information"]["reason"] = f"Already covered in {rel_story['id']}."
    assert run_gate(cfg, store, pending(store, mirror_ok), Writer(update_analysis(evidence=["Tor 1.9.0 is now available"])),
                    Reviewer(skip_dup))["status"] == "ignored"
    after_ok = json.loads(store.db.execute("SELECT payload FROM stories WHERE id=?", (rel_story["id"],)).fetchone()[0])
    assert len(after_ok["sources"]) == 2 and after_ok["updated_at"] == before_updated

    mirror_low = item(authority="community", url="https://forum.example.org/tor-1-9-0",
                      title="Tor 1.9.0 released", content="Short mirror repost of Tor 1.9.0.")
    skip_both = verdict("skip", criterion="new_information", update=True)
    skip_both["criteria"]["new_information"]["reason"] = f"Already covered in {rel_story['id']}."
    skip_both["criteria"]["news_value"]["outcome"] = "fail"
    assert run_gate(cfg, store, pending(store, mirror_low),
                    Writer(update_analysis(evidence=["Short mirror repost of Tor 1.9.0."])),
                    Reviewer(skip_both))["status"] == "ignored"
    assert len(json.loads(store.db.execute("SELECT payload FROM stories WHERE id=?", (rel_story["id"],)).fetchone()[0])["sources"]) == 2

    routed_q = item(authority="community", url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/99190",
                    kind="gitlab_issue", product="tor", title="Question after upgrading relay",
                    content="Thanks +1, everything works fine on my BSD box.")
    row_q = pending(store, routed_q)
    with store.db:
        store.db.execute("UPDATE items SET story_id=? WHERE id=?", (rel_story["id"], routed_q["id"]))
    row_q = next(r for r in store.pending(10, LATER) if r["id"] == routed_q["id"])
    skip_q = verdict("skip", criterion="new_information", update=True)
    skip_q["criteria"]["new_information"]["reason"] = f"Routine question on {rel_story['id']}."
    assert run_gate(cfg, store, row_q, Writer(update_analysis(evidence=["everything works fine on my BSD box"])),
                    Reviewer(skip_q))["status"] == "ignored"
    assert len(json.loads(store.db.execute("SELECT payload FROM stories WHERE id=?", (rel_story["id"],)).fetchone()[0])["sources"]) == 2


def test_official_unroutable_skip_verifies_then_holds(store):
    surv = _publish(store, item(url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/501", kind="gitlab_issue",
                                title="Relay descriptor parsing issue #501",
                                content="Initial report of relay descriptor parsing issue."))
    rel_item = item(url="https://blog.torproject.org/new-release-tor-0499/", title="New Release: Tor 0.4.9.9",
                    content="Tor 0.4.9.9 fixes a relay crash tracked in #501.",
                    published_at=LATER, updated_at=LATER, authority="official", product="tor")
    store.ingest(rel_item, LATER)
    rel_row = next(r for r in store.pending(10, LATER) if "0499" in r["url"])
    assert rel_row["cluster_key"] == "release:tor:0.4.9.9"
    prepared = store.prepare_candidate(
        rel_row,
        analysis(title="Tor 0.4.9.9 released", summary="Tor 0.4.9.9 fixes a relay crash.", why_it_matters="",
                 category="release", confidence="confirmed", state="released", products=["tor"], tags=["release"],
                 evidence=["Tor 0.4.9.9 fixes a relay crash"]),
        LATER,
    )
    skip_res = verdict("skip", criterion="new_information", same_story=surv["id"])
    skip_res["criteria"]["new_information"]["reason"] = f"Already covered in {surv['id']}."
    rev1 = {"stage": "review", "candidate_hash": digest(prepared["candidate"]), "result": skip_res}
    assert review_gate.next_step([rev1], prepared["candidate"], prepared)[0] == "verify"
    rev2 = {"stage": "verification", "candidate_hash": digest(prepared["candidate"]), "result": skip_res}
    assert review_gate.next_step([rev1, rev2], prepared["candidate"], prepared) == ("hold", ("verification", "model_hold"))


def test_commit_candidate_lock_recheck_and_unverified_route_isolation_and_cleanup(context):
    cfg, store = context
    host = _publish(store, item(url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/700", kind="gitlab_issue",
                                title="Relay circuit timeout bug #700",
                                content="Operators reported relay circuit timeout bug."))
    host_id = host["id"]
    upd_item = item(url="https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/701", kind="gitlab_mr",
                    title="Fix relay circuit timeout", content="Closes #700 with a circuit timeout fix.",
                    published_at=LATER, updated_at=LATER, upstream_state="merged")
    store.ingest(upd_item, LATER)
    upd_row = next(r for r in store.pending(10, LATER) if "701" in r["url"])
    upd_draft = update_analysis(update="A merge request merged a fix for the circuit timeout.",
                                confidence="confirmed", state="merged",
                                evidence=["Closes #700 with a circuit timeout fix."])
    prepared = store.prepare_candidate(upd_row, upd_draft, LATER)
    pol = review.policy_hash(cfg)
    receipt = insert_approval(store, prepared, key=digest(["ak", upd_row["id"]]), policy=pol,
                              result=verdict("approve", update=True), record={}, created_at=LATER)
    editorial.correct(store.db, host_id, {"why_it_matters": "Locked mid-flight."},
                      reason="Lock before commit.", expect_hash=editorial.show(store.db, host_id)["hash"], observed=LATER)
    with pytest.raises(candidate.StaleCandidate):
        store.commit_candidate(prepared, prepared["candidate"], "wk", LATER, **receipt)

    editorial.unlock(store.db, host_id, reason="Unlock for routing test.",
                     expect_hash=editorial.show(store.db, host_id)["hash"], observed="2026-11-10T13:05:00Z")
    unrel = item(url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/999", kind="gitlab_issue",
                 title="Unrelated issue 999", content="Completely unrelated discussion text for testing.",
                 published_at=LATER, updated_at=LATER)
    store.ingest(unrel, LATER)
    unrel_row = next(r for r in store.pending(10, LATER) if "999" in r["url"])
    with store.db:
        store.db.execute("UPDATE items SET story_id=?,last_error=? WHERE id=?",
                         (host_id, candidate.UNVERIFIED_ROUTE, unrel_row["id"]))
    assert candidate._stories_for_urls(store.db, [unrel_row["url"]]) == []

    requeued_700 = item(url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/700", kind="gitlab_issue",
                        title="Relay circuit timeout bug #700",
                        content="Operators reported relay circuit timeout bug with follow-up reproduction steps.",
                        published_at=DATE, updated_at="2026-11-10T13:06:00Z")
    assert store.ingest(requeued_700, "2026-11-10T13:06:00Z") is True
    assert tuple(store.db.execute("SELECT status,last_error,story_id FROM items WHERE url=?",
                                  (requeued_700["url"],)).fetchone()) == ("pending", None, host_id)
    assert [s["id"] for s in candidate._stories_for_urls(store.db, [requeued_700["url"]])] == [host_id]

    unrel_row = next(r for r in store.pending(10, LATER) if r["id"] == unrel_row["id"])
    skip_prep = store.prepare_candidate(unrel_row, upd_draft, "2026-11-10T13:10:00Z")
    skip_rev = verdict("skip", criterion="new_information", update=True)
    skip_receipt = insert_approval(
        store, skip_prep, key=digest(["sk", unrel_row["id"]]), policy=pol, result=skip_rev,
        record={"reviews": [{"stage": "review", "result": skip_rev}]}, created_at=LATER,
    )
    store.commit_candidate(skip_prep, skip_prep["candidate"], "wk-skip", "2026-11-10T13:10:00Z",
                           decision="skip", **skip_receipt)
    assert store.db.execute("SELECT story_id FROM items WHERE id=?", (unrel_row["id"],)).fetchone()[0] is None


def test_wire_reviewer_populates_same_story_from_single_duplicate_reason_and_holds_retracted_mirror(monkeypatch):
    cfg = {**DEFAULTS, "llm": {**DEFAULTS["llm"], "base_url": "https://llm.example/v1"}}
    pkt = {
        "truncated": False, "missing_sources": [],
        "sources": [{"id": "S1", "kind": "gitlab_issue", "authority": "development", "product": "tor",
                     "published_at": DATE, "updated_at": DATE, "url": "https://example.org/news/1",
                     "title": "A reported security incident", "snapshot": "current",
                     "passages": [{"id": "S1:P1", "text": "A reported security incident"},
                                  {"id": "S1:P2", "text": "The operator reported a plausible compromise."}]}],
    }
    story_cand = {
        "id": "a" * 24, "title": "Operator reports possible compromise",
        "summary": "The operator reported a plausible compromise.",
        "why_it_matters": "The report concerns directory authority trust.",
        "category": "security", "priority": "high", "confidence": "reported", "state": "developing",
        "products": ["tor"], "tags": ["security"], "published_at": DATE, "updated_at": DATE,
        "sources": [{"url": "https://example.org/news/1", "title": "A reported security incident"}],
    }
    live_id, retracted_id = "1d0b897c21b1d07101efff97", "db4deae2b06e4b086d6ef8a2"
    cov = {
        "prior_story": None, "truncated": False,
        "recent": [
            {"id": live_id, "title": "Protocol crash reported", "summary": "Crash in parser.",
             "category": "security", "state": "developing", "updated_at": LATER,
             "summary_truncated": False, "products": ["tor"]},
            {"id": retracted_id, "title": "Withdrawn mirror claim", "retracted": True},
        ],
    }

    dup_skip = verdict("skip", criterion="new_information", ref="S1:P2")
    dup_skip["criteria"]["new_information"]["reason"] = f"Already covered by {live_id}."
    ret_skip = verdict("skip", criterion="new_information", ref="S1:P2")
    ret_skip["criteria"]["news_value"]["outcome"] = "fail"
    ret_skip["criteria"]["new_information"]["reason"] = f"Repeats retracted story {retracted_id}."

    llm = FakeLLM(completion(dup_skip), completion(ret_skip))
    monkeypatch.setenv("ONIONFLASH_LLM_API_KEY", "test-key")
    monkeypatch.setattr("onionflash.llm.HttpClient", lambda *_a, **_kw: llm)
    with review.Reviewer(cfg) as wire_reviewer:
        res_dup = wire_reviewer.review(story_cand, pkt, coverage=cov)
        res_ret = wire_reviewer.review(story_cand, pkt, coverage=cov)
    assert res_dup["verdict"] == "skip" and res_dup["same_story"] == live_id
    assert res_ret["verdict"] == "hold" and res_ret["model_verdict"] == "skip" and res_ret["same_story"] is None
