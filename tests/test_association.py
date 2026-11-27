"""Deterministic item-to-story association, coverage background, and same_story routing."""

import pytest

from helpers import (
    DATE, LATER, STORY, Reviewer, Writer, analysis, editorial_act, insert_approval, item, make_note,
    pending, queued_row, run_gate, seed_source_story, story_payload, update_analysis, verdict,
    wire_reviewer,
)
from onionflash import candidate, editorial, rejection, review, review_gate, source_packet
from onionflash.analyze import tag_notice
from onionflash.config import DEFAULTS
from onionflash.render import prepare_story
from onionflash.util import (
    cve_ids, digest, duplicate_issue_refs, gitlab_refs, item_cluster, release_mentions,
    story_cluster, thread_subject,
)

LIST_BASE = "https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/message/"
OTHER_LIST_BASE = "https://lists.torproject.org/mailman3/hyperkitty/list/tor-dev@lists.torproject.org/message/"


def test_pure_reference_release_mention_and_thread_helpers():
    """Extract GitLab closing/mentioned refs, normalized release mentions, and list thread subjects."""
    mr = item(
        kind="gitlab_mr",
        url="https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/1080",
        title="Fix relay crash (closes #41339, resolves tpo/core/arti#99)",
        content="Follow-up to !1075 and https://gitlab.torproject.org/tpo/core/tor/-/issues/41466.",
        public_comments=[
            make_note(
                1,
                "Closes #99999 in a comment is only a mention, not an MR header close.",
                author="dev",
                url="https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/1080",
            )
        ],
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
        public_comments=[
            make_note(
                1,
                "Also tested arti 2.8.0 and Tor 0.4.9.16 on staging.",
                author="op",
                url="https://gitlab.torproject.org/tpo/network-health/analysis/-/issues/1",
            )
        ],
    )
    assert release_mentions(mentions_item) == ["release:tor:0.4.9.16", "release:tor-browser:16.0", "release:arti:2.8.0"]
    assert release_mentions(item(title="", content="Operators upgraded to Tor 0.4.9.16.")) == ["release:tor:0.4.9.16"]
    assert release_mentions(item(title="", content="Operators upgraded to Tor Browser 16.0.1.")) == ["release:tor-browser:16.0.1"]
    assert release_mentions(item(title="", content="Malformed build Tor 0.4.9.16.1.")) == []
    assert release_mentions(item(title="Tor v0.4.9.16", content="")) == ["release:tor:0.4.9.16"]

    assert thread_subject(item(url=LIST_BASE + "ABC/", title="[tor-relays] Re: re. Guard flag drop across relays")) == (
        "guard flag drop across relays", True
    )
    assert thread_subject(item(url=LIST_BASE + "DEF/", title="[tor-relays] Fwd: Guard flag drop across relays")) == (
        "guard flag drop across relays", False
    )
    assert thread_subject(item(url=LIST_BASE + "SHORT/", title="[tor-relays] Re: Short subject")) == (None, True)
    assert thread_subject(item(url="https://blog.torproject.org/post/", title="Re: Guard flag drop across relays")) == (None, False)


@pytest.mark.parametrize("title,product,version", [
    ("Tor releases 0.4.9.16 emergency fix for directory authority thundering herd", "tor", "0.4.9.16"),
    ("Tor releases stable version 0.4.9.17", "tor", "0.4.9.17"),
    ("Tor releases v0.4.9.16", "tor", "0.4.9.16"),
    ("Tor releases stable version v0.4.9.17", "tor", "0.4.9.17"),
    ("Tor v0.4.9.16 released", "tor", "0.4.9.16"),
    ("Arti releases 2.8.0", "arti", "2.8.0"),
    ("Arti releases v2.8.0", "arti", "2.8.0"),
    ("Tor Browser releases 16.0a14", "tor-browser", "16.0a14"),
    ("Tor Browser releases v16.0a14", "tor-browser", "16.0a14"),
])
def test_releases_verb_supplies_consistent_hints_without_merging_prose(title, product, version):
    """Map release-verb titles to consistent `item_cluster` and `release_mentions` hints without merging prose."""
    incoming = item(kind="feed", product="network", title=title, content="Release announcement.")
    key = f"release:{product}:{version}"
    assert item_cluster(incoming) == key
    assert release_mentions(incoming) == [key]
    assert story_cluster(incoming).startswith("url:")


@pytest.mark.parametrize("title,mentions", [
    ("Tor releases 0.4.9.16 delayed", ["release:tor:0.4.9.16"]),
    ("Tor releases 0.4.9.16 postponed", ["release:tor:0.4.9.16"]),
    ("Tor releases 0.4.9.16 end-of-life notice", ["release:tor:0.4.9.16"]),
    ("Tor releases 0.4.9.16.1", []),
    ("Tor releases 0.4.9.16-unknown", []),
    ("Tor releases an advisory about 0.4.9.16", []),
    ("Tails 7.16 bundles Tor releases 0.4.9.16", ["release:tor:0.4.9.16"]),
])
def test_releases_verb_retains_conservative_release_identity_guards(title, mentions):
    """Keep release-verb clustering conservative on delayed, EOL, malformed, or embedded titles."""
    incoming = item(kind="feed", product="tor", title=title, content="")
    assert item_cluster(incoming).startswith("url:")
    assert release_mentions(incoming) == mentions


def test_gitlab_refs_ignore_malformed_urls_and_normalize_project_case():
    """Normalize mixed-case GitLab project paths and ignore malformed backslash URLs."""
    closing, mentioned = gitlab_refs({
        "url": "https://gitlab.torproject.org/tpo/core/tor/-/work_items/1",
        "title": "Fixes TPO/Core/Tor#123, closes HTTPS://gitlab.torproject.org/tpo/core/tor/-/issues/124",
        "content": (
            "Closes https://GitLab.TorProject.org/TPO/Core/Tor/-/issues/123. "
            "Related to TPO/Core/Tor#789, https://GitLab.TorProject.org/TPO/Core/Tor/-/issues/789, "
            "https://gitlab.torproject.org/a/../b/-/issues/999, "
            "and https://gitlab.torproject.org/foo\\bar/-/issues/456."
        ),
    })
    assert closing == [
        "https://gitlab.torproject.org/tpo/core/tor/-/work_items/123",
        "https://gitlab.torproject.org/tpo/core/tor/-/work_items/124",
    ]
    assert mentioned == ["https://gitlab.torproject.org/tpo/core/tor/-/work_items/789"]

    custom_closing, custom_mentioned = gitlab_refs({
        "url": "https://gitlab.example.org/grp/proj/-/work_items/1",
        "title": "Closes https://GitLab.Example.org/Grp/Proj/-/issues/55",
        "content": (
            "See https://gitlab.example.org/foo\\bar/-/issues/456 "
            "and https://gitlab.example.org/a/../b/-/issues/789."
        ),
    })
    assert custom_closing == ["https://gitlab.example.org/grp/proj/-/work_items/55"]
    assert custom_mentioned == []


def test_associate_precedence_and_ambiguous_fallbacks(store):
    """Order `candidate.associate` precedence across `story_id`, `closing_ref`, `thread`, `cluster`, and `alias`."""
    s1 = seed_source_story(store, item(url=LIST_BASE + "M1/", source_id="tor-relays", title="[tor-relays] Consensus bandwidth drop across relays"))
    s2 = seed_source_story(store, item(url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/41339", kind="gitlab_issue",
                                       title="Relay crash in circuit padding", content="Crash details " + "x" * 200))
    s3 = seed_source_story(store, item(url="https://example.org/s3", title="Tor 1.2.3 released"))
    s4 = seed_source_story(store, item(url="https://example.org/s4", title="Distinct story four"))

    reply_only = item(kind="feed", source_id="tor-relays", url=LIST_BASE + "M2A/",
                      title="[tor-relays] Re: Consensus bandwidth drop across relays",
                      content="Closes tpo/core/tor#41339 with full details.",
                      published_at="2026-11-09T12:00:00Z", updated_at="2026-11-09T12:00:00Z")
    r_thread = pending(store, reply_only, LATER)
    assert candidate.associate(store.db, r_thread) == (
        dict(store.db.execute("SELECT * FROM stories WHERE id=?", (s1["id"],)).fetchone()), "thread"
    )

    probe = item(kind="gitlab_mr", upstream_state="merged", source_id="tor-relays", url=LIST_BASE + "M2/",
                 title="[tor-relays] Re: Consensus bandwidth drop across relays",
                 content="Closes tpo/core/tor#41339 with full details.",
                 published_at="2026-11-09T12:00:00Z", updated_at="2026-11-09T12:00:00Z")
    r_close = pending(store, probe, LATER)
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

    second_crash = seed_source_story(store, item(url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/41340", kind="gitlab_issue",
                                                 title="Second crash issue", content="Different crash " + "y" * 200))
    ambig_mr = item(kind="gitlab_mr", upstream_state="merged",
                    url="https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/1099",
                    title="Fix two crashes (closes #41339 and #41340)", content="Fixes #41339, #41340.")
    r_ambig = pending(store, ambig_mr, LATER)
    assert candidate.associate(store.db, r_ambig) == (None, None)
    rel_ids = [sid for sid, _ in candidate.related(store.db, r_ambig, ambig_mr)]
    assert s2["id"] in rel_ids and second_crash["id"] in rel_ids


def test_remapped_item_cluster_associates_to_survivor_without_recreating_removed_id(store):
    """Associate body-clustered duplicates onto the survivor story without recreating retired IDs."""
    body = "Operators report sustained descriptor upload timeouts across multiple directory authorities " + ("detail " * 20)
    first = item(kind="gitlab_issue", url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/501",
                 title="authority: Descriptor upload timeouts", content=body)
    dup_source = item(kind="gitlab_issue", url="https://gitlab.torproject.org/tpo/network-health/team/-/work_items/88",
                      title="dirauth: Descriptor upload timeouts", content=body)
    assert item_cluster(first) == item_cluster(dup_source) and item_cluster(first).startswith("body:")
    removed_id = digest("url:synthetic-removed-duplicate")[:24]

    survivor = seed_source_story(store, item(url="https://example.org/survivor", title="Directory authority upload timeouts"))
    store.ingest(first, DATE)
    with store.db:
        store.db.execute("UPDATE items SET status='published',story_id=? WHERE id=?", (survivor["id"], first["id"]))
    row = pending(store, dup_source, LATER)
    matched, how = candidate.associate(store.db, row)
    assert matched["id"] == survivor["id"] and how == "item_cluster"
    prepared = store.prepare_candidate(row, update_analysis(update="Follow-up details.",
                                                            evidence=["sustained descriptor upload timeouts"]), LATER)
    assert prepared["candidate"]["id"] == survivor["id"] != removed_id


@pytest.mark.parametrize("title", ["Security Release 0.4.9.17", "Tor 0.4.9.17 released"])
def test_release_announcement_can_publish_distinct_incident_development(context, title):
    """Allow official release announcements with distinct incident-response facts to publish separately."""
    cfg, store = context
    tag = item(kind="tag", authority="official", title="tor-0.4.9.17", content="",
               url="https://gitlab.torproject.org/tpo/core/tor/-/tags/tor-0.4.9.17")
    release = seed_source_story(store, tag)
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
    """Keep tag notices from attaching to incident-response stories that mention the same release."""
    response = item(kind="feed", authority="official", product="tor", title="Security Release 0.4.9.17",
                    url="https://example.org/response", content="Additional relay defenses are under evaluation.")
    response_story = seed_source_story(store, response, analysis(title="Further relay defenses under evaluation",
                                       summary=response["content"], why_it_matters="", category="dos", tags=["dos"],
                                       evidence=[response["content"]]))
    tag = item(kind="tag", authority="official", title="tor-0.4.9.17", content="",
               url="https://gitlab.torproject.org/tpo/core/tor/-/tags/tor-0.4.9.17")
    row = pending(store, tag)
    assert candidate.associate(store.db, row) == (None, None)
    assert (response_story["id"], "mentions tor 0.4.9.17") in candidate.related(store.db, row, tag)

    release = item(kind="feed", authority="official", product="tor", title="Tor 0.4.9.17 released",
                   url="https://example.org/release", content="Tor 0.4.9.17 is available with security fixes.")
    release_story = seed_source_story(store, release, analysis(title=release["title"], summary=release["content"],
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
    """Review a version tag as its own story when a legacy non-release story owns the release key."""
    cfg, store = context
    response = item(kind="feed", authority="official", title="Tor 0.4.9.17 released",
                    url="https://example.org/response", content="Additional relay defenses are under evaluation.")
    original = seed_source_story(store, response, analysis(title="Further relay defenses under evaluation",
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
    """Honor explicit `story_id` mappings and retirement aliases for tags regardless of prior state."""
    prior = seed_source_story(store, item(url="https://example.org/merged-fix", kind="gitlab_mr", upstream_state="merged",
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


@pytest.mark.parametrize("title,version", [
    ("Tor 0.4.9.17 released", "0.4.9.17"),
    ("Security Release 0.4.9.17", "0.4.9.17"),
    ("Tor releases 0.4.9.16 emergency fix for directory authority thundering herd", "0.4.9.16"),
])
def test_announcement_repost_routes_to_reviewed_release_and_adds_only_citation(context, title, version):
    """Route duplicate release announcements to the existing story and record only a citation."""
    cfg, store = context
    release = item(kind="feed", authority="official", product="tor", title=title,
                   url="https://example.org/release", content=f"Tor {version} is available with security fixes.")
    draft = analysis(title=release["title"], summary=release["content"], why_it_matters="", category="release",
                     tags=["release"], state="released", confidence="confirmed", evidence=[release["content"]])
    original = seed_source_story(store, release, draft)
    repost = item(kind="feed", authority="official", product="tor", title=f"Security Release {version}",
                  url="https://example.org/repost", content=release["content"])
    reply = verdict("skip", criterion="new_information", same_story=original["id"])
    reply["criteria"]["new_information"]["reason"] = f"The release is already covered by {original['id']}."
    assert run_gate(cfg, store, pending(store, repost), Writer(draft), Reviewer(reply))["status"] == "routed"
    row = next(r for r in store.pending(20, LATER) if r["id"] == repost["id"])
    skip = verdict("skip", criterion="new_information", update=True)
    skip["criteria"]["new_information"]["reason"] = reply["criteria"]["new_information"]["reason"]
    update = update_analysis(update=f"Another announcement reports Tor {version} is available.",
                             state="released", confidence="confirmed", evidence=[release["content"]])
    assert run_gate(cfg, store, row, Writer(update), Reviewer(skip))["status"] == "ignored"
    assert len(store.stories()) == 1
    current = store.stories()[0]
    assert current["title"] == original["title"] and current["summary"] == original["summary"]
    assert not current.get("updates")
    assert {s["url"] for s in current["sources"]} == {release["url"], repost["url"]}


@pytest.mark.parametrize("summary", ["Tor 0.4.9.18 is available.", "Tor 0.4.9.18 supersedes Tor 0.4.9.17."])
@pytest.mark.parametrize("title", ["Tor 0.4.9.18 released", "Security Release 0.4.9.18",
                                   "Tor 0.4.9.18 released after Tor 0.4.9.17", "Tor security update",
                                   "Tor releases 0.4.9.18 after Tor 0.4.9.17"])
def test_release_announcement_cannot_route_to_a_different_released_version(context, summary, title):
    """Block `same_story` routing between different released versions."""
    cfg, store = context
    older = item(kind="feed", authority="official", title=title,
                 url="https://example.org/release18", content=summary)
    target = seed_source_story(store, older, analysis(title=older["title"], summary=older["content"],
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
    """Keep novel official incident-response announcements separate even when `same_story` targets the release."""
    cfg, store = context
    release = item(kind="feed", authority="official", title="Tor releases 0.4.9.17",
                   url="https://example.org/release", content="Tor 0.4.9.17 is available with security fixes.")
    original = seed_source_story(store, release, analysis(title=release["title"], summary=release["content"],
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
    """Hold on `disagreed_news` before routing if review and verification disagree on novelty."""
    cfg, store = context
    release = item(kind="feed", authority="official", title="Tor 0.4.9.17 released",
                   url="https://example.org/release", content="Tor 0.4.9.17 is available with security fixes.")
    original = seed_source_story(store, release, analysis(title=release["title"], summary=release["content"],
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
    """Distinguish closing MRs from mention-only MRs and enforce 45-day same-list thread reply bounds."""
    issue_story = seed_source_story(store, item(
        kind="gitlab_issue", url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/41339",
        title="Relay crash on malformed cell", content="A malformed cell triggers an assertion failure in relay handling.",
    ))
    other_issue = seed_source_story(store, item(
        kind="gitlab_issue", url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/41466",
        title="Separate metrics counter bug", content="Metrics counters wrap on 32-bit targets.",
    ))
    closing_mr = item(kind="gitlab_mr", upstream_state="merged",
                      url="https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/2001",
                      title="Fix relay crash (closes #41339)", content="Resolves the assertion failure when parsing cells.")
    mr_row = pending(store, closing_mr, LATER)
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
    m_row = pending(store, mention_only, LATER)
    m_prep = store.prepare_candidate(
        m_row, analysis(title="Counter refactor", summary="64-bit counters.",
                        evidence=["Because of #41466 we keep 64-bit counters"]), LATER,
    )
    assert m_prep["coverage"]["prior_story"] is None
    assert (other_issue["id"], "references #41466") in [(e["id"], e.get("related")) for e in m_prep["coverage"]["recent"]]

    thread_story = seed_source_story(store, item(
        source_id="tor-relays", url=LIST_BASE + "ROOT1/",
        title="[tor-relays] Exit relay throughput regression on Linux",
        published_at="2026-09-20T10:00:00Z", updated_at="2026-09-20T10:00:00Z",
    ), at="2026-09-20T10:05:00Z")

    good_reply = item(source_id="tor-relays", url=LIST_BASE + "REP1/",
                      title="[tor-relays] Re: re. Exit relay throughput regression on Linux",
                      published_at="2026-10-25T10:00:00Z", updated_at="2026-10-25T10:00:00Z")
    good_row = pending(store, good_reply, "2026-10-25T10:05:00Z")
    assert candidate.associate(store.db, good_row)[0]["id"] == thread_story["id"]

    for bad in (
        item(source_id="tor-relays", url=LIST_BASE + "NONREP/", title="[tor-relays] Exit relay throughput regression on Linux",
             published_at="2026-10-25T10:00:00Z", updated_at="2026-10-25T10:00:00Z"),
        item(source_id="tor-dev", url=OTHER_LIST_BASE + "OTHER/", title="[tor-dev] Re: Exit relay throughput regression on Linux",
             published_at="2026-10-25T10:00:00Z", updated_at="2026-10-25T10:00:00Z"),
        item(source_id="tor-relays", url=LIST_BASE + "OLD/", title="[tor-relays] Re: Exit relay throughput regression on Linux",
             published_at="2026-11-10T10:00:00Z", updated_at="2026-11-10T10:00:00Z"),
    ):
        bad_row = pending(store, bad, bad["updated_at"])
        assert candidate.associate(store.db, bad_row) == (None, None)


def test_relations_tag_citation_locked_hold_upgrade_and_update(context):
    """Handle tag/timeline upgrades, prose updates, and locked-story holds across release sources."""
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
    assert after_upd["updates"][-1]["text"] == "Relay operators report clean upgrades on Debian bookworm."

    editorial_act(editorial.correct, store, after_upd["id"], {"title": after_upd["title"] + " (verified)"}, reason="Pin headline")
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
    """Order `coverage_background` by recent activity, emit retracted markers, and pin reconsidered refs."""
    cfg, store = context
    first = seed_source_story(store, item(url="https://example.org/old-active", title="Old story later updated",
                                          published_at="2026-10-01T00:00:00Z", updated_at="2026-10-01T00:00:00Z"),
                              at="2026-10-01T00:00:00Z")
    stories = []
    for idx in range(39):
        stamp = f"2026-10-{idx + 2:02d}T00:00:00Z" if idx < 30 else f"2026-11-{idx - 29:02d}T00:00:00Z"
        stories.append(seed_source_story(store, item(url=f"https://example.org/s-{idx}", title=f"Story {idx:02d}",
                                                     published_at=stamp, updated_at=stamp), at=stamp))
    bg40 = candidate.coverage_background(store.db, None)
    assert len(bg40["recent"]) == 40 and bg40["truncated"] is False

    with store.db:
        store.db.execute("UPDATE stories SET updated_at='2026-11-10T18:00:00Z' WHERE id=?", (first["id"],))
    old_dated_new_run = seed_source_story(
        store,
        item(url="https://example.org/added-now", title="Backfilled report added now",
             published_at="2026-10-03T00:00:00Z", updated_at="2026-10-03T00:00:00Z"),
        at="2026-11-10T19:00:00Z",
    )
    bg41 = candidate.coverage_background(store.db, None)
    assert bg41["truncated"] is True and bg41["recent"][0]["id"] == old_dated_new_run["id"]
    assert bg41["recent"][1]["id"] == first["id"]

    prior_row = dict(store.db.execute("SELECT * FROM stories WHERE id=?", (first["id"],)).fetchone())
    bg_prior = candidate.coverage_background(store.db, prior_row)
    assert bg_prior["prior_story"]["id"] == first["id"]
    assert all(entry["id"] != first["id"] for entry in bg_prior["recent"])

    editorial_act(editorial.retract, store, stories[-1]["id"], reason="Withdrawn upstream", observed="2026-11-10T19:30:00Z")
    bg_ret = candidate.coverage_background(store.db, None)
    marker = next(entry for entry in bg_ret["recent"] if entry["id"] == stories[-1]["id"])
    assert marker == {"id": stories[-1]["id"], "title": stories[-1]["title"], "retracted": True}

    skipped_item = item(url="https://example.org/reconsider-me", title="Follow-up report on relays",
                        content="Routine follow-up mentioning Tor 0.4.9.16.")
    row = pending(store, skipped_item)
    skip_reply = verdict("skip", criterion="new_information", reason=f"Already covered by {stories[0]['id']}.")
    with store.db:
        store.db.execute("UPDATE stories SET updated_at='2026-11-10T20:00:00Z' WHERE id=?", (stories[0]["id"],))
    assert run_gate(cfg, store, row, Writer(), Reviewer(skip_reply))["status"] == "ignored"

    for idx in range(40):
        stamp = f"2026-11-11T00:{idx:02d}:00Z"
        seed_source_story(store, item(url=f"https://example.org/newer-{idx}", title=f"Newer story {idx}",
                                      published_at=stamp, updated_at=stamp), at=stamp)
    cur = store.db.execute("SELECT content_hash FROM items WHERE id=?", (skipped_item["id"],)).fetchone()
    rejection.retry_item(store, skipped_item["id"], cur["content_hash"], "Check again")
    retried_row = queued_row(store, skipped_item["id"], "2026-11-12T00:00:00Z")
    prep = store.prepare_candidate(retried_row, analysis(), "2026-11-12T00:00:00Z")
    assert any(e["id"] == stories[0]["id"] for e in prep["coverage"]["recent"] if e.get("related") == "earlier decision")

    row_rev2 = pending(store, {**skipped_item, "content": "Updated upstream note mentioning Tor 0.4.9.16 with new logs."})
    prep_rev2 = store.prepare_candidate(row_rev2, analysis(), "2026-11-12T01:00:00Z")
    assert not [e for e in prep_rev2["coverage"]["recent"] if e.get("related") == "earlier decision"]
    assert any(e["title"] == "Newer story 39" for e in prep_rev2["coverage"]["recent"])


def test_same_story_routing_overlap_guards_and_cite_on_skip(context):
    """Route valid `same_story` follow-ups, block product mismatches, and add citations only on verified mirrors."""
    cfg, store = context
    target = seed_source_story(store, item(
        authority="official", url="https://lists.torproject.org/tor-relays/incident-1", product="tor",
        title="Directory authority overload on maatuska",
        content="Operators report sustained overload on directory authority maatuska.",
    ))
    unrelated = seed_source_story(store, item(
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
    requeued = queued_row(store, cross_channel["id"], LATER)
    assert requeued["story_id"] == target["id"]

    out2 = run_gate(
        cfg, store, requeued,
        Writer(update_analysis(update="Tor 0.4.9.16 mitigated the maatuska authority overload.",
                               evidence=["mitigated the maatuska authority overload"])),
        Reviewer(verdict("approve", update=True)),
    )
    assert out2["status"] == "published"
    assert story_payload(store, target["id"])["updates"][-1]["text"] == "Tor 0.4.9.16 mitigated the maatuska authority overload."

    distinct_tor = item(product="arti", url="https://gitlab.torproject.org/tpo/core/arti/-/work_items/777",
                        title="Arti RPC socket permission check on BSD",
                        content="Arti RPC sockets reject group-writable directories on FreeBSD.")
    bad_route = verdict("skip", criterion="new_information", same_story=unrelated["id"], reason=f"Covered by {unrelated['id']}.")
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

    rel_story = seed_source_story(store, item(
        authority="official", url="https://lists.torproject.org/tor-announce/tor-1.9.0",
        title="[tor-announce] [RELEASE] Tor release 1.9.0", content="Tor 1.9.0 is released with relay stability fixes.",
    ))
    before_updated = rel_story["updated_at"]
    for inc, quote, routed, skip_reply in (
        (item(authority="official", url="https://blog.torproject.org/tor-1-9-0",
              title="New Release: Tor 1.9.0", content="Tor 1.9.0 is now available with relay stability fixes."),
         "Tor 1.9.0 is now available", False,
         verdict("skip", criterion="new_information", update=True, reason=f"Already covered in {rel_story['id']}.")),
        (item(authority="community", url="https://forum.example.org/tor-1-9-0",
              title="Tor 1.9.0 released", content="Short mirror repost of Tor 1.9.0."),
         "Short mirror repost of Tor 1.9.0.", False,
         verdict("skip", criteria=("new_information", "news_value"), update=True, reason=f"Already covered in {rel_story['id']}.")),
        (item(authority="community", url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/99190",
              kind="gitlab_issue", product="tor", title="Question after upgrading relay",
              content="Thanks +1, everything works fine on my BSD box."),
         "everything works fine on my BSD box", True,
         verdict("skip", criterion="new_information", update=True, reason=f"Routine question on {rel_story['id']}.")),
    ):
        row_rel = pending(store, inc)
        if routed:
            with store.db:
                store.db.execute("UPDATE items SET story_id=? WHERE id=?", (rel_story["id"], row_rel["id"]))
            row_rel = queued_row(store, row_rel["id"], LATER)
        assert run_gate(cfg, store, row_rel, Writer(update_analysis(evidence=[quote])), Reviewer(skip_reply))["status"] == "ignored"
        after_rel = story_payload(store, rel_story["id"])
        assert len(after_rel["sources"]) == 2 and after_rel["updated_at"] == before_updated


def test_official_unroutable_skip_verifies_then_holds(store):
    """Verify and then hold official `new_information` skips when `same_story` cannot route onto the target."""
    surv = seed_source_story(store, item(url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/501", kind="gitlab_issue",
                                         title="Relay descriptor parsing issue #501",
                                         content="Initial report of relay descriptor parsing issue."))
    rel_item = item(url="https://blog.torproject.org/new-release-tor-0499/", title="New Release: Tor 0.4.9.9",
                    content="Tor 0.4.9.9 fixes a relay crash tracked in #501.",
                    published_at=LATER, updated_at=LATER, authority="official", product="tor")
    rel_row = pending(store, rel_item, LATER)
    assert rel_row["cluster_key"] == "release:tor:0.4.9.9"
    prepared = store.prepare_candidate(
        rel_row,
        analysis(title="Tor 0.4.9.9 released", summary="Tor 0.4.9.9 fixes a relay crash.", why_it_matters="",
                 category="release", confidence="confirmed", state="released", products=["tor"], tags=["release"],
                 evidence=["Tor 0.4.9.9 fixes a relay crash"]),
        LATER,
    )
    skip_res = verdict("skip", criterion="new_information", same_story=surv["id"],
                       reason=f"Already covered in {surv['id']}.")
    rev1 = {"stage": "review", "candidate_hash": digest(prepared["candidate"]), "result": skip_res}
    assert review_gate.next_step([rev1], prepared["candidate"], prepared)[0] == "verify"
    rev2 = {"stage": "verification", "candidate_hash": digest(prepared["candidate"]), "result": skip_res}
    assert review_gate.next_step([rev1, rev2], prepared["candidate"], prepared) == ("hold", ("verification", "model_hold"))


def test_commit_candidate_lock_recheck_and_unverified_route_isolation_and_cleanup(context):
    """Recheck story locks at commit time and isolate/clear unverified `story_id` routes on skip."""
    cfg, store = context
    host = seed_source_story(store, item(url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/700", kind="gitlab_issue",
                                         title="Relay circuit timeout bug #700",
                                         content="Operators reported relay circuit timeout bug."))
    host_id = host["id"]
    upd_item = item(url="https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/701", kind="gitlab_mr",
                    title="Fix relay circuit timeout", content="Closes #700 with a circuit timeout fix.",
                    published_at=LATER, updated_at=LATER, upstream_state="merged")
    upd_row = pending(store, upd_item, LATER)
    upd_draft = update_analysis(update="A merge request merged a fix for the circuit timeout.",
                                confidence="confirmed", state="merged",
                                evidence=["Closes #700 with a circuit timeout fix."])
    prepared = store.prepare_candidate(upd_row, upd_draft, LATER)
    pol = review.policy_hash(cfg)
    receipt = insert_approval(store, prepared, key=digest(["ak", upd_row["id"]]), policy=pol,
                              result=verdict("approve", update=True), record={}, created_at=LATER)
    editorial_act(editorial.correct, store, host_id, {"why_it_matters": "Locked mid-flight."},
                  reason="Lock before commit.", observed=LATER)
    with pytest.raises(candidate.StaleCandidate):
        store.commit_candidate(prepared, prepared["candidate"], "wk", LATER, **receipt)

    editorial_act(editorial.unlock, store, host_id, reason="Unlock for routing test.", observed="2026-11-10T13:05:00Z")
    unrel = item(url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/999", kind="gitlab_issue",
                 title="Unrelated issue 999", content="Completely unrelated discussion text for testing.",
                 published_at=LATER, updated_at=LATER)
    unrel_row = pending(store, unrel, LATER)
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

    unrel_row = queued_row(store, unrel_row["id"], LATER)
    skip_prep = store.prepare_candidate(unrel_row, upd_draft, "2026-11-10T13:10:00Z")
    skip_rev = verdict("skip", criterion="new_information", update=True)
    skip_receipt = insert_approval(
        store, skip_prep, key=digest(["sk", unrel_row["id"]]), policy=pol, result=skip_rev,
        record={"reviews": [{"stage": "review", "result": skip_rev}]}, created_at=LATER,
    )
    store.commit_candidate(skip_prep, skip_prep["candidate"], "wk-skip", "2026-11-10T13:10:00Z",
                           decision="skip", **skip_receipt)
    assert store.db.execute("SELECT story_id FROM items WHERE id=?", (unrel_row["id"],)).fetchone()[0] is None


def test_wire_reviewer_populates_same_story_from_single_duplicate_reason_and_holds_retracted_mirror(llm_context):
    """Infer `same_story` from a single cited recent ID on `skip` and hold skips citing retracted stories."""
    cfg, _ = llm_context
    story_cand = prepare_story(STORY)
    pkt = {
        "truncated": False, "missing_sources": [],
        "sources": [{"id": "S1", "kind": "gitlab_issue", "authority": "development", "product": "tor",
                     "url": STORY["sources"][0]["url"], "title": STORY["title"],
                     "passages": [{"id": "S1:P2", "text": STORY["summary"]}]}],
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
    dup_skip = verdict("skip", criterion="new_information", ref="S1:P2", reason=f"Already covered by {live_id}.")
    ret_skip = verdict("skip", criteria=("new_information", "news_value"), ref="S1:P2",
                       reason=f"Repeats retracted story {retracted_id}.")
    wired = wire_reviewer(cfg, dup_skip, ret_skip)
    res_dup = wired.review(story_cand, pkt, coverage=cov)
    res_ret = wired.review(story_cand, pkt, coverage=cov)
    assert res_dup["verdict"] == "skip" and res_dup["same_story"] == live_id
    assert res_ret["verdict"] == "hold" and res_ret["model_verdict"] == "skip" and res_ret["same_story"] is None


def test_duplicate_issue_refs_and_symmetric_closed_by_mr_association(store):
    """Extract canonical duplicate refs and symmetrically associate closed issues to merged MRs."""
    tor_41240 = "https://gitlab.torproject.org/tpo/core/tor/-/work_items/41240"
    tor_41244 = "https://gitlab.torproject.org/tpo/core/tor/-/work_items/41244"
    tor_mr_1076 = "https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/1076"

    for body in (
        "Closed as duplicate of #41240.",
        "Closed as a duplicate of #41240 after triage.",
        "Duplicate of tpo/core/tor#41240.",
        "Dup of https://gitlab.torproject.org/tpo/core/tor/-/issues/41240",
    ):
        assert duplicate_issue_refs(item(kind="gitlab_issue", upstream_state="closed", url=tor_41244, content=body)) == [tor_41240]

    assert duplicate_issue_refs(item(
        kind="gitlab_issue", upstream_state="closed", url=tor_41244, title="Duplicate of !1076", content="See notes.",
    )) == [tor_mr_1076]
    assert duplicate_issue_refs(item(
        kind="gitlab_issue", upstream_state="closed", url=tor_41244, content="Checking.",
        public_comments=[make_note(1, "Closing: duplicate of #41240.", url=tor_41244)],
    )) == [tor_41240]
    assert duplicate_issue_refs(item(
        kind="gitlab_issue", upstream_state="closed", url=tor_41244,
        labels=["status::duplicate"], content="Same bug as #41240.",
    )) == [tor_41240]
    assert duplicate_issue_refs(item(
        kind="gitlab_issue", upstream_state="closed", url=tor_41244,
        labels=["duplicate"], content="Compare #41240 and #41241.",
    )) == []

    for rejected_item in (
        item(kind="gitlab_issue", upstream_state="closed", url=tor_41244, content="This is not a duplicate of #41240."),
        item(kind="gitlab_issue", upstream_state="closed", url=tor_41244, content="This isn't a duplicate of #41240."),
        item(kind="gitlab_issue", upstream_state="opened", url=tor_41244, content="Duplicate of #41240."),
        item(kind="gitlab_mr", upstream_state="closed", url=tor_mr_1076, content="Duplicate of #41240."),
    ):
        assert duplicate_issue_refs(rejected_item) == []

    canon_story = seed_source_story(store, item(
        kind="gitlab_issue", url=tor_41240, labels=["Security"],
        title="Original security descriptor bug", content="Detailed report of the descriptor bug.",
    ))
    sec_dup_row = pending(store, item(
        kind="gitlab_issue", url=tor_41244, labels=["Security"], upstream_state="closed",
        title="Second filing for descriptor bug", content="Closed as a duplicate of #41240.",
    ), LATER)
    matched, how = candidate.associate(store.db, sec_dup_row)
    assert matched["id"] == canon_story["id"] and how == "duplicate_ref"

    nonsec_dup_row = pending(store, item(
        kind="gitlab_issue", url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/41245",
        labels=[], upstream_state="closed", title="Repeated non-security bug", content="Duplicate of #41240.",
    ), LATER)
    assert candidate.associate(store.db, nonsec_dup_row) == (None, None)

    second_story = seed_source_story(store, item(
        kind="gitlab_issue", url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/41241",
        labels=["Security"], title="Another security bug", content="Separate security defect.",
    ))
    ambig_dup = pending(store, item(
        kind="gitlab_issue", url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/41246",
        labels=["Security"], upstream_state="closed", title="Ambiguous duplicate",
        content="Closed as duplicate of #41240 and #41241.",
    ), LATER)
    assert candidate.associate(store.db, ambig_dup) == (None, None)

    mr_story = seed_source_story(store, item(
        kind="gitlab_mr", upstream_state="merged", url=tor_mr_1076,
        title="Fix circuit guard selection (closes TPO/Core/Tor#41471)",
        content="Closes https://gitlab.torproject.org/TPO/Core/Tor/-/issues/41471 with guard check.",
    ))
    open_mr_story = seed_source_story(store, item(
        kind="gitlab_mr", upstream_state="opened",
        url="https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/1077",
        title="WIP fix (closes #41472)", content="Closes #41472 when ready.",
    ))
    unverified_mr = pending(store, item(
        kind="gitlab_mr", upstream_state="merged",
        url="https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/1078",
        title="Unverified routed MR (closes #41473)", content="Closes #41473.",
    ), LATER)
    with store.db:
        store.db.execute(
            "UPDATE items SET story_id=?,last_error=? WHERE id=?",
            (second_story["id"], candidate.UNVERIFIED_ROUTE, unverified_mr["id"]),
        )
        store.db.execute(
            "INSERT INTO items(id,url,source_id,payload,content_hash,cluster_key,first_seen,last_seen,status,story_id) "
            "VALUES('badblob','https://example.org/badblob','test',X'80','h','k',?,?, 'published',?)",
            (DATE, DATE, second_story["id"]),
        )

    issue_41471 = pending(store, item(
        kind="gitlab_issue", url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/41471",
        title="Circuit guard selection defect", content="Observed guard selection regression.",
    ), LATER)
    matched_mr, how_mr = candidate.associate(store.db, issue_41471)
    assert matched_mr["id"] == mr_story["id"] and how_mr == "closed_by_mr"

    issue_41472 = pending(store, item(
        kind="gitlab_issue", url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/41472",
        title="Issue linked to open MR only", content="Open MR should not trigger closed_by_mr.",
    ), LATER)
    assert candidate.associate(store.db, issue_41472) == (None, None)

    issue_41473 = pending(store, item(
        kind="gitlab_issue", url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/41473",
        title="Issue linked to unverified route MR", content="Unverified route should not trigger closed_by_mr.",
    ), LATER)
    assert candidate.associate(store.db, issue_41473) == (None, None)

    second_closing_mr = seed_source_story(store, item(
        kind="gitlab_mr", upstream_state="merged",
        url="https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/1079",
        title="Duplicate MR closing #41471", content="Also closes #41471.",
    ))
    assert second_closing_mr["id"] != mr_story["id"]
    assert candidate.associate(store.db, issue_41471) == (None, None)
    assert open_mr_story["id"] != mr_story["id"]


def test_mailing_list_thread_root_context_is_metadata_only(store):
    """Attach bounded parent-thread context metadata on mailing-list replies without altering passages."""
    stale_root = item(
        source_id="tor-relays", url=LIST_BASE + "OLDROOT/",
        title="[tor-relays] Guard scheduler latency spike",
        content="Too old parent message outside the 45-day thread window.",
        published_at="2026-08-01T10:00:00Z", updated_at="2026-08-01T10:00:00Z",
    )
    other_list_root = item(
        source_id="tor-dev", url=OTHER_LIST_BASE + "DEVROOT/",
        title="[tor-dev] Guard scheduler latency spike",
        content="Different mailing list should not supply parent thread context.",
        published_at="2026-10-20T09:00:00Z", updated_at="2026-10-20T09:00:00Z",
    )
    real_root = item(
        source_id="tor-relays", url=LIST_BASE + "ROOT/",
        title="[tor-relays] Guard scheduler latency spike",
        content="Root report describing guard scheduler latency across relays.\n\n> Quoted prelude omitted.",
        published_at="2026-10-20T10:00:00Z", updated_at="2026-10-20T10:00:00Z",
    )
    mid_reply = item(
        source_id="tor-relays", url=LIST_BASE + "MID/",
        title="[tor-relays] Re: Guard scheduler latency spike",
        content="Intermediate reply.",
        published_at="2026-10-25T10:00:00Z", updated_at="2026-10-25T10:00:00Z",
    )
    for msg in (stale_root, other_list_root, real_root, mid_reply):
        store.ingest(msg, msg["updated_at"])
        with store.db:
            store.db.execute("UPDATE items SET status='ignored' WHERE id=?", (msg["id"],))

    reply = item(
        source_id="tor-relays", url=LIST_BASE + "LEAF/",
        title="[tor-relays] Re: Guard scheduler latency spike",
        content="Our measurement shows 18ms median delay.\n\nOn Tue Alice wrote:\n> Earlier quoted line from thread.",
        published_at="2026-11-08T12:00:00Z", updated_at="2026-11-08T12:00:00Z",
    )
    row = pending(store, reply, LATER)
    assert candidate.associate(store.db, row) == (None, None)

    root_meta = candidate._thread_root_item(store.db, row, reply)
    assert root_meta == {
        "title": "[tor-relays] Guard scheduler latency spike",
        "published_at": "2026-10-20T10:00:00Z",
        "url": LIST_BASE + "ROOT/",
        "excerpt": "Root report describing guard scheduler latency across relays.",
    }

    mode, writer_item = candidate.own_update_input(store.db, row, reply)
    assert mode == "story" and writer_item["thread_root"] == root_meta
    assert "thread_root" not in reply

    unrelated_post = item(
        source_id="tor-relays", url=LIST_BASE + "STANDALONE/",
        title="[tor-relays] Unrelated standalone post", content="Standalone post body.",
    )
    unrelated_row = pending(store, unrelated_post, LATER)
    assert candidate.own_update_input(store.db, unrelated_row, unrelated_post) == ("story", unrelated_post)

    draft = analysis(
        title="Guard scheduler latency measured at 18ms",
        summary="A mailing-list reply measures 18ms median guard scheduler delay.",
        why_it_matters="", evidence=["Our measurement shows 18ms median delay."],
    )
    prepared = store.prepare_candidate(row, draft, LATER)
    [unit] = prepared["packet"]["sources"]
    assert unit["thread_context"] == root_meta
    assert unit["unquoted_content"] == "Our measurement shows 18ms median delay."
    assert all("Root report" not in p["text"] for p in unit["passages"])

    compat_pkt, _ = source_packet.build_packet(
        store.db, reply, prepared["payload"], prepared["candidate"], prepared["payload"]["editorial_item"],
    )
    assert "thread_context" not in compat_pkt["sources"][0]


def test_related_expands_cve_authority_and_rare_lexical_overlap(store):
    """Pin live non-retracted stories by CVE, directory authority nickname, and 90-day rare lexical overlap."""
    assert (candidate.COVERAGE_ROWS, candidate.COVERAGE_CHARS, candidate.COVERAGE_SUMMARY_CHARS, candidate.RELATED_LIMIT) == (
        40, 18000, 300, 10,
    )

    s_cve = seed_source_story(store, item(
        url="https://example.org/cve-story", title="Parser issue assigned CVE-2026-55555",
        content="Advisory tracks CVE-2026-55555 in cell parsing. " + ("padding " * 60),
    ), draft=analysis(
        title="Parser issue assigned CVE-2026-55555",
        summary="Tracks CVE-2026-55555 in descriptor cell parsing. " + ("Detailed background text. " * 15),
        evidence=["Advisory tracks CVE-2026-55555 in cell parsing."],
    ))
    s_auth = seed_source_story(store, item(
        url="https://example.org/auth-story", title="Vote latency on maatuska",
        content="Operators observed elevated latency on Maatuska yesterday.",
    ), draft=analysis(
        title="Vote latency on maatuska", summary="Elevated vote latency reported on maatuska.",
        evidence=["Operators observed elevated latency on Maatuska yesterday."],
    ))
    s_lex_recent = seed_source_story(store, item(
        url="https://example.org/lex-recent", title="WebTunnel nginx websocket buffer stall",
        content="Reverse proxies using WebTunnel with nginx experience websocket handshake stalls.",
        published_at="2026-10-15T00:00:00Z", updated_at="2026-10-15T00:00:00Z",
    ), draft=analysis(
        title="WebTunnel nginx websocket buffer stall",
        summary="WebTunnel deployments behind nginx observe websocket handshake stalls.",
        evidence=["Reverse proxies using WebTunnel with nginx experience websocket handshake stalls."],
    ), at="2026-10-15T00:00:00Z")
    s_lex_old = seed_source_story(store, item(
        url="https://example.org/lex-old", title="Old WebTunnel nginx websocket note",
        content="Historical WebTunnel nginx websocket handshake report from June.",
        published_at="2026-06-01T00:00:00Z", updated_at="2026-06-01T00:00:00Z",
    ), draft=analysis(
        title="Old WebTunnel nginx websocket note",
        summary="Historical WebTunnel nginx websocket handshake report from June.",
        evidence=["Historical WebTunnel nginx websocket handshake report from June."],
    ), at="2026-06-01T00:00:00Z")
    s_generic = seed_source_story(store, item(
        url="https://example.org/generic", title="Tor relay directory authority tor260 counter issue",
        content="Tor and Arti relay client server network browser fix counter checks.",
        published_at="2026-10-20T00:00:00Z", updated_at="2026-10-20T00:00:00Z",
    ), draft=analysis(
        title="Tor relay directory authority tor260 counter issue",
        summary="Tor and Arti relay client server network browser fix counters.",
        evidence=["Tor and Arti relay client server network browser fix counter checks."],
    ), at="2026-10-20T00:00:00Z")

    probe = item(
        url="https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/message/CROSS1/",
        title="[tor-relays] WebTunnel nginx handshake issue, CVE-2026-55555, and tor26 follow-up",
        content=(
            "Our counter test and counters aside, operators using WebTunnel with nginx "
            "hit websocket handshake stalls; maatuska and CVE-2026-55555 were also discussed.\n\n"
            "> Quoted older serge remark must not match authority."
        ),
        published_at="2026-11-08T12:00:00Z", updated_at="2026-11-08T12:00:00Z",
    )
    assert cve_ids(probe) == ["CVE-2026-55555"]
    rel = candidate.related(store.db, {"id": probe["id"], "cluster_key": "url:probe"}, probe)
    rel_map = dict(rel)
    assert rel_map.get(s_cve["id"]) == "references CVE-2026-55555"
    assert rel_map.get(s_auth["id"]) == "shared authority"
    assert rel_map.get(s_lex_recent["id"]) == "shared technical terms"
    assert s_lex_old["id"] not in rel_map
    assert s_generic["id"] not in rel_map

    bg = candidate.coverage_background(store.db, None, related_rows=rel)
    cve_entry = next(e for e in bg["recent"] if e["id"] == s_cve["id"])
    assert len(cve_entry["summary"]) > candidate.COVERAGE_SUMMARY_CHARS
    assert len(cve_entry["summary"]) <= candidate.RELATED_SUMMARY_CHARS

    # Verify RELATED_LIMIT == 10 pins up to 10 distinct stories cleanly.
    ten_target = item(
        url="https://example.org/ten-probe", title="Multi-CVE tracking note",
        content=" ".join(f"CVE-2026-{1000 + n}" for n in range(12)),
    )
    for n in range(12):
        cve = f"CVE-2026-{1000 + n}"
        seed_source_story(store, item(
            url=f"https://example.org/cve-cap-{n}", title=f"Tracking {cve}", content=f"Details for {cve}.",
        ), draft=analysis(title=f"Tracking {cve}", summary=f"Details for {cve}.", evidence=[f"Details for {cve}."]))
    assert len(candidate.related(store.db, {"id": ten_target["id"], "cluster_key": "url:ten"}, ten_target)) == 10


def test_cross_product_release_rollout_related_and_can_route(context):
    """Pin and route cross-product deployment notices for covered Tor releases while keeping separate releases blocked."""
    cfg, store = context
    tor_rel_item = item(
        kind="feed",
        authority="official",
        product="tor",
        url="https://lists.torproject.org/tor-announce/tor-0-4-9-17",
        title="Tor stable 0.4.9.17 released",
        content="Tor 0.4.9.17 released with relay IPv6 DoS mitigations.",
        published_at=DATE,
        updated_at=DATE,
    )
    tor_rel = seed_source_story(
        store,
        tor_rel_item,
        draft=analysis(
            title="Tor stable 0.4.9.17 released",
            summary="The Tor Project released 0.4.9.17 with relay IPv6 DoS mitigations.",
            why_it_matters="",
            category="release",
            tags=["release"],
            confidence="confirmed",
            state="released",
            products=["tor"],
            evidence=["Tor 0.4.9.17 released with relay IPv6 DoS mitigations."],
        ),
    )

    unrelated_nginx = seed_source_story(
        store,
        item(
            kind="feed",
            authority="official",
            product="arti",
            url="https://example.org/arti-1-4-2",
            title="Arti 1.4.2 released",
            content="Arti 1.4.2 released with RPC improvements.",
        ),
        draft=analysis(
            title="Arti 1.4.2 released",
            summary="Arti 1.4.2 released with RPC improvements.",
            why_it_matters="",
            category="release",
            tags=["release"],
            confidence="confirmed",
            state="released",
            products=["arti"],
            evidence=["Arti 1.4.2 released with RPC improvements."],
        ),
    )

    rollout_item = item(
        kind="gitlab_issue",
        authority="dirauth-operator",
        product="snowflake",
        url="https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/-/work_items/40584",
        title="Update tor on snowflake bridges to 0.4.9.17 for security fixes",
        content="Upgraded tor on snowflake-01 and snowflake-02 to 0.4.9.17.",
        published_at=LATER,
        updated_at=LATER,
    )
    rollout_row = pending(store, rollout_item, LATER)
    rel = candidate.related(store.db, rollout_row, rollout_item)
    assert (tor_rel["id"], "mentions tor 0.4.9.17") in rel
    assert all(sid != unrelated_nginx["id"] for sid, _ in rel)

    rollout_cand = analysis(
        title="Snowflake bridges updated to Tor 0.4.9.17",
        summary="Operators upgraded snowflake-01 and snowflake-02 to Tor 0.4.9.17.",
        why_it_matters="",
        category="security",
        tags=["security"],
        confidence="reported",
        state="developing",
        products=["snowflake"],
        evidence=["Upgraded tor on snowflake-01 and snowflake-02 to 0.4.9.17."],
    )
    prepared_rollout = store.prepare_candidate(rollout_row, rollout_cand, LATER)
    assert any(entry["id"] == tor_rel["id"] for entry in prepared_rollout["coverage"]["recent"])

    # Even if `related` is absent on the recent entry, cross-product version overlap permits routing.
    stripped_prepared = {
        **prepared_rollout,
        "coverage": {
            "prior_story": None,
            "recent": [
                {k: v for k, v in entry.items() if k != "related"}
                for entry in prepared_rollout["coverage"]["recent"]
            ],
            "truncated": False,
        },
    }
    route_verdict = verdict("approve", same_story=tor_rel["id"])
    assert review_gate._can_route(prepared_rollout["candidate"], stripped_prepared, route_verdict, tor_rel["id"]) is True

    # Conversely, a separate product release (Tails 7.18 bundling Tor 0.4.9.17) must not route onto Tor 0.4.9.17.
    tails_item = item(
        kind="feed",
        authority="official",
        product="tails",
        url="https://tails.net/news/version_7.18/",
        title="Tails 7.18",
        content="Tails 7.18 updates the bundled Tor client to 0.4.9.17.",
        published_at=LATER,
        updated_at=LATER,
    )
    tails_row = pending(store, tails_item, LATER)
    tails_prep = store.prepare_candidate(
        tails_row,
        analysis(
            title="Tails 7.18 released with Tor 0.4.9.17",
            summary="Tails 7.18 updates the Tor client to 0.4.9.17.",
            why_it_matters="",
            category="release",
            tags=["release"],
            confidence="confirmed",
            state="released",
            products=["tails"],
            evidence=["Tails 7.18 updates the bundled Tor client to 0.4.9.17."],
        ),
        LATER,
    )
    assert review_gate._can_route(tails_prep["candidate"], tails_prep, route_verdict, tor_rel["id"]) is False

    # And a mention of "Tor Project ... Arti 1.4.2" must not pin Tor 1.4.2.
    tor_142 = seed_source_story(
        store,
        item(
            kind="feed",
            authority="official",
            product="tor",
            url="https://lists.torproject.org/tor-announce/tor-1-4-2",
            title="Tor 1.4.2 released",
            content="Tor 1.4.2 released.",
        ),
        draft=analysis(
            title="Tor 1.4.2 released",
            summary="Tor 1.4.2 released.",
            why_it_matters="",
            category="release",
            tags=["release"],
            confidence="confirmed",
            state="released",
            products=["tor"],
            evidence=["Tor 1.4.2 released."],
        ),
    )
    arti_post = item(
        kind="feed",
        authority="official",
        product="arti",
        url="https://blog.torproject.org/arti-1-4-2",
        title="Tor Project released Arti 1.4.2",
        content="Tor Project released Arti 1.4.2 today.",
        published_at=LATER,
        updated_at=LATER,
    )
    arti_rel = candidate.related(store.db, pending(store, arti_post, LATER), arti_post)
    assert (unrelated_nginx["id"], "mentions arti 1.4.2") in arti_rel
    assert all(sid != tor_142["id"] for sid, _ in arti_rel)

    # Full run_gate routes the Snowflake rollout issue cleanly to Tor 0.4.9.17.
    out = run_gate(cfg, store, rollout_row, Writer(rollout_cand), Reviewer(verdict("approve", same_story=tor_rel["id"])), LATER)
    assert out["status"] == "routed"
    assert queued_row(store, rollout_item["id"], LATER)["story_id"] == tor_rel["id"]
