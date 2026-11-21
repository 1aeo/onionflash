"""The exact merged public candidate, its evidence and the commit boundary."""

import json

import pytest

from helpers import (
    DAMAGE, DATE, analysis, damage_item, editorial_act, insert_approval, item, item_row, make_note, pending,
    seed_story, update_analysis,
)
from onionflash import candidate, editorial, render, review, source_packet
from onionflash.analyze import _writer_schema, tag_notice, tag_update
from onionflash.candidate import ReviewRequired, StaleCandidate, coverage_background
from onionflash.comments import INPUT_CHARS, _compose
from onionflash.config import DEFAULTS

LATER = "2026-11-09T12:00:00Z"
BODY = "The operator reports that old directory-authority keys cannot be trusted and requests a source-code change. " * 4


def _release_item(name, content, **changes):
    return item(**{"kind": "feed", "title": "Tor 0.4.9.16 released", "url": "https://example.org/release/" + name,
                   "source_id": name, "content": content, **changes})


def _issue_notes(url, at, body_fn):
    return [make_note(n, body_fn(n), author=f"user{n}", created_at=at, url=url) for n in range(12, 0, -1)]


def test_prepare_is_read_only_and_an_unreviewed_commit_is_refused(store):
    """Keep `prepare_candidate` read-only and refuse unapproved `commit_candidate` calls."""
    row = pending(store, item(content=BODY))
    before = store.db.total_changes
    prepared = store.prepare_candidate(row, analysis(), DATE)
    assert store.db.total_changes == before and store.stories() == []
    assert prepared["candidate"] == render.prepare_story(prepared["payload"])
    with pytest.raises(ReviewRequired):
        store.commit_candidate(prepared, prepared["candidate"], "unreviewed", DATE)
    assert store.stories() == [] and store.db.execute("SELECT COUNT(*) FROM analyses").fetchone()[0] == 0


@pytest.mark.parametrize("field,limit", [("title", 180), ("summary", 1600), ("why_it_matters", 800), ("source_title", 200)])
def test_truncation_at_space_keeps_reviewed_candidate_stable_through_commit(store, field, limit):
    """Preserve truncated public field values identically between `prepare_candidate` and `commit_candidate`."""
    text = "x" * (limit - 1) + " more supported text"
    incoming = item(content=BODY, **({"title": text} if field == "source_title" else {}))
    result = analysis(**({field: text} if field != "source_title" else {}))
    prepared = store.prepare_candidate(pending(store, incoming), result, DATE)
    public = prepared["candidate"]
    assert render.prepare_story(public) == public
    store.commit_candidate(prepared, public, "truncated-source", DATE, **insert_approval(store, prepared))
    assert render.prepare_story(store.stories()[0]) == public


def test_poll_only_metadata_does_not_invalidate_approval(store):
    """Ignore poll-only comment check markers when validating an existing approval receipt."""
    row = pending(store, item(content=BODY))
    prepared = store.prepare_candidate(row, analysis(), DATE)
    receipt = insert_approval(store, prepared)
    payload = {**json.loads(row["payload"]), "comments_checked_at": LATER, "comments_source_key": "poll-only-marker"}
    with store.db:
        store.db.execute("UPDATE items SET payload=?,last_seen=? WHERE id=?", (json.dumps(payload), LATER, row["id"]))
    assert store.commit_candidate(prepared, prepared["candidate"], "approved", LATER, **receipt)["status"] == "published"


def test_new_story_is_dated_when_published_not_when_first_prepared(store):
    """Set `added_at` to the commit timestamp rather than the initial preparation timestamp."""
    prepared = store.prepare_candidate(pending(store, item(content=BODY)), analysis(), DATE)
    store.commit_candidate(prepared, prepared["candidate"], "retried", LATER, **insert_approval(store, prepared))
    assert store.stories()[0]["added_at"] == LATER


def test_locked_story_skips_model_prose_but_records_analysis_and_grouping(store):
    """Preserve operator-locked story prose while recording grouped item associations."""
    old = seed_story(store, item(content=BODY), key="fixture")
    editorial_act(editorial.correct, store, old["id"], {"summary": "An operator correction."},
                  reason="Source clarification", observed=LATER)
    row = pending(store, item(content=BODY + " Updated detail.", updated_at=LATER), LATER)
    prepared = store.prepare_candidate(row, analysis(summary="Unreviewed replacement."), LATER)
    assert prepared["locked"] and prepared["candidate"] is None
    assert store.commit_candidate(prepared, None, "locked", LATER)["status"] == "locked"
    assert store.stories()[0]["summary"] == "An operator correction."
    assert store.db.execute("SELECT COUNT(*) FROM analyses").fetchone()[0] == 2
    assert store.db.execute("SELECT story_id FROM items WHERE id=?", (row["id"],)).fetchone()[0] == old["id"]


def test_a_model_update_keeps_the_dated_updates_an_operator_added(store):
    """Append model updates after operator-added dated update entries on unlocked stories."""
    update = {"at": LATER, "text": "The operator rotated the keys.",
              "sources": [{"url": "https://example.org/news/2", "title": "Follow-up"}]}
    old = seed_story(store, item(content=BODY), key="fixture")
    for action, arguments in ((editorial.correct, ({"updates": [update]},)), (editorial.unlock, ())):
        editorial_act(action, store, old["id"], *arguments, reason="Reviewed the follow-up.", observed=LATER)
    later2 = "2026-11-10T12:00:00Z"
    row = pending(store, item(content=BODY + " Updated detail.", updated_at=later2), later2)
    prepared = store.prepare_candidate(row, update_analysis(update="Updated detail reported.", evidence=["Updated detail."]), later2)
    assert prepared["candidate"]["updates"][0] == update
    assert prepared["candidate"]["updates"][1]["text"] == "Updated detail reported."
    store.commit_candidate(prepared, prepared["candidate"], "rewrite", later2, **insert_approval(store, prepared))
    assert store.stories()[0]["summary"] == old["summary"]
    assert [u["text"] for u in store.stories()[0]["updates"]] == [update["text"], "Updated detail reported."]


def test_cold_required_source_holds_and_hot_historical_snapshot_is_labeled(store):
    """Fall back to `historical-analysis` snapshots for compacted sources and block missing ones."""
    old = seed_story(store, item(content=BODY, updated_at=LATER), key="fixture", at=LATER)
    damage_item(store.db, old["editorial_item"], "compacted")
    row = pending(store, item(url="https://example.org/other", source_id="other", content=BODY), LATER)
    prepared = store.prepare_candidate(row, update_analysis(), LATER)
    assert not prepared["packet"]["missing_sources"]
    historical = next(s for s in prepared["packet"]["sources"] if s["snapshot"] == "historical-analysis")
    assert historical["published_at"] == DATE and historical["updated_at"] == LATER
    with store.db:
        store.db.execute("DELETE FROM analyses WHERE source_item_id=?", (old["editorial_item"],))
    missing = store.prepare_candidate(row, update_analysis(), LATER)
    assert missing["packet"]["missing_sources"]
    with pytest.raises(ReviewRequired):
        store.commit_candidate(missing, missing["candidate"], "cold", LATER, **insert_approval(store, missing))


def test_packet_limits_and_required_source_overflow(store, monkeypatch):
    """Enforce source packet passage/character caps and flag required-source overflows."""
    seed_story(store, item(content=BODY * 100, updated_at=LATER), key="fixture", at=LATER)
    row = pending(store, item(url="https://example.org/other", source_id="other", content=BODY * 100), LATER)
    limits = {"max_sources": 2, "max_passages": 6, "passage_chars": 100, "max_source_chars": 450}
    monkeypatch.setattr(source_packet, "LIMITS", limits)
    packet = store.prepare_candidate(row, update_analysis(), LATER)["packet"]
    assert packet["truncated"] and not packet["missing_sources"] and len(packet["sources"]) == 2
    passages = [p for s in packet["sources"] for p in s["passages"]]
    assert len(passages) <= 6 and sum(len(p["text"]) for p in passages) <= 450
    assert all(len(p["text"]) <= 100 for p in passages) and len({p["id"] for p in passages}) == len(passages)
    limits["max_sources"] = 1
    assert store.prepare_candidate(row, update_analysis(), LATER)["packet"]["missing_sources"]


@pytest.mark.parametrize("field", ["candidate_hash", "source_hash", "binding_hash", "policy_hash"])
def test_approval_receipt_is_bound_to_exact_candidate_sources_context_and_policy(store, field):
    """Reject `commit_candidate` if any hash binding column on the approval receipt mismatches."""
    prepared = store.prepare_candidate(pending(store, item(content=BODY)), analysis(), DATE)
    receipt = insert_approval(store, prepared)
    with store.db:
        store.db.execute(f"UPDATE review_approvals SET {field}='wrong' WHERE key=?", (receipt["approval_key"],))
    with pytest.raises(ReviewRequired):
        store.commit_candidate(prepared, prepared["candidate"], "bad-receipt", DATE, **receipt)
    assert store.stories() == []


def test_semantic_repair_is_exact_and_immutable_public_fields_cannot_change(store):
    """Accept exact reviewed semantic repairs while rejecting tampered immutable story fields."""
    prepared = store.prepare_candidate(pending(store, item(content=BODY)), analysis(), DATE)
    repaired = review.apply_repair(prepared["candidate"], {"why_it_matters": "", "priority": "normal"})
    receipt = insert_approval(store, prepared, repaired)
    wrong = {**repaired, "published_at": LATER}
    with pytest.raises(ReviewRequired):
        store.commit_candidate(prepared, wrong, "bad-date", DATE, **insert_approval(store, prepared, wrong))
    store.commit_candidate(prepared, repaired, "exact-repair", DATE, **receipt)
    assert render.prepare_story(store.stories()[0]) == repaired
    record = json.loads(store.db.execute("SELECT review_record FROM analyses WHERE cache_key='exact-repair'").fetchone()[0])
    assert record["candidate"] == repaired and record["packet"] == prepared["packet"]


def test_review_audits_append_instead_of_losing_retried_decisions(store):
    """Append distinct `analyses` audit rows across retries sharing the same writer cache key."""
    row = pending(store, item(content=BODY))
    with store.db:
        first = store.record_analysis(row, analysis(), "same-writer-key", DATE, review_record={"verdict": "hold"})
        second = store.record_analysis(row, analysis(), "same-writer-key", LATER, review_record={"verdict": "approve"})
    assert first != second
    assert [json.loads(r[0])["verdict"] for r in store.db.execute("SELECT review_record FROM analyses ORDER BY created_at")] == [
        "hold", "approve"
    ]


def test_comment_evidence_has_real_author_dates(store):
    """Populate authored note passages with upstream `author`, `created_at`, and permalink URL."""
    url = "https://gitlab.torproject.org/tpo/core/tor/-/work_items/41473"
    note = make_note(42, "The proposed source-code fix still needs review.", author="maintainer", created_at=LATER, url=url)
    incoming = _compose(item(url=url, content=BODY), [note], LATER, source_key="k")
    prepared = store.prepare_candidate(pending(store, incoming, LATER), analysis(evidence=[note["body"]]), LATER)
    [src] = prepared["packet"]["sources"]
    assert [p for p in src["passages"] if "author" in p] == [
        {"id": "S1:P2", "author": "maintainer", "created_at": LATER, "url": note["url"], "text": note["body"]}
    ]
    assert prepared["candidate"]["updated_at"] == LATER and prepared["candidate"]["published_at"] == DATE


def test_uncited_corrective_note_survives_long_description_and_binds_approval(store):
    """Keep uncited public notes ahead of truncated descriptions and include them in `source_hash`."""
    url = "https://gitlab.torproject.org/tpo/core/tor/-/work_items/41473"
    note = make_note(99, "Correction: relay operators do not need to edit their configurations.",
                     author="maintainer", created_at=LATER, url=url)
    incoming = _compose(item(url=url, content=BODY * 100), [note], LATER, source_key="k")
    draft = analysis(evidence=["The operator reports that old directory-authority keys cannot be trusted"])
    prepared = store.prepare_candidate(pending(store, incoming, LATER), draft, LATER)
    assert len(prepared["candidate"]["sources"]) == 1
    [src] = prepared["packet"]["sources"]
    assert [(p["author"], p["text"]) for p in src["passages"] if "author" in p] == [("maintainer", note["body"])]
    assert src["passages"][2]["text"].startswith(BODY)
    assert sum(len(p["text"]) for p in src["passages"]) == source_packet.LIMITS["max_source_chars"]
    assert prepared["packet"]["truncated"]
    assert prepared["candidate"]["updated_at"] == DATE and prepared["candidate"]["published_at"] == DATE
    incoming["public_comments"][0]["body"] += " The change is not released yet."
    incoming = _compose(incoming, incoming["public_comments"], LATER, source_key="k")
    store.ingest(incoming, LATER)
    assert store.prepare_candidate(store.pending(1, LATER)[0], draft, LATER)["source_hash"] != prepared["source_hash"]


@pytest.mark.parametrize("missing_body", [False, True])
def test_legacy_multi_source_prose_requires_all_evidence_not_guessed_writer(store, monkeypatch, missing_body):
    """Require every cited source to remain readable when updating legacy multi-source stories."""
    first = item(content=BODY, updated_at=LATER)
    seed_story(store, first, analysis(summary="A source-supported grouped account.", confidence="confirmed"), key="fixture", at=LATER)
    second = item(url="https://example.org/second", source_id="second", content=BODY)
    old = seed_story(store, second, analysis(), key="second", at=LATER)
    assert len(old["sources"]) == 2
    old.pop("editorial_item")
    old.pop("editorial_analysis_key", None)
    with store.db:
        store.db.execute("UPDATE stories SET payload=? WHERE id=?", (json.dumps(old), old["id"]))
        if missing_body:
            store.db.execute("DELETE FROM analyses WHERE source_item_id=?", (first["id"],))
    if missing_body:
        damage_item(store.db, first["id"], "compacted")
    second["content"] += " A further detail in the related report."
    row = pending(store, second, LATER)
    prepared = store.prepare_candidate(row, update_analysis(evidence=["A further detail in the related report."]), LATER)
    assert prepared["payload"]["editorial_item"] is None and prepared["candidate"]["summary"] == old["summary"]
    if missing_body:
        assert first["url"] in prepared["packet"]["missing_sources"]
        with pytest.raises(ReviewRequired):
            store.commit_candidate(prepared, prepared["candidate"], "legacy-missing", LATER, **insert_approval(store, prepared))
    else:
        assert not prepared["packet"]["missing_sources"]
        assert {s["url"] for s in prepared["packet"]["sources"]} == {first["url"], second["url"]}
        monkeypatch.setitem(source_packet.LIMITS, "max_sources", 1)
        assert store.prepare_candidate(row, update_analysis(evidence=["A further detail in the related report."]), LATER)["packet"]["missing_sources"]
        store.commit_candidate(prepared, prepared["candidate"], "legacy-reviewed", LATER, **insert_approval(store, prepared))
        assert store.stories()[0]["summary"] == old["summary"]


@pytest.mark.parametrize("historical", ["recorded", "legacy", "missing", "wrong-url"])
def test_stable_timeline_identity_cannot_label_new_commit_bytes_with_old_citation(store, historical):
    """Bind timeline citations to the exact commit-permalink snapshot rather than newer moved revisions."""
    old_url = "https://gitlab.example/metrics/-/blob/" + "1" * 40 + "/README.md?plain=1#L10"
    new_url = old_url.replace("1" * 40, "2" * 40).replace("#L10", "#L20")
    timeline = item(kind="metrics_timeline", authority="telemetry", product="network",
                    source_entry_id="a" * 64, title="Release of tor 0.4.9.16", url=old_url,
                    content="The original timeline records the release on November 7.")
    old = seed_story(store, timeline, analysis(summary="The timeline records the release on November 7."), key="fixture")
    moved = {**timeline, "url": new_url, "content": "The corrected timeline says the release occurred November 5.", "updated_at": LATER}
    store.ingest(moved, LATER)
    assert moved["id"] == timeline["id"]
    with store.db:
        if historical in {"legacy", "missing", "wrong-url"}:
            old.pop("editorial_analysis_key", None)
            store.db.execute("UPDATE stories SET payload=? WHERE id=?", (json.dumps(old), old["id"]))
        if historical in {"missing", "wrong-url"}:
            store.db.execute("DELETE FROM analyses WHERE source_item_id=?", (timeline["id"],))
        if historical in {"legacy", "wrong-url"}:
            store.record_analysis(item_row(store, timeline), analysis(), "later-snapshot", LATER)
    row = pending(store, item(kind="tag", title="tor-0.4.9.16", url="https://example.org/tag/0.4.9.16", content="", updated_at=LATER), LATER, target=old["id"])
    prepared = store.prepare_candidate(row, tag_update(json.loads(row["payload"]), old), LATER)
    cited_urls = {s["url"] for s in prepared["candidate"]["sources"]}
    assert old_url in cited_urls and new_url not in cited_urls
    packet_text = "".join(p["text"] for s in prepared["packet"]["sources"] for p in s["passages"])
    assert "corrected timeline" not in packet_text
    if historical in {"missing", "wrong-url"}:
        assert old_url in prepared["packet"]["missing_sources"]
        with pytest.raises(ReviewRequired):
            store.commit_candidate(prepared, prepared["candidate"], "missing-history", LATER, **insert_approval(store, prepared))
    else:
        assert not prepared["packet"]["missing_sources"]
        src = next(s for s in prepared["packet"]["sources"] if s["url"] == old_url)
        assert src["snapshot"] == "historical-analysis" and src["updated_at"] == DATE
        assert "original timeline" in packet_text
        store.ingest({**moved, "content": "A further timeline correction.", "updated_at": "2026-11-10T12:00:00Z"}, "2026-11-10T12:00:00Z")
        again = store.prepare_candidate(row, tag_update(json.loads(row["payload"]), old), LATER)
        assert again["source_hash"] == prepared["source_hash"] and again["binding_hash"] != prepared["binding_hash"]
    assert store.stories()[0]["summary"] == old["summary"]


@pytest.mark.parametrize("kind", [*DAMAGE, "blob"])
def test_a_cited_source_with_a_damaged_saved_copy_reads_as_its_snapshot_or_missing(store, kind):
    """Recover damaged cited source rows from recorded analysis snapshots or mark them missing."""
    old = seed_story(store, item(content=BODY, updated_at=LATER), key="fixture", at=LATER)
    damage_item(store.db, old["editorial_item"], kind)
    with store.db:
        store.db.execute(
            """INSERT INTO analyses(cache_key,result,created_at,source_payload,source_item_id)
               SELECT 'newer',result,'2026-11-10T12:00:00Z',json_set(source_payload,'$.content','A newer account.'),source_item_id
               FROM analyses WHERE cache_key=?""",
            (old["editorial_analysis_key"],),
        )
    row = pending(store, item(url="https://example.org/other", source_id="other", content=BODY), LATER)
    prepared = store.prepare_candidate(row, update_analysis(), LATER)
    cited = next(s for s in prepared["packet"]["sources"] if s["url"] == "https://example.org/news/1")
    assert cited["snapshot"] == ("current" if kind == "blob" else "historical-analysis")
    assert cited["passages"][-1]["text"] == BODY and not prepared["packet"]["missing_sources"]
    with store.db:
        store.db.execute("DELETE FROM analyses WHERE source_item_id=?", (old["editorial_item"],))
    missing = store.prepare_candidate(row, update_analysis(), LATER)["packet"]["missing_sources"]
    assert missing == ([] if kind == "blob" else ["https://example.org/news/1"])


@pytest.mark.parametrize("body", ["", None])
def test_title_only_source_is_reviewable_but_compacted_snapshot_is_missing(store, body):
    """Allow title-only feed items while treating compacted `None`-content rows as missing."""
    src = item(kind="feed", title="Tor 0.4.9.16 released", content="")
    row = pending(store, src)
    if body is None:
        damage_item(store.db, row["id"], "compacted")
        row = item_row(store, row)
    draft = analysis(title=src["title"], summary="The release feed announces Tor 0.4.9.16.",
                     why_it_matters="", category="release", tags=["release"], state="released", evidence=[src["title"]])
    prepared = store.prepare_candidate(row, draft, DATE)
    if body is None:
        assert prepared["packet"]["missing_sources"] == [src["url"]] and prepared["packet"]["sources"] == []
    else:
        assert not prepared["packet"]["missing_sources"]
        assert prepared["packet"]["sources"][0]["passages"] == [{"id": "S1:P1", "text": src["title"]}]
        store.commit_candidate(prepared, prepared["candidate"], "title-only", DATE, **insert_approval(store, prepared))
        assert store.stories()[0]["title"] == src["title"]


def test_writer_source_keeps_the_text_its_writer_saw_and_short_sources_leave_room(store):
    """Retain full writer-source text and notes while reclaiming unused budget from short mirrors."""
    url = "https://gitlab.torproject.org/tpo/core/tor/-/work_items/41473"
    notes = _issue_notes(url, DATE, lambda n: f"Note {n} reports a detail. " * 22)
    notes[-1]["body"] += "The oldest note confirms TROVE-2026-001."
    writer = _compose(_release_item("issue", "Release notes for the announced change. " * 250, kind="gitlab_issue",
                                    url=url, updated_at=LATER), notes, LATER, source_key="k")
    long_mirror = _release_item("0-long", "A longer mirror of the announcement. " * 130)
    original = seed_story(store, writer, analysis(evidence=["The oldest note confirms TROVE-2026-001"]), key="writer", at=LATER)
    for name in ["a", "b", "c", "d", "e"]:
        seed_story(store, _release_item(name, f"Short mirror {name}."),
                   update_analysis(update=f"Short mirror {name}.", evidence=[f"Short mirror {name}."]), key=name, target=original["id"])
    seed_story(store, long_mirror, update_analysis(update="Long mirror posted.", evidence=["A longer mirror of the announcement."]),
               key="long", target=original["id"])
    row = pending(store, _release_item("f", "Short mirror f."), LATER, target=original["id"])
    prepared = store.prepare_candidate(row, update_analysis(update="Short mirror f.", evidence=["Short mirror f."]), LATER)
    assert prepared["payload"]["editorial_item"] == writer["id"] and not prepared["packet"]["missing_sources"]
    assert url + "#note_1" in {s["url"] for s in prepared["candidate"]["sources"]}
    packet = {s["url"]: s["passages"] for s in prepared["packet"]["sources"]}
    assert len(packet) == 8
    assert "".join(p["text"] for p in packet[url] if "author" not in p) == writer["title"] + writer["content"]
    assert [p["text"] for p in packet[url] if "author" in p] == [note["body"] for note in notes]
    assert "".join(p["text"] for p in packet[long_mirror["url"]]) == long_mirror["title"] + long_mirror["content"]
    assert sum(len(p["text"]) for passages in packet.values() for p in passages) <= source_packet.LIMITS["max_source_chars"]


def test_kept_prose_keeps_its_writer_window_and_an_incoming_issue_keeps_every_note(store):
    """Preserve `INPUT_CHARS` writer window on kept prose alongside all notes on incoming issues."""
    post = _release_item("post", "The release fixes the reported crash and updates the directory code. " * 220)
    url = "https://gitlab.torproject.org/tpo/core/tor/-/work_items/41473"
    notes = _issue_notes(url, LATER, lambda n: f"Note {n} confirms the crash.")
    notes[-1]["body"] = "Correction: this release does not fix the reported crash."
    incoming = _compose(item(title=post["title"], url=url, updated_at=LATER, content="Release tracking notes. " * 75),
                        notes, LATER, source_key="k")
    original = seed_story(store, post, analysis(confidence="confirmed", evidence=["The release fixes the reported crash"]), key="post")
    for name in "abcdef":
        seed_story(store, _release_item(name, f"Mirror {name} of the announcement. " * 75),
                   update_analysis(update=f"Mirror {name} posted.", confidence="confirmed",
                                   evidence=[f"Mirror {name} of the announcement."]), key=name, target=original["id"])
    row = pending(store, incoming, LATER, target=original["id"])
    prepared = store.prepare_candidate(row, update_analysis(update="Release tracking notes updated.",
                                                            confidence="confirmed", evidence=["Release tracking notes"]), LATER)
    assert prepared["payload"]["editorial_item"] != row["id"] and not prepared["packet"]["missing_sources"]
    packet = {s["url"]: s["passages"] for s in prepared["packet"]["sources"]}
    assert len(packet) == 8
    assert "".join(p["text"] for p in packet[post["url"]]) == post["title"] + post["content"][:INPUT_CHARS]
    assert [p["text"] for p in packet[url] if "author" in p] == [note["body"] for note in notes]


def test_empty_title_and_body_are_not_review_evidence(store):
    """Mark sources with empty title and body as missing in the review packet."""
    prepared = store.prepare_candidate(pending(store, item(kind="feed", title="", content="")), analysis(), DATE)
    assert prepared["packet"]["missing_sources"] and prepared["packet"]["sources"] == []


def test_source_labels_are_bounded_packet_metadata_never_passages(store):
    """Expose sanitized, bounded `labels` metadata on packet sources without leaking into passages."""
    overlong = "Severity::" + ("x" * 120)
    raw_labels = ["  Security \n", "Severity::medium", "<b>Tag</b>", "", "   ", overlong, *(f"extra-{n}" for n in range(35))]
    labeled = item(kind="gitlab_issue", url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/41412",
                   content=BODY, labels=raw_labels)
    policy_before = review.policy_hash(DEFAULTS)
    prepared = store.prepare_candidate(pending(store, labeled), analysis(), DATE)
    [src] = prepared["packet"]["sources"]
    assert set(src) == {"id", "kind", "authority", "product", "published_at", "updated_at",
                        "upstream_state", "labels", "url", "title", "snapshot", "passages"}
    assert len(src["labels"]) == 28
    assert src["labels"][:3] == ["Security", "Severity::medium", "<b>Tag</b>"]
    assert len(src["labels"][3]) == 100 and src["labels"][3].startswith("Severity::")
    assert all("Severity::" not in p["text"] and "<b>Tag</b>" not in p["text"] for p in src["passages"])
    assert review._packet_refs(prepared["packet"]) == {"S1", *(p["id"] for p in src["passages"])}
    excerpts = _writer_schema({"title": labeled["title"], "content": BODY, "labels": src["labels"],
                               "kind": "gitlab_issue", "authority": "development", "upstream_state": "opened"})
    assert all("Severity::" not in choice for choice in excerpts["properties"]["evidence"]["items"]["enum"])
    assert review.policy_hash(DEFAULTS) == policy_before

    store.ingest({**labeled, "labels": ["Security", "Severity::high"], "updated_at": LATER}, LATER)
    updated_row = store.pending(1, LATER)[0]
    updated_prepared = store.prepare_candidate(updated_row, analysis(), LATER)
    assert updated_prepared["packet"]["sources"][0]["labels"] == ["Security", "Severity::high"]
    assert updated_prepared["source_hash"] != prepared["source_hash"]
    assert updated_prepared["binding_hash"] != prepared["binding_hash"]

    for corrupt in ([7, None, "ValidLabel"], "not-a-list"):
        plain = {**json.loads(updated_row["payload"]), "labels": corrupt}
        updated_row["payload"] = json.dumps(plain)
        with store.db:
            store.db.execute("UPDATE items SET payload=? WHERE id=?", (updated_row["payload"], updated_row["id"]))
        expected = ["ValidLabel"] if isinstance(corrupt, list) else []
        assert store.prepare_candidate(updated_row, analysis(), LATER)["packet"]["sources"][0]["labels"] == expected


def test_tag_and_timeline_notices_upgrade_in_story_scope_while_prose_uses_update_scope(store):
    """Upgrade tag notices in `story` mode while enforcing `update` mode on prose stories."""
    tag = item(kind="tag", title="tor-0.4.9.16", url="https://example.org/tag/0.4.9.16", content="")
    first = seed_story(store, tag, tag_notice(tag), key="tag")
    update_entry = {"at": DATE, "text": "Earlier operator note.", "sources": [{"url": "https://example.org/note", "title": "Note"}]}
    for action, args in ((editorial.correct, ({"updates": [update_entry]},)), (editorial.unlock, ())):
        editorial_act(action, store, first["id"], *args, reason="Seed update.", observed=LATER)
    row = pending(store, item(kind="feed", title="Tor 0.4.9.16 released", url="https://example.org/post/0.4.9.16",
                              content="Tor 0.4.9.16 was released with directory fixes.", updated_at=LATER), LATER, target=first["id"])
    with pytest.raises(StaleCandidate):
        store.prepare_candidate(row, update_analysis(evidence=["Tor 0.4.9.16 was released"]), LATER)
    upgraded = store.prepare_candidate(row, analysis(title="Tor 0.4.9.16 released", state="released",
                                                     evidence=["Tor 0.4.9.16 was released"]), LATER)
    assert upgraded["mode"] == "story" and upgraded["story_id"] == first["id"]
    assert upgraded["candidate"]["updates"] == [update_entry]
    store.commit_candidate(upgraded, upgraded["candidate"], "upgraded", LATER, **insert_approval(store, upgraded))

    later2 = "2026-11-10T12:00:00Z"
    followup = pending(store, item(kind="feed", title="Tor 0.4.9.16 released", url="https://example.org/mirror/0.4.9.16",
                                   content="Mirror reports package availability.", updated_at=later2), later2, target=first["id"])
    with pytest.raises(StaleCandidate):
        store.prepare_candidate(followup, analysis(evidence=["Mirror reports package availability."]), later2)
    upd = store.prepare_candidate(followup, update_analysis(update="Mirror reports package availability.",
                                                            state="released", evidence=["Mirror reports package availability."]), later2)
    assert upd["mode"] == "update" and upd["binding"]["mode"] == "update"
    for tampered in (
        {**upd["candidate"], "title": "Tampered title"},
        {**upd["candidate"], "summary": "Tampered summary"},
        {**upd["candidate"], "updates": [upd["candidate"]["updates"][-1]]},
        {**upd["candidate"], "updates": [upd["candidate"]["updates"][0], {**upd["candidate"]["updates"][1], "at": DATE}]},
        {**upd["candidate"], "updates": [upd["candidate"]["updates"][0],
                                         {**upd["candidate"]["updates"][1], "sources": [{"url": "https://example.org/other", "title": "Other"}]}]},
    ):
        with pytest.raises(ReviewRequired):
            store.commit_candidate(upd, tampered, "tampered", later2, **insert_approval(store, upd, tampered))

    store.commit_candidate(upd, upd["candidate"], "valid-update", later2, **insert_approval(store, upd))
    assert coverage_background(store.db, None)["recent"][0]["latest_update"] == "Mirror reports package availability."
    prior_row = dict(store.db.execute("SELECT * FROM stories WHERE id=?", (first["id"],)).fetchone())
    assert len(coverage_background(store.db, prior_row)["prior_story"]["updates"]) == 2

    later3, later4 = "2026-11-11T12:00:00Z", "2026-11-12T12:00:00Z"
    tagged_prose = seed_story(store, item(kind="feed", title="Tor 0.4.9.17 released", url="https://example.org/post/0.4.9.17",
                                          content="Upstream tagged Tor 0.4.9.17 ahead of packaging.", published_at=later3, updated_at=later3),
                              analysis(title="Tor 0.4.9.17 tagged ahead of packaging", state="tagged",
                                       evidence=["Upstream tagged Tor 0.4.9.17 ahead of packaging."]), key="tagged-prose", at=later3)
    prose_followup = pending(store, item(kind="feed", title="Tor 0.4.9.17 released", url="https://example.org/release/0.4.9.17",
                                         content="Tor 0.4.9.17 packages are now available.", published_at=later4, updated_at=later4),
                             later4, target=tagged_prose["id"])
    with pytest.raises(StaleCandidate):
        store.prepare_candidate(prose_followup, analysis(state="released", evidence=["Tor 0.4.9.17 packages are now available."]), later4)
    prose_upd = store.prepare_candidate(prose_followup, update_analysis(update="Tor 0.4.9.17 packages are now available.",
                                                                        state="released", evidence=["Tor 0.4.9.17 packages are now available."]), later4)
    assert prose_upd["mode"] == "update" and prose_upd["story_id"] == tagged_prose["id"]


def test_closed_issue_update_cites_parent_issue_and_named_short_closing_note(store):
    """Cite both the parent issue URL and attributed short closing notes on closed issue updates."""
    url = "https://gitlab.torproject.org/tpo/core/tor/-/work_items/41499"
    opened = item(kind="gitlab_issue", title="dirauth: Remove retired authority from list", url=url,
                  content=BODY, upstream_state="opened", published_at=DATE, updated_at=DATE)
    user_at, done_at, closed_at = "2026-11-09T01:00:00Z", "2026-11-10T14:00:00Z", "2026-11-10T14:05:00Z"
    notes = [
        make_note(3, "Done.", author="maintainer", created_at=done_at, url=url),
        make_note(2, "Ok.", author="maint", created_at=user_at, url=url),
        make_note(1, "Thank you for tracking when updated keys become available.", author="reader", created_at=user_at, url=url),
    ]
    closed = _compose({**opened, "upstream_state": "closed", "updated_at": closed_at}, notes, closed_at, source_key="k1")
    first = seed_story(store, opened, analysis(state="developing", evidence=["requests a source-code change"]), key="opened")
    row = pending(store, closed, closed_at)
    prepared = store.prepare_candidate(
        row,
        update_analysis(update='maintainer commented "Done." and closed the issue.', state="resolved",
                        evidence=["Thank you for tracking when updated keys become available."]),
        closed_at,
    )
    assert prepared["mode"] == "update" and prepared["story_id"] == first["id"]
    entry = prepared["candidate"]["updates"][-1]
    assert entry["at"] == closed_at
    assert entry["sources"] == [
        {"url": url, "title": opened["title"]},
        {"url": f"{url}#note_1", "title": "Public comment by @reader"},
        {"url": f"{url}#note_3", "title": "Public comment by @maintainer"},
    ]
    only_closing = store.prepare_candidate(
        row,
        update_analysis(update='maintainer commented "Done." and closed the issue.', state="resolved",
                        evidence=["requests a source-code change"]),
        closed_at,
    )["candidate"]["updates"][-1]
    assert only_closing["sources"] == [
        {"url": url, "title": opened["title"]},
        {"url": f"{url}#note_3", "title": "Public comment by @maintainer"},
    ]


def test_own_update_input_mail_quote_stripping_preserves_dated_and_eof_from_lines(store):
    """Keep dated reply headings and EOF `From:` lines in `own_update_input` while skipping pure wrapped quotes."""
    list_url = "https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/message/"
    root = item(kind="feed", source_id="tor-relays", url=list_url + "ROOT/",
                title="[tor-relays] Guard relay CPU load spike", content="Initial report on guard relay CPU load.")
    seed_story(store, root, analysis(evidence=["Initial report on guard relay CPU load."]), key="root")
    existing = dict(store.db.execute("SELECT * FROM stories").fetchone())

    dated_reply = item(
        kind="feed", source_id="tor-relays", url=list_url + "R1/",
        title="[tor-relays] Re: Guard relay CPU load spike",
        content="2026-11-14 rollout started:\n2026-11-15 CPU load returned to baseline:\nOn 2026-11-13, Bob wrote:\n> Any update on CPU load?",
        updated_at=LATER,
    )
    mode1, out1 = candidate.own_update_input(store.db, {"id": "r1"}, dated_reply, existing=existing)
    assert mode1 == "update"
    assert out1["content"] == "2026-11-14 rollout started:\n2026-11-15 CPU load returned to baseline:"

    wrapped_quote = item(
        kind="feed", source_id="tor-relays", url=list_url + "R2/",
        title="[tor-relays] Re: Guard relay CPU load spike",
        content="On Wednesday,\n2026-11-16 at 10:00 UTC, Alice wrote:\n> Any update on CPU load?",
        updated_at=LATER,
    )
    mode2, _ = candidate.own_update_input(store.db, {"id": "r2"}, wrapped_quote, existing=existing)
    assert mode2 == "skip"

    eof_from_reply = item(
        kind="feed", source_id="tor-relays", url=list_url + "R3/",
        title="[tor-relays] Re: Guard relay CPU load spike",
        content="> Any metrics?\n\nFrom: our Prometheus metrics on 3 guard relays, CPU dropped 40%.",
        updated_at=LATER,
    )
    mode3, out3 = candidate.own_update_input(store.db, {"id": "r3"}, eof_from_reply, existing=existing)
    assert mode3 == "update" and out3["content"] == "From: our Prometheus metrics on 3 guard relays, CPU dropped 40%."
