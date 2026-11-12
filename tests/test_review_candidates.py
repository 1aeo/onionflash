"""The exact merged public candidate, its evidence and the commit boundary."""

import json

import pytest

from approval_helpers import approve, finish_reviewed
from onionflash import editorial, render, review, source_packet
from onionflash.analyze import tag_notice
from onionflash.candidate import ReviewRequired
from onionflash.comments import INPUT_CHARS, _compose
from onionflash.store import Store
from test_core import DAMAGE, DATE, analysis, damage_item, item


LATER = "2026-11-09T12:00:00Z"
BODY = "The operator reports that old directory-authority keys cannot be trusted and requests a source-code change. " * 4


def pending(store, incoming=None, observed=DATE):
    store.ingest(incoming or item(content=BODY), observed)
    return store.pending(1, observed)[0]


def publish(store, incoming=None, result=None, *, observed=DATE, key="fixture"):
    finish_reviewed(store, pending(store, incoming, observed), result or analysis(), key, observed)
    return store.stories()[0]


def test_prepare_is_read_only_and_an_unreviewed_commit_is_refused(tmp_path):
    with Store(tmp_path / "db") as store:
        row = pending(store)
        before = store.db.total_changes
        prepared = store.prepare_candidate(row, analysis(), DATE)
        assert store.db.total_changes == before
        assert store.stories() == []
        assert prepared["candidate"] == render._prepare_story(prepared["payload"])
        with pytest.raises(ReviewRequired):
            store.commit_candidate(prepared, prepared["candidate"], "unreviewed", DATE)
        assert store.stories() == []
        assert store.db.execute("SELECT COUNT(*) FROM analyses").fetchone()[0] == 0


@pytest.mark.parametrize("field,limit", [("title", 180), ("summary", 1600), ("why_it_matters", 800), ("source_title", 200)])
def test_truncation_at_space_keeps_reviewed_candidate_stable_through_commit(tmp_path, field, limit):
    text = "x" * (limit - 1) + " more supported text"
    incoming = item(content=BODY, **({"title": text} if field == "source_title" else {}))
    result = analysis(**({field: text} if field != "source_title" else {}))
    with Store(tmp_path / "db") as store:
        row = pending(store, incoming)
        prepared = store.prepare_candidate(row, result, DATE)
        public = prepared["candidate"]
        assert render._prepare_story(public) == public
        receipt = approve(store, prepared)
        store.commit_candidate(prepared, public, "truncated-source", DATE, **receipt)
        assert render._prepare_story(store.stories()[0]) == public


def test_poll_only_metadata_does_not_invalidate_approval(tmp_path):
    with Store(tmp_path / "db") as store:
        row = pending(store)
        prepared = store.prepare_candidate(row, analysis(), DATE)
        receipt = approve(store, prepared)
        payload = json.loads(row["payload"])
        payload.update(comments_checked_at=LATER, comments_source_key="poll-only-marker")
        with store.db:
            store.db.execute("UPDATE items SET payload=?,last_seen=? WHERE id=?", (json.dumps(payload), LATER, row["id"]))
        assert store.commit_candidate(prepared, prepared["candidate"], "approved", LATER, **receipt)["status"] == "published"


def test_new_story_is_dated_when_published_not_when_first_prepared(tmp_path):
    # A retried review or an operator retry commits a candidate prepared earlier.
    with Store(tmp_path / "db") as store:
        prepared = store.prepare_candidate(pending(store), analysis(), DATE)
        store.commit_candidate(prepared, prepared["candidate"], "retried", LATER, **approve(store, prepared))
        assert store.stories()[0]["added_at"] == LATER


def test_locked_story_skips_model_prose_but_records_analysis_and_grouping(tmp_path):
    with Store(tmp_path / "db") as store:
        old = publish(store)
        editorial.correct(store.db, old["id"], {"summary": "An operator correction."},
                          reason="Source clarification", expect_hash=editorial.show(store.db, old["id"])["hash"], observed=LATER)
        incoming = item(content=BODY + " Updated detail.", updated_at=LATER)
        row = pending(store, incoming, LATER)
        prepared = store.prepare_candidate(row, analysis(summary="Unreviewed replacement."), LATER)
        assert prepared["locked"] and prepared["candidate"] is None
        assert store.commit_candidate(prepared, None, "locked", LATER)["status"] == "locked"
        assert store.stories()[0]["summary"] == "An operator correction."
        assert store.db.execute("SELECT COUNT(*) FROM analyses").fetchone()[0] == 2
        assert store.db.execute("SELECT story_id FROM items WHERE id=?", (row["id"],)).fetchone()[0] == old["id"]


def test_cold_required_source_holds_and_hot_historical_snapshot_is_labeled(tmp_path):
    with Store(tmp_path / "db") as store:
        old = publish(store, item(content=BODY, updated_at=LATER), observed=LATER)
        with store.db:
            source = json.loads(store.db.execute("SELECT payload FROM items WHERE id=?", (old["editorial_item"],)).fetchone()[0])
            source.pop("content")
            store.db.execute("UPDATE items SET payload=? WHERE id=?", (json.dumps(source), old["editorial_item"]))
        row = pending(store, item(url="https://example.org/other", source_id="other", content=BODY), LATER)
        prepared = store.prepare_candidate(row, analysis(), LATER)
        assert not prepared["packet"]["missing_sources"]
        historical = next(source for source in prepared["packet"]["sources"] if source["snapshot"] == "historical-analysis")
        assert historical["published_at"] == DATE and historical["updated_at"] == LATER
        with store.db:
            store.db.execute("DELETE FROM analyses WHERE source_item_id=?", (old["editorial_item"],))
        missing = store.prepare_candidate(row, analysis(), LATER)
        assert missing["packet"]["missing_sources"]
        with pytest.raises(ReviewRequired):
            store.commit_candidate(missing, missing["candidate"], "cold", LATER, **approve(store, missing))


def test_packet_limits_and_required_source_overflow(tmp_path, monkeypatch):
    with Store(tmp_path / "db") as store:
        old = publish(store, item(content=BODY * 100, updated_at=LATER), observed=LATER)
        row = pending(store, item(url="https://example.org/other", source_id="other", content=BODY * 100), LATER)
        limits = {"max_sources": 2, "max_passages": 6, "passage_chars": 100, "max_source_chars": 450}
        monkeypatch.setattr(source_packet, "LIMITS", limits)
        prepared = store.prepare_candidate(row, analysis(), LATER)
        packet = prepared["packet"]
        assert packet["truncated"] and not packet["missing_sources"]
        assert len(packet["sources"]) == 2
        passages = [p for source in packet["sources"] for p in source["passages"]]
        assert len(passages) <= 6 and sum(len(p["text"]) for p in passages) <= 450
        assert all(len(p["text"]) <= 100 for p in passages)
        assert len({p["id"] for p in passages}) == len(passages)
        limits["max_sources"] = 1
        overflow = store.prepare_candidate(row, analysis(), LATER)
        assert overflow["packet"]["missing_sources"]


@pytest.mark.parametrize("field", ["candidate_hash", "source_hash", "binding_hash", "policy_hash"])
def test_approval_receipt_is_bound_to_exact_candidate_sources_context_and_policy(tmp_path, field):
    with Store(tmp_path / "db") as store:
        prepared = store.prepare_candidate(pending(store), analysis(), DATE)
        receipt = approve(store, prepared)
        with store.db:
            store.db.execute("UPDATE review_approvals SET " + field + "='wrong' WHERE key=?", (receipt["approval_key"],))
        with pytest.raises(ReviewRequired):
            store.commit_candidate(prepared, prepared["candidate"], "bad-receipt", DATE, **receipt)
        assert store.stories() == []


def test_semantic_repair_is_exact_and_immutable_public_fields_cannot_change(tmp_path):
    with Store(tmp_path / "db") as store:
        prepared = store.prepare_candidate(pending(store), analysis(), DATE)
        repaired = review.apply_repair(prepared["candidate"], {"why_it_matters": "", "priority": "normal"})
        receipt = approve(store, prepared, repaired)
        wrong = {**repaired, "published_at": LATER}
        with pytest.raises(ReviewRequired):
            store.commit_candidate(prepared, wrong, "bad-date", DATE, **approve(store, prepared, wrong))
        store.commit_candidate(prepared, repaired, "exact-repair", DATE, **receipt)
        assert render._prepare_story(store.stories()[0]) == repaired
        record = json.loads(store.db.execute("SELECT review_record FROM analyses WHERE cache_key='exact-repair'").fetchone()[0])
        assert record["candidate"] == repaired and record["packet"] == prepared["packet"]


def test_review_audits_append_instead_of_losing_retried_decisions(tmp_path):
    with Store(tmp_path / "db") as store:
        row = pending(store)
        with store.db:
            first = store.record_analysis(row, analysis(), "same-writer-key", DATE, review_record={"verdict": "hold"})
            second = store.record_analysis(row, analysis(), "same-writer-key", LATER, review_record={"verdict": "approve"})
        assert first != second
        assert [json.loads(row[0])["verdict"] for row in store.db.execute("SELECT review_record FROM analyses ORDER BY created_at")] == ["hold", "approve"]


def test_comment_evidence_has_real_author_dates(tmp_path):
    url = "https://gitlab.torproject.org/tpo/core/tor/-/work_items/41473"
    note = {"id": "gid://gitlab/Note/42", "url": url + "#note_42", "title": "Public comment by @maintainer",
            "author": "maintainer", "created_at": LATER, "body": "The proposed source-code fix still needs review."}
    incoming = _compose(item(url=url, content=BODY), [note], LATER, source_key="k")
    with Store(tmp_path / "db") as store:
        row = pending(store, incoming, LATER)
        prepared = store.prepare_candidate(row, analysis(evidence=[note["body"]]), LATER)
        [source] = prepared["packet"]["sources"]
        # The attribution is structured, never text a note body could imitate.
        assert [p for p in source["passages"] if "author" in p] == [
            {"id": "S1:P2", "author": "maintainer", "created_at": LATER, "url": note["url"], "text": note["body"]}]
        assert prepared["candidate"]["updated_at"] == LATER  # the cited note's creation time
        assert prepared["candidate"]["published_at"] == DATE


def test_uncited_corrective_note_survives_long_description_and_binds_approval(tmp_path):
    url = "https://gitlab.torproject.org/tpo/core/tor/-/work_items/41473"
    note = {"id": "gid://gitlab/Note/99", "url": url + "#note_99", "title": "Public comment by @maintainer",
            "author": "maintainer", "created_at": LATER,
            "body": "Correction: relay operators do not need to edit their configurations."}
    incoming = _compose(item(url=url, content=BODY * 100), [note], LATER, source_key="k")
    with Store(tmp_path / "db") as store:
        row = pending(store, incoming, LATER)
        draft = analysis(evidence=["The operator reports that old directory-authority keys cannot be trusted"])
        prepared = store.prepare_candidate(row, draft, LATER)
        assert len(prepared["candidate"]["sources"]) == 1  # The writer never cited the corrective note.
        [source] = prepared["packet"]["sources"]
        assert [(p["author"], p["text"]) for p in source["passages"] if "author" in p] == [("maintainer", note["body"])]
        assert source["passages"][2]["text"].startswith(BODY)  # the description follows the note
        # With room to spare, review also sees description text past the writer's window.
        assert sum(len(p["text"]) for p in source["passages"]) == source_packet.LIMITS["max_source_chars"]
        assert prepared["packet"]["truncated"]
        assert prepared["candidate"]["updated_at"] == DATE  # a note review only saw does not date the story
        assert prepared["candidate"]["published_at"] == DATE
        incoming["public_comments"][0]["body"] += " The change is not released yet."
        incoming = _compose(incoming, incoming["public_comments"], LATER, source_key="k")
        store.ingest(incoming, LATER)
        refreshed_row = store.pending(1, LATER)[0]
        refreshed = store.prepare_candidate(refreshed_row, draft, LATER)
        assert refreshed["source_hash"] != prepared["source_hash"]


@pytest.mark.parametrize("missing_body", [False, True])
def test_legacy_multi_source_prose_requires_all_evidence_not_guessed_writer(tmp_path, monkeypatch, missing_body):
    with Store(tmp_path / "db") as store:
        first = item(content=BODY, updated_at=LATER)
        publish(store, first, analysis(summary="A source-supported grouped account.", confidence="confirmed"), observed=LATER)
        second = item(url="https://example.org/second", source_id="second", content=BODY)
        old = publish(store, second, analysis(), observed=LATER, key="second")
        assert len(old["sources"]) == 2
        old.pop("editorial_item")
        old.pop("editorial_analysis_key", None)
        with store.db:
            store.db.execute("UPDATE stories SET payload=? WHERE id=?", (json.dumps(old), old["id"]))
            if missing_body:
                cold = json.loads(store.db.execute("SELECT payload FROM items WHERE id=?", (first["id"],)).fetchone()[0])
                cold.pop("content")
                store.db.execute("UPDATE items SET payload=? WHERE id=?", (json.dumps(cold), first["id"]))
                store.db.execute("DELETE FROM analyses WHERE source_item_id=?", (first["id"],))
        second["content"] += " A further detail in the related report."
        row = pending(store, second, LATER)
        prepared = store.prepare_candidate(row, analysis(), LATER)
        assert prepared["payload"]["editorial_item"] is None
        assert prepared["candidate"]["summary"] == old["summary"]
        if missing_body:
            assert first["url"] in prepared["packet"]["missing_sources"]
            with pytest.raises(ReviewRequired):
                store.commit_candidate(prepared, prepared["candidate"], "legacy-missing", LATER, **approve(store, prepared))
        else:
            assert not prepared["packet"]["missing_sources"]
            assert {source["url"] for source in prepared["packet"]["sources"]} == {first["url"], second["url"]}
            # Resource bounds still hold even when the writer is unidentified.
            monkeypatch.setitem(source_packet.LIMITS, "max_sources", 1)
            bounded = store.prepare_candidate(row, analysis(), LATER)
            assert bounded["packet"]["missing_sources"]
            receipt = approve(store, prepared)
            store.commit_candidate(prepared, prepared["candidate"], "legacy-reviewed", LATER, **receipt)
            assert store.stories()[0]["summary"] == old["summary"]


@pytest.mark.parametrize("historical", ["recorded", "legacy", "missing", "wrong-url"])
def test_stable_timeline_identity_cannot_label_new_commit_bytes_with_old_citation(tmp_path, historical):
    old_url = "https://gitlab.example/metrics/-/blob/" + "1" * 40 + "/README.md?plain=1#L10"
    new_url = old_url.replace("1" * 40, "2" * 40).replace("#L10", "#L20")
    timeline = item(kind="metrics_timeline", authority="telemetry", product="network",
                    source_entry_id="a" * 64, title="Release of tor 0.4.9.16", url=old_url,
                    content="The original timeline records the release on November 7.")
    with Store(tmp_path / "db") as store:
        old = publish(store, timeline, analysis(summary="The timeline records the release on November 7."))
        moved = {**timeline, "url": new_url, "content": "The corrected timeline says the release occurred November 5.", "updated_at": LATER}
        store.ingest(moved, LATER)
        assert moved["id"] == timeline["id"]  # Repository entry identity survives commit and line changes.
        with store.db:
            if historical in {"legacy", "missing", "wrong-url"}:
                old.pop("editorial_analysis_key", None)
                store.db.execute("UPDATE stories SET payload=? WHERE id=?", (json.dumps(old), old["id"]))
            if historical in {"missing", "wrong-url"}:
                store.db.execute("DELETE FROM analyses WHERE source_item_id=?", (timeline["id"],))
            if historical in {"legacy", "wrong-url"}:
                changed_row = dict(store.db.execute("SELECT * FROM items WHERE id=?", (timeline["id"],)).fetchone())
                store.record_analysis(changed_row, analysis(), "later-snapshot", LATER)
        tag = item(kind="tag", title="tor-0.4.9.16", url="https://example.org/tag/0.4.9.16", content="", updated_at=LATER)
        store.ingest(tag, LATER)
        row = dict(store.db.execute("SELECT * FROM items WHERE id=?", (tag["id"],)).fetchone())
        prepared = store.prepare_candidate(row, tag_notice(json.loads(row["payload"])), LATER)
        assert old_url in {source["url"] for source in prepared["candidate"]["sources"]}
        assert new_url not in {source["url"] for source in prepared["candidate"]["sources"]}
        packet_text = "".join(p["text"] for source in prepared["packet"]["sources"] for p in source["passages"])
        assert "corrected timeline" not in packet_text
        if historical in {"missing", "wrong-url"}:
            assert old_url in prepared["packet"]["missing_sources"]
            with pytest.raises(ReviewRequired):
                store.commit_candidate(prepared, prepared["candidate"], "missing-history", LATER, **approve(store, prepared))
        else:
            assert not prepared["packet"]["missing_sources"]
            source = next(source for source in prepared["packet"]["sources"] if source["url"] == old_url)
            assert source["snapshot"] == "historical-analysis"
            assert source["updated_at"] == DATE
            assert "original timeline" in packet_text
            # Even an exact historical packet stays bound to the current source state
            # that selected it, so a later update changes the binding but not the packet.
            store.ingest({**moved, "content": "A further timeline correction.", "updated_at": "2026-11-10T12:00:00Z"}, "2026-11-10T12:00:00Z")
            again = store.prepare_candidate(row, tag_notice(json.loads(row["payload"])), LATER)
            assert again["source_hash"] == prepared["source_hash"] and again["binding_hash"] != prepared["binding_hash"]
        assert store.stories()[0]["summary"] == old["summary"]


@pytest.mark.parametrize("kind", [*DAMAGE, "blob"])
def test_a_cited_source_with_a_damaged_saved_copy_reads_as_its_snapshot_or_missing(tmp_path, kind):
    """A story's earlier source whose saved copy is damaged never stops the review of an update."""
    with Store(tmp_path / "db") as store:
        old = publish(store, item(content=BODY, updated_at=LATER), observed=LATER)
        damage_item(store.db, old["editorial_item"], kind)
        with store.db:  # a newer snapshot of the same citation; the story's own analysis is read first
            store.db.execute("""INSERT INTO analyses(cache_key,result,created_at,source_payload,source_item_id)
                SELECT 'newer',result,'2026-11-10T12:00:00Z',json_set(source_payload,'$.content','A newer account.'),source_item_id
                FROM analyses WHERE cache_key=?""", (old["editorial_analysis_key"],))
        row = pending(store, item(url="https://example.org/other", source_id="other", content=BODY), LATER)
        prepared = store.prepare_candidate(row, analysis(), LATER)
        cited = next(source for source in prepared["packet"]["sources"] if source["url"] == "https://example.org/news/1")
        # A BLOB that is valid UTF-8 JSON still reads as the current copy.
        assert cited["snapshot"] == ("current" if kind == "blob" else "historical-analysis")
        assert cited["passages"][-1]["text"] == BODY and not prepared["packet"]["missing_sources"]
        with store.db:
            store.db.execute("DELETE FROM analyses WHERE source_item_id=?", (old["editorial_item"],))
        missing = store.prepare_candidate(row, analysis(), LATER)["packet"]["missing_sources"]
        assert missing == ([] if kind == "blob" else ["https://example.org/news/1"])


@pytest.mark.parametrize("body", ["", None])
def test_title_only_source_is_reviewable_but_compacted_snapshot_is_missing(tmp_path, body):
    with Store(tmp_path / "db") as store:
        source = item(kind="feed", title="Tor 0.4.9.16 released", content="")
        row = pending(store, source)
        if body is None:
            cold = json.loads(row["payload"])
            cold.pop("content")
            row["payload"] = json.dumps(cold)
            with store.db:
                store.db.execute("UPDATE items SET payload=? WHERE id=?", (row["payload"], row["id"]))
        draft = analysis(title=source["title"], summary="The release feed announces Tor 0.4.9.16.",
                         why_it_matters="", category="release", tags=["release"], state="released", evidence=[source["title"]])
        prepared = store.prepare_candidate(row, draft, DATE)
        if body is None:
            assert prepared["packet"]["missing_sources"] == [source["url"]]
            assert prepared["packet"]["sources"] == []
        else:
            assert not prepared["packet"]["missing_sources"]
            assert prepared["packet"]["sources"][0]["passages"] == [{"id": "S1:P1", "text": source["title"]}]
            store.commit_candidate(prepared, prepared["candidate"], "title-only", DATE, **approve(store, prepared))
            assert store.stories()[0]["title"] == source["title"]


def test_writer_source_keeps_the_text_its_writer_saw_and_short_sources_leave_room(tmp_path):
    """The writer's window, with every note it saw, beats any share; other sources fill the rest smallest first
    and leave the writer what they do not need."""
    def release(name, content, **changes):
        return item(**{"kind": "feed", "title": "Tor 0.4.9.16 released", "url": "https://example.org/release/" + name,
                       "source_id": name, "content": content, **changes})

    url = "https://gitlab.torproject.org/tpo/core/tor/-/work_items/41473"
    notes = [{"id": f"gid://gitlab/Note/{n}", "url": f"{url}#note_{n}", "title": f"Public comment by @user{n}",
              "author": f"user{n}", "created_at": DATE, "body": f"Note {n} reports a detail. " * 22} for n in range(12, 0, -1)]
    notes[-1]["body"] += "The oldest note confirms TROVE-2026-001."
    # The description runs past the writer's window, into room the other sources leave.
    writer = _compose(release("issue", "Release notes for the announced change. " * 250, kind="gitlab_issue",
                              url=url, updated_at=LATER), notes, LATER, source_key="k")
    long_mirror = release("0-long", "A longer mirror of the announcement. " * 130)  # listed before the short ones
    with Store(tmp_path / "db") as store:
        for name in ["a", "b", "c", "d", "e", "f"]:
            publish(store, release(name, f"Short mirror {name}."), key=name)
        publish(store, long_mirror, key="long")
        row = pending(store, writer, LATER)
        prepared = store.prepare_candidate(row, analysis(evidence=["The oldest note confirms TROVE-2026-001"]), LATER)
        assert prepared["payload"]["editorial_item"] == row["id"] and not prepared["packet"]["missing_sources"]
        assert url + "#note_1" in {source["url"] for source in prepared["candidate"]["sources"]}
        packet = {source["url"]: source["passages"] for source in prepared["packet"]["sources"]}
        assert len(packet) == 8
        seen = [p["text"] for p in packet[url] if "author" not in p]
        assert "".join(seen) == writer["title"] + writer["content"]
        assert [p["text"] for p in packet[url] if "author" in p] == [note["body"] for note in notes]
        assert "".join(p["text"] for p in packet[long_mirror["url"]]) == long_mirror["title"] + long_mirror["content"]
        assert sum(len(p["text"]) for passages in packet.values() for p in passages) <= source_packet.LIMITS["max_source_chars"]


def test_kept_prose_keeps_its_writer_window_and_an_incoming_issue_keeps_every_note(tmp_path):
    """A confirmed post keeps the prose; review still sees every note of the incoming issue, the oldest a correction."""
    def release(name, content):
        return item(kind="feed", title="Tor 0.4.9.16 released", url="https://example.org/release/" + name, source_id=name, content=content)

    post = release("post", "The release fixes the reported crash and updates the directory code. " * 220)
    url = "https://gitlab.torproject.org/tpo/core/tor/-/work_items/41473"
    notes = [{"id": f"gid://gitlab/Note/{n}", "url": f"{url}#note_{n}", "title": f"Public comment by @user{n}",
              "author": f"user{n}", "created_at": LATER, "body": f"Note {n} confirms the crash."} for n in range(12, 0, -1)]
    notes[-1]["body"] = "Correction: this release does not fix the reported crash."
    # The description outgrows the issue's share; the mirrors are longer but come in fewer passages.
    incoming = _compose(item(title=post["title"], url=url, updated_at=LATER, content="Release tracking notes. " * 75),
                        notes, LATER, source_key="k")
    with Store(tmp_path / "db") as store:
        publish(store, post, analysis(confidence="confirmed", evidence=["The release fixes the reported crash"]), key="post")
        for name in "abcdef":
            publish(store, release(name, f"Mirror {name} of the announcement. " * 75), key=name)
        row = pending(store, incoming, LATER)
        prepared = store.prepare_candidate(row, analysis(evidence=["Release tracking notes"]), LATER)
        assert prepared["payload"]["editorial_item"] != row["id"] and not prepared["packet"]["missing_sources"]
        packet = {source["url"]: source["passages"] for source in prepared["packet"]["sources"]}
        assert len(packet) == 8
        assert "".join(p["text"] for p in packet[post["url"]]) == post["title"] + post["content"][:INPUT_CHARS]
        assert [p["text"] for p in packet[url] if "author" in p] == [note["body"] for note in notes]


def test_empty_title_and_body_are_not_review_evidence(tmp_path):
    with Store(tmp_path / "db") as store:
        row = pending(store, item(kind="feed", title="", content=""))
        prepared = store.prepare_candidate(row, analysis(), DATE)
        assert prepared["packet"]["missing_sources"]
        assert prepared["packet"]["sources"] == []
