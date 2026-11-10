"""The exact merged public candidate, its evidence and the commit boundary."""

import copy
import json

import pytest

from onionflash import editorial, render, review, review_gate
from onionflash.analyze import tag_notice
from onionflash.candidate import ReviewRequired, StaleCandidate
from onionflash.source_packet import DEFAULT_LIMITS
from onionflash.store import Store
from onionflash.util import digest
from test_core import DATE, analysis, item


LATER = "2026-11-09T12:00:00Z"
BODY = "The operator reports that old directory-authority keys cannot be trusted and requests a source-code change. " * 4


def pending(store, incoming=None, observed=DATE):
    store.ingest(incoming or item(content=BODY), observed)
    return store.pending(1, observed)[0]


def approve(store, prepared, candidate=None, *, policy="test-policy", verdict=None):
    candidate = candidate or prepared["candidate"]
    review_gate.initialize(store)
    ref = prepared["packet"]["sources"][0]["passages"][0]["id"]
    verdict = verdict or {"verdict": "approve", "repair": None, "issues": [],
                          "criteria": {name: {"outcome": "pass", "source_refs": [ref], "reason": "Fixture review."} for name in review.CRITERIA}}
    key = digest([digest(candidate), prepared["source_hash"], policy, prepared["binding_hash"]])
    audit = {"candidate": candidate, "packet": prepared["packet"], "reviews": [verdict]}
    with store.db:
        store.db.execute("INSERT OR REPLACE INTO review_approvals VALUES(?,?,?,?,?,?,?,?,?)",
                         (key, digest(candidate), prepared["source_hash"], policy, prepared["binding_hash"],
                          json.dumps(verdict), json.dumps(audit), DATE, DATE))
    return {"approval_key": key, "policy_hash": policy}


def publish(store, incoming=None, result=None, *, observed=DATE, key="fixture", input_chars=14000):
    row = pending(store, incoming, observed)
    prepared = store.prepare_candidate(row, result or analysis(), observed, input_chars=input_chars)
    receipt = approve(store, prepared) if prepared["requires_review"] else {}
    store.commit_candidate(prepared, prepared["candidate"], key, observed, **receipt)
    return store.stories()[0]


def test_prepare_is_read_only_and_finish_cannot_bypass_final_review(tmp_path):
    with Store(tmp_path / "db") as store:
        row = pending(store)
        before = store.db.total_changes
        prepared = store.prepare_candidate(row, analysis(), DATE)
        assert store.db.total_changes == before
        assert store.stories() == [] and prepared["requires_review"]
        assert prepared["candidate"] == render._prepare_story(prepared["payload"])
        with pytest.raises(ReviewRequired):
            store.finish(row, analysis(), "unreviewed", DATE)
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


def test_review_sees_retained_bad_text_and_actual_prior_writer_source(tmp_path):
    with Store(tmp_path / "db") as store:
        old = publish(store, item(content=BODY, updated_at=LATER),
                      analysis(why_it_matters="Operators must edit their configurations."), observed=LATER)
        incoming = item(url="https://example.org/arti/1", source_id="arti", content=BODY)
        row = pending(store, incoming, LATER)
        prepared = store.prepare_candidate(row, analysis(why_it_matters="The report requests a source-code change."), LATER)
        assert prepared["candidate"]["why_it_matters"] == old["why_it_matters"]
        assert prepared["candidate"]["id"] == old["id"]
        assert prepared["candidate"]["published_at"] == old["published_at"]
        assert prepared["writer_item_id"] == old["editorial_item"]
        assert len(prepared["candidate"]["sources"]) == 2
        passages = [p["text"] for source in prepared["packet"]["sources"] for p in source["passages"]]
        assert BODY in passages
        assert not any("Operators must edit" in text for text in passages)
        repaired = review.apply_repair(prepared["candidate"], {"why_it_matters": ""})
        receipt = approve(store, prepared, repaired)
        store.commit_candidate(prepared, repaired, "repair", LATER, **receipt)
        final = store.stories()[0]
        assert final["why_it_matters"] == ""
        assert final["id"] == old["id"] and final["published_at"] == old["published_at"]


@pytest.mark.parametrize("change", ["item", "supporting-source", "story", "lock", "new-story"])
def test_stale_approval_never_writes_or_remerges(tmp_path, change):
    with Store(tmp_path / "db") as store:
        old = publish(store) if change != "new-story" else None
        incoming = item(url="https://example.org/second", source_id="second", content=BODY, updated_at=LATER)
        row = pending(store, incoming, LATER)
        prepared = store.prepare_candidate(row, analysis(), LATER)
        receipt = approve(store, prepared)
        if change == "item":
            incoming["content"] += " Corrected evidence."
            store.ingest(incoming, LATER)
        elif change == "supporting-source":
            original = json.loads(store.db.execute("SELECT payload FROM items WHERE id=?", (old["editorial_item"],)).fetchone()[0])
            original["content"] += " A later source correction."
            original["updated_at"] = LATER
            store.ingest(original, LATER)
        elif change == "story":
            with store.db:
                store.db.execute("UPDATE stories SET updated_at=? WHERE id=?", (LATER, old["id"]))
        elif change == "lock":
            current = editorial.show(store.db, old["id"])
            editorial.correct(store.db, old["id"], {"summary": "Operator-reviewed source text."},
                              reason="Correction", expect_hash=current["hash"], observed=LATER)
        else:
            value = prepared["payload"]
            with store.db:
                store.db.execute("INSERT INTO stories VALUES(?,?,?,?,?)", (value["id"], prepared["cluster_key"], json.dumps(value), value["published_at"], value["updated_at"]))
        before = [dict(row) for row in store.db.execute("SELECT * FROM stories")]
        with pytest.raises(StaleCandidate):
            store.commit_candidate(prepared, prepared["candidate"], "stale", LATER, **receipt)
        assert [dict(row) for row in store.db.execute("SELECT * FROM stories")] == before
        assert not store.db.in_transaction


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


def test_tag_exemption_applies_to_final_candidate_not_incoming_kind(tmp_path):
    release = item(kind="feed", title="Tor 0.4.9.16 released", url="https://example.org/release", content=BODY)
    tag = item(kind="tag", title="tor-0.4.9.16", url="https://example.org/tag", content="", updated_at=LATER)
    with Store(tmp_path / "db") as store:
        old = publish(store, release, analysis(title="Tor release includes security changes.", state="released"))
        row = pending(store, tag, LATER)
        prepared = store.prepare_candidate(row, tag_notice(json.loads(row["payload"])), LATER)
        assert prepared["requires_review"] and not prepared["wholly_deterministic"]
        assert prepared["candidate"]["title"] == old["title"]
        with pytest.raises(ReviewRequired):
            store.finish(row, tag_notice(json.loads(row["payload"])), "tag-model-merge", LATER)
    with Store(tmp_path / "new-db") as store:
        row = pending(store, tag, LATER)
        result = tag_notice(json.loads(row["payload"]))
        prepared = store.prepare_candidate(row, result, LATER)
        assert prepared["wholly_deterministic"] and not prepared["requires_review"]
        store.finish(row, result, "literal", LATER)
        assert store.stories()[0]["state"] == "tagged"


def test_cold_required_source_holds_and_hot_historical_snapshot_is_labeled(tmp_path):
    with Store(tmp_path / "db") as store:
        old = publish(store, item(content=BODY, updated_at=LATER), observed=LATER)
        with store.db:
            source = json.loads(store.db.execute("SELECT payload FROM items WHERE id=?", (old["editorial_item"],)).fetchone()[0])
            source.pop("content")
            store.db.execute("UPDATE items SET payload=? WHERE id=?", (json.dumps(source), old["editorial_item"]))
        row = pending(store, item(url="https://example.org/other", source_id="other", content=BODY), LATER)
        prepared = store.prepare_candidate(row, analysis(), LATER)
        assert not prepared["missing_sources"]
        historical = next(source for source in prepared["packet"]["sources"] if source["snapshot"] == "historical-analysis")
        assert historical["published_at"] == DATE and historical["updated_at"] == LATER
        receipt = approve(store, prepared)
        with store.db:
            store.db.execute("DELETE FROM analyses WHERE source_item_id=?", (old["editorial_item"],))
        with pytest.raises(StaleCandidate):
            store.commit_candidate(prepared, prepared["candidate"], "evicted", LATER, **receipt)
        missing = store.prepare_candidate(row, analysis(), LATER)
        assert missing["missing_sources"]
        with pytest.raises(ReviewRequired):
            store.commit_candidate(missing, missing["candidate"], "cold", LATER, **approve(store, missing))


def test_packet_limits_and_required_source_overflow(tmp_path):
    with Store(tmp_path / "db") as store:
        old = publish(store, item(content=BODY * 100, updated_at=LATER), observed=LATER)
        row = pending(store, item(url="https://example.org/other", source_id="other", content=BODY * 100), LATER)
        limits = {"max_sources": 2, "max_passages": 6, "passage_chars": 100, "max_source_chars": 450}
        prepared = store.prepare_candidate(row, analysis(), LATER, review_settings=limits)
        packet = prepared["packet"]
        assert packet["truncated"] and not packet["missing_sources"]
        assert len(packet["sources"]) == 2
        passages = [p for source in packet["sources"] for p in source["passages"]]
        assert len(passages) <= 6 and sum(len(p["text"]) for p in passages) <= 450
        assert all(len(p["text"]) <= 100 for p in passages)
        assert len({p["id"] for p in passages}) == len(passages)
        overflow = store.prepare_candidate(row, analysis(), LATER, review_settings={**limits, "max_sources": 1})
        assert overflow["missing_sources"]


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


def test_comment_evidence_has_real_author_dates_and_invalidates_stale_approval(tmp_path):
    from onionflash.comments import _compose
    url = "https://gitlab.torproject.org/tpo/core/tor/-/work_items/41473"
    note = {"id": "gid://gitlab/Note/42", "url": url + "#note_42", "title": "Public comment by @maintainer",
            "author": "maintainer", "created_at": DATE, "updated_at": LATER,
            "body": "The proposed source-code fix still needs review."}
    incoming = _compose(item(url=url, content=BODY), [note], LATER)
    with Store(tmp_path / "db") as store:
        row = pending(store, incoming, LATER)
        prepared = store.prepare_candidate(row, analysis(evidence=[note["body"]]), LATER, input_chars=4000)
        assert len(prepared["packet"]["sources"]) == 1
        text = "".join(p["text"] for p in prepared["packet"]["sources"][0]["passages"])
        assert "@maintainer" in text and DATE in text and LATER in text
        assert note["url"] in text and note["body"] in text
        assert prepared["candidate"]["updated_at"] == LATER
        assert prepared["candidate"]["published_at"] == DATE
        receipt = approve(store, prepared)
        altered = json.loads(row["payload"])
        altered["public_comments"][0]["body"] = "The earlier comment has been withdrawn."
        with store.db:
            store.db.execute("UPDATE items SET payload=? WHERE id=?", (json.dumps(altered), row["id"]))
        with pytest.raises(StaleCandidate):
            store.commit_candidate(prepared, prepared["candidate"], "comment-race", LATER, **receipt)


def test_raw_payload_or_packet_mutation_cannot_reuse_an_approval(tmp_path):
    with Store(tmp_path / "db") as store:
        prepared = store.prepare_candidate(pending(store), analysis(), DATE)
        receipt = approve(store, prepared)
        altered = copy.deepcopy(prepared)
        altered["payload"]["editorial_kind"] = "tag"
        with pytest.raises(StaleCandidate):
            store.commit_candidate(altered, altered["candidate"], "provenance-tamper", DATE, **receipt)
        altered = copy.deepcopy(prepared)
        altered["packet"]["sources"][0]["passages"][0]["text"] = "Replacement source text."
        with pytest.raises(StaleCandidate):
            store.commit_candidate(altered, altered["candidate"], "packet-tamper", DATE, **receipt)
        assert not store.stories()


def test_uncited_corrective_note_survives_long_description_and_binds_approval(tmp_path):
    from onionflash.comments import _compose
    url = "https://gitlab.torproject.org/tpo/core/tor/-/work_items/41473"
    note = {"id": "gid://gitlab/Note/99", "url": url + "#note_99", "title": "Public comment by @maintainer",
            "author": "maintainer", "created_at": DATE, "updated_at": LATER,
            "body": "Correction: relay operators do not need to edit their configurations."}
    incoming = _compose(item(url=url, content=BODY * 100), [note], LATER)
    limits = {**DEFAULT_LIMITS, "max_source_chars": 2000, "passage_chars": 500}
    with Store(tmp_path / "db") as store:
        row = pending(store, incoming, LATER)
        draft = analysis(evidence=["The operator reports that old directory-authority keys cannot be trusted"])
        prepared = store.prepare_candidate(row, draft, LATER, input_chars=14000, review_settings=limits)
        assert len(prepared["candidate"]["sources"]) == 1  # The writer never cited the corrective note.
        text = "".join(p["text"] for source in prepared["packet"]["sources"] for p in source["passages"])
        assert note["body"] in text and "@maintainer" in text
        assert "The operator reports" in text
        assert prepared["packet"]["truncated"]
        assert prepared["candidate"]["updated_at"] == LATER
        assert prepared["candidate"]["published_at"] == DATE
        receipt = approve(store, prepared)
        incoming["public_comments"][0]["body"] += " The change is not released yet."
        incoming = _compose(incoming, incoming["public_comments"], LATER)
        store.ingest(incoming, LATER)
        refreshed_row = store.pending(1, LATER)[0]
        refreshed = store.prepare_candidate(refreshed_row, draft, LATER, input_chars=14000, review_settings=limits)
        assert refreshed["source_hash"] != prepared["source_hash"]
        with pytest.raises(StaleCandidate):
            store.commit_candidate(prepared, prepared["candidate"], "uncited-change", LATER, **receipt)


@pytest.mark.parametrize("missing_body", [False, True])
def test_legacy_multi_source_prose_requires_all_evidence_not_guessed_writer(tmp_path, missing_body):
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
        assert prepared["writer_item_id"] is None
        assert prepared["candidate"]["summary"] == old["summary"]
        assert prepared["requires_review"]
        if missing_body:
            assert first["url"] in prepared["missing_sources"]
            with pytest.raises(ReviewRequired):
                store.commit_candidate(prepared, prepared["candidate"], "legacy-missing", LATER, **approve(store, prepared))
        else:
            assert not prepared["missing_sources"]
            assert {source["url"] for source in prepared["packet"]["sources"]} == {first["url"], second["url"]}
            # Resource bounds still hold even when the writer is unidentified.
            bounded = store.prepare_candidate(row, analysis(), LATER, review_settings={**DEFAULT_LIMITS, "max_sources": 1})
            assert bounded["missing_sources"]
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
        assert prepared["requires_review"]
        assert old_url in {source["url"] for source in prepared["candidate"]["sources"]}
        assert new_url not in {source["url"] for source in prepared["candidate"]["sources"]}
        packet_text = "".join(p["text"] for source in prepared["packet"]["sources"] for p in source["passages"])
        assert "corrected timeline" not in packet_text
        if historical in {"missing", "wrong-url"}:
            assert old_url in prepared["missing_sources"]
            with pytest.raises(ReviewRequired):
                store.commit_candidate(prepared, prepared["candidate"], "missing-history", LATER, **approve(store, prepared))
        else:
            assert not prepared["missing_sources"]
            source = next(source for source in prepared["packet"]["sources"] if source["url"] == old_url)
            assert source["snapshot"] == "historical-analysis"
            assert source["updated_at"] == DATE
            assert "original timeline" in packet_text
            receipt = approve(store, prepared)
            # Even an exact historical packet remains bound to the current
            # source state that selected it, so a later update invalidates it.
            store.ingest({**moved, "content": "A further timeline correction.", "updated_at": "2026-11-10T12:00:00Z"}, "2026-11-10T12:00:00Z")
            with pytest.raises(StaleCandidate):
                store.commit_candidate(prepared, prepared["candidate"], "source-moved-again", LATER, **receipt)
        assert store.stories()[0]["summary"] == old["summary"]


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
        assert prepared["requires_review"]
        if body is None:
            assert prepared["missing_sources"] == [source["url"]]
            assert prepared["packet"]["sources"] == []
        else:
            assert not prepared["missing_sources"]
            assert prepared["packet"]["sources"][0]["passages"] == [{"id": "S1:P1", "text": source["title"]}]
            store.commit_candidate(prepared, prepared["candidate"], "title-only", DATE, **approve(store, prepared))
            assert store.stories()[0]["title"] == source["title"]


def test_only_review_supplied_note_dates_advance_candidate_not_poll_receipts(tmp_path):
    from onionflash.comments import _compose
    from onionflash.util import after
    url = "https://gitlab.torproject.org/tpo/core/tor/-/work_items/41473"
    note = {"id": "gid://gitlab/Note/42", "url": url + "#note_42", "title": "Public comment by @maintainer",
            "author": "maintainer", "created_at": LATER, "updated_at": LATER,
            "body": "Correction: relay operators do not need to edit their configurations."}
    incoming = _compose(item(url=url, content=BODY), [note], after(3600, LATER))
    with Store(tmp_path / "db") as store:
        row = pending(store, incoming, after(3600, LATER))
        draft = analysis(evidence=["The operator reports that old directory-authority keys cannot be trusted"])
        supplied = store.prepare_candidate(row, draft, after(3600, LATER), input_chars=14000)
        assert len(supplied["candidate"]["sources"]) == 1
        assert supplied["candidate"]["updated_at"] == LATER
        assert supplied["payload"]["editorial_updated_at"] == LATER
        excluded = store.prepare_candidate(row, draft, after(3600, LATER), input_chars=14000,
                                           review_settings={**DEFAULT_LIMITS, "max_source_chars": 400})
        assert excluded["candidate"]["updated_at"] == DATE  # Context too small to supply the note.
        assert excluded["packet"]["truncated"]
        poll = json.loads(row["payload"])
        poll["comments_checked_at"] = after(7200, LATER)
        with store.db:
            store.db.execute("UPDATE items SET payload=?,last_seen=? WHERE id=?", (json.dumps(poll), after(7200, LATER), row["id"]))
        refreshed_row = dict(store.db.execute("SELECT * FROM items WHERE id=?", (row["id"],)).fetchone())
        refreshed = store.prepare_candidate(refreshed_row, draft, after(3600, LATER), input_chars=14000)
        assert refreshed["candidate_hash"] == supplied["candidate_hash"]
        assert refreshed["source_hash"] == supplied["source_hash"]
        repaired = review.apply_repair(supplied["candidate"], {"why_it_matters": ""})
        store.commit_candidate(supplied, repaired, "later-note-repair", after(7200, LATER), **approve(store, supplied, repaired))
        saved = store.stories()[0]
        assert saved["updated_at"] == LATER and saved["published_at"] == DATE
        assert render._json_feed_item(render._prepare_story(saved), "https://example.org/")["date_modified"] == LATER


def test_empty_title_and_body_are_not_review_evidence(tmp_path):
    with Store(tmp_path / "db") as store:
        row = pending(store, item(kind="feed", title="", content=""))
        prepared = store.prepare_candidate(row, analysis(), DATE)
        assert prepared["missing_sources"]
        assert prepared["packet"]["sources"] == []
