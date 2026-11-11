"""Editorial decisions survive late inputs, retries, backup and publication."""

from approval_helpers import finish_reviewed
import copy
import json
import shutil
import sqlite3
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from onionflash import editorial, render
from onionflash.cli import build
from onionflash.comments import _compose, analysis_context
from onionflash.store import Store, backup_database
from onionflash.util import after
from test_core import DATE, analysis, config, item


EDIT = "2026-11-09T12:00:00Z"
LATER = "2026-11-10T12:00:00Z"
FIX = "The report requests removal of the old keys from the software."


@pytest.fixture
def seeded(tmp_path):
    cfg = config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        store.ingest(item(content=item()["content"] * 3), DATE)
        row = store.pending(1, DATE)[0]
        finish_reviewed(store, row, analysis(why_it_matters="Unsupported operator configuration instruction."), "seed", DATE)
        story_id = store.stories()[0]["id"]
        build(cfg, store)
        yield cfg, store, story_id


def edit(store, story_id, **kw):
    return editorial.correct(store.db, story_id, kw.pop("patch", {"why_it_matters": FIX}),
                             expect_hash=editorial.show(store.db, story_id)["hash"],
                             reason=kw.pop("reason", "Removed unsupported operator advice."), observed=kw.pop("observed", EDIT), **kw)


def act(function, store, story_id, *args, **kw):
    return function(store.db, story_id, *args, expect_hash=editorial.show(store.db, story_id)["hash"],
                    reason=kw.pop("reason", "Reviewed source evidence."), observed=kw.pop("observed", LATER), **kw)


def current_files(cfg, story_id):
    root = Path(cfg["storage"]["output_dir"])
    return {"home": (root / "index.html").read_text(),
            "article": (root / "news" / story_id / "index.html").read_text(),
            "rss": ET.parse(root / "feed.xml").findtext("./channel/item/description"),
            "feed": json.loads((root / "feed.json").read_text())["items"][0],
            "json": json.loads((root / "news" / story_id / "story.json").read_text())}


def test_correction_preserves_identity_dates_and_keeps_superseded_text_off_feeds(seeded):
    cfg, store, story_id = seeded
    before = editorial.show(store.db, story_id)
    receipt = edit(store, story_id, reason='Removed unsupported advice. <script>alert("x")</script>')
    assert receipt["locked"] and receipt["revision"] == 1
    assert not store.db.in_transaction
    assert editorial.show(store.db, story_id)["hash"] == receipt["hash"]
    build(cfg, store)
    files = current_files(cfg, story_id)
    assert files["json"]["id"] == story_id
    assert files["json"]["published_at"] == files["json"]["added_at"] == DATE
    assert files["json"]["updated_at"] == EDIT
    assert files["feed"]["date_published"] == DATE
    assert files["feed"]["date_modified"] == EDIT
    for text in (files["home"], files["rss"], files["feed"]["content_text"]):
        assert FIX in text
        assert "Unsupported operator configuration instruction." not in text
    assert "Superseded public text" in files["article"]
    assert "Unsupported operator configuration instruction." in files["article"]
    for text in (files["home"], files["rss"], files["article"]):
        assert '<script>alert("x")</script>' not in text
        assert "&lt;script&gt;" in text
    history = editorial.history(store.db, story_id)["revisions"][0]
    assert history["before_public"] == before["published_story"]
    assert history["before_story"]["why_it_matters"].startswith("Unsupported")
    assert history["after_story"]["why_it_matters"] == FIX
    assert history["before_hash"] == before["hash"]


@pytest.mark.parametrize("cross_source", [False, True])
def test_late_automation_is_cached_and_grouped_but_cannot_overwrite_locked_story(seeded, cross_source):
    cfg, store, story_id = seeded
    locked = edit(store, story_id)
    incoming = item(updated_at=LATER)
    if cross_source:
        incoming.update(id="arti", url="https://example.org/arti/1", source_id="arti", content=item()["content"] * 3)
    else:
        incoming["content"] += " The source has been updated."
    store.ingest(incoming, LATER)
    row = store.pending(1, LATER)[0]
    finish_reviewed(store, row, analysis(why_it_matters="New automation advice."), "late", LATER)
    saved = editorial.show(store.db, story_id)
    assert saved["hash"] == locked["hash"]
    assert saved["held_updates"] == 1
    assert saved["story"]["why_it_matters"] == FIX
    assert store.db.execute("SELECT COUNT(*) FROM analyses WHERE cache_key='late'").fetchone()[0] == 1
    mapped = store.db.execute("SELECT status,story_id FROM items WHERE id=?", (row["id"],)).fetchone()
    assert tuple(mapped) == ("published", story_id)
    assert len(store.stories()) == 1


def test_sql_guard_covers_update_delete_insert_replace_and_raw_connections(seeded):
    cfg, store, story_id = seeded
    edit(store, story_id)
    row = dict(store.db.execute("SELECT * FROM stories WHERE id=?", (story_id,)).fetchone())
    with store.db:
        store.db.execute("UPDATE stories SET payload='bad' WHERE id=?", (story_id,))
        store.db.execute("DELETE FROM stories WHERE id=?", (story_id,))
        store.db.execute("INSERT OR REPLACE INTO stories VALUES(?,?,?,?,?)", (story_id, row["cluster_key"], "bad", DATE, DATE))
        store.db.execute("INSERT INTO stories VALUES(?,?,?,?,?)", ("other-id", row["cluster_key"], "bad", DATE, DATE))
        store.db.execute("INSERT INTO stories VALUES(?,?,?,?,?)", ("unlocked", "unlocked", "unrelated", DATE, DATE))
        store.db.execute("UPDATE OR REPLACE stories SET id=? WHERE id='unlocked'", (story_id,))
        store.db.execute("UPDATE OR REPLACE stories SET cluster_key=? WHERE id='unlocked'", (row["cluster_key"],))
        assert store.db.execute("SELECT payload FROM stories WHERE id='unlocked'").fetchone()[0] == "unrelated"
        store.db.execute("DELETE FROM stories WHERE id='unlocked'")
    assert dict(store.db.execute("SELECT * FROM stories WHERE id=?", (story_id,)).fetchone()) == row
    with sqlite3.connect(cfg["storage"]["database"]) as raw:
        assert raw.execute("SELECT COUNT(*) FROM stories").fetchone()[0] == 1
        with pytest.raises(sqlite3.OperationalError, match="onionflash_editorial_permit"):
            raw.execute("UPDATE stories SET payload='bad' WHERE id=?", (story_id,))
    assert len(store.stories()) == 1


def test_failed_operator_write_rolls_back_revision_and_cannot_leave_permit_open(seeded):
    cfg, store, story_id = seeded
    before = edit(store, story_id)
    store.db.execute("CREATE TRIGGER fail_revision BEFORE INSERT ON editorial_revisions BEGIN SELECT RAISE(ABORT,'injected failure'); END")
    store.db.commit()
    with pytest.raises(sqlite3.IntegrityError, match="injected failure"):
        edit(store, story_id, patch={"title": "A change that must roll back"}, observed=LATER)
    assert not store.db.in_transaction
    assert editorial.show(store.db, story_id)["hash"] == before["hash"]
    assert store.db.execute("SELECT onionflash_editorial_permit(?)", (story_id,)).fetchone()[0] == 0
    with store.db:
        store.db.execute("UPDATE stories SET payload='bad' WHERE id=?", (story_id,))
    assert editorial.show(store.db, story_id)["hash"] == before["hash"]
    assert len(editorial.history(store.db, story_id)["revisions"]) == 1


def test_retraction_tombstone_restore_and_explicit_unlock(seeded):
    cfg, store, story_id = seeded
    original = editorial.show(store.db, story_id)["story"]
    quoting = "Replaced the claim " + original["title"]  # an operator reason may quote the old text
    edit(store, story_id, reason=quoting)
    build(cfg, store)
    withdrawn = act(editorial.retract, store, story_id, reason="The source withdrew this report.")
    build(cfg, store)
    files = current_files(cfg, story_id)
    assert files["json"]["id"] == story_id
    assert files["json"]["editorial"]["status"] == "retracted"
    assert files["json"]["title"] == "Retracted story"
    # Neither the original nor the corrected text stays public, not even as superseded
    # history or in an earlier correction's reason.
    for text in (files["home"], files["rss"], files["feed"]["content_text"], files["article"], json.dumps(files["json"])):
        assert "The source withdrew this report." in text
        for old in (original["title"], original["summary"], original["why_it_matters"], FIX, quoting):
            assert old not in text
    with pytest.raises(ValueError, match="Restore a retracted"):
        edit(store, story_id, patch={"summary": "New text."}, observed=LATER)
    with pytest.raises(ValueError, match="restore"):
        act(editorial.unlock, store, story_id)
    assert editorial.show(store.db, story_id)["hash"] == withdrawn["hash"]
    restored = act(editorial.restore, store, story_id, 1)
    assert restored["locked"] and not restored["retracted"]
    assert editorial.show(store.db, story_id)["story"]["why_it_matters"] == FIX
    with pytest.raises(ValueError, match="accepted public text"):
        act(editorial.restore, store, story_id, 2)
    act(editorial.unlock, store, story_id)
    reviewed = editorial.show(store.db, story_id)
    assert not reviewed["locked"]
    store.ingest(item(content="An updated source report after explicit review.", updated_at=LATER), LATER)
    finish_reviewed(store, store.pending(1, LATER)[0], analysis(summary="New source-supported text."), "after-unlock", LATER)
    # The rewrite keeps the row's update time; only its payload invalidates the reviewed hash.
    with pytest.raises(ValueError, match="changed since it was reviewed"):
        editorial.correct(store.db, story_id, {"why_it_matters": FIX}, reason="Reviewed.", expect_hash=reviewed["hash"], observed=LATER)
    build(cfg, store)
    files = current_files(cfg, story_id)
    assert files["json"]["summary"] == "New source-supported text."
    assert files["json"]["editorial"]["revision"] == 4
    assert files["json"]["editorial"]["history"][0]["action"] == "unlock"
    assert "Restored" in files["article"] and "Superseded public text" in files["article"]
    assert quoting in json.dumps(files["json"])  # restoring brings earlier reasons back


def test_restore_original_and_backup_recover_last_good_public_revision(seeded, tmp_path):
    cfg, store, story_id = seeded
    before = editorial.show(store.db, story_id)["story"]
    edit(store, story_id); build(cfg, store)
    act(editorial.restore, store, story_id, 0)
    build(cfg, store)
    assert editorial.show(store.db, story_id)["story"]["why_it_matters"] == before["why_it_matters"]
    backup = tmp_path / "backup.sqlite3"
    backup_database(cfg["storage"]["database"], backup)
    shutil.rmtree(cfg["storage"]["output_dir"])
    cfg["storage"]["database"] = str(backup)
    with Store(backup) as restored:
        build(cfg, restored, force=True)
        assert current_files(cfg, story_id)["json"]["editorial"]["revision"] == 2
        assert len(editorial.history(restored.db, story_id)["revisions"]) == 2
        assert editorial.is_locked(restored.db, story_id)


def test_bad_unpublished_payload_is_private_and_last_good_snapshot_is_correctable(seeded):
    cfg, store, story_id = seeded
    with store.db:
        store.db.execute("UPDATE stories SET payload=? WHERE id=?", ('{"secret":"unpublished secret"}', story_id))
    assert editorial.show(store.db, story_id)["using_last_published_snapshot"]
    edit(store, story_id); build(cfg, store)
    assert "unpublished secret" not in current_files(cfg, story_id)["article"]
    assert editorial.history(store.db, story_id)["revisions"][0]["before_story"] == {"secret": "unpublished secret"}


def test_mismatched_draft_identity_uses_last_good_snapshot_without_moving_permalink(seeded):
    cfg, store, story_id = seeded
    raw = store.stories()[0]
    raw["id"] = "incorrect-draft-id"
    with store.db:
        store.db.execute("UPDATE stories SET payload=? WHERE id=?", (json.dumps(raw), story_id))
    assert editorial.show(store.db, story_id)["using_last_published_snapshot"]
    assert build(cfg, store)["stories_skipped"] == 1
    assert not (Path(cfg["storage"]["output_dir"]) / "news" / "incorrect-draft-id").exists()
    edit(store, story_id)
    assert build(cfg, store)["stories_skipped"] == 0
    assert current_files(cfg, story_id)["json"]["id"] == story_id


@pytest.mark.parametrize("patch", [{}, {"id": "new"}, {"published_at": DATE}, {"added_at": DATE},
    {"editorial": {}}, {"title": ""}, {"title": "\x00"}, {"title": "\ud800"}, {"title": "x" * 181},
    {"summary": []}, {"priority": []}, {"products": "tor"}, {"tags": ["fake"]}, {"sources": []},
    {"sources": [{"url": "http://example.org", "title": "Bad"}]},
    {"sources": [{"url": "https://127.0.0.1/", "title": "Private"}]},
    {"sources": [{"url": "https://example.org", "title": "Source", "secret": "hidden"}]},
    # No-ops once normalized: the category is always a tag, and whitespace collapses.
    {"category": "security"}, {"tags": []}, {"title": "Operator reports  possible compromise"}])
def test_invalid_patch_cannot_mutate_or_unlock_story(seeded, patch):
    cfg, store, story_id = seeded
    before = editorial.show(store.db, story_id)
    with pytest.raises((ValueError, TypeError)):
        edit(store, story_id, patch=patch)
    assert editorial.show(store.db, story_id)["hash"] == before["hash"]
    assert not store.db.in_transaction


def test_list_field_correction_publishes_canonical_sources_tags_and_products(seeded):
    cfg, store, story_id = seeded
    edit(store, story_id, patch={"tags": ["relay", "relay"], "products": ["arti", "arti"], "sources": [
        {"url": "https://example.org/news/1", "title": "Original"}, {"url": "https://example.org/news/2?utm_source=x", "title": "Follow-up"}]})
    build(cfg, store)
    story = current_files(cfg, story_id)["json"]
    assert [source["url"] for source in story["sources"]] == ["https://example.org/news/1", "https://example.org/news/2"]
    assert story["tags"] == ["security", "relay"] and story["products"] == ["arti"]
    assert story_id in (Path(cfg["storage"]["output_dir"]) / "topics" / "relay" / "index.html").read_text()


@pytest.mark.parametrize("changes", [{"reason": ""}, {"reason": "x" * 1001}, {"expect_hash": ""},
    {"expect_hash": "0" * 64}, {"observed": "not a date"}, {"observed": "2020-01-01T00:00:00Z"}])
def test_reason_hash_and_time_are_required_and_validated(seeded, changes):
    cfg, store, story_id = seeded
    before = editorial.show(store.db, story_id)
    kwargs = {"reason": "Reviewed", "expect_hash": before["hash"], "observed": EDIT, **changes}
    with pytest.raises(ValueError):
        editorial.correct(store.db, story_id, {"why_it_matters": FIX}, **kwargs)
    assert editorial.show(store.db, story_id)["hash"] == before["hash"]


def test_private_history_paginates_and_public_history_is_bounded(seeded):
    cfg, store, story_id = seeded
    for number in range(23):
        edit(store, story_id, patch={"summary": f"Correction {number}."})
    first = editorial.history(store.db, story_id, limit=2)
    second = editorial.history(store.db, story_id, limit=2, before=first["next_before"])
    assert [r["revision"] for r in first["revisions"]] == [23, 22]
    assert [r["revision"] for r in second["revisions"]] == [21, 20]
    metadata = editorial.public_metadata(store.db, story_id)
    assert metadata["history_total"] == 23 and len(metadata["history"]) == 20
    build(cfg, store)
    assert len(current_files(cfg, story_id)["json"]["editorial"]["history"]) == 20
    with pytest.raises(ValueError):
        editorial.history(store.db, story_id, limit=101)


def test_model_or_raw_story_cannot_forge_editorial_notice(seeded):
    cfg, store, story_id = seeded
    raw = store.stories()[0]
    raw["editorial"] = {"status": "retracted", "reason": "Forged"}
    assert "editorial" not in render._prepare_story(raw)
    with store.db:
        store.db.execute("UPDATE stories SET payload=? WHERE id=?", (json.dumps(raw), story_id))
    build(cfg, store)
    assert "editorial" not in current_files(cfg, story_id)["json"]


def note_item(body="The report’s old keys remain untrusted.", **changes):
    url = "https://gitlab.torproject.org/tpo/core/tor/-/work_items/41473"
    note = {"id": "gid://gitlab/Note/123", "url": url + "#note_123", "title": "Public comment by @operator",
            "author": "operator", "created_at": EDIT, "updated_at": EDIT, "body": body, **changes}
    return _compose(item(url=url), [note], LATER)


@pytest.mark.parametrize("budget,evidence,cited", [(4000, "the report's OLD keys remain untrusted", True),
    (None, "The report’s old keys remain untrusted", False), (499, "The report’s old keys remain untrusted", False),
    (4000, "The operator reported a plausible compromise", False), (4000, "keys", False)])
@pytest.mark.parametrize("note_kind", ["Note", "DiscussionNote"])
def test_writer_quotes_select_citations_while_supplied_review_notes_date_story(tmp_path, budget, evidence, cited, note_kind):
    cfg = config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        incoming = note_item(id=f"gid://gitlab/{note_kind}/123")
        store.ingest(incoming, LATER)
        row = store.pending(1, LATER)[0]
        finish_reviewed(store, row, analysis(evidence=[evidence]), "note", LATER, input_chars=budget)
        story = store.stories()[0]
        assert len(story["sources"]) == (2 if cited else 1)
        assert story["updated_at"] == EDIT  # Final review sees the verified note even when the draft did not cite it.
        assert story["editorial_updated_at"] == story["updated_at"]
        assert story["published_at"] == DATE and story["added_at"] == LATER
        assert json.loads(store.db.execute("SELECT payload FROM items").fetchone()[0])["updated_at"] == DATE
        saved = store.db.execute("SELECT input_chars FROM analyses WHERE cache_key='note'").fetchone()
        assert saved[0] == budget


def test_unknown_note_type_cannot_supply_story_citations_or_update_time(tmp_path):
    cfg = config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        store.ingest(note_item(id="gid://gitlab/OtherNote/123"), LATER)
        finish_reviewed(store, store.pending(1, LATER)[0], analysis(evidence=["The report’s old keys remain untrusted"]),
                     "unknown-note", LATER, input_chars=4000)
        story = store.stories()[0]
        assert len(story["sources"]) == 1 and story["updated_at"] == DATE


def test_unseen_note_tail_or_mismatched_url_cannot_be_cited(tmp_path):
    cfg = config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        incoming = note_item(body="Visible prefix. " * 1000 + "Only in unseen tail.")
        text, notes = analysis_context(incoming, 500)
        assert "Only in unseen tail." not in text
        store.ingest(incoming, LATER)
        finish_reviewed(store, store.pending(1, LATER)[0], analysis(evidence=["Only in unseen tail."]), "tail", LATER, input_chars=500)
        assert len(store.stories()[0]["sources"]) == 1
        incoming = note_item(url="https://evil.example/#note_123")
        store.ingest(incoming, LATER)
        finish_reviewed(store, store.pending(1, LATER)[0], analysis(evidence=["The report’s old keys remain untrusted"]), "wrong-url", LATER, input_chars=4000)
        assert len(store.stories()[0]["sources"]) == 1


def test_note_only_edits_advance_story_time_and_removed_citations_are_refreshed(tmp_path):
    cfg = config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        incoming = note_item()
        evidence = ["The report’s old keys remain untrusted"]
        store.ingest(incoming, EDIT)
        finish_reviewed(store, store.pending(1, EDIT)[0], analysis(evidence=evidence), "first", EDIT, input_chars=4000)
        first = copy.deepcopy(store.stories()[0])
        incoming["public_comments"][0].update(body="The report’s old keys remain untrusted. Added a detail.", updated_at=LATER)
        incoming = _compose(incoming, incoming["public_comments"], LATER)
        store.ingest(incoming, LATER)
        finish_reviewed(store, store.pending(1, LATER)[0], analysis(evidence=evidence), "edit", LATER, input_chars=4000)
        current = store.stories()[0]
        assert current["updated_at"] == LATER
        assert current["added_at"] == first["added_at"] and current["published_at"] == first["published_at"]
        assert len(current["sources"]) == 2
        incoming["public_comments"] = []
        incoming = _compose(incoming, [], LATER)
        store.ingest(incoming, LATER)
        finish_reviewed(store, store.pending(1, LATER)[0], analysis(), "removed", LATER, input_chars=4000)
        assert len(store.stories()[0]["sources"]) == 1
        assert store.stories()[0]["updated_at"] == LATER
