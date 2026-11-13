"""Editorial decisions survive late inputs, retries, backup and publication."""

from approval_helpers import finish_reviewed
import copy
import hashlib
import json
import shutil
import sqlite3
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from onionflash import editorial, render
from onionflash.cli import build
from onionflash.comments import _compose
from onionflash.schema import UPDATE_CHARS
from onionflash.store import Store, backup_database
from test_core import DATE, analysis, config, item


EDIT = "2026-11-09T12:00:00Z"
LATER = "2026-11-10T12:00:00Z"
FIX = "The report requests removal of the old keys from the software."
UPDATE_SOURCE = {"url": "https://example.org/news/2", "title": "Follow-up report"}
UPDATES = [{"at": "2026-11-08T18:00:00Z", "text": "The operator rotated the keys.", "sources": [UPDATE_SOURCE]},
           {"at": "2026-11-09T06:00:00+00:00", "text": "Relays picked up the new keys.", "sources": [UPDATE_SOURCE]}]


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


def test_databases_this_release_creates_still_accept_earlier_held_update_writes(tmp_path):
    # An earlier release, after a code rollback, records a held update in last_held_at.
    with Store(tmp_path / "db.sqlite3") as store:
        store.db.execute("""INSERT INTO editorial_controls(story_id,revision,locked,retracted,notice_action,
            notice_reason,notice_at) VALUES('s',1,1,0,'correct','r','t')""")
        store.db.execute("UPDATE editorial_controls SET held_updates=held_updates+1,last_held_at='t2' WHERE story_id='s'")
        assert store.db.execute("SELECT last_held_at FROM editorial_controls").fetchone()[0] == "t2"


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


def test_story_guards_left_by_an_earlier_release_cannot_stop_other_writers(seeded):
    cfg, store, story_id = seeded
    with store.db:  # earlier releases guarded stories with a function only they register
        for event, row in (("INSERT", "NEW"), ("UPDATE", "OLD"), ("DELETE", "OLD")):
            store.db.execute(f"CREATE TRIGGER IF NOT EXISTS editorial_story_{event.lower()} BEFORE {event} ON stories "
                             f"WHEN onionflash_editorial_permit({row}.id)=0 BEGIN SELECT RAISE(IGNORE); END")
    with Store(cfg["storage"]["database"]), sqlite3.connect(cfg["storage"]["database"]) as raw:
        assert raw.execute("INSERT INTO stories VALUES('other','other','{}',?,?)", (DATE, DATE)).rowcount == 1
        assert raw.execute("UPDATE stories SET updated_at=updated_at WHERE id=?", (story_id,)).rowcount == 1
        assert raw.execute("DELETE FROM stories WHERE id='other'").rowcount == 1


def test_published_stories_and_editorial_history_are_permanent(seeded):
    cfg, store, story_id = seeded
    edit(store, story_id)
    build(cfg, store)
    # Plain triggers: a direct sqlite3 session, which registers no application function, is held to them.
    with sqlite3.connect(cfg["storage"]["database"]) as raw:
        for statement, params in (
            ("DELETE FROM public_catalog", ()),
            ("DELETE FROM editorial_revisions", ()),
            ("UPDATE editorial_revisions SET reason=''", ()),
            ("""INSERT OR REPLACE INTO editorial_revisions(story_id,revision,action,reason,created_at,
                before_story_json,before_public_json,after_story_json,after_public_json,before_hash,after_hash)
                SELECT story_id,revision,action,'rewritten',created_at,before_story_json,before_public_json,
                after_story_json,after_public_json,before_hash,after_hash
                FROM editorial_revisions WHERE story_id=? AND revision=1""", (story_id,)),
            ("DELETE FROM editorial_controls", ()),
        ):
            with pytest.raises(sqlite3.IntegrityError, match="permanent"):
                raw.execute(statement, params)
    assert editorial.history(store.db, story_id)["revisions"][0]["reason"] == "Removed unsupported operator advice."
    # Appending new revisions and updating controls and catalog snapshots remain allowed.
    act(editorial.retract, store, story_id, reason="The source withdrew this report.")
    act(editorial.restore, store, story_id, 1, reason="Restored the verified correction.")
    act(editorial.unlock, store, story_id, reason="Resumed tracking.")
    build(cfg, store)
    with sqlite3.connect(cfg["storage"]["database"]) as raw:
        assert raw.execute("UPDATE editorial_controls SET held_updates=held_updates+1").rowcount == 1
        assert raw.execute("UPDATE public_catalog SET template_hash='earlier'").rowcount == 1
        # Removing a private source row leaves the article to its catalog entry,
        # while editing requires restoring the stored record first.
        assert raw.execute("DELETE FROM stories WHERE id=?", (story_id,)).rowcount == 1
    with pytest.raises(ValueError, match="restore its stored record"):
        edit(store, story_id, observed=LATER)
    assert build(cfg, store, force=True)["published_stories"] == 1
    assert "Editorial history (4)" in current_files(cfg, story_id)["article"]
    assert len(editorial.history(store.db, story_id)["revisions"]) == 4


def test_failed_operator_write_rolls_back_revision(seeded):
    cfg, store, story_id = seeded
    before = edit(store, story_id)
    store.db.execute("CREATE TRIGGER fail_revision BEFORE INSERT ON editorial_revisions BEGIN SELECT RAISE(ABORT,'injected failure'); END")
    store.db.commit()
    with pytest.raises(sqlite3.IntegrityError, match="injected failure"):
        edit(store, story_id, patch={"title": "A change that must roll back"}, observed=LATER)
    assert not store.db.in_transaction
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
    {"updates": {}}, {"updates": [UPDATE_SOURCE]},
    {"updates": [{**UPDATES[0], "at": "not a date"}]}, {"updates": [{**UPDATES[0], "at": "2026-11-08T18:00:00"}]},
    {"updates": [{**UPDATES[0], "sources": []}]}, {"updates": [{**UPDATES[0], "sources": [UPDATE_SOURCE, UPDATE_SOURCE]}]},
    {"updates": [{**UPDATES[0], "sources": [{"url": f"https://example.org/{n}", "title": "Source"} for n in range(4)]}]},
    {"updates": [{**UPDATES[0], "sources": [{"url": "http://example.org/news/2", "title": "Plain"}]}]},
    {"updates": [{**UPDATES[0], "id": "extra"}]}, {"updates": [{**UPDATES[0], "text": "x" * (UPDATE_CHARS + 1)}]},
    {"updates": [{**UPDATES[0], "text": " "}]}, {"state": "hacked"},
    # No-ops once normalized: the category is always a tag, and whitespace collapses.
    {"category": "security"}, {"tags": []}, {"title": "Operator reports  possible compromise"}, {"updates": []}])
def test_invalid_patch_cannot_mutate_or_unlock_story(seeded, patch):
    cfg, store, story_id = seeded
    before = editorial.show(store.db, story_id)
    with pytest.raises((ValueError, TypeError)):
        edit(store, story_id, patch=patch)
    assert editorial.show(store.db, story_id)["hash"] == before["hash"]
    assert not store.db.in_transaction


def test_operator_updates_publish_and_history_supersedes_only_replaced_entries(seeded):
    cfg, store, story_id = seeded
    marked = {**UPDATES[1], "text": "<b>Relays</b> picked up the new keys."}
    edit(store, story_id, patch={"updates": [UPDATES[0], marked], "state": "no-longer-listed"}, reason="Added the follow-up reports.")
    build(cfg, store)
    files = current_files(cfg, story_id)
    assert files["json"]["updates"] == [UPDATES[0], {**marked, "at": "2026-11-09T06:00:00Z"}]
    assert files["json"]["state"] == "no-longer-listed"
    assert files["article"].index("picked up the new keys") < files["article"].index("The operator rotated")
    assert 'First published <time datetime="2026-11-08T12:00:00Z"' in files["article"]
    assert 'Last updated <time datetime="2026-11-09T12:00:00Z"' in files["article"]
    for text in (files["home"], files["rss"], files["feed"]["content_text"]):
        assert "picked up the new keys." in text and "The operator rotated the keys." not in text
    edit(store, story_id, patch={"priority": "normal"}, observed=LATER)
    edited = {**files["json"]["updates"][1], "text": "Relays began using the new keys."}
    edit(store, story_id, patch={"updates": [UPDATES[0], edited]}, observed=LATER)
    build(cfg, store)
    files = current_files(cfg, story_id)
    history = files["json"]["editorial"]["history"]
    assert history[0]["superseded"]["updates"] == [{"at": "2026-11-09T06:00:00Z", "text": marked["text"]}]
    assert all("updates" not in entry["superseded"] for entry in history[1:])  # a badge change, then no earlier updates
    assert files["article"].count("Previous update") == 1
    assert "&lt;b&gt;Relays&lt;/b&gt; picked up" in files["article"] and "<b>Relays" not in files["article"]
    assert files["article"].count("The operator rotated the keys.") == 1  # unchanged, so only current
    for text in (files["home"], files["rss"], files["feed"]["content_text"]):
        assert "Relays began using the new keys." in text and "picked up the new keys." not in text
    # Re-citing an update keeps its date and text, so it is not superseded either.
    recited = {**UPDATES[0], "sources": [{"url": "https://example.org/news/3", "title": "Notice"}]}
    edit(store, story_id, patch={"updates": [recited, edited]}, observed=LATER)
    build(cfg, store)
    files = current_files(cfg, story_id)
    assert "updates" not in files["json"]["editorial"]["history"][0]["superseded"]
    assert files["article"].count("The operator rotated the keys.") == 1
    # Moving an update to another time supersedes its old date and text.
    edit(store, story_id, patch={"updates": [{**recited, "at": "2026-11-08T19:00:00Z"}, edited]}, observed=LATER)
    build(cfg, store)
    history = current_files(cfg, story_id)["json"]["editorial"]["history"]
    assert history[0]["superseded"]["updates"] == [{"at": "2026-11-08T18:00:00Z", "text": UPDATES[0]["text"]}]
    edit(store, story_id, patch={"updates": []}, observed=LATER)
    build(cfg, store)
    assert "updates" not in current_files(cfg, story_id)["json"] and "updates" not in store.stories()[0]


def test_retraction_hides_updates_and_restore_keeps_them(seeded):
    cfg, store, story_id = seeded
    edit(store, story_id, patch={"updates": UPDATES[:1]})
    edit(store, story_id, patch={"updates": UPDATES}, observed=LATER)
    build(cfg, store)
    act(editorial.retract, store, story_id, reason="The source withdrew this report.")
    build(cfg, store)
    files = current_files(cfg, story_id)
    assert "updates" not in files["json"]
    for text in (files["home"], files["rss"], files["feed"]["content_text"], files["article"], json.dumps(files["json"])):
        for update in UPDATES:
            assert update["text"] not in text
    assert len(store.stories()[0]["updates"]) == 2  # kept privately
    # Restoring an earlier revision's text leaves the current updates in place.
    act(editorial.restore, store, story_id, 1)
    build(cfg, store)
    assert [update["text"] for update in current_files(cfg, story_id)["json"]["updates"]] == [update["text"] for update in UPDATES]


def test_list_field_correction_publishes_canonical_sources_tags_and_products(seeded):
    cfg, store, story_id = seeded
    edit(store, story_id, patch={"tags": ["relay", "relay"], "products": ["arti", "arti"], "sources": [
        {"url": "https://example.org/news/1", "title": "Original"}, {"url": "https://example.org/news/2?utm_source=x", "title": "Follow-up"}]})
    build(cfg, store)
    story = current_files(cfg, story_id)["json"]
    assert [source["url"] for source in story["sources"]] == ["https://example.org/news/1", "https://example.org/news/2"]
    assert story["tags"] == ["security", "relay"] and story["products"] == ["arti"]
    assert story_id in (Path(cfg["storage"]["output_dir"]) / "topics" / "relay" / "index.html").read_text()


@pytest.mark.parametrize("changes", [{"reason": ""}, {"reason": "x" * 1001}, {"reason": "Fixed a claim.\uffff"},
    {"expect_hash": ""}, {"expect_hash": "0" * 64}, {"observed": "not a date"}, {"observed": "2020-01-01T00:00:00Z"}])
def test_reason_hash_and_time_are_required_and_validated(seeded, changes):
    cfg, store, story_id = seeded
    before = editorial.show(store.db, story_id)
    kwargs = {"reason": "Reviewed", "expect_hash": before["hash"], "observed": EDIT, **changes}
    with pytest.raises(ValueError):
        editorial.correct(store.db, story_id, {"why_it_matters": FIX}, **kwargs)
    assert editorial.show(store.db, story_id)["hash"] == before["hash"]


def test_private_history_is_complete_and_public_history_is_bounded(seeded):
    cfg, store, story_id = seeded
    for number in range(23):
        edit(store, story_id, patch={"summary": f"Correction {number}."})
    assert [r["revision"] for r in editorial.history(store.db, story_id)["revisions"]] == list(range(23, 0, -1))
    build(cfg, store)
    files = current_files(cfg, story_id)
    assert len(files["json"]["editorial"]["history"]) == 20
    assert files["json"]["editorial"]["history_total"] == 23  # earlier releases require it after a rollback
    assert "Editorial history (23)" in files["article"] and "latest 20 of 23 changes" in files["article"]


def test_a_catalog_snapshot_with_other_editorial_fields_still_renders(seeded):
    cfg, store, story_id = seeded
    edit(store, story_id)
    act(editorial.unlock, store, story_id)
    build(cfg, store)
    # As another release may write it; with its private row gone, only this snapshot renders the story.
    public = current_files(cfg, story_id)["json"]
    public["editorial"]["later_field"] = 1
    text = json.dumps(public, ensure_ascii=False, sort_keys=True) + "\n"
    with store.db:
        store.db.execute("UPDATE public_catalog SET public_json=?,json_sha256=?,template_hash='earlier' WHERE story_id=?",
                         (text, hashlib.sha256(text.encode()).hexdigest(), story_id))
        store.db.execute("DELETE FROM stories WHERE id=?", (story_id,))
    assert build(cfg, store, force=True)["stories_skipped"] == 0
    assert f'id="story-{story_id}"' in current_files(cfg, story_id)["home"]


def test_model_or_raw_story_cannot_forge_editorial_notice(seeded):
    cfg, store, story_id = seeded
    raw = store.stories()[0]
    raw["editorial"] = {"status": "retracted", "reason": "Forged"}
    assert "editorial" not in render._prepare_story(raw)
    with store.db:
        store.db.execute("UPDATE stories SET payload=? WHERE id=?", (json.dumps(raw), story_id))
    build(cfg, store)
    assert "editorial" not in current_files(cfg, story_id)["json"]


URL = "https://gitlab.torproject.org/tpo/core/tor/-/work_items/41473"


def note(ident, created, body):
    return {"id": f"gid://gitlab/Note/{ident}", "url": f"{URL}#note_{ident}", "title": f"Public comment by @user{ident}",
            "author": f"user{ident}", "created_at": created, "body": body}


def note_item(body="The report’s old keys remain untrusted."):
    return _compose(item(url=URL), [note(123, EDIT, body)], LATER, source_key="k")


@pytest.mark.parametrize("evidence,cited", [("the report's OLD keys remain untrusted", True),
    ("The operator reported a plausible compromise", False), ("keys", False)])
def test_only_cited_notes_add_citations_and_date_the_story(tmp_path, evidence, cited):
    cfg = config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        store.ingest(note_item(), LATER)
        finish_reviewed(store, store.pending(1, LATER)[0], analysis(evidence=[evidence]), "note", LATER)
        story = store.stories()[0]
        assert len(story["sources"]) == (2 if cited else 1)
        # A cited note dates the story by when it was written; a note review only saw does not.
        assert story["updated_at"] == story["editorial_updated_at"] == (EDIT if cited else DATE)
        assert story["published_at"] == DATE and story["added_at"] == LATER
        assert json.loads(store.db.execute("SELECT payload FROM items").fetchone()[0])["updated_at"] == DATE


def test_a_quote_cites_only_its_earliest_note_and_never_a_reply_repeating_the_description(tmp_path):
    cfg = config(tmp_path)
    notes = [note(3, LATER, "> The report’s old keys remain untrusted. Agreed."),
             note(2, LATER, "+1, the operator reported a plausible compromise."),
             note(1, EDIT, "The report’s old keys remain untrusted.")]
    with Store(cfg["storage"]["database"]) as store:
        store.ingest(_compose(item(url=URL), notes, LATER, source_key="k"), LATER)
        evidence = ["The report’s old keys remain untrusted", "the operator reported a plausible compromise"]
        finish_reviewed(store, store.pending(1, LATER)[0], analysis(evidence=evidence), "replies", LATER)
        story = store.stories()[0]
        assert [source["url"] for source in story["sources"]] == [URL, URL + "#note_1"]
        assert story["updated_at"] == EDIT


def test_note_edits_keep_the_story_date_and_removed_citations_are_refreshed(tmp_path):
    cfg = config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        incoming = note_item()
        evidence = ["The report’s old keys remain untrusted"]
        store.ingest(incoming, EDIT)
        finish_reviewed(store, store.pending(1, EDIT)[0], analysis(evidence=evidence), "first", EDIT)
        first = copy.deepcopy(store.stories()[0])
        assert first["updated_at"] == EDIT and len(first["sources"]) == 2
        incoming["public_comments"][0]["body"] = "The report’s old keys remain untrusted. Added a detail."
        assert store.ingest(_compose(incoming, incoming["public_comments"], LATER, source_key="k"), LATER)
        finish_reviewed(store, store.pending(1, LATER)[0], analysis(evidence=evidence), "edit", LATER)
        current = store.stories()[0]
        assert current["updated_at"] == EDIT  # an edit is not a newer note
        assert current["added_at"] == first["added_at"] and current["published_at"] == first["published_at"]
        assert len(current["sources"]) == 2
        store.ingest(_compose(incoming, [], LATER, source_key="k"), LATER)
        finish_reviewed(store, store.pending(1, LATER)[0], analysis(), "removed", LATER)
        assert len(store.stories()[0]["sources"]) == 1 and store.stories()[0]["updated_at"] == EDIT
