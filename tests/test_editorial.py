"""Editorial decisions survive late inputs, retries, backup and publication."""

import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import xml.etree.ElementTree as ET

import pytest

from helpers import (
    DATE, LATER, TOR_WORK_ITEM_URL as URL, analysis, editorial_act, invoke_cli, item, make_config,
    make_note, make_story, pub_settings, put_story, seed_story, update_analysis, write_toml,
)
from onionflash import candidate, editorial, render
from onionflash.cli import build, run_lock
from onionflash.comments import _compose
from onionflash.schema import UPDATE_CHARS
from onionflash.store import Store, backup_database

EDIT = "2026-11-09T12:00:00Z"
FIX = "The report requests removal of the old keys from the software."
UPDATE_SOURCE = {"url": "https://example.org/news/2", "title": "Follow-up report"}
UPDATES = [{"at": "2026-11-08T18:00:00Z", "text": "The operator rotated the keys.", "sources": [UPDATE_SOURCE]},
           {"at": "2026-11-09T06:00:00+00:00", "text": "Relays picked up the new keys.", "sources": [UPDATE_SOURCE]}]


@pytest.fixture
def seeded(tmp_path):
    """Seed and build one published story with an initial `why_it_matters` sentence."""
    cfg = make_config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        story_id = seed_story(store, item(content=item()["content"] * 3),
                              analysis(why_it_matters="Unsupported operator configuration instruction."), key="seed", at=DATE)["id"]
        build(cfg, store)
        yield cfg, store, story_id


def _edit(store, story_id, *, patch=None, reason="Removed unsupported operator advice.", observed=EDIT):
    return editorial_act(editorial.correct, store, story_id, {"why_it_matters": FIX} if patch is None else patch,
                         reason=reason, observed=observed)


def _current_files(cfg, story_id):
    root = Path(cfg["storage"]["output_dir"])
    return {"home": (root / "index.html").read_text(),
            "article": (root / "news" / story_id / "index.html").read_text(),
            "rss": ET.parse(root / "feed.xml").findtext("./channel/item/description"),
            "feed": json.loads((root / "feed.json").read_text())["items"][0],
            "json": json.loads((root / "news" / story_id / "story.json").read_text())}


def _note_item():
    return _compose(item(url=URL), [make_note(123, "The report’s old keys remain untrusted.", author="user123", created_at=EDIT, url=URL)], LATER, source_key="k")


def test_databases_this_release_creates_still_accept_earlier_held_update_writes(store):
    """Accept legacy `held_updates` and `last_held_at` updates against `editorial_controls`."""
    store.db.execute("""INSERT INTO editorial_controls(story_id,revision,locked,retracted,notice_action,
        notice_reason,notice_at) VALUES('s',1,1,0,'correct','r','t')""")
    store.db.execute("UPDATE editorial_controls SET held_updates=held_updates+1,last_held_at='t2' WHERE story_id='s'")
    assert store.db.execute("SELECT last_held_at FROM editorial_controls").fetchone()[0] == "t2"


def test_correction_preserves_identity_dates_and_keeps_superseded_text_off_feeds(seeded):
    """Keep superseded text on article history only while escaping reasons and updating feeds."""
    cfg, store, story_id = seeded
    before = editorial.show(store.db, story_id)
    receipt = _edit(store, story_id, reason='Removed unsupported advice. <script>alert("x")</script>')
    assert receipt["locked"] and receipt["revision"] == 1 and not store.db.in_transaction
    assert editorial.show(store.db, story_id)["hash"] == receipt["hash"]
    build(cfg, store)
    files = _current_files(cfg, story_id)
    assert files["json"]["id"] == story_id and files["json"]["published_at"] == files["json"]["added_at"] == DATE
    assert files["json"]["updated_at"] == EDIT and files["feed"]["date_published"] == DATE and files["feed"]["date_modified"] == EDIT
    for text in (files["home"], files["rss"], files["feed"]["content_text"]):
        assert FIX in text and "Unsupported operator configuration instruction." not in text
    assert "Superseded public text" in files["article"] and "Unsupported operator configuration instruction." in files["article"]
    for text in (files["home"], files["rss"], files["article"]):
        assert '<script>alert("x")</script>' not in text and "&lt;script&gt;" in text
    history = editorial.history(store.db, story_id)["revisions"][0]
    assert history["before_public"] == before["published_story"]
    assert history["before_story"]["why_it_matters"].startswith("Unsupported")
    assert history["after_story"]["why_it_matters"] == FIX and history["before_hash"] == before["hash"]


@pytest.mark.parametrize("cross_source", [False, True])
def test_late_automation_is_cached_and_grouped_but_cannot_overwrite_locked_story(seeded, cross_source):
    """Group late same-source and cross-source revisions onto locked stories without overwriting prose."""
    _, store, story_id = seeded
    locked = _edit(store, story_id)
    incoming = item(updated_at=LATER)
    if cross_source:
        incoming.update(id="arti", url="https://example.org/arti/1", source_id="arti", content=item()["content"] * 3)
    else:
        incoming["content"] += " The source has been updated."
    seed_story(store, incoming, analysis(why_it_matters="New automation advice."), key="late", at=LATER)
    saved = editorial.show(store.db, story_id)
    assert saved["hash"] == locked["hash"] and saved["held_updates"] == 1 and saved["story"]["why_it_matters"] == FIX
    assert store.db.execute("SELECT COUNT(*) FROM analyses WHERE cache_key='late'").fetchone()[0] == 1
    assert tuple(store.db.execute("SELECT status,story_id FROM items WHERE url=?", (incoming["url"],)).fetchone()) == ("published", story_id)
    assert len(store.stories()) == 1


def test_story_guards_left_by_an_earlier_release_cannot_stop_other_writers(seeded):
    """Drop legacy `onionflash_editorial_permit` triggers when opening a `Store`."""
    cfg, store, story_id = seeded
    with store.db:
        for event, row in (("INSERT", "NEW"), ("UPDATE", "OLD"), ("DELETE", "OLD")):
            store.db.execute(f"CREATE TRIGGER IF NOT EXISTS editorial_story_{event.lower()} BEFORE {event} ON stories "
                             f"WHEN onionflash_editorial_permit({row}.id)=0 BEGIN SELECT RAISE(IGNORE); END")
    with Store(cfg["storage"]["database"]), sqlite3.connect(cfg["storage"]["database"]) as raw:
        assert raw.execute("INSERT INTO stories VALUES('other','other','{}',?,?)", (DATE, DATE)).rowcount == 1
        assert raw.execute("UPDATE stories SET updated_at=updated_at WHERE id=?", (story_id,)).rowcount == 1
        assert raw.execute("DELETE FROM stories WHERE id='other'").rowcount == 1


def test_published_stories_and_editorial_history_are_permanent(seeded):
    """Enforce SQLite permanence triggers on `public_catalog`, `editorial_revisions`, and `editorial_controls`."""
    cfg, store, story_id = seeded
    _edit(store, story_id)
    build(cfg, store)
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
    editorial_act(editorial.retract, store, story_id, reason="The source withdrew this report.")
    editorial_act(editorial.restore, store, story_id, 1, reason="Restored the verified correction.")
    editorial_act(editorial.unlock, store, story_id, reason="Resumed tracking.")
    build(cfg, store)
    with sqlite3.connect(cfg["storage"]["database"]) as raw:
        assert raw.execute("UPDATE editorial_controls SET held_updates=held_updates+1").rowcount == 1
        assert raw.execute("UPDATE public_catalog SET template_hash='earlier'").rowcount == 1
        assert raw.execute("DELETE FROM stories WHERE id=?", (story_id,)).rowcount == 1
    with pytest.raises(ValueError, match="restore its stored record"):
        _edit(store, story_id, observed=LATER)
    assert build(cfg, store, force=True)["published_stories"] == 1
    assert "Editorial history (4)" in _current_files(cfg, story_id)["article"]
    assert len(editorial.history(store.db, story_id)["revisions"]) == 4


def test_failed_operator_write_rolls_back_revision(seeded):
    """Roll back story edits if inserting the `editorial_revisions` row fails."""
    _, store, story_id = seeded
    before = _edit(store, story_id)
    store.db.execute("CREATE TRIGGER fail_revision BEFORE INSERT ON editorial_revisions BEGIN SELECT RAISE(ABORT,'injected failure'); END")
    store.db.commit()
    with pytest.raises(sqlite3.IntegrityError, match="injected failure"):
        _edit(store, story_id, patch={"title": "A change that must roll back"}, observed=LATER)
    assert not store.db.in_transaction and editorial.show(store.db, story_id)["hash"] == before["hash"]
    assert len(editorial.history(store.db, story_id)["revisions"]) == 1


def test_retraction_tombstone_restore_and_explicit_unlock(seeded):
    """Publish clean retraction tombstones, restore prior accepted revisions, and resume automation on unlock."""
    cfg, store, story_id = seeded
    original = editorial.show(store.db, story_id)["story"]
    quoting = "Replaced the claim " + original["title"]
    _edit(store, story_id, reason=quoting)
    build(cfg, store)
    withdrawn = editorial_act(editorial.retract, store, story_id, reason="The source withdrew this report.")
    build(cfg, store)
    files = _current_files(cfg, story_id)
    assert files["json"]["id"] == story_id and files["json"]["editorial"]["status"] == "retracted"
    assert files["json"]["title"] == "Retracted story"
    for text in (files["home"], files["rss"], files["feed"]["content_text"], files["article"], json.dumps(files["json"])):
        assert "The source withdrew this report." in text
        for old in (original["title"], original["summary"], original["why_it_matters"], FIX, quoting):
            assert old not in text
    with pytest.raises(ValueError, match="Restore a retracted"):
        _edit(store, story_id, patch={"summary": "New text."}, observed=LATER)
    with pytest.raises(ValueError, match="restore"):
        editorial_act(editorial.unlock, store, story_id, reason="Reviewed source evidence.")
    assert editorial.show(store.db, story_id)["hash"] == withdrawn["hash"]
    restored = editorial_act(editorial.restore, store, story_id, 1, reason="Reviewed source evidence.")
    assert restored["locked"] and not restored["retracted"] and editorial.show(store.db, story_id)["story"]["why_it_matters"] == FIX
    with pytest.raises(ValueError, match="accepted public text"):
        editorial_act(editorial.restore, store, story_id, 2, reason="Reviewed source evidence.")
    editorial_act(editorial.unlock, store, story_id, reason="Reviewed source evidence.")
    reviewed = editorial.show(store.db, story_id)
    assert not reviewed["locked"]
    seed_story(store, item(content="An updated source report after explicit review.", updated_at=LATER),
               update_analysis(update="New source-supported text.", evidence=["An updated source report after explicit review."]),
               key="after-unlock", at=LATER)
    with pytest.raises(ValueError, match="changed since it was reviewed"):
        editorial.correct(store.db, story_id, {"why_it_matters": FIX}, reason="Reviewed.", expect_hash=reviewed["hash"], observed=LATER)
    build(cfg, store)
    files = _current_files(cfg, story_id)
    assert files["json"]["updates"][-1]["text"] == "New source-supported text."
    assert files["json"]["editorial"]["revision"] == 4 and files["json"]["editorial"]["history"][0]["action"] == "unlock"
    assert "Restored" in files["article"] and "Superseded public text" in files["article"] and quoting in json.dumps(files["json"])


def test_restore_original_backup_and_damaged_draft_fallbacks(seeded, tmp_path):
    """Restore revision 0 and preserve editorial locks and history across `backup_database`."""
    cfg, store, story_id = seeded
    before = editorial.show(store.db, story_id)["story"]
    _edit(store, story_id)
    build(cfg, store)
    editorial_act(editorial.restore, store, story_id, 0, reason="Reviewed source evidence.")
    build(cfg, store)
    assert editorial.show(store.db, story_id)["story"]["why_it_matters"] == before["why_it_matters"]
    backup = tmp_path / "backup.sqlite3"
    backup_database(cfg["storage"]["database"], backup)
    shutil.rmtree(cfg["storage"]["output_dir"])
    cfg["storage"]["database"] = str(backup)
    with Store(backup) as restored:
        build(cfg, restored, force=True)
        assert _current_files(cfg, story_id)["json"]["editorial"]["revision"] == 2
        assert len(editorial.history(restored.db, story_id)["revisions"]) == 2 and editorial.is_locked(restored.db, story_id)


def test_bad_unpublished_or_mismatched_draft_uses_last_good_snapshot(seeded):
    """Fall back to `public_catalog` snapshot when `stories.payload` becomes invalid or mismatched."""
    cfg, store, story_id = seeded
    with store.db:
        store.db.execute("UPDATE stories SET payload=? WHERE id=?", ('{"secret":"unpublished secret"}', story_id))
    assert editorial.show(store.db, story_id)["using_last_published_snapshot"]
    _edit(store, story_id)
    build(cfg, store)
    assert "unpublished secret" not in _current_files(cfg, story_id)["article"]
    assert editorial.history(store.db, story_id)["revisions"][0]["before_story"] == {"secret": "unpublished secret"}

    raw = store.stories()[0]
    raw["id"] = "incorrect-draft-id"
    with store.db:
        store.db.execute("UPDATE stories SET payload=? WHERE id=?", (json.dumps(raw), story_id))
    assert editorial.show(store.db, story_id)["using_last_published_snapshot"]
    assert build(cfg, store)["stories_skipped"] == 1
    assert not (Path(cfg["storage"]["output_dir"]) / "news" / "incorrect-draft-id").exists()
    _edit(store, story_id, patch={"why_it_matters": "Updated verified notice."}, observed=LATER)
    assert build(cfg, store)["stories_skipped"] == 0 and _current_files(cfg, story_id)["json"]["id"] == story_id


def test_prebuild_retract_deleted_story_retraction_and_blob_fallback(tmp_path):
    """Handle pre-build retractions, deleted-row tombstones, category retagging, and invalid UTF-8 blobs."""
    cfg = make_config(tmp_path / "pre")
    with Store(cfg["storage"]["database"]) as store:
        sid = seed_story(store, item(url="https://example.org/prebuild", title="Drafted notice", content="Initial notice text. " * 3),
                         analysis(title="Drafted notice", summary="Initial notice text.", evidence=["Initial notice text."]))["id"]
        editorial_act(editorial.retract, store, sid, reason="Retracted before build.", observed=LATER)
        hist = editorial.history(store.db, sid)["revisions"][0]
        assert "updates" not in (hist["after_public"] or {}) and "alert_notes" not in (hist["after_public"] or {})
        restored = editorial_act(editorial.restore, store, sid, 0, reason="Restore pre-build story.",
                                 observed="2026-11-10T13:30:00Z")
        assert restored["retracted"] is False
        build(cfg, store)
        editorial_act(editorial.retract, store, sid, reason="Withdrawn after verification.",
                      observed="2026-11-10T14:00:00Z")
        with store.db:
            store.db.execute("DELETE FROM stories WHERE id=?", (sid,))
        build(cfg, store)
        html = (Path(cfg["storage"]["output_dir"]) / "news" / sid / "index.html").read_text(encoding="utf-8")
        assert "Retracted story" in html and "Initial notice text." not in html

    cfg2 = make_config(tmp_path / "trig")
    out2 = Path(cfg2["storage"]["output_dir"])
    out2.mkdir(parents=True, exist_ok=True)
    with Store(cfg2["storage"]["database"]) as store:
        triggers = {r[0] for r in store.db.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
        assert {"editorial_revisions_append_only", "editorial_revisions_permanent",
                "editorial_revisions_unchanged", "editorial_controls_permanent"} <= triggers
        sid2 = seed_story(store, item(url="https://gitlab.torproject.org/tpo/core/tor/-/work_items/777",
                                      title="Relay memory spike", content="Operators observed higher relay memory use."),
                          analysis(title="Relay memory spike", summary="Operators observed higher relay memory use.",
                                   category="network", tags=["network"], evidence=["Operators observed higher relay memory use."]))["id"]
        assert build(cfg2, store)["published_stories"] == 1 and (out2 / "news" / sid2 / "index.html").exists()
        res = editorial_act(editorial.correct, store, sid2, {"category": "security"},
                            reason="Reclassify as security.", observed=LATER)
        shown = editorial.show(store.db, sid2)
        assert res["locked"] is True and shown["story"]["category"] == "security"
        assert "network" not in shown["story"]["tags"] and "security" in shown["story"]["tags"]
        build(cfg2, store)
        with store.db:
            store.db.execute("UPDATE stories SET payload=? WHERE id=?", (b"\xff\xfeinvalid", sid2))
        assert editorial.show(store.db, sid2)["using_last_published_snapshot"] is True
        assert build(cfg2, store)["published_stories"] == 1


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
    {"category": "security"}, {"tags": []}, {"title": "Operator reports  possible compromise"}, {"updates": []}])
def test_invalid_patch_cannot_mutate_or_unlock_story(seeded, patch):
    """Reject malformed, unsafe, or no-op `editorial.correct` patches without mutating story state."""
    _, store, story_id = seeded
    before = editorial.show(store.db, story_id)
    with pytest.raises((ValueError, TypeError)):
        _edit(store, story_id, patch=patch)
    assert editorial.show(store.db, story_id)["hash"] == before["hash"] and not store.db.in_transaction


def test_operator_updates_publish_and_history_supersedes_only_replaced_entries(seeded):
    """Render operator `updates` newest-first and record superseded history only for edited entries."""
    cfg, store, story_id = seeded
    marked = {**UPDATES[1], "text": "<b>Relays</b> picked up the new keys."}
    _edit(store, story_id, patch={"updates": [UPDATES[0], marked], "state": "no-longer-listed"}, reason="Added the follow-up reports.")
    build(cfg, store)
    files = _current_files(cfg, story_id)
    assert files["json"]["updates"] == [UPDATES[0], {**marked, "at": "2026-11-09T06:00:00Z"}]
    assert files["json"]["state"] == "no-longer-listed"
    assert files["article"].index("picked up the new keys") < files["article"].index("The operator rotated")
    assert 'First published <time datetime="2026-11-08T12:00:00Z"' in files["article"]
    assert 'Last updated <time datetime="2026-11-09T12:00:00Z"' in files["article"]
    for text in (files["home"], files["rss"], files["feed"]["content_text"]):
        assert "picked up the new keys." in text and "The operator rotated the keys." not in text
    _edit(store, story_id, patch={"priority": "normal"}, observed=LATER)
    edited = {**files["json"]["updates"][1], "text": "Relays began using the new keys."}
    _edit(store, story_id, patch={"updates": [UPDATES[0], edited]}, observed=LATER)
    build(cfg, store)
    files = _current_files(cfg, story_id)
    history = files["json"]["editorial"]["history"]
    assert history[0]["superseded"]["updates"] == [{"at": "2026-11-09T06:00:00Z", "text": marked["text"]}]
    assert all("updates" not in entry["superseded"] for entry in history[1:])
    assert files["article"].count("Previous update") == 1
    assert "&lt;b&gt;Relays&lt;/b&gt; picked up" in files["article"] and "<b>Relays" not in files["article"]
    assert files["article"].count("The operator rotated the keys.") == 1
    for text in (files["home"], files["rss"], files["feed"]["content_text"]):
        assert "Relays began using the new keys." in text and "picked up the new keys." not in text
    recited = {**UPDATES[0], "sources": [{"url": "https://example.org/news/3", "title": "Notice"}]}
    _edit(store, story_id, patch={"updates": [recited, edited]}, observed=LATER)
    build(cfg, store)
    files = _current_files(cfg, story_id)
    assert "updates" not in files["json"]["editorial"]["history"][0]["superseded"]
    assert files["article"].count("The operator rotated the keys.") == 1
    _edit(store, story_id, patch={"updates": [{**recited, "at": "2026-11-08T19:00:00Z"}, edited]}, observed=LATER)
    build(cfg, store)
    assert _current_files(cfg, story_id)["json"]["editorial"]["history"][0]["superseded"]["updates"] == [
        {"at": "2026-11-08T18:00:00Z", "text": UPDATES[0]["text"]}]
    _edit(store, story_id, patch={"updates": []}, observed=LATER)
    build(cfg, store)
    assert "updates" not in _current_files(cfg, story_id)["json"] and "updates" not in store.stories()[0]


def test_retraction_hides_updates_and_restore_keeps_them(seeded):
    """Suppress `updates` from retracted tombstones and restore them cleanly from prior revisions."""
    cfg, store, story_id = seeded
    _edit(store, story_id, patch={"updates": UPDATES[:1]})
    _edit(store, story_id, patch={"updates": UPDATES}, observed=LATER)
    build(cfg, store)
    editorial_act(editorial.retract, store, story_id, reason="The source withdrew this report.")
    build(cfg, store)
    files = _current_files(cfg, story_id)
    assert "updates" not in files["json"]
    for text in (files["home"], files["rss"], files["feed"]["content_text"], files["article"], json.dumps(files["json"])):
        for upd in UPDATES:
            assert upd["text"] not in text
    assert len(store.stories()[0]["updates"]) == 2
    editorial_act(editorial.restore, store, story_id, 1, reason="Reviewed source evidence.")
    build(cfg, store)
    restored = _current_files(cfg, story_id)
    assert [u["text"] for u in restored["json"]["updates"]] == [u["text"] for u in UPDATES]
    assert all("updates" not in (entry.get("superseded") or {}) for entry in restored["json"]["editorial"]["history"])
    assert "Previous update" not in restored["article"]


def test_list_field_correction_bounded_history_catalog_fields_and_forged_notice(seeded):
    """Deduplicate corrected list fields, cap displayed history to 20 entries, and strip forged `editorial` keys."""
    cfg, store, story_id = seeded
    raw = store.stories()[0]
    raw["editorial"] = {"status": "retracted", "reason": "Forged"}
    assert "editorial" not in render.prepare_story(raw)
    with store.db:
        store.db.execute("UPDATE stories SET payload=? WHERE id=?", (json.dumps(raw), story_id))
    build(cfg, store)
    assert "editorial" not in _current_files(cfg, story_id)["json"]

    _edit(store, story_id, patch={"tags": ["relay", "relay"], "products": ["arti", "arti"], "sources": [
        {"url": "https://example.org/news/1", "title": "Original"}, {"url": "https://example.org/news/2?utm_source=x", "title": "Follow-up"}]})
    build(cfg, store)
    story = _current_files(cfg, story_id)["json"]
    assert [s["url"] for s in story["sources"]] == ["https://example.org/news/1", "https://example.org/news/2"]
    assert story["tags"] == ["security", "relay"] and story["products"] == ["arti"]
    assert story_id in (Path(cfg["storage"]["output_dir"]) / "topics" / "relay" / "index.html").read_text()

    for number in range(22):
        _edit(store, story_id, patch={"summary": f"Correction {number}."})
    assert [r["revision"] for r in editorial.history(store.db, story_id)["revisions"]] == list(range(23, 0, -1))
    build(cfg, store)
    files = _current_files(cfg, story_id)
    assert len(files["json"]["editorial"]["history"]) == 20 and files["json"]["editorial"]["history_total"] == 23
    assert "Editorial history (23)" in files["article"] and "latest 20 of 23 changes" in files["article"]

    editorial_act(editorial.unlock, store, story_id, reason="Reviewed source evidence.")
    build(cfg, store)
    public = _current_files(cfg, story_id)["json"]
    public["editorial"]["later_field"] = 1
    text = json.dumps(public, ensure_ascii=False, sort_keys=True) + "\n"
    with store.db:
        store.db.execute("UPDATE public_catalog SET public_json=?,json_sha256=?,template_hash='earlier' WHERE story_id=?",
                         (text, hashlib.sha256(text.encode()).hexdigest(), story_id))
        store.db.execute("DELETE FROM stories WHERE id=?", (story_id,))
    assert build(cfg, store, force=True)["stories_skipped"] == 0
    assert f'id="story-{story_id}"' in _current_files(cfg, story_id)["home"]


@pytest.mark.parametrize("changes", [{"reason": ""}, {"reason": "x" * 1001}, {"reason": "Fixed a claim.\uffff"},
    {"expect_hash": ""}, {"expect_hash": "0" * 64}, {"observed": "not a date"}, {"observed": "2020-01-01T00:00:00Z"}])
def test_reason_hash_and_time_are_required_and_validated(seeded, changes):
    """Validate `reason`, `expect_hash`, and `observed` bounds in `editorial.correct`."""
    _, store, story_id = seeded
    before = editorial.show(store.db, story_id)
    with pytest.raises(ValueError):
        editorial.correct(store.db, story_id, {"why_it_matters": FIX}, **{"reason": "Reviewed", "expect_hash": before["hash"], "observed": EDIT, **changes})
    assert editorial.show(store.db, story_id)["hash"] == before["hash"]


@pytest.mark.parametrize("evidence,cited", [
    ("the report's OLD keys remain untrusted", True),
    ("The operator reported a plausible compromise", False),
    ("keys", False),
])
def test_only_cited_notes_add_citations_and_date_the_story(store, evidence, cited):
    """Add note permalinks and advance `updated_at` only when writer `evidence` cites a note."""
    story = seed_story(store, _note_item(), analysis(evidence=[evidence]), key="note", at=LATER)
    assert len(story["sources"]) == (2 if cited else 1) and story["updated_at"] == (EDIT if cited else DATE)
    assert story["published_at"] == DATE and story["added_at"] == LATER
    assert json.loads(store.db.execute("SELECT payload FROM items").fetchone()[0])["updated_at"] == DATE


def test_a_quote_cites_only_its_earliest_note_and_cumulative_updates_keep_citations(tmp_path):
    """Attribute repeated quotes to the earliest note and retain prior note citations across updates."""
    notes = [
        make_note(3, "> The report’s old keys remain untrusted. Agreed.", author="user3", created_at=LATER, url=URL),
        make_note(2, "+1, the operator reported a plausible compromise.", author="user2", created_at=LATER, url=URL),
        make_note(1, "The report’s old keys remain untrusted.", author="user1", created_at=EDIT, url=URL),
    ]
    with Store(tmp_path / "quote.db") as store:
        story = seed_story(
            store, _compose(item(url=URL), notes, LATER, source_key="k"),
            analysis(evidence=["The report’s old keys remain untrusted", "the operator reported a plausible compromise"]),
            key="replies", at=LATER,
        )
        assert [s["url"] for s in story["sources"]] == [URL, URL + "#note_1"] and story["updated_at"] == EDIT

    with Store(tmp_path / "cum.db") as store:
        incoming = _note_item()
        first = seed_story(store, incoming, analysis(evidence=["The report’s old keys remain untrusted"]), key="first", at=EDIT)
        assert first["updated_at"] == EDIT and len(first["sources"]) == 2
        later_note = make_note(456, "Maintainers merged the key-removal patch.", author="user456", created_at=LATER, url=URL)
        current = seed_story(
            store, _compose(incoming, [*incoming["public_comments"], later_note], LATER, source_key="k"),
            update_analysis(update="Maintainers merged the key-removal patch.", state="merged",
                            evidence=["Maintainers merged the key-removal patch."]),
            key="followup", at=LATER,
        )
        assert current["updated_at"] == LATER and (current["added_at"], current["published_at"]) == (first["added_at"], first["published_at"])
        assert [s["url"] for s in current["sources"]] == [URL, URL + "#note_123", URL + "#note_456"]
        assert current["updates"] == [{"at": LATER, "text": "Maintainers merged the key-removal patch.",
                                       "sources": [{"url": URL + "#note_456", "title": later_note["title"]}]}]
        later2 = "2026-11-11T12:00:00Z"
        updated_body = _compose(item(url=URL, content=incoming["content"] + " Upstream closed the tracking issue.", updated_at=later2),
                                [], later2, source_key="k")
        final = seed_story(
            store, updated_body,
            update_analysis(update="Upstream closed the tracking issue.", state="resolved",
                            evidence=["Upstream closed the tracking issue."]),
            key="closed", at=later2,
        )
        assert [s["url"] for s in final["sources"]] == [URL, URL + "#note_123", URL + "#note_456"] and final["updated_at"] == later2


def test_cli_correct_build_lock_and_stale_guard(seeded, tmp_path, capsys):
    """Apply `story correct` patches with CAS hash checks, lock the story, and render revisions."""
    cfg, _, story_id = seeded
    config_path = write_toml(tmp_path)
    current = invoke_cli(capsys, "story", "show", "--config", config_path, "--story", story_id)
    patch_file = tmp_path / "patch.json"
    arguments = ("story", "correct", "--config", config_path, "--story", story_id,
                 "--expect-hash", current["hash"], "--patch", patch_file,
                 "--reason", "Removed an unsupported operator instruction.")
    for body in (b"\xff", b"[]", b'{"why_it_matters": NaN}'):
        patch_file.write_bytes(body)
        invoke_cli(capsys, *arguments, expected=2)
    patch_file.write_text(json.dumps({"why_it_matters": "The report says the existing keys cannot be trusted."}))
    changed = invoke_cli(capsys, *arguments)
    assert changed["locked"] and changed["publication_pending"] and changed["revision"] == 1
    stale = invoke_cli(capsys, *arguments, expected=2)
    assert "changed" in stale["error"].lower() or "hash" in stale["error"].lower()
    invoke_cli(capsys, "build", "--config", config_path)
    public = _current_files(cfg, story_id)["json"]
    assert public["why_it_matters"] == "The report says the existing keys cannot be trusted."
    assert public["published_at"] == DATE and public["editorial"]["status"] == "corrected"
    history = invoke_cli(capsys, "story", "history", "--config", config_path, "--story", story_id)
    assert [r["reason"] for r in history["revisions"]] == ["Removed an unsupported operator instruction."]


def test_cli_retraction_is_a_permanent_noticed_page(seeded, tmp_path, capsys):
    """Render retracted stories as permanent notice pages and refuse subsequent `story unlock`."""
    cfg, _, story_id = seeded
    config_path = write_toml(tmp_path)
    current = invoke_cli(capsys, "story", "show", "--config", config_path, "--story", story_id)
    withdrawn = invoke_cli(capsys, "story", "retract", "--config", config_path, "--story", story_id,
                           "--expect-hash", current["hash"], "--reason", "The report was withdrawn.")
    assert withdrawn["retracted"] and withdrawn["locked"]
    invoke_cli(capsys, "build", "--config", config_path)
    article = _current_files(cfg, story_id)["article"]
    assert "retract" in article.lower()
    invoke_cli(capsys, "story", "unlock", "--config", config_path, "--story", story_id,
               "--expect-hash", withdrawn["hash"], "--reason", "Resume automation", expected=2)


def test_operator_write_reports_busy_without_touching_story(seeded, tmp_path, capsys):
    """Return exit code 75 (`already-running`) when an operator write contends with `run_lock`."""
    cfg, _, story_id = seeded
    config_path = write_toml(tmp_path)
    current = invoke_cli(capsys, "story", "show", "--config", config_path, "--story", story_id)
    with run_lock(cfg["storage"]["database"]) as locked:
        assert locked
        busy = invoke_cli(capsys, "story", "retract", "--config", config_path, "--story", story_id,
                          "--expect-hash", current["hash"], "--reason", "Test lock", expected=75)
    assert busy["status"] == "already-running"
    assert invoke_cli(capsys, "story", "show", "--config", config_path, "--story", story_id)["hash"] == current["hash"]


def test_unknown_editorial_action_rejected_without_mutating_state(seeded):
    """Reject unknown editorial actions on unlocked and locked stories without writing controls or revisions."""
    _, store, story_id = seeded
    shown = editorial.show(store.db, story_id)
    with pytest.raises(ValueError, match="Unknown editorial action"):
        editorial._apply(store.db, story_id, "typo_action", reason="Reviewed.", expect_hash=shown["hash"], observed=EDIT)
    assert store.db.execute("SELECT COUNT(*) FROM editorial_controls").fetchone()[0] == 0
    assert store.db.execute("SELECT COUNT(*) FROM editorial_revisions").fetchone()[0] == 0

    _edit(store, story_id)
    before_ctrl = tuple(store.db.execute("SELECT * FROM editorial_controls WHERE story_id=?", (story_id,)).fetchone())
    locked_shown = editorial.show(store.db, story_id)
    with pytest.raises(ValueError, match="Unknown editorial action"):
        editorial._apply(store.db, story_id, "typo_action", reason="Reviewed.", expect_hash=locked_shown["hash"], observed=LATER)
    assert tuple(store.db.execute("SELECT * FROM editorial_controls WHERE story_id=?", (story_id,)).fetchone()) == before_ctrl
    assert store.db.execute("SELECT COUNT(*) FROM editorial_revisions").fetchone()[0] == 1


def test_legacy_quarantined_snapshots_support_show_correct_and_retract(tmp_path, monkeypatch):
    """Allow `show`, repairing `correct`, and `retract` on legacy cataloged stories with `http://` sources."""
    cfg = pub_settings(tmp_path)
    output = Path(cfg["storage"]["output_dir"])
    plain_fix = {"url": "http://example.org/legacy-1", "title": "Legacy HTTP Report 1"}
    plain_ret = {"url": "http://example.org/legacy-2", "title": "Legacy HTTP Report 2"}
    s_keep = make_story(1)
    s_fix = make_story(2, sources=[plain_fix])
    s_ret = make_story(3, sources=[plain_ret])
    with Store(cfg["storage"]["database"]) as store:
        put_story(store.db, s_keep)
        with monkeypatch.context() as older:
            older.setattr(render, "_public_url", lambda url: url)
            put_story(store.db, s_fix)
            put_story(store.db, s_ret)
            build(cfg, store)
        ret_cat = json.loads(store.db.execute("SELECT public_json FROM public_catalog WHERE story_id=?", (s_ret["id"],)).fetchone()[0])
        ret_cat["state"] = "retired-legacy-state"
        ret_json = json.dumps(ret_cat, ensure_ascii=False, sort_keys=True) + "\n"
        with store.db:
            store.db.execute(
                "UPDATE public_catalog SET public_json=?,json_sha256=? WHERE story_id=?",
                (ret_json, hashlib.sha256(ret_json.encode("utf-8")).hexdigest(), s_ret["id"]),
            )
            store.db.execute("UPDATE stories SET payload=json_set(payload,'$.state','retired-legacy-state') WHERE id=?", (s_ret["id"],))
            store.db.execute("UPDATE public_catalog SET template_hash='old-template'")
            store.db.execute("UPDATE metadata SET value='old-template' WHERE key='publication_template'")
        assert build(cfg, store)["stories_skipped"] == 2

        shown_fix = editorial.show(store.db, s_fix["id"])
        assert shown_fix["using_last_published_snapshot"] is True and len(shown_fix["hash"]) == 64
        with pytest.raises(ValueError, match="safe source URL"):
            editorial.correct(
                store.db, s_fix["id"], {"title": "Still missing HTTPS source"},
                reason="Incomplete repair.", expect_hash=shown_fix["hash"], observed=LATER,
            )
        repaired = editorial.correct(
            store.db, s_fix["id"],
            {"sources": [{"url": "https://example.org/legacy-1", "title": "Upgraded HTTPS Report 1"}]},
            reason="Upgraded source citation to HTTPS.", expect_hash=shown_fix["hash"], observed=LATER,
        )
        assert repaired["locked"] is True and repaired["revision"] == 1

        shown_ret = editorial.show(store.db, s_ret["id"])
        assert shown_ret["using_last_published_snapshot"] is True and len(shown_ret["hash"]) == 64
        withdrawn = editorial.retract(
            store.db, s_ret["id"], reason="Withdrawn legacy report.", expect_hash=shown_ret["hash"], observed=LATER,
        )
        assert withdrawn["retracted"] is True and withdrawn["locked"] is True

        rebuilt = build(cfg, store)
        assert rebuilt["stories_skipped"] == 0 and rebuilt["published_stories"] == 3
        home = (output / "index.html").read_text(encoding="utf-8")
        assert s_fix["id"] in home and "https://example.org/legacy-1" in (output / f"news/{s_fix['id']}/story.json").read_text(encoding="utf-8")
        tomb_html = (output / f"news/{s_ret['id']}/index.html").read_text(encoding="utf-8")
        tomb_json = json.loads((output / f"news/{s_ret['id']}/story.json").read_text(encoding="utf-8"))
        assert tomb_json["title"] == "Retracted story" and tomb_json["sources"] == []
        assert "Withdrawn legacy report." in tomb_html and plain_ret["url"] not in tomb_html
        assert editorial.show(store.db, s_ret["id"])["retracted"] is True
        with pytest.raises(ValueError, match="no accepted public text"):
            editorial_act(editorial.restore, store, s_ret["id"], 0, reason="Attempt restore.", observed="2026-11-11T00:00:00Z")


def test_escaped_lone_surrogate_in_public_catalog_supports_show_correct_retract_and_restore(tmp_path):
    """Handle escaped lone surrogates in `public_catalog` across `show`, `correct`, `retract`, and `restore`."""
    cfg = pub_settings(tmp_path)
    story_obj = make_story(1)
    sid = story_obj["id"]
    with Store(cfg["storage"]["database"]) as store:
        put_story(store.db, story_obj)
        build(cfg, store)
        cat_row = store.db.execute("SELECT public_json FROM public_catalog WHERE story_id=?", (sid,)).fetchone()
        cat_data = json.loads(cat_row[0])
        cat_data["title"] = "Legacy \ud800 Title"
        legacy_json = json.dumps(cat_data, ensure_ascii=True, sort_keys=True) + "\n"
        legacy_sha = hashlib.sha256(legacy_json.encode("utf-8")).hexdigest()
        story_data = json.loads(store.db.execute("SELECT payload FROM stories WHERE id=?", (sid,)).fetchone()[0])
        story_data["title"] = "Legacy \ud800 Title"
        with store.db:
            store.db.execute(
                "UPDATE public_catalog SET public_json=?,json_sha256=? WHERE story_id=?",
                (legacy_json, legacy_sha, sid),
            )
            store.db.execute(
                "UPDATE stories SET payload=? WHERE id=?",
                (json.dumps(story_data, ensure_ascii=True), sid),
            )

        shown = editorial.show(store.db, sid)
        assert shown["using_last_published_snapshot"] is True
        json.dumps(shown, ensure_ascii=False).encode("utf-8")

        corr = editorial.correct(
            store.db,
            sid,
            {"summary": "Cleaned legacy summary."},
            reason="Cleaned legacy title and summary.",
            expect_hash=shown["hash"],
            observed=LATER,
        )
        assert corr["revision"] == 1
        hist_corr = editorial.history(store.db, sid)
        meta_corr = editorial.public_metadata(store.db, sid)
        assert len(hist_corr["revisions"]) == 1 and meta_corr is not None
        json.dumps(hist_corr, ensure_ascii=False).encode("utf-8")
        json.dumps(meta_corr, ensure_ascii=False).encode("utf-8")

        ret = editorial.retract(
            store.db,
            sid,
            reason="Withdrawn legacy story.",
            expect_hash=corr["hash"],
            observed="2026-11-11T00:00:00Z",
        )
        assert ret["retracted"] is True and ret["revision"] == 2

        rest = editorial.restore(
            store.db,
            sid,
            0,
            reason="Restored cleaned snapshot.",
            expect_hash=ret["hash"],
            observed="2026-11-12T00:00:00Z",
        )
        assert rest["retracted"] is False and rest["revision"] == 3
        hist_final = editorial.history(store.db, sid)
        meta_final = editorial.public_metadata(store.db, sid)
        assert len(hist_final["revisions"]) == 3 and meta_final is not None
        json.dumps(hist_final, ensure_ascii=False).encode("utf-8")
        json.dumps(meta_final, ensure_ascii=False).encode("utf-8")
        assert build(cfg, store)["stories_skipped"] == 0


def test_invalid_utf8_sqlite_text_in_editorial_controls_and_revisions(tmp_path):
    """Tolerate invalid UTF-8 SQLite `TEXT` in `editorial_controls` and `editorial_revisions` across editorial operations."""
    cfg = pub_settings(tmp_path)
    story_a = make_story(1)
    story_b = make_story(2)
    story_c = make_story(3)
    with Store(cfg["storage"]["database"]) as store:
        for entry in (story_a, story_b, story_c):
            put_story(store.db, entry)
        build(cfg, store)
        for sid in (story_a["id"], story_b["id"], story_c["id"]):
            editorial_act(editorial.correct, store, sid, {"why_it_matters": FIX}, reason="Initial edit.", observed=EDIT)
        editorial_act(editorial.unlock, store, story_c["id"], reason="Unlock before merge check.", observed=EDIT)

        with store.db:
            store.db.execute("DROP TRIGGER editorial_revisions_unchanged")
            for sid in (story_a["id"], story_b["id"], story_c["id"]):
                store.db.execute(
                    "UPDATE editorial_controls SET notice_reason=CAST(X'c328' AS TEXT) WHERE story_id=?",
                    (sid,),
                )
            for sid in (story_a["id"], story_b["id"]):
                store.db.execute(
                    "UPDATE editorial_revisions SET reason=CAST(X'c328' AS TEXT) WHERE story_id=? AND revision=1",
                    (sid,),
                )
            store.db.execute(
                """UPDATE editorial_revisions
                   SET before_public_json=CAST(X'c328' AS TEXT),after_public_json=CAST(X'c328' AS TEXT)
                   WHERE story_id=? AND revision=1""",
                (story_b["id"],),
            )
            editorial.initialize(store.db)

        with pytest.raises(ValueError, match="Invalid editorial") as meta_err:
            editorial.public_metadata(store.db, story_a["id"])
        assert not isinstance(meta_err.value, UnicodeError)

        shown_a = editorial.show(store.db, story_a["id"])
        hist_a = editorial.history(store.db, story_a["id"])
        assert len(hist_a["revisions"]) == 1
        json.dumps(hist_a, ensure_ascii=False).encode("utf-8")

        corr_a = editorial.correct(
            store.db,
            story_a["id"],
            {"summary": "Repaired summary after damaged notice."},
            reason="Repaired editorial notice.",
            expect_hash=shown_a["hash"],
            observed=LATER,
        )
        assert corr_a["revision"] == 2

        shown_b = editorial.show(store.db, story_b["id"])
        hist_b = editorial.history(store.db, story_b["id"])
        assert "unparseable_record" in hist_b["revisions"][0]["after_public"]
        ret_b = editorial.retract(
            store.db,
            story_b["id"],
            reason="Withdrawn damaged record.",
            expect_hash=shown_b["hash"],
            observed=LATER,
        )
        assert ret_b["retracted"] is True and ret_b["revision"] == 2
        meta_b = editorial.public_metadata(store.db, story_b["id"])
        assert meta_b is not None and meta_b["status"] == "retracted"
        with pytest.raises(ValueError, match="no accepted public text"):
            editorial.restore(
                store.db,
                story_b["id"],
                1,
                reason="Attempt restore of damaged revision.",
                expect_hash=ret_b["hash"],
                observed="2026-11-11T00:00:00Z",
            )

        shown_c = editorial.show(store.db, story_c["id"])
        merged = editorial.merge(
            store.db,
            story_c["id"],
            story_a["id"],
            reason="Merge story with damaged notice.",
            expect_hash=shown_c["hash"],
            observed="2026-11-11T00:00:00Z",
        )
        assert merged["merged_into"] == story_a["id"]


def test_catalog_fallback_rejects_mismatched_story_id_and_binds_snapshot_in_hash(tmp_path):
    """Reject cross-story catalog fallback snapshots and invalidate CAS hashes when fallback text changes."""
    cfg_id = pub_settings(tmp_path / "id")
    story_a = make_story(1, id="story-a", title="Story A", summary="Summary A.")
    story_b = make_story(2, id="story-b", title="Story B", summary="Summary B.")
    with Store(cfg_id["storage"]["database"]) as store:
        put_story(store.db, story_a)
        put_story(store.db, story_b)
        build(cfg_id, store)

        b_cat_json = store.db.execute("SELECT public_json FROM public_catalog WHERE story_id='story-b'").fetchone()[0]
        b_cat_sha = hashlib.sha256(b_cat_json.encode("utf-8")).hexdigest()
        with store.db:
            store.db.execute("UPDATE stories SET payload='broken json' WHERE id='story-a'")
            store.db.execute(
                "UPDATE public_catalog SET public_json=?,json_sha256=? WHERE story_id='story-a'",
                (b_cat_json, b_cat_sha),
            )
        with pytest.raises(ValueError, match="no valid public snapshot"):
            editorial.show(store.db, "story-a")

    cfg = pub_settings(tmp_path / "hash")
    with Store(cfg["storage"]["database"]) as store:
        put_story(store.db, story_b)
        build(cfg, store)

        shown_b = editorial.show(store.db, "story-b")
        editorial.correct(
            store.db, "story-b", {"summary": "Summary B revised."},
            reason="Revise summary B.", expect_hash=shown_b["hash"], observed=LATER,
        )
        with store.db:
            store.db.execute("UPDATE stories SET payload='broken json' WHERE id='story-b'")
        fallback_before = editorial.show(store.db, "story-b")
        assert fallback_before["using_last_published_snapshot"] is True
        assert fallback_before["story"]["summary"] == "Summary B."

        # Rebuilding without changing the effective public snapshot preserves the hash.
        with store.db:
            store.db.execute("UPDATE public_catalog SET template_hash='old-template' WHERE story_id='story-b'")
        assert editorial.show(store.db, "story-b")["hash"] == fallback_before["hash"]

        # Building publishes Summary B revised from editorial_revisions without altering stories or editorial_controls.
        build(cfg, store)
        fallback_after = editorial.show(store.db, "story-b")
        assert fallback_after["using_last_published_snapshot"] is True
        assert fallback_after["story"]["summary"] == "Summary B revised."
        assert fallback_after["hash"] != fallback_before["hash"]
        with pytest.raises(ValueError, match="changed since it was reviewed"):
            editorial.correct(
                store.db, "story-b", {"why_it_matters": FIX},
                reason="Stale review.", expect_hash=fallback_before["hash"], observed="2026-11-11T00:00:00Z",
            )


def test_retraction_hides_blob_historical_reason_and_tolerates_unreadable_after_json_and_list_category(tmp_path):
    """Hide BLOB historical reasons on retraction, skip unreadable `after_public_json` update diffs, and coerce list categories."""
    cfg = pub_settings(tmp_path)
    output = Path(cfg["storage"]["output_dir"])
    s_blob = make_story(1, id="story-blob-reason", title="Blob reason story")
    s_upd = make_story(2, id="story-upd-after", title="Update history story", updates=UPDATES[:1])
    s_cat = make_story(3, id="story-list-cat", title="List category story")
    with Store(cfg["storage"]["database"]) as store:
        for entry in (s_blob, s_upd, s_cat):
            put_story(store.db, entry)
        build(cfg, store)

        # BLOB historical reason must not break public_metadata, update_target, or retraction rendering.
        editorial_act(editorial.correct, store, s_blob["id"], {"summary": "First correction."}, reason="Old reason.", observed=EDIT)
        with store.db:
            store.db.execute("DROP TRIGGER editorial_revisions_unchanged")
            store.db.execute(
                "UPDATE editorial_revisions SET reason=CAST('hidden blob' AS BLOB) WHERE story_id=? AND revision=1",
                (s_blob["id"],),
            )
            editorial.initialize(store.db)
        meta_unretracted = editorial.public_metadata(store.db, s_blob["id"])
        assert meta_unretracted is not None and meta_unretracted["status"] == "corrected"
        assert meta_unretracted["reason"] == "Old reason."
        assert meta_unretracted["history"][0]["reason"] == ""
        editorial_act(editorial.retract, store, s_blob["id"], reason="Withdrawn publicly.", observed=LATER)
        meta_blob = editorial.public_metadata(store.db, s_blob["id"])
        assert meta_blob is not None and meta_blob["status"] == "retracted"
        assert {entry["revision"]: entry["reason"] for entry in meta_blob["history"]} == {2: "Withdrawn publicly.", 1: ""}
        assert build(cfg, store)["stories_skipped"] == 0
        with store.db:
            store.db.execute("DELETE FROM stories WHERE id=?", (s_blob["id"],))
        assert build(cfg, store, force=True)["stories_skipped"] == 0
        assert "Withdrawn publicly." in (output / f"news/{s_blob['id']}/index.html").read_text(encoding="utf-8")

        # Unreadable after_public_json must not mark retained updates as superseded, while valid empty updates still do.
        editorial_act(editorial.correct, store, s_upd["id"], {"title": "Retitled update story"}, reason="Retitled.", observed=EDIT)
        with store.db:
            store.db.execute("DROP TRIGGER editorial_revisions_unchanged")
            store.db.execute(
                "UPDATE editorial_revisions SET after_public_json='not-valid-json' WHERE story_id=? AND revision=1",
                (s_upd["id"],),
            )
            editorial.initialize(store.db)
        meta_upd = editorial.public_metadata(store.db, s_upd["id"])
        assert meta_upd is not None and "updates" not in meta_upd["history"][0]["superseded"]
        build(cfg, store)
        editorial_act(editorial.correct, store, s_upd["id"], {"updates": []}, reason="Removed update.", observed=LATER)
        meta_removed = editorial.public_metadata(store.db, s_upd["id"])
        assert meta_removed["history"][0]["superseded"]["updates"] == [{"at": UPDATES[0]["at"], "text": UPDATES[0]["text"]}]

        # Non-string legacy category (list) coerces to "network" on retract and in _render_accepted.
        cat_snap = json.loads(store.db.execute("SELECT public_json FROM public_catalog WHERE story_id=?", (s_cat["id"],)).fetchone()[0])
        cat_snap["category"] = []
        cat_snap["confidence"] = []
        cat_snap["state"] = []
        cat_text = json.dumps(cat_snap, ensure_ascii=False, sort_keys=True) + "\n"
        cat_sha = hashlib.sha256(cat_text.encode("utf-8")).hexdigest()
        with store.db:
            store.db.execute("UPDATE public_catalog SET public_json=?,json_sha256=? WHERE story_id=?", (cat_text, cat_sha, s_cat["id"]))
            store.db.execute("UPDATE stories SET payload='broken json' WHERE id=?", (s_cat["id"],))
        retracted = editorial_act(editorial.retract, store, s_cat["id"], reason="Withdrawn legacy category.", observed=LATER)
        assert retracted["retracted"] is True
        with store.db:
            store.db.execute("DELETE FROM stories WHERE id=?", (s_cat["id"],))
        assert build(cfg, store)["stories_skipped"] == 0
        tomb = json.loads((output / f"news/{s_cat['id']}/story.json").read_text(encoding="utf-8"))
        assert (tomb["category"], tomb["confidence"], tomb["state"]) == ("network", "reported", "developing")
        assert tomb["editorial"]["status"] == "retracted"


def test_retraction_skips_unreadable_older_history_and_blob_reason_does_not_break_update_target(tmp_path):
    """Skip unreadable older revision rows on retraction and keep `candidate.update_target` working with BLOB reasons."""
    cfg = pub_settings(tmp_path)
    output = Path(cfg["storage"]["output_dir"])
    with Store(cfg["storage"]["database"]) as store:
        base_item = item(url=URL, content="Original report on relay key rotation details.")
        seeded_story = seed_story(store, base_item, analysis(), key="seed-blob", at=DATE)
        sid = seeded_story["id"]
        build(cfg, store)

        # Unretracted story with a BLOB historical revision reason must still allow candidate.update_target().
        editorial_act(editorial.correct, store, sid, {"summary": "Clarified summary."}, reason="Initial fix.", observed=EDIT)
        editorial_act(editorial.unlock, store, sid, reason="Resume updates.", observed=EDIT)
        with store.db:
            store.db.execute("DROP TRIGGER editorial_revisions_unchanged")
            store.db.execute(
                "UPDATE editorial_revisions SET reason=CAST('raw blob reason' AS BLOB) WHERE story_id=? AND revision=1",
                (sid,),
            )
            editorial.initialize(store.db)
        follow_up = {**base_item, "content": "Follow-up update confirming all relays completed rotation.", "updated_at": LATER}
        assert store.ingest(follow_up, LATER) is True
        pending_row = store.pending(5, LATER)[0]
        target = candidate.update_target(store.db, pending_row)
        assert target is not None and target["id"] == sid
        assert {entry["revision"]: entry["reason"] for entry in target["editorial"]["history"]} == {
            2: "Resume updates.",
            1: "",
        }

        # Retracted story with a BLOB action in an older revision row must skip that older row and still publish cleanly.
        s_ret = make_story(2, id="story-blob-action", title="Blob action story")
        put_story(store.db, s_ret)
        build(cfg, store)
        editorial_act(editorial.correct, store, s_ret["id"], {"summary": "First revision."}, reason="Fix 1.", observed=EDIT)
        with store.db:
            store.db.execute("DROP TRIGGER editorial_revisions_unchanged")
            store.db.execute(
                "UPDATE editorial_revisions SET action=CAST('correct' AS BLOB) WHERE story_id=? AND revision=1",
                (s_ret["id"],),
            )
            editorial.initialize(store.db)
        editorial_act(editorial.retract, store, s_ret["id"], reason="Withdrawn despite older BLOB.", observed=LATER)
        meta = editorial.public_metadata(store.db, s_ret["id"])
        assert meta is not None and meta["status"] == "retracted"
        assert [entry["revision"] for entry in meta["history"]] == [2]
        assert meta["history"][0]["reason"] == "Withdrawn despite older BLOB."
        # Private revision row in editorial_revisions stays intact and untouched.
        assert len(editorial.history(store.db, s_ret["id"])["revisions"]) == 2
        assert build(cfg, store)["stories_skipped"] == 0
        with store.db:
            store.db.execute("DELETE FROM stories WHERE id=?", (s_ret["id"],))
        assert build(cfg, store, force=True)["stories_skipped"] == 0
        assert "Withdrawn despite older BLOB." in (output / f"news/{s_ret['id']}/index.html").read_text(encoding="utf-8")


def test_retraction_tolerates_non_strict_legacy_catalog_snapshot_and_restore_rejects_foreign_story_id(tmp_path):
    """Record non-strict legacy `before_public_json` as unavailable on retraction and validate restore snapshot IDs."""
    cfg = pub_settings(tmp_path)
    output = Path(cfg["storage"]["output_dir"])
    s_nan = make_story(1, id="story-legacy-nan", title="Legacy NaN story", summary="Initial summary.")
    s_a = make_story(2, id="story-restore-a", title="Story A original", summary="Original summary A.")
    s_b = make_story(3, id="story-restore-b", title="Story B original", summary="Original summary B.")
    with Store(cfg["storage"]["database"]) as store:
        for entry in (s_nan, s_a, s_b):
            put_story(store.db, entry)
        build(cfg, store)

        # Checksum-valid catalog snapshot carrying legacy NaN must not abort retraction.
        nan_cat = json.loads(store.db.execute("SELECT public_json FROM public_catalog WHERE story_id=?", (s_nan["id"],)).fetchone()[0])
        nan_cat["legacy_score"] = float("nan")
        nan_text = json.dumps(nan_cat, ensure_ascii=False, sort_keys=True, allow_nan=True) + "\n"
        nan_sha = hashlib.sha256(nan_text.encode("utf-8")).hexdigest()
        with store.db:
            store.db.execute(
                "UPDATE public_catalog SET public_json=?,json_sha256=? WHERE story_id=?",
                (nan_text, nan_sha, s_nan["id"]),
            )
        shown_nan = editorial.show(store.db, s_nan["id"])
        ret_nan = editorial.retract(
            store.db, s_nan["id"], reason="Withdrawn legacy NaN snapshot.", expect_hash=shown_nan["hash"], observed=LATER,
        )
        assert ret_nan["retracted"] is True and ret_nan["revision"] == 1
        hist_nan = editorial.history(store.db, s_nan["id"])
        assert hist_nan["revisions"][0]["before_public"] is None
        assert hist_nan["revisions"][0]["after_public"]["title"] == "Retracted story"
        assert build(cfg, store)["stories_skipped"] == 0
        assert "Withdrawn legacy NaN snapshot." in (output / f"news/{s_nan['id']}/index.html").read_text(encoding="utf-8")

        # Restore must validate snapshot IDs on both revision > 0 and revision == 0 fallbacks.
        editorial_act(editorial.correct, store, s_a["id"], {"summary": "Corrected summary A."}, reason="Rev 1.", observed=EDIT)
        editorial_act(editorial.correct, store, s_a["id"], {"summary": "Second summary A."}, reason="Rev 2.", observed=LATER)
        b_pub = store.db.execute("SELECT public_json FROM public_catalog WHERE story_id=?", (s_b["id"],)).fetchone()[0]
        with store.db:
            store.db.execute("DROP TRIGGER editorial_revisions_unchanged")
            store.db.execute(
                "UPDATE editorial_revisions SET after_public_json=?,before_public_json=? WHERE story_id=? AND revision=1",
                (b_pub, b_pub, s_a["id"]),
            )
            editorial.initialize(store.db)
        # Revision 1 after_public_json belongs to story B -> must reject.
        with pytest.raises(ValueError, match="no accepted public text"):
            editorial_act(editorial.restore, store, s_a["id"], 1, reason="Attempt foreign rev 1.", observed="2026-11-11T00:00:00Z")
        # Revision 0 before_public_json belongs to story B, but before_story_json belongs to story A -> restores story A.
        restored = editorial_act(editorial.restore, store, s_a["id"], 0, reason="Restore original A.", observed="2026-11-11T00:00:00Z")
        assert restored["revision"] == 3
        assert editorial.show(store.db, s_a["id"])["story"]["title"] == "Story A original"
        assert editorial.show(store.db, s_a["id"])["story"]["summary"] == "Original summary A."

        # If both revision-0 candidates belong to story B, restore must reject.
        with store.db:
            store.db.execute("DROP TRIGGER editorial_revisions_unchanged")
            store.db.execute(
                "UPDATE editorial_revisions SET before_story_json=? WHERE story_id=? AND revision=1",
                (b_pub, s_a["id"]),
            )
            editorial.initialize(store.db)
        with pytest.raises(ValueError, match="no accepted public text"):
            editorial_act(editorial.restore, store, s_a["id"], 0, reason="Attempt foreign rev 0.", observed="2026-11-12T00:00:00Z")
