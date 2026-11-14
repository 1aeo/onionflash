"""Editorial decisions survive late inputs, retries, backup and publication."""

import copy
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import xml.etree.ElementTree as ET

import pytest

from helpers import DATE, LATER, analysis, config, finish_reviewed, item, seed_story, update_analysis
from onionflash import editorial, publication, render
from onionflash.cli import build
from onionflash.comments import _compose
from onionflash.schema import UPDATE_CHARS
from onionflash.store import Store, backup_database

EDIT = "2026-11-09T12:00:00Z"
FIX = "The report requests removal of the old keys from the software."
UPDATE_SOURCE = {"url": "https://example.org/news/2", "title": "Follow-up report"}
UPDATES = [{"at": "2026-11-08T18:00:00Z", "text": "The operator rotated the keys.", "sources": [UPDATE_SOURCE]},
           {"at": "2026-11-09T06:00:00+00:00", "text": "Relays picked up the new keys.", "sources": [UPDATE_SOURCE]}]
URL = "https://gitlab.torproject.org/tpo/core/tor/-/work_items/41473"


@pytest.fixture
def seeded(tmp_path):
    cfg = config(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        story_id = seed_story(store, item(content=item()["content"] * 3),
                              analysis(why_it_matters="Unsupported operator configuration instruction."), key="seed", at=DATE)["id"]
        build(cfg, store)
        yield cfg, store, story_id


def edit(store, story_id, **kw):
    return editorial.correct(store.db, story_id, kw.pop("patch", {"why_it_matters": FIX}),
                             expect_hash=editorial.show(store.db, story_id)["hash"],
                             reason=kw.pop("reason", "Removed unsupported operator advice."),
                             observed=kw.pop("observed", EDIT), **kw)


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


def test_databases_this_release_creates_still_accept_earlier_held_update_writes(store):
    store.db.execute("""INSERT INTO editorial_controls(story_id,revision,locked,retracted,notice_action,
        notice_reason,notice_at) VALUES('s',1,1,0,'correct','r','t')""")
    store.db.execute("UPDATE editorial_controls SET held_updates=held_updates+1,last_held_at='t2' WHERE story_id='s'")
    assert store.db.execute("SELECT last_held_at FROM editorial_controls").fetchone()[0] == "t2"


def test_correction_preserves_identity_dates_and_keeps_superseded_text_off_feeds(seeded):
    cfg, store, story_id = seeded
    before = editorial.show(store.db, story_id)
    receipt = edit(store, story_id, reason='Removed unsupported advice. <script>alert("x")</script>')
    assert receipt["locked"] and receipt["revision"] == 1 and not store.db.in_transaction
    assert editorial.show(store.db, story_id)["hash"] == receipt["hash"]
    build(cfg, store)
    files = current_files(cfg, story_id)
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
    assert saved["hash"] == locked["hash"] and saved["held_updates"] == 1 and saved["story"]["why_it_matters"] == FIX
    assert store.db.execute("SELECT COUNT(*) FROM analyses WHERE cache_key='late'").fetchone()[0] == 1
    assert tuple(store.db.execute("SELECT status,story_id FROM items WHERE id=?", (row["id"],)).fetchone()) == ("published", story_id)
    assert len(store.stories()) == 1


def test_story_guards_left_by_an_earlier_release_cannot_stop_other_writers(seeded):
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
    cfg, store, story_id = seeded
    edit(store, story_id)
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
    act(editorial.retract, store, story_id, reason="The source withdrew this report.")
    act(editorial.restore, store, story_id, 1, reason="Restored the verified correction.")
    act(editorial.unlock, store, story_id, reason="Resumed tracking.")
    build(cfg, store)
    with sqlite3.connect(cfg["storage"]["database"]) as raw:
        assert raw.execute("UPDATE editorial_controls SET held_updates=held_updates+1").rowcount == 1
        assert raw.execute("UPDATE public_catalog SET template_hash='earlier'").rowcount == 1
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
    assert not store.db.in_transaction and editorial.show(store.db, story_id)["hash"] == before["hash"]
    assert len(editorial.history(store.db, story_id)["revisions"]) == 1


def test_retraction_tombstone_restore_and_explicit_unlock(seeded):
    cfg, store, story_id = seeded
    original = editorial.show(store.db, story_id)["story"]
    quoting = "Replaced the claim " + original["title"]
    edit(store, story_id, reason=quoting)
    build(cfg, store)
    withdrawn = act(editorial.retract, store, story_id, reason="The source withdrew this report.")
    build(cfg, store)
    files = current_files(cfg, story_id)
    assert files["json"]["id"] == story_id and files["json"]["editorial"]["status"] == "retracted"
    assert files["json"]["title"] == "Retracted story"
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
    assert restored["locked"] and not restored["retracted"] and editorial.show(store.db, story_id)["story"]["why_it_matters"] == FIX
    with pytest.raises(ValueError, match="accepted public text"):
        act(editorial.restore, store, story_id, 2)
    act(editorial.unlock, store, story_id)
    reviewed = editorial.show(store.db, story_id)
    assert not reviewed["locked"]
    store.ingest(item(content="An updated source report after explicit review.", updated_at=LATER), LATER)
    finish_reviewed(store, store.pending(1, LATER)[0],
                    update_analysis(update="New source-supported text.", evidence=["An updated source report after explicit review."]),
                    "after-unlock", LATER)
    with pytest.raises(ValueError, match="changed since it was reviewed"):
        editorial.correct(store.db, story_id, {"why_it_matters": FIX}, reason="Reviewed.", expect_hash=reviewed["hash"], observed=LATER)
    build(cfg, store)
    files = current_files(cfg, story_id)
    assert files["json"]["updates"][-1]["text"] == "New source-supported text."
    assert files["json"]["editorial"]["revision"] == 4 and files["json"]["editorial"]["history"][0]["action"] == "unlock"
    assert "Restored" in files["article"] and "Superseded public text" in files["article"] and quoting in json.dumps(files["json"])


def test_restore_original_backup_and_damaged_draft_fallbacks(seeded, tmp_path):
    cfg, store, story_id = seeded
    before = editorial.show(store.db, story_id)["story"]
    edit(store, story_id)
    build(cfg, store)
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
        assert len(editorial.history(restored.db, story_id)["revisions"]) == 2 and editorial.is_locked(restored.db, story_id)


def test_bad_unpublished_or_mismatched_draft_uses_last_good_snapshot(seeded):
    cfg, store, story_id = seeded
    with store.db:
        store.db.execute("UPDATE stories SET payload=? WHERE id=?", ('{"secret":"unpublished secret"}', story_id))
    assert editorial.show(store.db, story_id)["using_last_published_snapshot"]
    edit(store, story_id)
    build(cfg, store)
    assert "unpublished secret" not in current_files(cfg, story_id)["article"]
    assert editorial.history(store.db, story_id)["revisions"][0]["before_story"] == {"secret": "unpublished secret"}

    raw = store.stories()[0]
    raw["id"] = "incorrect-draft-id"
    with store.db:
        store.db.execute("UPDATE stories SET payload=? WHERE id=?", (json.dumps(raw), story_id))
    assert editorial.show(store.db, story_id)["using_last_published_snapshot"]
    assert build(cfg, store)["stories_skipped"] == 1
    assert not (Path(cfg["storage"]["output_dir"]) / "news" / "incorrect-draft-id").exists()
    edit(store, story_id, patch={"why_it_matters": "Updated verified notice."}, observed=LATER)
    assert build(cfg, store)["stories_skipped"] == 0 and current_files(cfg, story_id)["json"]["id"] == story_id


def test_prebuild_retract_deleted_story_retraction_and_blob_fallback(tmp_path):
    cfg = config(tmp_path / "pre")
    with Store(cfg["storage"]["database"]) as store:
        sid = seed_story(store, item(url="https://example.org/prebuild", title="Drafted notice", content="Initial notice text. " * 3),
                         analysis(title="Drafted notice", summary="Initial notice text.", evidence=["Initial notice text."]))["id"]
        editorial.retract(store.db, sid, reason="Retracted before build.", expect_hash=editorial.show(store.db, sid)["hash"], observed=LATER)
        hist = editorial.history(store.db, sid)["revisions"][0]
        assert "updates" not in (hist["after_public"] or {}) and "alert_notes" not in (hist["after_public"] or {})
        restored = editorial.restore(store.db, sid, 0, reason="Restore pre-build story.",
                                     expect_hash=editorial.show(store.db, sid)["hash"], observed="2026-11-10T13:30:00Z")
        assert restored["retracted"] is False
        publication.build(cfg, store)
        editorial.retract(store.db, sid, reason="Withdrawn after verification.",
                          expect_hash=editorial.show(store.db, sid)["hash"], observed="2026-11-10T14:00:00Z")
        with store.db:
            store.db.execute("DELETE FROM stories WHERE id=?", (sid,))
        publication.build(cfg, store)
        html = (Path(cfg["storage"]["output_dir"]) / "news" / sid / "index.html").read_text(encoding="utf-8")
        assert "Retracted story" in html and "Initial notice text." not in html

    cfg2 = config(tmp_path / "trig")
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
        assert publication.build(cfg2, store)["published_stories"] == 1 and (out2 / "news" / sid2 / "index.html").exists()
        res = editorial.correct(store.db, sid2, {"category": "security"}, reason="Reclassify as security.",
                                expect_hash=editorial.show(store.db, sid2)["hash"], observed=LATER)
        shown = editorial.show(store.db, sid2)
        assert res["locked"] is True and shown["story"]["category"] == "security"
        assert "network" not in shown["story"]["tags"] and "security" in shown["story"]["tags"]
        publication.build(cfg2, store)
        with store.db:
            store.db.execute("UPDATE stories SET payload=? WHERE id=?", (b"\xff\xfeinvalid", sid2))
        assert editorial.show(store.db, sid2)["using_last_published_snapshot"] is True
        assert publication.build(cfg2, store)["published_stories"] == 1


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
    cfg, store, story_id = seeded
    before = editorial.show(store.db, story_id)
    with pytest.raises((ValueError, TypeError)):
        edit(store, story_id, patch=patch)
    assert editorial.show(store.db, story_id)["hash"] == before["hash"] and not store.db.in_transaction


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
    assert all("updates" not in entry["superseded"] for entry in history[1:])
    assert files["article"].count("Previous update") == 1
    assert "&lt;b&gt;Relays&lt;/b&gt; picked up" in files["article"] and "<b>Relays" not in files["article"]
    assert files["article"].count("The operator rotated the keys.") == 1
    for text in (files["home"], files["rss"], files["feed"]["content_text"]):
        assert "Relays began using the new keys." in text and "picked up the new keys." not in text
    recited = {**UPDATES[0], "sources": [{"url": "https://example.org/news/3", "title": "Notice"}]}
    edit(store, story_id, patch={"updates": [recited, edited]}, observed=LATER)
    build(cfg, store)
    files = current_files(cfg, story_id)
    assert "updates" not in files["json"]["editorial"]["history"][0]["superseded"]
    assert files["article"].count("The operator rotated the keys.") == 1
    edit(store, story_id, patch={"updates": [{**recited, "at": "2026-11-08T19:00:00Z"}, edited]}, observed=LATER)
    build(cfg, store)
    assert current_files(cfg, story_id)["json"]["editorial"]["history"][0]["superseded"]["updates"] == [
        {"at": "2026-11-08T18:00:00Z", "text": UPDATES[0]["text"]}]
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
        for upd in UPDATES:
            assert upd["text"] not in text
    assert len(store.stories()[0]["updates"]) == 2
    act(editorial.restore, store, story_id, 1)
    build(cfg, store)
    assert [u["text"] for u in current_files(cfg, story_id)["json"]["updates"]] == [u["text"] for u in UPDATES]


def test_list_field_correction_bounded_history_catalog_fields_and_forged_notice(seeded):
    cfg, store, story_id = seeded
    edit(store, story_id, patch={"tags": ["relay", "relay"], "products": ["arti", "arti"], "sources": [
        {"url": "https://example.org/news/1", "title": "Original"}, {"url": "https://example.org/news/2?utm_source=x", "title": "Follow-up"}]})
    build(cfg, store)
    story = current_files(cfg, story_id)["json"]
    assert [s["url"] for s in story["sources"]] == ["https://example.org/news/1", "https://example.org/news/2"]
    assert story["tags"] == ["security", "relay"] and story["products"] == ["arti"]
    assert story_id in (Path(cfg["storage"]["output_dir"]) / "topics" / "relay" / "index.html").read_text()

    raw = store.stories()[0]
    raw["editorial"] = {"status": "retracted", "reason": "Forged"}
    assert "editorial" not in render.prepare_story(raw)

    for number in range(22):
        edit(store, story_id, patch={"summary": f"Correction {number}."})
    assert [r["revision"] for r in editorial.history(store.db, story_id)["revisions"]] == list(range(23, 0, -1))
    build(cfg, store)
    files = current_files(cfg, story_id)
    assert len(files["json"]["editorial"]["history"]) == 20 and files["json"]["editorial"]["history_total"] == 23
    assert "Editorial history (23)" in files["article"] and "latest 20 of 23 changes" in files["article"]

    act(editorial.unlock, store, story_id)
    build(cfg, store)
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
    with store.db:
        store.db.execute("UPDATE stories SET payload=? WHERE id=?", (json.dumps(raw), story_id))
    build(cfg, store)
    assert "editorial" not in current_files(cfg, story_id)["json"]


@pytest.mark.parametrize("changes", [{"reason": ""}, {"reason": "x" * 1001}, {"reason": "Fixed a claim.\uffff"},
    {"expect_hash": ""}, {"expect_hash": "0" * 64}, {"observed": "not a date"}, {"observed": "2020-01-01T00:00:00Z"}])
def test_reason_hash_and_time_are_required_and_validated(seeded, changes):
    cfg, store, story_id = seeded
    before = editorial.show(store.db, story_id)
    with pytest.raises(ValueError):
        editorial.correct(store.db, story_id, {"why_it_matters": FIX}, **{"reason": "Reviewed", "expect_hash": before["hash"], "observed": EDIT, **changes})
    assert editorial.show(store.db, story_id)["hash"] == before["hash"]


def note(ident, created, body):
    return {"id": f"gid://gitlab/Note/{ident}", "url": f"{URL}#note_{ident}", "title": f"Public comment by @user{ident}",
            "author": f"user{ident}", "created_at": created, "body": body}


def note_item(body="The report’s old keys remain untrusted."):
    return _compose(item(url=URL), [note(123, EDIT, body)], LATER, source_key="k")


@pytest.mark.parametrize("evidence,cited", [
    ("the report's OLD keys remain untrusted", True),
    ("The operator reported a plausible compromise", False),
    ("keys", False),
])
def test_only_cited_notes_add_citations_and_date_the_story(store, evidence, cited):
    store.ingest(note_item(), LATER)
    finish_reviewed(store, store.pending(1, LATER)[0], analysis(evidence=[evidence]), "note", LATER)
    story = store.stories()[0]
    assert len(story["sources"]) == (2 if cited else 1) and story["updated_at"] == (EDIT if cited else DATE)
    assert story["published_at"] == DATE and story["added_at"] == LATER
    assert json.loads(store.db.execute("SELECT payload FROM items").fetchone()[0])["updated_at"] == DATE


def test_a_quote_cites_only_its_earliest_note_and_cumulative_updates_keep_citations(tmp_path):
    notes = [note(3, LATER, "> The report’s old keys remain untrusted. Agreed."),
             note(2, LATER, "+1, the operator reported a plausible compromise."),
             note(1, EDIT, "The report’s old keys remain untrusted.")]
    with Store(tmp_path / "quote.db") as store:
        store.ingest(_compose(item(url=URL), notes, LATER, source_key="k"), LATER)
        finish_reviewed(store, store.pending(1, LATER)[0],
                        analysis(evidence=["The report’s old keys remain untrusted", "the operator reported a plausible compromise"]),
                        "replies", LATER)
        story = store.stories()[0]
        assert [s["url"] for s in story["sources"]] == [URL, URL + "#note_1"] and story["updated_at"] == EDIT

    with Store(tmp_path / "cum.db") as store:
        incoming = note_item()
        store.ingest(incoming, EDIT)
        finish_reviewed(store, store.pending(1, EDIT)[0], analysis(evidence=["The report’s old keys remain untrusted"]), "first", EDIT)
        first = copy.deepcopy(store.stories()[0])
        assert first["updated_at"] == EDIT and len(first["sources"]) == 2
        later_note = note(456, LATER, "Maintainers merged the key-removal patch.")
        assert store.ingest(_compose(incoming, [*incoming["public_comments"], later_note], LATER, source_key="k"), LATER)
        finish_reviewed(store, store.pending(1, LATER)[0],
                        update_analysis(update="Maintainers merged the key-removal patch.", state="merged",
                                        evidence=["Maintainers merged the key-removal patch."]), "followup", LATER)
        current = store.stories()[0]
        assert current["updated_at"] == LATER and (current["added_at"], current["published_at"]) == (first["added_at"], first["published_at"])
        assert [s["url"] for s in current["sources"]] == [URL, URL + "#note_123", URL + "#note_456"]
        assert current["updates"] == [{"at": LATER, "text": "Maintainers merged the key-removal patch.",
                                       "sources": [{"url": URL + "#note_456", "title": later_note["title"]}]}]
        later2 = "2026-11-11T12:00:00Z"
        updated_body = _compose(item(url=URL, content=incoming["content"] + " Upstream closed the tracking issue.", updated_at=later2),
                                [], later2, source_key="k")
        assert store.ingest(updated_body, later2)
        finish_reviewed(store, store.pending(1, later2)[0],
                        update_analysis(update="Upstream closed the tracking issue.", state="resolved",
                                        evidence=["Upstream closed the tracking issue."]), "closed", later2)
        final = store.stories()[0]
        assert [s["url"] for s in final["sources"]] == [URL, URL + "#note_123", URL + "#note_456"] and final["updated_at"] == later2
