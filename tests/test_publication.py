"""Permanent artifacts, bounded publication work and restart-safe indexes."""

import copy
import json
import shutil
from pathlib import Path
import xml.etree.ElementTree as ET

import pytest

from onionflash import editorial, publication, render
from onionflash.cli import build
from onionflash.config import DEFAULTS
from onionflash.store import Store, backup_database
from test_render import STORY


def settings(tmp_path, **storage):
    cfg = copy.deepcopy(DEFAULTS)
    cfg["storage"].update(database=str(tmp_path / "db.sqlite3"), output_dir=str(tmp_path / "public"), **storage)
    cfg["site"]["base_url"] = "https://example.org/onionflash/"
    cfg["sources"] = []
    return cfg


def story(number, **changes):
    return {**copy.deepcopy(STORY), "id": f"{number:024x}", "title": f"News {number}", **changes}


def put(db, value):
    db.execute("""INSERT INTO stories(id,cluster_key,payload,published_at,updated_at)
        VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,
        published_at=excluded.published_at,updated_at=excluded.updated_at""",
        (value["id"], "test:" + value["id"], json.dumps(value), value["published_at"], value["updated_at"]))
    db.commit()


def meta(db, key):
    return db.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()[0]


def upgrade(db):
    """As after an upgrade: an older release rendered the catalog, so the next build rebuilds it."""
    db.execute("UPDATE public_catalog SET template_hash='old-template'")
    db.execute("UPDATE metadata SET value='old-template' WHERE key='publication_template'")
    db.commit()


@pytest.mark.parametrize("trigger", ["upgrade", "missing-output", "force"])
def test_full_rebuild_is_bounded_and_rewrites_feeds_once(tmp_path, monkeypatch, trigger):
    cfg = settings(tmp_path, render_batch_size=5)
    output = Path(cfg["storage"]["output_dir"])
    with Store(cfg["storage"]["database"]) as store:
        for number in range(5):
            put(store.db, story(number))
        build(cfg, store)
        cfg["storage"]["render_batch_size"] = 2
        if trigger == "upgrade":
            upgrade(store.db)
        elif trigger == "missing-output":
            shutil.rmtree(output)
        calls, feeds = [], publication._feeds
        monkeypatch.setattr(publication, "_feeds", lambda *args: calls.append(1) or feeds(*args))
        pending = [build(cfg, store, force=trigger == "force").get("articles_pending") for _ in range(3)]
        assert pending == [3, 1, None] and len(calls) == 1
        assert len(list((output / "news").glob("*/index.html"))) == 5


def test_history_beyond_one_catalog_batch_is_permanent_and_feeds_carry_every_story(tmp_path):
    cfg = settings(tmp_path, render_batch_size=25)
    cfg["site"]["page_size"] = 10
    output = Path(cfg["storage"]["output_dir"])
    with Store(cfg["storage"]["database"]) as store:
        for number in range(101):  # equal dates, so the story_id tie-break sorts story(0) last everywhere
            put(store.db, story(number, tags=["release", "security"] if number == 0 else ["release"]))
        first = build(cfg, store)
        assert first["articles_pending"] == 76
        for _ in range(4):
            build(cfg, store)
        assert store.db.execute("SELECT COUNT(*) FROM public_catalog").fetchone()[0] == 101
        assert store.db.execute("SELECT COUNT(*) FROM public_render_queue").fetchone()[0] == 0
        assert (output / "news" / story(0)["id"] / "index.html").is_file()
        assert (output / "news" / story(100)["id"] / "story.json").is_file()
        def guids(path):
            return [guid.text for guid in ET.parse(output / path).iter("guid")]
        assert len(guids("feed.xml")) == len(guids("tags/release.xml")) == 101
        assert [item["id"] for item in json.loads((output / "feed.json").read_text())["items"]] == guids("feed.xml")
        last = f"https://example.org/onionflash/news/{story(0)['id']}/"
        assert guids("feed.xml")[-1] == last and guids("tags/security.xml") == [last]
        assert (output / "page/11/index.html").is_file()
        assert (output / "topics/release/page/11/index.html").is_file()
        assert store.db.execute("SELECT COUNT(*) FROM public_story_topics WHERE topic='release'").fetchone()[0] == 101
        # Each catalog walk follows an index instead of sorting the history in a temporary table.
        statements = []
        store.db.set_trace_callback(statements.append)
        for order in ({"topic": "release"}, {}, {"order": "updated_at"}):
            assert len(list(publication._accepted(store.db, batch_size=17, **order))) == 101
        store.db.set_trace_callback(None)
        plans = [row[3] for sql in set(statements) for row in store.db.execute("EXPLAIN QUERY PLAN " + sql)]
        assert plans and not [plan for plan in plans if "TEMP B-TREE" in plan]
        page1 = (output / "index.html").read_text()
        page11 = (output / "page/11/index.html").read_text()
        assert page1.count('class="story"') == 10
        assert page11.count('class="story"') == 1
        assert 'href="https://example.org/onionflash/page/2/" rel="next"' in page1
        assert 'href="https://example.org/onionflash/page/10/" rel="prev"' in page11
        assert 'href="https://example.org/onionflash/page/11/"' in page11
        assert "101 stories in the complete history" in page1
        # A missing private source row never expires its already published URL.
        store.db.execute("DELETE FROM stories WHERE id=?", (story(0)["id"],)); store.db.commit()
        build(cfg, store)
        assert (output / "news" / story(0)["id"] / "index.html").is_file()
        assert len(guids("feed.xml")) == 101


def test_every_feed_lists_all_its_stories_most_recently_updated_first(tmp_path):
    cfg = settings(tmp_path)
    output = Path(cfg["storage"]["output_dir"])
    with Store(cfg["storage"]["database"]) as store:
        for number in range(3):  # story(0) was updated last; publication dates precede every update
            put(store.db, story(number, tags=render.CATEGORIES, published_at="2026-01-01T00:00:00Z",
                                updated_at=f"2026-11-0{3 - number}T00:00:00Z"))
        build(cfg, store)
    newest = [f"https://example.org/onionflash/news/{story(number)['id']}/" for number in (0, 1, 2)]
    for path in ["feed.xml", *(f"tags/{topic}.xml" for topic in render.CATEGORIES)]:
        assert [guid.text for guid in ET.parse(output / path).iter("guid")] == newest, path
    assert [item["id"] for item in json.loads((output / "feed.json").read_text())["items"]] == newest


def test_homepage_follows_added_dates_while_feeds_follow_updates_and_keep_source_dates(tmp_path):
    cfg = settings(tmp_path)
    cfg["site"]["page_size"] = 1
    with Store(cfg["storage"]["database"]) as store:
        added = story(1, published_at="2025-01-01T00:00:00Z", added_at="2026-11-10T12:00:00Z")
        updated = story(2, updated_at="2026-11-10T00:00:00Z")
        put(store.db, added); put(store.db, updated)
        build(cfg, store)
        output = Path(cfg["storage"]["output_dir"])
        first = (output / "index.html").read_text()
        assert f'id="story-{added["id"]}"' in first and 'datetime="2026-11-10T12:00:00Z"' in first
        assert f'id="story-{updated["id"]}"' in (output / "page/2/index.html").read_text()
        assert json.loads((output / "feed.json").read_text())["items"][0]["id"].endswith(updated["id"] + "/")
        items = ET.parse(output / "feed.xml").findall("./channel/item")
        rss_story = next(item for item in items if item.findtext("guid").endswith(added["id"] + "/"))
        assert rss_story.findtext("pubDate") == "Wed, 01 Jan 2025 00:00:00 GMT"


def test_page_size_changes_remove_only_obsolete_pagination_artifacts(tmp_path):
    cfg = settings(tmp_path)
    cfg["site"]["page_size"] = 1
    with Store(cfg["storage"]["database"]) as store:
        for number in range(3): put(store.db, story(number))
        build(cfg, store)
        output = Path(cfg["storage"]["output_dir"])
        assert (output / "page/3/index.html").is_file() and (output / "topics/release/page/3/index.html").is_file()
        cfg["site"]["page_size"] = 3
        assert build(cfg, store)["public_changed"]
        assert not (output / "page/2/index.html").exists() and not (output / "topics/release/page/2/index.html").exists()
        assert store.db.execute("SELECT COUNT(*) FROM public_artifacts WHERE path LIKE '%page/%'").fetchone()[0] == 0
        assert (output / "topics/release/index.html").read_text().count('class="story"') == 3
        assert len(list((output / "news").glob('*/index.html'))) == 3


def test_updating_a_story_leaves_archive_pages_without_it_unchanged(tmp_path):
    cfg = settings(tmp_path)
    cfg["site"]["page_size"] = 1
    output = Path(cfg["storage"]["output_dir"])
    with Store(cfg["storage"]["database"]) as store:
        for number in range(3):
            put(store.db, story(number, added_at=f"2026-11-0{number + 1}T00:00:00Z"))
        build(cfg, store)
        archive = [output / "page/2/index.html", output / "topics/release/page/3/index.html"]
        before = [path.read_bytes() for path in archive]
        put(store.db, story(2, added_at="2026-11-03T00:00:00Z", summary="Updated summary.", updated_at="2026-11-10T00:00:00Z"))
        assert build(cfg, store)["public_changed"]
        assert "Updated summary." in (output / "index.html").read_text()
        assert [path.read_bytes() for path in archive] == before


def test_pages_rewritten_by_a_failed_build_are_still_removed_when_obsolete(tmp_path, monkeypatch):
    cfg = settings(tmp_path)
    cfg["site"]["page_size"] = 1
    output = Path(cfg["storage"]["output_dir"])
    with Store(cfg["storage"]["database"]) as store:
        for number in range(3): put(store.db, story(number, added_at=f"2026-11-0{number + 1}T00:00:00Z"))
        build(cfg, store)
        # The failed build shifts every page on disk, then rolls back their ledger rows.
        put(store.db, story(9, added_at="2026-11-09T00:00:00Z"))
        with monkeypatch.context() as scoped:
            scoped.setattr(render, "json_feed_header", lambda *args: (_ for _ in ()).throw(RuntimeError("interrupted")))
            with pytest.raises(RuntimeError, match="interrupted"):
                build(cfg, store)
        cfg["site"]["page_size"] = 2
        assert build(cfg, store)["public_changed"]
        assert not (output / "page/3/index.html").exists()
        assert not (output / "topics/release/page/3/index.html").exists()


def test_no_article_rewrite_on_replay_or_health_update(tmp_path, monkeypatch):
    cfg = settings(tmp_path)
    monkeypatch.setattr(publication, "now_iso", lambda: "2026-11-08T12:00:00Z")
    cfg["sources"] = [{"id": "source", "name": "Source", "url": "https://example.org/feed", "enabled": True, "interval_seconds": 300}]
    with Store(cfg["storage"]["database"]) as store:
        put(store.db, story(1)); put(store.db, story(2))
        source = cfg["sources"][0]
        store.source(source)
        store.source_success(source, {"url": source["url"]}, "2026-11-08T12:00:00Z")
        build(cfg, store)
        output = Path(cfg["storage"]["output_dir"])
        paths = [output / f"news/{story(1)['id']}/index.html", output / "feed.xml", output / "feed.json"]
        mtimes = [p.stat().st_mtime_ns for p in paths]
        before = (output / "index.html").read_bytes()
        generation = meta(store.db, "publication_generation")
        monkeypatch.setattr(render, "article_html", lambda *args: pytest.fail("Unchanged article was regenerated"))
        assert not build(cfg, store)["public_changed"]
        store.source_success(source, {"url": source["url"]}, "2026-11-08T12:01:00Z")
        monkeypatch.setattr(publication, "now_iso", lambda: "2026-11-08T12:01:00Z")
        assert not build(cfg, store)["public_changed"]
        assert meta(store.db, "publication_generation") == generation
        assert before == (output / "index.html").read_bytes()
        assert "Last success" not in (output / "index.html").read_text()
        monkeypatch.setattr(publication, "now_iso", lambda: "2026-11-09T12:00:00Z")
        assert build(cfg, store)["public_changed"]
        assert before != (output / "index.html").read_bytes()
        assert mtimes == [p.stat().st_mtime_ns for p in paths]


def test_uploaded_hash_survives_update_and_json_contains_only_public_fields(tmp_path):
    cfg = settings(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        value = story(1, editorial_kind="private-origin", evidence=["private evidence"], secret="private-secret")
        put(store.db, value); build(cfg, store)
        store.db.execute("UPDATE public_artifacts SET uploaded_sha256=sha256"); store.db.commit()
        path = f"news/{value['id']}/story.json"
        previous = store.db.execute("SELECT sha256 FROM public_artifacts WHERE path=?", (path,)).fetchone()[0]
        put(store.db, {**value, "summary": "Changed summary."}); build(cfg, store)
        updated = store.db.execute("SELECT sha256,uploaded_sha256 FROM public_artifacts WHERE path=?", (path,)).fetchone()
        assert updated[0] != previous and updated[1] == previous
        text = (Path(cfg["storage"]["output_dir"]) / path).read_text()
        assert all(value not in text for value in ["private-origin", "private evidence", "private-secret", "editorial_kind"])


def test_invalid_revision_keeps_last_good_publication_and_can_recover(tmp_path):
    cfg = settings(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        value = story(1); put(store.db, value); build(cfg, store)
        output = Path(cfg["storage"]["output_dir"])
        path = output / f"news/{value['id']}/index.html"
        before = path.read_bytes()
        put(store.db, {**value, "sources": [{"url": "http://127.0.0.1/", "title": "bad"}]})
        result = build(cfg, store)
        assert result["stories_skipped"] == 1
        assert path.read_bytes() == before
        assert len(ET.parse(output / "feed.xml").findall("./channel/item")) == 1
        put(store.db, {**value, "summary": "Repaired source record."})
        result = build(cfg, store)
        assert result["stories_skipped"] == 0
        assert "Repaired source record." in path.read_text()


def test_views_reuse_accepted_snapshots_instead_of_preparing_each_story_again(tmp_path, monkeypatch):
    cfg = settings(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        for number in range(3):
            put(store.db, story(number))
        build(cfg, store)
        calls, prepare = [], render._prepare_story
        monkeypatch.setattr(render, "_prepare_story", lambda *args, **kwargs: calls.append(1) or prepare(*args, **kwargs))
        put(store.db, story(3))
        build(cfg, store)
        assert len(calls) == 1  # the new story; the listings and feeds reuse the catalog


def test_a_snapshot_an_older_release_accepted_and_this_one_rejects_cannot_stop_builds(tmp_path, monkeypatch):
    cfg = settings(tmp_path)
    output = Path(cfg["storage"]["output_dir"])
    plain = {"url": "http://example.org/report", "title": "Report"}
    with Store(cfg["storage"]["database"]) as store:
        put(store.db, story(1))
        with monkeypatch.context() as older:  # an older release accepted plain-HTTP sources
            older.setattr(render, "_public_url", lambda url: url)
            put(store.db, story(2, sources=[plain]))
            put(store.db, story(3, sources=[plain, *STORY["sources"]]))
            build(cfg, store)
        upgrade(store.db)  # this release rebuilds
        put(store.db, story(3, sources=[{"url": "https://127.0.0.1/", "title": "Invalid"}]))
        put(store.db, story(4))
        assert build(cfg, store)["stories_skipped"] == 2
        home = (output / "index.html").read_text()
        assert all(story(n)["id"] in home for n in (1, 3, 4)) and story(2)["id"] not in home
        feed = (output / "feed.xml").read_text()
        assert len(ET.fromstring(feed).findall("./channel/item")) == 3
        # The quarantined story is restored from its snapshot under this release's rules.
        assert plain["url"] not in feed and plain["url"] not in (output / f"news/{story(3)['id']}/story.json").read_text()
        assert (output / f"news/{story(2)['id']}/index.html").is_file()


def test_topic_backfill_after_an_upgrade_skips_a_snapshot_this_release_rejects(tmp_path, monkeypatch):
    cfg = settings(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        put(store.db, story(1))
        with monkeypatch.context() as older:  # an older release accepted plain-HTTP sources
            older.setattr(render, "_public_url", lambda url: url)
            put(store.db, story(2, sources=[{"url": "http://example.org/report", "title": "Report"}]))
            build(cfg, store)
        upgrade(store.db)  # this release rebuilds
        with store.db:  # as after an upgrade from a release without topic tables
            store.db.execute("DELETE FROM public_story_topics")
            store.db.execute("DELETE FROM metadata WHERE key='publication_topics'")
        build(cfg, store)
        assert meta(store.db, "publication_topics") == "1"
        topics = {row[0] for row in store.db.execute("SELECT DISTINCT story_id FROM public_story_topics")}
        assert topics == {story(1)["id"]}


def test_interrupted_index_work_resumes_and_generation_advances_once(tmp_path, monkeypatch):
    cfg = settings(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        put(store.db, story(1)); build(cfg, store)
        first_generation = int(meta(store.db, "publication_generation"))
        put(store.db, story(2))
        with monkeypatch.context() as scoped:
            scoped.setattr(render, "json_feed_header", lambda *args: (_ for _ in ()).throw(RuntimeError("simulated interruption")))
            with pytest.raises(RuntimeError, match="interruption"):
                build(cfg, store)
        assert meta(store.db, "publication_build_pending") == "1"
        assert int(meta(store.db, "publication_generation")) == first_generation
        assert build(cfg, store)["public_changed"]
        assert meta(store.db, "publication_build_pending") == "0"
        assert int(meta(store.db, "publication_generation")) == first_generation + 1
        assert len(ET.parse(Path(cfg["storage"]["output_dir"]) / "feed.xml").findall("./channel/item")) == 2


def test_a_killed_build_leaves_no_temporary_files_in_the_public_tree(tmp_path, monkeypatch):
    cfg = settings(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        put(store.db, story(1)); build(cfg, store)
        put(store.db, story(2))
        with monkeypatch.context() as killed:  # A killed process runs no cleanup.
            killed.setattr(Path, "unlink", lambda *args, **kwargs: None)
            killed.setattr(render, "json_feed_header", lambda *args: (_ for _ in ()).throw(RuntimeError("killed")))
            with pytest.raises(RuntimeError, match="killed"):
                build(cfg, store)
        build(cfg, store)
    public = Path(cfg["storage"]["output_dir"])
    assert not list(public.rglob(".*")) and not list(public.rglob("tmp*"))
    assert not any((tmp_path / ".public.onionflash-staging").iterdir())


def test_a_staging_directory_others_can_write_is_refused(tmp_path):
    cfg = settings(tmp_path)
    staging = tmp_path / ".public.onionflash-staging"
    staging.mkdir()
    staging.chmod(0o777)
    with Store(cfg["storage"]["database"]) as store:
        put(store.db, story(1))
        with pytest.raises(ValueError, match="Unsafe public staging directory"):
            build(cfg, store)


def test_the_staging_directory_keeps_files_it_did_not_create(tmp_path):
    cfg = settings(tmp_path)
    staging = tmp_path / ".public.onionflash-staging"
    staging.mkdir()
    (staging / "data.sqlite3").write_text("unrelated")
    with Store(cfg["storage"]["database"]) as store:
        put(store.db, story(1)); build(cfg, store)
    assert (staging / "data.sqlite3").read_text() == "unrelated"


def test_template_rebuild_is_bounded_and_resumes_across_connections(tmp_path):
    cfg = settings(tmp_path, render_batch_size=2)
    with Store(cfg["storage"]["database"]) as store:
        for number in range(5): put(store.db, story(number))
        assert build(cfg, store)["articles_pending"] == 3
    with Store(cfg["storage"]["database"]) as store:
        assert build(cfg, store)["articles_pending"] == 1
        assert "articles_pending" not in build(cfg, store)


def test_new_stories_and_editorial_actions_render_before_a_rebuild_backlog(tmp_path):
    cfg = settings(tmp_path, render_batch_size=2)
    output = Path(cfg["storage"]["output_dir"])
    stamp = "2026-11-10T00:00:00Z"
    def published(number):
        return json.loads((output / f"news/{story(number)['id']}/story.json").read_text())
    with Store(cfg["storage"]["database"]) as store:
        def reviewed(number):
            return {"reason": "Reviewed the sources.", "observed": stamp,
                    "expect_hash": editorial.show(store.db, story(number)["id"])["hash"]}
        for number in range(8):
            put(store.db, story(number))
        for _ in range(4):
            build(cfg, store)
        editorial.correct(store.db, story(7)["id"], {"summary": "Corrected summary."}, **reviewed(7))
        build(cfg, store)
        # A story analysed in the run that starts a rebuild keeps its place ahead of it.
        put(store.db, story(9))
        upgrade(store.db)
        build(cfg, store)
        assert published(9)["title"] == "News 9"
        put(store.db, story(10)); put(store.db, story(6, summary="Updated summary."))
        build(cfg, store)
        assert published(10)["title"] == "News 10" and published(6)["summary"] == "Updated summary."
        editorial.retract(store.db, story(5)["id"], **reviewed(5))
        editorial.unlock(store.db, story(7)["id"], **reviewed(7))  # same time as the correction: only its record changes
        assert build(cfg, store)["articles_pending"] == 4
        assert published(5)["title"] == "Retracted story" and published(7)["editorial"]["revision"] == 2


def test_removing_a_source_row_keeps_its_queued_rebuild_and_clears_its_quarantine(tmp_path):
    cfg = settings(tmp_path, render_batch_size=1)
    with Store(cfg["storage"]["database"]) as store:
        for number in range(3):
            put(store.db, story(number))
        for _ in range(3):
            build(cfg, store)
        upgrade(store.db)
        build(cfg, store)
        put(store.db, story(9, sources=[{"url": "https://127.0.0.1/", "title": "Invalid"}]))
        assert build(cfg, store)["stories_skipped"] == 1
        # One row still waits for the rebuild; the other is quarantined and was never published.
        store.db.execute("DELETE FROM stories WHERE id IN (?,?)", (story(2)["id"], story(9)["id"])); store.db.commit()
        for _ in range(3):
            result = build(cfg, store)
        assert "articles_pending" not in result and result["stories_skipped"] == 0
        assert not store.db.execute("SELECT 1 FROM public_catalog WHERE template_hash<>?", (meta(store.db, "publication_template"),)).fetchone()


def test_article_symlink_is_never_followed(tmp_path):
    cfg = settings(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        value = story(1); put(store.db, value); build(cfg, store)
        unrelated = tmp_path / "keep.txt"; unrelated.write_text("untouched")
        path = Path(cfg["storage"]["output_dir"]) / f"news/{value['id']}/index.html"
        path.unlink(); path.symlink_to(unrelated)
        put(store.db, {**value, "summary": "Changed story."})
        with pytest.raises(ValueError, match="regular file"):
            build(cfg, store)
        assert unrelated.read_text() == "untouched"


@pytest.mark.parametrize("case,message", [("article", "real directory"), ("output", "must not be a symlink"),
                                          ("owner", "ownership marker"), ("staging", "staging directory")])
def test_symlinked_output_paths_are_refused(tmp_path, case, message):
    cfg = settings(tmp_path)
    output, outside = Path(cfg["storage"]["output_dir"]), tmp_path / "outside"
    outside.mkdir()
    with Store(cfg["storage"]["database"]) as store:
        value = story(1); put(store.db, value)
        if case == "article":
            build(cfg, store)
            shutil.rmtree(output / "news" / value["id"])
            (output / "news" / value["id"]).symlink_to(outside, target_is_directory=True)
            put(store.db, {**value, "summary": "Changed story."})
        elif case == "output":
            output.symlink_to(outside, target_is_directory=True)
        elif case == "owner":
            output.mkdir(); (output / "index.html").write_text("operator page")
            (tmp_path / ".public.onionflash-owner").symlink_to(tmp_path / "db.sqlite3")
        else:
            (tmp_path / ".public.onionflash-staging").symlink_to(outside, target_is_directory=True)
        with pytest.raises(ValueError, match=message):
            build(cfg, store)
    assert not any(outside.iterdir())


def test_a_new_empty_database_cannot_replace_existing_public_history(tmp_path):
    cfg = settings(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        put(store.db, story(1)); build(cfg, store)
    before = (Path(cfg["storage"]["output_dir"]) / "index.html").read_bytes()
    cfg["storage"]["database"] = str(tmp_path / "empty.sqlite3")
    with Store(cfg["storage"]["database"]) as store:
        with pytest.raises(ValueError, match="empty catalog"):
            build(cfg, store)
    assert (Path(cfg["storage"]["output_dir"]) / "index.html").read_bytes() == before


def test_story_upsert_replaces_an_already_pending_queue_entry(tmp_path):
    cfg = settings(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        publication.initialize(store.db)
        value = story(1)
        put(store.db, value)
        put(store.db, {**value, "summary": "Latest queued revision."})
        assert store.db.execute("SELECT COUNT(*) FROM public_render_queue").fetchone()[0] == 1
        build(cfg, store)
        page = Path(cfg["storage"]["output_dir"]) / f"news/{value['id']}/index.html"
        assert "Latest queued revision." in page.read_text()


def test_db_only_restore_rebuilds_all_history_and_last_good_quarantined_story(tmp_path, monkeypatch):
    cfg = settings(tmp_path, render_batch_size=2)
    with Store(cfg["storage"]["database"]) as store:
        for number in range(5): put(store.db, story(number))
        for _ in range(3): build(cfg, store)
        put(store.db, story(1, sources=[{"url": "https://127.0.0.1/", "title": "invalid"}]))
        build(cfg, store)
        store.db.execute("DELETE FROM stories WHERE id=?", (story(0)["id"],)); store.db.commit()
        backup_database(cfg["storage"]["database"], tmp_path / "restore.sqlite3")
    restored = copy.deepcopy(cfg)
    restored["storage"].update(database=str(tmp_path / "restore.sqlite3"), output_dir=str(tmp_path / "restored-public"))
    monkeypatch.setattr("onionflash.analyze.Analyzer.analyze", lambda *args: pytest.fail("Restore must not call an LLM"))
    with Store(restored["storage"]["database"]) as store:
        first = build(restored, store, force=True)
        assert first["articles_pending"] == 3 and first["stories_skipped"] == 1
        assert build(restored, store, force=True)["articles_pending"] == 1
        final = build(restored, store, force=True)
        assert "articles_pending" not in final and final["stories_skipped"] == 1
        output = Path(restored["storage"]["output_dir"])
        assert len(list((output / "news").glob('*/index.html'))) == 5
        assert len(list((output / "news").glob('*/story.json'))) == 5
        assert len(ET.parse(output / "feed.xml").findall("./channel/item")) == 5
        assert "127.0.0.1" not in (output / f"news/{story(1)['id']}/story.json").read_text()
