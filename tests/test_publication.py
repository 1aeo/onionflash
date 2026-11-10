"""Permanent artifacts, bounded publication work and restart-safe indexes."""

import copy
import json
import shutil
from pathlib import Path
import xml.etree.ElementTree as ET

import pytest

from onionflash import publication, render
from onionflash.cli import build
from onionflash.config import DEFAULTS, load_config
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


def test_resuming_forced_rebuild_does_not_rewrite_all_feeds_each_batch(tmp_path, monkeypatch):
    cfg = settings(tmp_path, render_batch_size=5)
    with Store(cfg["storage"]["database"]) as store:
        for number in range(5):
            put(store.db, story(number))
        build(cfg, store)
        cfg["storage"]["render_batch_size"] = 2
        calls = []
        original = publication._feeds
        def counted(*args):
            calls.append(1)
            return original(*args)
        monkeypatch.setattr(publication, "_feeds", counted)
        assert build(cfg, store, force=True)["articles_pending"] == 3
        assert build(cfg, store, force=True)["articles_pending"] == 1
        assert "articles_pending" not in build(cfg, store, force=True)
        assert len(calls) == 1


def test_more_than_1000_stories_are_permanent_and_all_feeds_are_complete(tmp_path):
    cfg = settings(tmp_path, max_stories=1, render_batch_size=250)
    cfg["site"]["page_size"] = 100
    output = Path(cfg["storage"]["output_dir"])
    with Store(cfg["storage"]["database"]) as store:
        for number in range(1001):
            put(store.db, story(number))
        first = build(cfg, store)
        assert first["articles_pending"] == 751
        for _ in range(4):
            build(cfg, store)
        assert store.db.execute("SELECT COUNT(*) FROM public_catalog").fetchone()[0] == 1001
        assert store.db.execute("SELECT COUNT(*) FROM public_render_queue").fetchone()[0] == 0
        assert (output / "news" / story(0)["id"] / "index.html").is_file()
        assert (output / "news" / story(1000)["id"] / "story.json").is_file()
        assert len(ET.parse(output / "feed.xml").findall("./channel/item")) == 1001
        assert len(json.loads((output / "feed.json").read_text())["items"]) == 1001
        assert len(ET.parse(output / "tags/release.xml").findall("./channel/item")) == 1001
        assert (output / "page/11/index.html").is_file()
        assert (output / "topics/release/page/11/index.html").is_file()
        assert store.db.execute("SELECT COUNT(*) FROM public_story_topics WHERE topic='release'").fetchone()[0] == 1001
        assert len(list(publication._accepted(store.db, topic="release", batch_size=17))) == 1001
        plan = " ".join(row[3] for row in store.db.execute("""EXPLAIN QUERY PLAN
            SELECT c.public_json FROM public_story_topics t JOIN public_catalog c ON c.story_id=t.story_id
            WHERE t.topic='release' AND (t.added_at,t.updated_at,t.story_id)<('9999','9999','z')
            ORDER BY t.added_at DESC,t.updated_at DESC,t.story_id DESC LIMIT 17"""))
        assert "public_story_topics_added" in plan and "TEMP B-TREE" not in plan
        page1 = (output / "index.html").read_text()
        page11 = (output / "page/11/index.html").read_text()
        assert page1.count('class="story"') == 100
        assert page11.count('class="story"') == 1
        assert 'href="https://example.org/onionflash/page/2/" rel="next"' in page1
        assert 'href="https://example.org/onionflash/page/10/" rel="prev"' in page11
        assert 'href="https://example.org/onionflash/page/11/"' in page11
        assert "1001 stories in the complete history" in page1
        # A missing private source row never expires its already published URL.
        store.db.execute("DELETE FROM stories WHERE id=?", (story(0)["id"],)); store.db.commit()
        build(cfg, store)
        assert (output / "news" / story(0)["id"] / "index.html").is_file()
        assert len(ET.parse(output / "feed.xml").findall("./channel/item")) == 1001


def test_newest_publications_page_first_while_feed_updates_are_independent(tmp_path):
    cfg = settings(tmp_path)
    cfg["site"]["page_size"] = 1
    with Store(cfg["storage"]["database"]) as store:
        older = story(1, published_at="2025-01-01T00:00:00Z", updated_at="2026-11-10T00:00:00Z")
        newer = story(2)
        put(store.db, older); put(store.db, newer)
        build(cfg, store)
        root = Path(cfg["storage"]["output_dir"])
        assert (root / "_headers").read_text() == render.headers_text(cfg["site"]["base_url"])
        assert f'id="story-{newer["id"]}"' in (root / "index.html").read_text()
        assert f'id="story-{older["id"]}"' in (root / "page/2/index.html").read_text()
        feed = json.loads((root / "feed.json").read_text())
        assert feed["items"][0]["id"].endswith(older["id"] + "/")


def test_homepage_pages_follow_added_at_but_rss_keeps_source_dates(tmp_path):
    cfg = settings(tmp_path)
    cfg["site"]["page_size"] = 1
    with Store(cfg["storage"]["database"]) as store:
        recently_added = story(1, published_at="2025-01-01T00:00:00Z", added_at="2026-11-10T12:00:00Z")
        earlier_added = story(2, added_at="2026-11-09T12:00:00Z")
        put(store.db, recently_added); put(store.db, earlier_added)
        build(cfg, store)
        output = Path(cfg["storage"]["output_dir"])
        first = (output / "index.html").read_text()
        second = (output / "page/2/index.html").read_text()
        assert f'id="story-{recently_added["id"]}"' in first
        assert 'datetime="2026-11-10T12:00:00Z"' in first
        assert f'id="story-{earlier_added["id"]}"' in second
        items = ET.parse(output / "feed.xml").findall("./channel/item")
        rss_story = next(item for item in items if item.findtext("guid").endswith(recently_added["id"] + "/"))
        assert rss_story.findtext("pubDate") == "Wed, 01 Jan 2025 00:00:00 GMT"


def test_page_size_changes_remove_only_obsolete_pagination_artifacts(tmp_path):
    cfg = settings(tmp_path)
    cfg["site"]["page_size"] = 1
    with Store(cfg["storage"]["database"]) as store:
        for number in range(3): put(store.db, story(number))
        build(cfg, store)
        output = Path(cfg["storage"]["output_dir"])
        assert (output / "page/3/index.html").is_file()
        cfg["site"]["page_size"] = 3
        assert build(cfg, store)["public_changed"]
        assert not (output / "page/3/index.html").exists()
        assert store.db.execute("SELECT COUNT(*) FROM public_artifacts WHERE path LIKE 'page/%'").fetchone()[0] == 0
        assert len(list((output / "news").glob('*/index.html'))) == 3


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


def test_template_rebuild_is_bounded_and_resumes_across_connections(tmp_path, monkeypatch):
    cfg = settings(tmp_path, render_batch_size=2)
    with Store(cfg["storage"]["database"]) as store:
        for number in range(5): put(store.db, story(number))
        assert build(cfg, store)["articles_pending"] == 3
    with Store(cfg["storage"]["database"]) as store:
        assert build(cfg, store)["articles_pending"] == 1
        assert "articles_pending" not in build(cfg, store)
        monkeypatch.setattr(publication, "publication_year", lambda: 2030)
        assert build(cfg, store)["articles_pending"] == 3
        assert build(cfg, store)["articles_pending"] == 1
        assert "articles_pending" not in build(cfg, store)


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


def test_missing_output_directory_automatically_queues_bounded_recovery(tmp_path):
    cfg = settings(tmp_path, render_batch_size=2)
    with Store(cfg["storage"]["database"]) as store:
        for number in range(5): put(store.db, story(number))
        for _ in range(3): build(cfg, store)
        output = Path(cfg["storage"]["output_dir"])
        shutil.rmtree(output)
        assert build(cfg, store)["articles_pending"] == 3
        assert build(cfg, store)["articles_pending"] == 1
        assert "articles_pending" not in build(cfg, store)
        assert len(list((output / "news").glob('*/index.html'))) == 5


@pytest.mark.parametrize("setting", ["render_batch_size = 0", "render_batch_size = 1001", "render_batch_size = true"])
def test_render_batch_bounds_are_validated(tmp_path, monkeypatch, setting):
    monkeypatch.setenv("ONIONFLASH_LLM_BASE_URL", "https://model.example/v1")
    text = (Path(__file__).parents[1] / "config.example.toml").read_text()
    path = tmp_path / "config.toml"
    path.write_text(text.replace("render_batch_size = 250", setting))
    with pytest.raises(ValueError): load_config(path)
