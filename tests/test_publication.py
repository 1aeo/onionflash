"""Permanent artifacts, bounded publication work and restart-safe indexes."""

import copy
import json
from pathlib import Path
import shutil
import xml.etree.ElementTree as ET

import pytest

from helpers import STORY, make_story as story, pub_meta as meta, pub_settings as settings, put_story as put, upgrade_template as upgrade
from onionflash import editorial, publication, render
from onionflash.cli import build
from onionflash.store import Store, backup_database


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
        for number in range(101):
            put(store.db, story(number, tags=["release", "security"] if number == 0 else ["release"]))
        assert build(cfg, store)["articles_pending"] == 76
        for _ in range(4):
            build(cfg, store)
        assert store.db.execute("SELECT COUNT(*) FROM public_catalog").fetchone()[0] == 101
        assert store.db.execute("SELECT COUNT(*) FROM public_render_queue").fetchone()[0] == 0
        assert (output / "news" / story(0)["id"] / "index.html").is_file()
        assert (output / "news" / story(100)["id"] / "story.json").is_file()
        guids = lambda path: [g.text for g in ET.parse(output / path).iter("guid")]
        assert len(guids("feed.xml")) == len(guids("tags/release.xml")) == 101
        assert [i["id"] for i in json.loads((output / "feed.json").read_text())["items"]] == guids("feed.xml")
        last = f"https://example.org/onionflash/news/{story(0)['id']}/"
        assert guids("feed.xml")[-1] == last and guids("tags/security.xml") == [last]
        assert (output / "page/11/index.html").is_file() and (output / "topics/release/page/11/index.html").is_file()
        assert store.db.execute("SELECT COUNT(*) FROM public_story_topics WHERE topic='release'").fetchone()[0] == 101
        statements = []
        store.db.set_trace_callback(statements.append)
        for order in ({"topic": "release"}, {}, {"order": "updated_at"}):
            assert len(list(publication._accepted(store.db, batch_size=17, **order))) == 101
        store.db.set_trace_callback(None)
        plans = [row[3] for sql in set(statements) for row in store.db.execute("EXPLAIN QUERY PLAN " + sql)]
        assert plans and not [plan for plan in plans if "TEMP B-TREE" in plan]
        page1, page11 = (output / "index.html").read_text(), (output / "page/11/index.html").read_text()
        assert page1.count('class="story"') == 10 and page11.count('class="story"') == 1
        assert 'href="https://example.org/onionflash/page/2/" rel="next"' in page1
        assert 'href="https://example.org/onionflash/page/10/" rel="prev"' in page11
        assert 'href="https://example.org/onionflash/page/11/"' in page11
        assert "101 stories in the complete history" in page1
        store.db.execute("DELETE FROM stories WHERE id=?", (story(0)["id"],))
        store.db.commit()
        build(cfg, store)
        assert (output / "news" / story(0)["id"] / "index.html").is_file() and len(guids("feed.xml")) == 101


def test_feed_ordering_homepage_added_dates_and_pagination_cleanup(tmp_path, monkeypatch):
    cfg = settings(tmp_path)
    output = Path(cfg["storage"]["output_dir"])
    with Store(cfg["storage"]["database"]) as store:
        for n in range(3):
            put(store.db, story(n, tags=render.CATEGORIES, published_at="2026-01-01T00:00:00Z",
                                updated_at=f"2026-11-0{3 - n}T00:00:00Z"))
        build(cfg, store)
    newest = [f"https://example.org/onionflash/news/{story(n)['id']}/" for n in (0, 1, 2)]
    for path in ["feed.xml", *(f"tags/{t}.xml" for t in render.CATEGORIES)]:
        assert [g.text for g in ET.parse(output / path).iter("guid")] == newest, path
    assert [i["id"] for i in json.loads((output / "feed.json").read_text())["items"]] == newest

    cfg2 = settings(tmp_path / "added")
    cfg2["site"]["page_size"] = 1
    out2 = Path(cfg2["storage"]["output_dir"])
    with Store(cfg2["storage"]["database"]) as store:
        added = story(1, published_at="2025-01-01T00:00:00Z", added_at="2026-11-10T12:00:00Z")
        updated = story(2, updated_at="2026-11-10T00:00:00Z")
        put(store.db, added); put(store.db, updated)
        build(cfg2, store)
        first = (out2 / "index.html").read_text()
        assert f'id="story-{added["id"]}"' in first and 'datetime="2026-11-10T12:00:00Z"' in first
        assert f'id="story-{updated["id"]}"' in (out2 / "page/2/index.html").read_text()
        assert json.loads((out2 / "feed.json").read_text())["items"][0]["id"].endswith(updated["id"] + "/")
        rss_story = next(i for i in ET.parse(out2 / "feed.xml").findall("./channel/item") if i.findtext("guid").endswith(added["id"] + "/"))
        assert rss_story.findtext("pubDate") == "Wed, 01 Jan 2025 00:00:00 GMT"

        put(store.db, story(3))
        build(cfg2, store)
        assert (out2 / "page/3/index.html").is_file() and (out2 / "topics/release/page/3/index.html").is_file()
        cfg2["site"]["page_size"] = 3
        assert build(cfg2, store)["public_changed"]
        assert not (out2 / "page/2/index.html").exists() and not (out2 / "topics/release/page/2/index.html").exists()
        assert store.db.execute("SELECT COUNT(*) FROM public_artifacts WHERE path LIKE '%page/%'").fetchone()[0] == 0
        assert (out2 / "topics/release/index.html").read_text().count('class="story"') == 3
        assert len(list((out2 / "news").glob("*/index.html"))) == 3


def test_archive_stability_failed_build_cleanup_and_health_caching(tmp_path, monkeypatch):
    cfg = settings(tmp_path / "arch")
    cfg["site"]["page_size"] = 1
    out = Path(cfg["storage"]["output_dir"])
    with Store(cfg["storage"]["database"]) as store:
        for n in range(3):
            put(store.db, story(n, added_at=f"2026-11-0{n + 1}T00:00:00Z"))
        build(cfg, store)
        archive = [out / "page/2/index.html", out / "topics/release/page/3/index.html"]
        before = [p.read_bytes() for p in archive]
        put(store.db, story(2, added_at="2026-11-03T00:00:00Z", summary="Updated summary.", updated_at="2026-11-10T00:00:00Z"))
        assert build(cfg, store)["public_changed"]
        assert "Updated summary." in (out / "index.html").read_text() and [p.read_bytes() for p in archive] == before

        put(store.db, story(9, added_at="2026-11-09T00:00:00Z"))
        with monkeypatch.context() as scoped:
            scoped.setattr(render, "json_feed_header", lambda *a: (_ for _ in ()).throw(RuntimeError("interrupted")))
            with pytest.raises(RuntimeError, match="interrupted"):
                build(cfg, store)
        cfg["site"]["page_size"] = 2
        assert build(cfg, store)["public_changed"]
        assert not (out / "page/3/index.html").exists() and not (out / "topics/release/page/3/index.html").exists()

    cfg_h = settings(tmp_path / "health")
    monkeypatch.setattr(publication, "now_iso", lambda: "2026-11-08T12:00:00Z")
    cfg_h["sources"] = [{"id": "source", "name": "Source", "url": "https://example.org/feed", "enabled": True, "interval_seconds": 300}]
    with Store(cfg_h["storage"]["database"]) as store:
        put(store.db, story(1)); put(store.db, story(2))
        src = cfg_h["sources"][0]
        store.source(src)
        store.source_success(src, {"url": src["url"]}, "2026-11-08T12:00:00Z")
        build(cfg_h, store)
        outh = Path(cfg_h["storage"]["output_dir"])
        paths = [outh / f"news/{story(1)['id']}/index.html", outh / "feed.xml", outh / "feed.json"]
        mtimes = [p.stat().st_mtime_ns for p in paths]
        before_home = (outh / "index.html").read_bytes()
        gen = meta(store.db, "publication_generation")
        monkeypatch.setattr(render, "article_html", lambda *a: pytest.fail("Unchanged article was regenerated"))
        assert not build(cfg_h, store)["public_changed"]
        store.source_success(src, {"url": src["url"]}, "2026-11-08T12:01:00Z")
        monkeypatch.setattr(publication, "now_iso", lambda: "2026-11-08T12:01:00Z")
        assert not build(cfg_h, store)["public_changed"] and meta(store.db, "publication_generation") == gen
        assert before_home == (outh / "index.html").read_bytes() and "Last success" not in (outh / "index.html").read_text()
        monkeypatch.setattr(publication, "now_iso", lambda: "2026-11-09T12:00:00Z")
        assert build(cfg_h, store)["public_changed"] and before_home != (outh / "index.html").read_bytes()
        assert mtimes == [p.stat().st_mtime_ns for p in paths]


def test_public_fields_quarantine_recovery_and_snapshot_reuse(tmp_path, monkeypatch):
    cfg = settings(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        value = story(1, editorial_kind="private-origin", evidence=["private evidence"], secret="private-secret")
        put(store.db, value); build(cfg, store)
        store.db.execute("UPDATE public_artifacts SET uploaded_sha256=sha256"); store.db.commit()
        rel = f"news/{value['id']}/story.json"
        previous = store.db.execute("SELECT sha256 FROM public_artifacts WHERE path=?", (rel,)).fetchone()[0]
        put(store.db, {**value, "summary": "Changed summary."}); build(cfg, store)
        updated = store.db.execute("SELECT sha256,uploaded_sha256 FROM public_artifacts WHERE path=?", (rel,)).fetchone()
        assert updated[0] != previous and updated[1] == previous
        text = (Path(cfg["storage"]["output_dir"]) / rel).read_text()
        assert all(v not in text for v in ("private-origin", "private evidence", "private-secret", "editorial_kind"))

        art_path = Path(cfg["storage"]["output_dir"]) / f"news/{value['id']}/index.html"
        before = art_path.read_bytes()
        put(store.db, {**value, "sources": [{"url": "http://127.0.0.1/", "title": "bad"}]})
        assert build(cfg, store)["stories_skipped"] == 1 and art_path.read_bytes() == before
        assert len(ET.parse(Path(cfg["storage"]["output_dir"]) / "feed.xml").findall("./channel/item")) == 1
        put(store.db, {**value, "summary": "Repaired source record."})
        assert build(cfg, store)["stories_skipped"] == 0 and "Repaired source record." in art_path.read_text()

        put(store.db, story(2))
        build(cfg, store)
        calls, prepare = [], render.prepare_story
        monkeypatch.setattr(render, "prepare_story", lambda *a, **kw: calls.append(1) or prepare(*a, **kw))
        put(store.db, story(3))
        build(cfg, store)
        assert len(calls) == 1


def test_older_release_snapshots_skip_invalid_views_while_preserving_articles(tmp_path, monkeypatch):
    cfg = settings(tmp_path / "snap")
    output = Path(cfg["storage"]["output_dir"])
    plain = {"url": "http://example.org/report", "title": "Report"}
    with Store(cfg["storage"]["database"]) as store:
        put(store.db, story(1))
        with monkeypatch.context() as older:
            older.setattr(render, "_public_url", lambda url: url)
            put(store.db, story(2, sources=[plain]))
            put(store.db, story(3, sources=[plain, *STORY["sources"]]))
            build(cfg, store)
        upgrade(store.db)
        put(store.db, story(3, sources=[{"url": "https://127.0.0.1/", "title": "Invalid"}]))
        put(store.db, story(4))
        assert build(cfg, store)["stories_skipped"] == 2
        home = (output / "index.html").read_text()
        assert all(story(n)["id"] in home for n in (1, 3, 4)) and story(2)["id"] not in home
        feed = (output / "feed.xml").read_text()
        assert len(ET.fromstring(feed).findall("./channel/item")) == 3
        assert plain["url"] not in feed and plain["url"] not in (output / f"news/{story(3)['id']}/story.json").read_text()
        assert (output / f"news/{story(2)['id']}/index.html").is_file()


def test_interruption_killed_build_and_staging_safety(tmp_path, monkeypatch):
    cfg = settings(tmp_path / "intr")
    with Store(cfg["storage"]["database"]) as store:
        put(store.db, story(1)); build(cfg, store)
        first_gen = int(meta(store.db, "publication_generation"))
        put(store.db, story(2))
        with monkeypatch.context() as scoped:
            scoped.setattr(render, "json_feed_header", lambda *a: (_ for _ in ()).throw(RuntimeError("simulated interruption")))
            with pytest.raises(RuntimeError, match="interruption"):
                build(cfg, store)
        assert meta(store.db, "publication_build_pending") == "1" and int(meta(store.db, "publication_generation")) == first_gen
        assert build(cfg, store)["public_changed"]
        assert meta(store.db, "publication_build_pending") == "0" and int(meta(store.db, "publication_generation")) == first_gen + 1
        assert len(ET.parse(Path(cfg["storage"]["output_dir"]) / "feed.xml").findall("./channel/item")) == 2

        put(store.db, story(3))
        with monkeypatch.context() as killed:
            killed.setattr(Path, "unlink", lambda *a, **kw: None)
            killed.setattr(render, "json_feed_header", lambda *a: (_ for _ in ()).throw(RuntimeError("killed")))
            with pytest.raises(RuntimeError, match="killed"):
                build(cfg, store)
        build(cfg, store)
    public = Path(cfg["storage"]["output_dir"])
    assert not list(public.rglob(".*")) and not list(public.rglob("tmp*"))
    assert not any((tmp_path / "intr/.public.onionflash-staging").iterdir())

    cfg_perm = settings(tmp_path / "perm")
    staging = tmp_path / "perm/.public.onionflash-staging"
    staging.mkdir(parents=True)
    staging.chmod(0o777)
    with Store(cfg_perm["storage"]["database"]) as store:
        put(store.db, story(1))
        with pytest.raises(ValueError, match="Unsafe public staging directory"):
            build(cfg_perm, store)

    cfg_keep = settings(tmp_path / "keep")
    keep_stage = tmp_path / "keep/.public.onionflash-staging"
    keep_stage.mkdir(parents=True)
    (keep_stage / "data.sqlite3").write_text("unrelated")
    with Store(cfg_keep["storage"]["database"]) as store:
        put(store.db, story(1)); build(cfg_keep, store)
    assert (keep_stage / "data.sqlite3").read_text() == "unrelated"


def test_backlog_priority_resume_and_deleted_source_rows(tmp_path):
    cfg = settings(tmp_path / "res", render_batch_size=2)
    with Store(cfg["storage"]["database"]) as store:
        for n in range(5):
            put(store.db, story(n))
        assert build(cfg, store)["articles_pending"] == 3
    with Store(cfg["storage"]["database"]) as store:
        assert build(cfg, store)["articles_pending"] == 1
        assert "articles_pending" not in build(cfg, store)

    cfg_p = settings(tmp_path / "prio", render_batch_size=2)
    output = Path(cfg_p["storage"]["output_dir"])
    stamp = "2026-11-10T00:00:00Z"
    published = lambda n: json.loads((output / f"news/{story(n)['id']}/story.json").read_text())
    with Store(cfg_p["storage"]["database"]) as store:
        reviewed = lambda n: {"reason": "Reviewed the sources.", "observed": stamp,
                              "expect_hash": editorial.show(store.db, story(n)["id"])["hash"]}
        for n in range(8):
            put(store.db, story(n))
        for _ in range(4):
            build(cfg_p, store)
        editorial.correct(store.db, story(7)["id"], {"summary": "Corrected summary."}, **reviewed(7))
        build(cfg_p, store)
        put(store.db, story(9)); upgrade(store.db); build(cfg_p, store)
        assert published(9)["title"] == "News 9"
        put(store.db, story(10)); put(store.db, story(6, summary="Updated summary."))
        build(cfg_p, store)
        assert published(10)["title"] == "News 10" and published(6)["summary"] == "Updated summary."
        editorial.retract(store.db, story(5)["id"], **reviewed(5))
        editorial.unlock(store.db, story(7)["id"], **reviewed(7))
        assert build(cfg_p, store)["articles_pending"] == 4
        assert published(5)["title"] == "Retracted story" and published(7)["editorial"]["revision"] == 2

    cfg_del = settings(tmp_path / "del", render_batch_size=1)
    with Store(cfg_del["storage"]["database"]) as store:
        for n in range(3):
            put(store.db, story(n))
        for _ in range(3):
            build(cfg_del, store)
        upgrade(store.db); build(cfg_del, store)
        put(store.db, story(9, sources=[{"url": "https://127.0.0.1/", "title": "Invalid"}]))
        assert build(cfg_del, store)["stories_skipped"] == 1
        store.db.execute("DELETE FROM stories WHERE id IN (?,?)", (story(2)["id"], story(9)["id"])); store.db.commit()
        for _ in range(3):
            result = build(cfg_del, store)
        assert "articles_pending" not in result and result["stories_skipped"] == 0
        assert not store.db.execute("SELECT 1 FROM public_catalog WHERE template_hash<>?",
                                    (meta(store.db, "publication_template"),)).fetchone()


@pytest.mark.parametrize("case,message", [
    ("article-file", "regular file"), ("article-dir", "real directory"),
    ("output", "must not be a symlink"), ("owner", "ownership marker"), ("staging", "staging directory"),
])
def test_symlinked_output_paths_are_refused(tmp_path, case, message):
    cfg = settings(tmp_path)
    output, outside = Path(cfg["storage"]["output_dir"]), tmp_path / "outside"
    outside.mkdir()
    unrelated = tmp_path / "keep.txt"; unrelated.write_text("untouched")
    with Store(cfg["storage"]["database"]) as store:
        value = story(1); put(store.db, value)
        if case == "article-file":
            build(cfg, store)
            p = output / f"news/{value['id']}/index.html"
            p.unlink(); p.symlink_to(unrelated)
            put(store.db, {**value, "summary": "Changed story."})
        elif case == "article-dir":
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
    assert unrelated.read_text() == "untouched" and not any(outside.iterdir())


def test_empty_db_guard_queue_dedup_db_restore_and_template_dependencies(tmp_path, monkeypatch):
    cfg = settings(tmp_path / "guard")
    with Store(cfg["storage"]["database"]) as store:
        publication.initialize(store.db)
        value = story(1)
        put(store.db, value)
        put(store.db, {**value, "summary": "Latest queued revision."})
        assert store.db.execute("SELECT COUNT(*) FROM public_render_queue").fetchone()[0] == 1
        build(cfg, store)
        assert "Latest queued revision." in (Path(cfg["storage"]["output_dir"]) / f"news/{value['id']}/index.html").read_text()
    before = (Path(cfg["storage"]["output_dir"]) / "index.html").read_bytes()
    cfg["storage"]["database"] = str(tmp_path / "guard/empty.sqlite3")
    with Store(cfg["storage"]["database"]) as store, pytest.raises(ValueError, match="empty catalog"):
        build(cfg, store)
    assert (Path(cfg["storage"]["output_dir"]) / "index.html").read_bytes() == before

    cfg_r = settings(tmp_path / "rest", render_batch_size=2)
    with Store(cfg_r["storage"]["database"]) as store:
        for n in range(5):
            put(store.db, story(n))
        for _ in range(3):
            build(cfg_r, store)
        put(store.db, story(1, sources=[{"url": "https://127.0.0.1/", "title": "invalid"}]))
        build(cfg_r, store)
        store.db.execute("DELETE FROM stories WHERE id=?", (story(0)["id"],)); store.db.commit()
        backup_database(cfg_r["storage"]["database"], tmp_path / "rest/restore.sqlite3")
    restored = copy.deepcopy(cfg_r)
    restored["storage"].update(database=str(tmp_path / "rest/restore.sqlite3"), output_dir=str(tmp_path / "rest/restored-public"))
    monkeypatch.setattr("onionflash.analyze.Analyzer.analyze", lambda *a: pytest.fail("Restore must not call an LLM"))
    with Store(restored["storage"]["database"]) as store:
        first = build(restored, store, force=True)
        assert first["articles_pending"] == 3 and first["stories_skipped"] == 1
        assert build(restored, store, force=True)["articles_pending"] == 1
        final = build(restored, store, force=True)
        assert "articles_pending" not in final and final["stories_skipped"] == 1
        out = Path(restored["storage"]["output_dir"])
        assert len(list((out / "news").glob("*/index.html"))) == 5
        assert len(list((out / "news").glob("*/story.json"))) == 5
        assert len(ET.parse(out / "feed.xml").findall("./channel/item")) == 5
        assert "127.0.0.1" not in (out / f"news/{story(1)['id']}/story.json").read_text()

    package = shutil.copytree(Path(publication.__file__).parent, tmp_path / "package")
    monkeypatch.setattr(publication, "__file__", str(package / "publication.py"))
    seen = {publication.template_identity({})}
    for name in ("render.py", "publication.py", "editorial.py", "schema.py", "util.py"):
        (package / name).write_text("changed")
        seen.add(publication.template_identity({}))
    assert len(seen) == 6
