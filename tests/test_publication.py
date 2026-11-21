"""Permanent artifacts, topic views, bounded publication work, and restart-safe indexes."""

import copy
import json
from pathlib import Path
import re
import shutil
import xml.etree.ElementTree as ET

import pytest

from helpers import STORY, editorial_act, make_story as story, pub_settings as settings, put_story as put, raise_once
from onionflash import editorial, publication, render
from onionflash.cli import build
from onionflash.store import Store, backup_database


def _upgrade(db):
    db.execute("UPDATE public_catalog SET template_hash='old-template'")
    db.execute("UPDATE metadata SET value='old-template' WHERE key='publication_template'")
    db.commit()


def _ids(path):
    return re.findall(r'id="story-([a-z0-9]+)"', path.read_text())


def _interrupt_build(monkeypatch, cfg, store, message="interrupted", *, keep_files=False):
    with monkeypatch.context() as scoped:
        if keep_files:
            scoped.setattr(Path, "unlink", lambda *a, **kw: None)
        scoped.setattr(render, "json_feed_header", raise_once(RuntimeError(message)))
        with pytest.raises(RuntimeError, match=message):
            build(cfg, store)


@pytest.mark.parametrize("trigger", ["upgrade", "missing-output", "force"])
def test_full_rebuild_is_bounded_and_rewrites_feeds_once(tmp_path, monkeypatch, trigger):
    """Render full rebuilds in bounded batches, rewrite feeds once, and keep articles script-free."""
    cfg = settings(tmp_path, render_batch_size=5)
    output = Path(cfg["storage"]["output_dir"])
    with Store(cfg["storage"]["database"]) as store:
        for number in range(5):
            put(store.db, story(number))
        build(cfg, store)
        cfg["storage"]["render_batch_size"] = 2
        if trigger == "upgrade":
            _upgrade(store.db)
        elif trigger == "missing-output":
            shutil.rmtree(output)
        calls, feeds = [], publication._feeds
        monkeypatch.setattr(publication, "_feeds", lambda *args: calls.append(1) or feeds(*args))
        pending = [build(cfg, store, force=trigger == "force").get("articles_pending") for _ in range(3)]
        assert pending == [3, 1, None] and len(calls) == 1
        articles = list((output / "news").glob("*/index.html"))
        assert len(articles) == 5 and all("<script" not in p.read_text() for p in articles)
        assert not build(cfg, store)["public_changed"]


def test_history_beyond_one_catalog_batch_is_permanent_and_feeds_carry_every_story(tmp_path):
    """Keep all 101+ cataloged stories in feeds, topic indexes, and permanent article pages."""
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


def test_feed_ordering_homepage_added_dates_and_pagination_cleanup(tmp_path):
    """Order feeds by `updated_at`, order pages by `added_at`, and prune obsolete pagination files."""
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
        put(store.db, added)
        put(store.db, updated)
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
    """Avoid rewriting unchanged archive pages or regenerating articles during health-only updates."""
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
        _interrupt_build(monkeypatch, cfg, store)
        cfg["site"]["page_size"] = 2
        assert build(cfg, store)["public_changed"]
        assert not (out / "page/3/index.html").exists() and not (out / "topics/release/page/3/index.html").exists()

    cfg_h = settings(tmp_path / "health")
    monkeypatch.setattr(publication, "now_iso", lambda: "2026-11-08T12:00:00Z")
    cfg_h["sources"] = [{"id": "source", "name": "Source", "url": "https://example.org/feed", "enabled": True, "interval_seconds": 300}]
    with Store(cfg_h["storage"]["database"]) as store:
        put(store.db, story(1))
        put(store.db, story(2))
        src = cfg_h["sources"][0]
        store.source(src)
        store.source_success(src, {"url": src["url"]}, "2026-11-08T12:00:00Z")
        build(cfg_h, store)
        outh = Path(cfg_h["storage"]["output_dir"])
        paths = [outh / f"news/{story(1)['id']}/index.html", outh / "feed.xml", outh / "feed.json"]
        mtimes = [p.stat().st_mtime_ns for p in paths]
        before_home = (outh / "index.html").read_bytes()
        gen = store.get_meta("publication_generation")
        monkeypatch.setattr(render, "article_html", lambda *a: pytest.fail("Unchanged article was regenerated"))
        assert not build(cfg_h, store)["public_changed"]
        store.source_success(src, {"url": src["url"]}, "2026-11-08T12:01:00Z")
        monkeypatch.setattr(publication, "now_iso", lambda: "2026-11-08T12:01:00Z")
        assert not build(cfg_h, store)["public_changed"] and store.get_meta("publication_generation") == gen
        assert before_home == (outh / "index.html").read_bytes() and "Last success" not in (outh / "index.html").read_text()
        monkeypatch.setattr(publication, "now_iso", lambda: "2026-11-09T12:00:00Z")
        assert build(cfg_h, store)["public_changed"] and before_home != (outh / "index.html").read_bytes()
        assert mtimes == [p.stat().st_mtime_ns for p in paths]


def test_public_fields_quarantine_recovery_and_snapshot_reuse(tmp_path, monkeypatch):
    """Scrub private fields, preserve prior snapshots across quarantined upgrades, and reuse catalog rows."""
    cfg = settings(tmp_path)
    output = Path(cfg["storage"]["output_dir"])
    with Store(cfg["storage"]["database"]) as store:
        value = story(1, editorial_kind="private-origin", evidence=["private evidence"], secret="private-secret")
        put(store.db, value)
        build(cfg, store)
        store.db.execute("UPDATE public_artifacts SET uploaded_sha256=sha256")
        store.db.commit()
        rel = f"news/{value['id']}/story.json"
        previous = store.db.execute("SELECT sha256 FROM public_artifacts WHERE path=?", (rel,)).fetchone()[0]
        put(store.db, {**value, "summary": "Changed summary."})
        build(cfg, store)
        updated = store.db.execute("SELECT sha256,uploaded_sha256 FROM public_artifacts WHERE path=?", (rel,)).fetchone()
        assert updated[0] != previous and updated[1] == previous
        text = (output / rel).read_text()
        assert all(v not in text for v in ("private-origin", "private evidence", "private-secret", "editorial_kind"))

        art_path = output / f"news/{value['id']}/index.html"
        before, json_before = art_path.read_bytes(), (output / rel).read_bytes()
        _upgrade(store.db)
        put(store.db, {**value, "sources": [{"url": "http://127.0.0.1/", "title": "bad"}]})
        assert build(cfg, store)["stories_skipped"] == 1
        assert art_path.read_bytes() == before and (output / rel).read_bytes() == json_before
        assert "127.0.0.1" not in art_path.read_text()
        assert len(ET.parse(output / "feed.xml").findall("./channel/item")) == 1
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
    """Omit legacy non-HTTPS snapshots from rebuilt views, counts, pagination, and latest timestamps."""
    cfg = settings(tmp_path / "snap")
    cfg["site"]["page_size"] = 3
    output = Path(cfg["storage"]["output_dir"])
    plain = {"url": "http://example.org/report", "title": "Report"}
    with Store(cfg["storage"]["database"]) as store:
        put(store.db, story(1))
        with monkeypatch.context() as older:
            older.setattr(render, "_public_url", lambda url: url)
            put(store.db, story(2, sources=[plain], updated_at="2026-11-12T00:00:00Z"))
            put(store.db, story(3, sources=[plain, *STORY["sources"]]))
            build(cfg, store)
        assert (output / "index.html").is_file()
        _upgrade(store.db)
        put(store.db, story(3, sources=[{"url": "https://127.0.0.1/", "title": "Invalid"}]))
        put(store.db, story(4))
        rebuilt = build(cfg, store)
        assert rebuilt["stories_skipped"] == 2 and rebuilt["published_stories"] == 3
        assert not (output / "page/2/index.html").exists()
        assert not (output / "topics/release/page/2/index.html").exists()
        home = (output / "index.html").read_text()
        topic_page = (output / "topics/release/index.html").read_text()
        assert all(story(n)["id"] in home for n in (1, 3, 4)) and story(2)["id"] not in home
        assert "2026-11-12T00:00:00Z" not in home and "2026-11-08T14:00:00Z" in home
        assert "2026-11-12T00:00:00Z" not in topic_page and "2026-11-08T14:00:00Z" in topic_page
        feed = (output / "feed.xml").read_text()
        assert len(ET.fromstring(feed).findall("./channel/item")) == 3
        assert plain["url"] not in feed and plain["url"] not in (output / f"news/{story(3)['id']}/story.json").read_text()
        assert (output / f"news/{story(2)['id']}/index.html").is_file()


def test_interruption_killed_build_and_staging_safety(tmp_path, monkeypatch):
    """Recover cleanly from interrupted builds, clean staging leftovers, and check directory permissions."""
    cfg = settings(tmp_path / "intr")
    with Store(cfg["storage"]["database"]) as store:
        put(store.db, story(1))
        build(cfg, store)
        first_gen = int(store.get_meta("publication_generation"))
        put(store.db, story(2))
        _interrupt_build(monkeypatch, cfg, store, "simulated interruption")
        assert store.get_meta("publication_build_pending") == "1" and int(store.get_meta("publication_generation")) == first_gen
        assert build(cfg, store)["public_changed"]
        assert store.get_meta("publication_build_pending") == "0" and int(store.get_meta("publication_generation")) == first_gen + 1
        assert len(ET.parse(Path(cfg["storage"]["output_dir"]) / "feed.xml").findall("./channel/item")) == 2

        put(store.db, story(3))
        _interrupt_build(monkeypatch, cfg, store, "killed", keep_files=True)
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
        put(store.db, story(1))
        build(cfg_keep, store)
    assert (keep_stage / "data.sqlite3").read_text() == "unrelated"


def test_backlog_priority_resume_and_deleted_source_rows(tmp_path):
    """Prioritize live edits and retractions ahead of template-upgrade backlogs and clear deleted rows."""
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
        for n in range(8):
            put(store.db, story(n))
        for _ in range(4):
            build(cfg_p, store)
        editorial_act(editorial.correct, store, story(7)["id"], {"summary": "Corrected summary."},
                      reason="Reviewed the sources.", observed=stamp)
        build(cfg_p, store)
        put(store.db, story(9))
        _upgrade(store.db)
        build(cfg_p, store)
        assert published(9)["title"] == "News 9"
        put(store.db, story(10))
        put(store.db, story(6, summary="Updated summary."))
        build(cfg_p, store)
        assert published(10)["title"] == "News 10" and published(6)["summary"] == "Updated summary."
        editorial_act(editorial.retract, store, story(5)["id"], reason="Reviewed the sources.", observed=stamp)
        editorial_act(editorial.unlock, store, story(7)["id"], reason="Reviewed the sources.", observed=stamp)
        assert build(cfg_p, store)["articles_pending"] == 4
        assert published(5)["title"] == "Retracted story" and published(7)["editorial"]["revision"] == 2

    cfg_del = settings(tmp_path / "del", render_batch_size=1)
    with Store(cfg_del["storage"]["database"]) as store:
        for n in range(3):
            put(store.db, story(n))
        for _ in range(3):
            build(cfg_del, store)
        _upgrade(store.db)
        build(cfg_del, store)
        put(store.db, story(9, sources=[{"url": "https://127.0.0.1/", "title": "Invalid"}]))
        assert build(cfg_del, store)["stories_skipped"] == 1
        store.db.execute("DELETE FROM stories WHERE id IN (?,?)", (story(2)["id"], story(9)["id"]))
        store.db.commit()
        for _ in range(3):
            result = build(cfg_del, store)
        assert "articles_pending" not in result and result["stories_skipped"] == 0
        assert not store.db.execute("SELECT 1 FROM public_catalog WHERE template_hash<>?",
                                    (store.get_meta("publication_template"),)).fetchone()


@pytest.mark.parametrize("case,message", [
    ("article-file", "regular file"), ("article-dir", "real directory"),
    ("output", "must not be a symlink"), ("owner", "ownership marker"), ("staging", "staging directory"),
])
def test_symlinked_output_paths_are_refused(tmp_path, case, message):
    """Refuse to write into symlinked output, article, ownership-marker, or staging paths."""
    cfg = settings(tmp_path)
    output, outside = Path(cfg["storage"]["output_dir"]), tmp_path / "outside"
    outside.mkdir()
    unrelated = tmp_path / "keep.txt"
    unrelated.write_text("untouched")
    with Store(cfg["storage"]["database"]) as store:
        value = story(1)
        put(store.db, value)
        if case == "article-file":
            build(cfg, store)
            p = output / f"news/{value['id']}/index.html"
            p.unlink()
            p.symlink_to(unrelated)
            put(store.db, {**value, "summary": "Changed story."})
        elif case == "article-dir":
            build(cfg, store)
            shutil.rmtree(output / "news" / value["id"])
            (output / "news" / value["id"]).symlink_to(outside, target_is_directory=True)
            put(store.db, {**value, "summary": "Changed story."})
        elif case == "output":
            output.symlink_to(outside, target_is_directory=True)
        elif case == "owner":
            output.mkdir()
            (output / "index.html").write_text("operator page")
            (tmp_path / ".public.onionflash-owner").symlink_to(tmp_path / "db.sqlite3")
        else:
            (tmp_path / ".public.onionflash-staging").symlink_to(outside, target_is_directory=True)
        with pytest.raises(ValueError, match=message):
            build(cfg, store)
    assert unrelated.read_text() == "untouched" and not any(outside.iterdir())


def test_empty_db_guard_queue_dedup_db_restore_and_template_dependencies(tmp_path, monkeypatch):
    """Guard against empty-DB overwrites, rebuild from SQLite backups offline, and hash code modules."""
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
        store.db.execute("DELETE FROM stories WHERE id=?", (story(0)["id"],))
        store.db.commit()
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


def test_topics_include_category_or_tag_without_duplicates_and_follow_added_date(tmp_path):
    """Deduplicate category/tag topic memberships and paginate topic views by `added_at`."""
    cfg = settings(tmp_path)
    cfg["site"]["page_size"] = 1
    with Store(cfg["storage"]["database"]) as store:
        values = [story(1, category="release", tags=["security", "release", "security"], added_at="2026-11-10T00:00:00Z"),
                  story(2, category="security", tags=[], added_at="2026-11-09T00:00:00Z"),
                  story(3, category="network", tags=[], added_at="2026-11-08T00:00:00Z")]
        for value in values:
            put(store.db, value)
        build(cfg, store)
        output = Path(cfg["storage"]["output_dir"])
        for topic in render.CATEGORIES:
            assert (output / f"topics/{topic}/index.html").is_file()
        assert _ids(output / "topics/security/index.html") == [values[0]["id"]]
        assert _ids(output / "topics/security/page/2/index.html") == [values[1]["id"]]
        assert not (output / "topics/security/page/3/index.html").exists()
        assert _ids(output / "topics/release/index.html") == [values[0]["id"]]
        assert _ids(output / "topics/feature/index.html") == []
        sec_html = (output / "topics/security/index.html").read_text()
        assert 'href="https://example.org/onionflash/topics/security/page/2/" rel="next"' in sec_html
        assert 'href="https://example.org/onionflash/tags/security.xml"' in sec_html
        assert store.db.execute("SELECT COUNT(*) FROM public_story_topics WHERE topic='security'").fetchone()[0] == 2


def test_recategorization_updates_only_affected_topics_and_removes_stale_views(tmp_path):
    """Regenerate only affected topic views when a story's category/tags change."""
    cfg = settings(tmp_path)
    cfg["site"]["page_size"] = 1
    with Store(cfg["storage"]["database"]) as store:
        for number in range(3):
            put(store.db, story(number))
        build(cfg, store)
        output = Path(cfg["storage"]["output_dir"])
        unrelated = output / "topics/network/index.html"
        previous = unrelated.stat().st_mtime_ns
        put(store.db, story(0, category="security", tags=[]))
        build(cfg, store)
        assert not (output / "topics/release/page/3/index.html").exists()
        assert store.db.execute("SELECT 1 FROM public_artifacts WHERE path='topics/release/page/3/index.html'").fetchone() is None
        assert _ids(output / "topics/security/index.html") == [story(0)["id"]]
        assert (output / f"news/{story(0)['id']}/index.html").is_file()
        assert unrelated.stat().st_mtime_ns == previous
        home = output / "index.html"
        home_before, home_mtime = home.read_bytes(), home.stat().st_mtime_ns
        assert not build(cfg, store)["public_changed"]
        assert home.read_bytes() == home_before
        assert home.stat().st_mtime_ns == home_mtime
        assert unrelated.stat().st_mtime_ns == previous


def test_corrupt_catalog_after_first_batch_and_artifact_allowlist(tmp_path):
    """Preserve output files across corrupt `public_catalog` batches and enforce `public_path_allowed`."""
    cfg = settings(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        for n in range(5):
            put(store.db, story(n))
        build(cfg, store)
        output = Path(cfg["storage"]["output_dir"])
        originals = {p.relative_to(output): p.read_bytes() for p in output.glob("news/*/story.json")}
        _upgrade(store.db)
        store.db.execute("UPDATE public_catalog SET public_json='broken catalog JSON' WHERE story_id=?", (story(4)["id"],))
        store.db.commit()
        cfg["storage"]["render_batch_size"] = 1
        for remaining in (4, 3, 2, 1):
            with pytest.raises(ValueError, match="Accepted public story snapshot"):
                build(cfg, store, force=True)
            assert store.db.execute("SELECT COUNT(*) FROM public_render_queue WHERE last_error IS NULL").fetchone()[0] == remaining
            assert store.get_meta("publication_build_pending") == "1"
            assert all((output / p).read_bytes() == c for p, c in originals.items())
        result = build(cfg, store, force=True)
        assert "articles_pending" not in result and store.get_meta("publication_build_pending") == "0"
        assert len(_ids(output / "topics/release/index.html")) == 5
        assert all((output / p).read_bytes() == c for p, c in originals.items())
        assert not build(cfg, store)["public_changed"]

    for valid in ("topics/security/index.html", "topics/directory-authority/page/20/index.html"):
        assert publication.public_path_allowed(valid)
    for invalid in ("app.js", "topics/unknown/index.html", "topics/../index.html", "topics/security/page/0/index.html"):
        assert not publication.public_path_allowed(invalid)


@pytest.mark.parametrize("mode", ["deleted", "damaged"])
def test_render_accepted_rejects_cross_story_revision_id_mismatch(tmp_path, mode):
    """Quarantine accepted stories whose editorial revision rewrites `id` instead of overwriting peers."""
    cfg = settings(tmp_path)
    output = Path(cfg["storage"]["output_dir"])
    story_a = story(1, id="story-a", title="Story A", tags=["release"])
    story_b = story(2, id="story-b", title="Story B", tags=["security"], category="security")
    with Store(cfg["storage"]["database"]) as store:
        put(store.db, story_a)
        put(store.db, story_b)
        build(cfg, store)
        b_html = (output / "news/story-b/index.html").read_bytes()
        b_json = (output / "news/story-b/story.json").read_bytes()
        b_cat = tuple(store.db.execute("SELECT * FROM public_catalog WHERE story_id='story-b'").fetchone())
        b_topics = store.db.execute("SELECT * FROM public_story_topics WHERE story_id='story-b' ORDER BY topic").fetchall()

        editorial_act(editorial.correct, store, "story-a", {"summary": "Edited summary for story A."},
                      reason="Clarify summary.", observed="2026-11-10T00:00:00Z")
        with store.db:
            store.db.execute("DROP TRIGGER editorial_revisions_unchanged")
            store.db.execute("UPDATE editorial_revisions SET after_public_json=json_set(after_public_json,'$.id','story-b') WHERE story_id='story-a' AND revision=1")
            editorial.initialize(store.db)
            if mode == "deleted":
                store.db.execute("DELETE FROM stories WHERE id='story-a'")
            else:
                store.db.execute("UPDATE stories SET payload='broken json' WHERE id='story-a'")

        result = build(cfg, store)
        assert result["stories_skipped"] == 1
        assert store.db.execute("SELECT last_error FROM public_render_queue WHERE story_id='story-a'").fetchone()[0] == "ValueError"
        assert (output / "news/story-b/index.html").read_bytes() == b_html
        assert (output / "news/story-b/story.json").read_bytes() == b_json
        assert tuple(store.db.execute("SELECT * FROM public_catalog WHERE story_id='story-b'").fetchone()) == b_cat
        assert store.db.execute("SELECT * FROM public_story_topics WHERE story_id='story-b' ORDER BY topic").fetchall() == b_topics


def test_editorial_revision_surrogates_and_invalid_utf8_do_not_crash_build(tmp_path):
    """Sanitize lone surrogates and tolerate invalid UTF-8 in `editorial_revisions` without aborting `build`."""
    cfg = settings(tmp_path)
    output = Path(cfg["storage"]["output_dir"])
    s1 = story(1, id="story-surrogate", title="Original Surrogate Title")
    s2 = story(2, id="story-bad-utf8", title="Original UTF8 Title")
    s3 = story(3, id="story-bad-notice", title="Original Notice Title")
    with Store(cfg["storage"]["database"]) as store:
        for item_story in (s1, s2, s3):
            put(store.db, item_story)
        build(cfg, store)
        for sid in ("story-surrogate", "story-bad-utf8", "story-bad-notice"):
            editorial_act(editorial.correct, store, sid, {"summary": f"Corrected summary for {sid}."},
                          reason="Clarified wording.", observed="2026-11-10T00:00:00Z")
        surrogate_before = '{"title":"Superseded\\ud800Headline","summary":"Superseded\\ud800Summary","why_it_matters":""}'
        with store.db:
            store.db.execute("DROP TRIGGER editorial_revisions_unchanged")
            store.db.execute(
                "UPDATE editorial_revisions SET before_public_json=? WHERE story_id='story-surrogate' AND revision=1",
                (surrogate_before,),
            )
            store.db.execute(
                "UPDATE editorial_revisions SET before_public_json=CAST(x'7b227469746c65223a22fffe227d' AS TEXT) WHERE story_id='story-bad-utf8' AND revision=1"
            )
            store.db.execute(
                "UPDATE editorial_controls SET notice_reason=CAST(x'fffe' AS TEXT) WHERE story_id='story-bad-notice'"
            )
            editorial.initialize(store.db)

        result = build(cfg, store, force=True)
        assert result["stories_skipped"] == 1 and result["published_stories"] == 3
        s1_json = json.loads((output / "news/story-surrogate/story.json").read_text(encoding="utf-8"))
        assert s1_json["editorial"]["history"][0]["superseded"]["title"] == "SupersededHeadline"
        assert "SupersededHeadline" in (output / "news/story-surrogate/index.html").read_text(encoding="utf-8")
        s2_json = json.loads((output / "news/story-bad-utf8/story.json").read_text(encoding="utf-8"))
        assert "superseded" not in s2_json["editorial"]["history"][0]


def test_unreadable_correction_revision_preserves_old_catalog_until_repaired(tmp_path):
    """Quarantine missing-row corrections with unreadable `after_public_json` so forced retries publish once repaired."""
    cfg = settings(tmp_path)
    output = Path(cfg["storage"]["output_dir"])
    orig = story(1, summary="Original summary.")
    sid = orig["id"]
    with Store(cfg["storage"]["database"]) as store:
        put(store.db, orig)
        build(cfg, store)
        before_json = (output / f"news/{sid}/story.json").read_bytes()
        before_cat = tuple(store.db.execute("SELECT * FROM public_catalog WHERE story_id=?", (sid,)).fetchone())

        editorial_act(editorial.correct, store, sid, {"summary": "Corrected summary."},
                      reason="Fix wording.", observed="2026-11-10T00:00:00Z")
        repaired_after = store.db.execute(
            "SELECT after_public_json FROM editorial_revisions WHERE story_id=? AND revision=1", (sid,),
        ).fetchone()[0]
        with store.db:
            store.db.execute("DROP TRIGGER editorial_revisions_unchanged")
            store.db.execute(
                "UPDATE editorial_revisions SET after_public_json='corrupt json' WHERE story_id=? AND revision=1", (sid,),
            )
            editorial.initialize(store.db)
            store.db.execute("DELETE FROM stories WHERE id=?", (sid,))

        failed = build(cfg, store)
        assert failed["stories_skipped"] == 1
        assert (output / f"news/{sid}/story.json").read_bytes() == before_json
        assert tuple(store.db.execute("SELECT * FROM public_catalog WHERE story_id=?", (sid,)).fetchone()) == before_cat

        with store.db:
            store.db.execute("DROP TRIGGER editorial_revisions_unchanged")
            store.db.execute(
                "UPDATE editorial_revisions SET after_public_json=? WHERE story_id=? AND revision=1",
                (repaired_after, sid),
            )
            editorial.initialize(store.db)

        recovered = build(cfg, store, force=True)
        assert recovered["stories_skipped"] == 0
        published = json.loads((output / f"news/{sid}/story.json").read_text(encoding="utf-8"))
        assert published["summary"] == "Corrected summary."
        assert published["editorial"]["revision"] == 1
        assert sid in _ids(output / "topics/release/index.html")


def test_repaired_same_checksum_accepted_story_rebuilds_deleted_topic_memberships(tmp_path):
    """Restore missing `public_story_topics` rows and refresh topic views when a repaired story matches its old checksum."""
    cfg = settings(tmp_path, render_batch_size=1)
    output = Path(cfg["storage"]["output_dir"])
    s2 = story(1, tags=["release"])
    s1 = story(2, tags=["release", "security"])
    with Store(cfg["storage"]["database"]) as store:
        put(store.db, s2)
        put(store.db, s1)
        for _ in range(2):
            build(cfg, store)
        editorial_act(editorial.correct, store, s1["id"], {"summary": "Clarified summary."},
                      reason="Clarify.", observed="2026-11-10T00:00:00Z")
        build(cfg, store)
        assert s1["id"] in _ids(output / "topics/security/index.html")

        with store.db:
            store.db.execute("UPDATE editorial_controls SET notice_reason=CAST(x'fffe' AS TEXT) WHERE story_id=?", (s1["id"],))
        for _ in range(2):
            failed = build(cfg, store, force=True)
        assert failed["stories_skipped"] == 1 and "articles_pending" not in failed
        assert store.db.execute("SELECT COUNT(*) FROM public_story_topics WHERE story_id=?", (s1["id"],)).fetchone()[0] == 0
        assert s1["id"] not in _ids(output / "topics/security/index.html")

        with store.db:
            store.db.execute("UPDATE editorial_controls SET notice_reason='Clarify.' WHERE story_id=?", (s1["id"],))
        rev_before = int(store.get_meta("publication_catalog_revision") or 0)
        batch1 = build(cfg, store, force=True)
        assert batch1["articles_pending"] == 1
        batch2 = build(cfg, store, force=True)
        assert "articles_pending" not in batch2 and batch2["stories_skipped"] == 0
        assert int(store.get_meta("publication_catalog_revision") or 0) == rev_before + 1
        assert store.db.execute("SELECT COUNT(*) FROM public_story_topics WHERE story_id=?", (s1["id"],)).fetchone()[0] == 2
        assert s1["id"] in _ids(output / "topics/release/index.html")
        assert s1["id"] in _ids(output / "topics/security/index.html")

        rev_stable = store.get_meta("publication_catalog_revision")
        assert not build(cfg, store)["public_changed"]
        assert store.get_meta("publication_catalog_revision") == rev_stable


def test_incremental_omission_checks_avoid_full_archive_rescan_across_rebuild_batches(tmp_path, monkeypatch):
    """Cache stale-snapshot omission decisions across rebuild batches while keeping exact counts and pagination."""
    cfg = settings(tmp_path, render_batch_size=2)
    cfg["site"]["page_size"] = 3
    output = Path(cfg["storage"]["output_dir"])
    plain = {"url": "http://example.org/legacy-only", "title": "Legacy HTTP"}
    with Store(cfg["storage"]["database"]) as store:
        for n in range(10):
            if n == 5:
                with monkeypatch.context() as older:
                    older.setattr(render, "_public_url", lambda url: url)
                    put(store.db, story(n, sources=[plain], updated_at="2026-11-12T00:00:00Z"))
                    build(cfg, store)
            else:
                put(store.db, story(n))
        for _ in range(6):
            if "articles_pending" not in build(cfg, store):
                break
        assert store.db.execute("SELECT COUNT(*) FROM public_catalog").fetchone()[0] == 10

        _upgrade(store.db)
        sync_calls = []
        original_public_story = publication._public_story

        def _counting_public_story(row, current=None, *, warn=True):
            if not warn:
                sync_calls.append(row["story_id"])
            return original_public_story(row, current, warn=warn)

        monkeypatch.setattr(publication, "_public_story", _counting_public_story)
        batch_counts = []
        for _ in range(6):
            sync_calls.clear()
            res = build(cfg, store)
            batch_counts.append((len(sync_calls), res["published_stories"], res.get("articles_pending")))
            if "articles_pending" not in res:
                break

        # First batch validates the 8 remaining stale snapshots once; later batches revalidate 0.
        assert batch_counts[0][0] == 8
        assert all(checked == 0 for checked, _, _ in batch_counts[1:])
        assert all(pub == 9 for _, pub, _ in batch_counts)
        assert not (output / "page/4/index.html").exists()
        assert (output / "page/3/index.html").is_file()
        assert "2026-11-12T00:00:00Z" not in (output / "index.html").read_text(encoding="utf-8")
        assert [tuple(r) for r in store.db.execute("SELECT story_id, omitted FROM public_catalog_checks").fetchall()] == [
            (story(5)["id"], 1)
        ]

        # Repairing story 5 invalidates its cached omission row via trigger and restores count to 10.
        put(store.db, story(5))
        final = build(cfg, store)
        assert final["published_stories"] == 10 and final["stories_skipped"] == 0
        assert store.db.execute("SELECT COUNT(*) FROM public_catalog_checks").fetchone()[0] == 0
        assert (output / "page/4/index.html").is_file()
