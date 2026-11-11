"""Permanent topic views and a safe, resumable retirement of browser JavaScript."""

import hashlib
import re
from pathlib import Path

import pytest

from onionflash import publication, render
from onionflash.cli import build
from onionflash.store import Store
from test_publication import meta, put, settings, story, upgrade


def ids(path):
    return re.findall(r'id="story-([a-z0-9]+)"', path.read_text())


def legacy_script(store, output, contents=b"old browser script"):
    (output / "app.js").write_bytes(contents)
    store.db.execute("""INSERT INTO public_artifacts(path,sha256,size,content_type,updated_at)
        VALUES('app.js',?,?, 'text/javascript', '2026-11-08T00:00:00Z')""",
                     (hashlib.sha256(contents).hexdigest(), len(contents)))
    store.db.execute("DELETE FROM metadata WHERE key='publication_no_browser_js_ready'")
    store.db.commit()


def test_topics_include_category_or_tag_without_duplicates_and_follow_added_date(tmp_path):
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
        assert ids(output / "topics/security/index.html") == [values[0]["id"]]
        assert ids(output / "topics/security/page/2/index.html") == [values[1]["id"]]
        assert not (output / "topics/security/page/3/index.html").exists()
        assert ids(output / "topics/release/index.html") == [values[0]["id"]]
        assert ids(output / "topics/feature/index.html") == []
        assert 'href="https://example.org/onionflash/topics/security/page/2/" rel="next"' in (output / "topics/security/index.html").read_text()
        assert 'href="https://example.org/onionflash/tags/security.xml"' in (output / "topics/security/index.html").read_text()
        assert store.db.execute("SELECT COUNT(*) FROM public_story_topics WHERE topic='security'").fetchone()[0] == 2


def test_recategorization_updates_only_affected_topics_and_removes_stale_views(tmp_path, monkeypatch):
    cfg = settings(tmp_path)
    cfg["site"]["page_size"] = 1
    with Store(cfg["storage"]["database"]) as store:
        for number in range(3):
            put(store.db, story(number))
        build(cfg, store)
        output = Path(cfg["storage"]["output_dir"])
        unrelated = output / "topics/network/index.html"
        previous = unrelated.stat().st_mtime_ns
        calls, original = [], render.index_html
        def counted(*args, **kwargs):
            calls.append(kwargs.get("topic"))
            return original(*args, **kwargs)
        monkeypatch.setattr(render, "index_html", counted)
        put(store.db, story(0, category="security", tags=[]))
        build(cfg, store)
        assert not (output / "topics/release/page/3/index.html").exists()
        assert store.db.execute("SELECT 1 FROM public_artifacts WHERE path='topics/release/page/3/index.html'").fetchone() is None
        assert ids(output / "topics/security/index.html") == [story(0)["id"]]
        assert (output / f"news/{story(0)['id']}/index.html").is_file()
        assert unrelated.stat().st_mtime_ns == previous
        calls.clear()
        assert not build(cfg, store)["public_changed"]
        assert calls == [None]


def test_migration_keeps_script_until_all_accepted_articles_are_rebuilt(tmp_path):
    cfg = settings(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        for number in range(5):
            put(store.db, story(number))
        build(cfg, store)
        output = Path(cfg["storage"]["output_dir"])
        accepted = dict(store.db.execute("SELECT story_id,json_sha256 FROM public_catalog"))
        legacy_script(store, output)
        store.db.execute("UPDATE public_catalog SET template_hash='old-template'")
        store.db.execute("UPDATE metadata SET value='old-template' WHERE key='publication_template'")
        store.db.execute("DELETE FROM public_story_topics")
        store.db.execute("DELETE FROM metadata WHERE key='publication_topics'")
        store.db.commit()
        cfg["storage"]["render_batch_size"] = 2
        first = build(cfg, store)
        assert first["articles_pending"] == 3 and not first["no_browser_js_ready"]
        assert meta(store.db, "publication_no_browser_js_ready") == "0"
        assert (output / "app.js").exists()
        assert len(ids(output / "topics/release/index.html")) == 5
        assert not build(cfg, store)["no_browser_js_ready"]
        assert (output / "app.js").exists()
        final = build(cfg, store)
        assert final["no_browser_js_ready"] and "articles_pending" not in final
        assert meta(store.db, "publication_no_browser_js_ready") == "1"
        assert not (output / "app.js").exists()
        assert store.db.execute("SELECT 1 FROM public_artifacts WHERE path='app.js'").fetchone() is None
        assert dict(store.db.execute("SELECT story_id,json_sha256 FROM public_catalog")) == accepted
        assert all("<script" not in path.read_text() for path in output.glob("news/*/index.html"))
        assert not build(cfg, store)["public_changed"]


@pytest.mark.parametrize("change", ["symlink", "modified", "untracked", "directory"])
def test_legacy_script_removal_refuses_unowned_or_unsafe_paths(tmp_path, change):
    cfg = settings(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        put(store.db, story(1)); build(cfg, store)
        output = Path(cfg["storage"]["output_dir"])
        legacy_script(store, output)
        path = output / "app.js"
        if change == "symlink":
            target = tmp_path / "unrelated"; target.write_text("keep")
            path.unlink(); path.symlink_to(target)
        elif change == "modified":
            path.write_text("keep modified")
        elif change == "untracked":
            store.db.execute("DELETE FROM public_artifacts WHERE path='app.js'"); store.db.commit()
        else:
            path.unlink(); path.mkdir(); (path / "keep").write_text("keep")
        with pytest.raises(ValueError, match="artifact|untracked"):
            build(cfg, store)
        assert meta(store.db, "publication_no_browser_js_ready") == "0"
        assert path.exists()
        if change == "symlink":
            assert target.read_text() == "keep"


def test_missing_legacy_script_cleans_ledger_and_orphan_article_blocks_transition(tmp_path):
    cfg = settings(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        put(store.db, story(1)); build(cfg, store)
        output = Path(cfg["storage"]["output_dir"])
        legacy_script(store, output)
        (output / "app.js").unlink()
        orphan = output / "news/orphan/index.html"
        orphan.parent.mkdir(); orphan.write_text("Keep this published article")
        with pytest.raises(ValueError, match="Unverified existing article"):
            build(cfg, store)
        assert meta(store.db, "publication_no_browser_js_ready") == "0"
        assert store.db.execute("SELECT 1 FROM public_artifacts WHERE path='app.js'").fetchone()
        assert orphan.read_text() == "Keep this published article"
        orphan.unlink()  # Explicit test fixture repair, never performed by the builder.
        assert build(cfg, store)["no_browser_js_ready"]
        assert store.db.execute("SELECT 1 FROM public_artifacts WHERE path='app.js'").fetchone() is None


def test_template_rebuild_does_not_revoke_completed_migration(tmp_path):
    cfg = settings(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        for number in range(3):
            put(store.db, story(number))
        build(cfg, store)
        cfg["storage"]["render_batch_size"] = 1
        upgrade(store.db)
        result = build(cfg, store)
        assert result["articles_pending"] == 2 and result["no_browser_js_ready"]
        build(cfg, store); build(cfg, store)
        assert not build(cfg, store)["public_changed"]


def test_remote_only_orphan_artifact_blocks_retirement_until_story_is_restored(tmp_path):
    cfg = settings(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        put(store.db, story(1)); build(cfg, store)
        output = Path(cfg["storage"]["output_dir"])
        original = (output / f"news/{story(1)['id']}/story.json").read_bytes()
        legacy_script(store, output)
        path = f"news/{story(2)['id']}/index.html"
        store.db.execute("""INSERT INTO public_artifacts(path,sha256,size,content_type,updated_at)
            VALUES(?, ?, 100, 'text/html', '2026-11-08T00:00:00Z')""", (path, "a" * 64))
        store.db.commit()
        assert not (output / path).exists()
        with pytest.raises(ValueError, match="Unverified article artifact"):
            build(cfg, store)
        assert (output / "app.js").exists()
        assert meta(store.db, "publication_no_browser_js_ready") == "0"
        assert store.db.execute("SELECT sha256 FROM public_artifacts WHERE path=?", (path,)).fetchone()[0] == "a" * 64
        put(store.db, story(2))
        assert build(cfg, store)["no_browser_js_ready"]
        assert (output / path).is_file()
        assert (output / f"news/{story(1)['id']}/story.json").read_bytes() == original
        assert not (output / "app.js").exists()


def test_corrupt_catalog_after_first_batch_repairs_before_topic_backfill(tmp_path):
    cfg = settings(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        for number in range(5):
            put(store.db, story(number))
        build(cfg, store)
        output = Path(cfg["storage"]["output_dir"])
        originals = {path.relative_to(output): path.read_bytes() for path in output.glob("news/*/story.json")}
        legacy_script(store, output)
        store.db.execute("UPDATE public_catalog SET template_hash='old-template'")
        store.db.execute("UPDATE public_catalog SET public_json='broken catalog JSON' WHERE story_id=?", (story(4)["id"],))
        store.db.execute("UPDATE metadata SET value='old-template' WHERE key='publication_template'")
        store.db.execute("DELETE FROM public_story_topics")
        store.db.execute("DELETE FROM metadata WHERE key='publication_topics'")
        store.db.commit()
        cfg["storage"]["render_batch_size"] = 1
        for remaining in (4, 3, 2, 1):
            with pytest.raises(ValueError, match="Accepted public story snapshot"):
                build(cfg, store, force=True)
            assert store.db.execute("SELECT COUNT(*) FROM public_render_queue WHERE last_error IS NULL").fetchone()[0] == remaining
            assert meta(store.db, "publication_build_pending") == "1"
            assert meta(store.db, "publication_no_browser_js_ready") == "0"
            assert (output / "app.js").exists()
            assert all((output / path).read_bytes() == contents for path, contents in originals.items())
        result = build(cfg, store, force=True)
        assert result["no_browser_js_ready"] and "articles_pending" not in result
        assert meta(store.db, "publication_build_pending") == "0"
        assert len(ids(output / "topics/release/index.html")) == 5
        assert all((output / path).read_bytes() == contents for path, contents in originals.items())
        assert not build(cfg, store)["public_changed"]


def test_quarantined_latest_revision_rebuilds_last_good_article_before_retirement(tmp_path):
    cfg = settings(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        put(store.db, story(1)); build(cfg, store)
        output = Path(cfg["storage"]["output_dir"])
        snapshot = (output / f"news/{story(1)['id']}/story.json").read_bytes()
        legacy_script(store, output)
        store.db.execute("UPDATE public_catalog SET template_hash='old-template'")
        store.db.execute("UPDATE metadata SET value='old-template' WHERE key='publication_template'")
        store.db.commit()
        put(store.db, story(1, sources=[{"url": "https://127.0.0.1/private", "title": "Invalid"}]))
        result = build(cfg, store)
        assert result["stories_skipped"] == 1 and result["no_browser_js_ready"]
        assert not (output / "app.js").exists()
        assert (output / f"news/{story(1)['id']}/story.json").read_bytes() == snapshot
        assert "127.0.0.1" not in (output / f"news/{story(1)['id']}/index.html").read_text()


def test_artifact_allowlist_accepts_only_real_topics_and_rejects_browser_script(tmp_path):
    for path in ("topics/security/index.html", "topics/directory-authority/page/20/index.html"):
        assert publication._PATH.fullmatch(path)
    for path in ("app.js", "topics/unknown/index.html", "topics/../index.html", "topics/security/page/0/index.html"):
        assert not publication._PATH.fullmatch(path)
