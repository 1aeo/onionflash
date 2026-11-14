"""Permanent topic views, bounded rebuilds and artifact path allowlisting."""

from pathlib import Path
import re

import pytest

from helpers import make_story as story, pub_meta as meta, pub_settings as settings, put_story as put, upgrade_template as upgrade
from onionflash import publication, render
from onionflash.cli import build
from onionflash.store import Store


def ids(path):
    return re.findall(r'id="story-([a-z0-9]+)"', path.read_text())


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
        sec_html = (output / "topics/security/index.html").read_text()
        assert 'href="https://example.org/onionflash/topics/security/page/2/" rel="next"' in sec_html
        assert 'href="https://example.org/onionflash/tags/security.xml"' in sec_html
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
        monkeypatch.setattr(render, "index_html", lambda *a, **kw: (calls.append(kw.get("topic")), original(*a, **kw))[1])
        put(store.db, story(0, category="security", tags=[]))
        build(cfg, store)
        assert not (output / "topics/release/page/3/index.html").exists()
        assert store.db.execute("SELECT 1 FROM public_artifacts WHERE path='topics/release/page/3/index.html'").fetchone() is None
        assert ids(output / "topics/security/index.html") == [story(0)["id"]]
        assert (output / f"news/{story(0)['id']}/index.html").is_file()
        assert unrelated.stat().st_mtime_ns == previous
        calls.clear()
        assert not build(cfg, store)["public_changed"] and calls == [None]


def test_template_rebuild_and_quarantined_revisions_preserve_script_free_articles(tmp_path):
    cfg_t = settings(tmp_path / "tmpl")
    with Store(cfg_t["storage"]["database"]) as store:
        for n in range(3):
            put(store.db, story(n))
        build(cfg_t, store)
        cfg_t["storage"]["render_batch_size"] = 1
        upgrade(store.db)
        res = build(cfg_t, store)
        assert res["articles_pending"] == 2
        build(cfg_t, store)
        final = build(cfg_t, store)
        assert "articles_pending" not in final
        assert all("<script" not in p.read_text() for p in Path(cfg_t["storage"]["output_dir"]).glob("news/*/index.html"))
        assert not build(cfg_t, store)["public_changed"]

    cfg_q = settings(tmp_path / "quar")
    with Store(cfg_q["storage"]["database"]) as store:
        put(store.db, story(1))
        build(cfg_q, store)
        output = Path(cfg_q["storage"]["output_dir"])
        snapshot = (output / f"news/{story(1)['id']}/story.json").read_bytes()
        upgrade(store.db)
        put(store.db, story(1, sources=[{"url": "https://127.0.0.1/private", "title": "Invalid"}]))
        res = build(cfg_q, store)
        assert res["stories_skipped"] == 1
        assert (output / f"news/{story(1)['id']}/story.json").read_bytes() == snapshot
        assert "127.0.0.1" not in (output / f"news/{story(1)['id']}/index.html").read_text()


def test_corrupt_catalog_after_first_batch_and_artifact_allowlist(tmp_path):
    cfg = settings(tmp_path)
    with Store(cfg["storage"]["database"]) as store:
        for n in range(5):
            put(store.db, story(n))
        build(cfg, store)
        output = Path(cfg["storage"]["output_dir"])
        originals = {p.relative_to(output): p.read_bytes() for p in output.glob("news/*/story.json")}
        upgrade(store.db)
        store.db.execute("UPDATE public_catalog SET public_json='broken catalog JSON' WHERE story_id=?", (story(4)["id"],))
        store.db.commit()
        cfg["storage"]["render_batch_size"] = 1
        for remaining in (4, 3, 2, 1):
            with pytest.raises(ValueError, match="Accepted public story snapshot"):
                build(cfg, store, force=True)
            assert store.db.execute("SELECT COUNT(*) FROM public_render_queue WHERE last_error IS NULL").fetchone()[0] == remaining
            assert meta(store.db, "publication_build_pending") == "1"
            assert all((output / p).read_bytes() == c for p, c in originals.items())
        result = build(cfg, store, force=True)
        assert "articles_pending" not in result and meta(store.db, "publication_build_pending") == "0"
        assert len(ids(output / "topics/release/index.html")) == 5
        assert all((output / p).read_bytes() == c for p, c in originals.items())
        assert not build(cfg, store)["public_changed"]

    for valid in ("topics/security/index.html", "topics/directory-authority/page/20/index.html"):
        assert publication.public_path_allowed(valid)
    for invalid in ("app.js", "topics/unknown/index.html", "topics/../index.html", "topics/security/page/0/index.html"):
        assert not publication.public_path_allowed(invalid)
