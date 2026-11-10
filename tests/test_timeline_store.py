"""Repository revisions must preserve story identity and richer reporting."""

import copy

import pytest

from onionflash.render import render_site
from onionflash.store import Store
from test_core import DATE, analysis, item


def timeline(**changes):
    return item(
        kind="metrics_timeline", authority="telemetry", product="network",
        source_entry_id="a" * 64,
        url="https://gitlab.example/repo/-/blob/" + "1" * 40 + "/README.md?plain=1#L10",
        published_at="2026-11-01T00:00:00Z", updated_at="2026-11-08T12:00:00Z",
        **changes,
    )


def finish(store, incoming, result):
    assert store.ingest(incoming, DATE)
    row = dict(store.db.execute("SELECT * FROM items WHERE id=?", (incoming["id"],)).fetchone())
    store.finish(row, result, incoming["id"] + result["summary"], DATE)
    return store.stories(10)[0]


def test_line_moves_do_not_requeue_but_corrections_replace_the_citation(tmp_path):
    with Store(tmp_path / "db") as store:
        original = timeline(content="End date: 2026-11-07. Cause unknown.")
        first = finish(store, original, analysis(summary="The reported range ended November 7."))
        moved = {**original, "url": original["url"].replace("1" * 40, "2" * 40).replace("#L10", "#L20"), "updated_at": "2026-11-09T12:00:00Z"}
        assert not store.ingest(copy.deepcopy(moved), DATE)
        assert store.pending_count() == 0
        corrected = {**moved, "content": "End date: 2026-11-05. Cause unknown."}
        final = finish(store, corrected, analysis(summary="The corrected range ended November 5."))
        assert final["id"] == first["id"]
        assert final["published_at"] == first["published_at"]
        assert final["summary"] == "The corrected range ended November 5."
        assert final["sources"] == [{"id": corrected["id"], "url": corrected["url"], "title": corrected["title"], "published_at": corrected["published_at"]}]
        assert store.db.execute("SELECT COUNT(*) FROM items").fetchone()[0] == 1
        assert store.db.execute("SELECT url FROM items").fetchone()[0] == corrected["url"]
        render_site({"site": {"base_url": "https://example.org/"}}, [final], [], tmp_path / "public")
        for name in ["index.html", "feed.xml", "feed.json"]:
            assert "editorial_kind" not in (tmp_path / "public" / name).read_text()


def release_sources():
    primary = item(kind="feed", product="tor", title="Tor 0.4.9.16 released", url="https://example.org/release", published_at="2026-11-04T12:00:00Z", updated_at="2026-11-04T12:00:00Z")
    context = timeline(title="Release of tor 0.4.9.16")
    return primary, context


def test_timeline_adds_context_without_replacing_existing_release(tmp_path):
    primary, context = release_sources()
    with Store(tmp_path / "db") as store:
        first = finish(store, primary, analysis(summary="Detailed official release announcement.", state="released", confidence="confirmed"))
        # Legacy stories predate editorial_kind; they must still be protected.
        import json
        legacy = {k: v for k, v in first.items() if k != "editorial_kind"}
        store.db.execute("UPDATE stories SET payload=? WHERE id=?", (json.dumps(legacy), first["id"]))
        store.db.commit()
        final = finish(store, context, analysis(summary="Brief timeline context."))
        assert len(store.stories(10)) == 1
        assert final["id"] == first["id"]
        assert final["summary"] == first["summary"]
        assert final["confidence"] == "confirmed"
        assert final["state"] == "released"
        assert len(final["sources"]) == 2


def test_primary_reporting_can_replace_newer_timeline_context(tmp_path):
    primary, context = release_sources()
    with Store(tmp_path / "db") as store:
        first = finish(store, context, analysis(summary="Brief timeline context."))
        final = finish(store, primary, analysis(summary="Detailed official release announcement.", state="released", confidence="confirmed"))
        assert len(store.stories(10)) == 1
        assert final["id"] == first["id"]
        assert final["summary"] == "Detailed official release announcement."
        assert final["editorial_kind"] == "feed"
        assert final["published_at"] == first["published_at"]

