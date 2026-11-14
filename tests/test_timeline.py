"""Repository snapshots, timeline store continuity, and Atom/RSS timeline feeds."""

import base64
import copy
import hashlib
import json
from xml.sax.saxutils import escape

import pytest

from helpers import (
    DATE, FakeClient, analysis, finish_reviewed, item, publish_stories,
    response, source, update_analysis,
)
from onionflash.collect import CollectionError, collect_source
from onionflash.config import DEFAULTS
from onionflash.store import Store
from onionflash.timeline import collect_timeline

API = "https://gitlab.example.org/api/v4/projects/644/repository/files/README.md?ref=master"
REPOSITORY = "https://gitlab.example.org/group/timeline"
REVISION = "a" * 40
HEADER = "## Timeline\n\n|start date|end date|places|protocols|description|links|?  |\n|---|---|---|---|---|---|---|\n"


def row(start="2026-11-08", end="", places="", protocols="", description="A reported network observation", links="", unknown=""):
    return "|" + "|".join([start, end, places, protocols, description, links, unknown]) + "|\n"


def metadata(text, **changes):
    content = text.encode()
    return {
        "encoding": "base64", "size": len(content), "file_path": "README.md",
        "content_sha256": hashlib.sha256(content).hexdigest(), "last_commit_id": REVISION,
        "content": base64.b64encode(content).decode(), **changes,
    }


def stream(**changes):
    return source(**{"kind": "metrics_timeline", "url": API, "website_url": REPOSITORY, "authority": "telemetry", "max_items": 1000, **changes})


def collect(rows=None, *, text=None, record=None, settings=None, src=None, commit=None):
    record = record if record is not None else metadata(text if text is not None else HEADER + "".join(rows or [row()]))
    commit = commit if commit is not None else {"id": record.get("last_commit_id"), "committed_date": "2026-11-08T11:30:00Z"}
    client = FakeClient([response(json.dumps(record).encode(), {"etag": '"snapshot"'}), response(json.dumps(commit).encode())])
    src = src or stream()
    return collect_timeline(client, src, src["url"], {}, settings or DEFAULTS["collection"], DATE)


def timeline_item(**changes):
    return item(
        kind="metrics_timeline", authority="telemetry", product="network", source_entry_id="a" * 64,
        url="https://gitlab.example/repo/-/blob/" + "1" * 40 + "/README.md?plain=1#L10",
        published_at="2026-11-01T00:00:00Z", updated_at="2026-11-08T12:00:00Z", **changes,
    )


def finish_tl(store, incoming, result):
    assert store.ingest(incoming, DATE)
    stored = dict(store.db.execute("SELECT * FROM items WHERE id=?", (incoming["id"],)).fetchone())
    finish_reviewed(store, stored, result, incoming["id"] + result.get("summary", result.get("update", "")), DATE)
    return store.stories(10)[0]


def atom_entry(identity, title, updated=DATE, alternate=None):
    link = f'<link href="{escape(alternate)}"/>' if alternate else ""
    return (f'<entry><id>{escape(identity)}</id><title>{escape(title)}</title><updated>{updated}</updated>{link}'
            '<content type="xhtml"><div xmlns="http://www.w3.org/1999/xhtml"><p>Dates: 2026-11-08</p>'
            '<p>Protocols: snowflake</p><p>Unknown: Yes</p></div></content></entry>')


def collect_atom(entries, started=DATE):
    body = ('<feed xmlns="http://www.w3.org/2005/Atom"><title>Timeline</title>'
            '<id>https://metrics.example.org/news.atom</id><updated>' + DATE + '</updated>'
            + "".join(entries) + "</feed>").encode()
    return collect_source(FakeClient([response(body)]), source(kind="feed", authority="telemetry", max_items=1000),
                          {}, DEFAULTS["collection"], started)


def test_repository_revision_namespace_and_stable_event_identity():
    first = collect([row()])["items"][0]
    changed = collect(record=metadata("# Extra introduction\n" + HEADER + row(description="Corrected description", end="2026-11-08 11:00"),
                                      last_commit_id="b" * 40))["items"][0]
    assert first["source_entry_id"] == changed["source_entry_id"]
    assert first["url"] == REPOSITORY + "/-/blob/" + REVISION + "/README.md?plain=1#L5"
    assert "/-/blob/" + "b" * 40 in changed["url"] and changed["url"].endswith("#L6")
    assert first["published_at"] == "2026-11-08T00:00:00Z"
    assert first["updated_at"] == changed["updated_at"] == "2026-11-08T11:30:00Z"
    assert "End date as supplied: 2026-11-08 11:00" in changed["content"] and changed["kind"] == "metrics_timeline"

    assert collect(src=stream(url=API.replace("master", "stable")))["items"][0]["source_entry_id"] == first["source_entry_id"]
    assert collect(record=metadata(HEADER + row(), file_path="archive/README.md"),
                   src=stream(url=API.replace("README.md", "archive%2FREADME.md")))["items"][0]["source_entry_id"] != first["source_entry_id"]
    assert collect(src=stream(website_url="https://gitlab.example.org/other/timeline"))["items"][0]["source_entry_id"] != first["source_entry_id"]

    approx = collect([row(start="~2026-11-08", places="cn ru", protocols="OR snowflake")])["items"][0]
    norm = collect([row(start="2026-11-08", places="RU CN", protocols="snowflake or")])["items"][0]
    assert approx["source_entry_id"] == norm["source_entry_id"] and "Start date as supplied: ~2026-11-08" in approx["content"]


def test_date_ranges_escaping_context_bounds_and_gitlab_line_numbers():
    items = collect([
        row(start="2020-01-01", end="ongoing", places="cn", description="Historical blocking"),
        row(start="2020-01-02", end="2026-11-08 10:00:00", places="ru", unknown="X"),
        row(start="2026-11-09", places="by"),
    ])["items"]
    assert len(items) == 1 and items[0]["published_at"] == "2026-11-08T10:00:00Z"
    assert items[0]["updated_at"] == "2026-11-08T11:30:00Z"
    assert "Unknown cause: Yes; preserve this uncertainty" in items[0]["content"]
    assert "Event dates are not publication timestamps" in items[0]["content"]

    escaped = collect([row(description=r"Changed `a\|b` path with \\ before text and escaped \#1")])["items"][0]
    assert "`a|b`" in escaped["title"] and r"with \ before" in escaped["title"] and "escaped #1" in escaped["title"]
    assert collect([row(description="ends in \\\\")])["items"][0]["title"].endswith("\\")

    bounded = collect([row(description="Long description " * 1000, unknown="X")],
                      settings={**DEFAULTS["collection"], "content_chars": 1000})["items"][0]
    assert len(bounded["title"]) == 500 and len(bounded["content"]) <= 1000 and "Unknown cause: Yes" in bounded["content"]

    fut = collect([row(start="2026-11-07", end="2026-11-20")], commit={"id": REVISION, "committed_date": "2026-11-09T00:00:00Z"})["items"][0]
    assert fut["published_at"] == "2026-11-07T00:00:00Z" and fut["updated_at"] == DATE

    old = [row(start="2012-03-01", places="ru,by", protocols="obfs4/meek", unknown="x"),
           row(start="2012-04-01", end="2012-03-01", description="Reversed old range")]
    assert len(collect(old + [row()])["items"]) == 1
    assert collect(text="Intro\x0cpage\n" + HEADER + row(description="One\u2028two"))["items"][0]["url"].endswith("#L6")


def test_ambiguity_collisions_304_caching_and_commit_binding():
    with pytest.raises(CollectionError, match="Ambiguous recent") as failure:
        collect([row(description="Event A"), row(description="Event B"), row(start="2026-11-07")])
    assert failure.value.catching_up and len(failure.value.items) == 1
    assert failure.value.items[0]["published_at"] == "2026-11-07T00:00:00Z"

    res = collect([row(start="2012-01-01", description="A"), row(start="2012-01-01", description="B"), row(), row()])
    assert len(res["items"]) == 1 and res["etag"] == '"snapshot"'

    with pytest.raises(CollectionError, match="Ambiguous recent") as ongoing_err:
        collect([row(start="2020-01-01", end="ongoing"), row(start="2020-01-01", end="2026-11-08")])
    assert ongoing_err.value.items == []

    c304 = FakeClient([response(b"", status=304)])
    r304 = collect_timeline(c304, stream(), API, {"active_url": API, "etag": '"previous"', "last_modified": "yesterday"},
                            DEFAULTS["collection"], DATE)
    assert r304["items"] == [] and r304["etag"] == '"previous"' and len(c304.calls) == 1
    assert c304.calls[0][2]["headers"] == {"If-None-Match": '"previous"', "If-Modified-Since": "yesterday"}

    first = collect()["items"][0]
    later = collect(record=metadata("# New introduction\n" + HEADER + row(), last_commit_id="b" * 40),
                    commit={"id": "b" * 40, "committed_date": DATE})["items"][0]
    assert first["source_entry_id"] == later["source_entry_id"] and first["content"] == later["content"]
    assert first["published_at"] == later["published_at"] and first["updated_at"] < later["updated_at"]
    assert "Repository revision time is not event time" in later["content"]

    client = FakeClient([response(json.dumps(metadata(HEADER + row())).encode()),
                         response(json.dumps({"id": REVISION, "committed_date": DATE}).encode())])
    collect_timeline(client, stream(), API, {}, DEFAULTS["collection"], DATE)
    assert client.calls[1][1] == "https://gitlab.example.org/api/v4/projects/644/repository/commits/" + REVISION
    assert "ref=" not in client.calls[1][1]


@pytest.mark.parametrize("commit", [
    {"id": "b" * 40, "committed_date": DATE}, {"id": REVISION, "committed_date": "2026-11-08T00:00:00"},
    {"id": REVISION, "committed_date": "not a date"}, {"id": REVISION},
])
def test_invalid_revision_metadata_fails_closed(commit):
    with pytest.raises(CollectionError, match="Invalid Metrics Timeline"):
        collect(commit=commit)


@pytest.mark.parametrize("change", [
    {"encoding": "utf8"}, {"content": "!not-base64!"}, {"last_commit_id": "../main"}, {"last_commit_id": ""},
    {"file_path": "../private.md"}, {"file_path": "/README.md"}, {"file_path": "a/%2e%2e/private.md"},
    {"file_path": "a\\README.md"}, {"file_path": "a//README.md"},
])
def test_invalid_snapshot_metadata_is_rejected(change):
    with pytest.raises(CollectionError, match="Invalid Metrics Timeline"):
        collect(record=metadata(HEADER + row(), **change))


@pytest.mark.parametrize("text", [
    "No table", HEADER + row() + "\n## Timeline\n", HEADER.replace("start date", "published date") + row(),
    HEADER.replace("|---|---|", "|--|---|", 1) + row(), HEADER + row(start="invalid"), HEADER + row(start="2026-02-30"),
    HEADER + row(end="2026-01-01"), HEADER + row(description="unescaped | pipe"), HEADER + row(description="<script>bad()</script>"),
])
def test_malformed_tables_fail_closed(text):
    with pytest.raises(CollectionError, match="Invalid Metrics Timeline"):
        collect(text=text)


@pytest.mark.parametrize("website", ["javascript:alert(1)", "https://user:secret@example.org/", "https://127.0.0.1/"])
def test_unsafe_repository_citations_are_rejected(website):
    with pytest.raises(CollectionError):
        collect(src=stream(website_url=website))


def test_timeline_store_continuity_release_protection_and_clock_skew(tmp_path):
    with Store(tmp_path / "db1") as store:
        original = timeline_item(content="End date: 2026-11-07. Cause unknown.")
        first = finish_tl(store, original, analysis(summary="The reported range ended November 7."))
        moved = {**original, "url": original["url"].replace("1" * 40, "2" * 40).replace("#L10", "#L20"),
                 "updated_at": "2026-11-09T12:00:00Z"}
        assert not store.ingest(copy.deepcopy(moved), DATE) and store.pending_count() == 0
        corrected = {**moved, "content": "End date: 2026-11-05. Cause unknown."}
        final = finish_tl(store, corrected, analysis(summary="The corrected range ended November 5."))
        assert final["id"] == first["id"] and final["published_at"] == first["published_at"]
        assert final["summary"] == "The corrected range ended November 5."
        assert final["sources"] == [{"id": corrected["id"], "url": corrected["url"],
                                     "title": corrected["title"], "published_at": corrected["published_at"]}]
        assert store.db.execute("SELECT COUNT(*),url FROM items").fetchone()[:] == (1, corrected["url"])
        publish_stories([final], tmp_path / "public")
        for name in ("index.html", "feed.xml", "feed.json"):
            assert "editorial_kind" not in (tmp_path / "public" / name).read_text()

        tl_v1 = {**item(url="https://gitlab.torproject.org/tpo/metrics/timeline/-/blob/aaa111/README.md?plain=1#L10",
                        kind="metrics_timeline", title="Relay censorship event", content="Initial timeline description.",
                        published_at="2024-01-15T00:00:00Z", updated_at="2024-01-15T12:00:00Z"),
                 "source_entry_id": "entry-1"}
        tl_stale = {**tl_v1, "url": "https://gitlab.torproject.org/tpo/metrics/timeline/-/blob/000999/README.md?plain=1#L9",
                    "content": "Superseded older fallback description.", "updated_at": "2024-01-15T11:55:00Z"}
        tl_v2 = {**tl_v1, "url": "https://gitlab.torproject.org/tpo/metrics/timeline/-/blob/bbb222/README.md?plain=1#L10",
                 "content": "Corrected timeline description from rebased commit.", "updated_at": "2024-01-15T12:00:00Z"}
        assert store.ingest(tl_v1, "2024-01-15T12:05:00Z") is True
        assert store.ingest(tl_stale, "2024-01-15T12:06:00Z") is False
        assert store.ingest(tl_v2, "2024-01-15T12:10:00Z") is True

    primary = item(kind="feed", product="tor", title="Tor 0.4.9.16 released", url="https://example.org/release",
                   published_at="2026-11-04T12:00:00Z", updated_at="2026-11-04T12:00:00Z")
    ctx_item = timeline_item(title="Release of tor 0.4.9.16")
    with Store(tmp_path / "db2") as store:
        first = finish_tl(store, primary, analysis(summary="Detailed official release announcement.", state="released", confidence="confirmed"))
        legacy = {k: v for k, v in first.items() if k != "editorial_kind"}
        store.db.execute("UPDATE stories SET payload=? WHERE id=?", (json.dumps(legacy), first["id"]))
        store.db.commit()
        final = finish_tl(store, ctx_item, update_analysis(update="Brief timeline context.", confidence="confirmed",
                                                           state="released", evidence=[ctx_item["title"]]))
        assert len(store.stories(10)) == 1 and final["id"] == first["id"] and final["summary"] == first["summary"]
        assert final["confidence"] == "confirmed" and final["state"] == "released" and len(final["sources"]) == 2
        assert final["updates"][-1]["text"] == "Brief timeline context."

    with Store(tmp_path / "db3") as store:
        first = finish_tl(store, ctx_item, analysis(summary="Brief timeline context."))
        final = finish_tl(store, primary, analysis(summary="Detailed official release announcement.", state="released", confidence="confirmed"))
        assert len(store.stories(10)) == 1 and final["id"] == first["id"]
        assert final["summary"] == "Detailed official release announcement."
        assert final["editorial_kind"] == "feed" and final["published_at"] == first["published_at"]


def test_atom_and_rss_timeline_id_fallbacks_and_conflict_guards():
    url = "https://metrics.example.org/news.atom#event"
    res = collect_atom([atom_entry(url, "An unexplained network change")])
    entry0 = res["items"][0]
    assert entry0["url"] == url and "Protocols: snowflake" in entry0["content"] and "Unknown: Yes" in entry0["content"]
    assert entry0["published_at"] == DATE == entry0["updated_at"]

    old_url = "https://metrics.example.org/news.atom#old"
    assert collect_atom([atom_entry(old_url, "First old event", "2026-03-09T12:00:00Z"),
                         atom_entry(old_url, "Different old event", "2026-03-09T12:00:00Z")])["items"] == []

    col_url = "https://metrics.example.org/news.atom#collision"
    col_res = collect_atom([atom_entry(col_url, "First event"), atom_entry(col_url, "Different event"),
                            atom_entry("https://metrics.example.org/news.atom#unique", "Unambiguous event")])
    assert [i["title"] for i in col_res["items"]] == ["Unambiguous event"] and col_res["skipped"] == 2

    assert len(collect_atom([atom_entry(url, "Same event"), atom_entry(url, "Same event")])["items"]) == 2
    assert len(collect_atom([atom_entry(url, "First version"), atom_entry(url, "Updated version", "2026-11-08T12:01:00Z")],
                            started="2026-11-08T12:05:00Z")["items"]) == 2
    assert len(collect_atom([atom_entry("urn:one", "First update", alternate="https://example.org/incident"),
                             atom_entry("urn:two", "Second update", alternate="https://example.org/incident")])["items"]) == 2

    rss_entries = "".join(
        f'<item><guid isPermaLink="true">https://example.org/incident</guid>'
        f"<title>Update {n}</title><description>Revision {n}</description>"
        "<pubDate>Sun, 08 Nov 2026 12:00:00 GMT</pubDate></item>" for n in (1, 2)
    )
    rss_body = ("<rss version=\"2.0\"><channel><title>Updates</title><link>https://example.org/</link>"
                "<description>News</description>" + rss_entries + "</channel></rss>").encode()
    assert len(collect_source(FakeClient([response(rss_body)]), source(), {}, DEFAULTS["collection"], DATE)["items"]) == 2

    assert collect_atom([atom_entry("urn:uuid:unlinked", "No public citation")])["items"] == []
    assert collect_atom([atom_entry("https://127.0.0.1/private", "Unsafe citation")])["items"] == []
    long_item = collect_atom([atom_entry("https://metrics.example.org/news.atom#long",
                                         "A long event description " * 30 + "The cause remains unknown.")])["items"][0]
    assert len(long_item["title"]) == 500 and "The cause remains unknown." in long_item["content"]

    atom_xml = b"""<?xml version="1.0" encoding="utf-8"?>
    <feed xmlns="http://www.w3.org/2005/Atom"><title>Feed</title>
      <entry><id>https://example.org/entry-1</id><title>Event A</title><updated>2026-11-10T12:00:00Z</updated>
        <link rel="related" href="https://example.org/ref-a"/><summary>First distinct body.</summary></entry>
      <entry><id>https://example.org/entry-1</id><title>Event B</title><updated>2026-11-10T12:00:00Z</updated>
        <link rel="related" href="https://example.org/ref-b"/><summary>Second conflicting body.</summary></entry>
    </feed>"""
    rel_res = collect_source(FakeClient([response(atom_xml)]), source(), {}, DEFAULTS["collection"], "2026-11-10T12:05:00Z")
    assert rel_res["items"] == [] and rel_res["skipped"] == 2

    pdf_xml = atom_xml.replace(b'rel="related" href="https://example.org/ref-',
                               b'rel="alternate" type="application/pdf" href="https://example.org/doc-')
    pdf_res = collect_source(FakeClient([response(pdf_xml)]), source(), {}, DEFAULTS["collection"], "2026-11-10T12:05:00Z")
    assert pdf_res["items"] == [] and pdf_res["skipped"] == 2

    mixed_xml = atom_xml.replace(
        b"</feed>",
        b"""<entry><id>tag:example.org,2026:explicit</id><title>Explicit Alternate Event</title>
            <updated>2026-11-10T12:00:00Z</updated><link rel="alternate" type="text/html" href="https://example.org/entry-1"/>
            <summary>Explicitly linked body.</summary></entry></feed>""",
    )
    mixed_res = collect_source(FakeClient([response(mixed_xml)]), source(), {}, DEFAULTS["collection"], "2026-11-10T12:05:00Z")
    assert len(mixed_res["items"]) == 1 and mixed_res["items"][0]["title"] == "Explicit Alternate Event" and mixed_res["skipped"] == 2
