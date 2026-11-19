"""Core unit tests for text normalization, URLs, storage, collection, transport, and config."""

import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import socket
import sqlite3
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from helpers import (DAMAGE, DATE, ApprovingReviewer, FakeClient, FakeLLM, ScriptedAnalyzer, analysis, completion, config,
                     damage_item, damaged, finish_reviewed, item, patch_cli_pipeline, response, source,
                     tag, update_analysis)
from onionflash import cli, collect, review, review_gate
from onionflash.analyze import AnalysisError, Analyzer, tag_notice, validate_analysis
from onionflash.cli import build, main, run_lock
from onionflash.collect import CollectionError, _item, collect_source
from onionflash.config import DEFAULT_TRUSTED_OPERATOR_DOMAINS, DEFAULTS, load_config
from onionflash.llm import json_object, unquoted_mail_text
from onionflash.store import Store, after as store_after, backup_database
from onionflash.transport import DeadlineReached, FetchError, HttpClient, Response
from onionflash.util import (MAX_SAVED_DEPTH, after, backoff_seconds, canonical_url, format_utc,
                             gitlab_refs, item_cluster, parse_utc, plain_text, saved_object, timestamp)

LIST_URL = "https://lists.torproject.org/mailman3/hyperkitty/list/tor-dev@lists.torproject.org/feed/"
RESOLVER = lambda *args: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]
EXAMPLE_TOML = (Path(__file__).parents[1] / "config.example.toml").read_text()


@pytest.mark.parametrize("raw,expected", [
    ("<p>Hello</p><script>steal()</script><style>bad</style>world\x00", "Hello\nworld"),
    ("v1 <word", "v1 <word"),
    ("one\r\ntwo\rthree", "one\ntwo\nthree"),
    ("v1 &amp", "v1 &"),
    ("v1 <!--hidden", "v1"),
    ("<script>hidden <word", ""),
    ("security\ud800 report", "security\ufffd report"),
])
def test_plain_text_and_unicode_normalization(raw, expected):
    """Strip hidden HTML elements, control characters, and lone surrogates in plain_text."""
    assert plain_text(raw, 100) == expected


@pytest.mark.parametrize("quoted,expected", [
    ("Quoted <b>claim</b>.<br>Second line.", "> Quoted claim.\n> Second line."),
    ("Outer <i>claim</i>.<blockquote>Inner claim.</blockquote>Outer continuation.",
     "> Outer claim.\n>> Inner claim.\n> Outer continuation."),
    ("First line.\nSecond line.\r\nThird line.\u2028Fourth line.",
     "> First line.\n> Second line.\n> Third line.\u2028> Fourth line."),
    ("Quoted <span>claim</span><script>hidden()</script><style>hidden</style>"
     "<noscript>hidden</noscript><template><blockquote>hidden</blockquote></template> remains.",
     "> Quoted claim remains."),
])
def test_opt_in_blockquote_markers_preserve_visible_quote_boundaries(quoted, expected):
    raw = ("<p>Own reply.</p><template><blockquote>Hidden claim.</blockquote></template>"
           f"<blockquote>{quoted}</blockquote><p>Own follow-up.</p>")
    marked = plain_text(raw, 2000, mark_blockquotes=True)
    assert marked == f"Own reply.\n\n{expected}\n\nOwn follow-up."
    assert unquoted_mail_text(marked) == "Own reply.\n\nOwn follow-up."
    assert "hidden" not in marked.lower()
    assert "> " not in plain_text(raw, 2000)


def test_blockquote_marking_keeps_literal_quotes_and_plain_text_defaults():
    raw = "<p>Own reply.</p>&gt; Existing quoted line.<br>&gt; Another quoted line."
    assert plain_text(raw, 2000, mark_blockquotes=True) == plain_text(raw, 2000)
    assert unquoted_mail_text(plain_text(raw, 2000, mark_blockquotes=True)) == "Own reply."
    literal = "<blockquote>Literal markup in a text field.</blockquote>"
    assert plain_text(literal, 2000, html=False, mark_blockquotes=True) == literal
    assert plain_text(literal, 2000) == "Literal markup in a text field."


@pytest.mark.parametrize("limit", [200, 20_000])
def test_blockquote_prefix_materialization_stays_proportional_to_output_limit(monkeypatch, limit):
    from onionflash import util

    class BoundedParts(list):
        characters = 0

        def append(self, text):
            self.characters += len(text)
            assert self.characters <= 6 * limit
            super().append(text)

    original = util._TextParser

    class InspectingParser(original):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.parts = BoundedParts()

    monkeypatch.setattr(util, "_TextParser", InspectingParser)
    depth = limit // 5
    lines = (4 * limit - len("<blockquote>") * depth) // 2
    raw = "<blockquote>" * depth + "x\n" * lines
    expected = (">" * depth + " x\n") * (limit // depth + 1)
    assert plain_text(raw, limit, mark_blockquotes=True) == expected[:limit]


@pytest.mark.parametrize("raw,limit,expected", [
    (" \t\x00" + "<blockquote>" * 5 + "\t\x00\n \t\nx\n\nY \t", 20,
     ">>>>> \n>>>>> \n>>>>> "),
    (" " * 40 + "<blockquote>" * 3 + "\x00\n" * 10, 24,
     ">>> \n>>> \n>>> \n>>> \n>>> "),
    ("<blockquote>" * 4 + " \t\u2028\x00\n\tA\t\tB\nZ \x85 " * 2, 20,
     ">>>> \u2028>>>> \n>>>> A B"),
])
def test_quote_budget_preserves_truncation_after_whitespace_and_control_cleanup(raw, limit, expected):
    assert plain_text(raw, limit, mark_blockquotes=True) == expected


def _quoted_reply_feed(entry_url, authority="community"):
    body = ("<p>The current reply narrows the measurement to a smaller sample.</p>"
            "<blockquote>The earlier author reported failures across every measured relay.</blockquote>")
    xml = ("<rss version='2.0'><channel><title>Replies</title><link>https://example.org/</link>"
           "<description>Replies</description><item><title>Re: Measurements</title>"
           f"<link>{entry_url}</link><description><![CDATA[{body}]]></description>"
           "<pubDate>Sun, 08 Nov 2026 12:00:00 GMT</pubDate></item></channel></rss>").encode()
    return collect_source(FakeClient([response(xml, url=LIST_URL)]),
                          source(url=LIST_URL, authority=authority), {}, DEFAULTS["collection"], DATE)["items"]


@pytest.mark.parametrize("entry_url,authority,marked", [
    ("https://lists.torproject.org/thread/EXAMPLE/", "community", True),
    ("https://lists.torproject.org/thread/EXAMPLE/", "official", True),
    ("https://LISTS.TORPROJECT.ORG/thread/EXAMPLE/", "community", True),
    ("https://example.org/thread/EXAMPLE/", "official", False),
    ("https://lists.torproject.org.example.org/thread/EXAMPLE/", "community", False),
    ("https://example.org/lists.torproject.org/?host=lists.torproject.org", "community", False),
])
def test_feed_marks_blockquotes_only_for_the_exact_entry_hostname(entry_url, authority, marked):
    [collected] = _quoted_reply_feed(entry_url, authority)
    assert collected["content"].startswith("The current reply narrows")
    assert ("\n> The earlier author" in collected["content"]) is marked


@pytest.mark.parametrize("entry_url", [
    "https://lists.torproject.org@invalid.example/thread/", "https://[invalid/thread/",
])
def test_quote_marking_still_skips_invalid_entry_urls(entry_url):
    assert _quoted_reply_feed(entry_url) == []


@pytest.mark.parametrize("quoted_only", [False, True])
def test_collected_html_quotes_stay_outside_writer_and_packet_reply_evidence(monkeypatch, quoted_only):
    from onionflash.source_packet import build_packet

    [collected] = _quoted_reply_feed("https://lists.torproject.org/thread/EXAMPLE/")
    collected["id"] = "a" * 24
    own = "The current reply narrows the measurement to a smaller sample."
    quoted = "The earlier author reported failures across every measured relay."
    packet, _ = build_packet(None, collected, {"sources": [{"id": collected["id"], "url": collected["url"]}]},
                             {"sources": []}, collected["id"])
    assert packet["sources"][0]["unquoted_content"] == own
    draft = analysis(title="A reply narrows the measured sample", summary=own, why_it_matters="",
                     evidence=[quoted if quoted_only else own])
    cfg = copy.deepcopy(DEFAULTS)
    cfg["llm"].update(base_url="https://model.example/v1", fallback_base_urls=[])
    monkeypatch.setenv("ONIONFLASH_LLM_API_KEY", "synthetic-fixture-key")
    with Analyzer(cfg) as writer:
        writer.client = FakeLLM(completion(draft))
        if quoted_only:
            with pytest.raises(AnalysisError) as caught:
                writer.analyze(collected)
            assert caught.value.code == "writer.quoted_only_evidence"
        else:
            assert writer.analyze(collected)["summary"] == own
        payload = json.loads(writer.client.requests[0][1]["messages"][-1]["content"])
    assert payload["unquoted_content"] == own and quoted not in payload["unquoted_content"]


def test_tag_notice_clean_text_and_surrogate_json_rejection():
    """Format literal tag notices and reject unpaired surrogate JSON escapes."""
    cleaned = plain_text("v1\r\n<word", 100)
    assert tag_notice(tag(title=cleaned, content=""))["evidence"] == [cleaned]
    with pytest.raises(AnalysisError, match="invalid JSON"):
        json_object('{"title":"\\ud800"}')


@pytest.mark.parametrize("url", [
    "file:///etc/passwd", "http://example.org/news", "https://user:secret@example.org/",
    "https://127.0.0.1/", "https://127.1/", "https://224.0.0.1/", "https://localhost/",
    "https://foo.internal/", "https://example.org/\nheader", "https://example.org/a\ufffeb",
    "https://example.org/#\uffff", "https://example.org/\ud800", "https://[::127.0.0.1]/",
    "https://[64:ff9b::127.0.0.1]/", "https://example.org:0/feed.xml",
])
def test_bad_citation_urls_are_rejected(url):
    """Reject non-HTTPS, credentialed, local, numeric, or malformed citation URLs."""
    with pytest.raises(ValueError):
        canonical_url(url)


def test_gitlab_aliases_url_identities_utc_helpers_and_extra_fields():
    """Unify GitLab issue/work_item URLs, extract references, and validate UTC timestamps."""
    assert canonical_url("https://gitlab.torproject.org/tpo/core/tor/-/issues/123?utm_source=x") == "https://gitlab.torproject.org/tpo/core/tor/-/work_items/123"
    assert canonical_url("https://[2606:4700:4700::1111]/feed.xml") == "https://[2606:4700:4700::1111]/feed.xml"
    assert canonical_url("https://gitlab.torproject.org/tpo/core/tor/-/issues/123/designs") == "https://gitlab.torproject.org/tpo/core/tor/-/issues/123/designs"
    closing, _ = gitlab_refs({"url": "https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/10", "title": "Fix crash",
                              "content": "Closes https://gitlab.torproject.org/tpo/core/tor/-/issues/41473?iid_path=true"})
    assert closing == ["https://gitlab.torproject.org/tpo/core/tor/-/work_items/41473"]

    assert parse_utc("2026-11-08T04:00:00-08:00") == datetime(2026, 11, 8, 12, tzinfo=timezone.utc)
    assert format_utc(parse_utc("2026-11-08T13:00:00+01:00")) == DATE
    assert timestamp("2026-11-08T13:00:00+01:00") == DATE and timestamp({}, DATE) == DATE
    assert store_after is after and after(2, "2026-11-08T04:00:00-08:00") == "2026-11-08T12:00:02Z"
    with pytest.raises(ValueError):
        parse_utc("2026-11-08T12:00:00")
    with pytest.raises(ValueError):
        format_utc(datetime(2026, 11, 8))
    assert [backoff_seconds(n, 5, 20) for n in (1, 2, 3, 50)] == [5, 10, 20, 20]

    with pytest.raises(AnalysisError):
        validate_analysis(analysis(evidence=["This was definitely confirmed"]), item())
    with pytest.raises(AnalysisError):
        validate_analysis({**analysis(), "url": "https://evil.example/"}, item())


def test_queue_is_durable_idempotent_and_ignores_stale_or_late_defer(tmp_path):
    """Persist pending items idempotently and ignore stale deferrals after source updates."""
    db = tmp_path / "state.db"
    with Store(db) as store:
        assert store.ingest(item(), DATE)
        row = store.pending(1, DATE)[0]
        store.defer(row["id"], "Provider unavailable", DEFAULTS["llm"], DATE)
        assert not store.pending(1, DATE) and store.pending_count() == 1
        assert not store.ingest(item(updated_at="2026-11-09T00:00:00Z"), "2026-11-09T00:00:00Z")
    with Store(db) as store:
        assert store.pending_count() == 1
        row = store.pending(1, "2026-11-09T00:00:00Z")[0]
        finish_reviewed(store, row, analysis(), "cache", DATE)
        assert store.pending_count() == 0 and len(store.stories(10)) == 1
        assert json.loads(store.db.execute("SELECT result FROM analyses WHERE cache_key='cache'").fetchone()[0])["title"] == analysis()["title"]
        before = dict(store.db.execute("SELECT * FROM items").fetchone())
        store.defer(row["id"], "Late timeout", DEFAULTS["llm"], DATE)
        assert dict(store.db.execute("SELECT * FROM items").fetchone()) == before

    with Store(tmp_path / "skip.db") as store:
        store.ingest(item(), DATE)
        row = store.pending(1, DATE)[0]
        finish_reviewed(store, row, analysis(), "cache", DATE, decision="skip")
        before = dict(store.db.execute("SELECT * FROM items").fetchone())
        store.defer(row["id"], "Late timeout", DEFAULTS["llm"], DATE)
        assert dict(store.db.execute("SELECT * FROM items").fetchone()) == before

    with Store(tmp_path / "stale.db") as store:
        store.ingest(item(updated_at="2026-11-09T00:00:00Z"), DATE)
        assert not store.ingest(item(content="Older stale cached report"), DATE)
        assert json.loads(store.pending(1, "2026-11-09T00:00:00Z")[0]["payload"])["content"] == item()["content"]


def test_private_backup_copies_wal_and_cleans_up_failed_partial(tmp_path):
    """Create mode-0600 SQLite backups and unlink partial files when validation fails."""
    src_db, dest_db = tmp_path / "source.db", tmp_path / "copy.db"
    with Store(src_db) as store:
        store.set_meta(kept="committed")
        backup_database(src_db, dest_db)
    assert dest_db.stat().st_mode & 0o777 == 0o600
    with sqlite3.connect(dest_db) as conn:
        assert conn.execute("SELECT value FROM metadata WHERE key='kept'").fetchone()[0] == "committed"
    with pytest.raises(ValueError, match="must be new"):
        backup_database(src_db, dest_db)

    partial = tmp_path / "partial.db"
    original_connect, opened = sqlite3.connect, []

    def connect(path, *args, **kwargs):
        """Intercept SQLite backup destination connection to simulate failed quick_check."""
        if path == partial:
            assert partial.stat().st_mode & 0o777 == 0o600
            raise RuntimeError("simulated destination failure")
        assert "mode=ro" in path
        conn = original_connect(path, *args, **kwargs)
        opened.append(conn)
        return conn

    with patch("onionflash.store.sqlite3.connect", side_effect=connect), pytest.raises(RuntimeError):
        backup_database(src_db, partial)
    assert not partial.exists()
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        opened[0].execute("SELECT 1")


def test_exact_body_duplicates_release_mirrors_and_older_mirrors(store):
    """Cluster identical issue bodies and release versions while ignoring older mirror revisions."""
    body = item()["content"] * 3
    for n in (1, 2):
        store.ingest(item(url=f"https://example.org/{n}", content=body), DATE)
        finish_reviewed(store, store.pending(1, DATE)[0], analysis(), f"cache{n}", DATE)
    stories = store.stories(10)
    assert len(stories) == 1 and len(stories[0]["sources"]) == 2
    assert item_cluster(item(content="Unrelated event", url="https://example.org/other")) != item_cluster(item())
    assert item_cluster(item(content=body, title="Unrelated title")) != item_cluster(item(content=body))
    assert item_cluster(item(content=body, title="dirauth: Remove bastet from list")) == item_cluster(item(content=body, title="Remove bastet from list"))

    release = item(url="https://example.org/released", kind="feed", title="Tor 0.4.9.16 released", product="network")
    rel_tag = item(url="https://example.org/tag", kind="tag", title="tor-0.4.9.16", updated_at="2026-11-09T00:00:00Z")
    assert item_cluster(release) == item_cluster(rel_tag)
    store.ingest(release, DATE)
    finish_reviewed(store, store.pending(1, DATE)[0], analysis(title="Tor 0.4.9.16 released", state="released"), "release", DATE)
    store.ingest(rel_tag, DATE)
    finish_reviewed(store, store.pending(1, DATE)[0], analysis(title="Tor tag created", state="tagged"), "tag", DATE)
    rel_story = next(s for s in store.stories(10) if "0.4.9.16" in s["title"])
    assert rel_story["state"] == "released" and rel_story["title"] == "Tor 0.4.9.16 released" and len(rel_story["sources"]) == 2

    other_body = "Distinct mirror body text long enough to group across URLs. " * 5
    store.ingest(item(url="https://example.org/new", content=other_body, updated_at="2026-11-09T00:00:00Z"), DATE)
    finish_reviewed(store, store.pending(1, "2026-11-09T00:00:00Z")[0], analysis(title="Newest facts", evidence=["Distinct mirror body text long enough"]), "new", DATE)
    store.ingest(item(url="https://example.org/old", content=other_body), DATE)
    finish_reviewed(store, store.pending(1, DATE)[0], analysis(title="Old facts", evidence=["Distinct mirror body text long enough"]), "old", DATE)
    assert len(next(s for s in store.stories(10) if s["title"] == "Newest facts")["sources"]) == 2


def test_source_failure_keeps_last_success_and_updates_in_one_statement(store):
    """Preserve last_success and apply bounded backoff when recording source failures."""
    s = source()
    store.source(s)
    store.source_success(s, {"url": s["url"], "watermark": DATE}, DATE)
    statements = []
    store.db.set_trace_callback(statements.append)
    store.source_failure(s, "HTTP 503", DEFAULTS["collection"], DATE)
    assert len([st for st in statements if st.startswith("UPDATE source_state")]) == 1
    state = store.source(s)
    assert state["watermark"] == DATE and state["last_success"] == DATE and state["failures"] == 1
    assert state["error"] == "HTTP 503" and state["next_fetch_at"] > DATE and store.source(source(url="https://other.example/feed"))["watermark"] is None


def test_collect_fallback_conditional_cache_and_feed_bounds():
    """Use conditional GET validators, fall back across mirrors, and cap collected feed items."""
    xml = b'<?xml version="1.0"?><rss version="2.0"><channel><title>News</title><item><title>Hello</title><link>https://example.org/one</link><description>Safe story</description><pubDate>Sun, 08 Nov 2026 10:00:00 GMT</pubDate></item></channel></rss>'
    s = source(fallback_urls=["https://backup.example/feed.xml"])
    res = collect_source(FakeClient([FetchError("HTTP 503", status=503, retryable=True), response(xml, {"etag": "abc"})]), s, {}, DEFAULTS["collection"], DATE)
    assert len(res["items"]) == 1 and res["url"] == s["fallback_urls"][0]
    client = FakeClient([response(b"", status=304)])
    res304 = collect_source(client, s, {"active_url": s["url"], "etag": "abc"}, DEFAULTS["collection"], DATE)
    assert res304["items"] == [] and res304["etag"] == "abc" and client.calls[0][2]["headers"]["If-None-Match"] == "abc"

    two_xml = (b'<rss version="2.0"><channel><title>News</title>'
               b'<item><title>First report</title><link>https://example.org/one</link><description>First</description><pubDate>Sun, 08 Nov 2026 10:00:00 GMT</pubDate></item>'
               b'<item><title>Second report</title><link>https://example.org/two</link><description>Second</description><pubDate>Sun, 08 Nov 2026 11:00:00 GMT</pubDate></item></channel></rss>')
    assert [r["title"] for r in collect_source(FakeClient([response(two_xml)]), source(max_items=1), {}, DEFAULTS["collection"], DATE)["items"]] == ["Second report"]

    cutoff_xml = (b'<rss version="2.0"><channel><title>News</title>'
                  b'<item><title>On cutoff</title><link>https://example.org/on</link><pubDate>Sun, 25 Oct 2026 14:00:00 +0200</pubDate></item>'
                  b'<item><title>Before cutoff</title><link>https://example.org/before</link><pubDate>Sun, 25 Oct 2026 11:59:59 GMT</pubDate></item></channel></rss>')
    assert [r["title"] for r in collect_source(FakeClient([response(cutoff_xml)]), source(), {}, DEFAULTS["collection"], DATE)["items"]] == ["On cutoff"]


@pytest.mark.parametrize("body", [
    b"<rss><bad>", b'<!DOCTYPE rss [<!ENTITY attack "boom">]><rss/>', b"<html>Not a feed</html>",
    '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE rss [<!ENTITY x "ENTITY_EXPANDED">]><rss version="2.0"><channel><title>&x;</title></channel></rss>'.encode("utf-16"),
])
def test_malformed_or_entity_feeds_rejected(body):
    """Reject bozo feeds, DTDs, and XML entity declarations during feed collection."""
    with pytest.raises(CollectionError):
        collect_source(FakeClient([response(body)]), source(), {}, DEFAULTS["collection"], DATE)


_BASE_EXP = "https://example.org/" + "a" * 60000 + "/"


@pytest.mark.parametrize("bad_base", [
    f'<rss xml:base="{_BASE_EXP}">' + "<item/>" * 200 + "</rss>",
    f'<rss><a BASE="{_BASE_EXP}">' + "<b/>" * 200 + "</a></rss>",
    f'<rss><channel><item xml:base="{_BASE_EXP}"/>' + "<item><title>x</title></item>" * 100 + "</channel></rss>",
    f'<rss><channel><item xml:base="{_BASE_EXP}"/>' + '<item xml:base="data://x/"><title>x</title></item>' * 100 + "</channel></rss>",
    "<rss>" + ('<a xml:base="' + "a" * 60000 + '/">') * 100 + "</a>" * 100 + "</rss>",
])
def test_xml_base_expansion_rejected_before_feedparser(monkeypatch, bad_base):
    """Abort feed XML scans when cumulative xml:base growth exceeds limits."""
    monkeypatch.setattr(collect.feedparser, "parse", lambda *a, **kw: pytest.fail("feedparser ran"))
    with pytest.raises(CollectionError, match="xml:base text"):
        collect_source(FakeClient([response(bad_base.encode())]), source(), {}, DEFAULTS["collection"], DATE)


def test_xml_guards_before_feedparser_and_accepted_bases(monkeypatch):
    """Enforce XML element and nesting caps while accepting bounded relative xml:base attributes."""
    item_tpl = '<item data-padding="' + "x" * 40000 + '"><title>Item {n}</title><link>https://example.org/{n}</link></item>'
    xml = f'<rss version="2.0" xml:base="https://example.org/"><channel><title>News</title>{item_tpl.format(n=1)}{item_tpl.format(n=2)}</channel></rss>'
    assert sorted(r["title"] for r in collect_source(FakeClient([response(xml.encode())]), source(), {}, DEFAULTS["collection"], DATE)["items"]) == ["Item 1", "Item 2"]

    abs_tpl = '<item xml:base="https://example.org/2026/11/10/a-fairly-long-permalink-for-post-{n}/"><title>Item {n}</title><link>https://example.org/{n}</link></item>'
    abs_xml = '<rss version="2.0"><channel><title>News</title>' + "".join(abs_tpl.format(n=n) for n in range(1000)) + "</channel></rss>"
    assert len(collect_source(FakeClient([response(abs_xml.encode())]), source(max_items=1000), {}, DEFAULTS["collection"], DATE)["items"]) == 1000

    monkeypatch.setattr(collect.feedparser, "parse", lambda *a, **kw: pytest.fail("feedparser ran"))
    with pytest.raises(CollectionError, match="nested too deeply"):
        collect_source(FakeClient([response(("<rss>" + "<a>" * 128 + "</a>" * 128 + "</rss>").encode())]), source(), {}, DEFAULTS["collection"], DATE)
    monkeypatch.setattr(collect, "MAX_FEED_ELEMENTS", 10)
    with pytest.raises(CollectionError, match="too many XML elements"):
        collect_source(FakeClient([response(("<rss><channel>" + "<item/>" * 20 + "</channel></rss>").encode())]), source(), {}, DEFAULTS["collection"], DATE)


def gitlab_records(*stamps):
    """Build synthetic GitLab issue API records for given timestamps."""
    return json.dumps([{"web_url": f"https://example.org/issues/{n}", "title": f"Report {n}", "description": "Body",
                        "created_at": stamp, "updated_at": stamp} for n, stamp in enumerate(stamps)]).encode()


def gitlab_queries(client):
    """Extract parsed query-parameter dictionaries from recorded client requests."""
    return [parse_qs(urlsplit(call[1]).query) for call in client.calls]


def test_gitlab_collection_watermarks_ties_and_fallbacks(store):
    """Step through GitLab updated_at watermarks, same-timestamp tie pages, and fallbacks."""
    client = FakeClient([response(gitlab_records(DATE))])
    res = collect_source(client, source(kind="gitlab_issue"), {}, DEFAULTS["collection"], DATE)
    q0 = gitlab_queries(client)[0]
    assert q0["updated_after"] == [after(-DEFAULTS["collection"]["lookback_days"] * 86400, DATE)]
    assert q0["updated_before"] == [DATE] and q0["sort"] == ["asc"] and q0["page"] == ["1"]
    assert res["watermark"] == after(-DEFAULTS["collection"]["overlap_seconds"], DATE)

    stream, settings = source(kind="gitlab_issue", max_pages=1), {**DEFAULTS["collection"], "page_size": 2}
    with pytest.raises(CollectionError, match="catching up") as exc:
        collect_source(FakeClient([response(gitlab_records("2026-11-01T00:00:00Z", "2026-11-02T00:00:00.250Z"))]), stream, store.source(stream), settings, DATE)
    assert len(exc.value.items) == 2 and exc.value.catching_up
    store.source_failure(stream, str(exc.value), settings, DATE, exc.value.watermark, exc.value.catching_up)
    c2 = FakeClient([response(gitlab_records("2026-11-03T00:00:00Z"))])
    r2 = collect_source(c2, stream, store.source(stream), settings, "2026-11-08T12:05:00Z")
    assert gitlab_queries(c2)[0]["updated_after"] == ["2026-11-02T00:00:00.250Z"] and gitlab_queries(c2)[0]["page"] == ["1"]
    store.source_success(stream, r2, "2026-11-08T12:05:00Z")
    assert store.source(stream)["watermark"] == after(-settings["overlap_seconds"], "2026-11-08T12:05:00Z")

    tie = "2026-11-02T00:00:00.000Z"
    ctie = FakeClient([response(gitlab_records(tie, tie)), response(gitlab_records(tie, tie)), response(gitlab_records(tie))])
    collect_source(ctie, source(kind="gitlab_issue", max_pages=3), {"watermark": "2026-11-01T00:00:00Z"}, settings, DATE)
    assert [(q["updated_after"][0], q["page"][0]) for q in gitlab_queries(ctie)] == [("2026-11-01T00:00:00Z", "1"), (tie, "1"), (tie, "2")]

    s2 = source(kind="gitlab_issue", max_pages=2)
    with pytest.raises(CollectionError, match="catching up") as exc:
        collect_source(FakeClient([response(gitlab_records("2026-11-01T00:00:00Z", tie)), response(gitlab_records(tie, tie))]),
                       s2, {"watermark": "2026-10-31T00:00:00Z"}, settings, DATE)
    assert exc.value.watermark == tie
    with pytest.raises(CollectionError, match="same-timestamp") as exc:
        collect_source(FakeClient([response(gitlab_records(tie, tie)), response(gitlab_records(tie, tie))]), s2, {"watermark": tie}, settings, DATE)
    assert exc.value.watermark == "2026-11-02T00:00:00.001Z" and exc.value.catching_up

    for err in (FetchError("HTTP 503", retryable=True), DeadlineReached()):
        with pytest.raises(CollectionError) as exc:
            collect_source(FakeClient([response(gitlab_records("2026-11-01T00:00:00Z", "2026-11-02T00:00:00Z")), err]),
                           s2, {"watermark": "2026-10-31T00:00:00Z"}, settings, DATE)
        assert len(exc.value.items) == 2 and exc.value.watermark == "2026-11-02T00:00:00Z" and not exc.value.catching_up
    with pytest.raises(CollectionError) as exc:
        collect_source(FakeClient([FetchError("HTTP 503", retryable=True)]), s2, {"watermark": "2026-10-31T00:00:00Z"}, settings, DATE)
    assert exc.value.watermark is None

    bad_ts = [{"web_url": "https://gitlab.torproject.org/tpo/core/tor/-/issues/1", "title": "Security report", "description": "Body", "created_at": {"bad": "value"}, "updated_at": DATE}]
    assert collect_source(FakeClient([response(json.dumps(bad_ts).encode(), {"x-next-page": ""})]), source(kind="gitlab_issue"), {}, DEFAULTS["collection"], DATE)["items"][0]["published_at"] == DATE

    fb_client = FakeClient([response(b"[" * 10000 + b"]" * 10000), response(b"[]")])
    assert collect_source(fb_client, source(kind="gitlab_issue", fallback_urls=["https://mirror.example.org/issues"]), {}, DEFAULTS["collection"], DATE)["items"] == [] and len(fb_client.calls) == 2


def test_http_client_request_deadlines_and_retry_after():
    """Enforce address policy, Retry-After caps, and monotonic request deadlines in HttpClient."""
    calls, sleeps, clock = [], [], [100.0]
    settings = {**DEFAULTS["http"], "retry_attempts": 3, "backoff_base_seconds": 5}
    with HttpClient(settings, transport=httpx.MockTransport(lambda req: calls.append(req) or httpx.Response(503, content=b"busy")),
                    resolver=RESOLVER, sleep=sleeps.append, clock=lambda: clock[0]) as client:
        client.deadline = 102.0
        with pytest.raises(FetchError, match="deadline") as caught:
            client.request("GET", "https://example.org/")
        assert caught.value.retryable
        clock[0] = 103.0
        with pytest.raises(FetchError, match="deadline"):
            client.request("GET", "https://example.org/")
    assert len(calls) == 1 and sleeps == []

    calls2, sleeps2 = [], []
    settings2 = {**DEFAULTS["http"], "retry_attempts": 3, "backoff_base_seconds": 1}
    with HttpClient(settings2, transport=httpx.MockTransport(lambda req: calls2.append(req) or httpx.Response(429, headers={"Retry-After": "30"}, content=b"slow")),
                    resolver=RESOLVER, sleep=sleeps2.append, clock=lambda: 100.0) as client:
        client.deadline = 110.0
        with pytest.raises(DeadlineReached):
            client.request("GET", "https://example.org/")
        assert client.deadline_reached
    assert len(calls2) == 1 and sleeps2 == []

    respond = lambda req: httpx.Response(429, headers={"Retry-After": "30"}, content=b"slow") if req.url.path == "/primary" else httpx.Response(404, content=b"missing")
    with HttpClient(settings2, transport=httpx.MockTransport(respond), resolver=RESOLVER, sleep=lambda _: None, clock=lambda: 100.0) as client:
        client.deadline = 110.0
        with pytest.raises(DeadlineReached):
            client.request("GET", "https://example.org/primary")
        with pytest.raises(FetchError, match="404"):
            client.request("GET", "https://example.org/fallback")
        assert not client.deadline_reached


def test_run_deadlines_source_budgets_and_endpoint_circuit_breakers(tmp_path, monkeypatch):
    """Bound per-source collection and reserve analysis time within the run budget."""
    cfg = config(tmp_path)
    patch_cli_pipeline(monkeypatch, now=None, analyzer=ScriptedAnalyzer.factory(), reviewer=ApprovingReviewer,
                       collect=lambda *a: (_ for _ in ()).throw(CollectionError("request deadline reached")), no_build=False)
    monkeypatch.setattr(cli, "HttpClient", lambda *a, **kw: FakeClient([]))
    with Store(tmp_path / "state.db") as store:
        store.ingest(item(), DATE)
        res = cli.run(cfg, store)
        assert res["sources_failed"] == 1 and res["analyzed"] == 1 and store.source(cfg["sources"][0])["next_fetch_at"] is not None

    for source_budget, shared in [(600, True), (5, False)]:
        cfg_b = config(tmp_path / f"b-{source_budget}")
        cfg_b["collection"]["source_budget_seconds"] = source_budget
        cfg_b["sources"] = [source(id="first"), source(id="second", url="https://example.org/second.xml")]
        collected = []

        def collect_cut(client, stream, *args):
            """Advance fake clock during collection to exercise source budget cutoffs."""
            collected.append(stream["id"]); client.deadline_reached = True
            raise CollectionError("request deadline reached")

        patch_cli_pipeline(monkeypatch, now=None, reviewer=None, collect=collect_cut)
        with Store(cfg_b["storage"]["database"]) as store:
            rep = cli.run(cfg_b, store)
            first = store.source(cfg_b["sources"][0])
        assert bool(rep.get("budget_reached")) is shared and first["failures"] == (0 if shared else 1)
        assert collected == (["first"] if shared else ["first", "second"])

    analyzed = []
    patch_cli_pipeline(monkeypatch, analyzer=ScriptedAnalyzer.factory(lambda p: analyzed.append(p) or analysis()), reviewer=ApprovingReviewer)
    monkeypatch.setattr(cli.time, "monotonic", lambda: 10**6 if analyzed else 0.0)
    with Store(tmp_path / "deadline.db") as store:
        store.ingest(item(url="https://example.org/first", labels=["Security"]), DATE)
        store.ingest(item(url="https://example.org/second", labels=[], content="second"), DATE)
        r_dl = cli.run({**copy.deepcopy(DEFAULTS), "sources": []}, store)
        second = store.db.execute("SELECT status,attempts FROM items WHERE url=?", ("https://example.org/second",)).fetchone()
    assert r_dl["budget_reached"] and len(analyzed) == 1 and tuple(second) == ("pending", 0)
    monkeypatch.undo()


def test_two_endpoint_failures_leave_the_remaining_rows_untouched(tmp_path, monkeypatch):
    """Stop analyzing remaining queued items after consecutive retryable LLM endpoint failures."""
    patch_cli_pipeline(monkeypatch, analyzer=lambda *a, **kw: ScriptedAnalyzer(
        lambda p: (_ for _ in ()).throw(AnalysisError("Unavailable", retryable=True))), reviewer=ApprovingReviewer)
    with Store(tmp_path / "state.db") as store:
        store.ingest(item(url="https://example.org/urgent", title="Authority compromised"), DATE)
        store.ingest(item(url="https://example.org/second", title="Second update", labels=["Security"], content="second"), DATE)
        store.ingest(item(url="https://example.org/later", title="Other update", labels=[], content=""), DATE)
        cli.run({**copy.deepcopy(DEFAULTS), "sources": []}, store)
        skipped = store.db.execute("SELECT attempts,last_error,next_attempt_at FROM items WHERE url=?", ("https://example.org/later",)).fetchone()
    assert skipped["attempts"] == 0 and skipped["last_error"] is None and skipped["next_attempt_at"] is None


def test_render_failure_ownership_and_build_counts(tmp_path, monkeypatch):
    """Verify output directory ownership guards and incremental static build artifact counts."""
    cfg = config(tmp_path)
    with Store(tmp_path / "state.db") as store:
        store.source(cfg["sources"][0])
        store.source_success(cfg["sources"][0], {"url": cfg["sources"][0]["url"]}, DATE)
        store.ingest(item(), DATE)
        finish_reviewed(store, store.pending(1, DATE)[0], analysis(), "cache", DATE)
        assert build(cfg, store) == {"public_changed": True, "published_stories": 1, "stories_skipped": 0}
        before = (tmp_path / "public/index.html").read_bytes()
        assert build(cfg, store)["published_stories"] == 1 and (tmp_path / "public/index.html").read_bytes() == before
        monkeypatch.setattr("onionflash.render.index_html", lambda *a, **kw: (_ for _ in ()).throw(ValueError("simulated")))
        with pytest.raises(ValueError):
            build(cfg, store)
        assert (tmp_path / "public/index.html").read_bytes() == before
    monkeypatch.undo()

    unowned = tmp_path / "unowned"
    (unowned / "public").mkdir(parents=True)
    (unowned / "public" / "keep.txt").write_text("mine")
    with Store(unowned / "state.db") as store, pytest.raises(ValueError):
        build(config(unowned), store)
    assert (unowned / "public" / "keep.txt").read_text() == "mine"

    marker_dir = tmp_path / "marker_dir"
    (marker_dir / "public").mkdir(parents=True)
    (marker_dir / "public" / "operator-file.txt").write_text("keep")
    (marker_dir / ".public.onionflash-owner").mkdir()
    with Store(marker_dir / "state.db") as store, pytest.raises(ValueError, match="regular file"):
        build(config(marker_dir), store)
    assert (marker_dir / "public" / "operator-file.txt").read_text() == "keep"

    first, moved = tmp_path / "first", tmp_path / "moved"
    first.mkdir()
    with Store(first / "state.db") as store:
        build(config(first), store)
    first.rename(moved)
    with Store(moved / "state.db") as store:
        build(config(moved), store)
    assert (moved / "public" / "index.html").exists()

    web = tmp_path / "web"
    web_cfg = config(web)
    src = web_cfg["sources"][0]
    with Store(web / "state.db") as store:
        store.source(src)
        store.source_success(src, {"url": src["url"]}, DATE)
        state = store.source(src)
        build(web_cfg, store)
        assert f'href="{src["url"]}"' not in (web / "public/index.html").read_text()
        src["website_url"] = "https://example.org/mailing-list/"
        build(web_cfg, store)
        assert f'href="{src["website_url"]}"' in (web / "public/index.html").read_text() and store.source(src) == state

    skip_dir = tmp_path / "skipped"
    skip_cfg = config(skip_dir)
    with Store(skip_dir / "state.db") as store:
        for url in ["https://example.org/news/1", "https://example.org/news/2"]:
            store.ingest(item(url=url, content=url), DATE)
        for row in store.pending(10, DATE):
            finish_reviewed(store, row, analysis(), "key-" + row["id"], DATE)
        store.db.execute("UPDATE stories SET payload=json_set(payload, '$.priority', 'urgent') WHERE rowid=(SELECT MIN(rowid) FROM stories)")
        assert build(skip_cfg, store) == {"public_changed": True, "published_stories": 1, "stories_skipped": 1}
        assert build(skip_cfg, store) == {"public_changed": False, "published_stories": 1, "stories_skipped": 1}


def test_run_lock_and_status_commands(tmp_path, capsys):
    """Acquire exclusive run locks and report JSON status summaries via the CLI."""
    with run_lock(str(tmp_path / "db")) as first, run_lock(str(tmp_path / "db")) as second:
        assert first and not second
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text('[storage]\ndatabase = "db.sqlite3"\noutput_dir = "public"\n[[sources]]\nid = "a"\nurl = "https://example.org/feed.xml"\n')
    with run_lock(str(tmp_path / "db.sqlite3")) as held:
        assert held and main(["build", "--config", str(cfg_path)]) == 75 and main(["run", "--config", str(cfg_path)]) == 0
        capsys.readouterr()
        assert main(["status", "--config", str(cfg_path)]) == 0
        assert json.loads(capsys.readouterr().out)["sources"][0]["last_success"] is None
    with Store(tmp_path / "db.sqlite3") as store:
        assert store.db.execute("SELECT COUNT(*) FROM source_state").fetchone()[0] == 0
    writer = sqlite3.connect(tmp_path / "db.sqlite3", isolation_level=None)
    writer.execute("BEGIN IMMEDIATE")
    try:
        assert main(["status", "--config", str(cfg_path)]) == 0 and main(["rejected", "list", "--config", str(cfg_path)]) == 0
        capsys.readouterr()
    finally:
        writer.close()
    assert main(["status", "--config", str(cfg_path)]) == 0 and json.loads(capsys.readouterr().out)["published_stories"] is None
    assert main(["build", "--config", str(cfg_path)]) == 0
    capsys.readouterr()
    assert main(["status", "--config", str(cfg_path)]) == 0 and json.loads(capsys.readouterr().out)["published_stories"] == 0


@pytest.mark.parametrize("fb,env_val,match", [
    ('[""]', "   ", "fallback"),
    ('["   "]', "   ", "fallback"),
    ('["/"]', "   ", "fallback"),
    ('[123]', "   ", "fallback"),
    ('["${ONIONFLASH_LLM_FALLBACK_URL}"]', "   ", "fallback"),
    ('["${ONIONFLASH_LLM_FALLBACK_URL}"]', "", "fallback"),
    ('["http://backup.example/v1"]', "   ", "Invalid LLM base URL"),
    ('["ftp://backup.example/v1"]', "   ", "Invalid LLM base URL"),
])
def test_invalid_fallback_base_urls_rejected(tmp_path, monkeypatch, fb, env_val, match):
    """Reject non-HTTPS, private, or empty fallback LLM endpoint URLs."""
    monkeypatch.setenv("ONIONFLASH_LLM_BASE_URL", "https://model.example/v1")
    monkeypatch.setenv("ONIONFLASH_LLM_FALLBACK_URL", env_val)
    p = tmp_path / "config.toml"
    p.write_text(EXAMPLE_TOML.replace("fallback_base_urls = []", "fallback_base_urls = " + fb))
    with pytest.raises(ValueError, match=match):
        load_config(p)


def test_example_config_and_validation_guards(tmp_path, monkeypatch):
    """Validate config.example.toml and reject out-of-range or malformed TOML settings."""
    p = tmp_path / "config.toml"
    p.write_text(EXAMPLE_TOML)
    monkeypatch.setenv("ONIONFLASH_LLM_BASE_URL", "https://model.example/v1")
    cfg = load_config(p)
    assert cfg["storage"]["database"] == str(tmp_path / "state/onionflash.sqlite3") and len(cfg["sources"]) >= 10 and cfg["llm"]["fallback_base_urls"] == []
    for old, new in [("max_items_per_run = 12", "max_items_per_run = 0"), ('output_dir = "build/public"', 'output_dir = "."')]:
        p.write_text(EXAMPLE_TOML.replace(old, new))
        with pytest.raises(ValueError):
            load_config(p)
    p.write_text(EXAMPLE_TOML.replace("fallback_base_urls = []", 'fallback_base_urls = ["https://backup.example/v1/"]'))
    assert load_config(p)["llm"]["fallback_base_urls"] == ["https://backup.example/v1"]

    for bad_toml in ('site = { base_url = 123 }\n',
                     '[llm]\nbase_url = "https://llm.example/v1"\nmodel = "m"\nallowed_networks = [true]\n[[sources]]\nid = "s"\nurl = "https://example.org/feed.xml"\n'):
        p.write_text(bad_toml)
        with pytest.raises(ValueError):
            load_config(p)

    p.write_text('[[sources]]\nid = "a"\nurl = "https://example.org/feed.xml"\n')
    assert "website_url" not in load_config(p)["sources"][0]
    p.write_text('[[sources]]\nid = "t"\nkind = "metrics_timeline"\nauthority = "telemetry"\nurl = "https://gitlab.example.org/api/v4/projects/1/repository/files/README.md?ref=main"\n')
    with pytest.raises(ValueError, match="website_url"):
        load_config(p)

    cfg_t = copy.deepcopy(DEFAULTS)
    with Analyzer(cfg_t) as a1:
        assert a1.http_settings["total_timeout_seconds"] == 180
    cfg_t["llm"]["timeout_seconds"] = 240
    with Analyzer(cfg_t) as a2:
        assert a2.http_settings["total_timeout_seconds"] == 250


def test_only_operator_settings_are_configurable_and_the_rest_are_ignored(tmp_path, caplog):
    """Ignore unknown internal keys while applying documented operator configuration fields."""
    path = tmp_path / "config.toml"
    path.write_text('[collection]\nlookback_days = 3\n[http]\nretry_attempts = 7\n'
                    '[storage]\nrender_batch_size = 7\n[llm]\nmax_items_per_run = 20\nenable_thinking = true\n'
                    '[[sources]]\nid = "a"\nurl = "https://example.org/feed.xml"\n')
    with caplog.at_level("WARNING", logger="onionflash.config"):
        loaded = load_config(path)
    assert loaded["llm"]["max_items_per_run"] == 20 and loaded["llm"]["enable_thinking"] is False
    assert loaded["collection"]["lookback_days"] == DEFAULTS["collection"]["lookback_days"]
    assert loaded["http"]["retry_attempts"] == DEFAULTS["http"]["retry_attempts"]
    assert loaded["storage"]["render_batch_size"] == DEFAULTS["storage"]["render_batch_size"]
    for key in ("collection.lookback_days", "http.retry_attempts", "storage.render_batch_size", "llm.enable_thinking"):
        assert f"Ignoring setting {key}" in caplog.text
    for bad_section in ('[http]\nnot_a_setting = 1\n', '[llm]\nmax_input_chars = 5000\n',
                        '[comments]\nmax_pages = 2\n', '[site]\nfeed_size = 0\n',
                        '[storage]\nmax_stories = 1000\n', '[http]\nrequests_per_minute = 30\n',
                        '[monitoring]\nmin_reports = 2\n'):
        path.write_text(bad_section + '[[sources]]\nid = "a"\nurl = "https://example.org/feed.xml"\n')
        with pytest.raises(ValueError, match="Unknown"):
            load_config(path)


@pytest.mark.parametrize("base", ["javascript:bad", "https://example.com/x/../", "https://example.com/%2e%2e/",
                                  "https://example.com/?token=secret", "https://secret@example.com/"])
def test_bad_base_url_and_traversal_are_rejected(tmp_path, base):
    """Reject non-HTTPS site base URLs and path-traversal storage paths."""
    path = tmp_path / "config.toml"
    path.write_text(f'[site]\nbase_url = "{base}"\n[[sources]]\nid = "a"\nurl = "https://example.org/feed.xml"\n')
    with pytest.raises(ValueError, match="base_url"):
        load_config(path)


@pytest.mark.parametrize("base", ["https://example.com/news?", "https://example.com/news/#", "https://example.com/news"])
def test_base_url_is_normalized_to_a_clean_directory(tmp_path, base):
    """Normalize site.base_url to end with a single trailing slash."""
    path = tmp_path / "config.toml"
    path.write_text(f'[site]\nbase_url = "{base}"\n[[sources]]\nid = "a"\nurl = "https://example.org/feed.xml"\n')
    assert load_config(path)["site"]["base_url"] == "https://example.com/news/"


@pytest.mark.parametrize("authority", ["user:private-value＠example.org", "[user:private-value", "example.org:private-value"])
def test_base_url_parser_failures_use_only_the_redacted_diagnostic(tmp_path, authority):
    path = tmp_path / "config.toml"
    path.write_text(f'[site]\nbase_url = "https://{authority}/"\n[[sources]]\nid = "a"\nurl = "https://example.org/feed.xml"\n')
    with pytest.raises(ValueError) as caught:
        load_config(path)
    assert str(caught.value) == "site.base_url must be a clean absolute HTTP(S) URL (invalid value [redacted])"
    assert "private-value" not in str(caught.value)


def test_story_precedence_legacy_stories_and_added_at(tmp_path):
    """Preserve story source-tier upgrades, dated updates, and chronological ordering."""
    def known_update(store, url):
        # These fixtures exercise prose precedence after same-event association.
        with store.db:
            store.db.execute("UPDATE items SET story_id=? WHERE url=?", (store.stories(1)[0]["id"], url))

    def pub_arti(store, url, updated, draft, content=item()["content"]):
        """Ingest and publish a synthetic Arti story revision for precedence tests."""
        store.ingest(item(url=url, title="Arti 2.8.0 released", updated_at=updated, kind="feed", content=content, product="arti"), updated)
        if "update" in draft:
            known_update(store, url)
        finish_reviewed(store, next(r for r in store.pending(10, updated) if r["url"] == url), draft, "key-" + url + updated, updated)
        return store.stories(10)

    later, latest = "2026-11-08T13:00:00Z", "2026-11-08T14:00:00Z"
    with Store(tmp_path / "arti.db") as store:
        pub_arti(store, "https://blog.example/arti", DATE, analysis(title="Arti 2.8.0 released", confidence="confirmed", state="released"))
        stories = pub_arti(store, "https://gitlab.example/arti/1", later, update_analysis(update="Arti 2.8.0 release checklist completed.", confidence="confirmed", state="released"))
        assert len(stories) == 1 and len(stories[0]["sources"]) == 2 and (stories[0]["title"], stories[0]["confidence"]) == ("Arti 2.8.0 released", "confirmed")
        assert stories[0]["updates"][-1]["text"] == "Arti 2.8.0 release checklist completed."
        stories = pub_arti(store, "https://blog.example/arti", latest,
                           update_analysis(update="Update: the release was withdrawn.", confidence="reported", state="developing", evidence=["Update: the release was withdrawn."]),
                           content="Update: the release was withdrawn.")
        assert (stories[0]["title"], stories[0]["confidence"], stories[0]["state"]) == ("Arti 2.8.0 released", "reported", "developing")
        assert [e["text"] for e in stories[0]["updates"]] == ["Arti 2.8.0 release checklist completed.", "Update: the release was withdrawn."]

    def pub_tor(store, url, updated, draft):
        """Ingest and publish a synthetic Tor story revision for precedence tests."""
        store.ingest(item(url=url, title="Tor 0.4.9.17 released", updated_at=updated, kind="feed", content=url), updated)
        if "update" in draft:
            known_update(store, url)
        finish_reviewed(store, next(r for r in store.pending(10, updated) if r["url"] == url), draft, "k" + url, updated)
        return store.stories(10)[0]

    with Store(tmp_path / "prec.db") as store:
        first = pub_tor(store, "https://a.example/1", DATE, analysis(title="A", confidence="confirmed", state="released"))
        writer_id = first["editorial_item"]
        s1 = pub_tor(store, "https://b.example/1", "2026-11-08T15:00:00Z", update_analysis(update="Follow-up B.", confidence="confirmed", state="released", evidence=["https://b.example/1"]))
        assert (s1["title"], s1["updated_at"], s1["editorial_item"]) == ("A", "2026-11-08T15:00:00Z", writer_id)
        s2 = pub_tor(store, "https://c.example/1", later, update_analysis(update="Follow-up C.", confidence="confirmed", state="released", evidence=["https://c.example/1"]))
        assert (s2["title"], s2["updated_at"], s2["editorial_item"]) == ("A", "2026-11-08T15:00:00Z", writer_id) and [e["text"] for e in s2["updates"]] == ["Follow-up B.", "Follow-up C."]

    legacy = {**analysis(title="Tor 0.4.9.18 released"), "id": "legacy000000000000000000", "published_at": DATE,
              "updated_at": "2026-11-08T15:00:00Z", "sources": [{"id": "old", "url": "https://old.example/1", "title": "Old", "published_at": DATE}]}
    legacy.pop("evidence")
    with Store(tmp_path / "legacy.db") as store:
        store.ingest(item(url="https://old.example/1", title=legacy["title"], kind="feed", content="The original Tor release announcement.", updated_at=legacy["updated_at"]), DATE)
        old_row = store.pending(1, DATE)[0]
        legacy["sources"][0]["id"] = old_row["id"]
        store.db.execute("UPDATE items SET status='published',story_id=? WHERE id=?", (legacy["id"], old_row["id"]))
        store.db.execute("INSERT INTO stories VALUES(?,?,?,?,?)", (legacy["id"], item_cluster(item(title="Tor 0.4.9.18 released", kind="feed")), json.dumps(legacy), DATE, legacy["updated_at"]))
        for idx, stamp in enumerate([later, latest]):
            store.ingest(item(url=f"https://new.example/{idx}", title="Tor 0.4.9.18 released", kind="feed", content=f"Follow-up {idx} notes.", updated_at=stamp), stamp)
            known_update(store, f"https://new.example/{idx}")
            finish_reviewed(store, next(r for r in store.pending(10, stamp) if r["url"].endswith(str(idx))),
                            update_analysis(update=f"Item {idx}.", evidence=[f"Follow-up {idx} notes."]), f"k{idx}", stamp)
        ls = store.stories(10)[0]
        assert ls["title"] == "Tor 0.4.9.18 released" and len(ls["sources"]) == 3 and [e["text"] for e in ls["updates"]] == ["Item 0.", "Item 1."]

    url19 = "https://blog.example/tor-0.4.9.19"
    with Store(tmp_path / "single.db") as store:
        store.ingest(item(url=url19, title="Tor 0.4.9.19 released", kind="feed"), DATE)
        row = store.pending(1, DATE)[0]
        leg19 = {**analysis(title="Tor 0.4.9.19 released", confidence="confirmed", state="released"), "id": "legacy111111111111111111",
                 "published_at": DATE, "updated_at": DATE, "sources": [{"id": row["id"], "url": url19, "title": "x", "published_at": DATE}]}
        leg19.pop("evidence")
        store.db.execute("INSERT INTO stories VALUES(?,?,?,?,?)", (leg19["id"], row["cluster_key"], json.dumps(leg19), DATE, DATE))
        store.ingest(item(url=url19, title="Tor 0.4.9.19 released", kind="feed", content="The release was withdrawn.", updated_at=later), later)
        finish_reviewed(store, store.pending(1, later)[0], update_analysis(update="The release was withdrawn.", confidence="confirmed", state="developing", evidence=["The release was withdrawn."]), "k", later)
        s19 = store.stories(1)[0]
        assert s19["title"] == "Tor 0.4.9.19 released" and s19["editorial_item"] == row["id"]
        assert s19["updates"] == [{"at": later, "text": "The release was withdrawn.", "sources": [{"url": url19, "title": "Tor 0.4.9.19 released"}]}]

    with Store(tmp_path / "added.db") as store:
        store.ingest(item(published_at="2026-09-22T12:00:00Z", updated_at="2026-11-09T12:00:00Z"), "2026-11-09T12:00:00Z")
        finish_reviewed(store, store.pending(1, "2026-11-09T12:00:00Z")[0], analysis(), "key", "2026-11-09T12:00:00Z")
        assert (store.stories()[0]["published_at"], store.stories()[0]["added_at"]) == ("2026-09-22T12:00:00Z", "2026-11-09T12:00:00Z")


@pytest.mark.parametrize("title,kind,product,expected", [
    ("New Release: Tor Browser 16.0", "feed", "network", "release:tor-browser:16.0"),
    ("Tor Browser 16.0 is released", "feed", "network", "release:tor-browser:16.0"),
    ("New Alpha Release: Tor Browser 16.0a14", "feed", "network", "release:tor-browser:16.0a14"),
    ("Tor 0.4.9.16 is released", "feed", "network", "release:tor:0.4.9.16"),
    ("Tor 0.5.0.1-alpha is released", "feed", "network", "release:tor:0.5.0.1-alpha"),
    ("New Release: Tor Browser 15.0.26", "feed", "network", "release:tor-browser:15.0.26"),
    ("tor-0.4.9.16", "tag", "network", "release:tor:0.4.9.16"),
    ("arti-v2.8.0", "tag", "network", "release:arti:2.8.0"),
    ("tor-browser-16.0.4", "tag", "tor-browser", "release:tor-browser:16.0.4"),
    ("Tor Browser 16.0-alpha.1 released", "feed", "network", "release:tor-browser:16.0-alpha.1"),
    ("Tor Browser 16.0-alpha.2 released", "feed", "network", "release:tor-browser:16.0-alpha.2"),
    ("[tor-announce] [RELEASE] Tor release 0.4.9.17", "feed", "network", "release:tor:0.4.9.17"),
    ("tor-0.4.9.17", "tag", "network", "release:tor:0.4.9.17"),
    ("Tor stable release 1.2.3", "feed", "network", "release:tor:1.2.3"),
    ("New Tor stable release 0.4.8.19", "feed", "network", "release:tor:0.4.8.19"),
    ("Arti 1.7.0 is now available", "feed", "network", "release:arti:1.7.0"),
    ("Arti 1.8.0 is released after being postponed", "feed", "network", "release:arti:1.8.0"),
    ("New Release: Tor Browser 15.0.3 (fixes a startup delay)", "feed", "network", "release:tor-browser:15.0.3"),
    *[(f"Tor {q} 1.2.3 released", "feed", "network", "release:tor:1.2.3") for q in ("new", "stable", "alpha", "beta", "security", "bugfix", "release", "version")],
    *[(t, "feed", "network", "url:") for t in (
        "Tor Browser for Ubuntu 24.04: 15.0.26 released", "Tails 7.16 released with Tor Browser 16.0 and Tor 0.4.9.15",
        "Tor release 0.4.9.17 delayed", "Tor 0.4.9.17 release postponed", "Tor 0.4.8 is out of support",
        "Tor 0.4.9.16 packages available for Debian", "Tor Browser 15.0 is no longer available on older systems",
    )],
])
def test_release_clusters_include_two_part_versions_and_alpha_suffixes(title, kind, product, expected):
    """Cluster product release announcements while keeping delays and EOL notices separate."""
    cluster = item_cluster({"title": title, "kind": kind, "product": product, "content": "", "url": "https://example.org/" + title})
    assert cluster.startswith("url:") if expected == "url:" else cluster == expected


def test_feed_item_titles_dates_and_non_permalink_guids():
    """Normalize HTML/plain feed titles, clamp future dates, and skip non-permalink GUIDs."""
    stream = source(kind="gitlab_issue")
    assert _item(stream, "https://example.org/1", "Use Vec<u8> instead of String", "", DATE, DATE, title_html=False)["title"] == "Use Vec<u8> instead of String"
    assert _item(stream, "https://example.org/2", "A <b>bold</b> claim", "", DATE, DATE)["title"] == "A bold claim"
    assert _item(stream, "https://example.org/3", "t", "", DATE, DATE, labels=["ok", "\ud800bad"])["labels"] == ["ok", "\ufffdbad"]

    atom_xml = (b'<feed xmlns="http://www.w3.org/2005/Atom"><title>T</title><id>urn:t</id><updated>2026-11-08T12:00:00Z</updated>'
                b'<entry><title type="xhtml"><div xmlns="http://www.w3.org/1999/xhtml">A <b>bold</b> title</div></title>'
                b'<link href="https://example.org/a"/><id>urn:a</id><updated>2026-11-08T12:00:00Z</updated></entry>'
                b'<entry><title type="text">Use Vec&lt;u8&gt; here</title>'
                b'<link href="https://example.org/b"/><id>urn:b</id><updated>2026-11-08T11:00:00Z</updated></entry></feed>')
    assert [r["title"] for r in collect_source(FakeClient([response(atom_xml)]), source(), {}, DEFAULTS["collection"], DATE)["items"]] == ["A bold title", "Use Vec<u8> here"]

    long_title = "Use Vec<u8> " + "x" * 600
    long_xml = ('<feed xmlns="http://www.w3.org/2005/Atom"><title>T</title><id>urn:t</id><updated>2026-11-08T12:00:00Z</updated>'
                f'<entry><title type="text">{long_title.replace("<", "&lt;").replace(">", "&gt;")}</title>'
                '<link href="https://example.org/a"/><id>urn:a</id><updated>2026-11-08T12:00:00Z</updated></entry></feed>').encode()
    assert "Use Vec<u8>" in collect_source(FakeClient([response(long_xml)]), source(), {}, DEFAULTS["collection"], DATE)["items"][0]["content"]
    clamped = _item(source(), "https://example.org/1", "t", "", "2062-01-01T00:00:00Z", "2062-01-01T00:00:00Z", observed=DATE)
    assert (clamped["published_at"], clamped["updated_at"]) == (DATE, DATE)

    guid_xml = (b'<rss version="2.0"><channel><title>T</title><link>https://example.org/</link><description>D</description>'
                b'<item><title>No link</title><guid isPermaLink="false">https://example.org/?p=123</guid>'
                b'<pubDate>Sun, 08 Nov 2026 12:00:00 GMT</pubDate></item></channel></rss>')
    assert collect_source(FakeClient([response(guid_xml)]), source(), {}, DEFAULTS["collection"], DATE)["items"] == []


def test_configured_forum_announcements_keep_operational_context(tmp_path, monkeypatch):
    monkeypatch.setenv("ONIONFLASH_LLM_BASE_URL", "https://model.example/v1")
    path = tmp_path / "config.toml"
    path.write_text(EXAMPLE_TOML)
    stream = next(s for s in load_config(path)["sources"] if s["id"] == "tor-release-announcements")
    assert stream["enabled"] and stream["kind"] == "feed"
    assert stream["authority"] == "official" and stream["product"] == "tor"
    assert stream["url"] == "https://forum.torproject.org/c/news/tor-release-announcement/28.rss"

    url = "https://forum.torproject.org/t/security-release-0-4-9-17/22454"
    # Discourse category RSS shape, with paraphrased announcement text.
    xml = (f'<rss version="2.0" xmlns:dc="http://purl.org/dc/elements/1.1/">'
           f'<channel><title>Tor Release Announcement</title><link>{stream["website_url"]}</link>'
           '<description>Release announcements</description><item><title>Security Release 0.4.9.17</title>'
           f'<link>{url}</link><dc:creator><![CDATA[dgoulet]]></dc:creator>'
           '<pubDate>Fri, 13 Nov 2026 19:35:15 +0000</pubDate>'
           '<guid isPermaLink="false">forum.torproject.org-topic-22454</guid><description><![CDATA['
           '<p>The release improves IPv6-related relay DoS protections.</p>'
           '<p>The ongoing circuit flood affects relay operators across the network.</p>'
           '<p>Additional defenses are being assessed, with further releases expected soon.</p>'
           '<p><strong>Relay operators are asked to upgrade promptly.</strong> No subsequent action is requested.</p>'
           '<p><small>1 post - 1 participant</small></p>'
           f'<p><a href="{url}">Read full topic</a></p>]]></description></item></channel></rss>').encode()
    result = collect_source(FakeClient([response(xml, url=stream["url"])]), stream, {}, DEFAULTS["collection"],
                            "2026-11-15T12:00:00Z")
    assert len(result["items"]) == 1
    entry = result["items"][0]
    assert entry["url"] == url and entry["title"] == "Security Release 0.4.9.17"
    assert entry["published_at"] == entry["updated_at"] == "2026-11-13T19:35:15Z"
    assert entry["authority"] == "official" and entry["product"] == "tor"
    for text in ("The ongoing circuit flood affects relay operators across the network.",
                 "Additional defenses are being assessed, with further releases expected soon.",
                 "Relay operators are asked to upgrade promptly.", "No subsequent action is requested."):
        assert text in entry["content"]
    # The same author and host on an ordinary community stream confer no authority.
    community = {**stream, "authority": "community"}
    assert collect_source(FakeClient([response(xml, url=stream["url"])]), community, {}, DEFAULTS["collection"],
                          "2026-11-15T12:00:00Z")["items"][0]["authority"] == "community"


def _list_rss(*author_xml: str) -> bytes:
    entries = "".join(f'<item><title>Message {n}</title><link>https://lists.torproject.org/m/{n}/</link>'
                      f'<description>Body</description>{xml}<pubDate>Sun, 08 Nov 2026 12:00:00 GMT</pubDate></item>'
                      for n, xml in enumerate(author_xml, 1))
    return ('<?xml version="1.0" encoding="utf-8"?><rss version="2.0" xmlns:dc="http://purl.org/dc/elements/1.1/" '
            'xmlns:itunes="http://www.itunes.com/dtds/podcast-1.0.dtd"><channel>'
            f'<title>tor-dev</title><link>https://lists.torproject.org/</link><description>List</description>{entries}'
            '</channel></rss>').encode()


def _collected_items(body: bytes, *, src_url: str = LIST_URL, final_url: str = LIST_URL, authority: str = "community"):
    return collect_source(FakeClient([Response(200, body, {}, final_url)]), source(url=src_url, authority=authority), {}, DEFAULTS["collection"], DATE)["items"]


def test_a_torproject_org_sender_on_the_list_archive_is_project_sender():
    """Classify verified HyperKitty @torproject.org RSS authors as project-sender."""
    items = _collected_items(_list_rss(
        "<author>dev＠torproject.org (A Developer)</author>",
        "<author>Dev.Name+x_1-2＠TorProject.ORG</author>",
        "<author>member＠example.org (Community Member)</author>",
    ))
    assert [e["authority"] for e in items] == ["project-sender", "project-sender", "community"]
    assert all("dev@torproject.org" not in json.dumps(e).lower() and "＠" not in json.dumps(e) for e in items)
    assert _collected_items(_list_rss("<author>dev＠torproject.org (Dev)</author>"), src_url="https://example.org/feed.xml", final_url=LIST_URL)[0]["authority"] == "project-sender"
    assert _collected_items(_list_rss("<author>dev＠torproject.org (Dev)</author>"), src_url=LIST_URL, final_url="https://example.org/feed.xml")[0]["authority"] == "community"
    assert [e["authority"] for e in _collected_items(_list_rss("<author>dev＠torproject.org (Dev)</author>", "<author>member＠example.org (Member)</author>"), authority="official")] == ["official", "official"]

    criteria = {name: {"reason": "Supported.", "source_refs": ["S1P1"], "outcome": "pass"} for name in review.CRITERIA}
    criteria["news_value"] = {"reason": "Routine reply.", "source_refs": ["S1P1"], "outcome": "fail"}
    first = {"stage": "review", "candidate_hash": "h", "result": {"verdict": "skip", "criteria": criteria, "same_story": None, "repair": None}}
    prepared = {"row": {"payload": json.dumps(items[0])}, "payload": {"editorial_kind": "feed"},
                "packet": {"sources": [{**items[0], "passages": [{"ref": "S1P1", "text": "Body"}]}]}, "coverage": {}}
    assert review_gate.next_step([first], analysis(), prepared)[0] == "verify"
    assert "confirmed_source" in review.final_holds(analysis(confidence="confirmed"), prepared)


@pytest.mark.parametrize("author_entries,final_url", [
    (["<author>mallory＠example.org (dev@torproject.org)</author>"], LIST_URL),
    (["<author>mallory＠example.org (Dev &lt;dev＠torproject.org&gt;)</author>"], LIST_URL),
    (["<author>dev＠torproject.org.example.org (Dev)</author>"], LIST_URL),
    (["<author>dev＠example-torproject.org (Dev)</author>"], LIST_URL),
    (["<author>alert＠monitor.torproject.org (Alert)</author>"], LIST_URL),
    (["<author>tor-dev＠lists.torproject.org (Dev via tor-dev)</author>"], LIST_URL),
    (["<author>dev%example.org＠torproject.org (Dev)</author>"], LIST_URL),
    (["<author>a＠torproject.org＠example.org (Dev)</author>"], LIST_URL),
    (["<author>dev@torproject.org (Dev)</author>"], LIST_URL),
    (["<author>dev＠torprоject.org (Dev)</author>"], LIST_URL),
    (["<author>Kate＠torproject.org (Kate)</author>"], LIST_URL),
    (["<author>Real Dev dev＠torproject.org (Dev)</author>"], LIST_URL),
    (["<author>dev＠torproject.org(Dev)</author>"], LIST_URL),
    (["<dc:creator>dev@torproject.org</dc:creator>"], LIST_URL),
    (["<dc:creator>dev＠torproject.org</dc:creator>"], LIST_URL),
    (["<dc:creator>dev＠torproject.org (Real Dev)</dc:creator>"], LIST_URL),
    (["<author>dev＠torproject.org (Dev)</author>", "<author>Plain Name</author>"], LIST_URL),
    (["<author>dev＠torproject.org (Dev)</author>", "<dc:creator>Plain Name</dc:creator>"], LIST_URL),
    (["<author>mallory＠example.org (M)</author><author>dev＠torproject.org (Dev)</author>"], LIST_URL),
    (["<author>mallory＠example.org (M)</author><dc:creator>dev＠torproject.org (Dev)</dc:creator>"], LIST_URL),
    (["<author>mallory＠example.org (M)</author><dc:author>dev＠torproject.org (Dev)</dc:author>"], LIST_URL),
    (["<author>mallory＠example.org (M)</author><dc:author>Plain Name</dc:author>", "<author>dev＠torproject.org (Dev)</author>"], LIST_URL),
    (["<author>mallory＠example.org (M)</author><itunes:author>dev＠torproject.org (Dev)</itunes:author>"], LIST_URL),
    (["<author>mallory＠example.org (M)</author><managingEditor>dev＠torproject.org (Dev)</managingEditor>"], LIST_URL),
    (["<Author>dev＠torproject.org (Dev)</Author>"], LIST_URL),
    (["<author><name>dev＠torproject.org</name><email>mallory@example.org</email></author>"], LIST_URL),
    (["<author>dev＠torproject.org<span/></author>"], LIST_URL),
    (["<author>dev＠torproject.org (Dev)</author>"], "https://example.org/feed.xml"),
    (["<author>dev＠torproject.org (Dev)</author>"], "https://lists.torproject.org.example.org/feed/"),
])
def test_names_lookalikes_and_other_hosts_never_make_a_sender_project_sender(author_entries, final_url):
    """Reject spoofed display names, homoglyphs, subdomains, and non-HyperKitty hosts."""
    assert all(e["authority"] == "community" for e in _collected_items(_list_rss(*author_entries), final_url=final_url))


def test_atom_and_namespaced_items_never_make_a_sender_project_sender():
    """Keep Atom and mixed-namespace feed entries at community authority."""
    atom = (b'<feed xmlns="http://www.w3.org/2005/Atom"><title>T</title><id>urn:t</id><updated>2026-11-08T12:00:00Z</updated>'
            b'<entry><title>Msg</title><link href="https://lists.torproject.org/m/1/"/><id>urn:1</id>'
            b'<updated>2026-11-08T12:00:00Z</updated><author><name>dev\xef\xbc\xa0torproject.org</name>'
            b'<email>mallory@example.org</email></author></entry></feed>')
    mixed = (b'<rss version="2.0" xmlns:dc="http://purl.org/dc/elements/1.1/"><channel><title>T</title>'
             b'<link>https://lists.torproject.org/</link><description>D</description>'
             b'<item xmlns="http://purl.org/dc/elements/1.1/"><author>dev\xef\xbc\xa0torproject.org (Dev)</author></item>'
             b'<entry><title>Msg</title><link>https://lists.torproject.org/m/1/</link>'
             b'<dc:creator>dev\xef\xbc\xa0torproject.org (Dev)</dc:creator></entry></channel></rss>')
    assert all(_collected_items(raw) == [{**_collected_items(raw)[0], "authority": "community"}] for raw in (atom, mixed))


@pytest.mark.parametrize("error, where", [(RuntimeError("unexpected parser crash"), "RuntimeError at test_core.py:"),
                                          (CollectionError("unexpected parser crash", [{"title": "No URL"}]), "KeyError at ")])
def test_an_unexpected_source_error_is_recorded_and_other_sources_still_run(tmp_path, monkeypatch, error, where):
    """Sanitize unexpected collector exceptions while continuing other configured sources."""
    cfg = config(tmp_path, sources=[source(id="broken", url="https://broken.example/feed.xml"), source(id="fine")])
    patch_cli_pipeline(monkeypatch, now=None, reviewer=None,
                       collect=lambda client, stream, *args: (_ for _ in ()).throw(error) if stream["id"] == "broken" else {"items": [], "url": stream["url"]})
    with Store(tmp_path / "state.db") as store:
        report = cli.run(cfg, store)
        broken = store.source(cfg["sources"][0])
    assert report["sources_failed"] == 1 and report["sources_ok"] == 1
    assert broken["error"].startswith("Unexpected " + where) and "parser crash" not in broken["error"] and broken["failures"] == 1


@pytest.mark.parametrize("bad_raw", [
    damaged("{}", "nested"), b'{"x":"\\ud800"}', None, b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}',
    b'{"x":23456789012E666}', b'{"x":-23456789012E666}',
])
def test_a_saved_object_nests_at_most_the_cap_and_holds_no_lone_surrogate(bad_raw):
    """Reject over-deep JSON structures, non-finite numbers, and lone surrogates in saved_object."""
    within = b'{"x":' + b"[" * (MAX_SAVED_DEPTH - 1) + b"]" * (MAX_SAVED_DEPTH - 1) + b"}"
    assert saved_object(within) is not None and saved_object(b'{"x":"\\ud83d\\ude00"}') == {"x": "\U0001f600"}
    assert saved_object(bad_raw) is None
    if bad_raw in (b'{"x":23456789012E666}', b'{"x":-23456789012E666}'):
        assert saved_object(bad_raw, allow_surrogates=True) is None


def test_number_sources_assigns_sequential_ids_over_caller_keys():
    """Overwrite caller-supplied IDs with sequential S<i> and S<i>:P<j> identifiers."""
    from onionflash.source_packet import number_sources

    numbered = number_sources([({"id": "custom", "url": "https://example.org/a"}, [{"id": "P99", "text": "body"}])])
    assert numbered[0]["id"] == "S1" and numbered[0]["passages"][0]["id"] == "S1:P1"


@pytest.mark.parametrize("kind", [*DAMAGE, "blob", "undated"])
def test_collection_replaces_a_damaged_saved_copy(store, caplog, kind):
    """Heal damaged saved item payloads during collection without spurious re-queueing."""
    entry = lambda **kw: item(kind="feed", **kw)
    store.ingest(entry(), DATE)
    item_id = store.db.execute("SELECT id FROM items").fetchone()[0]
    store.db.execute("UPDATE items SET status='dismissed'")
    damage_item(store.db, item_id, kind)
    assert not store.ingest(entry(), DATE)
    assert tuple(store.db.execute("SELECT status,typeof(payload),json_extract(payload,'$.id') FROM items").fetchone()) == ("dismissed", "text", item_id)
    damage_item(store.db, item_id, kind)
    assert store.ingest(entry(content="A later account.", updated_at="2026-11-01T00:00:00Z"), DATE)
    assert json.loads(store.pending(1, DATE)[0]["payload"])["content"] == "A later account." and caplog.text.count("Replacing damaged saved item") == 2


@pytest.mark.parametrize("kind", [*DAMAGE, "blob"])
def test_pending_reports_a_damaged_saved_copy_without_reading_or_changing_it(store, kind):
    """Return damaged markers from Store.pending without mutating database rows."""
    store.ingest(item(url="https://example.org/damaged"), DATE)
    store.ingest(item(url="https://example.org/intact", content="An intact report."), DATE)
    damaged_id, intact_id = (store.db.execute("SELECT id FROM items WHERE url=?", (u,)).fetchone()[0] for u in ("https://example.org/damaged", "https://example.org/intact"))
    damage_item(store.db, damaged_id, kind)
    before = store.db.execute("SELECT status,attempts,rejections,last_error,next_attempt_at FROM items ORDER BY id").fetchall()
    rows = {r["id"]: r for r in store.pending(10, DATE)}
    assert rows[damaged_id] == {"id": damaged_id, "damaged": True} and rows[intact_id]["url"] == "https://example.org/intact"
    assert store.db.execute("SELECT status,attempts,rejections,last_error,next_attempt_at FROM items ORDER BY id").fetchall() == before


@pytest.mark.parametrize("kind", ["invalid-utf8", "blob", "escaped-surrogate"])
def test_a_run_rejects_a_damaged_pending_item_without_a_model_call_and_still_builds(context, monkeypatch, kind):
    """Mark damaged pending items rejected during cli.run and complete static site builds."""
    cfg, store = context
    cfg["sources"] = []
    writer = ScriptedAnalyzer()
    patch_cli_pipeline(monkeypatch, now=None, analyzer=lambda *a, **kw: writer, reviewer=ApprovingReviewer, no_build=False)
    store.ingest(item(url="https://example.org/damaged"), DATE)
    store.ingest(item(url="https://example.org/intact", content="An intact report."), DATE)
    damaged_id = store.db.execute("SELECT id FROM items WHERE url='https://example.org/damaged'").fetchone()[0]
    store.defer(damaged_id, "LLM request failed (HTTP 503)", cfg["llm"], DATE)
    damage_item(store.db, damaged_id, kind)
    report = cli.run(cfg, store)
    assert tuple(store.db.execute("SELECT status,last_error,next_attempt_at FROM items WHERE id=?", (damaged_id,)).fetchone()) == ("rejected", "Stored source item is damaged", None)
    assert len(store.stories()) == 1 and (report["analyzed"], report["analysis_failed"], report["rejected_analysis"], len(writer.calls)) == (1, 1, 1, 1)
    assert (Path(cfg["storage"]["output_dir"]) / "index.html").exists()


@pytest.mark.parametrize("kind", ["invalid-json", "invalid-utf8"])
def test_a_partial_collection_with_a_damaged_saved_copy_still_analyzes_and_builds(context, monkeypatch, kind):
    """Ingest partial collection items and heal damaged rows when a source hits a deadline."""
    cfg, store = context
    collected = [item(url="https://example.org/damaged", content="A changed report."), item(url="https://example.org/next")]
    patch_cli_pipeline(monkeypatch, now=None, analyzer=ScriptedAnalyzer.factory(), reviewer=ApprovingReviewer,
                       collect=lambda *a: (_ for _ in ()).throw(CollectionError("request deadline reached", collected)), no_build=False)
    monkeypatch.setattr(cli, "HttpClient", lambda *a, **kw: FakeClient([]))
    store.ingest(item(url="https://example.org/damaged"), DATE)
    damage_item(store.db, store.db.execute("SELECT id FROM items").fetchone()[0], kind)
    result = cli.run(cfg, store)
    assert (result["sources_failed"], result["items_changed"], result["analyzed"]) == (1, 2, 2)


def test_trusted_operator_domains_defaults_overrides_and_validation(tmp_path):
    """Validate default, custom, normalized, and malformed trusted_operator_domains lists."""
    assert DEFAULTS["collection"]["trusted_operator_domains"] == [
        "1aeo.com", "applied-privacy.net", "appliedprivacy.net", "artikel10.org",
        "dfri.se", "nothingtohide.nl", "prsv.ch", "quintex.com", "unredacted.org",
    ]
    path = tmp_path / "config.toml"
    src_toml = '[[sources]]\nid = "a"\nurl = "https://example.org/feed.xml"\n'
    path.write_text(src_toml)
    assert load_config(path)["collection"]["trusted_operator_domains"] == DEFAULT_TRUSTED_OPERATOR_DOMAINS

    path.write_text(
        '[collection]\ntrusted_operator_domains = ["  Example.NET ", "ops.example.org", "example.net", "torproject.org"]\n'
        + src_toml
    )
    assert load_config(path)["collection"]["trusted_operator_domains"] == ["example.net", "ops.example.org"]

    path.write_text('[collection]\ntrusted_operator_domains = "1aeo.com"\n' + src_toml)
    with pytest.raises(ValueError, match="trusted_operator_domains must be an array"):
        load_config(path)

    long_domain = ("a" * 60 + ".") * 4 + "aaaaaa.org"
    for bad in (
        "[123]", '[""]', '["   "]', '["localhost"]', '["-bad.org"]', '["bad-.org"]',
        '["a..org"]', '["https://1aeo.com"]', '["ops@1aeo.com"]', '["1äeo.com"]',
        f'["{long_domain}"]', json.dumps([f"op{n}.example.org" for n in range(501)]),
    ):
        path.write_text(f"[collection]\ntrusted_operator_domains = {bad}\n" + src_toml)
        with pytest.raises(ValueError, match="trusted_operator_domains"):
            load_config(path)


def test_trusted_operator_sender_authority_and_spoofing_guards():
    """Assign trusted-operator and sender_domain only to verified HyperKitty domains."""
    items = _collected_items(_list_rss(
        "<author>tor＠1aeo.com (Operator One)</author>",
        "<author>tor＠appliedprivacy.net (Operator Two)</author>",
        "<author>ops＠relays.applied-privacy.net (Subdomain Ops)</author>",
        "<author>dev＠torproject.org (Project Dev)</author>",
        "<author>attacker＠example.org (1aeo.com)</author>",
        "<author>attacker＠example.org (tor＠appliedprivacy.net)</author>",
        "<author>attacker＠1aeo.com.example.org (Ops)</author>",
        "<author>attacker＠not-1aeo.com (Ops)</author>",
        "<author>member＠example.org (Member)</author>",
    ))
    assert [entry["authority"] for entry in items] == [
        "trusted-operator", "trusted-operator", "trusted-operator", "project-sender",
        "community", "community", "community", "community", "community",
    ]
    assert [entry.get("sender_domain") for entry in items] == [
        "1aeo.com", "appliedprivacy.net", "relays.applied-privacy.net", "torproject.org",
        None, None, None, None, None,
    ]
    assert all("tor@1aeo.com" not in json.dumps(entry).lower() and "＠" not in json.dumps(entry) for entry in items)
    assert all("1aeo.com" not in json.dumps(entry).lower() for entry in items[4:])
    assert _collected_items(_list_rss("<author>attacker＠example.org (tor@appliedprivacy.net)</author>"))[0]["authority"] == "community"

    spoof_body = (
        '<?xml version="1.0" encoding="utf-8"?><rss version="2.0"><channel>'
        '<title>tor-relays</title><link>https://lists.torproject.org/</link><description>List</description>'
        '<item><title>Report from 1aeo.com</title><link>https://lists.torproject.org/m/99/</link>'
        '<description>From: tor@1aeo.com and tor@appliedprivacy.net</description>'
        '<author>attacker＠example.org (1aeo.com)</author>'
        '<pubDate>Sun, 08 Nov 2026 12:00:00 GMT</pubDate></item></channel></rss>'
    ).encode()
    assert _collected_items(spoof_body)[0]["authority"] == "community"
    assert _collected_items(_list_rss("<author>tor＠1aeo.com (Ops)</author>"), final_url="https://example.org/feed.xml")[0]["authority"] == "community"
    assert _collected_items(_list_rss("<author>tor＠1aeo.com (Ops)</author>"), authority="official")[0]["authority"] == "official"
    assert collect._sender_authority("dev＠torproject.org (Dev)", ["torproject.org", "1aeo.com"]) == "project-sender"
    assert collect._sender_authority("ops＠.1aeo.com (Ops)", ["1aeo.com"]) is None
    assert collect._sender_authority("operator＠ops.xn--p1ai (Operator)", ["ops.xn--p1ai"]) == "trusted-operator"
    assert collect._sender_authority("operator＠sub.ops.xn--p1ai (Operator)", ["ops.xn--p1ai"]) == "trusted-operator"
    assert collect._sender_authority("operator＠ops.xn--p1ai (Operator)", ["1aeo.com"]) is None
    punycode_collection = {**DEFAULTS["collection"], "trusted_operator_domains": ["ops.xn--p1ai"]}
    punycode_items = collect_source(
        FakeClient([Response(200, _list_rss("<author>operator＠ops.xn--p1ai (Operator)</author>"), {}, LIST_URL)]),
        source(url=LIST_URL, authority="community"),
        {},
        punycode_collection,
        DATE,
    )["items"]
    assert punycode_items[0]["authority"] == "trusted-operator"


@pytest.mark.parametrize("broken_patch", [
    {"title": 123},
    {"content": None},
    {"source_content": 99},
    {"author": 123},
    {"sender_domain": 123},
    {"comments_truncated": "yes"},
    {"labels": "Security"},
    {"labels": [123]},
    {"public_comments": "not-a-list"},
    {"public_comments": [123]},
    {"public_comments": [{"author": "op"}]},
    {"public_comments": [{"author": None, "created_at": DATE, "body": "note"}]},
    {"dirauth_notes": "not-a-list"},
    {"dirauth_notes": [{"author": "stefani", "created_at": DATE}]},
])
def test_ingest_replaces_saved_items_with_damaged_fields_or_comments(store, caplog, broken_patch):
    """Replace saved items containing malformed scalar, comment, or dirauth_notes fields."""
    entry = lambda **kw: item(kind="gitlab_issue", **kw)
    store.ingest(entry(), DATE)
    row = store.db.execute("SELECT id, payload FROM items").fetchone()
    damaged_payload = json.dumps({**json.loads(row["payload"]), **broken_patch})
    store.db.execute("UPDATE items SET status='dismissed', payload=? WHERE id=?", (damaged_payload, row["id"]))
    assert not store.ingest(entry(), DATE)
    assert store.db.execute("SELECT status FROM items WHERE id=?", (row["id"],)).fetchone()[0] == "dismissed"
    store.db.execute("UPDATE items SET payload=? WHERE id=?", (damaged_payload, row["id"]))
    assert store.ingest(entry(content="Updated intact description.", updated_at="2026-11-09T00:00:00Z"), DATE)
    assert json.loads(store.pending(1, DATE)[0]["payload"])["content"] == "Updated intact description."
    assert caplog.text.count("Replacing damaged saved item") == 2
