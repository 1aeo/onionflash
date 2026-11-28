"""Core unit tests for text normalization, URLs, storage, collection, tags, and config."""

import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import threading
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from helpers import (
    DAMAGE, DATE, LATER, ApprovingReviewer, FakeClient, FakeLLM, Writer, analysis, completion, damage_item,
    damaged, finish_reviewed, invoke_cli, item, job, job_record, list_rss, make_config, patch_cli_pipeline, pending,
    public_dns, publish_stories, queued_row, raise_once, response, seed_story, source, tag, update_analysis,
    verdict, write_toml,
)
from onionflash import cli, collect, comments, editorial, llm, review, review_gate
from onionflash.analyze import SCHEMA, AnalysisError, Analyzer, tag_notice, validate_analysis
from onionflash.cli import build, run_lock
from onionflash.collect import CollectionError, collect_source
from onionflash.config import DEFAULT_TRUSTED_OPERATOR_DOMAINS, DEFAULTS, _clean_endpoint_url, load_config
from onionflash.llm import CompletionClient, is_quoted_list_post, json_object, unquoted_mail_text
from onionflash.source_packet import number_sources
from onionflash.store import PT_SECURITY_PRIORITY, Store, backup_database, item_priority, source_due
from onionflash.transport import DeadlineReached, FetchError, HttpClient, Response
from onionflash.util import (
    MAX_SAVED_DEPTH, after, backoff_seconds, canonical_url, format_utc, gitlab_refs, item_cluster,
    is_official_release_announcement, mandatory_news_rule, parse_utc, plain_text, saved_object,
    software_from_url, timestamp,
)

LIST_URL = "https://lists.torproject.org/mailman3/hyperkitty/list/tor-dev@lists.torproject.org/feed/"
EXAMPLE_TOML = (Path(__file__).parents[1] / "config.example.toml").read_text()
POLL_DATE = "2026-11-09T15:30:00Z"


def _tag_source(**overrides):
    return {
        "id": "tor-tags", "name": "Tor tags", "kind": "tag",
        "url": "https://gitlab.torproject.org/tpo/core/tor/-/tags?format=atom",
        "enabled": True, "interval_seconds": 300, **overrides,
    }


@pytest.mark.parametrize("raw,expected", [
    ("<p>Hello</p><script>steal()</script><style>bad</style>world\x00", "Hello\nworld"),
    ("v1 <word", "v1 <word"),
    ("one\r\ntwo\rthree", "one\ntwo\nthree"),
    ("v1 &amp", "v1 &"),
    ("v1 <!--hidden", "v1"),
    ("<script>hidden <word", ""),
    ("Hello <script alert(1)", "Hello"),
    ("tor-0.4.9.16\ufffe\uffff", "tor-0.4.9.16"),
    ("security\ud800 report", "security\ufffd report"),
])
def test_plain_text_and_unicode_normalization(raw, expected):
    """Strip hidden HTML elements, control characters, and lone surrogates in plain_text."""
    assert plain_text(raw, 100) == expected


def test_tag_notice_clean_text_and_surrogate_json_rejection():
    """Format literal tag notices and reject unpaired surrogate JSON escapes."""
    cleaned = plain_text("v1\r\n<word", 100)
    assert tag_notice(tag(title=cleaned, content=""))["evidence"] == [cleaned]
    nonchar_tag = tag(title=plain_text("tor-0.4.9.16\ufffe\uffff", 500, html=False), content="")
    assert nonchar_tag["title"] == "tor-0.4.9.16"
    assert validate_analysis(tag_notice(nonchar_tag), nonchar_tag)["title"] == tag_notice(nonchar_tag)["title"]
    truncated_html = "<b>Hello</b>" + (" " * 1980) + '<a href="https://example.org/secret">'
    assert plain_text(truncated_html, 500, html=True) == "Hello"
    with pytest.raises(AnalysisError, match="invalid JSON"):
        json_object('{"title":"\\ud800"}')


@pytest.mark.parametrize("url", [
    "file:///etc/passwd", "http://example.org/news", "https://user:secret@example.org/",
    "https://127.0.0.1/", "https://127.1/", "https://224.0.0.1/", "https://localhost/",
    "https://foo.internal/", "https://example.org/\nheader", "https://example.org/a\ufffeb",
    "https://example.org/#\uffff", "https://example.org/\ud800", "https://[::127.0.0.1]/",
    "https://[64:ff9b::127.0.0.1]/", "https://example.org:0/feed.xml",
    "https://127.0\u30020.1/", "https://127.0.0.1\u3002/", "https://foo.localhost\u3002/",
    "https://foo.internal\uff0e/", 'https://bad"host.example/', "https://bad<host>.example/",
    "https://[2606:4700:4700::1111%lo0]/", "https://[2606:4700:4700::1111%25lo0]/",
])
def test_bad_citation_urls_are_rejected(url):
    """Reject non-HTTPS, credentialed, local, numeric, or malformed citation URLs."""
    with pytest.raises(ValueError):
        canonical_url(url)


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
    """Preserve HTML blockquote nesting as `>` prefixes when `mark_blockquotes=True`."""
    raw = ("<p>Own reply.</p><template><blockquote>Hidden claim.</blockquote></template>"
           f"<blockquote>{quoted}</blockquote><p>Own follow-up.</p>")
    marked = plain_text(raw, 2000, mark_blockquotes=True)
    assert marked == f"Own reply.\n\n{expected}\n\nOwn follow-up."
    assert unquoted_mail_text(marked) == "Own reply.\n\nOwn follow-up."
    assert "hidden" not in marked.lower()
    assert "> " not in plain_text(raw, 2000)


def test_blockquote_marking_keeps_literal_quotes_and_plain_text_defaults():
    """Keep literal `>`, plain-text markup, trailing `<word`, and truncated `<script` consistent."""
    raw = "<p>Own reply.</p>&gt; Existing quoted line.<br>&gt; Another quoted line."
    assert plain_text(raw, 2000, mark_blockquotes=True) == plain_text(raw, 2000)
    assert unquoted_mail_text(plain_text(raw, 2000, mark_blockquotes=True)) == "Own reply."
    literal = "<blockquote>Literal markup in a text field.</blockquote>"
    assert plain_text(literal, 2000, html=False, mark_blockquotes=True) == literal
    assert plain_text(literal, 2000) == "Literal markup in a text field."
    assert plain_text("<blockquote>x\n<word", 2000, mark_blockquotes=True) == "> x\n> <word"
    assert plain_text("<blockquote>x\n<script", 2000, mark_blockquotes=True) == "> x"


@pytest.mark.parametrize("limit", [200, 20_000])
def test_blockquote_prefix_materialization_stays_proportional_to_output_limit(monkeypatch, limit):
    """Bound generated blockquote prefix materialization to the requested output limit."""
    from onionflash import util

    class BoundedParts(list):
        """List wrapper enforcing a linear bound on materialized character length."""

        characters = 0

        def append(self, text):
            """Accumulate appended text length and assert the linear ceiling."""
            self.characters += len(text)
            assert self.characters <= 6 * limit
            super().append(text)

    original = util._TextParser

    class InspectingParser(original):
        """Parser subclass swapping `parts` with `BoundedParts`."""

        def __init__(self, *args, **kwargs):
            """Initialize parser with bounded character-tracking list."""
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
    """Match expected truncated prefixes after whitespace and control cleanup."""
    assert plain_text(raw, limit, mark_blockquotes=True) == expected


def _quoted_reply_feed(entry_url, authority="community", body=None):
    """Collect items from a synthetic RSS feed entry containing HTML blockquote markup."""
    content = body or ("<p>The current reply narrows the measurement to a smaller sample.</p>"
                       "<blockquote>The earlier author reported failures across every measured relay.</blockquote>")
    xml = ("<rss version='2.0'><channel><title>Replies</title><link>https://example.org/</link>"
           "<description>Replies</description><item><title>Re: Measurements</title>"
           f"<link>{entry_url}</link><description><![CDATA[{content}]]></description>"
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
    """Mark HTML blockquotes only when the canonicalized entry host is lists.torproject.org."""
    [collected] = _quoted_reply_feed(entry_url, authority)
    assert collected["content"].startswith("The current reply narrows")
    assert ("\n> The earlier author" in collected["content"]) is marked


@pytest.mark.parametrize("entry_url", [
    "https://lists.torproject.org@invalid.example/thread/", "https://[invalid/thread/",
])
def test_quote_marking_still_skips_invalid_entry_urls(entry_url):
    """Skip invalid entry URLs cleanly during feed collection."""
    assert _quoted_reply_feed(entry_url) == []


@pytest.mark.parametrize("tail", ["é" * 700, "x" * 4096])
def test_citation_length_limit_applies_to_the_saved_representation(tail):
    """Reject URLs whose encoded canonical representation exceeds 4096 characters."""
    url = "https://example.org/?q=" + tail
    with pytest.raises(ValueError, match="source URL"):
        canonical_url(url)
    assert _quoted_reply_feed(url) == []


@pytest.mark.parametrize("character", ["a", "é"])
def test_citation_canonical_length_boundary_is_inclusive(character):
    """Allow exact 4096-character canonical URLs while rejecting 4097-character expansions."""
    prefix = "https://example.org/?q="
    raw = prefix + character * 600
    raw += "x" * (4096 - len(canonical_url(raw)))
    canonical = canonical_url(raw)
    assert len(canonical) == 4096 and canonical_url(canonical) == canonical
    assert _quoted_reply_feed(raw)[0]["url"] == canonical
    with pytest.raises(ValueError, match="source URL"):
        canonical_url(raw + "x")
    assert _quoted_reply_feed(raw + "x") == []


@pytest.mark.parametrize("host", ["example.org", "LISTS.TORPROJECT.ORG"])
def test_collected_encoded_citations_remain_valid_through_packet_construction(store, host):
    """Verify encoded query citations pass collection, ingestion, and source-packet checks."""
    from onionflash.source_packet import build_packet

    raw = f"https://{host}/?q=" + "é" * 600
    [collected] = _quoted_reply_feed(raw)
    expected = canonical_url(raw)
    assert collected["url"] == canonical_url(expected) == expected
    assert len(expected) < 4096
    assert ("\n> The earlier author" in collected["content"]) is (host.lower() == "lists.torproject.org")
    store.ingest(collected, DATE)
    [row] = store.pending(1, DATE)
    references = {"sources": [{"id": row["id"], "url": expected}]}
    packet, _ = build_packet(store.db, json.loads(row["payload"]), references, references, row["id"])
    assert packet["missing_sources"] == [] and packet["sources"][0]["url"] == expected


@pytest.mark.parametrize("quoted_only", [False, True])
def test_collected_html_quotes_stay_outside_writer_and_packet_reply_evidence(llm_context, quoted_only):
    """Keep HTML blockquote text out of unquoted reply evidence across packet and analyzer paths."""
    from onionflash.source_packet import build_packet

    cfg, _store = llm_context
    [collected] = _quoted_reply_feed("https://lists.torproject.org/thread/EXAMPLE/")
    collected["id"] = "a" * 24
    own = "The current reply narrows the measurement to a smaller sample."
    quoted = "The earlier author reported failures across every measured relay."
    packet, _ = build_packet(None, collected, {"sources": [{"id": collected["id"], "url": collected["url"]}]},
                             {"sources": []}, collected["id"])
    assert packet["sources"][0]["unquoted_content"] == own
    draft = analysis(title="A reply narrows the measured sample", summary=own, why_it_matters="",
                     evidence=[quoted if quoted_only else own])
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

    [pure_quote] = _quoted_reply_feed(
        "https://lists.torproject.org/thread/PUREQUOTE/",
        body="<blockquote>The earlier author reported failures across every measured relay.</blockquote>",
    )
    assert is_quoted_list_post(pure_quote["url"], pure_quote["content"])
    assert unquoted_mail_text(pure_quote["content"]) == ""


def test_gitlab_aliases_url_identities_utc_helpers_and_extra_fields():
    """Unify GitLab issue/work_item URLs, extract references, and validate UTC timestamps."""
    assert canonical_url("https://gitlab.torproject.org/tpo/core/tor/-/issues/123?utm_source=x") == "https://gitlab.torproject.org/tpo/core/tor/-/work_items/123"
    assert canonical_url("https://[2606:4700:4700::1111]/feed.xml") == "https://[2606:4700:4700::1111]/feed.xml"
    assert canonical_url("https://ops.xn--p1ai/feed.xml") == "https://ops.xn--p1ai/feed.xml"
    assert canonical_url("https://gitlab.torproject.org/tpo/core/tor/-/issues/123/designs") == "https://gitlab.torproject.org/tpo/core/tor/-/issues/123/designs"
    closing, _ = gitlab_refs({"url": "https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/10", "title": "Fix crash",
                              "content": "Closes https://gitlab.torproject.org/tpo/core/tor/-/issues/41473?iid_path=true"})
    assert closing == ["https://gitlab.torproject.org/tpo/core/tor/-/work_items/41473"]

    assert parse_utc("2026-11-08T04:00:00-08:00") == datetime(2026, 11, 8, 12, tzinfo=timezone.utc)
    assert format_utc(parse_utc("2026-11-08T13:00:00+01:00")) == DATE
    assert timestamp("2026-11-08T13:00:00+01:00") == DATE and timestamp({}, DATE) == DATE
    assert after(2, "2026-11-08T04:00:00-08:00") == "2026-11-08T12:00:02Z"
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
        row = pending(store)
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

    def _connect(path, *args, **kwargs):
        if path == partial:
            assert partial.stat().st_mode & 0o777 == 0o600
            raise RuntimeError("simulated destination failure")
        assert "mode=ro" in path
        conn = original_connect(path, *args, **kwargs)
        opened.append(conn)
        return conn

    with patch("onionflash.store.sqlite3.connect", side_effect=_connect), pytest.raises(RuntimeError):
        backup_database(src_db, partial)
    assert not partial.exists()
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        opened[0].execute("SELECT 1")


def test_exact_body_duplicates_release_mirrors_and_older_mirrors(store):
    """Cluster identical issue bodies and release versions while ignoring older mirror revisions."""
    body = item()["content"] * 3
    for n in (1, 2):
        seed_story(store, item(url=f"https://example.org/{n}", content=body), analysis(), key=f"cache{n}")
    stories = store.stories(10)
    assert len(stories) == 1 and len(stories[0]["sources"]) == 2
    assert item_cluster(item(content="Unrelated event", url="https://example.org/other")) != item_cluster(item())
    assert item_cluster(item(content=body, title="Unrelated title")) != item_cluster(item(content=body))
    assert item_cluster(item(content=body, title="dirauth: Remove bastet from list")) == item_cluster(item(content=body, title="Remove bastet from list"))

    release = item(url="https://example.org/released", kind="feed", title="Tor 0.4.9.16 released", product="network")
    rel_tag = item(url="https://example.org/tag", kind="tag", title="tor-0.4.9.16", updated_at="2026-11-09T00:00:00Z")
    assert item_cluster(release) == item_cluster(rel_tag)
    seed_story(store, release, analysis(title="Tor 0.4.9.16 released", state="released"), key="release")
    seed_story(store, rel_tag, analysis(title="Tor tag created", state="tagged"), key="tag")
    rel_story = next(s for s in store.stories(10) if "0.4.9.16" in s["title"])
    assert rel_story["state"] == "released" and rel_story["title"] == "Tor 0.4.9.16 released" and len(rel_story["sources"]) == 2

    other_body = "Distinct mirror body text long enough to group across URLs. " * 5
    seed_story(store, item(url="https://example.org/new", content=other_body, updated_at="2026-11-09T00:00:00Z"),
               analysis(title="Newest facts", evidence=["Distinct mirror body text long enough"]), key="new")
    seed_story(store, item(url="https://example.org/old", content=other_body),
               analysis(title="Old facts", evidence=["Distinct mirror body text long enough"]), key="old")
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
    dl_client = FakeClient([FetchError("HTTP 503", status=503, retryable=True), response(xml)])
    dl_client.deadline_reached = True
    with pytest.raises(CollectionError):
        collect_source(dl_client, s, {}, DEFAULTS["collection"], DATE)
    assert len(dl_client.calls) == 1
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


def _gitlab_records(*stamps):
    return json.dumps([{"web_url": f"https://example.org/issues/{n}", "title": f"Report {n}", "description": "Body",
                        "created_at": stamp, "updated_at": stamp} for n, stamp in enumerate(stamps)]).encode()


def _gitlab_queries(client):
    return [parse_qs(urlsplit(call[1]).query) for call in client.calls]


def test_gitlab_collection_watermarks_ties_and_fallbacks(store):
    """Step through GitLab updated_at watermarks, same-timestamp tie pages, and fallbacks."""
    client = FakeClient([response(_gitlab_records(DATE))])
    res = collect_source(client, source(kind="gitlab_issue"), {}, DEFAULTS["collection"], DATE)
    q0 = _gitlab_queries(client)[0]
    assert q0["updated_after"] == [after(-DEFAULTS["collection"]["lookback_days"] * 86400, DATE)]
    assert q0["updated_before"] == [DATE] and q0["sort"] == ["asc"] and q0["page"] == ["1"]
    assert res["watermark"] == after(-DEFAULTS["collection"]["overlap_seconds"], DATE)

    stream, settings = source(kind="gitlab_issue", max_pages=1), {**DEFAULTS["collection"], "page_size": 2}
    with pytest.raises(CollectionError, match="catching up") as exc:
        collect_source(FakeClient([response(_gitlab_records("2026-11-01T00:00:00Z", "2026-11-02T00:00:00.250Z"))]), stream, store.source(stream), settings, DATE)
    assert len(exc.value.items) == 2 and exc.value.catching_up
    store.source_failure(stream, str(exc.value), settings, DATE, exc.value.watermark, exc.value.catching_up)
    c2 = FakeClient([response(_gitlab_records("2026-11-03T00:00:00Z"))])
    r2 = collect_source(c2, stream, store.source(stream), settings, "2026-11-08T12:05:00Z")
    assert _gitlab_queries(c2)[0]["updated_after"] == ["2026-11-02T00:00:00.250Z"] and _gitlab_queries(c2)[0]["page"] == ["1"]
    store.source_success(stream, r2, "2026-11-08T12:05:00Z")
    assert store.source(stream)["watermark"] == after(-settings["overlap_seconds"], "2026-11-08T12:05:00Z")

    tie = "2026-11-02T00:00:00.000Z"
    ctie = FakeClient([response(_gitlab_records(tie, tie)), response(_gitlab_records(tie, tie)), response(_gitlab_records(tie))])
    collect_source(ctie, source(kind="gitlab_issue", max_pages=3), {"watermark": "2026-11-01T00:00:00Z"}, settings, DATE)
    assert [(q["updated_after"][0], q["page"][0]) for q in _gitlab_queries(ctie)] == [("2026-11-01T00:00:00Z", "1"), (tie, "1"), (tie, "2")]

    s2 = source(kind="gitlab_issue", max_pages=2)
    with pytest.raises(CollectionError, match="catching up") as exc:
        collect_source(FakeClient([response(_gitlab_records("2026-11-01T00:00:00Z", tie)), response(_gitlab_records(tie, tie))]),
                       s2, {"watermark": "2026-10-31T00:00:00Z"}, settings, DATE)
    assert exc.value.watermark == tie
    with pytest.raises(CollectionError, match="same-timestamp") as exc:
        collect_source(FakeClient([response(_gitlab_records(tie, tie)), response(_gitlab_records(tie, tie))]), s2, {"watermark": tie}, settings, DATE)
    assert exc.value.watermark == "2026-11-02T00:00:00.001Z" and exc.value.catching_up

    for err in (FetchError("HTTP 503", retryable=True), DeadlineReached()):
        with pytest.raises(CollectionError) as exc:
            collect_source(FakeClient([response(_gitlab_records("2026-11-01T00:00:00Z", "2026-11-02T00:00:00Z")), err]),
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
                    resolver=public_dns, sleep=sleeps.append, clock=lambda: clock[0]) as client:
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
                    resolver=public_dns, sleep=sleeps2.append, clock=lambda: 100.0) as client:
        client.deadline = 110.0
        with pytest.raises(DeadlineReached):
            client.request("GET", "https://example.org/")
        assert client.deadline_reached
    assert len(calls2) == 1 and sleeps2 == []

    respond = lambda req: httpx.Response(429, headers={"Retry-After": "30"}, content=b"slow") if req.url.path == "/primary" else httpx.Response(404, content=b"missing")
    with HttpClient(settings2, transport=httpx.MockTransport(respond), resolver=public_dns, sleep=lambda _: None, clock=lambda: 100.0) as client:
        client.deadline = 110.0
        with pytest.raises(DeadlineReached):
            client.request("GET", "https://example.org/primary")
        with pytest.raises(FetchError, match="404"):
            client.request("GET", "https://example.org/fallback")
        assert not client.deadline_reached


def test_run_deadlines_source_budgets_and_endpoint_circuit_breakers(tmp_path, monkeypatch):
    """Bound per-source collection and reserve analysis time within the run budget."""
    cfg = make_config(tmp_path)
    patch_cli_pipeline(monkeypatch, now=None, analyzer=Writer.factory(), reviewer=ApprovingReviewer,
                       collect=raise_once(CollectionError("request deadline reached")), no_build=False)
    monkeypatch.setattr(cli, "HttpClient", lambda *a, **kw: FakeClient([]))
    with Store(tmp_path / "state.db") as store:
        store.ingest(item(), DATE)
        res = cli.run(cfg, store)
        assert res["sources_failed"] == 1 and res["analyzed"] == 1 and store.source(cfg["sources"][0])["next_fetch_at"] is not None

    for source_budget, shared in [(600, True), (5, False)]:
        cfg_b = make_config(tmp_path / f"b-{source_budget}")
        cfg_b["collection"]["source_budget_seconds"] = source_budget
        cfg_b["sources"] = [source(id="first"), source(id="second", url="https://example.org/second.xml")]
        collected = []

        def _collect_cut(client, stream, *args):
            collected.append(stream["id"])
            client.deadline_reached = True
            raise CollectionError("request deadline reached")

        patch_cli_pipeline(monkeypatch, now=None, reviewer=None, collect=_collect_cut)
        with Store(cfg_b["storage"]["database"]) as store:
            rep = cli.run(cfg_b, store)
            first = store.source(cfg_b["sources"][0])
        assert bool(rep.get("budget_reached")) is shared and first["failures"] == (0 if shared else 1)
        assert collected == (["first"] if shared else ["first", "second"])

    analyzed = []
    patch_cli_pipeline(monkeypatch, analyzer=Writer.factory(lambda p: analyzed.append(p) or analysis()), reviewer=ApprovingReviewer)
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
    writer = Writer(raise_once(AnalysisError("Unavailable", retryable=True)))
    patch_cli_pipeline(monkeypatch, analyzer=lambda *_a, **_kw: writer, reviewer=ApprovingReviewer)
    with Store(tmp_path / "state.db") as store:
        store.ingest(item(url="https://example.org/urgent", title="Authority compromised"), DATE)
        store.ingest(item(url="https://example.org/second", title="Second update", labels=["Security"], content="second"), DATE)
        store.ingest(item(url="https://example.org/later", title="Other update", labels=[], content=""), DATE)
        cli.run({**copy.deepcopy(DEFAULTS), "sources": []}, store)
        skipped = store.db.execute("SELECT attempts,last_error,next_attempt_at FROM items WHERE url=?", ("https://example.org/later",)).fetchone()
    assert [call["url"] for call in writer.calls] == ["https://example.org/urgent", "https://example.org/second"]
    assert skipped["attempts"] == 0 and skipped["last_error"] is None and skipped["next_attempt_at"] is None


def test_render_failure_ownership_and_build_counts(tmp_path, monkeypatch):
    """Verify output directory ownership guards and incremental static build artifact counts."""
    cfg = make_config(tmp_path)
    with Store(tmp_path / "state.db") as store:
        store.source(cfg["sources"][0])
        store.source_success(cfg["sources"][0], {"url": cfg["sources"][0]["url"]}, DATE)
        seed_story(store, item(), analysis(), key="cache")
        assert build(cfg, store) == {"public_changed": True, "published_stories": 1, "stories_skipped": 0}
        before = (tmp_path / "public/index.html").read_bytes()
        assert build(cfg, store)["published_stories"] == 1 and (tmp_path / "public/index.html").read_bytes() == before
        monkeypatch.setattr("onionflash.render.index_html", raise_once(ValueError("simulated")))
        with pytest.raises(ValueError):
            build(cfg, store)
        assert (tmp_path / "public/index.html").read_bytes() == before
    monkeypatch.undo()

    for sub, filename, content, mk_marker, match in [
        ("unowned", "keep.txt", "mine", False, None),
        ("marker_dir", "operator-file.txt", "keep", True, "regular file"),
    ]:
        d = tmp_path / sub
        (d / "public").mkdir(parents=True)
        (d / "public" / filename).write_text(content)
        if mk_marker:
            (d / ".public.onionflash-owner").mkdir()
        with Store(d / "state.db") as store, pytest.raises(ValueError, match=match):
            build(make_config(d), store)
        assert (d / "public" / filename).read_text() == content

    first, moved = tmp_path / "first", tmp_path / "moved"
    first.mkdir()
    with Store(first / "state.db") as store:
        build(make_config(first), store)
    first.rename(moved)
    with Store(moved / "state.db") as store:
        build(make_config(moved), store)
    assert (moved / "public" / "index.html").exists()

    web = tmp_path / "web"
    web_cfg = make_config(web)
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
    skip_cfg = make_config(skip_dir)
    with Store(skip_dir / "state.db") as store:
        for url in ["https://example.org/news/1", "https://example.org/news/2"]:
            seed_story(store, item(url=url, content=url), analysis())
        store.db.execute("UPDATE stories SET payload=json_set(payload, '$.priority', 'urgent') WHERE rowid=(SELECT MIN(rowid) FROM stories)")
        assert build(skip_cfg, store) == {"public_changed": True, "published_stories": 1, "stories_skipped": 1}
        assert build(skip_cfg, store) == {"public_changed": False, "published_stories": 1, "stories_skipped": 1}


def test_run_lock_and_status_commands(tmp_path, capsys):
    """Acquire exclusive run locks and report JSON status summaries via the CLI."""
    with run_lock(str(tmp_path / "db")) as first, run_lock(str(tmp_path / "db")) as second:
        assert first and not second
    cfg_path = write_toml(tmp_path)
    db_path = tmp_path / "state.sqlite3"
    with run_lock(str(db_path)) as held:
        assert held and invoke_cli(capsys, "build", "--config", cfg_path, expected=75)["status"] == "already-running"
        assert invoke_cli(capsys, "run", "--config", cfg_path)["status"] == "already-running"
        assert invoke_cli(capsys, "status", "--config", cfg_path)["sources"][0]["last_success"] is None
    with Store(db_path) as store:
        assert store.db.execute("SELECT COUNT(*) FROM source_state").fetchone()[0] == 0
    writer = sqlite3.connect(db_path, isolation_level=None)
    writer.execute("BEGIN IMMEDIATE")
    try:
        invoke_cli(capsys, "status", "--config", cfg_path)
        invoke_cli(capsys, "rejected", "list", "--config", cfg_path)
    finally:
        writer.close()
    assert invoke_cli(capsys, "status", "--config", cfg_path)["published_stories"] is None
    invoke_cli(capsys, "build", "--config", cfg_path)
    assert invoke_cli(capsys, "status", "--config", cfg_path)["published_stories"] == 0


@pytest.mark.parametrize("fb,env_val,match", [
    ('[""]', "   ", "fallback"),
    ('["   "]', "   ", "fallback"),
    ('["/"]', "   ", "fallback"),
    ('[123]', "   ", "fallback"),
    ('["${ONIONFLASH_LLM_FALLBACK_URL}"]', "   ", "fallback"),
    ('["${ONIONFLASH_LLM_FALLBACK_URL}"]', "", "fallback"),
    ('["http://backup.example/v1"]', "   ", "Invalid LLM base URL"),
    ('["ftp://backup.example/v1"]', "   ", "Invalid LLM base URL"),
    ('["https://backup.example/v1?"]', "   ", "Invalid LLM base URL"),
    ('["https://backup.example/v1#"]', "   ", "Invalid LLM base URL"),
    ('["https://backup.example/v1/../admin"]', "   ", "Invalid LLM base URL"),
])
def test_invalid_fallback_base_urls_rejected(tmp_path, monkeypatch, fb, env_val, match):
    """Reject non-HTTPS, private, or empty fallback LLM endpoint URLs."""
    monkeypatch.setenv("ONIONFLASH_LLM_BASE_URL", "https://model.example/v1")
    monkeypatch.setenv("ONIONFLASH_LLM_FALLBACK_URL", env_val)
    p = tmp_path / "config.toml"
    p.write_text(EXAMPLE_TOML.replace("fallback_base_urls = []", "fallback_base_urls = " + fb))
    with pytest.raises(ValueError, match=match):
        load_config(p)


def test_pool_base_urls_and_max_concurrent_requests_config_validation(tmp_path, capsys):
    """Validate `llm.pool_base_urls` and `llm.max_concurrent_requests` bounds and pool-only `check` status."""
    too_many_pools = json.dumps([f"https://pool{i}.example/v1" for i in range(17)])
    for snippet, match in (
        ('[llm]\npool_base_urls = "https://pool.example/v1"\n', "must be an array"),
        ('[llm]\npool_base_urls = [""]\n', "nonempty URL"),
        ('[llm]\npool_base_urls = ["https://192.168.7.42:8000/v1"]\nallow_http = true\n', "Invalid LLM base URL"),
        (f'[llm]\npool_base_urls = {too_many_pools}\n', "At most 16"),
        ('[llm]\nmax_concurrent_requests = 0\n', "between 1 and 16"),
        ('[llm]\nmax_concurrent_requests = 17\n', "between 1 and 16"),
        ('[llm]\nmax_concurrent_requests = true\n', "between 1 and 16"),
        ('[llm]\nmax_concurrent_requests = "4"\n', "between 1 and 16"),
    ):
        with pytest.raises(ValueError, match=match):
            load_config(write_toml(tmp_path / "bad_pool", snippet))

    pool_only_cfg = write_toml(tmp_path / "pool_only", '[llm]\npool_base_urls = ["https://pool.example/v1"]\n')
    checked = invoke_cli(capsys, "check", "--config", pool_only_cfg)
    assert checked["configuration"] == "valid"
    assert checked["llm_endpoint_configured"] is True
    assert cli._effective_concurrency({"llm": {"max_concurrent_requests": True}}) == cli.MAX_CONCURRENT_LLM_ITEMS


def test_example_config_and_validation_guards(tmp_path, monkeypatch):
    """Validate config.example.toml (including verified sources) and reject malformed TOML settings."""
    p = tmp_path / "config.toml"
    p.write_text(EXAMPLE_TOML)
    assert _clean_endpoint_url("https://model.example/v1/", allow_http=False, trailing_slash=False, error="bad") == "https://model.example/v1"
    monkeypatch.setenv("ONIONFLASH_LLM_BASE_URL", "https://model.example/v1/")
    cfg = load_config(p)
    assert cfg["llm"]["base_url"] == "https://model.example/v1"
    for bad_base in ("https://model.example/v1?", "https://model.example/v1#", "https://model.example/v1/../admin"):
        monkeypatch.setenv("ONIONFLASH_LLM_BASE_URL", bad_base)
        with pytest.raises(ValueError, match="Invalid LLM base URL"):
            load_config(p)
    monkeypatch.setenv("ONIONFLASH_LLM_BASE_URL", "https://model.example/v1")
    assert cfg["storage"]["database"] == str(tmp_path / "state/onionflash.sqlite3") and len(cfg["sources"]) == 36 and cfg["llm"]["fallback_base_urls"] == []
    sources = {s["id"]: s for s in cfg["sources"]}
    assert sources["tor-browser-security"]["enabled"] and sources["tor-browser-security"]["authority"] == "development"
    assert sources["anti-censorship-team"]["enabled"] and sources["tor-dev"]["enabled"]
    expected_new = {
        "snowflake-tags": ("tag", "snowflake", "official", None, "https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/-/tags?format=atom"),
        "snowflake-issues": ("gitlab_issue", "snowflake", "development", "tpo/anti-censorship/pluggable-transports/snowflake", "https://gitlab.torproject.org/api/v4/projects/43/issues"),
        "snowflake-merges": ("gitlab_mr", "snowflake", "development", None, "https://gitlab.torproject.org/api/v4/projects/43/merge_requests"),
        "webtunnel-tags": ("tag", "webtunnel", "official", None, "https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/webtunnel/-/tags?format=atom"),
        "webtunnel-issues": ("gitlab_issue", "webtunnel", "development", "tpo/anti-censorship/pluggable-transports/webtunnel", "https://gitlab.torproject.org/api/v4/projects/1674/issues"),
        "webtunnel-merges": ("gitlab_mr", "webtunnel", "development", None, "https://gitlab.torproject.org/api/v4/projects/1674/merge_requests"),
        "lyrebird-tags": ("tag", "lyrebird", "official", None, "https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/-/tags?format=atom"),
        "lyrebird-issues": ("gitlab_issue", "lyrebird", "development", "tpo/anti-censorship/pluggable-transports/lyrebird", "https://gitlab.torproject.org/api/v4/projects/417/issues"),
        "lyrebird-merges": ("gitlab_mr", "lyrebird", "development", None, "https://gitlab.torproject.org/api/v4/projects/417/merge_requests"),
        "tails-news": ("feed", "tails", "official", None, "https://tails.net/news/index.en.rss"),
        "tor-browser-high-impact-bugs": ("gitlab_issue", "tor-browser", "development", "tpo/applications/tor-browser", canonical_url("https://gitlab.torproject.org/api/v4/projects/472/issues?labels=Apps::Product::TorBrowser,Apps::Impact::High,Apps::Type::Bug")),
        "oniux-tags": ("tag", "oniux", "official", None, "https://gitlab.torproject.org/tpo/core/oniux/-/tags?format=atom"),
        "oniux-issues": ("gitlab_issue", "oniux", "development", "tpo/core/oniux", "https://gitlab.torproject.org/api/v4/projects/3212/issues"),
        "oniux-merges": ("gitlab_mr", "oniux", "development", None, "https://gitlab.torproject.org/api/v4/projects/3212/merge_requests"),
        "orbot-android-releases": ("feed", "orbot", "official", None, "https://github.com/guardianproject/orbot-android/releases.atom"),
        "orbot-apple-releases": ("feed", "orbot", "official", None, "https://github.com/guardianproject/orbot-apple/releases.atom"),
    }
    for sid, (kind, product, authority, project, url) in expected_new.items():
        stream = sources[sid]
        assert stream["enabled"] is True
        assert (stream["kind"], stream["product"], stream["authority"]) == (kind, product, authority)
        assert stream["url"] == url
        assert stream.get("gitlab_project") == project
        assert stream["website_url"]
        if kind == "gitlab_issue":
            assert comments._identity(stream)[0] == project
        if kind == "tag":
            notice = tag_notice(tag(source_id=sid, product=product, title=f"{sid}-v1.0", url=f"{stream['website_url']}/v1.0"))
            assert notice["state"] == "tagged" and notice["products"] == [product]
    assert sources["tails-news"]["website_url"] == "https://tails.net/news/index.en.html"
    assert software_from_url("https://tails.net/news/version_7.18/") == "tails"
    assert software_from_url("https://www.tails.net/news/index.en.html") == "tails"
    assert software_from_url("http://tails.net/news/version_7.18/") is None
    assert software_from_url("https://tails.net.example.org/news/version_7.18/") is None
    tails_entry = {
        "kind": "feed",
        "authority": "official",
        "product": "tails",
        "url": "https://tails.net/news/version_7.18/",
        "title": "Tails 7.18",
        "content": "Tails 7.18 is out.",
    }
    assert item_cluster(tails_entry) == "release:tails:7.18"
    assert is_official_release_announcement(tails_entry) is True
    assert mandatory_news_rule(tails_entry) == "release_announcement"
    tb_client = FakeClient([response(b"[]")])
    collect_source(tb_client, sources["tor-browser-high-impact-bugs"], {}, cfg["collection"], DATE)
    assert parse_qs(urlsplit(tb_client.calls[0][1]).query)["labels"] == ["Apps::Product::TorBrowser,Apps::Impact::High,Apps::Type::Bug"]
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


@pytest.mark.parametrize("bad_toml,with_source,raw_file,match", [
    ('[[sources]]\nid = 123\nurl = "https://example.org/feed.xml"\n', False, False, "Source IDs must be unique"),
    ('[[sources]]\nid = "s"\n', False, False, "Invalid source URL"),
    ('[[sources]]\nid = "s"\nurl = "https://example.org/feed.xml"\nkind = []\n', False, False, "Unsupported source kind"),
    ('[[sources]]\nid = "s"\nurl = "https://example.org/feed.xml"\nauthority = []\n', False, False, "Unsupported source authority"),
    ('[[sources]]\nid = "s"\nurl = "https://example.org/feed.xml"\nname = 123\n', False, False, "Invalid source name"),
    ('[[sources]]\nid = "s"\nurl = "https://example.org/feed.xml"\nname = "   "\n', False, False, "Invalid source name"),
    ('[storage]\ndatabase = ""\noutput_dir = "public"\n[[sources]]\nid = "test"\nurl = "https://example.org/feed.xml"\n',
     False, True, "storage.database must not be empty"),
    ('[storage]\ndatabase = "."\noutput_dir = "public"\n[[sources]]\nid = "test"\nurl = "https://example.org/feed.xml"\n',
     False, True, "Database must be a file path outside config and directory roots"),
    ('[storage]\ndatabase = "config.toml"\noutput_dir = "public"\n[[sources]]\nid = "test"\nurl = "https://example.org/feed.xml"\n',
     False, True, "Database must be a file path outside config and directory roots"),
    ('[llm]\nmodel = "   "\n', True, False, "llm.model must be a valid model identifier"),
    ('[llm]\nmodel = "m\\u007f"\n', True, False, "llm.model must be a valid model identifier"),
    ('[review]\nmodel = "r\\u007f"\n', True, False, "review.model must be a short model identifier"),
])
def test_malformed_sources_storage_and_model_configs_raise_value_error(tmp_path, capsys, bad_toml, with_source, raw_file, match):
    """Raise `ValueError` (CLI exit 2) on malformed source fields, database paths, or model IDs."""
    import tomllib

    if raw_file:
        cfg_path = tmp_path / "config.toml"
        cfg_path.write_text(bad_toml, encoding="utf-8")
    else:
        cfg_path = write_toml(tmp_path, bad_toml, with_source=with_source)
    assert isinstance(tomllib.loads(cfg_path.read_text(encoding="utf-8")), dict)
    with pytest.raises(ValueError, match=match):
        load_config(cfg_path)
    assert cli.main(["check", "--config", str(cfg_path)]) == 2
    capsys.readouterr()


def test_only_operator_settings_are_configurable_and_the_rest_are_ignored(tmp_path, caplog):
    """Ignore unknown internal keys while applying documented operator configuration fields."""
    path = write_toml(
        tmp_path,
        "render_batch_size = 7\n[collection]\nlookback_days = 3\n"
        "[http]\nretry_attempts = 7\n[llm]\nmax_items_per_run = 20\nenable_thinking = true",
    )
    with caplog.at_level("WARNING", logger="onionflash.config"):
        loaded = load_config(path)
    assert loaded["llm"]["max_items_per_run"] == 20 and loaded["llm"]["enable_thinking"] is False
    assert loaded["collection"]["lookback_days"] == DEFAULTS["collection"]["lookback_days"]
    assert loaded["http"]["retry_attempts"] == DEFAULTS["http"]["retry_attempts"]
    assert loaded["storage"]["render_batch_size"] == DEFAULTS["storage"]["render_batch_size"]
    for key in ("collection.lookback_days", "http.retry_attempts", "storage.render_batch_size", "llm.enable_thinking"):
        assert f"Ignoring setting {key}" in caplog.text
    for bad_section in ("[http]\nnot_a_setting = 1", "[llm]\nmax_input_chars = 5000",
                        "[comments]\nmax_pages = 2", "[site]\nfeed_size = 0",
                        "[storage]\nmax_stories = 1000", "[http]\nrequests_per_minute = 30",
                        "[monitoring]\nmin_reports = 2"):
        with pytest.raises(ValueError, match="Unknown"):
            load_config(write_toml(tmp_path, bad_section.removeprefix("[storage]\n")))


@pytest.mark.parametrize("base", ["javascript:bad", "https://example.com/x/../", "https://example.com/%2e%2e/",
                                  "https://example.com/?token=secret", "https://secret@example.com/"])
def test_bad_base_url_and_traversal_are_rejected(tmp_path, base):
    """Reject non-HTTPS site base URLs and path-traversal storage paths."""
    with pytest.raises(ValueError, match="base_url"):
        load_config(write_toml(tmp_path, f'[site]\nbase_url = "{base}"'))


@pytest.mark.parametrize("base", ["https://example.com/news?", "https://example.com/news/#", "https://example.com/news"])
def test_base_url_is_normalized_to_a_clean_directory(tmp_path, base):
    """Normalize site.base_url to end with a single trailing slash."""
    assert load_config(write_toml(tmp_path, f'[site]\nbase_url = "{base}"'))["site"]["base_url"] == "https://example.com/news/"


def test_story_precedence_legacy_stories_and_added_at(tmp_path):
    """Preserve story source-tier upgrades, dated updates, and chronological ordering."""
    def _pub_release(store, url, updated, draft, *, title="Tor 0.4.9.17 released", product="tor", content=None, target=None):
        seed_story(store, item(url=url, title=title, updated_at=updated, kind="feed",
                               content=url if content is None else content, product=product),
                   draft, key=f"key-{url}-{updated}", at=updated, target=target)
        return store.stories(10)

    def _seed_legacy_release(store, story_id, url, title, *, content=None, updated_at=DATE, published=True, **draft_kw):
        src_kw = {"url": url, "title": title, "kind": "feed", "updated_at": updated_at}
        if content is not None:
            src_kw["content"] = content
        row = pending(store, item(**src_kw), at=DATE, ready=DATE)
        payload = {**analysis(title=title, **draft_kw), "id": story_id, "published_at": DATE, "updated_at": updated_at,
                   "sources": [{"id": row["id"], "url": url, "title": "Old", "published_at": DATE}]}
        payload.pop("evidence")
        if published:
            store.db.execute("UPDATE items SET status='published',story_id=? WHERE id=?", (story_id, row["id"]))
        store.db.execute("INSERT INTO stories VALUES(?,?,?,?,?)",
                         (story_id, row["cluster_key"], json.dumps(payload), DATE, updated_at))
        return row

    later, latest = "2026-11-08T13:00:00Z", "2026-11-08T14:00:00Z"
    with Store(tmp_path / "arti.db") as store:
        first_arti = _pub_release(store, "https://blog.example/arti", DATE,
                                  analysis(title="Arti 2.8.0 released", confidence="confirmed", state="released"),
                                  title="Arti 2.8.0 released", product="arti", content=item()["content"])[0]
        stories = _pub_release(store, "https://gitlab.example/arti/1", later,
                               update_analysis(update="Arti 2.8.0 release checklist completed.", confidence="confirmed", state="released"),
                               title="Arti 2.8.0 released", product="arti", content=item()["content"], target=first_arti["id"])
        assert len(stories) == 1 and len(stories[0]["sources"]) == 2 and (stories[0]["title"], stories[0]["confidence"]) == ("Arti 2.8.0 released", "confirmed")
        assert stories[0]["updates"][-1]["text"] == "Arti 2.8.0 release checklist completed."
        stories = _pub_release(
            store, "https://blog.example/arti", latest,
            update_analysis(update="Update: the release was withdrawn.", confidence="reported", state="developing",
                            evidence=["Update: the release was withdrawn."]),
            title="Arti 2.8.0 released", product="arti", content="Update: the release was withdrawn.", target=first_arti["id"],
        )
        assert (stories[0]["title"], stories[0]["confidence"], stories[0]["state"]) == ("Arti 2.8.0 released", "reported", "developing")
        assert [e["text"] for e in stories[0]["updates"]] == ["Arti 2.8.0 release checklist completed.", "Update: the release was withdrawn."]

    with Store(tmp_path / "prec.db") as store:
        first = _pub_release(store, "https://a.example/1", DATE, analysis(title="A", confidence="confirmed", state="released"))[0]
        writer_id = first["editorial_item"]
        s1 = _pub_release(store, "https://b.example/1", "2026-11-08T15:00:00Z",
                          update_analysis(update="Follow-up B.", confidence="confirmed", state="released", evidence=["https://b.example/1"]),
                          target=first["id"])[0]
        assert (s1["title"], s1["updated_at"], s1["editorial_item"]) == ("A", "2026-11-08T15:00:00Z", writer_id)
        s2 = _pub_release(store, "https://c.example/1", later,
                          update_analysis(update="Follow-up C.", confidence="confirmed", state="released", evidence=["https://c.example/1"]),
                          target=first["id"])[0]
        assert (s2["title"], s2["updated_at"], s2["editorial_item"]) == ("A", "2026-11-08T15:00:00Z", writer_id) and [e["text"] for e in s2["updates"]] == ["Follow-up B.", "Follow-up C."]

    with Store(tmp_path / "legacy.db") as store:
        _seed_legacy_release(store, "legacy000000000000000000", "https://old.example/1", "Tor 0.4.9.18 released",
                             content="The original Tor release announcement.", updated_at="2026-11-08T15:00:00Z")
        for idx, stamp in enumerate([later, latest]):
            seed_story(store, item(url=f"https://new.example/{idx}", title="Tor 0.4.9.18 released", kind="feed",
                                   content=f"Follow-up {idx} notes.", updated_at=stamp),
                       update_analysis(update=f"Item {idx}.", evidence=[f"Follow-up {idx} notes."]),
                       key=f"k{idx}", at=stamp, target="legacy000000000000000000")
        ls = store.stories(10)[0]
        assert ls["title"] == "Tor 0.4.9.18 released" and len(ls["sources"]) == 3 and [e["text"] for e in ls["updates"]] == ["Item 0.", "Item 1."]

    url19 = "https://blog.example/tor-0.4.9.19"
    with Store(tmp_path / "single.db") as store:
        row = _seed_legacy_release(store, "legacy111111111111111111", url19, "Tor 0.4.9.19 released",
                                   published=False, confidence="confirmed", state="released")
        seed_story(store, item(url=url19, title="Tor 0.4.9.19 released", kind="feed",
                               content="The release was withdrawn.", updated_at=later),
                   update_analysis(update="The release was withdrawn.", confidence="confirmed",
                                   state="developing", evidence=["The release was withdrawn."]), key="k", at=later)
        s19 = store.stories(1)[0]
        assert s19["title"] == "Tor 0.4.9.19 released" and s19["editorial_item"] == row["id"]
        assert s19["updates"] == [{"at": later, "text": "The release was withdrawn.", "sources": [{"url": url19, "title": "Tor 0.4.9.19 released"}]}]

    with Store(tmp_path / "added.db") as store:
        story = seed_story(store, item(published_at="2026-09-22T12:00:00Z", updated_at="2026-11-09T12:00:00Z"),
                           analysis(), key="key", at="2026-11-09T12:00:00Z")
        assert (story["published_at"], story["added_at"]) == ("2026-09-22T12:00:00Z", "2026-11-09T12:00:00Z")


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
    assert collect.make_item(stream, "https://example.org/1", "Use Vec<u8> instead of String", "", DATE, DATE, title_html=False)["title"] == "Use Vec<u8> instead of String"
    assert collect.make_item(stream, "https://example.org/2", "A <b>bold</b> claim", "", DATE, DATE)["title"] == "A bold claim"
    assert collect.make_item(stream, "https://example.org/3", "t", "", DATE, DATE, labels=["ok", "\ud800bad"])["labels"] == ["ok", "\ufffdbad"]

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
    clamped = collect.make_item(source(), "https://example.org/1", "t", "", "2062-01-01T00:00:00Z", "2062-01-01T00:00:00Z", observed=DATE)
    assert (clamped["published_at"], clamped["updated_at"]) == (DATE, DATE)

    guid_xml = (b'<rss version="2.0"><channel><title>T</title><link>https://example.org/</link><description>D</description>'
                b'<item><title>No link</title><guid isPermaLink="false">https://example.org/?p=123</guid>'
                b'<pubDate>Sun, 08 Nov 2026 12:00:00 GMT</pubDate></item></channel></rss>')
    assert collect_source(FakeClient([response(guid_xml)]), source(), {}, DEFAULTS["collection"], DATE)["items"] == []


def test_configured_forum_announcements_keep_operational_context(tmp_path, monkeypatch):
    """Collect configured Tor forum release announcements while preserving operational context."""
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
def _collected_items(body: bytes, *, src_url: str = LIST_URL, final_url: str = LIST_URL, authority: str = "community"):
    return collect_source(FakeClient([Response(200, body, {}, final_url)]), source(url=src_url, authority=authority), {}, DEFAULTS["collection"], DATE)["items"]


def test_a_torproject_org_sender_on_the_list_archive_is_project_sender():
    """Classify verified HyperKitty @torproject.org RSS authors as project-sender."""
    items = _collected_items(list_rss(
        "<author>dev＠torproject.org (A Developer)</author>",
        "<author>Dev.Name+x_1-2＠TorProject.ORG</author>",
        "<author>member＠example.org (Community Member)</author>",
    ))
    assert [e["authority"] for e in items] == ["project-sender", "project-sender", "community"]
    assert all("dev@torproject.org" not in json.dumps(e).lower() and "＠" not in json.dumps(e) for e in items)
    assert _collected_items(list_rss("<author>dev＠torproject.org (Dev)</author>"), src_url="https://example.org/feed.xml", final_url=LIST_URL)[0]["authority"] == "project-sender"
    assert _collected_items(list_rss("<author>dev＠torproject.org (Dev)</author>"), src_url=LIST_URL, final_url="https://example.org/feed.xml")[0]["authority"] == "community"
    assert [e["authority"] for e in _collected_items(list_rss("<author>dev＠torproject.org (Dev)</author>", "<author>member＠example.org (Member)</author>"), authority="official")] == ["official", "official"]

    first = {"stage": "review", "candidate_hash": "h", "result": verdict("skip", criterion="news_value", ref="S1P1", reason="Routine reply.")}
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
    (["<author>dev＠torproject.org (Dev)</author><dc:creator>Plain &lt;mallory@example.org&gt;</dc:creator>"], LIST_URL),
    (["<author>tor＠1aeo.com (Ops)</author><dc:creator>Plain &lt;mallory@example.org&gt;</dc:creator>"], LIST_URL),
    (["<author>dev＠torproject.org (Dev)</author>"], "https://example.org/feed.xml"),
    (["<author>dev＠torproject.org (Dev)</author>"], "https://lists.torproject.org.example.org/feed/"),
])
def test_names_lookalikes_and_other_hosts_never_make_a_sender_project_sender(author_entries, final_url):
    """Reject spoofed display names, homoglyphs, subdomains, and non-HyperKitty hosts."""
    items = _collected_items(list_rss(*author_entries), final_url=final_url)
    assert len(items) == len(author_entries)
    assert all(e["authority"] == "community" and "sender_domain" not in e for e in items)


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


@pytest.mark.parametrize("error, where", [(RuntimeError("unexpected parser crash"), "RuntimeError at helpers.py:"),
                                          (CollectionError("unexpected parser crash", [{"title": "No URL"}]), "KeyError at ")])
def test_an_unexpected_source_error_is_recorded_and_other_sources_still_run(tmp_path, monkeypatch, error, where):
    """Sanitize unexpected collector exceptions while continuing other configured sources."""
    cfg = make_config(tmp_path, sources=[source(id="broken", url="https://broken.example/feed.xml"), source(id="fine")])
    patch_cli_pipeline(monkeypatch, now=None, reviewer=None,
                       collect=lambda client, stream, *args: raise_once(error)() if stream["id"] == "broken" else {"items": [], "url": stream["url"]})
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
    writer = Writer()
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
    patch_cli_pipeline(monkeypatch, now=None, analyzer=Writer.factory(), reviewer=ApprovingReviewer,
                       collect=raise_once(CollectionError("request deadline reached", collected)), no_build=False)
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
    assert load_config(write_toml(tmp_path))["collection"]["trusted_operator_domains"] == DEFAULT_TRUSTED_OPERATOR_DOMAINS

    custom = write_toml(tmp_path, '[collection]\ntrusted_operator_domains = ["  Example.NET ", "ops.example.org", "example.net", "torproject.org", "ops.xn--p1ai"]')
    assert load_config(custom)["collection"]["trusted_operator_domains"] == ["example.net", "ops.example.org", "ops.xn--p1ai"]

    with pytest.raises(ValueError, match="trusted_operator_domains must be an array"):
        load_config(write_toml(tmp_path, '[collection]\ntrusted_operator_domains = "1aeo.com"'))

    long_domain = ("a" * 60 + ".") * 4 + "aaaaaa.org"
    for bad in (
        "[123]", '[""]', '["   "]', '["localhost"]', '["127.0.0.1"]', '["-bad.org"]', '["bad-.org"]',
        '["a..org"]', '["https://1aeo.com"]', '["ops@1aeo.com"]', '["1äeo.com"]',
        f'["{long_domain}"]', json.dumps([f"op{n}.example.org" for n in range(501)]),
    ):
        with pytest.raises(ValueError, match="trusted_operator_domains"):
            load_config(write_toml(tmp_path, f"[collection]\ntrusted_operator_domains = {bad}"))


def test_trusted_operator_sender_authority_and_spoofing_guards():
    """Assign trusted-operator and sender_domain only to verified HyperKitty domains."""
    items = _collected_items(list_rss(
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
    assert _collected_items(list_rss("<author>attacker＠example.org (tor@appliedprivacy.net)</author>"))[0]["authority"] == "community"

    spoof_body = list_rss(
        {"title": "Report from 1aeo.com", "link": "https://lists.torproject.org/m/99/",
         "description": "From: tor@1aeo.com and tor@appliedprivacy.net", "author": "attacker＠example.org (1aeo.com)"},
        list_name="tor-relays",
    )
    assert _collected_items(spoof_body)[0]["authority"] == "community"
    assert _collected_items(list_rss("<author>tor＠1aeo.com (Ops)</author>"), final_url="https://example.org/feed.xml")[0]["authority"] == "community"
    assert _collected_items(list_rss("<author>tor＠1aeo.com (Ops)</author>"), authority="official")[0]["authority"] == "official"
    assert collect._sender_authority("dev＠torproject.org (Dev)", ["torproject.org", "1aeo.com"]) == "project-sender"
    assert collect._sender_authority("ops＠.1aeo.com (Ops)", ["1aeo.com"]) is None
    assert collect._sender_authority("operator＠ops.xn--p1ai (Operator)", ["ops.xn--p1ai"]) == "trusted-operator"
    assert collect._sender_authority("operator＠sub.ops.xn--p1ai (Operator)", ["ops.xn--p1ai"]) == "trusted-operator"
    assert collect._sender_authority("operator＠ops.xn--p1ai (Operator)", ["1aeo.com"]) is None
    punycode_collection = {**DEFAULTS["collection"], "trusted_operator_domains": ["ops.xn--p1ai"]}
    punycode_items = collect_source(
        FakeClient([Response(200, list_rss("<author>operator＠ops.xn--p1ai (Operator)</author>"), {}, LIST_URL)]),
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
    {"public_comments": [{"author": "op", "created_at": DATE, "body": "note", "edited_at": 123}]},
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


@pytest.mark.parametrize("name", ["tor-0.4.9.15", "tor-0.4.9.16", "arti-v2.8.0", "v1", "a"])
def test_tag_notice_needs_no_model_credential_or_http_client(name, monkeypatch):
    """Draft literal tag notices locally without model credentials or HTTP client construction."""
    cfg = copy.deepcopy(DEFAULTS)
    cfg["llm"]["base_url"] = cfg["llm"]["model"] = ""
    monkeypatch.delenv(cfg["llm"]["api_key_env"], raising=False)
    monkeypatch.setattr("onionflash.llm.HttpClient", lambda *a, **kw: pytest.fail("HTTP client forbidden"))
    with Analyzer(cfg) as analyzer:
        result = analyzer.analyze(tag(title=name, content=""))
    assert result["publish"] is True and result["state"] == "tagged" and result["category"] == "release"
    assert result["priority"] == "normal" and result["confidence"] == "reported" and result["evidence"] == [name]
    assert "upstream" in result["summary"] and "released" not in result["summary"] and "verified" not in result["summary"]


@pytest.mark.parametrize("product", SCHEMA["properties"]["products"]["items"]["enum"])
def test_literal_tag_notice_still_passes_the_model_output_checks(product):
    """Ensure every product's literal `tag_notice` passes `validate_analysis`."""
    raw = tag(product=product)
    notice = tag_notice(raw)
    assert validate_analysis(copy.deepcopy(notice), raw) == notice


def test_tag_notice_preserves_publication_dates_and_escapes_hostile_text(tmp_path, store):
    """Preserve tag timestamps and HTML-escape hostile tag names in rendered pages."""
    raw = tag(title='<img src=x onerror="alert(1)">', content="")
    with Analyzer(copy.deepcopy(DEFAULTS)) as analyzer:
        result = analyzer.analyze(raw)
    story = seed_story(store, raw, result, at=POLL_DATE)
    assert (story["published_at"], story["updated_at"]) == (raw["published_at"], raw["updated_at"])
    output = tmp_path / "public"
    publish_stories([story], output)
    page = (output / "index.html").read_text()
    assert "<img src=x onerror=" not in page and "<script>attack()" not in page
    assert "&lt;img" in page and "attack()" not in page


def test_tag_cannot_downgrade_existing_announced_release(store):
    """Keep `released` state and headline when a later tag arrives on an announced release."""
    release_item = tag(kind="feed", product="network", title="Tor 0.4.9.16 released",
                       url="https://example.org/tor-0.4.9.16", content="Tor 0.4.9.16 released.")
    with Analyzer(copy.deepcopy(DEFAULTS)) as analyzer:
        tag_result = analyzer.analyze(tag())
    release_result = {**tag_result, "title": "Tor 0.4.9.16 released", "state": "released"}
    seed_story(store, release_item, release_result, key="release", at=POLL_DATE)
    story = seed_story(store, tag(updated_at=POLL_DATE), tag_result, key="tag", at=POLL_DATE)
    assert story["state"] == "released" and story["title"] == release_result["title"] and len(story["sources"]) == 2


def test_tags_have_a_fixed_queue_floor_below_serious_security(store):
    """Assign tags a fixed priority score of 5 below high-severity security issues."""
    assert item_priority(tag()) == 5
    incident = tag(kind="gitlab_issue", title="Directory authority plausibly compromised", content="", labels=["Security"])
    assert item_priority(incident) > item_priority(tag())
    assert item_priority(tag(kind="feed", title="Tor 0.4.9.16 released", content="")) == 5
    store.ingest(tag(), POLL_DATE)
    assert store.pending(1, POLL_DATE)[0]["priority_score"] == 5


def test_a_success_is_rescheduled_a_few_seconds_early_and_never_more_than_a_tenth(store):
    """Schedule successful source polls slightly early without shaving more than 10% of the interval."""
    for interval, expected in [(300, "2026-11-09T15:34:55Z"), (30, "2026-11-09T15:30:27Z")]:
        stream = _tag_source(id=f"s{interval}", interval_seconds=interval)
        store.source(stream)
        store.source_success(stream, {"url": stream["url"]}, POLL_DATE)
        due = store.source(stream)["next_fetch_at"]
        assert due == expected and not source_due({"next_fetch_at": due}, after(-1, due)) and source_due({"next_fetch_at": due}, due)


def test_failure_and_catching_up_cooldowns_are_never_shortened(store):
    """Apply full interval or failure backoff cooldowns without early-reschedule shaving."""
    stream = _tag_source(interval_seconds=300)
    store.source(stream)
    store.source_failure(stream, "GitLab scan catching up", DEFAULTS["collection"], POLL_DATE, catching_up=True)
    assert store.source(stream)["next_fetch_at"] == "2026-11-09T15:35:00Z"
    store.source_failure(stream, "HTTP 429", DEFAULTS["collection"], POLL_DATE)
    assert store.source(stream)["next_fetch_at"] == after(DEFAULTS["collection"]["failure_backoff_base_seconds"], POLL_DATE)


def test_late_fetch_records_actual_observation_but_keeps_schedule_anchor(tmp_path, store, monkeypatch):
    """Record actual completion timestamps on items while anchoring `next_fetch_at` to run start."""
    cfg = make_config(tmp_path, sources=[_tag_source()])
    times = iter([POLL_DATE, "2026-11-09T15:30:07Z"])
    patch_cli_pipeline(monkeypatch, now=lambda: next(times, "2026-11-09T15:30:08Z"), reviewer=None,
                       collect=lambda *a: {"items": [tag()], "url": _tag_source()["url"]})
    cli.run(cfg, store)
    row = store.db.execute("SELECT first_seen,last_seen FROM items").fetchone()
    state = store.source(_tag_source())
    assert row["first_seen"] == row["last_seen"] == "2026-11-09T15:30:07Z"
    assert state["last_success"] == "2026-11-09T15:30:07Z"
    assert state["next_fetch_at"] == after(300 - 5, POLL_DATE)


def test_inference_outage_does_not_block_a_queued_deterministic_tag(tmp_path, store, monkeypatch):
    """Publish queued deterministic tag notices even when an earlier item hits an LLM outage."""
    cfg = make_config(tmp_path, sources=[_tag_source()])
    writer = Writer(lambda inc: tag_notice(inc) if inc["kind"] == "tag" else raise_once(
        AnalysisError("LLM unavailable", retryable=True))())
    patch_cli_pipeline(monkeypatch, now=POLL_DATE, analyzer=lambda *a, **kw: writer, reviewer=ApprovingReviewer)
    store.source(_tag_source())
    store.source_success(_tag_source(), {"url": _tag_source()["url"]}, POLL_DATE)
    store.ingest(tag(kind="gitlab_issue", title="Authority plausibly compromised", url="https://example.org/security"), POLL_DATE)
    store.ingest(tag(), POLL_DATE)
    result = cli.run(cfg, store)
    assert store.stories(1)[0]["state"] == "tagged"
    assert [c["kind"] for c in writer.calls] == ["gitlab_issue", "tag"]
    assert result["analysis_failed"] == 1 and result["analyzed"] == 1


def test_url_domain_del_plain_text_and_gitlab_ref_performance_guards(tmp_path, monkeypatch):
    """Enforce DEL/HTML-fragment sanitization, punycode/FQDN URL checks, gitlab_refs parsing, and config guards."""
    from onionflash import util
    from onionflash.llm import validate_text
    from onionflash.util import has_invalid_text_chars, is_valid_domain

    assert has_invalid_text_chars("a\x7fb") is True
    with pytest.raises(AnalysisError):
        validate_text("a\x7fb", 100)
    assert plain_text('<b>Hello</b> <a href="https://example.org/secret"', 500, html=True) == "Hello"
    assert plain_text('Hello <svg onload="alert(1)"', 500, html=True) == "Hello"
    assert plain_text("Hello <!-- hidden comment", 500, html=True) == "Hello"
    assert plain_text("v1 <word", 100) == "v1 <word"
    assert plain_text("v1 &amp", 100) == "v1 &"

    # Simulate CPython 3.11.9 HTMLParser.close() emitting any unconsumed rawdata as text.
    class _EmittingCloseParser(util._TextParser):
        def close(self) -> None:
            """Emit buffered rawdata on close() to verify incomplete markup is discarded beforehand."""
            if self.rawdata:
                self.handle_data(self.rawdata)
                self.rawdata = ""
            super().close()

    with monkeypatch.context() as scoped:
        scoped.setattr(util, "_TextParser", _EmittingCloseParser)
        assert plain_text('<b>Hello</b> <a href="https://example.org/secret"', 500, html=True) == "Hello"
        assert plain_text('Hello <svg onload="alert(1)"', 500, html=True) == "Hello"
        assert plain_text("Hello <!-- unfinished comment", 500, html=True) == "Hello"
        assert plain_text("Hello <!DOCTYPE html", 500, html=True) == "Hello"
        assert plain_text("v1 <word", 100, html=True) == "v1 <word"
        assert plain_text("v1 <", 100, html=True) == "v1 <"
        assert plain_text("v1 <script", 100, html=True) == "v1"

    for bad_domain in ("ops.xn--", "ops.xn--99999999999999999999", "bad_underscore.example.org", "foo.123"):
        assert is_valid_domain(bad_domain) is False
    for bad_url in (
        "https://example.org../",
        "https://8.8.8.8./",
        "https://8.8.8.8../",
        "https://ops.xn--99999999999999999999/",
    ):
        with pytest.raises(ValueError):
            canonical_url(bad_url)
    assert (
        canonical_url("https://gitlab.torproject.org/tpo/core/tor/-/ISSUES/123")
        == "https://gitlab.torproject.org/tpo/core/tor/-/work_items/123"
    )

    rss = list_rss({"author": "alice＠torproject.org (Alice)", "title": "Release notice", "description": "Details"})
    fqdn_feed = "https://lists.torproject.org./mailman3/hyperkitty/list/tor-dev@lists.torproject.org/feed/"
    with HttpClient(
        DEFAULTS["http"],
        transport=httpx.MockTransport(
            lambda req: httpx.Response(301, headers={"location": fqdn_feed})
            if req.url.host == "mirror.example.org"
            else httpx.Response(200, content=rss)
        ),
        resolver=public_dns,
    ) as client:
        collected = collect_source(
            client, source(url="https://mirror.example.org/feed/"), {}, DEFAULTS["collection"], DATE
        )
    assert collected["items"][0]["authority"] == "project-sender"

    for content in ("Fixes " + ("a-" * 13990), "Fixes " + ("a/b-" * 7000)):
        closing, mentioned = gitlab_refs(
            {"url": "https://gitlab.torproject.org/tpo/core/tor/-/issues/1", "title": "t", "content": content}
        )
        assert closing == []
        assert mentioned == []
    closing_refs, mentioned_refs = gitlab_refs({
        "url": "https://gitlab.torproject.org/tpo/core/tor/-/issues/1",
        "title": "Fixes #123",
        "content": "See (#123), -#456, .#789, and Tpo/Core-1/Tor.2!99",
    })
    assert closing_refs == ["https://gitlab.torproject.org/tpo/core/tor/-/work_items/123"]
    assert mentioned_refs == [
        "https://gitlab.torproject.org/tpo/core/tor/-/work_items/456",
        "https://gitlab.torproject.org/tpo/core/tor/-/work_items/789",
        "https://gitlab.torproject.org/tpo/core-1/tor.2/-/merge_requests/99",
    ]

    db_parent_cfg = tmp_path / "db_parent.toml"
    db_parent_cfg.write_text(
        '[storage]\ndatabase = "build/state"\noutput_dir = "build/state/public"\n'
        '[[sources]]\nid = "test"\nurl = "https://example.org/feed.xml"\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="outside public output"):
        load_config(db_parent_cfg)
    for bad_cfg in (
        '[site]\nbase_url = "https://example.com/\\ufffe/"\n',
        '[site]\nbase_url = "https://example.com/\\uffff/"\n',
        '[site]\nbase_url = "https://bad\\"host.com/"\n',
        '[llm]\nbase_url = "https://model.example../v1"\n',
        '[llm]\nbase_url = "https://model.example/\\ufffe"\n',
        '[llm]\nbase_url = "https://bad\\"host.com/v1"\n',
        '[llm]\nallow_http = true\nbase_url = "http://127.0.0.1:18000/v1"\n',
        '[llm]\nallow_http = true\nbase_url = "http://localhost:18000/v1"\n',
    ):
        with pytest.raises(ValueError):
            load_config(write_toml(tmp_path / "bad_ep", bad_cfg))
    local_cfg = load_config(
        write_toml(
            tmp_path / "local_ep",
            '[llm]\nallow_http = true\nallowed_networks = ["127.0.0.1/32"]\nbase_url = "http://localhost:18000/v1"\n',
        )
    )
    assert local_cfg["llm"]["base_url"] == "http://localhost:18000/v1"


def test_gitlab_descending_timestamps_rejected_and_fallback_mirror_used(store):
    """Reject regressive or descending GitLab `updated_at` pages without advancing watermarks, falling back to mirrors."""
    settings = {**DEFAULTS["collection"], "page_size": 2}
    gl_src = source(
        kind="gitlab_issue",
        max_pages=2,
        fallback_urls=["https://mirror.example.org/api/v4/projects/426/issues"],
    )
    regressive = _gitlab_records("2026-11-08T10:00:00Z", "2026-11-01T00:00:00Z")
    valid_mirror = _gitlab_records("2026-11-06T00:00:00Z")
    state = {"watermark": "2026-11-05T00:00:00Z"}

    ok_res = collect_source(FakeClient([response(regressive), response(valid_mirror)]), gl_src, state, settings, DATE)
    assert len(ok_res["items"]) == 1 and ok_res["url"] == gl_src["fallback_urls"][0]

    store.source(gl_src)
    store.source_success(gl_src, {"url": gl_src["url"], "watermark": "2026-11-05T00:00:00Z"}, DATE)
    with pytest.raises(CollectionError, match="out-of-order") as err:
        collect_source(
            FakeClient([response(regressive), response(regressive)]),
            gl_src,
            store.source(gl_src),
            settings,
            DATE,
        )
    assert err.value.catching_up is False and err.value.watermark is None
    store.source_failure(gl_src, str(err.value), settings, DATE, err.value.watermark, err.value.catching_up)
    saved_state = store.source(gl_src)
    assert saved_state["watermark"] == "2026-11-05T00:00:00Z" and saved_state["failures"] == 1


def test_gitlab_future_updated_at_rejected_without_poisoning_watermark(store):
    """Reject GitLab pages ending after `started`, keep watermark bounded, and allow mirror fallback."""
    settings = {**DEFAULTS["collection"], "page_size": 2}
    gl_src = source(
        kind="gitlab_issue",
        max_pages=2,
        fallback_urls=["https://mirror.example.org/api/v4/projects/426/issues"],
    )
    future_page = _gitlab_records("2026-11-08T11:00:00Z", "2099-01-01T00:00:00Z")
    valid_mirror = _gitlab_records("2026-11-08T11:30:00Z")
    state = {"watermark": "2026-11-08T10:00:00Z"}

    ok_res = collect_source(FakeClient([response(future_page), response(valid_mirror)]), gl_src, state, settings, DATE)
    assert len(ok_res["items"]) == 1 and ok_res["url"] == gl_src["fallback_urls"][0]
    assert ok_res["watermark"] == after(-settings["overlap_seconds"], DATE)

    store.source(gl_src)
    store.source_success(gl_src, {"url": gl_src["url"], "watermark": "2026-11-08T10:00:00Z"}, DATE)
    with pytest.raises(CollectionError, match="out-of-range") as err:
        collect_source(
            FakeClient([response(future_page), response(future_page)]),
            gl_src,
            store.source(gl_src),
            settings,
            DATE,
        )
    assert err.value.catching_up is False and err.value.watermark is None
    store.source_failure(gl_src, str(err.value), settings, DATE, err.value.watermark, err.value.catching_up)
    assert store.source(gl_src)["watermark"] == "2026-11-08T10:00:00Z"

    page1 = _gitlab_records("2026-11-08T10:30:00Z", "2026-11-08T11:00:00Z")
    with pytest.raises(CollectionError, match="out-of-range") as page2_err:
        collect_source(
            FakeClient([response(page1), response(future_page)]),
            source(kind="gitlab_issue", max_pages=2),
            {"watermark": "2026-11-08T10:00:00Z"},
            settings,
            DATE,
        )
    assert page2_err.value.catching_up is False and page2_err.value.watermark == "2026-11-08T11:00:00Z"


def test_gitlab_malformed_timestamp_preserves_valid_peer_issues_without_advancing_watermark():
    """Return independently valid in-range records in `CollectionError.items` when a peer has a bad `updated_at`."""
    settings = {**DEFAULTS["collection"], "page_size": 5}
    gl_src = source(kind="gitlab_issue", max_pages=2)
    mixed_page = json.dumps([
        {"web_url": "https://gitlab.torproject.org/tpo/core/tor/-/issues/1", "title": "Valid Issue 1",
         "description": "Body 1", "created_at": "2026-11-08T10:05:00Z", "updated_at": "2026-11-08T10:10:00Z", "state": "opened"},
        {"web_url": "https://gitlab.torproject.org/tpo/core/tor/-/issues/2", "title": "Malformed Issue",
         "description": "Body 2", "created_at": "2026-11-08T10:12:00Z", "updated_at": "not-a-timestamp", "state": "opened"},
        {"web_url": "https://gitlab.torproject.org/tpo/core/tor/-/issues/3", "title": "Valid Issue 3",
         "description": "Body 3", "created_at": "2026-11-08T10:15:00Z", "updated_at": "2026-11-08T10:20:00Z", "state": "opened"},
    ]).encode()
    with pytest.raises(CollectionError, match="invalid timestamp") as err:
        collect_source(
            FakeClient([response(mixed_page)]),
            gl_src,
            {"watermark": "2026-11-08T10:00:00Z"},
            settings,
            DATE,
        )
    assert err.value.watermark is None
    assert err.value.catching_up is False
    assert [entry["title"] for entry in err.value.items] == ["Valid Issue 1", "Valid Issue 3"]


@pytest.mark.parametrize("bad_url", [
    "https://127.0.0.1/v1",
    "https://169.254.169.254/v1",
    "https://[::1]/v1",
    "https://[::ffff:127.0.0.1]/v1",
    "https://[64:ff9b::127.0.0.1]/v1",
    "https://localhost/v1",
    "https://vllm.local/v1",
    "https://vllm.internal/v1",
    "https://vllm.localhost/v1",
    "https://\u2100.example/v1",
])
def test_llm_endpoint_rejects_local_private_ips_and_nfkc_and_preserves_host_port(tmp_path, monkeypatch, bad_url):
    """Reject non-public IPs, local domains, and NFKC errors while preserving compatible LLM endpoint text."""
    monkeypatch.setenv("ONIONFLASH_LLM_BASE_URL", bad_url)
    cfg_path = write_toml(tmp_path, '[llm]\nbase_url = "${ONIONFLASH_LLM_BASE_URL}"\n')
    with pytest.raises(ValueError, match="Invalid LLM base URL"):
        load_config(cfg_path)

    fb_path = write_toml(tmp_path / "fb", f'[llm]\nfallback_base_urls = ["{bad_url}"]\n')
    with pytest.raises(ValueError, match="Invalid LLM base URL"):
        load_config(fb_path)

    # Preserving host case and explicit ports keeps analyze.cache_key and review.policy_hash compatible.
    norm_path = write_toml(
        tmp_path / "norm",
        '[site]\nbase_url = "https://example.com:443/news"\n'
        '[llm]\nbase_url = "https://API.example.org:443/v1/"\n'
        'fallback_base_urls = ["https://BACKUP.example.org:443/v1/"]\n',
    )
    loaded = load_config(norm_path)
    assert loaded["site"]["base_url"] == "https://example.com:443/news/"
    assert loaded["llm"]["base_url"] == "https://API.example.org:443/v1"
    assert loaded["llm"]["fallback_base_urls"] == ["https://BACKUP.example.org:443/v1"]
    assert _clean_endpoint_url(
        "https://example.com:443/news", allow_http=True, trailing_slash=True, error="bad", allow_local=True
    ) == "https://example.com:443/news/"

    # allow_http alone permits public HTTP endpoints, never private literals or local hostnames.
    public_http = load_config(
        write_toml(
            tmp_path / "pub_http",
            '[llm]\nallow_http = true\nbase_url = "http://public.example.org:18000/v1/"\n'
            'fallback_base_urls = ["http://93.184.216.34:18000/v1/"]\n',
        )
    )
    assert public_http["llm"]["base_url"] == "http://public.example.org:18000/v1"
    assert public_http["llm"]["fallback_base_urls"] == ["http://93.184.216.34:18000/v1"]

    # Private literal IPs require an explicit matching CIDR in allowed_networks.
    local_path = write_toml(
        tmp_path / "local",
        '[site]\nbase_url = "http://localhost:80/onionflash"\n'
        '[llm]\nallow_http = true\nallowed_networks = ["127.0.0.1/32"]\n'
        'base_url = "http://127.0.0.1:80/v1/"\n'
        'fallback_base_urls = ["https://vllm.local:443/v1"]\n',
    )
    local_cfg = load_config(local_path)
    assert local_cfg["site"]["base_url"] == "http://localhost:80/onionflash/"
    assert local_cfg["llm"]["base_url"] == "http://127.0.0.1:80/v1"
    assert local_cfg["llm"]["fallback_base_urls"] == ["https://vllm.local:443/v1"]

    disallowed_private = write_toml(
        tmp_path / "disallowed_priv",
        '[llm]\nallow_http = true\nallowed_networks = ["127.0.0.1/32"]\nbase_url = "http://10.0.0.5:18000/v1"\n',
    )
    with pytest.raises(ValueError, match="Invalid LLM base URL"):
        load_config(disallowed_private)


def test_configured_trailing_dot_gitlab_source_uses_absolute_dns_and_canonical_identity(tmp_path):
    """Preserve a configured trailing-dot GitLab FQDN for DNS lookup while keeping source and item URLs canonical."""
    from onionflash.util import item_identity

    cfg_path = tmp_path / "fqdn_gitlab.toml"
    cfg_path.write_text(
        '[storage]\ndatabase = "state/app.sqlite3"\noutput_dir = "build/public"\n'
        '[[sources]]\n'
        'id = "gl-fqdn"\n'
        'name = "GitLab FQDN"\n'
        'kind = "gitlab_issue"\n'
        'url = "https://gitlab.example.org./api/v4/projects/426/issues"\n'
        'product = "tor"\n'
        'authority = "development"\n',
        encoding="utf-8",
    )
    loaded = load_config(cfg_path)
    src = loaded["sources"][0]
    assert src["url"] == "https://gitlab.example.org/api/v4/projects/426/issues"

    dns_hosts: list[str] = []
    request_hosts: list[str] = []

    def _recording_dns(host, port, *args, **kwargs):
        dns_hosts.append(host)
        return public_dns(host, port, *args, **kwargs)

    issue_payload = json.dumps([
        {
            "web_url": "https://gitlab.example.org./tpo/core/tor/-/issues/42",
            "title": "Absolute FQDN issue",
            "description": "Reported on a trailing-dot GitLab endpoint.",
            "created_at": "2026-11-08T10:00:00Z",
            "updated_at": "2026-11-08T11:00:00Z",
            "state": "opened",
        }
    ]).encode()

    def _handler(request: httpx.Request) -> httpx.Response:
        request_hosts.append(request.url.host)
        return httpx.Response(200, content=issue_payload)

    with Store(loaded["storage"]["database"]) as st:
        state = st.source(src)
        assert state["url"] == "https://gitlab.example.org/api/v4/projects/426/issues"
        with HttpClient(DEFAULTS["http"], transport=httpx.MockTransport(_handler), resolver=_recording_dns) as client:
            collected = collect_source(client, src, state, loaded["collection"], DATE)

    assert dns_hosts == ["gitlab.example.org."]
    assert request_hosts == ["gitlab.example.org"]
    assert collected["url"] == "https://gitlab.example.org/api/v4/projects/426/issues"
    assert len(collected["items"]) == 1
    assert collected["items"][0]["url"] == "https://gitlab.example.org/tpo/core/tor/-/issues/42"
    assert item_identity(collected["items"][0]) == "https://gitlab.example.org/tpo/core/tor/-/issues/42"


def test_registry_and_tor_core_gitlab_users_config_validation(tmp_path, monkeypatch):
    """Validate `[registry]` boolean settings and `[collection].tor_core_gitlab_users` list rules."""
    from onionflash.registry import DEFAULT_TOR_CORE_USERS

    monkeypatch.setenv("ONIONFLASH_LLM_BASE_URL", "https://model.example/v1")
    assert DEFAULTS["registry"] == {"enabled": False}
    assert DEFAULTS["collection"]["tor_core_gitlab_users"] == list(DEFAULT_TOR_CORE_USERS)

    example_path = tmp_path / "example.toml"
    example_path.write_text(EXAMPLE_TOML, encoding="utf-8")
    example_cfg = load_config(example_path)
    assert example_cfg["registry"] == {"enabled": False}
    assert example_cfg["collection"]["tor_core_gitlab_users"] == list(DEFAULT_TOR_CORE_USERS)

    enabled_cfg = load_config(
        write_toml(
            tmp_path / "reg_on",
            '[registry]\nenabled = true\n[collection]\ntor_core_gitlab_users = ["  NickM ", "arma", "nickm", "User_1.test"]\n',
        )
    )
    assert enabled_cfg["registry"] == {"enabled": True}
    assert enabled_cfg["collection"]["tor_core_gitlab_users"] == ["nickm", "arma", "user_1.test"]

    for bad_reg in ('[registry]\nenabled = "yes"\n', '[registry]\nunknown = true\n', 'registry = "bad"\n'):
        with pytest.raises(ValueError):
            load_config(write_toml(tmp_path / "bad_reg", bad_reg))

    with pytest.raises(ValueError, match="tor_core_gitlab_users must be an array"):
        load_config(write_toml(tmp_path / "bad_type", '[collection]\ntor_core_gitlab_users = "nickm"\n'))

    for bad_users in (
        "[123]", '[""]', '["_hc"]', '[".."]', '["bad..user"]', '["trail."]',
        '["@nickm"]', f'["{"a" * 101}"]', json.dumps([f"user{i}" for i in range(501)]),
    ):
        with pytest.raises(ValueError, match="tor_core_gitlab_users"):
            load_config(write_toml(tmp_path / "bad_users", f"[collection]\ntor_core_gitlab_users = {bad_users}\n"))


def test_cli_run_uses_configured_max_concurrent_requests(context, monkeypatch):
    """Honor configured `llm.max_concurrent_requests` above default 4 while preserving MAX_CONCURRENT_LLM_ITEMS."""
    assert cli.MAX_CONCURRENT_LLM_ITEMS == 4
    cfg, store = context
    cfg["sources"] = []
    cfg["llm"].update(
        base_url="https://llm.example/v1",
        pool_base_urls=["https://llm2.example/v1"],
        max_concurrent_requests=6,
        api_key_env="CONCURRENCY6_KEY",
    )
    monkeypatch.setenv("CONCURRENCY6_KEY", "synthetic-fixture-value")
    patch_cli_pipeline(monkeypatch, now=DATE, reviewer=None, build=lambda *_a: {})

    for i in range(6):
        store.ingest(
            item(
                url=f"https://example.org/c6-{i}",
                title=f"Concurrent six report {i}",
                content=f"Distinct verifiable network event {i} under concurrency 6.",
            ),
            DATE,
        )

    barrier = threading.Barrier(6, timeout=5.0)
    lock = threading.Lock()
    in_flight = 0
    max_in_flight = 0

    def _handle(request: httpx.Request) -> httpx.Response:
        nonlocal in_flight, max_in_flight
        body = json.loads(request.content)
        schema_name = body["response_format"]["json_schema"]["name"]
        if schema_name == "onionflash_news":
            with lock:
                in_flight += 1
                max_in_flight = max(max_in_flight, in_flight)
            try:
                barrier.wait()
                user_payload = json.loads(body["messages"][1]["content"])
                reply = analysis(
                    title=user_payload["title"],
                    summary=user_payload["content"],
                    why_it_matters="",
                    evidence=[user_payload["content"]],
                )
            finally:
                with lock:
                    in_flight -= 1
        elif schema_name == "onionflash_select":
            reply = {"winner": 1, "reason": "Best candidate."}
        elif schema_name == "onionflash_polish":
            draft = json.loads(body["messages"][1]["content"])["draft"]
            reply = {k: draft[k] for k in ("title", "summary", "why_it_matters")}
        else:
            reply = verdict()
        return httpx.Response(200, json={"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(reply)}}]})

    monkeypatch.setattr(
        llm,
        "HttpClient",
        lambda settings, **kwargs: HttpClient(
            settings, **kwargs, transport=httpx.MockTransport(_handle), resolver=public_dns
        ),
    )

    CompletionClient._reset_pool_state()
    report = cli.run(cfg, store)
    CompletionClient._reset_pool_state()
    assert max_in_flight == 6
    assert report["analyzed"] == 6
    assert report["analysis_failed"] == 0


def test_cli_run_prefetches_drafts_concurrently_and_preserves_report_contract(context, monkeypatch):
    """Run concurrent draft prefetch in `cli.run` without monkeypatched pipeline hooks and publish all items."""
    assert cli.MAX_CONCURRENT_LLM_ITEMS == 4
    cfg, store = context
    cfg["sources"] = []
    cfg["llm"].update(base_url="https://llm.example/v1", api_key_env="CONCURRENCY_TEST_KEY")
    monkeypatch.setenv("CONCURRENCY_TEST_KEY", "synthetic-fixture-value")
    patch_cli_pipeline(monkeypatch, now=DATE, reviewer=None, build=lambda *_a: {})

    items = [
        item(
            url=f"https://example.org/concurrent-{i}",
            title=f"Concurrent security report {i}",
            content=f"Operators observed a distinct reproducible network event {i}.",
        )
        for i in range(4)
    ]
    for entry in items:
        store.ingest(entry, DATE)

    barrier = threading.Barrier(4, timeout=5.0)
    lock = threading.Lock()
    in_flight = 0
    max_in_flight = 0

    def _handle(request: httpx.Request) -> httpx.Response:
        """Serve thread-safe writer and review JSON responses while proving concurrent writer overlap."""
        nonlocal in_flight, max_in_flight
        body = json.loads(request.content)
        schema_name = body["response_format"]["json_schema"]["name"]
        if schema_name == "onionflash_news":
            with lock:
                in_flight += 1
                max_in_flight = max(max_in_flight, in_flight)
            try:
                barrier.wait()
                user_payload = json.loads(body["messages"][1]["content"])
                reply = analysis(
                    title=user_payload["title"],
                    summary=user_payload["content"],
                    why_it_matters="",
                    evidence=[user_payload["content"]],
                )
            finally:
                with lock:
                    in_flight -= 1
        elif schema_name == "onionflash_select":
            reply = {"winner": 1, "reason": "Best candidate."}
        elif schema_name == "onionflash_polish":
            draft = json.loads(body["messages"][1]["content"])["draft"]
            reply = {k: draft[k] for k in ("title", "summary", "why_it_matters")}
        else:
            reply = verdict()
        return httpx.Response(200, json={"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(reply)}}]})

    monkeypatch.setattr(
        llm,
        "HttpClient",
        lambda settings, **kwargs: HttpClient(
            settings, **kwargs, transport=httpx.MockTransport(_handle), resolver=public_dns
        ),
    )

    report = cli.run(cfg, store)
    assert max_in_flight == 4
    assert report["analyzed"] == 4
    assert report["analysis_failed"] == 0
    assert report["budget_reached"] is False
    assert report["model_calls"] == 36
    assert len(store.stories()) == 4
    assert store.db.execute("SELECT COUNT(*) FROM review_jobs").fetchone()[0] == 0
    assert set(report) == {
        "sources_ok", "sources_failed", "items_changed", "analyzed", "analysis_failed",
        "budget_reached", "entries_skipped", "review_cache_hits", "review_stale",
        "review_routed", "model_calls", "registry", "comments", "decisions",
        "pending_analysis", "rejected_analysis", "final_review",
    }


def test_prefetch_drafts_filters_non_draftable_rows_preserves_clears_and_carries_budget(context, monkeypatch):
    """Skip ineligible rows in `_prefetch_drafts`, persist drafts, and carry routed request budgets."""
    cfg, store = context
    cfg["sources"] = []
    cfg["llm"].update(base_url="https://llm.example/v1", api_key_env="PREFETCH_FILTER_KEY")
    monkeypatch.setenv("PREFETCH_FILTER_KEY", "synthetic-fixture-value")

    prior_story = seed_story(
        store,
        item(url="https://example.org/prior-story", title="Prior story", content="Initial prior story report body."),
        analysis(title="Prior story", summary="Initial prior story report body.", why_it_matters="", evidence=["Initial prior story report body."]),
    )
    retired_item = item(url="https://example.org/retired-target", title="Retired story", content="Retired report body.")
    retired_story = seed_story(
        store,
        retired_item,
        analysis(title="Retired story", summary="Retired report body.", why_it_matters="", evidence=["Retired report body."]),
    )
    editorial.retract(
        store.db,
        retired_story["id"],
        expect_hash=editorial.show(store.db, retired_story["id"])["hash"],
        reason="Retracted.",
        observed=LATER,
    )

    # 1) Eligible fresh story item (also exercises writer clears accounting).
    fresh = item(url="https://example.org/eligible-1", title="Eligible story one", content="Fresh verifiable defect report one.")
    # 2) Eligible routed item carrying an existing request_budget.
    routed = item(url="https://example.org/routed-2", title="Eligible routed item", content="Second verifiable report routed to prior story.")
    # 3) Tag item (must not invoke Analyzer).
    tag_entry = tag(title="tor-0.4.9.99", url="https://example.org/tags/tor-0.4.9.99")
    # 4) Old non-recent item (skipped before LLM).
    old_entry = item(url="https://example.org/old-3", title="Old issue", content="Old issue content body.",
                     published_at="2026-09-01T00:00:00Z", updated_at="2026-09-01T00:00:00Z", labels=[])
    # 5) Housekeeping ack item (deterministic skip).
    ack_entry = item(url="https://example.org/ack-4", title="Re: report", content="Thanks!", labels=[])
    # 6) Already drafted item in review_jobs.
    already_drafted = item(url="https://example.org/drafted-5", title="Already drafted", content="Already drafted verifiable report.")

    for entry in (fresh, tag_entry, old_entry, ack_entry, already_drafted):
        store.ingest(entry, DATE)
    store.ingest(retired_item, LATER)

    # Create a genuine routed review_jobs record using Reviewer(same_story=prior_story["id"]).
    from helpers import Reviewer as ScriptedReviewer

    routed_row = pending(store, routed, at=DATE, ready=DATE)
    routed_res = review_gate.process_item(
        cfg,
        store,
        routed_row,
        Writer(analysis(title=routed["title"], summary=routed["content"], why_it_matters="", evidence=[routed["content"]])),
        ScriptedReviewer(verdict(same_story=prior_story["id"])),
        DATE,
    )
    assert routed_res["status"] == "routed"
    routed_row = queued_row(store, routed, LATER)

    drafted_row = queued_row(store, already_drafted, DATE)
    drafted_key = review_gate.cache_key(drafted_row, cfg["llm"], None)
    drafted_record = review_gate._new_record(drafted_row)
    drafted_record["writer"] = {"key": drafted_key}
    review_gate._save(store, drafted_row, drafted_key, review.policy_hash(cfg), "drafted", analysis(), None, drafted_record, DATE, prepared_at=DATE)

    seen_urls: list[str] = []
    seen_lock = threading.Lock()

    class _CheckingAnalyzer:
        """Thread-safe stub Analyzer asserting only eligible items are drafted."""

        def __init__(self, config, deadline=None, editorial_polish=False):
            """Track calls, clears, and the editorial_polish opt-in flag."""
            self.calls = 0
            self.clears = 0
            assert editorial_polish is True

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def analyze(self, incoming, prior=None):
            """Record analyzed URL and return a story or update draft."""
            self.calls += 1
            with seen_lock:
                seen_urls.append(incoming["url"])
            if prior is not None:
                return update_analysis(update="A second report adds detail.", evidence=[incoming["content"]])
            self.clears = 1
            return analysis(title=incoming["title"], summary=incoming["content"], why_it_matters="", evidence=[incoming["content"]])

    monkeypatch.setattr(cli, "Analyzer", _CheckingAnalyzer)
    pending_rows = store.pending(20, LATER)
    pending_rows.append({"id": "damaged-row", "damaged": True})
    report = {"analysis_failed": 0, "review_stale": 0}
    calls, failures, handled_ids, budget_reached = cli._prefetch_drafts(
        cfg, store, pending_rows, report, LATER, run_deadline=10**9, allow_network=True,
    )

    assert set(seen_urls) == {fresh["url"], routed["url"]}
    assert calls == 2 and failures == 0 and handled_ids == set() and budget_reached is False
    fresh_job = job(store, queued_row(store, fresh, LATER)["id"])
    assert fresh_job["stage"] == "drafted"
    assert job_record(store, fresh_job["item_id"])["writer"]["clears"] == 1
    routed_job = job(store, routed_row["id"])
    assert routed_job["stage"] == "drafted"
    assert job_record(store, routed_row["id"])["request_budget"]["reserved"] == 1


def test_prefetch_drafts_circuit_breaker_terminal_errors_and_deadline(context, monkeypatch):
    """Respect circuit-breaker limits, terminal deferrals, and budget expiration in `_prefetch_drafts`."""
    cfg, store = context
    cfg["sources"] = []

    urls = [f"https://example.org/err-{i}" for i in range(4)]
    for u in urls:
        store.ingest(item(url=u, content=f"Content for {u}"), DATE)
    rows = store.pending(10, DATE)

    class _CircuitAnalyzer:
        """Stub Analyzer simulating two retryable failures, one terminal failure, and one success."""

        def __init__(self, config, deadline=None):
            """Initialize call and clear counters."""
            self.calls = 0
            self.clears = 0

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def analyze(self, incoming, prior=None):
            """Fail first two items retryably, third non-retryably, and succeed on fourth."""
            self.calls += 1
            if incoming["url"].endswith(("err-0", "err-1")):
                raise AnalysisError("HTTP 503", retryable=True)
            if incoming["url"].endswith("err-2"):
                raise AnalysisError("Bad evidence", retryable=False, code="writer.evidence_not_exact")
            return analysis(title=incoming["title"], summary=incoming["content"], why_it_matters="", evidence=[incoming["content"]])

    monkeypatch.setattr(cli, "Analyzer", _CircuitAnalyzer)
    report = {"analysis_failed": 0, "review_stale": 0}
    calls, failures, handled_ids, budget_reached = cli._prefetch_drafts(
        cfg, store, rows, report, DATE, run_deadline=10**9, allow_network=True,
    )
    assert calls == 4 and failures == 2 and budget_reached is False
    assert report["analysis_failed"] == 3 and len(handled_ids) == 3
    # Fourth item's draft was saved without strikes even after earlier failures.
    by_url = {r["url"]: r for r in rows}
    assert job(store, by_url["https://example.org/err-3"]["id"])["stage"] == "drafted"

    # CompletionDeferred sets budget_reached without deferring or adding strikes.
    class _DeadlineAnalyzer:
        """Stub Analyzer raising CompletionDeferred."""

        calls = 0
        attempted = 0
        _lock = threading.Lock()

        def __init__(self, config, deadline=None):
            """Initialize deadline stub without altering class counters."""

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def analyze(self, incoming, prior=None):
            """Raise CompletionDeferred immediately before dispatch."""
            with self._lock:
                type(self).attempted += 1
            raise llm.CompletionDeferred("Run deadline reached")

    monkeypatch.setattr(cli, "Analyzer", _DeadlineAnalyzer)
    rows2 = [by_url["https://example.org/err-0"], by_url["https://example.org/err-1"]]
    report2 = {"analysis_failed": 0, "review_stale": 0}
    before_attempts = [store.db.execute("SELECT attempts FROM items WHERE id=?", (r["id"],)).fetchone()[0] for r in rows2]
    calls2, _fail2, handled2, budget2 = cli._prefetch_drafts(
        cfg, store, rows2, report2, DATE, run_deadline=10**9, allow_network=True,
    )
    after_attempts = [store.db.execute("SELECT attempts FROM items WHERE id=?", (r["id"],)).fetchone()[0] for r in rows2]
    assert _DeadlineAnalyzer.attempted >= 1
    assert calls2 == 0 and budget2 is True and handled2 == set() and after_attempts == before_attempts


def test_cli_opt_in_adapters_match_target_signatures(monkeypatch):
    """Pass `editorial_polish` and `parallel_verify` only when target signatures accept them."""
    seen: list[dict] = []

    class _NoOptAnalyzer:
        """Analyzer double without `editorial_polish`."""

        def __init__(self, config, deadline=None):
            """Record constructor args without `editorial_polish`."""
            seen.append({"kind": "no_opt", "deadline": deadline})

    class _PolishAnalyzer:
        """Analyzer double declaring `editorial_polish`."""

        def __init__(self, config, deadline=None, editorial_polish=False):
            """Record constructor args including `editorial_polish`."""
            seen.append({"kind": "polish", "deadline": deadline, "editorial_polish": editorial_polish})

    monkeypatch.setattr(cli, "Analyzer", _NoOptAnalyzer)
    cli._new_analyzer(DEFAULTS, deadline=42.0)
    monkeypatch.setattr(cli, "Analyzer", _PolishAnalyzer)
    cli._new_analyzer(DEFAULTS, deadline=43.0)
    assert seen == [
        {"kind": "no_opt", "deadline": 42.0},
        {"kind": "polish", "deadline": 43.0, "editorial_polish": True},
    ]

    def _seq_process(cfg, store, row, writer, reviewer, observed=None, *, allow_network=True):
        """Sequential process_item double."""

    def _par_process(cfg, store, row, writer, reviewer, observed=None, *, allow_network=True, parallel_verify=False, reviewer_factory=None):
        """Parallel-capable process_item double."""

    factory = lambda: None
    monkeypatch.setattr(cli, "process_item", _seq_process)
    assert cli._parallel_verify_kwargs(True, factory) == {}
    monkeypatch.setattr(cli, "process_item", _par_process)
    assert cli._parallel_verify_kwargs(False, factory) == {}
    assert cli._parallel_verify_kwargs(True, factory) == {"parallel_verify": True, "reviewer_factory": factory}


def test_cli_run_concurrent_partial_failures_do_not_double_defer(context, monkeypatch):
    """Ensure items deferred in `_prefetch_drafts` are not re-deferred during the main `cli.run` loop."""
    cfg, store = context
    cfg["sources"] = []
    cfg["llm"].update(base_url="https://llm.example/v1", api_key_env="CONCURRENCY_FAIL_KEY")
    monkeypatch.setenv("CONCURRENCY_FAIL_KEY", "synthetic-fixture-value")
    patch_cli_pipeline(monkeypatch, now=DATE, reviewer=None, build=lambda *_a: {})

    ok_item = item(url="https://example.org/part-ok", title="Healthy report", content="Healthy verifiable report body.")
    retry_item = item(url="https://example.org/part-retry", title="Retryable report", content="Retryable report body text.")
    bad_item = item(url="https://example.org/part-bad", title="Bad JSON report", content="Bad JSON report body text.")
    for entry in (ok_item, retry_item, bad_item):
        store.ingest(entry, DATE)

    def _handle(request: httpx.Request) -> httpx.Response:
        """Return HTTP 503 for retry_item, invalid JSON for bad_item, and valid responses for ok_item."""
        body = json.loads(request.content)
        schema_name = body["response_format"]["json_schema"]["name"]
        if schema_name == "onionflash_news":
            user_payload = json.loads(body["messages"][1]["content"])
            if user_payload["title"] == retry_item["title"]:
                return httpx.Response(503, content=b"unavailable")
            if user_payload["title"] == bad_item["title"]:
                return httpx.Response(200, json={"choices": [{"finish_reason": "stop", "message": {"content": "{"}}]})
            reply = analysis(
                title=user_payload["title"],
                summary=user_payload["content"],
                why_it_matters="",
                evidence=[user_payload["content"]],
            )
            return httpx.Response(200, json={"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(reply)}}]})
        if schema_name == "onionflash_select":
            return httpx.Response(
                200, json={"choices": [{"finish_reason": "stop", "message": {"content": json.dumps({"winner": 1, "reason": "Best candidate."})}}]}
            )
        if schema_name == "onionflash_polish":
            draft = json.loads(body["messages"][1]["content"])["draft"]
            reply = {k: draft[k] for k in ("title", "summary", "why_it_matters")}
            return httpx.Response(200, json={"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(reply)}}]})
        return httpx.Response(200, json={"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(verdict())}}]})

    monkeypatch.setattr(
        llm,
        "HttpClient",
        lambda settings, **kwargs: HttpClient(
            settings, **kwargs, transport=httpx.MockTransport(_handle), resolver=public_dns
        ),
    )

    report = cli.run(cfg, store)
    assert report["analyzed"] == 1
    assert report["analysis_failed"] == 2
    assert report["model_calls"] == 15
    assert len(store.stories()) == 1
    rows = {
        r["url"]: (r["status"], r["attempts"], r["rejections"])
        for r in store.db.execute("SELECT url, status, attempts, rejections FROM items")
    }
    assert rows == {
        ok_item["url"]: ("published", 0, 0),
        retry_item["url"]: ("pending", 1, 0),
        bad_item["url"]: ("pending", 1, 1),
    }


def test_pluggable_transport_high_impact_priority_outranks_dependency_chores(store):
    """Boost pluggable-transport security, crash, DoS, and nginx issues ahead of chore(deps) bumps."""
    assert PT_SECURITY_PRIORITY == 20
    pt_crash = item(
        url="https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/-/issues/401",
        title="Snowflake broker panic on malformed offer",
        content="A malformed client offer triggers a broker panic and memory exhaustion.",
        labels=[],
    )
    pt_nginx = item(
        url="https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/webtunnel/-/issues/19",
        title="WebTunnel nginx proxy DoS via HTTP/2 header flood",
        content="Repeated oversized headers cause nginx worker exhaustion.",
        labels=[],
    )
    chore_bump = item(
        url="https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/-/merge_requests/312",
        kind="gitlab_mr",
        title="chore(deps): bump github.com/pion/webrtc to v4.0.1",
        content="Routine dependency version bump for CI builds.",
        labels=[],
    )
    assert item_priority(pt_crash) >= PT_SECURITY_PRIORITY
    assert item_priority(pt_nginx) >= PT_SECURITY_PRIORITY
    assert item_priority(chore_bump) == 0
    assert item_priority(pt_crash) > item_priority(chore_bump)
    assert item_priority(pt_nginx) > item_priority(chore_bump)

    store.ingest(chore_bump, DATE)
    store.ingest(pt_crash, DATE)
    queued = store.pending(10, DATE)
    assert [r["url"] for r in queued] == [pt_crash["url"], chore_bump["url"]]


def test_cli_opt_in_adapters_include_best_of_quote_digest_and_specialists(monkeypatch):
    """Pass `best_of=3`, `quote_digest=True`, and `specialists=3` when target signatures accept them."""
    seen: list[dict] = []

    class _FullAnalyzer:
        def __init__(self, config, deadline=None, editorial_polish=False, best_of=1, quote_digest=False):
            seen.append({
                "deadline": deadline,
                "editorial_polish": editorial_polish,
                "best_of": best_of,
                "quote_digest": quote_digest,
            })

    monkeypatch.setattr(cli, "Analyzer", _FullAnalyzer)
    cli._new_analyzer(DEFAULTS, deadline=99.0)
    assert seen == [{"deadline": 99.0, "editorial_polish": True, "best_of": 3, "quote_digest": True}]

    def _spec_process(cfg, store, row, writer, reviewer, observed=None, *, allow_network=True,
                      parallel_verify=False, reviewer_factory=None, specialists=1):
        """Specialist-capable process_item double."""

    factory = lambda: None
    monkeypatch.setattr(cli, "process_item", _spec_process)
    assert cli._parallel_verify_kwargs(True, factory) == {
        "parallel_verify": True,
        "reviewer_factory": factory,
        "specialists": 3,
    }


def test_cli_refresh_list_and_guarded_retry(tmp_path, capsys):
    """List refresh states read-only and require CAS `--expect-hash` + `--reason` for `refresh retry`."""
    from onionflash import refresh as refresh_mod
    from onionflash.analyze import cache_key

    cfg_path = write_toml(tmp_path)
    db_path = tmp_path / "state.sqlite3"
    with Store(db_path) as store:
        s1 = seed_story(
            store,
            item(url="https://example.org/ref-cli-1", title="Held refresh story", content="Initial report body."),
            analysis(title="Held refresh story", summary="Initial report body.", evidence=["Initial report body."]),
        )
        for idx in range(1, 4):
            ts = after(idx * 3600, DATE)
            upd = item(
                url=f"https://example.org/ref-cli-1/upd/{idx}",
                title=f"Follow-up {idx}",
                content=f"Milestone {idx} details.",
                published_at=ts,
                updated_at=ts,
            )
            row = pending(store, upd, at=ts, ready=ts, target=s1["id"])
            finish_reviewed(
                store, row, update_analysis(update=f"Milestone {idx} verified.", evidence=[upd["content"]]),
                cache_key(row, DEFAULTS["llm"]), ts,
            )
        cand = store.refresh_candidates(limit=5)[0]
        policy = "a" * 64
        store.record_refresh_status(
            s1["id"],
            update_count=3,
            refreshed_hash=cand["refreshed_hash"],
            status="held",
            observed=LATER,
            code="held.refresh.review_rejected",
            reason="review_hold",
            extra={"title": s1["title"], "hold_code": "source_support"},
            policy_hash=policy,
        )

    # `refresh list` is read-only (works even while run_lock is held) and returns joined metadata.
    with run_lock(str(db_path)) as held:
        assert held
        listed = invoke_cli(capsys, "refresh", "list", "--config", cfg_path)
        assert len(listed["refreshes"]) == 1
        entry = listed["refreshes"][0]
        assert entry["story_id"] == s1["id"]
        assert entry["title"] == "Held refresh story"
        assert entry["state"] == "developing"
        assert entry["story_update_count"] == 3
        assert entry["update_count"] == 3
        assert entry["status"] == "held"
        assert entry["reason"] == "review_hold"
        assert entry["hold_code"] == "source_support"
        assert entry["policy_hash"] == policy
        assert entry["refreshed_hash"] == cand["refreshed_hash"]

        assert invoke_cli(capsys, "refresh", "list", "--config", cfg_path, "--status", "refreshed")["refreshes"] == []
        assert len(invoke_cli(capsys, "refresh", "list", "--config", cfg_path, "--status", "held")["refreshes"]) == 1

        # `refresh retry` acquires run_lock and returns exit 75 when busy.
        busy = invoke_cli(
            capsys, "refresh", "retry", "--config", cfg_path,
            "--story", s1["id"], "--expect-hash", cand["refreshed_hash"], "--reason", "Retry after prompt update",
            expected=75,
        )
        assert busy["status"] == "already-running"

    # Mismatched `--expect-hash` is rejected with exit 2 and leaves story_refreshes intact.
    bad = invoke_cli(
        capsys, "refresh", "retry", "--config", cfg_path,
        "--story", s1["id"], "--expect-hash", "0" * 64, "--reason", "Wrong hash",
        expected=2,
    )
    assert "changed" in bad["error"].lower()

    # Valid `--expect-hash` clears the refresh record so the story is immediately re-eligible.
    retried = invoke_cli(
        capsys, "refresh", "retry", "--config", cfg_path,
        "--story", s1["id"], "--expect-hash", cand["refreshed_hash"], "--reason", "Retry under v2 policy",
    )
    assert retried["status"] == "pending_retry"
    assert retried["before_status"] == "held"
    assert invoke_cli(capsys, "refresh", "list", "--config", cfg_path)["refreshes"] == []

    # Second retry with same hash is rejected since the record was cleared.
    invoke_cli(
        capsys, "refresh", "retry", "--config", cfg_path,
        "--story", s1["id"], "--expect-hash", cand["refreshed_hash"], "--reason", "Duplicate retry",
        expected=2,
    )

    with Store(db_path) as store:
        assert [c["story_id"] for c in store.refresh_candidates(limit=5, policy_hash=policy)] == [s1["id"]]
        assert refresh_mod.MAX_REFRESHES_PER_RUN == 4
