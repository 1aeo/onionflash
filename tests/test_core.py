import copy
import json
from pathlib import Path

import pytest

from onionflash.analyze import AnalysisError, validate_analysis
from onionflash.cli import build, run_lock
from onionflash.collect import CollectionError, collect_source
from onionflash.config import DEFAULTS, load_config
from onionflash.store import Store
from onionflash.transport import FetchError, Response
from onionflash.util import after, canonical_url, item_cluster, plain_text


DATE = "2026-11-08T12:00:00Z"


def source(**kw):
    return {
        "id": "test",
        "name": "Test source",
        "url": "https://example.org/feed.xml",
        "kind": "feed",
        "fallback_urls": [],
        "authority": "community",
        "product": "network",
        "enabled": True,
        "interval_seconds": 300,
        "max_pages": 2,
        "max_items": 100,
        **kw,
    }


def item(**kw):
    return {
        "id": "example",
        "source_id": "test",
        "url": "https://example.org/news/1",
        "title": "A reported security incident",
        "content": "The operator reported a plausible compromise and said its keys must no longer be trusted.",
        "published_at": DATE,
        "updated_at": DATE,
        "kind": "gitlab_issue",
        "product": "tor",
        "authority": "development",
        "labels": ["Security"],
        **kw,
    }


def analysis(**kw):
    return {
        "publish": True,
        "title": "Operator reports possible compromise",
        "summary": "The operator reported a plausible compromise and stopped trusting the affected keys.",
        "why_it_matters": "The report concerns directory authority trust.",
        "category": "security",
        "priority": "high",
        "confidence": "reported",
        "state": "developing",
        "products": ["tor"],
        "tags": ["security"],
        "evidence": ["The operator reported a plausible compromise"],
        **kw,
    }


def config(tmp_path):
    result = copy.deepcopy(DEFAULTS)
    result["storage"]["database"] = str(tmp_path / "state.sqlite3")
    result["storage"]["output_dir"] = str(tmp_path / "public")
    result["sources"] = [source()]
    return result


class FakeClient:
    def __init__(self, values):
        self.values = iter(values)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        result = next(self.values)
        if isinstance(result, Exception):
            raise result
        return result


def response(body, headers=None, status=200):
    return Response(status, body, headers or {}, "https://example.org/feed.xml")


def test_plain_text_never_keeps_script_or_controls():
    assert (
        plain_text(
            "<p>Hello</p><script>steal()</script><style>bad</style>world\x00", 100
        )
        == "Hello\nworld"
    )


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "http://example.org/news",
        "https://user:secret@example.org/",
        "https://127.0.0.1/",
        "https://127.1/",
        "https://224.0.0.1/",
        "https://localhost/",
        "https://foo.internal/",
        "https://example.org/\nheader",
    ],
)
def test_bad_citation_urls_are_rejected(url):
    with pytest.raises(ValueError):
        canonical_url(url)


def test_gitlab_aliases_share_identity():
    assert (
        canonical_url(
            "https://gitlab.torproject.org/tpo/core/tor/-/issues/123?utm_source=x"
        )
        == "https://gitlab.torproject.org/tpo/core/tor/-/work_items/123"
    )


def test_false_evidence_and_extra_model_fields_rejected():
    with pytest.raises(AnalysisError):
        validate_analysis(analysis(evidence=["This was definitely confirmed"]), item())
    with pytest.raises(AnalysisError):
        validate_analysis({**analysis(), "url": "https://evil.example/"}, item())


def test_confirmation_cannot_be_invented_from_public_issue():
    result = validate_analysis(analysis(confidence="confirmed"), item())
    assert result["confidence"] == "reported"


def test_bastet_requested_removal_cannot_be_published_as_completed():
    body = "Last night, bastet's operator notified us that the machine is very plausibly compromised. In any kind of scenario here, the keys can't be trusted anymore and bastet will generate a new identity soon. In the meantime, remove bastet from source as we can't trust it anymore."
    src = item(title="dirauth: Remove bastet from list", content=body)
    quote = "the machine is very plausibly compromised"
    wrong = analysis(
        title="Bastet reported plausibly compromised",
        summary="The Tor team has removed bastet from the source code.",
        state="resolved",
        evidence=[quote],
    )
    with pytest.raises(AnalysisError, match="completed action"):
        validate_analysis(wrong, src)
    correct = analysis(
        title="Bastet reported plausibly compromised",
        summary="Tor's issue requests removal of bastet after the operator reported a plausible compromise.",
        state="resolved",
        evidence=[quote],
    )
    assert validate_analysis(correct, src)["state"] == "developing"
    with pytest.raises(AnalysisError, match="uncertainty"):
        validate_analysis(
            {**correct, "title": "Bastet directory authority compromised"}, src
        )


def test_tags_and_merges_are_not_release_availability():
    assert (
        validate_analysis(analysis(state="released"), item(kind="tag"))["state"]
        == "tagged"
    )
    assert (
        validate_analysis(analysis(state="released"), item(kind="gitlab_mr"))["state"]
        == "merged"
    )


def test_queue_is_durable_and_idempotent(tmp_path):
    db = tmp_path / "state.db"
    with Store(db) as store:
        assert store.ingest(item(), DATE)
        row = store.pending(1, DATE)[0]
        store.defer(row["id"], "Provider unavailable", DEFAULTS["llm"], DATE)
        assert not store.pending(1, DATE)
        assert store.pending_count() == 1
        assert not store.ingest(
            item(updated_at="2026-11-09T00:00:00Z"), "2026-11-09T00:00:00Z"
        )
    with Store(db) as store:
        assert store.pending_count() == 1
        row = store.pending(1, "2026-11-09T00:00:00Z")[0]
        store.finish(row, analysis(), "cache", DATE)
        assert store.pending_count() == 0
        assert len(store.stories(10)) == 1
        record = store.db.execute("SELECT result FROM analyses WHERE cache_key='cache'").fetchone()
        assert json.loads(record[0])["title"] == analysis()["title"]  # kept as a write-only record


def test_stale_fallback_cannot_replace_a_newer_item(tmp_path):
    with Store(tmp_path / "state.db") as store:
        store.ingest(item(updated_at="2026-11-09T00:00:00Z"), DATE)
        assert not store.ingest(item(content="Older stale cached report"), DATE)
        assert (
            json.loads(store.pending(1, "2026-11-09T00:00:00Z")[0]["payload"])[
                "content"
            ]
            == item()["content"]
        )


def test_exact_body_duplicates_merge_but_distinct_claims_do_not(tmp_path):
    body = item()["content"] * 3
    with Store(tmp_path / "state.db") as store:
        for n in (1, 2):
            store.ingest(item(url=f"https://example.org/{n}", content=body), DATE)
            row = store.pending(1, DATE)[0]
            store.finish(row, analysis(), f"cache{n}", DATE)
        stories = store.stories(10)
        assert len(stories) == 1
        assert len(stories[0]["sources"]) == 2
    assert item_cluster(
        item(content="Unrelated event", url="https://example.org/other")
    ) != item_cluster(item())
    assert item_cluster(item(content=body, title="Unrelated title")) != item_cluster(
        item(content=body)
    )
    assert item_cluster(
        item(content=body, title="dirauth: Remove bastet from list")
    ) == item_cluster(item(content=body, title="Remove bastet from list"))


def test_release_mirrors_merge_and_tags_cannot_downgrade_announced_release(tmp_path):
    release = item(
        url="https://example.org/released",
        kind="feed",
        title="Tor 0.4.9.16 released",
        product="network",
    )
    tag = item(
        url="https://example.org/tag",
        kind="tag",
        title="tor-0.4.9.16",
        updated_at="2026-11-09T00:00:00Z",
    )
    assert item_cluster(release) == item_cluster(tag)
    with Store(tmp_path / "state.db") as store:
        store.ingest(release, DATE)
        store.finish(
            store.pending(1, DATE)[0],
            analysis(title="Tor 0.4.9.16 released", state="released"),
            "release",
            DATE,
        )
        store.ingest(tag, DATE)
        store.finish(
            store.pending(1, DATE)[0],
            analysis(title="Tor tag created", state="tagged"),
            "tag",
            DATE,
        )
        story = store.stories(1)[0]
        assert (
            story["state"] == "released" and story["title"] == "Tor 0.4.9.16 released"
        )
        assert len(story["sources"]) == 2


def test_older_mirror_only_adds_source_without_editorial_rollback(tmp_path):
    body = item()["content"] * 3
    with Store(tmp_path / "state.db") as store:
        newer = item(
            url="https://example.org/new",
            content=body,
            updated_at="2026-11-09T00:00:00Z",
        )
        older = item(url="https://example.org/old", content=body)
        store.ingest(newer, DATE)
        store.finish(
            store.pending(1, DATE)[0], analysis(title="Newest facts"), "new", DATE
        )
        store.ingest(older, DATE)
        store.finish(
            store.pending(1, DATE)[0], analysis(title="Old facts"), "old", DATE
        )
        assert store.stories(1)[0]["title"] == "Newest facts"
        assert len(store.stories(1)[0]["sources"]) == 2


def test_source_failure_keeps_last_success_and_watermark(tmp_path):
    s = source()
    with Store(tmp_path / "state.db") as store:
        store.source(s)
        store.source_success(s, {"url": s["url"], "watermark": DATE}, DATE)
        store.source_failure(s, "HTTP 503", DEFAULTS["collection"], DATE)
        state = store.source(s)
        assert state["watermark"] == DATE and state["last_success"] == DATE
        assert state["error"] == "HTTP 503" and state["next_fetch_at"] > DATE
        changed = source(url="https://other.example/feed")
        assert store.source(changed)["watermark"] is None


def test_collect_fallback_and_conditional_cache():
    xml = b'<?xml version="1.0"?><rss version="2.0"><channel><title>News</title><item><title>Hello</title><link>https://example.org/one</link><description>Safe story</description><pubDate>Sun, 08 Nov 2026 10:00:00 GMT</pubDate></item></channel></rss>'
    s = source(fallback_urls=["https://backup.example/feed.xml"])
    client = FakeClient(
        [
            FetchError("HTTP 503", status=503, retryable=True),
            response(xml, {"etag": "abc"}),
        ]
    )
    result = collect_source(client, s, {}, DEFAULTS["collection"], DATE)
    assert len(result["items"]) == 1 and result["url"] == s["fallback_urls"][0]
    client = FakeClient([response(b"", status=304)])
    result = collect_source(
        client, s, {"active_url": s["url"], "etag": "abc"}, DEFAULTS["collection"], DATE
    )
    assert result["items"] == [] and result["etag"] == "abc"
    assert client.calls[0][2]["headers"]["If-None-Match"] == "abc"


@pytest.mark.parametrize(
    "body",
    [
        b"<rss><bad>",
        b'<!DOCTYPE rss [<!ENTITY attack "boom">]><rss/>',
        b"<html>Not a feed</html>",
    ],
)
def test_malformed_or_entity_feeds_rejected(body):
    with pytest.raises(CollectionError):
        collect_source(
            FakeClient([response(body)]), source(), {}, DEFAULTS["collection"], DATE
        )


def test_utf16_entity_declarations_are_rejected_before_feedparser():
    xml = '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE rss [<!ENTITY x "ENTITY_EXPANDED">]><rss version="2.0"><channel><title>&x;</title></channel></rss>'
    with pytest.raises(CollectionError, match="disallowed"):
        collect_source(
            FakeClient([response(xml.encode("utf-16"))]),
            source(),
            {},
            DEFAULTS["collection"],
            DATE,
        )


def test_a_feed_with_too_many_elements_is_rejected_before_feedparser(monkeypatch):
    from onionflash import collect
    monkeypatch.setattr(collect, "MAX_FEED_ELEMENTS", 10)
    monkeypatch.setattr(collect.feedparser, "parse", lambda *args, **kwargs: pytest.fail("feedparser ran"))
    xml = ("<rss><channel>" + "<item/>" * 20 + "</channel></rss>").encode()
    with pytest.raises(CollectionError, match="too many XML elements"):
        collect_source(FakeClient([response(xml)]), source(), {}, DEFAULTS["collection"], DATE)


def test_large_attributes_and_a_normal_base_are_accepted():
    item = '<item data-padding="' + "x" * 40000 + '"><title>Item {n}</title><link>https://example.org/{n}</link></item>'
    xml = (f'<rss version="2.0" xml:base="https://example.org/"><channel><title>News</title>'
           f'{item.format(n=1)}{item.format(n=2)}</channel></rss>')
    result = collect_source(FakeClient([response(xml.encode())]), source(), {}, DEFAULTS["collection"], DATE)
    assert sorted(row["title"] for row in result["items"]) == ["Item 1", "Item 2"]


def test_an_absolute_base_on_every_entry_does_not_accumulate():
    item = ('<item xml:base="https://example.org/2026/11/10/a-fairly-long-permalink-for-post-{n}/">'
            '<title>Item {n}</title><link>https://example.org/{n}</link></item>')
    xml = '<rss version="2.0"><channel><title>News</title>' + "".join(item.format(n=n) for n in range(1000)) + "</channel></rss>"
    result = collect_source(FakeClient([response(xml.encode())]), source(max_items=1000), {}, DEFAULTS["collection"], DATE)
    assert len(result["items"]) == 1000


def test_deep_nesting_is_rejected_before_feedparser(monkeypatch):
    from onionflash import collect
    monkeypatch.setattr(collect.feedparser, "parse", lambda *args, **kwargs: pytest.fail("feedparser ran"))
    with pytest.raises(CollectionError, match="nested too deeply"):
        collect_source(FakeClient([response(("<rss>" + "<a>" * 128 + "</a>" * 128 + "</rss>").encode())]),
                       source(), {}, DEFAULTS["collection"], DATE)


def test_base_text_copied_to_every_element_is_bounded_before_feedparser(monkeypatch):
    from onionflash import collect
    monkeypatch.setattr(collect.feedparser, "parse", lambda *args, **kwargs: pytest.fail("feedparser ran"))
    # Feedparser copies the current base into every later element: beneath it, or
    # after it when a closed element's base stays current under a parent without one.
    base = "https://example.org/" + "a" * 60000 + "/"
    for xml in (f'<rss xml:base="{base}">' + "<item/>" * 200 + "</rss>",
                f'<rss><a BASE="{base}">' + "<b/>" * 200 + "</a></rss>",
                f'<rss><channel><item xml:base="{base}"/>' + "<item><title>x</title></item>" * 100 + "</channel></rss>",
                # An absolute base with a scheme feedparser does not accept leaves the long one current.
                f'<rss><channel><item xml:base="{base}"/>' + '<item xml:base="data://x/"><title>x</title></item>' * 100
                + "</channel></rss>",
                "<rss>" + ('<a xml:base="' + "a" * 60000 + '/">') * 100 + "</a>" * 100 + "</rss>"):
        with pytest.raises(CollectionError, match="xml:base text"):
            collect_source(FakeClient([response(xml.encode())]), source(), {}, DEFAULTS["collection"], DATE)


def gitlab_records(*stamps):
    return json.dumps([
        {"web_url": f"https://example.org/issues/{n}", "title": f"Report {n}", "description": "Body",
         "created_at": stamp, "updated_at": stamp}
        for n, stamp in enumerate(stamps)
    ]).encode()


def gitlab_queries(client):
    from urllib.parse import parse_qs, urlsplit
    return [parse_qs(urlsplit(call[1]).query) for call in client.calls]


def test_gitlab_first_poll_uses_the_lookback_and_sets_an_overlapping_watermark():
    client = FakeClient([response(gitlab_records(DATE))])
    result = collect_source(client, source(kind="gitlab_issue"), {}, DEFAULTS["collection"], DATE)
    query = gitlab_queries(client)[0]
    assert query["updated_after"] == [after(-DEFAULTS["collection"]["lookback_days"] * 86400, DATE)]
    assert query["updated_before"] == [DATE] and query["sort"] == ["asc"] and query["page"] == ["1"]
    assert result["watermark"] == after(-DEFAULTS["collection"]["overlap_seconds"], DATE)


def test_gitlab_catch_up_keeps_partial_items_and_resumes_from_the_last_row(tmp_path):
    stream = source(kind="gitlab_issue", max_pages=1)
    settings = {**DEFAULTS["collection"], "page_size": 2}
    with Store(tmp_path / "state.db") as store:
        client = FakeClient([response(gitlab_records("2026-11-01T00:00:00Z", "2026-11-02T00:00:00.250Z"))])
        with pytest.raises(CollectionError, match="catching up") as exc:
            collect_source(client, stream, store.source(stream), settings, DATE)
        assert len(exc.value.items) == 2 and exc.value.catching_up
        store.source_failure(stream, str(exc.value), settings, DATE, exc.value.watermark, exc.value.catching_up)
        client = FakeClient([response(gitlab_records("2026-11-03T00:00:00Z"))])
        result = collect_source(client, stream, store.source(stream), settings, "2026-11-08T12:05:00Z")
        query = gitlab_queries(client)[0]
        assert query["updated_after"] == ["2026-11-02T00:00:00.250Z"] and query["page"] == ["1"]
        store.source_success(stream, result, "2026-11-08T12:05:00Z")
        assert store.source(stream)["watermark"] == after(-settings["overlap_seconds"], "2026-11-08T12:05:00Z")


def test_gitlab_full_page_sharing_one_timestamp_steps_through_the_tie():
    tie = "2026-11-02T00:00:00.000Z"
    client = FakeClient([response(gitlab_records(tie, tie)), response(gitlab_records(tie, tie)),
                         response(gitlab_records(tie))])
    collect_source(client, source(kind="gitlab_issue", max_pages=3),
                   {"watermark": "2026-11-01T00:00:00Z"}, {**DEFAULTS["collection"], "page_size": 2}, DATE)
    assert [(q["updated_after"][0], q["page"][0]) for q in gitlab_queries(client)] == [
        ("2026-11-01T00:00:00Z", "1"), (tie, "1"), (tie, "2")]


def test_only_a_run_spent_entirely_inside_one_timestamp_skips_past_it():
    tie, settings = "2026-11-02T00:00:00.000Z", {**DEFAULTS["collection"], "page_size": 2}
    stream = source(kind="gitlab_issue", max_pages=2)
    # Moving into a large tie resumes at the tie: the next run has its whole budget for it.
    client = FakeClient([response(gitlab_records("2026-11-01T00:00:00Z", tie)), response(gitlab_records(tie, tie))])
    with pytest.raises(CollectionError, match="catching up") as exc:
        collect_source(client, stream, {"watermark": "2026-10-31T00:00:00Z"}, settings, DATE)
    assert exc.value.watermark == tie
    # A whole run inside the tie would restart it at page 1 forever, so it skips past it.
    client = FakeClient([response(gitlab_records(tie, tie)), response(gitlab_records(tie, tie))])
    with pytest.raises(CollectionError, match="same-timestamp") as exc:
        collect_source(client, stream, {"watermark": tie}, settings, DATE)
    assert exc.value.watermark == "2026-11-02T00:00:00.001Z" and exc.value.catching_up


def test_a_gitlab_fetch_error_keeps_items_and_resumes_where_the_failed_request_began():
    from onionflash.transport import DeadlineReached
    settings, stream = {**DEFAULTS["collection"], "page_size": 2}, source(kind="gitlab_issue", max_pages=2)
    for error in (FetchError("HTTP 503", retryable=True), DeadlineReached()):
        client = FakeClient([response(gitlab_records("2026-11-01T00:00:00Z", "2026-11-02T00:00:00Z")), error])
        with pytest.raises(CollectionError) as exc:
            collect_source(client, stream, {"watermark": "2026-10-31T00:00:00Z"}, settings, DATE)
        assert len(exc.value.items) == 2 and exc.value.watermark == "2026-11-02T00:00:00Z"
        assert not exc.value.catching_up  # an ordinary failure still backs off
    # Without progress the stored watermark stays as it was.
    with pytest.raises(CollectionError) as exc:
        collect_source(FakeClient([FetchError("HTTP 503", retryable=True)]), stream,
                       {"watermark": "2026-10-31T00:00:00Z"}, settings, DATE)
    assert exc.value.watermark is None


def test_malformed_gitlab_timestamp_cannot_abort_the_entire_cycle():
    records = [
        {
            "web_url": "https://gitlab.torproject.org/tpo/core/tor/-/issues/1",
            "title": "Security report",
            "description": "Body",
            "created_at": {"bad": "value"},
            "updated_at": DATE,
        }
    ]
    result = collect_source(
        FakeClient([response(json.dumps(records).encode(), {"x-next-page": ""})]),
        source(kind="gitlab_issue"),
        {},
        DEFAULTS["collection"],
        DATE,
    )
    assert result["items"][0]["published_at"] == DATE


def test_a_failing_source_is_deferred_and_does_not_starve_queued_analysis(
    tmp_path, monkeypatch
):
    from onionflash import cli

    cfg = config(tmp_path)

    class DummyContext:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def analyze(self, payload):
            return analysis()

    def timeout(*args):
        raise CollectionError("request deadline reached")

    monkeypatch.setattr(cli, "HttpClient", DummyContext)
    monkeypatch.setattr(cli, "Analyzer", DummyContext)
    monkeypatch.setattr(cli, "collect_source", timeout)
    with Store(tmp_path / "state.db") as store:
        store.ingest(item(), DATE)
        result = cli.run(cfg, store)
        assert result["sources_failed"] == 1 and result["analyzed"] == 1
        assert store.source(cfg["sources"][0])["next_fetch_at"] is not None


def test_request_deadline_is_never_slept_past():
    import socket
    import httpx
    from onionflash.transport import HttpClient

    calls, sleeps = [], []
    settings = {**DEFAULTS["http"], "retry_attempts": 3, "backoff_base_seconds": 5}
    resolver = lambda *args: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]
    clock = [100.0]
    def busy(request):
        calls.append(request)
        return httpx.Response(503, content=b"busy")
    with HttpClient(settings, transport=httpx.MockTransport(busy), resolver=resolver,
                    sleep=sleeps.append, clock=lambda: clock[0]) as client:
        client.deadline = 102.0  # less than one 5 s retry wait away
        with pytest.raises(FetchError, match="deadline") as caught:
            client.request("GET", "https://example.org/")
        assert caught.value.retryable
        clock[0] = 103.0
        with pytest.raises(FetchError, match="deadline"):
            client.request("GET", "https://example.org/")
    assert len(calls) == 1 and sleeps == []


def test_retry_after_past_the_deadline_is_not_replaced_by_a_shorter_backoff():
    import socket
    import httpx
    from onionflash.transport import DeadlineReached, HttpClient

    calls, sleeps = [], []
    settings = {**DEFAULTS["http"], "retry_attempts": 3, "backoff_base_seconds": 1}
    resolver = lambda *args: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]
    def limited(request):
        calls.append(request)
        return httpx.Response(429, headers={"Retry-After": "30"}, content=b"slow down")
    with HttpClient(settings, transport=httpx.MockTransport(limited), resolver=resolver,
                    sleep=sleeps.append, clock=lambda: 100.0) as client:
        client.deadline = 110.0  # the 30 s Retry-After does not fit; a 1 s backoff would
        with pytest.raises(DeadlineReached):
            client.request("GET", "https://example.org/")
        assert client.deadline_reached
    assert len(calls) == 1 and sleeps == []


def test_the_deadline_flag_describes_only_the_latest_request():
    import socket
    import httpx
    from onionflash.transport import DeadlineReached, HttpClient

    settings = {**DEFAULTS["http"], "retry_attempts": 3, "backoff_base_seconds": 1}
    resolver = lambda *args: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]
    def respond(request):
        if request.url.path == "/primary":
            return httpx.Response(429, headers={"Retry-After": "30"}, content=b"slow down")
        return httpx.Response(404, content=b"missing")
    with HttpClient(settings, transport=httpx.MockTransport(respond), resolver=resolver,
                    sleep=lambda seconds: None, clock=lambda: 100.0) as client:
        client.deadline = 110.0
        with pytest.raises(DeadlineReached):
            client.request("GET", "https://example.org/primary")
        # A fallback that then fails with a 404 while time remains is a real failure.
        with pytest.raises(FetchError, match="404"):
            client.request("GET", "https://example.org/fallback")
        assert not client.deadline_reached


@pytest.mark.parametrize("source_budget,shared", [(600, True), (5, False)])
def test_a_deadline_cutoff_is_penalized_only_when_it_is_the_source_budget(tmp_path, monkeypatch, source_budget, shared):
    from onionflash import cli

    cfg = config(tmp_path)
    cfg["collection"]["source_budget_seconds"] = source_budget
    cfg["sources"] = [source(id="first"), source(id="second", url="https://example.org/second.xml")]
    collected = []

    class Client:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    def collect(client, stream, *args):
        collected.append(stream["id"])
        client.deadline_reached = True
        raise CollectionError("request deadline reached")

    monkeypatch.setattr(cli, "HttpClient", Client)
    monkeypatch.setattr(cli, "collect_source", collect)
    monkeypatch.setattr(cli, "build", lambda *args: {})
    with Store(tmp_path / "state.db") as store:
        result = cli.run(cfg, store)
        first = store.source(cfg["sources"][0])
    # The shared window ends collection without a penalty; a source that overran
    # its own budget is a failure, and the next source still runs.
    assert bool(result.get("budget_reached")) is shared
    assert first["failures"] == (0 if shared else 1)
    assert collected == (["first"] if shared else ["first", "second"])


def test_render_failure_preserves_prior_site(tmp_path, monkeypatch):
    cfg = config(tmp_path)
    with Store(tmp_path / "state.db") as store:
        store.source(cfg["sources"][0])
        store.source_success(cfg["sources"][0], {"url": cfg["sources"][0]["url"]}, DATE)
        store.ingest(item(), DATE)
        store.finish(store.pending(1, DATE)[0], analysis(), "cache", DATE)
        assert build(cfg, store) == {"public_changed": True, "published_stories": 1, "stories_skipped": 0}
        before = (tmp_path / "public/index.html").read_bytes()
        assert build(cfg, store)["published_stories"] == 1
        assert (tmp_path / "public/index.html").read_bytes() == before  # deterministic output

        def fail(*args, **kwargs):
            raise ValueError("simulated renderer failure")

        monkeypatch.setattr("onionflash.render.index_html", fail)
        with pytest.raises(ValueError):
            build(cfg, store)
        assert (tmp_path / "public/index.html").read_bytes() == before


def test_existing_unowned_output_is_never_deleted(tmp_path):
    cfg = config(tmp_path)
    out = tmp_path / "public"
    out.mkdir()
    (out / "keep.txt").write_text("mine")
    with Store(tmp_path / "state.db") as store:
        with pytest.raises(ValueError):
            build(cfg, store)
    assert (out / "keep.txt").read_text() == "mine"


def test_source_website_change_rebuilds_without_resetting_collection(tmp_path):
    cfg = config(tmp_path)
    source = cfg["sources"][0]
    with Store(tmp_path / "state.db") as store:
        store.source(source)
        store.source_success(source, {"url": source["url"]}, DATE)
        state = store.source(source)
        build(cfg, store)
        # Without website_url the label is not linked (never to the raw feed/API URL).
        assert f'href="{source["url"]}"' not in (tmp_path / "public/index.html").read_text()
        source["website_url"] = "https://example.org/mailing-list/"
        build(cfg, store)
        assert f'href="{source["website_url"]}"' in (tmp_path / "public/index.html").read_text()
        assert store.source(source) == state


def test_concurrent_run_lock_is_nonblocking(tmp_path):
    with run_lock(str(tmp_path / "db")) as first:
        with run_lock(str(tmp_path / "db")) as second:
            assert first and not second


def test_example_config_resolves_paths_and_rejects_dangerous_settings(
    tmp_path, monkeypatch
):
    text = (Path(__file__).parents[1] / "config.example.toml").read_text()
    p = tmp_path / "config.toml"
    p.write_text(text)
    monkeypatch.setenv("ONIONFLASH_LLM_BASE_URL", "https://model.example/v1")
    cfg = load_config(p)
    assert cfg["storage"]["database"] == str(tmp_path / "state/onionflash.sqlite3")
    assert len(cfg["sources"]) >= 10
    p.write_text(text.replace("retry_attempts = 3", "retry_attempts = 0"))
    with pytest.raises(ValueError):
        load_config(p)
    p.write_text(text.replace('output_dir = "build/public"', 'output_dir = "."'))
    with pytest.raises(ValueError):
        load_config(p)


def test_skipped_story_count_is_reported_on_every_build(tmp_path):
    cfg = config(tmp_path)
    with Store(tmp_path / "state.db") as store:
        for url in ["https://example.org/news/1", "https://example.org/news/2"]:
            store.ingest(item(url=url, content=url), DATE)
        for row in store.pending(10, DATE):
            store.finish(row, analysis(), "key-" + row["id"], DATE)
        store.db.execute("UPDATE stories SET payload=json_set(payload, '$.priority', 'urgent') "
                         "WHERE rowid=(SELECT MIN(rowid) FROM stories)")
        assert build(cfg, store) == {"public_changed": True, "published_stories": 1, "stories_skipped": 1}
        assert build(cfg, store) == {"public_changed": False, "published_stories": 1, "stories_skipped": 1}


def test_story_precedence_keeps_confirmed_account_but_follows_its_own_updates(tmp_path):
    def publish(store, url, updated, content=item()["content"], **result):
        store.ingest(item(url=url, title="Arti 2.8.0 released", updated_at=updated, kind="feed", content=content,
                          product="arti"), updated)
        row = next(r for r in store.pending(10, updated) if r["url"] == url)
        store.finish(row, analysis(**result), "key-" + url + updated, updated)
        return store.stories(10)

    later = "2026-11-08T13:00:00Z"
    latest = "2026-11-08T14:00:00Z"
    with Store(tmp_path / "state.db") as store:
        official = dict(title="Arti 2.8.0 released", confidence="confirmed", state="released")
        publish(store, "https://blog.example/arti", DATE, **official)
        # A later, unconfirmed item in the same release cluster adds a source but not its text.
        stories = publish(store, "https://gitlab.example/arti/1", later,
                          title="Arti 2.8.0 release checklist completed", confidence="reported")
        assert len(stories) == 1 and len(stories[0]["sources"]) == 2
        assert (stories[0]["title"], stories[0]["confidence"]) == ("Arti 2.8.0 released", "confirmed")
        # The item that wrote the story can still update it, even to an unconfirmed account.
        stories = publish(store, "https://blog.example/arti", latest, content="Update: the release was withdrawn.",
                          title="Arti 2.8.0 release withdrawn",
                          confidence="reported", state="developing")
        assert (stories[0]["title"], stories[0]["confidence"]) == ("Arti 2.8.0 release withdrawn", "reported")


def test_release_clusters_include_two_part_versions_and_alpha_suffixes():
    def key(title, kind="feed"):
        return item_cluster({"title": title, "kind": kind, "product": "network", "content": "", "url": "https://example.org/" + title})

    assert key("New Release: Tor Browser 16.0") == key("Tor Browser 16.0 is released") == "release:tor-browser:16.0"
    assert key("New Alpha Release: Tor Browser 16.0a14") == "release:tor-browser:16.0a14"
    assert key("Tor 0.4.9.16 is released") == "release:tor:0.4.9.16"
    assert key("Tor 0.5.0.1-alpha is released") == "release:tor:0.5.0.1-alpha"
    assert key("New Release: Tor Browser 15.0.26") == "release:tor-browser:15.0.26"
    assert key("tor-0.4.9.16", kind="tag") == "release:tor:0.4.9.16" and key("arti-v2.8.0", kind="tag") == "release:arti:2.8.0"
    assert key("Tor Browser 16.0-alpha.1 released") != key("Tor Browser 16.0-alpha.2 released")
    assert key("Tor Browser 16.0-alpha.1 released") == "release:tor-browser:16.0-alpha.1"
    # A version that does not directly follow the product name never forms a release cluster.
    assert key("Tor Browser for Ubuntu 24.04: 15.0.26 released").startswith("url:")
    assert key("Tails 7.16 released with Tor Browser 16.0 and Tor 0.4.9.15").startswith("url:")


def test_precedence_compares_with_the_writing_item_not_later_losers(tmp_path):
    def publish(store, url, updated, **result):
        store.ingest(item(url=url, title="Tor 0.4.9.17 released", updated_at=updated, kind="feed", content=url), updated)
        row = next(r for r in store.pending(10, updated) if r["url"] == url)
        store.finish(row, analysis(title=result.pop("title"), **result), "k" + url, updated)
        return store.stories(10)[0]

    with Store(tmp_path / "state.db") as store:
        publish(store, "https://a.example/1", "2026-11-08T12:00:00Z", title="A", confidence="confirmed")
        # A lower-ranked (unconfirmed) item advances the story's updated_at but not its text.
        story = publish(store, "https://b.example/1", "2026-11-08T15:00:00Z", title="B", confidence="reported")
        assert (story["title"], story["updated_at"]) == ("A", "2026-11-08T15:00:00Z")
        # A newer confirmed item than the writer still replaces the text.
        story = publish(store, "https://c.example/1", "2026-11-08T13:00:00Z", title="C", confidence="confirmed")
        assert story["title"] == "C"


def test_legacy_story_without_editorial_fields_survives_successive_items(tmp_path):
    # Same tier and confidence, so the timestamps decide (and must be comparable).
    legacy = {**analysis(title="Tor 0.4.9.18 released"),
              "id": "legacy000000000000000000", "published_at": DATE, "updated_at": "2026-11-08T15:00:00Z",
              "sources": [{"id": "old", "url": "https://old.example/1", "title": "Old", "published_at": DATE}]}
    legacy.pop("evidence")
    with Store(tmp_path / "state.db") as store:
        key = item_cluster(item(title="Tor 0.4.9.18 released", kind="feed"))
        store.db.execute("INSERT INTO stories VALUES(?,?,?,?,?)", (legacy["id"], key, json.dumps(legacy), DATE, legacy["updated_at"]))
        for index, stamp in enumerate(["2026-11-08T13:00:00Z", "2026-11-08T14:00:00Z"]):
            store.ingest(item(url=f"https://new.example/{index}", title="Tor 0.4.9.18 released", kind="feed",
                              content=str(index), updated_at=stamp), stamp)
            row = next(r for r in store.pending(10, stamp) if r["url"].endswith(str(index)))
            store.finish(row, analysis(title=f"Item {index}"), f"k{index}", stamp)
        story = store.stories(10)[0]
    assert story["title"] == "Tor 0.4.9.18 released" and len(story["sources"]) == 3


def test_an_older_single_source_story_can_still_be_updated_by_its_source(tmp_path):
    url = "https://blog.example/tor-0.4.9.19"
    with Store(tmp_path / "state.db") as store:
        store.ingest(item(url=url, title="Tor 0.4.9.19 released", kind="feed"), DATE)
        row = store.pending(1, DATE)[0]
        legacy = {**analysis(title="Tor 0.4.9.19 released", confidence="confirmed", state="released"),
                  "id": "legacy111111111111111111", "published_at": DATE, "updated_at": DATE,
                  "sources": [{"id": row["id"], "url": url, "title": "x", "published_at": DATE}]}
        legacy.pop("evidence")
        store.db.execute("INSERT INTO stories VALUES(?,?,?,?,?)", (legacy["id"], row["cluster_key"], json.dumps(legacy), DATE, DATE))
        later = "2026-11-08T13:00:00Z"
        store.ingest(item(url=url, title="Tor 0.4.9.19 released", kind="feed", content="Withdrawn.", updated_at=later), later)
        store.finish(store.pending(1, later)[0], analysis(title="Tor 0.4.9.19 release withdrawn"), "k", later)
        story = store.stories(1)[0]
    assert story["title"] == "Tor 0.4.9.19 release withdrawn" and story["editorial_item"] == row["id"]


def test_new_story_records_when_onion_flash_added_it(tmp_path):
    later = "2026-11-09T12:00:00Z"
    with Store(tmp_path / "state.db") as store:
        store.ingest(item(published_at="2026-09-22T12:00:00Z", updated_at=later), later)
        store.finish(store.pending(1, later)[0], analysis(), "key", later)
        story = store.stories()[0]
    assert (story["published_at"], story["added_at"]) == ("2026-09-22T12:00:00Z", later)


@pytest.mark.parametrize("base", ["javascript:bad", "https://example.com/x/../", "https://example.com/%2e%2e/",
                                  "https://example.com/?token=secret", "https://secret@example.com/"])
def test_bad_base_url_and_traversal_are_rejected(tmp_path, base):
    path = tmp_path / "config.toml"
    path.write_text(f'[site]\nbase_url = "{base}"\n[[sources]]\nid = "a"\nurl = "https://example.org/feed.xml"\n')
    with pytest.raises(ValueError, match="base_url"):
        load_config(path)


@pytest.mark.parametrize("base", ["https://example.com/news?", "https://example.com/news/#", "https://example.com/news"])
def test_base_url_is_normalized_to_a_clean_directory(tmp_path, base):
    path = tmp_path / "config.toml"
    path.write_text(f'[site]\nbase_url = "{base}"\n[[sources]]\nid = "a"\nurl = "https://example.org/feed.xml"\n')
    assert load_config(path)["site"]["base_url"] == "https://example.com/news/"


def test_retired_settings_are_accepted_and_ignored(tmp_path, caplog):
    path = tmp_path / "config.toml"
    path.write_text(
        '[storage]\nmax_stories = 1000\n[http]\nrequests_per_minute = 30\n'
        '[[sources]]\nid = "a"\nurl = "https://example.org/feed.xml"\n'
    )
    with caplog.at_level("WARNING", logger="onionflash.config"):
        loaded = load_config(path)
    assert "max_stories" not in loaded["storage"] and "requests_per_minute" not in loaded["http"]
    assert "Ignoring retired setting http.requests_per_minute" in caplog.text


def test_busy_lock_status_is_read_only_and_a_skipped_build_is_not_success(tmp_path, capsys):
    import json as _json
    from onionflash.cli import main
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text('[storage]\ndatabase = "db.sqlite3"\noutput_dir = "public"\n'
                        '[[sources]]\nid = "a"\nurl = "https://example.org/feed.xml"\n')
    with run_lock(str(tmp_path / "db.sqlite3")) as held:
        assert held
        assert main(["build", "--config", str(cfg_path)]) == 75
        assert main(["run", "--config", str(cfg_path)]) == 0
        capsys.readouterr()
        assert main(["status", "--config", str(cfg_path)]) == 0
        assert _json.loads(capsys.readouterr().out)["sources"][0]["last_success"] is None
    with Store(tmp_path / "db.sqlite3") as store:
        assert store.db.execute("SELECT COUNT(*) FROM source_state").fetchone()[0] == 0


def test_moved_installation_keeps_building(tmp_path):
    first, moved = tmp_path / "first", tmp_path / "moved"
    first.mkdir()
    with Store(first / "state.db") as store:
        build(config(first), store)
    first.rename(moved)
    with Store(moved / "state.db") as store:
        build(config(moved), store)
    assert (moved / "public" / "index.html").exists()


def test_a_directory_at_the_marker_path_is_not_ownership(tmp_path):
    (tmp_path / "public").mkdir()
    (tmp_path / "public" / "operator-file.txt").write_text("keep")
    (tmp_path / ".public.onionflash-owner").mkdir()
    with Store(tmp_path / "state.db") as store, pytest.raises(ValueError, match="regular file"):
        build(config(tmp_path), store)
    assert (tmp_path / "public" / "operator-file.txt").read_text() == "keep"


def test_status_reports_the_count_recorded_by_the_last_build(tmp_path, capsys):
    import json as _json
    from onionflash.cli import main
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text('[storage]\ndatabase = "db.sqlite3"\noutput_dir = "public"\n'
                        '[[sources]]\nid = "a"\nurl = "https://example.org/feed.xml"\n')
    assert main(["status", "--config", str(cfg_path)]) == 0
    assert _json.loads(capsys.readouterr().out)["published_stories"] is None
    assert main(["build", "--config", str(cfg_path)]) == 0
    capsys.readouterr()
    assert main(["status", "--config", str(cfg_path)]) == 0
    assert _json.loads(capsys.readouterr().out)["published_stories"] == 0


def test_plain_titles_keep_angle_brackets_and_html_titles_are_stripped():
    from onionflash.collect import _item
    stream = source(kind="gitlab_issue")
    plain = _item(stream, "https://example.org/1", "Use Vec<u8> instead of String", "", DATE, DATE, title_html=False)
    assert plain["title"] == "Use Vec<u8> instead of String"
    marked = _item(stream, "https://example.org/2", "A <b>bold</b> claim", "", DATE, DATE)
    assert marked["title"] == "A bold claim"
    assert _item(stream, "https://example.org/3", "t", "", DATE, DATE, labels=["ok", "\ud800bad"])["labels"] == ["ok", "\ufffdbad"]


def test_xhtml_atom_titles_are_stripped_and_plain_ones_kept():
    xml = (b'<feed xmlns="http://www.w3.org/2005/Atom"><title>T</title><id>urn:t</id><updated>2026-11-08T12:00:00Z</updated>'
           b'<entry><title type="xhtml"><div xmlns="http://www.w3.org/1999/xhtml">A <b>bold</b> title</div></title>'
           b'<link href="https://example.org/a"/><id>urn:a</id><updated>2026-11-08T12:00:00Z</updated></entry>'
           b'<entry><title type="text">Use Vec&lt;u8&gt; here</title>'
           b'<link href="https://example.org/b"/><id>urn:b</id><updated>2026-11-08T11:00:00Z</updated></entry></feed>')
    items = collect_source(FakeClient([response(xml)]), source(), {}, DEFAULTS["collection"], DATE)["items"]
    assert [item["title"] for item in items] == ["A bold title", "Use Vec<u8> here"]


def test_website_url_has_no_default_but_timeline_sources_require_one(tmp_path):
    path = tmp_path / "config.toml"
    feed = '[[sources]]\nid = "a"\nurl = "https://example.org/feed.xml"\n'
    path.write_text(feed)
    assert "website_url" not in load_config(path)["sources"][0]
    path.write_text('[[sources]]\nid = "t"\nkind = "metrics_timeline"\nauthority = "telemetry"\n'
                    'url = "https://gitlab.example.org/api/v4/projects/1/repository/files/README.md?ref=main"\n')
    with pytest.raises(ValueError, match="website_url"):
        load_config(path)


def test_a_long_plain_text_title_keeps_its_brackets_in_the_content():
    long_title = "Use Vec<u8> " + "x" * 600
    xml = ('<feed xmlns="http://www.w3.org/2005/Atom"><title>T</title><id>urn:t</id><updated>2026-11-08T12:00:00Z</updated>'
           f'<entry><title type="text">{long_title.replace("<", "&lt;").replace(">", "&gt;")}</title>'
           '<link href="https://example.org/a"/><id>urn:a</id><updated>2026-11-08T12:00:00Z</updated></entry></feed>').encode()
    item_ = collect_source(FakeClient([response(xml)]), source(), {}, DEFAULTS["collection"], DATE)["items"][0]
    assert "Use Vec<u8>" in item_["content"]


def test_future_dates_are_clamped_to_the_poll_except_for_alert_parsers():
    from onionflash.collect import _item
    later = "2062-01-01T00:00:00Z"
    item_ = _item(source(), "https://example.org/1", "t", "", later, later, observed=DATE)
    assert (item_["published_at"], item_["updated_at"]) == (DATE, DATE)
    alert = _item(source(alert_format="consensus"), "https://example.org/2", "t", "", later, later, observed=DATE)
    assert alert["published_at"] == later


def test_rss_guid_that_is_not_a_permalink_is_never_a_citation():
    xml = (b'<rss version="2.0"><channel><title>T</title><link>https://example.org/</link><description>D</description>'
           b'<item><title>No link</title><guid isPermaLink="false">https://example.org/?p=123</guid>'
           b'<pubDate>Sun, 08 Nov 2026 12:00:00 GMT</pubDate></item></channel></rss>')
    assert collect_source(FakeClient([response(xml)]), source(), {}, DEFAULTS["collection"], DATE)["items"] == []


def test_an_unexpected_source_error_is_recorded_and_other_sources_still_run(tmp_path, monkeypatch):
    from onionflash import cli
    cfg = config(tmp_path)
    cfg["sources"] = [source(id="broken", url="https://broken.example/feed.xml"), source(id="fine")]
    def collect(client, stream, *args):
        if stream["id"] == "broken":
            raise RuntimeError("unexpected parser crash")
        return {"items": [], "url": stream["url"]}
    monkeypatch.setattr(cli, "collect_source", collect)
    monkeypatch.setattr(cli, "build", lambda *args: {})
    with Store(tmp_path / "state.db") as store:
        report = cli.run(cfg, store)
        broken = store.source(cfg["sources"][0])
    assert report["sources_failed"] == 1 and report["sources_ok"] == 1
    assert broken["error"].startswith("Unexpected RuntimeError at test_core.py:")
    assert "parser crash" not in broken["error"] and broken["failures"] == 1
