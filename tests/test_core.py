import copy
import json
from pathlib import Path

import pytest

from onionflash.analyze import AnalysisError, _json_object, validate_analysis
from onionflash.cli import build, run_lock
from onionflash.collect import CollectionError, collect_source
from onionflash.config import DEFAULTS, load_config
from onionflash.store import Store
from onionflash.transport import FetchError, Response
from onionflash.util import canonical_url, item_cluster, plain_text


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
        "source_name": "Test source",
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
    with pytest.raises(AnalysisError):
        _json_object('{"publish":true,"publish":false}')


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
        assert store.cached("cache")["title"] == analysis()["title"]


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


def test_deep_or_massive_feed_structure_is_rejected_before_materialization():
    xml = ("<rss>" + "<a>" * 129 + "</a>" * 129 + "</rss>").encode()
    with pytest.raises(CollectionError, match="structure"):
        collect_source(
            FakeClient([response(xml)]), source(), {}, DEFAULTS["collection"], DATE
        )
    xml = b"<rss><channel><item/><item/></channel></rss>"
    with pytest.raises(CollectionError, match="item limit"):
        collect_source(
            FakeClient([response(xml)]),
            source(max_items=1),
            {},
            DEFAULTS["collection"],
            DATE,
        )


def test_gitlab_pagination_keeps_partial_items_without_advancing_watermark():
    records = [
        {
            "web_url": "https://gitlab.torproject.org/tpo/core/tor/-/issues/1",
            "title": "Security report",
            "description": "Body",
            "created_at": DATE,
            "updated_at": DATE,
        }
    ]
    client = FakeClient([response(json.dumps(records).encode(), {"x-next-page": "2"})])
    with pytest.raises(CollectionError) as exc:
        collect_source(
            client,
            source(kind="gitlab_issue", max_pages=1),
            {},
            DEFAULTS["collection"],
            DATE,
        )
    assert len(exc.value.items) == 1
    assert "watermark retained" in str(exc.value)
    assert "updated_before=" in client.calls[0][1]


def test_gitlab_scan_resumes_next_page_then_advances_fixed_watermark(tmp_path):
    s = source(kind="gitlab_issue", max_pages=1)
    records = [
        {
            "web_url": "https://gitlab.torproject.org/tpo/core/tor/-/issues/1",
            "title": "Security report",
            "description": "Body",
            "created_at": DATE,
            "updated_at": DATE,
        }
    ]
    with Store(tmp_path / "state.db") as store:
        state = store.source(s)
        with pytest.raises(CollectionError) as exc:
            collect_source(
                FakeClient(
                    [response(json.dumps(records).encode(), {"x-next-page": "2"})]
                ),
                s,
                state,
                DEFAULTS["collection"],
                DATE,
            )
        store.source_failure(
            s,
            str(exc.value),
            DEFAULTS["collection"],
            DATE,
            exc.value.checkpoint,
            exc.value.catching_up,
        )
        state = store.source(s)
        assert state["watermark"] is None and state["scan_page"] == 2
        client = FakeClient([response(b"[]", {"x-next-page": ""})])
        result = collect_source(
            client, s, state, DEFAULTS["collection"], "2026-11-09T12:00:00Z"
        )
        assert "page=2" in client.calls[0][1] and result["watermark"] == DATE
        store.source_success(s, result, "2026-11-09T12:00:00Z")
        assert (
            store.source(s)["scan_page"] is None
            and store.source(s)["watermark"] == DATE
        )


def test_issue_keyset_cursor_resumes_without_offset_shift(tmp_path):
    from urllib.parse import parse_qs, urlsplit

    s = source(kind="gitlab_issue", max_pages=1, url="https://example.org/issues")
    settings = {**DEFAULTS["collection"], "page_size": 2}

    def records(ids):
        return [
            {
                "web_url": f"https://example.org/issues/{n}",
                "title": f"Report {n}",
                "description": "Body",
                "created_at": DATE,
                "updated_at": DATE,
            }
            for n in ids
        ]

    with Store(tmp_path / "state.db") as store:
        client = FakeClient(
            [
                response(
                    json.dumps(records([1, 2])).encode(),
                    {
                        "link": '<https://example.org/issues?cursor=after-two>; rel="next"'
                    },
                )
            ]
        )
        with pytest.raises(CollectionError) as exc:
            collect_source(client, s, store.source(s), settings, DATE)
        store.source_failure(
            s, str(exc.value), settings, DATE, exc.value.checkpoint, True
        )
        assert store.source(s)["scan_cursor"] == "after-two"
        # Record 1 can leave the window; cursor is still after record 2, not offset 2.
        client = FakeClient(
            [response(json.dumps(records([3, 4])).encode(), {"x-next-page": ""})]
        )
        result = collect_source(
            client, s, store.source(s), settings, "2026-11-09T12:00:00Z"
        )
        query = parse_qs(urlsplit(client.calls[0][1]).query)
        assert query["cursor"] == ["after-two"] and "page" not in query
        assert [x["title"] for x in result["items"]] == ["Report 3", "Report 4"]


def test_untrusted_pagination_link_cannot_change_destination():
    client = FakeClient(
        [
            response(
                b"[]", {"link": '<https://internal.invalid/steal?cursor=x>; rel="next"'}
            )
        ]
    )
    with pytest.raises(CollectionError, match="changed destination"):
        collect_source(
            client, source(kind="gitlab_issue"), {}, DEFAULTS["collection"], DATE
        )
    assert len(client.calls) == 1


@pytest.mark.parametrize("cursor", [None, "after-first"])
def test_exact_full_final_keyset_page_without_pagination_headers_is_terminal(cursor):
    records = [
        {
            "web_url": "https://example.org/issues/41473",
            "title": "Security report",
            "description": "Body",
            "created_at": DATE,
            "updated_at": DATE,
        }
    ]
    client = FakeClient([response(json.dumps(records).encode())])
    state = (
        {}
        if cursor is None
        else {
            "scan_cursor": cursor,
            "scan_page": 2,
            "scan_lower": "2026-10-25T12:00:00Z",
            "scan_upper": DATE,
            "scan_reconcile": True,
        }
    )
    result = collect_source(
        client,
        source(kind="gitlab_issue", max_pages=1),
        state,
        {**DEFAULTS["collection"], "page_size": 1},
        DATE,
    )
    assert result["watermark"] == DATE
    assert len(result["items"]) == 1 and len(client.calls) == 1
    if cursor:
        assert "cursor=after-first" in client.calls[0][1]


def test_full_offset_page_with_next_header_still_requires_continuation():
    records = [
        {
            "web_url": "https://example.org/issues/41473",
            "title": "Security report",
            "description": "Body",
            "created_at": DATE,
            "updated_at": DATE,
        }
    ]
    client = FakeClient([response(json.dumps(records).encode(), {"x-next-page": "2"})])
    with pytest.raises(CollectionError) as exc:
        collect_source(
            client,
            source(kind="gitlab_issue", max_pages=1),
            {},
            {**DEFAULTS["collection"], "page_size": 1},
            DATE,
        )
    assert exc.value.checkpoint["page"] == 2


def test_periodic_reconciliation_rechecks_full_lookback():
    from urllib.parse import parse_qs, urlsplit

    s = source(kind="gitlab_mr")
    client = FakeClient([response(b"[]", {"x-next-page": ""})])
    result = collect_source(
        client,
        s,
        {"watermark": DATE, "last_reconciled": "2026-11-01T12:00:00Z"},
        DEFAULTS["collection"],
        DATE,
    )
    query = parse_qs(urlsplit(client.calls[0][1]).query)
    assert query["updated_after"][0].startswith("2026-10-25")
    assert result["reconciled"] is True


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


def test_slow_source_is_deferred_and_does_not_starve_queued_analysis(
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
        raise cli.RunBudgetReached()

    monkeypatch.setattr(cli, "HttpClient", DummyContext)
    monkeypatch.setattr(cli, "Analyzer", DummyContext)
    monkeypatch.setattr(cli, "collect_source", timeout)
    with Store(tmp_path / "state.db") as store:
        store.ingest(item(), DATE)
        result = cli.run(cfg, store)
        assert result["sources_failed"] == 1 and result["analyzed"] == 1
        assert store.source(cfg["sources"][0])["next_fetch_at"] is not None


def test_transport_cannot_swallow_run_budget_as_a_retryable_network_error():
    import socket
    import time
    import httpx
    from onionflash.cli import RunBudgetReached, time_budget
    from onionflash.transport import HttpClient

    calls = []

    def slow(request):
        calls.append(request)
        time.sleep(0.15)
        return httpx.Response(200, content=b"ok")

    settings = {
        **DEFAULTS["http"],
        "retry_attempts": 2,
        "backoff_base_seconds": 0,
        "requests_per_minute": 10000,
    }
    resolver = lambda *args: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))
    ]
    with HttpClient(
        settings, transport=httpx.MockTransport(slow), resolver=resolver
    ) as client:
        with pytest.raises(RunBudgetReached):
            with time_budget(0.02):
                client.request("GET", "https://example.org/")
    assert len(calls) == 1


def test_render_failure_preserves_prior_site_and_changed_clocks_do_not_rebuild(
    tmp_path, monkeypatch
):
    cfg = config(tmp_path)
    with Store(tmp_path / "state.db") as store:
        store.source(cfg["sources"][0])
        store.source_success(cfg["sources"][0], {"url": cfg["sources"][0]["url"]}, DATE)
        store.ingest(item(), DATE)
        store.finish(store.pending(1, DATE)[0], analysis(), "cache", DATE)
        assert build(cfg, store)["public_changed"]
        before = (tmp_path / "public/index.html").read_bytes()
        assert not build(cfg, store)["public_changed"]

        def fail(*args):
            raise ValueError("simulated renderer failure")

        monkeypatch.setattr("onionflash.render.render_site", fail)
        with pytest.raises(ValueError):
            build(cfg, store, force=True)
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
        assert build(cfg, store)["public_changed"]
        assert f'href="{source["url"]}"' in (tmp_path / "public/index.html").read_text()
        source["website_url"] = "https://example.org/mailing-list/"
        assert build(cfg, store)["public_changed"]
        assert f'href="{source["website_url"]}"' in (tmp_path / "public/index.html").read_text()
        assert store.source(source) == state
        assert not build(cfg, store)["public_changed"]


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


def test_skipped_story_count_is_reported_on_unchanged_builds(tmp_path):
    cfg = config(tmp_path)
    with Store(tmp_path / "state.db") as store:
        for url in ["https://example.org/news/1", "https://news.example.test/a"]:
            store.ingest(item(url=url, content=url), DATE)
        for row in store.pending(10, DATE):
            store.finish(row, analysis(), "key-" + row["id"], DATE)
        assert build(cfg, store) == {"public_changed": True, "stories_skipped": 1}
        assert build(cfg, store) == {"public_changed": False, "stories_skipped": 1}

def test_story_precedence_keeps_confirmed_account_but_follows_its_own_updates(tmp_path):
    def publish(store, url, updated, content=item()["content"], **result):
        store.ingest(item(url=url, title="Arti 2.8.0 released", updated_at=updated, kind="feed", content=content), updated)
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
