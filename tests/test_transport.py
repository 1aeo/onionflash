"""HTTP transport safety, completion redirects, deadlines, and run admission budgets."""

import copy
from datetime import datetime, timezone
import gzip
import json
import socket
import time
from unittest.mock import Mock
import zlib

import httpcore
import httpx
import pytest

from helpers import DATE, analysis, job, job_record, patch_cli_pipeline, pending, public_dns, verdict, write_toml
from onionflash import cli, llm, review, review_gate
from onionflash.analyze import Analyzer
from onionflash.config import DEFAULTS, completion_budget_seconds, load_config, run_command_budget_seconds
from onionflash.llm import AnalysisError, CompletionClient, CompletionDeferred
from onionflash.transport import (
    AddressPolicy, DeadlineReached, FetchError, HttpClient, Response,
    _CheckedBackend, _DeadlineStream, retry_delay,
)


def _make_client(handler, **settings):
    sleeps = []
    cfg = {"retry_attempts": 3, "backoff_base_seconds": 1, "backoff_cap_seconds": 10,
           "backoff_jitter": 0, "max_retry_after_seconds": 20, "max_response_bytes": 1000, **settings}
    return HttpClient(cfg, transport=httpx.MockTransport(handler), resolver=public_dns, sleep=sleeps.append), sleeps


def _checked_client(addresses, attempts=1):
    resolved, connected = [], []

    def _resolver(host, port, *args):
        resolved.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port)) for address in addresses]

    class _Backend(httpcore.MockBackend):
        def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
            """Record `(host, port, timeout)` before delegating to `MockBackend`."""
            connected.append((host, port, timeout))
            return super().connect_tcp(host, port, timeout, local_address, socket_options)

    client = HttpClient({"retry_attempts": attempts, "backoff_base_seconds": 0}, resolver=_resolver, sleep=lambda _: None)
    client._client._transport.backend.backend = _Backend([b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"])
    return client, resolved, connected


def _httpx_completion(value):
    return httpx.Response(200, json={"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(value)}}]})


def _ledger(on_persist=None):
    record = {"reviews": [], **review_gate.initial_review_state()}
    persisted = []

    def _persist():
        persisted.append(copy.deepcopy(record))
        if on_persist is not None:
            on_persist(record)

    return record, review_gate.ReviewRequests(record, _persist), persisted


def _complete(client, requests):
    return client.complete("Assess the supplied evidence.", {"source": "An attributed statement."},
                           {"type": "object"}, "test_completion", on_request=requests.callback())


@pytest.fixture
def completion_client(monkeypatch):
    """Yield a factory building real `CompletionClient` instances over `httpx.MockTransport`."""
    clients = []
    monkeypatch.setenv("COMPLETION_TEST_KEY", "synthetic-fixture-value")

    def _make(handler, *, client_type=review.Reviewer, fallbacks=()):
        config = copy.deepcopy(DEFAULTS)
        config["llm"].update(base_url="https://model.example/v1", fallback_base_urls=list(fallbacks),
                             api_key_env="COMPLETION_TEST_KEY")
        result = client_type(config)
        result.client = HttpClient(result.http_settings, transport=httpx.MockTransport(handler), resolver=public_dns)
        clients.append(result)
        return result, config

    yield _make
    for client in clients:
        client.client.close()


def test_transient_retry_then_success():
    """Retry transient 503 responses with exponential backoff before succeeding."""
    calls = []
    client, waits = _make_client(lambda req: (calls.append(req), httpx.Response(503 if len(calls) < 3 else 200, content=b"ok"))[1])
    with client:
        assert client.request("GET", "https://example.org/feed").body == b"ok"
    assert len(calls) == 3 and waits == [1, 2]


def test_nontransient_error_not_retried_or_body_leaked():
    """Fail immediately on 401 without retrying or exposing sensitive response text."""
    handle = Mock(return_value=httpx.Response(401, content=b"secret credential=very-sensitive"))
    client, waits = _make_client(handle)
    with client, pytest.raises(FetchError) as err:
        client.request("GET", "https://example.org/feed")
    assert str(err.value) == "HTTP 401" and err.value.status == 401
    assert handle.call_count == 1 and not waits


def test_retry_after_is_capped():
    """Cap Retry-After delays to `max_retry_after_seconds`."""
    calls = []
    client, waits = _make_client(
        lambda req: (calls.append(req), httpx.Response(429, headers={"retry-after": "99999999"}))[1],
        retry_attempts=2,
    )
    with client, pytest.raises(FetchError) as err:
        client.request("GET", "https://example.org")
    assert err.value.status == 429 and err.value.retryable
    assert waits == [20] and len(calls) == 2


def test_network_errors_are_sanitized_and_bounded():
    """Sanitize transport exception strings while honoring `retry_attempts`."""
    def _handle(req):
        raise httpx.ConnectError("token=private-value", request=req)

    client, waits = _make_client(_handle, retry_attempts=2)
    with client, pytest.raises(FetchError) as err:
        client.request("GET", "https://example.org")
    assert str(err.value) == "network request failed" and waits == [1]


@pytest.mark.parametrize("url", [
    "http://example.org", "https://name:secret@example.org", "file:///etc/passwd",
    "https://127.0.0.1", "https://127.0.0.1./", "https://127.0.0.1\u3002/", "https://127.1/",
    "https://localhost/", "https://[::1]", "https://169.254.169.254/latest", "https://169.254.169.254./",
    "https://[::ffff:127.0.0.1]", "https://[64:ff9b::a9fe:a9fe]", "https://example.org:99999",
    "https://127.0.0.1 /", "https://foo.local /", "https://example.org../", "https://ops.xn--/",
    "https://bad_underscore.example.org/", "https://foo.123/", f"https://{'a' * 64}.example.org/",
    "https://example.org/\ufffe", "https://example.org\\path",
])
def test_unsafe_url_rejected_before_transport(url):
    """Reject non-HTTPS, credentialed, private-IP, malformed-domain, and out-of-range URLs before dispatch."""
    handler = Mock(return_value=httpx.Response(200))
    client, _ = _make_client(handler)
    with client:
        with pytest.raises(FetchError):
            client._url(url)
        with pytest.raises(FetchError):
            client.request("GET", url)
    assert handler.call_count == 0


def test_redirect_and_origin_header_isolation():
    """Block unsafe/POST redirects, cap redirect hops, and strip cross-origin auth headers."""
    priv = Mock(return_value=httpx.Response(302, headers={"location": "http://169.254.169.254/"}))
    client, _ = _make_client(priv)
    with client, pytest.raises(FetchError):
        client.request("GET", "https://example.org")
    assert priv.call_count == 1

    calls = []

    def _xorigin(req):
        calls.append(req)
        if len(calls) == 1:
            return httpx.Response(302, headers={"location": "https://second.example/feed", "set-cookie": "x=secret; Domain=.example"})
        return httpx.Response(200, content=b"ok")

    client, _ = _make_client(_xorigin)
    with client:
        client.request("GET", "https://first.example/feed",
                       headers={"Authorization": "Bearer secret", "X-Api-Key": "secret", "Cookie": "custom=secret"})
    for header in ("authorization", "x-api-key", "cookie"):
        assert header not in calls[1].headers

    post_redirect = Mock(return_value=httpx.Response(307, headers={"location": "https://second.example/"}))
    client, _ = _make_client(post_redirect)
    with client, pytest.raises(FetchError, match="cross-origin"):
        client.request("POST", "https://first.example/", json_body={"private": "content"})
    assert post_redirect.call_count == 1

    loop = Mock(return_value=httpx.Response(302, headers={"location": "/again"}))
    client, _ = _make_client(loop, max_redirects=2)
    with client, pytest.raises(FetchError, match="redirect limit"):
        client.request("GET", "https://example.org")
    assert loop.call_count == 3


def test_cookies_do_not_persist_and_methods_are_restricted():
    """Never persist Set-Cookie across requests and reject unsupported HTTP verbs."""
    calls = []
    client, waits = _make_client(
        lambda req: (calls.append(req), httpx.Response(200, content=b"ok", headers={"set-cookie": "tracking=secret; Path=/"}))[1]
    )
    with client:
        client.request("GET", "https://example.org/one")
        client.request("GET", "https://example.org/two")
        with pytest.raises(FetchError, match="unsupported request method"):
            client.request("DELETE", "https://example.org/route")
    assert "cookie" not in calls[1].headers and waits == []


@pytest.mark.parametrize("headers,payload", [
    ({"content-encoding": "gzip"}, gzip.compress(b"A" * 500_000)),
    ({"content-length": "999999"}, b"small"),
    ({}, b"X" * 1001),
])
def test_response_size_limits_fail_closed(headers, payload):
    """Fail closed when compressed, declared, or streamed bodies exceed `max_response_bytes`."""
    client, _ = _make_client(lambda _: httpx.Response(200, headers=headers, stream=httpx.ByteStream(payload)))
    with client, pytest.raises(FetchError, match="byte limit"):
        client.request("GET", "https://example.org")


def test_compression_variants_304_and_deadline_reached():
    """Support multi-member gzip, raw deflate, empty 304 responses, and deadline timeouts."""
    multi_gzip = gzip.compress(b"hello ") + gzip.compress(b"world")
    comp = zlib.compressobj(level=6, wbits=-zlib.MAX_WBITS)
    raw_deflate = comp.compress(b"raw deflate payload") + comp.flush()

    class _Streamed(httpx.SyncByteStream):
        def __init__(self, payload: bytes):
            self.payload = payload

        def __iter__(self):
            yield self.payload[:4]
            yield self.payload[4:]

    now = [100.0]

    def _handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/gzip":
            return httpx.Response(200, headers={"content-encoding": "gzip"}, stream=_Streamed(multi_gzip))
        if req.url.path == "/deflate":
            return httpx.Response(200, headers={"content-encoding": "deflate"}, stream=_Streamed(raw_deflate))
        if req.url.path == "/304":
            return httpx.Response(304, headers={"content-encoding": "gzip"}, stream=httpx.ByteStream(b""))
        now[0] = 200.0
        raise httpx.ReadTimeout("deadline expired")

    with HttpClient({"retry_attempts": 1}, transport=httpx.MockTransport(_handler), resolver=public_dns,
                    clock=lambda: now[0]) as client:
        assert client.request("GET", "https://example.org/gzip").body == b"hello world"
        assert client.request("GET", "https://example.org/deflate").body == b"raw deflate payload"
        not_mod = client.request("GET", "https://example.org/304", headers={"If-None-Match": '"etag"'})
        assert not_mod.status == 304 and not_mod.body == b""
        client.deadline = 150.0
        with pytest.raises(DeadlineReached):
            client.request("GET", "https://example.org/slow")
        assert client.deadline_reached is True


def test_private_allowlist_address_policy_and_dns_rebinding():
    """Enforce special-range blocks, explicit private allowlists, and per-connect DNS checks."""
    pol = AddressPolicy()
    assert pol.permits("192.88.99.1") is False
    assert pol.permits("2001:db8::1") is False
    assert pol.permits("2606:4700::100:5efe:127.0.0.1") is False
    assert pol.permits("2606:4700::200:5efe:127.0.0.1") is False
    assert pol.permits("2606:4700::300:5efe:127.0.0.1") is False
    assert pol.permits("2606:4700:4700::1111%lo0") is False
    assert AddressPolicy(["fe80::/10"]).permits("fe80::1%lo0") is False
    assert pol.permits("2606:4700:4700::1111") is True

    dns = lambda host, port, *a: [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.168.50.10", port))]
    handle = httpx.MockTransport(lambda _: httpx.Response(200, json={"ready": True}))
    with HttpClient({}, transport=handle, resolver=dns, allow_http=True, allowed_networks=["192.168.50.10/32"]) as client:
        assert client.request("GET", "http://model.example:18000/health").json()["ready"]
    with HttpClient({}, transport=handle, resolver=dns, allow_http=True) as client, pytest.raises(FetchError):
        client.request("GET", "http://model.example:18000/health")

    resolver = Mock(side_effect=[public_dns("example.org", 443),
                                 [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 443))]])
    delegate = Mock()
    backend = _CheckedBackend(AddressPolicy(resolver=resolver), delegate)
    stream = backend.connect_tcp("example.org", 443, timeout=10)
    assert stream.stream is delegate.connect_tcp.return_value
    assert delegate.connect_tcp.call_args.args == ("8.8.8.8", 443) and resolver.call_count == 1
    with pytest.raises(FetchError):
        backend.connect_tcp("example.org", 443, timeout=10)
    assert delegate.connect_tcp.call_count == 1

    mixed = lambda *a: public_dns("x", 443) + [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("10.0.0.1", 443))]
    with pytest.raises(FetchError):
        AddressPolicy(resolver=mixed).addresses("example.org", 443)


def test_deadline_stream_and_expired_connect():
    """Clamp socket read/write/TLS timeouts to the remaining deadline and abort expired connects."""
    stream = Mock()
    bounded = _DeadlineStream(stream, lambda timeout: min(timeout, 0.25))
    bounded.read(8192, timeout=30)
    bounded.write(b"data", timeout=30)
    bounded.start_tls(ssl_context=object(), server_hostname="original.example", timeout=30)
    assert stream.read.call_args.kwargs["timeout"] == 0.25
    assert stream.write.call_args.kwargs["timeout"] == 0.25
    assert stream.start_tls.call_args.kwargs["timeout"] == 0.25
    assert stream.start_tls.call_args.kwargs["server_hostname"] == "original.example"

    leaked = Mock()
    expired_tls = _DeadlineStream(leaked, Mock(side_effect=httpcore.ReadTimeout("request deadline exceeded")))
    with pytest.raises(httpcore.ReadTimeout):
        expired_tls.start_tls(ssl_context=object(), server_hostname="original.example", timeout=30)
    assert leaked.close.call_count == 1 and leaked.start_tls.call_count == 0

    now = [10.0]
    raw_stream = Mock()
    pool_delegate = Mock()
    pool_delegate.connect_tcp.side_effect = lambda *a, **kw: (now.__setitem__(0, 20.0), raw_stream)[1]
    pool_backend = _CheckedBackend(AddressPolicy(resolver=public_dns), pool_delegate, clock=lambda: now[0])
    pool_backend.deadline = 15.0
    with httpcore.ConnectionPool(network_backend=pool_backend) as pool, pytest.raises(httpcore.ReadTimeout):
        pool.request("GET", "https://example.org/")
    assert raw_stream.close.call_count == 1

    delegate = Mock()
    backend = _CheckedBackend(AddressPolicy(resolver=public_dns), delegate)
    backend.deadline = 0
    with pytest.raises(httpcore.ReadTimeout):
        backend.connect_tcp("example.org", 443, timeout=10)
    assert delegate.connect_tcp.call_count == 0


def test_deadline_expiry_on_precheck_and_final_retryable_fetch_errors():
    """Raise `DeadlineReached` on pre-expired requests and final retryable DNS or 503 attempts."""
    pre_dns = Mock(side_effect=public_dns)
    with HttpClient({"retry_attempts": 1}, transport=httpx.MockTransport(lambda _: httpx.Response(200)),
                    resolver=pre_dns, clock=lambda: 100.0) as client:
        client.deadline = 90.0
        with pytest.raises(DeadlineReached) as pre_err:
            client.request("GET", "https://example.org/")
        assert pre_err.value.request_started is False and client.deadline_reached is True
        assert pre_dns.call_count == 0

    dns_now = [100.0]

    def _slow_dns(*_args):
        dns_now[0] = 200.0
        raise OSError("resolver timed out")

    with HttpClient({"retry_attempts": 1}, transport=httpx.MockTransport(lambda _: httpx.Response(200)),
                    resolver=_slow_dns, clock=lambda: dns_now[0]) as client:
        client.deadline = 150.0
        with pytest.raises(DeadlineReached) as dns_err:
            client.request("GET", "https://example.org/")
        assert dns_err.value.request_started is True and client.deadline_reached is True

    http_now = [100.0]

    def _slow_503(_req):
        http_now[0] = 200.0
        return httpx.Response(503)

    with HttpClient({"retry_attempts": 2, "backoff_base_seconds": 1, "backoff_jitter": 0},
                    transport=httpx.MockTransport(_slow_503), resolver=public_dns,
                    sleep=lambda _: None, clock=lambda: 100.0 if http_now[0] < 150.0 else http_now[0]) as client:
        client.deadline = 150.0
        http_now[0] = 100.0
        calls = []

        def _step_503(_req):
            calls.append(1)
            if len(calls) == 2:
                http_now[0] = 200.0
            return httpx.Response(503)

        client._client._transport = httpx.MockTransport(_step_503)
        with pytest.raises(DeadlineReached) as http_err:
            client.request("GET", "https://example.org/")
        assert http_err.value.request_started is True and client.deadline_reached is True and len(calls) == 2


def test_api_error_body_deep_json_and_retry_delay_math():
    """Scrub 500 error bodies, reject deeply nested JSON, and bound backoff/jitter delays."""
    client, _ = _make_client(lambda _: httpx.Response(500, content=b"internal-password=do-not-log"), retry_attempts=1)
    with client, pytest.raises(FetchError) as err:
        client.request("POST", "https://example.org", json_body={"messages": []})
    assert "password" not in str(err.value)

    with pytest.raises(FetchError, match="invalid JSON response"):
        Response(200, b"[" * 10000 + b"]" * 10000, {}, "https://example.org").json()

    settings = {"backoff_base_seconds": 2, "backoff_cap_seconds": 10, "max_retry_after_seconds": 20, "backoff_jitter": 0}
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert retry_delay(0, settings, "Thu, 01 Jan 2026 00:01:00 GMT", now=now) == 20
    assert retry_delay(2, settings, "invalid", now=now) == 8
    assert retry_delay(30, settings, None) == 10

    jittered = {"backoff_base_seconds": 2, "backoff_cap_seconds": 10, "backoff_jitter": 0.25}
    assert retry_delay(0, jittered, jitter=lambda: 0.5) == 2.25
    assert retry_delay(8, jittered, jitter=lambda: 1) == 10


def test_checked_backend_production_connect_and_deadline_bounds():
    """Connect directly to validated IP literals and propagate monotonic deadline bounds."""
    client, resolved, connected = _checked_client(["93.184.216.34"])
    with client:
        assert client.request("GET", "https://example.org/feed").body == b"ok"
    assert resolved == ["example.org"]
    assert [(host, port) for host, port, _ in connected] == [("93.184.216.34", 443)]

    client, resolved, connected = _checked_client(["93.184.216.34", "10.0.0.7"], attempts=3)
    with client, pytest.raises(FetchError, match="not permitted") as caught:
        client.request("GET", "https://example.org/feed")
    assert not caught.value.retryable and resolved == ["example.org"] and connected == []

    client, _, connected = _checked_client(["93.184.216.34"])
    with client:
        client.deadline = time.monotonic() + 2
        client.request("GET", "https://example.org/feed")
    assert connected[0][2] <= 2


def _assert_charged(client, requests, record, sent, expected):
    assert len(sent) == record["request_budget"]["reserved"] == requests.actual == client.calls == expected


def _arm_deadline(client, clock):
    client.client.clock = lambda: clock[0]
    client.client.deadline = 1.0


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
@pytest.mark.parametrize("client_type", [Analyzer, review.Reviewer])
def test_redirect_never_forwards_completion_or_releases_spent_reservation(completion_client, status, client_type):
    """Refuse completion redirects while keeping the dispatched request charged."""
    record, requests, persisted, sent = *_ledger(), []

    def _handle(request):
        assert persisted[-1]["request_budget"]["reserved"] == len(sent) + 1
        sent.append(request)
        return httpx.Response(status, headers={"location": "/unmetered-hop"})

    client, _ = completion_client(_handle, client_type=client_type)
    with pytest.raises(AnalysisError, match="LLM request failed"):
        _complete(client, requests)
    assert [(request.method, request.url.path) for request in sent] == [("POST", "/v1/chat/completions")]
    _assert_charged(client, requests, record, sent, 1)


def test_redirects_cannot_exceed_budget_through_configured_fallbacks(completion_client):
    """Stop fallback traversal once redirected attempts exhaust the 7-request review budget."""
    record, requests, persisted, sent = *_ledger(), []

    def _handle(request):
        assert persisted[-1]["request_budget"]["reserved"] == len(sent) + 1
        sent.append(request)
        return httpx.Response(307, headers={"location": "/same-origin-loop"})

    fallbacks = [f"https://fallback-{number}.example/v1" for number in range(1, 10)]
    client, _ = completion_client(_handle, fallbacks=fallbacks)
    with pytest.raises(review.ReviewLimitReached, match="budget exhausted"):
        _complete(client, requests)
    _assert_charged(client, requests, record, sent, 7)
    assert all(request.method == "POST" and request.url.path == "/v1/chat/completions" for request in sent)
    assert [request.url.host for request in sent] == ["model.example", *[f"fallback-{n}.example" for n in range(1, 7)]]


def test_explicit_fallback_after_redirect_has_its_own_reservation(completion_client):
    """Reserve a fresh ledger slot when advancing to a configured fallback after a redirect."""
    record, requests, persisted, sent = *_ledger(), []

    def _handle(request):
        assert persisted[-1]["request_budget"]["reserved"] == len(sent) + 1
        sent.append(request)
        if request.url.host == "model.example":
            return httpx.Response(307, headers={"location": "/redirect-is-not-a-fallback"})
        return _httpx_completion({"assessed": True})

    client, _ = completion_client(_handle, fallbacks=["https://fallback.example/v1"])
    assert _complete(client, requests) == {"assessed": True}
    assert [(r.url.host, r.url.path) for r in sent] == [
        ("model.example", "/v1/chat/completions"), ("fallback.example", "/v1/chat/completions")]
    _assert_charged(client, requests, record, sent, 2)
    assert all(r.headers["authorization"] == "Bearer synthetic-fixture-value" for r in sent)


def test_unsent_fallback_refund_keeps_redirected_request_spent(completion_client):
    """Refund only the unsent fallback when deadline expiry blocks fallback dispatch."""
    record, requests, persisted, sent = *_ledger(), []

    def _handle(request):
        sent.append(request)
        client.client.deadline = 0
        return httpx.Response(302, headers={"location": "/ignored-hop"})

    client, _ = completion_client(_handle, fallbacks=["https://fallback.example/v1"])
    with pytest.raises(AnalysisError, match="LLM request failed"):
        _complete(client, requests)
    _assert_charged(client, requests, record, sent, 1)
    assert [r["request_budget"]["reserved"] for r in persisted] == [1, 2, 1]


def test_completion_policy_leaves_source_collection_redirects_available(completion_client):
    """Keep feed/source HTTP redirect settings intact when completion redirects are disabled."""
    sent = []

    def _handle(request):
        sent.append(request)
        if request.url.path == "/feed":
            return httpx.Response(302, headers={"location": "/new-feed"})
        return httpx.Response(200, content=b"source content")

    _, config = completion_client(_handle)
    assert config["http"] == DEFAULTS["http"]
    with HttpClient(config["http"], transport=httpx.MockTransport(_handle), resolver=public_dns) as collector:
        assert collector.request("GET", "https://source.example/feed").body == b"source content"
    assert [(r.method, r.url.path) for r in sent] == [("GET", "/feed"), ("GET", "/new-feed")]


@pytest.mark.parametrize("failure", [httpx.ReadTimeout, httpx.WriteTimeout, httpx.ConnectTimeout,
                                    httpx.RemoteProtocolError, DeadlineReached])
def test_deadline_after_dispatch_keeps_request_charged(completion_client, failure):
    """Keep post-dispatch transport failures charged while refunding subsequent unsent calls."""
    record, requests, persisted, clock, sent = *_ledger(), [0.0], []

    def _handle(request):
        sent.append(request)
        clock[0] = 2.0
        if failure is DeadlineReached:
            raise DeadlineReached()
        raise failure("controlled transport failure", request=request)

    client, _ = completion_client(_handle, fallbacks=["https://fallback.example/v1"])
    _arm_deadline(client, clock)
    with pytest.raises(AnalysisError, match="LLM request failed"):
        _complete(client, requests)
    _assert_charged(client, requests, record, sent, 1)
    assert [value["request_budget"]["reserved"] for value in persisted] == [1]

    with pytest.raises(AnalysisError, match="LLM request failed"):
        _complete(client, requests)
    _assert_charged(client, requests, record, sent, 1)
    assert [value["request_budget"]["reserved"] for value in persisted] == [1, 2, 1]


def test_repeated_dispatched_timeouts_cannot_replenish_budget(completion_client):
    """Enforce the 7-request ceiling across repeated dispatched ReadTimeouts."""
    record, requests, _, clock, sent = *_ledger(), [0.0], []

    def _handle(request):
        sent.append(request)
        clock[0] = 2.0
        raise httpx.ReadTimeout("controlled timeout", request=request)

    client, _ = completion_client(_handle)
    _arm_deadline(client, clock)
    for _ in range(7):
        clock[0] = 0.0
        with pytest.raises(AnalysisError):
            _complete(client, requests)
    clock[0] = 0.0
    with pytest.raises(review.ReviewLimitReached):
        _complete(client, requests)
    _assert_charged(client, requests, record, sent, 7)


def test_response_body_timeout_remains_charged(completion_client):
    """Keep mid-body stream ReadTimeouts charged in the review ledger."""
    record, requests, _, clock, sent = *_ledger(), [0.0], []

    class _IncompleteBody(httpx.SyncByteStream):
        def __iter__(self):
            yield b'{"choices":'
            clock[0] = 2.0
            raise httpx.ReadTimeout("controlled body timeout")

    def _handle(request):
        sent.append(request)
        return httpx.Response(200, stream=_IncompleteBody())

    client, _ = completion_client(_handle)
    _arm_deadline(client, clock)
    with pytest.raises(AnalysisError):
        _complete(client, requests)
    _assert_charged(client, requests, record, sent, 1)


@pytest.mark.parametrize("setting,value", [("retry_attempts", 2), ("max_redirects", 1)])
def test_review_identity_binds_the_effective_completion_transport(monkeypatch, setting, value):
    """Include `CompletionClient.REQUEST_POLICY` transport settings in `review.policy_hash`."""
    config = copy.deepcopy(DEFAULTS)
    before = review.policy_hash(config)
    transport = {**CompletionClient.REQUEST_POLICY["transport"], setting: value}
    monkeypatch.setitem(CompletionClient.REQUEST_POLICY, "transport", transport)
    client = CompletionClient(config)
    assert client.http_settings[setting] == value
    assert review.policy_hash(config) != before


def test_collection_settings_do_not_change_completion_policy_but_refund_contract_does(monkeypatch):
    """Isolate `review.policy_hash` from `[http]` while binding `deadline_refund`."""
    config = copy.deepcopy(DEFAULTS)
    before = review.policy_hash(config)
    config["http"].update(max_redirects=9, retry_attempts=8)
    client = CompletionClient(config)
    assert client.http_settings["max_redirects"] == 0 and client.http_settings["retry_attempts"] == 1
    assert review.policy_hash(config) == before
    monkeypatch.setitem(CompletionClient.REQUEST_POLICY, "deadline_refund", "legacy")
    assert review.policy_hash(config) != before


@pytest.mark.parametrize("timeout", [1, 120, 600, 3600, 3599.5])
def test_configured_completion_allowance_is_explicit(tmp_path, timeout):
    """Compute explicit completion and run budgets from valid `llm.timeout_seconds` values."""
    config = load_config(write_toml(tmp_path, f"[llm]\ntimeout_seconds = {timeout}"))
    assert config["llm"]["timeout_seconds"] == timeout
    assert config["collection"] == DEFAULTS["collection"]
    assert config["http"] == DEFAULTS["http"]
    allowance = max(180, timeout + 10)
    assert completion_budget_seconds(config["llm"]) == allowance
    assert run_command_budget_seconds(config) == 240 + allowance


@pytest.mark.parametrize("timeout", ["0", "3600.1", "true", "nan", "inf"])
def test_invalid_completion_allowance_rejected(tmp_path, timeout):
    """Reject out-of-range, boolean, or non-finite `llm.timeout_seconds` settings."""
    path = write_toml(tmp_path, f"[llm]\ntimeout_seconds = {timeout}")
    with pytest.raises(ValueError, match="timeout_seconds"):
        load_config(path)


def test_expired_admission_is_unsent_even_without_credentials(completion_client, monkeypatch):
    """Raise `CompletionDeferred` before credential checks or reservations when admission expired."""
    client, config = completion_client(lambda request: pytest.fail("Request must remain unsent"))
    monkeypatch.delenv(config["llm"]["api_key_env"])
    client.clock, client.deadline = lambda: 10, 10
    record, requests, persisted = _ledger()
    with pytest.raises(CompletionDeferred):
        _complete(client, requests)
    assert client.calls == requests.actual == record["request_budget"]["reserved"] == 0
    assert persisted == []


def test_expiry_during_reservation_refunds_only_unsent_attempt(completion_client):
    """Refund the reservation when admission expires during `on_request` persistence."""
    client, _ = completion_client(lambda request: pytest.fail("Request must remain unsent"))
    clock = [0]
    client.clock, client.deadline = lambda: clock[0], 10
    record, requests, saved = _ledger(lambda _rec: clock.__setitem__(0, 10))
    with pytest.raises(CompletionDeferred):
        _complete(client, requests)
    assert [entry["request_budget"]["reserved"] for entry in saved] == [1, 0]
    assert client.calls == requests.actual == record["request_budget"]["reserved"] == 0


@pytest.mark.parametrize("expire", ["after_failure", "during_fallback_reservation"])
def test_real_failure_survives_later_fallback_admission_refusal(completion_client, expire):
    """Surface the primary HTTP 503 failure when fallback admission expires before dispatch."""
    clock, sent = [0], []

    def _handle(request):
        sent.append(request)
        clock[0] = 10 if expire == "after_failure" else 1
        return httpx.Response(503)

    client, _ = completion_client(_handle, fallbacks=["https://fallback.example/v1"])
    client.clock, client.deadline = lambda: clock[0], 10
    client.client.clock = client.clock
    record, requests, saved = _ledger(
        lambda rec: clock.__setitem__(0, 10) if rec["request_budget"]["reserved"] == 2 else None
    )
    with pytest.raises(AnalysisError, match="HTTP 503") as caught:
        _complete(client, requests)
    assert caught.value.retryable
    assert len(sent) == client.calls == requests.actual == record["request_budget"]["reserved"] == 1
    assert [entry["request_budget"]["reserved"] for entry in saved] == ([1] if expire == "after_failure" else [1, 2, 1])


@pytest.mark.parametrize("expire", ["writer", "review", "reservation"])
def test_native_run_defers_unsent_work_without_strikes_and_resumes(context, monkeypatch, expire):
    """Defer unsent stages without item strikes when run admission expires, then resume cleanly."""
    config, store = context
    config["sources"] = []
    config["llm"].update(base_url="https://model.example/v1", api_key_env="ADMISSION_TEST_KEY",
                         writer_reasoning=True, timeout_seconds=3600)
    row = pending(store)
    clock, sent, settings_seen = [0.0], [], []
    monkeypatch.setenv("ADMISSION_TEST_KEY", "synthetic-fixture-value")
    monkeypatch.setattr(cli.time, "monotonic", lambda: clock[0])
    patch_cli_pipeline(monkeypatch, now=DATE, reviewer=None, build=lambda *_args: {})
    monkeypatch.setattr(review_gate, "now_iso", lambda: DATE)

    def _handle(request):
        body = json.loads(request.content)
        writer = body["max_tokens"] == 32768
        assert request.extensions["onionflash_deadline"] == clock[0] + 3610
        assert request.extensions["timeout"]["read"] == 3600
        sent.append("writer" if writer else "review")
        if (expire == "writer" and len(sent) == 1) or (expire == "review" and len(sent) == 2):
            clock[0] += 300
        return _httpx_completion(analysis(why_it_matters="") if writer else verdict())

    def _factory(settings, **kwargs):
        settings_seen.append(copy.deepcopy(settings))
        return HttpClient(settings, **kwargs, transport=httpx.MockTransport(_handle), resolver=public_dns)

    monkeypatch.setattr(llm, "HttpClient", _factory)
    if expire == "reservation":
        original = review_gate._save
        expired = []

        def _expire_save(*args, **kwargs):
            result = original(*args, **kwargs)
            if not expired and args[7].get("request_budget", {}).get("reserved") == 1:
                expired.append(True)
                clock[0] = 240
            return result

        monkeypatch.setattr(review_gate, "_save", _expire_save)

    first = cli.run(config, store)
    saved = job(store)
    record = job_record(store)
    assert first["budget_reached"] and first["analysis_failed"] == 0
    assert first["model_calls"] == len(sent) == (2 if expire == "review" else 1)
    assert saved["stage"] == ("verify" if expire == "review" else "review")
    assert record["request_budget"]["reserved"] == (1 if expire == "review" else 0)
    current = store.db.execute("SELECT status,attempts,rejections,last_error,next_attempt_at FROM items WHERE id=?", (row["id"],)).fetchone()
    assert tuple(current) == ("pending", 0, 0, None, None)
    assert store.stories() == []
    assert all(settings["timeout_seconds"] == 3600 and settings["total_timeout_seconds"] == 3610 for settings in settings_seen)
    second = cli.run(config, store)
    assert second["analysis_failed"] == 0 and second["model_calls"] == (1 if expire == "review" else 2)
    assert sent == ["writer", "review", "review"]
    assert len(store.stories()) == 1 and job(store) is None


def test_expired_deadline_skips_dns_and_aborts_mid_redirect_hop():
    """Skip blocking DNS on expired deadlines and raise `DeadlineReached` before dispatching a second redirect hop."""
    resolver = Mock(side_effect=public_dns)
    delegate = Mock()
    backend = _CheckedBackend(AddressPolicy(resolver=resolver), delegate, clock=lambda: 100.0)
    backend.deadline = 50.0
    with pytest.raises(httpcore.ReadTimeout):
        backend.connect_tcp("example.org", 443, timeout=10)
    assert resolver.call_count == 0 and delegate.connect_tcp.call_count == 0

    now = [100.0]
    hops = []

    def _redirect_handler(req: httpx.Request) -> httpx.Response:
        hops.append(str(req.url))
        if len(hops) == 1:
            now[0] = 200.0
            return httpx.Response(302, headers={"location": "https://second.example/feed"})
        return httpx.Response(404)

    with HttpClient({"retry_attempts": 1}, transport=httpx.MockTransport(_redirect_handler),
                    resolver=public_dns, clock=lambda: now[0]) as client:
        client.deadline = 150.0
        with pytest.raises(DeadlineReached) as caught:
            client.request("GET", "https://first.example/feed")
        assert caught.value.request_started is True and client.deadline_reached is True
    assert hops == ["https://first.example/feed"]

    fqdn_target = "https://lists.torproject.org./mailman3/hyperkitty/list/tor-dev@lists.torproject.org/feed/"
    looked_up: list[str] = []

    def _recording_dns(host, port, *args):
        looked_up.append(host)
        return public_dns(host, port, *args)

    with HttpClient({"retry_attempts": 1}, transport=httpx.MockTransport(
        lambda req: httpx.Response(301, headers={"location": fqdn_target}) if req.url.host == "old.example"
        else httpx.Response(200, content=b"ok")
    ), resolver=_recording_dns) as client:
        resp = client.request("GET", "https://old.example/feed")
    assert resp.url == "https://lists.torproject.org/mailman3/hyperkitty/list/tor-dev@lists.torproject.org/feed/"
    assert looked_up == ["old.example", "lists.torproject.org."]


def test_trailing_dot_fqdn_dns_post_dns_deadline_and_direct_deadline_reached():
    """Preserve trailing-dot DNS lookup, recheck deadline after DNS, and mark direct DeadlineReached."""
    from onionflash.collect import CollectionError, collect_source
    from helpers import source

    resolved, sni_hosts = [], []

    def _prod_dns(host, port, *args):
        resolved.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    class _RecordingStream(httpcore.MockStream):
        def start_tls(self, ssl_context, server_hostname=None, timeout=None):
            """Record TLS SNI server_hostname before delegating to MockStream."""
            sni_hosts.append(server_hostname)
            return super().start_tls(ssl_context, server_hostname=server_hostname, timeout=timeout)

    class _RedirectBackend(httpcore.MockBackend):
        def __init__(self, responses):
            super().__init__(responses)
            self._responses = list(responses)

        def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
            """Serve sequential raw HTTP responses via _RecordingStream."""
            return _RecordingStream([self._responses.pop(0)])

    client = HttpClient({"retry_attempts": 1, "backoff_base_seconds": 0}, resolver=_prod_dns, sleep=lambda _: None)
    client._client._transport.backend.backend = _RedirectBackend([
        b"HTTP/1.1 302 Found\r\nLocation: https://feed.example.org./news\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 302 Found\r\nLocation: /final\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    ])
    with client:
        resp = client.request("GET", "https://start.example.org/feed")
    assert resp.body == b"ok"
    assert resp.url == "https://feed.example.org/final"
    assert resolved == ["start.example.org", "feed.example.org.", "feed.example.org."]
    assert sni_hosts == ["start.example.org", "feed.example.org", "feed.example.org"]

    now = [100.0]
    handler_calls = []

    def _late_ok_dns(*args):
        now[0] = 200.0
        return public_dns(*args)

    def _handler(req):
        handler_calls.append(str(req.url))
        return httpx.Response(200, content=b"ok")

    with HttpClient({"retry_attempts": 1}, transport=httpx.MockTransport(_handler),
                    resolver=_late_ok_dns, clock=lambda: now[0]) as late_client:
        late_client.deadline = 150.0
        with pytest.raises(DeadlineReached) as late_err:
            late_client.request("GET", "https://example.org/late")
        assert late_err.value.request_started is True
        assert late_client.deadline_reached is True
    assert handler_calls == []

    now[0] = 100.0
    with HttpClient({"retry_attempts": 1}, transport=httpx.MockTransport(_handler),
                    resolver=public_dns, clock=lambda: now[0]) as ok_client:
        ok_client.deadline = 150.0
        assert ok_client.request("GET", "https://example.org/timely").body == b"ok"
    assert handler_calls == ["https://example.org/timely"]

    mirror_hits = []

    def _direct_deadline(req):
        mirror_hits.append(str(req.url))
        raise DeadlineReached()

    with HttpClient({"retry_attempts": 1}, transport=httpx.MockTransport(_direct_deadline),
                    resolver=public_dns) as deadline_client:
        src = source(url="https://primary.example/feed.xml", fallback_urls=["https://mirror.example/feed.xml"])
        with pytest.raises(CollectionError, match="request deadline reached"):
            collect_source(deadline_client, src, {}, DEFAULTS["collection"], DATE)
        assert deadline_client.deadline_reached is True
    assert mirror_hits == ["https://primary.example/feed.xml"]
