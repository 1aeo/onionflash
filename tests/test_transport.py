"""HTTP transport safety: SSRF defense, retry bounds, decompression limits, and deadlines."""

from datetime import datetime, timezone
import gzip
import socket
import time
from unittest.mock import Mock
import zlib

import httpcore
import httpx
import pytest

from onionflash.transport import (
    AddressPolicy, DeadlineReached, FetchError, HttpClient, Response,
    _CheckedBackend, _DeadlineStream, retry_delay,
)


def public_dns(host, port, *args):
    return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", port))]


def make_client(handler, **settings):
    sleeps = []
    cfg = {"retry_attempts": 3, "backoff_base_seconds": 1, "backoff_cap_seconds": 10,
           "backoff_jitter": 0, "max_retry_after_seconds": 20, "max_response_bytes": 1000, **settings}
    return HttpClient(cfg, transport=httpx.MockTransport(handler), resolver=public_dns, sleep=sleeps.append), sleeps


def checked_client(addresses, body=b"ok", attempts=1):
    resolved, connected = [], []

    def resolver(host, port, *args):
        resolved.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port)) for address in addresses]

    class Backend(httpcore.MockBackend):
        def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
            connected.append((host, port, timeout))
            return super().connect_tcp(host, port, timeout, local_address, socket_options)

    client = HttpClient({"retry_attempts": attempts, "backoff_base_seconds": 0}, resolver=resolver, sleep=lambda _: None)
    client._client._transport.backend.backend = Backend(
        [b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body]
    )
    return client, resolved, connected


def test_transient_retry_then_success():
    calls = []
    client, waits = make_client(lambda req: (calls.append(req), httpx.Response(503 if len(calls) < 3 else 200, content=b"ok"))[1])
    with client:
        assert client.request("GET", "https://example.org/feed").body == b"ok"
    assert len(calls) == 3 and waits == [1, 2]


def test_nontransient_error_not_retried_or_body_leaked():
    handle = Mock(return_value=httpx.Response(401, content=b"secret credential=very-sensitive"))
    client, waits = make_client(handle)
    with client, pytest.raises(FetchError) as err:
        client.request("GET", "https://example.org/feed")
    assert str(err.value) == "HTTP 401" and err.value.status == 401
    assert handle.call_count == 1 and not waits


def test_retry_after_is_capped():
    calls = []
    client, waits = make_client(
        lambda req: (calls.append(req), httpx.Response(429, headers={"retry-after": "99999999"}))[1],
        retry_attempts=2,
    )
    with client, pytest.raises(FetchError) as err:
        client.request("GET", "https://example.org")
    assert err.value.status == 429 and err.value.retryable
    assert waits == [20] and len(calls) == 2


def test_network_errors_are_sanitized_and_bounded():
    def handle(req):
        raise httpx.ConnectError("token=private-value", request=req)

    client, waits = make_client(handle, retry_attempts=2)
    with client, pytest.raises(FetchError) as err:
        client.request("GET", "https://example.org")
    assert str(err.value) == "network request failed" and waits == [1]


@pytest.mark.parametrize("url", [
    "http://example.org", "https://name:secret@example.org", "file:///etc/passwd",
    "https://127.0.0.1", "https://[::1]", "https://169.254.169.254/latest",
    "https://[::ffff:127.0.0.1]", "https://[64:ff9b::a9fe:a9fe]", "https://example.org:99999",
])
def test_unsafe_url_rejected_before_transport(url):
    handler = Mock(return_value=httpx.Response(200))
    client, _ = make_client(handler)
    with client, pytest.raises(FetchError):
        client.request("GET", url)
    assert handler.call_count == 0


def test_redirect_and_origin_header_isolation():
    priv = Mock(return_value=httpx.Response(302, headers={"location": "http://169.254.169.254/"}))
    client, _ = make_client(priv)
    with client, pytest.raises(FetchError):
        client.request("GET", "https://example.org")
    assert priv.call_count == 1

    calls = []
    def xorigin(req):
        calls.append(req)
        if len(calls) == 1:
            return httpx.Response(302, headers={"location": "https://second.example/feed", "set-cookie": "x=secret; Domain=.example"})
        return httpx.Response(200, content=b"ok")

    client, _ = make_client(xorigin)
    with client:
        client.request("GET", "https://first.example/feed",
                       headers={"Authorization": "Bearer secret", "X-Api-Key": "secret", "Cookie": "custom=secret"})
    for header in ("authorization", "x-api-key", "cookie"):
        assert header not in calls[1].headers

    post_redirect = Mock(return_value=httpx.Response(307, headers={"location": "https://second.example/"}))
    client, _ = make_client(post_redirect)
    with client, pytest.raises(FetchError, match="cross-origin"):
        client.request("POST", "https://first.example/", json_body={"private": "content"})
    assert post_redirect.call_count == 1

    loop = Mock(return_value=httpx.Response(302, headers={"location": "/again"}))
    client, _ = make_client(loop, max_redirects=2)
    with client, pytest.raises(FetchError, match="redirect limit"):
        client.request("GET", "https://example.org")
    assert loop.call_count == 3


def test_cookies_do_not_persist_and_methods_are_restricted():
    calls = []
    client, waits = make_client(
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
    client, _ = make_client(lambda _: httpx.Response(200, headers=headers, stream=httpx.ByteStream(payload)))
    with client, pytest.raises(FetchError, match="byte limit"):
        client.request("GET", "https://example.org")


def test_compression_variants_304_and_deadline_reached():
    multi_gzip = gzip.compress(b"hello ") + gzip.compress(b"world")
    comp = zlib.compressobj(level=6, wbits=-zlib.MAX_WBITS)
    raw_deflate = comp.compress(b"raw deflate payload") + comp.flush()

    class Streamed(httpx.SyncByteStream):
        def __init__(self, payload: bytes):
            self.payload = payload

        def __iter__(self):
            yield self.payload[:4]
            yield self.payload[4:]

    now = [100.0]

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/gzip":
            return httpx.Response(200, headers={"content-encoding": "gzip"}, stream=Streamed(multi_gzip))
        if req.url.path == "/deflate":
            return httpx.Response(200, headers={"content-encoding": "deflate"}, stream=Streamed(raw_deflate))
        if req.url.path == "/304":
            return httpx.Response(304, headers={"content-encoding": "gzip"}, stream=httpx.ByteStream(b""))
        now[0] = 200.0
        raise httpx.ReadTimeout("deadline expired")

    with HttpClient({"retry_attempts": 1}, transport=httpx.MockTransport(handler), resolver=public_dns,
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
    pol = AddressPolicy()
    assert pol.permits("192.88.99.1") is False
    assert pol.permits("2001:db8::1") is False
    assert pol.permits("2606:4700::200:5efe:127.0.0.1") is False
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
    stream = Mock()
    bounded = _DeadlineStream(stream, lambda timeout: min(timeout, 0.25))
    bounded.read(8192, timeout=30)
    bounded.write(b"data", timeout=30)
    bounded.start_tls(ssl_context=object(), server_hostname="original.example", timeout=30)
    assert stream.read.call_args.kwargs["timeout"] == 0.25
    assert stream.write.call_args.kwargs["timeout"] == 0.25
    assert stream.start_tls.call_args.kwargs["timeout"] == 0.25
    assert stream.start_tls.call_args.kwargs["server_hostname"] == "original.example"

    delegate = Mock()
    backend = _CheckedBackend(AddressPolicy(resolver=public_dns), delegate)
    backend.deadline = 0
    with pytest.raises(httpcore.ReadTimeout):
        backend.connect_tcp("example.org", 443, timeout=10)
    assert delegate.connect_tcp.call_count == 0


def test_api_error_body_deep_json_and_retry_delay_math():
    client, _ = make_client(lambda _: httpx.Response(500, content=b"internal-password=do-not-log"), retry_attempts=1)
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
    client, resolved, connected = checked_client(["93.184.216.34"])
    with client:
        assert client.request("GET", "https://example.org/feed").body == b"ok"
    assert resolved == ["example.org"]
    assert [(host, port) for host, port, _ in connected] == [("93.184.216.34", 443)]

    client, resolved, connected = checked_client(["93.184.216.34", "10.0.0.7"], attempts=3)
    with client, pytest.raises(FetchError, match="not permitted") as caught:
        client.request("GET", "https://example.org/feed")
    assert not caught.value.retryable and resolved == ["example.org"] and connected == []

    client, _, connected = checked_client(["93.184.216.34"])
    with client:
        client.deadline = time.monotonic() + 2
        client.request("GET", "https://example.org/feed")
    assert connected[0][2] <= 2
