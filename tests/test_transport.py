import gzip
import socket
import unittest
from datetime import datetime, timezone
from unittest.mock import Mock

import httpcore
import httpx

from onionflash.transport import AddressPolicy, FetchError, HttpClient, _CheckedBackend, _DeadlineStream, retry_delay


def public_dns(host, port, *args):
    return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", port))]


class TransportTests(unittest.TestCase):
    def client(self, handler, **settings):
        sleeps = []
        config = {"retry_attempts": 3, "backoff_base_seconds": 1, "backoff_cap_seconds": 10,
                  "backoff_jitter": 0, "max_retry_after_seconds": 20, "requests_per_minute": 0,
                  "max_response_bytes": 1000}
        config.update(settings)
        return HttpClient(config, transport=httpx.MockTransport(handler), resolver=public_dns, sleep=sleeps.append), sleeps

    def test_transient_retry_then_success(self):
        calls = []
        def handle(request):
            calls.append(request)
            return httpx.Response(503 if len(calls) < 3 else 200, content=b"ok")
        client, waits = self.client(handle)
        with client:
            self.assertEqual(client.request("GET", "https://example.org/feed").body, b"ok")
        self.assertEqual(len(calls), 3)
        self.assertEqual(waits, [1, 2])

    def test_nontransient_error_not_retried_or_body_leaked(self):
        handle = Mock(return_value=httpx.Response(401, content=b"secret credential=very-sensitive"))
        client, waits = self.client(handle)
        with client, self.assertRaises(FetchError) as error:
            client.request("GET", "https://example.org/feed")
        self.assertEqual(str(error.exception), "HTTP 401")
        self.assertEqual(error.exception.status, 401)
        self.assertEqual(handle.call_count, 1)
        self.assertFalse(waits)

    def test_retry_after_is_capped(self):
        calls = []
        def handle(request):
            calls.append(request)
            return httpx.Response(429, headers={"retry-after": "99999999"})
        client, waits = self.client(handle, retry_attempts=2)
        with client, self.assertRaises(FetchError) as error:
            client.request("GET", "https://example.org")
        self.assertEqual(error.exception.status, 429)
        self.assertTrue(error.exception.retryable)
        self.assertEqual(waits, [20])
        self.assertEqual(len(calls), 2)

    def test_network_errors_are_sanitized_and_bounded(self):
        def handle(request):
            raise httpx.ConnectError("token=private-value", request=request)
        client, waits = self.client(handle, retry_attempts=2)
        with client, self.assertRaises(FetchError) as error:
            client.request("GET", "https://example.org")
        self.assertEqual(str(error.exception), "network request failed")
        self.assertEqual(waits, [1])

    def test_unsafe_url_rejected_before_transport(self):
        handler = Mock(return_value=httpx.Response(200))
        client, _ = self.client(handler)
        with client:
            for url in ["http://example.org", "https://name:secret@example.org", "file:///etc/passwd",
                        "https://127.0.0.1", "https://[::1]", "https://169.254.169.254/latest",
                        "https://[::ffff:127.0.0.1]", "https://[64:ff9b::a9fe:a9fe]", "https://example.org:99999"]:
                with self.subTest(url=url), self.assertRaises(FetchError):
                    client.request("GET", url)
        self.assertEqual(handler.call_count, 0)

    def test_redirect_to_private_address_rejected(self):
        handler = Mock(return_value=httpx.Response(302, headers={"location": "http://169.254.169.254/"}))
        client, _ = self.client(handler)
        with client, self.assertRaises(FetchError):
            client.request("GET", "https://example.org")
        self.assertEqual(handler.call_count, 1)

    def test_cross_origin_redirect_drops_all_sensitive_headers(self):
        calls = []
        def handle(request):
            calls.append(request)
            if len(calls) == 1:
                return httpx.Response(302, headers={"location": "https://second.example/feed", "set-cookie": "x=secret; Domain=.example"})
            return httpx.Response(200, content=b"ok")
        client, _ = self.client(handle)
        with client:
            client.request("GET", "https://first.example/feed", headers={"Authorization": "Bearer secret", "X-Api-Key": "secret", "Cookie": "custom=secret"})
        for header in ["authorization", "x-api-key", "cookie"]:
            self.assertNotIn(header, calls[1].headers)

    def test_post_body_does_not_cross_origins(self):
        handler = Mock(return_value=httpx.Response(307, headers={"location": "https://second.example/"}))
        client, _ = self.client(handler)
        with client, self.assertRaisesRegex(FetchError, "cross-origin"):
            client.request("POST", "https://first.example/", json_body={"private": "content"})
        self.assertEqual(handler.call_count, 1)

    def test_cookies_do_not_persist_between_requests(self):
        calls = []
        def handle(request):
            calls.append(request)
            return httpx.Response(200, content=b"ok", headers={"set-cookie": "tracking=secret; Path=/"})
        client, _ = self.client(handle)
        with client:
            client.request("GET", "https://example.org/one")
            client.request("GET", "https://example.org/two")
        self.assertNotIn("cookie", calls[1].headers)

    def test_redirect_loop_bounded(self):
        handler = Mock(return_value=httpx.Response(302, headers={"location": "/again"}))
        client, _ = self.client(handler, max_redirects=2)
        with client, self.assertRaisesRegex(FetchError, "redirect limit"):
            client.request("GET", "https://example.org")
        self.assertEqual(handler.call_count, 3)

    def test_decompressed_size_limit(self):
        data = gzip.compress(b"A" * 500_000)
        handler = lambda request: httpx.Response(200, headers={"content-encoding": "gzip"}, stream=httpx.ByteStream(data))
        client, _ = self.client(handler)
        with client, self.assertRaisesRegex(FetchError, "byte limit"):
            client.request("GET", "https://example.org")

    def test_valid_compressed_body(self):
        data = gzip.compress(b"hello")
        handler = lambda request: httpx.Response(200, headers={"content-encoding": "gzip"}, stream=httpx.ByteStream(data))
        client, _ = self.client(handler)
        with client:
            self.assertEqual(client.request("GET", "https://example.org").body, b"hello")

    def test_declared_size_rejected_before_read(self):
        handler = lambda request: httpx.Response(200, headers={"content-length": "999999"}, stream=httpx.ByteStream(b"small"))
        client, _ = self.client(handler)
        with client, self.assertRaisesRegex(FetchError, "byte limit"):
            client.request("GET", "https://example.org")

    def test_actual_stream_size_limited_without_content_length(self):
        handler = lambda request: httpx.Response(200, stream=httpx.ByteStream(b"X" * 1001))
        client, _ = self.client(handler)
        with client, self.assertRaisesRegex(FetchError, "byte limit"):
            client.request("GET", "https://example.org")

    def test_conditional_304_does_not_decode_body(self):
        handler = Mock(return_value=httpx.Response(304, headers={"content-encoding": "gzip"}, stream=httpx.ByteStream(b"")))
        client, _ = self.client(handler)
        with client:
            response = client.request("GET", "https://example.org", conditional={"If-None-Match": '"etag"'})
        self.assertEqual(response.status, 304)
        self.assertEqual(response.body, b"")
        self.assertEqual(handler.call_args.args[0].headers['if-none-match'], '"etag"')

    def test_private_access_requires_explicit_allowlist(self):
        dns = lambda host, port, *args: [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.168.50.10", port))]
        handle = httpx.MockTransport(lambda r: httpx.Response(200, json={"ready": True}))
        with HttpClient({"requests_per_minute": 0}, transport=handle, resolver=dns,
                        allow_http=True, allowed_networks=["192.168.50.10/32"]) as client:
            self.assertTrue(client.request("GET", "http://model.example:18000/health").json()["ready"])
        with HttpClient({"requests_per_minute": 0}, transport=handle, resolver=dns, allow_http=True) as client:
            with self.assertRaises(FetchError):
                client.request("GET", "http://model.example:18000/health")

    def test_dns_rebinding_cannot_change_address_after_validation(self):
        resolver = Mock(side_effect=[public_dns("example.org", 443), [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 443))]])
        delegate = Mock()
        backend = _CheckedBackend(AddressPolicy(resolver=resolver), delegate)
        stream = backend.connect_tcp("example.org", 443, timeout=10)
        self.assertIs(stream.stream, delegate.connect_tcp.return_value)
        self.assertEqual(delegate.connect_tcp.call_args.args, ("8.8.8.8", 443))
        self.assertEqual(resolver.call_count, 1)
        with self.assertRaises(FetchError):
            backend.connect_tcp("example.org", 443, timeout=10)
        self.assertEqual(delegate.connect_tcp.call_count, 1)

    def test_mixed_public_private_dns_is_rejected(self):
        dns = lambda *args: public_dns("x", 443) + [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("10.0.0.1", 443))]
        with self.assertRaises(FetchError):
            AddressPolicy(resolver=dns).addresses("example.org", 443)

    def test_deadline_is_applied_to_every_socket_read_write_and_tls(self):
        stream = Mock()
        bounded = _DeadlineStream(stream, lambda timeout: min(timeout, 0.25))
        bounded.read(8192, timeout=30)
        bounded.write(b"data", timeout=30)
        bounded.start_tls(ssl_context=object(), server_hostname="original.example", timeout=30)
        self.assertEqual(stream.read.call_args.kwargs["timeout"], 0.25)
        self.assertEqual(stream.write.call_args.kwargs["timeout"], 0.25)
        self.assertEqual(stream.start_tls.call_args.kwargs["timeout"], 0.25)
        self.assertEqual(stream.start_tls.call_args.kwargs["server_hostname"], "original.example")

    def test_expired_deadline_prevents_connect(self):
        delegate = Mock()
        backend = _CheckedBackend(AddressPolicy(resolver=public_dns), delegate)
        backend.deadline = 0
        with self.assertRaises(httpcore.ReadTimeout):
            backend.connect_tcp("example.org", 443, timeout=10)
        self.assertEqual(delegate.connect_tcp.call_count, 0)

    def test_api_error_body_not_retained(self):
        handler = lambda request: httpx.Response(500, content=b"internal-password=do-not-log")
        client, _ = self.client(handler, retry_attempts=1)
        with client, self.assertRaises(FetchError) as error:
            client.request("POST", "https://example.org", json_body={"messages": []})
        self.assertNotIn("password", str(error.exception))

    def test_retry_after_date_and_invalid_value(self):
        settings = {"backoff_base_seconds": 2, "backoff_cap_seconds": 10, "max_retry_after_seconds": 20, "backoff_jitter": 0}
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.assertEqual(retry_delay(0, settings, "Thu, 01 Jan 2026 00:01:00 GMT", now=now), 20)
        self.assertEqual(retry_delay(2, settings, "invalid", now=now), 8)
        self.assertEqual(retry_delay(30, settings, None), 10)


class PublisherTransportTests(unittest.TestCase):
    def test_strict_origin_policy_rejects_even_get_redirects(self):
        handler = Mock(return_value=httpx.Response(302, headers={"location": "https://other.example/path"}))
        with HttpClient({"requests_per_minute": 0}, transport=httpx.MockTransport(handler),
                        resolver=public_dns, same_origin_redirects=True) as client:
            with self.assertRaisesRegex(FetchError, "cross-origin redirect refused"):
                client.request("GET", "https://example.org/path", headers={"Authorization": "Bearer secret"})
        self.assertEqual(handler.call_count, 1)

    def test_delete_keeps_method_on_same_origin_redirect(self):
        calls = []
        def handler(request):
            calls.append(request)
            return httpx.Response(307, headers={"location": "/route/new"}) if len(calls) == 1 else httpx.Response(204)
        with HttpClient({"requests_per_minute": 0}, transport=httpx.MockTransport(handler),
                        resolver=public_dns, same_origin_redirects=True) as client:
            self.assertEqual(client.request("DELETE", "https://example.org/route/old").status, 204)
        self.assertEqual([request.method for request in calls], ["DELETE", "DELETE"])

    def test_fixed_jitter_is_supported_and_capped(self):
        settings = {"backoff_base_seconds": 2, "backoff_cap_seconds": 10,
                    "backoff_jitter_seconds": 1, "max_retry_after_seconds": 10}
        self.assertEqual(retry_delay(0, settings, jitter=lambda: .5), 2.5)
        self.assertEqual(retry_delay(8, settings, jitter=lambda: 1), 10)


if __name__ == "__main__":
    unittest.main()
