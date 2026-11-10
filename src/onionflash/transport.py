"""Bounded HTTP requests with connect-time address checks and retry policy.

Public sources use HTTPS and public IPs. The inference client can explicitly
allow its private networks. DNS is resolved when a TCP connection is opened;
only a vetted numeric address reaches the socket backend, while HTTP Host and
TLS SNI retain the original hostname. Environment proxies are never used.
"""

from __future__ import annotations

import ipaddress
import json
import random
import socket
import ssl
import time
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Callable, Iterable
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpcore
import httpx


RETRY_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504})
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_SAFE_CROSS_ORIGIN_HEADERS = frozenset({"accept", "accept-encoding", "user-agent"})


class FetchError(Exception):
    """A deliberately sanitized error suitable for persistent status records."""

    def __init__(self, message: str, *, status: int | None = None, retryable: bool = False):
        super().__init__(message)
        self.status = status
        self.retryable = retryable


class DeadlineReached(FetchError):
    """The caller's deadline arrived, or a retry wait would pass it. Never retried here."""

    def __init__(self) -> None:
        super().__init__("request deadline reached", retryable=True)


@dataclass(frozen=True)
class Response:
    status: int
    body: bytes
    headers: dict[str, str]
    url: str

    def json(self) -> Any:
        try:
            return json.loads(self.body)
        except (ValueError, UnicodeDecodeError, RecursionError):
            raise FetchError("invalid JSON response") from None


class AddressPolicy:
    def __init__(self, allowed_networks: Iterable[str] = (), *, resolver: Callable = socket.getaddrinfo):
        self.networks = tuple(ipaddress.ip_network(value, strict=True) for value in allowed_networks)
        if any(net.prefixlen == 0 for net in self.networks):
            raise ValueError("a private-network allowlist must not include a default route")
        self.resolver = resolver

    def permits(self, address: str) -> bool:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            return self.permits(str(ip.ipv4_mapped))
        if any(ip.version == net.version and ip in net for net in self.networks):
            return not (ip.is_multicast or ip.is_unspecified)
        if not ip.is_global or ip.is_multicast or ip.is_unspecified:
            return False
        # Translation/tunneling prefixes can reach an embedded private IPv4
        # address even though the outer IPv6 address is classified as global.
        if isinstance(ip, ipaddress.IPv6Address):
            return ip in ipaddress.ip_network("2000::/3") and not (ip.sixtofour or ip.teredo)
        return True

    def addresses(self, host: str, port: int) -> list[str]:
        try:
            records = self.resolver(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        except (OSError, ValueError):
            raise FetchError("DNS resolution failed", retryable=True) from None
        addresses = list(dict.fromkeys(record[4][0] for record in records))
        if not addresses or any(not self.permits(address) for address in addresses):
            raise FetchError("destination address is not permitted")
        return addresses[:8]


class _CheckedBackend(httpcore.NetworkBackend):
    """Validate DNS at the connect boundary, then connect to a literal IP."""

    def __init__(self, policy: AddressPolicy, backend: Any = None):
        self.policy = policy
        self.backend = backend or httpcore.SyncBackend()
        self.deadline: float | None = None

    def budget(self, timeout: float | None) -> float | None:
        if self.deadline is None:
            return timeout
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise httpcore.ReadTimeout("request deadline exceeded")
        return remaining if timeout is None else min(timeout, remaining)

    def connect_tcp(self, host: str, port: int, timeout: float | None = None,
                    local_address: str | None = None, socket_options: Any = None):
        addresses = self.policy.addresses(host, port)
        timeout = self.budget(timeout)
        deadline = time.monotonic() + timeout if timeout is not None else None
        for address in addresses:
            remaining = max(0.0, deadline - time.monotonic()) if deadline is not None else None
            if remaining == 0.0:
                break
            try:
                stream = self.backend.connect_tcp(address, port, timeout=remaining,
                                                  local_address=local_address, socket_options=socket_options)
                return _DeadlineStream(stream, self.budget)
            except (httpcore.ConnectError, httpcore.ConnectTimeout, OSError):
                continue
        raise httpcore.ConnectError("connection failed")

    def connect_unix_socket(self, path: str, timeout: float | None = None, socket_options: Any = None):
        raise FetchError("Unix sockets are not permitted")

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


class _DeadlineStream(httpcore.NetworkStream):
    def __init__(self, stream: Any, budget: Callable):
        self.stream, self.budget = stream, budget

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return self.stream.read(max_bytes, timeout=self.budget(timeout))

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self.stream.write(buffer, timeout=self.budget(timeout))

    def close(self) -> None:
        self.stream.close()

    def start_tls(self, ssl_context: ssl.SSLContext, server_hostname: str | None = None,
                  timeout: float | None = None):
        return _DeadlineStream(self.stream.start_tls(ssl_context=ssl_context, server_hostname=server_hostname,
                                                    timeout=self.budget(timeout)), self.budget)

    def get_extra_info(self, info: str) -> Any:
        return self.stream.get_extra_info(info)


class _ResponseStream(httpx.SyncByteStream):
    def __init__(self, stream: Any):
        self.stream = stream

    def __iter__(self):
        yield from self.stream

    def close(self):
        self.stream.close()


class _CheckedTransport(httpx.BaseTransport):
    """Small adapter using public httpcore APIs, without monkey-patching DNS."""

    def __init__(self, policy: AddressPolicy):
        self.backend = _CheckedBackend(policy)
        self.pool = httpcore.ConnectionPool(
            ssl_context=ssl.create_default_context(),
            max_connections=4,
            max_keepalive_connections=2,
            keepalive_expiry=10.0,
            network_backend=self.backend,
            retries=0,
        )

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.backend.deadline = request.extensions.get("onionflash_deadline")
        result = self.pool.handle_request(httpcore.Request(
            method=request.method,
            url=httpcore.URL(scheme=request.url.raw_scheme, host=request.url.raw_host,
                             port=request.url.port, target=request.url.raw_path),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        ))
        return httpx.Response(result.status, headers=result.headers,
                              stream=_ResponseStream(result.stream), extensions=result.extensions)

    def close(self) -> None:
        self.pool.close()


def retry_delay(attempt: int, settings: dict, retry_after: str | None = None,
                *, jitter: Callable[[], float] = random.random, now: datetime | None = None) -> float:
    """attempt=0 is the delay before the first retry; all waits have a cap."""
    base = float(settings.get("backoff_base_seconds", 1.0))
    cap = float(settings.get("backoff_cap_seconds", 30.0))
    delay = min(cap, base * 2 ** min(attempt, 30))
    spread = settings.get("backoff_jitter_seconds", delay * float(settings.get("backoff_jitter", 0.25)))
    delay = min(cap, delay + float(spread) * jitter())
    if retry_after:
        try:
            value = float(retry_after)
        except ValueError:
            try:
                moment = parsedate_to_datetime(retry_after)
                if moment.tzinfo is None:
                    moment = moment.replace(tzinfo=timezone.utc)
                value = (moment - (now or datetime.now(timezone.utc))).total_seconds()
            except (ValueError, TypeError, OverflowError):
                value = 0.0
        if value > 0:
            delay = max(delay, min(value, float(settings.get("max_retry_after_seconds", 60.0))))
    return delay


class HttpClient:
    """A reusable client for sequential requests; one request may be in flight."""

    def __init__(self, settings: dict, *, allowed_networks: Iterable[str] = (), allow_http: bool = False,
                 transport: httpx.BaseTransport | None = None, resolver: Callable = socket.getaddrinfo,
                 sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic,
                 same_origin_redirects: bool = False):
        self.settings = settings
        self.allow_http = allow_http
        self.same_origin_redirects = same_origin_redirects
        self.policy = AddressPolicy(allowed_networks, resolver=resolver)
        self.sleep = sleep
        self.clock = clock
        self._next_request = 0.0
        # Absolute time.monotonic() deadline set by the caller (None: no limit).
        # Every attempt is capped by it and no retry sleeps past it; deadline_reached
        # records that the deadline, not the server, ended a request.
        self.deadline: float | None = None
        self.deadline_reached = False
        self._injected_transport = transport is not None
        self._client = httpx.Client(
            transport=transport or _CheckedTransport(self.policy),
            timeout=httpx.Timeout(float(settings.get("timeout_seconds", 30.0)),
                                  connect=float(settings.get("connect_timeout_seconds", 10.0))),
            follow_redirects=False,
            trust_env=False,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _url(self, value: str) -> str:
        if not isinstance(value, str) or len(value) > 8192 or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise FetchError("invalid destination URL")
        try:
            parts = urlsplit(value)
            host = parts.hostname
            port = parts.port
            if not host or parts.username is not None or parts.password is not None or "%" in host:
                raise ValueError
            if parts.scheme not in ({"http", "https"} if self.allow_http else {"https"}):
                raise ValueError
            if port is not None and not 1 <= port <= 65535:
                raise ValueError
            # IDNA normalization is performed by HTTPX before the actual lookup.
            normalized = str(httpx.URL(urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))))
            actual = urlsplit(normalized)
            literal = None
            try:
                literal = ipaddress.ip_address(actual.hostname)
            except ValueError:
                pass
            if literal is not None and not self.policy.permits(str(literal)):
                raise FetchError("destination address is not permitted")
            if self._injected_transport:
                self.policy.addresses(actual.hostname, actual.port or (443 if actual.scheme == "https" else 80))
            return normalized
        except (ValueError, httpx.InvalidURL, UnicodeError):
            raise FetchError("invalid destination URL") from None

    @staticmethod
    def _origin(value: str) -> tuple[str, str, int]:
        parts = urlsplit(value)
        return parts.scheme, parts.hostname or "", parts.port or (443 if parts.scheme == "https" else 80)

    def _check_deadline(self, wait: float = 0.0) -> None:
        if self.deadline is not None and self.clock() + wait >= self.deadline:
            self.deadline_reached = True
            raise DeadlineReached()

    def _pause(self, seconds: float) -> None:
        self._check_deadline(seconds)
        self.sleep(seconds)

    def _rate_limit(self) -> None:
        rate = float(self.settings.get("requests_per_minute", 120.0))
        if rate <= 0:
            return
        remaining = self._next_request - self.clock()
        if remaining > 0:
            self._pause(remaining)  # never waits past the caller's deadline
        self._next_request = self.clock() + 60.0 / rate

    def _body(self, response: httpx.Response) -> bytes:
        limit = int(self.settings.get("max_response_bytes", 4 * 1024 * 1024))
        if self._injected_transport and response.is_stream_consumed:
            # MockTransport commonly constructs already-read responses. The
            # production transport always supplies an unread bounded stream.
            if len(response.content) > limit:
                raise FetchError("response exceeds configured byte limit")
            return response.content
        length = response.headers.get("content-length")
        if length:
            try:
                if int(length) < 0:
                    raise ValueError
                if int(length) > limit:
                    raise FetchError("response exceeds configured byte limit")
            except ValueError:
                raise FetchError("invalid response length") from None
        encoding = response.headers.get("content-encoding", "identity").lower().strip()
        decoder = None
        if encoding in {"gzip", "x-gzip"}:
            decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        elif encoding == "deflate":
            decoder = zlib.decompressobj()
        elif encoding not in {"", "identity"}:
            raise FetchError("unsupported content encoding")
        body = bytearray()
        raw_size = 0
        try:
            for chunk in response.iter_raw(chunk_size=65536):
                raw_size += len(chunk)
                if raw_size > limit:
                    raise FetchError("response exceeds configured byte limit")
                decoded = decoder.decompress(chunk, limit - len(body) + 1) if decoder else chunk
                if len(body) + len(decoded) > limit:
                    raise FetchError("response exceeds configured byte limit")
                body.extend(decoded)
            if decoder and (not decoder.eof or decoder.unused_data):
                raise FetchError("invalid compressed response")
        except zlib.error:
            raise FetchError("invalid compressed response") from None
        return bytes(body)

    def request(self, method: str, url: str, headers: dict[str, str] | None = None,
                json_body: Any = None, conditional: dict[str, str] | None = None) -> Response:
        method = method.upper()
        if method not in {"GET", "HEAD", "POST", "DELETE"}:
            raise FetchError("unsupported request method")
        start_url = self._url(url)
        start_headers = {"user-agent": self.settings.get("user_agent", "OnionFlash"),
                         "accept-encoding": "gzip, deflate"}
        start_headers.update({str(k).lower(): str(v) for k, v in (headers or {}).items() if k.lower() != "host"})
        start_headers.update({str(k).lower(): str(v) for k, v in (conditional or {}).items()
                              if k.lower() in {"if-none-match", "if-modified-since"}})
        attempts = max(1, min(10, int(self.settings.get("retry_attempts", 3))))
        for attempt in range(attempts):
            current, active_headers, active_method, payload = start_url, dict(start_headers), method, json_body
            deadline = self.clock() + float(self.settings.get("total_timeout_seconds", 90.0))
            if self.deadline is not None:
                self._check_deadline()
                deadline = min(deadline, self.deadline)
            try:
                for redirects in range(int(self.settings.get("max_redirects", 4)) + 1):
                    self._rate_limit()
                    # Cookies are unnecessary for source collection and must not
                    # make independently configured source requests stateful.
                    self._client.cookies.clear()
                    with self._client.stream(active_method, current, headers=active_headers, json=payload,
                                             extensions={"onionflash_deadline": deadline}) as response:
                        if response.status_code in REDIRECT_STATUSES:
                            if redirects >= int(self.settings.get("max_redirects", 4)):
                                raise FetchError("redirect limit exceeded")
                            location = response.headers.get("location")
                            if not location:
                                raise FetchError("redirect missing destination")
                            destination = self._url(urljoin(current, location))
                            if self._origin(destination) != self._origin(current):
                                if self.same_origin_redirects:
                                    raise FetchError("cross-origin redirect refused")
                                if active_method not in {"GET", "HEAD"}:
                                    raise FetchError("cross-origin request-body redirect refused")
                                active_headers = {k: v for k, v in active_headers.items() if k in _SAFE_CROSS_ORIGIN_HEADERS}
                            if response.status_code == 303 and active_method != "HEAD":
                                active_method, payload = "GET", None
                            current = destination
                            continue
                        if response.status_code in RETRY_STATUSES:
                            if attempt + 1 < attempts:
                                self._pause(retry_delay(attempt, self.settings, response.headers.get("retry-after")))
                                break
                            raise FetchError(f"HTTP {response.status_code}", status=response.status_code, retryable=True)
                        if response.status_code >= 400:
                            raise FetchError(f"HTTP {response.status_code}", status=response.status_code)
                        body = b"" if active_method == "HEAD" or response.status_code in {204, 205, 304} else self._body(response)
                        return Response(response.status_code, body, dict(response.headers), current)
                else:
                    raise FetchError("redirect limit exceeded")
            except FetchError as exc:
                # A deadline stop must not fall back to a shorter wait than Retry-After.
                if isinstance(exc, DeadlineReached) or not exc.retryable or attempt + 1 >= attempts:
                    raise
                self._pause(retry_delay(attempt, self.settings))
            except (httpx.TimeoutException, httpx.NetworkError, httpx.RemoteProtocolError,
                    httpcore.TimeoutException, httpcore.NetworkError, httpcore.RemoteProtocolError, OSError):
                if attempt + 1 >= attempts:
                    raise FetchError("network request failed", retryable=True) from None
                self._pause(retry_delay(attempt, self.settings))
            except (httpx.HTTPError, httpcore.ProtocolError, ValueError):
                raise FetchError("invalid HTTP response") from None
        raise FetchError("request retries exhausted", retryable=True)
