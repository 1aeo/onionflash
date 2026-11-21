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
import re
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

from .util import backoff_seconds, is_valid_domain


RETRY_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504})
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_SAFE_CROSS_ORIGIN_HEADERS = frozenset({"accept", "accept-encoding", "user-agent"})
_RELAY_6TO4 = ipaddress.ip_network("192.88.99.0/24")
_GLOBAL_UNICAST_V6 = ipaddress.ip_network("2000::/3")


class FetchError(Exception):
    """A deliberately sanitized error suitable for persistent status records."""

    def __init__(self, message: str, *, status: int | None = None, retryable: bool = False, retry_after: str | None = None):
        super().__init__(message)
        self.status, self.retryable, self.retry_after = status, retryable, retry_after


class DeadlineReached(FetchError):
    """The caller's deadline arrived, or a retry wait would pass it. Never retried here."""

    def __init__(self, *, request_started: bool = False) -> None:
        super().__init__("request deadline reached", retryable=True)
        # Once dispatch starts, a deadline cannot prove that no request was sent.
        self.request_started = request_started


@dataclass(frozen=True)
class Response:
    """Bounded HTTP response with status code, raw bytes, headers, and final URL."""

    status: int
    body: bytes
    headers: dict[str, str]
    url: str

    def json(self) -> Any:
        """Decode the response body as JSON or raise a sanitized `FetchError`."""
        try:
            return json.loads(self.body)
        except (ValueError, UnicodeDecodeError, RecursionError):
            raise FetchError("invalid JSON response") from None


class AddressPolicy:
    """Connect-time IP policy restricting destinations to global or allowed networks."""

    def __init__(self, allowed_networks: Iterable[str] = (), *, resolver: Callable = socket.getaddrinfo):
        self.networks = tuple(ipaddress.ip_network(value, strict=True) for value in allowed_networks)
        if any(net.prefixlen == 0 for net in self.networks):
            raise ValueError("a private-network allowlist must not include a default route")
        self.resolver = resolver

    def permits(self, address: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        """Return whether `address` is a permitted global or explicitly allowed IP."""
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        if ip.is_multicast or ip.is_unspecified:
            return False
        if isinstance(ip, ipaddress.IPv6Address) and ip.scope_id is not None:
            return False
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            return self.permits(ip.ipv4_mapped)
        if any(ip.version == net.version and ip in net for net in self.networks):
            return True
        if not ip.is_global:
            return False
        if isinstance(ip, ipaddress.IPv4Address):
            return ip not in _RELAY_6TO4
        # Translation/tunneling prefixes can reach an embedded private IPv4
        # address even though the outer IPv6 address is classified as global.
        if ip not in _GLOBAL_UNICAST_V6 or ip.sixtofour or ip.teredo:
            return False
        if ((int(ip) >> 32) & 0xFCFFFFFF) == 0x00005EFE:
            return self.permits(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
        return True

    def addresses(self, host: str, port: int) -> list[str]:
        """Resolve `host` and return up to eight vetted numeric target addresses."""
        try:
            records = self.resolver(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        except (OSError, ValueError):
            raise FetchError("DNS resolution failed", retryable=True) from None
        addresses = list(dict.fromkeys(record[4][0] for record in records))
        if not addresses or any(not self.permits(address) for address in addresses):
            raise FetchError("destination address is not permitted")
        return addresses[:8]


PUBLIC_ADDRESS_POLICY = AddressPolicy()


class _CheckedBackend(httpcore.NetworkBackend):
    """Validate DNS at the connect boundary, then connect to a literal IP."""

    def __init__(self, policy: AddressPolicy, backend: Any = None, clock: Callable[[], float] = time.monotonic):
        self.policy, self.backend, self.clock = policy, backend or httpcore.SyncBackend(), clock
        self.deadline: float | None = None

    def budget(self, timeout: float | None) -> float | None:
        """Clamp timeout to the remaining request deadline."""
        if self.deadline is None:
            return timeout
        remaining = self.deadline - self.clock()
        if remaining <= 0:
            raise httpcore.ReadTimeout("request deadline exceeded")
        return remaining if timeout is None else min(timeout, remaining)

    def connect_tcp(self, host: str, port: int, timeout: float | None = None,
                    local_address: str | None = None, socket_options: Any = None):
        """Resolve and validate host addresses, then connect within deadline."""
        timeout = self.budget(timeout)
        addresses = self.policy.addresses(host, port)
        timeout = self.budget(timeout)
        deadline = self.clock() + timeout if timeout is not None else None
        for address in addresses:
            remaining = max(0.0, deadline - self.clock()) if deadline is not None else None
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
        """Reject Unix domain socket connections."""
        raise FetchError("Unix sockets are not permitted")

    def sleep(self, seconds: float) -> None:
        """Sleep for the requested duration."""
        time.sleep(seconds)


class _DeadlineStream(httpcore.NetworkStream):
    def __init__(self, stream: Any, budget: Callable):
        self.stream, self.budget = stream, budget

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        """Read up to max_bytes within the remaining deadline."""
        return self.stream.read(max_bytes, timeout=self.budget(timeout))

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        """Write buffer within the remaining deadline."""
        self.stream.write(buffer, timeout=self.budget(timeout))

    def close(self) -> None:
        """Close the underlying network stream."""
        self.stream.close()

    def start_tls(self, ssl_context: ssl.SSLContext, server_hostname: str | None = None,
                  timeout: float | None = None):
        """Upgrade the stream to TLS within the remaining deadline."""
        try:
            bounded = self.budget(timeout)
        except BaseException:
            self.stream.close()
            raise
        return _DeadlineStream(self.stream.start_tls(ssl_context=ssl_context, server_hostname=server_hostname,
                                                    timeout=bounded), self.budget)

    def get_extra_info(self, info: str) -> Any:
        """Return extra transport metadata from the underlying stream."""
        return self.stream.get_extra_info(info)


class _ResponseStream(httpx.SyncByteStream):
    def __init__(self, stream: Any):
        self.stream = stream

    def __iter__(self):
        yield from self.stream

    def close(self):
        """Close the underlying response stream."""
        self.stream.close()


class _CheckedTransport(httpx.BaseTransport):
    """Small adapter using public httpcore APIs, without monkey-patching DNS."""

    def __init__(self, policy: AddressPolicy, clock: Callable[[], float] = time.monotonic):
        self.backend = _CheckedBackend(policy, clock=clock)
        self.pool = httpcore.ConnectionPool(ssl_context=ssl.create_default_context(), max_connections=4,
                                            max_keepalive_connections=2, keepalive_expiry=10.0,
                                            network_backend=self.backend, retries=0)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        """Dispatch an httpx request through the checked connection pool."""
        self.backend.deadline = request.extensions.get("onionflash_deadline")
        lookup_host = request.extensions.get("onionflash_lookup_host")
        raw_host = lookup_host.encode("ascii") if isinstance(lookup_host, str) and lookup_host else request.url.raw_host
        extensions = dict(request.extensions)
        if raw_host != request.url.raw_host and "sni_hostname" not in extensions:
            extensions["sni_hostname"] = request.url.raw_host.decode("ascii")
        url = httpcore.URL(scheme=request.url.raw_scheme, host=raw_host,
                           port=request.url.port, target=request.url.raw_path)
        result = self.pool.handle_request(httpcore.Request(request.method, url, headers=request.headers.raw,
                                                           content=request.stream, extensions=extensions))
        return httpx.Response(result.status, headers=result.headers,
                              stream=_ResponseStream(result.stream), extensions=result.extensions)

    def close(self) -> None:
        """Close the underlying connection pool."""
        self.pool.close()


def retry_delay(attempt: int, settings: dict, retry_after: str | None = None,
                *, jitter: Callable[[], float] = random.random, now: datetime | None = None) -> float:
    """attempt=0 is the delay before the first retry; all waits have a cap."""
    cap = float(settings.get("backoff_cap_seconds", 30.0))
    delay = backoff_seconds(attempt + 1, float(settings.get("backoff_base_seconds", 1.0)), cap)
    delay = min(cap, delay * (1 + float(settings.get("backoff_jitter", 0.25)) * jitter()))
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
                 sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic):
        self.settings, self.allow_http = settings, allow_http
        self.policy = AddressPolicy(allowed_networks, resolver=resolver)
        self.sleep, self.clock = sleep, clock
        # Absolute time.monotonic() deadline set by the caller (None: no limit).
        # Every attempt is capped by it and no retry sleeps past it; deadline_reached
        # records that the deadline, not the server, ended the latest request.
        self.deadline: float | None = None
        self.deadline_reached, self._injected_transport = False, transport is not None
        self._request_started = False
        timeout = httpx.Timeout(float(settings.get("timeout_seconds", 30.0)),
                                connect=float(settings.get("connect_timeout_seconds", 10.0)))
        self._client = httpx.Client(transport=transport or _CheckedTransport(self.policy, clock=self.clock),
                                    timeout=timeout, follow_redirects=False, trust_env=False)

    def close(self) -> None:
        """Close the underlying HTTP connection pool."""
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _parse_url(self, value: str) -> tuple[str, str]:
        if (
            not isinstance(value, str)
            or len(value) > 8192
            or "\\" in value
            or any(ord(c) < 33 or ord(c) == 127 or c in "\ufffe\uffff" for c in value)
        ):
            raise FetchError("invalid destination URL")
        try:
            value.encode("utf-8")
            parts = urlsplit(value)
            host, port = parts.hostname, parts.port
            allowed_schemes = {"http", "https"} if self.allow_http else {"https"}
            if (not host or parts.username is not None or parts.password is not None or "%" in host
                    or parts.scheme not in allowed_schemes or (port is not None and not 1 <= port <= 65535)):
                raise ValueError
            # IDNA normalization is performed by HTTPX before the actual lookup.
            parsed_url = httpx.URL(urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, "")))
            host_name = parsed_url.raw_host.decode("ascii").lower()
            if "%" in host_name or host_name.endswith(".."):
                raise ValueError
            clean_host = host_name[:-1] if host_name.endswith(".") else host_name
            if not clean_host:
                raise ValueError
            try:
                ip = ipaddress.ip_address(clean_host)
            except ValueError:
                if all(re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)", part) for part in clean_host.split(".")):
                    raise ValueError
                if not self.policy.networks:
                    if "." not in clean_host or clean_host == "localhost" or clean_host.endswith((".localhost", ".local", ".internal")):
                        raise FetchError("destination address is not permitted")
                    if not is_valid_domain(clean_host):
                        raise ValueError
                elif not (
                    is_valid_domain(clean_host)
                    if "." in clean_host
                    else re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", clean_host)
                ):
                    raise ValueError
                if clean_host != host_name:
                    parsed_url = parsed_url.copy_with(host=clean_host)
            else:
                if clean_host != host_name or not self.policy.permits(ip):
                    raise FetchError("destination address is not permitted")
            return str(parsed_url), host_name
        except (ValueError, httpx.InvalidURL, UnicodeError):
            raise FetchError("invalid destination URL") from None

    def _url(self, value: str) -> str:
        return self._parse_url(value)[0]

    @staticmethod
    def _origin(value: str) -> tuple[str, str, int]:
        parts = urlsplit(value)
        return parts.scheme, parts.hostname or "", parts.port or (443 if parts.scheme == "https" else 80)

    def _check_deadline(self, wait: float = 0.0) -> None:
        if self.deadline is not None and self.clock() + wait >= self.deadline:
            self.deadline_reached = True
            raise DeadlineReached(request_started=self._request_started)

    def _body(self, response: httpx.Response) -> bytes:
        limit = int(self.settings.get("max_response_bytes", 4 * 1024 * 1024))

        def check_size(size: int) -> None:
            """Raise FetchError when size exceeds the configured byte limit."""
            if size > limit:
                raise FetchError("response exceeds configured byte limit")

        if self._injected_transport and response.is_stream_consumed:
            # MockTransport commonly constructs already-read responses. The
            # production transport always supplies an unread bounded stream.
            check_size(len(response.content))
            return response.content
        if length := response.headers.get("content-length"):
            try:
                declared = int(length)
                if declared < 0:
                    raise ValueError
            except ValueError:
                raise FetchError("invalid response length") from None
            check_size(declared)
        encoding = response.headers.get("content-encoding", "identity").lower().strip()
        wbits = {"gzip": 16 + zlib.MAX_WBITS, "x-gzip": 16 + zlib.MAX_WBITS, "deflate": zlib.MAX_WBITS}
        if encoding not in {*wbits, "", "identity"}:
            raise FetchError("unsupported content encoding")
        decoder = zlib.decompressobj(wbits[encoding]) if encoding in wbits else None
        body, raw_size, deflate_fallback = bytearray(), 0, encoding == "deflate"
        try:
            for chunk in response.iter_raw(chunk_size=65536):
                check_size(raw_size := raw_size + len(chunk))
                if not decoder:
                    body.extend(chunk)
                    continue
                pending = chunk
                while pending:
                    try:
                        decoded = decoder.decompress(pending, limit - len(body) + 1)
                        deflate_fallback = False
                    except zlib.error:
                        if not deflate_fallback or body:
                            raise
                        deflate_fallback, decoder = False, zlib.decompressobj(-zlib.MAX_WBITS)
                        decoded = decoder.decompress(pending, limit - len(body) + 1)
                    check_size(len(body) + len(decoded))
                    body.extend(decoded)
                    if decoder.unconsumed_tail:
                        pending = decoder.unconsumed_tail
                    elif decoder.eof and decoder.unused_data and encoding in {"gzip", "x-gzip"}:
                        pending, decoder = decoder.unused_data, zlib.decompressobj(16 + zlib.MAX_WBITS)
                    else:
                        pending = b""
            if decoder:
                flushed = decoder.flush(limit - len(body) + 1)
                check_size(len(body) + len(flushed))
                body.extend(flushed)
                if not decoder.eof or decoder.unused_data:
                    raise FetchError("invalid compressed response")
        except zlib.error:
            raise FetchError("invalid compressed response") from None
        return bytes(body)

    def request(self, method: str, url: str, headers: dict[str, str] | None = None,
                json_body: Any = None) -> Response:
        """Send one bounded GET or POST request with connect-time IP checks and retries."""
        method = method.upper()
        if method not in {"GET", "POST"}:
            raise FetchError("unsupported request method")
        self.deadline_reached = False  # describes this request only, e.g. the last fallback
        self._request_started = False
        if self.deadline is not None:
            self._check_deadline()
        start_url, start_lookup_host = self._parse_url(url)
        start_headers = {"user-agent": self.settings.get("user_agent", "OnionFlash"),
                         "accept-encoding": "gzip, deflate"}
        start_headers.update({str(k).lower(): str(v) for k, v in (headers or {}).items() if k.lower() != "host"})
        attempts = max(1, min(10, int(self.settings.get("retry_attempts", 3))))
        max_redirects = int(self.settings.get("max_redirects", 4))
        for attempt in range(attempts):
            current, lookup_host, active_headers, active_method, payload = (
                start_url, start_lookup_host, dict(start_headers), method, json_body
            )
            deadline = self.clock() + float(self.settings.get("total_timeout_seconds", 90.0))
            if self.deadline is not None:
                self._check_deadline()
                deadline = min(deadline, self.deadline)
            retry_after = None
            try:
                for redirects in range(max_redirects + 1):
                    self._check_deadline()
                    # Cookies are unnecessary for source collection and must not
                    # make independently configured source requests stateful.
                    self._client.cookies.clear()
                    self._request_started = True
                    if self._injected_transport:
                        self.policy.addresses(lookup_host, self._origin(current)[2])
                        self._check_deadline()
                    extensions: dict[str, Any] = {"onionflash_deadline": deadline}
                    if lookup_host != self._origin(current)[1]:
                        extensions["onionflash_lookup_host"] = lookup_host
                    with self._client.stream(active_method, current, headers=active_headers, json=payload,
                                             extensions=extensions) as response:
                        if response.status_code in REDIRECT_STATUSES:
                            if redirects >= max_redirects:
                                raise FetchError("redirect limit exceeded")
                            self._check_deadline()
                            location = response.headers.get("location")
                            if not location:
                                raise FetchError("redirect missing destination")
                            destination, next_lookup_host = self._parse_url(urljoin(current, location))
                            parsed_location = urlsplit(location)
                            if not parsed_location.scheme and not parsed_location.netloc and lookup_host.endswith("."):
                                next_lookup_host = lookup_host
                            if self._origin(destination) != self._origin(current):
                                if active_method != "GET":
                                    raise FetchError("cross-origin request-body redirect refused")
                                active_headers = {k: v for k, v in active_headers.items() if k in _SAFE_CROSS_ORIGIN_HEADERS}
                            if response.status_code == 303:
                                active_method, payload = "GET", None
                            current, lookup_host = destination, next_lookup_host
                            continue
                        if response.status_code in RETRY_STATUSES:
                            raise FetchError(f"HTTP {response.status_code}", status=response.status_code,
                                             retryable=True, retry_after=response.headers.get("retry-after"))
                        if response.status_code >= 400:
                            raise FetchError(f"HTTP {response.status_code}", status=response.status_code)
                        body = b"" if response.status_code in {204, 205, 304} else self._body(response)
                        return Response(response.status_code, body, dict(response.headers), current)
            except DeadlineReached as exc:
                self.deadline_reached = True
                exc.request_started = exc.request_started or self._request_started
                raise
            except FetchError as exc:
                if exc.retryable:
                    self._check_deadline()
                if not exc.retryable or attempt + 1 >= attempts:
                    raise
                retry_after = exc.retry_after
            except (httpx.TimeoutException, httpx.NetworkError, httpx.RemoteProtocolError,
                    httpcore.TimeoutException, httpcore.NetworkError, httpcore.RemoteProtocolError, OSError):
                self._check_deadline()
                if attempt + 1 >= attempts:
                    raise FetchError("network request failed", retryable=True) from None
            except (httpx.HTTPError, httpcore.ProtocolError, ValueError):
                raise FetchError("invalid HTTP response") from None
            delay = retry_delay(attempt, self.settings, retry_after)
            self._check_deadline(delay)
            self.sleep(delay)
        raise FetchError("request retries exhausted", retryable=True)
