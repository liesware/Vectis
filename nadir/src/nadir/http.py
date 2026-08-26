"""Bounded HTTP transport with stable failure classification."""

from __future__ import annotations

from dataclasses import dataclass
import errno
import ipaddress
import socket
import time
from typing import Iterable
from urllib.parse import urlsplit

import httpx


MAX_CAPTURED_BODY_BYTES = 64 * 1024


@dataclass(frozen=True)
class HttpRequest:
    method: str
    url: str
    headers: tuple[tuple[str, str], ...] = ()
    body: bytes | None = None


@dataclass(frozen=True)
class TransportFailure:
    kind: str
    public_message: str


# Failures caused by Nadir's own request before it ever reached the server: the
# mutation produced something the HTTP client refused to transmit (an illegal
# header value, a non-message). These carry no information about the server, so
# an oracle must not treat a mutation that triggers one as a finding.
CLIENT_SIDE_FAILURE_KINDS = frozenset({"local_protocol"})


def is_client_side_failure(failure: "TransportFailure | None") -> bool:
    return failure is not None and failure.kind in CLIENT_SIDE_FAILURE_KINDS


@dataclass(frozen=True)
class HttpResult:
    request: HttpRequest
    status: int | None
    headers: tuple[tuple[str, str], ...]
    body: bytes
    elapsed_ms: int
    failure: TransportFailure | None = None


def is_loopback_host(host: str | None) -> bool:
    if host is None:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _classify_error(error: httpx.HTTPError) -> TransportFailure:
    if isinstance(error, httpx.LocalProtocolError):
        # The client refused to send our request: the mutated input is not a valid
        # HTTP message (e.g. an illegal header value). It never reached the server.
        return TransportFailure("local_protocol", "HTTP request was rejected locally before sending")
    if isinstance(error, httpx.ConnectTimeout | httpx.ReadTimeout | httpx.WriteTimeout | httpx.PoolTimeout):
        return TransportFailure("timeout", "HTTP request timed out")
    if isinstance(error, httpx.ConnectError):
        cause = error.__cause__
        if isinstance(cause, socket.gaierror):
            return TransportFailure("dns", "HTTP host name could not be resolved")
        if isinstance(cause, OSError) and cause.errno == errno.ECONNREFUSED:
            return TransportFailure("refused", "HTTP connection was refused")
        return TransportFailure("connect", "HTTP connection could not be established")
    if isinstance(error, httpx.RemoteProtocolError):
        return TransportFailure("protocol", "HTTP peer returned an invalid protocol response")
    if isinstance(error, httpx.ReadError | httpx.WriteError):
        return TransportFailure("reset", "HTTP connection was interrupted")
    if isinstance(error, httpx.TransportError):
        return TransportFailure("transport", "HTTP transport failed")
    return TransportFailure("unknown", "HTTP request failed")


class HttpTransport:
    def __init__(
        self,
        *,
        timeout_seconds: float = 5.0,
        max_body_bytes: int = MAX_CAPTURED_BODY_BYTES,
        allow_non_loopback: bool = False,
    ):
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if max_body_bytes <= 0:
            raise ValueError("max_body_bytes must be positive")
        self._timeout = httpx.Timeout(timeout_seconds)
        self._max_body_bytes = max_body_bytes
        self._allow_non_loopback = allow_non_loopback

    def send(self, request: HttpRequest) -> HttpResult:
        started = time.monotonic()
        if not self._allow_non_loopback and not is_loopback_host(urlsplit(request.url).hostname):
            return HttpResult(
                request,
                None,
                (),
                b"",
                0,
                TransportFailure("blocked_host", "HTTP target host is not an allowed loopback address"),
            )
        if request.body is not None and len(request.body) > self._max_body_bytes:
            return HttpResult(
                request,
                None,
                (),
                b"",
                0,
                TransportFailure("request_too_large", "HTTP request exceeded capture limit"),
            )
        try:
            with httpx.Client(timeout=self._timeout, follow_redirects=False) as client:
                with client.stream(
                    request.method,
                    request.url,
                    headers=list(request.headers),
                    content=request.body,
                ) as response:
                    chunks: list[bytes] = []
                    size = 0
                    for chunk in response.iter_bytes():
                        size += len(chunk)
                        if size > self._max_body_bytes:
                            elapsed_ms = int((time.monotonic() - started) * 1000)
                            return HttpResult(
                                request,
                                response.status_code,
                                tuple(response.headers.multi_items()),
                                b"",
                                elapsed_ms,
                                TransportFailure("response_too_large", "HTTP response exceeded capture limit"),
                            )
                        chunks.append(chunk)
                    elapsed_ms = int((time.monotonic() - started) * 1000)
                    return HttpResult(
                        request,
                        response.status_code,
                        tuple(response.headers.multi_items()),
                        b"".join(chunks),
                        elapsed_ms,
                    )
        except httpx.HTTPError as error:
            elapsed_ms = int((time.monotonic() - started) * 1000)
            return HttpResult(request, None, (), b"", elapsed_ms, _classify_error(error))


def header_values(headers: Iterable[tuple[str, str]], name: str) -> tuple[str, ...]:
    return tuple(value for key, value in headers if key.lower() == name.lower())
