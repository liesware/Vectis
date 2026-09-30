import http.client
import io
import json
import threading
import time
import urllib.parse
from dataclasses import dataclass, field


REQUEST_TIMEOUT = 15


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError()
    return remaining


class _DeadlineReader(io.RawIOBase):
    """Keep header parsing and trickled response bodies on the same deadline."""

    def __init__(self, reader, sock, deadline):
        self.reader = reader
        self.sock = sock
        self.deadline = deadline

    def readable(self):
        return True

    def readinto(self, buffer):
        self.sock.settimeout(_remaining(self.deadline))
        data = self.reader.read1(len(buffer))
        buffer[:len(data)] = data
        return len(data)

    def close(self):
        try:
            self.reader.close()
        finally:
            super().close()


class _DeadlineResponse(http.client.HTTPResponse):
    def __init__(self, sock, *, deadline, **kwargs):
        super().__init__(sock, **kwargs)
        self.fp = io.BufferedReader(_DeadlineReader(self.fp, sock, deadline))


@dataclass(frozen=True)
class FuzzResponse:
    status: int
    body: str
    duration_ms: float
    headers: dict[str, str] | None = None
    transport_phase: str | None = None
    error_type: str | None = None
    error_errno: int | None = None
    request_body_bytes: int = 0
    method: str | None = None
    path: str | None = None
    request_body: bytes | None = field(default=None, repr=False)

    def __iter__(self):
        yield self.status
        yield self.body

    def __getitem__(self, index):
        return (self.status, self.body)[index]


class TimingCollector:
    def __init__(self):
        self._lock = threading.Lock()
        self._responses = []

    def add(self, response):
        with self._lock:
            self._responses.append(response)

    def drain(self):
        with self._lock:
            responses = self._responses
            self._responses = []
        return responses

    def clear(self):
        self.drain()


class FuzzClient:
    def __init__(self, base_url, apikey, timing=None):
        self.base_url = base_url.rstrip("/")
        self.apikey = apikey
        self.declared_secrets = (apikey,)
        self.timing = timing or TimingCollector()
        self._url = urllib.parse.urlsplit(self.base_url)
        if self._url.scheme not in ("http", "https") or not self._url.hostname or self._url.username:
            raise ValueError("base URL must be a direct HTTP or HTTPS endpoint")

    def request(self, method, path, data=None, headers=None, auth=False):
        return self._request(method, path, data, headers, auth, include_headers=False)

    def request_with_headers(self, method, path, data=None, headers=None, auth=False):
        return self._request(method, path, data, headers, auth, include_headers=True)

    def _request(self, method, path, data, headers, auth, *, include_headers):
        request_headers = dict(headers or {})
        if auth:
            request_headers["X-API-Key"] = self.apikey
        started = time.monotonic()
        deadline = started + REQUEST_TIMEOUT
        connection_type = (http.client.HTTPSConnection if self._url.scheme == "https"
                           else http.client.HTTPConnection)
        connection = connection_type(self._url.hostname, self._url.port, timeout=REQUEST_TIMEOUT)
        connection.response_class = lambda sock, **kwargs: _DeadlineResponse(sock, deadline=deadline, **kwargs)
        original_connect = connection._create_connection

        def connect(address, timeout, source_address):
            sock = original_connect(address, _remaining(deadline), source_address)
            try:
                # HTTPS must not restart the TCP budget for its TLS handshake.
                sock.settimeout(_remaining(deadline))
            except OSError:
                sock.close()
                raise
            return sock

        connection._create_connection = connect
        original_send = connection.send

        def send(data):
            connection.sock.settimeout(_remaining(deadline))
            original_send(data)

        connection.send = send
        phase = "connect"
        error = None
        status, body = 0, ""
        response_headers = {} if include_headers else None
        try:
            connection.connect()
            connection.sock.settimeout(_remaining(deadline))
            phase = "send"
            try:
                connection.request(method, self._url.path + path, body=data, headers=request_headers)
            except (BrokenPipeError, ConnectionResetError) as upload_error:
                # The server may have rejected the upload while we were sending.
                # Read that response on this connection; never retry the request.
                error = upload_error
            connection.sock.settimeout(_remaining(deadline))
            phase = "receive"
            with connection.getresponse() as response:
                content = response.read()
                _remaining(deadline)
                status, body = response.status, content.decode("utf-8", "replace")
                if include_headers:
                    response_headers = dict(response.headers.items())
        except (OSError, http.client.HTTPException) as failure:
            error = failure
        finally:
            connection.close()
        result = FuzzResponse(
            status, body, (time.monotonic() - started) * 1000, response_headers,
            transport_phase=("send" if status else phase) if error is not None else None,
            error_type=type(error).__name__ if error is not None else None,
            error_errno=getattr(error, "errno", None),
            request_body_bytes=len(data) if data is not None else 0,
            method=method, path=self._url.path + path, request_body=data,
        )
        self.timing.add(result)
        return result

    def consume_timings(self):
        return self.timing.drain()

    def clear_timings(self):
        self.timing.clear()

    def get_status(self, path):
        status, _ = self.request("GET", path)
        return status

    def post_json(self, path, obj, auth=False):
        data = json.dumps(obj).encode("utf-8")
        return self.request(
            "POST", path, data, {"Content-Type": "application/json"}, auth
        )

    def post_json_with_headers(self, path, obj, auth=False):
        data = json.dumps(obj).encode("utf-8")
        return self.request_with_headers(
            "POST", path, data, {"Content-Type": "application/json"}, auth
        )

    def post_raw(self, path, raw, auth=False):
        return self.request(
            "POST", path, raw, {"Content-Type": "application/json"}, auth
        )
