import json
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass


@dataclass(frozen=True)
class FuzzResponse:
    status: int
    body: str
    duration_ms: float
    headers: dict[str, str] | None = None

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
        self.timing = timing or TimingCollector()

    def request(self, method, path, data=None, headers=None, auth=False):
        request_headers = dict(headers or {})
        if auth:
            request_headers["X-API-Key"] = self.apikey
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            headers=request_headers,
            method=method,
        )
        started = time.monotonic()
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                result = FuzzResponse(
                    response.status,
                    response.read().decode("utf-8", "replace"),
                    (time.monotonic() - started) * 1000,
                )
        except urllib.error.HTTPError as err:
            result = FuzzResponse(
                err.code,
                err.read().decode("utf-8", "replace"),
                (time.monotonic() - started) * 1000,
            )
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
            result = FuzzResponse(0, "", (time.monotonic() - started) * 1000)
        self.timing.add(result)
        return result

    def request_with_headers(self, method, path, data=None, headers=None, auth=False):
        request_headers = dict(headers or {})
        if auth:
            request_headers["X-API-Key"] = self.apikey
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            headers=request_headers,
            method=method,
        )
        started = time.monotonic()
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                result = FuzzResponse(
                    response.status,
                    response.read().decode("utf-8", "replace"),
                    (time.monotonic() - started) * 1000,
                    dict(response.headers.items()),
                )
        except urllib.error.HTTPError as err:
            result = FuzzResponse(
                err.code,
                err.read().decode("utf-8", "replace"),
                (time.monotonic() - started) * 1000,
                dict(err.headers.items()),
            )
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
            result = FuzzResponse(0, "", (time.monotonic() - started) * 1000, {})
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
