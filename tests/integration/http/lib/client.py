"""HTTP transports shared by integration test cases."""

import json
import http.client
import urllib.error
import urllib.parse
import urllib.request


class WorkflowError(Exception):
    """A failed HTTP integration-test contract."""


def parse_json(payload):
    if not payload:
        return {}
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return {"raw": payload}


def raw_http_request(base_url, method, path, body=b"", headers=None):
    """Send a raw request while preserving the server status and JSON body."""
    parsed = urllib.parse.urlsplit(base_url)
    connection_class = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    connection = connection_class(parsed.hostname, parsed.port, timeout=60)
    request_headers = dict(headers or {})
    if body:
        request_headers["Content-Length"] = str(len(body))
    try:
        connection.request(method, path, body=body or None, headers=request_headers)
        response = connection.getresponse()
        return response.status, parse_json(response.read().decode("utf-8", errors="replace"))
    finally:
        connection.close()


def raw_request(base_url, method, path, data=None, content_type=None):
    """Send arbitrary bytes and method without JSON serialization."""
    headers = {"Content-Type": content_type} if content_type is not None else {}
    request = urllib.request.Request(f"{base_url}{path}", data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.status, parse_json(response.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as err:
        return err.code, parse_json(err.read().decode("utf-8", "replace"))


class Client:
    def __init__(self, base_url, apikey):
        self.base_url = base_url.rstrip("/")
        self.apikey = apikey

    def get(self, path, auth=False):
        headers = {"X-API-Key": self.apikey} if auth else {}
        return self._request("GET", path, headers=headers)

    def get_status(self, path, auth=False):
        headers = {"X-API-Key": self.apikey} if auth else {}
        request = urllib.request.Request(f"{self.base_url}{path}", headers=headers, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.status
        except urllib.error.HTTPError as err:
            return err.code
        except urllib.error.URLError as err:
            raise WorkflowError(f"GET {path} failed: {err}") from err

    def get_text(self, path, auth=False):
        headers = {"X-API-Key": self.apikey} if auth else {}
        request = urllib.request.Request(f"{self.base_url}{path}", headers=headers, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.read().decode("utf-8")
        except urllib.error.HTTPError as err:
            payload = err.read().decode("utf-8", errors="replace")
            raise WorkflowError(f"GET {path} failed with {err.code}: {payload}") from err
        except urllib.error.URLError as err:
            raise WorkflowError(f"GET {path} failed: {err}") from err

    def get_with_headers(self, path, auth=False):
        headers = {"X-API-Key": self.apikey} if auth else {}
        request = urllib.request.Request(f"{self.base_url}{path}", headers=headers, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.status, parse_json(response.read().decode("utf-8")), response.headers
        except urllib.error.HTTPError as err:
            payload = err.read().decode("utf-8", errors="replace")
            raise WorkflowError(f"GET {path} failed with {err.code}: {payload}") from err
        except urllib.error.URLError as err:
            raise WorkflowError(f"GET {path} failed: {err}") from err

    def post(self, path, body, auth=False):
        headers = {"Content-Type": "application/json"}
        if auth:
            headers["X-API-Key"] = self.apikey
        return self._request("POST", path, body=body, headers=headers)

    def _request(self, method, path, body=None, headers=None):
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(
            f"{self.base_url}{path}", data=data, headers=headers or {}, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                payload = response.read().decode("utf-8")
        except urllib.error.HTTPError as err:
            payload = err.read().decode("utf-8", errors="replace")
            raise WorkflowError(f"{method} {path} failed with {err.code}: {payload}") from err
        except urllib.error.URLError as err:
            raise WorkflowError(f"{method} {path} failed: {err}") from err

        if not payload:
            return {}
        try:
            return json.loads(payload)
        except json.JSONDecodeError as err:
            raise WorkflowError(f"{method} {path} returned invalid JSON: {payload}") from err


class StatusClient:
    """HTTP client that preserves 4xx and 5xx responses for contract assertions."""

    def __init__(self, base_url, apikey):
        self.base_url = base_url.rstrip("/")
        self.apikey = apikey

    def get(self, path, auth=False, headers=None):
        return self._request("GET", path, auth=auth, headers=headers)

    def get_with_headers(self, path, auth=False, headers=None):
        return self._request_with_headers("GET", path, auth=auth, headers=headers)

    def post(self, path, body, auth=False, headers=None):
        return self._request("POST", path, body=body, auth=auth, headers=headers)

    def post_with_headers(self, path, body, auth=False, headers=None):
        return self._request_with_headers("POST", path, body=body, auth=auth, headers=headers)

    def _request(self, method, path, body=None, auth=False, headers=None):
        status, payload, _ = self._request_with_headers(method, path, body, auth, headers)
        return status, payload

    def _request_with_headers(self, method, path, body=None, auth=False, headers=None):
        request_headers = dict(headers or {})
        if body is not None:
            request_headers.setdefault("Content-Type", "application/json")
        if auth:
            request_headers["X-API-Key"] = self.apikey
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(
            f"{self.base_url}{path}", data=data, headers=request_headers, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.status, parse_json(response.read().decode("utf-8")), response.headers
        except urllib.error.HTTPError as err:
            return err.code, parse_json(err.read().decode("utf-8", errors="replace")), err.headers
        except urllib.error.URLError as err:
            raise WorkflowError(f"{method} {path} failed: {err}") from err
