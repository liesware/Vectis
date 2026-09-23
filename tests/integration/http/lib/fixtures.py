"""Reusable suite fixtures kept independent from endpoint assertions."""

import http.server
import json
import subprocess
import threading
import urllib.parse
from dataclasses import dataclass, field

from .assertions import require, require_hex, require_kid
from .client import WorkflowError


@dataclass
class Fixtures:
    """Shared state that ordered cases produce and later cases consume by name.

    Populated incrementally: the authz bootstrap fills ``key_id``, the api-key
    hashes and the authz clients; the lifecycle module fills the lifecycle keys,
    a valid token and a valid internal message. Positive suites reuse ``keys``
    and ``recipient_host``.
    """

    key_id: str | None = None
    api_key_hashes: dict = field(default_factory=dict)
    limited: object = None
    metrics: object = None
    admin: object = None
    time: object = None
    disabled_key: str | None = None
    disabled_internal_message: object = None
    retired_key: str | None = None
    retired_token: object = None
    retired_internal_message: object = None
    compromised_key: str | None = None
    compromised_token: object = None
    compromised_internal_message: object = None
    destroyed_key: str | None = None
    destroyed_token: object = None
    destroyed_internal_message: object = None
    token: object = None
    internal_message: object = None
    encoded_token: str | None = None
    keys: object = None
    recipient_host: str | None = None


class FinalAppHandler(http.server.BaseHTTPRequestHandler):
    deliveries = []

    def do_POST(self):
        if self.path != "/message":
            self.send_response(404)
            self.end_headers()
            return
        content_length = int(self.headers.get("Content-Length", "0"))
        try:
            payload = json.loads(self.rfile.read(content_length).decode("utf-8"))
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            return
        self.deliveries.append(payload)
        response = b"{}"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, _format, *_args):
        return


def host_from_base_url(base_url):
    parsed = urllib.parse.urlparse(base_url)
    require(parsed.hostname, "base-url must include a host")
    require(parsed.port, "base-url must include a port")
    return f"{parsed.hostname}:{parsed.port}"


def parse_host_port(addr):
    require(":" in addr, "final app addr must be host:port")
    host, port = addr.rsplit(":", 1)
    require(host, "final app host must not be empty")
    try:
        return host, int(port)
    except ValueError as err:
        raise WorkflowError("final app port must be an integer") from err


def start_final_app(addr):
    host, port = parse_host_port(addr)
    FinalAppHandler.deliveries = []
    server = http.server.ThreadingHTTPServer((host, port), FinalAppHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def create_api_key_pair():
    result = subprocess.run(
        ["cargo", "run", "--", "apikey", "create", "--output", "json"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise WorkflowError(
            f"vectis apikey create failed: stdout={result.stdout} stderr={result.stderr}"
        )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as err:
        raise WorkflowError(f"vectis apikey create returned invalid JSON: {result.stdout}") from err
    api_key = payload.get("VECTIS_APIKEY")
    api_key_hash = payload.get("VECTIS_APIKEY_HASH")
    require_hex(api_key, "VECTIS_APIKEY")
    require_hex(api_key_hash, "VECTIS_APIKEY_HASH")
    return api_key, api_key_hash


def create_key(client, case):
    response = client.post("/keys", case, auth=True)
    key_id = response.get("kid")
    require_kid(key_id, "keys.kid")
    require("id" not in response, "keys create response must not include id")
    return key_id

__all__ = (
    "FinalAppHandler",
    "create_api_key_pair",
    "create_key",
    "host_from_base_url",
    "start_final_app",
)
