#!/usr/bin/env python3
import http.server
import json
import subprocess
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


DEFAULT_BASE_URL = "http://127.0.0.1:3000"
DEFAULT_FINAL_APP_ADDR = "localhost:3999"
INTERNAL_KEYS_KID_HEX_LEN = 64
MESSAGE = "The things you own end up owning you."
CONFIG_PATH = Path("config.json")
CONFIG_SIGN_PATH = Path("config_sign.json")

_CONFIG = {"version": "v1", "routes": [], "remote_routes": [], "permissions": []}

KEY_CASES = [
    {
        "tag": "1",
        "profile": "hybrid-performance-v1",
        "hash_algorithm": "BLAKE2b(256)",
        "symmetric_algorithm": "ChaCha20Poly1305",
        "eddsa_algorithm": "Ed25519",
        "xecdh_algorithm": "X25519",
        "ml_dsa_variant": "ML-DSA-44",
        "ml_kem_variant": "ML-KEM-512",
    },
    {
        "tag": "2",
        "profile": "hybrid-high-assurance-v1",
        "hash_algorithm": "SHA-3(384)",
        "symmetric_algorithm": "AES-256/GCM",
        "eddsa_algorithm": "Ed25519",
        "xecdh_algorithm": "X25519",
        "ml_dsa_variant": "ML-DSA-65",
        "ml_kem_variant": "ML-KEM-768",
    },
    {
        "tag": "3",
        "profile": "hybrid-long-term-v1",
        "hash_algorithm": "SHA-3(512)",
        "symmetric_algorithm": "AES-256/GCM",
        "eddsa_algorithm": "Ed448",
        "xecdh_algorithm": "X448",
        "ml_dsa_variant": "ML-DSA-87",
        "ml_kem_variant": "ML-KEM-1024",
    },
]


class WorkflowError(Exception):
    pass


class Client:
    def __init__(self, base_url, apikey):
        self.base_url = base_url.rstrip("/")
        self.apikey = apikey

    def get(self, path, auth=False):
        headers = {}
        if auth:
            headers["X-API-Key"] = self.apikey

        return self._request("GET", path, headers=headers)

    def get_status(self, path, auth=False):
        headers = {}
        if auth:
            headers["X-API-Key"] = self.apikey

        request = urllib.request.Request(
            f"{self.base_url}{path}", headers=headers, method="GET"
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.status
        except urllib.error.HTTPError as err:
            return err.code
        except urllib.error.URLError as err:
            raise WorkflowError(f"GET {path} failed: {err}") from err

    def get_text(self, path, auth=False):
        headers = {}
        if auth:
            headers["X-API-Key"] = self.apikey

        request = urllib.request.Request(
            f"{self.base_url}{path}", headers=headers, method="GET"
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.read().decode("utf-8")
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
        url = f"{self.base_url}{path}"
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")

        request = urllib.request.Request(
            url,
            data=data,
            headers=headers or {},
            method=method,
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


def require(condition, message):
    if not condition:
        raise WorkflowError(message)


def require_hex(value, field):
    require(isinstance(value, str), f"{field} must be a string")
    require(len(value) > 0, f"{field} must not be empty")
    try:
        int(value, 16)
    except ValueError as err:
        raise WorkflowError(f"{field} must be hex") from err


def require_kid(value, field):
    require_hex(value, field)
    require(
        len(value) == INTERNAL_KEYS_KID_HEX_LEN,
        f"{field} must be {INTERNAL_KEYS_KID_HEX_LEN} hex characters",
    )


def backup_file(path):
    if not path.exists():
        return None

    return path.read_text(encoding="utf-8")


def restore_file(path, backup):
    if backup is None:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        return

    path.write_text(backup, encoding="utf-8")


def backup_config_file():
    return backup_file(CONFIG_PATH)


def backup_config_sign_file():
    return backup_file(CONFIG_SIGN_PATH)


def restore_config_file(backup):
    restore_file(CONFIG_PATH, backup)


def restore_config_sign_file(backup):
    restore_file(CONFIG_SIGN_PATH, backup)


def sign_config():
    result = subprocess.run(
        ["cargo", "run", "--", "config", "sign", "--output", "json"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise WorkflowError(
            f"vectis config sign failed: stdout={result.stdout} stderr={result.stderr}"
        )


def write_config():
    CONFIG_PATH.write_text(json.dumps(_CONFIG, indent=2), encoding="utf-8")
    sign_config()


def write_test_routes(key_ids, final_app_addr):
    _CONFIG["routes"] = [
        {
            "kid": key_id,
            "final_app_addr": final_app_addr,
            "final_app_path": "/message",
        }
        for key_id in key_ids
    ]
    write_config()


def write_test_remote_routes(client, key_ids, recipient_host, wildcard=False):
    _CONFIG["remote_routes"] = [
        {
            "remote_kid": key_id,
            "name": f"positive-{index}",
            "remote_addr": recipient_host,
            "allowed_local_kids": ["*"] if wildcard else [key_id],
            "status": "active",
            "public_keys": client.get(f"/pub/{key_id}")["keys"],
        }
        for index, key_id in enumerate(key_ids, start=1)
    ]
    write_config()


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


def write_permissions(clients):
    _CONFIG["permissions"] = clients
    write_config()


def reload_config(client):
    response = client.post("/config/reload", {}, auth=True)
    require(response.get("status") == "reloaded", "config reload status must be reloaded")
    require(
        isinstance(response.get("routes_loaded"), int),
        "config reload routes_loaded must be an integer",
    )
    require(
        isinstance(response.get("remote_routes_loaded"), int),
        "config reload remote_routes_loaded must be an integer",
    )
    require(
        isinstance(response.get("clients_loaded"), int),
        "config reload clients_loaded must be an integer",
    )
    return response


def clear_permissions_state(client):
    saved = _CONFIG["permissions"]
    _CONFIG["permissions"] = []
    write_config()
    try:
        reload_config(client)
    finally:
        _CONFIG["permissions"] = saved
        write_config()


def clear_routes_state(client):
    saved = _CONFIG["routes"]
    _CONFIG["routes"] = []
    write_config()
    try:
        reload_config(client)
    finally:
        _CONFIG["routes"] = saved
        write_config()


def clear_remote_routes_state(client):
    saved = _CONFIG["remote_routes"]
    _CONFIG["remote_routes"] = []
    write_config()
    try:
        reload_config(client)
    finally:
        _CONFIG["remote_routes"] = saved
        write_config()


class FinalAppHandler(http.server.BaseHTTPRequestHandler):
    deliveries = []

    def do_POST(self):
        if self.path != "/message":
            self.send_response(404)
            self.end_headers()
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length)
        try:
            payload = json.loads(body.decode("utf-8"))
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

    def log_message(self, format, *args):
        return


def host_from_base_url(base_url):
    parsed = urllib.parse.urlparse(base_url)
    require(parsed.hostname, "base-url must include a host")
    require(parsed.port, "base-url must include a port")

    return f"{parsed.hostname}:{parsed.port}"


def start_final_app(addr):
    host, port = parse_host_port(addr)
    FinalAppHandler.deliveries = []
    server = http.server.ThreadingHTTPServer((host, port), FinalAppHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    return server


def parse_host_port(addr):
    require(":" in addr, "final app addr must be host:port")
    host, port = addr.rsplit(":", 1)
    require(host, "final app host must not be empty")
    try:
        port = int(port)
    except ValueError as err:
        raise WorkflowError("final app port must be an integer") from err

    return host, port


def create_key(client, case):
    response = client.post("/keys", case, auth=True)
    key_id = response.get("id")
    require_kid(key_id, "keys.id")
    return key_id
