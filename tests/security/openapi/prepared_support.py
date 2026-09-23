"""Private setup helpers for the prepared Schemathesis profile.

Schemathesis runs independently from HTTP integration cases, so it owns this
small amount of provisioning instead of importing ``tests/integration/http``.
"""

import json
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


DEFAULT_BASE_URL = "http://127.0.0.1:3000"
DEFAULT_FINAL_APP_ADDR = "localhost:3999"
CONFIG_PATH = Path("config.json")
CONFIG_SIGN_PATH = Path("config_sign.json")

KEY_CASES = (
    {
        "tag": "1", "profile": "hybrid-performance-v1", "hash_algorithm": "BLAKE2b(256)",
        "symmetric_algorithm": "ChaCha20Poly1305", "eddsa_algorithm": "Ed25519",
        "xecdh_algorithm": "X25519", "ml_dsa_variant": "ML-DSA-44", "ml_kem_variant": "ML-KEM-512",
    },
    {
        "tag": "2", "profile": "hybrid-standard-v1", "hash_algorithm": "SHA-3(256)",
        "symmetric_algorithm": "AES-128/GCM", "eddsa_algorithm": "Ed25519",
        "xecdh_algorithm": "X25519", "ml_dsa_variant": "ML-DSA-44", "ml_kem_variant": "ML-KEM-512",
    },
    {
        "tag": "3", "profile": "hybrid-high-assurance-v1", "hash_algorithm": "SHA-3(384)",
        "symmetric_algorithm": "AES-192/GCM", "eddsa_algorithm": "Ed25519",
        "xecdh_algorithm": "X25519", "ml_dsa_variant": "ML-DSA-65", "ml_kem_variant": "ML-KEM-768",
    },
    {
        "tag": "4", "profile": "hybrid-long-term-v1", "hash_algorithm": "SHA-3(512)",
        "symmetric_algorithm": "AES-256/GCM", "eddsa_algorithm": "Ed448",
        "xecdh_algorithm": "X448", "ml_dsa_variant": "ML-DSA-87", "ml_kem_variant": "ML-KEM-1024",
    },
)


class WorkflowError(Exception):
    """A failed Schemathesis preparation contract."""


class Client:
    def __init__(self, base_url, apikey):
        self.base_url = base_url.rstrip("/")
        self.apikey = apikey

    def get(self, path):
        return self._request("GET", path)

    def post(self, path, body):
        return self._request("POST", path, body)

    def _request(self, method, path, body=None):
        headers = {"X-API-Key": self.apikey}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}{path}", data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as err:
            detail = err.read().decode("utf-8", errors="replace")
            raise WorkflowError(f"{method} {path} failed with {err.code}: {detail}") from err
        except (urllib.error.URLError, json.JSONDecodeError) as err:
            raise WorkflowError(f"{method} {path} failed: {err}") from err


def _backup(path):
    return path.read_bytes() if path.exists() else None


def _restore(path, content):
    if content is None:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    else:
        path.write_bytes(content)


def backup_config_file():
    return _backup(CONFIG_PATH)


def backup_config_sign_file():
    return _backup(CONFIG_SIGN_PATH)


def restore_config_file(content):
    _restore(CONFIG_PATH, content)


def restore_config_sign_file(content):
    _restore(CONFIG_SIGN_PATH, content)


def _load_config():
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as err:
        raise WorkflowError(f"could not load config.json: {err}") from err


def _sign_and_write(config):
    CONFIG_PATH.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
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


def create_key(client, case):
    payload = client.post("/keys", case)
    kid = payload.get("kid")
    if not isinstance(kid, str) or len(kid) != 64:
        raise WorkflowError("keys create did not return a 64-character KID")
    return kid


def host_from_base_url(base_url):
    parsed = urllib.parse.urlparse(base_url)
    if not parsed.hostname or not parsed.port:
        raise WorkflowError("base URL must include host and port")
    return f"{parsed.hostname}:{parsed.port}"


def write_test_routes(key_ids, final_app_addr):
    config = _load_config()
    config["routes"] = [
        {
            "kid": key_id,
            "name": f"final-app-{index}",
            "final_app_addr": final_app_addr,
            "final_app_path": "/message",
        }
        for index, key_id in enumerate(key_ids, start=1)
    ]
    _sign_and_write(config)


def write_test_remote_routes(client, key_ids, recipient_host):
    config = _load_config()
    config["remote_routes"] = [
        {
            "remote_kid": key_id,
            "name": f"positive-{index}",
            "remote_addr": recipient_host,
            "allowed_local_kids": [key_id],
            "status": "active",
            "public_keys": client.get(f"/pub/{key_id}")["keys"],
        }
        for index, key_id in enumerate(key_ids, start=1)
    ]
    _sign_and_write(config)


def reload_config(client):
    response = client.post("/config/reload", {})
    if response.get("status") != "reloaded":
        raise WorkflowError("config reload status must be reloaded")
    return response


def start_final_app(addr):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import threading

    host, port = addr.rsplit(":", 1)

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, _format, *_args):
            return

    server = ThreadingHTTPServer((host, int(port)), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
