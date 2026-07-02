#!/usr/bin/env python3
import argparse
import atexit
import hashlib
import http.server
import json
import subprocess
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from test_config import require_apikey


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

HASH_CASES = {
    "SHA-256": lambda data: hashlib.sha256(data).hexdigest(),
    "SHA-384": lambda data: hashlib.sha384(data).hexdigest(),
    "SHA-512": lambda data: hashlib.sha512(data).hexdigest(),
}


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


def print_section(title, rows):
    print(f"{title}:")
    for name, status in rows:
        print(f"- {name}: {status}")
    print()


def print_create_key(rows):
    print("Create key:")
    for algorithm, key_id in rows:
        print(f"- {algorithm}: OK")
        print(f"  id: {key_id}")
    print()


def print_message(rows):
    print("message:")
    for key_id, timestamp, variant, ctx_len, plaintext in rows:
        print(f"- kid: {key_id}")
        print(f"  sent: OK")
        print(f"  final app: received OK")
        print(f"  timestamp: {timestamp}")
        print(f"  variant: {variant}")
        print(f"  ctx_hex_len: {ctx_len}")
        print(f"  plain_text: {plaintext}")
    print()


def print_internal_message(rows):
    print("internal message:")
    for key_id, timestamp, variant, ctx_len, plaintext in rows:
        print(f"- kid: {key_id}")
        print(f"  encrypt: OK")
        print(f"  decrypt: OK")
        print(f"  timestamp: {timestamp}")
        print(f"  variant: {variant}")
        print(f"  ctx_hex_len: {ctx_len}")
        print(f"  plain_text: {plaintext}")
    print()


def validate_init(response):
    require(response.get("timestamp"), "test init response must include timestamp")
    for field in ("hash", "symmetric", "eddsa", "xecdh", "ml-dsa", "ml-kem"):
        require(field in response, f"test init response must include {field}")


def validate_health(client):
    startup = client.get("/healthz/startup")
    require(startup.get("status") == "started", "health startup status must be started")
    require(startup.get("timestamp"), "health startup must include timestamp")

    live = client.get("/healthz/live")
    require(live.get("status") == "ok", "health live status must be ok")

    ready = client.get("/healthz/ready")
    require(ready.get("status") == "ready", "health ready status must be ready")
    require(ready.get("unsealed") is True, "health ready unsealed must be true")
    require(ready.get("storage") == "ok", "health ready storage must be ok")
    require(isinstance(ready.get("keys_loaded"), int), "health ready keys_loaded must be an integer")
    require(isinstance(ready.get("routes_loaded"), int), "health ready routes_loaded must be an integer")


def validate_metrics(client):
    status = client.get_status("/metrics", auth=True)
    require(status == 200, f"/metrics must return 200, got {status}")


def create_key(client, case):
    response = client.post("/keys", case, auth=True)
    key_id = response.get("id")
    require_kid(key_id, "keys.id")
    return key_id


def validate_test_response(response, case):
    require(response.get("timestamp"), "test response must include timestamp")
    require(response.get("aad"), "test response must include aad")

    expected_variants = {
        "eddsa": case["eddsa_algorithm"],
        "xecdh": case["xecdh_algorithm"],
        "ml-dsa": case["ml_dsa_variant"],
        "ml-kem": case["ml_kem_variant"],
    }
    for field, variant in expected_variants.items():
        block = response.get(field)
        require(isinstance(block, dict), f"test.{field} must be an object")
        require(block.get("variant") == variant, f"test.{field}.variant mismatch")
        require(block.get("valid") is True, f"test.{field}.valid must be true")


def validate_message_response(response, case):
    message = response.get("message")
    require(isinstance(message, dict), "message.message must be an object")
    require(message.get("valid") is True, "message.message.valid must be true")

    expected_variants = {
        "symmetric": case["symmetric_algorithm"],
        "eddsa": case["eddsa_algorithm"],
        "xecdh": case["xecdh_algorithm"],
        "ml-dsa": case["ml_dsa_variant"],
        "ml-kem": case["ml_kem_variant"],
    }
    for field, variant in expected_variants.items():
        block = response.get(field)
        require(isinstance(block, dict), f"message.{field} must be an object")
        require(block.get("variant") == variant, f"message.{field}.variant mismatch")
        require(block.get("valid") is True, f"message.{field}.valid must be true")


def validate_pub_response(response, case):
    require(response.get("info"), "pub response must include info")
    keys = response.get("keys")
    require(isinstance(keys, dict), "pub.keys must be an object")

    expected = {
        "eddsa": ("alg", case["eddsa_algorithm"], "public_key_der_hex"),
        "xecdh": ("alg", case["xecdh_algorithm"], "public_key_hex"),
        "ml-dsa": ("alg", case["ml_dsa_variant"], "public_key_der_hex"),
        "ml-kem": ("alg", case["ml_kem_variant"], "public_key_der_hex"),
    }
    for field, (alg_field, alg, key_field) in expected.items():
        block = keys.get(field)
        require(isinstance(block, dict), f"pub.keys.{field} must be an object")
        require(block.get(alg_field) == alg, f"pub.keys.{field}.{alg_field} mismatch")
        require_hex(block.get(key_field), f"pub.keys.{field}.{key_field}")


def validate_keys_list(response, key_ids):
    require(isinstance(response, dict), "keys list response must be an object")
    keys = response.get("keys")
    require(isinstance(keys, list), "keys list response.keys must be an array")
    by_kid = {}
    for item in keys:
        require(isinstance(item, dict), "keys list item must be an object")
        kid = item.get("kid")
        info = item.get("info")
        require_kid(kid, "keys list item kid")
        require(isinstance(info, str) and info, "keys list item info must be a non-empty string")
        by_kid[kid] = info

    for key_id in key_ids:
        require(key_id in by_kid, f"keys list must include {key_id}")


def validate_keys_properties_list(response, key_ids):
    require(isinstance(response, dict), "keys properties response must be an object")
    keys = response.get("keys")
    require(isinstance(keys, list), "keys properties response.keys must be an array")
    by_kid = {}
    for item in keys:
        require(isinstance(item, dict), "keys properties item must be an object")
        kid = item.get("kid")
        require_kid(kid, "keys properties item kid")
        require(isinstance(item.get("info"), str) and item["info"], "keys properties item info")
        require(
            isinstance(item.get("properties_info"), str) and item["properties_info"],
            "keys properties item properties_info",
        )
        properties = item.get("properties")
        require(isinstance(properties, dict), "keys properties item properties must be an object")
        require(properties.get("version") == 1, "keys properties version must be 1")
        require(
            properties.get("profile")
            in {
                "hybrid-performance-v1",
                "hybrid-high-assurance-v1",
                "hybrid-long-term-v1",
                "custom",
            },
            "keys properties profile must be supported",
        )
        require(isinstance(properties.get("tag"), str) and properties["tag"], "keys properties tag")
        require(
            isinstance(properties.get("created_at"), str) and properties["created_at"],
            "keys properties created_at",
        )
        lifecycle = properties.get("lifecycle")
        require(isinstance(lifecycle, dict), "keys properties lifecycle must be an object")
        require(
            lifecycle.get("status")
            in {"active", "disabled", "retired", "compromised", "destroyed"},
            "keys properties lifecycle.status",
        )
        require(
            isinstance(lifecycle.get("reason"), str) and lifecycle["reason"],
            "keys properties lifecycle.reason",
        )
        require(
            isinstance(lifecycle.get("changed_at"), str) and lifecycle["changed_at"],
            "keys properties lifecycle.changed_at",
        )
        require("access" in properties, "keys properties access must exist")
        by_kid[kid] = properties

    for key_id in key_ids:
        require(key_id in by_kid, f"keys properties must include {key_id}")


def validate_key_properties_item(response, key_id, expected_status=None):
    require(isinstance(response, dict), "key properties response must be an object")
    require(response.get("kid") == key_id, "key properties kid mismatch")
    require(isinstance(response.get("info"), str) and response["info"], "key properties info")
    require(
        isinstance(response.get("properties_info"), str) and response["properties_info"],
        "key properties properties_info",
    )
    properties = response.get("properties")
    require(isinstance(properties, dict), "key properties properties must be an object")
    lifecycle = properties.get("lifecycle")
    require(isinstance(lifecycle, dict), "key properties lifecycle must be an object")
    if expected_status is not None:
        require(
            lifecycle.get("status") == expected_status,
            f"key properties lifecycle.status must be {expected_status}",
        )
    return properties


def validate_lifecycle_response(response, key_id, expected_status):
    require(isinstance(response, dict), "lifecycle response must be an object")
    require(response.get("kid") == key_id, "lifecycle response kid mismatch")
    lifecycle = response.get("lifecycle")
    require(isinstance(lifecycle, dict), "lifecycle response lifecycle must be an object")
    require(
        lifecycle.get("status") == expected_status,
        f"lifecycle status must be {expected_status}",
    )
    require(
        isinstance(lifecycle.get("reason"), str) and lifecycle["reason"],
        "lifecycle reason must be a non-empty string",
    )
    require(
        isinstance(lifecycle.get("changed_at"), str) and lifecycle["changed_at"],
        "lifecycle changed_at must be a non-empty string",
    )


def validate_routes_list(response):
    require(isinstance(response, dict), "routes list response must be an object")
    routes = response.get("routes")
    require(isinstance(routes, list), "routes list response.routes must be an array")
    for item in routes:
        require(isinstance(item, dict), "routes list item must be an object")
        require_kid(item.get("kid"), "routes list item kid")
        require(
            isinstance(item.get("final_app_addr"), str) and item["final_app_addr"],
            "routes list item final_app_addr must be a non-empty string",
        )
        require(
            isinstance(item.get("final_app_path"), str) and item["final_app_path"].startswith("/"),
            "routes list item final_app_path must start with /",
        )


def validate_remote_routes_list(response):
    require(isinstance(response, dict), "remote routes list response must be an object")
    routes = response.get("routes")
    require(isinstance(routes, list), "remote routes list response.routes must be an array")
    for item in routes:
        require(isinstance(item, dict), "remote routes list item must be an object")
        require_kid(item.get("remote_kid"), "remote routes list item remote_kid")
        require(
            isinstance(item.get("name"), str) and item["name"],
            "remote routes list item name must be a non-empty string",
        )
        require(
            isinstance(item.get("remote_addr"), str) and item["remote_addr"],
            "remote routes list item remote_addr must be a non-empty string",
        )
        allowed_local_kids = item.get("allowed_local_kids")
        require(
            isinstance(allowed_local_kids, list) and allowed_local_kids,
            "remote routes list item allowed_local_kids must be a non-empty array",
        )
        for allowed_kid in allowed_local_kids:
            if allowed_kid != "*":
                require_kid(allowed_kid, "remote routes list item allowed_local_kids kid")
        require(
            item.get("status") in ("active", "disabled"),
            "remote routes list item status must be active or disabled",
        )
        if "public_keys" in item:
            validate_remote_route_public_keys(item["public_keys"])


def validate_remote_route_public_keys(block, case=None):
    require(isinstance(block, dict), "remote route public_keys must be an object")
    fields = {
        "eddsa": ("public_key_der_hex", "eddsa_algorithm"),
        "xecdh": ("public_key_hex", "xecdh_algorithm"),
        "ml-dsa": ("public_key_der_hex", "ml_dsa_variant"),
        "ml-kem": ("public_key_der_hex", "ml_kem_variant"),
    }
    for field, (key_field, case_key) in fields.items():
        sub = block.get(field)
        require(isinstance(sub, dict), f"remote route public_keys.{field} must be an object")
        require(
            isinstance(sub.get("alg"), str) and sub["alg"],
            f"remote route public_keys.{field}.alg must be a non-empty string",
        )
        if case is not None:
            require(
                sub.get("alg") == case[case_key],
                f"remote route public_keys.{field}.alg mismatch",
            )
        require_hex(sub.get(key_field), f"remote route public_keys.{field}.{key_field}")


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


def write_test_remote_routes(key_ids, recipient_host, wildcard=False):
    _CONFIG["remote_routes"] = [
        {
            "remote_kid": key_id,
            "name": f"positive-{index}",
            "remote_addr": recipient_host,
            "allowed_local_kids": ["*"] if wildcard else [key_id],
            "status": "active",
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


def reload_permissions(client):
    response = client.post("/permissions/reload", {}, auth=True)
    require(response.get("status") == "reloaded", "permissions reload status must be reloaded")
    require(
        isinstance(response.get("clients_loaded"), int),
        "permissions reload clients_loaded must be an integer",
    )
    return response


def clear_permissions_state(client):
    saved = _CONFIG["permissions"]
    _CONFIG["permissions"] = []
    write_config()
    try:
        reload_permissions(client)
    finally:
        _CONFIG["permissions"] = saved
        write_config()


def clear_routes_state(client):
    saved = _CONFIG["routes"]
    _CONFIG["routes"] = []
    write_config()
    try:
        validate_routes_list(client.post("/routes/reload", {}, auth=True))
    finally:
        _CONFIG["routes"] = saved
        write_config()


def clear_remote_routes_state(client):
    saved = _CONFIG["remote_routes"]
    _CONFIG["remote_routes"] = []
    write_config()
    try:
        validate_remote_routes_list(client.post("/remote-routes/reload", {}, auth=True))
    finally:
        _CONFIG["remote_routes"] = saved
        write_config()


def sign_key(client, key_id, hash_alg, message_hash_hex):
    body = {
        "message_hash": {
            "alg": hash_alg,
            "hex": message_hash_hex,
        }
    }
    token = client.post(f"/sign/{key_id}", body, auth=True)
    require(token.get("version") == "v1", "sign.version must be v1")

    payload = token.get("payload")
    require(isinstance(payload, dict), "sign.payload must be an object")
    require(payload.get("kid") == key_id, "sign.payload.kid mismatch")
    require(payload.get("message_hash") == body["message_hash"], "sign.payload.message_hash mismatch")

    signatures = token.get("signatures")
    require(isinstance(signatures, dict), "sign.signatures must be an object")
    require_hex(signatures.get("eddsa", {}).get("sig"), "sign.signatures.eddsa.sig")
    ml_dsa_signature = signatures.get("ml-dsa") or signatures.get("ml_dsa") or {}
    require_hex(ml_dsa_signature.get("sig"), "sign.signatures.ml-dsa.sig")

    return token


def verify_signature(client, token):
    response = client.post("/sign/verification", token)
    require(response.get("valid") == "ok", "verification.valid must be ok")
    status = response.get("status")
    require(isinstance(status, dict), "verification.status must be an object")
    require(status.get("eddsa") == "ok", "verification.status.eddsa must be ok")
    require(status.get("ml-dsa") == "ok", "verification.status.ml-dsa must be ok")


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


def validate_final_app_delivery(delivery, sender_key_id, case):
    require(isinstance(delivery, dict), "final app delivery must be an object")
    require(delivery.get("sender_host"), "final app sender_host must be present")
    require(delivery.get("sender_kid") == sender_key_id, "final app sender_kid mismatch")
    require(isinstance(delivery.get("timestamp"), str) and delivery.get("timestamp"), "final app timestamp must be a non-empty string")

    message = delivery.get("message")
    require(isinstance(message, dict), "final app message must be an object")
    require_hex(message.get("ctx"), "final app message.ctx")
    require_hex(message.get("nonce"), "final app message.nonce")
    require(isinstance(message.get("aad"), str) and message.get("aad"), "final app message.aad must be a non-empty string")
    require(message.get("variant") == case["symmetric_algorithm"], "final app message.variant mismatch")


def decrypt_message(client, delivery, expected_plaintext):
    response = client.post("/message/decrypt", delivery, auth=True)
    require(response.get("plaintext") == expected_plaintext, "message decrypt plaintext mismatch")
    return response["plaintext"]


def validate_internal_message_output(response, key_id, case):
    require(response.get("timestamp"), "internal message response must include timestamp")
    require(response.get("kid") == key_id, "internal message kid mismatch")
    message = response.get("message")
    require(isinstance(message, dict), "internal message.message must be an object")
    require_hex(message.get("ctx"), "internal message.ctx")
    require_hex(message.get("nonce"), "internal message.nonce")
    require(isinstance(message.get("aad"), str) and message.get("aad"), "internal message.aad must be a non-empty string")
    require(message.get("variant") == case["symmetric_algorithm"], "internal message.variant mismatch")


def encrypt_internal_message(client, message_number, key_id, case):
    plaintext_message = f"{MESSAGE} internal {message_number}"
    encrypted = client.post(
        f"/message/internal/encrypt/{key_id}",
        {"plaintext": plaintext_message},
        auth=True,
    )
    validate_internal_message_output(encrypted, key_id, case)

    decrypted = client.post("/message/internal/decrypt", encrypted, auth=True)
    require(
        decrypted.get("plaintext") == plaintext_message,
        "internal message decrypt plaintext mismatch",
    )

    return {
        "timestamp": encrypted["timestamp"],
        "variant": encrypted["message"]["variant"],
        "ctx_hex_len": len(encrypted["message"]["ctx"]),
        "plaintext": decrypted["plaintext"],
    }


def validate_permissions_flow(base_url, root_client, key_id, case):
    limited_key, limited_hash = create_api_key_pair()
    admin_key, admin_hash = create_api_key_pair()
    metrics_key, metrics_hash = create_api_key_pair()
    write_permissions(
        [
            {
                "client": "positive-limited-message",
                "apikey_hash": limited_hash,
                "status": "active",
                "permissions": [
                    {
                        "kid": key_id,
                        "actions": ["message"],
                    }
                ],
            },
            {
                "client": "positive-metrics",
                "apikey_hash": metrics_hash,
                "status": "active",
                "permissions": [
                    {
                        "kid": "*",
                        "actions": ["metrics"],
                    }
                ],
            },
            {
                "client": "positive-admin",
                "apikey_hash": admin_hash,
                "status": "active",
                "permissions": [
                    {
                        "kid": "*",
                        "actions": ["admin"],
                    }
                ],
            },
        ]
    )
    reload_permissions(root_client)

    limited_client = Client(base_url, limited_key)
    admin_client = Client(base_url, admin_key)
    metrics_client = Client(base_url, metrics_key)

    limited_result = encrypt_internal_message(limited_client, 1, key_id, case)
    validate_metrics(metrics_client)
    validate_init(admin_client.get("/self-test/init", auth=True))
    validate_routes_list(admin_client.get("/routes", auth=True))
    reload_permissions(admin_client)

    return [
        ("limited message key", "OK"),
        ("metrics key", "OK"),
        ("admin key", "OK"),
        (f"limited ctx_hex_len {limited_result['ctx_hex_len']}", "OK"),
    ]


def send_message(
    client,
    message_number,
    sender_key_id,
    recipient_key_id,
    sender_case,
    recipient_case=None,
):
    if recipient_case is None:
        recipient_case = sender_case
    before = len(FinalAppHandler.deliveries)
    plaintext_message = MESSAGE + str(message_number)
    response = client.post(
        f"/message/{sender_key_id}",
        {
            "recipient_kid": recipient_key_id,
            "message": plaintext_message,
        },
        auth=True,
    )
    validate_message_response(response, sender_case)
    require(
        len(FinalAppHandler.deliveries) == before + 1,
        "final app must receive exactly one delivery",
    )
    delivery = FinalAppHandler.deliveries[-1]
    validate_final_app_delivery(delivery, sender_key_id, recipient_case)
    plaintext = decrypt_message(client, delivery, plaintext_message)

    return {
        "timestamp": delivery["timestamp"],
        "variant": delivery["message"]["variant"],
        "ctx_hex_len": len(delivery["message"]["ctx"]),
        "plaintext": plaintext,
    }


def main():
    parser = argparse.ArgumentParser(description="Run the standard HTTP workflow.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--apikey")
    parser.add_argument("--final-app-addr", default=DEFAULT_FINAL_APP_ADDR)
    args = parser.parse_args()

    final_app = start_final_app(args.final_app_addr)
    apikey = require_apikey(args.apikey)
    client = Client(args.base_url, apikey)
    config_backup = backup_config_file()
    config_sign_backup = backup_config_sign_file()
    atexit.register(restore_config_file, config_backup)
    atexit.register(restore_config_sign_file, config_sign_backup)
    recipient_host = host_from_base_url(args.base_url)
    message = MESSAGE.encode("utf-8")

    validate_health(client)
    print("Health: OK\n")
    passed_count = 1

    validate_metrics(client)
    print("Metrics: OK\n")
    passed_count += 1

    validate_init(client.get("/self-test/init", auth=True))
    print("Test init: OK\n")
    passed_count += 1

    created = []
    create_rows = []
    for case in KEY_CASES:
        key_id = create_key(client, case)
        created.append((key_id, case))
        create_rows.extend(
            [
                (case["xecdh_algorithm"], key_id),
                (case["eddsa_algorithm"], key_id),
                (case["ml_dsa_variant"], key_id),
                (case["ml_kem_variant"], key_id),
            ]
        )
    print_create_key(create_rows)

    validate_keys_list(client.get("/keys"), [key_id for key_id, _ in created])
    print("List keys: OK\n")
    passed_count += 1
    validate_keys_properties_list(
        client.get("/keys/properties", auth=True),
        [key_id for key_id, _ in created],
    )
    print("List keys properties: OK\n")
    passed_count += 1
    first_key_id = created[0][0]
    validate_key_properties_item(
        client.get(f"/keys/properties/{first_key_id}", auth=True),
        first_key_id,
        expected_status="active",
    )
    print("Get key properties: OK\n")
    passed_count += 1
    validate_lifecycle_response(
        client.post(
            f"/lifecycle/{first_key_id}",
            {"status": "disabled", "reason": "positive test maintenance window"},
            auth=True,
        ),
        first_key_id,
        "disabled",
    )
    validate_key_properties_item(
        client.get(f"/keys/properties/{first_key_id}", auth=True),
        first_key_id,
        expected_status="disabled",
    )
    validate_lifecycle_response(
        client.post(
            f"/lifecycle/{first_key_id}",
            {"status": "active", "reason": "positive test restored"},
            auth=True,
        ),
        first_key_id,
        "active",
    )
    print("Update lifecycle: OK\n")
    passed_count += 1
    validate_keys_properties_list(
        client.post("/keys/reload", {}, auth=True),
        [key_id for key_id, _ in created],
    )
    print("Reload keys: OK\n")
    passed_count += 1
    write_test_routes([key_id for key_id, _ in created], args.final_app_addr)
    validate_routes_list(client.post("/routes/reload", {}, auth=True))
    print("Reload routes: OK\n")
    passed_count += 1
    validate_routes_list(client.get("/routes", auth=True))
    print("List routes: OK\n")
    passed_count += 1
    write_test_remote_routes([key_id for key_id, _ in created], recipient_host)
    validate_remote_routes_list(client.post("/remote-routes/reload", {}, auth=True))
    print("Reload remote routes: OK\n")
    passed_count += 1
    validate_remote_routes_list(client.get("/remote-routes", auth=True))
    print("List remote routes: OK\n")
    passed_count += 1

    peer_key_id, peer_case = created[0]
    peer_pub = client.get(f"/pub/{peer_key_id}")
    _CONFIG["remote_routes"] = [
        {
            "remote_kid": peer_key_id,
            "name": "positive-peer-keys",
            "remote_addr": recipient_host,
            "allowed_local_kids": ["*"],
            "status": "active",
            "public_keys": peer_pub["keys"],
        }
    ]
    write_config()
    validate_remote_routes_list(client.post("/remote-routes/reload", {}, auth=True))
    listed_peer = client.get("/remote-routes", auth=True)
    validate_remote_routes_list(listed_peer)
    peer_route = next(
        (route for route in listed_peer["routes"] if route.get("remote_kid") == peer_key_id),
        None,
    )
    require(peer_route is not None, "peer remote route must be listed")
    require("public_keys" in peer_route, "peer remote route must expose public_keys")
    validate_remote_route_public_keys(peer_route["public_keys"], peer_case)
    print("Remote route public_keys round-trip: OK\n")
    passed_count += 1
    write_test_remote_routes([key_id for key_id, _ in created], recipient_host)
    validate_remote_routes_list(client.post("/remote-routes/reload", {}, auth=True))

    permission_rows = validate_permissions_flow(args.base_url, client, created[0][0], created[0][1])
    print_section("permissions", permission_rows)
    passed_count += len(permission_rows)

    test_rows = []
    pub_rows = []
    message_rows = []
    internal_message_rows = []
    sign_rows = []
    verify_rows = []

    for key_id, case in created:
        validate_test_response(client.get(f"/self-test/keys/{key_id}", auth=True), case)
        test_rows.append((key_id, "OK"))

        validate_pub_response(client.get(f"/pub/{key_id}"), case)
        pub_rows.append((key_id, "OK"))

        message_result = send_message(
            client,
            len(message_rows) + 1,
            key_id,
            key_id,
            case,
        )
        message_rows.append(
            (
                key_id,
                message_result["timestamp"],
                message_result["variant"],
                message_result["ctx_hex_len"],
                message_result["plaintext"],
            )
        )

        internal_result = encrypt_internal_message(
            client,
            len(internal_message_rows) + 1,
            key_id,
            case,
        )
        internal_message_rows.append(
            (
                key_id,
                internal_result["timestamp"],
                internal_result["variant"],
                internal_result["ctx_hex_len"],
                internal_result["plaintext"],
            )
        )

        for hash_alg, digest in HASH_CASES.items():
            token = sign_key(client, key_id, hash_alg, digest(message))
            sign_rows.append((f"{key_id} {hash_alg}", "OK"))

            verify_signature(client, token)
            verify_rows.append((f"{key_id} {hash_alg}", "OK"))

    write_test_remote_routes([key_id for key_id, _ in created], recipient_host, wildcard=True)
    validate_remote_routes_list(client.post("/remote-routes/reload", {}, auth=True))
    wildcard_result = send_message(
        client,
        len(message_rows) + 1,
        created[-1][0],
        created[0][0],
        created[-1][1],
        created[0][1],
    )
    message_rows.append(
        (
            f"{created[-1][0]} -> {created[0][0]} wildcard",
            wildcard_result["timestamp"],
            wildcard_result["variant"],
            wildcard_result["ctx_hex_len"],
            wildcard_result["plaintext"],
        )
    )

    print_section("test key", test_rows)
    print_section("pub", pub_rows)
    print_message(message_rows)
    print_internal_message(internal_message_rows)
    print_section("sign", sign_rows)
    print_section("sign verification", verify_rows)
    passed_count += len(create_rows)
    passed_count += len(test_rows)
    passed_count += len(pub_rows)
    passed_count += len(message_rows)
    passed_count += len(internal_message_rows)
    passed_count += len(sign_rows)
    passed_count += len(verify_rows)
    print(f"SUMMARY positive passed={passed_count} failed=0")
    _CONFIG["routes"] = []
    _CONFIG["remote_routes"] = []
    _CONFIG["permissions"] = []
    write_config()
    client.post("/routes/reload", {}, auth=True)
    restore_config_file(config_backup)
    restore_config_sign_file(config_sign_backup)
    final_app.shutdown()


if __name__ == "__main__":
    try:
        main()
    except WorkflowError as err:
        print(f"ERROR: {err}", file=sys.stderr)
        sys.exit(1)
