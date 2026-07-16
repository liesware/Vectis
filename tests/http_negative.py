#!/usr/bin/env python3
import argparse
import atexit
import copy
import hashlib
import json
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from test_config import require_apikey
from http_support import StatusClient as Client, parse_json, require_request_id


DEFAULT_BASE_URL = "http://127.0.0.1:3000"
VALID_KEY_REQUEST = {
    "tag": "negative-1",
    "profile": "hybrid-performance-v1",
    "eddsa_algorithm": "Ed25519",
    "xecdh_algorithm": "X25519",
    "ml_dsa_variant": "ML-DSA-44",
    "ml_kem_variant": "ML-KEM-512",
}
VALID_MESSAGE = b"Vectis negative workflow test"
CONFIG_PATH = Path("config.json")
CONFIG_SIGN_PATH = Path("config_sign.json")

_CONFIG = {
    "version": "v1",
    "routes": [],
    "remote_routes": [],
    "permissions": [],
    "fpe_profiles": [],
    "tokenization_profiles": [],
}


class NegativeTestError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise NegativeTestError(message)


def require_status(name, actual, expected):
    require(
        actual == expected,
        f"{name} expected HTTP {expected}, got HTTP {actual}",
    )


def require_hex(value, field):
    require(isinstance(value, str), f"{field} must be a string")
    require(len(value) > 0, f"{field} must not be empty")
    try:
        int(value, 16)
    except ValueError as err:
        raise NegativeTestError(f"{field} must be hex") from err


def ml_dsa_signature_block(token):
    return token.get("signatures", {}).get("ml-dsa") or token.get("signatures", {}).get("ml_dsa")


def tamper_hex(value):
    prefix = "00" if not value.startswith("00") else "ff"
    return prefix + value[2:]


def print_section(title, rows):
    print(f"{title}:")
    for name, status in rows:
        print(f"- {name}: {status}")
    print()


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


def create_api_key_pair():
    result = subprocess.run(
        ["cargo", "run", "--", "apikey", "create", "--output", "json"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise NegativeTestError(
            f"vectis apikey create failed: stdout={result.stdout} stderr={result.stderr}"
        )

    payload = parse_json(result.stdout)
    api_key = payload.get("VECTIS_APIKEY")
    api_key_hash = payload.get("VECTIS_APIKEY_HASH")
    require_hex(api_key, "VECTIS_APIKEY")
    require_hex(api_key_hash, "VECTIS_APIKEY_HASH")
    return api_key, api_key_hash


def sign_config():
    result = subprocess.run(
        ["cargo", "run", "--", "config", "sign", "--output", "json"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise NegativeTestError(
            f"vectis config sign failed: stdout={result.stdout} stderr={result.stderr}"
        )


def try_sign_config():
    return subprocess.run(
        ["cargo", "run", "--", "config", "sign", "--output", "json"],
        check=False,
        capture_output=True,
        text=True,
    )


def require_config_sign_fails(name):
    result = try_sign_config()
    require(result.returncode != 0, f"{name} must fail config sign")
    require(result.stderr.strip(), f"{name} must report config sign error")


def write_config(sign=True):
    CONFIG_PATH.write_text(json.dumps(_CONFIG, indent=2), encoding="utf-8")
    if sign:
        sign_config()


def write_permissions(clients, sign=True):
    # Isolate the section under test: negative cases put deliberately bad data
    # in one section, and the unified config reload validates all sections.
    _CONFIG["routes"] = []
    _CONFIG["remote_routes"] = []
    _CONFIG["permissions"] = clients
    _CONFIG["fpe_profiles"] = []
    _CONFIG["tokenization_profiles"] = []
    write_config(sign=sign)


def write_fpe_profiles(profiles, sign=True):
    _CONFIG["routes"] = []
    _CONFIG["remote_routes"] = []
    _CONFIG["permissions"] = []
    _CONFIG["fpe_profiles"] = profiles
    _CONFIG["tokenization_profiles"] = []
    write_config(sign=sign)


def write_tokenization_profiles(profiles, sign=True):
    _CONFIG["routes"] = []
    _CONFIG["remote_routes"] = []
    _CONFIG["permissions"] = []
    _CONFIG["fpe_profiles"] = []
    _CONFIG["tokenization_profiles"] = profiles
    write_config(sign=sign)


def write_remote_routes(routes, sign=True):
    _CONFIG["routes"] = []
    _CONFIG["permissions"] = []
    _CONFIG["remote_routes"] = routes
    _CONFIG["fpe_profiles"] = []
    _CONFIG["tokenization_profiles"] = []
    write_config(sign=sign)


def write_routes(routes, sign=True):
    _CONFIG["routes"] = routes
    _CONFIG["remote_routes"] = []
    _CONFIG["permissions"] = []
    _CONFIG["fpe_profiles"] = []
    _CONFIG["tokenization_profiles"] = []
    write_config(sign=sign)


def reload_config(client):
    status, response = client.post("/config/reload", {}, auth=True)
    require_status("POST /config/reload", status, 200)
    require(response.get("status") == "reloaded", "config reload status must be reloaded")
    require(isinstance(response.get("routes_loaded"), int), "config routes_loaded must be int")
    require(
        isinstance(response.get("remote_routes_loaded"), int),
        "config remote_routes_loaded must be int",
    )
    require(isinstance(response.get("clients_loaded"), int), "config clients_loaded must be int")
    require(
        isinstance(response.get("fpe_profiles_loaded"), int),
        "config fpe_profiles_loaded must be int",
    )
    require(
        isinstance(response.get("tokenization_profiles_loaded"), int),
        "config tokenization_profiles_loaded must be int",
    )
    return response


def create_valid_key(client):
    status, response = client.post("/keys", VALID_KEY_REQUEST, auth=True)
    require_status("create valid key", status, 200)
    key_id = response.get("kid")
    require_hex(key_id, "keys.kid")
    require("id" not in response, "keys create response must not include id")
    return key_id


def create_valid_token(client, key_id):
    message_hash_hex = hashlib.sha256(VALID_MESSAGE).hexdigest()
    status, token = client.post(
        f"/sign/{key_id}",
        {
            "message_hash": {
                "alg": "SHA-256",
                "hex": message_hash_hex,
            }
        },
        auth=True,
    )
    require_status("create valid token", status, 200)
    require(token.get("version") == "v1", "valid token must include version v1")
    return token


def create_valid_internal_message(client, key_id):
    status, response = client.post(
        f"/message/internal/encrypt/{key_id}",
        {"plaintext": "negative internal message"},
        auth=True,
    )
    require_status("create valid internal message", status, 200)
    require(response.get("kid") == key_id, "valid internal message kid mismatch")
    require(isinstance(response.get("message"), dict), "valid internal message must include message")
    require_hex(response["message"].get("ctx"), "valid internal message.ctx")
    return response


def valid_fpe_profile(key_id):
    return {
        "name": "patient-id-decimal-v1",
        "fpe_version": "fpe-ff1-2025",
        "alphabet": "0123456789",
        "min_len": 6,
        "max_len": 32,
        "tweak_aad": "tenant=acme;field=patient_id;version=1",
        "kid": key_id,
    }


def valid_tokenization_profile(key_id):
    return {
        "name": "patient-id-token-v1",
        "tokenization_version": "token-random-v1",
        "kid": key_id,
        "token_prefix": "tok_patient",
        "token_len": 32,
        "max_plaintext_len": 1024,
    }


def create_valid_encoded_token(client, key_id):
    status, response = client.post(
        f"/token/encode/{key_id}",
        {
            "profile": "patient-id-token-v1",
            "plaintext": "123456",
            "metadata": {"suite": "negative"},
        },
        auth=True,
    )
    require_status("create valid encoded token", status, 200)
    token = response.get("token")
    require(isinstance(token, str) and token.startswith("tok_patient_"), "valid encoded token")
    return token


def valid_message_request(key_id):
    return {
        "recipient_kid": key_id,
        "message": "negative message",
    }


def host_from_base_url(base_url):
    parsed = urllib.parse.urlparse(base_url)
    require(parsed.hostname, "base-url must include a host")
    require(parsed.port, "base-url must include a port")

    return f"{parsed.hostname}:{parsed.port}"


def run_case(rows, name, func):
    func()
    rows.append((name, "OK"))
    print(f"- {name}: OK", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Run negative HTTP contract tests.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--apikey")
    args = parser.parse_args()

    apikey = require_apikey(args.apikey)
    client = Client(args.base_url, apikey)
    recipient_host = host_from_base_url(args.base_url)
    config_backup = backup_file(CONFIG_PATH)
    config_sign_backup = backup_file(CONFIG_SIGN_PATH)
    atexit.register(restore_file, CONFIG_PATH, config_backup)
    atexit.register(restore_file, CONFIG_SIGN_PATH, config_sign_backup)
    rows = []
    print("HTTP negative:", flush=True)

    def keys_without_auth():
        status, _, headers = client.post_with_headers("/keys", VALID_KEY_REQUEST)
        require_status("POST /keys without auth", status, 401)
        require_request_id(headers)

    def keys_invalid_auth():
        status, _ = client.post(
            "/keys",
            VALID_KEY_REQUEST,
            headers={"X-API-Key": "00" * 32},
        )
        require_status("POST /keys invalid auth", status, 401)

    def keys_reload_without_auth():
        status, _ = client.post("/keys/reload", {})
        require_status("POST /keys/reload without auth", status, 401)

    def keys_reload_invalid_auth():
        status, _ = client.post(
            "/keys/reload",
            {},
            headers={"X-API-Key": "00" * 32},
        )
        require_status("POST /keys/reload invalid auth", status, 401)

    def keys_properties_without_auth():
        status, _ = client.get("/keys/properties")
        require_status("GET /keys/properties without auth", status, 401)

    def keys_properties_invalid_auth():
        status, _ = client.get("/keys/properties", headers={"X-API-Key": "00" * 32})
        require_status("GET /keys/properties invalid auth", status, 401)

    def metrics_without_auth():
        status, _ = client.get("/metrics")
        require_status("GET /metrics without auth", status, 401)

    def metrics_invalid_auth():
        status, _ = client.get("/metrics", headers={"X-API-Key": "00" * 32})
        require_status("GET /metrics invalid auth", status, 401)

    def key_properties_without_auth():
        status, _ = client.get(f"/keys/properties/{key_id}")
        require_status("GET /keys/properties/{kid} without auth", status, 401)

    def key_properties_invalid_kid():
        status, _ = client.get("/keys/properties/not-hex", auth=True)
        require_status("GET /keys/properties/{kid} invalid kid", status, 400)

    def lifecycle_without_auth():
        status, _ = client.post(
            f"/lifecycle/{key_id}",
            {"status": "disabled", "reason": "maintenance"},
        )
        require_status("POST /lifecycle/{kid} without auth", status, 401)

    def lifecycle_invalid_kid():
        status, _ = client.post(
            "/lifecycle/not-hex",
            {"status": "disabled", "reason": "maintenance"},
            auth=True,
        )
        require_status("POST /lifecycle/{kid} invalid kid", status, 400)

    def lifecycle_status_not_string():
        status, _ = client.post(
            f"/lifecycle/{key_id}",
            {"status": 1, "reason": "maintenance"},
            auth=True,
        )
        require_status("POST /lifecycle/{kid} status not string", status, 400)

    def lifecycle_invalid_status():
        status, _ = client.post(
            f"/lifecycle/{key_id}",
            {"status": "paused", "reason": "maintenance"},
            auth=True,
        )
        require_status("POST /lifecycle/{kid} invalid status", status, 400)

    def lifecycle_reason_not_string():
        status, _ = client.post(
            f"/lifecycle/{key_id}",
            {"status": "disabled", "reason": 1},
            auth=True,
        )
        require_status("POST /lifecycle/{kid} reason not string", status, 400)

    def routes_list_without_auth():
        status, _ = client.get("/routes")
        require_status("GET /routes without auth", status, 401)

    def routes_list_invalid_auth():
        status, _ = client.get("/routes", headers={"X-API-Key": "00" * 32})
        require_status("GET /routes invalid auth", status, 401)

    def config_reload_without_auth():
        status, _ = client.post("/config/reload", {})
        require_status("POST /config/reload without auth", status, 401)

    def config_reload_invalid_auth():
        status, _ = client.post(
            "/config/reload",
            {},
            headers={"X-API-Key": "00" * 32},
        )
        require_status("POST /config/reload invalid auth", status, 401)

    def remote_routes_list_without_auth():
        status, _ = client.get("/remote-routes")
        require_status("GET /remote-routes without auth", status, 401)

    def remote_routes_list_invalid_auth():
        status, _ = client.get("/remote-routes", headers={"X-API-Key": "00" * 32})
        require_status("GET /remote-routes invalid auth", status, 401)

    def permissions_list_without_auth():
        status, _ = client.get("/permissions")
        require_status("GET /permissions without auth", status, 401)

    def permissions_list_invalid_auth():
        status, _ = client.get("/permissions", headers={"X-API-Key": "00" * 32})
        require_status("GET /permissions invalid auth", status, 401)

    def fpe_encrypt_without_auth():
        status, _, headers = client.post_with_headers(
            f"/fpe/encrypt/{key_id}",
            {"profile": "patient-id-decimal-v1", "plaintext": "123456"},
        )
        require_status("POST /fpe/encrypt/{kid} without auth", status, 401)
        require_request_id(headers)

    def fpe_decrypt_without_auth():
        status, _ = client.post(
            "/fpe/decrypt",
            {"kid": key_id, "profile": "patient-id-decimal-v1", "ciphertext": "123456"},
        )
        require_status("POST /fpe/decrypt without auth", status, 401)

    def fpe_encrypt_invalid_auth():
        status, _ = client.post(
            f"/fpe/encrypt/{key_id}",
            {"profile": "patient-id-decimal-v1", "plaintext": "123456"},
            headers={"X-API-Key": "00" * 32},
        )
        require_status("POST /fpe/encrypt/{kid} invalid auth", status, 401)

    def fpe_decrypt_invalid_auth():
        status, _ = client.post(
            "/fpe/decrypt",
            {"kid": key_id, "profile": "patient-id-decimal-v1", "ciphertext": "123456"},
            headers={"X-API-Key": "00" * 32},
        )
        require_status("POST /fpe/decrypt invalid auth", status, 401)

    def keys_tag_not_string():
        request = dict(VALID_KEY_REQUEST)
        request["tag"] = 1
        status, _ = client.post("/keys", request, auth=True)
        require_status("POST /keys tag not string", status, 400)

    def keys_invalid_algorithm():
        request = dict(VALID_KEY_REQUEST)
        request["eddsa_algorithm"] = "Ed25519-BAD"
        status, _ = client.post("/keys", request, auth=True)
        require_status("POST /keys invalid algorithm", status, 400)

    def keys_invalid_profile():
        request = dict(VALID_KEY_REQUEST)
        request["profile"] = "hybrid-imaginary-v1"
        status, _ = client.post("/keys", request, auth=True)
        require_status("POST /keys invalid profile", status, 400)

    def keys_invalid_hash_algorithm():
        request = dict(VALID_KEY_REQUEST)
        request["hash_algorithm"] = "SHA-999"
        status, _ = client.post("/keys", request, auth=True)
        require_status("POST /keys invalid hash algorithm", status, 400)

    def keys_invalid_symmetric_algorithm():
        request = dict(VALID_KEY_REQUEST)
        request["symmetric_algorithm"] = "AES-999/GCM"
        status, _ = client.post("/keys", request, auth=True)
        require_status("POST /keys invalid symmetric algorithm", status, 400)

    def keys_tag_with_aad_delimiters():
        for bad_tag in ("has;semicolon", "has=equals"):
            request = dict(VALID_KEY_REQUEST)
            request["tag"] = bad_tag
            status, _ = client.post("/keys", request, auth=True)
            require_status(f"POST /keys tag {bad_tag!r}", status, 400)

    def keys_control_char_field_name():
        request = dict(VALID_KEY_REQUEST)
        request["badfield"] = "x"
        status, body = client.post("/keys", request, auth=True)
        require_status("POST /keys control-char field name", status, 400)
        error = body.get("error", "")
        require(
            not any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in error),
            "error message must not contain control characters",
        )

    key_id = create_valid_key(client)

    limited_api_key, limited_api_key_hash = create_api_key_pair()
    metrics_api_key, metrics_api_key_hash = create_api_key_pair()
    admin_api_key, admin_api_key_hash = create_api_key_pair()
    write_permissions(
        [
            {
                "client": "negative-limited-message",
                "apikey_hash": limited_api_key_hash,
                "status": "active",
                "permissions": [
                    {
                        "kid": key_id,
                        "actions": ["message"],
                    }
                ],
            },
            {
                "client": "negative-metrics",
                "apikey_hash": metrics_api_key_hash,
                "status": "active",
                "permissions": [
                    {
                        "kid": "*",
                        "actions": ["metrics"],
                    }
                ],
            },
            {
                "client": "negative-admin",
                "apikey_hash": admin_api_key_hash,
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
    _CONFIG["fpe_profiles"] = [valid_fpe_profile(key_id)]
    _CONFIG["tokenization_profiles"] = [valid_tokenization_profile(key_id)]
    write_config()
    reload_config(client)
    limited_client = Client(args.base_url, limited_api_key)
    metrics_client = Client(args.base_url, metrics_api_key)
    admin_client = Client(args.base_url, admin_api_key)

    def limited_can_message():
        status, _ = limited_client.post(
            f"/message/internal/encrypt/{key_id}",
            {"plaintext": "limited message permission"},
            auth=True,
        )
        require_status("limited client can message", status, 200)

    def limited_blocks_keys_reload():
        status, _ = limited_client.post("/keys/reload", {}, auth=True)
        require_status("limited client blocks keys reload", status, 403)

    def limited_blocks_routes():
        status, _ = limited_client.get("/routes", auth=True)
        require_status("limited client blocks routes", status, 403)

    def limited_blocks_self_test():
        status, _ = limited_client.get("/self-test/init", auth=True)
        require_status("limited client blocks self-test init", status, 403)

    def limited_blocks_sign():
        status, _ = limited_client.post(
            f"/sign/{key_id}",
            {
                "message_hash": {
                    "alg": "SHA-256",
                    "hex": hashlib.sha256(VALID_MESSAGE).hexdigest(),
                }
            },
            auth=True,
        )
        require_status("limited client blocks sign", status, 403)

    def limited_blocks_config_reload():
        status, _ = limited_client.post("/config/reload", {}, auth=True)
        require_status("limited client blocks config reload", status, 403)

    def limited_blocks_metrics():
        status, _ = limited_client.get("/metrics", auth=True)
        require_status("limited client blocks metrics", status, 403)

    def limited_blocks_fpe_encrypt():
        status, _ = limited_client.post(
            f"/fpe/encrypt/{key_id}",
            {"profile": "patient-id-decimal-v1", "plaintext": "123456"},
            auth=True,
        )
        require_status("limited client blocks fpe encrypt", status, 403)

    def limited_blocks_fpe_decrypt():
        status, _ = limited_client.post(
            "/fpe/decrypt",
            {"kid": key_id, "profile": "patient-id-decimal-v1", "ciphertext": "123456"},
            auth=True,
        )
        require_status("limited client blocks fpe decrypt", status, 403)

    def limited_blocks_fpe_encrypt_batch():
        status, _ = limited_client.post(
            f"/fpe/encrypt/batch/{key_id}",
            {"profile": "patient-id-decimal-v1", "items": [{"plaintext": "123456"}]},
            auth=True,
        )
        require_status("limited client blocks fpe encrypt batch", status, 403)

    def limited_blocks_fpe_decrypt_batch():
        status, _ = limited_client.post(
            "/fpe/decrypt/batch",
            {
                "kid": key_id,
                "profile": "patient-id-decimal-v1",
                "items": [{"ciphertext": "123456"}],
            },
            auth=True,
        )
        require_status("limited client blocks fpe decrypt batch", status, 403)

    def limited_blocks_token_encode():
        status, _ = limited_client.post(
            f"/token/encode/{key_id}",
            {"profile": "patient-id-token-v1", "plaintext": "123456"},
            auth=True,
        )
        require_status("limited client blocks token encode", status, 403)

    def limited_blocks_token_decode():
        status, _ = limited_client.post(
            "/token/decode",
            {"kid": key_id, "profile": "patient-id-token-v1", "token": "tok_patient_missing"},
            auth=True,
        )
        require_status("limited client blocks token decode", status, 403)

    def metrics_client_allows_metrics():
        status, _ = metrics_client.get("/metrics", auth=True)
        require_status("metrics client allows metrics", status, 200)

    def metrics_client_blocks_admin():
        status, _ = metrics_client.get("/routes", auth=True)
        require_status("metrics client blocks admin", status, 403)

    def limited_blocks_permissions_list():
        status, _ = limited_client.get("/permissions", auth=True)
        require_status("limited client blocks permissions list", status, 403)

    def metrics_client_blocks_permissions_list():
        status, _ = metrics_client.get("/permissions", auth=True)
        require_status("metrics client blocks permissions list", status, 403)

    def admin_allows_config_reload():
        status, response = admin_client.post("/config/reload", {}, auth=True)
        require_status("admin client allows config reload", status, 200)
        require(response.get("status") == "reloaded", "admin config reload status")

    def admin_allows_permissions_list():
        status, response = admin_client.get("/permissions", auth=True)
        require_status("admin client allows permissions list", status, 200)
        require(isinstance(response.get("clients"), list), "permissions.clients must be a list")
        require("apikey_hash" not in json.dumps(response), "permissions list must not expose apikey_hash")

    def admin_allows_fpe_round_trip():
        status, encrypted = admin_client.post(
            f"/fpe/encrypt/{key_id}",
            {"profile": "patient-id-decimal-v1", "plaintext": "123456"},
            auth=True,
        )
        require_status("admin client allows fpe encrypt", status, 200)
        require("fpe_version" not in encrypted, "fpe encrypt response must not include fpe_version")
        status, decrypted = admin_client.post(
            "/fpe/decrypt",
            {
                "kid": key_id,
                "profile": "patient-id-decimal-v1",
                "ciphertext": encrypted.get("ciphertext"),
            },
            auth=True,
        )
        require_status("admin client allows fpe decrypt", status, 200)
        require(decrypted.get("plaintext") == "123456", "admin fpe decrypt plaintext mismatch")

    for name, func in (
        ("limited client can message", limited_can_message),
        ("limited client blocks keys reload", limited_blocks_keys_reload),
        ("limited client blocks routes", limited_blocks_routes),
        ("limited client blocks self-test init", limited_blocks_self_test),
        ("limited client blocks sign", limited_blocks_sign),
        ("limited client blocks config reload", limited_blocks_config_reload),
        ("limited client blocks metrics", limited_blocks_metrics),
        ("limited client blocks fpe encrypt", limited_blocks_fpe_encrypt),
        ("limited client blocks fpe decrypt", limited_blocks_fpe_decrypt),
        ("limited client blocks fpe encrypt batch", limited_blocks_fpe_encrypt_batch),
        ("limited client blocks fpe decrypt batch", limited_blocks_fpe_decrypt_batch),
        ("limited client blocks token encode", limited_blocks_token_encode),
        ("limited client blocks token decode", limited_blocks_token_decode),
        ("metrics client allows metrics", metrics_client_allows_metrics),
        ("metrics client blocks admin", metrics_client_blocks_admin),
        ("limited client blocks permissions list", limited_blocks_permissions_list),
        ("metrics client blocks permissions list", metrics_client_blocks_permissions_list),
        ("admin client allows config reload", admin_allows_config_reload),
        ("admin client allows permissions list", admin_allows_permissions_list),
        ("admin client allows fpe round trip", admin_allows_fpe_round_trip),
    ):
        run_case(rows, name, func)

    for name, func in (
        ("POST /keys without auth", keys_without_auth),
        ("POST /keys invalid auth", keys_invalid_auth),
        ("POST /keys/reload without auth", keys_reload_without_auth),
        ("POST /keys/reload invalid auth", keys_reload_invalid_auth),
        ("GET /keys/properties without auth", keys_properties_without_auth),
        ("GET /keys/properties invalid auth", keys_properties_invalid_auth),
        ("GET /metrics without auth", metrics_without_auth),
        ("GET /metrics invalid auth", metrics_invalid_auth),
        ("GET /keys/properties/{kid} without auth", key_properties_without_auth),
        ("GET /keys/properties/{kid} invalid kid", key_properties_invalid_kid),
        ("POST /lifecycle/{kid} without auth", lifecycle_without_auth),
        ("POST /lifecycle/{kid} invalid kid", lifecycle_invalid_kid),
        ("POST /lifecycle/{kid} status not string", lifecycle_status_not_string),
        ("POST /lifecycle/{kid} invalid status", lifecycle_invalid_status),
        ("POST /lifecycle/{kid} reason not string", lifecycle_reason_not_string),
        ("GET /routes without auth", routes_list_without_auth),
        ("GET /routes invalid auth", routes_list_invalid_auth),
        ("POST /config/reload without auth", config_reload_without_auth),
        ("POST /config/reload invalid auth", config_reload_invalid_auth),
        ("GET /remote-routes without auth", remote_routes_list_without_auth),
        ("GET /remote-routes invalid auth", remote_routes_list_invalid_auth),
        ("GET /permissions without auth", permissions_list_without_auth),
        ("GET /permissions invalid auth", permissions_list_invalid_auth),
        ("POST /fpe/encrypt/{kid} without auth", fpe_encrypt_without_auth),
        ("POST /fpe/decrypt without auth", fpe_decrypt_without_auth),
        ("POST /fpe/encrypt/{kid} invalid auth", fpe_encrypt_invalid_auth),
        ("POST /fpe/decrypt invalid auth", fpe_decrypt_invalid_auth),
        ("POST /keys tag not string", keys_tag_not_string),
        ("POST /keys invalid algorithm", keys_invalid_algorithm),
        ("POST /keys invalid profile", keys_invalid_profile),
        ("POST /keys invalid hash algorithm", keys_invalid_hash_algorithm),
        ("POST /keys invalid symmetric algorithm", keys_invalid_symmetric_algorithm),
        ("POST /keys tag with aad delimiters", keys_tag_with_aad_delimiters),
        ("POST /keys control-char field name", keys_control_char_field_name),
    ):
        run_case(rows, name, func)

    def restore_valid_permissions():
        write_permissions(
            [
                {
                    "client": "negative-limited-message",
                    "apikey_hash": limited_api_key_hash,
                    "status": "active",
                    "permissions": [
                        {
                            "kid": key_id,
                            "actions": ["message"],
                        }
                    ],
                },
                {
                    "client": "negative-admin",
                    "apikey_hash": admin_api_key_hash,
                    "status": "active",
                    "permissions": [
                        {
                            "kid": "*",
                            "actions": ["admin"],
                        }
                    ],
                },
                {
                    "client": "negative-metrics",
                    "apikey_hash": metrics_api_key_hash,
                    "status": "active",
                    "permissions": [
                        {
                            "kid": "*",
                            "actions": ["metrics"],
                        }
                    ],
                },
            ]
        )
        reload_config(client)

    def permissions_invalid_action_pub():
        write_permissions(
            [
                {
                    "client": "bad-action",
                    "apikey_hash": limited_api_key_hash,
                    "status": "active",
                    "permissions": [{"kid": key_id, "actions": ["pub"]}],
                }
            ],
            sign=False,
        )
        require_config_sign_fails("permissions invalid action pub")

    def permissions_invalid_action_routes():
        write_permissions(
            [
                {
                    "client": "bad-action-routes",
                    "apikey_hash": limited_api_key_hash,
                    "status": "active",
                    "permissions": [{"kid": key_id, "actions": ["routes"]}],
                }
            ],
            sign=False,
        )
        require_config_sign_fails("permissions invalid action routes")

    def permissions_wildcard_non_global_action():
        write_permissions(
            [
                {
                    "client": "bad-wildcard-message",
                    "apikey_hash": limited_api_key_hash,
                    "status": "active",
                    "permissions": [{"kid": "*", "actions": ["message"]}],
                }
            ],
            sign=False,
        )
        require_config_sign_fails("permissions wildcard non-global action")

    def permissions_wildcard_fpe_encrypt():
        write_permissions(
            [
                {
                    "client": "bad-wildcard-fpe",
                    "apikey_hash": limited_api_key_hash,
                    "status": "active",
                    "permissions": [{"kid": "*", "actions": ["fpe-encrypt"]}],
                }
            ],
            sign=False,
        )
        require_config_sign_fails("permissions wildcard fpe encrypt")

    def permissions_wildcard_token_encode():
        write_permissions(
            [
                {
                    "client": "bad-wildcard-token",
                    "apikey_hash": limited_api_key_hash,
                    "status": "active",
                    "permissions": [{"kid": "*", "actions": ["token-encode"]}],
                }
            ],
            sign=False,
        )
        require_config_sign_fails("permissions wildcard token encode")

    def fpe_profile_duplicate_name():
        profile = valid_fpe_profile(key_id)
        write_fpe_profiles([profile, dict(profile, kid=key_id)], sign=False)
        require_config_sign_fails("fpe profile duplicate name")

    def fpe_profile_invalid_version():
        profile = valid_fpe_profile(key_id)
        profile["fpe_version"] = "fpe-ff1-legacy"
        write_fpe_profiles([profile], sign=False)
        require_config_sign_fails("fpe profile invalid version")

    def fpe_profile_duplicate_alphabet():
        profile = valid_fpe_profile(key_id)
        profile["alphabet"] = "00123456789"
        write_fpe_profiles([profile], sign=False)
        require_config_sign_fails("fpe profile duplicate alphabet")

    def fpe_profile_invalid_lengths():
        profile = valid_fpe_profile(key_id)
        profile["min_len"] = 32
        profile["max_len"] = 6
        write_fpe_profiles([profile], sign=False)
        require_config_sign_fails("fpe profile invalid lengths")

    def fpe_profile_max_len_too_large():
        profile = valid_fpe_profile(key_id)
        profile["max_len"] = 1025
        write_fpe_profiles([profile], sign=False)
        require_config_sign_fails("fpe profile max len too large")

    def fpe_profile_unloaded_kid():
        profile = valid_fpe_profile("00" * 32)
        write_fpe_profiles([profile], sign=False)
        require_config_sign_fails("fpe profile unloaded kid")

    def token_profile_duplicate_name():
        profile = valid_tokenization_profile(key_id)
        write_tokenization_profiles([profile, dict(profile, kid=key_id)], sign=False)
        require_config_sign_fails("token profile duplicate name")

    def token_profile_invalid_version():
        profile = valid_tokenization_profile(key_id)
        profile["tokenization_version"] = "token-random-v2"
        write_tokenization_profiles([profile], sign=False)
        require_config_sign_fails("token profile invalid version")

    def token_profile_invalid_lengths():
        profile = valid_tokenization_profile(key_id)
        profile["token_len"] = 31
        write_tokenization_profiles([profile], sign=False)
        require_config_sign_fails("token profile invalid token_len")

    def token_profile_unloaded_kid():
        profile = valid_tokenization_profile("00" * 32)
        write_tokenization_profiles([profile], sign=False)
        require_config_sign_fails("token profile unloaded kid")

    def routes_missing_name():
        write_routes(
            [
                {
                    "kid": key_id,
                    "final_app_addr": "localhost:3999",
                    "final_app_path": "/message",
                }
            ],
            sign=False,
        )
        result = try_sign_config()
        require(result.returncode != 0, "routes missing name must fail config sign")
        require(
            "missing field `name`" in result.stderr,
            "routes missing name must report missing name",
        )

    def routes_invalid_name():
        write_routes(
            [
                {
                    "kid": key_id,
                    "name": "",
                    "final_app_addr": "localhost:3999",
                    "final_app_path": "/message",
                }
            ],
            sign=False,
        )
        require_config_sign_fails("routes invalid name")

    def remote_routes_invalid_kid():
        write_remote_routes(
            [
                {
                    "remote_kid": "not-hex",
                    "name": "bad kid",
                    "remote_addr": recipient_host,
                    "allowed_local_kids": [key_id],
                    "status": "active",
                }
            ],
            sign=False,
        )
        require_config_sign_fails("remote routes invalid kid")

    def remote_routes_invalid_addr():
        write_remote_routes(
            [
                {
                    "remote_kid": key_id,
                    "name": "bad addr",
                    "remote_addr": "not-a-socket-address",
                    "allowed_local_kids": [key_id],
                    "status": "active",
                }
            ],
            sign=False,
        )
        require_config_sign_fails("remote routes invalid addr")

    def remote_routes_invalid_signature():
        write_remote_routes(
            [
                {
                    "remote_kid": key_id,
                    "name": "invalid signature",
                    "remote_addr": recipient_host,
                    "allowed_local_kids": [key_id],
                    "status": "active",
                }
            ]
        )
        CONFIG_SIGN_PATH.write_text('{"invalid":true}\n', encoding="utf-8")
        status, _ = client.post("/config/reload", {}, auth=True)
        require_status("remote routes invalid signature", status, 400)

    def remote_routes_empty_allowed_local_kids():
        write_remote_routes(
            [
                {
                    "remote_kid": key_id,
                    "name": "empty allowed",
                    "remote_addr": recipient_host,
                    "allowed_local_kids": [],
                    "status": "active",
                }
            ],
            sign=False,
        )
        require_config_sign_fails("remote routes empty allowed local kids")

    def remote_routes_wildcard_mixed_with_kid():
        write_remote_routes(
            [
                {
                    "remote_kid": key_id,
                    "name": "mixed wildcard",
                    "remote_addr": recipient_host,
                    "allowed_local_kids": ["*", key_id],
                    "status": "active",
                }
            ],
            sign=False,
        )
        require_config_sign_fails("remote routes wildcard mixed with kid")

    def remote_routes_invalid_allowed_local_kid():
        write_remote_routes(
            [
                {
                    "remote_kid": key_id,
                    "name": "invalid allowed kid",
                    "remote_addr": recipient_host,
                    "allowed_local_kids": ["not-hex"],
                    "status": "active",
                }
            ],
            sign=False,
        )
        require_config_sign_fails("remote routes invalid allowed local kid")

    def remote_routes_unloaded_allowed_local_kid():
        write_remote_routes(
            [
                {
                    "remote_kid": key_id,
                    "name": "unloaded allowed kid",
                    "remote_addr": recipient_host,
                    "allowed_local_kids": ["00" * 32],
                    "status": "active",
                }
            ],
            sign=False,
        )
        require_config_sign_fails("remote routes unloaded allowed local kid")

    def remote_routes_invalid_status():
        write_remote_routes(
            [
                {
                    "remote_kid": key_id,
                    "name": "invalid status",
                    "remote_addr": recipient_host,
                    "allowed_local_kids": [key_id],
                    "status": "paused",
                }
            ],
            sign=False,
        )
        require_config_sign_fails("remote routes invalid status")

    def _peer_public_keys():
        status, response = client.get(f"/pub/{key_id}")
        require_status("GET /pub for remote route public keys", status, 200)
        keys = response.get("keys")
        require(isinstance(keys, dict), "pub response keys must be an object")
        return copy.deepcopy(keys)

    def remote_routes_invalid_public_key_alg():
        public_keys = _peer_public_keys()
        public_keys["eddsa"]["alg"] = "RSA"
        write_remote_routes(
            [
                {
                    "remote_kid": key_id,
                    "name": "bad public key alg",
                    "remote_addr": recipient_host,
                    "allowed_local_kids": [key_id],
                    "status": "active",
                    "public_keys": public_keys,
                }
            ],
            sign=False,
        )
        require_config_sign_fails("remote routes invalid public key alg")

    def remote_routes_invalid_public_key_hex():
        public_keys = _peer_public_keys()
        public_keys["xecdh"]["public_key_hex"] = "zz"
        write_remote_routes(
            [
                {
                    "remote_kid": key_id,
                    "name": "bad public key hex",
                    "remote_addr": recipient_host,
                    "allowed_local_kids": [key_id],
                    "status": "active",
                    "public_keys": public_keys,
                }
            ],
            sign=False,
        )
        require_config_sign_fails("remote routes invalid public key hex")

    def remote_routes_invalid_public_key_der():
        public_keys = _peer_public_keys()
        public_keys["eddsa"]["public_key_der_hex"] = "aa"
        write_remote_routes(
            [
                {
                    "remote_kid": key_id,
                    "name": "bad public key der",
                    "remote_addr": recipient_host,
                    "allowed_local_kids": [key_id],
                    "status": "active",
                    "public_keys": public_keys,
                }
            ],
            sign=False,
        )
        require_config_sign_fails("remote routes invalid public key der")

    def permissions_missing_kid():
        write_permissions(
            [
                {
                    "client": "missing-kid",
                    "apikey_hash": limited_api_key_hash,
                    "status": "active",
                    "permissions": [{"kid": "00" * 32, "actions": ["message"]}],
                }
            ],
            sign=False,
        )
        require_config_sign_fails("permissions missing kid")

    def permissions_invalid_apikey_hash():
        write_permissions(
            [
                {
                    "client": "bad-hash",
                    "apikey_hash": "not-hex",
                    "status": "active",
                    "permissions": [{"kid": key_id, "actions": ["message"]}],
                }
            ],
            sign=False,
        )
        require_config_sign_fails("permissions invalid apikey_hash")

    def permissions_invalid_status():
        write_permissions(
            [
                {
                    "client": "bad-status",
                    "apikey_hash": limited_api_key_hash,
                    "status": "paused",
                    "permissions": [{"kid": key_id, "actions": ["message"]}],
                }
            ],
            sign=False,
        )
        require_config_sign_fails("permissions invalid status")

    def permissions_invalid_signature():
        write_permissions(
            [
                {
                    "client": "invalid-signature",
                    "apikey_hash": limited_api_key_hash,
                    "status": "active",
                    "permissions": [{"kid": key_id, "actions": ["message"]}],
                }
            ]
        )
        CONFIG_SIGN_PATH.write_text('{"invalid":true}\n', encoding="utf-8")
        status, _ = client.post("/config/reload", {}, auth=True)
        require_status("permissions invalid signature", status, 400)

    for name, func in (
        ("permissions invalid action pub", permissions_invalid_action_pub),
        ("permissions invalid action routes", permissions_invalid_action_routes),
        ("permissions wildcard non-global action", permissions_wildcard_non_global_action),
        ("permissions wildcard fpe encrypt", permissions_wildcard_fpe_encrypt),
        ("permissions wildcard token encode", permissions_wildcard_token_encode),
        ("fpe profile duplicate name", fpe_profile_duplicate_name),
        ("fpe profile invalid version", fpe_profile_invalid_version),
        ("fpe profile duplicate alphabet", fpe_profile_duplicate_alphabet),
        ("fpe profile invalid lengths", fpe_profile_invalid_lengths),
        ("fpe profile max len too large", fpe_profile_max_len_too_large),
        ("fpe profile unloaded kid", fpe_profile_unloaded_kid),
        ("token profile duplicate name", token_profile_duplicate_name),
        ("token profile invalid version", token_profile_invalid_version),
        ("token profile invalid lengths", token_profile_invalid_lengths),
        ("token profile unloaded kid", token_profile_unloaded_kid),
        ("routes missing name", routes_missing_name),
        ("routes invalid name", routes_invalid_name),
        ("remote routes invalid kid", remote_routes_invalid_kid),
        ("remote routes invalid addr", remote_routes_invalid_addr),
        ("remote routes invalid signature", remote_routes_invalid_signature),
        ("remote routes empty allowed local kids", remote_routes_empty_allowed_local_kids),
        ("remote routes wildcard mixed with kid", remote_routes_wildcard_mixed_with_kid),
        ("remote routes invalid allowed local kid", remote_routes_invalid_allowed_local_kid),
        ("remote routes unloaded allowed local kid", remote_routes_unloaded_allowed_local_kid),
        ("remote routes invalid status", remote_routes_invalid_status),
        ("remote routes invalid public key alg", remote_routes_invalid_public_key_alg),
        ("remote routes invalid public key hex", remote_routes_invalid_public_key_hex),
        ("remote routes invalid public key der", remote_routes_invalid_public_key_der),
        ("permissions missing kid", permissions_missing_kid),
        ("permissions invalid apikey_hash", permissions_invalid_apikey_hash),
        ("permissions invalid status", permissions_invalid_status),
        ("permissions invalid signature", permissions_invalid_signature),
    ):
        run_case(rows, name, func)

    restore_valid_permissions()
    _CONFIG["fpe_profiles"] = [valid_fpe_profile(key_id)]
    write_config()
    reload_config(client)

    token = create_valid_token(client, key_id)
    internal_message = create_valid_internal_message(client, key_id)
    disabled_key_id = create_valid_key(client)
    disabled_internal_message = create_valid_internal_message(client, disabled_key_id)
    retired_key_id = create_valid_key(client)
    retired_token = create_valid_token(client, retired_key_id)
    retired_internal_message = create_valid_internal_message(client, retired_key_id)
    compromised_key_id = create_valid_key(client)
    compromised_token = create_valid_token(client, compromised_key_id)
    compromised_internal_message = create_valid_internal_message(client, compromised_key_id)
    destroyed_key_id = create_valid_key(client)
    destroyed_token = create_valid_token(client, destroyed_key_id)
    destroyed_internal_message = create_valid_internal_message(client, destroyed_key_id)

    def set_lifecycle(kid, status):
        response_status, _ = client.post(
            f"/lifecycle/{kid}",
            {"status": status, "reason": f"negative test {status}"},
            auth=True,
        )
        require_status(f"set lifecycle {status}", response_status, 200)

    def disabled_blocks_sign():
        set_lifecycle(disabled_key_id, "disabled")
        status, _ = client.post(
            f"/sign/{disabled_key_id}",
            {
                "message_hash": {
                    "alg": "SHA-256",
                    "hex": hashlib.sha256(VALID_MESSAGE).hexdigest(),
                }
            },
            auth=True,
        )
        require_status("disabled key blocks sign", status, 403)

    def disabled_blocks_pub():
        status, _ = client.get(f"/pub/{disabled_key_id}")
        require_status("disabled key blocks pub", status, 403)

    def disabled_blocks_internal_decrypt():
        status, _ = client.post("/message/internal/decrypt", disabled_internal_message, auth=True)
        require_status("disabled key blocks internal decrypt", status, 403)

    def assert_blocks_sign(kid, label):
        status, _ = client.post(
            f"/sign/{kid}",
            {
                "message_hash": {
                    "alg": "SHA-256",
                    "hex": hashlib.sha256(VALID_MESSAGE).hexdigest(),
                }
            },
            auth=True,
        )
        require_status(f"{label} key blocks sign", status, 403)

    def assert_blocks_pub(kid, label):
        status, _ = client.get(f"/pub/{kid}")
        require_status(f"{label} key blocks pub", status, 403)

    def assert_blocks_internal_decrypt(message, label):
        status, _ = client.post("/message/internal/decrypt", message, auth=True)
        require_status(f"{label} key blocks internal decrypt", status, 403)

    def assert_blocks_verification(token_value, label):
        status, _ = client.post("/sign/verification", token_value)
        require_status(f"{label} key blocks verification", status, 403)

    def retired_blocks_sign():
        set_lifecycle(retired_key_id, "retired")
        assert_blocks_sign(retired_key_id, "retired")

    def retired_blocks_pub():
        assert_blocks_pub(retired_key_id, "retired")

    def retired_allows_verification():
        status, response = client.post("/sign/verification", retired_token)
        require_status("retired key allows verification", status, 200)
        require(response.get("valid") == "ok", "retired key verification must remain valid")

    def retired_allows_internal_decrypt():
        status, response = client.post(
            "/message/internal/decrypt",
            retired_internal_message,
            auth=True,
        )
        require_status("retired key allows internal decrypt", status, 200)
        require(response.get("plaintext") == "negative internal message", "retired decrypt plaintext")

    def compromised_blocks_crypto():
        set_lifecycle(compromised_key_id, "compromised")
        assert_blocks_sign(compromised_key_id, "compromised")
        assert_blocks_pub(compromised_key_id, "compromised")
        assert_blocks_internal_decrypt(compromised_internal_message, "compromised")
        assert_blocks_verification(compromised_token, "compromised")

    def destroyed_blocks_crypto():
        set_lifecycle(destroyed_key_id, "destroyed")
        assert_blocks_sign(destroyed_key_id, "destroyed")
        assert_blocks_pub(destroyed_key_id, "destroyed")
        assert_blocks_internal_decrypt(destroyed_internal_message, "destroyed")
        assert_blocks_verification(destroyed_token, "destroyed")

    def lifecycle_rejects_same_state():
        same_state_key_id = create_valid_key(client)
        status, _ = client.post(
            f"/lifecycle/{same_state_key_id}",
            {"status": "active", "reason": "same state"},
            auth=True,
        )
        require_status("POST /lifecycle/{kid} active to active", status, 400)

    def lifecycle_rejects_terminal_transition():
        terminal_key_id = create_valid_key(client)
        set_lifecycle(terminal_key_id, "retired")
        status, _ = client.post(
            f"/lifecycle/{terminal_key_id}",
            {"status": "active", "reason": "restore retired"},
            auth=True,
        )
        require_status("POST /lifecycle/{kid} retired to active", status, 400)

    def lifecycle_rejects_compromised_to_active():
        terminal_key_id = create_valid_key(client)
        set_lifecycle(terminal_key_id, "compromised")
        status, _ = client.post(
            f"/lifecycle/{terminal_key_id}",
            {"status": "active", "reason": "restore compromised"},
            auth=True,
        )
        require_status("POST /lifecycle/{kid} compromised to active", status, 400)

    def lifecycle_rejects_destroyed_to_active():
        terminal_key_id = create_valid_key(client)
        set_lifecycle(terminal_key_id, "destroyed")
        status, _ = client.post(
            f"/lifecycle/{terminal_key_id}",
            {"status": "active", "reason": "restore destroyed"},
            auth=True,
        )
        require_status("POST /lifecycle/{kid} destroyed to active", status, 400)

    for name, func in (
        ("disabled key blocks sign", disabled_blocks_sign),
        ("disabled key blocks pub", disabled_blocks_pub),
        ("disabled key blocks internal decrypt", disabled_blocks_internal_decrypt),
        ("retired key blocks sign", retired_blocks_sign),
        ("retired key blocks pub", retired_blocks_pub),
        ("retired key allows verification", retired_allows_verification),
        ("retired key allows internal decrypt", retired_allows_internal_decrypt),
        ("compromised key blocks crypto", compromised_blocks_crypto),
        ("destroyed key blocks crypto", destroyed_blocks_crypto),
        ("POST /lifecycle/{kid} active to active", lifecycle_rejects_same_state),
        ("POST /lifecycle/{kid} retired to active", lifecycle_rejects_terminal_transition),
        ("POST /lifecycle/{kid} compromised to active", lifecycle_rejects_compromised_to_active),
        ("POST /lifecycle/{kid} destroyed to active", lifecycle_rejects_destroyed_to_active),
    ):
        run_case(rows, name, func)

    def message_without_auth():
        status, _ = client.post(
            f"/message/{key_id}",
            valid_message_request(key_id),
        )
        require_status("POST /message/{sender_kid} without auth", status, 401)

    def message_sender_id_not_hex():
        status, _ = client.post(
            "/message/not-hex",
            valid_message_request(key_id),
            auth=True,
        )
        require_status("POST /message/{sender_kid} sender not hex", status, 400)

    def message_recipient_route_not_found():
        write_remote_routes([])
        status, _ = client.post("/config/reload", {}, auth=True)
        require_status("POST /config/reload empty", status, 200)
        status, _ = client.post(
            f"/message/{key_id}",
            valid_message_request(key_id),
            auth=True,
        )
        require_status("POST /message/{sender_kid} recipient route not found", status, 404)

    def message_recipient_route_disabled():
        write_remote_routes(
            [
                {
                    "remote_kid": key_id,
                    "name": "disabled route",
                    "remote_addr": recipient_host,
                    "allowed_local_kids": [key_id],
                    "status": "disabled",
                }
            ]
        )
        status, _ = client.post("/config/reload", {}, auth=True)
        require_status("POST /config/reload disabled", status, 200)
        status, _ = client.post(
            f"/message/{key_id}",
            valid_message_request(key_id),
            auth=True,
        )
        require_status("POST /message/{sender_kid} recipient route disabled", status, 403)

    def message_sender_not_allowed_for_route():
        write_remote_routes(
            [
                {
                    "remote_kid": key_id,
                    "name": "sender not allowed",
                    "remote_addr": recipient_host,
                    "allowed_local_kids": [disabled_key_id],
                    "status": "active",
                }
            ]
        )
        status, _ = client.post("/config/reload", {}, auth=True)
        require_status("POST /config/reload sender not allowed", status, 200)
        status, _ = client.post(
            f"/message/{key_id}",
            valid_message_request(key_id),
            auth=True,
        )
        require_status("POST /message/{sender_kid} sender not allowed for route", status, 403)

    def message_route_without_public_keys():
        write_remote_routes(
            [
                {
                    "remote_kid": key_id,
                    "name": "no public keys",
                    "remote_addr": recipient_host,
                    "allowed_local_kids": [key_id],
                    "status": "active",
                }
            ]
        )
        status, _ = client.post("/config/reload", {}, auth=True)
        require_status("POST /config/reload no public keys", status, 200)
        status, _ = client.post(
            f"/message/{key_id}",
            valid_message_request(key_id),
            auth=True,
        )
        require_status("POST /message/{sender_kid} route without public keys", status, 403)

    def message_invalid_recipient_kid():
        request = valid_message_request(key_id)
        request["recipient_kid"] = "not-hex"
        status, _ = client.post(
            f"/message/{key_id}",
            request,
            auth=True,
        )
        require_status("POST /message/{sender_kid} invalid recipient kid", status, 400)

    def message_empty_message():
        request = valid_message_request(key_id)
        request["message"] = ""
        status, _ = client.post(
            f"/message/{key_id}",
            request,
            auth=True,
        )
        require_status("POST /message/{sender_kid} empty message", status, 400)

    for name, func in (
        ("POST /message/{sender_kid} without auth", message_without_auth),
        ("POST /message/{sender_kid} sender not hex", message_sender_id_not_hex),
        ("POST /message/{sender_kid} recipient route not found", message_recipient_route_not_found),
        ("POST /message/{sender_kid} recipient route disabled", message_recipient_route_disabled),
        ("POST /message/{sender_kid} sender not allowed for route", message_sender_not_allowed_for_route),
        ("POST /message/{sender_kid} route without public keys", message_route_without_public_keys),
        ("POST /message/{sender_kid} invalid recipient kid", message_invalid_recipient_kid),
        ("POST /message/{sender_kid} empty message", message_empty_message),
    ):
        run_case(rows, name, func)

    def internal_encrypt_without_auth():
        status, _ = client.post(
            f"/message/internal/encrypt/{key_id}",
            {"plaintext": "hello vectis"},
        )
        require_status("POST /message/internal/encrypt/{kid} without auth", status, 401)

    def internal_encrypt_kid_not_hex():
        status, _ = client.post(
            "/message/internal/encrypt/not-hex",
            {"plaintext": "hello vectis"},
            auth=True,
        )
        require_status("POST /message/internal/encrypt/{kid} kid not hex", status, 400)

    def internal_encrypt_empty_plaintext():
        status, _ = client.post(
            f"/message/internal/encrypt/{key_id}",
            {"plaintext": ""},
            auth=True,
        )
        require_status("POST /message/internal/encrypt/{kid} empty plaintext", status, 400)

    def internal_decrypt_without_auth():
        status, _ = client.post("/message/internal/decrypt", internal_message)
        require_status("POST /message/internal/decrypt without auth", status, 401)

    def internal_decrypt_tampered_kid():
        bad = copy.deepcopy(internal_message)
        bad["kid"] = "00" * 32
        status, _ = client.post("/message/internal/decrypt", bad, auth=True)
        require_status("POST /message/internal/decrypt tampered kid", status, 404)

    def internal_decrypt_tampered_ciphertext():
        bad = copy.deepcopy(internal_message)
        bad["message"]["ctx"] = tamper_hex(bad["message"]["ctx"])
        status, body = client.post("/message/internal/decrypt", bad, auth=True)
        require_status("POST /message/internal/decrypt tampered ciphertext", status, 400)
        require(
            body.get("error") == "message authentication failed",
            "tampered ciphertext must fail authentication cleanly",
        )

    def fpe_encrypt_plaintext_outside_alphabet():
        status, body = client.post(
            f"/fpe/encrypt/{key_id}",
            {"profile": "patient-id-decimal-v1", "plaintext": "abc123"},
            auth=True,
        )
        require_status("POST /fpe/encrypt/{kid} plaintext outside alphabet", status, 400)
        require(
            body.get("error") == "plaintext contains character outside fpe profile alphabet",
            "FPE plaintext outside alphabet must fail by alphabet validation",
        )

    def fpe_encrypt_plaintext_too_short():
        status, body = client.post(
            f"/fpe/encrypt/{key_id}",
            {"profile": "patient-id-decimal-v1", "plaintext": "123"},
            auth=True,
        )
        require_status("POST /fpe/encrypt/{kid} plaintext too short", status, 400)
        require(
            body.get("error") == "plaintext length is outside fpe profile bounds",
            "FPE plaintext too short must fail by profile bounds validation",
        )

    def fpe_encrypt_unknown_profile():
        status, body = client.post(
            f"/fpe/encrypt/{key_id}",
            {"profile": "missing-profile", "plaintext": "123456"},
            auth=True,
        )
        require_status("POST /fpe/encrypt/{kid} unknown profile", status, 400)
        require(
            body.get("error") == "fpe profile not found",
            "FPE unknown profile must fail by profile lookup",
        )

    def fpe_decrypt_ciphertext_outside_alphabet():
        status, body = client.post(
            "/fpe/decrypt",
            {"kid": key_id, "profile": "patient-id-decimal-v1", "ciphertext": "abc123"},
            auth=True,
        )
        require_status("POST /fpe/decrypt ciphertext outside alphabet", status, 400)
        require(
            body.get("error") == "ciphertext contains character outside fpe profile alphabet",
            "FPE ciphertext outside alphabet must fail by alphabet validation",
        )

    def fpe_encrypt_batch_plaintext_outside_alphabet():
        status, body = client.post(
            f"/fpe/encrypt/batch/{key_id}",
            {
                "profile": "patient-id-decimal-v1",
                "items": [{"plaintext": "123456"}, {"plaintext": "abc123"}],
            },
            auth=True,
        )
        require_status("POST /fpe/encrypt/batch/{kid} invalid item", status, 400)
        require("items" not in body, "FPE batch error must not return partial items")
        require(
            body.get("error")
            == "batch item 1 failed: plaintext contains character outside fpe profile alphabet",
            "FPE batch invalid item must fail all-or-nothing with item position",
        )

    def fpe_encrypt_batch_empty_items():
        status, body = client.post(
            f"/fpe/encrypt/batch/{key_id}",
            {"profile": "patient-id-decimal-v1", "items": []},
            auth=True,
        )
        require_status("POST /fpe/encrypt/batch/{kid} empty items", status, 400)
        require(
            body.get("error") == "fpe batch items must not be empty",
            "FPE batch empty items must fail",
        )

    def fpe_encrypt_batch_too_many_items():
        status, body = client.post(
            f"/fpe/encrypt/batch/{key_id}",
            {
                "profile": "patient-id-decimal-v1",
                "items": [{"plaintext": "123456"} for _ in range(129)],
            },
            auth=True,
        )
        require_status("POST /fpe/encrypt/batch/{kid} too many items", status, 400)
        require(
            body.get("error") == "fpe batch items exceeds maximum allowed value: 128",
            "FPE batch too many items must fail",
        )

    def fpe_decrypt_batch_ciphertext_outside_alphabet():
        status, body = client.post(
            "/fpe/decrypt/batch",
            {
                "kid": key_id,
                "profile": "patient-id-decimal-v1",
                "items": [{"ciphertext": "123456"}, {"ciphertext": "abc123"}],
            },
            auth=True,
        )
        require_status("POST /fpe/decrypt/batch invalid item", status, 400)
        require("items" not in body, "FPE decrypt batch error must not return partial items")
        require(
            body.get("error")
            == "batch item 1 failed: ciphertext contains character outside fpe profile alphabet",
            "FPE decrypt batch invalid item must fail all-or-nothing with item position",
        )

    def token_encode_unknown_profile():
        status, body = client.post(
            f"/token/encode/{key_id}",
            {"profile": "missing-profile", "plaintext": "123456"},
            auth=True,
        )
        require_status("POST /token/encode/{kid} unknown profile", status, 400)
        require(
            body.get("error") == "tokenization profile not found",
            "token encode unknown profile must fail by profile lookup",
        )

    def token_encode_plaintext_too_long():
        status, body = client.post(
            f"/token/encode/{key_id}",
            {"profile": "patient-id-token-v1", "plaintext": "x" * 1025},
            auth=True,
        )
        require_status("POST /token/encode/{kid} plaintext too long", status, 400)
        require(
            body.get("error") == "plaintext length exceeds tokenization profile maximum",
            "token encode oversized plaintext must fail by tokenization bounds",
        )

    def token_encode_metadata_too_long():
        status, body = client.post(
            f"/token/encode/{key_id}",
            {
                "profile": "patient-id-token-v1",
                "plaintext": "123456",
                "metadata": {"a": "x" * 129},
            },
            auth=True,
        )
        require_status("POST /token/encode/{kid} metadata too long", status, 400)
        require(
            body.get("error") == "metadata exceeds tokenization maximum length",
            "token encode oversized metadata must fail by metadata bounds",
        )

    def token_decode_unknown_profile():
        status, body = client.post(
            "/token/decode",
            {"kid": key_id, "profile": "missing-profile", "token": encoded_token},
            auth=True,
        )
        require_status("POST /token/decode unknown profile", status, 400)
        require(
            body.get("error") == "tokenization profile not found",
            "token decode unknown profile must fail by profile lookup",
        )

    def token_decode_invalid_prefix():
        status, body = client.post(
            "/token/decode",
            {"kid": key_id, "profile": "patient-id-token-v1", "token": "wrong_prefix"},
            auth=True,
        )
        require_status("POST /token/decode invalid prefix", status, 400)
        require(
            body.get("error") == "token prefix does not match tokenization profile",
            "token decode invalid prefix must fail by token validation",
        )

    def token_decode_invalid_encoding():
        status, body = client.post(
            "/token/decode",
            {
                "kid": key_id,
                "profile": "patient-id-token-v1",
                "token": "tok_patient_abc;def",
            },
            auth=True,
        )
        require_status("POST /token/decode invalid encoding", status, 400)
        require(
            body.get("error") == "token contains invalid tokenization encoding",
            "token decode invalid encoding must fail before token lookup",
        )

    def token_decode_wrong_length():
        status, body = client.post(
            "/token/decode",
            {
                "kid": key_id,
                "profile": "patient-id-token-v1",
                "token": "tok_patient_AA",
            },
            auth=True,
        )
        require_status("POST /token/decode wrong length", status, 400)
        require(
            body.get("error") == "token length does not match tokenization profile",
            "token decode wrong length must fail before token lookup",
        )

    def token_decode_not_found():
        status, body = client.post(
            "/token/decode",
            {
                "kid": key_id,
                "profile": "patient-id-token-v1",
                "token": "tok_patient_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            },
            auth=True,
        )
        require_status("POST /token/decode not found", status, 404)
        require(body.get("error") == "token not found", "missing token must be reported as not found")

    _CONFIG["routes"] = []
    _CONFIG["remote_routes"] = []
    _CONFIG["permissions"] = []
    _CONFIG["fpe_profiles"] = [valid_fpe_profile(key_id)]
    _CONFIG["tokenization_profiles"] = [valid_tokenization_profile(key_id)]
    write_config()
    reload_config(client)
    encoded_token = create_valid_encoded_token(client, key_id)

    for name, func in (
        ("POST /message/internal/encrypt/{kid} without auth", internal_encrypt_without_auth),
        ("POST /message/internal/encrypt/{kid} kid not hex", internal_encrypt_kid_not_hex),
        ("POST /message/internal/encrypt/{kid} empty plaintext", internal_encrypt_empty_plaintext),
        ("POST /message/internal/decrypt without auth", internal_decrypt_without_auth),
        ("POST /message/internal/decrypt tampered kid", internal_decrypt_tampered_kid),
        ("POST /message/internal/decrypt tampered ciphertext", internal_decrypt_tampered_ciphertext),
        ("POST /fpe/encrypt/{kid} plaintext outside alphabet", fpe_encrypt_plaintext_outside_alphabet),
        ("POST /fpe/encrypt/{kid} plaintext too short", fpe_encrypt_plaintext_too_short),
        ("POST /fpe/encrypt/{kid} unknown profile", fpe_encrypt_unknown_profile),
        ("POST /fpe/decrypt ciphertext outside alphabet", fpe_decrypt_ciphertext_outside_alphabet),
        (
            "POST /fpe/encrypt/batch/{kid} plaintext outside alphabet",
            fpe_encrypt_batch_plaintext_outside_alphabet,
        ),
        ("POST /fpe/encrypt/batch/{kid} empty items", fpe_encrypt_batch_empty_items),
        ("POST /fpe/encrypt/batch/{kid} too many items", fpe_encrypt_batch_too_many_items),
        (
            "POST /fpe/decrypt/batch ciphertext outside alphabet",
            fpe_decrypt_batch_ciphertext_outside_alphabet,
        ),
        ("POST /token/encode/{kid} unknown profile", token_encode_unknown_profile),
        ("POST /token/encode/{kid} plaintext too long", token_encode_plaintext_too_long),
        ("POST /token/encode/{kid} metadata too long", token_encode_metadata_too_long),
        ("POST /token/decode unknown profile", token_decode_unknown_profile),
        ("POST /token/decode invalid prefix", token_decode_invalid_prefix),
        ("POST /token/decode invalid encoding", token_decode_invalid_encoding),
        ("POST /token/decode wrong length", token_decode_wrong_length),
        ("POST /token/decode not found", token_decode_not_found),
    ):
        run_case(rows, name, func)

    def test_init_without_auth():
        status, _ = client.get("/self-test/init")
        require_status("GET /self-test/init without auth", status, 401)

    def test_id_without_auth():
        status, _ = client.get(f"/self-test/keys/{key_id}")
        require_status("GET /self-test/keys/{kid} without auth", status, 401)

    def test_id_not_hex():
        status, _ = client.get("/self-test/keys/not-hex", auth=True)
        require_status("GET /self-test/keys/{kid} not hex", status, 400)

    def test_id_wrong_length():
        status, _ = client.get("/self-test/keys/abcd", auth=True)
        require_status("GET /self-test/keys/{kid} wrong length", status, 400)

    def pub_id_not_hex():
        status, _ = client.get("/pub/not-hex")
        require_status("GET /pub/{kid} not hex", status, 400)

    def pub_no_private_keys():
        status, response = client.get(f"/pub/{key_id}")
        require_status("GET /pub/{kid}", status, 200)
        body = json.dumps(response)
        require("private_key" not in body, "GET /pub/{kid} must not expose private keys")
        require("kid" not in response, "GET /pub/{kid} must not include kid")

    def sign_without_auth():
        status, _ = client.post(
            f"/sign/{key_id}",
            {"message_hash": {"alg": "SHA-256", "hex": hashlib.sha256(VALID_MESSAGE).hexdigest()}},
        )
        require_status("POST /sign/{kid} without auth", status, 401)

    def sign_id_not_hex():
        status, _ = client.post(
            "/sign/not-hex",
            {"message_hash": {"alg": "SHA-256", "hex": hashlib.sha256(VALID_MESSAGE).hexdigest()}},
            auth=True,
        )
        require_status("POST /sign/{kid} not hex", status, 400)

    def sign_id_not_found():
        missing_id = "00" * 32
        status, _ = client.post(
            f"/sign/{missing_id}",
            {"message_hash": {"alg": "SHA-256", "hex": hashlib.sha256(VALID_MESSAGE).hexdigest()}},
            auth=True,
        )
        require_status("POST /sign/{kid} not found", status, 404)

    def sign_invalid_hash_algorithm():
        status, _ = client.post(
            f"/sign/{key_id}",
            {"message_hash": {"alg": "SHA-999", "hex": hashlib.sha256(VALID_MESSAGE).hexdigest()}},
            auth=True,
        )
        require_status("POST /sign/{kid} invalid hash algorithm", status, 400)

    def sign_hash_wrong_length():
        status, _ = client.post(
            f"/sign/{key_id}",
            {"message_hash": {"alg": "SHA-256", "hex": "00"}},
            auth=True,
        )
        require_status("POST /sign/{kid} hash wrong length", status, 400)

    def sign_hash_not_hex():
        status, _ = client.post(
            f"/sign/{key_id}",
            {"message_hash": {"alg": "SHA-256", "hex": "zz" * 32}},
            auth=True,
        )
        require_status("POST /sign/{kid} hash not hex", status, 400)

    for name, func in (
        ("GET /self-test/init without auth", test_init_without_auth),
        ("GET /self-test/keys/{kid} without auth", test_id_without_auth),
        ("GET /self-test/keys/{kid} not hex", test_id_not_hex),
        ("GET /self-test/keys/{kid} wrong length", test_id_wrong_length),
        ("GET /pub/{kid} not hex", pub_id_not_hex),
        ("GET /pub/{kid} no private keys", pub_no_private_keys),
        ("POST /sign/{kid} without auth", sign_without_auth),
        ("POST /sign/{kid} not hex", sign_id_not_hex),
        ("POST /sign/{kid} not found", sign_id_not_found),
        ("POST /sign/{kid} invalid hash algorithm", sign_invalid_hash_algorithm),
        ("POST /sign/{kid} hash wrong length", sign_hash_wrong_length),
        ("POST /sign/{kid} hash not hex", sign_hash_not_hex),
    ):
        run_case(rows, name, func)

    def verify_missing_payload():
        bad = copy.deepcopy(token)
        bad.pop("payload", None)
        status, _ = client.post("/sign/verification", bad)
        require_status("POST /sign/verification missing payload", status, 400)

    def verify_invalid_version():
        bad = copy.deepcopy(token)
        bad["version"] = "v2"
        status, _ = client.post("/sign/verification", bad)
        require_status("POST /sign/verification invalid version", status, 400)

    def verify_invalid_type():
        bad = copy.deepcopy(token)
        bad["payload"]["type"] = "bad"
        status, _ = client.post("/sign/verification", bad)
        require_status("POST /sign/verification invalid type", status, 400)

    def verify_tampered_message_hash():
        bad = copy.deepcopy(token)
        bad["payload"]["message_hash"]["hex"] = hashlib.sha256(b"tampered").hexdigest()
        status, response = client.post("/sign/verification", bad)
        require_status("POST /sign/verification tampered hash", status, 200)
        require(response.get("valid") == "fail", "tampered hash must fail verification")

    def verify_tampered_kid():
        bad = copy.deepcopy(token)
        bad["payload"]["kid"] = "00" * 32
        status, _ = client.post("/sign/verification", bad)
        require_status("POST /sign/verification tampered kid", status, 404)

    def verify_tampered_info():
        bad = copy.deepcopy(token)
        bad["payload"]["info"] = "tampered"
        status, _ = client.post("/sign/verification", bad)
        require_status("POST /sign/verification tampered info", status, 400)

    def verify_tampered_eddsa_signature():
        bad = copy.deepcopy(token)
        bad["signatures"]["eddsa"]["sig"] = tamper_hex(bad["signatures"]["eddsa"]["sig"])
        status, response = client.post("/sign/verification", bad)
        require_status("POST /sign/verification tampered eddsa signature", status, 200)
        require(response.get("valid") == "fail", "tampered eddsa signature must fail verification")

    def verify_tampered_ml_dsa_signature():
        bad = copy.deepcopy(token)
        signature = ml_dsa_signature_block(bad)
        require(isinstance(signature, dict), "token must include ml-dsa signature")
        signature["sig"] = tamper_hex(signature["sig"])
        status, response = client.post("/sign/verification", bad)
        require_status("POST /sign/verification tampered ml-dsa signature", status, 200)
        require(response.get("valid") == "fail", "tampered ml-dsa signature must fail verification")

    for name, func in (
        ("POST /sign/verification missing payload", verify_missing_payload),
        ("POST /sign/verification invalid version", verify_invalid_version),
        ("POST /sign/verification invalid type", verify_invalid_type),
        ("POST /sign/verification tampered hash", verify_tampered_message_hash),
        ("POST /sign/verification tampered kid", verify_tampered_kid),
        ("POST /sign/verification tampered info", verify_tampered_info),
        ("POST /sign/verification tampered eddsa signature", verify_tampered_eddsa_signature),
        ("POST /sign/verification tampered ml-dsa signature", verify_tampered_ml_dsa_signature),
    ):
        run_case(rows, name, func)

    _CONFIG["routes"] = []
    _CONFIG["remote_routes"] = []
    _CONFIG["permissions"] = []
    _CONFIG["fpe_profiles"] = []
    _CONFIG["tokenization_profiles"] = []
    write_config()
    status, _ = client.post("/config/reload", {}, auth=True)
    require_status("restore config reload", status, 200)
    restore_file(CONFIG_PATH, config_backup)
    restore_file(CONFIG_SIGN_PATH, config_sign_backup)

    print(f"SUMMARY negative passed={len(rows)} failed=0")


if __name__ == "__main__":
    try:
        main()
    except NegativeTestError as err:
        print(f"ERROR: {err}", file=sys.stderr)
        sys.exit(1)
