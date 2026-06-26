#!/usr/bin/env python3
import argparse
import copy
import hashlib
import json
import sys
import urllib.error
import urllib.parse
import urllib.request


DEFAULT_BASE_URL = "http://127.0.0.1:3000"
DEFAULT_APIKEY = "20e446d000498e82b056f54e68216d4c8c9bda089a6812d0aa9d82d59f918018"
VALID_KEY_REQUEST = {
    "tag": "negative-1",
    "profile": "hybrid-performance-v1",
    "eddsa_algorithm": "Ed25519",
    "xecdh_algorithm": "X25519",
    "ml_dsa_variant": "ML-DSA-44",
    "ml_kem_variant": "ML-KEM-512",
}
VALID_MESSAGE = b"Vectis negative workflow test"


class NegativeTestError(Exception):
    pass


class Client:
    def __init__(self, base_url, apikey):
        self.base_url = base_url.rstrip("/")
        self.apikey = apikey

    def get(self, path, auth=False, headers=None):
        request_headers = {}
        if headers:
            request_headers.update(headers)
        if auth:
            request_headers["Authorization"] = self.apikey

        return self._request("GET", path, headers=request_headers)

    def post(self, path, body, auth=False, headers=None):
        request_headers = {"Content-Type": "application/json"}
        if headers:
            request_headers.update(headers)
        if auth:
            request_headers["Authorization"] = self.apikey

        return self._request("POST", path, body=body, headers=request_headers)

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
                return response.status, parse_json(payload)
        except urllib.error.HTTPError as err:
            payload = err.read().decode("utf-8", errors="replace")
            return err.code, parse_json(payload)
        except urllib.error.URLError as err:
            raise NegativeTestError(f"{method} {path} failed: {err}") from err


def parse_json(payload):
    if not payload:
        return {}

    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return {"raw": payload}


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


def create_valid_key(client):
    status, response = client.post("/keys", VALID_KEY_REQUEST, auth=True)
    require_status("create valid key", status, 200)
    key_id = response.get("id")
    require_hex(key_id, "keys.id")
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


def valid_message_request(recipient_host, key_id):
    return {
        "recipient_host": recipient_host,
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


def main():
    parser = argparse.ArgumentParser(description="Run negative HTTP contract tests.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--apikey", default=DEFAULT_APIKEY)
    args = parser.parse_args()

    client = Client(args.base_url, args.apikey)
    recipient_host = host_from_base_url(args.base_url)
    rows = []

    def keys_without_auth():
        status, _ = client.post("/keys", VALID_KEY_REQUEST)
        require_status("POST /keys without auth", status, 401)

    def keys_invalid_auth():
        status, _ = client.post(
            "/keys",
            VALID_KEY_REQUEST,
            headers={"Authorization": "00" * 32},
        )
        require_status("POST /keys invalid auth", status, 401)

    def keys_reload_without_auth():
        status, _ = client.post("/keys/reload", {})
        require_status("POST /keys/reload without auth", status, 401)

    def keys_reload_invalid_auth():
        status, _ = client.post(
            "/keys/reload",
            {},
            headers={"Authorization": "00" * 32},
        )
        require_status("POST /keys/reload invalid auth", status, 401)

    def routes_list_without_auth():
        status, _ = client.get("/routes")
        require_status("GET /routes without auth", status, 401)

    def routes_list_invalid_auth():
        status, _ = client.get("/routes", headers={"Authorization": "00" * 32})
        require_status("GET /routes invalid auth", status, 401)

    def routes_reload_without_auth():
        status, _ = client.post("/routes/reload", {})
        require_status("POST /routes/reload without auth", status, 401)

    def routes_reload_invalid_auth():
        status, _ = client.post(
            "/routes/reload",
            {},
            headers={"Authorization": "00" * 32},
        )
        require_status("POST /routes/reload invalid auth", status, 401)

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

    for name, func in (
        ("POST /keys without auth", keys_without_auth),
        ("POST /keys invalid auth", keys_invalid_auth),
        ("POST /keys/reload without auth", keys_reload_without_auth),
        ("POST /keys/reload invalid auth", keys_reload_invalid_auth),
        ("GET /routes without auth", routes_list_without_auth),
        ("GET /routes invalid auth", routes_list_invalid_auth),
        ("POST /routes/reload without auth", routes_reload_without_auth),
        ("POST /routes/reload invalid auth", routes_reload_invalid_auth),
        ("POST /keys tag not string", keys_tag_not_string),
        ("POST /keys invalid algorithm", keys_invalid_algorithm),
        ("POST /keys invalid profile", keys_invalid_profile),
        ("POST /keys invalid hash algorithm", keys_invalid_hash_algorithm),
        ("POST /keys invalid symmetric algorithm", keys_invalid_symmetric_algorithm),
    ):
        run_case(rows, name, func)

    key_id = create_valid_key(client)
    token = create_valid_token(client, key_id)
    internal_message = create_valid_internal_message(client, key_id)

    def message_without_auth():
        status, _ = client.post(
            f"/message/{key_id}",
            valid_message_request(recipient_host, key_id),
        )
        require_status("POST /message/{id} without auth", status, 401)

    def message_sender_id_not_hex():
        status, _ = client.post(
            "/message/not-hex",
            valid_message_request(recipient_host, key_id),
            auth=True,
        )
        require_status("POST /message/{id} sender not hex", status, 400)

    def message_invalid_recipient_host():
        request = valid_message_request(recipient_host, key_id)
        request["recipient_host"] = "not-a-socket-address"
        status, _ = client.post(
            f"/message/{key_id}",
            request,
            auth=True,
        )
        require_status("POST /message/{id} invalid recipient host", status, 400)

    def message_invalid_recipient_kid():
        request = valid_message_request(recipient_host, key_id)
        request["recipient_kid"] = "not-hex"
        status, _ = client.post(
            f"/message/{key_id}",
            request,
            auth=True,
        )
        require_status("POST /message/{id} invalid recipient kid", status, 400)

    def message_empty_message():
        request = valid_message_request(recipient_host, key_id)
        request["message"] = ""
        status, _ = client.post(
            f"/message/{key_id}",
            request,
            auth=True,
        )
        require_status("POST /message/{id} empty message", status, 400)

    for name, func in (
        ("POST /message/{id} without auth", message_without_auth),
        ("POST /message/{id} sender not hex", message_sender_id_not_hex),
        ("POST /message/{id} invalid recipient host", message_invalid_recipient_host),
        ("POST /message/{id} invalid recipient kid", message_invalid_recipient_kid),
        ("POST /message/{id} empty message", message_empty_message),
    ):
        run_case(rows, name, func)

    def internal_encrypt_without_auth():
        status, _ = client.post(
            f"/message/internal/encrypt/{key_id}",
            {"plaintext": "hello vectis"},
        )
        require_status("POST /message/internal/encrypt/{id} without auth", status, 401)

    def internal_encrypt_kid_not_hex():
        status, _ = client.post(
            "/message/internal/encrypt/not-hex",
            {"plaintext": "hello vectis"},
            auth=True,
        )
        require_status("POST /message/internal/encrypt/{id} kid not hex", status, 400)

    def internal_encrypt_empty_plaintext():
        status, _ = client.post(
            f"/message/internal/encrypt/{key_id}",
            {"plaintext": ""},
            auth=True,
        )
        require_status("POST /message/internal/encrypt/{id} empty plaintext", status, 400)

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
        status, _ = client.post("/message/internal/decrypt", bad, auth=True)
        require_status("POST /message/internal/decrypt tampered ciphertext", status, 500)

    for name, func in (
        ("POST /message/internal/encrypt/{id} without auth", internal_encrypt_without_auth),
        ("POST /message/internal/encrypt/{id} kid not hex", internal_encrypt_kid_not_hex),
        ("POST /message/internal/encrypt/{id} empty plaintext", internal_encrypt_empty_plaintext),
        ("POST /message/internal/decrypt without auth", internal_decrypt_without_auth),
        ("POST /message/internal/decrypt tampered kid", internal_decrypt_tampered_kid),
        ("POST /message/internal/decrypt tampered ciphertext", internal_decrypt_tampered_ciphertext),
    ):
        run_case(rows, name, func)

    def test_init_without_auth():
        status, _ = client.get("/self-test/init")
        require_status("GET /self-test/init without auth", status, 401)

    def test_id_without_auth():
        status, _ = client.get(f"/self-test/keys/{key_id}")
        require_status("GET /self-test/keys/{id} without auth", status, 401)

    def test_id_not_hex():
        status, _ = client.get("/self-test/keys/not-hex", auth=True)
        require_status("GET /self-test/keys/{id} not hex", status, 400)

    def test_id_wrong_length():
        status, _ = client.get("/self-test/keys/abcd", auth=True)
        require_status("GET /self-test/keys/{id} wrong length", status, 400)

    def pub_id_not_hex():
        status, _ = client.get("/pub/not-hex")
        require_status("GET /pub/{id} not hex", status, 400)

    def pub_no_private_keys():
        status, response = client.get(f"/pub/{key_id}")
        require_status("GET /pub/{id}", status, 200)
        body = json.dumps(response)
        require("private_key" not in body, "GET /pub/{id} must not expose private keys")
        require("kid" not in response, "GET /pub/{id} must not include kid")

    def sign_without_auth():
        status, _ = client.post(
            f"/sign/{key_id}",
            {"message_hash": {"alg": "SHA-256", "hex": hashlib.sha256(VALID_MESSAGE).hexdigest()}},
        )
        require_status("POST /sign/{id} without auth", status, 401)

    def sign_id_not_hex():
        status, _ = client.post(
            "/sign/not-hex",
            {"message_hash": {"alg": "SHA-256", "hex": hashlib.sha256(VALID_MESSAGE).hexdigest()}},
            auth=True,
        )
        require_status("POST /sign/{id} not hex", status, 400)

    def sign_id_not_found():
        missing_id = "00" * 32
        status, _ = client.post(
            f"/sign/{missing_id}",
            {"message_hash": {"alg": "SHA-256", "hex": hashlib.sha256(VALID_MESSAGE).hexdigest()}},
            auth=True,
        )
        require_status("POST /sign/{id} not found", status, 404)

    def sign_invalid_hash_algorithm():
        status, _ = client.post(
            f"/sign/{key_id}",
            {"message_hash": {"alg": "SHA-999", "hex": hashlib.sha256(VALID_MESSAGE).hexdigest()}},
            auth=True,
        )
        require_status("POST /sign/{id} invalid hash algorithm", status, 400)

    def sign_hash_wrong_length():
        status, _ = client.post(
            f"/sign/{key_id}",
            {"message_hash": {"alg": "SHA-256", "hex": "00"}},
            auth=True,
        )
        require_status("POST /sign/{id} hash wrong length", status, 400)

    def sign_hash_not_hex():
        status, _ = client.post(
            f"/sign/{key_id}",
            {"message_hash": {"alg": "SHA-256", "hex": "zz" * 32}},
            auth=True,
        )
        require_status("POST /sign/{id} hash not hex", status, 400)

    for name, func in (
        ("GET /self-test/init without auth", test_init_without_auth),
        ("GET /self-test/keys/{id} without auth", test_id_without_auth),
        ("GET /self-test/keys/{id} not hex", test_id_not_hex),
        ("GET /self-test/keys/{id} wrong length", test_id_wrong_length),
        ("GET /pub/{id} not hex", pub_id_not_hex),
        ("GET /pub/{id} no private keys", pub_no_private_keys),
        ("POST /sign/{id} without auth", sign_without_auth),
        ("POST /sign/{id} not hex", sign_id_not_hex),
        ("POST /sign/{id} not found", sign_id_not_found),
        ("POST /sign/{id} invalid hash algorithm", sign_invalid_hash_algorithm),
        ("POST /sign/{id} hash wrong length", sign_hash_wrong_length),
        ("POST /sign/{id} hash not hex", sign_hash_not_hex),
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

    print_section("HTTP negative", rows)
    print(f"SUMMARY negative passed={len(rows)} failed=0")


if __name__ == "__main__":
    try:
        main()
    except NegativeTestError as err:
        print(f"ERROR: {err}", file=sys.stderr)
        sys.exit(1)
