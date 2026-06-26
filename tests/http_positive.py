#!/usr/bin/env python3
import argparse
import hashlib
import http.server
import json
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request


DEFAULT_BASE_URL = "http://127.0.0.1:3000"
DEFAULT_FINAL_APP_ADDR = "localhost:3999"
DEFAULT_APIKEY = "20e446d000498e82b056f54e68216d4c8c9bda089a6812d0aa9d82d59f918018"
INTERNAL_KEYS_KID_HEX_LEN = 64
MESSAGE = "The things you own end up owning you."

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
            headers["Authorization"] = self.apikey

        return self._request("GET", path, headers=headers)

    def post(self, path, body, auth=False):
        headers = {"Content-Type": "application/json"}
        if auth:
            headers["Authorization"] = self.apikey

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


def send_message(client, message_number, sender_key_id, recipient_host, recipient_key_id, case):
    before = len(FinalAppHandler.deliveries)
    plaintext_message = MESSAGE + str(message_number)
    response = client.post(
        f"/message/{sender_key_id}",
        {
            "recipient_host": recipient_host,
            "recipient_kid": recipient_key_id,
            "message": plaintext_message,
        },
        auth=True,
    )
    validate_message_response(response, case)
    require(
        len(FinalAppHandler.deliveries) == before + 1,
        "final app must receive exactly one delivery",
    )
    delivery = FinalAppHandler.deliveries[-1]
    validate_final_app_delivery(delivery, sender_key_id, case)
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
    parser.add_argument("--apikey", default=DEFAULT_APIKEY)
    parser.add_argument("--final-app-addr", default=DEFAULT_FINAL_APP_ADDR)
    args = parser.parse_args()

    final_app = start_final_app(args.final_app_addr)
    client = Client(args.base_url, args.apikey)
    recipient_host = host_from_base_url(args.base_url)
    message = MESSAGE.encode("utf-8")

    validate_health(client)
    print("Health: OK\n")
    passed_count = 1

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
    validate_keys_list(
        client.post("/keys/reload", {}, auth=True),
        [key_id for key_id, _ in created],
    )
    print("Reload keys: OK\n")
    passed_count += 1
    validate_routes_list(client.get("/routes", auth=True))
    print("List routes: OK\n")
    passed_count += 1
    validate_routes_list(client.post("/routes/reload", {}, auth=True))
    print("Reload routes: OK\n")
    passed_count += 1

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
            recipient_host,
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
    final_app.shutdown()


if __name__ == "__main__":
    try:
        main()
    except WorkflowError as err:
        print(f"ERROR: {err}", file=sys.stderr)
        sys.exit(1)
