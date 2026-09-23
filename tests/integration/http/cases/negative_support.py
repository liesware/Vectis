"""Shared mechanisms for the negative HTTP contract cases.

Reusable domain constants and validators imported by the negative_* case modules.
Config writing/reloading now lives on HttpTestContext (ctx.*), so this module no
longer carries the old global-config plumbing.
"""

import hashlib
import subprocess
from pathlib import Path

from lib.assertions import require, require_hex
from lib.fixtures import create_api_key_pair


VALID_KEY_REQUEST = {
    "tag": "negative-1",
    "profile": "hybrid-performance-v1",
    "eddsa_algorithm": "Ed25519",
    "xecdh_algorithm": "X25519",
    "ml_dsa_variant": "ML-DSA-44",
    "ml_kem_variant": "ML-KEM-512",
}

VALID_MESSAGE = b"Vectis negative workflow test"

CONFIG_SIGN_PATH = Path("config_sign.json")

HTTP_MAX_SIZE = 2 * 1024 * 1024

OVERSIZE_ERROR = {"error": "request body exceeds maximum allowed size"}

CONTENT_TYPE_ERROR = {"error": "request content type must be application/json"}

def require_status(name, actual, expected):
    require(
        actual == expected,
        f"{name} expected HTTP {expected}, got HTTP {actual}",
    )

def json_body_with_size(size):
    prefix = b'{"padding":"'
    suffix = b'"}'
    require(size >= len(prefix) + len(suffix), "requested JSON body size is too small")
    return prefix + (b"a" * (size - len(prefix) - len(suffix))) + suffix

def require_unknown_field_error(name, body, field):
    error = body.get("error")
    require(isinstance(error, str), f"{name} must return error string")
    require("unknown field" in error, f"{name} must mention unknown field, got {error!r}")
    require(field in error, f"{name} must mention {field!r}, got {error!r}")

def ml_dsa_signature_block(token):
    return token.get("signatures", {}).get("ml-dsa") or token.get("signatures", {}).get("ml_dsa")

def tamper_hex(value):
    prefix = "00" if not value.startswith("00") else "ff"
    return prefix + value[2:]

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
    require(token.get("kid") == key_id, "valid token must include the signing kid")
    signature = token.get("signature")
    require(isinstance(signature, str), "valid token must include a signature string")
    segments = signature.split(".")
    require(
        len(segments) == 4 and all(segments),
        "valid token signature must have four non-empty segments",
    )
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
        "kid": key_id,
        "token_prefix": "tok_patient",
        "token_len": 32,
        "max_plaintext_len": 1024,
        "one_time": False,
    }

def valid_mac_profile(key_id):
    return {
        "name": "pan-blind-index-v1",
        "kid": key_id,
        "context": "tenant=mx;field=pan;purpose=blind-index;version=1",
    }

def valid_masking_profile(key_id):
    return {
        "name": "pan-display-v1",
        "kid": key_id,
        "visible_first": 0,
        "visible_last": 4,
        "mask_char": "*",
        "min_len": 12,
        "max_len": 19,
    }

def valid_commitment_profile(key_id):
    return {
        "name": "pan-commitment-v1",
        "kid": key_id,
        "context": "tenant=mx;field=pan;purpose=commitment;version=1",
        "max_plaintext_len": 128,
        "opening_len": 32,
    }

def valid_sharing_profile(key_id):
    return {
        "name": "customer-secret-3of5-v1",
        "kid": key_id,
        "threshold": 3,
        "shares": 5,
        "max_secret_len": 4096,
        "context": "tenant=mx;purpose=customer-secret-sharing;version=1",
    }

def create_valid_shares(client, key_id):
    status, response = client.post(
        f"/shares/split/{key_id}",
        {"profile": "customer-secret-3of5-v1", "plaintext": "customer-secret-value"},
        auth=True,
    )
    require_status("split valid shares", status, 200)
    return response["shares"]

def create_valid_encoded_token(client, key_id):
    status, response = client.post(
        f"/token/encode/{key_id}",
        {
            "ref": "token-valid",
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
