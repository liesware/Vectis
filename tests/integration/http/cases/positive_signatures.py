"""Positive HTTP helpers for one capability domain."""

import base64
import hashlib
import json

from lib.assertions import require
from lib.client import StatusClient
from lib.positive_support import MESSAGE
from lib.casekit import CaseSet
from lib.results import CaseResult

cases = CaseSet()
from lib.compact_signature import mutate_compact_signature_segment
from .positive_output import print_section


HASH_CASES = {
    "SHA-256": lambda data: hashlib.sha256(data).hexdigest(),
    "SHA-384": lambda data: hashlib.sha384(data).hexdigest(),
    "SHA-512": lambda data: hashlib.sha512(data).hexdigest(),
}


def sign_key(client, key_id, hash_alg, message_hash_hex):
    body = {
        "message_hash": {
            "alg": hash_alg,
            "hex": message_hash_hex,
        }
    }
    token = client.post(f"/sign/{key_id}", body, auth=True)
    require(token.get("kid") == key_id, "sign.kid mismatch")
    signature = token.get("signature")
    require(isinstance(signature, str), "sign.signature must be a string")
    parts = signature.split(".")
    require(len(parts) == 4 and all(parts), "sign.signature must have four non-empty segments")

    payload_segment = parts[1]
    payload = json.loads(
        base64.urlsafe_b64decode(payload_segment + "=" * (-len(payload_segment) % 4))
    )
    require(payload.get("kid") == key_id, "sign.payload.kid mismatch")
    require(payload.get("message_hash") == body["message_hash"], "sign.payload.message_hash mismatch")

    return token


def verify_signature(client, token):
    response = client.post("/sign/verification", token)
    require(response.get("valid") == "ok", "verification.valid must be ok")
    status = response.get("status")
    require(isinstance(status, dict), "verification.status must be an object")
    require(status.get("eddsa") == "ok", "verification.status.eddsa must be ok")
    require(status.get("ml-dsa") == "ok", "verification.status.ml-dsa must be ok")


def compact_signature_integrity_round_trip(client, key_id):
    expected = {
        "header": (0, "fail", "not_checked"),
        "payload": (1, "fail", "not_checked"),
        "eddsa": (2, "ok", "fail"),
        "ml-dsa": (3, "fail", "not_checked"),
    }
    status_client = StatusClient(client.base_url, client.apikey)
    for label, (segment, expected_ml_dsa, expected_eddsa) in expected.items():
        token = sign_key(client, key_id, "BLAKE2b(256)", "cd" * 32)
        mutated = dict(token, signature=mutate_compact_signature_segment(token["signature"], segment))
        status, response = status_client.post("/sign/verification", mutated)
        require(status == 200, f"tampered compact {label} must return 200")
        require(response.get("valid") == "fail", f"tampered compact {label} must fail")
        verification = response.get("status")
        require(isinstance(verification, dict), f"tampered compact {label} status must be object")
        require(verification.get("ml-dsa") == expected_ml_dsa, f"tampered compact {label} ML-DSA state mismatch")
        require(verification.get("eddsa") == expected_eddsa, f"tampered compact {label} EdDSA state mismatch")


@cases('positive.signatures')
def run_signatures(ctx):
    client = ctx.client
    created = ctx.artifacts["positive.keys"]
    message = MESSAGE.encode("utf-8")

    sign_rows = []
    verify_rows = []
    for key_id, case in created:
        for hash_alg, digest in HASH_CASES.items():
            token = sign_key(client, key_id, hash_alg, digest(message))
            sign_rows.append((f"{key_id} {hash_alg}", "OK"))

            verify_signature(client, token)
            verify_rows.append((f"{key_id} {hash_alg}", "OK"))

    compact_signature_integrity_round_trip(client, created[0][0])
    verify_rows.append((f"{created[0][0]} compact segment integrity", "OK"))

    print_section("sign", sign_rows)
    print_section("sign verification", verify_rows)
    return CaseResult(passed=len(sign_rows) + len(verify_rows))


CASES = cases.tuple()
