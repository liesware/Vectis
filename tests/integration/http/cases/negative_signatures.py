"""Negative HTTP contract cases: signing and verification validation.

Reads ctx.fixtures.key_id and ctx.fixtures.token (a valid signed token produced
by the lifecycle bootstrap). Each case is a plain function taking ctx.
"""

import copy
import hashlib
import json

from lib.casekit import CaseSet
from .negative_support import (
    VALID_MESSAGE,
    ml_dsa_signature_block,
    require,
    require_status,
    require_unknown_field_error,
)

cases = CaseSet()


def tampered_signature(ctx, index):
    bad = copy.deepcopy(ctx.fixtures.token)
    segments = bad["signature"].split(".")
    first = segments[index][0]
    segments[index] = ("A" if first != "A" else "B") + segments[index][1:]
    bad["signature"] = ".".join(segments)
    status, response = ctx.http.post("/sign/verification", bad)
    return status, response


@cases('negative.signatures.test-init-without-auth')
def _(ctx):
    status, _ = ctx.http.get("/self-test/init")
    require_status("GET /self-test/init without auth", status, 401)


@cases('negative.signatures.test-id-without-auth')
def _(ctx):
    status, _ = ctx.http.get(f"/self-test/keys/{ctx.fixtures.key_id}")
    require_status("GET /self-test/keys/{kid} without auth", status, 401)


@cases('negative.signatures.test-id-not-hex')
def _(ctx):
    status, _ = ctx.http.get("/self-test/keys/not-hex", auth=True)
    require_status("GET /self-test/keys/{kid} not hex", status, 400)


@cases('negative.signatures.test-id-wrong-length')
def _(ctx):
    status, _ = ctx.http.get("/self-test/keys/abcd", auth=True)
    require_status("GET /self-test/keys/{kid} wrong length", status, 400)


@cases('negative.signatures.pub-id-not-hex')
def _(ctx):
    status, _ = ctx.http.get("/pub/not-hex")
    require_status("GET /pub/{kid} not hex", status, 400)


@cases('negative.signatures.pub-no-private-keys')
def _(ctx):
    status, response = ctx.http.get(f"/pub/{ctx.fixtures.key_id}")
    require_status("GET /pub/{kid}", status, 200)
    body = json.dumps(response)
    require("private_key" not in body, "GET /pub/{kid} must not expose private keys")
    require("kid" not in response, "GET /pub/{kid} must not include kid")


@cases('negative.signatures.sign-without-auth')
def _(ctx):
    status, _ = ctx.http.post(
        f"/sign/{ctx.fixtures.key_id}",
        {"message_hash": {"alg": "SHA-256", "hex": hashlib.sha256(VALID_MESSAGE).hexdigest()}},
    )
    require_status("POST /sign/{kid} without auth", status, 401)


@cases('negative.signatures.sign-id-not-hex')
def _(ctx):
    status, _ = ctx.http.post(
        "/sign/not-hex",
        {"message_hash": {"alg": "SHA-256", "hex": hashlib.sha256(VALID_MESSAGE).hexdigest()}},
        auth=True,
    )
    require_status("POST /sign/{kid} not hex", status, 400)


@cases('negative.signatures.sign-id-not-found')
def _(ctx):
    missing_id = "00" * 32
    status, _ = ctx.http.post(
        f"/sign/{missing_id}",
        {"message_hash": {"alg": "SHA-256", "hex": hashlib.sha256(VALID_MESSAGE).hexdigest()}},
        auth=True,
    )
    require_status("POST /sign/{kid} not found", status, 404)


@cases('negative.signatures.sign-invalid-hash-algorithm')
def _(ctx):
    status, _ = ctx.http.post(
        f"/sign/{ctx.fixtures.key_id}",
        {"message_hash": {"alg": "SHA-999", "hex": hashlib.sha256(VALID_MESSAGE).hexdigest()}},
        auth=True,
    )
    require_status("POST /sign/{kid} invalid hash algorithm", status, 400)


@cases('negative.signatures.sign-hash-wrong-length')
def _(ctx):
    status, _ = ctx.http.post(
        f"/sign/{ctx.fixtures.key_id}",
        {"message_hash": {"alg": "SHA-256", "hex": "00"}},
        auth=True,
    )
    require_status("POST /sign/{kid} hash wrong length", status, 400)


@cases('negative.signatures.sign-hash-not-hex')
def _(ctx):
    status, _ = ctx.http.post(
        f"/sign/{ctx.fixtures.key_id}",
        {"message_hash": {"alg": "SHA-256", "hex": "zz" * 32}},
        auth=True,
    )
    require_status("POST /sign/{kid} hash not hex", status, 400)


@cases('negative.signatures.sign-unknown-field')
def _(ctx):
    status, body = ctx.http.post(
        f"/sign/{ctx.fixtures.key_id}",
        {
            "message_hash": {"alg": "SHA-256", "hex": hashlib.sha256(VALID_MESSAGE).hexdigest()},
            "sorpresa": True,
        },
        auth=True,
    )
    require_status("POST /sign/{kid} unknown field", status, 400)
    require_unknown_field_error("POST /sign/{kid} unknown field", body, "sorpresa")


@cases('negative.signatures.verify-missing-signature')
def _(ctx):
    bad = copy.deepcopy(ctx.fixtures.token)
    bad.pop("signature", None)
    status, _ = ctx.http.post("/sign/verification", bad)
    require_status("POST /sign/verification missing signature", status, 400)


@cases('negative.signatures.verify-missing-kid')
def _(ctx):
    bad = copy.deepcopy(ctx.fixtures.token)
    bad.pop("kid", None)
    status, _ = ctx.http.post("/sign/verification", bad)
    require_status("POST /sign/verification missing kid", status, 400)


@cases('negative.signatures.verify-unknown-field')
def _(ctx):
    bad = copy.deepcopy(ctx.fixtures.token)
    bad["sorpresa"] = True
    status, body = ctx.http.post("/sign/verification", bad)
    require_status("POST /sign/verification unknown field", status, 400)
    require_unknown_field_error("POST /sign/verification unknown field", body, "sorpresa")


@cases('negative.signatures.verify-tampered-kid')
def _(ctx):
    bad = copy.deepcopy(ctx.fixtures.token)
    bad["kid"] = "00" * 32
    status, _ = ctx.http.post("/sign/verification", bad)
    require_status("POST /sign/verification tampered kid", status, 404)


@cases('negative.signatures.verify-tampered-header-segment')
def _(ctx):
    status, response = tampered_signature(ctx, 0)
    require_status("POST /sign/verification tampered header segment", status, 200)
    require(response.get("valid") == "fail", "tampered header must fail verification")
    require(response.get("status", {}).get("ml-dsa") == "fail", "tampered header must break the signed input")


@cases('negative.signatures.verify-tampered-payload-segment')
def _(ctx):
    status, response = tampered_signature(ctx, 1)
    require_status("POST /sign/verification tampered payload segment", status, 200)
    require(response.get("valid") == "fail", "tampered payload must fail verification")
    require(response.get("status", {}).get("ml-dsa") == "fail", "tampered payload must break the signed input")


@cases('negative.signatures.verify-tampered-eddsa-signature')
def _(ctx):
    status, response = tampered_signature(ctx, 2)
    require_status("POST /sign/verification tampered eddsa signature", status, 200)
    require(response.get("valid") == "fail", "tampered eddsa signature must fail verification")
    require(response.get("status", {}).get("ml-dsa") == "ok", "ML-DSA must be checked first")


@cases('negative.signatures.verify-tampered-ml-dsa-signature')
def _(ctx):
    status, response = tampered_signature(ctx, 3)
    require_status("POST /sign/verification tampered ml-dsa signature", status, 200)
    require(response.get("valid") == "fail", "tampered ml-dsa signature must fail verification")
    require(response.get("status", {}).get("eddsa") == "not_checked", "EdDSA must not run after ML-DSA failure")


CASES = cases.tuple()
