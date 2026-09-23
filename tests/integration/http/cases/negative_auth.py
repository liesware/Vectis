"""Negative HTTP contract cases: authentication and key-input validation.

Each case is a plain function taking ctx. Reads key_id (produced by
the authz bootstrap). No config mutation, no other shared state.
"""

from lib.casekit import CaseSet
from lib.assertions import require_request_id
from .negative_support import VALID_KEY_REQUEST, require, require_status

cases = CaseSet()


@cases('negative.auth.keys-without-auth')
def _(ctx):
    status, _, headers = ctx.http.post_with_headers("/keys", VALID_KEY_REQUEST)
    require_status("POST /keys without auth", status, 401)
    require_request_id(headers)


@cases('negative.auth.keys-invalid-auth')
def _(ctx):
    status, _ = ctx.http.post(
        "/keys",
        VALID_KEY_REQUEST,
        headers={"X-API-Key": "00" * 32},
    )
    require_status("POST /keys invalid auth", status, 401)


@cases('negative.auth.keys-reload-without-auth')
def _(ctx):
    status, _ = ctx.http.post("/keys/reload", {})
    require_status("POST /keys/reload without auth", status, 401)


@cases('negative.auth.keys-reload-invalid-auth')
def _(ctx):
    status, _ = ctx.http.post(
        "/keys/reload",
        {},
        headers={"X-API-Key": "00" * 32},
    )
    require_status("POST /keys/reload invalid auth", status, 401)


@cases('negative.auth.keys-properties-without-auth')
def _(ctx):
    status, _ = ctx.http.get("/keys/properties")
    require_status("GET /keys/properties without auth", status, 401)


@cases('negative.auth.keys-properties-invalid-auth')
def _(ctx):
    status, _ = ctx.http.get("/keys/properties", headers={"X-API-Key": "00" * 32})
    require_status("GET /keys/properties invalid auth", status, 401)


@cases('negative.auth.metrics-without-auth')
def _(ctx):
    status, _ = ctx.http.get("/metrics")
    require_status("GET /metrics without auth", status, 401)


@cases('negative.auth.metrics-invalid-auth')
def _(ctx):
    status, _ = ctx.http.get("/metrics", headers={"X-API-Key": "00" * 32})
    require_status("GET /metrics invalid auth", status, 401)


@cases('negative.auth.key-properties-without-auth')
def _(ctx):
    status, _ = ctx.http.get(f"/keys/properties/{ctx.fixtures.key_id}")
    require_status("GET /keys/properties/{kid} without auth", status, 401)


@cases('negative.auth.key-properties-invalid-kid')
def _(ctx):
    status, _ = ctx.http.get("/keys/properties/not-hex", auth=True)
    require_status("GET /keys/properties/{kid} invalid kid", status, 400)


@cases('negative.auth.lifecycle-without-auth')
def _(ctx):
    status, _ = ctx.http.post(
        f"/lifecycle/{ctx.fixtures.key_id}",
        {"status": "disabled", "reason": "maintenance"},
    )
    require_status("POST /lifecycle/{kid} without auth", status, 401)


@cases('negative.auth.lifecycle-invalid-kid')
def _(ctx):
    status, _ = ctx.http.post(
        "/lifecycle/not-hex",
        {"status": "disabled", "reason": "maintenance"},
        auth=True,
    )
    require_status("POST /lifecycle/{kid} invalid kid", status, 400)


@cases('negative.auth.lifecycle-status-not-string')
def _(ctx):
    status, _ = ctx.http.post(
        f"/lifecycle/{ctx.fixtures.key_id}",
        {"status": 1, "reason": "maintenance"},
        auth=True,
    )
    require_status("POST /lifecycle/{kid} status not string", status, 400)


@cases('negative.auth.lifecycle-invalid-status')
def _(ctx):
    status, _ = ctx.http.post(
        f"/lifecycle/{ctx.fixtures.key_id}",
        {"status": "paused", "reason": "maintenance"},
        auth=True,
    )
    require_status("POST /lifecycle/{kid} invalid status", status, 400)


@cases('negative.auth.lifecycle-reason-not-string')
def _(ctx):
    status, _ = ctx.http.post(
        f"/lifecycle/{ctx.fixtures.key_id}",
        {"status": "disabled", "reason": 1},
        auth=True,
    )
    require_status("POST /lifecycle/{kid} reason not string", status, 400)


@cases('negative.auth.routes-list-without-auth')
def _(ctx):
    status, _ = ctx.http.get("/routes")
    require_status("GET /routes without auth", status, 401)


@cases('negative.auth.routes-list-invalid-auth')
def _(ctx):
    status, _ = ctx.http.get("/routes", headers={"X-API-Key": "00" * 32})
    require_status("GET /routes invalid auth", status, 401)


@cases('negative.auth.config-reload-without-auth')
def _(ctx):
    status, _ = ctx.http.post("/config/reload", {})
    require_status("POST /config/reload without auth", status, 401)


@cases('negative.auth.config-reload-invalid-auth')
def _(ctx):
    status, _ = ctx.http.post(
        "/config/reload",
        {},
        headers={"X-API-Key": "00" * 32},
    )
    require_status("POST /config/reload invalid auth", status, 401)


@cases('negative.auth.remote-routes-list-without-auth')
def _(ctx):
    status, _ = ctx.http.get("/remote-routes")
    require_status("GET /remote-routes without auth", status, 401)


@cases('negative.auth.remote-routes-list-invalid-auth')
def _(ctx):
    status, _ = ctx.http.get("/remote-routes", headers={"X-API-Key": "00" * 32})
    require_status("GET /remote-routes invalid auth", status, 401)


@cases('negative.auth.permissions-list-without-auth')
def _(ctx):
    status, _ = ctx.http.get("/permissions")
    require_status("GET /permissions without auth", status, 401)


@cases('negative.auth.permissions-list-invalid-auth')
def _(ctx):
    status, _ = ctx.http.get("/permissions", headers={"X-API-Key": "00" * 32})
    require_status("GET /permissions invalid auth", status, 401)


@cases('negative.auth.fpe-encrypt-without-auth')
def _(ctx):
    status, _, headers = ctx.http.post_with_headers(
        f"/fpe/encrypt/{ctx.fixtures.key_id}",
        {"ref": "fpe-auth", "profile": "patient-id-decimal-v1", "plaintext": "123456"},
    )
    require_status("POST /fpe/encrypt/{kid} without auth", status, 401)
    require_request_id(headers)


@cases('negative.auth.fpe-decrypt-without-auth')
def _(ctx):
    status, _ = ctx.http.post(
        "/fpe/decrypt",
        {
            "ref": "fpe-auth",
            "kid": ctx.fixtures.key_id,
            "profile": "patient-id-decimal-v1",
            "ciphertext": "123456",
        },
    )
    require_status("POST /fpe/decrypt without auth", status, 401)


@cases('negative.auth.fpe-encrypt-invalid-auth')
def _(ctx):
    status, _ = ctx.http.post(
        f"/fpe/encrypt/{ctx.fixtures.key_id}",
        {"ref": "fpe-auth", "profile": "patient-id-decimal-v1", "plaintext": "123456"},
        headers={"X-API-Key": "00" * 32},
    )
    require_status("POST /fpe/encrypt/{kid} invalid auth", status, 401)


@cases('negative.auth.fpe-decrypt-invalid-auth')
def _(ctx):
    status, _ = ctx.http.post(
        "/fpe/decrypt",
        {
            "ref": "fpe-auth",
            "kid": ctx.fixtures.key_id,
            "profile": "patient-id-decimal-v1",
            "ciphertext": "123456",
        },
        headers={"X-API-Key": "00" * 32},
    )
    require_status("POST /fpe/decrypt invalid auth", status, 401)


@cases('negative.auth.keys-tag-not-string')
def _(ctx):
    request = dict(VALID_KEY_REQUEST)
    request["tag"] = 1
    status, _ = ctx.http.post("/keys", request, auth=True)
    require_status("POST /keys tag not string", status, 400)


@cases('negative.auth.keys-invalid-algorithm')
def _(ctx):
    request = dict(VALID_KEY_REQUEST)
    request["eddsa_algorithm"] = "Ed25519-BAD"
    status, _ = ctx.http.post("/keys", request, auth=True)
    require_status("POST /keys invalid algorithm", status, 400)


@cases('negative.auth.keys-invalid-profile')
def _(ctx):
    request = dict(VALID_KEY_REQUEST)
    request["profile"] = "hybrid-imaginary-v1"
    status, _ = ctx.http.post("/keys", request, auth=True)
    require_status("POST /keys invalid profile", status, 400)


@cases('negative.auth.keys-invalid-hash-algorithm')
def _(ctx):
    request = dict(VALID_KEY_REQUEST)
    request["hash_algorithm"] = "SHA-999"
    status, _ = ctx.http.post("/keys", request, auth=True)
    require_status("POST /keys invalid hash algorithm", status, 400)


@cases('negative.auth.keys-invalid-symmetric-algorithm')
def _(ctx):
    request = dict(VALID_KEY_REQUEST)
    request["symmetric_algorithm"] = "AES-999/GCM"
    status, _ = ctx.http.post("/keys", request, auth=True)
    require_status("POST /keys invalid symmetric algorithm", status, 400)


@cases('negative.auth.keys-tag-with-aad-delimiters')
def _(ctx):
    for bad_tag in ("has;semicolon", "has=equals"):
        request = dict(VALID_KEY_REQUEST)
        request["tag"] = bad_tag
        status, _ = ctx.http.post("/keys", request, auth=True)
        require_status(f"POST /keys tag {bad_tag!r}", status, 400)


@cases('negative.auth.keys-control-char-field-name')
def _(ctx):
    request = dict(VALID_KEY_REQUEST)
    request["bad    field"] = "x"
    status, body = ctx.http.post("/keys", request, auth=True)
    require_status("POST /keys control-char field name", status, 400)
    error = body.get("error", "")
    require(
        not any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in error),
        "error message must not contain control characters",
    )


CASES = cases.tuple()
