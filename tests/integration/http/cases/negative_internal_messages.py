"""Negative HTTP contract cases: internal message encrypt/decrypt input validation.

Each case is a plain function taking ctx; reads shared state from ctx.fixtures.
"""

import copy

from lib.casekit import CaseSet
from .negative_support import (
    create_valid_encoded_token,
    require,
    require_status,
    require_unknown_field_error,
    tamper_hex,
    valid_commitment_profile,
    valid_fpe_profile,
    valid_mac_profile,
    valid_masking_profile,
    valid_sharing_profile,
    valid_tokenization_profile,
)

cases = CaseSet()


@cases("negative.operations.bootstrap", weight=0)
def _(ctx):
    fx = ctx.fixtures
    ctx.config_data["routes"] = []
    ctx.config_data["remote_routes"] = []
    ctx.config_data["permissions"] = []
    ctx.config_data["fpe_profiles"] = [valid_fpe_profile(fx.key_id)]
    ctx.config_data["tokenization_profiles"] = [valid_tokenization_profile(fx.key_id)]
    ctx.config_data["mac_profiles"] = [valid_mac_profile(fx.key_id)]
    ctx.config_data["masking_profiles"] = [valid_masking_profile(fx.key_id)]
    ctx.config_data["commitment_profiles"] = [valid_commitment_profile(fx.key_id)]
    ctx.config_data["sharing_profiles"] = [valid_sharing_profile(fx.key_id)]
    ctx.write_config()
    ctx.reload_config()
    fx.encoded_token = create_valid_encoded_token(ctx.http, fx.key_id)


@cases('negative.operations.internal-encrypt-without-auth')
def _(ctx):
    status, _ = ctx.http.post(
        f"/message/internal/encrypt/{ctx.fixtures.key_id}",
        {"plaintext": "hello vectis"},
    )
    require_status("POST /message/internal/encrypt/{kid} without auth", status, 401)


@cases('negative.operations.internal-encrypt-kid-not-hex')
def _(ctx):
    status, _ = ctx.http.post(
        "/message/internal/encrypt/not-hex",
        {"plaintext": "hello vectis"},
        auth=True,
    )
    require_status("POST /message/internal/encrypt/{kid} kid not hex", status, 400)


@cases('negative.operations.internal-encrypt-empty-plaintext')
def _(ctx):
    status, _ = ctx.http.post(
        f"/message/internal/encrypt/{ctx.fixtures.key_id}",
        {"plaintext": ""},
        auth=True,
    )
    require_status("POST /message/internal/encrypt/{kid} empty plaintext", status, 400)


@cases('negative.operations.internal-encrypt-unknown-field')
def _(ctx):
    status, body = ctx.http.post(
        f"/message/internal/encrypt/{ctx.fixtures.key_id}",
        {"plaintext": "hello", "sorpresa": True},
        auth=True,
    )
    require_status("POST /message/internal/encrypt/{kid} unknown field", status, 400)
    require_unknown_field_error("POST /message/internal/encrypt/{kid} unknown field", body, "sorpresa")


@cases('negative.operations.internal-decrypt-without-auth')
def _(ctx):
    status, _ = ctx.http.post("/message/internal/decrypt", ctx.fixtures.internal_message)
    require_status("POST /message/internal/decrypt without auth", status, 401)


@cases('negative.operations.internal-decrypt-tampered-kid')
def _(ctx):
    bad = copy.deepcopy(ctx.fixtures.internal_message)
    bad["kid"] = "00" * 32
    status, _ = ctx.http.post("/message/internal/decrypt", bad, auth=True)
    require_status("POST /message/internal/decrypt tampered kid", status, 404)


@cases('negative.operations.internal-decrypt-tampered-ciphertext')
def _(ctx):
    bad = copy.deepcopy(ctx.fixtures.internal_message)
    bad["message"]["ctx"] = tamper_hex(bad["message"]["ctx"])
    status, body = ctx.http.post("/message/internal/decrypt", bad, auth=True)
    require_status("POST /message/internal/decrypt tampered ciphertext", status, 400)
    require(
        body.get("error") == "message authentication failed",
        "tampered ciphertext must fail authentication cleanly",
    )


CASES = cases.tuple()
