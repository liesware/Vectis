"""Negative HTTP contract cases: key lifecycle enforcement.

Bootstrap (weight 0) creates the lifecycle keys/tokens/messages the cases drive
through disabled/retired/compromised/destroyed states, storing them on
ctx.fixtures. Reads ctx.fixtures.key_id (from the authz bootstrap).
"""

import hashlib

from lib.casekit import CaseSet
from .negative_support import (
    VALID_MESSAGE,
    create_valid_internal_message,
    create_valid_key,
    create_valid_token,
    require,
    require_status,
    valid_fpe_profile,
)

cases = CaseSet()


def set_lifecycle(ctx, kid, status):
    response_status, _ = ctx.http.post(
        f"/lifecycle/{kid}",
        {"status": status, "reason": f"negative test {status}"},
        auth=True,
    )
    require_status(f"set lifecycle {status}", response_status, 200)


def assert_blocks_sign(ctx, kid, label):
    status, _ = ctx.http.post(
        f"/sign/{kid}",
        {"message_hash": {"alg": "SHA-256", "hex": hashlib.sha256(VALID_MESSAGE).hexdigest()}},
        auth=True,
    )
    require_status(f"{label} key blocks sign", status, 403)


def assert_blocks_pub(ctx, kid, label):
    status, _ = ctx.http.get(f"/pub/{kid}")
    require_status(f"{label} key blocks pub", status, 403)


def assert_blocks_internal_decrypt(ctx, message, label):
    status, _ = ctx.http.post("/message/internal/decrypt", message, auth=True)
    require_status(f"{label} key blocks internal decrypt", status, 403)


def assert_blocks_verification(ctx, token_value, label):
    status, _ = ctx.http.post("/sign/verification", token_value)
    require_status(f"{label} key blocks verification", status, 403)


@cases("negative.lifecycle.bootstrap", weight=0)
def _(ctx):
    fx = ctx.fixtures
    ctx.config_data["fpe_profiles"] = [valid_fpe_profile(fx.key_id)]
    ctx.write_config()
    ctx.reload_config()
    fx.token = create_valid_token(ctx.http, fx.key_id)
    fx.internal_message = create_valid_internal_message(ctx.http, fx.key_id)
    fx.disabled_key = create_valid_key(ctx.http)
    fx.disabled_internal_message = create_valid_internal_message(ctx.http, fx.disabled_key)
    fx.retired_key = create_valid_key(ctx.http)
    fx.retired_token = create_valid_token(ctx.http, fx.retired_key)
    fx.retired_internal_message = create_valid_internal_message(ctx.http, fx.retired_key)
    fx.compromised_key = create_valid_key(ctx.http)
    fx.compromised_token = create_valid_token(ctx.http, fx.compromised_key)
    fx.compromised_internal_message = create_valid_internal_message(ctx.http, fx.compromised_key)
    fx.destroyed_key = create_valid_key(ctx.http)
    fx.destroyed_token = create_valid_token(ctx.http, fx.destroyed_key)
    fx.destroyed_internal_message = create_valid_internal_message(ctx.http, fx.destroyed_key)


@cases('negative.lifecycle.disabled-blocks-sign')
def _(ctx):
    set_lifecycle(ctx, ctx.fixtures.disabled_key, "disabled")
    status, _ = ctx.http.post(
        f"/sign/{ctx.fixtures.disabled_key}",
        {
            "message_hash": {
                "alg": "SHA-256",
                "hex": hashlib.sha256(VALID_MESSAGE).hexdigest(),
            }
        },
        auth=True,
    )
    require_status("disabled key blocks sign", status, 403)


@cases('negative.lifecycle.disabled-blocks-pub')
def _(ctx):
    status, _ = ctx.http.get(f"/pub/{ctx.fixtures.disabled_key}")
    require_status("disabled key blocks pub", status, 403)


@cases('negative.lifecycle.disabled-blocks-internal-decrypt')
def _(ctx):
    status, _ = ctx.http.post("/message/internal/decrypt", ctx.fixtures.disabled_internal_message, auth=True)
    require_status("disabled key blocks internal decrypt", status, 403)


@cases('negative.lifecycle.retired-blocks-sign')
def _(ctx):
    set_lifecycle(ctx, ctx.fixtures.retired_key, "retired")
    assert_blocks_sign(ctx, ctx.fixtures.retired_key, "retired")


@cases('negative.lifecycle.retired-blocks-pub')
def _(ctx):
    assert_blocks_pub(ctx, ctx.fixtures.retired_key, "retired")


@cases('negative.lifecycle.retired-allows-verification')
def _(ctx):
    status, response = ctx.http.post("/sign/verification", ctx.fixtures.retired_token)
    require_status("retired key allows verification", status, 200)
    require(response.get("valid") == "ok", "retired key verification must remain valid")


@cases('negative.lifecycle.retired-allows-internal-decrypt')
def _(ctx):
    status, response = ctx.http.post(
        "/message/internal/decrypt",
        ctx.fixtures.retired_internal_message,
        auth=True,
    )
    require_status("retired key allows internal decrypt", status, 200)
    require(response.get("plaintext") == "negative internal message", "retired decrypt plaintext")


@cases('negative.lifecycle.compromised-blocks-crypto')
def _(ctx):
    set_lifecycle(ctx, ctx.fixtures.compromised_key, "compromised")
    assert_blocks_sign(ctx, ctx.fixtures.compromised_key, "compromised")
    assert_blocks_pub(ctx, ctx.fixtures.compromised_key, "compromised")
    assert_blocks_internal_decrypt(ctx, ctx.fixtures.compromised_internal_message, "compromised")
    assert_blocks_verification(ctx, ctx.fixtures.compromised_token, "compromised")


@cases('negative.lifecycle.destroyed-blocks-crypto')
def _(ctx):
    set_lifecycle(ctx, ctx.fixtures.destroyed_key, "destroyed")
    assert_blocks_sign(ctx, ctx.fixtures.destroyed_key, "destroyed")
    assert_blocks_pub(ctx, ctx.fixtures.destroyed_key, "destroyed")
    assert_blocks_internal_decrypt(ctx, ctx.fixtures.destroyed_internal_message, "destroyed")
    assert_blocks_verification(ctx, ctx.fixtures.destroyed_token, "destroyed")


@cases('negative.lifecycle.lifecycle-rejects-same-state')
def _(ctx):
    same_state_key_id = create_valid_key(ctx.http)
    status, _ = ctx.http.post(
        f"/lifecycle/{same_state_key_id}",
        {"status": "active", "reason": "same state"},
        auth=True,
    )
    require_status("POST /lifecycle/{kid} active to active", status, 400)


@cases('negative.lifecycle.lifecycle-rejects-terminal-transition')
def _(ctx):
    terminal_key_id = create_valid_key(ctx.http)
    set_lifecycle(ctx, terminal_key_id, "retired")
    status, _ = ctx.http.post(
        f"/lifecycle/{terminal_key_id}",
        {"status": "active", "reason": "restore retired"},
        auth=True,
    )
    require_status("POST /lifecycle/{kid} retired to active", status, 400)


@cases('negative.lifecycle.lifecycle-rejects-compromised-to-active')
def _(ctx):
    terminal_key_id = create_valid_key(ctx.http)
    set_lifecycle(ctx, terminal_key_id, "compromised")
    status, _ = ctx.http.post(
        f"/lifecycle/{terminal_key_id}",
        {"status": "active", "reason": "restore compromised"},
        auth=True,
    )
    require_status("POST /lifecycle/{kid} compromised to active", status, 400)


@cases('negative.lifecycle.lifecycle-rejects-destroyed-to-active')
def _(ctx):
    terminal_key_id = create_valid_key(ctx.http)
    set_lifecycle(ctx, terminal_key_id, "destroyed")
    status, _ = ctx.http.post(
        f"/lifecycle/{terminal_key_id}",
        {"status": "active", "reason": "restore destroyed"},
        auth=True,
    )
    require_status("POST /lifecycle/{kid} destroyed to active", status, 400)


CASES = cases.tuple()
