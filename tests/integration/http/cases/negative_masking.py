"""Negative HTTP contract cases: masking input validation.

Each case is a plain function taking ctx; reads shared state from ctx.fixtures.
"""

from lib.casekit import CaseSet
from .negative_support import (
    require,
    require_status,
    require_unknown_field_error,
)

cases = CaseSet()


@cases('negative.operations.mask-unknown-profile')
def _(ctx):
    status, body = ctx.http.post(
        f"/mask/{ctx.fixtures.key_id}",
        {"ref": "mask-missing", "profile": "missing-profile", "plaintext": "4111111111111111"},
        auth=True,
    )
    require_status("POST /mask/{kid} unknown profile", status, 400)
    require(body.get("error") == "masking profile not found", "mask unknown profile must fail")


@cases('negative.operations.mask-unknown-field')
def _(ctx):
    status, body = ctx.http.post(
        f"/mask/{ctx.fixtures.key_id}",
        {
            "ref": "mask-unknown-field",
            "profile": "pan-display-v1",
            "plaintext": "4111111111111111",
            "sorpresa": True,
        },
        auth=True,
    )
    require_status("POST /mask/{kid} unknown field", status, 400)
    require_unknown_field_error("POST /mask/{kid} unknown field", body, "sorpresa")


@cases('negative.operations.mask-wrong-kid')
def _(ctx):
    status, body = ctx.http.post(
        f"/mask/{ctx.fixtures.retired_key}",
        {"ref": "mask-wrong-kid", "profile": "pan-display-v1", "plaintext": "4111111111111111"},
        auth=True,
    )
    require_status("POST /mask/{kid} wrong kid", status, 403)
    require(
        body.get("error") == "masking profile is not authorized for this kid",
        "mask wrong KID must fail",
    )


@cases('negative.operations.mask-plaintext-too-short')
def _(ctx):
    status, body = ctx.http.post(
        f"/mask/{ctx.fixtures.key_id}",
        {"ref": "mask-short", "profile": "pan-display-v1", "plaintext": "123"},
        auth=True,
    )
    require_status("POST /mask/{kid} plaintext too short", status, 400)
    require(
        body.get("error") == "plaintext length is outside masking profile bounds",
        "mask plaintext too short must fail",
    )


@cases('negative.operations.mask-ref-empty')
def _(ctx):
    status, body = ctx.http.post(
        f"/mask/{ctx.fixtures.key_id}",
        {"ref": "", "profile": "pan-display-v1", "plaintext": "4111111111111111"},
        auth=True,
    )
    require_status("POST /mask/{kid} empty ref", status, 400)
    require(body.get("error") == "ref must not be empty", "mask empty ref must fail")


@cases('negative.operations.mask-batch-empty-items')
def _(ctx):
    status, body = ctx.http.post(
        f"/mask/batch/{ctx.fixtures.key_id}",
        {"profile": "pan-display-v1", "items": []},
        auth=True,
    )
    require_status("POST /mask/batch/{kid} empty items", status, 400)
    require("items" not in body, "mask batch error must not return partial items")
    require(body.get("error") == "mask batch items must not be empty", "mask batch empty items must fail")


@cases('negative.operations.mask-batch-too-many-items')
def _(ctx):
    status, body = ctx.http.post(
        f"/mask/batch/{ctx.fixtures.key_id}",
        {
            "profile": "pan-display-v1",
            "items": [
                {"ref": f"mask-batch-{index}", "plaintext": "4111111111111111"}
                for index in range(129)
            ],
        },
        auth=True,
    )
    require_status("POST /mask/batch/{kid} too many items", status, 400)
    require("items" not in body, "mask batch error must not return partial items")
    require(
        body.get("error") == "mask batch items exceeds maximum allowed value: 128",
        "mask batch too many items must fail",
    )


@cases('negative.operations.mask-batch-duplicate-ref')
def _(ctx):
    status, body = ctx.http.post(
        f"/mask/batch/{ctx.fixtures.key_id}",
        {
            "profile": "pan-display-v1",
            "items": [
                {"ref": "dup", "plaintext": "4111111111111111"},
                {"ref": "dup", "plaintext": "5555555555554444"},
            ],
        },
        auth=True,
    )
    require_status("POST /mask/batch/{kid} duplicate ref", status, 400)
    require("items" not in body, "mask batch error must not return partial items")
    require(
        body.get("error") == "batch item 1 failed: mask batch ref must be unique",
        "mask batch duplicate ref must fail",
    )


CASES = cases.tuple()
