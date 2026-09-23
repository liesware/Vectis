"""Negative HTTP contract cases: MAC and blind-index input validation.

Each case is a plain function taking ctx; reads shared state from ctx.fixtures.
"""

from lib.casekit import CaseSet
from .negative_support import (
    require,
    require_status,
    require_unknown_field_error,
)

cases = CaseSet()


@cases('negative.operations.mac-create-unknown-profile')
def _(ctx):
    status, body = ctx.http.post(
        f"/mac/{ctx.fixtures.key_id}",
        {"ref": "mac-missing", "profile": "missing-profile", "plaintext": "4111111111111111"},
        auth=True,
    )
    require_status("POST /mac/{kid} unknown profile", status, 400)
    require(body.get("error") == "mac profile not found", "MAC unknown profile must fail")


@cases('negative.operations.mac-create-unknown-field')
def _(ctx):
    status, body = ctx.http.post(
        f"/mac/{ctx.fixtures.key_id}",
        {
            "ref": "mac-unknown-field",
            "profile": "pan-blind-index-v1",
            "plaintext": "4111111111111111",
            "sorpresa": True,
        },
        auth=True,
    )
    require_status("POST /mac/{kid} unknown field", status, 400)
    require_unknown_field_error("POST /mac/{kid} unknown field", body, "sorpresa")


@cases('negative.operations.mac-create-wrong-kid')
def _(ctx):
    status, body = ctx.http.post(
        f"/mac/{ctx.fixtures.retired_key}",
        {"ref": "mac-wrong-kid", "profile": "pan-blind-index-v1", "plaintext": "4111111111111111"},
        auth=True,
    )
    require_status("POST /mac/{kid} wrong kid", status, 403)
    require(
        body.get("error") == "mac profile is not authorized for this kid",
        "MAC wrong KID must fail",
    )


@cases('negative.operations.mac-create-ref-missing')
def _(ctx):
    status, _ = ctx.http.post(
        f"/mac/{ctx.fixtures.key_id}",
        {"profile": "pan-blind-index-v1", "plaintext": "4111111111111111"},
        auth=True,
    )
    require_status("POST /mac/{kid} missing ref", status, 400)


@cases('negative.operations.mac-create-ref-empty')
def _(ctx):
    status, body = ctx.http.post(
        f"/mac/{ctx.fixtures.key_id}",
        {"ref": "", "profile": "pan-blind-index-v1", "plaintext": "4111111111111111"},
        auth=True,
    )
    require_status("POST /mac/{kid} empty ref", status, 400)
    require(body.get("error") == "ref must not be empty", "MAC empty ref must fail")


@cases('negative.operations.mac-verify-digest-not-hex')
def _(ctx):
    status, body = ctx.http.post(
        "/mac/verify",
        {
            "ref": "mac-digest",
            "kid": ctx.fixtures.key_id,
            "profile": "pan-blind-index-v1",
            "plaintext": "4111111111111111",
            "digest": "not-hex",
        },
        auth=True,
    )
    require_status("POST /mac/verify digest not hex", status, 400)
    require("digest" in body.get("error", ""), "MAC invalid digest must mention digest")


@cases('negative.operations.mac-verify-wrong-digest')
def _(ctx):
    status, body = ctx.http.post(
        "/mac/verify",
        {
            "ref": "mac-wrong-digest",
            "kid": ctx.fixtures.key_id,
            "profile": "pan-blind-index-v1",
            "plaintext": "4111111111111111",
            "digest": "00" * 32,
        },
        auth=True,
    )
    require_status("POST /mac/verify wrong digest", status, 200)
    require(body.get("ref") == "mac-wrong-digest", "MAC wrong digest must echo ref")
    require(body.get("valid") is False, "MAC wrong digest must return valid false")


@cases('negative.operations.mac-verify-ref-too-long')
def _(ctx):
    status, body = ctx.http.post(
        "/mac/verify",
        {
            "ref": "r" * 129,
            "kid": ctx.fixtures.key_id,
            "profile": "pan-blind-index-v1",
            "plaintext": "4111111111111111",
            "digest": "00" * 32,
        },
        auth=True,
    )
    require_status("POST /mac/verify long ref", status, 400)
    require(
        body.get("error") == "ref exceeds maximum allowed length: 128",
        "MAC long ref must fail",
    )


@cases('negative.operations.mac-create-batch-unknown-profile')
def _(ctx):
    status, body = ctx.http.post(
        f"/mac/batch/{ctx.fixtures.key_id}",
        {
            "profile": "missing-profile",
            "items": [{"ref": "mac-batch-missing", "plaintext": "4111111111111111"}],
        },
        auth=True,
    )
    require_status("POST /mac/batch/{kid} unknown profile", status, 400)
    require("items" not in body, "MAC create batch error must not return partial items")
    require(body.get("error") == "mac profile not found", "MAC batch unknown profile must fail")


@cases('negative.operations.mac-create-batch-wrong-kid')
def _(ctx):
    status, body = ctx.http.post(
        f"/mac/batch/{ctx.fixtures.retired_key}",
        {
            "profile": "pan-blind-index-v1",
            "items": [{"ref": "mac-batch-wrong-kid", "plaintext": "4111111111111111"}],
        },
        auth=True,
    )
    require_status("POST /mac/batch/{kid} wrong kid", status, 403)
    require("items" not in body, "MAC create batch error must not return partial items")
    require(
        body.get("error") == "mac profile is not authorized for this kid",
        "MAC batch wrong KID must fail",
    )


@cases('negative.operations.mac-create-batch-empty-items')
def _(ctx):
    status, body = ctx.http.post(
        f"/mac/batch/{ctx.fixtures.key_id}",
        {"profile": "pan-blind-index-v1", "items": []},
        auth=True,
    )
    require_status("POST /mac/batch/{kid} empty items", status, 400)
    require("items" not in body, "MAC create batch error must not return partial items")
    require(body.get("error") == "mac batch items must not be empty", "MAC batch empty items must fail")


@cases('negative.operations.mac-create-batch-too-many-items')
def _(ctx):
    status, body = ctx.http.post(
        f"/mac/batch/{ctx.fixtures.key_id}",
        {
            "profile": "pan-blind-index-v1",
            "items": [
                {"ref": f"mac-batch-{index}", "plaintext": "4111111111111111"}
                for index in range(129)
            ],
        },
        auth=True,
    )
    require_status("POST /mac/batch/{kid} too many items", status, 400)
    require("items" not in body, "MAC create batch error must not return partial items")
    require(
        body.get("error") == "mac batch items exceeds maximum allowed value: 128",
        "MAC batch too many items must fail",
    )


@cases('negative.operations.mac-create-batch-duplicate-ref')
def _(ctx):
    status, body = ctx.http.post(
        f"/mac/batch/{ctx.fixtures.key_id}",
        {
            "profile": "pan-blind-index-v1",
            "items": [
                {"ref": "dup", "plaintext": "4111111111111111"},
                {"ref": "dup", "plaintext": "5555555555554444"},
            ],
        },
        auth=True,
    )
    require_status("POST /mac/batch/{kid} duplicate ref", status, 400)
    require("items" not in body, "MAC create batch error must not return partial items")
    require(
        body.get("error") == "batch item 1 failed: mac batch ref must be unique",
        "MAC create batch duplicate ref must fail",
    )


@cases('negative.operations.mac-verify-batch-digest-not-hex')
def _(ctx):
    status, body = ctx.http.post(
        "/mac/verify/batch",
        {
            "kid": ctx.fixtures.key_id,
            "profile": "pan-blind-index-v1",
            "items": [
                {
                    "ref": "mac-batch-digest",
                    "plaintext": "4111111111111111",
                    "digest": "not-hex",
                }
            ],
        },
        auth=True,
    )
    require_status("POST /mac/verify/batch digest not hex", status, 400)
    require("items" not in body, "MAC verify batch error must not return partial items")
    require("batch item 0 failed: digest" in body.get("error", ""), "MAC batch invalid digest must mention item")


@cases('negative.operations.mac-verify-batch-duplicate-ref')
def _(ctx):
    status, body = ctx.http.post(
        "/mac/verify/batch",
        {
            "kid": ctx.fixtures.key_id,
            "profile": "pan-blind-index-v1",
            "items": [
                {"ref": "dup", "plaintext": "4111111111111111", "digest": "00" * 32},
                {"ref": "dup", "plaintext": "5555555555554444", "digest": "11" * 32},
            ],
        },
        auth=True,
    )
    require_status("POST /mac/verify/batch duplicate ref", status, 400)
    require("items" not in body, "MAC verify batch error must not return partial items")
    require(
        body.get("error") == "batch item 1 failed: mac batch ref must be unique",
        "MAC verify batch duplicate ref must fail",
    )


@cases('negative.operations.index-create-unknown-profile')
def _(ctx):
    status, body = ctx.http.post(
        f"/index/{ctx.fixtures.key_id}",
        {"ref": "index-missing", "profile": "missing-profile", "plaintext": "4111111111111111"},
        auth=True,
    )
    require_status("POST /index/{kid} unknown profile", status, 400)
    require(body.get("error") == "mac profile not found", "index unknown profile must fail")


@cases('negative.operations.index-create-unknown-field')
def _(ctx):
    status, body = ctx.http.post(
        f"/index/{ctx.fixtures.key_id}",
        {
            "ref": "index-unknown-field",
            "profile": "pan-blind-index-v1",
            "plaintext": "4111111111111111",
            "sorpresa": True,
        },
        auth=True,
    )
    require_status("POST /index/{kid} unknown field", status, 400)
    require_unknown_field_error("POST /index/{kid} unknown field", body, "sorpresa")


@cases('negative.operations.index-create-wrong-kid')
def _(ctx):
    status, body = ctx.http.post(
        f"/index/{ctx.fixtures.retired_key}",
        {"ref": "index-wrong-kid", "profile": "pan-blind-index-v1", "plaintext": "4111111111111111"},
        auth=True,
    )
    require_status("POST /index/{kid} wrong kid", status, 403)
    require(
        body.get("error") == "index profile is not authorized for this kid",
        "index wrong KID must fail",
    )


@cases('negative.operations.index-create-empty-ref')
def _(ctx):
    status, body = ctx.http.post(
        f"/index/{ctx.fixtures.key_id}",
        {"ref": "", "profile": "pan-blind-index-v1", "plaintext": "4111111111111111"},
        auth=True,
    )
    require_status("POST /index/{kid} empty ref", status, 400)
    require(body.get("error") == "ref must not be empty", "index empty ref must fail")


@cases('negative.operations.index-create-batch-empty-items')
def _(ctx):
    status, body = ctx.http.post(
        f"/index/batch/{ctx.fixtures.key_id}",
        {"profile": "pan-blind-index-v1", "items": []},
        auth=True,
    )
    require_status("POST /index/batch/{kid} empty items", status, 400)
    require("items" not in body, "index create batch error must not return partial items")
    require(body.get("error") == "index batch items must not be empty", "index batch empty items must fail")


@cases('negative.operations.index-create-batch-too-many-items')
def _(ctx):
    status, body = ctx.http.post(
        f"/index/batch/{ctx.fixtures.key_id}",
        {
            "profile": "pan-blind-index-v1",
            "items": [
                {"ref": f"index-batch-{index}", "plaintext": "4111111111111111"}
                for index in range(129)
            ],
        },
        auth=True,
    )
    require_status("POST /index/batch/{kid} too many items", status, 400)
    require("items" not in body, "index create batch error must not return partial items")
    require(
        body.get("error") == "index batch items exceeds maximum allowed value: 128",
        "index batch too many items must fail",
    )


@cases('negative.operations.index-create-batch-duplicate-ref')
def _(ctx):
    status, body = ctx.http.post(
        f"/index/batch/{ctx.fixtures.key_id}",
        {
            "profile": "pan-blind-index-v1",
            "items": [
                {"ref": "dup", "plaintext": "4111111111111111"},
                {"ref": "dup", "plaintext": "5555555555554444"},
            ],
        },
        auth=True,
    )
    require_status("POST /index/batch/{kid} duplicate ref", status, 400)
    require("items" not in body, "index create batch error must not return partial items")
    require(
        body.get("error") == "batch item 1 failed: index batch ref must be unique",
        "index create batch duplicate ref must fail",
    )


@cases('negative.operations.index-verify-batch-duplicate-ref')
def _(ctx):
    status, body = ctx.http.post(
        "/index/verify/batch",
        {
            "kid": ctx.fixtures.key_id,
            "profile": "pan-blind-index-v1",
            "items": [
                {"ref": "dup", "plaintext": "4111111111111111"},
                {"ref": "dup", "plaintext": "5555555555554444"},
            ],
        },
        auth=True,
    )
    require_status("POST /index/verify/batch duplicate ref", status, 400)
    require("items" not in body, "index verify batch error must not return partial items")
    require(
        body.get("error") == "batch item 1 failed: index batch ref must be unique",
        "index verify batch duplicate ref must fail",
    )


CASES = cases.tuple()
