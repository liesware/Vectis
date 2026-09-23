"""Negative HTTP contract cases: FPE input validation.

Each case is a plain function taking ctx; reads shared state from ctx.fixtures.
"""

from lib.casekit import CaseSet
from .negative_support import (
    require,
    require_status,
    require_unknown_field_error,
)

cases = CaseSet()


@cases('negative.operations.fpe-encrypt-plaintext-outside-alphabet')
def _(ctx):
    status, body = ctx.http.post(
        f"/fpe/encrypt/{ctx.fixtures.key_id}",
        {"ref": "fpe-bad-alpha", "profile": "patient-id-decimal-v1", "plaintext": "abc123"},
        auth=True,
    )
    require_status("POST /fpe/encrypt/{kid} plaintext outside alphabet", status, 400)
    require(
        body.get("error") == "plaintext contains character outside fpe profile alphabet",
        "FPE plaintext outside alphabet must fail by alphabet validation",
    )


@cases('negative.operations.fpe-encrypt-plaintext-too-short')
def _(ctx):
    status, body = ctx.http.post(
        f"/fpe/encrypt/{ctx.fixtures.key_id}",
        {"ref": "fpe-short", "profile": "patient-id-decimal-v1", "plaintext": "123"},
        auth=True,
    )
    require_status("POST /fpe/encrypt/{kid} plaintext too short", status, 400)
    require(
        body.get("error") == "plaintext length is outside fpe profile bounds",
        "FPE plaintext too short must fail by profile bounds validation",
    )


@cases('negative.operations.fpe-encrypt-unknown-profile')
def _(ctx):
    status, body = ctx.http.post(
        f"/fpe/encrypt/{ctx.fixtures.key_id}",
        {"ref": "fpe-missing", "profile": "missing-profile", "plaintext": "123456"},
        auth=True,
    )
    require_status("POST /fpe/encrypt/{kid} unknown profile", status, 400)
    require(
        body.get("error") == "fpe profile not found",
        "FPE unknown profile must fail by profile lookup",
    )


@cases('negative.operations.fpe-encrypt-unknown-field')
def _(ctx):
    status, body = ctx.http.post(
        f"/fpe/encrypt/{ctx.fixtures.key_id}",
        {
            "ref": "fpe-unknown-field",
            "profile": "patient-id-decimal-v1",
            "plaintext": "123456",
            "sorpresa": True,
        },
        auth=True,
    )
    require_status("POST /fpe/encrypt/{kid} unknown field", status, 400)
    require_unknown_field_error("POST /fpe/encrypt/{kid} unknown field", body, "sorpresa")


@cases('negative.operations.fpe-decrypt-ciphertext-outside-alphabet')
def _(ctx):
    status, body = ctx.http.post(
        "/fpe/decrypt",
        {
            "ref": "fpe-bad-alpha",
            "kid": ctx.fixtures.key_id,
            "profile": "patient-id-decimal-v1",
            "ciphertext": "abc123",
        },
        auth=True,
    )
    require_status("POST /fpe/decrypt ciphertext outside alphabet", status, 400)
    require(
        body.get("error") == "ciphertext contains character outside fpe profile alphabet",
        "FPE ciphertext outside alphabet must fail by alphabet validation",
    )


@cases('negative.operations.fpe-encrypt-batch-plaintext-outside-alphabet')
def _(ctx):
    status, body = ctx.http.post(
        f"/fpe/encrypt/batch/{ctx.fixtures.key_id}",
        {
            "profile": "patient-id-decimal-v1",
            "items": [
                {"ref": "fpe-batch-1", "plaintext": "123456"},
                {"ref": "fpe-batch-2", "plaintext": "abc123"},
            ],
        },
        auth=True,
    )
    require_status("POST /fpe/encrypt/batch/{kid} invalid item", status, 400)
    require("items" not in body, "FPE batch error must not return partial items")
    require(
        body.get("error")
        == "batch item 1 failed: plaintext contains character outside fpe profile alphabet",
        "FPE batch invalid item must fail all-or-nothing with item position",
    )


@cases('negative.operations.fpe-encrypt-batch-empty-items')
def _(ctx):
    status, body = ctx.http.post(
        f"/fpe/encrypt/batch/{ctx.fixtures.key_id}",
        {"profile": "patient-id-decimal-v1", "items": []},
        auth=True,
    )
    require_status("POST /fpe/encrypt/batch/{kid} empty items", status, 400)
    require(
        body.get("error") == "fpe batch items must not be empty",
        "FPE batch empty items must fail",
    )


@cases('negative.operations.fpe-encrypt-batch-too-many-items')
def _(ctx):
    status, body = ctx.http.post(
        f"/fpe/encrypt/batch/{ctx.fixtures.key_id}",
        {
            "profile": "patient-id-decimal-v1",
            "items": [
                {"ref": f"fpe-batch-{index}", "plaintext": "123456"}
                for index in range(129)
            ],
        },
        auth=True,
    )
    require_status("POST /fpe/encrypt/batch/{kid} too many items", status, 400)
    require(
        body.get("error") == "fpe batch items exceeds maximum allowed value: 128",
        "FPE batch too many items must fail",
    )


@cases('negative.operations.fpe-encrypt-ref-empty')
def _(ctx):
    status, body = ctx.http.post(
        f"/fpe/encrypt/{ctx.fixtures.key_id}",
        {"ref": "", "profile": "patient-id-decimal-v1", "plaintext": "123456"},
        auth=True,
    )
    require_status("POST /fpe/encrypt/{kid} empty ref", status, 400)
    require(body.get("error") == "ref must not be empty", "FPE empty ref must fail")


@cases('negative.operations.fpe-encrypt-ref-too-long')
def _(ctx):
    status, body = ctx.http.post(
        f"/fpe/encrypt/{ctx.fixtures.key_id}",
        {
            "ref": "r" * 129,
            "profile": "patient-id-decimal-v1",
            "plaintext": "123456",
        },
        auth=True,
    )
    require_status("POST /fpe/encrypt/{kid} long ref", status, 400)
    require(
        body.get("error") == "ref exceeds maximum allowed length: 128",
        "FPE long ref must fail",
    )


@cases('negative.operations.fpe-encrypt-batch-duplicate-ref')
def _(ctx):
    status, body = ctx.http.post(
        f"/fpe/encrypt/batch/{ctx.fixtures.key_id}",
        {
            "profile": "patient-id-decimal-v1",
            "items": [
                {"ref": "dup", "plaintext": "123456"},
                {"ref": "dup", "plaintext": "654321"},
            ],
        },
        auth=True,
    )
    require_status("POST /fpe/encrypt/batch/{kid} duplicate ref", status, 400)
    require(
        body.get("error") == "batch item 1 failed: fpe batch ref must be unique",
        "FPE batch duplicate ref must fail",
    )


@cases('negative.operations.fpe-decrypt-batch-ciphertext-outside-alphabet')
def _(ctx):
    status, body = ctx.http.post(
        "/fpe/decrypt/batch",
        {
            "kid": ctx.fixtures.key_id,
            "profile": "patient-id-decimal-v1",
            "items": [
                {"ref": "fpe-batch-1", "ciphertext": "123456"},
                {"ref": "fpe-batch-2", "ciphertext": "abc123"},
            ],
        },
        auth=True,
    )
    require_status("POST /fpe/decrypt/batch invalid item", status, 400)
    require("items" not in body, "FPE decrypt batch error must not return partial items")
    require(
        body.get("error")
        == "batch item 1 failed: ciphertext contains character outside fpe profile alphabet",
        "FPE decrypt batch invalid item must fail all-or-nothing with item position",
    )


@cases('negative.operations.fpe-decrypt-batch-duplicate-ref')
def _(ctx):
    status, body = ctx.http.post(
        "/fpe/decrypt/batch",
        {
            "kid": ctx.fixtures.key_id,
            "profile": "patient-id-decimal-v1",
            "items": [
                {"ref": "dup", "ciphertext": "123456"},
                {"ref": "dup", "ciphertext": "654321"},
            ],
        },
        auth=True,
    )
    require_status("POST /fpe/decrypt/batch duplicate ref", status, 400)
    require(
        body.get("error") == "batch item 1 failed: fpe batch ref must be unique",
        "FPE decrypt batch duplicate ref must fail",
    )


CASES = cases.tuple()
