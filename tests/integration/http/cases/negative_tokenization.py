"""Negative HTTP contract cases: tokenization input validation.

Each case is a plain function taking ctx; reads shared state from ctx.fixtures.
"""

from lib.casekit import CaseSet
from .negative_support import (
    require,
    require_status,
    require_unknown_field_error,
)

cases = CaseSet()


@cases('negative.operations.token-encode-unknown-profile')
def _(ctx):
    status, body = ctx.http.post(
        f"/token/encode/{ctx.fixtures.key_id}",
        {"ref": "token-missing", "profile": "missing-profile", "plaintext": "123456"},
        auth=True,
    )
    require_status("POST /token/encode/{kid} unknown profile", status, 400)
    require(
        body.get("error") == "tokenization profile not found",
        "token encode unknown profile must fail by profile lookup",
    )


@cases('negative.operations.token-encode-unknown-field')
def _(ctx):
    status, body = ctx.http.post(
        f"/token/encode/{ctx.fixtures.key_id}",
        {
            "ref": "token-unknown-field",
            "profile": "patient-id-token-v1",
            "plaintext": "123456",
            "sorpresa": True,
        },
        auth=True,
    )
    require_status("POST /token/encode/{kid} unknown field", status, 400)
    require_unknown_field_error("POST /token/encode/{kid} unknown field", body, "sorpresa")


@cases('negative.operations.token-encode-plaintext-too-long')
def _(ctx):
    status, body = ctx.http.post(
        f"/token/encode/{ctx.fixtures.key_id}",
        {"ref": "token-long", "profile": "patient-id-token-v1", "plaintext": "x" * 1025},
        auth=True,
    )
    require_status("POST /token/encode/{kid} plaintext too long", status, 400)
    require(
        body.get("error") == "plaintext length exceeds tokenization profile maximum",
        "token encode oversized plaintext must fail by tokenization bounds",
    )


@cases('negative.operations.token-encode-metadata-too-long')
def _(ctx):
    status, body = ctx.http.post(
        f"/token/encode/{ctx.fixtures.key_id}",
        {
            "ref": "token-metadata",
            "profile": "patient-id-token-v1",
            "plaintext": "123456",
            "metadata": {"a": "x" * 129},
        },
        auth=True,
    )
    require_status("POST /token/encode/{kid} metadata too long", status, 400)
    require(
        body.get("error") == "metadata exceeds tokenization maximum length",
        "token encode oversized metadata must fail by metadata bounds",
    )


@cases('negative.operations.token-encode-metadata-reserved-key')
def _(ctx):
    status, body = ctx.http.post(
        f"/token/encode/{ctx.fixtures.key_id}",
        {
            "ref": "token-reserved-metadata",
            "profile": "patient-id-token-v1",
            "plaintext": "123456",
            "metadata": {
                "safe": True,
                "$serde_json::private::RawValue": "44E4444444",
            },
        },
        auth=True,
    )
    require_status("POST /token/encode/{kid} reserved metadata key", status, 400)
    require(
        body.get("error") == "metadata contains a reserved JSON object key",
        "token encode reserved metadata key must fail",
    )


@cases('negative.operations.token-encode-batch-empty-items')
def _(ctx):
    status, body = ctx.http.post(
        f"/token/encode/batch/{ctx.fixtures.key_id}",
        {"profile": "patient-id-token-v1", "items": []},
        auth=True,
    )
    require_status("POST /token/encode/batch/{kid} empty items", status, 400)
    require("items" not in body, "token encode batch error must not return partial items")
    require(
        body.get("error") == "token batch items must not be empty",
        "token encode batch empty items must fail by batch bounds",
    )


@cases('negative.operations.token-encode-ref-empty')
def _(ctx):
    status, body = ctx.http.post(
        f"/token/encode/{ctx.fixtures.key_id}",
        {"ref": "", "profile": "patient-id-token-v1", "plaintext": "123456"},
        auth=True,
    )
    require_status("POST /token/encode/{kid} empty ref", status, 400)
    require(body.get("error") == "ref must not be empty", "token empty ref must fail")


@cases('negative.operations.token-encode-ref-too-long')
def _(ctx):
    status, body = ctx.http.post(
        f"/token/encode/{ctx.fixtures.key_id}",
        {
            "ref": "r" * 129,
            "profile": "patient-id-token-v1",
            "plaintext": "123456",
        },
        auth=True,
    )
    require_status("POST /token/encode/{kid} long ref", status, 400)
    require(
        body.get("error") == "ref exceeds maximum allowed length: 128",
        "token long ref must fail",
    )


@cases('negative.operations.token-encode-batch-too-many-items')
def _(ctx):
    status, body = ctx.http.post(
        f"/token/encode/batch/{ctx.fixtures.key_id}",
        {
            "profile": "patient-id-token-v1",
            "items": [
                {"ref": f"token-batch-{index}", "plaintext": "123456"}
                for index in range(129)
            ],
        },
        auth=True,
    )
    require_status("POST /token/encode/batch/{kid} too many items", status, 400)
    require("items" not in body, "token encode batch error must not return partial items")
    require(
        body.get("error") == "token batch items exceeds maximum allowed value: 128",
        "token encode batch oversized request must fail by batch bounds",
    )


@cases('negative.operations.token-encode-batch-duplicate-ref')
def _(ctx):
    status, body = ctx.http.post(
        f"/token/encode/batch/{ctx.fixtures.key_id}",
        {
            "profile": "patient-id-token-v1",
            "items": [
                {"ref": "dup", "plaintext": "123456"},
                {"ref": "dup", "plaintext": "654321"},
            ],
        },
        auth=True,
    )
    require_status("POST /token/encode/batch/{kid} duplicate ref", status, 400)
    require(
        body.get("error") == "batch item 1 failed: token batch ref must be unique",
        "token batch duplicate ref must fail",
    )


@cases('negative.operations.token-encode-batch-metadata-too-long')
def _(ctx):
    status, body = ctx.http.post(
        f"/token/encode/batch/{ctx.fixtures.key_id}",
        {
            "profile": "patient-id-token-v1",
            "items": [
                {"ref": "token-batch-1", "plaintext": "123456"},
                {
                    "ref": "token-batch-2",
                    "plaintext": "654321",
                    "metadata": {"a": "x" * 129},
                },
            ],
        },
        auth=True,
    )
    require_status("POST /token/encode/batch/{kid} metadata too long", status, 400)
    require("items" not in body, "token encode batch error must not return partial items")
    require(
        body.get("error")
        == "batch item 1 failed: metadata exceeds tokenization maximum length",
        "token encode batch oversized metadata must fail all-or-nothing",
    )


@cases('negative.operations.token-encode-batch-metadata-reserved-key')
def _(ctx):
    status, body = ctx.http.post(
        f"/token/encode/batch/{ctx.fixtures.key_id}",
        {
            "profile": "patient-id-token-v1",
            "items": [
                {"ref": "token-batch-1", "plaintext": "123456"},
                {
                    "ref": "token-batch-2",
                    "plaintext": "654321",
                    "metadata": {
                        "nested": {
                            "safe": True,
                            "$serde_json::private::Number": "44E4444444"
                        }
                    },
                },
            ],
        },
        auth=True,
    )
    require_status(
        "POST /token/encode/batch/{kid} reserved metadata key", status, 400
    )
    require("items" not in body, "token encode batch error must not return partial items")
    require(
        body.get("error")
        == "batch item 1 failed: metadata contains a reserved JSON object key",
        "token encode batch reserved metadata key must fail all-or-nothing",
    )


@cases('negative.operations.token-encode-batch-plaintext-too-long')
def _(ctx):
    status, body = ctx.http.post(
        f"/token/encode/batch/{ctx.fixtures.key_id}",
        {
            "profile": "patient-id-token-v1",
            "items": [
                {"ref": "token-batch-1", "plaintext": "123456"},
                {"ref": "token-batch-2", "plaintext": "x" * 1025},
            ],
        },
        auth=True,
    )
    require_status("POST /token/encode/batch/{kid} plaintext too long", status, 400)
    require("items" not in body, "token encode batch error must not return partial items")
    require(
        body.get("error")
        == "batch item 1 failed: plaintext length exceeds tokenization profile maximum",
        "token encode batch oversized plaintext must fail all-or-nothing",
    )


@cases('negative.operations.token-decode-unknown-profile')
def _(ctx):
    status, body = ctx.http.post(
        "/token/decode",
        {"ref": "token-missing", "kid": ctx.fixtures.key_id, "profile": "missing-profile", "token": ctx.fixtures.encoded_token},
        auth=True,
    )
    require_status("POST /token/decode unknown profile", status, 400)
    require(
        body.get("error") == "tokenization profile not found",
        "token decode unknown profile must fail by profile lookup",
    )


@cases('negative.operations.token-decode-invalid-prefix')
def _(ctx):
    status, body = ctx.http.post(
        "/token/decode",
        {
            "ref": "token-prefix",
            "kid": ctx.fixtures.key_id,
            "profile": "patient-id-token-v1",
            "token": "wrong_prefix",
        },
        auth=True,
    )
    require_status("POST /token/decode invalid prefix", status, 400)
    require(
        body.get("error") == "token prefix does not match tokenization profile",
        "token decode invalid prefix must fail by token validation",
    )


@cases('negative.operations.token-decode-invalid-encoding')
def _(ctx):
    status, body = ctx.http.post(
        "/token/decode",
        {
            "ref": "token-encoding",
            "kid": ctx.fixtures.key_id,
            "profile": "patient-id-token-v1",
            "token": "tok_patient_abc;def",
        },
        auth=True,
    )
    require_status("POST /token/decode invalid encoding", status, 400)
    require(
        body.get("error") == "token contains invalid tokenization encoding",
        "token decode invalid encoding must fail before token lookup",
    )


@cases('negative.operations.token-decode-wrong-length')
def _(ctx):
    status, body = ctx.http.post(
        "/token/decode",
        {
            "ref": "token-length",
            "kid": ctx.fixtures.key_id,
            "profile": "patient-id-token-v1",
            "token": "tok_patient_AA",
        },
        auth=True,
    )
    require_status("POST /token/decode wrong length", status, 400)
    require(
        body.get("error") == "token length does not match tokenization profile",
        "token decode wrong length must fail before token lookup",
    )


@cases('negative.operations.token-decode-not-found')
def _(ctx):
    status, body = ctx.http.post(
        "/token/decode",
        {
            "ref": "token-not-found",
            "kid": ctx.fixtures.key_id,
            "profile": "patient-id-token-v1",
            "token": "tok_patient_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        },
        auth=True,
    )
    require_status("POST /token/decode not found", status, 404)
    require(body.get("error") == "token not found", "missing token must be reported as not found")


@cases('negative.operations.token-decode-batch-invalid-prefix')
def _(ctx):
    status, body = ctx.http.post(
        "/token/decode/batch",
        {
            "kid": ctx.fixtures.key_id,
            "profile": "patient-id-token-v1",
            "items": [
                {"ref": "token-batch-1", "token": ctx.fixtures.encoded_token},
                {"ref": "token-batch-2", "token": "wrong_prefix"},
            ],
        },
        auth=True,
    )
    require_status("POST /token/decode/batch invalid prefix", status, 400)
    require("items" not in body, "token decode batch error must not return partial items")
    require(
        body.get("error")
        == "batch item 1 failed: token prefix does not match tokenization profile",
        "token decode batch invalid prefix must fail all-or-nothing with item position",
    )


@cases('negative.operations.token-decode-batch-empty-items')
def _(ctx):
    status, body = ctx.http.post(
        "/token/decode/batch",
        {"kid": ctx.fixtures.key_id, "profile": "patient-id-token-v1", "items": []},
        auth=True,
    )
    require_status("POST /token/decode/batch empty items", status, 400)
    require("items" not in body, "token decode batch error must not return partial items")
    require(
        body.get("error") == "token batch items must not be empty",
        "token decode batch empty items must fail by batch bounds",
    )


@cases('negative.operations.token-decode-batch-not-found')
def _(ctx):
    status, body = ctx.http.post(
        "/token/decode/batch",
        {
            "kid": ctx.fixtures.key_id,
            "profile": "patient-id-token-v1",
            "items": [
                {"ref": "token-batch-1", "token": ctx.fixtures.encoded_token},
                {
                    "ref": "token-batch-2",
                    "token": "tok_patient_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                },
            ],
        },
        auth=True,
    )
    require_status("POST /token/decode/batch not found", status, 404)
    require("items" not in body, "token decode batch error must not return partial items")
    require(
        body.get("error") == "batch item 1 failed: token not found",
        "token decode batch missing token must fail all-or-nothing with item position",
    )


@cases('negative.operations.token-decode-batch-duplicate-ref')
def _(ctx):
    status, body = ctx.http.post(
        "/token/decode/batch",
        {
            "kid": ctx.fixtures.key_id,
            "profile": "patient-id-token-v1",
            "items": [
                {"ref": "dup", "token": ctx.fixtures.encoded_token},
                {"ref": "dup", "token": "tok_patient_missing"},
            ],
        },
        auth=True,
    )
    require_status("POST /token/decode/batch duplicate ref", status, 400)
    require("items" not in body, "token decode batch error must not return partial items")
    require(
        body.get("error") == "batch item 1 failed: token batch ref must be unique",
        "token decode batch duplicate ref must fail",
    )


CASES = cases.tuple()
