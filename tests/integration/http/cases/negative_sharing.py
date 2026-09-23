"""Negative HTTP contract cases: commitment and secret-sharing input validation.

Each case is a plain function taking ctx; reads shared state from ctx.fixtures.
"""

from lib.casekit import CaseSet
from .negative_support import (
    create_valid_shares,
    require_status,
    require_unknown_field_error,
)

cases = CaseSet()


@cases('negative.operations.commit-create-unknown-field')
def _(ctx):
    status, body = ctx.http.post(
        f"/commit/{ctx.fixtures.key_id}",
        {
            "ref": "commit-unknown-field",
            "profile": "pan-commitment-v1",
            "plaintext": "4111111111111111",
            "sorpresa": True,
        },
        auth=True,
    )
    require_status("POST /commit/{kid} unknown field", status, 400)
    require_unknown_field_error("POST /commit/{kid} unknown field", body, "sorpresa")


@cases('negative.operations.share-split-unknown-field')
def _(ctx):
    status, body = ctx.http.post(
        f"/shares/split/{ctx.fixtures.key_id}",
        {
            "profile": "customer-secret-3of5-v1",
            "plaintext": "customer-secret-value",
            "sorpresa": True,
        },
        auth=True,
    )
    require_status("POST /shares/split/{kid} unknown field", status, 400)
    require_unknown_field_error(
        "POST /shares/split/{kid} unknown field", body, "sorpresa"
    )


@cases('negative.operations.share-split-unknown-profile')
def _(ctx):
    status, _ = ctx.http.post(
        f"/shares/split/{ctx.fixtures.key_id}",
        {"profile": "missing-sharing-profile-v1", "plaintext": "customer-secret-value"},
        auth=True,
    )
    require_status("POST /shares/split/{kid} unknown profile", status, 400)


@cases('negative.operations.share-combine-below-threshold')
def _(ctx):
    shares = create_valid_shares(ctx.http, ctx.fixtures.key_id)
    status, _ = ctx.http.post(
        "/shares/combine",
        {"kid": ctx.fixtures.key_id, "profile": "customer-secret-3of5-v1", "shares": shares[:2]},
        auth=True,
    )
    require_status("POST /shares/combine below threshold", status, 400)


@cases('negative.operations.share-combine-tampered-share')
def _(ctx):
    shares = create_valid_shares(ctx.http, ctx.fixtures.key_id)
    tampered = shares[0][:-1] + ("A" if shares[0][-1] != "A" else "B")
    status, _ = ctx.http.post(
        "/shares/combine",
        {
            "kid": ctx.fixtures.key_id,
            "profile": "customer-secret-3of5-v1",
            "shares": [tampered, shares[1], shares[2]],
        },
        auth=True,
    )
    require_status("POST /shares/combine tampered share", status, 400)


@cases('negative.operations.share-combine-duplicate-share')
def _(ctx):
    shares = create_valid_shares(ctx.http, ctx.fixtures.key_id)
    status, _ = ctx.http.post(
        "/shares/combine",
        {
            "kid": ctx.fixtures.key_id,
            "profile": "customer-secret-3of5-v1",
            "shares": [shares[0], shares[0], shares[1]],
        },
        auth=True,
    )
    require_status("POST /shares/combine duplicate share", status, 400)


@cases('negative.operations.share-combine-mixed-sets')
def _(ctx):
    first = create_valid_shares(ctx.http, ctx.fixtures.key_id)
    second = create_valid_shares(ctx.http, ctx.fixtures.key_id)
    status, _ = ctx.http.post(
        "/shares/combine",
        {
            "kid": ctx.fixtures.key_id,
            "profile": "customer-secret-3of5-v1",
            "shares": [first[0], first[1], second[2]],
        },
        auth=True,
    )
    require_status("POST /shares/combine mixed sets", status, 400)


@cases('negative.operations.share-combine-malformed-share')
def _(ctx):
    status, _ = ctx.http.post(
        "/shares/combine",
        {
            "kid": ctx.fixtures.key_id,
            "profile": "customer-secret-3of5-v1",
            "shares": ["not-a-vectis-share", "still-not", "nope"],
        },
        auth=True,
    )
    require_status("POST /shares/combine malformed share", status, 400)


CASES = cases.tuple()
