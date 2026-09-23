"""Positive HTTP helpers for one capability domain."""

import base64
import hashlib
import json

from lib.assertions import require
from lib.positive_support import reload_config, set_profiles
from lib.casekit import CaseSet
from lib.results import CaseResult

from .positive_output import print_section

cases = CaseSet()

def sharing_round_trip(client, key_id):
    profile = "customer-secret-3of5-v1"
    plaintext = "customer-secret-value"
    split = client.post(
        f"/shares/split/{key_id}",
        {"profile": profile, "plaintext": plaintext},
        auth=True,
    )
    require(split.get("kid") == key_id, "shares split kid mismatch")
    require(split.get("profile") == profile, "shares split profile mismatch")
    require(split.get("threshold") == 3, "shares split threshold mismatch")
    set_id = split.get("set_id")
    require(isinstance(set_id, str) and set_id, "shares split set_id must be present")
    shares = split.get("shares")
    require(isinstance(shares, list) and len(shares) == 5, "shares split must return 5 shares")
    require(
        all(isinstance(share, str) and share.startswith("vectis-sss-v1.") for share in shares),
        "every share must use the vectis-sss-v1 envelope prefix",
    )
    require(len(set(shares)) == 5, "shares split must return distinct shares")
    require(
        all(plaintext not in share for share in shares),
        "shares must not contain the plaintext",
    )

    combined = client.post(
        "/shares/combine",
        {"kid": key_id, "profile": profile, "shares": shares[:3]},
        auth=True,
    )
    require(combined.get("kid") == key_id, "shares combine kid mismatch")
    require(combined.get("profile") == profile, "shares combine profile mismatch")
    require(combined.get("set_id") == set_id, "shares combine set_id mismatch")
    require(
        combined.get("plaintext") == plaintext,
        "threshold subset must reconstruct the original secret",
    )

    disjoint = client.post(
        "/shares/combine",
        {"kid": key_id, "profile": profile, "shares": [shares[0], shares[2], shares[4]]},
        auth=True,
    )
    require(
        disjoint.get("plaintext") == plaintext,
        "any threshold subset must reconstruct the original secret",
    )

    split_again = client.post(
        f"/shares/split/{key_id}",
        {"profile": profile, "plaintext": plaintext},
        auth=True,
    )
    require(
        split_again.get("set_id") != set_id,
        "each split must create a fresh set id",
    )
    require(
        split_again.get("shares") != shares,
        "each split must create fresh randomized shares",
    )

    return profile, set_id, len(shares)


@cases('positive.shares')
def run_sharing(ctx):
    client = ctx.client
    key_id = ctx.artifacts["positive.keys"][0][0]
    set_profiles(
        ctx,
        "sharing_profiles",
        [
            {
                "name": "customer-secret-3of5-v1",
                "kid": key_id,
                "threshold": 3,
                "shares": 5,
                "max_secret_len": 4096,
                "context": "tenant=mx;purpose=customer-secret-sharing;version=1",
            }
        ]
    )
    require(
        reload_config(ctx).get("sharing_profiles_loaded") == 1,
        "config reload must report loaded sharing profile",
    )
    profile, set_id, count = sharing_round_trip(client, key_id)
    print_section("shares", [(f"{profile} 3-of-{count} set {set_id}", "OK")])
    return CaseResult(passed=1)


CASES = cases.tuple()
