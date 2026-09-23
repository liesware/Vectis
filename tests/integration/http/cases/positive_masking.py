"""Positive HTTP helpers for one capability domain."""

import base64
import hashlib
import json

from lib.assertions import require
from lib.positive_support import reload_config, set_profiles
from lib.casekit import CaseSet
from lib.results import CaseResult

from .positive_output import print_section, require_duplicate_batch_ref_rejected

cases = CaseSet()

def mask_round_trip(client, key_id):
    profile = "pan-display-v1"
    ref = "mask-single"
    plaintext = "4111111111111111"
    masked = client.post(
        f"/mask/{key_id}",
        {"ref": ref, "profile": profile, "plaintext": plaintext},
        auth=True,
    )
    require(masked.get("ref") == ref, "mask ref mismatch")
    require(masked.get("kid") == key_id, "mask kid mismatch")
    require(masked.get("profile") == profile, "mask profile mismatch")
    require(masked.get("masked") == "************1111", "mask output mismatch")

    return profile, masked.get("masked")


def mask_batch_round_trip(client, key_id):
    profile = "pan-display-v1"
    refs = ["mask-batch-1", "mask-batch-2"]
    plaintexts = ["4111111111111111", "5555555555554444"]
    masked = client.post(
        f"/mask/batch/{key_id}",
        {
            "profile": profile,
            "items": [
                {"ref": ref, "plaintext": plaintext}
                for ref, plaintext in zip(refs, plaintexts)
            ],
        },
        auth=True,
    )
    require(masked.get("kid") == key_id, "mask batch kid mismatch")
    require(masked.get("profile") == profile, "mask batch profile mismatch")
    items = masked.get("items")
    require(isinstance(items, list), "mask batch items must be a list")
    require([item.get("ref") for item in items] == refs, "mask batch ref mismatch")
    require(
        [item.get("masked") for item in items] == ["************1111", "************4444"],
        "mask batch output mismatch",
    )
    require_duplicate_batch_ref_rejected(
        client,
        f"/mask/batch/{key_id}",
        {"profile": profile, "items": [{"ref": refs[0], "plaintext": plaintexts[0]}, {"ref": refs[0], "plaintext": plaintexts[1]}]},
        "mask batch",
    )

    return profile, [item.get("masked") for item in items]


@cases('positive.mask')
def run_masking(ctx):
    client = ctx.client
    key_id = ctx.artifacts["positive.keys"][0][0]
    set_profiles(
        ctx,
        "masking_profiles",
        [
            {
                "name": "pan-display-v1",
                "kid": key_id,
                "visible_first": 0,
                "visible_last": 4,
                "mask_char": "*",
                "min_len": 12,
                "max_len": 19,
            }
        ]
    )
    require(
        reload_config(ctx).get("masking_profiles_loaded") == 1,
        "config reload must report loaded masking profile",
    )
    profile, masked = mask_round_trip(client, key_id)
    batch_profile, values = mask_batch_round_trip(client, key_id)
    print_section(
        "mask",
        [
            (f"{profile} {masked}", "OK"),
            (f"{batch_profile} batch {','.join(values)}", "OK"),
        ],
    )
    return CaseResult(passed=2)


CASES = cases.tuple()
