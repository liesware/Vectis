"""Positive HTTP helpers for one capability domain."""

import base64
import hashlib
import json

from lib.assertions import require, require_hex
from lib.positive_support import reload_config, set_profiles
from lib.casekit import CaseSet
from lib.results import CaseResult

from .positive_output import print_section, require_duplicate_batch_ref_rejected

cases = CaseSet()

def commitment_round_trip(client, key_id):
    profile = "pan-commitment-v1"
    plaintext = "4111111111111111"
    ref = "commit-reg1"
    created = client.post(
        f"/commit/{key_id}",
        {"ref": ref, "profile": profile, "plaintext": plaintext},
        auth=True,
    )
    require(created.get("ref") == ref, "commit create ref mismatch")
    require(created.get("kid") == key_id, "commit create kid mismatch")
    require(created.get("profile") == profile, "commit create profile mismatch")
    algorithm = created.get("algorithm")
    expected_hex_lengths = {
        "HMAC(BLAKE2b(256))": 64,
        "KMAC-224": 56,
        "KMAC-256": 64,
        "KMAC-384": 96,
        "KMAC-512": 128,
    }
    require(algorithm in expected_hex_lengths, "commit algorithm mismatch")
    commitment = created.get("commitment")
    opening = created.get("opening")
    require_hex(commitment, "commitment")
    require(len(commitment) == expected_hex_lengths[algorithm], "commitment length mismatch")
    require(isinstance(opening, str) and opening, "commit opening must be present")

    created_again = client.post(
        f"/commit/{key_id}",
        {"ref": "commit-reg2", "profile": profile, "plaintext": plaintext},
        auth=True,
    )
    require(
        created_again.get("commitment") != commitment,
        "same plaintext must produce a different commitment with a fresh opening",
    )

    verified = client.post(
        "/commit/verify",
        {
            "ref": ref,
            "kid": key_id,
            "profile": profile,
            "plaintext": plaintext,
            "opening": opening,
            "commitment": commitment,
        },
        auth=True,
    )
    require(verified.get("ref") == ref, "commit verify ref mismatch")
    require(verified.get("kid") == key_id, "commit verify kid mismatch")
    require(verified.get("profile") == profile, "commit verify profile mismatch")
    require(verified.get("valid") is True, "commit verify must accept matching opening")

    rejected = client.post(
        "/commit/verify",
        {
            "ref": ref,
            "kid": key_id,
            "profile": profile,
            "plaintext": plaintext + "0",
            "opening": opening,
            "commitment": commitment,
        },
        auth=True,
    )
    require(rejected.get("valid") is False, "commit verify must reject changed plaintext")

    return profile, algorithm, commitment[:16] + "..."


def commitment_batch_round_trip(client, key_id):
    profile = "pan-commitment-v1"
    refs = ["commit-batch-1", "commit-batch-2"]
    plaintexts = ["4111111111111111", "5555555555554444"]
    created = client.post(
        f"/commit/batch/{key_id}",
        {
            "profile": profile,
            "items": [
                {"ref": ref, "plaintext": plaintext}
                for ref, plaintext in zip(refs, plaintexts)
            ],
        },
        auth=True,
    )
    require(created.get("kid") == key_id, "commit batch create kid mismatch")
    require(created.get("profile") == profile, "commit batch create profile mismatch")
    algorithm = created.get("algorithm")
    items = created.get("items")
    require(isinstance(items, list), "commit batch create items must be a list")
    require([item.get("ref") for item in items] == refs, "commit batch create ref mismatch")
    require(
        all(set(item.keys()) == {"ref", "commitment", "opening"} for item in items),
        "commit batch create item shape mismatch",
    )
    commitments = [item.get("commitment") for item in items]
    openings = [item.get("opening") for item in items]
    for commitment in commitments:
        require_hex(commitment, "commit batch commitment")
    require(all(isinstance(opening, str) and opening for opening in openings), "commit batch opening missing")

    verified = client.post(
        "/commit/verify/batch",
        {
            "kid": key_id,
            "profile": profile,
            "items": [
                {
                    "ref": refs[0],
                    "plaintext": plaintexts[0],
                    "opening": openings[0],
                    "commitment": commitments[0],
                },
                {
                    "ref": refs[1],
                    "plaintext": plaintexts[1] + "0",
                    "opening": openings[1],
                    "commitment": commitments[1],
                },
            ],
        },
        auth=True,
    )
    require(verified.get("kid") == key_id, "commit batch verify kid mismatch")
    require(verified.get("profile") == profile, "commit batch verify profile mismatch")
    verify_items = verified.get("items")
    require(isinstance(verify_items, list), "commit batch verify items must be a list")
    require([item.get("ref") for item in verify_items] == refs, "commit batch verify ref mismatch")
    require(
        [item.get("valid") for item in verify_items] == [True, False],
        "commit batch verify must preserve true/false results",
    )
    require_duplicate_batch_ref_rejected(
        client,
        f"/commit/batch/{key_id}",
        {"profile": profile, "items": [{"ref": refs[0], "plaintext": plaintexts[0]}, {"ref": refs[0], "plaintext": plaintexts[1]}]},
        "commit batch create",
    )
    require_duplicate_batch_ref_rejected(
        client,
        "/commit/verify/batch",
        {"kid": key_id, "profile": profile, "items": [{"ref": refs[0], "plaintext": plaintexts[0], "opening": openings[0], "commitment": commitments[0]}, {"ref": refs[0], "plaintext": plaintexts[1], "opening": openings[1], "commitment": commitments[1]}]},
        "commit batch verify",
    )

    return profile, algorithm, [commitment[:16] + "..." for commitment in commitments]


@cases('positive.commit')
def run_commitments(ctx):
    client = ctx.client
    key_id = ctx.artifacts["positive.keys"][0][0]
    set_profiles(
        ctx,
        "commitment_profiles",
        [
            {
                "name": "pan-commitment-v1",
                "kid": key_id,
                "context": "tenant=mx;field=pan;purpose=commitment;version=1",
                "max_plaintext_len": 128,
                "opening_len": 32,
            }
        ]
    )
    require(
        reload_config(ctx).get("commitment_profiles_loaded") == 1,
        "config reload must report loaded commitment profile",
    )
    profile, algorithm, commitment = commitment_round_trip(client, key_id)
    batch_profile, batch_algorithm, commitments = commitment_batch_round_trip(client, key_id)
    print_section(
        "commit",
        [
            (f"{profile} {algorithm} {commitment}", "OK"),
            (f"{batch_profile} batch {batch_algorithm} {','.join(commitments)}", "OK"),
        ],
    )
    return CaseResult(passed=2)


CASES = cases.tuple()
