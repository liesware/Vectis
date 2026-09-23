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

def mac_round_trip(client, key_id):
    profile = "pan-blind-index-v1"
    plaintext = "4111111111111111"
    ref = "mac-reg1"
    created = client.post(
        f"/mac/{key_id}",
        {"ref": ref, "profile": profile, "plaintext": plaintext},
        auth=True,
    )
    require(created.get("ref") == ref, "mac create ref mismatch")
    require(created.get("kid") == key_id, "mac create kid mismatch")
    require(created.get("profile") == profile, "mac create profile mismatch")
    algorithm = created.get("algorithm")
    expected_digest_hex_lengths = {
        "HMAC(BLAKE2b(256))": 64,
        "KMAC-224": 56,
        "KMAC-256": 64,
        "KMAC-384": 96,
        "KMAC-512": 128,
    }
    require(algorithm in expected_digest_hex_lengths, "mac algorithm mismatch")
    digest = created.get("digest")
    require_hex(digest, "mac digest")
    require(
        len(digest) == expected_digest_hex_lengths[algorithm],
        "mac digest length mismatch",
    )

    verified = client.post(
        "/mac/verify",
        {"ref": ref, "kid": key_id, "profile": profile, "plaintext": plaintext, "digest": digest},
        auth=True,
    )
    require(verified.get("ref") == ref, "mac verify ref mismatch")
    require(verified.get("valid") is True, "mac verify must accept matching digest")

    rejected = client.post(
        "/mac/verify",
        {"ref": ref, "kid": key_id, "profile": profile, "plaintext": plaintext + "0", "digest": digest},
        auth=True,
    )
    require(rejected.get("ref") == ref, "mac verify rejection ref mismatch")
    require(rejected.get("valid") is False, "mac verify must reject changed plaintext")

    return profile, algorithm, digest[:16] + "..."


def mac_batch_round_trip(client, key_id):
    profile = "pan-blind-index-v1"
    refs = ["mac-batch-1", "mac-batch-2"]
    plaintexts = ["4111111111111111", "5555555555554444"]
    created = client.post(
        f"/mac/batch/{key_id}",
        {
            "profile": profile,
            "items": [
                {"ref": ref, "plaintext": plaintext}
                for ref, plaintext in zip(refs, plaintexts)
            ],
        },
        auth=True,
    )
    require(created.get("kid") == key_id, "mac batch create kid mismatch")
    require(created.get("profile") == profile, "mac batch create profile mismatch")
    algorithm = created.get("algorithm")
    require(algorithm, "mac batch create algorithm missing")
    items = created.get("items")
    require(isinstance(items, list), "mac batch create items must be a list")
    require([item.get("ref") for item in items] == refs, "mac batch create ref mismatch")
    require(all(set(item.keys()) == {"ref", "digest"} for item in items), "mac batch create item shape mismatch")
    digests = [item.get("digest") for item in items]
    for digest in digests:
        require_hex(digest, "mac batch digest")

    verified = client.post(
        "/mac/verify/batch",
        {
            "kid": key_id,
            "profile": profile,
            "items": [
                {"ref": refs[0], "plaintext": plaintexts[0], "digest": digests[0]},
                {"ref": refs[1], "plaintext": plaintexts[1] + "0", "digest": digests[1]},
            ],
        },
        auth=True,
    )
    require(verified.get("kid") == key_id, "mac batch verify kid mismatch")
    require(verified.get("profile") == profile, "mac batch verify profile mismatch")
    verify_items = verified.get("items")
    require(isinstance(verify_items, list), "mac batch verify items must be a list")
    require([item.get("ref") for item in verify_items] == refs, "mac batch verify ref mismatch")
    require(
        [item.get("valid") for item in verify_items] == [True, False],
        "mac batch verify must preserve true/false results",
    )
    require_duplicate_batch_ref_rejected(
        client,
        f"/mac/batch/{key_id}",
        {"profile": profile, "items": [{"ref": refs[0], "plaintext": plaintexts[0]}, {"ref": refs[0], "plaintext": plaintexts[1]}]},
        "mac batch create",
    )
    require_duplicate_batch_ref_rejected(
        client,
        "/mac/verify/batch",
        {"kid": key_id, "profile": profile, "items": [{"ref": refs[0], "plaintext": plaintexts[0], "digest": digests[0]}, {"ref": refs[0], "plaintext": plaintexts[1], "digest": digests[1]}]},
        "mac batch verify",
    )

    return profile, algorithm, [digest[:16] + "..." for digest in digests]



def index_round_trip(client, key_id):
    profile = "pan-blind-index-v1"
    plaintext = "4111111111111111"
    ref = "index-reg1"
    created = client.post(
        f"/index/{key_id}",
        {"ref": ref, "profile": profile, "plaintext": plaintext},
        auth=True,
    )
    require(created.get("ref") == ref, "index create ref mismatch")
    require(created.get("kid") == key_id, "index create kid mismatch")
    require(created.get("profile") == profile, "index create profile mismatch")
    digest = created.get("index")
    require_hex(digest, "index digest")

    matched = client.post(
        "/index/verify",
        {"ref": ref, "kid": key_id, "profile": profile, "plaintext": plaintext},
        auth=True,
    )
    require(matched.get("ref") == ref, "index verify ref mismatch")
    require(matched.get("kid") == key_id, "index verify kid mismatch")
    require(matched.get("profile") == profile, "index verify profile mismatch")
    require(matched.get("matched") is True, "index verify must match stored digest")
    require(matched.get("index") == digest, "index verify digest mismatch")

    missing = client.post(
        "/index/verify",
        {"ref": "index-reg2", "kid": key_id, "profile": profile, "plaintext": plaintext + "0"},
        auth=True,
    )
    require(missing.get("matched") is False, "index verify must reject missing digest")
    require_hex(missing.get("index"), "missing index digest")

    return profile, digest[:16] + "..."


def index_batch_round_trip(client, key_id):
    profile = "pan-blind-index-v1"
    refs = ["index-batch-1", "index-batch-2"]
    # Blind indexes persist by (kid, digest). Keep this atomicity probe separate
    # from prior index tests that intentionally use the common PAN fixtures.
    plaintexts = [
        f"index-batch-atomic-{key_id[:12]}-a",
        f"index-batch-atomic-{key_id[:12]}-b",
    ]
    require_duplicate_batch_ref_rejected(
        client,
        f"/index/batch/{key_id}",
        {"profile": profile, "items": [{"ref": refs[0], "plaintext": plaintexts[0]}, {"ref": refs[0], "plaintext": plaintexts[1]}]},
        "index batch create",
    )
    missing_after_rejection = client.post(
        "/index/verify",
        {"ref": refs[0], "kid": key_id, "profile": profile, "plaintext": plaintexts[0]},
        auth=True,
    )
    require(
        missing_after_rejection.get("matched") is False,
        "invalid index batch must not persist its first item",
    )
    created = client.post(
        f"/index/batch/{key_id}",
        {
            "profile": profile,
            "items": [
                {"ref": ref, "plaintext": plaintext}
                for ref, plaintext in zip(refs, plaintexts)
            ],
        },
        auth=True,
    )
    require(created.get("kid") == key_id, "index batch create kid mismatch")
    require(created.get("profile") == profile, "index batch create profile mismatch")
    items = created.get("items")
    require(isinstance(items, list), "index batch create items must be a list")
    require([item.get("ref") for item in items] == refs, "index batch create ref mismatch")
    require(all(set(item.keys()) == {"ref", "index"} for item in items), "index batch create item shape mismatch")
    digests = [item.get("index") for item in items]
    for digest in digests:
        require_hex(digest, "index batch digest")

    verified = client.post(
        "/index/verify/batch",
        {
            "kid": key_id,
            "profile": profile,
            "items": [
                {"ref": refs[0], "plaintext": plaintexts[0]},
                {"ref": refs[1], "plaintext": plaintexts[1] + "0"},
            ],
        },
        auth=True,
    )
    require(verified.get("kid") == key_id, "index batch verify kid mismatch")
    require(verified.get("profile") == profile, "index batch verify profile mismatch")
    verify_items = verified.get("items")
    require(isinstance(verify_items, list), "index batch verify items must be a list")
    require([item.get("ref") for item in verify_items] == refs, "index batch verify ref mismatch")
    require(
        [item.get("matched") for item in verify_items] == [True, False],
        "index batch verify must preserve true/false results",
    )
    require(verify_items[0].get("index") == digests[0], "index batch verify digest mismatch")
    require_duplicate_batch_ref_rejected(
        client,
        "/index/verify/batch",
        {"kid": key_id, "profile": profile, "items": [{"ref": refs[0], "plaintext": plaintexts[0]}, {"ref": refs[0], "plaintext": plaintexts[1]}]},
        "index batch verify",
    )

    return profile, [digest[:16] + "..." for digest in digests]


@cases('positive.mac')
def run_mac(ctx):
    client = ctx.client
    key_id = ctx.artifacts["positive.keys"][0][0]
    set_profiles(ctx, "mac_profiles", [{
        "name": "pan-blind-index-v1",
        "kid": key_id,
        "context": "tenant=mx;field=pan;purpose=blind-index;version=1",
    }])
    require(reload_config(ctx).get("mac_profiles_loaded") == 1, "config reload must report loaded mac profile")
    profile, algorithm, digest = mac_round_trip(client, key_id)
    batch_profile, batch_algorithm, digests = mac_batch_round_trip(client, key_id)
    print_section("mac", [(f"{profile} {algorithm} {digest}", "OK"), (f"{batch_profile} batch {batch_algorithm} {','.join(digests)}", "OK")])
    return CaseResult(passed=2)


@cases('positive.index')
def run_index(ctx):
    client = ctx.client
    key_id = ctx.artifacts["positive.keys"][0][0]
    profile, digest = index_round_trip(client, key_id)
    batch_profile, digests = index_batch_round_trip(client, key_id)
    print_section("index", [(f"{profile} {digest}", "OK"), (f"{batch_profile} batch {','.join(digests)}", "OK")])
    return CaseResult(passed=2)


CASES = cases.tuple()
