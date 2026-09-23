"""Positive HTTP helpers for one capability domain."""

import base64
import hashlib
import json

from lib.assertions import require
from lib.positive_support import reload_config, set_profiles
from lib.casekit import CaseSet
from lib.results import CaseResult

from .positive_output import print_fpe, print_fpe_batch, require_duplicate_batch_ref_rejected

cases = CaseSet()

def fpe_round_trip(client, key_id):
    profile = "patient-id-decimal-v1"
    ref = "fpe-single"
    plaintext = "123456789"
    encrypted = client.post(
        f"/fpe/encrypt/{key_id}",
        {"ref": ref, "profile": profile, "plaintext": plaintext},
        auth=True,
    )
    require(encrypted.get("ref") == ref, "fpe encrypt ref mismatch")
    require(encrypted.get("kid") == key_id, "fpe encrypt kid mismatch")
    require(encrypted.get("profile") == profile, "fpe encrypt profile mismatch")
    require("fpe_version" not in encrypted, "fpe encrypt response must not include fpe_version")
    ciphertext = encrypted.get("ciphertext")
    require(isinstance(ciphertext, str) and ciphertext, "fpe ciphertext must be a non-empty string")
    require(ciphertext != plaintext, "fpe ciphertext should differ from plaintext")
    require(ciphertext.isdigit(), "fpe ciphertext must preserve decimal alphabet")

    decrypted = client.post(
        "/fpe/decrypt",
        {"ref": ref, "kid": key_id, "profile": profile, "ciphertext": ciphertext},
        auth=True,
    )
    require(decrypted.get("ref") == ref, "fpe decrypt ref mismatch")
    require(decrypted.get("plaintext") == plaintext, "fpe decrypt plaintext mismatch")

    return profile, ciphertext, plaintext


def fpe_batch_round_trip(client, key_id):
    profile = "patient-id-decimal-v1"
    plaintexts = ["123456789", "987654321"]
    refs = ["fpe-batch-1", "fpe-batch-2"]
    encrypted = client.post(
        f"/fpe/encrypt/batch/{key_id}",
        {
            "profile": profile,
            "items": [
                {"ref": ref, "plaintext": item}
                for ref, item in zip(refs, plaintexts)
            ],
        },
        auth=True,
    )
    require(encrypted.get("kid") == key_id, "fpe batch encrypt kid mismatch")
    require(encrypted.get("profile") == profile, "fpe batch encrypt profile mismatch")
    encrypted_items = encrypted.get("items")
    require(isinstance(encrypted_items, list), "fpe batch encrypt items must be a list")
    require(len(encrypted_items) == len(plaintexts), "fpe batch encrypt item count mismatch")
    require(
        all(set(item.keys()) == {"ref", "ciphertext"} for item in encrypted_items),
        "fpe batch encrypt items must only include ref and ciphertext",
    )
    require([item.get("ref") for item in encrypted_items] == refs, "fpe batch encrypt ref mismatch")
    ciphertexts = [item["ciphertext"] for item in encrypted_items]
    require(ciphertexts[0] != ciphertexts[1], "fpe batch ciphertexts should differ")
    require(all(item.isdigit() for item in ciphertexts), "fpe batch must preserve decimal alphabet")

    decrypted = client.post(
        "/fpe/decrypt/batch",
        {
            "kid": key_id,
            "profile": profile,
            "items": [
                {"ref": ref, "ciphertext": item}
                for ref, item in zip(refs, ciphertexts)
            ],
        },
        auth=True,
    )
    require(decrypted.get("kid") == key_id, "fpe batch decrypt kid mismatch")
    require(decrypted.get("profile") == profile, "fpe batch decrypt profile mismatch")
    decrypted_items = decrypted.get("items")
    require(isinstance(decrypted_items, list), "fpe batch decrypt items must be a list")
    require([item.get("ref") for item in decrypted_items] == refs, "fpe batch decrypt ref mismatch")
    require(
        [item.get("plaintext") for item in decrypted_items] == plaintexts,
        "fpe batch decrypt plaintext order mismatch",
    )
    require_duplicate_batch_ref_rejected(
        client,
        f"/fpe/encrypt/batch/{key_id}",
        {"profile": profile, "items": [{"ref": refs[0], "plaintext": plaintexts[0]}, {"ref": refs[0], "plaintext": plaintexts[1]}]},
        "fpe batch encrypt",
    )
    require_duplicate_batch_ref_rejected(
        client,
        "/fpe/decrypt/batch",
        {"kid": key_id, "profile": profile, "items": [{"ref": refs[0], "ciphertext": ciphertexts[0]}, {"ref": refs[0], "ciphertext": ciphertexts[1]}]},
        "fpe batch decrypt",
    )

    return profile, ciphertexts, plaintexts


@cases('positive.fpe')
def run_fpe(ctx):
    client = ctx.client
    key_id = ctx.artifacts["positive.keys"][0][0]
    profile = {
        "name": "patient-id-decimal-v1",
        "fpe_version": "fpe-ff1-2025",
        "alphabet": "0123456789",
        "min_len": 6,
        "max_len": 32,
        "tweak_aad": "tenant=acme;field=patient_id;version=1",
        "kid": key_id,
    }
    set_profiles(ctx, "fpe_profiles", [profile])
    require(reload_config(ctx).get("fpe_profiles_loaded") == 1, "config reload must report loaded fpe profile")
    stale = dict(profile, name="patient-id-stale-v1", tweak_aad="tenant=acme;field=patient_id_stale;version=1")
    ctx.config_data["fpe_profiles"].append(stale)
    ctx.write_unsigned_config()
    response = reload_config(ctx)
    require(response.get("warning") == "config.json has changes not covered by config_sign.json — run 'vectis config sign' first", "config reload must warn when config.json is not covered by config_sign.json")
    require(response.get("fpe_profiles_loaded") == 1, "stale config reload must keep previously loaded fpe profiles")
    require('vectis_config_reload_total{result="stale"}' in client.get_text("/metrics", auth=True), "stale config reload must record a stale reload result metric")
    ctx.write_config()
    response = reload_config(ctx)
    require("warning" not in response and response.get("fpe_profiles_loaded") == 2, "signed config reload must apply new fpe profile")
    row = (key_id, *fpe_round_trip(client, key_id))
    batch_row = (key_id, *fpe_batch_round_trip(client, key_id))
    ctx.artifacts["positive.fpe"] = {"profile": profile["name"], "row": row, "batch_row": batch_row}
    print_fpe([row])
    print_fpe_batch([batch_row])
    return CaseResult(passed=2)


CASES = cases.tuple()
