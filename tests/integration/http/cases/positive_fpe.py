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


@cases('positive.fpe.formatted')
def run_formatted(ctx):
    kid = ctx.artifacts["positive.keys"][0][0]
    profiles = [
        {"name": "patient-id-formatted-v1", "alphabet_preset": "num", "preserve_characters": "-"},
        {"name": "label-formatted-v1", "alphabet_preset": "alphanum", "letter_case": "mixed", "preserve_characters": "- "},
        {"name": "unicode-formatted-v1", "alphabet": "零一二三四五六七八九", "preserve_characters": "🩺"},
    ]
    plaintexts = ["001-234-567", "AbC-012 xYZ", "零零一🩺二三四"]
    for profile in profiles:
        profile.update(kid=kid, fpe_version="fpe-ff1-2025", min_len=6, max_len=32, tweak_aad="tenant=acme;field=formatted;version=1")
    ctx.config_data["fpe_profiles"].extend(profiles)
    ctx.write_config()
    ctx.reload_config()
    for profile, plaintext in zip(profiles, plaintexts):
        body = {"ref": "formatted", "profile": profile["name"], "plaintext": plaintext}
        encrypted = ctx.client.post(f"/fpe/encrypt/{kid}", body, auth=True)
        require(len(encrypted["ciphertext"]) == len(plaintext), "formatted Unicode length preserved")
        for index, ch in enumerate(plaintext):
            if ch in profile["preserve_characters"]:
                require(encrypted["ciphertext"][index] == ch, "separator position preserved")
        decoded = ctx.client.post("/fpe/decrypt", {"ref": "formatted", "profile": profile["name"], "kid": kid, "ciphertext": encrypted["ciphertext"]}, auth=True)
        require(decoded["plaintext"] == plaintext, "formatted FPE exact round trip")
    batch = {"profile": profiles[0]["name"], "items": [{"ref": "a", "plaintext": "001-234"}, {"ref": "b", "plaintext": "--567890--"}]}
    encrypted = ctx.client.post(f"/fpe/encrypt/batch/{kid}", batch, auth=True)
    decoded = ctx.client.post("/fpe/decrypt/batch", {"profile": batch["profile"], "kid": kid, "items": encrypted["items"]}, auth=True)
    require([(item["ref"], item["plaintext"]) for item in decoded["items"]] == [(item["ref"], item["plaintext"]) for item in batch["items"]], "formatted batch order and plaintext")
    invalid = {"profile": batch["profile"], "items": [batch["items"][0], {"ref": "b", "plaintext": "--12345--"}]}
    status, error = ctx.http.post(f"/fpe/encrypt/batch/{kid}", invalid, auth=True)
    require(status == 400 and error == {"error": "batch item 1 failed: plaintext effective domain is too small for FF1 after excluding preserved characters"}, "effective domain failure rejects entire batch with clear indexed error")
    bad_decrypt = {"profile": batch["profile"], "kid": kid, "items": [encrypted["items"][0], {"ref": "b", "ciphertext": "--12345--"}]}
    status, error = ctx.http.post("/fpe/decrypt/batch", bad_decrypt, auth=True)
    require(status == 400 and error == {"error": "batch item 1 failed: ciphertext effective domain is too small for FF1 after excluding preserved characters"}, "decrypt rejects entire batch with clear indexed error")
    print("- FPE presets, Unicode, preserved separators and batch domain: OK", flush=True)
    return CaseResult()


@cases('positive.fpe.authenticated')
def run_authenticated(ctx):
    kid = ctx.artifacts["positive.keys"][0][0]
    profile = {"name":"authenticated-fpe-v1", "kid":kid, "fpe_version":"fpe-ff1-2025",
               "alphabet_preset":"num", "preserve_characters":"- ", "authenticated":True,
               "min_len":6, "max_len":32, "tweak_aad":"tenant=acme;field=auth;version=1"}
    ctx.config_data["fpe_profiles"].append(profile)
    unicode_profile = dict(profile, name="authenticated-unicode-v1", alphabet="零一二三四五六七八九", preserve_characters="🩺")
    unicode_profile.pop("alphabet_preset")
    ctx.config_data["fpe_profiles"].append(unicode_profile)
    ctx.write_config(); ctx.reload_config()
    for active, plaintext in [(profile,"001-234"),(unicode_profile,"零零一🩺二三四")]:
        encoded = ctx.client.post(f"/fpe/encrypt/{kid}", {"ref":"auth", "profile":active["name"], "plaintext":plaintext}, auth=True)
        tag = encoded["tag"]
        require(len(tag)==64 and all(ch in "0123456789abcdef" for ch in tag), "auth tag is lowercase hex")
        inverse = {"ref":"different-ref", "kid":kid, "profile":active["name"], "ciphertext":encoded["ciphertext"], "tag":tag}
        decoded = ctx.client.post("/fpe/decrypt", inverse, auth=True)
        require(decoded == {"ref":"different-ref","plaintext":plaintext}, "auth round trip and ref independence")
        changed = dict(inverse, tag=("1" if tag[0]=="0" else "0")+tag[1:])
        require(ctx.http.post("/fpe/decrypt", changed, auth=True) == (400,{"error":"fpe authentication failed"}), "wrong tag fails without plaintext")
        for invalid in [None, True, 1, "a"*63, "a"*65, "A"*64, "g"*64]:
            status, error = ctx.http.post("/fpe/decrypt", dict(inverse,tag=invalid), auth=True)
            require(status == 400 and set(error)=={"error"}, "invalid tag shape rejects cleanly")
        missing = dict(inverse); missing.pop("tag")
        require(ctx.http.post("/fpe/decrypt", missing, auth=True)[0] == 400, "auth tag cannot be omitted")
        require(ctx.http.post("/fpe/decrypt", dict(inverse,authenticated=False), auth=True)[0] == 400, "request cannot disable auth")
    values = ["001-234", "567-890"]
    encoded = ctx.client.post(f"/fpe/encrypt/batch/{kid}", {"profile":profile["name"],"items":[{"ref":str(i),"plaintext":p} for i,p in enumerate(values)]}, auth=True)
    inverse = {"kid":kid,"profile":profile["name"],"items":encoded["items"]}
    decoded = ctx.client.post("/fpe/decrypt/batch", inverse, auth=True)
    require([item["plaintext"] for item in decoded["items"]]==values, "authenticated batch order")
    bad = [dict(item) for item in encoded["items"]]; bad[1]["tag"]="0"*64
    require(ctx.http.post("/fpe/decrypt/batch",dict(inverse,items=bad),auth=True)==(400,{"error":"batch item 1 failed: fpe authentication failed"}), "bad final tag rejects entire batch")
    changed = dict(encoded["items"][0], kid=kid, profile=profile["name"])
    changed["ciphertext"] = changed["ciphertext"].replace('-', ' ')
    require(ctx.http.post("/fpe/decrypt",changed,auth=True)==(400,{"error":"fpe authentication failed"}), "separator changes are authenticated")
    for field, replacement in [("tweak_aad","tenant=other"),("preserve_characters"," -")]:
        original = profile[field]; profile[field]=replacement
        ctx.write_config(); ctx.reload_config()
        require(ctx.http.post("/fpe/decrypt",dict(encoded["items"][0],kid=kid,profile=profile["name"]),auth=True)==(400,{"error":"fpe authentication failed"}), "signed context mutation invalidates tags")
        profile[field]=original
    ctx.write_config(); ctx.reload_config()
    legacy = ctx.client.post(f"/fpe/encrypt/{kid}", {"ref":"legacy","profile":"patient-id-decimal-v1","plaintext":"001234"},auth=True)
    require("tag" not in legacy, "legacy output omits tag")
    require(ctx.http.post("/fpe/decrypt",dict(legacy,tag="0"*64),auth=True)[0]==400, "legacy rejects supplied tag")
    print("- authenticated FPE: tags, Unicode, batch, context and legacy compatibility: OK",flush=True)
    return CaseResult()


CASES = cases.tuple()
