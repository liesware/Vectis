"""Shared subject seeds with private symmetric keys and external envelopes."""

import copy

from lib.assertions import require
from lib.casekit import CaseSet
from lib.client import StatusClient
from lib.fixtures import create_api_key_pair, create_key
from lib.results import CaseResult

cases = CaseSet()


@cases("positive.symmetric.subjects")
def run_subject_symmetric(ctx):
    original = copy.deepcopy(ctx.config_data)
    try:
        kid = create_key(ctx.client, {"tag": "symmetric-subject", "profile": "hybrid-performance-v1"})
        creator = {
            "name": "symmetric-seed-origin", "kid": kid, "token_prefix": "sym_subject",
            "token_len": 32, "max_plaintext_len": 128, "one_time": False,
            "subject_mode": "stored",
        }
        ctx.config_data["tokenization_profiles"].append(creator)
        fpe = {
            "name": "symmetric-shared-fpe", "kid": kid, "fpe_version": "fpe-ff1-2025",
            "alphabet_preset": "num", "min_len": 6, "max_len": 32,
            "tweak_aad": "tenant=test;field=shared;version=1",
            "authenticated": True, "subject_mode": "stored",
        }
        ctx.config_data["fpe_profiles"].append(fpe)
        key, key_hash = create_api_key_pair()
        ctx.config_data["permissions"].append({
            "client": "symmetric-only-subject", "apikey_hash": key_hash, "status": "active",
            "permissions": [{"kid": kid, "actions": ["symmetric"]}],
        })
        ctx.write_config()
        ctx.reload_config()
        app = StatusClient(ctx.base_url, key)
        create = {"profile": creator["name"], "subject_name": "shared-person"}
        subject = ctx.client.post(f"/subject/{kid}", create, auth=True)["subject"]
        other = ctx.client.post(f"/subject/{kid}", dict(create, subject_name="other-person"), auth=True)["subject"]
        plaintext = {"plaintext": "synthetic shared symmetric data"}
        route = f"/symmetric/encrypt/{kid}/subject/{subject}"
        status, envelope = app.post(route, plaintext, auth=True)
        require(status == 200 and envelope["subject"] == subject, "symmetric-only client uses subject")
        require("type=subject-symmetric;" in envelope["message"]["aad"], "subject purpose in AAD")
        require(plaintext["plaintext"] not in str(envelope), "plaintext absent from envelope")
        require(app.post("/symmetric/decrypt", envelope, auth=True) == (200, plaintext), "subject symmetric round trip")
        require(app.post(route, plaintext, auth=False)[0] == 401, "subject encrypt requires authentication")
        require(StatusClient(ctx.base_url, "0" * 64).post(route, plaintext, auth=True)[0] == 401, "invalid credential rejected")
        require(app.post(f"/token/encode/{kid}/subject/{subject}", {"ref": "denied", "profile": creator["name"], "plaintext": "test"}, auth=True)[0] == 403, "symmetric grant is not token grant")

        token = ctx.client.post(f"/token/encode/{kid}/subject/{subject}", {"ref": "shared-token", "profile": creator["name"], "plaintext": "synthetic"}, auth=True)
        token_input = dict(token, subject=subject)
        require(ctx.client.post("/token/decode", token_input, auth=True)["plaintext"] == "synthetic", "same subject works for tokens")
        fpe_envelope = ctx.client.post(f"/fpe/encrypt/{kid}/subject/{subject}", {"ref": "shared-fpe", "profile": fpe["name"], "plaintext": "001234"}, auth=True)
        require(ctx.client.post("/fpe/decrypt", fpe_envelope, auth=True)["plaintext"] == "001234", "same subject works for FPE")

        for field, value in [("subject", None), ("subject", other), ("kid", "c" * 64), ("timestamp", "123456")]:
            changed = copy.deepcopy(envelope)
            changed[field] = value
            require(app.post("/symmetric/decrypt", changed, auth=True)[0] in (400, 403, 404), f"tampered {field} rejected")
        for field in ("ctx", "nonce", "aad", "variant"):
            changed = copy.deepcopy(envelope)
            value = changed["message"][field]
            changed["message"][field] = ("0" if value[0] != "0" else "1") + value[1:]
            require(app.post("/symmetric/decrypt", changed, auth=True)[0] == 400, f"tampered {field} rejected")
        removed = copy.deepcopy(envelope)
        removed.pop("subject")
        require(app.post("/symmetric/decrypt", removed, auth=True)[0] == 400, "no subject downgrade")
        coherent_wrong_subject = copy.deepcopy(envelope)
        coherent_wrong_subject["subject"] = other
        coherent_wrong_subject["message"]["aad"] = envelope["message"]["aad"].replace(subject, other)
        require(app.post("/symmetric/decrypt", coherent_wrong_subject, auth=True) == (400, {"error": "message authentication failed"}), "wrong subject key fails AEAD")
        require(app.post(f"/symmetric/encrypt/{kid}/subject/{'e' * 64}", plaintext, auth=True)[0] == 404, "absent subject rejected")

        ctx.config_data["tokenization_profiles"].remove(creator)
        ctx.write_config()
        ctx.reload_config()
        require(app.post("/symmetric/decrypt", envelope, auth=True) == (500, {"error": "internal server error"}), "missing creator fails closed")
        ctx.config_data["tokenization_profiles"].append(creator)
        creator["subject_mode"] = "none"
        ctx.write_config()
        ctx.reload_config()
        require(app.post("/symmetric/decrypt", envelope, auth=True)[0] == 500, "incompatible creator fails closed")
        creator["subject_mode"] = "stored"
        ctx.write_config()
        ctx.reload_config()
        require(ctx.http._request("DELETE", f"/subject/{kid}/{subject}", auth=True)[0] == 204, "delete shared seed")
        require(app.post("/symmetric/decrypt", envelope, auth=True)[0] == 404, "deleted subject cannot decrypt")
        require(app.post(route, plaintext, auth=True)[0] == 404, "deleted subject cannot encrypt")
        require(ctx.http.post("/token/decode", token_input, auth=True)[0] == 404, "delete blocks tokens")
        require(ctx.http.post("/fpe/decrypt", fpe_envelope, auth=True)[0] == 404, "delete blocks FPE")
        require(ctx.client.post(f"/subject/{kid}", create, auth=True)["subject"] == subject, "recreation retains ID")
        require(app.post("/symmetric/decrypt", envelope, auth=True) == (400, {"error": "message authentication failed"}), "new seed cannot recover old ciphertext")
        status, fresh = app.post(route, plaintext, auth=True)
        require(status == 200, "new seed encrypts")
        ctx.client.post(f"/lifecycle/{kid}", {"status": "retired", "reason": "symmetric subject test"}, auth=True)
        require(app.post("/symmetric/decrypt", fresh, auth=True) == (200, plaintext), "retired subject decrypts")
        require(app.post(route, plaintext, auth=True)[0] == 403, "retired subject cannot encrypt")
        print("- Symmetric shared subjects, integrity, lifecycle and erasure: OK", flush=True)
        return CaseResult()
    finally:
        ctx.config_data = original
        ctx.write_config()
        ctx.reload_config()


CASES = cases.tuple()
