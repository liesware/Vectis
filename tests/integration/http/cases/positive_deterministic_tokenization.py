"""Stateless deterministic tokens, subject isolation and lifecycle."""
import base64
import copy
import json

from lib.assertions import require
from lib.casekit import CaseSet
from lib.client import StatusClient
from lib.fixtures import create_api_key_pair, create_key
from lib.results import CaseResult

cases = CaseSet()


@cases("positive.tokenization.deterministic")
def run_deterministic(ctx):
    original = copy.deepcopy(ctx.config_data)
    try:
        kid = create_key(ctx.client, {"tag": "deterministic", "profile": "hybrid-performance-v1"})
        profile = "deterministic-email-v1"
        origin = "deterministic-subject-origin"
        ctx.config_data.setdefault("deterministic_tokenization_profiles", []).append({
            "name": profile, "kid": kid, "context": "tenant=test;field=email;version=1",
            "min_plaintext_len": 1, "max_plaintext_len": 16384,
        })
        stored_profile = profile + "-stored"
        ctx.config_data["deterministic_tokenization_profiles"].append({
            "name": stored_profile, "kid": kid, "context": "tenant=test;field=email;version=1",
            "min_plaintext_len": 1, "max_plaintext_len": 16384, "subject_mode": "stored",
        })
        ctx.config_data["tokenization_profiles"].append({
            "name": origin, "kid": kid, "token_prefix": "tok_origin", "token_len": 32,
            "max_plaintext_len": 128, "one_time": False, "subject_mode": "stored",
        })
        clients = {}
        for name, actions in [("det", ["token-deterministic-encode", "token-deterministic-decode"]),
                              ("random", ["token-encode", "token-decode"]),
                              ("encode", ["token-deterministic-encode"]),
                              ("decode", ["token-deterministic-decode"])]:
            key, hashed = create_api_key_pair()
            clients[name] = StatusClient(ctx.base_url, key)
            ctx.config_data["permissions"].append({"client": f"det-{name}", "apikey_hash": hashed,
                "status": "active", "permissions": [{"kid": kid, "actions": actions}]})
        ctx.write_config()
        ctx.reload_config()
        app = clients["det"]
        create = {"profile": origin, "subject_name": "synthetic-user"}
        subject = ctx.http.post(f"/subject/{kid}", create, auth=True)[1]["subject"]
        saved = {}
        for scoped in [False, True]:
            selected_profile = stored_profile if scoped else profile
            route = f"/subject/{subject}" if scoped else ""
            scope = {"subject": subject} if scoped else {}
            path = f"/token/deterministic/encode/{kid}{route}"
            plaintext = "synthetic \u00e9\U0001f600"
            body = {"ref": "first", "profile": selected_profile, "plaintext": plaintext}
            status, encoded = app.post(path, body, auth=True)
            require(status == 200 and encoded["kid"] == kid, "deterministic encode")
            token = encoded["token"]
            require(app.post(path, dict(body, ref="another"), auth=True)[1]["token"] == token,
                    "ref is not part of deterministic encryption")
            aad, ciphertext = token.split(".")
            context = json.loads(base64.urlsafe_b64decode(aad + "=" * (-len(aad) % 4)))
            require(context.get("subject") == scope.get("subject"), "public subject binding")
            inverse = {"ref": "inverse", "kid": kid, "profile": selected_profile, "token": token, **scope}
            require(app.post("/token/deterministic/decode", inverse, auth=True)[1]["plaintext"] == plaintext,
                    "deterministic round trip")
            altered = ("A" if ciphertext[0] != "A" else "B") + ciphertext[1:]
            status, error = app.post("/token/deterministic/decode", dict(inverse, token=f"{aad}.{altered}"), auth=True)
            require(status == 400 and error == {"error": "deterministic token authentication failed"}, "tamper rejected cleanly")
            maximum = "\U0001f600" * 16384
            status, maximum_token = app.post(path, dict(body, plaintext=maximum), auth=True)
            require(status == 200 and len(maximum_token["token"]) <= 131072, "Unicode maximum fits")
            require(app.post("/token/deterministic/decode", dict(inverse, token=maximum_token["token"]), auth=True)[1]["plaintext"] == maximum,
                    "Unicode maximum round trip")
            require(app.post(path, dict(body, plaintext=maximum + "x"), auth=True)[0] == 400, "maximum plus one")
            batch_path = f"/token/deterministic/encode/batch/{kid}{route}"
            batch = {"profile": selected_profile, "items": [{"ref": "a", "plaintext": "one"}, {"ref": "b", "plaintext": "two"}]}
            status, encoded_batch = app.post(batch_path, batch, auth=True)
            require(status == 200, "batch encode")
            inverse_batch = {"kid": kid, "profile": selected_profile, "items": encoded_batch["items"], **scope}
            output = app.post("/token/deterministic/decode/batch", inverse_batch, auth=True)[1]
            require([(i["ref"], i["plaintext"]) for i in output["items"]] == [("a", "one"), ("b", "two")], "batch order")
            bad = copy.deepcopy(inverse_batch)
            bad["items"][1]["token"] = f"{aad}.{altered}"
            status, error = app.post("/token/deterministic/decode/batch", bad, auth=True)
            require(status == 400 and "items" not in error and error["error"].startswith("batch item 1 failed"), "no partial plaintext")
            duplicate = dict(batch, items=[batch["items"][0], batch["items"][0]])
            require(app.post(batch_path, duplicate, auth=True)[0] == 400, "refs must be unique")
            for client in [clients["random"], clients["decode"]]:
                require(client.post(path, body, auth=True)[0] == 403, "independent encode permission")
            require(clients["encode"].post("/token/deterministic/decode", inverse, auth=True)[0] == 403, "independent decode permission")
            require(app.post(path, body, auth=False)[0] == 401, "authentication required")
            wrong_route = "" if scoped else f"/subject/{subject}"
            wrong_scope = {} if scoped else {"subject": subject}
            message = ("subject is required for stored deterministic token profiles" if scoped
                       else "subject is prohibited for none deterministic token profiles")
            wrong_inverse = {k: v for k, v in inverse.items() if k != "subject"}
            wrong_inverse_batch = {k: v for k, v in inverse_batch.items() if k != "subject"}
            for endpoint, payload in [
                (f"/token/deterministic/encode/{kid}{wrong_route}", body),
                (f"/token/deterministic/encode/batch/{kid}{wrong_route}", batch),
                ("/token/deterministic/decode", dict(wrong_inverse, **wrong_scope)),
                ("/token/deterministic/decode/batch", dict(wrong_inverse_batch, **wrong_scope)),
            ]:
                status, error = app.post(endpoint, payload, auth=True)
                require(status == 400 and error == {"error": message}, "signed subject policy without partial results")
                require(clients["random"].post(endpoint, payload, auth=True)[0] == 403,
                        "authorization precedes subject policy")
            missing = "0" * 64
            for endpoint, payload in [
                (f"/token/deterministic/encode/{kid}/subject/{missing}", body),
                (f"/token/deterministic/encode/batch/{kid}/subject/{missing}", batch),
                ("/token/deterministic/decode", dict(inverse, subject=missing)),
                ("/token/deterministic/decode/batch", dict(inverse_batch, subject=missing)),
            ]:
                status, error = app.post(endpoint, payload, auth=True)
                require(status == (404 if scoped else 400) and "items" not in error,
                        "policy precedes seed lookup without partial results")
            for invalid_subject in [None, 1, "INVALID"]:
                require(app.post("/token/deterministic/decode", dict(inverse, subject=invalid_subject), auth=True)[0] == 400, "strict subject")
            saved[scoped] = (path, body, inverse)
        require(saved[False][2]["token"] != saved[True][2]["token"], "subject separates tokens")
        missing_subject = dict(saved[True][2]); missing_subject.pop("subject")
        require(app.post("/token/deterministic/decode", missing_subject, auth=True)[0] == 400, "no fallback")
        definition = next(p for p in ctx.config_data["deterministic_tokenization_profiles"]
                          if p["name"] == stored_profile)
        definition.pop("subject_mode")
        ctx.write_config(); ctx.reload_config()
        require(app.post("/token/deterministic/decode", saved[True][2], auth=True)[1] ==
                {"error": "subject is prohibited for none deterministic token profiles"}, "reloaded policy enforced")
        definition["subject_mode"] = "stored"
        ctx.write_config(); ctx.reload_config()
        require(app.post("/token/deterministic/decode", saved[True][2], auth=True)[0] == 200,
                "restoring policy preserves existing subject tokens")
        require(ctx.http._request("DELETE", f"/subject/{kid}/{subject}", auth=True)[0] == 204, "delete seed")
        require(app.post("/token/deterministic/decode", saved[True][2], auth=True)[0] == 404, "deleted seed blocks decode")
        require(app.post("/token/deterministic/decode", saved[False][2], auth=True)[0] == 200, "unscoped tokens unaffected")
        require(ctx.http.post(f"/subject/{kid}", create, auth=True)[1]["subject"] == subject, "recreated stable ID")
        require(app.post("/token/deterministic/decode", saved[True][2], auth=True)[0] == 400, "new seed cannot unlock old token")
        ctx.client.post(f"/lifecycle/{kid}", {"status": "retired", "reason": "deterministic test"}, auth=True)
        require(app.post(saved[False][0], saved[False][1], auth=True)[0] == 403, "retired encode denied")
        require(app.post("/token/deterministic/decode", saved[False][2], auth=True)[0] == 200, "retired decode allowed")
        for lifecycle in ["disabled", "compromised", "destroyed"]:
            blocked_kid = create_key(ctx.client, {"tag": f"det-{lifecycle}", "profile": "hybrid-performance-v1"})
            blocked_profile = f"det-{lifecycle}-v1"
            ctx.config_data["deterministic_tokenization_profiles"].append({
                "name": blocked_profile, "kid": blocked_kid, "context": "tenant=test;field=blocked",
                "min_plaintext_len": 1, "max_plaintext_len": 128,
            })
            ctx.write_config(); ctx.reload_config()
            path = f"/token/deterministic/encode/{blocked_kid}"
            body = {"ref": "blocked", "profile": blocked_profile, "plaintext": "synthetic"}
            status, encoded = ctx.http.post(path, body, auth=True)
            require(status == 200, "prepare lifecycle token while active")
            ctx.client.post(f"/lifecycle/{blocked_kid}", {"status": lifecycle, "reason": "deterministic lifecycle"}, auth=True)
            require(ctx.http.post(path, body, auth=True)[0] == 403, "blocked lifecycle encode")
            inverse = {"ref": "blocked", "kid": blocked_kid, "profile": blocked_profile, "token": encoded["token"]}
            require(ctx.http.post("/token/deterministic/decode", inverse, auth=True)[0] == 403, "blocked lifecycle decode")
        print("- deterministic token single/batch, subject isolation, bounds, permissions and lifecycle: OK", flush=True)
        return CaseResult()
    finally:
        ctx.config_data = original
        ctx.write_config()
        ctx.reload_config()


CASES = cases.tuple()
