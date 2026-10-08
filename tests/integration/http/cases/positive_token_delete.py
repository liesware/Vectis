"""Explicit token deletion, authorization, lifecycle and concurrent consumption."""

import copy
import json

from lib.assertions import require
from lib.casekit import CaseSet
from lib.client import StatusClient
from lib.concurrency import run_simultaneously
from lib.fixtures import create_api_key_pair, create_key
from lib.results import CaseResult

cases = CaseSet()


def profile_for(kid, name, one_time=False):
    return {"name": name, "kid": kid, "token_prefix": "tok_delete",
            "token_len": 32, "max_plaintext_len": 128, "one_time": one_time}


def issue(ctx, kid, profile):
    encoded = ctx.client.post(f"/token/encode/{kid}", {
        "ref": "delete-encode", "profile": profile, "plaintext": "delete synthetic plaintext",
    }, auth=True)
    return {"ref": "delete-001", "kid": kid, "profile": profile, "token": encoded["token"]}


@cases("positive.tokenization.delete")
def run_token_delete(ctx):
    original = copy.deepcopy(ctx.config_data)
    try:
        key = create_key(ctx.client, {"tag": "delete", "profile": "hybrid-performance-v1"})
        profiles = [profile_for(key, "delete-reusable-v1"), profile_for(key, "delete-once-v1", True)]
        ctx.config_data["tokenization_profiles"].extend(profiles)
        delete_key, delete_hash = create_api_key_pair()
        decode_key, decode_hash = create_api_key_pair()
        for name, hash_value, actions in [
            ("delete-only", delete_hash, ["token-delete"]),
            ("encode-decode-only", decode_hash, ["token-encode", "token-decode"]),
        ]:
            ctx.config_data["permissions"].append({"client": name, "apikey_hash": hash_value,
                "status": "active", "permissions": [{"kid": key, "actions": actions}]})
        ctx.write_config()
        ctx.reload_config()
        deleter = StatusClient(ctx.base_url, delete_key)
        decoder = StatusClient(ctx.base_url, decode_key)
        for profile in profiles:
            body = issue(ctx, key, profile["name"])
            require(ctx.http.post("/token/delete", body, auth=False)[0] == 401, "delete requires auth")
            require(decoder.post("/token/delete", body, auth=True)[0] == 403, "decode cannot grant delete")
            require(deleter.post("/token/decode", body, auth=True)[0] == 403, "delete cannot grant decode")
            wrong = dict(body, profile="unknown-delete-profile")
            require(ctx.http.post("/token/delete", wrong, auth=True)[0] == 400, "unknown profile rejected")
            status, output = deleter.post("/token/delete", body, auth=True)
            require(status == 200 and output == {"ref": body["ref"], "deleted": True}, "delete committed output")
            for path in ["/token/delete", "/token/decode"]:
                status, output = ctx.http.post(path, body, auth=True)
                require(status == 404 and output == {"error": "token not found"}, "deleted token unavailable")

        for second_path in ["/token/delete", "/token/decode"]:
            body = issue(ctx, key, "delete-once-v1")
            def request(path):
                return StatusClient(ctx.base_url, ctx.apikey).post(path, body, auth=True)
            results = run_simultaneously([
                lambda: request("/token/delete"), lambda: request(second_path),
            ])
            require(sorted(status for status, _ in results) == [200, 404], "delete race must have one winner")
            for status, output in results:
                if status == 404:
                    require(output == {"error": "token not found"}, "race loser must return not found")
                    require("delete synthetic plaintext" not in json.dumps(output), "race loser leaks plaintext")

        lifecycle_keys = []
        for state in ["active", "retired", "compromised", "disabled", "destroyed"]:
            kid = create_key(ctx.client, {"tag": f"delete-{state}", "profile": "hybrid-performance-v1"})
            name = f"delete-{state}-v1"
            ctx.config_data["tokenization_profiles"].append(profile_for(kid, name))
            lifecycle_keys.append((state, kid, name))
        ctx.write_config()
        ctx.reload_config()
        for state, kid, name in lifecycle_keys:
            body = issue(ctx, kid, name)
            if state != "active":
                ctx.client.post(f"/lifecycle/{kid}", {"status": state, "reason": "delete policy test"}, auth=True)
            status, output = ctx.http.post("/token/delete", body, auth=True)
            require(status == 200 and output == {"ref": body["ref"], "deleted": True}, "cleanup lifecycle allowed")
        print("- token delete permissions, lifecycle and races: OK", flush=True)
        return CaseResult()
    finally:
        ctx.config_data = original
        ctx.write_config()
        ctx.reload_config()


CASES = cases.tuple()
