"""Decode batch envelope budget, complete responses and one-time preservation."""

import copy
import json

from lib.assertions import require
from lib.casekit import CaseSet
from lib.fixtures import create_key
from lib.results import CaseResult

cases = CaseSet()


@cases("positive.tokenization.batch-budget")
def run_token_budget(ctx):
    original = copy.deepcopy(ctx.config_data)
    plaintext = "\U0001f642" * 16384
    try:
        kid = create_key(ctx.client, {"tag": "batch-budget", "profile": "hybrid-performance-v1"})
        for once in [False, True]:
            profile = f"budget-{'once' if once else 'reuse'}-v1"
            ctx.config_data["tokenization_profiles"].append({
                "name": profile, "kid": kid, "token_prefix": "tok_budget", "token_len": 32,
                "max_plaintext_len": 16384, "one_time": once,
            })
        ctx.write_config()
        ctx.reload_config()
        for once in [False, True]:
            profile = f"budget-{'once' if once else 'reuse'}-v1"
            tokens = []
            for index in range(64 if once else 1):
                output = ctx.client.post(f"/token/encode/{kid}", {
                    "ref": f"budget-encode-{index}", "profile": profile, "plaintext": plaintext,
                }, auth=True)
                tokens.append(output["token"])
            if not once:
                tokens *= 64
            items = [{"ref": f"budget-{index}", "token": token} for index, token in enumerate(tokens)]
            request = {"kid": kid, "profile": profile, "items": items}
            status, output = ctx.http.post("/token/decode/batch", request, auth=True)
            require(status == 413 and output == {
                "error": "token decode batch exceeds maximum allowed envelope size"
            }, "oversized decode must fail without partial items")
            for group in [items[:32], items[32:]]:
                status, output = ctx.http.post("/token/decode/batch", dict(request, items=group), auth=True)
                require(status == 200, "smaller batch must remain decodable after budget rejection")
                require([item["ref"] for item in output["items"]] == [item["ref"] for item in group], "budget response order")
                require(all(item["plaintext"] == plaintext for item in output["items"]), "budget response is complete")
                require(len(json.dumps(output, ensure_ascii=False).encode()) > 2 * 1024 * 1024,
                        "accepted output must not have an independent 2 MiB cap")
        print("- token batch envelope budget and one-time preservation: OK", flush=True)
        return CaseResult()
    finally:
        ctx.config_data = original
        ctx.write_config()
        ctx.reload_config()


CASES = cases.tuple()
