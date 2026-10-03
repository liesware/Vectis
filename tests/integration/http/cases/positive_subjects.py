"""Subject seeds, isolation, batch atomicity and explicit deletion."""
import copy

from lib.assertions import require
from lib.casekit import CaseSet
from lib.client import StatusClient
from lib.concurrency import run_simultaneously
from lib.fixtures import create_api_key_pair, create_key
from lib.results import CaseResult

cases = CaseSet()


def delete(client, path, auth=True):
    return client._request("DELETE", path, auth=auth)


@cases("positive.tokenization.subjects")
def run_subjects(ctx):
    original = copy.deepcopy(ctx.config_data)
    try:
        kid = create_key(ctx.client, {"tag": "subjects", "profile": "hybrid-performance-v1"})
        names = ["subjects-reuse-v1", "subjects-once-v1", "subjects-other-v1"]
        for name in names:
            ctx.config_data["tokenization_profiles"].append({
                "name": name, "kid": kid, "token_prefix": "tok_subject", "token_len": 32,
                "max_plaintext_len": 128, "one_time": name == names[1], "subject_mode": "stored",
            })
        api_key, api_hash = create_api_key_pair()
        ctx.config_data["permissions"].append({"client": "subject-token-only", "apikey_hash": api_hash,
            "status": "active", "permissions": [{"kid": kid, "actions": ["token-encode", "token-decode", "token-delete"]}]})
        ctx.write_config()
        ctx.reload_config()
        app = StatusClient(ctx.base_url, api_key)
        create_body = {"profile": names[0], "subject_name": "synthetic-user"}
        require(app.post(f"/subject/{kid}", create_body, auth=True)[0] == 403, "token grants cannot create subjects")
        concurrent = run_simultaneously([
            lambda: StatusClient(ctx.base_url, ctx.apikey).post(f"/subject/{kid}", create_body, auth=True)
            for _ in range(8)
        ])
        statuses = sorted(status for status, _ in concurrent)
        require(statuses == [200] * 7 + [201], f"subject creation has one winner; received statuses: {statuses}")
        subject = next(output["subject"] for status, output in concurrent if status == 201)
        for status, output in concurrent:
            require(output == {"kid": kid, "profile": names[0], "subject": subject}, "retry returns the same subject ID")
        other = ctx.http.post(f"/subject/{kid}", dict(create_body, subject_name="other-user"), auth=True)[1]["subject"]
        other_profile = ctx.http.post(f"/subject/{kid}", dict(create_body, profile=names[2]), auth=True)[1]["subject"]
        require(len(subject) == 64 and subject != other != other_profile and subject != other_profile, "domain-scoped ids")
        body = {"ref": "subject-encode", "profile": names[0], "plaintext": "synthetic secret", "metadata": {"kind": "test"}}
        status, encoded = app.post(f"/token/encode/{kid}/subject/{subject}", body, auth=True)
        require(status == 200 and encoded["subject"] == subject, "encode echoes subject")
        inverse = {"ref": "subject-decode", "kid": kid, "profile": names[0], "token": encoded["token"], "subject": subject}
        require(app.post("/token/decode", inverse, auth=True)[1]["plaintext"] == body["plaintext"], "subject round trip")
        retry = ctx.http.post(f"/subject/{kid}", create_body, auth=True)
        require(retry[0] == 200 and retry[1]["subject"] == subject, "lost-response retry recovers ID")
        require(app.post("/token/decode", inverse, auth=True)[1]["plaintext"] == body["plaintext"], "retry preserves original seed")
        require(app.post("/token/decode", dict(inverse, subject=other), auth=True)[0] == 404, "other subject cannot decode")
        require(app.post("/token/delete", dict(inverse, subject=other), auth=True)[0] == 404, "other subject cannot delete")
        missing = dict(inverse)
        missing.pop("subject")
        require(app.post("/token/decode", missing, auth=True)[0] == 400, "stored mode never falls back")
        require(app.post(f"/token/encode/{kid}", body, auth=True)[0] == 400, "legacy path rejects stored profile")
        require(delete(app, f"/subject/{kid}/{subject}")[0] == 403, "token delete cannot delete subject")
        batch = {"profile": names[0], "items": [{"ref": f"item-{i}", "plaintext": f"synthetic-{i}"} for i in range(3)]}
        require(app.post(f"/token/encode/batch/{kid}", batch, auth=True)[0] == 400, "legacy batch path rejects stored profile")
        status, output = app.post(f"/token/encode/batch/{kid}/subject/{subject}", batch, auth=True)
        require(status == 200 and output["subject"] == subject, "subject batch encode")
        decode_batch = {"kid": kid, "profile": names[0], "subject": subject, "items": output["items"]}
        decoded = app.post("/token/decode/batch", decode_batch, auth=True)[1]
        require([item["ref"] for item in decoded["items"]] == [item["ref"] for item in batch["items"]], "subject batch order")
        require(delete(ctx.http, f"/subject/{kid}/{subject}")[0] == 204, "subject deletion committed")
        for path, request in [("/token/decode", inverse), ("/token/delete", inverse), ("/token/decode/batch", decode_batch)]:
            require(app.post(path, request, auth=True)[0] == 404, "missing seed rejects every operation")
        recreated = ctx.http.post(f"/subject/{kid}", create_body, auth=True)
        require(recreated[0] == 201 and recreated[1]["subject"] == subject, "recreated name has stable lookup id")
        require(app.post("/token/decode", inverse, auth=True)[0] == 404, "fresh seed cannot unlock old token")

        once = ctx.http.post(f"/subject/{kid}", dict(create_body, profile=names[1]), auth=True)[1]["subject"]
        status, output = app.post(f"/token/encode/batch/{kid}/subject/{once}", dict(batch, profile=names[1]), auth=True)
        require(status == 200, "one-time batch encode")
        inverse_batch = {"kid": kid, "profile": names[1], "subject": once, "items": output["items"]}
        invalid = dict(inverse_batch, items=output["items"] + [{"ref": "missing", "token": encoded["token"]}])
        require(app.post("/token/decode/batch", invalid, auth=True)[0] == 404, "missing item fails whole batch")
        race = run_simultaneously([lambda: StatusClient(ctx.base_url, api_key).post("/token/decode/batch", inverse_batch, auth=True) for _ in range(2)])
        require(sorted(status for status, _ in race) == [200, 404], "one-time batch has one complete winner")
        require(all("items" not in output for status, output in race if status != 200), "loser releases no plaintext")
        ctx.client.post(f"/lifecycle/{kid}", {"status": "disabled", "reason": "subject cleanup test"}, auth=True)
        require(ctx.http.post(f"/subject/{kid}", dict(create_body, subject_name="disabled-new"), auth=True)[0] == 403, "create requires active key")
        require(delete(ctx.http, f"/subject/{kid}/{once}")[0] == 204, "delete works with disabled key")
        require(delete(ctx.http, f"/subject/{kid}/{once}")[0] == 404, "delete absent subject")
        print("- subject isolation, idempotent create, batching, one-time races and cleanup: OK", flush=True)
        return CaseResult()
    finally:
        ctx.config_data = original
        ctx.write_config()
        ctx.reload_config()


CASES = cases.tuple()
