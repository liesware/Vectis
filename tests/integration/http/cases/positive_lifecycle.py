
import base64
import hashlib
import json

from lib.assertions import require
from lib.client import StatusClient
from lib.fixtures import create_api_key_pair, create_key
from lib.casekit import CaseSet
from lib.results import CaseResult

from .positive_keys import validate_key_properties_item, validate_lifecycle_response

cases = CaseSet()


@cases("positive.lifecycle.containment-transitions", weight=6)
def run_containment_transitions(ctx):
    transitions = (
        ("disabled", "retired"),
        ("disabled", "compromised"),
        ("disabled", "destroyed"),
        ("retired", "compromised"),
        ("retired", "destroyed"),
        ("compromised", "destroyed"),
    )
    sign_body = {"message_hash": {"alg": "SHA-256", "hex": hashlib.sha256(b"lifecycle").hexdigest()}}
    for current, destination in transitions:
        kid = create_key(ctx.client, {"tag": f"lifecycle-{current}-{destination}", "profile": "hybrid-performance-v1"})
        signature = ctx.client.post(f"/sign/{kid}", sign_body, auth=True)
        plaintext = {"plaintext": "lifecycle recovery"}
        envelope = ctx.client.post(f"/symmetric/encrypt/{kid}", plaintext, auth=True)

        def transition(status):
            reason = f"containment {status}"
            code, response = ctx.http.post(f"/lifecycle/{kid}", {"status": status, "reason": reason}, auth=True)
            ctx.expect(code, 200, f"lifecycle {status}")
            validate_lifecycle_response(response, kid, status)
            require(response["lifecycle"]["reason"] == reason, "lifecycle reason must be preserved")

        def recovery(expected):
            code, response = ctx.http.post("/symmetric/decrypt", envelope, auth=True)
            ctx.expect(code, expected, "historical decrypt")
            if expected == 200:
                require(response == plaintext, "historical plaintext must match exactly")
            code, response = ctx.http.post("/sign/verification", signature)
            ctx.expect(code, expected, "historical verification")
            if expected == 200:
                require(response.get("valid") == "ok", "historical signature must remain valid")

        recovery(200)
        transition(current)
        recovery(200 if current == "retired" else 403)
        code, _ = ctx.http.post(f"/sign/{kid}", sign_body, auth=True)
        ctx.expect(code, 403, "source state blocks signing")
        transition(destination)
        recovery(200 if destination == "retired" else 403)
        for path, body in ((f"/sign/{kid}", sign_body), (f"/symmetric/encrypt/{kid}", plaintext)):
            code, _ = ctx.http.post(path, body, auth=True)
            ctx.expect(code, 403, "destination blocks new production")
        code, _ = ctx.http.get(f"/pub/{kid}")
        ctx.expect(code, 403, "destination blocks public key publication")
        ctx.client.post("/keys/reload", {}, auth=True)
        properties = validate_key_properties_item(ctx.client.get(f"/keys/properties/{kid}", auth=True), kid, destination)
        require(properties["lifecycle"]["status"] == destination, "lifecycle must survive reload")
        recovery(200 if destination == "retired" else 403)
    return CaseResult(passed=6)


@cases("positive.lifecycle.scoped-authorization")
def run_scoped_lifecycle(ctx):
    kid = create_key(ctx.client, {"tag": "lifecycle-scoped", "profile": "hybrid-performance-v1"})
    other = create_key(ctx.client, {"tag": "lifecycle-other", "profile": "hybrid-performance-v1"})
    credential, credential_hash = create_api_key_pair()
    ctx.config_data["permissions"].append({
        "client": "lifecycle-scoped", "apikey_hash": credential_hash, "status": "active",
        "permissions": [{"kid": kid, "actions": ["lifecycle"]}],
    })
    ctx.write_config()
    ctx.reload_config()
    client = StatusClient(ctx.base_url, credential)
    body = {"status": "disabled", "reason": "scoped lifecycle"}
    code, _ = client.post(f"/lifecycle/{other}", body, auth=True)
    ctx.expect(code, 403, "lifecycle grant cannot update another KID")
    for destination in ("disabled", "compromised"):
        body["status"] = destination
        code, response = client.post(f"/lifecycle/{kid}", body, auth=True)
        ctx.expect(code, 200, "KID-scoped lifecycle grant")
        validate_lifecycle_response(response, kid, destination)
    code, _ = client.post(f"/sign/{kid}", {}, auth=True)
    ctx.expect(code, 403, "lifecycle grant does not grant signing")
    return CaseResult(passed=1)


def retired_lifecycle_historical_operations(ctx):
    client = ctx.client
    key_id = create_key(
        client,
        {"tag": "lifecycle-retired", "profile": "hybrid-standard-v1"},
    )
    fpe_profile = "lifecycle-retired-fpe-v1"
    token_profile = "lifecycle-retired-token-v1"
    sharing_profile = "lifecycle-retired-sharing-3of5-v1"
    ctx.config_data["fpe_profiles"].append(
        {
            "name": fpe_profile,
            "fpe_version": "fpe-ff1-2025",
            "alphabet": "0123456789",
            "min_len": 6,
            "max_len": 32,
            "tweak_aad": "tenant=positive;purpose=lifecycle;version=1",
            "kid": key_id,
        }
    )
    ctx.config_data["tokenization_profiles"].append(
        {
            "name": token_profile,
            "kid": key_id,
            "token_prefix": "tok_life_ret",
            "token_len": 32,
            "max_plaintext_len": 128,
            "one_time": False,
        }
    )
    ctx.config_data["sharing_profiles"].append(
        {
            "name": sharing_profile,
            "kid": key_id,
            "threshold": 3,
            "shares": 5,
            "max_secret_len": 128,
            "context": "tenant=positive;purpose=lifecycle;version=1",
        }
    )
    ctx.write_config()
    ctx.reload_config()

    fpe_plaintext = "123456789"
    fpe = client.post(
        f"/fpe/encrypt/{key_id}",
        {"ref": "lifecycle-fpe", "profile": fpe_profile, "plaintext": fpe_plaintext},
        auth=True,
    )
    token_plaintext = "lifecycle-token"
    token = client.post(
        f"/token/encode/{key_id}",
        {"ref": "lifecycle-token", "profile": token_profile, "plaintext": token_plaintext, "metadata": {}},
        auth=True,
    )
    secret = "lifecycle-sharing-secret"
    split = client.post(
        f"/shares/split/{key_id}",
        {"profile": sharing_profile, "plaintext": secret},
        auth=True,
    )
    shares = split.get("shares")
    require(isinstance(shares, list) and len(shares) == 5, "lifecycle split must return shares")

    validate_lifecycle_response(
        client.post(
            f"/lifecycle/{key_id}",
            {"status": "disabled", "reason": "contain key with existing token rows"},
            auth=True,
        ),
        key_id,
        "disabled",
    )
    validate_lifecycle_response(
        client.post(
            f"/lifecycle/{key_id}",
            {"status": "retired", "reason": "positive historical recovery test"},
            auth=True,
        ),
        key_id,
        "retired",
    )
    require(
        client.post(
            "/fpe/decrypt",
            {"ref": "lifecycle-fpe", "kid": key_id, "profile": fpe_profile, "ciphertext": fpe["ciphertext"]},
            auth=True,
        ).get("plaintext") == fpe_plaintext,
        "retired key must decrypt FPE ciphertext",
    )
    require(
        client.post(
            "/token/decode",
            {"ref": "lifecycle-token", "kid": key_id, "profile": token_profile, "token": token["token"]},
            auth=True,
        ).get("plaintext") == token_plaintext,
        "retired key must decode token",
    )
    require(
        client.post(
            "/shares/combine",
            {"kid": key_id, "profile": sharing_profile, "shares": shares[:3]},
            auth=True,
        ).get("plaintext") == secret,
        "retired key must combine shares",
    )

    status_client = StatusClient(client.base_url, client.apikey)
    blocked = [
        (f"/fpe/encrypt/{key_id}", {"ref": "lifecycle-fpe-new", "profile": fpe_profile, "plaintext": fpe_plaintext}),
        (f"/token/encode/{key_id}", {"ref": "lifecycle-token-new", "profile": token_profile, "plaintext": token_plaintext, "metadata": {}}),
        (f"/shares/split/{key_id}", {"profile": sharing_profile, "plaintext": secret}),
    ]
    for path, body in blocked:
        status, response = status_client.post(path, body, auth=True)
        require(status == 403, f"retired key must reject {path}")
        require(
            response.get("error") == "key is retired and can only be used for decrypt or verification",
            f"retired key error mismatch for {path}",
        )

    validate_lifecycle_response(
        client.post(f"/lifecycle/{key_id}", {"status": "compromised", "reason": "contain retained tokens"}, auth=True),
        key_id,
        "compromised",
    )
    status, _ = status_client.post("/token/decode", {
        "ref": "lifecycle-token", "kid": key_id, "profile": token_profile, "token": token["token"],
    }, auth=True)
    require(status == 403, "compromise must block recovery without deleting existing token rows")


@cases('positive.lifecycle.retired')
def run_retired_lifecycle(ctx):
    retired_lifecycle_historical_operations(ctx)
    print("Retired lifecycle historical operations: OK\n")
    return CaseResult(passed=1)


CASES = cases.tuple()
