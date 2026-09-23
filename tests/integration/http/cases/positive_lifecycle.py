"""Positive HTTP helpers for one capability domain."""

import base64
import hashlib
import json

from lib.assertions import require
from lib.client import StatusClient
from lib.fixtures import create_key
from lib.casekit import CaseSet
from lib.results import CaseResult

from .positive_keys import validate_lifecycle_response

cases = CaseSet()

def retired_lifecycle_historical_operations(ctx):
    """A retired key may recover or verify existing material, never create it."""
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


@cases('positive.lifecycle.retired')
def run_retired_lifecycle(ctx):
    retired_lifecycle_historical_operations(ctx)
    print("Retired lifecycle historical operations: OK\n")
    return CaseResult(passed=1)


CASES = cases.tuple()
