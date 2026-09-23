"""Positive HTTP helpers for one capability domain."""

import base64
import hashlib
import json

from lib.assertions import require
from lib.client import StatusClient
from lib.positive_support import reload_config, set_profiles
from lib.concurrency import run_simultaneously
from lib.casekit import CaseSet
from lib.results import CaseResult

from .positive_output import print_section, print_token, print_token_batch, require_duplicate_batch_ref_rejected

cases = CaseSet()

def token_round_trip(client, key_id):
    profile = "patient-id-token-v1"
    ref = "token-single"
    plaintext = "123456789"
    metadata = {"tenant": "acme", "field": "patient_id"}
    encoded = client.post(
        f"/token/encode/{key_id}",
        {"ref": ref, "profile": profile, "plaintext": plaintext, "metadata": metadata},
        auth=True,
    )
    require(encoded.get("ref") == ref, "token encode ref mismatch")
    require(encoded.get("kid") == key_id, "token encode kid mismatch")
    require(encoded.get("profile") == profile, "token encode profile mismatch")
    token = encoded.get("token")
    require(isinstance(token, str) and token.startswith("tok_patient_"), "token format mismatch")
    require(plaintext not in token, "token must not include plaintext")

    decoded = client.post(
        "/token/decode",
        {"ref": ref, "kid": key_id, "profile": profile, "token": token},
        auth=True,
    )
    require(decoded.get("ref") == ref, "token decode ref mismatch")
    require(decoded.get("plaintext") == plaintext, "token decode plaintext mismatch")
    require(decoded.get("metadata") == metadata, "token decode metadata mismatch")

    second = client.post(
        f"/token/encode/{key_id}",
        {"ref": "token-single-2", "profile": profile, "plaintext": plaintext, "metadata": metadata},
        auth=True,
    )
    require(second.get("token") != token, "token encode must generate random tokens")

    return profile, token[:16] + "...", plaintext


def token_batch_round_trip(client, key_id):
    profile = "patient-id-token-v1"
    plaintexts = ["123456789", "987654321"]
    refs = ["token-batch-1", "token-batch-2"]
    metadata = [
        {"tenant": "acme", "field": "patient_id", "item": "one"},
        {"tenant": "acme", "field": "patient_id", "item": "two"},
    ]
    encoded = client.post(
        f"/token/encode/batch/{key_id}",
        {
            "profile": profile,
            "items": [
                {"ref": refs[0], "plaintext": plaintexts[0], "metadata": metadata[0]},
                {"ref": refs[1], "plaintext": plaintexts[1], "metadata": metadata[1]},
            ],
        },
        auth=True,
    )
    require(encoded.get("kid") == key_id, "token batch encode kid mismatch")
    require(encoded.get("profile") == profile, "token batch encode profile mismatch")
    encoded_items = encoded.get("items")
    require(isinstance(encoded_items, list), "token batch encode items must be a list")
    require([item.get("ref") for item in encoded_items] == refs, "token batch encode ref mismatch")
    tokens = [item.get("token") for item in encoded_items]
    require(
        all(isinstance(token, str) and token.startswith("tok_patient_") for token in tokens),
        "token batch format mismatch",
    )
    require(tokens[0] != tokens[1], "token batch must generate distinct tokens")
    require(
        all(plaintext not in token for plaintext, token in zip(plaintexts, tokens)),
        "token batch must not include plaintext",
    )

    decoded = client.post(
        "/token/decode/batch",
        {
            "kid": key_id,
            "profile": profile,
            "items": [
                {"ref": ref, "token": token}
                for ref, token in zip(refs, tokens)
            ],
        },
        auth=True,
    )
    require(decoded.get("kid") == key_id, "token batch decode kid mismatch")
    require(decoded.get("profile") == profile, "token batch decode profile mismatch")
    decoded_items = decoded.get("items")
    require(isinstance(decoded_items, list), "token batch decode items must be a list")
    require([item.get("ref") for item in decoded_items] == refs, "token batch decode ref mismatch")
    require(
        [item.get("plaintext") for item in decoded_items] == plaintexts,
        "token batch decode plaintext order mismatch",
    )
    require(
        [item.get("metadata") for item in decoded_items] == metadata,
        "token batch decode metadata order mismatch",
    )

    # Reusable profiles permit one token per distinct client reference.
    duplicate_decoded = client.post(
        "/token/decode/batch",
        {
            "kid": key_id,
            "profile": profile,
            "items": [
                {"ref": "token-batch-duplicate-1", "token": tokens[0]},
                {"ref": "token-batch-duplicate-2", "token": tokens[0]},
            ],
        },
        auth=True,
    )
    duplicate_items = duplicate_decoded.get("items")
    require(isinstance(duplicate_items, list), "reusable token duplicate batch must return items")
    require(
        [item.get("ref") for item in duplicate_items]
        == ["token-batch-duplicate-1", "token-batch-duplicate-2"],
        "reusable token duplicate batch ref mismatch",
    )
    require(
        [item.get("plaintext") for item in duplicate_items] == [plaintexts[0], plaintexts[0]],
        "reusable token duplicate batch plaintext mismatch",
    )
    require_duplicate_batch_ref_rejected(
        client,
        f"/token/encode/batch/{key_id}",
        {"profile": profile, "items": [{"ref": refs[0], "plaintext": plaintexts[0], "metadata": metadata[0]}, {"ref": refs[0], "plaintext": plaintexts[1], "metadata": metadata[1]}]},
        "token batch encode",
    )
    require_duplicate_batch_ref_rejected(
        client,
        "/token/decode/batch",
        {"kid": key_id, "profile": profile, "items": [{"ref": refs[0], "token": tokens[0]}, {"ref": refs[0], "token": tokens[1]}]},
        "token batch decode",
    )

    return profile, [token[:16] + "..." for token in tokens], plaintexts


def one_time_token_cases(client, key_id):
    profile = "patient-id-token-v1"
    status_client = StatusClient(client.base_url, client.apikey)

    encoded = client.post(
        f"/token/encode/{key_id}",
        {"ref": "one-time-single", "profile": profile, "plaintext": "123456789"},
        auth=True,
    )
    token = encoded["token"]
    status, body = status_client.post(
        "/token/decode/batch",
        {
            "kid": key_id,
            "profile": profile,
            "items": [
                {"ref": "one-time-duplicate-1", "token": token},
                {"ref": "one-time-duplicate-2", "token": token},
            ],
        },
        auth=True,
    )
    require(
        status == 400
        and body.get("error") == "batch item 1 failed: token batch contains duplicated token",
        "one-time token duplicate batch must fail before lookup",
    )
    decoded = client.post(
        "/token/decode",
        {"ref": "one-time-single", "kid": key_id, "profile": profile, "token": token},
        auth=True,
    )
    require(decoded.get("plaintext") == "123456789", "one-time token must decode once")
    status, body = status_client.post(
        "/token/decode",
        {"ref": "one-time-replay", "kid": key_id, "profile": profile, "token": token},
        auth=True,
    )
    require(status == 404 and body.get("error") == "token not found", "one-time token replay must fail")

    encoded_batch = client.post(
        f"/token/encode/batch/{key_id}",
        {
            "profile": profile,
            "items": [
                {"ref": "one-time-batch-a", "plaintext": "111111111"},
                {"ref": "one-time-batch-b", "plaintext": "222222222"},
            ],
        },
        auth=True,
    )
    token_a, token_b = [item["token"] for item in encoded_batch["items"]]
    client.post(
        "/token/decode",
        {"ref": "one-time-batch-b", "kid": key_id, "profile": profile, "token": token_b},
        auth=True,
    )
    status, body = status_client.post(
        "/token/decode/batch",
        {
            "kid": key_id,
            "profile": profile,
            "items": [
                {"ref": "one-time-batch-a", "token": token_a},
                {"ref": "one-time-batch-b", "token": token_b},
            ],
        },
        auth=True,
    )
    require(status == 404 and "items" not in body, "one-time batch must fail without partial output")
    decoded_a = client.post(
        "/token/decode",
        {"ref": "one-time-batch-a", "kid": key_id, "profile": profile, "token": token_a},
        auth=True,
    )
    require(
        decoded_a.get("plaintext") == "111111111",
        "failed one-time batch must not consume other tokens",
    )

    race_plaintext = "333333333"
    race_encoded = client.post(
        f"/token/encode/{key_id}",
        {"ref": "one-time-race-source", "profile": profile, "plaintext": race_plaintext},
        auth=True,
    )
    race_token = race_encoded["token"]

    def decode_race_token(ref):
        worker = StatusClient(client.base_url, client.apikey)
        return worker.post(
            "/token/decode",
            {"ref": ref, "kid": key_id, "profile": profile, "token": race_token},
            auth=True,
        )

    outcomes = run_simultaneously(
        [lambda: decode_race_token("one-time-race-a"), lambda: decode_race_token("one-time-race-b")]
    )

    winners = [
        body
        for status, body in outcomes
        if status == 200 and body.get("plaintext") == race_plaintext
    ]
    losers = [
        body
        for status, body in outcomes
        if status == 404 and body.get("error") == "token not found"
    ]
    require(len(winners) == 1 and len(losers) == 1, "one-time token race must have one winner")
    # Scan the whole serialized loser body, not just its top-level keys: the
    # plaintext could leak inside an error message, a nested field, or a non-JSON
    # body that parse_json wrapped as {"raw": ...}. Matches the fuzz oracle
    # (one_time_race_semantic), which scans the raw response string.
    require(
        all(race_plaintext not in json.dumps(body) for status, body in outcomes if status != 200),
        "one-time token race loser must not receive plaintext",
    )

    return profile


def _profile(key_id, one_time):
    return {
        "name": "patient-id-token-v1",
        "kid": key_id,
        "token_prefix": "tok_patient",
        "token_len": 32,
        "max_plaintext_len": 1024,
        "one_time": one_time,
    }


@cases('positive.tokenization')
def run_tokenization(ctx):
    client = ctx.client
    key_id = ctx.artifacts["positive.keys"][0][0]
    set_profiles(ctx, "tokenization_profiles", [_profile(key_id, False)])
    require(reload_config(ctx).get("tokenization_profiles_loaded") == 1, "config reload must report loaded tokenization profile")
    row = (key_id, *token_round_trip(client, key_id))
    batch_row = (key_id, *token_batch_round_trip(client, key_id))
    ctx.artifacts["positive.tokenization"] = {"profile": row[1], "row": row, "batch_row": batch_row}
    print_token([row])
    print_token_batch([batch_row])
    return CaseResult(passed=2)


@cases('positive.tokenization.one-time')
def run_one_time_token(ctx):
    client = ctx.client
    key_id = ctx.artifacts["positive.keys"][0][0]
    set_profiles(ctx, "tokenization_profiles", [_profile(key_id, True)])
    reload_config(ctx)
    profile = one_time_token_cases(client, key_id)
    print_section("one-time token", [(profile, "OK")])
    return CaseResult()


CASES = cases.tuple()
