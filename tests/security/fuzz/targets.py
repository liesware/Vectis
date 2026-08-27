import json
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

from support.concurrency import run_simultaneously

from client import FuzzClient
from config import CONFIG_PATH, CONFIG_SIGN_PATH, build_config_baseline
from mutations import BAD_APIKEYS, NASTY_KIDS, WRONG_METHODS, corrupt_string, mutate_raw, mutate_structured
from oracle import ALLOWED_STATUS, FRAMEWORK_STATUS, _parse, oracle
from reporting import check_and_record, describe, print_progress
from seeds import (
    batch_contract_context,
    commitment_batch_seeds,
    commitment_seeds,
    decrypt_seeds,
    fpe_batch_seeds,
    fpe_seeds,
    index_batch_seeds,
    index_seeds,
    internal_encrypt_seeds,
    internal_seeds,
    keys_seeds,
    lifecycle_seeds,
    mac_batch_seeds,
    mac_seeds,
    masking_batch_seeds,
    masking_seeds,
    message_seeds,
    ONE_TIME_BATCH_PLAINTEXTS,
    ONE_TIME_TOKEN_PLAINTEXT,
    issue_token,
    issue_token_batch,
    one_time_token_context,
    send_message_seeds,
    sharing_seeds,
    sign_body_seeds,
    token_seeds,
    tokenization_batch_seeds,
    tokenization_seeds,
)
from semantics import (
    COMMITMENT_PLAINTEXTS,
    KID_HEX,
    FPE_BATCH_PLAINTEXTS,
    MAC_PLAINTEXTS,
    MASKING_PLAINTEXTS,
    ONE_TIME_TOKENIZATION_PROFILE,
    TOKENIZATION_PROFILE,
    TOKEN_BATCH_PLAINTEXTS,
    _response_items,
    commitment_batch_contract_semantic,
    config_semantic,
    fpe_batch_semantic,
    fpe_batch_contract_semantic,
    fpe_semantic,
    internal_encrypt_semantic,
    internal_semantic,
    index_batch_transaction_semantic,
    mac_batch_contract_semantic,
    masking_batch_contract_semantic,
    one_time_batch_semantic,
    one_time_race_semantic,
    one_time_single_semantic,
    reject_malformed_body_semantic,
    token_semantic,
    token_batch_duplicate_policy_semantic,
    token_batch_contract_semantic,
    tokenization_batch_semantic,
    tokenization_semantic,
)


def run_body(target, client, rng, args, secrets):
    apikey, unseal = secrets
    seeds = target["seed_factory"](client)
    auth = target.get("auth", False)
    allow_ru = target.get("allow_ru", False)
    # Every body endpoint gets at least the malformed-body floor oracle; targets
    # that declare their own richer semantic override it.
    semantic = target.get("semantic", reject_malformed_body_semantic)
    allowed = target.get("allowed_status", ALLOWED_STATUS)
    counters = {"passed": 0, "failed": 0}
    for index in range(args.iterations):
        path, seed_obj = rng.choice(seeds)
        if rng.random() < 0.3:
            body = mutate_raw(seed_obj, rng)
            status, response = client.post_raw(path, body, auth=auth)
            sent_value = _parse(body.decode("utf-8", "replace"))
            description = describe("POST", path, True, body)
        else:
            body = mutate_structured(seed_obj, rng)
            status, response = client.post_json(path, body, auth=auth)
            sent_value = body
            description = describe("POST", path, False, body)
        findings = oracle(status, response, apikey, unseal, allowed, allow_ru)
        if semantic is not None:
            findings.extend(semantic(sent_value, seed_obj, status, response))
        if check_and_record(target["name"], client, args, index, status, findings, description, counters):
            break
        print_progress(target["name"], index, args, counters)
    return counters


def run_path_param(target, client, rng, args, secrets):
    apikey, unseal = secrets
    endpoints = target["endpoints"]
    allowed = target.get("allowed_status", ALLOWED_STATUS)
    require_json = target.get("require_json_error", True)
    counters = {"passed": 0, "failed": 0}
    for index in range(args.iterations):
        template, auth = rng.choice(endpoints)
        raw_kid = rng.choice(NASTY_KIDS) if rng.random() < 0.5 else corrupt_string(KID_HEX, rng)
        path = template.format(urllib.parse.quote(raw_kid, safe=""))
        status, response = client.request("GET", path, auth=auth)
        description = {"method": "GET", "path": path[:2000], "kid": raw_kid[:200]}
        findings = oracle(status, response, apikey, unseal, allowed, False, require_json_error=require_json)
        if check_and_record(target["name"], client, args, index, status, findings, description, counters):
            break
        print_progress(target["name"], index, args, counters)
    return counters


def run_headers(target, client, rng, args, secrets):
    apikey, unseal = secrets
    allowed = target.get("allowed_status", FRAMEWORK_STATUS)
    counters = {"passed": 0, "failed": 0}
    for index in range(args.iterations):
        if rng.random() < 0.5:
            bad_key = rng.choice(BAD_APIKEYS)
            status, response = client.request(
                "GET", "/keys/properties", headers={"X-API-Key": bad_key}
            )
            description = {"mode": "apikey", "apikey_len": len(bad_key)}
        else:
            method = rng.choice(WRONG_METHODS)
            status, response = client.request(
                method, "/sign/verification", data=b"{}",
                headers={"Content-Type": "application/json"},
            )
            description = {"mode": "method", "method": method}
        findings = oracle(status, response, apikey, unseal, allowed, False, require_json_error=False)
        if check_and_record(target["name"], client, args, index, status, findings, description, counters):
            break
        print_progress(target["name"], index, args, counters)
    return counters


def run_no_body(target, client, rng, args, secrets):
    apikey, unseal = secrets
    endpoints = target["endpoints"]
    counters = {"passed": 0, "failed": 0}
    for index in range(args.iterations):
        method, path, auth, require_json_error = rng.choice(endpoints)
        status, response = client.request(method, path, auth=auth)
        description = {"method": method, "path": path, "auth": auth}
        findings = oracle(
            status,
            response,
            apikey,
            unseal,
            ALLOWED_STATUS,
            False,
            require_json_error=require_json_error,
        )
        if check_and_record(target["name"], client, args, index, status, findings, description, counters):
            break
        print_progress(target["name"], index, args, counters)
    return counters


def run_config(target, client, rng, args, secrets):
    apikey, unseal = secrets
    counters = {"passed": 0, "failed": 0}
    baseline_cfg, baseline_sig = build_config_baseline()
    for index in range(args.iterations):
        if rng.random() < 0.7:
            seed = json.loads(baseline_cfg)
            mutated = (
                json.dumps(mutate_structured(seed, rng)).encode("utf-8")
                if rng.random() < 0.7
                else mutate_raw(seed, rng)
            )
            CONFIG_PATH.write_bytes(mutated)
            CONFIG_SIGN_PATH.write_bytes(baseline_sig)
            target_file = "config.json"
        else:
            seed = json.loads(baseline_sig)
            mutated = (
                json.dumps(mutate_structured(seed, rng)).encode("utf-8")
                if rng.random() < 0.5
                else mutate_raw(seed, rng)
            )
            CONFIG_PATH.write_bytes(baseline_cfg)
            CONFIG_SIGN_PATH.write_bytes(mutated)
            target_file = "config_sign.json"
        status, response = client.post_json("/config/reload", {}, auth=True)
        findings = oracle(status, response, apikey, unseal, ALLOWED_STATUS, False)
        findings.extend(config_semantic(status, response))
        description = {
            "endpoint": "POST /config/reload",
            "mutated_file": target_file,
            "content": mutated[:2000].decode("latin-1"),
        }
        aborted = check_and_record("config", client, args, index, status, findings, description, counters)
        CONFIG_PATH.write_bytes(baseline_cfg)
        CONFIG_SIGN_PATH.write_bytes(baseline_sig)
        if aborted:
            break
        print_progress("config", index, args, counters)
    return counters


def _decode_token(client, kid, profile, ref, token):
    return client.post_json(
        "/token/decode",
        {"ref": ref, "kid": kid, "profile": profile, "token": token},
        auth=True,
    )


def _one_time_single_case(client, context, index):
    encoded_status, encoded_body, token = issue_token(
        client,
        context,
        ONE_TIME_TOKENIZATION_PROFILE,
        f"one-time-single-{index}",
        ONE_TIME_TOKEN_PLAINTEXT,
    )
    decoded_status, decoded_body = _decode_token(
        client,
        context["kid"],
        ONE_TIME_TOKENIZATION_PROFILE,
        f"one-time-decode-{index}",
        token,
    )
    replay_status, replay_body = _decode_token(
        client,
        context["kid"],
        ONE_TIME_TOKENIZATION_PROFILE,
        f"one-time-replay-{index}",
        token,
    )
    return [(encoded_status, encoded_body), (decoded_status, decoded_body), (replay_status, replay_body)]


def _one_time_batch_case(client, context, index):
    refs = [f"one-time-batch-{index}-0", f"one-time-batch-{index}-1"]
    encoded_status, encoded_body, tokens = issue_token_batch(
        client,
        context,
        ONE_TIME_TOKENIZATION_PROFILE,
        [
            {"ref": refs[0], "plaintext": ONE_TIME_BATCH_PLAINTEXTS[0], "metadata": {}},
            {"ref": refs[1], "plaintext": ONE_TIME_BATCH_PLAINTEXTS[1], "metadata": {}},
        ],
    )
    token_a = tokens[0] if len(tokens) > 0 else None
    token_b = tokens[1] if len(tokens) > 1 else None
    consumed_status, consumed_body = _decode_token(
        client, context["kid"], ONE_TIME_TOKENIZATION_PROFILE, f"one-time-consume-{index}", token_b
    )
    batch_status, batch_body = client.post_json(
        "/token/decode/batch",
        {
            "kid": context["kid"],
            "profile": ONE_TIME_TOKENIZATION_PROFILE,
            "items": [{"ref": refs[0], "token": token_a}, {"ref": refs[1], "token": token_b}],
        },
        auth=True,
    )
    survivor_status, survivor_body = _decode_token(
        client, context["kid"], ONE_TIME_TOKENIZATION_PROFILE, f"one-time-survivor-{index}", token_a
    )
    return [
        (encoded_status, encoded_body),
        (consumed_status, consumed_body),
        (batch_status, batch_body),
        (survivor_status, survivor_body),
    ]


def _one_time_race_case(client, context, index):
    encoded_status, encoded_body, token = issue_token(
        client,
        context,
        ONE_TIME_TOKENIZATION_PROFILE,
        f"one-time-race-source-{index}",
        ONE_TIME_TOKEN_PLAINTEXT,
    )
    def decode(ref):
        worker_client = FuzzClient(client.base_url, client.apikey)
        return _decode_token(worker_client, context["kid"], ONE_TIME_TOKENIZATION_PROFILE, ref, token)

    # Reuse the scenario's pool across every iteration (see run_one_time_scenario);
    # the barrier still releases both decodes at the same instant so they race.
    first_result, second_result = run_simultaneously(
        [lambda: decode(f"one-time-race-{index}-0"), lambda: decode(f"one-time-race-{index}-1")],
        executor=context["executor"],
    )
    return [(encoded_status, encoded_body), first_result, second_result]


def _token_batch_duplicate_policy_case(client, context, index):
    one_time_status, one_time_body, one_time_token = issue_token(
        client,
        context,
        ONE_TIME_TOKENIZATION_PROFILE,
        f"one-time-duplicate-source-{index}",
        ONE_TIME_TOKEN_PLAINTEXT,
    )
    rejected_status, rejected_body = client.post_json(
        "/token/decode/batch",
        {
            "kid": context["kid"],
            "profile": ONE_TIME_TOKENIZATION_PROFILE,
            "items": [
                {"ref": "one-time-duplicate-0", "token": one_time_token},
                {"ref": "one-time-duplicate-1", "token": one_time_token},
            ],
        },
        auth=True,
    )
    reusable_status, reusable_body, reusable_token = issue_token(
        client,
        context,
        TOKENIZATION_PROFILE,
        f"reusable-duplicate-source-{index}",
        ONE_TIME_TOKEN_PLAINTEXT,
    )
    accepted_status, accepted_body = client.post_json(
        "/token/decode/batch",
        {
            "kid": context["kid"],
            "profile": TOKENIZATION_PROFILE,
            "items": [
                {"ref": "reusable-duplicate-0", "token": reusable_token},
                {"ref": "reusable-duplicate-1", "token": reusable_token},
            ],
        },
        auth=True,
    )
    return [
        (one_time_status, one_time_body),
        (rejected_status, rejected_body),
        (reusable_status, reusable_body),
        (accepted_status, accepted_body),
    ]


def run_one_time_scenario(target, client, _rng, args, secrets):
    apikey, unseal = secrets
    context = one_time_token_context(client)
    counters = {"passed": 0, "failed": 0}
    # Concurrent scenarios share one pool for the whole run instead of spinning up
    # and tearing down a ThreadPoolExecutor on every iteration.
    executor = ThreadPoolExecutor(max_workers=2) if target.get("concurrent") else None
    if executor is not None:
        context["executor"] = executor
    try:
        for index in range(args.iterations):
            responses = target["scenario"](client, context, index)
            findings = []
            for status, body in responses:
                findings.extend(oracle(status, body, apikey, unseal, ALLOWED_STATUS, False))
            findings.extend(target["semantic"](responses))
            status = 0 if any(response_status == 0 for response_status, _body in responses) else 200
            description = {
                "scenario": target["name"],
                "kid": context["kid"],
                "statuses": [response_status for response_status, _body in responses],
            }
            if check_and_record(target["name"], client, args, index, status, findings, description, counters):
                break
            print_progress(target["name"], index, args, counters)
    finally:
        if executor is not None:
            executor.shutdown(wait=True)
    return counters


def _duplicate_refs(items):
    duplicate = [dict(item) for item in items]
    if len(duplicate) > 1:
        duplicate[1]["ref"] = duplicate[0].get("ref")
    return duplicate


def _batch_roundtrip(client, context, first_path, first_request, second_path, build_second):
    """Run the create->verify batch pattern shared by fpe/token/mac/commitment.

    POST `first_request` to `first_path`, derive the second request from the first
    response's items via `build_second(items)`, POST it to `second_path`, then
    replay both with duplicated refs. `first_path` carries a `{kid}` placeholder.
    Returns [first, second, duplicate_first, duplicate_second].
    """
    kid, profile = context["kid"], context["profile"]
    encode_path = first_path.format(kid=kid)
    first = client.post_json(encode_path, first_request, auth=True)
    second_request = build_second(_response_items(first))
    second = client.post_json(second_path, second_request, auth=True)
    duplicate_first = client.post_json(
        encode_path,
        {"profile": profile, "items": _duplicate_refs(first_request["items"])},
        auth=True,
    )
    duplicate_second = client.post_json(
        second_path,
        {"kid": kid, "profile": profile, "items": _duplicate_refs(second_request["items"])},
        auth=True,
    )
    return [first, second, duplicate_first, duplicate_second]


def _fpe_batch_contract_case(client, context, index):
    refs = [f"fpe-contract-{index}-0", f"fpe-contract-{index}-1"]
    encrypt_request = {
        "profile": context["profile"],
        "items": [
            {"ref": ref, "plaintext": plaintext}
            for ref, plaintext in zip(refs, FPE_BATCH_PLAINTEXTS)
        ],
    }

    def build_decrypt(items):
        return {
            "kid": context["kid"],
            "profile": context["profile"],
            "items": [
                {"ref": ref, "ciphertext": item.get("ciphertext") if isinstance(item, dict) else None}
                for ref, item in zip(refs, items)
            ],
        }

    responses = _batch_roundtrip(
        client, context, "/fpe/encrypt/batch/{kid}", encrypt_request, "/fpe/decrypt/batch", build_decrypt
    )
    return {"refs": refs, "plaintexts": FPE_BATCH_PLAINTEXTS, "responses": responses}


def _token_batch_contract_case(client, context, index):
    refs = [f"token-contract-{index}-0", f"token-contract-{index}-1"]
    metadata = [{"item": "first"}, {"item": "second"}]
    encode_request = {
        "profile": context["profile"],
        "items": [
            {"ref": ref, "plaintext": plaintext, "metadata": item_metadata}
            for ref, plaintext, item_metadata in zip(refs, TOKEN_BATCH_PLAINTEXTS, metadata)
        ],
    }

    def build_decode(items):
        return {
            "kid": context["kid"],
            "profile": context["profile"],
            "items": [
                {"ref": ref, "token": item.get("token") if isinstance(item, dict) else None}
                for ref, item in zip(refs, items)
            ],
        }

    responses = _batch_roundtrip(
        client, context, "/token/encode/batch/{kid}", encode_request, "/token/decode/batch", build_decode
    )
    return {"refs": refs, "plaintexts": TOKEN_BATCH_PLAINTEXTS, "metadata": metadata, "responses": responses}


def _mac_batch_contract_case(client, context, index):
    refs = [f"mac-contract-{index}-0", f"mac-contract-{index}-1"]
    create_request = {
        "profile": context["profile"],
        "items": [
            {"ref": ref, "plaintext": plaintext}
            for ref, plaintext in zip(refs, MAC_PLAINTEXTS)
        ],
    }

    def build_verify(items):
        return {
            "kid": context["kid"],
            "profile": context["profile"],
            "items": [
                {"ref": ref, "plaintext": plaintext, "digest": item.get("digest") if isinstance(item, dict) else None}
                for ref, plaintext, item in zip(refs, MAC_PLAINTEXTS, items)
            ],
        }

    responses = _batch_roundtrip(
        client, context, "/mac/batch/{kid}", create_request, "/mac/verify/batch", build_verify
    )
    return {"refs": refs, "responses": responses}


def _index_batch_transaction_case(client, context, index):
    refs = [f"index-contract-{index}-0", f"index-contract-{index}-1"]
    # The blind-index digest is derived from the plaintext, and indexes persist
    # under (kid, digest) across the whole run. Use per-iteration plaintexts so the
    # pre-create "missing" verify reflects THIS iteration's state — otherwise
    # iteration 0's persisted index makes every later "missing" check match and the
    # transaction semantic falsely reports partial persistence.
    plaintexts = [f"{plaintext}-{index}" for plaintext in MAC_PLAINTEXTS]
    create_request = {
        "profile": context["profile"],
        "items": [
            {"ref": ref, "plaintext": plaintext}
            for ref, plaintext in zip(refs, plaintexts)
        ],
    }
    duplicate_create = client.post_json(
        f"/index/batch/{context['kid']}",
        {"profile": context["profile"], "items": _duplicate_refs(create_request["items"])},
        auth=True,
    )
    missing = client.post_json(
        "/index/verify",
        {"ref": refs[0], "kid": context["kid"], "profile": context["profile"], "plaintext": plaintexts[0]},
        auth=True,
    )
    created = client.post_json(f"/index/batch/{context['kid']}", create_request, auth=True)
    verify_request = {
        "kid": context["kid"],
        "profile": context["profile"],
        "items": [
            {"ref": ref, "plaintext": plaintext}
            for ref, plaintext in zip(refs, plaintexts)
        ],
    }
    verified = client.post_json("/index/verify/batch", verify_request, auth=True)
    duplicate_verify = client.post_json(
        "/index/verify/batch",
        {"kid": context["kid"], "profile": context["profile"], "items": _duplicate_refs(verify_request["items"])},
        auth=True,
    )
    return {"refs": refs, "responses": [duplicate_create, missing, created, verified, duplicate_verify]}


def _masking_batch_contract_case(client, context, index):
    refs = [f"mask-contract-{index}-0", f"mask-contract-{index}-1"]
    request = {
        "profile": context["profile"],
        "items": [
            {"ref": ref, "plaintext": plaintext}
            for ref, plaintext in zip(refs, MASKING_PLAINTEXTS)
        ],
    }
    masked = client.post_json(f"/mask/batch/{context['kid']}", request, auth=True)
    duplicate = client.post_json(
        f"/mask/batch/{context['kid']}",
        {"profile": context["profile"], "items": _duplicate_refs(request["items"])},
        auth=True,
    )
    return {
        "refs": refs,
        "masked": ["*" * (len(value) - 4) + value[-4:] for value in MASKING_PLAINTEXTS],
        "responses": [masked, duplicate],
    }


def _commitment_batch_contract_case(client, context, index):
    refs = [f"commitment-contract-{index}-0", f"commitment-contract-{index}-1"]
    create_request = {
        "profile": context["profile"],
        "items": [
            {"ref": ref, "plaintext": plaintext}
            for ref, plaintext in zip(refs, COMMITMENT_PLAINTEXTS)
        ],
    }

    def build_verify(items):
        return {
            "kid": context["kid"],
            "profile": context["profile"],
            "items": [
                {
                    "ref": ref,
                    "plaintext": plaintext,
                    "opening": item.get("opening") if isinstance(item, dict) else None,
                    "commitment": item.get("commitment") if isinstance(item, dict) else None,
                }
                for ref, plaintext, item in zip(refs, COMMITMENT_PLAINTEXTS, items)
            ],
        }

    responses = _batch_roundtrip(
        client, context, "/commit/batch/{kid}", create_request, "/commit/verify/batch", build_verify
    )
    return {"refs": refs, "responses": responses}


def run_batch_contract(target, client, _rng, args, secrets):
    apikey, unseal = secrets
    context = batch_contract_context(client, target["capability"])
    counters = {"passed": 0, "failed": 0}
    for index in range(args.iterations):
        case = target["scenario"](client, context, index)
        responses = case["responses"]
        findings = []
        for status, body in responses:
            findings.extend(oracle(status, body, apikey, unseal, ALLOWED_STATUS, False))
        findings.extend(target["semantic"](case, context))
        status = 0 if any(response_status == 0 for response_status, _body in responses) else 200
        description = {
            "scenario": target["name"],
            "kid": context["kid"],
            "refs": case["refs"],
            "statuses": [response_status for response_status, _body in responses],
        }
        if check_and_record(target["name"], client, args, index, status, findings, description, counters):
            break
        print_progress(target["name"], index, args, counters)
    return counters


TARGETS = [
    {"name": "token", "runner": run_body, "seed_factory": token_seeds,
     "path": "/sign/verification", "auth": False, "semantic": token_semantic},
    {"name": "message", "runner": run_body, "seed_factory": message_seeds,
     "auth": False, "allow_ru": True},
    {"name": "message_send", "runner": run_body, "seed_factory": send_message_seeds,
     "auth": True},
    {"name": "internal", "runner": run_body, "seed_factory": internal_seeds,
     "auth": True, "semantic": internal_semantic},
    {"name": "internal_encrypt", "runner": run_body, "seed_factory": internal_encrypt_seeds,
     "auth": True, "semantic": internal_encrypt_semantic},
    {"name": "keys", "runner": run_body, "seed_factory": keys_seeds, "auth": True},
    {"name": "sign_body", "runner": run_body, "seed_factory": sign_body_seeds, "auth": True},
    {"name": "lifecycle", "runner": run_body, "seed_factory": lifecycle_seeds, "auth": True},
    {"name": "decrypt", "runner": run_body, "seed_factory": decrypt_seeds, "auth": True},
    {"name": "config", "runner": run_config},
    {"name": "fpe", "runner": run_body, "seed_factory": fpe_seeds,
     "auth": True, "semantic": fpe_semantic},
    {"name": "fpe_batch", "runner": run_body, "seed_factory": fpe_batch_seeds,
     "auth": True, "semantic": fpe_batch_semantic},
    {"name": "fpe_batch_contract", "runner": run_batch_contract, "capability": "fpe",
     "scenario": _fpe_batch_contract_case, "semantic": fpe_batch_contract_semantic},
    {"name": "tokenization", "runner": run_body, "seed_factory": tokenization_seeds,
     "auth": True, "semantic": tokenization_semantic},
    {"name": "tokenization_batch", "runner": run_body, "seed_factory": tokenization_batch_seeds,
     "auth": True, "semantic": tokenization_batch_semantic},
    {"name": "token_batch_contract", "runner": run_batch_contract, "capability": "token",
     "scenario": _token_batch_contract_case, "semantic": token_batch_contract_semantic},
    {"name": "one_time_token", "runner": run_one_time_scenario,
     "scenario": _one_time_single_case,
     "semantic": lambda results: one_time_single_semantic(results, ONE_TIME_TOKEN_PLAINTEXT)},
    {"name": "one_time_token_batch", "runner": run_one_time_scenario,
     "scenario": _one_time_batch_case,
     "semantic": lambda results: one_time_batch_semantic(
         results, ONE_TIME_BATCH_PLAINTEXTS[0], ONE_TIME_BATCH_PLAINTEXTS)},
    {"name": "one_time_token_race", "runner": run_one_time_scenario,
     "scenario": _one_time_race_case, "concurrent": True,
     "semantic": lambda results: one_time_race_semantic(results, ONE_TIME_TOKEN_PLAINTEXT)},
    {"name": "token_batch_duplicate_policy", "runner": run_one_time_scenario,
     "scenario": _token_batch_duplicate_policy_case,
     "semantic": lambda results: token_batch_duplicate_policy_semantic(results, ONE_TIME_TOKEN_PLAINTEXT)},
    {"name": "mac", "runner": run_body, "seed_factory": mac_seeds, "auth": True},
    {"name": "mac_batch", "runner": run_body, "seed_factory": mac_batch_seeds, "auth": True},
    {"name": "mac_batch_contract", "runner": run_batch_contract, "capability": "mac",
     "scenario": _mac_batch_contract_case, "semantic": mac_batch_contract_semantic},
    {"name": "index", "runner": run_body, "seed_factory": index_seeds, "auth": True},
    {"name": "index_batch", "runner": run_body, "seed_factory": index_batch_seeds, "auth": True},
    {"name": "index_batch_transaction", "runner": run_batch_contract, "capability": "index",
     "scenario": _index_batch_transaction_case, "semantic": index_batch_transaction_semantic},
    {"name": "masking", "runner": run_body, "seed_factory": masking_seeds, "auth": True},
    {"name": "masking_batch", "runner": run_body, "seed_factory": masking_batch_seeds, "auth": True},
    {"name": "masking_batch_contract", "runner": run_batch_contract, "capability": "mask",
     "scenario": _masking_batch_contract_case, "semantic": masking_batch_contract_semantic},
    {"name": "commitment", "runner": run_body, "seed_factory": commitment_seeds, "auth": True},
    {"name": "commitment_batch", "runner": run_body, "seed_factory": commitment_batch_seeds, "auth": True},
    {"name": "commitment_batch_contract", "runner": run_batch_contract, "capability": "commitment",
     "scenario": _commitment_batch_contract_case, "semantic": commitment_batch_contract_semantic},
    {"name": "sharing", "runner": run_body, "seed_factory": sharing_seeds, "auth": True},
    {"name": "pubkid", "runner": run_path_param, "require_json_error": False, "endpoints": [
        ("/pub/{}", False),
        ("/keys/properties/{}", True),
        ("/self-test/keys/{}", True),
    ]},
    {"name": "no_body", "runner": run_no_body, "endpoints": [
        ("GET", "/healthz/startup", False, False),
        ("GET", "/healthz/live", False, False),
        ("GET", "/healthz/ready", False, False),
        ("GET", "/metrics", False, False),
        ("GET", "/routes", True, True),
        ("GET", "/remote-routes", True, True),
        ("GET", "/permissions", True, True),
        ("GET", "/keys", True, True),
        ("GET", "/keys/properties", True, True),
        ("GET", "/self-test/init", True, True),
        ("POST", "/keys/reload", True, True),
    ]},
    {"name": "headers", "runner": run_headers, "allowed_status": FRAMEWORK_STATUS},
]

TARGET_NAMES = [t["name"] for t in TARGETS]
