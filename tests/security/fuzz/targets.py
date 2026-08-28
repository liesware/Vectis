import json
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

from support.concurrency import run_simultaneously

from client import FuzzClient
from config import (
    CONFIG_PATH,
    CONFIG_SIGN_PATH,
    build_config_baseline,
    configure_time_attestation_offline,
    restore_time_attestation_config,
)
from mutations import BAD_APIKEYS, NASTY_KIDS, WRONG_METHODS, corrupt_string, mutate_raw, mutate_structured
from oracle import ALLOWED_STATUS, FRAMEWORK_STATUS, _parse, oracle
from reporting import check_and_record, describe, print_progress
from seeds import (
    batch_contract_context,
    commitment_batch_seeds,
    commitment_seeds,
    COMPACT_SIGNATURE_MESSAGE_HASH,
    compact_signature_context,
    crypto_semantics_context,
    decrypt_seeds,
    fpe_batch_seeds,
    fpe_seeds,
    index_batch_seeds,
    index_seeds,
    internal_encrypt_seeds,
    internal_seeds,
    keys_seeds,
    lifecycle_contract_setup,
    lifecycle_seeds,
    mac_batch_seeds,
    mac_seeds,
    masking_batch_seeds,
    masking_seeds,
    mutate_base64url,
    mutate_compact_signature_segment,
    mutate_hex,
    mutate_share_tag,
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
    FPE_PLAINTEXT,
    INTERNAL_SEED_PLAINTEXT,
    MAC_PLAINTEXTS,
    MASKING_PLAINTEXTS,
    ONE_TIME_TOKENIZATION_PROFILE,
    SHARING_PLAINTEXT,
    TOKENIZATION_PROFILE,
    TOKEN_BATCH_PLAINTEXTS,
    TOKEN_PLAINTEXT,
    _response_items,
    commitment_batch_contract_semantic,
    commitment_randomness_semantic,
    compact_signature_integrity_semantic,
    config_semantic,
    fpe_batch_semantic,
    fpe_batch_contract_semantic,
    fpe_semantic,
    internal_encrypt_semantic,
    internal_semantic,
    index_batch_transaction_semantic,
    index_determinism_semantic,
    lifecycle_contract_semantic,
    mac_batch_contract_semantic,
    mac_determinism_semantic,
    masking_batch_contract_semantic,
    masking_policy_semantic,
    one_time_batch_semantic,
    one_time_race_semantic,
    one_time_single_semantic,
    reject_malformed_body_semantic,
    token_semantic,
    token_batch_duplicate_policy_semantic,
    token_batch_contract_semantic,
    tokenization_batch_semantic,
    tokenization_semantic,
    sharing_integrity_semantic,
    time_attest_source_unavailable_semantic,
)

HTTP_MAX_SIZE = 2 * 1024 * 1024


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
    client.clear_timings()  # drop setup-phase timings so they don't attach to case 0
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
    client.clear_timings()  # drop setup-phase timings so they don't attach to case 0
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
    client.clear_timings()  # drop setup-phase timings so they don't attach to case 0
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


def _json_body_with_size(size):
    prefix = b'{"padding":"'
    suffix = b'"}'
    if size < len(prefix) + len(suffix):
        raise ValueError("requested JSON body size is too small")
    return prefix + (b"a" * (size - len(prefix) - len(suffix))) + suffix


def _protocol_findings(status, body, expected, apikey, unseal):
    findings = oracle(
        status,
        body,
        apikey,
        unseal,
        {expected},
        False,
        require_json_error=expected != 405,
    )
    if status != expected:
        findings.append(f"protocol contract expected HTTP {expected}, got {status}")
    if expected == 413 and _parse(body) != {"error": "request body exceeds maximum allowed size"}:
        findings.append("protocol limit response did not use the exact 413 error contract")
    return findings


def run_http_protocol(target, client, _rng, args, secrets):
    apikey, unseal = secrets
    counters = {"passed": 0, "failed": 0}
    client.clear_timings()

    for index, (label, size, expected) in enumerate(
        (
            ("body-at-limit", HTTP_MAX_SIZE, 400),
            ("body-over-limit", HTTP_MAX_SIZE + 1, 413),
        )
    ):
        status, body = client.request(
            "POST",
            "/sign/verification",
            data=_json_body_with_size(size),
            headers={"Content-Type": "application/json"},
        )
        findings = _protocol_findings(status, body, expected, apikey, unseal)
        description = {"case": label, "path": "/sign/verification", "body_bytes": size, "status": status}
        if check_and_record(target["name"], client, args, index, status, findings, description, counters):
            return counters

    endpoints = (
        ("/keys", True),
        ("/sign/verification", False),
        (f"/fpe/encrypt/{KID_HEX}", True),
        ("/token/decode", True),
        ("/shares/combine", True),
    )
    variants = (
        ("content-type-text", "POST", b"{}", {"Content-Type": "text/plain"}, 415),
        ("content-type-missing", "POST", b"{}", {}, 415),
        ("empty-json-body", "POST", b"", {"Content-Type": "application/json"}, 400),
        ("wrong-method", None, None, None, 405),
    )
    for index in range(args.iterations):
        path, auth = endpoints[index % len(endpoints)]
        label, method, data, headers, expected = variants[(index // len(endpoints)) % len(variants)]
        if method is None:
            # Axum maps HEAD to an existing GET route and suppresses the body.
            # Only methods without a registered route are protocol violations.
            methods = [
                candidate
                for candidate in WRONG_METHODS
                if not (path == "/keys" and candidate in {"GET", "HEAD"})
            ]
            method = methods[(index // (len(endpoints) * len(variants))) % len(methods)]
            data = b"{}"
            headers = {"Content-Type": "application/json"}
        status, body = client.request(method, path, data=data, headers=headers, auth=auth)
        findings = _protocol_findings(status, body, expected, apikey, unseal)
        description = {
            "case": label,
            "method": method,
            "path": path,
            "body_bytes": len(data or b""),
            "status": status,
        }
        if check_and_record(target["name"], client, args, index + 2, status, findings, description, counters):
            break
        print_progress(target["name"], index, args, counters)
    return counters


def run_no_body(target, client, rng, args, secrets):
    apikey, unseal = secrets
    endpoints = target["endpoints"]
    counters = {"passed": 0, "failed": 0}
    client.clear_timings()  # drop setup-phase timings so they don't attach to case 0
    for index in range(args.iterations):
        method, path, auth, require_json_error, check_latency = rng.choice(endpoints)
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
        if check_and_record(
            target["name"],
            client,
            args,
            index,
            status,
            findings,
            description,
            counters,
            check_latency=check_latency,
        ):
            break
        print_progress(target["name"], index, args, counters)
    return counters


def run_config(target, client, rng, args, secrets):
    apikey, unseal = secrets
    counters = {"passed": 0, "failed": 0}
    baseline_cfg, baseline_sig = build_config_baseline()
    client.clear_timings()  # drop setup-phase timings so they don't attach to case 0
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


def run_time_attest_offline(target, client, _rng, args, secrets):
    apikey, unseal = secrets
    counters = {"passed": 0, "failed": 0}
    snapshot = configure_time_attestation_offline(client)
    try:
        client.clear_timings()  # drop setup-phase timings so they don't attach to case 0
        for index in range(args.iterations):
            # `/time/attest` admits one authorized request per second. This target
            # tests source failure, not rate limiting, so keep each attempt eligible.
            time.sleep(1.05)
            ready_before = client.get_status("/healthz/ready")
            status, body = client.request("POST", "/time/attest", auth=True)
            ready_after = client.get_status("/healthz/ready")
            case = {
                "response": (status, body),
                "ready_before": ready_before,
                "ready_after": ready_after,
            }
            findings = oracle(status, body, apikey, unseal, {502}, False)
            findings.extend(time_attest_source_unavailable_semantic(case))
            description = {
                "scenario": target["name"],
                "status": status,
                "ready_before": ready_before,
                "ready_after": ready_after,
            }
            if check_and_record(target["name"], client, args, index, status, findings, description, counters):
                break
            print_progress(target["name"], index, args, counters)
    finally:
        restore_time_attestation_config(client, snapshot)
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
        worker_client = FuzzClient(client.base_url, client.apikey, timing=client.timing)
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
        client.clear_timings()  # drop setup-phase timings so they don't attach to case 0
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
    client.clear_timings()  # drop setup-phase timings so they don't attach to case 0
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


def _mac_determinism_case(client, context, index):
    plaintext = MAC_PLAINTEXTS[0]
    first = client.post_json(
        f"/mac/{context['kid']}",
        {"ref": f"mac-determinism-{index}-0", "profile": context["profile"], "plaintext": plaintext},
        auth=True,
    )
    second = client.post_json(
        f"/mac/{context['kid']}",
        {"ref": f"mac-determinism-{index}-1", "profile": context["profile"], "plaintext": plaintext},
        auth=True,
    )
    digest = (_parse(first[1]) or {}).get("digest")
    verified = client.post_json(
        "/mac/verify",
        {"ref": f"mac-determinism-verify-{index}", "kid": context["kid"], "profile": context["profile"], "plaintext": plaintext, "digest": digest},
        auth=True,
    )
    changed_plaintext = client.post_json(
        "/mac/verify",
        {"ref": f"mac-determinism-plaintext-{index}", "kid": context["kid"], "profile": context["profile"], "plaintext": "5111111111111111", "digest": digest},
        auth=True,
    )
    changed_digest = client.post_json(
        "/mac/verify",
        {"ref": f"mac-determinism-digest-{index}", "kid": context["kid"], "profile": context["profile"], "plaintext": plaintext, "digest": mutate_hex(digest)},
        auth=True,
    )
    return {"refs": [f"mac-determinism-{index}-0", f"mac-determinism-{index}-1"], "responses": [first, second, verified, changed_plaintext, changed_digest]}


def _index_determinism_case(client, context, index):
    plaintext = f"{MAC_PLAINTEXTS[0]}-{index}"
    first = client.post_json(
        f"/index/{context['kid']}",
        {"ref": f"index-determinism-{index}-0", "profile": context["profile"], "plaintext": plaintext},
        auth=True,
    )
    second = client.post_json(
        f"/index/{context['kid']}",
        {"ref": f"index-determinism-{index}-1", "profile": context["profile"], "plaintext": plaintext},
        auth=True,
    )
    matched = client.post_json(
        "/index/verify",
        {"ref": f"index-determinism-match-{index}", "kid": context["kid"], "profile": context["profile"], "plaintext": plaintext},
        auth=True,
    )
    changed = client.post_json(
        "/index/verify",
        {"ref": f"index-determinism-changed-{index}", "kid": context["kid"], "profile": context["profile"], "plaintext": f"{plaintext}x"},
        auth=True,
    )
    return {"refs": [f"index-determinism-{index}-0", f"index-determinism-{index}-1"], "responses": [first, second, matched, changed]}


def _masking_policy_case(client, context, index):
    plaintext = MASKING_PLAINTEXTS[index % len(MASKING_PLAINTEXTS)]
    response = client.post_json_with_headers(
        f"/mask/{context['kid']}",
        {"ref": f"mask-policy-{index}", "profile": context["profile"], "plaintext": plaintext},
        auth=True,
    )
    return {"refs": [f"mask-policy-{index}"], "plaintext": plaintext, "expected": "*" * (len(plaintext) - 4) + plaintext[-4:], "response": response, "responses": [response[:2]]}


def _commitment_randomness_case(client, context, index):
    plaintext = COMMITMENT_PLAINTEXTS[0]
    first = client.post_json(
        f"/commit/{context['kid']}",
        {"ref": f"commitment-randomness-{index}-0", "profile": context["profile"], "plaintext": plaintext},
        auth=True,
    )
    second = client.post_json(
        f"/commit/{context['kid']}",
        {"ref": f"commitment-randomness-{index}-1", "profile": context["profile"], "plaintext": plaintext},
        auth=True,
    )
    material = _parse(first[1]) or {}
    base = {"kid": context["kid"], "profile": context["profile"], "plaintext": plaintext, "opening": material.get("opening"), "commitment": material.get("commitment")}
    verified = client.post_json("/commit/verify", {"ref": f"commitment-randomness-verify-{index}", **base}, auth=True)
    changed_opening = client.post_json("/commit/verify", {"ref": f"commitment-randomness-opening-{index}", **base, "opening": mutate_base64url(material.get("opening"))}, auth=True)
    changed_commitment = client.post_json("/commit/verify", {"ref": f"commitment-randomness-commitment-{index}", **base, "commitment": mutate_hex(material.get("commitment"))}, auth=True)
    return {"refs": [f"commitment-randomness-{index}-0", f"commitment-randomness-{index}-1"], "responses": [first, second, verified, changed_opening, changed_commitment]}


def _sharing_integrity_case(client, context, index):
    split_input = {"profile": context["profile"], "plaintext": SHARING_PLAINTEXT}
    first = client.post_json(f"/shares/split/{context['kid']}", split_input, auth=True)
    second = client.post_json(f"/shares/split/{context['kid']}", split_input, auth=True)
    first_shares = (_parse(first[1]) or {}).get("shares", [])
    second_shares = (_parse(second[1]) or {}).get("shares", [])
    def combine(label, shares):
        return client.post_json("/shares/combine", {"kid": context["kid"], "profile": context["profile"], "shares": shares}, auth=True)
    control = combine("control", first_shares[:3])
    threshold = combine("threshold", first_shares[:2])
    duplicate = combine("duplicate", [first_shares[0], first_shares[0], first_shares[1]] if len(first_shares) >= 2 else first_shares)
    tampered = combine("tampered", [mutate_share_tag(first_shares[0]), *first_shares[1:3]] if len(first_shares) >= 3 else first_shares)
    mixed = combine("mixed", [*first_shares[:2], second_shares[2]] if len(first_shares) >= 2 and len(second_shares) >= 3 else first_shares)
    return {
        "refs": [f"sharing-integrity-{index}"],
        "plaintext": SHARING_PLAINTEXT,
        "responses": [first, second, control, threshold, duplicate, tampered, mixed],
        "checks": [control, threshold, duplicate, tampered, mixed],
    }


def run_crypto_semantics(target, client, _rng, args, secrets):
    apikey, unseal = secrets
    context = crypto_semantics_context(client, target["capability"])
    counters = {"passed": 0, "failed": 0}
    client.clear_timings()  # drop setup-phase timings so they don't attach to case 0
    for index in range(args.iterations):
        case = target["scenario"](client, context, index)
        responses = case["responses"]
        findings = []
        for status, body in responses:
            findings.extend(oracle(status, body, apikey, unseal, ALLOWED_STATUS, False))
        findings.extend(target["semantic"](case, context))
        status = 0 if any(response_status == 0 for response_status, _body in responses) else 200
        description = {"scenario": target["name"], "kid": context["kid"], "refs": case["refs"], "statuses": [response_status for response_status, _body in responses]}
        if check_and_record(target["name"], client, args, index, status, findings, description, counters):
            break
        print_progress(target["name"], index, args, counters)
    return counters


def _compact_signature_integrity_case(client, context, index):
    checks = []
    for label, segment_index in (("control", None), ("header", 0), ("payload", 1), ("eddsa", 2), ("ml_dsa", 3)):
        signed_status, signed_body = client.post_json(
            f"/sign/{context['kid']}",
            {"message_hash": COMPACT_SIGNATURE_MESSAGE_HASH},
            auth=True,
        )
        signed = _parse(signed_body)
        signature = signed.get("signature") if isinstance(signed, dict) else None
        if segment_index is not None:
            try:
                signature = mutate_compact_signature_segment(signature, segment_index)
            except ValueError:
                signature = None
        verify_status, verify_body = client.post_json(
            "/sign/verification",
            {"kid": context["kid"], "signature": signature},
        )
        checks.append((label, signed_status, signed_body, verify_status, verify_body, signature))
    return {
        "refs": [f"compact-signature-{index}"],
        "checks": checks,
        "message_hash_hex": COMPACT_SIGNATURE_MESSAGE_HASH["hex"],
        "responses": [response for _label, signed_status, signed_body, verify_status, verify_body, _signature in checks for response in ((signed_status, signed_body), (verify_status, verify_body))],
    }


def run_compact_signature_integrity(target, client, _rng, args, secrets):
    apikey, unseal = secrets
    context = compact_signature_context(client)
    counters = {"passed": 0, "failed": 0}
    client.clear_timings()  # drop setup-phase timings so they don't attach to case 0
    for index in range(args.iterations):
        case = _compact_signature_integrity_case(client, context, index)
        findings = []
        for status, body in case["responses"]:
            findings.extend(oracle(status, body, apikey, unseal, ALLOWED_STATUS, False))
        findings.extend(compact_signature_integrity_semantic(case, context))
        status = 0 if any(response_status == 0 for response_status, _body in case["responses"]) else 200
        description = {
            "scenario": target["name"],
            "kid": context["kid"],
            "statuses": [response_status for response_status, _body in case["responses"]],
        }
        if check_and_record(target["name"], client, args, index, status, findings, description, counters):
            break
        print_progress(target["name"], index, args, counters)
    return counters


def _lifecycle_new_requests(context, state, index):
    kid = context["kids"][state]
    profiles = context["profiles"][state]
    suffix = f"lifecycle-{state}-{index}"
    return {
        "fpe_encrypt": (f"/fpe/encrypt/{kid}", {"ref": f"{suffix}-fpe", "profile": profiles["fpe"], "plaintext": FPE_PLAINTEXT}, True),
        "token_encode": (f"/token/encode/{kid}", {"ref": f"{suffix}-token", "profile": profiles["token"], "plaintext": TOKEN_PLAINTEXT, "metadata": {}}, True),
        "mac_create": (f"/mac/{kid}", {"ref": f"{suffix}-mac", "profile": profiles["mac"], "plaintext": MAC_PLAINTEXTS[0]}, True),
        "index_create": (f"/index/{kid}", {"ref": f"{suffix}-index", "profile": profiles["mac"], "plaintext": MAC_PLAINTEXTS[0]}, True),
        "commitment_create": (f"/commit/{kid}", {"ref": f"{suffix}-commitment", "profile": profiles["commitment"], "plaintext": COMMITMENT_PLAINTEXTS[0]}, True),
        "share_split": (f"/shares/split/{kid}", {"profile": profiles["sharing"], "plaintext": SHARING_PLAINTEXT}, True),
        "sign": (f"/sign/{kid}", {"message_hash": {"alg": "BLAKE2b(256)", "hex": "cd" * 32}}, True),
        "internal_encrypt": (f"/message/internal/encrypt/{kid}", {"plaintext": INTERNAL_SEED_PLAINTEXT}, True),
    }


def _post_lifecycle_request(client, path, body, auth):
    return client.post_json(path, body, auth=auth)


def _prepare_lifecycle_material(client, context, state, index):
    requests = _lifecycle_new_requests(context, state, index)
    records = []
    outputs = {}
    for operation, (path, body, auth) in requests.items():
        status, response = _post_lifecycle_request(client, path, body, auth)
        records.append({"state": "active", "phase": "prepare", "operation": operation, "expected": "allowed", "status": status, "body": response})
        outputs[operation] = _parse(response) if status == 200 else None
    return records, outputs


def _lifecycle_historical_requests(context, state, index, outputs):
    kid = context["kids"][state]
    profiles = context["profiles"][state]
    suffix = f"lifecycle-{state}-{index}"
    fpe = outputs.get("fpe_encrypt") or {}
    token = outputs.get("token_encode") or {}
    mac = outputs.get("mac_create") or {}
    commitment = outputs.get("commitment_create") or {}
    split = outputs.get("share_split") or {}
    signature = outputs.get("sign") or {}
    internal = outputs.get("internal_encrypt") or {}
    return {
        "fpe_decrypt": ("/fpe/decrypt", {"ref": f"{suffix}-fpe-decrypt", "kid": kid, "profile": profiles["fpe"], "ciphertext": fpe.get("ciphertext")}, True),
        "token_decode": ("/token/decode", {"ref": f"{suffix}-token-decode", "kid": kid, "profile": profiles["token"], "token": token.get("token")}, True),
        "mac_verify": ("/mac/verify", {"ref": f"{suffix}-mac-verify", "kid": kid, "profile": profiles["mac"], "plaintext": MAC_PLAINTEXTS[0], "digest": mac.get("digest")}, True),
        "index_verify": ("/index/verify", {"ref": f"{suffix}-index-verify", "kid": kid, "profile": profiles["mac"], "plaintext": MAC_PLAINTEXTS[0]}, True),
        "commitment_verify": ("/commit/verify", {"ref": f"{suffix}-commitment-verify", "kid": kid, "profile": profiles["commitment"], "plaintext": COMMITMENT_PLAINTEXTS[0], "opening": commitment.get("opening"), "commitment": commitment.get("commitment")}, True),
        "share_combine": ("/shares/combine", {"kid": kid, "profile": profiles["sharing"], "shares": split.get("shares", [])[:3]}, True),
        "sign_verify": ("/sign/verification", signature, False),
        "internal_decrypt": ("/message/internal/decrypt", internal, True),
        "mask": (f"/mask/{kid}", {"ref": f"{suffix}-mask", "profile": profiles["mask"], "plaintext": MASKING_PLAINTEXTS[0]}, True),
    }


def _run_lifecycle_requests(client, state, phase, requests, expected):
    records = []
    for operation, (path, body, auth) in requests.items():
        status, response = _post_lifecycle_request(client, path, body, auth)
        records.append({"state": state, "phase": phase, "operation": operation, "expected": expected, "status": status, "body": response})
    return records


def _transition_lifecycle(client, kid, state):
    return client.post_json(
        f"/lifecycle/{kid}",
        {"status": state, "reason": f"fuzz lifecycle {state}"},
        auth=True,
    )


def _lifecycle_contract_case(client, context, index):
    records = []
    material = {}
    for state in context["kids"]:
        prepared, material[state] = _prepare_lifecycle_material(client, context, state, index)
        records.extend(prepared)

    for state in ("retired", "disabled", "compromised", "destroyed"):
        kid = context["kids"][state]
        status, body = _transition_lifecycle(client, kid, state)
        records.append({"state": state, "phase": "transition", "operation": "lifecycle_transition", "expected": "allowed", "status": status, "body": body})
        historical = _lifecycle_historical_requests(context, state, index, material[state])
        production = _lifecycle_new_requests(context, state, index)
        records.extend(_run_lifecycle_requests(client, state, "historical", historical, "allowed" if state == "retired" else "rejected"))
        records.extend(_run_lifecycle_requests(client, state, "production", production, "rejected"))
        pub_status, pub_body = client.request("GET", f"/pub/{kid}")
        records.append({"state": state, "phase": "public", "operation": "public_key", "expected": "rejected", "status": pub_status, "body": pub_body})
    return records


def run_lifecycle_contract(target, client, _rng, args, secrets):
    apikey, unseal = secrets
    counters = {"passed": 0, "failed": 0}
    # Provision every iteration's keys and profiles once (one cargo-signed config
    # reload for the whole run) instead of rebuilding the context per iteration.
    contexts = lifecycle_contract_setup(client, args.iterations)
    client.clear_timings()  # drop setup-phase timings so they don't attach to case 0
    for index, context in enumerate(contexts):
        records = _lifecycle_contract_case(client, context, index)
        findings = []
        for record in records:
            findings.extend(oracle(record["status"], record["body"], apikey, unseal, ALLOWED_STATUS, False))
        findings.extend(lifecycle_contract_semantic(records))
        status = 0 if any(record["status"] == 0 for record in records) else 200
        description = {
            "scenario": target["name"],
            "kids": context["kids"],
            "results": [
                {key: record[key] for key in ("state", "phase", "operation", "status")}
                for record in records
            ],
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
    {"name": "compact_signature_integrity", "runner": run_compact_signature_integrity},
    {"name": "lifecycle", "runner": run_body, "seed_factory": lifecycle_seeds, "auth": True},
    {"name": "lifecycle_contract", "runner": run_lifecycle_contract},
    {"name": "decrypt", "runner": run_body, "seed_factory": decrypt_seeds, "auth": True},
    {"name": "config", "runner": run_config},
    {"name": "time_attest_offline", "runner": run_time_attest_offline},
    {"name": "http_protocol", "runner": run_http_protocol},
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
    {"name": "mac_determinism", "runner": run_crypto_semantics, "capability": "mac",
     "scenario": _mac_determinism_case, "semantic": mac_determinism_semantic},
    {"name": "index", "runner": run_body, "seed_factory": index_seeds, "auth": True},
    {"name": "index_batch", "runner": run_body, "seed_factory": index_batch_seeds, "auth": True},
    {"name": "index_batch_transaction", "runner": run_batch_contract, "capability": "index",
     "scenario": _index_batch_transaction_case, "semantic": index_batch_transaction_semantic},
    {"name": "index_determinism", "runner": run_crypto_semantics, "capability": "index",
     "scenario": _index_determinism_case, "semantic": index_determinism_semantic},
    {"name": "masking", "runner": run_body, "seed_factory": masking_seeds, "auth": True},
    {"name": "masking_batch", "runner": run_body, "seed_factory": masking_batch_seeds, "auth": True},
    {"name": "masking_batch_contract", "runner": run_batch_contract, "capability": "mask",
     "scenario": _masking_batch_contract_case, "semantic": masking_batch_contract_semantic},
    {"name": "masking_policy", "runner": run_crypto_semantics, "capability": "mask",
     "scenario": _masking_policy_case, "semantic": masking_policy_semantic},
    {"name": "commitment", "runner": run_body, "seed_factory": commitment_seeds, "auth": True},
    {"name": "commitment_batch", "runner": run_body, "seed_factory": commitment_batch_seeds, "auth": True},
    {"name": "commitment_batch_contract", "runner": run_batch_contract, "capability": "commitment",
     "scenario": _commitment_batch_contract_case, "semantic": commitment_batch_contract_semantic},
    {"name": "commitment_randomness", "runner": run_crypto_semantics, "capability": "commitment",
     "scenario": _commitment_randomness_case, "semantic": commitment_randomness_semantic},
    {"name": "sharing", "runner": run_body, "seed_factory": sharing_seeds, "auth": True},
    {"name": "sharing_integrity", "runner": run_crypto_semantics, "capability": "sharing",
     "scenario": _sharing_integrity_case, "semantic": sharing_integrity_semantic},
    {"name": "pubkid", "runner": run_path_param, "require_json_error": False, "endpoints": [
        ("/pub/{}", False),
        ("/keys/properties/{}", True),
        ("/self-test/keys/{}", True),
    ]},
    {"name": "no_body", "runner": run_no_body, "endpoints": [
        ("GET", "/healthz/startup", False, False, True),
        ("GET", "/healthz/live", False, False, True),
        ("GET", "/healthz/ready", False, False, True),
        ("GET", "/metrics", False, False, True),
        ("GET", "/routes", True, True, True),
        ("GET", "/remote-routes", True, True, True),
        ("GET", "/permissions", True, True, True),
        ("GET", "/keys", True, True, True),
        ("GET", "/keys/properties", True, True, True),
        ("GET", "/self-test/init", True, True, True),
        # Reload performs key validation and may legitimately exceed the
        # malformed-input response budget on shared CI runners.
        ("POST", "/keys/reload", True, True, False),
    ]},
    {"name": "headers", "runner": run_headers, "allowed_status": FRAMEWORK_STATUS},
]

TARGET_NAMES = [t["name"] for t in TARGETS]
