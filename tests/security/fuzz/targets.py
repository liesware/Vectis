import json
import urllib.parse

from config import CONFIG_PATH, CONFIG_SIGN_PATH, build_config_baseline
from mutations import BAD_APIKEYS, NASTY_KIDS, WRONG_METHODS, corrupt_string, mutate_raw, mutate_structured
from oracle import ALLOWED_STATUS, FRAMEWORK_STATUS, _parse, oracle
from reporting import check_and_record, describe, print_progress
from seeds import (
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
    send_message_seeds,
    sharing_seeds,
    sign_body_seeds,
    token_seeds,
    tokenization_batch_seeds,
    tokenization_seeds,
)
from semantics import (
    KID_HEX,
    config_semantic,
    fpe_batch_semantic,
    fpe_semantic,
    internal_encrypt_semantic,
    internal_semantic,
    token_semantic,
    tokenization_batch_semantic,
    tokenization_semantic,
)


def run_body(target, client, rng, args, secrets):
    apikey, unseal = secrets
    seeds = target["seed_factory"](client)
    auth = target.get("auth", False)
    allow_ru = target.get("allow_ru", False)
    semantic = target.get("semantic")
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


# --- seed factories ----------------------------------------------------------
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
    {"name": "tokenization", "runner": run_body, "seed_factory": tokenization_seeds,
     "auth": True, "semantic": tokenization_semantic},
    {"name": "tokenization_batch", "runner": run_body, "seed_factory": tokenization_batch_seeds,
     "auth": True, "semantic": tokenization_batch_semantic},
    {"name": "mac", "runner": run_body, "seed_factory": mac_seeds, "auth": True},
    {"name": "mac_batch", "runner": run_body, "seed_factory": mac_batch_seeds, "auth": True},
    {"name": "index", "runner": run_body, "seed_factory": index_seeds, "auth": True},
    {"name": "index_batch", "runner": run_body, "seed_factory": index_batch_seeds, "auth": True},
    {"name": "masking", "runner": run_body, "seed_factory": masking_seeds, "auth": True},
    {"name": "masking_batch", "runner": run_body, "seed_factory": masking_batch_seeds, "auth": True},
    {"name": "commitment", "runner": run_body, "seed_factory": commitment_seeds, "auth": True},
    {"name": "commitment_batch", "runner": run_body, "seed_factory": commitment_batch_seeds, "auth": True},
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
