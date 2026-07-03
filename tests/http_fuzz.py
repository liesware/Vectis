#!/usr/bin/env python3
import argparse
import atexit
import copy
import json
import random
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from test_config import require_apikey

DEFAULT_BASE_URL = "http://127.0.0.1:3000"
CONFIG_PATH = Path("config.json")
CONFIG_SIGN_PATH = Path("config_sign.json")
UNSEAL_KEY_FILE = Path(".unseal_key")
CORPUS_DIR = Path(__file__).resolve().parent / "fuzz-corpus"

ALLOWED_STATUS = {200, 400, 401, 403, 404, 413}
FRAMEWORK_STATUS = ALLOWED_STATUS | {405, 415}
REMOTE_UNREACHABLE_MARKER = "final app can't be reached"
KID_HEX = "a" * 64
RECIPIENT_HEX = "b" * 64
INTERNAL_SEED_PLAINTEXT = "fuzz seed plaintext"

# Minimal, policy-safe key requests (one per crypto profile) used to CREATE seed
# keys. Creating with only tag+profile works under both crypto policies, and the
# different profiles exercise AES-256/GCM (12-byte nonce) vs ChaCha20 (24-byte),
# and Ed448/X448 vs Ed25519/X25519.
KEY_CASES = [
    {"tag": "fuzz-performance", "profile": "hybrid-performance-v1"},
    {"tag": "fuzz-high-assurance", "profile": "hybrid-high-assurance-v1"},
    {"tag": "fuzz-long-term", "profile": "hybrid-long-term-v1"},
]

# Full-shape request used as the seed for the /keys fuzz target (all fields
# present so mutations can hit every one).
KEY_TARGET_SEED = {
    "tag": "fuzz",
    "profile": "hybrid-performance-v1",
    "hash_algorithm": "BLAKE2b(256)",
    "symmetric_algorithm": "ChaCha20Poly1305",
    "eddsa_algorithm": "Ed25519",
    "xecdh_algorithm": "X25519",
    "ml_dsa_variant": "ML-DSA-44",
    "ml_kem_variant": "ML-KEM-512",
}

BAD_VALUES = [
    None,
    True,
    False,
    0,
    -1,
    2**70,
    -(2**70),
    1.5,
    "",
    "A" * 20000,
    "\x00\x01\x02",
    "../../../etc/passwd",
    "🔥" * 500,
    [],
    {},
    [1] * 2000,
    {"x": {"y": {"z": {}}}},
    float("nan"),
    float("inf"),
]

NEAR_MISS_ENUMS = [
    "Ed25518",
    "Ed449",
    "ML-DSA-45",
    "ML-DSA-43",
    "ML-KEM-513",
    "ChaCha20Poly1306",
    "X25518",
    "X449",
    "AES-257/GCM",
    "AES-128/CBC",
    "SHA-385",
    "BLAKE2b(257)",
]

NUMERIC_EDGE_STRINGS = ["1e400", "-0", "007", "0x1F", "1_000", str(2**64), "NaN"]

NASTY_KIDS = [
    "",
    "..",
    "../..",
    "%2e%2e",
    "..%2f..",
    "\x00\x00",
    "🔥",
    "a" * 10000,
    "not-hex",
    "z" * 64,
    "0" * 63,
    "0" * 65,
    "0" * 64,
    " ",
    "null",
]

BAD_APIKEYS = [
    "",
    "x",
    "00" * 32,
    "not-a-hex-key",
    "café" * 10,
    "a" * 5000,
    "0" * 63,
    "0" * 65,
]

WRONG_METHODS = ["GET", "PUT", "DELETE", "PATCH", "HEAD"]


class FuzzClient:
    def __init__(self, base_url, apikey):
        self.base_url = base_url.rstrip("/")
        self.apikey = apikey

    def request(self, method, path, data=None, headers=None, auth=False):
        request_headers = dict(headers or {})
        if auth:
            request_headers["X-API-Key"] = self.apikey
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            headers=request_headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                return response.status, response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as err:
            return err.code, err.read().decode("utf-8", "replace")
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
            return 0, ""

    def get_status(self, path):
        status, _ = self.request("GET", path)
        return status

    def post_json(self, path, obj, auth=False):
        data = json.dumps(obj).encode("utf-8")
        return self.request(
            "POST", path, data, {"Content-Type": "application/json"}, auth
        )

    def post_raw(self, path, raw, auth=False):
        return self.request(
            "POST", path, raw, {"Content-Type": "application/json"}, auth
        )


# --- mutation engine ---------------------------------------------------------


def all_paths(node, prefix=()):
    paths = [prefix]
    if isinstance(node, dict):
        for key, value in node.items():
            paths.extend(all_paths(value, prefix + (key,)))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            paths.extend(all_paths(value, prefix + (index,)))
    return paths


def get_at(node, path):
    for step in path:
        node = node[step]
    return node


def set_at(node, path, value):
    if not path:
        return value
    parent = get_at(node, path[:-1])
    parent[path[-1]] = value
    return node


def del_at(node, path):
    if not path:
        return node
    parent = get_at(node, path[:-1])
    key = path[-1]
    if isinstance(parent, dict):
        parent.pop(key, None)
    elif isinstance(parent, list) and isinstance(key, int) and 0 <= key < len(parent):
        parent.pop(key)
    return node


def corrupt_string(value, rng):
    if not value:
        return rng.choice(["", "x", "\x00"])
    op = rng.choice(["flip", "truncate", "append", "huge", "nullbyte", "odd"])
    if op == "flip":
        i = rng.randrange(len(value))
        return value[:i] + rng.choice("zZ!@#\x00") + value[i + 1 :]
    if op == "truncate":
        return value[: rng.randrange(len(value))]
    if op == "append":
        return value + rng.choice(["==", "..", "%%", "\x00"]) * 3
    if op == "huge":
        return value * 50
    if op == "nullbyte":
        i = rng.randrange(len(value))
        return value[:i] + "\x00" + value[i:]
    return value[:-1] if len(value) > 1 else value + "a"


def looks_hex(value):
    return (
        isinstance(value, str)
        and len(value) >= 2
        and all(c in "0123456789abcdefABCDEF" for c in value)
    )


def domain_mutate(key, value, rng):
    key_lower = str(key).lower()
    if "alg" in key_lower or "variant" in key_lower or "cipher" in key_lower:
        return rng.choice(NEAR_MISS_ENUMS)
    if looks_hex(value):
        op = rng.choice(["drop1", "add1", "double", "halve", "oddbyte"])
        if op == "drop1":
            return value[:-1]
        if op == "add1":
            return value + "a"
        if op == "double":
            return value + value
        if op == "halve":
            return value[: len(value) // 2]
        return value + "abc"
    return rng.choice(NUMERIC_EDGE_STRINGS)


def mutate_structured(seed, rng):
    node = json.loads(json.dumps(seed))
    for _ in range(rng.randint(1, 3)):
        paths = all_paths(node)
        path = rng.choice(paths)
        if path and rng.random() < 0.4:
            node = del_at(node, path)
            continue
        current = get_at(node, path) if path else node
        last_key = path[-1] if path else None
        roll = rng.random()
        if isinstance(current, str) and last_key is not None and roll < 0.3:
            new_value = domain_mutate(last_key, current, rng)
        elif isinstance(current, str) and roll < 0.7:
            new_value = corrupt_string(current, rng)
        else:
            new_value = copy.deepcopy(rng.choice(BAD_VALUES))
        node = set_at(node, path, new_value)
    return node


def mutate_raw(seed, rng):
    data = json.dumps(seed).encode("utf-8")
    op = rng.choice(
        ["truncate", "flip", "append", "prepend", "nullbyte", "dupkey", "repeat"]
    )
    if op == "truncate":
        return data[: rng.randrange(len(data))]
    if op == "flip":
        i = rng.randrange(len(data))
        buffer = bytearray(data)
        buffer[i] ^= rng.randint(1, 255)
        return bytes(buffer)
    if op == "append":
        return data + rng.choice([b"}}}", b"\x00\x00", b",,,", b"[]"])
    if op == "prepend":
        return rng.choice([b"\x00", b"[", b"{"]) + data
    if op == "nullbyte":
        i = rng.randrange(len(data))
        return data[:i] + b"\x00" + data[i:]
    if op == "dupkey":
        obj = _parse(data.decode("utf-8", "replace"))
        if isinstance(obj, dict) and obj:
            key = rng.choice(list(obj.keys()))
            duplicate = json.dumps({key: obj[key]})[1:-1]
            return data.replace(b"{", b"{" + duplicate.encode("utf-8") + b",", 1)
        return data + b',"dup":"dup"'
    return data * rng.randint(2, 5)


# --- oracle ------------------------------------------------------------------


def _parse(body):
    try:
        return json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return None


def oracle(status, body, apikey, unseal, allowed_status, allow_ru, require_json_error=True):
    findings = []
    if status == 0:
        findings.append("connection failed (possible crash or hang)")
        return findings
    if status not in allowed_status:
        known_unreachable = (
            status == 500
            and allow_ru
            and REMOTE_UNREACHABLE_MARKER in body
        )
        if not known_unreachable:
            findings.append(f"unexpected status {status}")
    if require_json_error and 400 <= status < 500:
        parsed = _parse(body)
        if isinstance(parsed, dict):
            extra = sorted(set(parsed.keys()) - {"error"})
            if extra:
                findings.append(f"4xx error body has extra keys: {extra}")
        else:
            findings.append("4xx body is not a JSON error object")
    for name, secret in (("apikey", apikey), ("unseal-key", unseal)):
        if secret and secret in body:
            findings.append(f"possible {name} leak in response body")
    return findings


# --- semantic oracles --------------------------------------------------------


def token_semantic(sent_value, seed, status, body):
    if sent_value is None or sent_value == seed:
        return []
    if status != 200:
        return []
    parsed = _parse(body)
    if isinstance(parsed, dict) and parsed.get("valid") == "ok":
        return ["SEMANTIC: verification bypass (mutated token still valid=ok)"]
    return []


CRYPTO_MESSAGE_FIELDS = ("ctx", "nonce", "aad", "variant")


def internal_semantic(sent_value, seed, status, body):
    findings = []
    if status == 200:
        parsed = _parse(body)
        returned = parsed.get("plaintext") if isinstance(parsed, dict) else None
        if returned != INTERNAL_SEED_PLAINTEXT:
            findings.append(
                "SEMANTIC: decrypt returned unexpected plaintext for a 200 response"
            )
        if isinstance(sent_value, dict) and _crypto_fields_differ(sent_value, seed):
            findings.append(
                "SEMANTIC: AEAD bypass (mutated cipher field accepted with 200)"
            )
    return findings


def _crypto_fields_differ(sent_value, seed):
    sent_msg = sent_value.get("message")
    seed_msg = seed.get("message")
    if not isinstance(sent_msg, dict) or not isinstance(seed_msg, dict):
        return True
    return any(sent_msg.get(field) != seed_msg.get(field) for field in CRYPTO_MESSAGE_FIELDS)


CONFIG_LOADED_COUNTS = ("routes_loaded", "remote_routes_loaded", "clients_loaded")


def config_semantic(status, body):
    # The baseline signed config is empty, so a legitimate 200 reload must load
    # zero content. Comparing raw bytes would false-positive on canonically
    # equivalent inputs (serde defaults, key order); comparing the observable
    # loaded counts catches a real integrity break: altered content accepted
    # under the baseline signature.
    if status != 200:
        return []
    parsed = _parse(body)
    if not isinstance(parsed, dict) or parsed.get("status") != "reloaded":
        return []
    if any(parsed.get(count) for count in CONFIG_LOADED_COUNTS):
        return ["SEMANTIC: config integrity bypass (altered content loaded under baseline signature)"]
    return []


# --- reporting ---------------------------------------------------------------


def save_crash(target, seed, index, description, findings):
    CORPUS_DIR.mkdir(parents=True, exist_ok=True)
    artifact = CORPUS_DIR / f"crash_{target}_{seed}_{index}.json"
    payload = {
        "target": target,
        "seed": seed,
        "index": index,
        "findings": findings,
        "request": description,
    }
    artifact.write_text(
        json.dumps(payload, indent=2, default=repr)[:100000], encoding="utf-8"
    )
    return artifact


def describe(method, path, raw, body):
    if isinstance(body, bytes):
        rendered = body[:2000].decode("latin-1")
    else:
        rendered = body
    return {"method": method, "path": path[:2000], "raw": raw, "body": rendered}


def check_and_record(name, client, args, index, status, findings, description, counters):
    if index % args.liveness_every == 0 and client.get_status("/healthz/live") != 200:
        findings.append("server not alive after case")
    if findings:
        counters["failed"] += 1
        artifact = save_crash(name, args.seed, index, description, findings)
        print(f"[{name}] FINDING at #{index}: {findings} -> {artifact}")
        if status == 0 and client.get_status("/healthz/live") != 200:
            print(f"[{name}] server appears down; aborting target")
            return True
    else:
        counters["passed"] += 1
    return False


# --- runners -----------------------------------------------------------------


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
    return counters


def build_config_baseline():
    original_cfg = CONFIG_PATH.read_bytes() if CONFIG_PATH.exists() else None
    original_sig = CONFIG_SIGN_PATH.read_bytes() if CONFIG_SIGN_PATH.exists() else None
    CONFIG_PATH.write_text(
        json.dumps(
            {"version": "v1", "routes": [], "remote_routes": [], "permissions": []},
            indent=2,
        ),
        encoding="utf-8",
    )
    result = subprocess.run(
        ["cargo", "run", "--quiet", "--", "config", "sign", "--output", "json"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"config sign failed: {result.stderr or result.stdout}")
    baseline_cfg = CONFIG_PATH.read_bytes()
    baseline_sig = CONFIG_SIGN_PATH.read_bytes()

    def restore():
        if original_cfg is None:
            CONFIG_PATH.unlink(missing_ok=True)
        else:
            CONFIG_PATH.write_bytes(original_cfg)
        if original_sig is None:
            CONFIG_SIGN_PATH.unlink(missing_ok=True)
        else:
            CONFIG_SIGN_PATH.write_bytes(original_sig)

    atexit.register(restore)
    return baseline_cfg, baseline_sig


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
    return counters


# --- seed factories ----------------------------------------------------------


def _create_key(client, case):
    status, body = client.post_json("/keys", case, auth=True)
    if status != 200:
        raise RuntimeError(f"could not create seed key ({case}): HTTP {status}: {body}")
    return json.loads(body)["id"]


def message_seeds(_client):
    envelope = {
        "version": "v1",
        "payload": {
            "version": "v1",
            "type": "protected-message",
            "created_at": "2026-01-01T00:00:00Z",
            "sender": {"host": "127.0.0.1:3000", "kid": KID_HEX},
            "recipient": {"kid": RECIPIENT_HEX},
            "kem": {
                "alg": "X25519+ML-KEM-512",
                "xecdh_ephemeral_public": "aa" * 16,
                "ml_kem_ciphertext": "aa" * 16,
                "ml_kem_salt": "aa" * 16,
                "hkdf_salt": "aa" * 16,
            },
            "cipher": {
                "alg": "ChaCha20Poly1305",
                "nonce": "aa" * 12,
                "aad": "version=v1;type=protected-message",
                "ct": "aabbccddeeff0011",
            },
        },
        "signatures": {
            "eddsa": {"alg": "Ed25519", "sig": "aa" * 32},
            "ml-dsa": {"alg": "ML-DSA-44", "sig": "aa" * 32},
        },
    }
    return [("/message", envelope)]


def token_seeds(client):
    seeds = []
    for case in KEY_CASES:
        kid = _create_key(client, case)
        status, body = client.post_json(
            f"/sign/{kid}", {"message_hash": {"alg": "BLAKE2b(256)", "hex": "cd" * 32}}, auth=True
        )
        if status != 200:
            raise RuntimeError(f"could not sign seed token: HTTP {status}: {body}")
        seeds.append(("/sign/verification", json.loads(body)))
    return seeds


def internal_seeds(client):
    seeds = []
    for case in KEY_CASES:
        kid = _create_key(client, case)
        status, body = client.post_json(
            f"/message/internal/encrypt/{kid}", {"plaintext": INTERNAL_SEED_PLAINTEXT}, auth=True
        )
        if status != 200:
            raise RuntimeError(f"could not encrypt seed message: HTTP {status}: {body}")
        seeds.append(("/message/internal/decrypt", json.loads(body)))
    return seeds


def keys_seeds(_client):
    return [("/keys", copy.deepcopy(KEY_TARGET_SEED))]


def sign_body_seeds(client):
    seeds = []
    for case in KEY_CASES:
        kid = _create_key(client, case)
        seeds.append((f"/sign/{kid}", {"message_hash": {"alg": "BLAKE2b(256)", "hex": "cd" * 32}}))
    return seeds


def lifecycle_seeds(client):
    kid = _create_key(client, {"tag": "fuzz-lifecycle", "profile": "hybrid-performance-v1"})
    return [(f"/lifecycle/{kid}", {"status": "disabled", "reason": "fuzz"})]


def decrypt_seeds(_client):
    delivery = {
        "sender_host": "127.0.0.1:3000",
        "sender_kid": KID_HEX,
        "timestamp": "1782058090",
        "message": {
            "ctx": "aabbccddeeff0011",
            "nonce": "aa" * 12,
            "aad": "version=v1;type=protected-message;sender_kid=" + KID_HEX,
            "variant": "ChaCha20Poly1305",
        },
    }
    return [("/message/decrypt", delivery)]


TARGETS = [
    {"name": "token", "runner": run_body, "seed_factory": token_seeds,
     "path": "/sign/verification", "auth": False, "semantic": token_semantic},
    {"name": "message", "runner": run_body, "seed_factory": message_seeds,
     "auth": False, "allow_ru": True},
    {"name": "internal", "runner": run_body, "seed_factory": internal_seeds,
     "auth": True, "semantic": internal_semantic},
    {"name": "keys", "runner": run_body, "seed_factory": keys_seeds, "auth": True},
    {"name": "sign_body", "runner": run_body, "seed_factory": sign_body_seeds, "auth": True},
    {"name": "lifecycle", "runner": run_body, "seed_factory": lifecycle_seeds, "auth": True},
    {"name": "decrypt", "runner": run_body, "seed_factory": decrypt_seeds, "auth": True},
    {"name": "config", "runner": run_config},
    {"name": "pubkid", "runner": run_path_param, "require_json_error": False, "endpoints": [
        ("/pub/{}", False),
        ("/keys/properties/{}", True),
        ("/self-test/keys/{}", True),
    ]},
    {"name": "headers", "runner": run_headers, "allowed_status": FRAMEWORK_STATUS},
]

TARGET_NAMES = [t["name"] for t in TARGETS]


# --- offline self-test of the semantic oracle --------------------------------


def self_check():
    failures = []

    def expect(condition, label):
        if not condition:
            failures.append(label)

    token = {
        "version": "v1",
        "payload": {"kid": "a" * 64},
        "signatures": {"eddsa": {"sig": "aa"}, "ml-dsa": {"sig": "bb"}},
    }
    token_mut = json.loads(json.dumps(token))
    token_mut["payload"]["kid"] = "b" * 64
    expect(token_semantic(token_mut, token, 200, '{"valid":"ok"}'), "token flags bypass")
    expect(not token_semantic(token, token, 200, '{"valid":"ok"}'), "token ignores identity")
    expect(not token_semantic(token_mut, token, 200, '{"valid":"fail"}'), "token ignores valid=fail")
    expect(not token_semantic(token_mut, token, 400, '{"error":"x"}'), "token ignores 4xx")

    iseed = {
        "timestamp": "1",
        "kid": "a" * 64,
        "message": {"ctx": "aa", "nonce": "bb", "aad": "c", "variant": "ChaCha20Poly1305"},
    }
    itamper = json.loads(json.dumps(iseed))
    itamper["message"]["ctx"] = "ff"
    ok_body = json.dumps({"plaintext": INTERNAL_SEED_PLAINTEXT})
    expect(internal_semantic(itamper, iseed, 200, ok_body), "internal flags AEAD bypass")
    expect(internal_semantic(iseed, iseed, 200, '{"plaintext":"WRONG"}'), "internal flags wrong plaintext")
    expect(not internal_semantic(iseed, iseed, 200, ok_body), "internal ignores correct decrypt")
    expect(not internal_semantic(itamper, iseed, 400, '{"error":"x"}'), "internal ignores 4xx")

    loaded_body = '{"status":"reloaded","routes_loaded":1,"remote_routes_loaded":0,"clients_loaded":0}'
    empty_body = '{"status":"reloaded","routes_loaded":0,"remote_routes_loaded":0,"clients_loaded":0}'
    expect(config_semantic(200, loaded_body), "config flags integrity bypass")
    expect(not config_semantic(200, empty_body), "config ignores empty reload")
    expect(not config_semantic(400, '{"error":"x"}'), "config ignores rejected")

    total = 13
    for label in failures:
        print(f"SELF-CHECK FAIL: {label}")
    print(f"SUMMARY self-check passed={total - len(failures)} failed={len(failures)}")
    return 1 if failures else 0


def main():
    parser = argparse.ArgumentParser(description="Fuzz the Vectis HTTP surface.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--apikey")
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--iterations", type=int, default=300)
    parser.add_argument("--target", choices=["all", *TARGET_NAMES], default="all")
    parser.add_argument("--liveness-every", type=int, default=1)
    parser.add_argument(
        "--self-check",
        action="store_true",
        help="run offline self-tests of the semantic oracle and exit",
    )
    args = parser.parse_args()

    if args.self_check:
        sys.exit(self_check())

    apikey = require_apikey(args.apikey)
    client = FuzzClient(args.base_url, apikey)
    rng = random.Random(args.seed)

    if client.get_status("/healthz/ready") != 200:
        print("Vectis is not ready; start the server first", file=sys.stderr)
        sys.exit(1)

    unseal = UNSEAL_KEY_FILE.read_text(encoding="utf-8").strip() if UNSEAL_KEY_FILE.exists() else ""
    secrets = (apikey, unseal)

    passed = 0
    failed = 0
    for target in TARGETS:
        if args.target not in ("all", target["name"]):
            continue
        counters = target["runner"](target, client, rng, args, secrets)
        passed += counters["passed"]
        failed += counters["failed"]

    if client.get_status("/healthz/ready") != 200:
        print("Vectis is not healthy after fuzzing", file=sys.stderr)
        failed += 1

    print(f"SUMMARY fuzz passed={passed} failed={failed}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
