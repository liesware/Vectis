#!/usr/bin/env python3
import argparse
import atexit
import copy
import json
import random
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

from test_config import require_apikey

DEFAULT_BASE_URL = "http://127.0.0.1:3000"
CONFIG_PATH = Path("config.json")
CONFIG_SIGN_PATH = Path("config_sign.json")
UNSEAL_KEY_FILE = Path(".unseal_key")
CORPUS_DIR = Path(__file__).resolve().parent / "fuzz-corpus"

ALLOWED_STATUS = {200, 400, 401, 403, 404, 413}
REMOTE_UNREACHABLE_MARKER = "final app can't be reached"
KID_HEX = "a" * 64
RECIPIENT_HEX = "b" * 64

KEY_CASE = {
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


def mutate_structured(seed, rng):
    node = json.loads(json.dumps(seed))
    for _ in range(rng.randint(1, 3)):
        paths = all_paths(node)
        path = rng.choice(paths)
        if path and rng.random() < 0.4:
            node = del_at(node, path)
            continue
        current = get_at(node, path) if path else node
        if isinstance(current, str) and rng.random() < 0.6:
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
        return data.replace(b"{", b'{"version":"v1","version":"v2",', 1)
    return data * rng.randint(2, 5)


def oracle(status, body, apikey, unseal, allow_remote_unreachable):
    findings = []
    if status == 0:
        findings.append("connection failed (possible crash or hang)")
        return findings
    if status not in ALLOWED_STATUS:
        known_unreachable = (
            status == 500
            and allow_remote_unreachable
            and REMOTE_UNREACHABLE_MARKER in body
        )
        if not known_unreachable:
            findings.append(f"unexpected status {status}")
    if 400 <= status < 500:
        try:
            obj = json.loads(body)
            extra = sorted(set(obj.keys()) - {"error"})
            if extra:
                findings.append(f"4xx error body has extra keys: {extra}")
        except (json.JSONDecodeError, AttributeError):
            findings.append("4xx body is not a JSON error object")
    for name, secret in (("apikey", apikey), ("unseal-key", unseal)):
        if secret and secret in body:
            findings.append(f"possible {name} leak in response body")
    return findings


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


def describe(path, raw, body):
    if raw:
        return {"method": "POST", "path": path, "raw": True, "body": body[:2000].decode("latin-1")}
    return {"method": "POST", "path": path, "raw": False, "body": body}


def fuzz_message_like(name, client, rng, seed_obj, path, auth, allow_ru, args, secrets):
    counters = {"passed": 0, "failed": 0}
    apikey, unseal = secrets
    for index in range(args.iterations):
        if rng.random() < 0.3:
            body = mutate_raw(seed_obj, rng)
            status, response = client.post_raw(path, body, auth=auth)
            description = describe(path, True, body)
        else:
            body = mutate_structured(seed_obj, rng)
            status, response = client.post_json(path, body, auth=auth)
            description = describe(path, False, body)
        findings = oracle(status, response, apikey, unseal, allow_ru)
        if index % args.liveness_every == 0 and client.get_status("/healthz/live") != 200:
            findings.append("server not alive after case")
        if findings:
            counters["failed"] += 1
            artifact = save_crash(name, args.seed, index, description, findings)
            print(f"[{name}] FINDING at #{index}: {findings} -> {artifact}")
            if status == 0 and client.get_status("/healthz/live") != 200:
                print(f"[{name}] server appears down; aborting target")
                break
        else:
            counters["passed"] += 1
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


def fuzz_config(client, rng, args, secrets):
    counters = {"passed": 0, "failed": 0}
    apikey, unseal = secrets
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
        findings = oracle(status, response, apikey, unseal, allow_remote_unreachable=False)
        if index % args.liveness_every == 0 and client.get_status("/healthz/live") != 200:
            findings.append("server not alive after case")
        if findings:
            counters["failed"] += 1
            description = {
                "endpoint": "POST /config/reload",
                "mutated_file": target_file,
                "content": mutated[:2000].decode("latin-1"),
            }
            artifact = save_crash("config", args.seed, index, description, findings)
            print(f"[config] FINDING at #{index}: {findings} -> {artifact}")
            if status == 0 and client.get_status("/healthz/live") != 200:
                print("[config] server appears down; aborting target")
                break
        else:
            counters["passed"] += 1
        CONFIG_PATH.write_bytes(baseline_cfg)
        CONFIG_SIGN_PATH.write_bytes(baseline_sig)
    return counters


def message_seed():
    return {
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


def token_seed(client):
    status, body = client.post_json("/keys", KEY_CASE, auth=True)
    if status != 200:
        raise RuntimeError(f"could not create seed key: HTTP {status}: {body}")
    kid = json.loads(body)["id"]
    message_hash = {"alg": "BLAKE2b(256)", "hex": "cd" * 32}
    status, body = client.post_json(
        f"/sign/{kid}", {"message_hash": message_hash}, auth=True
    )
    if status != 200:
        raise RuntimeError(f"could not sign seed token: HTTP {status}: {body}")
    return json.loads(body)


def main():
    parser = argparse.ArgumentParser(description="Fuzz the Vectis HTTP surface.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--apikey")
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--iterations", type=int, default=300)
    parser.add_argument(
        "--target", choices=["all", "token", "message", "config"], default="all"
    )
    parser.add_argument("--liveness-every", type=int, default=1)
    args = parser.parse_args()

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

    if args.target in ("all", "token"):
        counters = fuzz_message_like(
            "token", client, rng, token_seed(client),
            "/sign/verification", False, False, args, secrets,
        )
        passed += counters["passed"]
        failed += counters["failed"]

    if args.target in ("all", "message"):
        counters = fuzz_message_like(
            "message", client, rng, message_seed(),
            "/message", False, True, args, secrets,
        )
        passed += counters["passed"]
        failed += counters["failed"]

    if args.target in ("all", "config"):
        counters = fuzz_config(client, rng, args, secrets)
        passed += counters["passed"]
        failed += counters["failed"]

    if client.get_status("/healthz/ready") != 200:
        print("Vectis is not healthy after fuzzing", file=sys.stderr)
        failed += 1

    print(f"SUMMARY fuzz passed={passed} failed={failed}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
