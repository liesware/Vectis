#!/usr/bin/env python3
import hashlib
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

import yaml


SCRIPT_DIR = Path(__file__).resolve().parent
SITE_DIR = SCRIPT_DIR / "site"
PERSONALDATA_PATH = SCRIPT_DIR / "personaldata.json"

FPE_SAMPLES = [
    ("credit-card-pan-v1", "4111111111111111"),
    ("ssn-decimal-v1", "123456789"),
    ("identity-document-v1", "ACME123456"),
    ("driver-license-v1", "D1234567"),
    ("bank-account-v1", "987654321012"),
    ("payroll-number-v1", "PAY123456"),
    ("insurance-policy-v1", "POLICY123456"),
]

TOKEN_SAMPLES = [
    ("credit-card-token-v1", "4111111111111111"),
    ("ssn-token-v1", "123456789"),
    ("identity-document-token-v1", "ACME123456"),
    ("driver-license-token-v1", "D1234567"),
    ("bank-account-token-v1", "987654321012"),
    ("payroll-number-token-v1", "PAY123456"),
    ("insurance-policy-token-v1", "POLICY123456"),
]


def load_env(path):
    values = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def pretty_json(value):
    return json.dumps(value, indent=2, sort_keys=True)


def pretty_yaml(value):
    return yaml.safe_dump(value, sort_keys=False, allow_unicode=True).rstrip()


def wait_for_key(message):
    print(message, end="", flush=True)
    if sys.stdin.isatty():
        sys.stdin.read(1)
    print(flush=True)


def wait_for_start():
    wait_for_key("Press any key to start: ")


def wait_for_continue():
    wait_for_key("Press any key to continue: ")


def print_yaml_block(title, value):
    wait_for_key(f"Press any key to show {title}: ")
    print(f"== {title} ==", flush=True)
    print(pretty_yaml(value), flush=True)
    print(flush=True)


def post_json(base_url, path, payload, api_key=None):
    url = f"{base_url}{path}"
    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key
    request_info = {
        "method": "POST",
        "headers": headers,
        "body": payload,
    }
    request = urllib.request.Request(
        url,
        data=body,
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return {
                "url": url,
                "request": request_info,
                "response": json.loads(response.read().decode("utf-8")),
            }
    except urllib.error.HTTPError as err:
        detail = err.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"POST {path} failed: HTTP {err.code} {detail}") from err


def print_section(title):
    print(f"[{title}]", flush=True)
    print(flush=True)


def print_http_step(name, exchange):
    print(name, flush=True)
    print(f"url: {exchange['url']}", flush=True)
    print("request:", flush=True)
    print(pretty_json(exchange["request"]), flush=True)
    print("response:", flush=True)
    print(pretty_json(exchange["response"]), flush=True)
    print(flush=True)


def print_summary(rows):
    for key, value in rows:
        print(f"{key}: {value}", flush=True)
    print(flush=True)
    wait_for_continue()


def run_fpe(base_url, kid, api_key):
    print("== FPE Profiles ==", flush=True)
    for profile, plaintext in FPE_SAMPLES:
        ref = f"{profile}-sample"
        encrypted = post_json(
            base_url,
            f"/fpe/encrypt/{kid}",
            {"ref": ref, "profile": profile, "plaintext": plaintext},
            api_key,
        )
        ciphertext = encrypted["response"]["ciphertext"]
        decrypted = post_json(
            base_url,
            "/fpe/decrypt",
            {"ref": ref, "kid": kid, "profile": profile, "ciphertext": ciphertext},
            api_key,
        )
        recovered = decrypted["response"]["plaintext"]
        status = "OK" if recovered == plaintext else "FAILED"
        print_section(profile)
        print_http_step("encode", encrypted)
        print_http_step("decode", decrypted)
        print_summary(
            [
                ("input", plaintext),
                ("output", ciphertext),
                ("decode", recovered),
                ("status", status),
            ],
        )
        if status != "OK":
            raise RuntimeError(f"FPE round-trip failed for {profile}")


def run_tokenization(base_url, kid, api_key):
    print("== Tokenization Profiles ==", flush=True)
    for profile, plaintext in TOKEN_SAMPLES:
        ref = f"{profile}-sample"
        encoded = post_json(
            base_url,
            f"/token/encode/{kid}",
            {
                "ref": ref,
                "profile": profile,
                "plaintext": plaintext,
                "metadata": {"demo": "local"},
            },
            api_key,
        )
        token = encoded["response"]["token"]
        decoded = post_json(
            base_url,
            "/token/decode",
            {"ref": ref, "kid": kid, "profile": profile, "token": token},
            api_key,
        )
        recovered = decoded["response"]["plaintext"]
        status = "OK" if recovered == plaintext else "FAILED"
        print_section(profile)
        print_http_step("encode", encoded)
        print_http_step("decode", decoded)
        print_summary(
            [
                ("input", plaintext),
                ("token", token),
                ("decode", recovered),
                ("metadata", json.dumps(decoded["response"].get("metadata"), sort_keys=True)),
                ("status", status),
            ],
        )
        if status != "OK":
            raise RuntimeError(f"Token round-trip failed for {profile}")


def run_internal_message(base_url, kid, api_key, plaintext):
    print("== Internal Message ==", flush=True)
    encrypted = post_json(
        base_url,
        f"/message/internal/encrypt/{kid}",
        {"plaintext": plaintext},
        api_key,
    )
    decrypted = post_json(
        base_url,
        "/message/internal/decrypt",
        encrypted["response"],
        api_key,
    )
    recovered = decrypted["response"]["plaintext"]
    status = "OK" if recovered == plaintext else "FAILED"
    print_section("personaldata.json")
    print_http_step("encrypt", encrypted)
    print_http_step("decrypt", decrypted)
    print_summary(
        [
            ("encrypt", "OK"),
            ("decrypt", "OK" if recovered == plaintext else "FAILED"),
            ("plaintext_bytes", str(len(plaintext.encode("utf-8")))),
            ("status", status),
        ],
    )
    if status != "OK":
        raise RuntimeError("Internal message round-trip failed")


def run_sign_verify(base_url, kid, api_key, plaintext):
    print("== Sign / Verify ==", flush=True)
    digest = hashlib.blake2b(plaintext.encode("utf-8"), digest_size=32).hexdigest()
    token = post_json(
        base_url,
        f"/sign/{kid}",
        {"message_hash": {"alg": "BLAKE2b(256)", "hex": digest}},
        api_key,
    )
    verification = post_json(base_url, "/sign/verification", token["response"])
    status = "OK" if verification["response"].get("valid") == "ok" else "FAILED"
    print_section("personaldata.json")
    print_http_step("sign", token)
    print_http_step("verify", verification)
    print_summary(
        [
            ("hash_alg", "BLAKE2b(256)"),
            ("hash_hex", digest),
            ("sign", "OK"),
            ("verify", verification["response"].get("valid")),
            ("status", status),
        ],
    )
    if status != "OK":
        raise RuntimeError("Sign verification failed")


def main():
    env_path = SITE_DIR / "app.env"
    if not env_path.exists():
        raise SystemExit("Missing site/app.env. Run: bash demo/local/create-keys.sh")
    env = load_env(env_path)
    base_url = env["VECTIS_URL"]
    kid = env["LOCAL_KID"]
    api_key = env["VECTIS_APIKEY"]
    init_json = load_json(SITE_DIR / "init.json")
    config_json = load_json(SITE_DIR / "config.json")
    config_sign_json = load_json(SITE_DIR / "config_sign.json")
    personaldata = load_json(PERSONALDATA_PATH)
    plaintext = json.dumps(personaldata, separators=(",", ":"), sort_keys=True)

    print("Vectis local data protection demo", flush=True)
    print(f"base_url: {base_url}", flush=True)
    print(f"kid: {kid}", flush=True)
    print(flush=True)
    print_yaml_block("init.json", init_json)
    print_yaml_block("config.json", config_json)
    print_yaml_block("config_sign.json", config_sign_json)
    wait_for_start()

    run_fpe(base_url, kid, api_key)
    run_tokenization(base_url, kid, api_key)
    print_yaml_block("personaldata.json", personaldata)
    run_internal_message(base_url, kid, api_key, plaintext)
    print_yaml_block("personaldata.json", personaldata)
    run_sign_verify(base_url, kid, api_key, plaintext)

    print("Demo status: OK", flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        print(f"Demo status: FAILED: {err}", file=sys.stderr, flush=True)
        raise
