import json

from oracle import _parse


KID_HEX = "a" * 64
RECIPIENT_HEX = "b" * 64
INTERNAL_SEED_PLAINTEXT = "fuzz seed plaintext"
FPE_PROFILE = "fuzz-patient-id-decimal-v1"
FPE_PLAINTEXT = "1234567890"
FPE_BATCH_PLAINTEXTS = [FPE_PLAINTEXT, "9876543210"]
TOKENIZATION_PROFILE = "fuzz-patient-id-token-v1"
TOKEN_PLAINTEXT = "fuzz token plaintext"
TOKEN_BATCH_PLAINTEXTS = [TOKEN_PLAINTEXT, "second fuzz token plaintext"]
MAC_PROFILE = "fuzz-pan-blind-index-v1"
MAC_PLAINTEXTS = ["4111111111111111", "5555555555554444"]
MASKING_PROFILE = "fuzz-pan-display-v1"
MASKING_PLAINTEXTS = ["4111111111111111", "5555555555554444"]
COMMITMENT_PROFILE = "fuzz-pan-commitment-v1"
COMMITMENT_PLAINTEXTS = ["4111111111111111", "5555555555554444"]
SHARING_PROFILE = "fuzz-customer-secret-3of5-v1"
SHARING_PLAINTEXT = "fuzz secret sharing plaintext"


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


def internal_encrypt_semantic(sent_value, seed, status, body):
    findings = []
    if status != 200:
        return findings
    parsed = _parse(body)
    message = parsed.get("message") if isinstance(parsed, dict) else None
    if not isinstance(message, dict):
        findings.append("SEMANTIC: internal encrypt 200 body is missing message")
        return findings
    if (
        isinstance(sent_value, dict)
        and sent_value == seed
        and message.get("ctx") == seed.get("plaintext")
    ):
        findings.append("SEMANTIC: internal encrypt returned plaintext as ciphertext")
    return findings


def _crypto_fields_differ(sent_value, seed):
    sent_msg = sent_value.get("message")
    seed_msg = seed.get("message")
    if not isinstance(sent_msg, dict) or not isinstance(seed_msg, dict):
        return True
    return any(sent_msg.get(field) != seed_msg.get(field) for field in CRYPTO_MESSAGE_FIELDS)


def _fields_differ(sent_value, seed, fields):
    if not isinstance(sent_value, dict) or not isinstance(seed, dict):
        return sent_value != seed
    return any(sent_value.get(field) != seed.get(field) for field in fields)


def _batch_item_fields_differ(sent_value, seed, fields):
    if not isinstance(sent_value, dict) or not isinstance(seed, dict):
        return sent_value != seed
    if _fields_differ(sent_value, seed, ("kid", "profile")):
        return True
    sent_items = sent_value.get("items")
    seed_items = seed.get("items")
    if not isinstance(sent_items, list) or not isinstance(seed_items, list):
        return sent_items != seed_items
    if len(sent_items) != len(seed_items):
        return True
    for sent_item, seed_item in zip(sent_items, seed_items):
        if not isinstance(sent_item, dict) or not isinstance(seed_item, dict):
            return sent_item != seed_item
        if any(sent_item.get(field) != seed_item.get(field) for field in fields):
            return True
    return False


CONFIG_LOADED_COUNTS = (
    "routes_loaded",
    "remote_routes_loaded",
    "clients_loaded",
    "fpe_profiles_loaded",
    "tokenization_profiles_loaded",
    "mac_profiles_loaded",
    "masking_profiles_loaded",
    "commitment_profiles_loaded",
    "sharing_profiles_loaded",
)


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


def fpe_semantic(sent_value, seed, status, body):
    findings = []
    if status != 200:
        return findings
    parsed = _parse(body)
    if not isinstance(parsed, dict):
        return ["SEMANTIC: fpe 200 body is not JSON object"]

    if "plaintext" in seed:
        ciphertext = parsed.get("ciphertext")
        if ciphertext is None:
            findings.append("SEMANTIC: fpe encrypt 200 body is missing ciphertext")
        if (
            isinstance(sent_value, dict)
            and sent_value == seed
            and ciphertext == seed["plaintext"]
        ):
            findings.append("SEMANTIC: fpe encrypt returned plaintext as ciphertext")
        return findings

    if "ciphertext" in seed:
        plaintext = parsed.get("plaintext")
        if plaintext is None:
            findings.append("SEMANTIC: fpe decrypt 200 body is missing plaintext")
        if sent_value == seed and plaintext != FPE_PLAINTEXT:
            findings.append("SEMANTIC: fpe decrypt returned unexpected plaintext")
        if (
            _fields_differ(sent_value, seed, ("kid", "profile", "ciphertext"))
            and plaintext == FPE_PLAINTEXT
        ):
            findings.append(
                "SEMANTIC: fpe decrypt accepted mutated input as original plaintext"
            )
    return findings


def fpe_batch_semantic(sent_value, seed, status, body):
    findings = []
    if status != 200:
        return findings
    parsed = _parse(body)
    if not isinstance(parsed, dict):
        return ["SEMANTIC: fpe batch 200 body is not JSON object"]
    items = parsed.get("items")
    if not isinstance(items, list):
        return ["SEMANTIC: fpe batch 200 body is missing items list"]
    seed_items = seed.get("items") if isinstance(seed, dict) else None
    if not isinstance(seed_items, list) or not seed_items:
        return findings

    if "plaintext" in seed_items[0]:
        if sent_value == seed:
            if len(items) != len(seed_items):
                findings.append("SEMANTIC: fpe batch encrypt item count mismatch")
            for out_item, in_item in zip(items, seed_items):
                if isinstance(out_item, dict) and out_item.get("ciphertext") == in_item.get("plaintext"):
                    findings.append("SEMANTIC: fpe batch encrypt returned plaintext as ciphertext")
                    break
        return findings

    if "ciphertext" in seed_items[0]:
        returned = [it.get("plaintext") for it in items if isinstance(it, dict)]
        if sent_value == seed and returned != FPE_BATCH_PLAINTEXTS:
            findings.append("SEMANTIC: fpe batch decrypt returned unexpected plaintext")
        if (
            _batch_item_fields_differ(sent_value, seed, ("ciphertext",))
            and returned == FPE_BATCH_PLAINTEXTS
        ):
            findings.append(
                "SEMANTIC: fpe batch decrypt accepted mutated input as original plaintext"
            )
    return findings


def tokenization_semantic(sent_value, seed, status, body):
    findings = []
    if status != 200:
        return findings
    parsed = _parse(body)
    if not isinstance(parsed, dict):
        return ["SEMANTIC: token 200 body is not JSON object"]

    if "plaintext" in seed:
        token = parsed.get("token")
        if token is None:
            findings.append("SEMANTIC: token encode 200 body is missing token")
        elif isinstance(token, str) and TOKEN_PLAINTEXT in token:
            findings.append("SEMANTIC: token encode leaked plaintext in token")
        return findings

    if "token" in seed:
        returned = parsed.get("plaintext")
        if sent_value == seed and returned != TOKEN_PLAINTEXT:
            findings.append("SEMANTIC: token decode returned unexpected plaintext")
        if (
            _fields_differ(sent_value, seed, ("kid", "profile", "token"))
            and returned == TOKEN_PLAINTEXT
        ):
            findings.append(
                "SEMANTIC: token decode accepted mutated token as original plaintext"
            )
    return findings


def tokenization_batch_semantic(sent_value, seed, status, body):
    findings = []
    if status != 200:
        return findings
    parsed = _parse(body)
    if not isinstance(parsed, dict):
        return ["SEMANTIC: token batch 200 body is not JSON object"]
    items = parsed.get("items")
    if not isinstance(items, list):
        return ["SEMANTIC: token batch 200 body is missing items list"]
    seed_items = seed.get("items") if isinstance(seed, dict) else None
    if not isinstance(seed_items, list) or not seed_items:
        return findings

    if "plaintext" in seed_items[0]:
        if sent_value == seed:
            if len(items) != len(seed_items):
                findings.append("SEMANTIC: token batch encode item count mismatch")
            for out_item, in_item in zip(items, seed_items):
                token = out_item.get("token") if isinstance(out_item, dict) else None
                plaintext = in_item.get("plaintext") if isinstance(in_item, dict) else None
                if token is None:
                    findings.append("SEMANTIC: token batch encode item is missing token")
                    break
                if isinstance(token, str) and isinstance(plaintext, str) and plaintext in token:
                    findings.append("SEMANTIC: token batch encode leaked plaintext in token")
                    break
        return findings

    if "token" in seed_items[0]:
        returned = [it.get("plaintext") for it in items if isinstance(it, dict)]
        if sent_value == seed and returned != TOKEN_BATCH_PLAINTEXTS:
            findings.append("SEMANTIC: token batch decode returned unexpected plaintext")
        if (
            _batch_item_fields_differ(sent_value, seed, ("token",))
            and returned == TOKEN_BATCH_PLAINTEXTS
        ):
            findings.append(
                "SEMANTIC: token batch decode accepted mutated token as original plaintext"
            )
    return findings


# --- reporting ---------------------------------------------------------------
def self_check():
    failures = []
    total = 0

    def expect(condition, label):
        nonlocal total
        total += 1
        if not condition:
            failures.append(label)

    token = {
        "kid": "a" * 64,
        "signature": "header.payload.eddsa.ml-dsa",
    }
    token_mut = json.loads(json.dumps(token))
    token_mut["kid"] = "b" * 64
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

    encrypt_seed = {"plaintext": INTERNAL_SEED_PLAINTEXT}
    bad_encrypt_body = json.dumps({"message": {"ctx": INTERNAL_SEED_PLAINTEXT}})
    good_encrypt_body = json.dumps({"message": {"ctx": "aa", "nonce": "bb", "aad": "c"}})
    expect(
        internal_encrypt_semantic(encrypt_seed, encrypt_seed, 200, bad_encrypt_body),
        "internal encrypt flags plaintext ciphertext",
    )
    expect(
        not internal_encrypt_semantic(encrypt_seed, encrypt_seed, 200, good_encrypt_body),
        "internal encrypt ignores plausible body",
    )

    loaded_body = '{"status":"reloaded","routes_loaded":1,"remote_routes_loaded":0,"clients_loaded":0,"fpe_profiles_loaded":0,"tokenization_profiles_loaded":0,"mac_profiles_loaded":0,"masking_profiles_loaded":0,"commitment_profiles_loaded":0,"sharing_profiles_loaded":0}'
    empty_body = '{"status":"reloaded","routes_loaded":0,"remote_routes_loaded":0,"clients_loaded":0,"fpe_profiles_loaded":0,"tokenization_profiles_loaded":0,"mac_profiles_loaded":0,"masking_profiles_loaded":0,"commitment_profiles_loaded":0,"sharing_profiles_loaded":0}'
    expect(config_semantic(200, loaded_body), "config flags integrity bypass")
    expect(not config_semantic(200, empty_body), "config ignores empty reload")
    expect(not config_semantic(400, '{"error":"x"}'), "config ignores rejected")

    fpe_encrypt_seed = {"ref": "fpe-self", "profile": FPE_PROFILE, "plaintext": FPE_PLAINTEXT}
    fpe_decrypt_seed = {
        "ref": "fpe-self",
        "kid": "a" * 64,
        "profile": FPE_PROFILE,
        "ciphertext": "9876543210",
    }
    fpe_decrypt_mut = dict(fpe_decrypt_seed, ciphertext="9876543211")
    fpe_decrypt_ref_mut = dict(fpe_decrypt_seed, ref="0x1F")
    expect(
        fpe_semantic(
            fpe_encrypt_seed, fpe_encrypt_seed, 200, '{"ciphertext":"1234567890"}'
        ),
        "fpe encrypt flags plaintext ciphertext",
    )
    expect(
        not fpe_semantic(
            fpe_encrypt_seed, fpe_encrypt_seed, 200, '{"ciphertext":"9876543210"}'
        ),
        "fpe encrypt ignores changed ciphertext",
    )
    expect(
        fpe_semantic(fpe_decrypt_seed, fpe_decrypt_seed, 200, '{"plaintext":"WRONG"}'),
        "fpe decrypt flags wrong plaintext",
    )
    expect(
        fpe_semantic(fpe_decrypt_mut, fpe_decrypt_seed, 200, '{"plaintext":"1234567890"}'),
        "fpe decrypt flags mutated original plaintext",
    )
    expect(
        not fpe_semantic(fpe_decrypt_ref_mut, fpe_decrypt_seed, 200, '{"plaintext":"1234567890"}'),
        "fpe decrypt ignores ref-only mutation",
    )
    expect(
        not fpe_semantic(fpe_decrypt_seed, fpe_decrypt_seed, 200, '{"plaintext":"1234567890"}'),
        "fpe decrypt ignores correct plaintext",
    )

    fpe_batch_encrypt_seed = {
        "profile": FPE_PROFILE,
        "items": [
            {"ref": f"fpe-self-{index}", "plaintext": item}
            for index, item in enumerate(FPE_BATCH_PLAINTEXTS)
        ],
    }
    fpe_batch_decrypt_seed = {
        "kid": "a" * 64,
        "profile": FPE_PROFILE,
        "items": [
            {"ref": "fpe-self-0", "ciphertext": "9876543210"},
            {"ref": "fpe-self-1", "ciphertext": "0123456789"},
        ],
    }
    fpe_batch_decrypt_mut = json.loads(json.dumps(fpe_batch_decrypt_seed))
    fpe_batch_decrypt_mut["items"][0]["ciphertext"] = "9876543211"
    fpe_batch_decrypt_ref_mut = json.loads(json.dumps(fpe_batch_decrypt_seed))
    fpe_batch_decrypt_ref_mut["items"][0]["ref"] = "0x1F"
    correct_batch_plaintext_body = json.dumps(
        {"items": [{"plaintext": FPE_BATCH_PLAINTEXTS[0]}, {"plaintext": FPE_BATCH_PLAINTEXTS[1]}]}
    )
    expect(
        fpe_batch_semantic(
            fpe_batch_encrypt_seed, fpe_batch_encrypt_seed, 200,
            json.dumps({"items": [{"ciphertext": FPE_BATCH_PLAINTEXTS[0]}, {"ciphertext": "aaaa"}]}),
        ),
        "fpe batch encrypt flags plaintext ciphertext",
    )
    expect(
        not fpe_batch_semantic(
            fpe_batch_encrypt_seed, fpe_batch_encrypt_seed, 200,
            json.dumps({"items": [{"ciphertext": "111"}, {"ciphertext": "222"}]}),
        ),
        "fpe batch encrypt ignores changed ciphertext",
    )
    expect(
        fpe_batch_semantic(
            fpe_batch_decrypt_seed, fpe_batch_decrypt_seed, 200,
            json.dumps({"items": [{"plaintext": "WRONG"}, {"plaintext": "X"}]}),
        ),
        "fpe batch decrypt flags wrong plaintext",
    )
    expect(
        fpe_batch_semantic(
            fpe_batch_decrypt_mut, fpe_batch_decrypt_seed, 200, correct_batch_plaintext_body
        ),
        "fpe batch decrypt flags mutated original plaintext",
    )
    expect(
        not fpe_batch_semantic(
            fpe_batch_decrypt_ref_mut, fpe_batch_decrypt_seed, 200, correct_batch_plaintext_body
        ),
        "fpe batch decrypt ignores ref-only mutation",
    )
    expect(
        not fpe_batch_semantic(
            fpe_batch_decrypt_seed, fpe_batch_decrypt_seed, 200, correct_batch_plaintext_body
        ),
        "fpe batch decrypt ignores correct plaintext",
    )
    expect(
        not fpe_batch_semantic(fpe_batch_decrypt_mut, fpe_batch_decrypt_seed, 400, '{"error":"x"}'),
        "fpe batch ignores 4xx",
    )

    token_encode_seed = {
        "ref": "token-self",
        "profile": TOKENIZATION_PROFILE,
        "plaintext": TOKEN_PLAINTEXT,
        "metadata": {},
    }
    token_decode_seed = {
        "ref": "token-self",
        "kid": "a" * 64,
        "profile": TOKENIZATION_PROFILE,
        "token": "tok_fuzz_deadbeef",
    }
    token_decode_mut = dict(token_decode_seed, token="tok_fuzz_ffffffff")
    token_decode_ref_mut = dict(token_decode_seed, ref="Zoken-fuzz")
    expect(
        tokenization_semantic(
            token_encode_seed, token_encode_seed, 200,
            json.dumps({"kid": "a" * 64, "profile": TOKENIZATION_PROFILE, "token": "tok_fuzz_" + TOKEN_PLAINTEXT}),
        ),
        "token encode flags plaintext leak",
    )
    expect(
        not tokenization_semantic(
            token_encode_seed, token_encode_seed, 200, json.dumps({"token": "tok_fuzz_abcdef"})
        ),
        "token encode ignores clean token",
    )
    expect(
        tokenization_semantic(token_decode_seed, token_decode_seed, 200, '{"plaintext":"WRONG"}'),
        "token decode flags wrong plaintext",
    )
    expect(
        tokenization_semantic(
            token_decode_mut, token_decode_seed, 200, json.dumps({"plaintext": TOKEN_PLAINTEXT})
        ),
        "token decode flags mutated token as original",
    )
    expect(
        not tokenization_semantic(
            token_decode_ref_mut, token_decode_seed, 200, json.dumps({"plaintext": TOKEN_PLAINTEXT})
        ),
        "token decode ignores ref-only mutation",
    )
    expect(
        not tokenization_semantic(
            token_decode_seed, token_decode_seed, 200, json.dumps({"plaintext": TOKEN_PLAINTEXT})
        ),
        "token decode ignores correct plaintext",
    )
    expect(
        not tokenization_semantic(token_decode_mut, token_decode_seed, 400, '{"error":"x"}'),
        "token decode ignores 4xx",
    )

    token_batch_encode_seed = {
        "profile": TOKENIZATION_PROFILE,
        "items": [
            {"ref": "token-self-0", "plaintext": TOKEN_BATCH_PLAINTEXTS[0], "metadata": {}},
            {"ref": "token-self-1", "plaintext": TOKEN_BATCH_PLAINTEXTS[1], "metadata": {}},
        ],
    }
    token_batch_decode_seed = {
        "kid": "a" * 64,
        "profile": TOKENIZATION_PROFILE,
        "items": [
            {"ref": "token-self-0", "token": "tok_fuzz_deadbeef"},
            {"ref": "token-self-1", "token": "tok_fuzz_cafebabe"},
        ],
    }
    token_batch_decode_mut = json.loads(json.dumps(token_batch_decode_seed))
    token_batch_decode_mut["items"][0]["token"] = "tok_fuzz_ffffffff"
    token_batch_decode_ref_mut = json.loads(json.dumps(token_batch_decode_seed))
    token_batch_decode_ref_mut["items"][0]["ref"] = "token-f*zz-0"
    correct_token_batch_plaintext_body = json.dumps(
        {"items": [{"plaintext": TOKEN_BATCH_PLAINTEXTS[0]}, {"plaintext": TOKEN_BATCH_PLAINTEXTS[1]}]}
    )
    expect(
        tokenization_batch_semantic(
            token_batch_encode_seed, token_batch_encode_seed, 200,
            json.dumps({"items": [{"token": "tok_fuzz_" + TOKEN_BATCH_PLAINTEXTS[0]}, {"token": "tok_fuzz_clean"}]}),
        ),
        "token batch encode flags plaintext leak",
    )
    expect(
        not tokenization_batch_semantic(
            token_batch_encode_seed, token_batch_encode_seed, 200,
            json.dumps({"items": [{"token": "tok_fuzz_abcdef"}, {"token": "tok_fuzz_123456"}]}),
        ),
        "token batch encode ignores clean tokens",
    )
    expect(
        tokenization_batch_semantic(
            token_batch_decode_seed, token_batch_decode_seed, 200,
            json.dumps({"items": [{"plaintext": "WRONG"}, {"plaintext": "X"}]}),
        ),
        "token batch decode flags wrong plaintext",
    )
    expect(
        tokenization_batch_semantic(
            token_batch_decode_mut, token_batch_decode_seed, 200, correct_token_batch_plaintext_body
        ),
        "token batch decode flags mutated token as original",
    )
    expect(
        not tokenization_batch_semantic(
            token_batch_decode_ref_mut, token_batch_decode_seed, 200, correct_token_batch_plaintext_body
        ),
        "token batch decode ignores ref-only mutation",
    )
    expect(
        not tokenization_batch_semantic(
            token_batch_decode_seed, token_batch_decode_seed, 200, correct_token_batch_plaintext_body
        ),
        "token batch decode ignores correct plaintext",
    )
    expect(
        not tokenization_batch_semantic(
            token_batch_decode_mut, token_batch_decode_seed, 400, '{"error":"x"}'
        ),
        "token batch decode ignores 4xx",
    )

    for label in failures:
        print(f"SELF-CHECK FAIL: {label}")
    print(f"SUMMARY self-check passed={total - len(failures)} failed={len(failures)}")
    return 1 if failures else 0
