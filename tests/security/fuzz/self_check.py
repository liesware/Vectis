"""Offline self-tests for the semantic oracles in semantics.py.

Each oracle is exercised with hand-built mock responses to prove it both accepts
a valid flow and flags the specific defect it exists to catch. Run with
`http_fuzz.py --self-check`; it needs no server. Kept in its own module so
semantics.py stays a library of oracles rather than a library-plus-test-suite.
"""

import json

from semantics import (
    FPE_BATCH_PLAINTEXTS,
    FPE_PLAINTEXT,
    FPE_PROFILE,
    INTERNAL_SEED_PLAINTEXT,
    TOKENIZATION_PROFILE,
    TOKEN_BATCH_PLAINTEXTS,
    TOKEN_PLAINTEXT,
    batch_duplicate_ref_rejection,
    batch_output_contract,
    commitment_batch_contract_semantic,
    commitment_randomness_semantic,
    compact_signature_integrity_semantic,
    config_semantic,
    fpe_batch_contract_semantic,
    fpe_batch_semantic,
    fpe_semantic,
    index_batch_transaction_semantic,
    index_determinism_semantic,
    internal_encrypt_semantic,
    internal_semantic,
    lifecycle_contract_semantic,
    mac_batch_contract_semantic,
    mac_determinism_semantic,
    masking_batch_contract_semantic,
    masking_policy_semantic,
    one_time_batch_semantic,
    one_time_race_semantic,
    one_time_single_semantic,
    reject_malformed_body_semantic,
    token_batch_contract_semantic,
    token_batch_duplicate_policy_semantic,
    token_semantic,
    tokenization_batch_semantic,
    tokenization_semantic,
    sharing_integrity_semantic,
)


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

    # Floor oracle: a body that is not a JSON object must never be accepted with 200.
    expect(
        reject_malformed_body_semantic(None, {"a": 1}, 200, ""),
        "malformed floor flags a non-JSON body accepted with 200",
    )
    expect(
        reject_malformed_body_semantic([1, 2], {"a": 1}, 200, ""),
        "malformed floor flags a JSON array accepted with 200",
    )
    expect(
        not reject_malformed_body_semantic({"a": 1}, {"a": 1}, 200, ""),
        "malformed floor ignores a valid object body",
    )
    expect(
        not reject_malformed_body_semantic(None, {"a": 1}, 400, ""),
        "malformed floor ignores a rejected non-object body",
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

    one_time_plaintext = "one-time-self-check"
    one_time_single = [
        (200, '{"token":"opaque"}'),
        (200, json.dumps({"plaintext": one_time_plaintext})),
        (404, '{"error":"token not found"}'),
    ]
    expect(
        not one_time_single_semantic(one_time_single, one_time_plaintext),
        "one-time single accepts one decode followed by not found",
    )
    expect(
        one_time_single_semantic(
            [one_time_single[0], one_time_single[1], (200, "{}")], one_time_plaintext
        ),
        "one-time single flags successful replay",
    )

    one_time_batch = [
        (200, '{"items":[{"token":"opaque-a"},{"token":"opaque-b"}]}'),
        (200, '{"plaintext":"second"}'),
        (404, '{"error":"batch item 1 failed: token not found"}'),
        (200, json.dumps({"plaintext": one_time_plaintext})),
    ]
    expect(
        not one_time_batch_semantic(one_time_batch, one_time_plaintext),
        "one-time batch preserves the unconsumed item after rollback",
    )
    expect(
        one_time_batch_semantic(
            [one_time_batch[0], one_time_batch[1], (404, '{"items":[]}'), one_time_batch[3]],
            one_time_plaintext,
        ),
        "one-time batch flags partial output on rejection",
    )
    expect(
        one_time_batch_semantic(
            [(200, '{"items":[]}'), one_time_batch[1], one_time_batch[2], one_time_batch[3]],
            one_time_plaintext,
        ),
        "one-time batch flags a 200 encode that returned no tokens",
    )
    expect(
        one_time_batch_semantic(
            [
                one_time_batch[0],
                one_time_batch[1],
                (404, '{"error":"batch item 1 failed: token not found","echo":"second"}'),
                one_time_batch[3],
            ],
            one_time_plaintext,
            [one_time_plaintext, "second"],
        ),
        "one-time batch flags a leak of the already-consumed plaintext",
    )

    one_time_race = [
        (200, '{"token":"opaque"}'),
        (200, json.dumps({"plaintext": one_time_plaintext})),
        (404, '{"error":"token not found"}'),
    ]
    expect(
        not one_time_race_semantic(one_time_race, one_time_plaintext),
        "one-time race accepts exactly one winner",
    )
    expect(
        one_time_race_semantic(
            [one_time_race[0], one_time_race[1], (200, json.dumps({"plaintext": one_time_plaintext}))],
            one_time_plaintext,
        ),
        "one-time race flags two winners",
    )

    duplicate_policy = [
        (200, '{"token":"opaque"}'),
        (400, '{"error":"batch item 1 failed: token batch contains duplicated token"}'),
        (200, '{"token":"opaque"}'),
        (
            200,
            json.dumps(
                {
                    "items": [
                        {"ref": "reusable-duplicate-0", "plaintext": one_time_plaintext},
                        {"ref": "reusable-duplicate-1", "plaintext": one_time_plaintext},
                    ]
                }
            ),
        ),
    ]
    expect(
        not token_batch_duplicate_policy_semantic(duplicate_policy, one_time_plaintext),
        "duplicate policy distinguishes one-time and reusable profiles",
    )
    expect(
        token_batch_duplicate_policy_semantic(
            [duplicate_policy[0], duplicate_policy[1], duplicate_policy[2], (400, '{"error":"x"}')],
            one_time_plaintext,
        ),
        "duplicate policy flags reusable rejection",
    )

    batch_kid = "c" * 64
    batch_profile = "batch-self-check"
    batch_refs = ["batch-0", "batch-1"]
    batch_success = (
        200,
        json.dumps(
            {
                "kid": batch_kid,
                "profile": batch_profile,
                "items": [
                    {"ref": batch_refs[0], "value": "one"},
                    {"ref": batch_refs[1], "value": "two"},
                ],
            }
        ),
    )
    expect(
        not batch_output_contract(*batch_success, batch_kid, batch_profile, batch_refs, ("value",)),
        "batch contract accepts ordered output",
    )
    expect(
        batch_output_contract(
            200,
            json.dumps(
                {
                    "kid": batch_kid,
                    "profile": batch_profile,
                    "items": [
                        {"ref": batch_refs[1], "value": "one"},
                        {"ref": batch_refs[0], "value": "two"},
                    ],
                }
            ),
            batch_kid,
            batch_profile,
            batch_refs,
            ("value",),
        ),
        "batch contract flags reordered output",
    )
    expect(
        batch_output_contract(
            200,
            json.dumps(
                {
                    "kid": batch_kid,
                    "profile": batch_profile,
                    "items": [
                        {"ref": batch_refs[0], "value": "one", "plaintext": "leak"},
                        {"ref": batch_refs[1], "value": "two"},
                    ],
                }
            ),
            batch_kid,
            batch_profile,
            batch_refs,
            ("value",),
        ),
        "batch contract flags an item with an extra leaked field",
    )
    expect(
        batch_output_contract(
            200,
            json.dumps(
                {
                    "kid": batch_kid,
                    "profile": batch_profile,
                    "items": [
                        {"ref": batch_refs[0]},
                        {"ref": batch_refs[1], "value": "two"},
                    ],
                }
            ),
            batch_kid,
            batch_profile,
            batch_refs,
            ("value",),
        ),
        "batch contract flags an item missing a required field",
    )
    duplicate_ref = (400, '{"error":"batch item 1 failed: ref must be unique"}')
    expect(
        not batch_duplicate_ref_rejection(*duplicate_ref),
        "batch contract accepts indexed duplicate-ref rejection",
    )
    expect(
        batch_duplicate_ref_rejection(400, '{"error":"batch item 1 failed: ref","items":[]}'),
        "batch contract flags partial output on rejection",
    )
    expect(
        batch_duplicate_ref_rejection(400, '{"error":"duplicate ref"}'),
        "batch contract flags unindexed rejection",
    )

    index_case = {
        "refs": batch_refs,
        "responses": [
            duplicate_ref,
            (200, json.dumps({"matched": False})),
            (200, json.dumps({"kid": batch_kid, "profile": batch_profile, "items": [{"ref": batch_refs[0], "index": "a"}, {"ref": batch_refs[1], "index": "b"}]})),
            (200, json.dumps({"kid": batch_kid, "profile": batch_profile, "items": [{"ref": batch_refs[0], "matched": True, "index": "a"}, {"ref": batch_refs[1], "matched": True, "index": "b"}]})),
            duplicate_ref,
        ],
    }
    expect(
        not index_batch_transaction_semantic(index_case, {"kid": batch_kid, "profile": batch_profile}),
        "index batch contract accepts rollback and ordered persistence",
    )
    index_case["responses"][1] = (200, json.dumps({"matched": True}))
    expect(
        index_batch_transaction_semantic(index_case, {"kid": batch_kid, "profile": batch_profile}),
        "index batch contract flags partial persistence",
    )

    def contract_response(items):
        return 200, json.dumps({"kid": batch_kid, "profile": batch_profile, "items": items})

    contract_context = {"kid": batch_kid, "profile": batch_profile}
    fpe_case = {
        "refs": batch_refs,
        "plaintexts": ["one", "two"],
        "responses": [
            contract_response([{"ref": batch_refs[0], "ciphertext": "x"}, {"ref": batch_refs[1], "ciphertext": "y"}]),
            contract_response([{"ref": batch_refs[0], "plaintext": "one"}, {"ref": batch_refs[1], "plaintext": "two"}]),
            duplicate_ref,
            duplicate_ref,
        ],
    }
    expect(not fpe_batch_contract_semantic(fpe_case, contract_context), "fpe batch contract accepts valid flow")
    fpe_case["responses"][1] = contract_response([{"ref": batch_refs[0], "plaintext": "bad"}, {"ref": batch_refs[1], "plaintext": "two"}])
    expect(fpe_batch_contract_semantic(fpe_case, contract_context), "fpe batch contract flags wrong plaintext")

    token_case = {
        "refs": batch_refs,
        "plaintexts": ["one", "two"],
        "metadata": [{"n": 1}, {"n": 2}],
        "responses": [
            contract_response([{"ref": batch_refs[0], "token": "x"}, {"ref": batch_refs[1], "token": "y"}]),
            contract_response([{"ref": batch_refs[0], "plaintext": "one", "metadata": {"n": 1}}, {"ref": batch_refs[1], "plaintext": "two", "metadata": {"n": 2}}]),
            duplicate_ref,
            duplicate_ref,
        ],
    }
    expect(not token_batch_contract_semantic(token_case, contract_context), "token batch contract accepts valid flow")
    token_case["responses"][1] = contract_response([{"ref": batch_refs[0], "plaintext": "one", "metadata": {"n": 1}}, {"ref": batch_refs[1], "plaintext": "two", "metadata": {"n": 3}}])
    expect(token_batch_contract_semantic(token_case, contract_context), "token batch contract flags wrong metadata")

    mac_case = {
        "refs": batch_refs,
        "responses": [
            contract_response([{"ref": batch_refs[0], "digest": "a"}, {"ref": batch_refs[1], "digest": "b"}]),
            contract_response([{"ref": batch_refs[0], "valid": True}, {"ref": batch_refs[1], "valid": True}]),
            duplicate_ref,
            duplicate_ref,
        ],
    }
    expect(not mac_batch_contract_semantic(mac_case, contract_context), "mac batch contract accepts valid flow")
    mac_case["responses"][1] = contract_response([{"ref": batch_refs[0], "valid": True}, {"ref": batch_refs[1], "valid": False}])
    expect(mac_batch_contract_semantic(mac_case, contract_context), "mac batch contract flags failed valid item")

    masking_case = {
        "refs": batch_refs,
        "masked": ["****one", "****two"],
        "responses": [contract_response([{"ref": batch_refs[0], "masked": "****one"}, {"ref": batch_refs[1], "masked": "****two"}]), duplicate_ref],
    }
    expect(not masking_batch_contract_semantic(masking_case, contract_context), "mask batch contract accepts valid flow")
    masking_case["responses"][0] = contract_response([{"ref": batch_refs[0], "masked": "wrong"}, {"ref": batch_refs[1], "masked": "****two"}])
    expect(masking_batch_contract_semantic(masking_case, contract_context), "mask batch contract flags wrong policy output")

    commitment_case = {
        "refs": batch_refs,
        "responses": [
            contract_response([{"ref": batch_refs[0], "commitment": "a", "opening": "x"}, {"ref": batch_refs[1], "commitment": "b", "opening": "y"}]),
            contract_response([{"ref": batch_refs[0], "valid": True}, {"ref": batch_refs[1], "valid": True}]),
            duplicate_ref,
            duplicate_ref,
        ],
    }
    expect(not commitment_batch_contract_semantic(commitment_case, contract_context), "commitment batch contract accepts valid flow")
    commitment_case["responses"][1] = contract_response([{"ref": batch_refs[0], "valid": True}, {"ref": batch_refs[1], "valid": False}])
    expect(commitment_batch_contract_semantic(commitment_case, contract_context), "commitment batch contract flags failed valid item")

    lifecycle_records = [
        {
            "state": "retired",
            "phase": "historical",
            "operation": "fpe_decrypt",
            "expected": "allowed",
            "status": 200,
            "body": json.dumps({"plaintext": FPE_PLAINTEXT}),
        },
        {
            "state": "retired",
            "phase": "production",
            "operation": "fpe_encrypt",
            "expected": "rejected",
            "status": 403,
            "body": json.dumps({"error": "key is retired and can only be used for decrypt or verification"}),
        },
        {
            "state": "disabled",
            "phase": "historical",
            "operation": "token_decode",
            "expected": "rejected",
            "status": 403,
            "body": json.dumps({"error": "key is currently disabled"}),
        },
        {
            "state": "compromised",
            "phase": "production",
            "operation": "share_split",
            "expected": "rejected",
            "status": 403,
            "body": json.dumps({"error": "key is compromised and cannot be used for security reasons"}),
        },
        {
            "state": "destroyed",
            "phase": "public",
            "operation": "public_key",
            "expected": "rejected",
            "status": 403,
            "body": json.dumps({"error": "key is logically destroyed and cannot be used"}),
        },
    ]
    expect(not lifecycle_contract_semantic(lifecycle_records), "lifecycle contract accepts the policy matrix")
    lifecycle_records[2] = dict(lifecycle_records[2], status=200, body=json.dumps({"plaintext": TOKEN_PLAINTEXT}))
    expect(lifecycle_contract_semantic(lifecycle_records), "lifecycle contract flags blocked historical use")
    lifecycle_records[2] = {
        "state": "disabled",
        "phase": "historical",
        "operation": "token_decode",
        "expected": "rejected",
        "status": 403,
        "body": json.dumps({"error": "key is currently disabled", "plaintext": TOKEN_PLAINTEXT}),
    }
    expect(lifecycle_contract_semantic(lifecycle_records), "lifecycle contract flags output in rejection")

    crypto_context = {"kid": "a" * 64, "profile": "crypto-self"}
    mac_case = {"responses": [
        (200, '{"digest":"aa"}'), (200, '{"digest":"aa"}'),
        (200, '{"valid":true}'), (200, '{"valid":false}'), (200, '{"valid":false}'),
    ]}
    expect(not mac_determinism_semantic(mac_case, crypto_context), "MAC determinism accepts valid flow")
    mac_case["responses"][1] = (200, '{"digest":"bb"}')
    expect(mac_determinism_semantic(mac_case, crypto_context), "MAC determinism flags changed digest")

    index_case = {"responses": [
        (200, '{"index":"aa"}'), (200, '{"index":"aa"}'),
        (200, '{"matched":true}'), (200, '{"matched":false}'),
    ]}
    expect(not index_determinism_semantic(index_case, crypto_context), "index determinism accepts valid flow")
    index_case["responses"][3] = (200, '{"matched":true}')
    expect(index_determinism_semantic(index_case, crypto_context), "index determinism flags changed plaintext match")

    masking_case = {"plaintext": "4111111111111111", "expected": "************1111", "response": (200, '{"masked":"************1111"}', {})}
    expect(not masking_policy_semantic(masking_case, crypto_context), "mask policy accepts exact redacted output")
    masking_case["response"] = (200, '{"masked":"4111111111111111"}', {})
    expect(masking_policy_semantic(masking_case, crypto_context), "mask policy flags plaintext leak")

    commitment_case = {"responses": [
        (200, '{"opening":"AA","commitment":"aa"}'), (200, '{"opening":"BB","commitment":"bb"}'),
        (200, '{"valid":true}'), (200, '{"valid":false}'), (200, '{"valid":false}'),
    ]}
    expect(not commitment_randomness_semantic(commitment_case, crypto_context), "commitment randomness accepts valid flow")
    commitment_case["responses"][1] = (200, '{"opening":"AA","commitment":"aa"}')
    expect(commitment_randomness_semantic(commitment_case, crypto_context), "commitment randomness flags reused opening")

    sharing_case = {"plaintext": "share-self", "checks": [
        (200, '{"plaintext":"share-self"}'), (400, '{"error":"x"}'),
        (400, '{"error":"x"}'), (400, '{"error":"x"}'), (400, '{"error":"x"}'),
    ]}
    expect(not sharing_integrity_semantic(sharing_case, crypto_context), "sharing integrity accepts valid flow")
    sharing_case["checks"][3] = (200, '{"plaintext":"share-self"}')
    expect(sharing_integrity_semantic(sharing_case, crypto_context), "sharing integrity flags tag bypass")

    compact_case = {
        "message_hash_hex": "cd" * 32,
        "checks": [
            ("control", 200, '{"signature":"redacted"}', 200, '{"valid":"ok","status":{"ml-dsa":"ok","eddsa":"ok"}}', "signature-control"),
            ("header", 200, '{"signature":"redacted"}', 200, '{"valid":"fail","status":{"ml-dsa":"fail","eddsa":"not_checked"}}', "signature-header"),
            ("payload", 200, '{"signature":"redacted"}', 200, '{"valid":"fail","status":{"ml-dsa":"fail","eddsa":"not_checked"}}', "signature-payload"),
            ("eddsa", 200, '{"signature":"redacted"}', 200, '{"valid":"fail","status":{"ml-dsa":"ok","eddsa":"fail"}}', "signature-eddsa"),
            ("ml_dsa", 200, '{"signature":"redacted"}', 200, '{"valid":"fail","status":{"ml-dsa":"fail","eddsa":"not_checked"}}', "signature-ml-dsa"),
        ],
    }
    expect(not compact_signature_integrity_semantic(compact_case, crypto_context), "compact signature accepts expected hybrid states")
    compact_case["checks"][4] = ("ml_dsa", 200, '{"signature":"redacted"}', 200, '{"valid":"fail","status":{"ml-dsa":"fail","eddsa":"fail"}}', "signature-ml-dsa")
    expect(compact_signature_integrity_semantic(compact_case, crypto_context), "compact signature flags ML-DSA order violation")

    for label in failures:
        print(f"SELF-CHECK FAIL: {label}")
    print(f"SUMMARY self-check passed={total - len(failures)} failed={len(failures)}")
    return 1 if failures else 0
