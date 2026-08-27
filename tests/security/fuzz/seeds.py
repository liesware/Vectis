import copy
import json

from config import (
    configure_commitment_profile,
    configure_fpe_profile,
    configure_mac_profile,
    configure_masking_profile,
    configure_one_time_tokenization_profiles,
    configure_sharing_profile,
    configure_tokenization_profile,
)
from semantics import (
    COMMITMENT_PLAINTEXTS,
    COMMITMENT_PROFILE,
    FPE_BATCH_PLAINTEXTS,
    FPE_PLAINTEXT,
    FPE_PROFILE,
    INTERNAL_SEED_PLAINTEXT,
    KID_HEX,
    MAC_PLAINTEXTS,
    MAC_PROFILE,
    MASKING_PLAINTEXTS,
    MASKING_PROFILE,
    ONE_TIME_TOKENIZATION_PROFILE,
    RECIPIENT_HEX,
    SHARING_PLAINTEXT,
    SHARING_PROFILE,
    TOKENIZATION_PROFILE,
    TOKEN_BATCH_PLAINTEXTS,
    TOKEN_PLAINTEXT,
)


# Minimal, policy-safe key requests (one per crypto profile) used to CREATE seed
# keys. Creating with only tag+profile works under both crypto policies, and the
# different profiles exercise AES-GCM nonce sizes, ChaCha20 (24-byte nonce),
# and Ed448/X448 vs Ed25519/X25519.
KEY_CASES = [
    {"tag": "fuzz-performance", "profile": "hybrid-performance-v1"},
    {"tag": "fuzz-standard", "profile": "hybrid-standard-v1"},
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


_BATCH_CONTRACTS = {
    "fpe": (
        {"tag": "fuzz-fpe-batch-contract", "profile": "hybrid-high-assurance-v1"},
        configure_fpe_profile,
        FPE_PROFILE,
    ),
    "token": (
        {"tag": "fuzz-token-batch-contract", "profile": "hybrid-performance-v1"},
        configure_tokenization_profile,
        TOKENIZATION_PROFILE,
    ),
    "mac": (
        {"tag": "fuzz-mac-batch-contract", "profile": "hybrid-standard-v1"},
        configure_mac_profile,
        MAC_PROFILE,
    ),
    "index": (
        {"tag": "fuzz-index-batch-contract", "profile": "hybrid-standard-v1"},
        configure_mac_profile,
        MAC_PROFILE,
    ),
    "mask": (
        {"tag": "fuzz-mask-batch-contract", "profile": "hybrid-standard-v1"},
        configure_masking_profile,
        MASKING_PROFILE,
    ),
    "commitment": (
        {"tag": "fuzz-commitment-batch-contract", "profile": "hybrid-standard-v1"},
        configure_commitment_profile,
        COMMITMENT_PROFILE,
    ),
}

ONE_TIME_TOKEN_PLAINTEXT = "fuzz one-time token plaintext"
ONE_TIME_BATCH_PLAINTEXTS = ["fuzz one-time batch first", "fuzz one-time batch second"]


def _create_key(client, case):
    status, body = client.post_json("/keys", case, auth=True)
    if status != 200:
        raise RuntimeError(f"could not create seed key ({case}): HTTP {status}: {body}")
    return json.loads(body)["kid"]


def batch_contract_context(client, capability):
    try:
        key_case, configure_profile, profile = _BATCH_CONTRACTS[capability]
    except KeyError as err:
        raise ValueError(f"unknown batch contract capability: {capability}") from err
    kid = _create_key(client, key_case)
    configure_profile(client, kid)
    return {"kid": kid, "profile": profile}


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


def send_message_seeds(client):
    kid = _create_key(client, {"tag": "fuzz-send", "profile": "hybrid-performance-v1"})
    return [(f"/message/{kid}", {"recipient_kid": RECIPIENT_HEX, "message": "fuzz message"})]


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
            f"/message/internal/encrypt/{kid}",
            {"plaintext": INTERNAL_SEED_PLAINTEXT},
            auth=True,
        )
        if status != 200:
            raise RuntimeError(f"could not encrypt seed message: HTTP {status}: {body}")
        seeds.append(("/message/internal/decrypt", json.loads(body)))
    return seeds


def internal_encrypt_seeds(client):
    seeds = []
    for case in KEY_CASES:
        kid = _create_key(client, case)
        seeds.append(
            (f"/message/internal/encrypt/{kid}", {"plaintext": INTERNAL_SEED_PLAINTEXT})
        )
    return seeds


def keys_seeds(_client):
    return [("/keys", copy.deepcopy(KEY_TARGET_SEED))]


def sign_body_seeds(client):
    seeds = []
    for case in KEY_CASES:
        kid = _create_key(client, case)
        seeds.append(
            (
                f"/sign/{kid}",
                {"message_hash": {"alg": "BLAKE2b(256)", "hex": "cd" * 32}},
            )
        )
    return seeds


def lifecycle_seeds(client):
    kid = _create_key(
        client, {"tag": "fuzz-lifecycle", "profile": "hybrid-performance-v1"}
    )
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


def fpe_seeds(client):
    kid = _create_key(
        client, {"tag": "fuzz-fpe", "profile": "hybrid-high-assurance-v1"}
    )
    configure_fpe_profile(client, kid)
    encrypt_seed = {"ref": "fpe-fuzz", "profile": FPE_PROFILE, "plaintext": FPE_PLAINTEXT}
    status, body = client.post_json(f"/fpe/encrypt/{kid}", encrypt_seed, auth=True)
    if status != 200:
        raise RuntimeError(f"could not encrypt fpe seed: HTTP {status}: {body}")
    parsed = json.loads(body)
    decrypt_seed = {
        "ref": "fpe-fuzz",
        "kid": kid,
        "profile": FPE_PROFILE,
        "ciphertext": parsed["ciphertext"],
    }
    return [(f"/fpe/encrypt/{kid}", encrypt_seed), ("/fpe/decrypt", decrypt_seed)]


def fpe_batch_seeds(client):
    kid = _create_key(
        client, {"tag": "fuzz-fpe-batch", "profile": "hybrid-high-assurance-v1"}
    )
    configure_fpe_profile(client, kid)
    encrypt_seed = {
        "profile": FPE_PROFILE,
        "items": [
            {"ref": f"fpe-fuzz-{index}", "plaintext": item}
            for index, item in enumerate(FPE_BATCH_PLAINTEXTS)
        ],
    }
    status, body = client.post_json(f"/fpe/encrypt/batch/{kid}", encrypt_seed, auth=True)
    if status != 200:
        raise RuntimeError(f"could not encrypt fpe batch seed: HTTP {status}: {body}")
    parsed = json.loads(body)
    decrypt_seed = {
        "kid": kid,
        "profile": FPE_PROFILE,
        "items": [
            {"ref": item["ref"], "ciphertext": item["ciphertext"]}
            for item in parsed["items"]
        ],
    }
    return [
        (f"/fpe/encrypt/batch/{kid}", encrypt_seed),
        ("/fpe/decrypt/batch", decrypt_seed),
    ]


def tokenization_seeds(client):
    kid = _create_key(client, {"tag": "fuzz-token", "profile": "hybrid-performance-v1"})
    configure_tokenization_profile(client, kid)
    encode_seed = {
        "ref": "token-fuzz",
        "profile": TOKENIZATION_PROFILE,
        "plaintext": TOKEN_PLAINTEXT,
        "metadata": {"tenant": "fuzz", "field": "patient_id"},
    }
    status, body = client.post_json(f"/token/encode/{kid}", encode_seed, auth=True)
    if status != 200:
        raise RuntimeError(f"could not encode token seed: HTTP {status}: {body}")
    token = json.loads(body)["token"]
    decode_seed = {"ref": "token-fuzz", "kid": kid, "profile": TOKENIZATION_PROFILE, "token": token}
    return [
        (f"/token/encode/{kid}", encode_seed),
        ("/token/decode", decode_seed),
    ]


def tokenization_batch_seeds(client):
    kid = _create_key(client, {"tag": "fuzz-token-batch", "profile": "hybrid-performance-v1"})
    configure_tokenization_profile(client, kid)
    encode_seed = {
        "profile": TOKENIZATION_PROFILE,
        "items": [
            {
                "ref": "token-fuzz-0",
                "plaintext": TOKEN_BATCH_PLAINTEXTS[0],
                "metadata": {"tenant": "fuzz", "field": "patient_id", "item": "one"},
            },
            {
                "ref": "token-fuzz-1",
                "plaintext": TOKEN_BATCH_PLAINTEXTS[1],
                "metadata": {"tenant": "fuzz", "field": "patient_id", "item": "two"},
            },
        ],
    }
    status, body = client.post_json(f"/token/encode/batch/{kid}", encode_seed, auth=True)
    if status != 200:
        raise RuntimeError(f"could not encode token batch seed: HTTP {status}: {body}")
    parsed = json.loads(body)
    decode_seed = {
        "kid": kid,
        "profile": TOKENIZATION_PROFILE,
        "items": [{"ref": item["ref"], "token": item["token"]} for item in parsed["items"]],
    }
    return [
        (f"/token/encode/batch/{kid}", encode_seed),
        ("/token/decode/batch", decode_seed),
    ]


def one_time_token_context(client):
    kid = _create_key(
        client,
        {"tag": "fuzz-one-time-token", "profile": "hybrid-performance-v1"},
    )
    configure_one_time_tokenization_profiles(client, kid)
    return {"kid": kid}


def issue_token(client, context, profile, ref, plaintext):
    status, body = client.post_json(
        f"/token/encode/{context['kid']}",
        {"ref": ref, "profile": profile, "plaintext": plaintext, "metadata": {}},
        auth=True,
    )
    try:
        parsed = json.loads(body) if status == 200 else None
    except json.JSONDecodeError:
        parsed = None
    token = parsed.get("token") if isinstance(parsed, dict) else None
    return status, body, token


def issue_token_batch(client, context, profile, items):
    status, body = client.post_json(
        f"/token/encode/batch/{context['kid']}",
        {"profile": profile, "items": items},
        auth=True,
    )
    try:
        parsed = json.loads(body) if status == 200 else None
    except json.JSONDecodeError:
        parsed = None
    tokens = (
        [item.get("token") for item in parsed.get("items", []) if isinstance(item, dict)]
        if isinstance(parsed, dict)
        else []
    )
    return status, body, tokens


def mac_seeds(client):
    kid = _create_key(client, {"tag": "fuzz-mac", "profile": "hybrid-standard-v1"})
    configure_mac_profile(client, kid)
    create_seed = {"ref": "mac-fuzz", "profile": MAC_PROFILE, "plaintext": MAC_PLAINTEXTS[0]}
    status, body = client.post_json(f"/mac/{kid}", create_seed, auth=True)
    if status != 200:
        raise RuntimeError(f"could not create mac seed: HTTP {status}: {body}")
    digest = json.loads(body)["digest"]
    verify_seed = {
        "ref": "mac-fuzz",
        "kid": kid,
        "profile": MAC_PROFILE,
        "plaintext": MAC_PLAINTEXTS[0],
        "digest": digest,
    }
    return [
        (f"/mac/{kid}", create_seed),
        ("/mac/verify", verify_seed),
    ]


def mac_batch_seeds(client):
    kid = _create_key(client, {"tag": "fuzz-mac-batch", "profile": "hybrid-standard-v1"})
    configure_mac_profile(client, kid)
    create_seed = {
        "profile": MAC_PROFILE,
        "items": [
            {"ref": f"mac-fuzz-{index}", "plaintext": plaintext}
            for index, plaintext in enumerate(MAC_PLAINTEXTS)
        ],
    }
    status, body = client.post_json(f"/mac/batch/{kid}", create_seed, auth=True)
    if status != 200:
        raise RuntimeError(f"could not create mac batch seed: HTTP {status}: {body}")
    parsed = json.loads(body)
    verify_seed = {
        "kid": kid,
        "profile": MAC_PROFILE,
        "items": [
            {
                "ref": item["ref"],
                "plaintext": plaintext,
                "digest": item["digest"],
            }
            for item, plaintext in zip(parsed["items"], MAC_PLAINTEXTS)
        ],
    }
    return [
        (f"/mac/batch/{kid}", create_seed),
        ("/mac/verify/batch", verify_seed),
    ]


def index_seeds(client):
    kid = _create_key(client, {"tag": "fuzz-index", "profile": "hybrid-standard-v1"})
    configure_mac_profile(client, kid)
    create_seed = {"ref": "index-fuzz", "profile": MAC_PROFILE, "plaintext": MAC_PLAINTEXTS[0]}
    status, body = client.post_json(f"/index/{kid}", create_seed, auth=True)
    if status != 200:
        raise RuntimeError(f"could not create index seed: HTTP {status}: {body}")
    verify_seed = {
        "ref": "index-fuzz",
        "kid": kid,
        "profile": MAC_PROFILE,
        "plaintext": MAC_PLAINTEXTS[0],
    }
    return [
        (f"/index/{kid}", create_seed),
        ("/index/verify", verify_seed),
    ]


def index_batch_seeds(client):
    kid = _create_key(client, {"tag": "fuzz-index-batch", "profile": "hybrid-standard-v1"})
    configure_mac_profile(client, kid)
    create_seed = {
        "profile": MAC_PROFILE,
        "items": [
            {"ref": f"index-fuzz-{index}", "plaintext": plaintext}
            for index, plaintext in enumerate(MAC_PLAINTEXTS)
        ],
    }
    status, body = client.post_json(f"/index/batch/{kid}", create_seed, auth=True)
    if status != 200:
        raise RuntimeError(f"could not create index batch seed: HTTP {status}: {body}")
    verify_seed = {
        "kid": kid,
        "profile": MAC_PROFILE,
        "items": [
            {"ref": f"index-fuzz-{index}", "plaintext": plaintext}
            for index, plaintext in enumerate(MAC_PLAINTEXTS)
        ],
    }
    return [
        (f"/index/batch/{kid}", create_seed),
        ("/index/verify/batch", verify_seed),
    ]


def masking_seeds(client):
    kid = _create_key(client, {"tag": "fuzz-mask", "profile": "hybrid-standard-v1"})
    configure_masking_profile(client, kid)
    return [
        (
            f"/mask/{kid}",
            {
                "ref": "mask-fuzz",
                "profile": MASKING_PROFILE,
                "plaintext": MASKING_PLAINTEXTS[0],
            },
        )
    ]


def masking_batch_seeds(client):
    kid = _create_key(client, {"tag": "fuzz-mask-batch", "profile": "hybrid-standard-v1"})
    configure_masking_profile(client, kid)
    return [
        (
            f"/mask/batch/{kid}",
            {
                "profile": MASKING_PROFILE,
                "items": [
                    {"ref": f"mask-fuzz-{index}", "plaintext": plaintext}
                    for index, plaintext in enumerate(MASKING_PLAINTEXTS)
                ],
            },
        )
    ]


def commitment_seeds(client):
    kid = _create_key(client, {"tag": "fuzz-commit", "profile": "hybrid-standard-v1"})
    configure_commitment_profile(client, kid)
    create_seed = {
        "ref": "commit-fuzz",
        "profile": COMMITMENT_PROFILE,
        "plaintext": COMMITMENT_PLAINTEXTS[0],
    }
    status, body = client.post_json(f"/commit/{kid}", create_seed, auth=True)
    if status != 200:
        raise RuntimeError(f"could not create commitment seed: HTTP {status}: {body}")
    parsed = json.loads(body)
    verify_seed = {
        "ref": "commit-fuzz",
        "kid": kid,
        "profile": COMMITMENT_PROFILE,
        "plaintext": COMMITMENT_PLAINTEXTS[0],
        "opening": parsed["opening"],
        "commitment": parsed["commitment"],
    }
    return [
        (f"/commit/{kid}", create_seed),
        ("/commit/verify", verify_seed),
    ]


def commitment_batch_seeds(client):
    kid = _create_key(client, {"tag": "fuzz-commit-batch", "profile": "hybrid-standard-v1"})
    configure_commitment_profile(client, kid)
    create_seed = {
        "profile": COMMITMENT_PROFILE,
        "items": [
            {"ref": f"commit-fuzz-{index}", "plaintext": plaintext}
            for index, plaintext in enumerate(COMMITMENT_PLAINTEXTS)
        ],
    }
    status, body = client.post_json(f"/commit/batch/{kid}", create_seed, auth=True)
    if status != 200:
        raise RuntimeError(f"could not create commitment batch seed: HTTP {status}: {body}")
    parsed = json.loads(body)
    verify_seed = {
        "kid": kid,
        "profile": COMMITMENT_PROFILE,
        "items": [
            {
                "ref": item["ref"],
                "plaintext": plaintext,
                "opening": item["opening"],
                "commitment": item["commitment"],
            }
            for item, plaintext in zip(parsed["items"], COMMITMENT_PLAINTEXTS)
        ],
    }
    return [
        (f"/commit/batch/{kid}", create_seed),
        ("/commit/verify/batch", verify_seed),
    ]


def sharing_seeds(client):
    kid = _create_key(client, {"tag": "fuzz-sharing", "profile": "hybrid-standard-v1"})
    configure_sharing_profile(client, kid)
    split_seed = {
        "profile": SHARING_PROFILE,
        "plaintext": SHARING_PLAINTEXT,
    }
    status, body = client.post_json(f"/shares/split/{kid}", split_seed, auth=True)
    if status != 200:
        raise RuntimeError(f"could not split sharing seed: HTTP {status}: {body}")
    parsed = json.loads(body)
    combine_seed = {
        "kid": kid,
        "profile": SHARING_PROFILE,
        "shares": parsed["shares"][:3],
    }
    return [
        (f"/shares/split/{kid}", split_seed),
        ("/shares/combine", combine_seed),
    ]
