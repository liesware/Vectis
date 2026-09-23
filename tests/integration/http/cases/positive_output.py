"""Positive HTTP helpers for one capability domain."""

import base64
import hashlib
import json

from lib.assertions import require
from lib.client import StatusClient

def print_section(title, rows):
    print(f"{title}:")
    for name, status in rows:
        print(f"- {name}: {status}")
    print()


def print_create_key(rows):
    print("Create key:")
    for algorithm, key_id in rows:
        print(f"- {algorithm}: OK")
        print(f"  id: {key_id}")
    print()


def require_duplicate_batch_ref_rejected(client, path, body, label):
    status, response = StatusClient(client.base_url, client.apikey).post(path, body, auth=True)
    require(status == 400, f"{label} duplicate ref must return 400")
    require(isinstance(response, dict), f"{label} duplicate ref must return JSON object")
    require(isinstance(response.get("error"), str), f"{label} duplicate ref must return JSON error")
    require(
        response["error"].startswith("batch item 1 failed:"),
        f"{label} duplicate ref error must identify the second item",
    )
    require("items" not in response, f"{label} duplicate ref must not return partial items")


def print_message(rows):
    print("message:")
    for key_id, timestamp, variant, ctx_len, plaintext in rows:
        print(f"- kid: {key_id}")
        print(f"  sent: OK")
        print(f"  final app: received OK")
        print(f"  timestamp: {timestamp}")
        print(f"  variant: {variant}")
        print(f"  ctx_hex_len: {ctx_len}")
        print(f"  plain_text: {plaintext}")
    print()


def print_internal_message(rows):
    print("internal message:")
    for key_id, timestamp, variant, ctx_len, plaintext in rows:
        print(f"- kid: {key_id}")
        print(f"  encrypt: OK")
        print(f"  decrypt: OK")
        print(f"  timestamp: {timestamp}")
        print(f"  variant: {variant}")
        print(f"  ctx_hex_len: {ctx_len}")
        print(f"  plain_text: {plaintext}")
    print()


def print_fpe(rows):
    print("fpe:")
    for key_id, profile, ciphertext, plaintext in rows:
        print(f"- kid: {key_id}")
        print(f"  profile: {profile}")
        print(f"  encrypt: OK")
        print(f"  decrypt: OK")
        print(f"  ciphertext: {ciphertext}")
        print(f"  plain_text: {plaintext}")
    print()


def print_fpe_batch(rows):
    print("fpe batch:")
    for key_id, profile, ciphertexts, plaintexts in rows:
        print(f"- kid: {key_id}")
        print(f"  profile: {profile}")
        print(f"  encrypt_batch: OK")
        print(f"  decrypt_batch: OK")
        print(f"  ciphertexts: {','.join(ciphertexts)}")
        print(f"  plain_texts: {','.join(plaintexts)}")
    print()


def print_token(rows):
    print("token:")
    for key_id, profile, token_preview, plaintext in rows:
        print(f"- kid: {key_id}")
        print(f"  profile: {profile}")
        print(f"  encode: OK")
        print(f"  decode: OK")
        print(f"  token: {token_preview}")
        print(f"  plain_text: {plaintext}")
    print()


def print_token_batch(rows):
    print("token batch:")
    for key_id, profile, token_previews, plaintexts in rows:
        print(f"- kid: {key_id}")
        print(f"  profile: {profile}")
        print(f"  encode_batch: OK")
        print(f"  decode_batch: OK")
        print(f"  tokens: {','.join(token_previews)}")
        print(f"  plain_texts: {','.join(plaintexts)}")
    print()


