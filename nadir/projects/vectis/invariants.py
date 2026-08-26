"""Vectis-specific semantic expectations; execution remains in Nadir core."""

from __future__ import annotations

import json
import re

from nadir.http import HttpResult
from nadir.workflows import EvaluationContext, Finding


_HEX = re.compile(r"[0-9a-fA-F]+\Z")
_B64URL = re.compile(r"[A-Za-z0-9_-]+\Z")
_KEY_SHAPE = {
    "eddsa": "public_key_der_hex",
    "xecdh": "public_key_hex",
    "ml-dsa": "public_key_der_hex",
    "ml-kem": "public_key_der_hex",
}
_SYMMETRIC_VARIANTS = frozenset({"ChaCha20Poly1305", "AES-128/GCM", "AES-192/GCM", "AES-256/GCM"})


def _finding(code: str, message: str) -> tuple[Finding, ...]:
    return (Finding(code, message),)


def _json(result: HttpResult) -> object | None:
    try:
        return json.loads(result.body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def _is_hex(value: object) -> bool:
    return isinstance(value, str) and bool(value) and len(value) % 2 == 0 and _HEX.fullmatch(value) is not None


def _internal_message(result: HttpResult, context: EvaluationContext) -> tuple[dict[str, object] | None, tuple[Finding, ...]]:
    body = _json(result)
    plaintext = context.variables.get("internal_message_plaintext")
    if not isinstance(plaintext, str):
        return None, _finding("internal-message-input-invalid", "internal message plaintext control is unavailable")
    if plaintext.encode("utf-8") in result.body or any(plaintext in value for _, value in result.headers):
        return None, _finding("internal-message-encrypt-leaks-plaintext", "internal message envelope exposes the plaintext")
    if not isinstance(body, dict) or set(body) != {"timestamp", "kid", "message"}:
        return None, _finding("internal-message-envelope-invalid", "internal message response has an invalid envelope shape")
    timestamp, message = body.get("timestamp"), body.get("message")
    if (
        not isinstance(timestamp, str)
        or not timestamp.isdigit()
        or body.get("kid") != context.variables.get("kid")
        or not isinstance(message, dict)
        or set(message) != {"ctx", "nonce", "aad", "variant"}
        or not _is_hex(message.get("ctx"))
        or not _is_hex(message.get("nonce"))
        or not isinstance(message.get("aad"), str)
        or not message["aad"]
        or message.get("variant") not in _SYMMETRIC_VARIANTS
    ):
        return None, _finding("internal-message-envelope-invalid", "internal message response does not contain a valid opaque envelope")
    return body, ()


def internal_message_encrypt_output(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    _, findings = _internal_message(result, context)
    return findings


def internal_message_round_trip(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    plaintext = context.variables.get("internal_message_plaintext")
    if not isinstance(plaintext, str):
        return _finding("internal-message-input-invalid", "internal message plaintext control is unavailable")
    body = _json(result)
    if body != {"plaintext": plaintext}:
        return _finding("internal-message-round-trip-failed", "internal message decrypt did not restore exactly the control plaintext")
    return ()


def internal_message_tamper_rejected(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    if result.failure is None and result.status is not None and 200 <= result.status < 300:
        return _finding("mutated-internal-message-accepted", "a modified internal-message AEAD envelope decrypted successfully")
    return ()


def _prohibited_field(value: object) -> str | None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str):
                return "non-string key"
            normalized = key.lower().replace("-", "_")
            if normalized == "kid" or any(marker in normalized for marker in ("private", "symmetric", "unseal", "secret")):
                return key
            found = _prohibited_field(nested)
            if found is not None:
                return found
    elif isinstance(value, list):
        for nested in value:
            found = _prohibited_field(nested)
            if found is not None:
                return found
    return None


def public_keys_output(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    body = _json(result)
    if body is None:
        return _finding("public-key-response-invalid-json", "public-key response is not valid JSON")
    prohibited = _prohibited_field(body)
    if prohibited is not None:
        return _finding("public-key-response-leaks-private-material", f"response contains prohibited field {prohibited!r}")
    if not isinstance(body, dict) or set(body) != {"info", "keys"} or not isinstance(body["info"], str) or not body["info"]:
        return _finding("public-key-response-invalid-shape", "response must contain exactly non-empty info and keys")
    keys = body["keys"]
    if not isinstance(keys, dict) or set(keys) != set(_KEY_SHAPE):
        return _finding("public-key-response-invalid-shape", "response keys do not match the public-key contract")
    for key_name, field_name in _KEY_SHAPE.items():
        key = keys[key_name]
        if not isinstance(key, dict) or set(key) != {"alg", field_name}:
            return _finding("public-key-response-invalid-shape", f"{key_name} key shape is invalid")
        if not isinstance(key["alg"], str) or not key["alg"] or not _is_hex(key[field_name]):
            return _finding("public-key-response-invalid-shape", f"{key_name} public key is invalid")
    return ()


def compact_signature_output(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    body = _json(result)
    if not isinstance(body, dict) or set(body) != {"kid", "signature"}:
        return _finding("sign-output-invalid-shape", "sign response must contain exactly kid and signature")
    if not isinstance(body["kid"], str) or not _is_hex(body["kid"]) or len(body["kid"]) != 64:
        return _finding("sign-output-invalid-shape", "sign response kid is invalid")
    signature = body["signature"]
    if not isinstance(signature, str) or len(signature.split(".")) != 4 or not all(signature.split(".")):
        return _finding("sign-output-invalid-shape", "sign response signature is not compact")
    return ()


def verification_success(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    body = _json(result)
    if not isinstance(body, dict) or body.get("valid") != "ok" or body.get("status") != {"eddsa": "ok", "ml-dsa": "ok"}:
        return _finding("verification-control-failed", "valid signature did not verify with both algorithms")
    return ()


def verification_failure(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    body = _json(result)
    if not isinstance(body, dict) or body.get("valid") != "fail" or not isinstance(body.get("status"), dict):
        return _finding("mutated-signature-accepted", "mutated signature was not rejected")
    status = body["status"]
    expected = {
        "compact-segment-0": {"eddsa": "not_checked", "ml-dsa": "fail"},
        "compact-segment-1": {"eddsa": "not_checked", "ml-dsa": "fail"},
        "compact-segment-2": {"eddsa": "fail", "ml-dsa": "ok"},
        "compact-segment-3": {"eddsa": "not_checked", "ml-dsa": "fail"},
    }
    if context.mutation is None or status != expected.get(context.mutation.name):
        return _finding("verification-order-invalid", "hybrid verification status does not match the mutated segment")
    return ()


def fpe_round_trip(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    body = _json(result)
    if not isinstance(body, dict):
        return _finding("fpe-round-trip-invalid-json", "FPE decrypt response is not valid JSON")
    expected = context.variables.get("fpe_plaintext")
    if body.get("ref") != context.variables.get("fpe_ref") or body.get("plaintext") != expected:
        return _finding("fpe-round-trip-failed", "FPE decrypt response did not restore the control plaintext")
    return ()


def retired_fpe_round_trip(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    body = _json(result)
    if (
        not isinstance(body, dict)
        or body.get("ref") != context.variables.get("retired_fpe_ref")
        or body.get("plaintext") != context.variables.get("retired_fpe_plaintext")
    ):
        return _finding("retired-fpe-decrypt-failed", "a retired KID did not permit its historical FPE decrypt")
    return ()


def fpe_encrypt_output(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    body = _json(result)
    plaintext = context.variables.get("fpe_plaintext")
    if (
        not isinstance(body, dict)
        or body.get("ref") != context.variables.get("fpe_ref")
        or body.get("kid") != context.variables.get("kid")
        or body.get("profile") != context.variables.get("fpe_profile")
        or not isinstance(body.get("ciphertext"), str)
        or not isinstance(plaintext, str)
        or len(body["ciphertext"]) != len(plaintext)
        or not body["ciphertext"].isdigit()
    ):
        return _finding("fpe-producer-invalid", "FPE encrypt response does not satisfy its control contract")
    return ()


def fpe_ciphertext_integrity(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    # FF1 does not authenticate ciphertext, so a tampered ciphertext need not
    # error; but it must never decrypt back to the original plaintext, which would
    # mean the corrupted bytes were ignored. No-5xx and no-leak are enforced by the
    # generic clauses paired with this one in the mutated oracle.
    body = _json(result)
    if isinstance(body, dict) and body.get("plaintext") == context.variables.get("fpe_plaintext"):
        return _finding("fpe-tamper-round-trips", "a tampered ciphertext decrypted to the original plaintext")
    return ()


def _mac_verification(result: HttpResult, context: EvaluationContext, expected: bool, code: str, message: str) -> tuple[Finding, ...]:
    # MAC verification is intentionally distinct from hybrid-signature
    # verification: its public contract uses a JSON boolean.
    body = _json(result)
    if not isinstance(body, dict) or body.get("ref") != context.variables.get("mac_ref") or body.get("valid") != expected:
        return _finding(code, message)
    return ()


def mac_verification_success(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    return _mac_verification(result, context, True, "mac-verification-control-failed", "control MAC digest did not verify")


def mac_create_output(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    body = _json(result)
    digest = body.get("digest") if isinstance(body, dict) else None
    if (
        not isinstance(body, dict)
        or body.get("ref") != context.variables.get("mac_ref")
        or body.get("kid") != context.variables.get("kid")
        or body.get("profile") != context.variables.get("mac_profile")
        or not isinstance(body.get("algorithm"), str)
        or not body["algorithm"]
        or not _is_hex(digest)
        or len(digest) not in {64, 96, 128}
    ):
        return _finding("mac-producer-invalid", "MAC create response does not satisfy its control contract")
    return ()


def mac_verification_failure(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    return _mac_verification(result, context, False, "mutated-mac-accepted", "mutated MAC digest was not rejected")


def _index_plaintext_leak(result: HttpResult, context: EvaluationContext, label: str) -> tuple[Finding, ...]:
    """Per-index defence-in-depth: no declared index plaintext may echo back.

    NoDeclaredSecrets guards these globally, but each index validator also checks
    directly so a leak is reported with the index-specific code; this helper is the
    single implementation the three index shapes share.
    """
    plaintexts = tuple(
        value
        for name, value in context.variables.items()
        if name.startswith("index_") and "plaintext" in name and isinstance(value, str) and value
    )
    if any(value.encode("utf-8") in result.body or any(value in header for _, header in result.headers) for value in plaintexts):
        return _finding("blind-index-response-leaks-plaintext", f"blind-index {label} exposes a declared plaintext")
    return ()


def _index_response(
    result: HttpResult,
    context: EvaluationContext,
    *,
    ref_variable: str,
) -> tuple[dict[str, object] | None, tuple[Finding, ...]]:
    """Validate the shared single-index response shape without exposing inputs."""
    leak = _index_plaintext_leak(result, context, "response")
    if leak:
        return None, leak
    body = _json(result)
    if (
        not isinstance(body, dict)
        or body.get("ref") != context.variables.get(ref_variable)
        or body.get("kid") != context.variables.get("kid")
        or body.get("profile") != context.variables.get("index_profile")
        or not _is_hex(body.get("index"))
        or len(body["index"]) not in {64, 96, 128}
    ):
        return None, _finding("blind-index-output-invalid", "blind-index response does not satisfy its public contract")
    return body, ()


def blind_index_create_output(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    body, findings = _index_response(result, context, ref_variable="index_ref")
    if findings:
        return findings
    if body is None or set(body) != {"ref", "kid", "profile", "index"}:
        return _finding("blind-index-output-invalid", "blind-index create response has an invalid shape")
    return ()


def blind_index_membership(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    body, findings = _index_response(result, context, ref_variable="index_ref")
    if findings:
        return findings
    if body is None or set(body) != {"ref", "kid", "profile", "matched", "index"} or body.get("matched") is not True:
        return _finding("blind-index-membership-failed", "persisted blind index did not match its original plaintext")
    if body.get("index") != context.variables.get("index_digest"):
        return _finding("blind-index-digest-mismatch", "blind-index verify returned a digest different from create")
    return ()


def blind_index_nonmembership(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    body, findings = _index_response(result, context, ref_variable="index_ref")
    if findings:
        return findings
    if body is None or set(body) != {"ref", "kid", "profile", "matched", "index"} or body.get("matched") is not False:
        return _finding("blind-index-nonmembership-failed", "changed blind-index plaintext unexpectedly matched")
    if body.get("index") == context.variables.get("index_digest"):
        return _finding("blind-index-determinism-failed", "different plaintext produced the captured blind-index digest")
    return ()


def blind_index_verify_nonmembership(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    body, findings = _index_response(result, context, ref_variable="index_verify_ref")
    if findings:
        return findings
    if body is None or set(body) != {"ref", "kid", "profile", "matched", "index"} or body.get("matched") is not False:
        return _finding("blind-index-nonmembership-failed", "uncreated blind index unexpectedly matched")
    return ()


def _batch_index_response(result: HttpResult, context: EvaluationContext) -> tuple[list[dict[str, object]] | None, tuple[Finding, ...]]:
    leak = _index_plaintext_leak(result, context, "batch response")
    if leak:
        return None, leak
    body = _json(result)
    expected_refs = [context.variables.get("index_batch_ref_zero"), context.variables.get("index_batch_ref_one")]
    if (
        not isinstance(body, dict)
        or set(body) != {"kid", "profile", "items"}
        or body.get("kid") != context.variables.get("kid")
        or body.get("profile") != context.variables.get("index_profile")
        or not isinstance(body.get("items"), list)
        or len(body["items"]) != 2
        or not all(isinstance(item, dict) and set(item) == {"ref", "matched", "index"} for item in body["items"])
    ):
        return None, _finding("blind-index-batch-output-invalid", "blind-index batch verify response has an invalid shape")
    items = body["items"]
    if [item["ref"] for item in items] != expected_refs or not all(_is_hex(item["index"]) for item in items):
        return None, _finding("blind-index-batch-output-invalid", "blind-index batch verify did not preserve its item contract")
    return items, ()


def blind_index_batch_membership(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    items, findings = _batch_index_response(result, context)
    if findings:
        return findings
    if items is None or [item["matched"] for item in items] != [True, True]:
        return _finding("blind-index-batch-membership-failed", "blind-index batch control values did not both match")
    expected = [context.variables.get("index_batch_zero"), context.variables.get("index_batch_one")]
    if [item["index"] for item in items] != expected:
        return _finding("blind-index-batch-digest-mismatch", "blind-index batch verify digests differ from batch create")
    return ()


def blind_index_batch_nonmembership(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    items, findings = _batch_index_response(result, context)
    if findings:
        return findings
    if items is None or [item["matched"] for item in items] != [True, False]:
        return _finding("blind-index-batch-nonmembership-failed", "changed second blind-index batch value did not produce [true, false]")
    if items[0]["index"] != context.variables.get("index_batch_zero") or items[1]["index"] == context.variables.get("index_batch_one"):
        return _finding("blind-index-batch-determinism-failed", "blind-index batch digest did not bind each plaintext")
    return ()


def blind_index_batch_atomicity(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    leak = _index_plaintext_leak(result, context, "batch response")
    if leak:
        return leak
    body = _json(result)
    expected_refs = [context.variables.get("index_atomic_ref_zero"), context.variables.get("index_atomic_ref_one")]
    if (
        not isinstance(body, dict)
        or set(body) != {"kid", "profile", "items"}
        or body.get("kid") != context.variables.get("kid")
        or body.get("profile") != context.variables.get("index_profile")
        or not isinstance(body.get("items"), list)
        or len(body["items"]) != 2
        or not all(isinstance(item, dict) and set(item) == {"ref", "matched", "index"} for item in body["items"])
        or [item["ref"] for item in body["items"]] != expected_refs
        or [item["matched"] for item in body["items"]] != [False, False]
        or not all(_is_hex(item["index"]) for item in body["items"])
    ):
        return _finding("blind-index-batch-atomicity-failed", "rejected blind-index batch left persisted membership behind")
    return ()


def _token_round_trip(result: HttpResult, context: EvaluationContext, prefix: str) -> tuple[Finding, ...]:
    """Ensure a stored token returns only its intended synthetic control value.

    The variable prefix comes from the caller, not from the target name, so the
    same logic serves both the standard and one-time targets without either one
    hard-coding the other's identity.
    """

    body = _json(result)
    expected_metadata = {"tenant": context.variables.get(f"{prefix}_metadata_tenant")}
    if (
        not isinstance(body, dict)
        or body.get("ref") != context.variables.get(f"{prefix}_ref")
        or body.get("plaintext") != context.variables.get(f"{prefix}_plaintext")
        or body.get("metadata") != expected_metadata
    ):
        return _finding("token-round-trip-failed", "token decode response did not restore the control value and metadata")
    return ()


def token_round_trip(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    return _token_round_trip(result, context, "token")


def token_once_round_trip(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    return _token_round_trip(result, context, "token_once")


def one_time_token_race(results: tuple[HttpResult, ...], context: EvaluationContext) -> tuple[Finding, ...]:
    """Exactly one concurrent decode may reveal a one-time plaintext."""
    statuses = [result.status for result in results]
    if any(result.failure is not None for result in results) or sorted(statuses) != [200, 404]:
        return _finding("one-time-race-invalid-outcome", "concurrent one-time decode did not produce exactly one 200 and one 404")
    successful = next(result for result in results if result.status == 200)
    failed = next(result for result in results if result.status == 404)
    if _token_round_trip(successful, context, "token_once"):
        return _finding("one-time-race-winner-invalid", "winning one-time decode did not return the expected value")
    failed_body = _json(failed)
    plaintext = context.variables.get("token_once_plaintext")
    leaked = isinstance(plaintext, str) and plaintext.encode("utf-8") in failed.body
    if not isinstance(failed_body, dict) or not isinstance(failed_body.get("error"), str) or leaked:
        return _finding("one-time-race-loser-leaked", "losing one-time decode was not a clean not-found response")
    return ()


def one_time_token_batch_round_trip(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    body = _json(result)
    if not isinstance(body, dict) or not isinstance(body.get("items"), list) or len(body["items"]) != 2:
        return _finding("one-time-batch-invalid", "one-time batch decode response has an invalid shape")
    refs = [item.get("ref") if isinstance(item, dict) else None for item in body["items"]]
    plaintexts = [item.get("plaintext") if isinstance(item, dict) else None for item in body["items"]]
    if refs != [context.variables.get("token_once_batch_ref_zero"), context.variables.get("token_once_batch_ref_one")] or plaintexts != [context.variables.get("token_once_plaintext")] * 2:
        return _finding("one-time-batch-order-or-rollback-failed", "one-time batch did not preserve order or rollback after a failed consume")
    return ()


def _token_output(result: HttpResult, context: EvaluationContext, prefix: str) -> tuple[Finding, ...]:
    body = _json(result)
    token = body.get("token") if isinstance(body, dict) else None
    token_prefix = context.variables.get(f"{prefix}_token_prefix")
    if (
        not isinstance(body, dict)
        or body.get("ref") != context.variables.get(f"{prefix}_ref")
        or body.get("kid") != context.variables.get("kid")
        or body.get("profile") != context.variables.get(f"{prefix}_profile")
        or not isinstance(token, str)
        or not isinstance(token_prefix, str)
        or not token.startswith(token_prefix + "_")
        or _B64URL.fullmatch(token[len(token_prefix) + 1 :]) is None
    ):
        return _finding("token-producer-invalid", "token encode response does not satisfy its control contract")
    return ()


def token_output(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    return _token_output(result, context, "token")


def token_once_output(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    return _token_output(result, context, "token_once")


def token_distinct_output(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    findings = _token_output(result, context, "token")
    if findings:
        return findings
    body = _json(result)
    if isinstance(body, dict) and body.get("token") == context.variables.get("first_token"):
        return _finding("token-randomness-failed", "two encodes of the same plaintext returned the same token")
    return ()


def masking_output(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    body = _json(result)
    if not isinstance(body, dict):
        return _finding("masking-output-invalid-json", "mask response is not valid JSON")
    expected = {
        "ref": context.variables.get("mask_ref"),
        "kid": context.variables.get("kid"),
        "profile": context.variables.get("mask_profile"),
        "masked": context.variables.get("mask_expected"),
    }
    if any(body.get(name) != value for name, value in expected.items()):
        return _finding("masking-output-invalid", "mask response did not match the signed display policy")
    return ()


def masking_policy_output(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    plaintext = context.variables.get("mask_policy_plaintext")
    first = context.variables.get("mask_visible_first")
    last = context.variables.get("mask_visible_last")
    mask_char = context.variables.get("mask_char")
    if not isinstance(plaintext, str) or not isinstance(first, str) or not isinstance(last, str) or not isinstance(mask_char, str):
        return _finding("masking-policy-input-invalid", "masking policy variables are unavailable")
    try:
        visible_first, visible_last = int(first), int(last)
    except ValueError:
        return _finding("masking-policy-input-invalid", "masking visibility values are invalid")
    expected = plaintext[:visible_first] + mask_char * (len(plaintext) - visible_first - visible_last) + plaintext[len(plaintext) - visible_last :]
    body = _json(result)
    if (
        not isinstance(body, dict)
        or body.get("ref") != context.variables.get("mask_policy_ref")
        or body.get("kid") != context.variables.get("kid")
        or body.get("profile") != context.variables.get("mask_profile")
        or body.get("masked") != expected
    ):
        return _finding("masking-policy-violated", "mask response did not apply the configured visible ranges and mask character")
    return ()
