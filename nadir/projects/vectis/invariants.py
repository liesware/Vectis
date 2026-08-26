"""Vectis-specific semantic expectations; execution remains in Nadir core."""

from __future__ import annotations

import json
import re

from nadir.http import HttpResult
from nadir.workflows import EvaluationContext, Finding


_HEX = re.compile(r"[0-9a-fA-F]+\Z")
_KEY_SHAPE = {
    "eddsa": "public_key_der_hex",
    "xecdh": "public_key_hex",
    "ml-dsa": "public_key_der_hex",
    "ml-kem": "public_key_der_hex",
}


def _finding(code: str, message: str) -> tuple[Finding, ...]:
    return (Finding(code, message),)


def _json(result: HttpResult) -> object | None:
    try:
        return json.loads(result.body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def _is_hex(value: object) -> bool:
    return isinstance(value, str) and bool(value) and len(value) % 2 == 0 and _HEX.fullmatch(value) is not None


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


def mac_verification_failure(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    return _mac_verification(result, context, False, "mutated-mac-accepted", "mutated MAC digest was not rejected")


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
