"""Vectis-specific semantic expectations; execution remains in Nadir core."""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Callable

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


def _declared_plaintext_leak(
    result: HttpResult,
    context: EvaluationContext,
    *,
    predicate: Callable[[str], bool],
    code: str,
    label: str,
) -> tuple[Finding, ...]:
    """No declared plaintext (selected by name) may echo in the body or headers.

    NoDeclaredSecrets guards these globally; each capability also checks directly so
    a leak is reported with its own code. One implementation, three predicates
    (index / sharing / commitment)."""
    plaintexts = tuple(
        value
        for name, value in context.variables.items()
        if predicate(name) and isinstance(value, str) and value
    )
    if any(value.encode("utf-8") in result.body or any(value in header for _, header in result.headers) for value in plaintexts):
        return _finding(code, f"{label} exposes a declared plaintext")
    return ()


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


def _batch_items(
    result: HttpResult,
    context: EvaluationContext,
    *,
    prefix: str,
    profile_variable: str,
    fields: set[str],
    code: str,
) -> tuple[list[dict[str, object]] | None, tuple[Finding, ...]]:
    """Validate the common ordered batch response contract without data leakage."""
    body = _json(result)
    expected_refs = [context.variables.get(f"{prefix}_ref_zero"), context.variables.get(f"{prefix}_ref_one")]
    if (
        not isinstance(body, dict)
        or body.get("kid") != context.variables.get("kid")
        or body.get("profile") != context.variables.get(profile_variable)
        or not isinstance(body.get("items"), list)
        or len(body["items"]) != 2
        or not all(isinstance(item, dict) and set(item) == fields for item in body["items"])
        or [item["ref"] for item in body["items"]] != expected_refs
    ):
        return None, _finding(code, "batch response does not preserve its ordered item contract")
    return body["items"], ()


def fpe_batch_encrypt_output(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    items, findings = _batch_items(result, context, prefix="fpe_batch", profile_variable="fpe_profile", fields={"ref", "ciphertext"}, code="fpe-batch-output-invalid")
    if findings:
        return findings
    plaintexts = [context.variables.get("fpe_batch_plaintext_zero"), context.variables.get("fpe_batch_plaintext_one")]
    if items is None or not all(
        isinstance(item["ciphertext"], str) and item["ciphertext"].isdigit() and len(item["ciphertext"]) == len(plaintext)
        for item, plaintext in zip(items, plaintexts)
        if isinstance(plaintext, str)
    ):
        return _finding("fpe-batch-output-invalid", "FPE batch ciphertext is not format preserving")
    return ()


def fpe_batch_round_trip(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    items, findings = _batch_items(result, context, prefix="fpe_batch", profile_variable="fpe_profile", fields={"ref", "plaintext"}, code="fpe-batch-round-trip-failed")
    if findings:
        return findings
    expected = [context.variables.get("fpe_batch_plaintext_zero"), context.variables.get("fpe_batch_plaintext_one")]
    if items is None or [item["plaintext"] for item in items] != expected:
        return _finding("fpe-batch-round-trip-failed", "FPE batch decrypt did not restore both plaintexts")
    return ()


def fpe_batch_ciphertext_integrity(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    if result.status is not None and 200 <= result.status < 300:
        items, findings = _batch_items(result, context, prefix="fpe_batch", profile_variable="fpe_profile", fields={"ref", "plaintext"}, code="fpe-batch-tamper-invalid")
        if findings:
            return findings
        if items is not None and items[1]["plaintext"] == context.variables.get("fpe_batch_plaintext_one"):
            return _finding("fpe-batch-tamper-round-trips", "tampered FPE batch ciphertext restored the original plaintext")
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


def mac_batch_create_output(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    items, findings = _batch_items(result, context, prefix="mac_batch", profile_variable="mac_profile", fields={"ref", "digest"}, code="mac-batch-output-invalid")
    if findings:
        return findings
    body = _json(result)
    if items is None or not isinstance(body, dict) or not isinstance(body.get("algorithm"), str) or not all(_is_hex(item["digest"]) for item in items):
        return _finding("mac-batch-output-invalid", "MAC batch create response has invalid digests")
    return ()


def _mac_batch_verify(result: HttpResult, context: EvaluationContext, expected: list[bool]) -> tuple[Finding, ...]:
    items, findings = _batch_items(result, context, prefix="mac_batch", profile_variable="mac_profile", fields={"ref", "valid"}, code="mac-batch-verify-invalid")
    if findings:
        return findings
    if items is None or [item["valid"] for item in items] != expected:
        return _finding("mac-batch-verification-failed", "MAC batch verification did not match its expected per-item result")
    return ()


def mac_batch_verification_success(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    return _mac_batch_verify(result, context, [True, True])


def mac_batch_verification_failure(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    return _mac_batch_verify(result, context, [True, False])


def _sharing_value(context: EvaluationContext, name: str) -> str | None:
    value = context.variables.get(name)
    return value if isinstance(value, str) and value else None


def _sharing_count(context: EvaluationContext, name: str) -> int | None:
    value = _sharing_value(context, name)
    if value is None or not value.isdigit():
        return None
    count = int(value)
    return count if 1 <= count <= 32 else None


def _is_base64url(value: object, *, expected_len: int | None = None) -> bool:
    if not isinstance(value, str) or not value or _B64URL.fullmatch(value) is None:
        return False
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except ValueError:
        return False
    return expected_len is None or len(decoded) == expected_len


def _is_share(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith("vectis-sss-v1."):
        return False
    return _is_base64url(value.removeprefix("vectis-sss-v1."))


def _sharing_plaintext_leak(result: HttpResult, context: EvaluationContext, label: str) -> tuple[Finding, ...]:
    return _declared_plaintext_leak(
        result,
        context,
        predicate=lambda name: name in ("share_plaintext", "retired_share_plaintext"),
        code="sharing-response-leaks-plaintext",
        label=f"sharing {label}",
    )


def _sharing_split(
    result: HttpResult,
    context: EvaluationContext,
    *,
    profile_variable: str = "share_profile",
    kid_variable: str = "kid",
) -> tuple[dict[str, object] | None, tuple[Finding, ...]]:
    leak = _sharing_plaintext_leak(result, context, "split response")
    if leak:
        return None, leak
    body = _json(result)
    threshold = _sharing_count(context, "share_threshold")
    total = _sharing_count(context, "share_total")
    if (
        not isinstance(body, dict)
        or set(body) != {"kid", "profile", "threshold", "set_id", "shares"}
        or body.get("kid") != context.variables.get(kid_variable)
        or body.get("profile") != context.variables.get(profile_variable)
        or body.get("threshold") != threshold
        or not _is_base64url(body.get("set_id"), expected_len=16)
        or not isinstance(body.get("shares"), list)
        or total is None
        or len(body["shares"]) != total
        or not all(_is_share(share) for share in body["shares"])
        or len(set(body["shares"])) != total
    ):
        return None, _finding("sharing-split-output-invalid", "sharing split response does not satisfy its public contract")
    return body, ()


def sharing_split_output(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    _, findings = _sharing_split(result, context)
    return findings


def _sharing_combine(
    result: HttpResult,
    context: EvaluationContext,
    *,
    kid_variable: str = "kid",
    profile_variable: str = "share_profile",
    plaintext_variable: str = "share_plaintext",
    set_id_variable: str | None = "share_set_id",
    code: str = "sharing-round-trip-failed",
) -> tuple[Finding, ...]:
    body = _json(result)
    expected_set_id = context.variables.get(set_id_variable) if set_id_variable is not None else None
    # If we are meant to pin a set_id but the control is blank (e.g. a plain combine
    # target that was never given the split's set_id), fail loud as input-invalid
    # instead of comparing against "" and reporting a misleading combine failure.
    if set_id_variable is not None and not (isinstance(expected_set_id, str) and expected_set_id):
        return _finding("sharing-combine-input-invalid", f"sharing set_id control {set_id_variable!r} is unavailable")
    if (
        not isinstance(body, dict)
        or set(body) != {"kid", "profile", "set_id", "plaintext"}
        or body.get("kid") != context.variables.get(kid_variable)
        or body.get("profile") != context.variables.get(profile_variable)
        or body.get("plaintext") != context.variables.get(plaintext_variable)
        or not _is_base64url(body.get("set_id"), expected_len=16)
        or (set_id_variable is not None and body.get("set_id") != expected_set_id)
    ):
        return _finding(code, "sharing combine did not reconstruct the expected threshold secret")
    return ()


def sharing_round_trip(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    return _sharing_combine(result, context)


def retired_sharing_round_trip(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    return _sharing_combine(
        result,
        context,
        kid_variable="retired_kid",
        profile_variable="retired_share_profile",
        plaintext_variable="retired_share_plaintext",
        set_id_variable="retired_share_set_id",
        code="retired-sharing-combine-failed",
    )


def sharing_randomness(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    body, findings = _sharing_split(result, context)
    if findings:
        return findings
    if body is None:
        return _finding("sharing-randomness-failed", "second sharing split response was unavailable")
    first_set_id = context.variables.get("first_set_id")
    # Collect whatever shares each split captured, independent of the profile's share
    # total, so the check does not silently degrade when the total is not five.
    first_shares = _captured_shares(context, "first_share_")
    second_shares = _captured_shares(context, "second_share_")
    if body.get("set_id") == first_set_id or first_shares == second_shares:
        return _finding("sharing-randomness-failed", "same secret produced a repeated sharing distribution")
    return ()


def _captured_shares(context: EvaluationContext, prefix: str) -> list[str]:
    return [
        value
        for name, value in sorted(context.variables.items())
        if name.startswith(prefix) and isinstance(value, str) and value
    ]


def _commitment_plaintext_leak(result: HttpResult, context: EvaluationContext, label: str) -> tuple[Finding, ...]:
    return _declared_plaintext_leak(
        result,
        context,
        predicate=lambda name: name.startswith("commit_") and "plaintext" in name,
        code="commitment-response-leaks-plaintext",
        label=f"commitment {label}",
    )


def _commitment_opening_len(context: EvaluationContext) -> int | None:
    value = context.variables.get("commit_opening_len")
    if not isinstance(value, str) or not value.isdigit():
        return None
    length = int(value)
    return length if 1 <= length <= 64 else None


def _is_opening(value: object, expected_len: int | None) -> bool:
    # An opening is a base64url blob of a known length; with no expected length there
    # is nothing to accept. Reuse the single base64url implementation.
    return _is_base64url(value, expected_len=expected_len) if expected_len is not None else False


def _commitment_create_response(
    result: HttpResult,
    context: EvaluationContext,
    *,
    ref_variable: str | None,
) -> tuple[dict[str, object] | None, tuple[Finding, ...]]:
    leak = _commitment_plaintext_leak(result, context, "create response")
    if leak:
        return None, leak
    body = _json(result)
    if (
        not isinstance(body, dict)
        or set(body) != {"ref", "kid", "profile", "algorithm", "commitment", "opening"}
        or (ref_variable is not None and body.get("ref") != context.variables.get(ref_variable))
        or not isinstance(body.get("ref"), str)
        or not body["ref"]
        or body.get("kid") != context.variables.get("kid")
        or body.get("profile") != context.variables.get("commit_profile")
        or not isinstance(body.get("algorithm"), str)
        or not body["algorithm"]
        or not _is_hex(body.get("commitment"))
        or len(body["commitment"]) not in {56, 64, 96, 128}
        or not _is_opening(body.get("opening"), _commitment_opening_len(context))
    ):
        return None, _finding("commitment-output-invalid", "commitment create response does not satisfy its public contract")
    return body, ()


def commitment_create_output(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    _, findings = _commitment_create_response(result, context, ref_variable="commit_ref")
    return findings


def _commitment_verify(result: HttpResult, context: EvaluationContext, expected: bool, code: str, message: str) -> tuple[Finding, ...]:
    leak = _commitment_plaintext_leak(result, context, "verify response")
    if leak:
        return leak
    body = _json(result)
    if (
        not isinstance(body, dict)
        or set(body) != {"ref", "kid", "profile", "valid"}
        or body.get("ref") != context.variables.get("commit_ref")
        or body.get("kid") != context.variables.get("kid")
        or body.get("profile") != context.variables.get("commit_profile")
        or body.get("valid") is not expected
    ):
        return _finding(code, message)
    return ()


def commitment_verification_success(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    return _commitment_verify(result, context, True, "commitment-verification-control-failed", "control commitment did not verify")


def commitment_verification_failure(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    return _commitment_verify(result, context, False, "mutated-commitment-accepted", "modified commitment material verified")


def commitment_randomness(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    body, findings = _commitment_create_response(result, context, ref_variable=None)
    if findings:
        return findings
    if body is None:
        return _finding("commitment-randomness-failed", "second commitment response was unavailable")
    if body.get("commitment") == context.variables.get("first_commitment") or body.get("opening") == context.variables.get("first_opening"):
        return _finding("commitment-randomness-failed", "same plaintext produced a repeated commitment or opening")
    return ()


def _commitment_batch_create_response(result: HttpResult, context: EvaluationContext) -> tuple[list[dict[str, object]] | None, tuple[Finding, ...]]:
    leak = _commitment_plaintext_leak(result, context, "batch create response")
    if leak:
        return None, leak
    body = _json(result)
    expected_refs = [context.variables.get("commit_batch_ref_zero"), context.variables.get("commit_batch_ref_one")]
    if (
        not isinstance(body, dict)
        or set(body) != {"kid", "profile", "algorithm", "items"}
        or body.get("kid") != context.variables.get("kid")
        or body.get("profile") != context.variables.get("commit_profile")
        or not isinstance(body.get("algorithm"), str)
        or not body["algorithm"]
        or not isinstance(body.get("items"), list)
        or len(body["items"]) != 2
        or not all(isinstance(item, dict) and set(item) == {"ref", "commitment", "opening"} for item in body["items"])
    ):
        return None, _finding("commitment-batch-output-invalid", "commitment batch create response has an invalid shape")
    items = body["items"]
    if (
        [item["ref"] for item in items] != expected_refs
        or not all(_is_hex(item["commitment"]) and len(item["commitment"]) in {56, 64, 96, 128} for item in items)
        or not all(_is_opening(item["opening"], _commitment_opening_len(context)) for item in items)
    ):
        return None, _finding("commitment-batch-output-invalid", "commitment batch create response has invalid item values")
    return items, ()


def commitment_batch_create_output(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    _, findings = _commitment_batch_create_response(result, context)
    return findings


def _commitment_batch_verify_response(result: HttpResult, context: EvaluationContext) -> tuple[list[dict[str, object]] | None, tuple[Finding, ...]]:
    leak = _commitment_plaintext_leak(result, context, "batch verify response")
    if leak:
        return None, leak
    body = _json(result)
    expected_refs = [context.variables.get("commit_batch_ref_zero"), context.variables.get("commit_batch_ref_one")]
    if (
        not isinstance(body, dict)
        or set(body) != {"kid", "profile", "items"}
        or body.get("kid") != context.variables.get("kid")
        or body.get("profile") != context.variables.get("commit_profile")
        or not isinstance(body.get("items"), list)
        or len(body["items"]) != 2
        or not all(isinstance(item, dict) and set(item) == {"ref", "valid"} for item in body["items"])
        or [item["ref"] for item in body["items"]] != expected_refs
    ):
        return None, _finding("commitment-batch-verify-invalid", "commitment batch verify response has an invalid shape")
    return body["items"], ()


def commitment_batch_verification_success(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    items, findings = _commitment_batch_verify_response(result, context)
    if findings:
        return findings
    if items is None or [item["valid"] for item in items] != [True, True]:
        return _finding("commitment-batch-verification-failed", "commitment batch control values did not both verify")
    return ()


def commitment_batch_verification_failure(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    items, findings = _commitment_batch_verify_response(result, context)
    if findings:
        return findings
    if items is None or [item["valid"] for item in items] != [True, False]:
        return _finding("commitment-batch-mutation-failed", "changed second commitment batch plaintext did not produce [true, false]")
    return ()


def _index_plaintext_leak(result: HttpResult, context: EvaluationContext, label: str) -> tuple[Finding, ...]:
    """Per-index defence-in-depth: no declared index plaintext may echo back.

    NoDeclaredSecrets guards these globally, but each index validator also checks
    directly so a leak is reported with the index-specific code; this helper is the
    single implementation the three index shapes share.
    """
    return _declared_plaintext_leak(
        result,
        context,
        predicate=lambda name: name.startswith("index_") and "plaintext" in name,
        code="blind-index-response-leaks-plaintext",
        label=f"blind-index {label}",
    )


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


def one_time_token_batch_race(results: tuple[HttpResult, ...], context: EvaluationContext) -> tuple[Finding, ...]:
    statuses = [result.status for result in results]
    if any(result.failure is not None for result in results) or sorted(statuses) != [200, 404]:
        return _finding("one-time-batch-race-invalid-outcome", "concurrent one-time batch decodes did not produce exactly one 200 and one 404")
    failed = next(result for result in results if result.status == 404)
    body = _json(failed)
    plaintext = context.variables.get("token_once_plaintext")
    if not isinstance(body, dict) or not isinstance(body.get("error"), str) or (isinstance(plaintext, str) and plaintext.encode("utf-8") in failed.body):
        return _finding("one-time-batch-race-loser-leaked", "losing one-time batch decode was not a clean not-found response")
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


def token_batch_encode_output(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    items, findings = _batch_items(result, context, prefix="token_batch", profile_variable="token_profile", fields={"ref", "token"}, code="token-batch-output-invalid")
    if findings:
        return findings
    token_prefix = context.variables.get("token_token_prefix")
    if items is None or not isinstance(token_prefix, str) or not all(isinstance(item["token"], str) and item["token"].startswith(token_prefix + "_") for item in items):
        return _finding("token-batch-output-invalid", "token batch encode response has invalid opaque tokens")
    return ()


def token_batch_round_trip(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    items, findings = _batch_items(result, context, prefix="token_batch", profile_variable="token_profile", fields={"ref", "plaintext", "metadata"}, code="token-batch-round-trip-failed")
    if findings:
        return findings
    expected_plaintexts = [context.variables.get("token_batch_plaintext_zero"), context.variables.get("token_batch_plaintext_one")]
    expected_metadata = [
        {"tenant": context.variables.get("token_batch_metadata_zero")},
        {"tenant": context.variables.get("token_batch_metadata_one")},
    ]
    if items is None or [item["plaintext"] for item in items] != expected_plaintexts or [item["metadata"] for item in items] != expected_metadata:
        return _finding("token-batch-round-trip-failed", "token batch decode did not restore plaintexts and metadata in order")
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


def _mask_policy(context: EvaluationContext) -> tuple[str, int, int] | None:
    """Resolve the configured masking display policy (char, visible first, visible
    last) from the fixture, or None if the controls are missing or malformed."""
    first = context.variables.get("mask_visible_first")
    last = context.variables.get("mask_visible_last")
    mask_char = context.variables.get("mask_char")
    if not isinstance(first, str) or not isinstance(last, str) or not isinstance(mask_char, str):
        return None
    try:
        return mask_char, int(first), int(last)
    except ValueError:
        return None


def _apply_mask(policy: tuple[str, int, int], plaintext: str) -> str:
    mask_char, visible_first, visible_last = policy
    return plaintext[:visible_first] + mask_char * (len(plaintext) - visible_first - visible_last) + plaintext[len(plaintext) - visible_last :]


def masking_policy_output(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    plaintext = context.variables.get("mask_policy_plaintext")
    policy = _mask_policy(context)
    if not isinstance(plaintext, str) or policy is None:
        return _finding("masking-policy-input-invalid", "masking policy variables are unavailable")
    expected = _apply_mask(policy, plaintext)
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


def masking_batch_output(result: HttpResult, context: EvaluationContext) -> tuple[Finding, ...]:
    items, findings = _batch_items(result, context, prefix="mask_batch", profile_variable="mask_profile", fields={"ref", "masked"}, code="mask-batch-output-invalid")
    if findings:
        return findings
    policy = _mask_policy(context)
    values = [context.variables.get("mask_batch_plaintext_zero"), context.variables.get("mask_batch_plaintext_one")]
    if policy is None or not all(isinstance(value, str) for value in values):
        return _finding("mask-batch-input-invalid", "masking batch policy or plaintext controls are unavailable")
    expected = [_apply_mask(policy, value) for value in values]
    if items is None or [item["masked"] for item in items] != expected:
        return _finding("mask-batch-policy-violated", "mask batch response did not preserve the configured display policy")
    return ()
