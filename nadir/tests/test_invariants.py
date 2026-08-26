import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "projects" / "vectis"))

from nadir.http import HttpRequest, HttpResult
from nadir.workflows import EvaluationContext
from invariants import (
    blind_index_batch_atomicity,
    blind_index_batch_membership,
    blind_index_create_output,
    blind_index_membership,
    blind_index_nonmembership,
    fpe_encrypt_output,
    fpe_round_trip,
    internal_message_encrypt_output,
    internal_message_round_trip,
    internal_message_tamper_rejected,
    mac_create_output,
    mac_verification_failure,
    masking_policy_output,
    public_keys_output,
    token_round_trip,
    verification_failure,
)


def context(mutation=None, *, target="vectis", variables=None):
    return EvaluationContext(target, "test", mutation, (), variables or {})


class InvariantTests(unittest.TestCase):
    def _result(self, body, *, status=200, headers=()):
        request = HttpRequest("GET", "http://127.0.0.1/pub/kid")
        return HttpResult(request, status, tuple(headers), json.dumps(body).encode("utf-8"), 1)

    def test_detects_private_public_key_response_field(self):
        body = {"info": "x", "keys": {"eddsa": {"alg": "a", "public_key_der_hex": "aa", "private_key": "bad"}}}
        self.assertEqual(public_keys_output(self._result(body), context())[0].code, "public-key-response-leaks-private-material")

    def test_detects_mutated_signature_that_is_accepted(self):
        body = {"valid": "ok", "status": {"eddsa": "ok", "ml-dsa": "ok"}}
        self.assertEqual(verification_failure(self._result(body), context())[0].code, "mutated-signature-accepted")

    def test_detects_fpe_round_trip_with_wrong_plaintext(self):
        body = {"ref": "fpe-ref", "plaintext": "wrong"}
        variables = {"fpe_ref": "fpe-ref", "fpe_plaintext": "expected"}
        self.assertEqual(fpe_round_trip(self._result(body), context(variables=variables))[0].code, "fpe-round-trip-failed")

    def test_detects_invalid_fpe_producer_shape(self):
        body = {"ref": "fpe-ref", "kid": "a" * 64, "profile": "profile", "ciphertext": "not-digits"}
        variables = {"fpe_ref": "fpe-ref", "kid": "a" * 64, "fpe_profile": "profile", "fpe_plaintext": "1234"}
        self.assertEqual(fpe_encrypt_output(self._result(body), context(variables=variables))[0].code, "fpe-producer-invalid")

    def test_detects_mac_digest_that_was_accepted(self):
        body = {"ref": "mac-ref", "valid": True}
        self.assertEqual(
            mac_verification_failure(self._result(body), context(variables={"mac_ref": "mac-ref"}))[0].code,
            "mutated-mac-accepted",
        )

    def test_detects_invalid_mac_producer_digest(self):
        body = {"ref": "mac-ref", "kid": "a" * 64, "profile": "profile", "algorithm": "HMAC", "digest": "xyz"}
        variables = {"mac_ref": "mac-ref", "kid": "a" * 64, "mac_profile": "profile"}
        self.assertEqual(mac_create_output(self._result(body), context(variables=variables))[0].code, "mac-producer-invalid")

    def test_blind_index_create_requires_complete_hex_output(self):
        variables = {"kid": "a" * 64, "index_ref": "index-ref", "index_profile": "nadir-mac-v1"}
        invalid = {"ref": "index-ref", "kid": "a" * 64, "profile": "nadir-mac-v1", "index": "not-hex"}
        self.assertEqual(
            blind_index_create_output(self._result(invalid), context(variables=variables))[0].code,
            "blind-index-output-invalid",
        )

    def test_blind_index_create_detects_plaintext_reflection(self):
        plaintext = "synthetic-index-plaintext"
        body = {"ref": "index-ref", "kid": "a" * 64, "profile": "nadir-mac-v1", "index": "ab" * 32, "debug": plaintext}
        variables = {"kid": "a" * 64, "index_ref": "index-ref", "index_profile": "nadir-mac-v1", "index_plaintext": plaintext}
        self.assertEqual(
            blind_index_create_output(self._result(body), context(variables=variables))[0].code,
            "blind-index-response-leaks-plaintext",
        )

    def test_blind_index_membership_binds_the_captured_digest(self):
        digest = "ab" * 32
        variables = {"kid": "a" * 64, "index_ref": "index-ref", "index_profile": "nadir-mac-v1", "index_digest": digest}
        matched = {"ref": "index-ref", "kid": "a" * 64, "profile": "nadir-mac-v1", "matched": True, "index": digest}
        self.assertEqual(blind_index_membership(self._result(matched), context(variables=variables)), ())
        mismatched = {**matched, "matched": False}
        self.assertEqual(
            blind_index_membership(self._result(mismatched), context(variables=variables))[0].code,
            "blind-index-membership-failed",
        )
        different_plaintext = {**matched, "matched": False, "index": "cd" * 32}
        self.assertEqual(blind_index_nonmembership(self._result(different_plaintext), context(variables=variables)), ())

    def test_blind_index_batch_requires_order_and_atomic_rollback(self):
        variables = {
            "kid": "a" * 64,
            "index_profile": "nadir-mac-v1",
            "index_batch_ref_zero": "zero",
            "index_batch_ref_one": "one",
            "index_batch_zero": "ab" * 32,
            "index_batch_one": "cd" * 32,
            "index_atomic_ref_zero": "atomic-zero",
            "index_atomic_ref_one": "atomic-one",
        }
        membership = {
            "kid": "a" * 64,
            "profile": "nadir-mac-v1",
            "items": [{"ref": "zero", "matched": True, "index": "ab" * 32}, {"ref": "one", "matched": True, "index": "cd" * 32}],
        }
        self.assertEqual(blind_index_batch_membership(self._result(membership), context(variables=variables)), ())
        out_of_order = {**membership, "items": list(reversed(membership["items"]))}
        self.assertEqual(
            blind_index_batch_membership(self._result(out_of_order), context(variables=variables))[0].code,
            "blind-index-batch-output-invalid",
        )
        atomicity = {
            "kid": "a" * 64,
            "profile": "nadir-mac-v1",
            "items": [{"ref": "atomic-zero", "matched": False, "index": "ef" * 32}, {"ref": "atomic-one", "matched": False, "index": "01" * 32}],
        }
        self.assertEqual(blind_index_batch_atomicity(self._result(atomicity), context(variables=variables)), ())
        persisted = {**atomicity, "items": [{**atomicity["items"][0], "matched": True}, atomicity["items"][1]]}
        self.assertEqual(
            blind_index_batch_atomicity(self._result(persisted), context(variables=variables))[0].code,
            "blind-index-batch-atomicity-failed",
        )

    def test_detects_masking_policy_mismatch(self):
        body = {"ref": "mask-ref", "kid": "a" * 64, "profile": "profile", "masked": "wrong"}
        variables = {"mask_policy_ref": "mask-ref", "kid": "a" * 64, "mask_profile": "profile", "mask_policy_plaintext": "123456", "mask_visible_first": "1", "mask_visible_last": "2", "mask_char": "*"}
        self.assertEqual(masking_policy_output(self._result(body), context(variables=variables))[0].code, "masking-policy-violated")

    def test_detects_wrong_one_time_token_plaintext(self):
        body = {"ref": "once-ref", "plaintext": "wrong", "metadata": {"tenant": "nadir-once"}}
        variables = {
            "token_once_ref": "once-ref",
            "token_once_plaintext": "expected",
            "token_once_metadata_tenant": "nadir-once",
        }
        self.assertEqual(
            token_round_trip(self._result(body), context(target="vectis.one-time-token", variables=variables))[0].code,
            "token-round-trip-failed",
        )

    def test_internal_message_encrypt_requires_an_opaque_complete_envelope(self):
        plaintext = "synthetic-sensitive-message"
        variables = {"kid": "a" * 64, "internal_message_plaintext": plaintext}
        valid = {
            "timestamp": "1782058090",
            "kid": "a" * 64,
            "message": {"ctx": "aa", "nonce": "bb", "aad": "version=v1", "variant": "AES-256/GCM"},
        }
        self.assertEqual(internal_message_encrypt_output(self._result(valid), context(variables=variables)), ())
        invalid = {**valid, "message": {"ctx": "nope", "nonce": "bb", "aad": "version=v1", "variant": "AES-256/GCM"}}
        self.assertEqual(
            internal_message_encrypt_output(self._result(invalid), context(variables=variables))[0].code,
            "internal-message-envelope-invalid",
        )

    def test_internal_message_encrypt_detects_plaintext_leak(self):
        plaintext = "synthetic-sensitive-message"
        body = {"timestamp": "1", "kid": "a" * 64, "message": {"ctx": "aa", "nonce": "bb", "aad": plaintext, "variant": "AES-256/GCM"}}
        self.assertEqual(
            internal_message_encrypt_output(self._result(body), context(variables={"kid": "a" * 64, "internal_message_plaintext": plaintext}))[0].code,
            "internal-message-encrypt-leaks-plaintext",
        )
        safe_body = {"timestamp": "1", "kid": "a" * 64, "message": {"ctx": "aa", "nonce": "bb", "aad": "version=v1", "variant": "AES-256/GCM"}}
        self.assertEqual(
            internal_message_encrypt_output(
                self._result(safe_body, headers=(("X-Test", plaintext),)),
                context(variables={"kid": "a" * 64, "internal_message_plaintext": plaintext}),
            )[0].code,
            "internal-message-encrypt-leaks-plaintext",
        )

    def test_internal_message_round_trip_and_tamper_contracts(self):
        variables = {"internal_message_plaintext": "expected"}
        self.assertEqual(internal_message_round_trip(self._result({"plaintext": "expected"}), context(variables=variables)), ())
        self.assertEqual(
            internal_message_round_trip(self._result({"plaintext": "wrong"}), context(variables=variables))[0].code,
            "internal-message-round-trip-failed",
        )
        self.assertEqual(
            internal_message_round_trip(self._result({"plaintext": "expected"}), context(variables={}))[0].code,
            "internal-message-input-invalid",
        )
        self.assertEqual(
            internal_message_tamper_rejected(self._result({"plaintext": "expected"}), context(variables=variables))[0].code,
            "mutated-internal-message-accepted",
        )
        self.assertEqual(
            internal_message_tamper_rejected(self._result({"error": "authentication failed"}, status=400), context(variables=variables)),
            (),
        )
