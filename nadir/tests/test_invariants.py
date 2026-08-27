import base64
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
    commitment_batch_create_output,
    commitment_batch_verification_failure,
    commitment_batch_verification_success,
    commitment_create_output,
    commitment_randomness,
    commitment_verification_failure,
    commitment_verification_success,
    fpe_encrypt_output,
    fpe_round_trip,
    internal_message_encrypt_output,
    internal_message_round_trip,
    internal_message_tamper_rejected,
    mac_create_output,
    mac_verification_failure,
    masking_batch_output,
    masking_policy_output,
    public_keys_output,
    retired_sharing_round_trip,
    sharing_randomness,
    sharing_round_trip,
    sharing_split_output,
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

    def test_commitment_output_and_plaintext_protection(self):
        opening = base64.urlsafe_b64encode(b"a" * 32).decode("ascii").rstrip("=")
        variables = {
            "kid": "a" * 64,
            "commit_profile": "nadir-commitment-v1",
            "commit_ref": "commit-ref",
            "commit_opening_len": "32",
            "commit_plaintext": "synthetic-commitment-plaintext",
        }
        valid = {
            "ref": "commit-ref",
            "kid": "a" * 64,
            "profile": "nadir-commitment-v1",
            "algorithm": "HMAC-SHA-256",
            "commitment": "ab" * 32,
            "opening": opening,
        }
        self.assertEqual(commitment_create_output(self._result(valid), context(variables=variables)), ())
        self.assertEqual(
            commitment_create_output(self._result({**valid, "opening": "not-base64!"}), context(variables=variables))[0].code,
            "commitment-output-invalid",
        )
        self.assertEqual(
            commitment_create_output(self._result({**valid, "debug": variables["commit_plaintext"]}), context(variables=variables))[0].code,
            "commitment-response-leaks-plaintext",
        )

    def test_commitment_verification_randomness_and_batch_contracts(self):
        opening_a = base64.urlsafe_b64encode(b"a" * 32).decode("ascii").rstrip("=")
        opening_b = base64.urlsafe_b64encode(b"b" * 32).decode("ascii").rstrip("=")
        variables = {
            "kid": "a" * 64,
            "commit_profile": "nadir-commitment-v1",
            "commit_ref": "commit-ref",
            "commit_opening_len": "32",
            "commit_batch_ref_zero": "zero",
            "commit_batch_ref_one": "one",
            "first_commitment": "ab" * 32,
            "first_opening": opening_a,
        }
        verified = {"ref": "commit-ref", "kid": "a" * 64, "profile": "nadir-commitment-v1", "valid": True}
        self.assertEqual(commitment_verification_success(self._result(verified), context(variables=variables)), ())
        self.assertEqual(
            commitment_verification_failure(self._result(verified), context(variables=variables))[0].code,
            "mutated-commitment-accepted",
        )
        second = {
            "ref": "another-ref",
            "kid": "a" * 64,
            "profile": "nadir-commitment-v1",
            "algorithm": "HMAC-SHA-256",
            "commitment": "cd" * 32,
            "opening": opening_b,
        }
        self.assertEqual(commitment_randomness(self._result(second), context(variables=variables)), ())
        created = {
            "kid": "a" * 64,
            "profile": "nadir-commitment-v1",
            "algorithm": "HMAC-SHA-256",
            "items": [
                {"ref": "zero", "commitment": "ab" * 32, "opening": opening_a},
                {"ref": "one", "commitment": "cd" * 32, "opening": opening_b},
            ],
        }
        self.assertEqual(commitment_batch_create_output(self._result(created), context(variables=variables)), ())
        verified_batch = {
            "kid": "a" * 64,
            "profile": "nadir-commitment-v1",
            "items": [{"ref": "zero", "valid": True}, {"ref": "one", "valid": True}],
        }
        self.assertEqual(commitment_batch_verification_success(self._result(verified_batch), context(variables=variables)), ())
        failed_batch = {**verified_batch, "items": [verified_batch["items"][0], {"ref": "one", "valid": False}]}
        self.assertEqual(commitment_batch_verification_failure(self._result(failed_batch), context(variables=variables)), ())

    def test_sharing_split_round_trip_and_randomness_contracts(self):
        set_id = base64.urlsafe_b64encode(b"a" * 16).decode("ascii").rstrip("=")
        shares = [
            "vectis-sss-v1." + base64.urlsafe_b64encode(f"share-{index}".encode("ascii")).decode("ascii").rstrip("=")
            for index in range(5)
        ]
        variables = {
            "kid": "a" * 64,
            "share_profile": "nadir-sharing-3of5-v1",
            "share_threshold": "3",
            "share_total": "5",
            "share_plaintext": "synthetic-sharing-secret",
            "share_set_id": set_id,
            "first_set_id": base64.urlsafe_b64encode(b"b" * 16).decode("ascii").rstrip("="),
            **{f"first_share_{name}": f"old-{name}" for name in ("zero", "one", "two", "three", "four")},
            **{f"second_share_{name}": f"new-{name}" for name in ("zero", "one", "two", "three", "four")},
        }
        split = {
            "kid": "a" * 64,
            "profile": "nadir-sharing-3of5-v1",
            "threshold": 3,
            "set_id": set_id,
            "shares": shares,
        }
        self.assertEqual(sharing_split_output(self._result(split), context(variables=variables)), ())
        self.assertEqual(
            sharing_split_output(self._result({**split, "shares": [shares[0]] * 5}), context(variables=variables))[0].code,
            "sharing-split-output-invalid",
        )
        self.assertEqual(
            sharing_split_output(self._result({**split, "debug": variables["share_plaintext"]}), context(variables=variables))[0].code,
            "sharing-response-leaks-plaintext",
        )
        combined = {"kid": "a" * 64, "profile": "nadir-sharing-3of5-v1", "set_id": set_id, "plaintext": "synthetic-sharing-secret"}
        self.assertEqual(sharing_round_trip(self._result(combined), context(variables=variables)), ())
        randomness_variables = {**variables, "first_set_id": "different-set", **{f"second_share_{name}": shares[index] for index, name in enumerate(("zero", "one", "two", "three", "four"))}}
        self.assertEqual(sharing_randomness(self._result(split), context(variables=randomness_variables)), ())

    def test_retired_sharing_combine_binds_historical_material(self):
        set_id = base64.urlsafe_b64encode(b"c" * 16).decode("ascii").rstrip("=")
        variables = {
            "retired_kid": "b" * 64,
            "retired_share_profile": "nadir-retired-sharing-3of5-v1",
            "retired_share_plaintext": "historical-sharing-secret",
            "retired_share_set_id": set_id,
        }
        body = {"kid": "b" * 64, "profile": "nadir-retired-sharing-3of5-v1", "set_id": set_id, "plaintext": "historical-sharing-secret"}
        self.assertEqual(retired_sharing_round_trip(self._result(body), context(variables=variables)), ())
        self.assertEqual(
            retired_sharing_round_trip(self._result({**body, "plaintext": "wrong"}), context(variables=variables))[0].code,
            "retired-sharing-combine-failed",
        )
        # A blank pinned set_id (e.g. combine target never given the split's set_id)
        # must fail loud as input-invalid, not as a misleading combine failure.
        self.assertEqual(
            retired_sharing_round_trip(self._result(body), context(variables={**variables, "retired_share_set_id": ""}))[0].code,
            "sharing-combine-input-invalid",
        )

    def test_detects_masking_policy_mismatch(self):
        body = {"ref": "mask-ref", "kid": "a" * 64, "profile": "profile", "masked": "wrong"}
        variables = {"mask_policy_ref": "mask-ref", "kid": "a" * 64, "mask_profile": "profile", "mask_policy_plaintext": "123456", "mask_visible_first": "1", "mask_visible_last": "2", "mask_char": "*"}
        self.assertEqual(masking_policy_output(self._result(body), context(variables=variables))[0].code, "masking-policy-violated")

    def test_masking_batch_derives_the_configured_policy(self):
        # Non-default mask char (#) and visible range (first=0, last=3): the batch
        # invariant must apply the configured policy, not a hardcoded '*'/last-4.
        variables = {
            "kid": "a" * 64, "mask_profile": "profile",
            "mask_batch_ref_zero": "r0", "mask_batch_ref_one": "r1",
            "mask_batch_plaintext_zero": "9998888", "mask_batch_plaintext_one": "1112222",
            "mask_char": "#", "mask_visible_first": "0", "mask_visible_last": "3",
        }
        body = {"kid": "a" * 64, "profile": "profile", "items": [
            {"ref": "r0", "masked": "####888"},
            {"ref": "r1", "masked": "####222"},
        ]}
        self.assertEqual(masking_batch_output(self._result(body), context(variables=variables)), ())
        # The old hardcoded '*'/last-4 expectation would now be a violation.
        wrong = {"kid": "a" * 64, "profile": "profile", "items": [
            {"ref": "r0", "masked": "***8888"},
            {"ref": "r1", "masked": "***2222"},
        ]}
        self.assertEqual(masking_batch_output(self._result(wrong), context(variables=variables))[0].code, "mask-batch-policy-violated")

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
