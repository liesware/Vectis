import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "projects" / "vectis"))

from nadir.http import HttpRequest, HttpResult
from nadir.workflows import EvaluationContext
from invariants import fpe_encrypt_output, fpe_round_trip, mac_create_output, mac_verification_failure, masking_policy_output, public_keys_output, token_round_trip, verification_failure


def context(mutation=None, *, target="vectis", variables=None):
    return EvaluationContext(target, "test", mutation, (), variables or {})


class InvariantTests(unittest.TestCase):
    def _result(self, body):
        request = HttpRequest("GET", "http://127.0.0.1/pub/kid")
        return HttpResult(request, 200, (), json.dumps(body).encode("utf-8"), 1)

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
