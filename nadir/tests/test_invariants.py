import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "projects" / "vectis"))

from nadir.http import HttpRequest, HttpResult
from nadir.workflows import EvaluationContext
from invariants import public_keys_output, verification_failure


def context(mutation=None):
    return EvaluationContext("vectis", "test", mutation, ())


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

