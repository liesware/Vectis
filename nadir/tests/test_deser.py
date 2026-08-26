import json
import random
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nadir.http import MAX_CAPTURED_BODY_BYTES, HttpRequest, HttpResult, TransportFailure
from nadir.mutations import DeserStressMutation
from nadir.workflows import EvaluationContext, ExpectUnderLatency


def _rng(seed: int = 0) -> random.Random:
    return random.Random(seed)


def _context() -> EvaluationContext:
    return EvaluationContext("target", "step", None, ())


def _payload_size(payload: object) -> int:
    if isinstance(payload, bytes):
        return len(payload)
    return len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))


class DeserStressTests(unittest.TestCase):
    def test_changes_body_deterministically(self):
        body = {"value": "x", "n": 1}
        first = DeserStressMutation().apply({}, body, _rng(11))
        second = DeserStressMutation().apply({}, body, _rng(11))
        self.assertEqual(first[1], second[1])
        self.assertNotEqual(first[1], body)
        self.assertTrue(first[2].name.startswith("deser-stress:"))

    def test_every_operation_stays_under_transport_cap(self):
        body = {"a": "b", "list": [1, 2, 3]}
        for seed in range(60):
            _, payload, _ = DeserStressMutation().apply({}, body, _rng(seed))
            self.assertLessEqual(_payload_size(payload), MAX_CAPTURED_BODY_BYTES)

    def test_near_limit_control_body_still_produces_a_bounded_payload(self):
        body = {"payload": "x" * (MAX_CAPTURED_BODY_BYTES - 128)}
        self.assertLessEqual(_payload_size(body), MAX_CAPTURED_BODY_BYTES)
        operations = set()
        for seed in range(80):
            _, payload, record = DeserStressMutation().apply({}, body, _rng(seed))
            operations.add(record.name.removeprefix("deser-stress:"))
            self.assertLessEqual(_payload_size(payload), MAX_CAPTURED_BODY_BYTES)
        self.assertEqual(operations, set(DeserStressMutation.OPERATIONS))

    def test_requires_a_body(self):
        with self.assertRaises(ValueError):
            DeserStressMutation().apply({}, None, _rng())


class LatencyOracleTests(unittest.TestCase):
    def _result(self, elapsed_ms: int, failure: TransportFailure | None = None) -> HttpResult:
        request = HttpRequest("POST", "http://127.0.0.1/x", (), b"{}")
        return HttpResult(request, 200, (), b"{}", elapsed_ms, failure)

    def test_flags_a_slow_completed_response(self):
        findings = ExpectUnderLatency(1000).evaluate(self._result(1500), _context())
        self.assertEqual([finding.code for finding in findings], ["slow-response"])

    def test_passes_a_fast_response(self):
        self.assertEqual(ExpectUnderLatency(1000).evaluate(self._result(40), _context()), ())

    def test_ignores_transport_failure(self):
        result = self._result(9999, TransportFailure("timeout", "timed out"))
        self.assertEqual(ExpectUnderLatency(1000).evaluate(result, _context()), ())
