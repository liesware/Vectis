import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nadir.http import HttpRequest, HttpResult
from nadir.workflows import EvaluationContext, ExpectNoJsonFields


class WorkflowExpectationTests(unittest.TestCase):
    def _result(self, body):
        request = HttpRequest("POST", "http://127.0.0.1/batch")
        return HttpResult(request, 400, (), json.dumps(body).encode("utf-8"), 1)

    def test_batch_rejection_without_items_is_accepted(self):
        expectation = ExpectNoJsonFields(frozenset({"items"}))
        self.assertEqual(expectation.evaluate(self._result({"error": "invalid batch"}), EvaluationContext("demo", "batch", None, ())), ())

    def test_batch_rejection_with_items_is_a_finding(self):
        expectation = ExpectNoJsonFields(frozenset({"items"}))
        findings = expectation.evaluate(self._result({"error": "invalid batch", "items": []}), EvaluationContext("demo", "batch", None, ()))
        self.assertEqual(findings[0].code, "forbidden-json-field")

