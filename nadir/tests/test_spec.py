import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nadir.spec import load_targets
from nadir.workflows import ProducerConsumerTarget, RequestTarget


def _noop(result, context):
    return ()


SHALLOW = """
targets:
  - name: demo.keys
    request: {method: GET, path: /keys, auth: true}
    mutate:
      - variable: api_key
        values: ["", "bad"]
    expect:
      control: {status: [200]}
      mutated: {status: [401, 403]}
"""

DEEP = """
targets:
  - name: demo.sign
    producer: {method: POST, path: "/sign/{kid}", auth: true, replayable: false, body: {m: "x"}}
    capture: {sig: $.signature}
    consumer: {method: POST, path: /verify, body: {signature: "{sig}"}}
    mutate:
      - {json_field: $.signature, delimiter: ".", segments: [0, 1], name: seg}
    expect:
      control: {status: [200], invariant: verify_ok}
      mutated: {status: [200], invariant: verify_fail}
"""


class SpecTests(unittest.TestCase):
    def test_shallow_request_target(self):
        (target,) = load_targets(SHALLOW, invariants={})
        self.assertIsInstance(target, RequestTarget)
        self.assertEqual(target.name, "demo.keys")
        self.assertEqual(target.required_variables, frozenset({"base_url", "api_key"}))
        self.assertEqual(len(target.mutations), 2)

    def test_deep_producer_consumer_target(self):
        (target,) = load_targets(DEEP, invariants={"verify_ok": _noop, "verify_fail": _noop})
        self.assertIsInstance(target, ProducerConsumerTarget)
        # captured names are produced by the producer, not required from the fixture
        self.assertEqual(target.required_variables, frozenset({"base_url", "kid", "api_key"}))
        self.assertEqual([mutation.name for mutation in target.mutations], ["seg-0", "seg-1"])
        self.assertFalse(target.producer.replayable)

    def test_unknown_invariant_is_rejected(self):
        with self.assertRaises(ValueError):
            load_targets(DEEP, invariants={})

    def test_empty_mutate_is_rejected(self):
        document = (
            "targets:\n"
            "  - name: demo.x\n"
            "    request: {method: GET, path: /x}\n"
            "    mutate: []\n"
            "    expect: {control: {status: [200]}, mutated: {status: [400]}}\n"
        )
        with self.assertRaises(ValueError):
            load_targets(document, invariants={})

    def test_status_class_expands(self):
        document = (
            "targets:\n"
            "  - name: demo.x\n"
            "    request: {method: GET, path: \"/x/{id}\"}\n"
            "    mutate:\n"
            "      - {variable: id, values: [bad]}\n"
            "    expect: {control: {status: [200]}, mutated: {status: \"4xx\", json_error: true}}\n"
        )
        (target,) = load_targets(document, invariants={})
        self.assertEqual(target.required_variables, frozenset({"base_url", "id"}))

    def test_authorization_matrix_declares_denied_credential_dependency(self):
        document = """
targets:
  - name: demo.auth
    request: {method: POST, path: /protected, auth: true, body: {value: ok}}
    mutate:
      - {variable: api_key, values: [bad], name: authn-invalid}
      - {variable: api_key, from_variable: denied_api_key, name: authz-denied}
    expect:
      control: {status: [200]}
      mutated: {authorization_matrix: true, json_error: true}
"""
        (target,) = load_targets(document, invariants={})
        self.assertEqual(target.required_variables, frozenset({"base_url", "api_key", "denied_api_key"}))
        self.assertEqual([mutation.name for mutation in target.mutations], ["authn-invalid-0", "authz-denied"])

    def test_duplicate_mutation_names_are_rejected(self):
        document = """
targets:
  - name: demo.duplicate
    request: {method: POST, path: /test, body: {first: a, second: b}}
    mutate:
      - {json_field: $.first, name: duplicate}
      - {json_field: $.second, name: duplicate}
    expect:
      control: {status: [200]}
      mutated: {status: [400]}
"""
        with self.assertRaisesRegex(ValueError, "duplicate mutation names"):
            load_targets(document, invariants={})
