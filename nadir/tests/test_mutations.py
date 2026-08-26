import random
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nadir.mutations import DeserStressMutation, JsonFieldMutation, RawBodyMutation, StructuredMutation, TemplateValueMutation


def _rng(seed: int = 0) -> random.Random:
    return random.Random(seed)


class MutationTests(unittest.TestCase):
    def test_template_variable_mutation(self):
        variables, body, record = TemplateValueMutation("wrong", "kid", "bad").apply({"kid": "good"}, None, _rng())
        self.assertEqual(variables["kid"], "bad")
        self.assertIsNone(body)
        self.assertEqual(record.location, "kid")

    def test_json_segment_mutation_preserves_other_segments(self):
        mutation = JsonFieldMutation("signature", "$.signature", delimiter=".", segment_index=2)
        _, body, record = mutation.apply({}, {"signature": "one.two.three.four"}, _rng())
        self.assertEqual(body["signature"], "one.two.Ahree.four")
        self.assertEqual(record.location, "$.signature")

    def test_json_selector_must_exist(self):
        with self.assertRaises(ValueError):
            JsonFieldMutation("bad", "$.missing").apply({}, {"signature": "value"}, _rng())

    def test_structured_mutation_changes_body_and_is_deterministic(self):
        seed_body = {"alg": "SHA-256", "hex": "abcdef", "nested": {"k": "v"}}
        first = StructuredMutation().apply({}, seed_body, _rng(7))
        second = StructuredMutation().apply({}, seed_body, _rng(7))
        self.assertEqual(first[1], second[1])
        self.assertNotEqual(first[1], seed_body)
        self.assertTrue(first[2].location.startswith("$"))

    def test_raw_mutation_returns_bytes_deterministically(self):
        seed_body = {"message": "hello", "n": 1}
        variables, body, record = RawBodyMutation().apply({}, seed_body, _rng(3))
        self.assertIsInstance(body, bytes)
        again = RawBodyMutation().apply({}, seed_body, _rng(3))
        self.assertEqual(body, again[1])
        self.assertTrue(record.name.startswith("raw-invalid:"))

    def test_generative_mutators_require_a_body(self):
        for mutator in (StructuredMutation(), RawBodyMutation(), DeserStressMutation()):
            with self.assertRaises(ValueError):
                mutator.apply({}, None, _rng())
