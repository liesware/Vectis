"""Offline contracts for the private ZAP fixture preparation."""

import copy
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import zap_fixtures

from zap_fixtures import (
    OPERATIONS, POST, PUBLIC, Preflight, VALUES, batch_items, checked_batch, prepare_document,
)


class FakeClient:
    """Synthetic transport: captures are intentionally different for every plaintext."""

    kid = "a" * 64
    subject = "b" * 64
    url = "https://127.0.0.1:12345"

    def __init__(self):
        self.calls = []

    def request(self, method, path, body=None):
        self.calls.append((method, path, copy.deepcopy(body)))
        if path in PUBLIC[:3]:
            return 200, {"status": dict(zip(PUBLIC[:3], ("started", "ok", "ready")))[path]}
        if method == "GET":
            return 200, {"kid": self.kid}
        profile = body.get("profile")
        output = {"kid": self.kid, "profile": profile}
        if "subject/{subject}" in path or body.get("subject"):
            output["subject"] = self.subject
        if path.startswith("/symmetric/encrypt"):
            return 200, {**output, "plaintext": body["plaintext"], "ciphertext": "synthetic"}
        if path == "/symmetric/decrypt":
            return 200, body
        if path.startswith("/shares/split"):
            return 200, {**output, "threshold": 3, "shares": [f"share-{i}" for i in range(5)], "set_id": "set"}
        if path == "/shares/combine":
            return 200, {**output, "set_id": "set", "plaintext": "Synthetic ZAP shared secret"}
        if path.startswith("/sign/"):
            if path == "/sign/verification":
                return 200, {"valid": "ok", "status": {"eddsa": "ok", "ml-dsa": "ok"}}
            return 200, {"kid": self.kid, "signature": "synthetic"}

        def result(item):
            ref = {"ref": item["ref"]}
            if "/decrypt" in path or "/decode" in path:
                field = "ciphertext" if path.startswith("/fpe") else "token"
                return {**ref, "plaintext": item[field].removeprefix("encoded:")}
            if "/verify" in path:
                field = "digest" if path.startswith("/mac") else "commitment"
                if path.startswith("/index"):
                    return {**ref, "matched": True, "index": "index:" + item["plaintext"]}
                if "John Doe" in item.get(field, ""):
                    raise ValueError("SQL probe must be processed before batch result")
                return {**ref, "valid": True}
            text = item["plaintext"]
            if path.startswith("/fpe"):
                return {**ref, "ciphertext": "encoded:" + text, "tag": "tag:" + text}
            if path.startswith("/token"):
                return {**ref, "token": "encoded:" + text}
            if path.startswith("/mac"):
                return {**ref, "digest": "digest:" + text}
            if path.startswith("/index"):
                return {**ref, "index": "index:" + text}
            if path.startswith("/commit"):
                return {**ref, "opening": "opening:" + text, "commitment": "commitment:" + text}
            if path.startswith("/mask"):
                return {**ref, "masked": "*" * 12 + text[-4:]}
            raise AssertionError(path)

        target = body["items"][0] if "items" in body else body
        if any("John Doe" in str(value) for value in target.values()):
            return 400, {"error": "field must be hexadecimal"}
        if "items" in body:
            return 200, {**output, "items": [result(item) for item in body["items"]]}
        return 200, {**output, **result(body)}


class FixtureTests(unittest.TestCase):
    def test_identifiers_are_fixed_width_non_card_values(self):
        self.assertEqual(len(VALUES), 3)
        self.assertEqual(len(set(VALUES)), 3)
        for value in VALUES:
            with self.subTest(value=value):
                self.assertEqual(len(value), 16)
                self.assertTrue(value.isascii() and value.isdecimal())
                self.assertTrue(value.startswith("00"))
                digits = [int(char) for char in value]
                total = sum(
                    (2 * digit - 9 if digit >= 5 else 2 * digit) if index % 2 == 0 else digit
                    for index, digit in enumerate(digits)
                )
                self.assertNotEqual(total % 10, 0, "fixture must fail the Luhn checksum")

    def setUp(self):
        self.client = FakeClient()
        self.preflight = Preflight(self.client)

    def test_all_families_and_modes_chain_real_captures(self):
        self.preflight.run()
        self.assertEqual(set(self.preflight.examples), set(OPERATIONS))
        self.assertEqual(len(OPERATIONS), len(set(OPERATIONS)))
        for path, method in OPERATIONS:
            for body in self.preflight.examples[(path, method)]:
                if body and "items" in body:
                    self.assertEqual(len(body["items"]), 3)
                    self.assertEqual(len({item["ref"] for item in body["items"]}), 3)
        for base in ("/fpe/decrypt", "/token/decode", "/token/deterministic/decode"):
            self.assertEqual(len(self.preflight.examples[(base, "post")]), 2)
        mac = self.preflight.examples[("/mac/verify", "post")][0]
        self.assertEqual(mac["digest"], "digest:" + VALUES[0])
        commit = self.preflight.examples[("/commit/verify/batch", "post")][0]
        self.assertEqual([item["opening"] for item in commit["items"]],
                         ["opening:" + text for text in VALUES])

    def test_errors_and_wrong_contract_stop_preparation(self):
        self.client.request = lambda *args: (403, {"error": "forbidden"})
        with self.assertRaisesRegex(ValueError, "HTTP 403"):
            self.preflight.run()
        self.assertEqual(self.preflight.completed, [])
        self.client.request = lambda *args: (200, {"status": "wrong"})
        with self.assertRaisesRegex(ValueError, "contract mismatch"):
            self.preflight.run()

    def test_batch_order_count_and_identity(self):
        inputs = batch_items("ordered")
        output = {"kid": self.client.kid, "profile": "p", "items": inputs}
        checked_batch(output, inputs, self.client.kid, "p")
        for modified in (list(reversed(inputs)), inputs[:2]):
            with self.assertRaises(ValueError):
                checked_batch({**output, "items": modified}, inputs, self.client.kid, "p")
        with self.assertRaises(ValueError):
            checked_batch(output, inputs, self.client.kid, "wrong")

    def test_sql_probes_keep_baselines_and_mutate_only_first_item(self):
        self.preflight.run()
        originals = copy.deepcopy(self.preflight.examples)
        evidence = self.preflight.sql_probes()
        self.assertEqual(len(evidence), 12)
        self.assertEqual([row["status"] for row in evidence], [200, 400, 400] * 4)
        self.assertEqual(self.preflight.examples, originals)
        for method, path, body in self.client.calls[-12:]:
            if "items" in body:
                self.assertNotIn("John Doe", json.dumps(body["items"][1:]))

    def test_scope_and_operational_examples_leave_source_unchanged(self):
        self.preflight.run()
        source = {"openapi": "3.0.3", "components": {"schemas": {
            "Shared": {"type": "object", "example": {"plaintext": "John Doe"}}}}, "paths": {}}
        for path, method in OPERATIONS:
            operation = {"parameters": [{"name": name, "in": "path", "required": True,
                                          "schema": {"type": "string", "example": "wrong"}}
                                         for name in ("kid", "subject") if "{" + name + "}" in path]}
            if method == "post":
                operation["requestBody"] = {"content": {"application/json": {
                    "schema": {"$ref": "#/components/schemas/Shared"},
                    "examples": {"bad": {"value": {"plaintext": "John Doe"}}}}}}
            source["paths"][path] = {method: operation, "delete": {}}
        source["paths"]["/admin"] = {"post": {}}
        original = copy.deepcopy(source)
        document = prepare_document(source, self.preflight)
        self.assertEqual(source, original)
        self.assertEqual({(path, method) for path, entry in document["paths"].items()
                          for method in entry}, set(OPERATIONS))
        for path in POST:
            media = document["paths"][path]["post"]["requestBody"]["content"]["application/json"]
            self.assertEqual(media["example"], self.preflight.examples[(path, "post")][0])
            self.assertEqual(media["schema"]["example"], media["example"])
            self.assertNotIn("examples", media)
        for entry in document["paths"].values():
            for operation in entry.values():
                for parameter in operation["parameters"]:
                    self.assertEqual(parameter["example"], getattr(self.client, parameter["name"]))
        del source["paths"][POST[0]]
        with self.assertRaisesRegex(ValueError, "operation missing"):
            prepare_document(source, self.preflight)

    def test_fixture_missing_and_unlisted_operation_fail(self):
        with self.assertRaisesRegex(ValueError, "outside ZAP scope"):
            self.preflight.call("/keys/reload", {})
        source = {"openapi": "3.0.3", "components": {}, "paths": {PUBLIC[0]: {"get": {}}}}
        with self.assertRaisesRegex(ValueError, "fixture missing"):
            prepare_document(source, self.preflight)

    def test_laboratory_has_no_admin_or_delete_grants_and_one_scan(self):
        script = Path(__file__).with_name("zap_scan.sh").read_text()
        grants = script.split("for action in", 1)[1].split("done", 1)[0]
        self.assertNotIn("admin", grants)
        self.assertNotIn("delete", grants)
        self.assertNotIn("subject-create", grants)
        self.assertIn('DENIED_STATUS', script)
        self.assertEqual(script.count('zap-api-scan.py'), 1)
        self.assertNotIn("IGNORE", script)
        self.assertTrue(all("/subject/" not in path or path.endswith("/subject/{subject}")
                            for path, _ in OPERATIONS))

    def test_entrypoint_real_document_and_secret_free_artifacts(self):
        root = Path(__file__).resolve().parents[3]
        credential = "synthetic-zap-credential-canary"
        self.client.credential = credential
        with tempfile.TemporaryDirectory() as directory:
            environment = {
                "ZAP_RESULTS_DIR": directory, "ZAP_OPENAPI_INPUT": str(root / "doc/openapi.yaml"),
                "ZAP_OPENAPI_BASE_URL": self.client.url, "ZAP_OPENAPI_KID": self.client.kid,
                "ZAP_SUBJECT": self.client.subject, "ZAP_AUTH_HEADER_VALUE": credential,
                "ZAP_CERTIFICATE": "unused-mocked-transport.pem",
            }
            with patch.dict(os.environ, environment), patch.object(zap_fixtures, "Client", return_value=self.client):
                with contextlib.redirect_stdout(io.StringIO()) as output:
                    zap_fixtures.main()
            self.assertNotIn(credential, output.getvalue())
            for artifact in Path(directory).iterdir():
                self.assertNotIn(credential, artifact.read_text())
            summary = json.loads(Path(directory, "preflight.json").read_text())
            self.assertEqual(summary["result"], "passed")
            self.assertEqual(len(summary["completed"]), 51)
            self.assertEqual({entry["subject_mode"] for entry in summary["completed"]}, {"none", "stored"})
            document = json.loads(Path(directory, "openapi-zap.json").read_text())
            self.assertEqual(len(document["paths"]), len(OPERATIONS))
            self.assertNotIn("/subject/{kid}", document["paths"])
            self.assertNotIn("/token/delete", document["paths"])

    def test_entrypoint_failure_preserves_partial_summary(self):
        self.client.request = lambda *args: (500, {"error": "must not be printed"})
        with tempfile.TemporaryDirectory() as directory:
            environment = {
                "ZAP_RESULTS_DIR": directory, "ZAP_OPENAPI_INPUT": "never-read",
                "ZAP_OPENAPI_BASE_URL": self.client.url, "ZAP_OPENAPI_KID": self.client.kid,
                "ZAP_SUBJECT": self.client.subject, "ZAP_AUTH_HEADER_VALUE": "canary",
                "ZAP_CERTIFICATE": "unused",
            }
            with patch.dict(os.environ, environment), patch.object(zap_fixtures, "Client", return_value=self.client):
                with self.assertRaisesRegex(ValueError, "HTTP 500"):
                    zap_fixtures.main()
            summary = json.loads(Path(directory, "preflight.json").read_text())
            self.assertEqual(summary["result"], "failed")
            self.assertEqual(summary["completed"], [])
            self.assertFalse(Path(directory, "openapi-zap.json").exists())


if __name__ == "__main__":
    unittest.main()
