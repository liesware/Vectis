import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nadir.artifacts import load_replay_requests, write_finding
from nadir.http import HttpRequest, HttpResult
from nadir.workflows import Finding, MutationRecord, StepExecution, WorkflowCase


class ArtifactTests(unittest.TestCase):
    def test_replays_only_public_consumer_step(self):
        producer_request = HttpRequest("POST", "http://127.0.0.1/sign", (("X-API-Key", "secret"),), b"{}")
        consumer_request = HttpRequest("POST", "http://127.0.0.1/sign/verification", (), b'{"signature":"mutated"}')
        producer = StepExecution("sign", producer_request, HttpResult(producer_request, 200, (), b"{}", 1), replayable=False)
        consumer = StepExecution("verify", consumer_request, HttpResult(consumer_request, 200, (), b"{}", 1))
        case = WorkflowCase("target", 1, MutationRecord("mutated", "$.signature", "a", "b"), (producer, consumer))
        with tempfile.TemporaryDirectory() as directory:
            path = write_finding(Path(directory), project="test", run_seed=1, case=case, findings=(Finding("test", "test"),), secrets=(b"secret",))
            self.assertNotIn("secret", path.read_text(encoding="utf-8"))
            replay = load_replay_requests(path)
        self.assertEqual(replay, (consumer_request,))

    def test_mutation_over_secret_variable_is_redacted(self):
        # Mutating a secret variable stores the real value in MutationRecord.original;
        # it must be scrubbed from the artifact, not written verbatim.
        request = HttpRequest("GET", "http://127.0.0.1/keys", (("X-API-Key", "top-secret-key"),), None)
        step = StepExecution("keys", request, HttpResult(request, 401, (), b'{"error":"no"}', 1))
        case = WorkflowCase("target", 1, MutationRecord("api_key:0", "api_key", "top-secret-key", "bad"), (step,))
        with tempfile.TemporaryDirectory() as directory:
            path = write_finding(Path(directory), project="t", run_seed=1, case=case, findings=(Finding("f", "f"),), secrets=(b"top-secret-key",))
            text = path.read_text(encoding="utf-8")
        self.assertNotIn("top-secret-key", text)
        self.assertIn("<redacted>", text)

    def test_authenticated_request_replays_with_environment_key_only(self):
        request = HttpRequest("POST", "http://127.0.0.1/token/decode", (("X-API-Key", "original-secret"),), b"{}")
        step = StepExecution("decode", request, HttpResult(request, 403, (), b'{"error":"denied"}', 1))
        case = WorkflowCase("target", 1, MutationRecord("x", "$.token", "a", "b"), (step,))
        with tempfile.TemporaryDirectory() as directory:
            path = write_finding(Path(directory), project="test", run_seed=1, case=case, findings=(Finding("test", "test"),), secrets=(b"original-secret",), primary_api_key=b"original-secret")
            rendered = path.read_text(encoding="utf-8")
            self.assertNotIn("original-secret", rendered)
            with self.assertRaisesRegex(ValueError, "NADIR_API_KEY"):
                load_replay_requests(path)
            (replay,) = load_replay_requests(path, api_key="fresh-secret")
        self.assertEqual(replay.headers, (("X-API-Key", "fresh-secret"),))

    def test_non_primary_principal_step_is_not_replayable(self):
        # A step that authenticated with the scoped/denied key must not be replayed
        # with the primary key; it is recorded as unreplayable instead.
        request = HttpRequest("POST", "http://127.0.0.1/fpe/encrypt", (("X-API-Key", "scoped-secret"),), b"{}")
        step = StepExecution("encrypt", request, HttpResult(request, 403, (), b'{"error":"denied"}', 1))
        case = WorkflowCase("target", 1, MutationRecord("x", "api_key", "scoped-secret", "<variable-value>"), (step,))
        with tempfile.TemporaryDirectory() as directory:
            path = write_finding(
                Path(directory), project="test", run_seed=1, case=case,
                findings=(Finding("test", "test"),), secrets=(b"primary-secret", b"scoped-secret"),
                primary_api_key=b"primary-secret",
            )
            self.assertNotIn("scoped-secret", path.read_text(encoding="utf-8"))
            with self.assertRaisesRegex(ValueError, "no replayable"):
                load_replay_requests(path, api_key="fresh-secret")

    def test_rejects_v1_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "old.json"
            path.write_text(json.dumps({"artifact_version": "nadir-finding-v1"}), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_replay_requests(path)

    def test_rejects_pre_authenticated_replay_format(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "v2.json"
            path.write_text(json.dumps({"artifact_version": "nadir-finding-v2"}), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_replay_requests(path)
