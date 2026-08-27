import json
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nadir.artifacts import load_replay_requests, load_reproduction_recipe, write_finding
from nadir.engine import _artifact_capture_secrets
from nadir.http import HttpRequest, HttpResult
from nadir.workflows import CaseRecipe, Finding, MutationRecord, StepExecution, WorkflowCase


class ArtifactTests(unittest.TestCase):
    _recipe = CaseRecipe("semantic", 7, "mutated")

    def test_replays_only_public_consumer_step(self):
        producer_request = HttpRequest("POST", "http://127.0.0.1/sign", (("X-API-Key", "secret"),), b"{}")
        consumer_request = HttpRequest("POST", "http://127.0.0.1/sign/verification", (), b'{"signature":"mutated"}')
        producer = StepExecution("sign", producer_request, HttpResult(producer_request, 200, (), b"{}", 1), replayable=False)
        consumer = StepExecution("verify", consumer_request, HttpResult(consumer_request, 200, (), b"{}", 1))
        case = WorkflowCase("target", 1, MutationRecord("mutated", "$.signature", "a", "b"), (producer, consumer), self._recipe)
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
        case = WorkflowCase("target", 1, MutationRecord("api_key:0", "api_key", "top-secret-key", "bad"), (step,), self._recipe)
        with tempfile.TemporaryDirectory() as directory:
            path = write_finding(Path(directory), project="t", run_seed=1, case=case, findings=(Finding("f", "f"),), secrets=(b"top-secret-key",))
            text = path.read_text(encoding="utf-8")
        self.assertNotIn("top-secret-key", text)
        self.assertIn("<redacted>", text)

    def test_response_body_and_headers_are_redacted(self):
        request = HttpRequest("GET", "http://127.0.0.1/test", (), None)
        result = HttpResult(
            request,
            500,
            (("X-Debug", "secret-value"), ("Set-Cookie", "secret-value")),
            b'{"leak":"secret-value"}',
            1,
        )
        case = WorkflowCase(
            "target",
            1,
            MutationRecord("mutated", "$.value", "a", "b"),
            (StepExecution("test", request, result),),
            self._recipe,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = write_finding(
                Path(directory),
                project="test",
                run_seed=1,
                case=case,
                findings=(Finding("leak", "leak"),),
                secrets=(b"secret-value",),
            )
            rendered = path.read_text(encoding="utf-8")
        self.assertNotIn("secret-value", rendered)
        self.assertIn("<redacted>", rendered)

    def test_sensitive_capture_is_redacted_and_disables_request_replay(self):
        opening = "secret-opening"
        producer_request = HttpRequest("POST", "http://127.0.0.1/commit", (), b"{}")
        consumer_request = HttpRequest("POST", "http://127.0.0.1/commit/verify", (), b'{"opening":"secret-opening"}')
        producer = StepExecution(
            "create",
            producer_request,
            HttpResult(producer_request, 200, (), b'{"opening":"secret-opening"}', 1),
            (("opening", opening),),
            replayable=False,
        )
        consumer = StepExecution("verify", consumer_request, HttpResult(consumer_request, 500, (), b"{}", 1))
        case = WorkflowCase("target", 1, MutationRecord("opening", "$.opening", opening, "changed"), (producer, consumer), self._recipe)
        with tempfile.TemporaryDirectory() as directory:
            path = write_finding(
                Path(directory),
                project="test",
                run_seed=1,
                case=case,
                findings=(Finding("test", "test"),),
                secrets=(opening.encode("utf-8"),),
            )
            rendered = path.read_text(encoding="utf-8")
            self.assertNotIn(opening, rendered)
            self.assertIn("<redacted>", rendered)
            with self.assertRaisesRegex(ValueError, "no replayable"):
                load_replay_requests(path)

    def test_target_declared_capture_is_added_to_artifact_redaction(self):
        opening = "fresh-opening"
        request = HttpRequest("POST", "http://127.0.0.1/commit", (), b"{}")
        case = WorkflowCase(
            "target",
            1,
            MutationRecord("opening", "$.opening", opening, "changed"),
            (StepExecution("create", request, HttpResult(request, 200, (), b"{}", 1), (("opening", opening),)),),
            self._recipe,
        )
        target = SimpleNamespace(name="target", artifact_redact_captures=frozenset({"opening"}))
        self.assertEqual(_artifact_capture_secrets(target, case), (opening.encode("utf-8"),))

    def test_all_captured_shares_are_redacted_from_a_finding(self):
        shares = tuple(f"vectis-sss-v1.synthetic-share-{index}" for index in range(5))
        request = HttpRequest(
            "POST",
            "http://127.0.0.1/shares/combine",
            (),
            ("{\"shares\":" + json.dumps(list(shares)) + "}").encode("utf-8"),
        )
        step = StepExecution(
            "split",
            request,
            HttpResult(request, 500, (), json.dumps({"shares": list(shares)}).encode("utf-8"), 1),
            tuple((f"share_{index}", share) for index, share in enumerate(shares)),
            replayable=False,
        )
        case = WorkflowCase("sharing", 1, MutationRecord("share", "$.shares.2", shares[2], "changed"), (step,), self._recipe)
        target = SimpleNamespace(
            name="sharing",
            artifact_redact_captures=frozenset(f"share_{index}" for index in range(5)),
        )
        secrets = _artifact_capture_secrets(target, case)
        with tempfile.TemporaryDirectory() as directory:
            path = write_finding(
                Path(directory),
                project="test",
                run_seed=1,
                case=case,
                findings=(Finding("test", "test"),),
                secrets=secrets,
            )
            rendered = path.read_text(encoding="utf-8")
        for share in shares:
            self.assertNotIn(share, rendered)
        self.assertIn("<redacted>", rendered)

    def test_authenticated_request_replays_with_environment_key_only(self):
        request = HttpRequest("POST", "http://127.0.0.1/token/decode", (("X-API-Key", "original-secret"),), b"{}")
        step = StepExecution("decode", request, HttpResult(request, 403, (), b'{"error":"denied"}', 1))
        case = WorkflowCase("target", 1, MutationRecord("x", "$.token", "a", "b"), (step,), self._recipe)
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
        case = WorkflowCase("target", 1, MutationRecord("x", "api_key", "scoped-secret", "<variable-value>"), (step,), self._recipe)
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

    def test_v3_artifact_remains_replayable_but_not_reproducible(self):
        request = HttpRequest("GET", "http://127.0.0.1/ready", (), None)
        payload = {
            "artifact_version": "nadir-finding-v3",
            "steps": [{
                "replayable": True,
                "request": {
                    "method": "GET",
                    "url": request.url,
                    "headers": [],
                    "body": None,
                    "requires_api_key": False,
                },
            }],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "v3.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            self.assertEqual(load_replay_requests(path), (request,))
            with self.assertRaisesRegex(ValueError, "request replay only"):
                load_reproduction_recipe(path)

    def test_v4_artifact_exposes_reproduction_recipe(self):
        request = HttpRequest("POST", "http://127.0.0.1/test", (), b"{}")
        step = StepExecution("test", request, HttpResult(request, 500, (), b"{}", 1))
        case = WorkflowCase(
            "target",
            9,
            MutationRecord("mutated", "$.value", "a", "b"),
            (step,),
            CaseRecipe("semantic", 123, "mutated"),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = write_finding(
                Path(directory),
                project="test",
                run_seed=5,
                case=case,
                findings=(Finding("server-error", "failed"),),
                secrets=(),
            )
            recipe = load_reproduction_recipe(path)
        self.assertEqual(recipe.project, "test")
        self.assertEqual(recipe.target, "target")
        self.assertEqual(recipe.iteration, 9)
        self.assertEqual(recipe.run_seed, 5)
        self.assertEqual(recipe.case, CaseRecipe("semantic", 123, "mutated"))
        self.assertEqual(recipe.finding_codes, frozenset({"server-error"}))
