import json
from contextlib import nullcontext
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nadir.artifacts import load_replay_requests
from nadir.engine import run_project
from nadir.http import HttpRequest, HttpResult, TransportFailure
from nadir.mutations import JsonFieldMutation
from nadir.workflows import AllOf, CaseWeights, Capture, EvaluationContext, ExpectStatus, Finding, HttpStep, MutationRecord, ProducerConsumerTarget, ProjectPredicate, RequestTarget


class _Handler(BaseHTTPRequestHandler):
    accept_mutation = False
    producer_calls = 0

    def do_GET(self):
        self._write(200, {"status": "ready"})

    def do_POST(self):
        if self.path == "/sign":
            self.producer_calls += 1
            if self.headers.get("X-API-Key") != "test-key":
                self._write(401, {"error": "unauthorized"})
            else:
                self._write(200, {"kid": "a" * 64, "signature": "aaaa.bbbb.cccc.dddd"})
            return
        if self.path == "/verify":
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            altered = any(segment.startswith("A") for segment in body["signature"].split("."))
            if altered and not self.accept_mutation:
                self._write(200, {"valid": "fail"})
            else:
                self._write(200, {"valid": "ok"})
            return
        self._write(404, {"error": "missing"})

    def _write(self, status, body):
        rendered = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(rendered)))
        self.end_headers()
        self.wfile.write(rendered)

    def log_message(self, format, *args):
        return


class _Fixture:
    def __init__(self, base_url): self.base_url = base_url
    def variables(self): return {"base_url": self.base_url, "api_key": "test-key"}


class _Project:
    name = "synthetic"
    def __init__(self, base_url): self.base_url = base_url
    def target_names(self): return ("synthetic.workflow",)
    def fixture(self, options): return nullcontext(_Fixture(self.base_url))
    def healthcheck_step(self): return HttpStep("ready", "GET", "{base_url}/ready", expectation=ExpectStatus(frozenset({200})))
    def redaction_values(self, fixture): return (b"test-key",)
    def self_check(self): return ()
    def targets(self):
        def output(result, context):
            try: body = json.loads(result.body)
            except json.JSONDecodeError: return ()
            return () if "signature" in body else ()
        def control(result, context):
            return () if json.loads(result.body).get("valid") == "ok" else ()
        def rejected(result, context):
            return () if json.loads(result.body).get("valid") == "fail" else (Finding("accepted", "mutation accepted"),)
        return (ProducerConsumerTarget(
            "synthetic.workflow", frozenset({"base_url", "api_key"}),
            HttpStep("sign", "POST", "{base_url}/sign", (("X-API-Key", "{api_key}"),), {}, expectation=AllOf((ExpectStatus(frozenset({200})), ProjectPredicate("output", output))), replayable=False),
            (Capture("signature", "$.signature"),),
            HttpStep("verify", "POST", "{base_url}/verify", json_body_template={"signature": "{signature}"}),
            (JsonFieldMutation("mutated", "$.signature", delimiter=".", segment_index=0),),
            AllOf((ExpectStatus(frozenset({200})), ProjectPredicate("control", control))),
            AllOf((ExpectStatus(frozenset({200})), ProjectPredicate("rejected", rejected))),
        ),)


class _DeserFixture:
    def variables(self):
        return {"base_url": "http://nadir.test"}


class _DeserProject:
    name = "synthetic-deser"

    def target_names(self):
        return ("synthetic.deser",)

    def fixture(self, options):
        return nullcontext(_DeserFixture())

    def healthcheck_step(self):
        return HttpStep("ready", "GET", "{base_url}/healthz/ready", expectation=ExpectStatus(frozenset({200})))

    def redaction_values(self, fixture):
        return ()

    def self_check(self):
        return ()

    def targets(self):
        return (
            RequestTarget(
                "synthetic.deser",
                frozenset({"base_url"}),
                HttpStep("deserialize", "POST", "{base_url}/deserialize", json_body_template={"value": "valid"}),
                (JsonFieldMutation("semantic", "$.value"),),
                ExpectStatus(frozenset({200})),
                weights=CaseWeights(semantic=0, structured=0, raw=0, deser=1),
            ),
        )


class _DeserTimeoutTransport:
    def __init__(self, unhealthy_after_timeout):
        self.unhealthy_after_timeout = unhealthy_after_timeout
        self.request_count = 0
        self.ready_count = 0

    def send(self, request):
        if request.url.endswith("/healthz/ready"):
            self.ready_count += 1
            if self.unhealthy_after_timeout and self.ready_count == 2:
                return HttpResult(request, None, (), b"", 2_500, TransportFailure("timeout", "ready probe timed out"))
            return HttpResult(request, 200, (), b"{}", 1)
        self.request_count += 1
        if self.request_count == 3:
            return HttpResult(request, None, (), b"", 2_500, TransportFailure("timeout", "request timed out"))
        return HttpResult(request, 200, (), b"{}", 1)


class ExpectStatusTransportTests(unittest.TestCase):
    """A mutation that yields un-sendable input is not a server finding (#4)."""

    def _result(self, failure):
        request = HttpRequest("GET", "http://127.0.0.1/x", (), None)
        return HttpResult(request, None, (), b"", 0, failure)

    def _context(self, mutation):
        return EvaluationContext("t", "step", mutation, ())

    _record = MutationRecord("auth", "api_key", "valid", "   ")

    def test_client_side_failure_from_mutation_is_not_a_finding(self):
        result = self._result(TransportFailure("local_protocol", "rejected locally"))
        self.assertEqual(ExpectStatus(frozenset({401})).evaluate(result, self._context(self._record)), ())

    def test_client_side_failure_without_mutation_is_reported(self):
        result = self._result(TransportFailure("local_protocol", "rejected locally"))
        findings = ExpectStatus(frozenset({401})).evaluate(result, self._context(None))
        self.assertEqual([finding.code for finding in findings], ["transport-failure"])

    def test_server_side_failure_from_mutation_is_still_a_finding(self):
        result = self._result(TransportFailure("reset", "connection reset"))
        findings = ExpectStatus(frozenset({401})).evaluate(result, self._context(self._record))
        self.assertEqual([finding.code for finding in findings], ["transport-failure"])


class EngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.thread.join()

    def test_workflow_control_and_rejection_are_executed_generically(self):
        _Handler.accept_mutation = False
        summary = run_project(_Project(self.base_url), options={}, target_name=None, iterations=1, run_seed=1, output_dir=Path(tempfile.mkdtemp()))
        self.assertEqual(summary.targets[0].findings, 0)

    def test_finding_replays_only_consumer_request(self):
        _Handler.accept_mutation = True
        with tempfile.TemporaryDirectory() as directory:
            summary = run_project(_Project(self.base_url), options={}, target_name=None, iterations=1, run_seed=1, output_dir=Path(directory))
            replay = load_replay_requests(summary.artifacts[0])
        self.assertEqual(len(replay), 1)
        self.assertTrue(replay[0].url.endswith("/verify"))
        _Handler.accept_mutation = False

    def test_deser_timeout_with_healthy_ready_is_not_a_dos_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            summary = run_project(
                _DeserProject(),
                options={},
                target_name=None,
                iterations=2,
                run_seed=7,
                output_dir=Path(directory),
                transport=_DeserTimeoutTransport(False),
            )
        self.assertEqual(summary.targets[0].deser, 1)
        self.assertEqual(summary.targets[0].findings, 0)

    def test_deser_timeout_with_unhealthy_ready_is_a_dos_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            summary = run_project(
                _DeserProject(),
                options={},
                target_name=None,
                iterations=2,
                run_seed=7,
                output_dir=Path(directory),
                transport=_DeserTimeoutTransport(True),
            )
        self.assertEqual(summary.targets[0].deser, 1)
        self.assertEqual(summary.targets[0].findings, 1)
