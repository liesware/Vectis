import json
from contextlib import nullcontext
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nadir.artifacts import ReproductionRecipe, load_replay_requests, load_reproduction_recipe
from nadir.engine import _case_seed, _target_has_body, reproduce_project, run_project
from nadir.http import HttpRequest, HttpResult, TransportFailure
from nadir.mutations import JsonFieldMutation
from nadir.workflows import AllOf, CaseRecipe, CaseWeights, Capture, EvaluationContext, ExpectNoServerCrash, ExpectStatus, Finding, HttpStep, MutationRecord, NoDeclaredSecrets, ProducerConsumerTarget, ProjectPredicate, ProjectRacePredicate, RaceTarget, RequestTarget


class _Handler(BaseHTTPRequestHandler):
    accept_mutation = False
    producer_calls = 0

    def do_GET(self):
        self._write(200, {"status": "ready"})

    def do_POST(self):
        if self.path == "/sign":
            type(self).producer_calls += 1
            if self.headers.get("X-API-Key") != "test-key":
                self._write(401, {"error": "unauthorized"})
            else:
                self._write(200, {"kid": "a" * 64, "signature": f"{type(self).producer_calls:04x}.bbbb.cccc.dddd"})
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
        # control + semantic + structured + raw run before the guaranteed deser case.
        if self.request_count == 5:
            return HttpResult(request, None, (), b"", 2_500, TransportFailure("timeout", "request timed out"))
        return HttpResult(request, 200, (), b"{}", 1)


class _FindingProject:
    name = "synthetic-finding"

    def __init__(self, base_url):
        self.base_url = base_url

    def target_names(self):
        return ("synthetic.finding",)

    def fixture(self, options):
        return nullcontext(_Fixture(self.base_url))

    def healthcheck_step(self):
        return HttpStep("ready", "GET", "{base_url}/ready", expectation=ExpectStatus(frozenset({200})))

    def redaction_values(self, fixture):
        return ()

    def self_check(self):
        return ()

    def targets(self):
        finding = ExpectStatus(frozenset({201}))
        return (
            RequestTarget(
                "synthetic.finding",
                frozenset({"base_url", "api_key"}),
                HttpStep(
                    "finding",
                    "POST",
                    "{base_url}/sign",
                    (("X-API-Key", "{api_key}"),),
                    {"value": "valid"},
                    expectation=ExpectStatus(frozenset({200})),
                ),
                (JsonFieldMutation("semantic", "$.value"),),
                finding,
                malformed_expectation=finding,
            ),
        )


class _MultiFindingProject(_FindingProject):
    def target_names(self):
        return ("synthetic.extra", "synthetic.finding")

    def targets(self):
        finding = super().targets()[0]
        return (replace(finding, name="synthetic.extra"), finding)


class _RaceProject:
    name = "synthetic-race"

    def __init__(self, base_url):
        self.base_url = base_url
        self.report_finding = True

    def target_names(self):
        return ("synthetic.race",)

    def fixture(self, options):
        return nullcontext(_Fixture(self.base_url))

    def healthcheck_step(self):
        return HttpStep("ready", "GET", "{base_url}/ready", expectation=ExpectStatus(frozenset({200})))

    def redaction_values(self, fixture):
        return ()

    def self_check(self):
        return ()

    def targets(self):
        def race_finding(results, context):
            return (
                (Finding("race-finding", "synthetic race finding"),)
                if self.report_finding
                else ()
            )

        producer = HttpStep(
            "sign",
            "POST",
            "{base_url}/sign",
            (("X-API-Key", "{api_key}"),),
            {},
            expectation=ExpectStatus(frozenset({200})),
        )
        contender = lambda name: HttpStep(
            name,
            "POST",
            "{base_url}/verify",
            json_body_template={"signature": "{signature}"},
        )
        return (
            RaceTarget(
                "synthetic.race",
                frozenset({"base_url", "api_key"}),
                producer,
                (Capture("signature", "$.signature"),),
                (contender("a"), contender("b")),
                ProjectRacePredicate("race", race_finding),
            ),
        )


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

    def test_no_server_crash_flags_reset_but_not_timeout_or_success(self):
        oracle = ExpectNoServerCrash()
        context = self._context(self._record)
        self.assertEqual([f.code for f in oracle.evaluate(self._result(TransportFailure("reset", "x")), context)], ["server-crash"])
        self.assertEqual([f.code for f in oracle.evaluate(self._result(TransportFailure("protocol", "x")), context)], ["server-crash"])
        self.assertEqual(oracle.evaluate(self._result(TransportFailure("timeout", "x")), context), ())
        self.assertEqual(oracle.evaluate(self._result(TransportFailure("local_protocol", "x")), context), ())
        request = HttpRequest("GET", "http://127.0.0.1/x", (), None)
        self.assertEqual(oracle.evaluate(HttpResult(request, 200, (), b"{}", 1, None), context), ())

    def test_declared_secrets_are_detected_in_body_and_headers(self):
        request = HttpRequest("GET", "http://127.0.0.1/x", (), None)
        context = EvaluationContext("t", "step", None, (b"secret-value",))
        oracle = NoDeclaredSecrets()
        body_result = HttpResult(request, 200, (), b"secret-value", 1)
        header_result = HttpResult(request, 200, (("X-Debug", "secret-value"),), b"{}", 1)
        self.assertEqual([finding.code for finding in oracle.evaluate(body_result, context)], ["response-leaks-declared-secret"])
        self.assertEqual([finding.code for finding in oracle.evaluate(header_result, context)], ["response-leaks-declared-secret"])

    def test_secret_in_header_name_only_is_not_a_finding(self):
        # A short declared secret that is a substring of a fixed header NAME (not its
        # value) must not raise a spurious leak finding; header names carry no secrets.
        request = HttpRequest("GET", "http://127.0.0.1/x", (), None)
        context = EvaluationContext("t", "step", None, (b"kid1",))
        result = HttpResult(request, 200, (("X-Kid1-Trace", "opaque"),), b"{}", 1)
        self.assertEqual(NoDeclaredSecrets().evaluate(result, context), ())


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
        self.assertEqual(summary.targets[0].mutated_cases, 1)
        self.assertEqual(summary.targets[0].requests, 4)

    def test_finding_replays_only_consumer_request(self):
        _Handler.accept_mutation = True
        with tempfile.TemporaryDirectory() as directory:
            summary = run_project(_Project(self.base_url), options={}, target_name=None, iterations=1, run_seed=1, output_dir=Path(directory))
            replay = load_replay_requests(summary.artifacts[0])
        self.assertEqual(len(replay), 1)
        self.assertTrue(replay[0].url.endswith("/verify"))
        _Handler.accept_mutation = False

    def test_stateful_finding_reproduction_rebuilds_dynamic_capture(self):
        _Handler.accept_mutation = True
        with tempfile.TemporaryDirectory() as directory:
            summary = run_project(
                _Project(self.base_url),
                options={},
                target_name=None,
                iterations=1,
                run_seed=1,
                output_dir=Path(directory),
            )
            recipe = load_reproduction_recipe(summary.artifacts[0])
            original_signature = json.loads(summary.artifacts[0].read_text())["steps"][0]["response"]["body"]["value"]
            result = reproduce_project(_Project(self.base_url), options={}, recipe=recipe)
        reproduced_signature = result.case.steps[0].result.body.decode("utf-8")
        self.assertTrue(result.reproduced)
        self.assertEqual(result.expected_codes, frozenset({"accepted"}))
        self.assertNotEqual(original_signature, reproduced_signature)
        _Handler.accept_mutation = False

    def test_reproduction_returns_false_after_finding_is_fixed(self):
        _Handler.accept_mutation = True
        with tempfile.TemporaryDirectory() as directory:
            summary = run_project(
                _Project(self.base_url), options={}, target_name=None, iterations=1,
                run_seed=1, output_dir=Path(directory),
            )
            recipe = load_reproduction_recipe(summary.artifacts[0])
        _Handler.accept_mutation = False
        result = reproduce_project(_Project(self.base_url), options={}, recipe=recipe)
        self.assertFalse(result.reproduced)
        self.assertEqual(result.findings, ())

    def test_reproduces_every_generative_case_class(self):
        project = _FindingProject(self.base_url)
        for case_class in ("semantic", "structured", "raw", "deser"):
            mutation_name = "semantic" if case_class == "semantic" else None
            recipe = ReproductionRecipe(
                project.name,
                "synthetic.finding",
                1,
                9,
                CaseRecipe(case_class, _case_seed(9, "synthetic.finding", 1, case_class, mutation_name), mutation_name),
                frozenset({"unexpected-status"}),
            )
            result = reproduce_project(project, options={}, recipe=recipe)
            self.assertTrue(result.reproduced, case_class)

    def test_tampered_case_seed_is_rejected(self):
        # A hand-edited artifact whose case_seed no longer matches the run seed
        # derivation must be refused, not reproduced against the wrong mutation stream.
        project = _FindingProject(self.base_url)
        good = _case_seed(9, "synthetic.finding", 1, "semantic", "semantic")
        recipe = ReproductionRecipe(
            project.name,
            "synthetic.finding",
            1,
            9,
            CaseRecipe("semantic", good + 1, "semantic"),
            frozenset({"unexpected-status"}),
        )
        with self.assertRaisesRegex(ValueError, "inconsistent"):
            reproduce_project(project, options={}, recipe=recipe)

    def test_case_recipe_is_independent_of_other_target_execution(self):
        project = _MultiFindingProject(self.base_url)
        with tempfile.TemporaryDirectory() as all_directory, tempfile.TemporaryDirectory() as one_directory:
            all_summary = run_project(
                project,
                options={},
                target_name=None,
                iterations=2,
                run_seed=41,
                output_dir=Path(all_directory),
            )
            one_summary = run_project(
                project,
                options={},
                target_name="synthetic.finding",
                iterations=2,
                run_seed=41,
                output_dir=Path(one_directory),
            )
            all_recipes = [
                load_reproduction_recipe(path).case
                for path in all_summary.artifacts
                if load_reproduction_recipe(path).target == "synthetic.finding"
            ]
            one_recipes = [load_reproduction_recipe(path).case for path in one_summary.artifacts]
        self.assertEqual(all_recipes, one_recipes)

    def test_reproduces_race_and_counts_every_contender(self):
        project = _RaceProject(self.base_url)
        recipe = ReproductionRecipe(
            project.name,
            "synthetic.race",
            1,
            3,
            CaseRecipe("semantic", _case_seed(3, "synthetic.race", 1, "semantic", None)),
            frozenset({"race-finding"}),
        )
        result = reproduce_project(project, options={}, recipe=recipe)
        self.assertTrue(result.reproduced)
        self.assertEqual(len(result.case.steps), 3)
        project.report_finding = False
        with tempfile.TemporaryDirectory() as directory:
            summary = run_project(
                project, options={}, target_name=None, iterations=1,
                run_seed=3, output_dir=Path(directory),
            ).targets[0]
        self.assertEqual(summary.requests, 6)

    def test_deser_timeout_with_healthy_ready_is_not_a_dos_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            summary = run_project(
                _DeserProject(),
                options={},
                target_name=None,
                iterations=4,
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
                iterations=4,
                run_seed=7,
                output_dir=Path(directory),
                transport=_DeserTimeoutTransport(True),
            )
        self.assertEqual(summary.targets[0].deser, 1)
        self.assertEqual(summary.targets[0].findings, 1)

    def test_scheduler_covers_every_case_class_before_weighted_draws(self):
        with tempfile.TemporaryDirectory() as directory:
            summary = run_project(
                _DeserProject(), options={}, target_name=None, iterations=4, run_seed=7,
                output_dir=Path(directory), transport=_DeserTimeoutTransport(False),
            ).targets[0]
        self.assertEqual((summary.semantic, summary.structured, summary.raw, summary.deser), (1, 1, 1, 1))
        self.assertEqual(summary.required_iterations, 4)
        self.assertEqual(summary.uncovered_classes, ())

    def test_request_target_generative_false_suppresses_body_fuzzing(self):
        def _request_target(include_generative):
            return RequestTarget(
                "synthetic.request",
                frozenset({"base_url"}),
                HttpStep("encrypt", "POST", "{base_url}/encrypt", json_body_template={"value": "valid"}),
                (JsonFieldMutation("semantic", "$.value"),),
                ExpectStatus(frozenset({200})),
                include_generative=include_generative,
            )

        self.assertTrue(_target_has_body(_request_target(True)))
        self.assertFalse(_target_has_body(_request_target(False)))

    def test_scheduler_surfaces_classes_omitted_by_small_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            summary = run_project(
                _DeserProject(), options={}, target_name=None, iterations=2, run_seed=7,
                output_dir=Path(directory), transport=_DeserTimeoutTransport(False),
            ).targets[0]
        self.assertEqual((summary.semantic, summary.structured, summary.raw, summary.deser), (1, 1, 0, 0))
        self.assertEqual(summary.required_iterations, 4)
        self.assertEqual(summary.uncovered_classes, ("raw", "deser"))
