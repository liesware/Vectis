import json
from contextlib import nullcontext
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nadir.engine import run_project
from nadir.spec import load_targets
from nadir.workflows import ExpectStatus, HttpStep


FLOW = """
targets:
  - name: demo.flow
    flow:
      - step: login
        request: {method: POST, path: /login, body: {user: "{user}"}}
        capture: {token: $.token}
      - step: charge
        request: {method: POST, path: /charge, body: {token: "{token}", amount: 10}}
        fuzz: true
        mutate:
          - {json_field: $.token}
        expect: {status: [200]}
        fuzz_expect: {status: [401, 403]}
"""

VALID_TOKEN = "tok-abc"


class _Handler(BaseHTTPRequestHandler):
    accept_tampered_token = False  # vulnerable mode

    def do_GET(self):
        self._write(200, {"status": "ready"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return self._write(400, {"error": "bad json"})
        if self.path == "/login":
            return self._write(200, {"token": VALID_TOKEN})
        if self.path == "/charge":
            token = body.get("token") if isinstance(body, dict) else None
            if token != VALID_TOKEN and not self.accept_tampered_token:
                return self._write(401, {"error": "invalid session"})
            if not isinstance(body, dict) or not isinstance(body.get("amount"), (int, float)):
                return self._write(400, {"error": "bad amount"})
            return self._write(200, {"receipt": "r-1"})
        self._write(404, {"error": "missing"})

    def _write(self, status, body):
        rendered = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(rendered)))
        self.end_headers()
        self.wfile.write(rendered)

    def log_message(self, *args):
        return


class _Fixture:
    def __init__(self, base_url):
        self.base_url = base_url

    def variables(self):
        return {"base_url": self.base_url, "user": "alice"}


class _Project:
    name = "demo"

    def __init__(self, base_url):
        self.base_url = base_url

    def target_names(self):
        return ("demo.flow",)

    def fixture(self, options):
        return nullcontext(_Fixture(self.base_url))

    def healthcheck_step(self):
        return HttpStep("ready", "GET", "{base_url}/ready", expectation=ExpectStatus(frozenset({200})))

    def redaction_values(self, fixture):
        return ()

    def self_check(self):
        return ()

    def targets(self):
        return load_targets(FLOW, invariants={})


class FlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join()

    def _run(self):
        return run_project(
            _Project(self.base_url), options={}, target_name=None,
            iterations=6, run_seed=3, output_dir=Path(tempfile.mkdtemp()),
        )

    def test_secure_server_rejects_tampered_step(self):
        _Handler.accept_tampered_token = False
        summary = self._run()
        self.assertEqual(summary.targets[0].findings, 0)
        self.assertGreater(summary.targets[0].semantic, 0)

    def test_vulnerable_server_accepting_tampered_step_is_caught(self):
        _Handler.accept_tampered_token = True
        try:
            summary = self._run()
        finally:
            _Handler.accept_tampered_token = False
        self.assertGreater(summary.targets[0].findings, 0)
