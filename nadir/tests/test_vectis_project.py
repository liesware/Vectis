import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nadir.engine import run_project
from nadir.engine import SetupFailure
from nadir.project import load_project


KID = "a" * 64
PUBLIC_RESPONSE = {
    "info": "version=v1;type=ops-keys",
    "keys": {
        "eddsa": {"alg": "Ed25519", "public_key_der_hex": "aa"},
        "xecdh": {"alg": "X25519", "public_key_hex": "bb"},
        "ml-dsa": {"alg": "ML-DSA-44", "public_key_der_hex": "cc"},
        "ml-kem": {"alg": "ML-KEM-512", "public_key_der_hex": "dd"},
    },
}


class _VectisHandler(BaseHTTPRequestHandler):
    public_auth_headers: list[str] = []

    def do_GET(self):
        if self.path == "/healthz/ready":
            self._write(200, {"status": "ready"})
        elif self.path == f"/keys/properties/{KID}":
            if self.headers.get("X-API-Key") == "test-api-key":
                self._write(200, {"kid": KID, "properties": {}})
            else:
                self._write(401, {"error": "denied"})
        elif self.path == f"/pub/{KID}":
            if self.headers.get("Authorization"):
                self.public_auth_headers.append(self.headers["Authorization"])
            self._write(200, PUBLIC_RESPONSE)
        else:
            self._write(400, {"error": "invalid kid"})

    def do_POST(self):
        if self.path == f"/sign/{KID}":
            if self.headers.get("X-API-Key") != "test-api-key":
                self._write(403, {"error": "denied"})
            else:
                self._write(200, {"kid": KID, "signature": "aaaa.bbbb.cccc.dddd"})
            return
        if self.path == "/sign/verification":
            raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            try:
                body = json.loads(raw)
                signature = body["signature"].split(".")
            except (json.JSONDecodeError, UnicodeDecodeError, KeyError, AttributeError, TypeError):
                self._write(400, {"error": "malformed verification request"})
                return
            mutated = next((index for index, value in enumerate(signature) if value.startswith("A")), None)
            if mutated is None:
                self._write(200, {"valid": "ok", "status": {"eddsa": "ok", "ml-dsa": "ok"}})
            elif mutated == 2:
                self._write(200, {"valid": "fail", "status": {"eddsa": "fail", "ml-dsa": "ok"}})
            else:
                self._write(200, {"valid": "fail", "status": {"eddsa": "not_checked", "ml-dsa": "fail"}})
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


class VectisProjectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _VectisHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"
        cls.project = load_project(Path(__file__).resolve().parents[1] / "projects/vectis/project.py")

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join()

    def _run(self, target):
        options = {"base_url": self.base_url, "kid": KID, "digest": "aa" * 32}
        if "NADIR_API_KEY" in os.environ:
            options["api_key"] = os.environ["NADIR_API_KEY"]
        return run_project(
            self.project,
            options=options,
            target_name=target,
            iterations=5,
            run_seed=2,
            output_dir=Path(tempfile.mkdtemp()),
        )

    def test_public_key_target_needs_no_api_key(self):
        _VectisHandler.public_auth_headers.clear()
        with patch.dict(os.environ, {}, clear=True):
            summary = self._run("vectis.public-keys")
        self.assertEqual(summary.targets[0].findings, 0)
        self.assertEqual(_VectisHandler.public_auth_headers, [])

    def test_key_properties_target_rejects_mutated_api_keys(self):
        with patch.dict(os.environ, {"NADIR_API_KEY": "test-api-key"}, clear=True):
            summary = self._run("vectis.keys")
        self.assertEqual(summary.targets[0].findings, 0)
        self.assertGreater(summary.targets[0].expected_rejections, 0)

    def test_sign_target_requires_environment_api_key_and_checks_all_segments(self):
        with patch.dict(os.environ, {"NADIR_API_KEY": "test-api-key"}, clear=True):
            summary = self._run("vectis.sign-verification")
        self.assertEqual(summary.targets[0].findings, 0)
        self.assertEqual(summary.targets[0].expected_rejections, 5)

    def test_sign_target_fails_before_requests_without_api_key(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(SetupFailure):
                self._run("vectis.sign-verification")
