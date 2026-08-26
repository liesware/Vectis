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
    one_time_tokens: set[str] = set()
    token_counter = 0
    issued_tokens: dict[str, str] = {}

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
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        try:
            body = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._write(400, {"error": "invalid request"})
            return
        if self.path == f"/sign/{KID}":
            if self.headers.get("X-API-Key") != "test-api-key":
                self._write(403, {"error": "denied"})
            else:
                self._write(200, {"kid": KID, "signature": "aaaa.bbbb.cccc.dddd"})
            return
        if self.path == "/sign/verification":
            try:
                signature = body["signature"].split(".")
            except (KeyError, AttributeError, TypeError):
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
        if self.headers.get("X-API-Key") != "test-api-key":
            self._write(403, {"error": "denied"})
            return
        if self.path == f"/fpe/encrypt/{KID}":
            if body.get("profile") != "nadir-fpe-v1":
                self._write(400, {"error": "unknown profile"})
            else:
                self._write(200, {"ref": body.get("ref"), "kid": KID, "profile": body["profile"], "ciphertext": "9876543210"})
            return
        if self.path == "/fpe/decrypt":
            if body.get("profile") != "nadir-fpe-v1":
                self._write(400, {"error": "unknown profile"})
            elif body.get("ciphertext") == "9876543210":
                self._write(200, {"ref": body.get("ref"), "plaintext": "1234567890"})
            else:
                # unauthenticated FF1: a tampered ciphertext decrypts to other bytes
                self._write(200, {"ref": body.get("ref"), "plaintext": "0000000000"})
            return
        if self.path == f"/mac/{KID}":
            self._write(200, {"ref": body.get("ref"), "kid": KID, "profile": body.get("profile"), "algorithm": "HMAC-SHA-256", "digest": "ab" * 32})
            return
        if self.path == "/mac/verify":
            digest = body.get("digest")
            # hex comparison is case-insensitive, like a real hex parser: a bare
            # case flip must not read as a different digest.
            matches = isinstance(digest, str) and digest.lower() == "ab" * 32
            self._write(200, {"ref": body.get("ref"), "valid": matches})
            return
        if self.path == f"/mask/{KID}":
            if body.get("profile") != "nadir-mask-v1":
                self._write(400, {"error": "unknown profile"})
            else:
                self._write(200, {"ref": body.get("ref"), "kid": KID, "profile": body["profile"], "masked": "************1111"})
            return
        if self.path == f"/token/encode/{KID}":
            profile = body.get("profile")
            if profile not in {"nadir-token-v1", "nadir-once-v1"}:
                self._write(400, {"error": "unknown profile"})
                return
            type(self).token_counter += 1
            prefix = "nadir_tok" if profile == "nadir-token-v1" else "nadir_once"
            token = f"{prefix}_synthetic{type(self).token_counter:04d}"
            type(self).issued_tokens[token] = profile
            if profile == "nadir-once-v1":
                type(self).one_time_tokens.add(token)
            self._write(200, {"ref": body.get("ref"), "kid": KID, "profile": profile, "token": token})
            return
        if self.path == "/token/decode":
            profile, token = body.get("profile"), body.get("token")
            expected_prefix = "nadir_tok_" if profile == "nadir-token-v1" else "nadir_once_" if profile == "nadir-once-v1" else None
            if not isinstance(token, str) or expected_prefix is None:
                self._write(400, {"error": "invalid token request"})
            elif not token.startswith(expected_prefix) or type(self).issued_tokens.get(token) != profile:
                self._write(404, {"error": "token not found"})
            elif profile == "nadir-once-v1":
                if token not in type(self).one_time_tokens:
                    self._write(404, {"error": "token not found"})
                else:
                    type(self).one_time_tokens.remove(token)
                    self._write(200, {"ref": body.get("ref"), "plaintext": "nadir-once-plaintext", "metadata": {"tenant": "nadir-once"}})
            else:
                self._write(200, {"ref": body.get("ref"), "plaintext": "nadir-token-plaintext", "metadata": {"tenant": "nadir"}})
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
        _VectisHandler.one_time_tokens.clear()
        _VectisHandler.issued_tokens.clear()
        _VectisHandler.token_counter = 0
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _VectisHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"
        cls.project = load_project(Path(__file__).resolve().parents[1] / "projects/vectis/project.py")

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join()

    def _run(self, target, drop=()):
        options = {
            "base_url": self.base_url,
            "kid": KID,
            "digest": "aa" * 32,
            "fpe_profile": "nadir-fpe-v1",
            "fpe_ref": "nadir-fpe-control",
            "fpe_plaintext": "1234567890",
            "mac_profile": "nadir-mac-v1",
            "mac_ref": "nadir-mac-control",
            "mac_plaintext": "nadir-mac-sample-value",
            "mask_profile": "nadir-mask-v1",
            "mask_ref": "nadir-mask-control",
            "mask_plaintext": "nadir-pan-001111",
            "mask_expected": "************1111",
            "token_profile": "nadir-token-v1",
            "token_ref": "nadir-token-control",
            "token_plaintext": "nadir-token-plaintext",
            "token_metadata_tenant": "nadir",
            "token_once_profile": "nadir-once-v1",
            "token_once_ref": "nadir-once-control",
            "token_once_plaintext": "nadir-once-plaintext",
            "token_once_metadata_tenant": "nadir-once",
        }
        if "NADIR_API_KEY" in os.environ:
            options["api_key"] = os.environ["NADIR_API_KEY"]
        for key in drop:
            options.pop(key, None)
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

    def test_masking_missing_expected_variable_fails_at_setup(self):
        with patch.dict(os.environ, {"NADIR_API_KEY": "test-api-key"}, clear=True):
            with self.assertRaises(SetupFailure) as raised:
                self._run("vectis.masking", drop=("mask_expected",))
        self.assertIn("mask_expected", str(raised.exception))

    def test_profile_and_token_targets_hold_their_control_contracts(self):
        with patch.dict(os.environ, {"NADIR_API_KEY": "test-api-key"}, clear=True):
            for target in (
                "vectis.fpe-round-trip",
                "vectis.fpe-ciphertext",
                "vectis.mac-verification",
                "vectis.masking",
                "vectis.token-round-trip",
                "vectis.one-time-token",
            ):
                summary = self._run(target)
                self.assertEqual(summary.targets[0].findings, 0, target)
