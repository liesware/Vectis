import hashlib
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
    internal_messages: dict[str, str] = {}
    internal_counter = 0
    indexes: set[tuple[str, str]] = set()
    one_time_lock = threading.Lock()

    @staticmethod
    def _index_digest(profile: str, plaintext: str) -> str:
        return hashlib.sha256(f"{profile}\0{plaintext}".encode("utf-8")).hexdigest()

    @staticmethod
    def _index_item(item: object) -> tuple[str, str] | None:
        if not isinstance(item, dict) or set(item) != {"ref", "plaintext"}:
            return None
        ref, plaintext = item.get("ref"), item.get("plaintext")
        if not isinstance(ref, str) or not ref or not isinstance(plaintext, str) or not plaintext:
            return None
        return ref, plaintext

    def _auth(self, *, allow_scoped=False):
        key = self.headers.get("X-API-Key")
        if key == "test-api-key":
            return True
        if allow_scoped and key == "scoped-api-key":
            return True
        self._write(403 if key in {"denied-api-key", "scoped-api-key"} else 401, {"error": "denied"})
        return False

    def do_GET(self):
        if self.path == "/healthz/ready":
            self._write(200, {"status": "ready"})
        elif self.path == f"/keys/properties/{KID}":
            if self.headers.get("X-API-Key") == "test-api-key":
                self._write(200, {"kid": KID, "properties": {}})
            else:
                self._write(403 if self.headers.get("X-API-Key") == "denied-api-key" else 401, {"error": "denied"})
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
            if self._auth():
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
        if self.path == f"/fpe/encrypt/{KID}":
            if not self._auth(allow_scoped=True):
                return
            if body.get("profile") != "nadir-fpe-v1":
                self._write(400, {"error": "unknown profile"})
            else:
                self._write(200, {"ref": body.get("ref"), "kid": KID, "profile": body["profile"], "ciphertext": "9876543210"})
            return
        if not self._auth():
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
        if self.path == f"/message/internal/encrypt/{KID}":
            if set(body) != {"plaintext"} or not isinstance(body.get("plaintext"), str) or not body["plaintext"]:
                self._write(400, {"error": "invalid internal message request"})
                return
            type(self).internal_counter += 1
            timestamp = str(type(self).internal_counter)
            message = {
                "ctx": f"{type(self).internal_counter:032x}",
                "nonce": f"{type(self).internal_counter:024x}",
                "aad": f"version=v1;type=internal-message;kid={KID};timestamp={timestamp};cipher_alg=AES-128/GCM",
                "variant": "AES-128/GCM",
            }
            envelope = {"timestamp": timestamp, "kid": KID, "message": message}
            type(self).internal_messages[json.dumps(envelope, sort_keys=True, separators=(",", ":"))] = body["plaintext"]
            self._write(200, envelope)
            return
        if self.path == "/message/internal/decrypt":
            plaintext = type(self).internal_messages.get(json.dumps(body, sort_keys=True, separators=(",", ":")))
            if plaintext is None:
                self._write(400, {"error": "internal message authentication failed"})
            else:
                self._write(200, {"plaintext": plaintext})
            return
        if self.path == f"/mac/{KID}":
            self._write(200, {"ref": body.get("ref"), "kid": KID, "profile": body.get("profile"), "algorithm": "HMAC-SHA-256", "digest": "ab" * 32})
            return
        if self.path == "/mac/verify":
            digest = body.get("digest")
            # hex comparison is case-insensitive, like a real hex parser: a bare
            # case flip must not read as a different digest.
            matches = (
                isinstance(digest, str)
                and digest.lower() == "ab" * 32
                and body.get("plaintext") == "nadir-mac-sample-value"
            )
            self._write(200, {"ref": body.get("ref"), "valid": matches})
            return
        if self.path == f"/index/{KID}":
            item = self._index_item({"ref": body.get("ref"), "plaintext": body.get("plaintext")}) if isinstance(body, dict) and set(body) == {"ref", "profile", "plaintext"} else None
            if item is None or body.get("profile") != "nadir-mac-v1":
                self._write(400, {"error": "invalid blind index request"})
                return
            ref, plaintext = item
            digest = self._index_digest(body["profile"], plaintext)
            type(self).indexes.add((KID, digest))
            self._write(200, {"ref": ref, "kid": KID, "profile": body["profile"], "index": digest})
            return
        if self.path == "/index/verify":
            if not isinstance(body, dict) or set(body) != {"ref", "kid", "profile", "plaintext"}:
                self._write(400, {"error": "invalid blind index verify request"})
                return
            item = self._index_item({"ref": body.get("ref"), "plaintext": body.get("plaintext")})
            if item is None or body.get("kid") != KID or body.get("profile") != "nadir-mac-v1":
                self._write(400, {"error": "invalid blind index verify request"})
                return
            ref, plaintext = item
            digest = self._index_digest(body["profile"], plaintext)
            self._write(200, {"ref": ref, "kid": KID, "profile": body["profile"], "matched": (KID, digest) in type(self).indexes, "index": digest})
            return
        if self.path == f"/index/batch/{KID}":
            if not isinstance(body, dict) or set(body) != {"profile", "items"} or body.get("profile") != "nadir-mac-v1" or not isinstance(body.get("items"), list):
                self._write(400, {"error": "invalid blind index batch request"})
                return
            items = [self._index_item(item) for item in body["items"]]
            if not items or any(item is None for item in items) or len({item[0] for item in items if item is not None}) != len(items):
                self._write(400, {"error": "duplicate or invalid blind index batch ref"})
                return
            output = []
            for ref, plaintext in items:
                digest = self._index_digest(body["profile"], plaintext)
                output.append({"ref": ref, "index": digest})
            type(self).indexes.update((KID, item["index"]) for item in output)
            self._write(200, {"kid": KID, "profile": body["profile"], "items": output})
            return
        if self.path == "/index/verify/batch":
            if not isinstance(body, dict) or set(body) != {"kid", "profile", "items"} or body.get("kid") != KID or body.get("profile") != "nadir-mac-v1" or not isinstance(body.get("items"), list):
                self._write(400, {"error": "invalid blind index verify batch request"})
                return
            items = [self._index_item(item) for item in body["items"]]
            if not items or any(item is None for item in items) or len({item[0] for item in items if item is not None}) != len(items):
                self._write(400, {"error": "duplicate or invalid blind index batch ref"})
                return
            output = []
            for ref, plaintext in items:
                digest = self._index_digest(body["profile"], plaintext)
                output.append({"ref": ref, "matched": (KID, digest) in type(self).indexes, "index": digest})
            self._write(200, {"kid": KID, "profile": body["profile"], "items": output})
            return
        if self.path == f"/mask/{KID}":
            if body.get("profile") != "nadir-mask-v1":
                self._write(400, {"error": "unknown profile"})
            else:
                plaintext = body.get("plaintext", "")
                if not isinstance(plaintext, str):
                    self._write(400, {"error": "invalid masking request"})
                else:
                    self._write(200, {"ref": body.get("ref"), "kid": KID, "profile": body["profile"], "masked": "*" * max(0, len(plaintext) - 4) + plaintext[-4:]})
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
                with type(self).one_time_lock:
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
        _VectisHandler.internal_messages.clear()
        _VectisHandler.internal_counter = 0
        _VectisHandler.indexes.clear()
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
            "index_profile": "nadir-mac-v1",
            "index_ref": "nadir-index-control",
            "index_plaintext": "nadir-index-primary-value",
            "index_mutated_plaintext": "nadir-index-secondary-value",
            "index_verify_ref": "nadir-index-verify",
            "index_verify_plaintext": "nadir-index-absent-value",
            "index_batch_ref_zero": "nadir-index-batch-zero",
            "index_batch_ref_one": "nadir-index-batch-one",
            "index_batch_plaintext_zero": "nadir-index-batch-primary",
            "index_batch_plaintext_one": "nadir-index-batch-secondary",
            "index_atomic_ref_zero": "nadir-index-atomic-zero",
            "index_atomic_ref_one": "nadir-index-atomic-one",
            "index_atomic_plaintext_zero": "nadir-index-atomic-primary",
            "index_atomic_plaintext_one": "nadir-index-atomic-secondary",
            "mask_profile": "nadir-mask-v1",
            "mask_ref": "nadir-mask-control",
            "mask_plaintext": "nadir-pan-001111",
            "mask_expected": "************1111",
            "mask_policy_ref": "nadir-mask-policy",
            "mask_policy_plaintext": "nadir-pan-001111",
            "mask_visible_first": "0",
            "mask_visible_last": "4",
            "mask_char": "*",
            "token_profile": "nadir-token-v1",
            "token_token_prefix": "nadir_tok",
            "token_ref": "nadir-token-control",
            "token_plaintext": "nadir-token-plaintext",
            "token_metadata_tenant": "nadir",
            "token_once_profile": "nadir-once-v1",
            "token_once_token_prefix": "nadir_once",
            "token_once_ref": "nadir-once-control",
            "token_once_plaintext": "nadir-once-plaintext",
            "token_once_metadata_tenant": "nadir-once",
            "internal_message_plaintext": "nadir-internal-message-control",
        }
        if "NADIR_API_KEY" in os.environ:
            options["api_key"] = os.environ["NADIR_API_KEY"]
        if "NADIR_DENIED_API_KEY" in os.environ:
            options["denied_api_key"] = os.environ["NADIR_DENIED_API_KEY"]
        if "NADIR_SCOPED_API_KEY" in os.environ:
            options["scoped_api_key"] = os.environ["NADIR_SCOPED_API_KEY"]
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
        with patch.dict(os.environ, {"NADIR_API_KEY": "test-api-key", "NADIR_DENIED_API_KEY": "denied-api-key"}, clear=True):
            summary = self._run("vectis.keys")
        self.assertEqual(summary.targets[0].findings, 0)
        self.assertGreater(summary.targets[0].mutated_cases, 0)

    def test_sign_target_requires_environment_api_key_and_checks_all_segments(self):
        with patch.dict(os.environ, {"NADIR_API_KEY": "test-api-key"}, clear=True):
            summary = self._run("vectis.sign-verification")
        self.assertEqual(summary.targets[0].findings, 0)
        self.assertEqual(summary.targets[0].mutated_cases, 5)

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
                "vectis.blind-index-create",
                "vectis.blind-index-membership",
                "vectis.blind-index-batch-membership",
                "vectis.blind-index-batch-atomicity",
                "vectis.masking",
                "vectis.masking-policy",
                "vectis.internal-encrypt",
                "vectis.internal-message-round-trip",
                "vectis.token-round-trip",
                "vectis.one-time-token",
                "vectis.one-time-token-race",
                "vectis.token-randomness",
            ):
                summary = self._run(target)
                self.assertEqual(summary.targets[0].findings, 0, target)

    def test_internal_message_round_trip_uses_only_semantic_mutations(self):
        with patch.dict(os.environ, {"NADIR_API_KEY": "test-api-key"}, clear=True):
            encrypt_summary = self._run("vectis.internal-encrypt")
            round_trip_summary = self._run("vectis.internal-message-round-trip")
        self.assertEqual(encrypt_summary.targets[0].findings, 0)
        self.assertGreaterEqual(encrypt_summary.targets[0].structured, 1)
        self.assertGreaterEqual(encrypt_summary.targets[0].raw, 1)
        self.assertGreaterEqual(encrypt_summary.targets[0].deser, 1)
        self.assertEqual(round_trip_summary.targets[0].findings, 0)
        self.assertEqual(round_trip_summary.targets[0].structured, 0)
        self.assertEqual(round_trip_summary.targets[0].raw, 0)
        self.assertEqual(round_trip_summary.targets[0].deser, 0)

    def test_blind_index_targets_cover_persistence_batch_and_atomicity(self):
        with patch.dict(os.environ, {"NADIR_API_KEY": "test-api-key"}, clear=True):
            create_summary = self._run("vectis.blind-index-create")
            membership_summary = self._run("vectis.blind-index-membership")
            batch_summary = self._run("vectis.blind-index-batch-membership")
            atomicity_summary = self._run("vectis.blind-index-batch-atomicity")
        self.assertEqual(create_summary.targets[0].findings, 0)
        self.assertGreaterEqual(create_summary.targets[0].structured, 1)
        self.assertGreaterEqual(create_summary.targets[0].raw, 1)
        self.assertGreaterEqual(create_summary.targets[0].deser, 1)
        for summary in (membership_summary, batch_summary, atomicity_summary):
            self.assertEqual(summary.targets[0].findings, 0)
            self.assertEqual(summary.targets[0].structured, 0)
            self.assertEqual(summary.targets[0].raw, 0)
            self.assertEqual(summary.targets[0].deser, 0)

    def test_internal_plaintext_is_artifact_only_redaction(self):
        with self.project.fixture(
            {
                "base_url": self.base_url,
                "kid": KID,
                "api_key": "test-api-key",
                "internal_message_plaintext": "nadir-internal-message-control",
                "required_variables": frozenset({"api_key"}),
            }
        ) as fixture:
            self.assertNotIn(b"nadir-internal-message-control", self.project.redaction_values(fixture))
            self.assertIn(b"nadir-internal-message-control", self.project.artifact_redaction_values(fixture))

    def test_blind_index_plaintexts_are_response_and_artifact_redacted(self):
        with self.project.fixture(
            {
                "base_url": self.base_url,
                "kid": KID,
                "api_key": "test-api-key",
                "index_plaintext": "nadir-index-primary-value",
                "index_mutated_plaintext": "nadir-index-secondary-value",
                "required_variables": frozenset({"api_key"}),
            }
        ) as fixture:
            self.assertIn(b"nadir-index-primary-value", self.project.redaction_values(fixture))
            self.assertIn(b"nadir-index-secondary-value", self.project.redaction_values(fixture))
            self.assertIn(b"nadir-index-primary-value", self.project.artifact_redaction_values(fixture))

    def test_authorization_matrix_uses_401_and_403_per_operation(self):
        with patch.dict(os.environ, {"NADIR_API_KEY": "test-api-key", "NADIR_DENIED_API_KEY": "denied-api-key"}, clear=True):
            for target in (
                "vectis.sign-authorization",
                "vectis.fpe-encrypt-authorization",
                "vectis.mac-create-authorization",
                "vectis.blind-index-create-authorization",
                "vectis.blind-index-verify-authorization",
                "vectis.mask-authorization",
                "vectis.token-encode-authorization",
            ):
                summary = self._run(target)
                self.assertEqual(summary.targets[0].findings, 0, target)

    def test_scoped_client_can_only_execute_its_granted_operation(self):
        with patch.dict(os.environ, {"NADIR_SCOPED_API_KEY": "scoped-api-key"}, clear=True):
            for target in ("vectis.scoped-fpe-encrypt", "vectis.scoped-mac-denied"):
                summary = self._run(target)
                self.assertEqual(summary.targets[0].findings, 0, target)
