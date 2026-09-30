"""Offline regression checks and disposable loopback transport tests."""

import gzip
import hashlib
import http.client
import http.server
import json
import os
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
import io
from contextlib import contextmanager, redirect_stdout
from pathlib import Path
from unittest.mock import MagicMock, patch

from campaign import TargetMetrics
from client import FuzzClient, FuzzResponse, _DeadlineReader
from oracle import oracle
from reporting import check_and_record, describe, save_crash


class TransportTests(unittest.TestCase):
    def connection(self, send_error=None, read_error=None):
        connection = MagicMock()
        connection.request.side_effect = send_error
        response = connection.getresponse.return_value.__enter__.return_value
        response.status = 413
        response.headers = {"X-Test": "rejected"}
        response.read.return_value = b'{"error":"too large"}'
        response.read.side_effect = read_error
        return connection

    def test_normal_and_recovered_response_preserve_headers_and_single_send(self):
        for send_error in (None, BrokenPipeError(32, "private message"), ConnectionResetError(104, "private message")):
            with self.subTest(error=type(send_error).__name__):
                connection = self.connection(send_error)
                with patch("client.http.client.HTTPConnection", return_value=connection) as factory:
                    client = FuzzClient("http://localhost:3000/api", "SECRET")
                    response = client.request_with_headers("POST", "/test", b"body",
                                                           {"Content-Type": "application/json"}, auth=True)
                self.assertEqual(tuple(response), (413, '{"error":"too large"}'))
                self.assertEqual(response.headers, {"X-Test": "rejected"})
                self.assertEqual(response.request_body_bytes, 4)
                self.assertEqual(response.error_type, type(send_error).__name__ if send_error else None)
                self.assertEqual(response.transport_phase, "send" if send_error else None)
                factory.assert_called_once_with("localhost", 3000, timeout=15)
                connection.request.assert_called_once_with(
                    "POST", "/api/test", body=b"body",
                    headers={"Content-Type": "application/json", "X-API-Key": "SECRET"})
                connection.getresponse.assert_called_once()
                connection.close.assert_called_once()
                self.assertEqual(client.consume_timings(), [response])
                self.assertNotIn("private message", repr(response))

    def test_disconnect_and_incomplete_response_remain_findings(self):
        for error in (ConnectionResetError(104, "secret"), http.client.RemoteDisconnected(),
                      http.client.IncompleteRead(b"partial", 20), TimeoutError()):
            with self.subTest(error=type(error).__name__):
                connection = self.connection(BrokenPipeError(), error)
                with patch("client.http.client.HTTPConnection", return_value=connection):
                    response = FuzzClient("http://localhost", "SECRET").post_raw("/test", b"body")
                self.assertEqual(response.status, 0)
                self.assertEqual(response.body, "")
                self.assertEqual(response.error_type, type(error).__name__)
                self.assertEqual(response.transport_phase, "receive")
                self.assertTrue(oracle(0, "", "", "", {413}, False))
                connection.request.assert_called_once()
                connection.close.assert_called_once()

    def test_connection_failure_is_not_retried(self):
        connection = self.connection()
        connection.connect.side_effect = ConnectionRefusedError(111, "SECRET")
        with patch("client.http.client.HTTPConnection", return_value=connection):
            response = FuzzClient("http://localhost", "SECRET").get_status("/test")
        self.assertEqual(response, 0)
        connection.request.assert_not_called()
        connection.close.assert_called_once()

    def test_recovery_uses_remaining_deadline(self):
        now = [0.0]
        connection = self.connection()

        def send(*args, **kwargs):
            now[0] = 14.0
            raise BrokenPipeError()

        connection.request.side_effect = send
        with patch("client.http.client.HTTPConnection", return_value=connection), \
             patch("client.time.monotonic", side_effect=lambda: now[0]):
            response = FuzzClient("http://localhost", "SECRET").post_raw("/test", b"body")
        self.assertEqual(response.status, 413)
        self.assertEqual(connection.sock.settimeout.call_args.args, (1.0,))

    def test_expired_budget_does_not_start_response_read(self):
        now = [0.0]
        connection = self.connection()

        def send(*args, **kwargs):
            now[0] = 15.1
            raise BrokenPipeError()

        connection.request.side_effect = send
        with patch("client.http.client.HTTPConnection", return_value=connection), \
             patch("client.time.monotonic", side_effect=lambda: now[0]):
            response = FuzzClient("http://localhost", "SECRET").post_raw("/test", b"body")
        self.assertEqual(response.status, 0)
        self.assertEqual(response.error_type, "TimeoutError")
        connection.getresponse.assert_not_called()

    def test_response_reader_enforces_deadline_on_each_read(self):
        reader, sock = MagicMock(), MagicMock()
        reader.read1.return_value = b"a"
        deadline_reader = _DeadlineReader(reader, sock, 15)
        with patch("client.time.monotonic", return_value=14):
            self.assertEqual(deadline_reader.readinto(bytearray(2)), 1)
        with patch("client.time.monotonic", return_value=16), self.assertRaises(TimeoutError):
            deadline_reader.readinto(bytearray(2))
        reader.read1.assert_called_once()
        deadline_reader.close()

    def test_https_selects_verified_connection_and_preserves_redirect_status(self):
        connection = self.connection()
        response = connection.getresponse.return_value.__enter__.return_value
        response.status = 302
        with patch("client.http.client.HTTPSConnection", return_value=connection) as factory, \
             patch.dict(os.environ, {"HTTPS_PROXY": "http://invalid.proxy:1"}):
            result = FuzzClient("https://localhost:3443", "SECRET").request("GET", "/redirect")
        factory.assert_called_once_with("localhost", 3443, timeout=15)
        self.assertEqual(result.status, 302)
        connection.request.assert_called_once()


class ReportingTests(unittest.TestCase):
    def save(self, directory, description, **kwargs):
        with patch("reporting.CORPUS_DIR", Path(directory)):
            return save_crash("self", 1337, 13, description, ["test finding"], target_seed=17, **kwargs)

    def test_large_unicode_artifact_is_valid_and_payload_is_complete(self):
        body = "\U0001f525" * 1250000
        original = json.dumps(body).encode()
        with tempfile.TemporaryDirectory() as directory:
            artifact = self.save(directory, describe("POST", "/test", False, body))
            result = json.loads(artifact.read_text())
            metadata = result["request"]["payload"]
            stored = gzip.decompress((artifact.parent / metadata["file"]).read_bytes())
            self.assertEqual(stored, original)
            self.assertEqual(metadata["original_bytes"], 15000002)
            self.assertEqual(metadata["original_sha256"], hashlib.sha256(original).hexdigest())
            self.assertEqual(metadata["stored_sha256"], metadata["original_sha256"])
            self.assertTrue(result["request"]["preview_truncated"])
            self.assertLessEqual(len(result["request"]["body"]), 2000)
            self.assertEqual(result["format"], "http-fuzz-finding-v2")

    def test_raw_and_config_bytes_redact_before_preview(self):
        original = b"\xff" + b"a" * 1990 + b"SECRET-API" + b"SECRET-UNSEAL" + b"\x00" * 3000
        descriptions = [describe("POST", "/test", True, original),
                        {"mutated_file": "config.json", "_payload_bytes": original}]
        for description in descriptions:
            with self.subTest(kind=description.keys()), tempfile.TemporaryDirectory() as directory:
                artifact = self.save(directory, description, secrets=("SECRET-API", "SECRET-UNSEAL"))
                text = artifact.read_text()
                result = json.loads(text)
                metadata = result["request"]["payload"]
                stored = gzip.decompress((artifact.parent / metadata["file"]).read_bytes())
                self.assertTrue(metadata["redacted"])
                self.assertNotIn("SECRET", text)
                self.assertNotIn(b"SECRET", stored)
                self.assertEqual(metadata["stored_sha256"], hashlib.sha256(stored).hexdigest())
                self.assertEqual(metadata["stored_bytes"], len(stored))
                self.assertTrue(stored.startswith(b"\xff"))

    def test_actual_wire_bytes_and_diagnostics_are_recorded_without_headers(self):
        response = FuzzResponse(0, "", 12, {"X-API-Key": "SECRET"}, "receive",
                                "ConnectionResetError", 104, 4, "POST", "/test", b"null")
        with tempfile.TemporaryDirectory() as directory:
            artifact = self.save(directory, describe("POST", "/test", False, None), responses=[response])
            result = json.loads(artifact.read_text())
            evidence = result["responses"][0]
            self.assertEqual(evidence["status"], 0)
            self.assertEqual(evidence["error_type"], "ConnectionResetError")
            self.assertEqual(evidence["request_body_bytes"], 4)
            self.assertEqual(evidence["payload"], result["request"]["payload"])
            self.assertNotIn("SECRET", artifact.read_text())

    def test_existing_historical_artifact_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            historical = Path(directory) / "crash_self_1337_13.json"
            historical.write_text("unfinished")
            artifact = self.save(directory, describe("POST", "/test", True, b"body"))
            self.assertNotEqual(artifact, historical)
            self.assertEqual(historical.read_text(), "unfinished")
            json.loads(artifact.read_text())

    def test_publication_failure_propagates_and_removes_temporary_file(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch("reporting.os.replace", side_effect=OSError("write failed")):
            with self.assertRaises(OSError):
                self.save(directory, describe("POST", "/test", True, b"body"))
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_json_publication_failure_never_leaves_partial_metadata(self):
        replace = os.replace

        def publish(source, destination):
            if destination.suffix == ".json":
                raise OSError("metadata failed")
            return replace(source, destination)

        with tempfile.TemporaryDirectory() as directory, patch("reporting.os.replace", side_effect=publish):
            with self.assertRaises(OSError):
                self.save(directory, describe("POST", "/test", True, b"body"))
            files = list(Path(directory).iterdir())
            self.assertEqual([path.suffix for path in files], [".gz"])
            self.assertEqual(gzip.decompress(files[0].read_bytes()), b"body")

    def test_multiple_requests_keep_distinct_payloads_and_redact_metadata(self):
        responses = [FuzzResponse(400, "", 1, method="POST", path="/first", request_body=b"first"),
                     FuzzResponse(400, "", 2, method="POST", path="/second", request_body=b"SECRET"),
                     FuzzResponse(400, "", 3, method="POST", path="/third", request_body=b"first")]
        with tempfile.TemporaryDirectory() as directory:
            artifact = self.save(directory, {"scenario": "SECRET", "nested": b"SECRET"},
                                 responses=responses, secrets=("SECRET",))
            result = json.loads(artifact.read_text())
            self.assertEqual(len(list(artifact.parent.glob("*.gz"))), 2)
            self.assertEqual(result["responses"][0]["payload"], result["responses"][2]["payload"])
            self.assertNotIn("SECRET", artifact.read_text())
            for evidence in result["responses"]:
                stored = gzip.decompress((artifact.parent / evidence["payload"]["file"]).read_bytes())
                self.assertNotIn(b"SECRET", stored)

    def test_reset_with_healthy_server_remains_failed(self):
        from types import SimpleNamespace

        response = FuzzResponse(0, "", 1, error_type="ConnectionResetError")
        client = SimpleNamespace(consume_timings=MagicMock(side_effect=[[response], []]),
                                 get_status=lambda path: 200, declared_secrets=("SECRET",))
        args = SimpleNamespace(seed=1, liveness_every=1,
                               metrics=TargetMetrics({"name": "self", "kind": "mutation"}, 1))
        counters = {"passed": 0, "failed": 0}
        with patch("reporting.save_crash", return_value="mock.json") as save, redirect_stdout(io.StringIO()):
            check_and_record("self", client, args, 0, 0,
                             oracle(0, "", "", "", {413}, False), {}, counters)
        self.assertEqual(counters, {"passed": 0, "failed": 1})
        save.assert_called_once()

    def test_success_does_not_write_payloads(self):
        from types import SimpleNamespace

        response = FuzzResponse(413, "", 1, request_body=b"body")
        client = SimpleNamespace(consume_timings=MagicMock(side_effect=[[response], []]),
                                 get_status=lambda path: 200)
        args = SimpleNamespace(seed=1, liveness_every=1,
                               metrics=TargetMetrics({"name": "self", "kind": "mutation"}, 1))
        counters = {"passed": 0, "failed": 0}
        with patch("reporting.save_crash") as save:
            check_and_record("self", client, args, 0, 413, [], {}, counters)
        save.assert_not_called()
        self.assertEqual(counters, {"passed": 1, "failed": 0})


class _RejectingServer(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_POST(self):
        self.rfile.read(min(int(self.headers.get("Content-Length", 0)), 2 * 1024 * 1024))
        self.close_connection = True
        if self.path == "/reset":
            self.connection.shutdown(socket.SHUT_RDWR)
            return
        content = b'{"error":"too large"}'
        self.send_response(413)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Connection", "close")
        self.send_header("X-Test", "early")
        self.end_headers()
        self.wfile.write(content)

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")


@contextmanager
def loopback_server(context=None):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _RejectingServer)
    server.daemon_threads = True
    if context is not None:
        server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


class LoopbackTests(unittest.TestCase):
    def assert_upload(self, url):
        client = FuzzClient(url, "synthetic")
        for _ in range(3):
            response = client.post_json_with_headers("/reject", "\U0001f525" * 1250000)
            self.assertEqual(response.status, 413)
            self.assertEqual(response.headers["X-Test"], "early")
            self.assertEqual(client.get_status("/healthz/live"), 200)
        response = client.post_raw("/reset", b"a" * 15000000)
        self.assertEqual(response.status, 0)
        self.assertEqual(client.get_status("/healthz/live"), 200)

    def test_http_early_rejection(self):
        with loopback_server() as port:
            self.assert_upload(f"http://localhost:{port}")

    def test_https_rejection_and_certificate_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            cert, key = Path(directory) / "cert.pem", Path(directory) / "key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                            "ec_paramgen_curve:prime256v1", "-sha256", "-nodes", "-days", "1",
                            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                            "-keyout", str(key), "-out", str(cert)],
                           check=True, capture_output=True, timeout=15)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            with loopback_server(context) as port:
                url = f"https://localhost:{port}"
                response = FuzzClient(url, "synthetic").request("GET", "/healthz/live")
                self.assertEqual(response.status, 0)
                self.assertEqual(response.error_type, "SSLCertVerificationError")
                with patch.dict(os.environ, {"SSL_CERT_FILE": str(cert)}):
                    self.assert_upload(url)
