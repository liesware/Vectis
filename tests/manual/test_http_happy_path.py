"""Offline regressions for the manual tool; no Vectis process or external calls."""

import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from happy_flows import reversible, time_attestation
from happy_lab import KEY_ACTIONS, Laboratory, configuration
from happy_transport import Client, Transcript, batch_result, three_items
import http_happy_path


class Response(io.BytesIO):
    status = 200


class TransportTests(unittest.TestCase):
    def test_exchange_flushes_and_redacts_requests_and_responses(self):
        stream = Mock(wraps=io.StringIO())
        out = Transcript(stream, ["unseal-secret", "api-hash"])
        client = Client("http://127.0.0.1:1234", "api-secret", out)
        opener = Mock()
        opener.open.return_value = Response(b'{"echo":"api-secret unseal-secret api-hash"}')
        with patch("happy_transport.urllib.request.build_opener", return_value=opener):
            client.call("POST", "/example", {"synthetic": True})
        output = stream.getvalue()
        for secret in ("api-secret", "unseal-secret", "api-hash"):
            self.assertNotIn(secret, output)
        self.assertIn("### POST /example", output)
        self.assertIn("Response: HTTP 200", output)
        self.assertIn("Result: OK", output)
        self.assertGreater(stream.flush.call_count, 0)
        self.assertEqual(client.completed, 1)

    def test_response_failure_never_counts_as_success(self):
        out = Transcript(io.StringIO())
        client = Client("http://127.0.0.1:1234", "secret", out)
        opener = Mock()
        opener.open.return_value = Response(b'{}')
        with patch("happy_transport.urllib.request.build_opener", return_value=opener):
            with self.assertRaisesRegex(RuntimeError, "contract failed"):
                client.call("GET", "/example", check=lambda _: (_ for _ in ()).throw(RuntimeError("contract failed")))
        self.assertEqual(client.completed, 0)
        self.assertIn("FAILED", out.stream.getvalue())

    def test_batch_requires_three_distinct_refs_and_preserves_order(self):
        inputs = [{"ref": str(i)} for i in range(3)]
        self.assertEqual(three_items(inputs), inputs)
        for bad in (inputs[:2], inputs + [{"ref": "3"}], [inputs[0]] * 3):
            with self.assertRaises(RuntimeError):
                three_items(bad)
        with self.assertRaisesRegex(RuntimeError, "order"):
            batch_result({"kid": "kid", "profile": "profile", "items": inputs[::-1]}, inputs, "kid", "profile")

    def test_markdown_cannot_be_closed_by_response_content(self):
        out = Transcript(io.StringIO())
        block = out.block("```\n### hostile content", "text")
        self.assertTrue(block.startswith("````text\n"))
        self.assertTrue(block.endswith("\n````"))


class FlowTests(unittest.TestCase):
    def test_decode_uses_captured_fresh_fpe_ciphertext_and_tag(self):
        kid, subject = "a" * 64, "b" * 64
        profile = "manual-fpe-stored"
        calls = []

        def call(method, path, body, **options):
            calls.append((method, path, body))
            if "/encrypt/batch/" in path:
                result = {"kid": kid, "profile": profile, "subject": subject,
                          "items": [{"ref": item["ref"], "ciphertext": f"cipher-{i}", "tag": f"tag-{i}"}
                                    for i, item in enumerate(body["items"])]}
            elif "/encrypt/" in path:
                result = {"kid": kid, "profile": profile, "subject": subject,
                          "ref": body["ref"], "ciphertext": "fresh-cipher", "tag": "fresh-tag"}
            elif path.endswith("/batch"):
                result = {"kid": kid, "profile": profile,
                          "items": [{"ref": item["ref"], "plaintext": text} for item, text in
                                    zip(body["items"], ("001-234-567", "002-345-678", "003-456-789"))]}
            else:
                result = {"ref": body["ref"], "plaintext": "001-234-567"}
            if options.get("check"):
                options["check"](result)
            return result

        reversible(Mock(call=call), kid, "fpe", subject)
        self.assertEqual(calls[1][2]["ciphertext"], "fresh-cipher")
        self.assertEqual(calls[1][2]["tag"], "fresh-tag")
        self.assertEqual(calls[1][2]["subject"], subject)
        self.assertEqual([item["ciphertext"] for item in calls[3][2]["items"]],
                         ["cipher-0", "cipher-1", "cipher-2"])
        self.assertEqual(len(calls[2][2]["items"]), 3)

    def test_single_client_single_kid_and_subject_policy(self):
        config = configuration("a" * 64, "hash")
        self.assertEqual(len(config["permissions"]), 1)
        grants = config["permissions"][0]["permissions"]
        self.assertEqual(grants[0]["kid"], "a" * 64)
        self.assertNotIn("admin", KEY_ACTIONS)
        self.assertNotIn("message", KEY_ACTIONS)
        self.assertTrue(all("metrics" not in grant["actions"] for grant in grants))
        for section, profiles in config.items():
            if section.endswith("_profiles"):
                self.assertTrue(all(profile["kid"] == "a" * 64 for profile in profiles))
        self.assertEqual({p["subject_mode"] for p in config["tokenization_profiles"]}, {"none", "stored"})

    def test_live_time_rejects_incomplete_response(self):
        with self.assertRaises(RuntimeError):
            time_attestation({"version": "vectis-time-attestation-v1", "provider": "cloudflare", "sources": {}})

    def test_live_time_allows_unacceptable_but_authenticated_clock(self):
        payload = {
            "version": "vectis-time-attestation-v1", "provider": "cloudflare",
            "sources": {
                "system": {"unix_us": "123"},
                "nts": {"authenticated": True, "server": "time.cloudflare.com",
                        "offset_us": "1", "round_trip_us": "2"},
                "roughtime": {"verified": True, **dict.fromkeys(
                    ("midpoint_us", "radius_us", "earliest_us", "latest_us", "nonce_b64", "response_b64"), "synthetic")},
            },
            "server_clock": {"acceptable": False, "max_allowed_skew_ms": 1000,
                             "local_vs_nts_skew_ms": 2000.0,
                             "local_within_roughtime_interval": False,
                             "nts_within_roughtime_interval": True},
        }
        time_attestation(payload)


class LaboratoryTests(unittest.TestCase):
    def test_cleanup_terminates_and_waits_for_process(self):
        with tempfile.TemporaryDirectory() as temp:
            lab = Laboratory.__new__(Laboratory)
            lab.path = Path(temp) / "lab"
            lab.path.mkdir()
            lab.keep = False
            lab.out = Transcript(io.StringIO())
            process = Mock()
            process.poll.return_value = None
            process.wait.side_effect = [subprocess.TimeoutExpired("vectis", 35), 0]
            lab.process = process
            log = Mock()
            lab.log = log
            lab.close(True)
            process.terminate.assert_called_once()
            process.kill.assert_called_once()
            self.assertEqual(process.wait.call_count, 2)
            log.close.assert_called_once()
            self.assertFalse(lab.path.exists())

    def test_failure_still_closes_lab_and_returns_nonzero(self):
        lab = Mock()
        lab.path = Path("/tmp/mock-lab")
        lab.url = "http://127.0.0.1:1234"
        lab.api_key = "secret"
        with patch("http_happy_path.Laboratory", return_value=lab), \
             patch("http_happy_path.prepare", side_effect=RuntimeError("broken setup")):
            output = io.StringIO()
            self.assertEqual(http_happy_path.execute("vectis", stream=output), 1)
        lab.close.assert_called_once_with(False)
        self.assertIn("Result: FAILED", output.getvalue())

    def test_failure_retains_lab_even_without_keep_flag(self):
        with tempfile.TemporaryDirectory() as temp:
            lab = Laboratory.__new__(Laboratory)
            lab.path = Path(temp)
            lab.keep = False
            lab.process = lab.log = None
            lab.out = Transcript(io.StringIO())
            lab.close(False)
            self.assertTrue(lab.path.is_dir())
            self.assertIn("Laboratory retained", lab.out.stream.getvalue())


if __name__ == "__main__":
    unittest.main()
