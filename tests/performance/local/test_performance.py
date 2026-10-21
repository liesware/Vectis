"""Offline contracts for CLI selection, fixtures, resources and process cleanup."""

import contextlib
import copy
import csv
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from options import parse_options, PROFILES, TARGETS, duration_seconds
from catalog import CATALOG, PROFILE_SPECS, validate_catalog
from provision import profiles_config, build_fixtures
from laboratory import Laboratory
from processes import command, stop_process
from resources import ResourceSampler, cpu_seconds
import runner


class CatalogTests(unittest.TestCase):
    def test_profiles_and_target_order_match_pre_refactor_contract(self):
        baseline = json.loads((Path(__file__).resolve().parents[1] / "lib/regression.json").read_text())
        self.assertEqual(list(PROFILES), baseline["profiles"])
        self.assertEqual(list(TARGETS[1:]), baseline["targets"])

    def test_rejects_invalid_and_inconsistent_catalogs(self):
        invalid = []
        for field in ("profiles", "targets"):
            value = copy.deepcopy(CATALOG)
            value[field] = []
            invalid.append(value)
        for change in ({"batch": "true"}, {"operations": ["flow"]}, {"name": "unexpected"}):
            value = copy.deepcopy(CATALOG)
            value["targets"][0].update(change)
            invalid.append(value)
        value = copy.deepcopy(CATALOG)
        value["targets"][1]["subject"] = False
        invalid.append(value)
        value = copy.deepcopy(CATALOG)
        value["profiles"][1]["slug"] = value["profiles"][0]["slug"]
        invalid.append(value)
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_catalog(value)


class OptionsTests(unittest.TestCase):
    def parse(self, args=(), env=None):
        return parse_options(args, {} if env is None else env)

    def reject(self, args=(), env=None):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.parse(args, env)

    def test_defaults(self):
        args = self.parse()
        self.assertEqual((args.target, args.crypto_profile, args.batch_size, args.vusr, args.iterations),
                         ("all", "all", 3, 1, 4))
        self.assertFalse(args.save_results)

    def test_save_results_is_explicit_and_duplicate_flags_are_rejected(self):
        self.assertTrue(self.parse(["--save-results"]).save_results)
        self.reject(["--save-results", "--save-results"])

    def test_flags_override_environment_without_conflicting_load_modes(self):
        args = self.parse(["--target", "fpe-batch", "--vusr", "7", "--duration", "1m30s"],
                          {"K6_TARGET": "sign", "K6_VUS": "99", "K6_ITERATIONS": "8", "K6_BATCH_SIZE": "4"})
        self.assertEqual((args.target, args.vusr, args.duration_seconds, args.iterations, args.batch_size),
                         ("fpe-batch", 7, 90, None, 4))
        self.assertIsNone(self.parse(["--iterations", "2"], {"K6_DURATION": "1s"}).duration)

    def test_duplicates_unknown_flags_and_bad_values(self):
        for args in (["--target", "sign", "--target=sign"], ["--vusr", "0"], ["--vus", "2"],
                     ["--duration", "0s"], ["--duration", "NaNs"], ["--duration", "1"],
                     ["--iterations", "-1"], ["--duration", "1s", "--iterations", "1"],
                     ["--target", "fpe-batch", "--batch-size", "129"]):
            self.reject(args)
        self.reject(env={"K6_DURATION": "1s", "K6_ITERATIONS": "1"})
        self.reject(env={"K6_P95_MS": "nan"})

    def test_incompatible_options(self):
        for args in (["--subject"], ["--authenticated"], ["--batch-size", "3"],
                     ["--target", "mac", "--subject"], ["--target", "token", "--authenticated"],
                     ["--target", "sign", "--batch-size", "1"]):
            self.reject(args)

    def test_vusr_cannot_exceed_iterations(self):
        self.reject(["--vusr", "8"])
        self.reject(["--vusr", "5", "--iterations", "4"])
        self.reject(env={"K6_VUS": "8"})
        self.assertEqual(self.parse(["--vusr", "4"]).vusr, 4)
        self.assertEqual(self.parse(["--vusr", "8", "--duration", "1s"]).vusr, 8)

    def test_invalid_options_do_not_build_or_create_laboratory(self):
        with patch.object(runner, "command") as command, patch.object(Path, "mkdir") as mkdir:
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                runner.main(["--target", "missing"])
        command.assert_not_called()
        mkdir.assert_not_called()


class FixtureTests(unittest.TestCase):
    def test_fixture_names_are_the_exact_signed_profile_names(self):
        app = {spec["kid_env"]: str(i) * 64 for i, spec in enumerate(PROFILE_SPECS)}
        app.update(K6_CLIENT="test", K6_APIKEY_HASH="a" * 64,
                   K6_BASE_URL="http://loopback", K6_APIKEY="secret")
        config, fixtures = build_fixtures(app)
        self.assertEqual(fixtures["version"], 1)
        for suite in fixtures["profiles"].values():
            for family, section in (("fpe", "fpe_profiles"), ("token", "tokenization_profiles"),
                                    ("token-deterministic", "deterministic_tokenization_profiles"),
                                    ("mac", "mac_profiles"), ("index", "mac_profiles"),
                                    ("masking", "masking_profiles"), ("commitment", "commitment_profiles"),
                                    ("sharing", "sharing_profiles")):
                names = suite["profiles"][family]
                for name in names.values() if isinstance(names, dict) else [names]:
                    self.assertTrue(any(p["name"] == name and p["kid"] == suite["kid"]
                                        for p in config[section]))

    def test_single_kid_provisions_only_that_profile(self):
        spec = PROFILE_SPECS[2]
        app = {spec["kid_env"]: "c" * 64, "K6_CLIENT": "test", "K6_APIKEY_HASH": "a" * 64,
               "K6_BASE_URL": "http://loopback", "K6_APIKEY": "secret"}
        config, fixtures = build_fixtures(app)
        self.assertEqual(list(fixtures["profiles"]), [spec["name"]])
        self.assertEqual(len(config["fpe_profiles"]), 4)
        self.assertEqual(len(config["deterministic_tokenization_profiles"]), 2)
        self.assertEqual([g["kid"] for g in config["permissions"][0]["permissions"]], ["c" * 64, "*"])

    def test_missing_kid_is_rejected(self):
        with self.assertRaises(ValueError):
            build_fixtures({"K6_CLIENT": "test", "K6_APIKEY_HASH": "a" * 64,
                            "K6_BASE_URL": "http://loopback", "K6_APIKEY": "secret"})

    def test_equivalent_limits_four_kids_and_explicit_grants(self):
        app = {spec["kid_env"]: str(i) * 64 for i, spec in enumerate(PROFILE_SPECS)}
        app.update(K6_CLIENT="test", K6_APIKEY_HASH="a" * 64,
                   K6_BASE_URL="http://loopback", K6_APIKEY="secret")
        config = profiles_config(app)
        self.assertEqual(len(config["fpe_profiles"]), 16)
        for kid in app.values():
            profiles = [p for p in config["fpe_profiles"] if p["kid"] == kid]
            if profiles:
                self.assertEqual({(p["subject_mode"], p["authenticated"]) for p in profiles},
                                 {("none", False), ("none", True), ("stored", False), ("stored", True)})
        self.assertTrue(all(p["one_time"] is False for p in config["tokenization_profiles"]))
        self.assertEqual({p["max_plaintext_len"] for p in config["tokenization_profiles"]}, {128})
        self.assertEqual(len(config["deterministic_tokenization_profiles"]), 8)
        actions = config["permissions"][0]["permissions"][0]["actions"]
        self.assertIn("subject-create", actions)
        self.assertIn("token-deterministic-decode", actions)
        self.assertNotIn("admin", actions)


class ResourceTests(unittest.TestCase):
    def test_cpu_time_formats_on_linux_and_macos(self):
        self.assertEqual(cpu_seconds("01:02.50"), 62.5)
        self.assertEqual(cpu_seconds("02:01:02"), 7262)
        self.assertEqual(cpu_seconds("1-02:01:02"), 93662)

    def test_csv_samples_target_pid_and_cpu_delta(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "samples.csv"
            with patch("resources.process_sample", side_effect=[(1000, 1), (2000, 1.1)]) as sample:
                sampler = ResourceSampler(123, path)
                sampler.start()
                sampler.stop()
            with path.open() as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(len(rows), 2)
            self.assertEqual(float(rows[-1]["rss_bytes"]), 2000)
            self.assertTrue(float(rows[-1]["cpu_percent_one_core"]) >= 0)
            self.assertTrue(all(call.args == (123,) for call in sample.call_args_list))
            summary = sampler.summary()
            self.assertEqual(summary["rss_peak_bytes"], 2000)
            self.assertEqual(summary["rss_delta_bytes"], 1000)
            self.assertAlmostEqual(summary["cpu_seconds_delta"], .1)

    def test_sampling_without_csv_keeps_only_incremental_aggregates(self):
        with patch("resources.process_sample", side_effect=[(1000, 1), (3000, 1.5)]), \
             patch.object(Path, "open") as opened:
            sampler = ResourceSampler(123)
            sampler.start()
            sampler.stop()
        opened.assert_not_called()
        self.assertEqual(sampler.summary()["samples"], 2)
        self.assertEqual(sampler.summary()["rss_peak_bytes"], 3000)
        self.assertEqual(sampler.summary()["cpu_seconds_delta"], .5)

    def test_cleanup_kills_group_after_grace_and_reaps(self):
        process = Mock(pid=123)
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired("vectis", 35), 0]
        with patch("processes.os.killpg") as kill:
            stop_process(process)
        self.assertEqual(kill.call_count, 2)
        self.assertEqual(process.wait.call_count, 2)

    def test_sampler_reports_output_failure_instead_of_silently_succeeding(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch("resources.process_sample", return_value=(1000, 1)):
                sampler = ResourceSampler(123, Path(temp) / "missing" / "resources.csv")
                sampler.start()
                sampler.stop()
            self.assertEqual(len(sampler.errors), 1)

    def test_interrupted_command_always_stops_its_group(self):
        process = Mock()
        process.wait.side_effect = KeyboardInterrupt
        with patch("processes.subprocess.Popen", return_value=process), patch("processes.stop_process") as stop:
            with self.assertRaises(KeyboardInterrupt):
                command(["fake"])
        stop.assert_called_once_with(process)

    def test_measured_k6_inherits_terminal_descriptors(self):
        process = Mock()
        process.wait.return_value = 0
        process.poll.return_value = 0
        with patch("runner.subprocess.Popen", return_value=process) as popen:
            self.assertEqual(runner.run_measured_k6({}), 0)
        self.assertIsNone(popen.call_args.kwargs["stdout"])
        self.assertIsNone(popen.call_args.kwargs["stderr"])
        self.assertNotIn("stdin", popen.call_args.kwargs)


class LaboratoryTests(unittest.TestCase):
    def test_prepare_provisions_only_the_measured_profile(self):
        with tempfile.TemporaryDirectory() as temp:
            site = Path(temp) / "run/standard"
            lab = Laboratory(site, Path("vectis"), {}, PROFILES[1])
            seen = []

            def run(args, *, env=None, stdout=None, **_):
                seen.append(env["K6_PROFILE"])
                if args[-1].endswith("configure-config.sh"):
                    site.mkdir(parents=True, exist_ok=True)
                    (site / "fixtures.json").write_text(json.dumps({"version": 1, "profiles": {}}))
                return 0

            with patch("laboratory.command", side_effect=run):
                lab.prepare()
            self.assertEqual(seen, [PROFILES[1]] * 3)

    def test_close_handles_partial_setup_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temp:
            lab = Laboratory(Path(temp), Path("vectis"), {}, PROFILES[0])
            with patch("laboratory.stop_process") as stop:
                first = lab.close()
                self.assertIs(first, lab.close())
            stop.assert_called_once_with(None)
            self.assertEqual(first, {"audit_exit": None, "cleanup_errors": []})

    def test_audit_failure_still_stops_server_and_closes_log(self):
        with tempfile.TemporaryDirectory() as temp:
            site = Path(temp)
            (site / "logs").mkdir()
            (site / "logs/audit.jsonl").touch()
            lab = Laboratory(site, Path("vectis"), {}, PROFILES[0])
            lab.env = {}
            lab.server, lab.log = Mock(), Mock()
            with patch("laboratory.stop_process") as stop, patch("laboratory.command", side_effect=RuntimeError):
                result = lab.close()
            stop.assert_called_once_with(lab.server)
            lab.log.close.assert_called_once()
            self.assertIn("offline audit verification could not complete", result["cleanup_errors"])

    def test_stop_error_does_not_skip_audit(self):
        with tempfile.TemporaryDirectory() as temp:
            site = Path(temp)
            (site / "logs").mkdir()
            (site / "logs/audit.jsonl").touch()
            lab = Laboratory(site, Path("vectis"), {}, PROFILES[0])
            lab.env = {}
            with patch("laboratory.stop_process", side_effect=RuntimeError), \
                 patch("laboratory.command", return_value=0) as audit:
                result = lab.close()
            audit.assert_called_once()
            self.assertEqual(result["audit_exit"], 0)
            self.assertIn("could not stop laboratory server", result["cleanup_errors"])

    def test_each_phase_failure_closes_lab_and_preserves_initial_error(self):
        for phase in ("prepare", "start", "warmup", "measurement", "audit", "sampler", "ok"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temp:
                here = Path(temp)
                site = here / "site/run/performance"
                lab = Mock(fixture_path=site / "fixtures.json", pid=123)
                def prepare():
                    (site / "logs").mkdir(parents=True)
                    if phase == "prepare":
                        raise RuntimeError("initial prepare failure")
                lab.prepare.side_effect = prepare
                lab.sizes.return_value = {"db": 0, "-wal": 0, "-shm": 0}
                if phase == "start":
                    lab.start.side_effect = RuntimeError("initial start failure")
                lab.close.return_value = ({"audit_exit": 0, "cleanup_errors": []} if phase == "ok" else
                                          {"audit_exit": 1, "cleanup_errors": ["audit failed"]})
                sampler = Mock(errors=[])
                sampler.summary.return_value = {"samples": 0}
                if phase == "sampler":
                    sampler.stop.side_effect = RuntimeError("sampler failure")
                with patch.object(runner, "HERE", here), patch("runner.Laboratory", return_value=lab), \
                     patch("runner.ResourceSampler", return_value=sampler), \
                     patch("runner.command", side_effect=RuntimeError("initial warmup failure") if phase == "warmup" else None), \
                     patch("runner.run_measured_k6", side_effect=KeyboardInterrupt if phase == "measurement" else None,
                           return_value=0), contextlib.redirect_stdout(io.StringIO()), \
                     contextlib.redirect_stderr(io.StringIO()):
                    result = runner.run_profile(parse_options(["--target", "fpe"], {}), 0,
                                                Path("vectis"), "run", {})
                if phase == "ok":
                    self.assertEqual(result["status"], "ok")
                    baseline = json.loads((Path(__file__).resolve().parents[1] / "lib/regression.json").read_text())
                    self.assertEqual(set(result), set(baseline["profile_fields"]))
                else:
                    self.assertEqual(result["status"], "failed")
                    expected = {"prepare": "initial prepare failure", "start": "initial start failure",
                                "warmup": "initial warmup failure", "measurement": "interrupted",
                                "audit": "audit failed", "sampler": "resource sampler cleanup failed"}[phase]
                    self.assertEqual(result["error"], expected)
                lab.close.assert_called_once()
                if phase in ("measurement", "audit", "sampler", "ok"):
                    sampler.stop.assert_called_once()
                self.assertTrue(site.exists())


class PersistenceTests(unittest.TestCase):
    def run_fake_campaign(self, base, *, save=False, failed=False):
        here = base / "local"
        previous = here / "site/older-run"
        previous.mkdir(parents=True)
        (previous / "preserve").write_text("old lab")

        def captured(args, **kwargs):
            if args[:2] == ["git", "rev-parse"]:
                return "commit\n"
            if args[0] == "git":
                return ""
            if args[0] == "k6":
                return "k6 test"
            if args[0] == "cargo":
                return json.dumps({"target_directory": str(base / "target")})
            return '{"version":"test"}'

        def profile(args, index, binary, run_id, environment, **kwargs):
            site = here / "site" / run_id / "performance"
            site.mkdir(parents=True)
            (site / "secret").write_text("synthetic private lab")
            return {"status": "failed" if failed else "ok", "laboratory": str(site)}

        argv = ["--crypto-profile", PROFILES[0]] + (["--save-results"] if save else [])
        with patch.dict(os.environ, {}, clear=True), patch.object(runner, "HERE", here), \
             patch("runner.shutil.which", return_value="k6"), patch("runner.command", return_value=0), \
             patch("runner.subprocess.check_output", side_effect=captured), \
             patch("runner.platform.platform", return_value="test-platform"), \
             patch("runner.platform.processor", return_value="test-cpu"), \
             patch("runner.run_profile", side_effect=profile), contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            code = runner.main(argv)
        self.assertTrue((previous / "preserve").exists())
        return here, code

    def test_default_success_removes_owned_lab_without_creating_results(self):
        with tempfile.TemporaryDirectory() as temp:
            here, code = self.run_fake_campaign(Path(temp))
            self.assertEqual(code, 0)
            self.assertFalse((here / "results").exists())
            self.assertEqual([p.name for p in (here / "site").iterdir()], ["older-run"])

    def test_default_failure_preserves_lab_but_creates_no_reports(self):
        with tempfile.TemporaryDirectory() as temp:
            here, code = self.run_fake_campaign(Path(temp), failed=True)
            self.assertEqual(code, 1)
            self.assertFalse((here / "results").exists())
            self.assertEqual(len(list((here / "site").iterdir())), 2)

    def test_save_flag_keeps_manifest_and_cleans_successful_lab(self):
        with tempfile.TemporaryDirectory() as temp:
            here, code = self.run_fake_campaign(Path(temp), save=True)
            self.assertEqual(code, 0)
            manifests = list((here / "results").glob("*/manifest.json"))
            self.assertEqual(len(manifests), 1)
            manifest = json.loads(manifests[0].read_text())
            self.assertEqual(manifest["status"], "ok")
            baseline = json.loads((Path(__file__).resolve().parents[1] / "lib/regression.json").read_text())
            self.assertEqual(set(manifest), set(baseline["campaign_fields"]))
            self.assertEqual([p.name for p in (here / "site").iterdir()], ["older-run"])

    def test_save_flag_preserves_failure_manifest_and_lab(self):
        with tempfile.TemporaryDirectory() as temp:
            here, code = self.run_fake_campaign(Path(temp), save=True, failed=True)
            self.assertEqual(code, 1)
            manifests = list((here / "results").glob("*/manifest.json"))
            self.assertEqual(len(manifests), 1)
            self.assertEqual(json.loads(manifests[0].read_text())["status"], "failed")
            self.assertEqual(len(list((here / "site").iterdir())), 2)


class RegistryTests(unittest.TestCase):
    @unittest.skipUnless(__import__("shutil").which("node"), "Node is only needed for offline JS contracts")
    def test_transport_metrics_and_flow_contracts_without_k6(self):
        script = Path(__file__).resolve().parents[1] / "lib/contracts.test.mjs"
        subprocess.run(["node", "--experimental-vm-modules", "--test", str(script)],
                       check=True, capture_output=True, text=True)

    @unittest.skipUnless(__import__("shutil").which("node"), "Node is only needed for offline JS contracts")
    def test_actual_js_registry_has_complete_ordered_matrix(self):
        registry = (Path(__file__).resolve().parents[1] / "lib/registry.js").read_text()
        code = "globalThis.open = () => " + json.dumps(json.dumps(CATALOG)) + ";\n"
        code += "const {selectCases, operations, PROFILES, TARGETS} = await import('data:text/javascript,' + encodeURIComponent(" + json.dumps(registry) + "));\n"
        code += "console.log(JSON.stringify({profiles:PROFILES, targets:TARGETS, all:selectCases('all'), one:selectCases('fpe-batch',true,true,128), ops:operations({target:'token-deterministic-batch'})}));"
        result = json.loads(subprocess.check_output(["node", "--input-type=module", "-e", code], text=True))
        self.assertEqual(result["profiles"], list(PROFILES))
        self.assertEqual(result["targets"], list(TARGETS[1:]))
        self.assertEqual(len(result["all"]), 28)
        self.assertEqual(len({case["id"] for case in result["all"]}), 28)
        self.assertTrue(all(case["batchSize"] == 3 for case in result["all"] if case["target"].endswith("-batch")))
        self.assertEqual(result["one"][0]["batchSize"], 128)
        self.assertEqual(result["ops"], ["token_deterministic_encode_batch", "token_deterministic_decode_batch"])


if __name__ == "__main__":
    unittest.main()
