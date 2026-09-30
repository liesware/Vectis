import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import support.vectis as vectis


class BinaryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.binary = self.root / "bin with spaces" / "vectis"
        self.binary.parent.mkdir()
        self.binary.write_text(
            f"#!{Path(sys.executable).resolve()}\n"
            "import json, os, sys\n"
            "print(json.dumps({'args': sys.argv[1:], 'cwd': os.getcwd(), 'marker': os.environ['MARKER']}))\n",
            encoding="utf-8",
        )
        self.binary.chmod(0o700)

    def test_explicit_binary_preserves_args_cwd_and_environment(self):
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir()
        env = dict(os.environ, VECTIS_BIN=str(self.binary), MARKER="fixture-only")
        args = ["config", "sign", "--output", "json", "value with spaces"]
        result = subprocess.run(vectis.vectis_command(args, env=env), cwd=elsewhere,
                                env=env, capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(result.stdout),
                         {"args": args, "cwd": str(elsewhere.resolve()), "marker": "fixture-only"})

    def test_relative_binary_uses_repository_root(self):
        with patch.object(vectis, "ROOT", self.root):
            self.assertEqual(vectis.configured_binary({"VECTIS_BIN": "bin with spaces/vectis"}),
                             self.binary.resolve())

    def test_invalid_explicit_binary_never_falls_back(self):
        nonexecutable = self.root / "not-executable"
        nonexecutable.write_text("not an executable", encoding="utf-8")
        for value in ("", str(self.root / "missing"), str(nonexecutable), str(self.root)):
            with self.subTest(value=value), self.assertRaisesRegex(RuntimeError, "VECTIS_BIN"):
                vectis.vectis_command(["init"], env={"VECTIS_BIN": value})

    def test_standalone_cargo_flags_are_preserved(self):
        self.assertIsNone(vectis.configured_binary({}))
        self.assertEqual(vectis.vectis_command(["init"], env={}, quiet=True),
                         ["cargo", "run", "--quiet", "--", "init"])
        self.assertEqual(vectis.vectis_command(["config", "sign"], env={}),
                         ["cargo", "run", "--", "config", "sign"])

    def fuzz_config(self):
        directory = vectis.ROOT / "tests" / "security" / "fuzz"
        spec = importlib.util.spec_from_file_location("fuzz_config_under_test", directory / "config.py")
        module = importlib.util.module_from_spec(spec)
        with patch.object(sys, "path", [str(directory), *sys.path]):
            spec.loader.exec_module(module)
        return module

    def test_fuzzer_uses_supplied_binary_without_compiling(self):
        config = self.fuzz_config()
        with patch.dict(os.environ, {"VECTIS_BIN": str(self.binary)}), \
             patch.object(config, "_build_vectis_binary") as build:
            self.assertEqual(config._vectis_binary(), str(self.binary.resolve()))
            self.assertEqual(config._vectis_binary(), str(self.binary.resolve()))
            build.assert_not_called()
        with patch.dict(os.environ, {"VECTIS_BIN": str(self.root / "missing")}), \
             patch.object(config, "_build_vectis_binary") as build:
            with self.assertRaises(RuntimeError):
                config._vectis_binary()
            build.assert_not_called()

    def test_standalone_fuzzer_compiles_once(self):
        config = self.fuzz_config()
        with patch.dict(os.environ, {}, clear=True), \
             patch.object(config.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as build:
            self.assertEqual(config._vectis_binary(), str(config.VECTIS_BIN))
            self.assertEqual(config._vectis_binary(), str(config.VECTIS_BIN))
            build.assert_called_once()
            self.assertEqual(build.call_args.args[0], ["cargo", "build", "--quiet"])
