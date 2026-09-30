import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class RunnerTests(unittest.TestCase):
    def run_runner(self, fail="", skip_binary=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo with spaces"
            root.mkdir()
            (root / "tests.sh").write_text((ROOT / "tests.sh").read_text(), encoding="utf-8")
            tools = Path(directory) / "tools"
            tools.mkdir()
            log = Path(directory) / "commands.jsonl"
            mock = (
                f"#!{Path(sys.executable).resolve()}\n"
                "import json, os, sys\n"
                "from pathlib import Path\n"
                "tool = Path(sys.argv[0]).name\n"
                "args = sys.argv[1:]\n"
                "with open(os.environ['MOCK_LOG'], 'a') as log:\n"
                "    log.write(json.dumps({'tool': tool, 'args': args, 'cwd': os.getcwd(), "
                "'binary': os.environ.get('VECTIS_BIN'), 'no_sync': os.environ.get('UV_NO_SYNC'), "
                "'locked': os.environ.get('UV_LOCKED')}) + '\\n')\n"
                "if tool + ':' + (args[0] if args else '') == os.environ.get('MOCK_FAIL'):\n"
                "    sys.exit(23)\n"
                "if tool == 'cargo' and args[0] == 'build' and os.environ.get('MOCK_SKIP_BINARY') != '1':\n"
                "    binary = Path.cwd() / 'target/debug/vectis'\n"
                "    binary.parent.mkdir(parents=True)\n"
                "    binary.write_text('#!/bin/sh\\nexit 0\\n')\n"
                "    binary.chmod(0o700)\n"
            )
            for tool in ("cargo", "uv", "curl", "bash", "figlet", "cowsay"):
                path = tools / tool
                path.write_text(mock, encoding="utf-8")
                path.chmod(0o700)
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith(("VECTIS_", "UV_"))}
            env.update(PATH=f"{tools}{os.pathsep}{env['PATH']}", MOCK_LOG=str(log),
                       MOCK_FAIL=fail, MOCK_SKIP_BINARY="1" if skip_binary else "0")
            result = subprocess.run(["/bin/bash", str(root / "tests.sh")], cwd=directory,
                                    env=env, capture_output=True, text=True)
            entries = [json.loads(line) for line in log.read_text().splitlines()]
            return result, entries, str(root.resolve())

    def test_one_build_one_sync_and_same_suite_order(self):
        result, entries, root = self.run_runner()
        self.assertEqual(result.returncode, 0, result.stderr)
        cargo = [entry['args'] for entry in entries if entry['tool'] == 'cargo']
        self.assertEqual(cargo, [["fmt", "--", "--check"], ["audit"], ["test", "--locked"],
                                 ["clippy", "--locked", "--all-targets", "--all-features", "--", "-D", "warnings"],
                                 ["build", "--locked"]])
        uv = [entry for entry in entries if entry['tool'] == 'uv']
        self.assertEqual(uv[0]['args'], ["sync", "--locked", "--group", "fuzz"])
        self.assertEqual([entry['args'] for entry in uv[1:]], [
            ["run", "--no-sync", "tests/integration/cli/cli_all.py"],
            ["run", "--no-sync", "tests/integration/http/http_all.py"],
            ["run", "--no-sync", "tests/security/fuzz/http_fuzz.py",
             "--random-seed", "--mutation-only", "--iterations", "100"],
            ["run", "--no-sync", "tests/security/openapi/http_schemathesis.py", "--profile", "prepared"],
        ])
        for entry in uv[1:]:
            self.assertEqual(str(Path(entry['binary']).resolve()), f"{root}/target/debug/vectis")
            self.assertEqual((entry['no_sync'], entry['locked']), ("1", "1"))
        self.assertTrue(all(entry['cwd'] == root for entry in entries))
        self.assertEqual(entries[-1]['args'], ["tests/integration/tls/tls.sh"])
        self.assertIn("Total:", result.stdout)
        self.assertIn("exit=0", result.stdout)

    def test_failure_stops_later_stages_and_preserves_exit_and_times(self):
        for fail in ("cargo:fmt", "cargo:test", "uv:sync", "uv:run", "curl:--fail"):
            with self.subTest(fail=fail):
                result, entries, _ = self.run_runner(fail)
                self.assertEqual(result.returncode, 23, result.stderr)
                self.assertEqual(entries[-1]['tool'] + ':' + entries[-1]['args'][0], fail)
                self.assertIn("Total:", result.stdout)
                self.assertIn("exit=23", result.stdout)

    def test_missing_binary_fails_before_python_suites(self):
        result, entries, _ = self.run_runner(skip_binary=True)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn('uv', [entry['tool'] for entry in entries])
        self.assertIn("Binary validation", result.stdout)
        self.assertIn("exit=1", result.stdout)
