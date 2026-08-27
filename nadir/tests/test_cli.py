import os
from io import StringIO
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nadir.cli import _options, _parser, _print_progress, main
from nadir.engine import RunSummary, TargetCompleted, TargetSummary
from nadir.workflows import Finding


class CliEnvironmentTests(unittest.TestCase):
    def _project_file(self, environment: str) -> Path:
        directory = Path(tempfile.mkdtemp())
        (directory / "project.py").write_text("PROJECT = None\n", encoding="utf-8")
        (directory / "env.dist").write_text(environment, encoding="utf-8")
        return directory / "project.py"

    def test_env_dist_supplies_all_runtime_values(self):
        project_file = self._project_file(
            "NADIR_BASE_URL=http://127.0.0.1:3000\nNADIR_KID=" + "a" * 64 + "\nNADIR_API_KEY=from-file\n"
        )
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(
                _options(project_file),
                {"base_url": "http://127.0.0.1:3000", "kid": "a" * 64, "api_key": "from-file"},
            )

    def test_process_environment_overrides_env_dist(self):
        project_file = self._project_file("NADIR_BASE_URL=http://127.0.0.1:3000\nNADIR_KID=" + "a" * 64 + "\n")
        with patch.dict(os.environ, {"NADIR_BASE_URL": "http://127.0.0.1:3010", "NADIR_KID": "b" * 64}, clear=True):
            self.assertEqual(
                _options(project_file),
                {"base_url": "http://127.0.0.1:3010", "kid": "b" * 64, "api_key": None},
            )

    def test_env_dist_rejects_non_nadir_variables(self):
        project_file = self._project_file("VECTIS_API_URL=http://127.0.0.1:3000\n")
        with self.assertRaisesRegex(ValueError, "NADIR_\\*"):
            _options(project_file)

    def test_missing_required_env_dist_value_is_rejected(self):
        project_file = self._project_file("NADIR_BASE_URL=http://127.0.0.1:3000\nNADIR_KID=\n")
        with patch.dict(os.environ, {}, clear=True), self.assertRaisesRegex(ValueError, "NADIR_KID"):
            _options(project_file)

    def test_connection_flags_are_not_accepted(self):
        with self.assertRaises(SystemExit):
            _parser().parse_args(["check", "--project", "project.py", "--base-url", "http://127.0.0.1:3000"])

    def test_reproduce_parser_requires_project_and_artifact(self):
        args = _parser().parse_args(
            ["reproduce", "--project", "project.py", "--artifact", "finding.json"]
        )
        self.assertEqual(args.command, "reproduce")

    def test_reproduce_exit_codes_distinguish_fixed_and_invalid_cases(self):
        result = SimpleNamespace(
            target="target",
            expected_codes=frozenset({"finding"}),
            findings=(Finding("finding", "message"),),
            reproduced=True,
        )
        arguments = ["reproduce", "--project", "project.py", "--artifact", "finding.json"]
        with (
            patch("nadir.cli.load_reproduction_recipe", return_value=object()),
            patch("nadir.cli.load_project", return_value=object()),
            patch("nadir.cli._options", return_value={}),
            patch("nadir.cli.reproduce_project", return_value=result),
        ):
            main(arguments)

        result.reproduced = False
        result.findings = ()
        with (
            patch("nadir.cli.load_reproduction_recipe", return_value=object()),
            patch("nadir.cli.load_project", return_value=object()),
            patch("nadir.cli._options", return_value={}),
            patch("nadir.cli.reproduce_project", return_value=result),
            self.assertRaises(SystemExit) as stopped,
        ):
            main(arguments)
        self.assertEqual(stopped.exception.code, 1)

        with (
            patch("nadir.cli.load_reproduction_recipe", side_effect=ValueError("invalid artifact")),
            self.assertRaises(SystemExit) as stopped,
        ):
            main(arguments)
        self.assertEqual(stopped.exception.code, 4)

        with (
            patch("nadir.cli.load_reproduction_recipe", return_value=object()),
            patch("nadir.cli.load_project", return_value=object()),
            patch("nadir.cli._options", return_value={}),
            patch("nadir.cli.reproduce_project", side_effect=ValueError("missing target")),
            self.assertRaises(SystemExit) as stopped,
        ):
            main(arguments)
        self.assertEqual(stopped.exception.code, 4)


class _FlushingStream(StringIO):
    def __init__(self):
        super().__init__()
        self.flushes = 0

    def flush(self):
        self.flushes += 1
        super().flush()


class CliProgressTests(unittest.TestCase):
    @staticmethod
    def _summary() -> RunSummary:
        return RunSummary(
            (
                TargetSummary(
                    "vectis.target", 1, 1, 2, 0, 1, 0, 0, 0,
                    2, 0, 0, 0, 0, 1, (),
                ),
            ),
            (),
        )

    def test_progress_renders_completed_target_summary_to_stdout_and_flushes(self):
        stream = _FlushingStream()
        event = TargetCompleted(1, 3, self._summary().targets[0], ())
        with patch("sys.stdout", stream):
            _print_progress(event)
        self.assertIn("[1/3] vectis.target: controls=1 mutated_cases=1", stream.getvalue())
        self.assertIn("classes: semantic=1 structured=0 raw=0 deser=0", stream.getvalue())
        self.assertEqual(stream.flushes, 4)

    def test_progress_prints_target_artifacts_immediately(self):
        artifact = Path("tests/security/nadir/results/finding.json")
        stream = _FlushingStream()
        event = TargetCompleted(2, 3, self._summary().targets[0], (artifact,))
        with patch("sys.stdout", stream):
            _print_progress(event)
        self.assertIn("[2/3] vectis.target", stream.getvalue())
        self.assertIn("finding artifact: tests/security/nadir/results/finding.json", stream.getvalue())
        self.assertEqual(stream.flushes, 5)

    def test_run_registers_live_target_summary_without_duplicate_final_summary(self):
        stdout = _FlushingStream()

        def fake_run_project(*args, **kwargs):
            kwargs["progress"](
                TargetCompleted(1, 1, self._summary().targets[0], ())
            )
            return self._summary()

        with (
            patch("nadir.cli.load_project", return_value=object()),
            patch("nadir.cli._options", return_value={}),
            patch("nadir.cli.run_project", side_effect=fake_run_project),
            patch("sys.stdout", stdout),
        ):
            main(["run", "--project", "project.py", "--iterations", "1"])
        self.assertEqual(stdout.getvalue().count("vectis.target: controls=1 mutated_cases=1"), 1)
        self.assertIn("[1/1] vectis.target", stdout.getvalue())
