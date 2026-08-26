import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nadir.cli import _options, _parser


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
