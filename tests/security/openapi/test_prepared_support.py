"""Offline regression tests for Schemathesis prepared-profile setup."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import prepared_support


class PreparedSupportTests(unittest.TestCase):
    def test_missing_config_uses_a_fresh_minimal_config(self):
        with tempfile.TemporaryDirectory() as directory:
            missing_path = Path(directory) / "config.json"
            with patch.object(prepared_support, "CONFIG_PATH", missing_path):
                config = prepared_support._load_config()

        self.assertEqual(config, prepared_support.DEFAULT_CONFIG)
        self.assertIsNot(config, prepared_support.DEFAULT_CONFIG)
