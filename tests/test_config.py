import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ASSETS = (
    Path(__file__).resolve().parents[1]
    / "projects"
    / "PineAI"
    / "src"
    / "assets"
)
sys.path.insert(0, str(ASSETS))

from pineai_backend.config import (  # noqa: E402
    ConfigError,
    delete_api_key,
    ensure_pseudonymization_key,
    load_api_key,
    load_settings,
    public_status,
    save_api_key,
    save_settings,
    update_frontend_settings,
)


class ConfigTests(unittest.TestCase):
    def test_defaults_and_safe_public_status(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(load_settings(directory)["model"], "gpt-5.6-terra")
            status = public_status(directory)
            self.assertFalse(status["configured"])
            self.assertEqual(status["key_source"], "none")
            self.assertEqual(status["supported_bands"], [])

    def test_keys_are_persistent_and_not_exposed(self):
        with tempfile.TemporaryDirectory() as directory:
            first = ensure_pseudonymization_key(directory)
            second = ensure_pseudonymization_key(directory)
            self.assertEqual(first, second)
            self.assertEqual(len(first), 32)
            save_api_key("sk-test-secret", directory)
            status = public_status(directory)
            self.assertTrue(status["configured"])
            self.assertEqual(status["key_source"], "file")
            self.assertNotIn("sk-test-secret", json.dumps(status))
            self.assertEqual(load_api_key(directory), "sk-test-secret")

    def test_environment_key_override(self):
        with tempfile.TemporaryDirectory() as directory:
            save_api_key("file-key", directory)
            with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "env-key"}):
                self.assertEqual(load_api_key(directory), "env-key")
                self.assertEqual(public_status(directory)["key_source"], "environment")

    def test_frontend_settings_validate_and_persist_privacy_preferences(self):
        with tempfile.TemporaryDirectory() as directory:
            status = update_frontend_settings(
                {
                    "language": "fi",
                    "share_ssids": True,
                },
                directory,
            )
            self.assertEqual(status["language"], "fi")
            self.assertTrue(status["share_ssids"])
            persisted = load_settings(directory)
            self.assertEqual(persisted["language"], "fi")
            self.assertTrue(persisted["share_ssids"])

    def test_frontend_settings_reject_unsafe_or_unknown_values(self):
        invalid = (
            {"model": "other"},
            {
                "supported_bands": [
                    {"value": "bad\nvalue", "covers": ["2.4"], "is_default": True}
                ]
            },
            {
                "supported_bands": [
                    {"value": "a", "covers": ["2.4"], "is_default": True},
                    {"value": "b", "covers": ["5"], "is_default": True},
                ]
            },
        )
        with tempfile.TemporaryDirectory() as directory:
            for value in invalid:
                with self.subTest(value=value):
                    with self.assertRaises(ConfigError):
                        update_frontend_settings(value, directory)

    def test_delete_managed_key_preserves_environment_override(self):
        with tempfile.TemporaryDirectory() as directory:
            save_api_key("file-key", directory)
            delete_api_key(directory)
            self.assertIsNone(load_api_key(directory))
            with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "env-key"}):
                delete_api_key(directory)
                status = public_status(directory)
                self.assertTrue(status["configured"])
                self.assertEqual(status["key_source"], "environment")

    @unittest.skipIf(os.name == "nt", "POSIX permissions are verified on Linux/Mark VII")
    def test_secret_file_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            save_api_key("secret", directory)
            ensure_pseudonymization_key(directory)
            save_settings(load_settings(directory), directory)
            for name in ("openai.key", "pseudonymization.key", "config.json"):
                mode = stat.S_IMODE(os.stat(os.path.join(directory, name)).st_mode)
                self.assertEqual(mode, 0o600)


if __name__ == "__main__":
    unittest.main()
