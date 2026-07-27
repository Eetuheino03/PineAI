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
    ensure_pseudonymization_key,
    load_api_key,
    load_settings,
    public_status,
    save_api_key,
    save_settings,
)


class ConfigTests(unittest.TestCase):
    def test_defaults_and_safe_public_status(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(load_settings(directory)["model"], "gpt-5.6-terra")
            self.assertFalse(public_status(directory)["configured"])

    def test_keys_are_persistent_and_not_exposed(self):
        with tempfile.TemporaryDirectory() as directory:
            first = ensure_pseudonymization_key(directory)
            second = ensure_pseudonymization_key(directory)
            self.assertEqual(first, second)
            self.assertEqual(len(first), 32)
            save_api_key("sk-test-secret", directory)
            status = public_status(directory)
            self.assertTrue(status["configured"])
            self.assertNotIn("sk-test-secret", json.dumps(status))
            self.assertEqual(load_api_key(directory), "sk-test-secret")

    def test_environment_key_override(self):
        with tempfile.TemporaryDirectory() as directory:
            save_api_key("file-key", directory)
            with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "env-key"}):
                self.assertEqual(load_api_key(directory), "env-key")

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
