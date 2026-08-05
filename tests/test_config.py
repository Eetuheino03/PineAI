import json
import os
import stat
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
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
    IdentityKeyError,
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

    def test_nested_configuration_errors_are_sanitized(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "config.json").write_text(
                "{}", encoding="utf-8"
            )
            with mock.patch(
                "pineai_backend.config._read_private_bytes",
                side_effect=ConfigError(
                    "SECRET-PATH-CANARY /root/.PineAI/config.json"
                ),
            ):
                with self.assertRaises(ConfigError) as raised:
                    load_settings(directory)
            self.assertEqual(
                str(raised.exception),
                "Could not read PineAI configuration",
            )

    def test_private_write_retries_transient_atomic_replace_denial(self):
        with tempfile.TemporaryDirectory() as directory:
            real_replace = os.replace
            attempts = {"count": 0}

            def transient_replace(source, target):
                attempts["count"] += 1
                if attempts["count"] < 3:
                    raise PermissionError("transient sharing violation")
                return real_replace(source, target)

            with mock.patch(
                "pineai_backend.config.os.replace",
                side_effect=transient_replace,
            ):
                save_settings(load_settings(directory), directory)

            self.assertEqual(attempts["count"], 3)
            self.assertEqual(
                load_settings(directory)["model"], "gpt-5.6-terra"
            )

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

    def test_non_secret_config_rejects_unknown_secret_like_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = load_settings(directory)
            for field in ("api_key", "password", "token"):
                with self.subTest(field=field):
                    invalid = dict(settings)
                    invalid[field] = "secret-canary"
                    with self.assertRaises(ConfigError):
                        save_settings(invalid, directory)
            self.assertFalse(
                (Path(directory) / "config.json").exists()
            )

    def test_concurrent_identity_initialization_uses_one_key(self):
        with tempfile.TemporaryDirectory() as directory:
            with ThreadPoolExecutor(max_workers=12) as executor:
                keys = list(
                    executor.map(
                        lambda _: ensure_pseudonymization_key(directory),
                        range(24),
                    )
                )
            self.assertEqual(len(set(keys)), 1)
            self.assertEqual(len(keys[0]), 32)

    def test_transient_assessment_lock_does_not_bind_missing_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            assessment = (
                Path(directory)
                / "assessments"
                / "assessment_00000000-0000-4000-8000-000000000000"
            )
            for name in ("baselines", "snapshots", "comparisons"):
                (assessment / name).mkdir(parents=True, exist_ok=True)
            (assessment / ".lock").write_bytes(b"\0")

            secret = ensure_pseudonymization_key(directory)

            self.assertEqual(len(secret), 32)

    def test_nontransient_assessment_data_blocks_identity_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            assessment_id = (
                "assessment_00000000-0000-4000-8000-000000000000"
            )
            assessment = (
                Path(directory) / "assessments" / assessment_id
            )
            assessment.mkdir(parents=True)
            (assessment / "assessment.json").write_text(
                json.dumps({"assessment_id": assessment_id}),
                encoding="utf-8",
            )

            with self.assertRaises(IdentityKeyError) as raised:
                ensure_pseudonymization_key(directory)

            self.assertEqual(
                raised.exception.code, "identity_key_missing"
            )

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
