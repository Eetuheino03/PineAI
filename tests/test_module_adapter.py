import importlib.util
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "projects" / "PineAI" / "src" / "module.py"


class FakeModule:
    def __init__(self, *_args):
        self.actions = {}

    def handles_action(self, name):
        def decorator(function):
            self.actions[name] = function
            return function

        return decorator

    def start(self):
        pass


class FakeRequest:
    pass


class ModuleAdapterTests(unittest.TestCase):
    def load_module(self):
        pineapple = types.ModuleType("pineapple")
        pineapple_modules = types.ModuleType("pineapple.modules")
        pineapple_modules.Module = FakeModule
        pineapple_modules.Request = FakeRequest
        pineapple.modules = pineapple_modules
        with mock.patch.dict(
            sys.modules,
            {"pineapple": pineapple, "pineapple.modules": pineapple_modules},
        ):
            spec = importlib.util.spec_from_file_location(
                "pineai_hak5_module", str(MODULE_PATH)
            )
            loaded = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(loaded)
        return loaded

    def test_actions_are_registered_and_health_is_safe(self):
        loaded = self.load_module()
        self.assertIn("health", loaded.module.actions)
        self.assertIn("profile_recon", loaded.module.actions)
        for action in (
            "advisor_capabilities",
            "create_engagement",
            "get_engagement",
            "list_engagements",
            "update_engagement",
            "archive_engagement",
            "append_engagement_event",
            "advise_attack_paths",
            "get_settings",
            "update_settings",
            "set_openai_api_key",
            "delete_openai_api_key",
            "prepare_profile_recon",
            "prepare_attack_paths",
            "adaptive_recon_capabilities",
            "prepare_adaptive_recon",
            "recommend_adaptive_recon",
            "get_recon_plan",
            "list_recon_plans",
            "approve_recon_plan",
            "record_recon_scan_started",
            "record_recon_scan_finished",
        ):
            self.assertIn(action, loaded.module.actions)
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(os.environ, {"PINEAI_CONFIG_DIR": directory}):
                response = loaded.health(FakeRequest())
        self.assertEqual(response["version"], "0.5.0")
        self.assertFalse(response["api_key_configured"])
        self.assertNotIn("api_key", response)
        self.assertEqual(response["supported_band_count"], 0)

    def test_settings_and_api_key_actions_never_echo_the_secret(self):
        loaded = self.load_module()
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(os.environ, {"PINEAI_CONFIG_DIR": directory}):
                request_value = FakeRequest()
                request_value.settings = {
                    "language": "fi",
                    "share_ssids": False,
                    "supported_bands": [
                        {
                            "value": "confirmed",
                            "covers": ["2.4"],
                            "is_default": True,
                        }
                    ],
                }
                settings = loaded.update_settings(request_value)
                self.assertEqual(settings["language"], "fi")
                self.assertEqual(settings["supported_bands"][0]["value"], "confirmed")

                key_request = FakeRequest()
                key_request.api_key = "test-key-never-return"
                key_request.transport_secure = False
                key_request.insecure_transport_acknowledged = True
                key_response = loaded.set_openai_api_key(key_request)
                self.assertTrue(key_response["api_key_configured"])
                self.assertNotIn("test-key-never-return", repr(key_response))
                self.assertNotIn(
                    "test-key-never-return",
                    repr(loaded.get_settings(FakeRequest())),
                )

                deleted = loaded.delete_openai_api_key(FakeRequest())
                self.assertFalse(deleted["api_key_configured"])

    def test_insecure_key_submission_requires_acknowledgement(self):
        loaded = self.load_module()
        request_value = FakeRequest()
        request_value.api_key = "secret"
        request_value.transport_secure = False
        request_value.insecure_transport_acknowledged = False
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(os.environ, {"PINEAI_CONFIG_DIR": directory}):
                response, success = loaded.set_openai_api_key(request_value)
        self.assertFalse(success)
        self.assertEqual(response["error"]["code"], "configuration_error")

    def test_invalid_recon_returns_hak5_backend_error(self):
        loaded = self.load_module()
        request_value = FakeRequest()
        request_value.scan = {"invalid": []}
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(os.environ, {"PINEAI_CONFIG_DIR": directory}):
                response, success = loaded.profile_recon(request_value)
        self.assertFalse(success)
        self.assertEqual(response["error"]["code"], "invalid_recon")


if __name__ == "__main__":
    unittest.main()
