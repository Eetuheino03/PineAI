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
        ):
            self.assertIn(action, loaded.module.actions)
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(os.environ, {"PINEAI_CONFIG_DIR": directory}):
                response = loaded.health(FakeRequest())
        self.assertEqual(response["version"], "0.3.0")
        self.assertFalse(response["api_key_configured"])
        self.assertNotIn("api_key", response)

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
