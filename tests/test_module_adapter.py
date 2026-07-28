import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "projects" / "PineAI" / "src" / "module.py"
FIXTURE = ROOT / "tests" / "fixtures" / "recon_basic.json"


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

    def test_only_v06_actions_are_registered_and_health_is_safe(self):
        loaded = self.load_module()
        expected = {
            "health",
            "get_settings",
            "update_settings",
            "set_openai_api_key",
            "delete_openai_api_key",
            "assurance_capabilities",
            "create_assessment",
            "get_assessment",
            "list_assessments",
            "update_assessment",
            "archive_assessment",
            "resolve_recon",
            "create_baseline_version",
            "list_baseline_versions",
            "activate_baseline_version",
            "compare_recon",
            "analyze_recon",
            "list_findings",
            "update_finding",
            "prepare_ai_analysis",
            "generate_ai_analysis",
            "generate_report",
        }
        self.assertEqual(set(loaded.module.actions), expected)
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(os.environ, {"PINEAI_CONFIG_DIR": directory}):
                response = loaded.health(FakeRequest())
        self.assertEqual(response["version"], "0.6.0")
        self.assertEqual(response["product_mode"], "baseline_and_drift")
        self.assertTrue(response["offline_complete"])
        self.assertFalse(response["recon_control"])
        self.assertFalse(response["api_key_configured"])
        self.assertNotIn("api_key", response)
        for old_action in (
            "profile_recon",
            "advisor_capabilities",
            "create_engagement",
            "advise_attack_paths",
            "adaptive_recon_capabilities",
        ):
            self.assertNotIn(old_action, loaded.module.actions)

    def test_settings_and_api_key_actions_never_echo_secret(self):
        loaded = self.load_module()
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(os.environ, {"PINEAI_CONFIG_DIR": directory}):
                request_value = FakeRequest()
                request_value.settings = {
                    "language": "fi",
                    "share_ssids": False,
                }
                settings = loaded.update_settings(request_value)
                self.assertEqual(settings["language"], "fi")
                self.assertNotIn("supported_bands", settings)

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

    def test_resolve_recon_and_backend_errors_use_hak5_shape(self):
        loaded = self.load_module()
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(os.environ, {"PINEAI_CONFIG_DIR": directory}):
                valid = FakeRequest()
                valid.scan = json.loads(FIXTURE.read_text(encoding="utf-8"))
                valid.scan_metadata = {
                    "scan_id": "scan",
                    "scan_time": 180,
                    "coverage": ["2.4"],
                }
                result = loaded.resolve_recon(valid)
                self.assertEqual(result["snapshot"]["summary"]["access_point_count"], 3)

                invalid = FakeRequest()
                invalid.scan = {"invalid": []}
                invalid.scan_metadata = {}
                response, success = loaded.resolve_recon(invalid)
        self.assertFalse(success)
        self.assertEqual(response["error"]["code"], "invalid_recon")

    def test_module_actions_complete_the_offline_assurance_workflow(self):
        loaded = self.load_module()
        scan = json.loads(FIXTURE.read_text(encoding="utf-8"))
        metadata = {
            "scan_time": 180,
            "coverage": ["2.4"],
            "source": "hak5_recon",
        }
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(
                os.environ, {"PINEAI_CONFIG_DIR": directory}
            ):
                create_request = FakeRequest()
                create_request.assessment = {
                    "name": "Office",
                    "location": "Helsinki",
                    "notes": "",
                }
                assessment = loaded.create_assessment(create_request)

                baseline_request = FakeRequest()
                baseline_request.assessment_id = assessment["assessment_id"]
                baseline_request.expected_revision = assessment["revision"]
                baseline_request.scan = scan
                baseline_request.scan_metadata = metadata
                baseline_request.label = "Initial"
                baseline_result = loaded.create_baseline_version(
                    baseline_request
                )
                self.assertIn("baseline", baseline_result)
                self.assertNotIn("baseline_version", baseline_result)

                activate_request = FakeRequest()
                activate_request.assessment_id = assessment["assessment_id"]
                activate_request.expected_revision = baseline_result[
                    "assessment"
                ]["revision"]
                activate_request.baseline_version = baseline_result[
                    "baseline"
                ]["baseline_version_id"]
                activated = loaded.activate_baseline_version(
                    activate_request
                )

                changed_scan = json.loads(json.dumps(scan))
                changed_scan["APResults"][0]["channel"] = 11
                analyze_request = FakeRequest()
                analyze_request.assessment_id = assessment["assessment_id"]
                analyze_request.expected_revision = activated["assessment"][
                    "revision"
                ]
                analyze_request.scan = changed_scan
                analyze_request.scan_metadata = metadata
                analysis = loaded.analyze_recon(analyze_request)
                self.assertEqual(
                    analysis["comparison"]["comparability_status"],
                    "comparable",
                )
                self.assertTrue(analysis["findings"])

                finding_request = FakeRequest()
                finding_request.assessment_id = assessment["assessment_id"]
                findings = loaded.list_findings(finding_request)["findings"]
                self.assertEqual(findings[0]["status"], "open")

                report_request = FakeRequest()
                report_request.assessment_id = assessment["assessment_id"]
                report_request.comparison_id = analysis["comparison"][
                    "comparison_id"
                ]
                report_request.format = "html"
                report_request.ai_analysis = None
                report = loaded.generate_report_action(report_request)
                self.assertEqual(report["format"], "html")
                self.assertIn(
                    "Deterministic authority", report["content"]
                )

    def test_adapter_cold_start_does_not_import_analysis_graph(self):
        service_modules = {
            "pineai_backend.assurance_service",
            "pineai_backend.assessment_store",
            "pineai_backend.assurance",
            "pineai_backend.ai_analysis",
            "pineai_backend.reports",
        }
        saved = {
            name: value
            for name, value in sys.modules.items()
            if name == "pineai_backend" or name.startswith("pineai_backend.")
        }
        for name in saved:
            sys.modules.pop(name, None)
        try:
            loaded = self.load_module()
            self.assertEqual(loaded.__version__, "0.6.0")
            self.assertTrue(service_modules.isdisjoint(sys.modules))
        finally:
            for name in list(sys.modules):
                if name == "pineai_backend" or name.startswith("pineai_backend."):
                    sys.modules.pop(name, None)
            sys.modules.update(saved)


if __name__ == "__main__":
    unittest.main()
