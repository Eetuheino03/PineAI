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

    def test_v07_actions_are_registered_and_health_is_safe(self):
        loaded = self.load_module()
        expected = {
            "health",
            "get_settings",
            "update_settings",
            "set_openai_api_key",
            "delete_openai_api_key",
            "assurance_capabilities",
            "platform_capabilities",
            "list_measurement_profiles",
            "create_measurement_profile",
            "update_measurement_profile",
            "archive_measurement_profile",
            "create_assessment",
            "get_assessment",
            "list_assessments",
            "update_assessment",
            "archive_assessment",
            "resolve_recon",
            "create_baseline_version",
            "preview_consensus_baseline",
            "create_consensus_baseline_version",
            "list_baseline_versions",
            "get_baseline_version",
            "activate_baseline_version",
            "preview_inventory_csv",
            "create_assurance_profile_version",
            "list_assurance_profile_versions",
            "get_assurance_profile_version",
            "activate_assurance_profile_version",
            "export_inventory_csv",
            "compare_recon",
            "analyze_recon",
            "list_findings",
            "update_finding",
            "list_observed_changes",
            "get_evidence_bundle",
            "prepare_ai_analysis",
            "generate_ai_analysis",
            "prepare_report",
            "generate_report",
            "repeatable_audit_capabilities",
            "resource_telemetry",
            "create_measurement_point",
            "list_measurement_points",
            "get_measurement_point",
            "update_measurement_point",
            "archive_measurement_point",
            "create_audit_run",
            "list_audit_runs",
            "get_audit_run",
            "start_audit_run",
            "cancel_audit_run",
            "complete_audit_run",
            "resolve_audit_measurement",
            "save_audit_measurement_comparison",
            "retry_audit_measurement",
            "generate_audit_run_report",
        }
        self.assertEqual(set(loaded.module.actions), expected)
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(os.environ, {"PINEAI_CONFIG_DIR": directory}):
                response = loaded.health(FakeRequest())
        self.assertEqual(response["version"], "0.7.0")
        self.assertEqual(response["product_name"], "PineAssure")
        self.assertEqual(response["product_mode"], "repeatable_field_audit")
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

    def test_v07_handlers_reject_unknown_public_request_fields(self):
        loaded = self.load_module()
        request = FakeRequest()
        request.module = "PineAI"
        request.action = "repeatable_audit_capabilities"
        request.unexpected_payload = "must fail closed"
        result = loaded.repeatable_audit_capabilities(request)
        self.assertEqual(result[0]["error"]["code"], "invalid_request")

        update = FakeRequest()
        update.assessment_id = "assessment_00000000-0000-4000-8000-000000000000"
        update.expected_assessment_revision = 1
        update.measurement_point_id = "mp_0000000000000000"
        update.expected_measurement_point_revision = 1
        update.changes = {"name": "legacy alias"}
        result = loaded.update_measurement_point(update)
        self.assertEqual(
            result[0]["error"]["code"], "invalid_measurement_point"
        )

        telemetry = FakeRequest()
        telemetry.assessment_id = "not-a-canonical-assessment-id"
        result = loaded.resource_telemetry_action(telemetry)
        self.assertEqual(result[0]["error"]["code"], "invalid_assessment_id")

        report = FakeRequest()
        report.assessment_id = "assessment_00000000-0000-4000-8000-000000000000"
        report.audit_run_id = "ar_0000000000000000"
        report.format = "json"
        result = loaded.generate_audit_run_report(report)
        self.assertEqual(result[0]["error"]["code"], "invalid_privacy_profile")

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

        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(os.environ, {"PINEAI_CONFIG_DIR": directory}):
                invalid_time = FakeRequest()
                invalid_time.scan = json.loads(
                    FIXTURE.read_text(encoding="utf-8")
                )
                invalid_time.scan_metadata = {"date": "not-rfc3339"}
                response, success = loaded.resolve_recon(invalid_time)
        self.assertFalse(success)
        self.assertEqual(
            response["error"]["code"], "invalid_scan_metadata"
        )

    def test_deprecated_relative_position_input_is_rejected(self):
        loaded = self.load_module()
        request_value = FakeRequest()
        request_value.position_confirmation = "different"
        response, success = loaded.compare_recon(request_value)
        self.assertFalse(success)
        self.assertEqual(response["error"]["code"], "invalid_request")
        self.assertIn("measurement_context", response["error"]["message"])

    def test_module_actions_complete_the_offline_assurance_workflow(self):
        loaded = self.load_module()
        scan = json.loads(FIXTURE.read_text(encoding="utf-8"))
        metadata = {
            "scan_time": 180,
            "coverage": ["2.4"],
            "source": "hak5_recon",
            "location_id": "loc-1",
            "measurement_point_id": "point-1",
            "scan_profile_id": "full-sweep-v1",
            "radio_profile_id": "mk7-radio-a",
            "interface": "wlan1mon",
            "declared_channels": [1, 6, 11],
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
                self.assertTrue(analysis["observed_changes"])
                self.assertEqual(analysis["findings"], [])

                finding_request = FakeRequest()
                finding_request.assessment_id = assessment["assessment_id"]
                findings = loaded.list_findings(finding_request)["findings"]
                self.assertEqual(findings, [])

                prepare_req = FakeRequest()
                prepare_req.assessment_id = assessment["assessment_id"]
                prepare_req.scope = {
                    "type": "comparison",
                    "comparison_id": analysis["comparison"]["comparison_id"],
                }
                prepare_res = loaded.module.actions["prepare_report"](prepare_req)
                self.assertIn("scope_digest", prepare_res)

                report_request = FakeRequest()
                report_request.assessment_id = assessment["assessment_id"]
                report_request.comparison_id = analysis["comparison"]["comparison_id"]
                report_request.scope = prepare_res["scope"]
                report_request.scope_digest = prepare_res["scope_digest"]
                report_request.format = "html"
                report_request.ai_analysis = None

                report = loaded.generate_report_action(report_request)
                self.assertEqual(report["format"], "html")
                self.assertIn("scope_digest", report)
                self.assertNotIn("content", report)

                # Direct call without scope or digest should fail
                invalid_req = FakeRequest()
                invalid_req.assessment_id = assessment["assessment_id"]
                invalid_req.format = "html"
                res = loaded.generate_report_action(invalid_req)
                self.assertEqual(res[0]["error"]["code"], "invalid_report_scope")

    def test_module_actions_complete_repeatable_field_audit_workflow(self):
        loaded = self.load_module()
        scan = json.loads(FIXTURE.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(
                os.environ, {"PINEAI_CONFIG_DIR": directory}
            ):
                loaded._reset_singletons()
                profile_request = FakeRequest()
                profile_request.profile = {
                    "name": "Saved Recon",
                    "description": "",
                    "scan_profile_id": "saved-recon",
                    "radio_profile_id": "wlan1",
                    "interface": "wlan1mon",
                    "declared_bands": ["2.4"],
                    "declared_channels": [1, 6, 11],
                    "scan_time": 180,
                    "is_default": True,
                    "five_ghz_operator_confirmed": False,
                }
                profile = loaded.create_measurement_profile(profile_request)[
                    "measurement_profile"
                ]
                profile_version = profile["active_version"]

                assessment_request = FakeRequest()
                assessment_request.assessment = {
                    "name": "Repeatable site",
                    "location": "Lab",
                    "notes": "",
                }
                assessment = loaded.create_assessment(assessment_request)

                point_request = FakeRequest()
                point_request.assessment_id = assessment["assessment_id"]
                point_request.expected_assessment_revision = assessment[
                    "revision"
                ]
                point_request.measurement_point = {
                    "location_label": "North desk",
                    "physical_notes": "Blue marker",
                    "operator_instructions": "Keep antenna vertical",
                }
                point_result = loaded.create_measurement_point(point_request)
                point = point_result["measurement_point"]

                metadata = {
                    "scan_id": "baseline",
                    "date": "2026-07-31T09:00:00Z",
                    "scan_time": 180,
                    "coverage": ["2.4"],
                    "measurement_context": {
                        "location_id": assessment["assessment_id"],
                        "measurement_point_id": point[
                            "measurement_point_id"
                        ],
                        "scan_profile_id": "saved-recon",
                        "radio_profile_id": "wlan1",
                        "interface": "wlan1mon",
                        "declared_bands": ["2.4"],
                        "declared_channels": [1, 6, 11],
                        "measurement_profile_id": profile[
                            "measurement_profile_id"
                        ],
                        "measurement_profile_version_id": profile_version[
                            "version_id"
                        ],
                        "measurement_profile_digest": profile_version[
                            "digest"
                        ],
                    },
                }
                baseline_request = FakeRequest()
                baseline_request.assessment_id = assessment["assessment_id"]
                baseline_request.expected_revision = point_result[
                    "assessment_revision"
                ]
                baseline_request.scan = scan
                baseline_request.scan_metadata = metadata
                baseline_request.label = "Approved north desk"
                baseline = loaded.create_baseline_version(baseline_request)

                inventory_request = FakeRequest()
                inventory_request.content = (
                    "site,ssid,bssid,vendor,role,approved\n"
                    "Lab,Example-Corp,AA:BB:CC:00:00:01,Unknown,corp,true\n"
                )
                inventory_request.delimiter = "comma"
                inventory = loaded.preview_inventory_csv(inventory_request)
                assurance_request = FakeRequest()
                assurance_request.assessment_id = assessment["assessment_id"]
                assurance_request.expected_revision = baseline["assessment"][
                    "revision"
                ]
                assurance_request.label = "Approved inventory"
                assurance_request.inventory_preview = inventory
                assurance_request.coverage_mode = "partial"
                assurance = loaded.create_assurance_profile_version(
                    assurance_request
                )

                run_request = FakeRequest()
                run_request.assessment_id = assessment["assessment_id"]
                run_request.expected_assessment_revision = assurance[
                    "assessment"
                ]["revision"]
                run_request.audit_run = {
                    "name": "July round",
                    "description": "Operator driven",
                    "assurance_profile_version_id": assurance[
                        "assurance_profile"
                    ]["assurance_profile_version_id"],
                    "assignments": [
                        {
                            "measurement_point_id": point[
                                "measurement_point_id"
                            ],
                            "measurement_profile_id": profile[
                                "measurement_profile_id"
                            ],
                            "measurement_profile_version_id": profile_version[
                                "version_id"
                            ],
                            "baseline_version_id": baseline["baseline"][
                                "baseline_version_id"
                            ],
                        }
                    ],
                }
                created = loaded.create_audit_run(run_request)

                start_request = FakeRequest()
                start_request.assessment_id = assessment["assessment_id"]
                start_request.expected_assessment_revision = created[
                    "assessment_revision"
                ]
                start_request.audit_run_id = created["audit_run"][
                    "audit_run_id"
                ]
                start_request.expected_audit_run_revision = created[
                    "audit_run"
                ]["revision"]
                started = loaded.start_audit_run(start_request)
                measurement = started["measurements"][0]

                resolve_request = FakeRequest()
                resolve_request.assessment_id = assessment["assessment_id"]
                resolve_request.expected_assessment_revision = started[
                    "assessment_revision"
                ]
                resolve_request.audit_run_id = started["audit_run"][
                    "audit_run_id"
                ]
                resolve_request.expected_audit_run_revision = started[
                    "audit_run"
                ]["revision"]
                resolve_request.measurement_id = measurement[
                    "measurement_id"
                ]
                resolve_request.expected_measurement_revision = measurement[
                    "revision"
                ]
                resolve_request.scan = scan
                resolve_request.scan_metadata = {
                    "scan_id": "current",
                    "date": "2026-07-31T10:00:00Z",
                    "scan_time": 180,
                    "coverage": ["2.4"],
                }
                resolved = loaded.resolve_audit_measurement(resolve_request)
                self.assertEqual(resolved["measurement"]["status"], "resolved")

                compare_request = FakeRequest()
                compare_request.assessment_id = assessment["assessment_id"]
                compare_request.expected_assessment_revision = resolved[
                    "assessment_revision"
                ]
                compare_request.audit_run_id = resolved["audit_run"][
                    "audit_run_id"
                ]
                compare_request.expected_audit_run_revision = resolved[
                    "audit_run"
                ]["revision"]
                compare_request.measurement_id = measurement[
                    "measurement_id"
                ]
                compare_request.expected_measurement_revision = resolved[
                    "measurement"
                ]["revision"]
                compared = loaded.save_audit_measurement_comparison(
                    compare_request
                )
                self.assertEqual(compared["measurement"]["status"], "completed")

                complete_request = FakeRequest()
                complete_request.assessment_id = assessment["assessment_id"]
                complete_request.expected_assessment_revision = compared[
                    "assessment_revision"
                ]
                complete_request.audit_run_id = compared["audit_run"][
                    "audit_run_id"
                ]
                complete_request.expected_audit_run_revision = compared[
                    "audit_run"
                ]["revision"]
                completed = loaded.complete_audit_run(complete_request)

                report_request = FakeRequest()
                report_request.assessment_id = assessment["assessment_id"]
                report_request.audit_run_id = completed["audit_run"][
                    "audit_run_id"
                ]
                report_request.format = "html"
                report_request.privacy_profile = "share_safe"
                report = loaded.generate_audit_run_report(report_request)
                self.assertEqual(report["format"], "html")
                self.assertNotIn("AA:BB:CC", report["content"])
                self.assertNotIn("Blue marker", report["content"])

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
            loaded._reset_singletons()
            self.assertEqual(loaded.__version__, "0.7.0")
            self.assertTrue(service_modules.isdisjoint(sys.modules))

            # Metadata actions should use store directly without loading reports or AI analysis
            with tempfile.TemporaryDirectory() as directory:
                with mock.patch.dict(os.environ, {"PINEAI_CONFIG_DIR": directory}):
                    loaded.list_measurement_profiles(FakeRequest())
                    loaded.platform_capabilities(FakeRequest())
            self.assertNotIn("pineai_backend.reports", sys.modules)
            self.assertNotIn("pineai_backend.ai_analysis", sys.modules)
            self.assertNotIn("pineai_backend.customer_analysis", sys.modules)
        finally:
            for name in list(sys.modules):
                if name == "pineai_backend" or name.startswith("pineai_backend."):
                    sys.modules.pop(name, None)
            sys.modules.update(saved)


if __name__ == "__main__":
    unittest.main()
