import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "projects" / "PineAI" / "src" / "assets"
sys.path.insert(0, str(ASSETS))

from pineai_backend import __version__  # noqa: E402
from pineai_backend.assurance_service import AssuranceService  # noqa: E402
from pineai_backend.errors import BackendError  # noqa: E402


FIXTURE = Path(__file__).resolve().parent / "fixtures" / "recon_basic.json"


def scan():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def metadata(identifier):
    return {
        "scan_id": identifier,
        "date": "2026-07-27T12:00:00Z",
        "scan_time": 180,
        "coverage": ["2.4"],
        "location_id": "loc-1",
        "measurement_point_id": "point-1",
        "scan_profile_id": "full-sweep-v1",
        "radio_profile_id": "mk7-radio-a",
        "interface": "wlan1mon",
        "declared_channels": [1, 6, 11],
    }


class AssuranceServiceTests(unittest.TestCase):
    def test_capabilities_version_matches_package_version(self):
        with tempfile.TemporaryDirectory() as directory:
            capabilities = AssuranceService(config_dir=directory).capabilities()
        self.assertEqual(capabilities["backend_version"], __version__)
        self.assertEqual(__version__, "0.7.0")

    def active_service(self, directory):
        service = AssuranceService(config_dir=directory)
        store = service.store
        assessment = service.create_assessment(
            {"name": "Office", "location": "Helsinki", "notes": "local"}
        )
        created = service.create_baseline_version(
            assessment["assessment_id"],
            assessment["revision"],
            scan(),
            metadata("baseline"),
            "Initial baseline",
        )
        activated = store.activate_baseline_version(
            assessment["assessment_id"],
            created["assessment"]["revision"],
            created["baseline_version"]["baseline_version_id"],
        )
        return service, store, activated["assessment"]

    def test_offline_end_to_end_baseline_diff_lifecycle_and_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            service, store, assessment = self.active_service(directory)
            changed = scan()
            changed["APResults"].append(
                {
                    "ssid": "Example-Corp",
                    "bssid": "AA:BB:CC:00:00:03",
                    "encryption": 5,
                    "channel": 11,
                }
            )
            preview = service.compare_recon(
                assessment["assessment_id"], changed, metadata("changed")
            )
            self.assertEqual(preview["mode"], "preview")
            self.assertEqual(
                preview["diff"]["comparability"]["status"], "comparable"
            )
            self.assertEqual(len(preview["observed_changes"]), 1)
            self.assertEqual(
                preview["observed_changes"][0]["change_type"],
                "known_ssid_new_bssid",
            )
            self.assertNotIn("severity", preview["observed_changes"][0])

            persisted = service.analyze_recon(
                assessment["assessment_id"],
                assessment["revision"],
                changed,
                metadata("changed"),
            )
            self.assertEqual(persisted["lifecycle"]["opened"], [])
            self.assertEqual(persisted["findings"], [])
            comparison_id = persisted["comparison"]["comparison_id"]

            ai = service.generate_ai_analysis(
                assessment["assessment_id"], comparison_id, None, None
            )
            self.assertEqual(ai["ai_status"]["code"], "api_key_missing")

            json_report = service.generate_report(
                assessment["assessment_id"], comparison_id, "json"
            )
            html_report = service.generate_report(
                assessment["assessment_id"], comparison_id, "html"
            )
            self.assertEqual(json_report["mime_type"], "application/json")
            self.assertIn("known_ssid_new_bssid", json_report["content"])
            self.assertIn("Deterministic authority", html_report["content"])
            cloud_payload = service.prepare_ai_analysis(
                assessment["assessment_id"], comparison_id, None, None
            )["cloud_payload"]
            serialized_payload = json.dumps(cloud_payload, sort_keys=True)
            self.assertNotIn("local", serialized_payload)
            self.assertNotIn(assessment["name"], serialized_payload)
            self.assertNotIn(assessment["location"], serialized_payload)

            detail = service.assessment_detail(assessment["assessment_id"])
            self.assertEqual(len(detail["baseline_versions"]), 1)
            self.assertEqual(len(detail["comparisons"]), 1)
            self.assertEqual(detail["finding_summary"]["open"], 0)

    def test_compare_is_read_only_and_revision_conflicts_are_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            service, store, assessment = self.active_service(directory)
            before = service.assessment_detail(assessment["assessment_id"])
            service.compare_recon(
                assessment["assessment_id"], scan(), metadata("preview")
            )
            after = service.assessment_detail(assessment["assessment_id"])
            self.assertEqual(before["revision"], after["revision"])
            self.assertEqual(after["comparisons"], [])

            store.update(
                assessment["assessment_id"],
                assessment["revision"],
                {"location": "Espoo"},
            )
            with self.assertRaises(BackendError) as raised:
                service.analyze_recon(
                    assessment["assessment_id"],
                    assessment["revision"],
                    scan(),
                    metadata("stale"),
                )
            self.assertEqual(raised.exception.code, "revision_conflict")

    def test_not_comparable_analysis_is_diagnostic_only(self):
        with tempfile.TemporaryDirectory() as directory:
            service, store, assessment = self.active_service(directory)
            empty = {
                "APResults": [],
                "OutOfRangeClientResults": [],
                "UnassociatedClientResults": [],
            }
            result = service.analyze_recon(
                assessment["assessment_id"],
                assessment["revision"],
                empty,
                metadata("empty"),
            )
            self.assertEqual(
                result["comparison"]["comparability_status"],
                "not_comparable",
            )
            self.assertFalse(result["lifecycle"]["mutated"])
            self.assertEqual(
                store.list_findings(assessment["assessment_id"]), []
            )


if __name__ == "__main__":
    unittest.main()
