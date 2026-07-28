import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "projects" / "PineAI" / "src" / "assets"
sys.path.insert(0, str(ASSETS))

from pineai_backend.assurance_service import AssuranceService  # noqa: E402
from pineai_backend.errors import BackendError  # noqa: E402


FIXTURE = ROOT / "tests" / "fixtures" / "recon_basic.json"


def fixture_scan():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def profile_input():
    return {
        "name": "Office fixed point",
        "description": "Repeatable saved Recon acquisition",
        "location_id": "loc-1",
        "measurement_point_id": "point-1",
        "scan_profile_id": "saved-recon-v1",
        "radio_profile_id": "mk7-default",
        "interface": "wlan1mon",
        "declared_bands": ["2.4"],
        "declared_channels": [1, 6, 11],
        "scan_time": 180,
        "is_default": True,
        "five_ghz_operator_confirmed": False,
    }


def inventory_csv():
    return (
        "site,ssid,bssid,vendor,role,approved,name,required_presence,"
        "allowed_encryption_codes,wps_allowed,allowed_channels,"
        "allowed_vendors,notes\n"
        "Helsinki,Example-Corp,AA:BB:CC:00:00:01,Unknown,corporate,"
        "true,AP1,true,5,true,1,,\n"
        "Helsinki,Example-Corp,AA:BB:CC:00:00:02,Unknown,corporate,"
        "true,AP2,true,5,true,6,,\n"
        "Helsinki,,DE:AD:BE:EF:00:01,Unknown,hidden,true,Hidden,"
        "false,4,false,11,,\n"
    )


class CustomerAuditIntegrationTests(unittest.TestCase):
    def build_context(self, measurement_profile, hour):
        version = measurement_profile["active_version"]
        return {
            "scan_id": "scan-{0}".format(hour),
            "date": "2026-07-27T{0:02d}:00:00Z".format(hour),
            "scan_time": 180,
            "coverage": ["2.4"],
            "source": "hak5_recon",
            "measurement_context": {
                "location_id": "loc-1",
                "measurement_point_id": "point-1",
                "scan_profile_id": "saved-recon-v1",
                "radio_profile_id": "mk7-default",
                "interface": "wlan1mon",
                "declared_bands": ["2.4"],
                "declared_channels": [1, 6, 11],
                "measurement_profile_id": measurement_profile[
                    "measurement_profile_id"
                ],
                "measurement_profile_version_id": version["version_id"],
                "measurement_profile_digest": version["digest"],
            },
        }

    def create_active_foundation(self, directory):
        service = AssuranceService(config_dir=directory)
        measurement = service.create_measurement_profile(
            profile_input()
        )["measurement_profile"]
        assessment = service.create_assessment(
            {
                "name": "Office audit",
                "location": "Helsinki",
                "notes": "local-only operator note",
            }
        )
        observations = []
        for index in range(3):
            scan = fixture_scan()
            if index == 2:
                scan["APResults"] = [
                    item
                    for item in scan["APResults"]
                    if item["bssid"] != "DE:AD:BE:EF:00:01"
                ]
            if index == 0:
                scan["APResults"].append(
                    {
                        "ssid": "Lab-once",
                        "bssid": "02:00:00:00:00:55",
                        "encryption": 5,
                        "channel": 1,
                    }
                )
            observations.append(
                {
                    "scan": scan,
                    "scan_metadata": self.build_context(
                        measurement, index
                    ),
                }
            )
        preview = service.preview_consensus_baseline(observations, 24)
        created = service.create_consensus_baseline_version(
            assessment["assessment_id"],
            assessment["revision"],
            observations,
            "Approved consensus",
            24,
        )
        activated = service.store.activate_baseline_version(
            assessment["assessment_id"],
            created["assessment"]["revision"],
            created["baseline_version"]["baseline_version_id"],
        )
        assessment = activated["assessment"]
        inventory = service.preview_inventory_csv(
            inventory_csv(), "comma"
        )
        profile = service.create_assurance_profile_version(
            assessment["assessment_id"],
            assessment["revision"],
            "Approved inventory and policy",
            inventory_preview=inventory,
            coverage_mode="authoritative",
        )
        assessment = profile["assessment"]
        version_id = profile["assurance_profile_version"][
            "assurance_profile_version_id"
        ]
        with self.assertRaises(BackendError) as raised:
            service.activate_assurance_profile_version(
                assessment["assessment_id"],
                assessment["revision"],
                version_id,
                False,
            )
        self.assertEqual(
            raised.exception.code, "authoritative_confirmation_required"
        )
        assessment = service.activate_assurance_profile_version(
            assessment["assessment_id"],
            assessment["revision"],
            version_id,
            True,
        )["assessment"]
        return service, assessment, measurement, preview

    def test_full_consensus_policy_evidence_and_report_workflow(self):
        with tempfile.TemporaryDirectory() as directory:
            (
                service,
                assessment,
                measurement,
                baseline_preview,
            ) = self.create_active_foundation(directory)

            classifications = {
                item["bssid"]: item["presence"]["classification"]
                for item in baseline_preview["baseline_model"]["assets"]
            }
            self.assertEqual(
                classifications["AA:BB:CC:00:00:01"], "core"
            )
            self.assertEqual(
                classifications["DE:AD:BE:EF:00:01"], "recurring"
            )
            self.assertEqual(
                classifications["02:00:00:00:00:55"], "singleton"
            )

            current = fixture_scan()
            current["APResults"].append(
                {
                    "ssid": "Example-Corp",
                    "bssid": "AA:BB:CC:00:00:03",
                    "encryption": 4,
                    "channel": 11,
                    "wps": 0,
                }
            )
            preview = service.compare_recon(
                assessment["assessment_id"],
                current,
                self.build_context(measurement, 4),
            )
            self.assertEqual(
                preview["diff"]["comparability"]["status"], "comparable"
            )
            serialized_comparability = json.dumps(
                preview["diff"]["comparability"], sort_keys=True
            )
            self.assertNotIn("quality_score", serialized_comparability)
            self.assertNotIn("coverage_ratio", serialized_comparability)
            self.assertNotIn("detection_ratio", serialized_comparability)
            self.assertTrue(preview["observed_changes"])
            self.assertTrue(preview["policy_deviations"])
            rules = {
                item["rule_id"] for item in preview["security_findings"]
            }
            self.assertEqual(
                rules,
                {
                    "unauthorized_bssid_advertising_protected_ssid",
                    "protected_ssid_encryption_violation",
                },
            )
            for item in preview["observed_changes"]:
                self.assertNotIn("severity", item)
                self.assertIn(
                    item["certainty"],
                    ("confirmed", "probable", "limited"),
                )

            persisted = service.analyze_recon(
                assessment["assessment_id"],
                assessment["revision"],
                current,
                self.build_context(measurement, 4),
            )
            comparison_id = persisted["comparison"]["comparison_id"]
            self.assertEqual(
                persisted["policy_evaluation_status"], "evaluated"
            )
            self.assertEqual(
                len(persisted["lifecycle"]["opened"]),
                len(persisted["policy_deviations"])
                + len(persisted["security_findings"]),
            )
            self.assertEqual(
                persisted["comparison"]["pinned_versions"][
                    "measurement_profile_version_id"
                ],
                measurement["active_version"]["version_id"],
            )

            security = persisted["security_findings"][0]
            bundle = service.get_evidence_bundle(
                assessment["assessment_id"],
                comparison_id,
                security["finding_id"],
            )
            self.assertIsNotNone(bundle["before_after"]["before"])
            self.assertIsNotNone(bundle["before_after"]["after"])
            self.assertTrue(bundle["evidence"])
            self.assertEqual(
                bundle["pinned_versions"][
                    "assurance_profile_version_id"
                ],
                assessment["active_assurance_profile_version"],
            )

            prepared = service.prepare_report(
                assessment["assessment_id"],
                {
                    "type": "comparison",
                    "comparison_id": comparison_id,
                },
                "local_full",
            )
            report = service.generate_report(
                assessment["assessment_id"],
                comparison_id,
                "json",
                None,
                {
                    "type": "comparison",
                    "comparison_id": comparison_id,
                },
                "local_full",
                prepared["scope_digest"],
            )
            self.assertNotIn("content", report)
            self.assertEqual(
                report["export"]["download"]["path"], "/api/download"
            )
            report_path = Path(report["export"]["filename"])
            canonical = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertNotIn("confidence", report_path.read_text(encoding="utf-8"))
            self.assertEqual(
                canonical["scope"]["mode"], "comparison"
            )
            self.assertTrue(canonical["evidence_appendix"]["records"])

            safe_prepared = service.prepare_report(
                assessment["assessment_id"],
                {
                    "type": "comparison",
                    "comparison_id": comparison_id,
                },
                "share_safe",
            )
            safe_report = service.generate_report(
                assessment["assessment_id"],
                comparison_id,
                "html",
                None,
                {
                    "type": "comparison",
                    "comparison_id": comparison_id,
                },
                "share_safe",
                safe_prepared["scope_digest"],
            )
            safe_html = Path(
                safe_report["export"]["filename"]
            ).read_text(encoding="utf-8")
            self.assertNotIn("<script", safe_html.lower())
            self.assertNotIn("AA:BB:CC:00:00:03", safe_html)
            self.assertNotIn("Example-Corp", safe_html)

    def test_comparison_occurrence_is_immutable_across_lifecycle_update(self):
        with tempfile.TemporaryDirectory() as directory:
            service, assessment, measurement, _ = (
                self.create_active_foundation(directory)
            )
            current = fixture_scan()
            current["APResults"][0]["encryption"] = 4
            analyzed = service.analyze_recon(
                assessment["assessment_id"],
                assessment["revision"],
                current,
                self.build_context(measurement, 5),
            )
            comparison_id = analyzed["comparison"]["comparison_id"]
            before = service.store.get_occurrence_set(
                assessment["assessment_id"], comparison_id
            )
            finding = analyzed["findings"][0]
            service.store.update_finding(
                assessment["assessment_id"],
                analyzed["assessment"]["revision"],
                finding["finding_id"],
                "acknowledged",
            )
            after = service.store.get_occurrence_set(
                assessment["assessment_id"], comparison_id
            )
            self.assertEqual(before, after)
            current_report = service.prepare_report(
                assessment["assessment_id"],
                {"type": "assessment_current"},
            )
            history_report = service.prepare_report(
                assessment["assessment_id"],
                {"type": "assessment_history"},
            )
            self.assertNotEqual(
                current_report["scope_digest"],
                history_report["scope_digest"],
            )


if __name__ == "__main__":
    unittest.main()
