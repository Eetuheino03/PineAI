import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "projects" / "PineAI" / "src" / "assets"
sys.path.insert(0, str(ASSETS))

from pineai_backend.assurance_service import AssuranceService  # noqa: E402
from pineai_backend.audit_run_report import AuditRunReportService  # noqa: E402
from pineai_backend.config import ensure_pseudonymization_key  # noqa: E402
from pineai_backend.repeatable_audit_service import (  # noqa: E402
    RepeatableAuditService,
)
from pineai_backend.repeatable_audit_store import (  # noqa: E402
    RepeatableAuditStore,
)


RECON_FIXTURE = ROOT / "tests" / "fixtures" / "recon_basic.json"


class RepeatableAuditServiceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = self.temporary.name
        ensure_pseudonymization_key(self.directory)
        self.store = RepeatableAuditStore(self.directory)
        self.assurance = AssuranceService(
            config_dir=self.directory, store=self.store
        )
        self.workflow = RepeatableAuditService(
            config_dir=self.directory, store=self.store
        )
        self.profile = self.assurance.create_measurement_profile(
            {
                "name": "Saved Recon profile",
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
        )["measurement_profile"]
        assessment = self.assurance.create_assessment(
            {"name": "Field audit", "location": "Lab", "notes": ""}
        )
        self.assessment_id = assessment["assessment_id"]
        point_result = self.store.create_measurement_point(
            self.assessment_id,
            assessment["revision"],
            "North desk",
            "Blue floor marker",
            "Keep the antenna vertical",
        )
        self.point = point_result["measurement_point"]
        self.scan = json.loads(RECON_FIXTURE.read_text(encoding="utf-8"))
        baseline = self.assurance.create_baseline_version(
            self.assessment_id,
            point_result["assessment_revision"],
            self.scan,
            self.scan_metadata("baseline", "2026-07-31T09:00:00Z"),
            "Approved north desk",
        )
        self.baseline_id = baseline["baseline_version"][
            "baseline_version_id"
        ]
        inventory = self.assurance.preview_inventory_csv(
            "site,ssid,bssid,vendor,role,approved\n"
            "Lab,Example-Corp,AA:BB:CC:00:00:01,Unknown,corp,true\n",
            "comma",
        )
        assurance = self.assurance.create_assurance_profile_version(
            self.assessment_id,
            baseline["assessment"]["revision"],
            "Approved partial inventory",
            inventory_preview=inventory,
            coverage_mode="partial",
        )
        self.assurance_id = assurance["assurance_profile_version"][
            "assurance_profile_version_id"
        ]

    def revision(self):
        return self.store.get(self.assessment_id, 0, 1)["revision"]

    def scan_metadata(self, scan_id, date):
        version = self.profile["active_version"]
        return {
            "scan_id": scan_id,
            "date": date,
            "scan_time": 180,
            "coverage": ["2.4"],
            "source": "hak5_recon",
            "measurement_context": {
                "location_id": self.assessment_id,
                "measurement_point_id": self.point["measurement_point_id"],
                "scan_profile_id": "saved-recon",
                "radio_profile_id": "wlan1",
                "interface": "wlan1mon",
                "declared_bands": ["2.4"],
                "declared_channels": [1, 6, 11],
                "measurement_profile_id": self.profile[
                    "measurement_profile_id"
                ],
                "measurement_profile_version_id": version["version_id"],
                "measurement_profile_digest": version["digest"],
            },
        }

    def create_started_run(self):
        version = self.profile["active_version"]
        created = self.store.create_audit_run(
            self.assessment_id,
            self.revision(),
            {
                "name": "July round",
                "description": "Operator driven",
                "assurance_profile_version_id": self.assurance_id,
                "assignments": [
                    {
                        "measurement_point_id": self.point[
                            "measurement_point_id"
                        ],
                        "measurement_profile_id": self.profile[
                            "measurement_profile_id"
                        ],
                        "measurement_profile_version_id": version[
                            "version_id"
                        ],
                        "baseline_version_id": self.baseline_id,
                    }
                ],
            },
        )
        started = self.store.start_audit_run(
            self.assessment_id,
            created["assessment_revision"],
            created["audit_run"]["audit_run_id"],
            created["audit_run"]["revision"],
        )
        return started

    def test_complete_raw_recon_workflow_and_report_are_deterministic(self):
        started = self.create_started_run()
        measurement = started["measurements"][0]
        resolved = self.workflow.resolve_measurement(
            self.assessment_id,
            started["assessment_revision"],
            started["audit_run"]["audit_run_id"],
            started["audit_run"]["revision"],
            measurement["measurement_id"],
            measurement["revision"],
            self.scan,
            {
                "scan_id": "current",
                "date": "2026-07-31T10:00:00Z",
                "scan_time": 180,
                "coverage": ["2.4"],
                "measurement_context": {
                    "location_id": "untrusted-override",
                    "measurement_point_id": "untrusted-override",
                },
            },
        )
        self.assertEqual(resolved["measurement"]["status"], "resolved")
        snapshot = self.store.get_snapshot(
            self.assessment_id, resolved["measurement"]["snapshot_id"]
        )
        context = snapshot["scan_metadata"]["measurement_context"]
        self.assertEqual(context["location_id"], self.assessment_id)
        self.assertEqual(
            context["measurement_point_id"],
            self.point["measurement_point_id"],
        )
        self.assertEqual(
            context["measurement_profile_digest"],
            measurement["measurement_profile_digest"],
        )

        compared = self.workflow.save_comparison(
            self.assessment_id,
            resolved["assessment_revision"],
            resolved["audit_run"]["audit_run_id"],
            resolved["audit_run"]["revision"],
            measurement["measurement_id"],
            resolved["measurement"]["revision"],
        )
        self.assertEqual(compared["measurement"]["status"], "completed")
        completed = self.store.complete_audit_run(
            self.assessment_id,
            compared["assessment_revision"],
            compared["audit_run"]["audit_run_id"],
            compared["audit_run"]["revision"],
        )
        reporter = AuditRunReportService(self.store)
        with mock.patch.object(
            self.store,
            "_read_events",
            wraps=self.store._read_events,
        ) as event_log_reads:
            first = reporter.generate(
                self.assessment_id,
                completed["audit_run"]["audit_run_id"],
                "json",
                "local_full",
            )
        self.assertEqual(event_log_reads.call_count, 1)
        reopened = AuditRunReportService(
            RepeatableAuditStore(self.directory)
        ).generate(
            self.assessment_id,
            completed["audit_run"]["audit_run_id"],
            "json",
            "local_full",
        )
        self.assertEqual(first, reopened)
        self.assertIn("comparison_", first["content"])
        for path in Path(self.directory).rglob("*.json"):
            self.assertNotIn(
                '"APResults"', path.read_text(encoding="utf-8")
            )

    def test_invalid_recon_is_recorded_and_retry_returns_to_pending(self):
        started = self.create_started_run()
        measurement = started["measurements"][0]
        invalid_scan = copy.deepcopy(self.scan)
        invalid_scan["APResults"][0]["bssid"] = "not-a-mac"
        failed = self.workflow.resolve_measurement(
            self.assessment_id,
            started["assessment_revision"],
            started["audit_run"]["audit_run_id"],
            started["audit_run"]["revision"],
            measurement["measurement_id"],
            measurement["revision"],
            invalid_scan,
            {"scan_id": "bad", "date": "2026-07-31T10:00:00Z"},
        )
        self.assertEqual(failed["measurement"]["status"], "failed")
        self.assertEqual(failed["measurement"]["failed_stage"], "resolution")
        self.assertEqual(failed["measurement"]["error_code"], "invalid_recon")
        retried = self.store.retry_audit_measurement(
            self.assessment_id,
            failed["assessment_revision"],
            failed["audit_run"]["audit_run_id"],
            failed["audit_run"]["revision"],
            measurement["measurement_id"],
            failed["measurement"]["revision"],
        )
        self.assertEqual(retried["measurement"]["status"], "pending")

    def test_invalid_scan_timestamp_is_recorded_as_resolution_failure(self):
        started = self.create_started_run()
        measurement = started["measurements"][0]
        failed = self.workflow.resolve_measurement(
            self.assessment_id,
            started["assessment_revision"],
            started["audit_run"]["audit_run_id"],
            started["audit_run"]["revision"],
            measurement["measurement_id"],
            measurement["revision"],
            self.scan,
            {"scan_id": "bad-time", "date": "not-rfc3339"},
        )
        self.assertEqual(failed["measurement"]["status"], "failed")
        self.assertEqual(
            failed["measurement"]["error_code"], "invalid_scan_metadata"
        )

    def test_capabilities_freeze_resource_and_safety_boundaries(self):
        result = self.workflow.capabilities()
        self.assertEqual(result["product"]["name"], "PineAssure")
        self.assertEqual(
            result["limits"]["active_measurement_points_per_assessment"],
            16,
        )
        self.assertEqual(result["limits"]["simultaneous_scan_processing"], 1)
        self.assertFalse(result["hardware_calibrated"])
        self.assertIn("radio_control", result["strict_exclusions"])


if __name__ == "__main__":
    unittest.main()
