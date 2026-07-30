import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "docs" / "schemas" / "repeatable-audits-v1.schema.json"


def load_schema():
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


class RepeatableAuditsSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import jsonschema
            cls.jsonschema = jsonschema
        except ImportError:
            raise unittest.SkipTest("jsonschema library is required for contract validation")

    def setUp(self):
        self.schema = load_schema()
        # Verify schema validity explicitly
        self.jsonschema.Draft7Validator.check_schema(self.schema)

    def validate_def(self, instance, def_name):
        wrapper = {
            "$schema": self.schema["$schema"],
            "$defs": self.schema["$defs"],
            "$ref": f"#/$defs/{def_name}",
        }
        self.jsonschema.validate(instance=instance, schema=wrapper)

    def test_measurement_point_id_ownership(self):
        # Client creation request omits measurement_point_id inside context
        create_req = {
            "assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
            "name": "Floor 2 West Wing",
            "expected_measurement_context": {
                "location_id": "loc_site_alpha",
                "scan_profile_id": "prof_full_dual_band",
                "radio_profile_id": "radio_wlan0_wlan1",
                "interface": "wlan0",
                "declared_bands": ["2.4", "5"],
                "declared_channels": [1, 6, 11, 36, 40],
                "scan_time": 300,
            },
            "expected_assessment_revision": 1,
        }
        self.validate_def(create_req, "createMeasurementPointRequest")

    def test_audit_run_measurement_state_variants(self):
        # 1. Pending variant
        pending = {
            "measurement_id": "arm_0123456789abcdef",
            "audit_run_id": "ar_0123456789abcdef",
            "measurement_point_id": "mp_a1b2c3d4e5f67890",
            "status": "pending",
            "created_at": "2026-07-30T09:00:00Z",
        }
        self.validate_def(pending, "auditRunMeasurementPending")
        self.validate_def(pending, "auditRunMeasurement")

        # 2. Resolved variant
        resolved = {
            "measurement_id": "arm_0123456789abcdef",
            "audit_run_id": "ar_0123456789abcdef",
            "measurement_point_id": "mp_a1b2c3d4e5f67890",
            "status": "resolved",
            "snapshot_id": "snapshot_a1b2c3d4e5f67890",
            "snapshot_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "measurement_profile_id": "mprofile_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
            "measurement_profile_version_id": "mprofile_r0001",
            "measurement_profile_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "baseline_version_id": "baseline_v0001",
            "baseline_type": "consensus",
            "baseline_record_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "assurance_profile_version_id": "assurance_v0001",
            "assurance_profile_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "comparability_status": "comparable",
            "resolved_at": "2026-07-30T09:10:00Z",
        }
        self.validate_def(resolved, "auditRunMeasurementResolved")
        self.validate_def(resolved, "auditRunMeasurement")

        # 3. Completed Consensus variant
        consensus = {
            "measurement_id": "arm_0123456789abcdef",
            "audit_run_id": "ar_0123456789abcdef",
            "measurement_point_id": "mp_a1b2c3d4e5f67890",
            "status": "completed",
            "snapshot_id": "snapshot_a1b2c3d4e5f67890",
            "snapshot_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "measurement_profile_id": "mprofile_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
            "measurement_profile_version_id": "mprofile_r0001",
            "measurement_profile_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "baseline_version_id": "baseline_v0001",
            "baseline_type": "consensus",
            "baseline_model_id": "bmodel_1122334455667788",
            "baseline_model_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "baseline_record_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "assurance_profile_version_id": "assurance_v0001",
            "assurance_profile_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "comparability_status": "comparable",
            "comparison_id": "comparison_0123456789abcdef",
            "comparison_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "occurrence_set_id": "occurrence_fedcba9876543210",
            "evidence_ids": ["evidence_123456789abc"],
            "completed_at": "2026-07-30T09:15:00Z",
        }
        self.validate_def(consensus, "auditRunMeasurementCompletedConsensus")
        self.validate_def(consensus, "auditRunMeasurement")

        # 4. Completed Single Scan variant
        single_scan = {
            "measurement_id": "arm_0123456789abcdef",
            "audit_run_id": "ar_0123456789abcdef",
            "measurement_point_id": "mp_a1b2c3d4e5f67890",
            "status": "completed",
            "snapshot_id": "snapshot_a1b2c3d4e5f67890",
            "snapshot_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "measurement_profile_id": "mprofile_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
            "measurement_profile_version_id": "mprofile_r0001",
            "measurement_profile_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "baseline_version_id": "baseline_v0001",
            "baseline_type": "single_scan",
            "baseline_snapshot_id": "snapshot_a1b2c3d4e5f67890",
            "baseline_snapshot_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "baseline_record_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "assurance_profile_version_id": "assurance_v0001",
            "assurance_profile_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "comparability_status": "comparable",
            "comparison_id": "comparison_0123456789abcdef",
            "comparison_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "occurrence_set_id": "occurrence_fedcba9876543210",
            "evidence_ids": ["evidence_123456789abc"],
            "completed_at": "2026-07-30T09:15:00Z",
        }
        self.validate_def(single_scan, "auditRunMeasurementCompletedSingleScan")
        self.validate_def(single_scan, "auditRunMeasurement")

        # 5. Failed variant
        failed = {
            "measurement_id": "arm_0123456789abcdef",
            "audit_run_id": "ar_0123456789abcdef",
            "measurement_point_id": "mp_a1b2c3d4e5f67890",
            "status": "failed",
            "failed_stage": "resolution",
            "error_code": "invalid_recon",
            "error_message": "Malformed Hak5 Recon scan payload",
            "failed_at": "2026-07-30T09:05:00Z",
            "retry_target": "pending",
        }
        self.validate_def(failed, "auditRunMeasurementFailed")
        self.validate_def(failed, "auditRunMeasurement")

    def test_negative_measurement_state_validations(self):
        # Negative 1: pending measurement cannot contain completed fields
        bad_pending = {
            "measurement_id": "arm_0123456789abcdef",
            "audit_run_id": "ar_0123456789abcdef",
            "measurement_point_id": "mp_a1b2c3d4e5f67890",
            "status": "pending",
            "created_at": "2026-07-30T09:00:00Z",
            "completed_at": "2026-07-30T09:15:00Z",
        }
        with self.assertRaises(self.jsonschema.ValidationError):
            self.validate_def(bad_pending, "auditRunMeasurementPending")

        # Negative 2: consensus measurement cannot contain single-scan fields
        bad_consensus = {
            "measurement_id": "arm_0123456789abcdef",
            "audit_run_id": "ar_0123456789abcdef",
            "measurement_point_id": "mp_a1b2c3d4e5f67890",
            "status": "completed",
            "snapshot_id": "snapshot_a1b2c3d4e5f67890",
            "snapshot_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "measurement_profile_id": "mprofile_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
            "measurement_profile_version_id": "mprofile_r0001",
            "measurement_profile_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "baseline_version_id": "baseline_v0001",
            "baseline_type": "consensus",
            "baseline_model_id": "bmodel_1122334455667788",
            "baseline_model_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "baseline_snapshot_id": "snapshot_a1b2c3d4e5f67890",  # Prohibited in consensus
            "baseline_record_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "assurance_profile_version_id": "assurance_v0001",
            "assurance_profile_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "comparability_status": "comparable",
            "comparison_id": "comparison_0123456789abcdef",
            "comparison_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "occurrence_set_id": "occurrence_fedcba9876543210",
            "evidence_ids": ["evidence_123456789abc"],
            "completed_at": "2026-07-30T09:15:00Z",
        }
        with self.assertRaises(self.jsonschema.ValidationError):
            self.validate_def(bad_consensus, "auditRunMeasurementCompletedConsensus")

        # Negative 3: arbitrary unknown fields are rejected
        with_unknown = {
            "measurement_id": "arm_0123456789abcdef",
            "audit_run_id": "ar_0123456789abcdef",
            "measurement_point_id": "mp_a1b2c3d4e5f67890",
            "status": "pending",
            "created_at": "2026-07-30T09:00:00Z",
            "unknown_field": "disallowed",
        }
        with self.assertRaises(self.jsonschema.ValidationError):
            self.validate_def(with_unknown, "auditRunMeasurementPending")

    def test_all_action_requests_and_responses(self):
        # 1. create_measurement_point
        self.validate_def(
            {
                "assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
                "name": "Point Alpha",
                "expected_measurement_context": {
                    "location_id": "loc_1",
                    "scan_profile_id": "prof_1",
                    "radio_profile_id": "radio_1",
                    "interface": "wlan0",
                    "declared_bands": ["2.4"],
                    "declared_channels": [1],
                    "scan_time": 300,
                },
                "expected_assessment_revision": 1,
            },
            "createMeasurementPointRequest",
        )

        # 2. list_measurement_points
        self.validate_def({"assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890"}, "listMeasurementPointsRequest")

        # 3. get_measurement_point
        self.validate_def(
            {"assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890", "measurement_point_id": "mp_a1b2c3d4e5f67890"},
            "getMeasurementPointRequest",
        )

        # 4. update_measurement_point
        self.validate_def(
            {
                "assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
                "measurement_point_id": "mp_a1b2c3d4e5f67890",
                "expected_assessment_revision": 1,
                "expected_measurement_point_revision": 1,
            },
            "updateMeasurementPointRequest",
        )

        # 5. archive_measurement_point
        self.validate_def(
            {
                "assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
                "measurement_point_id": "mp_a1b2c3d4e5f67890",
                "expected_assessment_revision": 1,
                "expected_measurement_point_revision": 1,
            },
            "archiveMeasurementPointRequest",
        )

        # 6. create_audit_run
        self.validate_def(
            {
                "assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
                "title": "Audit 1",
                "pinned_assurance_profile_version_id": "assurance_v0001",
                "measurement_point_ids": ["mp_a1b2c3d4e5f67890"],
                "expected_assessment_revision": 1,
            },
            "createAuditRunRequest",
        )

        # 7. list_audit_runs
        self.validate_def({"assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890"}, "listAuditRunsRequest")

        # 8. get_audit_run
        self.validate_def(
            {"assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890", "audit_run_id": "ar_0123456789abcdef"},
            "getAuditRunRequest",
        )

        # 9. start_audit_run
        self.validate_def(
            {
                "assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
                "audit_run_id": "ar_0123456789abcdef",
                "expected_assessment_revision": 1,
                "expected_audit_run_revision": 1,
            },
            "startAuditRunRequest",
        )

        # 10. cancel_audit_run
        self.validate_def(
            {
                "assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
                "audit_run_id": "ar_0123456789abcdef",
                "expected_assessment_revision": 1,
                "expected_audit_run_revision": 1,
            },
            "cancelAuditRunRequest",
        )

        # 11. resolve_audit_measurement
        self.validate_def(
            {
                "assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
                "audit_run_id": "ar_0123456789abcdef",
                "measurement_point_id": "mp_a1b2c3d4e5f67890",
                "raw_recon_json": {},
                "measurement_profile_id": "mprofile_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
                "baseline_version_id": "baseline_v0001",
                "expected_assessment_revision": 1,
                "expected_audit_run_revision": 1,
            },
            "resolveAuditMeasurementRequest",
        )

        # 12. retry_audit_measurement
        self.validate_def(
            {
                "assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
                "audit_run_id": "ar_0123456789abcdef",
                "measurement_point_id": "mp_a1b2c3d4e5f67890",
                "expected_assessment_revision": 1,
                "expected_audit_run_revision": 1,
            },
            "retryAuditMeasurementRequest",
        )

        # 13. save_audit_measurement_comparison
        self.validate_def(
            {
                "assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
                "audit_run_id": "ar_0123456789abcdef",
                "measurement_point_id": "mp_a1b2c3d4e5f67890",
                "expected_assessment_revision": 1,
                "expected_audit_run_revision": 1,
            },
            "saveAuditMeasurementComparisonRequest",
        )

        # 14. complete_audit_run
        self.validate_def(
            {
                "assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
                "audit_run_id": "ar_0123456789abcdef",
                "expected_assessment_revision": 1,
                "expected_audit_run_revision": 1,
            },
            "completeAuditRunRequest",
        )

        # 15. generate_audit_run_report
        self.validate_def(
            {
                "assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
                "audit_run_id": "ar_0123456789abcdef",
                "format": "json",
            },
            "generateAuditRunReportRequest",
        )


if __name__ == "__main__":
    unittest.main()
