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

    def test_assessment_capacity_response_object(self):
        capacity = {
            "snapshot_limit": 100,
            "snapshot_used": 42,
            "snapshot_available": 58,
            "comparison_limit": 100,
            "comparison_used": 40,
            "comparison_available": 60,
            "event_limit": 5000,
            "event_used": 281,
            "event_available": 4719,
            "event_reserved_for_run_closure": 4,
            "event_available_for_non_terminal": 4715,
        }
        self.validate_def(capacity, "assessmentCapacity")

        audit_run_sample = {
            "audit_run_id": "ar_0123456789abcdef",
            "assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
            "title": "Audit 1",
            "status": "draft",
            "created_at": "2026-07-30T09:00:00Z",
            "pinned_assurance_profile_version_id": "assurance_v0001",
            "pinned_assurance_profile_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "measurement_point_ids": ["mp_a1b2c3d4e5f67890"],
            "revision": 1,
        }
        pending_measurement = {
            "measurement_id": "arm_0123456789abcdef",
            "audit_run_id": "ar_0123456789abcdef",
            "measurement_point_id": "mp_a1b2c3d4e5f67890",
            "status": "pending",
            "created_at": "2026-07-30T09:00:00Z",
        }

        # Response envelope with revisions & capacity
        resolve_resp = {
            "schema_version": "1.0",
            "assessment_revision": 12,
            "assessment_capacity": capacity,
            "audit_run": audit_run_sample,
            "measurement": pending_measurement,
        }
        self.validate_def(resolve_resp, "resolveAuditMeasurementResponse")
        self.validate_def(resolve_resp, "retryAuditMeasurementResponse")
        self.validate_def(resolve_resp, "saveAuditMeasurementComparisonResponse")

        create_resp = {
            "schema_version": "1.0",
            "audit_run": audit_run_sample,
            "ready_to_start": True,
            "assessment_capacity": capacity,
        }
        self.validate_def(create_resp, "createAuditRunResponse")

    def test_three_failed_measurement_discriminated_branches(self):
        # 1. Failed Resolution branch
        failed_res = {
            "measurement_id": "arm_0123456789abcdef",
            "audit_run_id": "ar_0123456789abcdef",
            "measurement_point_id": "mp_a1b2c3d4e5f67890",
            "status": "failed",
            "failed_stage": "resolution",
            "error_code": "scan_processing_failed",
            "error_message": "Normalization error",
            "failed_at": "2026-07-30T10:00:00Z",
            "retry_target": "pending",
        }
        self.validate_def(failed_res, "auditRunMeasurementFailedResolution")
        self.validate_def(failed_res, "auditRunMeasurement")

        # 2. Failed Comparison Consensus branch
        failed_comp_consensus = {
            "measurement_id": "arm_0123456789abcdef",
            "audit_run_id": "ar_0123456789abcdef",
            "measurement_point_id": "mp_a1b2c3d4e5f67890",
            "status": "failed",
            "failed_stage": "comparison",
            "retry_target": "resolved",
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
            "resolved_at": "2026-07-30T10:00:00Z",
            "error_code": "engine_comparison_failed",
            "error_message": "Comparison execution error",
            "failed_at": "2026-07-30T10:05:00Z",
        }
        self.validate_def(failed_comp_consensus, "auditRunMeasurementFailedComparisonConsensus")
        self.validate_def(failed_comp_consensus, "auditRunMeasurement")

        # 3. Failed Comparison Single Scan branch
        failed_comp_single = {
            "measurement_id": "arm_0123456789abcdef",
            "audit_run_id": "ar_0123456789abcdef",
            "measurement_point_id": "mp_a1b2c3d4e5f67890",
            "status": "failed",
            "failed_stage": "comparison",
            "retry_target": "resolved",
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
            "resolved_at": "2026-07-30T10:00:00Z",
            "error_code": "engine_comparison_failed",
            "error_message": "Comparison execution error",
            "failed_at": "2026-07-30T10:05:00Z",
        }
        self.validate_def(failed_comp_single, "auditRunMeasurementFailedComparisonSingleScan")
        self.validate_def(failed_comp_single, "auditRunMeasurement")

        # Negative checks:
        # Failed resolution prohibiting snapshot/profile fields
        failed_res_bad = dict(failed_res, snapshot_id="snapshot_a1b2c3d4e5f67890")
        with self.assertRaises(self.jsonschema.ValidationError):
            self.validate_def(failed_res_bad, "auditRunMeasurementFailedResolution")

        # Failed comparison consensus prohibiting single scan fields
        failed_comp_bad_mix = dict(failed_comp_consensus, baseline_snapshot_id="snapshot_a1b2c3d4e5f67890")
        with self.assertRaises(self.jsonschema.ValidationError):
            self.validate_def(failed_comp_bad_mix, "auditRunMeasurementFailedComparisonConsensus")

    def test_evidence_ids_bounds(self):
        ev_100 = [f"evidence_{i:012x}" for i in range(100)]
        consensus_100 = {
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
            "evidence_ids": ev_100,
            "completed_at": "2026-07-30T09:15:00Z",
        }
        self.validate_def(consensus_100, "auditRunMeasurementCompletedConsensus")

        ev_101 = [f"evidence_{i:012x}" for i in range(101)]
        consensus_101 = dict(consensus_100, evidence_ids=ev_101)
        with self.assertRaises(self.jsonschema.ValidationError):
            self.validate_def(consensus_101, "auditRunMeasurementCompletedConsensus")

    def test_measurement_point_ids_bounds_and_uniqueness(self):
        pts_64 = [f"mp_{i:016x}" for i in range(64)]
        run_req_64 = {
            "assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
            "title": "Run 64 Points",
            "pinned_assurance_profile_version_id": "assurance_v0001",
            "measurement_point_ids": pts_64,
            "expected_assessment_revision": 1,
        }
        self.validate_def(run_req_64, "createAuditRunRequest")

        pts_65 = [f"mp_{i:016x}" for i in range(65)]
        run_req_65 = dict(run_req_64, measurement_point_ids=pts_65)
        with self.assertRaises(self.jsonschema.ValidationError):
            self.validate_def(run_req_65, "createAuditRunRequest")

        # Duplicate point IDs rejected
        pts_dup = [f"mp_{i:016x}" for i in range(63)] + ["mp_0000000000000000"]
        run_req_dup = dict(run_req_64, measurement_point_ids=pts_dup)
        with self.assertRaises(self.jsonschema.ValidationError):
            self.validate_def(run_req_dup, "createAuditRunRequest")

    def test_worst_case_audit_run_document_serialization_below_limit(self):
        ev_100 = [f"evidence_{i:012x}" for i in range(100)]
        measurements = []
        for i in range(64):
            measurements.append({
                "measurement_id": f"arm_{i:016x}",
                "audit_run_id": "ar_0123456789abcdef",
                "measurement_point_id": f"mp_{i:016x}",
                "status": "completed",
                "source_recon_id": "recon_" + "x" * 120,
                "snapshot_id": f"snapshot_{i:016x}",
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
                "comparison_id": f"comparison_{i:016x}",
                "comparison_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "occurrence_set_id": f"occurrence_{i:016x}",
                "evidence_ids": ev_100,
                "completed_at": "2026-07-30T09:15:00Z",
            })

        audit_run_doc = {
            "schema_version": "1.0",
            "storage_writer_version": "1.0",
            "audit_run_id": "ar_0123456789abcdef",
            "assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
            "title": "T" * 128,
            "status": "completed",
            "created_at": "2026-07-30T09:00:00Z",
            "started_at": "2026-07-30T09:05:00Z",
            "completed_at": "2026-07-30T09:30:00Z",
            "due_at": "2026-08-15T17:00:00Z",
            "pinned_assurance_profile_version_id": "assurance_v0001",
            "pinned_assurance_profile_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "measurement_point_ids": [f"mp_{i:016x}" for i in range(64)],
            "revision": 99,
            "measurements": measurements,
        }

        serialized = json.dumps(audit_run_doc, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        size = len(serialized)
        max_limit = 512 * 1024
        self.assertLess(size, max_limit, f"AuditRun serialized size {size} exceeds max limit {max_limit}")

    def test_measurement_points_persistence_envelope_size(self):
        def make_mp(i):
            return {
                "measurement_point_id": f"mp_{i:016x}",
                "assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
                "name": "N" * 128,
                "description": "D" * 512,
                "expected_measurement_context": {
                    "location_id": "L" * 128,
                    "measurement_point_id": f"mp_{i:016x}",
                    "scan_profile_id": "S" * 128,
                    "radio_profile_id": "R" * 128,
                    "interface": "I" * 64,
                    "declared_bands": ["2.4", "5"],
                    "declared_channels": list(range(1, 197)) + [197, 198, 199, 200],
                    "scan_time": 3600,
                },
                "status": "archived",
                "created_at": "2026-07-30T09:00:00Z",
                "archived_at": "2026-07-30T09:05:00Z",
                "revision": 99,
            }

        # Test 44 maximum-sized records fit under 256 KB with >20% headroom
        doc_44 = {
            "schema_version": "1.0",
            "storage_writer_version": "1.0",
            "assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
            "updated_at": "2026-07-30T10:00:00Z",
            "measurement_points": [make_mp(i) for i in range(44)],
        }
        b_44 = json.dumps(doc_44, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        size_44 = len(b_44)
        limit_256 = 256 * 1024
        headroom_256 = (limit_256 - size_44) / limit_256 * 100
        self.assertLess(size_44, limit_256)
        self.assertGreaterEqual(headroom_256, 20.0)

        # Test 90 maximum-sized records fit under 512 KB with >20% headroom
        doc_90 = {
            "schema_version": "1.0",
            "storage_writer_version": "1.0",
            "assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
            "updated_at": "2026-07-30T10:00:00Z",
            "measurement_points": [make_mp(i) for i in range(90)],
        }
        b_90 = json.dumps(doc_90, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        size_90 = len(b_90)
        limit_512 = 512 * 1024
        headroom_512 = (limit_512 - size_90) / limit_512 * 100
        self.assertLess(size_90, limit_512)
        self.assertGreaterEqual(headroom_512, 20.0)

    def test_negative_context_string_bounds(self):
        bad_loc = {
            "assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
            "name": "Point Alpha",
            "expected_measurement_context": {
                "location_id": "L" * 129,
                "scan_profile_id": "prof_1",
                "radio_profile_id": "radio_1",
                "interface": "wlan0",
                "declared_bands": ["2.4"],
                "declared_channels": [1],
                "scan_time": 300,
            },
            "expected_assessment_revision": 1,
        }
        with self.assertRaises(self.jsonschema.ValidationError):
            self.validate_def(bad_loc, "createMeasurementPointRequest")


if __name__ == "__main__":
    unittest.main()
