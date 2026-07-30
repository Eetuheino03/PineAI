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

    def test_assessment_capacity_object(self):
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

        create_resp = {
            "schema_version": "1.0",
            "audit_run": audit_run_sample,
            "ready_to_start": True,
            "assessment_capacity": capacity,
        }
        self.validate_def(create_resp, "createAuditRunResponse")

    def _sample_capacity(self):
        return {
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

    def _sample_audit_run(self):
        return {
            "audit_run_id": "ar_0123456789abcdef",
            "assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
            "title": "Audit 1",
            "status": "in_progress",
            "created_at": "2026-07-30T09:00:00Z",
            "pinned_assurance_profile_version_id": "assurance_v0001",
            "pinned_assurance_profile_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "measurement_point_ids": ["mp_a1b2c3d4e5f67890"],
            "revision": 2,
        }

    def _sample_pending(self):
        return {
            "measurement_id": "arm_0123456789abcdef",
            "audit_run_id": "ar_0123456789abcdef",
            "measurement_point_id": "mp_a1b2c3d4e5f67890",
            "status": "pending",
            "created_at": "2026-07-30T09:00:00Z",
        }

    def _sample_resolved_consensus(self):
        return {
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
            "baseline_model_id": "bmodel_1122334455667788",
            "baseline_model_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "baseline_record_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "assurance_profile_version_id": "assurance_v0001",
            "assurance_profile_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "comparability_status": "comparable",
            "resolved_at": "2026-07-30T10:00:00Z",
        }

    def _sample_resolved_single_scan(self):
        return {
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
            "baseline_type": "single_scan",
            "baseline_snapshot_id": "snapshot_a1b2c3d4e5f67890",
            "baseline_snapshot_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "baseline_record_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "assurance_profile_version_id": "assurance_v0001",
            "assurance_profile_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "comparability_status": "comparable",
            "resolved_at": "2026-07-30T10:00:00Z",
        }

    def _sample_completed_consensus(self):
        ev_100 = [f"evidence_{i:012x}" for i in range(100)]
        return {
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

    def _sample_completed_single_scan(self):
        ev_100 = [f"evidence_{i:012x}" for i in range(100)]
        return {
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
            "evidence_ids": ev_100,
            "completed_at": "2026-07-30T09:15:00Z",
        }

    def _sample_failed_resolution(self):
        return {
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

    def _sample_failed_comparison_consensus(self):
        return {
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

    def _sample_failed_comparison_single_scan(self):
        return {
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

    def test_action_specific_response_outcomes(self):
        capacity = self._sample_capacity()
        run = self._sample_audit_run()

        def make_resp(m):
            return {
                "schema_version": "1.0",
                "assessment_revision": 12,
                "assessment_capacity": capacity,
                "audit_run": run,
                "measurement": m,
            }

        # 1. Resolve response:
        # Accepted: resolved consensus, resolved single scan, failed resolution
        self.validate_def(make_resp(self._sample_resolved_consensus()), "resolveAuditMeasurementResponse")
        self.validate_def(make_resp(self._sample_resolved_single_scan()), "resolveAuditMeasurementResponse")
        self.validate_def(make_resp(self._sample_failed_resolution()), "resolveAuditMeasurementResponse")

        # Rejected by resolve outcome: pending, completed
        with self.assertRaises(self.jsonschema.ValidationError):
            self.validate_def(make_resp(self._sample_pending()), "resolveAuditMeasurementResponse")
        with self.assertRaises(self.jsonschema.ValidationError):
            self.validate_def(make_resp(self._sample_completed_consensus()), "resolveAuditMeasurementResponse")

        # 2. Retry response:
        # Accepted: pending, resolved consensus, resolved single scan
        self.validate_def(make_resp(self._sample_pending()), "retryAuditMeasurementResponse")
        self.validate_def(make_resp(self._sample_resolved_consensus()), "retryAuditMeasurementResponse")
        self.validate_def(make_resp(self._sample_resolved_single_scan()), "retryAuditMeasurementResponse")

        # Rejected by retry outcome: completed, failed
        with self.assertRaises(self.jsonschema.ValidationError):
            self.validate_def(make_resp(self._sample_completed_consensus()), "retryAuditMeasurementResponse")
        with self.assertRaises(self.jsonschema.ValidationError):
            self.validate_def(make_resp(self._sample_failed_resolution()), "retryAuditMeasurementResponse")

        # 3. Save comparison response:
        # Accepted: completed consensus, completed single scan, failed comparison consensus, failed comparison single scan
        self.validate_def(make_resp(self._sample_completed_consensus()), "saveAuditMeasurementComparisonResponse")
        self.validate_def(make_resp(self._sample_completed_single_scan()), "saveAuditMeasurementComparisonResponse")
        self.validate_def(make_resp(self._sample_failed_comparison_consensus()), "saveAuditMeasurementComparisonResponse")
        self.validate_def(make_resp(self._sample_failed_comparison_single_scan()), "saveAuditMeasurementComparisonResponse")

        # Rejected by comparison outcome: pending, resolved
        with self.assertRaises(self.jsonschema.ValidationError):
            self.validate_def(make_resp(self._sample_pending()), "saveAuditMeasurementComparisonResponse")
        with self.assertRaises(self.jsonschema.ValidationError):
            self.validate_def(make_resp(self._sample_resolved_consensus()), "saveAuditMeasurementComparisonResponse")

    def test_full_eight_measurement_union_branches_positive(self):
        # Proves all 8 branches validate against both their specific definition and the auditRunMeasurement union
        self.validate_def(self._sample_pending(), "auditRunMeasurementPending")
        self.validate_def(self._sample_pending(), "auditRunMeasurement")

        self.validate_def(self._sample_resolved_consensus(), "auditRunMeasurementResolvedConsensus")
        self.validate_def(self._sample_resolved_consensus(), "auditRunMeasurement")

        self.validate_def(self._sample_resolved_single_scan(), "auditRunMeasurementResolvedSingleScan")
        self.validate_def(self._sample_resolved_single_scan(), "auditRunMeasurement")

        self.validate_def(self._sample_completed_consensus(), "auditRunMeasurementCompletedConsensus")
        self.validate_def(self._sample_completed_consensus(), "auditRunMeasurement")

        self.validate_def(self._sample_completed_single_scan(), "auditRunMeasurementCompletedSingleScan")
        self.validate_def(self._sample_completed_single_scan(), "auditRunMeasurement")

        self.validate_def(self._sample_failed_resolution(), "auditRunMeasurementFailedResolution")
        self.validate_def(self._sample_failed_resolution(), "auditRunMeasurement")

        self.validate_def(self._sample_failed_comparison_consensus(), "auditRunMeasurementFailedComparisonConsensus")
        self.validate_def(self._sample_failed_comparison_consensus(), "auditRunMeasurement")

        self.validate_def(self._sample_failed_comparison_single_scan(), "auditRunMeasurementFailedComparisonSingleScan")
        self.validate_def(self._sample_failed_comparison_single_scan(), "auditRunMeasurement")

    def test_full_measurement_union_negative_checks(self):
        # 1. resolved consensus rejects single-scan baseline fields
        bad_res_cons = dict(self._sample_resolved_consensus(), baseline_snapshot_id="snapshot_a1b2c3d4e5f67890")
        with self.assertRaises(self.jsonschema.ValidationError):
            self.validate_def(bad_res_cons, "auditRunMeasurementResolvedConsensus")
        with self.assertRaises(self.jsonschema.ValidationError):
            self.validate_def(bad_res_cons, "auditRunMeasurement")

        # 2. resolved single scan rejects consensus fields
        bad_res_single = dict(self._sample_resolved_single_scan(), baseline_model_id="bmodel_1122334455667788")
        with self.assertRaises(self.jsonschema.ValidationError):
            self.validate_def(bad_res_single, "auditRunMeasurementResolvedSingleScan")
        with self.assertRaises(self.jsonschema.ValidationError):
            self.validate_def(bad_res_single, "auditRunMeasurement")

        # 3. completed consensus rejects single-scan fields
        bad_comp_cons = dict(self._sample_completed_consensus(), baseline_snapshot_id="snapshot_a1b2c3d4e5f67890")
        with self.assertRaises(self.jsonschema.ValidationError):
            self.validate_def(bad_comp_cons, "auditRunMeasurementCompletedConsensus")
        with self.assertRaises(self.jsonschema.ValidationError):
            self.validate_def(bad_comp_cons, "auditRunMeasurement")

        # 4. completed single scan rejects consensus fields
        bad_comp_single = dict(self._sample_completed_single_scan(), baseline_model_id="bmodel_1122334455667788")
        with self.assertRaises(self.jsonschema.ValidationError):
            self.validate_def(bad_comp_single, "auditRunMeasurementCompletedSingleScan")
        with self.assertRaises(self.jsonschema.ValidationError):
            self.validate_def(bad_comp_single, "auditRunMeasurement")

        # 5. pending rejects resolved/completed/failure fields
        bad_pending = dict(self._sample_pending(), snapshot_id="snapshot_a1b2c3d4e5f67890")
        with self.assertRaises(self.jsonschema.ValidationError):
            self.validate_def(bad_pending, "auditRunMeasurementPending")
        with self.assertRaises(self.jsonschema.ValidationError):
            self.validate_def(bad_pending, "auditRunMeasurement")

        # 6. failed resolution rejects snapshot and contract-pin fields
        bad_failed_res = dict(self._sample_failed_resolution(), snapshot_id="snapshot_a1b2c3d4e5f67890")
        with self.assertRaises(self.jsonschema.ValidationError):
            self.validate_def(bad_failed_res, "auditRunMeasurementFailedResolution")
        with self.assertRaises(self.jsonschema.ValidationError):
            self.validate_def(bad_failed_res, "auditRunMeasurement")

        # 7. failed comparison branches reject completed-result fields
        bad_failed_comp_cons = dict(
            self._sample_failed_comparison_consensus(),
            comparison_id="comparison_0123456789abcdef",
            occurrence_set_id="occurrence_fedcba9876543210",
            evidence_ids=["evidence_000000000001"],
        )
        with self.assertRaises(self.jsonschema.ValidationError):
            self.validate_def(bad_failed_comp_cons, "auditRunMeasurementFailedComparisonConsensus")
        with self.assertRaises(self.jsonschema.ValidationError):
            self.validate_def(bad_failed_comp_cons, "auditRunMeasurement")

        bad_failed_comp_single = dict(
            self._sample_failed_comparison_single_scan(),
            comparison_id="comparison_0123456789abcdef",
            occurrence_set_id="occurrence_fedcba9876543210",
            evidence_ids=["evidence_000000000001"],
        )
        with self.assertRaises(self.jsonschema.ValidationError):
            self.validate_def(bad_failed_comp_single, "auditRunMeasurementFailedComparisonSingleScan")
        with self.assertRaises(self.jsonschema.ValidationError):
            self.validate_def(bad_failed_comp_single, "auditRunMeasurement")

    def test_evidence_ids_bounds(self):
        consensus_100 = self._sample_completed_consensus()
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
            m = {
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
            }
            self.validate_def(m, "auditRunMeasurementCompletedConsensus")
            measurements.append(m)

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
            mp = {
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
                    "declared_channels": list(range(1, 197)),
                    "scan_time": 3600,
                },
                "status": "archived",
                "created_at": "2026-07-30T09:00:00Z",
                "archived_at": "2026-07-30T09:05:00Z",
                "revision": 99,
            }
            # Validate each generated MeasurementPoint against the schema before serialization
            self.validate_def(mp, "measurementPoint")
            return mp

        # Test 90 maximum-sized records fit under 512 KB with at least 20% headroom
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

        # Test channels > 196 rejected
        bad_chan = {
            "assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
            "name": "Point Alpha",
            "expected_measurement_context": {
                "location_id": "loc_1",
                "scan_profile_id": "prof_1",
                "radio_profile_id": "radio_1",
                "interface": "wlan0",
                "declared_bands": ["2.4"],
                "declared_channels": [197],
                "scan_time": 300,
            },
            "expected_assessment_revision": 1,
        }
        with self.assertRaises(self.jsonschema.ValidationError):
            self.validate_def(bad_chan, "createMeasurementPointRequest")


if __name__ == "__main__":
    unittest.main()
