import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "docs" / "schemas" / "repeatable-audits-v1.schema.json"


def load_schema():
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


class RepeatableAuditsSchemaTests(unittest.TestCase):
    def setUp(self):
        try:
            import jsonschema
            self.jsonschema = jsonschema
        except ImportError:
            self.skipTest("jsonschema library not installed")
        self.schema = load_schema()

    def validate_def(self, instance, def_name):
        wrapper = {
            "$schema": self.schema["$schema"],
            "$defs": self.schema["$defs"],
            "$ref": f"#/$defs/{def_name}",
        }
        self.jsonschema.validate(instance=instance, schema=wrapper)

    def test_measurement_point_valid_and_invalid(self):
        valid_point = {
            "measurement_point_id": "mp_a1b2c3d4e5f67890",
            "assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
            "name": "Floor 2 West Wing",
            "description": "Primary workspace",
            "expected_measurement_context": {
                "location_id": "loc_site_alpha",
                "measurement_point_id": "mp_a1b2c3d4e5f67890",
                "scan_profile_id": "prof_full_dual_band",
                "radio_profile_id": "radio_wlan0_wlan1",
                "interface": "wlan0",
                "declared_bands": ["2.4", "5"],
                "declared_channels": [1, 6, 11, 36, 40],
                "scan_time": 300,
            },
            "status": "active",
            "created_at": "2026-07-29T12:00:00Z",
            "archived_at": None,
            "revision": 1,
        }
        self.validate_def(valid_point, "measurementPoint")

        # Invalid declared band ("2.4GHz" instead of "2.4")
        invalid_band = json.loads(json.dumps(valid_point))
        invalid_band["expected_measurement_context"]["declared_bands"] = ["2.4GHz"]
        with self.assertRaises(self.jsonschema.ValidationError):
            self.validate_def(invalid_band, "measurementPoint")

        # Invalid scan_time (< 30)
        invalid_time = json.loads(json.dumps(valid_point))
        invalid_time["expected_measurement_context"]["scan_time"] = 10
        with self.assertRaises(self.jsonschema.ValidationError):
            self.validate_def(invalid_time, "measurementPoint")

    def test_audit_run_valid_and_no_persisted_ready_to_start(self):
        valid_run = {
            "audit_run_id": "ar_0123456789abcdef",
            "assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
            "title": "Q3 Wireless Security Audit",
            "status": "in_progress",
            "created_at": "2026-07-29T12:00:00Z",
            "started_at": "2026-07-29T12:05:00Z",
            "completed_at": None,
            "archived_at": None,
            "due_at": "2026-08-15T17:00:00Z",
            "pinned_assurance_profile_version_id": "assurance_v0001",
            "pinned_assurance_profile_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "measurement_point_ids": ["mp_a1b2c3d4e5f67890"],
            "revision": 2,
        }
        self.validate_def(valid_run, "auditRun")

        # Additional property ready_to_start should be rejected on persisted auditRun schema
        with_ready = json.loads(json.dumps(valid_run))
        with_ready["ready_to_start"] = True
        with self.assertRaises(self.jsonschema.ValidationError):
            self.validate_def(with_ready, "auditRun")

    def test_audit_run_measurement_consensus_and_single_scan_variants(self):
        consensus_measurement = {
            "measurement_id": "arm_0123456789abcdef",
            "audit_run_id": "ar_0123456789abcdef",
            "measurement_point_id": "mp_a1b2c3d4e5f67890",
            "status": "completed",
            "source_recon_id": "recon_20260729_120000",
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
            "occurrence_set_id": "occurrence_fedcba9876543210",
            "evidence_ids": ["evidence_123456789abc"],
            "completed_at": "2026-07-29T12:15:00Z",
        }
        self.validate_def(consensus_measurement, "auditRunMeasurementConsensus")
        self.validate_def(consensus_measurement, "auditRunMeasurement")

        single_scan_measurement = {
            "measurement_id": "arm_0123456789abcdef",
            "audit_run_id": "ar_0123456789abcdef",
            "measurement_point_id": "mp_a1b2c3d4e5f67890",
            "status": "completed",
            "source_recon_id": "recon_20260729_120000",
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
            "occurrence_set_id": "occurrence_fedcba9876543210",
            "evidence_ids": ["evidence_123456789abc"],
            "completed_at": "2026-07-29T12:15:00Z",
        }
        self.validate_def(single_scan_measurement, "auditRunMeasurementSingleScan")
        self.validate_def(single_scan_measurement, "auditRunMeasurement")

    def test_digest_constraints(self):
        # Digest with sha256_ prefix must be rejected
        bad_digest_run = {
            "audit_run_id": "ar_0123456789abcdef",
            "assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
            "title": "Q3 Wireless Security Audit",
            "status": "in_progress",
            "created_at": "2026-07-29T12:00:00Z",
            "pinned_assurance_profile_version_id": "assurance_v0001",
            "pinned_assurance_profile_digest": "sha256_e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "measurement_point_ids": ["mp_a1b2c3d4e5f67890"],
            "revision": 1,
        }
        with self.assertRaises(self.jsonschema.ValidationError):
            self.validate_def(bad_digest_run, "auditRun")


if __name__ == "__main__":
    unittest.main()
