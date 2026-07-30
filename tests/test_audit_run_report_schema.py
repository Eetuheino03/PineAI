import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT_SCHEMA_PATH = ROOT / "docs" / "schemas" / "audit-run-report-v1.schema.json"


def load_report_schema():
    return json.loads(REPORT_SCHEMA_PATH.read_text(encoding="utf-8"))


class AuditRunReportSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import jsonschema
            cls.jsonschema = jsonschema
        except ImportError:
            raise unittest.SkipTest("jsonschema library is required for contract validation")

    def setUp(self):
        self.schema = load_report_schema()
        self.jsonschema.Draft7Validator.check_schema(self.schema)

    def test_valid_audit_run_report_consensus_variant(self):
        valid_report = {
            "report_id": "report_0123456789abcdef",
            "schema_version": "1.0",
            "scope": "audit_run",
            "assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
            "audit_run_id": "ar_0123456789abcdef",
            "title": "Q3 Wireless Security Audit Report",
            "generated_at": "2026-07-29T12:30:00Z",
            "assurance_profile_version_id": "assurance_v0001",
            "assurance_profile_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "measurements_summary": {
                "total_points": 4,
                "completed_points": 4,
                "failed_points": 0,
                "comparable_points": 4,
                "partially_comparable_points": 0,
                "not_comparable_points": 0,
            },
            "per_point_measurements": [
                {
                    "measurement_point_id": "mp_a1b2c3d4e5f67890",
                    "status": "completed",
                    "comparability_status": "comparable",
                    "snapshot_id": "snapshot_a1b2c3d4e5f67890",
                    "snapshot_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "baseline_version_id": "baseline_v0001",
                    "baseline_type": "consensus",
                    "baseline_record_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "baseline_model_id": "bmodel_1122334455667788",
                    "baseline_model_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "finding_counts": {
                        "total": 4,
                        "open": 1,
                        "acknowledged": 1,
                        "false_positive": 1,
                        "resolved": 1,
                    },
                }
            ],
            "evidence_references": ["evidence_123456789abc"],
            "privacy_profile": "share_safe",
            "report_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        }
        self.jsonschema.validate(instance=valid_report, schema=self.schema)

        # Assert total consistency rule
        fc = valid_report["per_point_measurements"][0]["finding_counts"]
        self.assertEqual(fc["total"], fc["open"] + fc["acknowledged"] + fc["false_positive"] + fc["resolved"])

    def test_valid_audit_run_report_single_scan_variant(self):
        valid_report = {
            "report_id": "report_0123456789abcdef",
            "schema_version": "1.0",
            "scope": "audit_run",
            "assessment_id": "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890",
            "audit_run_id": "ar_0123456789abcdef",
            "title": "Q3 Single Scan Audit Report",
            "generated_at": "2026-07-29T12:30:00Z",
            "assurance_profile_version_id": "assurance_v0001",
            "assurance_profile_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "measurements_summary": {
                "total_points": 1,
                "completed_points": 1,
                "failed_points": 0,
                "comparable_points": 1,
                "partially_comparable_points": 0,
                "not_comparable_points": 0,
            },
            "per_point_measurements": [
                {
                    "measurement_point_id": "mp_a1b2c3d4e5f67890",
                    "status": "completed",
                    "comparability_status": "comparable",
                    "snapshot_id": "snapshot_a1b2c3d4e5f67890",
                    "snapshot_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "baseline_version_id": "baseline_v0001",
                    "baseline_type": "single_scan",
                    "baseline_record_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "baseline_snapshot_id": "snapshot_a1b2c3d4e5f67890",
                    "baseline_snapshot_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "finding_counts": {
                        "total": 0,
                        "open": 0,
                        "acknowledged": 0,
                        "false_positive": 0,
                        "resolved": 0,
                    },
                }
            ],
            "evidence_references": [],
            "privacy_profile": "share_safe",
            "report_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        }
        self.jsonschema.validate(instance=valid_report, schema=self.schema)


if __name__ == "__main__":
    unittest.main()
