import copy
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "projects" / "PineAI" / "src" / "assets"
REPORT_SCHEMA_PATH = (
    ROOT / "docs" / "schemas" / "audit-run-report-v1.schema.json"
)
sys.path.insert(0, str(ASSETS))

from pineai_backend.audit_run_report import AuditRunReportService  # noqa: E402


ASSESSMENT_ID = "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890"
RUN_ID = "ar_0123456789abcdef"
DIGEST = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class ContractStore:
    def __init__(self, status="completed"):
        self.status = status
        self.snapshot = {
            "snapshot_id": "snapshot_1111111111111111",
            "snapshot_digest": "a" * 64,
            "access_points": [],
        }
        self.comparison = {
            "comparison_id": "comparison_2222222222222222",
            "comparison_digest": "b" * 64,
            "comparability_status": "comparable",
        }
        self.occurrence = {
            "occurrence_set_id": "occurrence_3333333333333333",
            "occurrence_digest": "c" * 64,
            "policy_deviations": [
                {"finding_id": "finding_000000000001", "severity": "medium"}
            ],
            "security_findings": [],
        }

    def get_audit_run(self, _assessment_id, _audit_run_id):
        measurement = {
            "schema_version": "1.1",
            "measurement_id": "arm_0123456789abcdef",
            "audit_run_id": RUN_ID,
            "measurement_point_id": "mp_0123456789abcdef",
            "status": "completed",
            "created_at": "2026-07-31T08:00:00Z",
            "revision": 3,
            "provenance_status": "pinned",
            "snapshot_id": self.snapshot["snapshot_id"],
            "snapshot_digest": self.snapshot["snapshot_digest"],
            "comparison_id": self.comparison["comparison_id"],
            "comparison_digest": self.comparison["comparison_digest"],
            "occurrence_digest": self.occurrence["occurrence_digest"],
        }
        return {
            "audit_run": {
                "schema_version": "1.1",
                "audit_run_id": RUN_ID,
                "assessment_id": ASSESSMENT_ID,
                "name": "July floor audit",
                "description": None,
                "status": self.status,
                "created_at": "2026-07-31T08:00:00Z",
                "started_at": "2026-07-31T08:05:00Z",
                "completed_at": "2026-07-31T08:15:00Z",
                "due_at": None,
                "pinned_assurance_profile_version_id": "assurance_v0001",
                "pinned_assurance_profile_digest": DIGEST,
                "measurement_ids": [measurement["measurement_id"]],
                "revision": 4,
            },
            "measurements": [measurement],
            "workflow": {
                "current_measurement_id": None,
                "next_measurement_id": None,
                "next_action": "generate_report",
            },
        }

    def get_snapshot(self, _assessment_id, _snapshot_id):
        return copy.deepcopy(self.snapshot)

    def get_comparison(self, _assessment_id, _comparison_id):
        return copy.deepcopy(self.comparison)

    def get_occurrence_set(self, _assessment_id, _comparison_id):
        return copy.deepcopy(self.occurrence)

    def get(self, _assessment_id, after_sequence=0, limit=100):
        events = [
            {
                "sequence": 1,
                "event_id": "evt_00000000-0000-4000-8000-000000000001",
                "event_type": "audit_run_created",
                "recorded_at": "2026-07-31T08:00:00Z",
                "revision": 1,
                "data": {"audit_run_id": RUN_ID},
            }
        ]
        selected = [item for item in events if item["sequence"] > after_sequence]
        return {
            "events": selected[:limit],
            "events_has_more": len(selected) > limit,
        }


class AuditRunReportSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import jsonschema
        except ImportError:
            raise unittest.SkipTest(
                "jsonschema library is required for contract validation"
            )
        cls.jsonschema = jsonschema

    def setUp(self):
        self.schema = json.loads(
            REPORT_SCHEMA_PATH.read_text(encoding="utf-8")
        )
        self.jsonschema.Draft7Validator.check_schema(self.schema)
        self.validator = self.jsonschema.Draft7Validator(
            self.schema,
            format_checker=self.jsonschema.FormatChecker(),
        )

    def generate_facts(self, status="completed", privacy="local_full"):
        result = AuditRunReportService(ContractStore(status)).generate(
            ASSESSMENT_ID,
            RUN_ID,
            "json",
            privacy,
        )
        return result, json.loads(result["content"])

    def test_production_completed_fact_model_matches_schema(self):
        result, facts = self.generate_facts()
        self.validator.validate(facts)
        self.assertEqual(len(result["fact_digest"]), 64)
        self.assertEqual(facts["capacity_limits"]["audit_runs_per_assessment"], 32)
        self.assertEqual(facts["capacity_limits"]["measurement_points_per_audit_run"], 16)

    def test_production_cancelled_fact_model_matches_schema(self):
        _result, facts = self.generate_facts(status="cancelled")
        self.validator.validate(facts)
        self.assertEqual(facts["audit_run"]["status"], "cancelled")

    def test_share_safe_fact_model_matches_same_schema(self):
        _result, facts = self.generate_facts(privacy="share_safe")
        self.validator.validate(facts)

    def test_ssid_collision_does_not_redact_status_enums(self):
        store = ContractStore()
        store.snapshot["access_points"] = [
            {
                "ssid": "completed",
                "bssid": "AA:BB:CC:DD:EE:FF",
            }
        ]
        store.occurrence["policy_deviations"][0].update(
            {
                "protected_ssid": "completed",
                "expected": "completed",
                "observed": "completed",
            }
        )
        result = AuditRunReportService(store).generate(
            ASSESSMENT_ID,
            RUN_ID,
            "json",
            "share_safe",
        )
        facts = json.loads(result["content"])
        self.validator.validate(facts)
        self.assertEqual(facts["audit_run"]["status"], "completed")
        self.assertEqual(facts["measurements"][0]["status"], "completed")
        deviation = facts["measurements"][0]["occurrence"][
            "policy_deviations"
        ][0]
        self.assertEqual(deviation["expected"], "[redacted-ssid]")
        self.assertEqual(deviation["observed"], "[redacted-ssid]")

    def test_report_requires_frozen_capacity_fields(self):
        _result, facts = self.generate_facts()
        facts["capacity_limits"]["audit_runs_per_assessment"] = 128
        with self.assertRaises(self.jsonschema.ValidationError):
            self.validator.validate(facts)

    def test_report_rejects_old_flat_contract(self):
        legacy = {
            "report_id": "report_0123456789abcdef",
            "schema_version": "1.0",
            "scope": "audit_run",
            "assessment_id": ASSESSMENT_ID,
            "audit_run_id": RUN_ID,
            "privacy_profile": "internal_full",
            "report_digest": DIGEST,
        }
        with self.assertRaises(self.jsonschema.ValidationError):
            self.validator.validate(legacy)

    def test_unknown_top_level_fact_is_rejected(self):
        _result, facts = self.generate_facts()
        facts["raw_recon"] = {"AccessPoints": []}
        with self.assertRaises(self.jsonschema.ValidationError):
            self.validator.validate(facts)


if __name__ == "__main__":
    unittest.main()
