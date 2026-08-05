import copy
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "docs" / "schemas" / "repeatable-audits-v1.schema.json"

ASSESSMENT_ID = "assessment_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890"
POINT_ID = "mp_0123456789abcdef"
RUN_ID = "ar_0123456789abcdef"
MEASUREMENT_ID = "arm_0123456789abcdef"
PROFILE_ID = "mprofile_a1b2c3d4-e5f6-4789-a1b2-c3d4e5f67890"
DIGEST = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def load_schema():
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


class RepeatableAuditsSchemaTests(unittest.TestCase):
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
        self.schema = load_schema()
        self.jsonschema.Draft7Validator.check_schema(self.schema)
        self.format_checker = self.jsonschema.FormatChecker()

    def validate_def(self, instance, definition):
        wrapper = {
            "$schema": self.schema["$schema"],
            "$defs": self.schema["$defs"],
            "$ref": "#/$defs/{0}".format(definition),
        }
        self.jsonschema.Draft7Validator(
            wrapper, format_checker=self.format_checker
        ).validate(instance)

    def assert_invalid(self, instance, definition):
        with self.assertRaises(self.jsonschema.ValidationError):
            self.validate_def(instance, definition)

    @staticmethod
    def point():
        return {
            "measurement_point_id": POINT_ID,
            "assessment_id": ASSESSMENT_ID,
            "location_label": "Reception desk",
            "physical_notes": "North wall",
            "operator_instructions": "Use the marked position",
            "status": "active",
            "created_at": "2026-07-31T08:00:00Z",
            "archived_at": None,
            "revision": 1,
        }

    @staticmethod
    def assignment(index=0):
        return {
            "measurement_point_id": "mp_{0:016x}".format(index),
            "measurement_profile_id": PROFILE_ID,
            "measurement_profile_version_id": "mprofile_r0001",
            "baseline_version_id": "baseline_v0001",
        }

    @staticmethod
    def create_run_request(assignments=None):
        return {
            "assessment_id": ASSESSMENT_ID,
            "expected_assessment_revision": 4,
            "audit_run": {
                "name": "July floor audit",
                "description": "Operator-guided repeat measurement",
                "due_at": "2026-08-01T15:00:00Z",
                "assurance_profile_version_id": "assurance_v0001",
                "assignments": assignments
                if assignments is not None
                else [RepeatableAuditsSchemaTests.assignment()],
            },
        }

    @staticmethod
    def audit_run(status="draft"):
        started_at = None
        completed_at = None
        if status in ("in_progress", "completed", "cancelled"):
            started_at = "2026-07-31T08:05:00Z"
        if status in ("completed", "cancelled"):
            completed_at = "2026-07-31T08:15:00Z"
        return {
            "schema_version": "1.1",
            "audit_run_id": RUN_ID,
            "assessment_id": ASSESSMENT_ID,
            "name": "July floor audit",
            "description": None,
            "status": status,
            "created_at": "2026-07-31T08:00:00Z",
            "started_at": started_at,
            "completed_at": completed_at,
            "due_at": None,
            "pinned_assurance_profile_version_id": "assurance_v0001",
            "pinned_assurance_profile_digest": DIGEST,
            "measurement_ids": [MEASUREMENT_ID],
            "revision": 1,
        }

    @staticmethod
    def pinned_measurement(status="pending", baseline_type="consensus"):
        measurement = {
            "schema_version": "1.1",
            "measurement_id": MEASUREMENT_ID,
            "audit_run_id": RUN_ID,
            "measurement_point_id": POINT_ID,
            "status": status,
            "created_at": "2026-07-31T08:00:00Z",
            "revision": 1,
            "provenance_status": "pinned",
            "measurement_point_revision": 1,
            "measurement_point_digest": DIGEST,
            "measurement_point_snapshot": RepeatableAuditsSchemaTests.point(),
            "measurement_profile_id": PROFILE_ID,
            "measurement_profile_version_id": "mprofile_r0001",
            "measurement_profile_digest": DIGEST,
            "baseline_version_id": "baseline_v0001",
            "baseline_type": baseline_type,
            "baseline_digest": DIGEST,
            "baseline_record_digest": DIGEST,
            "assurance_profile_version_id": "assurance_v0001",
            "assurance_profile_digest": DIGEST,
        }
        if baseline_type == "consensus":
            measurement.update(
                baseline_model_id="bmodel_0123456789abcdef",
                baseline_model_digest=DIGEST,
            )
        else:
            measurement.update(
                baseline_snapshot_id="snapshot_0123456789abcdef",
                baseline_snapshot_digest=DIGEST,
            )
        if status in ("resolved", "completed"):
            measurement.update(
                snapshot_id="snapshot_1111111111111111",
                snapshot_digest=DIGEST,
                snapshot_record_digest=DIGEST,
                comparability_status="comparable",
                resolved_at="2026-07-31T08:10:00Z",
            )
        if status == "completed":
            measurement.pop("resolved_at")
            measurement.update(
                comparison_id="comparison_0123456789abcdef",
                comparison_digest=DIGEST,
                occurrence_set_id="occurrence_0123456789abcdef",
                evidence_ids=["evidence_0123456789ab"],
                completed_at="2026-07-31T08:15:00Z",
            )
        if status == "failed":
            measurement.update(
                failed_stage="resolution",
                retry_target="pending",
                error_code="invalid_recon",
                error_message="The saved Recon scan is invalid",
                failed_at="2026-07-31T08:10:00Z",
            )
        return measurement

    @staticmethod
    def capacity():
        return {
            "measurement_point_active_limit": 16,
            "measurement_point_active_used": 1,
            "measurement_point_active_available": 15,
            "measurement_point_total_limit": 32,
            "measurement_point_total_used": 1,
            "measurement_point_total_available": 31,
            "audit_run_limit": 32,
            "audit_run_used": 1,
            "audit_run_available": 31,
            "assignments_per_run_limit": 16,
            "in_progress_audit_run_limit": 1,
            "in_progress_audit_run_used": 0,
            "in_progress_audit_run_available": 1,
            "snapshot_limit": 100,
            "snapshot_used": 0,
            "snapshot_available": 100,
            "comparison_limit": 100,
            "comparison_used": 0,
            "comparison_available": 100,
            "event_limit": 5000,
            "event_used": 2,
            "event_available": 4998,
            "event_reserved_for_run_closure": 1,
            "event_available_for_non_terminal": 4997,
        }

    @staticmethod
    def workflow(action="start_run"):
        return {
            "current_measurement_id": MEASUREMENT_ID,
            "next_measurement_id": MEASUREMENT_ID,
            "next_action": action,
        }

    def test_measurement_point_contract_separates_location_from_profile(self):
        request = {
            "assessment_id": ASSESSMENT_ID,
            "expected_assessment_revision": 1,
            "measurement_point": {
                "location_label": "Reception desk",
                "physical_notes": "North wall",
                "operator_instructions": "Use the marked position",
            },
        }
        self.validate_def(request, "createMeasurementPointRequest")
        self.validate_def(self.point(), "measurementPoint")

        old_public_shape = {
            "assessment_id": ASSESSMENT_ID,
            "expected_assessment_revision": 1,
            "name": "Reception",
            "expected_measurement_context": {"interface": "wlan0"},
        }
        self.assert_invalid(old_public_shape, "createMeasurementPointRequest")

        technical_field = copy.deepcopy(request)
        technical_field["measurement_point"]["interface"] = "wlan0"
        self.assert_invalid(technical_field, "createMeasurementPointRequest")

    def test_capabilities_match_public_runtime_shape(self):
        response = {
            "schema_version": "1.0",
            "backend_version": "0.7.0",
            "product": {
                "name": "PineAssure",
                "technical_module_id": "PineAI",
                "tagline": "Baseline. Detect drift. Prove changes.",
            },
            "public_actions": [
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
            ],
            "limits": {
                "active_measurement_points_per_assessment": 16,
                "total_measurement_points_per_assessment": 32,
                "measurement_points_per_audit_run": 16,
                "audit_runs_per_assessment": 32,
                "simultaneous_active_audit_runs_per_assessment": 1,
                "simultaneous_scan_processing": 1,
                "raw_recon_bytes": 8388608,
                "evidence_references_per_measurement": 100,
            },
            "states": {
                "audit_run": ["draft", "in_progress", "completed", "cancelled"],
                "measurement": ["pending", "resolved", "completed", "failed"],
                "resume": "reload_in_progress_run",
            },
            "storage_layout": "assessments/<assessment_id>/audit_runs/<audit_run_id>/{manifest.json,measurements/<measurement_id>.json}",
            "report": {
                "formats": ["html", "json"],
                "privacy_profiles": ["local_full", "share_safe"],
                "terminal_states": ["completed", "cancelled"],
            },
            "strict_exclusions": [
                "automatic_recon_start",
                "radio_control",
                "background_scheduler",
                "autonomous_agent_loop",
                "attack_actions",
                "raw_recon_persistence",
            ],
            "hardware_calibrated": False,
        }
        self.validate_def(response, "repeatableAuditCapabilitiesResponse")

    def test_measurement_point_bounds_and_archival_semantics(self):
        request = {
            "assessment_id": ASSESSMENT_ID,
            "expected_assessment_revision": 1,
            "measurement_point": {"location_label": "x" * 128},
        }
        self.validate_def(request, "createMeasurementPointRequest")
        request["measurement_point"]["location_label"] += "x"
        self.assert_invalid(request, "createMeasurementPointRequest")

        archived = dict(
            self.point(),
            status="archived",
            archived_at="2026-07-31T09:00:00Z",
        )
        self.validate_def(archived, "measurementPoint")
        archived["archived_at"] = None
        self.assert_invalid(archived, "measurementPoint")

    def test_update_uses_both_revisions_and_nested_changes(self):
        request = {
            "assessment_id": ASSESSMENT_ID,
            "measurement_point_id": POINT_ID,
            "expected_assessment_revision": 2,
            "expected_measurement_point_revision": 1,
            "changes": {"operator_instructions": "New marker"},
        }
        self.validate_def(request, "updateMeasurementPointRequest")
        missing_revision = dict(request)
        missing_revision.pop("expected_measurement_point_revision")
        self.assert_invalid(missing_revision, "updateMeasurementPointRequest")
        empty_changes = dict(request, changes={})
        self.assert_invalid(empty_changes, "updateMeasurementPointRequest")

    def test_audit_run_creation_pins_explicit_assignments(self):
        self.validate_def(self.create_run_request(), "createAuditRunRequest")
        assignments = [self.assignment(index) for index in range(16)]
        self.validate_def(
            self.create_run_request(assignments), "createAuditRunRequest"
        )
        self.assert_invalid(
            self.create_run_request(assignments + [self.assignment(16)]),
            "createAuditRunRequest",
        )

        old_flat_shape = {
            "assessment_id": ASSESSMENT_ID,
            "expected_assessment_revision": 1,
            "title": "Old run",
            "measurement_point_ids": [POINT_ID],
            "pinned_assurance_profile_version_id": "assurance_v0001",
        }
        self.assert_invalid(old_flat_shape, "createAuditRunRequest")

    def test_strict_rfc3339_is_applied_to_run_requests(self):
        request = self.create_run_request()
        request["audit_run"]["due_at"] = "2026-07-31 12:00:00"
        self.assert_invalid(request, "createAuditRunRequest")
        request["audit_run"]["due_at"] = "2026-07-31T12:00:00+03:00"
        self.validate_def(request, "createAuditRunRequest")

    def test_public_resolve_accepts_recon_but_not_internal_snapshot(self):
        request = {
            "assessment_id": ASSESSMENT_ID,
            "audit_run_id": RUN_ID,
            "measurement_id": MEASUREMENT_ID,
            "expected_assessment_revision": 5,
            "expected_audit_run_revision": 2,
            "expected_measurement_revision": 1,
            "scan": {"AccessPoints": []},
            "scan_metadata": {"scan_time": 180},
        }
        self.validate_def(request, "resolveAuditMeasurementRequest")
        request.pop("scan")
        request["snapshot"] = {"snapshot_id": "snapshot_0123456789abcdef"}
        self.assert_invalid(request, "resolveAuditMeasurementRequest")

    def test_comparison_and_retry_accept_only_identifiers_and_revisions(self):
        request = {
            "assessment_id": ASSESSMENT_ID,
            "audit_run_id": RUN_ID,
            "measurement_id": MEASUREMENT_ID,
            "expected_assessment_revision": 5,
            "expected_audit_run_revision": 2,
            "expected_measurement_revision": 2,
        }
        self.validate_def(request, "saveAuditMeasurementComparisonRequest")
        self.validate_def(request, "retryAuditMeasurementRequest")
        request["comparison"] = {"comparability_status": "comparable"}
        self.assert_invalid(request, "saveAuditMeasurementComparisonRequest")

    def test_split_v11_entities_and_detail_response(self):
        run = self.audit_run()
        measurement = self.pinned_measurement()
        self.validate_def(run, "auditRun")
        self.validate_def(measurement, "auditRunMeasurement")
        response = {
            "schema_version": "1.0",
            "assessment_revision": 5,
            "audit_run": run,
            "measurements": [measurement],
            "ready_to_start": True,
            "workflow": self.workflow(),
            "assessment_capacity": self.capacity(),
        }
        self.validate_def(response, "auditRunDetailResponse")

    def test_run_timestamps_follow_state_semantics(self):
        for status in ("draft", "in_progress", "completed", "cancelled"):
            self.validate_def(self.audit_run(status), "auditRun")

        invalid_draft = self.audit_run("draft")
        invalid_draft["started_at"] = "2026-07-31T08:05:00Z"
        self.assert_invalid(invalid_draft, "auditRun")

        invalid_active = self.audit_run("in_progress")
        invalid_active["started_at"] = None
        self.assert_invalid(invalid_active, "auditRun")

        cancelled_before_start = self.audit_run("cancelled")
        cancelled_before_start["started_at"] = None
        self.validate_def(cancelled_before_start, "auditRun")

    def test_run_mutations_require_new_assessment_revision(self):
        detail = {
            "schema_version": "1.0",
            "audit_run": self.audit_run(),
            "measurements": [self.pinned_measurement()],
            "ready_to_start": True,
            "workflow": self.workflow(),
            "assessment_capacity": self.capacity(),
        }
        self.validate_def(detail, "auditRunDetailResponse")
        self.assert_invalid(detail, "createAuditRunResponse")
        self.assert_invalid(detail, "auditRunMutationResponse")

        detail["assessment_revision"] = 5
        self.validate_def(detail, "createAuditRunResponse")
        self.validate_def(detail, "auditRunMutationResponse")

    def test_measurement_mutation_response_does_not_embed_sibling_list(self):
        response = {
            "schema_version": "1.0",
            "assessment_revision": 6,
            "audit_run": self.audit_run("in_progress"),
            "measurement": self.pinned_measurement("resolved"),
            "workflow": self.workflow("save_comparison"),
            "assessment_capacity": self.capacity(),
        }
        self.validate_def(response, "auditMeasurementMutationResponse")
        response["measurements"] = [self.pinned_measurement("resolved")]
        self.assert_invalid(response, "auditMeasurementMutationResponse")

    def test_measurement_status_requirements(self):
        for status, definition in (
            ("pending", "auditRunMeasurementPending"),
            ("resolved", "auditRunMeasurementResolved"),
            ("completed", "auditRunMeasurementCompleted"),
            ("failed", "auditRunMeasurementFailed"),
        ):
            self.validate_def(self.pinned_measurement(status), definition)

        incomplete = self.pinned_measurement("completed")
        incomplete.pop("comparison_id")
        self.assert_invalid(incomplete, "auditRunMeasurement")

        pending_with_snapshot = self.pinned_measurement("pending")
        pending_with_snapshot["snapshot_id"] = "snapshot_1111111111111111"
        self.assert_invalid(pending_with_snapshot, "auditRunMeasurement")

        completed_with_resolved_at = self.pinned_measurement("completed")
        completed_with_resolved_at["resolved_at"] = "2026-07-31T08:10:00Z"
        self.assert_invalid(completed_with_resolved_at, "auditRunMeasurement")

        resolution_failure = self.pinned_measurement("failed")
        resolution_failure["retry_target"] = "resolved"
        self.assert_invalid(resolution_failure, "auditRunMeasurement")

        comparison_failure = self.pinned_measurement("resolved")
        comparison_failure.update(
            status="failed",
            failed_stage="comparison",
            retry_target="resolved",
            error_code="invalid_comparison",
            error_message="Comparison failed",
            failed_at="2026-07-31T08:12:00Z",
        )
        self.validate_def(comparison_failure, "auditRunMeasurementFailed")
        comparison_failure["retry_target"] = "pending"
        self.assert_invalid(comparison_failure, "auditRunMeasurement")
        comparison_failure["retry_target"] = "resolved"
        comparison_failure.pop("snapshot_record_digest")
        self.assert_invalid(comparison_failure, "auditRunMeasurement")

    def test_single_scan_and_consensus_pins_are_distinct(self):
        consensus = self.pinned_measurement("resolved", "consensus")
        single_scan = self.pinned_measurement("resolved", "single_scan")
        self.validate_def(consensus, "auditRunMeasurement")
        self.validate_def(single_scan, "auditRunMeasurement")
        consensus.pop("baseline_model_digest")
        self.assert_invalid(consensus, "auditRunMeasurement")
        single_scan["baseline_model_id"] = "bmodel_0123456789abcdef"
        single_scan["baseline_model_digest"] = DIGEST
        self.assert_invalid(single_scan, "auditRunMeasurement")

    def test_capacity_encodes_frozen_v070_limits(self):
        self.validate_def(self.capacity(), "assessmentCapacity")
        bad = dict(self.capacity(), measurement_point_active_limit=64)
        self.assert_invalid(bad, "assessmentCapacity")
        bad = dict(self.capacity(), audit_run_limit=128)
        self.assert_invalid(bad, "assessmentCapacity")

    def test_report_request_uses_only_frozen_privacy_profiles(self):
        request = {
            "assessment_id": ASSESSMENT_ID,
            "audit_run_id": RUN_ID,
            "format": "html",
            "privacy_profile": "local_full",
        }
        self.validate_def(request, "generateAuditRunReportRequest")
        request["privacy_profile"] = "share_safe"
        self.validate_def(request, "generateAuditRunReportRequest")
        request["privacy_profile"] = "internal_full"
        self.assert_invalid(request, "generateAuditRunReportRequest")
        request["privacy_profile"] = "pseudonymized"
        self.assert_invalid(request, "generateAuditRunReportRequest")

    def test_report_response_wrapper(self):
        response = {
            "schema_version": "1.0",
            "report_id": "audit_report_0123456789abcdef",
            "audit_run_id": RUN_ID,
            "format": "json",
            "privacy_profile": "share_safe",
            "generated_at": "2026-07-31T08:15:00Z",
            "fact_digest": DIGEST,
            "content_sha256": DIGEST,
            "filename": "PineAssure-ar_0123456789abcdef-share_safe.json",
            "mime_type": "application/json",
            "content": "{}\n",
        }
        self.validate_def(response, "generateAuditRunReportResponse")

    def test_mutation_request_rejects_unknown_fields(self):
        request = {
            "assessment_id": ASSESSMENT_ID,
            "audit_run_id": RUN_ID,
            "expected_assessment_revision": 4,
            "expected_audit_run_revision": 1,
            "shell_command": "do not accept",
        }
        self.assert_invalid(request, "auditRunTransitionRequest")

    def test_cancel_accepts_only_an_optional_bounded_reason(self):
        request = {
            "assessment_id": ASSESSMENT_ID,
            "audit_run_id": RUN_ID,
            "expected_assessment_revision": 4,
            "expected_audit_run_revision": 1,
            "reason": "Site closed before the final point",
        }
        self.validate_def(request, "cancelAuditRunRequest")
        request["reason"] = "x" * 513
        self.assert_invalid(request, "cancelAuditRunRequest")


if __name__ == "__main__":
    unittest.main()
