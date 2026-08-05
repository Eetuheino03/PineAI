"""Operator-driven Repeatable Field Audit orchestration.

This service is the only public bridge from raw saved Hak5 Recon responses to
AuditRun artifacts.  It keeps radio control outside PineAssure, enforces the
single-scan resource boundary and delegates all durable writes to the
transactional store.
"""

import json
from typing import Any, Dict, Optional

from . import __version__
from .assessment_store import _validate_revision
from .assurance_service import AssuranceService
from .customer_analysis import evidence_records
from .errors import BackendError
from .operation_lock import scan_processing_lock
from .platform import require_operation_capacity
from .repeatable_audit_store import (
    MAX_ACTIVE_MEASUREMENT_POINTS,
    MAX_AUDIT_RUNS_PER_ASSESSMENT,
    MAX_EVIDENCE_IDS_PER_AUDIT_MEASUREMENT,
    MAX_MEASUREMENT_POINTS_PER_RUN,
    MAX_TOTAL_MEASUREMENT_POINT_RECORDS,
    REPEATABLE_AUDITS_SCHEMA_VERSION,
    RepeatableAuditStore,
    _timestamp_not_before,
)


MAX_RAW_RECON_BYTES = 8 * 1024 * 1024
RESOLUTION_FAILURE_CODES = {"invalid_recon", "invalid_scan_metadata"}
COMPARISON_FAILURE_CODES = {
    "audit_measurement_evidence_limit",
    "invalid_comparison",
    "invalid_occurrence_set",
}


def _json_size(value: Any, error_code: str, label: str) -> int:
    try:
        return len(
            json.dumps(
                value,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
        )
    except (TypeError, ValueError) as error:
        raise BackendError(
            error_code, "{0} must be valid JSON".format(label)
        ) from error


def _measurement(detail: Dict[str, Any], measurement_id: Any) -> Dict[str, Any]:
    measurements = detail.get("measurements")
    if not isinstance(measurements, list):
        raise BackendError(
            "invalid_audit_run_measurement",
            "AuditRun measurement list is invalid",
        )
    for item in measurements:
        if isinstance(item, dict) and item.get("measurement_id") == measurement_id:
            return item
    raise BackendError(
        "audit_measurement_not_found", "measurement was not found"
    )


def _baseline_context(baseline: Dict[str, Any]) -> Dict[str, Any]:
    if isinstance(baseline.get("baseline_model"), dict):
        context = baseline["baseline_model"].get("measurement_context")
    elif isinstance(baseline.get("snapshot"), dict):
        context = baseline["snapshot"].get("scan_metadata", {}).get(
            "measurement_context"
        )
    else:
        context = baseline.get("measurement_context")
    return dict(context) if isinstance(context, dict) else {}


def _pinned_scan_metadata(
    assessment_id: str,
    measurement: Dict[str, Any],
    profile_record: Dict[str, Any],
    baseline: Dict[str, Any],
    supplied: Any,
) -> Dict[str, Any]:
    if supplied is None:
        supplied = {}
    if not isinstance(supplied, dict):
        raise BackendError(
            "invalid_scan_metadata", "scan_metadata must be an object"
        )
    result = dict(supplied)
    context_fields = {
        "location_id",
        "measurement_point_id",
        "scan_profile_id",
        "radio_profile_id",
        "interface",
        "declared_channels",
        "declared_bands",
        "measurement_profile_id",
        "measurement_profile_version_id",
        "measurement_profile_revision",
        "measurement_profile_digest",
    }
    for field in context_fields:
        result.pop(field, None)
    result.pop("measurement_context", None)

    profile = profile_record.get("profile")
    if not isinstance(profile, dict):
        raise BackendError(
            "pinned_reference_mismatch",
            "measurement profile version is invalid",
        )
    baseline_context = _baseline_context(baseline)
    point = measurement.get("measurement_point_snapshot")
    if not isinstance(point, dict):
        raise BackendError(
            "pinned_reference_missing",
            "measurement point snapshot is unavailable",
        )
    assigned_point_id = measurement.get("measurement_point_id")
    baseline_point_id = baseline_context.get("measurement_point_id")
    if baseline_point_id != assigned_point_id:
        raise BackendError(
            "pinned_reference_mismatch",
            "baseline measurement point differs from the AuditRun assignment",
        )
    # The current snapshot always inherits the immutable physical point from
    # the AuditRun measurement. A baseline can never overwrite this identity.
    # Technical fields always come from the MeasurementProfile pin.
    result["measurement_context"] = {
        "location_id": baseline_context.get("location_id") or assessment_id,
        "measurement_point_id": assigned_point_id,
        "scan_profile_id": profile.get("scan_profile_id"),
        "radio_profile_id": profile.get("radio_profile_id"),
        "interface": profile.get("interface"),
        "declared_channels": profile.get("declared_channels"),
        "declared_bands": profile.get("declared_bands"),
        "measurement_profile_id": measurement.get("measurement_profile_id"),
        "measurement_profile_version_id": measurement.get(
            "measurement_profile_version_id"
        ),
        "measurement_profile_digest": measurement.get(
            "measurement_profile_digest"
        ),
    }
    return result


def _occurrence_input(preview: Dict[str, Any]) -> Dict[str, Any]:
    baseline = preview["baseline"]
    limitations = list(
        baseline.get("baseline_model", {}).get("limitation_codes", [])
    )
    if baseline.get("legacy"):
        limitations.append("legacy_single_scan_baseline")
    all_evidence = evidence_records(baseline, preview["current_snapshot"])
    return {
        "observed_changes": preview["observed_changes"],
        "inventory_reconciliation": preview["inventory_reconciliation"],
        "policy_deviations": preview["policy_deviations"],
        "security_findings": preview["security_findings"],
        "policy_evaluation_status": preview["policy_evaluation_status"],
        "lifecycle_findings": preview["lifecycle_findings"],
        # The store builder keeps only evidence referenced by authoritative
        # result objects and enforces the per-measurement limit.
        "evidence": all_evidence,
        "quality_factors": preview["diff"]["comparability"].get(
            "quality_factors", []
        ),
        "policy_reference": {
            "assurance_profile_version_id": preview["pinned_versions"].get(
                "assurance_profile_version_id"
            ),
            "assurance_profile_digest": preview["pinned_versions"].get(
                "assurance_profile_digest"
            ),
        },
        "limitations": sorted(set(limitations)),
    }


class RepeatableAuditService:
    """Coordinate raw Recon processing and pinned deterministic analysis."""

    def __init__(
        self,
        config_dir: Optional[str] = None,
        store: Optional[RepeatableAuditStore] = None,
    ):
        self.config_dir = config_dir
        self.store = store or RepeatableAuditStore(config_dir)
        self.assurance = AssuranceService(
            config_dir=config_dir, store=self.store
        )

    def capabilities(self) -> Dict[str, Any]:
        return {
            "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
            "backend_version": __version__,
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
                "active_measurement_points_per_assessment": (
                    MAX_ACTIVE_MEASUREMENT_POINTS
                ),
                "total_measurement_points_per_assessment": (
                    MAX_TOTAL_MEASUREMENT_POINT_RECORDS
                ),
                "measurement_points_per_audit_run": (
                    MAX_MEASUREMENT_POINTS_PER_RUN
                ),
                "audit_runs_per_assessment": (
                    MAX_AUDIT_RUNS_PER_ASSESSMENT
                ),
                "simultaneous_active_audit_runs_per_assessment": 1,
                "simultaneous_scan_processing": 1,
                "raw_recon_bytes": MAX_RAW_RECON_BYTES,
                "evidence_references_per_measurement": (
                    MAX_EVIDENCE_IDS_PER_AUDIT_MEASUREMENT
                ),
            },
            "states": {
                "audit_run": [
                    "draft",
                    "in_progress",
                    "completed",
                    "cancelled",
                ],
                "measurement": [
                    "pending",
                    "resolved",
                    "completed",
                    "failed",
                ],
                "resume": "reload_in_progress_run",
            },
            "storage_layout": (
                "assessments/<assessment_id>/audit_runs/<audit_run_id>/"
                "{manifest.json,measurements/<measurement_id>.json}"
            ),
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

    def _detail_and_measurement(
        self,
        assessment_id: str,
        expected_assessment_revision: int,
        audit_run_id: str,
        measurement_id: str,
    ):
        expected = _validate_revision(expected_assessment_revision)
        actual = self.store.get(assessment_id, 0, 1).get("revision")
        if actual != expected:
            raise BackendError(
                "revision_conflict", "assessment revision has changed"
            )
        detail = self.store.get_audit_run(assessment_id, audit_run_id)
        return detail, _measurement(detail, measurement_id)

    def resolve_measurement(
        self,
        assessment_id: str,
        expected_assessment_revision: int,
        audit_run_id: str,
        expected_audit_run_revision: int,
        measurement_id: str,
        expected_measurement_revision: int,
        scan: Any,
        scan_metadata: Any,
    ) -> Dict[str, Any]:
        payload_bytes = _json_size(scan, "invalid_recon", "scan")
        if payload_bytes > MAX_RAW_RECON_BYTES:
            raise BackendError(
                "invalid_recon", "scan exceeds the 8 MiB input limit"
            )
        with scan_processing_lock(self.config_dir):
            require_operation_capacity(
                self.config_dir,
                payload_bytes=payload_bytes,
                estimated_write_bytes=min(payload_bytes, 4 * 1024 * 1024),
            )
            detail, measurement = self._detail_and_measurement(
                assessment_id,
                expected_assessment_revision,
                audit_run_id,
                measurement_id,
            )
            run = detail.get("audit_run", {})
            if run.get("revision") != expected_audit_run_revision:
                raise BackendError(
                    "revision_conflict", "audit run revision has changed"
                )
            if measurement.get("revision") != expected_measurement_revision:
                raise BackendError(
                    "revision_conflict", "measurement revision has changed"
                )
            try:
                profile_record = self.store._profile_version(
                    measurement["measurement_profile_id"],
                    measurement["measurement_profile_version_id"],
                )
                if profile_record.get("digest") != measurement.get(
                    "measurement_profile_digest"
                ):
                    raise BackendError(
                        "pinned_reference_mismatch",
                        "measurement profile digest no longer verifies",
                    )
                baseline = self.store.get_baseline_version(
                    assessment_id, measurement["baseline_version_id"]
                )
                metadata = _pinned_scan_metadata(
                    assessment_id,
                    measurement,
                    profile_record,
                    baseline,
                    scan_metadata,
                )
                snapshot = self.assurance.resolve_recon(
                    scan, metadata
                )["snapshot"]
                preview = self.assurance.comparison_for_pinned_versions(
                    assessment_id,
                    snapshot,
                    measurement["baseline_version_id"],
                    measurement["assurance_profile_version_id"],
                    measurement["measurement_profile_id"],
                    measurement["measurement_profile_version_id"],
                    measurement["measurement_profile_digest"],
                )
            except BackendError as failure:
                if failure.code not in RESOLUTION_FAILURE_CODES:
                    raise
                failed_at = _timestamp_not_before(measurement.get("created_at"))
                return self.store.resolve_audit_measurement(
                    assessment_id,
                    expected_assessment_revision,
                    audit_run_id,
                    expected_audit_run_revision,
                    measurement_id,
                    expected_measurement_revision,
                    failure={
                        "error_code": failure.code,
                        "error_message": failure.safe_message,
                        "failed_at": failed_at,
                    },
                )
            return self.store.resolve_audit_measurement(
                assessment_id,
                expected_assessment_revision,
                audit_run_id,
                expected_audit_run_revision,
                measurement_id,
                expected_measurement_revision,
                snapshot={
                    "document": snapshot,
                    "comparability_status": preview["diff"][
                        "comparability"
                    ]["status"],
                    "resolved_at": _timestamp_not_before(
                        measurement.get("created_at")
                    ),
                    "source_recon_id": snapshot.get("scan_metadata", {}).get(
                        "scan_id"
                    ),
                },
            )

    def save_comparison(
        self,
        assessment_id: str,
        expected_assessment_revision: int,
        audit_run_id: str,
        expected_audit_run_revision: int,
        measurement_id: str,
        expected_measurement_revision: int,
    ) -> Dict[str, Any]:
        with scan_processing_lock(self.config_dir):
            require_operation_capacity(
                self.config_dir,
                payload_bytes=0,
                estimated_write_bytes=4 * 1024 * 1024,
            )
            detail, measurement = self._detail_and_measurement(
                assessment_id,
                expected_assessment_revision,
                audit_run_id,
                measurement_id,
            )
            run = detail.get("audit_run", {})
            if run.get("revision") != expected_audit_run_revision:
                raise BackendError(
                    "revision_conflict", "audit run revision has changed"
                )
            if measurement.get("revision") != expected_measurement_revision:
                raise BackendError(
                    "revision_conflict", "measurement revision has changed"
                )
            try:
                snapshot = self.store.get_snapshot(
                    assessment_id, measurement.get("snapshot_id")
                )
                preview = self.assurance.comparison_for_pinned_versions(
                    assessment_id,
                    snapshot,
                    measurement["baseline_version_id"],
                    measurement["assurance_profile_version_id"],
                    measurement["measurement_profile_id"],
                    measurement["measurement_profile_version_id"],
                    measurement["measurement_profile_digest"],
                )
                completed_at = _timestamp_not_before(
                    measurement.get("resolved_at"),
                    measurement.get("created_at"),
                )
                analysis = self.store.build_audit_measurement_analysis(
                    assessment_id,
                    expected_assessment_revision,
                    audit_run_id,
                    expected_audit_run_revision,
                    measurement_id,
                    expected_measurement_revision,
                    preview["diff"],
                    preview["lifecycle_findings"],
                    _occurrence_input(preview),
                    completed_at=completed_at,
                )
            except BackendError as failure:
                if failure.code not in COMPARISON_FAILURE_CODES:
                    raise
                return self.store.save_audit_measurement_comparison(
                    assessment_id,
                    expected_assessment_revision,
                    audit_run_id,
                    expected_audit_run_revision,
                    measurement_id,
                    expected_measurement_revision,
                    failure={
                        "error_code": failure.code,
                        "error_message": failure.safe_message,
                        "failed_at": _timestamp_not_before(
                            measurement.get("resolved_at"),
                            measurement.get("created_at"),
                        ),
                    },
                )
            return self.store.save_audit_measurement_comparison(
                assessment_id,
                expected_assessment_revision,
                audit_run_id,
                expected_audit_run_revision,
                measurement_id,
                expected_measurement_revision,
                analysis=analysis,
            )
