"""PineAI v0.7.0 Repeatable Field Audits domain store.

Extends CustomerAuditStore with MeasurementPoint, AuditRun, and AuditRunMeasurement
persistence, optimistic concurrency, dynamic closure reserves, and recoverable storage.
"""

import datetime
import json
import os
import re
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from .assessment_store import (
    ASSESSMENT_ID_PATTERN,
    FINDING_ID_PATTERN,
    MAX_COMPARISONS,
    MAX_EVENTS,
    MAX_SNAPSHOTS,
    _canonical_digest,
    _ensure_no_raw_recon,
    _json_clone,
    _utc_now,
    _validate_comparison,
    _validate_revision,
    _validate_snapshot,
)
from .customer_store import (
    CUSTOMER_AUDIT_SCHEMA_VERSION,
    OCCURRENCE_SCHEMA_VERSION,
    CustomerAuditStore,
    _clean_text,
    _integer_list,
    _text_list,
)
from .errors import BackendError
from .storage_transaction import PrivateTransaction


REPEATABLE_AUDITS_SCHEMA_VERSION = "1.0"

MEASUREMENT_POINT_ID_PATTERN = re.compile(r"^mp_[0-9a-f]{16}$")
AUDIT_RUN_ID_PATTERN = re.compile(r"^ar_[0-9a-f]{16}$")
AUDIT_MEASUREMENT_ID_PATTERN = re.compile(r"^arm_[0-9a-f]{16}$")
ASSURANCE_VERSION_ID_PATTERN = re.compile(r"^assurance_v[0-9]{4}$")
SNAPSHOT_ID_PATTERN = re.compile(r"^snapshot_[0-9a-f]{16}$")
BASELINE_MODEL_ID_PATTERN = re.compile(r"^bmodel_[0-9a-f]{16}$")
BASELINE_VERSION_ID_PATTERN = re.compile(r"^baseline_v[0-9]{4}$")
MEASUREMENT_PROFILE_ID_PATTERN = re.compile(r"^mprofile_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
MEASUREMENT_PROFILE_VERSION_ID_PATTERN = re.compile(r"^mprofile_r[0-9]{4}$")
COMPARISON_ID_PATTERN = re.compile(r"^comparison_[0-9a-f]{16}$")
OCCURRENCE_SET_ID_PATTERN = re.compile(r"^occurrence_[0-9a-f]{16}$")
EVIDENCE_ID_PATTERN = re.compile(r"^evidence_[0-9a-f]{12}$")
SHA256_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")

MAX_ACTIVE_MEASUREMENT_POINTS = 64
MAX_TOTAL_MEASUREMENT_POINT_RECORDS = 90
MAX_AUDIT_RUNS_PER_ASSESSMENT = 128
MAX_MEASUREMENT_POINTS_PER_RUN = 64
MAX_MEASUREMENT_POINTS_DOCUMENT_BYTES = 512 * 1024
MAX_AUDIT_RUN_DOCUMENT_BYTES = 512 * 1024
MAX_EVIDENCE_IDS_PER_AUDIT_MEASUREMENT = 100
MAX_OCCURRENCES = 100
MAX_AUDIT_RUN_MANIFEST_BYTES = 64 * 1024
MAX_NATIVE_ARTIFACT_DOCUMENT_BYTES = 4 * 1024 * 1024
NATIVE_OCCURRENCE_SECTION_LIMITS = {
    "observed_changes": 2000,
    "policy_deviations": 7000,
    "security_findings": 3000,
    "lifecycle_findings": 500,
    "evidence": 2000,
    "limitations": 1000,
}

AUDIT_RUN_STATUSES = {"draft", "in_progress", "completed", "cancelled"}
ACTIVE_AUDIT_RUN_STATUSES = {"draft", "in_progress"}
AUDIT_RUN_MANIFEST_FIELDS = {
    "schema_version",
    "active_closure_reserve",
    "runs",
}
PRIVATE_AUDIT_RUN_FIELDS = {
    "audit_run_id",
    "assessment_id",
    "title",
    "status",
    "created_at",
    "started_at",
    "completed_at",
    "due_at",
    "pinned_assurance_profile_version_id",
    "pinned_assurance_profile_digest",
    "measurement_point_ids",
    "measurements",
    "revision",
}
NATIVE_COMPARISON_FIELDS = {
    "schema_version",
    "comparison_id",
    "assessment_id",
    "baseline_version_id",
    "created_at",
    "baseline_snapshot_id",
    "current_snapshot_id",
    "current_snapshot_digest",
    "comparability_status",
    "observed_finding_ids",
    "lifecycle",
    "comparison",
    "occurrence_set_id",
    "occurrence_digest",
    "pinned_versions",
}
NATIVE_OCCURRENCE_REQUIRED_FIELDS = {
    "schema_version",
    "occurrence_set_id",
    "occurrence_digest",
    "comparison_id",
    "assessment_id",
    "recorded_at",
    "baseline_reference",
    "pinned_versions",
    "comparability",
    "lifecycle",
    "observed_changes",
    "inventory_reconciliation",
    "policy_deviations",
    "security_findings",
    "policy_evaluation_status",
    "lifecycle_findings",
    "evidence",
    "quality_factors",
    "policy_reference",
    "limitations",
}
PINNED_VERSION_FIELDS = {
    "baseline_version_id",
    "baseline_digest",
    "measurement_profile_id",
    "measurement_profile_version_id",
    "measurement_profile_digest",
    "assurance_profile_version_id",
    "assurance_profile_digest",
}
LIFECYCLE_FIELDS = {
    "opened",
    "reopened",
    "updated",
    "resolved",
    "preserved_false_positive",
    "mutated",
}
MEASUREMENT_POINTS_DOCUMENT_FIELDS = {
    "schema_version",
    "assessment_id",
    "updated_at",
    "measurement_points",
}
PRIVATE_MEASUREMENT_POINT_FIELDS = {
    "measurement_point_id",
    "assessment_id",
    "name",
    "description",
    "status",
    "created_at",
    "archived_at",
    "revision",
    "expected_measurement_context",
}


def _read_bounded_json_file(
    store,
    path: Path,
    maximum_bytes: int,
    missing_code: str,
    invalid_code: str,
    description: str,
) -> Any:
    try:
        stat_result = path.lstat()
    except FileNotFoundError:
        raise BackendError(missing_code, "{0} is unavailable".format(description))
    except OSError as error:
        raise BackendError(
            invalid_code, "{0} metadata is unavailable".format(description)
        ) from error
    if (
        path.is_symlink()
        or not path.is_file()
        or stat_result.st_size < 2
        or stat_result.st_size > maximum_bytes
    ):
        raise BackendError(
            invalid_code, "{0} path or size is invalid".format(description)
        )
    return store._read_json(
        path, invalid_code, "{0} is unreadable".format(description)
    )


def _generate_mp_id() -> str:
    return "mp_{0}".format(uuid.uuid4().hex[:16])


def _generate_ar_id() -> str:
    return "ar_{0}".format(uuid.uuid4().hex[:16])


def _generate_arm_id() -> str:
    return "arm_{0}".format(uuid.uuid4().hex[:16])


_RFC3339_PATTERN = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?"
    r"(Z|[+-]\d{2}:\d{2})$"
)


def _validate_rfc3339(
    value: Any,
    param_name: str,
    error_code: str = "invalid_audit_run_measurement",
) -> str:
    """Validate a strict RFC 3339 date-time string.

    Accepted forms:
        YYYY-MM-DDTHH:MM:SSZ
        YYYY-MM-DDTHH:MM:SS.fractionZ
        YYYY-MM-DDTHH:MM:SS+/-HH:MM
        YYYY-MM-DDTHH:MM:SS.fraction+/-HH:MM

    Rejected forms:
        Date-only (2026-07-30)
        Naive datetime without timezone (2026-07-30T10:00:00)
        Space-separated (2026-07-30 10:00:00Z)
        Invalid calendar dates
        Invalid timezone offsets (e.g. +25:00)
    """
    if not isinstance(value, str) or not value:
        raise BackendError(
            error_code,
            "{0} must be a non-empty RFC 3339 date-time string".format(param_name),
        )

    match = _RFC3339_PATTERN.match(value)
    if match is None:
        raise BackendError(
            error_code,
            "{0} must be a valid RFC 3339 date-time string".format(param_name),
        )

    year, month, day = int(match.group(1)), int(match.group(2)), int(match.group(3))
    hour, minute, second = int(match.group(4)), int(match.group(5)), int(match.group(6))
    tz_part = match.group(8)

    # Validate calendar date via stdlib
    from datetime import date as _date

    try:
        _date(year, month, day)
    except ValueError:
        raise BackendError(
            error_code,
            "{0} contains an invalid calendar date".format(param_name),
        )

    if hour > 23 or minute > 59 or second > 59:
        raise BackendError(
            error_code,
            "{0} contains an invalid time component".format(param_name),
        )

    # Validate timezone offset bounds
    if tz_part != "Z":
        tz_hour = int(tz_part[1:3])
        tz_min = int(tz_part[4:6])
        if tz_hour > 23 or tz_min > 59:
            raise BackendError(
                error_code,
                "{0} contains an invalid timezone offset".format(param_name),
            )

    return value


def _validate_iso_datetime(
    value: Any,
    param_name: str,
    error_code: str = "invalid_audit_run_measurement",
) -> str:
    """Convenience alias for backwards compatibility."""
    return _validate_rfc3339(value, param_name, error_code=error_code)


def _rfc3339_order_key(value: str):
    """Return an exact UTC `(seconds, nanoseconds)` ordering key."""
    match = _RFC3339_PATTERN.match(value)
    if match is None:  # Defensive: callers validate before conversion.
        raise ValueError("invalid RFC 3339 value")
    fraction = int((match.group(7) or "").ljust(9, "0"))
    zone = match.group(8)
    if zone == "Z":
        offset_seconds = 0
    else:
        sign = 1 if zone[0] == "+" else -1
        offset_seconds = sign * (
            int(zone[1:3]) * 3600 + int(zone[4:6]) * 60
        )
    day = datetime.date(
        int(match.group(1)),
        int(match.group(2)),
        int(match.group(3)),
    )
    seconds = (
        day.toordinal() * 86400
        + int(match.group(4)) * 3600
        + int(match.group(5)) * 60
        + int(match.group(6))
        - offset_seconds
    )
    return (seconds, fraction)


def _timestamp_not_before(*values: Optional[str]) -> str:
    """Return current UTC time unless a persisted timestamp is later."""
    candidates = [_utc_now()]
    candidates.extend(
        value for value in values if isinstance(value, str) and value
    )
    return max(candidates, key=_rfc3339_order_key)


def _audit_run_terminal_times(audit_run: Dict[str, Any]) -> List[str]:
    values = [
        audit_run.get("created_at"),
        audit_run.get("started_at"),
    ]
    for measurement in audit_run.get("measurements", []):
        for field in ("resolved_at", "failed_at", "completed_at"):
            value = measurement.get(field)
            if isinstance(value, str):
                values.append(value)
    return [value for value in values if isinstance(value, str)]


def _sanitize_audit_run(audit_run: Dict[str, Any]) -> Dict[str, Any]:
    """Return public auditRun object adhering strictly to #/$defs/auditRun."""
    allowed = {
        "audit_run_id",
        "assessment_id",
        "title",
        "status",
        "created_at",
        "started_at",
        "completed_at",
        "due_at",
        "pinned_assurance_profile_version_id",
        "pinned_assurance_profile_digest",
        "measurement_point_ids",
        "revision",
    }
    res = {}
    for k in allowed:
        if k in audit_run:
            res[k] = audit_run[k]
        elif k in ("started_at", "completed_at", "due_at"):
            res[k] = None
    return res


def _compute_ready_to_start(audit_run: Dict[str, Any]) -> bool:
    """Compute derived ready_to_start status. Never persisted on disk."""
    if audit_run.get("status") != "draft":
        return False
    mp_ids = audit_run.get("measurement_point_ids")
    if not isinstance(mp_ids, list) or len(mp_ids) == 0:
        return False
    assurance_version = audit_run.get("pinned_assurance_profile_version_id")
    assurance_digest = audit_run.get("pinned_assurance_profile_digest")
    if not assurance_version or not assurance_digest:
        return False
    return True


RESOLVED_PINNED_FIELDS = {
    "snapshot_id",
    "snapshot_digest",
    "measurement_profile_id",
    "measurement_profile_version_id",
    "measurement_profile_digest",
    "baseline_version_id",
    "baseline_type",
    "baseline_model_id",
    "baseline_model_digest",
    "baseline_snapshot_id",
    "baseline_snapshot_digest",
    "baseline_record_digest",
    "assurance_profile_version_id",
    "assurance_profile_digest",
    "comparability_status",
    "resolved_at",
}

COMPLETED_FIELDS = {
    "comparison_id",
    "comparison_digest",
    "occurrence_set_id",
    "evidence_ids",
    "completed_at",
}

FAILURE_FIELDS = {
    "failed_stage",
    "retry_target",
    "error_code",
    "error_message",
    "failed_at",
}

CONSENSUS_FIELDS = {
    "baseline_model_id",
    "baseline_model_digest",
}

SINGLE_SCAN_FIELDS = {
    "baseline_snapshot_id",
    "baseline_snapshot_digest",
}


def _validate_audit_run_measurement(m: Dict[str, Any]) -> None:
    """Validate measurement fields strictly against the 8 variant schemas."""
    if not isinstance(m, dict):
        raise BackendError("invalid_audit_run_measurement", "measurement must be an object")

    mid = m.get("measurement_id") or m.get("audit_measurement_id")
    if not mid or not isinstance(mid, str) or not AUDIT_MEASUREMENT_ID_PATTERN.match(mid):
        raise BackendError("invalid_audit_run_measurement", "invalid measurement_id format")

    arid = m.get("audit_run_id")
    if not arid or not isinstance(arid, str) or not AUDIT_RUN_ID_PATTERN.match(arid):
        raise BackendError("invalid_audit_run_measurement", "invalid audit_run_id format")

    mpid = m.get("measurement_point_id")
    if not mpid or not isinstance(mpid, str) or not MEASUREMENT_POINT_ID_PATTERN.match(mpid):
        raise BackendError("invalid_audit_run_measurement", "invalid measurement_point_id format")

    status = m.get("status")
    if status not in ("pending", "resolved", "completed", "failed"):
        raise BackendError("invalid_audit_run_measurement", "invalid status value")

    def _val_digest(val: Any, name: str) -> None:
        if not isinstance(val, str) or not SHA256_DIGEST_PATTERN.match(val):
            raise BackendError("invalid_audit_run_measurement", "{0} must be a 64-character lowercase hex digest".format(name))

    def _val_id(val: Any, pattern: re.Pattern, name: str) -> None:
        if not isinstance(val, str) or not pattern.match(val):
            raise BackendError("invalid_audit_run_measurement", "{0} format is invalid".format(name))

    def _val_time(val: Any, name: str) -> None:
        _validate_iso_datetime(val, name)

    def _val_evidence(ev_list: Any) -> None:
        if not isinstance(ev_list, list) or len(ev_list) > MAX_EVIDENCE_IDS_PER_AUDIT_MEASUREMENT:
            raise BackendError("invalid_audit_run_measurement", "evidence_ids must be a list of at most {0} items".format(MAX_EVIDENCE_IDS_PER_AUDIT_MEASUREMENT))
        if len(ev_list) != len(set(ev_list)):
            raise BackendError("invalid_audit_run_measurement", "evidence_ids must contain unique elements")
        for item in ev_list:
            if not isinstance(item, str) or not EVIDENCE_ID_PATTERN.match(item):
                raise BackendError("invalid_audit_run_measurement", "invalid evidence_id format: {0}".format(item))

    def _val_enum(val: Any, allowed_set: set, name: str) -> None:
        if val not in allowed_set:
            raise BackendError("invalid_audit_run_measurement", "{0} must be one of {1}".format(name, allowed_set))

    def _val_str(val: Any, min_len: int, max_len: int, name: str) -> None:
        if not isinstance(val, str) or len(val) < min_len or len(val) > max_len:
            raise BackendError("invalid_audit_run_measurement", "{0} length must be between {1} and {2}".format(name, min_len, max_len))

    keys = set(m)
    keys.discard("audit_measurement_id")

    if status == "pending":
        required = {"measurement_id", "audit_run_id", "measurement_point_id", "status", "created_at"}
        if keys != required:
            raise BackendError("invalid_audit_run_measurement", "pending measurement keys mismatch")
        _val_time(m["created_at"], "created_at")

    elif status == "resolved":
        btype = m.get("baseline_type")
        if btype == "consensus":
            required = {
                "measurement_id", "audit_run_id", "measurement_point_id", "status",
                "snapshot_id", "snapshot_digest", "measurement_profile_id", "measurement_profile_version_id",
                "measurement_profile_digest", "baseline_version_id", "baseline_type", "baseline_model_id",
                "baseline_model_digest", "baseline_record_digest", "assurance_profile_version_id",
                "assurance_profile_digest", "comparability_status", "resolved_at",
            }
            allowed = required | {"source_recon_id"}
            if not required.issubset(keys) or not keys.issubset(allowed):
                raise BackendError("invalid_audit_run_measurement", "resolved consensus keys mismatch")

            _val_id(m["snapshot_id"], SNAPSHOT_ID_PATTERN, "snapshot_id")
            _val_digest(m["snapshot_digest"], "snapshot_digest")
            _val_id(m["measurement_profile_id"], MEASUREMENT_PROFILE_ID_PATTERN, "measurement_profile_id")
            _val_id(m["measurement_profile_version_id"], MEASUREMENT_PROFILE_VERSION_ID_PATTERN, "measurement_profile_version_id")
            _val_digest(m["measurement_profile_digest"], "measurement_profile_digest")
            _val_id(m["baseline_version_id"], BASELINE_VERSION_ID_PATTERN, "baseline_version_id")
            _val_id(m["baseline_model_id"], BASELINE_MODEL_ID_PATTERN, "baseline_model_id")
            _val_digest(m["baseline_model_digest"], "baseline_model_digest")
            _val_digest(m["baseline_record_digest"], "baseline_record_digest")
            _val_id(m["assurance_profile_version_id"], ASSURANCE_VERSION_ID_PATTERN, "assurance_profile_version_id")
            _val_digest(m["assurance_profile_digest"], "assurance_profile_digest")
            _val_enum(m["comparability_status"], {"comparable", "partially_comparable", "not_comparable"}, "comparability_status")
            _val_time(m["resolved_at"], "resolved_at")
            if "source_recon_id" in m and m["source_recon_id"] is not None:
                _val_str(m["source_recon_id"], 1, 128, "source_recon_id")

        elif btype == "single_scan":
            required = {
                "measurement_id", "audit_run_id", "measurement_point_id", "status",
                "snapshot_id", "snapshot_digest", "measurement_profile_id", "measurement_profile_version_id",
                "measurement_profile_digest", "baseline_version_id", "baseline_type", "baseline_snapshot_id",
                "baseline_snapshot_digest", "baseline_record_digest", "assurance_profile_version_id",
                "assurance_profile_digest", "comparability_status", "resolved_at",
            }
            allowed = required | {"source_recon_id"}
            if not required.issubset(keys) or not keys.issubset(allowed):
                raise BackendError("invalid_audit_run_measurement", "resolved single_scan keys mismatch")

            _val_id(m["snapshot_id"], SNAPSHOT_ID_PATTERN, "snapshot_id")
            _val_digest(m["snapshot_digest"], "snapshot_digest")
            _val_id(m["measurement_profile_id"], MEASUREMENT_PROFILE_ID_PATTERN, "measurement_profile_id")
            _val_id(m["measurement_profile_version_id"], MEASUREMENT_PROFILE_VERSION_ID_PATTERN, "measurement_profile_version_id")
            _val_digest(m["measurement_profile_digest"], "measurement_profile_digest")
            _val_id(m["baseline_version_id"], BASELINE_VERSION_ID_PATTERN, "baseline_version_id")
            _val_id(m["baseline_snapshot_id"], SNAPSHOT_ID_PATTERN, "baseline_snapshot_id")
            _val_digest(m["baseline_snapshot_digest"], "baseline_snapshot_digest")
            _val_digest(m["baseline_record_digest"], "baseline_record_digest")
            _val_id(m["assurance_profile_version_id"], ASSURANCE_VERSION_ID_PATTERN, "assurance_profile_version_id")
            _val_digest(m["assurance_profile_digest"], "assurance_profile_digest")
            _val_enum(m["comparability_status"], {"comparable", "partially_comparable", "not_comparable"}, "comparability_status")
            _val_time(m["resolved_at"], "resolved_at")
            if "source_recon_id" in m and m["source_recon_id"] is not None:
                _val_str(m["source_recon_id"], 1, 128, "source_recon_id")
        else:
            raise BackendError("invalid_audit_run_measurement", "invalid baseline_type")

    elif status == "completed":
        btype = m.get("baseline_type")
        if btype == "consensus":
            required = {
                "measurement_id", "audit_run_id", "measurement_point_id", "status",
                "snapshot_id", "snapshot_digest", "measurement_profile_id", "measurement_profile_version_id",
                "measurement_profile_digest", "baseline_version_id", "baseline_type", "baseline_model_id",
                "baseline_model_digest", "baseline_record_digest", "assurance_profile_version_id",
                "assurance_profile_digest", "comparability_status", "comparison_id", "comparison_digest",
                "occurrence_set_id", "evidence_ids", "completed_at",
            }
            allowed = required | {"source_recon_id"}
            if not required.issubset(keys) or not keys.issubset(allowed):
                raise BackendError("invalid_audit_run_measurement", "completed consensus keys mismatch")

            _val_id(m["snapshot_id"], SNAPSHOT_ID_PATTERN, "snapshot_id")
            _val_digest(m["snapshot_digest"], "snapshot_digest")
            _val_id(m["measurement_profile_id"], MEASUREMENT_PROFILE_ID_PATTERN, "measurement_profile_id")
            _val_id(m["measurement_profile_version_id"], MEASUREMENT_PROFILE_VERSION_ID_PATTERN, "measurement_profile_version_id")
            _val_digest(m["measurement_profile_digest"], "measurement_profile_digest")
            _val_id(m["baseline_version_id"], BASELINE_VERSION_ID_PATTERN, "baseline_version_id")
            _val_id(m["baseline_model_id"], BASELINE_MODEL_ID_PATTERN, "baseline_model_id")
            _val_digest(m["baseline_model_digest"], "baseline_model_digest")
            _val_digest(m["baseline_record_digest"], "baseline_record_digest")
            _val_id(m["assurance_profile_version_id"], ASSURANCE_VERSION_ID_PATTERN, "assurance_profile_version_id")
            _val_digest(m["assurance_profile_digest"], "assurance_profile_digest")
            _val_enum(m["comparability_status"], {"comparable", "partially_comparable", "not_comparable"}, "comparability_status")
            _val_id(m["comparison_id"], COMPARISON_ID_PATTERN, "comparison_id")
            _val_digest(m["comparison_digest"], "comparison_digest")
            _val_id(m["occurrence_set_id"], OCCURRENCE_SET_ID_PATTERN, "occurrence_set_id")
            _val_evidence(m["evidence_ids"])
            _val_time(m["completed_at"], "completed_at")
            if "source_recon_id" in m and m["source_recon_id"] is not None:
                _val_str(m["source_recon_id"], 1, 128, "source_recon_id")

        elif btype == "single_scan":
            required = {
                "measurement_id", "audit_run_id", "measurement_point_id", "status",
                "snapshot_id", "snapshot_digest", "measurement_profile_id", "measurement_profile_version_id",
                "measurement_profile_digest", "baseline_version_id", "baseline_type", "baseline_snapshot_id",
                "baseline_snapshot_digest", "baseline_record_digest", "assurance_profile_version_id",
                "assurance_profile_digest", "comparability_status", "comparison_id", "comparison_digest",
                "occurrence_set_id", "evidence_ids", "completed_at",
            }
            allowed = required | {"source_recon_id"}
            if not required.issubset(keys) or not keys.issubset(allowed):
                raise BackendError("invalid_audit_run_measurement", "completed single_scan keys mismatch")

            _val_id(m["snapshot_id"], SNAPSHOT_ID_PATTERN, "snapshot_id")
            _val_digest(m["snapshot_digest"], "snapshot_digest")
            _val_id(m["measurement_profile_id"], MEASUREMENT_PROFILE_ID_PATTERN, "measurement_profile_id")
            _val_id(m["measurement_profile_version_id"], MEASUREMENT_PROFILE_VERSION_ID_PATTERN, "measurement_profile_version_id")
            _val_digest(m["measurement_profile_digest"], "measurement_profile_digest")
            _val_id(m["baseline_version_id"], BASELINE_VERSION_ID_PATTERN, "baseline_version_id")
            _val_id(m["baseline_snapshot_id"], SNAPSHOT_ID_PATTERN, "baseline_snapshot_id")
            _val_digest(m["baseline_snapshot_digest"], "baseline_snapshot_digest")
            _val_digest(m["baseline_record_digest"], "baseline_record_digest")
            _val_id(m["assurance_profile_version_id"], ASSURANCE_VERSION_ID_PATTERN, "assurance_profile_version_id")
            _val_digest(m["assurance_profile_digest"], "assurance_profile_digest")
            _val_enum(m["comparability_status"], {"comparable", "partially_comparable", "not_comparable"}, "comparability_status")
            _val_id(m["comparison_id"], COMPARISON_ID_PATTERN, "comparison_id")
            _val_digest(m["comparison_digest"], "comparison_digest")
            _val_id(m["occurrence_set_id"], OCCURRENCE_SET_ID_PATTERN, "occurrence_set_id")
            _val_evidence(m["evidence_ids"])
            _val_time(m["completed_at"], "completed_at")
            if "source_recon_id" in m and m["source_recon_id"] is not None:
                _val_str(m["source_recon_id"], 1, 128, "source_recon_id")
        else:
            raise BackendError("invalid_audit_run_measurement", "invalid baseline_type")

    elif status == "failed":
        fstage = m.get("failed_stage")
        rtarget = m.get("retry_target")
        if fstage == "resolution":
            if rtarget != "pending":
                raise BackendError("invalid_audit_run_transition", "resolution failure must have retry_target pending")
            required = {
                "measurement_id", "audit_run_id", "measurement_point_id", "status",
                "failed_stage", "error_code", "error_message", "failed_at", "retry_target",
            }
            allowed = required
            if keys != allowed:
                raise BackendError("invalid_audit_run_measurement", "failed resolution keys mismatch")

            _val_str(m["error_code"], 1, 128, "error_code")
            _val_str(m["error_message"], 0, 1024, "error_message")
            _val_time(m["failed_at"], "failed_at")

        elif fstage == "comparison":
            if rtarget != "resolved":
                raise BackendError("invalid_audit_run_transition", "comparison failure must have retry_target resolved")
            btype = m.get("baseline_type")
            if btype == "consensus":
                required = {
                    "measurement_id", "audit_run_id", "measurement_point_id", "status",
                    "failed_stage", "retry_target", "snapshot_id", "snapshot_digest",
                    "measurement_profile_id", "measurement_profile_version_id", "measurement_profile_digest",
                    "baseline_version_id", "baseline_type", "baseline_model_id", "baseline_model_digest",
                    "baseline_record_digest", "assurance_profile_version_id", "assurance_profile_digest",
                    "comparability_status", "resolved_at", "error_code", "error_message", "failed_at",
                }
                allowed = required | {"source_recon_id"}
                if not required.issubset(keys) or not keys.issubset(allowed):
                    raise BackendError("invalid_audit_run_measurement", "failed comparison consensus keys mismatch")

                _val_id(m["snapshot_id"], SNAPSHOT_ID_PATTERN, "snapshot_id")
                _val_digest(m["snapshot_digest"], "snapshot_digest")
                _val_id(m["measurement_profile_id"], MEASUREMENT_PROFILE_ID_PATTERN, "measurement_profile_id")
                _val_id(m["measurement_profile_version_id"], MEASUREMENT_PROFILE_VERSION_ID_PATTERN, "measurement_profile_version_id")
                _val_digest(m["measurement_profile_digest"], "measurement_profile_digest")
                _val_id(m["baseline_version_id"], BASELINE_VERSION_ID_PATTERN, "baseline_version_id")
                _val_id(m["baseline_model_id"], BASELINE_MODEL_ID_PATTERN, "baseline_model_id")
                _val_digest(m["baseline_model_digest"], "baseline_model_digest")
                _val_digest(m["baseline_record_digest"], "baseline_record_digest")
                _val_id(m["assurance_profile_version_id"], ASSURANCE_VERSION_ID_PATTERN, "assurance_profile_version_id")
                _val_digest(m["assurance_profile_digest"], "assurance_profile_digest")
                _val_enum(m["comparability_status"], {"comparable", "partially_comparable", "not_comparable"}, "comparability_status")
                _val_time(m["resolved_at"], "resolved_at")
                _val_str(m["error_code"], 1, 128, "error_code")
                _val_str(m["error_message"], 0, 1024, "error_message")
                _val_time(m["failed_at"], "failed_at")
                if "source_recon_id" in m and m["source_recon_id"] is not None:
                    _val_str(m["source_recon_id"], 1, 128, "source_recon_id")

            elif btype == "single_scan":
                required = {
                    "measurement_id", "audit_run_id", "measurement_point_id", "status",
                    "failed_stage", "retry_target", "snapshot_id", "snapshot_digest",
                    "measurement_profile_id", "measurement_profile_version_id", "measurement_profile_digest",
                    "baseline_version_id", "baseline_type", "baseline_snapshot_id", "baseline_snapshot_digest",
                    "baseline_record_digest", "assurance_profile_version_id", "assurance_profile_digest",
                    "comparability_status", "resolved_at", "error_code", "error_message", "failed_at",
                }
                allowed = required | {"source_recon_id"}
                if not required.issubset(keys) or not keys.issubset(allowed):
                    raise BackendError("invalid_audit_run_measurement", "failed comparison single_scan keys mismatch")

                _val_id(m["snapshot_id"], SNAPSHOT_ID_PATTERN, "snapshot_id")
                _val_digest(m["snapshot_digest"], "snapshot_digest")
                _val_id(m["measurement_profile_id"], MEASUREMENT_PROFILE_ID_PATTERN, "measurement_profile_id")
                _val_id(m["measurement_profile_version_id"], MEASUREMENT_PROFILE_VERSION_ID_PATTERN, "measurement_profile_version_id")
                _val_digest(m["measurement_profile_digest"], "measurement_profile_digest")
                _val_id(m["baseline_version_id"], BASELINE_VERSION_ID_PATTERN, "baseline_version_id")
                _val_id(m["baseline_snapshot_id"], SNAPSHOT_ID_PATTERN, "baseline_snapshot_id")
                _val_digest(m["baseline_snapshot_digest"], "baseline_snapshot_digest")
                _val_digest(m["baseline_record_digest"], "baseline_record_digest")
                _val_id(m["assurance_profile_version_id"], ASSURANCE_VERSION_ID_PATTERN, "assurance_profile_version_id")
                _val_digest(m["assurance_profile_digest"], "assurance_profile_digest")
                _val_enum(m["comparability_status"], {"comparable", "partially_comparable", "not_comparable"}, "comparability_status")
                _val_time(m["resolved_at"], "resolved_at")
                _val_str(m["error_code"], 1, 128, "error_code")
                _val_str(m["error_message"], 0, 1024, "error_message")
                _val_time(m["failed_at"], "failed_at")
                if "source_recon_id" in m and m["source_recon_id"] is not None:
                    _val_str(m["source_recon_id"], 1, 128, "source_recon_id")
            else:
                raise BackendError("invalid_audit_run_measurement", "invalid baseline_type")
        else:
            raise BackendError("invalid_audit_run_transition", "unknown failed_stage")


def _validate_persisted_measurement(m: Dict[str, Any]) -> None:
    if not isinstance(m, dict):
        raise BackendError("invalid_audit_run_measurement", "measurement must be an object")

    status = m.get("status")
    if status == "pending":
        keys = set(m)
        keys.discard("audit_measurement_id")
        required = {"measurement_id", "audit_run_id", "measurement_point_id", "status", "created_at", "expected_measurement_context"}
        if keys != required:
            raise BackendError("invalid_audit_run_measurement", "persisted pending measurement keys mismatch")
        public_measurement = dict(m)
        public_measurement.pop("expected_measurement_context", None)
        _validate_audit_run_measurement(public_measurement)
        _validate_expected_measurement_context(m["expected_measurement_context"], measurement_point_id=m["measurement_point_id"])
    elif status == "failed" and m.get("failed_stage") == "resolution":
        if "expected_measurement_context" not in m:
            raise BackendError(
                "invalid_audit_run_measurement",
                "failed resolution measurement is missing its immutable context",
            )
        public_measurement = dict(m)
        context = public_measurement.pop("expected_measurement_context")
        _validate_audit_run_measurement(public_measurement)
        _validate_expected_measurement_context(
            context, measurement_point_id=m.get("measurement_point_id")
        )
    else:
        _validate_audit_run_measurement(m)


def _validate_lifecycle(value: Any, error_code: str) -> Dict[str, Any]:
    if not isinstance(value, dict) or set(value) != LIFECYCLE_FIELDS:
        raise BackendError(error_code, "lifecycle fields are invalid")
    result = {}
    for field in LIFECYCLE_FIELDS - {"mutated"}:
        items = value.get(field)
        if not isinstance(items, list) or len(items) > 500:
            raise BackendError(error_code, "lifecycle {0} is invalid".format(field))
        if len(items) != len(set(items)):
            raise BackendError(
                error_code,
                "lifecycle {0} contains duplicate finding IDs".format(field),
            )
        for finding_id in items:
            if (
                not isinstance(finding_id, str)
                or not FINDING_ID_PATTERN.match(finding_id)
            ):
                raise BackendError(
                    error_code,
                    "lifecycle {0} contains an invalid finding ID".format(field),
                )
        result[field] = list(items)
    if not isinstance(value.get("mutated"), bool):
        raise BackendError(error_code, "lifecycle mutated must be a boolean")
    result["mutated"] = value["mutated"]
    return result


def _validate_pinned_versions(value: Any, error_code: str) -> Dict[str, Any]:
    if not isinstance(value, dict) or set(value) != PINNED_VERSION_FIELDS:
        raise BackendError(error_code, "pinned_versions fields are invalid")

    required_patterns = (
        ("baseline_version_id", BASELINE_VERSION_ID_PATTERN),
        ("measurement_profile_id", MEASUREMENT_PROFILE_ID_PATTERN),
        (
            "measurement_profile_version_id",
            MEASUREMENT_PROFILE_VERSION_ID_PATTERN,
        ),
    )
    for field, pattern in required_patterns:
        item = value.get(field)
        if not isinstance(item, str) or not pattern.match(item):
            raise BackendError(error_code, "{0} is invalid".format(field))

    for field in ("baseline_digest", "measurement_profile_digest"):
        item = value.get(field)
        if not isinstance(item, str) or not SHA256_DIGEST_PATTERN.match(item):
            raise BackendError(error_code, "{0} is invalid".format(field))

    assurance_version = value.get("assurance_profile_version_id")
    assurance_digest = value.get("assurance_profile_digest")
    if assurance_version is None or assurance_digest is None:
        if assurance_version is not None or assurance_digest is not None:
            raise BackendError(
                error_code,
                "assurance profile version and digest must both be null or valid",
            )
    else:
        if (
            not isinstance(assurance_version, str)
            or not ASSURANCE_VERSION_ID_PATTERN.match(assurance_version)
            or not isinstance(assurance_digest, str)
            or not SHA256_DIGEST_PATTERN.match(assurance_digest)
        ):
            raise BackendError(error_code, "assurance profile pin is invalid")
    return dict(value)


def _validate_audit_runs_manifest(value: Any) -> Dict[str, Any]:
    """Validate the exact private AuditRun manifest shape.

    The stored closure reserve is only accepted when it agrees with the
    authoritative status map. Callers still derive capacity from ``runs``.
    """
    if not isinstance(value, dict) or set(value) != AUDIT_RUN_MANIFEST_FIELDS:
        raise BackendError(
            "invalid_audit_run_manifest", "audit run manifest fields are invalid"
        )
    if value.get("schema_version") != REPEATABLE_AUDITS_SCHEMA_VERSION:
        raise BackendError(
            "invalid_audit_run_manifest",
            "audit run manifest schema_version is unsupported",
        )
    runs = value.get("runs")
    if not isinstance(runs, dict) or len(runs) > MAX_AUDIT_RUNS_PER_ASSESSMENT:
        raise BackendError(
            "invalid_audit_run_manifest", "audit run manifest runs are invalid"
        )
    normalized_runs = {}
    for audit_run_id, status in runs.items():
        if (
            not isinstance(audit_run_id, str)
            or not AUDIT_RUN_ID_PATTERN.match(audit_run_id)
            or status not in AUDIT_RUN_STATUSES
        ):
            raise BackendError(
                "invalid_audit_run_manifest",
                "audit run manifest contains an invalid run entry",
            )
        normalized_runs[audit_run_id] = status
    reserve = value.get("active_closure_reserve")
    derived_reserve = sum(
        1 for status in normalized_runs.values() if status in ACTIVE_AUDIT_RUN_STATUSES
    )
    if (
        not isinstance(reserve, int)
        or isinstance(reserve, bool)
        or reserve < 0
        or reserve != derived_reserve
    ):
        raise BackendError(
            "invalid_audit_run_manifest",
            "audit run manifest closure reserve is inconsistent",
        )
    return {
        "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
        "active_closure_reserve": derived_reserve,
        "runs": normalized_runs,
    }


def _validate_private_audit_run_document(
    value: Any,
    expected_assessment_id: Optional[str] = None,
    expected_audit_run_id: Optional[str] = None,
) -> Dict[str, Any]:
    run = _json_clone(value, "invalid_audit_run", "audit run")
    if not isinstance(run, dict) or set(run) != PRIVATE_AUDIT_RUN_FIELDS:
        raise BackendError("invalid_audit_run", "audit run fields are invalid")
    _ensure_no_raw_recon(run)

    audit_run_id = run.get("audit_run_id")
    assessment_id = run.get("assessment_id")
    if (
        not isinstance(audit_run_id, str)
        or not AUDIT_RUN_ID_PATTERN.match(audit_run_id)
        or (
            expected_audit_run_id is not None
            and audit_run_id != expected_audit_run_id
        )
    ):
        raise BackendError("invalid_audit_run", "audit_run_id is invalid")
    if (
        not isinstance(assessment_id, str)
        or not ASSESSMENT_ID_PATTERN.match(assessment_id)
        or (
            expected_assessment_id is not None
            and assessment_id != expected_assessment_id
        )
    ):
        raise BackendError("invalid_audit_run", "assessment_id is invalid")

    title = run.get("title")
    if (
        not isinstance(title, str)
        or not title
        or len(title) > 128
        or any(ord(character) < 32 for character in title)
    ):
        raise BackendError("invalid_audit_run", "title is invalid")
    status = run.get("status")
    if status not in AUDIT_RUN_STATUSES:
        raise BackendError("invalid_audit_run", "audit run status is invalid")
    _validate_rfc3339(run.get("created_at"), "created_at", "invalid_audit_run")
    for field in ("started_at", "completed_at", "due_at"):
        if run.get(field) is not None:
            _validate_rfc3339(run[field], field, "invalid_audit_run")

    created_time = _rfc3339_order_key(run["created_at"])
    started_time = (
        _rfc3339_order_key(run["started_at"])
        if run.get("started_at") is not None
        else None
    )
    completed_time = (
        _rfc3339_order_key(run["completed_at"])
        if run.get("completed_at") is not None
        else None
    )
    if started_time is not None and started_time < created_time:
        raise BackendError(
            "invalid_audit_run", "started_at precedes audit run creation"
        )
    if completed_time is not None and completed_time < created_time:
        raise BackendError(
            "invalid_audit_run", "completed_at precedes audit run creation"
        )
    if (
        started_time is not None
        and completed_time is not None
        and completed_time < started_time
    ):
        raise BackendError(
            "invalid_audit_run", "completed_at precedes audit run start"
        )

    if status == "draft":
        if run.get("started_at") is not None or run.get("completed_at") is not None:
            raise BackendError("invalid_audit_run", "draft audit run timestamps conflict")
    elif status == "in_progress":
        if run.get("started_at") is None or run.get("completed_at") is not None:
            raise BackendError(
                "invalid_audit_run", "in-progress audit run timestamps conflict"
            )
    elif status == "completed":
        if run.get("started_at") is None or run.get("completed_at") is None:
            raise BackendError(
                "invalid_audit_run", "completed audit run timestamps are incomplete"
            )
    elif status == "cancelled" and run.get("completed_at") is None:
        raise BackendError(
            "invalid_audit_run", "cancelled audit run completed_at is required"
        )

    assurance_version = run.get("pinned_assurance_profile_version_id")
    assurance_digest = run.get("pinned_assurance_profile_digest")
    if (
        not isinstance(assurance_version, str)
        or not ASSURANCE_VERSION_ID_PATTERN.match(assurance_version)
        or not isinstance(assurance_digest, str)
        or not SHA256_DIGEST_PATTERN.match(assurance_digest)
    ):
        raise BackendError("invalid_audit_run", "assurance profile pin is invalid")

    point_ids = run.get("measurement_point_ids")
    measurements = run.get("measurements")
    if (
        not isinstance(point_ids, list)
        or not (1 <= len(point_ids) <= MAX_MEASUREMENT_POINTS_PER_RUN)
        or len(point_ids) != len(set(point_ids))
        or not isinstance(measurements, list)
        or len(measurements) != len(point_ids)
    ):
        raise BackendError("invalid_audit_run", "audit run measurements are invalid")
    for point_id in point_ids:
        if (
            not isinstance(point_id, str)
            or not MEASUREMENT_POINT_ID_PATTERN.match(point_id)
        ):
            raise BackendError("invalid_audit_run", "measurement point ID is invalid")

    measurement_point_ids = []
    measurement_ids = []
    for measurement in measurements:
        _validate_persisted_measurement(measurement)
        if measurement.get("audit_run_id") != audit_run_id:
            raise BackendError(
                "invalid_audit_run",
                "measurement audit_run_id does not match its document",
            )
        measurement_point_ids.append(measurement.get("measurement_point_id"))
        measurement_ids.append(
            measurement.get("measurement_id")
            or measurement.get("audit_measurement_id")
        )
    if (
        measurement_point_ids != point_ids
        or len(measurement_ids) != len(set(measurement_ids))
    ):
        raise BackendError(
            "invalid_audit_run", "audit run measurement references are inconsistent"
        )

    measurement_statuses = [item.get("status") for item in measurements]
    if status == "draft" and any(
        item_status != "pending" for item_status in measurement_statuses
    ):
        raise BackendError(
            "invalid_audit_run", "draft audit runs may contain only pending measurements"
        )
    if status == "completed" and any(
        item_status != "completed" for item_status in measurement_statuses
    ):
        raise BackendError(
            "invalid_audit_run",
            "completed audit runs must contain only completed measurements",
        )

    lower_bound = started_time or created_time
    for measurement in measurements:
        timestamp_field = None
        if measurement.get("status") == "resolved":
            timestamp_field = "resolved_at"
        elif measurement.get("status") == "completed":
            timestamp_field = "completed_at"
        elif measurement.get("status") == "failed":
            timestamp_field = "failed_at"
        if timestamp_field is not None:
            measurement_time = _rfc3339_order_key(
                measurement[timestamp_field]
            )
            if measurement_time < lower_bound:
                raise BackendError(
                    "invalid_audit_run",
                    "{0} precedes the audit run".format(timestamp_field),
                )
            if (
                completed_time is not None
                and measurement_time > completed_time
            ):
                raise BackendError(
                    "invalid_audit_run",
                    "{0} follows the sealed audit run".format(timestamp_field),
                )
        if (
            measurement.get("status") == "failed"
            and measurement.get("failed_stage") == "comparison"
            and _rfc3339_order_key(measurement["failed_at"])
            < _rfc3339_order_key(measurement["resolved_at"])
        ):
            raise BackendError(
                "invalid_audit_run",
                "failed_at precedes resolved_at for comparison failure",
            )

    revision = run.get("revision")
    if (
        not isinstance(revision, int)
        or isinstance(revision, bool)
        or revision < 1
    ):
        raise BackendError("invalid_audit_run", "audit run revision is invalid")
    return run


def _validate_measurement_points_document(
    value: Any, expected_assessment_id: str
) -> Dict[str, Any]:
    document = _json_clone(
        value, "invalid_measurement_point", "measurement points document"
    )
    if (
        not isinstance(document, dict)
        or set(document) != MEASUREMENT_POINTS_DOCUMENT_FIELDS
        or document.get("schema_version") != REPEATABLE_AUDITS_SCHEMA_VERSION
        or document.get("assessment_id") != expected_assessment_id
    ):
        raise BackendError(
            "invalid_measurement_point",
            "measurement points document fields are invalid",
        )
    _ensure_no_raw_recon(document)
    _validate_rfc3339(
        document.get("updated_at"),
        "updated_at",
        "invalid_measurement_point",
    )
    points = document.get("measurement_points")
    if (
        not isinstance(points, list)
        or len(points) > MAX_TOTAL_MEASUREMENT_POINT_RECORDS
    ):
        raise BackendError(
            "invalid_measurement_point", "measurement point count is invalid"
        )
    identifiers = []
    active_count = 0
    for point in points:
        if (
            not isinstance(point, dict)
            or set(point) != PRIVATE_MEASUREMENT_POINT_FIELDS
        ):
            raise BackendError(
                "invalid_measurement_point", "measurement point fields are invalid"
            )
        point_id = point.get("measurement_point_id")
        if (
            not isinstance(point_id, str)
            or not MEASUREMENT_POINT_ID_PATTERN.match(point_id)
            or point.get("assessment_id") != expected_assessment_id
        ):
            raise BackendError(
                "invalid_measurement_point", "measurement point identity is invalid"
            )
        identifiers.append(point_id)
        name = point.get("name")
        description = point.get("description")
        if (
            not isinstance(name, str)
            or not name
            or len(name) > 128
            or any(ord(character) < 32 for character in name)
            or (
                description is not None
                and (
                    not isinstance(description, str)
                    or len(description) > 512
                    or any(ord(character) < 32 for character in description)
                )
            )
        ):
            raise BackendError(
                "invalid_measurement_point", "measurement point text is invalid"
            )
        status = point.get("status")
        if status not in {"active", "archived"}:
            raise BackendError(
                "invalid_measurement_point", "measurement point status is invalid"
            )
        _validate_rfc3339(
            point.get("created_at"),
            "created_at",
            "invalid_measurement_point",
        )
        archived_at = point.get("archived_at")
        if status == "active":
            active_count += 1
            if archived_at is not None:
                raise BackendError(
                    "invalid_measurement_point",
                    "active measurement point cannot have archived_at",
                )
        else:
            _validate_rfc3339(
                archived_at, "archived_at", "invalid_measurement_point"
            )
        revision = point.get("revision")
        if (
            not isinstance(revision, int)
            or isinstance(revision, bool)
            or revision < 1
        ):
            raise BackendError(
                "invalid_measurement_point", "measurement point revision is invalid"
            )
        _validate_expected_measurement_context(
            point.get("expected_measurement_context"),
            measurement_point_id=point_id,
        )
    if len(identifiers) != len(set(identifiers)):
        raise BackendError(
            "invalid_measurement_point", "measurement point IDs are not unique"
        )
    if active_count > MAX_ACTIVE_MEASUREMENT_POINTS:
        raise BackendError(
            "invalid_measurement_point",
            "active measurement point count exceeds the frozen limit",
        )
    return document


def _to_public_measurement(m: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(m, dict):
        raise BackendError("invalid_audit_run_measurement", "measurement must be an object")

    m_copy = dict(m)
    if "audit_measurement_id" in m_copy and "measurement_id" not in m_copy:
        m_copy["measurement_id"] = m_copy.pop("audit_measurement_id")
    else:
        m_copy.pop("audit_measurement_id", None)

    # The context is a private AuditRun pin. It remains on disk across a
    # resolution failure so retry cannot silently adopt a later point edit,
    # but it is not part of any public measurement union branch.
    m_copy.pop("expected_measurement_context", None)

    _validate_audit_run_measurement(m_copy)
    return m_copy


def _sanitize_measurement(m: Dict[str, Any]) -> Dict[str, Any]:
    """Validate measurement strictly and return a clean dict conforming to public branch schema."""
    return _to_public_measurement(m)


def _validate_expected_measurement_context(
    context: Any, measurement_point_id: Optional[str] = None
) -> Dict[str, Any]:
    if not isinstance(context, dict):
        raise BackendError(
            "invalid_measurement_point",
            "expected measurement context must be an object",
        )
    allowed = {
        "location_id",
        "scan_profile_id",
        "radio_profile_id",
        "interface",
        "declared_bands",
        "declared_channels",
        "scan_time",
    }
    if measurement_point_id is not None:
        allowed.add("measurement_point_id")

    if set(context) - allowed:
        raise BackendError(
            "invalid_measurement_point",
            "expected measurement context contains unsupported fields",
        )
    required = {
        "location_id",
        "scan_profile_id",
        "radio_profile_id",
        "interface",
        "declared_bands",
        "declared_channels",
        "scan_time",
    }
    if not required.issubset(set(context)):
        missing = sorted(required - set(context))
        raise BackendError(
            "invalid_measurement_point",
            "expected measurement context fields are incomplete: {0}".format(
                ", ".join(missing)
            ),
        )

    res = {
        "location_id": _clean_text(context.get("location_id"), "location_id", 128, required=True),
        "scan_profile_id": _clean_text(context.get("scan_profile_id"), "scan_profile_id", 128, required=True),
        "radio_profile_id": _clean_text(context.get("radio_profile_id"), "radio_profile_id", 128, required=True),
        "interface": _clean_text(context.get("interface"), "interface", 64, required=True),
        "declared_bands": _text_list(context.get("declared_bands"), "declared_bands", allowed={"2.4", "5"}, maximum=2),
        "declared_channels": _integer_list(context.get("declared_channels"), "declared_channels", 1, 196),
        "scan_time": context.get("scan_time"),
    }
    if not res["declared_bands"]:
        raise BackendError("invalid_measurement_point", "declared_bands must not be empty")
    if not res["declared_channels"]:
        raise BackendError("invalid_measurement_point", "declared_channels must not be empty")
    if (
        not isinstance(res["scan_time"], int)
        or isinstance(res["scan_time"], bool)
        or res["scan_time"] < 30
        or res["scan_time"] > 3600
    ):
        raise BackendError("invalid_measurement_point", "scan_time must be between 30 and 3600 seconds")

    if measurement_point_id is not None:
        if "measurement_point_id" in context and context.get("measurement_point_id") != measurement_point_id:
            raise BackendError(
                "invalid_measurement_point",
                "measurement_point_id in context does not match expected id",
            )
        res["measurement_point_id"] = measurement_point_id

    return res


class RepeatableAuditStore(CustomerAuditStore):
    """Domain store for Repeatable Field Audits v0.7.0."""

    def _event_closure_reserve_unlocked(self, assessment_id: str) -> int:
        manifest = self._read_audit_runs_manifest_unlocked(assessment_id)
        return sum(
            1
            for status in manifest["runs"].values()
            if status in ACTIVE_AUDIT_RUN_STATUSES
        )

    def _require_event_slot_unlocked(
        self,
        assessment_id: str,
        metadata: Dict[str, Any],
        terminal_audit_run_event: bool = False,
        extra_closure_reserve: int = 0,
    ) -> None:
        reserve = self._event_closure_reserve_unlocked(assessment_id)
        if terminal_audit_run_event and reserve:
            reserve -= 1
        reserve += extra_closure_reserve
        sequence = metadata.get("last_event_sequence", 0)
        if (
            not isinstance(sequence, int)
            or isinstance(sequence, bool)
            or sequence < 0
            or sequence + 1 + reserve > MAX_EVENTS
        ):
            raise BackendError("event_limit", "event capacity limit exceeded")

    def _transaction_event(
        self,
        assessment_id: str,
        metadata: Dict[str, Any],
        event_type: str,
        data: Optional[Dict[str, Any]],
    ):
        self._require_event_slot_unlocked(
            assessment_id,
            metadata,
            terminal_audit_run_event=event_type
            in {"audit_run_cancelled", "audit_run_completed"},
        )
        return super()._transaction_event(
            assessment_id, metadata, event_type, data
        )

    def _append_event(
        self,
        metadata: Dict[str, Any],
        event_type: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        self._require_event_slot_unlocked(
            metadata["assessment_id"], metadata
        )
        return super()._append_event(metadata, event_type, data)

    def archive(
        self, assessment_id: str, expected_revision: Any
    ) -> Dict[str, Any]:
        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_revision)
            active_runs = [
                audit_run_id
                for audit_run_id, status in self._read_audit_runs_manifest_unlocked(
                    assessment_id
                )["runs"].items()
                if status in ACTIVE_AUDIT_RUN_STATUSES
            ]
            if active_runs:
                raise BackendError(
                    "active_audit_runs",
                    "assessment cannot be archived while audit runs are active",
                )
            metadata["status"] = "archived"
            event, event_bytes = self._transaction_event(
                assessment_id, metadata, "assessment_archived", None
            )
            base = self._ensure_assessment_directories(assessment_id)
            transaction = PrivateTransaction(
                base, fault_injector=self.fault_injector
            )
            transaction.add_json("assessment.json", metadata)
            transaction.add_bytes("events.jsonl", event_bytes)
            transaction.commit()
        result = dict(metadata)
        result["events"] = [event]
        return result

    def _ensure_assessment_directories(self, assessment_id: str) -> Path:
        base = super()._ensure_assessment_directories(assessment_id)
        self._ensure_private_directory(base / "audit_runs")
        return base

    def _validate_audit_run_size(self, audit_run: Dict[str, Any]) -> bytes:
        _validate_private_audit_run_document(
            audit_run,
            expected_assessment_id=audit_run.get("assessment_id"),
            expected_audit_run_id=audit_run.get("audit_run_id"),
        )
        run_bytes = json.dumps(audit_run, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
        if len(run_bytes) > MAX_AUDIT_RUN_DOCUMENT_BYTES:
            raise BackendError("storage_limit_exceeded", "audit run document size exceeded limit")
        return run_bytes

    def _validate_native_comparison_record(
        self,
        assessment_id: str,
        comparison_id: str,
        data: Any,
    ) -> Dict[str, Any]:
        if not isinstance(data, dict) or set(data) != NATIVE_COMPARISON_FIELDS:
            raise BackendError(
                "invalid_comparison", "native comparison fields are invalid"
            )
        _ensure_no_raw_recon(data)
        if data.get("schema_version") != CUSTOMER_AUDIT_SCHEMA_VERSION:
            raise BackendError(
                "invalid_comparison", "native comparison schema_version is unsupported"
            )
        if (
            data.get("comparison_id") != comparison_id
            or not COMPARISON_ID_PATTERN.match(comparison_id)
            or data.get("assessment_id") != assessment_id
        ):
            raise BackendError(
                "invalid_comparison", "native comparison identity is invalid"
            )
        baseline_version_id = data.get("baseline_version_id")
        if (
            not isinstance(baseline_version_id, str)
            or not BASELINE_VERSION_ID_PATTERN.match(baseline_version_id)
        ):
            raise BackendError(
                "invalid_comparison", "baseline_version_id is invalid"
            )
        _validate_rfc3339(
            data.get("created_at"), "created_at", "invalid_comparison"
        )
        nested = _validate_comparison(data.get("comparison"))
        if (
            nested["baseline_snapshot_id"] != data.get("baseline_snapshot_id")
            or nested["current_snapshot_id"] != data.get("current_snapshot_id")
            or nested["comparability"]["status"]
            != data.get("comparability_status")
        ):
            raise BackendError(
                "invalid_comparison",
                "native comparison outer and nested references disagree",
            )

        current_snapshot_id = data.get("current_snapshot_id")
        current_snapshot_digest = data.get("current_snapshot_digest")
        if (
            not isinstance(current_snapshot_id, str)
            or not SNAPSHOT_ID_PATTERN.match(current_snapshot_id)
            or not isinstance(current_snapshot_digest, str)
            or not SHA256_DIGEST_PATTERN.match(current_snapshot_digest)
        ):
            raise BackendError(
                "invalid_comparison", "current snapshot reference is invalid"
            )
        self._validate_artifact_reference(
            assessment_id,
            "snapshot",
            current_snapshot_id,
            expected_digest=current_snapshot_digest,
        )

        observed_finding_ids = data.get("observed_finding_ids")
        if (
            not isinstance(observed_finding_ids, list)
            or len(observed_finding_ids) > 500
            or len(observed_finding_ids) != len(set(observed_finding_ids))
        ):
            raise BackendError(
                "invalid_comparison", "observed_finding_ids are invalid"
            )
        for finding_id in observed_finding_ids:
            if (
                not isinstance(finding_id, str)
                or not FINDING_ID_PATTERN.match(finding_id)
            ):
                raise BackendError(
                    "invalid_comparison", "observed finding ID is invalid"
                )
        lifecycle = _validate_lifecycle(
            data.get("lifecycle"), "invalid_comparison"
        )
        if set(observed_finding_ids) != set(
            lifecycle["opened"]
            + lifecycle["reopened"]
            + lifecycle["updated"]
            + lifecycle["preserved_false_positive"]
        ):
            raise BackendError(
                "invalid_comparison",
                "observed findings conflict with lifecycle occurrence state",
            )

        occurrence_id = data.get("occurrence_set_id")
        occurrence_digest = data.get("occurrence_digest")
        if (
            not isinstance(occurrence_id, str)
            or not OCCURRENCE_SET_ID_PATTERN.match(occurrence_id)
            or not isinstance(occurrence_digest, str)
            or not SHA256_DIGEST_PATTERN.match(occurrence_digest)
        ):
            raise BackendError(
                "invalid_comparison", "occurrence reference is invalid"
            )
        _validate_pinned_versions(data.get("pinned_versions"), "invalid_comparison")

        expected_id = self._comparison_id(
            assessment_id, baseline_version_id, nested
        )
        if expected_id != comparison_id:
            raise BackendError(
                "invalid_comparison",
                "comparison_id does not match the production writer algorithm",
            )
        return data

    def _validate_native_occurrence_record(
        self,
        assessment_id: str,
        occurrence_id: str,
        data: Any,
        expected_comparison_id: Optional[str],
    ) -> Dict[str, Any]:
        if (
            not isinstance(data, dict)
            or not NATIVE_OCCURRENCE_REQUIRED_FIELDS.issubset(set(data))
        ):
            raise BackendError(
                "invalid_occurrence_set",
                "native occurrence result sections are incomplete",
            )
        _ensure_no_raw_recon(data)
        if data.get("schema_version") != OCCURRENCE_SCHEMA_VERSION:
            raise BackendError(
                "invalid_occurrence_set",
                "native occurrence schema_version is unsupported",
            )
        if (
            data.get("occurrence_set_id") != occurrence_id
            or not OCCURRENCE_SET_ID_PATTERN.match(occurrence_id)
            or data.get("assessment_id") != assessment_id
        ):
            raise BackendError(
                "invalid_occurrence_set", "native occurrence identity is invalid"
            )
        comparison_id = data.get("comparison_id")
        if (
            not isinstance(comparison_id, str)
            or not COMPARISON_ID_PATTERN.match(comparison_id)
            or (
                expected_comparison_id is not None
                and comparison_id != expected_comparison_id
            )
        ):
            raise BackendError(
                "invalid_occurrence_set",
                "native occurrence comparison reference is invalid",
            )
        _validate_rfc3339(
            data.get("recorded_at"), "recorded_at", "invalid_occurrence_set"
        )
        baseline_reference = data.get("baseline_reference")
        if (
            not isinstance(baseline_reference, dict)
            or set(baseline_reference)
            != {"baseline_version_id", "baseline_type", "digest"}
            or not isinstance(baseline_reference.get("baseline_version_id"), str)
            or not BASELINE_VERSION_ID_PATTERN.match(
                baseline_reference["baseline_version_id"]
            )
            or baseline_reference.get("baseline_type")
            not in {"single_scan", "consensus"}
            or not isinstance(baseline_reference.get("digest"), str)
            or not SHA256_DIGEST_PATTERN.match(baseline_reference["digest"])
        ):
            raise BackendError(
                "invalid_occurrence_set", "baseline_reference is invalid"
            )
        _validate_pinned_versions(
            data.get("pinned_versions"), "invalid_occurrence_set"
        )
        comparability = data.get("comparability")
        if (
            not isinstance(comparability, dict)
            or comparability.get("status")
            not in {"comparable", "partially_comparable", "not_comparable"}
            or not isinstance(comparability.get("absence_findings_allowed"), bool)
            or comparability["absence_findings_allowed"]
            != (comparability["status"] == "comparable")
        ):
            raise BackendError(
                "invalid_occurrence_set", "comparability is invalid"
            )
        _validate_lifecycle(data.get("lifecycle"), "invalid_occurrence_set")

        for field, maximum in NATIVE_OCCURRENCE_SECTION_LIMITS.items():
            items = data.get(field)
            if not isinstance(items, list) or len(items) > maximum:
                raise BackendError(
                    "invalid_occurrence_set",
                    "{0} result section is invalid".format(field),
                )
        if not isinstance(data.get("inventory_reconciliation"), dict):
            raise BackendError(
                "invalid_occurrence_set",
                "inventory_reconciliation result section is invalid",
            )
        if data.get("policy_evaluation_status") not in {
            "evaluated",
            "not_configured",
        }:
            raise BackendError(
                "invalid_occurrence_set",
                "policy_evaluation_status is invalid",
            )
        if not isinstance(data.get("quality_factors"), (list, dict)):
            raise BackendError(
                "invalid_occurrence_set", "quality_factors are invalid"
            )
        if not isinstance(data.get("policy_reference"), dict):
            raise BackendError(
                "invalid_occurrence_set", "policy_reference is invalid"
            )

        evidence_ids = set()
        for evidence in data["evidence"]:
            if not isinstance(evidence, dict):
                raise BackendError(
                    "invalid_occurrence_set", "evidence record is invalid"
                )
            evidence_id = evidence.get("evidence_id")
            if (
                not isinstance(evidence_id, str)
                or not EVIDENCE_ID_PATTERN.match(evidence_id)
                or evidence_id in evidence_ids
            ):
                raise BackendError(
                    "invalid_occurrence_set", "evidence ID is invalid or duplicated"
                )
            evidence_ids.add(evidence_id)
        for section in (
            "observed_changes",
            "policy_deviations",
            "security_findings",
        ):
            for item in data[section]:
                if not isinstance(item, dict):
                    raise BackendError(
                        "invalid_occurrence_set",
                        "{0} item is invalid".format(section),
                    )
                references = item.get("evidence_ids", [])
                if (
                    not isinstance(references, list)
                    or len(references) != len(set(references))
                    or not set(references).issubset(evidence_ids)
                ):
                    raise BackendError(
                        "invalid_occurrence_set",
                        "{0} evidence references are invalid".format(section),
                    )

        stored_digest = data.get("occurrence_digest")
        digest_input = {
            key: value
            for key, value in data.items()
            if key not in ("occurrence_set_id", "occurrence_digest")
        }
        reproduced_digest = _canonical_digest(digest_input)
        if (
            not isinstance(stored_digest, str)
            or not SHA256_DIGEST_PATTERN.match(stored_digest)
            or stored_digest != reproduced_digest
            or occurrence_id != "occurrence_{0}".format(reproduced_digest[:16])
        ):
            raise BackendError(
                "invalid_occurrence_set",
                "occurrence digest does not match the production writer algorithm",
            )
        return data

    def _validate_artifacts_match_resolved_measurement(
        self,
        measurement: Dict[str, Any],
        comparison: Dict[str, Any],
        occurrence: Optional[Dict[str, Any]],
        evidence_ids: Optional[List[str]],
    ) -> None:
        baseline_digest = (
            measurement.get("baseline_model_digest")
            if measurement.get("baseline_type") == "consensus"
            else measurement.get("baseline_snapshot_digest")
        )
        pins = comparison["pinned_versions"]
        expected_pins = {
            "baseline_version_id": measurement.get("baseline_version_id"),
            "baseline_digest": baseline_digest,
            "measurement_profile_id": measurement.get(
                "measurement_profile_id"
            ),
            "measurement_profile_version_id": measurement.get(
                "measurement_profile_version_id"
            ),
            "measurement_profile_digest": measurement.get(
                "measurement_profile_digest"
            ),
            "assurance_profile_version_id": measurement.get(
                "assurance_profile_version_id"
            ),
            "assurance_profile_digest": measurement.get(
                "assurance_profile_digest"
            ),
        }
        expected_baseline_snapshot_id = (
            "snapshot_{0}".format(baseline_digest[:16])
            if measurement.get("baseline_type") == "consensus"
            else measurement.get("baseline_snapshot_id")
        )
        if (
            comparison["current_snapshot_id"] != measurement.get("snapshot_id")
            or comparison["current_snapshot_digest"]
            != measurement.get("snapshot_digest")
            or comparison["baseline_version_id"]
            != measurement.get("baseline_version_id")
            or comparison["baseline_snapshot_id"]
            != expected_baseline_snapshot_id
            or comparison["comparability_status"]
            != measurement.get("comparability_status")
            or pins != expected_pins
        ):
            raise BackendError(
                "invalid_comparison",
                "comparison artifact does not match the resolved measurement pins",
            )
        if occurrence is not None:
            if (
                occurrence["comparison_id"] != comparison["comparison_id"]
                or occurrence["pinned_versions"] != pins
                or occurrence["comparability"]
                != comparison["comparison"]["comparability"]
            ):
                raise BackendError(
                    "invalid_occurrence_set",
                    "occurrence artifact does not match the resolved measurement",
                )
            available_evidence = {
                item["evidence_id"] for item in occurrence["evidence"]
            }
            if evidence_ids is not None and not set(evidence_ids).issubset(
                available_evidence
            ):
                raise BackendError(
                    "invalid_audit_run_measurement",
                    "measurement evidence_ids are not present in the occurrence",
                )

    def _validate_artifact_reference(
        self,
        assessment_id: str,
        artifact_type: str,
        artifact_id: str,
        expected_digest: Optional[str] = None,
        expected_comparison_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        base = self._ensure_assessment_directories(assessment_id)
        if artifact_type == "snapshot":
            if (
                not isinstance(artifact_id, str)
                or not SNAPSHOT_ID_PATTERN.match(artifact_id)
            ):
                raise BackendError("invalid_snapshot", "snapshot_id is invalid")
            file_path = base / "snapshots" / f"{artifact_id}.json"
            err_not_found = "snapshot_not_found"
            err_invalid = "invalid_snapshot"
            id_key = "snapshot_id"
        elif artifact_type == "comparison":
            if (
                not isinstance(artifact_id, str)
                or not COMPARISON_ID_PATTERN.match(artifact_id)
            ):
                raise BackendError(
                    "invalid_comparison", "comparison_id is invalid"
                )
            file_path = base / "comparisons" / f"{artifact_id}.json"
            err_not_found = "comparison_not_found"
            err_invalid = "invalid_comparison"
            id_key = "comparison_id"
        elif artifact_type == "occurrence":
            if (
                not isinstance(artifact_id, str)
                or not OCCURRENCE_SET_ID_PATTERN.match(artifact_id)
            ):
                raise BackendError(
                    "invalid_occurrence_set", "occurrence_set_id is invalid"
                )
            file_path = base / "occurrences" / f"{artifact_id}.json"
            err_not_found = "occurrence_set_not_found"
            err_invalid = "invalid_occurrence_set"
            id_key = "occurrence_set_id"
        else:
            raise BackendError("invalid_audit_run_measurement", f"unknown artifact_type {artifact_type}")

        if not file_path.exists():
            raise BackendError(err_not_found, f"{artifact_type} {artifact_id} not found")
        if file_path.is_symlink() or not file_path.is_file():
            raise BackendError(err_invalid, f"{artifact_type} path is invalid")

        data = _read_bounded_json_file(
            self,
            file_path,
            MAX_NATIVE_ARTIFACT_DOCUMENT_BYTES,
            err_not_found,
            err_invalid,
            "{0} document".format(artifact_type),
        )

        if not isinstance(data, dict) or len(data) == 0:
            raise BackendError(err_invalid, f"{artifact_type} document must be a non-empty object")

        if id_key not in data:
            raise BackendError(err_invalid, f"{artifact_type} document missing required id field {id_key}")

        if data[id_key] != artifact_id:
            raise BackendError(err_invalid, f"{artifact_type} internal id does not match {artifact_id}")

        if artifact_type == "snapshot":
            normalized = _validate_snapshot(data)
            embedded_digest = normalized["snapshot_digest"]
            if normalized["snapshot_id"] != "snapshot_{0}".format(
                embedded_digest[:16]
            ):
                raise BackendError(
                    err_invalid,
                    "snapshot_id does not match the production snapshot digest",
                )
            if expected_digest is not None and embedded_digest != expected_digest:
                raise BackendError(err_invalid, "snapshot digest mismatch")
        elif artifact_type == "comparison":
            self._validate_native_comparison_record(
                assessment_id, artifact_id, data
            )
            # comparison_digest is the canonical SHA-256 of the complete
            # native outer comparison record written by CustomerAuditStore.
            record_digest = _canonical_digest(data)
            if expected_digest is not None and record_digest != expected_digest:
                raise BackendError(err_invalid, "comparison digest mismatch")
        elif artifact_type == "occurrence":
            self._validate_native_occurrence_record(
                assessment_id,
                artifact_id,
                data,
                expected_comparison_id,
            )
            if expected_comparison_id is not None:
                comparison_record = self._validate_artifact_reference(
                    assessment_id,
                    "comparison",
                    expected_comparison_id,
                )
                if (
                    comparison_record["occurrence_set_id"] != artifact_id
                    or comparison_record["occurrence_digest"]
                    != data["occurrence_digest"]
                    or comparison_record["pinned_versions"]
                    != data["pinned_versions"]
                    or comparison_record["lifecycle"] != data["lifecycle"]
                    or comparison_record["comparison"]["comparability"]
                    != data["comparability"]
                    or comparison_record["baseline_version_id"]
                    != data["baseline_reference"]["baseline_version_id"]
                    or comparison_record["pinned_versions"]["baseline_digest"]
                    != data["baseline_reference"]["digest"]
                ):
                    raise BackendError(
                        err_invalid,
                        "occurrence and comparison records are inconsistent",
                    )
            if (
                expected_digest is not None
                and data["occurrence_digest"] != expected_digest
            ):
                raise BackendError(err_invalid, "occurrence digest mismatch")

        return data

    def _load_assurance_profile_pin_unlocked(
        self,
        assessment_id: str,
        version_id: Any,
        expected_digest: Any,
        error_code: str = "profile_version_not_found",
    ) -> Dict[str, Any]:
        if (
            not isinstance(version_id, str)
            or not ASSURANCE_VERSION_ID_PATTERN.match(version_id)
            or not isinstance(expected_digest, str)
            or not SHA256_DIGEST_PATTERN.match(expected_digest)
        ):
            raise BackendError(error_code, "assurance profile pin is invalid")
        path = self._assurance_profile_path(assessment_id, version_id)
        if path.is_symlink() or not path.is_file():
            raise BackendError(error_code, "assurance profile version is unavailable")
        record = self._read_json(
            path, error_code, "assurance profile version is unavailable"
        )
        required = {
            "schema_version",
            "assessment_id",
            "assurance_profile_version_id",
            "version",
            "label",
            "created_at",
            "digest",
            "profile",
        }
        if (
            not isinstance(record, dict)
            or set(record) != required
            or record.get("schema_version") != "1.0"
            or record.get("assessment_id") != assessment_id
            or record.get("assurance_profile_version_id") != version_id
            or not isinstance(record.get("version"), int)
            or isinstance(record.get("version"), bool)
            or record.get("version") < 1
            or not isinstance(record.get("profile"), dict)
            or record.get("digest") != _canonical_digest(record["profile"])
            or record.get("digest") != expected_digest
        ):
            raise BackendError(error_code, "assurance profile pin does not match storage")
        _validate_rfc3339(record.get("created_at"), "created_at", error_code)
        return record

    def _audit_run_ready_unlocked(
        self, assessment_id: str, audit_run: Dict[str, Any]
    ) -> bool:
        if not _compute_ready_to_start(audit_run):
            return False
        try:
            self._load_assurance_profile_pin_unlocked(
                assessment_id,
                audit_run.get("pinned_assurance_profile_version_id"),
                audit_run.get("pinned_assurance_profile_digest"),
            )
        except BackendError:
            return False
        return True

    def _load_measurement_profile_pin_unlocked(
        self,
        outcome: Dict[str, Any],
        expected_context: Dict[str, Any],
    ) -> Dict[str, Any]:
        profile_id = outcome.get("measurement_profile_id")
        version_id = outcome.get("measurement_profile_version_id")
        expected_digest = outcome.get("measurement_profile_digest")
        if (
            not isinstance(profile_id, str)
            or not MEASUREMENT_PROFILE_ID_PATTERN.match(profile_id)
            or not isinstance(version_id, str)
            or not MEASUREMENT_PROFILE_VERSION_ID_PATTERN.match(version_id)
            or not isinstance(expected_digest, str)
            or not SHA256_DIGEST_PATTERN.match(expected_digest)
        ):
            raise BackendError(
                "profile_version_not_found", "measurement profile pin is invalid"
            )
        path = self._profile_base(profile_id) / "versions" / (version_id + ".json")
        if path.is_symlink() or not path.is_file():
            raise BackendError(
                "profile_version_not_found",
                "measurement profile version is unavailable",
            )
        record = self._read_json(
            path,
            "profile_version_not_found",
            "measurement profile version is unavailable",
        )
        required = {
            "schema_version",
            "measurement_profile_id",
            "version_id",
            "revision",
            "created_at",
            "profile",
            "digest",
        }
        if (
            not isinstance(record, dict)
            or set(record) != required
            or record.get("schema_version") != "1.0"
            or record.get("measurement_profile_id") != profile_id
            or record.get("version_id") != version_id
            or not isinstance(record.get("revision"), int)
            or isinstance(record.get("revision"), bool)
            or record.get("revision") < 1
            or not isinstance(record.get("profile"), dict)
            or record.get("digest") != _canonical_digest(record["profile"])
            or record.get("digest") != expected_digest
        ):
            raise BackendError(
                "profile_version_not_found",
                "measurement profile pin does not match storage",
            )
        _validate_rfc3339(
            record.get("created_at"), "created_at", "profile_version_not_found"
        )
        profile = record["profile"]
        context_fields = (
            "location_id",
            "scan_profile_id",
            "radio_profile_id",
            "interface",
            "declared_bands",
            "declared_channels",
            "scan_time",
        )
        if any(
            profile.get(field) != expected_context.get(field)
            for field in context_fields
        ):
            raise BackendError(
                "profile_version_not_found",
                "measurement profile does not match the AuditRun measurement context",
            )
        return record

    def _validate_resolved_pins_unlocked(
        self,
        assessment_id: str,
        audit_run: Dict[str, Any],
        pending_measurement: Dict[str, Any],
        outcome: Dict[str, Any],
        current_snapshot: Dict[str, Any],
    ) -> None:
        if (
            outcome.get("assurance_profile_version_id")
            != audit_run.get("pinned_assurance_profile_version_id")
            or outcome.get("assurance_profile_digest")
            != audit_run.get("pinned_assurance_profile_digest")
        ):
            raise BackendError(
                "profile_version_not_found",
                "measurement assurance profile differs from the AuditRun pin",
            )
        self._load_assurance_profile_pin_unlocked(
            assessment_id,
            outcome.get("assurance_profile_version_id"),
            outcome.get("assurance_profile_digest"),
        )

        expected_context = pending_measurement.get("expected_measurement_context")
        _validate_expected_measurement_context(
            expected_context,
            measurement_point_id=pending_measurement.get("measurement_point_id"),
        )
        measurement_profile = self._load_measurement_profile_pin_unlocked(
            outcome, expected_context
        )

        snapshot_context = current_snapshot.get("scan_metadata", {}).get(
            "measurement_context"
        )
        if not isinstance(snapshot_context, dict):
            raise BackendError(
                "profile_version_not_found",
                "snapshot is missing its measurement context",
            )
        for field in (
            "measurement_profile_id",
            "measurement_profile_version_id",
            "measurement_profile_digest",
        ):
            if snapshot_context.get(field) != outcome.get(field):
                raise BackendError(
                    "profile_version_not_found",
                    "snapshot measurement profile pin is inconsistent",
                )
        for field in (
            "location_id",
            "scan_profile_id",
            "radio_profile_id",
            "interface",
        ):
            if snapshot_context.get(field) != expected_context.get(field):
                raise BackendError(
                    "profile_version_not_found",
                    "snapshot measurement context differs from the AuditRun pin",
                )
        snapshot_bands = snapshot_context.get(
            "declared_bands", snapshot_context.get("declared_coverage")
        )
        snapshot_channels = snapshot_context.get(
            "declared_channels",
            snapshot_context.get("declared_channels_scanned"),
        )
        if (
            snapshot_bands != expected_context.get("declared_bands")
            or snapshot_channels != expected_context.get("declared_channels")
            or current_snapshot.get("scan_metadata", {}).get("scan_time")
            != expected_context.get("scan_time")
            or snapshot_context.get("measurement_point_id")
            != measurement_profile["profile"].get("measurement_point_id")
        ):
            raise BackendError(
                "profile_version_not_found",
                "snapshot coverage context differs from the AuditRun pin",
            )

        baseline_id = outcome.get("baseline_version_id")
        if (
            not isinstance(baseline_id, str)
            or not BASELINE_VERSION_ID_PATTERN.match(baseline_id)
        ):
            raise BackendError(
                "baseline_version_not_found", "baseline version pin is invalid"
            )
        baseline_path = self._baseline_path(assessment_id, baseline_id)
        if baseline_path.is_symlink() or not baseline_path.is_file():
            raise BackendError(
                "baseline_version_not_found", "baseline version is unavailable"
            )
        stored_baseline = _read_bounded_json_file(
            self,
            baseline_path,
            MAX_NATIVE_ARTIFACT_DOCUMENT_BYTES,
            "baseline_version_not_found",
            "baseline_version_not_found",
            "baseline version",
        )
        try:
            baseline = self._read_baseline_record(assessment_id, baseline_id)
        except BackendError as error:
            raise BackendError(
                "baseline_version_not_found", "baseline version is invalid"
            ) from error
        _ensure_no_raw_recon(stored_baseline)
        if (
            not isinstance(stored_baseline, dict)
            or stored_baseline.get("assessment_id") != assessment_id
            or stored_baseline.get("baseline_version_id") != baseline_id
            or not isinstance(stored_baseline.get("version"), int)
            or isinstance(stored_baseline.get("version"), bool)
            or stored_baseline.get("version") < 1
        ):
            raise BackendError(
                "baseline_version_not_found",
                "baseline version metadata is invalid",
            )
        _validate_rfc3339(
            stored_baseline.get("created_at"),
            "created_at",
            "baseline_version_not_found",
        )
        if _canonical_digest(stored_baseline) != outcome.get(
            "baseline_record_digest"
        ):
            raise BackendError(
                "baseline_version_not_found",
                "baseline record digest does not match storage",
            )

        baseline_type = baseline.get("baseline_type", "single_scan")
        if baseline_type != outcome.get("baseline_type"):
            raise BackendError(
                "baseline_version_not_found",
                "baseline type pin is inconsistent",
            )
        if baseline_type == "single_scan":
            if (
                baseline.get("snapshot_id")
                != outcome.get("baseline_snapshot_id")
                or baseline.get("snapshot_digest")
                != outcome.get("baseline_snapshot_digest")
            ):
                raise BackendError(
                    "baseline_version_not_found",
                    "single-scan baseline pin does not match storage",
                )
            self._validate_artifact_reference(
                assessment_id,
                "snapshot",
                outcome.get("baseline_snapshot_id"),
                expected_digest=outcome.get("baseline_snapshot_digest"),
            )
            return

        model_id = outcome.get("baseline_model_id")
        model_digest = outcome.get("baseline_model_digest")
        if (
            baseline_type != "consensus"
            or baseline.get("baseline_model_id") != model_id
            or baseline.get("baseline_model_digest") != model_digest
            or not isinstance(model_id, str)
            or not BASELINE_MODEL_ID_PATTERN.match(model_id)
            or not isinstance(model_digest, str)
            or not SHA256_DIGEST_PATTERN.match(model_digest)
        ):
            raise BackendError(
                "baseline_version_not_found",
                "consensus baseline pin does not match storage",
            )
        model_path = (
            self._ensure_assessment_directories(assessment_id)
            / "baseline_models"
            / (model_id + ".json")
        )
        if model_path.is_symlink() or not model_path.is_file():
            raise BackendError(
                "baseline_version_not_found",
                "consensus baseline model is unavailable",
            )
        model = _read_bounded_json_file(
            self,
            model_path,
            MAX_NATIVE_ARTIFACT_DOCUMENT_BYTES,
            "baseline_version_not_found",
            "baseline_version_not_found",
            "consensus baseline model",
        )
        if not isinstance(model, dict):
            raise BackendError(
                "baseline_version_not_found",
                "consensus baseline model is invalid",
            )
        digest_input = {
            key: value
            for key, value in model.items()
            if key not in {"baseline_model_id", "baseline_model_digest"}
        }
        reproduced = _canonical_digest(digest_input)
        if (
            not isinstance(model, dict)
            or model.get("baseline_model_id") != model_id
            or model.get("baseline_model_digest") != model_digest
            or reproduced != model_digest
            or model_id != "bmodel_{0}".format(model_digest[:16])
        ):
            raise BackendError(
                "baseline_version_not_found",
                "consensus baseline model failed digest validation",
            )

    def _authoritative_audit_runs_unlocked(
        self, assessment_id: str
    ) -> Dict[str, Dict[str, Any]]:
        base = self._ensure_assessment_directories(assessment_id)
        runs_dir = base / "audit_runs"
        if not runs_dir.exists():
            return {}
        entries = []
        try:
            with os.scandir(str(runs_dir)) as iterator:
                for entry in iterator:
                    entries.append(entry)
                    if len(entries) > MAX_AUDIT_RUNS_PER_ASSESSMENT:
                        raise BackendError(
                            "storage_limit_exceeded",
                            "audit run document count exceeds the frozen limit",
                        )
        except BackendError:
            raise
        except OSError as error:
            raise BackendError(
                "invalid_audit_run", "audit run directory is unreadable"
            ) from error
        entries.sort(key=lambda entry: entry.name)
        runs = {}
        for entry in entries:
            if (
                not re.match(r"^ar_[0-9a-f]{16}\.json$", entry.name)
                or not entry.is_file(follow_symlinks=False)
            ):
                raise BackendError(
                    "invalid_audit_run",
                    "audit run directory contains an invalid entry",
                )
            audit_run_id = entry.name[:-5]
            path = Path(entry.path)
            run = _read_bounded_json_file(
                self,
                path,
                MAX_AUDIT_RUN_DOCUMENT_BYTES,
                "audit_run_unreadable",
                "invalid_audit_run",
                "audit run document",
            )
            runs[audit_run_id] = _validate_private_audit_run_document(
                run,
                expected_assessment_id=assessment_id,
                expected_audit_run_id=audit_run_id,
            )
        return runs

    def _reconstruct_audit_runs_manifest_unlocked(
        self, assessment_id: str
    ) -> Dict[str, Any]:
        authoritative = self._authoritative_audit_runs_unlocked(assessment_id)
        runs_map = {
            audit_run_id: run["status"]
            for audit_run_id, run in sorted(authoritative.items())
        }
        closure_reserve = sum(
            1
            for status in runs_map.values()
            if status in ACTIVE_AUDIT_RUN_STATUSES
        )
        return {
            "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
            "active_closure_reserve": closure_reserve,
            "runs": runs_map,
        }

    def _read_audit_runs_manifest_unlocked(self, assessment_id: str) -> Dict[str, Any]:
        """Read or reconstruct the audit-runs manifest in memory.

        Never writes the manifest to disk.  Persisting a repaired
        or updated manifest is the responsibility of mutating operations
        that include the manifest in their PrivateTransaction commit.
        """
        base = self._ensure_assessment_directories(assessment_id)
        manifest_file = base / "audit_runs_manifest.json"
        persisted = None
        if manifest_file.exists() or manifest_file.is_symlink():
            try:
                persisted = _validate_audit_runs_manifest(
                    _read_bounded_json_file(
                        self,
                        manifest_file,
                        MAX_AUDIT_RUN_MANIFEST_BYTES,
                        "invalid_audit_run_manifest",
                        "invalid_audit_run_manifest",
                        "audit run manifest",
                    )
                )
            except BackendError:
                persisted = None

        reconstructed = self._reconstruct_audit_runs_manifest_unlocked(
            assessment_id
        )
        if persisted is not None and persisted["runs"] == reconstructed["runs"]:
            return persisted
        return reconstructed

    def _update_audit_runs_manifest_unlocked(self, assessment_id: str, audit_run_id: str, status: str) -> Dict[str, Any]:
        manifest = self._read_audit_runs_manifest_unlocked(assessment_id)
        runs_map = dict(manifest.get("runs", {}))
        runs_map[audit_run_id] = status
        closure_reserve = sum(
            1 for st in runs_map.values() if st in ACTIVE_AUDIT_RUN_STATUSES
        )
        updated_manifest = {
            "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
            "active_closure_reserve": closure_reserve,
            "runs": runs_map,
        }
        return updated_manifest

    def _get_assessment_capacity_unlocked(self, assessment_id: str) -> Dict[str, Any]:
        base = self._ensure_assessment_directories(assessment_id)

        def _strict_count(directory: Path, pattern: re.Pattern, label: str) -> int:
            if not directory.exists():
                return 0
            count = 0
            for entry in os.scandir(str(directory)):
                if (
                    not pattern.match(entry.name)
                    or not entry.is_file(follow_symlinks=False)
                ):
                    raise BackendError(
                        "storage_error",
                        "{0} directory contains an invalid entry".format(label),
                    )
                count += 1
            return count

        snapshots = _strict_count(
            base / "snapshots",
            re.compile(r"^snapshot_[0-9a-f]{16}\.json$"),
            "snapshot",
        )
        comparisons = _strict_count(
            base / "comparisons",
            re.compile(r"^comparison_[0-9a-f]{16}\.json$"),
            "comparison",
        )

        metadata = self._read_metadata(assessment_id)
        event_used = metadata.get("last_event_sequence", 0)

        manifest = self._read_audit_runs_manifest_unlocked(assessment_id)
        closure_reserve = sum(
            1
            for status in manifest["runs"].values()
            if status in ACTIVE_AUDIT_RUN_STATUSES
        )

        snapshot_limit = MAX_SNAPSHOTS
        comparison_limit = MAX_COMPARISONS
        event_limit = MAX_EVENTS

        return {
            "snapshot_limit": snapshot_limit,
            "snapshot_used": snapshots,
            "snapshot_available": max(0, snapshot_limit - snapshots),
            "comparison_limit": comparison_limit,
            "comparison_used": comparisons,
            "comparison_available": max(0, comparison_limit - comparisons),
            "event_limit": event_limit,
            "event_used": event_used,
            "event_available": max(0, event_limit - event_used),
            "event_reserved_for_run_closure": closure_reserve,
            "event_available_for_non_terminal": max(0, event_limit - event_used - closure_reserve),
        }

    def get_assessment_capacity(self, assessment_id: str) -> Dict[str, Any]:
        with self._lock(assessment_id):
            return self._get_assessment_capacity_unlocked(assessment_id)

    def _check_non_terminal_event_capacity(
        self, assessment_id: str, extra_closure_reserve: int = 0
    ) -> int:
        capacity = self._get_assessment_capacity_unlocked(assessment_id)
        closure_reserve = capacity["event_reserved_for_run_closure"] + extra_closure_reserve
        event_used = capacity["event_used"]
        last_seq = event_used
        if last_seq + 1 + closure_reserve > MAX_EVENTS:
            raise BackendError("event_limit", "event capacity limit exceeded")
        return last_seq

    # -------------------------------------------------------------------------
    # MeasurementPoint Operations
    # -------------------------------------------------------------------------

    def _read_measurement_points_doc(self, assessment_id: str) -> Dict[str, Any]:
        base = self._ensure_assessment_directories(assessment_id)
        path = base / "measurement_points.json"
        if not path.exists() and not path.is_symlink():
            return {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "assessment_id": assessment_id,
                "updated_at": _utc_now(),
                "measurement_points": [],
            }
        doc = _read_bounded_json_file(
            self,
            path,
            MAX_MEASUREMENT_POINTS_DOCUMENT_BYTES,
            "invalid_measurement_point",
            "invalid_measurement_point",
            "measurement points document",
        )
        return _validate_measurement_points_document(doc, assessment_id)

    def _list_measurement_points_unlocked(
        self, assessment_id: str, include_archived: bool = False
    ) -> List[Dict[str, Any]]:
        doc = self._read_measurement_points_doc(assessment_id)
        points = doc.get("measurement_points", [])
        if not include_archived:
            return [p for p in points if p.get("status") == "active"]
        return list(points)

    def list_measurement_points(
        self, assessment_id: str, include_archived: bool = False, limit: int = 50, offset: int = 0
    ) -> Dict[str, Any]:
        if (
            not isinstance(include_archived, bool)
            or not isinstance(limit, int)
            or isinstance(limit, bool)
            or not isinstance(offset, int)
            or isinstance(offset, bool)
            or limit < 1
            or limit > 100
            or offset < 0
        ):
            raise BackendError("invalid_page_token", "invalid pagination parameters")
        with self._lock(assessment_id):
            all_pts = self._list_measurement_points_unlocked(assessment_id, include_archived=include_archived)
            sorted_pts = sorted(all_pts, key=lambda p: (p.get("created_at", ""), p.get("measurement_point_id", "")))
            sorted_pts.sort(key=lambda p: p.get("created_at", ""), reverse=True)
            total = len(sorted_pts)
            paginated = sorted_pts[offset:offset + limit]
            return {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "measurement_points": paginated,
                "total": total,
                "limit": limit,
                "offset": offset,
                "has_more": offset + len(paginated) < total,
            }

    def _get_measurement_point_unlocked(
        self, assessment_id: str, measurement_point_id: str
    ) -> Dict[str, Any]:
        if not MEASUREMENT_POINT_ID_PATTERN.match(measurement_point_id):
            raise BackendError("invalid_measurement_point", "invalid measurement_point_id format")
        doc = self._read_measurement_points_doc(assessment_id)
        for p in doc.get("measurement_points", []):
            if p.get("measurement_point_id") == measurement_point_id:
                return _json_clone(p, "invalid_measurement_point", "measurement_point")
        raise BackendError("measurement_point_not_found", "measurement point not found")

    def get_measurement_point(
        self, assessment_id: str, measurement_point_id: str
    ) -> Dict[str, Any]:
        with self._lock(assessment_id):
            mp = self._get_measurement_point_unlocked(assessment_id, measurement_point_id)
            return {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "measurement_point": mp,
            }

    def create_measurement_point(
        self,
        assessment_id: str,
        expected_assessment_revision: int,
        context: Dict[str, Any],
        name: str,
        description: Optional[str] = None,
    ) -> Dict[str, Any]:
        _validate_revision(expected_assessment_revision)
        clean_name = _clean_text(name, "name", 128, required=True)
        clean_desc = _clean_text(description, "description", 512, required=False) if description is not None else None

        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_assessment_revision)
            self._check_non_terminal_event_capacity(assessment_id)

            doc = self._read_measurement_points_doc(assessment_id)
            existing_points = doc.get("measurement_points", [])

            active_count = sum(1 for p in existing_points if p.get("status") == "active")
            total_count = len(existing_points)

            if active_count >= MAX_ACTIVE_MEASUREMENT_POINTS:
                raise BackendError("storage_limit_exceeded", "active measurement point limit reached")
            if total_count >= MAX_TOTAL_MEASUREMENT_POINT_RECORDS:
                raise BackendError("storage_limit_exceeded", "total measurement point limit reached")

            mp_id = _generate_mp_id()
            validated_context = _validate_expected_measurement_context(context, measurement_point_id=mp_id)

            new_point = {
                "measurement_point_id": mp_id,
                "assessment_id": assessment_id,
                "name": clean_name,
                "description": clean_desc if clean_desc else None,
                "status": "active",
                "created_at": _utc_now(),
                "archived_at": None,
                "revision": 1,
                "expected_measurement_context": validated_context,
            }

            updated_points = list(existing_points)
            updated_points.append(new_point)

            new_doc = {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "assessment_id": assessment_id,
                "updated_at": _utc_now(),
                "measurement_points": updated_points,
            }

            _validate_measurement_points_document(new_doc, assessment_id)
            _canonical_digest(new_doc)
            doc_bytes = json.dumps(new_doc, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
            if len(doc_bytes) > MAX_MEASUREMENT_POINTS_DOCUMENT_BYTES:
                raise BackendError("storage_limit_exceeded", "measurement points document size exceeded limit")

            event_obj, events_bytes = self._transaction_event(
                assessment_id,
                metadata,
                "measurement_point_created",
                {"measurement_point_id": mp_id},
            )

            base = self._ensure_assessment_directories(assessment_id)
            txn = PrivateTransaction(base, fault_injector=self.fault_injector)
            txn.add_bytes("measurement_points.json", doc_bytes)
            txn.add_json("assessment.json", metadata)
            txn.add_bytes("events.jsonl", events_bytes)
            txn.commit()

            return {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "measurement_point": new_point,
            }

    def update_measurement_point(
        self,
        assessment_id: str,
        expected_assessment_revision: int,
        measurement_point_id: str,
        expected_measurement_point_revision: int,
        updates: Dict[str, Any],
    ) -> Dict[str, Any]:
        _validate_revision(expected_assessment_revision)
        _validate_revision(expected_measurement_point_revision)
        if not isinstance(updates, dict) or not updates:
            raise BackendError("invalid_measurement_point", "updates must be a non-empty object")

        allowed_keys = {"name", "description", "expected_measurement_context"}
        if set(updates) - allowed_keys:
            raise BackendError("invalid_measurement_point", "updates contains unsupported fields")

        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_assessment_revision)
            self._check_non_terminal_event_capacity(assessment_id)

            doc = self._read_measurement_points_doc(assessment_id)
            points = doc.get("measurement_points", [])

            target_idx = -1
            target_mp = None
            for idx, p in enumerate(points):
                if p.get("measurement_point_id") == measurement_point_id:
                    target_idx = idx
                    target_mp = p
                    break

            if target_mp is None:
                raise BackendError("measurement_point_not_found", "measurement point not found")
            if target_mp.get("status") == "archived":
                raise BackendError("measurement_point_archived", "archived measurement point cannot be updated")
            if target_mp.get("revision") != expected_measurement_point_revision:
                raise BackendError("revision_conflict", "measurement point revision has changed")

            updated_mp = _json_clone(target_mp, "invalid_measurement_point", "measurement_point")
            if "name" in updates:
                updated_mp["name"] = _clean_text(updates["name"], "name", 128, required=True)
            if "description" in updates:
                updated_mp["description"] = (
                    _clean_text(updates["description"], "description", 512, required=False)
                    if updates["description"] is not None
                    else None
                )
            if "expected_measurement_context" in updates:
                updated_mp["expected_measurement_context"] = _validate_expected_measurement_context(
                    updates["expected_measurement_context"], measurement_point_id=measurement_point_id
                )

            updated_mp["revision"] += 1

            updated_points = list(points)
            updated_points[target_idx] = updated_mp

            new_doc = {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "assessment_id": assessment_id,
                "updated_at": _utc_now(),
                "measurement_points": updated_points,
            }

            _validate_measurement_points_document(new_doc, assessment_id)
            doc_bytes = json.dumps(new_doc, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
            if len(doc_bytes) > MAX_MEASUREMENT_POINTS_DOCUMENT_BYTES:
                raise BackendError("storage_limit_exceeded", "measurement points document size exceeded limit")

            event_obj, events_bytes = self._transaction_event(
                assessment_id,
                metadata,
                "measurement_point_updated",
                {"measurement_point_id": measurement_point_id},
            )

            base = self._ensure_assessment_directories(assessment_id)
            txn = PrivateTransaction(base, fault_injector=self.fault_injector)
            txn.add_bytes("measurement_points.json", doc_bytes)
            txn.add_json("assessment.json", metadata)
            txn.add_bytes("events.jsonl", events_bytes)
            txn.commit()

            return {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "measurement_point": updated_mp,
            }

    def archive_measurement_point(
        self,
        assessment_id: str,
        expected_assessment_revision: int,
        measurement_point_id: str,
        expected_measurement_point_revision: int,
    ) -> Dict[str, Any]:
        _validate_revision(expected_assessment_revision)
        _validate_revision(expected_measurement_point_revision)

        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_assessment_revision)
            self._check_non_terminal_event_capacity(assessment_id)

            doc = self._read_measurement_points_doc(assessment_id)
            points = doc.get("measurement_points", [])

            target_idx = -1
            target_mp = None
            for idx, p in enumerate(points):
                if p.get("measurement_point_id") == measurement_point_id:
                    target_idx = idx
                    target_mp = p
                    break

            if target_mp is None:
                raise BackendError("measurement_point_not_found", "measurement point not found")
            if target_mp.get("status") == "archived":
                raise BackendError("measurement_point_archived", "measurement point is already archived")
            if target_mp.get("revision") != expected_measurement_point_revision:
                raise BackendError("revision_conflict", "measurement point revision has changed")

            updated_mp = _json_clone(target_mp, "invalid_measurement_point", "measurement_point")
            updated_mp["status"] = "archived"
            updated_mp["archived_at"] = _utc_now()
            updated_mp["revision"] += 1

            updated_points = list(points)
            updated_points[target_idx] = updated_mp

            new_doc = {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "assessment_id": assessment_id,
                "updated_at": _utc_now(),
                "measurement_points": updated_points,
            }

            _validate_measurement_points_document(new_doc, assessment_id)
            doc_bytes = json.dumps(new_doc, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
            if len(doc_bytes) > MAX_MEASUREMENT_POINTS_DOCUMENT_BYTES:
                raise BackendError("storage_limit_exceeded", "measurement points document size exceeded limit")

            event_obj, events_bytes = self._transaction_event(
                assessment_id,
                metadata,
                "measurement_point_archived",
                {"measurement_point_id": measurement_point_id},
            )

            base = self._ensure_assessment_directories(assessment_id)
            txn = PrivateTransaction(base, fault_injector=self.fault_injector)
            txn.add_bytes("measurement_points.json", doc_bytes)
            txn.add_json("assessment.json", metadata)
            txn.add_bytes("events.jsonl", events_bytes)
            txn.commit()

            return {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "measurement_point": updated_mp,
            }

    # -------------------------------------------------------------------------
    # AuditRun Operations
    # -------------------------------------------------------------------------

    def _list_audit_runs_unlocked(self, assessment_id: str) -> List[Dict[str, Any]]:
        return list(
            self._authoritative_audit_runs_unlocked(assessment_id).values()
        )

    def list_audit_runs(self, assessment_id: str, limit: int = 50, offset: int = 0) -> Dict[str, Any]:
        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or not isinstance(offset, int)
            or isinstance(offset, bool)
            or limit < 1
            or limit > 100
            or offset < 0
        ):
            raise BackendError("invalid_page_token", "invalid pagination parameters")
        with self._lock(assessment_id):
            all_runs = self._list_audit_runs_unlocked(assessment_id)
            sorted_runs = sorted(all_runs, key=lambda r: (r.get("created_at", ""), r.get("audit_run_id", "")))
            sorted_runs.sort(key=lambda r: r.get("created_at", ""), reverse=True)
            total = len(sorted_runs)
            paginated = sorted_runs[offset:offset + limit]
            items = [
                {
                    "audit_run": _sanitize_audit_run(run),
                    "ready_to_start": self._audit_run_ready_unlocked(
                        assessment_id, run
                    ),
                }
                for run in paginated
            ]
            return {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "audit_runs": items,
                "total": total,
                "limit": limit,
                "offset": offset,
                "has_more": offset + len(items) < total,
                "assessment_capacity": self._get_assessment_capacity_unlocked(assessment_id),
            }

    def _get_audit_run_unlocked(self, assessment_id: str, audit_run_id: str) -> Dict[str, Any]:
        if not AUDIT_RUN_ID_PATTERN.match(audit_run_id):
            raise BackendError("invalid_audit_run", "invalid audit_run_id format")
        base = self._ensure_assessment_directories(assessment_id)
        path = base / "audit_runs" / "{0}.json".format(audit_run_id)
        if not path.exists():
            raise BackendError("audit_run_not_found", "audit run not found")
        if path.is_symlink() or not path.is_file():
            raise BackendError("invalid_audit_run", "audit run path is invalid")
        run = _read_bounded_json_file(
            self,
            path,
            MAX_AUDIT_RUN_DOCUMENT_BYTES,
            "audit_run_unreadable",
            "invalid_audit_run",
            "audit run document",
        )
        return _validate_private_audit_run_document(
            run,
            expected_assessment_id=assessment_id,
            expected_audit_run_id=audit_run_id,
        )

    def get_audit_run(self, assessment_id: str, audit_run_id: str) -> Dict[str, Any]:
        with self._lock(assessment_id):
            run_doc = self._get_audit_run_unlocked(assessment_id, audit_run_id)
            sanitized_measurements = [_sanitize_measurement(m) for m in run_doc.get("measurements", [])]
            return {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "audit_run": _sanitize_audit_run(run_doc),
                "ready_to_start": self._audit_run_ready_unlocked(
                    assessment_id, run_doc
                ),
                "measurements": sanitized_measurements,
                "assessment_capacity": self._get_assessment_capacity_unlocked(assessment_id),
            }

    def create_audit_run(
        self,
        assessment_id: str,
        expected_assessment_revision: int,
        title: str,
        pinned_assurance_profile_version_id: str,
        measurement_point_ids: List[str],
        due_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        _validate_revision(expected_assessment_revision)
        clean_title = _clean_text(title, "title", 128, required=True)
        if due_at is not None:
            _validate_iso_datetime(due_at, "due_at", error_code="invalid_audit_run")
        if not pinned_assurance_profile_version_id or not isinstance(pinned_assurance_profile_version_id, str):
            raise BackendError("profile_version_not_found", "pinned_assurance_profile_version_id is required")
        if not ASSURANCE_VERSION_ID_PATTERN.match(pinned_assurance_profile_version_id):
            raise BackendError("profile_version_not_found", "pinned_assurance_profile_version_id format is invalid")
        if not isinstance(measurement_point_ids, list) or len(measurement_point_ids) < 1 or len(measurement_point_ids) > MAX_MEASUREMENT_POINTS_PER_RUN:
            raise BackendError("invalid_audit_run", "measurement_point_ids must contain between 1 and 64 items")
        for mpid in measurement_point_ids:
            if not isinstance(mpid, str) or not MEASUREMENT_POINT_ID_PATTERN.match(mpid):
                raise BackendError("invalid_audit_run", "measurement_point_id format is invalid: {0}".format(mpid))

        if len(set(measurement_point_ids)) != len(measurement_point_ids):
            raise BackendError("invalid_audit_run", "measurement_point_ids must contain unique items")

        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_assessment_revision)
            self._check_non_terminal_event_capacity(assessment_id, extra_closure_reserve=1)

            existing_runs = self._list_audit_runs_unlocked(assessment_id)
            if len(existing_runs) >= MAX_AUDIT_RUNS_PER_ASSESSMENT:
                raise BackendError("storage_limit_exceeded", "max audit runs per assessment reached")

            active_mps = {mp["measurement_point_id"]: mp for mp in self._list_measurement_points_unlocked(assessment_id, include_archived=False)}
            all_mps = {mp["measurement_point_id"]: mp for mp in self._list_measurement_points_unlocked(assessment_id, include_archived=True)}

            for mpid in measurement_point_ids:
                if mpid not in all_mps:
                    raise BackendError("measurement_point_not_found", "measurement point {0} not found".format(mpid))
                if mpid not in active_mps:
                    raise BackendError("archived_measurement_point_not_allowed", "measurement point {0} is archived".format(mpid))

            assurance_path = self._assurance_profile_path(
                assessment_id, pinned_assurance_profile_version_id
            )
            if assurance_path.is_symlink() or not assurance_path.is_file():
                raise BackendError(
                    "profile_version_not_found",
                    "assurance profile version is unavailable",
                )
            assurance_prof = self._read_json(
                assurance_path,
                "profile_version_not_found",
                "assurance profile version is unavailable",
            )
            assurance_digest = (
                assurance_prof.get("digest")
                if isinstance(assurance_prof, dict)
                else None
            )
            if not assurance_digest:
                raise BackendError("profile_version_not_found", "assurance profile digest missing")
            self._load_assurance_profile_pin_unlocked(
                assessment_id,
                pinned_assurance_profile_version_id,
                assurance_digest,
            )

            ar_id = _generate_ar_id()
            now = _utc_now()

            measurements = []
            for mpid in measurement_point_ids:
                mp_obj = active_mps[mpid]
                arm_id = _generate_arm_id()
                measurements.append({
                    "measurement_id": arm_id,
                    "audit_run_id": ar_id,
                    "measurement_point_id": mpid,
                    "status": "pending",
                    "created_at": now,
                    "expected_measurement_context": _json_clone(mp_obj["expected_measurement_context"], "invalid_measurement_point", "context"),
                })

            audit_run = {
                "audit_run_id": ar_id,
                "assessment_id": assessment_id,
                "title": clean_title,
                "status": "draft",
                "created_at": now,
                "started_at": None,
                "completed_at": None,
                "due_at": due_at,
                "pinned_assurance_profile_version_id": pinned_assurance_profile_version_id,
                "pinned_assurance_profile_digest": assurance_digest,
                "measurement_point_ids": list(measurement_point_ids),
                "measurements": measurements,
                "revision": 1,
            }

            run_bytes = self._validate_audit_run_size(audit_run)

            event_obj, events_bytes = self._transaction_event(
                assessment_id,
                metadata,
                "audit_run_created",
                {"audit_run_id": ar_id},
            )

            manifest = self._update_audit_runs_manifest_unlocked(assessment_id, ar_id, "draft")

            base = self._ensure_assessment_directories(assessment_id)
            runs_dir = base / "audit_runs"
            self._ensure_private_directory(runs_dir)

            txn = PrivateTransaction(base, fault_injector=self.fault_injector)
            txn.add_bytes(f"audit_runs/{ar_id}.json", run_bytes)
            txn.add_json("audit_runs_manifest.json", manifest)
            txn.add_json("assessment.json", metadata)
            txn.add_bytes("events.jsonl", events_bytes)
            txn.commit()

            return {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "audit_run": _sanitize_audit_run(audit_run),
                "ready_to_start": self._audit_run_ready_unlocked(
                    assessment_id, audit_run
                ),
                "assessment_capacity": self._get_assessment_capacity_unlocked(assessment_id),
            }

    def start_audit_run(
        self,
        assessment_id: str,
        expected_assessment_revision: int,
        audit_run_id: str,
        expected_audit_run_revision: int,
    ) -> Dict[str, Any]:
        _validate_revision(expected_assessment_revision)
        _validate_revision(expected_audit_run_revision)
        if not AUDIT_RUN_ID_PATTERN.match(audit_run_id):
            raise BackendError("invalid_audit_run", "audit_run_id format is invalid")

        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_assessment_revision)
            self._check_non_terminal_event_capacity(assessment_id)

            audit_run = self._get_audit_run_unlocked(assessment_id, audit_run_id)
            if audit_run.get("status") in ("completed", "cancelled"):
                raise BackendError("audit_run_sealed", "cannot start sealed audit run")
            if audit_run.get("status") != "draft":
                raise BackendError("invalid_audit_run_transition", "audit run is already started")
            if audit_run.get("revision") != expected_audit_run_revision:
                raise BackendError("revision_conflict", "audit run revision has changed")
            if not self._audit_run_ready_unlocked(assessment_id, audit_run):
                raise BackendError(
                    "audit_run_not_ready",
                    "audit run assurance profile pin is no longer valid",
                )

            updated_run = _json_clone(audit_run, "invalid_audit_run", "audit_run")
            updated_run["status"] = "in_progress"
            updated_run["started_at"] = _timestamp_not_before(
                audit_run.get("created_at")
            )
            updated_run["revision"] += 1

            run_bytes = self._validate_audit_run_size(updated_run)

            event_obj, events_bytes = self._transaction_event(
                assessment_id,
                metadata,
                "audit_run_started",
                {"audit_run_id": audit_run_id},
            )

            manifest = self._update_audit_runs_manifest_unlocked(assessment_id, audit_run_id, "in_progress")

            base = self._ensure_assessment_directories(assessment_id)
            txn = PrivateTransaction(base, fault_injector=self.fault_injector)
            txn.add_bytes(f"audit_runs/{audit_run_id}.json", run_bytes)
            txn.add_json("audit_runs_manifest.json", manifest)
            txn.add_json("assessment.json", metadata)
            txn.add_bytes("events.jsonl", events_bytes)
            txn.commit()

            return {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "audit_run": _sanitize_audit_run(updated_run),
            }

    def cancel_audit_run(
        self,
        assessment_id: str,
        expected_assessment_revision: int,
        audit_run_id: str,
        expected_audit_run_revision: int,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        _validate_revision(expected_assessment_revision)
        _validate_revision(expected_audit_run_revision)
        if not AUDIT_RUN_ID_PATTERN.match(audit_run_id):
            raise BackendError("invalid_audit_run", "audit_run_id format is invalid")
        clean_reason = (
            _clean_text(reason, "reason", 512, required=False)
            if reason is not None
            else None
        )

        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_assessment_revision)

            audit_run = self._get_audit_run_unlocked(assessment_id, audit_run_id)
            if audit_run.get("status") in ("completed", "cancelled"):
                raise BackendError("audit_run_sealed", "audit run is already sealed")
            if audit_run.get("revision") != expected_audit_run_revision:
                raise BackendError("revision_conflict", "audit run revision has changed")

            updated_run = _json_clone(audit_run, "invalid_audit_run", "audit_run")
            updated_run["status"] = "cancelled"
            updated_run["completed_at"] = _timestamp_not_before(
                *_audit_run_terminal_times(audit_run)
            )
            updated_run["revision"] += 1

            run_bytes = self._validate_audit_run_size(updated_run)

            event_data = {"audit_run_id": audit_run_id}
            if clean_reason:
                event_data["reason"] = clean_reason
            event_obj, events_bytes = self._transaction_event(
                assessment_id,
                metadata,
                "audit_run_cancelled",
                event_data,
            )

            manifest = self._update_audit_runs_manifest_unlocked(assessment_id, audit_run_id, "cancelled")

            base = self._ensure_assessment_directories(assessment_id)
            txn = PrivateTransaction(base, fault_injector=self.fault_injector)
            txn.add_bytes(f"audit_runs/{audit_run_id}.json", run_bytes)
            txn.add_json("audit_runs_manifest.json", manifest)
            txn.add_json("assessment.json", metadata)
            txn.add_bytes("events.jsonl", events_bytes)
            txn.commit()

            return {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "audit_run": _sanitize_audit_run(updated_run),
            }

    def complete_audit_run(
        self,
        assessment_id: str,
        expected_assessment_revision: int,
        audit_run_id: str,
        expected_audit_run_revision: int,
    ) -> Dict[str, Any]:
        _validate_revision(expected_assessment_revision)
        _validate_revision(expected_audit_run_revision)
        if not AUDIT_RUN_ID_PATTERN.match(audit_run_id):
            raise BackendError("invalid_audit_run", "audit_run_id format is invalid")

        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_assessment_revision)

            audit_run = self._get_audit_run_unlocked(assessment_id, audit_run_id)
            if audit_run.get("status") in ("completed", "cancelled"):
                raise BackendError("audit_run_sealed", "audit run is already sealed")
            if audit_run.get("status") != "in_progress":
                raise BackendError("invalid_audit_run_transition", "audit run must be in_progress to complete")
            if audit_run.get("revision") != expected_audit_run_revision:
                raise BackendError("revision_conflict", "audit run revision has changed")

            measurements = audit_run.get("measurements", [])
            incomplete = [m for m in measurements if m.get("status") != "completed"]
            if incomplete:
                raise BackendError("invalid_audit_run_transition", "all measurements must be completed before completing audit run")

            updated_run = _json_clone(audit_run, "invalid_audit_run", "audit_run")
            updated_run["status"] = "completed"
            updated_run["completed_at"] = _timestamp_not_before(
                *_audit_run_terminal_times(audit_run)
            )
            updated_run["revision"] += 1

            run_bytes = self._validate_audit_run_size(updated_run)

            event_obj, events_bytes = self._transaction_event(
                assessment_id,
                metadata,
                "audit_run_completed",
                {"audit_run_id": audit_run_id},
            )

            manifest = self._update_audit_runs_manifest_unlocked(assessment_id, audit_run_id, "completed")

            base = self._ensure_assessment_directories(assessment_id)
            txn = PrivateTransaction(base, fault_injector=self.fault_injector)
            txn.add_bytes(f"audit_runs/{audit_run_id}.json", run_bytes)
            txn.add_json("audit_runs_manifest.json", manifest)
            txn.add_json("assessment.json", metadata)
            txn.add_bytes("events.jsonl", events_bytes)
            txn.commit()

            return {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "audit_run": _sanitize_audit_run(updated_run),
            }

    # -------------------------------------------------------------------------
    # AuditRunMeasurement Operations
    # -------------------------------------------------------------------------

    def resolve_audit_measurement(
        self,
        assessment_id: str,
        expected_assessment_revision: int,
        audit_run_id: str,
        expected_audit_run_revision: int,
        measurement_point_id: str,
        outcome: Dict[str, Any],
    ) -> Dict[str, Any]:
        _validate_revision(expected_assessment_revision)
        _validate_revision(expected_audit_run_revision)
        _ensure_no_raw_recon(outcome)

        status = outcome.get("status")
        failed_stage = outcome.get("failed_stage")

        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_assessment_revision)
            self._check_non_terminal_event_capacity(assessment_id)

            audit_run = self._get_audit_run_unlocked(assessment_id, audit_run_id)
            if audit_run.get("status") in ("completed", "cancelled"):
                raise BackendError("audit_run_sealed", "cannot resolve measurement in sealed audit run")
            if audit_run.get("status") != "in_progress":
                raise BackendError("invalid_audit_run_transition", "audit run must be in_progress to resolve measurements")
            if audit_run.get("revision") != expected_audit_run_revision:
                raise BackendError("revision_conflict", "audit run revision has changed")

            measurements = audit_run.get("measurements", [])
            target_idx = -1
            target_m = None
            for idx, m in enumerate(measurements):
                if m.get("measurement_point_id") == measurement_point_id:
                    target_idx = idx
                    target_m = m
                    break

            if target_m is None:
                raise BackendError(
                    "audit_measurement_not_found",
                    "measurement point is not part of the audit run",
                )
            if target_m.get("status") != "pending":
                raise BackendError(
                    "invalid_audit_measurement_transition",
                    "cannot resolve measurement in status {0}".format(
                        target_m.get("status")
                    ),
                )

            updated_m = _json_clone(
                target_m, "invalid_audit_run_measurement", "measurement"
            )
            updated_m.pop("created_at", None)
            immutable_context = updated_m.pop("expected_measurement_context", None)
            updated_m.update(
                _json_clone(
                    outcome, "invalid_audit_run_measurement", "outcome"
                )
            )
            mid = target_m.get("measurement_id") or target_m.get(
                "audit_measurement_id"
            )
            updated_m["measurement_id"] = mid
            updated_m["audit_run_id"] = audit_run_id
            updated_m["measurement_point_id"] = measurement_point_id
            # Validate the action payload before consulting referenced storage,
            # so malformed RFC 3339 or branch fields get the action-specific
            # error instead of being masked by a missing pin.
            _validate_audit_run_measurement(updated_m)

            current_snapshot = None
            if status == "resolved":
                snap_id = outcome.get("snapshot_id")
                snap_digest = outcome.get("snapshot_digest")
                if not snap_id:
                    raise BackendError(
                        "invalid_audit_run_measurement", "snapshot_id is required"
                    )
                current_snapshot = self._validate_artifact_reference(
                    assessment_id,
                    "snapshot",
                    snap_id,
                    expected_digest=snap_digest,
                )
                self._validate_resolved_pins_unlocked(
                    assessment_id,
                    audit_run,
                    target_m,
                    outcome,
                    current_snapshot,
                )
            elif not (status == "failed" and failed_stage == "resolution"):
                raise BackendError(
                    "invalid_audit_run_measurement",
                    "resolve outcome must be resolved or failed resolution",
                )

            if status == "failed":
                updated_m["expected_measurement_context"] = immutable_context
                _validate_persisted_measurement(updated_m)

            updated_measurements = list(measurements)
            updated_measurements[target_idx] = updated_m

            updated_run = _json_clone(audit_run, "invalid_audit_run", "audit_run")
            updated_run["measurements"] = updated_measurements
            updated_run["revision"] += 1

            run_bytes = self._validate_audit_run_size(updated_run)

            sanitized_m = _sanitize_measurement(updated_m)

            event_type = (
                "audit_measurement_resolved"
                if status == "resolved"
                else "audit_measurement_failed"
            )
            event_data = (
                {"snapshot_id": updated_m["snapshot_id"]}
                if status == "resolved"
                else {
                    "measurement_point_id": measurement_point_id,
                    "failed_stage": "resolution",
                    "error_code": updated_m["error_code"],
                }
            )
            event_obj, events_bytes = self._transaction_event(
                assessment_id,
                metadata,
                event_type,
                event_data,
            )

            base = self._ensure_assessment_directories(assessment_id)
            txn = PrivateTransaction(base, fault_injector=self.fault_injector)
            txn.add_bytes(f"audit_runs/{audit_run_id}.json", run_bytes)
            txn.add_json("assessment.json", metadata)
            txn.add_bytes("events.jsonl", events_bytes)
            txn.commit()

            return {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "assessment_revision": metadata["revision"],
                "assessment_capacity": self._get_assessment_capacity_unlocked(assessment_id),
                "audit_run": _sanitize_audit_run(updated_run),
                "measurement": sanitized_m,
            }

    def retry_audit_measurement(
        self,
        assessment_id: str,
        expected_assessment_revision: int,
        audit_run_id: str,
        expected_audit_run_revision: int,
        measurement_point_id: str,
    ) -> Dict[str, Any]:
        _validate_revision(expected_assessment_revision)
        _validate_revision(expected_audit_run_revision)

        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_assessment_revision)
            self._check_non_terminal_event_capacity(assessment_id)

            audit_run = self._get_audit_run_unlocked(assessment_id, audit_run_id)
            if audit_run.get("status") in ("completed", "cancelled"):
                raise BackendError("audit_run_sealed", "cannot retry measurement in sealed audit run")
            if audit_run.get("status") != "in_progress":
                raise BackendError("invalid_audit_run_transition", "audit run must be in_progress to retry measurements")
            if audit_run.get("revision") != expected_audit_run_revision:
                raise BackendError("revision_conflict", "audit run revision has changed")

            measurements = audit_run.get("measurements", [])
            target_idx = -1
            target_m = None
            for idx, m in enumerate(measurements):
                if m.get("measurement_point_id") == measurement_point_id:
                    target_idx = idx
                    target_m = m
                    break

            if target_m is None:
                raise BackendError(
                    "audit_measurement_not_found",
                    "measurement point is not part of the audit run",
                )
            if target_m.get("status") != "failed":
                raise BackendError(
                    "invalid_audit_measurement_transition",
                    "cannot retry measurement that is not in failed status",
                )

            failed_stage = target_m.get("failed_stage")

            if failed_stage == "resolution":
                updated_m = {
                    "measurement_id": target_m.get("measurement_id") or target_m.get("audit_measurement_id"),
                    "audit_run_id": audit_run_id,
                    "measurement_point_id": measurement_point_id,
                    "status": "pending",
                    "created_at": _utc_now(),
                    "expected_measurement_context": _json_clone(
                        target_m["expected_measurement_context"],
                        "invalid_audit_run_measurement",
                        "context",
                    ),
                }
            elif failed_stage == "comparison":
                updated_m = _json_clone(target_m, "invalid_audit_run_measurement", "measurement")
                for k in ("error_code", "error_message", "failed_stage", "retry_target", "failed_at", "comparison_id", "comparison_digest", "occurrence_set_id", "evidence_ids", "completed_at"):
                    updated_m.pop(k, None)
                updated_m["status"] = "resolved"
                updated_m["measurement_id"] = target_m.get("measurement_id") or target_m.get("audit_measurement_id")
                updated_m["audit_run_id"] = audit_run_id
                updated_m["measurement_point_id"] = measurement_point_id
            else:
                raise BackendError(
                    "invalid_audit_measurement_transition",
                    "unknown failed_stage for measurement",
                )

            _validate_persisted_measurement(updated_m)

            updated_measurements = list(measurements)
            updated_measurements[target_idx] = updated_m

            updated_run = _json_clone(audit_run, "invalid_audit_run", "audit_run")
            updated_run["measurements"] = updated_measurements
            updated_run["revision"] += 1

            run_bytes = self._validate_audit_run_size(updated_run)

            public_m = _to_public_measurement(updated_m)

            event_obj, events_bytes = self._transaction_event(
                assessment_id,
                metadata,
                "audit_measurement_retried",
                {"measurement_point_id": measurement_point_id},
            )

            base = self._ensure_assessment_directories(assessment_id)
            txn = PrivateTransaction(base, fault_injector=self.fault_injector)
            txn.add_bytes(f"audit_runs/{audit_run_id}.json", run_bytes)
            txn.add_json("assessment.json", metadata)
            txn.add_bytes("events.jsonl", events_bytes)
            txn.commit()

            return {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "assessment_revision": metadata["revision"],
                "assessment_capacity": self._get_assessment_capacity_unlocked(assessment_id),
                "audit_run": _sanitize_audit_run(updated_run),
                "measurement": public_m,
            }

    def save_audit_measurement_comparison(
        self,
        assessment_id: str,
        expected_assessment_revision: int,
        audit_run_id: str,
        expected_audit_run_revision: int,
        measurement_point_id: str,
        outcome: Dict[str, Any],
    ) -> Dict[str, Any]:
        _validate_revision(expected_assessment_revision)
        _validate_revision(expected_audit_run_revision)
        _ensure_no_raw_recon(outcome)

        status = outcome.get("status")
        failed_stage = outcome.get("failed_stage")
        if status != "completed" and not (
            status == "failed" and failed_stage == "comparison"
        ):
            raise BackendError("invalid_audit_run_measurement", "save_comparison outcome must be completed or failed comparison")

        evidence_ids = outcome.get("evidence_ids")
        if evidence_ids is not None:
            if not isinstance(evidence_ids, list) or len(evidence_ids) > MAX_EVIDENCE_IDS_PER_AUDIT_MEASUREMENT:
                raise BackendError("invalid_audit_run_measurement", "evidence_ids cannot exceed 100 items")
            if len(set(evidence_ids)) != len(evidence_ids):
                raise BackendError("invalid_audit_run_measurement", "evidence_ids must contain unique items")

        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_assessment_revision)
            self._check_non_terminal_event_capacity(assessment_id)

            audit_run = self._get_audit_run_unlocked(assessment_id, audit_run_id)
            if audit_run.get("status") in ("completed", "cancelled"):
                raise BackendError("audit_run_sealed", "cannot save comparison in sealed audit run")
            if audit_run.get("status") != "in_progress":
                raise BackendError("invalid_audit_run_transition", "audit run must be in_progress to save comparisons")
            if audit_run.get("revision") != expected_audit_run_revision:
                raise BackendError("revision_conflict", "audit run revision has changed")

            measurements = audit_run.get("measurements", [])
            target_idx = -1
            target_m = None
            for idx, m in enumerate(measurements):
                if m.get("measurement_point_id") == measurement_point_id:
                    target_idx = idx
                    target_m = m
                    break

            if target_m is None:
                raise BackendError(
                    "audit_measurement_not_found",
                    "measurement point is not part of the audit run",
                )
            if target_m.get("status") != "resolved":
                raise BackendError(
                    "audit_measurement_not_resolved",
                    "cannot save comparison for a measurement that is not resolved",
                )

            # Read and verify immutable native artifacts only after acquiring the
            # same assessment lock used by their production writers. The bytes
            # validated here are the bytes bound into this mutation.
            comparison_record = None
            occurrence_record = None
            comp_id = outcome.get("comparison_id")
            comp_digest = outcome.get("comparison_digest")
            occ_id = outcome.get("occurrence_set_id")
            if status == "completed":
                if not comp_id:
                    raise BackendError(
                        "invalid_audit_run_measurement",
                        "comparison_id is required",
                    )
                comparison_record = self._validate_artifact_reference(
                    assessment_id,
                    "comparison",
                    comp_id,
                    expected_digest=comp_digest,
                )
                if not occ_id:
                    raise BackendError(
                        "invalid_audit_run_measurement",
                        "occurrence_set_id is required",
                    )
                occurrence_record = self._validate_artifact_reference(
                    assessment_id,
                    "occurrence",
                    occ_id,
                    expected_digest=comparison_record["occurrence_digest"],
                    expected_comparison_id=comp_id,
                )
            elif comp_id:
                comparison_record = self._validate_artifact_reference(
                    assessment_id,
                    "comparison",
                    comp_id,
                    expected_digest=comp_digest,
                )
                if occ_id:
                    occurrence_record = self._validate_artifact_reference(
                        assessment_id,
                        "occurrence",
                        occ_id,
                        expected_digest=comparison_record["occurrence_digest"],
                        expected_comparison_id=comp_id,
                    )
            elif occ_id:
                raise BackendError(
                    "invalid_audit_run_measurement",
                    "occurrence_set_id requires comparison_id",
                )

            if comparison_record is not None:
                self._validate_artifacts_match_resolved_measurement(
                    target_m,
                    comparison_record,
                    occurrence_record,
                    evidence_ids,
                )

            for pin in RESOLVED_PINNED_FIELDS:
                if pin in outcome and outcome[pin] != target_m.get(pin):
                    raise BackendError(
                        "invalid_audit_run_measurement",
                        "cannot replace immutable pinned fields during comparison",
                    )

            updated_m = _json_clone(target_m, "invalid_audit_run_measurement", "measurement")
            if status == "completed":
                updated_m.update(_json_clone(outcome, "invalid_audit_run_measurement", "outcome"))
                updated_m.pop("resolved_at", None)
                for k in FAILURE_FIELDS:
                    updated_m.pop(k, None)
            elif status == "failed":
                updated_m.update(_json_clone(outcome, "invalid_audit_run_measurement", "outcome"))
                updated_m["failed_stage"] = "comparison"
                updated_m["retry_target"] = "resolved"
                for k in COMPLETED_FIELDS:
                    updated_m.pop(k, None)

            mid = target_m.get("measurement_id") or target_m.get("audit_measurement_id")
            updated_m["measurement_id"] = mid
            updated_m["audit_run_id"] = audit_run_id
            updated_m["measurement_point_id"] = measurement_point_id

            _validate_audit_run_measurement(updated_m)

            updated_measurements = list(measurements)
            updated_measurements[target_idx] = updated_m

            updated_run = _json_clone(audit_run, "invalid_audit_run", "audit_run")
            updated_run["measurements"] = updated_measurements
            updated_run["revision"] += 1

            run_bytes = self._validate_audit_run_size(updated_run)

            sanitized_m = _sanitize_measurement(updated_m)

            event_type = (
                "audit_measurement_completed"
                if status == "completed"
                else "audit_measurement_failed"
            )
            event_data = (
                {"comparison_id": updated_m["comparison_id"]}
                if status == "completed"
                else {
                    "measurement_point_id": measurement_point_id,
                    "failed_stage": "comparison",
                    "error_code": updated_m["error_code"],
                }
            )
            event_obj, events_bytes = self._transaction_event(
                assessment_id,
                metadata,
                event_type,
                event_data,
            )
            base = self._ensure_assessment_directories(assessment_id)
            txn = PrivateTransaction(base, fault_injector=self.fault_injector)
            txn.add_bytes(f"audit_runs/{audit_run_id}.json", run_bytes)
            txn.add_json("assessment.json", metadata)
            txn.add_bytes("events.jsonl", events_bytes)
            txn.commit()

            return {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "assessment_revision": metadata["revision"],
                "assessment_capacity": self._get_assessment_capacity_unlocked(assessment_id),
                "audit_run": _sanitize_audit_run(updated_run),
                "measurement": sanitized_m,
            }
