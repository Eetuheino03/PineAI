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
    ASSESSMENT_SCHEMA_VERSION,
    ASSESSMENT_ID_PATTERN,
    FINDING_CORE_FIELDS,
    FINDING_ID_PATTERN,
    MAX_COMPARISONS,
    MAX_DOCUMENT_BYTES,
    MAX_EVENTS,
    MAX_FINDINGS,
    MAX_SNAPSHOTS,
    _canonical_digest,
    _bind_snapshot_record_digest,
    _ensure_no_raw_recon,
    _json_clone,
    _snapshot_record_digest,
    _utc_now,
    _validate_comparison,
    _validate_finding_core,
    _validate_revision,
    _validate_snapshot,
)
from .customer_store import (
    CUSTOMER_AUDIT_SCHEMA_VERSION,
    MAX_PROFILE_DOCUMENT_BYTES,
    OCCURRENCE_INPUT_FIELDS,
    OCCURRENCE_SCHEMA_VERSION,
    OCCURRENCE_STORED_FIELDS,
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

MAX_ACTIVE_MEASUREMENT_POINTS = 16
MAX_TOTAL_MEASUREMENT_POINT_RECORDS = 32
MAX_AUDIT_RUNS_PER_ASSESSMENT = 32
MAX_MEASUREMENT_POINTS_PER_RUN = 16
MAX_MEASUREMENT_POINTS_DOCUMENT_BYTES = 512 * 1024
MAX_AUDIT_RUN_DOCUMENT_BYTES = 512 * 1024
MAX_AUDIT_RUN_INDEX_BYTES = 256 * 1024
MAX_AUDIT_RUN_LIST_BYTES = 512 * 1024
MAX_AUDIT_RUN_REPORT_ARTIFACT_BYTES = 512 * 1024
MAX_EVIDENCE_IDS_PER_AUDIT_MEASUREMENT = 100
MAX_OCCURRENCES = 100
MAX_AUDIT_RUN_MANIFEST_BYTES = 64 * 1024
MAX_NATIVE_ARTIFACT_DOCUMENT_BYTES = 4 * 1024 * 1024
# A cancellation reason may contain 512 four-byte UTF-8 code points. Keep
# enough additional space for the canonical event envelope so every accepted
# active run can still be sealed when the event document is near capacity.
AUDIT_RUN_TERMINAL_EVENT_RESERVE_BYTES = 4096
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
        path,
        invalid_code,
        "{0} is unreadable".format(description),
        invalid_code=invalid_code,
    )


def _canonical_json_size(value: Any, code: str, description: str) -> int:
    try:
        return len(
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        )
    except (TypeError, ValueError) as error:
        raise BackendError(
            code, "{0} is not valid JSON".format(description)
        ) from error


def _generate_mp_id() -> str:
    return "mp_{0}".format(uuid.uuid4().hex[:16])


def _generate_ar_id() -> str:
    return "ar_{0}".format(uuid.uuid4().hex[:16])


def _generate_arm_id() -> str:
    return "arm_{0}".format(uuid.uuid4().hex[:16])


_RFC3339_PATTERN = re.compile(
    r"^([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):"
    r"([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?"
    r"([Zz]|[+-][0-9]{2}:[0-9]{2})$"
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

    # PineAI's persisted canonical profile deliberately excludes leap-second
    # notation because it cannot validate the external leap-second table
    # offline without introducing mutable time authority.
    if hour > 23 or minute > 59 or second > 59:
        raise BackendError(
            error_code,
            "{0} contains an invalid time component".format(param_name),
        )

    # Validate timezone offset bounds
    if tz_part.upper() != "Z":
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
    if zone.upper() == "Z":
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


def _clean_action_text(
    value: Any,
    field: str,
    maximum: int,
    required: bool,
    error_code: str,
) -> str:
    try:
        return _clean_text(
            value, field, maximum, required=required
        )
    except BackendError as error:
        if error.code != "invalid_profile":
            raise
        raise BackendError(error_code, str(error)) from error


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


def _canonical_measurement_identity(value: Dict[str, Any]) -> Dict[str, Any]:
    measurement = dict(value)
    legacy = measurement.get("audit_measurement_id")
    current = measurement.get("measurement_id")
    if legacy is not None:
        if current is not None and current != legacy:
            raise BackendError(
                "invalid_audit_run_measurement",
                "measurement identity aliases conflict",
            )
        measurement.setdefault("measurement_id", legacy)
    return measurement


def _validate_audit_run_measurement(m: Dict[str, Any]) -> None:
    """Validate measurement fields strictly against the 8 variant schemas."""
    if not isinstance(m, dict):
        raise BackendError("invalid_audit_run_measurement", "measurement must be an object")
    m = _canonical_measurement_identity(m)

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
            raise BackendError(
                "invalid_audit_run_measurement", "unknown failed_stage"
            )


def _validate_persisted_measurement(m: Dict[str, Any]) -> None:
    if not isinstance(m, dict):
        raise BackendError("invalid_audit_run_measurement", "measurement must be an object")
    m = _canonical_measurement_identity(m)

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
        measurement_created = lower_bound
        if isinstance(measurement.get("created_at"), str):
            measurement_created = _rfc3339_order_key(
                measurement["created_at"]
            )
            if measurement_created < created_time:
                raise BackendError(
                    "invalid_audit_run",
                    "measurement created_at precedes the audit run",
                )
            if (
                completed_time is not None
                and measurement_created > completed_time
            ):
                raise BackendError(
                    "invalid_audit_run",
                    "measurement created_at follows the sealed audit run",
                )
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
            if measurement_time < max(lower_bound, measurement_created):
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
            if _rfc3339_order_key(archived_at) < _rfc3339_order_key(
                point["created_at"]
            ):
                raise BackendError(
                    "invalid_measurement_point",
                    "archived_at precedes measurement point creation",
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

    m_copy = _canonical_measurement_identity(m)
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

    try:
        res = {
            "location_id": _clean_text(
                context.get("location_id"),
                "location_id",
                128,
                required=True,
            ),
            "scan_profile_id": _clean_text(
                context.get("scan_profile_id"),
                "scan_profile_id",
                128,
                required=True,
            ),
            "radio_profile_id": _clean_text(
                context.get("radio_profile_id"),
                "radio_profile_id",
                128,
                required=True,
            ),
            "interface": _clean_text(
                context.get("interface"),
                "interface",
                64,
                required=True,
            ),
            "declared_bands": _text_list(
                context.get("declared_bands"),
                "declared_bands",
                allowed={"2.4", "5"},
                maximum=2,
            ),
            "declared_channels": _integer_list(
                context.get("declared_channels"),
                "declared_channels",
                1,
                196,
            ),
            "scan_time": context.get("scan_time"),
        }
    except BackendError as error:
        if error.code != "invalid_profile":
            raise
        raise BackendError(
            "invalid_measurement_point", str(error)
        ) from error
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


class _LegacyRepeatableAuditStore(CustomerAuditStore):
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
        required_events = 1 + int(
            metadata.get("_pending_storage_schema_migration_from")
            is not None
        )
        if (
            not isinstance(sequence, int)
            or isinstance(sequence, bool)
            or sequence < 0
            or sequence + required_events + reserve > MAX_EVENTS
        ):
            raise BackendError("event_limit", "event capacity limit exceeded")

    def _transaction_event(
        self,
        assessment_id: str,
        metadata: Dict[str, Any],
        event_type: str,
        data: Optional[Dict[str, Any]],
        extra_closure_reserve: int = 0,
    ):
        terminal = event_type in {
            "audit_run_cancelled",
            "audit_run_completed",
        }
        self._require_event_slot_unlocked(
            assessment_id,
            metadata,
            terminal_audit_run_event=terminal,
            extra_closure_reserve=extra_closure_reserve,
        )
        event, event_bytes = super()._transaction_event(
            assessment_id, metadata, event_type, data
        )
        remaining_reserve = self._event_closure_reserve_unlocked(
            assessment_id
        )
        if terminal and remaining_reserve:
            remaining_reserve -= 1
        remaining_reserve += extra_closure_reserve
        if (
            len(event_bytes)
            + (
                remaining_reserve
                * AUDIT_RUN_TERMINAL_EVENT_RESERVE_BYTES
            )
            > MAX_DOCUMENT_BYTES
        ):
            raise BackendError(
                "event_limit",
                "event storage cannot preserve active audit run closure",
            )
        return event, event_bytes

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
        validate_snapshot_reference: bool = True,
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
        if validate_snapshot_reference:
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
            or set(data) != NATIVE_OCCURRENCE_REQUIRED_FIELDS
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
                or occurrence["occurrence_set_id"]
                != comparison["occurrence_set_id"]
                or occurrence["occurrence_digest"]
                != comparison["occurrence_digest"]
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
        maximum_bytes: int = MAX_NATIVE_ARTIFACT_DOCUMENT_BYTES,
        validate_linked_artifacts: bool = True,
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
            min(maximum_bytes, MAX_NATIVE_ARTIFACT_DOCUMENT_BYTES),
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
                assessment_id,
                artifact_id,
                data,
                validate_snapshot_reference=validate_linked_artifacts,
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
            if expected_comparison_id is not None and validate_linked_artifacts:
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
        base, _, _, _, _ = self._assessment_paths(assessment_id)
        if base.is_symlink() or not base.is_dir():
            raise BackendError(
                "assessment_not_found", "assessment was not found"
            )
        runs_dir = base / "audit_runs"
        if not runs_dir.exists() and not runs_dir.is_symlink():
            return {}
        if runs_dir.is_symlink() or not runs_dir.is_dir():
            raise BackendError(
                "invalid_audit_run", "audit run directory is invalid"
            )
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
        base, _, _, _, _ = self._assessment_paths(assessment_id)
        if base.is_symlink() or not base.is_dir():
            raise BackendError(
                "assessment_not_found", "assessment was not found"
            )
        manifest_file = base / "audit_runs_manifest.json"
        if manifest_file.exists() or manifest_file.is_symlink():
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
            reconstructed = self._reconstruct_audit_runs_manifest_unlocked(
                assessment_id
            )
            if persisted["runs"] != reconstructed["runs"]:
                raise BackendError(
                    "invalid_audit_run_manifest",
                    "audit run manifest does not match authoritative records",
                )
            return persisted

        return self._reconstruct_audit_runs_manifest_unlocked(
            assessment_id
        )

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
        snapshots = len(
            self._bounded_document_paths(
                base / "snapshots",
                re.compile(r"^snapshot_[0-9a-f]{16}\.json$"),
                MAX_SNAPSHOTS,
                "snapshot",
            )
        )
        comparisons = len(
            self._bounded_document_paths(
                base / "comparisons",
                re.compile(r"^comparison_[0-9a-f]{16}\.json$"),
                MAX_COMPARISONS,
                "comparison",
            )
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
            sorted_pts = sorted(
                sorted(
                    all_pts,
                    key=lambda point: point["measurement_point_id"],
                ),
                key=lambda point: _rfc3339_order_key(
                    point["created_at"]
                ),
                reverse=True,
            )
            total = len(sorted_pts)
            paginated = sorted_pts[offset:offset + limit]
            return {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "measurement_points": paginated,
                "total": total,
                "limit": limit,
                "offset": offset,
                "has_more": offset + len(paginated) < total,
                "assessment_capacity": self._get_assessment_capacity_unlocked(
                    assessment_id
                ),
            }

    def _get_measurement_point_unlocked(
        self, assessment_id: str, measurement_point_id: str
    ) -> Dict[str, Any]:
        if (
            not isinstance(measurement_point_id, str)
            or not MEASUREMENT_POINT_ID_PATTERN.match(
                measurement_point_id
            )
        ):
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
                "assessment_capacity": self._get_assessment_capacity_unlocked(
                    assessment_id
                ),
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
        clean_name = _clean_action_text(
            name, "name", 128, True, "invalid_measurement_point"
        )
        clean_desc = (
            _clean_action_text(
                description,
                "description",
                512,
                False,
                "invalid_measurement_point",
            )
            if description is not None
            else None
        )

        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_assessment_revision)

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
        if (
            not isinstance(measurement_point_id, str)
            or not MEASUREMENT_POINT_ID_PATTERN.match(
                measurement_point_id
            )
        ):
            raise BackendError(
                "invalid_measurement_point",
                "invalid measurement_point_id format",
            )
        if not isinstance(updates, dict) or not updates:
            raise BackendError("invalid_measurement_point", "updates must be a non-empty object")

        allowed_keys = {"name", "description", "expected_measurement_context"}
        if set(updates) - allowed_keys:
            raise BackendError("invalid_measurement_point", "updates contains unsupported fields")

        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_assessment_revision)

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
                updated_mp["name"] = _clean_action_text(
                    updates["name"],
                    "name",
                    128,
                    True,
                    "invalid_measurement_point",
                )
            if "description" in updates:
                updated_mp["description"] = (
                    _clean_action_text(
                        updates["description"],
                        "description",
                        512,
                        False,
                        "invalid_measurement_point",
                    )
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
        if (
            not isinstance(measurement_point_id, str)
            or not MEASUREMENT_POINT_ID_PATTERN.match(
                measurement_point_id
            )
        ):
            raise BackendError(
                "invalid_measurement_point",
                "invalid measurement_point_id format",
            )

        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_assessment_revision)

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
            updated_mp["archived_at"] = _timestamp_not_before(
                target_mp.get("created_at")
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
            sorted_runs = sorted(
                sorted(
                    all_runs,
                    key=lambda run: run["audit_run_id"],
                ),
                key=lambda run: _rfc3339_order_key(run["created_at"]),
                reverse=True,
            )
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
        if (
            not isinstance(audit_run_id, str)
            or not AUDIT_RUN_ID_PATTERN.match(audit_run_id)
        ):
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
        clean_title = _clean_action_text(
            title, "title", 128, True, "invalid_audit_run"
        )
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
                extra_closure_reserve=1,
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

    def _ensure_run_split_unlocked(
        self, assessment_id: str, audit_run_id: str
    ) -> Dict[str, Any]:
        directory = self._run_directory(assessment_id, audit_run_id)
        if (directory / "manifest.json").exists() or (directory / "manifest.json").is_symlink():
            return self._assemble_v11_run_unlocked(assessment_id, audit_run_id)
        return self._migrate_legacy_run_unlocked(assessment_id, audit_run_id)

    def _write_manifest_event_unlocked(
        self,
        assessment_id: str,
        metadata: Dict[str, Any],
        manifest: Dict[str, Any],
        event_type: str,
        event_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        self._validate_v11_manifest(manifest, assessment_id, manifest["audit_run_id"])
        event, events_bytes = self._transaction_event(
            assessment_id, metadata, event_type, event_data
        )
        transaction = PrivateTransaction(self._ensure_assessment_directories(assessment_id), fault_injector=self.fault_injector)
        transaction.add_json(
            "audit_runs/{0}/manifest.json".format(manifest["audit_run_id"]), manifest
        )
        transaction.add_json("assessment.json", metadata)
        transaction.add_bytes("events.jsonl", events_bytes)
        transaction.commit()
        return event

    def _split_start_audit_run_compat(
        self,
        assessment_id: str,
        expected_assessment_revision: int,
        audit_run_id: str,
        expected_audit_run_revision: int,
    ) -> Dict[str, Any]:
        _validate_revision(expected_assessment_revision)
        _validate_revision(expected_audit_run_revision)
        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_assessment_revision)
            run = self._ensure_run_split_unlocked(assessment_id, audit_run_id)
            if run["status"] in {"completed", "cancelled"}:
                raise BackendError("audit_run_sealed", "audit run is sealed")
            if run["status"] != "draft":
                raise BackendError("invalid_state_transition", "only a draft run can be started")
            if run["revision"] != expected_audit_run_revision:
                raise BackendError("revision_conflict", "audit run revision has changed")
            competing = [
                item["audit_run_id"]
                for item in self._list_audit_runs_unlocked(assessment_id)
                if item["status"] == "in_progress" and item["audit_run_id"] != audit_run_id
            ]
            if competing:
                raise BackendError("active_audit_run_exists", "another audit run is in progress")
            if not self._pins_still_valid_unlocked(assessment_id, run):
                raise BackendError("pinned_reference_mismatch", "audit run provenance is no longer valid")
            manifest = self._public_manifest(run)
            manifest["status"] = "in_progress"
            manifest["started_at"] = _timestamp_not_before(run["created_at"])
            manifest["revision"] += 1
            self._write_manifest_event_unlocked(
                assessment_id,
                metadata,
                manifest,
                "audit_run_started",
                {"audit_run_id": audit_run_id},
            )
            assembled = dict(manifest, measurements=run["measurements"])
            return {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "assessment_revision": metadata["revision"],
                "audit_run": manifest,
                "measurements": [self._public_measurement(item) for item in run["measurements"]],
                "workflow": self._workflow(assembled),
            }

    def _split_cancel_audit_run_compat(
        self,
        assessment_id: str,
        expected_assessment_revision: int,
        audit_run_id: str,
        expected_audit_run_revision: int,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        _validate_revision(expected_assessment_revision)
        _validate_revision(expected_audit_run_revision)
        clean_reason = (
            _clean_action_text(reason, "reason", 512, False, "invalid_audit_run")
            if reason is not None
            else None
        )
        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_assessment_revision)
            run = self._ensure_run_split_unlocked(assessment_id, audit_run_id)
            if run["status"] in {"completed", "cancelled"}:
                raise BackendError("audit_run_sealed", "audit run is already sealed")
            if run["revision"] != expected_audit_run_revision:
                raise BackendError("revision_conflict", "audit run revision has changed")
            manifest = self._public_manifest(run)
            manifest["status"] = "cancelled"
            manifest["completed_at"] = _timestamp_not_before(*_audit_run_terminal_times(run))
            manifest["revision"] += 1
            data = {"audit_run_id": audit_run_id}
            if clean_reason:
                data["reason"] = clean_reason
            self._write_manifest_event_unlocked(
                assessment_id, metadata, manifest, "audit_run_cancelled", data
            )
            return {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "assessment_revision": metadata["revision"],
                "audit_run": manifest,
                "measurements": [self._public_measurement(item) for item in run["measurements"]],
                "workflow": self._workflow(dict(manifest, measurements=run["measurements"])),
            }

    def _split_complete_audit_run_compat(
        self,
        assessment_id: str,
        expected_assessment_revision: int,
        audit_run_id: str,
        expected_audit_run_revision: int,
    ) -> Dict[str, Any]:
        _validate_revision(expected_assessment_revision)
        _validate_revision(expected_audit_run_revision)
        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_assessment_revision)
            run = self._ensure_run_split_unlocked(assessment_id, audit_run_id)
            if run["status"] in {"completed", "cancelled"}:
                raise BackendError("audit_run_sealed", "audit run is already sealed")
            if run["status"] != "in_progress":
                raise BackendError("invalid_state_transition", "run must be in progress")
            if run["revision"] != expected_audit_run_revision:
                raise BackendError("revision_conflict", "audit run revision has changed")
            if any(item["status"] != "completed" for item in run["measurements"]):
                raise BackendError("invalid_state_transition", "all measurements must be completed")
            manifest = self._public_manifest(run)
            manifest["status"] = "completed"
            manifest["completed_at"] = _timestamp_not_before(*_audit_run_terminal_times(run))
            manifest["revision"] += 1
            self._write_manifest_event_unlocked(
                assessment_id,
                metadata,
                manifest,
                "audit_run_completed",
                {"audit_run_id": audit_run_id},
            )
            return {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "assessment_revision": metadata["revision"],
                "audit_run": manifest,
                "measurements": [self._public_measurement(item) for item in run["measurements"]],
                "workflow": self._workflow(dict(manifest, measurements=run["measurements"])),
            }

    def _find_measurement_unlocked(
        self, run: Dict[str, Any], measurement_id: str
    ) -> Dict[str, Any]:
        if not isinstance(measurement_id, str) or not AUDIT_MEASUREMENT_ID_PATTERN.match(measurement_id):
            raise BackendError("invalid_audit_run_measurement", "measurement_id format is invalid")
        for item in run["measurements"]:
            if item["measurement_id"] == measurement_id:
                return item
        raise BackendError("audit_measurement_not_found", "measurement was not found")

    def _measurement_mutation_transaction(
        self,
        assessment_id: str,
        metadata: Dict[str, Any],
        manifest: Dict[str, Any],
        measurement: Dict[str, Any],
        event_type: str,
        event_data: Dict[str, Any],
        immutable_documents: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> None:
        self._validate_v11_manifest(manifest, assessment_id, manifest["audit_run_id"])
        self._validate_v11_measurement(measurement, assessment_id, manifest["audit_run_id"])
        event, events_bytes = self._transaction_event(
            assessment_id, metadata, event_type, event_data
        )
        transaction = PrivateTransaction(self._ensure_assessment_directories(assessment_id), fault_injector=self.fault_injector)
        transaction.add_json(
            "audit_runs/{0}/manifest.json".format(manifest["audit_run_id"]), manifest
        )
        transaction.add_json(
            "audit_runs/{0}/measurements/{1}.json".format(manifest["audit_run_id"], measurement["measurement_id"]),
            measurement,
        )
        for relative_path, document in sorted((immutable_documents or {}).items()):
            transaction.add_json(relative_path, document)
        transaction.add_json("assessment.json", metadata)
        transaction.add_bytes("events.jsonl", events_bytes)
        transaction.commit()

    def _split_resolve_audit_measurement_compat(
        self,
        assessment_id: str,
        expected_assessment_revision: int,
        audit_run_id: str,
        expected_audit_run_revision: int,
        measurement_id: str,
        expected_measurement_revision: int,
        resolution: Optional[Dict[str, Any]] = None,
        snapshot: Optional[Dict[str, Any]] = None,
        failure: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        _validate_revision(expected_assessment_revision)
        _validate_revision(expected_audit_run_revision)
        _validate_revision(expected_measurement_revision)
        supplied = sum(item is not None for item in (resolution, snapshot, failure))
        if supplied != 1:
            raise BackendError(
                "invalid_audit_run_measurement",
                "provide exactly one of resolution, snapshot, or failure",
            )
        if snapshot is not None:
            if not isinstance(snapshot, dict):
                raise BackendError("invalid_audit_run_measurement", "snapshot bundle must be an object")
            resolution = dict(snapshot, status="resolved")
            if "document" in resolution and "snapshot" not in resolution:
                resolution["snapshot"] = resolution.pop("document")
        elif failure is not None:
            if not isinstance(failure, dict):
                raise BackendError("invalid_audit_run_measurement", "failure must be an object")
            resolution = dict(failure, status="failed", failed_stage="resolution")
        if not isinstance(resolution, dict):
            raise BackendError("invalid_audit_run_measurement", "resolution must be an object")
        _ensure_no_raw_recon(resolution)
        status = resolution.get("status")
        if status not in {"resolved", "failed"}:
            raise BackendError("invalid_audit_run_measurement", "resolution status is invalid")
        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_assessment_revision)
            run = self._ensure_run_split_unlocked(assessment_id, audit_run_id)
            if run["status"] in {"completed", "cancelled"}:
                raise BackendError("audit_run_sealed", "audit run is sealed")
            if run["status"] != "in_progress":
                raise BackendError("invalid_state_transition", "run must be in progress")
            if run["revision"] != expected_audit_run_revision:
                raise BackendError("revision_conflict", "audit run revision has changed")
            current = self._find_measurement_unlocked(run, measurement_id)
            if current["revision"] != expected_measurement_revision:
                raise BackendError("revision_conflict", "measurement revision has changed")
            if current["status"] != "pending":
                raise BackendError("invalid_state_transition", "only a pending measurement can be resolved")
            if current.get("provenance_status") != "pinned":
                raise BackendError("pinned_reference_missing", "legacy measurement lacks immutable provenance")

            updated = dict(current)
            immutable_documents = {}
            if status == "failed":
                if resolution.get("failed_stage", "resolution") != "resolution":
                    raise BackendError("invalid_audit_run_measurement", "resolution failure stage is invalid")
                updated.update(
                    {
                        "status": "failed",
                        "failed_stage": "resolution",
                        "retry_target": "pending",
                        "error_code": _clean_action_text(
                            resolution.get("error_code"), "error_code", 128, True, "invalid_audit_run_measurement"
                        ),
                        "error_message": _clean_action_text(
                            resolution.get("error_message"), "error_message", 512, True, "invalid_audit_run_measurement"
                        ),
                        "failed_at": _validate_rfc3339(
                            resolution.get("failed_at"), "failed_at", "invalid_audit_run_measurement"
                        ),
                    }
                )
                event_type = "audit_measurement_failed"
                event_data = {
                    "measurement_id": measurement_id,
                    "failed_stage": "resolution",
                    "error_code": updated["error_code"],
                }
            else:
                snapshot_value = resolution.get("snapshot")
                try:
                    snapshot = _validate_snapshot(snapshot_value)
                except BackendError as error:
                    raise BackendError("invalid_audit_run_measurement", "normalized snapshot is invalid") from error
                snapshot_id = snapshot["snapshot_id"]
                snapshot_digest = snapshot["snapshot_digest"]
                context = snapshot.get("scan_metadata", {}).get("measurement_context", {})
                for field in (
                    "measurement_profile_id",
                    "measurement_profile_version_id",
                    "measurement_profile_digest",
                ):
                    if context.get(field) != current.get(field):
                        raise BackendError("pinned_reference_mismatch", "snapshot measurement profile pin differs")
                comparability_status = resolution.get("comparability_status")
                if comparability_status not in {"comparable", "partially_comparable", "not_comparable"}:
                    raise BackendError("invalid_audit_run_measurement", "comparability status is invalid")
                resolved_at = _validate_rfc3339(
                    resolution.get("resolved_at"), "resolved_at", "invalid_audit_run_measurement"
                )
                if _rfc3339_order_key(resolved_at) < _rfc3339_order_key(current["created_at"]):
                    raise BackendError("invalid_audit_run_measurement", "resolved_at precedes measurement creation")
                snapshot_path = self._snapshot_path(assessment_id, snapshot_id)
                snapshot_is_new = self._snapshot_immutable_preflight(
                    snapshot_path, snapshot, "immutable_artifact_conflict"
                )
                if snapshot_is_new:
                    capacity = self._get_assessment_capacity_unlocked(assessment_id)
                    if capacity["snapshot_available"] < 1:
                        raise BackendError("capacity_exceeded", "snapshot capacity is exhausted")
                updated.update(
                    {
                        "status": "resolved",
                        "snapshot_id": snapshot_id,
                        "snapshot_digest": snapshot_digest,
                        "comparability_status": comparability_status,
                        "resolved_at": resolved_at,
                    }
                )
                source_recon_id = resolution.get("source_recon_id")
                if source_recon_id is not None:
                    updated["source_recon_id"] = _clean_action_text(
                        source_recon_id, "source_recon_id", 128, True, "invalid_audit_run_measurement"
                    )
                if snapshot_is_new:
                    immutable_documents[
                        "snapshots/{0}.json".format(snapshot_id)
                    ] = snapshot
                event_type = "audit_measurement_resolved"
                event_data = {"measurement_id": measurement_id, "snapshot_id": snapshot_id}
            updated["revision"] += 1
            manifest = self._public_manifest(run)
            manifest["revision"] += 1
            self._measurement_mutation_transaction(
                assessment_id,
                metadata,
                manifest,
                updated,
                event_type,
                event_data,
                immutable_documents,
            )
            updated_run = dict(
                manifest,
                measurements=[updated if item["measurement_id"] == measurement_id else item for item in run["measurements"]],
            )
            return {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "assessment_revision": metadata["revision"],
                "audit_run": manifest,
                "measurement": self._public_measurement(updated),
                "workflow": self._workflow(updated_run),
                "assessment_capacity": self._get_assessment_capacity_unlocked(assessment_id),
            }

    def _validate_comparison_bundle_unlocked(
        self,
        assessment_id: str,
        measurement: Dict[str, Any],
        comparison: Any,
        occurrence: Any,
    ) -> Dict[str, Any]:
        if not isinstance(comparison, dict) or not isinstance(occurrence, dict):
            raise BackendError("invalid_audit_run_measurement", "comparison bundle is incomplete")
        _ensure_no_raw_recon(comparison)
        _ensure_no_raw_recon(occurrence)
        comparison_id = comparison.get("comparison_id")
        occurrence_id = occurrence.get("occurrence_set_id")
        if (
            not isinstance(comparison_id, str)
            or not COMPARISON_ID_PATTERN.match(comparison_id)
            or comparison.get("assessment_id") != assessment_id
            or comparison.get("current_snapshot_id") != measurement.get("snapshot_id")
            or comparison.get("current_snapshot_digest") != measurement.get("snapshot_digest")
            or comparison.get("baseline_version_id") != measurement.get("baseline_version_id")
        ):
            raise BackendError("pinned_reference_mismatch", "comparison does not match the resolved measurement")
        if (
            not isinstance(occurrence_id, str)
            or not OCCURRENCE_SET_ID_PATTERN.match(occurrence_id)
            or occurrence.get("assessment_id") != assessment_id
            or occurrence.get("comparison_id") != comparison_id
            or comparison.get("occurrence_set_id") != occurrence_id
        ):
            raise BackendError("pinned_reference_mismatch", "occurrence does not match comparison")
        pins = comparison.get("pinned_versions")
        if not isinstance(pins, dict):
            raise BackendError("pinned_reference_mismatch", "comparison pins are missing")
        expected = {
            "baseline_version_id": measurement.get("baseline_version_id"),
            "baseline_digest": measurement.get("baseline_digest"),
            "measurement_profile_id": measurement.get("measurement_profile_id"),
            "measurement_profile_version_id": measurement.get("measurement_profile_version_id"),
            "measurement_profile_digest": measurement.get("measurement_profile_digest"),
            "assurance_profile_version_id": measurement.get("assurance_profile_version_id"),
            "assurance_profile_digest": measurement.get("assurance_profile_digest"),
        }
        if pins != expected or occurrence.get("pinned_versions") != expected:
            raise BackendError("pinned_reference_mismatch", "comparison provenance differs from run pins")
        stored_occurrence_digest = occurrence.get("occurrence_digest")
        reproduced_occurrence_digest = _canonical_digest(
            {key: value for key, value in occurrence.items() if key not in {"occurrence_set_id", "occurrence_digest"}}
        )
        if (
            stored_occurrence_digest != reproduced_occurrence_digest
            or occurrence_id != "occurrence_{0}".format(reproduced_occurrence_digest[:16])
            or comparison.get("occurrence_digest") != stored_occurrence_digest
        ):
            raise BackendError("digest_mismatch", "occurrence digest is invalid")
        self._validate_native_occurrence_record(
            assessment_id, occurrence_id, occurrence, comparison_id
        )
        self._validate_native_comparison_record(
            assessment_id, comparison_id, comparison
        )
        nested = _validate_comparison(comparison.get("comparison"))
        if nested.get("current_snapshot_id") != measurement.get("snapshot_id"):
            raise BackendError("pinned_reference_mismatch", "nested comparison snapshot differs")
        evidence = occurrence.get("evidence")
        if not isinstance(evidence, list) or len(evidence) > MAX_EVIDENCE_IDS_PER_AUDIT_MEASUREMENT:
            raise BackendError("invalid_audit_run_measurement", "occurrence evidence exceeds the measurement limit")
        evidence_ids = [item.get("evidence_id") for item in evidence if isinstance(item, dict)]
        if (
            len(evidence_ids) != len(evidence)
            or len(evidence_ids) != len(set(evidence_ids))
            or any(not isinstance(item, str) or not EVIDENCE_ID_PATTERN.match(item) for item in evidence_ids)
        ):
            raise BackendError("invalid_audit_run_measurement", "occurrence evidence IDs are invalid")
        return {
            "comparison_id": comparison_id,
            "comparison_digest": _canonical_digest(comparison),
            "occurrence_set_id": occurrence_id,
            "evidence_ids": evidence_ids,
        }

    def save_audit_measurement_comparison(
        self,
        assessment_id: str,
        expected_assessment_revision: int,
        audit_run_id: str,
        expected_audit_run_revision: int,
        measurement_id: str,
        expected_measurement_revision: int,
        analysis: Optional[Dict[str, Any]] = None,
        failure: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        _validate_revision(expected_assessment_revision)
        _validate_revision(expected_audit_run_revision)
        _validate_revision(expected_measurement_revision)
        if (analysis is None) == (failure is None):
            raise BackendError(
                "invalid_audit_run_measurement",
                "provide exactly one of analysis or failure",
            )
        if failure is not None:
            if not isinstance(failure, dict):
                raise BackendError("invalid_audit_run_measurement", "failure must be an object")
            analysis = dict(failure, status="failed", failed_stage="comparison")
        elif isinstance(analysis, dict):
            analysis = dict(analysis)
            analysis.setdefault("status", "completed")
        if not isinstance(analysis, dict):
            raise BackendError("invalid_audit_run_measurement", "analysis must be an object")
        _ensure_no_raw_recon(analysis)
        status = analysis.get("status")
        if status not in {"completed", "failed"}:
            raise BackendError("invalid_audit_run_measurement", "analysis status is invalid")
        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_assessment_revision)
            run = self._ensure_run_split_unlocked(assessment_id, audit_run_id)
            if run["status"] in {"completed", "cancelled"}:
                raise BackendError("audit_run_sealed", "audit run is sealed")
            if run["status"] != "in_progress":
                raise BackendError("invalid_state_transition", "run must be in progress")
            if run["revision"] != expected_audit_run_revision:
                raise BackendError("revision_conflict", "audit run revision has changed")
            current = self._find_measurement_unlocked(run, measurement_id)
            if current["revision"] != expected_measurement_revision:
                raise BackendError("revision_conflict", "measurement revision has changed")
            if current["status"] != "resolved":
                raise BackendError("invalid_state_transition", "measurement must be resolved")
            updated = dict(current)
            immutable_documents = {}
            if status == "failed":
                failed_at = _validate_rfc3339(
                    analysis.get("failed_at"),
                    "failed_at",
                    "invalid_audit_run_measurement",
                )
                if _rfc3339_order_key(failed_at) < _rfc3339_order_key(
                    current["resolved_at"]
                ):
                    raise BackendError(
                        "invalid_audit_run_measurement",
                        "failed_at precedes resolved_at",
                    )
                updated.update(
                    {
                        "status": "failed",
                        "failed_stage": "comparison",
                        "retry_target": "resolved",
                        "error_code": _clean_action_text(
                            analysis.get("error_code"), "error_code", 128, True, "invalid_audit_run_measurement"
                        ),
                        "error_message": _clean_action_text(
                            analysis.get("error_message"), "error_message", 512, True, "invalid_audit_run_measurement"
                        ),
                        "failed_at": failed_at,
                    }
                )
                event_type = "audit_measurement_failed"
                event_data = {
                    "measurement_id": measurement_id,
                    "failed_stage": "comparison",
                    "error_code": updated["error_code"],
                }
            else:
                comparison = analysis.get("comparison")
                occurrence = analysis.get("occurrence")
                references = self._validate_comparison_bundle_unlocked(
                    assessment_id, current, comparison, occurrence
                )
                completed_at = _validate_rfc3339(
                    analysis.get("completed_at"), "completed_at", "invalid_audit_run_measurement"
                )
                if _rfc3339_order_key(completed_at) < _rfc3339_order_key(current["resolved_at"]):
                    raise BackendError("invalid_audit_run_measurement", "completed_at precedes resolved_at")
                if (
                    comparison.get("created_at") != completed_at
                    or occurrence.get("recorded_at") != completed_at
                ):
                    raise BackendError(
                        "invalid_audit_run_measurement",
                        "analysis artifact timestamps are inconsistent",
                    )

                current_findings = self._read_findings(assessment_id)
                supplied_base_digest = analysis.get("findings_base_digest")
                if supplied_base_digest is not None and (
                    not isinstance(supplied_base_digest, str)
                    or not SHA256_DIGEST_PATTERN.match(supplied_base_digest)
                    or supplied_base_digest != _canonical_digest(current_findings)
                ):
                    raise BackendError(
                        "revision_conflict",
                        "finding state changed after analysis was built",
                    )
                occurrence_findings = occurrence.get("lifecycle_findings")
                if (
                    not isinstance(occurrence_findings, list)
                    or len(occurrence_findings) > MAX_FINDINGS
                ):
                    raise BackendError(
                        "invalid_audit_run_measurement",
                        "analysis lifecycle findings are invalid",
                    )
                normalized_findings = [
                    _validate_finding_core(item)
                    for item in occurrence_findings
                ]
                finding_ids = [
                    item["finding_id"] for item in normalized_findings
                ]
                if len(finding_ids) != len(set(finding_ids)):
                    raise BackendError(
                        "invalid_audit_run_measurement",
                        "analysis lifecycle finding IDs are duplicated",
                    )
                expected_findings, expected_lifecycle, expected_observed = (
                    self._build_finding_transition(
                        current_findings,
                        normalized_findings,
                        comparison["comparability_status"],
                        completed_at,
                        current.get("measurement_point_id"),
                    )
                )
                if (
                    comparison.get("lifecycle") != expected_lifecycle
                    or occurrence.get("lifecycle") != expected_lifecycle
                    or comparison.get("observed_finding_ids")
                    != sorted(expected_observed)
                ):
                    raise BackendError(
                        "invalid_audit_run_measurement",
                        "analysis lifecycle differs from deterministic state",
                    )
                expected_findings_document = None
                if expected_lifecycle["mutated"]:
                    expected_findings_document = {
                        "schema_version": ASSESSMENT_SCHEMA_VERSION,
                        "updated_at": completed_at,
                        "findings": expected_findings,
                    }
                findings_document = analysis.get("findings_document")
                if findings_document != expected_findings_document:
                    raise BackendError(
                        "invalid_audit_run_measurement",
                        "findings_document differs from deterministic state",
                    )
                if findings_document is not None:
                    _ensure_no_raw_recon(findings_document)

                comparison_path = self._comparison_path(
                    assessment_id, references["comparison_id"]
                )
                base = self._ensure_assessment_directories(assessment_id)
                occurrence_path = (
                    base / "occurrences"
                    / (references["occurrence_set_id"] + ".json")
                )
                self._immutable_preflight(
                    comparison_path, comparison, "immutable_artifact_conflict"
                )
                self._immutable_preflight(
                    occurrence_path, occurrence, "immutable_artifact_conflict"
                )
                capacity = self._get_assessment_capacity_unlocked(assessment_id)
                if not comparison_path.exists() and capacity["comparison_available"] < 1:
                    raise BackendError("capacity_exceeded", "comparison capacity is exhausted")
                occurrence_count = len(
                    self._bounded_document_paths(
                        base / "occurrences",
                        re.compile(r"^occurrence_[0-9a-f]{16}\.json$"),
                        MAX_OCCURRENCES,
                        "occurrence",
                    )
                )
                if not occurrence_path.exists() and occurrence_count >= MAX_OCCURRENCES:
                    raise BackendError(
                        "capacity_exceeded", "occurrence capacity is exhausted"
                    )
                updated.pop("resolved_at", None)
                updated.update(
                    {
                        "status": "completed",
                        "comparison_id": references["comparison_id"],
                        "comparison_digest": references["comparison_digest"],
                        "occurrence_set_id": references["occurrence_set_id"],
                        "evidence_ids": references["evidence_ids"],
                        "completed_at": completed_at,
                    }
                )
                immutable_documents[
                    "comparisons/{0}.json".format(references["comparison_id"])
                ] = comparison
                immutable_documents[
                    "occurrences/{0}.json".format(references["occurrence_set_id"])
                ] = occurrence
                if findings_document is not None:
                    immutable_documents["findings.json"] = findings_document
                event_type = "audit_measurement_completed"
                event_data = {
                    "measurement_id": measurement_id,
                    "comparison_id": references["comparison_id"],
                }
            updated["revision"] += 1
            manifest = self._public_manifest(run)
            manifest["revision"] += 1
            self._measurement_mutation_transaction(
                assessment_id,
                metadata,
                manifest,
                updated,
                event_type,
                event_data,
                immutable_documents,
            )
            updated_run = dict(
                manifest,
                measurements=[updated if item["measurement_id"] == measurement_id else item for item in run["measurements"]],
            )
            return {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "assessment_revision": metadata["revision"],
                "audit_run": manifest,
                "measurement": self._public_measurement(updated),
                "workflow": self._workflow(updated_run),
                "assessment_capacity": self._get_assessment_capacity_unlocked(assessment_id),
            }

    def retry_audit_measurement(
        self,
        assessment_id: str,
        expected_assessment_revision: int,
        audit_run_id: str,
        expected_audit_run_revision: int,
        measurement_id: str,
        expected_measurement_revision: int,
    ) -> Dict[str, Any]:
        _validate_revision(expected_assessment_revision)
        _validate_revision(expected_audit_run_revision)
        _validate_revision(expected_measurement_revision)
        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_assessment_revision)
            run = self._ensure_run_split_unlocked(assessment_id, audit_run_id)
            if run["status"] in {"completed", "cancelled"}:
                raise BackendError("audit_run_sealed", "audit run is sealed")
            if run["status"] != "in_progress":
                raise BackendError("invalid_state_transition", "run must be in progress")
            if run["revision"] != expected_audit_run_revision:
                raise BackendError("revision_conflict", "audit run revision has changed")
            current = self._find_measurement_unlocked(run, measurement_id)
            if current["revision"] != expected_measurement_revision:
                raise BackendError("revision_conflict", "measurement revision has changed")
            if current["status"] != "failed":
                raise BackendError("invalid_state_transition", "only failed measurements can be retried")
            updated = dict(current)
            stage = updated.get("failed_stage")
            for field in ("failed_stage", "retry_target", "error_code", "error_message", "failed_at"):
                updated.pop(field, None)
            if stage == "resolution":
                for field in (
                    "snapshot_id",
                    "snapshot_digest",
                    "snapshot_record_digest",
                    "comparability_status",
                    "source_recon_id",
                    "resolved_at",
                    "comparison_id",
                    "comparison_digest",
                    "occurrence_set_id",
                    "evidence_ids",
                    "completed_at",
                ):
                    updated.pop(field, None)
                updated["status"] = "pending"
            elif stage == "comparison":
                updated["status"] = "resolved"
            else:
                raise BackendError("invalid_state_transition", "failed stage is invalid")
            updated["revision"] += 1
            manifest = self._public_manifest(run)
            manifest["revision"] += 1
            self._measurement_mutation_transaction(
                assessment_id,
                metadata,
                manifest,
                updated,
                "audit_measurement_retried",
                {"measurement_id": measurement_id, "retry_target": updated["status"]},
            )
            updated_run = dict(
                manifest,
                measurements=[updated if item["measurement_id"] == measurement_id else item for item in run["measurements"]],
            )
            return {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "assessment_revision": metadata["revision"],
                "audit_run": manifest,
                "measurement": self._public_measurement(updated),
                "measurements": [
                    self._public_measurement(item)
                    for item in updated_run["measurements"]
                ],
                "workflow": self._workflow(updated_run),
                "assessment_capacity": self._get_assessment_capacity_unlocked(assessment_id),
            }

    def _get_assessment_capacity_unlocked(self, assessment_id: str) -> Dict[str, Any]:
        capacity = super()._get_assessment_capacity_unlocked(assessment_id)
        points = self._read_measurement_points_doc(assessment_id)["measurement_points"]
        runs = self._list_audit_runs_unlocked(assessment_id)
        active_points = sum(1 for item in points if item["status"] == "active")
        in_progress = sum(1 for item in runs if item["status"] == "in_progress")
        capacity.update(
            {
                "measurement_point_active_limit": MAX_ACTIVE_MEASUREMENT_POINTS,
                "measurement_point_active_used": active_points,
                "measurement_point_active_available": max(0, MAX_ACTIVE_MEASUREMENT_POINTS - active_points),
                "measurement_point_total_limit": MAX_TOTAL_MEASUREMENT_POINT_RECORDS,
                "measurement_point_total_used": len(points),
                "measurement_point_total_available": max(0, MAX_TOTAL_MEASUREMENT_POINT_RECORDS - len(points)),
                "audit_run_limit": MAX_AUDIT_RUNS_PER_ASSESSMENT,
                "audit_run_used": len(runs),
                "audit_run_available": max(0, MAX_AUDIT_RUNS_PER_ASSESSMENT - len(runs)),
                "assignments_per_run_limit": MAX_MEASUREMENT_POINTS_PER_RUN,
                "in_progress_audit_run_limit": 1,
                "in_progress_audit_run_used": in_progress,
                "in_progress_audit_run_available": max(0, 1 - in_progress),
            }
        )
        return capacity

    def start_audit_run(
        self,
        assessment_id: str,
        expected_assessment_revision: int,
        audit_run_id: str,
        expected_audit_run_revision: int,
    ) -> Dict[str, Any]:
        _validate_revision(expected_assessment_revision)
        _validate_revision(expected_audit_run_revision)
        if (
            not isinstance(audit_run_id, str)
            or not AUDIT_RUN_ID_PATTERN.match(audit_run_id)
        ):
            raise BackendError("invalid_audit_run", "audit_run_id format is invalid")

        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_assessment_revision)

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
        if (
            not isinstance(audit_run_id, str)
            or not AUDIT_RUN_ID_PATTERN.match(audit_run_id)
        ):
            raise BackendError("invalid_audit_run", "audit_run_id format is invalid")
        clean_reason = (
            _clean_action_text(
                reason,
                "reason",
                512,
                False,
                "invalid_audit_run",
            )
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
        if (
            not isinstance(audit_run_id, str)
            or not AUDIT_RUN_ID_PATTERN.match(audit_run_id)
        ):
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
        if not isinstance(outcome, dict):
            raise BackendError(
                "invalid_audit_run_measurement",
                "resolution outcome must be an object",
            )
        if (
            not isinstance(audit_run_id, str)
            or not AUDIT_RUN_ID_PATTERN.match(audit_run_id)
        ):
            raise BackendError(
                "invalid_audit_run", "audit_run_id format is invalid"
            )
        if (
            not isinstance(measurement_point_id, str)
            or not MEASUREMENT_POINT_ID_PATTERN.match(
                measurement_point_id
            )
        ):
            raise BackendError(
                "invalid_audit_run_measurement",
                "measurement_point_id is invalid",
            )
        _ensure_no_raw_recon(outcome)

        status = outcome.get("status")
        failed_stage = outcome.get("failed_stage")

        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_assessment_revision)

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


class _V11PublicMethods(object):
    """Authoritative public v0.7 store assembled after legacy adapters."""

    def _get_assessment_capacity_unlocked(self, assessment_id: str) -> Dict[str, Any]:
        base = self._ensure_assessment_directories(assessment_id)
        snapshots = len(
            self._bounded_document_paths(
                base / "snapshots", re.compile(r"^snapshot_[0-9a-f]{16}\.json$"),
                MAX_SNAPSHOTS, "snapshot"
            )
        )
        comparisons = len(
            self._bounded_document_paths(
                base / "comparisons", re.compile(r"^comparison_[0-9a-f]{16}\.json$"),
                MAX_COMPARISONS, "comparison"
            )
        )
        metadata = self._read_metadata(assessment_id)
        event_used = metadata.get("last_event_sequence", 0)
        points = self._read_measurement_points_doc(assessment_id)["measurement_points"]
        run_index = self._read_audit_runs_manifest_unlocked(assessment_id)
        run_statuses = run_index["runs"]
        active_points = sum(1 for item in points if item["status"] == "active")
        active_runs = sum(
            1 for status in run_statuses.values() if status == "in_progress"
        )
        closure_reserve = run_index["active_closure_reserve"]
        return {
            "snapshot_limit": MAX_SNAPSHOTS,
            "snapshot_used": snapshots,
            "snapshot_available": max(0, MAX_SNAPSHOTS - snapshots),
            "comparison_limit": MAX_COMPARISONS,
            "comparison_used": comparisons,
            "comparison_available": max(0, MAX_COMPARISONS - comparisons),
            "event_limit": MAX_EVENTS,
            "event_used": event_used,
            "event_available": max(0, MAX_EVENTS - event_used),
            "event_reserved_for_run_closure": closure_reserve,
            "event_available_for_non_terminal": max(0, MAX_EVENTS - event_used - closure_reserve),
            "measurement_point_active_limit": MAX_ACTIVE_MEASUREMENT_POINTS,
            "measurement_point_active_used": active_points,
            "measurement_point_active_available": max(0, MAX_ACTIVE_MEASUREMENT_POINTS - active_points),
            "measurement_point_total_limit": MAX_TOTAL_MEASUREMENT_POINT_RECORDS,
            "measurement_point_total_used": len(points),
            "measurement_point_total_available": max(0, MAX_TOTAL_MEASUREMENT_POINT_RECORDS - len(points)),
            "audit_run_limit": MAX_AUDIT_RUNS_PER_ASSESSMENT,
            "audit_run_used": len(run_statuses),
            "audit_run_available": max(
                0, MAX_AUDIT_RUNS_PER_ASSESSMENT - len(run_statuses)
            ),
            "assignments_per_run_limit": MAX_MEASUREMENT_POINTS_PER_RUN,
            "in_progress_audit_run_limit": 1,
            "in_progress_audit_run_used": active_runs,
            "in_progress_audit_run_available": max(0, 1 - active_runs),
        }

    def start_audit_run(
        self, assessment_id: str, expected_assessment_revision: int,
        audit_run_id: str, expected_audit_run_revision: int,
    ) -> Dict[str, Any]:
        return _V11LifecycleMixin.start_audit_run(
            self, assessment_id, expected_assessment_revision,
            audit_run_id, expected_audit_run_revision,
        )

    def cancel_audit_run(
        self, assessment_id: str, expected_assessment_revision: int,
        audit_run_id: str, expected_audit_run_revision: int,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        return _V11LifecycleMixin.cancel_audit_run(
            self, assessment_id, expected_assessment_revision,
            audit_run_id, expected_audit_run_revision, reason,
        )

    def complete_audit_run(
        self, assessment_id: str, expected_assessment_revision: int,
        audit_run_id: str, expected_audit_run_revision: int,
    ) -> Dict[str, Any]:
        return _V11LifecycleMixin.complete_audit_run(
            self, assessment_id, expected_assessment_revision,
            audit_run_id, expected_audit_run_revision,
        )

    def save_audit_measurement_comparison(
        self, assessment_id: str, expected_assessment_revision: int,
        audit_run_id: str, expected_audit_run_revision: int,
        measurement_id: str, expected_measurement_revision: int,
        analysis: Optional[Dict[str, Any]] = None,
        failure: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return _LegacyRepeatableAuditStore.save_audit_measurement_comparison(
            self, assessment_id, expected_assessment_revision,
            audit_run_id, expected_audit_run_revision,
            measurement_id, expected_measurement_revision,
            analysis=analysis, failure=failure,
        )

    def retry_audit_measurement(
        self, assessment_id: str, expected_assessment_revision: int,
        audit_run_id: str, expected_audit_run_revision: int,
        measurement_id: str, expected_measurement_revision: int,
    ) -> Dict[str, Any]:
        return _LegacyRepeatableAuditStore.retry_audit_measurement(
            self, assessment_id, expected_assessment_revision,
            audit_run_id, expected_audit_run_revision,
            measurement_id, expected_measurement_revision,
        )

    def resolve_audit_measurement(
        self, assessment_id: str, expected_assessment_revision: int,
        audit_run_id: str, expected_audit_run_revision: int,
        measurement_id: str, expected_measurement_revision: int,
        snapshot: Optional[Dict[str, Any]] = None,
        failure: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        _validate_revision(expected_assessment_revision)
        _validate_revision(expected_audit_run_revision)
        _validate_revision(expected_measurement_revision)
        if (snapshot is None) == (failure is None):
            raise BackendError(
                "invalid_audit_run_measurement",
                "provide exactly one of snapshot or failure",
            )
        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_assessment_revision)
            run = self._ensure_run_split_unlocked(assessment_id, audit_run_id)
            if run["status"] in {"completed", "cancelled"}:
                raise BackendError("audit_run_sealed", "audit run is sealed")
            if run["status"] != "in_progress":
                raise BackendError("invalid_state_transition", "run must be in progress")
            if run["revision"] != expected_audit_run_revision:
                raise BackendError("revision_conflict", "audit run revision has changed")
            current = self._find_measurement_unlocked(run, measurement_id)
            if current["revision"] != expected_measurement_revision:
                raise BackendError("revision_conflict", "measurement revision has changed")
            if current["status"] != "pending":
                raise BackendError("invalid_state_transition", "measurement must be pending")
            if current.get("provenance_status") != "pinned":
                raise BackendError("pinned_reference_missing", "measurement provenance is incomplete")
            updated = dict(current)
            documents = {}
            if failure is not None:
                if not isinstance(failure, dict):
                    raise BackendError("invalid_audit_run_measurement", "failure must be an object")
                failed_at = _validate_rfc3339(
                    failure.get("failed_at"),
                    "failed_at",
                    "invalid_audit_run_measurement",
                )
                if _rfc3339_order_key(failed_at) < _rfc3339_order_key(
                    current["created_at"]
                ):
                    raise BackendError(
                        "invalid_audit_run_measurement",
                        "failed_at precedes measurement creation",
                    )
                updated.update(
                    status="failed",
                    failed_stage="resolution",
                    retry_target="pending",
                    error_code=_clean_action_text(failure.get("error_code"), "error_code", 128, True, "invalid_audit_run_measurement"),
                    error_message=_clean_action_text(failure.get("error_message"), "error_message", 512, True, "invalid_audit_run_measurement"),
                    failed_at=failed_at,
                )
                event_type = "audit_measurement_failed"
                event_data = {"measurement_id": measurement_id, "failed_stage": "resolution", "error_code": updated["error_code"]}
            else:
                if not isinstance(snapshot, dict):
                    raise BackendError("invalid_audit_run_measurement", "snapshot bundle must be an object")
                document = snapshot.get("document")
                try:
                    normalized = _validate_snapshot(document)
                except BackendError as error:
                    raise BackendError("invalid_audit_run_measurement", "normalized snapshot is invalid") from error
                context = normalized.get("scan_metadata", {}).get("measurement_context", {})
                for field in ("measurement_profile_id", "measurement_profile_version_id", "measurement_profile_digest"):
                    if context.get(field) != current.get(field):
                        raise BackendError("pinned_reference_mismatch", "snapshot profile pin differs")
                comparability = snapshot.get("comparability_status")
                if comparability not in {"comparable", "partially_comparable", "not_comparable"}:
                    raise BackendError("invalid_audit_run_measurement", "comparability status is invalid")
                resolved_at = _validate_rfc3339(snapshot.get("resolved_at"), "resolved_at", "invalid_audit_run_measurement")
                if _rfc3339_order_key(resolved_at) < _rfc3339_order_key(
                    current["created_at"]
                ):
                    raise BackendError(
                        "invalid_audit_run_measurement",
                        "resolved_at precedes measurement creation",
                    )
                path = self._snapshot_path(assessment_id, normalized["snapshot_id"])
                snapshot_is_new = self._snapshot_immutable_preflight(
                    path, normalized, "immutable_artifact_conflict"
                )
                if snapshot_is_new and self._get_assessment_capacity_unlocked(assessment_id)["snapshot_available"] < 1:
                    raise BackendError("capacity_exceeded", "snapshot capacity is exhausted")
                updated.update(
                    status="resolved",
                    snapshot_id=normalized["snapshot_id"],
                    snapshot_digest=normalized["snapshot_digest"],
                    snapshot_record_digest=_snapshot_record_digest(normalized),
                    comparability_status=comparability,
                    resolved_at=resolved_at,
                )
                if snapshot.get("source_recon_id") is not None:
                    updated["source_recon_id"] = _clean_action_text(snapshot["source_recon_id"], "source_recon_id", 128, True, "invalid_audit_run_measurement")
                if snapshot_is_new:
                    documents[
                        "snapshots/{0}.json".format(normalized["snapshot_id"])
                    ] = normalized
                event_type = "audit_measurement_resolved"
                event_data = {"measurement_id": measurement_id, "snapshot_id": normalized["snapshot_id"]}
            updated["revision"] += 1
            manifest = self._public_manifest(run)
            manifest["revision"] += 1
            self._measurement_mutation_transaction(
                assessment_id, metadata, manifest, updated,
                event_type, event_data, documents,
            )
            updated_measurements = [
                updated if item["measurement_id"] == measurement_id else item
                for item in run["measurements"]
            ]
            return {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "assessment_revision": metadata["revision"],
                "audit_run": manifest,
                "measurement": self._public_measurement(updated),
                "workflow": self._workflow(dict(manifest, measurements=updated_measurements)),
                "assessment_capacity": self._get_assessment_capacity_unlocked(assessment_id),
            }


class _V11LifecycleMixin(_LegacyRepeatableAuditStore):
    """Public v0.7 store with split, per-measurement mutations."""

    def _get_assessment_capacity_unlocked(self, assessment_id: str) -> Dict[str, Any]:
        capacity = _LegacyRepeatableAuditStore._get_assessment_capacity_unlocked(
            self, assessment_id
        )
        points = self._read_measurement_points_doc(assessment_id)["measurement_points"]
        runs = self._list_audit_runs_unlocked(assessment_id)
        active_points = sum(1 for item in points if item["status"] == "active")
        active_runs = sum(1 for item in runs if item["status"] == "in_progress")
        capacity.update(
            {
                "measurement_point_active_limit": MAX_ACTIVE_MEASUREMENT_POINTS,
                "measurement_point_active_used": active_points,
                "measurement_point_active_available": max(0, MAX_ACTIVE_MEASUREMENT_POINTS - active_points),
                "measurement_point_total_limit": MAX_TOTAL_MEASUREMENT_POINT_RECORDS,
                "measurement_point_total_used": len(points),
                "measurement_point_total_available": max(0, MAX_TOTAL_MEASUREMENT_POINT_RECORDS - len(points)),
                "audit_run_limit": MAX_AUDIT_RUNS_PER_ASSESSMENT,
                "audit_run_used": len(runs),
                "audit_run_available": max(0, MAX_AUDIT_RUNS_PER_ASSESSMENT - len(runs)),
                "assignments_per_run_limit": MAX_MEASUREMENT_POINTS_PER_RUN,
                "in_progress_audit_run_limit": 1,
                "in_progress_audit_run_used": active_runs,
                "in_progress_audit_run_available": max(0, 1 - active_runs),
            }
        )
        return capacity

    def start_audit_run(
        self, assessment_id: str, expected_assessment_revision: int,
        audit_run_id: str, expected_audit_run_revision: int,
    ) -> Dict[str, Any]:
        _validate_revision(expected_assessment_revision)
        _validate_revision(expected_audit_run_revision)
        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_assessment_revision)
            run = self._ensure_run_split_unlocked(assessment_id, audit_run_id)
            if run["status"] in {"completed", "cancelled"}:
                raise BackendError("audit_run_sealed", "audit run is sealed")
            if run["status"] != "draft":
                raise BackendError("invalid_state_transition", "only a draft run can be started")
            if run["revision"] != expected_audit_run_revision:
                raise BackendError("revision_conflict", "audit run revision has changed")
            run_headers = self._authoritative_audit_run_headers_unlocked(
                assessment_id
            )
            if any(
                header["status"] == "in_progress"
                and existing_id != audit_run_id
                for existing_id, header in run_headers.items()
            ):
                raise BackendError("active_audit_run_exists", "another audit run is in progress")
            if not self._pins_still_valid_unlocked(assessment_id, run):
                raise BackendError("pinned_reference_mismatch", "audit run provenance is invalid")
            manifest = self._public_manifest(run)
            manifest.update(
                status="in_progress",
                started_at=_timestamp_not_before(run["created_at"]),
                revision=run["revision"] + 1,
            )
            self._write_manifest_event_unlocked(
                assessment_id, metadata, manifest, "audit_run_started",
                {"audit_run_id": audit_run_id},
            )
            updated = dict(manifest, measurements=run["measurements"])
            return {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "assessment_revision": metadata["revision"],
                "audit_run": manifest,
                "measurements": [self._public_measurement(item) for item in run["measurements"]],
                "ready_to_start": False,
                "workflow": self._workflow(updated),
                "assessment_capacity": self._get_assessment_capacity_unlocked(assessment_id),
            }

    def cancel_audit_run(
        self, assessment_id: str, expected_assessment_revision: int,
        audit_run_id: str, expected_audit_run_revision: int,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        _validate_revision(expected_assessment_revision)
        _validate_revision(expected_audit_run_revision)
        clean_reason = (
            _clean_action_text(reason, "reason", 512, False, "invalid_audit_run")
            if reason is not None else None
        )
        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_assessment_revision)
            run = self._ensure_run_split_unlocked(assessment_id, audit_run_id)
            if run["status"] in {"completed", "cancelled"}:
                raise BackendError("audit_run_sealed", "audit run is already sealed")
            if run["revision"] != expected_audit_run_revision:
                raise BackendError("revision_conflict", "audit run revision has changed")
            manifest = self._public_manifest(run)
            manifest.update(
                status="cancelled",
                completed_at=_timestamp_not_before(*_audit_run_terminal_times(run)),
                revision=run["revision"] + 1,
            )
            data = {"audit_run_id": audit_run_id}
            if clean_reason:
                data["reason"] = clean_reason
            self._write_manifest_event_unlocked(
                assessment_id, metadata, manifest, "audit_run_cancelled", data
            )
            updated = dict(manifest, measurements=run["measurements"])
            return {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "assessment_revision": metadata["revision"],
                "audit_run": manifest,
                "measurements": [self._public_measurement(item) for item in run["measurements"]],
                "ready_to_start": False,
                "workflow": self._workflow(updated),
                "assessment_capacity": self._get_assessment_capacity_unlocked(assessment_id),
            }

    def complete_audit_run(
        self, assessment_id: str, expected_assessment_revision: int,
        audit_run_id: str, expected_audit_run_revision: int,
    ) -> Dict[str, Any]:
        _validate_revision(expected_assessment_revision)
        _validate_revision(expected_audit_run_revision)
        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_assessment_revision)
            run = self._ensure_run_split_unlocked(assessment_id, audit_run_id)
            if run["status"] in {"completed", "cancelled"}:
                raise BackendError("audit_run_sealed", "audit run is already sealed")
            if run["status"] != "in_progress":
                raise BackendError("invalid_state_transition", "run must be in progress")
            if run["revision"] != expected_audit_run_revision:
                raise BackendError("revision_conflict", "audit run revision has changed")
            if any(item["status"] != "completed" for item in run["measurements"]):
                raise BackendError("invalid_state_transition", "all measurements must be completed")
            manifest = self._public_manifest(run)
            manifest.update(
                status="completed",
                completed_at=_timestamp_not_before(*_audit_run_terminal_times(run)),
                revision=run["revision"] + 1,
            )
            self._write_manifest_event_unlocked(
                assessment_id, metadata, manifest, "audit_run_completed",
                {"audit_run_id": audit_run_id},
            )
            updated = dict(manifest, measurements=run["measurements"])
            return {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "assessment_revision": metadata["revision"],
                "audit_run": manifest,
                "measurements": [self._public_measurement(item) for item in run["measurements"]],
                "ready_to_start": False,
                "workflow": self._workflow(updated),
                "assessment_capacity": self._get_assessment_capacity_unlocked(assessment_id),
            }


class RepeatableAuditStore(_V11PublicMethods, _V11LifecycleMixin):
    """v0.7 split-document Repeatable Field Audit store.

    The v0.6 assessment, baseline, profile, comparison and finding documents
    remain untouched.  AuditRun manifests and measurements are deliberately
    stored separately so a measurement transition never rewrites sibling
    measurements.  Flat AuditRun documents produced by the unreleased v0.7
    draft are adapted on reads and journal-migrated before their first write.
    """

    RUN_MANIFEST_SCHEMA_VERSION = "1.1"
    MEASUREMENT_SCHEMA_VERSION = "1.1"
    MIGRATION_SCHEMA_VERSION = "1.0"

    _RUN_MANIFEST_FIELDS = {
        "schema_version",
        "audit_run_id",
        "assessment_id",
        "name",
        "description",
        "status",
        "created_at",
        "started_at",
        "completed_at",
        "due_at",
        "pinned_assurance_profile_version_id",
        "pinned_assurance_profile_digest",
        "measurement_ids",
        "revision",
    }
    _POINT_FIELDS = {
        "measurement_point_id",
        "assessment_id",
        "location_label",
        "physical_notes",
        "operator_instructions",
        "status",
        "created_at",
        "archived_at",
        "revision",
    }
    _MEASUREMENT_PIN_FIELDS = {
        "measurement_point_revision",
        "measurement_point_digest",
        "measurement_profile_id",
        "measurement_profile_version_id",
        "measurement_profile_digest",
        "baseline_version_id",
        "baseline_type",
        "baseline_digest",
        "baseline_record_digest",
        "assurance_profile_version_id",
        "assurance_profile_digest",
    }

    @staticmethod
    def _v11_bytes(value: Any, error_code: str, label: str) -> bytes:
        _ensure_no_raw_recon(value)
        try:
            payload = (
                json.dumps(
                    value, ensure_ascii=False, indent=2, sort_keys=True
                ).encode("utf-8")
                + b"\n"
            )
        except (TypeError, ValueError) as error:
            raise BackendError(error_code, "{0} is not valid JSON".format(label)) from error
        if len(payload) > MAX_AUDIT_RUN_DOCUMENT_BYTES:
            raise BackendError(
                "storage_limit_exceeded",
                "{0} exceeds the safe document limit".format(label),
            )
        return payload

    def read_audit_run_events(
        self,
        assessment_id: str,
        audit_run_id: str,
        measurement_ids: List[str],
        max_total_bytes: int,
    ):
        """Read relevant AuditRun events once inside a consistent session."""
        if (
            not isinstance(audit_run_id, str)
            or not AUDIT_RUN_ID_PATTERN.match(audit_run_id)
            or not isinstance(measurement_ids, list)
            or len(measurement_ids) > MAX_MEASUREMENT_POINTS_PER_RUN
            or len(measurement_ids) != len(set(measurement_ids))
            or any(
                not isinstance(item, str)
                or not AUDIT_MEASUREMENT_ID_PATTERN.match(item)
                for item in measurement_ids
            )
        ):
            raise BackendError(
                "invalid_audit_run_report",
                "AuditRun event references are invalid",
            )
        if (
            not isinstance(max_total_bytes, int)
            or isinstance(max_total_bytes, bool)
            or max_total_bytes < 0
            or max_total_bytes > MAX_AUDIT_RUN_DOCUMENT_BYTES
        ):
            raise BackendError(
                "invalid_audit_run_report",
                "AuditRun event budget is invalid",
            )
        selected = []
        selected_bytes = 0
        measurement_id_set = set(measurement_ids)
        with self._read_session(assessment_id):
            session = getattr(
                self._assessment_read_state, "sessions", {}
            ).get(assessment_id)
            if session is None:
                raise BackendError(
                    "storage_error",
                    "consistent assessment read session is unavailable",
                )
            for event in session["events"]:
                data = event.get("data", {})
                if not isinstance(data, dict) or not (
                    data.get("audit_run_id") == audit_run_id
                    or data.get("measurement_id") in measurement_id_set
                ):
                    continue
                try:
                    event_bytes = len(
                        json.dumps(
                            event,
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode("utf-8")
                    )
                except (TypeError, ValueError) as error:
                    raise BackendError(
                        "invalid_audit_run_report",
                        "AuditRun event is not valid JSON",
                    ) from error
                if selected_bytes + event_bytes > max_total_bytes:
                    raise BackendError(
                        "audit_report_too_large",
                        "AuditRun event facts exceed the safe report limit",
                    )
                selected.append(event)
                selected_bytes += event_bytes
        return selected, selected_bytes

    def _run_directory(self, assessment_id: str, audit_run_id: str) -> Path:
        if (
            not isinstance(audit_run_id, str)
            or not AUDIT_RUN_ID_PATTERN.match(audit_run_id)
        ):
            raise BackendError("invalid_audit_run", "audit_run_id format is invalid")
        return self._ensure_assessment_directories(assessment_id) / "audit_runs" / audit_run_id

    def _measurement_path(
        self, assessment_id: str, audit_run_id: str, measurement_id: str
    ) -> Path:
        if (
            not isinstance(measurement_id, str)
            or not AUDIT_MEASUREMENT_ID_PATTERN.match(measurement_id)
        ):
            raise BackendError(
                "invalid_audit_run_measurement", "measurement_id format is invalid"
            )
        return self._run_directory(assessment_id, audit_run_id) / "measurements" / (measurement_id + ".json")

    def _validate_v11_point(
        self, value: Any, assessment_id: str
    ) -> Dict[str, Any]:
        point = _json_clone(value, "invalid_measurement_point", "measurement point")
        if not isinstance(point, dict):
            raise BackendError("invalid_measurement_point", "measurement point must be an object")

        # Read compatibility for the pre-v0.7 physical/context hybrid.  The
        # technical expected_measurement_context is intentionally discarded.
        if "location_label" not in point and "name" in point:
            point = {
                "measurement_point_id": point.get("measurement_point_id"),
                "assessment_id": point.get("assessment_id"),
                "location_label": point.get("name"),
                "physical_notes": point.get("description"),
                "operator_instructions": None,
                "status": point.get("status"),
                "created_at": point.get("created_at"),
                "archived_at": point.get("archived_at"),
                "revision": point.get("revision"),
            }
        if set(point) != self._POINT_FIELDS:
            raise BackendError("invalid_measurement_point", "measurement point fields are invalid")
        if (
            point.get("assessment_id") != assessment_id
            or not isinstance(point.get("measurement_point_id"), str)
            or not MEASUREMENT_POINT_ID_PATTERN.match(point["measurement_point_id"])
        ):
            raise BackendError("invalid_measurement_point", "measurement point identity is invalid")
        for field, maximum, required in (
            ("location_label", 128, True),
            ("physical_notes", 1024, False),
            ("operator_instructions", 1024, False),
        ):
            value = point.get(field)
            if required and (not isinstance(value, str) or not value):
                raise BackendError("invalid_measurement_point", "{0} is required".format(field))
            if value is not None and (
                not isinstance(value, str)
                or len(value) > maximum
                or any(ord(character) < 32 for character in value)
            ):
                raise BackendError("invalid_measurement_point", "{0} is invalid".format(field))
        if point.get("status") not in {"active", "archived"}:
            raise BackendError("invalid_measurement_point", "measurement point status is invalid")
        _validate_rfc3339(point.get("created_at"), "created_at", "invalid_measurement_point")
        if point["status"] == "active":
            if point.get("archived_at") is not None:
                raise BackendError("invalid_measurement_point", "active point cannot have archived_at")
        else:
            _validate_rfc3339(point.get("archived_at"), "archived_at", "invalid_measurement_point")
        if (
            not isinstance(point.get("revision"), int)
            or isinstance(point.get("revision"), bool)
            or point["revision"] < 1
        ):
            raise BackendError("invalid_measurement_point", "measurement point revision is invalid")
        return point

    def _validate_v11_manifest(
        self, value: Any, assessment_id: str, audit_run_id: str
    ) -> Dict[str, Any]:
        manifest = _json_clone(value, "invalid_audit_run", "audit run manifest")
        if not isinstance(manifest, dict) or set(manifest) != self._RUN_MANIFEST_FIELDS:
            raise BackendError("invalid_audit_run", "audit run manifest fields are invalid")
        if (
            manifest.get("schema_version") != self.RUN_MANIFEST_SCHEMA_VERSION
            or manifest.get("assessment_id") != assessment_id
            or manifest.get("audit_run_id") != audit_run_id
        ):
            raise BackendError("invalid_audit_run", "audit run manifest identity is invalid")
        for field, maximum, required in (
            ("name", 128, True),
            ("description", 512, False),
        ):
            item = manifest.get(field)
            if required and (not isinstance(item, str) or not item):
                raise BackendError("invalid_audit_run", "{0} is required".format(field))
            if item is not None and (
                not isinstance(item, str)
                or len(item) > maximum
                or any(ord(character) < 32 for character in item)
            ):
                raise BackendError("invalid_audit_run", "{0} is invalid".format(field))
        status = manifest.get("status")
        if status not in AUDIT_RUN_STATUSES:
            raise BackendError("invalid_audit_run", "audit run status is invalid")
        _validate_rfc3339(manifest.get("created_at"), "created_at", "invalid_audit_run")
        for field in ("started_at", "completed_at", "due_at"):
            if manifest.get(field) is not None:
                _validate_rfc3339(manifest[field], field, "invalid_audit_run")
        created_time = _rfc3339_order_key(manifest["created_at"])
        started_time = (
            _rfc3339_order_key(manifest["started_at"])
            if manifest.get("started_at") is not None
            else None
        )
        completed_time = (
            _rfc3339_order_key(manifest["completed_at"])
            if manifest.get("completed_at") is not None
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
        if status == "draft" and (
            manifest.get("started_at") is not None
            or manifest.get("completed_at") is not None
        ):
            raise BackendError("invalid_audit_run", "draft timestamps conflict")
        if status == "in_progress" and (
            manifest.get("started_at") is None
            or manifest.get("completed_at") is not None
        ):
            raise BackendError("invalid_audit_run", "in-progress timestamps conflict")
        if status == "completed" and (
            manifest.get("started_at") is None
            or manifest.get("completed_at") is None
        ):
            raise BackendError("invalid_audit_run", "completed timestamps are incomplete")
        if status == "cancelled" and manifest.get("completed_at") is None:
            raise BackendError("invalid_audit_run", "cancelled run requires completed_at")
        version_id = manifest.get("pinned_assurance_profile_version_id")
        digest = manifest.get("pinned_assurance_profile_digest")
        if (
            not isinstance(version_id, str)
            or not ASSURANCE_VERSION_ID_PATTERN.match(version_id)
            or not isinstance(digest, str)
            or not SHA256_DIGEST_PATTERN.match(digest)
        ):
            raise BackendError("invalid_audit_run", "assurance profile pin is invalid")
        measurement_ids = manifest.get("measurement_ids")
        if (
            not isinstance(measurement_ids, list)
            or not (1 <= len(measurement_ids) <= MAX_MEASUREMENT_POINTS_PER_RUN)
            or len(measurement_ids) != len(set(measurement_ids))
            or any(
                not isinstance(item, str)
                or not AUDIT_MEASUREMENT_ID_PATTERN.match(item)
                for item in measurement_ids
            )
        ):
            raise BackendError("invalid_audit_run", "measurement_ids are invalid")
        if (
            not isinstance(manifest.get("revision"), int)
            or isinstance(manifest.get("revision"), bool)
            or manifest["revision"] < 1
        ):
            raise BackendError("invalid_audit_run", "audit run revision is invalid")
        return manifest

    def _validate_v11_measurement(
        self, value: Any, assessment_id: str, audit_run_id: str
    ) -> Dict[str, Any]:
        measurement = _json_clone(
            value, "invalid_audit_run_measurement", "audit measurement"
        )
        base_fields = {
            "schema_version",
            "measurement_id",
            "audit_run_id",
            "measurement_point_id",
            "status",
            "created_at",
            "revision",
            "provenance_status",
        }
        pin_fields = set(self._MEASUREMENT_PIN_FIELDS) | {
            "measurement_point_snapshot",
            "baseline_model_id",
            "baseline_model_digest",
            "baseline_snapshot_id",
            "baseline_snapshot_digest",
        }
        resolved_fields = {
            "snapshot_id",
            "snapshot_digest",
            "snapshot_record_digest",
            "comparability_status",
            "source_recon_id",
            "resolved_at",
        }
        completed_fields = {
            "comparison_id",
            "comparison_digest",
            "occurrence_set_id",
            "evidence_ids",
            "completed_at",
        }
        failure_fields = {
            "failed_stage",
            "retry_target",
            "error_code",
            "error_message",
            "failed_at",
        }
        if not isinstance(measurement, dict) or not base_fields.issubset(measurement):
            raise BackendError("invalid_audit_run_measurement", "measurement fields are invalid")
        _ensure_no_raw_recon(measurement)
        if (
            measurement.get("schema_version") != self.MEASUREMENT_SCHEMA_VERSION
            or measurement.get("audit_run_id") != audit_run_id
            or not isinstance(measurement.get("measurement_id"), str)
            or not AUDIT_MEASUREMENT_ID_PATTERN.match(measurement["measurement_id"])
            or not isinstance(measurement.get("measurement_point_id"), str)
            or not MEASUREMENT_POINT_ID_PATTERN.match(measurement["measurement_point_id"])
        ):
            raise BackendError("invalid_audit_run_measurement", "measurement identity is invalid")
        if measurement.get("status") not in {"pending", "resolved", "completed", "failed"}:
            raise BackendError("invalid_audit_run_measurement", "measurement status is invalid")
        if measurement.get("provenance_status") not in {"pinned", "legacy_unpinned"}:
            raise BackendError("invalid_audit_run_measurement", "provenance status is invalid")
        _validate_rfc3339(
            measurement.get("created_at"),
            "created_at",
            "invalid_audit_run_measurement",
        )
        if (
            not isinstance(measurement.get("revision"), int)
            or isinstance(measurement.get("revision"), bool)
            or measurement["revision"] < 1
        ):
            raise BackendError("invalid_audit_run_measurement", "measurement revision is invalid")

        status = measurement["status"]
        stage = measurement.get("failed_stage")
        required_fields = set(base_fields)
        allowed_fields = set(base_fields) | pin_fields
        if measurement["provenance_status"] == "pinned":
            required_fields |= self._MEASUREMENT_PIN_FIELDS | {
                "measurement_point_snapshot"
            }
        resolved_required = resolved_fields - {
            "source_recon_id",
            "snapshot_record_digest",
        }
        if status == "resolved":
            required_fields |= resolved_required
            allowed_fields |= resolved_fields
        elif status == "completed":
            required_fields |= (
                resolved_required - {"resolved_at"}
            ) | completed_fields
            allowed_fields |= (
                resolved_fields - {"resolved_at"}
            ) | completed_fields
        elif status == "failed":
            required_fields |= failure_fields
            allowed_fields |= failure_fields
            if stage == "comparison":
                required_fields |= resolved_required
                allowed_fields |= resolved_fields
        if measurement["provenance_status"] == "pinned" and (
            status in {"resolved", "completed"}
            or (status == "failed" and stage == "comparison")
        ):
            required_fields.add("snapshot_record_digest")
        if not required_fields.issubset(measurement) or set(measurement) - allowed_fields:
            raise BackendError(
                "invalid_audit_run_measurement",
                "measurement fields do not match its lifecycle state",
            )

        if measurement["provenance_status"] == "pinned":
            point_snapshot = measurement.get("measurement_point_snapshot")
            try:
                validated_point = self._validate_v11_point(
                    point_snapshot, assessment_id
                )
            except BackendError as error:
                raise BackendError(
                    "pinned_reference_mismatch",
                    "measurement point snapshot is invalid",
                ) from error
            if (
                validated_point != point_snapshot
                or point_snapshot.get("measurement_point_id")
                != measurement.get("measurement_point_id")
                or _canonical_digest(point_snapshot)
                != measurement.get("measurement_point_digest")
            ):
                raise BackendError(
                    "pinned_reference_mismatch",
                    "measurement point snapshot does not match its digest",
                )
            if point_snapshot.get("revision") != measurement.get(
                "measurement_point_revision"
            ):
                raise BackendError(
                    "pinned_reference_mismatch",
                    "measurement point revision does not match its snapshot",
                )
            for field in (
                "measurement_point_digest",
                "measurement_profile_digest",
                "baseline_digest",
                "baseline_record_digest",
                "assurance_profile_digest",
            ):
                if not isinstance(measurement.get(field), str) or not SHA256_DIGEST_PATTERN.match(measurement[field]):
                    raise BackendError("pinned_reference_mismatch", "{0} is invalid".format(field))
            for field, pattern in (
                ("measurement_profile_id", MEASUREMENT_PROFILE_ID_PATTERN),
                (
                    "measurement_profile_version_id",
                    MEASUREMENT_PROFILE_VERSION_ID_PATTERN,
                ),
                ("baseline_version_id", BASELINE_VERSION_ID_PATTERN),
                ("assurance_profile_version_id", ASSURANCE_VERSION_ID_PATTERN),
            ):
                if (
                    not isinstance(measurement.get(field), str)
                    or not pattern.match(measurement[field])
                ):
                    raise BackendError(
                        "pinned_reference_mismatch",
                        "{0} is invalid".format(field),
                    )
            if (
                not isinstance(measurement.get("measurement_point_revision"), int)
                or isinstance(measurement.get("measurement_point_revision"), bool)
                or measurement["measurement_point_revision"] < 1
            ):
                raise BackendError("pinned_reference_mismatch", "measurement point revision is invalid")
            baseline_type = measurement.get("baseline_type")
            if baseline_type == "consensus":
                expected_variant = {"baseline_model_id", "baseline_model_digest"}
                forbidden_variant = {
                    "baseline_snapshot_id",
                    "baseline_snapshot_digest",
                }
                if (
                    not expected_variant.issubset(measurement)
                    or set(measurement) & forbidden_variant
                    or not isinstance(measurement.get("baseline_model_id"), str)
                    or not BASELINE_MODEL_ID_PATTERN.match(
                        measurement["baseline_model_id"]
                    )
                    or not isinstance(
                        measurement.get("baseline_model_digest"), str
                    )
                    or not SHA256_DIGEST_PATTERN.match(
                        measurement["baseline_model_digest"]
                    )
                ):
                    raise BackendError(
                        "pinned_reference_mismatch",
                        "consensus baseline pin is invalid",
                    )
            elif baseline_type == "single_scan":
                expected_variant = {
                    "baseline_snapshot_id",
                    "baseline_snapshot_digest",
                }
                forbidden_variant = {"baseline_model_id", "baseline_model_digest"}
                if (
                    not expected_variant.issubset(measurement)
                    or set(measurement) & forbidden_variant
                    or not isinstance(
                        measurement.get("baseline_snapshot_id"), str
                    )
                    or not SNAPSHOT_ID_PATTERN.match(
                        measurement["baseline_snapshot_id"]
                    )
                    or not isinstance(
                        measurement.get("baseline_snapshot_digest"), str
                    )
                    or not SHA256_DIGEST_PATTERN.match(
                        measurement["baseline_snapshot_digest"]
                    )
                ):
                    raise BackendError(
                        "pinned_reference_mismatch",
                        "single-scan baseline pin is invalid",
                    )
            else:
                raise BackendError(
                    "pinned_reference_mismatch", "baseline_type is invalid"
                )

        if status in {"resolved", "completed"} or (
            status == "failed" and stage == "comparison"
        ):
            if (
                not isinstance(measurement.get("snapshot_id"), str)
                or not SNAPSHOT_ID_PATTERN.match(measurement["snapshot_id"])
            ):
                raise BackendError(
                    "invalid_audit_run_measurement", "snapshot_id is invalid"
                )
            for field in ("snapshot_digest", "snapshot_record_digest"):
                if field not in measurement and measurement[
                    "provenance_status"
                ] == "legacy_unpinned":
                    continue
                if (
                    not isinstance(measurement.get(field), str)
                    or not SHA256_DIGEST_PATTERN.match(measurement[field])
                ):
                    raise BackendError(
                        "invalid_audit_run_measurement",
                        "{0} is invalid".format(field),
                    )
            if measurement.get("comparability_status") not in {
                "comparable",
                "partially_comparable",
                "not_comparable",
            }:
                raise BackendError(
                    "invalid_audit_run_measurement",
                    "comparability status is invalid",
                )
            if measurement.get("source_recon_id") is not None:
                source_recon_id = measurement["source_recon_id"]
                if (
                    not isinstance(source_recon_id, str)
                    or not source_recon_id
                    or len(source_recon_id) > 128
                    or any(ord(character) < 32 for character in source_recon_id)
                ):
                    raise BackendError(
                        "invalid_audit_run_measurement",
                        "source_recon_id is invalid",
                    )
        if status == "resolved" or (
            status == "failed" and stage == "comparison"
        ):
            _validate_rfc3339(
                measurement["resolved_at"],
                "resolved_at",
                "invalid_audit_run_measurement",
            )
        elif status == "completed":
            _validate_rfc3339(
                measurement["completed_at"],
                "completed_at",
                "invalid_audit_run_measurement",
            )
            if (
                not isinstance(measurement.get("comparison_id"), str)
                or not COMPARISON_ID_PATTERN.match(measurement["comparison_id"])
                or not isinstance(measurement.get("comparison_digest"), str)
                or not SHA256_DIGEST_PATTERN.match(
                    measurement["comparison_digest"]
                )
                or not isinstance(measurement.get("occurrence_set_id"), str)
                or not OCCURRENCE_SET_ID_PATTERN.match(
                    measurement["occurrence_set_id"]
                )
            ):
                raise BackendError(
                    "invalid_audit_run_measurement",
                    "completed artifact references are invalid",
                )
            evidence_ids = measurement.get("evidence_ids")
            if (
                not isinstance(evidence_ids, list)
                or len(evidence_ids) > MAX_EVIDENCE_IDS_PER_AUDIT_MEASUREMENT
                or len(evidence_ids) != len(set(evidence_ids))
                or any(
                    not isinstance(item, str)
                    or not EVIDENCE_ID_PATTERN.match(item)
                    for item in evidence_ids
                )
            ):
                raise BackendError(
                    "invalid_audit_run_measurement", "evidence_ids are invalid"
                )
        elif status == "failed":
            if stage not in {"resolution", "comparison"}:
                raise BackendError("invalid_audit_run_measurement", "failed stage is invalid")
            expected_retry = "pending" if stage == "resolution" else "resolved"
            if measurement.get("retry_target") != expected_retry:
                raise BackendError(
                    "invalid_audit_run_measurement", "retry target is invalid"
                )
            for field, maximum in (("error_code", 128), ("error_message", 512)):
                item = measurement.get(field)
                if (
                    not isinstance(item, str)
                    or not item
                    or len(item) > maximum
                    or any(ord(character) < 32 for character in item)
                ):
                    raise BackendError(
                        "invalid_audit_run_measurement",
                        "{0} is invalid".format(field),
                    )
            _validate_rfc3339(
                measurement.get("failed_at"),
                "failed_at",
                "invalid_audit_run_measurement",
            )
        return measurement

    def _read_v11_manifest_unlocked(
        self, assessment_id: str, audit_run_id: str
    ) -> Dict[str, Any]:
        path = self._run_directory(assessment_id, audit_run_id) / "manifest.json"
        value = _read_bounded_json_file(
            self,
            path,
            MAX_AUDIT_RUN_MANIFEST_BYTES,
            "audit_run_not_found",
            "invalid_audit_run",
            "audit run manifest",
        )
        return self._validate_v11_manifest(value, assessment_id, audit_run_id)

    def _read_v11_measurement_unlocked(
        self, assessment_id: str, audit_run_id: str, measurement_id: str
    ) -> Dict[str, Any]:
        value = _read_bounded_json_file(
            self,
            self._measurement_path(assessment_id, audit_run_id, measurement_id),
            MAX_AUDIT_RUN_DOCUMENT_BYTES,
            "audit_measurement_not_found",
            "invalid_audit_run_measurement",
            "audit measurement",
        )
        measurement = self._validate_v11_measurement(value, assessment_id, audit_run_id)
        if measurement["measurement_id"] != measurement_id:
            raise BackendError("invalid_audit_run_measurement", "measurement filename and identity differ")
        return measurement

    def _validate_measurement_snapshot_reference_unlocked(
        self, assessment_id: str, measurement: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        if measurement.get("snapshot_id") is None:
            return None
        snapshot = _read_bounded_json_file(
            self,
            self._snapshot_path(assessment_id, measurement["snapshot_id"]),
            MAX_NATIVE_ARTIFACT_DOCUMENT_BYTES,
            "pinned_reference_missing",
            "pinned_reference_mismatch",
            "resolved snapshot",
        )
        try:
            normalized = _validate_snapshot(snapshot)
        except BackendError as error:
            raise BackendError(
                "pinned_reference_mismatch", "resolved snapshot is invalid"
            ) from error
        if (
            normalized["snapshot_id"] != measurement["snapshot_id"]
            or normalized["snapshot_digest"] != measurement["snapshot_digest"]
        ):
            raise BackendError(
                "pinned_reference_mismatch",
                "resolved snapshot identity differs from the measurement pin",
            )
        record_digest = measurement.get("snapshot_record_digest")
        if (
            record_digest is not None
            and _snapshot_record_digest(normalized) != record_digest
        ):
            raise BackendError(
                "pinned_reference_mismatch",
                "resolved snapshot content differs from the measurement pin",
            )
        return normalized

    def _assemble_v11_run_unlocked(
        self,
        assessment_id: str,
        audit_run_id: str,
        validate_artifacts: bool = True,
    ) -> Dict[str, Any]:
        manifest = self._read_v11_manifest_unlocked(assessment_id, audit_run_id)
        measurements = [
            self._read_v11_measurement_unlocked(assessment_id, audit_run_id, item)
            for item in manifest["measurement_ids"]
        ]
        run_created = _rfc3339_order_key(manifest["created_at"])
        run_started = (
            _rfc3339_order_key(manifest["started_at"])
            if manifest.get("started_at") is not None
            else None
        )
        run_completed = (
            _rfc3339_order_key(manifest["completed_at"])
            if manifest.get("completed_at") is not None
            else None
        )
        measurement_statuses = [item["status"] for item in measurements]
        if manifest["status"] == "draft" and any(
            status != "pending" for status in measurement_statuses
        ):
            raise BackendError(
                "invalid_audit_run",
                "draft audit runs may contain only pending measurements",
            )
        if manifest["status"] == "completed" and any(
            status != "completed" for status in measurement_statuses
        ):
            raise BackendError(
                "invalid_audit_run",
                "completed audit runs must contain only completed measurements",
            )
        for measurement in measurements:
            measurement_created = _rfc3339_order_key(
                measurement["created_at"]
            )
            if measurement_created < run_created:
                raise BackendError(
                    "invalid_audit_run_measurement",
                    "measurement created_at precedes the audit run",
                )
            if run_completed is not None and measurement_created > run_completed:
                raise BackendError(
                    "invalid_audit_run_measurement",
                    "measurement created_at follows the sealed audit run",
                )
            timestamp_field = None
            if measurement["status"] == "resolved":
                timestamp_field = "resolved_at"
            elif measurement["status"] == "completed":
                timestamp_field = "completed_at"
            elif measurement["status"] == "failed":
                timestamp_field = "failed_at"
            if timestamp_field is not None:
                measurement_time = _rfc3339_order_key(
                    measurement[timestamp_field]
                )
                lower_bound = max(
                    run_started or run_created,
                    measurement_created,
                )
                if measurement_time < lower_bound:
                    raise BackendError(
                        "invalid_audit_run_measurement",
                        "{0} precedes the audit run or measurement".format(
                            timestamp_field
                        ),
                    )
                if run_completed is not None and measurement_time > run_completed:
                    raise BackendError(
                        "invalid_audit_run_measurement",
                        "{0} follows the sealed audit run".format(
                            timestamp_field
                        ),
                    )
            if (
                measurement["status"] == "failed"
                and measurement.get("failed_stage") == "comparison"
                and _rfc3339_order_key(measurement["failed_at"])
                < _rfc3339_order_key(measurement["resolved_at"])
            ):
                raise BackendError(
                    "invalid_audit_run_measurement",
                    "failed_at precedes resolved_at for comparison failure",
                )
            if validate_artifacts:
                self._validate_measurement_snapshot_reference_unlocked(
                    assessment_id, measurement
                )
            if validate_artifacts and measurement["status"] == "completed":
                comparison = self._validate_artifact_reference(
                    assessment_id,
                    "comparison",
                    measurement["comparison_id"],
                    expected_digest=measurement["comparison_digest"],
                )
                occurrence = self._validate_artifact_reference(
                    assessment_id,
                    "occurrence",
                    measurement["occurrence_set_id"],
                    expected_digest=comparison["occurrence_digest"],
                    expected_comparison_id=measurement["comparison_id"],
                )
                self._validate_artifacts_match_resolved_measurement(
                    measurement,
                    comparison,
                    occurrence,
                    measurement["evidence_ids"],
                )
        point_ids = [item["measurement_point_id"] for item in measurements]
        if len(point_ids) != len(set(point_ids)):
            raise BackendError("invalid_audit_run", "measurement point assignments are duplicated")
        return dict(manifest, measurement_point_ids=point_ids, measurements=measurements)

    def _legacy_run_path(self, assessment_id: str, audit_run_id: str) -> Path:
        return self._ensure_assessment_directories(assessment_id) / "audit_runs" / (audit_run_id + ".json")

    def _read_legacy_run_unlocked(
        self, assessment_id: str, audit_run_id: str
    ) -> Dict[str, Any]:
        value = _read_bounded_json_file(
            self,
            self._legacy_run_path(assessment_id, audit_run_id),
            MAX_AUDIT_RUN_DOCUMENT_BYTES,
            "audit_run_not_found",
            "invalid_audit_run",
            "legacy audit run",
        )
        return _validate_private_audit_run_document(
            value,
            expected_assessment_id=assessment_id,
            expected_audit_run_id=audit_run_id,
        )

    def _adapt_legacy_measurement(
        self, measurement: Dict[str, Any], audit_run: Dict[str, Any]
    ) -> Dict[str, Any]:
        source = _canonical_measurement_identity(measurement)
        adapted = {
            "schema_version": self.MEASUREMENT_SCHEMA_VERSION,
            "measurement_id": source["measurement_id"],
            "audit_run_id": audit_run["audit_run_id"],
            "measurement_point_id": source["measurement_point_id"],
            "status": source["status"],
            "created_at": source.get("created_at", audit_run["created_at"]),
            "revision": 1,
            "provenance_status": "legacy_unpinned",
        }
        pin_fields = self._MEASUREMENT_PIN_FIELDS - {
            "measurement_point_revision",
            "measurement_point_digest",
        }
        if all(field in source for field in pin_fields):
            adapted.update({field: source[field] for field in pin_fields})
            # The old document did not freeze the full physical point, so its
            # provenance remains explicitly legacy even when technical pins exist.
        for field in (
            "baseline_model_id",
            "baseline_model_digest",
            "baseline_snapshot_id",
            "baseline_snapshot_digest",
            "snapshot_id",
            "snapshot_digest",
            "snapshot_record_digest",
            "comparability_status",
            "source_recon_id",
            "resolved_at",
            "comparison_id",
            "comparison_digest",
            "occurrence_set_id",
            "evidence_ids",
            "completed_at",
            "failed_stage",
            "retry_target",
            "error_code",
            "error_message",
            "failed_at",
        ):
            if field in source:
                adapted[field] = _json_clone(
                    source[field],
                    "invalid_audit_run_measurement",
                    field,
                )
        return self._validate_v11_measurement(
            adapted, audit_run["assessment_id"], audit_run["audit_run_id"]
        )

    def _adapt_legacy_run_unlocked(
        self, assessment_id: str, audit_run_id: str
    ) -> Dict[str, Any]:
        legacy = self._read_legacy_run_unlocked(assessment_id, audit_run_id)
        measurements = [
            self._adapt_legacy_measurement(item, legacy)
            for item in legacy["measurements"]
        ]
        manifest = {
            "schema_version": self.RUN_MANIFEST_SCHEMA_VERSION,
            "audit_run_id": audit_run_id,
            "assessment_id": assessment_id,
            "name": legacy["title"],
            "description": None,
            "status": legacy["status"],
            "created_at": legacy["created_at"],
            "started_at": legacy.get("started_at"),
            "completed_at": legacy.get("completed_at"),
            "due_at": legacy.get("due_at"),
            "pinned_assurance_profile_version_id": legacy[
                "pinned_assurance_profile_version_id"
            ],
            "pinned_assurance_profile_digest": legacy[
                "pinned_assurance_profile_digest"
            ],
            "measurement_ids": [item["measurement_id"] for item in measurements],
            "revision": legacy["revision"],
        }
        self._validate_v11_manifest(manifest, assessment_id, audit_run_id)
        return dict(
            manifest,
            measurement_point_ids=[item["measurement_point_id"] for item in measurements],
            measurements=measurements,
        )

    def _migrate_legacy_run_unlocked(
        self, assessment_id: str, audit_run_id: str
    ) -> Dict[str, Any]:
        directory = self._run_directory(assessment_id, audit_run_id)
        manifest_path = directory / "manifest.json"
        if manifest_path.exists() or manifest_path.is_symlink():
            return self._assemble_v11_run_unlocked(assessment_id, audit_run_id)
        adapted = self._adapt_legacy_run_unlocked(assessment_id, audit_run_id)
        manifest = {
            key: value
            for key, value in adapted.items()
            if key in self._RUN_MANIFEST_FIELDS
        }
        marker = {
            "schema_version": self.MIGRATION_SCHEMA_VERSION,
            "source": "flat_audit_run_v1",
            "source_digest": _canonical_digest(self._read_legacy_run_unlocked(assessment_id, audit_run_id)),
            "migrated_at": _utc_now(),
        }
        base = self._ensure_assessment_directories(assessment_id)
        transaction = PrivateTransaction(base, fault_injector=self.fault_injector)
        transaction.add_json("audit_runs/{0}/manifest.json".format(audit_run_id), manifest)
        for measurement in adapted["measurements"]:
            transaction.add_json(
                "audit_runs/{0}/measurements/{1}.json".format(
                    audit_run_id, measurement["measurement_id"]
                ),
                measurement,
            )
        transaction.add_json("audit_runs/{0}/migration.json".format(audit_run_id), marker)
        transaction.commit()
        return self._assemble_v11_run_unlocked(assessment_id, audit_run_id)

    def _audit_run_ids_unlocked(self, assessment_id: str) -> List[str]:
        runs_dir = self._ensure_assessment_directories(assessment_id) / "audit_runs"
        if runs_dir.is_symlink() or not runs_dir.is_dir():
            raise BackendError("invalid_audit_run", "audit run directory is invalid")
        identifiers = set()
        try:
            entries = list(os.scandir(str(runs_dir)))
        except OSError as error:
            raise BackendError("invalid_audit_run", "audit run directory is unreadable") from error
        if len(entries) > (MAX_AUDIT_RUNS_PER_ASSESSMENT * 2 + 2):
            raise BackendError("storage_limit_exceeded", "audit run storage contains too many entries")
        for entry in entries:
            if entry.name in {".transactions"}:
                continue
            if AUDIT_RUN_ID_PATTERN.match(entry.name) and entry.is_dir(follow_symlinks=False):
                identifiers.add(entry.name)
                continue
            match = re.match(r"^(ar_[0-9a-f]{16})\.json$", entry.name)
            if match and entry.is_file(follow_symlinks=False):
                identifiers.add(match.group(1))
                continue
            raise BackendError("invalid_audit_run", "audit run directory contains an invalid entry")
        if len(identifiers) > MAX_AUDIT_RUNS_PER_ASSESSMENT:
            raise BackendError("storage_limit_exceeded", "audit run count exceeds the limit")
        return sorted(identifiers)

    def _read_audit_run_header_unlocked(
        self, assessment_id: str, audit_run_id: str
    ) -> Dict[str, Any]:
        directory = self._run_directory(assessment_id, audit_run_id)
        manifest_path = directory / "manifest.json"
        if manifest_path.exists() or manifest_path.is_symlink():
            return self._read_v11_manifest_unlocked(
                assessment_id, audit_run_id
            )
        legacy_path = self._legacy_run_path(assessment_id, audit_run_id)
        if legacy_path.exists() or legacy_path.is_symlink():
            adapted = self._adapt_legacy_run_unlocked(
                assessment_id, audit_run_id
            )
            return self._public_manifest(adapted)
        raise BackendError("audit_run_not_found", "audit run was not found")

    def _authoritative_audit_run_headers_unlocked(
        self, assessment_id: str
    ) -> Dict[str, Dict[str, Any]]:
        headers = {}
        total_bytes = 0
        for audit_run_id in self._audit_run_ids_unlocked(assessment_id):
            header = self._read_audit_run_header_unlocked(
                assessment_id, audit_run_id
            )
            total_bytes += _canonical_json_size(
                header, "invalid_audit_run", "audit run header"
            )
            if total_bytes > MAX_AUDIT_RUN_INDEX_BYTES:
                raise BackendError(
                    "storage_limit_exceeded",
                    "audit run index exceeds the safe aggregate size limit",
                )
            headers[audit_run_id] = header
        return headers

    def _get_audit_run_unlocked(
        self,
        assessment_id: str,
        audit_run_id: str,
        validate_artifacts: bool = True,
    ) -> Dict[str, Any]:
        directory = self._run_directory(assessment_id, audit_run_id)
        if (directory / "manifest.json").exists() or (directory / "manifest.json").is_symlink():
            return self._assemble_v11_run_unlocked(
                assessment_id,
                audit_run_id,
                validate_artifacts=validate_artifacts,
            )
        legacy_path = self._legacy_run_path(assessment_id, audit_run_id)
        if legacy_path.exists() or legacy_path.is_symlink():
            return self._adapt_legacy_run_unlocked(assessment_id, audit_run_id)
        raise BackendError("audit_run_not_found", "audit run was not found")

    def _authoritative_audit_runs_unlocked(
        self, assessment_id: str, validate_artifacts: bool = True
    ) -> Dict[str, Dict[str, Any]]:
        return {
            audit_run_id: self._get_audit_run_unlocked(
                assessment_id,
                audit_run_id,
                validate_artifacts=validate_artifacts,
            )
            for audit_run_id in self._audit_run_ids_unlocked(assessment_id)
        }

    def _read_audit_runs_manifest_unlocked(
        self, assessment_id: str
    ) -> Dict[str, Any]:
        headers = self._authoritative_audit_run_headers_unlocked(assessment_id)
        statuses = {key: value["status"] for key, value in headers.items()}
        return {
            "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
            "active_closure_reserve": sum(
                1 for status in statuses.values() if status in ACTIVE_AUDIT_RUN_STATUSES
            ),
            "runs": statuses,
        }

    def _read_measurement_points_doc(self, assessment_id: str) -> Dict[str, Any]:
        base = self._ensure_assessment_directories(assessment_id)
        path = base / "measurement_points.json"
        if not path.exists() and not path.is_symlink():
            return {
                "schema_version": self.RUN_MANIFEST_SCHEMA_VERSION,
                "assessment_id": assessment_id,
                "updated_at": _utc_now(),
                "measurement_points": [],
            }
        value = _read_bounded_json_file(
            self,
            path,
            MAX_MEASUREMENT_POINTS_DOCUMENT_BYTES,
            "invalid_measurement_point",
            "invalid_measurement_point",
            "measurement points document",
        )
        if (
            not isinstance(value, dict)
            or set(value)
            != {
                "schema_version",
                "assessment_id",
                "updated_at",
                "measurement_points",
            }
            or value.get("schema_version") != self.RUN_MANIFEST_SCHEMA_VERSION
            or value.get("assessment_id") != assessment_id
            or not isinstance(value.get("measurement_points"), list)
            or len(value["measurement_points"]) > MAX_TOTAL_MEASUREMENT_POINT_RECORDS
        ):
            raise BackendError("invalid_measurement_point", "measurement points document is invalid")
        _validate_rfc3339(
            value.get("updated_at"),
            "updated_at",
            "invalid_measurement_point",
        )
        points = [self._validate_v11_point(item, assessment_id) for item in value["measurement_points"]]
        if len({item["measurement_point_id"] for item in points}) != len(points):
            raise BackendError("invalid_measurement_point", "measurement point IDs are duplicated")
        if sum(1 for item in points if item["status"] == "active") > MAX_ACTIVE_MEASUREMENT_POINTS:
            raise BackendError("invalid_measurement_point", "active measurement point count exceeds the limit")
        return {
            "schema_version": self.RUN_MANIFEST_SCHEMA_VERSION,
            "assessment_id": assessment_id,
            "updated_at": value["updated_at"],
            "measurement_points": points,
        }

    def _point_document_bytes(
        self, assessment_id: str, points: List[Dict[str, Any]]
    ) -> bytes:
        document = {
            "schema_version": self.RUN_MANIFEST_SCHEMA_VERSION,
            "assessment_id": assessment_id,
            "updated_at": _utc_now(),
            "measurement_points": points,
        }
        payload = self._v11_bytes(document, "invalid_measurement_point", "measurement points document")
        if len(payload) > MAX_MEASUREMENT_POINTS_DOCUMENT_BYTES:
            raise BackendError("storage_limit_exceeded", "measurement points document size exceeded")
        return payload

    def _list_measurement_points_unlocked(
        self, assessment_id: str, include_archived: bool = False
    ) -> List[Dict[str, Any]]:
        points = self._read_measurement_points_doc(assessment_id)["measurement_points"]
        if include_archived:
            return points
        return [item for item in points if item["status"] == "active"]

    def _get_measurement_point_unlocked(
        self, assessment_id: str, measurement_point_id: str
    ) -> Dict[str, Any]:
        if (
            not isinstance(measurement_point_id, str)
            or not MEASUREMENT_POINT_ID_PATTERN.match(measurement_point_id)
        ):
            raise BackendError("invalid_measurement_point", "measurement_point_id format is invalid")
        for point in self._read_measurement_points_doc(assessment_id)["measurement_points"]:
            if point["measurement_point_id"] == measurement_point_id:
                return point
        raise BackendError("measurement_point_not_found", "measurement point was not found")

    def create_measurement_point(
        self,
        assessment_id: str,
        expected_assessment_revision: int,
        location_label: Any,
        physical_notes: Optional[str] = None,
        operator_instructions: Optional[str] = None,
    ) -> Dict[str, Any]:
        _validate_revision(expected_assessment_revision)
        clean_label = _clean_action_text(
            location_label, "location_label", 128, True, "invalid_measurement_point"
        )
        clean_notes = (
            _clean_action_text(physical_notes, "physical_notes", 1024, False, "invalid_measurement_point")
            if physical_notes is not None
            else None
        )
        clean_instructions = (
            _clean_action_text(operator_instructions, "operator_instructions", 1024, False, "invalid_measurement_point")
            if operator_instructions is not None
            else None
        )
        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_assessment_revision)
            points = self._read_measurement_points_doc(assessment_id)["measurement_points"]
            if sum(1 for item in points if item["status"] == "active") >= MAX_ACTIVE_MEASUREMENT_POINTS:
                raise BackendError("capacity_exceeded", "active measurement point limit reached")
            if len(points) >= MAX_TOTAL_MEASUREMENT_POINT_RECORDS:
                raise BackendError("capacity_exceeded", "total measurement point limit reached")
            now = _utc_now()
            point = {
                "measurement_point_id": _generate_mp_id(),
                "assessment_id": assessment_id,
                "location_label": clean_label,
                "physical_notes": clean_notes or None,
                "operator_instructions": clean_instructions or None,
                "status": "active",
                "created_at": now,
                "archived_at": None,
                "revision": 1,
            }
            self._validate_v11_point(point, assessment_id)
            event, events_bytes = self._transaction_event(
                assessment_id,
                metadata,
                "measurement_point_created",
                {"measurement_point_id": point["measurement_point_id"]},
            )
            transaction = PrivateTransaction(
                self._ensure_assessment_directories(assessment_id),
                fault_injector=self.fault_injector,
            )
            transaction.add_bytes("measurement_points.json", self._point_document_bytes(assessment_id, points + [point]))
            transaction.add_json("assessment.json", metadata)
            transaction.add_bytes("events.jsonl", events_bytes)
            transaction.commit()
            return {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "assessment_revision": metadata["revision"],
                "measurement_point": point,
                "assessment_capacity": self._get_assessment_capacity_unlocked(
                    assessment_id
                ),
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
        normalized = dict(updates)
        allowed = {"location_label", "physical_notes", "operator_instructions"}
        if set(normalized) - allowed:
            raise BackendError("invalid_measurement_point", "updates contain unsupported fields")
        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_assessment_revision)
            document = self._read_measurement_points_doc(assessment_id)
            points = list(document["measurement_points"])
            index = next(
                (i for i, item in enumerate(points) if item["measurement_point_id"] == measurement_point_id),
                None,
            )
            if index is None:
                raise BackendError("measurement_point_not_found", "measurement point was not found")
            current = points[index]
            if current["status"] == "archived":
                raise BackendError("measurement_point_archived", "archived measurement point cannot be updated")
            if current["revision"] != expected_measurement_point_revision:
                raise BackendError("revision_conflict", "measurement point revision has changed")
            updated = dict(current)
            for field, maximum, required in (
                ("location_label", 128, True),
                ("physical_notes", 1024, False),
                ("operator_instructions", 1024, False),
            ):
                if field in normalized:
                    value = normalized[field]
                    updated[field] = (
                        _clean_action_text(value, field, maximum, required, "invalid_measurement_point")
                        if value is not None
                        else None
                    )
            updated["revision"] += 1
            self._validate_v11_point(updated, assessment_id)
            points[index] = updated
            event, events_bytes = self._transaction_event(
                assessment_id,
                metadata,
                "measurement_point_updated",
                {"measurement_point_id": measurement_point_id},
            )
            transaction = PrivateTransaction(self._ensure_assessment_directories(assessment_id), fault_injector=self.fault_injector)
            transaction.add_bytes("measurement_points.json", self._point_document_bytes(assessment_id, points))
            transaction.add_json("assessment.json", metadata)
            transaction.add_bytes("events.jsonl", events_bytes)
            transaction.commit()
            return {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "assessment_revision": metadata["revision"],
                "measurement_point": updated,
                "assessment_capacity": self._get_assessment_capacity_unlocked(
                    assessment_id
                ),
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
            points = list(self._read_measurement_points_doc(assessment_id)["measurement_points"])
            index = next(
                (i for i, item in enumerate(points) if item["measurement_point_id"] == measurement_point_id),
                None,
            )
            if index is None:
                raise BackendError("measurement_point_not_found", "measurement point was not found")
            current = points[index]
            if current["status"] == "archived":
                raise BackendError("measurement_point_archived", "measurement point is already archived")
            if current["revision"] != expected_measurement_point_revision:
                raise BackendError("revision_conflict", "measurement point revision has changed")
            updated = dict(current)
            updated["status"] = "archived"
            updated["archived_at"] = _timestamp_not_before(current["created_at"])
            updated["revision"] += 1
            points[index] = updated
            event, events_bytes = self._transaction_event(
                assessment_id,
                metadata,
                "measurement_point_archived",
                {"measurement_point_id": measurement_point_id},
            )
            transaction = PrivateTransaction(self._ensure_assessment_directories(assessment_id), fault_injector=self.fault_injector)
            transaction.add_bytes("measurement_points.json", self._point_document_bytes(assessment_id, points))
            transaction.add_json("assessment.json", metadata)
            transaction.add_bytes("events.jsonl", events_bytes)
            transaction.commit()
            return {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "assessment_revision": metadata["revision"],
                "measurement_point": updated,
                "assessment_capacity": self._get_assessment_capacity_unlocked(
                    assessment_id
                ),
            }

    def _load_assurance_pin_by_id_unlocked(
        self, assessment_id: str, version_id: str
    ) -> Dict[str, Any]:
        if not isinstance(version_id, str) or not ASSURANCE_VERSION_ID_PATTERN.match(version_id):
            raise BackendError("pinned_reference_missing", "assurance profile version is invalid")
        path = self._assurance_profile_path(assessment_id, version_id)
        record = _read_bounded_json_file(
            self,
            path,
            MAX_NATIVE_ARTIFACT_DOCUMENT_BYTES,
            "pinned_reference_missing",
            "pinned_reference_mismatch",
            "assurance profile version",
        )
        digest = record.get("digest") if isinstance(record, dict) else None
        try:
            return self._load_assurance_profile_pin_unlocked(
                assessment_id, version_id, digest, "pinned_reference_mismatch"
            )
        except BackendError as error:
            if error.code in {"pinned_reference_mismatch", "pinned_reference_missing"}:
                raise
            raise BackendError("pinned_reference_mismatch", str(error)) from error

    def _load_measurement_profile_assignment_unlocked(
        self,
        profile_id: Any,
        version_id: Any,
        require_active: bool = False,
    ) -> Dict[str, Any]:
        if (
            not isinstance(profile_id, str)
            or not MEASUREMENT_PROFILE_ID_PATTERN.match(profile_id)
            or not isinstance(version_id, str)
            or not MEASUREMENT_PROFILE_VERSION_ID_PATTERN.match(version_id)
        ):
            raise BackendError("pinned_reference_missing", "measurement profile pin is invalid")
        try:
            if require_active:
                metadata = self._profile_meta(profile_id)
                if metadata.get("status") != "active":
                    raise BackendError(
                        "pinned_reference_missing",
                        "archived measurement profiles cannot be assigned",
                    )
            record = self._profile_version(profile_id, version_id)
        except BackendError as error:
            if error.code == "pinned_reference_missing":
                raise
            raise BackendError("pinned_reference_missing", "measurement profile version is unavailable") from error
        if record.get("digest") != _canonical_digest(record.get("profile")):
            raise BackendError("pinned_reference_mismatch", "measurement profile digest is invalid")
        return record

    def _load_baseline_assignment_unlocked(
        self, assessment_id: str, baseline_version_id: Any
    ) -> Dict[str, Any]:
        if (
            not isinstance(baseline_version_id, str)
            or not BASELINE_VERSION_ID_PATTERN.match(baseline_version_id)
        ):
            raise BackendError("pinned_reference_missing", "baseline version is invalid")
        path = self._baseline_path(assessment_id, baseline_version_id)
        stored = _read_bounded_json_file(
            self,
            path,
            MAX_NATIVE_ARTIFACT_DOCUMENT_BYTES,
            "pinned_reference_missing",
            "pinned_reference_mismatch",
            "baseline version",
        )
        try:
            baseline = self._read_baseline_record(assessment_id, baseline_version_id)
        except BackendError as error:
            raise BackendError("pinned_reference_mismatch", "baseline version is invalid") from error
        result = {
            "baseline_version_id": baseline_version_id,
            "baseline_type": baseline.get("baseline_type", "single_scan"),
            "baseline_digest": baseline.get(
                "baseline_model_digest", baseline.get("snapshot_digest")
            ),
            "baseline_record_digest": _canonical_digest(stored),
        }
        context = baseline.get("measurement_context")
        if not isinstance(context, dict):
            context = baseline.get("scan_metadata", {}).get(
                "measurement_context"
            )
        if not isinstance(context, dict):
            raise BackendError(
                "pinned_reference_mismatch",
                "baseline measurement context is unavailable",
            )
        result["measurement_context"] = _json_clone(
            context,
            "pinned_reference_mismatch",
            "baseline measurement context",
        )
        for field in (
            "baseline_model_id",
            "baseline_model_digest",
            "snapshot_id",
            "snapshot_digest",
        ):
            if field in baseline:
                result[field] = baseline[field]
        return result

    def _public_manifest(self, manifest: Dict[str, Any]) -> Dict[str, Any]:
        return {
            key: _json_clone(value, "invalid_audit_run", key)
            for key, value in manifest.items()
            if key in self._RUN_MANIFEST_FIELDS
        }

    def _public_measurement(self, measurement: Dict[str, Any]) -> Dict[str, Any]:
        result = _json_clone(
            measurement, "invalid_audit_run_measurement", "measurement"
        )
        result.pop("legacy_context", None)
        return result

    @staticmethod
    def _workflow(run: Dict[str, Any]) -> Dict[str, Any]:
        measurements = run.get("measurements", [])
        current = None
        next_action = None
        for item in measurements:
            if item.get("status") == "failed":
                current = item.get("measurement_id")
                next_action = "retry_measurement"
                break
            if item.get("status") == "resolved":
                current = item.get("measurement_id")
                next_action = "save_comparison"
                break
            if item.get("status") == "pending":
                current = item.get("measurement_id")
                next_action = "resolve_measurement"
                break
        if run.get("status") == "draft":
            next_action = "start_run"
        elif run.get("status") in {"completed", "cancelled"}:
            current = None
            next_action = "generate_report"
        elif current is None:
            next_action = "complete_run"
        return {
            "current_measurement_id": current,
            "next_measurement_id": current,
            "next_action": next_action,
        }

    def _pins_still_valid_unlocked(
        self,
        assessment_id: str,
        run: Dict[str, Any],
        validation_cache: Optional[Dict[str, Dict[Any, Any]]] = None,
    ) -> bool:
        cache = validation_cache if validation_cache is not None else {}
        assurance_cache = cache.setdefault("assurance", {})
        profile_cache = cache.setdefault("measurement_profile", {})
        baseline_cache = cache.setdefault("baseline", {})
        try:
            assurance_key = (
                run["pinned_assurance_profile_version_id"],
                run["pinned_assurance_profile_digest"],
            )
            if assurance_key not in assurance_cache:
                assurance_cache[assurance_key] = (
                    self._load_assurance_profile_pin_unlocked(
                        assessment_id,
                        assurance_key[0],
                        assurance_key[1],
                        "pinned_reference_mismatch",
                    )
                )
            assurance = assurance_cache[assurance_key]
            for measurement in run["measurements"]:
                if measurement.get("provenance_status") != "pinned":
                    return False
                if (
                    measurement.get("assurance_profile_version_id")
                    != run["pinned_assurance_profile_version_id"]
                    or measurement.get("assurance_profile_digest")
                    != run["pinned_assurance_profile_digest"]
                    or assurance.get("assurance_profile_version_id")
                    != measurement.get("assurance_profile_version_id")
                    or assurance.get("digest")
                    != measurement.get("assurance_profile_digest")
                ):
                    return False
                if (
                    measurement.get("measurement_point_snapshot", {}).get("revision")
                    != measurement["measurement_point_revision"]
                    or _canonical_digest(measurement.get("measurement_point_snapshot"))
                    != measurement["measurement_point_digest"]
                ):
                    return False
                profile_key = (
                    measurement["measurement_profile_id"],
                    measurement["measurement_profile_version_id"],
                )
                if profile_key not in profile_cache:
                    profile_cache[profile_key] = (
                        self._load_measurement_profile_assignment_unlocked(
                            profile_key[0], profile_key[1]
                        )
                    )
                profile = profile_cache[profile_key]
                if profile["digest"] != measurement["measurement_profile_digest"]:
                    return False
                baseline_key = measurement["baseline_version_id"]
                if baseline_key not in baseline_cache:
                    baseline_cache[baseline_key] = (
                        self._load_baseline_assignment_unlocked(
                            assessment_id, baseline_key
                        )
                    )
                baseline = baseline_cache[baseline_key]
                if (
                    baseline["baseline_type"] != measurement["baseline_type"]
                    or baseline["baseline_digest"]
                    != measurement["baseline_digest"]
                    or baseline["baseline_record_digest"]
                    != measurement["baseline_record_digest"]
                    or baseline["measurement_context"].get(
                        "measurement_point_id"
                    )
                    != measurement["measurement_point_id"]
                ):
                    return False
                if baseline["baseline_type"] == "consensus":
                    if (
                        baseline.get("baseline_model_id")
                        != measurement.get("baseline_model_id")
                        or baseline.get("baseline_model_digest")
                        != measurement.get("baseline_model_digest")
                        or "baseline_snapshot_id" in measurement
                        or "baseline_snapshot_digest" in measurement
                    ):
                        return False
                elif (
                    baseline.get("snapshot_id")
                    != measurement.get("baseline_snapshot_id")
                    or baseline.get("snapshot_digest")
                    != measurement.get("baseline_snapshot_digest")
                    or "baseline_model_id" in measurement
                    or "baseline_model_digest" in measurement
                ):
                    return False
        except BackendError:
            return False
        return True

    def _audit_run_ready_unlocked(
        self,
        assessment_id: str,
        audit_run: Dict[str, Any],
        validation_cache: Optional[Dict[str, Dict[Any, Any]]] = None,
    ) -> bool:
        return (
            audit_run.get("status") == "draft"
            and bool(audit_run.get("measurements"))
            and self._pins_still_valid_unlocked(
                assessment_id, audit_run, validation_cache
            )
        )

    def _list_audit_runs_unlocked(
        self, assessment_id: str
    ) -> List[Dict[str, Any]]:
        return list(self._authoritative_audit_runs_unlocked(assessment_id).values())

    def list_audit_runs(
        self, assessment_id: str, limit: int = 50, offset: int = 0
    ) -> Dict[str, Any]:
        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or not 1 <= limit <= 100
            or not isinstance(offset, int)
            or isinstance(offset, bool)
            or offset < 0
        ):
            raise BackendError("invalid_page_token", "pagination is invalid")
        with self._lock(assessment_id):
            headers = sorted(
                self._authoritative_audit_run_headers_unlocked(
                    assessment_id
                ).values(),
                key=lambda item: (_rfc3339_order_key(item["created_at"]), item["audit_run_id"]),
                reverse=True,
            )
            selected_headers = headers[offset:offset + limit]
            selected = []
            selected_bytes = 0
            validation_cache: Dict[str, Dict[Any, Any]] = {}
            for header in selected_headers:
                run = self._get_audit_run_unlocked(
                    assessment_id,
                    header["audit_run_id"],
                    validate_artifacts=False,
                )
                item = {
                    "audit_run": self._public_manifest(run),
                    "ready_to_start": self._audit_run_ready_unlocked(
                        assessment_id, run, validation_cache
                    ),
                    "workflow": self._workflow(run),
                }
                selected_bytes += _canonical_json_size(
                    item, "invalid_audit_run", "audit run list item"
                )
                if selected_bytes > MAX_AUDIT_RUN_LIST_BYTES:
                    raise BackendError(
                        "storage_limit_exceeded",
                        "audit run listing exceeds the safe aggregate size limit",
                    )
                selected.append(item)
            return {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "audit_runs": selected,
                "total": len(headers),
                "limit": limit,
                "offset": offset,
                "has_more": offset + len(selected) < len(headers),
                "assessment_capacity": self._get_assessment_capacity_unlocked(assessment_id),
            }

    def get_audit_run(
        self, assessment_id: str, audit_run_id: str
    ) -> Dict[str, Any]:
        with self._lock(assessment_id):
            run = self._get_audit_run_unlocked(assessment_id, audit_run_id)
            public_run = self._public_manifest(run)
            public_measurements = [
                self._public_measurement(item) for item in run["measurements"]
            ]
            if _canonical_json_size(
                {
                    "audit_run": public_run,
                    "measurements": public_measurements,
                },
                "invalid_audit_run",
                "audit run detail",
            ) > MAX_AUDIT_RUN_DOCUMENT_BYTES:
                raise BackendError(
                    "storage_limit_exceeded",
                    "assembled audit run exceeds the safe size limit",
                )
            return {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "audit_run": public_run,
                "measurements": public_measurements,
                "ready_to_start": self._audit_run_ready_unlocked(assessment_id, run),
                "workflow": self._workflow(run),
                "assessment_capacity": self._get_assessment_capacity_unlocked(assessment_id),
            }

    def read_audit_run_report_seed(
        self, assessment_id: str, audit_run_id: str
    ) -> Dict[str, Any]:
        """Read one structurally strict run while deferring artifact bodies."""
        with self._lock(assessment_id):
            run = self._get_audit_run_unlocked(
                assessment_id,
                audit_run_id,
                validate_artifacts=False,
            )
            public_run = self._public_manifest(run)
            public_measurements = [
                self._public_measurement(item) for item in run["measurements"]
            ]
            if _canonical_json_size(
                {
                    "audit_run": public_run,
                    "measurements": public_measurements,
                },
                "invalid_audit_run_report",
                "audit run report seed",
            ) > MAX_AUDIT_RUN_DOCUMENT_BYTES:
                raise BackendError(
                    "audit_report_too_large",
                    "AuditRun report seed exceeds the safe fact limit",
                )
            return {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "audit_run": public_run,
                "measurements": public_measurements,
                "ready_to_start": False,
                "workflow": self._workflow(run),
            }

    def read_audit_run_report_artifact(
        self,
        assessment_id: str,
        artifact_type: str,
        artifact_id: str,
        remaining_bytes: int,
        expected_digest: Optional[str] = None,
        expected_comparison_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Read and validate one artifact within the remaining fact budget."""
        if (
            not isinstance(remaining_bytes, int)
            or isinstance(remaining_bytes, bool)
            or not 1 <= remaining_bytes <= MAX_AUDIT_RUN_REPORT_ARTIFACT_BYTES
        ):
            raise BackendError(
                "audit_report_too_large",
                "AuditRun report artifact budget is exhausted",
            )
        base = self._ensure_assessment_directories(assessment_id)
        if artifact_type == "snapshot":
            if (
                not isinstance(artifact_id, str)
                or not SNAPSHOT_ID_PATTERN.match(artifact_id)
            ):
                raise BackendError("invalid_snapshot", "snapshot_id is invalid")
            path = base / "snapshots" / (str(artifact_id) + ".json")
        elif artifact_type == "comparison":
            if (
                not isinstance(artifact_id, str)
                or not COMPARISON_ID_PATTERN.match(artifact_id)
            ):
                raise BackendError(
                    "invalid_comparison", "comparison_id is invalid"
                )
            path = base / "comparisons" / (str(artifact_id) + ".json")
        elif artifact_type == "occurrence":
            if (
                not isinstance(artifact_id, str)
                or not OCCURRENCE_SET_ID_PATTERN.match(artifact_id)
            ):
                raise BackendError(
                    "invalid_occurrence_set", "occurrence_set_id is invalid"
                )
            path = base / "occurrences" / (str(artifact_id) + ".json")
        else:
            raise BackendError(
                "invalid_audit_run_measurement", "artifact type is invalid"
            )
        try:
            details = path.lstat()
        except (FileNotFoundError, OSError):
            details = None
        if details is not None and details.st_size > remaining_bytes:
            raise BackendError(
                "audit_report_too_large",
                "AuditRun artifact exceeds the remaining report fact budget",
            )
        with self._lock(assessment_id):
            return self._validate_artifact_reference(
                assessment_id,
                artifact_type,
                artifact_id,
                expected_digest=expected_digest,
                expected_comparison_id=expected_comparison_id,
                maximum_bytes=remaining_bytes,
                validate_linked_artifacts=False,
            )

    def create_audit_run(
        self,
        assessment_id: str,
        expected_assessment_revision: int,
        audit_run: Any,
    ) -> Dict[str, Any]:
        _validate_revision(expected_assessment_revision)
        if not isinstance(audit_run, dict):
            raise BackendError(
                "invalid_audit_run", "audit run must be an object"
            )
        allowed = {
            "name",
            "description",
            "due_at",
            "assurance_profile_version_id",
            "assignments",
        }
        if set(audit_run) - allowed:
            raise BackendError("invalid_audit_run", "audit run contains unsupported fields")
        name = _clean_action_text(audit_run.get("name"), "name", 128, True, "invalid_audit_run")
        description = (
            _clean_action_text(audit_run.get("description"), "description", 512, False, "invalid_audit_run")
            if audit_run.get("description") is not None
            else None
        )
        due_at = audit_run.get("due_at")
        if due_at is not None:
            _validate_rfc3339(due_at, "due_at", "invalid_audit_run")
        assignments = audit_run.get("assignments")
        if (
            not isinstance(assignments, list)
            or not (1 <= len(assignments) <= MAX_MEASUREMENT_POINTS_PER_RUN)
        ):
            raise BackendError("invalid_audit_run", "assignments must contain 1 to 16 items")
        required_assignment_fields = {
            "measurement_point_id",
            "measurement_profile_id",
            "measurement_profile_version_id",
            "baseline_version_id",
        }
        if any(not isinstance(item, dict) or set(item) != required_assignment_fields for item in assignments):
            raise BackendError("invalid_audit_run", "assignment fields are invalid")
        point_ids = [item["measurement_point_id"] for item in assignments]
        if len(point_ids) != len(set(point_ids)):
            raise BackendError("invalid_audit_run", "measurement points must be unique within a run")

        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_assessment_revision)
            existing = self._authoritative_audit_run_headers_unlocked(
                assessment_id
            )
            if len(existing) >= MAX_AUDIT_RUNS_PER_ASSESSMENT:
                raise BackendError("capacity_exceeded", "audit run limit reached")
            assurance = self._load_assurance_pin_by_id_unlocked(
                assessment_id, audit_run.get("assurance_profile_version_id")
            )
            now = _utc_now()
            audit_run_id = _generate_ar_id()
            measurements = []
            for assignment in assignments:
                point = self._get_measurement_point_unlocked(
                    assessment_id, assignment["measurement_point_id"]
                )
                if point["status"] != "active":
                    raise BackendError("measurement_point_archived", "archived points cannot be assigned")
                profile = self._load_measurement_profile_assignment_unlocked(
                    assignment["measurement_profile_id"],
                    assignment["measurement_profile_version_id"],
                    require_active=True,
                )
                baseline = self._load_baseline_assignment_unlocked(
                    assessment_id, assignment["baseline_version_id"]
                )
                if baseline["measurement_context"].get(
                    "measurement_point_id"
                ) != point["measurement_point_id"]:
                    raise BackendError(
                        "pinned_reference_mismatch",
                        "baseline measurement point differs from the assignment",
                    )
                measurement = {
                    "schema_version": self.MEASUREMENT_SCHEMA_VERSION,
                    "measurement_id": _generate_arm_id(),
                    "audit_run_id": audit_run_id,
                    "measurement_point_id": point["measurement_point_id"],
                    "status": "pending",
                    "created_at": now,
                    "revision": 1,
                    "provenance_status": "pinned",
                    "measurement_point_revision": point["revision"],
                    "measurement_point_digest": _canonical_digest(point),
                    "measurement_point_snapshot": _json_clone(
                        point, "invalid_measurement_point", "measurement point"
                    ),
                    "measurement_profile_id": profile["measurement_profile_id"],
                    "measurement_profile_version_id": profile["version_id"],
                    "measurement_profile_digest": profile["digest"],
                    "baseline_version_id": baseline["baseline_version_id"],
                    "baseline_type": baseline["baseline_type"],
                    "baseline_digest": baseline["baseline_digest"],
                    "baseline_record_digest": baseline["baseline_record_digest"],
                    "assurance_profile_version_id": assurance["assurance_profile_version_id"],
                    "assurance_profile_digest": assurance["digest"],
                }
                if baseline["baseline_type"] == "consensus":
                    measurement["baseline_model_id"] = baseline["baseline_model_id"]
                    measurement["baseline_model_digest"] = baseline["baseline_model_digest"]
                else:
                    measurement["baseline_snapshot_id"] = baseline["snapshot_id"]
                    measurement["baseline_snapshot_digest"] = baseline["snapshot_digest"]
                self._validate_v11_measurement(measurement, assessment_id, audit_run_id)
                measurements.append(measurement)
            manifest = {
                "schema_version": self.RUN_MANIFEST_SCHEMA_VERSION,
                "audit_run_id": audit_run_id,
                "assessment_id": assessment_id,
                "name": name,
                "description": description or None,
                "status": "draft",
                "created_at": now,
                "started_at": None,
                "completed_at": None,
                "due_at": due_at,
                "pinned_assurance_profile_version_id": assurance["assurance_profile_version_id"],
                "pinned_assurance_profile_digest": assurance["digest"],
                "measurement_ids": [item["measurement_id"] for item in measurements],
                "revision": 1,
            }
            self._validate_v11_manifest(manifest, assessment_id, audit_run_id)
            event, events_bytes = self._transaction_event(
                assessment_id,
                metadata,
                "audit_run_created",
                {"audit_run_id": audit_run_id},
                extra_closure_reserve=1,
            )
            transaction = PrivateTransaction(self._ensure_assessment_directories(assessment_id), fault_injector=self.fault_injector)
            transaction.add_json("audit_runs/{0}/manifest.json".format(audit_run_id), manifest)
            for measurement in measurements:
                transaction.add_json(
                    "audit_runs/{0}/measurements/{1}.json".format(audit_run_id, measurement["measurement_id"]),
                    measurement,
                )
            transaction.add_json("assessment.json", metadata)
            transaction.add_bytes("events.jsonl", events_bytes)
            transaction.commit()
            assembled = dict(manifest, measurements=measurements)
            return {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "assessment_revision": metadata["revision"],
                "audit_run": self._public_manifest(manifest),
                "measurements": [self._public_measurement(item) for item in measurements],
                "ready_to_start": True,
                "workflow": self._workflow(assembled),
                "assessment_capacity": self._get_assessment_capacity_unlocked(assessment_id),
            }

    @staticmethod
    def _build_finding_transition(
        stored_findings: List[Dict[str, Any]],
        normalized_findings: List[Dict[str, Any]],
        comparability_status: str,
        occurred_at: str,
        measurement_point_id: Optional[str] = None,
    ):
        """Return the production finding transition without writing it."""
        by_id = {
            item["finding_id"]: _json_clone(
                item, "storage_error", "stored finding"
            )
            for item in stored_findings
        }
        lifecycle = {
            "opened": [],
            "reopened": [],
            "updated": [],
            "resolved": [],
            "preserved_false_positive": [],
            "mutated": comparability_status != "not_comparable",
        }
        observed_ids = set()
        if lifecycle["mutated"]:
            for core in normalized_findings:
                finding_id = core["finding_id"]
                observed_ids.add(finding_id)
                existing = by_id.get(finding_id)
                if existing is None:
                    if len(by_id) >= MAX_FINDINGS:
                        raise BackendError(
                            "finding_limit",
                            "assessment finding limit was reached",
                        )
                    stored = dict(core)
                    stored.update(
                        {
                            "status": "open",
                            "currently_observed": True,
                            "first_seen": occurred_at,
                            "last_seen": occurred_at,
                            "occurrence_count": 1,
                            "status_updated_at": occurred_at,
                        }
                    )
                    by_id[finding_id] = stored
                    lifecycle["opened"].append(finding_id)
                    continue
                for field in FINDING_CORE_FIELDS:
                    existing[field] = core[field]
                existing["currently_observed"] = True
                existing["last_seen"] = occurred_at
                existing["occurrence_count"] += 1
                if existing["status"] == "resolved":
                    existing["status"] = "open"
                    existing["status_updated_at"] = occurred_at
                    lifecycle["reopened"].append(finding_id)
                elif existing["status"] == "false_positive":
                    lifecycle["preserved_false_positive"].append(finding_id)
                else:
                    lifecycle["updated"].append(finding_id)

            if comparability_status == "comparable":
                for finding_id, existing in by_id.items():
                    if finding_id in observed_ids:
                        continue
                    details = existing.get("details")
                    finding_point_id = (
                        details.get("measurement_point_id")
                        if isinstance(details, dict)
                        else None
                    )
                    if finding_point_id != measurement_point_id:
                        continue
                    existing["currently_observed"] = False
                    if existing["status"] in {"open", "acknowledged"}:
                        existing["status"] = "resolved"
                        existing["status_updated_at"] = occurred_at
                        lifecycle["resolved"].append(finding_id)
            stored_findings = sorted(
                by_id.values(), key=lambda item: item["finding_id"]
            )
        return stored_findings, lifecycle, observed_ids

    def build_audit_measurement_analysis(
        self,
        assessment_id: str,
        expected_assessment_revision: int,
        audit_run_id: str,
        expected_audit_run_revision: int,
        measurement_id: str,
        expected_measurement_revision: int,
        comparison: Any,
        lifecycle_findings: Any,
        occurrence_set: Any,
        completed_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Build native analysis artifacts without mutating assessment state.

        The returned object is the ``analysis`` argument accepted by
        :meth:`save_audit_measurement_comparison`.  Building and saving are
        deliberately separate: the caller may inspect the canonical facts,
        while the save operation rechecks every optimistic-concurrency token
        and the findings base digest before one atomic transaction.
        """
        _validate_revision(expected_assessment_revision)
        _validate_revision(expected_audit_run_revision)
        _validate_revision(expected_measurement_revision)
        normalized_comparison = _validate_comparison(comparison)
        if (
            not isinstance(lifecycle_findings, list)
            or len(lifecycle_findings) > MAX_FINDINGS
        ):
            raise BackendError(
                "invalid_finding",
                "lifecycle findings must contain at most {0} items".format(
                    MAX_FINDINGS
                ),
            )
        normalized_findings = [
            _validate_finding_core(item) for item in lifecycle_findings
        ]
        finding_ids = [item["finding_id"] for item in normalized_findings]
        if len(finding_ids) != len(set(finding_ids)):
            raise BackendError(
                "invalid_finding", "finding_id values must be unique"
            )
        occurrence = _json_clone(
            occurrence_set,
            "invalid_occurrence_set",
            "occurrence set",
            MAX_PROFILE_DOCUMENT_BYTES,
        )
        if not isinstance(occurrence, dict):
            raise BackendError(
                "invalid_occurrence_set", "occurrence set must be an object"
            )
        if set(occurrence) != OCCURRENCE_INPUT_FIELDS:
            raise BackendError(
                "invalid_occurrence_set",
                "occurrence set fields are invalid",
            )
        referenced_evidence_ids = set()
        for section in (
            "observed_changes",
            "policy_deviations",
            "security_findings",
        ):
            items = occurrence.get(section)
            if not isinstance(items, list):
                raise BackendError(
                    "invalid_occurrence_set",
                    "{0} must be an array".format(section),
                )
            for item in items:
                if not isinstance(item, dict):
                    raise BackendError(
                        "invalid_occurrence_set",
                        "{0} item is invalid".format(section),
                    )
                references = item.get("evidence_ids", [])
                if (
                    not isinstance(references, list)
                    or len(references) != len(set(references))
                    or any(
                        not isinstance(reference, str)
                        or not EVIDENCE_ID_PATTERN.match(reference)
                        for reference in references
                    )
                ):
                    raise BackendError(
                        "invalid_occurrence_set",
                        "{0} evidence references are invalid".format(section),
                    )
                referenced_evidence_ids.update(references)
        if (
            len(referenced_evidence_ids)
            > MAX_EVIDENCE_IDS_PER_AUDIT_MEASUREMENT
        ):
            raise BackendError(
                "audit_measurement_evidence_limit",
                "analysis references more than {0} evidence records".format(
                    MAX_EVIDENCE_IDS_PER_AUDIT_MEASUREMENT
                ),
            )
        evidence_by_id = {}
        evidence_records = occurrence.get("evidence")
        if not isinstance(evidence_records, list):
            raise BackendError(
                "invalid_occurrence_set", "evidence must be an array"
            )
        for record in evidence_records:
            if not isinstance(record, dict):
                raise BackendError(
                    "invalid_occurrence_set", "evidence record is invalid"
                )
            evidence_id = record.get("evidence_id")
            if (
                not isinstance(evidence_id, str)
                or not EVIDENCE_ID_PATTERN.match(evidence_id)
                or evidence_id in evidence_by_id
            ):
                raise BackendError(
                    "invalid_occurrence_set",
                    "evidence ID is invalid or duplicated",
                )
            evidence_by_id[evidence_id] = record
        if not referenced_evidence_ids.issubset(evidence_by_id):
            raise BackendError(
                "invalid_occurrence_set",
                "analysis references unavailable evidence",
            )
        # AuditRun measurements retain only evidence that supports a returned
        # change, deviation, or security finding.  This keeps the frozen
        # per-measurement contract within its 100-evidence safety bound while
        # preserving every authoritative reference.
        occurrence["evidence"] = [
            evidence_by_id[evidence_id]
            for evidence_id in sorted(referenced_evidence_ids)
        ]
        _ensure_no_raw_recon(
            {
                "comparison": normalized_comparison,
                "lifecycle_findings": normalized_findings,
                "occurrence_set": occurrence,
            }
        )
        built_at = (
            _utc_now()
            if completed_at is None
            else _validate_rfc3339(
                completed_at,
                "completed_at",
                "invalid_audit_run_measurement",
            )
        )

        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_assessment_revision)
            run = self._get_audit_run_unlocked(assessment_id, audit_run_id)
            if run["status"] in {"completed", "cancelled"}:
                raise BackendError("audit_run_sealed", "audit run is sealed")
            if run["status"] != "in_progress":
                raise BackendError(
                    "invalid_state_transition", "run must be in progress"
                )
            if run["revision"] != expected_audit_run_revision:
                raise BackendError(
                    "revision_conflict", "audit run revision has changed"
                )
            measurement = self._find_measurement_unlocked(run, measurement_id)
            if measurement["revision"] != expected_measurement_revision:
                raise BackendError(
                    "revision_conflict", "measurement revision has changed"
                )
            if measurement["status"] != "resolved":
                raise BackendError(
                    "invalid_state_transition", "measurement must be resolved"
                )
            if measurement.get("provenance_status") != "pinned":
                raise BackendError(
                    "pinned_reference_missing",
                    "measurement provenance is incomplete",
                )
            if _rfc3339_order_key(built_at) < _rfc3339_order_key(
                measurement["resolved_at"]
            ):
                raise BackendError(
                    "invalid_audit_run_measurement",
                    "completed_at precedes resolved_at",
                )

            profile = self._load_measurement_profile_assignment_unlocked(
                measurement["measurement_profile_id"],
                measurement["measurement_profile_version_id"],
            )
            if profile.get("digest") != measurement["measurement_profile_digest"]:
                raise BackendError(
                    "pinned_reference_mismatch",
                    "measurement profile differs from the frozen run pin",
                )
            baseline_pin = self._load_baseline_assignment_unlocked(
                assessment_id, measurement["baseline_version_id"]
            )
            if (
                baseline_pin.get("baseline_digest")
                != measurement["baseline_digest"]
                or baseline_pin.get("baseline_record_digest")
                != measurement["baseline_record_digest"]
            ):
                raise BackendError(
                    "pinned_reference_mismatch",
                    "baseline differs from the frozen run pin",
                )
            assurance = self._load_assurance_profile_pin_unlocked(
                assessment_id,
                measurement["assurance_profile_version_id"],
                measurement["assurance_profile_digest"],
                "pinned_reference_mismatch",
            )
            if assurance.get("digest") != measurement["assurance_profile_digest"]:
                raise BackendError(
                    "pinned_reference_mismatch",
                    "assurance profile differs from the frozen run pin",
                )

            snapshot = _read_bounded_json_file(
                self,
                self._snapshot_path(assessment_id, measurement["snapshot_id"]),
                MAX_NATIVE_ARTIFACT_DOCUMENT_BYTES,
                "pinned_reference_missing",
                "pinned_reference_mismatch",
                "resolved snapshot",
            )
            normalized_snapshot = _bind_snapshot_record_digest(snapshot)
            if (
                normalized_snapshot["snapshot_id"] != measurement["snapshot_id"]
                or normalized_snapshot["snapshot_digest"]
                != measurement["snapshot_digest"]
                or _snapshot_record_digest(normalized_snapshot)
                != measurement["snapshot_record_digest"]
                or normalized_comparison["current_snapshot_id"]
                != normalized_snapshot["snapshot_id"]
            ):
                raise BackendError(
                    "pinned_reference_mismatch",
                    "comparison does not use the resolved snapshot",
                )

            comparison_id = self._comparison_id(
                assessment_id,
                measurement["baseline_version_id"],
                normalized_comparison,
            )
            comparison_path = self._comparison_path(
                assessment_id, comparison_id
            )
            if comparison_path.exists() or comparison_path.is_symlink():
                raise BackendError(
                    "analysis_already_persisted",
                    "this comparison was already persisted",
                )

            stored_findings = self._read_findings(assessment_id)
            findings_base_digest = _canonical_digest(stored_findings)
            status = normalized_comparison["comparability"]["status"]
            stored_findings, lifecycle, observed_ids = (
                self._build_finding_transition(
                    stored_findings,
                    normalized_findings,
                    status,
                    built_at,
                    measurement.get("measurement_point_id"),
                )
            )

            pins = {
                "baseline_version_id": measurement["baseline_version_id"],
                "baseline_digest": measurement["baseline_digest"],
                "measurement_profile_id": measurement[
                    "measurement_profile_id"
                ],
                "measurement_profile_version_id": measurement[
                    "measurement_profile_version_id"
                ],
                "measurement_profile_digest": measurement[
                    "measurement_profile_digest"
                ],
                "assurance_profile_version_id": measurement[
                    "assurance_profile_version_id"
                ],
                "assurance_profile_digest": measurement[
                    "assurance_profile_digest"
                ],
            }
            occurrence.update(
                {
                    "schema_version": OCCURRENCE_SCHEMA_VERSION,
                    "comparison_id": comparison_id,
                    "assessment_id": assessment_id,
                    "recorded_at": built_at,
                    "baseline_reference": {
                        "baseline_version_id": measurement[
                            "baseline_version_id"
                        ],
                        "baseline_type": measurement["baseline_type"],
                        "digest": measurement["baseline_digest"],
                    },
                    "pinned_versions": pins,
                    "comparability": normalized_comparison["comparability"],
                    "lifecycle": lifecycle,
                }
            )
            occurrence_digest = _canonical_digest(
                {
                    key: value
                    for key, value in occurrence.items()
                    if key not in {"occurrence_set_id", "occurrence_digest"}
                }
            )
            occurrence_id = "occurrence_{0}".format(
                occurrence_digest[:16]
            )
            occurrence["occurrence_set_id"] = occurrence_id
            occurrence["occurrence_digest"] = occurrence_digest
            if set(occurrence) != OCCURRENCE_STORED_FIELDS:
                raise BackendError(
                    "invalid_occurrence_set",
                    "stored occurrence set fields are invalid",
                )

            record = {
                "schema_version": CUSTOMER_AUDIT_SCHEMA_VERSION,
                "comparison_id": comparison_id,
                "assessment_id": assessment_id,
                "baseline_version_id": measurement["baseline_version_id"],
                "created_at": built_at,
                "baseline_snapshot_id": normalized_comparison[
                    "baseline_snapshot_id"
                ],
                "current_snapshot_id": normalized_snapshot["snapshot_id"],
                "current_snapshot_digest": normalized_snapshot[
                    "snapshot_digest"
                ],
                "comparability_status": status,
                "observed_finding_ids": sorted(observed_ids),
                "lifecycle": lifecycle,
                "comparison": normalized_comparison,
                "occurrence_set_id": occurrence_id,
                "occurrence_digest": occurrence_digest,
                "pinned_versions": pins,
            }
            self._validate_native_occurrence_record(
                assessment_id, occurrence_id, occurrence, comparison_id
            )
            self._validate_native_comparison_record(
                assessment_id, comparison_id, record
            )

            result = {
                "comparison": record,
                "occurrence": occurrence,
                "completed_at": built_at,
                "findings_base_digest": findings_base_digest,
                "findings_document": None,
            }
            if lifecycle["mutated"]:
                result["findings_document"] = {
                    "schema_version": ASSESSMENT_SCHEMA_VERSION,
                    "updated_at": built_at,
                    "findings": stored_findings,
                }
            return result

    def _legacy_retry_audit_measurement(
        self,
        assessment_id: str,
        expected_assessment_revision: int,
        audit_run_id: str,
        expected_audit_run_revision: int,
        measurement_point_id: str,
    ) -> Dict[str, Any]:
        _validate_revision(expected_assessment_revision)
        _validate_revision(expected_audit_run_revision)
        if (
            not isinstance(audit_run_id, str)
            or not AUDIT_RUN_ID_PATTERN.match(audit_run_id)
        ):
            raise BackendError(
                "invalid_audit_run", "audit_run_id format is invalid"
            )
        if (
            not isinstance(measurement_point_id, str)
            or not MEASUREMENT_POINT_ID_PATTERN.match(
                measurement_point_id
            )
        ):
            raise BackendError(
                "invalid_audit_run_measurement",
                "measurement_point_id is invalid",
            )

        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_assessment_revision)

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
                    "created_at": _timestamp_not_before(
                        target_m.get("created_at"),
                        target_m.get("resolved_at"),
                        target_m.get("failed_at"),
                    ),
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

    def _legacy_save_audit_measurement_comparison(
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
        if not isinstance(outcome, dict):
            raise BackendError(
                "invalid_audit_run_measurement",
                "comparison outcome must be an object",
            )
        if (
            not isinstance(audit_run_id, str)
            or not AUDIT_RUN_ID_PATTERN.match(audit_run_id)
        ):
            raise BackendError(
                "invalid_audit_run", "audit_run_id format is invalid"
            )
        if (
            not isinstance(measurement_point_id, str)
            or not MEASUREMENT_POINT_ID_PATTERN.match(
                measurement_point_id
            )
        ):
            raise BackendError(
                "invalid_audit_run_measurement",
                "measurement_point_id is invalid",
            )
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
            outcome_time_field = (
                "completed_at" if status == "completed" else "failed_at"
            )
            outcome_time = _validate_rfc3339(
                outcome.get(outcome_time_field),
                outcome_time_field,
                "invalid_audit_run_measurement",
            )
            if _rfc3339_order_key(outcome_time) < _rfc3339_order_key(
                target_m["resolved_at"]
            ):
                raise BackendError(
                    "invalid_audit_run_measurement",
                    "{0} precedes resolved_at".format(
                        outcome_time_field
                    ),
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
