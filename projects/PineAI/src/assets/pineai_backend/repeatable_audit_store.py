"""PineAI v0.7.0 Repeatable Field Audits domain store.

Extends CustomerAuditStore with MeasurementPoint, AuditRun, and AuditRunMeasurement
persistence, optimistic concurrency, dynamic closure reserves, and recoverable storage.
"""

import json
import os
import re
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from .assessment_store import (
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
    CustomerAuditStore,
    _clean_text,
    _integer_list,
    _text_list,
)
from .errors import BackendError
from .storage_transaction import PrivateTransaction, recover_private_transactions


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
        _validate_iso_datetime(m["created_at"], "created_at")
        _validate_expected_measurement_context(m["expected_measurement_context"], measurement_point_id=m["measurement_point_id"])
    else:
        _validate_audit_run_measurement(m)


def _to_public_measurement(m: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(m, dict):
        raise BackendError("invalid_audit_run_measurement", "measurement must be an object")

    m_copy = dict(m)
    if "audit_measurement_id" in m_copy and "measurement_id" not in m_copy:
        m_copy["measurement_id"] = m_copy.pop("audit_measurement_id")
    else:
        m_copy.pop("audit_measurement_id", None)

    if m_copy.get("status") == "pending":
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

    def _ensure_assessment_directories(self, assessment_id: str) -> Path:
        base = super()._ensure_assessment_directories(assessment_id)
        self._ensure_private_directory(base / "audit_runs")
        recover_private_transactions(base)
        return base

    def _validate_audit_run_size(self, audit_run: Dict[str, Any]) -> bytes:
        run_bytes = json.dumps(audit_run, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
        if len(run_bytes) > MAX_AUDIT_RUN_DOCUMENT_BYTES:
            raise BackendError("storage_limit_exceeded", "audit run document size exceeded limit")
        return run_bytes

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
            file_path = base / "snapshots" / f"{artifact_id}.json"
            err_not_found = "snapshot_not_found"
            err_invalid = "invalid_snapshot"
            id_key = "snapshot_id"
        elif artifact_type == "comparison":
            file_path = base / "comparisons" / f"{artifact_id}.json"
            err_not_found = "comparison_not_found"
            err_invalid = "invalid_comparison"
            id_key = "comparison_id"
        elif artifact_type == "occurrence":
            file_path = base / "occurrences" / f"{artifact_id}.json"
            err_not_found = "occurrence_set_not_found"
            err_invalid = "invalid_occurrence_set"
            id_key = "occurrence_set_id"
        else:
            raise BackendError("invalid_audit_run_measurement", f"unknown artifact_type {artifact_type}")

        if not file_path.exists():
            raise BackendError(err_not_found, f"{artifact_type} {artifact_id} not found")

        data = self._read_json(file_path, err_invalid, f"{artifact_type} document is unreadable JSON")

        if not isinstance(data, dict) or len(data) == 0:
            raise BackendError(err_invalid, f"{artifact_type} document must be a non-empty object")

        if id_key not in data:
            raise BackendError(err_invalid, f"{artifact_type} document missing required id field {id_key}")

        if data[id_key] != artifact_id:
            raise BackendError(err_invalid, f"{artifact_type} internal id does not match {artifact_id}")

        if artifact_type == "snapshot":
            _validate_snapshot(data)
        elif artifact_type == "comparison":
            comp_copy = dict(data)
            comp_copy.pop("comparison_id", None)
            _validate_comparison(comp_copy)
        elif artifact_type == "occurrence":
            if "occurrences" not in data or not isinstance(data["occurrences"], list):
                raise BackendError(err_invalid, "occurrence set occurrences must be a list")
            for occ in data["occurrences"]:
                if not isinstance(occ, dict):
                    raise BackendError(err_invalid, "occurrence item must be an object")
                if expected_comparison_id is not None and "comparison_id" in occ:
                    if occ["comparison_id"] != expected_comparison_id:
                        raise BackendError(err_invalid, "occurrence comparison_id does not match referenced comparison")

        if expected_digest is not None:
            digest = _canonical_digest(data)
            if digest != expected_digest:
                raise BackendError(err_invalid, f"{artifact_type} digest mismatch")

        return data

    def _read_audit_runs_manifest_unlocked(self, assessment_id: str) -> Dict[str, Any]:
        """Read or reconstruct the audit-runs manifest in memory.

        Never writes the manifest to disk.  Persisting a repaired
        or updated manifest is the responsibility of mutating operations
        that include the manifest in their PrivateTransaction commit.
        """
        base = self._ensure_assessment_directories(assessment_id)
        manifest_file = base / "audit_runs_manifest.json"
        if manifest_file.exists():
            try:
                manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
                if isinstance(manifest, dict) and "runs" in manifest and isinstance(manifest["runs"], dict):
                    return manifest
            except (OSError, ValueError):
                pass

        runs_dir = base / "audit_runs"
        runs_map = {}
        if runs_dir.exists():
            with os.scandir(str(runs_dir)) as it:
                for entry in sorted(it, key=lambda e: e.name):
                    if entry.name.startswith("ar_") and entry.name.endswith(".json"):
                        try:
                            run_doc = json.loads(Path(entry.path).read_text(encoding="utf-8"))
                            if isinstance(run_doc, dict) and "audit_run_id" in run_doc:
                                runs_map[run_doc["audit_run_id"]] = run_doc.get("status", "draft")
                        except (OSError, ValueError) as error:
                            raise BackendError("audit_run_unreadable", f"Audit run file {entry.name} is unreadable") from error

        closure_reserve = sum(1 for status in runs_map.values() if status in ("draft", "in_progress"))
        manifest = {
            "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
            "active_closure_reserve": closure_reserve,
            "runs": runs_map,
        }
        return manifest

    def _update_audit_runs_manifest_unlocked(self, assessment_id: str, audit_run_id: str, status: str) -> Dict[str, Any]:
        manifest = self._read_audit_runs_manifest_unlocked(assessment_id)
        runs_map = dict(manifest.get("runs", {}))
        runs_map[audit_run_id] = status
        closure_reserve = sum(1 for st in runs_map.values() if st in ("draft", "in_progress"))
        updated_manifest = {
            "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
            "active_closure_reserve": closure_reserve,
            "runs": runs_map,
        }
        return updated_manifest

    def _get_assessment_capacity_unlocked(self, assessment_id: str) -> Dict[str, Any]:
        base = self._ensure_assessment_directories(assessment_id)

        snapshots = 0
        snap_dir = base / "snapshots"
        if snap_dir.exists():
            with os.scandir(str(snap_dir)) as it:
                snapshots = sum(1 for entry in it if entry.name.endswith(".json"))

        comparisons = 0
        comp_dir = base / "comparisons"
        if comp_dir.exists():
            with os.scandir(str(comp_dir)) as it:
                comparisons = sum(1 for entry in it if entry.name.endswith(".json"))

        metadata = self._read_metadata(assessment_id)
        event_used = metadata.get("last_event_sequence", 0)

        manifest = self._read_audit_runs_manifest_unlocked(assessment_id)
        closure_reserve = manifest.get("active_closure_reserve", 0)

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
        if not path.exists():
            return {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "assessment_id": assessment_id,
                "updated_at": _utc_now(),
                "measurement_points": [],
            }
        doc = self._read_json(path, "invalid_measurement_point", "measurement_points document missing")
        if not isinstance(doc, dict) or not isinstance(doc.get("measurement_points"), list):
            raise BackendError("invalid_measurement_point", "measurement_points document is corrupted")
        return doc

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
        if limit < 1 or limit > 100 or offset < 0:
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

            _canonical_digest(new_doc)
            doc_bytes = json.dumps(new_doc, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
            if len(doc_bytes) > MAX_MEASUREMENT_POINTS_DOCUMENT_BYTES:
                raise BackendError("storage_limit_exceeded", "measurement points document size exceeded limit")

            event_obj, events_bytes = self._transaction_event(
                assessment_id,
                metadata,
                "measurement_point_created",
                {"measurement_point": new_point},
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

            doc_bytes = json.dumps(new_doc, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
            if len(doc_bytes) > MAX_MEASUREMENT_POINTS_DOCUMENT_BYTES:
                raise BackendError("storage_limit_exceeded", "measurement points document size exceeded limit")

            event_obj, events_bytes = self._transaction_event(
                assessment_id,
                metadata,
                "measurement_point_updated",
                {"measurement_point": updated_mp},
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

            doc_bytes = json.dumps(new_doc, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
            if len(doc_bytes) > MAX_MEASUREMENT_POINTS_DOCUMENT_BYTES:
                raise BackendError("storage_limit_exceeded", "measurement points document size exceeded limit")

            event_obj, events_bytes = self._transaction_event(
                assessment_id,
                metadata,
                "measurement_point_archived",
                {"measurement_point": updated_mp},
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
        base = self._ensure_assessment_directories(assessment_id)
        runs_dir = base / "audit_runs"
        if not runs_dir.exists():
            return []
        results = []
        for path in sorted(runs_dir.glob("ar_*.json")):
            run = self._read_json(path, "invalid_audit_run", "audit run document is invalid")
            if isinstance(run, dict):
                results.append(_json_clone(run, "invalid_audit_run", "audit_run"))
        return results

    def list_audit_runs(self, assessment_id: str, limit: int = 50, offset: int = 0) -> Dict[str, Any]:
        if limit < 1 or limit > 100 or offset < 0:
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
                    "ready_to_start": _compute_ready_to_start(run),
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
        run = self._read_json(path, "audit_run_not_found", "audit run not found")
        return _json_clone(run, "invalid_audit_run", "audit_run")

    def get_audit_run(self, assessment_id: str, audit_run_id: str) -> Dict[str, Any]:
        with self._lock(assessment_id):
            run_doc = self._get_audit_run_unlocked(assessment_id, audit_run_id)
            sanitized_measurements = [_sanitize_measurement(m) for m in run_doc.get("measurements", [])]
            return {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "audit_run": _sanitize_audit_run(run_doc),
                "ready_to_start": _compute_ready_to_start(run_doc),
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

            assurance_prof = self.get_assurance_profile_version(assessment_id, pinned_assurance_profile_version_id)
            assurance_digest = assurance_prof.get("digest")
            if not assurance_digest:
                raise BackendError("profile_version_not_found", "assurance profile digest missing")

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
                {"audit_run": _sanitize_audit_run(audit_run)},
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
                "ready_to_start": _compute_ready_to_start(audit_run),
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

            updated_run = _json_clone(audit_run, "invalid_audit_run", "audit_run")
            updated_run["status"] = "in_progress"
            updated_run["started_at"] = _utc_now()
            updated_run["revision"] += 1

            run_bytes = self._validate_audit_run_size(updated_run)

            event_obj, events_bytes = self._transaction_event(
                assessment_id,
                metadata,
                "audit_run_started",
                {"audit_run": _sanitize_audit_run(updated_run)},
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
        if reason is not None:
            _clean_text(reason, "reason", 512, required=False)

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
            updated_run["completed_at"] = _utc_now()
            updated_run["revision"] += 1

            run_bytes = self._validate_audit_run_size(updated_run)

            event_obj, events_bytes = self._transaction_event(
                assessment_id,
                metadata,
                "audit_run_cancelled",
                {"audit_run": _sanitize_audit_run(updated_run)},
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
            updated_run["completed_at"] = _utc_now()
            updated_run["revision"] += 1

            run_bytes = self._validate_audit_run_size(updated_run)

            event_obj, events_bytes = self._transaction_event(
                assessment_id,
                metadata,
                "audit_run_completed",
                {"audit_run": _sanitize_audit_run(updated_run)},
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

            if status == "resolved":
                btype = outcome.get("baseline_type")
                snap_id = outcome.get("snapshot_id")
                snap_digest = outcome.get("snapshot_digest")
                if not snap_id:
                    raise BackendError("invalid_audit_run_measurement", "snapshot_id is required")
                self._validate_artifact_reference(assessment_id, "snapshot", snap_id, expected_digest=snap_digest)

                if btype == "single_scan":
                    base_snap_id = outcome.get("baseline_snapshot_id")
                    base_snap_digest = outcome.get("baseline_snapshot_digest")
                    if not base_snap_id:
                        raise BackendError("invalid_audit_run_measurement", "baseline_snapshot_id is required")
                    self._validate_artifact_reference(assessment_id, "snapshot", base_snap_id, expected_digest=base_snap_digest)
            elif status == "failed" and failed_stage == "resolution":
                pass
            else:
                raise BackendError("invalid_audit_run_measurement", "resolve outcome must be resolved or failed resolution")

            measurements = audit_run.get("measurements", [])
            target_idx = -1
            target_m = None
            for idx, m in enumerate(measurements):
                if m.get("measurement_point_id") == measurement_point_id:
                    target_idx = idx
                    target_m = m
                    break

            if target_m is None:
                raise BackendError("measurement_point_not_found", "measurement point not in audit run")
            if target_m.get("status") != "pending":
                raise BackendError("invalid_audit_run_transition", "cannot resolve measurement in status {0}".format(target_m.get("status")))

            updated_m = _json_clone(target_m, "invalid_audit_run_measurement", "measurement")
            updated_m.pop("created_at", None)
            updated_m.pop("expected_measurement_context", None)
            updated_m.update(_json_clone(outcome, "invalid_audit_run_measurement", "outcome"))
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

            event_obj, events_bytes = self._transaction_event(
                assessment_id,
                metadata,
                "audit_measurement_resolved",
                {"measurement": sanitized_m},
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
                raise BackendError("measurement_point_not_found", "measurement point not in audit run")
            if target_m.get("status") != "failed":
                raise BackendError("invalid_audit_run_transition", "cannot retry measurement that is not in failed status")

            failed_stage = target_m.get("failed_stage")

            if failed_stage == "resolution":
                mp_obj = self._get_measurement_point_unlocked(assessment_id, measurement_point_id)
                updated_m = {
                    "measurement_id": target_m.get("measurement_id") or target_m.get("audit_measurement_id"),
                    "audit_run_id": audit_run_id,
                    "measurement_point_id": measurement_point_id,
                    "status": "pending",
                    "created_at": _utc_now(),
                    "expected_measurement_context": _json_clone(mp_obj["expected_measurement_context"], "invalid_measurement_point", "context"),
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
                raise BackendError("invalid_audit_run_transition", "unknown failed_stage for measurement")

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
                {"measurement": public_m},
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

        if status == "completed":
            comp_id = outcome.get("comparison_id")
            comp_digest = outcome.get("comparison_digest")
            if not comp_id:
                raise BackendError("invalid_audit_run_measurement", "comparison_id is required")
            self._validate_artifact_reference(assessment_id, "comparison", comp_id, expected_digest=comp_digest)

            occ_id = outcome.get("occurrence_set_id")
            if not occ_id:
                raise BackendError("invalid_audit_run_measurement", "occurrence_set_id is required")
            self._validate_artifact_reference(assessment_id, "occurrence", occ_id)
        elif status == "failed" and failed_stage == "comparison":
            comp_id = outcome.get("comparison_id")
            comp_digest = outcome.get("comparison_digest")
            if comp_id:
                self._validate_artifact_reference(assessment_id, "comparison", comp_id, expected_digest=comp_digest)
            occ_id = outcome.get("occurrence_set_id")
            if occ_id:
                self._validate_artifact_reference(assessment_id, "occurrence", occ_id)
        else:
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
                raise BackendError("measurement_point_not_found", "measurement point not in audit run")
            if target_m.get("status") != "resolved":
                raise BackendError("invalid_audit_run_transition", "cannot save comparison for measurement not in resolved status")

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

            event_obj, events_bytes = self._transaction_event(
                assessment_id,
                metadata,
                "audit_measurement_comparison_saved",
                {"measurement": sanitized_m},
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
