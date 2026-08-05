"""Private, revisioned storage for Baseline & Drift assessments.

The store accepts only PineAI's normalized assurance documents.  It never
accepts or persists a raw Hak5 Recon response.
"""

import collections
import copy
import datetime
import hashlib
import json
import os
import re
import stat
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .config import resolve_config_dir, write_private_file
from .errors import BackendError
from .storage_transaction import PrivateTransaction, recover_private_transactions
from .timestamps import rfc3339_order_key, validate_rfc3339


ASSESSMENT_SCHEMA_VERSION = "1.1"
SUPPORTED_ASSESSMENT_SCHEMA_VERSIONS = ("1.0", "1.1")
SUPPORTED_SCHEMA_VERSIONS = ("1.0", "1.1", "1.2")
ASSESSMENT_ID_PATTERN = re.compile(
    r"^assessment_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
BASELINE_VERSION_ID_PATTERN = re.compile(r"^baseline_v[0-9]{4}$")
SNAPSHOT_ID_PATTERN = re.compile(r"^snapshot_[0-9a-f]{16}$")
SNAPSHOT_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
COMPARISON_ID_PATTERN = re.compile(r"^comparison_[0-9a-f]{16}$")
FINDING_ID_PATTERN = re.compile(r"^finding_[0-9a-f]{12}$")
ASSET_ID_PATTERN = re.compile(r"^ap_[0-9a-f]{12}$")
NETWORK_ID_PATTERN = re.compile(r"^network_[0-9a-f]{12}$")
EVIDENCE_ID_PATTERN = re.compile(r"^evidence_[0-9a-f]{12}$")
EVENT_ID_PATTERN = re.compile(
    r"^evt_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
EVENT_TYPE_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,99}$")
STORED_TIMESTAMP_PATTERN = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:"
    r"[0-9]{2}(?:\.[0-9]{1,6})?Z$"
)

ASSESSMENT_EDITABLE_FIELDS = {"name", "location", "notes"}
ASSESSMENT_STATUSES = {"active", "archived"}
FINDING_STATUSES = {"open", "acknowledged", "false_positive", "resolved"}
OPERATOR_FINDING_STATUSES = {"open", "acknowledged", "false_positive"}
COMPARABILITY_STATUSES = {
    "comparable",
    "partially_comparable",
    "not_comparable",
}
SEVERITIES = {"critical", "high", "medium", "low", "info"}

MAX_BASELINE_VERSIONS = 50
MAX_FINDINGS = 500
MAX_SNAPSHOTS = 100
MAX_COMPARISONS = 100
MAX_EVENTS = 5000
MAX_DOCUMENT_BYTES = 4 * 1024 * 1024
MAX_CUSTOMER_LIST_BYTES = 4 * 1024 * 1024

SNAPSHOT_FIELDS = {
    "schema_version",
    "snapshot_id",
    "snapshot_digest",
    "observed_at",
    "scan_metadata",
    "comparability_profile",
    "summary",
    "access_points",
    "networks",
    "evidence",
}
SNAPSHOT_AP_FIELDS = {
    "asset_id",
    "network_id",
    "evidence_id",
    "bssid",
    "ssid",
    "hidden",
    "encryption",
    "wps",
    "channel",
    "band",
    "signal",
    "vendor",
    "client_count",
    "data",
    "probes",
    "last_seen",
}
SNAPSHOT_NETWORK_FIELDS = {
    "network_id",
    "ssid",
    "hidden",
    "asset_ids",
    "bssids",
    "channels",
    "encryption_codes",
    "vendors",
    "client_count",
}
SNAPSHOT_EVIDENCE_FIELDS = {
    "evidence_id",
    "snapshot_id",
    "evidence_type",
    "subject_id",
    "observed",
}
SINGLE_SCAN_BASELINE_FIELDS = {
    "schema_version",
    "assessment_id",
    "baseline_version_id",
    "version",
    "label",
    "created_at",
    "snapshot_id",
    "snapshot_digest",
    "summary",
    "scan_metadata",
    "comparability_profile",
}
COMPARISON_FIELDS = {
    "schema_version",
    "baseline_snapshot_id",
    "current_snapshot_id",
    "comparability",
    "access_points",
    "networks",
    "summary",
}
STORED_COMPARISON_FIELDS = {
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
}
CUSTOMER_STORED_COMPARISON_FIELDS = STORED_COMPARISON_FIELDS | {
    "occurrence_set_id",
    "occurrence_digest",
    "pinned_versions",
}
COMPARISON_LIFECYCLE_FIELDS = {
    "opened",
    "reopened",
    "updated",
    "resolved",
    "preserved_false_positive",
    "mutated",
}
CUSTOMER_ANALYSIS_PIN_FIELDS = {
    "baseline_version_id",
    "baseline_digest",
    "measurement_profile_id",
    "measurement_profile_version_id",
    "measurement_profile_digest",
    "assurance_profile_version_id",
    "assurance_profile_digest",
}
OCCURRENCE_SET_ID_PATTERN = re.compile(r"^occurrence_[0-9a-f]{16}$")
MEASUREMENT_PROFILE_ID_PATTERN = re.compile(
    r"^mprofile_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
MEASUREMENT_PROFILE_VERSION_ID_PATTERN = re.compile(r"^mprofile_r[0-9]{4}$")
ASSURANCE_PROFILE_VERSION_ID_PATTERN = re.compile(r"^assurance_v[0-9]{4}$")
FINDING_CORE_FIELDS = {
    "finding_id",
    "rule_id",
    "title",
    "severity",
    "confidence",
    "subject_id",
    "summary",
    "evidence_ids",
    "details",
    "confidence_factors",
}

# These names exist in raw Hak5 Recon responses but not in resolved snapshots.
RAW_RECON_KEYS = {
    "apresults",
    "outofrangeresult",
    "outofrangeresults",
    "outofrangeclientresults",
    "unassociatedresult",
    "unassociatedresults",
    "unassociatedclientresults",
    "clients",
}


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )


def _stored_timestamp(value: Any, code: str = "storage_error"):
    if not isinstance(value, str) or not STORED_TIMESTAMP_PATTERN.match(
        value
    ):
        raise BackendError(code, "stored timestamp is invalid")
    try:
        return datetime.datetime.fromisoformat(
            value[:-1] + "+00:00"
        )
    except ValueError as error:
        raise BackendError(code, "stored timestamp is invalid") from error


def _clean_text(
    value: Any, field: str, minimum: int, maximum: int
) -> str:
    if not isinstance(value, str):
        raise BackendError(
            "invalid_assessment", "{0} must be a string".format(field)
        )
    cleaned = "".join(character for character in value if ord(character) >= 32)
    cleaned = cleaned.strip()
    if len(cleaned) < minimum or len(cleaned) > maximum:
        raise BackendError(
            "invalid_assessment",
            "{0} must contain {1}-{2} characters".format(
                field, minimum, maximum
            ),
        )
    return cleaned


def _validate_revision(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise BackendError(
            "invalid_request", "expected_revision must be a positive integer"
        )
    return value


def _json_clone(
    value: Any, code: str, label: str, maximum: int = MAX_DOCUMENT_BYTES
) -> Any:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise BackendError(code, "{0} must be valid JSON".format(label))
    if len(encoded) > maximum:
        raise BackendError(code, "{0} is too large".format(label))
    return json.loads(encoded.decode("utf-8"))


def _canonical_digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _snapshot_record_digest(value: Dict[str, Any]) -> str:
    return _canonical_digest(
        {
            key: item
            for key, item in value.items()
            if key != "snapshot_record_digest"
        }
    )


def _normalized_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def _ensure_no_raw_recon(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if _normalized_key(key) in RAW_RECON_KEYS:
                raise BackendError(
                    "raw_recon_not_allowed",
                    "raw Hak5 Recon data must not be persisted",
                )
            _ensure_no_raw_recon(item)
    elif isinstance(value, list):
        for item in value:
            _ensure_no_raw_recon(item)


def _validate_assessment_fields(
    value: Any, partial: bool = False
) -> Dict[str, str]:
    if not isinstance(value, dict):
        raise BackendError(
            "invalid_assessment", "assessment must be a JSON object"
        )
    if set(value) - ASSESSMENT_EDITABLE_FIELDS:
        raise BackendError(
            "invalid_assessment", "assessment contains unknown fields"
        )
    if partial and not value:
        raise BackendError(
            "invalid_assessment", "assessment update is empty"
        )
    if not partial and set(value) != ASSESSMENT_EDITABLE_FIELDS:
        missing = sorted(ASSESSMENT_EDITABLE_FIELDS - set(value))
        raise BackendError(
            "invalid_assessment",
            "assessment is missing fields: {0}".format(", ".join(missing)),
        )

    result = {}
    if "name" in value:
        result["name"] = _clean_text(value["name"], "name", 1, 100)
    if "location" in value:
        result["location"] = _clean_text(
            value["location"], "location", 0, 200
        )
    if "notes" in value:
        result["notes"] = _clean_text(value["notes"], "notes", 0, 2000)
    return result


def _validate_snapshot(value: Any) -> Dict[str, Any]:
    snapshot = _json_clone(value, "invalid_snapshot", "snapshot")
    if not isinstance(snapshot, dict) or set(snapshot) not in (
        SNAPSHOT_FIELDS,
        SNAPSHOT_FIELDS | {"snapshot_record_digest"},
    ):
        raise BackendError(
            "invalid_snapshot", "snapshot fields do not match schema 1.0"
        )
    _ensure_no_raw_recon(snapshot)
    if snapshot.get("schema_version") not in SUPPORTED_SCHEMA_VERSIONS:
        raise BackendError(
            "invalid_snapshot", "snapshot schema_version is unsupported"
        )
    if not isinstance(snapshot.get("snapshot_id"), str) or not (
        SNAPSHOT_ID_PATTERN.match(snapshot["snapshot_id"])
    ):
        raise BackendError("invalid_snapshot", "snapshot_id is invalid")
    if not isinstance(snapshot.get("snapshot_digest"), str) or not (
        SNAPSHOT_DIGEST_PATTERN.match(snapshot["snapshot_digest"])
    ):
        raise BackendError("invalid_snapshot", "snapshot_digest is invalid")
    record_digest = snapshot.get("snapshot_record_digest")
    if record_digest is not None and (
        not isinstance(record_digest, str)
        or not SNAPSHOT_DIGEST_PATTERN.match(record_digest)
        or record_digest != _snapshot_record_digest(snapshot)
    ):
        raise BackendError(
            "invalid_snapshot", "snapshot_record_digest is invalid"
        )
    observed_at = validate_rfc3339(
        snapshot.get("observed_at"),
        "observed_at",
        "invalid_snapshot",
        nullable=True,
    )
    for field in (
        "scan_metadata",
        "comparability_profile",
        "summary",
    ):
        if not isinstance(snapshot.get(field), dict):
            raise BackendError(
                "invalid_snapshot", "{0} must be an object".format(field)
            )
    scan_metadata = snapshot["scan_metadata"]
    scan_times = {
        field: validate_rfc3339(
            scan_metadata.get(field),
            field,
            "invalid_snapshot",
            nullable=True,
        )
        for field in ("date", "started_at", "completed_at")
    }
    if (
        scan_times["started_at"] is not None
        and scan_times["completed_at"] is not None
        and rfc3339_order_key(scan_times["started_at"])
        > rfc3339_order_key(scan_times["completed_at"])
    ):
        raise BackendError(
            "invalid_snapshot", "completed_at must not precede started_at"
        )
    expected_observed_at = (
        scan_times["completed_at"]
        or scan_times["date"]
        or scan_times["started_at"]
    )
    if observed_at != expected_observed_at:
        raise BackendError(
            "invalid_snapshot",
            "observed_at must match normalized scan metadata",
        )
    access_points = snapshot.get("access_points")
    networks = snapshot.get("networks")
    evidence = snapshot.get("evidence")
    if not isinstance(access_points, list) or len(access_points) > 1000:
        raise BackendError(
            "invalid_snapshot",
            "access_points must contain at most 1000 items",
        )
    if not isinstance(networks, list) or len(networks) > 1000:
        raise BackendError(
            "invalid_snapshot", "networks must contain at most 1000 items"
        )
    if not isinstance(evidence, list) or len(evidence) > 1000:
        raise BackendError(
            "invalid_snapshot", "evidence must contain at most 1000 items"
        )

    asset_ids = set()
    evidence_ids = set()
    for access_point in access_points:
        if (
            not isinstance(access_point, dict)
            or set(access_point) != SNAPSHOT_AP_FIELDS
        ):
            raise BackendError(
                "invalid_snapshot", "access point fields are invalid"
            )
        if not isinstance(access_point["asset_id"], str) or not (
            ASSET_ID_PATTERN.match(access_point["asset_id"])
        ):
            raise BackendError("invalid_snapshot", "asset_id is invalid")
        if access_point["asset_id"] in asset_ids:
            raise BackendError(
                "invalid_snapshot", "asset_id values must be unique"
            )
        if not isinstance(access_point["network_id"], str) or not (
            NETWORK_ID_PATTERN.match(access_point["network_id"])
        ):
            raise BackendError("invalid_snapshot", "network_id is invalid")
        if not isinstance(access_point["evidence_id"], str) or not (
            EVIDENCE_ID_PATTERN.match(access_point["evidence_id"])
        ):
            raise BackendError("invalid_snapshot", "evidence_id is invalid")
        asset_ids.add(access_point["asset_id"])
        evidence_ids.add(access_point["evidence_id"])

    network_ids = set()
    for network in networks:
        if (
            not isinstance(network, dict)
            or set(network) != SNAPSHOT_NETWORK_FIELDS
        ):
            raise BackendError(
                "invalid_snapshot", "network fields are invalid"
            )
        if not isinstance(network["network_id"], str) or not (
            NETWORK_ID_PATTERN.match(network["network_id"])
        ):
            raise BackendError("invalid_snapshot", "network_id is invalid")
        if network["network_id"] in network_ids:
            raise BackendError(
                "invalid_snapshot", "network_id values must be unique"
            )
        if not isinstance(network["asset_ids"], list) or not set(
            network["asset_ids"]
        ).issubset(asset_ids):
            raise BackendError(
                "invalid_snapshot",
                "network asset_ids must reference snapshot assets",
            )
        network_ids.add(network["network_id"])

    for access_point in access_points:
        if access_point["network_id"] not in network_ids:
            raise BackendError(
                "invalid_snapshot",
                "access point network_id must reference a snapshot network",
            )
    evidence_record_ids = set()
    for record in evidence:
        if (
            not isinstance(record, dict)
            or set(record) != SNAPSHOT_EVIDENCE_FIELDS
        ):
            raise BackendError(
                "invalid_snapshot", "evidence record fields are invalid"
            )
        evidence_id = record["evidence_id"]
        if not isinstance(evidence_id, str) or not (
            EVIDENCE_ID_PATTERN.match(evidence_id)
        ):
            raise BackendError("invalid_snapshot", "evidence_id is invalid")
        if evidence_id in evidence_record_ids:
            raise BackendError(
                "invalid_snapshot", "evidence_id values must be unique"
            )
        if record["snapshot_id"] != snapshot["snapshot_id"]:
            raise BackendError(
                "invalid_snapshot",
                "evidence snapshot_id must reference its snapshot",
            )
        if record["subject_id"] not in asset_ids:
            raise BackendError(
                "invalid_snapshot",
                "evidence subject_id must reference a snapshot asset",
            )
        if (
            record["evidence_type"]
            != "recon_access_point_observation"
            or not isinstance(record["observed"], dict)
        ):
            raise BackendError(
                "invalid_snapshot", "evidence record is invalid"
            )
        evidence_record_ids.add(evidence_id)
    if evidence_record_ids != evidence_ids:
        raise BackendError(
            "invalid_snapshot",
            "evidence records must match access point evidence IDs",
        )
    return snapshot


def _bind_snapshot_record_digest(value: Any) -> Dict[str, Any]:
    """Validate a snapshot and bind all new immutable writes to its contents."""
    snapshot = _validate_snapshot(value)
    if "snapshot_record_digest" not in snapshot:
        snapshot["snapshot_record_digest"] = _snapshot_record_digest(snapshot)
    return snapshot


def _validate_comparison(value: Any) -> Dict[str, Any]:
    comparison = _json_clone(
        value, "invalid_comparison", "comparison"
    )
    if not isinstance(comparison, dict) or set(comparison) != COMPARISON_FIELDS:
        raise BackendError(
            "invalid_comparison",
            "comparison fields do not match schema 1.0",
        )
    _ensure_no_raw_recon(comparison)
    if comparison.get("schema_version") not in SUPPORTED_SCHEMA_VERSIONS:
        raise BackendError(
            "invalid_comparison", "comparison schema_version is unsupported"
        )
    for field in ("baseline_snapshot_id", "current_snapshot_id"):
        if not isinstance(comparison.get(field), str) or not (
            SNAPSHOT_ID_PATTERN.match(comparison[field])
        ):
            raise BackendError(
                "invalid_comparison", "{0} is invalid".format(field)
            )
    comparability = comparison.get("comparability")
    if (
        not isinstance(comparability, dict)
        or comparability.get("status") not in COMPARABILITY_STATUSES
        or not isinstance(
            comparability.get("absence_findings_allowed"), bool
        )
    ):
        raise BackendError(
            "invalid_comparison", "comparability is invalid"
        )
    if (
        comparability["absence_findings_allowed"]
        != (comparability["status"] == "comparable")
    ):
        raise BackendError(
            "invalid_comparison",
            "absence finding policy conflicts with comparability",
        )
    for field in ("access_points", "networks", "summary"):
        if not isinstance(comparison.get(field), dict):
            raise BackendError(
                "invalid_comparison",
                "{0} must be an object".format(field),
            )
    return comparison


def _validate_stored_comparison_record(
    value: Any,
    assessment_id: str,
    comparison_id: str,
) -> Dict[str, Any]:
    """Fail closed on immutable legacy and customer comparison records."""
    try:
        record = _json_clone(
            value,
            "storage_error",
            "stored comparison",
            MAX_DOCUMENT_BYTES,
        )
        if not isinstance(record, dict):
            raise ValueError()
        schema_version = record.get("schema_version")
        expected_fields = (
            CUSTOMER_STORED_COMPARISON_FIELDS
            if schema_version == "1.2"
            else STORED_COMPARISON_FIELDS
        )
        if (
            schema_version not in SUPPORTED_SCHEMA_VERSIONS
            or set(record) != expected_fields
            or record.get("assessment_id") != assessment_id
            or record.get("comparison_id") != comparison_id
            or not BASELINE_VERSION_ID_PATTERN.match(
                str(record.get("baseline_version_id", ""))
            )
            or not SNAPSHOT_ID_PATTERN.match(
                str(record.get("baseline_snapshot_id", ""))
            )
            or not SNAPSHOT_ID_PATTERN.match(
                str(record.get("current_snapshot_id", ""))
            )
            or not SNAPSHOT_DIGEST_PATTERN.match(
                str(record.get("current_snapshot_digest", ""))
            )
            or record.get("comparability_status")
            not in COMPARABILITY_STATUSES
        ):
            raise ValueError()
        validate_rfc3339(
            record.get("created_at"),
            "created_at",
            "storage_error",
        )
        finding_ids = record.get("observed_finding_ids")
        if (
            not isinstance(finding_ids, list)
            or len(finding_ids) > MAX_FINDINGS
            or finding_ids != sorted(set(finding_ids))
            or any(
                not isinstance(item, str)
                or not FINDING_ID_PATTERN.match(item)
                for item in finding_ids
            )
        ):
            raise ValueError()
        lifecycle = record.get("lifecycle")
        if (
            not isinstance(lifecycle, dict)
            or set(lifecycle) != COMPARISON_LIFECYCLE_FIELDS
            or not isinstance(lifecycle.get("mutated"), bool)
            or lifecycle["mutated"]
            != (record["comparability_status"] != "not_comparable")
        ):
            raise ValueError()
        lifecycle_ids = set()
        for field in COMPARISON_LIFECYCLE_FIELDS - {"mutated"}:
            values = lifecycle.get(field)
            if (
                not isinstance(values, list)
                or len(values) > MAX_FINDINGS
                or len(values) != len(set(values))
                or any(
                    not isinstance(item, str)
                    or not FINDING_ID_PATTERN.match(item)
                    for item in values
                )
                or lifecycle_ids.intersection(values)
            ):
                raise ValueError()
            lifecycle_ids.update(values)
        expected_observed_ids = set(lifecycle["opened"])
        expected_observed_ids.update(lifecycle["reopened"])
        expected_observed_ids.update(lifecycle["updated"])
        expected_observed_ids.update(lifecycle["preserved_false_positive"])
        if expected_observed_ids != set(finding_ids):
            raise ValueError()
        nested = _validate_comparison(record.get("comparison"))
        if (
            nested["baseline_snapshot_id"]
            != record["baseline_snapshot_id"]
            or nested["current_snapshot_id"]
            != record["current_snapshot_id"]
            or nested["comparability"]["status"]
            != record["comparability_status"]
        ):
            raise ValueError()
        if schema_version == "1.2":
            if (
                not OCCURRENCE_SET_ID_PATTERN.match(
                    str(record.get("occurrence_set_id", ""))
                )
                or not SNAPSHOT_DIGEST_PATTERN.match(
                    str(record.get("occurrence_digest", ""))
                )
            ):
                raise ValueError()
            pins = record.get("pinned_versions")
            if (
                not isinstance(pins, dict)
                or set(pins) != CUSTOMER_ANALYSIS_PIN_FIELDS
                or pins.get("baseline_version_id")
                != record["baseline_version_id"]
                or not SNAPSHOT_DIGEST_PATTERN.match(
                    str(pins.get("baseline_digest", ""))
                )
            ):
                raise ValueError()
            measurement_pin = (
                pins.get("measurement_profile_id"),
                pins.get("measurement_profile_version_id"),
                pins.get("measurement_profile_digest"),
            )
            if any(item is not None for item in measurement_pin) and not (
                isinstance(measurement_pin[0], str)
                and MEASUREMENT_PROFILE_ID_PATTERN.match(measurement_pin[0])
                and isinstance(measurement_pin[1], str)
                and MEASUREMENT_PROFILE_VERSION_ID_PATTERN.match(
                    measurement_pin[1]
                )
                and isinstance(measurement_pin[2], str)
                and SNAPSHOT_DIGEST_PATTERN.match(measurement_pin[2])
            ):
                raise ValueError()
            assurance_pin = (
                pins.get("assurance_profile_version_id"),
                pins.get("assurance_profile_digest"),
            )
            if any(item is not None for item in assurance_pin) and not (
                isinstance(assurance_pin[0], str)
                and ASSURANCE_PROFILE_VERSION_ID_PATTERN.match(
                    assurance_pin[0]
                )
                and isinstance(assurance_pin[1], str)
                and SNAPSHOT_DIGEST_PATTERN.match(assurance_pin[1])
            ):
                raise ValueError()
        _ensure_no_raw_recon(record)
        return record
    except BackendError as error:
        if error.code == "storage_error":
            raise
        raise BackendError(
            "storage_error", "comparison is invalid"
        ) from error
    except (TypeError, ValueError):
        raise BackendError("storage_error", "comparison is invalid")


def _validate_finding_core(value: Any) -> Dict[str, Any]:
    finding = _json_clone(value, "invalid_finding", "finding", 262144)
    if not isinstance(finding, dict) or set(finding) != FINDING_CORE_FIELDS:
        raise BackendError(
            "invalid_finding", "finding fields do not match schema 1.0"
        )
    _ensure_no_raw_recon(finding)
    if not isinstance(finding.get("finding_id"), str) or not (
        FINDING_ID_PATTERN.match(finding["finding_id"])
    ):
        raise BackendError("invalid_finding", "finding_id is invalid")
    for field in ("rule_id", "title", "subject_id", "summary"):
        if not isinstance(finding.get(field), str) or not finding[field]:
            raise BackendError(
                "invalid_finding", "{0} is invalid".format(field)
            )
    if len(finding["rule_id"]) > 100 or len(finding["title"]) > 200:
        raise BackendError("invalid_finding", "finding text is too long")
    if len(finding["subject_id"]) > 100 or len(finding["summary"]) > 1000:
        raise BackendError("invalid_finding", "finding text is too long")
    if finding.get("severity") not in SEVERITIES:
        raise BackendError("invalid_finding", "severity is invalid")
    confidence = finding.get("confidence")
    if (
        not isinstance(confidence, (int, float))
        or isinstance(confidence, bool)
        or confidence < 0
        or confidence > 1
    ):
        raise BackendError("invalid_finding", "confidence is invalid")
    evidence_ids = finding.get("evidence_ids")
    if not isinstance(evidence_ids, list) or len(evidence_ids) > 100:
        raise BackendError(
            "invalid_finding",
            "evidence_ids must contain at most 100 values",
        )
    if len(set(evidence_ids)) != len(evidence_ids):
        raise BackendError(
            "invalid_finding", "evidence_ids must be unique"
        )
    for evidence_id in evidence_ids:
        if not isinstance(evidence_id, str) or not (
            EVIDENCE_ID_PATTERN.match(evidence_id)
        ):
            raise BackendError(
                "invalid_finding", "evidence_id is invalid"
            )
    if not isinstance(finding.get("details"), dict) or not isinstance(
        finding.get("confidence_factors"), dict
    ):
        raise BackendError(
            "invalid_finding",
            "details and confidence_factors must be objects",
        )
    return finding


CACHE_MAX_ITEMS = 64
CACHE_MAX_SERIALIZED_BYTES = 4 * 1024 * 1024
CACHE_MAX_ITEM_BYTES = 256 * 1024


class AssessmentStore:
    """Store assessments, immutable baselines, comparisons, and findings."""

    def __init__(
        self,
        config_dir: Optional[str] = None,
        fault_injector=None,
    ):
        self.directory = resolve_config_dir(config_dir) / "assessments"
        self.fault_injector = fault_injector
        self._mtime_cache = collections.OrderedDict()
        self._mtime_cache_lock = threading.RLock()
        self._mtime_cache_total_bytes = 0
        self._mtime_cache_hits = 0
        self._mtime_cache_misses = 0
        self._mtime_cache_evictions = 0
        self._assessment_lock_state = threading.local()
        self._assessment_read_state = threading.local()

    def _invalidate_cache(self, path: Optional[Path] = None) -> None:
        with self._mtime_cache_lock:
            if path is None:
                self._mtime_cache.clear()
                self._mtime_cache_total_bytes = 0
            else:
                try:
                    resolved_str = str(path.resolve())
                    keys = [k for k in self._mtime_cache if k[0] == resolved_str]
                    for k in keys:
                        entry = self._mtime_cache.pop(k, None)
                        if entry:
                            self._mtime_cache_total_bytes -= entry.get("size", 0)
                except OSError:
                    self._mtime_cache.clear()
                    self._mtime_cache_total_bytes = 0

    def _ensure_private_directory(self, path: Path) -> None:
        try:
            details = path.lstat()
        except FileNotFoundError:
            path.mkdir(parents=True, exist_ok=False)
            details = path.lstat()
        except OSError as error:
            raise BackendError(
                "storage_error", "private storage directory is unavailable"
            ) from error
        if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(
            details.st_mode
        ):
            raise BackendError(
                "storage_error",
                "private storage directory must be a real directory",
            )
        try:
            os.chmod(str(path), 0o700)
        except OSError:
            pass

    def _validate_assessment_id(self, assessment_id: Any) -> str:
        if not isinstance(assessment_id, str) or not (
            ASSESSMENT_ID_PATTERN.match(assessment_id)
        ):
            raise BackendError(
                "invalid_assessment_id", "assessment_id is invalid"
            )
        return assessment_id

    def _assessment_paths(
        self, assessment_id: str
    ) -> Tuple[Path, Path, Path, Path, Path]:
        self._validate_assessment_id(assessment_id)
        base = self.directory / assessment_id
        return (
            base,
            base / "assessment.json",
            base / "events.jsonl",
            base / "findings.json",
            base / ".lock",
        )

    def _ensure_assessment_directories(self, assessment_id: str) -> Path:
        self._ensure_private_directory(self.directory)
        base, _, _, _, _ = self._assessment_paths(assessment_id)
        self._ensure_private_directory(base)
        for name in ("baselines", "snapshots", "comparisons"):
            self._ensure_private_directory(base / name)
        return base

    @contextmanager
    def _exclusive_file_lock(self, lock_path: Path):
        self._ensure_private_directory(lock_path.parent)
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(str(lock_path), flags, 0o600)
            details = os.fstat(descriptor)
            if not stat.S_ISREG(details.st_mode) or lock_path.is_symlink():
                raise OSError("lock path is not a regular file")
            descriptor_chmod = getattr(os, "fchmod", None)
            if descriptor_chmod is not None:
                try:
                    descriptor_chmod(descriptor, 0o600)
                except OSError:
                    pass
            else:
                try:
                    os.chmod(str(lock_path), 0o600)
                except OSError:
                    pass
            if details.st_size == 0:
                os.write(descriptor, b"\0")
                os.fsync(descriptor)
        except OSError as error:
            if "descriptor" in locals():
                os.close(descriptor)
            raise BackendError(
                "storage_busy", "assessment storage lock is unavailable"
            ) from error

        lock_backend = None
        deadline = time.monotonic() + 2.0
        while lock_backend is None:
            try:
                if os.name == "nt":
                    import msvcrt

                    os.lseek(descriptor, 0, os.SEEK_SET)
                    msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                    lock_backend = ("msvcrt", msvcrt)
                else:
                    import fcntl

                    fcntl.flock(
                        descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB
                    )
                    lock_backend = ("fcntl", fcntl)
            except (BlockingIOError, OSError):
                if time.monotonic() >= deadline:
                    os.close(descriptor)
                    raise BackendError(
                        "storage_busy", "assessment storage is busy"
                    )
                time.sleep(0.05)
        try:
            yield
        finally:
            try:
                if lock_backend[0] == "msvcrt":
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    lock_backend[1].locking(
                        descriptor, lock_backend[1].LK_UNLCK, 1
                    )
                else:
                    lock_backend[1].flock(
                        descriptor, lock_backend[1].LOCK_UN
                    )
            finally:
                os.close(descriptor)

    @contextmanager
    def _lock(self, assessment_id: str):
        held = getattr(self._assessment_lock_state, "held", {})
        if held.get(assessment_id, 0):
            held[assessment_id] += 1
            self._assessment_lock_state.held = held
            try:
                yield
            finally:
                held[assessment_id] -= 1
            return
        self._ensure_assessment_directories(assessment_id)
        base, _, _, _, lock_path = self._assessment_paths(assessment_id)
        with self._exclusive_file_lock(lock_path):
            held = dict(held)
            held[assessment_id] = 1
            self._assessment_lock_state.held = held
            try:
                recover_private_transactions(
                    base, cleanup_unprepared=True
                )
                yield
            finally:
                held.pop(assessment_id, None)
                self._assessment_lock_state.held = held

    @contextmanager
    def _read_session(self, assessment_id: str):
        """Hold one consistent read lock and validate the event log once."""
        sessions = getattr(self._assessment_read_state, "sessions", {})
        if assessment_id in sessions:
            yield
            return
        with self._lock(assessment_id):
            events = self._read_events(assessment_id)
            metadata = self._read_metadata(
                assessment_id, validated_events=events
            )
            sessions = dict(sessions)
            sessions[assessment_id] = {
                "metadata": metadata,
                "events": events,
            }
            self._assessment_read_state.sessions = sessions
            try:
                yield
            finally:
                sessions = dict(
                    getattr(self._assessment_read_state, "sessions", {})
                )
                sessions.pop(assessment_id, None)
                self._assessment_read_state.sessions = sessions

    def _read_private_bytes(
        self,
        path: Path,
        missing_code: str,
        missing_message: str,
        maximum_bytes: int = MAX_DOCUMENT_BYTES,
    ):
        try:
            stat_before = path.lstat()
            if (
                stat.S_ISLNK(stat_before.st_mode)
                or not stat.S_ISREG(stat_before.st_mode)
                or stat_before.st_size > maximum_bytes
            ):
                raise OSError("stored path or size is invalid")
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(str(path), flags)
            try:
                opened = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or opened.st_size != stat_before.st_size
                    or getattr(opened, "st_ino", 0)
                    != getattr(stat_before, "st_ino", 0)
                ):
                    raise OSError("stored data changed while opening")
                chunks = []
                remaining = opened.st_size
                while remaining:
                    chunk = os.read(
                        descriptor, min(64 * 1024, remaining)
                    )
                    if not chunk:
                        raise OSError("stored data was truncated")
                    chunks.append(chunk)
                    remaining -= len(chunk)
                if os.read(descriptor, 1):
                    raise OSError("stored data exceeded its size")
                return b"".join(chunks), opened
            finally:
                os.close(descriptor)
        except FileNotFoundError:
            raise BackendError(missing_code, missing_message)
        except OSError as error:
            raise BackendError(
                "storage_error", "stored assessment data could not be read"
            ) from error

    def _read_json(
        self,
        path: Path,
        missing_code: str,
        missing_message: str,
        invalid_code: Optional[str] = None,
    ) -> Any:
        try:
            payload, stat_before = self._read_private_bytes(
                path, missing_code, missing_message
            )
            cache_key = (
                str(path.absolute()),
                stat_before.st_mtime_ns,
                stat_before.st_size,
                getattr(stat_before, "st_ino", 0),
            )
            with self._mtime_cache_lock:
                if cache_key in self._mtime_cache:
                    self._mtime_cache.move_to_end(cache_key)
                    self._mtime_cache_hits += 1
                    return copy.deepcopy(self._mtime_cache[cache_key]["value"])
                self._mtime_cache_misses += 1

            value = json.loads(payload.decode("utf-8"))
            item_bytes = stat_before.st_size
            if item_bytes <= CACHE_MAX_ITEM_BYTES and item_bytes <= CACHE_MAX_SERIALIZED_BYTES:
                with self._mtime_cache_lock:
                    resolved_str = str(path.absolute())
                    old_keys = [k for k in self._mtime_cache if k[0] == resolved_str]
                    for k in old_keys:
                        old_entry = self._mtime_cache.pop(k, None)
                        if old_entry:
                            self._mtime_cache_total_bytes -= old_entry.get("size", 0)

                    self._mtime_cache[cache_key] = {
                        "value": value,
                        "size": item_bytes,
                    }
                    self._mtime_cache_total_bytes += item_bytes

                    while (
                        len(self._mtime_cache) > CACHE_MAX_ITEMS
                        or self._mtime_cache_total_bytes > CACHE_MAX_SERIALIZED_BYTES
                    ) and self._mtime_cache:
                        _, evicted = self._mtime_cache.popitem(last=False)
                        self._mtime_cache_total_bytes -= evicted.get("size", 0)
                        self._mtime_cache_evictions += 1

            return copy.deepcopy(value)
        except BackendError:
            raise
        except (UnicodeError, ValueError):
            raise BackendError(
                invalid_code or "storage_error",
                "stored assessment data could not be read",
            )

    def _write_json(self, path: Path, value: Any) -> None:
        self._invalidate_cache(path)
        payload = json.dumps(
            value, ensure_ascii=False, indent=2, sort_keys=True
        ).encode("utf-8") + b"\n"
        write_private_file(path, payload)

    def _transaction(
        self, root: Path, json_documents: Dict[str, Any], bytes_documents=None
    ):
        transaction = PrivateTransaction(
            root, getattr(self, "fault_injector", None)
        )
        for relative, value in sorted(json_documents.items()):
            transaction.add_json(relative, value)
        for relative, value in sorted((bytes_documents or {}).items()):
            transaction.add_bytes(relative, value)
        return transaction.commit()

    def _staged_event(
        self,
        metadata: Dict[str, Any],
        event_type: str,
        data: Optional[Dict[str, Any]] = None,
    ):
        migration_from = metadata.pop(
            "_pending_storage_schema_migration_from", None
        )
        event_specs = []
        if migration_from is not None:
            event_specs.append(
                (
                    "storage_schema_migrated",
                    {
                        "from_schema_version": migration_from,
                        "to_schema_version": ASSESSMENT_SCHEMA_VERSION,
                    },
                )
            )
        event_specs.append((event_type, data))
        if (
            metadata["last_event_sequence"] + len(event_specs)
            > MAX_EVENTS
        ):
            raise BackendError(
                "event_limit", "assessment event limit was reached"
            )
        _, _, event_path, _, _ = self._assessment_paths(
            metadata["assessment_id"]
        )
        persisted_events = self._read_events(metadata["assessment_id"])
        persisted_sequence = (
            persisted_events[-1]["sequence"] if persisted_events else 0
        )
        if persisted_sequence != metadata["last_event_sequence"]:
            raise BackendError(
                "storage_error",
                "assessment event cursor is inconsistent",
            )
        if event_path.exists() or event_path.is_symlink():
            previous, _ = self._read_private_bytes(
                event_path,
                "storage_error",
                "assessment audit events are invalid",
            )
        else:
            previous = b""
        payload = bytearray(previous)
        primary_event = None
        for current_type, current_data in event_specs:
            event = {
                "sequence": metadata["last_event_sequence"] + 1,
                "event_id": "evt_{0}".format(uuid.uuid4()),
                "event_type": current_type,
                "recorded_at": metadata["updated_at"],
                "revision": metadata["revision"],
            }
            if current_data:
                event["data"] = current_data
            metadata["last_event_sequence"] = event["sequence"]
            payload.extend(
                json.dumps(
                    event,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            )
            payload.extend(b"\n")
            primary_event = event
        if len(payload) > MAX_DOCUMENT_BYTES:
            raise BackendError(
                "event_limit", "assessment event storage size limit was reached"
            )
        return primary_event, bytes(payload)

    def _transaction_event(
        self,
        assessment_id: str,
        metadata: Dict[str, Any],
        event_type: str,
        data: Optional[Dict[str, Any]],
    ):
        if metadata.get("assessment_id") != assessment_id:
            raise BackendError(
                "storage_error", "assessment event identity is inconsistent"
            )
        self._advance_revision(metadata)
        return self._staged_event(metadata, event_type, data)

    def _append_event_file(self, path: Path, event: Dict[str, Any]) -> None:
        self._ensure_private_directory(path.parent)
        payload = (
            json.dumps(
                event,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        descriptor = None
        try:
            flags = (
                os.O_CREAT
                | os.O_APPEND
                | os.O_WRONLY
                | getattr(os, "O_BINARY", 0)
            )
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(
                str(path),
                flags,
                0o600,
            )
            details = os.fstat(descriptor)
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_size + len(payload) > MAX_DOCUMENT_BYTES
            ):
                raise BackendError(
                    "event_limit",
                    "assessment event storage size limit was reached",
                )
            with os.fdopen(descriptor, "ab") as handle:
                descriptor = None
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.chmod(str(path), 0o600)
            except OSError:
                pass
        except BackendError:
            raise
        except OSError as error:
            raise BackendError(
                "storage_error", "assessment event could not be written"
            ) from error
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _read_metadata(
        self,
        assessment_id: str,
        validated_events: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        session = getattr(
            self._assessment_read_state, "sessions", {}
        ).get(assessment_id)
        if session is not None:
            return session["metadata"]
        _, metadata_path, _, _, _ = self._assessment_paths(assessment_id)
        metadata = self._read_json(
            metadata_path,
            "assessment_not_found",
            "assessment was not found",
        )
        if (
            not isinstance(metadata, dict)
            or metadata.get("assessment_id") != assessment_id
            or metadata.get("schema_version")
            not in SUPPORTED_ASSESSMENT_SCHEMA_VERSIONS
            or metadata.get("status") not in ASSESSMENT_STATUSES
            or not isinstance(metadata.get("revision"), int)
            or isinstance(metadata.get("revision"), bool)
            or metadata.get("revision", 0) < 1
            or not isinstance(metadata.get("last_event_sequence"), int)
            or isinstance(metadata.get("last_event_sequence"), bool)
            or metadata.get("last_event_sequence", -1) < 0
            or metadata.get("last_event_sequence", MAX_EVENTS + 1)
            > MAX_EVENTS
        ):
            raise BackendError(
                "storage_error", "assessment metadata is invalid"
            )
        # Legacy metadata is adapted in memory. Immutable v0.6.0/v0.6.1
        # documents are never rewritten merely because they were read.
        metadata.setdefault("active_assurance_profile_version", None)
        metadata.setdefault("storage_writer_version", metadata["schema_version"])
        created_time = _stored_timestamp(metadata.get("created_at"))
        updated_time = _stored_timestamp(metadata.get("updated_at"))
        if updated_time < created_time:
            raise BackendError(
                "storage_error",
                "assessment timestamps are inconsistent",
            )
        events = (
            validated_events
            if validated_events is not None
            else self._read_events(assessment_id)
        )
        if not events:
            raise BackendError(
                "storage_error", "assessment creation history is missing"
            )
        event_sequence = events[-1]["sequence"] if events else 0
        if event_sequence != metadata["last_event_sequence"]:
            raise BackendError(
                "storage_error",
                "assessment event cursor is inconsistent",
            )
        if events and (
            events[-1]["revision"] != metadata["revision"]
            or _stored_timestamp(events[-1]["recorded_at"])
            > updated_time
        ):
            raise BackendError(
                "storage_error",
                "assessment event revision is inconsistent",
            )
        return metadata

    def _write_metadata(self, metadata: Dict[str, Any]) -> None:
        _, path, _, _, _ = self._assessment_paths(
            metadata["assessment_id"]
        )
        self._write_json(path, metadata)

    def _read_events(self, assessment_id: str) -> List[Dict[str, Any]]:
        session = getattr(
            self._assessment_read_state, "sessions", {}
        ).get(assessment_id)
        if session is not None:
            return session["events"]
        _, _, path, _, _ = self._assessment_paths(assessment_id)
        if not path.exists() and not path.is_symlink():
            return []
        events = []
        expected_sequence = 1
        previous_revision = 0
        previous_event_type = None
        previous_recorded_at = None
        event_ids = set()
        try:
            payload, _ = self._read_private_bytes(
                path,
                "storage_error",
                "assessment audit events are invalid",
            )
            for line in payload.decode("utf-8").splitlines():
                if not line.strip():
                    continue
                event = json.loads(line)
                fields = set(event) if isinstance(event, dict) else set()
                if (
                    not isinstance(event, dict)
                    or fields
                    not in (
                        {
                            "sequence",
                            "event_id",
                            "event_type",
                            "recorded_at",
                            "revision",
                        },
                        {
                            "sequence",
                            "event_id",
                            "event_type",
                            "recorded_at",
                            "revision",
                            "data",
                        },
                    )
                    or event.get("sequence") != expected_sequence
                    or len(events) >= MAX_EVENTS
                    or not isinstance(event.get("event_id"), str)
                    or not EVENT_ID_PATTERN.match(event["event_id"])
                    or event["event_id"] in event_ids
                    or not isinstance(event.get("event_type"), str)
                    or not EVENT_TYPE_PATTERN.match(event["event_type"])
                    or not isinstance(event.get("revision"), int)
                    or isinstance(event.get("revision"), bool)
                    or event["revision"] < 1
                    or (
                        expected_sequence == 1
                        and (
                            event["revision"] != 1
                            or event["event_type"]
                            != "assessment_created"
                        )
                    )
                    or (
                        expected_sequence > 1
                        and event["revision"]
                        not in (
                            previous_revision,
                            previous_revision + 1,
                        )
                    )
                    or (
                        expected_sequence > 1
                        and event["revision"] == previous_revision
                        and (
                            previous_event_type
                            != "storage_schema_migrated"
                            or event["event_type"]
                            == "storage_schema_migrated"
                        )
                    )
                    or (
                        "data" in event
                        and not isinstance(event.get("data"), dict)
                    )
                ):
                    raise ValueError()
                recorded_at = _stored_timestamp(event.get("recorded_at"))
                if (
                    previous_recorded_at is not None
                    and recorded_at < previous_recorded_at
                ):
                    raise ValueError()
                if "data" in event:
                    try:
                        _ensure_no_raw_recon(event["data"])
                    except BackendError as error:
                        raise ValueError() from error
                events.append(event)
                event_ids.add(event["event_id"])
                previous_revision = event["revision"]
                previous_event_type = event["event_type"]
                previous_recorded_at = recorded_at
                expected_sequence += 1
            if previous_event_type == "storage_schema_migrated":
                raise ValueError()
        except BackendError:
            raise
        except (UnicodeError, ValueError):
            raise BackendError(
                "storage_error", "assessment audit events are invalid"
            )
        return events

    def _append_event(
        self,
        metadata: Dict[str, Any],
        event_type: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if metadata["last_event_sequence"] >= MAX_EVENTS:
            raise BackendError(
                "event_limit", "assessment event limit was reached"
            )
        event = {
            "sequence": metadata["last_event_sequence"] + 1,
            "event_id": "evt_{0}".format(uuid.uuid4()),
            "event_type": event_type,
            "recorded_at": metadata["updated_at"],
            "revision": metadata["revision"],
        }
        if data:
            event["data"] = data
        metadata["last_event_sequence"] = event["sequence"]
        _, _, event_path, _, _ = self._assessment_paths(
            metadata["assessment_id"]
        )
        self._append_event_file(event_path, event)
        return event

    def _require_mutable(
        self, metadata: Dict[str, Any], expected_revision: Any
    ) -> None:
        revision = _validate_revision(expected_revision)
        if metadata["revision"] != revision:
            raise BackendError(
                "revision_conflict", "assessment revision has changed"
            )
        if metadata["status"] == "archived":
            raise BackendError(
                "assessment_archived", "assessment is archived"
            )
        if metadata.get("schema_version") == "1.0":
            previous = metadata["schema_version"]
            metadata["schema_version"] = ASSESSMENT_SCHEMA_VERSION
            metadata["storage_writer_version"] = ASSESSMENT_SCHEMA_VERSION
            metadata.setdefault("active_assurance_profile_version", None)
            metadata[
                "_pending_storage_schema_migration_from"
            ] = previous

    def _advance_revision(self, metadata: Dict[str, Any]) -> str:
        now = _utc_now()
        previous = metadata.get("updated_at")
        if isinstance(previous, str):
            try:
                if _stored_timestamp(previous) > _stored_timestamp(now):
                    now = previous
            except BackendError:
                raise BackendError(
                    "storage_error",
                    "assessment updated_at is invalid",
                )
        metadata["revision"] += 1
        metadata["updated_at"] = now
        return now

    def _baseline_path(
        self, assessment_id: str, baseline_version_id: Any
    ) -> Path:
        if not isinstance(baseline_version_id, str) or not (
            BASELINE_VERSION_ID_PATTERN.match(baseline_version_id)
        ):
            raise BackendError(
                "invalid_baseline", "baseline_version_id is invalid"
            )
        base, _, _, _, _ = self._assessment_paths(assessment_id)
        return base / "baselines" / "{0}.json".format(baseline_version_id)

    def _snapshot_path(self, assessment_id: str, snapshot_id: str) -> Path:
        if not SNAPSHOT_ID_PATTERN.match(snapshot_id):
            raise BackendError("invalid_snapshot", "snapshot_id is invalid")
        base, _, _, _, _ = self._assessment_paths(assessment_id)
        return base / "snapshots" / "{0}.json".format(snapshot_id)

    def _bounded_document_paths(
        self,
        directory: Path,
        filename_pattern: re.Pattern,
        maximum: int,
        label: str,
    ) -> List[Path]:
        self._ensure_private_directory(directory)
        results = []
        try:
            with os.scandir(str(directory)) as iterator:
                for entry in iterator:
                    if (
                        not filename_pattern.match(entry.name)
                        or not entry.is_file(follow_symlinks=False)
                    ):
                        raise BackendError(
                            "storage_error",
                            "{0} storage contains an invalid entry".format(
                                label
                            ),
                        )
                    results.append(Path(entry.path))
                    if len(results) > maximum:
                        raise BackendError(
                            "storage_error",
                            "{0} storage exceeds its safe limit".format(
                                label
                            ),
                        )
        except BackendError:
            raise
        except OSError as error:
            raise BackendError(
                "storage_error",
                "{0} storage is unreadable".format(label),
            ) from error
        return sorted(results, key=lambda item: item.name)

    def _preflight_aggregate_document_bytes(
        self,
        paths: List[Path],
        maximum_bytes: int,
        label: str,
    ) -> int:
        """Admit a bounded document set before opening any document body."""
        total_bytes = 0
        for path in paths:
            try:
                details = path.lstat()
            except OSError as error:
                raise BackendError(
                    "storage_error",
                    "{0} storage metadata is unavailable".format(label),
                ) from error
            if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(
                details.st_mode
            ):
                raise BackendError(
                    "storage_error",
                    "{0} storage contains an invalid path".format(label),
                )
            if details.st_size < 2:
                raise BackendError(
                    "storage_error",
                    "{0} storage contains an invalid document".format(label),
                )
            total_bytes += details.st_size
            if total_bytes > maximum_bytes:
                raise BackendError(
                    "storage_limit_exceeded",
                    "{0} listing exceeds the safe aggregate size limit".format(
                        label
                    ),
                )
        return total_bytes

    def _comparison_path(
        self, assessment_id: str, comparison_id: Any
    ) -> Path:
        if not isinstance(comparison_id, str) or not (
            COMPARISON_ID_PATTERN.match(comparison_id)
        ):
            raise BackendError(
                "invalid_comparison", "comparison_id is invalid"
            )
        base, _, _, _, _ = self._assessment_paths(assessment_id)
        return base / "comparisons" / "{0}.json".format(comparison_id)

    def _write_immutable(
        self, path: Path, value: Dict[str, Any], conflict_code: str
    ) -> None:
        if path.exists():
            existing = self._read_json(
                path, conflict_code, "immutable document is missing"
            )
            if existing != value:
                raise BackendError(
                    conflict_code,
                    "immutable document already exists with different content",
                )
            return
        self._write_json(path, value)

    def _immutable_preflight(
        self, path: Path, value: Dict[str, Any], conflict_code: str
    ) -> bool:
        if not path.exists() and not path.is_symlink():
            return True
        if path.is_symlink() or not path.is_file():
            raise BackendError(
                conflict_code, "immutable document path is invalid"
            )
        existing = self._read_json(
            path, conflict_code, "immutable document is missing"
        )
        if existing != value:
            raise BackendError(
                conflict_code,
                "immutable document already exists with different content",
            )
        return False

    def _snapshot_immutable_preflight(
        self, path: Path, value: Dict[str, Any], conflict_code: str
    ) -> bool:
        """Admit a new bound snapshot or reuse an identical legacy snapshot."""
        if not path.exists() and not path.is_symlink():
            return True
        if path.is_symlink() or not path.is_file():
            raise BackendError(
                conflict_code, "immutable snapshot path is invalid"
            )
        try:
            existing = _validate_snapshot(
                self._read_json(
                    path, conflict_code, "immutable snapshot is missing"
                )
            )
        except BackendError as error:
            raise BackendError(
                conflict_code, "immutable snapshot is invalid"
            ) from error
        if existing == value:
            return False
        if (
            "snapshot_record_digest" not in existing
            and value.get("snapshot_record_digest")
            == _snapshot_record_digest(existing)
            and {
                key: item
                for key, item in value.items()
                if key != "snapshot_record_digest"
            }
            == existing
        ):
            return False
        raise BackendError(
            conflict_code,
            "immutable snapshot already exists with different content",
        )

    def _read_findings(self, assessment_id: str) -> List[Dict[str, Any]]:
        _, _, _, path, _ = self._assessment_paths(assessment_id)
        document = self._read_json(
            path, "storage_error", "finding storage was not initialized"
        )
        if (
            not isinstance(document, dict)
            or document.get("schema_version")
            not in SUPPORTED_ASSESSMENT_SCHEMA_VERSIONS
            or not isinstance(document.get("findings"), list)
        ):
            raise BackendError("storage_error", "finding storage is invalid")
        findings = document["findings"]
        if len(findings) > MAX_FINDINGS:
            raise BackendError("storage_error", "finding storage is invalid")
        return findings

    def _write_findings(
        self, assessment_id: str, findings: List[Dict[str, Any]], now: str
    ) -> None:
        _, _, _, path, _ = self._assessment_paths(assessment_id)
        self._write_json(
            path,
            {
                "schema_version": ASSESSMENT_SCHEMA_VERSION,
                "updated_at": now,
                "findings": sorted(
                    findings, key=lambda item: item["finding_id"]
                ),
            },
        )

    def create(self, value: Any) -> Dict[str, Any]:
        fields = _validate_assessment_fields(value)
        assessment_id = "assessment_{0}".format(uuid.uuid4())
        now = _utc_now()
        metadata = {
            "schema_version": ASSESSMENT_SCHEMA_VERSION,
            "assessment_id": assessment_id,
            "name": fields["name"],
            "location": fields["location"],
            "notes": fields["notes"],
            "status": "active",
            "revision": 1,
            "active_baseline_version": None,
            "active_assurance_profile_version": None,
            "storage_writer_version": ASSESSMENT_SCHEMA_VERSION,
            "created_at": now,
            "updated_at": now,
            "last_event_sequence": 0,
        }
        with self._lock(assessment_id):
            base, metadata_path, event_path, findings_path, _ = self._assessment_paths(
                assessment_id
            )
            if metadata_path.exists() or metadata_path.is_symlink():
                raise BackendError(
                    "storage_error", "assessment already exists"
                )
            event, event_bytes = self._staged_event(
                metadata, "assessment_created"
            )
            self._transaction(
                base,
                {
                    metadata_path.name: metadata,
                    findings_path.name: {
                        "schema_version": ASSESSMENT_SCHEMA_VERSION,
                        "updated_at": now,
                        "findings": [],
                    },
                },
                {event_path.name: event_bytes},
            )
        result = dict(metadata)
        result["events"] = [event]
        return result

    def get(
        self, assessment_id: str, after_sequence: int = 0, limit: int = 100
    ) -> Dict[str, Any]:
        if (
            not isinstance(after_sequence, int)
            or isinstance(after_sequence, bool)
            or after_sequence < 0
        ):
            raise BackendError(
                "invalid_request", "after_sequence must be non-negative"
            )
        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or limit < 1
            or limit > 100
        ):
            raise BackendError(
                "invalid_request", "limit must be between 1 and 100"
            )
        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            selected = [
                event
                for event in self._read_events(assessment_id)
                if event["sequence"] > after_sequence
            ][:limit]
        result = dict(metadata)
        result["events"] = selected
        result["events_has_more"] = bool(
            selected
            and selected[-1]["sequence"]
            < metadata["last_event_sequence"]
        )
        return result

    def list(self, include_archived: bool = False) -> List[Dict[str, Any]]:
        if not isinstance(include_archived, bool):
            raise BackendError(
                "invalid_request", "include_archived must be a boolean"
            )
        if not self.directory.exists():
            return []
        results = []
        paths = []
        try:
            with os.scandir(str(self.directory)) as iterator:
                for entry in iterator:
                    if entry.name == ".lock":
                        continue
                    if (
                        not ASSESSMENT_ID_PATTERN.match(entry.name)
                        or not entry.is_dir(follow_symlinks=False)
                    ):
                        raise BackendError(
                            "storage_error",
                            "assessment storage contains an invalid entry",
                        )
                    paths.append(Path(entry.path))
                    if len(paths) > 1000:
                        raise BackendError(
                            "storage_error",
                            "assessment storage exceeds its safe limit",
                        )
        except BackendError:
            raise
        except OSError as error:
            raise BackendError(
                "storage_error", "assessment storage is unreadable"
            ) from error
        for path in sorted(paths, key=lambda item: item.name):
            try:
                with self._lock(path.name):
                    metadata = self._read_metadata(path.name)
            except BackendError as error:
                if error.code == "assessment_not_found":
                    continue
                raise
            if include_archived or metadata["status"] != "archived":
                results.append(metadata)
        return sorted(
            results,
            key=lambda item: (item["updated_at"], item["assessment_id"]),
            reverse=True,
        )

    def update(
        self, assessment_id: str, expected_revision: Any, changes: Any
    ) -> Dict[str, Any]:
        validated = _validate_assessment_fields(changes, partial=True)
        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_revision)
            changed_fields = [
                field
                for field, new_value in validated.items()
                if metadata.get(field) != new_value
            ]
            if not changed_fields:
                raise BackendError(
                    "no_changes", "assessment update did not change values"
                )
            for field in changed_fields:
                metadata[field] = validated[field]
            event, event_bytes = self._transaction_event(
                assessment_id,
                metadata,
                "assessment_updated",
                {"changed_fields": sorted(changed_fields)},
            )
            base, _, _, _, _ = self._assessment_paths(assessment_id)
            self._transaction(
                base,
                {"assessment.json": metadata},
                {"events.jsonl": event_bytes},
            )
        result = dict(metadata)
        result["events"] = [event]
        return result

    def archive(
        self, assessment_id: str, expected_revision: Any
    ) -> Dict[str, Any]:
        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_revision)
            metadata["status"] = "archived"
            event, event_bytes = self._transaction_event(
                assessment_id, metadata, "assessment_archived", None
            )
            base, _, _, _, _ = self._assessment_paths(assessment_id)
            self._transaction(
                base,
                {"assessment.json": metadata},
                {"events.jsonl": event_bytes},
            )
        result = dict(metadata)
        result["events"] = [event]
        return result

    def create_baseline_version(
        self,
        assessment_id: str,
        expected_revision: Any,
        snapshot: Any,
        label: Any = "",
    ) -> Dict[str, Any]:
        normalized_snapshot = _bind_snapshot_record_digest(snapshot)
        if (
            not isinstance(label, str)
            or len(label) > 128
            or any(ord(character) < 32 for character in label)
        ):
            raise BackendError(
                "invalid_baseline",
                "label must be a control-free string of at most 128 characters",
            )
        normalized_label = label.strip()
        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_revision)
            base, _, _, _, _ = self._assessment_paths(assessment_id)
            baseline_paths = self._bounded_document_paths(
                base / "baselines",
                re.compile(r"^baseline_v[0-9]{4}\.json$"),
                MAX_BASELINE_VERSIONS,
                "baseline",
            )
            if len(baseline_paths) >= MAX_BASELINE_VERSIONS:
                raise BackendError(
                    "baseline_limit",
                    "assessment baseline version limit was reached",
                )
            numbers = []
            for path in baseline_paths:
                if BASELINE_VERSION_ID_PATTERN.match(path.stem):
                    numbers.append(int(path.stem[-4:]))
            version_number = max(numbers or [0]) + 1
            baseline_version_id = "baseline_v{0:04d}".format(version_number)
            snapshot_path = self._snapshot_path(
                assessment_id, normalized_snapshot["snapshot_id"]
            )
            snapshot_is_new = self._snapshot_immutable_preflight(
                snapshot_path,
                normalized_snapshot,
                "snapshot_conflict",
            )
            if snapshot_is_new and len(
                self._bounded_document_paths(
                    base / "snapshots",
                    re.compile(r"^snapshot_[0-9a-f]{16}\.json$"),
                    MAX_SNAPSHOTS,
                    "snapshot",
                )
            ) >= MAX_SNAPSHOTS:
                raise BackendError(
                    "snapshot_limit",
                    "assessment snapshot limit was reached",
                )
            baseline_path = self._baseline_path(
                assessment_id, baseline_version_id
            )
            event, event_bytes = self._transaction_event(
                assessment_id,
                metadata,
                "baseline_version_created",
                {
                    "baseline_version_id": baseline_version_id,
                    "snapshot_id": normalized_snapshot["snapshot_id"],
                    "snapshot_digest": normalized_snapshot[
                        "snapshot_digest"
                    ],
                },
            )
            record = {
                "schema_version": ASSESSMENT_SCHEMA_VERSION,
                "assessment_id": assessment_id,
                "baseline_version_id": baseline_version_id,
                "version": version_number,
                "label": normalized_label,
                "created_at": metadata["updated_at"],
                "snapshot_id": normalized_snapshot["snapshot_id"],
                "snapshot_digest": normalized_snapshot["snapshot_digest"],
                "summary": normalized_snapshot["summary"],
                "scan_metadata": normalized_snapshot["scan_metadata"],
                "comparability_profile": normalized_snapshot[
                    "comparability_profile"
                ],
            }
            self._immutable_preflight(
                baseline_path,
                record,
                "baseline_conflict",
            )
            documents = {
                "assessment.json": metadata,
                "baselines/{0}.json".format(baseline_version_id): record,
            }
            if snapshot_is_new:
                documents[
                    "snapshots/{0}.json".format(
                        normalized_snapshot["snapshot_id"]
                    )
                ] = normalized_snapshot
            self._transaction(
                base, documents, {"events.jsonl": event_bytes}
            )
        return {
            "assessment": metadata,
            "baseline_version": dict(
                record,
                is_active=(
                    metadata["active_baseline_version"]
                    == baseline_version_id
                ),
            ),
            "event": event,
        }

    def _read_baseline_record(
        self, assessment_id: str, baseline_version_id: str
    ) -> Dict[str, Any]:
        record = self._read_json(
            self._baseline_path(assessment_id, baseline_version_id),
            "baseline_not_found",
            "baseline version was not found",
        )
        version = int(baseline_version_id[-4:])
        if (
            not isinstance(record, dict)
            or set(record) != SINGLE_SCAN_BASELINE_FIELDS
            or record.get("schema_version")
            not in SUPPORTED_ASSESSMENT_SCHEMA_VERSIONS
            or record.get("assessment_id") != assessment_id
            or record.get("baseline_version_id") != baseline_version_id
            or record.get("version") != version
            or not isinstance(record.get("label"), str)
            or len(record["label"]) > 128
            or any(ord(character) < 32 for character in record["label"])
            or not SNAPSHOT_ID_PATTERN.match(
                str(record.get("snapshot_id", ""))
            )
            or not SNAPSHOT_DIGEST_PATTERN.match(
                str(record.get("snapshot_digest", ""))
            )
            or not isinstance(record.get("summary"), dict)
            or not isinstance(record.get("scan_metadata"), dict)
            or not isinstance(record.get("comparability_profile"), dict)
        ):
            raise BackendError(
                "storage_error", "baseline version is invalid"
            )
        validate_rfc3339(
            record.get("created_at"),
            "created_at",
            "storage_error",
        )
        _ensure_no_raw_recon(record)
        return record

    def list_baseline_versions(
        self, assessment_id: str
    ) -> List[Dict[str, Any]]:
        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            base, _, _, _, _ = self._assessment_paths(assessment_id)
            results = []
            for path in self._bounded_document_paths(
                base / "baselines",
                re.compile(r"^baseline_v[0-9]{4}\.json$"),
                MAX_BASELINE_VERSIONS,
                "baseline",
            ):
                record = self._read_baseline_record(
                    assessment_id, path.stem
                )
                result = dict(record)
                result["is_active"] = (
                    metadata["active_baseline_version"] == path.stem
                )
                results.append(result)
        return sorted(results, key=lambda item: item["version"])

    def get_baseline_version(
        self, assessment_id: str, baseline_version_id: str
    ) -> Dict[str, Any]:
        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            record = self._read_baseline_record(
                assessment_id, baseline_version_id
            )
            snapshot = self._read_json(
                self._snapshot_path(
                    assessment_id, record["snapshot_id"]
                ),
                "storage_error",
                "baseline snapshot was not found",
            )
        result = dict(record)
        result["is_active"] = (
            metadata["active_baseline_version"] == baseline_version_id
        )
        result["snapshot"] = _validate_snapshot(snapshot)
        return result

    def activate_baseline_version(
        self,
        assessment_id: str,
        expected_revision: Any,
        baseline_version_id: str,
    ) -> Dict[str, Any]:
        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_revision)
            record = self._read_baseline_record(
                assessment_id, baseline_version_id
            )
            if metadata["active_baseline_version"] == baseline_version_id:
                raise BackendError(
                    "no_changes", "baseline version is already active"
                )
            previous = metadata["active_baseline_version"]
            metadata["active_baseline_version"] = baseline_version_id
            event, event_bytes = self._transaction_event(
                assessment_id,
                metadata,
                "baseline_version_activated",
                {
                    "baseline_version_id": baseline_version_id,
                    "previous_baseline_version_id": previous,
                    "snapshot_id": record["snapshot_id"],
                },
            )
            base, _, _, _, _ = self._assessment_paths(assessment_id)
            self._transaction(
                base,
                {"assessment.json": metadata},
                {"events.jsonl": event_bytes},
            )
        return {
            "assessment": metadata,
            "baseline_version": dict(record, is_active=True),
            "event": event,
        }

    def _comparison_id(
        self,
        assessment_id: str,
        baseline_version_id: str,
        comparison: Dict[str, Any],
    ) -> str:
        digest = _canonical_digest(
            {
                "assessment_id": assessment_id,
                "baseline_version_id": baseline_version_id,
                "comparison": comparison,
            }
        )
        return "comparison_{0}".format(digest[:16])

    def persist_analysis(
        self,
        assessment_id: str,
        expected_revision: Any,
        comparison: Any,
        current_snapshot: Any,
        findings: Any,
    ) -> Dict[str, Any]:
        """Persist an analysis and apply deterministic finding lifecycle rules."""
        normalized_comparison = _validate_comparison(comparison)
        normalized_snapshot = _bind_snapshot_record_digest(current_snapshot)
        if not isinstance(findings, list) or len(findings) > MAX_FINDINGS:
            raise BackendError(
                "invalid_finding",
                "findings must contain at most {0} items".format(MAX_FINDINGS),
            )
        normalized_findings = [
            _validate_finding_core(finding) for finding in findings
        ]
        finding_ids = [item["finding_id"] for item in normalized_findings]
        if len(set(finding_ids)) != len(finding_ids):
            raise BackendError(
                "invalid_finding", "finding_id values must be unique"
            )
        if (
            normalized_comparison["current_snapshot_id"]
            != normalized_snapshot["snapshot_id"]
        ):
            raise BackendError(
                "invalid_comparison",
                "comparison current_snapshot_id does not match snapshot",
            )

        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_revision)
            active_baseline = metadata["active_baseline_version"]
            if active_baseline is None:
                raise BackendError(
                    "baseline_not_active",
                    "assessment has no active baseline version",
                )
            baseline = self._read_baseline_record(
                assessment_id, active_baseline
            )
            if (
                normalized_comparison["baseline_snapshot_id"]
                != baseline["snapshot_id"]
            ):
                raise BackendError(
                    "invalid_comparison",
                    "comparison does not use the active baseline snapshot",
                )
            baseline_snapshot = _validate_snapshot(
                self._read_json(
                    self._snapshot_path(
                        assessment_id, baseline["snapshot_id"]
                    ),
                    "storage_error",
                    "active baseline snapshot was not found",
                )
            )
            if (
                baseline_snapshot["snapshot_digest"]
                != baseline["snapshot_digest"]
            ):
                raise BackendError(
                    "storage_error",
                    "active baseline snapshot digest is inconsistent",
                )
            known_evidence_ids = {
                item["evidence_id"]
                for item in baseline_snapshot["access_points"]
            }
            known_evidence_ids.update(
                item["evidence_id"]
                for item in normalized_snapshot["access_points"]
            )
            known_subject_ids = {
                item["asset_id"]
                for item in baseline_snapshot["access_points"]
            }
            known_subject_ids.update(
                item["asset_id"]
                for item in normalized_snapshot["access_points"]
            )
            known_subject_ids.update(
                item["network_id"]
                for item in baseline_snapshot["networks"]
            )
            known_subject_ids.update(
                item["network_id"]
                for item in normalized_snapshot["networks"]
            )
            for finding in normalized_findings:
                if not set(finding["evidence_ids"]).issubset(
                    known_evidence_ids
                ):
                    raise BackendError(
                        "invalid_finding",
                        "finding references unknown evidence",
                    )
                if finding["subject_id"] not in known_subject_ids:
                    raise BackendError(
                        "invalid_finding",
                        "finding references an unknown subject",
                    )

            base, _, _, _, _ = self._assessment_paths(assessment_id)
            if len(
                self._bounded_document_paths(
                    base / "comparisons",
                    re.compile(r"^comparison_[0-9a-f]{16}\.json$"),
                    MAX_COMPARISONS,
                    "comparison",
                )
            ) >= MAX_COMPARISONS:
                raise BackendError(
                    "comparison_limit",
                    "assessment comparison limit was reached",
                )
            snapshot_path = self._snapshot_path(
                assessment_id, normalized_snapshot["snapshot_id"]
            )
            if not snapshot_path.exists() and len(
                self._bounded_document_paths(
                    base / "snapshots",
                    re.compile(r"^snapshot_[0-9a-f]{16}\.json$"),
                    MAX_SNAPSHOTS,
                    "snapshot",
                )
            ) >= MAX_SNAPSHOTS:
                raise BackendError(
                    "snapshot_limit",
                    "assessment snapshot limit was reached",
                )

            comparison_id = self._comparison_id(
                assessment_id, active_baseline, normalized_comparison
            )
            comparison_path = self._comparison_path(
                assessment_id, comparison_id
            )
            if comparison_path.exists():
                raise BackendError(
                    "analysis_already_persisted",
                    "this comparison was already persisted",
                )

            now = _utc_now()
            stored_findings = self._read_findings(assessment_id)
            by_id = {
                finding["finding_id"]: finding
                for finding in stored_findings
            }
            lifecycle = {
                "opened": [],
                "reopened": [],
                "updated": [],
                "resolved": [],
                "preserved_false_positive": [],
                "mutated": (
                    normalized_comparison["comparability"]["status"]
                    != "not_comparable"
                ),
            }

            if lifecycle["mutated"]:
                observed_ids = set()
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
                                "first_seen": now,
                                "last_seen": now,
                                "occurrence_count": 1,
                                "status_updated_at": now,
                            }
                        )
                        by_id[finding_id] = stored
                        lifecycle["opened"].append(finding_id)
                        continue

                    for field in FINDING_CORE_FIELDS:
                        existing[field] = core[field]
                    existing["currently_observed"] = True
                    existing["last_seen"] = now
                    existing["occurrence_count"] += 1
                    if existing["status"] == "resolved":
                        existing["status"] = "open"
                        existing["status_updated_at"] = now
                        lifecycle["reopened"].append(finding_id)
                    elif existing["status"] == "false_positive":
                        lifecycle["preserved_false_positive"].append(
                            finding_id
                        )
                    else:
                        lifecycle["updated"].append(finding_id)

                status = normalized_comparison["comparability"]["status"]
                for finding_id, existing in by_id.items():
                    if finding_id in observed_ids:
                        continue
                    details = existing.get("details")
                    if (
                        isinstance(details, dict)
                        and details.get("measurement_point_id") is not None
                    ):
                        continue
                    if status == "comparable":
                        existing["currently_observed"] = False
                        if existing["status"] in (
                            "open",
                            "acknowledged",
                        ):
                            existing["status"] = "resolved"
                            existing["status_updated_at"] = now
                            lifecycle["resolved"].append(finding_id)

                stored_findings = sorted(
                    by_id.values(), key=lambda item: item["finding_id"]
                )
            else:
                observed_ids = set()

            snapshot_is_new = self._snapshot_immutable_preflight(
                snapshot_path,
                normalized_snapshot,
                "snapshot_conflict",
            )
            record = {
                "schema_version": ASSESSMENT_SCHEMA_VERSION,
                "comparison_id": comparison_id,
                "assessment_id": assessment_id,
                "baseline_version_id": active_baseline,
                "created_at": now,
                "baseline_snapshot_id": normalized_comparison[
                    "baseline_snapshot_id"
                ],
                "current_snapshot_id": normalized_snapshot["snapshot_id"],
                "current_snapshot_digest": normalized_snapshot[
                    "snapshot_digest"
                ],
                "comparability_status": normalized_comparison[
                    "comparability"
                ]["status"],
                "observed_finding_ids": sorted(observed_ids),
                "lifecycle": lifecycle,
                "comparison": normalized_comparison,
            }
            self._immutable_preflight(
                comparison_path, record, "comparison_conflict"
            )
            event, event_bytes = self._transaction_event(
                assessment_id,
                metadata,
                "analysis_persisted",
                {
                    "comparison_id": comparison_id,
                    "baseline_version_id": active_baseline,
                    "current_snapshot_id": normalized_snapshot["snapshot_id"],
                    "current_snapshot_digest": normalized_snapshot[
                        "snapshot_digest"
                    ],
                    "comparability_status": record[
                        "comparability_status"
                    ],
                    "observed_finding_count": len(observed_ids),
                    "opened_count": len(lifecycle["opened"]),
                    "reopened_count": len(lifecycle["reopened"]),
                    "resolved_count": len(lifecycle["resolved"]),
                    "lifecycle_mutated": lifecycle["mutated"],
                },
            )
            documents = {
                "assessment.json": metadata,
                "comparisons/{0}.json".format(comparison_id): record,
            }
            if snapshot_is_new:
                documents[
                    "snapshots/{0}.json".format(
                        normalized_snapshot["snapshot_id"]
                    )
                ] = normalized_snapshot
            if lifecycle["mutated"]:
                documents["findings.json"] = {
                    "schema_version": ASSESSMENT_SCHEMA_VERSION,
                    "updated_at": now,
                    "findings": stored_findings,
                }
            self._transaction(
                base, documents, {"events.jsonl": event_bytes}
            )

        return {
            "assessment": metadata,
            "comparison": record,
            "findings": stored_findings,
            "lifecycle": lifecycle,
            "event": event,
        }

    def get_comparison(
        self, assessment_id: str, comparison_id: str
    ) -> Dict[str, Any]:
        with self._lock(assessment_id):
            self._read_metadata(assessment_id)
            record = self._read_comparison_record_unlocked(
                assessment_id, comparison_id
            )
        return record

    def _read_comparison_record_unlocked(
        self,
        assessment_id: str,
        comparison_id: str,
        validate_snapshot_reference: bool = True,
        validate_linked_references: bool = True,
    ) -> Dict[str, Any]:
        record = self._read_json(
            self._comparison_path(assessment_id, comparison_id),
            "comparison_not_found",
            "comparison was not found",
        )
        record = _validate_stored_comparison_record(
            record, assessment_id, comparison_id
        )
        if validate_snapshot_reference:
            self._validate_comparison_snapshot_reference_unlocked(
                assessment_id, record
            )
        if validate_linked_references:
            self._validate_linked_comparison_references_unlocked(
                assessment_id, record
            )
        return record

    def _validate_linked_comparison_references_unlocked(
        self, assessment_id: str, record: Dict[str, Any]
    ) -> None:
        """Subclass hook for version-specific immutable reference checks."""
        return None

    def _validate_comparison_snapshot_reference_unlocked(
        self,
        assessment_id: str,
        record: Dict[str, Any],
        snapshots: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> None:
        snapshot_id = record["current_snapshot_id"]
        snapshot = snapshots.get(snapshot_id) if snapshots is not None else None
        if snapshot is None:
            stored = self._read_json(
                self._snapshot_path(assessment_id, snapshot_id),
                "storage_error",
                "comparison snapshot was not found",
            )
            snapshot = _validate_snapshot(stored)
            if snapshots is not None:
                snapshots[snapshot_id] = snapshot
        if (
            snapshot.get("snapshot_id") != snapshot_id
            or snapshot.get("snapshot_digest")
            != record["current_snapshot_digest"]
        ):
            raise BackendError(
                "storage_error", "comparison snapshot reference is invalid"
            )

    def list_comparisons(
        self, assessment_id: str
    ) -> List[Dict[str, Any]]:
        with self._read_session(assessment_id), self._lock(assessment_id):
            self._read_metadata(assessment_id)
            base, _, _, _, _ = self._assessment_paths(assessment_id)
            results = []
            paths = self._bounded_document_paths(
                base / "comparisons",
                re.compile(r"^comparison_[0-9a-f]{16}\.json$"),
                MAX_COMPARISONS,
                "comparison",
            )
            comparison_bytes = self._preflight_aggregate_document_bytes(
                paths, MAX_CUSTOMER_LIST_BYTES, "comparison"
            )
            records = []
            for path in paths:
                record = self._read_comparison_record_unlocked(
                    assessment_id,
                    path.stem,
                    validate_snapshot_reference=False,
                    validate_linked_references=False,
                )
                records.append(record)
            snapshot_paths = sorted(
                {
                    self._snapshot_path(
                        assessment_id, record["current_snapshot_id"]
                    )
                    for record in records
                },
                key=lambda item: item.name,
            )
            self._preflight_aggregate_document_bytes(
                snapshot_paths,
                MAX_CUSTOMER_LIST_BYTES - comparison_bytes,
                "comparison snapshot",
            )
            snapshots = {}
            for record in records:
                self._validate_comparison_snapshot_reference_unlocked(
                    assessment_id, record, snapshots
                )
                summary = {
                    key: record[key]
                    for key in (
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
                    )
                }
                results.append(summary)
        return sorted(
            results,
            key=lambda item: (item["created_at"], item["comparison_id"]),
            reverse=True,
        )

    def list_findings(
        self,
        assessment_id: str,
        statuses: Optional[List[str]] = None,
        currently_observed: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        if statuses is not None:
            if not isinstance(statuses, list) or not statuses:
                raise BackendError(
                    "invalid_request", "statuses must be a non-empty list"
                )
            if any(status not in FINDING_STATUSES for status in statuses):
                raise BackendError(
                    "invalid_request", "statuses contains an unknown value"
                )
        if currently_observed is not None and not isinstance(
            currently_observed, bool
        ):
            raise BackendError(
                "invalid_request", "currently_observed must be a boolean"
            )
        with self._lock(assessment_id):
            self._read_metadata(assessment_id)
            findings = self._read_findings(assessment_id)
        status_filter = set(statuses or FINDING_STATUSES)
        return [
            finding
            for finding in findings
            if finding["status"] in status_filter
            and (
                currently_observed is None
                or finding["currently_observed"] == currently_observed
            )
        ]

    def update_finding(
        self,
        assessment_id: str,
        expected_revision: Any,
        finding_id: Any,
        status: Any,
        note: Any = "",
    ) -> Dict[str, Any]:
        if not isinstance(finding_id, str) or not (
            FINDING_ID_PATTERN.match(finding_id)
        ):
            raise BackendError("invalid_finding", "finding_id is invalid")
        if status not in OPERATOR_FINDING_STATUSES:
            raise BackendError(
                "invalid_finding",
                "operator status must be open, acknowledged, or false_positive",
            )
        if (
            not isinstance(note, str)
            or len(note) > 1000
            or any(ord(character) < 32 for character in note)
        ):
            raise BackendError(
                "invalid_finding",
                "note must be a control-free string of at most 1000 characters",
            )
        normalized_note = note.strip()
        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_revision)
            findings = self._read_findings(assessment_id)
            selected = None
            for finding in findings:
                if finding["finding_id"] == finding_id:
                    selected = finding
                    break
            if selected is None:
                raise BackendError(
                    "finding_not_found", "finding was not found"
                )
            if selected["status"] == "resolved" and status == "open":
                raise BackendError(
                    "invalid_finding",
                    "a resolved finding can reopen only after deterministic recurrence",
                )
            if selected["status"] == status:
                raise BackendError(
                    "no_changes", "finding already has the requested status"
                )
            previous = selected["status"]
            now = _utc_now()
            selected["status"] = status
            selected["status_updated_at"] = now
            event_data = {
                "finding_id": finding_id,
                "previous_status": previous,
                "status": status,
            }
            if normalized_note:
                event_data["note"] = normalized_note
            event, event_bytes = self._transaction_event(
                assessment_id,
                metadata,
                "finding_status_updated",
                event_data,
            )
            selected["status_updated_at"] = metadata["updated_at"]
            base, _, _, _, _ = self._assessment_paths(assessment_id)
            self._transaction(
                base,
                {
                    "assessment.json": metadata,
                    "findings.json": {
                        "schema_version": ASSESSMENT_SCHEMA_VERSION,
                        "updated_at": metadata["updated_at"],
                        "findings": sorted(
                            findings,
                            key=lambda item: item["finding_id"],
                        ),
                    },
                },
                {"events.jsonl": event_bytes},
            )
        return {
            "assessment": metadata,
            "finding": selected,
            "event": event,
        }
