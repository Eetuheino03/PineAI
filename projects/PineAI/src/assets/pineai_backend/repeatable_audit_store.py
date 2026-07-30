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
    _validate_revision,
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


def _sanitize_measurement(m: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize measurement dict to conform strictly to matching branch schema."""
    m_copy = dict(m)
    if "audit_measurement_id" in m_copy and "measurement_id" not in m_copy:
        m_copy["measurement_id"] = m_copy.pop("audit_measurement_id")
    else:
        m_copy.pop("audit_measurement_id", None)

    m_copy.pop("assessment_id", None)
    m_copy.pop("expected_measurement_context", None)

    status = m_copy.get("status")
    failed_stage = m_copy.get("failed_stage")
    baseline_type = m_copy.get("baseline_type")

    if status == "pending":
        allowed = {"measurement_id", "audit_run_id", "measurement_point_id", "status", "created_at"}
    elif status == "resolved":
        if baseline_type == "consensus":
            allowed = {
                "measurement_id", "audit_run_id", "measurement_point_id", "status",
                "source_recon_id", "snapshot_id", "snapshot_digest",
                "measurement_profile_id", "measurement_profile_version_id", "measurement_profile_digest",
                "baseline_version_id", "baseline_type", "baseline_model_id", "baseline_model_digest",
                "baseline_record_digest", "assurance_profile_version_id", "assurance_profile_digest",
                "comparability_status", "resolved_at",
            }
        else:
            allowed = {
                "measurement_id", "audit_run_id", "measurement_point_id", "status",
                "source_recon_id", "snapshot_id", "snapshot_digest",
                "measurement_profile_id", "measurement_profile_version_id", "measurement_profile_digest",
                "baseline_version_id", "baseline_type", "baseline_snapshot_id", "baseline_snapshot_digest",
                "baseline_record_digest", "assurance_profile_version_id", "assurance_profile_digest",
                "comparability_status", "resolved_at",
            }
    elif status == "completed":
        if baseline_type == "consensus":
            allowed = {
                "measurement_id", "audit_run_id", "measurement_point_id", "status",
                "source_recon_id", "snapshot_id", "snapshot_digest",
                "measurement_profile_id", "measurement_profile_version_id", "measurement_profile_digest",
                "baseline_version_id", "baseline_type", "baseline_model_id", "baseline_model_digest",
                "baseline_record_digest", "assurance_profile_version_id", "assurance_profile_digest",
                "comparability_status", "comparison_id", "comparison_digest",
                "occurrence_set_id", "evidence_ids", "completed_at",
            }
        else:
            allowed = {
                "measurement_id", "audit_run_id", "measurement_point_id", "status",
                "source_recon_id", "snapshot_id", "snapshot_digest",
                "measurement_profile_id", "measurement_profile_version_id", "measurement_profile_digest",
                "baseline_version_id", "baseline_type", "baseline_snapshot_id", "baseline_snapshot_digest",
                "baseline_record_digest", "assurance_profile_version_id", "assurance_profile_digest",
                "comparability_status", "comparison_id", "comparison_digest",
                "occurrence_set_id", "evidence_ids", "completed_at",
            }
    elif status == "failed":
        if failed_stage == "resolution":
            allowed = {
                "measurement_id", "audit_run_id", "measurement_point_id", "status",
                "failed_stage", "error_code", "error_message", "failed_at", "retry_target",
            }
        elif failed_stage == "comparison":
            if baseline_type == "consensus":
                allowed = {
                    "measurement_id", "audit_run_id", "measurement_point_id", "status",
                    "failed_stage", "retry_target", "source_recon_id", "snapshot_id", "snapshot_digest",
                    "measurement_profile_id", "measurement_profile_version_id", "measurement_profile_digest",
                    "baseline_version_id", "baseline_type", "baseline_model_id", "baseline_model_digest",
                    "baseline_record_digest", "assurance_profile_version_id", "assurance_profile_digest",
                    "comparability_status", "resolved_at", "error_code", "error_message", "failed_at",
                }
            else:
                allowed = {
                    "measurement_id", "audit_run_id", "measurement_point_id", "status",
                    "failed_stage", "retry_target", "source_recon_id", "snapshot_id", "snapshot_digest",
                    "measurement_profile_id", "measurement_profile_version_id", "measurement_profile_digest",
                    "baseline_version_id", "baseline_type", "baseline_snapshot_id", "baseline_snapshot_digest",
                    "baseline_record_digest", "assurance_profile_version_id", "assurance_profile_digest",
                    "comparability_status", "resolved_at", "error_code", "error_message", "failed_at",
                }
        else:
            allowed = set(m_copy.keys())
    else:
        allowed = set(m_copy.keys())

    return {k: v for k, v in m_copy.items() if k in allowed and (v is not None or k == "source_recon_id")}


def _validate_audit_run_measurement(m: Dict[str, Any]) -> None:
    """Validate measurement fields strictly against the 8 variant schemas."""
    status = m.get("status")
    mid = m.get("measurement_id") or m.get("audit_measurement_id")
    if not mid or not AUDIT_MEASUREMENT_ID_PATTERN.match(mid):
        raise BackendError("invalid_audit_run_measurement", "invalid measurement_id format")

    if status == "pending":
        if set(m) & (RESOLVED_PINNED_FIELDS | COMPLETED_FIELDS | FAILURE_FIELDS):
            raise BackendError(
                "invalid_audit_run_measurement",
                "pending measurement cannot contain resolution, completed, or failure fields",
            )
    elif status == "resolved":
        if set(m) & (COMPLETED_FIELDS | FAILURE_FIELDS):
            raise BackendError(
                "invalid_audit_run_measurement",
                "resolved measurement cannot contain completed or failure fields",
            )
        btype = m.get("baseline_type")
        if btype == "consensus":
            if set(m) & SINGLE_SCAN_FIELDS:
                raise BackendError(
                    "invalid_audit_run_measurement",
                    "consensus branch cannot contain single scan fields",
                )
            if not CONSENSUS_FIELDS.issubset(set(m)):
                raise BackendError(
                    "invalid_audit_run_measurement",
                    "consensus branch missing required baseline model fields",
                )
        elif btype == "single_scan":
            if set(m) & CONSENSUS_FIELDS:
                raise BackendError(
                    "invalid_audit_run_measurement",
                    "single scan branch cannot contain consensus fields",
                )
            if not SINGLE_SCAN_FIELDS.issubset(set(m)):
                raise BackendError(
                    "invalid_audit_run_measurement",
                    "single scan branch missing required baseline snapshot fields",
                )
        else:
            raise BackendError("invalid_audit_run_measurement", "invalid baseline_type")
    elif status == "completed":
        if set(m) & FAILURE_FIELDS:
            raise BackendError(
                "invalid_audit_run_measurement",
                "completed measurement cannot contain failure fields",
            )
        if not COMPLETED_FIELDS.issubset(set(m)):
            raise BackendError(
                "invalid_audit_run_measurement",
                "completed measurement missing required comparison result fields",
            )
        btype = m.get("baseline_type")
        if btype == "consensus":
            if set(m) & SINGLE_SCAN_FIELDS:
                raise BackendError(
                    "invalid_audit_run_measurement",
                    "consensus branch cannot contain single scan fields",
                )
            if not CONSENSUS_FIELDS.issubset(set(m)):
                raise BackendError(
                    "invalid_audit_run_measurement",
                    "consensus branch missing required baseline model fields",
                )
        elif btype == "single_scan":
            if set(m) & CONSENSUS_FIELDS:
                raise BackendError(
                    "invalid_audit_run_measurement",
                    "single scan branch cannot contain consensus fields",
                )
            if not SINGLE_SCAN_FIELDS.issubset(set(m)):
                raise BackendError(
                    "invalid_audit_run_measurement",
                    "single scan branch missing required baseline snapshot fields",
                )
        else:
            raise BackendError("invalid_audit_run_measurement", "invalid baseline_type")
    elif status == "failed":
        if set(m) & COMPLETED_FIELDS:
            raise BackendError(
                "invalid_audit_run_measurement",
                "failed measurement cannot contain completed fields",
            )
        if not FAILURE_FIELDS.issubset(set(m)):
            raise BackendError(
                "invalid_audit_run_measurement",
                "failed measurement missing required error fields",
            )
        fstage = m.get("failed_stage")
        rtarget = m.get("retry_target")
        if fstage == "resolution":
            if rtarget != "pending":
                raise BackendError(
                    "invalid_audit_run_transition",
                    "resolution failure must have retry_target pending",
                )
            if set(m) & RESOLVED_PINNED_FIELDS:
                raise BackendError(
                    "invalid_audit_run_measurement",
                    "failed resolution measurement cannot contain resolution fields",
                )
        elif fstage == "comparison":
            if rtarget != "resolved":
                raise BackendError(
                    "invalid_audit_run_transition",
                    "comparison failure must have retry_target resolved",
                )
            btype = m.get("baseline_type")
            if btype == "consensus":
                if set(m) & SINGLE_SCAN_FIELDS:
                    raise BackendError(
                        "invalid_audit_run_measurement",
                        "consensus branch cannot contain single scan fields",
                    )
                if not CONSENSUS_FIELDS.issubset(set(m)):
                    raise BackendError(
                        "invalid_audit_run_measurement",
                        "consensus branch missing required baseline model fields",
                    )
            elif btype == "single_scan":
                if set(m) & CONSENSUS_FIELDS:
                    raise BackendError(
                        "invalid_audit_run_measurement",
                        "single scan branch cannot contain consensus fields",
                    )
                if not SINGLE_SCAN_FIELDS.issubset(set(m)):
                    raise BackendError(
                        "invalid_audit_run_measurement",
                        "single scan branch missing required baseline snapshot fields",
                    )
            else:
                raise BackendError("invalid_audit_run_measurement", "invalid baseline_type")
        else:
            raise BackendError("invalid_audit_run_transition", "unknown failed_stage")
    else:
        raise BackendError("invalid_audit_run_measurement", "unknown status")


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

        runs_dir = base / "audit_runs"
        closure_reserve = 0
        if runs_dir.exists():
            with os.scandir(str(runs_dir)) as it:
                for entry in it:
                    if entry.name.startswith("ar_") and entry.name.endswith(".json"):
                        try:
                            with open(entry.path, "r", encoding="utf-8") as f:
                                content = f.read(512)
                                if '"status": "draft"' in content or '"status": "in_progress"' in content:
                                    closure_reserve += 1
                        except OSError:
                            pass

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
        if not pinned_assurance_profile_version_id or not isinstance(pinned_assurance_profile_version_id, str):
            raise BackendError("profile_version_not_found", "pinned_assurance_profile_version_id is required")
        if not isinstance(measurement_point_ids, list) or len(measurement_point_ids) < 1 or len(measurement_point_ids) > MAX_MEASUREMENT_POINTS_PER_RUN:
            raise BackendError("invalid_audit_run", "measurement_point_ids must contain between 1 and 64 items")

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

            base = self._ensure_assessment_directories(assessment_id)
            runs_dir = base / "audit_runs"
            self._ensure_private_directory(runs_dir)

            txn = PrivateTransaction(base, fault_injector=self.fault_injector)
            txn.add_bytes(f"audit_runs/{ar_id}.json", run_bytes)
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

            base = self._ensure_assessment_directories(assessment_id)
            txn = PrivateTransaction(base, fault_injector=self.fault_injector)
            txn.add_bytes(f"audit_runs/{audit_run_id}.json", run_bytes)
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
    ) -> Dict[str, Any]:
        _validate_revision(expected_assessment_revision)
        _validate_revision(expected_audit_run_revision)

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

            base = self._ensure_assessment_directories(assessment_id)
            txn = PrivateTransaction(base, fault_injector=self.fault_injector)
            txn.add_bytes(f"audit_runs/{audit_run_id}.json", run_bytes)
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

            base = self._ensure_assessment_directories(assessment_id)
            txn = PrivateTransaction(base, fault_injector=self.fault_injector)
            txn.add_bytes(f"audit_runs/{audit_run_id}.json", run_bytes)
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
                raise BackendError("measurement_point_not_found", "measurement point not in audit run")
            if target_m.get("status") != "pending":
                raise BackendError("invalid_audit_run_transition", "cannot resolve measurement in status {0}".format(target_m.get("status")))

            status = outcome.get("status")
            if status not in ("resolved", "failed"):
                raise BackendError("invalid_audit_run_measurement", "resolve outcome status must be resolved or failed")

            snapshot_id = outcome.get("snapshot_id")
            if snapshot_id:
                snap_path = self._ensure_assessment_directories(assessment_id) / "snapshots" / f"{snapshot_id}.json"
                if not snap_path.exists():
                    raise BackendError("snapshot_not_found", "referenced snapshot missing")

            updated_m = _json_clone(target_m, "invalid_audit_run_measurement", "measurement")
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
        outcome: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        _validate_revision(expected_assessment_revision)
        _validate_revision(expected_audit_run_revision)
        if outcome is not None:
            _ensure_no_raw_recon(outcome)

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
            expected_retry_target = target_m.get("retry_target")

            if failed_stage == "resolution":
                if expected_retry_target != "pending":
                    raise BackendError("invalid_audit_run_transition", "invalid retry target for resolution failure")
            elif failed_stage == "comparison":
                if expected_retry_target != "resolved":
                    raise BackendError("invalid_audit_run_transition", "invalid retry target for comparison failure")
            else:
                raise BackendError("invalid_audit_run_transition", "unknown failed_stage for measurement")

            if outcome is not None and isinstance(outcome, dict):
                provided_status = outcome.get("status")
                if provided_status is not None and provided_status != expected_retry_target:
                    raise BackendError(
                        "invalid_audit_run_transition",
                        "retry outcome status does not match retry target",
                    )
                if failed_stage == "comparison":
                    for pin in RESOLVED_PINNED_FIELDS:
                        if pin in outcome and outcome[pin] != target_m.get(pin):
                            raise BackendError(
                                "invalid_audit_run_measurement",
                                "cannot replace immutable pinned fields during retry",
                            )

            updated_m = _json_clone(target_m, "invalid_audit_run_measurement", "measurement")
            for k in ("error_code", "error_message", "failed_stage", "retry_target", "failed_at"):
                updated_m.pop(k, None)

            if failed_stage == "resolution":
                updated_m["status"] = "pending"
                for pin in RESOLVED_PINNED_FIELDS:
                    updated_m.pop(pin, None)
                for comp in COMPLETED_FIELDS:
                    updated_m.pop(comp, None)
            elif failed_stage == "comparison":
                updated_m["status"] = "resolved"
                for comp in COMPLETED_FIELDS:
                    updated_m.pop(comp, None)

            if outcome is not None and isinstance(outcome, dict):
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
                "audit_measurement_retried",
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

            status = outcome.get("status")
            if status not in ("completed", "failed"):
                raise BackendError("invalid_audit_run_measurement", "comparison outcome status must be completed or failed")

            for pin in RESOLVED_PINNED_FIELDS:
                if pin in outcome and outcome[pin] != target_m.get(pin):
                    raise BackendError(
                        "invalid_audit_run_measurement",
                        "cannot replace immutable pinned fields during comparison",
                    )

            base = self._ensure_assessment_directories(assessment_id)
            comp_id = outcome.get("comparison_id")
            if comp_id:
                comp_path = base / "comparisons" / f"{comp_id}.json"
                if not comp_path.exists():
                    raise BackendError("comparison_not_found", "referenced comparison missing")

            occ_id = outcome.get("occurrence_set_id")
            if occ_id:
                occ_path = base / "occurrences" / f"{occ_id}.json"
                if not occ_path.exists():
                    raise BackendError("occurrence_set_not_found", "referenced occurrence set missing")

            updated_m = _json_clone(target_m, "invalid_audit_run_measurement", "measurement")
            if status == "completed":
                updated_m.update(_json_clone(outcome, "invalid_audit_run_measurement", "outcome"))
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
