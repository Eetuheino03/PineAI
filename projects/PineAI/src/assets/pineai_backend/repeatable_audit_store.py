"""PineAI v0.7.0 Repeatable Field Audits domain store.

Extends CustomerAuditStore with MeasurementPoint, AuditRun, and AuditRunMeasurement
persistence, optimistic concurrency, dynamic closure reserves, and recoverable storage.
"""

import json
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

    def _get_assessment_capacity_unlocked(self, assessment_id: str) -> Dict[str, Any]:
        base = self._ensure_assessment_directories(assessment_id)
        snapshots = len(list((base / "snapshots").glob("*.json"))) if (base / "snapshots").exists() else 0
        comparisons = len(list((base / "comparisons").glob("*.json"))) if (base / "comparisons").exists() else 0
        events = self._read_events(assessment_id)
        event_used = len(events)

        runs = self._list_audit_runs_unlocked(assessment_id)
        closure_reserve = sum(
            1 for run in runs if run.get("status") in ("draft", "in_progress")
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
        self, assessment_id: str, include_archived: bool = False
    ) -> List[Dict[str, Any]]:
        with self._lock(assessment_id):
            return self._list_measurement_points_unlocked(assessment_id, include_archived=include_archived)

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
            return self._get_measurement_point_unlocked(assessment_id, measurement_point_id)

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
                "expected_measurement_context": validated_context,
                "status": "active",
                "created_at": _utc_now(),
                "archived_at": None,
                "revision": 1,
            }
            _ensure_no_raw_recon(new_point)

            updated_points = list(existing_points) + [new_point]
            new_doc = {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "assessment_id": assessment_id,
                "updated_at": _utc_now(),
                "measurement_points": updated_points,
            }

            _canonical_digest(new_doc)  # verifies serializability
            doc_bytes = json.dumps(new_doc, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
            if len(doc_bytes) > MAX_MEASUREMENT_POINTS_DOCUMENT_BYTES:
                raise BackendError("storage_limit_exceeded", "measurement points document size exceeded limit")

            base = self._ensure_assessment_directories(assessment_id)
            event_payload = {
                "measurement_point_id": mp_id,
                "name": clean_name,
                "status": "active",
            }
            event_obj, events_bytes = self._transaction_event(
                assessment_id, metadata, "measurement_point_created", event_payload
            )

            txn = PrivateTransaction(base)
            txn.add_json("assessment.json", metadata)
            txn.add_json("measurement_points.json", new_doc)
            txn.add_bytes("events.jsonl", events_bytes)
            txn.commit()

            return {
                "measurement_point": new_point,
                "assessment_revision": metadata["revision"],
                "assessment_capacity": self._get_assessment_capacity_unlocked(assessment_id),
                "event": event_obj,
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
        if not isinstance(updates, dict):
            raise BackendError("invalid_measurement_point", "updates must be an object")

        allowed_updates = {"name", "description", "expected_measurement_context"}
        if set(updates) - allowed_updates:
            raise BackendError("invalid_measurement_point", "unsupported update fields")

        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_assessment_revision)
            self._check_non_terminal_event_capacity(assessment_id)

            doc = self._read_measurement_points_doc(assessment_id)
            points = doc.get("measurement_points", [])

            target_index = -1
            target_mp = None
            for idx, p in enumerate(points):
                if p.get("measurement_point_id") == measurement_point_id:
                    target_index = idx
                    target_mp = p
                    break

            if target_mp is None:
                raise BackendError("measurement_point_not_found", "measurement point not found")
            if target_mp.get("status") == "archived":
                raise BackendError("measurement_point_archived", "cannot update archived measurement point")
            if target_mp.get("revision") != expected_measurement_point_revision:
                raise BackendError("revision_conflict", "measurement point revision has changed")

            updated_mp = _json_clone(target_mp, "invalid_measurement_point", "measurement_point")
            if "name" in updates:
                updated_mp["name"] = _clean_text(updates["name"], "name", 128, required=True)
            if "description" in updates:
                desc = updates["description"]
                updated_mp["description"] = _clean_text(desc, "description", 512, required=False) if desc is not None else None
            if "expected_measurement_context" in updates:
                updated_mp["expected_measurement_context"] = _validate_expected_measurement_context(
                    updates["expected_measurement_context"], measurement_point_id=measurement_point_id
                )

            updated_mp["revision"] += 1
            _ensure_no_raw_recon(updated_mp)

            updated_points = list(points)
            updated_points[target_index] = updated_mp

            new_doc = {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "assessment_id": assessment_id,
                "updated_at": _utc_now(),
                "measurement_points": updated_points,
            }

            doc_bytes = json.dumps(new_doc, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
            if len(doc_bytes) > MAX_MEASUREMENT_POINTS_DOCUMENT_BYTES:
                raise BackendError("storage_limit_exceeded", "measurement points document size exceeded limit")

            base = self._ensure_assessment_directories(assessment_id)
            event_payload = {
                "measurement_point_id": measurement_point_id,
                "name": updated_mp["name"],
                "status": updated_mp["status"],
            }
            event_obj, events_bytes = self._transaction_event(
                assessment_id, metadata, "measurement_point_updated", event_payload
            )

            txn = PrivateTransaction(base)
            txn.add_json("assessment.json", metadata)
            txn.add_json("measurement_points.json", new_doc)
            txn.add_bytes("events.jsonl", events_bytes)
            txn.commit()

            return {
                "measurement_point": updated_mp,
                "assessment_revision": metadata["revision"],
                "assessment_capacity": self._get_assessment_capacity_unlocked(assessment_id),
                "event": event_obj,
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

            target_index = -1
            target_mp = None
            for idx, p in enumerate(points):
                if p.get("measurement_point_id") == measurement_point_id:
                    target_index = idx
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
            updated_points[target_index] = updated_mp

            new_doc = {
                "schema_version": REPEATABLE_AUDITS_SCHEMA_VERSION,
                "assessment_id": assessment_id,
                "updated_at": _utc_now(),
                "measurement_points": updated_points,
            }

            base = self._ensure_assessment_directories(assessment_id)
            event_payload = {
                "measurement_point_id": measurement_point_id,
                "name": updated_mp["name"],
                "status": "archived",
            }
            event_obj, events_bytes = self._transaction_event(
                assessment_id, metadata, "measurement_point_archived", event_payload
            )

            txn = PrivateTransaction(base)
            txn.add_json("assessment.json", metadata)
            txn.add_json("measurement_points.json", new_doc)
            txn.add_bytes("events.jsonl", events_bytes)
            txn.commit()

            return {
                "measurement_point": updated_mp,
                "assessment_revision": metadata["revision"],
                "assessment_capacity": self._get_assessment_capacity_unlocked(assessment_id),
                "event": event_obj,
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

    def list_audit_runs(self, assessment_id: str) -> List[Dict[str, Any]]:
        with self._lock(assessment_id):
            return self._list_audit_runs_unlocked(assessment_id)

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
            return self._get_audit_run_unlocked(assessment_id, audit_run_id)

    def create_audit_run(
        self,
        assessment_id: str,
        expected_assessment_revision: int,
        title: str,
        measurement_point_ids: List[str],
        due_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        _validate_revision(expected_assessment_revision)
        clean_title = _clean_text(title, "title", 128, required=True)
        if not isinstance(measurement_point_ids, list) or len(measurement_point_ids) < 1 or len(measurement_point_ids) > MAX_MEASUREMENT_POINTS_PER_RUN:
            raise BackendError("invalid_audit_run", "measurement_point_ids must contain between 1 and 64 items")
        if len(set(measurement_point_ids)) != len(measurement_point_ids):
            raise BackendError("invalid_audit_run", "measurement_point_ids must contain unique items")
        for mpid in measurement_point_ids:
            if not MEASUREMENT_POINT_ID_PATTERN.match(mpid):
                raise BackendError("invalid_audit_run", "invalid measurement_point_id in list")

        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_assessment_revision)
            self._check_non_terminal_event_capacity(assessment_id, extra_closure_reserve=1)

            existing_runs = self._list_audit_runs_unlocked(assessment_id)
            if len(existing_runs) >= MAX_AUDIT_RUNS_PER_ASSESSMENT:
                raise BackendError("audit_run_limit_exceeded", "audit run limit reached")

            active_mps = {mp["measurement_point_id"]: mp for mp in self._list_measurement_points_unlocked(assessment_id, include_archived=False)}
            for mpid in measurement_point_ids:
                if mpid not in active_mps:
                    raise BackendError("measurement_point_archived", "referenced measurement point {0} is archived or missing".format(mpid))

            assurance_version = metadata.get("active_assurance_profile_version")
            if not assurance_version:
                raise BackendError("invalid_audit_run", "assessment has no active assurance profile")
            assurance_prof = self.get_assurance_profile_version(assessment_id, assurance_version)
            assurance_digest = assurance_prof.get("digest")

            ar_id = _generate_ar_id()
            now = _utc_now()

            measurements = []
            for mpid in measurement_point_ids:
                mp_obj = active_mps[mpid]
                arm_id = _generate_arm_id()
                measurements.append({
                    "audit_measurement_id": arm_id,
                    "audit_run_id": ar_id,
                    "assessment_id": assessment_id,
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
                "pinned_assurance_profile_version_id": assurance_version,
                "pinned_assurance_profile_digest": assurance_digest,
                "measurement_point_ids": list(measurement_point_ids),
                "measurements": measurements,
                "revision": 1,
            }
            _ensure_no_raw_recon(audit_run)

            run_bytes = json.dumps(audit_run, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
            if len(run_bytes) > MAX_AUDIT_RUN_DOCUMENT_BYTES:
                raise BackendError("storage_limit_exceeded", "audit run document size exceeded limit")

            base = self._ensure_assessment_directories(assessment_id)
            event_payload = {
                "audit_run_id": ar_id,
                "title": clean_title,
                "status": "draft",
                "measurement_point_count": len(measurement_point_ids),
            }
            event_obj, events_bytes = self._transaction_event(
                assessment_id, metadata, "audit_run_created", event_payload
            )

            txn = PrivateTransaction(base)
            txn.add_json("assessment.json", metadata)
            txn.add_json("audit_runs/{0}.json".format(ar_id), audit_run)
            txn.add_bytes("events.jsonl", events_bytes)
            txn.commit()

            res_run = _json_clone(audit_run, "invalid_audit_run", "audit_run")
            res_run["ready_to_start"] = True
            return {
                "audit_run": res_run,
                "assessment_revision": metadata["revision"],
                "assessment_capacity": self._get_assessment_capacity_unlocked(assessment_id),
                "event": event_obj,
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
                raise BackendError("audit_run_sealed", "cannot modify sealed audit run")
            if audit_run.get("status") != "draft":
                raise BackendError("invalid_audit_run_transition", "audit run is not in draft status")
            if audit_run.get("revision") != expected_audit_run_revision:
                raise BackendError("revision_conflict", "audit run revision has changed")

            updated_run = _json_clone(audit_run, "invalid_audit_run", "audit_run")
            updated_run["status"] = "in_progress"
            updated_run["started_at"] = _utc_now()
            updated_run["revision"] += 1

            base = self._ensure_assessment_directories(assessment_id)
            event_payload = {
                "audit_run_id": audit_run_id,
                "status": "in_progress",
            }
            event_obj, events_bytes = self._transaction_event(
                assessment_id, metadata, "audit_run_started", event_payload
            )

            txn = PrivateTransaction(base)
            txn.add_json("assessment.json", metadata)
            txn.add_json("audit_runs/{0}.json".format(audit_run_id), updated_run)
            txn.add_bytes("events.jsonl", events_bytes)
            txn.commit()

            res_run = _json_clone(updated_run, "invalid_audit_run", "audit_run")
            res_run["ready_to_start"] = False
            return {
                "audit_run": res_run,
                "assessment_revision": metadata["revision"],
                "assessment_capacity": self._get_assessment_capacity_unlocked(assessment_id),
                "event": event_obj,
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

            base = self._ensure_assessment_directories(assessment_id)
            event_payload = {
                "audit_run_id": audit_run_id,
                "status": "cancelled",
            }
            event_obj, events_bytes = self._transaction_event(
                assessment_id, metadata, "audit_run_cancelled", event_payload
            )

            txn = PrivateTransaction(base)
            txn.add_json("assessment.json", metadata)
            txn.add_json("audit_runs/{0}.json".format(audit_run_id), updated_run)
            txn.add_bytes("events.jsonl", events_bytes)
            txn.commit()

            res_run = _json_clone(updated_run, "invalid_audit_run", "audit_run")
            res_run["ready_to_start"] = False
            return {
                "audit_run": res_run,
                "assessment_revision": metadata["revision"],
                "assessment_capacity": self._get_assessment_capacity_unlocked(assessment_id),
                "event": event_obj,
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
                raise BackendError("audit_run_sealed", "cannot complete sealed audit run")
            if audit_run.get("status") != "in_progress":
                raise BackendError("invalid_audit_run_transition", "audit run must be in_progress to complete")
            if audit_run.get("revision") != expected_audit_run_revision:
                raise BackendError("revision_conflict", "audit run revision has changed")

            measurements = audit_run.get("measurements", [])
            incomplete = [m for m in measurements if m.get("status") not in ("completed", "failed")]
            if incomplete:
                raise BackendError("audit_run_incomplete", "all measurements must be completed or failed before closing run")

            updated_run = _json_clone(audit_run, "invalid_audit_run", "audit_run")
            updated_run["status"] = "completed"
            updated_run["completed_at"] = _utc_now()
            updated_run["revision"] += 1

            base = self._ensure_assessment_directories(assessment_id)
            event_payload = {
                "audit_run_id": audit_run_id,
                "status": "completed",
            }
            event_obj, events_bytes = self._transaction_event(
                assessment_id, metadata, "audit_run_completed", event_payload
            )

            txn = PrivateTransaction(base)
            txn.add_json("assessment.json", metadata)
            txn.add_json("audit_runs/{0}.json".format(audit_run_id), updated_run)
            txn.add_bytes("events.jsonl", events_bytes)
            txn.commit()

            res_run = _json_clone(updated_run, "invalid_audit_run", "audit_run")
            res_run["ready_to_start"] = False
            return {
                "audit_run": res_run,
                "assessment_revision": metadata["revision"],
                "assessment_capacity": self._get_assessment_capacity_unlocked(assessment_id),
                "event": event_obj,
            }

    # -------------------------------------------------------------------------
    # AuditRunMeasurement Persistence Primitives
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
            if target_m.get("status") not in ("pending", "failed"):
                raise BackendError("invalid_audit_run_transition", "cannot resolve measurement in status {0}".format(target_m.get("status")))

            status = outcome.get("status")
            if status not in ("resolved", "failed"):
                raise BackendError("invalid_audit_run_measurement", "resolve outcome status must be resolved or failed")

            updated_m = _json_clone(target_m, "invalid_audit_run_measurement", "measurement")
            updated_m.update(_json_clone(outcome, "invalid_audit_run_measurement", "outcome"))
            updated_m["audit_measurement_id"] = target_m["audit_measurement_id"]
            updated_m["audit_run_id"] = audit_run_id
            updated_m["assessment_id"] = assessment_id
            updated_m["measurement_point_id"] = measurement_point_id

            updated_measurements = list(measurements)
            updated_measurements[target_idx] = updated_m

            updated_run = _json_clone(audit_run, "invalid_audit_run", "audit_run")
            updated_run["measurements"] = updated_measurements
            updated_run["revision"] += 1

            base = self._ensure_assessment_directories(assessment_id)
            event_payload = {
                "audit_run_id": audit_run_id,
                "measurement_point_id": measurement_point_id,
                "audit_measurement_id": target_m["audit_measurement_id"],
                "status": status,
            }
            event_obj, events_bytes = self._transaction_event(
                assessment_id, metadata, "audit_measurement_resolved", event_payload
            )

            txn = PrivateTransaction(base)
            txn.add_json("assessment.json", metadata)
            txn.add_json("audit_runs/{0}.json".format(audit_run_id), updated_run)
            txn.add_bytes("events.jsonl", events_bytes)
            txn.commit()

            res_run = _json_clone(updated_run, "invalid_audit_run", "audit_run")
            res_run["ready_to_start"] = False
            return {
                "audit_run": res_run,
                "measurement": updated_m,
                "assessment_revision": metadata["revision"],
                "assessment_capacity": self._get_assessment_capacity_unlocked(assessment_id),
                "event": event_obj,
            }

    def retry_audit_measurement(
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

            updated_m = _json_clone(target_m, "invalid_audit_run_measurement", "measurement")
            for k in ("error_code", "error_message", "failed_stage", "retry_target", "failed_at"):
                updated_m.pop(k, None)

            updated_m.update(_json_clone(outcome, "invalid_audit_run_measurement", "outcome"))
            updated_m["audit_measurement_id"] = target_m["audit_measurement_id"]
            updated_m["audit_run_id"] = audit_run_id
            updated_m["assessment_id"] = assessment_id
            updated_m["measurement_point_id"] = measurement_point_id

            updated_measurements = list(measurements)
            updated_measurements[target_idx] = updated_m

            updated_run = _json_clone(audit_run, "invalid_audit_run", "audit_run")
            updated_run["measurements"] = updated_measurements
            updated_run["revision"] += 1

            base = self._ensure_assessment_directories(assessment_id)
            event_payload = {
                "audit_run_id": audit_run_id,
                "measurement_point_id": measurement_point_id,
                "audit_measurement_id": target_m["audit_measurement_id"],
                "status": updated_m.get("status"),
            }
            event_obj, events_bytes = self._transaction_event(
                assessment_id, metadata, "audit_measurement_retried", event_payload
            )

            txn = PrivateTransaction(base)
            txn.add_json("assessment.json", metadata)
            txn.add_json("audit_runs/{0}.json".format(audit_run_id), updated_run)
            txn.add_bytes("events.jsonl", events_bytes)
            txn.commit()

            res_run = _json_clone(updated_run, "invalid_audit_run", "audit_run")
            res_run["ready_to_start"] = False
            return {
                "audit_run": res_run,
                "measurement": updated_m,
                "assessment_revision": metadata["revision"],
                "assessment_capacity": self._get_assessment_capacity_unlocked(assessment_id),
                "event": event_obj,
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

            updated_m = _json_clone(target_m, "invalid_audit_run_measurement", "measurement")
            updated_m.update(_json_clone(outcome, "invalid_audit_run_measurement", "outcome"))
            updated_m["audit_measurement_id"] = target_m["audit_measurement_id"]
            updated_m["audit_run_id"] = audit_run_id
            updated_m["assessment_id"] = assessment_id
            updated_m["measurement_point_id"] = measurement_point_id

            updated_measurements = list(measurements)
            updated_measurements[target_idx] = updated_m

            updated_run = _json_clone(audit_run, "invalid_audit_run", "audit_run")
            updated_run["measurements"] = updated_measurements
            updated_run["revision"] += 1

            base = self._ensure_assessment_directories(assessment_id)
            event_payload = {
                "audit_run_id": audit_run_id,
                "measurement_point_id": measurement_point_id,
                "audit_measurement_id": target_m["audit_measurement_id"],
                "status": status,
            }
            event_obj, events_bytes = self._transaction_event(
                assessment_id, metadata, "audit_measurement_comparison_saved", event_payload
            )

            txn = PrivateTransaction(base)
            txn.add_json("assessment.json", metadata)
            txn.add_json("audit_runs/{0}.json".format(audit_run_id), updated_run)
            txn.add_bytes("events.jsonl", events_bytes)
            txn.commit()

            res_run = _json_clone(updated_run, "invalid_audit_run", "audit_run")
            res_run["ready_to_start"] = False
            return {
                "audit_run": res_run,
                "measurement": updated_m,
                "assessment_revision": metadata["revision"],
                "assessment_capacity": self._get_assessment_capacity_unlocked(assessment_id),
                "event": event_obj,
            }


def _canonical_bytes_single(value: Any) -> bytes:
    import json
    return json.dumps(value, ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n"
