"""Versioned Customer Audit Foundation persistence.

This module extends the v0.6.1 assessment store without rewriting its
immutable documents. New multi-document mutations use a recoverable journal.
"""

import datetime
import hashlib
import json
import os
import re
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from .assessment_store import (
    ASSESSMENT_SCHEMA_VERSION,
    BASELINE_VERSION_ID_PATTERN,
    FINDING_CORE_FIELDS,
    MAX_BASELINE_VERSIONS,
    MAX_COMPARISONS,
    MAX_FINDINGS,
    MAX_SNAPSHOTS,
    AssessmentStore,
    _canonical_digest,
    _json_clone,
    _utc_now,
    _validate_revision,
    _validate_comparison,
    _validate_finding_core,
    _validate_snapshot,
)
from .config import resolve_config_dir, write_private_file
from .errors import BackendError
from .storage_transaction import PrivateTransaction, recover_private_transactions


CUSTOMER_AUDIT_SCHEMA_VERSION = "1.2"
MEASUREMENT_PROFILE_SCHEMA_VERSION = "1.0"
ASSURANCE_PROFILE_SCHEMA_VERSION = "1.0"
BASELINE_MODEL_SCHEMA_VERSION = "1.0"
OCCURRENCE_SCHEMA_VERSION = "1.0"

MEASUREMENT_PROFILE_ID = re.compile(
    r"^mprofile_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
MEASUREMENT_PROFILE_VERSION_ID = re.compile(r"^mprofile_r[0-9]{4}$")
ASSURANCE_PROFILE_VERSION_ID = re.compile(r"^assurance_v[0-9]{4}$")
BASELINE_MODEL_ID = re.compile(r"^bmodel_[0-9a-f]{16}$")
OCCURRENCE_SET_ID = re.compile(r"^occurrence_[0-9a-f]{16}$")

MAX_MEASUREMENT_PROFILES = 100
MAX_ASSURANCE_PROFILES = 100
MAX_PROFILE_DOCUMENT_BYTES = 2 * 1024 * 1024


def _private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(str(path), 0o700)
    except OSError:
        pass


def _clean_text(value: Any, field: str, maximum: int, required: bool = False) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise BackendError("invalid_profile", "{0} must be a string".format(field))
    cleaned = "".join(character for character in value if ord(character) >= 32).strip()
    if len(cleaned) > maximum or (required and not cleaned):
        raise BackendError("invalid_profile", "{0} is invalid".format(field))
    return cleaned


def _integer_list(value: Any, field: str, minimum: int, maximum: int) -> List[int]:
    if not isinstance(value, list) or len(value) > 200:
        raise BackendError("invalid_profile", "{0} must be an array".format(field))
    result = []
    for item in value:
        if (
            not isinstance(item, int)
            or isinstance(item, bool)
            or item < minimum
            or item > maximum
        ):
            raise BackendError("invalid_profile", "{0} is invalid".format(field))
        if item not in result:
            result.append(item)
    return sorted(result)


def _text_list(
    value: Any, field: str, allowed: Optional[set] = None, maximum: int = 16
) -> List[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise BackendError("invalid_profile", "{0} must be an array".format(field))
    result = []
    for item in value:
        if (
            not isinstance(item, str)
            or not item
            or len(item) > 128
            or any(ord(character) < 32 for character in item)
            or (allowed is not None and item not in allowed)
        ):
            raise BackendError("invalid_profile", "{0} is invalid".format(field))
        if item not in result:
            result.append(item)
    return sorted(result)


def validate_measurement_profile(value: Any, partial: bool = False) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise BackendError("invalid_profile", "measurement profile must be an object")
    allowed = {
        "name",
        "description",
        "location_id",
        "measurement_point_id",
        "scan_profile_id",
        "radio_profile_id",
        "interface",
        "declared_bands",
        "declared_channels",
        "scan_time",
        "is_default",
        "five_ghz_operator_confirmed",
    }
    if set(value) - allowed:
        raise BackendError(
            "invalid_profile", "measurement profile contains unsupported fields"
        )
    required = allowed if not partial else set()
    if not partial and set(value) != required:
        missing = sorted(required - set(value))
        raise BackendError(
            "invalid_profile",
            "measurement profile fields are incomplete: {0}".format(
                ", ".join(missing)
            ),
        )
    result: Dict[str, Any] = {}
    for field, maximum, is_required in (
        ("name", 100, True),
        ("description", 500, False),
        ("location_id", 128, True),
        ("measurement_point_id", 128, True),
        ("scan_profile_id", 128, True),
        ("radio_profile_id", 128, True),
        ("interface", 64, True),
    ):
        if field in value:
            result[field] = _clean_text(
                value[field], field, maximum, is_required
            )
    if "declared_bands" in value:
        result["declared_bands"] = _text_list(
            value["declared_bands"], "declared_bands", {"2.4", "5"}, 2
        )
    if "declared_channels" in value:
        result["declared_channels"] = _integer_list(
            value["declared_channels"], "declared_channels", 1, 196
        )
    if "scan_time" in value:
        scan_time = value["scan_time"]
        if (
            not isinstance(scan_time, int)
            or isinstance(scan_time, bool)
            or scan_time < 30
            or scan_time > 3600
        ):
            raise BackendError(
                "invalid_profile", "scan_time must be between 30 and 3600"
            )
        result["scan_time"] = scan_time
    for field in ("is_default", "five_ghz_operator_confirmed"):
        if field in value:
            if not isinstance(value[field], bool):
                raise BackendError(
                    "invalid_profile", "{0} must be a boolean".format(field)
                )
            result[field] = value[field]
    if (
        result.get("declared_bands")
        and "5" in result["declared_bands"]
        and result.get("five_ghz_operator_confirmed") is not True
    ):
        raise BackendError(
            "five_ghz_confirmation_required",
            "5 GHz coverage must be explicitly confirmed by the operator",
        )
    return result


class CustomerAuditStore(AssessmentStore):
    """Persist versioned profiles, consensus baselines, and occurrences."""

    def __init__(
        self,
        config_dir: Optional[str] = None,
        fault_injector=None,
    ):
        super().__init__(config_dir)
        self.config_directory = resolve_config_dir(config_dir)
        self.measurement_directory = self.config_directory / "measurement_profiles"
        self.fault_injector = fault_injector
        recover_private_transactions(self.directory)
        recover_private_transactions(self.measurement_directory)

    def list_findings(
        self,
        assessment_id: str,
        status: Optional[str] = None,
        currently_observed: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        """Label pre-v0.6.2 findings as immutable legacy history."""
        results = super().list_findings(
            assessment_id, status, currently_observed
        )
        for finding in results:
            result_type = finding.get("details", {}).get("result_type")
            finding["legacy_read_only"] = result_type not in (
                "policy_deviation",
                "security_finding",
            )
        return results

    def update_finding(
        self,
        assessment_id: str,
        expected_revision: Any,
        finding_id: str,
        status: str,
        note: str = "",
    ) -> Dict[str, Any]:
        """Prevent retrospective reclassification of legacy findings."""
        matches = [
            item
            for item in super().list_findings(assessment_id)
            if item.get("finding_id") == finding_id
        ]
        if matches and matches[0].get("details", {}).get(
            "result_type"
        ) not in ("policy_deviation", "security_finding"):
            raise BackendError(
                "read_only_finding",
                "legacy finding is read-only and cannot be updated",
            )
        return super().update_finding(
            assessment_id,
            expected_revision,
            finding_id,
            status,
            note=note,
        )

    def _ensure_assessment_directories(self, assessment_id: str) -> Path:
        base = super()._ensure_assessment_directories(assessment_id)
        for name in (
            "baseline_models",
            "assurance_profiles",
            "occurrences",
            "exports",
        ):
            self._ensure_private_directory(base / name)
        recover_private_transactions(base)
        return base

    def _transaction_event(
        self,
        assessment_id: str,
        metadata: Dict[str, Any],
        event_type: str,
        data: Optional[Dict[str, Any]],
    ):
        now = _utc_now()
        metadata["revision"] += 1
        metadata["updated_at"] = now
        metadata["schema_version"] = ASSESSMENT_SCHEMA_VERSION
        metadata["storage_writer_version"] = ASSESSMENT_SCHEMA_VERSION
        metadata.setdefault("active_assurance_profile_version", None)
        metadata["last_event_sequence"] += 1
        event = {
            "sequence": metadata["last_event_sequence"],
            "event_id": "evt_{0}".format(uuid.uuid4()),
            "event_type": event_type,
            "recorded_at": now,
            "revision": metadata["revision"],
        }
        if data:
            event["data"] = data
        _, _, event_path, _, _ = self._assessment_paths(assessment_id)
        previous = event_path.read_bytes() if event_path.exists() else b""
        line = (
            json.dumps(
                event,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        return event, previous + line

    def _transaction(
        self, root: Path, json_documents: Dict[str, Any], bytes_documents=None
    ):
        transaction = PrivateTransaction(root, self.fault_injector)
        for relative, value in sorted(json_documents.items()):
            transaction.add_json(relative, value)
        for relative, value in sorted((bytes_documents or {}).items()):
            transaction.add_bytes(relative, value)
        return transaction.commit()

    # Measurement profiles -------------------------------------------------

    def _profile_base(self, profile_id: str) -> Path:
        if not isinstance(profile_id, str) or not MEASUREMENT_PROFILE_ID.match(
            profile_id
        ):
            raise BackendError(
                "invalid_measurement_profile_id",
                "measurement_profile_id is invalid",
            )
        return self.measurement_directory / profile_id

    def _profile_meta(self, profile_id: str) -> Dict[str, Any]:
        base = self._profile_base(profile_id)
        try:
            value = json.loads((base / "profile.json").read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise BackendError(
                "measurement_profile_not_found",
                "measurement profile was not found",
            )
        except (OSError, ValueError):
            raise BackendError(
                "storage_error", "measurement profile metadata is invalid"
            )
        if (
            not isinstance(value, dict)
            or value.get("measurement_profile_id") != profile_id
            or not isinstance(value.get("revision"), int)
        ):
            raise BackendError(
                "storage_error", "measurement profile metadata is invalid"
            )
        return value

    def _profile_version(self, profile_id: str, version_id: str) -> Dict[str, Any]:
        if not isinstance(version_id, str) or not MEASUREMENT_PROFILE_VERSION_ID.match(
            version_id
        ):
            raise BackendError(
                "invalid_measurement_profile_version",
                "measurement profile version is invalid",
            )
        try:
            value = json.loads(
                (self._profile_base(profile_id) / "versions" / (
                    version_id + ".json"
                )).read_text(encoding="utf-8")
            )
        except FileNotFoundError:
            raise BackendError(
                "measurement_profile_not_found",
                "measurement profile version was not found",
            )
        except (OSError, ValueError):
            raise BackendError(
                "storage_error", "measurement profile version is invalid"
            )
        return value

    def create_measurement_profile(self, value: Any) -> Dict[str, Any]:
        profile = validate_measurement_profile(value)
        _private_directory(self.measurement_directory)
        if len(list(self.measurement_directory.glob("mprofile_*"))) >= (
            MAX_MEASUREMENT_PROFILES
        ):
            raise BackendError(
                "measurement_profile_limit",
                "measurement profile limit was reached",
            )
        profile_id = "mprofile_{0}".format(uuid.uuid4())
        base = self._profile_base(profile_id)
        _private_directory(base / "versions")
        now = _utc_now()
        version_id = "mprofile_r0001"
        record = {
            "schema_version": MEASUREMENT_PROFILE_SCHEMA_VERSION,
            "measurement_profile_id": profile_id,
            "version_id": version_id,
            "revision": 1,
            "created_at": now,
            "profile": profile,
            "digest": _canonical_digest(profile),
        }
        metadata = {
            "schema_version": MEASUREMENT_PROFILE_SCHEMA_VERSION,
            "measurement_profile_id": profile_id,
            "revision": 1,
            "active_version_id": version_id,
            "status": "active",
            "created_at": now,
            "updated_at": now,
        }
        self._transaction(
            base,
            {
                "profile.json": metadata,
                "versions/{0}.json".format(version_id): record,
            },
        )
        return dict(metadata, active_version=record)

    def list_measurement_profiles(
        self, include_archived: bool = False
    ) -> List[Dict[str, Any]]:
        if not isinstance(include_archived, bool):
            raise BackendError(
                "invalid_request", "include_archived must be a boolean"
            )
        if not self.measurement_directory.exists():
            return []
        results = []
        for path in sorted(self.measurement_directory.glob("mprofile_*")):
            if not path.is_dir() or not MEASUREMENT_PROFILE_ID.match(path.name):
                continue
            metadata = self._profile_meta(path.name)
            if metadata["status"] == "archived" and not include_archived:
                continue
            record = self._profile_version(
                path.name, metadata["active_version_id"]
            )
            results.append(dict(metadata, active_version=record))
        return sorted(
            results,
            key=lambda item: (item["updated_at"], item["measurement_profile_id"]),
            reverse=True,
        )

    def update_measurement_profile(
        self, profile_id: str, expected_revision: Any, changes: Any
    ) -> Dict[str, Any]:
        normalized = validate_measurement_profile(changes, partial=True)
        if not normalized:
            raise BackendError("no_changes", "profile update did not change values")
        metadata = self._profile_meta(profile_id)
        revision = _validate_revision(expected_revision)
        if metadata["revision"] != revision:
            raise BackendError(
                "revision_conflict", "measurement profile revision has changed"
            )
        if metadata["status"] == "archived":
            raise BackendError(
                "measurement_profile_archived",
                "measurement profile is archived",
            )
        current = self._profile_version(profile_id, metadata["active_version_id"])
        profile = dict(current["profile"])
        profile.update(normalized)
        profile = validate_measurement_profile(profile)
        if profile == current["profile"]:
            raise BackendError("no_changes", "profile update did not change values")
        new_revision = revision + 1
        version_id = "mprofile_r{0:04d}".format(new_revision)
        now = _utc_now()
        record = {
            "schema_version": MEASUREMENT_PROFILE_SCHEMA_VERSION,
            "measurement_profile_id": profile_id,
            "version_id": version_id,
            "revision": new_revision,
            "created_at": now,
            "profile": profile,
            "digest": _canonical_digest(profile),
        }
        updated = dict(metadata)
        updated.update(
            {
                "revision": new_revision,
                "active_version_id": version_id,
                "updated_at": now,
            }
        )
        self._transaction(
            self._profile_base(profile_id),
            {
                "profile.json": updated,
                "versions/{0}.json".format(version_id): record,
            },
        )
        return dict(updated, active_version=record)

    def archive_measurement_profile(
        self, profile_id: str, expected_revision: Any
    ) -> Dict[str, Any]:
        metadata = self._profile_meta(profile_id)
        revision = _validate_revision(expected_revision)
        if metadata["revision"] != revision:
            raise BackendError(
                "revision_conflict", "measurement profile revision has changed"
            )
        if metadata["status"] == "archived":
            raise BackendError("no_changes", "measurement profile is archived")
        metadata["revision"] += 1
        metadata["status"] = "archived"
        metadata["updated_at"] = _utc_now()
        self._transaction(
            self._profile_base(profile_id), {"profile.json": metadata}
        )
        return dict(
            metadata,
            active_version=self._profile_version(
                profile_id, metadata["active_version_id"]
            ),
        )

    # Consensus baseline ---------------------------------------------------

    def _read_baseline_record(
        self, assessment_id: str, baseline_version_id: str
    ) -> Dict[str, Any]:
        path = self._baseline_path(assessment_id, baseline_version_id)
        record = self._read_json(
            path,
            "baseline_not_found",
            "baseline version was not found",
        )
        if (
            not isinstance(record, dict)
            or record.get("assessment_id") != assessment_id
            or record.get("baseline_version_id") != baseline_version_id
        ):
            raise BackendError(
                "storage_error", "baseline version is invalid"
            )
        if record.get("baseline_type") == "consensus":
            model_id = record.get("baseline_model_id")
            if not isinstance(model_id, str) or not BASELINE_MODEL_ID.match(
                model_id
            ):
                raise BackendError(
                    "storage_error", "baseline model reference is invalid"
                )
            return record
        snapshot_id = record.get("snapshot_id")
        if not isinstance(snapshot_id, str) or not re.match(
            r"^snapshot_[0-9a-f]{16}$", snapshot_id
        ):
            raise BackendError(
                "storage_error", "baseline version is invalid"
            )
        record.setdefault("baseline_type", "single_scan")
        return record

    def create_consensus_baseline_version(
        self,
        assessment_id: str,
        expected_revision: Any,
        snapshots: List[Dict[str, Any]],
        model: Dict[str, Any],
        label: str,
    ) -> Dict[str, Any]:
        normalized_snapshots = [_validate_snapshot(item) for item in snapshots]
        model = _json_clone(
            model,
            "invalid_consensus_baseline",
            "consensus baseline",
            MAX_PROFILE_DOCUMENT_BYTES,
        )
        model_id = model.get("baseline_model_id")
        if not isinstance(model_id, str) or not BASELINE_MODEL_ID.match(model_id):
            raise BackendError(
                "invalid_consensus_baseline", "baseline_model_id is invalid"
            )
        if model.get("schema_version") != BASELINE_MODEL_SCHEMA_VERSION:
            raise BackendError(
                "invalid_consensus_baseline",
                "baseline model schema_version is unsupported",
            )
        if not isinstance(label, str) or len(label) > 128:
            raise BackendError("invalid_baseline", "label is invalid")

        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_revision)
            base = self._ensure_assessment_directories(assessment_id)
            baseline_paths = sorted((base / "baselines").glob("baseline_v*.json"))
            if len(baseline_paths) >= MAX_BASELINE_VERSIONS:
                raise BackendError(
                    "baseline_limit",
                    "assessment baseline version limit was reached",
                )
            numbers = [
                int(path.stem[-4:])
                for path in baseline_paths
                if BASELINE_VERSION_ID_PATTERN.match(path.stem)
            ]
            number = max(numbers or [0]) + 1
            version_id = "baseline_v{0:04d}".format(number)
            now = _utc_now()
            record = {
                "schema_version": CUSTOMER_AUDIT_SCHEMA_VERSION,
                "assessment_id": assessment_id,
                "baseline_version_id": version_id,
                "baseline_type": "consensus",
                "version": number,
                "label": label.strip(),
                "created_at": now,
                "baseline_model_id": model_id,
                "baseline_model_digest": model.get("baseline_model_digest"),
                "source_snapshot_ids": [
                    item["snapshot_id"] for item in normalized_snapshots
                ],
                "source_snapshot_digests": [
                    item["snapshot_digest"] for item in normalized_snapshots
                ],
                "sample_count": len(normalized_snapshots),
                "summary": model.get("summary", {}),
                "measurement_context": model.get("measurement_context", {}),
                "max_source_age_hours": model.get("max_source_age_hours"),
            }
            previous_schema = metadata.get("schema_version")
            event, event_bytes = self._transaction_event(
                assessment_id,
                metadata,
                "consensus_baseline_version_created",
                {
                    "baseline_version_id": version_id,
                    "baseline_model_id": model_id,
                    "source_snapshot_ids": record["source_snapshot_ids"],
                    "sample_count": len(normalized_snapshots),
                },
            )
            documents = {
                "assessment.json": metadata,
                "baselines/{0}.json".format(version_id): record,
                "baseline_models/{0}.json".format(model_id): model,
            }
            for snapshot in normalized_snapshots:
                documents[
                    "snapshots/{0}.json".format(snapshot["snapshot_id"])
                ] = snapshot
            self._transaction(
                base, documents, {"events.jsonl": event_bytes}
            )
            if previous_schema == "1.0":
                # The transaction itself is the first 1.1 writer mutation.
                pass
        return {
            "assessment": metadata,
            "baseline_version": dict(record, is_active=False),
            "baseline_model": model,
            "event": event,
        }

    def get_baseline_version(
        self, assessment_id: str, baseline_version_id: str
    ) -> Dict[str, Any]:
        record = self._read_baseline_record(assessment_id, baseline_version_id)
        if record.get("baseline_type") != "consensus":
            result = super().get_baseline_version(
                assessment_id, baseline_version_id
            )
            result.setdefault("baseline_type", "single_scan")
            result.setdefault("legacy", record.get("schema_version") in ("1.0", "1.1"))
            return result
        model_id = record.get("baseline_model_id")
        if not isinstance(model_id, str) or not BASELINE_MODEL_ID.match(model_id):
            raise BackendError("storage_error", "baseline model reference is invalid")
        base = self._ensure_assessment_directories(assessment_id)
        try:
            model = json.loads(
                (base / "baseline_models" / (model_id + ".json")).read_text(
                    encoding="utf-8"
                )
            )
        except (OSError, ValueError):
            raise BackendError("storage_error", "baseline model is unavailable")
        result = dict(record)
        result["is_active"] = (
            self._read_metadata(assessment_id)["active_baseline_version"]
            == baseline_version_id
        )
        result["baseline_model"] = model
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
            event_data = {
                "baseline_version_id": baseline_version_id,
                "previous_baseline_version_id": previous,
                "baseline_type": record.get("baseline_type", "single_scan"),
            }
            if record.get("snapshot_id"):
                event_data["snapshot_id"] = record["snapshot_id"]
            if record.get("baseline_model_id"):
                event_data["baseline_model_id"] = record["baseline_model_id"]
            event, event_bytes = self._transaction_event(
                assessment_id,
                metadata,
                "baseline_version_activated",
                event_data,
            )
            base = self._ensure_assessment_directories(assessment_id)
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

    # Assurance profiles ---------------------------------------------------

    def _assurance_profile_path(
        self, assessment_id: str, version_id: str
    ) -> Path:
        if not isinstance(version_id, str) or not ASSURANCE_PROFILE_VERSION_ID.match(
            version_id
        ):
            raise BackendError(
                "invalid_assurance_profile",
                "assurance profile version is invalid",
            )
        base = self._ensure_assessment_directories(assessment_id)
        return base / "assurance_profiles" / (version_id + ".json")

    def create_assurance_profile_version(
        self,
        assessment_id: str,
        expected_revision: Any,
        profile: Any,
        label: Any = "",
    ) -> Dict[str, Any]:
        normalized = _json_clone(
            profile,
            "invalid_assurance_profile",
            "assurance profile",
            MAX_PROFILE_DOCUMENT_BYTES,
        )
        if not isinstance(normalized, dict):
            raise BackendError(
                "invalid_assurance_profile",
                "assurance profile must be an object",
            )
        if not isinstance(label, str) or len(label) > 128:
            raise BackendError("invalid_assurance_profile", "label is invalid")
        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_revision)
            base = self._ensure_assessment_directories(assessment_id)
            paths = sorted(
                (base / "assurance_profiles").glob("assurance_v*.json")
            )
            if len(paths) >= MAX_ASSURANCE_PROFILES:
                raise BackendError(
                    "assurance_profile_limit",
                    "assurance profile limit was reached",
                )
            numbers = [
                int(path.stem[-4:])
                for path in paths
                if ASSURANCE_PROFILE_VERSION_ID.match(path.stem)
            ]
            number = max(numbers or [0]) + 1
            version_id = "assurance_v{0:04d}".format(number)
            now = _utc_now()
            record = {
                "schema_version": ASSURANCE_PROFILE_SCHEMA_VERSION,
                "assessment_id": assessment_id,
                "assurance_profile_version_id": version_id,
                "version": number,
                "label": label.strip(),
                "created_at": now,
                "digest": _canonical_digest(normalized),
                "profile": normalized,
            }
            event, event_bytes = self._transaction_event(
                assessment_id,
                metadata,
                "assurance_profile_version_created",
                {
                    "assurance_profile_version_id": version_id,
                    "digest": record["digest"],
                },
            )
            self._transaction(
                base,
                {
                    "assessment.json": metadata,
                    "assurance_profiles/{0}.json".format(version_id): record,
                },
                {"events.jsonl": event_bytes},
            )
        return {
            "assessment": metadata,
            "assurance_profile_version": dict(record, is_active=False),
            "event": event,
        }

    def list_assurance_profile_versions(
        self, assessment_id: str
    ) -> List[Dict[str, Any]]:
        metadata = self._read_metadata(assessment_id)
        base = self._ensure_assessment_directories(assessment_id)
        results = []
        for path in sorted(
            (base / "assurance_profiles").glob("assurance_v*.json")
        ):
            if not ASSURANCE_PROFILE_VERSION_ID.match(path.stem):
                continue
            record = self.get_assurance_profile_version(
                assessment_id, path.stem
            )
            record.pop("profile", None)
            results.append(record)
        for record in results:
            record["is_active"] = (
                metadata["active_assurance_profile_version"]
                == record["assurance_profile_version_id"]
            )
        return results

    def get_assurance_profile_version(
        self, assessment_id: str, version_id: str
    ) -> Dict[str, Any]:
        self._read_metadata(assessment_id)
        try:
            record = json.loads(
                self._assurance_profile_path(
                    assessment_id, version_id
                ).read_text(encoding="utf-8")
            )
        except FileNotFoundError:
            raise BackendError(
                "assurance_profile_not_found",
                "assurance profile version was not found",
            )
        except (OSError, ValueError):
            raise BackendError(
                "storage_error", "assurance profile version is invalid"
            )
        record["is_active"] = (
            self._read_metadata(assessment_id)[
                "active_assurance_profile_version"
            ]
            == version_id
        )
        return record

    def activate_assurance_profile_version(
        self,
        assessment_id: str,
        expected_revision: Any,
        version_id: str,
        authoritative_confirmation: bool = False,
    ) -> Dict[str, Any]:
        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_revision)
            record = self.get_assurance_profile_version(
                assessment_id, version_id
            )
            coverage_mode = record.get("profile", {}).get(
                "inventory", {}
            ).get("coverage_mode", "partial")
            if (
                coverage_mode == "authoritative"
                and authoritative_confirmation is not True
            ):
                raise BackendError(
                    "authoritative_confirmation_required",
                    "authoritative inventory activation requires confirmation",
                )
            if metadata["active_assurance_profile_version"] == version_id:
                raise BackendError(
                    "no_changes", "assurance profile is already active"
                )
            previous = metadata["active_assurance_profile_version"]
            metadata["active_assurance_profile_version"] = version_id
            event, event_bytes = self._transaction_event(
                assessment_id,
                metadata,
                "assurance_profile_version_activated",
                {
                    "assurance_profile_version_id": version_id,
                    "previous_assurance_profile_version_id": previous,
                    "coverage_mode": coverage_mode,
                },
            )
            base = self._ensure_assessment_directories(assessment_id)
            self._transaction(
                base,
                {"assessment.json": metadata},
                {"events.jsonl": event_bytes},
            )
        return {
            "assessment": metadata,
            "assurance_profile_version": dict(record, is_active=True),
            "event": event,
        }

    # Immutable occurrences/evidence --------------------------------------

    def persist_customer_analysis(
        self,
        assessment_id: str,
        expected_revision: Any,
        baseline_version_id: str,
        comparison: Any,
        current_snapshot: Any,
        lifecycle_findings: Any,
        occurrence_set: Any,
        pinned_versions: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Atomically persist v0.6.2 facts, lifecycle state, and occurrences."""
        normalized_comparison = _validate_comparison(comparison)
        normalized_snapshot = _validate_snapshot(current_snapshot)
        if not isinstance(lifecycle_findings, list) or len(
            lifecycle_findings
        ) > MAX_FINDINGS:
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
        if not isinstance(pinned_versions, dict):
            raise BackendError(
                "invalid_analysis", "pinned_versions must be an object"
            )

        with self._lock(assessment_id):
            metadata = self._read_metadata(assessment_id)
            self._require_mutable(metadata, expected_revision)
            if metadata.get("active_baseline_version") != baseline_version_id:
                raise BackendError(
                    "baseline_changed",
                    "active baseline changed before analysis was saved",
                )
            baseline = self._read_baseline_record(
                assessment_id, baseline_version_id
            )
            active_assurance = metadata.get(
                "active_assurance_profile_version"
            )
            requested_assurance = pinned_versions.get(
                "assurance_profile_version_id"
            )
            if active_assurance != requested_assurance:
                raise BackendError(
                    "assurance_profile_changed",
                    "active assurance profile changed before analysis was saved",
                )
            if (
                normalized_comparison["current_snapshot_id"]
                != normalized_snapshot["snapshot_id"]
            ):
                raise BackendError(
                    "invalid_comparison",
                    "comparison current snapshot does not match",
                )

            base = self._ensure_assessment_directories(assessment_id)
            if len(list((base / "comparisons").glob("comparison_*.json"))) >= (
                MAX_COMPARISONS
            ):
                raise BackendError(
                    "comparison_limit",
                    "assessment comparison limit was reached",
                )
            snapshot_path = self._snapshot_path(
                assessment_id, normalized_snapshot["snapshot_id"]
            )
            if not snapshot_path.exists() and len(
                list((base / "snapshots").glob("snapshot_*.json"))
            ) >= MAX_SNAPSHOTS:
                raise BackendError(
                    "snapshot_limit",
                    "assessment snapshot limit was reached",
                )
            comparison_id = self._comparison_id(
                assessment_id, baseline_version_id, normalized_comparison
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
            by_id = {item["finding_id"]: item for item in stored_findings}
            status = normalized_comparison["comparability"]["status"]
            lifecycle = {
                "opened": [],
                "reopened": [],
                "updated": [],
                "resolved": [],
                "preserved_false_positive": [],
                "mutated": status != "not_comparable",
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

                # Partial observations can open positive issues, but only a
                # fully comparable clean measurement may resolve old issues.
                if status == "comparable":
                    for finding_id, existing in by_id.items():
                        if finding_id in observed_ids:
                            continue
                        existing["currently_observed"] = False
                        if existing["status"] in ("open", "acknowledged"):
                            existing["status"] = "resolved"
                            existing["status_updated_at"] = now
                            lifecycle["resolved"].append(finding_id)
                stored_findings = sorted(
                    by_id.values(), key=lambda item: item["finding_id"]
                )

            occurrence.update(
                {
                    "schema_version": OCCURRENCE_SCHEMA_VERSION,
                    "comparison_id": comparison_id,
                    "assessment_id": assessment_id,
                    "recorded_at": now,
                    "baseline_reference": {
                        "baseline_version_id": baseline_version_id,
                        "baseline_type": baseline.get(
                            "baseline_type", "single_scan"
                        ),
                        "digest": baseline.get(
                            "baseline_model_digest",
                            baseline.get("snapshot_digest"),
                        ),
                    },
                    "pinned_versions": pinned_versions,
                    "comparability": normalized_comparison["comparability"],
                    "lifecycle": lifecycle,
                }
            )
            occurrence_without_id = {
                key: value
                for key, value in occurrence.items()
                if key
                not in ("occurrence_set_id", "occurrence_digest")
            }
            occurrence_digest = _canonical_digest(occurrence_without_id)
            occurrence_id = "occurrence_{0}".format(
                occurrence_digest[:16]
            )
            occurrence["occurrence_set_id"] = occurrence_id
            occurrence["occurrence_digest"] = occurrence_digest

            record = {
                "schema_version": CUSTOMER_AUDIT_SCHEMA_VERSION,
                "comparison_id": comparison_id,
                "assessment_id": assessment_id,
                "baseline_version_id": baseline_version_id,
                "created_at": now,
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
                "pinned_versions": pinned_versions,
            }
            event, event_bytes = self._transaction_event(
                assessment_id,
                metadata,
                "customer_audit_analysis_persisted",
                {
                    "comparison_id": comparison_id,
                    "baseline_version_id": baseline_version_id,
                    "occurrence_set_id": occurrence_id,
                    "comparability_status": status,
                    "observed_change_count": len(
                        occurrence.get("observed_changes", [])
                    ),
                    "policy_deviation_count": len(
                        occurrence.get("policy_deviations", [])
                    ),
                    "security_finding_count": len(
                        occurrence.get("security_findings", [])
                    ),
                    "opened_count": len(lifecycle["opened"]),
                    "resolved_count": len(lifecycle["resolved"]),
                },
            )
            documents = {
                "assessment.json": metadata,
                "snapshots/{0}.json".format(
                    normalized_snapshot["snapshot_id"]
                ): normalized_snapshot,
                "comparisons/{0}.json".format(comparison_id): record,
                "occurrences/{0}.json".format(occurrence_id): occurrence,
            }
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
            "schema_version": CUSTOMER_AUDIT_SCHEMA_VERSION,
            "assessment": metadata,
            "comparison": record,
            "observed_changes": occurrence.get("observed_changes", []),
            "inventory_reconciliation": occurrence.get(
                "inventory_reconciliation", {}
            ),
            "policy_deviations": occurrence.get("policy_deviations", []),
            "security_findings": occurrence.get("security_findings", []),
            "policy_evaluation_status": occurrence.get(
                "policy_evaluation_status", "not_configured"
            ),
            "findings": stored_findings,
            "lifecycle": lifecycle,
            "event": event,
        }

    def persist_occurrence_set(
        self,
        assessment_id: str,
        comparison_id: str,
        occurrence_set: Any,
    ) -> Dict[str, Any]:
        record = _json_clone(
            occurrence_set,
            "invalid_occurrence_set",
            "occurrence set",
            MAX_PROFILE_DOCUMENT_BYTES,
        )
        if not isinstance(record, dict):
            raise BackendError(
                "invalid_occurrence_set", "occurrence set must be an object"
            )
        digest = _canonical_digest(record)
        occurrence_id = "occurrence_{0}".format(digest[:16])
        record.setdefault("schema_version", OCCURRENCE_SCHEMA_VERSION)
        record["occurrence_set_id"] = occurrence_id
        record["occurrence_digest"] = _canonical_digest(
            {
                key: value
                for key, value in record.items()
                if key != "occurrence_digest"
            }
        )
        base = self._ensure_assessment_directories(assessment_id)
        comparison = self.get_comparison(assessment_id, comparison_id)
        if comparison.get("occurrence_set_id") not in (None, occurrence_id):
            raise BackendError(
                "occurrence_conflict",
                "comparison already references another occurrence set",
            )
        path = base / "occurrences" / (occurrence_id + ".json")
        if path.exists():
            try:
                existing = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                raise BackendError(
                    "storage_error", "occurrence set is invalid"
                )
            if existing != record:
                raise BackendError(
                    "occurrence_conflict",
                    "occurrence set already exists with different content",
                )
        else:
            write_private_file(
                path,
                json.dumps(
                    record, ensure_ascii=False, indent=2, sort_keys=True
                ).encode("utf-8")
                + b"\n",
            )
        return record

    def get_occurrence_set(
        self, assessment_id: str, comparison_id: str
    ) -> Optional[Dict[str, Any]]:
        comparison = self.get_comparison(assessment_id, comparison_id)
        base = self._ensure_assessment_directories(assessment_id)
        direct = comparison.get("occurrence_set_id")
        if direct:
            candidates = [base / "occurrences" / (direct + ".json")]
        else:
            candidates = sorted(
                (base / "occurrences").glob("occurrence_*.json")
            )
        for path in candidates:
            try:
                record = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if record.get("comparison_id") == comparison_id:
                return record
        return None

    def list_occurrence_sets(self, assessment_id: str) -> List[Dict[str, Any]]:
        self._read_metadata(assessment_id)
        base = self._ensure_assessment_directories(assessment_id)
        results = []
        for path in sorted((base / "occurrences").glob("occurrence_*.json")):
            try:
                record = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                raise BackendError(
                    "storage_error", "occurrence history is invalid"
                )
            results.append(record)
        return results

    def get_snapshot(
        self, assessment_id: str, snapshot_id: str
    ) -> Dict[str, Any]:
        self._read_metadata(assessment_id)
        return _validate_snapshot(
            self._read_json(
                self._snapshot_path(assessment_id, snapshot_id),
                "snapshot_not_found",
                "snapshot was not found",
            )
        )

    def write_report_export(
        self,
        assessment_id: str,
        filename: str,
        content: str,
        ttl_seconds: int = 900,
    ) -> Dict[str, Any]:
        """Write a short-lived private export for Hak5 /api/download."""
        self._read_metadata(assessment_id)
        if (
            not isinstance(filename, str)
            or not filename
            or len(filename) > 180
            or not re.match(r"^[A-Za-z0-9._-]+$", filename)
            or filename in (".", "..")
        ):
            raise BackendError(
                "invalid_report", "report filename is unsafe"
            )
        if not isinstance(content, str):
            raise BackendError(
                "invalid_report", "report content must be text"
            )
        if (
            not isinstance(ttl_seconds, int)
            or isinstance(ttl_seconds, bool)
            or ttl_seconds < 60
            or ttl_seconds > 3600
        ):
            raise BackendError(
                "invalid_report", "report TTL is invalid"
            )
        base = self._ensure_assessment_directories(assessment_id)
        export_directory = base / "exports"
        now = datetime.datetime.now(datetime.timezone.utc)
        for path in export_directory.glob("PineAI-*"):
            try:
                age = now.timestamp() - path.stat().st_mtime
                if age > ttl_seconds:
                    path.unlink()
            except OSError:
                pass
        path = export_directory / filename
        write_private_file(path, content.encode("utf-8"))
        return {
            "filename": str(path),
            "expires_at": (
                now + datetime.timedelta(seconds=ttl_seconds)
            ).isoformat().replace("+00:00", "Z"),
            "download": {
                "method": "POST",
                "path": "/api/download",
                "body": {"filename": str(path)},
            },
        }

    def evidence_bundle(
        self,
        assessment_id: str,
        comparison_id: str,
        item_id: str,
    ) -> Dict[str, Any]:
        occurrence = self.get_occurrence_set(assessment_id, comparison_id)
        if occurrence is None:
            raise BackendError(
                "legacy_evidence_unavailable",
                "legacy comparison has no immutable evidence bundle",
            )
        items = []
        for field in (
            "observed_changes",
            "policy_deviations",
            "security_findings",
        ):
            for item in occurrence.get(field, []):
                identifier = (
                    item.get("change_id")
                    or item.get("deviation_id")
                    or item.get("finding_id")
                )
                if identifier == item_id:
                    items.append((field, item))
        if len(items) != 1:
            raise BackendError(
                "evidence_not_found",
                "the requested evidence item was not found uniquely",
            )
        field, item = items[0]
        evidence_by_id = {
            record["evidence_id"]: record
            for record in occurrence.get("evidence", [])
            if isinstance(record, dict) and "evidence_id" in record
        }
        evidence_ids = item.get("evidence_ids", [])
        before_after = item.get("before_after")
        if not isinstance(before_after, dict):
            before_after = {
                "before": item.get("expected"),
                "after": item.get("observed"),
            }
        return {
            "schema_version": OCCURRENCE_SCHEMA_VERSION,
            "comparison_id": comparison_id,
            "item_type": field[:-1],
            "item": item,
            "before_after": before_after,
            "evidence": [
                evidence_by_id[evidence_id]
                for evidence_id in evidence_ids
                if evidence_id in evidence_by_id
            ],
            "recorded_at": occurrence.get("recorded_at"),
            "baseline_reference": occurrence.get("baseline_reference"),
            "pinned_versions": occurrence.get("pinned_versions"),
            "comparability": occurrence.get("comparability"),
            "quality_factors": occurrence.get("quality_factors", []),
            "policy": occurrence.get("policy_reference"),
            "limitations": occurrence.get("limitations", []),
        }
