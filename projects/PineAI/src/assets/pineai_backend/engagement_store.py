"""Persistent, revisioned engagement state for Attack-Path Advisor."""

import datetime
import json
import os
import re
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .config import resolve_config_dir, write_private_file
from .errors import BackendError


ENGAGEMENT_SCHEMA_VERSION = "1.0"
TARGET_ID_PATTERN = re.compile(r"^target_[0-9a-f]{12}$")
EVIDENCE_ID_PATTERN = re.compile(r"^evidence_[0-9a-f]{12}$")
ENGAGEMENT_ID_PATTERN = re.compile(
    r"^eng_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)

OBJECTIVE_CODES = (
    "wireless_mapping",
    "enterprise_authentication",
    "guest_network_security",
    "captive_portal_security",
    "rogue_ap_resilience",
    "client_awareness",
    "credential_capture_assessment",
)

ACTION_IDS = (
    "collect_additional_recon",
    "passive_handshake_capture",
    "test_device_association",
    "captive_portal_inspection",
    "enterprise_eap_validation",
    "authorized_deauthentication",
    "evil_twin_simulation",
)

EVENT_TYPES = (
    "action_started",
    "action_completed",
    "action_failed",
    "action_aborted",
    "operator_note",
)

EDITABLE_FIELDS = {
    "name",
    "objectives",
    "objective_notes",
    "authorized_target_ids",
    "allowed_actions",
    "disruption_allowed",
    "authorization_reference",
    "valid_from",
    "valid_until",
}

MAX_EVENTS = 1000
SYSTEM_EVENT_PREFIXES = ("adaptive_recon_",)


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )


def parse_utc(value: Any, field: str) -> datetime.datetime:
    if not isinstance(value, str) or not value:
        raise BackendError("invalid_engagement", "{0} must be an ISO-8601 timestamp".format(field))
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise BackendError("invalid_engagement", "{0} must be an ISO-8601 timestamp".format(field))
    if parsed.tzinfo is None:
        raise BackendError("invalid_engagement", "{0} must include a timezone".format(field))
    return parsed.astimezone(datetime.timezone.utc)


def normalize_utc(value: Any, field: str) -> str:
    return parse_utc(value, field).isoformat().replace("+00:00", "Z")


def _string(value: Any, field: str, minimum: int, maximum: int) -> str:
    if not isinstance(value, str):
        raise BackendError("invalid_engagement", "{0} must be a string".format(field))
    clean = "".join(character for character in value if ord(character) >= 32).strip()
    if len(clean) < minimum or len(clean) > maximum:
        raise BackendError(
            "invalid_engagement",
            "{0} must contain {1}-{2} characters".format(field, minimum, maximum),
        )
    return clean


def _unique_enum_list(
    value: Any, field: str, allowed: Iterable[str], minimum: int, maximum: int
) -> List[str]:
    if not isinstance(value, list) or len(value) < minimum or len(value) > maximum:
        raise BackendError(
            "invalid_engagement",
            "{0} must contain {1}-{2} items".format(field, minimum, maximum),
        )
    allowed_values = set(allowed)
    result = []
    for item in value:
        if item not in allowed_values:
            raise BackendError("invalid_engagement", "{0} contains an unknown value".format(field))
        if item not in result:
            result.append(item)
    return result


def _target_ids(value: Any) -> List[str]:
    if not isinstance(value, list) or not value or len(value) > 200:
        raise BackendError(
            "invalid_engagement", "authorized_target_ids must contain 1-200 target IDs"
        )
    result = []
    for item in value:
        if not isinstance(item, str) or not TARGET_ID_PATTERN.match(item):
            raise BackendError(
                "invalid_engagement", "authorized_target_ids contains an invalid target ID"
            )
        if item not in result:
            result.append(item)
    return result


def validate_engagement_fields(value: Any, partial: bool = False) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise BackendError("invalid_engagement", "engagement must be a JSON object")
    if set(value) - EDITABLE_FIELDS:
        raise BackendError("invalid_engagement", "engagement contains unknown fields")
    if partial and not value:
        raise BackendError("invalid_engagement", "engagement update is empty")
    if not partial and set(value) != EDITABLE_FIELDS:
        missing = sorted(EDITABLE_FIELDS - set(value))
        raise BackendError(
            "invalid_engagement",
            "engagement is missing fields: {0}".format(", ".join(missing)),
        )

    result = {}
    if "name" in value:
        result["name"] = _string(value["name"], "name", 1, 100)
    if "objectives" in value:
        result["objectives"] = _unique_enum_list(
            value["objectives"], "objectives", OBJECTIVE_CODES, 1, 5
        )
    if "objective_notes" in value:
        result["objective_notes"] = _string(
            value["objective_notes"], "objective_notes", 0, 1000
        )
    if "authorized_target_ids" in value:
        result["authorized_target_ids"] = _target_ids(value["authorized_target_ids"])
    if "allowed_actions" in value:
        result["allowed_actions"] = _unique_enum_list(
            value["allowed_actions"], "allowed_actions", ACTION_IDS, 1, len(ACTION_IDS)
        )
    if "disruption_allowed" in value:
        if not isinstance(value["disruption_allowed"], bool):
            raise BackendError(
                "invalid_engagement", "disruption_allowed must be a boolean"
            )
        result["disruption_allowed"] = value["disruption_allowed"]
    if "authorization_reference" in value:
        result["authorization_reference"] = _string(
            value["authorization_reference"], "authorization_reference", 1, 200
        )
    if "valid_from" in value:
        result["valid_from"] = normalize_utc(value["valid_from"], "valid_from")
    if "valid_until" in value:
        result["valid_until"] = normalize_utc(value["valid_until"], "valid_until")
    return result


def validate_time_window(engagement: Dict[str, Any]) -> None:
    start = parse_utc(engagement["valid_from"], "valid_from")
    end = parse_utc(engagement["valid_until"], "valid_until")
    if end <= start:
        raise BackendError("invalid_engagement", "valid_until must be later than valid_from")


class EngagementStore:
    """Store engagement metadata and append-only audit events."""

    def __init__(self, config_dir: Optional[str] = None):
        self.directory = resolve_config_dir(config_dir) / "engagements"

    def _ensure_directory(self) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(str(self.directory), 0o700)
        except OSError:
            pass

    def _paths(self, engagement_id: str) -> tuple:
        if not isinstance(engagement_id, str) or not ENGAGEMENT_ID_PATTERN.match(
            engagement_id
        ):
            raise BackendError("invalid_engagement_id", "engagement_id is invalid")
        return (
            self.directory / "{0}.json".format(engagement_id),
            self.directory / "{0}.events.jsonl".format(engagement_id),
            self.directory / "{0}.lock".format(engagement_id),
        )

    @contextmanager
    def _lock(self, engagement_id: str):
        self._ensure_directory()
        _, _, lock_path = self._paths(engagement_id)
        deadline = time.monotonic() + 2.0
        descriptor = None
        while descriptor is None:
            try:
                descriptor = os.open(
                    str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600
                )
            except FileExistsError:
                try:
                    stale = time.time() - lock_path.stat().st_mtime > 30
                except OSError:
                    stale = False
                if stale:
                    try:
                        lock_path.unlink()
                    except OSError:
                        pass
                    continue
                if time.monotonic() >= deadline:
                    raise BackendError("storage_busy", "engagement storage is busy")
                time.sleep(0.05)
        try:
            os.write(descriptor, str(os.getpid()).encode("ascii"))
            os.close(descriptor)
            descriptor = None
            yield
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                lock_path.unlink()
            except OSError:
                pass

    def _read_metadata(self, engagement_id: str) -> Dict[str, Any]:
        metadata_path, _, _ = self._paths(engagement_id)
        try:
            value = json.loads(metadata_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise BackendError("engagement_not_found", "engagement was not found")
        except (OSError, ValueError):
            raise BackendError("storage_error", "engagement metadata could not be read")
        if not isinstance(value, dict) or value.get("engagement_id") != engagement_id:
            raise BackendError("storage_error", "engagement metadata is invalid")
        return value

    def _read_events(self, engagement_id: str) -> List[Dict[str, Any]]:
        _, events_path, _ = self._paths(engagement_id)
        if not events_path.exists():
            return []
        events = []
        try:
            for line in events_path.read_text(encoding="utf-8").splitlines():
                event = json.loads(line)
                if not isinstance(event, dict):
                    raise ValueError()
                events.append(event)
        except (OSError, ValueError):
            raise BackendError("storage_error", "engagement events could not be read")
        return events

    def _write_metadata(self, metadata: Dict[str, Any]) -> None:
        metadata_path, _, _ = self._paths(metadata["engagement_id"])
        write_private_file(
            metadata_path,
            json.dumps(metadata, indent=2, sort_keys=True).encode("utf-8") + b"\n",
        )

    def _write_events(self, engagement_id: str, events: List[Dict[str, Any]]) -> None:
        _, events_path, _ = self._paths(engagement_id)
        payload = "".join(
            json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n"
            for event in events
        ).encode("utf-8")
        write_private_file(events_path, payload)

    def create(self, value: Any) -> Dict[str, Any]:
        fields = validate_engagement_fields(value)
        validate_time_window(fields)
        engagement_id = "eng_{0}".format(uuid.uuid4())
        now = _utc_now()
        metadata = {
            "schema_version": ENGAGEMENT_SCHEMA_VERSION,
            "engagement_id": engagement_id,
            "status": "active",
            "revision": 1,
            "created_at": now,
            "updated_at": now,
            "last_event_sequence": 1,
        }
        metadata.update(fields)
        event = {
            "sequence": 1,
            "event_id": "evt_{0}".format(uuid.uuid4()),
            "event_type": "engagement_created",
            "recorded_at": now,
            "revision": 1,
        }
        with self._lock(engagement_id):
            self._write_metadata(metadata)
            self._write_events(engagement_id, [event])
        result = dict(metadata)
        result["events"] = [event]
        return result

    def get(
        self, engagement_id: str, after_sequence: int = 0, limit: int = 100
    ) -> Dict[str, Any]:
        if (
            not isinstance(after_sequence, int)
            or isinstance(after_sequence, bool)
            or after_sequence < 0
        ):
            raise BackendError("invalid_request", "after_sequence must be non-negative")
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1 or limit > 100:
            raise BackendError("invalid_request", "limit must be between 1 and 100")
        metadata = self._read_metadata(engagement_id)
        events = [
            event
            for event in self._read_events(engagement_id)
            if event.get("sequence", 0) > after_sequence
        ][:limit]
        result = dict(metadata)
        result["events"] = events
        result["events_has_more"] = bool(
            events and events[-1]["sequence"] < metadata["last_event_sequence"]
        )
        return result

    def list(self, include_archived: bool = False) -> List[Dict[str, Any]]:
        if not isinstance(include_archived, bool):
            raise BackendError("invalid_request", "include_archived must be a boolean")
        if not self.directory.exists():
            return []
        results = []
        for path in sorted(self.directory.glob("eng_*.json")):
            if path.name.endswith(".events.json"):
                continue
            engagement_id = path.stem
            if not ENGAGEMENT_ID_PATTERN.match(engagement_id):
                continue
            metadata = self._read_metadata(engagement_id)
            if include_archived or metadata["status"] != "archived":
                results.append(metadata)
        return sorted(results, key=lambda item: (item["updated_at"], item["engagement_id"]), reverse=True)

    def all_events(self, engagement_id: str) -> List[Dict[str, Any]]:
        """Return all events for internal policy evaluation."""
        self._read_metadata(engagement_id)
        return self._read_events(engagement_id)

    def append_system_event(
        self,
        engagement_id: str,
        expected_revision: Any,
        event_type: str,
        data: Any,
    ) -> Dict[str, Any]:
        """Append a prevalidated internal event under engagement revision control."""
        if not isinstance(expected_revision, int) or isinstance(expected_revision, bool):
            raise BackendError("invalid_request", "expected_revision must be an integer")
        if (
            not isinstance(event_type, str)
            or not any(event_type.startswith(prefix) for prefix in SYSTEM_EVENT_PREFIXES)
        ):
            raise BackendError("invalid_event", "internal event_type is invalid")
        if not isinstance(data, dict):
            raise BackendError("invalid_event", "internal event data must be an object")
        try:
            encoded = json.dumps(data, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        except (TypeError, ValueError):
            raise BackendError("invalid_event", "internal event data is not JSON")
        if len(encoded) > 131072:
            raise BackendError("invalid_event", "internal event data is too large")

        with self._lock(engagement_id):
            metadata = self._read_metadata(engagement_id)
            if metadata["status"] == "archived":
                raise BackendError("engagement_archived", "engagement is archived")
            if metadata["revision"] != expected_revision:
                raise BackendError("revision_conflict", "engagement revision has changed")
            events = self._read_events(engagement_id)
            if len(events) >= MAX_EVENTS:
                raise BackendError("event_limit", "engagement event limit was reached")
            metadata["revision"] += 1
            metadata["updated_at"] = _utc_now()
            event = {
                "sequence": metadata["last_event_sequence"] + 1,
                "event_id": "evt_{0}".format(uuid.uuid4()),
                "event_type": event_type,
                "recorded_at": metadata["updated_at"],
                "revision": metadata["revision"],
                "data": data,
            }
            metadata["last_event_sequence"] = event["sequence"]
            events.append(event)
            self._write_metadata(metadata)
            self._write_events(engagement_id, events)
        return {"engagement": metadata, "event": event}

    def update(
        self, engagement_id: str, expected_revision: Any, changes: Any
    ) -> Dict[str, Any]:
        if not isinstance(expected_revision, int) or isinstance(expected_revision, bool):
            raise BackendError("invalid_request", "expected_revision must be an integer")
        validated = validate_engagement_fields(changes, partial=True)
        with self._lock(engagement_id):
            metadata = self._read_metadata(engagement_id)
            if metadata["status"] == "archived":
                raise BackendError("engagement_archived", "engagement is archived")
            if metadata["revision"] != expected_revision:
                raise BackendError("revision_conflict", "engagement revision has changed")
            updated = dict(metadata)
            changed_fields = {}
            for key, new_value in validated.items():
                if updated.get(key) != new_value:
                    changed_fields[key] = {"old": updated.get(key), "new": new_value}
                    updated[key] = new_value
            if not changed_fields:
                raise BackendError("no_changes", "engagement update did not change values")
            validate_time_window(updated)
            updated["revision"] += 1
            updated["updated_at"] = _utc_now()
            events = self._read_events(engagement_id)
            event = {
                "sequence": updated["last_event_sequence"] + 1,
                "event_id": "evt_{0}".format(uuid.uuid4()),
                "event_type": "engagement_updated",
                "recorded_at": updated["updated_at"],
                "revision": updated["revision"],
                "changes": changed_fields,
            }
            updated["last_event_sequence"] = event["sequence"]
            events.append(event)
            self._write_metadata(updated)
            self._write_events(engagement_id, events)
        result = dict(updated)
        result["events"] = [event]
        return result

    def archive(self, engagement_id: str, expected_revision: Any) -> Dict[str, Any]:
        if not isinstance(expected_revision, int) or isinstance(expected_revision, bool):
            raise BackendError("invalid_request", "expected_revision must be an integer")
        with self._lock(engagement_id):
            metadata = self._read_metadata(engagement_id)
            if metadata["revision"] != expected_revision:
                raise BackendError("revision_conflict", "engagement revision has changed")
            if metadata["status"] == "archived":
                raise BackendError("engagement_archived", "engagement is already archived")
            metadata["status"] = "archived"
            metadata["revision"] += 1
            metadata["updated_at"] = _utc_now()
            events = self._read_events(engagement_id)
            event = {
                "sequence": metadata["last_event_sequence"] + 1,
                "event_id": "evt_{0}".format(uuid.uuid4()),
                "event_type": "engagement_archived",
                "recorded_at": metadata["updated_at"],
                "revision": metadata["revision"],
            }
            metadata["last_event_sequence"] = event["sequence"]
            events.append(event)
            self._write_metadata(metadata)
            self._write_events(engagement_id, events)
        result = dict(metadata)
        result["events"] = [event]
        return result

    def append_event(
        self, engagement_id: str, expected_revision: Any, value: Any
    ) -> Dict[str, Any]:
        if not isinstance(expected_revision, int) or isinstance(expected_revision, bool):
            raise BackendError("invalid_request", "expected_revision must be an integer")
        if not isinstance(value, dict):
            raise BackendError("invalid_event", "event must be a JSON object")
        required = {"event_type", "summary", "target_id", "action_id", "evidence_ids"}
        if set(value) != required:
            raise BackendError("invalid_event", "event fields are invalid")
        event_type = value["event_type"]
        if event_type not in EVENT_TYPES:
            raise BackendError("invalid_event", "event_type is invalid")
        summary = _string(value["summary"], "summary", 0, 1000)
        target_id = value["target_id"]
        action_id = value["action_id"]
        if event_type == "operator_note":
            if target_id is not None or action_id is not None:
                raise BackendError(
                    "invalid_event", "operator_note target_id and action_id must be null"
                )
        else:
            if not isinstance(target_id, str) or not TARGET_ID_PATTERN.match(target_id):
                raise BackendError("invalid_event", "event target_id is invalid")
            if action_id not in ACTION_IDS:
                raise BackendError("invalid_event", "event action_id is invalid")
        evidence_ids = value["evidence_ids"]
        if not isinstance(evidence_ids, list) or len(evidence_ids) > 50:
            raise BackendError("invalid_event", "evidence_ids must contain at most 50 items")
        for evidence_id in evidence_ids:
            if not isinstance(evidence_id, str) or not EVIDENCE_ID_PATTERN.match(evidence_id):
                raise BackendError("invalid_event", "evidence_ids contains an invalid value")

        with self._lock(engagement_id):
            metadata = self._read_metadata(engagement_id)
            if metadata["status"] == "archived":
                raise BackendError("engagement_archived", "engagement is archived")
            if metadata["revision"] != expected_revision:
                raise BackendError("revision_conflict", "engagement revision has changed")
            if target_id is not None and target_id not in metadata["authorized_target_ids"]:
                raise BackendError("target_out_of_scope", "event target is outside engagement scope")
            events = self._read_events(engagement_id)
            if len(events) >= MAX_EVENTS:
                raise BackendError("event_limit", "engagement event limit was reached")
            metadata["revision"] += 1
            metadata["updated_at"] = _utc_now()
            event = {
                "sequence": metadata["last_event_sequence"] + 1,
                "event_id": "evt_{0}".format(uuid.uuid4()),
                "event_type": event_type,
                "recorded_at": metadata["updated_at"],
                "revision": metadata["revision"],
                "summary": summary,
                "target_id": target_id,
                "action_id": action_id,
                "evidence_ids": list(dict.fromkeys(evidence_ids)),
            }
            metadata["last_event_sequence"] = event["sequence"]
            events.append(event)
            self._write_metadata(metadata)
            self._write_events(engagement_id, events)
        result = dict(metadata)
        result["event"] = event
        return result
