"""Pure deterministic consensus-baseline construction.

The module deliberately knows nothing about assessment storage or module
actions.  It consumes already resolved PineAI snapshots and returns a
canonical model which can be persisted by a higher layer.
"""

import hashlib
import json
import math
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .errors import BackendError
from .timestamps import (
    normalize_rfc3339_utc,
    rfc3339_order_key,
    validate_rfc3339,
)


CONSENSUS_SCHEMA_VERSION = "1.0"
CONSENSUS_POLICY_ID = "strict_80_v1"
MIN_CONSENSUS_SCANS = 2
MAX_CONSENSUS_SCANS = 5
MAX_CONSENSUS_WINDOW_SECONDS = 24 * 60 * 60
DEFAULT_MAX_SOURCE_AGE_HOURS = 24
MIN_MAX_SOURCE_AGE_HOURS = 1
MAX_MAX_SOURCE_AGE_HOURS = 168
UNBOUNDED_SOURCE_AGE_LIMITATION = "source_age_window_unbounded"

CANONICAL_BSSID = re.compile(r"^(?:[0-9A-F]{2}:){5}[0-9A-F]{2}$")
SNAPSHOT_ID = re.compile(r"^snapshot_[0-9a-f]{16}$")
SNAPSHOT_DIGEST = re.compile(r"^[0-9a-f]{64}$")
ASSET_ID = re.compile(r"^ap_[0-9a-f]{12}$")
EVIDENCE_ID = re.compile(r"^evidence_[0-9a-f]{12}$")

CONTEXT_FIELDS = (
    "location_id",
    "measurement_point_id",
    "scan_profile_id",
    "radio_profile_id",
    "interface",
    "measurement_profile_id",
    "measurement_profile_version_id",
    "measurement_profile_digest",
    "declared_coverage",
    "declared_channels_scanned",
)
ATTRIBUTE_FIELDS = (
    "network_id",
    "ssid",
    "hidden",
    "encryption",
    "wps",
    "vendor",
    "band",
)


def _median(values: Iterable[Any]) -> Any:
    """Return the deterministic median without the optional decimal module."""

    ordered = sorted(values)
    if not ordered:
        raise ValueError("median requires at least one value")
    midpoint = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[midpoint]
    return (ordered[midpoint - 1] + ordered[midpoint]) / 2


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError):
        raise BackendError(
            "invalid_consensus_input",
            "consensus input must contain JSON-compatible values",
        )


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _strict_threshold(count: int) -> int:
    return int(math.ceil(count * 0.8))


def _parse_observed_at(value: Any) -> Optional[Tuple[int, int]]:
    if value is None:
        return None
    validate_rfc3339(
        value,
        "snapshot observed_at",
        "invalid_consensus_time",
    )
    try:
        key = rfc3339_order_key(value)
        normalize_rfc3339_utc(value)
        return key
    except ValueError as failure:  # Defensive UTC range validation.
        raise BackendError(
            "invalid_consensus_time",
            "snapshot observed_at must be an RFC3339 timestamp or null",
        ) from failure


def _common_context(snapshots: List[Dict[str, Any]]) -> Dict[str, Any]:
    profiles = []
    for snapshot in snapshots:
        profile = snapshot.get("comparability_profile")
        if not isinstance(profile, dict):
            raise BackendError(
                "invalid_consensus_input",
                "every snapshot must contain a comparability_profile",
            )
        profiles.append(profile)

    common = {}
    for field in CONTEXT_FIELDS:
        values = [profile.get(field) for profile in profiles]
        canonical_values = {_canonical_json(value) for value in values}
        if len(canonical_values) != 1:
            raise BackendError(
                "consensus_context_mismatch",
                "consensus snapshots must use the same {0}".format(field),
            )
        common[field] = values[0]

    scan_times = [profile.get("scan_time") for profile in profiles]
    if any(
        value is not None
        and (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value <= 0
        )
        for value in scan_times
    ):
        raise BackendError(
            "invalid_consensus_input",
            "scan_time must be a positive integer or null",
        )
    known_scan_times = [
        value
        for value in scan_times
        if isinstance(value, int) and not isinstance(value, bool) and value > 0
    ]
    if known_scan_times and len(known_scan_times) != len(scan_times):
        raise BackendError(
            "consensus_context_mismatch",
            "scan duration must be known for every snapshot or for none",
        )
    common["scan_time_median"] = (
        _median(known_scan_times) if known_scan_times else None
    )
    return common


def _time_window(
    snapshots: List[Dict[str, Any]],
    max_source_age_hours: Optional[int],
) -> Dict[str, Any]:
    parsed = [
        (snapshot.get("observed_at"), _parse_observed_at(snapshot.get("observed_at")))
        for snapshot in snapshots
    ]
    known = [value for value in parsed if value[1] is not None]
    if not known:
        return {
            "status": "unknown",
            "started_at": None,
            "ended_at": None,
            "duration_seconds": None,
        }
    if len(known) != len(parsed):
        raise BackendError(
            "consensus_time_mismatch",
            "observed_at must be known for every snapshot or null for every snapshot",
        )
    started_value, started_key = min(known, key=lambda item: item[1])
    ended_value, ended_key = max(known, key=lambda item: item[1])
    duration_nanoseconds = (
        (ended_key[0] - started_key[0]) * 1_000_000_000
        + ended_key[1]
        - started_key[1]
    )
    duration = duration_nanoseconds // 1_000_000_000
    maximum_seconds = (
        max_source_age_hours * 60 * 60
        if max_source_age_hours is not None
        else None
    )
    if (
        maximum_seconds is not None
        and duration_nanoseconds > maximum_seconds * 1_000_000_000
    ):
        raise BackendError(
            "consensus_time_window_exceeded",
            "consensus snapshots exceed max_source_age_hours",
        )
    return {
        "status": "bounded",
        "started_at": normalize_rfc3339_utc(started_value),
        "ended_at": normalize_rfc3339_utc(ended_value),
        "duration_seconds": duration,
    }


def _value_counts(values: Iterable[Any]) -> List[Dict[str, Any]]:
    indexed: Dict[str, Dict[str, Any]] = {}
    for value in values:
        key = _canonical_json(value)
        if key not in indexed:
            indexed[key] = {"value": value, "count": 0}
        indexed[key]["count"] += 1
    return sorted(
        indexed.values(),
        key=lambda item: (-item["count"], _canonical_json(item["value"])),
    )


def _attribute_consensus(values: List[Any]) -> Dict[str, Any]:
    counts = _value_counts(values)
    required = _strict_threshold(len(values))
    winner = counts[0]
    has_consensus = winner["count"] >= required
    return {
        "status": "consensus" if has_consensus else "ambiguous",
        "value": winner["value"] if has_consensus else None,
        "support_count": winner["count"],
        "required_count": required,
        "observation_count": len(values),
        "support_ratio": round(winner["count"] / float(len(values)), 4),
        "values": counts,
    }


def _signal_summary(values: Iterable[Any]) -> Dict[str, Any]:
    signals = sorted(
        value
        for value in values
        if isinstance(value, int) and not isinstance(value, bool) and value < 0
    )
    if not signals:
        return {
            "observation_count": 0,
            "median_dbm": None,
            "median_absolute_deviation_db": None,
            "minimum_dbm": None,
            "maximum_dbm": None,
        }
    median = _median(signals)
    deviation = _median(abs(value - median) for value in signals)
    return {
        "observation_count": len(signals),
        "median_dbm": median,
        "median_absolute_deviation_db": deviation,
        "minimum_dbm": min(signals),
        "maximum_dbm": max(signals),
    }


def _validate_snapshots(value: Any) -> List[Dict[str, Any]]:
    if not isinstance(value, list) or not (
        MIN_CONSENSUS_SCANS <= len(value) <= MAX_CONSENSUS_SCANS
    ):
        raise BackendError(
            "invalid_consensus_input",
            "consensus requires two to five resolved snapshots",
        )
    snapshots = []
    seen_ids = set()
    seen_digests = set()
    seen_source_ids = set()
    for snapshot in value:
        if not isinstance(snapshot, dict):
            raise BackendError(
                "invalid_consensus_input",
                "every consensus observation must be a resolved snapshot",
            )
        snapshot_id = snapshot.get("snapshot_id")
        digest = snapshot.get("snapshot_digest")
        if not isinstance(snapshot_id, str) or not SNAPSHOT_ID.match(snapshot_id):
            raise BackendError(
                "invalid_consensus_input", "snapshot_id is invalid"
            )
        if not isinstance(digest, str) or not SNAPSHOT_DIGEST.match(digest):
            raise BackendError(
                "invalid_consensus_input", "snapshot_digest is invalid"
            )
        if snapshot_id in seen_ids or digest in seen_digests:
            raise BackendError(
                "duplicate_consensus_snapshot",
                "a snapshot may participate in a consensus baseline only once",
            )
        scan_metadata = snapshot.get("scan_metadata")
        if not isinstance(scan_metadata, dict):
            raise BackendError(
                "invalid_consensus_input",
                "snapshot scan_metadata must identify its saved Recon source",
            )
        scan_id = scan_metadata.get("scan_id")
        if not isinstance(scan_id, str) or not scan_id:
            raise BackendError(
                "invalid_consensus_input",
                "snapshot scan_id must be a non-empty saved Recon identifier",
            )
        if len(scan_id) > 128:
            raise BackendError(
                "invalid_consensus_input",
                "snapshot scan_id exceeds the safe length limit",
            )
        if scan_id in seen_source_ids:
            raise BackendError(
                "duplicate_consensus_snapshot",
                "one saved scan may participate in a consensus baseline only once",
            )
        seen_source_ids.add(scan_id)
        access_points = snapshot.get("access_points")
        if not isinstance(access_points, list) or not access_points:
            raise BackendError(
                "invalid_consensus_input",
                "consensus snapshots must contain at least one access point",
            )
        seen_ids.add(snapshot_id)
        seen_digests.add(digest)
        snapshots.append(snapshot)
    return sorted(
        snapshots,
        key=lambda item: (item["snapshot_id"], item["snapshot_digest"]),
    )


def _asset_model(
    asset_id: str,
    observations: List[Tuple[str, Dict[str, Any]]],
    total_scans: int,
) -> Dict[str, Any]:
    bssids = {observation.get("bssid") for _, observation in observations}
    if len(bssids) != 1:
        raise BackendError(
            "consensus_asset_conflict",
            "one asset_id resolves to multiple BSSIDs",
        )
    bssid = next(iter(bssids))
    if not isinstance(bssid, str) or not CANONICAL_BSSID.match(bssid):
        raise BackendError(
            "invalid_consensus_input",
            "consensus access points must contain canonical BSSIDs",
        )

    observed_count = len(observations)
    core_required_count = _strict_threshold(total_scans)
    if observed_count >= core_required_count:
        classification = "core"
    elif observed_count >= 2:
        classification = "recurring"
    else:
        classification = "singleton"

    attribute_values = {
        field: [observation.get(field) for _, observation in observations]
        for field in ATTRIBUTE_FIELDS
    }
    channels = [
        observation.get("channel")
        for _, observation in observations
        if isinstance(observation.get("channel"), int)
        and not isinstance(observation.get("channel"), bool)
    ]
    evidence_ids = sorted(
        {
            observation["evidence_id"]
            for _, observation in observations
            if isinstance(observation.get("evidence_id"), str)
        }
    )
    return {
        "asset_id": asset_id,
        "bssid": bssid,
        "presence": {
            "classification": classification,
            "observed_count": observed_count,
            "required_count": core_required_count,
            "total_scans": total_scans,
            "ratio": round(observed_count / float(total_scans), 4),
        },
        "source_snapshot_ids": sorted(
            snapshot_id for snapshot_id, _ in observations
        ),
        "evidence_ids": evidence_ids,
        "attributes": {
            field: _attribute_consensus(attribute_values[field])
            for field in ATTRIBUTE_FIELDS
        },
        "channels": {
            "observed_values": sorted(set(channels)),
            "values": _value_counts(channels),
        },
        "signal": _signal_summary(
            observation.get("signal") for _, observation in observations
        ),
    }


def build_consensus_baseline(
    snapshots: Any,
    consensus_policy_id: str = CONSENSUS_POLICY_ID,
    max_source_age_hours: Optional[int] = DEFAULT_MAX_SOURCE_AGE_HOURS,
) -> Dict[str, Any]:
    """Build an order-independent strict-80% consensus baseline."""
    if consensus_policy_id != CONSENSUS_POLICY_ID:
        raise BackendError(
            "unsupported_consensus_policy",
            "only strict_80_v1 is supported",
        )
    if max_source_age_hours is not None and (
        not isinstance(max_source_age_hours, int)
        or isinstance(max_source_age_hours, bool)
        or max_source_age_hours < MIN_MAX_SOURCE_AGE_HOURS
        or max_source_age_hours > MAX_MAX_SOURCE_AGE_HOURS
    ):
        raise BackendError(
            "invalid_max_source_age",
            "max_source_age_hours must be null or an integer from 1 to 168",
        )
    normalized = _validate_snapshots(snapshots)
    context = _common_context(normalized)
    window = _time_window(normalized, max_source_age_hours)

    grouped: Dict[str, List[Tuple[str, Dict[str, Any]]]] = {}
    asset_id_by_bssid: Dict[str, str] = {}
    for snapshot in normalized:
        seen_assets = set()
        seen_bssids = set()
        for access_point in snapshot["access_points"]:
            if not isinstance(access_point, dict):
                raise BackendError(
                    "invalid_consensus_input",
                    "snapshot access_points must contain objects",
                )
            asset_id = access_point.get("asset_id")
            if not isinstance(asset_id, str) or not ASSET_ID.match(asset_id):
                raise BackendError(
                    "invalid_consensus_input",
                    "snapshot access point asset_id is invalid",
                )
            if asset_id in seen_assets:
                raise BackendError(
                    "invalid_consensus_input",
                    "snapshot contains a duplicate asset_id",
                )
            bssid = access_point.get("bssid")
            if not isinstance(bssid, str) or not CANONICAL_BSSID.match(bssid):
                raise BackendError(
                    "invalid_consensus_input",
                    "snapshot access point BSSID is invalid",
                )
            if bssid in seen_bssids:
                raise BackendError(
                    "invalid_consensus_input",
                    "snapshot contains a duplicate BSSID",
                )
            previous_asset_id = asset_id_by_bssid.setdefault(
                bssid, asset_id
            )
            if previous_asset_id != asset_id:
                raise BackendError(
                    "consensus_identity_mismatch",
                    "one BSSID resolves to multiple asset IDs",
                )
            evidence_id = access_point.get("evidence_id")
            if (
                not isinstance(evidence_id, str)
                or not EVIDENCE_ID.match(evidence_id)
            ):
                raise BackendError(
                    "invalid_consensus_input",
                    "snapshot access point evidence_id is invalid",
                )
            seen_assets.add(asset_id)
            seen_bssids.add(bssid)
            grouped.setdefault(asset_id, []).append(
                (snapshot["snapshot_id"], access_point)
            )

    assets = [
        _asset_model(asset_id, grouped[asset_id], len(normalized))
        for asset_id in sorted(grouped)
    ]
    classification_counts = {
        name: sum(
            asset["presence"]["classification"] == name for asset in assets
        )
        for name in ("core", "recurring", "singleton")
    }
    source_snapshots = [
        {
            "snapshot_id": snapshot["snapshot_id"],
            "snapshot_digest": snapshot["snapshot_digest"],
            "observed_at": snapshot.get("observed_at"),
        }
        for snapshot in normalized
    ]
    model = {
        "schema_version": CONSENSUS_SCHEMA_VERSION,
        "model_type": "consensus_baseline",
        "consensus_policy": {
            "policy_id": CONSENSUS_POLICY_ID,
            "presence_threshold": 0.8,
            "required_count": _strict_threshold(len(normalized)),
        },
        "sample_count": len(normalized),
        "max_source_age_hours": max_source_age_hours,
        "limitation_codes": (
            [UNBOUNDED_SOURCE_AGE_LIMITATION]
            if max_source_age_hours is None
            else []
        ),
        "source_snapshots": source_snapshots,
        "measurement_context": context,
        "observation_window": window,
        "summary": {
            "asset_count": len(assets),
            "core_asset_count": classification_counts["core"],
            "recurring_asset_count": classification_counts["recurring"],
            "singleton_asset_count": classification_counts["singleton"],
        },
        "assets": assets,
    }
    digest = _digest(model)
    return dict(
        model,
        baseline_model_id="bmodel_{0}".format(digest[:16]),
        baseline_model_digest=digest,
    )


def consensus_capabilities() -> Dict[str, Any]:
    return {
        "schema_version": CONSENSUS_SCHEMA_VERSION,
        "policies": [
            {
                "policy_id": CONSENSUS_POLICY_ID,
                "presence_threshold": 0.8,
                "minimum_scans": MIN_CONSENSUS_SCANS,
                "maximum_scans": MAX_CONSENSUS_SCANS,
                "default_window_seconds": MAX_CONSENSUS_WINDOW_SECONDS,
                "default_max_source_age_hours": (
                    DEFAULT_MAX_SOURCE_AGE_HOURS
                ),
                "minimum_max_source_age_hours": MIN_MAX_SOURCE_AGE_HOURS,
                "maximum_max_source_age_hours": MAX_MAX_SOURCE_AGE_HOURS,
                "unbounded_source_age_supported": True,
                "unbounded_source_age_limitation_code": (
                    UNBOUNDED_SOURCE_AGE_LIMITATION
                ),
                "classifications": ["core", "recurring", "singleton"],
            }
        ],
    }
