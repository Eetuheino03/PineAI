"""Deterministic WiFi asset resolution, drift comparison, and findings.

This module is the authoritative analysis boundary for PineAI.  It deliberately
contains no provider calls and uses only the Python standard library.
"""

import hashlib
import hmac
import json
import re
import unicodedata
from typing import Any, Dict, Iterable, List, Optional, Set

from .errors import BackendError
from .recon import (
    ReconValidationError,
    contains_mac_address,
    validate_and_normalize_scan,
)


ASSURANCE_SCHEMA_VERSION = "1.2"
SUPPORTED_SCHEMA_VERSIONS = ("1.0", "1.1", "1.2")
QUALITY_MODEL_VERSION = "1.1"
MAX_METADATA_TEXT = 256
ALLOWED_COVERAGE = ("2.4", "5")
COMPARABILITY_STATES = ("comparable", "partially_comparable", "not_comparable")
FINDING_STATUSES = ("open", "acknowledged", "false_positive", "resolved")
ASSET_ID_PATTERN = re.compile(r"^ap_[0-9a-f]{12}$")
NETWORK_ID_PATTERN = re.compile(r"^network_[0-9a-f]{12}$")
EVIDENCE_ID_PATTERN = re.compile(r"^evidence_[0-9a-f]{12}$")
MAC_IN_TEXT_PATTERN = re.compile(r"(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}")
MEASUREMENT_PROFILE_ID_PATTERN = re.compile(
    r"^mprofile_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
MEASUREMENT_PROFILE_VERSION_ID_PATTERN = re.compile(
    r"^mprofile_r[0-9]{4}$"
)
MEASUREMENT_PROFILE_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")

RULE_REGISTRY = {
    "new_access_point": {
        "title": "New access point observed",
        "severity": "medium",
        "base_confidence": 0.95,
    },
    "known_ssid_new_bssid": {
        "title": "Known SSID advertised by a new BSSID",
        "severity": "high",
        "base_confidence": 0.92,
    },
    "access_point_missing": {
        "title": "Baseline access point was not observed",
        "severity": "medium",
        "base_confidence": 0.88,
    },
    "ssid_changed": {
        "title": "Access point SSID changed",
        "severity": "high",
        "base_confidence": 0.98,
    },
    "encryption_changed": {
        "title": "Access point encryption code changed",
        "severity": "high",
        "base_confidence": 0.98,
    },
    "wps_enabled": {
        "title": "WPS became enabled",
        "severity": "high",
        "base_confidence": 0.98,
    },
    "channel_changed": {
        "title": "Access point channel changed",
        "severity": "low",
        "base_confidence": 0.95,
    },
    "security_profile_divergence": {
        "title": "SSID now has divergent encryption codes",
        "severity": "high",
        "base_confidence": 0.93,
    },
}


def _clean_text(value: Any, maximum: int = MAX_METADATA_TEXT) -> str:
    if value is None:
        return ""
    text = "".join(
        character
        for character in str(value)
        if unicodedata.category(character)[0] != "C"
    ).strip()
    return text[:maximum]


def _stable_id(secret: bytes, namespace: str, value: str) -> str:
    if not isinstance(secret, bytes) or len(secret) < 16:
        raise BackendError(
            "invalid_secret", "pseudonymization key must contain at least 16 bytes"
        )
    digest = hmac.new(
        secret,
        "{0}:{1}".format(namespace, value).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return "{0}_{1}".format(namespace, digest[:12])


def canonical_digest(value: Any) -> str:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise BackendError("invalid_data", "value must be valid JSON")
    return hashlib.sha256(encoded).hexdigest()


def _integer(value: Any, field: str, minimum: int, maximum: int) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < minimum
        or value > maximum
    ):
        raise BackendError(
            "invalid_scan_metadata",
            "{0} must be between {1} and {2}".format(field, minimum, maximum),
        )
    return value


def normalize_measurement_context(value: Any) -> Dict[str, Any]:
    """Normalize absolute measurement context for a scan snapshot."""
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise BackendError("invalid_scan_metadata", "measurement_context must be an object")

    allowed = {
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
    if set(value) - allowed:
        raise BackendError(
            "invalid_scan_metadata", "measurement_context contains unsupported fields"
        )

    location_id = _clean_text(value.get("location_id"), 128) or None
    measurement_point_id = _clean_text(value.get("measurement_point_id"), 128) or None
    scan_profile_id = _clean_text(value.get("scan_profile_id"), 128) or None
    radio_profile_id = _clean_text(value.get("radio_profile_id"), 128) or None
    interface = _clean_text(value.get("interface"), 64) or None
    measurement_profile_id = (
        _clean_text(value.get("measurement_profile_id"), 64) or None
    )
    measurement_profile_version_id = (
        _clean_text(value.get("measurement_profile_version_id"), 32)
        or None
    )
    measurement_profile_digest = (
        _clean_text(value.get("measurement_profile_digest"), 64).lower()
        or None
    )
    legacy_revision = value.get("measurement_profile_revision")
    if legacy_revision is not None:
        if (
            not isinstance(legacy_revision, int)
            or isinstance(legacy_revision, bool)
            or legacy_revision < 1
            or legacy_revision > 9999
        ):
            raise BackendError(
                "invalid_scan_metadata",
                "measurement_profile_revision must be between 1 and 9999",
            )
        derived_version_id = "mprofile_r{0:04d}".format(legacy_revision)
        if (
            measurement_profile_version_id is not None
            and measurement_profile_version_id != derived_version_id
        ):
            raise BackendError(
                "invalid_scan_metadata",
                "measurement profile version fields conflict",
            )
        measurement_profile_version_id = derived_version_id
    for field, field_value, pattern in (
        (
            "measurement_profile_id",
            measurement_profile_id,
            MEASUREMENT_PROFILE_ID_PATTERN,
        ),
        (
            "measurement_profile_version_id",
            measurement_profile_version_id,
            MEASUREMENT_PROFILE_VERSION_ID_PATTERN,
        ),
        (
            "measurement_profile_digest",
            measurement_profile_digest,
            MEASUREMENT_PROFILE_DIGEST_PATTERN,
        ),
    ):
        if field_value is not None and not pattern.match(field_value):
            raise BackendError(
                "invalid_scan_metadata",
                "{0} is invalid".format(field),
            )

    declared_channels_input = value.get("declared_channels")
    declared_channels = None
    if declared_channels_input is not None:
        if not isinstance(declared_channels_input, list):
            raise BackendError("invalid_scan_metadata", "declared_channels must be an array")
        channels_set = set()
        for ch in declared_channels_input:
            if not isinstance(ch, int) or isinstance(ch, bool) or ch < 1 or ch > 200:
                raise BackendError("invalid_scan_metadata", "declared_channels contains an invalid channel number")
            channels_set.add(ch)
        declared_channels = sorted(channels_set)

    declared_bands_input = value.get("declared_bands")
    declared_bands = None
    if declared_bands_input is not None:
        if not isinstance(declared_bands_input, list) or len(declared_bands_input) > 2:
            raise BackendError("invalid_scan_metadata", "declared_bands must contain zero to two bands")
        bands_set = set()
        for band in declared_bands_input:
            if band not in ALLOWED_COVERAGE:
                raise BackendError("invalid_scan_metadata", "declared_bands contains an unknown band")
            bands_set.add(band)
        declared_bands = sorted(bands_set)

    result = {
        "location_id": location_id,
        "measurement_point_id": measurement_point_id,
        "scan_profile_id": scan_profile_id,
        "radio_profile_id": radio_profile_id,
        "interface": interface,
        "declared_channels": declared_channels,
        "declared_bands": declared_bands,
    }
    for field, field_value in (
        ("measurement_profile_id", measurement_profile_id),
        (
            "measurement_profile_version_id",
            measurement_profile_version_id,
        ),
        ("measurement_profile_digest", measurement_profile_digest),
    ):
        if field_value is not None:
            result[field] = field_value
    return result


def normalize_scan_metadata(value: Any) -> Dict[str, Any]:
    """Normalize safe metadata accepted from the Hak5 scan list response and user options."""
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise BackendError("invalid_scan_metadata", "scan_metadata must be an object")

    allowed = {
        "scan_id",
        "id",
        "date",
        "started_at",
        "completed_at",
        "scan_time",
        "duration",
        "coverage",
        "source",
        "label",
        "measurement_context",
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
    if set(value) - allowed:
        raise BackendError(
            "invalid_scan_metadata", "scan_metadata contains unsupported fields"
        )

    scan_id_value = value.get("scan_id", value.get("id"))
    duration_value = value.get("scan_time", value.get("duration"))

    context_fields = (
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
    )
    raw_mc = value.get("measurement_context")
    if raw_mc is None:
        direct_mc = {
            key: value[key] for key in context_fields if key in value
        }
        measurement_context = normalize_measurement_context(direct_mc)
    else:
        if any(key in value for key in context_fields):
            raise BackendError(
                "invalid_scan_metadata",
                "measurement context must use either the nested or direct form, not both",
            )
        measurement_context = normalize_measurement_context(raw_mc)

    result = {
        "scan_id": _clean_text(scan_id_value, 128) or None,
        "date": _clean_text(value.get("date"), 64) or None,
        "started_at": _clean_text(value.get("started_at"), 64) or None,
        "completed_at": _clean_text(value.get("completed_at"), 64) or None,
        "scan_time": None,
        "coverage": [],
        "source": _clean_text(value.get("source"), 64) or "hak5_recon",
        "label": _clean_text(value.get("label"), 128) or None,
        "measurement_context": measurement_context,
    }
    if duration_value is not None:
        result["scan_time"] = _integer(
            duration_value, "scan_time", minimum=1, maximum=86400
        )

    coverage = value.get("coverage", [])
    if not isinstance(coverage, list) or len(coverage) > 2:
        raise BackendError(
            "invalid_scan_metadata", "coverage must contain zero to two bands"
        )
    normalized_coverage = []
    for band in coverage:
        if band not in ALLOWED_COVERAGE:
            raise BackendError(
                "invalid_scan_metadata", "coverage contains an unknown band"
            )
        if band not in normalized_coverage:
            normalized_coverage.append(band)
    result["coverage"] = sorted(normalized_coverage)
    return result


def _channel_band(channel: int) -> Optional[str]:
    if 1 <= channel <= 14:
        return "2.4"
    if 30 <= channel <= 196:
        return "5"
    return None


def _unique_sorted(values: Iterable[Any]) -> List[Any]:
    return sorted(set(values))


def _canonical_json_sort_key(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _canonicalize_normalized_scan(value: Dict[str, Any]) -> Dict[str, Any]:
    """Remove source-array ordering from a normalized Recon observation."""
    access_points = []
    for source in value["access_points"]:
        access_point = dict(source)
        access_point["clients"] = sorted(
            (dict(client) for client in source.get("clients", [])),
            key=_canonical_json_sort_key,
        )
        access_points.append(access_point)
    access_points.sort(key=lambda item: item["bssid"])
    return {
        "access_points": access_points,
        "out_of_range_clients": sorted(
            (dict(client) for client in value["out_of_range_clients"]),
            key=_canonical_json_sort_key,
        ),
        "unassociated_clients": sorted(
            (dict(client) for client in value["unassociated_clients"]),
            key=_canonical_json_sort_key,
        ),
        "input_bytes": value["input_bytes"],
    }


def _median(numbers: List[int]) -> Optional[int]:
    if not numbers:
        return None
    sorted_nums = sorted(numbers)
    length = len(sorted_nums)
    mid = length // 2
    if length % 2 == 1:
        return sorted_nums[mid]
    return int(round((sorted_nums[mid - 1] + sorted_nums[mid]) / 2.0))


def _mad(numbers: List[int], median_val: Optional[int]) -> Optional[int]:
    if not numbers or median_val is None:
        return None
    deviations = [abs(num - median_val) for num in numbers]
    return _median(deviations)


def resolve_assets(
    scan: Any,
    scan_metadata: Any,
    pseudonymization_key: bytes,
    oui_database: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Resolve a Hak5 Recon response into a deterministic local snapshot."""
    try:
        normalized = validate_and_normalize_scan(scan, oui_database=oui_database)
    except ReconValidationError as failure:
        raise BackendError("invalid_recon", str(failure))
    normalized = _canonicalize_normalized_scan(normalized)
    metadata = normalize_scan_metadata(scan_metadata)

    identity_seed = {
        "metadata": metadata,
        "access_points": normalized["access_points"],
        "out_of_range_clients": normalized["out_of_range_clients"],
        "unassociated_clients": normalized["unassociated_clients"],
    }
    snapshot_digest = canonical_digest(identity_seed)
    snapshot_id = "snapshot_{0}".format(snapshot_digest[:16])
    access_points = []
    networks: Dict[str, Dict[str, Any]] = {}
    evidence = []
    observed_bands: Set[str] = set()

    valid_signals = []
    for access_point in sorted(
        normalized["access_points"], key=lambda item: item["bssid"]
    ):
        bssid = access_point["bssid"]
        asset_id = _stable_id(pseudonymization_key, "ap", bssid)
        network_key = (
            "hidden:{0}".format(bssid)
            if access_point["hidden"]
            else "ssid:{0}".format(access_point["ssid"])
        )
        network_id = _stable_id(pseudonymization_key, "network", network_key)
        evidence_id = _stable_id(
            pseudonymization_key,
            "evidence",
            "{0}:{1}".format(snapshot_digest, bssid),
        )
        band = _channel_band(access_point["channel"])
        if band:
            observed_bands.add(band)

        sig = access_point.get("signal")
        if isinstance(sig, int) and not isinstance(sig, bool) and sig < 0:
            valid_signals.append(sig)

        asset = {
            "asset_id": asset_id,
            "network_id": network_id,
            "evidence_id": evidence_id,
            "bssid": bssid,
            "ssid": access_point["ssid"],
            "hidden": bool(access_point["hidden"]),
            "encryption": access_point["encryption"],
            "wps": bool(access_point["wps"]),
            "channel": access_point["channel"],
            "band": band,
            "signal": access_point["signal"],
            "vendor": access_point["vendor"],
            "client_count": len(access_point["clients"]),
            "data": access_point["data"],
            "probes": access_point["probes"],
            "last_seen": access_point["last_seen"],
        }
        access_points.append(asset)
        evidence.append(
            {
                "evidence_id": evidence_id,
                "snapshot_id": snapshot_id,
                "evidence_type": "recon_access_point_observation",
                "subject_id": asset_id,
                "observed": {
                    "network_id": network_id,
                    "bssid": bssid,
                    "ssid": access_point["ssid"],
                    "hidden": bool(access_point["hidden"]),
                    "encryption": access_point["encryption"],
                    "wps": bool(access_point["wps"]),
                    "channel": access_point["channel"],
                    "signal": access_point["signal"],
                    "vendor": access_point["vendor"],
                    "client_count": len(access_point["clients"]),
                },
            }
        )

        network = networks.setdefault(
            network_id,
            {
                "network_id": network_id,
                "ssid": access_point["ssid"],
                "hidden": bool(access_point["hidden"]),
                "asset_ids": [],
                "bssids": [],
                "channels": [],
                "encryption_codes": [],
                "vendors": [],
                "client_count": 0,
            },
        )
        network["asset_ids"].append(asset_id)
        network["bssids"].append(bssid)
        network["channels"].append(access_point["channel"])
        network["encryption_codes"].append(access_point["encryption"])
        if access_point["vendor"]:
            network["vendors"].append(access_point["vendor"])
        network["client_count"] += len(access_point["clients"])

    network_list = []
    for network in networks.values():
        for key in (
            "asset_ids",
            "bssids",
            "channels",
            "encryption_codes",
            "vendors",
        ):
            network[key] = _unique_sorted(network[key])
        network_list.append(network)
    network_list.sort(key=lambda item: item["network_id"])
    evidence.sort(key=lambda item: item["evidence_id"])

    mc = metadata["measurement_context"]
    declared_coverage = metadata["coverage"] or (mc["declared_bands"] or [])
    effective_coverage = declared_coverage or sorted(observed_bands)
    observed_channels = sorted(set(ap["channel"] for ap in access_points))

    med_signal = _median(valid_signals)
    signal_summary = {
        "valid_observation_count": len(valid_signals),
        "median_dbm": med_signal,
        "minimum_dbm": min(valid_signals) if valid_signals else None,
        "maximum_dbm": max(valid_signals) if valid_signals else None,
        "median_absolute_deviation_db": _mad(valid_signals, med_signal),
    }

    return {
        "schema_version": ASSURANCE_SCHEMA_VERSION,
        "snapshot_id": snapshot_id,
        "snapshot_digest": snapshot_digest,
        "observed_at": (
            metadata["completed_at"]
            or metadata["date"]
            or metadata["started_at"]
        ),
        "scan_metadata": metadata,
        "comparability_profile": {
            "location_id": mc["location_id"],
            "measurement_point_id": mc["measurement_point_id"],
            "scan_profile_id": mc["scan_profile_id"],
            "radio_profile_id": mc["radio_profile_id"],
            "interface": mc["interface"],
            "measurement_profile_id": mc.get("measurement_profile_id"),
            "measurement_profile_version_id": mc.get(
                "measurement_profile_version_id"
            ),
            "measurement_profile_digest": mc.get(
                "measurement_profile_digest"
            ),
            "declared_coverage": declared_coverage,
            "observed_coverage": sorted(observed_bands),
            "effective_coverage": effective_coverage,
            "declared_channels_scanned": mc["declared_channels"],
            "observed_channels": observed_channels,
            "scan_time": metadata["scan_time"],
            "signal_summary": signal_summary,
        },
        "summary": {
            "access_point_count": len(access_points),
            "network_count": len(network_list),
            "associated_client_count": sum(
                item["client_count"] for item in access_points
            ),
            "out_of_range_client_count": len(normalized["out_of_range_clients"]),
            "unassociated_client_count": len(
                normalized["unassociated_clients"]
            ),
            "input_bytes": normalized["input_bytes"],
        },
        "access_points": access_points,
        "networks": network_list,
        "evidence": evidence,
    }


def _profile(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(snapshot, dict):
        raise BackendError("invalid_snapshot", "snapshot must be an object")
    profile = snapshot.get("comparability_profile")
    summary = snapshot.get("summary")
    if not isinstance(profile, dict) or not isinstance(summary, dict):
        raise BackendError("invalid_snapshot", "snapshot is incomplete")
    return profile


def _match_state(val1: Optional[str], val2: Optional[str]) -> Optional[bool]:
    if val1 is not None and val2 is not None:
        return val1 == val2
    return None


def evaluate_comparability(
    baseline: Dict[str, Any], current: Dict[str, Any]
) -> Dict[str, Any]:
    """Decide whether state transitions and absence findings are trustworthy."""
    baseline_profile = _profile(baseline)
    current_profile = _profile(current)
    reasons = []
    hard_gate_failed = False

    location_match = _match_state(baseline_profile.get("location_id"), current_profile.get("location_id"))
    measurement_point_match = _match_state(baseline_profile.get("measurement_point_id"), current_profile.get("measurement_point_id"))
    radio_profile_match = _match_state(baseline_profile.get("radio_profile_id"), current_profile.get("radio_profile_id"))
    scan_profile_match = _match_state(baseline_profile.get("scan_profile_id"), current_profile.get("scan_profile_id"))
    interface_match = _match_state(baseline_profile.get("interface"), current_profile.get("interface"))
    provenance_fields = (
        "measurement_profile_id",
        "measurement_profile_version_id",
        "measurement_profile_digest",
    )
    provenance_field_matches = {
        field: _match_state(
            baseline_profile.get(field), current_profile.get(field)
        )
        for field in provenance_fields
    }
    provenance_values = [
        baseline_profile.get(field)
        for field in provenance_fields
    ] + [
        current_profile.get(field)
        for field in provenance_fields
    ]
    provenance_present = any(
        value is not None for value in provenance_values
    )
    provenance_complete = all(
        value is not None for value in provenance_values
    )
    if not provenance_present:
        measurement_profile_provenance_match = None
        provenance_blocks_full_comparability = False
    elif not provenance_complete:
        measurement_profile_provenance_match = None
        provenance_blocks_full_comparability = True
        reasons.append("measurement_profile_provenance_incomplete")
    else:
        measurement_profile_provenance_match = all(
            value is True for value in provenance_field_matches.values()
        )
        provenance_blocks_full_comparability = (
            not measurement_profile_provenance_match
        )
        if provenance_blocks_full_comparability:
            reasons.append("measurement_profile_provenance_mismatch")
    for field, matches in provenance_field_matches.items():
        if matches is False:
            reasons.append("{0}_mismatch".format(field))

    if location_match is False:
        reasons.append("location_mismatch")
        hard_gate_failed = True

    if measurement_point_match is False:
        reasons.append("measurement_point_mismatch")
        hard_gate_failed = True

    if scan_profile_match is False:
        reasons.append("scan_profile_mismatch")
        hard_gate_failed = True
    elif scan_profile_match is None:
        reasons.append("scan_profile_unknown")

    if interface_match is False:
        reasons.append("interface_mismatch")
        hard_gate_failed = True
    elif interface_match is None:
        reasons.append("interface_unknown")

    if location_match is not True or measurement_point_match is not True:
        if baseline.get("schema_version") == "1.0" or current.get("schema_version") == "1.0":
            reasons.append("legacy_baseline_missing_measurement_context")
        else:
            reasons.append("measurement_context_unknown")

    baseline_count = baseline["summary"].get("access_point_count", 0)
    current_count = current["summary"].get("access_point_count", 0)
    if baseline_count > 0 and current_count == 0:
        reasons.append("current_scan_contains_no_access_points")
        hard_gate_failed = True

    baseline_coverage = set(baseline_profile.get("effective_coverage") or [])
    current_coverage = set(current_profile.get("effective_coverage") or [])
    if baseline_coverage and current_coverage:
        if not baseline_coverage.issubset(current_coverage):
            reasons.append("current_scan_does_not_cover_baseline_bands")
            hard_gate_failed = True

    current_declared_channels = current_profile.get("declared_channels_scanned")
    eligible_baseline_aps = []
    for ap in baseline.get("access_points", []):
        ap_band = ap.get("band") or _channel_band(ap.get("channel", 0))
        if ap_band and current_coverage and ap_band not in current_coverage:
            continue
        if current_declared_channels is not None:
            if ap.get("channel") not in current_declared_channels:
                continue
        eligible_baseline_aps.append(ap)

    eligible_ap_ids = set(ap["asset_id"] for ap in eligible_baseline_aps)
    current_ap_ids = set(ap["asset_id"] for ap in current.get("access_points", []))
    reobserved_eligible_aps = eligible_ap_ids & current_ap_ids

    eligible_baseline_ap_count = len(eligible_baseline_aps)
    reobserved_baseline_ap_count = len(reobserved_eligible_aps)

    if eligible_baseline_ap_count > 0:
        baseline_ap_detection_ratio = round(reobserved_baseline_ap_count / float(eligible_baseline_ap_count), 4)
    else:
        baseline_ap_detection_ratio = 1.0

    baseline_ap_channels = set(ap["channel"] for ap in baseline.get("access_points", []))
    if current_declared_channels is not None:
        if baseline_ap_channels:
            covered_count = len(baseline_ap_channels & set(current_declared_channels))
            channel_coverage_ratio = round(covered_count / float(len(baseline_ap_channels)), 4)
        else:
            channel_coverage_ratio = 1.0
    else:
        channel_coverage_ratio = None
        reasons.append("channel_coverage_unknown")

    baseline_time = baseline_profile.get("scan_time")
    current_time = current_profile.get("scan_time")
    if baseline_time is not None and current_time is not None:
        duration_score = round(min(1.0, current_time / float(max(1, baseline_time))), 4)
        if current_time < max(1, int(baseline_time * 0.75)):
            reasons.append("current_scan_is_materially_shorter")
    else:
        duration_score = None
        reasons.append("scan_duration_is_unknown")

    if radio_profile_match is False:
        radio_profile_score = 0.7
        reasons.append("radio_profile_mismatch")
    elif radio_profile_match is None:
        radio_profile_score = 0.85
        reasons.append("radio_profile_unknown")
    else:
        radio_profile_score = 1.0

    matched_deltas = []
    baseline_aps_by_id = {ap["asset_id"]: ap for ap in baseline.get("access_points", [])}
    for ap in current.get("access_points", []):
        b_ap = baseline_aps_by_id.get(ap["asset_id"])
        if b_ap and isinstance(ap.get("signal"), int) and isinstance(b_ap.get("signal"), int):
            if ap["signal"] < 0 and b_ap["signal"] < 0:
                matched_deltas.append(abs(b_ap["signal"] - ap["signal"]))

    matched_ap_signal_stability = {
        "matched_ap_count": len(matched_deltas),
        "median_absolute_delta_db": _median(matched_deltas),
    }
    if matched_ap_signal_stability["median_absolute_delta_db"] is not None and matched_ap_signal_stability["median_absolute_delta_db"] > 15:
        reasons.append("signal_profile_changed_materially")

    quality_factors = {
        "duration_score": duration_score,
        "channel_coverage_score": channel_coverage_ratio,
        "baseline_detection_score": baseline_ap_detection_ratio,
        "radio_profile_score": radio_profile_score,
    }

    eff_duration_score = duration_score if duration_score is not None else 0.5
    eff_channel_score = channel_coverage_ratio if channel_coverage_ratio is not None else 0.5
    eff_detection_score = baseline_ap_detection_ratio
    eff_radio_score = radio_profile_score

    if duration_score is not None or channel_coverage_ratio is not None:
        raw_score = (
            0.25 * eff_duration_score
            + 0.35 * eff_channel_score
            + 0.35 * eff_detection_score
            + 0.05 * eff_radio_score
        )
        comparison_quality_score = round(max(0.0, min(1.0, raw_score)), 2)
    else:
        comparison_quality_score = None

    if hard_gate_failed:
        status = "not_comparable"
    elif (
        location_match is not True
        or measurement_point_match is not True
        or scan_profile_match is not True
        or radio_profile_match is not True
        or interface_match is not True
        or provenance_blocks_full_comparability
        or comparison_quality_score is None
        or comparison_quality_score < 0.75
        or baseline_ap_detection_ratio < 0.50
        or channel_coverage_ratio is None
        or channel_coverage_ratio < 1.0
        or duration_score is None
        or duration_score < 0.75
    ):
        status = "partially_comparable"
        if comparison_quality_score is not None and comparison_quality_score < 0.75:
            reasons.append("low_comparison_quality_score")
        if baseline_ap_detection_ratio < 0.50:
            reasons.append("low_baseline_ap_detection_ratio")
    else:
        status = "comparable"

    absence_findings_allowed = (status == "comparable")
    positive_findings_allowed = (status != "not_comparable")
    lifecycle_updates_allowed = (status != "not_comparable")

    return {
        "status": status,
        "positive_findings_allowed": positive_findings_allowed,
        "absence_findings_allowed": absence_findings_allowed,
        "lifecycle_updates_allowed": lifecycle_updates_allowed,
        "comparison_quality_score": comparison_quality_score,
        "quality_model_version": QUALITY_MODEL_VERSION,
        "quality_factors": quality_factors,
        "location_match": location_match,
        "measurement_point_match": measurement_point_match,
        "scan_profile_match": scan_profile_match,
        "radio_profile_match": radio_profile_match,
        "interface_match": interface_match,
        "measurement_profile_id_match": provenance_field_matches[
            "measurement_profile_id"
        ],
        "measurement_profile_version_id_match": provenance_field_matches[
            "measurement_profile_version_id"
        ],
        "measurement_profile_digest_match": provenance_field_matches[
            "measurement_profile_digest"
        ],
        "measurement_profile_provenance_match": (
            measurement_profile_provenance_match
        ),
        "channel_coverage_ratio": channel_coverage_ratio,
        "eligible_baseline_ap_count": eligible_baseline_ap_count,
        "reobserved_baseline_ap_count": reobserved_baseline_ap_count,
        "baseline_ap_detection_ratio": baseline_ap_detection_ratio,
        "matched_ap_signal_stability": matched_ap_signal_stability,
        "reasons": sorted(set(reasons)),
        "baseline": {
            "coverage": sorted(baseline_coverage),
            "scan_time": baseline_time,
            "access_point_count": baseline_count,
            "measurement_profile": {
                field: baseline_profile.get(field)
                for field in provenance_fields
            },
        },
        "current": {
            "coverage": sorted(current_coverage),
            "scan_time": current_time,
            "access_point_count": current_count,
            "measurement_profile": {
                field: current_profile.get(field)
                for field in provenance_fields
            },
        },
    }


def compare_snapshots(
    baseline: Dict[str, Any], current: Dict[str, Any]
) -> Dict[str, Any]:
    """Return deterministic AP and SSID drift between two resolved snapshots."""
    comparability = evaluate_comparability(baseline, current)
    baseline_aps = {item["asset_id"]: item for item in baseline["access_points"]}
    current_aps = {item["asset_id"]: item for item in current["access_points"]}
    baseline_networks = {
        item["network_id"]: item for item in baseline["networks"]
    }
    current_networks = {item["network_id"]: item for item in current["networks"]}

    added = [
        current_aps[asset_id]
        for asset_id in sorted(set(current_aps) - set(baseline_aps))
    ]
    removed = [
        baseline_aps[asset_id]
        for asset_id in sorted(set(baseline_aps) - set(current_aps))
    ]
    changed = []
    fields = ("ssid", "hidden", "encryption", "wps", "channel", "vendor")
    for asset_id in sorted(set(baseline_aps) & set(current_aps)):
        before = baseline_aps[asset_id]
        after = current_aps[asset_id]
        field_changes = {
            field: {"before": before[field], "after": after[field]}
            for field in fields
            if before[field] != after[field]
        }
        if field_changes:
            changed.append(
                {
                    "asset_id": asset_id,
                    "network_id": after["network_id"],
                    "bssid": after["bssid"],
                    "evidence_id": after["evidence_id"],
                    "changes": field_changes,
                }
            )

    network_added = [
        current_networks[network_id]
        for network_id in sorted(set(current_networks) - set(baseline_networks))
    ]
    network_removed = [
        baseline_networks[network_id]
        for network_id in sorted(set(baseline_networks) - set(current_networks))
    ]
    network_changed = []
    for network_id in sorted(set(baseline_networks) & set(current_networks)):
        before = baseline_networks[network_id]
        after = current_networks[network_id]
        field_changes = {}
        for field in ("asset_ids", "channels", "encryption_codes", "vendors"):
            if before[field] != after[field]:
                field_changes[field] = {
                    "before": before[field],
                    "after": after[field],
                }
        if field_changes:
            network_changed.append(
                {
                    "network_id": network_id,
                    "ssid": after["ssid"],
                    "changes": field_changes,
                }
            )

    return {
        "schema_version": ASSURANCE_SCHEMA_VERSION,
        "baseline_snapshot_id": baseline["snapshot_id"],
        "current_snapshot_id": current["snapshot_id"],
        "comparability": comparability,
        "access_points": {
            "added": added,
            "removed": removed,
            "changed": changed,
        },
        "networks": {
            "added": network_added,
            "removed": network_removed,
            "changed": network_changed,
        },
        "summary": {
            "access_points_added": len(added),
            "access_points_removed": len(removed),
            "access_points_changed": len(changed),
            "networks_added": len(network_added),
            "networks_removed": len(network_removed),
            "networks_changed": len(network_changed),
        },
    }


def _finding(
    secret: bytes,
    assessment_id: str,
    rule_id: str,
    subject_id: str,
    evidence_ids: List[str],
    summary: str,
    details: Dict[str, Any],
    comparability_status: str,
) -> Dict[str, Any]:
    rule = RULE_REGISTRY[rule_id]
    penalty = 0.15 if comparability_status == "partially_comparable" else 0.0
    evidence_bonus = min(0.05, max(0, len(set(evidence_ids)) - 1) * 0.01)
    confidence = round(
        max(0.0, min(1.0, rule["base_confidence"] - penalty + evidence_bonus)),
        2,
    )
    finding_id = _stable_id(
        secret,
        "finding",
        "{0}:{1}:{2}".format(assessment_id, rule_id, subject_id),
    )
    return {
        "finding_id": finding_id,
        "rule_id": rule_id,
        "title": rule["title"],
        "severity": rule["severity"],
        "confidence": confidence,
        "subject_id": subject_id,
        "summary": _clean_text(summary, 500),
        "evidence_ids": sorted(set(evidence_ids)),
        "details": details,
        "confidence_factors": {
            "base": rule["base_confidence"],
            "comparability_penalty": penalty,
            "evidence_bonus": evidence_bonus,
        },
    }


def evaluate_finding_rules(
    assessment_id: str,
    baseline: Dict[str, Any],
    current: Dict[str, Any],
    diff: Dict[str, Any],
    pseudonymization_key: bytes,
) -> List[Dict[str, Any]]:
    """Evaluate finding rules deterministically."""
    comparability_status = diff["comparability"]["status"]
    if not diff["comparability"]["positive_findings_allowed"]:
        return []

    results = []
    baseline_networks = {
        item["network_id"]: item for item in baseline["networks"]
    }
    current_aps = {item["asset_id"]: item for item in current["access_points"]}

    for asset in diff["access_points"]["added"]:
        rule_id = (
            "known_ssid_new_bssid"
            if asset["network_id"] in baseline_networks
            else "new_access_point"
        )
        summary = (
            "A known baseline SSID is advertised by a new BSSID."
            if rule_id == "known_ssid_new_bssid"
            else "A BSSID not present in the active baseline was observed."
        )
        results.append(
            _finding(
                pseudonymization_key,
                assessment_id,
                rule_id,
                asset["asset_id"],
                [asset["evidence_id"]],
                summary,
                {
                    "asset_id": asset["asset_id"],
                    "network_id": asset["network_id"],
                    "bssid": asset["bssid"],
                    "ssid": asset["ssid"],
                },
                comparability_status,
            )
        )

    if diff["comparability"]["absence_findings_allowed"]:
        current_profile = _profile(current)
        current_declared_channels = current_profile.get("declared_channels_scanned")
        current_coverage = set(current_profile.get("effective_coverage") or [])

        eligible_baseline_aps = []
        for ap in baseline.get("access_points", []):
            ap_band = ap.get("band") or _channel_band(ap.get("channel", 0))
            if ap_band and current_coverage and ap_band not in current_coverage:
                continue
            if current_declared_channels is not None:
                if ap.get("channel") not in current_declared_channels:
                    continue
            eligible_baseline_aps.append(ap)

        total_eligible_count = len(eligible_baseline_aps)

        for asset in diff["access_points"]["removed"]:
            if current_declared_channels is not None and asset["channel"] not in current_declared_channels:
                continue

            other_eligible = [ap for ap in eligible_baseline_aps if ap["asset_id"] != asset["asset_id"]]
            total_other = len(other_eligible)
            reobserved_other = len([ap for ap in other_eligible if ap["asset_id"] in current_aps])
            anchor_detection_ratio = reobserved_other / float(total_other) if total_other > 0 else 1.0

            if total_eligible_count <= 1:
                continue
            elif total_eligible_count == 2:
                if anchor_detection_ratio < 1.0:
                    continue
            else:
                if anchor_detection_ratio < 0.75:
                    continue

            results.append(
                _finding(
                    pseudonymization_key,
                    assessment_id,
                    "access_point_missing",
                    asset["asset_id"],
                    [asset["evidence_id"]],
                    "A baseline BSSID was not observed in a comparable scan.",
                    {
                        "asset_id": asset["asset_id"],
                        "network_id": asset["network_id"],
                        "bssid": asset["bssid"],
                        "ssid": asset["ssid"],
                        "anchor_detection_ratio": round(anchor_detection_ratio, 2),
                    },
                    comparability_status,
                )
            )

    for change in diff["access_points"]["changed"]:
        after = current_aps[change["asset_id"]]
        evidence_ids = [change["evidence_id"]]
        change_rules = []
        if "ssid" in change["changes"]:
            change_rules.append(
                (
                    "ssid_changed",
                    "A known BSSID now advertises a different SSID.",
                )
            )
        if "encryption" in change["changes"]:
            change_rules.append(
                (
                    "encryption_changed",
                    "The opaque encryption code of a known BSSID changed.",
                )
            )
        if "wps" in change["changes"] and after["wps"]:
            change_rules.append(
                (
                    "wps_enabled",
                    "WPS is enabled although it was disabled in the baseline.",
                )
            )
        if "channel" in change["changes"]:
            change_rules.append(
                (
                    "channel_changed",
                    "A known BSSID moved to another channel.",
                )
            )
        for rule_id, summary in change_rules:
            results.append(
                _finding(
                    pseudonymization_key,
                    assessment_id,
                    rule_id,
                    change["asset_id"],
                    evidence_ids,
                    summary,
                    change,
                    comparability_status,
                )
            )

    baseline_network_map = {
        item["network_id"]: item for item in baseline["networks"]
    }
    for network in current["networks"]:
        before = baseline_network_map.get(network["network_id"])
        if (
            before
            and len(before["encryption_codes"]) <= 1
            and len(network["encryption_codes"]) > 1
        ):
            evidence_ids = [
                asset["evidence_id"]
                for asset in current["access_points"]
                if asset["network_id"] == network["network_id"]
            ]
            results.append(
                _finding(
                    pseudonymization_key,
                    assessment_id,
                    "security_profile_divergence",
                    network["network_id"],
                    evidence_ids,
                    "The same SSID now uses more than one opaque encryption code.",
                    {
                        "network_id": network["network_id"],
                        "ssid": network["ssid"],
                        "before": before["encryption_codes"],
                        "after": network["encryption_codes"],
                    },
                    comparability_status,
                )
            )

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(
        results,
        key=lambda item: (
            severity_order.get(item["severity"], 5),
            item["rule_id"],
            item["finding_id"],
        ),
    )


def build_ai_payload(
    assessment: Dict[str, Any],
    comparison: Dict[str, Any],
    findings: List[Dict[str, Any]],
    language: str,
    share_ssids: bool,
) -> Dict[str, Any]:
    """Return the exact privacy-filtered data allowed to reach an AI provider."""
    if language not in ("en", "fi"):
        raise BackendError("invalid_options", "language must be 'en' or 'fi'")
    if not isinstance(share_ssids, bool):
        raise BackendError("invalid_options", "share_ssids must be a boolean")
    if not isinstance(findings, list) or len(findings) > 100:
        raise BackendError(
            "invalid_request", "findings must contain at most 100 items"
        )

    safe_findings = []
    evidence_ids = set()
    for finding in findings:
        if not isinstance(finding, dict):
            raise BackendError("invalid_finding", "finding must be an object")
        details = finding.get("details") if isinstance(finding.get("details"), dict) else {}
        safe_details = {}
        for key in ("asset_id", "network_id", "before", "after"):
            if key in details:
                safe_details[key] = details[key]
        changes = details.get("changes")
        if isinstance(changes, dict):
            allowed_change_fields = {
                "hidden",
                "encryption",
                "wps",
                "channel",
                "vendor",
            }
            if share_ssids:
                allowed_change_fields.add("ssid")
            safe_details["changes"] = {
                key: changes[key]
                for key in sorted(changes)
                if key in allowed_change_fields
            }
        if share_ssids and isinstance(details.get("ssid"), str):
            safe_details["ssid"] = _clean_text(details["ssid"], 128)
        references = finding.get("evidence_ids", [])
        if not isinstance(references, list):
            raise BackendError("invalid_finding", "finding evidence_ids are invalid")
        evidence_ids.update(references)
        safe_findings.append(
            {
                "finding_id": finding.get("finding_id"),
                "rule_id": finding.get("rule_id"),
                "severity": finding.get("severity"),
                "confidence": finding.get("confidence"),
                "status": finding.get("status", "open"),
                "currently_observed": finding.get("currently_observed", True),
                "summary": _clean_text(finding.get("summary"), 500),
                "evidence_ids": sorted(set(references)),
                "details": safe_details,
            }
        )

    payload = {
        "schema_version": ASSURANCE_SCHEMA_VERSION,
        "task": "explain_deterministic_wireless_findings",
        "language": language,
        "assessment": {
            "assessment_id": assessment.get("assessment_id"),
        },
        "comparison": {
            "comparison_id": comparison.get("comparison_id"),
            "comparability": comparison.get("comparability"),
            "summary": comparison.get("summary"),
        },
        "findings": safe_findings,
        "allowed_evidence_ids": sorted(evidence_ids),
        "authority_notice": (
            "All finding facts, severity, confidence, lifecycle, and "
            "comparability values are authoritative and must not be changed."
        ),
    }
    serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    if MAC_IN_TEXT_PATTERN.search(serialized) or contains_mac_address(payload):
        raise BackendError(
            "privacy_violation", "AI payload contains a MAC address"
        )
    return payload


def assurance_capabilities() -> Dict[str, Any]:
    return {
        "schema_version": ASSURANCE_SCHEMA_VERSION,
        "product_mode": "baseline_and_drift",
        "offline_complete": True,
        "comparability_states": list(COMPARABILITY_STATES),
        "finding_statuses": list(FINDING_STATUSES),
        "rules": [
            {
                "rule_id": rule_id,
                "title": RULE_REGISTRY[rule_id]["title"],
                "severity": RULE_REGISTRY[rule_id]["severity"],
                "base_confidence": RULE_REGISTRY[rule_id]["base_confidence"],
            }
            for rule_id in RULE_REGISTRY
        ],
        "limits": {
            "access_points_per_scan": 1000,
            "baseline_versions_per_assessment": 50,
            "observations_per_assessment": 100,
            "findings_per_assessment": 500,
            "ai_findings_per_request": 100,
        },
        "authoritative_fields": [
            "comparability",
            "diff",
            "rule_id",
            "severity",
            "confidence",
            "confidence_factors",
            "evidence_ids",
            "finding_status",
        ],
    }
