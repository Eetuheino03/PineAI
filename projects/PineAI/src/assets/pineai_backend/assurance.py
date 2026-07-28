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


ASSURANCE_SCHEMA_VERSION = "1.0"
MAX_METADATA_TEXT = 256
ALLOWED_COVERAGE = ("2.4", "5")
COMPARABILITY_STATES = ("comparable", "partially_comparable", "not_comparable")
FINDING_STATUSES = ("open", "acknowledged", "false_positive", "resolved")
ASSET_ID_PATTERN = re.compile(r"^ap_[0-9a-f]{12}$")
NETWORK_ID_PATTERN = re.compile(r"^network_[0-9a-f]{12}$")
EVIDENCE_ID_PATTERN = re.compile(r"^evidence_[0-9a-f]{12}$")
MAC_IN_TEXT_PATTERN = re.compile(r"(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}")

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


def normalize_scan_metadata(value: Any) -> Dict[str, Any]:
    """Normalize safe metadata accepted from the Hak5 scan list response."""
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
    }
    if set(value) - allowed:
        raise BackendError(
            "invalid_scan_metadata", "scan_metadata contains unsupported fields"
        )

    scan_id_value = value.get("scan_id", value.get("id"))
    duration_value = value.get("scan_time", value.get("duration"))
    result = {
        "scan_id": _clean_text(scan_id_value, 128) or None,
        "date": _clean_text(value.get("date"), 64) or None,
        "started_at": _clean_text(value.get("started_at"), 64) or None,
        "completed_at": _clean_text(value.get("completed_at"), 64) or None,
        "scan_time": None,
        "coverage": [],
        "source": _clean_text(value.get("source"), 64) or "hak5_recon",
        "label": _clean_text(value.get("label"), 128) or None,
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
    metadata = normalize_scan_metadata(scan_metadata)

    # input_bytes depends on JSON formatting and is therefore diagnostic rather
    # than part of the identity of a semantic snapshot.
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

    effective_coverage = metadata["coverage"] or sorted(observed_bands)
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
            "declared_coverage": metadata["coverage"],
            "observed_coverage": sorted(observed_bands),
            "effective_coverage": effective_coverage,
            "scan_time": metadata["scan_time"],
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


def evaluate_comparability(
    baseline: Dict[str, Any], current: Dict[str, Any]
) -> Dict[str, Any]:
    """Decide whether state transitions and absence findings are trustworthy."""
    baseline_profile = _profile(baseline)
    current_profile = _profile(current)
    reasons = []
    status = "comparable"
    baseline_coverage = set(baseline_profile.get("effective_coverage") or [])
    current_coverage = set(current_profile.get("effective_coverage") or [])
    baseline_count = baseline["summary"].get("access_point_count", 0)
    current_count = current["summary"].get("access_point_count", 0)

    if baseline_count and not current_count:
        status = "not_comparable"
        reasons.append("current_scan_contains_no_access_points")
    if baseline_coverage and current_coverage:
        if not baseline_coverage.issubset(current_coverage):
            status = "not_comparable"
            reasons.append("current_scan_does_not_cover_baseline_bands")
    elif status != "not_comparable":
        status = "partially_comparable"
        reasons.append("band_coverage_is_incomplete")

    baseline_time = baseline_profile.get("scan_time")
    current_time = current_profile.get("scan_time")
    if baseline_time is None or current_time is None:
        if status == "comparable":
            status = "partially_comparable"
        reasons.append("scan_duration_is_unknown")
    elif current_time < max(1, int(baseline_time * 0.75)):
        if status == "comparable":
            status = "partially_comparable"
        reasons.append("current_scan_is_materially_shorter")

    return {
        "status": status,
        "positive_findings_allowed": status != "not_comparable",
        "absence_findings_allowed": status == "comparable",
        "lifecycle_updates_allowed": status != "not_comparable",
        "reasons": sorted(set(reasons)),
        "baseline": {
            "coverage": sorted(baseline_coverage),
            "scan_time": baseline_time,
            "access_point_count": baseline_count,
        },
        "current": {
            "coverage": sorted(current_coverage),
            "scan_time": current_time,
            "access_point_count": current_count,
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
    """Evaluate the first eight rules without making probabilistic decisions."""
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
        for asset in diff["access_points"]["removed"]:
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
