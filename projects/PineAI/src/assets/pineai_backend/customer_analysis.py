"""Deterministic baseline, drift, policy, and occurrence composition."""

import hashlib
import hmac
import json
from typing import Any, Dict, List, Optional, Tuple

from .assurance import compare_snapshots
from .errors import BackendError


CUSTOMER_ANALYSIS_SCHEMA_VERSION = "1.2"
CERTAINTY_LEVELS = ("confirmed", "probable", "limited")


def _canonical_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _stable_id(secret: bytes, prefix: str, *parts: Any) -> str:
    if not isinstance(secret, bytes) or len(secret) < 16:
        raise BackendError(
            "invalid_secret", "identity key is invalid"
        )
    payload = json.dumps(
        parts, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    digest = hmac.new(
        secret, prefix.encode("ascii") + b":" + payload, hashlib.sha256
    ).hexdigest()
    length = 12 if prefix in ("change", "finding", "evidence") else 16
    return "{0}_{1}".format(prefix, digest[:length])


def _attribute_value(asset: Dict[str, Any], field: str) -> Any:
    attribute = asset.get("attributes", {}).get(field, {})
    if attribute.get("status") == "consensus":
        return attribute.get("value")
    values = attribute.get("values", [])
    if values and isinstance(values[0], dict):
        return values[0].get("value")
    return None


def _projection_networks(access_points: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for access_point in access_points:
        grouped.setdefault(access_point["network_id"], []).append(access_point)
    results = []
    for network_id in sorted(grouped):
        assets = grouped[network_id]
        results.append(
            {
                "network_id": network_id,
                "ssid": assets[0]["ssid"],
                "hidden": bool(assets[0]["hidden"]),
                "asset_ids": sorted(item["asset_id"] for item in assets),
                "bssids": sorted(item["bssid"] for item in assets),
                "channels": sorted(
                    {
                        item["channel"]
                        for item in assets
                        if isinstance(item.get("channel"), int)
                    }
                ),
                "encryption_codes": sorted(
                    {
                        item["encryption"]
                        for item in assets
                        if isinstance(item.get("encryption"), int)
                    }
                ),
                "vendors": sorted(
                    {
                        item["vendor"]
                        for item in assets
                        if isinstance(item.get("vendor"), str)
                    }
                ),
                "client_count": sum(
                    item.get("client_count", 0) for item in assets
                ),
            }
        )
    return results


def baseline_projection(
    baseline: Dict[str, Any],
) -> Tuple[Dict[str, Any], Dict[str, Dict[str, Any]]]:
    """Return an in-memory comparison projection and consensus membership."""
    if baseline.get("baseline_type") != "consensus":
        snapshot = baseline.get("snapshot")
        if not isinstance(snapshot, dict):
            raise BackendError(
                "invalid_baseline", "single-scan baseline snapshot is missing"
            )
        membership = {
            item["asset_id"]: {
                "classification": "core",
                "asset": None,
            }
            for item in snapshot["access_points"]
        }
        return snapshot, membership

    model = baseline.get("baseline_model")
    if not isinstance(model, dict) or not isinstance(model.get("assets"), list):
        raise BackendError(
            "invalid_baseline", "consensus baseline model is missing"
        )
    digest = model.get("baseline_model_digest")
    if not isinstance(digest, str) or len(digest) != 64:
        raise BackendError(
            "invalid_baseline", "consensus baseline digest is invalid"
        )
    access_points = []
    membership = {}
    for asset in sorted(model["assets"], key=lambda item: item["asset_id"]):
        asset_id = asset["asset_id"]
        classification = asset["presence"]["classification"]
        membership[asset_id] = {
            "classification": classification,
            "asset": asset,
        }
        network_id = _attribute_value(asset, "network_id")
        if not isinstance(network_id, str) or not network_id:
            network_id = "network_{0}".format(asset_id.split("_", 1)[-1])
        evidence_ids = asset.get("evidence_ids", [])
        evidence_id = (
            evidence_ids[0]
            if evidence_ids
            else "evidence_{0}".format(asset_id.split("_", 1)[-1])
        )
        channels = asset.get("channels", {}).get("observed_values", [])
        channel = channels[0] if channels else None
        access_points.append(
            {
                "asset_id": asset_id,
                "network_id": network_id,
                "evidence_id": evidence_id,
                "bssid": asset.get("bssid"),
                "ssid": _attribute_value(asset, "ssid") or "",
                "hidden": bool(_attribute_value(asset, "hidden")),
                "encryption": _attribute_value(asset, "encryption"),
                "wps": bool(_attribute_value(asset, "wps")),
                "channel": channel,
                "band": _attribute_value(asset, "band"),
                "signal": asset.get("signal", {}).get("median_dbm"),
                "vendor": _attribute_value(asset, "vendor") or "Unknown",
                "client_count": 0,
                "data": 0,
                "probes": 0,
                "last_seen": 0,
            }
        )
    context = model.get("measurement_context", {})
    coverage = context.get("declared_coverage") or []
    profile = {
        "declared_coverage": coverage,
        "observed_coverage": coverage,
        "effective_coverage": coverage,
        "scan_time": context.get("scan_time_median"),
        "location_id": context.get("location_id"),
        "measurement_point_id": context.get("measurement_point_id"),
        "scan_profile_id": context.get("scan_profile_id"),
        "radio_profile_id": context.get("radio_profile_id"),
        "interface": context.get("interface"),
        "measurement_profile_id": context.get("measurement_profile_id"),
        "measurement_profile_version_id": context.get(
            "measurement_profile_version_id"
        ),
        "measurement_profile_digest": context.get(
            "measurement_profile_digest"
        ),
        "declared_channels_scanned": context.get(
            "declared_channels_scanned"
        ),
    }
    networks = _projection_networks(access_points)
    snapshot_id = "snapshot_{0}".format(digest[:16])
    projection = {
        "schema_version": CUSTOMER_ANALYSIS_SCHEMA_VERSION,
        "snapshot_id": snapshot_id,
        "snapshot_digest": digest,
        "observed_at": model.get("observation_window", {}).get("ended_at"),
        "scan_metadata": {
            "scan_id": None,
            "date": model.get("observation_window", {}).get("ended_at"),
            "started_at": model.get("observation_window", {}).get(
                "started_at"
            ),
            "completed_at": model.get("observation_window", {}).get(
                "ended_at"
            ),
            "scan_time": context.get("scan_time_median"),
            "coverage": coverage,
            "source": "pineai_consensus_baseline",
            "label": baseline.get("label", ""),
            "measurement_context": {
                "location_id": context.get("location_id"),
                "measurement_point_id": context.get(
                    "measurement_point_id"
                ),
                "scan_profile_id": context.get("scan_profile_id"),
                "radio_profile_id": context.get("radio_profile_id"),
                "interface": context.get("interface"),
                "declared_channels": context.get(
                    "declared_channels_scanned"
                ),
                "declared_bands": coverage,
            },
        },
        "comparability_profile": profile,
        "summary": {
            "access_point_count": len(access_points),
            "network_count": len(networks),
            "associated_client_count": 0,
            "out_of_range_client_count": 0,
            "unassociated_client_count": 0,
            "input_bytes": 0,
        },
        "access_points": access_points,
        "networks": networks,
        "evidence": [],
    }
    return projection, membership


def _certainty(comparability: str, absence: bool = False) -> str:
    if comparability == "not_comparable":
        return "limited"
    if absence or comparability == "partially_comparable":
        return "probable"
    return "confirmed"


def _before_after(before: Any, after: Any) -> Dict[str, Any]:
    return {"before": before, "after": after}


def _observed_change(
    secret: bytes,
    assessment_id: str,
    change_type: str,
    subject_id: str,
    certainty: str,
    evidence_ids: List[str],
    before: Any,
    after: Any,
) -> Dict[str, Any]:
    return {
        "change_id": _stable_id(
            secret,
            "change",
            assessment_id,
            change_type,
            subject_id,
        ),
        "change_type": change_type,
        "subject_id": subject_id,
        "certainty": certainty,
        "evidence_ids": sorted(set(evidence_ids)),
        "before_after": _before_after(before, after),
    }


def compare_customer_baseline(
    assessment_id: str,
    baseline: Dict[str, Any],
    current: Dict[str, Any],
    secret: bytes,
) -> Dict[str, Any]:
    """Compare current observation to single-scan or consensus baseline."""
    reference, membership = baseline_projection(baseline)
    diff = compare_snapshots(reference, current)
    comparability = diff["comparability"]
    status = comparability["status"]
    # The legacy comparator calculates useful internal numeric heuristics, but
    # v0.6.2 has not been field-calibrated and must not present them as customer
    # confidence percentages. Preserve auditable raw facts and categorical
    # match results instead.
    comparability["quality_factors"] = {
        "duration": {
            "baseline_seconds": comparability["baseline"].get("scan_time"),
            "current_seconds": comparability["current"].get("scan_time"),
        },
        "coverage": {
            "baseline_bands": comparability["baseline"].get("coverage", []),
            "current_bands": comparability["current"].get("coverage", []),
        },
        "baseline_detection": {
            "eligible_access_points": comparability.get(
                "eligible_baseline_ap_count", 0
            ),
            "reobserved_access_points": comparability.get(
                "reobserved_baseline_ap_count", 0
            ),
        },
        "profile_consistency": {
            "location_match": comparability.get("location_match"),
            "measurement_point_match": comparability.get(
                "measurement_point_match"
            ),
            "scan_profile_match": comparability.get("scan_profile_match"),
            "radio_profile_match": comparability.get(
                "radio_profile_match"
            ),
            "interface_match": comparability.get("interface_match"),
            "measurement_profile_provenance_match": comparability.get(
                "measurement_profile_provenance_match"
            ),
        },
    }
    for uncalibrated_field in (
        "comparison_quality_score",
        "channel_coverage_ratio",
        "baseline_ap_detection_ratio",
    ):
        comparability.pop(uncalibrated_field, None)
    baseline_by_id = {
        item["asset_id"]: item for item in reference["access_points"]
    }
    current_by_id = {
        item["asset_id"]: item for item in current["access_points"]
    }

    if baseline.get("baseline_type") == "consensus":
        removed = [
            item
            for item in diff["access_points"]["removed"]
            if membership[item["asset_id"]]["classification"] == "core"
        ]
        diff["access_points"]["removed"] = removed
        changed = []
        for asset_id in sorted(set(baseline_by_id) & set(current_by_id)):
            model_asset = membership[asset_id]["asset"]
            current_ap = current_by_id[asset_id]
            changes = {}
            for field in (
                "ssid",
                "hidden",
                "encryption",
                "wps",
                "vendor",
            ):
                attribute = model_asset["attributes"][field]
                if (
                    attribute.get("status") == "consensus"
                    and attribute.get("value") != current_ap.get(field)
                ):
                    changes[field] = {
                        "before": attribute.get("value"),
                        "after": current_ap.get(field),
                    }
            normal_channels = model_asset.get("channels", {}).get(
                "observed_values", []
            )
            if (
                isinstance(current_ap.get("channel"), int)
                and current_ap["channel"] not in normal_channels
            ):
                changes["channel"] = {
                    "before": normal_channels,
                    "after": current_ap["channel"],
                }
            if changes:
                changed.append(
                    {
                        "asset_id": asset_id,
                        "network_id": current_ap["network_id"],
                        "bssid": current_ap["bssid"],
                        "evidence_id": current_ap["evidence_id"],
                        "changes": changes,
                    }
                )
        diff["access_points"]["changed"] = changed
        diff["summary"]["access_points_removed"] = len(removed)
        diff["summary"]["access_points_changed"] = len(changed)

    changes = []
    baseline_ssids = {
        item.get("ssid")
        for item in reference["access_points"]
        if item.get("ssid")
    }
    for item in diff["access_points"]["added"]:
        change_type = (
            "known_ssid_new_bssid"
            if item.get("ssid") in baseline_ssids
            else "new_access_point"
        )
        changes.append(
            _observed_change(
                secret,
                assessment_id,
                change_type,
                item["asset_id"],
                _certainty(status),
                [item["evidence_id"]],
                None,
                item,
            )
        )
    for item in diff["access_points"]["removed"]:
        baseline_item = baseline_by_id[item["asset_id"]]
        changes.append(
            _observed_change(
                secret,
                assessment_id,
                "access_point_missing",
                item["asset_id"],
                _certainty(status, absence=True),
                [item["evidence_id"]],
                baseline_item,
                None,
            )
        )
    for item in diff["access_points"]["changed"]:
        changes.append(
            _observed_change(
                secret,
                assessment_id,
                "access_point_attributes_changed",
                item["asset_id"],
                _certainty(status),
                [item["evidence_id"]],
                {
                    key: value.get("before")
                    for key, value in item["changes"].items()
                },
                {
                    key: value.get("after")
                    for key, value in item["changes"].items()
                },
            )
        )
    return {
        "schema_version": CUSTOMER_ANALYSIS_SCHEMA_VERSION,
        "baseline_projection": reference,
        "membership": membership,
        "diff": diff,
        "observed_changes": sorted(
            changes, key=lambda item: item["change_id"]
        ),
    }


def lifecycle_findings(
    assessment_id: str,
    policy_deviations: List[Dict[str, Any]],
    security_findings: List[Dict[str, Any]],
    secret: bytes,
) -> List[Dict[str, Any]]:
    """Adapt authoritative lifecycle issues to the legacy mutable store core."""
    results = []
    certainty_values = {"confirmed": 1.0, "probable": 0.75, "limited": 0.4}
    for result_type, items in (
        ("policy_deviation", policy_deviations),
        ("security_finding", security_findings),
    ):
        for item in items:
            certainty = item.get("certainty")
            if certainty == "limited":
                continue
            subject_id = item.get("subject_id")
            rule_id = item.get("rule_id")
            finding_id = _stable_id(
                secret,
                "finding",
                assessment_id,
                result_type,
                rule_id,
                subject_id,
            )
            summary = item.get("title") or rule_id
            results.append(
                {
                    "finding_id": finding_id,
                    "rule_id": "{0}:{1}".format(result_type, rule_id),
                    "title": item.get("title") or rule_id,
                    "severity": item.get("severity", "info"),
                    "confidence": certainty_values.get(certainty, 0.4),
                    "subject_id": subject_id,
                    "summary": str(summary)[:1000],
                    "evidence_ids": sorted(
                        set(item.get("evidence_ids", []))
                    ),
                    "details": {
                        "result_type": result_type,
                        "certainty": certainty,
                        "source_result_id": item.get("deviation_id")
                        or item.get("finding_id"),
                        "expected": item.get("expected"),
                        "observed": item.get("observed"),
                        "before_after": item.get("before_after"),
                    },
                    "confidence_factors": {
                        "presentation": "categorical_only",
                        "certainty": certainty,
                    },
                }
            )
    return sorted(results, key=lambda item: item["finding_id"])


def evidence_records(
    baseline: Dict[str, Any],
    current: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Return unique local evidence records for an immutable occurrence."""
    records = []
    seen = set()
    if baseline.get("snapshot"):
        sources = [baseline["snapshot"], current]
    else:
        sources = [current]
    for source in sources:
        for item in source.get("evidence", []):
            evidence_id = item.get("evidence_id")
            if evidence_id in seen:
                continue
            seen.add(evidence_id)
            records.append(item)
    model = baseline.get("baseline_model")
    if isinstance(model, dict):
        for asset in model.get("assets", []):
            for evidence_id in asset.get("evidence_ids", []):
                if evidence_id in seen:
                    continue
                seen.add(evidence_id)
                records.append(
                    {
                        "evidence_id": evidence_id,
                        "evidence_type": "consensus_observation_summary",
                        "subject_id": asset.get("asset_id"),
                        "observed": {
                            "presence": asset.get("presence"),
                            "attributes": asset.get("attributes"),
                            "channels": asset.get("channels"),
                            "signal": asset.get("signal"),
                        },
                    }
                )
    return sorted(records, key=lambda item: item["evidence_id"])
