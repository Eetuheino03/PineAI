"""Deterministic normalization and target profiling for Hak5 Recon data."""

import hashlib
import hmac
import json
import math
import re
import unicodedata
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional, Tuple


MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_ACCESS_POINTS = 1000
MAX_CLIENTS = 10000
MAX_TEXT_LENGTH = 128
MAC_PATTERN = re.compile(r"^[0-9A-F]{12}$")
MAC_IN_TEXT_PATTERN = re.compile(r"(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}")


class ReconValidationError(ValueError):
    """Raised when a Recon result cannot be safely normalized."""


def _sanitize_text(value: Any, maximum: int = MAX_TEXT_LENGTH) -> str:
    if value is None:
        return ""
    text = str(value)
    text = "".join(
        character
        for character in text
        if unicodedata.category(character)[0] != "C"
    )
    return text[:maximum]


def _as_int(value: Any, field: str, default: int = 0) -> int:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return int(value)
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ReconValidationError("{0} must be an integer".format(field))
    return number


def _canonical_mac(value: Any) -> str:
    text = _sanitize_text(value, 32).upper()
    compact = re.sub(r"[^0-9A-F]", "", text)
    if not MAC_PATTERN.match(compact):
        return text
    return ":".join(compact[index : index + 2] for index in range(0, 12, 2))


def _pseudonym(secret: bytes, namespace: str, value: str, length: int = 12) -> str:
    digest = hmac.new(
        secret,
        "{0}:{1}".format(namespace, value).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return "{0}_{1}".format(namespace, digest[:length])


def _redact_mac_addresses(value: Any, maximum: int = 256) -> str:
    return MAC_IN_TEXT_PATTERN.sub(
        "[redacted_mac]", _sanitize_text(value, maximum)
    )


def _find_client_list(scan: Dict[str, Any], primary: str, alias: str) -> List[Any]:
    value = scan.get(primary)
    if value is None:
        value = scan.get(alias, [])
    if not isinstance(value, list):
        raise ReconValidationError("{0} must be an array".format(primary))
    return value


def _load_oui_database(path: str = "/etc/pineapple/ouis") -> Dict[str, str]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except (OSError, ValueError):
        return {}
    if not isinstance(raw, dict):
        return {}
    return {
        str(key).replace(":", "").replace("-", "").upper()[:6]: _sanitize_text(value)
        for key, value in raw.items()
    }


def _vendor_for_mac(mac: str, oui_database: Dict[str, str]) -> str:
    prefix = mac.replace(":", "").replace("-", "").upper()[:6]
    return oui_database.get(prefix, "Unknown")


def _normalize_client(client: Any, index: int) -> Dict[str, Any]:
    if not isinstance(client, dict):
        raise ReconValidationError("client at index {0} must be an object".format(index))
    return {
        "client_mac": _canonical_mac(client.get("client_mac", "")),
        "ap_mac": _canonical_mac(client.get("ap_mac", "")),
        "ap_channel": _as_int(client.get("ap_channel"), "ap_channel"),
        "data": _as_int(client.get("data"), "client.data"),
        "broadcast_probes": _as_int(
            client.get("broadcast_probes"), "broadcast_probes"
        ),
        "direct_probes": _as_int(client.get("direct_probes"), "direct_probes"),
        "last_seen": _sanitize_text(client.get("last_seen", ""), 64),
    }


def _normalize_ap(
    access_point: Any,
    index: int,
    oui_database: Dict[str, str],
) -> Dict[str, Any]:
    if not isinstance(access_point, dict):
        raise ReconValidationError("AP at index {0} must be an object".format(index))

    clients = access_point.get("clients", [])
    if clients is None:
        clients = []
    if not isinstance(clients, list):
        raise ReconValidationError("AP clients at index {0} must be an array".format(index))

    bssid = _canonical_mac(access_point.get("bssid", ""))
    ssid = _sanitize_text(access_point.get("ssid", ""))
    normalized_clients = [
        _normalize_client(client, client_index)
        for client_index, client in enumerate(clients)
    ]
    return {
        "ssid": ssid,
        "bssid": bssid,
        "encryption": _as_int(access_point.get("encryption"), "encryption"),
        "hidden": _as_int(access_point.get("hidden"), "hidden"),
        "wps": _as_int(access_point.get("wps"), "wps"),
        "channel": _as_int(access_point.get("channel"), "channel"),
        "signal": _as_int(access_point.get("signal"), "signal"),
        "data": _as_int(access_point.get("data"), "data"),
        "last_seen": _sanitize_text(access_point.get("last_seen", ""), 64),
        "probes": _as_int(access_point.get("probes"), "probes"),
        "clients": normalized_clients,
        "vendor": _vendor_for_mac(bssid, oui_database),
    }


def validate_and_normalize_scan(
    scan: Any,
    oui_database: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Validate documented Recon shapes and return a canonical representation."""
    if not isinstance(scan, dict):
        raise ReconValidationError("scan must be a JSON object")
    try:
        encoded_size = len(
            json.dumps(scan, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        )
    except (TypeError, ValueError) as error:
        raise ReconValidationError("scan must be JSON serializable: {0}".format(error))
    if encoded_size > MAX_INPUT_BYTES:
        raise ReconValidationError("scan exceeds the 8 MiB input limit")

    access_points = scan.get("APResults")
    if not isinstance(access_points, list):
        raise ReconValidationError("scan.APResults must be an array")
    if len(access_points) > MAX_ACCESS_POINTS:
        raise ReconValidationError("scan contains more than 1000 access points")

    out_of_range = _find_client_list(
        scan, "OutOfRangeClientResults", "OutOfRangeResult"
    )
    unassociated = _find_client_list(
        scan, "UnassociatedClientResults", "UnassociatedResult"
    )
    database = oui_database if oui_database is not None else _load_oui_database()
    normalized_aps = [
        _normalize_ap(access_point, index, database)
        for index, access_point in enumerate(access_points)
    ]
    normalized_out_of_range = [
        _normalize_client(client, index) for index, client in enumerate(out_of_range)
    ]
    normalized_unassociated = [
        _normalize_client(client, index) for index, client in enumerate(unassociated)
    ]
    total_clients = (
        sum(len(access_point["clients"]) for access_point in normalized_aps)
        + len(normalized_out_of_range)
        + len(normalized_unassociated)
    )
    if total_clients > MAX_CLIENTS:
        raise ReconValidationError("scan contains more than 10000 client records")

    return {
        "access_points": normalized_aps,
        "out_of_range_clients": normalized_out_of_range,
        "unassociated_clients": normalized_unassociated,
        "input_bytes": encoded_size,
    }


def _mean(values: Iterable[int]) -> float:
    items = list(values)
    if not items:
        return 0.0
    return round(sum(items) / float(len(items)), 2)


def _counter_items(values: Iterable[Any]) -> List[Dict[str, Any]]:
    counter = Counter(values)
    return [
        {"value": value, "count": counter[value]}
        for value in sorted(counter, key=lambda item: str(item))
    ]


def _target_flags(access_points: List[Dict[str, Any]]) -> List[str]:
    flags = []
    if len(access_points) > 1:
        flags.append("multi_ap")
    if any(access_point["hidden"] for access_point in access_points):
        flags.append("hidden_network")
    if any(access_point["wps"] for access_point in access_points):
        flags.append("wps_present")
    if len({access_point["encryption"] for access_point in access_points}) > 1:
        flags.append("mixed_encryption")
    if sum(len(access_point["clients"]) for access_point in access_points) > 0:
        flags.append("active_clients")
    return flags


def _target_rank(target: Dict[str, Any]) -> Tuple[int, str]:
    metrics = target["metrics"]
    score = (
        len(target["flags"]) * 1000000
        + metrics["client_count"] * 10000
        + metrics["probes_total"] * 10
        + metrics["data_total"]
    )
    return (-score, target["target_id"])


def build_deterministic_profiles(
    normalized_scan: Dict[str, Any],
    pseudonymization_key: bytes,
    max_ai_targets: int = 50,
) -> Dict[str, Any]:
    """Group normalized APs and calculate evidence-backed target profiles."""
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for access_point in normalized_scan["access_points"]:
        if access_point["hidden"]:
            group_key = "hidden:{0}".format(access_point["bssid"])
        else:
            group_key = "ssid:{0}".format(access_point["ssid"])
        groups.setdefault(group_key, []).append(access_point)

    targets = []
    for group_key in sorted(groups):
        access_points = sorted(groups[group_key], key=lambda item: item["bssid"])
        ssid = access_points[0]["ssid"]
        hidden = bool(access_points[0]["hidden"])
        target_id = _pseudonym(pseudonymization_key, "target", group_key)
        evidence = []
        for access_point in access_points:
            evidence_id = _pseudonym(
                pseudonymization_key,
                "evidence",
                "{0}:{1}".format(group_key, access_point["bssid"]),
            )
            evidence.append(
                {
                    "evidence_id": evidence_id,
                    "type": "access_point",
                    "bssid": access_point["bssid"],
                    "channel": access_point["channel"],
                    "signal": access_point["signal"],
                }
            )

        signals = [access_point["signal"] for access_point in access_points]
        targets.append(
            {
                "target_id": target_id,
                "ssid": ssid,
                "hidden": hidden,
                "bssids": [access_point["bssid"] for access_point in access_points],
                "vendors": _counter_items(
                    access_point["vendor"] for access_point in access_points
                ),
                "channels": sorted(
                    {access_point["channel"] for access_point in access_points}
                ),
                "encryption_codes": sorted(
                    {access_point["encryption"] for access_point in access_points}
                ),
                "metrics": {
                    "ap_count": len(access_points),
                    "client_count": sum(
                        len(access_point["clients"]) for access_point in access_points
                    ),
                    "wps_enabled_count": sum(
                        1 for access_point in access_points if access_point["wps"]
                    ),
                    "hidden_ap_count": sum(
                        1 for access_point in access_points if access_point["hidden"]
                    ),
                    "data_total": sum(
                        access_point["data"] for access_point in access_points
                    ),
                    "probes_total": sum(
                        access_point["probes"] for access_point in access_points
                    ),
                    "signal_min": min(signals) if signals else 0,
                    "signal_max": max(signals) if signals else 0,
                    "signal_average": _mean(signals),
                },
                "flags": _target_flags(access_points),
                "evidence": evidence,
                "ai_selected": False,
                "ai_profile": None,
            }
        )

    selected = sorted(targets, key=_target_rank)[:max_ai_targets]
    selected_ids = {target["target_id"] for target in selected}
    for target in targets:
        target["ai_selected"] = target["target_id"] in selected_ids

    return {
        "scan_summary": {
            "access_point_count": len(normalized_scan["access_points"]),
            "target_count": len(targets),
            "associated_client_count": sum(
                len(access_point["clients"])
                for access_point in normalized_scan["access_points"]
            ),
            "out_of_range_client_count": len(
                normalized_scan["out_of_range_clients"]
            ),
            "unassociated_client_count": len(
                normalized_scan["unassociated_clients"]
            ),
            "input_bytes": normalized_scan["input_bytes"],
            "ai_target_count": len(selected),
        },
        "targets": targets,
    }


def build_cloud_payload(
    deterministic_result: Dict[str, Any],
    pseudonymization_key: bytes,
    share_ssids: bool,
    language: str,
    scan_metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build the exact privacy-filtered JSON sent to OpenAI."""
    cloud_targets = []
    for target in deterministic_result["targets"]:
        if not target["ai_selected"]:
            continue
        ssid_value = target["ssid"]
        if not share_ssids:
            ssid_value = _pseudonym(
                pseudonymization_key,
                "ssid",
                target["ssid"] if target["ssid"] else target["target_id"],
            )
        cloud_targets.append(
            {
                "target_id": target["target_id"],
                "ssid": ssid_value,
                "ssid_shared": share_ssids,
                "hidden": target["hidden"],
                "vendors": target["vendors"],
                "channels": target["channels"],
                "encryption_codes": target["encryption_codes"],
                "metrics": target["metrics"],
                "flags": target["flags"],
                "evidence_ids": [
                    evidence["evidence_id"] for evidence in target["evidence"]
                ],
            }
        )

    metadata = {}
    if scan_metadata:
        if not isinstance(scan_metadata, dict):
            raise ReconValidationError("scan_metadata must be an object")
        for key in ("scan_id", "date", "objective"):
            if key in scan_metadata:
                metadata[key] = _redact_mac_addresses(scan_metadata[key], 256)

    return {
        "schema_version": "1.0",
        "analysis_language": language,
        "scan_metadata": metadata,
        "scan_summary": deterministic_result["scan_summary"],
        "targets": cloud_targets,
    }


def contains_mac_address(value: Any) -> bool:
    """Return True when serialized data appears to contain a MAC address."""
    serialized = json.dumps(value, ensure_ascii=False)
    return bool(MAC_IN_TEXT_PATTERN.search(serialized))
