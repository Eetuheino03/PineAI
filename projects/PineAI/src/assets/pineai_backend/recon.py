"""Validation and normalization for documented Hak5 Recon response shapes."""

import json
import re
import unicodedata
from typing import Any, Dict, List, Optional


MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_ACCESS_POINTS = 1000
MAX_CLIENTS = 10000
MAX_TEXT_LENGTH = 128
MAC_PATTERN = re.compile(r"^[0-9A-F]{12}$")
COLON_MAC_PATTERN = re.compile(r"^(?:[0-9A-F]{2}:){5}[0-9A-F]{2}$")
HYPHEN_MAC_PATTERN = re.compile(r"^(?:[0-9A-F]{2}-){5}[0-9A-F]{2}$")
MAC_IN_TEXT_PATTERN = re.compile(
    r"(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}"
)


class ReconValidationError(ValueError):
    """Raised when a Recon result cannot be safely normalized."""


def _sanitize_text(value: Any, maximum: int = MAX_TEXT_LENGTH) -> str:
    if value is None:
        return ""
    text = "".join(
        character
        for character in str(value)
        if unicodedata.category(character)[0] != "C"
    )
    return text[:maximum]


def _as_int(value: Any, field: str, default: int = 0) -> int:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return int(value)
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ReconValidationError("{0} must be an integer".format(field))


def _canonical_mac(value: Any) -> str:
    text = _sanitize_text(value, 32).upper()
    compact = re.sub(r"[^0-9A-F]", "", text)
    if not MAC_PATTERN.match(compact):
        return text
    return ":".join(
        compact[index : index + 2] for index in range(0, 12, 2)
    )


def _canonical_bssid(value: Any, index: int) -> str:
    """Return a strict canonical BSSID or reject the AP observation.

    Client addresses are allowed to be absent in documented Recon responses,
    but an access point without an unambiguous BSSID cannot participate in
    stable asset resolution or inventory reconciliation.
    """
    text = _sanitize_text(value, 32).strip().upper()
    if MAC_PATTERN.match(text):
        compact = text
    elif COLON_MAC_PATTERN.match(text):
        compact = text.replace(":", "")
    elif HYPHEN_MAC_PATTERN.match(text):
        compact = text.replace("-", "")
    else:
        raise ReconValidationError(
            "AP bssid at index {0} must be a 48-bit MAC address".format(index)
        )
    return ":".join(
        compact[position : position + 2]
        for position in range(0, 12, 2)
    )


def _find_client_list(
    scan: Dict[str, Any], primary: str, alias: str
) -> List[Any]:
    value = scan.get(primary)
    if value is None:
        value = scan.get(alias, [])
    if not isinstance(value, list):
        raise ReconValidationError(
            "{0} must be an array".format(primary)
        )
    return value


def _load_oui_database(
    path: str = "/etc/pineapple/ouis",
) -> Dict[str, str]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except (OSError, ValueError):
        return {}
    if not isinstance(raw, dict):
        return {}
    return {
        str(key).replace(":", "").replace("-", "").upper()[:6]:
        _sanitize_text(value)
        for key, value in raw.items()
    }


def _vendor_for_mac(mac: str, oui_database: Dict[str, str]) -> str:
    prefix = mac.replace(":", "").replace("-", "").upper()[:6]
    return oui_database.get(prefix, "Unknown")


def _normalize_client(client: Any, index: int) -> Dict[str, Any]:
    if not isinstance(client, dict):
        raise ReconValidationError(
            "client at index {0} must be an object".format(index)
        )
    return {
        "client_mac": _canonical_mac(client.get("client_mac", "")),
        "ap_mac": _canonical_mac(client.get("ap_mac", "")),
        "ap_channel": _as_int(client.get("ap_channel"), "ap_channel"),
        "data": _as_int(client.get("data"), "client.data"),
        "broadcast_probes": _as_int(
            client.get("broadcast_probes"), "broadcast_probes"
        ),
        "direct_probes": _as_int(
            client.get("direct_probes"), "direct_probes"
        ),
        "last_seen": _sanitize_text(client.get("last_seen", ""), 64),
    }


def _normalize_ap(
    access_point: Any,
    index: int,
    oui_database: Dict[str, str],
) -> Dict[str, Any]:
    if not isinstance(access_point, dict):
        raise ReconValidationError(
            "AP at index {0} must be an object".format(index)
        )
    clients = access_point.get("clients", [])
    if clients is None:
        clients = []
    if not isinstance(clients, list):
        raise ReconValidationError(
            "AP clients at index {0} must be an array".format(index)
        )
    bssid = _canonical_bssid(access_point.get("bssid"), index)
    return {
        "ssid": _sanitize_text(access_point.get("ssid", "")),
        "bssid": bssid,
        "encryption": _as_int(
            access_point.get("encryption"), "encryption"
        ),
        "hidden": _as_int(access_point.get("hidden"), "hidden"),
        "wps": _as_int(access_point.get("wps"), "wps"),
        "channel": _as_int(access_point.get("channel"), "channel"),
        "signal": _as_int(access_point.get("signal"), "signal"),
        "data": _as_int(access_point.get("data"), "data"),
        "last_seen": _sanitize_text(
            access_point.get("last_seen", ""), 64
        ),
        "probes": _as_int(access_point.get("probes"), "probes"),
        "clients": [
            _normalize_client(client, client_index)
            for client_index, client in enumerate(clients)
        ],
        "vendor": _vendor_for_mac(bssid, oui_database),
    }


def validate_and_normalize_scan(
    scan: Any,
    oui_database: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Validate documented Recon aliases and return canonical data."""
    if not isinstance(scan, dict):
        raise ReconValidationError("scan must be a JSON object")
    try:
        encoded_size = len(
            json.dumps(
                scan, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
        )
    except (TypeError, ValueError) as error:
        raise ReconValidationError(
            "scan must be JSON serializable: {0}".format(error)
        )
    if encoded_size > MAX_INPUT_BYTES:
        raise ReconValidationError("scan exceeds the 8 MiB input limit")

    access_points = scan.get("APResults")
    if not isinstance(access_points, list):
        raise ReconValidationError("scan.APResults must be an array")
    if len(access_points) > MAX_ACCESS_POINTS:
        raise ReconValidationError(
            "scan contains more than 1000 access points"
        )

    out_of_range = _find_client_list(
        scan, "OutOfRangeClientResults", "OutOfRangeResult"
    )
    unassociated = _find_client_list(
        scan, "UnassociatedClientResults", "UnassociatedResult"
    )
    database = (
        oui_database if oui_database is not None else _load_oui_database()
    )
    normalized_aps = [
        _normalize_ap(access_point, index, database)
        for index, access_point in enumerate(access_points)
    ]
    bssids = [access_point["bssid"] for access_point in normalized_aps]
    if len(set(bssids)) != len(bssids):
        raise ReconValidationError("scan.APResults contains a duplicate BSSID")
    normalized_out_of_range = [
        _normalize_client(client, index)
        for index, client in enumerate(out_of_range)
    ]
    normalized_unassociated = [
        _normalize_client(client, index)
        for index, client in enumerate(unassociated)
    ]
    total_clients = (
        sum(len(access_point["clients"]) for access_point in normalized_aps)
        + len(normalized_out_of_range)
        + len(normalized_unassociated)
    )
    if total_clients > MAX_CLIENTS:
        raise ReconValidationError(
            "scan contains more than 10000 client records"
        )

    return {
        "access_points": normalized_aps,
        "out_of_range_clients": normalized_out_of_range,
        "unassociated_clients": normalized_unassociated,
        "input_bytes": encoded_size,
    }


def contains_mac_address(value: Any) -> bool:
    """Return true when serialized data appears to contain a MAC address."""
    return bool(
        MAC_IN_TEXT_PATTERN.search(
            json.dumps(value, ensure_ascii=False)
        )
    )
