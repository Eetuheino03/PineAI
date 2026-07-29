"""Immutable customer assurance profiles and deterministic policy evaluation."""

import csv
import hashlib
import io
import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .errors import BackendError


ASSURANCE_PROFILE_SCHEMA_VERSION = "1.0"
POLICY_REGISTRY_VERSION = "fixed_v1"
CERTAINTY_LEVELS = ("confirmed", "probable", "limited")
COVERAGE_MODES = ("partial", "authoritative")
MAX_CSV_BYTES = 1024 * 1024
MAX_CSV_ROWS = 2000

CSV_REQUIRED_FIELDS = (
    "site",
    "ssid",
    "bssid",
    "vendor",
    "role",
    "approved",
)
CSV_OPTIONAL_FIELDS = (
    "name",
    "required_presence",
    "allowed_encryption_codes",
    "wps_allowed",
    "allowed_channels",
    "allowed_vendors",
    "notes",
)
CSV_FIELDS = CSV_REQUIRED_FIELDS + CSV_OPTIONAL_FIELDS

POLICY_DEVIATION_REGISTRY = {
    "asset_not_in_authoritative_inventory": {
        "title": "Observed asset is not in the authoritative inventory",
        "severity": "high",
    },
    "required_asset_missing": {
        "title": "Required inventory asset was not observed",
        "severity": "medium",
    },
    "ssid_not_allowed": {
        "title": "Access point advertises an SSID not allowed by inventory policy",
        "severity": "high",
    },
    "encryption_code_not_allowed": {
        "title": "Access point uses an encryption code not allowed by policy",
        "severity": "high",
    },
    "wps_not_allowed": {
        "title": "WPS is enabled where policy forbids it",
        "severity": "high",
    },
    "channel_not_allowed": {
        "title": "Access point uses a channel not allowed by policy",
        "severity": "low",
    },
    "vendor_not_allowed": {
        "title": "Access point vendor is not allowed by policy",
        "severity": "medium",
    },
}

SECURITY_FINDING_REGISTRY = {
    "unauthorized_bssid_advertising_protected_ssid": {
        "title": "Unauthorized BSSID advertises a protected corporate SSID",
        "severity": "critical",
    },
    "protected_ssid_encryption_violation": {
        "title": "Protected SSID encryption violates active policy",
        "severity": "high",
    },
    "wps_enabled_where_forbidden": {
        "title": "WPS is enabled where active policy forbids it",
        "severity": "high",
    },
}

_MAC_COMPACT = re.compile(r"^[0-9A-F]{12}$")
_MAC_COLON = re.compile(r"^(?:[0-9A-F]{2}:){5}[0-9A-F]{2}$")
_MAC_HYPHEN = re.compile(r"^(?:[0-9A-F]{2}-){5}[0-9A-F]{2}$")
_DELIMITERS = {
    ",": ",",
    "comma": ",",
    ";": ";",
    "semicolon": ";",
    "\t": "\t",
    "tab": "\t",
}


def _clean_text(value: Any, maximum: int = 256) -> str:
    if value is None:
        return ""
    text = "".join(
        " " if character in "\r\n\t" else character
        for character in str(value)
        if unicodedata.category(character)[0] != "C"
        or character in "\r\n\t"
    )
    return " ".join(text.split())[:maximum]


def _clean_ssid(value: Any) -> str:
    """Preserve significant printable SSID whitespace while removing controls."""
    if value is None:
        return ""
    return "".join(
        character
        for character in str(value)
        if unicodedata.category(character)[0] != "C"
    )[:128]


def _canonical_bssid(value: Any) -> str:
    text = _clean_text(value, 32).upper()
    if _MAC_COMPACT.match(text):
        compact = text
    elif _MAC_COLON.match(text):
        compact = text.replace(":", "")
    elif _MAC_HYPHEN.match(text):
        compact = text.replace("-", "")
    else:
        raise BackendError(
            "invalid_inventory_bssid",
            "bssid must be a 48-bit MAC address",
        )
    return ":".join(
        compact[position : position + 2]
        for position in range(0, 12, 2)
    )


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _stable_id(prefix: str, *values: Any) -> str:
    return "{0}_{1}".format(prefix, _digest(list(values))[:12])


def _delimiter(value: Any) -> str:
    if value not in _DELIMITERS:
        raise BackendError(
            "invalid_csv_delimiter",
            "delimiter must be comma, semicolon, or tab",
        )
    return _DELIMITERS[value]


def _parse_boolean(
    value: Any,
    field: str,
    allow_empty: bool,
) -> Optional[bool]:
    text = _clean_text(value, 16).lower()
    if allow_empty and not text:
        return None
    if text in ("true", "1", "yes"):
        return True
    if text in ("false", "0", "no", ""):
        return False
    raise BackendError(
        "invalid_inventory_value",
        "{0} must be true or false".format(field),
    )


def _split_text(value: Any) -> Tuple[str, ...]:
    return tuple(
        sorted(
            {
                _clean_text(item, 128)
                for item in str(value or "").split("|")
                if _clean_text(item, 128)
            }
        )
    )


def _split_integers(
    value: Any,
    field: str,
    minimum: Optional[int] = None,
    maximum: Optional[int] = None,
) -> Tuple[int, ...]:
    if value is None or str(value).strip() == "":
        return ()
    result = set()
    for item in str(value).split("|"):
        try:
            number = int(item.strip())
        except (TypeError, ValueError):
            raise BackendError(
                "invalid_inventory_value",
                "{0} must contain pipe-separated integers".format(field),
            )
        if minimum is not None and number < minimum:
            raise BackendError(
                "invalid_inventory_value",
                "{0} contains an out-of-range value".format(field),
            )
        if maximum is not None and number > maximum:
            raise BackendError(
                "invalid_inventory_value",
                "{0} contains an out-of-range value".format(field),
            )
        result.add(number)
    return tuple(sorted(result))


def _spreadsheet_safe(value: Any) -> str:
    text = str(value if value is not None else "")
    if text.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


@dataclass(frozen=True)
class AssuranceAsset:
    site: str
    ssid: str
    bssid: str
    vendor: str
    role: str
    approved: bool
    name: str = ""
    required_presence: bool = False
    allowed_encryption_codes: Tuple[int, ...] = ()
    wps_allowed: Optional[bool] = None
    allowed_channels: Tuple[int, ...] = ()
    allowed_vendors: Tuple[str, ...] = ()
    notes: str = ""

    def __post_init__(self) -> None:
        if _canonical_bssid(self.bssid) != self.bssid:
            raise BackendError(
                "invalid_assurance_profile",
                "AssuranceAsset bssid must use canonical uppercase notation",
            )
        text_limits = {
            "site": (self.site, 200),
            "ssid": (self.ssid, 128),
            "vendor": (self.vendor, 200),
            "role": (self.role, 100),
            "name": (self.name, 200),
            "notes": (self.notes, 1000),
        }
        if any(
            not isinstance(value, str) or len(value) > maximum
            for value, maximum in text_limits.values()
        ):
            raise BackendError(
                "invalid_assurance_profile",
                "AssuranceAsset text field is invalid",
            )
        if not isinstance(self.approved, bool) or not isinstance(
            self.required_presence, bool
        ):
            raise BackendError(
                "invalid_assurance_profile",
                "approved and required_presence must be booleans",
            )
        if self.wps_allowed is not None and not isinstance(
            self.wps_allowed, bool
        ):
            raise BackendError(
                "invalid_assurance_profile",
                "wps_allowed must be a boolean or null",
            )
        tuple_fields = (
            self.allowed_encryption_codes,
            self.allowed_channels,
            self.allowed_vendors,
        )
        if any(not isinstance(value, tuple) for value in tuple_fields):
            raise BackendError(
                "invalid_assurance_profile",
                "AssuranceAsset policy fields must be immutable tuples",
            )
        if any(
            not isinstance(value, int) or isinstance(value, bool)
            for value in self.allowed_encryption_codes
        ) or any(
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < 1
            or value > 196
            for value in self.allowed_channels
        ):
            raise BackendError(
                "invalid_assurance_profile",
                "AssuranceAsset numeric policy field is invalid",
            )
        if any(
            not isinstance(value, str) or len(value) > 200
            for value in self.allowed_vendors
        ):
            raise BackendError(
                "invalid_assurance_profile",
                "AssuranceAsset allowed_vendors is invalid",
            )

    @property
    def inventory_asset_id(self) -> str:
        return _stable_id("inventory_asset", self.bssid)

    @property
    def evidence_id(self) -> str:
        return "evidence_{0}".format(
            _digest(["inventory_asset_declaration", self.bssid])[:12]
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "inventory_asset_id": self.inventory_asset_id,
            "evidence_id": self.evidence_id,
            "site": self.site,
            "ssid": self.ssid,
            "bssid": self.bssid,
            "vendor": self.vendor,
            "role": self.role,
            "approved": self.approved,
            "name": self.name,
            "required_presence": self.required_presence,
            "allowed_encryption_codes": list(
                self.allowed_encryption_codes
            ),
            "wps_allowed": self.wps_allowed,
            "allowed_channels": list(self.allowed_channels),
            "allowed_vendors": list(self.allowed_vendors),
            "notes": self.notes,
        }


@dataclass(frozen=True)
class ProtectedSSIDPolicy:
    ssid: str
    allowed_encryption_codes: Tuple[int, ...] = ()
    wps_allowed: Optional[bool] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ssid": self.ssid,
            "allowed_encryption_codes": list(
                self.allowed_encryption_codes
            ),
            "wps_allowed": self.wps_allowed,
        }


def _asset_from_dict(value: Any) -> AssuranceAsset:
    if not isinstance(value, dict):
        raise BackendError(
            "invalid_assurance_profile", "profile asset must be an object"
        )
    allowed = set(CSV_FIELDS) | {"inventory_asset_id", "evidence_id"}
    if set(value) - allowed:
        raise BackendError(
            "invalid_assurance_profile",
            "profile asset contains unsupported fields",
        )
    bssid = _canonical_bssid(value.get("bssid"))
    for field in ("allowed_encryption_codes", "allowed_channels", "allowed_vendors"):
        if not isinstance(value.get(field, []), (list, tuple)):
            raise BackendError(
                "invalid_assurance_profile",
                "{0} must be an array".format(field),
            )
    allowed_vendors = tuple(
        sorted(
            {
                _clean_text(item, 128)
                for item in value.get("allowed_vendors", [])
                if _clean_text(item, 128)
            },
            key=lambda item: (item.casefold(), item),
        )
    )
    raw_encryption = value.get("allowed_encryption_codes", [])
    if any(
        not isinstance(item, int) or isinstance(item, bool)
        for item in raw_encryption
    ):
        raise BackendError(
            "invalid_assurance_profile",
            "allowed_encryption_codes must contain integers",
        )
    encryption = tuple(sorted(set(raw_encryption)))
    raw_channels = value.get("allowed_channels", [])
    if any(
        not isinstance(item, int) or isinstance(item, bool)
        for item in raw_channels
    ):
        raise BackendError(
            "invalid_assurance_profile",
            "allowed_channels must contain integers",
        )
    channels = tuple(sorted(set(raw_channels)))
    if any(channel < 1 or channel > 196 for channel in channels):
        raise BackendError(
            "invalid_assurance_profile",
            "allowed_channels contains an invalid channel",
        )
    approved = value.get("approved")
    required_presence = value.get("required_presence", False)
    wps_allowed = value.get("wps_allowed")
    if not isinstance(approved, bool):
        raise BackendError(
            "invalid_assurance_profile",
            "approved must be a boolean",
        )
    if not isinstance(required_presence, bool):
        raise BackendError(
            "invalid_assurance_profile",
            "required_presence must be a boolean",
        )
    if wps_allowed is not None and not isinstance(wps_allowed, bool):
        raise BackendError(
            "invalid_assurance_profile",
            "wps_allowed must be a boolean or null",
        )
    return AssuranceAsset(
        site=_clean_text(value.get("site"), 200),
        ssid=_clean_ssid(value.get("ssid")),
        bssid=bssid,
        vendor=_clean_text(value.get("vendor"), 200),
        role=_clean_text(value.get("role"), 100),
        approved=approved,
        name=_clean_text(value.get("name"), 200),
        required_presence=required_presence,
        allowed_encryption_codes=encryption,
        wps_allowed=wps_allowed,
        allowed_channels=channels,
        allowed_vendors=allowed_vendors,
        notes=_clean_text(value.get("notes"), 1000),
    )


def _ssid_policy_from_dict(value: Any) -> ProtectedSSIDPolicy:
    if not isinstance(value, dict) or set(value) - {
        "ssid",
        "allowed_encryption_codes",
        "wps_allowed",
    }:
        raise BackendError(
            "invalid_assurance_profile",
            "protected SSID policy is invalid",
        )
    ssid = _clean_ssid(value.get("ssid"))
    if not ssid:
        raise BackendError(
            "invalid_assurance_profile",
            "protected SSID policy requires an SSID",
        )
    codes = value.get("allowed_encryption_codes", [])
    if not isinstance(codes, (list, tuple)) or any(
        not isinstance(item, int) or isinstance(item, bool) for item in codes
    ):
        raise BackendError(
            "invalid_assurance_profile",
            "protected SSID encryption codes are invalid",
        )
    wps_allowed = value.get("wps_allowed")
    if wps_allowed is not None and not isinstance(wps_allowed, bool):
        raise BackendError(
            "invalid_assurance_profile",
            "protected SSID wps_allowed must be a boolean or null",
        )
    return ProtectedSSIDPolicy(
        ssid=ssid,
        allowed_encryption_codes=tuple(sorted(set(codes))),
        wps_allowed=wps_allowed,
    )


@dataclass(frozen=True)
class AssuranceProfile:
    coverage_mode: str
    assets: Tuple[AssuranceAsset, ...]
    policy_rule_ids: Tuple[str, ...] = tuple(POLICY_DEVIATION_REGISTRY)

    def __post_init__(self) -> None:
        if self.coverage_mode not in COVERAGE_MODES:
            raise BackendError(
                "invalid_assurance_profile",
                "inventory coverage_mode must be partial or authoritative",
            )
        if not isinstance(self.assets, tuple) or any(
            not isinstance(asset, AssuranceAsset) for asset in self.assets
        ):
            raise BackendError(
                "invalid_assurance_profile",
                "profile assets must be an immutable tuple",
            )
        bssids = [asset.bssid for asset in self.assets]
        if len(set(bssids)) != len(bssids):
            raise BackendError(
                "invalid_assurance_profile",
                "profile contains duplicate BSSIDs",
            )
        if (
            not isinstance(self.policy_rule_ids, tuple)
            or set(self.policy_rule_ids) != set(POLICY_DEVIATION_REGISTRY)
            or len(self.policy_rule_ids) != len(POLICY_DEVIATION_REGISTRY)
        ):
            raise BackendError(
                "invalid_assurance_profile",
                "profile must use the complete fixed_v1 policy registry",
            )

    @property
    def profile_id(self) -> str:
        return _stable_id("profile", self._identity_document())

    @property
    def inventory_authoritative(self) -> bool:
        return self.coverage_mode == "authoritative"

    @property
    def protected_ssid_policies(self) -> Tuple[ProtectedSSIDPolicy, ...]:
        policies_by_ssid: Dict[str, Dict[str, Any]] = {}
        for asset in self.assets:
            if not asset.approved or not asset.ssid:
                continue
            current = policies_by_ssid.setdefault(
                asset.ssid,
                {"codes": set(), "wps_values": set()},
            )
            current["codes"].update(asset.allowed_encryption_codes)
            if asset.wps_allowed is not None:
                current["wps_values"].add(asset.wps_allowed)
        result = []
        for ssid in sorted(policies_by_ssid):
            item = policies_by_ssid[ssid]
            if True in item["wps_values"]:
                wps_allowed = True
            elif False in item["wps_values"]:
                wps_allowed = False
            else:
                wps_allowed = None
            result.append(
                ProtectedSSIDPolicy(
                    ssid=ssid,
                    allowed_encryption_codes=tuple(sorted(item["codes"])),
                    wps_allowed=wps_allowed,
                )
            )
        return tuple(result)

    def _identity_document(self) -> Dict[str, Any]:
        return {
            "schema_version": ASSURANCE_PROFILE_SCHEMA_VERSION,
            "inventory": {
                "coverage_mode": self.coverage_mode,
                "assets": [
                    asset.to_dict()
                    for asset in sorted(
                        self.assets, key=lambda item: item.bssid
                    )
                ],
            },
            "policy": {
                "registry_version": POLICY_REGISTRY_VERSION,
                "rules": {
                    rule_id: {"enabled": True}
                    for rule_id in sorted(self.policy_rule_ids)
                },
            },
        }

    def to_dict(self) -> Dict[str, Any]:
        return dict(self._identity_document(), profile_id=self.profile_id)

    @classmethod
    def from_dict(cls, value: Any) -> "AssuranceProfile":
        if not isinstance(value, dict) or set(value) - {
            "schema_version",
            "profile_id",
            "inventory",
            "policy",
        }:
            raise BackendError(
                "invalid_assurance_profile",
                "assurance profile fields are invalid",
            )
        if value.get("schema_version") != ASSURANCE_PROFILE_SCHEMA_VERSION:
            raise BackendError(
                "invalid_assurance_profile",
                "assurance profile schema_version is unsupported",
            )
        inventory = value.get("inventory")
        policy = value.get("policy")
        if not isinstance(inventory, dict) or set(inventory) - {
            "coverage_mode",
            "assets",
        }:
            raise BackendError(
                "invalid_assurance_profile",
                "profile inventory fields are invalid",
            )
        if not isinstance(policy, dict) or set(policy) - {
            "registry_version",
            "rules",
        }:
            raise BackendError(
                "invalid_assurance_profile",
                "profile policy fields are invalid",
            )
        if policy.get("registry_version") != POLICY_REGISTRY_VERSION:
            raise BackendError(
                "invalid_assurance_profile",
                "profile policy registry_version is unsupported",
            )
        rules = policy.get("rules")
        if not isinstance(rules, dict):
            raise BackendError(
                "invalid_assurance_profile",
                "profile policy rules must be an object",
            )
        if rules and set(rules) != set(POLICY_DEVIATION_REGISTRY):
            raise BackendError(
                "invalid_assurance_profile",
                "profile policy rules must match fixed_v1",
            )
        for rule_id, rule in rules.items():
            if not isinstance(rule, dict) or rule.get("enabled") is not True:
                raise BackendError(
                    "invalid_assurance_profile",
                    "fixed_v1 policy rules cannot be disabled",
                )
        raw_assets = inventory.get("assets")
        if not isinstance(raw_assets, list) or len(raw_assets) > MAX_CSV_ROWS:
            raise BackendError(
                "invalid_assurance_profile",
                "profile assets must contain at most {0} items".format(
                    MAX_CSV_ROWS
                ),
            )
        profile = cls(
            coverage_mode=inventory.get("coverage_mode"),
            assets=tuple(
                sorted(
                    (_asset_from_dict(item) for item in raw_assets),
                    key=lambda item: item.bssid,
                )
            ),
        )
        supplied_id = value.get("profile_id")
        if supplied_id is not None and supplied_id != profile.profile_id:
            raise BackendError(
                "invalid_assurance_profile",
                "profile_id does not match the immutable profile content",
            )
        return profile

    @classmethod
    def from_inventory_preview(
        cls,
        preview: Any,
        coverage_mode: str = "partial",
    ) -> "AssuranceProfile":
        if not isinstance(preview, dict) or not preview.get("valid"):
            raise BackendError(
                "invalid_inventory_csv",
                "a valid inventory preview is required",
            )
        assets = tuple(
            _asset_from_dict(item) for item in preview.get("rows", [])
        )
        return cls(
            coverage_mode=coverage_mode,
            assets=tuple(sorted(assets, key=lambda item: item.bssid)),
        )


def preview_inventory_csv(
    content: Any,
    delimiter: str = ",",
) -> Dict[str, Any]:
    """Parse an inventory CSV without persisting it."""
    if not isinstance(content, str):
        raise BackendError(
            "invalid_inventory_csv", "CSV content must be text"
        )
    encoded = content.encode("utf-8")
    if len(encoded) > MAX_CSV_BYTES:
        raise BackendError(
            "inventory_csv_too_large", "CSV exceeds the 1 MiB limit"
        )
    selected_delimiter = _delimiter(delimiter)
    source = content.lstrip("\ufeff")
    errors = []
    rows = []
    try:
        reader = csv.DictReader(io.StringIO(source), delimiter=selected_delimiter)
        headers = reader.fieldnames
        if not headers or any(
            field not in headers for field in CSV_REQUIRED_FIELDS
        ):
            raise BackendError(
                "invalid_inventory_csv",
                "CSV requires these headers: {0}".format(
                    ", ".join(CSV_REQUIRED_FIELDS)
                ),
            )
        unknown_headers = sorted(set(headers) - set(CSV_FIELDS))
        if unknown_headers:
            raise BackendError(
                "invalid_inventory_csv",
                "CSV contains unsupported headers: {0}".format(
                    ", ".join(unknown_headers)
                ),
            )
        seen_bssids = set()
        for row_number, source_row in enumerate(reader, start=2):
            if row_number > MAX_CSV_ROWS + 1:
                raise BackendError(
                    "inventory_csv_too_large",
                    "CSV contains more than {0} inventory rows".format(
                        MAX_CSV_ROWS
                    ),
                )
            try:
                bssid = _canonical_bssid(source_row.get("bssid"))
                if bssid in seen_bssids:
                    raise BackendError(
                        "duplicate_inventory_bssid",
                        "BSSID appears more than once",
                    )
                seen_bssids.add(bssid)
                normalized = {
                    "site": _clean_text(source_row.get("site"), 200),
                    "ssid": _clean_ssid(source_row.get("ssid")),
                    "bssid": bssid,
                    "vendor": _clean_text(
                        source_row.get("vendor"), 200
                    ),
                    "role": _clean_text(source_row.get("role"), 100),
                    "approved": _parse_boolean(
                        source_row.get("approved"), "approved", False
                    ),
                    "name": _clean_text(source_row.get("name"), 200),
                    "required_presence": _parse_boolean(
                        source_row.get("required_presence"),
                        "required_presence",
                        False,
                    ),
                    "allowed_encryption_codes": list(
                        _split_integers(
                            source_row.get("allowed_encryption_codes"),
                            "allowed_encryption_codes",
                        )
                    ),
                    "wps_allowed": _parse_boolean(
                        source_row.get("wps_allowed"),
                        "wps_allowed",
                        True,
                    ),
                    "allowed_channels": list(
                        _split_integers(
                            source_row.get("allowed_channels"),
                            "allowed_channels",
                            1,
                            196,
                        )
                    ),
                    "allowed_vendors": list(
                        _split_text(source_row.get("allowed_vendors"))
                    ),
                    "notes": _clean_text(
                        source_row.get("notes"), 1000
                    ),
                }
                rows.append(normalized)
            except BackendError as failure:
                errors.append(
                    {
                        "row": row_number,
                        "code": failure.code,
                        "message": failure.safe_message,
                    }
                )
    except csv.Error as failure:
        raise BackendError(
            "invalid_inventory_csv",
            "CSV could not be parsed: {0}".format(failure),
        )
    rows.sort(key=lambda item: item["bssid"])
    return {
        "schema_version": ASSURANCE_PROFILE_SCHEMA_VERSION,
        "valid": not errors,
        "source_sha256": hashlib.sha256(encoded).hexdigest(),
        "normalized_digest": _digest(rows),
        "row_count": len(rows),
        "rows": rows,
        "errors": errors,
        "warnings": [],
    }


def export_inventory_csv(
    profile_or_rows: Any,
    delimiter: str = ",",
) -> str:
    """Export deterministic formula-safe inventory CSV text."""
    selected_delimiter = _delimiter(delimiter)
    if isinstance(profile_or_rows, AssuranceProfile):
        rows = [asset.to_dict() for asset in profile_or_rows.assets]
    elif isinstance(profile_or_rows, dict) and isinstance(
        profile_or_rows.get("rows"), list
    ):
        rows = profile_or_rows["rows"]
    elif isinstance(profile_or_rows, (list, tuple)):
        rows = list(profile_or_rows)
    else:
        raise BackendError(
            "invalid_inventory_export",
            "inventory export requires a profile or normalized rows",
        )
    normalized_assets = sorted(
        (_asset_from_dict(row) for row in rows),
        key=lambda item: item.bssid,
    )
    output = io.StringIO(newline="")
    writer = csv.DictWriter(
        output,
        fieldnames=list(CSV_FIELDS),
        delimiter=selected_delimiter,
        lineterminator="\n",
    )
    writer.writeheader()
    for asset in normalized_assets:
        writer.writerow(
            {
                "site": _spreadsheet_safe(asset.site),
                "ssid": _spreadsheet_safe(asset.ssid),
                "bssid": asset.bssid,
                "vendor": _spreadsheet_safe(asset.vendor),
                "role": _spreadsheet_safe(asset.role),
                "approved": "true" if asset.approved else "false",
                "name": _spreadsheet_safe(asset.name),
                "required_presence": (
                    "true" if asset.required_presence else "false"
                ),
                "allowed_encryption_codes": "|".join(
                    str(value)
                    for value in asset.allowed_encryption_codes
                ),
                "wps_allowed": (
                    ""
                    if asset.wps_allowed is None
                    else ("true" if asset.wps_allowed else "false")
                ),
                "allowed_channels": "|".join(
                    str(value) for value in asset.allowed_channels
                ),
                "allowed_vendors": _spreadsheet_safe(
                    "|".join(asset.allowed_vendors)
                ),
                "notes": _spreadsheet_safe(asset.notes),
            }
        )
    return output.getvalue()


def _evidence_ids(access_point: Dict[str, Any]) -> List[str]:
    value = access_point.get("evidence_id")
    return [value] if isinstance(value, str) and value else []


def _observed_change(
    profile_id: str,
    change_type: str,
    subject_id: str,
    certainty: str,
    evidence_ids: List[str],
    expected: Any,
    observed: Any,
) -> Dict[str, Any]:
    return {
        "change_id": _stable_id(
            "change", profile_id, change_type, subject_id
        ),
        "change_type": change_type,
        "subject_id": subject_id,
        "certainty": certainty,
        "evidence_ids": sorted(set(evidence_ids)),
        "before_after": {
            "before": expected,
            "after": observed,
        },
        "expected": expected,
        "observed": observed,
    }


def _policy_deviation(
    profile_id: str,
    rule_id: str,
    subject_id: str,
    certainty: str,
    evidence_ids: List[str],
    expected: Any,
    observed: Any,
) -> Dict[str, Any]:
    capability = POLICY_DEVIATION_REGISTRY[rule_id]
    return {
        "deviation_id": _stable_id(
            "deviation", profile_id, rule_id, subject_id
        ),
        "rule_id": rule_id,
        "title": capability["title"],
        "severity": capability["severity"],
        "certainty": certainty,
        "subject_id": subject_id,
        "evidence_ids": sorted(set(evidence_ids)),
        "expected": expected,
        "observed": observed,
    }


def _security_finding(
    profile_id: str,
    rule_id: str,
    subject_id: str,
    certainty: str,
    evidence_ids: List[str],
    expected: Any,
    observed: Any,
) -> Dict[str, Any]:
    capability = SECURITY_FINDING_REGISTRY[rule_id]
    return {
        "finding_id": _stable_id(
            "finding", profile_id, rule_id, subject_id
        ),
        "rule_id": rule_id,
        "title": capability["title"],
        "severity": capability["severity"],
        "certainty": certainty,
        "subject_id": subject_id,
        "evidence_ids": sorted(set(evidence_ids)),
        "expected": expected,
        "observed": observed,
    }


def evaluate_assurance_profile(
    profile: Any,
    snapshot: Any,
    comparability: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Evaluate inventory policy without provider calls or mutable state."""
    if not isinstance(profile, AssuranceProfile):
        profile = AssuranceProfile.from_dict(profile)
    if not isinstance(snapshot, dict) or not isinstance(
        snapshot.get("access_points"), list
    ):
        raise BackendError(
            "invalid_assurance_snapshot",
            "a resolved snapshot is required",
        )
    comparable = (
        isinstance(comparability, dict)
        and comparability.get("status") == "comparable"
    )
    inventory = {asset.bssid: asset for asset in profile.assets}
    protected = {
        policy.ssid: policy
        for policy in profile.protected_ssid_policies
    }
    observed_by_bssid = {}
    for access_point in snapshot["access_points"]:
        if not isinstance(access_point, dict):
            raise BackendError(
                "invalid_assurance_snapshot",
                "snapshot access_points must contain objects",
            )
        bssid = _canonical_bssid(access_point.get("bssid"))
        if bssid in observed_by_bssid:
            raise BackendError(
                "invalid_assurance_snapshot",
                "snapshot contains duplicate BSSIDs",
            )
        observed_by_bssid[bssid] = access_point

    changes: Dict[str, Dict[str, Any]] = {}
    deviations: Dict[str, Dict[str, Any]] = {}
    security: Dict[str, Dict[str, Any]] = {}

    def add_change(
        change_type: str,
        subject_id: str,
        certainty: str,
        evidence_ids: List[str],
        expected: Any,
        observed: Any,
    ) -> None:
        item = _observed_change(
            profile.profile_id,
            change_type,
            subject_id,
            certainty,
            evidence_ids,
            expected,
            observed,
        )
        changes[item["change_id"]] = item

    def add_deviation(
        rule_id: str,
        subject_id: str,
        certainty: str,
        evidence_ids: List[str],
        expected: Any,
        observed: Any,
    ) -> None:
        item = _policy_deviation(
            profile.profile_id,
            rule_id,
            subject_id,
            certainty,
            evidence_ids,
            expected,
            observed,
        )
        deviations[item["deviation_id"]] = item

    def add_security(
        rule_id: str,
        subject_id: str,
        certainty: str,
        evidence_ids: List[str],
        expected: Any,
        observed: Any,
    ) -> None:
        item = _security_finding(
            profile.profile_id,
            rule_id,
            subject_id,
            certainty,
            evidence_ids,
            expected,
            observed,
        )
        security[item["finding_id"]] = item

    for bssid in sorted(observed_by_bssid):
        access_point = observed_by_bssid[bssid]
        subject_id = (
            access_point.get("asset_id")
            if isinstance(access_point.get("asset_id"), str)
            and access_point.get("asset_id")
            else _stable_id("observed_asset", bssid)
        )
        evidence_ids = _evidence_ids(access_point)
        asset = inventory.get(bssid)
        ssid = _clean_ssid(access_point.get("ssid"))
        ssid_policy = protected.get(ssid)

        if asset is None:
            certainty = (
                "confirmed"
                if profile.inventory_authoritative
                else "limited"
            )
            add_change(
                "asset_not_in_inventory",
                subject_id,
                certainty,
                evidence_ids,
                {"inventory_authoritative": profile.inventory_authoritative},
                {"bssid": bssid, "ssid": ssid},
            )
            if profile.inventory_authoritative:
                add_deviation(
                    "asset_not_in_authoritative_inventory",
                    subject_id,
                    "confirmed",
                    evidence_ids,
                    {"authorized": True},
                    {"bssid": bssid, "ssid": ssid},
                )
                if ssid_policy is not None:
                    add_security(
                        "unauthorized_bssid_advertising_protected_ssid",
                        subject_id,
                        "confirmed",
                        evidence_ids,
                        {"authorized": True, "protected_ssid": ssid},
                        {"bssid": bssid, "ssid": ssid},
                    )
        else:
            if not asset.approved and ssid_policy is not None:
                add_security(
                    "unauthorized_bssid_advertising_protected_ssid",
                    subject_id,
                    "confirmed",
                    evidence_ids,
                    {"authorized": True, "protected_ssid": ssid},
                    {"bssid": bssid, "ssid": ssid},
                )
            if asset.ssid and ssid != asset.ssid:
                add_change(
                    "ssid_not_allowed",
                    subject_id,
                    "confirmed",
                    evidence_ids,
                    {"allowed_ssids": [asset.ssid]},
                    {"ssid": ssid},
                )
                add_deviation(
                    "ssid_not_allowed",
                    subject_id,
                    "confirmed",
                    evidence_ids,
                    {"allowed_ssids": [asset.ssid]},
                    {"ssid": ssid},
                )
            encryption = access_point.get("encryption")
            if (
                asset.allowed_encryption_codes
                and encryption not in asset.allowed_encryption_codes
            ):
                add_change(
                    "encryption_code_not_allowed",
                    subject_id,
                    "confirmed",
                    evidence_ids,
                    {
                        "allowed_encryption_codes": list(
                            asset.allowed_encryption_codes
                        )
                    },
                    {"encryption_code": encryption},
                )
                add_deviation(
                    "encryption_code_not_allowed",
                    subject_id,
                    "confirmed",
                    evidence_ids,
                    {
                        "allowed_encryption_codes": list(
                            asset.allowed_encryption_codes
                        )
                    },
                    {"encryption_code": encryption},
                )
            if asset.wps_allowed is False and bool(access_point.get("wps")):
                add_change(
                    "wps_not_allowed",
                    subject_id,
                    "confirmed",
                    evidence_ids,
                    {"wps_allowed": False},
                    {"wps": True},
                )
                add_deviation(
                    "wps_not_allowed",
                    subject_id,
                    "confirmed",
                    evidence_ids,
                    {"wps_allowed": False},
                    {"wps": True},
                )
            channel = access_point.get("channel")
            if asset.allowed_channels and channel not in asset.allowed_channels:
                add_change(
                    "channel_not_allowed",
                    subject_id,
                    "confirmed",
                    evidence_ids,
                    {"allowed_channels": list(asset.allowed_channels)},
                    {"channel": channel},
                )
                add_deviation(
                    "channel_not_allowed",
                    subject_id,
                    "confirmed",
                    evidence_ids,
                    {"allowed_channels": list(asset.allowed_channels)},
                    {"channel": channel},
                )
            vendor = _clean_text(access_point.get("vendor"), 128)
            known_vendor = bool(
                vendor and vendor.casefold() != "unknown"
            )
            configured_vendors = asset.allowed_vendors
            if (
                not configured_vendors
                and asset.vendor
                and asset.vendor.casefold() != "unknown"
            ):
                configured_vendors = (asset.vendor,)
            allowed_vendor_names = {
                item.casefold() for item in configured_vendors
            }
            if (
                configured_vendors
                and known_vendor
                and vendor.casefold() not in allowed_vendor_names
            ):
                add_change(
                    "vendor_not_allowed",
                    subject_id,
                    "confirmed",
                    evidence_ids,
                    {"allowed_vendors": list(configured_vendors)},
                    {"vendor": vendor},
                )
                add_deviation(
                    "vendor_not_allowed",
                    subject_id,
                    "confirmed",
                    evidence_ids,
                    {"allowed_vendors": list(configured_vendors)},
                    {"vendor": vendor},
                )

        if ssid_policy is not None:
            encryption = access_point.get("encryption")
            if (
                ssid_policy.allowed_encryption_codes
                and encryption
                not in ssid_policy.allowed_encryption_codes
            ):
                add_security(
                    "protected_ssid_encryption_violation",
                    subject_id,
                    "confirmed",
                    evidence_ids,
                    {
                        "ssid": ssid,
                        "allowed_encryption_codes": list(
                            ssid_policy.allowed_encryption_codes
                        ),
                    },
                    {"encryption_code": encryption},
                )
            if (
                ssid_policy.wps_allowed is False
                and bool(access_point.get("wps"))
            ):
                add_security(
                    "wps_enabled_where_forbidden",
                    subject_id,
                    "confirmed",
                    evidence_ids,
                    {"ssid": ssid, "wps_allowed": False},
                    {"wps": True},
                )

    for bssid in sorted(inventory):
        asset = inventory[bssid]
        if asset.required_presence and bssid not in observed_by_bssid:
            certainty = "probable" if comparable else "limited"
            add_change(
                "required_asset_missing",
                asset.inventory_asset_id,
                certainty,
                [asset.evidence_id],
                {"required": True, "bssid": bssid},
                {"observed": False},
            )
            if comparable:
                add_deviation(
                    "required_asset_missing",
                    asset.inventory_asset_id,
                    "probable",
                    [asset.evidence_id],
                    {"required": True, "bssid": bssid},
                    {"observed": False},
                )

    observed_changes = sorted(
        changes.values(),
        key=lambda item: (
            item["change_type"],
            item["subject_id"],
            item["change_id"],
        ),
    )
    policy_deviations = sorted(
        deviations.values(),
        key=lambda item: (
            item["rule_id"],
            item["subject_id"],
            item["deviation_id"],
        ),
    )
    security_findings = sorted(
        security.values(),
        key=lambda item: (
            item["rule_id"],
            item["subject_id"],
            item["finding_id"],
        ),
    )
    return {
        "schema_version": ASSURANCE_PROFILE_SCHEMA_VERSION,
        "profile_id": profile.profile_id,
        "coverage_mode": profile.coverage_mode,
        "inventory_authoritative": profile.inventory_authoritative,
        "comparability_status": (
            comparability.get("status")
            if isinstance(comparability, dict)
            else None
        ),
        "observed_changes": observed_changes,
        "policy_deviations": policy_deviations,
        "security_findings": security_findings,
        "summary": {
            "observed_change_count": len(observed_changes),
            "policy_deviation_count": len(policy_deviations),
            "security_finding_count": len(security_findings),
        },
    }


def assurance_profile_capabilities() -> Dict[str, Any]:
    return {
        "schema_version": ASSURANCE_PROFILE_SCHEMA_VERSION,
        "coverage_modes": list(COVERAGE_MODES),
        "policy_registry_version": POLICY_REGISTRY_VERSION,
        "certainty_levels": list(CERTAINTY_LEVELS),
        "policy_deviations": [
            dict(
                POLICY_DEVIATION_REGISTRY[rule_id],
                rule_id=rule_id,
            )
            for rule_id in POLICY_DEVIATION_REGISTRY
        ],
        "security_findings": [
            dict(
                SECURITY_FINDING_REGISTRY[rule_id],
                rule_id=rule_id,
            )
            for rule_id in SECURITY_FINDING_REGISTRY
        ],
        "observed_changes_have_severity": False,
        "csv": {
            "fields": list(CSV_FIELDS),
            "required_fields": list(CSV_REQUIRED_FIELDS),
            "optional_fields": list(CSV_OPTIONAL_FIELDS),
            "maximum_bytes": MAX_CSV_BYTES,
            "maximum_rows": MAX_CSV_ROWS,
            "delimiters": ["comma", "semicolon", "tab"],
            "formula_neutralization": True,
        },
    }
