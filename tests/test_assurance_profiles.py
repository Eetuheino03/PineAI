import csv
import dataclasses
import io
import re
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "projects" / "PineAI" / "src" / "assets"
sys.path.insert(0, str(ASSETS))

from pineai_backend.assurance_profiles import (  # noqa: E402
    CERTAINTY_LEVELS,
    CSV_REQUIRED_FIELDS,
    POLICY_DEVIATION_REGISTRY,
    SECURITY_FINDING_REGISTRY,
    AssuranceAsset,
    AssuranceProfile,
    assurance_profile_capabilities,
    evaluate_assurance_profile,
    export_inventory_csv,
    preview_inventory_csv,
)
from pineai_backend.errors import BackendError  # noqa: E402


CSV_HEADER = (
    "site,ssid,bssid,vendor,role,approved,name,required_presence,"
    "allowed_encryption_codes,wps_allowed,allowed_channels,"
    "allowed_vendors,notes\n"
)


def _asset(
    bssid,
    ssid,
    approved=True,
    required=False,
    vendor="Example",
    encryption=(5,),
    wps_allowed=False,
    channels=(1,),
    allowed_vendors=(),
):
    return AssuranceAsset(
        site="HQ",
        ssid=ssid,
        bssid=bssid,
        vendor=vendor,
        role="corporate",
        approved=approved,
        required_presence=required,
        allowed_encryption_codes=encryption,
        wps_allowed=wps_allowed,
        allowed_channels=channels,
        allowed_vendors=allowed_vendors,
    )


def _access_point(
    number,
    bssid,
    ssid,
    encryption=5,
    wps=False,
    channel=1,
    vendor="Example",
):
    return {
        "asset_id": "ap_{0:012x}".format(number),
        "network_id": "network_{0:012x}".format(number),
        "evidence_id": "evidence_{0:012x}".format(number),
        "bssid": bssid,
        "ssid": ssid,
        "hidden": not bool(ssid),
        "encryption": encryption,
        "wps": wps,
        "channel": channel,
        "band": "2.4",
        "signal": -45,
        "vendor": vendor,
        "client_count": 0,
    }


class InventoryCsvTests(unittest.TestCase):
    def test_required_base_fields_and_normalization(self):
        content = (
            CSV_HEADER
            + "HQ,Corp,aa-bb-cc-00-00-01,Example,corporate,true,"
            "Main AP,true,5|4,false,6|1,Example|Backup,Approved\n"
        )
        preview = preview_inventory_csv(content)
        self.assertTrue(preview["valid"])
        self.assertEqual(
            tuple(preview["rows"][0][field] for field in CSV_REQUIRED_FIELDS),
            (
                "HQ",
                "Corp",
                "AA:BB:CC:00:00:01",
                "Example",
                "corporate",
                True,
            ),
        )
        self.assertEqual(
            preview["rows"][0]["allowed_encryption_codes"], [4, 5]
        )
        self.assertEqual(preview["rows"][0]["allowed_channels"], [1, 6])

    def test_missing_required_header_and_duplicate_bssid_are_rejected(self):
        missing = "ssid,bssid,vendor,role,approved\nCorp,AA:BB:CC:00:00:01,X,r,true\n"
        with self.assertRaises(BackendError) as raised:
            preview_inventory_csv(missing)
        self.assertEqual(raised.exception.code, "invalid_inventory_csv")

        duplicate = (
            CSV_HEADER
            + "HQ,Corp,AA:BB:CC:00:00:01,X,r,true,,,,,,\n"
            + "HQ,Corp,aa-bb-cc-00-00-01,X,r,true,,,,,,\n"
        )
        result = preview_inventory_csv(duplicate)
        self.assertFalse(result["valid"])
        self.assertEqual(result["errors"][0]["code"], "duplicate_inventory_bssid")

    def test_export_is_stable_and_neutralizes_spreadsheet_formulas(self):
        dangerous = (
            CSV_HEADER
            + "=site,-ssid,AA:BB:CC:00:00:01,Example,role,true,"
            "+name,false,5,false,1,Example,@note\n"
        )
        profile = AssuranceProfile.from_inventory_preview(
            preview_inventory_csv(dangerous),
            coverage_mode="partial",
        )
        first = export_inventory_csv(profile)
        second = export_inventory_csv(profile)
        self.assertEqual(first, second)
        parsed = list(csv.DictReader(io.StringIO(first)))[0]
        self.assertEqual(parsed["site"], "'=site")
        self.assertEqual(parsed["ssid"], "'-ssid")
        self.assertEqual(parsed["name"], "'+name")
        self.assertEqual(parsed["notes"], "'@note")


class AssuranceProfileTests(unittest.TestCase):
    def _profile(self, coverage_mode="authoritative"):
        return AssuranceProfile(
            coverage_mode=coverage_mode,
            assets=(
                _asset(
                    "AA:BB:CC:00:00:01",
                    "Corp",
                    required=True,
                    allowed_vendors=("Example",),
                ),
                _asset(
                    "AA:BB:CC:00:00:02",
                    "Guest",
                    required=True,
                    encryption=(4,),
                ),
                _asset(
                    "AA:BB:CC:00:00:03",
                    "IoT",
                    vendor="Expected",
                    allowed_vendors=("Expected",),
                    channels=(11,),
                ),
                _asset(
                    "AA:BB:CC:00:00:04",
                    "Corp",
                    approved=False,
                    encryption=(),
                    wps_allowed=None,
                    channels=(),
                ),
            ),
        )

    def _snapshot(self, unknown_ssid="Other"):
        return {
            "access_points": [
                _access_point(
                    1,
                    "AA:BB:CC:00:00:01",
                    "Corp",
                    encryption=4,
                    wps=True,
                    channel=6,
                    vendor="Other",
                ),
                _access_point(
                    3,
                    "AA:BB:CC:00:00:03",
                    "Wrong-IoT",
                    channel=11,
                    vendor="Unknown",
                ),
                _access_point(
                    4,
                    "AA:BB:CC:00:00:04",
                    "Corp",
                ),
                _access_point(
                    5,
                    "AA:BB:CC:00:00:05",
                    unknown_ssid,
                ),
            ]
        }

    def test_profile_is_deeply_immutable_and_round_trips(self):
        profile = self._profile()
        self.assertIsInstance(profile.assets, tuple)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            profile.coverage_mode = "partial"
        restored = AssuranceProfile.from_dict(profile.to_dict())
        self.assertEqual(restored, profile)
        self.assertEqual(restored.profile_id, profile.profile_id)
        self.assertEqual(
            restored.to_dict()["inventory"]["coverage_mode"],
            "authoritative",
        )
        self.assertEqual(
            restored.to_dict()["policy"]["registry_version"], "fixed_v1"
        )

    def test_invalid_mutable_policy_values_are_rejected(self):
        value = self._profile().to_dict()
        value.pop("profile_id")
        value["inventory"]["assets"][0]["allowed_channels"] = "1|6"
        with self.assertRaises(BackendError) as raised:
            AssuranceProfile.from_dict(value)
        self.assertEqual(
            raised.exception.code, "invalid_assurance_profile"
        )

    def test_fixed_registries_and_certainty_contract(self):
        self.assertEqual(
            set(POLICY_DEVIATION_REGISTRY),
            {
                "asset_not_in_authoritative_inventory",
                "required_asset_missing",
                "ssid_not_allowed",
                "encryption_code_not_allowed",
                "wps_not_allowed",
                "channel_not_allowed",
                "vendor_not_allowed",
            },
        )
        self.assertEqual(
            set(SECURITY_FINDING_REGISTRY),
            {
                "unauthorized_bssid_advertising_protected_ssid",
                "protected_ssid_encryption_violation",
                "wps_enabled_where_forbidden",
            },
        )
        capabilities = assurance_profile_capabilities()
        self.assertEqual(
            tuple(capabilities["certainty_levels"]), CERTAINTY_LEVELS
        )
        self.assertEqual(
            capabilities["coverage_modes"], ["partial", "authoritative"]
        )
        self.assertFalse(capabilities["observed_changes_have_severity"])

    def test_all_fixed_policy_deviations_and_security_findings(self):
        result = evaluate_assurance_profile(
            self._profile(),
            self._snapshot(),
            {"status": "comparable"},
        )
        self.assertEqual(
            {item["rule_id"] for item in result["policy_deviations"]},
            set(POLICY_DEVIATION_REGISTRY),
        )
        self.assertEqual(
            {item["rule_id"] for item in result["security_findings"]},
            set(SECURITY_FINDING_REGISTRY),
        )
        self.assertTrue(
            all(
                re.match(r"^finding_[0-9a-f]{12}$", item["finding_id"])
                for item in result["security_findings"]
            )
        )
        self.assertTrue(
            all("severity" not in item for item in result["observed_changes"])
        )
        self.assertTrue(
            all(
                set(item["before_after"]) == {"before", "after"}
                for item in result["observed_changes"]
            )
        )
        self.assertTrue(
            {
                item["certainty"] for item in result["observed_changes"]
            }.issubset(set(CERTAINTY_LEVELS))
        )
        vendor_deviations = [
            item
            for item in result["policy_deviations"]
            if item["rule_id"] == "vendor_not_allowed"
        ]
        self.assertEqual(len(vendor_deviations), 1)
        self.assertEqual(
            vendor_deviations[0]["subject_id"], "ap_000000000001"
        )

    def test_partial_inventory_and_noncomparable_absence_are_conservative(self):
        partial = evaluate_assurance_profile(
            self._profile("partial"),
            self._snapshot(unknown_ssid="Corp"),
            {"status": "comparable"},
        )
        unknown_id = "ap_000000000005"
        self.assertFalse(
            any(
                item["subject_id"] == unknown_id
                for item in partial["policy_deviations"]
            )
        )
        self.assertFalse(
            any(
                item["subject_id"] == unknown_id
                for item in partial["security_findings"]
            )
        )
        unknown_change = next(
            item
            for item in partial["observed_changes"]
            if item["subject_id"] == unknown_id
        )
        self.assertEqual(unknown_change["certainty"], "limited")

        not_comparable = evaluate_assurance_profile(
            self._profile(),
            self._snapshot(),
            {"status": "not_comparable"},
        )
        self.assertFalse(
            any(
                item["rule_id"] == "required_asset_missing"
                for item in not_comparable["policy_deviations"]
            )
        )
        missing = next(
            item
            for item in not_comparable["observed_changes"]
            if item["change_type"] == "required_asset_missing"
        )
        self.assertEqual(missing["certainty"], "limited")


if __name__ == "__main__":
    unittest.main()
