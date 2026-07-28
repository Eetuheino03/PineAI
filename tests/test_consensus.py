import copy
import datetime
import hashlib
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "projects" / "PineAI" / "src" / "assets"
sys.path.insert(0, str(ASSETS))

from pineai_backend.assurance import (  # noqa: E402
    evaluate_comparability,
    normalize_measurement_context,
    resolve_assets,
)
from pineai_backend.consensus import (  # noqa: E402
    CONSENSUS_POLICY_ID,
    UNBOUNDED_SOURCE_AGE_LIMITATION,
    build_consensus_baseline,
    consensus_capabilities,
)
from pineai_backend.errors import BackendError  # noqa: E402


FIXTURE = Path(__file__).resolve().parent / "fixtures" / "recon_basic.json"
MEASUREMENT_PROFILE_ID = (
    "mprofile_123e4567-e89b-42d3-a456-426614174000"
)
MEASUREMENT_PROFILE_VERSION_ID = "mprofile_r0007"
MEASUREMENT_PROFILE_DIGEST = "a" * 64


def _asset(number, ssid="Corp", channel=1, signal=-40):
    suffix = "{0:02X}".format(number)
    return {
        "asset_id": "ap_{0:012x}".format(number),
        "network_id": "network_{0:012x}".format(number),
        "evidence_id": "evidence_{0:012x}".format(number),
        "bssid": "02:00:00:00:00:{0}".format(suffix),
        "ssid": ssid,
        "hidden": False,
        "encryption": 5,
        "wps": False,
        "channel": channel,
        "band": "2.4",
        "signal": signal,
        "vendor": "Example",
        "client_count": 1,
    }


def _snapshot(number, assets, observed_at=None, context=None):
    if observed_at is None:
        observed_at = (
            datetime.datetime(2026, 7, 28, tzinfo=datetime.timezone.utc)
            + datetime.timedelta(hours=number)
        ).isoformat().replace("+00:00", "Z")
    profile = {
        "location_id": "site-a",
        "measurement_point_id": "lobby",
        "scan_profile_id": "full",
        "radio_profile_id": "mk7",
        "interface": "wlan1mon",
        "declared_coverage": ["2.4"],
        "declared_channels_scanned": [1, 6, 11],
        "scan_time": 180,
    }
    if context:
        profile.update(context)
    digest = hashlib.sha256(
        "snapshot-{0}".format(number).encode("ascii")
    ).hexdigest()
    return {
        "schema_version": "1.1",
        "snapshot_id": "snapshot_{0:016x}".format(number),
        "snapshot_digest": digest,
        "observed_at": observed_at,
        "comparability_profile": profile,
        "access_points": copy.deepcopy(assets),
    }


class ReconCanonicalizationTests(unittest.TestCase):
    def _fixture(self):
        return json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_rejects_missing_invalid_and_duplicate_bssids(self):
        for bad_value in (None, "", "not-a-mac", "AA:BB:CC:DD:EE"):
            scan = self._fixture()
            scan["APResults"][0]["bssid"] = bad_value
            with self.subTest(value=bad_value):
                with self.assertRaises(BackendError) as raised:
                    resolve_assets(scan, {}, b"x" * 32)
                self.assertEqual(raised.exception.code, "invalid_recon")

        duplicate = self._fixture()
        duplicate["APResults"][1]["bssid"] = duplicate["APResults"][0]["bssid"]
        with self.assertRaises(BackendError) as raised:
            resolve_assets(duplicate, {}, b"x" * 32)
        self.assertEqual(raised.exception.code, "invalid_recon")

    def test_source_array_order_does_not_change_snapshot_identity(self):
        first_scan = self._fixture()
        second_scan = copy.deepcopy(first_scan)
        second_scan["APResults"].reverse()
        for access_point in second_scan["APResults"]:
            access_point["clients"].reverse()
        second_scan["OutOfRangeClientResults"].reverse()
        second_scan["UnassociatedClientResults"].reverse()
        metadata = {
            "scan_id": "scan-order",
            "date": "2026-07-28T10:00:00Z",
            "scan_time": 180,
            "coverage": ["2.4"],
        }
        first = resolve_assets(first_scan, metadata, b"x" * 32)
        second = resolve_assets(second_scan, metadata, b"x" * 32)
        self.assertEqual(first["snapshot_id"], second["snapshot_id"])
        self.assertEqual(first["snapshot_digest"], second["snapshot_digest"])
        self.assertEqual(first["access_points"], second["access_points"])
        self.assertEqual(first["evidence"], second["evidence"])


class MeasurementProfileProvenanceTests(unittest.TestCase):
    def _scan(self):
        return json.loads(FIXTURE.read_text(encoding="utf-8"))

    def _metadata(self, scan_id, provenance=True):
        context = {
            "location_id": "site-a",
            "measurement_point_id": "lobby",
            "scan_profile_id": "full",
            "radio_profile_id": "mk7",
            "interface": "wlan1mon",
            "declared_channels": [1, 6, 11],
            "declared_bands": ["2.4"],
        }
        if provenance:
            context.update(
                {
                    "measurement_profile_id": MEASUREMENT_PROFILE_ID,
                    "measurement_profile_version_id": (
                        MEASUREMENT_PROFILE_VERSION_ID
                    ),
                    "measurement_profile_digest": (
                        MEASUREMENT_PROFILE_DIGEST
                    ),
                }
            )
        return {
            "scan_id": scan_id,
            "date": "2026-07-28T12:00:00Z",
            "scan_time": 180,
            "coverage": ["2.4"],
            "measurement_context": context,
        }

    def _resolve(self, scan_id, provenance=True):
        return resolve_assets(
            self._scan(),
            self._metadata(scan_id, provenance=provenance),
            b"p" * 32,
        )

    def test_provenance_is_normalized_and_pinned_to_snapshot(self):
        snapshot = self._resolve("scan-a")
        context = snapshot["scan_metadata"]["measurement_context"]
        profile = snapshot["comparability_profile"]
        for field, value in (
            ("measurement_profile_id", MEASUREMENT_PROFILE_ID),
            (
                "measurement_profile_version_id",
                MEASUREMENT_PROFILE_VERSION_ID,
            ),
            (
                "measurement_profile_digest",
                MEASUREMENT_PROFILE_DIGEST,
            ),
        ):
            self.assertEqual(context[field], value)
            self.assertEqual(profile[field], value)

        legacy_alias = normalize_measurement_context(
            {
                "measurement_profile_id": MEASUREMENT_PROFILE_ID,
                "measurement_profile_revision": 7,
                "measurement_profile_digest": (
                    MEASUREMENT_PROFILE_DIGEST.upper()
                ),
            }
        )
        self.assertEqual(
            legacy_alias["measurement_profile_version_id"],
            MEASUREMENT_PROFILE_VERSION_ID,
        )
        self.assertEqual(
            legacy_alias["measurement_profile_digest"],
            MEASUREMENT_PROFILE_DIGEST,
        )

    def test_invalid_or_conflicting_provenance_is_rejected(self):
        invalid_values = (
            {"measurement_profile_id": "mprofile_bad"},
            {"measurement_profile_version_id": "mprofile_r7"},
            {"measurement_profile_digest": "z" * 64},
            {"measurement_profile_revision": 0},
            {
                "measurement_profile_version_id": "mprofile_r0007",
                "measurement_profile_revision": 8,
            },
        )
        for value in invalid_values:
            with self.subTest(value=value):
                with self.assertRaises(BackendError) as raised:
                    normalize_measurement_context(value)
                self.assertEqual(
                    raised.exception.code, "invalid_scan_metadata"
                )

    def test_matching_mismatching_and_legacy_comparability(self):
        baseline = self._resolve("scan-a")
        matching = self._resolve("scan-b")
        result = evaluate_comparability(baseline, matching)
        self.assertEqual(result["status"], "comparable")
        self.assertEqual(result["quality_model_version"], "1.1")
        self.assertTrue(result["measurement_profile_provenance_match"])
        self.assertTrue(result["measurement_profile_id_match"])
        self.assertTrue(result["measurement_profile_version_id_match"])
        self.assertTrue(result["measurement_profile_digest_match"])

        mismatching = copy.deepcopy(matching)
        mismatching["comparability_profile"][
            "measurement_profile_version_id"
        ] = "mprofile_r0008"
        result = evaluate_comparability(baseline, mismatching)
        self.assertEqual(result["status"], "partially_comparable")
        self.assertFalse(result["absence_findings_allowed"])
        self.assertFalse(result["measurement_profile_provenance_match"])
        self.assertIn(
            "measurement_profile_version_id_mismatch", result["reasons"]
        )

        legacy_baseline = self._resolve("scan-legacy-a", provenance=False)
        legacy_current = self._resolve("scan-legacy-b", provenance=False)
        legacy_context = legacy_baseline["scan_metadata"][
            "measurement_context"
        ]
        self.assertNotIn("measurement_profile_id", legacy_context)
        self.assertNotIn(
            "measurement_profile_version_id", legacy_context
        )
        self.assertNotIn("measurement_profile_digest", legacy_context)
        legacy_result = evaluate_comparability(
            legacy_baseline, legacy_current
        )
        self.assertEqual(legacy_result["status"], "comparable")
        self.assertIsNone(
            legacy_result["measurement_profile_provenance_match"]
        )

        mixed_result = evaluate_comparability(legacy_baseline, matching)
        self.assertEqual(mixed_result["status"], "partially_comparable")
        self.assertIn(
            "measurement_profile_provenance_incomplete",
            mixed_result["reasons"],
        )


class ConsensusTests(unittest.TestCase):
    def _five_snapshots(self):
        result = []
        for index in range(5):
            assets = [
                _asset(
                    1,
                    channel=1 if index < 3 else 6,
                    signal=-40 - (2 * index),
                )
            ]
            if index < 2:
                assets.append(_asset(2, ssid="Guest", signal=-60))
            if index == 0:
                assets.append(_asset(3, ssid="IoT", signal=-70))
            if index < 4:
                assets.append(
                    _asset(
                        4,
                        ssid="Stable" if index < 3 else "Changed",
                        signal=-50,
                    )
                )
            result.append(_snapshot(index + 1, assets))
        return result

    def test_strict_80_presence_attributes_channels_and_signal(self):
        model = build_consensus_baseline(self._five_snapshots())
        self.assertEqual(model["consensus_policy"]["policy_id"], CONSENSUS_POLICY_ID)
        self.assertEqual(model["consensus_policy"]["required_count"], 4)
        self.assertEqual(
            model["summary"],
            {
                "asset_count": 4,
                "core_asset_count": 2,
                "recurring_asset_count": 1,
                "singleton_asset_count": 1,
            },
        )
        by_id = {item["asset_id"]: item for item in model["assets"]}
        self.assertEqual(by_id["ap_000000000001"]["presence"]["classification"], "core")
        self.assertEqual(
            by_id["ap_000000000002"]["presence"]["classification"],
            "recurring",
        )
        self.assertEqual(
            by_id["ap_000000000003"]["presence"]["classification"],
            "singleton",
        )
        ambiguous = by_id["ap_000000000004"]["attributes"]["ssid"]
        self.assertEqual(ambiguous["status"], "ambiguous")
        self.assertIsNone(ambiguous["value"])
        core = by_id["ap_000000000001"]
        self.assertEqual(core["channels"]["observed_values"], [1, 6])
        self.assertEqual(core["signal"]["median_dbm"], -44)
        self.assertEqual(
            core["signal"]["median_absolute_deviation_db"], 2
        )

    def test_result_is_order_independent(self):
        snapshots = self._five_snapshots()
        first = build_consensus_baseline(snapshots)
        second = build_consensus_baseline(list(reversed(snapshots)))
        self.assertEqual(first, second)

    def test_scan_count_context_and_timestamp_validation(self):
        scans = self._five_snapshots()
        for invalid in (scans[:1], scans + [_snapshot(9, [_asset(9)])]):
            with self.assertRaises(BackendError) as raised:
                build_consensus_baseline(invalid)
            self.assertEqual(raised.exception.code, "invalid_consensus_input")

        mismatch = copy.deepcopy(scans[:2])
        mismatch[1]["comparability_profile"]["location_id"] = "site-b"
        with self.assertRaises(BackendError) as raised:
            build_consensus_baseline(mismatch)
        self.assertEqual(raised.exception.code, "consensus_context_mismatch")

        mixed_time = copy.deepcopy(scans[:2])
        mixed_time[0]["observed_at"] = None
        with self.assertRaises(BackendError) as raised:
            build_consensus_baseline(mixed_time)
        self.assertEqual(raised.exception.code, "consensus_time_mismatch")

        unknown_time = copy.deepcopy(scans[:2])
        for item in unknown_time:
            item["observed_at"] = None
        self.assertEqual(
            build_consensus_baseline(unknown_time)["observation_window"]["status"],
            "unknown",
        )

    def test_source_age_override_is_bounded_or_explicitly_unbounded(self):
        scans = self._five_snapshots()
        with self.assertRaises(BackendError) as raised:
            build_consensus_baseline(scans, max_source_age_hours=1)
        self.assertEqual(
            raised.exception.code, "consensus_time_window_exceeded"
        )
        unbounded = build_consensus_baseline(
            scans, max_source_age_hours=None
        )
        self.assertIsNone(unbounded["max_source_age_hours"])
        self.assertEqual(
            unbounded["limitation_codes"],
            [UNBOUNDED_SOURCE_AGE_LIMITATION],
        )
        for invalid in (0, 169, True, "24"):
            with self.subTest(value=invalid):
                with self.assertRaises(BackendError) as raised:
                    build_consensus_baseline(
                        scans, max_source_age_hours=invalid
                    )
                self.assertEqual(
                    raised.exception.code, "invalid_max_source_age"
                )

    def test_capabilities_publish_operator_limits(self):
        policy = consensus_capabilities()["policies"][0]
        self.assertEqual(policy["default_max_source_age_hours"], 24)
        self.assertEqual(policy["minimum_max_source_age_hours"], 1)
        self.assertEqual(policy["maximum_max_source_age_hours"], 168)
        self.assertTrue(policy["unbounded_source_age_supported"])

    def test_consensus_requires_matching_measurement_profile_provenance(self):
        context = {
            "measurement_profile_id": MEASUREMENT_PROFILE_ID,
            "measurement_profile_version_id": (
                MEASUREMENT_PROFILE_VERSION_ID
            ),
            "measurement_profile_digest": MEASUREMENT_PROFILE_DIGEST,
        }
        scans = [
            _snapshot(1, [_asset(1)], context=context),
            _snapshot(2, [_asset(1)], context=context),
        ]
        model = build_consensus_baseline(scans)
        for field, value in context.items():
            self.assertEqual(
                model["measurement_context"][field], value
            )

        mismatching = copy.deepcopy(scans)
        mismatching[1]["comparability_profile"][
            "measurement_profile_digest"
        ] = "b" * 64
        with self.assertRaises(BackendError) as raised:
            build_consensus_baseline(mismatching)
        self.assertEqual(
            raised.exception.code, "consensus_context_mismatch"
        )


if __name__ == "__main__":
    unittest.main()
