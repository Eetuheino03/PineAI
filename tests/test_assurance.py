import copy
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "projects" / "PineAI" / "src" / "assets"
sys.path.insert(0, str(ASSETS))

from pineai_backend.assurance import (  # noqa: E402
    RULE_REGISTRY,
    build_ai_payload,
    compare_snapshots,
    evaluate_comparability,
    evaluate_finding_rules,
    resolve_assets,
)
from pineai_backend.errors import BackendError  # noqa: E402


FIXTURE = Path(__file__).resolve().parent / "fixtures" / "recon_basic.json"


def load_fixture():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


class AssuranceTests(unittest.TestCase):
    def setUp(self):
        self.secret = b"a" * 32
        self.metadata = {
            "scan_id": "scan-1",
            "date": "2026-07-27T12:00:00Z",
            "scan_time": 180,
            "coverage": ["2.4"],
            "location_id": "loc-1",
            "measurement_point_id": "point-1",
            "scan_profile_id": "full-sweep-v1",
            "radio_profile_id": "mk7-radio-a",
            "interface": "wlan1mon",
            "declared_channels": [1, 6, 11],
        }

    def resolve(self, scan=None, metadata=None):
        return resolve_assets(
            scan if scan is not None else load_fixture(),
            metadata if metadata is not None else self.metadata,
            self.secret,
            oui_database={"AABBCC": "Example Networks"},
        )

    def test_resolution_is_deterministic_and_has_local_evidence(self):
        first = self.resolve()
        second = self.resolve()
        self.assertEqual(first, second)
        self.assertEqual(len(first["access_points"]), 3)
        self.assertEqual(len(first["evidence"]), 3)
        self.assertEqual(
            {item["evidence_id"] for item in first["access_points"]},
            {item["evidence_id"] for item in first["evidence"]},
        )
        hidden = next(item for item in first["networks"] if item["hidden"])
        self.assertEqual(len(hidden["asset_ids"]), 1)
        self.assertIn("DE:AD:BE:EF:00:01", hidden["bssids"])

    def test_scan_id_and_input_format_do_not_leak_into_asset_ids(self):
        first = self.resolve()
        metadata = dict(self.metadata, scan_id="another-scan")
        second = self.resolve(metadata=metadata)
        self.assertEqual(
            [item["asset_id"] for item in first["access_points"]],
            [item["asset_id"] for item in second["access_points"]],
        )
        self.assertNotEqual(first["snapshot_id"], second["snapshot_id"])

    def test_comparability_states(self):
        baseline = self.resolve()
        exact = evaluate_comparability(baseline, self.resolve())
        self.assertEqual(exact["status"], "comparable")
        self.assertTrue(exact["scan_profile_match"])
        self.assertTrue(exact["radio_profile_match"])
        self.assertTrue(exact["interface_match"])
        unknown = self.resolve(metadata={"scan_id": "x", "coverage": ["2.4"]})
        self.assertEqual(
            evaluate_comparability(baseline, unknown)["status"],
            "partially_comparable",
        )
        wrong_band = self.resolve(
            metadata=dict(self.metadata, scan_id="x", coverage=["5"])
        )
        result = evaluate_comparability(baseline, wrong_band)
        self.assertEqual(result["status"], "not_comparable")
        self.assertFalse(result["lifecycle_updates_allowed"])

    def test_unknown_measurement_context_prevents_comparable_status(self):
        baseline = self.resolve()
        no_context_meta = {
            "scan_id": "scan-no-ctx",
            "scan_time": 180,
            "coverage": ["2.4"],
            "declared_channels": [1, 6, 11],
        }
        no_context_scan = self.resolve(metadata=no_context_meta)
        result = evaluate_comparability(baseline, no_context_scan)
        self.assertEqual(result["status"], "partially_comparable")
        self.assertFalse(result["absence_findings_allowed"])
        self.assertIn("measurement_context_unknown", result["reasons"])

    def test_location_and_point_mismatches_cause_not_comparable(self):
        baseline = self.resolve()
        loc_mismatch_meta = dict(self.metadata, scan_id="loc-mismatch", location_id="loc-2")
        loc_mismatch_scan = self.resolve(metadata=loc_mismatch_meta)
        res1 = evaluate_comparability(baseline, loc_mismatch_scan)
        self.assertEqual(res1["status"], "not_comparable")
        self.assertIn("location_mismatch", res1["reasons"])

        point_mismatch_meta = dict(self.metadata, scan_id="pt-mismatch", measurement_point_id="point-2")
        point_mismatch_scan = self.resolve(metadata=point_mismatch_meta)
        res2 = evaluate_comparability(baseline, point_mismatch_scan)
        self.assertEqual(res2["status"], "not_comparable")
        self.assertIn("measurement_point_mismatch", res2["reasons"])

    def test_profile_and_interface_mismatch_policy_is_conservative(self):
        baseline_metadata = dict(
            self.metadata,
            scan_profile_id="full-sweep-v1",
            radio_profile_id="mk7-radio-a",
            interface="wlan1mon",
        )
        baseline = self.resolve(metadata=baseline_metadata)

        scan_profile_scan = self.resolve(
            metadata=dict(
                baseline_metadata,
                scan_id="scan-profile-mismatch",
                scan_profile_id="focused-sweep-v2",
            )
        )
        scan_profile_result = evaluate_comparability(
            baseline, scan_profile_scan
        )
        self.assertEqual(scan_profile_result["status"], "not_comparable")
        self.assertFalse(scan_profile_result["scan_profile_match"])
        self.assertIn(
            "scan_profile_mismatch", scan_profile_result["reasons"]
        )

        interface_scan = self.resolve(
            metadata=dict(
                baseline_metadata,
                scan_id="interface-mismatch",
                interface="wlan2mon",
            )
        )
        interface_result = evaluate_comparability(baseline, interface_scan)
        self.assertEqual(interface_result["status"], "not_comparable")
        self.assertFalse(interface_result["interface_match"])
        self.assertIn("interface_mismatch", interface_result["reasons"])

        radio_scan = self.resolve(
            metadata=dict(
                baseline_metadata,
                scan_id="radio-profile-mismatch",
                radio_profile_id="mk7-radio-b",
            )
        )
        radio_result = evaluate_comparability(baseline, radio_scan)
        self.assertEqual(radio_result["status"], "partially_comparable")
        self.assertFalse(radio_result["radio_profile_match"])
        self.assertFalse(radio_result["absence_findings_allowed"])
        self.assertTrue(radio_result["positive_findings_allowed"])
        self.assertIn("radio_profile_mismatch", radio_result["reasons"])

    def test_unknown_profiles_force_partial_comparison(self):
        baseline = self.resolve()
        reason_by_field = {
            "scan_profile_id": "scan_profile_unknown",
            "radio_profile_id": "radio_profile_unknown",
            "interface": "interface_unknown",
        }
        for field, reason in reason_by_field.items():
            current_metadata = dict(self.metadata, scan_id="missing-" + field)
            current_metadata.pop(field)
            result = evaluate_comparability(
                baseline, self.resolve(metadata=current_metadata)
            )
            self.assertEqual(result["status"], "partially_comparable", field)
            self.assertFalse(result["absence_findings_allowed"], field)
            self.assertIn(reason, result["reasons"], field)

            baseline_metadata = dict(self.metadata, scan_id="baseline-missing-" + field)
            baseline_metadata.pop(field)
            both_missing = evaluate_comparability(
                self.resolve(metadata=baseline_metadata),
                self.resolve(metadata=baseline_metadata),
            )
            self.assertEqual(
                both_missing["status"], "partially_comparable", field
            )
            self.assertIn(reason, both_missing["reasons"], field)

    def test_radio_profile_mismatch_keeps_positive_changes_but_suppresses_absence(self):
        baseline = self.resolve()
        changed_scan = load_fixture()
        changed_scan["APResults"].pop()
        changed_scan["APResults"][0]["channel"] = 11
        current = self.resolve(
            changed_scan,
            dict(
                self.metadata,
                scan_id="radio-profile-partial",
                radio_profile_id="mk7-radio-b",
            ),
        )
        diff = compare_snapshots(baseline, current)
        findings = evaluate_finding_rules(
            "assessment_test", baseline, current, diff, self.secret
        )
        rules = {finding["rule_id"] for finding in findings}
        self.assertEqual(
            diff["comparability"]["status"], "partially_comparable"
        )
        self.assertIn("channel_changed", rules)
        self.assertNotIn("access_point_missing", rules)

    def test_measurement_context_forms_and_declared_bands_are_unambiguous(self):
        conflicting = dict(
            self.metadata,
            measurement_context={
                "location_id": "loc-1",
                "measurement_point_id": "point-1",
            },
        )
        with self.assertRaises(BackendError) as raised:
            self.resolve(metadata=conflicting)
        self.assertEqual(raised.exception.code, "invalid_scan_metadata")

        nested_metadata = {
            "scan_id": "nested-context",
            "scan_time": 180,
            "measurement_context": {
                "location_id": "loc-1",
                "measurement_point_id": "point-1",
                "scan_profile_id": "full-sweep-v1",
                "radio_profile_id": "mk7-radio-a",
                "interface": "wlan1mon",
                "declared_channels": [1, 6, 11],
                "declared_bands": ["2.4"],
            },
        }
        snapshot = self.resolve(metadata=nested_metadata)
        self.assertEqual(
            snapshot["comparability_profile"]["declared_coverage"], ["2.4"]
        )
        self.assertEqual(
            snapshot["comparability_profile"]["effective_coverage"], ["2.4"]
        )

    def test_scan_timestamps_are_strict_rfc3339_and_ordered(self):
        metadata = dict(
            self.metadata,
            started_at="2026-07-27T14:00:00.123456789+02:00",
            completed_at="2026-07-27T12:00:01.123456789Z",
        )
        snapshot = self.resolve(metadata=metadata)
        self.assertEqual(
            snapshot["observed_at"], metadata["completed_at"]
        )

        for field, value in (
            ("date", "not-rfc3339"),
            ("started_at", "2026-07-27 12:00:00Z"),
            ("completed_at", "2026-02-30T12:00:00Z"),
            ("completed_at", "2026-07-27T12:00:00+25:00"),
        ):
            with self.subTest(field=field, value=value):
                invalid = dict(self.metadata)
                invalid[field] = value
                with self.assertRaises(BackendError) as raised:
                    self.resolve(metadata=invalid)
                self.assertEqual(
                    raised.exception.code, "invalid_scan_metadata"
                )

        reversed_times = dict(
            self.metadata,
            started_at="2026-07-27T12:00:01Z",
            completed_at="2026-07-27T12:00:00Z",
        )
        with self.assertRaises(BackendError) as raised:
            self.resolve(metadata=reversed_times)
        self.assertEqual(raised.exception.code, "invalid_scan_metadata")

    def test_undeclared_channels_forces_partially_comparable(self):
        baseline = self.resolve()
        no_channels_meta = {
            "scan_id": "scan-no-chan",
            "scan_time": 180,
            "coverage": ["2.4"],
            "location_id": "loc-1",
            "measurement_point_id": "point-1",
            "scan_profile_id": "full-sweep-v1",
            "radio_profile_id": "mk7-radio-a",
            "interface": "wlan1mon",
        }
        no_channels_scan = self.resolve(metadata=no_channels_meta)
        result = evaluate_comparability(baseline, no_channels_scan)
        self.assertEqual(result["status"], "partially_comparable")
        self.assertIsNone(result["channel_coverage_ratio"])
        self.assertFalse(result["absence_findings_allowed"])
        self.assertIn("channel_coverage_unknown", result["reasons"])

    def test_known_ssid_new_bssid_does_not_duplicate_generic_rule(self):
        baseline = self.resolve()
        scan = load_fixture()
        scan["APResults"].append(
            {
                "ssid": "Example-Corp",
                "bssid": "AA:BB:CC:00:00:03",
                "encryption": 5,
                "channel": 11,
            }
        )
        current = self.resolve(scan, dict(self.metadata, scan_id="scan-2"))
        diff = compare_snapshots(baseline, current)
        findings = evaluate_finding_rules(
            "assessment_test", baseline, current, diff, self.secret
        )
        new_subject = next(
            item["asset_id"]
            for item in current["access_points"]
            if item["bssid"] == "AA:BB:CC:00:00:03"
        )
        subject_rules = [
            item["rule_id"]
            for item in findings
            if item["subject_id"] == new_subject
        ]
        self.assertEqual(subject_rules, ["known_ssid_new_bssid"])

    def test_all_eight_rules_are_reachable(self):
        self.assertEqual(len(RULE_REGISTRY), 8)
        baseline_scan = load_fixture()
        baseline_scan["APResults"] = [baseline_scan["APResults"][0]]
        baseline = self.resolve(baseline_scan)

        changed_scan = copy.deepcopy(baseline_scan)
        changed_scan["APResults"][0].update(
            {
                "ssid": "Changed-Network",
                "encryption": 7,
                "wps": 1,
                "channel": 6,
            }
        )
        current = self.resolve(
            changed_scan, dict(self.metadata, scan_id="changed")
        )
        diff = compare_snapshots(baseline, current)
        rules = {
            item["rule_id"]
            for item in evaluate_finding_rules(
                "assessment_test", baseline, current, diff, self.secret
            )
        }
        self.assertTrue(
            {"ssid_changed", "encryption_changed", "wps_enabled", "channel_changed"}
            .issubset(rules)
        )

        removed = self.resolve(
            {"APResults": [], "OutOfRangeClientResults": [], "UnassociatedClientResults": []},
            dict(self.metadata, scan_id="empty"),
        )
        # Empty vs non-empty is deliberately not comparable and cannot mutate state.
        removed_diff = compare_snapshots(baseline, removed)
        self.assertEqual(removed_diff["comparability"]["status"], "not_comparable")
        self.assertEqual(
            evaluate_finding_rules(
                "assessment_test", baseline, removed, removed_diff, self.secret
            ),
            [],
        )

    def test_missing_ap_requires_comparable_nonempty_scan(self):
        baseline_scan = load_fixture()
        baseline = self.resolve(baseline_scan)
        current_scan = load_fixture()
        current_scan["APResults"].pop()
        current = self.resolve(
            current_scan, dict(self.metadata, scan_id="scan-2")
        )
        diff = compare_snapshots(baseline, current)
        rules = [
            item["rule_id"]
            for item in evaluate_finding_rules(
                "assessment_test", baseline, current, diff, self.secret
            )
        ]
        self.assertIn("access_point_missing", rules)

        partial = self.resolve(
            current_scan, {"scan_id": "scan-3", "coverage": ["2.4"]}
        )
        partial_diff = compare_snapshots(baseline, partial)
        self.assertEqual(partial_diff["comparability"]["status"], "partially_comparable")
        partial_rules = [
            item["rule_id"]
            for item in evaluate_finding_rules(
                "assessment_test", baseline, partial, partial_diff, self.secret
            )
        ]
        self.assertNotIn("access_point_missing", partial_rules)

    def test_cloud_payload_is_privacy_filtered_and_ssid_is_opt_in(self):
        baseline = self.resolve()
        scan = load_fixture()
        scan["APResults"].append(
            {
                "ssid": "Example-Corp",
                "bssid": "AA:BB:CC:00:00:03",
                "encryption": 5,
                "channel": 11,
            }
        )
        current = self.resolve(scan, dict(self.metadata, scan_id="scan-2"))
        diff = compare_snapshots(baseline, current)
        findings = evaluate_finding_rules(
            "assessment_test", baseline, current, diff, self.secret
        )
        comparison = {
            "comparison_id": "comparison_test",
            "comparability": diff["comparability"],
            "summary": diff["summary"],
        }
        hidden = build_ai_payload(
            {
                "assessment_id": "assessment_test",
                "name": "Office",
                "location": "Helsinki",
                "notes": "never send",
            },
            comparison,
            findings,
            "en",
            False,
        )
        serialized = json.dumps(hidden)
        self.assertNotIn("AA:BB:CC", serialized)
        self.assertNotIn("Example-Corp", serialized)
        self.assertNotIn("never send", serialized)
        self.assertNotIn("measurement_profile_id", serialized)
        self.assertNotIn("measurement_profile_digest", serialized)
        self.assertNotIn('"coverage"', serialized)
        self.assertNotIn('"scan_time"', serialized)
        self.assertEqual(
            hidden["comparison"]["comparability"]["status"],
            diff["comparability"]["status"],
        )

        shared = build_ai_payload(
            {"assessment_id": "assessment_test", "name": "Office", "location": ""},
            comparison,
            findings,
            "fi",
            True,
        )
        self.assertIn("Example-Corp", json.dumps(shared))

        changed_scan = load_fixture()
        changed_scan["APResults"][0]["ssid"] = "Private-New-SSID"
        changed = self.resolve(
            changed_scan, dict(self.metadata, scan_id="ssid-change")
        )
        changed_diff = compare_snapshots(baseline, changed)
        changed_findings = evaluate_finding_rules(
            "assessment_test", baseline, changed, changed_diff, self.secret
        )
        hidden_change = build_ai_payload(
            {"assessment_id": "assessment_test", "name": "Private customer"},
            {
                "comparison_id": "comparison_changed",
                "comparability": changed_diff["comparability"],
                "summary": changed_diff["summary"],
            },
            changed_findings,
            "en",
            False,
        )
        self.assertNotIn("Private-New-SSID", json.dumps(hidden_change))

        generic_values = build_ai_payload(
            {"assessment_id": "assessment_test"},
            comparison,
            [
                {
                    "finding_id": "finding_private_values",
                    "rule_id": "new_access_point",
                    "severity": "medium",
                    "confidence": 0.9,
                    "evidence_ids": [],
                    "details": {
                        "before": "PRIVATE-SSID-BEFORE",
                        "after": "PRIVATE-SSID-AFTER",
                    },
                }
            ],
            "en",
            False,
        )
        generic_serialized = json.dumps(generic_values)
        self.assertNotIn("PRIVATE-SSID-BEFORE", generic_serialized)
        self.assertNotIn("PRIVATE-SSID-AFTER", generic_serialized)

    def test_mac_like_local_assessment_text_is_not_in_cloud_payload(self):
        payload = build_ai_payload(
            {
                "assessment_id": "assessment_test",
                "name": "AA:BB:CC:00:00:01",
                "location": "",
            },
            {
                "comparison_id": "comparison_test",
                "comparability": {},
                "summary": {},
            },
            [],
            "en",
            False,
        )
        self.assertNotIn("AA:BB:CC", json.dumps(payload))


if __name__ == "__main__":
    unittest.main()
