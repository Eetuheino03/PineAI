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
        self.assertEqual(
            evaluate_comparability(baseline, self.resolve())["status"],
            "comparable",
        )
        unknown = self.resolve(metadata={"scan_id": "x"})
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
