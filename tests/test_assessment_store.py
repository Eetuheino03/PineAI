import copy
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path


ASSETS = (
    Path(__file__).resolve().parents[1]
    / "projects"
    / "PineAI"
    / "src"
    / "assets"
)
sys.path.insert(0, str(ASSETS))

from pineai_backend.assessment_store import AssessmentStore  # noqa: E402
from pineai_backend.errors import BackendError  # noqa: E402


AP_ID = "ap_aaaaaaaaaaaa"
NETWORK_ID = "network_bbbbbbbbbbbb"
EVIDENCE_ID = "evidence_cccccccccccc"
FINDING_ID = "finding_dddddddddddd"


def assessment_value():
    return {
        "name": "Factory wireless assurance",
        "location": "Pori plant",
        "notes": "Local-only assessment notes",
    }


def snapshot(suffix="1", channel=6):
    digest_character = suffix[-1]
    snapshot_id = "snapshot_{0}".format(digest_character * 16)
    digest = digest_character * 64
    return {
        "schema_version": "1.0",
        "snapshot_id": snapshot_id,
        "snapshot_digest": digest,
        "observed_at": "2026-07-27T12:00:00Z",
        "scan_metadata": {
            "scan_id": "local-scan-{0}".format(suffix),
            "date": "2026-07-27T12:00:00Z",
            "source": "hak5_recon",
            "label": "Fixture",
            "scan_time": 180,
            "coverage": ["2.4"],
        },
        "comparability_profile": {
            "declared_coverage": ["2.4"],
            "observed_coverage": ["2.4"],
            "effective_coverage": ["2.4"],
            "scan_time": 180,
        },
        "summary": {
            "access_point_count": 1,
            "network_count": 1,
            "associated_client_count": 2,
            "out_of_range_client_count": 0,
            "unassociated_client_count": 0,
            "input_bytes": 512,
        },
        "access_points": [
            {
                "asset_id": AP_ID,
                "network_id": NETWORK_ID,
                "evidence_id": EVIDENCE_ID,
                "bssid": "AA:BB:CC:DD:EE:FF",
                "ssid": "Factory-WiFi",
                "hidden": False,
                "encryption": 4,
                "wps": False,
                "channel": channel,
                "band": "2.4",
                "signal": -42,
                "vendor": "Example",
                "client_count": 2,
                "data": 100,
                "probes": 4,
                "last_seen": 1000,
            }
        ],
        "networks": [
            {
                "network_id": NETWORK_ID,
                "ssid": "Factory-WiFi",
                "hidden": False,
                "asset_ids": [AP_ID],
                "bssids": ["AA:BB:CC:DD:EE:FF"],
                "channels": [channel],
                "encryption_codes": [4],
                "vendors": ["Example"],
                "client_count": 2,
            }
        ],
        "evidence": [
            {
                "evidence_id": EVIDENCE_ID,
                "snapshot_id": snapshot_id,
                "evidence_type": "recon_access_point_observation",
                "subject_id": AP_ID,
                "observed": {
                    "network_id": NETWORK_ID,
                    "bssid": "AA:BB:CC:DD:EE:FF",
                    "ssid": "Factory-WiFi",
                    "hidden": False,
                    "encryption": 4,
                    "wps": False,
                    "channel": channel,
                    "signal": -42,
                    "vendor": "Example",
                    "client_count": 2,
                },
            }
        ],
    }


def comparison(baseline, current, status="comparable"):
    return {
        "schema_version": "1.0",
        "baseline_snapshot_id": baseline["snapshot_id"],
        "current_snapshot_id": current["snapshot_id"],
        "comparability": {
            "status": status,
            "absence_findings_allowed": status == "comparable",
            "reasons": [],
            "baseline": {
                "coverage": ["2.4"],
                "scan_time": 180,
                "access_point_count": 1,
            },
            "current": {
                "coverage": ["2.4"],
                "scan_time": 180,
                "access_point_count": 1,
            },
        },
        "access_points": {"added": [], "removed": [], "changed": []},
        "networks": {"added": [], "removed": [], "changed": []},
        "summary": {
            "access_points_added": 0,
            "access_points_removed": 0,
            "access_points_changed": 0,
            "networks_added": 0,
            "networks_removed": 0,
            "networks_changed": 0,
        },
    }


def finding(finding_id=FINDING_ID):
    return {
        "finding_id": finding_id,
        "rule_id": "channel_changed",
        "title": "Access point channel changed",
        "severity": "low",
        "confidence": 0.95,
        "subject_id": AP_ID,
        "summary": "A known BSSID moved to another channel.",
        "evidence_ids": [EVIDENCE_ID],
        "details": {"asset_id": AP_ID},
        "confidence_factors": {
            "base": 0.95,
            "comparability_penalty": 0.0,
            "evidence_bonus": 0.0,
        },
    }


def active_store(directory):
    store = AssessmentStore(directory)
    created = store.create(assessment_value())
    baseline = snapshot("1")
    created_baseline = store.create_baseline_version(
        created["assessment_id"], created["revision"], baseline
    )
    activated = store.activate_baseline_version(
        created["assessment_id"],
        created_baseline["assessment"]["revision"],
        created_baseline["baseline_version"]["baseline_version_id"],
    )
    return store, activated["assessment"], baseline


class AssessmentStoreTests(unittest.TestCase):
    def test_create_get_list_update_archive_and_append_only_audit(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AssessmentStore(directory)
            created = store.create(assessment_value())
            assessment_id = created["assessment_id"]
            self.assertEqual(created["revision"], 1)
            self.assertEqual(created["status"], "active")
            self.assertIsNone(created["active_baseline_version"])
            self.assertEqual(
                created["events"][0]["event_type"], "assessment_created"
            )
            updated = store.update(
                assessment_id,
                1,
                {"name": "Updated factory assurance"},
            )
            self.assertEqual(updated["revision"], 2)
            self.assertEqual(len(store.get(assessment_id)["events"]), 2)
            event_path = (
                Path(directory)
                / "assessments"
                / assessment_id
                / "events.jsonl"
            )
            lines_before_archive = event_path.read_text(
                encoding="utf-8"
            ).splitlines()
            archived = store.archive(assessment_id, 2)
            lines_after_archive = event_path.read_text(
                encoding="utf-8"
            ).splitlines()
            self.assertEqual(
                lines_after_archive[:2], lines_before_archive
            )
            self.assertEqual(archived["revision"], 3)
            self.assertEqual(store.list(), [])
            self.assertEqual(len(store.list(include_archived=True)), 1)

    def test_revision_conflicts_and_archived_assessments_are_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AssessmentStore(directory)
            created = store.create(assessment_value())
            with self.assertRaises(BackendError) as raised:
                store.update(
                    created["assessment_id"], 99, {"location": "Other"}
                )
            self.assertEqual(raised.exception.code, "revision_conflict")
            archived = store.archive(
                created["assessment_id"], created["revision"]
            )
            with self.assertRaises(BackendError) as raised:
                store.create_baseline_version(
                    created["assessment_id"],
                    archived["revision"],
                    snapshot("1"),
                )
            self.assertEqual(raised.exception.code, "assessment_archived")

    def test_baseline_versions_are_immutable_and_activation_is_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AssessmentStore(directory)
            created = store.create(assessment_value())
            first_snapshot = snapshot("1")
            first = store.create_baseline_version(
                created["assessment_id"],
                created["revision"],
                first_snapshot,
                "Approved factory baseline",
            )
            self.assertIsNone(
                first["assessment"]["active_baseline_version"]
            )
            first_path = (
                Path(directory)
                / "assessments"
                / created["assessment_id"]
                / "baselines"
                / "baseline_v0001.json"
            )
            first_bytes = first_path.read_bytes()
            second = store.create_baseline_version(
                created["assessment_id"],
                first["assessment"]["revision"],
                snapshot("2"),
            )
            self.assertEqual(first_path.read_bytes(), first_bytes)
            self.assertEqual(
                second["baseline_version"]["baseline_version_id"],
                "baseline_v0002",
            )
            self.assertEqual(
                first["baseline_version"]["label"],
                "Approved factory baseline",
            )
            activated = store.activate_baseline_version(
                created["assessment_id"],
                second["assessment"]["revision"],
                "baseline_v0001",
            )
            self.assertEqual(
                activated["assessment"]["active_baseline_version"],
                "baseline_v0001",
            )
            versions = store.list_baseline_versions(
                created["assessment_id"]
            )
            self.assertEqual(len(versions), 2)
            self.assertTrue(versions[0]["is_active"])
            loaded = store.get_baseline_version(
                created["assessment_id"], "baseline_v0001"
            )
            self.assertEqual(loaded["snapshot"], first_snapshot)

    def test_persist_analysis_and_finding_lifecycle(self):
        with tempfile.TemporaryDirectory() as directory:
            store, assessment, baseline = active_store(directory)
            assessment_id = assessment["assessment_id"]
            current = snapshot("2", channel=11)
            first = store.persist_analysis(
                assessment_id,
                assessment["revision"],
                comparison(baseline, current),
                current,
                [finding()],
            )
            stored = first["findings"][0]
            self.assertEqual(stored["status"], "open")
            self.assertTrue(stored["currently_observed"])
            self.assertEqual(stored["occurrence_count"], 1)
            self.assertEqual(first["lifecycle"]["opened"], [FINDING_ID])

            acknowledged = store.update_finding(
                assessment_id,
                first["assessment"]["revision"],
                FINDING_ID,
                "acknowledged",
            )
            self.assertEqual(
                acknowledged["finding"]["status"], "acknowledged"
            )

            clean = snapshot("3")
            resolved = store.persist_analysis(
                assessment_id,
                acknowledged["assessment"]["revision"],
                comparison(baseline, clean),
                clean,
                [],
            )
            self.assertEqual(
                resolved["findings"][0]["status"], "resolved"
            )
            self.assertFalse(
                resolved["findings"][0]["currently_observed"]
            )
            self.assertEqual(
                resolved["lifecycle"]["resolved"], [FINDING_ID]
            )
            with self.assertRaises(BackendError) as raised:
                store.update_finding(
                    assessment_id,
                    resolved["assessment"]["revision"],
                    FINDING_ID,
                    "open",
                )
            self.assertEqual(raised.exception.code, "invalid_finding")

            recurring = snapshot("4", channel=11)
            reopened = store.persist_analysis(
                assessment_id,
                resolved["assessment"]["revision"],
                comparison(baseline, recurring),
                recurring,
                [finding()],
            )
            stored = reopened["findings"][0]
            self.assertEqual(stored["status"], "open")
            self.assertEqual(stored["occurrence_count"], 2)
            self.assertEqual(
                reopened["lifecycle"]["reopened"], [FINDING_ID]
            )
            loaded = store.get_comparison(
                assessment_id,
                reopened["comparison"]["comparison_id"],
            )
            self.assertEqual(
                loaded["current_snapshot_id"], recurring["snapshot_id"]
            )

    def test_false_positive_is_preserved_when_absent_or_recurring(self):
        with tempfile.TemporaryDirectory() as directory:
            store, assessment, baseline = active_store(directory)
            current = snapshot("2", channel=11)
            first = store.persist_analysis(
                assessment["assessment_id"],
                assessment["revision"],
                comparison(baseline, current),
                current,
                [finding()],
            )
            marked = store.update_finding(
                assessment["assessment_id"],
                first["assessment"]["revision"],
                FINDING_ID,
                "false_positive",
            )
            clean = snapshot("3")
            absent = store.persist_analysis(
                assessment["assessment_id"],
                marked["assessment"]["revision"],
                comparison(baseline, clean),
                clean,
                [],
            )
            self.assertEqual(
                absent["findings"][0]["status"], "false_positive"
            )
            recurring = snapshot("4", channel=11)
            again = store.persist_analysis(
                assessment["assessment_id"],
                absent["assessment"]["revision"],
                comparison(baseline, recurring),
                recurring,
                [finding()],
            )
            self.assertEqual(
                again["findings"][0]["status"], "false_positive"
            )
            self.assertEqual(
                again["lifecycle"]["preserved_false_positive"],
                [FINDING_ID],
            )

    def test_partial_scan_does_not_resolve_and_not_comparable_does_not_mutate(self):
        with tempfile.TemporaryDirectory() as directory:
            store, assessment, baseline = active_store(directory)
            current = snapshot("2", channel=11)
            first = store.persist_analysis(
                assessment["assessment_id"],
                assessment["revision"],
                comparison(baseline, current),
                current,
                [finding()],
            )
            partial_snapshot = snapshot("3")
            partial = store.persist_analysis(
                assessment["assessment_id"],
                first["assessment"]["revision"],
                comparison(
                    baseline,
                    partial_snapshot,
                    "partially_comparable",
                ),
                partial_snapshot,
                [],
            )
            self.assertEqual(partial["findings"][0]["status"], "open")
            self.assertTrue(
                partial["findings"][0]["currently_observed"]
            )

            before = copy.deepcopy(partial["findings"])
            unsuitable = snapshot("4")
            diagnostic = store.persist_analysis(
                assessment["assessment_id"],
                partial["assessment"]["revision"],
                comparison(
                    baseline, unsuitable, "not_comparable"
                ),
                unsuitable,
                [finding()],
            )
            self.assertFalse(diagnostic["lifecycle"]["mutated"])
            self.assertEqual(diagnostic["findings"], before)

    def test_duplicate_analysis_is_rejected_before_occurrence_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            store, assessment, baseline = active_store(directory)
            current = snapshot("2", channel=11)
            value = comparison(baseline, current)
            first = store.persist_analysis(
                assessment["assessment_id"],
                assessment["revision"],
                value,
                current,
                [finding()],
            )
            with self.assertRaises(BackendError) as raised:
                store.persist_analysis(
                    assessment["assessment_id"],
                    first["assessment"]["revision"],
                    value,
                    current,
                    [finding()],
                )
            self.assertEqual(
                raised.exception.code, "analysis_already_persisted"
            )
            self.assertEqual(
                store.list_findings(
                    assessment["assessment_id"]
                )[0]["occurrence_count"],
                1,
            )

    def test_analysis_references_and_active_baseline_are_authoritative(self):
        with tempfile.TemporaryDirectory() as directory:
            store, assessment, baseline = active_store(directory)
            current = snapshot("2", channel=11)
            unknown_evidence = finding()
            unknown_evidence["evidence_ids"] = [
                "evidence_eeeeeeeeeeee"
            ]
            with self.assertRaises(BackendError) as raised:
                store.persist_analysis(
                    assessment["assessment_id"],
                    assessment["revision"],
                    comparison(baseline, current),
                    current,
                    [unknown_evidence],
                )
            self.assertEqual(raised.exception.code, "invalid_finding")

            wrong_baseline = snapshot("3")
            mismatched = comparison(wrong_baseline, current)
            with self.assertRaises(BackendError) as raised:
                store.persist_analysis(
                    assessment["assessment_id"],
                    assessment["revision"],
                    mismatched,
                    current,
                    [finding()],
                )
            self.assertEqual(raised.exception.code, "invalid_comparison")

    def test_finding_filters_status_updates_and_revision_conflict(self):
        with tempfile.TemporaryDirectory() as directory:
            store, assessment, baseline = active_store(directory)
            current = snapshot("2", channel=11)
            first = store.persist_analysis(
                assessment["assessment_id"],
                assessment["revision"],
                comparison(baseline, current),
                current,
                [finding()],
            )
            with self.assertRaises(BackendError) as raised:
                store.update_finding(
                    assessment["assessment_id"],
                    assessment["revision"],
                    FINDING_ID,
                    "acknowledged",
                )
            self.assertEqual(raised.exception.code, "revision_conflict")
            updated = store.update_finding(
                assessment["assessment_id"],
                first["assessment"]["revision"],
                FINDING_ID,
                "acknowledged",
                "Validated by the operator",
            )
            self.assertEqual(updated["finding"]["status"], "acknowledged")
            self.assertNotIn("note", updated["finding"])
            self.assertEqual(
                updated["event"]["data"]["note"],
                "Validated by the operator",
            )
            self.assertEqual(
                len(
                    store.list_findings(
                        assessment["assessment_id"],
                        statuses=["acknowledged"],
                        currently_observed=True,
                    )
                ),
                1,
            )
            self.assertEqual(
                store.list_findings(
                    assessment["assessment_id"], statuses=["open"]
                ),
                [],
            )
            with self.assertRaises(BackendError) as raised:
                store.update_finding(
                    assessment["assessment_id"],
                    updated["assessment"]["revision"],
                    FINDING_ID,
                    "resolved",
                )
            self.assertEqual(raised.exception.code, "invalid_finding")
            with self.assertRaises(BackendError) as raised:
                store.update_finding(
                    assessment["assessment_id"],
                    updated["assessment"]["revision"],
                    FINDING_ID,
                    "open",
                    "bad\nnote",
                )
            self.assertEqual(raised.exception.code, "invalid_finding")

    def test_raw_recon_data_is_never_persisted(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AssessmentStore(directory)
            created = store.create(assessment_value())
            raw = snapshot("1")
            raw["APResults"] = []
            with self.assertRaises(BackendError) as raised:
                store.create_baseline_version(
                    created["assessment_id"],
                    created["revision"],
                    raw,
                )
            self.assertEqual(
                raised.exception.code, "invalid_snapshot"
            )
            serialized = json.dumps(
                list(
                    (
                        Path(directory)
                        / "assessments"
                        / created["assessment_id"]
                    ).rglob("*")
                ),
                default=str,
            )
            self.assertNotIn("APResults", serialized)

    def test_existing_engagement_storage_is_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            legacy = Path(directory) / "engagements" / "legacy.json"
            legacy.parent.mkdir(parents=True)
            legacy.write_text('{"legacy":true}\\n', encoding="utf-8")
            before = legacy.read_bytes()
            AssessmentStore(directory).create(assessment_value())
            self.assertEqual(legacy.read_bytes(), before)

    @unittest.skipIf(os.name == "nt", "POSIX permissions are verified on Linux")
    def test_private_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            store, assessment, baseline = active_store(directory)
            current = snapshot("2", channel=11)
            store.persist_analysis(
                assessment["assessment_id"],
                assessment["revision"],
                comparison(baseline, current),
                current,
                [finding()],
            )
            root = Path(directory) / "assessments"
            for path in root.rglob("*"):
                expected = 0o700 if path.is_dir() else 0o600
                self.assertEqual(
                    stat.S_IMODE(path.stat().st_mode), expected, str(path)
                )

    def test_lru_cache_deep_copy_and_invalidation(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AssessmentStore(directory)
            created = store.create(assessment_value())
            get1 = store.get(created["assessment_id"])
            get2 = store.get(created["assessment_id"])
            self.assertEqual(get1, get2)
            self.assertIsNot(get1, get2)
            get1["name"] = "Mutated Name"
            get3 = store.get(created["assessment_id"])
            self.assertEqual(get3["name"], created["name"])
            self.assertGreater(store._mtime_cache_hits, 0)

    def test_lru_cache_item_count_eviction(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AssessmentStore(directory)
            for i in range(70):
                created = store.create({"name": f"Assessment {i}", "location": "Lab", "notes": "notes"})
                store.get(created["assessment_id"])
            self.assertLessEqual(len(store._mtime_cache), 64)
            self.assertGreater(store._mtime_cache_evictions, 0)

    def test_lru_cache_path_invalidation(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AssessmentStore(directory)
            created = store.create(assessment_value())
            store.get(created["assessment_id"])
            self.assertGreater(len(store._mtime_cache), 0)
            store.update(created["assessment_id"], created["revision"], {"name": "Updated Name"})
            updated = store.get(created["assessment_id"])
            self.assertEqual(updated["name"], "Updated Name")

    def test_lru_cache_oversized_item_bypass(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AssessmentStore(directory)
            large_file = Path(directory) / "large.json"
            large_data = {"data": "x" * (260 * 1024)}  # > 256 KiB limit
            store._write_json(large_file, large_data)
            cache_count_before = len(store._mtime_cache)
            got = store._read_json(large_file, "missing", "missing")
            self.assertEqual(len(got["data"]), 260 * 1024)
            # Oversized item must bypass cache
            self.assertEqual(len(store._mtime_cache), cache_count_before)

    def test_lru_cache_ordering_on_hit(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AssessmentStore(directory)
            a1 = store.create({"name": "First", "location": "Lab", "notes": "n1"})
            a2 = store.create({"name": "Second", "location": "Lab", "notes": "n2"})
            store.get(a1["assessment_id"])
            store.get(a2["assessment_id"])
            keys1 = list(store._mtime_cache.keys())
            # Re-fetch a1 -> it should be moved to end of OrderedDict
            store.get(a1["assessment_id"])
            keys2 = list(store._mtime_cache.keys())
            self.assertEqual(keys2[-1], keys1[0])

    def test_lru_cache_malformed_json_handling(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AssessmentStore(directory)
            created = store.create(assessment_value())
            _, json_path, _, _, _ = store._assessment_paths(created["assessment_id"])
            json_path.write_text("{malformed json", encoding="utf-8")
            with self.assertRaises(BackendError) as cm:
                store.get(created["assessment_id"])
            self.assertEqual(cm.exception.code, "storage_error")


if __name__ == "__main__":
    unittest.main()

