import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "projects" / "PineAI" / "src" / "assets"
sys.path.insert(0, str(ASSETS))

from pineai_backend.backup import create_backup, restore_backup_staging  # noqa: E402
from pineai_backend.config import ensure_pseudonymization_key  # noqa: E402
from pineai_backend.errors import BackendError  # noqa: E402
from pineai_backend.repeatable_audit_store import RepeatableAuditStore  # noqa: E402


def sample_context():
    return {
        "location_id": "building-a",
        "scan_profile_id": "fast-scan",
        "radio_profile_id": "wlan1-mk7",
        "interface": "wlan1mon",
        "declared_bands": ["2.4", "5"],
        "declared_channels": [1, 6, 11, 36, 40],
        "scan_time": 300,
    }


def sample_assurance_profile():
    return {
        "title": "Default Assurance Profile",
        "description": "Standard assurance rules",
        "rules": [
            {
                "rule_id": "open_ssid_detected",
                "severity": "high",
                "enabled": True,
            }
        ],
    }


class RepeatableAuditStoreTests(unittest.TestCase):
    def test_measurement_point_lifecycle_and_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            ensure_pseudonymization_key(directory)
            store = RepeatableAuditStore(directory)
            assessment = store.create({"name": "Test Assessment", "location": "Lab", "notes": ""})
            aid = assessment["assessment_id"]

            # Create MeasurementPoint
            res = store.create_measurement_point(aid, assessment["revision"], sample_context(), "Point 1", "North Wall")
            mp = res["measurement_point"]
            self.assertEqual(mp["status"], "active")
            self.assertEqual(mp["revision"], 1)
            self.assertEqual(mp["name"], "Point 1")
            self.assertEqual(mp["expected_measurement_context"]["measurement_point_id"], mp["measurement_point_id"])
            self.assertEqual(res["assessment_revision"], 2)

            # Get and List
            fetched = store.get_measurement_point(aid, mp["measurement_point_id"])
            self.assertEqual(fetched["measurement_point_id"], mp["measurement_point_id"])
            listed = store.list_measurement_points(aid)
            self.assertEqual(len(listed), 1)

            # Update MeasurementPoint
            upd_res = store.update_measurement_point(
                aid,
                res["assessment_revision"],
                mp["measurement_point_id"],
                mp["revision"],
                {"name": "Point 1 Updated", "description": "Updated North Wall"},
            )
            upd_mp = upd_res["measurement_point"]
            self.assertEqual(upd_mp["name"], "Point 1 Updated")
            self.assertEqual(upd_mp["revision"], 2)

            # Archive MeasurementPoint
            arc_res = store.archive_measurement_point(
                aid,
                upd_res["assessment_revision"],
                mp["measurement_point_id"],
                upd_mp["revision"],
            )
            arc_mp = arc_res["measurement_point"]
            self.assertEqual(arc_mp["status"], "archived")
            self.assertIsNotNone(arc_mp["archived_at"])

            # Archived excluded from active listing but included when requested
            self.assertEqual(len(store.list_measurement_points(aid)), 0)
            self.assertEqual(len(store.list_measurement_points(aid, include_archived=True)), 1)

            # Updating archived point fails
            with self.assertRaises(BackendError) as raised:
                store.update_measurement_point(
                    aid,
                    arc_res["assessment_revision"],
                    mp["measurement_point_id"],
                    arc_mp["revision"],
                    {"name": "New Name"},
                )
            self.assertEqual(raised.exception.code, "measurement_point_archived")

    def test_measurement_point_capacity_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            ensure_pseudonymization_key(directory)
            store = RepeatableAuditStore(directory)
            assessment = store.create({"name": "Capacity Test", "location": "", "notes": ""})
            aid = assessment["assessment_id"]
            rev = assessment["revision"]

            points = []
            for i in range(64):
                res = store.create_measurement_point(aid, rev, sample_context(), "MP {0}".format(i))
                rev = res["assessment_revision"]
                points.append(res["measurement_point"])

            # 65th active point fails
            with self.assertRaises(BackendError) as raised:
                store.create_measurement_point(aid, rev, sample_context(), "MP 64")
            self.assertEqual(raised.exception.code, "storage_limit_exceeded")

            # Archive 2 points
            res1 = store.archive_measurement_point(aid, rev, points[0]["measurement_point_id"], 1)
            rev = res1["assessment_revision"]
            res2 = store.archive_measurement_point(aid, rev, points[1]["measurement_point_id"], 1)
            rev = res2["assessment_revision"]

            # Now 2 new active points can be created
            res3 = store.create_measurement_point(aid, rev, sample_context(), "MP 64")
            rev = res3["assessment_revision"]
            res4 = store.create_measurement_point(aid, rev, sample_context(), "MP 65")
            rev = res4["assessment_revision"]
            self.assertEqual(len(store.list_measurement_points(aid)), 64)

    def test_audit_run_lifecycle_and_sealing(self):
        with tempfile.TemporaryDirectory() as directory:
            ensure_pseudonymization_key(directory)
            store = RepeatableAuditStore(directory)
            assessment = store.create({"name": "AuditRun Test", "location": "", "notes": ""})
            aid = assessment["assessment_id"]
            rev = assessment["revision"]

            # Create assurance profile & set active
            ap_res = store.create_assurance_profile_version(aid, rev, sample_assurance_profile())
            rev = ap_res["assessment"]["revision"]
            vid = ap_res["assurance_profile_version"]["assurance_profile_version_id"]
            act_res = store.activate_assurance_profile_version(aid, rev, vid)
            rev = act_res["assessment"]["revision"]

            # Create MeasurementPoint
            mp_res = store.create_measurement_point(aid, rev, sample_context(), "Point A")
            rev = mp_res["assessment_revision"]
            mp_id = mp_res["measurement_point"]["measurement_point_id"]

            # Create AuditRun
            ar_res = store.create_audit_run(aid, rev, "Run 1", [mp_id])
            rev = ar_res["assessment_revision"]
            run = ar_res["audit_run"]
            self.assertEqual(run["status"], "draft")
            self.assertTrue(run["ready_to_start"])
            self.assertEqual(len(run["measurements"]), 1)
            self.assertEqual(run["measurements"][0]["status"], "pending")

            # Start AuditRun
            start_res = store.start_audit_run(aid, rev, run["audit_run_id"], run["revision"])
            rev = start_res["assessment_revision"]
            run = start_res["audit_run"]
            self.assertEqual(run["status"], "in_progress")
            self.assertFalse(run["ready_to_start"])

            # Attempting to complete before measurements are done fails
            with self.assertRaises(BackendError) as raised:
                store.complete_audit_run(aid, rev, run["audit_run_id"], run["revision"])
            self.assertEqual(raised.exception.code, "audit_run_incomplete")

            # Resolve measurement
            resolve_res = store.resolve_audit_measurement(
                aid,
                rev,
                run["audit_run_id"],
                run["revision"],
                mp_id,
                {
                    "status": "resolved",
                    "baseline_type": "consensus",
                    "snapshot_id": "snapshot_1111222233334444",
                    "snapshot_digest": "a" * 64,
                    "measurement_profile_version_id": "mprofile_r0001",
                    "measurement_profile_digest": "b" * 64,
                    "baseline_model_id": "bmodel_1111222233334444",
                    "baseline_model_digest": "c" * 64,
                    "assurance_profile_version_id": "assurance_v0001",
                    "assurance_profile_digest": "d" * 64,
                    "comparability_status": "comparable",
                    "resolved_at": "2026-07-30T12:00:00Z",
                },
            )
            rev = resolve_res["assessment_revision"]
            run = resolve_res["audit_run"]
            self.assertEqual(resolve_res["measurement"]["status"], "resolved")

            # Save comparison
            cmp_res = store.save_audit_measurement_comparison(
                aid,
                rev,
                run["audit_run_id"],
                run["revision"],
                mp_id,
                {
                    "status": "completed",
                    "baseline_type": "consensus",
                    "comparison_id": "comparison_1111222233334444",
                    "comparison_digest": "e" * 64,
                    "occurrence_set_id": "occurrence_1111222233334444",
                    "evidence_ids": ["evidence_111122223333"],
                    "completed_at": "2026-07-30T12:05:00Z",
                },
            )
            rev = cmp_res["assessment_revision"]
            run = cmp_res["audit_run"]
            self.assertEqual(cmp_res["measurement"]["status"], "completed")

            # Now complete AuditRun succeeds
            comp_res = store.complete_audit_run(aid, rev, run["audit_run_id"], run["revision"])
            rev = comp_res["assessment_revision"]
            run = comp_res["audit_run"]
            self.assertEqual(run["status"], "completed")

            # Sealed run rejects further mutations
            with self.assertRaises(BackendError) as raised:
                store.start_audit_run(aid, rev, run["audit_run_id"], run["revision"])
            self.assertEqual(raised.exception.code, "audit_run_sealed")

    def test_measurement_retry_semantics(self):
        with tempfile.TemporaryDirectory() as directory:
            ensure_pseudonymization_key(directory)
            store = RepeatableAuditStore(directory)
            assessment = store.create({"name": "Retry Test", "location": "", "notes": ""})
            aid = assessment["assessment_id"]
            rev = assessment["revision"]

            ap_res = store.create_assurance_profile_version(aid, rev, sample_assurance_profile())
            rev = ap_res["assessment"]["revision"]
            vid = ap_res["assurance_profile_version"]["assurance_profile_version_id"]
            act_res = store.activate_assurance_profile_version(aid, rev, vid)
            rev = act_res["assessment"]["revision"]

            mp_res = store.create_measurement_point(aid, rev, sample_context(), "Point A")
            rev = mp_res["assessment_revision"]
            mp_id = mp_res["measurement_point"]["measurement_point_id"]

            ar_res = store.create_audit_run(aid, rev, "Run 1", [mp_id])
            rev = ar_res["assessment_revision"]
            run = ar_res["audit_run"]

            start_res = store.start_audit_run(aid, rev, run["audit_run_id"], run["revision"])
            rev = start_res["assessment_revision"]
            run = start_res["audit_run"]

            # Fail resolution
            fail_res = store.resolve_audit_measurement(
                aid,
                rev,
                run["audit_run_id"],
                run["revision"],
                mp_id,
                {
                    "status": "failed",
                    "failed_stage": "resolution",
                    "retry_target": "pending",
                    "error_code": "scan_timeout",
                    "error_message": "Recon acquisition timed out",
                    "failed_at": "2026-07-30T12:00:00Z",
                },
            )
            rev = fail_res["assessment_revision"]
            run = fail_res["audit_run"]

            # Retry resolution failure -> transitions to pending and clears error fields
            retry_res = store.retry_audit_measurement(
                aid,
                rev,
                run["audit_run_id"],
                run["revision"],
                mp_id,
                {"status": "pending"},
            )
            rev = retry_res["assessment_revision"]
            m = retry_res["measurement"]
            self.assertEqual(m["status"], "pending")
            self.assertNotIn("error_code", m)
            self.assertNotIn("error_message", m)

    def test_evidence_limit_and_no_raw_recon(self):
        with tempfile.TemporaryDirectory() as directory:
            ensure_pseudonymization_key(directory)
            store = RepeatableAuditStore(directory)
            assessment = store.create({"name": "Evidence Test", "location": "", "notes": ""})
            aid = assessment["assessment_id"]
            rev = assessment["revision"]

            ap_res = store.create_assurance_profile_version(aid, rev, sample_assurance_profile())
            rev = ap_res["assessment"]["revision"]
            vid = ap_res["assurance_profile_version"]["assurance_profile_version_id"]
            act_res = store.activate_assurance_profile_version(aid, rev, vid)
            rev = act_res["assessment"]["revision"]

            mp_res = store.create_measurement_point(aid, rev, sample_context(), "Point A")
            rev = mp_res["assessment_revision"]
            mp_id = mp_res["measurement_point"]["measurement_point_id"]

            ar_res = store.create_audit_run(aid, rev, "Run 1", [mp_id])
            rev = ar_res["assessment_revision"]
            run = ar_res["audit_run"]
            start_res = store.start_audit_run(aid, rev, run["audit_run_id"], run["revision"])
            rev = start_res["assessment_revision"]
            run = start_res["audit_run"]

            resolve_res = store.resolve_audit_measurement(
                aid,
                rev,
                run["audit_run_id"],
                run["revision"],
                mp_id,
                {
                    "status": "resolved",
                    "baseline_type": "single_scan",
                    "snapshot_id": "snapshot_1111222233334444",
                    "snapshot_digest": "a" * 64,
                    "measurement_profile_version_id": "mprofile_r0001",
                    "measurement_profile_digest": "b" * 64,
                    "baseline_snapshot_id": "snapshot_9999888877776666",
                    "baseline_snapshot_digest": "c" * 64,
                    "assurance_profile_version_id": "assurance_v0001",
                    "assurance_profile_digest": "d" * 64,
                    "comparability_status": "comparable",
                    "resolved_at": "2026-07-30T12:00:00Z",
                },
            )
            rev = resolve_res["assessment_revision"]
            run = resolve_res["audit_run"]

            # 101 evidence IDs fails validation
            too_many_ev = ["evidence_{0:012x}".format(i) for i in range(101)]
            with self.assertRaises(BackendError) as raised:
                store.save_audit_measurement_comparison(
                    aid,
                    rev,
                    run["audit_run_id"],
                    run["revision"],
                    mp_id,
                    {
                        "status": "completed",
                        "baseline_type": "single_scan",
                        "comparison_id": "comparison_1111222233334444",
                        "comparison_digest": "e" * 64,
                        "occurrence_set_id": "occurrence_1111222233334444",
                        "evidence_ids": too_many_ev,
                        "completed_at": "2026-07-30T12:05:00Z",
                    },
                )
            self.assertEqual(raised.exception.code, "invalid_audit_run_measurement")

            # Raw Recon payload rejection
            with self.assertRaises(BackendError) as raised:
                store.save_audit_measurement_comparison(
                    aid,
                    rev,
                    run["audit_run_id"],
                    run["revision"],
                    mp_id,
                    {
                        "status": "completed",
                        "baseline_type": "single_scan",
                        "comparison_id": "comparison_1111222233334444",
                        "comparison_digest": "e" * 64,
                        "occurrence_set_id": "occurrence_1111222233334444",
                        "evidence_ids": ["evidence_000000000001"],
                        "completed_at": "2026-07-30T12:05:00Z",
                        "apresults": [1, 2, 3],
                    },
                )
            self.assertEqual(raised.exception.code, "raw_recon_not_allowed")

    def test_assessment_capacity_and_closure_reserve(self):
        with tempfile.TemporaryDirectory() as directory:
            ensure_pseudonymization_key(directory)
            store = RepeatableAuditStore(directory)
            assessment = store.create({"name": "Capacity Test", "location": "", "notes": ""})
            aid = assessment["assessment_id"]

            cap = store.get_assessment_capacity(aid)
            self.assertEqual(cap["event_limit"], 5000)
            self.assertEqual(cap["event_reserved_for_run_closure"], 0)
            self.assertEqual(cap["event_available_for_non_terminal"], cap["event_available"])

    def test_backup_and_v063_compatibility(self):
        with tempfile.TemporaryDirectory() as directory:
            ensure_pseudonymization_key(directory)
            store = RepeatableAuditStore(directory)
            assessment = store.create({"name": "Backup Test", "location": "", "notes": ""})
            aid = assessment["assessment_id"]
            rev = assessment["revision"]

            ap_res = store.create_assurance_profile_version(aid, rev, sample_assurance_profile())
            rev = ap_res["assessment"]["revision"]
            vid = ap_res["assurance_profile_version"]["assurance_profile_version_id"]
            act_res = store.activate_assurance_profile_version(aid, rev, vid)
            rev = act_res["assessment"]["revision"]

            mp_res = store.create_measurement_point(aid, rev, sample_context(), "Point A")
            rev = mp_res["assessment_revision"]

            store.create_audit_run(aid, rev, "Run 1", [mp_res["measurement_point"]["measurement_point_id"]])

            # Create backup
            backup_path = Path(directory) / "backup.tar.gz"
            manifest = create_backup(directory, backup_path)
            self.assertEqual(manifest["backup_type"], "pineai_device_continuity")

            # Restore into new directory
            restore_dir = Path(directory) / "restored"
            restore_backup_staging(str(backup_path), str(restore_dir))

            restored_store = RepeatableAuditStore(restore_dir)
            self.assertEqual(len(restored_store.list_measurement_points(aid)), 1)
            self.assertEqual(len(restored_store.list_audit_runs(aid)), 1)


if __name__ == "__main__":
    unittest.main()
