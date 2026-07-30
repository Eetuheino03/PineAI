import json
import sys
import tempfile
import unittest
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "projects" / "PineAI" / "src" / "assets"
sys.path.insert(0, str(ASSETS))

from pineai_backend.assessment_store import _canonical_digest  # noqa: E402
from pineai_backend.backup import create_backup, restore_backup_staging  # noqa: E402
from pineai_backend.config import ensure_pseudonymization_key  # noqa: E402
from pineai_backend.errors import BackendError  # noqa: E402
from pineai_backend.repeatable_audit_store import RepeatableAuditStore  # noqa: E402

SCHEMA_PATH = ROOT / "docs" / "schemas" / "repeatable-audits-v1.schema.json"
with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
    REPEATABLE_AUDITS_SCHEMA = json.load(f)


def validate_schema(instance, schema_def_name):
    defs_dict = REPEATABLE_AUDITS_SCHEMA.get("$defs", REPEATABLE_AUDITS_SCHEMA.get("defs", {}))
    schema = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "$ref": f"#/$defs/{schema_def_name}",
        "$defs": defs_dict,
    }
    jsonschema.validate(instance=instance, schema=schema)


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


def setup_test_artifacts(directory, aid, snapshot_id="snapshot_0000000000000001", comparison_id="comparison_0000000000000001", occurrence_set_id="occurrence_0000000000000001"):
    base = Path(directory) / "assessments" / aid
    (base / "snapshots").mkdir(parents=True, exist_ok=True)
    (base / "comparisons").mkdir(parents=True, exist_ok=True)
    (base / "occurrences").mkdir(parents=True, exist_ok=True)

    snap_doc = {"snapshot_id": snapshot_id, "data": "sample snapshot payload"}
    snap_bytes = json.dumps(snap_doc, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    snap_digest = _canonical_digest(snap_doc)

    comp_doc = {"comparison_id": comparison_id, "data": "sample comparison payload"}
    comp_bytes = json.dumps(comp_doc, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    comp_digest = _canonical_digest(comp_doc)

    occ_doc = {"occurrence_set_id": occurrence_set_id, "occurrences": []}
    occ_bytes = json.dumps(occ_doc, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    occ_digest = _canonical_digest(occ_doc)

    if snapshot_id:
        (base / "snapshots" / f"{snapshot_id}.json").write_bytes(snap_bytes)
    if comparison_id:
        (base / "comparisons" / f"{comparison_id}.json").write_bytes(comp_bytes)
    if occurrence_set_id:
        (base / "occurrences" / f"{occurrence_set_id}.json").write_bytes(occ_bytes)

    return {
        "snapshot_digest": snap_digest,
        "comparison_digest": comp_digest,
        "occurrence_digest": occ_digest,
    }


class RepeatableAuditStoreTests(unittest.TestCase):
    def test_measurement_point_lifecycle_and_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            ensure_pseudonymization_key(directory)
            store = RepeatableAuditStore(directory)
            assessment = store.create({"name": "Test Assessment", "location": "Lab", "notes": ""})
            aid = assessment["assessment_id"]

            res = store.create_measurement_point(aid, assessment["revision"], sample_context(), "Point 1", "North Wall")
            mp = res["measurement_point"]
            self.assertEqual(mp["status"], "active")
            self.assertEqual(mp["revision"], 1)
            self.assertEqual(mp["name"], "Point 1")
            self.assertEqual(mp["expected_measurement_context"]["measurement_point_id"], mp["measurement_point_id"])

            fetched_res = store.get_measurement_point(aid, mp["measurement_point_id"])
            self.assertEqual(fetched_res["measurement_point"]["measurement_point_id"], mp["measurement_point_id"])

            listed_res = store.list_measurement_points(aid)
            self.assertEqual(len(listed_res["measurement_points"]), 1)
            self.assertEqual(listed_res["total"], 1)

            upd_res = store.update_measurement_point(
                aid,
                2,
                mp["measurement_point_id"],
                mp["revision"],
                {"name": "Point 1 Updated", "description": "Updated North Wall"},
            )
            upd_mp = upd_res["measurement_point"]
            self.assertEqual(upd_mp["name"], "Point 1 Updated")
            self.assertEqual(upd_mp["revision"], 2)

            arc_res = store.archive_measurement_point(
                aid,
                3,
                mp["measurement_point_id"],
                upd_mp["revision"],
            )
            arc_mp = arc_res["measurement_point"]
            self.assertEqual(arc_mp["status"], "archived")
            self.assertIsNotNone(arc_mp["archived_at"])

            self.assertEqual(len(store.list_measurement_points(aid)["measurement_points"]), 0)
            self.assertEqual(len(store.list_measurement_points(aid, include_archived=True)["measurement_points"]), 1)

            with self.assertRaises(BackendError) as raised:
                store.update_measurement_point(
                    aid,
                    4,
                    mp["measurement_point_id"],
                    arc_mp["revision"],
                    {"name": "New Name"},
                )
            self.assertEqual(raised.exception.code, "measurement_point_archived")

    def test_audit_run_lifecycle_and_sealing(self):
        with tempfile.TemporaryDirectory() as directory:
            ensure_pseudonymization_key(directory)
            store = RepeatableAuditStore(directory)
            assessment = store.create({"name": "Lifecycle Test", "location": "Lab", "notes": ""})
            aid = assessment["assessment_id"]
            rev = assessment["revision"]

            ap_res = store.create_assurance_profile_version(aid, rev, sample_assurance_profile())
            rev = ap_res["assessment"]["revision"]
            vid = ap_res["assurance_profile_version"]["assurance_profile_version_id"]
            act_res = store.activate_assurance_profile_version(aid, rev, vid)
            rev = act_res["assessment"]["revision"]

            mp_res = store.create_measurement_point(aid, rev, sample_context(), "Point A")
            rev = 4
            mp_id = mp_res["measurement_point"]["measurement_point_id"]

            ar_res = store.create_audit_run(aid, rev, "Run 1", vid, [mp_id])
            validate_schema(ar_res, "createAuditRunResponse")
            run = ar_res["audit_run"]
            self.assertEqual(run["status"], "draft")
            self.assertEqual(ar_res["ready_to_start"], True)
            self.assertNotIn("measurements", run)
            self.assertNotIn("ready_to_start", run)

            digests = setup_test_artifacts(directory, aid)
            start_res = store.start_audit_run(aid, 5, run["audit_run_id"], run["revision"])
            validate_schema(start_res, "startAuditRunResponse")
            self.assertEqual(start_res["audit_run"]["status"], "in_progress")

            # Resolve measurement
            res_outcome = {
                "status": "resolved",
                "source_recon_id": "recon_1",
                "snapshot_id": "snapshot_0000000000000001",
                "snapshot_digest": digests["snapshot_digest"],
                "measurement_profile_id": "mprofile_00000000-0000-4000-8000-000000000001",
                "measurement_profile_version_id": "mprofile_r0001",
                "measurement_profile_digest": "b" * 64,
                "baseline_version_id": "baseline_v0001",
                "baseline_type": "consensus",
                "baseline_model_id": "bmodel_0000000000000001",
                "baseline_model_digest": "c" * 64,
                "baseline_record_digest": "d" * 64,
                "assurance_profile_version_id": vid,
                "assurance_profile_digest": "e" * 64,
                "comparability_status": "comparable",
                "resolved_at": "2026-07-30T10:00:00Z",
            }
            res_out = store.resolve_audit_measurement(
                aid, 6, run["audit_run_id"], 2, mp_id, res_outcome
            )
            validate_schema(res_out, "resolveAuditMeasurementResponse")
            self.assertEqual(res_out["measurement"]["measurement_id"].startswith("arm_"), True)

            # Save comparison to complete
            comp_outcome = {
                "status": "completed",
                "comparison_id": "comparison_0000000000000001",
                "comparison_digest": digests["comparison_digest"],
                "occurrence_set_id": "occurrence_0000000000000001",
                "evidence_ids": ["evidence_000000000001"],
                "completed_at": "2026-07-30T10:05:00Z",
            }
            comp_out = store.save_audit_measurement_comparison(
                aid, 7, run["audit_run_id"], 3, mp_id, comp_outcome
            )
            validate_schema(comp_out, "saveAuditMeasurementComparisonResponse")

            comp_run_res = store.complete_audit_run(aid, 8, run["audit_run_id"], 4)
            validate_schema(comp_run_res, "completeAuditRunResponse")
            self.assertEqual(comp_run_res["audit_run"]["status"], "completed")

            with self.assertRaises(BackendError) as raised:
                store.start_audit_run(aid, 9, run["audit_run_id"], 5)
            self.assertEqual(raised.exception.code, "audit_run_sealed")

    def test_complete_audit_run_rejects_failed_or_pending_measurements(self):
        with tempfile.TemporaryDirectory() as directory:
            ensure_pseudonymization_key(directory)
            store = RepeatableAuditStore(directory)
            assessment = store.create({"name": "Completion Guard Test", "location": "Lab", "notes": ""})
            aid = assessment["assessment_id"]
            rev = assessment["revision"]

            ap_res = store.create_assurance_profile_version(aid, rev, sample_assurance_profile())
            rev = ap_res["assessment"]["revision"]
            vid = ap_res["assurance_profile_version"]["assurance_profile_version_id"]
            store.activate_assurance_profile_version(aid, rev, vid)

            mp_res = store.create_measurement_point(aid, 3, sample_context(), "Point A")
            mp_id = mp_res["measurement_point"]["measurement_point_id"]

            ar_res = store.create_audit_run(aid, 4, "Run 1", vid, [mp_id])
            run_id = ar_res["audit_run"]["audit_run_id"]
            store.start_audit_run(aid, 5, run_id, 1)

            # Try completing with pending measurement -> fails
            with self.assertRaises(BackendError) as raised:
                store.complete_audit_run(aid, 6, run_id, 2)
            self.assertEqual(raised.exception.code, "invalid_audit_run_transition")

            # Resolve as failed
            store.resolve_audit_measurement(aid, 6, run_id, 2, mp_id, {
                "status": "failed",
                "failed_stage": "resolution",
                "retry_target": "pending",
                "error_code": "recon_timeout",
                "error_message": "Recon timed out",
                "failed_at": "2026-07-30T10:00:00Z",
            })

            # Try completing with failed measurement -> fails
            with self.assertRaises(BackendError) as raised:
                store.complete_audit_run(aid, 7, run_id, 3)
            self.assertEqual(raised.exception.code, "invalid_audit_run_transition")

    def test_evidence_limit_and_no_raw_recon(self):
        with tempfile.TemporaryDirectory() as directory:
            ensure_pseudonymization_key(directory)
            store = RepeatableAuditStore(directory)
            assessment = store.create({"name": "Evidence Test", "location": "Lab", "notes": ""})
            aid = assessment["assessment_id"]

            ap_res = store.create_assurance_profile_version(aid, 1, sample_assurance_profile())
            vid = ap_res["assurance_profile_version"]["assurance_profile_version_id"]
            store.activate_assurance_profile_version(aid, 2, vid)

            mp_res = store.create_measurement_point(aid, 3, sample_context(), "Point 1")
            mp_id = mp_res["measurement_point"]["measurement_point_id"]
            ar_res = store.create_audit_run(aid, 4, "Run 1", vid, [mp_id])
            run_id = ar_res["audit_run"]["audit_run_id"]

            digests = setup_test_artifacts(directory, aid)
            store.start_audit_run(aid, 5, run_id, 1)

            # Raw recon keys rejected
            with self.assertRaises(BackendError) as raised:
                store.resolve_audit_measurement(aid, 6, run_id, 2, mp_id, {
                    "status": "resolved",
                    "recon": {"raw": "data"},
                })
            self.assertEqual(raised.exception.code, "invalid_audit_run_measurement")

            store.resolve_audit_measurement(aid, 6, run_id, 2, mp_id, {
                "status": "resolved",
                "source_recon_id": "recon_1",
                "snapshot_id": "snapshot_0000000000000001",
                "snapshot_digest": digests["snapshot_digest"],
                "measurement_profile_id": "mprofile_00000000-0000-4000-8000-000000000001",
                "measurement_profile_version_id": "mprofile_r0001",
                "measurement_profile_digest": "b" * 64,
                "baseline_version_id": "baseline_v0001",
                "baseline_type": "single_scan",
                "baseline_snapshot_id": "snapshot_0000000000000001",
                "baseline_snapshot_digest": digests["snapshot_digest"],
                "baseline_record_digest": "d" * 64,
                "assurance_profile_version_id": vid,
                "assurance_profile_digest": "e" * 64,
                "comparability_status": "comparable",
                "resolved_at": "2026-07-30T10:00:00Z",
            })

            # 101 evidence_ids rejected
            too_many = ["evidence_{0:012d}".format(i) for i in range(101)]
            with self.assertRaises(BackendError) as raised:
                store.save_audit_measurement_comparison(aid, 7, run_id, 3, mp_id, {
                    "status": "completed",
                    "comparison_id": "comparison_0000000000000001",
                    "comparison_digest": digests["comparison_digest"],
                    "occurrence_set_id": "occurrence_0000000000000001",
                    "evidence_ids": too_many,
                    "completed_at": "2026-07-30T10:05:00Z",
                })
            self.assertEqual(raised.exception.code, "invalid_audit_run_measurement")

            # Duplicate evidence_ids rejected
            with self.assertRaises(BackendError) as raised:
                store.save_audit_measurement_comparison(aid, 7, run_id, 3, mp_id, {
                    "status": "completed",
                    "comparison_id": "comparison_0000000000000001",
                    "comparison_digest": digests["comparison_digest"],
                    "occurrence_set_id": "occurrence_0000000000000001",
                    "evidence_ids": ["evidence_000000000001", "evidence_000000000001"],
                    "completed_at": "2026-07-30T10:05:00Z",
                })
            self.assertEqual(raised.exception.code, "invalid_audit_run_measurement")

            # Exactly 100 evidence_ids accepted
            exactly_100 = ["evidence_{0:012d}".format(i) for i in range(100)]
            comp_res = store.save_audit_measurement_comparison(aid, 7, run_id, 3, mp_id, {
                "status": "completed",
                "comparison_id": "comparison_0000000000000001",
                "comparison_digest": digests["comparison_digest"],
                "occurrence_set_id": "occurrence_0000000000000001",
                "evidence_ids": exactly_100,
                "completed_at": "2026-07-30T10:05:00Z",
            })
            self.assertEqual(len(comp_res["measurement"]["evidence_ids"]), 100)

    def test_repeatable_audit_store_fault_injection_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            ensure_pseudonymization_key(directory)
            calls = []

            def fault_injector(stage, index):
                calls.append((stage, index))
                if stage == "prepared":
                    raise RuntimeError("simulated crash after journal prepared")

            store = RepeatableAuditStore(directory, fault_injector=fault_injector)
            assessment = store.create({"name": "Fault Test", "location": "", "notes": ""})
            aid = assessment["assessment_id"]
            rev = assessment["revision"]

            with self.assertRaises(RuntimeError):
                store.create_measurement_point(aid, rev, sample_context(), "Point Fault")

            self.assertTrue(any(stage == "prepared" for stage, _ in calls))

            recovered_store = RepeatableAuditStore(directory)
            pts_res = recovered_store.list_measurement_points(aid)
            points = pts_res["measurement_points"]
            self.assertEqual(len(points), 1)
            self.assertEqual(points[0]["name"], "Point Fault")

    def test_backup_and_v063_compatibility(self):
        with tempfile.TemporaryDirectory() as directory:
            ensure_pseudonymization_key(directory)
            store = RepeatableAuditStore(directory)
            assessment = store.create({"name": "Backup Test", "location": "Lab", "notes": ""})
            aid = assessment["assessment_id"]
            rev = assessment["revision"]

            ap_res = store.create_assurance_profile_version(aid, rev, sample_assurance_profile())
            rev = ap_res["assessment"]["revision"]
            vid = ap_res["assurance_profile_version"]["assurance_profile_version_id"]
            store.activate_assurance_profile_version(aid, rev, vid)

            mp_res = store.create_measurement_point(aid, 3, sample_context(), "Point A")
            store.create_audit_run(aid, 4, "Run 1", vid, [mp_res["measurement_point"]["measurement_point_id"]])

            backup_path = Path(directory) / "backup.tar.gz"
            manifest = create_backup(directory, backup_path)
            self.assertEqual(manifest["backup_type"], "pineai_device_continuity")

            restore_dir = Path(directory) / "restored"
            restore_backup_staging(backup_path, restore_dir)

            restored_store = RepeatableAuditStore(restore_dir)
            runs_res = restored_store.list_audit_runs(aid)
            self.assertEqual(len(runs_res["audit_runs"]), 1)
            self.assertEqual(runs_res["audit_runs"][0]["audit_run"]["title"], "Run 1")

    def test_artifact_validation_and_digest_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            ensure_pseudonymization_key(directory)
            store = RepeatableAuditStore(directory)
            assessment = store.create({"name": "Artifact Verification Test", "location": "Lab", "notes": ""})
            aid = assessment["assessment_id"]

            ap_res = store.create_assurance_profile_version(aid, 1, sample_assurance_profile())
            vid = ap_res["assurance_profile_version"]["assurance_profile_version_id"]
            store.activate_assurance_profile_version(aid, 2, vid)

            mp_res = store.create_measurement_point(aid, 3, sample_context(), "Point A")
            mp_id = mp_res["measurement_point"]["measurement_point_id"]

            ar_res = store.create_audit_run(aid, 4, "Run 1", vid, [mp_id])
            run_id = ar_res["audit_run"]["audit_run_id"]
            store.start_audit_run(aid, 5, run_id, 1)

            # Missing snapshot file -> snapshot_not_found
            with self.assertRaises(BackendError) as raised:
                store.resolve_audit_measurement(aid, 6, run_id, 2, mp_id, {
                    "status": "resolved",
                    "snapshot_id": "snapshot_0000000000000099",
                    "snapshot_digest": "a" * 64,
                    "measurement_profile_id": "mprofile_00000000-0000-4000-8000-000000000001",
                    "measurement_profile_version_id": "mprofile_r0001",
                    "measurement_profile_digest": "b" * 64,
                    "baseline_version_id": "baseline_v0001",
                    "baseline_type": "consensus",
                    "baseline_model_id": "bmodel_0000000000000001",
                    "baseline_model_digest": "c" * 64,
                    "baseline_record_digest": "d" * 64,
                    "assurance_profile_version_id": vid,
                    "assurance_profile_digest": "e" * 64,
                    "comparability_status": "comparable",
                    "resolved_at": "2026-07-30T10:00:00Z",
                })
            self.assertEqual(raised.exception.code, "snapshot_not_found")

            # Create snapshot artifact with wrong digest -> invalid_snapshot
            snap_path = Path(directory) / "assessments" / aid / "snapshots" / "snapshot_0000000000000001.json"
            snap_path.parent.mkdir(parents=True, exist_ok=True)
            snap_path.write_text(json.dumps({"snapshot_id": "snapshot_0000000000000001"}), encoding="utf-8")

            with self.assertRaises(BackendError) as raised:
                store.resolve_audit_measurement(aid, 6, run_id, 2, mp_id, {
                    "status": "resolved",
                    "snapshot_id": "snapshot_0000000000000001",
                    "snapshot_digest": "0" * 64,  # wrong digest
                    "measurement_profile_id": "mprofile_00000000-0000-4000-8000-000000000001",
                    "measurement_profile_version_id": "mprofile_r0001",
                    "measurement_profile_digest": "b" * 64,
                    "baseline_version_id": "baseline_v0001",
                    "baseline_type": "consensus",
                    "baseline_model_id": "bmodel_0000000000000001",
                    "baseline_model_digest": "c" * 64,
                    "baseline_record_digest": "d" * 64,
                    "assurance_profile_version_id": vid,
                    "assurance_profile_digest": "e" * 64,
                    "comparability_status": "comparable",
                    "resolved_at": "2026-07-30T10:00:00Z",
                })
            self.assertEqual(raised.exception.code, "invalid_snapshot")

    def test_closure_reserve_late_status_field(self):
        with tempfile.TemporaryDirectory() as directory:
            ensure_pseudonymization_key(directory)
            store = RepeatableAuditStore(directory)
            assessment = store.create({"name": "Closure Reserve Test", "location": "Lab", "notes": ""})
            aid = assessment["assessment_id"]

            ap_res = store.create_assurance_profile_version(aid, 1, sample_assurance_profile())
            vid = ap_res["assurance_profile_version"]["assurance_profile_version_id"]
            store.activate_assurance_profile_version(aid, 2, vid)

            mp_res = store.create_measurement_point(aid, 3, sample_context(), "Point A")
            mp_id = mp_res["measurement_point"]["measurement_point_id"]

            ar_res = store.create_audit_run(aid, 4, "Run Late Status", vid, [mp_id])
            ar_id = ar_res["audit_run"]["audit_run_id"]

            # Overwrite ar_<id>.json so "status": "draft" is padded past 512 bytes
            run_path = Path(directory) / "assessments" / aid / "audit_runs" / f"{ar_id}.json"
            data = json.loads(run_path.read_text(encoding="utf-8"))
            data["padding"] = "X" * 1024  # push status field down
            run_path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")

            # Remove manifest file to force recalculation from disk
            manifest_path = Path(directory) / "assessments" / aid / "audit_runs_manifest.json"
            if manifest_path.exists():
                manifest_path.unlink()

            capacity = store.get_assessment_capacity(aid)
            self.assertEqual(capacity["event_reserved_for_run_closure"], 1)


if __name__ == "__main__":
    unittest.main()
