import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "projects" / "PineAI" / "src" / "assets"
sys.path.insert(0, str(ASSETS))

from pineai_backend.assessment_store import _canonical_digest  # noqa: E402
from pineai_backend.assurance_service import AssuranceService  # noqa: E402
from pineai_backend.backup import create_backup, restore_backup_staging  # noqa: E402
from pineai_backend.config import ensure_pseudonymization_key  # noqa: E402
from pineai_backend.errors import BackendError  # noqa: E402
from pineai_backend.repeatable_audit_store import RepeatableAuditStore  # noqa: E402

SCHEMA_PATH = ROOT / "docs" / "schemas" / "repeatable-audits-v1.schema.json"
RECON_FIXTURE_PATH = ROOT / "tests" / "fixtures" / "recon_basic.json"
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
        "declared_bands": ["2.4"],
        "declared_channels": [1, 6, 11],
        "scan_time": 180,
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


def fixture_scan():
    return json.loads(RECON_FIXTURE_PATH.read_text(encoding="utf-8"))


def utc_now():
    return (
        datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def measurement_profile_input():
    return {
        "name": "Repeatable audit point",
        "description": "Saved Recon test profile",
        "location_id": "building-a",
        "measurement_point_id": "point-a",
        "scan_profile_id": "fast-scan",
        "radio_profile_id": "wlan1-mk7",
        "interface": "wlan1mon",
        "declared_bands": ["2.4"],
        "declared_channels": [1, 6, 11],
        "scan_time": 180,
        "is_default": True,
        "five_ghz_operator_confirmed": False,
    }


def scan_metadata(measurement_profile, hour):
    version = measurement_profile["active_version"]
    return {
        "scan_id": "saved-scan-{0}".format(hour),
        "date": "2026-07-30T{0:02d}:00:00Z".format(hour),
        "scan_time": 180,
        "coverage": ["2.4"],
        "source": "hak5_recon",
        "measurement_context": {
            "location_id": "building-a",
            "measurement_point_id": "point-a",
            "scan_profile_id": "fast-scan",
            "radio_profile_id": "wlan1-mk7",
            "interface": "wlan1mon",
            "declared_bands": ["2.4"],
            "declared_channels": [1, 6, 11],
            "measurement_profile_id": measurement_profile[
                "measurement_profile_id"
            ],
            "measurement_profile_version_id": version["version_id"],
            "measurement_profile_digest": version["digest"],
        },
    }


def inventory_csv():
    return (
        "site,ssid,bssid,vendor,role,approved,name,required_presence,"
        "allowed_encryption_codes,wps_allowed,allowed_channels,"
        "allowed_vendors,notes\n"
        "Test,Example-Corp,AA:BB:CC:00:00:01,Unknown,corporate,true,"
        "AP1,true,5,true,1,,\n"
    )


def make_valid_snapshot(suffix="1"):
    digest_char = suffix[-1]
    digest = digest_char * 64
    snapshot_id = "snapshot_{0}".format(digest[:16])
    ap_id = "ap_aaaaaaaaaaaa"
    net_id = "network_bbbbbbbbbbbb"
    ev_id = "evidence_cccccccccccc"
    snap = {
        "schema_version": "1.0",
        "snapshot_id": snapshot_id,
        "snapshot_digest": digest,
        "observed_at": "2026-07-27T12:00:00Z",
        "scan_metadata": {
            "scan_id": f"local-scan-{suffix}",
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
            "associated_client_count": 0,
            "out_of_range_client_count": 0,
            "unassociated_client_count": 0,
            "input_bytes": 512,
        },
        "access_points": [
            {
                "asset_id": ap_id,
                "network_id": net_id,
                "evidence_id": ev_id,
                "bssid": "AA:BB:CC:DD:EE:FF",
                "ssid": "Factory-WiFi",
                "hidden": False,
                "encryption": 4,
                "wps": False,
                "channel": 6,
                "band": "2.4",
                "signal": -42,
                "vendor": "Example",
                "client_count": 0,
                "data": 100,
                "probes": 4,
                "last_seen": 1000,
            }
        ],
        "networks": [
            {
                "network_id": net_id,
                "ssid": "Factory-WiFi",
                "hidden": False,
                "asset_ids": [ap_id],
                "bssids": ["AA:BB:CC:DD:EE:FF"],
                "channels": [6],
                "encryption_codes": [4],
                "vendors": ["Example"],
                "client_count": 0,
            }
        ],
        "evidence": [
            {
                "evidence_id": ev_id,
                "snapshot_id": snapshot_id,
                "evidence_type": "recon_access_point_observation",
                "subject_id": ap_id,
                "observed": {
                    "network_id": net_id,
                    "bssid": "AA:BB:CC:DD:EE:FF",
                    "ssid": "Factory-WiFi",
                    "hidden": False,
                    "encryption": 4,
                    "wps": False,
                    "channel": 6,
                    "signal": -42,
                    "vendor": "Example",
                    "client_count": 0,
                },
            }
        ],
    }
    return snap


def current_revision(store, assessment_id):
    return store.get(assessment_id, 0, 1)["revision"]


def setup_native_customer_analysis(directory):
    """Create artifacts only through the production CustomerAuditStore writer."""
    service = AssuranceService(config_dir=directory)
    measurement_profile = service.create_measurement_profile(
        measurement_profile_input()
    )["measurement_profile"]
    assessment = service.create_assessment(
        {"name": "Native artifact test", "location": "Lab", "notes": ""}
    )
    aid = assessment["assessment_id"]
    baseline = service.create_baseline_version(
        aid,
        assessment["revision"],
        fixture_scan(),
        scan_metadata(measurement_profile, 10),
        "Approved baseline",
    )
    assessment = service.store.activate_baseline_version(
        aid,
        baseline["assessment"]["revision"],
        baseline["baseline_version"]["baseline_version_id"],
    )["assessment"]
    inventory = service.preview_inventory_csv(inventory_csv(), "comma")
    assurance = service.create_assurance_profile_version(
        aid,
        assessment["revision"],
        "Approved inventory",
        inventory_preview=inventory,
        coverage_mode="partial",
    )
    assessment = service.activate_assurance_profile_version(
        aid,
        assurance["assessment"]["revision"],
        assurance["assurance_profile_version"][
            "assurance_profile_version_id"
        ],
        False,
    )["assessment"]
    current_scan = fixture_scan()
    current_scan["APResults"][0]["channel"] = 6
    metadata = scan_metadata(measurement_profile, 11)
    preview = service.compare_recon(aid, current_scan, metadata)
    persisted = service.analyze_recon(
        aid, assessment["revision"], current_scan, metadata
    )
    occurrence = service.store.get_occurrence_set(
        aid, persisted["comparison"]["comparison_id"]
    )
    baseline_record = service.store.get_baseline_version(
        aid, baseline["baseline_version"]["baseline_version_id"]
    )
    return {
        "service": service,
        "store": RepeatableAuditStore(directory),
        "assessment_id": aid,
        "measurement_profile": measurement_profile,
        "assurance_profile_version_id": assurance[
            "assurance_profile_version"
        ]["assurance_profile_version_id"],
        "baseline": baseline_record,
        "preview": preview,
        "persisted": persisted,
        "occurrence": occurrence,
    }


def resolved_outcome(native):
    snapshot = native["preview"]["current_snapshot"]
    baseline = native["baseline"]
    pins = native["persisted"]["comparison"]["pinned_versions"]
    return {
        "status": "resolved",
        "source_recon_id": "saved-scan-11",
        "snapshot_id": snapshot["snapshot_id"],
        "snapshot_digest": snapshot["snapshot_digest"],
        "measurement_profile_id": pins["measurement_profile_id"],
        "measurement_profile_version_id": pins[
            "measurement_profile_version_id"
        ],
        "measurement_profile_digest": pins["measurement_profile_digest"],
        "baseline_version_id": pins["baseline_version_id"],
        "baseline_type": "single_scan",
        "baseline_snapshot_id": baseline["snapshot_id"],
        "baseline_snapshot_digest": baseline["snapshot_digest"],
        "baseline_record_digest": _canonical_digest(
            {
                key: value
                for key, value in baseline.items()
                if key
                not in {
                    "snapshot",
                    "is_active",
                    "baseline_type",
                    "legacy",
                }
            }
        ),
        "assurance_profile_version_id": pins[
            "assurance_profile_version_id"
        ],
        "assurance_profile_digest": pins["assurance_profile_digest"],
        "comparability_status": native["preview"]["diff"]["comparability"][
            "status"
        ],
        "resolved_at": utc_now(),
    }


def completed_outcome(native):
    comparison = native["persisted"]["comparison"]
    evidence_ids = [
        item["evidence_id"] for item in native["occurrence"]["evidence"]
    ][:100]
    return {
        "status": "completed",
        "comparison_id": comparison["comparison_id"],
        # Canonical hash of the complete native outer comparison record.
        "comparison_digest": _canonical_digest(comparison),
        "occurrence_set_id": comparison["occurrence_set_id"],
        "evidence_ids": evidence_ids,
        "completed_at": utc_now(),
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
            native = setup_native_customer_analysis(directory)
            store = native["store"]
            aid = native["assessment_id"]
            vid = native["assurance_profile_version_id"]
            mp_res = store.create_measurement_point(
                aid, current_revision(store, aid), sample_context(), "Point A"
            )
            mp_id = mp_res["measurement_point"]["measurement_point_id"]

            ar_res = store.create_audit_run(
                aid, current_revision(store, aid), "Run 1", vid, [mp_id]
            )
            validate_schema(ar_res, "createAuditRunResponse")
            run = ar_res["audit_run"]
            self.assertEqual(run["status"], "draft")
            self.assertEqual(ar_res["ready_to_start"], True)
            self.assertNotIn("measurements", run)
            self.assertNotIn("ready_to_start", run)

            start_res = store.start_audit_run(
                aid,
                current_revision(store, aid),
                run["audit_run_id"],
                run["revision"],
            )
            validate_schema(start_res, "startAuditRunResponse")
            self.assertEqual(start_res["audit_run"]["status"], "in_progress")

            res_out = store.resolve_audit_measurement(
                aid,
                current_revision(store, aid),
                run["audit_run_id"],
                2,
                mp_id,
                resolved_outcome(native),
            )
            validate_schema(res_out, "resolveAuditMeasurementResponse")
            self.assertEqual(res_out["measurement"]["measurement_id"].startswith("arm_"), True)

            comp_out = store.save_audit_measurement_comparison(
                aid,
                current_revision(store, aid),
                run["audit_run_id"],
                3,
                mp_id,
                completed_outcome(native),
            )
            validate_schema(comp_out, "saveAuditMeasurementComparisonResponse")

            comp_run_res = store.complete_audit_run(
                aid,
                current_revision(store, aid),
                run["audit_run_id"],
                4,
            )
            validate_schema(comp_run_res, "completeAuditRunResponse")
            self.assertEqual(comp_run_res["audit_run"]["status"], "completed")

            with self.assertRaises(BackendError) as raised:
                store.start_audit_run(
                    aid,
                    current_revision(store, aid),
                    run["audit_run_id"],
                    5,
                )
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
                    "failed_at": utc_now(),
            })

            # Try completing with failed measurement -> fails
            with self.assertRaises(BackendError) as raised:
                store.complete_audit_run(aid, 7, run_id, 3)
            self.assertEqual(raised.exception.code, "invalid_audit_run_transition")

    def test_evidence_limit_and_no_raw_recon(self):
        with tempfile.TemporaryDirectory() as directory:
            native = setup_native_customer_analysis(directory)
            store = native["store"]
            aid = native["assessment_id"]
            vid = native["assurance_profile_version_id"]
            mp_res = store.create_measurement_point(
                aid, current_revision(store, aid), sample_context(), "Point 1"
            )
            mp_id = mp_res["measurement_point"]["measurement_point_id"]
            ar_res = store.create_audit_run(
                aid, current_revision(store, aid), "Run 1", vid, [mp_id]
            )
            run_id = ar_res["audit_run"]["audit_run_id"]

            store.start_audit_run(
                aid, current_revision(store, aid), run_id, 1
            )

            # Raw recon keys rejected
            with self.assertRaises(BackendError) as raised:
                store.resolve_audit_measurement(
                    aid,
                    current_revision(store, aid),
                    run_id,
                    2,
                    mp_id,
                    {"status": "resolved", "recon": {"raw": "data"}},
                )
            self.assertEqual(raised.exception.code, "invalid_audit_run_measurement")

            store.resolve_audit_measurement(
                aid,
                current_revision(store, aid),
                run_id,
                2,
                mp_id,
                resolved_outcome(native),
            )

            # 101 evidence_ids rejected
            too_many = ["evidence_{0:012d}".format(i) for i in range(101)]
            invalid = completed_outcome(native)
            invalid["evidence_ids"] = too_many
            with self.assertRaises(BackendError) as raised:
                store.save_audit_measurement_comparison(
                    aid,
                    current_revision(store, aid),
                    run_id,
                    3,
                    mp_id,
                    invalid,
                )
            self.assertEqual(raised.exception.code, "invalid_audit_run_measurement")

            # Duplicate evidence_ids rejected
            invalid = completed_outcome(native)
            first_evidence = invalid["evidence_ids"][0]
            invalid["evidence_ids"] = [first_evidence, first_evidence]
            with self.assertRaises(BackendError) as raised:
                store.save_audit_measurement_comparison(
                    aid,
                    current_revision(store, aid),
                    run_id,
                    3,
                    mp_id,
                    invalid,
                )
            self.assertEqual(raised.exception.code, "invalid_audit_run_measurement")

            comp_res = store.save_audit_measurement_comparison(
                aid,
                current_revision(store, aid),
                run_id,
                3,
                mp_id,
                completed_outcome(native),
            )
            self.assertEqual(
                comp_res["measurement"]["evidence_ids"],
                completed_outcome(native)["evidence_ids"],
            )

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

            # Keep the exact private schema but serialize status last. This
            # proves reconstruction parses the complete JSON document rather
            # than searching a fixed prefix.
            run_path = Path(directory) / "assessments" / aid / "audit_runs" / f"{ar_id}.json"
            data = json.loads(run_path.read_text(encoding="utf-8"))
            reordered = {
                key: value for key, value in data.items() if key != "status"
            }
            reordered["status"] = data["status"]
            run_path.write_text(
                json.dumps(reordered, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            self.assertGreater(
                run_path.read_text(encoding="utf-8").index('"status"'), 512
            )

            # Remove manifest file to force recalculation from disk
            manifest_path = Path(directory) / "assessments" / aid / "audit_runs_manifest.json"
            if manifest_path.exists():
                manifest_path.unlink()

            capacity = store.get_assessment_capacity(aid)
            self.assertEqual(capacity["event_reserved_for_run_closure"], 1)

    def test_strict_rfc3339_datetime_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            ensure_pseudonymization_key(directory)
            store = RepeatableAuditStore(directory)
            assessment = store.create({"name": "RFC3339 Test", "location": "Lab", "notes": ""})
            aid = assessment["assessment_id"]
            rev = assessment["revision"]

            ap_res = store.create_assurance_profile_version(aid, rev, sample_assurance_profile())
            rev = ap_res["assessment"]["revision"]
            vid = ap_res["assurance_profile_version"]["assurance_profile_version_id"]
            store.activate_assurance_profile_version(aid, rev, vid)

            mp_res = store.create_measurement_point(aid, 3, sample_context(), "Point A")
            mp_id = mp_res["measurement_point"]["measurement_point_id"]

            # 1. Negative tests for due_at (error_code: invalid_audit_run)
            invalid_due_ats = [
                "2026-07-30",                   # Date only
                "2026-07-30T10:00:00",          # Naive (no timezone)
                "2026-07-30 10:00:00Z",         # Space separator
                "2026-02-31T10:00:00Z",         # Invalid calendar date
                "2026-07-30T10:00:00+25:00",    # Invalid timezone offset
            ]
            for bad_dt in invalid_due_ats:
                with self.assertRaises(BackendError) as raised:
                    store.create_audit_run(aid, 4, "Bad Due At", vid, [mp_id], due_at=bad_dt)
                self.assertEqual(raised.exception.code, "invalid_audit_run")

            # 2. Positive test for due_at (accepted RFC 3339 forms)
            valid_due_ats = [
                "2026-07-30T10:00:00Z",
                "2026-07-30T10:00:00.123456Z",
                "2026-07-30T10:00:00+02:00",
                "2026-07-30T10:00:00-05:00",
            ]
            for idx, ok_dt in enumerate(valid_due_ats):
                ar_out = store.create_audit_run(aid, 4 + idx, f"Run {idx}", vid, [mp_id], due_at=ok_dt)
                self.assertEqual(ar_out["audit_run"]["due_at"], ok_dt)

            # 3. Negative tests for measurement timestamps (resolved_at, completed_at, failed_at -> invalid_audit_run_measurement)
            run_id = store.create_audit_run(aid, 8, "Measurement Test Run", vid, [mp_id])["audit_run"]["audit_run_id"]
            store.start_audit_run(aid, 9, run_id, 1)

            snapshot = make_valid_snapshot("9")
            snapshot_path = (
                Path(directory)
                / "assessments"
                / aid
                / "snapshots"
                / (snapshot["snapshot_id"] + ".json")
            )
            snapshot_path.parent.mkdir(parents=True, exist_ok=True)
            snapshot_path.write_text(
                json.dumps(snapshot, ensure_ascii=False, indent=2, sort_keys=True)
                + "\n",
                encoding="utf-8",
            )
            bad_resolved_at = "2026-07-30T10:00:00"  # naive
            with self.assertRaises(BackendError) as raised:
                store.resolve_audit_measurement(aid, 10, run_id, 2, mp_id, {
                    "status": "resolved",
                    "snapshot_id": snapshot["snapshot_id"],
                    "snapshot_digest": snapshot["snapshot_digest"],
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
                    "resolved_at": bad_resolved_at,
                })
            self.assertEqual(raised.exception.code, "invalid_audit_run_measurement")

    def test_read_only_manifest_reconstruction_does_not_write_disk(self):
        with tempfile.TemporaryDirectory() as directory:
            ensure_pseudonymization_key(directory)
            store = RepeatableAuditStore(directory)
            assessment = store.create({"name": "Read-Only Manifest Test", "location": "Lab", "notes": ""})
            aid = assessment["assessment_id"]

            ap_res = store.create_assurance_profile_version(aid, 1, sample_assurance_profile())
            vid = ap_res["assurance_profile_version"]["assurance_profile_version_id"]
            store.activate_assurance_profile_version(aid, 2, vid)

            mp_res = store.create_measurement_point(aid, 3, sample_context(), "Point A")
            mp_id = mp_res["measurement_point"]["measurement_point_id"]

            store.create_audit_run(aid, 4, "Run 1", vid, [mp_id])

            manifest_path = Path(directory) / "assessments" / aid / "audit_runs_manifest.json"
            self.assertTrue(manifest_path.exists())

            # Delete manifest file on disk
            manifest_path.unlink()
            self.assertFalse(manifest_path.exists())

            # Call read-only operations (list, get, capacity)
            store.list_audit_runs(aid)
            store.get_assessment_capacity(aid)

            # Manifest must NOT have been written back to disk
            self.assertFalse(manifest_path.exists())


if __name__ == "__main__":
    unittest.main()
