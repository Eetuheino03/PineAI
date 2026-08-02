import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "projects" / "PineAI" / "src" / "assets"
sys.path.insert(0, str(ASSETS))

from pineai_backend.assurance_service import AssuranceService  # noqa: E402
from pineai_backend.assessment_store import MAX_SNAPSHOTS  # noqa: E402
from pineai_backend.audit_run_report import AuditRunReportService  # noqa: E402
from pineai_backend.backup import (  # noqa: E402
    create_backup,
    restore_backup_staging,
    verify_backup,
)
from pineai_backend.config import ensure_pseudonymization_key  # noqa: E402
from pineai_backend.customer_analysis import (  # noqa: E402
    evidence_records,
    lifecycle_findings,
)
from pineai_backend.errors import BackendError  # noqa: E402
from pineai_backend.repeatable_audit_store import (  # noqa: E402
    MAX_ACTIVE_MEASUREMENT_POINTS,
    MAX_AUDIT_RUNS_PER_ASSESSMENT,
    MAX_MEASUREMENT_POINTS_PER_RUN,
    MAX_TOTAL_MEASUREMENT_POINT_RECORDS,
    RepeatableAuditStore,
    _rfc3339_order_key,
    _validate_rfc3339,
)


RECON_FIXTURE = ROOT / "tests" / "fixtures" / "recon_basic.json"


class RepeatableAuditStoreV070Tests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = self.temporary.name
        ensure_pseudonymization_key(self.directory)
        store = RepeatableAuditStore(self.directory)
        service = AssuranceService(config_dir=self.directory, store=store)
        self.service = service
        self.profile = service.create_measurement_profile(
            {
                "name": "Repeatable profile",
                "description": "",
                "scan_profile_id": "saved-recon",
                "radio_profile_id": "wlan1",
                "interface": "wlan1mon",
                "declared_bands": ["2.4"],
                "declared_channels": [1, 6, 11],
                "scan_time": 180,
                "is_default": True,
                "five_ghz_operator_confirmed": False,
            }
        )["measurement_profile"]
        assessment = service.create_assessment(
            {"name": "v0.7 fixture", "location": "Lab", "notes": ""}
        )
        self.assessment_id = assessment["assessment_id"]
        point = service.store.create_measurement_point(
            self.assessment_id,
            assessment["revision"],
            "Fixture point",
            "Beside the door",
            "Hold the device at shoulder height",
        )
        self.default_point_id = point["measurement_point"][
            "measurement_point_id"
        ]
        scan = json.loads(RECON_FIXTURE.read_text(encoding="utf-8"))
        baseline = service.create_baseline_version(
            self.assessment_id,
            point["assessment_revision"],
            scan,
            self.scan_metadata("baseline", "2026-07-31T10:00:00Z"),
            "Approved baseline",
        )
        self.baseline_version_id = baseline["baseline_version"][
            "baseline_version_id"
        ]
        inventory = service.preview_inventory_csv(
            "site,ssid,bssid,vendor,role,approved\n"
            "Lab,Example-Corp,AA:BB:CC:00:00:01,Unknown,corp,true\n",
            "comma",
        )
        assurance = service.create_assurance_profile_version(
            self.assessment_id,
            baseline["assessment"]["revision"],
            "Approved inventory",
            inventory_preview=inventory,
            coverage_mode="partial",
        )
        self.assurance_version_id = assurance["assurance_profile_version"][
            "assurance_profile_version_id"
        ]
        self.store = store

    def scan_metadata(self, scan_id, observed_at):
        version = self.profile["active_version"]
        return {
            "scan_id": scan_id,
            "date": observed_at,
            "scan_time": 180,
            "coverage": ["2.4"],
            "source": "hak5_recon",
            "measurement_context": {
                "location_id": "lab",
                "measurement_point_id": self.default_point_id,
                "scan_profile_id": "saved-recon",
                "radio_profile_id": "wlan1",
                "interface": "wlan1mon",
                "declared_bands": ["2.4"],
                "declared_channels": [1, 6, 11],
                "measurement_profile_id": self.profile[
                    "measurement_profile_id"
                ],
                "measurement_profile_version_id": version["version_id"],
                "measurement_profile_digest": version["digest"],
            },
        }

    def revision(self):
        return self.store.get(self.assessment_id, 0, 1)["revision"]

    def create_point(self, label="North wall"):
        return self.store.create_measurement_point(
            self.assessment_id,
            self.revision(),
            label,
            "Beside the door",
            "Hold the device at shoulder height",
        )

    def run_request(self, point_id, name="Round one"):
        version = self.profile["active_version"]
        return {
            "name": name,
            "description": "Repeatable fixture",
            "assurance_profile_version_id": self.assurance_version_id,
            "assignments": [
                {
                    "measurement_point_id": point_id,
                    "measurement_profile_id": self.profile[
                        "measurement_profile_id"
                    ],
                    "measurement_profile_version_id": version["version_id"],
                    "baseline_version_id": self.baseline_version_id,
                }
            ],
        }

    def create_run(self, name="Round one"):
        return self.store.create_audit_run(
            self.assessment_id,
            self.revision(),
            self.run_request(self.default_point_id, name),
        )

    def test_archived_measurement_profile_cannot_be_assigned_to_new_run(self):
        profile_id = self.profile["measurement_profile_id"]
        self.store.archive_measurement_profile(
            profile_id, self.profile["revision"]
        )

        with self.assertRaises(BackendError) as raised:
            self.create_run()

        self.assertEqual(raised.exception.code, "pinned_reference_missing")

    def test_existing_run_keeps_immutable_profile_pin_after_archive(self):
        created = self.create_run()
        profile_id = self.profile["measurement_profile_id"]
        self.store.archive_measurement_profile(
            profile_id, self.profile["revision"]
        )

        reopened = RepeatableAuditStore(self.directory)
        fetched = reopened.get_audit_run(
            self.assessment_id, created["audit_run"]["audit_run_id"]
        )
        self.assertTrue(fetched["ready_to_start"])
        assessment_revision = reopened.get(
            self.assessment_id, 0, 1
        )["revision"]
        started = reopened.start_audit_run(
            self.assessment_id,
            assessment_revision,
            fetched["audit_run"]["audit_run_id"],
            fetched["audit_run"]["revision"],
        )
        self.assertEqual(started["audit_run"]["status"], "in_progress")

    def test_frozen_limits_and_physical_point_contract(self):
        self.assertEqual(MAX_ACTIVE_MEASUREMENT_POINTS, 16)
        self.assertEqual(MAX_TOTAL_MEASUREMENT_POINT_RECORDS, 32)
        self.assertEqual(MAX_MEASUREMENT_POINTS_PER_RUN, 16)
        self.assertEqual(MAX_AUDIT_RUNS_PER_ASSESSMENT, 32)
        result = self.create_point()
        point = result["measurement_point"]
        self.assertIn("assessment_capacity", result)
        self.assertEqual(point["location_label"], "North wall")
        self.assertNotIn("expected_measurement_context", point)
        self.assertEqual(point["operator_instructions"], "Hold the device at shoulder height")

    def test_point_responses_include_capacity_and_reject_legacy_aliases(self):
        created = self.create_point()
        point = created["measurement_point"]
        point_id = point["measurement_point_id"]
        listed = self.store.list_measurement_points(self.assessment_id)
        fetched = self.store.get_measurement_point(
            self.assessment_id, point_id
        )
        self.assertIn("assessment_capacity", listed)
        self.assertIn("assessment_capacity", fetched)
        with self.assertRaises(BackendError) as raised:
            self.store.update_measurement_point(
                self.assessment_id,
                created["assessment_revision"],
                point_id,
                point["revision"],
                {"name": "Legacy alias"},
            )
        self.assertEqual(raised.exception.code, "invalid_measurement_point")
        updated = self.store.update_measurement_point(
            self.assessment_id,
            created["assessment_revision"],
            point_id,
            point["revision"],
            {"location_label": "North doorway"},
        )
        self.assertIn("assessment_capacity", updated)
        archived = self.store.archive_measurement_point(
            self.assessment_id,
            updated["assessment_revision"],
            point_id,
            updated["measurement_point"]["revision"],
        )
        self.assertIn("assessment_capacity", archived)
        self.assertEqual(archived["measurement_point"]["status"], "archived")

    def test_untyped_identifiers_and_action_text_fail_closed(self):
        revision_before = self.revision()
        for invalid_id in (None, 1, True, [], {}):
            with self.subTest(kind="point", value=invalid_id):
                with self.assertRaises(BackendError) as point_error:
                    self.store.get_measurement_point(
                        self.assessment_id, invalid_id
                    )
                self.assertEqual(
                    point_error.exception.code, "invalid_measurement_point"
                )
            with self.subTest(kind="run", value=invalid_id):
                with self.assertRaises(BackendError) as run_error:
                    self.store.get_audit_run(self.assessment_id, invalid_id)
                self.assertEqual(run_error.exception.code, "invalid_audit_run")
        with self.assertRaises(BackendError) as label_error:
            self.store.create_measurement_point(
                self.assessment_id,
                revision_before,
                None,
                None,
                None,
            )
        self.assertEqual(label_error.exception.code, "invalid_measurement_point")
        self.assertEqual(self.revision(), revision_before)

    def test_v11_mutation_fault_recovers_atomically(self):
        calls = []
        armed = [False]

        def fault_injector(stage, index):
            calls.append((stage, index))
            if armed[0] and stage == "prepared":
                raise RuntimeError("simulated crash after journal prepared")

        store = RepeatableAuditStore(
            self.directory, fault_injector=fault_injector
        )
        before = len(
            store.list_measurement_points(
                self.assessment_id, include_archived=True
            )["measurement_points"]
        )
        armed[0] = True
        with self.assertRaises(RuntimeError):
            store.create_measurement_point(
                self.assessment_id,
                self.revision(),
                "Recovered point",
                None,
                None,
            )
        self.assertTrue(any(stage == "prepared" for stage, _ in calls))
        reopened = RepeatableAuditStore(self.directory)
        points = reopened.list_measurement_points(
            self.assessment_id, include_archived=True
        )["measurement_points"]
        self.assertEqual(len(points), before + 1)
        self.assertTrue(
            any(item["location_label"] == "Recovered point" for item in points)
        )

    def test_read_only_reconstruction_does_not_mutate_storage(self):
        created = self.create_run()
        root = Path(self.directory) / "assessments" / self.assessment_id

        def state():
            return {
                path.relative_to(root).as_posix(): (
                    path.read_bytes(),
                    path.stat().st_mtime_ns,
                )
                for path in root.rglob("*")
                if path.is_file() and not path.is_symlink()
            }

        before = state()
        self.store.list_audit_runs(self.assessment_id)
        self.store.get_audit_run(
            self.assessment_id, created["audit_run"]["audit_run_id"]
        )
        self.store.get_assessment_capacity(self.assessment_id)
        self.assertEqual(state(), before)

    def test_capacity_reads_headers_without_assembling_runs(self):
        self.create_run("Header one")
        self.create_run("Header two")
        self.create_run("Header three")
        with mock.patch.object(
            self.store,
            "_assemble_v11_run_unlocked",
            wraps=self.store._assemble_v11_run_unlocked,
        ) as assembler:
            capacity = self.store.get_assessment_capacity(
                self.assessment_id
            )
        self.assertEqual(capacity["audit_run_used"], 3)
        assembler.assert_not_called()

    def test_list_paginates_before_structural_assembly(self):
        self.create_run("Page one")
        self.create_run("Page two")
        self.create_run("Page three")
        with mock.patch.object(
            self.store,
            "_assemble_v11_run_unlocked",
            wraps=self.store._assemble_v11_run_unlocked,
        ) as assembler:
            result = self.store.list_audit_runs(
                self.assessment_id, limit=1
            )
        self.assertEqual(result["total"], 3)
        self.assertEqual(len(result["audit_runs"]), 1)
        self.assertEqual(assembler.call_count, 1)
        self.assertFalse(
            assembler.call_args.kwargs["validate_artifacts"]
        )

    def test_list_reuses_immutable_pin_validation_across_draft_runs(self):
        self.create_run("Cached one")
        self.create_run("Cached two")
        self.create_run("Cached three")
        with mock.patch.object(
            self.store,
            "_load_baseline_assignment_unlocked",
            wraps=self.store._load_baseline_assignment_unlocked,
        ) as baseline_loader, mock.patch.object(
            self.store,
            "_load_measurement_profile_assignment_unlocked",
            wraps=self.store._load_measurement_profile_assignment_unlocked,
        ) as profile_loader, mock.patch.object(
            self.store,
            "_load_assurance_profile_pin_unlocked",
            wraps=self.store._load_assurance_profile_pin_unlocked,
        ) as assurance_loader:
            result = self.store.list_audit_runs(
                self.assessment_id, limit=3
            )
        self.assertEqual(len(result["audit_runs"]), 3)
        self.assertTrue(
            all(item["ready_to_start"] for item in result["audit_runs"])
        )
        self.assertEqual(baseline_loader.call_count, 1)
        self.assertEqual(profile_loader.call_count, 1)
        self.assertEqual(assurance_loader.call_count, 1)

    def test_get_assembles_only_the_requested_run(self):
        first = self.create_run("Requested")
        self.create_run("Unrelated one")
        self.create_run("Unrelated two")
        with mock.patch.object(
            self.store,
            "_assemble_v11_run_unlocked",
            wraps=self.store._assemble_v11_run_unlocked,
        ) as assembler:
            result = self.store.get_audit_run(
                self.assessment_id,
                first["audit_run"]["audit_run_id"],
            )
        self.assertEqual(
            result["audit_run"]["audit_run_id"],
            first["audit_run"]["audit_run_id"],
        )
        self.assertEqual(assembler.call_count, 1)

    def test_create_and_start_do_not_assemble_unrelated_runs(self):
        first = self.create_run("Existing one")
        self.create_run("Existing two")
        with mock.patch.object(
            self.store,
            "_assemble_v11_run_unlocked",
            wraps=self.store._assemble_v11_run_unlocked,
        ) as create_assembler:
            third = self.create_run("New run")
        create_assembler.assert_not_called()

        with mock.patch.object(
            self.store,
            "_assemble_v11_run_unlocked",
            wraps=self.store._assemble_v11_run_unlocked,
        ) as start_assembler:
            started = self.store.start_audit_run(
                self.assessment_id,
                third["assessment_revision"],
                first["audit_run"]["audit_run_id"],
                first["audit_run"]["revision"],
            )
        self.assertEqual(started["audit_run"]["status"], "in_progress")
        self.assertEqual(start_assembler.call_count, 1)

    def test_closure_reserve_is_reconstructed_from_validated_runs(self):
        first = self.create_run("Reserve one")
        second = self.create_run("Reserve two")
        capacity = self.store.get_assessment_capacity(self.assessment_id)
        self.assertEqual(capacity["event_reserved_for_run_closure"], 2)
        cancelled = self.store.cancel_audit_run(
            self.assessment_id,
            second["assessment_revision"],
            second["audit_run"]["audit_run_id"],
            second["audit_run"]["revision"],
            "No longer required",
        )
        self.assertEqual(cancelled["audit_run"]["status"], "cancelled")
        capacity = self.store.get_assessment_capacity(self.assessment_id)
        self.assertEqual(capacity["event_reserved_for_run_closure"], 1)
        self.assertEqual(
            first["audit_run"]["status"], "draft"
        )

    def test_split_layout_and_pinned_provenance(self):
        result = self.create_run()
        run = result["audit_run"]
        measurement = result["measurements"][0]
        base = (
            Path(self.directory)
            / "assessments"
            / self.assessment_id
            / "audit_runs"
            / run["audit_run_id"]
        )
        self.assertTrue((base / "manifest.json").is_file())
        self.assertTrue(
            (base / "measurements" / (measurement["measurement_id"] + ".json")).is_file()
        )
        self.assertFalse((base.parent / (run["audit_run_id"] + ".json")).exists())
        self.assertEqual(measurement["provenance_status"], "pinned")
        self.assertEqual(
            measurement["measurement_point_snapshot"]["location_label"],
            "Fixture point",
        )
        self.assertEqual(len(measurement["baseline_digest"]), 64)

    def test_audit_run_rejects_baseline_from_another_measurement_point(self):
        other = self.create_point("Other point")
        with self.assertRaises(BackendError) as raised:
            self.store.create_audit_run(
                self.assessment_id,
                other["assessment_revision"],
                self.run_request(
                    other["measurement_point"]["measurement_point_id"],
                    "Cross-point run",
                ),
            )
        self.assertEqual(raised.exception.code, "pinned_reference_mismatch")

    def test_split_audit_run_backup_verify_and_restore_round_trip(self):
        created = self.create_run("Backup round")
        run = created["audit_run"]
        measurement = created["measurements"][0]
        with tempfile.TemporaryDirectory() as output_directory:
            archive = Path(output_directory) / "pineassure-v070.tar.gz"
            created_backup = create_backup(self.directory, str(archive))
            self.assertGreater(created_backup["file_count"], 0)
            self.assertTrue(verify_backup(str(archive))["verified"])
            target = Path(output_directory) / "restore"
            restored = restore_backup_staging(str(archive), str(target))
            self.assertTrue(restored["restored"])
            relative_run = (
                Path("assessments")
                / self.assessment_id
                / "audit_runs"
                / run["audit_run_id"]
            )
            for relative in (
                relative_run / "manifest.json",
                relative_run
                / "measurements"
                / (measurement["measurement_id"] + ".json"),
            ):
                self.assertEqual(
                    (target / relative).read_bytes(),
                    (Path(self.directory) / relative).read_bytes(),
                )
            restored_store = RepeatableAuditStore(str(target))
            restored_run = restored_store.get_audit_run(
                self.assessment_id, run["audit_run_id"]
            )
            self.assertEqual(
                restored_run["measurements"][0]["measurement_id"],
                measurement["measurement_id"],
            )

    def test_only_one_in_progress_run_and_implicit_resume(self):
        first = self.create_run("First")
        first_started = self.store.start_audit_run(
            self.assessment_id,
            first["assessment_revision"],
            first["audit_run"]["audit_run_id"],
            first["audit_run"]["revision"],
        )
        second = self.create_run("Second")
        with self.assertRaises(BackendError) as raised:
            self.store.start_audit_run(
                self.assessment_id,
                second["assessment_revision"],
                second["audit_run"]["audit_run_id"],
                second["audit_run"]["revision"],
            )
        self.assertEqual(raised.exception.code, "active_audit_run_exists")
        reopened = RepeatableAuditStore(self.directory).get_audit_run(
            self.assessment_id, first["audit_run"]["audit_run_id"]
        )
        self.assertEqual(reopened["audit_run"]["status"], "in_progress")
        self.assertEqual(reopened["workflow"], first_started["workflow"])

    def test_complete_rejects_pending_and_failed_measurements(self):
        created = self.create_run()
        started = self.store.start_audit_run(
            self.assessment_id,
            created["assessment_revision"],
            created["audit_run"]["audit_run_id"],
            created["audit_run"]["revision"],
        )
        with self.assertRaises(BackendError) as pending_error:
            self.store.complete_audit_run(
                self.assessment_id,
                started["assessment_revision"],
                started["audit_run"]["audit_run_id"],
                started["audit_run"]["revision"],
            )
        self.assertEqual(pending_error.exception.code, "invalid_state_transition")
        measurement = started["measurements"][0]
        failed = self.store.resolve_audit_measurement(
            self.assessment_id,
            started["assessment_revision"],
            started["audit_run"]["audit_run_id"],
            started["audit_run"]["revision"],
            measurement["measurement_id"],
            measurement["revision"],
            failure={
                "error_code": "invalid_recon",
                "error_message": "Fixture failure",
                "failed_at": "2099-07-31T12:00:00Z",
            },
        )
        with self.assertRaises(BackendError) as failed_error:
            self.store.complete_audit_run(
                self.assessment_id,
                failed["assessment_revision"],
                failed["audit_run"]["audit_run_id"],
                failed["audit_run"]["revision"],
            )
        self.assertEqual(failed_error.exception.code, "invalid_state_transition")

    def test_measurement_timestamps_are_strict_and_monotonic(self):
        created = self.create_run()
        started = self.store.start_audit_run(
            self.assessment_id,
            created["assessment_revision"],
            created["audit_run"]["audit_run_id"],
            created["audit_run"]["revision"],
        )
        measurement = started["measurements"][0]
        scan = json.loads(RECON_FIXTURE.read_text(encoding="utf-8"))
        snapshot = self.service.resolve_recon(
            scan,
            self.scan_metadata("timestamps", "2099-07-31T10:00:00Z"),
        )["snapshot"]
        with self.assertRaises(BackendError) as early_resolution:
            self.store.resolve_audit_measurement(
                self.assessment_id,
                started["assessment_revision"],
                started["audit_run"]["audit_run_id"],
                started["audit_run"]["revision"],
                measurement["measurement_id"],
                measurement["revision"],
                snapshot={
                    "document": snapshot,
                    "comparability_status": "comparable",
                    "resolved_at": "2000-01-01T00:00:00Z",
                },
            )
        self.assertEqual(
            early_resolution.exception.code, "invalid_audit_run_measurement"
        )
        resolved = self.store.resolve_audit_measurement(
            self.assessment_id,
            started["assessment_revision"],
            started["audit_run"]["audit_run_id"],
            started["audit_run"]["revision"],
            measurement["measurement_id"],
            measurement["revision"],
            snapshot={
                "document": snapshot,
                "comparability_status": "comparable",
                "resolved_at": "2099-07-31T10:00:00.000000002Z",
            },
        )
        revision_before = resolved["assessment_revision"]
        with self.assertRaises(BackendError) as early_failure:
            self.store.save_audit_measurement_comparison(
                self.assessment_id,
                revision_before,
                resolved["audit_run"]["audit_run_id"],
                resolved["audit_run"]["revision"],
                resolved["measurement"]["measurement_id"],
                resolved["measurement"]["revision"],
                failure={
                    "error_code": "invalid_comparison",
                    "error_message": "Too early",
                    "failed_at": "2099-07-31T10:00:00.000000001Z",
                },
            )
        self.assertEqual(
            early_failure.exception.code, "invalid_audit_run_measurement"
        )
        self.assertEqual(self.revision(), revision_before)

    def test_rfc3339_fractional_precision_orders_exactly(self):
        accepted = [
            "2026-07-30T10:00:00.1Z",
            "2026-07-30T10:00:00.123456789Z",
            "2026-07-30T12:00:00.123456789+02:00",
            "2026-07-30t10:00:00.123456789z",
        ]
        for value in accepted:
            self.assertEqual(
                _validate_rfc3339(value, "timestamp", "invalid_test"), value
            )
        for value in (
            "2026-07-30T10:00:00.1234567890Z",
            "2026-07-30T10:00:00",
            "2026-12-31T23:59:60Z",
            "٢٠٢٦-٠٧-٣٠T١٠:٠٠:٠٠Z",
        ):
            with self.assertRaises(BackendError):
                _validate_rfc3339(value, "timestamp", "invalid_test")
        self.assertLess(
            _rfc3339_order_key("2026-07-30T10:00:00.123456788Z"),
            _rfc3339_order_key("2026-07-30T10:00:00.123456789Z"),
        )

    def test_resolution_failure_retry_updates_only_target_measurement(self):
        result = self.create_run()
        started = self.store.start_audit_run(
            self.assessment_id,
            result["assessment_revision"],
            result["audit_run"]["audit_run_id"],
            1,
        )
        measurement = started["measurements"][0]
        failed = self.store.resolve_audit_measurement(
            self.assessment_id,
            started["assessment_revision"],
            started["audit_run"]["audit_run_id"],
            2,
            measurement["measurement_id"],
            1,
            failure={
                "error_code": "fixture_failure",
                "error_message": "The fixture failed",
                "failed_at": "2099-07-31T12:00:00Z",
            },
        )
        self.assertEqual(failed["measurement"]["status"], "failed")
        retried = self.store.retry_audit_measurement(
            self.assessment_id,
            failed["assessment_revision"],
            failed["audit_run"]["audit_run_id"],
            3,
            measurement["measurement_id"],
            2,
        )
        self.assertEqual(retried["measurement"]["status"], "pending")
        self.assertEqual(retried["measurement"]["revision"], 3)
        self.assertEqual(retried["workflow"]["next_action"], "resolve_measurement")

    def test_comparison_failure_retry_preserves_resolved_snapshot(self):
        created = self.create_run()
        started = self.store.start_audit_run(
            self.assessment_id,
            created["assessment_revision"],
            created["audit_run"]["audit_run_id"],
            created["audit_run"]["revision"],
        )
        measurement = started["measurements"][0]
        scan = json.loads(RECON_FIXTURE.read_text(encoding="utf-8"))
        snapshot = self.service.resolve_recon(
            scan,
            self.scan_metadata("retry", "2026-07-31T11:00:00Z"),
        )["snapshot"]
        resolved = self.store.resolve_audit_measurement(
            self.assessment_id,
            started["assessment_revision"],
            started["audit_run"]["audit_run_id"],
            started["audit_run"]["revision"],
            measurement["measurement_id"],
            measurement["revision"],
            snapshot={
                "document": snapshot,
                "comparability_status": "comparable",
                "resolved_at": "2099-07-31T11:01:00Z",
            },
        )
        failed = self.store.save_audit_measurement_comparison(
            self.assessment_id,
            resolved["assessment_revision"],
            resolved["audit_run"]["audit_run_id"],
            resolved["audit_run"]["revision"],
            resolved["measurement"]["measurement_id"],
            resolved["measurement"]["revision"],
            failure={
                "error_code": "invalid_occurrence_set",
                "error_message": "Fixture comparison failed",
                "failed_at": "2099-07-31T11:02:00Z",
            },
        )
        self.assertEqual(failed["measurement"]["status"], "failed")
        self.assertEqual(failed["measurement"]["retry_target"], "resolved")
        retried = self.store.retry_audit_measurement(
            self.assessment_id,
            failed["assessment_revision"],
            failed["audit_run"]["audit_run_id"],
            failed["audit_run"]["revision"],
            failed["measurement"]["measurement_id"],
            failed["measurement"]["revision"],
        )
        self.assertEqual(retried["measurement"]["status"], "resolved")
        self.assertEqual(
            len(retried["measurement"]["snapshot_record_digest"]), 64
        )
        self.assertEqual(
            retried["measurement"]["snapshot_id"], snapshot["snapshot_id"]
        )
        self.assertEqual(retried["workflow"]["next_action"], "save_comparison")

    def test_snapshot_record_digest_rejects_tampered_native_artifact(self):
        created = self.create_run()
        started = self.store.start_audit_run(
            self.assessment_id,
            created["assessment_revision"],
            created["audit_run"]["audit_run_id"],
            created["audit_run"]["revision"],
        )
        measurement = started["measurements"][0]
        scan = json.loads(RECON_FIXTURE.read_text(encoding="utf-8"))
        snapshot = self.service.resolve_recon(
            scan,
            self.scan_metadata("integrity", "2026-07-31T11:00:00Z"),
        )["snapshot"]
        resolved = self.store.resolve_audit_measurement(
            self.assessment_id,
            started["assessment_revision"],
            started["audit_run"]["audit_run_id"],
            started["audit_run"]["revision"],
            measurement["measurement_id"],
            measurement["revision"],
            snapshot={
                "document": snapshot,
                "comparability_status": "comparable",
                "resolved_at": "2099-07-31T11:01:00Z",
            },
        )
        self.assertEqual(
            len(resolved["measurement"]["snapshot_record_digest"]), 64
        )
        snapshot_path = (
            Path(self.directory)
            / "assessments"
            / self.assessment_id
            / "snapshots"
            / (snapshot["snapshot_id"] + ".json")
        )
        tampered = json.loads(snapshot_path.read_text(encoding="utf-8"))
        tampered["access_points"][0]["vendor"] = "Tampered vendor"
        snapshot_path.write_text(
            json.dumps(tampered, sort_keys=True), encoding="utf-8"
        )
        reopened = RepeatableAuditStore(self.directory)
        with self.assertRaises(BackendError) as raised:
            reopened.get_audit_run(
                self.assessment_id, started["audit_run"]["audit_run_id"]
            )
        self.assertEqual(raised.exception.code, "pinned_reference_mismatch")
        with self.assertRaises(BackendError) as report_error:
            AuditRunReportService(reopened).fact_model(
                self.assessment_id, started["audit_run"]["audit_run_id"]
            )
        self.assertEqual(
            report_error.exception.code, "audit_run_not_terminal"
        )

    def test_split_documents_reject_unknown_fields_and_bad_point_envelope(self):
        created = self.create_run()
        run = created["audit_run"]
        measurement = created["measurements"][0]
        base = Path(self.directory) / "assessments" / self.assessment_id
        measurement_path = (
            base
            / "audit_runs"
            / run["audit_run_id"]
            / "measurements"
            / (measurement["measurement_id"] + ".json")
        )
        invalid_measurement = json.loads(
            measurement_path.read_text(encoding="utf-8")
        )
        invalid_measurement["unexpected"] = True
        measurement_path.write_text(
            json.dumps(invalid_measurement, sort_keys=True), encoding="utf-8"
        )
        with self.assertRaises(BackendError) as raised:
            self.store.get_audit_run(self.assessment_id, run["audit_run_id"])
        self.assertEqual(raised.exception.code, "invalid_audit_run_measurement")

        measurement_path.write_text(
            json.dumps(measurement, sort_keys=True), encoding="utf-8"
        )
        invalid_time = dict(measurement, created_at="2000-01-01T00:00:00Z")
        measurement_path.write_text(
            json.dumps(invalid_time, sort_keys=True), encoding="utf-8"
        )
        with self.assertRaises(BackendError) as time_error:
            self.store.get_audit_run(
                self.assessment_id, run["audit_run_id"]
            )
        self.assertEqual(
            time_error.exception.code, "invalid_audit_run_measurement"
        )

        measurement_path.write_text(
            json.dumps(measurement, sort_keys=True), encoding="utf-8"
        )
        points_path = base / "measurement_points.json"
        points = json.loads(points_path.read_text(encoding="utf-8"))
        points["unexpected"] = True
        points_path.write_text(
            json.dumps(points, sort_keys=True), encoding="utf-8"
        )
        with self.assertRaises(BackendError) as point_error:
            self.store.list_measurement_points(self.assessment_id)
        self.assertEqual(point_error.exception.code, "invalid_measurement_point")

    def test_v11_manifest_corruption_fails_closed(self):
        created = self.create_run()
        run = created["audit_run"]
        manifest_path = (
            Path(self.directory)
            / "assessments"
            / self.assessment_id
            / "audit_runs"
            / run["audit_run_id"]
            / "manifest.json"
        )
        original = manifest_path.read_bytes()
        valid = json.loads(original.decode("utf-8"))
        invalid_documents = [
            b"{",
            b"{\n",
            json.dumps(dict(valid, unexpected=True)).encode("utf-8"),
            json.dumps(dict(valid, schema_version="9.9")).encode("utf-8"),
            json.dumps(dict(valid, revision=True)).encode("utf-8"),
            json.dumps(dict(valid, measurement_ids=[])).encode("utf-8"),
            json.dumps(dict(valid, status="unknown")).encode("utf-8"),
            json.dumps(
                dict(
                    valid,
                    status="in_progress",
                    started_at="2000-01-01T00:00:00Z",
                )
            ).encode("utf-8"),
            json.dumps(
                dict(
                    valid,
                    status="completed",
                    started_at=valid["created_at"],
                    completed_at="2000-01-01T00:00:00Z",
                )
            ).encode("utf-8"),
        ]
        for payload in invalid_documents:
            with self.subTest(payload=payload[:80]):
                manifest_path.write_bytes(payload)
                with self.assertRaises(BackendError) as raised:
                    self.store.get_audit_run(
                        self.assessment_id, run["audit_run_id"]
                    )
                self.assertEqual(raised.exception.code, "invalid_audit_run")
        manifest_path.write_bytes(original)
        self.assertEqual(
            self.store.get_audit_run(
                self.assessment_id, run["audit_run_id"]
            )["audit_run"]["audit_run_id"],
            run["audit_run_id"],
        )

    def test_draft_run_revalidates_every_frozen_assignment_pin(self):
        created = self.create_run()
        run = created["audit_run"]
        measurement = created["measurements"][0]
        measurement_path = (
            Path(self.directory)
            / "assessments"
            / self.assessment_id
            / "audit_runs"
            / run["audit_run_id"]
            / "measurements"
            / (measurement["measurement_id"] + ".json")
        )
        invalid_values = {
            "assurance_profile_digest": "f" * 64,
            "measurement_profile_digest": "f" * 64,
            "baseline_digest": "f" * 64,
            "baseline_record_digest": "f" * 64,
            "baseline_snapshot_id": "snapshot_ffffffffffffffff",
            "baseline_snapshot_digest": "f" * 64,
        }
        for field, value in invalid_values.items():
            with self.subTest(field=field):
                tampered = dict(measurement, **{field: value})
                measurement_path.write_text(
                    json.dumps(tampered, sort_keys=True), encoding="utf-8"
                )
                reopened = self.store.get_audit_run(
                    self.assessment_id, run["audit_run_id"]
                )
                self.assertFalse(reopened["ready_to_start"])
                with self.assertRaises(BackendError) as raised:
                    self.store.start_audit_run(
                        self.assessment_id,
                        created["assessment_revision"],
                        run["audit_run_id"],
                        run["revision"],
                    )
                self.assertEqual(
                    raised.exception.code, "pinned_reference_mismatch"
                )
                measurement_path.write_text(
                    json.dumps(measurement, sort_keys=True),
                    encoding="utf-8",
                )

        self.assertTrue(
            self.store.get_audit_run(
                self.assessment_id, run["audit_run_id"]
            )["ready_to_start"]
        )

    def test_capacity_rejects_snapshot_count_above_frozen_limit(self):
        snapshot_directory = (
            Path(self.directory)
            / "assessments"
            / self.assessment_id
            / "snapshots"
        )
        existing = len(list(snapshot_directory.glob("snapshot_*.json")))
        for index in range(MAX_SNAPSHOTS + 1 - existing):
            (
                snapshot_directory
                / "snapshot_{0:016x}.json".format(index + 0x1000)
            ).write_text("{}", encoding="utf-8")
        with self.assertRaises(BackendError) as raised:
            self.store.get_assessment_capacity(self.assessment_id)
        self.assertEqual(raised.exception.code, "storage_error")

    def test_comparable_point_does_not_resolve_another_points_finding(self):
        def stored_finding(finding_id, subject_id, point_id):
            return {
                "finding_id": finding_id,
                "rule_id": "policy_deviation:wps_not_allowed",
                "title": "WPS is not allowed",
                "severity": "medium",
                "confidence": 1.0,
                "subject_id": subject_id,
                "summary": "WPS is enabled",
                "evidence_ids": ["evidence_111111111111"],
                "details": {
                    "result_type": "policy_deviation",
                    "measurement_point_id": point_id,
                },
                "confidence_factors": {"certainty": "confirmed"},
                "status": "open",
                "currently_observed": True,
                "first_seen": "2026-07-31T10:00:00Z",
                "last_seen": "2026-07-31T10:00:00Z",
                "occurrence_count": 1,
                "status_updated_at": "2026-07-31T10:00:00Z",
            }

        point_a = stored_finding(
            "finding_111111111111", "ap_111111111111", "mp_aaaaaaaaaaaaaaaa"
        )
        point_b = stored_finding(
            "finding_222222222222", "ap_222222222222", "mp_bbbbbbbbbbbbbbbb"
        )
        findings, lifecycle, _ = self.store._build_finding_transition(
            [point_a, point_b],
            [],
            "comparable",
            "2026-07-31T11:00:00Z",
            "mp_aaaaaaaaaaaaaaaa",
        )
        by_id = {item["finding_id"]: item for item in findings}
        self.assertEqual(by_id[point_a["finding_id"]]["status"], "resolved")
        self.assertEqual(by_id[point_b["finding_id"]]["status"], "open")
        self.assertEqual(lifecycle["resolved"], [point_a["finding_id"]])

        legacy = stored_finding(
            "finding_333333333333", "ap_333333333333", None
        )
        legacy["details"].pop("measurement_point_id")
        findings, lifecycle, _ = self.store._build_finding_transition(
            [legacy],
            [],
            "comparable",
            "2026-07-31T11:00:00Z",
            "mp_aaaaaaaaaaaaaaaa",
        )
        self.assertEqual(findings[0]["status"], "open")
        self.assertEqual(lifecycle["resolved"], [])

    def test_audit_lifecycle_identity_is_scoped_to_measurement_point(self):
        deviation = {
            "certainty": "confirmed",
            "subject_id": "ap_111111111111",
            "rule_id": "wps_not_allowed",
            "title": "WPS is not allowed",
            "severity": "medium",
            "evidence_ids": ["evidence_111111111111"],
        }
        first = lifecycle_findings(
            self.assessment_id,
            [deviation],
            [],
            b"a" * 32,
            measurement_point_id="mp_aaaaaaaaaaaaaaaa",
        )[0]
        second = lifecycle_findings(
            self.assessment_id,
            [deviation],
            [],
            b"a" * 32,
            measurement_point_id="mp_bbbbbbbbbbbbbbbb",
        )[0]
        self.assertNotEqual(first["finding_id"], second["finding_id"])
        self.assertEqual(
            first["details"]["measurement_point_id"],
            "mp_aaaaaaaaaaaaaaaa",
        )

    def test_read_only_builder_then_atomic_native_analysis_save(self):
        created = self.create_run()
        started = self.store.start_audit_run(
            self.assessment_id,
            created["assessment_revision"],
            created["audit_run"]["audit_run_id"],
            created["audit_run"]["revision"],
        )
        measurement = started["measurements"][0]
        scan = json.loads(RECON_FIXTURE.read_text(encoding="utf-8"))
        scan["APResults"][0]["channel"] = 6
        metadata = self.scan_metadata(
            "comparison", "2026-07-31T11:00:00Z"
        )
        snapshot = self.service.resolve_recon(scan, metadata)["snapshot"]
        resolved = self.store.resolve_audit_measurement(
            self.assessment_id,
            started["assessment_revision"],
            started["audit_run"]["audit_run_id"],
            started["audit_run"]["revision"],
            measurement["measurement_id"],
            measurement["revision"],
            snapshot={
                "document": snapshot,
                "comparability_status": "comparable",
                "resolved_at": "2099-07-31T11:01:00Z",
                "source_recon_id": "comparison",
            },
        )
        current = resolved["measurement"]
        preview = self.service.comparison_for_pinned_versions(
            self.assessment_id,
            snapshot,
            current["baseline_version_id"],
            current["assurance_profile_version_id"],
            current["measurement_profile_id"],
            current["measurement_profile_version_id"],
            current["measurement_profile_digest"],
        )
        baseline = preview["baseline"]
        occurrence = {
            "observed_changes": preview["observed_changes"],
            "inventory_reconciliation": preview[
                "inventory_reconciliation"
            ],
            "policy_deviations": preview["policy_deviations"],
            "security_findings": preview["security_findings"],
            "policy_evaluation_status": preview[
                "policy_evaluation_status"
            ],
            "lifecycle_findings": preview["lifecycle_findings"],
            "evidence": evidence_records(baseline, snapshot),
            "quality_factors": preview["diff"]["comparability"].get(
                "quality_factors", []
            ),
            "policy_reference": {
                "assurance_profile_version_id": current[
                    "assurance_profile_version_id"
                ],
                "assurance_profile_digest": current[
                    "assurance_profile_digest"
                ],
            },
            "limitations": [],
        }
        revision_before = self.revision()
        analysis = self.store.build_audit_measurement_analysis(
            self.assessment_id,
            revision_before,
            resolved["audit_run"]["audit_run_id"],
            resolved["audit_run"]["revision"],
            current["measurement_id"],
            current["revision"],
            preview["diff"],
            preview["lifecycle_findings"],
            occurrence,
            completed_at="2099-07-31T11:02:00Z",
        )
        self.assertEqual(self.revision(), revision_before)
        comparison_path = (
            Path(self.directory)
            / "assessments"
            / self.assessment_id
            / "comparisons"
            / (analysis["comparison"]["comparison_id"] + ".json")
        )
        self.assertFalse(comparison_path.exists())
        saved = self.store.save_audit_measurement_comparison(
            self.assessment_id,
            revision_before,
            resolved["audit_run"]["audit_run_id"],
            resolved["audit_run"]["revision"],
            current["measurement_id"],
            current["revision"],
            analysis=analysis,
        )
        self.assertEqual(saved["measurement"]["status"], "completed")
        self.assertTrue(comparison_path.is_file())
        self.assertEqual(
            saved["measurement"]["comparison_id"],
            analysis["comparison"]["comparison_id"],
        )
        completed = self.store.complete_audit_run(
            self.assessment_id,
            saved["assessment_revision"],
            saved["audit_run"]["audit_run_id"],
            saved["audit_run"]["revision"],
        )
        with mock.patch.object(
            self.store,
            "read_audit_run_report_seed",
            wraps=self.store.read_audit_run_report_seed,
        ) as seed_reader, mock.patch.object(
            self.store,
            "read_audit_run_report_artifact",
            wraps=self.store.read_audit_run_report_artifact,
        ) as artifact_reader:
            report = AuditRunReportService(self.store).fact_model(
                self.assessment_id,
                completed["audit_run"]["audit_run_id"],
            )
        self.assertEqual(report["summary"]["measurement_count"], 1)
        seed_reader.assert_called_once()
        self.assertEqual(artifact_reader.call_count, 3)
        self.assertEqual(
            [call.args[1] for call in artifact_reader.call_args_list],
            ["snapshot", "comparison", "occurrence"],
        )
        snapshot_path = (
            Path(self.directory)
            / "assessments"
            / self.assessment_id
            / "snapshots"
            / (saved["measurement"]["snapshot_id"] + ".json")
        )
        original_snapshot = snapshot_path.read_bytes()
        snapshot_path.write_bytes(b"{" + (b"x" * (520 * 1024)) + b"}")
        with mock.patch.object(
            self.store,
            "read_audit_run_report_artifact",
            wraps=self.store.read_audit_run_report_artifact,
        ) as bounded_reader:
            with self.assertRaises(BackendError) as oversized:
                AuditRunReportService(self.store).fact_model(
                    self.assessment_id,
                    completed["audit_run"]["audit_run_id"],
                )
        self.assertEqual(
            oversized.exception.code, "audit_report_too_large"
        )
        self.assertEqual(bounded_reader.call_count, 1)
        snapshot_path.write_bytes(original_snapshot)
        occurrence_path = (
            Path(self.directory)
            / "assessments"
            / self.assessment_id
            / "occurrences"
            / (saved["measurement"]["occurrence_set_id"] + ".json")
        )
        tampered_occurrence = json.loads(
            occurrence_path.read_text(encoding="utf-8")
        )
        tampered_occurrence["limitations"].append("tampered")
        occurrence_path.write_text(
            json.dumps(tampered_occurrence, sort_keys=True), encoding="utf-8"
        )
        with self.assertRaises(BackendError) as raised:
            reopened = RepeatableAuditStore(self.directory)
            reopened.get_audit_run(
                self.assessment_id, completed["audit_run"]["audit_run_id"]
            )
        self.assertIn(
            raised.exception.code,
            {"invalid_occurrence_set", "pinned_reference_mismatch"},
        )
        with self.assertRaises(BackendError) as report_error:
            AuditRunReportService(reopened).fact_model(
                self.assessment_id,
                completed["audit_run"]["audit_run_id"],
            )
        self.assertEqual(
            report_error.exception.code, "invalid_occurrence_set"
        )

    def test_unreleased_flat_run_is_read_only_adapted_then_migrated(self):
        point_result = self.create_point("Legacy doorway")
        point_id = point_result["measurement_point"]["measurement_point_id"]
        assurance = self.store.get_assurance_profile_version(
            self.assessment_id, self.assurance_version_id
        )
        audit_run_id = "ar_1111111111111111"
        measurement_id = "arm_2222222222222222"
        created_at = "2026-07-31T10:00:00Z"
        legacy = {
            "audit_run_id": audit_run_id,
            "assessment_id": self.assessment_id,
            "title": "Unreleased flat draft",
            "status": "draft",
            "created_at": created_at,
            "started_at": None,
            "completed_at": None,
            "due_at": None,
            "pinned_assurance_profile_version_id": self.assurance_version_id,
            "pinned_assurance_profile_digest": assurance["digest"],
            "measurement_point_ids": [point_id],
            "measurements": [
                {
                    "measurement_id": measurement_id,
                    "audit_run_id": audit_run_id,
                    "measurement_point_id": point_id,
                    "status": "pending",
                    "created_at": created_at,
                    "expected_measurement_context": {
                        "location_id": "legacy-lab",
                        "measurement_point_id": point_id,
                        "scan_profile_id": "saved-recon",
                        "radio_profile_id": "wlan1",
                        "interface": "wlan1mon",
                        "declared_bands": ["2.4"],
                        "declared_channels": [1, 6, 11],
                        "scan_time": 180,
                    },
                }
            ],
            "revision": 1,
        }
        run_root = (
            Path(self.directory)
            / "assessments"
            / self.assessment_id
            / "audit_runs"
        )
        run_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        flat_path = run_root / (audit_run_id + ".json")
        flat_path.write_text(
            json.dumps(legacy, sort_keys=True), encoding="utf-8"
        )
        split_root = run_root / audit_run_id

        adapted = self.store.get_audit_run(
            self.assessment_id, audit_run_id
        )
        self.assertFalse(split_root.exists())
        self.assertEqual(
            adapted["measurements"][0]["provenance_status"],
            "legacy_unpinned",
        )
        self.assertNotIn(
            "expected_measurement_context", adapted["measurements"][0]
        )

        migrated = self.store.cancel_audit_run(
            self.assessment_id,
            self.revision(),
            audit_run_id,
            adapted["audit_run"]["revision"],
            "Retire unreleased draft",
        )
        self.assertEqual(migrated["audit_run"]["status"], "cancelled")
        self.assertTrue((split_root / "manifest.json").is_file())
        self.assertTrue(
            (split_root / "measurements" / (measurement_id + ".json")).is_file()
        )
        self.assertTrue((split_root / "migration.json").is_file())
        self.assertTrue(flat_path.is_file())


if __name__ == "__main__":
    unittest.main()
