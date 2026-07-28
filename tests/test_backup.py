import base64
import io
import json
import os
import stat
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ASSETS = (
    Path(__file__).resolve().parents[1]
    / "projects"
    / "PineAI"
    / "src"
    / "assets"
)
sys.path.insert(0, str(ASSETS))

import pineai_cli  # noqa: E402
from pineai_backend.backup import (  # noqa: E402
    create_backup,
    restore_backup_staging,
    verify_backup,
)
from pineai_backend.errors import BackendError  # noqa: E402


class BackupTests(unittest.TestCase):
    def source(self, root):
        source = Path(root) / "source"
        (source / "assessments" / "assessment_example" / "snapshots").mkdir(
            parents=True
        )
        (
            source
            / "assessments"
            / "assessment_example"
            / "assurance_profiles"
        ).mkdir()
        measurement = (
            source
            / "measurement_profiles"
            / "mprofile_00000000-0000-4000-8000-000000000001"
        )
        (measurement / "versions").mkdir(parents=True)
        (source / "assessments" / "assessment_example" / "assessment.json").write_text(
            json.dumps({"assessment_id": "assessment_example", "revision": 2}),
            encoding="utf-8",
        )
        (
            source
            / "assessments"
            / "assessment_example"
            / "snapshots"
            / "snapshot_example.json"
        ).write_text(json.dumps({"snapshot_id": "snapshot_example"}), encoding="utf-8")
        (
            source
            / "assessments"
            / "assessment_example"
            / "assurance_profiles"
            / "assurance_v0001.json"
        ).write_text(
            json.dumps({"assurance_profile_version_id": "assurance_v0001"}),
            encoding="utf-8",
        )
        (measurement / "profile.json").write_text(
            json.dumps(
                {
                    "measurement_profile_id": (
                        "mprofile_00000000-0000-4000-8000-000000000001"
                    ),
                    "active_version_id": "mprofile_r0001",
                }
            ),
            encoding="utf-8",
        )
        (measurement / "versions" / "mprofile_r0001.json").write_text(
            json.dumps({"version_id": "mprofile_r0001"}), encoding="utf-8"
        )
        # These transient files must never enter a point-in-time backup.
        (
            source / "assessments" / "assessment_example" / ".lock"
        ).write_text("transient", encoding="utf-8")
        transaction = (
            source
            / "assessments"
            / "assessment_example"
            / ".transactions"
            / "txn_transient"
        )
        transaction.mkdir(parents=True)
        (transaction / "journal.json").write_text(
            json.dumps({"state": "prepared"}), encoding="utf-8"
        )
        measurement_transaction = (
            source
            / "measurement_profiles"
            / ".transactions"
            / "txn_transient"
        )
        measurement_transaction.mkdir(parents=True)
        (measurement_transaction / "journal.json").write_text(
            json.dumps({"state": "prepared"}), encoding="utf-8"
        )
        (source / "profiles").mkdir()
        (source / "profiles" / "legacy.json").write_text(
            json.dumps({"legacy": True}), encoding="utf-8"
        )
        (source / "config.json").write_text(
            json.dumps({"schema_version": 1, "language": "fi"}),
            encoding="utf-8",
        )
        (source / "pseudonymization.key").write_bytes(
            base64.b64encode(b"k" * 32) + b"\n"
        )
        (source / "openai.key").write_text("sk-never-back-up\n", encoding="utf-8")
        return source

    def test_create_verify_and_restore_round_trip_excludes_openai_key(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.source(directory)
            archive = Path(directory) / "pineai-backup.tar.gz"
            created = create_backup(str(source), str(archive))
            self.assertEqual(created["file_count"], 7)
            self.assertTrue(archive.exists())
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(archive.stat().st_mode), 0o600)

            verified = verify_backup(str(archive))
            self.assertTrue(verified["verified"])
            self.assertEqual(
                verified["archive_sha256"], created["archive_sha256"]
            )
            with tarfile.open(str(archive), "r:gz") as handle:
                names = handle.getnames()
            self.assertFalse(any("openai.key" in name for name in names))
            self.assertFalse(any("/.lock" in name for name in names))
            self.assertFalse(any(".transactions" in name for name in names))
            self.assertFalse(any("/profiles/" in name for name in names))
            self.assertIn("data/pseudonymization.key", names)
            self.assertIn(
                "data/measurement_profiles/"
                "mprofile_00000000-0000-4000-8000-000000000001/"
                "profile.json",
                names,
            )
            self.assertIn(
                "data/assessments/assessment_example/assurance_profiles/"
                "assurance_v0001.json",
                names,
            )

            target = Path(directory) / "restore-staging"
            with mock.patch.dict(
                os.environ, {"PINEAI_CONFIG_DIR": str(source)}, clear=False
            ):
                restored = restore_backup_staging(str(archive), str(target))
            self.assertTrue(restored["restored"])
            self.assertFalse((target / "openai.key").exists())
            for relative in (
                "pseudonymization.key",
                "config.json",
                "measurement_profiles/"
                "mprofile_00000000-0000-4000-8000-000000000001/"
                "profile.json",
                "measurement_profiles/"
                "mprofile_00000000-0000-4000-8000-000000000001/"
                "versions/mprofile_r0001.json",
                "assessments/assessment_example/assessment.json",
                "assessments/assessment_example/snapshots/snapshot_example.json",
                "assessments/assessment_example/assurance_profiles/"
                "assurance_v0001.json",
            ):
                self.assertEqual(
                    (target / relative).read_bytes(),
                    (source / relative).read_bytes(),
                )
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)
                self.assertEqual(
                    stat.S_IMODE(
                        (target / "pseudonymization.key").stat().st_mode
                    ),
                    0o600,
                )

    def test_create_requires_identity_and_never_overwrites_output(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.source(directory)
            (source / "pseudonymization.key").unlink()
            with self.assertRaises(BackendError) as failure:
                create_backup(str(source), str(Path(directory) / "missing.tar.gz"))
            self.assertEqual(failure.exception.code, "backup_identity_missing")

            (source / "pseudonymization.key").write_bytes(
                base64.b64encode(b"k" * 32) + b"\n"
            )
            output = Path(directory) / "existing.tar.gz"
            output.write_bytes(b"keep")
            with self.assertRaises(BackendError) as failure:
                create_backup(str(source), str(output))
            self.assertEqual(failure.exception.code, "backup_output_exists")
            self.assertEqual(output.read_bytes(), b"keep")

    def test_verify_rejects_path_traversal_and_special_members(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "unsafe.tar.gz"
            manifest = {
                "schema_version": "1.0",
                "backup_type": "pineai_device_continuity",
                "created_at": "2026-07-28T12:00:00Z",
                "included_roots": [
                    "assessments",
                    "measurement_profiles",
                    "config.json",
                    "pseudonymization.key",
                ],
                "excluded": [".lock", ".transactions", "openai.key"],
                "directories": ["assessments", "measurement_profiles"],
                "files": [],
                "file_count": 0,
                "total_bytes": 0,
                "payload_sha256": "0" * 64,
            }
            manifest_bytes = json.dumps(manifest).encode("utf-8")
            with tarfile.open(str(archive), "w:gz") as handle:
                info = tarfile.TarInfo("manifest.json")
                info.mode = 0o600
                info.size = len(manifest_bytes)
                handle.addfile(info, io.BytesIO(manifest_bytes))
                unsafe = tarfile.TarInfo(
                    "data/assessments/../../openai.key"
                )
                unsafe.mode = 0o600
                unsafe.size = 1
                handle.addfile(unsafe, io.BytesIO(b"x"))
            with self.assertRaises(BackendError) as failure:
                verify_backup(str(archive))
            self.assertIn(
                failure.exception.code,
                ("backup_unsafe_path", "backup_contains_secret"),
            )

    def test_verify_detects_tampered_file_and_restore_requires_empty_target(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.source(directory)
            archive = Path(directory) / "good.tar.gz"
            create_backup(str(source), str(archive))

            tampered = Path(directory) / "tampered.tar.gz"
            with tarfile.open(str(archive), "r:gz") as original:
                members = original.getmembers()
                contents = {}
                for member in members:
                    if member.isfile():
                        extracted = original.extractfile(member)
                        contents[member.name] = extracted.read() if extracted else b""
            with tarfile.open(str(tampered), "w:gz") as output:
                for member in members:
                    if member.isdir():
                        output.addfile(member)
                        continue
                    data = contents[member.name]
                    if member.name.endswith("config.json"):
                        data += b"tampered"
                        member.size = len(data)
                    output.addfile(member, io.BytesIO(data))
            with self.assertRaises(BackendError) as failure:
                verify_backup(str(tampered))
            self.assertEqual(failure.exception.code, "backup_hash_mismatch")

            target = Path(directory) / "not-empty"
            target.mkdir()
            (target / "keep.txt").write_text("keep", encoding="utf-8")
            with mock.patch.dict(
                os.environ, {"PINEAI_CONFIG_DIR": str(source)}, clear=False
            ):
                with self.assertRaises(BackendError) as failure:
                    restore_backup_staging(str(archive), str(target))
            self.assertEqual(
                failure.exception.code, "backup_restore_target_not_empty"
            )
            self.assertEqual((target / "keep.txt").read_text(), "keep")

    def test_cli_backup_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.source(directory)
            archive = Path(directory) / "cli.tar.gz"
            output = io.StringIO()
            self.assertEqual(
                pineai_cli.main(
                    [
                        "--config-dir",
                        str(source),
                        "backup",
                        "create",
                        "--output",
                        str(archive),
                    ],
                    stdout=output,
                ),
                0,
            )
            self.assertNotIn("sk-never-back-up", output.getvalue())

            verify_output = io.StringIO()
            self.assertEqual(
                pineai_cli.main(
                    ["backup", "verify", "--input", str(archive)],
                    stdout=verify_output,
                ),
                0,
            )
            self.assertTrue(json.loads(verify_output.getvalue())["verified"])

            target = Path(directory) / "cli-restore"
            restore_output = io.StringIO()
            with mock.patch.dict(
                os.environ, {"PINEAI_CONFIG_DIR": str(source)}, clear=False
            ):
                self.assertEqual(
                    pineai_cli.main(
                        [
                            "backup",
                            "restore-staging",
                            "--input",
                            str(archive),
                            "--target",
                            str(target),
                        ],
                        stdout=restore_output,
                    ),
                    0,
                )
            self.assertTrue(json.loads(restore_output.getvalue())["restored"])


if __name__ == "__main__":
    unittest.main()
