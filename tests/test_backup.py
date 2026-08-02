import base64
import gzip
import io
import json
import os
import stat
import sys
import tarfile
import tempfile
import time
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
import pineai_backend.backup as backup_module  # noqa: E402
from pineai_backend.backup import (  # noqa: E402
    MAX_ARCHIVE_BYTES,
    MAX_MEMBER_BYTES,
    create_backup,
    restore_backup_staging,
    verify_backup,
)
from pineai_backend.errors import BackendError  # noqa: E402

ASSESSMENT_ID = (
    "assessment_00000000-0000-4000-8000-000000000001"
)
SNAPSHOT_ID = "snapshot_0000000000000001"


def pax_record(key, value):
    body = key + b"=" + value + b"\n"
    length = len(body) + 2
    while True:
        record = str(length).encode("ascii") + b" " + body
        if len(record) == length:
            return record
        length = len(record)


def prefix_pax_header(source, output, payload):
    original_tar = gzip.decompress(Path(source).read_bytes())
    info = tarfile.TarInfo("././@PaxHeader")
    info.type = tarfile.XHDTYPE
    info.mode = 0o600
    info.uid = 0
    info.gid = 0
    info.mtime = 0
    info.size = len(payload)
    header = info.tobuf(
        format=tarfile.USTAR_FORMAT, encoding="utf-8", errors="strict"
    )
    padding = b"\0" * (
        ((len(payload) + tarfile.BLOCKSIZE - 1) // tarfile.BLOCKSIZE)
        * tarfile.BLOCKSIZE
        - len(payload)
    )
    with Path(output).open("wb") as raw:
        with gzip.GzipFile(
            filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9
        ) as compressed:
            compressed.write(header + payload + padding + original_tar)


class BackupTests(unittest.TestCase):
    def source(self, root):
        source = Path(root) / "source"
        (source / "assessments" / ASSESSMENT_ID / "snapshots").mkdir(
            parents=True
        )
        (
            source
            / "assessments"
            / ASSESSMENT_ID
            / "assurance_profiles"
        ).mkdir()
        measurement = (
            source
            / "measurement_profiles"
            / "mprofile_00000000-0000-4000-8000-000000000001"
        )
        (measurement / "versions").mkdir(parents=True)
        (source / "assessments" / ASSESSMENT_ID / "assessment.json").write_text(
            json.dumps({"assessment_id": ASSESSMENT_ID, "revision": 2}),
            encoding="utf-8",
        )
        (
            source
            / "assessments"
            / ASSESSMENT_ID
            / "snapshots"
            / (SNAPSHOT_ID + ".json")
        ).write_text(json.dumps({"snapshot_id": SNAPSHOT_ID}), encoding="utf-8")
        (
            source
            / "assessments"
            / ASSESSMENT_ID
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
            source / "assessments" / ASSESSMENT_ID / ".lock"
        ).write_text("transient", encoding="utf-8")
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

    def crafted_archive(self, path, relative, payload):
        identity = base64.b64encode(b"k" * 32) + b"\n"
        contents = {
            "pseudonymization.key": identity,
            relative: payload,
        }
        files = [
            {
                "path": name,
                "size": len(contents[name]),
                "sha256": backup_module.hashlib.sha256(
                    contents[name]
                ).hexdigest(),
            }
            for name in sorted(contents)
        ]
        directories = ["assessments", "measurement_profiles"]
        total_bytes = sum(item["size"] for item in files)
        manifest_payload = {
            "directories": directories,
            "files": files,
            "total_bytes": total_bytes,
        }
        manifest = {
            "schema_version": "1.0",
            "backup_type": "pineai_device_continuity",
            "created_at": "2026-08-02T12:00:00Z",
            "included_roots": [
                "assessments",
                "measurement_profiles",
                "config.json",
                "pseudonymization.key",
            ],
            "excluded": [
                ".lock",
                ".transactions",
                "exports",
                "openai.key",
            ],
            "directories": directories,
            "files": files,
            "file_count": len(files),
            "total_bytes": total_bytes,
            "payload_sha256": backup_module.hashlib.sha256(
                backup_module._canonical_bytes(manifest_payload)
            ).hexdigest(),
        }
        manifest_bytes = json.dumps(manifest, sort_keys=True).encode("utf-8")
        with tarfile.open(str(path), "w:gz") as archive:
            manifest_info = tarfile.TarInfo("manifest.json")
            manifest_info.mode = 0o600
            manifest_info.size = len(manifest_bytes)
            archive.addfile(manifest_info, io.BytesIO(manifest_bytes))
            for directory in directories:
                info = tarfile.TarInfo("data/" + directory)
                info.type = tarfile.DIRTYPE
                info.mode = 0o700
                archive.addfile(info)
            for name in sorted(contents):
                info = tarfile.TarInfo("data/" + name)
                info.mode = 0o600
                info.size = len(contents[name])
                archive.addfile(info, io.BytesIO(contents[name]))

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
                f"data/assessments/{ASSESSMENT_ID}/"
                "assurance_profiles/assurance_v0001.json",
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
                "assessments/{0}/assessment.json".format(
                    ASSESSMENT_ID
                ),
                "assessments/{0}/snapshots/{1}.json".format(
                    ASSESSMENT_ID, SNAPSHOT_ID
                ),
                f"assessments/{ASSESSMENT_ID}/"
                "assurance_profiles/assurance_v0001.json",
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

    def test_failed_post_lock_validation_never_publishes_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.source(directory)
            output = Path(directory) / "must-not-exist.tar.gz"
            failure = BackendError(
                "backup_source_changed",
                "assessment set changed during backup",
            )
            with mock.patch.object(
                backup_module,
                "_assert_no_active_transactions",
                side_effect=[None, failure],
            ):
                with self.assertRaises(BackendError) as raised:
                    create_backup(str(source), str(output))
            self.assertEqual(
                raised.exception.code, "backup_source_changed"
            )
            self.assertFalse(output.exists())
            self.assertEqual(
                list(Path(directory).glob(".must-not-exist.tar.gz.*")),
                [],
            )

    def test_os_error_details_are_not_exposed(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.source(directory)
            output = Path(directory) / "must-not-exist.tar.gz"
            with mock.patch.object(
                backup_module.os,
                "link",
                side_effect=OSError(
                    "SECRET-PATH-CANARY /root/.PineAI/private"
                ),
            ):
                with self.assertRaises(BackendError) as raised:
                    create_backup(str(source), str(output))
            self.assertEqual(raised.exception.code, "backup_io_error")
            self.assertEqual(
                raised.exception.safe_message,
                "could not publish backup archive",
            )
            self.assertNotIn(
                "SECRET-PATH-CANARY", raised.exception.safe_message
            )
            self.assertFalse(output.exists())

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
                "excluded": [
                    ".lock",
                    ".transactions",
                    "exports",
                    "openai.key",
                ],
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

    def test_backup_rejects_raw_recon_and_unknown_config_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.source(directory)
            raw_path = (
                source
                / "assessments"
                / ASSESSMENT_ID
                / "snapshots"
                / (SNAPSHOT_ID + ".json")
            )
            raw_path.write_text(
                json.dumps(
                    {
                        "nested": {
                            "OutOfRangeClientResults": [],
                            "APResults": [],
                        }
                    }
                ),
                encoding="utf-8",
            )
            output = Path(directory) / "raw.tar.gz"
            with self.assertRaises(BackendError) as failure:
                create_backup(str(source), str(output))
            self.assertEqual(
                failure.exception.code, "raw_recon_not_allowed"
            )
            self.assertFalse(output.exists())

            raw_path.unlink()
            (source / "config.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "language": "fi",
                        "api_key": "secret-canary",
                    }
                ),
                encoding="utf-8",
            )
            output = Path(directory) / "secret.tar.gz"
            with self.assertRaises(BackendError) as failure:
                create_backup(str(source), str(output))
            self.assertEqual(
                failure.exception.code, "backup_unsafe_source"
            )
            self.assertFalse(output.exists())

    def test_verify_and_restore_reject_crafted_contract_violations(self):
        cases = (
            (
                "raw-recon",
                "assessments/{0}/snapshots/{1}.json".format(
                    ASSESSMENT_ID, SNAPSHOT_ID
                ),
                json.dumps({"APResults": []}).encode("utf-8"),
                "raw_recon_not_allowed",
            ),
            (
                "unsupported-path",
                "assessments/{0}/arbitrary-secret.json".format(
                    ASSESSMENT_ID
                ),
                json.dumps({"api_key": "secret-canary"}).encode("utf-8"),
                "backup_unsafe_source",
            ),
            (
                "secret-config",
                "config.json",
                json.dumps(
                    {
                        "schema_version": 1,
                        "language": "fi",
                        "api_key": "secret-canary",
                    }
                ).encode("utf-8"),
                "backup_unsafe_source",
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            for name, relative, payload, error_code in cases:
                with self.subTest(name=name):
                    archive = Path(directory) / (name + ".tar.gz")
                    self.crafted_archive(archive, relative, payload)
                    with self.assertRaises(BackendError) as raised:
                        verify_backup(str(archive))
                    self.assertEqual(raised.exception.code, error_code)

                    target = Path(directory) / (name + "-staging")
                    with self.assertRaises(BackendError) as raised:
                        restore_backup_staging(str(archive), str(target))
                    self.assertEqual(raised.exception.code, error_code)
                    self.assertFalse(target.exists())

    def test_verify_rejects_oversized_compressed_input_before_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "oversized.tar.gz"
            with archive.open("wb") as handle:
                handle.truncate(MAX_ARCHIVE_BYTES + 1)
            with mock.patch(
                "pineai_backend.backup.tarfile.open"
            ) as archive_open:
                with self.assertRaises(BackendError) as failure:
                    verify_backup(str(archive))
            self.assertEqual(failure.exception.code, "backup_limit")
            archive_open.assert_not_called()

    def test_verify_rejects_oversized_first_compressed_member_from_header(self):
        class ZeroReader:
            def __init__(self, remaining):
                self.remaining = remaining

            def read(self, size=-1):
                if self.remaining <= 0:
                    return b""
                if size < 0:
                    size = self.remaining
                count = min(size, self.remaining)
                self.remaining -= count
                return b"\0" * count

        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "compressed-member-bomb.tar.gz"
            declared_size = MAX_MEMBER_BYTES + 1
            with tarfile.open(str(archive), "w:gz") as handle:
                oversized = tarfile.TarInfo(
                    "data/assessments/oversized.json"
                )
                oversized.mode = 0o600
                oversized.size = declared_size
                handle.addfile(oversized, ZeroReader(declared_size))

            self.assertLess(archive.stat().st_size, declared_size // 100)
            with self.assertRaises(BackendError) as failure:
                verify_backup(str(archive))
            self.assertEqual(failure.exception.code, "backup_limit")

    def test_verify_rejects_oversized_pax_metadata_before_parsing_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "pax-metadata-bomb.tar.gz"
            with tarfile.open(
                str(archive), "w:gz", format=tarfile.PAX_FORMAT
            ) as handle:
                member = tarfile.TarInfo("manifest.json")
                member.mode = 0o600
                member.size = 0
                member.pax_headers = {"comment": "x" * (64 * 1024)}
                handle.addfile(member, io.BytesIO(b""))

            self.assertLess(archive.stat().st_size, 4096)
            started = time.monotonic()
            with self.assertRaises(BackendError) as failure:
                verify_backup(str(archive))
            elapsed = time.monotonic() - started
            self.assertEqual(failure.exception.code, "backup_limit")
            self.assertLess(elapsed, 2.0)

    def test_verify_rejects_malformed_local_pax_metadata(self):
        cases = {
            "bad-length": b"12 path=x\n",
            "bad-key": pax_record(b"comment", b"x"),
            "bad-utf8": pax_record(b"path", b"\xff"),
            "trailing": pax_record(b"path", b"data/example") + b"x",
            "duplicate": (
                pax_record(b"path", b"data/example")
                + pax_record(b"path", b"data/example")
            ),
        }
        with tempfile.TemporaryDirectory() as directory:
            source = self.source(directory)
            valid = Path(directory) / "valid.tar.gz"
            create_backup(str(source), str(valid))
            for name, payload in cases.items():
                with self.subTest(name=name):
                    archive = Path(directory) / (name + ".tar.gz")
                    prefix_pax_header(valid, archive, payload)
                    started = time.monotonic()
                    with self.assertRaises(BackendError) as failure:
                        verify_backup(str(archive))
                    self.assertIn(
                        failure.exception.code,
                        ("backup_invalid", "backup_unsafe_member"),
                    )
                    self.assertLess(time.monotonic() - started, 2.0)


if __name__ == "__main__":
    unittest.main()
