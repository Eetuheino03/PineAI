import gzip
import io
import json
import os
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import package_tool  # noqa: E402


class PackageToolTests(unittest.TestCase):
    def build_package(self, directory):
        root = Path(directory)
        bundle = root / "PineAI.umd.js"
        bundle.write_text(
            "(function(){'use strict';return 'PineAI';}());\n",
            encoding="utf-8",
        )
        dist = root / "dist"
        package_tool.stage_runtime(bundle, dist)
        module = json.loads(
            (dist / "module.json").read_text(encoding="utf-8")
        )
        archive = root / "PineAI-{0}.tar.gz".format(module["version"])
        package_tool.create_package(dist, archive)
        return archive

    def entries(self, archive):
        payload = package_tool._decompress_archive(archive)
        result = []
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as handle:
            while True:
                member = handle.next()
                if member is None:
                    break
                data = None
                if member.isfile():
                    extracted = handle.extractfile(member)
                    data = extracted.read() if extracted else b""
                result.append((member, data))
        return result

    def write_entries(self, path, entries):
        with path.open("wb") as raw:
            with gzip.GzipFile(
                filename="", mode="wb", fileobj=raw, mtime=0
            ) as compressed:
                with tarfile.open(
                    fileobj=compressed,
                    mode="w",
                    format=tarfile.USTAR_FORMAT,
                ) as handle:
                    for member, data in entries:
                        if data is not None:
                            member.size = len(data)
                            handle.addfile(member, io.BytesIO(data))
                        else:
                            handle.addfile(member)

    def assert_package_error(self, path, code):
        with self.assertRaises(package_tool.PackageError) as raised:
            package_tool.verify_package(path, run_import_check=False)
        self.assertEqual(raised.exception.code, code)

    def test_exact_package_passes_and_imports_all_runtime_modules(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = self.build_package(directory)
            result = package_tool.verify_package(
                archive, run_import_check=True
            )
            self.assertTrue(result["verified"])
            self.assertEqual(result["file_count"], 24)
            self.assertEqual(result["directory_count"], 3)
            names = {
                member.name for member, _data in self.entries(archive)
            }
            self.assertIn(
                "PineAI/assets/pineai_backend/"
                "repeatable_audit_store.py",
                names,
            )

    def test_generated_bundle_is_sanitized_and_bound_to_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "PineAI.umd.js"
            bundle.write_bytes(
                b"(function(){return 'PineAI';}());\n"
                b"//# sourceMappingURL=PineAI.umd.js.map\n"
            )
            dist = root / "dist"
            package_tool.stage_runtime(bundle, dist)
            staged = dist / "PineAI.umd.js"
            self.assertNotIn(b"sourceMappingURL", staged.read_bytes())

            module = json.loads(
                (dist / "module.json").read_text(encoding="utf-8")
            )
            archive = root / "PineAI-{0}.tar.gz".format(module["version"])
            package_tool.create_package(dist, archive)
            package_tool.verify_package(
                archive,
                run_import_check=False,
                expected_bundle=staged,
            )

            other = root / "other.umd.js"
            other.write_bytes(b"(function(){return 'Other';}());\n")
            with self.assertRaises(package_tool.PackageError) as raised:
                package_tool.verify_package(
                    archive,
                    run_import_check=False,
                    expected_bundle=other,
                )
            self.assertEqual(raised.exception.code, "bundle_mismatch")

    @unittest.skipIf(
        os.name == "nt", "symlink creation is not portable on Windows"
    )
    def test_stage_rejects_output_directory_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "PineAI.umd.js"
            bundle.write_bytes(b"(function(){return 'PineAI';}());\n")
            target = root / "outside"
            target.mkdir()
            output = root / "dist"
            output.symlink_to(target, target_is_directory=True)

            with self.assertRaises(package_tool.PackageError) as raised:
                package_tool.stage_runtime(bundle, output)

            self.assertEqual(raised.exception.code, "stage_unsafe")
            self.assertEqual(list(target.iterdir()), [])

    def test_noncanonical_archive_encodings_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = self.build_package(directory)
            compressed = original.read_bytes()

            concatenated_dir = root / "concatenated"
            concatenated_dir.mkdir()
            concatenated = concatenated_dir / original.name
            concatenated.write_bytes(compressed + compressed)
            self.assert_package_error(concatenated, "archive_noncanonical")

            original_entries = self.entries(original)
            reordered_dir = root / "reordered"
            reordered_dir.mkdir()
            reordered = reordered_dir / original.name
            self.write_entries(
                reordered,
                [original_entries[1], original_entries[0]]
                + original_entries[2:],
            )
            self.assert_package_error(reordered, "archive_noncanonical")

            metadata_dir = root / "metadata"
            metadata_dir.mkdir()
            metadata = metadata_dir / original.name
            metadata_entries = self.entries(original)
            metadata_entries[0][0].mtime = 1
            self.write_entries(metadata, metadata_entries)
            self.assert_package_error(metadata, "archive_metadata")

    def test_missing_and_changed_runtime_files_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = self.build_package(directory)
            entries = self.entries(archive)

            missing = root / archive.name
            archive.rename(root / "original.tar.gz")
            self.write_entries(
                missing,
                [
                    item
                    for item in entries
                    if item[0].name
                    != "PineAI/assets/pineai_backend/"
                    "repeatable_audit_store.py"
                ],
            )
            self.assert_package_error(missing, "archive_mismatch")

            changed = root / "changed" / archive.name
            changed.parent.mkdir()
            changed_entries = self.entries(root / "original.tar.gz")
            for index, (member, data) in enumerate(changed_entries):
                if member.name.endswith("/customer_store.py"):
                    changed_entries[index] = (member, data + b"\n# changed\n")
            self.write_entries(changed, changed_entries)
            self.assert_package_error(changed, "source_mismatch")

    def test_duplicate_extra_secret_and_source_map_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = self.build_package(directory)
            original_entries = self.entries(original)
            original.rename(root / "original.tar.gz")

            duplicate = root / original.name
            duplicate_entries = list(original_entries)
            duplicate_entries.append(
                next(
                    item
                    for item in original_entries
                    if item[0].name == "PineAI/module.json"
                )
            )
            self.write_entries(duplicate, duplicate_entries)
            self.assert_package_error(duplicate, "archive_duplicate")

            extra_dir = root / "extra"
            extra_dir.mkdir()
            extra = extra_dir / original.name
            extra_entries = self.entries(root / "original.tar.gz")
            secret = tarfile.TarInfo("PineAI/assets/openai.key")
            secret.uid = 0
            secret.gid = 0
            secret.mode = 0o600
            secret.mtime = 0
            extra_entries.append((secret, b"secret-canary"))
            self.write_entries(extra, extra_entries)
            self.assert_package_error(extra, "archive_extra")

            map_dir = root / "map"
            map_dir.mkdir()
            source_map = map_dir / original.name
            map_entries = self.entries(root / "original.tar.gz")
            for index, (member, data) in enumerate(map_entries):
                if member.name == "PineAI/PineAI.umd.js":
                    map_entries[index] = (
                        member,
                        data + b"//# sourceMappingURL=PineAI.umd.js.map\n",
                    )
            self.write_entries(source_map, map_entries)
            self.assert_package_error(source_map, "forbidden_artifact")

    def test_unsafe_special_owner_and_mode_mutations_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = self.build_package(directory)
            original.rename(root / "original.tar.gz")

            cases = []

            unsafe_entries = self.entries(root / "original.tar.gz")
            unsafe = tarfile.TarInfo("PineAI/../escape")
            unsafe.uid = 0
            unsafe.gid = 0
            unsafe.mode = 0o644
            unsafe.mtime = 0
            unsafe_entries.append((unsafe, b"x"))
            cases.append(("unsafe", unsafe_entries, "archive_unsafe"))

            special_entries = self.entries(root / "original.tar.gz")
            special = tarfile.TarInfo("PineAI/assets/link")
            special.uid = 0
            special.gid = 0
            special.mode = 0o777
            special.mtime = 0
            special.type = tarfile.SYMTYPE
            special.linkname = "/tmp/escape"
            special_entries.append((special, None))
            cases.append(("special", special_entries, "archive_special"))

            owner_entries = self.entries(root / "original.tar.gz")
            owner_entries[0][0].uid = 1000
            cases.append(("owner", owner_entries, "archive_owner"))

            mode_entries = self.entries(root / "original.tar.gz")
            for member, _data in mode_entries:
                if member.name == "PineAI/module.py":
                    member.mode = 0o644
            cases.append(("mode", mode_entries, "archive_mode"))

            for name, entries, code in cases:
                with self.subTest(name=name):
                    case_directory = root / name
                    case_directory.mkdir()
                    path = case_directory / original.name
                    self.write_entries(path, entries)
                    self.assert_package_error(path, code)


if __name__ == "__main__":
    unittest.main()
