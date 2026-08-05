import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "projects" / "PineAI" / "src" / "assets"
sys.path.insert(0, str(ASSETS))

from pineai_backend.errors import BackendError  # noqa: E402
from pineai_backend.operation_lock import (  # noqa: E402
    scan_processing_lock,
    scan_processing_status,
)
from pineai_backend.platform import (  # noqa: E402
    MIN_AVAILABLE_MEMORY_BYTES,
    MIN_FREE_STORAGE_BYTES,
    require_operation_capacity,
    resource_telemetry,
)


class ResourceSafetyTests(unittest.TestCase):
    def test_telemetry_is_bounded_and_secret_free(self):
        with tempfile.TemporaryDirectory() as directory:
            assessments = Path(directory) / "assessments" / "assessment_test"
            assessments.mkdir(parents=True)
            (assessments / "artifact.json").write_text("{}", encoding="utf-8")
            result = resource_telemetry(directory, "assessment_test")
            self.assertIn(result["status"], ("ready", "degraded"))
            self.assertEqual(result["artifacts"]["assessment_count"], 1)
            self.assertEqual(result["artifacts"]["file_count"], 1)
            self.assertNotIn("assessment_test", repr(result))
            self.assertEqual(result["scan_processing"]["status"], "idle")

    def test_scan_lock_is_process_safe_and_private(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(scan_processing_status(directory), "idle")
            with scan_processing_lock(directory):
                self.assertEqual(scan_processing_status(directory), "busy")
                with self.assertRaises(BackendError) as raised:
                    with scan_processing_lock(directory):
                        pass
                self.assertEqual(raised.exception.code, "scan_processing_busy")
            lock_path = Path(directory) / ".locks" / "scan-processing.lock"
            self.assertTrue(lock_path.is_file())
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(lock_path.stat().st_mode), 0o600)

    def test_resource_guard_rejects_low_memory_and_storage(self):
        base = {
            "schema_version": "1.0",
            "status": "ready",
            "blocking_codes": [],
            "warnings": [],
            "memory": {
                "mem_available_bytes": MIN_AVAILABLE_MEMORY_BYTES,
            },
            "storage": {
                "status": "ready",
                "free_bytes": MIN_FREE_STORAGE_BYTES,
            },
        }
        with mock.patch(
            "pineai_backend.platform.resource_telemetry", return_value=base
        ):
            with self.assertRaises(BackendError) as raised:
                require_operation_capacity(payload_bytes=1)
            self.assertEqual(raised.exception.code, "resource_guard_blocked")

    def test_resource_guard_accepts_available_headroom(self):
        base = {
            "schema_version": "1.0",
            "status": "ready",
            "blocking_codes": [],
            "warnings": [],
            "memory": {
                "mem_available_bytes": MIN_AVAILABLE_MEMORY_BYTES + 64 * 1024 * 1024,
            },
            "storage": {
                "status": "ready",
                "free_bytes": MIN_FREE_STORAGE_BYTES + 64 * 1024 * 1024,
            },
        }
        with mock.patch(
            "pineai_backend.platform.resource_telemetry", return_value=base
        ):
            self.assertIs(
                require_operation_capacity(payload_bytes=1024), base
            )


if __name__ == "__main__":
    unittest.main()
