import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "projects" / "PineAI" / "src" / "assets"
sys.path.insert(0, str(ASSETS))

from pineai_backend.errors import BackendError  # noqa: E402
from pineai_backend.storage_transaction import (  # noqa: E402
    PrivateTransaction,
    recover_private_transactions,
)


class StorageTransactionTests(unittest.TestCase):
    def test_fault_stage_staged_abandoned_pre_prepare(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            calls = []

            def fault_injector(stage, index):
                calls.append((stage, index))
                if stage == "staged" and index == 0:
                    raise RuntimeError("simulated crash at staged 0")

            txn = PrivateTransaction(root, fault_injector=fault_injector)
            txn.add_json("doc1.json", {"a": 1})
            txn.add_json("doc2.json", {"b": 2})

            with self.assertRaises(RuntimeError):
                txn.commit()

            self.assertFalse((root / "doc1.json").exists())
            self.assertFalse((root / "doc2.json").exists())

            # Recover pre-prepare abandoned transaction
            recovered = recover_private_transactions(root)
            self.assertEqual(recovered, [])
            self.assertEqual(list((root / ".transactions").glob("*")), [])

    def test_fault_stage_prepared_roll_forward(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            def fault_injector(stage, index):
                if stage == "prepared":
                    raise RuntimeError("simulated crash after journal prepared")

            txn = PrivateTransaction(root, fault_injector=fault_injector)
            txn.add_json("data/one.json", {"item": 1})
            txn.add_json("data/two.json", {"item": 2})

            with self.assertRaises(RuntimeError):
                txn.commit()

            self.assertFalse((root / "data" / "one.json").exists())

            recovered = recover_private_transactions(root)
            self.assertEqual(len(recovered), 1)
            self.assertEqual(json.loads((root / "data" / "one.json").read_text()), {"item": 1})
            self.assertEqual(json.loads((root / "data" / "two.json").read_text()), {"item": 2})

    def test_fault_stage_target_written_partial_roll_forward(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            def fault_injector(stage, index):
                if stage == "target_written" and index == 0:
                    raise RuntimeError("crash after target 0 written")

            txn = PrivateTransaction(root, fault_injector=fault_injector)
            txn.add_json("f1.json", {"val": 1})
            txn.add_json("f2.json", {"val": 2})

            with self.assertRaises(RuntimeError):
                txn.commit()

            self.assertTrue((root / "f1.json").exists())
            self.assertFalse((root / "f2.json").exists())

            recovered = recover_private_transactions(root)
            self.assertEqual(len(recovered), 1)
            self.assertEqual(json.loads((root / "f1.json").read_text()), {"val": 1})
            self.assertEqual(json.loads((root / "f2.json").read_text()), {"val": 2})

    def test_fault_stage_committed_and_before_cleanup(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            def fault_injector(stage, index):
                if stage == "before_cleanup":
                    raise RuntimeError("crash before cleanup")

            txn = PrivateTransaction(root, fault_injector=fault_injector)
            txn.add_json("f1.json", {"val": 1})

            with self.assertRaises(RuntimeError):
                txn.commit()

            self.assertTrue((root / "f1.json").exists())

            recovered = recover_private_transactions(root)
            self.assertEqual(recovered, [])
            self.assertEqual(json.loads((root / "f1.json").read_text()), {"val": 1})

    def test_fault_stage_cleanup_failed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            cleanup_failed_called = []

            def fault_injector(stage, index):
                if stage == "cleanup_failed":
                    cleanup_failed_called.append(True)

            txn = PrivateTransaction(root, fault_injector=fault_injector)
            txn.add_json("f1.json", {"val": 1})

            # Mock shutil.rmtree to raise OSError
            original_rmtree = shutil.rmtree

            def mock_rmtree(path, *args, **kwargs):
                if ".transactions" in str(path):
                    raise OSError("permission denied")
                return original_rmtree(path, *args, **kwargs)

            shutil.rmtree = mock_rmtree
            try:
                txn.commit()
            finally:
                shutil.rmtree = original_rmtree

            self.assertTrue(cleanup_failed_called)
            self.assertTrue((root / "f1.json").exists())

            # Next recovery succeeds cleanly
            recovered = recover_private_transactions(root)
            self.assertEqual(recovered, [])

    def test_malformed_and_unsupported_journals(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            txns_dir = root / ".transactions" / "txn_test"
            txns_dir.mkdir(parents=True)

            # Unparseable JSON
            (txns_dir / "journal.json").write_text("invalid json", encoding="utf-8")
            with self.assertRaises(BackendError) as raised:
                recover_private_transactions(root)
            self.assertEqual(raised.exception.code, "transaction_recovery_failed")

            # Unsupported schema version
            (txns_dir / "journal.json").write_text(
                json.dumps({"schema_version": "9.9", "entries": []}), encoding="utf-8"
            )
            with self.assertRaises(BackendError) as raised:
                recover_private_transactions(root)
            self.assertEqual(raised.exception.code, "transaction_recovery_failed")

    def test_missing_and_corrupt_staged_documents(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            txns_dir = root / ".transactions" / "txn_test"
            txns_dir.mkdir(parents=True)
            (txns_dir / "staged").mkdir()

            journal = {
                "schema_version": "1.0",
                "transaction_id": "txn_test",
                "state": "prepared",
                "entries": [
                    {
                        "index": 0,
                        "target": "doc.json",
                        "staged": "staged/0000.json",
                        "sha256": "0" * 64,
                        "size": 10,
                    }
                ],
            }
            (txns_dir / "journal.json").write_text(json.dumps(journal), encoding="utf-8")

            # Missing staged document
            with self.assertRaises(BackendError) as raised:
                recover_private_transactions(root)
            self.assertEqual(raised.exception.code, "transaction_recovery_failed")

            # Corrupt staged document
            (txns_dir / "staged" / "0000.json").write_bytes(b"bad content")
            with self.assertRaises(BackendError) as raised:
                recover_private_transactions(root)
            self.assertEqual(raised.exception.code, "transaction_recovery_failed")

    def test_idempotent_recovery(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            txn = PrivateTransaction(root)
            txn.add_json("data.json", {"a": 1})
            res = txn.commit()
            self.assertEqual(res["state"], "committed")

            rec1 = recover_private_transactions(root)
            rec2 = recover_private_transactions(root)
            self.assertEqual(rec1, [])
            self.assertEqual(rec2, [])

    def test_symlink_escape_rejection(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            outside = root.parent / "outside_target.json"
            symlink_target = root / "symlink_doc.json"

            # Create symlink pointing outside
            try:
                symlink_target.symlink_to(outside)
            except (OSError, NotImplementedError):
                self.skipTest("Symlinks not supported on this platform/user permissions")

            txn = PrivateTransaction(root)
            with self.assertRaises(BackendError) as raised:
                txn.add_json("symlink_doc.json", {"val": 123})
            self.assertEqual(raised.exception.code, "invalid_transaction")

    def test_already_matching_targets_recovery(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            # Pre-create matching file on target
            target_file = root / "existing.json"
            payload = json.dumps({"val": 999}, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
            target_file.write_bytes(payload)

            written_calls = []

            def fault_injector(stage, index):
                if stage == "target_written":
                    written_calls.append(index)
                if stage == "prepared":
                    raise RuntimeError("crash after prepared")

            txn = PrivateTransaction(root, fault_injector=fault_injector)
            txn.add_json("existing.json", {"val": 999})

            with self.assertRaises(RuntimeError):
                txn.commit()

            # Target already matched so target_written was NOT triggered during commit
            self.assertEqual(written_calls, [])

            # Recovery rolls forward idempotently
            recovered = recover_private_transactions(root)
            self.assertEqual(len(recovered), 1)
            self.assertEqual(json.loads(target_file.read_text()), {"val": 999})


if __name__ == "__main__":
    unittest.main()
