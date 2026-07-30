"""Crash-recoverable multi-file transactions for PineAI private JSON state."""

import hashlib
import json
import os
import shutil
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .config import write_private_file
from .errors import BackendError


TRANSACTION_SCHEMA_VERSION = "1.0"


def _canonical_bytes(value: Any) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )
    except (TypeError, ValueError) as error:
        raise BackendError(
            "invalid_transaction", "transaction value must be valid JSON"
        ) from error


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(str(path), 0o700)
    except OSError:
        pass


def _safe_relative_path(value: str, root: Optional[Path] = None) -> Path:
    path = Path(value)
    if (
        not value
        or path.is_absolute()
        or ".." in path.parts
        or any(part in ("", ".") for part in path.parts)
    ):
        raise BackendError(
            "invalid_transaction", "transaction target path is invalid"
        )
    if root is not None:
        try:
            root_resolved = root.resolve()
            target_resolved = (root / path).resolve()
            target_resolved.relative_to(root_resolved)
        except (ValueError, OSError) as error:
            raise BackendError(
                "invalid_transaction", "transaction target path escapes root"
            ) from error
        if (root / path).is_symlink():
            raise BackendError(
                "invalid_transaction", "transaction target path is a symlink"
            )
    return path


class PrivateTransaction:
    """Stage and roll forward a bounded set of private JSON documents."""

    def __init__(
        self,
        root: Path,
        fault_injector: Optional[Callable[[str, int], None]] = None,
    ):
        self.root = root
        self.transactions = root / ".transactions"
        self.transaction_id = "txn_{0}".format(uuid.uuid4())
        self.directory = self.transactions / self.transaction_id
        self.fault_injector = fault_injector
        self._entries: List[Tuple[str, bytes]] = []

    def add_json(self, relative_path: str, value: Any) -> None:
        self.add_bytes(relative_path, _canonical_bytes(value))

    def add_bytes(self, relative_path: str, payload: bytes) -> None:
        """Add a private byte document, used for append-only JSONL snapshots."""
        path = _safe_relative_path(relative_path, root=self.root)
        normalized = path.as_posix()
        if any(existing == normalized for existing, _ in self._entries):
            raise BackendError(
                "invalid_transaction",
                "transaction target paths must be unique",
            )
        if not isinstance(payload, bytes):
            raise BackendError(
                "invalid_transaction", "transaction payload must be bytes"
            )
        self._entries.append((normalized, payload))

    def _fault(self, stage: str, index: int) -> None:
        if self.fault_injector is not None:
            self.fault_injector(stage, index)

    def commit(self) -> Dict[str, Any]:
        if not self._entries:
            raise BackendError(
                "invalid_transaction", "transaction has no documents"
            )
        _private_directory(self.root)
        _private_directory(self.transactions)
        _private_directory(self.directory)
        _private_directory(self.directory / "staged")

        manifest_entries = []
        for index, (relative, payload) in enumerate(self._entries):
            staged_name = "{0:04d}.json".format(index)
            write_private_file(self.directory / "staged" / staged_name, payload)
            manifest_entries.append(
                {
                    "index": index,
                    "target": relative,
                    "staged": "staged/{0}".format(staged_name),
                    "sha256": _sha256(payload),
                    "size": len(payload),
                }
            )
            self._fault("staged", index)

        journal = {
            "schema_version": TRANSACTION_SCHEMA_VERSION,
            "transaction_id": self.transaction_id,
            "state": "prepared",
            "entries": manifest_entries,
        }
        write_private_file(
            self.directory / "journal.json", _canonical_bytes(journal)
        )
        self._fault("prepared", -1)
        self._roll_forward(self.root, self.directory, fault_injector=self.fault_injector)
        return {
            "transaction_id": self.transaction_id,
            "document_count": len(manifest_entries),
            "state": "committed",
        }

    @staticmethod
    def _read_journal(directory: Path) -> Dict[str, Any]:
        try:
            journal = json.loads(
                (directory / "journal.json").read_text(encoding="utf-8")
            )
        except (OSError, ValueError) as error:
            raise BackendError(
                "transaction_recovery_failed",
                "a storage transaction journal is unreadable",
            ) from error
        if (
            not isinstance(journal, dict)
            or journal.get("schema_version") != TRANSACTION_SCHEMA_VERSION
            or not isinstance(journal.get("entries"), list)
        ):
            raise BackendError(
                "transaction_recovery_failed",
                "a storage transaction journal is invalid",
            )
        return journal

    @classmethod
    def _roll_forward(
        cls,
        root: Path,
        directory: Path,
        fault_injector: Optional[Callable[[str, int], None]] = None,
    ) -> None:
        def _trigger(stage: str, index: int) -> None:
            if fault_injector is not None:
                fault_injector(stage, index)

        journal = cls._read_journal(directory)
        root_resolved = root.resolve()

        for index, entry in enumerate(journal["entries"]):
            if not isinstance(entry, dict):
                raise BackendError(
                    "transaction_recovery_failed",
                    "a storage transaction entry is invalid",
                )
            try:
                relative = _safe_relative_path(str(entry.get("target", "")), root=root)
                staged_relative = _safe_relative_path(str(entry.get("staged", "")))
            except BackendError as error:
                raise BackendError(
                    "transaction_recovery_failed",
                    "a storage transaction target path is invalid",
                ) from error

            target = root / relative
            try:
                target_resolved = target.resolve()
                if target.is_symlink() or not str(target_resolved).startswith(str(root_resolved)):
                    raise BackendError(
                        "transaction_recovery_failed",
                        "transaction target path escapes root",
                    )
            except OSError as error:
                raise BackendError(
                    "transaction_recovery_failed",
                    "transaction target path is invalid",
                ) from error

            staged = directory / staged_relative
            expected = entry.get("sha256")
            if not isinstance(expected, str) or len(expected) != 64:
                raise BackendError(
                    "transaction_recovery_failed",
                    "a storage transaction digest is invalid",
                )

            target_matches = False
            if target.exists() and not target.is_symlink():
                try:
                    target_matches = _sha256(target.read_bytes()) == expected
                except OSError:
                    target_matches = False

            if target_matches:
                # Target already matches; skip writing and do not trigger target_written
                continue

            if not staged.exists():
                raise BackendError(
                    "transaction_recovery_failed",
                    "a staged transaction document is missing",
                )
            try:
                payload = staged.read_bytes()
            except OSError as error:
                raise BackendError(
                    "transaction_recovery_failed",
                    "a staged transaction document is unreadable",
                ) from error
            if _sha256(payload) != expected:
                raise BackendError(
                    "transaction_recovery_failed",
                    "a staged transaction document failed verification",
                )
            _private_directory(target.parent)
            write_private_file(target, payload)
            _trigger("target_written", index)

        write_private_file(directory / "COMMITTED", b"committed\n")
        _trigger("committed", -1)
        _trigger("before_cleanup", -1)
        try:
            shutil.rmtree(str(directory))
        except OSError:
            _trigger("cleanup_failed", -1)


def recover_private_transactions(root: Path) -> List[str]:
    """Roll forward every prepared transaction and remove committed or abandoned journals."""
    transactions = root / ".transactions"
    if not transactions.exists():
        return []
    recovered = []
    for directory in sorted(transactions.glob("txn_*")):
        if not directory.is_dir():
            continue
        if (directory / "COMMITTED").exists():
            try:
                shutil.rmtree(str(directory))
            except OSError:
                pass
            continue
        if not (directory / "journal.json").exists():
            # Abandoned pre-prepare transaction without journal or committed marker
            try:
                shutil.rmtree(str(directory))
            except OSError:
                pass
            continue
        PrivateTransaction._roll_forward(root, directory)
        recovered.append(directory.name)
    return recovered
