"""Crash-recoverable multi-file transactions for PineAI private JSON state."""

import hashlib
import json
import os
import re
import shutil
import stat
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .config import write_private_file
from .errors import BackendError


TRANSACTION_SCHEMA_VERSION = "1.0"
MAX_TRANSACTION_ENTRIES = 64
MAX_TRANSACTION_DOCUMENT_BYTES = 8 * 1024 * 1024
MAX_TRANSACTION_TOTAL_BYTES = 32 * 1024 * 1024
MAX_TRANSACTION_JOURNAL_BYTES = 256 * 1024
MAX_TRANSACTION_DIRECTORIES = 128
TRANSACTION_ID_PATTERN = re.compile(
    r"^txn_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


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


def _fsync_directory(path: Path) -> None:
    """Best-effort directory durability for Linux/Mark VII filesystems."""
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = None
    try:
        descriptor = os.open(str(path), flags)
        os.fsync(descriptor)
    except OSError:
        # Windows and some filesystems do not support directory fsync.
        pass
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _path_details(path: Path):
    try:
        return path.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise BackendError(
            "transaction_recovery_failed",
            "a storage transaction path is unreadable",
        ) from error


def _private_directory(path: Path) -> None:
    details = _path_details(path)
    if details is not None:
        if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
            raise BackendError(
                "invalid_transaction",
                "transaction directory must be a real directory",
            )
    else:
        path.mkdir(parents=True, exist_ok=False)
        _fsync_directory(path.parent)
    try:
        os.chmod(str(path), 0o700)
    except OSError:
        pass


def _safe_relative_path(value: str, root: Optional[Path] = None) -> Path:
    if not isinstance(value, str):
        raise BackendError(
            "invalid_transaction", "transaction target path is invalid"
        )
    path = Path(value)
    if (
        not value
        or "\x00" in value
        or "\\" in value
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
        current = root
        for index, part in enumerate(path.parts):
            current = current / part
            details = _path_details(current)
            if details is None:
                continue
            if stat.S_ISLNK(details.st_mode):
                raise BackendError(
                    "invalid_transaction",
                    "transaction target path contains a symlink",
                )
            if index < len(path.parts) - 1 and not stat.S_ISDIR(
                details.st_mode
            ):
                raise BackendError(
                    "invalid_transaction",
                    "transaction target parent is not a directory",
                )
            if (
                index == len(path.parts) - 1
                and not stat.S_ISREG(details.st_mode)
            ):
                raise BackendError(
                    "invalid_transaction",
                    "transaction target path is not a regular file",
                )
    return path


def _read_regular_file(
    path: Path,
    maximum_bytes: int,
    error_code: str,
    error_message: str,
    expected_size: Optional[int] = None,
) -> bytes:
    details = _path_details(path)
    if (
        details is None
        or stat.S_ISLNK(details.st_mode)
        or not stat.S_ISREG(details.st_mode)
        or details.st_size > maximum_bytes
        or (expected_size is not None and details.st_size != expected_size)
    ):
        raise BackendError(error_code, error_message)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = None
    try:
        descriptor = os.open(str(path), flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size != details.st_size
            or getattr(opened, "st_ino", 0) != getattr(details, "st_ino", 0)
        ):
            raise BackendError(error_code, error_message)
        chunks = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                raise BackendError(error_code, error_message)
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise BackendError(error_code, error_message)
        return b"".join(chunks)
    except BackendError:
        raise
    except OSError as error:
        raise BackendError(error_code, error_message) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _remove_transaction_directory(transactions: Path, directory: Path) -> None:
    details = _path_details(directory)
    if details is None:
        return
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
        raise BackendError(
            "transaction_recovery_failed",
            "a storage transaction directory is invalid",
        )
    try:
        shutil.rmtree(str(directory))
        _fsync_directory(transactions)
    except OSError as error:
        raise BackendError(
            "transaction_recovery_failed",
            "a storage transaction could not be cleaned up",
        ) from error


def _bounded_directory_entries(directory: Path, maximum: int) -> List[Path]:
    entries = []
    try:
        with os.scandir(str(directory)) as iterator:
            for entry in iterator:
                entries.append(Path(entry.path))
                if len(entries) > maximum:
                    raise BackendError(
                        "transaction_recovery_failed",
                        "storage transaction directory limit was exceeded",
                    )
    except BackendError:
        raise
    except OSError as error:
        raise BackendError(
            "transaction_recovery_failed",
            "storage transaction root is unreadable",
        ) from error
    return sorted(entries, key=lambda item: item.name)


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
        if len(self._entries) >= MAX_TRANSACTION_ENTRIES:
            raise BackendError(
                "invalid_transaction",
                "transaction contains too many documents",
            )
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
        if len(payload) > MAX_TRANSACTION_DOCUMENT_BYTES:
            raise BackendError(
                "invalid_transaction",
                "transaction document exceeds the safe size limit",
            )
        if (
            sum(len(existing_payload) for _, existing_payload in self._entries)
            + len(payload)
            > MAX_TRANSACTION_TOTAL_BYTES
        ):
            raise BackendError(
                "invalid_transaction",
                "transaction exceeds the safe total size limit",
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
        existing_transactions = _bounded_directory_entries(
            self.transactions, MAX_TRANSACTION_DIRECTORIES
        )
        if len(existing_transactions) >= MAX_TRANSACTION_DIRECTORIES:
            raise BackendError(
                "invalid_transaction",
                "transaction directory capacity limit was reached",
            )
        _private_directory(self.directory)
        _private_directory(self.directory / "staged")

        prepared = False
        try:
            manifest_entries = []
            for index, (relative, payload) in enumerate(self._entries):
                staged_name = "{0:04d}.json".format(index)
                write_private_file(
                    self.directory / "staged" / staged_name, payload
                )
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
            journal_bytes = _canonical_bytes(journal)
            if len(journal_bytes) > MAX_TRANSACTION_JOURNAL_BYTES:
                raise BackendError(
                    "invalid_transaction",
                    "transaction journal exceeds the safe size limit",
                )
            write_private_file(self.directory / "journal.json", journal_bytes)
            prepared = True
            self._fault("prepared", -1)
            self._roll_forward(
                self.root,
                self.directory,
                fault_injector=self.fault_injector,
            )
            return {
                "transaction_id": self.transaction_id,
                "document_count": len(manifest_entries),
                "state": "committed",
            }
        except BaseException:
            # A transaction without a prepared journal has never published any
            # target and is safe for its creator to remove. Recovery never
            # guesses that an unjournaled directory owned by another process is
            # abandoned.
            if not prepared:
                try:
                    _remove_transaction_directory(
                        self.transactions, self.directory
                    )
                except BackendError:
                    pass
            raise

    @staticmethod
    def _read_journal(directory: Path) -> Dict[str, Any]:
        try:
            raw = _read_regular_file(
                directory / "journal.json",
                MAX_TRANSACTION_JOURNAL_BYTES,
                "transaction_recovery_failed",
                "a storage transaction journal is unreadable",
            )
            journal = json.loads(raw.decode("utf-8"))
        except (UnicodeError, ValueError) as error:
            raise BackendError(
                "transaction_recovery_failed",
                "a storage transaction journal is unreadable",
            ) from error
        expected_fields = {
            "schema_version",
            "transaction_id",
            "state",
            "entries",
        }
        if not isinstance(journal, dict) or set(journal) != expected_fields:
            raise BackendError(
                "transaction_recovery_failed",
                "a storage transaction journal is invalid",
            )
        entries = journal.get("entries")
        if (
            journal.get("schema_version") != TRANSACTION_SCHEMA_VERSION
            or journal.get("transaction_id") != directory.name
            or not TRANSACTION_ID_PATTERN.match(
                str(journal.get("transaction_id", ""))
            )
            or journal.get("state") != "prepared"
            or not isinstance(entries, list)
            or not entries
            or len(entries) > MAX_TRANSACTION_ENTRIES
        ):
            raise BackendError(
                "transaction_recovery_failed",
                "a storage transaction journal is invalid",
            )

        seen_targets = set()
        seen_staged = set()
        total_bytes = 0
        for expected_index, entry in enumerate(entries):
            if (
                not isinstance(entry, dict)
                or set(entry)
                != {"index", "target", "staged", "sha256", "size"}
            ):
                raise BackendError(
                    "transaction_recovery_failed",
                    "a storage transaction entry is invalid",
                )
            index = entry.get("index")
            size = entry.get("size")
            target = entry.get("target")
            staged = entry.get("staged")
            digest = entry.get("sha256")
            if (
                not isinstance(index, int)
                or isinstance(index, bool)
                or index != expected_index
                or not isinstance(size, int)
                or isinstance(size, bool)
                or size < 0
                or size > MAX_TRANSACTION_DOCUMENT_BYTES
                or not isinstance(target, str)
                or not isinstance(staged, str)
                or staged != "staged/{0:04d}.json".format(expected_index)
                or target in seen_targets
                or staged in seen_staged
                or not isinstance(digest, str)
                or not SHA256_PATTERN.match(digest)
            ):
                raise BackendError(
                    "transaction_recovery_failed",
                    "a storage transaction entry is invalid",
                )
            try:
                _safe_relative_path(target)
                _safe_relative_path(staged)
            except BackendError as error:
                raise BackendError(
                    "transaction_recovery_failed",
                    "a storage transaction entry path is invalid",
                ) from error
            seen_targets.add(target)
            seen_staged.add(staged)
            total_bytes += size
            if total_bytes > MAX_TRANSACTION_TOTAL_BYTES:
                raise BackendError(
                    "transaction_recovery_failed",
                    "a storage transaction exceeds the safe total size limit",
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

        root_details = _path_details(root)
        directory_details = _path_details(directory)
        if (
            root_details is None
            or stat.S_ISLNK(root_details.st_mode)
            or not stat.S_ISDIR(root_details.st_mode)
            or directory_details is None
            or stat.S_ISLNK(directory_details.st_mode)
            or not stat.S_ISDIR(directory_details.st_mode)
            or directory.parent != root / ".transactions"
            or not TRANSACTION_ID_PATTERN.match(directory.name)
        ):
            raise BackendError(
                "transaction_recovery_failed",
                "a storage transaction directory is invalid",
            )
        journal = cls._read_journal(directory)

        for index, entry in enumerate(journal["entries"]):
            try:
                relative = _safe_relative_path(entry["target"], root=root)
            except BackendError as error:
                raise BackendError(
                    "transaction_recovery_failed",
                    "a storage transaction target path is invalid",
                ) from error

            target = root / relative
            target_details = _path_details(target)
            if target_details is not None and (
                stat.S_ISLNK(target_details.st_mode)
                or not stat.S_ISREG(target_details.st_mode)
            ):
                raise BackendError(
                    "transaction_recovery_failed",
                    "transaction target path is invalid",
                )

            expected = entry["sha256"]
            expected_size = entry["size"]
            target_matches = False
            if target_details is not None and target_details.st_size == expected_size:
                try:
                    target_payload = _read_regular_file(
                        target,
                        MAX_TRANSACTION_DOCUMENT_BYTES,
                        "transaction_recovery_failed",
                        "transaction target path is unreadable",
                        expected_size,
                    )
                    target_matches = _sha256(target_payload) == expected
                except BackendError:
                    target_matches = False

            if target_matches:
                continue

            staged = directory / entry["staged"]
            try:
                staged.relative_to(directory)
            except ValueError as error:
                raise BackendError(
                    "transaction_recovery_failed",
                    "a staged transaction path escapes its directory",
                ) from error
            staged_parent = _path_details(staged.parent)
            if (
                staged_parent is None
                or stat.S_ISLNK(staged_parent.st_mode)
                or not stat.S_ISDIR(staged_parent.st_mode)
            ):
                raise BackendError(
                    "transaction_recovery_failed",
                    "a staged transaction directory is invalid",
                )
            payload = _read_regular_file(
                staged,
                MAX_TRANSACTION_DOCUMENT_BYTES,
                "transaction_recovery_failed",
                "a staged transaction document is missing or unreadable",
                expected_size,
            )
            if _sha256(payload) != expected:
                raise BackendError(
                    "transaction_recovery_failed",
                    "a staged transaction document failed verification",
                )
            try:
                _private_directory(target.parent)
            except BackendError as error:
                raise BackendError(
                    "transaction_recovery_failed",
                    "transaction target parent is invalid",
                ) from error
            write_private_file(target, payload)
            _trigger("target_written", index)

        committed = directory / "COMMITTED"
        committed_details = _path_details(committed)
        if committed_details is not None and (
            stat.S_ISLNK(committed_details.st_mode)
            or not stat.S_ISREG(committed_details.st_mode)
        ):
            raise BackendError(
                "transaction_recovery_failed",
                "a storage transaction commit marker is invalid",
            )
        write_private_file(committed, b"committed\n")
        _trigger("committed", -1)
        _trigger("before_cleanup", -1)
        try:
            _remove_transaction_directory(root / ".transactions", directory)
        except BackendError:
            _trigger("cleanup_failed", -1)


def recover_private_transactions(
    root: Path, cleanup_unprepared: bool = False
) -> List[str]:
    """Roll forward prepared transactions under the caller's storage lock.

    `cleanup_unprepared` may be enabled only while the exclusive lock for
    `root` is held. It removes crash residue that never reached the prepared
    journal boundary without racing a live stager.
    """
    if not isinstance(cleanup_unprepared, bool):
        raise BackendError(
            "transaction_recovery_failed",
            "transaction recovery mode is invalid",
        )
    transactions = root / ".transactions"
    details = _path_details(transactions)
    if details is None:
        return []
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
        raise BackendError(
            "transaction_recovery_failed",
            "storage transaction root is invalid",
        )
    directories = _bounded_directory_entries(
        transactions, MAX_TRANSACTION_DIRECTORIES
    )

    recovered = []
    for directory in directories:
        directory_details = _path_details(directory)
        if (
            not TRANSACTION_ID_PATTERN.match(directory.name)
            or directory_details is None
            or stat.S_ISLNK(directory_details.st_mode)
            or not stat.S_ISDIR(directory_details.st_mode)
        ):
            raise BackendError(
                "transaction_recovery_failed",
                "a storage transaction directory is invalid",
            )

        committed = directory / "COMMITTED"
        committed_details = _path_details(committed)
        if committed_details is not None:
            committed_payload = _read_regular_file(
                committed,
                32,
                "transaction_recovery_failed",
                "a storage transaction commit marker is invalid",
            )
            if committed_payload != b"committed\n":
                raise BackendError(
                    "transaction_recovery_failed",
                    "a storage transaction commit marker is invalid",
                )
            _remove_transaction_directory(transactions, directory)
            continue

        journal_details = _path_details(directory / "journal.json")
        if journal_details is None:
            if cleanup_unprepared:
                _remove_transaction_directory(transactions, directory)
            # Without an exclusive caller-owned lock, a different process may
            # still be staging this transaction. Never infer abandonment.
            continue
        if stat.S_ISLNK(journal_details.st_mode) or not stat.S_ISREG(
            journal_details.st_mode
        ):
            raise BackendError(
                "transaction_recovery_failed",
                "a storage transaction journal is invalid",
            )
        PrivateTransaction._roll_forward(root, directory)
        recovered.append(directory.name)
    return recovered
