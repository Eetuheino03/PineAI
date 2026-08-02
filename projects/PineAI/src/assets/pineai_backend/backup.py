"""Portable, secret-minimized PineAI device continuity backups.

Backups contain deterministic assessment state (including nested assurance
profiles), top-level measurement profiles, the non-secret configuration, and
the pseudonymization identity required to keep stable IDs continuous.  The
optional OpenAI key and transient storage locks/transactions are never
included.

The restore operation always targets a new or empty staging directory.  It
never extracts over a live PineAI configuration directory.
"""

import base64
import hashlib
import io
import json
import os
import re
import shutil
import stat
import tarfile
import tempfile
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Dict, List, Optional, Tuple

from .assessment_store import _ensure_no_raw_recon
from .config import (
    _validate_settings,
    resolve_config_dir,
)
from .errors import BackendError
from .storage_transaction import recover_private_transactions


BACKUP_SCHEMA_VERSION = "1.0"
BACKUP_TYPE = "pineai_device_continuity"
MANIFEST_NAME = "manifest.json"
DATA_PREFIX = "data"
ALLOWED_DIRECTORIES = ("assessments", "measurement_profiles")
ALLOWED_FILES = ("config.json", "pseudonymization.key")
SECRET_EXCLUDED_NAMES = {"openai.key"}
TRANSIENT_EXCLUDED_NAMES = {".lock", ".transactions"}
TRANSIENT_EXCLUDED_NAMES.add("exports")
EXCLUDED_NAMES = SECRET_EXCLUDED_NAMES | TRANSIENT_EXCLUDED_NAMES
MAX_MEMBERS = 10000
MAX_FILES = 9000
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_BYTES = 544 * 1024 * 1024
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
COPY_CHUNK_BYTES = 64 * 1024
MAX_ASSESSMENTS_FOR_BACKUP = 1000
MAX_PAX_HEADER_BYTES = 4 * 1024
MAX_PAX_TOTAL_BYTES = 2 * 1024 * 1024
MAX_PAX_HEADERS = MAX_MEMBERS
RFC3339_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$"
)


def _validate_local_pax_payload(archive: tarfile.TarFile, size: int) -> str:
    """Validate the only PAX extension emitted by the backup writer."""

    fileobj = archive.fileobj
    padded_size = ((size + tarfile.BLOCKSIZE - 1) // tarfile.BLOCKSIZE) * tarfile.BLOCKSIZE
    try:
        position = fileobj.tell()
        raw = fileobj.read(padded_size)
        fileobj.seek(position)
    except (AttributeError, OSError, tarfile.TarError) as failure:
        raise BackendError(
            "backup_invalid", "could not validate backup extended metadata"
        ) from failure
    if len(raw) != padded_size or raw[size:] != b"\0" * (padded_size - size):
        raise BackendError(
            "backup_invalid", "backup extended metadata framing is invalid"
        )

    payload = raw[:size]
    offset = 0
    path_value = None
    while offset < len(payload):
        separator = payload.find(b" ", offset)
        if separator <= offset:
            raise BackendError(
                "backup_invalid", "backup extended metadata record is invalid"
            )
        length_field = payload[offset:separator]
        if (
            not length_field.isdigit()
            or (len(length_field) > 1 and length_field.startswith(b"0"))
        ):
            raise BackendError(
                "backup_invalid", "backup extended metadata length is invalid"
            )
        record_length = int(length_field)
        record_end = offset + record_length
        if (
            record_length < 7
            or str(record_length).encode("ascii") != length_field
            or record_end > len(payload)
            or payload[record_end - 1 : record_end] != b"\n"
        ):
            raise BackendError(
                "backup_invalid", "backup extended metadata framing is invalid"
            )
        body = payload[separator + 1 : record_end - 1]
        key, equals, value = body.partition(b"=")
        if key != b"path" or equals != b"=" or not value or path_value is not None:
            raise BackendError(
                "backup_unsafe_member",
                "backup extended metadata key is unsupported",
            )
        try:
            path_value = value.decode("utf-8", "strict")
        except UnicodeDecodeError as failure:
            raise BackendError(
                "backup_invalid", "backup extended metadata path is invalid"
            ) from failure
        offset = record_end
    if offset != len(payload) or path_value is None:
        raise BackendError(
            "backup_invalid", "backup extended metadata payload is invalid"
        )
    return path_value


class _BoundedBackupTarInfo(tarfile.TarInfo):
    """Reject expensive or unsupported tar metadata before stdlib parses it."""

    def _proc_member(self, archive: tarfile.TarFile) -> tarfile.TarInfo:
        size = self.size
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise BackendError(
                "backup_invalid", "backup member size is invalid"
            )

        if self.type == tarfile.XGLTYPE:
            raise BackendError(
                "backup_unsafe_member",
                "backup global extended metadata is unsupported",
            )
        if self.type == tarfile.XHDTYPE:
            if size > MAX_PAX_HEADER_BYTES:
                raise BackendError(
                    "backup_limit",
                    "backup extended metadata exceeds the safe size limit",
                )
            header_count = getattr(archive, "_pineai_pax_header_count", 0) + 1
            header_bytes = getattr(archive, "_pineai_pax_header_bytes", 0) + size
            if (
                header_count > MAX_PAX_HEADERS
                or header_bytes > MAX_PAX_TOTAL_BYTES
            ):
                raise BackendError(
                    "backup_limit",
                    "backup extended metadata exceeds the safe aggregate limit",
                )
            archive._pineai_pax_header_count = header_count
            archive._pineai_pax_header_bytes = header_bytes
            _validate_local_pax_payload(archive, size)
        elif self.type in (tarfile.REGTYPE, tarfile.AREGTYPE):
            if size > MAX_MEMBER_BYTES:
                raise BackendError(
                    "backup_limit",
                    "a backup member exceeds the safe size limit",
                )
        elif self.type == tarfile.DIRTYPE:
            if size != 0:
                raise BackendError(
                    "backup_invalid", "backup directory size is invalid"
                )
        else:
            raise BackendError(
                "backup_unsafe_member",
                "backup contains a link or unsupported tar extension",
            )
        return super()._proc_member(archive)


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise BackendError("backup_invalid", "backup metadata is not valid JSON")


def _sha256_stream(handle: BinaryIO) -> Tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    while True:
        chunk = handle.read(COPY_CHUNK_BYTES)
        if not chunk:
            break
        size += len(chunk)
        if size > MAX_MEMBER_BYTES:
            raise BackendError(
                "backup_limit", "a backup file exceeds the safe size limit"
            )
        digest.update(chunk)
    return digest.hexdigest(), size


def _sha256_path(path: Path) -> Tuple[str, int]:
    try:
        before = path.lstat()
    except OSError as failure:
        raise BackendError(
            "backup_io_error",
            "could not inspect backup source file",
        ) from failure
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_size > MAX_MEMBER_BYTES
    ):
        raise BackendError(
            "backup_unsafe_source",
            "backup source must be a bounded regular file",
        )
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = None
    try:
        descriptor = os.open(str(path), flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size != before.st_size
            or getattr(opened, "st_ino", 0)
            != getattr(before, "st_ino", 0)
        ):
            raise BackendError(
                "backup_source_changed",
                "backup source changed while it was being opened",
            )
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            return _sha256_stream(handle)
    except BackendError:
        raise
    except OSError as failure:
        raise BackendError(
            "backup_io_error",
            "could not read backup source file",
        ) from failure
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _archive_sha256(path: Path) -> str:
    with _open_archive_source(path) as handle:
        digest, _size = _archive_stream_sha256(handle)
        return digest


def _archive_stream_sha256(handle: BinaryIO) -> Tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    while True:
        chunk = handle.read(COPY_CHUNK_BYTES)
        if not chunk:
            break
        size += len(chunk)
        if size > MAX_ARCHIVE_BYTES:
            raise BackendError(
                "backup_limit", "backup archive exceeds the safe size limit"
            )
        digest.update(chunk)
    return digest.hexdigest(), size


@contextmanager
def _open_archive_source(path: Path):
    try:
        before = path.lstat()
    except OSError as failure:
        raise BackendError(
            "backup_invalid", "backup input must be a regular file"
        ) from failure
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_size > MAX_ARCHIVE_BYTES
    ):
        code = (
            "backup_limit"
            if stat.S_ISREG(before.st_mode)
            and before.st_size > MAX_ARCHIVE_BYTES
            else "backup_invalid"
        )
        raise BackendError(code, "backup input must be a bounded regular file")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = None
    try:
        descriptor = os.open(str(path), flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size != before.st_size
            or getattr(opened, "st_dev", 0) != getattr(before, "st_dev", 0)
            or getattr(opened, "st_ino", 0) != getattr(before, "st_ino", 0)
        ):
            raise BackendError(
                "backup_source_changed",
                "backup archive changed while it was being opened",
            )
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            yield handle
            after = os.fstat(handle.fileno())
            if (
                after.st_size != opened.st_size
                or getattr(after, "st_dev", 0) != getattr(opened, "st_dev", 0)
                or getattr(after, "st_ino", 0) != getattr(opened, "st_ino", 0)
            ):
                raise BackendError(
                    "backup_source_changed",
                    "backup archive changed while it was being read",
                )
    except BackendError:
        raise
    except OSError as failure:
        raise BackendError(
            "backup_io_error", "could not read backup archive"
        ) from failure
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _validate_relative_path(value: Any, directory: bool = False) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\x00" in value
        or "\\" in value
    ):
        raise BackendError("backup_unsafe_path", "backup path is invalid")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in ("", ".", "..") for part in path.parts)
    ):
        raise BackendError("backup_unsafe_path", "backup path is unsafe")
    if any(part in SECRET_EXCLUDED_NAMES for part in path.parts):
        raise BackendError(
            "backup_contains_secret", "backup contains a prohibited secret file"
        )
    if any(part in TRANSIENT_EXCLUDED_NAMES for part in path.parts):
        raise BackendError(
            "backup_unsafe_member",
            "backup contains a transient lock or transaction",
        )
    root = path.parts[0]
    if directory:
        if root not in ALLOWED_DIRECTORIES:
            raise BackendError(
                "backup_unsafe_path", "backup directory is outside the allowlist"
            )
    elif root in ALLOWED_FILES:
        if len(path.parts) != 1:
            raise BackendError("backup_unsafe_path", "backup file path is invalid")
    elif root not in ALLOWED_DIRECTORIES or len(path.parts) < 2:
        raise BackendError(
            "backup_unsafe_path", "backup file is outside the allowlist"
        )
    return path.as_posix()


def _assessment_names(root: Path) -> List[str]:
    directory = root / "assessments"
    if not directory.exists():
        return []
    if directory.is_symlink() or not directory.is_dir():
        raise BackendError(
            "backup_unsafe_source",
            "assessments must be a real directory",
        )
    identifiers = []
    try:
        with os.scandir(str(directory)) as iterator:
            for entry in iterator:
                if entry.name in (".transactions",):
                    continue
                if (
                    not entry.is_dir(follow_symlinks=False)
                    or not re.match(
                        r"^assessment_[0-9a-f]{8}-[0-9a-f]{4}-"
                        r"4[0-9a-f]{3}-[89ab][0-9a-f]{3}-"
                        r"[0-9a-f]{12}$",
                        entry.name,
                    )
                ):
                    raise BackendError(
                        "backup_unsafe_source",
                        "assessment storage contains an invalid entry",
                    )
                identifiers.append(entry.name)
                if len(identifiers) > MAX_ASSESSMENTS_FOR_BACKUP:
                    raise BackendError(
                        "backup_limit", "backup contains too many assessments"
                    )
    except BackendError:
        raise
    except OSError as failure:
        raise BackendError(
            "backup_io_error", "could not enumerate assessments"
        ) from failure
    return sorted(identifiers)


def _assert_no_active_transactions(root: Path) -> None:
    visited = 0
    for allowed in ALLOWED_DIRECTORIES:
        directory = root / allowed
        if not directory.exists():
            continue
        for current_root, directory_names, _ in os.walk(
            str(directory), topdown=True, followlinks=False
        ):
            visited += 1
            if visited > MAX_MEMBERS:
                raise BackendError(
                    "backup_limit",
                    "backup source directory limit was exceeded",
                )
            current = Path(current_root)
            if ".transactions" in directory_names:
                transaction_root = current / ".transactions"
                if transaction_root.is_symlink() or not transaction_root.is_dir():
                    raise BackendError(
                        "backup_unsafe_source",
                        "transaction storage is invalid",
                    )
                try:
                    with os.scandir(str(transaction_root)) as iterator:
                        if next(iterator, None) is not None:
                            raise BackendError(
                                "backup_busy",
                                "backup cannot run while a transaction is active",
                            )
                except BackendError:
                    raise
                except OSError as failure:
                    raise BackendError(
                        "backup_io_error",
                        "could not inspect transaction storage",
                    ) from failure
                directory_names.remove(".transactions")
            directory_names[:] = [
                name for name in directory_names if name != ".lock"
            ]


def _validate_source_path_contract(relative: str) -> None:
    parts = PurePosixPath(relative).parts
    if len(parts) == 1:
        if parts[0] not in ALLOWED_FILES:
            raise BackendError(
                "backup_unsafe_source",
                "backup source contains an unsupported top-level file",
            )
        return
    if parts[0] == "measurement_profiles":
        if (
            len(parts) < 2
            or not re.match(
                r"^mprofile_[0-9a-f]{8}-[0-9a-f]{4}-"
                r"4[0-9a-f]{3}-[89ab][0-9a-f]{3}-"
                r"[0-9a-f]{12}$",
                parts[1],
            )
        ):
            raise BackendError(
                "backup_unsafe_source",
                "measurement profile storage contains an invalid identity",
            )
        valid = (
            len(parts) == 3 and parts[2] == "profile.json"
        ) or (
            len(parts) == 4
            and parts[2] == "versions"
            and re.match(r"^mprofile_r[0-9]{4}\.json$", parts[3])
        )
        if not valid:
            raise BackendError(
                "backup_unsafe_source",
                "measurement profile storage contains an unsupported file",
            )
        return
    if parts[0] == "assessments":
        if (
            len(parts) < 2
            or not re.match(
                r"^assessment_[0-9a-f]{8}-[0-9a-f]{4}-"
                r"4[0-9a-f]{3}-[89ab][0-9a-f]{3}-"
                r"[0-9a-f]{12}$",
                parts[1],
            )
        ):
            raise BackendError(
                "backup_unsafe_source",
                "assessment storage contains an invalid identity",
            )
        top_level = {
            "assessment.json",
            "events.jsonl",
            "findings.json",
            "measurement_points.json",
            "audit_runs_manifest.json",
        }
        document_patterns = {
            "baselines": r"^baseline_v[0-9]{4}\.json$",
            "snapshots": r"^snapshot_[0-9a-f]{16}\.json$",
            "comparisons": r"^comparison_[0-9a-f]{16}\.json$",
            "baseline_models": r"^bmodel_[0-9a-f]{16}\.json$",
            "assurance_profiles": r"^assurance_v[0-9]{4}\.json$",
            "occurrences": r"^occurrence_[0-9a-f]{16}\.json$",
            "audit_runs": r"^ar_[0-9a-f]{16}\.json$",
        }
        split_audit_run = (
            len(parts) == 5
            and parts[2] == "audit_runs"
            and re.match(r"^ar_[0-9a-f]{16}$", parts[3])
            and parts[4] in {"manifest.json", "migration.json"}
        ) or (
            len(parts) == 6
            and parts[2] == "audit_runs"
            and re.match(r"^ar_[0-9a-f]{16}$", parts[3])
            and parts[4] == "measurements"
            and re.match(r"^arm_[0-9a-f]{16}\.json$", parts[5])
        )
        valid = (
            len(parts) == 3 and parts[2] in top_level
        ) or (
            len(parts) == 4
            and parts[2] in document_patterns
            and re.match(
                document_patterns[parts[2]],
                parts[3],
            )
        ) or split_audit_run
        if not valid:
            raise BackendError(
                "backup_unsafe_source",
                "assessment storage contains an unsupported file",
            )
        return
    raise BackendError(
        "backup_unsafe_source",
        "backup source file is outside the storage contract",
    )


def _validate_content_bytes(payload: bytes, relative: str) -> None:
    if relative == "pseudonymization.key":
        try:
            secret = base64.b64decode(payload.strip(), validate=True)
            if len(secret) != 32:
                raise ValueError()
        except Exception as error:
            raise BackendError(
                "backup_identity_invalid",
                "pseudonymization.key is invalid",
            ) from error
        return
    if relative.endswith("events.jsonl"):
        try:
            for line in payload.decode("utf-8").splitlines():
                if line.strip():
                    _ensure_no_raw_recon(json.loads(line))
        except BackendError:
            raise
        except Exception as error:
            raise BackendError(
                "backup_unsafe_source",
                "backup source JSONL is invalid",
            ) from error
        return
    if not relative.endswith(".json"):
        return
    try:
        value = json.loads(payload.decode("utf-8"))
        if relative == "config.json":
            _validate_settings(value)
        else:
            _ensure_no_raw_recon(value)
    except BackendError:
        raise
    except Exception as error:
        raise BackendError(
            "backup_unsafe_source",
            "backup source JSON is invalid",
        ) from error


def _validate_source_content(path: Path, relative: str, size: int) -> None:
    try:
        with _safe_source_handle(path, size) as handle:
            payload = handle.read(MAX_MEMBER_BYTES + 1)
        if len(payload) != size or len(payload) > MAX_MEMBER_BYTES:
            raise BackendError(
                "backup_source_changed",
                "backup source changed while validating content",
            )
        _validate_content_bytes(payload, relative)
    except BackendError:
        raise
    except OSError as error:
        raise BackendError(
            "backup_io_error", "could not validate backup source"
        ) from error


@contextmanager
def _locked_backup_source(root: Path):
    """Hold production storage locks and recover journals during backup."""
    from .customer_store import CustomerAuditStore

    store = CustomerAuditStore(str(root))
    identifiers = _assessment_names(root)
    with ExitStack() as stack:
        for assessment_id in identifiers:
            base = root / "assessments" / assessment_id
            stack.enter_context(store._exclusive_file_lock(base / ".lock"))
            recover_private_transactions(
                base, cleanup_unprepared=True
            )
        stack.enter_context(store._measurement_profiles_lock())
        if _assessment_names(root) != identifiers:
            raise BackendError(
                "backup_source_changed",
                "assessment set changed while backup locks were acquired",
            )
        _assert_no_active_transactions(root)
        yield
        _assert_no_active_transactions(root)
        if _assessment_names(root) != identifiers:
            raise BackendError(
                "backup_source_changed",
                "assessment set changed during backup",
            )


def _source_entries(
    root: Path,
) -> Tuple[List[str], List[Dict[str, Any]], int]:
    directories = set(ALLOWED_DIRECTORIES)
    files = []
    total_bytes = 0
    visited_directories = 0

    for name in ALLOWED_DIRECTORIES:
        directory = root / name
        if not directory.exists():
            continue
        if directory.is_symlink() or not directory.is_dir():
            raise BackendError(
                "backup_unsafe_source",
                "{0} must be a real directory".format(name),
            )
        for current_root, directory_names, file_names in os.walk(
            str(directory), topdown=True, followlinks=False
        ):
            visited_directories += 1
            if visited_directories > MAX_MEMBERS:
                raise BackendError(
                    "backup_limit",
                    "backup source directory limit was exceeded",
                )
            current = Path(current_root)
            relative_directory = current.relative_to(root).as_posix()
            _validate_relative_path(relative_directory, directory=True)
            directories.add(relative_directory)

            retained_directories = []
            for directory_name in sorted(directory_names):
                if directory_name in EXCLUDED_NAMES:
                    continue
                child = current / directory_name
                if child.is_symlink():
                    raise BackendError(
                        "backup_unsafe_source",
                        "backup source directories must not be symlinks",
                    )
                retained_directories.append(directory_name)
            directory_names[:] = retained_directories

            for file_name in sorted(file_names):
                if file_name in EXCLUDED_NAMES:
                    continue
                path = current / file_name
                if path.is_symlink():
                    raise BackendError(
                        "backup_unsafe_source",
                        "backup source files must not be symlinks",
                    )
                try:
                    file_stat = path.stat()
                except OSError:
                    raise BackendError(
                        "backup_io_error",
                        "could not inspect backup source",
                    )
                if not stat.S_ISREG(file_stat.st_mode):
                    raise BackendError(
                        "backup_unsafe_source",
                        "backup source contains a non-regular file",
                    )
                relative = _validate_relative_path(
                    path.relative_to(root).as_posix()
                )
                _validate_source_path_contract(relative)
                sha256, size = _sha256_path(path)
                if size != file_stat.st_size:
                    raise BackendError(
                        "backup_source_changed",
                        "backup source changed while it was being read",
                    )
                total_bytes += size
                if total_bytes > MAX_TOTAL_BYTES:
                    raise BackendError(
                        "backup_limit", "backup exceeds the safe total size limit"
                    )
                files.append(
                    {
                        "path": relative,
                        "size": size,
                        "sha256": sha256,
                    }
                )
                _validate_source_content(path, relative, size)
                if len(files) > MAX_FILES:
                    raise BackendError(
                        "backup_limit",
                        "backup contains too many files",
                    )

    for name in ALLOWED_FILES:
        path = root / name
        if not path.exists():
            continue
        if path.is_symlink() or not path.is_file():
            raise BackendError(
                "backup_unsafe_source",
                "{0} must be a regular file".format(name),
            )
        sha256, size = _sha256_path(path)
        _validate_source_path_contract(name)
        _validate_source_content(path, name, size)
        total_bytes += size
        if total_bytes > MAX_TOTAL_BYTES:
            raise BackendError(
                "backup_limit", "backup exceeds the safe total size limit"
            )
        files.append({"path": name, "size": size, "sha256": sha256})

    if not any(item["path"] == "pseudonymization.key" for item in files):
        raise BackendError(
            "backup_identity_missing",
            "pseudonymization.key is required for a continuity backup",
        )
    if len(files) > MAX_FILES:
        raise BackendError("backup_limit", "backup contains too many files")
    return sorted(directories), sorted(files, key=lambda item: item["path"]), total_bytes


def _manifest(
    directories: List[str], files: List[Dict[str, Any]], total_bytes: int
) -> Dict[str, Any]:
    payload = {
        "directories": directories,
        "files": files,
        "total_bytes": total_bytes,
    }
    return {
        "schema_version": BACKUP_SCHEMA_VERSION,
        "backup_type": BACKUP_TYPE,
        "created_at": _utc_now(),
        "included_roots": list(ALLOWED_DIRECTORIES + ALLOWED_FILES),
        "excluded": sorted(EXCLUDED_NAMES),
        "directories": directories,
        "files": files,
        "file_count": len(files),
        "total_bytes": total_bytes,
        "payload_sha256": hashlib.sha256(_canonical_bytes(payload)).hexdigest(),
    }


def _tar_info(name: str, size: int = 0, directory: bool = False) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name=name)
    info.size = size
    info.mode = 0o700 if directory else 0o600
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mtime = 0
    info.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
    return info


def _safe_source_handle(path: Path, expected_size: int) -> BinaryIO:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(str(path), flags)
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_size != expected_size:
            os.close(descriptor)
            raise BackendError(
                "backup_source_changed",
                "backup source changed before archiving",
            )
        return os.fdopen(descriptor, "rb")
    except BackendError:
        raise
    except OSError:
        raise BackendError(
            "backup_io_error",
            "could not open backup source file",
        )


def create_backup(
    config_dir: Optional[str], output: str
) -> Dict[str, Any]:
    """Create and verify a private device-continuity tar.gz archive."""
    root = resolve_config_dir(config_dir)
    if not (root / "pseudonymization.key").exists():
        raise BackendError(
            "backup_identity_missing",
            "pseudonymization.key is required for a continuity backup",
        )
    temporary = None
    try:
        with _locked_backup_source(root):
            temporary, result = _prepare_backup_unlocked(root, output)
        _publish_prepared_backup(temporary, Path(output))
        return result
    finally:
        if temporary is not None and temporary.exists():
            try:
                temporary.unlink()
            except OSError:
                pass


def _prepare_backup_unlocked(
    root: Path, output: str
) -> Tuple[Path, Dict[str, Any]]:
    output_path = Path(output)
    if output_path.exists() or output_path.is_symlink():
        raise BackendError(
            "backup_output_exists", "backup output path already exists"
        )
    parent = output_path.parent
    if not parent.exists() or not parent.is_dir():
        raise BackendError(
            "backup_output_invalid", "backup output directory does not exist"
        )
    try:
        root_resolved = root.resolve()
        output_resolved = output_path.resolve()
        output_resolved.relative_to(root_resolved)
    except ValueError:
        pass
    except OSError as failure:
        raise BackendError(
            "backup_output_invalid", "backup output path cannot be resolved"
        ) from failure
    else:
        raise BackendError(
            "backup_output_invalid",
            "backup output must be outside the active PineAI directory",
        )

    directories, files, total_bytes = _source_entries(root)
    manifest = _manifest(directories, files, total_bytes)
    manifest_bytes = (
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True).encode(
            "utf-8"
        )
        + b"\n"
    )
    if len(manifest_bytes) > MAX_MANIFEST_BYTES:
        raise BackendError("backup_limit", "backup manifest is too large")

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".{0}.".format(output_path.name), dir=str(parent)
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        os.chmod(str(temporary), 0o600)
        try:
            with tarfile.open(str(temporary), mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
                archive.addfile(
                    _tar_info(MANIFEST_NAME, len(manifest_bytes)),
                    io.BytesIO(manifest_bytes),
                )
                for directory in directories:
                    archive.addfile(
                        _tar_info(
                            "{0}/{1}".format(DATA_PREFIX, directory),
                            directory=True,
                        )
                    )
                for item in files:
                    source = root / Path(item["path"])
                    with _safe_source_handle(source, item["size"]) as handle:
                        archive.addfile(
                            _tar_info(
                                "{0}/{1}".format(DATA_PREFIX, item["path"]),
                                item["size"],
                            ),
                            handle,
                        )
        except (OSError, tarfile.TarError):
            raise BackendError(
                "backup_io_error",
                "could not create backup archive",
            )

        verification = verify_backup(str(temporary))
        result = {
            "schema_version": BACKUP_SCHEMA_VERSION,
            "backup_type": BACKUP_TYPE,
            "output": str(output_path),
            "archive_sha256": verification["archive_sha256"],
            "file_count": verification["file_count"],
            "total_bytes": verification["total_bytes"],
            "payload_sha256": verification["payload_sha256"],
            "excluded": sorted(EXCLUDED_NAMES),
        }
        return temporary, result
    except Exception:
        if temporary.exists():
            try:
                temporary.unlink()
            except OSError:
                pass
        raise


def _publish_prepared_backup(temporary: Path, output_path: Path) -> None:
    try:
        # A same-directory hard link publishes the completed inode without
        # overwriting a path created by another process.
        os.link(str(temporary), str(output_path))
    except FileExistsError:
        raise BackendError(
            "backup_output_exists", "backup output path already exists"
        )
    except OSError:
        raise BackendError(
            "backup_io_error",
            "could not publish backup archive",
        )
    try:
        os.chmod(str(output_path), 0o600)
    except OSError:
        pass


def _member_relative(name: str, directory: bool = False) -> str:
    if (
        not isinstance(name, str)
        or not name.startswith(DATA_PREFIX + "/")
        or PurePosixPath(name).as_posix() != name
    ):
        raise BackendError("backup_unsafe_path", "archive member path is invalid")
    relative = name[len(DATA_PREFIX) + 1 :]
    return _validate_relative_path(relative, directory=directory)


def _read_manifest(archive: tarfile.TarFile, member: tarfile.TarInfo) -> Dict[str, Any]:
    if not member.isfile() or member.size > MAX_MANIFEST_BYTES:
        raise BackendError("backup_invalid", "backup manifest is invalid")
    handle = archive.extractfile(member)
    if handle is None:
        raise BackendError("backup_invalid", "backup manifest is unreadable")
    try:
        raw = handle.read(MAX_MANIFEST_BYTES + 1)
    except OSError:
        raise BackendError(
            "backup_io_error", "could not read backup manifest"
        )
    if len(raw) > MAX_MANIFEST_BYTES:
        raise BackendError("backup_limit", "backup manifest is too large")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError):
        raise BackendError("backup_invalid", "backup manifest is not valid JSON")
    expected_fields = {
        "schema_version",
        "backup_type",
        "created_at",
        "included_roots",
        "excluded",
        "directories",
        "files",
        "file_count",
        "total_bytes",
        "payload_sha256",
    }
    if not isinstance(value, dict) or set(value) != expected_fields:
        raise BackendError("backup_invalid", "backup manifest shape is invalid")
    if (
        value["schema_version"] != BACKUP_SCHEMA_VERSION
        or value["backup_type"] != BACKUP_TYPE
    ):
        raise BackendError(
            "backup_version_unsupported", "backup format is not supported"
        )
    return value


def _validate_manifest(value: Dict[str, Any]) -> Tuple[List[str], List[Dict[str, Any]]]:
    directories = value.get("directories")
    files = value.get("files")
    if (
        not isinstance(directories, list)
        or not isinstance(files, list)
        or len(files) > MAX_FILES
    ):
        raise BackendError("backup_invalid", "backup manifest entries are invalid")
    if value.get("included_roots") != list(ALLOWED_DIRECTORIES + ALLOWED_FILES):
        raise BackendError("backup_invalid", "backup root allowlist is invalid")
    if value.get("excluded") != sorted(EXCLUDED_NAMES):
        raise BackendError("backup_invalid", "backup exclusion policy is invalid")
    created_at = value.get("created_at")
    if not isinstance(created_at, str) or not RFC3339_PATTERN.match(created_at):
        raise BackendError("backup_invalid", "backup created_at is invalid")
    try:
        datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError as failure:
        raise BackendError(
            "backup_invalid", "backup created_at is invalid"
        ) from failure

    normalized_directories = []
    seen_directories = set()
    for item in directories:
        relative = _validate_relative_path(item, directory=True)
        if relative in seen_directories:
            raise BackendError("backup_invalid", "backup has duplicate directories")
        seen_directories.add(relative)
        normalized_directories.append(relative)
    if not set(ALLOWED_DIRECTORIES).issubset(seen_directories):
        raise BackendError(
            "backup_invalid", "required backup directories are missing"
        )

    normalized_files = []
    seen_files = set()
    total_bytes = 0
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "size", "sha256"}:
            raise BackendError("backup_invalid", "backup file entry is invalid")
        relative = _validate_relative_path(item["path"])
        _validate_source_path_contract(relative)
        size = item["size"]
        digest = item["sha256"]
        if (
            relative in seen_files
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or size > MAX_MEMBER_BYTES
            or not isinstance(digest, str)
            or not re_full_sha256(digest)
        ):
            raise BackendError("backup_invalid", "backup file entry is invalid")
        seen_files.add(relative)
        total_bytes += size
        if total_bytes > MAX_TOTAL_BYTES:
            raise BackendError("backup_limit", "backup is too large")
        normalized_files.append(
            {"path": relative, "size": size, "sha256": digest}
        )

    if "pseudonymization.key" not in seen_files:
        raise BackendError(
            "backup_identity_missing",
            "backup does not contain pseudonymization.key",
        )
    if value.get("file_count") != len(normalized_files):
        raise BackendError("backup_invalid", "backup file count is inconsistent")
    if value.get("total_bytes") != total_bytes:
        raise BackendError("backup_invalid", "backup byte count is inconsistent")
    payload = {
        "directories": normalized_directories,
        "files": normalized_files,
        "total_bytes": total_bytes,
    }
    expected_payload = hashlib.sha256(_canonical_bytes(payload)).hexdigest()
    if value.get("payload_sha256") != expected_payload:
        raise BackendError("backup_hash_mismatch", "backup manifest hash is invalid")
    return normalized_directories, normalized_files


def re_full_sha256(value: str) -> bool:
    return (
        len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


@contextmanager
def _open_archive(path: Path):
    with _open_archive_source(path) as source:
        initial_digest, initial_size = _archive_stream_sha256(source)
        source.seek(0)
        try:
            archive = tarfile.open(
                fileobj=source,
                mode="r:gz",
                tarinfo=_BoundedBackupTarInfo,
            )
        except (OSError, tarfile.TarError) as failure:
            raise BackendError(
                "backup_invalid", "could not open backup archive"
            ) from failure
        try:
            archive._pineai_archive_sha256 = initial_digest
            archive._pineai_archive_size = initial_size
            yield archive
        finally:
            archive.close()
        source.seek(0)
        final_digest, final_size = _archive_stream_sha256(source)
        if final_size != initial_size or final_digest != initial_digest:
            raise BackendError(
                "backup_source_changed",
                "backup archive changed while it was being processed",
            )


def _bounded_members(archive: tarfile.TarFile) -> List[tarfile.TarInfo]:
    members = []
    declared_data_bytes = 0
    seen_names = set()
    manifest_count = 0
    try:
        while True:
            member = archive.next()
            if member is None:
                break
            size = member.size
            if not isinstance(size, int) or isinstance(size, bool) or size < 0:
                raise BackendError(
                    "backup_invalid", "backup member size is invalid"
                )
            if member.name in seen_names:
                raise BackendError(
                    "backup_invalid", "backup has duplicate members"
                )
            seen_names.add(member.name)
            pax_headers = member.pax_headers
            if (
                not isinstance(pax_headers, dict)
                or any(key != "path" for key in pax_headers)
                or (
                    "path" in pax_headers
                    and pax_headers["path"]
                    not in (
                        member.name,
                        member.name + "/" if member.isdir() else member.name,
                    )
                )
            ):
                raise BackendError(
                    "backup_unsafe_member",
                    "backup contains unsupported extended metadata",
                )
            if member.isdir():
                if size != 0:
                    raise BackendError(
                        "backup_invalid", "backup directory size is invalid"
                    )
                _member_relative(member.name, directory=True)
                if member.mode != 0o700:
                    raise BackendError(
                        "backup_permissions_invalid",
                        "backup directory permissions are invalid",
                    )
            elif member.isfile():
                member_limit = (
                    MAX_MANIFEST_BYTES
                    if member.name == MANIFEST_NAME
                    else MAX_MEMBER_BYTES
                )
                if size > member_limit:
                    raise BackendError(
                        "backup_limit",
                        "a backup member exceeds the safe size limit",
                    )
                if member.name == MANIFEST_NAME:
                    manifest_count += 1
                    if manifest_count > 1:
                        raise BackendError(
                            "backup_invalid",
                            "backup must contain exactly one manifest",
                        )
                    if member.mode != 0o600:
                        raise BackendError(
                            "backup_permissions_invalid",
                            "backup manifest permissions are invalid",
                        )
                else:
                    _member_relative(member.name)
                    if member.mode != 0o600:
                        raise BackendError(
                            "backup_permissions_invalid",
                            "backup file permissions are invalid",
                        )
                    declared_data_bytes += size
                    if declared_data_bytes > MAX_TOTAL_BYTES:
                        raise BackendError(
                            "backup_limit",
                            "backup payload exceeds the safe size limit",
                        )
            else:
                # Reject before archive.next() can advance through a payload
                # attached to an unsupported member type.
                raise BackendError(
                    "backup_unsafe_member",
                    "backup contains a link or special file",
                )
            members.append(member)
            if len(members) > MAX_MEMBERS:
                raise BackendError(
                    "backup_limit", "backup member count is invalid"
                )
    except BackendError:
        raise
    except (OSError, tarfile.TarError):
        raise BackendError(
            "backup_invalid",
            "could not read backup archive",
        )
    if not members:
        raise BackendError("backup_limit", "backup member count is invalid")
    return members


def verify_backup(input_path: str) -> Dict[str, Any]:
    """Verify archive structure, allowlisted paths, sizes, and every file hash."""
    path = Path(input_path)
    with _open_archive(path) as archive:
        archive_sha256 = archive._pineai_archive_sha256
        members = _bounded_members(archive)

        seen_names = set()
        manifest_members = []
        data_files = {}
        data_directories = set()
        for member in members:
            if member.name in seen_names:
                raise BackendError("backup_invalid", "backup has duplicate members")
            seen_names.add(member.name)
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                raise BackendError(
                    "backup_unsafe_member",
                    "backup contains a link or special file",
                )
            if member.name == MANIFEST_NAME:
                manifest_members.append(member)
                continue
            if member.isdir():
                relative = _member_relative(member.name, directory=True)
                if member.mode != 0o700:
                    raise BackendError(
                        "backup_permissions_invalid",
                        "backup directory permissions are invalid",
                    )
                data_directories.add(relative)
            elif member.isfile():
                relative = _member_relative(member.name)
                if member.mode != 0o600 or member.size > MAX_MEMBER_BYTES:
                    raise BackendError(
                        "backup_permissions_invalid",
                        "backup file permissions or size are invalid",
                    )
                data_files[relative] = member
            else:
                raise BackendError(
                    "backup_unsafe_member",
                    "backup contains an unsupported member type",
                )
        if len(manifest_members) != 1:
            raise BackendError(
                "backup_invalid", "backup must contain exactly one manifest"
            )

        manifest = _read_manifest(archive, manifest_members[0])
        directories, files = _validate_manifest(manifest)
        if set(directories) != data_directories:
            raise BackendError(
                "backup_invalid", "backup directory members do not match manifest"
            )
        expected_files = {item["path"]: item for item in files}
        if set(expected_files) != set(data_files):
            raise BackendError(
                "backup_invalid", "backup file members do not match manifest"
            )

        for relative in sorted(expected_files):
            expected = expected_files[relative]
            member = data_files[relative]
            if member.size != expected["size"]:
                raise BackendError(
                    "backup_hash_mismatch", "backup file size does not match manifest"
                )
            handle = archive.extractfile(member)
            if handle is None:
                raise BackendError("backup_invalid", "backup file is unreadable")
            try:
                payload = handle.read(MAX_MEMBER_BYTES + 1)
            except OSError as error:
                raise BackendError(
                    "backup_io_error", "could not read backup file"
                ) from error
            size = len(payload)
            digest = hashlib.sha256(payload).hexdigest()
            if (
                size > MAX_MEMBER_BYTES
                or size != expected["size"]
                or digest != expected["sha256"]
            ):
                raise BackendError(
                    "backup_hash_mismatch", "backup file hash does not match manifest"
                )
            _validate_content_bytes(payload, relative)

    return {
        "schema_version": BACKUP_SCHEMA_VERSION,
        "backup_type": BACKUP_TYPE,
        "verified": True,
        "input": str(path),
        "archive_sha256": archive_sha256,
        "payload_sha256": manifest["payload_sha256"],
        "file_count": manifest["file_count"],
        "total_bytes": manifest["total_bytes"],
        "manifest": manifest,
    }


def _target_is_empty(target: Path) -> bool:
    try:
        return target.is_dir() and not any(target.iterdir())
    except OSError:
        raise BackendError(
            "backup_restore_target_invalid",
            "could not inspect restore target",
        )


def _write_member(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    destination: Path,
    expected: Dict[str, Any],
) -> None:
    handle = archive.extractfile(member)
    if handle is None:
        raise BackendError("backup_invalid", "backup file is unreadable")
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(str(destination.parent), 0o700)
    except OSError:
        pass
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
    )
    descriptor = None
    digest = hashlib.sha256()
    size = 0
    try:
        descriptor = os.open(str(destination), flags, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            descriptor = None
            while True:
                chunk = handle.read(COPY_CHUNK_BYTES)
                if not chunk:
                    break
                size += len(chunk)
                if size > expected["size"] or size > MAX_MEMBER_BYTES:
                    raise BackendError(
                        "backup_hash_mismatch",
                        "backup file exceeded its declared size",
                    )
                output.write(chunk)
                digest.update(chunk)
            output.flush()
            os.fsync(output.fileno())
        try:
            os.chmod(str(destination), 0o600)
        except OSError:
            pass
    except BackendError:
        raise
    except OSError:
        raise BackendError(
            "backup_io_error",
            "could not restore backup file",
        )
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if size != expected["size"] or digest.hexdigest() != expected["sha256"]:
        raise BackendError(
            "backup_hash_mismatch", "restored backup file hash is invalid"
        )


def restore_backup_staging(input_path: str, target: str) -> Dict[str, Any]:
    """Restore a verified backup into a new or empty staging directory."""
    verification = verify_backup(input_path)
    manifest = verification["manifest"]
    target_path = Path(target)
    if not target_path.name or target_path.name in (".", ".."):
        raise BackendError(
            "backup_restore_target_invalid",
            "restore target must be a dedicated staging directory",
        )
    if target_path.is_symlink():
        raise BackendError(
            "backup_restore_target_invalid", "restore target must not be a symlink"
        )
    try:
        active_root = resolve_config_dir().resolve()
        requested_target = target_path.resolve()
    except OSError:
        raise BackendError(
            "backup_restore_target_invalid",
            "could not resolve restore target",
        )
    overlaps_active = requested_target == active_root
    try:
        requested_target.relative_to(active_root)
        overlaps_active = True
    except ValueError:
        pass
    try:
        active_root.relative_to(requested_target)
        overlaps_active = True
    except ValueError:
        pass
    if overlaps_active:
        raise BackendError(
            "backup_restore_target_invalid",
            "restore-staging must not overlap the active PineAI directory",
        )
    target_exists = target_path.exists()
    if target_exists and not _target_is_empty(target_path):
        raise BackendError(
            "backup_restore_target_not_empty", "restore target must be empty"
        )
    parent = target_path.parent
    if not parent.exists() or not parent.is_dir():
        raise BackendError(
            "backup_restore_target_invalid",
            "restore target parent directory does not exist",
        )

    staging = Path(
        tempfile.mkdtemp(
            prefix=".{0}.restore.".format(target_path.name or "pineai"),
            dir=str(parent),
        )
    )
    try:
        os.chmod(str(staging), 0o700)
        for relative in manifest["directories"]:
            directory = staging / Path(relative)
            directory.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(str(directory), 0o700)
            except OSError:
                pass

        with _open_archive(Path(input_path)) as archive:
            if (
                archive._pineai_archive_sha256
                != verification["archive_sha256"]
            ):
                raise BackendError(
                    "backup_source_changed",
                    "backup archive changed before restore",
                )
            members = {
                _member_relative(member.name): member
                for member in _bounded_members(archive)
                if member.isfile() and member.name != MANIFEST_NAME
            }
            for expected in manifest["files"]:
                relative = expected["path"]
                destination = staging / Path(relative)
                _write_member(
                    archive, members[relative], destination, expected
                )

        removed_empty_target = False
        if target_exists:
            if not _target_is_empty(target_path):
                raise BackendError(
                    "backup_restore_target_not_empty",
                    "restore target changed during restore",
                )
            try:
                target_path.rmdir()
                removed_empty_target = True
            except OSError:
                raise BackendError(
                    "backup_restore_target_invalid",
                    "could not prepare restore target",
                )
        try:
            os.replace(str(staging), str(target_path))
        except OSError:
            if removed_empty_target and not target_path.exists():
                try:
                    target_path.mkdir(mode=0o700)
                except OSError:
                    pass
            raise BackendError(
                "backup_io_error",
                "could not publish restore staging directory",
            )
        try:
            os.chmod(str(target_path), 0o700)
        except OSError:
            pass
        return {
            "schema_version": BACKUP_SCHEMA_VERSION,
            "backup_type": BACKUP_TYPE,
            "restored": True,
            "target": str(target_path),
            "archive_sha256": verification["archive_sha256"],
            "payload_sha256": verification["payload_sha256"],
            "file_count": verification["file_count"],
            "total_bytes": verification["total_bytes"],
        }
    finally:
        if staging.exists():
            shutil.rmtree(str(staging), ignore_errors=True)
