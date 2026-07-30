"""Portable, secret-minimized PineAI device continuity backups.

Backups contain deterministic assessment state (including nested assurance
profiles), top-level measurement profiles, the non-secret configuration, and
the pseudonymization identity required to keep stable IDs continuous.  The
optional OpenAI key and transient storage locks/transactions are never
included.

The restore operation always targets a new or empty staging directory.  It
never extracts over a live PineAI configuration directory.
"""

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

from .config import resolve_config_dir
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
EXCLUDED_NAMES = SECRET_EXCLUDED_NAMES | TRANSIENT_EXCLUDED_NAMES
MAX_MEMBERS = 10000
MAX_FILES = 9000
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
COPY_CHUNK_BYTES = 64 * 1024
MAX_ASSESSMENTS_FOR_BACKUP = 1000
RFC3339_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$"
)


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
        with path.open("rb") as handle:
            return _sha256_stream(handle)
    except OSError as failure:
        raise BackendError(
            "backup_io_error",
            "could not read backup source file: {0}".format(failure),
        )


def _archive_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(COPY_CHUNK_BYTES)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError as failure:
        raise BackendError(
            "backup_io_error", "could not read backup archive: {0}".format(failure)
        )
    return digest.hexdigest()


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
                    or entry.name in ("", ".", "..")
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
    for allowed in ALLOWED_DIRECTORIES:
        directory = root / allowed
        if not directory.exists():
            continue
        for current_root, directory_names, _ in os.walk(
            str(directory), topdown=True, followlinks=False
        ):
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
                except OSError as failure:
                    raise BackendError(
                        "backup_io_error",
                        "could not inspect backup source: {0}".format(failure),
                    )
                if not stat.S_ISREG(file_stat.st_mode):
                    raise BackendError(
                        "backup_unsafe_source",
                        "backup source contains a non-regular file",
                    )
                relative = _validate_relative_path(
                    path.relative_to(root).as_posix()
                )
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
    flags = os.O_RDONLY
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
    except OSError as failure:
        raise BackendError(
            "backup_io_error",
            "could not open backup source file: {0}".format(failure),
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
    with _locked_backup_source(root):
        return _create_backup_unlocked(root, output)


def _create_backup_unlocked(root: Path, output: str) -> Dict[str, Any]:
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
        except (OSError, tarfile.TarError) as failure:
            raise BackendError(
                "backup_io_error",
                "could not create backup archive: {0}".format(failure),
            )

        verification = verify_backup(str(temporary))
        try:
            # A same-directory hard link publishes the completed inode without
            # ever overwriting a path created by another process.
            os.link(str(temporary), str(output_path))
        except FileExistsError:
            raise BackendError(
                "backup_output_exists", "backup output path already exists"
            )
        except OSError as failure:
            raise BackendError(
                "backup_io_error",
                "could not publish backup archive: {0}".format(failure),
            )
        try:
            os.chmod(str(output_path), 0o600)
        except OSError:
            pass
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
        return result
    finally:
        if temporary.exists():
            try:
                temporary.unlink()
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
    except OSError as failure:
        raise BackendError(
            "backup_io_error", "could not read backup manifest: {0}".format(failure)
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


def _open_archive(path: Path) -> tarfile.TarFile:
    if path.is_symlink() or not path.is_file():
        raise BackendError("backup_invalid", "backup input must be a regular file")
    try:
        return tarfile.open(str(path), mode="r:gz")
    except (OSError, tarfile.TarError) as failure:
        raise BackendError(
            "backup_invalid", "could not open backup archive: {0}".format(failure)
        )


def _bounded_members(archive: tarfile.TarFile) -> List[tarfile.TarInfo]:
    members = []
    try:
        while True:
            member = archive.next()
            if member is None:
                break
            members.append(member)
            if len(members) > MAX_MEMBERS:
                raise BackendError(
                    "backup_limit", "backup member count is invalid"
                )
    except BackendError:
        raise
    except (OSError, tarfile.TarError) as failure:
        raise BackendError(
            "backup_invalid",
            "could not read backup archive: {0}".format(failure),
        )
    if not members:
        raise BackendError("backup_limit", "backup member count is invalid")
    return members


def verify_backup(input_path: str) -> Dict[str, Any]:
    """Verify archive structure, allowlisted paths, sizes, and every file hash."""
    path = Path(input_path)
    with _open_archive(path) as archive:
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
            digest, size = _sha256_stream(handle)
            if size != expected["size"] or digest != expected["sha256"]:
                raise BackendError(
                    "backup_hash_mismatch", "backup file hash does not match manifest"
                )

    return {
        "schema_version": BACKUP_SCHEMA_VERSION,
        "backup_type": BACKUP_TYPE,
        "verified": True,
        "input": str(path),
        "archive_sha256": _archive_sha256(path),
        "payload_sha256": manifest["payload_sha256"],
        "file_count": manifest["file_count"],
        "total_bytes": manifest["total_bytes"],
        "manifest": manifest,
    }


def _target_is_empty(target: Path) -> bool:
    try:
        return target.is_dir() and not any(target.iterdir())
    except OSError as failure:
        raise BackendError(
            "backup_restore_target_invalid",
            "could not inspect restore target: {0}".format(failure),
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
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
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
    except OSError as failure:
        raise BackendError(
            "backup_io_error",
            "could not restore backup file: {0}".format(failure),
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
    except OSError as failure:
        raise BackendError(
            "backup_restore_target_invalid",
            "could not resolve restore target: {0}".format(failure),
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
            except OSError as failure:
                raise BackendError(
                    "backup_restore_target_invalid",
                    "could not prepare restore target: {0}".format(failure),
                )
        if _archive_sha256(Path(input_path)) != verification["archive_sha256"]:
            if removed_empty_target:
                target_path.mkdir(mode=0o700)
            raise BackendError(
                "backup_source_changed",
                "backup archive changed during restore",
            )
        try:
            os.replace(str(staging), str(target_path))
        except OSError as failure:
            if removed_empty_target and not target_path.exists():
                try:
                    target_path.mkdir(mode=0o700)
                except OSError:
                    pass
            raise BackendError(
                "backup_io_error",
                "could not publish restore staging directory: {0}".format(
                    failure
                ),
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
