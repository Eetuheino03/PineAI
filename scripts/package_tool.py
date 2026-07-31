#!/usr/bin/env python3
"""Deterministic, fail-closed PineAI package staging and verification."""

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import zlib
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Optional, Tuple


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = REPOSITORY_ROOT / "scripts" / "package-manifest.json"
MODULE_ROOT = "PineAI"
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_TAR_BYTES = 64 * 1024 * 1024
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_TOTAL_FILE_BYTES = 32 * 1024 * 1024
MAX_MEMBERS = 64
COPY_CHUNK_BYTES = 64 * 1024
SEMVER_PATTERN = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)
OPENAI_KEY_PATTERN = re.compile(
    rb"sk-(?:proj-)?[A-Za-z0-9_-]{20,}"
)
PRIVATE_KEY_LABELS = (
    b"",
    b"OPENSSH",
    b"RSA",
    b"EC",
    b"DSA",
    b"ENCRYPTED",
)
SOURCE_MAP_TRAILER = b"//# sourceMappingURL=PineAI.umd.js.map"


class PackageError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _canonical_relative_path(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or "\x00" in value
        or any(ord(character) < 32 for character in value)
    ):
        raise PackageError("manifest_invalid", "{0} is invalid".format(label))
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in ("", ".", "..") for part in value.split("/"))
    ):
        raise PackageError("manifest_invalid", "{0} is unsafe".format(label))
    return value


def _read_json_file(path: Path, code: str) -> Dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as failure:
        raise PackageError(code, "required JSON file is unreadable") from failure
    if len(raw) > 1024 * 1024:
        raise PackageError(code, "required JSON file is too large")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as failure:
        raise PackageError(code, "required JSON file is invalid") from failure
    if not isinstance(value, dict):
        raise PackageError(code, "required JSON value must be an object")
    return value


def _source_path(relative: str) -> Path:
    candidate = REPOSITORY_ROOT / Path(relative)
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(REPOSITORY_ROOT.resolve())
    except (OSError, ValueError) as failure:
        raise PackageError(
            "manifest_invalid", "manifest source is outside the repository"
        ) from failure
    try:
        metadata = candidate.lstat()
    except OSError as failure:
        raise PackageError(
            "manifest_invalid", "manifest source is unavailable"
        ) from failure
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise PackageError(
            "manifest_invalid", "manifest source is not a regular file"
        )
    return resolved


def load_manifest() -> Dict[str, Any]:
    manifest = _read_json_file(MANIFEST_PATH, "manifest_invalid")
    if set(manifest) != {"schema_version", "module_root", "files"}:
        raise PackageError("manifest_invalid", "package manifest fields are invalid")
    if (
        manifest.get("schema_version") != "1.0"
        or manifest.get("module_root") != MODULE_ROOT
        or not isinstance(manifest.get("files"), list)
    ):
        raise PackageError("manifest_invalid", "package manifest header is invalid")

    normalized = []
    seen_paths = set()
    for item in manifest["files"]:
        if not isinstance(item, dict):
            raise PackageError("manifest_invalid", "manifest file entry is invalid")
        generated = item.get("generated", False)
        expected_fields = {"path", "source", "mode"}
        if generated:
            expected_fields.add("generated")
        if set(item) != expected_fields or not isinstance(generated, bool):
            raise PackageError("manifest_invalid", "manifest file fields are invalid")
        relative = _canonical_relative_path(item.get("path"), "package path")
        if relative in seen_paths:
            raise PackageError("manifest_invalid", "manifest path is duplicated")
        seen_paths.add(relative)
        mode = item.get("mode")
        if mode not in {"0644", "0755"}:
            raise PackageError("manifest_invalid", "manifest mode is invalid")
        source = item.get("source")
        if generated:
            if source is not None or relative != "PineAI.umd.js":
                raise PackageError(
                    "manifest_invalid", "generated manifest entry is invalid"
                )
        else:
            source = _canonical_relative_path(source, "source path")
            _source_path(source)
        normalized.append(
            {
                "path": relative,
                "source": source,
                "generated": generated,
                "mode": int(mode, 8),
            }
        )

    backend_directory = (
        REPOSITORY_ROOT
        / "projects"
        / "PineAI"
        / "src"
        / "assets"
        / "pineai_backend"
    )
    actual_backend = {
        "assets/pineai_backend/{0}".format(path.name)
        for path in backend_directory.glob("*.py")
        if path.is_file() and not path.is_symlink()
    }
    manifest_backend = {
        item["path"]
        for item in normalized
        if item["path"].startswith("assets/pineai_backend/")
    }
    if actual_backend != manifest_backend:
        raise PackageError(
            "manifest_invalid",
            "runtime backend manifest does not match source modules",
        )
    if len(normalized) != 24:
        raise PackageError(
            "manifest_invalid", "runtime manifest file count is invalid"
        )
    return {
        "schema_version": "1.0",
        "module_root": MODULE_ROOT,
        "files": normalized,
    }


def _expected_directories(manifest: Dict[str, Any]) -> List[str]:
    directories = {MODULE_ROOT}
    for item in manifest["files"]:
        parent = PurePosixPath(MODULE_ROOT, item["path"]).parent
        while parent.as_posix() != ".":
            directories.add(parent.as_posix())
            if parent.as_posix() == MODULE_ROOT:
                break
            parent = parent.parent
    return sorted(
        directories,
        key=lambda value: (len(PurePosixPath(value).parts), value),
    )


def _read_bounded_regular(path: Path, maximum: int) -> bytes:
    try:
        before = path.lstat()
    except OSError as failure:
        raise PackageError("file_unreadable", "required file is unreadable") from failure
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_size > maximum
    ):
        raise PackageError("file_unsafe", "required file is not a bounded regular file")
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
            raise PackageError("file_changed", "required file changed while opening")
        chunks = []
        size = 0
        while True:
            chunk = os.read(descriptor, COPY_CHUNK_BYTES)
            if not chunk:
                break
            size += len(chunk)
            if size > maximum:
                raise PackageError("file_too_large", "required file exceeds limit")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if after.st_size != opened.st_size:
            raise PackageError("file_changed", "required file changed while reading")
        return b"".join(chunks)
    except PackageError:
        raise
    except OSError as failure:
        raise PackageError("file_unreadable", "required file is unreadable") from failure
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _validate_runtime_bytes(path: str, payload: bytes) -> None:
    lowered = path.lower()
    if (
        "__pycache__" in path.split("/")
        or lowered.endswith((".pyc", ".pyo", ".map"))
        or "sourcemappingurl=" in payload.decode("utf-8", errors="ignore").lower()
    ):
        raise PackageError(
            "forbidden_artifact", "package contains a forbidden build artifact"
        )
    private_key_markers = tuple(
        b"-----BEGIN "
        + (label + b" " if label else b"")
        + b"PRIVATE KEY-----"
        for label in PRIVATE_KEY_LABELS
    )
    if OPENAI_KEY_PATTERN.search(payload) or any(
        marker in payload for marker in private_key_markers
    ):
        raise PackageError("secret_detected", "package contains a likely secret")


def _sanitize_generated_bundle(payload: bytes) -> bytes:
    normalized = payload.replace(b"\r\n", b"\n")
    lines = normalized.splitlines(keepends=True)
    source_map_lines = [
        index
        for index, line in enumerate(lines)
        if b"sourcemappingurl=" in line.lower()
    ]
    if not source_map_lines:
        return normalized
    if source_map_lines != [len(lines) - 1]:
        raise PackageError(
            "forbidden_artifact",
            "generated bundle contains an unexpected source map directive",
        )
    if lines[-1].rstrip(b"\n") != SOURCE_MAP_TRAILER:
        raise PackageError(
            "forbidden_artifact",
            "generated bundle source map directive is not recognized",
        )
    sanitized = b"".join(lines[:-1])
    if not sanitized.endswith(b"\n"):
        sanitized += b"\n"
    return sanitized


def stage_runtime(bundle: Path, output: Path) -> Dict[str, Any]:
    manifest = load_manifest()
    try:
        output_details = output.lstat()
    except FileNotFoundError:
        output.mkdir(parents=True, exist_ok=False)
        output_details = output.lstat()
    except OSError as failure:
        raise PackageError(
            "stage_unsafe", "package stage cannot be inspected safely"
        ) from failure
    if stat.S_ISLNK(output_details.st_mode) or not stat.S_ISDIR(
        output_details.st_mode
    ):
        raise PackageError(
            "stage_unsafe", "package stage must be a real directory"
        )
    try:
        if any(output.iterdir()):
            raise PackageError(
                "stage_not_empty", "package stage must be empty"
            )
    except PackageError:
        raise
    except OSError as failure:
        raise PackageError(
            "stage_unsafe", "package stage cannot be inspected safely"
        ) from failure
    bundle_bytes = _sanitize_generated_bundle(
        _read_bounded_regular(bundle, MAX_MEMBER_BYTES)
    )
    _validate_runtime_bytes("PineAI.umd.js", bundle_bytes)

    for item in manifest["files"]:
        destination = output / Path(item["path"])
        destination.parent.mkdir(parents=True, exist_ok=True)
        payload = (
            bundle_bytes
            if item["generated"]
            else _read_bounded_regular(
                _source_path(item["source"]), MAX_MEMBER_BYTES
            )
        )
        _validate_runtime_bytes(item["path"], payload)
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
        )
        descriptor = os.open(str(destination), flags, item["mode"])
        try:
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        os.chmod(str(destination), item["mode"])
        if (
            os.name == "posix"
            and stat.S_IMODE(destination.stat().st_mode) != item["mode"]
        ):
            raise PackageError(
                "mode_mismatch",
                "stage file mode could not be applied",
            )
    for directory in _expected_directories(manifest):
        relative = PurePosixPath(directory).relative_to(MODULE_ROOT).as_posix()
        target = output if relative == "." else output / Path(relative)
        os.chmod(str(target), 0o755)
    return {
        "schema_version": "1.0",
        "file_count": len(manifest["files"]),
        "output": str(output),
    }


def _walk_dist(dist: Path) -> Tuple[set, set]:
    files = set()
    directories = {MODULE_ROOT}
    for root, directory_names, file_names in os.walk(str(dist), followlinks=False):
        root_path = Path(root)
        for name in list(directory_names):
            path = root_path / name
            if path.is_symlink():
                raise PackageError("dist_unsafe", "dist contains a link")
            relative = path.relative_to(dist).as_posix()
            directories.add("{0}/{1}".format(MODULE_ROOT, relative))
        for name in file_names:
            path = root_path / name
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise PackageError("dist_unsafe", "dist contains a special file")
            relative = path.relative_to(dist).as_posix()
            files.add("{0}/{1}".format(MODULE_ROOT, relative))
    return files, directories


def validate_dist(dist: Path) -> Dict[str, bytes]:
    manifest = load_manifest()
    if dist.is_symlink() or not dist.is_dir():
        raise PackageError("dist_invalid", "dist directory is unavailable")
    expected_files = {
        "{0}/{1}".format(MODULE_ROOT, item["path"])
        for item in manifest["files"]
    }
    expected_directories = set(_expected_directories(manifest))
    actual_files, actual_directories = _walk_dist(dist)
    if actual_files != expected_files or actual_directories != expected_directories:
        raise PackageError(
            "dist_mismatch", "dist contents do not match the runtime manifest"
        )

    payloads = {}
    for item in manifest["files"]:
        payload = _read_bounded_regular(
            dist / Path(item["path"]), MAX_MEMBER_BYTES
        )
        _validate_runtime_bytes(item["path"], payload)
        if not item["generated"]:
            source_payload = _read_bounded_regular(
                _source_path(item["source"]), MAX_MEMBER_BYTES
            )
            if not hashlib.sha256(payload).digest() == hashlib.sha256(
                source_payload
            ).digest():
                raise PackageError(
                    "source_mismatch",
                    "packaged runtime file differs from its source",
                )
        payloads[item["path"]] = payload
    return payloads


def _tar_info(name: str, mode: int, directory: bool = False) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mode = mode
    info.mtime = 0
    if directory:
        info.type = tarfile.DIRTYPE
        info.size = 0
    return info


def _canonical_archive_bytes(
    manifest: Dict[str, Any], payloads: Dict[str, bytes]
) -> bytes:
    tar_buffer = io.BytesIO()
    with tarfile.open(
        fileobj=tar_buffer,
        mode="w",
        format=tarfile.USTAR_FORMAT,
    ) as archive:
        for directory in _expected_directories(manifest):
            archive.addfile(_tar_info(directory, 0o755, True))
        for item in manifest["files"]:
            archive_name = "{0}/{1}".format(MODULE_ROOT, item["path"])
            payload = payloads[item["path"]]
            info = _tar_info(archive_name, item["mode"])
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    tar_payload = tar_buffer.getvalue()
    if len(tar_payload) > MAX_TAR_BYTES:
        raise PackageError("archive_too_large", "package tar stream exceeds limit")

    compressed_buffer = io.BytesIO()
    with gzip.GzipFile(
        filename="",
        mode="wb",
        fileobj=compressed_buffer,
        mtime=0,
        compresslevel=9,
    ) as compressed:
        compressed.write(tar_payload)
    archive_payload = compressed_buffer.getvalue()
    if len(archive_payload) > MAX_ARCHIVE_BYTES:
        raise PackageError("archive_too_large", "package archive exceeds limit")
    return archive_payload


def create_package(dist: Path, output: Path) -> Dict[str, Any]:
    manifest = load_manifest()
    payloads = validate_dist(dist)
    if output.exists() or output.is_symlink():
        raise PackageError("output_exists", "package output already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    archive_payload = _canonical_archive_bytes(manifest, payloads)
    descriptor = os.open(
        str(output),
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0),
        0o644,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(archive_payload)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    os.chmod(str(output), 0o644)
    return {
        "schema_version": "1.0",
        "output": str(output),
        "file_count": len(manifest["files"]),
        "sha256": hashlib.sha256(
            _read_bounded_regular(output, MAX_ARCHIVE_BYTES)
        ).hexdigest(),
    }


def _decompress_bytes(compressed: bytes) -> bytes:
    try:
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        payload = decompressor.decompress(compressed, MAX_TAR_BYTES + 1)
        if decompressor.unconsumed_tail or len(payload) > MAX_TAR_BYTES:
            raise PackageError(
                "archive_too_large", "package tar stream exceeds limit"
            )
        payload += decompressor.flush()
    except zlib.error as failure:
        raise PackageError(
            "archive_invalid", "package gzip stream is invalid"
        ) from failure
    if len(payload) > MAX_TAR_BYTES:
        raise PackageError("archive_too_large", "package tar stream exceeds limit")
    if not decompressor.eof or decompressor.unused_data:
        raise PackageError(
            "archive_noncanonical",
            "package must contain exactly one complete gzip stream",
        )
    return payload


def _decompress_archive(path: Path) -> bytes:
    return _decompress_bytes(_read_bounded_regular(path, MAX_ARCHIVE_BYTES))


def _validate_archive_name(name: Any) -> str:
    if (
        not isinstance(name, str)
        or not name
        or "\\" in name
        or "\x00" in name
        or any(ord(character) < 32 for character in name)
    ):
        raise PackageError("archive_unsafe", "package member name is invalid")
    parts = name.split("/")
    if (
        name.startswith("/")
        or any(part in ("", ".", "..") for part in parts)
        or PurePosixPath(name).as_posix() != name
    ):
        raise PackageError("archive_unsafe", "package member path is unsafe")
    return name


def inspect_archive(path: Path) -> Dict[str, Any]:
    manifest = load_manifest()
    compressed_payload = _read_bounded_regular(path, MAX_ARCHIVE_BYTES)
    tar_payload = _decompress_bytes(compressed_payload)
    expected_files = {
        "{0}/{1}".format(MODULE_ROOT, item["path"]): item
        for item in manifest["files"]
    }
    expected_directories = set(_expected_directories(manifest))
    expected_order = _expected_directories(manifest) + [
        "{0}/{1}".format(MODULE_ROOT, item["path"])
        for item in manifest["files"]
    ]
    seen = set()
    observed_order = []
    files = {}
    directories = set()
    total_size = 0
    try:
        archive = tarfile.open(fileobj=io.BytesIO(tar_payload), mode="r:")
    except tarfile.TarError as failure:
        raise PackageError("archive_invalid", "package tar stream is invalid") from failure
    try:
        count = 0
        while True:
            try:
                member = archive.next()
            except (OSError, tarfile.TarError) as failure:
                raise PackageError(
                    "archive_invalid", "package member stream is invalid"
                ) from failure
            if member is None:
                break
            count += 1
            if count > MAX_MEMBERS:
                raise PackageError("archive_too_large", "package has too many members")
            name = _validate_archive_name(member.name)
            if name in seen:
                raise PackageError("archive_duplicate", "package member is duplicated")
            seen.add(name)
            observed_order.append(name)
            if member.uid != 0 or member.gid != 0:
                raise PackageError("archive_owner", "package owner metadata is invalid")
            if member.type not in (tarfile.DIRTYPE, tarfile.REGTYPE):
                raise PackageError(
                    "archive_special", "package contains a link or special member"
                )
            if (
                member.uname
                or member.gname
                or member.linkname
                or member.mtime != 0
                or member.devmajor != 0
                or member.devminor != 0
                or member.pax_headers
                or getattr(member, "sparse", None)
            ):
                raise PackageError(
                    "archive_metadata", "package member metadata is invalid"
                )
            if member.type == tarfile.DIRTYPE:
                if member.mode != 0o755 or member.size != 0:
                    raise PackageError("archive_mode", "package directory mode is invalid")
                directories.add(name)
                continue
            expected = expected_files.get(name)
            if expected is None:
                raise PackageError("archive_extra", "package contains an unknown file")
            if member.mode != expected["mode"]:
                raise PackageError("archive_mode", "package file mode is invalid")
            if member.size < 0 or member.size > MAX_MEMBER_BYTES:
                raise PackageError("archive_too_large", "package member exceeds limit")
            total_size += member.size
            if total_size > MAX_TOTAL_FILE_BYTES:
                raise PackageError("archive_too_large", "package payload exceeds limit")
            extracted = archive.extractfile(member)
            if extracted is None:
                raise PackageError("archive_invalid", "package member is unreadable")
            payload = extracted.read(MAX_MEMBER_BYTES + 1)
            if len(payload) != member.size:
                raise PackageError("archive_invalid", "package member size is invalid")
            _validate_runtime_bytes(expected["path"], payload)
            files[name] = payload
    finally:
        archive.close()
    if set(files) != set(expected_files) or directories != expected_directories:
        raise PackageError(
            "archive_mismatch", "package contents do not match the runtime manifest"
        )
    if observed_order != expected_order:
        raise PackageError(
            "archive_noncanonical", "package member order is not canonical"
        )
    canonical_payloads = {
        item["path"]: files["{0}/{1}".format(MODULE_ROOT, item["path"])]
        for item in manifest["files"]
    }
    if compressed_payload != _canonical_archive_bytes(
        manifest, canonical_payloads
    ):
        raise PackageError(
            "archive_noncanonical", "package encoding is not canonical"
        )
    return {
        "manifest": manifest,
        "files": files,
        "directories": directories,
        "total_size": total_size,
    }


def _module_version(payload: bytes) -> str:
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as failure:
        raise PackageError("version_invalid", "module.json is invalid") from failure
    if not isinstance(value, dict) or not isinstance(value.get("version"), str):
        raise PackageError("version_invalid", "module version is invalid")
    version = value["version"]
    if not SEMVER_PATTERN.match(version):
        raise PackageError("version_invalid", "module version is not strict SemVer")
    return version


def _controlled_extract(
    files: Dict[str, bytes], directories: Iterable[str], target: Path
) -> Path:
    if target.exists():
        if not target.is_dir() or any(target.iterdir()):
            raise PackageError(
                "extract_target_invalid",
                "package verification target must be an empty directory",
            )
        os.chmod(str(target), 0o700)
    else:
        target.mkdir(mode=0o700)
    for directory in sorted(directories):
        path = target / Path(directory)
        path.mkdir(parents=True, exist_ok=True)
        os.chmod(str(path), 0o755)
    for name, payload in files.items():
        path = target / Path(name)
        descriptor = os.open(
            str(path),
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0),
            0o600,
        )
        try:
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(payload)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    return target / MODULE_ROOT


def _isolated_import_check(package_root: Path, backend_names: List[str]) -> None:
    script = r"""
import importlib
import importlib.util
import json
import sys
import types
from pathlib import Path

root = Path(sys.argv[1])
assets = root / "assets"
sys.path.insert(0, str(assets))

pineapple = types.ModuleType("pineapple")
modules = types.ModuleType("pineapple.modules")
class Request:
    pass
class Module:
    def __init__(self, *_args, **_kwargs):
        self._actions = {}
    def handles_action(self, name):
        def decorator(function):
            self._actions[name] = function
            return function
        return decorator
    def start(self):
        return None
modules.Request = Request
modules.Module = Module
pineapple.modules = modules
sys.modules["pineapple"] = pineapple
sys.modules["pineapple.modules"] = modules

for name in json.loads(sys.argv[2]):
    importlib.import_module(name)
importlib.import_module("pineai_cli")
spec = importlib.util.spec_from_file_location("pineai_packaged_module", root / "module.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module_json = json.loads((root / "module.json").read_text(encoding="utf-8"))
backend = importlib.import_module("pineai_backend")
if getattr(backend, "__version__", None) != module_json["version"]:
    raise SystemExit(3)
"""
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    for name in ("SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    try:
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                "-c",
                script,
                str(package_root),
                json.dumps(backend_names),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=environment,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as failure:
        raise PackageError(
            "package_import_failed",
            "isolated packaged runtime import check failed",
        ) from failure
    if completed.returncode != 0:
        raise PackageError(
            "package_import_failed",
            "isolated packaged runtime import check failed",
        )


def verify_package(
    path: Path,
    run_import_check: bool = True,
    expected_bundle: Optional[Path] = None,
) -> Dict[str, Any]:
    inspected = inspect_archive(path)
    manifest = inspected["manifest"]
    module_name = "{0}/module.json".format(MODULE_ROOT)
    version = _module_version(inspected["files"][module_name])
    expected_name = "{0}-{1}.tar.gz".format(MODULE_ROOT, version)
    if path.name != expected_name:
        raise PackageError("package_name", "package filename does not match version")

    if expected_bundle is not None:
        bundle_payload = _sanitize_generated_bundle(
            _read_bounded_regular(expected_bundle, MAX_MEMBER_BYTES)
        )
        _validate_runtime_bytes("PineAI.umd.js", bundle_payload)
        if inspected["files"]["{0}/PineAI.umd.js".format(MODULE_ROOT)] != bundle_payload:
            raise PackageError(
                "bundle_mismatch",
                "packaged bundle differs from the expected production bundle",
            )

    for item in manifest["files"]:
        if item["generated"]:
            continue
        archive_name = "{0}/{1}".format(MODULE_ROOT, item["path"])
        source = _read_bounded_regular(
            _source_path(item["source"]), MAX_MEMBER_BYTES
        )
        if hashlib.sha256(inspected["files"][archive_name]).digest() != hashlib.sha256(
            source
        ).digest():
            raise PackageError(
                "source_mismatch", "packaged runtime file differs from source"
            )

    if run_import_check:
        backend_names = [
            "pineai_backend"
        ] + [
            "pineai_backend.{0}".format(Path(item["path"]).stem)
            for item in manifest["files"]
            if item["path"].startswith("assets/pineai_backend/")
            and item["path"] != "assets/pineai_backend/__init__.py"
        ]
        with tempfile.TemporaryDirectory(prefix="pineai-package-verify-") as temp:
            package_root = _controlled_extract(
                inspected["files"], inspected["directories"], Path(temp)
            )
            _isolated_import_check(package_root, sorted(backend_names))
    archive_payload = _read_bounded_regular(path, MAX_ARCHIVE_BYTES)
    return {
        "schema_version": "1.0",
        "verified": True,
        "version": version,
        "file_count": len(inspected["files"]),
        "directory_count": len(inspected["directories"]),
        "payload_bytes": inspected["total_size"],
        "sha256": hashlib.sha256(archive_payload).hexdigest(),
    }


def _print_result(result: Dict[str, Any]) -> None:
    print(json.dumps(result, sort_keys=True))


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    stage = subparsers.add_parser("stage")
    stage.add_argument("--bundle", required=True)
    stage.add_argument("--output", required=True)

    create = subparsers.add_parser("create")
    create.add_argument("--dist", required=True)
    create.add_argument("--output", required=True)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--archive", required=True)
    verify.add_argument("--bundle")
    verify.add_argument("--skip-import-check", action="store_true")

    args = parser.parse_args(argv)
    try:
        if args.command == "stage":
            result = stage_runtime(Path(args.bundle), Path(args.output))
        elif args.command == "create":
            result = create_package(Path(args.dist), Path(args.output))
        else:
            result = verify_package(
                Path(args.archive),
                run_import_check=not args.skip_import_check,
                expected_bundle=Path(args.bundle) if args.bundle else None,
            )
    except PackageError as failure:
        print(
            json.dumps(
                {"success": False, "error": {"code": failure.code}},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    _print_result(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
