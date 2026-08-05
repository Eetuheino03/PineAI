"""Safe platform, storage, and resource reporting for the module UI.

The implementation deliberately uses only the Python standard library.  The
Mark VII image does not ship psutil, and collecting telemetry must never shell
out or inspect secrets.  Values that are unavailable on a development host are
reported as ``None`` instead of being guessed.
"""

import os
import platform
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from .config import public_identity_status, resolve_config_dir
from .errors import BackendError


PLATFORM_CAPABILITY_SCHEMA_VERSION = "1.0"
RESOURCE_TELEMETRY_SCHEMA_VERSION = "1.0"
MIN_AVAILABLE_MEMORY_BYTES = 32 * 1024 * 1024
MIN_FREE_STORAGE_BYTES = 16 * 1024 * 1024
MAX_TELEMETRY_ASSESSMENTS = 128
MAX_TELEMETRY_FILES = 8192


def _storage_status(directory: Path) -> Dict[str, Any]:
    probe = directory if directory.exists() else directory.parent
    try:
        usage = shutil.disk_usage(str(probe))
        readable = os.access(str(probe), os.R_OK)
        writable = os.access(str(probe), os.W_OK)
        return {
            "status": "ready" if readable and writable else "blocked",
            "readable": readable,
            "writable": writable,
            "free_bytes": usage.free,
            "total_bytes": usage.total,
            "config_directory_exists": directory.exists(),
        }
    except OSError:
        return {
            "status": "blocked",
            "readable": False,
            "writable": False,
            "free_bytes": None,
            "total_bytes": None,
            "config_directory_exists": directory.exists(),
        }


def _proc_key_value(path: Path) -> Dict[str, str]:
    """Read a small Linux procfs key/value document without following links."""
    values: Dict[str, str] = {}
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 256 * 1024:
            return values
        with path.open("r", encoding="ascii", errors="replace") as handle:
            for line in handle:
                key, separator, value = line.partition(":")
                if separator:
                    values[key.strip()] = value.strip()
    except OSError:
        return {}
    return values


def _kib_value(values: Dict[str, str], key: str) -> Optional[int]:
    raw = values.get(key)
    if not raw:
        return None
    fields = raw.split()
    try:
        number = int(fields[0])
    except (IndexError, TypeError, ValueError):
        return None
    if len(fields) > 1 and fields[1].lower() != "kb":
        return None
    return number * 1024


def _memory_status() -> Dict[str, Optional[int]]:
    process = _proc_key_value(Path("/proc/self/status"))
    system = _proc_key_value(Path("/proc/meminfo"))
    return {
        "process_rss_bytes": _kib_value(process, "VmRSS"),
        "process_peak_rss_bytes": _kib_value(process, "VmHWM"),
        "mem_available_bytes": _kib_value(system, "MemAvailable"),
        "mem_total_bytes": _kib_value(system, "MemTotal"),
    }


def _load_status() -> Dict[str, Optional[float]]:
    try:
        one, five, fifteen = os.getloadavg()
        return {
            "one_minute": round(float(one), 4),
            "five_minutes": round(float(five), 4),
            "fifteen_minutes": round(float(fifteen), 4),
        }
    except (AttributeError, OSError):
        return {
            "one_minute": None,
            "five_minutes": None,
            "fifteen_minutes": None,
        }


def _bounded_tree_usage(root: Path) -> Dict[str, Any]:
    """Count regular assessment artifacts without traversing symlinks."""
    if not root.exists():
        return {
            "assessment_count": 0,
            "file_count": 0,
            "total_bytes": 0,
            "transaction_directories": 0,
            "truncated": False,
        }
    try:
        root.lstat()
    except OSError:
        return {
            "assessment_count": None,
            "file_count": None,
            "total_bytes": None,
            "transaction_directories": None,
            "truncated": True,
        }
    if root.is_symlink() or not root.is_dir():
        return {
            "assessment_count": None,
            "file_count": None,
            "total_bytes": None,
            "transaction_directories": None,
            "truncated": True,
        }

    assessment_count = 0
    file_count = 0
    total_bytes = 0
    transaction_directories = 0
    truncated = False
    try:
        with os.scandir(str(root)) as assessments:
            assessment_paths = []
            for entry in assessments:
                if entry.is_dir(follow_symlinks=False):
                    assessment_paths.append(Path(entry.path))
                    assessment_count += 1
                    if assessment_count > MAX_TELEMETRY_ASSESSMENTS:
                        truncated = True
                        break
        for assessment in assessment_paths[:MAX_TELEMETRY_ASSESSMENTS]:
            for current, directories, files in os.walk(
                str(assessment), topdown=True, followlinks=False
            ):
                directories[:] = [
                    name
                    for name in directories
                    if not (Path(current) / name).is_symlink()
                ]
                transaction_directories += sum(
                    1 for name in directories if name == ".transactions"
                )
                for name in files:
                    path = Path(current) / name
                    try:
                        item = path.lstat()
                    except OSError:
                        truncated = True
                        continue
                    if path.is_symlink() or not path.is_file():
                        continue
                    file_count += 1
                    total_bytes += item.st_size
                    if file_count >= MAX_TELEMETRY_FILES:
                        truncated = True
                        break
                if truncated and file_count >= MAX_TELEMETRY_FILES:
                    directories[:] = []
                    break
            if truncated and file_count >= MAX_TELEMETRY_FILES:
                break
    except OSError:
        truncated = True
    return {
        "assessment_count": min(assessment_count, MAX_TELEMETRY_ASSESSMENTS),
        "file_count": file_count,
        "total_bytes": total_bytes,
        "transaction_directories": transaction_directories,
        "truncated": truncated,
    }


def resource_telemetry(
    config_dir: Optional[str] = None,
    assessment_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Return bounded, secret-free resource telemetry.

    ``assessment_id`` is accepted for the public API contract.  The current
    telemetry is deliberately aggregate-only so an untrusted caller cannot use
    it to enumerate private assessment names or identifiers.
    """
    if assessment_id is not None and (
        not isinstance(assessment_id, str)
        or len(assessment_id) > 128
        or not assessment_id
    ):
        raise BackendError("invalid_assessment_id", "assessment_id is invalid")
    directory = resolve_config_dir(config_dir)
    storage = _storage_status(directory)
    memory = _memory_status()
    artifacts = _bounded_tree_usage(directory / "assessments")
    try:
        from .operation_lock import scan_processing_status

        scan_status = scan_processing_status(config_dir)
    except BackendError:
        scan_status = "unavailable"
    blocking = []
    warnings = []
    available = memory["mem_available_bytes"]
    free_storage = storage.get("free_bytes")
    if storage["status"] == "blocked":
        blocking.append("storage_unavailable")
    elif isinstance(free_storage, int) and free_storage < MIN_FREE_STORAGE_BYTES:
        blocking.append("storage_guard_blocked")
    if isinstance(available, int) and available < MIN_AVAILABLE_MEMORY_BYTES:
        blocking.append("memory_guard_blocked")
    elif available is None:
        warnings.append("memory_telemetry_unavailable")
    if artifacts["truncated"]:
        warnings.append("artifact_telemetry_truncated")
    return {
        "schema_version": RESOURCE_TELEMETRY_SCHEMA_VERSION,
        "status": "blocked" if blocking else ("degraded" if warnings else "ready"),
        "blocking_codes": blocking,
        "warnings": warnings,
        "memory": memory,
        "load_average": _load_status(),
        "storage": storage,
        "artifacts": artifacts,
        "scan_processing": {"status": scan_status},
        "guard": {
            "minimum_available_memory_bytes": MIN_AVAILABLE_MEMORY_BYTES,
            "minimum_free_storage_bytes": MIN_FREE_STORAGE_BYTES,
            "hardware_calibrated": False,
        },
        "assessment_filter_applied": assessment_id is not None,
    }


def require_operation_capacity(
    config_dir: Optional[str] = None,
    payload_bytes: int = 0,
    estimated_write_bytes: int = 0,
) -> Dict[str, Any]:
    """Apply conservative pre-operation memory and storage admission rules."""
    if (
        not isinstance(payload_bytes, int)
        or isinstance(payload_bytes, bool)
        or payload_bytes < 0
        or not isinstance(estimated_write_bytes, int)
        or isinstance(estimated_write_bytes, bool)
        or estimated_write_bytes < 0
    ):
        raise BackendError("invalid_resource_estimate", "resource estimate is invalid")
    status = resource_telemetry(config_dir)
    available = status["memory"]["mem_available_bytes"]
    free_storage = status["storage"].get("free_bytes")
    projected_memory = max(8 * 1024 * 1024, payload_bytes * 4)
    projected_storage = max(estimated_write_bytes * 2, 1024 * 1024)
    if isinstance(available, int) and (
        available - projected_memory < MIN_AVAILABLE_MEMORY_BYTES
    ):
        raise BackendError(
            "resource_guard_blocked",
            "available memory is below the safe operation threshold",
        )
    if isinstance(free_storage, int) and (
        free_storage - projected_storage < MIN_FREE_STORAGE_BYTES
    ):
        raise BackendError(
            "resource_guard_blocked",
            "free storage is below the safe operation threshold",
        )
    if status["storage"]["status"] == "blocked":
        raise BackendError("resource_guard_blocked", "private storage is unavailable")
    return status


def platform_capabilities(config_dir: Optional[str] = None) -> Dict[str, Any]:
    """Return local capabilities without secrets, shelling out, or radio writes."""
    directory = resolve_config_dir(config_dir)
    identity = public_identity_status(config_dir)
    storage = _storage_status(directory)
    blocking = []
    warnings = []
    if identity["status"] == "blocked":
        blocking.append(identity["code"])
    elif identity["status"] == "uninitialized":
        warnings.append("identity_will_initialize_on_first_resolve")
    if storage["status"] == "blocked":
        blocking.append("storage_unavailable")
    if blocking:
        status = "blocked"
    elif warnings:
        status = "degraded"
    else:
        status = "ready"
    return {
        "schema_version": PLATFORM_CAPABILITY_SCHEMA_VERSION,
        "status": status,
        "blocking_codes": blocking,
        "warnings": warnings,
        "identity": identity,
        "storage": storage,
        "runtime": {
            "python_version": "{0}.{1}.{2}".format(
                sys.version_info[0], sys.version_info[1], sys.version_info[2]
            ),
            "python_3_8_compatible": sys.version_info >= (3, 8),
            "platform": platform.system().lower(),
        },
        "device": {
            "source": "frontend_hak5_api",
            "endpoint": "/api/device",
            "value": None,
        },
        "interfaces": {
            "source": "frontend_hak5_api",
            "endpoint": "/api/settings/networking/interfaces",
            "values": [],
            "band_capability_documented": False,
        },
        "bands": {
            "2.4": "profile_declared",
            "5": "operator_confirmation_required",
            "6": "unsupported_on_mark_vii",
        },
        "recon_control": False,
        "saved_recon_only": True,
    }
