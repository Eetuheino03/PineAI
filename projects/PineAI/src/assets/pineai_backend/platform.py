"""Safe platform and storage capability reporting for the module UI."""

import os
import platform
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from .config import public_identity_status, resolve_config_dir


PLATFORM_CAPABILITY_SCHEMA_VERSION = "1.0"


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
