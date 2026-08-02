#!/usr/bin/env python3
"""Passively verify and import a PineAssure package in disposable state."""

import argparse
import hashlib
import importlib
import importlib.util
import json
import os
import stat
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional, Tuple


MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_MEMBERS = 64
EXPECTED_ACTIONS = {
    "health",
    "repeatable_audit_capabilities",
    "resource_telemetry",
    "create_measurement_point",
    "list_measurement_points",
    "get_measurement_point",
    "update_measurement_point",
    "archive_measurement_point",
    "create_audit_run",
    "list_audit_runs",
    "get_audit_run",
    "start_audit_run",
    "cancel_audit_run",
    "complete_audit_run",
    "resolve_audit_measurement",
    "save_audit_measurement_comparison",
    "retry_audit_measurement",
    "generate_audit_run_report",
}


class SmokeError(Exception):
    """Raised when a passive package smoke gate fails."""


class _StrictPackageTarInfo(tarfile.TarInfo):
    """Reject non-USTAR extensions before their payload is parsed."""

    def _proc_member(self, archive: tarfile.TarFile) -> tarfile.TarInfo:
        if self.type not in (tarfile.REGTYPE, tarfile.DIRTYPE):
            raise SmokeError("archive contains a tar extension or special member")
        if (
            not isinstance(self.size, int)
            or isinstance(self.size, bool)
            or self.size < 0
            or self.size > MAX_MEMBER_BYTES
        ):
            raise SmokeError("archive member exceeds size limit")
        return super()._proc_member(archive)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(64 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _expected_sha(path: Path, archive_name: str) -> str:
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeDecodeError) as failure:
        raise SmokeError("checksum file is unavailable or invalid") from failure
    matches = []
    for line in lines:
        fields = line.strip().split()
        if len(fields) == 2 and fields[1].lstrip("*") == archive_name:
            matches.append(fields[0].lower())
    if len(matches) != 1 or len(matches[0]) != 64:
        raise SmokeError("checksum file must contain exactly one archive entry")
    if any(character not in "0123456789abcdef" for character in matches[0]):
        raise SmokeError("checksum is not lowercase SHA-256")
    return matches[0]


def _safe_name(name: str) -> str:
    if not name or "\\" in name or "\x00" in name or name.startswith("/"):
        raise SmokeError("archive member path is unsafe")
    path = PurePosixPath(name)
    if path.as_posix() != name or any(part in ("", ".", "..") for part in path.parts):
        raise SmokeError("archive member path is unsafe")
    if path.parts[0] != "PineAI":
        raise SmokeError("archive root is not PineAI")
    return name


def _extract_archive(archive_path: Path, target: Path) -> Tuple[Path, int, int]:
    if archive_path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise SmokeError("archive exceeds size limit")
    count = 0
    total = 0
    seen = set()
    try:
        archive = tarfile.open(
            str(archive_path),
            mode="r:gz",
            tarinfo=_StrictPackageTarInfo,
        )
    except (OSError, tarfile.TarError) as failure:
        raise SmokeError("archive cannot be opened") from failure
    try:
        for member in archive:
            count += 1
            if count > MAX_MEMBERS:
                raise SmokeError("archive has too many members")
            name = _safe_name(member.name)
            if name in seen:
                raise SmokeError("archive has duplicate members")
            seen.add(name)
            destination = target.joinpath(*PurePosixPath(name).parts)
            if member.isdir():
                if member.mode != 0o755:
                    raise SmokeError("archive directory mode is invalid")
                destination.mkdir(parents=True, exist_ok=True)
                os.chmod(str(destination), 0o755)
                continue
            if not member.isfile() or member.mode not in (0o644, 0o755):
                raise SmokeError("archive contains a link or special member")
            if member.size < 0 or member.size > MAX_MEMBER_BYTES:
                raise SmokeError("archive member exceeds size limit")
            total += member.size
            if total > MAX_TOTAL_BYTES:
                raise SmokeError("archive payload exceeds size limit")
            extracted = archive.extractfile(member)
            if extracted is None:
                raise SmokeError("archive member is unreadable")
            payload = extracted.read(MAX_MEMBER_BYTES + 1)
            if len(payload) != member.size:
                raise SmokeError("archive member length is invalid")
            destination.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(
                str(destination), os.O_WRONLY | os.O_CREAT | os.O_EXCL, member.mode
            )
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    descriptor = -1
                    handle.write(payload)
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
    finally:
        archive.close()
    return target / "PineAI", count, total


class Request:
    def __init__(self, **values: Any):
        for name, value in values.items():
            setattr(self, name, value)


class Module:
    def __init__(self, *_arguments: Any, **_keywords: Any):
        self.actions: Dict[str, Any] = {}

    def handles_action(self, name: str):
        def decorator(function: Any) -> Any:
            self.actions[name] = function
            return function

        return decorator

    def start(self) -> None:
        return None


def _install_pineapple_stub() -> None:
    import types

    pineapple = types.ModuleType("pineapple")
    modules = types.ModuleType("pineapple.modules")
    modules.Module = Module
    modules.Request = Request
    pineapple.modules = modules
    sys.modules["pineapple"] = pineapple
    sys.modules["pineapple.modules"] = modules


def _rss_kib() -> Optional[int]:
    try:
        for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except (OSError, UnicodeDecodeError, ValueError, IndexError):
        return None
    return None


def _import_and_probe(package_root: Path, state: Path, iterations: int) -> Dict[str, Any]:
    os.environ["PINEAI_CONFIG_DIR"] = str(state)
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    sys.dont_write_bytecode = True
    assets = package_root / "assets"
    sys.path.insert(0, str(assets))
    _install_pineapple_stub()
    backend_dir = assets / "pineai_backend"
    backend_names = [
        "pineai_backend.{0}".format(path.stem)
        for path in sorted(backend_dir.glob("*.py"))
        if path.name != "__init__.py"
    ]
    importlib.import_module("pineai_backend")
    for name in backend_names:
        importlib.import_module(name)
    specification = importlib.util.spec_from_file_location(
        "pineassure_markvii_smoke_module", package_root / "module.py"
    )
    if specification is None or specification.loader is None:
        raise SmokeError("module.py cannot be imported")
    imported = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(imported)
    actions = set(imported.module.actions)
    missing = sorted(EXPECTED_ACTIONS - actions)
    if missing:
        raise SmokeError("required v0.7 module actions are missing")
    before = _rss_kib()
    health = None
    for _index in range(iterations):
        health = imported.module.actions["health"](Request())
        if not isinstance(health, dict) or health.get("status") != "ok":
            raise SmokeError("health action failed")
        if health.get("offline_complete") is not True:
            raise SmokeError("health does not confirm offline operation")
        if health.get("recon_control") is not False:
            raise SmokeError("health unexpectedly enables Recon control")
    after = _rss_kib()
    try:
        import resource

        maximum = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    except ImportError:
        maximum = None
    return {
        "module_version": health.get("version") if health else None,
        "action_count": len(actions),
        "required_actions_present": True,
        "iterations": iterations,
        "rss_before_kib": before,
        "rss_after_kib": after,
        "peak_rss_kib": maximum,
        "state_mode": stat.S_IMODE(state.stat().st_mode),
    }


def _platform_facts() -> Dict[str, Any]:
    facts: Dict[str, Any] = {
        "python": sys.version.split()[0],
        "platform": sys.platform,
    }
    release = Path("/etc/openwrt_release")
    if release.is_file():
        values = {}
        try:
            for line in release.read_text(encoding="utf-8").splitlines():
                if line.startswith(("DISTRIB_ID=", "DISTRIB_RELEASE=", "DISTRIB_TARGET=")):
                    name, value = line.split("=", 1)
                    values[name] = value.strip("'\"")[:128]
        except (OSError, UnicodeDecodeError, ValueError):
            values = {}
        facts["openwrt"] = values
    return facts


def _write_result(path: Path, result: Dict[str, Any]) -> None:
    payload = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(payload)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--sha256-file", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--iterations", type=int, default=1)
    arguments = parser.parse_args(argv)
    if arguments.iterations < 1 or arguments.iterations > 1000:
        parser.error("--iterations must be between 1 and 1000")
    archive = Path(arguments.archive)
    output = Path(arguments.output)
    result: Dict[str, Any] = {
        "schema_version": "1.0",
        "hardware_validated": False,
        "radio_actions_performed": False,
        "archive": archive.name,
        "platform": _platform_facts(),
    }
    try:
        expected = _expected_sha(Path(arguments.sha256_file), archive.name)
        actual = _sha256_file(archive)
        if actual != expected:
            raise SmokeError("archive checksum does not match")
        with tempfile.TemporaryDirectory(prefix="pineassure-v070-smoke-") as temp:
            temporary = Path(temp)
            package, members, total = _extract_archive(
                archive, temporary / "package"
            )
            state = temporary / "state"
            state.mkdir(mode=0o700)
            result.update(_import_and_probe(package, state, arguments.iterations))
            result["archive_member_count"] = members
            result["archive_payload_bytes"] = total
        result["archive_sha256"] = actual
        result["success"] = True
    except (
        ImportError,
        KeyError,
        OSError,
        SmokeError,
        ValueError,
        tarfile.TarError,
    ):
        result["success"] = False
        result["error"] = {"code": "passive_smoke_failed"}
    try:
        _write_result(output, result)
    except OSError:
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("success") else 1


if __name__ == "__main__":
    sys.exit(main())
