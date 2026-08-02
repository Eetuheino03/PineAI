#!/usr/bin/env python3
"""Generate a deterministic CycloneDX 1.5 SBOM for a verified package."""

import argparse
import hashlib
import json
import os
import re
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import quote

from package_tool import MODULE_ROOT, PackageError, inspect_archive


ROOT = Path(__file__).resolve().parents[1]
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
REQUIREMENT_PATTERN = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:==([^;\s]+))?$"
)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _property(name: str, value: Any) -> Dict[str, str]:
    return {"name": name, "value": str(value).lower() if isinstance(value, bool) else str(value)}


def _module_metadata(files: Dict[str, bytes]) -> Dict[str, Any]:
    path = "{0}/module.json".format(MODULE_ROOT)
    try:
        value = json.loads(files[path].decode("utf-8"))
    except (KeyError, UnicodeDecodeError, ValueError) as failure:
        raise ValueError("package module.json is invalid") from failure
    if not isinstance(value, dict):
        raise ValueError("package module.json must be an object")
    for field in ("name", "version", "firmware_required"):
        if not isinstance(value.get(field), str) or not value[field]:
            raise ValueError("package module.json field {0} is invalid".format(field))
    return value


def _file_components(files: Dict[str, bytes]) -> Tuple[List[Dict[str, Any]], List[str]]:
    components = []
    references = []
    for path in sorted(files):
        digest = _sha256(files[path])
        reference = "file:{0}:{1}".format(path, digest[:16])
        references.append(reference)
        components.append(
            {
                "type": "file",
                "bom-ref": reference,
                "name": path,
                "hashes": [{"alg": "SHA-256", "content": digest}],
                "scope": "required",
                "properties": [
                    _property("pineassure:dependency-class", "shipped-runtime"),
                    _property("pineassure:archive-path", path),
                ],
            }
        )
    return components, references


def _npm_name(path: str, record: Dict[str, Any]) -> Optional[str]:
    name = record.get("name")
    if isinstance(name, str) and name:
        return name
    if "node_modules/" not in path:
        return None
    return path.rsplit("node_modules/", 1)[1]


def _npm_components(path: Path) -> List[Dict[str, Any]]:
    try:
        lock = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as failure:
        raise ValueError("package lock is unavailable or invalid") from failure
    packages = lock.get("packages")
    if not isinstance(packages, dict):
        raise ValueError("package lock does not use the supported v2 packages map")
    observed: Set[Tuple[str, str]] = set()
    result = []
    for package_path, raw in sorted(packages.items()):
        if not package_path or not isinstance(raw, dict):
            continue
        name = _npm_name(package_path, raw)
        version = raw.get("version")
        if not name or not isinstance(version, str) or not version:
            continue
        key = (name, version)
        if key in observed:
            continue
        observed.add(key)
        encoded = quote(name, safe="/")
        reference = "pkg:npm/{0}@{1}".format(encoded, version)
        properties = [
            _property("pineassure:dependency-class", "frontend-build-input"),
            _property("pineassure:shipped-as-package-file", False),
            _property("pineassure:lockfile-path", package_path),
        ]
        if raw.get("dev") is True:
            properties.append(_property("pineassure:npm-scope", "development"))
        else:
            properties.append(_property("pineassure:npm-scope", "build-runtime"))
        component: Dict[str, Any] = {
            "type": "library",
            "bom-ref": reference,
            "name": name,
            "version": version,
            "purl": reference,
            "scope": "excluded",
            "properties": properties,
        }
        integrity = raw.get("integrity")
        if isinstance(integrity, str) and integrity:
            component["properties"].append(
                _property("pineassure:npm-integrity", integrity)
            )
        result.append(component)
    return result


def _python_tool_components(path: Path) -> List[Dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as failure:
        raise ValueError("requirements file is unavailable or invalid") from failure
    result = []
    for line in lines:
        value = line.split("#", 1)[0].strip()
        if not value:
            continue
        match = REQUIREMENT_PATTERN.match(value)
        if not match or not match.group(2):
            raise ValueError("requirements must be exact name==version pins")
        name, version = match.groups()
        normalized = re.sub(r"[-_.]+", "-", name).lower()
        reference = "pkg:pypi/{0}@{1}".format(normalized, version)
        result.append(
            {
                "type": "library",
                "bom-ref": reference,
                "name": name,
                "version": version,
                "purl": reference,
                "scope": "excluded",
                "properties": [
                    _property("pineassure:dependency-class", "test-tool"),
                    _property("pineassure:shipped-as-package-file", False),
                ],
            }
        )
    return result


def _host_components(module: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[str]]:
    firmware_ref = "platform:hak5-wifi-pineapple-mark-vii"
    python_ref = "framework:cpython:3.8"
    components = [
        {
            "type": "platform",
            "bom-ref": firmware_ref,
            "name": "Hak5 WiFi Pineapple Mark VII firmware",
            "version": module["firmware_required"],
            "scope": "required",
            "properties": [
                _property("pineassure:dependency-class", "host-platform"),
                _property("pineassure:version-semantics", "minimum-required"),
            ],
        },
        {
            "type": "framework",
            "bom-ref": python_ref,
            "name": "CPython",
            "version": "3.8",
            "scope": "required",
            "properties": [
                _property("pineassure:dependency-class", "host-runtime"),
                _property("pineassure:version-semantics", "tested-compatibility"),
            ],
        },
    ]
    return components, [firmware_ref, python_ref]


def _unique_components(components: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    result = []
    references = set()
    for component in components:
        reference = component.get("bom-ref")
        if not isinstance(reference, str) or not reference or reference in references:
            raise ValueError("SBOM component references must be unique strings")
        references.add(reference)
        result.append(component)
    return result


def build_sbom(
    archive: Path,
    package_lock: Path,
    requirements: Path,
) -> Dict[str, Any]:
    inspected = inspect_archive(archive)
    files = inspected["files"]
    module = _module_metadata(files)
    archive_payload = archive.read_bytes()
    archive_digest = _sha256(archive_payload)
    application_ref = "pkg:generic/PineAI@{0}".format(module["version"])
    shipped, shipped_refs = _file_components(files)
    hosts, host_refs = _host_components(module)
    components = _unique_components(
        shipped
        + hosts
        + _npm_components(package_lock)
        + _python_tool_components(requirements)
    )
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:{0}".format(
            uuid.uuid5(uuid.NAMESPACE_URL, "sha256:{0}".format(archive_digest))
        ),
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": application_ref,
                "name": "PineAssure",
                "version": module["version"],
                "hashes": [{"alg": "SHA-256", "content": archive_digest}],
                "properties": [
                    _property("pineassure:technical-module-id", module["name"]),
                    _property("pineassure:archive-name", archive.name),
                    _property("pineassure:hardware-validated", False),
                ],
            }
        },
        "components": components,
        "dependencies": [
            {
                "ref": application_ref,
                "dependsOn": sorted(shipped_refs + host_refs),
            }
        ],
    }
    validate_sbom(sbom)
    return sbom


def validate_sbom(sbom: Dict[str, Any]) -> None:
    if sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") != "1.5":
        raise ValueError("SBOM header is invalid")
    components = sbom.get("components")
    if not isinstance(components, list) or not components:
        raise ValueError("SBOM components are missing")
    references = set()
    for component in components:
        if not isinstance(component, dict):
            raise ValueError("SBOM component is invalid")
        reference = component.get("bom-ref")
        if not isinstance(reference, str) or not reference or reference in references:
            raise ValueError("SBOM component reference is invalid")
        references.add(reference)
        for digest in component.get("hashes", []):
            if digest.get("alg") != "SHA-256" or not SHA256_PATTERN.match(
                digest.get("content", "")
            ):
                raise ValueError("SBOM SHA-256 hash is invalid")


def _write_exclusive(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        str(path),
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
        0o644,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--package-lock", default=str(ROOT / "package-lock.json"))
    parser.add_argument(
        "--requirements", default=str(ROOT / "requirements-dev.txt")
    )
    arguments = parser.parse_args(argv)
    try:
        sbom = build_sbom(
            Path(arguments.archive),
            Path(arguments.package_lock),
            Path(arguments.requirements),
        )
        payload = (
            json.dumps(sbom, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        ).encode("utf-8")
        _write_exclusive(Path(arguments.output), payload)
    except (OSError, PackageError, ValueError):
        print(
            json.dumps(
                {"success": False, "error": {"code": "sbom_generation_failed"}},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    print(
        json.dumps(
            {
                "success": True,
                "output": str(Path(arguments.output)),
                "sha256": _sha256(payload),
                "component_count": len(sbom["components"]),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
