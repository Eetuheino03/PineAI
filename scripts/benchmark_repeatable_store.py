#!/usr/bin/env python3
"""Workstation-only RepeatableAuditStore benchmark workloads."""

import json
import os
import re
import stat
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "projects" / "PineAI" / "src" / "assets"
if str(ASSETS) not in sys.path:
    sys.path.insert(0, str(ASSETS))

from pineai_backend.assessment_store import (  # noqa: E402
    _canonical_digest,
)
from pineai_backend.assurance_service import AssuranceService  # noqa: E402
from pineai_backend.config import ensure_pseudonymization_key  # noqa: E402
from pineai_backend.errors import BackendError  # noqa: E402
from pineai_backend.repeatable_audit_store import (  # noqa: E402
    MAX_ACTIVE_MEASUREMENT_POINTS,
    MAX_AUDIT_RUNS_PER_ASSESSMENT,
    MAX_TOTAL_MEASUREMENT_POINT_RECORDS,
    RepeatableAuditStore,
)


ERROR_CODE_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
SCENARIOS = {"minimal", "realistic", "frozen-limit"}
FROZEN_ACTIVE_MEASUREMENT_POINTS = 64
FROZEN_TOTAL_MEASUREMENT_POINT_RECORDS = 90
FROZEN_AUDIT_RUNS_PER_ASSESSMENT = 128
MAX_SCENARIO_ITERATIONS = {
    "minimal": 100,
    "realistic": 20,
    "frozen-limit": 1,
}


class ScenarioAbort(Exception):
    pass


def _percentile(values: List[float], percentile: int) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(
        0,
        int(
            __import__("math").ceil(
                (float(percentile) / 100.0) * len(ordered)
            )
        )
        - 1,
    )
    return float(ordered[index])


def _error_code(error: BaseException) -> str:
    if isinstance(error, BackendError):
        code = getattr(error, "code", None)
        if isinstance(code, str) and ERROR_CODE_PATTERN.match(code):
            return code
    return "unexpected_exception"


class OperationMetrics:
    def __init__(self):
        self.success_samples = {}  # type: Dict[str, List[float]]
        self.attempts = {}  # type: Dict[str, int]
        self.successes = {}  # type: Dict[str, int]
        self.expected_failures = {}  # type: Dict[str, int]
        self.failures = {}  # type: Dict[str, int]
        self.last_error_codes = {}  # type: Dict[str, str]

    def record(
        self,
        name: str,
        duration_ms: float,
        outcome: str,
        error_code: Optional[str] = None,
    ) -> None:
        self.attempts[name] = self.attempts.get(name, 0) + 1
        if outcome == "success":
            self.success_samples.setdefault(name, []).append(duration_ms)
        target = {
            "success": self.successes,
            "expected_failure": self.expected_failures,
            "failure": self.failures,
        }[outcome]
        target[name] = target.get(name, 0) + 1
        if error_code is not None:
            self.last_error_codes[name] = error_code

    def result(self) -> Dict[str, Any]:
        result = {}
        for name in sorted(self.attempts):
            values = self.success_samples.get(name, [])
            entry = {
                "attempts": self.attempts[name],
                "successes": self.successes.get(name, 0),
                "expected_failures": self.expected_failures.get(name, 0),
                "failures": self.failures.get(name, 0),
                "latency_basis": "successful_samples_only",
                "p50_ms": round(_percentile(values, 50), 3),
                "p95_ms": round(_percentile(values, 95), 3),
                "max_ms": round(max(values) if values else 0.0, 3),
            }
            if name in self.last_error_codes:
                entry["last_error_code"] = self.last_error_codes[name]
            result[name] = entry
        return result


def _required(
    metrics: OperationMetrics,
    violations: List[str],
    name: str,
    operation: Callable[[], Any],
) -> Any:
    started = time.monotonic_ns()
    try:
        value = operation()
    except BaseException as error:
        elapsed = (time.monotonic_ns() - started) / 1e6
        code = _error_code(error)
        metrics.record(name, elapsed, "failure", code)
        violations.append("operation_failed:{0}:{1}".format(name, code))
        raise ScenarioAbort()
    elapsed = (time.monotonic_ns() - started) / 1e6
    metrics.record(name, elapsed, "success")
    return value


def _expected_failure(
    metrics: OperationMetrics,
    violations: List[str],
    name: str,
    expected_code: str,
    operation: Callable[[], Any],
) -> None:
    started = time.monotonic_ns()
    try:
        operation()
    except BaseException as error:
        elapsed = (time.monotonic_ns() - started) / 1e6
        code = _error_code(error)
        if code == expected_code:
            metrics.record(name, elapsed, "expected_failure", code)
            return
        metrics.record(name, elapsed, "failure", code)
        violations.append(
            "unexpected_error_code:{0}:{1}".format(name, code)
        )
        raise ScenarioAbort()
    elapsed = (time.monotonic_ns() - started) / 1e6
    metrics.record(name, elapsed, "failure", "expected_failure_missing")
    violations.append("expected_failure_missing:{0}".format(name))
    raise ScenarioAbort()


def _utc_now() -> str:
    import datetime

    return (
        datetime.datetime.now(datetime.timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _current_revision(store: RepeatableAuditStore, assessment_id: str) -> int:
    return store.get(assessment_id, 0, 1)["revision"]


def _assurance_profile() -> Dict[str, Any]:
    return {
        "title": "Benchmark assurance",
        "description": "Deterministic workstation benchmark",
        "rules": [
            {
                "rule_id": "open_ssid_detected",
                "severity": "high",
                "enabled": True,
            }
        ],
    }


def _measurement_context() -> Dict[str, Any]:
    return {
        "location_id": "benchmark-site",
        "scan_profile_id": "saved-recon",
        "radio_profile_id": "benchmark-radio",
        "interface": "benchmark0",
        "declared_bands": ["2.4"],
        "declared_channels": [1, 6, 11],
        "scan_time": 180,
    }


def _measurement_profile_input() -> Dict[str, Any]:
    return {
        "name": "Benchmark measurement",
        "description": "Saved Recon benchmark profile",
        "location_id": "benchmark-site",
        "measurement_point_id": "benchmark-point",
        "scan_profile_id": "saved-recon",
        "radio_profile_id": "benchmark-radio",
        "interface": "benchmark0",
        "declared_bands": ["2.4"],
        "declared_channels": [1, 6, 11],
        "scan_time": 180,
        "is_default": True,
        "five_ghz_operator_confirmed": False,
    }


def _recon_scan() -> Dict[str, Any]:
    fixture = ROOT / "tests" / "fixtures" / "recon_basic.json"
    return json.loads(fixture.read_text(encoding="utf-8"))


def _scan_metadata(profile: Dict[str, Any], hour: int) -> Dict[str, Any]:
    version = profile["active_version"]
    return {
        "scan_id": "benchmark-scan-{0}".format(hour),
        "date": "2026-07-31T{0:02d}:00:00Z".format(hour),
        "scan_time": 180,
        "coverage": ["2.4"],
        "source": "hak5_recon",
        "measurement_context": {
            "location_id": "benchmark-site",
            "measurement_point_id": "benchmark-point",
            "scan_profile_id": "saved-recon",
            "radio_profile_id": "benchmark-radio",
            "interface": "benchmark0",
            "declared_bands": ["2.4"],
            "declared_channels": [1, 6, 11],
            "measurement_profile_id": profile["measurement_profile_id"],
            "measurement_profile_version_id": version["version_id"],
            "measurement_profile_digest": version["digest"],
        },
    }


def _inventory_csv() -> str:
    return (
        "site,ssid,bssid,vendor,role,approved,name,required_presence,"
        "allowed_encryption_codes,wps_allowed,allowed_channels,"
        "allowed_vendors,notes\n"
        "Benchmark,Example-Corp,AA:BB:CC:00:00:01,Unknown,corporate,"
        "true,AP1,true,5,true,1,,\n"
    )


def _prepare_native_artifacts(
    config_dir: str,
    metrics: OperationMetrics,
    violations: List[str],
) -> Dict[str, Any]:
    service = AssuranceService(config_dir=config_dir)
    measurement_profile = _required(
        metrics,
        violations,
        "create_measurement_profile",
        lambda: service.create_measurement_profile(
            _measurement_profile_input()
        )["measurement_profile"],
    )
    assessment = _required(
        metrics,
        violations,
        "create_assessment",
        lambda: service.create_assessment(
            {"name": "Benchmark", "location": "Lab", "notes": ""}
        ),
    )
    assessment_id = assessment["assessment_id"]
    baseline = _required(
        metrics,
        violations,
        "create_baseline",
        lambda: service.create_baseline_version(
            assessment_id,
            assessment["revision"],
            _recon_scan(),
            _scan_metadata(measurement_profile, 10),
            "Benchmark baseline",
        ),
    )
    assessment = _required(
        metrics,
        violations,
        "activate_baseline",
        lambda: service.store.activate_baseline_version(
            assessment_id,
            baseline["assessment"]["revision"],
            baseline["baseline_version"]["baseline_version_id"],
        )["assessment"],
    )
    inventory = _required(
        metrics,
        violations,
        "preview_inventory",
        lambda: service.preview_inventory_csv(_inventory_csv(), "comma"),
    )
    assurance = _required(
        metrics,
        violations,
        "create_assurance_profile",
        lambda: service.create_assurance_profile_version(
            assessment_id,
            assessment["revision"],
            "Benchmark inventory",
            inventory_preview=inventory,
            coverage_mode="partial",
        ),
    )
    assessment = _required(
        metrics,
        violations,
        "activate_assurance_profile",
        lambda: service.activate_assurance_profile_version(
            assessment_id,
            assurance["assessment"]["revision"],
            assurance["assurance_profile_version"][
                "assurance_profile_version_id"
            ],
            False,
        )["assessment"],
    )
    current_scan = _recon_scan()
    current_scan["APResults"][0]["channel"] = 6
    metadata = _scan_metadata(measurement_profile, 11)
    preview = _required(
        metrics,
        violations,
        "compare_recon",
        lambda: service.compare_recon(
            assessment_id, current_scan, metadata
        ),
    )
    persisted = _required(
        metrics,
        violations,
        "analyze_recon",
        lambda: service.analyze_recon(
            assessment_id,
            assessment["revision"],
            current_scan,
            metadata,
        ),
    )
    occurrence = service.store.get_occurrence_set(
        assessment_id, persisted["comparison"]["comparison_id"]
    )
    baseline_record = service.store.get_baseline_version(
        assessment_id,
        baseline["baseline_version"]["baseline_version_id"],
    )
    return {
        "store": RepeatableAuditStore(config_dir),
        "assessment_id": assessment_id,
        "source_recon_id": "benchmark-scan-11",
        "measurement_profile": measurement_profile,
        "assurance_profile_version_id": assurance[
            "assurance_profile_version"
        ]["assurance_profile_version_id"],
        "baseline": baseline_record,
        "preview": preview,
        "persisted": persisted,
        "occurrence": occurrence,
    }


def _prepare_additional_native_artifact(
    config_dir: str,
    native: Dict[str, Any],
    index: int,
    metrics: OperationMetrics,
    violations: List[str],
) -> Dict[str, Any]:
    service = AssuranceService(config_dir=config_dir)
    assessment_id = native["assessment_id"]
    current_scan = json.loads(json.dumps(_recon_scan()))
    current_scan["APResults"][0]["channel"] = [1, 6, 11][index % 3]
    current_scan["APResults"][0]["signal"] = -41 - index
    current_scan["APResults"][0]["last_seen"] = (
        "2026-07-31T{0:02d}:00:00Z".format(11 + index)
    )
    metadata = _scan_metadata(native["measurement_profile"], 11 + index)
    preview = _required(
        metrics,
        violations,
        "compare_recon",
        lambda: service.compare_recon(
            assessment_id, current_scan, metadata
        ),
    )
    persisted = _required(
        metrics,
        violations,
        "analyze_recon",
        lambda: service.analyze_recon(
            assessment_id,
            service.store.get(assessment_id, 0, 1)["revision"],
            current_scan,
            metadata,
        ),
    )
    occurrence = service.store.get_occurrence_set(
        assessment_id, persisted["comparison"]["comparison_id"]
    )
    return {
        "store": RepeatableAuditStore(config_dir),
        "assessment_id": assessment_id,
        "source_recon_id": metadata["scan_id"],
        "measurement_profile": native["measurement_profile"],
        "assurance_profile_version_id": native[
            "assurance_profile_version_id"
        ],
        "baseline": native["baseline"],
        "preview": preview,
        "persisted": persisted,
        "occurrence": occurrence,
    }


def _resolved_outcome(native: Dict[str, Any]) -> Dict[str, Any]:
    snapshot = native["preview"]["current_snapshot"]
    baseline = native["baseline"]
    pins = native["persisted"]["comparison"]["pinned_versions"]
    record = {
        key: value
        for key, value in baseline.items()
        if key not in {"snapshot", "is_active", "baseline_type", "legacy"}
    }
    return {
        "status": "resolved",
        "source_recon_id": native["source_recon_id"],
        "snapshot_id": snapshot["snapshot_id"],
        "snapshot_digest": snapshot["snapshot_digest"],
        "measurement_profile_id": pins["measurement_profile_id"],
        "measurement_profile_version_id": pins[
            "measurement_profile_version_id"
        ],
        "measurement_profile_digest": pins["measurement_profile_digest"],
        "baseline_version_id": pins["baseline_version_id"],
        "baseline_type": "single_scan",
        "baseline_snapshot_id": baseline["snapshot_id"],
        "baseline_snapshot_digest": baseline["snapshot_digest"],
        "baseline_record_digest": _canonical_digest(record),
        "assurance_profile_version_id": pins[
            "assurance_profile_version_id"
        ],
        "assurance_profile_digest": pins["assurance_profile_digest"],
        "comparability_status": native["preview"]["diff"][
            "comparability"
        ]["status"],
        "resolved_at": _utc_now(),
    }


def _completed_outcome(native: Dict[str, Any]) -> Dict[str, Any]:
    comparison = native["persisted"]["comparison"]
    evidence_ids = [
        item["evidence_id"] for item in native["occurrence"]["evidence"]
    ][:100]
    return {
        "status": "completed",
        "comparison_id": comparison["comparison_id"],
        "comparison_digest": _canonical_digest(comparison),
        "occurrence_set_id": comparison["occurrence_set_id"],
        "evidence_ids": evidence_ids,
        "completed_at": _utc_now(),
    }


def _tree_snapshot(root: Path) -> Dict[str, int]:
    result = {}
    if not root.exists():
        return result
    for current, directories, files in os.walk(str(root), followlinks=False):
        current_path = Path(current)
        for name in list(directories):
            path = current_path / name
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(
                metadata.st_mode
            ):
                raise ScenarioAbort()
        for name in files:
            path = current_path / name
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(
                metadata.st_mode
            ):
                raise ScenarioAbort()
            result[path.relative_to(root).as_posix()] = metadata.st_size
    return result


def _proc_io() -> Optional[Dict[str, int]]:
    path = Path("/proc/self/io")
    if not path.is_file():
        return None
    try:
        values = {}
        for line in path.read_text(encoding="ascii").splitlines():
            key, raw = line.split(":", 1)
            if key in {"write_bytes", "syscw"}:
                values[key] = int(raw.strip())
        if set(values) != {"write_bytes", "syscw"}:
            return None
        return values
    except (OSError, UnicodeError, ValueError):
        return None


def _rss_mib() -> float:
    try:
        for line in Path("/proc/self/status").read_text(
            encoding="ascii"
        ).splitlines():
            if line.startswith("VmRSS:"):
                return float(line.split()[1]) / 1024.0
    except (OSError, UnicodeError, ValueError):
        pass
    return 0.0


def _peak_rss_mib() -> float:
    try:
        for line in Path("/proc/self/status").read_text(
            encoding="ascii"
        ).splitlines():
            if line.startswith("VmHWM:"):
                return float(line.split()[1]) / 1024.0
    except (OSError, UnicodeError, ValueError):
        pass
    return _rss_mib()


def _document_sizes(config_root: Path) -> Dict[str, int]:
    categories = {
        "measurement_points_max": 0,
        "audit_run_max": 0,
        "audit_run_manifest_max": 0,
        "events_max": 0,
        "document_max": 0,
    }
    for current, directories, files in os.walk(
        str(config_root), followlinks=False
    ):
        current_path = Path(current)
        for name in list(directories):
            metadata = (current_path / name).lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise ScenarioAbort()
        for name in files:
            path = current_path / name
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(
                metadata.st_mode
            ):
                raise ScenarioAbort()
            size = metadata.st_size
            categories["document_max"] = max(
                categories["document_max"], size
            )
            if name == "measurement_points.json":
                categories["measurement_points_max"] = max(
                    categories["measurement_points_max"], size
                )
            elif name == "audit_runs_manifest.json":
                categories["audit_run_manifest_max"] = max(
                    categories["audit_run_manifest_max"], size
                )
            elif name == "events.jsonl":
                categories["events_max"] = max(
                    categories["events_max"], size
                )
            elif (
                current_path.name == "audit_runs"
                and name.startswith("ar_")
                and name.endswith(".json")
            ):
                categories["audit_run_max"] = max(
                    categories["audit_run_max"], size
                )
    return categories


def _transaction_residue(config_root: Path) -> int:
    residue = 0
    for path in config_root.rglob(".transactions"):
        if path.is_symlink() or not path.is_dir():
            raise ScenarioAbort()
        residue += sum(1 for _entry in path.iterdir())
    return residue


def _capacity_snapshot(
    store: RepeatableAuditStore,
    assessment_id: str,
    capacity: Dict[str, Any],
    metrics: OperationMetrics,
    violations: List[str],
) -> Dict[str, Any]:
    points = _required(
        metrics,
        violations,
        "capacity_measurement_points",
        lambda: store.list_measurement_points(
            assessment_id, include_archived=True, limit=100, offset=0
        ),
    )
    runs = _required(
        metrics,
        violations,
        "capacity_audit_runs",
        lambda: store.list_audit_runs(
            assessment_id, limit=100, offset=0
        ),
    )
    result = dict(capacity)
    result.update(
        {
            "measurement_point_active_limit": (
                MAX_ACTIVE_MEASUREMENT_POINTS
            ),
            "measurement_point_active_used": sum(
                1
                for point in points["measurement_points"]
                if point["status"] == "active"
            ),
            "measurement_point_total_limit": (
                MAX_TOTAL_MEASUREMENT_POINT_RECORDS
            ),
            "measurement_point_total_used": points["total"],
            "audit_run_limit": MAX_AUDIT_RUNS_PER_ASSESSMENT,
            "audit_run_used": runs["total"],
        }
    )
    return result


def _minimal_workload(
    config_dir: str,
    metrics: OperationMetrics,
    violations: List[str],
) -> Tuple[Dict[str, Any], Dict[str, Optional[float]]]:
    ensure_pseudonymization_key(config_dir)
    store = RepeatableAuditStore(config_dir)
    assessment = _required(
        metrics,
        violations,
        "create_assessment",
        lambda: store.create(
            {"name": "Minimal", "location": "Lab", "notes": ""}
        ),
    )
    aid = assessment["assessment_id"]
    profile = _required(
        metrics,
        violations,
        "create_assurance_profile",
        lambda: store.create_assurance_profile_version(
            aid, 1, _assurance_profile()
        ),
    )
    version_id = profile["assurance_profile_version"][
        "assurance_profile_version_id"
    ]
    _required(
        metrics,
        violations,
        "activate_assurance_profile",
        lambda: store.activate_assurance_profile_version(
            aid, 2, version_id
        ),
    )
    point = _required(
        metrics,
        violations,
        "create_measurement_point",
        lambda: store.create_measurement_point(
            aid, 3, _measurement_context(), "Point"
        ),
    )
    point_id = point["measurement_point"]["measurement_point_id"]
    audit = _required(
        metrics,
        violations,
        "create_audit_run",
        lambda: store.create_audit_run(
            aid, 4, "Run", version_id, [point_id]
        ),
    )
    run = audit["audit_run"]
    started = _required(
        metrics,
        violations,
        "start_audit_run",
        lambda: store.start_audit_run(
            aid, 5, run["audit_run_id"], run["revision"]
        ),
    )
    _required(
        metrics,
        violations,
        "cancel_audit_run",
        lambda: store.cancel_audit_run(
            aid,
            6,
            run["audit_run_id"],
            started["audit_run"]["revision"],
        ),
    )
    reopened_started = time.monotonic_ns()
    reopened = RepeatableAuditStore(config_dir)
    _required(
        metrics,
        violations,
        "reopen_read",
        lambda: reopened.get_audit_run(aid, run["audit_run_id"]),
    )
    reopen_ms = (time.monotonic_ns() - reopened_started) / 1e6

    armed = [True]

    def fault(stage, _index):
        if armed[0] and stage == "prepared":
            armed[0] = False
            raise RuntimeError("benchmark fault")

    crashing = RepeatableAuditStore(config_dir, fault_injector=fault)
    before_recovery = reopened.get(aid, 0, 1)
    expected_recovery_revision = before_recovery["revision"] + 1
    expected_recovery_event_sequence = (
        before_recovery["last_event_sequence"] + 1
    )
    try:
        crashing.update(
            aid,
            before_recovery["revision"],
            {"name": "Recovered"},
        )
        violations.append("fault_injection_missing")
    except RuntimeError:
        pass
    except BaseException as error:
        violations.append(
            "fault_injection_error:{0}".format(_error_code(error))
        )
    recovery_started = time.monotonic_ns()
    recovered = RepeatableAuditStore(config_dir)
    recovered_assessment = _required(
        metrics,
        violations,
        "recovery_read",
        lambda: recovered.get(
            aid, expected_recovery_event_sequence - 1, 1
        ),
    )
    recovery_ms = (time.monotonic_ns() - recovery_started) / 1e6
    if (
        recovered_assessment.get("name") != "Recovered"
        or recovered_assessment.get("revision")
        != expected_recovery_revision
        or recovered_assessment.get("last_event_sequence")
        != expected_recovery_event_sequence
        or not recovered_assessment.get("events")
        or recovered_assessment["events"][-1].get("event_type")
        != "assessment_updated"
    ):
        violations.append("recovery_state_mismatch")
    if _transaction_residue(Path(config_dir)):
        violations.append("recovery_transaction_residue")
    capacity = _required(
        metrics,
        violations,
        "capacity",
        lambda: recovered.get_assessment_capacity(aid),
    )
    capacity = _capacity_snapshot(
        recovered, aid, capacity, metrics, violations
    )
    return capacity, {
        "reopen_ms": reopen_ms,
        "recovery_ms": recovery_ms,
    }


def _realistic_workload(
    config_dir: str,
    metrics: OperationMetrics,
    violations: List[str],
) -> Tuple[Dict[str, Any], Dict[str, Optional[float]]]:
    native = _prepare_native_artifacts(config_dir, metrics, violations)
    native_artifacts = [native]
    for index in range(1, 8):
        native_artifacts.append(
            _prepare_additional_native_artifact(
                config_dir, native, index, metrics, violations
            )
        )
    if len(
        {
            item["persisted"]["comparison"]["comparison_id"]
            for item in native_artifacts
        }
    ) != 8:
        violations.append("realistic_comparison_reuse")
    store = native["store"]
    aid = native["assessment_id"]
    version_id = native["assurance_profile_version_id"]
    point_ids = []
    for _index in range(8):
        point = _required(
            metrics,
            violations,
            "create_measurement_point",
            lambda: store.create_measurement_point(
                aid,
                _current_revision(store, aid),
                _measurement_context(),
                "Point",
            ),
        )
        point_ids.append(point["measurement_point"]["measurement_point_id"])
    audit = _required(
        metrics,
        violations,
        "create_audit_run",
        lambda: store.create_audit_run(
            aid,
            _current_revision(store, aid),
            "Realistic run",
            version_id,
            point_ids,
        ),
    )
    run = audit["audit_run"]
    started = _required(
        metrics,
        violations,
        "start_audit_run",
        lambda: store.start_audit_run(
            aid,
            _current_revision(store, aid),
            run["audit_run_id"],
            run["revision"],
        ),
    )
    run_revision = started["audit_run"]["revision"]
    for point_id, artifact in zip(point_ids, native_artifacts):
        resolved = _required(
            metrics,
            violations,
            "resolve_measurement",
            lambda point_id=point_id, run_revision=run_revision: (
                store.resolve_audit_measurement(
                    aid,
                    _current_revision(store, aid),
                    run["audit_run_id"],
                    run_revision,
                    point_id,
                    _resolved_outcome(artifact),
                )
            ),
        )
        run_revision = resolved["audit_run"]["revision"]
        completed = _required(
            metrics,
            violations,
            "save_comparison",
            lambda point_id=point_id, run_revision=run_revision: (
                store.save_audit_measurement_comparison(
                    aid,
                    _current_revision(store, aid),
                    run["audit_run_id"],
                    run_revision,
                    point_id,
                    _completed_outcome(artifact),
                )
            ),
        )
        run_revision = completed["audit_run"]["revision"]
    completed_run = _required(
        metrics,
        violations,
        "complete_audit_run",
        lambda: store.complete_audit_run(
            aid,
            _current_revision(store, aid),
            run["audit_run_id"],
            run_revision,
        ),
    )
    reopened_started = time.monotonic_ns()
    reopened = RepeatableAuditStore(config_dir)
    reopened_run = _required(
        metrics,
        violations,
        "reopen_read",
        lambda: reopened.get_audit_run(aid, run["audit_run_id"]),
    )
    reopen_ms = (time.monotonic_ns() - reopened_started) / 1e6
    if (
        completed_run["audit_run"].get("status") != "completed"
        or reopened_run["audit_run"].get("status") != "completed"
        or len(reopened_run.get("measurements", [])) != 8
        or any(
            measurement.get("status") != "completed"
            for measurement in reopened_run.get("measurements", [])
        )
    ):
        violations.append("realistic_completed_state_mismatch")
    capacity = _required(
        metrics,
        violations,
        "capacity",
        lambda: reopened.get_assessment_capacity(aid),
    )
    capacity = _capacity_snapshot(
        reopened, aid, capacity, metrics, violations
    )
    return capacity, {
        "reopen_ms": reopen_ms,
        "recovery_ms": None,
    }


def _frozen_limit_workload(
    config_dir: str,
    metrics: OperationMetrics,
    violations: List[str],
) -> Tuple[Dict[str, Any], Dict[str, Optional[float]]]:
    if (
        MAX_ACTIVE_MEASUREMENT_POINTS
        != FROZEN_ACTIVE_MEASUREMENT_POINTS
        or MAX_TOTAL_MEASUREMENT_POINT_RECORDS
        != FROZEN_TOTAL_MEASUREMENT_POINT_RECORDS
        or MAX_AUDIT_RUNS_PER_ASSESSMENT
        != FROZEN_AUDIT_RUNS_PER_ASSESSMENT
    ):
        violations.append("frozen_limit_constant_drift")
        raise ScenarioAbort()
    ensure_pseudonymization_key(config_dir)
    store = RepeatableAuditStore(config_dir)
    assessment = _required(
        metrics,
        violations,
        "create_assessment",
        lambda: store.create(
            {"name": "Frozen limits", "location": "Lab", "notes": ""}
        ),
    )
    aid = assessment["assessment_id"]
    profile = _required(
        metrics,
        violations,
        "create_assurance_profile",
        lambda: store.create_assurance_profile_version(
            aid, 1, _assurance_profile()
        ),
    )
    version_id = profile["assurance_profile_version"][
        "assurance_profile_version_id"
    ]
    _required(
        metrics,
        violations,
        "activate_assurance_profile",
        lambda: store.activate_assurance_profile_version(
            aid, 2, version_id
        ),
    )
    revision = 3
    points = []
    for _index in range(MAX_ACTIVE_MEASUREMENT_POINTS):
        point = _required(
            metrics,
            violations,
            "create_measurement_point",
            lambda revision=revision: store.create_measurement_point(
                aid, revision, _measurement_context(), "Point"
            ),
        )
        points.append(point["measurement_point"])
        revision += 1
    _expected_failure(
        metrics,
        violations,
        "active_point_limit",
        "storage_limit_exceeded",
        lambda: store.create_measurement_point(
            aid, revision, _measurement_context(), "Point"
        ),
    )

    for point in points[:-1]:
        _required(
            metrics,
            violations,
            "archive_measurement_point",
            lambda point=point, revision=revision: (
                store.archive_measurement_point(
                    aid,
                    revision,
                    point["measurement_point_id"],
                    point["revision"],
                )
            ),
        )
        revision += 1
    for _index in range(
        MAX_TOTAL_MEASUREMENT_POINT_RECORDS
        - MAX_ACTIVE_MEASUREMENT_POINTS
    ):
        point = _required(
            metrics,
            violations,
            "create_measurement_point",
            lambda revision=revision: store.create_measurement_point(
                aid, revision, _measurement_context(), "Point"
            ),
        )["measurement_point"]
        revision += 1
        _required(
            metrics,
            violations,
            "archive_measurement_point",
            lambda point=point, revision=revision: (
                store.archive_measurement_point(
                    aid,
                    revision,
                    point["measurement_point_id"],
                    point["revision"],
                )
            ),
        )
        revision += 1
    _expected_failure(
        metrics,
        violations,
        "total_point_limit",
        "storage_limit_exceeded",
        lambda: store.create_measurement_point(
            aid, revision, _measurement_context(), "Point"
        ),
    )

    active_point_id = points[-1]["measurement_point_id"]
    for _index in range(MAX_AUDIT_RUNS_PER_ASSESSMENT):
        _required(
            metrics,
            violations,
            "create_audit_run",
            lambda revision=revision: store.create_audit_run(
                aid,
                revision,
                "Run",
                version_id,
                [active_point_id],
            ),
        )
        revision += 1
    _expected_failure(
        metrics,
        violations,
        "audit_run_limit",
        "storage_limit_exceeded",
        lambda: store.create_audit_run(
            aid,
            revision,
            "Run",
            version_id,
            [active_point_id],
        ),
    )
    reopened_started = time.monotonic_ns()
    reopened = RepeatableAuditStore(config_dir)
    listed = _required(
        metrics,
        violations,
        "reopen_read",
        lambda: reopened.list_audit_runs(aid, limit=100, offset=0),
    )
    if listed["total"] != MAX_AUDIT_RUNS_PER_ASSESSMENT:
        violations.append("frozen_run_count_mismatch")
    points_after = _required(
        metrics,
        violations,
        "reopen_measurement_points",
        lambda: reopened.list_measurement_points(
            aid, include_archived=True, limit=100, offset=0
        ),
    )
    active_after = sum(
        1
        for point in points_after["measurement_points"]
        if point["status"] == "active"
    )
    if (
        points_after["total"] != MAX_TOTAL_MEASUREMENT_POINT_RECORDS
        or active_after != 1
    ):
        violations.append("frozen_measurement_point_count_mismatch")
    manifest_path = (
        Path(config_dir)
        / "assessments"
        / aid
        / "audit_runs_manifest.json"
    )
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        violations.append("frozen_manifest_unreadable")
        manifest = {}
    runs_map = manifest.get("runs")
    if (
        not isinstance(runs_map, dict)
        or len(runs_map) != MAX_AUDIT_RUNS_PER_ASSESSMENT
        or manifest.get("active_closure_reserve")
        != MAX_AUDIT_RUNS_PER_ASSESSMENT
        or set(runs_map.values()) != {"draft"}
    ):
        violations.append("frozen_manifest_state_mismatch")
    capacity = _required(
        metrics,
        violations,
        "capacity",
        lambda: reopened.get_assessment_capacity(aid),
    )
    capacity = _capacity_snapshot(
        reopened, aid, capacity, metrics, violations
    )
    return capacity, {
        "reopen_ms": (time.monotonic_ns() - reopened_started) / 1e6,
        "recovery_ms": None,
    }


def run_repeatable_store_benchmark(
    scenario: str = "minimal", iterations: int = 1
) -> Dict[str, Any]:
    if scenario not in SCENARIOS or not isinstance(iterations, int) or (
        isinstance(iterations, bool)
        or iterations < 1
        or (
            scenario in MAX_SCENARIO_ITERATIONS
            and iterations > MAX_SCENARIO_ITERATIONS[scenario]
        )
    ):
        return {
            "schema_version": "1.0",
            "mode": "repeatable-store",
            "scenario": scenario,
            "iterations": iterations,
            "validation_scope": "workstation_software_only",
            "hardware_validated": False,
            "protocol_validated": False,
            "performance_thresholds_applied": False,
            "operations": {},
            "violations": ["invalid_benchmark_arguments"],
            "functional_workload_passed": False,
            "passed": False,
        }

    metrics = OperationMetrics()
    violations = []  # type: List[str]
    workload_ms = []  # type: List[float]
    reopen_ms = []  # type: List[float]
    recovery_ms = []  # type: List[float]
    final_logical_bytes = []  # type: List[float]
    final_file_counts = []  # type: List[float]
    max_documents = {}  # type: Dict[str, int]
    final_capacity_snapshot = None
    rss_before = _rss_mib()
    io_before = _proc_io()

    workload = {
        "minimal": _minimal_workload,
        "realistic": _realistic_workload,
        "frozen-limit": _frozen_limit_workload,
    }[scenario]
    for _iteration in range(iterations):
        with tempfile.TemporaryDirectory(
            prefix="pineai-repeatable-benchmark-"
        ) as directory:
            config_root = Path(directory) / "config"
            started = time.monotonic_ns()
            scenario_succeeded = False
            try:
                capacity, lifecycle_timings = workload(
                    str(config_root), metrics, violations
                )
                final_capacity_snapshot = capacity
                reopen_value = lifecycle_timings.get("reopen_ms")
                recovery_value = lifecycle_timings.get("recovery_ms")
                if reopen_value is not None:
                    reopen_ms.append(float(reopen_value))
                if recovery_value is not None:
                    recovery_ms.append(float(recovery_value))
                scenario_succeeded = True
            except ScenarioAbort:
                violations.append("scenario_aborted")
            except BaseException as error:
                violations.append(
                    "scenario_failed:{0}".format(_error_code(error))
                )
            if scenario_succeeded:
                workload_ms.append(
                    (time.monotonic_ns() - started) / 1e6
                )
            try:
                after = _tree_snapshot(config_root)
                final_logical_bytes.append(float(sum(after.values())))
                final_file_counts.append(float(len(after)))
                sizes = _document_sizes(config_root)
                for name, size in sizes.items():
                    max_documents[name] = max(
                        max_documents.get(name, 0), size
                    )
                residue = _transaction_residue(config_root)
                if residue:
                    violations.append("transaction_residue")
            except ScenarioAbort:
                violations.append("unsafe_filesystem_entry")

    steady_rss = _rss_mib()
    peak_rss = _peak_rss_mib()
    io_after = _proc_io()
    io_result = None
    if io_before is not None and io_after is not None:
        io_result = {
            "scope": "benchmark_process_delta_including_runtime",
            "write_bytes": max(
                0, io_after["write_bytes"] - io_before["write_bytes"]
            ),
            "write_syscalls": max(
                0, io_after["syscw"] - io_before["syscw"]
            ),
        }
    unique_violations = sorted(set(violations))
    functional_passed = not unique_violations
    return {
        "schema_version": "1.0",
        "mode": "repeatable-store",
        "scenario": scenario,
        "iterations": iterations,
        "validation_scope": "workstation_software_only",
        "hardware_validated": False,
        "protocol_validated": False,
        "performance_thresholds_applied": False,
        "operations": metrics.result(),
        "workload_ms": {
            "p50": round(_percentile(workload_ms, 50), 3),
            "p95": round(_percentile(workload_ms, 95), 3),
            "max": round(max(workload_ms or [0.0]), 3),
        },
        "reopen_ms": {
            "p50": round(_percentile(reopen_ms, 50), 3),
            "p95": round(_percentile(reopen_ms, 95), 3),
            "max": round(max(reopen_ms or [0.0]), 3),
        },
        "recovery_ms": {
            "p50": round(_percentile(recovery_ms, 50), 3),
            "p95": round(_percentile(recovery_ms, 95), 3),
            "max": round(max(recovery_ms or [0.0]), 3),
            "samples": len(recovery_ms),
        },
        "rss_mib": {
            "before": round(rss_before, 2),
            "steady": round(steady_rss, 2),
            "steady_delta": round(steady_rss - rss_before, 2),
            "process_lifetime_peak": round(peak_rss, 2),
        },
        "process_io": io_result,
        "logical_filesystem": {
            "final_bytes": {
                "p50": int(_percentile(final_logical_bytes, 50)),
                "p95": int(_percentile(final_logical_bytes, 95)),
                "max": int(max(final_logical_bytes or [0.0])),
            },
            "final_file_count": {
                "p50": int(_percentile(final_file_counts, 50)),
                "p95": int(_percentile(final_file_counts, 95)),
                "max": int(max(final_file_counts or [0.0])),
            },
        },
        "document_sizes": dict(sorted(max_documents.items())),
        "final_capacity_snapshot": final_capacity_snapshot,
        "violations": unique_violations,
        "functional_workload_passed": functional_passed,
        "passed": functional_passed,
    }
