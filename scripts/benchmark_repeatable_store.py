#!/usr/bin/env python3
"""Workstation-only PineAssure RepeatableAuditStore benchmarks.

The workloads use the production v0.7 split-document store and immutable
MeasurementPoint, MeasurementProfile, baseline, and AssuranceProfile pins.
Results are observational software measurements.  They are not Mark VII
hardware calibration or proof of Hak5 runtime protocol compatibility.
"""

import datetime
import json
import math
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

from pineai_backend import __version__  # noqa: E402
from pineai_backend.assurance_service import AssuranceService  # noqa: E402
from pineai_backend.config import ensure_pseudonymization_key  # noqa: E402
from pineai_backend.customer_analysis import evidence_records  # noqa: E402
from pineai_backend.errors import BackendError  # noqa: E402
from pineai_backend.repeatable_audit_store import (  # noqa: E402
    MAX_ACTIVE_MEASUREMENT_POINTS,
    MAX_AUDIT_RUNS_PER_ASSESSMENT,
    MAX_MEASUREMENT_POINTS_PER_RUN,
    MAX_TOTAL_MEASUREMENT_POINT_RECORDS,
    RepeatableAuditStore,
)


ERROR_CODE_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
SCENARIOS = {"minimal", "realistic", "frozen-limit"}
FROZEN_ACTIVE_MEASUREMENT_POINTS = 16
FROZEN_TOTAL_MEASUREMENT_POINT_RECORDS = 32
FROZEN_MEASUREMENTS_PER_RUN = 16
FROZEN_AUDIT_RUNS_PER_ASSESSMENT = 32
MAX_SCENARIO_ITERATIONS = {
    "minimal": 100,
    "realistic": 20,
    "frozen-limit": 1,
}


class ScenarioAbort(Exception):
    """Stop a workload after recording a fixed-code violation."""


def _percentile(values: List[float], percentile: int) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(
        0,
        int(math.ceil((float(percentile) / 100.0) * len(ordered))) - 1,
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
        violations.append("unexpected_error_code:{0}:{1}".format(name, code))
        raise ScenarioAbort()
    elapsed = (time.monotonic_ns() - started) / 1e6
    metrics.record(name, elapsed, "failure", "expected_failure_missing")
    violations.append("expected_failure_missing:{0}".format(name))
    raise ScenarioAbort()


def _utc_now() -> str:
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _fixture_time(index: int) -> str:
    start = datetime.datetime(
        2026, 7, 31, 8, 0, 0, tzinfo=datetime.timezone.utc
    )
    return (start + datetime.timedelta(minutes=index)).isoformat().replace(
        "+00:00", "Z"
    )


def _current_revision(store: RepeatableAuditStore, assessment_id: str) -> int:
    return store.get(assessment_id, 0, 1)["revision"]


def _measurement_profile_input() -> Dict[str, Any]:
    return {
        "name": "Benchmark measurement",
        "description": "Saved Recon benchmark profile",
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


def _scan_metadata(
    assessment_id: str,
    point_id: str,
    measurement_profile: Dict[str, Any],
    index: int,
) -> Dict[str, Any]:
    version = measurement_profile["active_version"]
    return {
        "scan_id": "benchmark-scan-{0:03d}".format(index),
        "date": _fixture_time(index),
        "scan_time": 180,
        "coverage": ["2.4"],
        "source": "hak5_recon",
        "measurement_context": {
            "location_id": assessment_id,
            "measurement_point_id": point_id,
            "scan_profile_id": "saved-recon",
            "radio_profile_id": "benchmark-radio",
            "interface": "benchmark0",
            "declared_bands": ["2.4"],
            "declared_channels": [1, 6, 11],
            "measurement_profile_id": measurement_profile[
                "measurement_profile_id"
            ],
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


def _prepare_native_environment(
    config_dir: str,
    point_count: int,
    metrics: OperationMetrics,
    violations: List[str],
) -> Dict[str, Any]:
    ensure_pseudonymization_key(config_dir)
    service = AssuranceService(config_dir=config_dir)
    store = RepeatableAuditStore(config_dir)
    profile = _required(
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
        lambda: store.create(
            {"name": "Benchmark", "location": "Lab", "notes": ""}
        ),
    )
    assessment_id = assessment["assessment_id"]
    points = []
    baselines = []
    for index in range(point_count):
        point = _required(
            metrics,
            violations,
            "create_measurement_point",
            lambda index=index: store.create_measurement_point(
                assessment_id,
                _current_revision(store, assessment_id),
                "Benchmark point {0}".format(index + 1),
                "Fixed workstation workload point",
                "Load an existing saved Recon result",
            ),
        )["measurement_point"]
        points.append(point)
        baseline = _required(
            metrics,
            violations,
            "create_baseline",
            lambda index=index, point=point: service.create_baseline_version(
                assessment_id,
                _current_revision(store, assessment_id),
                _recon_scan(),
                _scan_metadata(
                    assessment_id,
                    point["measurement_point_id"],
                    profile,
                    index,
                ),
                "Benchmark baseline {0}".format(index + 1),
            ),
        )["baseline_version"]
        baselines.append(baseline)

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
            _current_revision(store, assessment_id),
            "Benchmark inventory",
            inventory_preview=inventory,
            coverage_mode="partial",
        ),
    )["assurance_profile_version"]
    return {
        "service": service,
        "store": store,
        "assessment_id": assessment_id,
        "measurement_profile": profile,
        "measurement_points": points,
        "baselines": baselines,
        "assurance_profile": assurance,
    }


def _assignments(native: Dict[str, Any]) -> List[Dict[str, str]]:
    profile = native["measurement_profile"]
    version = profile["active_version"]
    return [
        {
            "measurement_point_id": point["measurement_point_id"],
            "measurement_profile_id": profile["measurement_profile_id"],
            "measurement_profile_version_id": version["version_id"],
            "baseline_version_id": baseline["baseline_version_id"],
        }
        for point, baseline in zip(
            native["measurement_points"], native["baselines"]
        )
    ]


def _audit_run_input(
    native: Dict[str, Any], name: str, assignments: List[Dict[str, str]]
) -> Dict[str, Any]:
    return {
        "name": name,
        "description": "Deterministic workstation benchmark",
        "due_at": None,
        "assurance_profile_version_id": native["assurance_profile"][
            "assurance_profile_version_id"
        ],
        "assignments": assignments,
    }


def _occurrence_input(preview: Dict[str, Any]) -> Dict[str, Any]:
    baseline = preview["baseline"]
    limitations = list(
        baseline.get("baseline_model", {}).get("limitation_codes", [])
    )
    if baseline.get("legacy"):
        limitations.append("legacy_single_scan_baseline")
    return {
        "observed_changes": preview["observed_changes"],
        "inventory_reconciliation": preview["inventory_reconciliation"],
        "policy_deviations": preview["policy_deviations"],
        "security_findings": preview["security_findings"],
        "policy_evaluation_status": preview["policy_evaluation_status"],
        "lifecycle_findings": preview["lifecycle_findings"],
        "evidence": evidence_records(
            baseline, preview["current_snapshot"]
        ),
        "quality_factors": preview["diff"]["comparability"].get(
            "quality_factors", []
        ),
        "policy_reference": {
            "assurance_profile_version_id": preview["pinned_versions"].get(
                "assurance_profile_version_id"
            ),
            "assurance_profile_digest": preview["pinned_versions"].get(
                "assurance_profile_digest"
            ),
        },
        "limitations": sorted(set(limitations)),
    }


def _current_snapshot_and_preview(
    native: Dict[str, Any], measurement: Dict[str, Any], index: int
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    scan = _recon_scan()
    scan["APResults"][0]["channel"] = [1, 6, 11][index % 3]
    scan["APResults"][0]["signal"] = -41 - index
    scan["APResults"][0]["last_seen"] = _fixture_time(100 + index)
    metadata = _scan_metadata(
        native["assessment_id"],
        measurement["measurement_point_id"],
        native["measurement_profile"],
        100 + index,
    )
    snapshot = native["service"].resolve_recon(scan, metadata)["snapshot"]
    preview = native["service"].comparison_for_pinned_versions(
        native["assessment_id"],
        snapshot,
        measurement["baseline_version_id"],
        measurement["assurance_profile_version_id"],
        measurement["measurement_profile_id"],
        measurement["measurement_profile_version_id"],
        measurement["measurement_profile_digest"],
    )
    return snapshot, preview


def _tree_snapshot(root: Path) -> Dict[str, int]:
    result = {}
    if not root.exists():
        return result
    for current, directories, files in os.walk(str(root), followlinks=False):
        current_path = Path(current)
        for name in list(directories):
            metadata = (current_path / name).lstat()
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
        return values if set(values) == {"write_bytes", "syscw"} else None
    except (OSError, UnicodeError, ValueError):
        return None


def _rss_mib(kind: str = "VmRSS:") -> float:
    try:
        for line in Path("/proc/self/status").read_text(
            encoding="ascii"
        ).splitlines():
            if line.startswith(kind):
                return float(line.split()[1]) / 1024.0
    except (OSError, UnicodeError, ValueError):
        pass
    return 0.0


def _document_sizes(config_root: Path) -> Dict[str, int]:
    categories = {
        "measurement_points_max": 0,
        "audit_run_index_max": 0,
        "audit_run_manifest_max": 0,
        "audit_measurement_max": 0,
        "events_max": 0,
        "document_max": 0,
    }
    for current, directories, files in os.walk(
        str(config_root), followlinks=False
    ):
        current_path = Path(current)
        for name in list(directories):
            if (current_path / name).is_symlink():
                raise ScenarioAbort()
        for name in files:
            path = current_path / name
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(
                metadata.st_mode
            ):
                raise ScenarioAbort()
            size = metadata.st_size
            categories["document_max"] = max(categories["document_max"], size)
            if name == "measurement_points.json":
                key = "measurement_points_max"
            elif name == "audit_runs_manifest.json":
                key = "audit_run_index_max"
            elif name == "manifest.json" and current_path.name.startswith("ar_"):
                key = "audit_run_manifest_max"
            elif current_path.name == "measurements" and name.endswith(".json"):
                key = "audit_measurement_max"
            elif name == "events.jsonl":
                key = "events_max"
            else:
                continue
            categories[key] = max(categories[key], size)
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
    metrics: OperationMetrics,
    violations: List[str],
) -> Dict[str, Any]:
    capacity = _required(
        metrics,
        violations,
        "capacity",
        lambda: store.get_assessment_capacity(assessment_id),
    )
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
        lambda: store.list_audit_runs(assessment_id, limit=100, offset=0),
    )
    result = dict(capacity)
    result.update(
        {
            "measurement_point_active_limit": MAX_ACTIVE_MEASUREMENT_POINTS,
            "measurement_point_active_used": sum(
                1
                for point in points["measurement_points"]
                if point["status"] == "active"
            ),
            "measurement_point_total_limit": (
                MAX_TOTAL_MEASUREMENT_POINT_RECORDS
            ),
            "measurement_point_total_used": points["total"],
            "assignments_per_run_limit": MAX_MEASUREMENT_POINTS_PER_RUN,
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
    native = _prepare_native_environment(config_dir, 1, metrics, violations)
    store = native["store"]
    aid = native["assessment_id"]
    created = _required(
        metrics,
        violations,
        "create_audit_run",
        lambda: store.create_audit_run(
            aid,
            _current_revision(store, aid),
            _audit_run_input(native, "Minimal run", _assignments(native)),
        ),
    )
    run = created["audit_run"]
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
    _required(
        metrics,
        violations,
        "cancel_audit_run",
        lambda: store.cancel_audit_run(
            aid,
            _current_revision(store, aid),
            run["audit_run_id"],
            started["audit_run"]["revision"],
            "benchmark terminal transition",
        ),
    )

    reopen_started = time.monotonic_ns()
    reopened = RepeatableAuditStore(config_dir)
    _required(
        metrics,
        violations,
        "reopen_read",
        lambda: reopened.get_audit_run(aid, run["audit_run_id"]),
    )
    reopen_ms = (time.monotonic_ns() - reopen_started) / 1e6

    armed = [True]

    def fault(stage, _index):
        if armed[0] and stage == "prepared":
            armed[0] = False
            raise RuntimeError("benchmark fault")

    before = reopened.get(aid, 0, 1)
    crashing = RepeatableAuditStore(config_dir, fault_injector=fault)
    try:
        crashing.update(aid, before["revision"], {"name": "Recovered"})
        violations.append("fault_injection_missing")
    except RuntimeError:
        pass
    except BaseException as error:
        violations.append("fault_injection_error:{0}".format(_error_code(error)))
    recovery_started = time.monotonic_ns()
    recovered = RepeatableAuditStore(config_dir)
    recovered_assessment = _required(
        metrics,
        violations,
        "recovery_read",
        lambda: recovered.get(aid, before["last_event_sequence"], 1),
    )
    recovery_ms = (time.monotonic_ns() - recovery_started) / 1e6
    if (
        recovered_assessment.get("name") != "Recovered"
        or recovered_assessment.get("revision") != before["revision"] + 1
    ):
        violations.append("recovery_state_mismatch")
    if _transaction_residue(Path(config_dir)):
        violations.append("recovery_transaction_residue")
    return _capacity_snapshot(recovered, aid, metrics, violations), {
        "reopen_ms": reopen_ms,
        "recovery_ms": recovery_ms,
    }


def _realistic_workload(
    config_dir: str,
    metrics: OperationMetrics,
    violations: List[str],
) -> Tuple[Dict[str, Any], Dict[str, Optional[float]]]:
    native = _prepare_native_environment(config_dir, 8, metrics, violations)
    store = native["store"]
    aid = native["assessment_id"]
    created = _required(
        metrics,
        violations,
        "create_audit_run",
        lambda: store.create_audit_run(
            aid,
            _current_revision(store, aid),
            _audit_run_input(native, "Realistic run", _assignments(native)),
        ),
    )
    run = created["audit_run"]
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
    measurements = created["measurements"]

    for index, initial in enumerate(measurements):
        snapshot, preview = _required(
            metrics,
            violations,
            "build_native_preview",
            lambda index=index, initial=initial: _current_snapshot_and_preview(
                native, initial, index
            ),
        )
        resolved = _required(
            metrics,
            violations,
            "resolve_measurement",
            lambda initial=initial, snapshot=snapshot, preview=preview: (
                store.resolve_audit_measurement(
                    aid,
                    _current_revision(store, aid),
                    run["audit_run_id"],
                    run_revision,
                    initial["measurement_id"],
                    initial["revision"],
                    snapshot={
                        "document": snapshot,
                        "comparability_status": preview["diff"][
                            "comparability"
                        ]["status"],
                        "resolved_at": _utc_now(),
                        "source_recon_id": snapshot["scan_metadata"]["scan_id"],
                    },
                )
            ),
        )
        run_revision = resolved["audit_run"]["revision"]
        resolved_measurement = resolved["measurement"]
        analysis = _required(
            metrics,
            violations,
            "build_measurement_analysis",
            lambda preview=preview, resolved_measurement=resolved_measurement: (
                store.build_audit_measurement_analysis(
                    aid,
                    _current_revision(store, aid),
                    run["audit_run_id"],
                    run_revision,
                    resolved_measurement["measurement_id"],
                    resolved_measurement["revision"],
                    preview["diff"],
                    preview["lifecycle_findings"],
                    _occurrence_input(preview),
                    completed_at=_utc_now(),
                )
            ),
        )
        saved = _required(
            metrics,
            violations,
            "save_comparison",
            lambda analysis=analysis, resolved_measurement=resolved_measurement: (
                store.save_audit_measurement_comparison(
                    aid,
                    _current_revision(store, aid),
                    run["audit_run_id"],
                    run_revision,
                    resolved_measurement["measurement_id"],
                    resolved_measurement["revision"],
                    analysis=analysis,
                )
            ),
        )
        run_revision = saved["audit_run"]["revision"]

    completed = _required(
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
    reopen_started = time.monotonic_ns()
    reopened = RepeatableAuditStore(config_dir)
    detail = _required(
        metrics,
        violations,
        "reopen_read",
        lambda: reopened.get_audit_run(aid, run["audit_run_id"]),
    )
    reopen_ms = (time.monotonic_ns() - reopen_started) / 1e6
    if (
        completed["audit_run"].get("status") != "completed"
        or detail["audit_run"].get("status") != "completed"
        or len(detail.get("measurements", [])) != 8
        or any(item.get("status") != "completed" for item in detail["measurements"])
    ):
        violations.append("realistic_completed_state_mismatch")
    return _capacity_snapshot(reopened, aid, metrics, violations), {
        "reopen_ms": reopen_ms,
        "recovery_ms": None,
    }


def _frozen_limit_workload(
    config_dir: str,
    metrics: OperationMetrics,
    violations: List[str],
) -> Tuple[Dict[str, Any], Dict[str, Optional[float]]]:
    expected = (
        FROZEN_ACTIVE_MEASUREMENT_POINTS,
        FROZEN_TOTAL_MEASUREMENT_POINT_RECORDS,
        FROZEN_MEASUREMENTS_PER_RUN,
        FROZEN_AUDIT_RUNS_PER_ASSESSMENT,
    )
    actual = (
        MAX_ACTIVE_MEASUREMENT_POINTS,
        MAX_TOTAL_MEASUREMENT_POINT_RECORDS,
        MAX_MEASUREMENT_POINTS_PER_RUN,
        MAX_AUDIT_RUNS_PER_ASSESSMENT,
    )
    if actual != expected:
        violations.append("frozen_limit_constant_drift")
        raise ScenarioAbort()

    native = _prepare_native_environment(
        config_dir, MAX_MEASUREMENT_POINTS_PER_RUN, metrics, violations
    )
    store = native["store"]
    aid = native["assessment_id"]
    initial_point = native["measurement_points"][0]
    _expected_failure(
        metrics,
        violations,
        "active_point_limit",
        "capacity_exceeded",
        lambda: store.create_measurement_point(
            aid, _current_revision(store, aid), "Beyond active limit"
        ),
    )
    _required(
        metrics,
        violations,
        "create_max_assignment_audit_run",
        lambda: store.create_audit_run(
            aid,
            _current_revision(store, aid),
            _audit_run_input(
                native, "Maximum assignment run", _assignments(native)
            ),
        ),
    )
    for point in native["measurement_points"][1:]:
        _required(
            metrics,
            violations,
            "archive_measurement_point",
            lambda point=point: store.archive_measurement_point(
                aid,
                _current_revision(store, aid),
                point["measurement_point_id"],
                point["revision"],
            ),
        )
    for index in range(
        MAX_TOTAL_MEASUREMENT_POINT_RECORDS - MAX_ACTIVE_MEASUREMENT_POINTS
    ):
        point = _required(
            metrics,
            violations,
            "create_measurement_point",
            lambda index=index: store.create_measurement_point(
                aid,
                _current_revision(store, aid),
                "Archived capacity point {0}".format(index + 1),
            ),
        )["measurement_point"]
        _required(
            metrics,
            violations,
            "archive_measurement_point",
            lambda point=point: store.archive_measurement_point(
                aid,
                _current_revision(store, aid),
                point["measurement_point_id"],
                point["revision"],
            ),
        )
    _expected_failure(
        metrics,
        violations,
        "total_point_limit",
        "capacity_exceeded",
        lambda: store.create_measurement_point(
            aid, _current_revision(store, aid), "Beyond total limit"
        ),
    )

    assignment = [_assignments(native)[0]]
    for index in range(1, MAX_AUDIT_RUNS_PER_ASSESSMENT):
        _required(
            metrics,
            violations,
            "create_audit_run",
            lambda index=index: store.create_audit_run(
                aid,
                _current_revision(store, aid),
                _audit_run_input(
                    native,
                    "Capacity run {0}".format(index + 1),
                    assignment,
                ),
            ),
        )
    _expected_failure(
        metrics,
        violations,
        "audit_run_limit",
        "capacity_exceeded",
        lambda: store.create_audit_run(
            aid,
            _current_revision(store, aid),
            _audit_run_input(native, "Beyond run limit", assignment),
        ),
    )
    reopen_started = time.monotonic_ns()
    reopened = RepeatableAuditStore(config_dir)
    listed = _required(
        metrics,
        violations,
        "reopen_read",
        lambda: reopened.list_audit_runs(aid, limit=100, offset=0),
    )
    reopen_ms = (time.monotonic_ns() - reopen_started) / 1e6
    if listed["total"] != MAX_AUDIT_RUNS_PER_ASSESSMENT:
        violations.append("frozen_run_count_mismatch")
    points = reopened.list_measurement_points(
        aid, include_archived=True, limit=100, offset=0
    )
    if (
        points["total"] != MAX_TOTAL_MEASUREMENT_POINT_RECORDS
        or sum(1 for item in points["measurement_points"] if item["status"] == "active") != 1
        or points["measurement_points"][0]["assessment_id"] != aid
        or initial_point["measurement_point_id"]
        not in {item["measurement_point_id"] for item in points["measurement_points"]}
    ):
        violations.append("frozen_measurement_point_count_mismatch")
    capacity = _capacity_snapshot(reopened, aid, metrics, violations)
    if capacity.get("event_reserved_for_run_closure") != 32:
        violations.append("frozen_event_reserve_mismatch")
    return capacity, {"reopen_ms": reopen_ms, "recovery_ms": None}


def run_repeatable_store_benchmark(
    scenario: str = "minimal", iterations: int = 1
) -> Dict[str, Any]:
    if scenario not in SCENARIOS or not isinstance(iterations, int) or (
        isinstance(iterations, bool)
        or iterations < 1
        or iterations > MAX_SCENARIO_ITERATIONS.get(scenario, 0)
    ):
        return {
            "schema_version": "1.1",
            "mode": "repeatable-store",
            "product": "PineAssure",
            "product_mode": "repeatable_field_audit",
            "pineai_version": __version__,
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
    logical_bytes_added = []  # type: List[float]
    files_added = []  # type: List[float]
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
            prefix="pineassure-repeatable-benchmark-"
        ) as directory:
            config_root = Path(directory) / "config"
            before = _tree_snapshot(config_root)
            started = time.monotonic_ns()
            succeeded = False
            try:
                capacity, timings = workload(
                    str(config_root), metrics, violations
                )
                final_capacity_snapshot = capacity
                if timings.get("reopen_ms") is not None:
                    reopen_ms.append(float(timings["reopen_ms"]))
                if timings.get("recovery_ms") is not None:
                    recovery_ms.append(float(timings["recovery_ms"]))
                succeeded = True
            except ScenarioAbort:
                violations.append("scenario_aborted")
            except BaseException as error:
                violations.append("scenario_failed:{0}".format(_error_code(error)))
            if succeeded:
                workload_ms.append((time.monotonic_ns() - started) / 1e6)
            try:
                after = _tree_snapshot(config_root)
                logical_bytes_added.append(
                    float(
                        sum(after.values())
                        - sum(before.get(name, 0) for name in after)
                    )
                )
                files_added.append(float(len(set(after) - set(before))))
                final_file_counts.append(float(len(after)))
                for name, size in _document_sizes(config_root).items():
                    max_documents[name] = max(max_documents.get(name, 0), size)
                if _transaction_residue(config_root):
                    violations.append("transaction_residue")
            except ScenarioAbort:
                violations.append("unsafe_filesystem_entry")

    rss_after = _rss_mib()
    io_after = _proc_io()
    process_io = None
    if io_before is not None and io_after is not None:
        process_io = {
            "scope": "benchmark_process_delta_including_runtime",
            "write_bytes": max(
                0, io_after["write_bytes"] - io_before["write_bytes"]
            ),
            "write_syscalls": max(0, io_after["syscw"] - io_before["syscw"]),
        }
    unique_violations = sorted(set(violations))
    functional_passed = not unique_violations
    return {
        "schema_version": "1.1",
        "mode": "repeatable-store",
        "product": "PineAssure",
        "product_mode": "repeatable_field_audit",
        "pineai_version": __version__,
        "storage_contract": "split_run_manifest_and_measurement_v1.1",
        "native_pins": True,
        "scenario": scenario,
        "iterations": iterations,
        "validation_scope": "workstation_software_only",
        "hardware_validated": False,
        "protocol_validated": False,
        "performance_thresholds_applied": False,
        "measurement_notes": [
            "latency uses monotonic workstation process time",
            "RSS and proc I/O are process-wide observations when available",
            "logical disk deltas include benchmark-created private artifacts",
            "results are not Mark VII hardware calibration",
        ],
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
            "steady": round(rss_after, 2),
            "steady_delta": round(rss_after - rss_before, 2),
            "process_lifetime_peak": round(_rss_mib("VmHWM:"), 2),
        },
        "process_io": process_io,
        "logical_disk_delta": {
            "bytes_added": {
                "p50": int(_percentile(logical_bytes_added, 50)),
                "p95": int(_percentile(logical_bytes_added, 95)),
                "max": int(max(logical_bytes_added or [0.0])),
            },
            "files_added": {
                "p50": int(_percentile(files_added, 50)),
                "p95": int(_percentile(files_added, 95)),
                "max": int(max(files_added or [0.0])),
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
