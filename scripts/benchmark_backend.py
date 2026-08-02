#!/usr/bin/env python3
"""PineAssure backend benchmark harness (v0.7.0).

Supports two modes:
1. --mode local-adapter: Runs in CI and local dev workstations using isolated module adapter.
2. --mode mark-vii-socket: Runs on physical WiFi Pineapple Mark VII in attach-only mode over Unix domain socket.
"""

import argparse
import json
import math
import os
import re
import socket
import stat
import subprocess
import sys
import tempfile
import time
import types
from pathlib import Path

from benchmark_repeatable_store import run_repeatable_store_benchmark

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "projects" / "PineAI" / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
ASSETS_DIR = SRC_DIR / "assets"
if str(ASSETS_DIR) not in sys.path:
    sys.path.insert(0, str(ASSETS_DIR))

from pineai_backend import __version__ as PINEAI_VERSION  # noqa: E402
from pineai_backend.errors import BackendError  # noqa: E402


REQUIRED_ACTIONS = [
    "health",
    "platform_capabilities",
    "list_assessments",
    "list_measurement_profiles",
    "assurance_capabilities",
    "repeatable_audit_capabilities",
    "resource_telemetry",
]
REPEATABLE_REQUIRED_ACTIONS = [
    "repeatable_audit_capabilities",
    "resource_telemetry",
    "create_measurement_point",
    "create_audit_run",
    "start_audit_run",
    "resolve_audit_measurement",
    "save_audit_measurement_comparison",
    "complete_audit_run",
    "generate_audit_run_report",
]
ERROR_CODE_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def benchmark_exception_code(error):
    if isinstance(error, BackendError):
        code = getattr(error, "code", None)
        if isinstance(code, str) and ERROR_CODE_PATTERN.match(code):
            return code
    return "unexpected_exception"


def setup_pineapple_stub():
    """Inject pineapple.modules stub for offline / workstation benchmarking."""
    if "pineapple.modules" not in sys.modules:
        pineapple = types.ModuleType("pineapple")
        modules = types.ModuleType("pineapple.modules")

        class Module:
            def __init__(self, *_args):
                self._actions = {}

            def handles_action(self, name):
                def decorator(function):
                    self._actions[name] = function
                    return function

                return decorator

            def start(self):
                pass

        class Request:
            pass

        modules.Module = Module
        modules.Request = Request
        pineapple.modules = modules
        sys.modules["pineapple"] = pineapple
        sys.modules["pineapple.modules"] = modules


def get_process_rss_mib(pid: int) -> float:
    """Retrieve Resident Set Size (RSS) in MiB for given PID."""
    try:
        if sys.platform.startswith("linux"):
            with open(f"/proc/{pid}/status", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        return float(line.split()[1]) / 1024.0
        out = subprocess.check_output(["ps", "-o", "rss=", "-p", str(pid)])
        return float(out.strip()) / 1024.0
    except Exception:
        return 0.0


def get_process_peak_rss_mib(pid: int) -> float:
    """Retrieve Peak Resident Set Size (VmHWM) in MiB for given PID on Linux."""
    try:
        if sys.platform.startswith("linux"):
            with open(f"/proc/{pid}/status", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("VmHWM:"):
                        return float(line.split()[1]) / 1024.0
    except Exception:
        pass
    return get_process_rss_mib(pid)


def calculate_percentile(values, percentile):
    """Nearest rank percentile calculation compatible with Python 3.8+."""
    if not values:
        return 0.0
    sorted_vals = sorted(values)
    idx = max(0, int(math.ceil((percentile / 100.0) * len(sorted_vals))) - 1)
    return float(sorted_vals[idx])


class FakeRequest:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


def validate_action_response(action_name: str, payload: any) -> tuple:
    """Return a fixed validation code without serializing response content."""
    if not isinstance(payload, dict):
        return False, "response_not_object"
    if "error" in payload:
        return False, "backend_error"
    if payload.get("success") is False:
        return False, "success_false"

    if action_name == "health":
        if payload.get("status") != "ok" or payload.get("module") != "PineAI":
            return False, "health_contract"
        if payload.get("product_name") != "PineAssure":
            return False, "health_product_name"
        if payload.get("product_mode") != "repeatable_field_audit":
            return False, "health_product_mode"
        ver = payload.get("version")
        b_ver = payload.get("backend_version")
        if ver != PINEAI_VERSION:
            return False, "health_version"
        if b_ver != PINEAI_VERSION:
            return False, "health_backend_version"

    elif action_name == "platform_capabilities":
        if "schema_version" not in payload:
            return False, "platform_schema"
        status = payload.get("status")
        if status not in {"ready", "degraded", "blocked"}:
            return False, "platform_status"
        if not isinstance(payload.get("storage"), dict):
            return False, "platform_storage"
        if not isinstance(payload.get("identity"), dict):
            return False, "platform_identity"
        if payload.get("recon_control") is not False:
            return False, "platform_recon_control"

    elif action_name == "list_assessments":
        if "schema_version" not in payload:
            return False, "assessment_schema"
        if not isinstance(payload.get("assessments"), list):
            return False, "assessment_list"

    elif action_name == "list_measurement_profiles":
        if "schema_version" not in payload:
            return False, "measurement_profile_schema"
        if not isinstance(payload.get("measurement_profiles"), list):
            return False, "measurement_profile_list"

    elif action_name == "assurance_capabilities":
        if payload.get("schema_version") != "1.2":
            return False, "assurance_schema"
        if payload.get("product_name") != "PineAssure":
            return False, "assurance_product_name"
        if payload.get("product_mode") != "repeatable_field_audit":
            return False, "assurance_product_mode"
        b_ver = payload.get("backend_version")
        if b_ver != PINEAI_VERSION:
            return False, "assurance_backend_version"
        mod_actions = payload.get("module_actions")
        if not isinstance(mod_actions, list):
            return False, "assurance_actions"
        missing_req = set(REQUIRED_ACTIONS) - set(mod_actions)
        if missing_req:
            return False, "assurance_actions_missing"
        if not isinstance(payload.get("result_types"), dict):
            return False, "assurance_result_types"
        if not isinstance(payload.get("report_scopes"), list):
            return False, "assurance_report_scopes"
        if payload.get("recon_control") is not False:
            return False, "assurance_recon_control"

    elif action_name == "repeatable_audit_capabilities":
        if payload.get("schema_version") != "1.0":
            return False, "repeatable_schema"
        product = payload.get("product")
        if not isinstance(product, dict) or product.get("name") != "PineAssure":
            return False, "repeatable_product"
        actions = payload.get("public_actions")
        if not isinstance(actions, list):
            return False, "repeatable_actions"
        if not set(REPEATABLE_REQUIRED_ACTIONS).issubset(set(actions)):
            return False, "repeatable_actions_missing"
        limits = payload.get("limits")
        if not isinstance(limits, dict):
            return False, "repeatable_limits"
        if payload.get("hardware_calibrated") is not False:
            return False, "repeatable_hardware_claim"

    elif action_name == "resource_telemetry":
        if payload.get("schema_version") != "1.0":
            return False, "telemetry_schema"
        guard = payload.get("guard")
        if not isinstance(guard, dict):
            return False, "telemetry_guard"
        if guard.get("hardware_calibrated") is not False:
            return False, "telemetry_hardware_claim"
        for field in ("memory", "storage", "artifacts", "scan_processing"):
            if not isinstance(payload.get(field), dict):
                return False, "telemetry_{0}".format(field)

    return True, ""


def run_local_adapter_benchmark(iterations=20, cold_start_runs=3):
    if iterations < 1 or cold_start_runs < 1:
        return {
            "schema_version": "1.0",
            "mode": "local-adapter",
            "product": "PineAssure",
            "product_mode": "repeatable_field_audit",
            "pineai_version": PINEAI_VERSION,
            "iterations": iterations,
            "service_reinitialization_ms": None,
            "actions": {},
            "rss_mib": None,
            "cache": None,
            "validation_scope": "workstation_software_only",
            "protocol_validated": False,
            "hardware_validated": False,
            "performance_thresholds_applied": False,
            "violations": ["invalid_benchmark_arguments"],
            "functional_workload_passed": False,
            "passed": False,
        }

    setup_pineapple_stub()
    old_config_dir = os.environ.get("PINEAI_CONFIG_DIR")
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = os.path.join(tmpdir, "config")
            os.environ["PINEAI_CONFIG_DIR"] = config_dir

            import module
            module._reset_singletons()

            cold_start_ms = []
            for _ in range(cold_start_runs):
                module._reset_singletons()
                t0 = time.monotonic_ns()
                module._service()
                cold_start_ms.append((time.monotonic_ns() - t0) / 1e6)

            module._reset_singletons()
            idle_rss = get_process_rss_mib(os.getpid())

            action_metrics = {}
            violations = []

            for action_name in REQUIRED_ACTIONS:
                handler = module.module._actions.get(action_name)
                if not handler:
                    violations.append(
                        "handler_missing:{0}".format(action_name)
                    )
                    action_metrics[action_name] = {
                        "first_ms": 0.0,
                        "p50_ms": 0.0,
                        "p95_ms": 0.0,
                        "max_ms": 0.0,
                        "attempts": iterations,
                        "successful_samples": 0,
                        "failed_samples": iterations,
                        "last_error_code": "handler_missing",
                    }
                    continue

                durations = []
                first_ms = 0.0
                action_failed = False
                last_error = ""

                for i in range(iterations):
                    t0 = time.monotonic_ns()
                    try:
                        resp = handler(FakeRequest())
                        dt_ms = (time.monotonic_ns() - t0) / 1e6
                        is_valid, err_msg = validate_action_response(action_name, resp)
                        if is_valid:
                            if len(durations) == 0:
                                first_ms = dt_ms
                            durations.append(dt_ms)
                        else:
                            action_failed = True
                            last_error = err_msg
                    except Exception as ex:
                        action_failed = True
                        last_error = benchmark_exception_code(ex)

                if action_failed or len(durations) < iterations:
                    violations.append(
                        "action_failed:{0}:{1}".format(
                            action_name, last_error or "validation_failed"
                        )
                    )

                action_metrics[action_name] = {
                    "first_ms": round(first_ms, 3) if durations else 0.0,
                    "p50_ms": round(calculate_percentile(durations, 50), 3),
                    "p95_ms": round(calculate_percentile(durations, 95), 3),
                    "max_ms": round(max(durations) if durations else 0.0, 3),
                    "attempts": iterations,
                    "successful_samples": len(durations),
                    "failed_samples": iterations - len(durations),
                }
                if last_error:
                    action_metrics[action_name][
                        "last_error_code"
                    ] = last_error

            store = module._store()
            cache_stats = {
                "items": len(store._mtime_cache),
                "accounted_bytes": store._mtime_cache_total_bytes,
                "hits": store._mtime_cache_hits,
                "misses": store._mtime_cache_misses,
                "evictions": store._mtime_cache_evictions,
            }

            steady_rss = get_process_rss_mib(os.getpid())
            peak_rss = get_process_peak_rss_mib(os.getpid())

            return {
                "schema_version": "1.0",
                "mode": "local-adapter",
                "product": "PineAssure",
                "product_mode": "repeatable_field_audit",
                "pineai_version": PINEAI_VERSION,
                "iterations": iterations,
                "validation_scope": "workstation_software_only",
                "protocol_validated": False,
                "hardware_validated": False,
                "performance_thresholds_applied": False,
                "service_reinitialization_ms": {
                    "runs": [round(x, 3) for x in cold_start_ms],
                    "p50": round(calculate_percentile(cold_start_ms, 50), 3),
                    "p95": round(calculate_percentile(cold_start_ms, 95), 3),
                    "max": round(max(cold_start_ms) if cold_start_ms else 0.0, 3),
                },
                "actions": action_metrics,
                "rss_mib": {
                    "idle": round(idle_rss, 2),
                    "steady": round(steady_rss, 2),
                    "process_lifetime_peak": round(peak_rss, 2),
                },
                "cache": cache_stats,
                "violations": violations,
                "functional_workload_passed": len(violations) == 0,
                "passed": len(violations) == 0,
            }
    finally:
        try:
            if "module" in sys.modules and hasattr(sys.modules["module"], "_reset_singletons"):
                sys.modules["module"]._reset_singletons()
        except Exception:
            pass
        if old_config_dir is None:
            os.environ.pop("PINEAI_CONFIG_DIR", None)
        else:
            os.environ["PINEAI_CONFIG_DIR"] = old_config_dir


def run_mark_vii_socket_benchmark(iterations=50, socket_path=None, timeout_seconds=2.0):
    """Attach to an already-running, genuine Unix socket without path output."""

    def failure(code):
        return {
            "schema_version": "1.0",
            "mode": "mark-vii-socket",
            "product": "PineAssure",
            "product_mode": "repeatable_field_audit",
            "pineai_version": PINEAI_VERSION,
            "iterations": iterations,
            "socket_configured": bool(socket_path),
            "connection_mode": "attach",
            "service_reinitialization_ms": None,
            "actions": {},
            "rss_mib": None,
            "cache": None,
            "protocol_validated": False,
            "hardware_validated": False,
            "response_contract_validated": False,
            "performance_thresholds_applied": False,
            "violations": [code],
            "functional_workload_passed": False,
            "passed": False,
        }

    if iterations < 1:
        return failure("invalid_benchmark_arguments")
    if not socket_path:
        socket_path = os.environ.get("PINEAI_SOCKET_PATH")
    if not socket_path:
        return failure("socket_path_required")
    try:
        socket_metadata = os.lstat(socket_path)
    except OSError:
        return failure("socket_unavailable")
    if not stat.S_ISSOCK(socket_metadata.st_mode):
        return failure("socket_not_unix_socket")

    timeout_seconds = max(0.5, min(10.0, float(timeout_seconds)))
    max_response_bytes = 524_288
    action_metrics = {}
    violations = []

    for action_name in REQUIRED_ACTIONS:
        durations = []
        first_ms = 0.0
        failed_samples = 0
        last_error_code = ""
        for _index in range(iterations):
            iteration_error = ""
            benchmark_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            benchmark_socket.settimeout(timeout_seconds)
            started = time.monotonic_ns()
            response_data = b""
            try:
                benchmark_socket.connect(socket_path)
                benchmark_socket.sendall(
                    json.dumps({"action": action_name}).encode("utf-8")
                    + b"\n"
                )
                while b"\n" not in response_data:
                    chunk = benchmark_socket.recv(4096)
                    if not chunk:
                        iteration_error = "connection_closed"
                        break
                    response_data += chunk
                    if len(response_data) > max_response_bytes:
                        iteration_error = "response_limit"
                        break
                elapsed = (time.monotonic_ns() - started) / 1e6
                if not iteration_error and b"\n" in response_data:
                    try:
                        response = json.loads(
                            response_data.split(b"\n", 1)[0].decode("utf-8")
                        )
                    except (UnicodeDecodeError, ValueError):
                        iteration_error = "malformed_json"
                    else:
                        valid, validation_code = validate_action_response(
                            action_name, response
                        )
                        if valid:
                            if not durations:
                                first_ms = elapsed
                            durations.append(elapsed)
                        else:
                            iteration_error = validation_code
            except socket.timeout:
                iteration_error = "socket_timeout"
            except OSError:
                iteration_error = "socket_error"
            finally:
                benchmark_socket.close()
            if iteration_error:
                failed_samples += 1
                last_error_code = iteration_error

        if failed_samples:
            violations.append(
                "action_failed:{0}:{1}".format(
                    action_name, last_error_code
                )
            )
        entry = {
            "first_ms": round(first_ms, 3) if durations else 0.0,
            "p50_ms": round(calculate_percentile(durations, 50), 3),
            "p95_ms": round(calculate_percentile(durations, 95), 3),
            "max_ms": round(max(durations) if durations else 0.0, 3),
            "attempts": iterations,
            "successful_samples": len(durations),
            "failed_samples": failed_samples,
        }
        if last_error_code:
            entry["last_error_code"] = last_error_code
        action_metrics[action_name] = entry

    return {
        "schema_version": "1.0",
        "mode": "mark-vii-socket",
        "product": "PineAssure",
        "product_mode": "repeatable_field_audit",
        "pineai_version": PINEAI_VERSION,
        "iterations": iterations,
        "socket_configured": True,
        "connection_mode": "attach",
        "service_reinitialization_ms": None,
        "actions": action_metrics,
        "rss_mib": None,
        "cache": None,
        # A syntactically valid response from an arbitrary attached socket is
        # not proof of Hak5 runtime protocol or hardware compatibility.
        "protocol_validated": False,
        "hardware_validated": False,
        "response_contract_validated": not violations,
        "performance_thresholds_applied": False,
        "violations": violations,
        "functional_workload_passed": not violations,
        "passed": not violations,
    }


def main():
    parser = argparse.ArgumentParser(
        description="PineAI backend workstation and attach-only benchmarks"
    )
    parser.add_argument(
        "--mode",
        choices=[
            "local-adapter",
            "repeatable-store",
            "mark-vii-socket",
        ],
        default="local-adapter",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=None,
        help=(
            "Iteration count. Defaults to 20 for local-adapter, 1 for "
            "repeatable-store, and 50 for attach-only socket mode."
        ),
    )
    parser.add_argument(
        "--cold-start-runs",
        type=int,
        default=3,
        help="Service reinitialization runs (local-adapter mode only)",
    )
    parser.add_argument(
        "--scenario",
        choices=["minimal", "realistic", "frozen-limit"],
        default="minimal",
        help="RepeatableAuditStore workload",
    )
    parser.add_argument(
        "--socket-path", type=str, default=None, help="Path to Unix domain socket for mark-vii-socket mode"
    )
    parser.add_argument(
        "--allow-frozen-limit",
        action="store_true",
        help="Explicitly allow the expensive frozen-limit store scenario.",
    )
    parser.add_argument(
        "--timeout-seconds", type=float, default=2.0, help="Socket request timeout in seconds (0.5 to 10.0)"
    )
    parser.add_argument(
        "--json", action="store_true", help="Output JSON only to stdout"
    )
    args = parser.parse_args()

    if args.iterations is None:
        args.iterations = {
            "local-adapter": 20,
            "repeatable-store": 1,
            "mark-vii-socket": 50,
        }[args.mode]
    if args.iterations < 1:
        parser.error("iterations must be >= 1")
    if args.mode == "local-adapter" and args.cold_start_runs < 1:
        parser.error("cold_start_runs must be >= 1")
    if (
        args.mode == "repeatable-store"
        and args.scenario == "frozen-limit"
        and not args.allow_frozen_limit
    ):
        parser.error(
            "frozen-limit requires explicit --allow-frozen-limit"
        )

    try:
        if args.mode == "local-adapter":
            results = run_local_adapter_benchmark(
                args.iterations, args.cold_start_runs
            )
        elif args.mode == "repeatable-store":
            results = run_repeatable_store_benchmark(
                args.scenario, args.iterations
            )
        else:
            results = run_mark_vii_socket_benchmark(
                args.iterations,
                args.socket_path,
                args.timeout_seconds,
            )
    except Exception as error:
        results = {
            "schema_version": "1.0",
            "mode": args.mode,
            "product": "PineAssure",
            "product_mode": "repeatable_field_audit",
            "pineai_version": PINEAI_VERSION,
            "iterations": args.iterations,
            "validation_scope": "workstation_software_only",
            "hardware_validated": False,
            "protocol_validated": False,
            "performance_thresholds_applied": False,
            "violations": [
                "benchmark_failed:{0}".format(
                    benchmark_exception_code(error)
                )
            ],
            "functional_workload_passed": False,
            "passed": False,
        }

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(f"=== PineAssure Benchmark Results ({results['mode']}) ===")
        print(json.dumps(results, indent=2))

    sys.exit(0 if results.get("passed") else 1)


if __name__ == "__main__":
    main()
