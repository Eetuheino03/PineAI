#!/usr/bin/env python3
"""PineAI Backend Benchmark Harness (v0.6.3).

Supports two modes:
1. --mode local-adapter: Runs in CI and local dev workstations using isolated module adapter.
2. --mode mark-vii-socket: Runs on physical WiFi Pineapple Mark VII in attach-only mode over Unix domain socket.
"""

import argparse
import json
import math
import os
import socket
import subprocess
import sys
import tempfile
import time
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "projects" / "PineAI" / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


REQUIRED_ACTIONS = [
    "health",
    "platform_capabilities",
    "list_assessments",
    "list_measurement_profiles",
    "assurance_capabilities",
]


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
    """Validate action response against backend contract specs.
    Returns (is_valid: bool, error_message: str).
    """
    if not isinstance(payload, dict):
        return False, f"{action_name} response is not a JSON object"
    if "error" in payload:
        err = payload.get("error", {})
        msg = err.get("message", "Unknown error") if isinstance(err, dict) else str(err)
        return False, f"{action_name} returned backend error: {msg}"
    if payload.get("success") is False:
        return False, f"{action_name} returned success: false"

    if action_name == "health":
        if payload.get("status") != "ok" or payload.get("module") != "PineAI":
            return False, "health missing status='ok' or module='PineAI'"
        ver = payload.get("version")
        b_ver = payload.get("backend_version")
        if not isinstance(ver, str) or len(ver) == 0:
            return False, "health missing non-empty string version"
        if not isinstance(b_ver, str) or len(b_ver) == 0:
            return False, "health missing non-empty string backend_version"

    elif action_name == "platform_capabilities":
        if "schema_version" not in payload:
            return False, "platform_capabilities missing schema_version"
        status = payload.get("status")
        if status not in {"ready", "degraded", "blocked"}:
            return False, f"platform_capabilities status '{status}' not in ['ready', 'degraded', 'blocked']"
        if not isinstance(payload.get("storage"), dict):
            return False, "platform_capabilities missing storage dict"
        if not isinstance(payload.get("identity"), dict):
            return False, "platform_capabilities missing identity dict"
        if payload.get("recon_control") is not False:
            return False, "platform_capabilities recon_control is not false"

    elif action_name == "list_assessments":
        if "schema_version" not in payload:
            return False, "list_assessments missing schema_version"
        if not isinstance(payload.get("assessments"), list):
            return False, "list_assessments missing assessments list"

    elif action_name == "list_measurement_profiles":
        if "schema_version" not in payload:
            return False, "list_measurement_profiles missing schema_version"
        if not isinstance(payload.get("measurement_profiles"), list):
            return False, "list_measurement_profiles missing measurement_profiles list"

    elif action_name == "assurance_capabilities":
        if payload.get("schema_version") != "1.2":
            return False, "assurance_capabilities schema_version is not '1.2'"
        if payload.get("product_mode") != "customer_audit_foundation":
            return False, "assurance_capabilities product_mode is not 'customer_audit_foundation'"
        b_ver = payload.get("backend_version")
        if not isinstance(b_ver, str) or len(b_ver) == 0:
            return False, "assurance_capabilities missing non-empty string backend_version"
        mod_actions = payload.get("module_actions")
        if not isinstance(mod_actions, list):
            return False, "assurance_capabilities missing module_actions list"
        missing_req = set(REQUIRED_ACTIONS) - set(mod_actions)
        if missing_req:
            return False, f"assurance_capabilities module_actions missing required actions: {missing_req}"
        if not isinstance(payload.get("result_types"), dict):
            return False, "assurance_capabilities result_types is not a dict"
        if not isinstance(payload.get("report_scopes"), list):
            return False, "assurance_capabilities missing report_scopes list"
        if payload.get("recon_control") is not False:
            return False, "assurance_capabilities recon_control is not false"

    return True, ""


def run_local_adapter_benchmark(iterations=20, cold_start_runs=3):
    if iterations < 1 or cold_start_runs < 1:
        return {
            "schema_version": "1.0",
            "mode": "local-adapter",
            "pineai_version": "0.6.3",
            "iterations": iterations,
            "service_initialization_ms": None,
            "actions": {},
            "rss_mib": None,
            "cache": None,
            "violations": ["iterations and cold_start_runs must be >= 1"],
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
                    violations.append(f"Required action handler missing: {action_name}")
                    action_metrics[action_name] = {
                        "first_ms": 0.0,
                        "p50_ms": 0.0,
                        "p95_ms": 0.0,
                        "max_ms": 0.0,
                        "attempts": iterations,
                        "successful_samples": 0,
                        "failed_samples": iterations,
                        "last_error": f"Handler missing in module.module._actions: {action_name}"
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
                        last_error = str(ex)

                if action_failed or len(durations) < iterations:
                    violations.append(f"Action '{action_name}' failed validation: {last_error}")

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
                    action_metrics[action_name]["last_error"] = last_error

            store = module._store()
            cache_stats = {
                "items": len(store._mtime_cache),
                "accounted_bytes": store._mtime_cache_total_bytes,
                "hits": store._mtime_cache_hits,
                "misses": store._mtime_cache_misses,
                "evictions": store._mtime_cache_evictions,
            }

            peak_rss = get_process_peak_rss_mib(os.getpid())

            return {
                "schema_version": "1.0",
                "mode": "local-adapter",
                "pineai_version": "0.6.3",
                "iterations": iterations,
                "service_initialization_ms": {
                    "runs": [round(x, 3) for x in cold_start_ms],
                    "p50": round(calculate_percentile(cold_start_ms, 50), 3),
                    "p95": round(calculate_percentile(cold_start_ms, 95), 3),
                    "max": round(max(cold_start_ms) if cold_start_ms else 0.0, 3),
                },
                "actions": action_metrics,
                "rss_mib": {
                    "idle": round(idle_rss, 2),
                    "steady": round(get_process_rss_mib(os.getpid()), 2),
                    "peak": round(peak_rss, 2),
                },
                "cache": cache_stats,
                "violations": violations,
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
    """Run native Hak5 Unix-domain socket benchmark on Mark VII device (attach-only mode)."""
    if iterations < 1:
        return {
            "schema_version": "1.0",
            "mode": "mark-vii-socket",
            "pineai_version": "0.6.3",
            "iterations": iterations,
            "socket_path": socket_path,
            "connection_mode": "attach",
            "service_initialization_ms": None,
            "actions": {},
            "rss_mib": None,
            "cache": None,
            "protocol_validated": False,
            "hardware_validated": False,
            "violations": ["iterations must be >= 1"],
            "passed": False,
        }

    if not socket_path:
        socket_path = os.environ.get("PINEAI_SOCKET_PATH")

    if not socket_path:
        return {
            "schema_version": "1.0",
            "mode": "mark-vii-socket",
            "pineai_version": "0.6.3",
            "iterations": iterations,
            "socket_path": None,
            "connection_mode": "attach",
            "service_initialization_ms": None,
            "actions": {},
            "rss_mib": None,
            "cache": None,
            "protocol_validated": False,
            "hardware_validated": False,
            "violations": ["--socket-path or PINEAI_SOCKET_PATH environment variable is required"],
            "passed": False,
        }

    timeout_seconds = max(0.5, min(10.0, float(timeout_seconds)))
    max_response_bytes = 524_288  # 512 KiB transport buffer safety limit

    action_metrics = {}
    violations = []
    all_actions_passed = True

    if not os.path.exists(socket_path):
        return {
            "schema_version": "1.0",
            "mode": "mark-vii-socket",
            "pineai_version": "0.6.3",
            "iterations": iterations,
            "socket_path": socket_path,
            "connection_mode": "attach",
            "service_initialization_ms": None,
            "actions": {},
            "rss_mib": None,
            "cache": None,
            "protocol_validated": False,
            "hardware_validated": False,
            "violations": [f"Socket path does not exist: {socket_path}"],
            "passed": False,
        }

    for action_name in REQUIRED_ACTIONS:
        durations = []
        first_ms = 0.0
        successful_samples = 0
        failed_samples = 0
        skipped_samples = 0
        last_error = ""

        for i in range(iterations):
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(timeout_seconds)
            try:
                sock.connect(socket_path)
                payload = json.dumps({"action": action_name}).encode("utf-8") + b"\n"
                t0 = time.monotonic_ns()
                sock.sendall(payload)

                response_data = b""
                stream_ok = True
                framing_complete = False

                while True:
                    try:
                        chunk = sock.recv(4096)
                        if not chunk:
                            stream_ok = False
                            last_error = "Connection closed before newline frame terminator"
                            break
                        response_data += chunk
                        if len(response_data) > max_response_bytes:
                            stream_ok = False
                            last_error = f"Response exceeded transport safety limit ({max_response_bytes} bytes)"
                            break
                        if b"\n" in response_data:
                            framing_complete = True
                            break
                    except socket.timeout:
                        stream_ok = False
                        last_error = f"Socket request timed out ({timeout_seconds}s)"
                        break
                    except OSError as ex:
                        stream_ok = False
                        last_error = f"Socket OS error: {ex}"
                        break

                dt_ms = (time.monotonic_ns() - t0) / 1e6

                if stream_ok and framing_complete and response_data:
                    line = response_data.split(b"\n", 1)[0].decode("utf-8").strip()
                    if not line:
                        failed_samples += 1
                        last_error = "Empty JSON payload"
                    else:
                        try:
                            resp_json = json.loads(line)
                            is_valid, err_msg = validate_action_response(action_name, resp_json)
                            if is_valid:
                                if successful_samples == 0:
                                    first_ms = dt_ms
                                durations.append(dt_ms)
                                successful_samples += 1
                            else:
                                failed_samples += 1
                                last_error = err_msg
                        except ValueError:
                            failed_samples += 1
                            last_error = f"Malformed JSON: {line[:50]}"
                else:
                    failed_samples += 1
            except socket.timeout:
                failed_samples += 1
                last_error = f"Socket request timed out ({timeout_seconds}s)"
            except OSError as ex:
                failed_samples += 1
                last_error = f"Socket OS error: {ex}"
            finally:
                try:
                    sock.close()
                except OSError:
                    pass

        if successful_samples < iterations:
            all_actions_passed = False
            violations.append(f"Action '{action_name}' had {failed_samples + skipped_samples} failures/skips: {last_error}")

        metric_entry = {
            "first_ms": round(first_ms, 3) if durations else 0.0,
            "p50_ms": round(calculate_percentile(durations, 50), 3),
            "p95_ms": round(calculate_percentile(durations, 95), 3),
            "max_ms": round(max(durations) if durations else 0.0, 3),
            "attempts": iterations,
            "successful_samples": successful_samples,
            "failed_samples": failed_samples,
            "skipped_samples": skipped_samples,
        }
        if last_error:
            metric_entry["last_error"] = last_error

        action_metrics[action_name] = metric_entry

    return {
        "schema_version": "1.0",
        "mode": "mark-vii-socket",
        "pineai_version": "0.6.3",
        "iterations": iterations,
        "socket_path": socket_path,
        "connection_mode": "attach",
        "service_initialization_ms": None,
        "actions": action_metrics,
        "rss_mib": None,
        "cache": None,
        "protocol_validated": False,
        "hardware_validated": False,
        "violations": violations,
        "passed": all_actions_passed and len(violations) == 0,
    }


def main():
    parser = argparse.ArgumentParser(
        description="PineAI Backend Socket/Adapter Benchmark"
    )
    parser.add_argument(
        "--mode", choices=["local-adapter", "mark-vii-socket"], default="local-adapter"
    )
    parser.add_argument("--iterations", type=int, default=20)
    parser.add_argument("--cold-start-runs", type=int, default=3, help="Cold start runs (local-adapter mode only)")
    parser.add_argument(
        "--socket-path", type=str, default=None, help="Path to Unix domain socket for mark-vii-socket mode"
    )
    parser.add_argument(
        "--timeout-seconds", type=float, default=2.0, help="Socket request timeout in seconds (0.5 to 10.0)"
    )
    parser.add_argument(
        "--json", action="store_true", help="Output JSON only to stdout"
    )
    args = parser.parse_args()

    if args.iterations < 1 or args.cold_start_runs < 1:
        parser.error("iterations and cold_start_runs must be >= 1")

    if args.mode == "local-adapter":
        results = run_local_adapter_benchmark(args.iterations, args.cold_start_runs)
    else:
        results = run_mark_vii_socket_benchmark(args.iterations, args.socket_path, args.timeout_seconds)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(f"=== PineAI Benchmark Results ({results['mode']}) ===")
        print(json.dumps(results, indent=2))

    sys.exit(0 if results.get("passed") else 1)


if __name__ == "__main__":
    main()
