#!/usr/bin/env python3
"""PineAI Backend Benchmark Harness (v0.6.3).

Supports two modes:
1. --mode local-adapter: Runs in CI and local dev workstations using isolated module adapter.
2. --mode mark-vii-socket: Runs on physical WiFi Pineapple Mark VII using Hak5 Unix domain socket framing.
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


def run_local_adapter_benchmark(iterations=20, cold_start_runs=3):
    setup_pineapple_stub()
    with tempfile.TemporaryDirectory() as tmpdir:
        os.environ["PINEAI_CONFIG_DIR"] = os.path.join(tmpdir, "config")

        import module

        cold_start_ms = []
        for _ in range(cold_start_runs):
            module._reset_singletons()
            t0 = time.monotonic_ns()
            module._service()
            cold_start_ms.append((time.monotonic_ns() - t0) / 1e6)

        module._reset_singletons()
        idle_rss = get_process_rss_mib(os.getpid())

        actions_to_measure = [
            "health",
            "platform_capabilities",
            "list_assessments",
            "list_measurement_profiles",
            "assurance_capabilities",
        ]

        action_metrics = {}

        for action_name in actions_to_measure:
            durations = []
            handler = module.module._actions.get(action_name)
            if not handler:
                continue

            first_ms = 0.0
            for i in range(iterations):
                t0 = time.monotonic_ns()
                handler(FakeRequest())
                dt_ms = (time.monotonic_ns() - t0) / 1e6
                if i == 0:
                    first_ms = dt_ms
                durations.append(dt_ms)

            action_metrics[action_name] = {
                "first_ms": round(first_ms, 3),
                "p50_ms": round(calculate_percentile(durations, 50), 3),
                "p95_ms": round(calculate_percentile(durations, 95), 3),
                "max_ms": round(max(durations) if durations else 0.0, 3),
            }

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
            "violations": [],
            "passed": True,
        }


def run_mark_vii_socket_benchmark(iterations=50, cold_start_runs=3, socket_path=None):
    """Run native Hak5 Unix-domain socket benchmark on Mark VII device."""
    if socket_path is None:
        socket_path = os.environ.get("PINEAI_SOCKET_PATH", "/tmp/pineai.sock")

    cold_start_ms = []
    actions_to_measure = [
        "health",
        "platform_capabilities",
        "list_assessments",
        "list_measurement_profiles",
        "assurance_capabilities",
    ]
    action_metrics = {}

    with tempfile.TemporaryDirectory() as tmpdir:
        config_dir = os.path.join(tmpdir, "config")
        env = os.environ.copy()
        env["PINEAI_CONFIG_DIR"] = config_dir

        # Launch main daemon for action benchmarks
        proc = subprocess.Popen(
            [sys.executable, "-u", str(SRC_DIR / "module.py")],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        try:
            connected_socket = None
            for _ in range(50):
                if os.path.exists(socket_path):
                    try:
                        candidate = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                        candidate.settimeout(1.0)
                        candidate.connect(socket_path)
                        connected_socket = candidate
                        break
                    except OSError:
                        time.sleep(0.05)
                else:
                    time.sleep(0.05)

            if connected_socket is None:
                return {
                    "schema_version": "1.0",
                    "mode": "mark-vii-socket",
                    "pineai_version": "0.6.3",
                    "iterations": iterations,
                    "socket_path": socket_path,
                    "service_initialization_ms": {"runs": [], "p50": 0.0, "p95": 0.0, "max": 0.0},
                    "actions": {},
                    "rss_mib": {"idle": 0.0, "steady": 0.0, "peak": 0.0},
                    "cache": {"items": 0, "accounted_bytes": 0, "hits": 0, "misses": 0, "evictions": 0},
                    "violations": ["Could not connect to Mark VII UDS socket"],
                    "passed": False,
                }

            idle_rss = get_process_rss_mib(proc.pid)
            all_actions_passed = True

            for action_name in actions_to_measure:
                durations = []
                first_ms = 0.0
                for i in range(iterations):
                    payload = json.dumps({"action": action_name}).encode("utf-8") + b"\n"
                    t0 = time.monotonic_ns()
                    try:
                        connected_socket.sendall(payload)
                        response_data = b""
                        while True:
                            chunk = connected_socket.recv(4096)
                            if not chunk:
                                break
                            response_data += chunk
                            if b"\n" in response_data:
                                break
                        dt_ms = (time.monotonic_ns() - t0) / 1e6
                        if i == 0:
                            first_ms = dt_ms
                        durations.append(dt_ms)

                        if response_data:
                            resp_json = json.loads(response_data.decode("utf-8").strip())
                            if isinstance(resp_json, dict) and ("error" in resp_json or resp_json.get("success") is False):
                                all_actions_passed = False
                        else:
                            all_actions_passed = False
                    except (OSError, ValueError):
                        all_actions_passed = False

                action_metrics[action_name] = {
                    "first_ms": round(first_ms, 3),
                    "p50_ms": round(calculate_percentile(durations, 50), 3),
                    "p95_ms": round(calculate_percentile(durations, 95), 3),
                    "max_ms": round(max(durations) if durations else 0.0, 3),
                }

            connected_socket.close()

            peak_rss = get_process_peak_rss_mib(proc.pid)
            steady_rss = get_process_rss_mib(proc.pid)

            return {
                "schema_version": "1.0",
                "mode": "mark-vii-socket",
                "pineai_version": "0.6.3",
                "iterations": iterations,
                "socket_path": socket_path,
                "service_initialization_ms": {
                    "runs": [round(x, 3) for x in cold_start_ms],
                    "p50": round(calculate_percentile(cold_start_ms, 50), 3),
                    "p95": round(calculate_percentile(cold_start_ms, 95), 3),
                    "max": round(max(cold_start_ms) if cold_start_ms else 0.0, 3),
                },
                "actions": action_metrics,
                "rss_mib": {
                    "idle": round(idle_rss, 2),
                    "steady": round(steady_rss, 2),
                    "peak": round(peak_rss, 2),
                },
                "cache": {
                    "items": 0,
                    "accounted_bytes": 0,
                    "hits": 0,
                    "misses": 0,
                    "evictions": 0,
                },
                "violations": [] if all_actions_passed else ["One or more socket actions failed or returned error"],
                "passed": all_actions_passed,
            }
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()


def main():
    parser = argparse.ArgumentParser(
        description="PineAI Backend Socket/Adapter Benchmark"
    )
    parser.add_argument(
        "--mode", choices=["local-adapter", "mark-vii-socket"], default="local-adapter"
    )
    parser.add_argument("--iterations", type=int, default=20)
    parser.add_argument("--cold-start-runs", type=int, default=3)
    parser.add_argument(
        "--socket-path", type=str, default=None, help="Path to Unix domain socket for mark-vii-socket mode"
    )
    parser.add_argument(
        "--json", action="store_true", help="Output JSON only to stdout"
    )
    args = parser.parse_args()

    if args.mode == "local-adapter":
        results = run_local_adapter_benchmark(args.iterations, args.cold_start_runs)
    else:
        results = run_mark_vii_socket_benchmark(args.iterations, args.cold_start_runs, args.socket_path)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(f"=== PineAI Benchmark Results ({results['mode']}) ===")
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
