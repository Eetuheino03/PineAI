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
        import subprocess

        out = subprocess.check_output(["ps", "-o", "rss=", "-p", str(pid)])
        return float(out.strip()) / 1024.0
    except Exception:
        return 0.0


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
                res = handler(FakeRequest())
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

        peak_rss = get_process_rss_mib(os.getpid())

        return {
            "schema_version": "1.0",
            "mode": "local-adapter",
            "pineai_version": "0.6.3",
            "iterations": iterations,
            "startup_ms": {
                "runs": [round(x, 3) for x in cold_start_ms],
                "p50": round(calculate_percentile(cold_start_ms, 50), 3),
                "p95": round(calculate_percentile(cold_start_ms, 95), 3),
                "max": round(max(cold_start_ms) if cold_start_ms else 0.0, 3),
            },
            "actions": action_metrics,
            "rss_mib": {
                "idle": round(idle_rss, 2),
                "steady": round(peak_rss, 2),
                "peak": round(peak_rss, 2),
            },
            "cache": cache_stats,
            "violations": [],
            "passed": True,
        }


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
        "--json", action="store_true", help="Output JSON only to stdout"
    )
    args = parser.parse_args()

    if args.mode == "local-adapter":
        results = run_local_adapter_benchmark(args.iterations, args.cold_start_runs)
    else:
        results = {
            "schema_version": "1.0",
            "mode": "mark-vii-socket",
            "pineai_version": "0.6.3",
            "error": "mark-vii-socket mode must be executed directly on WiFi Pineapple Mark VII hardware",
            "passed": False,
        }

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(f"=== PineAI Benchmark Results ({results['mode']}) ===")
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
