#!/usr/bin/env python3
"""Unix domain socket benchmark harness for PineAI Hak5 module daemon.

Measures:
1. Daemon startup time (module initialization -> socket ready).
2. Action latency p50, p95, and max over N iterations over Unix domain socket.
3. Process RSS memory footprint (idle, peak, post-action steady state).
"""

import json
import os
import sys
import time
import socket
import tempfile
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "projects" / "PineAI" / "src" / "module.py"


def get_process_rss(pid):
    """Retrieve Resident Set Size (RSS) in megabytes for given PID."""
    try:
        if sys.platform.startswith("linux"):
            with open(f"/proc/{pid}/status", "r") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        return float(line.split()[1]) / 1024.0
        out = subprocess.check_output(["ps", "-o", "rss=", "-p", str(pid)])
        return float(out.strip()) / 1024.0
    except Exception:
        return 0.0


def benchmark_socket(iterations=50):
    print("=== PineAI Backend Socket Benchmark ===")
    print(f"Python version: {sys.version.split()[0]}")
    print(f"Platform: {sys.platform}")

    with tempfile.TemporaryDirectory() as tmpdir:
        env = os.environ.copy()
        env["PINEAI_CONFIG_DIR"] = os.path.join(tmpdir, "config")
        print(f"Config dir: {env['PINEAI_CONFIG_DIR']}")


if __name__ == "__main__":
    benchmark_socket()
