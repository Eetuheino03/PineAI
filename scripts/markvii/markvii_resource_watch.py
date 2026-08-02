#!/usr/bin/env python3
"""Passively sample Mark VII process and system memory without signalling it."""

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


def _status(pid: int) -> Dict[str, int]:
    values = {}
    wanted = {"VmRSS", "VmHWM", "VmSize", "Threads"}
    for line in Path("/proc/{0}/status".format(pid)).read_text(
        encoding="ascii"
    ).splitlines():
        if ":" not in line:
            continue
        name, raw = line.split(":", 1)
        if name in wanted:
            values[name] = int(raw.strip().split()[0])
    return values


def _meminfo() -> Dict[str, int]:
    values = {}
    wanted = {"MemAvailable", "MemFree", "SwapFree"}
    for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
        if ":" not in line:
            continue
        name, raw = line.split(":", 1)
        if name in wanted:
            values[name] = int(raw.strip().split()[0])
    return values


def _write(path: Path, result: Dict[str, Any]) -> None:
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
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--duration-seconds", type=int, default=300)
    parser.add_argument("--interval-seconds", type=int, default=5)
    parser.add_argument("--output", required=True)
    arguments = parser.parse_args(argv)
    if arguments.pid < 1:
        parser.error("--pid must be positive")
    if arguments.duration_seconds < 1 or arguments.duration_seconds > 3600:
        parser.error("--duration-seconds must be between 1 and 3600")
    if arguments.interval_seconds < 1 or arguments.interval_seconds > 60:
        parser.error("--interval-seconds must be between 1 and 60")
    samples = []
    started = time.monotonic()
    failure = None
    while True:
        elapsed = time.monotonic() - started
        try:
            samples.append(
                {
                    "elapsed_seconds": round(elapsed, 3),
                    "process": _status(arguments.pid),
                    "system": _meminfo(),
                }
            )
        except (OSError, UnicodeDecodeError, ValueError, IndexError):
            failure = "process_or_proc_unavailable"
            break
        remaining = arguments.duration_seconds - elapsed
        if remaining <= 0:
            break
        time.sleep(min(arguments.interval_seconds, remaining))
    result = {
        "schema_version": "1.0",
        "hardware_validated": False,
        "radio_actions_performed": False,
        "pid": arguments.pid,
        "duration_requested_seconds": arguments.duration_seconds,
        "interval_seconds": arguments.interval_seconds,
        "samples": samples,
        "success": failure is None,
    }
    if failure:
        result["error"] = {"code": failure}
    try:
        _write(Path(arguments.output), result)
    except OSError:
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if failure is None else 1


if __name__ == "__main__":
    sys.exit(main())
