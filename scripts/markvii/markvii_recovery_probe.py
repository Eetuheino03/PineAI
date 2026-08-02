#!/usr/bin/env python3
"""Exercise transaction recovery in an explicitly disposable state directory."""

import argparse
import importlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


MARKER = "PINEASSURE_V070_DISPOSABLE_RECOVERY_STATE"
EXPECTED = {
    "probe/first.json": {"sequence": 1, "value": "before"},
    "probe/second.json": {"sequence": 2, "value": "after"},
}


class SimulatedInterruption(BaseException):
    """Stop after the durable prepared-journal boundary."""


def _validated_state(path: Path, prepare: bool) -> Path:
    resolved = path.resolve()
    if not resolved.is_absolute() or resolved == Path("/"):
        raise ValueError("state directory must be an absolute non-root path")
    if ".PineAI" in resolved.parts:
        raise ValueError("production .PineAI state is forbidden")
    if prepare:
        if resolved.exists() or resolved.is_symlink():
            raise ValueError("prepare requires a nonexistent state directory")
        resolved.mkdir(parents=True, mode=0o700)
        os.chmod(str(resolved), 0o700)
        marker = resolved / MARKER
        marker.write_text("disposable\n", encoding="ascii")
        os.chmod(str(marker), 0o600)
    else:
        marker = resolved / MARKER
        details = marker.lstat()
        if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode):
            raise ValueError("disposable-state marker is invalid")
        if marker.read_text(encoding="ascii") != "disposable\n":
            raise ValueError("disposable-state marker is invalid")
    return resolved


def _load_backend(package_root: Path) -> Any:
    assets = package_root.resolve() / "assets"
    backend = assets / "pineai_backend"
    if not backend.is_dir() or backend.is_symlink():
        raise ValueError("package backend directory is unavailable")
    sys.path.insert(0, str(assets))
    return importlib.import_module("pineai_backend.storage_transaction")


def _prepare(transaction_module: Any, state: Path) -> Dict[str, Any]:
    def stop(stage: str, _index: int) -> None:
        if stage == "prepared":
            raise SimulatedInterruption()

    transaction = transaction_module.PrivateTransaction(
        state, fault_injector=stop
    )
    for relative, value in EXPECTED.items():
        transaction.add_json(relative, value)
    interrupted = False
    try:
        transaction.commit()
    except SimulatedInterruption:
        interrupted = True
    if not interrupted:
        raise ValueError("prepared-boundary interruption did not occur")
    journals = sorted((state / ".transactions").glob("*/journal.json"))
    if len(journals) != 1:
        raise ValueError("exactly one prepared transaction was expected")
    if any((state / relative).exists() for relative in EXPECTED):
        raise ValueError("targets were published before recovery")
    return {
        "phase": "prepared",
        "prepared_transaction_count": 1,
        "targets_published": False,
    }


def _verify(transaction_module: Any, state: Path) -> Dict[str, Any]:
    recovered = transaction_module.recover_private_transactions(
        state, cleanup_unprepared=True
    )
    for relative, expected in EXPECTED.items():
        value = json.loads((state / relative).read_text(encoding="utf-8"))
        if value != expected:
            raise ValueError("recovered target content is invalid")
        mode = stat.S_IMODE((state / relative).stat().st_mode)
        if os.name != "nt" and mode != 0o600:
            raise ValueError("recovered target mode is invalid")
    remaining = []
    transactions = state / ".transactions"
    if transactions.is_dir():
        remaining = list(transactions.iterdir())
    if remaining:
        raise ValueError("transaction residue remains after recovery")
    return {
        "phase": "recovered",
        "recovered_transaction_count": len(recovered),
        "target_count": len(EXPECTED),
        "transaction_residue_count": 0,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "verify"))
    parser.add_argument("--package-root", required=True)
    parser.add_argument("--state-dir", required=True)
    arguments = parser.parse_args(argv)
    result: Dict[str, Any] = {
        "schema_version": "1.0",
        "hardware_validated": False,
        "production_state_used": False,
        "radio_actions_performed": False,
    }
    try:
        state = _validated_state(
            Path(arguments.state_dir), arguments.phase == "prepare"
        )
        transaction_module = _load_backend(Path(arguments.package_root))
        if arguments.phase == "prepare":
            result.update(_prepare(transaction_module, state))
        else:
            result.update(_verify(transaction_module, state))
        result["success"] = True
    except (OSError, ValueError, ImportError, json.JSONDecodeError):
        result["success"] = False
        result["error"] = {"code": "recovery_probe_failed"}
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("success") else 1


if __name__ == "__main__":
    sys.exit(main())
