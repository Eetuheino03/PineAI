"""Cross-platform, process-safe locks for bounded PineAI operations."""

import os
import stat
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

from .config import _ensure_private_directory, resolve_config_dir
from .errors import BackendError


LOCK_DIRECTORY_NAME = ".locks"
SCAN_LOCK_NAME = "scan-processing.lock"


def _lock_path(config_dir: Optional[str], name: str) -> Path:
    directory = resolve_config_dir(config_dir)
    _ensure_private_directory(directory)
    locks = directory / LOCK_DIRECTORY_NAME
    _ensure_private_directory(locks)
    path = locks / name
    try:
        details = path.lstat()
    except FileNotFoundError:
        descriptor = os.open(
            str(path),
            os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_BINARY", 0),
            0o600,
        )
        try:
            os.write(descriptor, b"0")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        details = path.lstat()
    except OSError as error:
        raise BackendError("scan_processing_unavailable", "scan lock is unavailable") from error
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode):
        raise BackendError("scan_processing_unavailable", "scan lock path is invalid")
    try:
        os.chmod(str(path), 0o600)
    except OSError:
        pass
    return path


def _acquire(descriptor: int) -> bool:
    if os.name == "nt":
        import msvcrt

        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            return True
        except OSError:
            return False
    import fcntl

    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except OSError:
        return False


def _release(descriptor: int) -> None:
    if os.name == "nt":
        import msvcrt

        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        return
    import fcntl

    fcntl.flock(descriptor, fcntl.LOCK_UN)


@contextmanager
def scan_processing_lock(config_dir: Optional[str] = None) -> Iterator[None]:
    """Allow exactly one Recon normalization/comparison operation at a time."""
    path = _lock_path(config_dir, SCAN_LOCK_NAME)
    flags = os.O_RDWR | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = None
    acquired = False
    try:
        descriptor = os.open(str(path), flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise BackendError("scan_processing_unavailable", "scan lock path is invalid")
        acquired = _acquire(descriptor)
        if not acquired:
            raise BackendError(
                "scan_processing_busy",
                "another saved Recon scan is already being processed",
            )
        yield
    finally:
        if descriptor is not None:
            try:
                if acquired:
                    _release(descriptor)
            finally:
                os.close(descriptor)


def scan_processing_status(config_dir: Optional[str] = None) -> str:
    """Return ``idle`` or ``busy`` without leaving a lock held."""
    path = _lock_path(config_dir, SCAN_LOCK_NAME)
    flags = os.O_RDWR | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(str(path), flags)
    acquired = False
    try:
        acquired = _acquire(descriptor)
        return "idle" if acquired else "busy"
    finally:
        try:
            if acquired:
                _release(descriptor)
        finally:
            os.close(descriptor)
