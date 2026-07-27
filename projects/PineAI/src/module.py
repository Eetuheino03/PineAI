#!/usr/bin/env python3

"""PineAI module backend."""

import logging
import os
import sys

from pineapple.modules import Module, Request


ASSETS_DIRECTORY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")
if ASSETS_DIRECTORY not in sys.path:
    sys.path.insert(0, ASSETS_DIRECTORY)

from pineai_backend import __version__  # noqa: E402
from pineai_backend.config import ConfigError, public_status  # noqa: E402
from pineai_backend.service import BackendError, TargetProfilerService  # noqa: E402


module = Module("PineAI", logging.INFO)


@module.handles_action("health")
def health(_request: Request):
    """Return safe runtime configuration without exposing secrets."""
    try:
        status = public_status()
        return {
            "status": "ok",
            "module": "PineAI",
            "version": __version__,
            "backend_version": __version__,
            "model": status["model"],
            "api_key_configured": status["configured"],
        }
    except ConfigError as failure:
        return (
            {
                "error": {
                    "code": "configuration_error",
                    "message": str(failure),
                }
            },
            False,
        )


@module.handles_action("profile_recon")
def profile_recon(request: Request):
    """Profile Recon JSON supplied by an authenticated Hak5 frontend session."""
    try:
        scan = getattr(request, "scan", None)
        metadata = getattr(request, "scan_metadata", None)
        options = getattr(request, "options", None)
        return TargetProfilerService().profile_recon(scan, metadata, options)
    except BackendError as failure:
        return (
            {
                "error": {
                    "code": failure.code,
                    "message": failure.safe_message,
                }
            },
            False,
        )


if __name__ == "__main__":
    module.start()
