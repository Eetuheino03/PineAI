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
from pineai_backend.advisor_service import AttackPathAdvisorService  # noqa: E402
from pineai_backend.config import ConfigError, public_status  # noqa: E402
from pineai_backend.engagement_store import EngagementStore  # noqa: E402
from pineai_backend.errors import BackendError  # noqa: E402
from pineai_backend.service import TargetProfilerService  # noqa: E402


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


def _backend_failure(failure: BackendError):
    return (
        {
            "error": {
                "code": failure.code,
                "message": failure.safe_message,
            }
        },
        False,
    )


@module.handles_action("advisor_capabilities")
def advisor_capabilities(_request: Request):
    try:
        return AttackPathAdvisorService().capabilities()
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("create_engagement")
def create_engagement(request: Request):
    try:
        return EngagementStore().create(getattr(request, "engagement", None))
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("get_engagement")
def get_engagement(request: Request):
    try:
        return EngagementStore().get(
            getattr(request, "engagement_id", None),
            getattr(request, "after_sequence", 0),
            getattr(request, "limit", 100),
        )
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("list_engagements")
def list_engagements(request: Request):
    try:
        return {
            "engagements": EngagementStore().list(
                getattr(request, "include_archived", False)
            )
        }
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("update_engagement")
def update_engagement(request: Request):
    try:
        return EngagementStore().update(
            getattr(request, "engagement_id", None),
            getattr(request, "expected_revision", None),
            getattr(request, "changes", None),
        )
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("archive_engagement")
def archive_engagement(request: Request):
    try:
        return EngagementStore().archive(
            getattr(request, "engagement_id", None),
            getattr(request, "expected_revision", None),
        )
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("append_engagement_event")
def append_engagement_event(request: Request):
    try:
        return EngagementStore().append_event(
            getattr(request, "engagement_id", None),
            getattr(request, "expected_revision", None),
            getattr(request, "event", None),
        )
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("advise_attack_paths")
def advise_attack_paths(request: Request):
    try:
        return AttackPathAdvisorService().advise(
            getattr(request, "engagement_id", None),
            getattr(request, "profile_result", None),
            getattr(request, "target_ids", None),
            getattr(request, "options", None),
        )
    except BackendError as failure:
        return _backend_failure(failure)


if __name__ == "__main__":
    module.start()
