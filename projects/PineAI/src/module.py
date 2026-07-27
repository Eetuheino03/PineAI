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
from pineai_backend.adaptive_recon_service import AdaptiveReconService  # noqa: E402
from pineai_backend.advisor_service import AttackPathAdvisorService  # noqa: E402
from pineai_backend.config import (  # noqa: E402
    ConfigError,
    delete_api_key,
    public_status,
    save_api_key,
    update_frontend_settings,
)
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
            "language": status["language"],
            "share_ssids": status["share_ssids"],
            "supported_band_count": len(status["supported_bands"]),
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


def _configuration_failure(failure: ConfigError):
    return (
        {
            "error": {
                "code": "configuration_error",
                "message": str(failure),
            }
        },
        False,
    )


@module.handles_action("get_settings")
def get_settings(_request: Request):
    """Return the non-secret settings used by the frontend."""
    try:
        status = public_status()
        return {
            "schema_version": "1.0",
            "model": status["model"],
            "language": status["language"],
            "share_ssids": status["share_ssids"],
            "max_ai_targets": status["max_ai_targets"],
            "supported_bands": status["supported_bands"],
            "api_key_configured": status["configured"],
            "api_key_source": status["key_source"],
        }
    except ConfigError as failure:
        return _configuration_failure(failure)


@module.handles_action("update_settings")
def update_settings(request: Request):
    """Persist only the frontend-editable non-secret settings."""
    try:
        status = update_frontend_settings(getattr(request, "settings", None))
        return {
            "schema_version": "1.0",
            "model": status["model"],
            "language": status["language"],
            "share_ssids": status["share_ssids"],
            "max_ai_targets": status["max_ai_targets"],
            "supported_bands": status["supported_bands"],
            "api_key_configured": status["configured"],
            "api_key_source": status["key_source"],
        }
    except ConfigError as failure:
        return _configuration_failure(failure)


@module.handles_action("set_openai_api_key")
def set_openai_api_key(request: Request):
    """Store a key without echoing it back to the browser."""
    try:
        transport_secure = getattr(request, "transport_secure", None)
        insecure_acknowledged = getattr(
            request, "insecure_transport_acknowledged", False
        )
        if not isinstance(transport_secure, bool):
            raise ConfigError("transport_secure must be a boolean")
        if not transport_secure and insecure_acknowledged is not True:
            raise ConfigError(
                "insecure HTTP key submission requires explicit acknowledgement"
            )
        save_api_key(getattr(request, "api_key", None))
        status = public_status()
        return {
            "api_key_configured": status["configured"],
            "api_key_source": status["key_source"],
        }
    except ConfigError as failure:
        return _configuration_failure(failure)


@module.handles_action("delete_openai_api_key")
def delete_openai_api_key(_request: Request):
    """Delete the managed key file and report any environment override."""
    try:
        delete_api_key()
        status = public_status()
        return {
            "api_key_configured": status["configured"],
            "api_key_source": status["key_source"],
        }
    except ConfigError as failure:
        return _configuration_failure(failure)


@module.handles_action("prepare_profile_recon")
def prepare_profile_recon(request: Request):
    """Return the exact privacy-filtered profiler cloud payload."""
    try:
        return TargetProfilerService().prepare_recon(
            getattr(request, "scan", None),
            getattr(request, "scan_metadata", None),
            getattr(request, "options", None),
        )
    except BackendError as failure:
        return _backend_failure(failure)


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


@module.handles_action("prepare_attack_paths")
def prepare_attack_paths(request: Request):
    """Return the exact policy-filtered advisor cloud payload."""
    try:
        return AttackPathAdvisorService().prepare_advice(
            getattr(request, "engagement_id", None),
            getattr(request, "profile_result", None),
            getattr(request, "target_ids", None),
            getattr(request, "options", None),
        )
    except BackendError as failure:
        return _backend_failure(failure)


def _adaptive_request(request: Request, method: str):
    service = AdaptiveReconService()
    function = getattr(service, method)
    return function(
        getattr(request, "engagement_id", None),
        getattr(request, "expected_revision", None),
        getattr(request, "profile_result", None),
        getattr(request, "advisor_result", None),
        getattr(request, "selected_path_ids", None),
        getattr(request, "history", None),
        getattr(request, "device_context", None),
        getattr(request, "options", None),
    )


@module.handles_action("adaptive_recon_capabilities")
def adaptive_recon_capabilities(_request: Request):
    try:
        return AdaptiveReconService().capabilities()
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("prepare_adaptive_recon")
def prepare_adaptive_recon(request: Request):
    try:
        return _adaptive_request(request, "prepare")
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("recommend_adaptive_recon")
def recommend_adaptive_recon(request: Request):
    try:
        return _adaptive_request(request, "recommend")
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("get_recon_plan")
def get_recon_plan(request: Request):
    try:
        return AdaptiveReconService().get_plan(
            getattr(request, "engagement_id", None),
            getattr(request, "plan_id", None),
        )
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("list_recon_plans")
def list_recon_plans(request: Request):
    try:
        return {
            "plans": AdaptiveReconService().list_plans(
                getattr(request, "engagement_id", None)
            )
        }
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("approve_recon_plan")
def approve_recon_plan(request: Request):
    try:
        return AdaptiveReconService().approve(
            getattr(request, "engagement_id", None),
            getattr(request, "expected_revision", None),
            getattr(request, "plan_id", None),
            getattr(request, "candidate_id", None),
            getattr(request, "device_context", None),
        )
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("record_recon_scan_started")
def record_recon_scan_started(request: Request):
    try:
        return AdaptiveReconService().record_started(
            getattr(request, "engagement_id", None),
            getattr(request, "expected_revision", None),
            getattr(request, "plan_id", None),
            getattr(request, "start_response", None),
        )
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("record_recon_scan_finished")
def record_recon_scan_finished(request: Request):
    try:
        return AdaptiveReconService().record_finished(
            getattr(request, "engagement_id", None),
            getattr(request, "expected_revision", None),
            getattr(request, "plan_id", None),
            getattr(request, "outcome", None),
            getattr(request, "scan_id", None),
            getattr(request, "profile_result", None),
            getattr(request, "error_code", None),
        )
    except BackendError as failure:
        return _backend_failure(failure)


if __name__ == "__main__":
    module.start()
