#!/usr/bin/env python3

"""Hak5 module adapter for PineAI Baseline & Drift."""

import logging
import os
import sys

from pineapple.modules import Module, Request


ASSETS_DIRECTORY = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "assets"
)
if ASSETS_DIRECTORY not in sys.path:
    sys.path.insert(0, ASSETS_DIRECTORY)

from pineai_backend import __version__  # noqa: E402


module = Module("PineAI", logging.INFO)


def _backend_failure(failure):
    return (
        {"error": {"code": failure.code, "message": failure.safe_message}},
        False,
    )


def _configuration_failure(failure):
    return (
        {"error": {"code": "configuration_error", "message": str(failure)}},
        False,
    )


def _service():
    # Keep Mark VII cold-start quick: import the analysis graph only when an
    # assurance action is actually requested.
    from pineai_backend.assurance_service import AssuranceService

    return AssuranceService()


def _store():
    from pineai_backend.assessment_store import AssessmentStore

    return AssessmentStore()


def _settings_response(status):
    return {
        "schema_version": "1.0",
        "model": status["model"],
        "language": status["language"],
        "share_ssids": status["share_ssids"],
        "api_key_configured": status["configured"],
        "api_key_source": status["key_source"],
    }


def _reject_deprecated_comparison_fields(request):
    from pineai_backend.errors import BackendError

    if getattr(request, "position_confirmation", None) is not None:
        raise BackendError(
            "invalid_request",
            "position_confirmation is not supported; use absolute measurement_context fields",
        )


@module.handles_action("health")
def health(_request: Request):
    """Return only safe startup information and never import analysis services."""
    from pineai_backend.config import ConfigError, public_status

    try:
        status = public_status()
        return {
            "status": "ok",
            "module": "PineAI",
            "product_mode": "baseline_and_drift",
            "version": __version__,
            "backend_version": __version__,
            "model": status["model"],
            "api_key_configured": status["configured"],
            "language": status["language"],
            "share_ssids": status["share_ssids"],
            "offline_complete": True,
            "recon_control": False,
        }
    except ConfigError as failure:
        return _configuration_failure(failure)


@module.handles_action("get_settings")
def get_settings(_request: Request):
    from pineai_backend.config import ConfigError, public_status

    try:
        return _settings_response(public_status())
    except ConfigError as failure:
        return _configuration_failure(failure)


@module.handles_action("update_settings")
def update_settings(request: Request):
    from pineai_backend.config import ConfigError, update_frontend_settings

    try:
        return _settings_response(
            update_frontend_settings(getattr(request, "settings", None))
        )
    except ConfigError as failure:
        return _configuration_failure(failure)


@module.handles_action("set_openai_api_key")
def set_openai_api_key(request: Request):
    from pineai_backend.config import ConfigError, public_status, save_api_key

    try:
        transport_secure = getattr(request, "transport_secure", None)
        acknowledged = getattr(
            request, "insecure_transport_acknowledged", False
        )
        if not isinstance(transport_secure, bool):
            raise ConfigError("transport_secure must be a boolean")
        if not transport_secure and acknowledged is not True:
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
    from pineai_backend.config import ConfigError, delete_api_key, public_status

    try:
        delete_api_key()
        status = public_status()
        return {
            "api_key_configured": status["configured"],
            "api_key_source": status["key_source"],
        }
    except ConfigError as failure:
        return _configuration_failure(failure)


@module.handles_action("assurance_capabilities")
def assurance_capabilities(_request: Request):
    from pineai_backend.errors import BackendError

    try:
        return _service().capabilities()
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("create_assessment")
def create_assessment(request: Request):
    from pineai_backend.errors import BackendError

    try:
        return _store().create(getattr(request, "assessment", None))
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("get_assessment")
def get_assessment(request: Request):
    from pineai_backend.errors import BackendError

    try:
        return _service().assessment_detail(
            getattr(request, "assessment_id", None),
            getattr(request, "after_sequence", 0),
            getattr(request, "limit", 100),
        )
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("list_assessments")
def list_assessments(request: Request):
    from pineai_backend.errors import BackendError

    try:
        return {
            "schema_version": "1.0",
            "assessments": _store().list(
                getattr(request, "include_archived", False)
            ),
        }
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("update_assessment")
def update_assessment(request: Request):
    from pineai_backend.errors import BackendError

    try:
        return _store().update(
            getattr(request, "assessment_id", None),
            getattr(request, "expected_revision", None),
            getattr(request, "changes", None),
        )
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("archive_assessment")
def archive_assessment(request: Request):
    from pineai_backend.errors import BackendError

    try:
        return _store().archive(
            getattr(request, "assessment_id", None),
            getattr(request, "expected_revision", None),
        )
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("resolve_recon")
def resolve_recon(request: Request):
    from pineai_backend.errors import BackendError

    try:
        return _service().resolve_recon(
            getattr(request, "scan", None),
            getattr(request, "scan_metadata", None),
        )
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("create_baseline_version")
def create_baseline_version(request: Request):
    from pineai_backend.errors import BackendError

    try:
        result = _service().create_baseline_version(
            getattr(request, "assessment_id", None),
            getattr(request, "expected_revision", None),
            getattr(request, "scan", None),
            getattr(request, "scan_metadata", None),
            getattr(request, "label", ""),
        )
        result["baseline"] = result.pop("baseline_version")
        return result
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("list_baseline_versions")
def list_baseline_versions(request: Request):
    from pineai_backend.errors import BackendError

    try:
        return _service().list_baseline_versions(
            getattr(request, "assessment_id", None)
        )
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("activate_baseline_version")
def activate_baseline_version(request: Request):
    from pineai_backend.errors import BackendError

    try:
        result = _store().activate_baseline_version(
            getattr(request, "assessment_id", None),
            getattr(request, "expected_revision", None),
            getattr(request, "baseline_version", None),
        )
        result["baseline"] = result.pop("baseline_version")
        return result
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("compare_recon")
def compare_recon(request: Request):
    from pineai_backend.errors import BackendError

    try:
        _reject_deprecated_comparison_fields(request)
        return _service().compare_recon(
            getattr(request, "assessment_id", None),
            getattr(request, "scan", None),
            getattr(request, "scan_metadata", None),
        )
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("analyze_recon")
def analyze_recon(request: Request):
    from pineai_backend.errors import BackendError

    try:
        _reject_deprecated_comparison_fields(request)
        return _service().analyze_recon(
            getattr(request, "assessment_id", None),
            getattr(request, "expected_revision", None),
            getattr(request, "scan", None),
            getattr(request, "scan_metadata", None),
        )
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("list_findings")
def list_findings(request: Request):
    from pineai_backend.errors import BackendError

    try:
        status = getattr(request, "status", None)
        statuses = [status] if status is not None else None
        return {
            "schema_version": "1.0",
            "findings": _store().list_findings(
                getattr(request, "assessment_id", None), statuses
            ),
        }
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("update_finding")
def update_finding(request: Request):
    from pineai_backend.errors import BackendError

    try:
        return _store().update_finding(
            getattr(request, "assessment_id", None),
            getattr(request, "expected_revision", None),
            getattr(request, "finding_id", None),
            getattr(request, "status", None),
            getattr(request, "note", ""),
        )
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("prepare_ai_analysis")
def prepare_ai_analysis(request: Request):
    from pineai_backend.errors import BackendError

    try:
        return _service().prepare_ai_analysis(
            getattr(request, "assessment_id", None),
            getattr(request, "comparison_id", None),
            getattr(request, "finding_ids", None),
            getattr(request, "options", None),
        )
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("generate_ai_analysis")
def generate_ai_analysis(request: Request):
    from pineai_backend.errors import BackendError

    try:
        return _service().generate_ai_analysis(
            getattr(request, "assessment_id", None),
            getattr(request, "comparison_id", None),
            getattr(request, "finding_ids", None),
            getattr(request, "options", None),
        )
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("generate_report")
def generate_report_action(request: Request):
    from pineai_backend.errors import BackendError

    try:
        return _service().generate_report(
            getattr(request, "assessment_id", None),
            getattr(request, "comparison_id", None),
            getattr(request, "format", None),
            getattr(request, "ai_analysis", None),
        )
    except BackendError as failure:
        return _backend_failure(failure)


if __name__ == "__main__":
    module.start()
