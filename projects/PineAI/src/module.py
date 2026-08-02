#!/usr/bin/env python3

"""Hak5 module adapter for PineAI Baseline & Drift."""

import logging
import os
import re
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


_STORE = None
_SERVICE = None
_REPEATABLE_STORE = None
_REPEATABLE_SERVICE = None
_AUDIT_RUN_REPORT_SERVICE = None


def _reset_singletons():
    """Reset process singletons for test isolation."""
    global _STORE, _SERVICE, _REPEATABLE_STORE, _REPEATABLE_SERVICE
    global _AUDIT_RUN_REPORT_SERVICE
    _STORE = None
    _SERVICE = None
    _REPEATABLE_STORE = None
    _REPEATABLE_SERVICE = None
    _AUDIT_RUN_REPORT_SERVICE = None


def _store():
    global _STORE
    if _STORE is None:
        from pineai_backend.repeatable_audit_store import RepeatableAuditStore

        _STORE = RepeatableAuditStore()
    return _STORE


def _service():
    global _SERVICE
    if _SERVICE is None:
        from pineai_backend.assurance_service import AssuranceService
        _SERVICE = AssuranceService(store=_store())
    return _SERVICE


def _repeatable_store():
    global _REPEATABLE_STORE
    if _REPEATABLE_STORE is None:
        _REPEATABLE_STORE = _store()
    return _REPEATABLE_STORE


def _repeatable_service():
    global _REPEATABLE_SERVICE
    if _REPEATABLE_SERVICE is None:
        from pineai_backend.repeatable_audit_service import RepeatableAuditService

        _REPEATABLE_SERVICE = RepeatableAuditService(store=_repeatable_store())
    return _REPEATABLE_SERVICE


def _audit_run_report_service():
    global _AUDIT_RUN_REPORT_SERVICE
    if _AUDIT_RUN_REPORT_SERVICE is None:
        from pineai_backend.audit_run_report import AuditRunReportService

        _AUDIT_RUN_REPORT_SERVICE = AuditRunReportService(
            store=_repeatable_store()
        )
    return _AUDIT_RUN_REPORT_SERVICE


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


def _validate_v07_request_fields(request, allowed_fields):
    """Reject unknown public v0.7 payload fields when Request is inspectable.

    Hak5 exposes action payload members as Request attributes.  Private
    implementation attributes and the framework's routing attributes are not
    payload, so they are deliberately ignored.  If a future Request
    implementation does not expose an attribute dictionary, downstream
    nested-object and scalar validation remains authoritative.
    """
    from pineai_backend.errors import BackendError

    try:
        attributes = vars(request)
    except TypeError:
        return
    if not isinstance(attributes, dict):
        return
    framework_fields = {"action", "module"}
    supplied = {
        key
        for key in attributes
        if isinstance(key, str)
        and not key.startswith("_")
        and key not in framework_fields
    }
    unsupported = sorted(supplied - set(allowed_fields))
    if unsupported:
        raise BackendError(
            "invalid_request",
            "request contains unsupported fields: {0}".format(
                ", ".join(unsupported)
            ),
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
            "product_name": "PineAssure",
            "product_mode": "repeatable_field_audit",
            "product_position": "Wireless Assurance for WiFi Pineapple",
            "tagline": "Baseline. Detect drift. Prove changes.",
            "version": __version__,
            "backend_version": __version__,
            "model": status["model"],
            "api_key_configured": status["configured"],
            "language": status["language"],
            "share_ssids": status["share_ssids"],
            "offline_complete": True,
            "recon_control": False,
            "identity": status["identity"],
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


@module.handles_action("platform_capabilities")
def platform_capabilities(_request: Request):
    from pineai_backend.errors import BackendError
    from pineai_backend.platform import platform_capabilities as get_platform_capabilities

    try:
        return get_platform_capabilities()
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("list_measurement_profiles")
def list_measurement_profiles(request: Request):
    from pineai_backend.errors import BackendError

    try:
        return {
            "schema_version": "1.0",
            "measurement_profiles": _store().list_measurement_profiles(
                getattr(request, "include_archived", False)
            ),
        }
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("create_measurement_profile")
def create_measurement_profile(request: Request):
    from pineai_backend.errors import BackendError

    try:
        return _service().create_measurement_profile(
            getattr(request, "profile", None)
        )
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("update_measurement_profile")
def update_measurement_profile(request: Request):
    from pineai_backend.errors import BackendError

    try:
        return _service().update_measurement_profile(
            getattr(request, "measurement_profile_id", None),
            getattr(request, "expected_revision", None),
            getattr(request, "changes", None),
        )
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("archive_measurement_profile")
def archive_measurement_profile(request: Request):
    from pineai_backend.errors import BackendError

    try:
        return _service().archive_measurement_profile(
            getattr(request, "measurement_profile_id", None),
            getattr(request, "expected_revision", None),
        )
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("create_assessment")
def create_assessment(request: Request):
    from pineai_backend.errors import BackendError

    try:
        return _service().create_assessment(
            getattr(request, "assessment", None)
        )
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


@module.handles_action("preview_consensus_baseline")
def preview_consensus_baseline(request: Request):
    from pineai_backend.errors import BackendError

    try:
        return _service().preview_consensus_baseline(
            getattr(request, "observations", None),
            getattr(request, "max_source_age_hours", 24),
        )
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("create_consensus_baseline_version")
def create_consensus_baseline_version(request: Request):
    from pineai_backend.errors import BackendError

    try:
        result = _service().create_consensus_baseline_version(
            getattr(request, "assessment_id", None),
            getattr(request, "expected_revision", None),
            getattr(request, "observations", None),
            getattr(request, "label", ""),
            getattr(request, "max_source_age_hours", 24),
        )
        result["baseline"] = result.pop("baseline_version")
        return result
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("list_baseline_versions")
def list_baseline_versions(request: Request):
    from pineai_backend.errors import BackendError

    try:
        return {
            "schema_version": "1.0",
            "baseline_versions": _store().list_baseline_versions(
                getattr(request, "assessment_id", None)
            ),
        }
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("get_baseline_version")
def get_baseline_version(request: Request):
    from pineai_backend.errors import BackendError

    try:
        return _service().get_baseline_version(
            getattr(request, "assessment_id", None),
            getattr(
                request,
                "baseline_version_id",
                getattr(request, "baseline_version", None),
            ),
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


@module.handles_action("preview_inventory_csv")
def preview_inventory_csv(request: Request):
    from pineai_backend.errors import BackendError

    try:
        return _service().preview_inventory_csv(
            getattr(request, "content", None),
            getattr(request, "delimiter", "comma"),
        )
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("create_assurance_profile_version")
def create_assurance_profile_version(request: Request):
    from pineai_backend.errors import BackendError

    try:
        result = _service().create_assurance_profile_version(
            getattr(request, "assessment_id", None),
            getattr(request, "expected_revision", None),
            getattr(request, "label", ""),
            getattr(request, "inventory_preview", None),
            getattr(request, "profile", None),
            getattr(request, "coverage_mode", "partial"),
        )
        result["assurance_profile"] = result.pop(
            "assurance_profile_version"
        )
        return result
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("list_assurance_profile_versions")
def list_assurance_profile_versions(request: Request):
    from pineai_backend.errors import BackendError

    try:
        return {
            "schema_version": "1.0",
            "assurance_profile_versions": _store().list_assurance_profile_versions(
                getattr(request, "assessment_id", None)
            ),
        }
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("get_assurance_profile_version")
def get_assurance_profile_version(request: Request):
    from pineai_backend.errors import BackendError

    try:
        return _service().get_assurance_profile_version(
            getattr(request, "assessment_id", None),
            getattr(request, "assurance_profile_version_id", None),
        )
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("activate_assurance_profile_version")
def activate_assurance_profile_version(request: Request):
    from pineai_backend.errors import BackendError

    try:
        result = _service().activate_assurance_profile_version(
            getattr(request, "assessment_id", None),
            getattr(request, "expected_revision", None),
            getattr(request, "assurance_profile_version_id", None),
            getattr(request, "authoritative_confirmation", False),
        )
        result["assurance_profile"] = result.pop(
            "assurance_profile_version"
        )
        return result
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("export_inventory_csv")
def export_inventory_csv(request: Request):
    from pineai_backend.errors import BackendError

    try:
        return _service().export_inventory_csv(
            getattr(request, "assessment_id", None),
            getattr(request, "assurance_profile_version_id", None),
            getattr(request, "delimiter", "comma"),
        )
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


@module.handles_action("list_observed_changes")
def list_observed_changes(request: Request):
    from pineai_backend.errors import BackendError

    try:
        return _service().list_observed_changes(
            getattr(request, "assessment_id", None),
            getattr(request, "comparison_id", None),
        )
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("get_evidence_bundle")
def get_evidence_bundle(request: Request):
    from pineai_backend.errors import BackendError

    try:
        return _service().get_evidence_bundle(
            getattr(request, "assessment_id", None),
            getattr(request, "comparison_id", None),
            getattr(request, "item_id", None),
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


@module.handles_action("prepare_report")
def prepare_report_action(request: Request):
    from pineai_backend.errors import BackendError

    try:
        return _service().prepare_report(
            getattr(request, "assessment_id", None),
            getattr(request, "scope", None),
            getattr(request, "privacy_profile", "local_full"),
            getattr(request, "comparison_id", None),
        )
    except BackendError as failure:
        return _backend_failure(failure)


def _validate_public_generate_report_request(request: Request) -> None:
    from pineai_backend.errors import BackendError

    scope = getattr(request, "scope", None)
    if not isinstance(scope, dict):
        raise BackendError(
            "invalid_report_scope",
            "generate_report action requires explicit scope object",
        )
    scope_type = scope.get("type")
    if scope_type not in ("comparison", "assessment_current", "assessment_history"):
        raise BackendError(
            "invalid_report_scope",
            "scope.type must be comparison, assessment_current, or assessment_history",
        )
    if scope_type == "comparison" and not scope.get("comparison_id"):
        raise BackendError(
            "invalid_report_scope",
            "comparison scope requires scope.comparison_id",
        )
    top_comp_id = getattr(request, "comparison_id", None)
    if top_comp_id and scope.get("comparison_id") and top_comp_id != scope.get("comparison_id"):
        raise BackendError(
            "invalid_report_scope",
            "top-level comparison_id does not match scope.comparison_id",
        )
    scope_digest = getattr(request, "scope_digest", None)
    if not isinstance(scope_digest, str) or len(scope_digest) != 64 or not re.match(r"^[0-9a-fA-F]{64}$", scope_digest):
        raise BackendError(
            "invalid_report_scope",
            "generate_report action requires explicit non-empty scope_digest SHA-256 string",
        )
    fmt = getattr(request, "format", None)
    if fmt not in ("json", "html"):
        raise BackendError(
            "invalid_report_format",
            "format must be json or html",
        )


@module.handles_action("generate_report")
def generate_report_action(request: Request):
    from pineai_backend.errors import BackendError

    try:
        _validate_public_generate_report_request(request)
        return _service().generate_report(
            getattr(request, "assessment_id", None),
            getattr(request, "comparison_id", None),
            getattr(request, "format", None),
            getattr(request, "ai_analysis", None),
            getattr(request, "scope", None),
            getattr(request, "privacy_profile", "local_full"),
            getattr(request, "scope_digest", None),
        )
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("repeatable_audit_capabilities")
def repeatable_audit_capabilities(_request: Request):
    from pineai_backend.errors import BackendError

    try:
        _validate_v07_request_fields(_request, set())
        return _repeatable_service().capabilities()
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("resource_telemetry")
def resource_telemetry_action(request: Request):
    from pineai_backend.assessment_store import ASSESSMENT_ID_PATTERN
    from pineai_backend.errors import BackendError
    from pineai_backend.platform import resource_telemetry

    try:
        _validate_v07_request_fields(request, {"assessment_id"})
        assessment_id = getattr(request, "assessment_id", None)
        if assessment_id is not None and (
            not isinstance(assessment_id, str)
            or not ASSESSMENT_ID_PATTERN.match(assessment_id)
        ):
            raise BackendError(
                "invalid_assessment_id", "assessment_id is invalid"
            )
        return resource_telemetry(
            assessment_id=assessment_id
        )
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("list_measurement_points")
def list_measurement_points(request: Request):
    from pineai_backend.errors import BackendError

    try:
        _validate_v07_request_fields(
            request,
            {"assessment_id", "include_archived", "limit", "offset"},
        )
        return _repeatable_store().list_measurement_points(
            getattr(request, "assessment_id", None),
            getattr(request, "include_archived", False),
            getattr(request, "limit", 50),
            getattr(request, "offset", 0),
        )
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("get_measurement_point")
def get_measurement_point(request: Request):
    from pineai_backend.errors import BackendError

    try:
        _validate_v07_request_fields(
            request, {"assessment_id", "measurement_point_id"}
        )
        return _repeatable_store().get_measurement_point(
            getattr(request, "assessment_id", None),
            getattr(request, "measurement_point_id", None),
        )
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("create_measurement_point")
def create_measurement_point(request: Request):
    from pineai_backend.errors import BackendError

    try:
        _validate_v07_request_fields(
            request,
            {
                "assessment_id",
                "expected_assessment_revision",
                "measurement_point",
            },
        )
        value = getattr(request, "measurement_point", None)
        if not isinstance(value, dict):
            raise BackendError(
                "invalid_measurement_point",
                "measurement_point must be an object",
            )
        if set(value) - {
            "location_label",
            "physical_notes",
            "operator_instructions",
        }:
            raise BackendError(
                "invalid_measurement_point",
                "measurement_point contains unsupported fields",
            )
        return _repeatable_store().create_measurement_point(
            getattr(request, "assessment_id", None),
            getattr(request, "expected_assessment_revision", None),
            value.get("location_label"),
            value.get("physical_notes"),
            value.get("operator_instructions"),
        )
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("update_measurement_point")
def update_measurement_point(request: Request):
    from pineai_backend.errors import BackendError

    try:
        _validate_v07_request_fields(
            request,
            {
                "assessment_id",
                "expected_assessment_revision",
                "measurement_point_id",
                "expected_measurement_point_revision",
                "changes",
            },
        )
        changes = getattr(request, "changes", None)
        if (
            not isinstance(changes, dict)
            or not changes
            or set(changes)
            - {
                "location_label",
                "physical_notes",
                "operator_instructions",
            }
        ):
            raise BackendError(
                "invalid_measurement_point",
                "changes must be a non-empty object with supported fields",
            )
        return _repeatable_store().update_measurement_point(
            getattr(request, "assessment_id", None),
            getattr(request, "expected_assessment_revision", None),
            getattr(request, "measurement_point_id", None),
            getattr(request, "expected_measurement_point_revision", None),
            changes,
        )
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("archive_measurement_point")
def archive_measurement_point(request: Request):
    from pineai_backend.errors import BackendError

    try:
        _validate_v07_request_fields(
            request,
            {
                "assessment_id",
                "expected_assessment_revision",
                "measurement_point_id",
                "expected_measurement_point_revision",
            },
        )
        return _repeatable_store().archive_measurement_point(
            getattr(request, "assessment_id", None),
            getattr(request, "expected_assessment_revision", None),
            getattr(request, "measurement_point_id", None),
            getattr(request, "expected_measurement_point_revision", None),
        )
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("list_audit_runs")
def list_audit_runs(request: Request):
    from pineai_backend.errors import BackendError

    try:
        _validate_v07_request_fields(
            request, {"assessment_id", "limit", "offset"}
        )
        return _repeatable_store().list_audit_runs(
            getattr(request, "assessment_id", None),
            getattr(request, "limit", 50),
            getattr(request, "offset", 0),
        )
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("get_audit_run")
def get_audit_run(request: Request):
    from pineai_backend.errors import BackendError

    try:
        _validate_v07_request_fields(
            request, {"assessment_id", "audit_run_id"}
        )
        return _repeatable_store().get_audit_run(
            getattr(request, "assessment_id", None),
            getattr(request, "audit_run_id", None),
        )
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("create_audit_run")
def create_audit_run(request: Request):
    from pineai_backend.errors import BackendError

    try:
        _validate_v07_request_fields(
            request,
            {
                "assessment_id",
                "expected_assessment_revision",
                "audit_run",
            },
        )
        return _repeatable_store().create_audit_run(
            getattr(request, "assessment_id", None),
            getattr(request, "expected_assessment_revision", None),
            getattr(request, "audit_run", None),
        )
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("start_audit_run")
def start_audit_run(request: Request):
    from pineai_backend.errors import BackendError

    try:
        _validate_v07_request_fields(
            request,
            {
                "assessment_id",
                "expected_assessment_revision",
                "audit_run_id",
                "expected_audit_run_revision",
            },
        )
        return _repeatable_store().start_audit_run(
            getattr(request, "assessment_id", None),
            getattr(request, "expected_assessment_revision", None),
            getattr(request, "audit_run_id", None),
            getattr(request, "expected_audit_run_revision", None),
        )
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("cancel_audit_run")
def cancel_audit_run(request: Request):
    from pineai_backend.errors import BackendError

    try:
        _validate_v07_request_fields(
            request,
            {
                "assessment_id",
                "expected_assessment_revision",
                "audit_run_id",
                "expected_audit_run_revision",
                "reason",
            },
        )
        return _repeatable_store().cancel_audit_run(
            getattr(request, "assessment_id", None),
            getattr(request, "expected_assessment_revision", None),
            getattr(request, "audit_run_id", None),
            getattr(request, "expected_audit_run_revision", None),
            getattr(request, "reason", None),
        )
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("complete_audit_run")
def complete_audit_run(request: Request):
    from pineai_backend.errors import BackendError

    try:
        _validate_v07_request_fields(
            request,
            {
                "assessment_id",
                "expected_assessment_revision",
                "audit_run_id",
                "expected_audit_run_revision",
            },
        )
        return _repeatable_store().complete_audit_run(
            getattr(request, "assessment_id", None),
            getattr(request, "expected_assessment_revision", None),
            getattr(request, "audit_run_id", None),
            getattr(request, "expected_audit_run_revision", None),
        )
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("resolve_audit_measurement")
def resolve_audit_measurement(request: Request):
    from pineai_backend.errors import BackendError

    try:
        _validate_v07_request_fields(
            request,
            {
                "assessment_id",
                "expected_assessment_revision",
                "audit_run_id",
                "expected_audit_run_revision",
                "measurement_id",
                "expected_measurement_revision",
                "scan",
                "scan_metadata",
            },
        )
        return _repeatable_service().resolve_measurement(
            getattr(request, "assessment_id", None),
            getattr(request, "expected_assessment_revision", None),
            getattr(request, "audit_run_id", None),
            getattr(request, "expected_audit_run_revision", None),
            getattr(request, "measurement_id", None),
            getattr(request, "expected_measurement_revision", None),
            getattr(request, "scan", None),
            getattr(request, "scan_metadata", None),
        )
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("save_audit_measurement_comparison")
def save_audit_measurement_comparison(request: Request):
    from pineai_backend.errors import BackendError

    try:
        _validate_v07_request_fields(
            request,
            {
                "assessment_id",
                "expected_assessment_revision",
                "audit_run_id",
                "expected_audit_run_revision",
                "measurement_id",
                "expected_measurement_revision",
            },
        )
        return _repeatable_service().save_comparison(
            getattr(request, "assessment_id", None),
            getattr(request, "expected_assessment_revision", None),
            getattr(request, "audit_run_id", None),
            getattr(request, "expected_audit_run_revision", None),
            getattr(request, "measurement_id", None),
            getattr(request, "expected_measurement_revision", None),
        )
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("retry_audit_measurement")
def retry_audit_measurement(request: Request):
    from pineai_backend.errors import BackendError

    try:
        _validate_v07_request_fields(
            request,
            {
                "assessment_id",
                "expected_assessment_revision",
                "audit_run_id",
                "expected_audit_run_revision",
                "measurement_id",
                "expected_measurement_revision",
            },
        )
        return _repeatable_store().retry_audit_measurement(
            getattr(request, "assessment_id", None),
            getattr(request, "expected_assessment_revision", None),
            getattr(request, "audit_run_id", None),
            getattr(request, "expected_audit_run_revision", None),
            getattr(request, "measurement_id", None),
            getattr(request, "expected_measurement_revision", None),
        )
    except BackendError as failure:
        return _backend_failure(failure)


@module.handles_action("generate_audit_run_report")
def generate_audit_run_report(request: Request):
    from pineai_backend.errors import BackendError

    try:
        _validate_v07_request_fields(
            request,
            {"assessment_id", "audit_run_id", "format", "privacy_profile"},
        )
        return _audit_run_report_service().generate(
            getattr(request, "assessment_id", None),
            getattr(request, "audit_run_id", None),
            getattr(request, "format", None),
            getattr(request, "privacy_profile", None),
        )
    except BackendError as failure:
        return _backend_failure(failure)


if __name__ == "__main__":
    module.start()
