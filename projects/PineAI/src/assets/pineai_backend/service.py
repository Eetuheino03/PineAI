"""Application service for deterministic and AI-assisted target profiling."""

import datetime
import hashlib
import hmac
from typing import Any, Callable, Dict, List, Optional, Tuple

from .config import (
    ConfigError,
    ensure_pseudonymization_key,
    load_api_key,
    load_settings,
)
from .errors import BackendError
from .openai_client import OpenAIClient, OpenAIClientError
from .profiler import (
    ReconValidationError,
    build_cloud_payload,
    build_deterministic_profiles,
    validate_and_normalize_scan,
)


SCHEMA_VERSION = "1.0"
BACKEND_VERSION = "0.4.0"
ROLES = {
    "corporate",
    "guest",
    "iot_ot",
    "management",
    "public",
    "personal",
    "infrastructure",
    "unknown",
}
INTEREST_LEVELS = {"low", "medium", "high"}


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )


def _resolve_options(
    settings: Dict[str, Any], options: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    if options is None:
        options = {}
    if not isinstance(options, dict):
        raise BackendError("invalid_options", "options must be a JSON object")
    language = options.get("language", settings["language"])
    if language not in ("en", "fi"):
        raise BackendError("invalid_options", "options.language must be 'en' or 'fi'")
    share_ssids = options.get("share_ssids", settings["share_ssids"])
    ai_enabled = options.get("ai_enabled", True)
    if not isinstance(share_ssids, bool):
        raise BackendError(
            "invalid_options", "options.share_ssids must be a boolean"
        )
    if not isinstance(ai_enabled, bool):
        raise BackendError("invalid_options", "options.ai_enabled must be a boolean")
    return {
        "language": language,
        "share_ssids": share_ssids,
        "ai_enabled": ai_enabled,
    }


def _validate_string_list(value: Any, field: str, maximum: int) -> List[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise OpenAIClientError(
            "invalid_ai_output", "{0} must be an array with at most {1} items".format(field, maximum)
        )
    result = []
    for item in value:
        if not isinstance(item, str) or len(item) > 500:
            raise OpenAIClientError(
                "invalid_ai_output", "{0} contains an invalid string".format(field)
            )
        result.append(item)
    return result


def _validate_ai_output(
    ai_output: Dict[str, Any],
    selected_targets: List[Dict[str, Any]],
    all_target_ids: set,
) -> Tuple[str, Dict[str, Dict[str, Any]]]:
    if set(ai_output.keys()) != {"overall_summary", "targets"}:
        raise OpenAIClientError(
            "invalid_ai_output", "AI output contains unexpected top-level fields"
        )
    overall_summary = ai_output["overall_summary"]
    profiles = ai_output["targets"]
    if not isinstance(overall_summary, str) or len(overall_summary) > 2000:
        raise OpenAIClientError(
            "invalid_ai_output", "AI overall_summary is invalid"
        )
    if not isinstance(profiles, list):
        raise OpenAIClientError("invalid_ai_output", "AI targets must be an array")

    expected = {target["target_id"]: target for target in selected_targets}
    validated = {}
    required = {
        "target_id",
        "role",
        "interest",
        "confidence",
        "summary",
        "observations",
        "missing_evidence",
        "related_target_ids",
        "evidence_ids",
    }
    for profile in profiles:
        if not isinstance(profile, dict) or set(profile.keys()) != required:
            raise OpenAIClientError(
                "invalid_ai_output", "AI target profile shape is invalid"
            )
        target_id = profile["target_id"]
        if target_id not in expected or target_id in validated:
            raise OpenAIClientError(
                "invalid_ai_output", "AI returned an unknown or duplicate target"
            )
        if profile["role"] not in ROLES:
            raise OpenAIClientError("invalid_ai_output", "AI role is invalid")
        if profile["interest"] not in INTEREST_LEVELS:
            raise OpenAIClientError("invalid_ai_output", "AI interest is invalid")
        confidence = profile["confidence"]
        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or confidence < 0
            or confidence > 1
        ):
            raise OpenAIClientError("invalid_ai_output", "AI confidence is invalid")
        if not isinstance(profile["summary"], str) or len(profile["summary"]) > 1000:
            raise OpenAIClientError("invalid_ai_output", "AI summary is invalid")

        observations = _validate_string_list(
            profile["observations"], "observations", 8
        )
        missing_evidence = _validate_string_list(
            profile["missing_evidence"], "missing_evidence", 8
        )
        related = _validate_string_list(
            profile["related_target_ids"], "related_target_ids", 10
        )
        evidence_ids = _validate_string_list(
            profile["evidence_ids"], "evidence_ids", 50
        )
        if not set(related).issubset(all_target_ids):
            raise OpenAIClientError(
                "invalid_ai_output", "AI referenced an unknown related target"
            )
        allowed_evidence = {
            evidence["evidence_id"] for evidence in expected[target_id]["evidence"]
        }
        if not set(evidence_ids).issubset(allowed_evidence):
            raise OpenAIClientError(
                "invalid_ai_output", "AI referenced unknown target evidence"
            )
        validated[target_id] = {
            "role": profile["role"],
            "interest": profile["interest"],
            "confidence": float(confidence),
            "summary": profile["summary"],
            "observations": observations,
            "missing_evidence": missing_evidence,
            "related_target_ids": related,
            "evidence_ids": evidence_ids,
        }

    if set(validated) != set(expected):
        raise OpenAIClientError(
            "invalid_ai_output", "AI did not return every selected target"
        )
    return overall_summary, validated


class TargetProfilerService:
    """Coordinate config, privacy filtering, OpenAI, and semantic validation."""

    def __init__(
        self,
        config_dir: Optional[str] = None,
        client_factory: Callable[..., OpenAIClient] = OpenAIClient,
    ):
        self.config_dir = config_dir
        self.client_factory = client_factory

    def _prepare(
        self,
        scan: Any,
        scan_metadata: Optional[Dict[str, Any]],
        options: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        try:
            settings = load_settings(self.config_dir)
            resolved = _resolve_options(settings, options)
            normalized = validate_and_normalize_scan(scan)
            secret = ensure_pseudonymization_key(self.config_dir)
            deterministic = build_deterministic_profiles(
                normalized, secret, settings["max_ai_targets"]
            )
            cloud_payload = build_cloud_payload(
                deterministic,
                secret,
                resolved["share_ssids"],
                resolved["language"],
                scan_metadata,
            )
        except ReconValidationError as failure:
            raise BackendError("invalid_recon", str(failure))
        except ConfigError as failure:
            raise BackendError("configuration_error", str(failure))
        return {
            "settings": settings,
            "options": resolved,
            "secret": secret,
            "deterministic": deterministic,
            "cloud_payload": cloud_payload,
        }

    def prepare_recon(
        self,
        scan: Any,
        scan_metadata: Optional[Dict[str, Any]] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return the exact payload that would be sent to OpenAI."""
        return self._prepare(scan, scan_metadata, options)["cloud_payload"]

    def profile_recon(
        self,
        scan: Any,
        scan_metadata: Optional[Dict[str, Any]] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        prepared = self._prepare(scan, scan_metadata, options)
        settings = prepared["settings"]
        resolved = prepared["options"]
        deterministic = prepared["deterministic"]
        targets = deterministic["targets"]
        result = {
            "schema_version": SCHEMA_VERSION,
            "backend_version": BACKEND_VERSION,
            "generated_at": _utc_now(),
            "scan_summary": deterministic["scan_summary"],
            "targets": targets,
            "overall_summary": None,
            "ai_status": {
                "state": "partial",
                "code": "not_started",
                "message": "Deterministic target profiles are available",
            },
            "model": settings["model"],
            "token_usage": {
                "input_tokens": None,
                "output_tokens": None,
                "total_tokens": None,
            },
        }
        if not resolved["ai_enabled"]:
            result["ai_status"] = {
                "state": "disabled",
                "code": "ai_disabled",
                "message": "AI analysis was disabled for this request",
            }
            return result
        if deterministic["scan_summary"]["ai_target_count"] == 0:
            result["ai_status"] = {
                "state": "complete",
                "code": "no_targets",
                "message": "No targets were available for AI analysis",
            }
            result["overall_summary"] = "No wireless targets were present."
            return result

        try:
            api_key = load_api_key(self.config_dir)
        except ConfigError as failure:
            result["ai_status"] = {
                "state": "partial",
                "code": "configuration_error",
                "message": str(failure),
            }
            return result
        if not api_key:
            result["ai_status"] = {
                "state": "partial",
                "code": "not_configured",
                "message": "OpenAI API key is not configured",
            }
            return result

        safety_digest = hmac.new(
            prepared["secret"],
            b"pineai-safety-identifier",
            hashlib.sha256,
        ).hexdigest()[:32]
        try:
            client = self.client_factory(api_key=api_key, model=settings["model"])
            ai_output, usage = client.profile(
                prepared["cloud_payload"],
                resolved["language"],
                "device_{0}".format(safety_digest),
            )
            selected = [target for target in targets if target["ai_selected"]]
            overall, validated = _validate_ai_output(
                ai_output, selected, {target["target_id"] for target in targets}
            )
            for target in targets:
                if target["target_id"] in validated:
                    target["ai_profile"] = validated[target["target_id"]]
            result["overall_summary"] = overall
            result["token_usage"] = usage
            result["ai_status"] = {
                "state": "complete",
                "code": "ok",
                "message": "AI target profiling completed",
            }
        except OpenAIClientError as failure:
            result["ai_status"] = {
                "state": "partial",
                "code": failure.code,
                "message": failure.safe_message,
            }
        return result
