"""Optional, non-authoritative AI explanations for deterministic findings."""

import hashlib
import hmac
import json
from typing import Any, Callable, Dict, List, Optional

from .assurance import build_ai_payload, canonical_digest
from .config import (
    ConfigError,
    ensure_pseudonymization_key,
    load_api_key,
    load_settings,
)
from .errors import BackendError
from .openai_client import OpenAIClient, OpenAIClientError


AI_ANALYSIS_SCHEMA_VERSION = "1.0"
FORBIDDEN_VALIDATION_TERMS = (
    "deauth",
    "evil twin",
    "credential",
    "password",
    "harvest",
    "impersonat",
    "aircrack",
    "hcxdump",
    "mdk4",
    "shell command",
    "run command",
    "execute command",
)


def _text(value: Any, field: str, maximum: int) -> str:
    if not isinstance(value, str) or len(value) > maximum:
        raise BackendError("invalid_ai_output", "{0} is invalid".format(field))
    return value


def _text_list(value: Any, field: str, maximum: int, item_maximum: int) -> List[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise BackendError("invalid_ai_output", "{0} is invalid".format(field))
    return [
        _text(item, "{0} item".format(field), item_maximum)
        for item in value
    ]


def validate_ai_analysis(
    value: Any, findings: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Validate provider output semantically against authoritative local data."""
    if not isinstance(value, dict) or set(value) != {
        "summary",
        "finding_explanations",
        "report_sections",
    }:
        raise BackendError("invalid_ai_output", "AI analysis shape is invalid")
    known_findings = {item["finding_id"]: item for item in findings}
    explanations = value["finding_explanations"]
    if not isinstance(explanations, list) or len(explanations) > len(findings):
        raise BackendError(
            "invalid_ai_output", "AI finding explanations are invalid"
        )
    seen = set()
    validated_explanations = []
    for item in explanations:
        required = {
            "finding_id",
            "explanation",
            "alternative_explanations",
            "validation_steps",
            "evidence_ids",
        }
        if not isinstance(item, dict) or set(item) != required:
            raise BackendError(
                "invalid_ai_output", "AI finding explanation shape is invalid"
            )
        finding_id = item["finding_id"]
        if finding_id not in known_findings or finding_id in seen:
            raise BackendError(
                "invalid_ai_reference", "AI returned an unknown finding reference"
            )
        seen.add(finding_id)
        allowed_evidence = set(known_findings[finding_id].get("evidence_ids", []))
        evidence_ids = item["evidence_ids"]
        if (
            not isinstance(evidence_ids, list)
            or len(evidence_ids) > 100
            or any(
                not isinstance(reference, str)
                or reference not in allowed_evidence
                for reference in evidence_ids
            )
        ):
            raise BackendError(
                "invalid_ai_reference", "AI returned an unknown evidence reference"
            )
        validation_steps = _text_list(
            item["validation_steps"], "validation_steps", 8, 1000
        )
        for step in validation_steps:
            normalized = step.casefold()
            if any(term in normalized for term in FORBIDDEN_VALIDATION_TERMS):
                raise BackendError(
                    "unsafe_ai_output",
                    "AI returned a validation step outside the safe advisory boundary",
                )
        validated_explanations.append(
            {
                "finding_id": finding_id,
                "explanation": _text(item["explanation"], "explanation", 2000),
                "alternative_explanations": _text_list(
                    item["alternative_explanations"],
                    "alternative_explanations",
                    5,
                    1000,
                ),
                "validation_steps": validation_steps,
                "evidence_ids": sorted(set(evidence_ids)),
            }
        )

    sections = value["report_sections"]
    if not isinstance(sections, dict) or set(sections) != {
        "executive_summary",
        "technical_summary",
        "change_summary",
        "limitations",
    }:
        raise BackendError("invalid_ai_output", "AI report sections are invalid")
    return {
        "summary": _text(value["summary"], "summary", 3000),
        "finding_explanations": sorted(
            validated_explanations, key=lambda item: item["finding_id"]
        ),
        "report_sections": {
            "executive_summary": _text(
                sections["executive_summary"], "executive_summary", 4000
            ),
            "technical_summary": _text(
                sections["technical_summary"], "technical_summary", 8000
            ),
            "change_summary": _text(
                sections["change_summary"], "change_summary", 4000
            ),
            "limitations": _text_list(
                sections["limitations"], "limitations", 10, 1000
            ),
        },
    }


def _options(
    settings: Dict[str, Any], value: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    if value is None:
        value = {}
    if not isinstance(value, dict) or set(value) - {
        "language",
        "share_ssids",
    }:
        raise BackendError("invalid_options", "AI options are invalid")
    language = value.get("language", settings["language"])
    share_ssids = value.get("share_ssids", settings["share_ssids"])
    if language not in ("en", "fi") or not isinstance(share_ssids, bool):
        raise BackendError("invalid_options", "AI options are invalid")
    return {"language": language, "share_ssids": share_ssids}


class AssuranceAIService:
    """Prepare and optionally execute a privacy-filtered explanation request."""

    def __init__(
        self,
        config_dir: Optional[str] = None,
        client_factory: Callable[..., OpenAIClient] = OpenAIClient,
    ):
        self.config_dir = config_dir
        self.client_factory = client_factory

    def prepare(
        self,
        assessment: Dict[str, Any],
        comparison: Dict[str, Any],
        findings: List[Dict[str, Any]],
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        try:
            settings = load_settings(self.config_dir)
        except ConfigError as failure:
            raise BackendError("configuration_error", str(failure))
        resolved = _options(settings, options)
        payload = build_ai_payload(
            assessment,
            comparison,
            findings,
            resolved["language"],
            resolved["share_ssids"],
        )
        return {
            "schema_version": AI_ANALYSIS_SCHEMA_VERSION,
            "model": settings["model"],
            "language": resolved["language"],
            "share_ssids": resolved["share_ssids"],
            "cloud_payload": payload,
        }

    def generate(
        self,
        assessment: Dict[str, Any],
        comparison: Dict[str, Any],
        findings: List[Dict[str, Any]],
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        prepared = self.prepare(assessment, comparison, findings, options)
        try:
            api_key = load_api_key(self.config_dir)
            secret = ensure_pseudonymization_key(self.config_dir)
        except ConfigError as failure:
            raise BackendError("configuration_error", str(failure))
        if not api_key:
            return {
                "schema_version": AI_ANALYSIS_SCHEMA_VERSION,
                "analysis": None,
                "ai_status": {
                    "state": "unavailable",
                    "code": "api_key_missing",
                    "message": "OpenAI API key is not configured",
                },
                "model": prepared["model"],
                "token_usage": {},
            }
        safety_identifier = hmac.new(
            secret,
            str(assessment.get("assessment_id", "assessment")).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()[:32]
        try:
            raw, usage = self.client_factory(
                api_key, prepared["model"]
            ).analyze_assurance(
                prepared["cloud_payload"],
                prepared["language"],
                safety_identifier,
            )
            validated = validate_ai_analysis(raw, findings)
        except OpenAIClientError as failure:
            return {
                "schema_version": AI_ANALYSIS_SCHEMA_VERSION,
                "analysis": None,
                "ai_status": {
                    "state": "partial",
                    "code": failure.code,
                    "message": failure.safe_message,
                    "retryable": failure.retryable,
                },
                "model": prepared["model"],
                "token_usage": {},
            }
        analysis_seed = {
            "assessment_id": assessment.get("assessment_id"),
            "comparison_id": comparison.get("comparison_id"),
            "model": prepared["model"],
            "language": prepared["language"],
            "analysis": validated,
        }
        analysis = {
            "analysis_id": "analysis_{0}".format(
                canonical_digest(analysis_seed)[:16]
            ),
            "model": prepared["model"],
            "language": prepared["language"],
        }
        analysis.update(validated)
        return {
            "schema_version": AI_ANALYSIS_SCHEMA_VERSION,
            "analysis": analysis,
            "ai_status": {"state": "complete", "code": None, "message": None},
            "model": prepared["model"],
            "token_usage": usage,
        }
