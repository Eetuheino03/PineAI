"""Application service for persistent, advisory attack-path planning."""

import datetime
import hashlib
import hmac
from typing import Any, Callable, Dict, List, Optional

from .advisor import (
    ADVISOR_SCHEMA_VERSION,
    MAX_PATHS_PER_TARGET,
    advisor_capabilities,
    build_advisor_cloud_payload,
    build_candidate_paths,
    deterministic_results,
    validate_advisor_target_ids,
    validate_profile_result,
)
from .config import (
    ConfigError,
    ensure_pseudonymization_key,
    load_api_key,
    load_settings,
)
from .engagement_store import EngagementStore
from .errors import BackendError
from .openai_client import OpenAIClient, OpenAIClientError


BACKEND_VERSION = "0.4.0"


def _generated_at() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )


def _options(settings: Dict[str, Any], value: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if value is None:
        value = {}
    if not isinstance(value, dict) or set(value) - {
        "language",
        "share_ssids",
        "ai_enabled",
    }:
        raise BackendError("invalid_options", "advisor options are invalid")
    language = value.get("language", settings["language"])
    share_ssids = value.get("share_ssids", settings["share_ssids"])
    ai_enabled = value.get("ai_enabled", True)
    if language not in ("en", "fi"):
        raise BackendError("invalid_options", "language must be 'en' or 'fi'")
    if not isinstance(share_ssids, bool):
        raise BackendError("invalid_options", "share_ssids must be a boolean")
    if not isinstance(ai_enabled, bool):
        raise BackendError("invalid_options", "ai_enabled must be a boolean")
    return {
        "language": language,
        "share_ssids": share_ssids,
        "ai_enabled": ai_enabled,
    }


def _validate_text_list(value: Any, field: str, maximum: int) -> List[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise OpenAIClientError(
            "invalid_ai_output",
            "{0} must contain at most {1} values".format(field, maximum),
        )
    result = []
    for item in value:
        if not isinstance(item, str) or len(item) > 500:
            raise OpenAIClientError(
                "invalid_ai_output", "{0} contains an invalid string".format(field)
            )
        result.append(item)
    return result


def _validate_ai_advice(
    value: Any,
    target_ids: List[str],
    candidates: Dict[str, List[Dict[str, Any]]],
    targets: Dict[str, Dict[str, Any]],
) -> Dict[str, List[Dict[str, Any]]]:
    if not isinstance(value, dict) or set(value) != {"targets"}:
        raise OpenAIClientError("invalid_ai_output", "AI advice shape is invalid")
    target_values = value["targets"]
    if not isinstance(target_values, list):
        raise OpenAIClientError("invalid_ai_output", "AI targets must be an array")
    result = {}
    for target_value in target_values:
        if not isinstance(target_value, dict) or set(target_value) != {
            "target_id",
            "paths",
        }:
            raise OpenAIClientError("invalid_ai_output", "AI target result is invalid")
        target_id = target_value["target_id"]
        if target_id not in target_ids or target_id in result:
            raise OpenAIClientError(
                "invalid_ai_output", "AI returned an unknown or duplicate target"
            )
        paths = target_value["paths"]
        if not isinstance(paths, list) or len(paths) > MAX_PATHS_PER_TARGET:
            raise OpenAIClientError("invalid_ai_output", "AI paths are invalid")
        known_paths = {path["path_id"]: path for path in candidates[target_id]}
        allowed_evidence = set(targets[target_id]["evidence_ids"])
        selected = []
        seen_paths = set()
        seen_ranks = set()
        for path in paths:
            required = {
                "path_id",
                "rank",
                "confidence",
                "rationale",
                "evidence_ids",
                "missing_evidence",
            }
            if not isinstance(path, dict) or set(path) != required:
                raise OpenAIClientError("invalid_ai_output", "AI path shape is invalid")
            path_id = path["path_id"]
            if path_id not in known_paths or path_id in seen_paths:
                raise OpenAIClientError(
                    "invalid_ai_output", "AI returned an unknown or duplicate path"
                )
            rank = path["rank"]
            if (
                not isinstance(rank, int)
                or isinstance(rank, bool)
                or rank < 1
                or rank > MAX_PATHS_PER_TARGET
                or rank in seen_ranks
            ):
                raise OpenAIClientError("invalid_ai_output", "AI path rank is invalid")
            confidence = path["confidence"]
            if (
                isinstance(confidence, bool)
                or not isinstance(confidence, (int, float))
                or confidence < 0
                or confidence > 1
            ):
                raise OpenAIClientError(
                    "invalid_ai_output", "AI path confidence is invalid"
                )
            rationale = path["rationale"]
            if not isinstance(rationale, str) or len(rationale) > 1000:
                raise OpenAIClientError("invalid_ai_output", "AI rationale is invalid")
            evidence_ids = _validate_text_list(path["evidence_ids"], "evidence_ids", 50)
            if not set(evidence_ids).issubset(allowed_evidence):
                raise OpenAIClientError(
                    "invalid_ai_output", "AI referenced unknown evidence"
                )
            missing = _validate_text_list(
                path["missing_evidence"], "missing_evidence", 8
            )
            selected.append(
                {
                    "path_id": path_id,
                    "rank": rank,
                    "confidence": float(confidence),
                    "rationale": rationale,
                    "evidence_ids": evidence_ids,
                    "missing_evidence": missing,
                }
            )
            seen_paths.add(path_id)
            seen_ranks.add(rank)
        result[target_id] = sorted(selected, key=lambda item: item["rank"])
    if set(result) != set(target_ids):
        raise OpenAIClientError(
            "invalid_ai_output", "AI did not return every requested target"
        )
    return result


def _merge_ai_results(
    candidates: Dict[str, List[Dict[str, Any]]],
    ai_results: Dict[str, List[Dict[str, Any]]],
) -> List[Dict[str, Any]]:
    output = []
    for target_id in candidates:
        known = {path["path_id"]: path for path in candidates[target_id]}
        paths = []
        selected_ids = set()
        for ai_path in ai_results[target_id]:
            authoritative = dict(known[ai_path["path_id"]])
            authoritative.update(
                {
                    "source": "ai",
                    "rank": ai_path["rank"],
                    "confidence": ai_path["confidence"],
                    "rationale": ai_path["rationale"],
                    "evidence_ids": ai_path["evidence_ids"],
                    "missing_evidence": ai_path["missing_evidence"],
                }
            )
            paths.append(authoritative)
            selected_ids.add(ai_path["path_id"])
        for candidate in candidates[target_id]:
            if len(paths) >= MAX_PATHS_PER_TARGET:
                break
            if candidate["path_id"] in selected_ids:
                continue
            fallback = dict(candidate)
            fallback["rank"] = len(paths) + 1
            paths.append(fallback)
        paths = sorted(paths, key=lambda item: item["rank"])
        for rank, path in enumerate(paths, start=1):
            path["rank"] = rank
        output.append({"target_id": target_id, "paths": paths})
    return output


class AttackPathAdvisorService:
    """Coordinate persisted ROE, deterministic policy, and AI enrichment."""

    def __init__(
        self,
        config_dir: Optional[str] = None,
        client_factory: Callable[..., OpenAIClient] = OpenAIClient,
    ):
        self.config_dir = config_dir
        self.store = EngagementStore(config_dir)
        self.client_factory = client_factory

    def capabilities(self) -> Dict[str, Any]:
        result = advisor_capabilities()
        result["backend_version"] = BACKEND_VERSION
        return result

    def _prepare(
        self,
        engagement_id: str,
        profile_result: Any,
        target_ids: Any,
        options: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        try:
            settings = load_settings(self.config_dir)
            resolved_options = _options(settings, options)
            selected_ids = validate_advisor_target_ids(target_ids)
            targets = validate_profile_result(profile_result)
            engagement = self.store.get(engagement_id)
            engagement.pop("events", None)
            engagement.pop("events_has_more", None)
            events = self.store.all_events(engagement_id)
            secret = ensure_pseudonymization_key(self.config_dir)
            candidates = build_candidate_paths(
                engagement, events, targets, selected_ids, secret
            )
            cloud_payload = build_advisor_cloud_payload(
                engagement,
                targets,
                candidates,
                selected_ids,
                secret,
                resolved_options["share_ssids"],
                resolved_options["language"],
            )
        except ConfigError as failure:
            raise BackendError("configuration_error", str(failure))
        return {
            "settings": settings,
            "options": resolved_options,
            "target_ids": selected_ids,
            "targets": targets,
            "engagement": engagement,
            "secret": secret,
            "candidates": candidates,
            "cloud_payload": cloud_payload,
        }

    def prepare_advice(
        self,
        engagement_id: str,
        profile_result: Any,
        target_ids: Any,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self._prepare(
            engagement_id, profile_result, target_ids, options
        )["cloud_payload"]

    def advise(
        self,
        engagement_id: str,
        profile_result: Any,
        target_ids: Any,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        prepared = self._prepare(engagement_id, profile_result, target_ids, options)
        paths = deterministic_results(prepared["candidates"])
        result = {
            "schema_version": ADVISOR_SCHEMA_VERSION,
            "backend_version": BACKEND_VERSION,
            "generated_at": _generated_at(),
            "engagement_id": engagement_id,
            "engagement_revision": prepared["engagement"]["revision"],
            "target_results": paths,
            "advisor_status": {
                "state": "partial",
                "code": "not_started",
                "message": "Deterministic attack paths are available",
            },
            "model": prepared["settings"]["model"],
            "token_usage": {
                "input_tokens": None,
                "output_tokens": None,
                "total_tokens": None,
            },
        }
        if not any(prepared["candidates"].values()):
            result["advisor_status"] = {
                "state": "complete",
                "code": "no_eligible_paths",
                "message": "No paths passed the local engagement policy",
            }
            return result
        if not prepared["options"]["ai_enabled"]:
            result["advisor_status"] = {
                "state": "disabled",
                "code": "ai_disabled",
                "message": "AI enrichment was disabled",
            }
            return result
        try:
            api_key = load_api_key(self.config_dir)
        except ConfigError as failure:
            result["advisor_status"] = {
                "state": "partial",
                "code": "configuration_error",
                "message": str(failure),
            }
            return result
        if not api_key:
            result["advisor_status"] = {
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
            client = self.client_factory(
                api_key=api_key, model=prepared["settings"]["model"]
            )
            ai_output, usage = client.advise(
                prepared["cloud_payload"],
                prepared["options"]["language"],
                "device_{0}".format(safety_digest),
            )
            validated = _validate_ai_advice(
                ai_output,
                prepared["target_ids"],
                prepared["candidates"],
                prepared["targets"],
            )
            result["target_results"] = _merge_ai_results(
                prepared["candidates"], validated
            )
            result["token_usage"] = usage
            result["advisor_status"] = {
                "state": "complete",
                "code": "ok",
                "message": "AI attack-path enrichment completed",
            }
        except OpenAIClientError as failure:
            result["advisor_status"] = {
                "state": "partial",
                "code": failure.code,
                "message": failure.safe_message,
            }
        return result
