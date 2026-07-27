"""Application service for bounded, operator-approved Adaptive Recon plans."""

import copy
import datetime
import hashlib
import hmac
from typing import Any, Callable, Dict, List, Optional, Tuple

from .adaptive_recon import (
    ADAPTIVE_RECON_SCHEMA_VERSION,
    APPROVAL_STATUS_MAX_AGE_SECONDS,
    CANDIDATE_ID_PATTERN,
    ERROR_CODE_PATTERN,
    PLAN_ID_PATTERN,
    PLAN_TTL_SECONDS,
    adaptive_recon_capabilities,
    build_candidates,
    build_cloud_payload,
    build_result_delta,
    normalize_profile_snapshot,
    utc_now,
    utc_string,
    validate_advisor_selection,
    validate_device_context,
    validate_history,
)
from .config import (
    ConfigError,
    ensure_pseudonymization_key,
    load_api_key,
    load_settings,
)
from .engagement_store import EngagementStore, parse_utc
from .errors import BackendError
from .openai_client import OpenAIClient, OpenAIClientError


BACKEND_VERSION = "0.4.0"
ADAPTIVE_EVENT_TYPES = (
    "adaptive_recon_recommended",
    "adaptive_recon_approved",
    "adaptive_recon_started",
    "adaptive_recon_finished",
)


def _options(settings: Dict[str, Any], value: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if value is None:
        value = {}
    if not isinstance(value, dict) or set(value) - {
        "language",
        "share_ssids",
        "ai_enabled",
    }:
        raise BackendError("invalid_options", "Adaptive Recon options are invalid")
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


def _validate_revision(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise BackendError("invalid_request", "expected_revision must be an integer")
    return value


def _validate_string_list(value: Any, field: str, maximum: int) -> List[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise OpenAIClientError(
            "invalid_ai_output",
            "{0} must contain at most {1} values".format(field, maximum),
        )
    result = []
    for item in value:
        if not isinstance(item, str) or len(item) > 500:
            raise OpenAIClientError(
                "invalid_ai_output", "{0} contains an invalid value".format(field)
            )
        result.append(item)
    return result


def _validate_ai_selection(
    value: Any, plan: Dict[str, Any]
) -> Dict[str, Any]:
    required = {
        "candidate_id",
        "target_ids",
        "confidence",
        "rationale",
        "expected_information",
        "evidence_ids",
        "missing_evidence",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise OpenAIClientError("invalid_ai_output", "AI Recon selection is invalid")
    candidate_ids = {
        candidate["candidate_id"] for candidate in plan["candidates"]
    }
    if value["candidate_id"] not in candidate_ids:
        raise OpenAIClientError(
            "invalid_ai_output", "AI referenced an unknown Recon candidate"
        )
    target_ids = _validate_string_list(value["target_ids"], "target_ids", 10)
    if target_ids != plan["target_ids"]:
        raise OpenAIClientError(
            "invalid_ai_output", "AI returned unknown or reordered targets"
        )
    confidence = value["confidence"]
    if (
        isinstance(confidence, bool)
        or not isinstance(confidence, (int, float))
        or confidence < 0
        or confidence > 1
    ):
        raise OpenAIClientError(
            "invalid_ai_output", "AI Recon confidence is invalid"
        )
    rationale = value["rationale"]
    if not isinstance(rationale, str) or len(rationale) > 1000:
        raise OpenAIClientError(
            "invalid_ai_output", "AI Recon rationale is invalid"
        )
    expected_information = _validate_string_list(
        value["expected_information"], "expected_information", 8
    )
    evidence_ids = _validate_string_list(value["evidence_ids"], "evidence_ids", 100)
    if not set(evidence_ids).issubset(set(plan["evidence_ids"])):
        raise OpenAIClientError(
            "invalid_ai_output", "AI referenced unknown Recon evidence"
        )
    missing_evidence = _validate_string_list(
        value["missing_evidence"], "missing_evidence", 8
    )
    return {
        "candidate_id": value["candidate_id"],
        "confidence": float(confidence),
        "rationale": rationale,
        "expected_information": expected_information,
        "evidence_ids": evidence_ids,
        "missing_evidence": missing_evidence,
    }


def _candidate(plan: Dict[str, Any], candidate_id: str) -> Dict[str, Any]:
    for candidate in plan["candidates"]:
        if candidate["candidate_id"] == candidate_id:
            return candidate
    raise BackendError(
        "unknown_recon_candidate", "candidate_id is not part of this Recon plan"
    )


def _plan_expiration(
    plan: Dict[str, Any], current: Optional[datetime.datetime] = None
) -> Dict[str, Any]:
    result = copy.deepcopy(plan)
    now = current or utc_now()
    if result["status"] == "recommended":
        if now > parse_utc(
            result["recommendation_expires_at"], "recommendation_expires_at"
        ):
            result["status"] = "expired"
            result["expired_from"] = "recommended"
    elif result["status"] == "approved":
        if now > parse_utc(result["approval_expires_at"], "approval_expires_at"):
            result["status"] = "expired"
            result["expired_from"] = "approved"
    return result


def reconstruct_plans(
    events: List[Dict[str, Any]], current: Optional[datetime.datetime] = None
) -> Dict[str, Dict[str, Any]]:
    plans = {}
    for event in events:
        event_type = event.get("event_type")
        if event_type not in ADAPTIVE_EVENT_TYPES:
            continue
        data = event.get("data")
        if not isinstance(data, dict):
            continue
        if event_type == "adaptive_recon_recommended":
            plan = copy.deepcopy(data.get("plan"))
            if not isinstance(plan, dict):
                continue
            plan_id = plan.get("plan_id")
            if not isinstance(plan_id, str) or not PLAN_ID_PATTERN.match(plan_id):
                continue
            plan["engagement_revision"] = event.get("revision")
            plans[plan_id] = plan
            continue
        plan_id = data.get("plan_id")
        if plan_id not in plans:
            continue
        plan = plans[plan_id]
        if event_type == "adaptive_recon_approved":
            plan["status"] = "approved"
            plan["selected_candidate_id"] = data["candidate_id"]
            plan["approval_expires_at"] = data["approval_expires_at"]
            plan["approved_at"] = event.get("recorded_at")
            plan["rest_request"] = data["rest_request"]
        elif event_type == "adaptive_recon_started":
            plan["status"] = "started"
            plan["started_at"] = event.get("recorded_at")
            plan["scan_id"] = data["scan_id"]
        elif event_type == "adaptive_recon_finished":
            plan["status"] = data["outcome"]
            plan["finished_at"] = event.get("recorded_at")
            plan["result"] = {
                key: value for key, value in data.items() if key != "plan_id"
            }
        plan["engagement_revision"] = event.get("revision")
    return {
        plan_id: _plan_expiration(plan, current)
        for plan_id, plan in plans.items()
    }


def _active_plan_for_targets(
    plans: Dict[str, Dict[str, Any]], target_ids: List[str]
) -> Optional[str]:
    selected = set(target_ids)
    for plan_id, plan in plans.items():
        if plan["status"] in ("recommended", "approved", "started") and selected.intersection(
            plan["target_ids"]
        ):
            return plan_id
    return None


def _validate_engagement(
    engagement: Dict[str, Any],
    expected_revision: int,
    target_ids: Optional[List[str]] = None,
    current: Optional[datetime.datetime] = None,
) -> None:
    if engagement["revision"] != expected_revision:
        raise BackendError("revision_conflict", "engagement revision has changed")
    if engagement["status"] != "active":
        raise BackendError("engagement_archived", "engagement is archived")
    now = current or utc_now()
    if now < parse_utc(engagement["valid_from"], "valid_from"):
        raise BackendError("engagement_not_started", "engagement has not started")
    if now > parse_utc(engagement["valid_until"], "valid_until"):
        raise BackendError("engagement_expired", "engagement has expired")
    if "collect_additional_recon" not in engagement["allowed_actions"]:
        raise BackendError(
            "action_not_allowed",
            "collect_additional_recon is not allowed by the engagement",
        )
    if target_ids is not None:
        if not set(target_ids).issubset(set(engagement["authorized_target_ids"])):
            raise BackendError(
                "target_out_of_scope", "Recon plan contains an out-of-scope target"
            )


class AdaptiveReconService:
    """Create, approve and audit bounded Recon plans without executing them."""

    def __init__(
        self,
        config_dir: Optional[str] = None,
        client_factory: Callable[..., OpenAIClient] = OpenAIClient,
        clock: Callable[[], datetime.datetime] = utc_now,
    ):
        self.config_dir = config_dir
        self.store = EngagementStore(config_dir)
        self.client_factory = client_factory
        self.clock = clock

    def capabilities(self) -> Dict[str, Any]:
        result = adaptive_recon_capabilities()
        result["backend_version"] = BACKEND_VERSION
        return result

    def _prepare(
        self,
        engagement_id: str,
        expected_revision: Any,
        profile_result: Any,
        advisor_result: Any,
        selected_path_ids: Any,
        history: Any,
        device_context: Any,
        options: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        revision = _validate_revision(expected_revision)
        now = self.clock()
        try:
            settings = load_settings(self.config_dir)
            resolved_options = _options(settings, options)
            engagement = self.store.get(engagement_id)
            events = self.store.all_events(engagement_id)
            target_ids, path_ids, evidence_ids = validate_advisor_selection(
                advisor_result, selected_path_ids, revision
            )
            _validate_engagement(engagement, revision, target_ids, now)
            secret = ensure_pseudonymization_key(self.config_dir)
            current_profile = normalize_profile_snapshot(profile_result, secret)
            for target_id in target_ids:
                if target_id not in current_profile["targets"]:
                    raise BackendError(
                        "target_not_found",
                        "selected target is missing from profile_result",
                    )
            snapshots = validate_history(history, secret)
            device = validate_device_context(device_context, now)
            plans = reconstruct_plans(events, now)
            active_plan = _active_plan_for_targets(plans, target_ids)
            if active_plan:
                raise BackendError(
                    "recon_plan_in_progress",
                    "an active Recon plan already covers a selected target",
                )
            plan = build_candidates(
                engagement_id,
                revision,
                current_profile,
                snapshots,
                target_ids,
                path_ids,
                evidence_ids,
                device,
                events,
                secret,
            )
            cloud_payload = build_cloud_payload(
                plan,
                current_profile,
                secret,
                resolved_options["share_ssids"],
                resolved_options["language"],
            )
        except ConfigError as failure:
            raise BackendError("configuration_error", str(failure))
        return {
            "revision": revision,
            "now": now,
            "settings": settings,
            "options": resolved_options,
            "engagement": engagement,
            "events": events,
            "secret": secret,
            "profile": current_profile,
            "history": snapshots,
            "device_context": device,
            "plan": plan,
            "cloud_payload": cloud_payload,
        }

    def prepare(
        self,
        engagement_id: str,
        expected_revision: Any,
        profile_result: Any,
        advisor_result: Any,
        selected_path_ids: Any,
        history: Any,
        device_context: Any,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self._prepare(
            engagement_id,
            expected_revision,
            profile_result,
            advisor_result,
            selected_path_ids,
            history,
            device_context,
            options,
        )["cloud_payload"]

    def recommend(
        self,
        engagement_id: str,
        expected_revision: Any,
        profile_result: Any,
        advisor_result: Any,
        selected_path_ids: Any,
        history: Any,
        device_context: Any,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        prepared = self._prepare(
            engagement_id,
            expected_revision,
            profile_result,
            advisor_result,
            selected_path_ids,
            history,
            device_context,
            options,
        )
        plan = copy.deepcopy(prepared["plan"])
        default = plan["candidates"][0]
        plan.update(
            {
                "backend_version": BACKEND_VERSION,
                "status": "recommended",
                "created_at": utc_string(prepared["now"]),
                "recommendation_expires_at": utc_string(
                    min(
                        prepared["now"]
                        + datetime.timedelta(seconds=PLAN_TTL_SECONDS),
                        parse_utc(
                            prepared["engagement"]["valid_until"], "valid_until"
                        ),
                    )
                ),
                "selected_candidate_id": default["candidate_id"],
                "source": "deterministic",
                "confidence": 0.5,
                "rationale": prepared["plan"]["analysis"]["duration_reason"],
                "expected_information": [
                    "Target presence and access-point coverage",
                    "Client activity and channel stability",
                    "Changes in encryption and available evidence",
                ],
                "missing_evidence": [],
            }
        )
        status = {
            "state": "partial",
            "code": "not_started",
            "message": "Deterministic Recon recommendation is available",
        }
        usage = {
            "input_tokens": None,
            "output_tokens": None,
            "total_tokens": None,
        }
        if not prepared["options"]["ai_enabled"]:
            status = {
                "state": "disabled",
                "code": "ai_disabled",
                "message": "AI enrichment was disabled",
            }
        else:
            try:
                api_key = load_api_key(self.config_dir)
            except ConfigError as failure:
                api_key = None
                status = {
                    "state": "partial",
                    "code": "configuration_error",
                    "message": str(failure),
                }
            if api_key:
                safety_digest = hmac.new(
                    prepared["secret"],
                    b"pineai-safety-identifier",
                    hashlib.sha256,
                ).hexdigest()[:32]
                try:
                    client = self.client_factory(
                        api_key=api_key, model=prepared["settings"]["model"]
                    )
                    ai_output, usage = client.plan_adaptive_recon(
                        prepared["cloud_payload"],
                        prepared["options"]["language"],
                        "device_{0}".format(safety_digest),
                    )
                    validated = _validate_ai_selection(ai_output, plan)
                    plan.update(
                        {
                            "selected_candidate_id": validated["candidate_id"],
                            "source": "ai",
                            "confidence": validated["confidence"],
                            "rationale": validated["rationale"],
                            "expected_information": validated[
                                "expected_information"
                            ],
                            "evidence_ids": validated["evidence_ids"],
                            "missing_evidence": validated["missing_evidence"],
                        }
                    )
                    status = {
                        "state": "complete",
                        "code": "ok",
                        "message": "AI Recon recommendation completed",
                    }
                except OpenAIClientError as failure:
                    status = {
                        "state": "partial",
                        "code": failure.code,
                        "message": failure.safe_message,
                    }
            elif status["code"] == "not_started":
                status = {
                    "state": "partial",
                    "code": "not_configured",
                    "message": "OpenAI API key is not configured",
                }
        plan["adaptive_status"] = status
        plan["model"] = prepared["settings"]["model"]
        plan["token_usage"] = usage
        plan["engagement_revision"] = prepared["revision"] + 1
        persisted = self.store.append_system_event(
            engagement_id,
            prepared["revision"],
            "adaptive_recon_recommended",
            {"plan": plan},
        )
        plan["engagement_revision"] = persisted["engagement"]["revision"]
        return plan

    def get_plan(self, engagement_id: str, plan_id: str) -> Dict[str, Any]:
        if not isinstance(plan_id, str) or not PLAN_ID_PATTERN.match(plan_id):
            raise BackendError("invalid_recon_plan_id", "plan_id is invalid")
        events = self.store.all_events(engagement_id)
        plans = reconstruct_plans(events, self.clock())
        if plan_id not in plans:
            raise BackendError("recon_plan_not_found", "Recon plan was not found")
        return plans[plan_id]

    def list_plans(self, engagement_id: str) -> List[Dict[str, Any]]:
        plans = reconstruct_plans(
            self.store.all_events(engagement_id), self.clock()
        )
        values = sorted(
            plans.values(),
            key=lambda item: (item["created_at"], item["plan_id"]),
            reverse=True,
        )
        return [
            {
                "plan_id": plan["plan_id"],
                "status": plan["status"],
                "created_at": plan["created_at"],
                "target_ids": plan["target_ids"],
                "selected_candidate_id": plan["selected_candidate_id"],
                "engagement_revision": plan["engagement_revision"],
            }
            for plan in values
        ]

    def approve(
        self,
        engagement_id: str,
        expected_revision: Any,
        plan_id: str,
        candidate_id: str,
        device_context: Any,
    ) -> Dict[str, Any]:
        revision = _validate_revision(expected_revision)
        if not isinstance(plan_id, str) or not PLAN_ID_PATTERN.match(plan_id):
            raise BackendError("invalid_recon_plan_id", "plan_id is invalid")
        if (
            not isinstance(candidate_id, str)
            or not CANDIDATE_ID_PATTERN.match(candidate_id)
        ):
            raise BackendError(
                "invalid_recon_candidate_id", "candidate_id is invalid"
            )
        now = self.clock()
        engagement = self.store.get(engagement_id)
        _validate_engagement(engagement, revision, current=now)
        plan = self.get_plan(engagement_id, plan_id)
        if plan["status"] == "expired":
            raise BackendError("recon_plan_expired", "Recon plan has expired")
        if plan["status"] != "recommended":
            raise BackendError(
                "invalid_recon_transition", "only a recommended plan can be approved"
            )
        if plan["engagement_revision"] != revision:
            raise BackendError(
                "stale_recon_plan", "engagement changed after plan recommendation"
            )
        _validate_engagement(engagement, revision, plan["target_ids"], now)
        candidate = _candidate(plan, candidate_id)
        device = validate_device_context(
            device_context,
            now,
            maximum_age_seconds=APPROVAL_STATUS_MAX_AGE_SECONDS,
        )
        matching_band = next(
            (
                band
                for band in device["supported_bands"]
                if band["value"] == candidate["request"]["band"]
                and band["covers"] == candidate["band_covers"]
            ),
            None,
        )
        if matching_band is None:
            raise BackendError(
                "band_capability_changed",
                "approved candidate is missing from current device capabilities",
            )
        approval_expires = min(
            now + datetime.timedelta(seconds=PLAN_TTL_SECONDS),
            parse_utc(engagement["valid_until"], "valid_until"),
        )
        rest_request = {
            "method": "POST",
            "path": "/api/recon/start",
            "body": copy.deepcopy(candidate["request"]),
        }
        persisted = self.store.append_system_event(
            engagement_id,
            revision,
            "adaptive_recon_approved",
            {
                "plan_id": plan_id,
                "candidate_id": candidate_id,
                "approval_expires_at": utc_string(approval_expires),
                "rest_request": rest_request,
                "device_capabilities_digest": hashlib.sha256(
                    repr(device["supported_bands"]).encode("utf-8")
                ).hexdigest(),
            },
        )
        result = self.get_plan(engagement_id, plan_id)
        result["engagement_revision"] = persisted["engagement"]["revision"]
        return result

    def record_started(
        self,
        engagement_id: str,
        expected_revision: Any,
        plan_id: str,
        start_response: Any,
    ) -> Dict[str, Any]:
        revision = _validate_revision(expected_revision)
        now = self.clock()
        engagement = self.store.get(engagement_id)
        _validate_engagement(engagement, revision, current=now)
        plan = self.get_plan(engagement_id, plan_id)
        if plan["status"] == "expired":
            raise BackendError("recon_plan_expired", "Recon approval has expired")
        if plan["status"] != "approved":
            raise BackendError(
                "invalid_recon_transition", "only an approved plan can be started"
            )
        if plan["engagement_revision"] != revision:
            raise BackendError(
                "stale_recon_plan", "engagement changed after plan approval"
            )
        if (
            not isinstance(start_response, dict)
            or set(start_response) != {"scanRunning", "scanID"}
            or start_response["scanRunning"] is not True
            or not isinstance(start_response["scanID"], int)
            or isinstance(start_response["scanID"], bool)
            or start_response["scanID"] < 0
        ):
            raise BackendError(
                "invalid_recon_start_response",
                "Hak5 Recon start response is invalid or did not start a scan",
            )
        persisted = self.store.append_system_event(
            engagement_id,
            revision,
            "adaptive_recon_started",
            {"plan_id": plan_id, "scan_id": start_response["scanID"]},
        )
        result = self.get_plan(engagement_id, plan_id)
        result["engagement_revision"] = persisted["engagement"]["revision"]
        return result

    def record_finished(
        self,
        engagement_id: str,
        expected_revision: Any,
        plan_id: str,
        outcome: str,
        scan_id: Any,
        profile_result: Any = None,
        error_code: Optional[str] = None,
    ) -> Dict[str, Any]:
        revision = _validate_revision(expected_revision)
        if outcome not in ("completed", "failed", "aborted"):
            raise BackendError("invalid_recon_outcome", "Recon outcome is invalid")
        if not isinstance(scan_id, int) or isinstance(scan_id, bool) or scan_id < 0:
            raise BackendError("invalid_recon_outcome", "scan_id is invalid")
        if error_code is not None and (
            not isinstance(error_code, str)
            or not ERROR_CODE_PATTERN.match(error_code)
        ):
            raise BackendError("invalid_recon_outcome", "error_code is invalid")
        now = self.clock()
        engagement = self.store.get(engagement_id)
        _validate_engagement(engagement, revision, current=now)
        plan = self.get_plan(engagement_id, plan_id)
        if plan["status"] != "started":
            raise BackendError(
                "invalid_recon_transition", "only a started plan can be finished"
            )
        if plan["engagement_revision"] != revision:
            raise BackendError(
                "stale_recon_plan", "engagement changed after scan start"
            )
        if plan["scan_id"] != scan_id:
            raise BackendError(
                "scan_id_mismatch", "scan_id does not match the started Recon plan"
            )
        data = {
            "plan_id": plan_id,
            "target_ids": plan["target_ids"],
            "outcome": outcome,
            "scan_id": scan_id,
            "error_code": error_code,
            "profile_digest": None,
            "result_delta": None,
        }
        if outcome == "completed":
            if profile_result is None:
                raise BackendError(
                    "invalid_recon_outcome",
                    "completed outcome requires profile_result",
                )
            try:
                secret = ensure_pseudonymization_key(self.config_dir)
            except ConfigError as failure:
                raise BackendError("configuration_error", str(failure))
            completed = normalize_profile_snapshot(profile_result, secret)
            data["profile_digest"] = completed["digest"]
            data["result_delta"] = build_result_delta(
                plan["baseline"], completed, plan["target_ids"]
            )
            if error_code is not None:
                raise BackendError(
                    "invalid_recon_outcome",
                    "completed outcome cannot contain error_code",
                )
        elif profile_result is not None:
            raise BackendError(
                "invalid_recon_outcome",
                "failed or aborted outcome cannot contain profile_result",
            )
        persisted = self.store.append_system_event(
            engagement_id,
            revision,
            "adaptive_recon_finished",
            data,
        )
        result = self.get_plan(engagement_id, plan_id)
        result["engagement_revision"] = persisted["engagement"]["revision"]
        return result
