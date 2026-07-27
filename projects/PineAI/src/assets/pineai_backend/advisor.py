"""Deterministic policy engine and cloud payload for Attack-Path Advisor."""

import datetime
import hashlib
import hmac
import json
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .engagement_store import (
    ACTION_IDS,
    ENGAGEMENT_SCHEMA_VERSION,
    OBJECTIVE_CODES,
    TARGET_ID_PATTERN,
    EngagementStore,
    parse_utc,
)
from .errors import BackendError
from .profiler import MAC_IN_TEXT_PATTERN


ADVISOR_SCHEMA_VERSION = "1.0"
MAX_ADVISOR_TARGETS = 10
MAX_PATHS_PER_TARGET = 3

RISK_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}
DETECTABILITY_ORDER = {"low": 0, "medium": 1, "high": 2}

ACTION_REGISTRY = {
    "collect_additional_recon": {
        "risk": "low",
        "detectability": "low",
        "disruptive": False,
        "requires_explicit_approval": False,
        "purpose": "Collect additional observations before making stronger conclusions.",
        "preconditions": ["Confirm the target remains within the engagement scope."],
        "stop_conditions": ["The engagement time window expires.", "The operator aborts the test."],
    },
    "passive_handshake_capture": {
        "risk": "low",
        "detectability": "low",
        "disruptive": False,
        "requires_explicit_approval": True,
        "purpose": "Observe authorized authentication exchanges without triggering radio disruption.",
        "preconditions": ["Confirm capture and data-handling authorization."],
        "stop_conditions": ["Unexpected sensitive traffic is captured.", "The operator aborts the test."],
    },
    "test_device_association": {
        "risk": "medium",
        "detectability": "medium",
        "disruptive": False,
        "requires_explicit_approval": True,
        "purpose": "Use an operator-controlled test device to inspect association behavior.",
        "preconditions": ["Use only an authorized test device."],
        "stop_conditions": ["Unexpected production impact is observed.", "The operator aborts the test."],
    },
    "captive_portal_inspection": {
        "risk": "medium",
        "detectability": "medium",
        "disruptive": False,
        "requires_explicit_approval": True,
        "purpose": "Inspect the authorized captive portal and session behavior with a test device.",
        "preconditions": ["Use only test identities and approved traffic."],
        "stop_conditions": ["Real user data becomes visible.", "The operator aborts the test."],
    },
    "enterprise_eap_validation": {
        "risk": "medium",
        "detectability": "high",
        "disruptive": False,
        "requires_explicit_approval": True,
        "purpose": "Validate Enterprise authentication behavior using an operator-controlled device.",
        "preconditions": ["Use approved test credentials and certificate expectations."],
        "stop_conditions": ["A non-test identity is involved.", "The operator aborts the test."],
    },
    "authorized_deauthentication": {
        "risk": "high",
        "detectability": "high",
        "disruptive": True,
        "requires_explicit_approval": True,
        "purpose": "Evaluate authorized client reauthentication resilience under bounded disruption.",
        "preconditions": ["Confirm explicit disruption authorization immediately before execution."],
        "stop_conditions": [
            "Unexpected user impact is observed.",
            "An out-of-scope device is affected.",
            "The engagement time window expires.",
            "The operator aborts the test.",
        ],
    },
    "evil_twin_simulation": {
        "risk": "high",
        "detectability": "high",
        "disruptive": True,
        "requires_explicit_approval": True,
        "purpose": (
            "Plan an authorized rogue-AP resilience exercise, including credential-collection "
            "advice only when covered by the engagement rules."
        ),
        "preconditions": [
            "Confirm explicit disruption and evil-twin authorization immediately before execution."
        ],
        "stop_conditions": [
            "An out-of-scope device connects.",
            "Unexpected user impact is observed.",
            "The engagement time window expires.",
            "The operator aborts the test.",
        ],
        "may_include_credential_collection_advice": True,
    },
}

PATH_TEMPLATES = (
    {
        "template_id": "recon_depth",
        "base_score": 70,
        "steps": ["collect_additional_recon"],
        "objectives": ["wireless_mapping"],
        "roles": [],
        "summary": "Deepen the target evidence before choosing an active test.",
    },
    {
        "template_id": "guest_portal_assessment",
        "base_score": 65,
        "steps": ["test_device_association", "captive_portal_inspection"],
        "objectives": ["guest_network_security", "captive_portal_security"],
        "roles": ["guest", "public"],
        "summary": "Assess guest association and captive-portal behavior with a test device.",
    },
    {
        "template_id": "enterprise_authentication_assessment",
        "base_score": 65,
        "steps": ["test_device_association", "enterprise_eap_validation"],
        "objectives": ["enterprise_authentication"],
        "roles": ["corporate", "infrastructure"],
        "summary": "Assess Enterprise authentication behavior using controlled identities.",
    },
    {
        "template_id": "handshake_assessment",
        "base_score": 55,
        "steps": ["passive_handshake_capture"],
        "objectives": ["enterprise_authentication", "guest_network_security"],
        "roles": ["corporate", "guest", "iot_ot"],
        "summary": "Collect bounded authentication evidence for offline validation.",
    },
    {
        "template_id": "deauthentication_resilience",
        "base_score": 35,
        "steps": ["authorized_deauthentication"],
        "objectives": ["rogue_ap_resilience", "client_awareness"],
        "roles": [],
        "summary": "Evaluate reauthentication resilience using explicitly authorized disruption.",
        "requires_clients": True,
    },
    {
        "template_id": "evil_twin_campaign",
        "base_score": 30,
        "steps": ["collect_additional_recon", "evil_twin_simulation"],
        "objectives": [
            "rogue_ap_resilience",
            "client_awareness",
            "credential_capture_assessment",
        ],
        "roles": ["corporate", "guest", "public"],
        "summary": "Plan a bounded rogue-AP resilience campaign under the engagement ROE.",
    },
)


def advisor_capabilities() -> Dict[str, Any]:
    return {
        "schema_version": ADVISOR_SCHEMA_VERSION,
        "engagement_schema_version": ENGAGEMENT_SCHEMA_VERSION,
        "objective_codes": list(OBJECTIVE_CODES),
        "actions": [
            dict({"action_id": action_id}, **ACTION_REGISTRY[action_id])
            for action_id in ACTION_IDS
        ],
        "limits": {
            "targets_per_request": MAX_ADVISOR_TARGETS,
            "paths_per_target": MAX_PATHS_PER_TARGET,
            "steps_per_path": 3,
        },
    }


def _utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _pseudonym(secret: bytes, namespace: str, value: str) -> str:
    digest = hmac.new(
        secret,
        "{0}:{1}".format(namespace, value).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return "{0}_{1}".format(namespace, digest[:12])


def _clean_text(value: Any, maximum: int = 500) -> str:
    text = str(value) if value is not None else ""
    text = "".join(character for character in text if ord(character) >= 32)
    return MAC_IN_TEXT_PATTERN.sub("[redacted_mac]", text)[:maximum]


def _validate_identifier_list(
    value: Any, field: str, pattern: re.Pattern, maximum: int
) -> List[str]:
    if not isinstance(value, list) or not value or len(value) > maximum:
        raise BackendError(
            "invalid_advisor_request",
            "{0} must contain 1-{1} identifiers".format(field, maximum),
        )
    result = []
    for item in value:
        if not isinstance(item, str) or not pattern.match(item):
            raise BackendError(
                "invalid_advisor_request", "{0} contains an invalid identifier".format(field)
            )
        if item not in result:
            result.append(item)
    return result


def validate_advisor_target_ids(value: Any) -> List[str]:
    return _validate_identifier_list(
        value, "target_ids", TARGET_ID_PATTERN, MAX_ADVISOR_TARGETS
    )


def validate_profile_result(profile_result: Any) -> Dict[str, Dict[str, Any]]:
    """Validate only the Target Profiler fields consumed by Advisor."""
    if not isinstance(profile_result, dict) or profile_result.get("schema_version") != "1.0":
        raise BackendError(
            "invalid_profile_result", "profile_result must use Target Profiler schema 1.0"
        )
    targets = profile_result.get("targets")
    if not isinstance(targets, list) or len(targets) > 1000:
        raise BackendError("invalid_profile_result", "profile_result.targets must be an array")
    result = {}
    for target in targets:
        if not isinstance(target, dict):
            raise BackendError("invalid_profile_result", "profile target must be an object")
        target_id = target.get("target_id")
        if not isinstance(target_id, str) or not TARGET_ID_PATTERN.match(target_id):
            raise BackendError("invalid_profile_result", "profile target_id is invalid")
        if target_id in result:
            raise BackendError("invalid_profile_result", "profile contains duplicate targets")
        metrics = target.get("metrics")
        if not isinstance(metrics, dict):
            raise BackendError("invalid_profile_result", "profile metrics are invalid")
        integer_metrics = {}
        for name in (
            "ap_count",
            "client_count",
            "wps_enabled_count",
            "hidden_ap_count",
            "data_total",
            "probes_total",
        ):
            value = metrics.get(name, 0)
            if not isinstance(value, int) or isinstance(value, bool):
                raise BackendError("invalid_profile_result", "profile metric is invalid")
            integer_metrics[name] = value
        evidence = target.get("evidence", [])
        if not isinstance(evidence, list) or len(evidence) > 50:
            raise BackendError("invalid_profile_result", "profile evidence is invalid")
        evidence_ids = []
        for item in evidence:
            evidence_id = item.get("evidence_id") if isinstance(item, dict) else None
            if (
                not isinstance(evidence_id, str)
                or not re.match(r"^evidence_[0-9a-f]{12}$", evidence_id)
            ):
                raise BackendError("invalid_profile_result", "profile evidence_id is invalid")
            evidence_ids.append(evidence_id)
        ai_profile = target.get("ai_profile")
        role = "unknown"
        interest = "low"
        missing_count = 0
        if ai_profile is not None:
            if not isinstance(ai_profile, dict):
                raise BackendError("invalid_profile_result", "profile ai_profile is invalid")
            role = ai_profile.get("role", "unknown")
            interest = ai_profile.get("interest", "low")
            missing = ai_profile.get("missing_evidence", [])
            if role not in (
                "corporate",
                "guest",
                "iot_ot",
                "management",
                "public",
                "personal",
                "infrastructure",
                "unknown",
            ):
                raise BackendError("invalid_profile_result", "profile role is invalid")
            if interest not in ("low", "medium", "high"):
                raise BackendError("invalid_profile_result", "profile interest is invalid")
            if not isinstance(missing, list):
                raise BackendError(
                    "invalid_profile_result", "profile missing_evidence is invalid"
                )
            missing_count = min(len(missing), 5)
        flags = target.get("flags", [])
        if not isinstance(flags, list) or any(not isinstance(flag, str) for flag in flags):
            raise BackendError("invalid_profile_result", "profile flags are invalid")
        vendors = target.get("vendors", [])
        if not isinstance(vendors, list) or len(vendors) > 50:
            raise BackendError("invalid_profile_result", "profile vendors are invalid")
        normalized_vendors = []
        for vendor in vendors:
            if (
                not isinstance(vendor, dict)
                or set(vendor) != {"value", "count"}
                or not isinstance(vendor["count"], int)
                or isinstance(vendor["count"], bool)
            ):
                raise BackendError("invalid_profile_result", "profile vendor is invalid")
            normalized_vendors.append(
                {"value": _clean_text(vendor["value"], 128), "count": vendor["count"]}
            )
        channels = target.get("channels", [])
        encryption_codes = target.get("encryption_codes", [])
        if (
            not isinstance(channels, list)
            or len(channels) > 200
            or any(not isinstance(item, int) or isinstance(item, bool) for item in channels)
        ):
            raise BackendError("invalid_profile_result", "profile channels are invalid")
        if (
            not isinstance(encryption_codes, list)
            or len(encryption_codes) > 50
            or any(
                not isinstance(item, int) or isinstance(item, bool)
                for item in encryption_codes
            )
        ):
            raise BackendError(
                "invalid_profile_result", "profile encryption_codes are invalid"
            )
        result[target_id] = {
            "target_id": target_id,
            "ssid": _clean_text(target.get("ssid", ""), 128),
            "hidden": bool(target.get("hidden", False)),
            "vendors": normalized_vendors,
            "channels": channels,
            "encryption_codes": encryption_codes,
            "metrics": integer_metrics,
            "flags": [_clean_text(flag, 64) for flag in flags[:20]],
            "role": role,
            "interest": interest,
            "missing_evidence_count": missing_count,
            "evidence_ids": list(dict.fromkeys(evidence_ids)),
        }
    return result


def _activity_state(events: Iterable[Dict[str, Any]]) -> Dict[Tuple[str, str], str]:
    state = {}
    for event in events:
        event_type = event.get("event_type")
        if event_type not in (
            "action_started",
            "action_completed",
            "action_failed",
            "action_aborted",
        ):
            continue
        target_id = event.get("target_id")
        action_id = event.get("action_id")
        if target_id and action_id:
            state[(target_id, action_id)] = event_type
    return state


def _highest(values: Iterable[str], order: Dict[str, int]) -> str:
    return max(values, key=lambda item: order[item])


def _policy_checks(engagement: Dict[str, Any], disruptive: bool) -> List[Dict[str, Any]]:
    checks = [
        {"check": "target_in_scope", "passed": True},
        {"check": "engagement_active", "passed": True},
        {"check": "time_window_valid", "passed": True},
        {"check": "actions_allowed", "passed": True},
    ]
    checks.append(
        {
            "check": "disruption_gate",
            "passed": bool(
                not disruptive
                or (
                    engagement["disruption_allowed"]
                    and engagement["authorization_reference"]
                )
            ),
        }
    )
    return checks


def build_candidate_paths(
    engagement: Dict[str, Any],
    events: List[Dict[str, Any]],
    targets: Dict[str, Dict[str, Any]],
    target_ids: List[str],
    secret: bytes,
    now: Optional[datetime.datetime] = None,
) -> Dict[str, List[Dict[str, Any]]]:
    if engagement.get("status") != "active":
        raise BackendError("engagement_archived", "engagement is archived")
    current = now or _utc_now()
    if current < parse_utc(engagement["valid_from"], "valid_from"):
        raise BackendError("engagement_not_started", "engagement has not started")
    if current > parse_utc(engagement["valid_until"], "valid_until"):
        raise BackendError("engagement_expired", "engagement has expired")

    activity = _activity_state(events)
    results = {}
    for target_id in target_ids:
        if target_id not in engagement["authorized_target_ids"]:
            raise BackendError("target_out_of_scope", "requested target is outside engagement scope")
        if target_id not in targets:
            raise BackendError("target_not_found", "requested target is missing from profile_result")
        target = targets[target_id]
        candidates = []
        for template in PATH_TEMPLATES:
            steps = template["steps"]
            if any(action_id not in engagement["allowed_actions"] for action_id in steps):
                continue
            if template.get("requires_clients") and target["metrics"]["client_count"] <= 0:
                continue
            states = [activity.get((target_id, action_id)) for action_id in steps]
            if any(state in ("action_started", "action_completed") for state in states):
                continue
            disruptive = any(ACTION_REGISTRY[action_id]["disruptive"] for action_id in steps)
            if disruptive and (
                not engagement["disruption_allowed"]
                or not engagement["authorization_reference"]
            ):
                continue
            score = template["base_score"]
            if set(template["objectives"]).intersection(engagement["objectives"]):
                score += 30
            if target["role"] in template["roles"]:
                score += 20
            score += {"high": 10, "medium": 5, "low": 0}[target["interest"]]
            score += target["missing_evidence_count"] * 2
            if any(state in ("action_failed", "action_aborted") for state in states):
                score -= 15
            action_values = [ACTION_REGISTRY[action_id] for action_id in steps]
            path_id = _pseudonym(
                secret,
                "path",
                "{0}:{1}:{2}".format(
                    engagement["engagement_id"], target_id, template["template_id"]
                ),
            )
            candidates.append(
                {
                    "path_id": path_id,
                    "template_id": template["template_id"],
                    "target_id": target_id,
                    "score": score,
                    "source": "deterministic",
                    "confidence": 0.5,
                    "rationale": template["summary"],
                    "risk": _highest(
                        [item["risk"] for item in action_values], RISK_ORDER
                    ),
                    "detectability": _highest(
                        [item["detectability"] for item in action_values],
                        DETECTABILITY_ORDER,
                    ),
                    "requires_explicit_approval": any(
                        item["requires_explicit_approval"] for item in action_values
                    ),
                    "credential_collection_advisory_permitted": any(
                        item.get("may_include_credential_collection_advice", False)
                        for item in action_values
                    )
                    and "credential_capture_assessment"
                    in engagement["objectives"],
                    "steps": [
                        dict(
                            {
                                "order": index + 1,
                                "action_id": action_id,
                            },
                            **ACTION_REGISTRY[action_id]
                        )
                        for index, action_id in enumerate(steps)
                    ],
                    "evidence_ids": target["evidence_ids"],
                    "missing_evidence": [],
                    "policy_checks": _policy_checks(engagement, disruptive),
                }
            )
        results[target_id] = sorted(
            candidates, key=lambda item: (-item["score"], item["template_id"], item["path_id"])
        )
    return results


def deterministic_results(
    candidates: Dict[str, List[Dict[str, Any]]]
) -> List[Dict[str, Any]]:
    results = []
    for target_id in candidates:
        paths = []
        for rank, candidate in enumerate(
            candidates[target_id][:MAX_PATHS_PER_TARGET], start=1
        ):
            path = dict(candidate)
            path["rank"] = rank
            paths.append(path)
        results.append({"target_id": target_id, "paths": paths})
    return results


def build_advisor_cloud_payload(
    engagement: Dict[str, Any],
    targets: Dict[str, Dict[str, Any]],
    candidates: Dict[str, List[Dict[str, Any]]],
    target_ids: List[str],
    secret: bytes,
    share_ssids: bool,
    language: str,
) -> Dict[str, Any]:
    cloud_targets = []
    for target_id in target_ids:
        target = targets[target_id]
        ssid = target["ssid"]
        if not share_ssids:
            ssid = _pseudonym(secret, "ssid", ssid or target_id)
        cloud_targets.append(
            {
                "target_id": target_id,
                "ssid": ssid,
                "ssid_shared": share_ssids,
                "hidden": target["hidden"],
                "vendors": target["vendors"],
                "channels": target["channels"],
                "encryption_codes": target["encryption_codes"],
                "metrics": target["metrics"],
                "flags": target["flags"],
                "role": target["role"],
                "interest": target["interest"],
                "evidence_ids": target["evidence_ids"],
                "candidate_paths": [
                    {
                        "path_id": path["path_id"],
                        "template_id": path["template_id"],
                        "score": path["score"],
                        "risk": path["risk"],
                        "detectability": path["detectability"],
                        "credential_collection_advisory_permitted": path[
                            "credential_collection_advisory_permitted"
                        ],
                        "steps": [
                            {"order": step["order"], "action_id": step["action_id"]}
                            for step in path["steps"]
                        ],
                        "evidence_ids": path["evidence_ids"],
                    }
                    for path in candidates[target_id]
                ],
            }
        )
    return {
        "schema_version": ADVISOR_SCHEMA_VERSION,
        "analysis_language": language,
        "engagement": {
            "engagement_id": _pseudonym(
                secret, "engagement", engagement["engagement_id"]
            ),
            "objectives": engagement["objectives"],
            "disruption_allowed": engagement["disruption_allowed"],
        },
        "targets": cloud_targets,
    }


def serialized_contains_mac(value: Any) -> bool:
    return bool(MAC_IN_TEXT_PATTERN.search(json.dumps(value, ensure_ascii=False)))
