"""Deterministic Adaptive Recon planning and privacy filtering."""

import datetime
import hashlib
import hmac
import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from .advisor import validate_profile_result
from .engagement_store import EVIDENCE_ID_PATTERN, TARGET_ID_PATTERN, parse_utc
from .errors import BackendError
from .profiler import MAC_IN_TEXT_PATTERN


ADAPTIVE_RECON_SCHEMA_VERSION = "1.0"
MAX_TARGETS = 10
MAX_HISTORY = 5
MAX_BANDS = 8
DURATION_CANDIDATES = (60, 180, 300, 600)
PLAN_TTL_SECONDS = 300
RECOMMENDATION_STATUS_MAX_AGE_SECONDS = 60
APPROVAL_STATUS_MAX_AGE_SECONDS = 10
PLAN_ID_PATTERN = re.compile(r"^reconplan_[0-9a-f]{12}$")
CANDIDATE_ID_PATTERN = re.compile(r"^reconcandidate_[0-9a-f]{12}$")
BAND_VALUE_PATTERN = re.compile(r"^[\x20-\x7e]{1,32}$")
ERROR_CODE_PATTERN = re.compile(r"^[a-z0-9_]{1,64}$")


def utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def utc_string(value: datetime.datetime) -> str:
    return value.astimezone(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def _identifier(secret: bytes, namespace: str, value: str) -> str:
    digest = hmac.new(
        secret,
        "{0}:{1}".format(namespace, value).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return "{0}_{1}".format(namespace, digest[:12])


def _digest(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _clean_text(value: Any, maximum: int = 500) -> str:
    text = str(value) if value is not None else ""
    text = "".join(character for character in text if ord(character) >= 32)
    return MAC_IN_TEXT_PATTERN.sub("[redacted_mac]", text)[:maximum]


def _missing_tokens(
    profile_target: Dict[str, Any], secret: bytes
) -> Tuple[List[str], int]:
    ai_profile = profile_target.get("ai_profile")
    if not isinstance(ai_profile, dict):
        return [], 0
    values = ai_profile.get("missing_evidence", [])
    if not isinstance(values, list):
        raise BackendError(
            "invalid_profile_result", "profile missing_evidence is invalid"
        )
    tokens = []
    for value in values[:8]:
        if not isinstance(value, str) or len(value) > 500:
            raise BackendError(
                "invalid_profile_result", "profile missing_evidence is invalid"
            )
        token = _identifier(secret, "missing", _clean_text(value, 500))
        if token not in tokens:
            tokens.append(token)
    return tokens, len(values)


def normalize_profile_snapshot(
    profile_result: Any, secret: bytes
) -> Dict[str, Any]:
    normalized = validate_profile_result(profile_result)
    original_targets = {
        target.get("target_id"): target
        for target in profile_result.get("targets", [])
        if isinstance(target, dict)
    }
    targets = {}
    for target_id, target in normalized.items():
        missing_tokens, missing_count = _missing_tokens(
            original_targets[target_id], secret
        )
        targets[target_id] = dict(
            target,
            missing_tokens=missing_tokens,
            missing_evidence_count=missing_count,
        )
    canonical = {
        target_id: {
            "channels": targets[target_id]["channels"],
            "encryption_codes": targets[target_id]["encryption_codes"],
            "metrics": targets[target_id]["metrics"],
            "flags": targets[target_id]["flags"],
            "role": targets[target_id]["role"],
            "interest": targets[target_id]["interest"],
            "missing_tokens": targets[target_id]["missing_tokens"],
            "evidence_ids": targets[target_id]["evidence_ids"],
        }
        for target_id in sorted(targets)
    }
    return {"targets": targets, "digest": _digest(canonical)}


def _validate_scan_request(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"live", "scan_time", "band"}:
        raise BackendError("invalid_history", "history scan request is invalid")
    if value["live"] is not False:
        raise BackendError("invalid_history", "history live must be false")
    scan_time = value["scan_time"]
    if (
        not isinstance(scan_time, int)
        or isinstance(scan_time, bool)
        or scan_time < 30
        or scan_time > 600
    ):
        raise BackendError("invalid_history", "history scan_time is invalid")
    band = value["band"]
    if not isinstance(band, str) or not BAND_VALUE_PATTERN.match(band):
        raise BackendError("invalid_history", "history band is invalid")
    return {"live": False, "scan_time": scan_time, "band": band}


def validate_history(history: Any, secret: bytes) -> List[Dict[str, Any]]:
    if history is None:
        return []
    if not isinstance(history, list) or len(history) > MAX_HISTORY:
        raise BackendError(
            "invalid_history", "history must contain at most five snapshots"
        )
    result = []
    for item in history:
        if not isinstance(item, dict) or set(item) != {
            "profile_result",
            "scan_metadata",
        }:
            raise BackendError("invalid_history", "history item shape is invalid")
        metadata = item["scan_metadata"]
        if not isinstance(metadata, dict) or set(metadata) != {
            "scan_id",
            "date",
            "request",
        }:
            raise BackendError("invalid_history", "history scan_metadata is invalid")
        scan_id = metadata["scan_id"]
        if not isinstance(scan_id, int) or isinstance(scan_id, bool) or scan_id < 0:
            raise BackendError("invalid_history", "history scan_id is invalid")
        date = parse_utc(metadata["date"], "history.date")
        snapshot = normalize_profile_snapshot(item["profile_result"], secret)
        result.append(
            {
                "profile": snapshot,
                "scan_id": scan_id,
                "date": utc_string(date),
                "request": _validate_scan_request(metadata["request"]),
            }
        )
    return sorted(result, key=lambda item: (item["date"], item["scan_id"]))


def validate_advisor_selection(
    advisor_result: Any,
    selected_path_ids: Any,
    expected_revision: int,
) -> Tuple[List[str], List[str], List[str]]:
    if (
        not isinstance(advisor_result, dict)
        or advisor_result.get("schema_version") != "1.0"
        or advisor_result.get("engagement_revision") != expected_revision
    ):
        raise BackendError(
            "stale_advisor_result",
            "advisor_result must be schema 1.0 at the expected engagement revision",
        )
    if (
        not isinstance(selected_path_ids, list)
        or not selected_path_ids
        or len(selected_path_ids) > MAX_TARGETS
        or any(not isinstance(value, str) for value in selected_path_ids)
    ):
        raise BackendError(
            "invalid_adaptive_request",
            "selected_path_ids must contain 1-10 path IDs",
        )
    selected_path_ids = list(dict.fromkeys(selected_path_ids))
    if len(selected_path_ids) > MAX_TARGETS:
        raise BackendError(
            "invalid_adaptive_request",
            "selected_path_ids must contain 1-10 unique path IDs",
        )
    target_results = advisor_result.get("target_results")
    if not isinstance(target_results, list):
        raise BackendError("invalid_advisor_result", "advisor target_results is invalid")
    known = {}
    for target_result in target_results:
        if not isinstance(target_result, dict):
            raise BackendError("invalid_advisor_result", "advisor target is invalid")
        target_id = target_result.get("target_id")
        paths = target_result.get("paths")
        if (
            not isinstance(target_id, str)
            or not TARGET_ID_PATTERN.match(target_id)
            or not isinstance(paths, list)
        ):
            raise BackendError("invalid_advisor_result", "advisor target is invalid")
        for path in paths:
            if not isinstance(path, dict):
                raise BackendError("invalid_advisor_result", "advisor path is invalid")
            path_id = path.get("path_id")
            if not isinstance(path_id, str) or path_id in known:
                raise BackendError("invalid_advisor_result", "advisor path_id is invalid")
            steps = path.get("steps")
            if not isinstance(steps, list):
                raise BackendError("invalid_advisor_result", "advisor steps are invalid")
            actions = []
            for step in steps:
                action_id = step.get("action_id") if isinstance(step, dict) else None
                if not isinstance(action_id, str):
                    raise BackendError(
                        "invalid_advisor_result", "advisor action is invalid"
                    )
                actions.append(action_id)
            evidence = path.get("evidence_ids", [])
            if (
                not isinstance(evidence, list)
                or any(
                    not isinstance(item, str)
                    or not EVIDENCE_ID_PATTERN.match(item)
                    for item in evidence
                )
            ):
                raise BackendError(
                    "invalid_advisor_result", "advisor evidence is invalid"
                )
            known[path_id] = {
                "target_id": target_id,
                "actions": actions,
                "evidence_ids": evidence,
            }
    target_ids = []
    evidence_ids = []
    for path_id in selected_path_ids:
        if path_id not in known:
            raise BackendError(
                "unknown_advisor_path", "selected path is missing from advisor_result"
            )
        path = known[path_id]
        if "collect_additional_recon" not in path["actions"]:
            raise BackendError(
                "invalid_advisor_path",
                "selected path does not contain collect_additional_recon",
            )
        if path["target_id"] in target_ids:
            raise BackendError(
                "invalid_adaptive_request",
                "only one Recon path may be selected for each target",
            )
        target_ids.append(path["target_id"])
        evidence_ids.extend(path["evidence_ids"])
    return target_ids, selected_path_ids, list(dict.fromkeys(evidence_ids))


def validate_device_context(
    value: Any,
    now: Optional[datetime.datetime] = None,
    maximum_age_seconds: int = RECOMMENDATION_STATUS_MAX_AGE_SECONDS,
) -> Dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "observed_at",
        "supported_bands",
        "recon_status",
    }:
        raise BackendError("invalid_device_context", "device_context shape is invalid")
    observed = parse_utc(value["observed_at"], "device_context.observed_at")
    current = now or utc_now()
    age = (current - observed).total_seconds()
    if age < -5 or age > maximum_age_seconds:
        raise BackendError(
            "stale_recon_status", "device Recon status observation is stale"
        )
    bands = value["supported_bands"]
    if not isinstance(bands, list) or not bands or len(bands) > MAX_BANDS:
        raise BackendError(
            "invalid_device_context", "supported_bands must contain 1-8 values"
        )
    normalized_bands = []
    seen_values = set()
    default_count = 0
    for band in bands:
        if not isinstance(band, dict) or set(band) != {
            "value",
            "covers",
            "is_default",
        }:
            raise BackendError(
                "invalid_device_context", "supported band shape is invalid"
            )
        raw_value = band["value"]
        covers = band["covers"]
        is_default = band["is_default"]
        if (
            not isinstance(raw_value, str)
            or not BAND_VALUE_PATTERN.match(raw_value)
            or raw_value in seen_values
        ):
            raise BackendError(
                "invalid_device_context", "supported band value is invalid"
            )
        if (
            not isinstance(covers, list)
            or not covers
            or len(covers) > 2
            or any(item not in ("2.4", "5") for item in covers)
        ):
            raise BackendError(
                "invalid_device_context", "supported band coverage is invalid"
            )
        if not isinstance(is_default, bool):
            raise BackendError(
                "invalid_device_context", "supported band is_default is invalid"
            )
        default_count += int(is_default)
        seen_values.add(raw_value)
        normalized_bands.append(
            {
                "value": raw_value,
                "covers": sorted(set(covers)),
                "is_default": is_default,
            }
        )
    if default_count > 1:
        raise BackendError(
            "invalid_device_context", "only one supported band may be default"
        )
    status = value["recon_status"]
    required = {
        "captureRunning",
        "scanRunning",
        "continuous",
        "scanPercent",
        "scanID",
    }
    if not isinstance(status, dict) or set(status) != required:
        raise BackendError("invalid_device_context", "recon_status shape is invalid")
    for field in ("captureRunning", "scanRunning", "continuous"):
        if not isinstance(status[field], bool):
            raise BackendError(
                "invalid_device_context", "recon_status boolean is invalid"
            )
    percent = status["scanPercent"]
    scan_id = status["scanID"]
    if (
        isinstance(percent, bool)
        or not isinstance(percent, (int, float))
        or percent < 0
        or percent > 100
        or not isinstance(scan_id, int)
        or isinstance(scan_id, bool)
        or scan_id < 0
    ):
        raise BackendError("invalid_device_context", "recon_status value is invalid")
    if status["captureRunning"] or status["scanRunning"]:
        raise BackendError("recon_busy", "Recon or capture operation is already running")
    return {
        "observed_at": utc_string(observed),
        "supported_bands": normalized_bands,
        "recon_status": dict(status),
    }


def _channel_bands(targets: Dict[str, Dict[str, Any]], target_ids: List[str]) -> Set[str]:
    bands = set()
    for target_id in target_ids:
        for channel in targets[target_id]["channels"]:
            if 1 <= channel <= 14:
                bands.add("2.4")
            elif 15 <= channel <= 196:
                bands.add("5")
            else:
                bands.add("unknown")
    return bands


def _structure(target: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "channels": target["channels"],
        "encryption_codes": target["encryption_codes"],
        "ap_count": target["metrics"]["ap_count"],
    }


def _latest_failed_or_aborted(
    events: List[Dict[str, Any]], target_ids: List[str]
) -> bool:
    for event in reversed(events):
        if event.get("event_type") != "adaptive_recon_finished":
            continue
        data = event.get("data", {})
        if not set(data.get("target_ids", [])).intersection(target_ids):
            continue
        return data.get("outcome") in ("failed", "aborted")
    return False


def analyze_history(
    current_profile: Dict[str, Any],
    history: List[Dict[str, Any]],
    target_ids: List[str],
    events: List[Dict[str, Any]],
) -> Dict[str, Any]:
    current_targets = current_profile["targets"]
    missing_now = {
        target_id: set(current_targets[target_id]["missing_tokens"])
        for target_id in target_ids
    }
    target_missing = False
    structure_changed = False
    stable = len(history) >= 3
    repeated_missing = False
    target_deltas = []
    for target_id in target_ids:
        current = current_targets[target_id]
        historical_targets = [
            item["profile"]["targets"].get(target_id) for item in history
        ]
        if history and any(item is None for item in historical_targets):
            target_missing = True
            stable = False
        present = [item for item in historical_targets if item is not None]
        if any(_structure(item) != _structure(current) for item in present):
            structure_changed = True
            stable = False
        if current["missing_evidence_count"]:
            stable = False
        if len(present) >= 2 and missing_now[target_id]:
            recent = present[-2:]
            repeated_missing = any(
                token in set(recent[0]["missing_tokens"])
                and token in set(recent[1]["missing_tokens"])
                for token in missing_now[target_id]
            )
        previous = present[-1] if present else None
        target_deltas.append(
            {
                "target_id": target_id,
                "present_in_history": len(present),
                "missing_from_history": len(history) - len(present),
                "ap_delta": (
                    current["metrics"]["ap_count"]
                    - previous["metrics"]["ap_count"]
                    if previous
                    else current["metrics"]["ap_count"]
                ),
                "client_delta": (
                    current["metrics"]["client_count"]
                    - previous["metrics"]["client_count"]
                    if previous
                    else current["metrics"]["client_count"]
                ),
                "channel_changed": bool(
                    previous and previous["channels"] != current["channels"]
                ),
                "encryption_changed": bool(
                    previous
                    and previous["encryption_codes"] != current["encryption_codes"]
                ),
                "missing_evidence_count": current["missing_evidence_count"],
                "evidence_ids": current["evidence_ids"],
            }
        )
    previous_failure = _latest_failed_or_aborted(events, target_ids)
    if stable:
        desired_duration = 60
        duration_reason = "Three or more stable snapshots have sufficient evidence."
    elif repeated_missing or previous_failure:
        desired_duration = 600
        duration_reason = (
            "Evidence remains unresolved across repeated snapshots or the previous "
            "Recon attempt did not complete."
        )
    elif (
        target_missing
        or structure_changed
        or any(missing_now[target_id] for target_id in target_ids)
    ):
        desired_duration = 300
        duration_reason = (
            "Targets changed, disappeared, or still have missing evidence."
        )
    else:
        desired_duration = 180
        duration_reason = "A bounded baseline observation is required."
    return {
        "history_count": len(history),
        "desired_duration": desired_duration,
        "duration_reason": duration_reason,
        "stable": stable,
        "target_missing": target_missing,
        "structure_changed": structure_changed,
        "repeated_missing": repeated_missing,
        "previous_failure": previous_failure,
        "target_deltas": target_deltas,
    }


def _eligible_bands(
    device_context: Dict[str, Any], required_bands: Set[str]
) -> List[Dict[str, Any]]:
    unknown = "unknown" in required_bands or not required_bands
    known = required_bands - {"unknown"}
    eligible = []
    for band in device_context["supported_bands"]:
        coverage = set(band["covers"])
        if unknown:
            if band["is_default"]:
                eligible.append(band)
        elif coverage.issuperset(known):
            eligible.append(band)
    if not eligible:
        raise BackendError(
            "band_not_supported",
            "no device-confirmed band covers the selected targets",
        )
    return eligible


def build_candidates(
    engagement_id: str,
    expected_revision: int,
    current_profile: Dict[str, Any],
    history: List[Dict[str, Any]],
    target_ids: List[str],
    path_ids: List[str],
    evidence_ids: List[str],
    device_context: Dict[str, Any],
    events: List[Dict[str, Any]],
    secret: bytes,
) -> Dict[str, Any]:
    analysis = analyze_history(current_profile, history, target_ids, events)
    required_bands = _channel_bands(current_profile["targets"], target_ids)
    bands = _eligible_bands(device_context, required_bands)
    plan_seed = {
        "engagement_id": engagement_id,
        "revision": expected_revision,
        "profile_digest": current_profile["digest"],
        "history_digests": [item["profile"]["digest"] for item in history],
        "target_ids": target_ids,
        "path_ids": path_ids,
        "supported_band_digest": _digest(device_context["supported_bands"]),
    }
    plan_id = _identifier(
        secret,
        "reconplan",
        json.dumps(plan_seed, sort_keys=True, separators=(",", ":")),
    )
    duration_index = {
        duration: index for index, duration in enumerate(DURATION_CANDIDATES)
    }
    candidates = []
    for band in bands:
        band_id = _identifier(secret, "band", band["value"])
        extra_coverage = len(set(band["covers"]) - (required_bands - {"unknown"}))
        for duration in DURATION_CANDIDATES:
            candidate_id = _identifier(
                secret,
                "reconcandidate",
                "{0}:{1}:{2}".format(plan_id, band["value"], duration),
            )
            candidates.append(
                {
                    "candidate_id": candidate_id,
                    "request": {
                        "live": False,
                        "scan_time": duration,
                        "band": band["value"],
                    },
                    "band_id": band_id,
                    "band_covers": band["covers"],
                    "is_default_band": band["is_default"],
                    "duration_distance": abs(
                        duration_index[duration]
                        - duration_index[analysis["desired_duration"]]
                    ),
                    "extra_band_coverage": extra_coverage,
                }
            )
    candidates = sorted(
        candidates,
        key=lambda item: (
            item["duration_distance"],
            item["extra_band_coverage"],
            item["request"]["scan_time"],
            item["candidate_id"],
        ),
    )
    for rank, candidate in enumerate(candidates, start=1):
        candidate["rank"] = rank
    return {
        "schema_version": ADAPTIVE_RECON_SCHEMA_VERSION,
        "plan_id": plan_id,
        "target_ids": target_ids,
        "path_ids": path_ids,
        "evidence_ids": list(dict.fromkeys(evidence_ids)),
        "profile_digest": current_profile["digest"],
        "history_digests": [item["profile"]["digest"] for item in history],
        "required_bands": sorted(required_bands),
        "analysis": analysis,
        "candidates": candidates,
        "baseline": {
            target_id: {
                "present": True,
                "channels": current_profile["targets"][target_id]["channels"],
                "encryption_codes": current_profile["targets"][target_id][
                    "encryption_codes"
                ],
                "metrics": current_profile["targets"][target_id]["metrics"],
                "evidence_ids": current_profile["targets"][target_id]["evidence_ids"],
            }
            for target_id in target_ids
        },
    }


def build_cloud_payload(
    plan: Dict[str, Any],
    current_profile: Dict[str, Any],
    secret: bytes,
    share_ssids: bool,
    language: str,
) -> Dict[str, Any]:
    targets = []
    delta_by_target = {
        item["target_id"]: item for item in plan["analysis"]["target_deltas"]
    }
    for target_id in plan["target_ids"]:
        target = current_profile["targets"][target_id]
        ssid = target["ssid"]
        if not share_ssids:
            ssid = _identifier(secret, "ssid", ssid or target_id)
        targets.append(
            {
                "target_id": target_id,
                "ssid": ssid,
                "ssid_shared": share_ssids,
                "channels": target["channels"],
                "encryption_codes": target["encryption_codes"],
                "metrics": target["metrics"],
                "role": target["role"],
                "interest": target["interest"],
                "missing_evidence_count": target["missing_evidence_count"],
                "evidence_ids": target["evidence_ids"],
                "delta": delta_by_target[target_id],
            }
        )
    return {
        "schema_version": ADAPTIVE_RECON_SCHEMA_VERSION,
        "analysis_language": language,
        "plan_id": plan["plan_id"],
        "targets": targets,
        "history_count": plan["analysis"]["history_count"],
        "desired_duration": plan["analysis"]["desired_duration"],
        "duration_reason": plan["analysis"]["duration_reason"],
        "candidate_plans": [
            {
                "candidate_id": candidate["candidate_id"],
                "rank": candidate["rank"],
                "scan_time": candidate["request"]["scan_time"],
                "band_id": candidate["band_id"],
                "band_covers": candidate["band_covers"],
            }
            for candidate in plan["candidates"]
        ],
    }


def build_result_delta(
    baseline: Dict[str, Any],
    completed_profile: Dict[str, Any],
    target_ids: List[str],
) -> Dict[str, Any]:
    output = []
    for target_id in target_ids:
        before = baseline[target_id]
        after = completed_profile["targets"].get(target_id)
        if after is None:
            output.append(
                {
                    "target_id": target_id,
                    "present_before": True,
                    "present_after": False,
                    "ap_delta": -before["metrics"]["ap_count"],
                    "client_delta": -before["metrics"]["client_count"],
                    "channels_added": [],
                    "channels_removed": before["channels"],
                    "encryption_added": [],
                    "encryption_removed": before["encryption_codes"],
                    "evidence_delta": -len(before["evidence_ids"]),
                }
            )
            continue
        output.append(
            {
                "target_id": target_id,
                "present_before": True,
                "present_after": True,
                "ap_delta": (
                    after["metrics"]["ap_count"] - before["metrics"]["ap_count"]
                ),
                "client_delta": (
                    after["metrics"]["client_count"]
                    - before["metrics"]["client_count"]
                ),
                "channels_added": sorted(
                    set(after["channels"]) - set(before["channels"])
                ),
                "channels_removed": sorted(
                    set(before["channels"]) - set(after["channels"])
                ),
                "encryption_added": sorted(
                    set(after["encryption_codes"])
                    - set(before["encryption_codes"])
                ),
                "encryption_removed": sorted(
                    set(before["encryption_codes"])
                    - set(after["encryption_codes"])
                ),
                "evidence_delta": (
                    len(after["evidence_ids"]) - len(before["evidence_ids"])
                ),
            }
        )
    return {
        "target_count_before": len(target_ids),
        "target_count_after": sum(
            1 for target_id in target_ids if target_id in completed_profile["targets"]
        ),
        "targets": output,
    }


def adaptive_recon_capabilities() -> Dict[str, Any]:
    return {
        "schema_version": ADAPTIVE_RECON_SCHEMA_VERSION,
        "durations": list(DURATION_CANDIDATES),
        "limits": {
            "targets_per_plan": MAX_TARGETS,
            "history_snapshots": MAX_HISTORY,
            "supported_bands": MAX_BANDS,
            "minimum_scan_time": 30,
            "maximum_scan_time": 600,
            "recommendation_ttl_seconds": PLAN_TTL_SECONDS,
            "approval_ttl_seconds": PLAN_TTL_SECONDS,
            "approval_status_max_age_seconds": APPROVAL_STATUS_MAX_AGE_SECONDS,
        },
        "live": False,
        "rest": {"method": "POST", "path": "/api/recon/start"},
        "states": [
            "recommended",
            "approved",
            "started",
            "completed",
            "failed",
            "aborted",
            "expired",
        ],
    }


def contains_mac(value: Any) -> bool:
    return bool(MAC_IN_TEXT_PATTERN.search(json.dumps(value, ensure_ascii=False)))
