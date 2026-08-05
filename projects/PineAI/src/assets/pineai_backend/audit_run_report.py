"""Deterministic, read-only AuditRun reports for PineAssure v0.7."""

import hashlib
import html
import json
import re
from typing import Any, Dict, Iterable, List, Set

from .errors import BackendError
from .repeatable_audit_store import (
    MAX_ACTIVE_MEASUREMENT_POINTS,
    MAX_AUDIT_RUNS_PER_ASSESSMENT,
    MAX_MEASUREMENT_POINTS_PER_RUN,
    MAX_TOTAL_MEASUREMENT_POINT_RECORDS,
)


AUDIT_REPORT_SCHEMA_VERSION = "1.0"
MAX_AUDIT_REPORT_BYTES = 4 * 1024 * 1024
MAX_AUDIT_FACT_BYTES = 512 * 1024
AUDIT_FACT_STATIC_RESERVE_BYTES = 32 * 1024
REPORT_FORMATS = {"json", "html"}
PRIVACY_PROFILES = {"local_full", "share_safe"}
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
MAC_PATTERN = re.compile(
    r"(?i)(?<![0-9a-f])(?:"
    r"(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}|"
    r"(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}"
    r")(?![0-9a-f])"
)
COMPACT_MAC_PATTERN = re.compile(
    r"(?i)(?<![0-9a-f])[0-9a-f]{12}(?![0-9a-f])"
)
SENSITIVE_KEYS = {
    "bssid",
    "bssids",
    "client_mac",
    "ap_mac",
    "mac",
    "physical_notes",
    "operator_instructions",
    "operator_notes",
    "description",
    "location_label",
    "reason",
    "scan_id",
    "source_recon_id",
    "location_id",
    "interface",
    "scan_profile_id",
    "radio_profile_id",
    "label",
}
SSID_PROSE_FIELDS = {
    "summary",
    "title",
    "description",
    "explanation",
    "alternative_explanations",
    "validation_steps",
    "limitations",
    "reason",
    "reasons",
    "message",
}
SSID_VALUE_FIELDS = {"expected", "observed", "before", "after"}


def _canonical_bytes(value: Any) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise BackendError("invalid_audit_report", "report facts are not valid JSON") from error


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _artifact_canonical_digest(value: Any) -> str:
    """Match immutable storage digest semantics (no presentation newline)."""
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise BackendError(
            "invalid_audit_report", "artifact is not valid JSON"
        ) from error
    return hashlib.sha256(encoded).hexdigest()


def _is_ssid_field(field: Any) -> bool:
    lowered = str(field).lower()
    return (
        lowered in ("ssid", "ssids")
        or lowered.endswith("_ssid")
        or lowered.endswith("_ssids")
    )


def _collect_ssid_values(value: Any, result: Set[str]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if _is_ssid_field(key):
                if isinstance(item, str) and item:
                    result.add(item)
                elif isinstance(item, list):
                    result.update(
                        entry
                        for entry in item
                        if isinstance(entry, str) and entry
                    )
            _collect_ssid_values(item, result)
    elif isinstance(value, list):
        for item in value:
            _collect_ssid_values(item, result)


def _redact_ssids_in_text(value: str, ssid_values: Iterable[str]) -> str:
    for ssid in sorted(set(ssid_values), key=lambda item: (-len(item), item)):
        prefix = r"(?<!\w)" if (ssid[0].isalnum() or ssid[0] == "_") else ""
        suffix = r"(?!\w)" if (ssid[-1].isalnum() or ssid[-1] == "_") else ""
        value = re.sub(
            prefix + re.escape(ssid) + suffix,
            "[redacted-ssid]",
            value,
        )
    return value


def _share_safe(
    value: Any,
    ssid_values: Iterable[str] = (),
    field: str = "",
) -> Any:
    if isinstance(value, dict):
        result = {}
        for key in sorted(value):
            lowered = str(key).lower()
            if lowered in SENSITIVE_KEYS:
                continue
            if _is_ssid_field(lowered):
                item = value[key]
                if isinstance(item, list):
                    result[key] = [
                        "[redacted-ssid]" for _unused in item
                    ]
                else:
                    result[key] = "[redacted-ssid]" if item else item
            else:
                result[key] = _share_safe(
                    value[key], ssid_values, lowered
                )
        return result
    if isinstance(value, list):
        return [_share_safe(item, ssid_values, field) for item in value]
    if isinstance(value, str):
        if field in SSID_VALUE_FIELDS and value and value in ssid_values:
            return "[redacted-ssid]"
        redacted = MAC_PATTERN.sub("[redacted-mac]", value)
        if field in SSID_PROSE_FIELDS | SSID_VALUE_FIELDS:
            redacted = COMPACT_MAC_PATTERN.sub("[redacted-mac]", redacted)
        if field in SSID_PROSE_FIELDS:
            redacted = _redact_ssids_in_text(redacted, ssid_values)
        return redacted
    return value


def _artifact_digest(record: Dict[str, Any], fields: List[str]) -> str:
    for field in fields:
        value = record.get(field)
        if isinstance(value, str) and SHA256_PATTERN.match(value):
            return value
    return _artifact_canonical_digest(record)


def _verify_reference(
    expected: Any,
    record: Dict[str, Any],
    fields: List[str],
    artifact_name: str,
) -> None:
    if expected is None:
        return
    actual = _artifact_digest(record, fields)
    if expected != actual:
        raise BackendError(
            "digest_mismatch",
            "{0} digest does not match the pinned AuditRun reference".format(
                artifact_name
            ),
        )


def _bounded_fact_size(value: Any, remaining_bytes: int) -> int:
    size = len(_canonical_bytes(value))
    if size > remaining_bytes:
        raise BackendError(
            "audit_report_too_large",
            "AuditRun facts exceed the safe report limit",
        )
    return size


def _terminal_time(run: Dict[str, Any]) -> str:
    value = (
        run.get("terminal_at")
        or run.get("completed_at")
        or run.get("cancelled_at")
    )
    if not isinstance(value, str) or not value:
        raise BackendError(
            "invalid_audit_run_report",
            "terminal AuditRun is missing its terminal timestamp",
        )
    return value


class AuditRunReportService:
    """Build a single canonical fact model and render it without writes."""

    def __init__(self, store):
        self.store = store

    def _measurement_facts(
        self,
        assessment_id: str,
        measurement: Dict[str, Any],
        remaining_bytes: int,
    ):
        fact = {
            key: measurement.get(key)
            for key in sorted(measurement)
            if key not in {"expected_measurement_context"}
        }
        fact_size = _bounded_fact_size(fact, remaining_bytes)
        artifact_reader = getattr(
            self.store, "read_audit_run_report_artifact", None
        )
        snapshot_id = measurement.get("snapshot_id")
        if snapshot_id:
            if callable(artifact_reader):
                snapshot = artifact_reader(
                    assessment_id,
                    "snapshot",
                    snapshot_id,
                    remaining_bytes - fact_size,
                    expected_digest=measurement.get("snapshot_digest"),
                )
            else:
                snapshot = self.store.get_snapshot(
                    assessment_id, snapshot_id
                )
            _verify_reference(
                measurement.get("snapshot_digest"),
                snapshot,
                ["snapshot_digest", "digest"],
                "snapshot",
            )
            _verify_reference(
                measurement.get("snapshot_record_digest"),
                snapshot,
                ["snapshot_record_digest"],
                "snapshot record",
            )
            fact["snapshot"] = snapshot
            fact_size = _bounded_fact_size(fact, remaining_bytes)
        comparison_id = measurement.get("comparison_id")
        comparison = None
        occurrence = None
        if comparison_id:
            if callable(artifact_reader):
                comparison = artifact_reader(
                    assessment_id,
                    "comparison",
                    comparison_id,
                    remaining_bytes - fact_size,
                    expected_digest=measurement.get("comparison_digest"),
                )
            else:
                comparison = self.store.get_comparison(
                    assessment_id, comparison_id
                )
            _verify_reference(
                measurement.get("comparison_digest"),
                comparison,
                ["comparison_digest", "digest"],
                "comparison",
            )
            fact["comparison"] = comparison
            fact_size = _bounded_fact_size(fact, remaining_bytes)
            if callable(artifact_reader):
                occurrence_id = measurement.get("occurrence_set_id")
                occurrence = artifact_reader(
                    assessment_id,
                    "occurrence",
                    occurrence_id,
                    remaining_bytes - fact_size,
                    expected_digest=comparison.get("occurrence_digest"),
                    expected_comparison_id=comparison_id,
                )
            else:
                occurrence = self.store.get_occurrence_set(
                    assessment_id, comparison_id
                )
            if occurrence is not None:
                _verify_reference(
                    measurement.get("occurrence_digest"),
                    occurrence,
                    ["occurrence_digest", "digest"],
                    "occurrence",
                )
                fact["occurrence"] = occurrence
                fact_size = _bounded_fact_size(fact, remaining_bytes)
            artifact_matcher = getattr(
                self.store,
                "_validate_artifacts_match_resolved_measurement",
                None,
            )
            if callable(artifact_matcher):
                artifact_matcher(
                    measurement,
                    comparison,
                    occurrence,
                    measurement.get("evidence_ids"),
                )
        return fact, fact_size

    def _run_events(
        self,
        assessment_id: str,
        audit_run_id: str,
        measurement_ids: List[str],
        remaining_bytes: int,
    ):
        """Return only immutable audit events that belong to this run."""
        direct_reader = getattr(
            self.store, "read_audit_run_events", None
        )
        if callable(direct_reader):
            return direct_reader(
                assessment_id,
                audit_run_id,
                measurement_ids,
                remaining_bytes,
            )
        after_sequence = 0
        selected = []
        selected_bytes = 0
        measurement_id_set = set(measurement_ids)
        page_limit = 25
        while True:
            page = self.store.get(
                assessment_id, after_sequence, page_limit
            )
            events = page.get("events", [])
            if not isinstance(events, list) or len(events) > page_limit:
                raise BackendError(
                    "invalid_audit_run_report",
                    "assessment audit history is invalid",
                )
            for event in events:
                data = event.get("data", {})
                if not isinstance(data, dict):
                    continue
                if (
                    data.get("audit_run_id") == audit_run_id
                    or data.get("measurement_id") in measurement_id_set
                ):
                    event_size = len(_canonical_bytes(event))
                    if selected_bytes + event_size > remaining_bytes:
                        raise BackendError(
                            "audit_report_too_large",
                            "AuditRun event facts exceed the safe report limit",
                        )
                    selected.append(event)
                    selected_bytes += event_size
            if not events or not page.get("events_has_more"):
                return selected, selected_bytes
            sequence = events[-1].get("sequence")
            if not isinstance(sequence, int) or sequence <= after_sequence:
                raise BackendError(
                    "invalid_audit_run_report",
                    "assessment audit history pagination is invalid",
                )
            after_sequence = sequence

    def fact_model(
        self, assessment_id: str, audit_run_id: str
    ) -> Dict[str, Any]:
        read_session = getattr(self.store, "_read_session", None)
        if callable(read_session):
            with read_session(assessment_id):
                return self._fact_model(assessment_id, audit_run_id)
        return self._fact_model(assessment_id, audit_run_id)

    def _fact_model(
        self, assessment_id: str, audit_run_id: str
    ) -> Dict[str, Any]:
        seed_reader = getattr(
            self.store, "read_audit_run_report_seed", None
        )
        if callable(seed_reader):
            detail = seed_reader(assessment_id, audit_run_id)
        else:
            detail = self.store.get_audit_run(
                assessment_id, audit_run_id
            )
        run = detail.get("audit_run")
        measurements = detail.get("measurements")
        if not isinstance(run, dict) or not isinstance(measurements, list):
            raise BackendError(
                "invalid_audit_run_report", "AuditRun detail is invalid"
            )
        if len(measurements) > MAX_MEASUREMENT_POINTS_PER_RUN:
            raise BackendError(
                "audit_report_too_large",
                "AuditRun contains too many measurements to report safely",
            )
        if run.get("status") not in ("completed", "cancelled"):
            raise BackendError(
                "audit_run_not_terminal",
                "AuditRun must be completed or cancelled before reporting",
            )
        measurement_facts = []
        fact_bytes = AUDIT_FACT_STATIC_RESERVE_BYTES
        for measurement in measurements:
            fact, fact_size = self._measurement_facts(
                assessment_id,
                measurement,
                MAX_AUDIT_FACT_BYTES - fact_bytes,
            )
            measurement_facts.append(fact)
            fact_bytes += fact_size
        measurement_ids = [
            item.get("measurement_id")
            for item in measurements
            if isinstance(item.get("measurement_id"), str)
        ]
        run_events, event_bytes = self._run_events(
            assessment_id,
            audit_run_id,
            measurement_ids,
            MAX_AUDIT_FACT_BYTES - fact_bytes,
        )
        fact_bytes += event_bytes
        status_counts = {}
        severity_counts = {}
        finding_count = 0
        for measurement in measurement_facts:
            status = str(measurement.get("status", "unknown"))
            status_counts[status] = status_counts.get(status, 0) + 1
            occurrence = measurement.get("occurrence") or {}
            findings = list(occurrence.get("policy_deviations", [])) + list(
                occurrence.get("security_findings", [])
            )
            finding_count += len(findings)
            for finding in findings:
                severity = str(finding.get("severity", "unknown"))
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
        facts = {
            "schema_version": AUDIT_REPORT_SCHEMA_VERSION,
            "product": {
                "name": "PineAssure",
                "technical_module_id": "PineAI",
                "tagline": "Baseline. Detect drift. Prove changes.",
            },
            "assessment_id": assessment_id,
            "audit_run": run,
            "generated_at": _terminal_time(run),
            "workflow": detail.get("workflow", {}),
            "capacity_limits": {
                "active_measurement_points_per_assessment": (
                    MAX_ACTIVE_MEASUREMENT_POINTS
                ),
                "total_measurement_points_per_assessment": (
                    MAX_TOTAL_MEASUREMENT_POINT_RECORDS
                ),
                "measurement_points_per_audit_run": (
                    MAX_MEASUREMENT_POINTS_PER_RUN
                ),
                "audit_runs_per_assessment": (
                    MAX_AUDIT_RUNS_PER_ASSESSMENT
                ),
                "simultaneous_active_audit_runs": 1,
                "simultaneous_scan_processing": 1,
            },
            "summary": {
                "measurement_count": len(measurement_facts),
                "measurement_status_counts": status_counts,
                "finding_count": finding_count,
                "severity_counts": severity_counts,
            },
            "measurements": measurement_facts,
            "audit_events": run_events,
            "limitations": [
                "Hardware resource limits are not Mark VII calibrated",
                (
                    "MeasurementProfile settings are operator-declared; "
                    "PineAssure does not independently verify that the "
                    "selected Hak5 saved Recon scan was collected with the "
                    "pinned interface, bands, channels, duration, or radio "
                    "profile"
                ),
            ],
        }
        _bounded_fact_size(facts, MAX_AUDIT_FACT_BYTES)
        return facts

    @staticmethod
    def _html(facts: Dict[str, Any]) -> str:
        run = facts["audit_run"]
        rows = []
        for measurement in facts["measurements"]:
            rows.append(
                "<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>".format(
                    html.escape(str(measurement.get("measurement_point_id", ""))),
                    html.escape(str(measurement.get("status", ""))),
                    html.escape(str(measurement.get("snapshot_id", ""))),
                    html.escape(str(measurement.get("comparison_id", ""))),
                )
            )
        canonical = _canonical_bytes(facts).decode("utf-8")
        return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>PineAssure AuditRun report</title>
<style>body{{font-family:sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#17202a}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ccd1d1;padding:.45rem;text-align:left}}pre{{white-space:pre-wrap;word-break:break-word;background:#f4f6f7;padding:1rem}}.notice{{border-left:4px solid #d68910;padding:.5rem 1rem;background:#fef9e7}}</style></head>
<body><h1>PineAssure AuditRun report</h1><p><strong>Run:</strong> {run}</p><p><strong>Status:</strong> {status}</p><p><strong>Terminal time:</strong> {generated}</p>
<div class="notice">Deterministic offline report. Hardware resource validation is pending. MeasurementProfile settings are operator-declared and are not independently verified against the selected Hak5 saved Recon scan.</div>
<h2>Measurements</h2><table><thead><tr><th>Measurement point</th><th>Status</th><th>Snapshot</th><th>Comparison</th></tr></thead><tbody>{rows}</tbody></table>
<h2>Canonical evidence appendix</h2><pre>{facts}</pre></body></html>\n""".format(
            run=html.escape(str(run.get("audit_run_id", ""))),
            status=html.escape(str(run.get("status", ""))),
            generated=html.escape(str(facts["generated_at"])),
            rows="".join(rows),
            facts=html.escape(canonical),
        )

    def generate(
        self,
        assessment_id: str,
        audit_run_id: str,
        report_format: str,
        privacy_profile: str,
    ) -> Dict[str, Any]:
        if report_format not in REPORT_FORMATS:
            raise BackendError(
                "invalid_report_format", "format must be json or html"
            )
        if privacy_profile not in PRIVACY_PROFILES:
            raise BackendError(
                "invalid_privacy_profile",
                "privacy_profile must be local_full or share_safe",
            )
        facts = self.fact_model(assessment_id, audit_run_id)
        if privacy_profile == "share_safe":
            ssid_values: Set[str] = set()
            _collect_ssid_values(facts, ssid_values)
            facts["audit_run"]["name"] = "[redacted]"
            facts = _share_safe(facts, ssid_values)
        fact_digest = _digest(facts)
        report_id = "audit_report_{0}".format(fact_digest[:16])
        if report_format == "json":
            content_bytes = _canonical_bytes(facts)
            mime_type = "application/json"
        else:
            content_bytes = self._html(facts).encode("utf-8")
            mime_type = "text/html"
        if len(content_bytes) > MAX_AUDIT_REPORT_BYTES:
            raise BackendError(
                "audit_report_too_large",
                "AuditRun report exceeds the safe output limit",
            )
        extension = "json" if report_format == "json" else "html"
        return {
            "schema_version": AUDIT_REPORT_SCHEMA_VERSION,
            "report_id": report_id,
            "audit_run_id": audit_run_id,
            "format": report_format,
            "privacy_profile": privacy_profile,
            "generated_at": facts["generated_at"],
            "fact_digest": fact_digest,
            "content_sha256": hashlib.sha256(content_bytes).hexdigest(),
            "filename": "PineAssure-{0}-{1}.{2}".format(
                audit_run_id, privacy_profile, extension
            ),
            "mime_type": mime_type,
            "content": content_bytes.decode("utf-8"),
        }
