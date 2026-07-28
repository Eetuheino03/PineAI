"""Deterministic JSON and standalone HTML reporting for Baseline & Drift.

The report fact model is deliberately independent from persistence.  Callers
must provide the immutable comparison occurrence/evidence records they want to
report.  This keeps report rendering deterministic and makes the scope and
privacy boundary visible to every adapter.
"""

import hashlib
import html
import json
import re
from typing import Any, Dict, Iterable, List, Optional, Set

from .assurance import ASSURANCE_SCHEMA_VERSION
from .errors import BackendError


REPORT_SCHEMA_VERSION = "1.1"
REPORT_SCOPES = (
    "comparison",
    "assessment_current",
    "assessment_history",
)
PRIVACY_PROFILES = ("local_full", "share_safe")
SAFE_FILENAME = re.compile(r"[^a-zA-Z0-9._-]+")
MAC_IN_TEXT = re.compile(r"(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}")
MAC_FIELDS = {
    "bssid",
    "bssids",
    "mac",
    "mac_address",
    "client_mac",
    "client_macs",
}


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise BackendError("invalid_report", "report data must be valid JSON")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _safe_name(value: Any, fallback: str = "assessment") -> str:
    """Return one path-component-safe portable filename stem."""
    text = str(value or fallback).strip()
    text = SAFE_FILENAME.sub("-", text).strip("-._")
    if not text or text in (".", ".."):
        text = fallback
    return text[:80]


def _copy_json(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value, ensure_ascii=False))
    except (TypeError, ValueError):
        raise BackendError("invalid_report", "report data must be valid JSON")


def _share_safe(value: Any, share_ssids: bool = False, field: str = "") -> Any:
    """Recursively remove direct wireless identifiers from a report value."""
    if isinstance(value, dict):
        result = {}
        for key in sorted(value):
            lowered = str(key).lower()
            item = value[key]
            if lowered in MAC_FIELDS:
                if isinstance(item, list):
                    result[key] = ["[redacted-mac]" for _unused in item]
                elif item is None:
                    result[key] = None
                else:
                    result[key] = "[redacted-mac]"
            elif (
                lowered != "share_ssids"
                and (
                    lowered in ("ssid", "ssids")
                    or lowered.endswith("_ssid")
                    or lowered.endswith("_ssids")
                )
                and not share_ssids
            ):
                if isinstance(item, list):
                    result[key] = ["[redacted-ssid]" for _unused in item]
                elif item is None:
                    result[key] = None
                else:
                    result[key] = "[redacted-ssid]"
            elif lowered in ("notes", "local_notes", "authorization_reference"):
                result[key] = "[redacted]"
            else:
                result[key] = _share_safe(item, share_ssids, lowered)
        return result
    if isinstance(value, list):
        return [_share_safe(item, share_ssids, field) for item in value]
    if isinstance(value, str):
        return MAC_IN_TEXT.sub("[redacted-mac]", value)
    return value


def _privacy_copy(
    value: Any, privacy_profile: str, share_ssids: bool = False
) -> Any:
    if privacy_profile == "local_full":
        return _copy_json(value)
    return _share_safe(value, share_ssids)


def _collect_evidence_ids(value: Any, result: Set[str]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "evidence_id" and isinstance(item, str) and item:
                result.add(item)
            elif key == "evidence_ids" and isinstance(item, list):
                result.update(
                    reference
                    for reference in item
                    if isinstance(reference, str) and reference
                )
            else:
                _collect_evidence_ids(item, result)
    elif isinstance(value, list):
        for item in value:
            _collect_evidence_ids(item, result)


def _evidence_sources(
    baseline: Dict[str, Any],
    comparison: Dict[str, Any],
    evidence: Optional[List[Dict[str, Any]]],
) -> Iterable[Dict[str, Any]]:
    baseline_snapshot = baseline.get("snapshot", baseline)
    current_snapshot = comparison.get("current_snapshot", {})
    for source in (baseline_snapshot, current_snapshot, comparison):
        if isinstance(source, dict) and isinstance(source.get("evidence"), list):
            for item in source["evidence"]:
                yield item
    if evidence is not None:
        if not isinstance(evidence, list):
            raise BackendError("invalid_report", "evidence must be an array")
        for item in evidence:
            yield item


def _index_evidence(
    baseline: Dict[str, Any],
    comparison: Dict[str, Any],
    evidence: Optional[List[Dict[str, Any]]],
) -> Dict[str, Dict[str, Any]]:
    indexed = {}
    for item in _evidence_sources(baseline, comparison, evidence):
        if not isinstance(item, dict):
            raise BackendError("invalid_report", "evidence records must be objects")
        evidence_id = item.get("evidence_id")
        if not isinstance(evidence_id, str) or not evidence_id:
            raise BackendError(
                "invalid_report", "evidence record has no evidence_id"
            )
        normalized = _copy_json(item)
        previous = indexed.get(evidence_id)
        if previous is not None and previous != normalized:
            raise BackendError(
                "invalid_report",
                "evidence_id {0} has conflicting records".format(evidence_id),
            )
        indexed[evidence_id] = normalized
    return indexed


def _scope_findings(
    scope: str,
    comparison: Dict[str, Any],
    findings: List[Dict[str, Any]],
    limitations: List[str],
) -> List[Dict[str, Any]]:
    if not isinstance(findings, list) or any(
        not isinstance(item, dict) for item in findings
    ):
        raise BackendError("invalid_report", "findings must be an array of objects")

    if scope != "comparison":
        return _copy_json(findings)

    occurrences = comparison.get("finding_occurrences")
    if occurrences is not None:
        if not isinstance(occurrences, list) or any(
            not isinstance(item, dict) for item in occurrences
        ):
            raise BackendError(
                "invalid_report", "finding_occurrences must be an array"
            )
        return _copy_json(occurrences)

    observed_ids = comparison.get("observed_finding_ids")
    if isinstance(observed_ids, list):
        allowed = set(
            item for item in observed_ids if isinstance(item, str) and item
        )
        selected = [
            item for item in findings if item.get("finding_id") in allowed
        ]
        missing = sorted(
            allowed
            - set(
                item.get("finding_id")
                for item in selected
                if isinstance(item.get("finding_id"), str)
            )
        )
        if missing:
            limitations.append(
                "Historical finding facts are unavailable for: {0}".format(
                    ", ".join(missing)
                )
            )
        limitations.append(
            "This legacy comparison has finding IDs but no immutable "
            "point-in-time finding occurrence records."
        )
        return _copy_json(selected)

    limitations.append(
        "This legacy comparison has no immutable point-in-time finding "
        "occurrence records; current findings are shown."
    )
    return _copy_json(findings)


def _history_records(value: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise BackendError("invalid_report", "history must be an array of objects")
    return sorted(
        _copy_json(value),
        key=lambda item: (
            str(item.get("created_at") or item.get("recorded_at") or ""),
            str(item.get("comparison_id") or ""),
        ),
    )


def report_scope_digest(fact_model: Dict[str, Any]) -> str:
    """Digest exactly the authoritative facts selected for one report scope."""
    if not isinstance(fact_model, dict):
        raise BackendError("invalid_report", "fact model must be an object")
    selected = {
        key: fact_model.get(key)
        for key in (
            "schema_version",
            "assurance_schema_version",
            "report_type",
            "scope",
            "privacy",
            "authority",
            "assessment",
            "baseline",
            "comparison",
            "observed_changes",
            "policy_deviations",
            "security_findings",
            "findings",
            "evidence_appendix",
            "history",
            "limitations",
        )
    }
    return _digest(selected)


def prepare_report_manifest(fact_model: Dict[str, Any]) -> Dict[str, Any]:
    """Prepare deterministic section and whole-fact hashes without self-hashing."""
    if not isinstance(fact_model, dict):
        raise BackendError("invalid_report", "fact model must be an object")
    excluded = {"integrity", "content_digest"}
    sections = {
        key: fact_model[key]
        for key in sorted(fact_model)
        if key not in excluded
    }
    section_hashes = {
        key: _digest(sections[key])
        for key in sorted(sections)
    }
    return {
        "algorithm": "sha256",
        "scope_digest": report_scope_digest(fact_model),
        "section_sha256": section_hashes,
        "report_sha256": _digest(sections),
    }


def build_fact_model(
    assessment: Dict[str, Any],
    baseline: Dict[str, Any],
    comparison: Dict[str, Any],
    findings: List[Dict[str, Any]],
    ai_analysis: Optional[Dict[str, Any]] = None,
    scope: str = "comparison",
    privacy_profile: str = "local_full",
    evidence: Optional[List[Dict[str, Any]]] = None,
    history: Optional[List[Dict[str, Any]]] = None,
    share_ssids: bool = False,
) -> Dict[str, Any]:
    """Build the canonical report fact model shared by JSON and HTML."""
    if scope not in REPORT_SCOPES:
        raise BackendError(
            "invalid_report_scope",
            "scope must be comparison, assessment_current, or assessment_history",
        )
    if privacy_profile not in PRIVACY_PROFILES:
        raise BackendError(
            "invalid_privacy_profile",
            "privacy_profile must be local_full or share_safe",
        )
    if not isinstance(share_ssids, bool):
        raise BackendError("invalid_report", "share_ssids must be a boolean")
    if not all(
        isinstance(value, dict)
        for value in (assessment, baseline, comparison)
    ):
        raise BackendError("invalid_report", "report inputs are incomplete")

    limitations = []
    selected_findings = _scope_findings(
        scope, comparison, findings, limitations
    )
    for finding in selected_findings:
        # v0.6.2 customer reports use calibrated categorical certainty only.
        # Legacy numeric confidence remains an internal read-only compatibility
        # value and is never presented in the customer fact model.
        finding.pop("confidence", None)
        finding.pop("confidence_factors", None)
        finding["certainty"] = (
            finding.get("certainty")
            or finding.get("details", {}).get("certainty")
            or "limited"
        )
    observed_changes = _copy_json(
        comparison.get("observed_changes", [])
    )
    policy_deviations = _copy_json(
        comparison.get("policy_deviations", [])
    )
    security_findings = _copy_json(
        comparison.get("security_findings", selected_findings)
    )
    for label, values in (
        ("observed_changes", observed_changes),
        ("policy_deviations", policy_deviations),
        ("security_findings", security_findings),
    ):
        if not isinstance(values, list) or any(
            not isinstance(item, dict) for item in values
        ):
            raise BackendError(
                "invalid_report", "{0} must be an array".format(label)
            )
    history_records = _history_records(history)
    if scope == "assessment_history" and not history_records:
        limitations.append("No comparison history records were supplied.")

    referenced_evidence: Set[str] = set()
    _collect_evidence_ids(selected_findings, referenced_evidence)
    _collect_evidence_ids(observed_changes, referenced_evidence)
    _collect_evidence_ids(policy_deviations, referenced_evidence)
    _collect_evidence_ids(security_findings, referenced_evidence)
    _collect_evidence_ids(comparison.get("diff", comparison.get("changes")), referenced_evidence)
    if scope == "assessment_history":
        _collect_evidence_ids(history_records, referenced_evidence)

    indexed = _index_evidence(baseline, comparison, evidence)
    resolved = [
        indexed[evidence_id]
        for evidence_id in sorted(referenced_evidence)
        if evidence_id in indexed
    ]
    unresolved = sorted(referenced_evidence - set(indexed))
    if unresolved:
        limitations.append(
            "Evidence records were not supplied for: {0}".format(
                ", ".join(unresolved)
            )
        )

    baseline_snapshot = baseline.get("snapshot", baseline)
    current_snapshot = comparison.get("current_snapshot", {})
    fact_model = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "assurance_schema_version": ASSURANCE_SCHEMA_VERSION,
        "report_type": "pineai_baseline_drift",
        "scope": {
            "mode": scope,
            "comparison_id": comparison.get("comparison_id"),
            "historical_finding_snapshot_available": isinstance(
                comparison.get("finding_occurrences"), list
            ),
        },
        "privacy": {
            "profile": privacy_profile,
            "contains_sensitive_local_identifiers": (
                privacy_profile == "local_full"
            ),
            "share_ssids": (
                bool(share_ssids) if privacy_profile == "share_safe" else True
            ),
            "notice": (
                "Local full reports may contain SSIDs, BSSIDs, locations, "
                "and other sensitive assessment facts."
                if privacy_profile == "local_full"
                else "Direct MAC/BSSID values and local notes are redacted."
            ),
        },
        "authority": {
            "deterministic": True,
            "ai_authoritative": False,
            "notice": (
                "Comparability, changes, finding rules, severity, certainty, "
                "lifecycle, and evidence references are produced deterministically."
            ),
        },
        "assessment": {
            "assessment_id": assessment.get("assessment_id"),
            "name": assessment.get("name"),
            "location": assessment.get("location"),
            "status": assessment.get("status"),
            "revision": assessment.get("revision"),
        },
        "baseline": {
            "baseline_version": baseline.get("version"),
            "baseline_id": baseline.get("baseline_version_id"),
            "label": baseline.get("label"),
            "created_at": baseline.get("created_at"),
            "snapshot_id": baseline_snapshot.get("snapshot_id"),
            "snapshot_digest": baseline_snapshot.get("snapshot_digest"),
            "summary": baseline_snapshot.get("summary"),
        },
        "comparison": {
            "comparison_id": comparison.get("comparison_id"),
            "recorded_at": comparison.get("recorded_at")
            or comparison.get("created_at"),
            "baseline_snapshot_id": comparison.get("baseline_snapshot_id"),
            "current_snapshot_id": comparison.get("current_snapshot_id"),
            "current_snapshot_digest": comparison.get(
                "current_snapshot_digest"
            )
            or (
                current_snapshot.get("snapshot_digest")
                if isinstance(current_snapshot, dict)
                else None
            ),
            "comparability": comparison.get("comparability"),
            "summary": comparison.get("summary"),
            "diff": comparison.get("diff", comparison.get("changes")),
            "lifecycle": comparison.get("lifecycle"),
            "current_snapshot_summary": (
                current_snapshot.get("summary")
                if isinstance(current_snapshot, dict)
                else None
            ),
        },
        "observed_changes": observed_changes,
        "policy_deviations": policy_deviations,
        "security_findings": security_findings,
        "findings": selected_findings,
        "evidence_appendix": {
            "records": resolved,
            "referenced_evidence_ids": sorted(referenced_evidence),
            "unresolved_evidence_ids": unresolved,
        },
        "history": history_records if scope == "assessment_history" else [],
        "limitations": limitations,
        "ai_analysis": None,
    }
    if ai_analysis:
        if not isinstance(ai_analysis, dict):
            raise BackendError("invalid_report", "ai_analysis must be an object")
        fact_model["ai_analysis"] = {
            "authoritative": False,
            "analysis_id": ai_analysis.get("analysis_id"),
            "generated_at": ai_analysis.get("generated_at"),
            "model": ai_analysis.get("model"),
            "language": ai_analysis.get("language"),
            "summary": ai_analysis.get("summary"),
            "finding_explanations": ai_analysis.get(
                "finding_explanations", []
            ),
            "report_sections": ai_analysis.get("report_sections", {}),
        }

    if privacy_profile == "share_safe":
        fact_model["assessment"]["name"] = "[redacted]"
        fact_model["assessment"]["location"] = "[redacted]"
    fact_model = _privacy_copy(
        fact_model, privacy_profile, share_ssids=share_ssids
    )
    manifest = prepare_report_manifest(fact_model)
    fact_model["integrity"] = manifest
    # Retain the v0.6.1 field as an alias for compatible consumers.
    fact_model["content_digest"] = manifest["report_sha256"]
    return fact_model


def _tag(name: str, value: Any) -> str:
    return "<{0}>{1}</{0}>".format(
        name, html.escape(str(value if value is not None else ""))
    )


def _finding_rows(findings: List[Dict[str, Any]]) -> str:
    rows = []
    for finding in findings:
        evidence_ids = finding.get("evidence_ids", [])
        evidence = ", ".join(evidence_ids) if isinstance(evidence_ids, list) else ""
        rows.append(
            "<tr>"
            + _tag("td", finding.get("title") or finding.get("rule_id"))
            + _tag("td", finding.get("severity"))
            + _tag("td", finding.get("certainty"))
            + _tag("td", finding.get("status"))
            + _tag(
                "td",
                "yes" if finding.get("currently_observed", True) else "no",
            )
            + _tag("td", finding.get("summary"))
            + _tag("td", evidence)
            + "</tr>"
        )
    if not rows:
        return '<tr><td colspan="7">No findings.</td></tr>'
    return "".join(rows)


def _result_rows(results: List[Dict[str, Any]], empty_label: str) -> str:
    rows = []
    for item in results:
        identifier = (
            item.get("change_id")
            or item.get("deviation_id")
            or item.get("finding_id")
        )
        before_after = item.get("before_after")
        if before_after is None:
            before_after = {
                "before": item.get("expected"),
                "after": item.get("observed"),
            }
        rows.append(
            "<tr>"
            + _tag("td", identifier)
            + _tag("td", item.get("title") or item.get("change_type") or item.get("rule_id"))
            + _tag("td", item.get("severity") or "not applicable")
            + _tag("td", item.get("certainty"))
            + _tag(
                "td",
                json.dumps(
                    before_after,
                    ensure_ascii=False,
                    sort_keys=True,
                ),
            )
            + _tag("td", ", ".join(item.get("evidence_ids", [])))
            + "</tr>"
        )
    if not rows:
        return '<tr><td colspan="6">{0}</td></tr>'.format(
            html.escape(empty_label)
        )
    return "".join(rows)


def _changes_list(summary: Dict[str, Any]) -> str:
    if not isinstance(summary, dict) or not summary:
        return "<li>No change summary is available.</li>"
    return "".join(
        "<li><strong>{0}</strong>: {1}</li>".format(
            html.escape(str(key).replace("_", " ").title()),
            html.escape(str(summary[key])),
        )
        for key in sorted(summary)
    )


def _evidence_rows(evidence: List[Dict[str, Any]]) -> str:
    rows = []
    for item in evidence:
        rows.append(
            "<tr>"
            + _tag("td", item.get("evidence_id"))
            + _tag("td", item.get("evidence_type"))
            + _tag("td", item.get("subject_id"))
            + _tag(
                "td",
                json.dumps(
                    item.get("observed"),
                    ensure_ascii=False,
                    sort_keys=True,
                ),
            )
            + "</tr>"
        )
    if not rows:
        return '<tr><td colspan="4">No resolved evidence records.</td></tr>'
    return "".join(rows)


def _history_rows(history: List[Dict[str, Any]]) -> str:
    rows = []
    for item in history:
        rows.append(
            "<tr>"
            + _tag("td", item.get("comparison_id"))
            + _tag("td", item.get("created_at") or item.get("recorded_at"))
            + _tag(
                "td",
                item.get("comparability_status")
                or (item.get("comparability") or {}).get("status"),
            )
            + _tag("td", json.dumps(item.get("summary"), sort_keys=True))
            + "</tr>"
        )
    if not rows:
        return '<tr><td colspan="4">No history records.</td></tr>'
    return "".join(rows)


def _ai_html(ai_analysis: Optional[Dict[str, Any]]) -> str:
    if not ai_analysis:
        return ""
    sections = ai_analysis.get("report_sections", {})
    explanations = ai_analysis.get("finding_explanations", [])
    explanation_items = []
    for item in explanations:
        alternatives = "".join(
            "<li>{0}</li>".format(html.escape(str(value)))
            for value in item.get("alternative_explanations", [])
        )
        validation = "".join(
            "<li>{0}</li>".format(html.escape(str(value)))
            for value in item.get("validation_steps", [])
        )
        explanation_items.append(
            '<article class="ai-finding">'
            + _tag("h3", item.get("finding_id"))
            + _tag("p", item.get("explanation"))
            + "<h4>Alternative explanations</h4><ul>"
            + alternatives
            + "</ul><h4>Safe validation steps</h4><ul>"
            + validation
            + "</ul></article>"
        )
    limitations = "".join(
        "<li>{0}</li>".format(html.escape(str(value)))
        for value in sections.get("limitations", [])
    )
    return (
        '<section class="ai"><h2>Optional AI narrative</h2>'
        '<p class="warning"><strong>Not authoritative.</strong> This prose explains '
        "the deterministic data and cannot change any finding.</p>"
        + _tag("h3", "Executive summary")
        + _tag("p", sections.get("executive_summary"))
        + _tag("h3", "Technical summary")
        + _tag("p", sections.get("technical_summary"))
        + _tag("h3", "Change summary")
        + _tag("p", sections.get("change_summary"))
        + "<h3>Limitations</h3><ul>"
        + limitations
        + "</ul>"
        + "".join(explanation_items)
        + "</section>"
    )


def _render_html(report: Dict[str, Any]) -> str:
    assessment = report["assessment"]
    baseline = report["baseline"]
    comparison = report["comparison"]
    comparability = comparison.get("comparability") or {}
    evidence = report["evidence_appendix"]
    limitations = "".join(
        "<li>{0}</li>".format(html.escape(str(value)))
        for value in report.get("limitations", [])
    ) or "<li>None recorded.</li>"
    unresolved = ", ".join(evidence.get("unresolved_evidence_ids", [])) or "none"
    section_hashes = report["integrity"]["section_sha256"]
    integrity_rows = "".join(
        "<tr>{0}{1}</tr>".format(_tag("td", key), _tag("td", section_hashes[key]))
        for key in sorted(section_hashes)
    )
    canonical_model = json.dumps(
        report, ensure_ascii=False, indent=2, sort_keys=True
    )
    return """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root {{ color-scheme: light; font-family: Inter, Segoe UI, sans-serif; }}
body {{ margin: 0; color: #17212b; background: #f4f7f8; }}
main {{ max-width: 1120px; margin: 0 auto; padding: 2rem; }}
header, section {{ background: white; margin: 0 0 1rem; padding: 1.25rem;
  border: 1px solid #dce4e7; border-radius: 10px; }}
h1, h2, h3 {{ color: #153f3b; }}
.meta {{ display: grid; grid-template-columns: repeat(auto-fit,minmax(180px,1fr));
  gap: .75rem; }}
.meta div {{ background: #eef5f3; padding: .75rem; border-radius: 6px; }}
table {{ width: 100%; border-collapse: collapse; font-size: .92rem; }}
th, td {{ padding: .65rem; border: 1px solid #dce4e7; text-align: left;
  vertical-align: top; overflow-wrap: anywhere; }}
th {{ background: #e8f2f0; }}
pre {{ white-space: pre-wrap; overflow-wrap: anywhere; }}
.warning {{ border-left: 4px solid #c27a00; padding: .75rem; background: #fff7e8; }}
.ai {{ border-color: #c8b5e8; }}
.ai-finding {{ border-top: 1px solid #ddd; padding-top: .75rem; }}
@media (max-width: 720px) {{ main {{ padding: .6rem; }} table {{ display: block;
  overflow-x: auto; }} }}
</style>
</head>
<body><main>
<header>
<h1>{title}</h1>
<p>Deterministic Wi-Fi baseline and drift report</p>
<div class="meta">
<div><strong>Location</strong><br>{location}</div>
<div><strong>Scope</strong><br>{scope}</div>
<div><strong>Privacy</strong><br>{privacy}</div>
<div><strong>Baseline</strong><br>{baseline_version}</div>
<div><strong>Comparison</strong><br>{comparison_id}</div>
<div><strong>Comparability</strong><br>{comparability}</div>
</div>
</header>
<section class="warning"><strong>Privacy notice.</strong> {privacy_notice}</section>
<section>
<h2>Deterministic authority</h2>
<p>{authority}</p>
<p><strong>Comparability reasons:</strong> {reasons}</p>
</section>
<section><h2>Comparison summary</h2><ul>{changes}</ul></section>
<section>
<h2>Observed changes</h2>
<table><thead><tr><th>ID</th><th>Change</th><th>Severity</th>
<th>Certainty</th><th>Before / after</th><th>Evidence</th></tr></thead>
<tbody>{observed_change_rows}</tbody></table>
</section>
<section>
<h2>Policy deviations</h2>
<table><thead><tr><th>ID</th><th>Deviation</th><th>Severity</th>
<th>Certainty</th><th>Expected / observed</th><th>Evidence</th></tr></thead>
<tbody>{policy_deviation_rows}</tbody></table>
</section>
<section>
<h2>Security findings</h2>
<table><thead><tr><th>ID</th><th>Finding</th><th>Severity</th>
<th>Certainty</th><th>Expected / observed</th><th>Evidence</th></tr></thead>
<tbody>{security_finding_rows}</tbody></table>
</section>
<section>
<h2>Lifecycle records</h2>
<table>
<thead><tr><th>Finding</th><th>Severity</th><th>Certainty</th><th>Status</th>
<th>Observed</th><th>Summary</th><th>Evidence</th></tr></thead>
<tbody>{finding_rows}</tbody>
</table>
</section>
<section>
<h2>Evidence appendix</h2>
<p><strong>Unresolved evidence IDs:</strong> {unresolved}</p>
<table><thead><tr><th>Evidence ID</th><th>Type</th><th>Subject</th>
<th>Observed facts</th></tr></thead><tbody>{evidence_rows}</tbody></table>
</section>
<section>
<h2>Comparison history</h2>
<table><thead><tr><th>Comparison</th><th>Recorded</th><th>Comparability</th>
<th>Summary</th></tr></thead><tbody>{history_rows}</tbody></table>
</section>
<section><h2>Limitations</h2><ul>{limitations}</ul></section>
{ai}
<section>
<h2>Integrity manifest</h2>
<p>Scope digest: {scope_digest}</p>
<p>Report fact digest: {report_digest}</p>
<table><thead><tr><th>Section</th><th>SHA-256</th></tr></thead>
<tbody>{integrity_rows}</tbody></table>
</section>
<section>
<h2>Canonical fact model</h2>
<p>This escaped appendix is the same authoritative fact model used for JSON.</p>
<pre>{canonical_model}</pre>
</section>
</main></body></html>
""".format(
        title=html.escape(str(assessment.get("name") or "PineAI report")),
        location=html.escape(str(assessment.get("location") or "")),
        scope=html.escape(str(report["scope"]["mode"])),
        privacy=html.escape(str(report["privacy"]["profile"])),
        privacy_notice=html.escape(str(report["privacy"]["notice"])),
        baseline_version=html.escape(
            str(baseline.get("baseline_version") or "")
        ),
        comparison_id=html.escape(str(comparison.get("comparison_id") or "")),
        comparability=html.escape(str(comparability.get("status") or "")),
        authority=html.escape(str(report["authority"]["notice"])),
        reasons=html.escape(
            ", ".join(comparability.get("reasons", [])) or "none"
        ),
        changes=_changes_list(comparison.get("summary") or {}),
        observed_change_rows=_result_rows(
            report.get("observed_changes", []),
            "No observed changes.",
        ),
        policy_deviation_rows=_result_rows(
            report.get("policy_deviations", []),
            "No policy deviations.",
        ),
        security_finding_rows=_result_rows(
            report.get("security_findings", []),
            "No security findings.",
        ),
        finding_rows=_finding_rows(report["findings"]),
        unresolved=html.escape(unresolved),
        evidence_rows=_evidence_rows(evidence.get("records", [])),
        history_rows=_history_rows(report.get("history", [])),
        limitations=limitations,
        ai=_ai_html(report.get("ai_analysis")),
        scope_digest=html.escape(str(report["integrity"]["scope_digest"])),
        report_digest=html.escape(str(report["integrity"]["report_sha256"])),
        integrity_rows=integrity_rows,
        canonical_model=html.escape(canonical_model),
    )


def generate_report(
    assessment: Dict[str, Any],
    baseline: Dict[str, Any],
    comparison: Dict[str, Any],
    findings: List[Dict[str, Any]],
    output_format: str,
    ai_analysis: Optional[Dict[str, Any]] = None,
    scope: str = "comparison",
    privacy_profile: str = "local_full",
    evidence: Optional[List[Dict[str, Any]]] = None,
    history: Optional[List[Dict[str, Any]]] = None,
    share_ssids: bool = False,
) -> Dict[str, Any]:
    """Return a downloadable deterministic report descriptor."""
    if output_format not in ("json", "html"):
        raise BackendError(
            "invalid_report_format", "format must be json or html"
        )
    report = build_fact_model(
        assessment,
        baseline,
        comparison,
        findings,
        ai_analysis=ai_analysis,
        scope=scope,
        privacy_profile=privacy_profile,
        evidence=evidence,
        history=history,
        share_ssids=share_ssids,
    )
    if output_format == "json":
        content = (
            json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)
            + "\n"
        )
        mime_type = "application/json"
    else:
        content = _render_html(report)
        mime_type = "text/html"
    output_digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    report_name = (
        assessment.get("assessment_id")
        if privacy_profile == "share_safe"
        else assessment.get("name")
    )
    name = _safe_name(report_name, "assessment")
    comparison_id = _safe_name(
        comparison.get("comparison_id"), "comparison"
    )
    scope_name = _safe_name(scope, "comparison")
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "format": output_format,
        "scope": scope,
        "privacy_profile": privacy_profile,
        "filename": "PineAI-{0}-{1}-{2}.{3}".format(
            name, comparison_id, scope_name, output_format
        ),
        "mime_type": mime_type,
        "sha256": output_digest,
        "scope_digest": report["integrity"]["scope_digest"],
        "report_sha256": report["integrity"]["report_sha256"],
        "content": content,
    }
