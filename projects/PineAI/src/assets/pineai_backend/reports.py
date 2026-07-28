"""Deterministic JSON and standalone HTML reporting for Baseline & Drift."""

import hashlib
import html
import json
import re
from typing import Any, Dict, List, Optional

from .assurance import ASSURANCE_SCHEMA_VERSION, canonical_digest
from .errors import BackendError


REPORT_SCHEMA_VERSION = "1.0"
SAFE_FILENAME = re.compile(r"[^a-zA-Z0-9._-]+")


def _safe_name(value: Any, fallback: str = "assessment") -> str:
    text = str(value or fallback).strip()
    text = SAFE_FILENAME.sub("-", text).strip("-._")
    return (text or fallback)[:80]


def _authoritative_report(
    assessment: Dict[str, Any],
    baseline: Dict[str, Any],
    comparison: Dict[str, Any],
    findings: List[Dict[str, Any]],
    ai_analysis: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    if not all(isinstance(value, dict) for value in (assessment, baseline, comparison)):
        raise BackendError("invalid_report", "report inputs are incomplete")
    if not isinstance(findings, list):
        raise BackendError("invalid_report", "findings must be an array")

    baseline_snapshot = baseline.get("snapshot", baseline)
    current_snapshot = comparison.get("current_snapshot", {})
    report = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "assurance_schema_version": ASSURANCE_SCHEMA_VERSION,
        "report_type": "pineai_baseline_drift",
        "authority": {
            "deterministic": True,
            "ai_authoritative": False,
            "notice": (
                "Comparability, changes, finding rules, severity, confidence, "
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
            "summary": baseline_snapshot.get("summary"),
        },
        "comparison": {
            "comparison_id": comparison.get("comparison_id"),
            "recorded_at": comparison.get("recorded_at"),
            "baseline_snapshot_id": comparison.get("baseline_snapshot_id"),
            "current_snapshot_id": comparison.get("current_snapshot_id"),
            "comparability": comparison.get("comparability"),
            "summary": comparison.get("summary"),
            "diff": comparison.get("diff", comparison.get("changes")),
            "current_snapshot_summary": (
                current_snapshot.get("summary")
                if isinstance(current_snapshot, dict)
                else None
            ),
        },
        "findings": findings,
    }
    if ai_analysis:
        report["ai_analysis"] = {
            "authoritative": False,
            "analysis_id": ai_analysis.get("analysis_id"),
            "generated_at": ai_analysis.get("generated_at"),
            "model": ai_analysis.get("model"),
            "language": ai_analysis.get("language"),
            "summary": ai_analysis.get("summary"),
            "finding_explanations": ai_analysis.get("finding_explanations", []),
            "report_sections": ai_analysis.get("report_sections", {}),
        }
    else:
        report["ai_analysis"] = None
    report["content_digest"] = canonical_digest(report)
    return report


def _tag(name: str, value: Any) -> str:
    return "<{0}>{1}</{0}>".format(name, html.escape(str(value or "")))


def _finding_rows(findings: List[Dict[str, Any]]) -> str:
    rows = []
    for finding in findings:
        evidence = ", ".join(finding.get("evidence_ids", []))
        rows.append(
            "<tr>"
            + _tag("td", finding.get("title") or finding.get("rule_id"))
            + _tag("td", finding.get("severity"))
            + _tag("td", finding.get("confidence"))
            + _tag("td", finding.get("status"))
            + _tag("td", "yes" if finding.get("currently_observed", True) else "no")
            + _tag("td", finding.get("summary"))
            + _tag("td", evidence)
            + "</tr>"
        )
    if not rows:
        return '<tr><td colspan="7">No findings.</td></tr>'
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
            "<article class=\"ai-finding\">"
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
    findings = report["findings"]
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
<div><strong>Baseline</strong><br>{baseline_version}</div>
<div><strong>Comparison</strong><br>{comparison_id}</div>
<div><strong>Comparability</strong><br>{comparability}</div>
</div>
</header>
<section>
<h2>Deterministic authority</h2>
<p>{authority}</p>
<p><strong>Comparability reasons:</strong> {reasons}</p>
</section>
<section>
<h2>Observed changes</h2><ul>{changes}</ul>
</section>
<section>
<h2>Findings</h2>
<table>
<thead><tr><th>Finding</th><th>Severity</th><th>Confidence</th><th>Status</th>
<th>Observed</th><th>Summary</th><th>Evidence</th></tr></thead>
<tbody>{finding_rows}</tbody>
</table>
</section>
{ai}
<section><h2>Integrity</h2><p>Content digest: {digest}</p></section>
</main></body></html>
""".format(
        title=html.escape(str(assessment.get("name") or "PineAI report")),
        location=html.escape(str(assessment.get("location") or "")),
        baseline_version=html.escape(str(baseline.get("baseline_version") or "")),
        comparison_id=html.escape(str(comparison.get("comparison_id") or "")),
        comparability=html.escape(str(comparability.get("status") or "")),
        authority=html.escape(str(report["authority"]["notice"])),
        reasons=html.escape(", ".join(comparability.get("reasons", [])) or "none"),
        changes=_changes_list(comparison.get("summary") or {}),
        finding_rows=_finding_rows(findings),
        ai=_ai_html(report.get("ai_analysis")),
        digest=html.escape(str(report["content_digest"])),
    )


def generate_report(
    assessment: Dict[str, Any],
    baseline: Dict[str, Any],
    comparison: Dict[str, Any],
    findings: List[Dict[str, Any]],
    output_format: str,
    ai_analysis: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Return a downloadable deterministic report descriptor."""
    if output_format not in ("json", "html"):
        raise BackendError("invalid_report_format", "format must be json or html")
    report = _authoritative_report(
        assessment, baseline, comparison, findings, ai_analysis
    )
    if output_format == "json":
        content = json.dumps(
            report, ensure_ascii=False, indent=2, sort_keys=True
        ) + "\n"
        mime_type = "application/json"
    else:
        content = _render_html(report)
        mime_type = "text/html"
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    name = _safe_name(assessment.get("name"), "assessment")
    comparison_id = _safe_name(
        comparison.get("comparison_id"), "comparison"
    )
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "format": output_format,
        "filename": "PineAI-{0}-{1}.{2}".format(
            name, comparison_id, output_format
        ),
        "mime_type": mime_type,
        "sha256": digest,
        "content": content,
    }
