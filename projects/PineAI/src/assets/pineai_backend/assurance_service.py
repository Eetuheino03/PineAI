"""Application service for the PineAI Baseline & Drift workflow."""

from typing import Any, Dict, List, Optional

from .ai_analysis import AssuranceAIService, validate_ai_analysis
from .assurance import (
    ASSURANCE_SCHEMA_VERSION,
    assurance_capabilities,
    compare_snapshots,
    evaluate_finding_rules,
    resolve_assets,
)
from .assessment_store import AssessmentStore
from .config import ConfigError, ensure_pseudonymization_key
from .errors import BackendError
from .reports import generate_report


BACKEND_VERSION = "0.6.0"


def _revision(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise BackendError(
            "invalid_request", "expected_revision must be a positive integer"
        )
    return value


def _identifier_list(value: Any, field: str, maximum: int) -> Optional[List[str]]:
    if value is None:
        return None
    if not isinstance(value, list) or len(value) > maximum:
        raise BackendError(
            "invalid_request", "{0} must contain at most {1} values".format(field, maximum)
        )
    result = []
    for item in value:
        if not isinstance(item, str) or not item or len(item) > 128:
            raise BackendError("invalid_request", "{0} contains an invalid value".format(field))
        if item not in result:
            result.append(item)
    return result


class AssuranceService:
    """Coordinate pure analysis, private storage, optional AI, and reports."""

    def __init__(
        self,
        config_dir: Optional[str] = None,
        store: Optional[AssessmentStore] = None,
        ai_service: Optional[AssuranceAIService] = None,
    ):
        self.config_dir = config_dir
        self.store = store or AssessmentStore(config_dir)
        self.ai_service = ai_service or AssuranceAIService(config_dir)

    def _secret(self) -> bytes:
        try:
            return ensure_pseudonymization_key(self.config_dir)
        except ConfigError as failure:
            raise BackendError("configuration_error", str(failure))

    def capabilities(self) -> Dict[str, Any]:
        result = assurance_capabilities()
        result["backend_version"] = BACKEND_VERSION
        result["module_actions"] = [
            "assurance_capabilities",
            "create_assessment",
            "get_assessment",
            "list_assessments",
            "update_assessment",
            "archive_assessment",
            "resolve_recon",
            "create_baseline_version",
            "list_baseline_versions",
            "activate_baseline_version",
            "compare_recon",
            "analyze_recon",
            "list_findings",
            "update_finding",
            "prepare_ai_analysis",
            "generate_ai_analysis",
            "generate_report",
        ]
        result["ai_role"] = "non_authoritative_explanation_and_report_prose"
        result["recon_control"] = False
        return result

    def assessment_detail(
        self, assessment_id: str, after_sequence: int = 0, limit: int = 100
    ) -> Dict[str, Any]:
        result = self.store.get(assessment_id, after_sequence, limit)
        result["baseline_versions"] = self.store.list_baseline_versions(assessment_id)
        result["comparisons"] = self.store.list_comparisons(assessment_id)
        findings = self.store.list_findings(assessment_id)
        result["finding_summary"] = {
            "total": len(findings),
            "open": sum(item["status"] == "open" for item in findings),
            "acknowledged": sum(
                item["status"] == "acknowledged" for item in findings
            ),
            "false_positive": sum(
                item["status"] == "false_positive" for item in findings
            ),
            "resolved": sum(item["status"] == "resolved" for item in findings),
            "currently_observed": sum(
                bool(item["currently_observed"]) for item in findings
            ),
        }
        return result

    def resolve_recon(self, scan: Any, scan_metadata: Any) -> Dict[str, Any]:
        return {
            "schema_version": ASSURANCE_SCHEMA_VERSION,
            "snapshot": resolve_assets(
                scan, scan_metadata, self._secret()
            ),
        }

    def create_baseline_version(
        self,
        assessment_id: str,
        expected_revision: Any,
        scan: Any,
        scan_metadata: Any,
        label: Any,
    ) -> Dict[str, Any]:
        snapshot = self.resolve_recon(scan, scan_metadata)["snapshot"]
        return self.store.create_baseline_version(
            assessment_id, _revision(expected_revision), snapshot, label
        )

    def list_baseline_versions(self, assessment_id: str) -> Dict[str, Any]:
        assessment = self.store.get(assessment_id, 0, 1)
        return {
            "schema_version": ASSURANCE_SCHEMA_VERSION,
            "active_baseline_version": assessment["active_baseline_version"],
            "baselines": self.store.list_baseline_versions(assessment_id),
        }

    def _active_baseline(self, assessment: Dict[str, Any]) -> Dict[str, Any]:
        active = assessment.get("active_baseline_version")
        if not active:
            raise BackendError(
                "baseline_not_active",
                "assessment has no active baseline version",
            )
        return self.store.get_baseline_version(
            assessment["assessment_id"], active
        )

    def _comparison(
        self,
        assessment_id: str,
        scan: Any,
        scan_metadata: Any,
    ) -> Dict[str, Any]:
        assessment = self.store.get(assessment_id, 0, 1)
        if assessment["status"] == "archived":
            raise BackendError("assessment_archived", "assessment is archived")
        baseline = self._active_baseline(assessment)
        current = self.resolve_recon(scan, scan_metadata)["snapshot"]
        diff = compare_snapshots(baseline["snapshot"], current)
        candidates = evaluate_finding_rules(
            assessment_id,
            baseline["snapshot"],
            current,
            diff,
            self._secret(),
        )
        return {
            "schema_version": ASSURANCE_SCHEMA_VERSION,
            "mode": "preview",
            "assessment_revision": assessment["revision"],
            "baseline": baseline,
            "current_snapshot": current,
            "diff": diff,
            "candidate_findings": candidates,
        }

    def compare_recon(
        self, assessment_id: str, scan: Any, scan_metadata: Any
    ) -> Dict[str, Any]:
        return self._comparison(assessment_id, scan, scan_metadata)

    def analyze_recon(
        self,
        assessment_id: str,
        expected_revision: Any,
        scan: Any,
        scan_metadata: Any,
    ) -> Dict[str, Any]:
        preview = self._comparison(assessment_id, scan, scan_metadata)
        if preview["assessment_revision"] != _revision(expected_revision):
            raise BackendError(
                "revision_conflict", "assessment revision has changed"
            )
        result = self.store.persist_analysis(
            assessment_id,
            expected_revision,
            preview["diff"],
            preview["current_snapshot"],
            preview["candidate_findings"],
        )
        result["schema_version"] = ASSURANCE_SCHEMA_VERSION
        return result

    def _analysis_inputs(
        self,
        assessment_id: str,
        comparison_id: str,
        finding_ids: Any,
    ):
        assessment = self.store.get(assessment_id, 0, 1)
        comparison_record = self.store.get_comparison(
            assessment_id, comparison_id
        )
        findings = self.store.list_findings(assessment_id)
        requested = _identifier_list(finding_ids, "finding_ids", 100)
        if requested is None:
            requested = comparison_record.get("observed_finding_ids", [])
        by_id = {finding["finding_id"]: finding for finding in findings}
        if any(finding_id not in by_id for finding_id in requested):
            raise BackendError(
                "finding_not_found", "one or more findings were not found"
            )
        selected = [by_id[finding_id] for finding_id in requested]
        diff = comparison_record["comparison"]
        comparison = {
            "comparison_id": comparison_record["comparison_id"],
            "recorded_at": comparison_record["created_at"],
            "comparability": diff["comparability"],
            "summary": diff["summary"],
            "diff": diff,
        }
        return assessment, comparison, selected

    def prepare_ai_analysis(
        self,
        assessment_id: str,
        comparison_id: str,
        finding_ids: Any,
        options: Any,
    ) -> Dict[str, Any]:
        assessment, comparison, findings = self._analysis_inputs(
            assessment_id, comparison_id, finding_ids
        )
        return self.ai_service.prepare(
            assessment, comparison, findings, options
        )

    def generate_ai_analysis(
        self,
        assessment_id: str,
        comparison_id: str,
        finding_ids: Any,
        options: Any,
    ) -> Dict[str, Any]:
        assessment, comparison, findings = self._analysis_inputs(
            assessment_id, comparison_id, finding_ids
        )
        return self.ai_service.generate(
            assessment, comparison, findings, options
        )

    def generate_report(
        self,
        assessment_id: str,
        comparison_id: str,
        output_format: Any,
        ai_analysis: Any = None,
    ) -> Dict[str, Any]:
        assessment = self.store.get(assessment_id, 0, 1)
        record = self.store.get_comparison(assessment_id, comparison_id)
        baseline = self.store.get_baseline_version(
            assessment_id, record["baseline_version_id"]
        )
        findings = self.store.list_findings(assessment_id)
        diff = record["comparison"]
        comparison = {
            "comparison_id": record["comparison_id"],
            "recorded_at": record["created_at"],
            "baseline_snapshot_id": record["baseline_snapshot_id"],
            "current_snapshot_id": record["current_snapshot_id"],
            "comparability": diff["comparability"],
            "summary": diff["summary"],
            "diff": diff,
        }
        validated_ai = None
        if ai_analysis is not None:
            if not isinstance(ai_analysis, dict):
                raise BackendError(
                    "invalid_ai_output", "ai_analysis must be an object"
                )
            selected = validate_ai_analysis(
                {
                    "summary": ai_analysis.get("summary"),
                    "finding_explanations": ai_analysis.get(
                        "finding_explanations"
                    ),
                    "report_sections": ai_analysis.get("report_sections"),
                },
                findings,
            )
            validated_ai = {
                "analysis_id": ai_analysis.get("analysis_id"),
                "model": ai_analysis.get("model"),
                "language": ai_analysis.get("language"),
            }
            validated_ai.update(selected)
        return generate_report(
            assessment,
            baseline,
            comparison,
            findings,
            output_format,
            validated_ai,
        )
