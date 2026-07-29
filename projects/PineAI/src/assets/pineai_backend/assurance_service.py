"""Application service for the PineAI Baseline & Drift workflow."""

from typing import Any, Dict, List, Optional

from . import __version__
from .assurance import (
    ASSURANCE_SCHEMA_VERSION,
    assurance_capabilities,
    resolve_assets,
)
from .customer_store import CustomerAuditStore
from .config import (
    ConfigError,
    IdentityKeyError,
    ensure_pseudonymization_key,
    load_settings,
)
from .errors import BackendError


BACKEND_VERSION = __version__


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
        store: Optional[CustomerAuditStore] = None,
        ai_service: Optional[Any] = None,
    ):
        self.config_dir = config_dir
        if store is None or not hasattr(
            store, "persist_customer_analysis"
        ):
            self.store = CustomerAuditStore(config_dir)
        else:
            self.store = store
        self._ai_service = ai_service

    @property
    def ai_service(self):
        if self._ai_service is None:
            from .ai_analysis import AssuranceAIService
            self._ai_service = AssuranceAIService(self.config_dir)
        return self._ai_service

    def _secret(self) -> bytes:
        try:
            return ensure_pseudonymization_key(self.config_dir)
        except IdentityKeyError as failure:
            raise BackendError(failure.code, str(failure))
        except ConfigError as failure:
            raise BackendError("configuration_error", str(failure))

    def create_assessment(self, value: Any) -> Dict[str, Any]:
        # Establish stable identity before the first identity-bound assessment
        # document is created. Later missing keys are never regenerated.
        self._secret()
        return self.store.create(value)

    def capabilities(self) -> Dict[str, Any]:
        from .assurance_profiles import assurance_profile_capabilities
        from .consensus import consensus_capabilities

        result = assurance_capabilities()
        legacy_rules = [
            {
                key: value
                for key, value in item.items()
                if key != "base_confidence"
            }
            for item in result.pop("rules", [])
        ]
        result["schema_version"] = "1.2"
        result["product_mode"] = "customer_audit_foundation"
        result["product_position"] = (
            "Portable offline wireless change auditing for WiFi Pineapple"
        )
        result["backend_version"] = BACKEND_VERSION
        result["module_actions"] = [
            "health",
            "get_settings",
            "update_settings",
            "set_openai_api_key",
            "delete_openai_api_key",
            "assurance_capabilities",
            "platform_capabilities",
            "list_measurement_profiles",
            "create_measurement_profile",
            "update_measurement_profile",
            "archive_measurement_profile",
            "create_assessment",
            "get_assessment",
            "list_assessments",
            "update_assessment",
            "archive_assessment",
            "resolve_recon",
            "create_baseline_version",
            "preview_consensus_baseline",
            "create_consensus_baseline_version",
            "list_baseline_versions",
            "get_baseline_version",
            "activate_baseline_version",
            "preview_inventory_csv",
            "create_assurance_profile_version",
            "list_assurance_profile_versions",
            "get_assurance_profile_version",
            "activate_assurance_profile_version",
            "export_inventory_csv",
            "compare_recon",
            "analyze_recon",
            "list_findings",
            "update_finding",
            "list_observed_changes",
            "get_evidence_bundle",
            "prepare_ai_analysis",
            "generate_ai_analysis",
            "prepare_report",
            "generate_report",
        ]
        result["consensus"] = consensus_capabilities()
        result["assurance_profiles"] = assurance_profile_capabilities()
        result["result_types"] = {
            "observed_change": {
                "severity": False,
                "lifecycle": False,
            },
            "policy_deviation": {
                "severity": True,
                "lifecycle": True,
            },
            "security_finding": {
                "severity": True,
                "lifecycle": True,
            },
        }
        result["legacy_history"] = {
            "read_only": True,
            "rules": legacy_rules,
        }
        result["authoritative_fields"] = [
            "comparability",
            "observed_changes",
            "policy_deviations",
            "security_findings",
            "certainty",
            "evidence_ids",
            "finding_status",
        ]
        result["certainty_levels"] = [
            "confirmed",
            "probable",
            "limited",
        ]
        result["report_scopes"] = [
            "comparison",
            "assessment_current",
            "assessment_history",
        ]
        result["privacy_profiles"] = ["local_full", "share_safe"]
        result["ai_role"] = "non_authoritative_explanation_and_report_prose"
        result["recon_control"] = False
        return result

    def assessment_detail(
        self, assessment_id: str, after_sequence: int = 0, limit: int = 100
    ) -> Dict[str, Any]:
        result = self.store.get(assessment_id, after_sequence, limit)
        result["baseline_versions"] = self.store.list_baseline_versions(assessment_id)
        if hasattr(self.store, "list_assurance_profile_versions"):
            result["assurance_profile_versions"] = (
                self.store.list_assurance_profile_versions(assessment_id)
            )
        result["comparisons"] = self.store.list_comparisons(assessment_id)
        findings = self.store.list_findings(assessment_id)
        legacy_findings = [
            item
            for item in findings
            if item.get("details", {}).get("result_type")
            not in ("policy_deviation", "security_finding")
        ]
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
            "legacy_read_only": len(legacy_findings),
        }
        result["legacy_findings"] = legacy_findings
        return result

    def platform_capabilities(self) -> Dict[str, Any]:
        from .platform import platform_capabilities

        result = platform_capabilities(self.config_dir)
        result["backend_version"] = BACKEND_VERSION
        return result

    def list_measurement_profiles(
        self, include_archived: bool = False
    ) -> Dict[str, Any]:
        return {
            "schema_version": "1.0",
            "profiles": self.store.list_measurement_profiles(
                include_archived
            ),
        }

    def create_measurement_profile(self, profile: Any) -> Dict[str, Any]:
        return {
            "schema_version": "1.0",
            "measurement_profile": self.store.create_measurement_profile(
                profile
            ),
        }

    def update_measurement_profile(
        self, profile_id: str, expected_revision: Any, changes: Any
    ) -> Dict[str, Any]:
        return {
            "schema_version": "1.0",
            "measurement_profile": self.store.update_measurement_profile(
                profile_id, expected_revision, changes
            ),
        }

    def archive_measurement_profile(
        self, profile_id: str, expected_revision: Any
    ) -> Dict[str, Any]:
        return {
            "schema_version": "1.0",
            "measurement_profile": self.store.archive_measurement_profile(
                profile_id, expected_revision
            ),
        }

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

    def _resolved_observations(self, observations: Any) -> List[Dict[str, Any]]:
        if not isinstance(observations, list) or not (2 <= len(observations) <= 5):
            raise BackendError(
                "invalid_consensus_input",
                "observations must contain two to five saved Recon scans",
            )
        snapshots = []
        for observation in observations:
            if not isinstance(observation, dict) or set(observation) != {
                "scan",
                "scan_metadata",
            }:
                raise BackendError(
                    "invalid_consensus_input",
                    "each observation requires scan and scan_metadata",
                )
            snapshots.append(
                self.resolve_recon(
                    observation["scan"], observation["scan_metadata"]
                )["snapshot"]
            )
        return snapshots

    def preview_consensus_baseline(
        self,
        observations: Any,
        max_source_age_hours: Any = 24,
    ) -> Dict[str, Any]:
        from .consensus import build_consensus_baseline

        snapshots = self._resolved_observations(observations)
        model = build_consensus_baseline(
            snapshots, max_source_age_hours=max_source_age_hours
        )
        return {
            "schema_version": "1.2",
            "mode": "preview",
            "baseline_model": model,
            "source_snapshots": [
                {
                    "snapshot_id": item["snapshot_id"],
                    "snapshot_digest": item["snapshot_digest"],
                    "observed_at": item["observed_at"],
                    "summary": item["summary"],
                }
                for item in snapshots
            ],
            "limitations": model.get("limitation_codes", []),
        }

    def create_consensus_baseline_version(
        self,
        assessment_id: str,
        expected_revision: Any,
        observations: Any,
        label: Any,
        max_source_age_hours: Any = 24,
    ) -> Dict[str, Any]:
        from .consensus import build_consensus_baseline

        snapshots = self._resolved_observations(observations)
        model = build_consensus_baseline(
            snapshots, max_source_age_hours=max_source_age_hours
        )
        return self.store.create_consensus_baseline_version(
            assessment_id,
            _revision(expected_revision),
            snapshots,
            model,
            label,
        )

    def list_baseline_versions(self, assessment_id: str) -> Dict[str, Any]:
        assessment = self.store.get(assessment_id, 0, 1)
        return {
            "schema_version": ASSURANCE_SCHEMA_VERSION,
            "active_baseline_version": assessment["active_baseline_version"],
            "baselines": self.store.list_baseline_versions(assessment_id),
        }

    def get_baseline_version(
        self, assessment_id: str, baseline_version_id: str
    ) -> Dict[str, Any]:
        return {
            "schema_version": "1.2",
            "baseline": self.store.get_baseline_version(
                assessment_id, baseline_version_id
            ),
        }

    def preview_inventory_csv(
        self, content: Any, delimiter: Any = "comma"
    ) -> Dict[str, Any]:
        from .assurance_profiles import preview_inventory_csv

        return preview_inventory_csv(content, delimiter)

    def create_assurance_profile_version(
        self,
        assessment_id: str,
        expected_revision: Any,
        label: Any,
        inventory_preview: Any = None,
        profile: Any = None,
        coverage_mode: Any = "partial",
    ) -> Dict[str, Any]:
        from .assurance_profiles import AssuranceProfile

        if profile is not None and inventory_preview is not None:
            raise BackendError(
                "invalid_assurance_profile",
                "provide either profile or inventory_preview, not both",
            )
        if profile is not None:
            normalized = AssuranceProfile.from_dict(profile)
        else:
            normalized = AssuranceProfile.from_inventory_preview(
                inventory_preview, coverage_mode=coverage_mode
            )
        return self.store.create_assurance_profile_version(
            assessment_id,
            _revision(expected_revision),
            normalized.to_dict(),
            label,
        )

    def list_assurance_profile_versions(
        self, assessment_id: str
    ) -> Dict[str, Any]:
        assessment = self.store.get(assessment_id, 0, 1)
        return {
            "schema_version": "1.0",
            "active_assurance_profile_version": assessment.get(
                "active_assurance_profile_version"
            ),
            "assurance_profiles": (
                self.store.list_assurance_profile_versions(assessment_id)
            ),
        }

    def get_assurance_profile_version(
        self, assessment_id: str, version_id: str
    ) -> Dict[str, Any]:
        return {
            "schema_version": "1.0",
            "assurance_profile": (
                self.store.get_assurance_profile_version(
                    assessment_id, version_id
                )
            ),
        }

    def activate_assurance_profile_version(
        self,
        assessment_id: str,
        expected_revision: Any,
        version_id: str,
        authoritative_confirmation: Any = False,
    ) -> Dict[str, Any]:
        return self.store.activate_assurance_profile_version(
            assessment_id,
            _revision(expected_revision),
            version_id,
            authoritative_confirmation,
        )

    def export_inventory_csv(
        self,
        assessment_id: str,
        version_id: str,
        delimiter: Any = "comma",
    ) -> Dict[str, Any]:
        import hashlib

        from .assurance_profiles import (
            AssuranceProfile,
            export_inventory_csv,
        )

        record = self.store.get_assurance_profile_version(
            assessment_id, version_id
        )
        content = export_inventory_csv(
            AssuranceProfile.from_dict(record["profile"]), delimiter
        )
        encoded = content.encode("utf-8")
        return {
            "schema_version": "1.0",
            "filename": "PineAI-inventory-{0}.csv".format(version_id),
            "mime_type": "text/csv",
            "sha256": hashlib.sha256(encoded).hexdigest(),
            "content": content,
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
        from .assurance_profiles import (
            AssuranceProfile,
            evaluate_assurance_profile,
        )
        from .customer_analysis import (
            compare_customer_baseline,
            lifecycle_findings,
        )

        secret = self._secret()
        customer = compare_customer_baseline(
            assessment_id, baseline, current, secret
        )
        diff = customer["diff"]
        status = diff["comparability"]["status"]
        active_profile_version = assessment.get(
            "active_assurance_profile_version"
        )
        profile_record = None
        policy = {
            "observed_changes": [],
            "policy_deviations": [],
            "security_findings": [],
        }
        if active_profile_version:
            profile_record = self.store.get_assurance_profile_version(
                assessment_id, active_profile_version
            )
            profile = AssuranceProfile.from_dict(
                profile_record["profile"]
            )
            policy = evaluate_assurance_profile(
                profile, current, diff["comparability"]
            )
            certainty = (
                "limited"
                if status == "not_comparable"
                else (
                    "probable"
                    if status == "partially_comparable"
                    else None
                )
            )
            if certainty:
                for field in (
                    "observed_changes",
                    "policy_deviations",
                    "security_findings",
                ):
                    for item in policy[field]:
                        item["certainty"] = certainty
        observed_changes = {
            item["change_id"]: item
            for item in customer["observed_changes"]
        }
        observed_changes.update(
            {
                item["change_id"]: item
                for item in policy["observed_changes"]
            }
        )
        lifecycle = lifecycle_findings(
            assessment_id,
            policy["policy_deviations"],
            policy["security_findings"],
            secret,
        )
        profile_assets = []
        if profile_record:
            profile_assets = profile_record["profile"].get(
                "inventory", {}
            ).get("assets", [])
        observed_bssids = {
            item["bssid"] for item in current["access_points"]
        }
        inventory_bssids = {
            item.get("bssid") for item in profile_assets
        }
        inventory_reconciliation = {
            "configured": profile_record is not None,
            "inventory_asset_count": len(profile_assets),
            "observed_inventory_asset_count": len(
                observed_bssids & inventory_bssids
            ),
            "missing_inventory_asset_count": len(
                inventory_bssids - observed_bssids
            ),
            "outside_inventory_asset_count": len(
                observed_bssids - inventory_bssids
            ),
            "coverage_mode": (
                profile_record["profile"]
                .get("inventory", {})
                .get("coverage_mode")
                if profile_record
                else None
            ),
        }
        measurement = current.get("scan_metadata", {}).get(
            "measurement_context", {}
        )
        pinned_versions = {
            "baseline_version_id": baseline["baseline_version_id"],
            "baseline_digest": baseline.get(
                "baseline_model_digest", baseline.get("snapshot_digest")
            ),
            "measurement_profile_id": measurement.get(
                "measurement_profile_id"
            ),
            "measurement_profile_version_id": measurement.get(
                "measurement_profile_version_id"
            ),
            "measurement_profile_digest": measurement.get(
                "measurement_profile_digest"
            ),
            "assurance_profile_version_id": active_profile_version,
            "assurance_profile_digest": (
                profile_record.get("digest") if profile_record else None
            ),
        }
        return {
            "schema_version": "1.2",
            "mode": "preview",
            "assessment_revision": assessment["revision"],
            "baseline": baseline,
            "current_snapshot": current,
            "diff": diff,
            "observed_changes": sorted(
                observed_changes.values(),
                key=lambda item: item["change_id"],
            ),
            "inventory_reconciliation": inventory_reconciliation,
            "policy_deviations": policy["policy_deviations"],
            "security_findings": policy["security_findings"],
            "policy_evaluation_status": (
                "evaluated" if profile_record else "not_configured"
            ),
            "lifecycle_findings": lifecycle,
            "pinned_versions": pinned_versions,
            # Deprecated alias remains empty so old clients fail safe instead
            # of treating unclassified drift as a security finding.
            "candidate_findings": [],
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
        from .customer_analysis import evidence_records

        baseline = preview["baseline"]
        limitations = list(
            baseline.get("baseline_model", {}).get(
                "limitation_codes", []
            )
        )
        if baseline.get("legacy"):
            limitations.append("legacy_single_scan_baseline")
        occurrence_set = {
            "observed_changes": preview["observed_changes"],
            "inventory_reconciliation": preview[
                "inventory_reconciliation"
            ],
            "policy_deviations": preview["policy_deviations"],
            "security_findings": preview["security_findings"],
            "policy_evaluation_status": preview[
                "policy_evaluation_status"
            ],
            "lifecycle_findings": preview["lifecycle_findings"],
            "evidence": evidence_records(
                baseline, preview["current_snapshot"]
            ),
            "quality_factors": preview["diff"]["comparability"].get(
                "quality_factors", []
            ),
            "policy_reference": {
                "assurance_profile_version_id": preview[
                    "pinned_versions"
                ].get("assurance_profile_version_id"),
                "assurance_profile_digest": preview[
                    "pinned_versions"
                ].get("assurance_profile_digest"),
            },
            "limitations": limitations,
        }
        result = self.store.persist_customer_analysis(
            assessment_id,
            expected_revision,
            baseline["baseline_version_id"],
            preview["diff"],
            preview["current_snapshot"],
            preview["lifecycle_findings"],
            occurrence_set,
            preview["pinned_versions"],
        )
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

    def list_observed_changes(
        self,
        assessment_id: str,
        comparison_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        if comparison_id:
            occurrence = self.store.get_occurrence_set(
                assessment_id, comparison_id
            )
            if occurrence is None:
                return {
                    "schema_version": "1.0",
                    "comparison_id": comparison_id,
                    "observed_changes": [],
                    "legacy_limited": True,
                }
            occurrences = [occurrence]
        else:
            occurrences = self.store.list_occurrence_sets(assessment_id)
        return {
            "schema_version": "1.0",
            "comparison_id": comparison_id,
            "observed_changes": [
                dict(item, comparison_id=occurrence["comparison_id"])
                for occurrence in occurrences
                for item in occurrence.get("observed_changes", [])
            ],
            "legacy_limited": False,
        }

    def get_evidence_bundle(
        self,
        assessment_id: str,
        comparison_id: str,
        item_id: str,
    ) -> Dict[str, Any]:
        return self.store.evidence_bundle(
            assessment_id, comparison_id, item_id
        )

    def _report_material(
        self,
        assessment_id: str,
        scope: Any,
        comparison_id: Optional[str] = None,
    ):
        if isinstance(scope, str):
            scope_value = {"type": scope}
            if comparison_id:
                scope_value["comparison_id"] = comparison_id
        elif isinstance(scope, dict):
            scope_value = dict(scope)
        else:
            raise BackendError(
                "invalid_report_scope", "report scope is required"
            )
        scope_type = scope_value.get("type")
        if scope_type not in (
            "comparison",
            "assessment_current",
            "assessment_history",
        ):
            raise BackendError(
                "invalid_report_scope", "report scope type is invalid"
            )
        if scope_type == "comparison":
            comparison_id = scope_value.get("comparison_id") or comparison_id
            if not isinstance(comparison_id, str) or not comparison_id:
                raise BackendError(
                    "invalid_report_scope",
                    "comparison scope requires comparison_id",
                )

        assessment = self.store.get(assessment_id, 0, 1)
        occurrences = self.store.list_occurrence_sets(assessment_id)
        records = self.store.list_comparisons(assessment_id)
        if scope_type == "comparison":
            record = self.store.get_comparison(
                assessment_id, comparison_id
            )
            occurrence = self.store.get_occurrence_set(
                assessment_id, comparison_id
            )
            selected_occurrences = [occurrence] if occurrence else []
        else:
            if not records:
                raise BackendError(
                    "comparison_not_found",
                    "assessment has no comparison to report",
                )
            record = self.store.get_comparison(
                assessment_id, records[0]["comparison_id"]
            )
            occurrence = self.store.get_occurrence_set(
                assessment_id, record["comparison_id"]
            )
            selected_occurrences = occurrences

        baseline = self.store.get_baseline_version(
            assessment_id, record["baseline_version_id"]
        )
        diff = record["comparison"]
        comparison = {
            "comparison_id": record["comparison_id"],
            "recorded_at": record["created_at"],
            "created_at": record["created_at"],
            "baseline_snapshot_id": record.get("baseline_snapshot_id"),
            "current_snapshot_id": record["current_snapshot_id"],
            "current_snapshot_digest": record.get(
                "current_snapshot_digest"
            ),
            "comparability": diff["comparability"],
            "summary": diff["summary"],
            "diff": diff,
            "lifecycle": record.get("lifecycle"),
            "observed_finding_ids": record.get(
                "observed_finding_ids", []
            ),
            "current_snapshot": self.store.get_snapshot(
                assessment_id, record["current_snapshot_id"]
            ),
        }
        evidence = []
        if occurrence:
            comparison.update(
                {
                    "finding_occurrences": occurrence.get(
                        "lifecycle_findings", []
                    ),
                    "observed_changes": occurrence.get(
                        "observed_changes", []
                    ),
                    "policy_deviations": occurrence.get(
                        "policy_deviations", []
                    ),
                    "security_findings": occurrence.get(
                        "security_findings", []
                    ),
                }
            )
            evidence.extend(occurrence.get("evidence", []))

        live_findings = self.store.list_findings(assessment_id)
        if scope_type == "comparison" and occurrence:
            findings = occurrence.get("lifecycle_findings", [])
        elif scope_type == "assessment_current":
            findings = [
                item
                for item in live_findings
                if item.get("status") in ("open", "acknowledged")
                and item.get("currently_observed") is True
            ]
        else:
            findings = live_findings
        if scope_type == "assessment_history":
            history = selected_occurrences
            for item in selected_occurrences:
                evidence.extend(item.get("evidence", []))
        else:
            history = None
        return (
            scope_type,
            assessment,
            baseline,
            comparison,
            findings,
            evidence,
            history,
        )

    def _validated_report_ai(
        self, ai_analysis: Any, findings: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        if ai_analysis is None:
            return None
        from .ai_analysis import validate_ai_analysis
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
        validated = {
            "analysis_id": ai_analysis.get("analysis_id"),
            "model": ai_analysis.get("model"),
            "language": ai_analysis.get("language"),
        }
        validated.update(selected)
        return validated

    def prepare_report(
        self,
        assessment_id: str,
        scope: Any,
        privacy_profile: Any = "local_full",
        comparison_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        from .reports import build_fact_model, prepare_report_manifest

        (
            scope_type,
            assessment,
            baseline,
            comparison,
            findings,
            evidence,
            history,
        ) = self._report_material(assessment_id, scope, comparison_id)
        settings = load_settings(self.config_dir)
        fact_model = build_fact_model(
            assessment,
            baseline,
            comparison,
            findings,
            scope=scope_type,
            privacy_profile=privacy_profile,
            evidence=evidence,
            history=history,
            share_ssids=settings["share_ssids"],
        )
        manifest = prepare_report_manifest(fact_model)
        return {
            "schema_version": "1.1",
            "scope": {
                "type": scope_type,
                "comparison_id": comparison.get("comparison_id"),
            },
            "privacy_profile": privacy_profile,
            "manifest": manifest,
            "warnings": list(fact_model.get("limitations", [])),
            "scope_digest": manifest["scope_digest"],
        }

    def generate_report(
        self,
        assessment_id: str,
        comparison_id: Optional[str],
        output_format: Any,
        ai_analysis: Any = None,
        scope: Any = None,
        privacy_profile: Any = "local_full",
        scope_digest: Any = None,
    ) -> Dict[str, Any]:
        from .reports import (
            build_fact_model,
            generate_report as build_report,
            prepare_report_manifest,
        )

        legacy_inline = scope is None
        if scope is None:
            # Backward-compatible direct caller shape. The public v0.6.2
            # adapter always supplies an explicit scope.
            scope = {
                "type": "comparison",
                "comparison_id": comparison_id,
            }
        (
            scope_type,
            assessment,
            baseline,
            comparison,
            findings,
            evidence,
            history,
        ) = self._report_material(assessment_id, scope, comparison_id)
        validated_ai = self._validated_report_ai(ai_analysis, findings)
        settings = load_settings(self.config_dir)
        prepared = build_fact_model(
            assessment,
            baseline,
            comparison,
            findings,
            scope=scope_type,
            privacy_profile=privacy_profile,
            evidence=evidence,
            history=history,
            share_ssids=settings["share_ssids"],
        )
        actual_scope_digest = prepare_report_manifest(prepared)[
            "scope_digest"
        ]
        if scope_digest is not None and scope_digest != actual_scope_digest:
            raise BackendError(
                "report_scope_changed",
                "report facts changed after preparation; prepare again",
            )
        report = build_report(
            assessment,
            baseline,
            comparison,
            findings,
            output_format,
            validated_ai,
            scope=scope_type,
            privacy_profile=privacy_profile,
            evidence=evidence,
            history=history,
            share_ssids=settings["share_ssids"],
        )
        export = self.store.write_report_export(
            assessment_id, report["filename"], report["content"]
        )
        if not legacy_inline:
            report.pop("content", None)
        report["export"] = export
        report["scope_digest"] = actual_scope_digest
        return report
