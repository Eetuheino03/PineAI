import copy
import json
import sys
import unittest
from pathlib import Path


ASSETS = (
    Path(__file__).resolve().parents[1]
    / "projects"
    / "PineAI"
    / "src"
    / "assets"
)
sys.path.insert(0, str(ASSETS))

from pineai_backend.reports import (  # noqa: E402
    build_fact_model,
    generate_report,
    prepare_report_manifest,
    report_scope_digest,
)
from pineai_backend.errors import BackendError  # noqa: E402


class CustomerReportTests(unittest.TestCase):
    def values(self):
        assessment = {
            "assessment_id": "assessment_example",
            "name": "<script>alert(1)</script> Factory",
            "location": "Helsinki",
            "status": "active",
            "revision": 12,
        }
        baseline_evidence = {
            "evidence_id": "evidence_baseline",
            "snapshot_id": "snapshot_a",
            "evidence_type": "recon_access_point_observation",
            "subject_id": "ap_baseline",
            "observed": {
                "network_id": "network_corp",
                "bssid": "AA:BB:CC:00:00:01",
                "ssid": "Factory-Corp",
                "channel": 1,
            },
        }
        current_evidence = {
            "evidence_id": "evidence_current",
            "snapshot_id": "snapshot_b",
            "evidence_type": "recon_access_point_observation",
            "subject_id": "ap_current",
            "observed": {
                "network_id": "network_corp",
                "bssid": "AA:BB:CC:00:00:02",
                "ssid": "Factory-Corp",
                "channel": 6,
                "vendor": "<script>bad()</script>",
            },
        }
        baseline = {
            "baseline_version_id": "baseline_v0001",
            "version": 1,
            "label": "Initial",
            "created_at": "2026-07-28T10:00:00Z",
            "snapshot": {
                "snapshot_id": "snapshot_a",
                "snapshot_digest": "a" * 64,
                "summary": {"access_point_count": 1},
                "evidence": [baseline_evidence],
            },
        }
        occurrence = {
            "finding_id": "finding_current",
            "rule_id": "known_ssid_new_bssid",
            "title": "Known SSID advertised by a new BSSID",
            "severity": "high",
            "confidence": 0.92,
            "confidence_factors": {
                "base": 0.92,
                "comparability_penalty": 0,
                "evidence_bonus": 0,
            },
            "status": "open",
            "currently_observed": True,
            "summary": "A new BSSID was observed.",
            "evidence_ids": ["evidence_current"],
        }
        comparison = {
            "comparison_id": "comparison_current",
            "recorded_at": "2026-07-28T11:00:00Z",
            "baseline_snapshot_id": "snapshot_a",
            "current_snapshot_id": "snapshot_b",
            "current_snapshot_digest": "b" * 64,
            "comparability": {
                "status": "comparable",
                "reasons": [],
                "quality_factors": {"duration_score": 1.0},
            },
            "summary": {"access_points_added": 1},
            "diff": {
                "access_points": {
                    "added": [
                        {
                            "asset_id": "ap_current",
                            "network_id": "network_corp",
                            "evidence_id": "evidence_current",
                            "bssid": "AA:BB:CC:00:00:02",
                            "ssid": "Factory-Corp",
                        }
                    ]
                }
            },
            "lifecycle": {"opened": ["finding_current"]},
            "finding_occurrences": [occurrence],
            "current_snapshot": {
                "snapshot_id": "snapshot_b",
                "snapshot_digest": "b" * 64,
                "summary": {"access_point_count": 2},
                "evidence": [current_evidence],
            },
        }
        future = {
            "finding_id": "finding_future",
            "rule_id": "wps_enabled",
            "title": "Future finding",
            "severity": "high",
            "confidence": 0.98,
            "status": "open",
            "currently_observed": True,
            "summary": "This belongs to a later comparison.",
            "evidence_ids": ["evidence_future"],
        }
        return assessment, baseline, comparison, [occurrence, future]

    def test_comparison_scope_uses_immutable_occurrences_and_resolves_evidence(self):
        model = build_fact_model(*self.values(), scope="comparison")
        self.assertEqual(
            [item["finding_id"] for item in model["findings"]],
            ["finding_current"],
        )
        self.assertEqual(
            [item["evidence_id"] for item in model["evidence_appendix"]["records"]],
            ["evidence_current"],
        )
        self.assertEqual(
            model["evidence_appendix"]["unresolved_evidence_ids"], []
        )
        self.assertTrue(
            model["scope"]["historical_finding_snapshot_available"]
        )

    def test_assessment_scopes_are_explicit_and_deterministic(self):
        values = self.values()
        current = build_fact_model(*values, scope="assessment_current")
        self.assertEqual(len(current["findings"]), 2)
        self.assertEqual(current["scope"]["mode"], "assessment_current")

        history_value = [
            {
                "comparison_id": "comparison_old",
                "created_at": "2026-07-28T09:00:00Z",
                "comparability_status": "partially_comparable",
                "summary": {"access_points_added": 0},
            }
        ]
        first = build_fact_model(
            *values, scope="assessment_history", history=history_value
        )
        second = build_fact_model(
            *values, scope="assessment_history", history=history_value
        )
        self.assertEqual(first, second)
        self.assertEqual(first["scope"]["mode"], "assessment_history")
        self.assertEqual(first["history"][0]["comparison_id"], "comparison_old")
        self.assertEqual(report_scope_digest(first), first["integrity"]["scope_digest"])
        self.assertEqual(
            prepare_report_manifest(first)["report_sha256"],
            first["integrity"]["report_sha256"],
        )
        for legacy_name in ("current", "history"):
            with self.assertRaises(BackendError) as failure:
                build_fact_model(*values, scope=legacy_name)
            self.assertEqual(
                failure.exception.code, "invalid_report_scope"
            )

    def test_share_safe_redacts_direct_identifiers_and_ssids(self):
        values = list(self.values())
        values[2] = copy.deepcopy(values[2])
        values[2]["policy_deviations"] = [
            {
                "rule_id": "ssid_not_allowed",
                "expected": ["Other", "Factory-Corp"],
                "observed": "Factory-Corp",
                "before_after": {
                    "before": ["Other"],
                    "after": "Factory-Corp",
                },
                "summary": (
                    "Observed AABB.CCDD.EEFF and AABBCCDDEEFF near the target"
                ),
            }
        ]
        result = generate_report(
            *values,
            output_format="json",
            scope="comparison",
            privacy_profile="share_safe",
        )
        content = result["content"]
        self.assertNotIn("AA:BB:CC", content)
        self.assertNotIn("AABB.CCDD.EEFF", content)
        self.assertNotIn("AABBCCDDEEFF", content)
        self.assertIn("[redacted-mac]", content)
        self.assertNotIn("Factory-Corp", content)
        self.assertNotIn("Helsinki", content)
        parsed = json.loads(content)
        self.assertEqual(parsed["privacy"]["profile"], "share_safe")
        self.assertEqual(parsed["assessment"]["name"], "[redacted]")
        self.assertEqual(parsed["baseline"]["label"], "[redacted]")
        self.assertEqual(
            parsed["evidence_appendix"]["records"][0]["observed"]["ssid"],
            "[redacted-ssid]",
        )
        deviation = parsed["policy_deviations"][0]
        self.assertEqual(
            deviation["expected"], ["Other", "[redacted-ssid]"]
        )
        self.assertEqual(deviation["observed"], "[redacted-ssid]")
        self.assertEqual(
            deviation["before_after"]["after"], "[redacted-ssid]"
        )

        html_result = generate_report(
            *values,
            output_format="html",
            scope="comparison",
            privacy_profile="share_safe",
        )
        self.assertNotIn("Factory-Corp", html_result["content"])
        self.assertNotIn("AABB.CCDD.EEFF", html_result["content"])
        self.assertNotIn("AABBCCDDEEFF", html_result["content"])
        self.assertIn("[redacted-ssid]", html_result["content"])

        with_ssids = generate_report(
            *values,
            output_format="json",
            scope="comparison",
            privacy_profile="share_safe",
            share_ssids=True,
        )
        self.assertIn("Factory-Corp", with_ssids["content"])
        self.assertNotIn("AA:BB:CC", with_ssids["content"])

    def test_share_safe_redacts_known_ssids_from_ai_json_and_html_prose(self):
        analysis = {
            "analysis_id": "analysis_privacy",
            "model": "model",
            "language": "en",
            "summary": "Factory-Corp changed during the audit.",
            "finding_explanations": [
                {
                    "finding_id": "finding_current",
                    "explanation": "Validate Factory-Corp with the owner.",
                    "alternative_explanations": ["Factory-Corp may be planned."],
                    "validation_steps": ["Review Factory-Corp configuration."],
                    "evidence_ids": ["evidence_current"],
                }
            ],
            "report_sections": {
                "executive_summary": "Factory-Corp requires review.",
                "technical_summary": "Observed Factory-Corp.",
                "change_summary": "Factory-Corp changed.",
                "limitations": ["Factory-Corp ownership was not checked."],
            },
        }
        for output_format in ("json", "html"):
            with self.assertRaises(BackendError) as raised:
                generate_report(
                    *self.values(),
                    output_format=output_format,
                    scope="comparison",
                    privacy_profile="share_safe",
                    share_ssids=False,
                    ai_analysis=analysis,
                )
            self.assertEqual(raised.exception.code, "privacy_violation")

            local = generate_report(
                *self.values(),
                output_format=output_format,
                scope="comparison",
                privacy_profile="local_full",
                ai_analysis=analysis,
            )
            self.assertIn("Factory-Corp", local["content"])

    def test_short_ssid_redaction_preserves_structural_values(self):
        for ssid in ("a", "1"):
            with self.subTest(ssid=ssid):
                values = copy.deepcopy(self.values())
                values[1]["snapshot"]["evidence"][0]["observed"]["ssid"] = ssid
                values[2]["diff"]["access_points"]["added"][0]["ssid"] = ssid
                values[2]["current_snapshot"]["evidence"][0]["observed"][
                    "ssid"
                ] = ssid
                analysis = {
                    "analysis_id": "analysis_short_ssid",
                    "model": "model",
                    "language": "en",
                    "summary": "SSID={0} changed".format(ssid),
                    "finding_explanations": [],
                    "report_sections": {
                        "executive_summary": "SSID={0} changed".format(ssid),
                        "technical_summary": "",
                        "change_summary": "",
                        "limitations": [],
                    },
                }
                result = generate_report(
                    *values,
                    output_format="json",
                    scope="comparison",
                    privacy_profile="local_full",
                    share_ssids=False,
                    ai_analysis=analysis,
                )
                parsed = json.loads(result["content"])
                self.assertEqual(parsed["schema_version"], "1.1")
                self.assertEqual(
                    parsed["assessment"]["assessment_id"],
                    "assessment_example",
                )
                self.assertEqual(parsed["assessment"]["status"], "active")
                self.assertEqual(
                    parsed["ai_analysis"]["summary"],
                    "SSID={0} changed".format(ssid),
                )
                html_result = generate_report(
                    *values,
                    output_format="html",
                    scope="comparison",
                    privacy_profile="local_full",
                    share_ssids=False,
                    ai_analysis=analysis,
                )
                self.assertIn("assessment_example", html_result["content"])
                self.assertIn("SSID={0} changed".format(ssid), html_result["content"])

    def test_ssid_collision_does_not_redact_customer_status(self):
        values = copy.deepcopy(self.values())
        values[0]["status"] = "active"
        values[1]["snapshot"]["evidence"][0]["observed"]["ssid"] = "active"
        values[2]["current_snapshot"]["evidence"][0]["observed"][
            "ssid"
        ] = "active"
        values[2]["policy_deviations"] = [
            {
                "rule_id": "ssid_not_allowed",
                "protected_ssid": "active",
                "expected": "active",
                "observed": "active",
            }
        ]
        result = generate_report(
            *values,
            output_format="json",
            scope="comparison",
            privacy_profile="share_safe",
            share_ssids=False,
        )
        facts = json.loads(result["content"])
        self.assertEqual(facts["assessment"]["status"], "active")
        self.assertEqual(
            facts["policy_deviations"][0]["expected"],
            "[redacted-ssid]",
        )
        self.assertEqual(
            facts["policy_deviations"][0]["observed"],
            "[redacted-ssid]",
        )

    def test_html_is_script_free_escaped_and_contains_evidence_appendix(self):
        result = generate_report(
            *self.values(),
            output_format="html",
            scope="comparison",
        )
        content = result["content"]
        self.assertNotIn("<script", content.lower())
        self.assertIn("&lt;script&gt;", content)
        self.assertIn("Evidence appendix", content)
        self.assertIn("evidence_current", content)
        self.assertIn("Canonical fact model", content)
        self.assertIn(result["scope_digest"], content)
        self.assertRegex(result["filename"], r"^[A-Za-z0-9._-]+$")

    def test_manifest_changes_when_authoritative_fact_changes(self):
        first = build_fact_model(*self.values(), scope="comparison")
        values = list(self.values())
        values[2] = dict(values[2])
        values[2]["summary"] = {"access_points_added": 2}
        second = build_fact_model(*values, scope="comparison")
        self.assertNotEqual(
            first["integrity"]["report_sha256"],
            second["integrity"]["report_sha256"],
        )


if __name__ == "__main__":
    unittest.main()
