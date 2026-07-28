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

from pineai_backend.reports import generate_report  # noqa: E402


class ReportTests(unittest.TestCase):
    def inputs(self):
        assessment = {
            "assessment_id": "assessment_test",
            "name": "<script>alert(1)</script> Office",
            "location": "Helsinki & Espoo",
            "status": "active",
            "revision": 4,
        }
        baseline = {
            "baseline_version_id": "baseline_test",
            "version": 1,
            "label": "Initial",
            "snapshot": {
                "snapshot_id": "snapshot_a",
                "summary": {"access_point_count": 2},
            },
        }
        comparison = {
            "comparison_id": "comparison_test",
            "recorded_at": "2026-07-27T12:00:00Z",
            "baseline_snapshot_id": "snapshot_a",
            "current_snapshot_id": "snapshot_b",
            "comparability": {"status": "comparable", "reasons": []},
            "summary": {"access_points_added": 1},
            "diff": {"access_points": {"added": []}},
        }
        findings = [
            {
                "finding_id": "finding_test",
                "rule_id": "new_access_point",
                "title": "New <b>AP</b>",
                "severity": "medium",
                "confidence": 0.95,
                "status": "open",
                "currently_observed": True,
                "summary": "<img src=x onerror=alert(1)>",
                "evidence_ids": ["evidence_test"],
            }
        ]
        return assessment, baseline, comparison, findings

    def test_json_and_html_are_deterministic(self):
        values = self.inputs()
        first = generate_report(*values, output_format="json")
        second = generate_report(*values, output_format="json")
        self.assertEqual(first, second)
        parsed = json.loads(first["content"])
        self.assertTrue(parsed["authority"]["deterministic"])
        self.assertFalse(parsed["authority"]["ai_authoritative"])
        self.assertEqual(parsed["baseline"]["baseline_id"], "baseline_test")
        self.assertEqual(parsed["baseline"]["baseline_version"], 1)

        html_result = generate_report(*values, output_format="html")
        self.assertEqual(html_result["mime_type"], "text/html")
        self.assertNotIn("<script>", html_result["content"])
        self.assertNotIn("<img src=x", html_result["content"])
        self.assertIn("&lt;script&gt;", html_result["content"])
        self.assertNotIn("<script", html_result["content"].lower())

    def test_ai_text_is_clearly_non_authoritative_and_escaped(self):
        values = self.inputs()
        analysis = {
            "analysis_id": "analysis_test",
            "model": "model",
            "language": "en",
            "summary": "Summary",
            "finding_explanations": [
                {
                    "finding_id": "finding_test",
                    "explanation": "<script>bad()</script>",
                    "alternative_explanations": [],
                    "validation_steps": [],
                    "evidence_ids": ["evidence_test"],
                }
            ],
            "report_sections": {
                "executive_summary": "Executive",
                "technical_summary": "Technical",
                "change_summary": "Change",
                "limitations": [],
            },
        }
        result = generate_report(
            *values, output_format="html", ai_analysis=analysis
        )
        self.assertIn("Not authoritative", result["content"])
        self.assertNotIn("<script>bad", result["content"])
        self.assertIn("&lt;script&gt;bad", result["content"])


if __name__ == "__main__":
    unittest.main()
