import json
import sys
import tempfile
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

from pineai_backend.ai_analysis import (  # noqa: E402
    AssuranceAIService,
    validate_ai_analysis,
)
from pineai_backend.config import save_api_key  # noqa: E402
from pineai_backend.errors import BackendError  # noqa: E402


FINDING = {
    "finding_id": "finding_aaaaaaaaaaaa",
    "rule_id": "new_access_point",
    "severity": "medium",
    "confidence": 0.95,
    "status": "open",
    "currently_observed": True,
    "summary": "A new AP was observed.",
    "evidence_ids": ["evidence_aaaaaaaaaaaa"],
    "details": {
        "asset_id": "ap_aaaaaaaaaaaa",
        "network_id": "network_aaaaaaaaaaaa",
        "bssid": "AA:BB:CC:00:00:01",
        "ssid": "Office",
    },
}
ASSESSMENT = {
    "assessment_id": "assessment_00000000-0000-4000-8000-000000000000",
    "name": "Assessment",
    "location": "Helsinki",
    "notes": "private note",
}
COMPARISON = {
    "comparison_id": "comparison_aaaaaaaaaaaaaaaa",
    "comparability": {"status": "comparable", "reasons": []},
    "summary": {"access_points_added": 1},
}


def provider_output():
    return {
        "summary": "One deterministic finding.",
        "finding_explanations": [
            {
                "finding_id": FINDING["finding_id"],
                "explanation": "The BSSID was not in the baseline.",
                "alternative_explanations": ["A planned access point was added."],
                "validation_steps": ["Confirm the device in the controller inventory."],
                "evidence_ids": FINDING["evidence_ids"],
            }
        ],
        "report_sections": {
            "executive_summary": "A change needs validation.",
            "technical_summary": "The baseline comparison found one new AP.",
            "change_summary": "One AP was added.",
            "limitations": ["Only one observation was supplied."],
        },
    }


class FakeClient:
    def __init__(self, *_args, **_kwargs):
        pass

    def analyze_assurance(self, payload, language, safety_identifier):
        self.payload = payload
        return provider_output(), {"total_tokens": 12}


class AssuranceAIServiceTests(unittest.TestCase):
    def test_prepare_is_exact_private_payload_and_ssid_is_opt_in(self):
        with tempfile.TemporaryDirectory() as directory:
            service = AssuranceAIService(config_dir=directory)
            hidden = service.prepare(
                ASSESSMENT, COMPARISON, [FINDING], {"share_ssids": False}
            )
            serialized = json.dumps(hidden["cloud_payload"])
            self.assertNotIn("AA:BB:CC", serialized)
            self.assertNotIn("Office", serialized)
            self.assertNotIn("private note", serialized)

            shared = service.prepare(
                dict(ASSESSMENT, name="Assessment", location=""),
                COMPARISON,
                [FINDING],
                {"share_ssids": True},
            )
            self.assertIn("Office", json.dumps(shared["cloud_payload"]))

    def test_missing_key_returns_offline_partial_result(self):
        with tempfile.TemporaryDirectory() as directory:
            result = AssuranceAIService(config_dir=directory).generate(
                ASSESSMENT, COMPARISON, [FINDING]
            )
        self.assertIsNone(result["analysis"])
        self.assertEqual(result["ai_status"]["code"], "api_key_missing")

    def test_success_is_semantically_validated(self):
        with tempfile.TemporaryDirectory() as directory:
            save_api_key("test-key", directory)
            result = AssuranceAIService(
                config_dir=directory, client_factory=FakeClient
            ).generate(ASSESSMENT, COMPARISON, [FINDING])
        self.assertEqual(result["ai_status"]["state"], "complete")
        self.assertEqual(
            result["analysis"]["finding_explanations"][0]["finding_id"],
            FINDING["finding_id"],
        )
        self.assertEqual(result["token_usage"]["total_tokens"], 12)

    def test_unknown_references_and_unsafe_steps_are_rejected(self):
        unknown = provider_output()
        unknown["finding_explanations"][0]["finding_id"] = "finding_bbbbbbbbbbbb"
        with self.assertRaises(BackendError) as raised:
            validate_ai_analysis(unknown, [FINDING])
        self.assertEqual(raised.exception.code, "invalid_ai_reference")

        unsafe = provider_output()
        unsafe["finding_explanations"][0]["validation_steps"] = [
            "Run a deauth attack."
        ]
        with self.assertRaises(BackendError) as raised:
            validate_ai_analysis(unsafe, [FINDING])
        self.assertEqual(raised.exception.code, "unsafe_ai_output")


if __name__ == "__main__":
    unittest.main()
