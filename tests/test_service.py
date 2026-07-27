import json
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
import sys

sys.path.insert(0, str(ASSETS))

from pineai_backend.config import save_api_key  # noqa: E402
from pineai_backend.openai_client import OpenAIClientError  # noqa: E402
from pineai_backend.service import BackendError, TargetProfilerService  # noqa: E402


FIXTURE = Path(__file__).resolve().parent / "fixtures" / "recon_basic.json"


def load_fixture():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


class SuccessfulClient:
    def __init__(self, **_kwargs):
        pass

    def profile(self, payload, language, safety_identifier):
        profiles = []
        for target in payload["targets"]:
            profiles.append(
                {
                    "target_id": target["target_id"],
                    "role": "unknown",
                    "interest": "medium",
                    "confidence": 0.75,
                    "summary": "Evidence-backed profile",
                    "observations": ["Observed target"],
                    "missing_evidence": ["Longer observation"],
                    "related_target_ids": [],
                    "evidence_ids": target["evidence_ids"],
                }
            )
        return (
            {"overall_summary": "Authorized scan profiled.", "targets": profiles},
            {"input_tokens": 20, "output_tokens": 10, "total_tokens": 30},
        )


class FailingClient:
    def __init__(self, **_kwargs):
        pass

    def profile(self, *_args):
        raise OpenAIClientError("network_error", "OpenAI could not be reached")


class UnknownEvidenceClient(SuccessfulClient):
    def profile(self, payload, language, safety_identifier):
        output, usage = super().profile(payload, language, safety_identifier)
        output["targets"][0]["evidence_ids"] = ["evidence_not_real"]
        return output, usage


class ServiceTests(unittest.TestCase):
    def test_missing_key_returns_deterministic_partial_result(self):
        with tempfile.TemporaryDirectory() as directory:
            service = TargetProfilerService(directory)
            result = service.profile_recon(load_fixture())
            repeated = service.profile_recon(load_fixture())
            self.assertEqual(result["ai_status"]["code"], "not_configured")
            self.assertEqual(len(result["targets"]), 2)
            self.assertTrue(all(target["ai_profile"] is None for target in result["targets"]))
            self.assertEqual(result["scan_summary"], repeated["scan_summary"])
            self.assertEqual(result["targets"], repeated["targets"])

    def test_ai_disabled_does_not_require_key(self):
        with tempfile.TemporaryDirectory() as directory:
            result = TargetProfilerService(directory).profile_recon(
                load_fixture(), options={"ai_enabled": False}
            )
            self.assertEqual(result["ai_status"]["state"], "disabled")

    def test_successful_ai_profiles_are_merged(self):
        with tempfile.TemporaryDirectory() as directory:
            save_api_key("secret", directory)
            result = TargetProfilerService(
                directory, client_factory=SuccessfulClient
            ).profile_recon(load_fixture())
            self.assertEqual(result["ai_status"]["code"], "ok")
            self.assertEqual(result["token_usage"]["total_tokens"], 30)
            self.assertTrue(all(target["ai_profile"] for target in result["targets"]))

    def test_network_failure_preserves_partial_result(self):
        with tempfile.TemporaryDirectory() as directory:
            save_api_key("secret", directory)
            result = TargetProfilerService(
                directory, client_factory=FailingClient
            ).profile_recon(load_fixture())
            self.assertEqual(result["ai_status"]["code"], "network_error")
            self.assertEqual(len(result["targets"]), 2)

    def test_unknown_evidence_is_rejected_locally(self):
        with tempfile.TemporaryDirectory() as directory:
            save_api_key("secret", directory)
            result = TargetProfilerService(
                directory, client_factory=UnknownEvidenceClient
            ).profile_recon(load_fixture())
            self.assertEqual(result["ai_status"]["code"], "invalid_ai_output")
            self.assertTrue(all(target["ai_profile"] is None for target in result["targets"]))

    def test_invalid_recon_fails_before_ai_call(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(BackendError) as raised:
                TargetProfilerService(directory).profile_recon({"bad": []})
            self.assertEqual(raised.exception.code, "invalid_recon")


if __name__ == "__main__":
    unittest.main()
