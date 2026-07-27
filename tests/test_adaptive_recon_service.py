import copy
import datetime
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

from pineai_backend.adaptive_recon_service import AdaptiveReconService
from pineai_backend.advisor_service import AttackPathAdvisorService
from pineai_backend.config import save_api_key
from pineai_backend.engagement_store import EngagementStore
from pineai_backend.errors import BackendError
from pineai_backend.openai_client import OpenAIClientError
from test_adaptive_recon import NOW, device_context, history_item
from test_advisor import EVIDENCE_ID, profile_result
from test_engagement_store import TARGET_ID, engagement_value


class MutableClock:
    def __init__(self):
        self.value = NOW

    def __call__(self):
        return self.value


class SuccessfulAdaptiveClient:
    def __init__(self, **_kwargs):
        pass

    def plan_adaptive_recon(self, payload, _language, _safety_identifier):
        candidate = payload["candidate_plans"][-1]
        return (
            {
                "candidate_id": candidate["candidate_id"],
                "target_ids": [target["target_id"] for target in payload["targets"]],
                "confidence": 0.82,
                "rationale": "Selected from bounded candidates.",
                "expected_information": ["Channel stability"],
                "evidence_ids": payload["targets"][0]["evidence_ids"],
                "missing_evidence": ["Longer observation"],
            },
            {"input_tokens": 30, "output_tokens": 10, "total_tokens": 40},
        )


class UnknownCandidateClient(SuccessfulAdaptiveClient):
    def plan_adaptive_recon(self, payload, language, safety_identifier):
        result, usage = super().plan_adaptive_recon(
            payload, language, safety_identifier
        )
        result["candidate_id"] = "reconcandidate_ffffffffffff"
        return result, usage


class UnknownTargetClient(SuccessfulAdaptiveClient):
    def plan_adaptive_recon(self, payload, language, safety_identifier):
        result, usage = super().plan_adaptive_recon(
            payload, language, safety_identifier
        )
        result["target_ids"] = ["target_ffffffffffff"]
        return result, usage


class UnknownEvidenceClient(SuccessfulAdaptiveClient):
    def plan_adaptive_recon(self, payload, language, safety_identifier):
        result, usage = super().plan_adaptive_recon(
            payload, language, safety_identifier
        )
        result["evidence_ids"] = ["evidence_ffffffffffff"]
        return result, usage


class FailingAdaptiveClient:
    def __init__(self, **_kwargs):
        pass

    def plan_adaptive_recon(self, *_args):
        raise OpenAIClientError("rate_limited", "OpenAI rate limit reached")


class AdaptiveReconServiceTests(unittest.TestCase):
    def setUp(self):
        self.clock = MutableClock()

    def setup_request(self, directory):
        engagement = EngagementStore(directory).create(engagement_value())
        advisor = AttackPathAdvisorService(directory).advise(
            engagement["engagement_id"],
            profile_result(),
            [TARGET_ID],
            {"ai_enabled": False},
        )
        selected = next(
            path["path_id"]
            for path in advisor["target_results"][0]["paths"]
            if any(
                step["action_id"] == "collect_additional_recon"
                for step in path["steps"]
            )
        )
        return engagement, advisor, selected

    def recommend(self, directory, service=None, options=None):
        engagement, advisor, selected = self.setup_request(directory)
        service = service or AdaptiveReconService(directory, clock=self.clock)
        result = service.recommend(
            engagement["engagement_id"],
            engagement["revision"],
            profile_result(),
            advisor,
            [selected],
            [],
            device_context(),
            options or {"ai_enabled": False},
        )
        return engagement, advisor, selected, result

    def test_prepare_is_exact_private_cloud_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            engagement, advisor, selected = self.setup_request(directory)
            payload = AdaptiveReconService(directory, clock=self.clock).prepare(
                engagement["engagement_id"],
                engagement["revision"],
                profile_result(),
                advisor,
                [selected],
                [],
                device_context(value="PRIVATE-BAND-VALUE"),
                {"share_ssids": False},
            )
            serialized = json.dumps(payload)
            for forbidden in (
                "Example-Guest",
                "AA:BB:CC",
                "PRIVATE-BAND-VALUE",
                "ROE-2026-001",
                "Local notes",
                '"scan_id"',
            ):
                self.assertNotIn(forbidden, serialized)

    def test_offline_lifecycle_and_exact_rest_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            engagement, _advisor, _selected, plan = self.recommend(directory)
            self.assertEqual(plan["adaptive_status"]["code"], "ai_disabled")
            self.assertEqual(plan["status"], "recommended")
            self.assertEqual(plan["engagement_revision"], 2)

            service = AdaptiveReconService(directory, clock=self.clock)
            candidate = plan["candidates"][-1]
            approved = service.approve(
                engagement["engagement_id"],
                2,
                plan["plan_id"],
                candidate["candidate_id"],
                device_context(),
            )
            self.assertEqual(
                approved["rest_request"],
                {
                    "method": "POST",
                    "path": "/api/recon/start",
                    "body": candidate["request"],
                },
            )
            self.assertEqual(approved["engagement_revision"], 3)
            started = service.record_started(
                engagement["engagement_id"],
                3,
                plan["plan_id"],
                {"scanRunning": True, "scanID": 91},
            )
            self.assertEqual(started["status"], "started")
            self.assertEqual(started["engagement_revision"], 4)

            completed_profile = copy.deepcopy(profile_result())
            completed_profile["targets"][0]["metrics"]["ap_count"] += 2
            completed_profile["targets"][0]["channels"].append(11)
            finished = service.record_finished(
                engagement["engagement_id"],
                4,
                plan["plan_id"],
                "completed",
                91,
                completed_profile,
            )
            self.assertEqual(finished["status"], "completed")
            self.assertEqual(finished["engagement_revision"], 5)
            delta = finished["result"]["result_delta"]["targets"][0]
            self.assertEqual(delta["ap_delta"], 2)
            self.assertEqual(delta["channels_added"], [11])
            self.assertEqual(
                service.get_plan(engagement["engagement_id"], plan["plan_id"]),
                finished,
            )
            self.assertEqual(len(service.list_plans(engagement["engagement_id"])), 1)

            audit = EngagementStore(directory).all_events(
                engagement["engagement_id"]
            )
            serialized = json.dumps(audit)
            self.assertNotIn("AA:BB:CC", serialized)
            self.assertNotIn("Example-Guest", serialized)
            self.assertNotIn('"targets": [{"target_id"', serialized)

    def test_expiration_revision_busy_scope_and_candidate_gates(self):
        with tempfile.TemporaryDirectory() as directory:
            engagement, _advisor, _selected, plan = self.recommend(directory)
            service = AdaptiveReconService(directory, clock=self.clock)
            self.clock.value += datetime.timedelta(seconds=301)
            stale_context = device_context()
            stale_context["observed_at"] = self.clock.value.isoformat().replace(
                "+00:00", "Z"
            )
            with self.assertRaises(BackendError) as raised:
                service.approve(
                    engagement["engagement_id"],
                    2,
                    plan["plan_id"],
                    plan["candidates"][0]["candidate_id"],
                    stale_context,
                )
            self.assertEqual(raised.exception.code, "recon_plan_expired")

        with tempfile.TemporaryDirectory() as directory:
            self.clock.value = NOW
            engagement, advisor, selected = self.setup_request(directory)
            service = AdaptiveReconService(directory, clock=self.clock)
            with self.assertRaises(BackendError) as raised:
                service.recommend(
                    engagement["engagement_id"],
                    99,
                    profile_result(),
                    advisor,
                    [selected],
                    [],
                    device_context(),
                )
            self.assertEqual(raised.exception.code, "stale_advisor_result")

            busy = device_context()
            busy["recon_status"]["scanRunning"] = True
            with self.assertRaises(BackendError) as raised:
                service.recommend(
                    engagement["engagement_id"],
                    1,
                    profile_result(),
                    advisor,
                    [selected],
                    [],
                    busy,
                )
            self.assertEqual(raised.exception.code, "recon_busy")

            plan = service.recommend(
                engagement["engagement_id"],
                1,
                profile_result(),
                advisor,
                [selected],
                [],
                device_context(),
                {"ai_enabled": False},
            )
            with self.assertRaises(BackendError) as raised:
                service.approve(
                    engagement["engagement_id"],
                    2,
                    plan["plan_id"],
                    "reconcandidate_ffffffffffff",
                    device_context(),
                )
            self.assertEqual(raised.exception.code, "unknown_recon_candidate")

            with self.assertRaises(BackendError) as raised:
                service.prepare(
                    engagement["engagement_id"],
                    2,
                    profile_result(),
                    dict(advisor, engagement_revision=2),
                    [selected],
                    [],
                    device_context(),
                )
            self.assertEqual(raised.exception.code, "recon_plan_in_progress")

    def test_ai_success_invalid_references_and_provider_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            engagement, advisor, selected = self.setup_request(directory)
            save_api_key("secret", directory)
            result = AdaptiveReconService(
                directory,
                client_factory=SuccessfulAdaptiveClient,
                clock=self.clock,
            ).recommend(
                engagement["engagement_id"],
                1,
                profile_result(),
                advisor,
                [selected],
                [],
                device_context(),
            )
            self.assertEqual(result["adaptive_status"]["code"], "ok")
            self.assertEqual(result["source"], "ai")
            self.assertEqual(result["token_usage"]["total_tokens"], 40)

        for client in (
            UnknownCandidateClient,
            UnknownTargetClient,
            UnknownEvidenceClient,
            FailingAdaptiveClient,
        ):
            with tempfile.TemporaryDirectory() as directory:
                engagement, advisor, selected = self.setup_request(directory)
                save_api_key("secret", directory)
                result = AdaptiveReconService(
                    directory, client_factory=client, clock=self.clock
                ).recommend(
                    engagement["engagement_id"],
                    1,
                    profile_result(),
                    advisor,
                    [selected],
                    [],
                    device_context(),
                )
                expected = (
                    "rate_limited"
                    if client is FailingAdaptiveClient
                    else "invalid_ai_output"
                )
                self.assertEqual(result["adaptive_status"]["code"], expected)
                self.assertEqual(result["source"], "deterministic")

    def test_failed_and_aborted_finish_without_profile(self):
        for outcome in ("failed", "aborted"):
            with tempfile.TemporaryDirectory() as directory:
                self.clock.value = NOW
                engagement, _advisor, _selected, plan = self.recommend(directory)
                service = AdaptiveReconService(directory, clock=self.clock)
                candidate = plan["candidates"][0]
                service.approve(
                    engagement["engagement_id"],
                    2,
                    plan["plan_id"],
                    candidate["candidate_id"],
                    device_context(),
                )
                service.record_started(
                    engagement["engagement_id"],
                    3,
                    plan["plan_id"],
                    {"scanRunning": True, "scanID": 92},
                )
                finished = service.record_finished(
                    engagement["engagement_id"],
                    4,
                    plan["plan_id"],
                    outcome,
                    92,
                    error_code="operator_abort" if outcome == "aborted" else "radio_error",
                )
                self.assertEqual(finished["status"], outcome)


if __name__ == "__main__":
    unittest.main()
