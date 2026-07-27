import copy
import datetime
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

from pineai_backend.advisor import (  # noqa: E402
    build_advisor_cloud_payload,
    build_candidate_paths,
    deterministic_results,
    serialized_contains_mac,
    validate_profile_result,
)
from pineai_backend.errors import BackendError  # noqa: E402
from test_engagement_store import TARGET_ID, engagement_value, event_value  # noqa: E402


EVIDENCE_ID = "evidence_bbbbbbbbbbbb"


def profile_result():
    return {
        "schema_version": "1.0",
        "backend_version": "0.3.0",
        "targets": [
            {
                "target_id": TARGET_ID,
                "ssid": "Example-Guest",
                "hidden": False,
                "bssids": ["AA:BB:CC:00:00:01"],
                "vendors": [{"value": "Vendor AA:BB:CC:00:00:02", "count": 1}],
                "channels": [6],
                "encryption_codes": [5],
                "metrics": {
                    "ap_count": 1,
                    "client_count": 3,
                    "wps_enabled_count": 0,
                    "hidden_ap_count": 0,
                    "data_total": 100,
                    "probes_total": 10,
                    "signal_min": -50,
                    "signal_max": -50,
                    "signal_average": -50,
                },
                "flags": ["active_clients"],
                "evidence": [{"evidence_id": EVIDENCE_ID, "bssid": "AA:BB:CC:00:00:01"}],
                "ai_selected": True,
                "ai_profile": {
                    "role": "guest",
                    "interest": "high",
                    "confidence": 0.9,
                    "summary": "Guest network",
                    "observations": [],
                    "missing_evidence": ["Portal behavior"],
                    "related_target_ids": [],
                    "evidence_ids": [EVIDENCE_ID],
                },
            }
        ],
    }


def engagement(disruption=True):
    value = engagement_value(disruption)
    return dict(
        {
            "engagement_id": "eng_11111111-1111-4111-8111-111111111111",
            "status": "active",
            "revision": 1,
        },
        **value
    )


class AdvisorPolicyTests(unittest.TestCase):
    def setUp(self):
        self.secret = b"a" * 32
        self.targets = validate_profile_result(profile_result())
        self.now = datetime.datetime(2026, 7, 27, tzinfo=datetime.timezone.utc)

    def candidates(self, engagement_value=None, events=None):
        return build_candidate_paths(
            engagement_value or engagement(),
            events or [],
            self.targets,
            [TARGET_ID],
            self.secret,
            now=self.now,
        )

    def test_deterministic_top_three_and_stable_path_ids(self):
        first = self.candidates()
        second = self.candidates()
        self.assertEqual(first, second)
        results = deterministic_results(first)
        self.assertEqual(len(results[0]["paths"]), 3)
        self.assertTrue(all(1 <= len(path["steps"]) <= 3 for path in results[0]["paths"]))

    def test_disruption_gate_removes_deauth_and_evil_twin(self):
        candidates = self.candidates(engagement(False))[TARGET_ID]
        action_ids = {
            step["action_id"] for path in candidates for step in path["steps"]
        }
        self.assertNotIn("authorized_deauthentication", action_ids)
        self.assertNotIn("evil_twin_simulation", action_ids)

    def test_credential_advice_requires_explicit_objective(self):
        engagement_value = engagement(True)
        engagement_value["objectives"] = ["rogue_ap_resilience"]
        paths = self.candidates(engagement_value)[TARGET_ID]
        evil_twin = next(
            path for path in paths if path["template_id"] == "evil_twin_campaign"
        )
        self.assertFalse(evil_twin["credential_collection_advisory_permitted"])

        engagement_value["objectives"].append("credential_capture_assessment")
        paths = self.candidates(engagement_value)[TARGET_ID]
        evil_twin = next(
            path for path in paths if path["template_id"] == "evil_twin_campaign"
        )
        self.assertTrue(evil_twin["credential_collection_advisory_permitted"])

    def test_completed_and_started_actions_are_removed(self):
        completed = event_value("action_completed", "collect_additional_recon")
        completed["sequence"] = 1
        candidates = self.candidates(events=[completed])[TARGET_ID]
        self.assertTrue(
            all(
                "collect_additional_recon"
                not in [step["action_id"] for step in path["steps"]]
                for path in candidates
            )
        )
        started = event_value("action_started", "authorized_deauthentication")
        started["sequence"] = 2
        candidates = self.candidates(events=[started])[TARGET_ID]
        self.assertTrue(
            all(
                "authorized_deauthentication"
                not in [step["action_id"] for step in path["steps"]]
                for path in candidates
            )
        )

    def test_failed_action_penalty(self):
        normal = {
            path["template_id"]: path["score"] for path in self.candidates()[TARGET_ID]
        }
        for event_type in ("action_failed", "action_aborted"):
            event = event_value(event_type, "authorized_deauthentication")
            penalized = {
                path["template_id"]: path["score"]
                for path in self.candidates(events=[event])[TARGET_ID]
            }
            self.assertEqual(
                penalized["deauthentication_resilience"],
                normal["deauthentication_resilience"] - 15,
            )

    def test_adaptive_recon_lifecycle_blocks_and_releases_recon_path(self):
        active = {
            "event_type": "adaptive_recon_recommended",
            "data": {
                "plan": {
                    "plan_id": "reconplan_aaaaaaaaaaaa",
                    "target_ids": [TARGET_ID],
                    "recommendation_expires_at": "2026-07-27T12:05:00Z",
                }
            },
        }
        candidates = self.candidates(events=[active])[TARGET_ID]
        self.assertTrue(
            all(
                "collect_additional_recon"
                not in [step["action_id"] for step in path["steps"]]
                for path in candidates
            )
        )

        completed = {
            "event_type": "adaptive_recon_finished",
            "data": {
                "plan_id": "reconplan_aaaaaaaaaaaa",
                "outcome": "completed",
            },
        }
        candidates = self.candidates(events=[active, completed])[TARGET_ID]
        self.assertTrue(
            any(
                "collect_additional_recon"
                in [step["action_id"] for step in path["steps"]]
                for path in candidates
            )
        )

        failed = copy.deepcopy(completed)
        failed["data"]["outcome"] = "failed"
        normal = {
            path["template_id"]: path["score"] for path in self.candidates()[TARGET_ID]
        }
        penalized = {
            path["template_id"]: path["score"]
            for path in self.candidates(events=[active, failed])[TARGET_ID]
        }
        self.assertEqual(
            penalized["recon_depth"],
            normal["recon_depth"] - 15,
        )

        older_failed = copy.deepcopy(completed)
        older_failed["data"]["outcome"] = "failed"
        newer_recommended = copy.deepcopy(active)
        newer_recommended["data"]["plan"]["plan_id"] = (
            "reconplan_bbbbbbbbbbbb"
        )
        newer_completed = copy.deepcopy(completed)
        newer_completed["data"]["plan_id"] = "reconplan_bbbbbbbbbbbb"
        recovered = {
            path["template_id"]: path["score"]
            for path in self.candidates(
                events=[
                    active,
                    older_failed,
                    newer_recommended,
                    newer_completed,
                ]
            )[TARGET_ID]
        }
        self.assertEqual(
            recovered["recon_depth"],
            normal["recon_depth"],
        )

    def test_expired_and_out_of_scope_are_rejected(self):
        expired = engagement()
        expired["valid_until"] = "2021-01-01T00:00:00Z"
        with self.assertRaises(BackendError) as raised:
            self.candidates(expired)
        self.assertEqual(raised.exception.code, "engagement_expired")
        outside = engagement()
        outside["authorized_target_ids"] = ["target_cccccccccccc"]
        with self.assertRaises(BackendError) as raised:
            self.candidates(outside)
        self.assertEqual(raised.exception.code, "target_out_of_scope")

    def test_cloud_payload_removes_local_and_mac_data(self):
        candidates = self.candidates()
        payload = build_advisor_cloud_payload(
            engagement(),
            self.targets,
            candidates,
            [TARGET_ID],
            self.secret,
            False,
            "en",
        )
        serialized = json.dumps(payload)
        self.assertNotIn("Example-Guest", serialized)
        self.assertNotIn("ROE-2026-001", serialized)
        self.assertNotIn("Local notes", serialized)
        self.assertFalse(serialized_contains_mac(payload))

    def test_more_than_ten_targets_is_rejected(self):
        from pineai_backend.advisor import validate_advisor_target_ids

        with self.assertRaises(BackendError):
            validate_advisor_target_ids(
                ["target_{0:012x}".format(index) for index in range(11)]
            )

    def test_ten_targets_return_at_most_thirty_paths(self):
        target_ids = ["target_{0:012x}".format(index) for index in range(10)]
        targets = {}
        for target_id in target_ids:
            target = copy.deepcopy(self.targets[TARGET_ID])
            target["target_id"] = target_id
            targets[target_id] = target
        engagement_value = engagement()
        engagement_value["authorized_target_ids"] = target_ids
        candidates = build_candidate_paths(
            engagement_value,
            [],
            targets,
            target_ids,
            self.secret,
            now=self.now,
        )
        results = deterministic_results(candidates)
        self.assertEqual(len(results), 10)
        self.assertLessEqual(
            sum(len(result["paths"]) for result in results),
            30,
        )
        self.assertTrue(all(len(result["paths"]) <= 3 for result in results))


if __name__ == "__main__":
    unittest.main()
