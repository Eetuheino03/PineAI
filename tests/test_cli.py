import io
import datetime
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ASSETS = (
    Path(__file__).resolve().parents[1]
    / "projects"
    / "PineAI"
    / "src"
    / "assets"
)
import sys

sys.path.insert(0, str(ASSETS))

import pineai_cli  # noqa: E402
from pineai_backend.advisor_service import AttackPathAdvisorService  # noqa: E402
from pineai_backend.engagement_store import EngagementStore  # noqa: E402
from test_adaptive_recon import device_context  # noqa: E402
from test_advisor import profile_result  # noqa: E402
from test_engagement_store import TARGET_ID, engagement_value  # noqa: E402


FIXTURE = Path(__file__).resolve().parent / "fixtures" / "recon_basic.json"


class CliTests(unittest.TestCase):
    def test_configure_and_status_never_print_key(self):
        with tempfile.TemporaryDirectory() as directory:
            output = io.StringIO()
            with mock.patch("pineai_cli.getpass.getpass", return_value="sk-secret"):
                exit_code = pineai_cli.main(
                    ["--config-dir", directory, "configure"],
                    stdout=output,
                )
            self.assertEqual(exit_code, 0)
            self.assertNotIn("sk-secret", output.getvalue())
            self.assertTrue(json.loads(output.getvalue())["configured"])

    def test_prepare_prints_exact_private_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            output = io.StringIO()
            exit_code = pineai_cli.main(
                [
                    "--config-dir",
                    directory,
                    "prepare",
                    "--input",
                    str(FIXTURE),
                ],
                stdout=output,
            )
            self.assertEqual(exit_code, 0)
            payload = json.loads(output.getvalue())
            self.assertNotIn("Example-Corp", json.dumps(payload))
            self.assertNotIn("AA:BB:CC", json.dumps(payload))

    def test_profile_offline_is_successful_partial_result(self):
        with tempfile.TemporaryDirectory() as directory:
            output = io.StringIO()
            exit_code = pineai_cli.main(
                [
                    "--config-dir",
                    directory,
                    "profile",
                    "--input",
                    str(FIXTURE),
                ],
                stdout=output,
            )
            self.assertEqual(exit_code, 0)
            self.assertEqual(
                json.loads(output.getvalue())["ai_status"]["code"], "not_configured"
            )

    def test_invalid_input_exit_code(self):
        with tempfile.TemporaryDirectory() as directory:
            invalid = Path(directory) / "bad.json"
            invalid.write_text("not json", encoding="utf-8")
            errors = io.StringIO()
            exit_code = pineai_cli.main(
                [
                    "--config-dir",
                    directory,
                    "prepare",
                    "--input",
                    str(invalid),
                ],
                stderr=errors,
            )
            self.assertEqual(exit_code, 2)
            self.assertEqual(
                json.loads(errors.getvalue())["error"]["code"], "invalid_input"
            )

    def test_engagement_and_offline_advisor_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            engagement_input = Path(directory) / "engagement.json"
            engagement_input.write_text(
                json.dumps(engagement_value()), encoding="utf-8"
            )
            created_output = io.StringIO()
            self.assertEqual(
                pineai_cli.main(
                    [
                        "--config-dir",
                        directory,
                        "engagement",
                        "create",
                        "--input",
                        str(engagement_input),
                    ],
                    stdout=created_output,
                ),
                0,
            )
            created = json.loads(created_output.getvalue())
            profile_path = Path(directory) / "profile.json"
            profile_path.write_text(json.dumps(profile_result()), encoding="utf-8")
            advice_output = io.StringIO()
            self.assertEqual(
                pineai_cli.main(
                    [
                        "--config-dir",
                        directory,
                        "advise",
                        "--engagement-id",
                        created["engagement_id"],
                        "--input",
                        str(profile_path),
                        "--target-id",
                        TARGET_ID,
                        "--no-ai",
                    ],
                    stdout=advice_output,
                ),
                0,
            )
            advice = json.loads(advice_output.getvalue())
            self.assertEqual(advice["advisor_status"]["code"], "ai_disabled")
            self.assertEqual(len(advice["target_results"][0]["paths"]), 3)

    def test_adaptive_recon_cli_lifecycle_and_exit_codes(self):
        with tempfile.TemporaryDirectory() as directory:
            engagement = EngagementStore(directory).create(engagement_value())
            advisor = AttackPathAdvisorService(directory).advise(
                engagement["engagement_id"],
                profile_result(),
                [TARGET_ID],
                {"ai_enabled": False},
            )
            path_id = next(
                path["path_id"]
                for path in advisor["target_results"][0]["paths"]
                if any(
                    step["action_id"] == "collect_additional_recon"
                    for step in path["steps"]
                )
            )
            observed_at = datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat().replace("+00:00", "Z")
            context = device_context()
            context["observed_at"] = observed_at
            request_value = {
                "engagement_id": engagement["engagement_id"],
                "expected_revision": 1,
                "profile_result": profile_result(),
                "advisor_result": advisor,
                "selected_path_ids": [path_id],
                "history": [],
                "device_context": context,
            }
            input_path = Path(directory) / "adaptive.json"
            input_path.write_text(json.dumps(request_value), encoding="utf-8")

            prepared_output = io.StringIO()
            self.assertEqual(
                pineai_cli.main(
                    [
                        "--config-dir",
                        directory,
                        "prepare-recon-plan",
                        "--input",
                        str(input_path),
                    ],
                    stdout=prepared_output,
                ),
                0,
            )
            self.assertNotIn("documented-device-value", prepared_output.getvalue())

            recommended_output = io.StringIO()
            self.assertEqual(
                pineai_cli.main(
                    [
                        "--config-dir",
                        directory,
                        "recommend-recon-plan",
                        "--input",
                        str(input_path),
                        "--no-ai",
                    ],
                    stdout=recommended_output,
                ),
                0,
            )
            plan = json.loads(recommended_output.getvalue())
            self.assertEqual(plan["engagement_revision"], 2)

            device_path = Path(directory) / "device.json"
            context["observed_at"] = datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat().replace("+00:00", "Z")
            device_path.write_text(json.dumps(context), encoding="utf-8")
            approved_output = io.StringIO()
            self.assertEqual(
                pineai_cli.main(
                    [
                        "--config-dir",
                        directory,
                        "recon-plan",
                        "approve",
                        "--engagement-id",
                        engagement["engagement_id"],
                        "--revision",
                        "2",
                        "--plan-id",
                        plan["plan_id"],
                        "--candidate-id",
                        plan["candidates"][0]["candidate_id"],
                        "--device-context",
                        str(device_path),
                    ],
                    stdout=approved_output,
                ),
                0,
            )
            self.assertEqual(
                json.loads(approved_output.getvalue())["rest_request"]["path"],
                "/api/recon/start",
            )

            errors = io.StringIO()
            self.assertEqual(
                pineai_cli.main(
                    [
                        "--config-dir",
                        directory,
                        "recon-plan",
                        "approve",
                        "--engagement-id",
                        engagement["engagement_id"],
                        "--revision",
                        "2",
                        "--plan-id",
                        plan["plan_id"],
                        "--candidate-id",
                        "reconcandidate_ffffffffffff",
                        "--device-context",
                        str(device_path),
                    ],
                    stderr=errors,
                ),
                2,
            )
            self.assertIn(
                json.loads(errors.getvalue())["error"]["code"],
                ("revision_conflict", "unknown_recon_candidate"),
            )


if __name__ == "__main__":
    unittest.main()
