import io
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


if __name__ == "__main__":
    unittest.main()
