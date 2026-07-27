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


if __name__ == "__main__":
    unittest.main()
