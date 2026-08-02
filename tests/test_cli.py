import io
import json
import os
import stat
import sys
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

sys.path.insert(0, str(ASSETS))

import pineai_cli  # noqa: E402


FIXTURE = Path(__file__).resolve().parent / "fixtures" / "recon_basic.json"


def write_json(directory, name, value):
    path = Path(directory) / name
    path.write_text(json.dumps(value), encoding="utf-8")
    return str(path)


class CliTests(unittest.TestCase):
    def _report_command(self, directory, output):
        result = {
            "content": '{"privacy_profile":"local_full"}\n',
            "mime_type": "application/json",
        }
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(
            pineai_cli.AssuranceService,
            "generate_report",
            return_value=result,
        ):
            exit_code = pineai_cli.main(
                [
                    "--config-dir",
                    directory,
                    "report",
                    "assessment_00000000-0000-4000-8000-000000000001",
                    "comparison_0000000000000001",
                    "--format",
                    "json",
                    "--output",
                    str(output),
                ],
                stdout=stdout,
                stderr=stderr,
            )
        return exit_code, stdout, stderr

    def test_report_output_is_exclusive_and_private(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            exit_code, stdout, _stderr = self._report_command(
                directory, output
            )
            self.assertEqual(exit_code, 0)
            self.assertEqual(
                output.read_text(encoding="utf-8"),
                '{"privacy_profile":"local_full"}\n',
            )
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(json.loads(stdout.getvalue())["output"], str(output))

            original = output.read_bytes()
            exit_code, _stdout, stderr = self._report_command(directory, output)
            self.assertEqual(exit_code, 2)
            self.assertEqual(
                json.loads(stderr.getvalue())["error"]["code"],
                "output_exists",
            )
            self.assertEqual(output.read_bytes(), original)

    @unittest.skipIf(os.name == "nt", "symlink creation is not portable on Windows")
    def test_report_output_does_not_follow_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.json"
            target.write_text("keep", encoding="utf-8")
            output = Path(directory) / "report.json"
            output.symlink_to(target)
            exit_code, _stdout, stderr = self._report_command(directory, output)
            self.assertEqual(exit_code, 2)
            self.assertEqual(
                json.loads(stderr.getvalue())["error"]["code"],
                "output_exists",
            )
            self.assertEqual(target.read_text(encoding="utf-8"), "keep")

    def test_json_input_is_bounded_before_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            oversized = Path(directory) / "oversized.json"
            with oversized.open("wb") as handle:
                handle.truncate(pineai_cli.MAX_CLI_JSON_INPUT_BYTES + 1)
            stderr = io.StringIO()
            exit_code = pineai_cli.main(
                [
                    "--config-dir",
                    directory,
                    "resolve",
                    "--input",
                    str(oversized),
                ],
                stderr=stderr,
            )
            self.assertEqual(exit_code, 2)
            self.assertEqual(
                json.loads(stderr.getvalue())["error"]["code"],
                "invalid_input",
            )

    def test_configure_and_status_never_print_key(self):
        with tempfile.TemporaryDirectory() as directory:
            output = io.StringIO()
            with mock.patch(
                "pineai_cli.getpass.getpass", return_value="sk-secret"
            ):
                exit_code = pineai_cli.main(
                    [
                        "--config-dir",
                        directory,
                        "configure",
                        "--language",
                        "fi",
                        "--set-openai-key",
                    ],
                    stdout=output,
                )
            self.assertEqual(exit_code, 0)
            self.assertNotIn("sk-secret", output.getvalue())
            configured = json.loads(output.getvalue())
            self.assertTrue(configured["configured"])
            self.assertEqual(configured["language"], "fi")

    def test_resolve_and_invalid_input_exit_codes(self):
        with tempfile.TemporaryDirectory() as directory:
            metadata = write_json(
                directory,
                "metadata.json",
                {"scan_time": 180, "coverage": ["2.4"]},
            )
            output = io.StringIO()
            self.assertEqual(
                pineai_cli.main(
                    [
                        "--config-dir",
                        directory,
                        "resolve",
                        "--input",
                        str(FIXTURE),
                        "--metadata",
                        metadata,
                    ],
                    stdout=output,
                ),
                0,
            )
            self.assertEqual(
                json.loads(output.getvalue())["snapshot"]["summary"][
                    "access_point_count"
                ],
                3,
            )
            invalid = Path(directory) / "invalid.json"
            invalid.write_text("not json", encoding="utf-8")
            errors = io.StringIO()
            self.assertEqual(
                pineai_cli.main(
                    [
                        "--config-dir",
                        directory,
                        "resolve",
                        "--input",
                        str(invalid),
                    ],
                    stderr=errors,
                ),
                2,
            )
            self.assertEqual(
                json.loads(errors.getvalue())["error"]["code"], "invalid_input"
            )

    def test_assessment_baseline_analyze_findings_and_report_workflow(self):
        with tempfile.TemporaryDirectory() as directory:
            assessment_input = write_json(
                directory,
                "assessment.json",
                {"name": "Office", "location": "Helsinki", "notes": ""},
            )
            metadata = write_json(
                directory,
                "metadata.json",
                {
                    "scan_id": "baseline",
                    "scan_time": 180,
                    "coverage": ["2.4"],
                },
            )
            created_output = io.StringIO()
            self.assertEqual(
                pineai_cli.main(
                    [
                        "--config-dir",
                        directory,
                        "assessment",
                        "create",
                        "--input",
                        assessment_input,
                    ],
                    stdout=created_output,
                ),
                0,
            )
            assessment = json.loads(created_output.getvalue())

            baseline_output = io.StringIO()
            self.assertEqual(
                pineai_cli.main(
                    [
                        "--config-dir",
                        directory,
                        "baseline",
                        "create",
                        assessment["assessment_id"],
                        "--expected-revision",
                        str(assessment["revision"]),
                        "--input",
                        str(FIXTURE),
                        "--metadata",
                        metadata,
                    ],
                    stdout=baseline_output,
                ),
                0,
            )
            baseline = json.loads(baseline_output.getvalue())

            activated_output = io.StringIO()
            self.assertEqual(
                pineai_cli.main(
                    [
                        "--config-dir",
                        directory,
                        "baseline",
                        "activate",
                        assessment["assessment_id"],
                        "--expected-revision",
                        str(baseline["assessment"]["revision"]),
                        baseline["baseline"]["baseline_version_id"],
                    ],
                    stdout=activated_output,
                ),
                0,
            )
            activated = json.loads(activated_output.getvalue())

            changed = json.loads(FIXTURE.read_text(encoding="utf-8"))
            changed["APResults"].append(
                {
                    "ssid": "Example-Corp",
                    "bssid": "AA:BB:CC:00:00:03",
                    "encryption": 5,
                    "channel": 11,
                }
            )
            changed_path = write_json(directory, "changed.json", changed)
            analyzed_output = io.StringIO()
            self.assertEqual(
                pineai_cli.main(
                    [
                        "--config-dir",
                        directory,
                        "analyze",
                        assessment["assessment_id"],
                        "--expected-revision",
                        str(activated["assessment"]["revision"]),
                        "--input",
                        changed_path,
                        "--metadata",
                        metadata,
                    ],
                    stdout=analyzed_output,
                ),
                0,
            )
            analyzed = json.loads(analyzed_output.getvalue())
            # Baseline-only drift is an observed change, not a security
            # finding. Findings require an active assurance policy.
            self.assertEqual(len(analyzed["observed_changes"]), 1)
            self.assertEqual(analyzed["policy_deviations"], [])
            self.assertEqual(analyzed["security_findings"], [])
            self.assertEqual(analyzed["findings"], [])
            self.assertEqual(
                analyzed["policy_evaluation_status"], "not_configured"
            )

            report_output = io.StringIO()
            self.assertEqual(
                pineai_cli.main(
                    [
                        "--config-dir",
                        directory,
                        "report",
                        assessment["assessment_id"],
                        analyzed["comparison"]["comparison_id"],
                        "--format",
                        "json",
                    ],
                    stdout=report_output,
                ),
                0,
            )
            report = json.loads(report_output.getvalue())
            self.assertEqual(report["mime_type"], "application/json")
            self.assertIn("known_ssid_new_bssid", report["content"])


if __name__ == "__main__":
    unittest.main()
