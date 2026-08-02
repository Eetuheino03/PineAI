import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "projects" / "PineAI" / "src" / "assets"
sys.path.insert(0, str(ASSETS))

from pineai_backend.audit_run_report import AuditRunReportService  # noqa: E402
from pineai_backend.errors import BackendError  # noqa: E402


def canonical_digest(value):
    payload = (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class FakeStore:
    def __init__(self):
        self.write_count = 0
        self.snapshot_reads = 0
        self.comparison_reads = 0
        self.occurrence_reads = 0
        self.snapshot = {
            "snapshot_id": "snapshot_1111111111111111",
            "snapshot_digest": "a" * 64,
            "scan_metadata": {
                "scan_id": "hak5-local-scan-SECRET-777",
                "label": "Sweep for Customer <Office> at customer HQ",
                "measurement_context": {
                    "location_id": "building-private",
                    "interface": "wlan1mon",
                    "scan_profile_id": "customer-profile",
                    "radio_profile_id": "customer-radio",
                    "declared_bands": ["2.4"],
                    "declared_channels": [1, 6, 11],
                },
            },
            "access_points": [
                {
                    "ssid": "Customer <Office>",
                    "bssid": "AA:BB:CC:DD:EE:FF",
                }
            ],
        }
        self.comparison = {
            "comparison_id": "comparison_2222222222222222",
            "comparison_digest": "b" * 64,
            "comparability_status": "comparable",
        }
        self.occurrence = {
            "occurrence_set_id": "occurrence_3333333333333333",
            "occurrence_digest": "c" * 64,
            "policy_deviations": [
                {
                    "severity": "medium",
                    "protected_ssid": "Customer <Office>",
                    "allowed_ssids": ["Customer <Office>"],
                    "summary": "Customer <Office> changed",
                }
            ],
            "security_findings": [{"severity": "high"}],
        }
        self.detail = {
            "audit_run": {
                "audit_run_id": "ar_0000000000000001",
                "name": "Customer Helsinki Site",
                "status": "completed",
                "completed_at": "2026-07-31T12:00:00Z",
                "operator_instructions": "Do not export",
            },
            "measurements": [
                {
                    "measurement_id": "arm_0000000000000001",
                    "measurement_point_id": "mp_0000000000000001",
                    "status": "completed",
                    "snapshot_id": self.snapshot["snapshot_id"],
                    "snapshot_digest": self.snapshot["snapshot_digest"],
                    "comparison_id": self.comparison["comparison_id"],
                    "comparison_digest": self.comparison["comparison_digest"],
                    "occurrence_digest": self.occurrence["occurrence_digest"],
                    "source_recon_id": "hak5-local-scan-SECRET-777",
                }
            ],
            "workflow": {"next_action": "none"},
            "assessment_capacity": {"audit_runs": {"used": 1, "limit": 32}},
        }

    def get_audit_run(self, _assessment_id, _audit_run_id):
        return copy.deepcopy(self.detail)

    def get_snapshot(self, _assessment_id, _snapshot_id):
        self.snapshot_reads += 1
        return copy.deepcopy(self.snapshot)

    def get_comparison(self, _assessment_id, _comparison_id):
        self.comparison_reads += 1
        return copy.deepcopy(self.comparison)

    def get_occurrence_set(self, _assessment_id, _comparison_id):
        self.occurrence_reads += 1
        return copy.deepcopy(self.occurrence)

    def get(self, _assessment_id, after_sequence=0, limit=100):
        events = [
            {
                "sequence": 1,
                "event_id": "evt_00000000-0000-4000-8000-000000000001",
                "event_type": "audit_measurement_retried",
                "recorded_at": "2026-07-31T11:59:00Z",
                "revision": 2,
                "data": {
                    "measurement_id": "arm_0000000000000001",
                    "retry_target": "resolved",
                },
            }
        ]
        selected = [item for item in events if item["sequence"] > after_sequence]
        return {
            "events": selected[:limit],
            "events_has_more": len(selected) > limit,
        }


class AuditRunReportTests(unittest.TestCase):
    def test_json_and_html_are_deterministic_and_read_only(self):
        store = FakeStore()
        service = AuditRunReportService(store)
        first = service.generate(
            "assessment_0000000000000001",
            "ar_0000000000000001",
            "json",
            "local_full",
        )
        second = service.generate(
            "assessment_0000000000000001",
            "ar_0000000000000001",
            "json",
            "local_full",
        )
        self.assertEqual(first, second)
        self.assertEqual(store.write_count, 0)
        self.assertEqual(
            hashlib.sha256(first["content"].encode("utf-8")).hexdigest(),
            first["content_sha256"],
        )

        html_report = service.generate(
            "assessment_0000000000000001",
            "ar_0000000000000001",
            "html",
            "local_full",
        )
        self.assertEqual(first["fact_digest"], html_report["fact_digest"])
        self.assertNotEqual(first["content_sha256"], html_report["content_sha256"])
        self.assertNotIn("<script", html_report["content"].lower())
        self.assertIn("Customer &lt;Office&gt;", html_report["content"])
        self.assertIn("audit_measurement_retried", first["content"])

    def test_share_safe_removes_local_identifiers(self):
        store = FakeStore()
        deviation = store.occurrence["policy_deviations"][0]
        deviation.update(
            {
                "expected": ["Other", "Customer <Office>"],
                "observed": "Customer <Office>",
                "before_after": {
                    "before": ["Other"],
                    "after": "Customer <Office>",
                },
                "summary": (
                    "Observed AA-BB-CC-DD-EE-FF, AABB.CCDD.EEFF, and "
                    "AABBCCDDEEFF "
                    "near the target"
                ),
            }
        )
        service = AuditRunReportService(store)
        for report_format in ("json", "html"):
            result = service.generate(
                "assessment_0000000000000001",
                "ar_0000000000000001",
                report_format,
                "share_safe",
            )
            self.assertNotIn("AA:BB:CC:DD:EE:FF", result["content"])
            self.assertNotIn("AA-BB-CC-DD-EE-FF", result["content"])
            self.assertNotIn("AABB.CCDD.EEFF", result["content"])
            self.assertNotIn("AABBCCDDEEFF", result["content"])
            self.assertIn("[redacted-mac]", result["content"])
            self.assertNotIn("Do not export", result["content"])
            self.assertNotIn("Customer Helsinki Site", result["content"])
            self.assertNotIn("hak5-local-scan-SECRET-777", result["content"])
            self.assertNotIn("building-private", result["content"])
            self.assertNotIn("wlan1mon", result["content"])
            self.assertNotIn("customer-profile", result["content"])
            self.assertNotIn("customer-radio", result["content"])
            self.assertNotIn("at customer HQ", result["content"])
            self.assertNotIn("Customer <Office>", result["content"])
            self.assertNotIn("Customer &lt;Office&gt;", result["content"])
            self.assertIn("[redacted-ssid]", result["content"])

        safe_json = service.generate(
            "assessment_0000000000000001",
            "ar_0000000000000001",
            "json",
            "share_safe",
        )
        policy = json.loads(safe_json["content"])["measurements"][0][
            "occurrence"
        ]["policy_deviations"][0]
        self.assertEqual(
            json.loads(safe_json["content"])["measurements"][0]["snapshot"]
            ["scan_metadata"]["measurement_context"]["declared_bands"],
            ["2.4"],
        )
        self.assertEqual(
            policy["expected"], ["Other", "[redacted-ssid]"]
        )
        self.assertEqual(policy["observed"], "[redacted-ssid]")
        self.assertEqual(
            policy["before_after"]["after"], "[redacted-ssid]"
        )

        local = service.generate(
            "assessment_0000000000000001",
            "ar_0000000000000001",
            "json",
            "local_full",
        )
        self.assertIn("Customer <Office>", local["content"])
        self.assertIn("Customer Helsinki Site", local["content"])

    def test_report_discloses_operator_declared_profile_limitation(self):
        service = AuditRunReportService(FakeStore())
        json_result = service.generate(
            "assessment_0000000000000001",
            "ar_0000000000000001",
            "json",
            "local_full",
        )
        facts = json.loads(json_result["content"])
        self.assertTrue(
            any(
                "MeasurementProfile settings are operator-declared" in item
                for item in facts["limitations"]
            )
        )
        html_result = service.generate(
            "assessment_0000000000000001",
            "ar_0000000000000001",
            "html",
            "local_full",
        )
        self.assertIn(
            "MeasurementProfile settings are operator-declared",
            html_result["content"],
        )

    def test_short_ssid_redaction_preserves_audit_structure(self):
        for ssid in ("a", "1"):
            with self.subTest(ssid=ssid):
                store = FakeStore()
                store.snapshot["access_points"][0]["ssid"] = ssid
                deviation = store.occurrence["policy_deviations"][0]
                deviation["protected_ssid"] = ssid
                deviation["allowed_ssids"] = [ssid]
                deviation["summary"] = "SSID={0} changed".format(ssid)
                deviation["expected"] = ["Other", ssid]
                deviation["observed"] = ssid
                deviation["before_after"] = {
                    "before": ["Other"],
                    "after": ssid,
                }
                service = AuditRunReportService(store)
                result = service.generate(
                    "assessment_0000000000000001",
                    "ar_0000000000000001",
                    "json",
                    "share_safe",
                )
                parsed = json.loads(result["content"])
                self.assertEqual(parsed["schema_version"], "1.0")
                self.assertEqual(
                    parsed["audit_run"]["audit_run_id"],
                    "ar_0000000000000001",
                )
                self.assertEqual(parsed["audit_run"]["status"], "completed")
                policy = parsed["measurements"][0]["occurrence"][
                    "policy_deviations"
                ][0]
                self.assertEqual(policy["protected_ssid"], "[redacted-ssid]")
                self.assertEqual(policy["allowed_ssids"], ["[redacted-ssid]"])
                self.assertEqual(
                    policy["summary"], "SSID=[redacted-ssid] changed"
                )
                self.assertEqual(
                    policy["expected"], ["Other", "[redacted-ssid]"]
                )
                self.assertEqual(policy["observed"], "[redacted-ssid]")
                self.assertEqual(
                    policy["before_after"]["after"], "[redacted-ssid]"
                )
                html_result = service.generate(
                    "assessment_0000000000000001",
                    "ar_0000000000000001",
                    "html",
                    "share_safe",
                )
                self.assertIn("ar_0000000000000001", html_result["content"])
                self.assertIn("[redacted-ssid]", html_result["content"])

    def test_non_terminal_run_is_rejected(self):
        store = FakeStore()
        store.detail["audit_run"]["status"] = "in_progress"
        with self.assertRaises(BackendError) as raised:
            AuditRunReportService(store).generate(
                "assessment_0000000000000001",
                "ar_0000000000000001",
                "json",
                "local_full",
            )
        self.assertEqual(raised.exception.code, "audit_run_not_terminal")

    def test_digest_mismatch_is_rejected(self):
        store = FakeStore()
        store.detail["measurements"][0]["snapshot_digest"] = "f" * 64
        with self.assertRaises(BackendError) as raised:
            AuditRunReportService(store).generate(
                "assessment_0000000000000001",
                "ar_0000000000000001",
                "json",
                "local_full",
            )
        self.assertEqual(raised.exception.code, "digest_mismatch")

    def test_aggregate_budget_rejects_before_remaining_artifacts_are_loaded(self):
        store = FakeStore()
        template = store.detail["measurements"][0]
        store.detail["measurements"] = []
        for index in range(4):
            measurement = copy.deepcopy(template)
            measurement["measurement_id"] = "arm_{0:016d}".format(index + 1)
            measurement["measurement_point_id"] = "mp_{0:016d}".format(
                index + 1
            )
            store.detail["measurements"].append(measurement)
        # One storage artifact is individually below the 4 MiB production
        # document limit, but two copies exceed the bounded report fact budget.
        store.snapshot["bounded_test_payload"] = "x" * (300 * 1024)

        with self.assertRaises(BackendError) as raised:
            AuditRunReportService(store).generate(
                "assessment_0000000000000001",
                "ar_0000000000000001",
                "json",
                "local_full",
            )
        self.assertEqual(raised.exception.code, "audit_report_too_large")
        self.assertEqual(store.snapshot_reads, 2)
        self.assertEqual(store.comparison_reads, 1)
        self.assertEqual(store.occurrence_reads, 1)


if __name__ == "__main__":
    unittest.main()
