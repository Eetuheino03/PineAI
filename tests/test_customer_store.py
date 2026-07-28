import base64
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "projects" / "PineAI" / "src" / "assets"
sys.path.insert(0, str(ASSETS))

from pineai_backend.config import (  # noqa: E402
    IdentityKeyError,
    ensure_pseudonymization_key,
    identity_fingerprint,
    public_identity_status,
)
from pineai_backend.customer_store import CustomerAuditStore  # noqa: E402
from pineai_backend.errors import BackendError  # noqa: E402
from pineai_backend.storage_transaction import (  # noqa: E402
    PrivateTransaction,
    recover_private_transactions,
)


def measurement_profile():
    return {
        "name": "North wall audit",
        "description": "Repeatable saved Recon acquisition",
        "location_id": "factory-a",
        "measurement_point_id": "north-wall",
        "scan_profile_id": "saved-recon-300",
        "radio_profile_id": "mk7-wlan1",
        "interface": "wlan1mon",
        "declared_bands": ["2.4"],
        "declared_channels": [1, 6, 11],
        "scan_time": 300,
        "is_default": True,
        "five_ghz_operator_confirmed": False,
    }


class IdentityAndCustomerStoreTests(unittest.TestCase):
    def test_missing_identity_is_not_recreated_when_assessments_exist(self):
        with tempfile.TemporaryDirectory() as directory:
            assessment = Path(directory) / "assessments" / "assessment_fixture"
            assessment.mkdir(parents=True)
            (assessment / "assessment.json").write_text(
                "{}", encoding="utf-8"
            )
            with self.assertRaises(IdentityKeyError) as raised:
                ensure_pseudonymization_key(directory)
            self.assertEqual(raised.exception.code, "identity_key_missing")
            self.assertFalse(
                (Path(directory) / "pseudonymization.key").exists()
            )
            self.assertEqual(
                public_identity_status(directory)["status"], "blocked"
            )

    def test_invalid_identity_is_blocked_and_fingerprint_is_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pseudonymization.key"
            path.write_text("not-base64\n", encoding="utf-8")
            with self.assertRaises(IdentityKeyError) as raised:
                ensure_pseudonymization_key(directory)
            self.assertEqual(raised.exception.code, "identity_key_invalid")
            secret = bytes(range(32))
            path.write_bytes(base64.b64encode(secret) + b"\n")
            status = public_identity_status(directory)
            self.assertEqual(status["status"], "ready")
            self.assertEqual(status["fingerprint"], identity_fingerprint(secret))
            self.assertNotIn(base64.b64encode(secret).decode(), repr(status))

    def test_transaction_recovery_rolls_forward_staged_documents(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls = []

            def fail_after_prepare(stage, index):
                calls.append((stage, index))
                if stage == "prepared":
                    raise RuntimeError("simulated power loss")

            transaction = PrivateTransaction(root, fail_after_prepare)
            transaction.add_json("state/one.json", {"value": 1})
            transaction.add_json("state/two.json", {"value": 2})
            with self.assertRaises(RuntimeError):
                transaction.commit()
            self.assertFalse((root / "state" / "one.json").exists())
            recovered = recover_private_transactions(root)
            self.assertEqual(len(recovered), 1)
            self.assertEqual(
                json.loads((root / "state" / "one.json").read_text()),
                {"value": 1},
            )
            self.assertEqual(
                json.loads((root / "state" / "two.json").read_text()),
                {"value": 2},
            )

    def test_measurement_profiles_are_versioned_and_private(self):
        with tempfile.TemporaryDirectory() as directory:
            store = CustomerAuditStore(directory)
            created = store.create_measurement_profile(measurement_profile())
            # Measurement profiles are not HMAC-bound assessment data and may
            # be configured before the first assessment initializes identity.
            self.assertEqual(len(ensure_pseudonymization_key(directory)), 32)
            self.assertEqual(created["revision"], 1)
            self.assertEqual(
                created["active_version"]["version_id"], "mprofile_r0001"
            )
            updated = store.update_measurement_profile(
                created["measurement_profile_id"],
                1,
                {"scan_time": 600, "description": "Long repeatable sweep"},
            )
            self.assertEqual(updated["revision"], 2)
            self.assertEqual(
                updated["active_version"]["version_id"], "mprofile_r0002"
            )
            self.assertEqual(
                len(store.list_measurement_profiles()), 1
            )
            base = (
                Path(directory)
                / "measurement_profiles"
                / created["measurement_profile_id"]
            )
            if os.name != "nt":
                self.assertEqual(
                    stat.S_IMODE(base.stat().st_mode), 0o700
                )
                self.assertEqual(
                    stat.S_IMODE((base / "profile.json").stat().st_mode),
                    0o600,
                )
            archived = store.archive_measurement_profile(
                created["measurement_profile_id"], 2
            )
            self.assertEqual(archived["status"], "archived")
            self.assertEqual(store.list_measurement_profiles(), [])
            self.assertEqual(
                len(store.list_measurement_profiles(include_archived=True)), 1
            )

    def test_five_ghz_profile_requires_explicit_confirmation(self):
        with tempfile.TemporaryDirectory() as directory:
            value = measurement_profile()
            value["declared_bands"] = ["2.4", "5"]
            value["five_ghz_operator_confirmed"] = False
            with self.assertRaises(BackendError) as raised:
                CustomerAuditStore(directory).create_measurement_profile(value)
            self.assertEqual(
                raised.exception.code, "five_ghz_confirmation_required"
            )

    def test_legacy_findings_are_labelled_and_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            store = CustomerAuditStore(directory)
            assessment = store.create(
                {"name": "Legacy", "location": "", "notes": ""}
            )
            finding = {
                "finding_id": "finding_dddddddddddd",
                "rule_id": "channel_changed",
                "title": "Legacy channel finding",
                "severity": "low",
                "confidence": 0.95,
                "subject_id": "ap_aaaaaaaaaaaa",
                "summary": "Historical v0.6.1 finding.",
                "evidence_ids": ["evidence_cccccccccccc"],
                "details": {"asset_id": "ap_aaaaaaaaaaaa"},
                "confidence_factors": {
                    "base": 0.95,
                    "comparability_penalty": 0.0,
                    "evidence_bonus": 0.0,
                },
                "status": "open",
                "currently_observed": True,
                "first_seen_at": "2026-07-27T12:00:00Z",
                "last_seen_at": "2026-07-27T12:00:00Z",
                "last_seen_comparison_id": "comparison_aaaaaaaaaaaaaaaa",
                "occurrence_count": 1,
                "status_updated_at": "2026-07-27T12:00:00Z",
            }
            path = (
                Path(directory)
                / "assessments"
                / assessment["assessment_id"]
                / "findings.json"
            )
            path.write_text(
                json.dumps(
                    {
                        "schema_version": "1.1",
                        "updated_at": "2026-07-27T12:00:00Z",
                        "findings": [finding],
                    }
                ),
                encoding="utf-8",
            )
            listed = store.list_findings(assessment["assessment_id"])
            self.assertTrue(listed[0]["legacy_read_only"])
            with self.assertRaises(BackendError) as raised:
                store.update_finding(
                    assessment["assessment_id"],
                    assessment["revision"],
                    finding["finding_id"],
                    "acknowledged",
                )
            self.assertEqual(
                raised.exception.code, "legacy_finding_read_only"
            )


if __name__ == "__main__":
    unittest.main()
