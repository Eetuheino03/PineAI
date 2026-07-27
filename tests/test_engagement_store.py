import os
import stat
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

from pineai_backend.engagement_store import EngagementStore  # noqa: E402
from pineai_backend.errors import BackendError  # noqa: E402


TARGET_ID = "target_aaaaaaaaaaaa"


def engagement_value(disruption=True):
    return {
        "name": "Authorized assessment",
        "objectives": [
            "wireless_mapping",
            "guest_network_security",
            "rogue_ap_resilience",
        ],
        "objective_notes": "Local notes",
        "authorized_target_ids": [TARGET_ID],
        "allowed_actions": [
            "collect_additional_recon",
            "test_device_association",
            "captive_portal_inspection",
            "authorized_deauthentication",
            "evil_twin_simulation",
        ],
        "disruption_allowed": disruption,
        "authorization_reference": "ROE-2026-001",
        "valid_from": "2020-01-01T00:00:00Z",
        "valid_until": "2099-01-01T00:00:00Z",
    }


def event_value(event_type="action_completed", action_id="collect_additional_recon"):
    return {
        "event_type": event_type,
        "summary": "Operator result",
        "target_id": TARGET_ID,
        "action_id": action_id,
        "evidence_ids": ["evidence_bbbbbbbbbbbb"],
    }


class EngagementStoreTests(unittest.TestCase):
    def test_create_get_list_update_event_and_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            store = EngagementStore(directory)
            created = store.create(engagement_value())
            self.assertEqual(created["revision"], 1)
            self.assertEqual(created["events"][0]["event_type"], "engagement_created")
            engagement_id = created["engagement_id"]
            self.assertEqual(store.get(engagement_id)["name"], "Authorized assessment")
            self.assertEqual(len(store.list()), 1)

            updated = store.update(
                engagement_id, 1, {"name": "Updated authorized assessment"}
            )
            self.assertEqual(updated["revision"], 2)
            self.assertEqual(updated["events"][0]["event_type"], "engagement_updated")
            appended = store.append_event(
                engagement_id, 2, event_value()
            )
            self.assertEqual(appended["revision"], 3)
            archived = store.archive(engagement_id, 3)
            self.assertEqual(archived["status"], "archived")
            self.assertEqual(store.list(), [])
            self.assertEqual(len(store.list(include_archived=True)), 1)

    def test_revision_conflict_and_archived_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            store = EngagementStore(directory)
            created = store.create(engagement_value())
            with self.assertRaises(BackendError) as raised:
                store.update(created["engagement_id"], 99, {"name": "No"})
            self.assertEqual(raised.exception.code, "revision_conflict")
            archived = store.archive(created["engagement_id"], 1)
            with self.assertRaises(BackendError) as raised:
                store.append_event(
                    created["engagement_id"], archived["revision"], event_value()
                )
            self.assertEqual(raised.exception.code, "engagement_archived")

    def test_scope_and_event_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            store = EngagementStore(directory)
            created = store.create(engagement_value())
            value = event_value()
            value["target_id"] = "target_cccccccccccc"
            with self.assertRaises(BackendError) as raised:
                store.append_event(created["engagement_id"], 1, value)
            self.assertEqual(raised.exception.code, "target_out_of_scope")

    def test_system_event_is_revisioned_and_not_user_appendable(self):
        with tempfile.TemporaryDirectory() as directory:
            store = EngagementStore(directory)
            created = store.create(engagement_value())
            result = store.append_system_event(
                created["engagement_id"],
                1,
                "adaptive_recon_recommended",
                {"plan_id": "reconplan_aaaaaaaaaaaa"},
            )
            self.assertEqual(result["engagement"]["revision"], 2)
            self.assertEqual(result["event"]["revision"], 2)
            self.assertEqual(
                result["event"]["event_type"], "adaptive_recon_recommended"
            )
            with self.assertRaises(BackendError) as raised:
                store.append_system_event(
                    created["engagement_id"],
                    2,
                    "action_completed",
                    {},
                )
            self.assertEqual(raised.exception.code, "invalid_event")

    @unittest.skipIf(os.name == "nt", "POSIX permissions are verified on Linux")
    def test_engagement_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            store = EngagementStore(directory)
            created = store.create(engagement_value())
            engagement_directory = Path(directory) / "engagements"
            self.assertEqual(stat.S_IMODE(engagement_directory.stat().st_mode), 0o700)
            for path in engagement_directory.glob("*"):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertTrue(created["engagement_id"].startswith("eng_"))


if __name__ == "__main__":
    unittest.main()
