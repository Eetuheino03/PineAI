"""Retirement checks for the unreleased flat AuditRun public contract.

The authoritative v0.7 split/frozen-assignment behavior is covered by
``test_repeatable_audit_store_v070.py``.  This file intentionally keeps only a
small guard against accidentally re-exposing the PR #47 draft write API.  Flat
documents remain read-compatible and their first mutation is covered by the
migration regression in the authoritative suite.
"""

import inspect
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "projects" / "PineAI" / "src" / "assets"
sys.path.insert(0, str(ASSETS))

from pineai_backend.repeatable_audit_store import (  # noqa: E402
    RepeatableAuditStore,
)


class RetiredFlatAuditRunContractTests(unittest.TestCase):
    def test_create_requires_one_versioned_audit_run_document(self):
        signature = inspect.signature(RepeatableAuditStore.create_audit_run)
        self.assertEqual(
            list(signature.parameters),
            [
                "self",
                "assessment_id",
                "expected_assessment_revision",
                "audit_run",
            ],
        )
        self.assertTrue(
            all(
                parameter.kind
                not in {
                    inspect.Parameter.VAR_POSITIONAL,
                    inspect.Parameter.VAR_KEYWORD,
                }
                for parameter in signature.parameters.values()
            )
        )


if __name__ == "__main__":
    unittest.main()
