import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "projects" / "PineAI" / "src" / "assets"
sys.path.insert(0, str(ASSETS))

from pineai_backend.advisor import advisor_capabilities  # noqa: E402


class ContractSchemaTests(unittest.TestCase):
    def test_documented_enums_match_runtime_capabilities(self):
        path = (
            ROOT
            / "docs"
            / "schemas"
            / "attack-path-advisor-v1.schema.json"
        )
        schema = json.loads(path.read_text(encoding="utf-8"))
        capabilities = advisor_capabilities()
        documented_objectives = schema["$defs"]["objectiveCode"]["enum"]
        documented_actions = schema["$defs"]["actionId"]["enum"]
        runtime_actions = [item["action_id"] for item in capabilities["actions"]]
        self.assertEqual(documented_objectives, capabilities["objective_codes"])
        self.assertEqual(documented_actions, runtime_actions)
        self.assertEqual(
            schema["$defs"]["adviseRequest"]["properties"]["target_ids"]["maxItems"],
            capabilities["limits"]["targets_per_request"],
        )


if __name__ == "__main__":
    unittest.main()
