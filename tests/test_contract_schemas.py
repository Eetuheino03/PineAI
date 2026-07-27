import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "projects" / "PineAI" / "src" / "assets"
sys.path.insert(0, str(ASSETS))

from pineai_backend.advisor import advisor_capabilities  # noqa: E402
from pineai_backend.adaptive_recon import adaptive_recon_capabilities  # noqa: E402
from pineai_backend.config import MAX_SUPPORTED_BANDS  # noqa: E402


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

    def test_adaptive_recon_schema_matches_runtime_capabilities(self):
        path = ROOT / "docs" / "schemas" / "adaptive-recon-v1.schema.json"
        schema = json.loads(path.read_text(encoding="utf-8"))
        capabilities = adaptive_recon_capabilities()
        self.assertEqual(
            schema["$defs"]["planState"]["enum"], capabilities["states"]
        )
        self.assertEqual(
            schema["$defs"]["planRequest"]["properties"]["selected_path_ids"][
                "maxItems"
            ],
            capabilities["limits"]["targets_per_plan"],
        )
        self.assertEqual(
            schema["$defs"]["planRequest"]["properties"]["history"]["maxItems"],
            capabilities["limits"]["history_snapshots"],
        )
        self.assertEqual(
            schema["$defs"]["deviceContext"]["properties"]["supported_bands"][
                "maxItems"
            ],
            capabilities["limits"]["supported_bands"],
        )
        self.assertEqual(
            schema["$defs"]["scanRequest"]["properties"]["scan_time"]["minimum"],
            capabilities["limits"]["minimum_scan_time"],
        )
        self.assertEqual(
            schema["$defs"]["scanRequest"]["properties"]["scan_time"]["maximum"],
            capabilities["limits"]["maximum_scan_time"],
        )
        self.assertEqual(
            (
                schema["$defs"]["restDescriptor"]["properties"]["method"]["const"],
                schema["$defs"]["restDescriptor"]["properties"]["path"]["const"],
            ),
            (
                capabilities["rest"]["method"],
                capabilities["rest"]["path"],
            ),
        )

    def test_frontend_settings_schema_matches_runtime_limits(self):
        path = ROOT / "docs" / "schemas" / "frontend-v1.schema.json"
        schema = json.loads(path.read_text(encoding="utf-8"))
        settings = schema["$defs"]["settings"]["properties"]
        band = schema["$defs"]["band"]["properties"]
        self.assertEqual(settings["supported_bands"]["maxItems"], MAX_SUPPORTED_BANDS)
        self.assertEqual(settings["language"]["enum"], ["en", "fi"])
        self.assertEqual(band["value"]["maxLength"], 32)
        self.assertEqual(band["covers"]["items"]["enum"], ["2.4", "5"])


if __name__ == "__main__":
    unittest.main()
