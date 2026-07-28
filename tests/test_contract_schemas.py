import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "projects" / "PineAI" / "src" / "assets"
SCHEMA_PATH = ROOT / "docs" / "schemas" / "baseline-drift-v1.schema.json"
sys.path.insert(0, str(ASSETS))

from pineai_backend.assurance_service import AssuranceService  # noqa: E402


def load_schema():
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def prefix_constants(value):
    return [item["const"] for item in value["prefixItems"]]


class ContractSchemaTests(unittest.TestCase):
    def test_schema_is_valid_json_with_resolvable_local_definitions(self):
        schema = load_schema()
        self.assertEqual(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema",
        )
        definitions = schema["$defs"]

        def visit(value):
            if isinstance(value, dict):
                reference = value.get("$ref")
                if reference and reference.startswith("#/$defs/"):
                    self.assertIn(reference.split("/")[-1], definitions)
                for item in value.values():
                    visit(item)
            elif isinstance(value, list):
                for item in value:
                    visit(item)

        visit(schema)

    def test_public_actions_match_runtime_capabilities(self):
        schema = load_schema()
        capabilities = AssuranceService().capabilities()
        documented = list(schema["x-module-actions"])
        self.assertEqual(documented, capabilities["module_actions"])
        self.assertEqual(
            prefix_constants(
                schema["$defs"]["assuranceCapabilities"]["properties"][
                    "module_actions"
                ]
            ),
            capabilities["module_actions"],
        )
        self.assertFalse(capabilities["recon_control"])

    def test_deterministic_enums_and_rules_match_runtime(self):
        schema = load_schema()
        definitions = schema["$defs"]
        capabilities = AssuranceService().capabilities()
        self.assertEqual(
            definitions["comparabilityStatus"]["enum"],
            capabilities["comparability_states"],
        )
        self.assertEqual(
            definitions["findingStatus"]["enum"],
            capabilities["finding_statuses"],
        )
        self.assertEqual(
            definitions["ruleId"]["enum"],
            [item["rule_id"] for item in capabilities["rules"]],
        )
        documented_rules = definitions["assuranceCapabilities"]["properties"][
            "rules"
        ]
        self.assertEqual(documented_rules["minItems"], 8)
        self.assertEqual(documented_rules["maxItems"], 8)
        documented_limits = definitions["assuranceCapabilities"]["properties"][
            "limits"
        ]["required"]
        self.assertEqual(
            set(documented_limits),
            set(capabilities["limits"]),
        )

    def test_boundary_contracts_are_explicit(self):
        definitions = load_schema()["$defs"]
        metadata = definitions["scanMetadataInput"]["properties"]
        self.assertIn("id", metadata)
        self.assertIn("duration", metadata)
        self.assertEqual(metadata["scan_time"]["minimum"], 1)
        self.assertEqual(metadata["scan_time"]["maximum"], 86400)
        self.assertEqual(
            definitions["operatorFindingStatus"]["enum"],
            ["open", "acknowledged", "false_positive"],
        )
        self.assertIn(
            "baseline_version",
            definitions["activateBaselineRequest"]["properties"],
        )
        self.assertNotIn(
            "baseline_version_id",
            definitions["activateBaselineRequest"]["properties"],
        )
        self.assertEqual(
            set(definitions["aiOptions"]["properties"]),
            {"language", "share_ssids"},
        )
        self.assertEqual(
            definitions["reportResponse"]["properties"]["mime_type"]["enum"],
            ["application/json", "text/html"],
        )

    def test_removed_attack_contracts_are_not_published(self):
        schema_directory = SCHEMA_PATH.parent
        for name in (
            "attack-path-advisor-v1.schema.json",
            "adaptive-recon-v1.schema.json",
            "frontend-v1.schema.json",
        ):
            self.assertFalse((schema_directory / name).exists(), name)

    def test_runtime_output_validates_against_json_schema(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema library not installed")

        from pineai_backend.assurance import compare_snapshots, resolve_assets  # noqa: E402

        schema = load_schema()
        fixture_path = ROOT / "tests" / "fixtures" / "recon_basic.json"
        raw_scan = json.loads(fixture_path.read_text(encoding="utf-8"))
        metadata = {
            "scan_id": "scan-1",
            "date": "2026-07-27T12:00:00Z",
            "scan_time": 180,
            "coverage": ["2.4"],
            "location_id": "loc-1",
            "measurement_point_id": "point-1",
            "declared_channels": [1, 6, 11],
        }
        secret = b"a" * 32
        snapshot = resolve_assets(raw_scan, metadata, secret, oui_database={})

        def validate_def(instance, def_name):
            wrapper = {
                "$schema": schema["$schema"],
                "$defs": schema["$defs"],
                "$ref": f"#/$defs/{def_name}",
            }
            jsonschema.validate(instance=instance, schema=wrapper)

        validate_def(snapshot, "resolvedSnapshot")
        comparison_res = compare_snapshots(snapshot, snapshot)
        validate_def(comparison_res["comparability"], "comparability")


if __name__ == "__main__":
    unittest.main()

