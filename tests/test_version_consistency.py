import json
import unittest
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "projects" / "PineAI" / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import pineai_backend  # noqa: E402


class VersionConsistencyTests(unittest.TestCase):
    def test_version_consistency_across_backend_and_module_json(self):
        module_json_path = SRC_DIR / "module.json"
        with open(module_json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        module_version = data.get("version")
        backend_version = pineai_backend.__version__
        self.assertEqual(
            module_version,
            backend_version,
            f"module.json version ({module_version}) != backend __version__ ({backend_version})",
        )
        self.assertEqual(module_version, "0.6.3")


if __name__ == "__main__":
    unittest.main()
