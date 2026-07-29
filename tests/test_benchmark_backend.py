import json
import unittest
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import benchmark_backend


class BenchmarkHarnessTests(unittest.TestCase):
    def test_percentile_calculation(self):
        values = [10.0, 20.0, 30.0, 40.0, 50.0]
        self.assertEqual(benchmark_backend.calculate_percentile(values, 50), 30.0)
        self.assertEqual(benchmark_backend.calculate_percentile(values, 95), 50.0)
        self.assertEqual(benchmark_backend.calculate_percentile([], 50), 0.0)

    def test_local_adapter_benchmark_returns_valid_shape(self):
        results = benchmark_backend.run_local_adapter_benchmark(iterations=3, cold_start_runs=2)
        self.assertEqual(results["schema_version"], "1.0")
        self.assertEqual(results["mode"], "local-adapter")
        self.assertTrue(results["passed"])
        self.assertIn("startup_ms", results)
        self.assertIn("actions", results)
        self.assertIn("health", results["actions"])
        self.assertIn("rss_mib", results)
        self.assertIn("cache", results)


if __name__ == "__main__":
    unittest.main()
