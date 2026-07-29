import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import benchmark_backend  # noqa: E402


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
        self.assertIn("service_initialization_ms", results)
        self.assertIn("actions", results)
        self.assertIn("health", results["actions"])
        self.assertIn("rss_mib", results)
        self.assertIn("cache", results)
        self.assertEqual(len(results["violations"]), 0)

    def test_local_adapter_environment_restoration(self):
        original_env = os.environ.get("PINEAI_CONFIG_DIR")
        os.environ["PINEAI_CONFIG_DIR"] = "/test/original/config/dir"
        try:
            benchmark_backend.run_local_adapter_benchmark(iterations=1, cold_start_runs=1)
            self.assertEqual(os.environ.get("PINEAI_CONFIG_DIR"), "/test/original/config/dir")
        finally:
            if original_env is None:
                os.environ.pop("PINEAI_CONFIG_DIR", None)
            else:
                os.environ["PINEAI_CONFIG_DIR"] = original_env

    def test_local_adapter_missing_action_handler(self):
        benchmark_backend.setup_pineapple_stub()
        import module
        saved_handler = module.module._actions.pop("health", None)
        try:
            results = benchmark_backend.run_local_adapter_benchmark(iterations=1, cold_start_runs=1)
            self.assertFalse(results["passed"])
            self.assertTrue(any("Required action handler missing: health" in v for v in results["violations"]))
        finally:
            if saved_handler:
                module.module._actions["health"] = saved_handler

    def test_local_adapter_handler_exception(self):
        benchmark_backend.setup_pineapple_stub()
        import module

        def broken_handler(_req):
            raise RuntimeError("Backend failure simulated")

        saved_handler = module.module._actions.get("health")
        module.module._actions["health"] = broken_handler
        try:
            results = benchmark_backend.run_local_adapter_benchmark(iterations=1, cold_start_runs=1)
            self.assertFalse(results["passed"])
            self.assertTrue(any("Backend failure simulated" in v for v in results["violations"]))
        finally:
            if saved_handler:
                module.module._actions["health"] = saved_handler

    def test_local_adapter_backend_error_response(self):
        benchmark_backend.setup_pineapple_stub()
        import module

        def error_handler(_req):
            return {"error": {"code": "storage_busy", "message": "Storage busy"}}

        saved_handler = module.module._actions.get("health")
        module.module._actions["health"] = error_handler
        try:
            results = benchmark_backend.run_local_adapter_benchmark(iterations=1, cold_start_runs=1)
            self.assertFalse(results["passed"])
            self.assertTrue(any("health returned backend error" in v for v in results["violations"]))
        finally:
            if saved_handler:
                module.module._actions["health"] = saved_handler

    def test_mark_vii_socket_missing_socket_path_argument(self):
        results = benchmark_backend.run_mark_vii_socket_benchmark(iterations=1, socket_path=None)
        self.assertFalse(results["passed"])
        self.assertEqual(results["connection_mode"], "attach")
        self.assertIsNone(results["rss_mib"])
        self.assertIsNone(results["service_initialization_ms"])
        self.assertIsNone(results["cache"])
        self.assertIn("--socket-path or PINEAI_SOCKET_PATH environment variable is required", results["violations"])

    def test_mark_vii_socket_unavailable(self):
        results = benchmark_backend.run_mark_vii_socket_benchmark(iterations=1, socket_path="/nonexistent/pineai.sock")
        self.assertFalse(results["passed"])
        self.assertEqual(results["connection_mode"], "attach")
        self.assertIsNone(results["rss_mib"])
        self.assertIn("Socket path does not exist: /nonexistent/pineai.sock", results["violations"])


class SyntheticSocketServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.has_uds = hasattr(socket, "AF_UNIX")

    def setUp(self):
        if not self.has_uds:
            self.skipTest("Unix domain sockets not supported on platform")
        self.tmpdir = tempfile.TemporaryDirectory()
        self.socket_path = os.path.join(self.tmpdir.name, "test_pineai.sock")
        self.server_sock = None
        self.server_thread = None
        self.running = False

    def tearDown(self):
        self.running = False
        if self.server_sock:
            try:
                self.server_sock.close()
            except OSError:
                pass
        self.tmpdir.cleanup()

    def start_mock_server(self, handler_func):
        self.server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server_sock.bind(self.socket_path)
        self.server_sock.listen(5)
        self.running = True

        def accept_loop():
            while self.running:
                try:
                    self.server_sock.settimeout(0.5)
                    client_sock, _ = self.server_sock.accept()
                    client_sock.settimeout(1.0)
                    try:
                        handler_func(client_sock)
                    finally:
                        client_sock.close()
                except (socket.timeout, OSError):
                    continue

        self.server_thread = threading.Thread(target=accept_loop)
        self.server_thread.daemon = True
        self.server_thread.start()

    def test_valid_action_responses(self):
        def valid_handler(sock):
            req_data = sock.recv(1024)
            if not req_data:
                return
            req = json.loads(req_data.decode("utf-8").strip())
            action = req.get("action")
            if action == "health":
                resp = {"status": "ok", "module": "PineAI", "version": "0.6.3", "backend_version": "0.6.3"}
            elif action == "platform_capabilities":
                resp = {"schema_version": "1.0", "status": "ok", "storage": {}, "identity": {}, "recon_control": False}
            elif action == "list_assessments":
                resp = {"schema_version": "1.0", "assessments": []}
            elif action == "list_measurement_profiles":
                resp = {"schema_version": "1.0", "measurement_profiles": []}
            elif action == "assurance_capabilities":
                resp = {
                    "schema_version": "1.2",
                    "product_mode": "customer_audit_foundation",
                    "module_actions": [],
                    "result_types": {},
                    "report_scopes": [],
                    "recon_control": False,
                }
            else:
                resp = {"error": {"code": "unknown_action"}}
            sock.sendall(json.dumps(resp).encode("utf-8") + b"\n")

        self.start_mock_server(valid_handler)
        results = benchmark_backend.run_mark_vii_socket_benchmark(iterations=2, socket_path=self.socket_path)
        self.assertTrue(results["passed"])
        self.assertEqual(results["connection_mode"], "attach")
        self.assertFalse(results["protocol_validated"])
        self.assertFalse(results["hardware_validated"])

    def test_non_dict_json_response(self):
        def list_handler(sock):
            sock.recv(1024)
            sock.sendall(b"[1, 2, 3]\n")

        self.start_mock_server(list_handler)
        results = benchmark_backend.run_mark_vii_socket_benchmark(iterations=1, socket_path=self.socket_path)
        self.assertFalse(results["passed"])
        self.assertTrue(any("not a JSON object" in v for v in results["violations"]))

    def test_malformed_json_response(self):
        def malformed_handler(sock):
            sock.recv(1024)
            sock.sendall(b"{bad json\n")

        self.start_mock_server(malformed_handler)
        results = benchmark_backend.run_mark_vii_socket_benchmark(iterations=1, socket_path=self.socket_path)
        self.assertFalse(results["passed"])
        self.assertTrue(any("Malformed JSON" in v for v in results["violations"]))

    def test_backend_error_response(self):
        def error_handler(sock):
            sock.recv(1024)
            sock.sendall(b'{"error": {"code": "storage_busy"}}\n')

        self.start_mock_server(error_handler)
        results = benchmark_backend.run_mark_vii_socket_benchmark(iterations=1, socket_path=self.socket_path)
        self.assertFalse(results["passed"])

    def test_timeout_handling(self):
        def hanging_handler(sock):
            sock.recv(1024)
            time.sleep(1.5)  # Stalls longer than 0.5s timeout

        self.start_mock_server(hanging_handler)
        results = benchmark_backend.run_mark_vii_socket_benchmark(
            iterations=1, socket_path=self.socket_path, timeout_seconds=0.5
        )
        self.assertFalse(results["passed"])
        self.assertTrue(any("timed out" in v for v in results["violations"]))


if __name__ == "__main__":
    unittest.main()
