from __future__ import annotations

import json
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path


LAB_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB_DIR))

from agent import GuardianLabAgent  # noqa: E402
from controller import LabState, make_handler  # noqa: E402
from http.server import ThreadingHTTPServer  # noqa: E402
from protocol import ProtocolError, make_job, signed, validate_job  # noqa: E402


SECRET = "test-shared-secret-that-is-long-enough"
TOKEN = "test-operator-token-long-enough"


class RemoteLabTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.state = LabState(SECRET, TOKEN, Path(self.temp.name))
        self.arsenal_fixture = Path(self.temp.name) / "The-Rootkit-Arsenal.pdf"
        self.arsenal_fixture.write_bytes(b"%PDF-1.4\n% Guardian test fixture\n%%EOF\n")
        self.server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_handler(self.state, {"The-Rootkit-Arsenal.pdf": self.arsenal_fixture}),
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def operator_post(self, path: str, payload: dict) -> tuple[int, dict]:
        request = urllib.request.Request(
            self.base + path,
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, json.loads(exc.read().decode("utf-8"))
            finally:
                exc.close()

    def operator_get(self, path: str) -> tuple[int, dict]:
        request = urllib.request.Request(
            self.base + path,
            headers={"Authorization": f"Bearer {TOKEN}", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, json.loads(exc.read().decode("utf-8"))
            finally:
                exc.close()

    def get(self, path: str, accept: str = "application/json") -> tuple[int, str, str]:
        request = urllib.request.Request(self.base + path, headers={"Accept": accept})
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                return response.status, response.headers.get_content_type(), response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, exc.headers.get_content_type(), exc.read().decode("utf-8")
            finally:
                exc.close()

    def test_agent_checks_back_executes_ping_and_returns_result(self) -> None:
        agent = GuardianLabAgent(self.base, "device-01", SECRET, Path(self.temp.name))
        agent.checkin()
        status, response = self.operator_post(
            "/v1/jobs",
            {"device_id": "device-01", "action": "ping", "params": {}, "ttl": 60},
        )
        self.assertEqual(status, 201)
        result = agent.run_once()
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["output"]["reply"], "pong")
        self.assertEqual(self.state.results[0]["job_id"], response["job"]["job_id"])

    def test_controller_rejects_shell_action(self) -> None:
        status, response = self.operator_post(
            "/v1/jobs",
            {"device_id": "device-01", "action": "shell", "params": {"command": "whoami"}, "ttl": 60},
        )
        self.assertEqual(status, 400)
        self.assertIn("Unsupported action", response["error"])

    def test_controller_rejects_command_parameter(self) -> None:
        status, response = self.operator_post(
            "/v1/jobs",
            {"device_id": "device-01", "action": "ping", "params": {"command": "whoami"}, "ttl": 60},
        )
        self.assertEqual(status, 400)
        self.assertIn("Unknown parameters", response["error"])

    def test_agent_rejects_altered_signed_job(self) -> None:
        job = make_job("device-01", "ping", {}, 60, SECRET)
        job["action"] = "system_info"
        with self.assertRaises(ProtocolError):
            validate_job(job, SECRET, "device-01")

    def test_agent_rejects_wrong_target(self) -> None:
        job = make_job("device-02", "ping", {}, 60, SECRET)
        with self.assertRaises(ProtocolError):
            validate_job(job, SECRET, "device-01")

    def test_unsigned_checkin_is_rejected(self) -> None:
        request = urllib.request.Request(
            self.base + "/v1/checkin",
            data=json.dumps({"device_id": "device-01"}).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request, timeout=3)
        try:
            self.assertEqual(caught.exception.code, 400)
        finally:
            caught.exception.close()

    def test_health_is_json_for_scripts_and_dashboard_for_browser(self) -> None:
        status, content_type, body = self.get("/health")
        self.assertEqual((status, content_type), (200, "application/json"))
        self.assertEqual(json.loads(body)["status"], "ok")
        status, content_type, body = self.get("/health", "text/html")
        self.assertEqual((status, content_type), (200, "text/html"))
        self.assertIn("ARCH ANGEL", body)
        self.assertIn("setInterval(refresh", body)
        self.assertIn("SCANNER", body)
        self.assertIn("ASL LAB", body)
        self.assertIn("PDF MANUALS", body)
        self.assertIn('/assets/arch-angel-logo.png', body)

    def test_arch_angel_logo_is_served_as_png(self) -> None:
        with urllib.request.urlopen(self.base + "/assets/arch-angel-logo.png", timeout=3) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(response.headers.get_content_type(), "image/png")
            self.assertEqual(response.read(8), b"\x89PNG\r\n\x1a\n")

    def test_loopback_dashboard_snapshot_updates(self) -> None:
        agent = GuardianLabAgent(self.base, "device-dashboard", SECRET, Path(self.temp.name))
        agent.checkin()
        status, content_type, body = self.get("/v1/dashboard")
        self.assertEqual((status, content_type), (200, "application/json"))
        snapshot = json.loads(body)
        self.assertEqual(snapshot["devices"][0]["device_id"], "device-dashboard")
        self.assertGreaterEqual(len(snapshot["events"]), 1)

    def test_scanner_is_fixed_to_loopback_profile(self) -> None:
        status, response = self.operator_post("/v1/scan", {"profile": "local-management"})
        self.assertEqual(status, 200)
        self.assertEqual(response["target"], "127.0.0.1")
        self.assertEqual([item["port"] for item in response["results"]], [8765, 16993, 5985, 5986])
        status, response = self.operator_post("/v1/scan", {"profile": "arbitrary-network"})
        self.assertEqual(status, 400)
        self.assertIn("Only the local-management", response["error"])

    def test_manual_path_traversal_is_rejected(self) -> None:
        status, content_type, body = self.get("/manuals/not-a-manual.pdf")
        self.assertEqual((status, content_type), (404, "application/json"))
        self.assertEqual(json.loads(body)["error"], "manual_not_found")

    def test_arsenal_manual_supports_bounded_ranges(self) -> None:
        request = urllib.request.Request(
            self.base + "/manuals/The-Rootkit-Arsenal.pdf",
            headers={"Range": "bytes=0-15"},
        )
        with urllib.request.urlopen(request, timeout=3) as response:
            data = response.read()
            self.assertEqual(response.status, 206)
            self.assertEqual(response.headers.get("Accept-Ranges"), "bytes")
            self.assertEqual(len(data), 16)
            self.assertTrue(data.startswith(b"%PDF"))

    def test_asl_source_is_staged_with_manifest_but_not_deployable(self) -> None:
        source = '''DefinitionBlock ("", "SSDT", 2, "GUARDN", "GDNVER00", 0x00000001)
{
    Method (GVER, 0, NotSerialized) { Return (0x00010000) }
}
'''
        status, response = self.operator_post(
            "/v1/asl/stage",
            {"filename": "GuardianPatch.dsl", "source": source, "notes": "unit test"},
        )
        self.assertEqual(status, 201)
        manifest = response["manifest"]
        self.assertEqual(manifest["status"], "staged-only")
        self.assertEqual(manifest["compile_status"], "not-run")
        self.assertFalse(manifest["deployable"])
        self.assertEqual(len(manifest["sha256"]), 64)
        self.assertTrue(Path(manifest["source_path"]).is_file())
        status, listing = self.operator_get("/v1/asl/staged")
        self.assertEqual(status, 200)
        self.assertEqual(listing["items"][0]["stage_id"], manifest["stage_id"])

    def test_asl_stage_rejects_hardware_regions_and_path_names(self) -> None:
        risky = '''DefinitionBlock ("", "SSDT", 2, "GUARDN", "GDNRISK0", 1)
{
    OperationRegion (RISK, SystemMemory, 0x1000, 0x10)
}
'''
        status, response = self.operator_post(
            "/v1/asl/stage", {"filename": "Risk.dsl", "source": risky}
        )
        self.assertEqual(status, 400)
        self.assertIn("not accepted", response["error"])
        safe = 'DefinitionBlock ("", "SSDT", 2, "GUARDN", "GDNSAFE0", 1) { }'
        status, response = self.operator_post(
            "/v1/asl/stage", {"filename": "../escape.dsl", "source": safe}
        )
        self.assertEqual(status, 400)
        self.assertIn("simple .dsl name", response["error"])


if __name__ == "__main__":
    unittest.main()
