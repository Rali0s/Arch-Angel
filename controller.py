#!/usr/bin/env python3
"""Loopback-first controller for the Guardian outbound connection lab."""

from __future__ import annotations

import argparse
import hmac
import ipaddress
import json
import os
import socket
import ssl
import threading
import uuid
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, DefaultDict, Dict, List, Mapping, Optional

try:
    from .protocol import (
        MAX_BODY_BYTES,
        ProtocolError,
        make_job,
        now,
        validate_asl_source,
        validate_device_id,
        validate_recent,
        verify,
    )
except ImportError:
    from protocol import (  # type: ignore
        MAX_BODY_BYTES,
        ProtocolError,
        make_job,
        now,
        validate_asl_source,
        validate_device_id,
        validate_recent,
        verify,
    )


class LabState:
    def __init__(self, secret: str, operator_token: str, state_dir: Path):
        if len(operator_token) < 16:
            raise ValueError("The operator token must be at least 16 characters.")
        self.secret = secret
        self.operator_token = operator_token
        self.state_dir = state_dir.resolve()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.audit_path = self.state_dir / "audit.jsonl"
        self.asl_staging_dir = self.state_dir / "asl-staging"
        self.asl_staging_dir.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.devices: Dict[str, Dict[str, Any]] = {}
        self.queues: DefaultDict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.outstanding: Dict[str, Dict[str, Any]] = {}
        self.results: List[Dict[str, Any]] = []
        self.events: List[Dict[str, Any]] = []
        self.seen_agent_nonces: Dict[str, int] = {}

    def audit(self, event: str, details: Mapping[str, Any]) -> None:
        record = {"timestamp": now(), "event": event, "details": dict(details)}
        line = json.dumps(record, sort_keys=True, separators=(",", ":"))
        with self.lock:
            self.events.append(record)
            self.events = self.events[-100:]
            with self.audit_path.open("a", encoding="utf-8") as stream:
                stream.write(line + "\n")

    def dashboard(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "server_time": now(),
                "devices": sorted(self.devices.values(), key=lambda item: item["device_id"]),
                "queued": sum(len(queue) for queue in self.queues.values()),
                "outstanding": [
                    {
                        "job_id": job["job_id"],
                        "device_id": job["device_id"],
                        "action": job["action"],
                        "expires_at": job["expires_at"],
                    }
                    for job in self.outstanding.values()
                ],
                "results": list(self.results[-30:]),
                "events": list(self.events[-30:]),
            }

    def scan_loopback(self) -> Dict[str, Any]:
        services = [
            (8765, "Guardian Remote Lab", "local signed-job controller"),
            (16993, "Intel AMT HTTPS", "open port is not proof of provisioning"),
            (5985, "WinRM HTTP", "unencrypted management transport"),
            (5986, "WinRM HTTPS", "TLS management transport"),
        ]
        results = []
        for port, name, note in services:
            opened = False
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                    opened = True
            except OSError:
                pass
            results.append({"port": port, "name": name, "open": opened, "note": note})
        report = {
            "profile": "local-management",
            "target": "127.0.0.1",
            "scanned_at": now(),
            "results": results,
            "interpretation": "A listening port identifies a TCP service only; it does not prove authentication, authorization, or ACPI access.",
        }
        self.audit("scanner.completed", {"target": report["target"], "open_ports": [item["port"] for item in results if item["open"]]})
        return report

    def stage_asl(self, filename: Any, source: Any, notes: Any = "") -> Dict[str, Any]:
        validation = validate_asl_source(filename, source)
        if not isinstance(notes, str) or len(notes) > 500:
            raise ProtocolError("notes must be a string of at most 500 characters.")
        stage_id = str(uuid.uuid4())
        stage_dir = self.asl_staging_dir / stage_id
        stage_dir.mkdir(mode=0o700)
        source_path = stage_dir / validation["filename"]
        source_path.write_text(source, encoding="utf-8")
        manifest = {
            "stage_id": stage_id,
            "created_at": now(),
            "filename": validation["filename"],
            "source_bytes": validation["bytes"],
            "sha256": validation["sha256"],
            "warnings": validation["warnings"],
            "notes": notes,
            "status": "staged-only",
            "compile_status": "not-run",
            "deployable": False,
            "source_path": str(source_path),
        }
        (stage_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        self.audit(
            "asl.staged",
            {"stage_id": stage_id, "filename": manifest["filename"], "sha256": manifest["sha256"]},
        )
        return manifest

    def staged_asl(self) -> List[Dict[str, Any]]:
        manifests = []
        for path in self.asl_staging_dir.glob("*/manifest.json"):
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(value, dict):
                manifests.append(value)
        return sorted(manifests, key=lambda item: item.get("created_at", 0), reverse=True)[:50]

    def verify_agent_message(self, message: Mapping[str, Any], expected_kind: str) -> str:
        verify(message, self.secret)
        if message.get("kind") != expected_kind:
            raise ProtocolError(f"Expected message kind {expected_kind!r}.")
        device_id = validate_device_id(message.get("device_id"))
        validate_recent(message.get("timestamp"))
        message_nonce = message.get("nonce")
        if not isinstance(message_nonce, str) or len(message_nonce) < 16:
            raise ProtocolError("Agent message nonce is invalid.")
        with self.lock:
            if message_nonce in self.seen_agent_nonces:
                raise ProtocolError("Agent message nonce was already used.")
            self.seen_agent_nonces[message_nonce] = now()
            cutoff = now() - 600
            self.seen_agent_nonces = {
                value: seen for value, seen in self.seen_agent_nonces.items() if seen >= cutoff
            }
        return device_id

    def checkin(self, device_id: str, body: Mapping[str, Any]) -> None:
        capabilities = body.get("capabilities")
        if not isinstance(capabilities, list) or not all(isinstance(item, str) for item in capabilities):
            raise ProtocolError("capabilities must be a list of strings.")
        with self.lock:
            self.devices[device_id] = {
                "device_id": device_id,
                "last_seen": now(),
                "capabilities": sorted(set(capabilities)),
                "agent_version": body.get("agent_version"),
            }
        self.audit("device.checkin", {"device_id": device_id, "capabilities": capabilities})

    def enqueue(self, device_id: str, action: str, params: Mapping[str, Any], ttl: int) -> Dict[str, Any]:
        job = make_job(device_id, action, params, ttl, self.secret)
        with self.lock:
            self.queues[device_id].append(job)
        self.audit("job.queued", {"job_id": job["job_id"], "device_id": device_id, "action": action})
        return job

    def poll(self, device_id: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            queue = self.queues[device_id]
            while queue:
                job = queue.pop(0)
                if job["expires_at"] < now():
                    self.audit("job.expired", {"job_id": job["job_id"], "device_id": device_id})
                    continue
                self.outstanding[job["job_id"]] = job
                self.audit("job.delivered", {"job_id": job["job_id"], "device_id": device_id})
                return job
        return None

    def accept_result(self, device_id: str, body: Mapping[str, Any]) -> None:
        job_id = body.get("job_id")
        if not isinstance(job_id, str):
            raise ProtocolError("Result job_id is required.")
        with self.lock:
            job = self.outstanding.get(job_id)
            if not job or job["device_id"] != device_id:
                raise ProtocolError("Result does not match an outstanding job for this device.")
            result = {
                "job_id": job_id,
                "device_id": device_id,
                "action": job["action"],
                "status": body.get("status"),
                "output": body.get("output"),
                "completed_at": body.get("completed_at"),
            }
            self.results.append(result)
            del self.outstanding[job_id]
        self.audit("job.completed", {"job_id": job_id, "device_id": device_id, "status": result["status"]})


def configured_manuals() -> Dict[str, Path]:
    """Return optional local manuals without embedding workstation-specific paths."""
    manual_dir = Path(
        os.environ.get("GUARDIAN_LAB_MANUAL_DIR", str(Path(__file__).with_name("manuals")))
    ).expanduser()
    manuals = {
        name: manual_dir / name
        for name in (
            "The-Rootkit-Arsenal.pdf",
            "Guardian-ASL-Magic-Interactive-Book.pdf",
            "Hacking-The-Art-of-Exploitation-2nd-Edition.pdf",
            "Guardian-Remote-Management-Blueprint.pdf",
        )
    }
    arsenal_override = os.environ.get("GUARDIAN_LAB_ARSENAL_PDF")
    if arsenal_override:
        manuals["The-Rootkit-Arsenal.pdf"] = Path(arsenal_override).expanduser()
    exploitation_override = os.environ.get("GUARDIAN_LAB_EXPLOITATION_PDF")
    if exploitation_override:
        manuals["Hacking-The-Art-of-Exploitation-2nd-Edition.pdf"] = Path(
            exploitation_override
        ).expanduser()
    return manuals


def make_handler(state: LabState, manual_paths: Optional[Mapping[str, Path]] = None):
    dashboard_path = Path(__file__).with_name("dashboard.html")
    logo_path = Path(__file__).with_name("assets") / "arch-angel-logo.png"
    manuals = dict(manual_paths) if manual_paths is not None else configured_manuals()

    class Handler(BaseHTTPRequestHandler):
        server_version = "GuardianRemoteLab/0.1"

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _json(self, status: int, payload: Mapping[str, Any]) -> None:
            data = json.dumps(payload, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _html(self, status: int) -> None:
            data = dashboard_path.read_bytes()
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _logo(self) -> None:
            if not logo_path.is_file():
                self._json(404, {"error": "asset_not_found"})
                return
            data = logo_path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "public, max-age=3600")
            self.end_headers()
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                return

        def _manual(self, name: str) -> None:
            path = manuals.get(name)
            if path is None or not path.is_file():
                self._json(404, {"error": "manual_not_found"})
                return
            size = path.stat().st_size
            start = 0
            end = size - 1
            status = 200
            range_header = self.headers.get("Range")
            if range_header:
                if not range_header.startswith("bytes=") or "," in range_header:
                    self.send_response(416)
                    self.send_header("Content-Range", f"bytes */{size}")
                    self.end_headers()
                    return
                bounds = range_header.removeprefix("bytes=").split("-", 1)
                try:
                    if bounds[0]:
                        start = int(bounds[0])
                    if bounds[1]:
                        end = int(bounds[1])
                except ValueError:
                    self.send_response(416)
                    self.send_header("Content-Range", f"bytes */{size}")
                    self.end_headers()
                    return
                if start < 0 or end < start or start >= size:
                    self.send_response(416)
                    self.send_header("Content-Range", f"bytes */{size}")
                    self.end_headers()
                    return
                end = min(end, size - 1)
                status = 206
            length = end - start + 1
            self.send_response(status)
            self.send_header("Content-Type", "application/pdf")
            self.send_header("Content-Length", str(length))
            self.send_header("Content-Disposition", f'inline; filename="{name}"')
            self.send_header("Accept-Ranges", "bytes")
            if status == 206:
                self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            try:
                with path.open("rb") as stream:
                    stream.seek(start)
                    remaining = length
                    while remaining:
                        chunk = stream.read(min(64 * 1024, remaining))
                        if not chunk:
                            break
                        self.wfile.write(chunk)
                        remaining -= len(chunk)
            except (BrokenPipeError, ConnectionResetError):
                return

        def _is_loopback_client(self) -> bool:
            try:
                return ipaddress.ip_address(self.client_address[0]).is_loopback
            except ValueError:
                return False

        def _read_json(self) -> Dict[str, Any]:
            length_text = self.headers.get("Content-Length")
            if not length_text or not length_text.isdigit():
                raise ProtocolError("A numeric Content-Length is required.")
            length = int(length_text)
            if length < 2 or length > MAX_BODY_BYTES:
                raise ProtocolError("Request body size is outside the lab limits.")
            try:
                value = json.loads(self.rfile.read(length).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ProtocolError("Request body must be valid UTF-8 JSON.") from exc
            if not isinstance(value, dict):
                raise ProtocolError("Request body must be a JSON object.")
            return value

        def _require_operator(self) -> None:
            supplied = self.headers.get("Authorization", "")
            expected = f"Bearer {state.operator_token}"
            if not hmac.compare_digest(supplied, expected):
                raise PermissionError("Operator authorization failed.")

        def do_GET(self) -> None:
            try:
                accepts_html = "text/html" in self.headers.get("Accept", "")
                if self.path in ("/", "/dashboard") or (self.path == "/health" and accepts_html):
                    self._html(200)
                    return
                if self.path == "/assets/arch-angel-logo.png":
                    self._logo()
                    return
                if self.path.startswith("/manuals/"):
                    self._manual(self.path.removeprefix("/manuals/"))
                    return
                if self.path == "/health":
                    self._json(200, {"status": "ok", "mode": "fixed-actions-only"})
                    return
                if self.path == "/v1/dashboard":
                    if not self._is_loopback_client():
                        self._require_operator()
                    self._json(200, state.dashboard())
                    return
                if self.path == "/v1/asl/staged":
                    self._require_operator()
                    self._json(200, {"items": state.staged_asl()})
                    return
                self._require_operator()
                if self.path == "/v1/devices":
                    with state.lock:
                        devices = list(state.devices.values())
                    self._json(200, {"devices": devices})
                    return
                if self.path == "/v1/results":
                    with state.lock:
                        results = list(state.results)
                    self._json(200, {"results": results})
                    return
                self._json(404, {"error": "not_found"})
            except PermissionError as exc:
                self._json(401, {"error": str(exc)})
            except Exception as exc:
                self._json(400, {"error": str(exc)})

        def do_POST(self) -> None:
            try:
                message = self._read_json()
                if self.path == "/v1/checkin":
                    device_id = state.verify_agent_message(message, "checkin")
                    body = message.get("body")
                    if not isinstance(body, dict):
                        raise ProtocolError("checkin body must be an object.")
                    state.checkin(device_id, body)
                    self._json(200, {"accepted": True, "server_time": now()})
                    return
                if self.path == "/v1/poll":
                    device_id = state.verify_agent_message(message, "poll")
                    self._json(200, {"job": state.poll(device_id)})
                    return
                if self.path == "/v1/result":
                    device_id = state.verify_agent_message(message, "result")
                    body = message.get("body")
                    if not isinstance(body, dict):
                        raise ProtocolError("result body must be an object.")
                    state.accept_result(device_id, body)
                    self._json(200, {"accepted": True})
                    return
                if self.path == "/v1/jobs":
                    self._require_operator()
                    device_id = validate_device_id(message.get("device_id"))
                    action = message.get("action")
                    params = message.get("params", {})
                    ttl = message.get("ttl", 60)
                    job = state.enqueue(device_id, action, params, ttl)
                    self._json(201, {"job": job})
                    return
                if self.path == "/v1/scan":
                    self._require_operator()
                    if message and message.get("profile") not in (None, "local-management"):
                        raise ProtocolError("Only the local-management scanner profile is available.")
                    self._json(200, state.scan_loopback())
                    return
                if self.path == "/v1/asl/stage":
                    self._require_operator()
                    manifest = state.stage_asl(
                        message.get("filename"), message.get("source"), message.get("notes", "")
                    )
                    self._json(201, {"manifest": manifest})
                    return
                self._json(404, {"error": "not_found"})
            except PermissionError as exc:
                self._json(401, {"error": str(exc)})
            except (ProtocolError, ValueError) as exc:
                state.audit("request.rejected", {"path": self.path, "error": str(exc)})
                self._json(400, {"error": str(exc)})
            except Exception:
                state.audit("request.error", {"path": self.path})
                self._json(500, {"error": "internal_error"})

    return Handler


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Guardian fixed-action outbound connection lab controller")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--state-dir", type=Path, default=Path(".guardian-remote-lab"))
    parser.add_argument("--allow-network", action="store_true", help="allow a non-loopback bind; TLS is also required")
    parser.add_argument("--certfile", type=Path)
    parser.add_argument("--keyfile", type=Path)
    return parser.parse_args()


def require_environment() -> tuple[str, str]:
    secret = os.environ.get("GUARDIAN_LAB_SHARED_SECRET", "")
    token = os.environ.get("GUARDIAN_LAB_OPERATOR_TOKEN", "")
    if len(secret) < 24 or len(token) < 16:
        raise SystemExit(
            "Set GUARDIAN_LAB_SHARED_SECRET (24+ characters) and "
            "GUARDIAN_LAB_OPERATOR_TOKEN (16+ characters)."
        )
    return secret, token


def main() -> int:
    args = parse_args()
    try:
        address = ipaddress.ip_address(args.bind)
    except ValueError as exc:
        raise SystemExit("--bind must be an IP address, not a hostname.") from exc
    if not address.is_loopback:
        if not args.allow_network or not args.certfile or not args.keyfile:
            raise SystemExit("Non-loopback binding requires --allow-network plus --certfile and --keyfile.")
    secret, token = require_environment()
    state = LabState(secret, token, args.state_dir)
    server = ThreadingHTTPServer((args.bind, args.port), make_handler(state))
    scheme = "http"
    if args.certfile and args.keyfile:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(args.certfile), str(args.keyfile))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        scheme = "https"
    print(f"Guardian Remote Lab listening on {scheme}://{args.bind}:{args.port}")
    print("Mode: fixed diagnostic actions only; no arbitrary shell or script execution")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
