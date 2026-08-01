#!/usr/bin/env python3
"""Simulated endpoint agent for the Guardian outbound connection lab."""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import socket
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

try:
    from . import __version__
    from .protocol import ACTION_SCHEMAS, ProtocolError, make_agent_message, now, validate_job
except ImportError:
    from __init__ import __version__  # type: ignore
    from protocol import ACTION_SCHEMAS, ProtocolError, make_agent_message, now, validate_job  # type: ignore


class GuardianLabAgent:
    def __init__(self, controller_url: str, device_id: str, secret: str, lab_root: Path):
        self.controller_url = controller_url.rstrip("/")
        self.device_id = device_id
        self.secret = secret
        self.lab_root = lab_root.resolve()
        self.seen_job_nonces: set[str] = set()

    def _post(self, path: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
        data = json.dumps(payload, sort_keys=True).encode("utf-8")
        request = urllib.request.Request(
            self.controller_url + path,
            data=data,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                value = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read().decode("utf-8", errors="replace")
            finally:
                exc.close()
            raise RuntimeError(f"Controller rejected {path}: HTTP {exc.code}: {body}") from exc
        if not isinstance(value, dict):
            raise RuntimeError("Controller response must be a JSON object.")
        return value

    def checkin(self) -> Dict[str, Any]:
        message = make_agent_message(
            self.device_id,
            "checkin",
            {"agent_version": __version__, "capabilities": sorted(ACTION_SCHEMAS)},
            self.secret,
        )
        return self._post("/v1/checkin", message)

    def poll(self) -> Optional[Dict[str, Any]]:
        message = make_agent_message(self.device_id, "poll", {}, self.secret)
        response = self._post("/v1/poll", message)
        job = response.get("job")
        if job is None:
            return None
        if not isinstance(job, dict):
            raise ProtocolError("Controller returned an invalid job object.")
        checked = validate_job(job, self.secret, self.device_id)
        job_nonce = checked["nonce"]
        if job_nonce in self.seen_job_nonces:
            raise ProtocolError("Job nonce has already been executed by this agent.")
        self.seen_job_nonces.add(job_nonce)
        return checked

    def execute(self, job: Mapping[str, Any]) -> Dict[str, Any]:
        action = job["action"]
        params = job["params"]
        handlers = {
            "ping": self._ping,
            "system_info": self._system_info,
            "disk_usage": self._disk_usage,
            "echo": self._echo,
        }
        handler = handlers.get(action)
        if handler is None:
            raise ProtocolError(f"No local handler exists for action {action!r}.")
        try:
            output = handler(params)
            status = "success"
        except Exception as exc:
            output = {"error": type(exc).__name__, "message": str(exc)[:256]}
            status = "failure"
        return {"job_id": job["job_id"], "status": status, "output": output, "completed_at": now()}

    def submit_result(self, result: Mapping[str, Any]) -> Dict[str, Any]:
        message = make_agent_message(self.device_id, "result", result, self.secret)
        return self._post("/v1/result", message)

    def run_once(self) -> Optional[Dict[str, Any]]:
        self.checkin()
        job = self.poll()
        if job is None:
            return None
        result = self.execute(job)
        self.submit_result(result)
        return result

    def _ping(self, params: Mapping[str, Any]) -> Dict[str, Any]:
        return {"reply": "pong", "device_time": now()}

    def _system_info(self, params: Mapping[str, Any]) -> Dict[str, Any]:
        return {
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "python": platform.python_version(),
            "agent_version": __version__,
        }

    def _disk_usage(self, params: Mapping[str, Any]) -> Dict[str, Any]:
        usage = shutil.disk_usage(self.lab_root)
        return {
            "lab_root": str(self.lab_root),
            "total_bytes": usage.total,
            "used_bytes": usage.used,
            "free_bytes": usage.free,
        }

    def _echo(self, params: Mapping[str, Any]) -> Dict[str, Any]:
        return {"message": params["message"]}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Guardian fixed-action outbound lab agent")
    parser.add_argument("--controller", default="http://127.0.0.1:8765")
    parser.add_argument("--device-id", default=f"lab-{socket.gethostname()}")
    parser.add_argument("--lab-root", type=Path, default=Path.cwd())
    parser.add_argument("--interval", type=float, default=3.0)
    parser.add_argument("--once", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    secret = os.environ.get("GUARDIAN_LAB_SHARED_SECRET", "")
    if len(secret) < 24:
        raise SystemExit("Set GUARDIAN_LAB_SHARED_SECRET to at least 24 characters.")
    if not args.controller.startswith(("http://127.0.0.1:", "http://[::1]:", "https://")):
        raise SystemExit("Plain HTTP is allowed only for a loopback controller; use HTTPS for network labs.")
    agent = GuardianLabAgent(args.controller, args.device_id, secret, args.lab_root)
    if args.once:
        result = agent.run_once()
        print(json.dumps({"result": result}, indent=2, sort_keys=True))
        return 0
    print(f"Guardian lab agent {args.device_id} checking in to {args.controller}")
    print(f"Capabilities: {', '.join(sorted(ACTION_SCHEMAS))}")
    try:
        while True:
            try:
                result = agent.run_once()
                if result:
                    print(json.dumps(result, sort_keys=True))
            except Exception as exc:
                print(f"lab cycle failed: {exc}")
            time.sleep(max(1.0, args.interval))
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
