#!/usr/bin/env python3
"""Operator client for submitting fixed Guardian Remote Lab actions."""

from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

try:
    from .protocol import ACTION_SCHEMAS, ProtocolError, validate_action, validate_device_id
except ImportError:
    from protocol import ACTION_SCHEMAS, ProtocolError, validate_action, validate_device_id  # type: ignore


def request_json(url: str, token: str, method: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            value = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", errors="replace")
        finally:
            exc.close()
        raise SystemExit(f"HTTP {exc.code}: {body}") from exc
    if not isinstance(value, dict):
        raise SystemExit("Controller returned a non-object response.")
    return value


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Guardian Remote Lab fixed-action operator")
    parser.add_argument("--controller", default="http://127.0.0.1:8765")
    sub = parser.add_subparsers(dest="command", required=True)
    submit = sub.add_parser("submit")
    submit.add_argument("--device-id", required=True)
    submit.add_argument("--action", required=True, choices=sorted(ACTION_SCHEMAS))
    submit.add_argument("--message", help="required only for the echo action")
    submit.add_argument("--ttl", type=int, default=60)
    sub.add_parser("devices")
    sub.add_parser("results")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    token = os.environ.get("GUARDIAN_LAB_OPERATOR_TOKEN", "")
    if len(token) < 16:
        raise SystemExit("Set GUARDIAN_LAB_OPERATOR_TOKEN to at least 16 characters.")
    base = args.controller.rstrip("/")
    if args.command == "submit":
        device_id = validate_device_id(args.device_id)
        params = {"message": args.message} if args.action == "echo" else {}
        if args.action == "echo" and args.message is None:
            raise SystemExit("--message is required for the echo action.")
        try:
            clean = validate_action(args.action, params)
        except ProtocolError as exc:
            raise SystemExit(str(exc)) from exc
        response = request_json(
            base + "/v1/jobs",
            token,
            "POST",
            {"device_id": device_id, "action": args.action, "params": clean, "ttl": args.ttl},
        )
    elif args.command == "devices":
        response = request_json(base + "/v1/devices", token, "GET")
    else:
        response = request_json(base + "/v1/results", token, "GET")
    print(json.dumps(response, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
