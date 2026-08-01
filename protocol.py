"""Signed message helpers and the fixed Guardian Remote Lab action contract."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
import uuid
from typing import Any, Dict, Mapping


MAX_BODY_BYTES = 64 * 1024
MAX_CLOCK_SKEW_SECONDS = 90
MAX_JOB_TTL_SECONDS = 300
MAX_ASL_SOURCE_BYTES = 16 * 1024

BLOCKED_ASL_CONSTRUCTS = (
    "OperationRegion",
    "Field",
    "BankField",
    "IndexField",
    "DataTableRegion",
    "Load",
    "LoadTable",
    "Unload",
    "Fatal",
    "SystemIO",
    "SystemMemory",
    "EmbeddedControl",
    "SMBus",
    "IPMI",
)


ACTION_SCHEMAS = {
    "ping": {},
    "system_info": {},
    "disk_usage": {},
    "echo": {"message": str},
}


class ProtocolError(ValueError):
    """Raised when a message violates the lab protocol."""


def canonical_json(payload: Mapping[str, Any]) -> bytes:
    unsigned = {key: value for key, value in payload.items() if key != "signature"}
    return json.dumps(
        unsigned,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def sign(payload: Mapping[str, Any], secret: str) -> str:
    if len(secret) < 24:
        raise ProtocolError("The shared lab secret must be at least 24 characters.")
    return hmac.new(secret.encode("utf-8"), canonical_json(payload), hashlib.sha256).hexdigest()


def signed(payload: Mapping[str, Any], secret: str) -> Dict[str, Any]:
    result = dict(payload)
    result["signature"] = sign(result, secret)
    return result


def verify(payload: Mapping[str, Any], secret: str) -> None:
    supplied = payload.get("signature")
    if not isinstance(supplied, str) or len(supplied) != 64:
        raise ProtocolError("A valid message signature is required.")
    expected = sign(payload, secret)
    if not hmac.compare_digest(supplied, expected):
        raise ProtocolError("Message signature verification failed.")


def now() -> int:
    return int(time.time())


def nonce() -> str:
    return secrets.token_hex(16)


def validate_recent(timestamp: Any, *, skew: int = MAX_CLOCK_SKEW_SECONDS) -> int:
    if not isinstance(timestamp, int):
        raise ProtocolError("timestamp must be an integer Unix time.")
    if abs(now() - timestamp) > skew:
        raise ProtocolError("Message timestamp is outside the allowed clock window.")
    return timestamp


def validate_device_id(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 80:
        raise ProtocolError("device_id must be a non-empty string of at most 80 characters.")
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")
    if any(char not in allowed for char in value):
        raise ProtocolError("device_id contains unsupported characters.")
    return value


def validate_action(action: Any, params: Any) -> Dict[str, Any]:
    if action not in ACTION_SCHEMAS:
        raise ProtocolError(
            f"Unsupported action {action!r}. Allowed actions: {sorted(ACTION_SCHEMAS)}"
        )
    if not isinstance(params, dict):
        raise ProtocolError("params must be a JSON object.")

    schema = ACTION_SCHEMAS[action]
    unknown = set(params) - set(schema)
    missing = set(schema) - set(params)
    if unknown:
        raise ProtocolError(f"Unknown parameters for {action}: {sorted(unknown)}")
    if missing:
        raise ProtocolError(f"Missing parameters for {action}: {sorted(missing)}")

    clean: Dict[str, Any] = {}
    for key, expected_type in schema.items():
        value = params[key]
        if not isinstance(value, expected_type):
            raise ProtocolError(f"Parameter {key} must be {expected_type.__name__}.")
        if isinstance(value, str) and len(value) > 256:
            raise ProtocolError(f"Parameter {key} exceeds the 256-character lab limit.")
        clean[key] = value
    return clean


def validate_asl_source(filename: Any, source: Any) -> Dict[str, Any]:
    if not isinstance(filename, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\.dsl", filename, re.IGNORECASE
    ):
        raise ProtocolError("filename must be a simple .dsl name of at most 68 characters.")
    if not isinstance(source, str) or not source.strip():
        raise ProtocolError("ASL source must be a non-empty string.")
    encoded = source.encode("utf-8")
    if len(encoded) > MAX_ASL_SOURCE_BYTES:
        raise ProtocolError(f"ASL source exceeds the {MAX_ASL_SOURCE_BYTES}-byte staging limit.")
    if "\x00" in source:
        raise ProtocolError("ASL source cannot contain NUL bytes.")
    if not re.search(r"\bDefinitionBlock\s*\(", source, re.IGNORECASE):
        raise ProtocolError("ASL source must contain a DefinitionBlock.")
    if not re.search(r"[\"']SSDT[\"']", source, re.IGNORECASE):
        raise ProtocolError("The DefinitionBlock must declare an SSDT.")
    if source.count("{") != source.count("}"):
        raise ProtocolError("ASL source has unbalanced braces.")

    blocked = [
        keyword
        for keyword in BLOCKED_ASL_CONSTRUCTS
        if re.search(rf"\b{re.escape(keyword)}\b", source, re.IGNORECASE)
    ]
    if blocked:
        raise ProtocolError(
            "Hardware-region, table-loading, and fatal constructs are not accepted by lab staging: "
            + ", ".join(blocked)
        )

    warnings = []
    if re.search(r"\bNotify\s*\(", source, re.IGNORECASE):
        warnings.append("Notify values require a documented cooperating driver contract.")
    reserved = sorted(
        set(re.findall(r"\b_(?:DSM|CRS|PRW|PS[0-3]|ON|OFF)\b", source, re.IGNORECASE))
    )
    if reserved:
        warnings.append("Review reserved-name semantics: " + ", ".join(reserved))
    if not re.search(r"\bExternal\s*\(", source, re.IGNORECASE):
        warnings.append("No External declarations were found; verify all referenced namespace objects.")

    return {
        "filename": filename,
        "bytes": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "warnings": warnings,
        "blocked": [],
        "safe_to_stage": True,
    }


def make_agent_message(device_id: str, kind: str, body: Mapping[str, Any], secret: str) -> Dict[str, Any]:
    payload = {
        "kind": kind,
        "device_id": validate_device_id(device_id),
        "timestamp": now(),
        "nonce": nonce(),
        "body": dict(body),
    }
    return signed(payload, secret)


def make_job(device_id: str, action: str, params: Mapping[str, Any], ttl: int, secret: str) -> Dict[str, Any]:
    validate_device_id(device_id)
    clean_params = validate_action(action, dict(params))
    if not isinstance(ttl, int) or ttl < 1 or ttl > MAX_JOB_TTL_SECONDS:
        raise ProtocolError(f"ttl must be between 1 and {MAX_JOB_TTL_SECONDS} seconds.")
    issued_at = now()
    payload = {
        "job_id": str(uuid.uuid4()),
        "device_id": device_id,
        "action": action,
        "params": clean_params,
        "issued_at": issued_at,
        "expires_at": issued_at + ttl,
        "nonce": nonce(),
    }
    return signed(payload, secret)


def validate_job(job: Mapping[str, Any], secret: str, expected_device_id: str) -> Dict[str, Any]:
    verify(job, secret)
    if job.get("device_id") != expected_device_id:
        raise ProtocolError("Job target does not match this device.")
    if not isinstance(job.get("job_id"), str):
        raise ProtocolError("job_id is required.")
    if not isinstance(job.get("nonce"), str) or len(job["nonce"]) < 16:
        raise ProtocolError("Job nonce is invalid.")
    issued_at = job.get("issued_at")
    expires_at = job.get("expires_at")
    if not isinstance(issued_at, int) or not isinstance(expires_at, int):
        raise ProtocolError("Job timestamps must be integers.")
    current = now()
    if issued_at > current + MAX_CLOCK_SKEW_SECONDS:
        raise ProtocolError("Job was issued in the future.")
    if expires_at < current:
        raise ProtocolError("Job has expired.")
    if expires_at - issued_at > MAX_JOB_TTL_SECONDS:
        raise ProtocolError("Job TTL exceeds the lab maximum.")
    clean_params = validate_action(job.get("action"), job.get("params"))
    result = dict(job)
    result["params"] = clean_params
    return result
