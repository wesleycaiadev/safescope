"""Restricted local-file implementation of the restore journal."""

from __future__ import annotations

import base64
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from safescope_core.policy import RequestDescriptor, RestoreAction, RestoreKind

_SENSITIVE_HEADERS = frozenset({"authorization", "cookie", "proxy-authorization"})


class FileRestoreJournal:
    """Store one atomic, permission-restricted JSON document per action."""

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)

    def append(self, action: RestoreAction) -> None:
        self._validate(action)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = self._path(action.id)
        if path.exists():
            raise ValueError(f"restore action '{action.id}' already exists")
        self._write(path, _serialize(action, "PENDING"))

    def pending(self) -> list[RestoreAction]:
        if not self.directory.exists():
            return []
        actions: list[RestoreAction] = []
        for path in sorted(self.directory.glob("*.json")):
            payload = json.loads(path.read_text(encoding="utf-8"))
            if payload.get("status") not in {"PENDING", "FAILED"}:
                continue
            action = _deserialize(payload)
            if action.attempts < action.max_attempts:
                actions.append(action)
        return actions

    def mark_completed(self, action_id: str) -> None:
        payload = self._read(action_id)
        payload["status"] = "COMPLETED"
        payload["last_error"] = None
        self._write(self._path(action_id), payload)

    def mark_failed(self, action_id: str, error: str) -> None:
        payload = self._read(action_id)
        payload["status"] = "FAILED"
        payload["attempts"] = int(payload.get("attempts", 0)) + 1
        payload["last_error"] = error[:500]
        self._write(self._path(action_id), payload)

    def unresolved_count(self) -> int:
        if not self.directory.exists():
            return 0
        count = 0
        for path in self.directory.glob("*.json"):
            payload = json.loads(path.read_text(encoding="utf-8"))
            if payload.get("status") in {"PENDING", "FAILED"}:
                count += 1
        return count

    def _read(self, action_id: str) -> dict[str, Any]:
        return json.loads(self._path(action_id).read_text(encoding="utf-8"))

    def _path(self, action_id: str) -> Path:
        safe_characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
        if not action_id or any(char not in safe_characters for char in action_id):
            raise ValueError("restore action id contains unsafe characters")
        return self.directory / f"{action_id}.json"

    def _write(self, path: Path, payload: dict[str, Any]) -> None:
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix="restore-", suffix=".tmp", dir=self.directory)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_name, path)
        finally:
            if os.path.exists(temporary_name):
                os.unlink(temporary_name)

    @staticmethod
    def _validate(action: RestoreAction) -> None:
        if action.request.scheme not in {"http", "https"}:
            raise ValueError("restore URL must use HTTP or HTTPS")
        if action.request.method.upper() not in {"DELETE", "PUT", "PATCH"}:
            raise ValueError("restore method must be DELETE, PUT or PATCH")
        if any(name.lower() in _SENSITIVE_HEADERS for name in action.request.headers):
            raise ValueError("secrets must be referenced through a target session, not stored in the journal")
        if action.request.body is not None and len(action.request.body) > 65_536:
            raise ValueError("restore body exceeds the 64 KiB journal limit")


def _serialize(action: RestoreAction, status: str) -> dict[str, Any]:
    body = base64.b64encode(action.request.body).decode("ascii") if action.request.body is not None else None
    return {
        "version": 1,
        "status": status,
        "id": action.id,
        "scan_run_id": action.scan_run_id,
        "kind": action.kind.value,
        "request": {
            "method": action.request.method,
            "url": action.request.url,
            "headers": action.request.headers,
            "body_base64": body,
            "is_probe": action.request.is_probe,
            "payload_id": action.request.payload_id,
        },
        "policy_snapshot": action.policy_snapshot,
        "marker": action.marker,
        "attempts": action.attempts,
        "max_attempts": action.max_attempts,
        "last_error": action.last_error,
    }


def _deserialize(payload: dict[str, Any]) -> RestoreAction:
    request = payload["request"]
    encoded = request.get("body_base64")
    body = base64.b64decode(encoded, validate=True) if encoded is not None else None
    return RestoreAction(
        id=str(payload["id"]),
        scan_run_id=str(payload["scan_run_id"]),
        kind=RestoreKind(str(payload["kind"])),
        request=RequestDescriptor(
            str(request["method"]),
            str(request["url"]),
            headers={str(key): str(value) for key, value in request.get("headers", {}).items()},
            body=body,
            is_probe=bool(request.get("is_probe", False)),
            payload_id=request.get("payload_id"),
        ),
        policy_snapshot=dict(payload["policy_snapshot"]),
        marker=str(payload["marker"]),
        attempts=int(payload.get("attempts", 0)),
        max_attempts=int(payload.get("max_attempts", 3)),
        last_error=payload.get("last_error"),
    )
