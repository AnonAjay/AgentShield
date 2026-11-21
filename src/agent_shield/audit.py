"""Audit sinks used by the runtime enforcement boundary."""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Protocol

from .events import SecurityEvent


class AuditSink(Protocol):
    def emit(self, event: SecurityEvent) -> None:
        """Persist one security event or raise an exception."""


class MemoryAuditSink:
    """In-memory sink useful for unit tests and local examples."""

    def __init__(self) -> None:
        self.events: list[SecurityEvent] = []
        self._lock = threading.Lock()

    def emit(self, event: SecurityEvent) -> None:
        with self._lock:
            self.events.append(event)


class JsonLinesAuditSink:
    """Append structured JSON events to a local JSON Lines file."""

    def __init__(self, path: str | Path, *, fsync: bool = False) -> None:
        self.path = Path(path)
        self.fsync = fsync
        self._lock = threading.Lock()

    def emit(self, event: SecurityEvent) -> None:
        payload = json.dumps(_event_to_json(event), sort_keys=True, separators=(",", ":"))
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8", newline="\n") as stream:
                stream.write(payload + "\n")
                stream.flush()
                if self.fsync:
                    os.fsync(stream.fileno())


def _event_to_json(event: SecurityEvent) -> dict[str, Any]:
    def convert(value: Any) -> Any:
        if isinstance(value, Enum):
            return value.value
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, Path):
            return str(value)
        if isinstance(value, dict) or hasattr(value, "items"):
            return {str(key): convert(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [convert(item) for item in value]
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        return repr(value)

    return {
        "event_type": convert(event.event_type),
        "request_id": event.request_id,
        "tool_name": event.tool_name,
        "reason_code": event.reason_code,
        "timestamp": convert(event.timestamp),
        "policy_id": event.policy_id,
        "principal": event.principal,
        "details": convert(event.details),
    }
