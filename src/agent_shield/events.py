"""Structured, JSON-serializable audit event definitions."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping


def _freeze_details(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise TypeError("event detail keys must be strings")
        return MappingProxyType({key: _freeze_details(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_details(item) for item in value)
    raise TypeError("event details must be JSON-compatible")


class SecurityEventType(str, Enum):
    REQUEST_RECEIVED = "request_received"
    REQUEST_DENIED = "request_denied"
    REQUEST_AUTHORIZED = "request_authorized"
    TOOL_EXECUTED = "tool_executed"
    TOOL_FAILED = "tool_failed"
    POLICY_ERROR = "policy_error"
    AUDIT_ERROR = "audit_error"
    STATIC_FINDING = "static_finding"


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    """Audit record metadata. Tool arguments and secrets are intentionally absent."""

    event_type: SecurityEventType
    request_id: str
    tool_name: str | None
    reason_code: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    policy_id: str | None = None
    principal: str | None = None
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.timestamp.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware")
        object.__setattr__(self, "details", _freeze_details(self.details))
