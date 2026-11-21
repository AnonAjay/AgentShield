"""Typed data exchanged across the Agent Shield security boundary."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import math
from types import MappingProxyType
from typing import Any, Mapping
from uuid import uuid4


def _freeze_mapping(value: Mapping[str, Any]) -> Mapping[str, Any]:
    """Copy JSON-like input recursively to prevent mutation after validation."""
    return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})


def _freeze_json(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite numbers are not valid tool arguments")
        return value
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise TypeError("tool argument object keys must be strings")
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(item) for item in value)
    raise TypeError("tool arguments must contain JSON-compatible values")


@dataclass(frozen=True, slots=True)
class ToolCall:
    """An untrusted proposal to invoke a named tool.

    Tool name and arguments are model-controlled input. request_id is only
    a correlation value; it must never be used as evidence of authorization.
    """

    tool_name: str
    arguments: Mapping[str, Any] = field(default_factory=dict)
    request_id: str = field(default_factory=lambda: str(uuid4()))

    def __post_init__(self) -> None:
        if (
            not isinstance(self.tool_name, str)
            or not self.tool_name.strip()
            or self.tool_name != self.tool_name.strip()
        ):
            raise ValueError("tool_name must be a non-empty string")
        if not isinstance(self.arguments, Mapping):
            raise TypeError("arguments must be a mapping")
        if not isinstance(self.request_id, str) or not self.request_id:
            raise ValueError("request_id must be a non-empty string")
        object.__setattr__(self, "arguments", _freeze_mapping(self.arguments))


@dataclass(frozen=True, slots=True)
class AuthorizationContext:
    """Host-supplied identity and grants; never accept this from model output."""

    principal: str = "anonymous"
    permissions: frozenset[str] = frozenset()
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.principal, str) or not self.principal:
            raise ValueError("principal must be a non-empty string")
        if isinstance(self.permissions, str):
            raise TypeError("permissions must be a collection of permission strings")
        if any(not isinstance(permission, str) or not permission for permission in self.permissions):
            raise ValueError("permissions must contain non-empty strings")
        object.__setattr__(self, "permissions", frozenset(self.permissions))
        object.__setattr__(self, "attributes", _freeze_mapping(self.attributes))


class DecisionEffect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True, slots=True)
class SecurityDecision:
    """A Shield-generated authorization outcome."""

    effect: DecisionEffect
    tool_name: str
    request_id: str
    reason_code: str
    message: str
    policy_id: str
    decided_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if self.decided_at.tzinfo is None:
            raise ValueError("decided_at must be timezone-aware")
