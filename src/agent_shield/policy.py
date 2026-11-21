"""Framework-independent policy interface and deterministic tool registry."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping, Protocol

from .models import AuthorizationContext, DecisionEffect, SecurityDecision, ToolCall


class Policy(Protocol):
    """Deterministic policy contract used by the runtime interceptor."""

    policy_id: str

    def get_tool(self, name: str) -> ToolDefinition | None:
        """Return a host-registered definition, never model-supplied code."""

    def evaluate(
        self, call: ToolCall, context: AuthorizationContext
    ) -> SecurityDecision:
        """Return a Shield-generated authorization decision."""


ToolHandler = Callable[..., Any]


def _freeze_schema(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise TypeError("schema keys must be strings")
        return MappingProxyType({key: _freeze_schema(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_schema(item) for item in value)
    raise TypeError("schema must contain JSON-compatible values")


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    """Host-owned callable and constraints for a single allowlisted tool."""

    name: str
    handler: ToolHandler
    argument_schema: Mapping[str, Any] = field(default_factory=lambda: {"type": "object"})
    required_permissions: frozenset[str] = frozenset()
    filesystem_roots: Mapping[str, tuple[Path, ...]] = field(default_factory=dict)
    network_host_argument: str | None = None
    allowed_network_hosts: tuple[str, ...] = ()
    sensitive: bool = False

    def __post_init__(self) -> None:
        if not self.name or not isinstance(self.name, str):
            raise ValueError("tool name must be a non-empty string")
        if not callable(self.handler):
            raise TypeError("tool handler must be callable")
        if isinstance(self.required_permissions, str):
            raise TypeError("required_permissions must be a collection of permission strings")
        if any(
            not isinstance(permission, str) or not permission
            for permission in self.required_permissions
        ):
            raise ValueError("required_permissions must contain non-empty strings")
        if not isinstance(self.argument_schema, Mapping):
            raise TypeError("argument_schema must be a mapping")
        object.__setattr__(self, "argument_schema", _freeze_schema(self.argument_schema))
        properties = self.argument_schema.get("properties", {})
        required = self.argument_schema.get("required", ())
        if not isinstance(properties, Mapping) or not isinstance(required, (list, tuple)):
            raise ValueError("argument schema must define object properties and required fields as mappings/lists")
        for argument_name in self.filesystem_roots:
            if argument_name not in required or not isinstance(properties.get(argument_name), Mapping):
                raise ValueError("filesystem path arguments must be declared required in the schema")
            if properties[argument_name].get("type") != "string":
                raise ValueError("filesystem path arguments must have string schema type")
        if self.network_host_argument is not None:
            if self.network_host_argument not in required:
                raise ValueError("network host argument must be required in the schema")
            if not isinstance(properties.get(self.network_host_argument), Mapping):
                raise ValueError("network host argument must be declared in schema properties")
            if properties[self.network_host_argument].get("type") != "string":
                raise ValueError("network host argument must have string schema type")
        object.__setattr__(self, "required_permissions", frozenset(self.required_permissions))
        object.__setattr__(
            self,
            "filesystem_roots",
            MappingProxyType({
                key: tuple(Path(root) for root in roots)
                for key, roots in self.filesystem_roots.items()
            }),
        )
        object.__setattr__(self, "allowed_network_hosts", tuple(self.allowed_network_hosts))
        if self.network_host_argument is not None and not self.allowed_network_hosts:
            raise ValueError("network tools must configure at least one allowed host")


class PolicyEngine:
    """Default-deny allowlist policy with host-owned permission checks."""

    def __init__(
        self,
        tools: tuple[ToolDefinition, ...] | list[ToolDefinition],
        *,
        policy_id: str = "default-allowlist-v1",
    ) -> None:
        self.policy_id = policy_id
        registry: dict[str, ToolDefinition] = {}
        for definition in tools:
            if definition.name in registry:
                raise ValueError(f"duplicate tool registration: {definition.name}")
            registry[definition.name] = definition
        self._tools = MappingProxyType(registry)

    def get_tool(self, name: str) -> ToolDefinition | None:
        return self._tools.get(name)

    def evaluate(
        self, call: ToolCall, context: AuthorizationContext
    ) -> SecurityDecision:
        definition = self.get_tool(call.tool_name)
        if definition is None:
            return self._decision(call, DecisionEffect.DENY, "TOOL_NOT_ALLOWLISTED", "Tool is not registered")
        required = set(definition.required_permissions)
        if definition.sensitive:
            required.add(f"sensitive:{definition.name}")
        if definition.network_host_argument is not None:
            required.add("network:connect")
        missing = required.difference(context.permissions)
        if missing:
            return self._decision(call, DecisionEffect.DENY, "PERMISSION_DENIED", "Required permission is missing")
        return self._decision(call, DecisionEffect.ALLOW, "AUTHORIZED", "Tool call is authorized")

    def _decision(
        self,
        call: ToolCall,
        effect: DecisionEffect,
        reason_code: str,
        message: str,
    ) -> SecurityDecision:
        return SecurityDecision(
            effect=effect,
            tool_name=call.tool_name,
            request_id=call.request_id,
            reason_code=reason_code,
            message=message,
            policy_id=self.policy_id,
        )
