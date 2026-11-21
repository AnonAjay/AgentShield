"""Argument and resource validation for registered tools.

The v0.1 schema evaluator intentionally implements a small JSON-Schema-like
subset using only the standard library: object properties, required fields,
additionalProperties, and primitive/array/object types.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from .errors import ToolValidationError


_TYPE_CHECKS = {
    "object": lambda value: isinstance(value, Mapping),
    "array": lambda value: isinstance(value, (list, tuple)),
    "string": lambda value: isinstance(value, str),
    "integer": lambda value: isinstance(value, int) and not isinstance(value, bool),
    "number": lambda value: isinstance(value, (int, float)) and not isinstance(value, bool),
    "boolean": lambda value: isinstance(value, bool),
    "null": lambda value: value is None,
}

_SUPPORTED_SCHEMA_KEYS = {
    "type", "enum", "minimum", "maximum", "minLength", "maxLength",
    "required", "properties", "additionalProperties",
}


def validate_arguments(
    arguments: Mapping[str, Any],
    schema: Mapping[str, Any],
    *,
    filesystem_roots: Mapping[str, tuple[Path, ...]] | None = None,
    network_host_argument: str | None = None,
    allowed_network_hosts: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Validate tool args and enforce configured filesystem/network boundaries."""
    if not isinstance(arguments, Mapping):
        raise ToolValidationError("Arguments must be an object")
    normalized = dict(arguments)
    _validate_schema(normalized, schema, "$")

    for argument_name, roots in (filesystem_roots or {}).items():
        if argument_name not in normalized:
            continue
        _validate_path(normalized[argument_name], roots, argument_name)

    if network_host_argument is not None:
        if not allowed_network_hosts:
            raise ToolValidationError("Network tool has no configured host allowlist")
        host = normalized.get(network_host_argument)
        if not isinstance(host, str) or not _host_is_allowed(host, allowed_network_hosts):
            raise ToolValidationError("Network destination is outside the configured allowlist")

    return normalized


def _validate_schema(value: Any, schema: Mapping[str, Any], path: str) -> None:
    unsupported = set(schema).difference(_SUPPORTED_SCHEMA_KEYS)
    if unsupported:
        raise ToolValidationError(f"Unsupported schema keyword at {path}")

    expected = schema.get("type")
    if expected is not None:
        check = _TYPE_CHECKS.get(expected)
        if check is None:
            raise ToolValidationError(f"Unsupported schema type at {path}")
        if not check(value):
            raise ToolValidationError(f"Expected {expected} at {path}")

    allowed_values = schema.get("enum")
    if allowed_values is not None:
        if not isinstance(allowed_values, (list, tuple)) or value not in allowed_values:
            raise ToolValidationError(f"Value is outside the allowed set at {path}")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise ToolValidationError(f"Value is below the allowed minimum at {path}")
        if "maximum" in schema and value > schema["maximum"]:
            raise ToolValidationError(f"Value is above the allowed maximum at {path}")
    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            raise ToolValidationError(f"String is shorter than allowed at {path}")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            raise ToolValidationError(f"String is longer than allowed at {path}")

    if isinstance(value, Mapping):
        required = schema.get("required", ())
        if not isinstance(required, (list, tuple)):
            raise ToolValidationError(f"Invalid required declaration at {path}")
        missing = [key for key in required if key not in value]
        if missing:
            raise ToolValidationError(f"Missing required field at {path}")

        properties = schema.get("properties", {})
        if not isinstance(properties, Mapping):
            raise ToolValidationError(f"Invalid properties declaration at {path}")
        additional = schema.get("additionalProperties", False)
        if not isinstance(additional, bool):
            raise ToolValidationError(f"Unsupported additionalProperties declaration at {path}")
        if additional is False and any(key not in properties for key in value):
            raise ToolValidationError(f"Unexpected field at {path}")
        for key, child_schema in properties.items():
            if key in value:
                if not isinstance(child_schema, Mapping):
                    raise ToolValidationError(f"Invalid property schema at {path}")
                _validate_schema(value[key], child_schema, f"{path}.{key}")


def _validate_path(value: Any, roots: tuple[Path, ...], argument_name: str) -> None:
    if not isinstance(value, (str, Path)):
        raise ToolValidationError(f"Filesystem argument {argument_name} must be a path")
    if not roots:
        raise ToolValidationError(f"Filesystem argument {argument_name} has no allowed roots")
    candidate = Path(value).expanduser().resolve(strict=False)
    for root in roots:
        resolved_root = Path(root).expanduser().resolve(strict=True)
        try:
            candidate.relative_to(resolved_root)
            return
        except ValueError:
            continue
    raise ToolValidationError(f"Filesystem argument {argument_name} is outside allowed roots")


def _host_is_allowed(host_value: str, allowed_hosts: tuple[str, ...]) -> bool:
    parsed = urlsplit(host_value if "://" in host_value else f"//{host_value}")
    hostname = parsed.hostname
    if not hostname or parsed.username is not None or parsed.password is not None:
        return False
    hostname = hostname.rstrip(".").lower()
    try:
        hostname = ipaddress.ip_address(hostname).compressed
    except ValueError:
        pass
    return any(hostname == allowed.rstrip(".").lower() for allowed in allowed_hosts)
