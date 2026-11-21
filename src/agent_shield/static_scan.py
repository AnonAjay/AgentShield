"""Focused pre-deployment checks for tool configuration and common secrets."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from .events import SecurityEvent, SecurityEventType


@dataclass(frozen=True, slots=True)
class StaticFinding:
    code: str
    severity: str
    message: str
    source: str
    line: int | None = None

    def to_event(self, *, request_id: str = "static-scan") -> SecurityEvent:
        return SecurityEvent(
            event_type=SecurityEventType.STATIC_FINDING,
            request_id=request_id,
            tool_name=None,
            reason_code=self.code,
            details={
                "severity": self.severity,
                "message": self.message,
                "source": self.source,
                "line": self.line,
            },
        )


_SENSITIVE_TERMS = (
    "delete", "remove", "drop", "shutdown", "reset", "write", "update",
    "modify", "admin", "prod", "production", "secret", "credential",
    "shell", "execute", "exec", "command", "network", "http", "fetch",
)
_BROAD_SCOPES = {"all", "read_write", "full", "admin"}

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("generic_api_key_assignment", re.compile(
        r"(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9_./+=-]{20,})"
    )),
)


def scan_text(text: str, *, source: str = "<memory>") -> list[StaticFinding]:
    """Find common hard-coded credential formats; matched values are redacted."""
    findings: list[StaticFinding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for credential_type, pattern in _SECRET_PATTERNS:
            if pattern.search(line):
                findings.append(
                    StaticFinding(
                        code="POSSIBLE_HARDCODED_SECRET",
                        severity="high",
                        message=f"Possible {credential_type} found; value redacted.",
                        source=source,
                        line=line_number,
                    )
                )
    return findings


def scan_tool_definitions(
    tools: Iterable[Mapping[str, Any]],
    *,
    source: str = "tool configuration",
) -> list[StaticFinding]:
    """Check a list of declared tools for weak or missing boundaries."""
    findings: list[StaticFinding] = []
    seen: set[str] = set()
    for index, tool in enumerate(tools):
        location = f"{source}[{index}]"
        if not isinstance(tool, Mapping):
            findings.append(StaticFinding(
                "INVALID_TOOL_DEFINITION", "high", "Tool definition must be an object.", location
            ))
            continue
        name = tool.get("name")
        if not isinstance(name, str) or not name.strip():
            findings.append(StaticFinding(
                "MISSING_TOOL_NAME", "high", "Tool definition has no valid name.", location
            ))
            name = ""
        elif name in seen:
            findings.append(StaticFinding(
                "DUPLICATE_TOOL_NAME", "high", f"Tool name {name!r} is duplicated.", location
            ))
        seen.add(name)

        searchable = f"{name} {tool.get('description', '')}".lower()
        sensitive = bool(tool.get("sensitive")) or any(term in searchable for term in _SENSITIVE_TERMS)
        permissions = tool.get("required_permissions", ())
        if sensitive and not permissions:
            findings.append(StaticFinding(
                "SENSITIVE_TOOL_WITHOUT_PERMISSION",
                "high",
                f"Sensitive tool {name or '<unnamed>'!r} declares no required permissions.",
                location,
            ))

        if tool.get("requires_auth") is False:
            findings.append(StaticFinding(
                "SENSITIVE_TOOL_WITHOUT_AUTH" if sensitive else "TOOL_WITHOUT_AUTH",
                "critical" if sensitive else "medium",
                (
                    f"Sensitive tool {name or '<unnamed>'!r} declares no authentication."
                    if sensitive
                    else f"Tool {name or '<unnamed>'!r} declares no authentication; verify this is intentional."
                ),
                location,
            ))

        scope = tool.get("scope")
        if isinstance(scope, str) and scope.lower() in _BROAD_SCOPES:
            findings.append(StaticFinding(
                "OVERBROAD_TOOL_SCOPE",
                "high",
                f"Tool {name or '<unnamed>'!r} declares broad scope {scope!r}.",
                location,
            ))

        if tool.get("allowed") is True and sensitive and not permissions:
            findings.append(StaticFinding(
                "LEGACY_SENSITIVE_TOOL_ALLOWED",
                "critical",
                f"Legacy configuration marks sensitive tool {name!r} allowed without a permission boundary.",
                location,
            ))

        host_argument = tool.get("network_host_argument")
        network_declared = bool(tool.get("network")) or host_argument is not None
        if network_declared and not tool.get("allowed_network_hosts"):
            findings.append(StaticFinding(
                "NETWORK_TOOL_WITHOUT_HOST_ALLOWLIST",
                "critical",
                f"Network tool {name or '<unnamed>'!r} has no host allowlist.",
                location,
            ))

        filesystem_roots = tool.get("filesystem_roots")
        if tool.get("filesystem_access") and not filesystem_roots:
            findings.append(StaticFinding(
                "FILESYSTEM_TOOL_WITHOUT_ROOTS",
                "critical",
                f"Filesystem tool {name or '<unnamed>'!r} has no configured path roots.",
                location,
            ))

        if tool.get("shell") or tool.get("uses_shell"):
            findings.append(StaticFinding(
                "SHELL_BACKED_TOOL",
                "high",
                f"Tool {name or '<unnamed>'!r} declares shell execution; review its boundary carefully.",
                location,
            ))
    return findings


def scan_config(config: Any, *, source: str = "configuration") -> list[StaticFinding]:
    """Validate the outer configuration shape and inspect its tool list."""
    if not isinstance(config, Mapping):
        return [StaticFinding(
            "INVALID_CONFIGURATION", "critical", "Configuration must be an object.", source
        )]
    tools = config.get("tools", config.get("tools_config"))
    if not isinstance(tools, (list, tuple)):
        return [StaticFinding(
            "MISSING_TOOLS_LIST", "high", "Configuration must declare a tools list.", source
        )]
    if not tools:
        findings = [StaticFinding(
            "EMPTY_TOOLS_LIST", "low", "Configuration contains no registered tools.", source
        )]
    else:
        findings = []
    findings.extend(scan_tool_definitions(tools, source=f"{source}.tools"))
    return findings


def scan_file(path: str | Path) -> list[StaticFinding]:
    """Scan one UTF-8 source/config file for known credential patterns."""
    file_path = Path(path)
    try:
        text = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return [StaticFinding(
            "FILE_UNREADABLE", "medium", "File could not be read as UTF-8.", str(file_path)
        )]
    return scan_text(text, source=str(file_path))


def scan_repository(
    root: str | Path,
    *,
    extensions: tuple[str, ...] = (".py", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg"),
) -> list[StaticFinding]:
    """Scan tracked-style source/config extensions, skipping secret and VCS dirs."""
    base = Path(root)
    findings: list[StaticFinding] = []
    ignored_dirs = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache"}
    for path in base.rglob("*"):
        if not path.is_file() or any(part in ignored_dirs for part in path.relative_to(base).parts):
            continue
        if path.suffix.lower() not in extensions or path.name.lower().startswith(".env"):
            continue
        findings.extend(scan_file(path))
    return findings
