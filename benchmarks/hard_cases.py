"""Hard red-team probes for known gaps and boundary assumptions.

This runner intentionally exits nonzero when it reproduces a vulnerability or scope gap.
All handlers are local stubs; file operations use a temporary directory.

Run from the repository root:
    python -m benchmarks.hard_cases
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent_shield.audit import MemoryAuditSink
from agent_shield.errors import AgentShieldError
from agent_shield.models import AuthorizationContext, ToolCall
from agent_shield.policy import PolicyEngine, ToolDefinition
from agent_shield.runtime import ToolCallInterceptor


def _result(case_id: str, status: str, message: str) -> dict[str, str]:
    return {"id": case_id, "status": status, "message": message}


def run_hard_cases() -> dict[str, Any]:
    results: list[dict[str, str]] = []
    permission = AuthorizationContext(
        principal="red-team-probe",
        permissions=frozenset({"documents:read", "network:connect"}),
    )

    with tempfile.TemporaryDirectory(prefix="agent-shield-hard-") as temporary:
        root = Path(temporary)
        allowed_root = root / "allowed"
        allowed_root.mkdir()
        protected_file = root / "protected-synthetic.txt"
        synthetic_secret = "SYNTHETIC_HARDLINK_SECRET_14b9"
        protected_file.write_text(synthetic_secret, encoding="utf-8")
        alias_path = allowed_root / "alias.txt"

        try:
            os.link(protected_file, alias_path)
        except (OSError, NotImplementedError) as exc:
            results.append(_result(
                "hardlink-filesystem-escape",
                "SKIPPED",
                f"Hard links unavailable on this filesystem ({type(exc).__name__}).",
            ))
        else:
            read_policy = PolicyEngine([
                ToolDefinition(
                    name="read_file",
                    handler=lambda path: Path(path).read_text(encoding="utf-8"),
                    argument_schema={
                        "type": "object",
                        "properties": {"path": {"type": "string"}},
                        "required": ["path"],
                        "additionalProperties": False,
                    },
                    required_permissions=frozenset({"documents:read"}),
                    filesystem_roots={"path": (allowed_root,)},
                )
            ])
            read_shield = ToolCallInterceptor(read_policy, MemoryAuditSink())
            try:
                data = read_shield.execute(
                    ToolCall("read_file", {"path": str(alias_path)}),
                    permission,
                )
            except AgentShieldError:
                data = None
            if data == synthetic_secret:
                results.append(_result(
                    "hardlink-filesystem-escape",
                    "VULNERABLE",
                    "An allowed-root hard link exposed a file created outside the root.",
                ))
            else:
                results.append(_result(
                    "hardlink-filesystem-escape",
                    "BLOCKED",
                    "The interceptor did not return the protected file contents.",
                ))

        array_effects: list[int] = []
        array_policy = PolicyEngine([
            ToolDefinition(
                name="submit_operations",
                handler=lambda operations: array_effects.append(len(operations)) or "accepted",
                argument_schema={
                    "type": "object",
                    "properties": {"operations": {"type": "array"}},
                    "required": ["operations"],
                    "additionalProperties": False,
                },
            )
        ])
        array_shield = ToolCallInterceptor(array_policy, MemoryAuditSink())
        nested_payload = [{"action": "delete", "target": "synthetic-record"}]
        try:
            array_shield.execute(
                ToolCall("submit_operations", {"operations": nested_payload}),
                AuthorizationContext(principal="red-team-probe"),
            )
        except AgentShieldError:
            pass
        if array_effects:
            results.append(_result(
                "unvalidated-array-items",
                "VULNERABLE",
                "An array without an item schema forwarded nested action data to its handler.",
            ))
        else:
            results.append(_result(
                "unvalidated-array-items",
                "BLOCKED",
                "The interceptor rejected array data without an item schema.",
            ))

        contacted: list[str] = []
        network_policy = PolicyEngine([
            ToolDefinition(
                name="fetch_stub",
                handler=lambda host: contacted.append(host) or "mock response",
                argument_schema={
                    "type": "object",
                    "properties": {"host": {"type": "string"}},
                    "required": ["host"],
                    "additionalProperties": False,
                },
                network_host_argument="host",
                allowed_network_hosts=("api.example.test",),
            )
        ])
        network_shield = ToolCallInterceptor(network_policy, MemoryAuditSink())
        alternate_authority = "https://api.example.test:9443/path"
        try:
            network_shield.execute(
                ToolCall("fetch_stub", {"host": alternate_authority}),
                permission,
            )
        except AgentShieldError:
            pass
        if contacted:
            results.append(_result(
                "allowlisted-host-unapproved-port",
                "SCOPE_GAP",
                "The hostname matched, so the stub accepted an authority with port 9443; no network request was sent.",
            ))
        else:
            results.append(_result(
                "allowlisted-host-unapproved-port",
                "BLOCKED",
                "The interceptor rejected an alternate port or URL authority.",
            ))

        blocked: list[str] = []
        controls = [
            (
                "network-lookalike-suffix",
                "api.example.test.attacker.invalid",
                ToolDefinition(
                    name="host_check",
                    handler=lambda host: blocked.append(host) or "called",
                    argument_schema={
                        "type": "object",
                        "properties": {"host": {"type": "string"}},
                        "required": ["host"],
                        "additionalProperties": False,
                    },
                    network_host_argument="host",
                    allowed_network_hosts=("api.example.test",),
                ),
            ),
        ]
        for case_id, host, definition in controls:
            shield = ToolCallInterceptor(PolicyEngine([definition]), MemoryAuditSink())
            try:
                shield.execute(ToolCall(definition.name, {"host": host}), permission)
            except AgentShieldError:
                results.append(_result(case_id, "BLOCKED", "Exact hostname check rejected the lookalike."))
            else:
                results.append(_result(case_id, "VULNERABLE", "Lookalike hostname reached the handler."))

        unicode_tool_name = "dеlete_record"  # Cyrillic small e, not ASCII e.
        unknown_tool_policy = PolicyEngine([
            ToolDefinition("delete_record", lambda: "should not run")
        ])
        unknown_tool_shield = ToolCallInterceptor(unknown_tool_policy, MemoryAuditSink())
        try:
            unknown_tool_shield.execute(ToolCall(unicode_tool_name, {}))
        except AgentShieldError:
            results.append(_result(
                "unicode-confusable-tool-name",
                "BLOCKED",
                "The visually similar name did not match the registered ASCII tool.",
            ))
        else:
            results.append(_result(
                "unicode-confusable-tool-name",
                "VULNERABLE",
                "Unicode-confusable tool name reached a handler.",
            ))

    vulnerabilities = [item for item in results if item["status"] == "VULNERABLE"]
    scope_gaps = [item for item in results if item["status"] == "SCOPE_GAP"]
    skipped = [item for item in results if item["status"] == "SKIPPED"]
    return {
        "suite": "agent-shield-hard-red-team-v0.1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "vulnerability_count": len(vulnerabilities),
        "scope_gap_count": len(scope_gaps),
        "finding_count": len(vulnerabilities) + len(scope_gaps),
        "skipped_count": len(skipped),
        "cases": results,
        "notes": [
            "VULNERABLE means a mock backend received data that the case expected Shield to stop.",
            "SCOPE_GAP means the current policy contract does not constrain that resource dimension.",
            "The hard-link case uses a synthetic file under TemporaryDirectory.",
            "The network case records arguments in a stub and never contacts a network.",
            "No shell commands or destructive host operations are run.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    report = run_hard_cases()
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if arguments.output:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        with arguments.output.open("w", encoding="utf-8", newline="\n") as stream:
            stream.write(rendered + "\n")
    print(rendered)
    return 1 if report["finding_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
