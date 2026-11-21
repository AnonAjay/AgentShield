from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any
import json

from agent_shield.audit import JsonLinesAuditSink, MemoryAuditSink
from agent_shield.errors import (
    AuditError,
    AuthorizationDenied,
    PolicyEvaluationError,
)
from agent_shield.models import AuthorizationContext, ToolCall
from agent_shield.models import DecisionEffect, SecurityDecision
from agent_shield.policy import PolicyEngine, ToolDefinition
from agent_shield.runtime import ToolCallInterceptor


class RuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.sink = MemoryAuditSink()
        definition = ToolDefinition(
            name="read_note",
            handler=lambda **kwargs: self._record(**kwargs),
            argument_schema={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
                "additionalProperties": False,
            },
            required_permissions=frozenset({"notes:read"}),
        )
        self.policy = PolicyEngine([definition])
        self.interceptor = ToolCallInterceptor(self.policy, self.sink)

    def _record(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        return kwargs

    def test_authorized_call_runs_and_is_audited(self) -> None:
        result = self.interceptor.execute(
            ToolCall("read_note", {"path": "notes/today.txt"}),
            AuthorizationContext(principal="alice", permissions=frozenset({"notes:read"})),
        )
        self.assertEqual(result, {"path": "notes/today.txt"})
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.sink.events[1].event_type.value, "request_authorized")
        self.assertEqual(self.sink.events[-1].event_type.value, "tool_executed")

    def test_unknown_tool_is_denied_without_execution(self) -> None:
        with self.assertRaises(AuthorizationDenied):
            self.interceptor.execute(ToolCall("delete_everything", {}))
        self.assertEqual(self.calls, [])

    def test_missing_permission_is_denied_without_execution(self) -> None:
        with self.assertRaises(AuthorizationDenied):
            self.interceptor.execute(ToolCall("read_note", {"path": "x"}))
        self.assertEqual(self.calls, [])

    def test_invalid_or_extra_arguments_are_denied(self) -> None:
        with self.assertRaises(AuthorizationDenied):
            self.interceptor.execute(
                ToolCall("read_note", {"path": "x", "admin": True}),
                AuthorizationContext(permissions=frozenset({"notes:read"})),
            )
        self.assertEqual(self.calls, [])

    def test_path_traversal_is_denied(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "safe"
            root.mkdir()
            policy = PolicyEngine(
                [
                    ToolDefinition(
                        name="read_file",
                        handler=self._record,
                        argument_schema={
                            "type": "object",
                            "properties": {"path": {"type": "string"}},
                            "required": ["path"],
                            "additionalProperties": False,
                        },
                        filesystem_roots={"path": (root,)},
                    )
                ]
            )
            interceptor = ToolCallInterceptor(policy, self.sink)
            with self.assertRaises(AuthorizationDenied):
                interceptor.execute(
                    ToolCall("read_file", {"path": str(root / ".." / "outside.txt")})
                )
            self.assertEqual(self.calls, [])

    def test_symlink_escape_is_denied(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "safe"
            root.mkdir()
            outside = base / "outside"
            outside.mkdir()
            link = root / "shortcut"
            try:
                link.symlink_to(outside, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation is not available on this platform")
            policy = PolicyEngine(
                [
                    ToolDefinition(
                        name="read_file",
                        handler=self._record,
                        argument_schema={"type": "object"},
                        filesystem_roots={"path": (root,)},
                    )
                ]
            )
            interceptor = ToolCallInterceptor(policy, self.sink)
            with self.assertRaises(AuthorizationDenied):
                interceptor.execute(ToolCall("read_file", {"path": str(link / "secret.txt")}))
            self.assertEqual(self.calls, [])

    def test_network_tool_requires_permission_and_allowed_host(self) -> None:
        policy = PolicyEngine(
            [
                ToolDefinition(
                    name="fetch_stub",
                    handler=self._record,
                    argument_schema={
                        "type": "object",
                        "properties": {"host": {"type": "string"}},
                        "required": ["host"],
                        "additionalProperties": False,
                    },
                    network_host_argument="host",
                    allowed_network_hosts=("api.example.test",),
                )
            ]
        )
        interceptor = ToolCallInterceptor(policy, self.sink)
        with self.assertRaises(AuthorizationDenied):
            interceptor.execute(ToolCall("fetch_stub", {"host": "api.example.test"}))
        with self.assertRaises(AuthorizationDenied):
            interceptor.execute(
                ToolCall("fetch_stub", {"host": "attacker.example.test"}),
                AuthorizationContext(permissions=frozenset({"network:connect"})),
            )
        self.assertEqual(self.calls, [])

    def test_sensitive_tool_requires_explicit_permission(self) -> None:
        policy = PolicyEngine(
            [
                ToolDefinition(
                    name="read_secret",
                    handler=self._record,
                    sensitive=True,
                )
            ]
        )
        interceptor = ToolCallInterceptor(policy, self.sink)
        with self.assertRaises(AuthorizationDenied):
            interceptor.execute(ToolCall("read_secret", {}))
        self.assertEqual(self.calls, [])

    def test_numeric_argument_limits_block_parameter_manipulation(self) -> None:
        policy = PolicyEngine(
            [
                ToolDefinition(
                    name="transfer",
                    handler=self._record,
                    argument_schema={
                        "type": "object",
                        "properties": {
                            "amount": {"type": "integer", "minimum": 1, "maximum": 100}
                        },
                        "required": ["amount"],
                        "additionalProperties": False,
                    },
                    required_permissions=frozenset({"payments:send"}),
                )
            ]
        )
        interceptor = ToolCallInterceptor(policy, self.sink)
        with self.assertRaises(AuthorizationDenied):
            interceptor.execute(
                ToolCall("transfer", {"amount": 10000}),
                AuthorizationContext(permissions=frozenset({"payments:send"})),
            )
        self.assertEqual(self.calls, [])

    def test_tool_call_copies_nested_model_arguments(self) -> None:
        nested = {"payload": {"items": ["safe"]}}
        call = ToolCall("capture", nested)
        nested["payload"]["items"][0] = "changed-after-request"
        self.assertEqual(call.arguments["payload"]["items"][0], "safe")

    def test_jsonl_audit_writes_structured_event_without_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            sink = JsonLinesAuditSink(path)
            self.interceptor = ToolCallInterceptor(self.policy, sink)
            private_path = "private-synthetic-secret-path.txt"
            self.interceptor.execute(
                ToolCall("read_note", {"path": private_path}),
                AuthorizationContext(permissions=frozenset({"notes:read"})),
            )
            event_lines = path.read_text(encoding="utf-8").splitlines()
            events = [json.loads(line) for line in event_lines]
            self.assertEqual(events[0]["event_type"], "request_received")
            self.assertEqual(events[-1]["event_type"], "tool_executed")
            self.assertNotIn(private_path, path.read_text(encoding="utf-8"))

    def test_unsupported_schema_keyword_is_denied(self) -> None:
        policy = PolicyEngine(
            [
                ToolDefinition(
                    name="pattern_tool",
                    handler=self._record,
                    argument_schema={
                        "type": "object",
                        "properties": {"value": {"type": "string", "pattern": "^safe"}},
                    },
                )
            ]
        )
        interceptor = ToolCallInterceptor(policy, self.sink)
        with self.assertRaises(AuthorizationDenied):
            interceptor.execute(ToolCall("pattern_tool", {"value": "safe"}))
        self.assertEqual(self.calls, [])

    def test_filesystem_argument_must_be_schema_required(self) -> None:
        with self.assertRaises(ValueError):
            ToolDefinition(
                name="unsafe_default_path",
                handler=self._record,
                argument_schema={
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                },
                filesystem_roots={"path": (Path("/tmp"),)},
            )

    def test_additional_arguments_are_denied_by_default(self) -> None:
        policy = PolicyEngine(
            [
                ToolDefinition(
                    name="strict_by_default",
                    handler=self._record,
                    argument_schema={"type": "object", "properties": {"value": {"type": "string"}}},
                )
            ]
        )
        interceptor = ToolCallInterceptor(policy, self.sink)
        with self.assertRaises(AuthorizationDenied):
            interceptor.execute(ToolCall("strict_by_default", {"value": "ok", "admin": True}))
        self.assertEqual(self.calls, [])

    def test_audit_failure_blocks_before_backend_execution(self) -> None:
        class FailingSink:
            def emit(self, event: object) -> None:
                raise OSError("disk unavailable")

        interceptor = ToolCallInterceptor(self.policy, FailingSink())
        with self.assertRaises(AuditError):
            interceptor.execute(
                ToolCall("read_note", {"path": "x"}),
                AuthorizationContext(permissions=frozenset({"notes:read"})),
            )
        self.assertEqual(self.calls, [])

    def test_policy_failure_blocks_before_backend_execution(self) -> None:
        class FailingPolicy(PolicyEngine):
            def evaluate(self, call: ToolCall, context: AuthorizationContext) -> object:
                raise RuntimeError("policy unavailable")

        interceptor = ToolCallInterceptor(FailingPolicy(self.policy._tools.values()), self.sink)
        with self.assertRaises(PolicyEvaluationError):
            interceptor.execute(
                ToolCall("read_note", {"path": "x"}),
                AuthorizationContext(permissions=frozenset({"notes:read"})),
            )
        self.assertEqual(self.calls, [])

    def test_mismatched_policy_decision_fails_closed(self) -> None:
        class MismatchedPolicy(PolicyEngine):
            def evaluate(self, call: ToolCall, context: AuthorizationContext) -> SecurityDecision:
                return SecurityDecision(
                    effect=DecisionEffect.ALLOW,
                    tool_name="different_tool",
                    request_id=call.request_id,
                    reason_code="AUTHORIZED",
                    message="incorrectly mismatched",
                    policy_id=self.policy_id,
                )

        interceptor = ToolCallInterceptor(MismatchedPolicy(self.policy._tools.values()), self.sink)
        with self.assertRaises(PolicyEvaluationError):
            interceptor.execute(
                ToolCall("read_note", {"path": "x"}),
                AuthorizationContext(permissions=frozenset({"notes:read"})),
            )
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
