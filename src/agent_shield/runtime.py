"""Synchronous tool-call interception and fail-closed execution."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .audit import AuditSink
from .errors import (
    AuditError,
    AuthorizationDenied,
    PolicyEvaluationError,
    ToolExecutionError,
    ToolValidationError,
)
from .events import SecurityEvent, SecurityEventType
from .models import AuthorizationContext, DecisionEffect, SecurityDecision, ToolCall
from .policy import Policy
from .validation import validate_arguments


class ToolCallInterceptor:
    """Validates, authorizes, audits, and dispatches protected tool calls."""

    def __init__(self, policy: Policy, audit_sink: AuditSink) -> None:
        self.policy = policy
        self.audit_sink = audit_sink

    def execute(
        self,
        call: ToolCall,
        context: AuthorizationContext | None = None,
    ) -> Any:
        """Execute a registered tool only after every pre-execution check passes."""
        context = context or AuthorizationContext()
        self._emit(
            SecurityEvent(
                event_type=SecurityEventType.REQUEST_RECEIVED,
                request_id=call.request_id,
                tool_name=call.tool_name,
                reason_code="REQUEST_RECEIVED",
                principal=context.principal,
            )
        )

        try:
            definition = self.policy.get_tool(call.tool_name)
        except Exception as exc:
            self._emit(
                SecurityEvent(
                    event_type=SecurityEventType.POLICY_ERROR,
                    request_id=call.request_id,
                    tool_name=call.tool_name,
                    reason_code="TOOL_REGISTRY_FAILED",
                    principal=context.principal,
                    details={"error_type": type(exc).__name__},
                )
            )
            raise PolicyEvaluationError("Tool registry failed; tool call denied") from exc
        if definition is None:
            decision = self._deny(
                call,
                context,
                reason_code="TOOL_NOT_ALLOWLISTED",
                message="Tool is not registered",
            )
            self._emit_decision(decision, context)
            raise AuthorizationDenied(decision)

        try:
            arguments = validate_arguments(
                call.arguments,
                definition.argument_schema,
                filesystem_roots=definition.filesystem_roots,
                network_host_argument=definition.network_host_argument,
                allowed_network_hosts=definition.allowed_network_hosts,
            )
        except (ToolValidationError, OSError, ValueError, TypeError):
            decision = self._deny(
                call,
                context,
                reason_code="ARGUMENT_VALIDATION_FAILED",
                message="Tool arguments or resource boundaries are invalid",
            )
            self._emit_decision(decision, context)
            raise AuthorizationDenied(decision)

        try:
            decision = self.policy.evaluate(call, context)
            if not isinstance(decision, SecurityDecision):
                raise TypeError("policy returned an invalid decision")
            if (
                decision.tool_name != call.tool_name
                or decision.request_id != call.request_id
                or decision.policy_id != self.policy.policy_id
            ):
                raise ValueError("policy returned a decision for a different request")
        except Exception as exc:
            self._emit(
                SecurityEvent(
                    event_type=SecurityEventType.POLICY_ERROR,
                    request_id=call.request_id,
                    tool_name=call.tool_name,
                    reason_code="POLICY_EVALUATION_FAILED",
                    principal=context.principal,
                    details={"error_type": type(exc).__name__},
                )
            )
            raise PolicyEvaluationError("Policy evaluation failed; tool call denied") from exc

        if decision.effect is not DecisionEffect.ALLOW:
            self._emit_decision(decision, context)
            raise AuthorizationDenied(decision)

        self._emit(
            SecurityEvent(
                event_type=SecurityEventType.REQUEST_AUTHORIZED,
                request_id=call.request_id,
                tool_name=call.tool_name,
                reason_code=decision.reason_code,
                policy_id=decision.policy_id,
                principal=context.principal,
            )
        )

        # Only the host-owned registry supplies executable code.
        try:
            result = definition.handler(**_thaw_json(arguments))
        except Exception as exc:
            self._emit(
                SecurityEvent(
                    event_type=SecurityEventType.TOOL_FAILED,
                    request_id=call.request_id,
                    tool_name=call.tool_name,
                    reason_code="TOOL_EXECUTION_FAILED",
                    policy_id=decision.policy_id,
                    principal=context.principal,
                    details={"error_type": type(exc).__name__},
                )
            )
            raise ToolExecutionError("Authorized tool execution failed") from exc

        self._emit(
            SecurityEvent(
                event_type=SecurityEventType.TOOL_EXECUTED,
                request_id=call.request_id,
                tool_name=call.tool_name,
                reason_code="TOOL_EXECUTED",
                policy_id=decision.policy_id,
                principal=context.principal,
            )
        )
        return result

    def _deny(
        self,
        call: ToolCall,
        context: AuthorizationContext,
        *,
        reason_code: str,
        message: str,
    ) -> SecurityDecision:
        policy_id = getattr(self.policy, "policy_id", "unknown-policy")
        return SecurityDecision(
            effect=DecisionEffect.DENY,
            tool_name=call.tool_name,
            request_id=call.request_id,
            reason_code=reason_code,
            message=message,
            policy_id=policy_id,
        )

    def _emit_decision(
        self, decision: SecurityDecision, context: AuthorizationContext
    ) -> None:
        self._emit(
            SecurityEvent(
                event_type=SecurityEventType.REQUEST_DENIED,
                request_id=decision.request_id,
                tool_name=decision.tool_name,
                reason_code=decision.reason_code,
                policy_id=decision.policy_id,
                principal=context.principal,
            )
        )

    def _emit(self, event: SecurityEvent) -> None:
        try:
            self.audit_sink.emit(event)
        except Exception as exc:
            raise AuditError("Audit persistence failed; tool call denied") from exc


def _thaw_json(value: Any) -> Any:
    """Give tools ordinary fresh containers after immutable validation."""
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value
