"""Explicit errors for denial, validation, policy, audit, and tool failures."""

from __future__ import annotations

from .models import SecurityDecision


class AgentShieldError(Exception):
    """Base class for expected Agent Shield failures."""


class AuthorizationDenied(AgentShieldError):
    """Raised when a valid request receives a deny decision."""

    def __init__(self, decision: SecurityDecision) -> None:
        self.decision = decision
        super().__init__(f"{decision.reason_code}: {decision.message}")


class ToolValidationError(AgentShieldError):
    """Raised when tool arguments or resource references are invalid."""


class PolicyEvaluationError(AgentShieldError):
    """Raised when authorization cannot be safely evaluated."""


class AuditError(AgentShieldError):
    """Raised when required audit persistence fails."""


class ToolExecutionError(AgentShieldError):
    """Raised when an authorized tool backend fails."""
