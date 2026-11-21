"""Framework-independent security controls for AI agent tool calls."""

from .errors import (
    AgentShieldError,
    AuditError,
    AuthorizationDenied,
    PolicyEvaluationError,
    ToolExecutionError,
    ToolValidationError,
)
from .assessment import (
    AttackPromptFamily,
    MEMORY_POISONING_PROBE_QUERIES,
    POISONED_MEMORY_SNIPPET,
    PROMPT_FAMILIES,
)
from .events import SecurityEvent, SecurityEventType
from .audit import AuditSink, JsonLinesAuditSink, MemoryAuditSink
from .models import (
    AuthorizationContext,
    DecisionEffect,
    SecurityDecision,
    ToolCall,
)
from .policy import Policy, PolicyEngine, ToolDefinition
from .runtime import ToolCallInterceptor
from .static_scan import StaticFinding, scan_config, scan_file, scan_repository, scan_text, scan_tool_definitions
from .evaluation import BenchmarkScenario, DispatchResult, compare_scenarios

__all__ = [
    "AgentShieldError",
    "AttackPromptFamily",
    "AuditSink",
    "AuditError",
    "AuthorizationContext",
    "AuthorizationDenied",
    "DecisionEffect",
    "BenchmarkScenario",
    "DispatchResult",
    "JsonLinesAuditSink",
    "MemoryAuditSink",
    "MEMORY_POISONING_PROBE_QUERIES",
    "Policy",
    "PolicyEngine",
    "POISONED_MEMORY_SNIPPET",
    "PROMPT_FAMILIES",
    "PolicyEvaluationError",
    "SecurityDecision",
    "SecurityEvent",
    "SecurityEventType",
    "StaticFinding",
    "ToolCall",
    "ToolCallInterceptor",
    "ToolDefinition",
    "ToolExecutionError",
    "ToolValidationError",
    "compare_scenarios",
    "scan_config",
    "scan_file",
    "scan_repository",
    "scan_text",
    "scan_tool_definitions",
]
