# Pending Architecture

This document lists work that is planned or under investigation. None of these items should be described as implemented in v0.1 until code and tests demonstrate it.

## Framework adapters

- Custom-agent helpers that convert framework-neutral requests to ToolCall.
- LangChain tool wrapper.
- LlamaIndex tool wrapper.
- MCP tool adapter with real server capability discovery and transport handling.

Each adapter must call the same core interceptor and must not duplicate policy decisions.

## Runtime expansion

- The earlier roadmap also proposed finite-state authorization, invariant verification, and Linux system-call sandboxing. These remain future exploration: v0.1 has no FSM supervisor, formal invariants, or OS-level isolation. If a syscall sandbox is pursued, treat it as a separate platform-specific containment layer rather than a property of the Python interceptor.
- Async interception without a second authorization implementation.
- Safer filesystem access APIs that mitigate time-of-check/time-of-use races.
- Network controls that cover resolved addresses, ports, redirects, and socket behavior rather than a declared hostname only.
- Audit sinks with process coordination, rotation, retention, remote storage, and tamper-evident integrity.
- Explicit policy composition, policy versioning, and an explainable review workflow.

## Static and assurance work

- Broader source/configuration checks with documented false-positive behavior.
- CI output formats and baseline management.
- Continuous monitoring and production assurance.
- Reproducible live-agent testing with controlled model/provider versions.
- Research whether and how MAST should be integrated; do not claim integration until implemented and evaluated.

## Out of scope for current claims

Agent Shield v0.1 does not provide formal verification, operating-system-level isolation, a process sandbox, a complete JSON Schema validator, a production MCP client, or protection for tool backends that are called outside the interceptor.
