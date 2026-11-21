# Contributor and Agent Guidance

This file describes the boundaries contributors and coding agents should preserve.

## Security contract

- Treat every model-produced tool name and argument as untrusted.
- The host owns tool handlers, tool registration, identity, and permissions.
- Only deterministic policy code creates an allow decision.
- Route protected tool execution through ToolCallInterceptor. A separate direct call is outside the guarantee.
- Unknown tools, invalid arguments, missing permissions, policy failures, and pre-execution audit failures must not invoke a handler.
- Never place raw tool arguments or secret values in security events by default.

## Architecture boundaries

- Keep src/agent_shield independent of agent frameworks and network SDKs.
- Keep detection, authorization, and execution separate. A detector may report a finding; it cannot grant authority.
- Put framework translation in adapters after the core contract is stable.
- Update public types, tests, and documentation together when changing a security boundary.
- Preserve useful assessment inputs and move them into the package area that owns the capability.
- Remove disconnected demos, hard-coded mocks, and unused dependencies when their references and value have been checked.

## Implementation constraints

- The argument validator supports only the documented subset. Do not imply complete JSON Schema support.
- Filesystem path resolution is not an OS sandbox and does not eliminate time-of-check/time-of-use races.
- A network hostname check does not control DNS, sockets, ports, redirects, or behavior hidden inside handlers.
- Static findings are indicators, not proof that a program is safe or unsafe.
- Benchmark external services must remain mocked. Use temporary directories and synthetic credentials.

## Before merging

Run the standard-library suite from the repository root after installing the editable package:

    python -m pip install -e .
    python -m unittest discover -s tests -v

For changes to benchmark scenarios or metrics, also run:

    python -m benchmarks.run --iterations 500

Report skipped tests and benchmark environment. Do not replace measured values with estimates.
