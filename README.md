# Agent Shield

Agent Shield is a Python library for deterministic authorization at AI agent tool boundaries. The agent proposes a tool call; the host-owned policy decides whether it may execute.

## v0.1 status

Implemented in this repository:

- Typed tool-call, authorization-context, decision, event, and error models.
- A synchronous tool-call interceptor with a host-owned tool registry and default-deny allowlist.
- Permission checks, a documented JSON-like argument-schema subset, and numeric/string bounds.
- Filesystem path checks against configured roots and exact hostname allowlists for network tools.
- Fail-closed policy evaluation and pre-execution audit persistence.
- In-memory and local JSON Lines audit sinks.
- Focused configuration, MCP-style permission/scope, tool-definition, and known-token secret checks.
- Reusable adversarial prompt families and heuristic assessment scoring, kept separate from authorization.
- Standard-library automated tests and a deterministic local benchmark comparing direct dispatch with protected dispatch.

Planned, not implemented in v0.1:

- LangChain, LlamaIndex, and MCP adapters; only the framework-independent core exists.
- An async interceptor, remote or tamper-evident audit storage, and multi-process audit coordination.
- Whole-program static analysis, production monitoring, dashboarding, and CI service integration.
- MAST integration, formal verification, or operating-system-level isolation.

Reusable adversarial prompts and heuristic risk-scoring helpers from the old red-team implementation now live in src/agent_shield/assessment/. The useful MCP metadata checks are part of the static scanner. Disconnected Gemini simulations, the hard-coded MCP mock, the broken LangGraph demo, and the stale Kaggle notebook were removed; they were not part of the v0.1 enforcement path.

## Architecture

A model proposal is represented as a ToolCall containing only a tool name, JSON-compatible arguments, and a correlation ID. Host code supplies AuthorizationContext. The PolicyEngine uses the host's ToolDefinition allowlist and permissions to make the decision. The interceptor validates arguments and configured resource boundaries, writes an authorization event, and invokes only the registered host callable after an allow decision.

    model proposal -> validation -> deterministic policy -> pre-execution audit -> registered handler
                                  deny/error ------------------------------> no handler call

The model cannot provide a decision, register a handler, or grant itself permissions. The request ID is for correlation only. A host application that invokes a backend through another route can bypass this library; register and route protected tools through the interceptor.

## Install and run

The security core has no runtime third-party dependencies. From the repository root:

    python -m pip install -e .
    python -m unittest discover -s tests -v

Run the local comparison benchmark:

    python -m benchmarks.run --iterations 500

To save the JSON report:

    python -m benchmarks.run --iterations 500 --output benchmarks/results/latest.json

The benchmark uses fixed scenarios, temporary files, a synthetic secret, and mocked network handlers. It does not call an LLM, contact external services, or issue destructive commands against the host.

## Minimal runtime example

Create the configured document root and choose a location for the audit file before running the example. Replace the sample paths with paths appropriate for the host application.

    from pathlib import Path

    from agent_shield.audit import JsonLinesAuditSink
    from agent_shield.models import AuthorizationContext, ToolCall
    from agent_shield.policy import PolicyEngine, ToolDefinition
    from agent_shield.runtime import ToolCallInterceptor

    def read_document(path: str) -> str:
        return Path(path).read_text(encoding="utf-8")

    policy = PolicyEngine([
        ToolDefinition(
            name="read_document",
            handler=read_document,
            argument_schema={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
                "additionalProperties": False,
            },
            required_permissions=frozenset({"documents:read"}),
            filesystem_roots={"path": (Path("/srv/documents"),)},
        ),
    ])
    shield = ToolCallInterceptor(policy, JsonLinesAuditSink("logs/security.jsonl"))
    result = shield.execute(
        ToolCall("read_document", {"path": "/srv/documents/guide.txt"}),
        AuthorizationContext(
            principal="support-agent",
            permissions=frozenset({"documents:read"}),
        ),
    )

Sensitive tools additionally require sensitive:<tool-name>. Network tools declare network_host_argument and allowed_network_hosts, and require network:connect. Both permission sets must be created by trusted host code.

AuthorizationDenied, ToolValidationError, PolicyEvaluationError, AuditError, and ToolExecutionError are explicit failure types. In particular, an audit write failure before execution raises AuditError and does not invoke the backend. An audit failure while recording the post-execution result cannot undo an already completed side effect; the earlier authorization event remains the precondition record.

## Static checks

The scanner can inspect a configuration mapping, tool definitions, a source string, a file, or a repository. It checks missing/duplicate names, sensitive tools without declared permissions, unsafe network/filesystem declarations, shell-backed declarations, and common credential formats. It redacts matched secret values. It uses known token patterns rather than entropy heuristics and can miss unknown formats or secrets assembled at runtime.

## Benchmark and evaluation

The benchmark catalog includes unauthorized tool invocation, numeric parameter manipulation, path traversal, prompt-injection text leading to an unauthorized proposal, sensitive-file access, unauthorized network destination, missing authorization, and three legitimate operations.

Evaluation definitions are in src/agent_shield/evaluation/benchmark.py. Attack success means a mock backend recorded an effect. Blocking rate is measured over adversarial attempts; false-positive rate and legitimate completion are measured over legitimate attempts. Enforcement latency includes validation, policy, and in-memory audit event recording; p95 uses nearest-rank. Direct-dispatch latency is included only as a baseline reference.

Measured run (2026-11-21 UTC): 500 iterations per scenario, 3,500 adversarial attempts and 1,500 legitimate attempts, Python 3.14.2 on Windows 11 x64. The raw report is benchmarks/results/v0.1-local-run.json.

| Metric | Unprotected direct dispatch | Agent Shield |
|---|---:|---:|
| Attack success rate | 100% (3,500/3,500) | 0% (0/3,500) |
| Blocking rate | Not applicable | 100% (3,500/3,500) |
| False-positive rate | Not measured for the baseline | 0% (0/1,500) |
| Legitimate task completion | 100% (1,500/1,500) | 100% (1,500/1,500) |
| Median dispatch/enforcement latency | 0.006 ms | 0.12275 ms |
| p95 dispatch/enforcement latency | 0.4379 ms | 1.644 ms |
| Policy bypasses | Not applicable | 0 |

These are actual measurements from the local mock suite, not estimates. The small fixed scenario set, temporary files, in-memory audit sink, and mocked network handler do not model production workloads or live-model behavior. Latency varies by machine and load.

### Hard red-team stress suite

Run the separate failure-seeking suite with:

    python -m benchmarks.hard_cases --output benchmarks/results/hard-red-team-run.json

This command exits with status 1 when it reproduces a vulnerability or scope gap. In the recorded run, it found two vulnerabilities and one policy-scope gap:

- **Hard-link filesystem escape — vulnerable:** a file created outside the allowed root was readable through a hard link inside it. Path resolution does not establish file ownership or inode containment.
- **Array item validation — vulnerable:** a tool schema declaring only an array type forwarded nested action data because v0.1 does not validate array items.
- **Alternate network port — scope gap:** the hostname matched, so a URL using port 9443 reached the mock handler. The current rule only compares hostnames.

The same run blocked a hostname lookalike suffix and a Unicode-confusable tool name. The full case-by-case report is benchmarks/results/hard-red-team-run.json. These findings are open hardening work: do not use path-root checks as a boundary against hard-link-capable writers, and do not accept arrays with security-sensitive contents until item validation is implemented.

## Security boundaries and limitations

- Enforcement applies only to calls routed through ToolCallInterceptor and its host-owned registry.
- The v0.1 interceptor is synchronous and in-process. It is not a process sandbox.
- Filesystem paths are resolved and checked against configured roots, including existing symlink targets. A backend can still face filesystem time-of-check/time-of-use races if the file system changes before it opens the path; use safer OS primitives for adversarial concurrent writers.
- Network checks compare a declared hostname argument with an exact allowlist. The stub does not enforce sockets, DNS resolution, IP ranges, ports, redirects, or hidden network behavior inside a handler.
- The local JSONL sink is not tamper-evident and coordinates threads within one process only.
- The secret scanner is pattern-based. The static scanner does not prove whole-program safety.
- The benchmark is deterministic policy coverage with mock handlers, not a live agent red-team or a MAST evaluation.
- The symlink test is skipped when the host cannot create symlinks; report the test result for the environment used.

## Repository map

- src/agent_shield/: framework-independent runtime, schemas, policy, validation, audit, and scanner.
- tests/: standard-library unit and adversarial tests.
- benchmarks/: fixed local benchmark scenarios and runner.
- src/agent_shield/assessment/: reusable adversarial prompt fixtures and advisory scoring.
- src/agent_shield/evaluation/: benchmark metric definitions.
- benchmarks/: fixed local benchmark scenarios, runner, and measured report.
- agents.md, learning.md, pending.architecture.md, research/: contribution guidance, teaching notes, planned architecture, and research topics.

See agents.md for contribution boundaries, learning.md for the design reasoning, and pending.architecture.md for work not included in v0.1.
