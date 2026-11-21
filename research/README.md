# Research Notes

Research work should record the question, source and version/date, applicability to this repository, assumptions, and what evidence would change the design. A reference is not evidence that Agent Shield implements the referenced control.

## Topics to investigate

- Threat models for tool-using and agentic systems, including prompt injection and confused-deputy behavior.
- MCP security model, authentication, capability discovery, and transport trust boundaries.
- Filesystem race-resistant access patterns on supported operating systems.
- Safe outbound network controls, DNS rebinding, redirects, and IP-range policy.
- Audit integrity, event schemas, retention, and privacy-preserving redaction.
- Reproducible agent evaluation and benchmark design, including whether a MAST mapping is useful.

## Research record template

For each investigation, add a dated note containing:

1. The engineering question.
2. Primary sources and exact versions reviewed.
3. Claims supported by each source.
4. Relevance and limitations for Agent Shield.
5. A proposed experiment or implementation change.
6. The tests and measurements needed before updating product claims.

## Current status

No MAST mapping or formal verification has been implemented or evaluated. The local benchmark in benchmarks/ is a deterministic mock-based comparison, not a research-grade claim about live agents.
