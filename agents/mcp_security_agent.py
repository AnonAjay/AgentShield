from typing import Dict, Any, List
from utils.mcp_client import MCPClient
State = Dict[str, Any]

# =========================
# SECURITY CHECKS
# =========================

SENSITIVE_KEYWORDS = [
    "delete", "remove", "drop", "shutdown", "reset", "write",
    "update", "modify", "admin", "prod", "production", "secret", "key",
]

def audit_capability(cap: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Given a single MCP capability/tool, returns a list of security findings.
    Each finding is a dict with:
      - severity ("Low", "Medium", "High", "Critical")
      - message
    """
    findings: List[Dict[str, Any]] = []

    name = cap.get("name", "").lower()
    desc = cap.get("description", "").lower()
    requires_auth = cap.get("requires_auth", False)
    scope = cap.get("scope", "unknown").lower()

    # 1) No auth required
    if not requires_auth:
        findings.append({
            "severity": "High",
            "message": f"Tool '{cap.get('name')}' does not require authentication.",
        })

    # 2) Overly broad scope
    if scope in ["all", "read_write", "full", "admin"]:
        findings.append({
            "severity": "High",
            "message": f"Tool '{cap.get('name')}' has overly broad scope: '{scope}'.",
        })

    # 3) Sensitive operations unprotected
    is_sensitive = any(k in name or k in desc for k in SENSITIVE_KEYWORDS)
    if is_sensitive and not requires_auth:
        findings.append({
            "severity": "Critical",
            "message": (
                f"Sensitive tool '{cap.get('name')}' appears unprotected "
                f"(no auth) and may allow destructive or confidential operations."
            ),
        })

    return findings

def compute_risk_score(all_findings: List[Dict[str, Any]]) -> float:
    """
    Compute a simple risk score (0‑10) based on findings.
    """
    severity_weights = {
        "Low": 1,
        "Medium": 3,
        "High": 7,
        "Critical": 10,
    }

    total = 0
    for f in all_findings:
        sev = f.get("severity", "Low")
        total += severity_weights.get(sev, 1)

    if not all_findings:
        return 0.0

    return float(min(10.0, total))

# =========================
# CORE AGENT FUNCTION
# =========================

async def run_mcp_security_scan(state: State) -> State:
    """
    Runs a security audit against an MCP server (simulated for now).
    state expects:
      - mcp_server_url: str

    It sets:
      - mcp_capabilities: list of tools/capabilities
      - mcp_findings: list of finding dicts
      - mcp_risk_score: float 0‑10
    """
    server_url = state["mcp_server_url"]

    # 1) Connect to MCP
    client = MCPClient(server_url)

    # 2) List capabilities/tools exposed by MCP server
    capabilities = client.list_capabilities()
    state["mcp_capabilities"] = capabilities

    # 3) Run security checks on each capability
    all_findings: List[Dict[str, Any]] = []
    for cap in capabilities:
        cap_findings = audit_capability(cap)
        for f in cap_findings:
            # Attach tool name for context
            f_with_tool = {
                **f,
                "tool": cap.get("name"),
            }
            all_findings.append(f_with_tool)

    state["mcp_findings"] = all_findings

    # 4) Compute overall risk score
    risk_score = compute_risk_score(all_findings)
    state["mcp_risk_score"] = risk_score

    return state

# =========================
# REPORT GENERATION
# =========================

def generate_mcp_report(state: State) -> str:
    """
    Builds a simple text report from the MCP security scan state.
    """
    findings: List[Dict[str, Any]] = state.get("mcp_findings", []) or []
    risk_score: float = state.get("mcp_risk_score", 0.0)
    server_url: str = state.get("mcp_server_url", "unknown")

    lines: List[str] = []
    lines.append("=== AgentShield: MCP Security Audit Report ===\n")
    lines.append(f"Target MCP Server: {server_url}")
    lines.append(f"Overall MCP Risk Score (0‑10): {risk_score:.2f}\n")

    if not findings:
        lines.append("No security findings detected. (This may be a simulation or minimal config.)")
        return "\n".join(lines)

    lines.append("Findings:")
    for i, f in enumerate(findings, start=1):
        lines.append(f"  {i}. Tool: {f.get('tool')}")
        lines.append(f"     Severity: {f.get('severity')}")
        lines.append(f"     Message: {f.get('message')}")
        lines.append("")

    return "\n".join(lines)

# =========================
# CLI DEMO ENTRYPOINT
# =========================

if __name__ == "__main__":
    import asyncio

    async def main():
        # Example MCP server URL (simulated)
        mcp_url = "https://example-mcp-server.internal"

        # Initial state for the scan
        state: State = {
            "mcp_server_url": mcp_url,
            "mcp_capabilities": [],
            "mcp_findings": [],
            "mcp_risk_score": 0.0,
        }

        # Run the MCP security scan
        final_state = await run_mcp_security_scan(state)

        # Generate and print report
        report = generate_mcp_report(final_state)
        print(report)

    asyncio.run(main())
