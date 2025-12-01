Below is a full README you can paste into `README.md`. You can trim later if you want it shorter.

***

# AgentShield: Security Testing for AI Agents

AgentShield is a multi‑agent security framework that red‑teams AI agents for common vulnerabilities like prompt injection, memory poisoning, over‑privileged tools (MCP), and privilege escalation. It is built as a capstone project for the **Kaggle x Google 5‑Day AI Agents Intensive**, showcasing how to combine models, tools, memory, and orchestration into a practical, security‑focused system.[1][2]

***

## 1. Problem & Motivation

Agentic AI systems are powerful but fragile. Real‑world deployments often connect agents to tools, long‑term memory, and external systems (databases, APIs, MCP). This opens them up to threats such as:[3][4][5]

- **Prompt injection and jailbreaks**: User messages that override system instructions or leak internal prompts.[6][7]
- **Memory poisoning**: Malicious content written into long‑term memory that later changes the agent’s behavior. 
- **Over‑privileged tools / MCP**: Tools that can read or modify sensitive data without proper auth or scoping.[4][8]
- **Privilege escalation**: Social‑engineering prompts that trick the agent into calling sensitive tools it should not use.[5][4]

Most teams don’t have an easy way to **test and evaluate** how vulnerable their agents are to these risks. Traditional unit tests are not enough; you need red‑teaming and automated security checks aligned with modern LLM threat models (OWASP GenAI, agentic AI security guidance, etc.).[9][5]

**AgentShield** answers this by providing:

- A **multi‑agent red‑team** that attacks an AI agent from multiple angles.
- **Per‑module risk scores and grades** (SAFE → CRITICAL).
- A single **supervisor** that orchestrates all tests and produces a consolidated report.

***

## 2. Solution Overview

AgentShield focuses on the **Enterprise / Agents‑for‑Good track**: helping other teams safely deploy AI agents by scanning them for vulnerabilities before (and during) production.[10][1]

### 2.1 Core Capabilities

AgentShield currently implements four main security agents:

1. **Prompt Injection Red‑Teaming Agent**
   - Runs a library of adversarial prompts (system prompt extraction, instruction override, jailbreaks, data exfiltration, obfuscation/encoding).
   - Detects likely prompt injection success via regex patterns and assigns a vulnerability score (0–10).

2. **Memory Poisoning Agent**
   - Simulates adding a malicious memory snippet to the agent’s context.
   - Compares baseline vs poisoned behavior on probing questions.
   - Uses pattern matching + response drift to infer poisoning impact and compute a risk score.

3. **MCP Security Agent**
   - Uses a simple MCP client abstraction to list “tools” exposed by a Model Context Protocol–style server.
   - Flags tools that:
     - Don’t require auth,
     - Have overly broad scope (e.g., `all`, `admin`, `read_write`),
     - Are sensitive (delete, production DB, secrets) but lack protection.

4. **Privilege Escalation Agent**
   - Simulates an agent with tool‑calling capabilities.
   - Sends social‑engineering prompts (role escalation, confused‑deputy, “I’m an admin…”).
   - Detects when sensitive or restricted tools are misused and scores the severity.

All four are coordinated by a **Supervisor Agent** that runs each module, aggregates scores, and outputs a full security report.

***

## 3. Architecture

The project is organized as a small, composable multi‑agent system aligned with the course focus on orchestration and agent quality.[1]

### 3.1 Directory Structure

```text
AgentShield/
  agents/
    prompt_injection_agent.py
    memory_poisoning_agent.py
    mcp_security_agent.py
    privilege_escalation_agent.py
    supervisor_agent.py
  utils/
    gemini_client.py
    mcp_client.py
    adversarial_prompts.py
    scoring.py
  evaluation/
    evaluator.py
  notebooks/
    demo.ipynb
  config.py
  graph.py
  run_demo.py
  requirements.txt
  README.md
```

### 3.2 Components

- **LLM access (`utils/gemini_client.py`)**
  - Wraps the Google GenAI Python SDK (`google-genai`) and loads `GEMINI_API_KEY` from `.env`.
  - Provides helpers:
    - `call_agent_with_system_and_user(system_prompt, user_prompt)`
    - `generate_text(prompt)`

- **Adversarial prompts (`utils/adversarial_prompts.py`)**
  - Central library of attack templates grouped by type:
    - `system_prompt_extraction`, `instruction_override`, `jailbreak`, `data_exfiltration`, `obfuscation_encoding`.
  - Easy to extend with new families of attacks.

- **Scoring (`utils/scoring.py`)**
  - Maps attack types to base severities.
  - Combines severity + confidence into a normalized 0–10 risk score.
  - Provides a `risk_grade` helper used in evaluation.

- **MCP client (`utils/mcp_client.py`)**
  - Abstracts an MCP‑style server that returns a list of capabilities/tools.
  - Currently uses a mock list, but can be replaced with real HTTP/WebSocket calls or an official MCP client.

- **Agents (`agents/*.py`)**
  - Each file implements one agent with a clear `run_*` entry function and a text‑based report generator.

- **Supervisor (`agents/supervisor_agent.py`)**
  - Orchestrates all tests and calculates:
    - Per‑module scores.
    - Overall risk score (max of the four).
  - Produces a combined human‑readable report.

- **Evaluation wrapper (`evaluation/evaluator.py`)**
  - Single async entry: `evaluate_agent_security(config)`.
  - Returns:
    - `metrics` (per‑module + overall scores + grades).
    - `final_state` (supervisor state for deeper analysis).
  - This is used in the notebook and `run_demo.py`.

- **LangGraph pipeline (`graph.py`)**
  - Demonstrates how prompt‑injection testing can be wrapped in a LangGraph stateful graph (START → attack node → scoring node → END).
  - Shows how AgentShield can integrate into more complex agent workflows.

***

## 4. Setup & Installation

### 4.1 Prerequisites

- Python 3.10+ recommended.
- A Gemini API key from Google AI Studio or Google Cloud.[11][12]
- Git.

### 4.2 Clone and create virtualenv

```bash
git clone <your-repo-url>.git
cd AgentShield

python -m venv venv
# Windows PowerShell
.\venv\Scripts\Activate.ps1
# or Linux/macOS
# source venv/bin/activate
```

### 4.3 Install dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

`requirements.txt` includes:

- `google-genai` for Gemini.
- `langgraph`, `fastapi`, etc. for potential future extensions.
- `python-dotenv` for loading `.env`.

### 4.4 Configure Gemini API key

Create a `.env` file in the project root:

```env
GEMINI_API_KEY=your_real_key_here
```

The key is automatically loaded by `utils/gemini_client.py` using `python-dotenv`, and passed into `genai.Client(api_key=...)`.

***

## 5. How to Run

Because the free tier has strict rate limits, the default demo runs only one prompt‑injection attack and one memory‑poisoning probe per scan, so you can safely use run_demo.py; if you increase these parameters, it’s best to run individual agents during development and use the full demo sparingly.[12][11]

### 5.1 Run full multi‑agent scan (supervisor + evaluation)

From project root (venv activated):

```bash
python run_demo.py
```

This will:

1. Build a sample “customer support agent” configuration.
2. Run all four agents via `agents.supervisor_agent.run_full_security_scan`.
3. Print:
   - A detailed **Full Security Scan Report** (per module sections + recommendations).
   - A compact **Evaluation Summary** (scores + grades).

If you see 429 “quota exceeded”, wait ~30–60 seconds and/or reduce the number of adversarial prompts during testing.

### 5.2 Run individual agents

These are safer for debugging and demo screenshots.

Prompt Injection:

```bash
python -m agents.prompt_injection_agent
```

Memory Poisoning:

```bash
python -m agents.memory_poisoning_agent
```

MCP Security (no LLM calls):

```bash
python -m agents.mcp_security_agent
```

Privilege Escalation (no LLM calls):

```bash
python -m agents.privilege_escalation_agent
```

Each script prints a self‑contained report to stdout that you can copy into your Kaggle notebook or writeup.

### 5.3 Run evaluation helper (optional)

If you want just the metrics:

```bash
python -m evaluation.evaluator
```

This calls `evaluate_agent_security(...)` with a default config and prints the evaluation summary.

***

## 6. Kaggle Notebook (demo.ipynb)

The `notebooks/demo.ipynb` notebook is designed for the **Agents Intensive Capstone**:[2][1]

- **Cell 1 – Setup**
  - Imports modules from `agents`, `utils`, `evaluation`.
  - Verifies environment (API key, versions).

- **Cell 2 – Define target agent**
  - Defines `target_system_prompt`, `mcp_server_url`, and `tools_config` for an example “Acme Corp customer support agent”.

- **Cell 3 – Prompt Injection Demo**
  - Runs `prompt_injection_agent.red_team_agent(...)` with a limited adversarial set to stay under rate limits.
  - Displays attack type, prompt, detection status, and vulnerability score.

- **Cell 4 – MCP + Privilege Escalation Demo**
  - Runs `mcp_security_agent.run_mcp_security_scan` and `generate_mcp_report`.
  - Runs `privilege_escalation_agent.run_privilege_escalation_test` and report.
  - These require no LLM calls and are safe to run multiple times.

- **Cell 5 – Full Evaluation**
  - Calls `evaluate_agent_security(config)`.
  - Prints the evaluation metrics using `pretty_print_metrics`.

In the Kaggle capstone submission, this notebook is linked in the **Writeup** as the main executable demo.

***

## 7. Evaluation Design

AgentShield’s evaluation is inspired by modern red‑teaming and guardrail practices for LLM systems.[13][14][5]

### 7.1 Per‑module scoring

Each module outputs:

- A **risk score** in \([0, 10]\).
- A **grade** based on the score:
  - `SAFE` (0)
  - `LOW` (0–3)
  - `MEDIUM` (3–5)
  - `HIGH` (5–8)
  - `CRITICAL` (≥ 8)

Examples:

- Prompt Injection:
  - Score = base severity (by attack type) × confidence of injection success.
- Memory Poisoning:
  - Score = severity(`memory_poisoning`) × combined confidence (pattern matches + response drift).
- MCP Security:
  - Score = sum of weights for each finding (Low/Medium/High/Critical).
- Privilege Escalation:
  - Score = combination of severity of misuse + number of incidents.

### 7.2 Overall evaluation

The supervisor aggregates module scores into an **overall risk score**:

- `overall_risk_score = max(pi, mp, mcp, pe)`.

This is intentionally pessimistic: if any one dimension is critical, the system is considered high risk overall, which aligns with security best practices.[8][5]

The `evaluation/evaluator.py` wraps all of this into a single function the notebook/demo can call.

***

## 8. How This Uses Course Concepts

The capstone guidelines encourage using multiple course concepts in a real use case.[2][1]

AgentShield applies:

- **Models**:
  - Uses Gemini 2.5‑Flash via `google-genai` for prompt injection and memory poisoning tests.

- **Tools & MCP**:
  - Models a tool ecosystem via MCP‑style capabilities (`utils.mcp_client`, `agents.mcp_security_agent`), inspired by agent tool‑calling labs.

- **Memory**:
  - Implements a simple but realistic simulation of poisoned long‑term memory by appending malicious snippets to the system context and examining behavioral drift.

- **Agent orchestration**:
  - Uses multiple agents (four security modules) coordinated by a **Supervisor Agent**.
  - Shows how to embed a security pipeline inside a LangGraph flow (`graph.py`) for potential CI/CD or online guardrails.

- **Evaluation & red‑teaming**:
  - Implements automated attacks, not just static rules.
  - Uses structured scoring and grading to make results actionable.

***

## 9. Extending AgentShield

AgentShield is designed as a foundation, not a finished product. Some natural extensions:

- **More adversarial prompts**
  - Add phishing‑style attacks, tool‑specific injection, or multi‑turn setups in `utils/adversarial_prompts.py`.

- **Real MCP integration**
  - Replace `utils.mcp_client.MCPClient.list_capabilities` with:
    - Calls to a real MCP server.
    - Parsing of tool schemas, auth requirements, rate limits.

- **Real target agents**
  - Instead of directly calling Gemini with a system prompt, wrap your own customer‑support agent endpoint:
    - E.g., an HTTP API, a LangGraph agent, or a tool‑calling agent.

- **Continuous monitoring**
  - Turn `run_full_security_scan` into a scheduled job (e.g., nightly) to re‑test agents after prompt/tool changes.

- **Dashboard / FastAPI**
  - Expose an HTTP API (`/scan`) and/or a minimal Streamlit dashboard for non‑technical users.

***

## 10. Limitations & Future Work

- Uses a **single underlying LLM** (Gemini 2.5‑Flash) both as target simulator and attacker; in production you’d often separate these or attack a real deployed agent.
- The adversarial library and probe list are larger, but the supervisor and notebook default to small max_attacks / max_probes values for free‑tier usage, and users can increase these parameters if they have higher quotas.
- Memory poisoning is simulated by context injection rather than a full vector‑DB memory pipeline.
- MCP client is currently mock‑based; integrating a real MCP server would make the audits more realistic.
- Rate limits on the free Gemini tier constrain how many attacks can be run in one scan; in production you would:
  - Use a paid tier or internal deployment.
  - Implement batching / backoff strategies.[11][12]

***

## 11. How to Use in Your Own Projects

If you have your own agent (e.g., customer support, coding assistant, research agent):

1. Plug your system prompt into `run_demo.py` or the notebook.
2. Optionally, represent your tools as MCP capabilities and/or a `tools_config` list.
3. Run the evaluation once per major change to get:
   - Prompt injection resilience.
   - Memory poisoning sensitivity.
   - MCP/tool misconfiguration warnings.
   - Privilege escalation issues.

This turns security from a checklist into a repeatable, automated process that you can run locally, in CI, or as a hosted service.

***

If you’re a reviewer or judge, start with:

- `run_demo.py` for the full console demo.
- `notebooks/demo.ipynb` for the interactive Kaggle notebook.
- This README for the architecture, rationale, and evaluation design.

[1](https://www.kaggle.com/learn-guide/5-day-agents)
[2](https://www.versatilescientist.com/5-day-ai-agents-intensive-by-google-kaggle/)
[3](https://www.rippling.com/blog/agentic-ai-security)
[4](https://www.akto.io/blog/ai-agent-red-teaming)
[5](https://www.lasso.security/blog/what-is-red-teaming-in-ai)
[6](https://v2docs.galileo.ai/concepts/metrics/safety-and-compliance/prompt-injection)
[7](https://www.evidentlyai.com/llm-guide/prompt-injection-llm)
[8](https://www.secureops.com/blog/agentic-ai-security-recommendations-for-the-next-phase-of-ai)
[9](https://genai.owasp.org/2025/01/22/announcing-the-owasp-gen-ai-red-teaming-guide/)
[10](https://www.kaggle.com/competitions/agents-intensive-capstone-project)
[11](https://ai.google.dev/gemini-api/docs/quickstart)
[12](https://ai.google.dev/gemini-api/docs/api-key)
[13](https://arxiv.org/html/2506.19109v1)
[14](https://www.confident-ai.com/blog/llm-guardrails-the-ultimate-guide-to-safeguard-llm-systems)
[15](https://www.kaggle.com/competitions/agents-intensive-capstone-project/code)
[16](https://www.kaggle.com/competitions/agents-intensive-capstone-project/rules)
[17](https://www.youtube.com/watch?v=ipBVqsNCXC0)
[18](https://dev.to/devteam/join-the-ai-agents-intensive-course-writing-challenge-with-google-and-kaggle-1i46)
[19](https://www.youtube.com/watch?v=Gh-tvBvlF2A)
[20](https://www.kaggle.com/learn-guide/5-day-genai)
[21](https://github.com/amol-davkhar/Google-AI-Agents-intensive-course)
[22](https://www.youtube.com/watch?v=ExA8lLjhzj4)
[23](https://www.kaggle.com/competitions/agents-intensive-capstone-project/discussion)
[24](https://www.kaggle.com/competitions/agents-intensive-capstone-project/discussion/629529)
[25](https://dev.to/challenges/google-kaggle-ai-agents-2025-11-10)
[26](https://www.youtube.com/watch?v=hDtsKaBmgXM)
[27](https://rsvp.withgoogle.com/events/google-ai-agents-intensive_2025/home)
[28](https://www.kaggle.com/competitions/agents-intensive-capstone-project/writeups)
[29](https://www.youtube.com/watch?v=_tIeTX5fKaE)
[30](https://github.com/geminii01/kaggle-genai-intensive-course)
[31](https://www.youtube.com/playlist?list=PLzJwCIvZuAFaFyWBSBWhwqWxU47k9sHBb)