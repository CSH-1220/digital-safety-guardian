# Digital Safety Guardian

A privacy-first AI agent that gives in-the-moment guidance for potentially risky online actions. When users face suspicious signups, phishing links, or over-asking app permissions, the Guardian assesses the situation, runs only the relevant deterministic checks, and explains what to do next in plain language.

## Problem

Everyday users face risky moments online—a friend's message with an unusual link, a signup form for a new service, a mobile app requesting unusual permissions. Without expert knowledge or specialized tools, users often:

- Don't know if they should trust a link or domain
- Aren't sure whether an app is asking for too much access
- React slowly or second-guess reasonable precautions
- Need reassurance or confirmation of their instincts

The Guardian solves this by making expert safety checks instant and understandable, right when it matters most.

## Solution

The Guardian is an ADK-based multi-node workflow that:

1. **Accepts a context** — the risky moment as a light context (app/domain, URL, short note), provided by the user or auto-assembled from on-screen activity like signup forms, link clicks, and permission prompts ([roadmap](docs/architecture.md#future-work--production-hardening))
2. **Assesses openly** — an LLM node triages the risk and decides which of six deterministic checks actually apply
3. **Runs selected checks** — only the relevant safety checks run in parallel (domain reputation, email leak, password hygiene, URL phishing signals, app permissions, app reputation)
4. **Synthesizes advice** — a second LLM node turns the findings into plain-language, prioritized guidance
5. **Returns structured advice** — the caller gets a risk level, the ranked checks that fired, and what to do about it

All six safety checks are also published as standard MCP tools via a self-built MCP server, so the same intelligence is reusable by any MCP client.

## Architecture

### Project Structure

```
guardian/
├── workflow.py              # ADK graph wiring (build_app, build_offline_app)
├── contracts.py             # Pydantic schemas (RiskEvent, RiskAssessment, GuardianAdvice)
├── state_keys.py            # Canonical workflow state keys (single source of truth)
├── mcp_server.py            # Self-built MCP server (exposes 6 checks as MCP tools)
├── nodes/
│   ├── intake.py            # Input normalization (text → RiskEvent)
│   ├── assess.py            # LLM node: triage & select checks
│   ├── advisor.py           # LLM node: synthesize findings into advice
│   ├── checks.py            # Wrapper nodes for all 6 checks + collect_findings
│   ├── routing.py           # Deterministic dispatch logic
├── tools/
│   ├── domain_reputation.py # RDAP + local threat list check
│   ├── email_leak.py        # Synthetic breach database lookup
│   ├── password_hygiene.py  # Fixed privacy-preserving advice (no input)
│   ├── url_phishing.py      # Local phishing heuristics
│   ├── permission_risk.py   # Local permission-risk heuristics
│   ├── app_reputation.py    # Synthetic reputation database
├── data/
│   └── threatlist.txt       # Bundled domain threat list (synthetic)
├── breach_db.py             # Synthetic email breach data
└── offline.py               # Offline deterministic fallbacks (for tests)

tests/                        # Full test suite (unit + integration)

pyproject.toml               # Project metadata & dependencies
.env.example                 # Environment template
README.md                    # This file
```

### Graph Overview

![Guardian workflow graph](docs/graph.png)

The production workflow is a single ADK graph called `guardian` with 9 nodes:

- **intake** — normalizes incoming input into a `RiskEvent`
- **assess_risk** — LLM node that triages the risk and selects relevant checks (open-ended, no fixed taxonomy)
- **dispatch** — deterministic router: "concern" → checks; "no_concern" → skip checks
- **6 parallel checks** — domain_reputation, email_leak, password_hygiene, url_phishing, permission_risk, app_reputation
- **checks_complete** — JoinNode that re-converges the six parallel branches
- **collect_findings** — fan-in node that normalizes all check results into a findings list
- **advisor** — LLM node that synthesizes findings + assessment into plain-language advice
- **finalize_advice** — reconciles the advisor's priority_order to the checks that actually ran, returns final `GuardianAdvice`
- **handle_unrelated** — deterministic branch for "no_concern" cases (no checks run)

> 📖 **Deep dive:** [`docs/architecture.md`](docs/architecture.md) covers the node-by-node specifications, the data-flow walkthrough, the LLM prompts, the full data contracts (`RiskEvent` → `RiskAssessment` → `RiskFinding` → `GuardianAdvice`), the privacy & security model, how to add a new check, and the production roadmap.


### The Three Demonstrated Concepts

#### 1. Multi-Node ADK Graph with Open-Ended LLM Triage
The workflow uses two LLM nodes (`assess_risk` and `advisor`), both schema-constrained with Pydantic:

- **assess_risk** (LLM node) — receives a free-text or structured risk event and makes an open-ended judgment about what checks apply. It does NOT use a fixed taxonomy; instead, it evaluates the event and selects from a list of available checks. This demonstrates adaptive LLM reasoning within a structured workflow.
- **advisor** (LLM node) — takes the validated findings and synthesizes them into plain-language advice. A deterministic post-processing step (`finalize_advice`) reconciles the advisor's priority ranking to the checks that actually ran, ensuring consistency.

This architecture separates concern from mechanism: the LLM assesses risk freely, then only the selected checks run.

#### 2. Self-Built MCP Server Exposing All Six Checks
The `guardian/mcp_server.py` is a FastMCP-based server that exposes all six deterministic safety checks as standard MCP tools:

```bash
uv run python -m guardian.mcp_server
```

This server runs on stdin/stdout and makes the same safety intelligence available to any MCP client (e.g., Claude, other agents, third-party tools). The workflow calls the underlying tool functions directly; the MCP server is an additional public surface for reuse.

#### 3. Privacy-by-Design
The system enforces privacy at every boundary:

- **Input contracts** (`guardian/contracts.py`) use Pydantic with `extra="forbid"` to reject any unexpected field, so a password field cannot be injected.
- **Password check** (`guardian/tools/password_hygiene.py`) has a function signature that takes **no input**—it cannot receive a password, by design.
- All demo data is **synthetic only**: breach database is in-memory, threat list is a local file, reputation data is hardcoded.
- **No network access to credentials**: domain reputation uses keyless RDAP; no API keys are passed to checks.

## Setup Instructions

### 1. Prerequisites

- Python 3.12+ (see `pyproject.toml` for `requires-python = ">=3.12,<3.14"`)
- `uv` package manager ([install here](https://docs.astral.sh/uv/))
- A Gemini API key from Google Cloud Console

### 2. Install Dependencies

```bash
uv sync
```

This installs all dependencies from `pyproject.toml`, including:
- `google-adk>=2.0.0` — ADK framework for building the workflow
- `httpx>=0.28.0` — HTTP client for RDAP lookups
- `mcp>=1.0.0` — Model Context Protocol for the MCP server
- `pydantic>=2.0.0` — schema validation
- `pytest>=8.0.0` (dev) — testing

### 3. Configure Environment

Copy `.env.example` to `.env` and add your Gemini API key:

```bash
cp .env.example .env
# Edit .env and set GEMINI_API_KEY to your key (never commit this file)
```

The workflow reads `GEMINI_API_KEY` and `GEMINI_MODEL` (defaults to `gemini-2.5-flash`) from the environment.

### 4. Verify Installation

```bash
uv run python -c "import google.adk, pydantic, httpx, mcp; print('ok')"
```

### 5. Run the Interactive Playground

The ADK playground is the main UI. Start it with:

```bash
adk web
```

This launches a web interface on `http://localhost:8000`. The agent name is `guardian` (from `workflow.py`).

**Note:** If `adk web` is not available, you can also run:

```bash
agents-cli playground
```

Either command starts an interactive session where you can:
- Type free-text risk descriptions (e.g., "I got a link from a friend saying urgent login needed for my email")
- Paste structured JSON risk events (see examples below)
- See the Guardian's assessment and advice in real time

### 6. Example Payloads for the Playground

**Free-text example:**
```
I got a link to phishy-demo.test from a friend saying "urgent login needed — verify now". Should I click it?
```

**Structured JSON example:**
```json
{
  "url": "https://phishy-demo.test/login",
  "raw_context": "friend sent urgent message"
}
```

**Another example (app permissions):**
```json
{
  "app_or_domain": "flashlight-helper.example",
  "raw_context": "app is asking to disable two-factor authentication and access my contacts"
}
```

### 7. Run the Self-Built MCP Server

To expose all six checks as standard MCP tools:

```bash
uv run python -m guardian.mcp_server
```

The server runs on stdin/stdout (Claude can connect to it directly). It exposes six tools:
- `check_email_leak_tool(email: str | None) -> EmailLeakCheck`
- `check_domain_reputation_tool(domain: str | None) -> DomainReputationCheck`
- `check_url_phishing_tool(url: str | None, raw_context: str | None = None) -> URLPhishingCheck`
- `check_permission_risk_tool(app_or_domain: str | None, raw_context: str | None = None) -> PermissionRiskCheck`
- `check_app_reputation_tool(app_or_domain: str | None) -> AppReputationCheck`
- `check_password_hygiene_tool() -> PasswordHygieneCheck`

### 8. Run Tests

```bash
uv run pytest -q
```

All tests use the offline workflow to avoid requiring Gemini credentials. Test coverage includes:
- Intake and event normalization
- LLM assessment logic (mocked)
- All six deterministic checks
- Routing and finalization
- Privacy contract enforcement


## Contributing

This is a capstone project for the Google×Kaggle 5-Day AI Agents vibe coding course. Contributions and feedback are welcome.
