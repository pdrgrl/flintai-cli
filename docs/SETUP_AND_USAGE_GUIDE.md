# Flint AI CLI — Setup, Usage, Architecture & Privacy Guide

> **Flint AI** is an AI Security Posture Management (AI-SPM) and static-plus-agentic vulnerability scanner designed to detect **OWASP Top 10 for Agentic AI (ASI01–ASI10)** security flaws across AI agent codebases.

---

## 1. Executive Summary & Licensing

### License Type
* **Base License:** Apache 2.0
* **Limitation:** **"Commons Clause" License Condition v1.0** (Source-Available)

### What This Means for Business & Commercial Use:
| Permission / Use Case | Allowed? | Details |
| :--- | :---: | :--- |
| **Internal Company Audits** | ✅ **YES** | Scanning your own applications in development or CI/CD pipelines is 100% permitted and royalty-free. |
| **Modifications & Extensions** | ✅ **YES** | You may modify, add language parsers (e.g. Elixir/BEAM), and customize rules internally. |
| **Reselling as a Product / Service** | ❌ **NO** | The Commons Clause strictly prohibits selling the software or offering a paid SaaS/consulting service whose primary value derives from Flint AI. |
| **Sublicensing & Redistribution** | ⚠️ **Limited** | Any derivative must carry the Apache 2.0 + Commons Clause notice. |

---

## 2. System Architecture: The 4-Layer Scanning Pipeline

Flint AI combines high-speed deterministic static AST analysis with autonomous LLM reasoning and triage:

```
┌────────────────────────────────────────────────────────────────────────┐
│ Layer 1: Multi-Language AST Discovery & Framework Classifier          │
│ • Detects Python (LangChain, CrewAI, AutoGen, Smolagents, LlamaIndex)  │
│ • Detects Elixir (LangChain Elixir, Instructor, ReqLLM, Anubis MCP)    │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Layer 2: Local Deterministic Static Analyzers                          │
│ • OpenGrep (51+ AST rules for ASI01–ASI10)                             │
│ • Sobelow (Elixir AST Security) & detect-secrets (Credentials)         │
│ • Hex Package Audit (OSV.dev Batch Vulnerability API)                  │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Layer 3: Autonomous AI Reasoner (Interactive Agent Loop)               │
│ • LLM explores agent goal logic, tool definitions, and prompt flows    │
│ • Calls local tool dispatcher (`read_source`, `analyze_code`)          │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Layer 4: AI Triage & Ground-Truth Verification Judge                  │
│ • Verifies findings against real disk source (Hallucination Verifier) │
│ • Evaluates exploitability in agent context (KEEP / DISMISS)          │
│ • Computes CVSS v4.0 metrics & severity bands                          │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Data Privacy & Code Access: Does the LLM See Your Entire Code?

### **No, your full codebase is never uploaded in bulk.**

1. **Deterministic Local Execution (Layers 1 & 2):**
   * File filtering, AST pattern matching, credential scanning, and lockfile dependency audits run **100% locally on your machine**.
   * No code is transmitted to external servers for static scanning.

2. **Targeted Tool Calls in AI Reasoning (Layer 3):**
   * The AI Reasoner does **not** ingest the entire repository.
   * Instead, the LLM receives the detected framework metadata and decides which specific files to inspect via isolated tool calls (`read_source(file, start_line, end_line)`).
   * Only the requested code slices are sent over the LLM connection.

3. **Candidate Triage (Layer 4):**
   * Only the specific code snippets attached to flagged candidate findings are sent to the triage judge for scoring.

4. **Telemetry:**
   * Telemetry is strictly opt-in (`FLINTAI_TELEMETRY_CONSENT=false` to disable).
   * Telemetry never transmits source code, file paths, prompts, API keys, or usernames.

---

## 4. Setup & Installation

### Prerequisites
* Python 3.10+
* OpenGrep (`curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash`)

### Running Locally
```bash
cd ~/flintai-cli

# Alias for CLI execution
alias flintai="PYTHONPATH=$(pwd) python3 -m flintai.cli"
```

---

## 5. LLM Gateway Configuration

Flint AI supports any OpenAI-compatible gateway (e.g., LiteLLM proxy, Cloudflare Workers AI, vLLM, Ollama):

```bash
# 1. Custom Gateway URL
export OPENAI_BASE_URL="https://api.your-gateway.com/v1"

# 2. API Key (e.g. from token file or env)
export OPENAI_API_KEY="<your-api-key>"

# 3. Model Selection
export SCANNER_MODEL="openai/cf/qwen2.5-coder-32b"
```

### Supported Models & Roles
* `openai/cf/qwen2.5-coder-32b` (Recommended for high-precision code auditing & zero hallucinations)
* `openai/cf/deepseek-v4-pro` (Recommended for complex multi-step reasoning)
* `openai/cf/llama-3.3-70b` (Balanced general intelligence)
* `openai/cf/mistral-small-3.1` (Fast lightweight scans)

---

## 6. CLI Usage & Commands

### 1. Standard Scan (Compact Table)
```bash
flintai scan /path/to/project
```

### 2. Detailed Scan (Rich Finding Cards & Remediation)
```bash
flintai scan /path/to/project -d
# or
flintai scan /path/to/project --detailed
```

### 3. SARIF Export (GitHub / GitLab CI Security Alerts)
```bash
flintai scan /path/to/project --format sarif -o results.sarif
```

### 4. JSON Forensic Export
```bash
flintai scan /path/to/project -o report.json
```

---

## 7. Real-World Elixir Project Audit Case Study

When audited against a production Elixir/Phoenix codebase (540 total files, 383 Elixir files), the scan triaged 17 static alerts down to **4 actionable Critical vulnerabilities**:

| Finding | File Location | Vulnerability Category | CVSS | Real-World Risk |
| :--- | :--- | :--- | :---: | :--- |
| **1. Exception Prompt Echo** | `deps/langchain/lib/chains/llm_chain.ex:1313` | ASI01: Prompt Injection | **10.0** | **Real Risk:** Exception messages wrapped in `Message.new_user!` reflect untrusted error payloads into the LLM context. |
| **2. JSON Decode Echo** | `deps/langchain/lib/message_processors/json_processor.ex:135` | ASI01: Prompt Injection | **10.0** | **Real Risk:** Malformed JSON parser errors containing injection payloads are fed directly to LLM as user role instructions. |
| **3. Process Kill Port** | `deps/owl/lib/owl/daemon.ex:81` | ASI05: Command Execution | **9.4** | **Benign in Practice:** OS PID integer cleanup via Erlang port. |
| **4. Version Check** | `deps/playwright_ex/lib/playwright_ex/processes/port_transport.ex:112` | ASI05: Command Execution | **9.4** | **Low Risk:** Startup version validation on Playwright binary. |
