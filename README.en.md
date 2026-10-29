# Suricata MCP Server 🛡️🚀

[![CI/CD Pipeline](https://github.com/nks1097/suricata-mcp-server/actions/workflows/ci.yml/badge.svg)](https://github.com/nks1097/suricata-mcp-server/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![MCP Protocol](https://img.shields.io/badge/MCP-1.0+-green.svg)](https://modelcontextprotocol.io/)
[![Suricata 7.x / 8.x Ready](https://img.shields.io/badge/Suricata-7.x%20%7C%208.x-orange.svg)](https://suricata.io/)

Production-ready **Model Context Protocol (MCP)** server for **Suricata IDS/IPS, Network Security Monitoring (NSM)**, and defensive network security. Provides **100 specialized tools**, designed to empower AI agents to inspect traffic, investigate security incidents, manage detection rules, and audit sensors.

> **[Leia a Documentação em Português (README.md)](README.md)**

---

## 🌟 Key Features

* **100 Production-Ready MCP Tools:** Structured across 10 mission-critical categories covering sensor health, EVE telemetry, network triage, and incident response.
* **High-Performance Incremental EVE JSON Reader:** Effortlessly processes multi-gigabyte `eve.json` files using 64KB reverse chunk seeking and memory-efficient streaming.
* **Isolated Offline PCAP Forensics:** Safely inspect `.pcap` and `.pcapng` capture files in sandboxed directories with magic bytes validation and strict size limits.
* **Controlled Rule Engineering:** Built-in Suricata rule AST parser, syntax verification, unified diff preview, and automated `.bak` backups.
* **Defense-in-Depth & RBAC:** Role-Based Access Control supporting `somente_leitura` (read-only), `operacional` (operational), and `administrativo` (administrative) levels.
* **Command Injection & Path Traversal Defense:** Safe subprocess execution with list arguments only (no dynamic shell string interpolation), strict timeouts, and binary whitelisting.
* **Automated Secrets Redaction:** Recursively sanitizes passwords, API keys, bearer tokens, and private keys from logs and agent outputs.
* **Enterprise Reporting Engine:** Direct export to styled **PDF** (ReportLab), multi-sheet **XLSX** workbooks (OpenPyXL), **CSV**, and structured **JSON**.
* **Comprehensive JSON Lines Audit Trail:** Records all tool invocations with duration, parameters, and unique correlation request IDs.
* **Dual Transport (STDIO & SSE):** Seamlessly integrates with Claude Desktop, Cursor, Antigravity IDE, Ollama, and remote deployments.

---

## 📐 Architecture Overview

```
+-------------------------------------------------------------+
|                 AI Agent / MCP Client                       |
|       (Claude Desktop, Cursor, Antigravity IDE, etc.)       |
+-------------------------------------------------------------+
                              |
                     [ STDIO / SSE Transport ]
                              v
+-------------------------------------------------------------+
|                     Suricata MCP Server                     |
|                                                             |
|  +-------------------------------------------------------+  |
|  |           Authorization & RBAC Security Layer         |  |
|  |  (somente_leitura | operacional | administrativo)     |  |
|  +-------------------------------------------------------+  |
|                             |                               |
|  +-------------------------------------------------------+  |
|  |         Structured Audit Log & Secret Redaction       |  |
|  +-------------------------------------------------------+  |
|                             |                               |
|  +-------------------------------------------------------+  |
|  |                 100 MCP Tool Endpoints                |  |
|  +-------------------------------------------------------+  |
+-------------------------------------------------------------+
          |                   |                     |
          v                   v                     v
+------------------+ +------------------+ +-------------------+
|  EVE JSON Engine | | Subprocess Runner| | Unix Socket Client|
+------------------+ +------------------+ +-------------------+
```

---

## 🧰 The 100 MCP Tools Inventory

| Category | Range | Operational Purpose |
| :--- | :---: | :--- |
| **A. Sensors and Operational State** | 01–10 | Sensor connectivity, version detection, health checks, diagnostics, interfaces. |
| **B. EVE Events and Telemetry** | 11–20 | Querying `eve.json`, alerts, flows, DNS queries, HTTP transactions, TLS, SSH. |
| **C. Network and Connection Analysis** | 21–30 | IP investigations, 5-tuple tracking, Top Talkers, portscans, and DGA heuristics. |
| **D. Alerts and Detection Engineering** | 31–40 | Signature grouping, frequency analysis, spikes, incident triage, false positive candidate detection. |
| **E. Rules and Signatures** | 41–50 | Listing rules, SID lookup, syntax validation, diff preview, local rules management, hot reload. |
| **F. PCAP and Offline Forensics** | 51–60 | Capture validation, offline execution, alert and flow extraction, cleanup. |
| **G. Engine Performance & Stats** | 61–70 | Kernel drops monitoring, capture module statistics, flow tables, memory usage. |
| **H. Configuration Management** | 71–80 | `suricata.yaml` validation, parameter inspection, log reopening, file checks. |
| **I. Defensive Response & SIEM** | 81–90 | Action planning, local incident tracking, IoC export, SHA-256 evidence packaging. |
| **J. Reporting, Audit & Automation** | 91–100 | Executive PDF/XLSX/CSV reports, approved workflow execution, MCP audit querying. |

---

## 🚀 Universal Quick Start

### Option 1: Zero-Install with `uvx` (Recommended)
No git clone or manual setup required. `uvx` executes the server directly from GitHub:

```bash
# Automated environment and health check
uvx --from git+https://github.com/nks1097/suricata-mcp-server.git suricata-mcp --doctor
```

---

### Option 2: Installation using `pip` or `git`
```bash
# 1. Clone the repository
git clone https://github.com/nks1097/suricata-mcp-server.git
cd suricata-mcp-server

# 2. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate # On Windows: .\.venv\Scripts\Activate.ps1

# 3. Install package in editable mode
pip install -e .

# 4. Run automated environment doctor
suricata-mcp --doctor
```

---

## ⚙️ MCP Client Configuration

### 1. Claude Desktop (`claude_desktop_config.json`)

#### Linux / macOS:
```json
{
  "mcpServers": {
    "suricata": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/nks1097/suricata-mcp-server.git",
        "suricata-mcp"
      ],
      "env": {
        "SURICATA_CONFIG_PATH": "/etc/suricata/suricata.yaml",
        "SURICATA_EVE_PATH": "/var/log/suricata/eve.json",
        "MCP_OPERATION_MODE": "operacional"
      }
    }
  }
}
```

#### Windows:
```json
{
  "mcpServers": {
    "suricata": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/nks1097/suricata-mcp-server.git",
        "suricata-mcp"
      ],
      "env": {
        "SURICATA_CONFIG_PATH": "C:/Program Files/Suricata/suricata.yaml",
        "SURICATA_EVE_PATH": "C:/Program Files/Suricata/log/eve.json",
        "MCP_OPERATION_MODE": "operacional"
      }
    }
  }
}
```

---

### 2. Cursor IDE (`.cursor/mcp.json`)
```json
{
  "mcpServers": {
    "suricata": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/nks1097/suricata-mcp-server.git",
        "suricata-mcp"
      ]
    }
  }
}
```

---

### 3. Server Deployment via Docker (SOC / SIEM)
```json
{
  "mcpServers": {
    "suricata": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "/var/log/suricata:/var/log/suricata:ro",
        "-v", "/etc/suricata:/etc/suricata:ro",
        "-e", "SURICATA_EVE_PATH=/var/log/suricata/eve.json",
        "ghcr.io/nks1097/suricata-mcp-server:latest"
      ]
    }
  }
}
```

---

## 🩺 Built-in Health Doctor: `suricata-mcp --doctor`

Verify your local Suricata engine, test EVE JSON telemetry readability, inspect local rules, and automatically output tailored JSON configuration snippets:

```bash
suricata-mcp --doctor
```

---

## 🧪 Testing & Validation

The codebase maintains 100% test pass rate across all tools:

```bash
# Run complete test suite (127 tests)
pytest -v

# Run static analysis with Ruff
ruff check .

# Strict type checking with Mypy
mypy src
```

---

## 📄 License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.

**Author:** Natanael Krindges (<natanael1097@gmail.com>)

