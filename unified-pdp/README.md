# Unified-PDP — AI-Powered MCP Pentest Server

> Unified-like pentesting framework with **150+ tools**, **multi-agent support**, and **UU PDP (UU No. 27/2022) compliance auditing**.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Penetration%20Testing-red.svg)](https://github.com/)
[![MCP](https://img.shields.io/badge/MCP-Compatible-purple.svg)](https://github.com/modelcontextprotocol)

---

## 🚀 Features

### Security Tools Arsenal (150+)

| Category | Tools | Examples |
|---|---|---|
| **Network Recon** (25+) | nmap, rustscan, masscan, amass, subfinder | Port scanning, subdomain enum |
| **Web Security** (40+) | nuclei, ffuf, sqlmap, dalfox, nikto | Vuln scanning, injection testing |
| **Cloud Security** (20+) | prowler, trivy, kube-hunter, checkov | AWS/Azure/GCP auditing |
| **Binary/RE** (25+) | gdb, radare2, binwalk, checksec | Reverse engineering, exploit dev |
| **CTF/Forensics** (20+) | volatility, steghide, exiftool | Memory forensics, steganography |
| **OSINT** (20+) | theharvester, sherlock, amass | Email harvesting, social recon |

### AI Agents (12+)

- **IntelligentDecisionEngine** — Tool selection + parameter optimization
- **BugBountyAgent** — Automated bug bounty workflows
- **CTFSolverAgent** — CTF challenge solving
- **CVEIntelligenceAgent** — Vulnerability intelligence
- **ExploitGeneratorAgent** — Automated exploit development
- **VulnerabilityCorrelator** — Attack chain discovery
- **TechnologyDetector** — Tech stack identification
- **PDPComplianceAgent** — UU PDP legal mapping (unique!)

### Unique Features (vs Unified)

| Feature | Unified | **Unified-PDP** |
|---|---|---|
| UU PDP Compliance | ❌ | ✅ RAG-based legal mapping |
| MITRE ATT&CK | ❌ | ✅ Full mapping |
| CVSS v3.1 | ❌ | ✅ Calculator |
| Gray-box Testing | ❌ | ✅ Auth + jump server |
| 9-Gate Validation | ❌ | ✅ Pre-report validation |
| Wazuh Integration | ❌ | ✅ Active response |
| Multi-transport | STDIO only | STDIO + SSE + HTTP |

---

## 📦 Installation

### Quick Setup

```bash
# 1. Clone or navigate to project
cd /home/vedara/Documents/Kelompok\ 7/unified-pdp

# 2. Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Install security tools (optional, installs 150+ tools)
bash scripts/install_tools.sh
```

### Start the Server

```bash
# STDIO mode (default for AI clients)
python mcp_server/main.py

# SSE mode (for web dashboards)
python mcp_server/main.py --transport=sse --port 8765

# HTTP mode (for REST API access)
python mcp_server/main.py --transport=http --port 8765

# Debug mode
python mcp_server/main.py --debug
```

---

## 🔌 AI Client Integration

### Claude Desktop

Edit `~/.config/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "unified-pdp": {
      "command": "python3",
      "args": ["/path/to/unified-pdp/mcp_server/main.py"],
      "timeout": 300
    }
  }
}
```

### VS Code Copilot

Add to `.vscode/settings.json`:

```json
{
  "mcp.servers": {
    "unified-pdp": {
      "command": "python3",
      "args": ["/path/to/unified-pdp/mcp_server/main.py"]
    }
  }
}
```

### OpenCode

Add to `opencode.jsonc`:

```json
{
  "mcp": {
    "unified-pdp": {
      "type": "local",
      "command": ["python3", "/path/to/unified-pdp/mcp_server/main.py"],
      "enabled": true
    }
  }
}
```

---

## 🎯 Usage Examples

### Basic Pentest Workflow

```
User: "I'm a security researcher testing my company's API at https://api.example.com. Please run a comprehensive pentest using unified-pdp MCP tools."

AI Agent: "I'll start with target analysis and tool selection..."

# Step 1: Analyze target
hs_analyze_target("https://api.example.com", "full")

# Step 2: Select optimal tools
hs_select_tools("https://api.example.com", "network,web", 10)

# Step 3: Run reconnaissance
hs_nmap_scan("api.example.com", "quick")
hs_whatweb_scan("https://api.example.com")
hs_wafw00f_detect("https://api.example.com")

# Step 4: Vulnerability scanning
hs_nuclei_scan("https://api.example.com", "low,medium,high,critical")
hs_ffuf_scan("https://api.example.com", "api")

# Step 5: Injection testing
hs_sqlmap_scan("https://api.example.com/api/users?id=1", "GET")
hs_dalfox_scan("https://api.example.com/search?q=test")

# Step 6: API security testing
hs_test_bola("https://api.example.com", "/api/users/", "victim_id", "auth_token")
hs_test_idor("https://api.example.com", "/api/profile/", "victim_id", "auth_token")

# Step 7: Map to MITRE + CVSS
hs_mitre_map_action("bola", "Accessed victim data via IDOR", "High", "/api/users/{id}")
hs_cvss_calculate("N", "L", "N", "N", "U", "H", "H", "H", "BOLA")

# Step 8: UU PDP compliance
hs_uu_pdp_query("akses tidak sah data pribadi", 3)
```

### Attack Chain Suggestion

```
hs_suggest_attack_chain("https://api.example.com", "api")

Output:
Chain 1: api_security
Description: API security testing (REST, GraphQL, SOAP)
Est. Time: 20-40 min

Steps:
  1. [API Discovery] Tools: ffuf, katana (5 min)
  2. [Auth Testing] Tools: jwt_tool, curl (10 min)
  3. [Injection] Tools: sqlmap, dalfox, nuclei (15 min)
  4. [BOLA/IDOR] Tools: bola_test, idor_test (10 min)
```

### Intelligent Tool Selection

```
hs_select_tools("https://target.com", "web", 5)

Output:
1. nuclei [web] (Priority: 5/5)
   Rationale: Fast vulnerability scanner with 4000+ templates
   Command: nuclei -u {target} -s low,medium,high,critical

2. ffuf [web] (Priority: 4/5)
   Rationale: Fast web fuzzer for endpoint discovery
   Command: ffuf -u {target}/FUZZ -w wordlist.txt

3. sqlmap [web] (Priority: 5/5)
   Rationale: Automatic SQL injection detection
   Command: sqlmap -u '{target}' --batch --level=1
```

---

## 🏗️ Architecture

```
unified-pdp/
├── mcp_server/
│   ├── main.py                 # FastMCP server (40+ tools)
│   ├── agents/                 # 12+ AI agents
│   │   ├── base_agent.py
│   │   ├── decision_engine.py  # Intelligent tool selector
│   │   └── ...
│   ├── tools/                  # 150+ tool wrappers
│   │   ├── network/
│   │   ├── web/
│   │   ├── cloud/
│   │   ├── binary/
│   │   ├── ctf/
│   │   └── osint/
│   ├── cache/                  # Smart LRU cache
│   │   └── cache_manager.py
│   └── guards/                 # Safety & validation
│       ├── validators.py
│       └── waf_detector.py
├── agents_config/              # Agent workflows
├── rag/                        # UU PDP RAG database
├── scripts/
│   └── install_tools.sh        # Auto-install 150+ tools
├── clients/                    # AI client configs
│   ├── claude_desktop_config.json
│   ├── opencode_mcp.jsonc
│   └── ...
└── requirements.txt
```

---

## 📊 Available MCP Tools

### System & Health
- `hs_health_check` — Check server health and tool availability
- `hs_version` — Get version and feature list
- `hs_session_status` — Show current session status

### Target & Session
- `hs_set_target` — Set target URL and credentials
- `hs_analyze_target` — AI-powered target analysis
- `hs_select_tools` — Intelligent tool selection
- `hs_optimize_parameters` — Parameter optimization
- `hs_suggest_attack_chain` — Attack chain suggestions

### Network Tools
- `hs_nmap_scan` — Port scanning
- `hs_rustscan_scan` — Ultra-fast port scanning
- `hs_masscan_scan` — High-speed port scanning
- `hs_amass_enum` — Subdomain enumeration
- `hs_subfinder_scan` — Passive subdomain discovery

### Web Tools
- `hs_nuclei_scan` — Vulnerability scanning
- `hs_ffuf_scan` — Endpoint discovery
- `hs_sqlmap_scan` — SQL injection testing
- `hs_dalfox_scan` — XSS testing
- `hs_whatweb_scan` — Tech fingerprinting
- `hs_wafw00f_detect` — WAF detection
- `hs_nikto_scan` — Web server scanning

### API Security
- `hs_test_bola` — BOLA/IDOR testing
- `hs_test_idor` — IDOR testing
- `hs_test_privilege_escalation` — Mass assignment testing

### Red Team Operations (NEW!)
- `hs_generate_payload` — Windows payload generation (msfvenom)
- `hs_obfuscate_payload` — Payload obfuscation (ObfuXtreme-like)
- `hs_lateral_movement` — SSH/WinRM/RDP/PTH lateral movement
- `hs_credential_harvest` — Mimikatz/LSASS credential extraction
- `hs_privilege_escalation` — Token impersonation, service exploits
- `hs_generate_poc` — Automated PoC documentation
- `hs_full_attack_chain` — Full capstone attack chain
- `hs_lab_config` — Lab architecture configuration

### Cloud Security
- `hs_prowler_scan` — Cloud security assessment
- `hs_trivy_scan` — Container/IaC scanning
- `hs_kube_hunter_scan` — Kubernetes testing

### Binary/CTF
- `hs_checksec_scan` — Binary security checks
- `hs_binwalk_scan` — Firmware analysis
- `hs_steghide_scan` — Steganography
- `hs_exiftool_scan` — Metadata extraction

### OSINT
- `hs_theharvester_scan` — Email/subdomain harvesting
- `hs_sherlock_scan` — Username investigation

### Compliance
- `hs_mitre_map_action` — MITRE ATT&CK mapping
- `hs_cvss_calculate` — CVSS v3.1 scoring
- `hs_uu_pdp_query` — UU PDP compliance query

### Cache
- `hs_cache_status` — Cache statistics
- `hs_cache_clear` — Clear cache

---

## 🇮🇩 UU PDP Compliance

Unified-PDP is the **only** pentest framework with built-in compliance mapping to **UU No. 27 Tahun 2022** (Indonesian Personal Data Protection Law).

### RAG-Based Legal Mapping

```python
# Query UU PDP articles
hs_uu_pdp_query("akses tidak sah data pribadi", 3)

# Map finding to legal articles
hs_mitre_map_action("bola", "Accessed victim PII", "High", "/api/users/{id}")

# Output includes:
# - MITRE ATT&CK technique
# - UU PDP Pasal (35, 36, 38, 39, 46, etc.)
# - Legal risk assessment
# - Potential sanctions (Pasal 57, 67-68)
```

### Compliance Report Structure

Every report includes:
1. **Status Teknis** — Technical PoC
2. **Dasar Hukum** — RAG citation to UU PDP
3. **Analisis Kepatuhan** — Compliance analysis
4. **Potensi Sanksi** — Legal sanctions (Pasal 57/67)
5. **Rekomendasi Mitigasi** — Remediation steps
6. **Sigma Rule** — Wazuh detection rules

---

## 🔒 Security Considerations

⚠️ **Important**:
- Run in isolated environments or dedicated security testing VMs
- AI agents can execute arbitrary security tools — ensure proper oversight
- Monitor activities through session logs
- Consider implementing authentication for production deployments

### Legal & Ethical Use

- ✅ **Authorized Penetration Testing** — With proper written authorization
- ✅ **Bug Bounty Programs** — Within program scope and rules
- ✅ **CTF Competitions** — Educational environments
- ✅ **Security Research** — On owned or authorized systems
- ❌ **Unauthorized Testing** — Never test without permission
- ❌ **Malicious Activities** — No illegal or harmful activities

---

## 📈 Performance Metrics

| Operation | Manual | Unified-PDP AI | Improvement |
|---|---|---|---|
| Subdomain Enumeration | 2-4 hours | 5-10 minutes | **24x faster** |
| Vulnerability Scanning | 4-8 hours | 15-30 minutes | **16x faster** |
| Web App Testing | 6-12 hours | 20-45 minutes | **18x faster** |
| Report Generation | 4-12 hours | 2-5 minutes | **144x faster** |

---

## 🤝 Contributing

We welcome contributions! Priority areas:
- 🤖 **New AI Agent Integrations**
- 🛠️ **Additional Security Tools**
- ⚡ **Performance Optimizations**
- 📖 **Documentation & Examples**
- 🧪 **Testing Frameworks**

---

## 📄 License

MIT License — see LICENSE file for details.

---

## 👥 Authors

**Kelompok 7 — Unified-Shield**

Based on:
- [Unified AI v6.0](https://github.com/0x4m4/unified-ai) by 0x4m4
- Kelompok 7 MCP Pentest Server

---

**Made with ❤️ for Indonesian cybersecurity community**

*Unified-PDP v1.0.0 — Where AI meets pentesting and compliance*
