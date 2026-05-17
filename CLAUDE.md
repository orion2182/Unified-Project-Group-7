# AI Agent Pentest & PDP Compliance

Autonomous pentest agent with RAG-based legal mapping to UU No. 27 Tahun 2022.

## Project Structure

```
├── index_uu_pdp.py              # RAG indexer: PDF → ChromaDB
├── tools_bridge.py             # Tool bridge: Nmap, FFUF, BOLA tester
├── agent_orchestrator.py       # AI agent orchestrator (LangChain)
├── skills/
│   ├── api_pentest.md          # Autonomous pentester skill
│   └── pdp_compliance_auditor.md # Legal mapping skill
├── db_uu_pdp/                   # ChromaDB vector store (170 chunks)
└── UU Nomor 27 Tahun 2022.pdf  # Source document
```

## AI Agent Skills

### 1. api_pentest (SKILL-PENTEST-ADVANCED-001)
- Decision: Determines tools based on tech stack
- Chaining: BOLA → Lateral Movement
- Evasion: Random headers, encoding

### 2. pdp_compliance_auditor (SKILL-COMPLIANCE-PDP-001)
- Analyze pentest findings
- Query RAG for UU PDP articles
- Map technical risk → legal risk
- Generate compliant report with sanctions reference

## Commands

```bash
# 1. Index UU PDP to vector DB (first time only)
python index_uu_pdp.py

# 2. Run agent orchestrator (main entry)
python agent_orchestrator.py

# 3. Direct tool bridge usage
python -c "
from tools_bridge import SecurityToolsBridge
tb = SecurityToolsBridge()
tb.set_auth_token('<JWT_TOKEN>')
print(tb.test_bola_advanced('/api/v1/users/profile', 'victim_id'))
"

# Activate venv if needed
source .venv/bin/activate
```

## RAG Query Mapping

| Technical Finding | RAG Query | UU PDP Article |
|------------------|-----------|----------------|
| BOLA, IDOR, SQLi | "Pasal 35, 36, 39 akses tidak sah" | Pasal 38, 39 |
| Data Breach | "Pasal 46 notifikasi kegagalan" | Pasal 46 |
| Unencrypted Data | "Pasal 35 langkah teknis keamanan" | Pasal 35 |
| Missing Logs | "Pasal 31 perekaman kegiatan" | Pasal 31 |

## Agent Workflow

1. **Recon** → Nmap/FFUF enumeration
2. **Analysis** → api_pentest skill analyzes findings
3. **Exploit** → Execute BOLA/IDOR with auth token
4. **Query** → Send finding to RAG system
5. **Map** → pdp_compliance_auditor maps to UU PDP
6. **Report** → Output with legal basis + sanctions (Pasal 57, 67-68)

## 9-Gate Validation (Adapted)

Setiap temuan **WAJIB** melewati validasi sebelum report:

| Gate | Check |
|------|-------|
| 1 | **Exploitability** - Bisa dieksploitasi sekarang? |
| 2 | **Real Impact** - Kerugian nyata bagi data subject? |
| 3 | **Proof** - Ada bukti konkret (bukan teori)? |
| 4 | **Legal Basis** - Sudah mapping ke UU PDP? |
| 5 | **Scope** - Target dalam scope? |
| 6 | **Duplication** - Apakah temuan generik sudah lama? |
| 7 | **Attacker Narrative** - Story meyakinkan? |
| 8 | **Two-Account Test** - Sudah test dengan 2 akun? |
| 9 | **Compliance Impact** - Sanksi yang relevan? |

## POV Triager

Sebelum report, agent **WAJIB** evaluasi dengan pertanyaan:
1. *"Apakah skenario eksploitasi bisa dilakukan sekarang?"*
2. *"Apa kerugian nyata (impact) bagi data subject?"*
3. *"Alasan apa yang bisa dipakai triager untuk menolak?"*

**Verdict:**
- **[SUBMIT]** → Impact nyata & bukti lengkap
- **[NEED CHAINING]** → Butuh digabungkan dengan finding lain
- **[KILL]** → Teori tanpa bukti

## Reporting

Template report ada di `/resources/templates/`:
- `h1_template.md` - HackerOne format
- `bugcrowd_template.md` - Bugcrowd format
- `pdp_template.md` - UU PDP legal mapping format

Struktur wajib:
- Status Teknis (PoC)
- Dasar Hukum (RAG citation)
- Analisis Kepatuhan
- Potensi Sanksi (Pasal 57/67)
- Rekomendasi Mitigasi
- Sigma Rule untuk Wazuh

## Slash Commands

### /set
Atur target untuk gray box testing. Format:
```
/set <target_url> --token <jwt_token> --staff <staff_username>
```

Contoh:
```
/set https://api.bank-pdp.local --token eyJhbGciOiJIUzI1NiIs... --staff administrator
```

Ini akan:
- Simpan target URL ke memory
- Set auth token untuk request
- Simpan staff credentials untuk privilege escalation testing

### /audit
Jalankan pengujian keamanan. Format:
```
/audit <scope> [--techniques <tech1,tech2,...>]
```

Scopes:
- `/audit recon` → Nmap, FFUF enumeration
- `/audit api` → BOLA, IDOR, Mass Assignment
- `/audit auth` → JWT, OAuth, Session fixation
- `/audit full` → Semua pengujian

Contoh:
```
/audit api --techniques bola,parameter-pollution
/audit full
```

## Jump Server Context

- **Akses:** Staff credentials dari jump server
- **Metode:** SSH ke jump server, lalu ke target internal
- **Testing:** Karena sudah dapat credentials staff:
  - Privilege escalation (staff → admin)
  - Horizontal IDOR (data orang lain)
  - Vertical IDOR ( akses ke fungsi admin)
  - Session hijacking
  - API abuse dengan token valid

## External Resources

### RedTeam RAG (`~/redteam-rag/`)
```
├── 01-cheatsheets/      # Hacktricks, Payloads All The Things, Seclists
├── 02-owasp/           # OWASP Top 10, WSTG, API Security, MASVS
├── 03-tools/           # Nuclei templates, Nmap NSE, Semgrep rules
├── 04-writeups/        # Writeups & case studies
└── 05-frameworks/      # Pentest frameworks
```

**Useful untuk Gray Box:**
- `03-tools/nuclei-templates/` → Custom templates untuk API
- `03-tools/nmap-nse/` → Nmap scripts (http-enum, etc)
- `03-tools/semgrep-rules/` → Code analysis rules
- `02-owasp/wstg/` → Web Security Testing Guide
- `02-owasp/api-security/` → API security checklist
- `01-cheatsheets/payloads-all-the-things/` → Payloads untuk BOLA, SSRF, etc

### Bug Bounty (`~/claude-skills/bug-bounty/`)
- **Scripts:** `scripts/engines/` (IDOR scanner, OAuth tester, Race condition)
- **Wordlists:** `resources/wordlists/`
- **Templates:** `resources/templates/`

## Missing Tools

Berikut tools yang **TIDAK tersedia** di laptop ini:

| Tool | Purpose | Alternatif |
|------|---------|------------|
| `msfvenom/msfconsole` | Metasploit framework | Install separately atau pakai Docker |
| `sslyze` | TLS analysis | `nmap --script ssl-enum-ciphers` |
| `x8` | HTTP fuzzer | `ffuf` sudah ada |
| `metasploit-framework` | Exploitation | Manual exploitation atau Nuclei CVEs |

**Rekomendasi install:**
```bash
# Install script sudah ada, jalankan:
./scripts/install_metasploit.sh

# Atau pakai Docker
docker run -it metasploitframework/metasploit-framework
```

## Environment

- **Python:** 3.x with `.venv`
- **LLM:** LangChain integration
- **Vector DB:** ChromaDB (paraphrase-multilingual-MiniLM-L12-v2)
- **Dependencies:** langchain, langchain-chroma, langchain-community, huggingface-hub

## Available Tools

```bash
# Network
nmap, masscan, amass

# Web Fuzzing
ffuf, gospider, dirb

# Vulnerability
nuclei, sqlmap, nikto, whatweb

# XSS/Injection
dalfox

# Password
hydra, john

# Screenshot
gowitness
```