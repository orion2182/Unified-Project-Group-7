# Project Unified-Shield: AI Agent Pentest & UU PDP Compliance

Mandat utama AI Agent untuk tugas Kelompok 7.

## Core Identity

1. **Tujuan:** Autonomous Pentest & UU PDP Compliance
2. **Metodologi:** Grey Box Testing (dengan staff credentials)
3. **Target:** API (REST) dengan authentication
4. **RAG-First:** Validasi setiap temuan teknis ke UU PDP No. 27 Tahun 2022
5. **CVSS:** Wajib gunakan skor risiko untuk setiap temuan

## Target Setup

```
/set https://api.bank-pdp.local --token <jwt_token> --staff <username>
```

Akses via jump server dengan staff credentials.

## Project Structure

```
├── index_uu_pdp.py              # RAG indexer: PDF → ChromaDB
├── tools_bridge.py             # Tool bridge: Nmap, FFUF, BOLA tester
├── agent_orchestrator.py       # AI agent orchestrator (LangChain)
├── skills/
│   ├── api_pentest.md          # Autonomous pentester skill
│   └── pdp_compliance_auditor.md # Legal mapping skill
├── db_uu_pdp/                   # ChromaDB vector store
└── scripts/install_metasploit.sh # Metasploit installer
```

## Commands

```bash
# 1. Index UU PDP ke vector DB (sekali saja)
python index_uu_pdp.py

# 2. Jalankan agent orchestrator
python agent_orchestrator.py

# 3. Direct tool bridge
python -c "from tools_bridge import SecurityToolsBridge; tb = SecurityToolsBridge(); tb.set_auth_token('<JWT>'); print(tb.test_bola_advanced('/api/v1/users/profile', 'victim_id'))"

# Activate venv
source .venv/bin/activate
```

## Slash Commands

### /set
Atur target untuk gray box testing:
```
/set <target_url> --token <jwt_token> --staff <staff_username>
```

### /audit
Jalankan pengujian keamanan:
```
/audit recon      # Nmap, FFUF enumeration
/audit api        # BOLA, IDOR, Mass Assignment
/audit auth       # JWT, OAuth, Session fixation
/audit full       # Semua pengujian
```

Contoh:
```
/audit api --techniques bola,parameter-pollution
/audit full
```

## Agent Workflow

1. **Recon** → Nmap/FFUF enumeration
2. **Analysis** → api_pentest skill analyzes
3. **Exploit** → Execute BOLA/IDOR dengan auth token
4. **Query** → Kirim finding ke RAG system
5. **Map** → pdp_compliance_auditor maps ke UU PDP
6. **Report** → Output dengan legal basis + sanksi (Pasal 57, 67-68)

## RAG Query Mapping

| Technical Finding | RAG Query | UU PDP Article |
|------------------|-----------|----------------|
| BOLA, IDOR, SQLi | "Pasal 35, 36, 39 akses tidak sah" | Pasal 38, 39 |
| Data Breach | "Pasal 46 notifikasi kegagalan" | Pasal 46 |
| Unencrypted Data | "Pasal 35 langkah teknis keamanan" | Pasal 35 |
| Missing Logs | "Pasal 31 perekaman kegiatan" | Pasal 31 |

## 9-Gate Validation

Setiap temuan WAJIB melewati validasi:

| Gate | Check |
|------|-------|
| 1 | Exploitability - Bisa dieksploitasi sekarang? |
| 2 | Real Impact - Kerugian nyata? |
| 3 | Proof - Ada bukti konkret? |
| 4 | Legal Basis - Sudah mapping ke UU PDP? |
| 5 | Scope - Target dalam scope? |
| 6 | Duplication - Apakah sudah ada? |
| 7 | Attacker Narrative - Story meyakinkan? |
| 8 | Two-Account Test - Sudah test 2 akun? |
| 9 | Compliance Impact - Sanksi relevan? |

## Reporting Structure

Setiap laporan WAJIB punya:
- Status Teknis (PoC)
- Dasar Hukum (RAG citation)
- Analisis Kepatuhan
- Potensi Sanksi (Pasal 57/67)
- Rekomendasi Mitigasi
- Sigma Rule untuk Wazuh

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

# Exploitation (after install)
msfconsole, msfvenom
```

## External Resources

- **RedTeam RAG:** `~/redteam-rag/` (cheatsheets, OWASP WSTG, nuclei templates)
- **Bug Bounty:** `~/claude-skills/bug-bounty/scripts/` (IDOR scanner, OAuth tester)

## Dependencies

- Python 3.x dengan `.venv`
- LangChain + ChromaDB
- paraphrase-multilingual-MiniLM-L12-v2 (embedding)