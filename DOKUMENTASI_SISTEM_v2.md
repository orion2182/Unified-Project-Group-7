# Dokumentasi Sistem — Unified-Shield MCP Pentest Server v2.0

> **Capstone Project Cybersecurity 2026 — Kelompok 7**
> AI-Driven Gray Box Penetration Testing dengan MITRE ATT&CK, CVSS v3.1, dan UU PDP Compliance

---

## Daftar Isi

1. [Apa Itu Sistem Ini?](#apa-itu-sistem-ini)
2. [Arsitektur Infrastruktur Lab](#arsitektur-infrastruktur-lab)
3. [Komponen Utama Sistem](#komponen-utama-sistem)
4. [Cara Kerja Alur Penetration Testing](#cara-kerja-alur-penetration-testing)
5. [65 MCP Tools yang Tersedia](#65-mcp-tools-yang-tersedia)
6. [Fitur v2.0: Async, Cache, Process Management](#fitur-v20-async-cache-process-management)
7. [Panduan Penggunaan](#panduan-penggunaan)
8. [Attack Chain yang Sudah Didesain](#attack-chain-yang-sudah-didesain)
9. [Mapping ke MITRE ATT&CK dan UU PDP](#mapping-ke-mitre-attck-dan-uu-pdp)
10. [Wazuh SIEM dan Evasion](#wazuh-siem-dan-evasion)
11. [Troubleshooting](#troubleshooting)
12. [Struktur File](#struktur-file)

---

## Apa Itu Sistem Ini?

Sistem ini adalah **AI Agent otomatis** yang bisa melakukan penetration testing (uji penetrasi) secara mandiri terhadap infrastruktur lab Kelompok 7.

**Analogi sederhana:** Bayangkan kamu punya "hacker robot" yang bisa:
1. **Scan** jaringan untuk mencari celah keamanan
2. **Exploit** celah yang ditemukan
3. **Mapping** temuan ke framework internasional (MITRE ATT&CK)
4. **Hitung** tingkat keparahan (CVSS v3.1)
5. **Cocokkan** dengan hukum Indonesia (UU PDP)
6. **Buat laporan** lengkap secara otomatis

Semua ini dijalankan melalui **MCP (Model Context Protocol)** — sebuah standar yang memungkinkan AI (seperti Claude, GPT) berkomunikasi langsung dengan tools keamanan di laptop kamu.

---

## Arsitektur Infrastruktur Lab

### Peta Jaringan

```
                    [Internet]
                        │
                        │  SSTP Port 6443
                        ▼
              ┌─────────────────────┐
              │   VPN Gateway       │
              │  blackops.surf      │
              │  (SSTP Server)      │
              └────────┬────────────┘
                       │
                       │  192.168.168.0/24
                       ▼
              ┌─────────────────────┐
              │   JumpServer        │
              │  192.168.168.10     │
              │  (Bastion Host)     │
              │  SSH: 22, Web: 8080 │
              └────────┬────────────┘
                       │
                       │  SSH Pivot / Port Forwarding
                       ▼
              ┌─────────────────────┐
              │  Internal Network   │
              │  10.10.10.0/24      │
              │                     │
              │  ┌───────────────┐  │
              │  │ Web Server    │  │
              │  │ 10.10.10.x    │  │
              │  │ :80, :443     │  │
              │  └───────────────┘  │
              │                     │
              │  ┌───────────────┐  │
              │  │ Database      │  │
              │  │ 10.10.10.x    │  │
              │  │ :3306, :5432  │  │
              │  └───────────────┘  │
              │                     │
              │  ┌───────────────┐  │
              │  │ NFS Server    │  │
              │  │ 10.10.10.x    │  │
              │  │ :2049         │  │
              │  └───────────────┘  │
              │                     │
              │  ┌───────────────┐  │
              │  │ Windows Srv   │  │
              │  │ 10.10.10.x    │  │
              │  │ :445, :3389   │  │
              │  └───────────────┘  │
              │                     │
              │  ┌───────────────┐  │
              │  │ Wazuh SIEM    │  │
              │  │ 10.10.10.12   │  │
              │  │ :1514, :1515  │  │
              │  └───────────────┘  │
              └─────────────────────┘
```

### Penjelasan Setiap Komponen

| Komponen | IP | Fungsi | Analogi |
|----------|-----|--------|---------|
| **VPN Gateway** | `blackops.surf:6443` | Pintu masuk utama via SSTP | Gerbang keamanan gedung |
| **JumpServer** | `192.168.168.10` | Bastion Host — satu-satunya pintu ke internal | Satpam yang harus dilewati dulu |
| **Web Server** | `10.10.10.x` | Menjalankan aplikasi web | Ruang pelayanan publik |
| **Database** | `10.10.10.x` | Menyimpan data (MySQL/PostgreSQL) | Brankas data |
| **NFS Server** | `10.10.10.x` | File sharing network | Lemari arsip bersama |
| **Windows Server** | `10.10.10.x` | Server Windows (AD, SMB, RDP) | Ruang kontrol Windows |
| **Wazuh SIEM** | `10.10.10.12` | Monitoring & deteksi serangan | CCTV + alarm keamanan |

### Alur Serangan yang Didesain

```
Attacker → VPN → JumpServer → Internal Network → Exploit → Data
```

1. **Connect VPN** ke `blackops.surf:6443`
2. **Scan JumpServer** (`192.168.168.10`) — cari celah di SSH dan web interface
3. **Gain access** ke JumpServer (credential exploit / CVE)
4. **Pivot** dari JumpServer ke internal network (`10.10.10.0/24`)
5. **Scan & exploit** server internal (Web, DB, NFS, Windows)
6. **Escalate** privilege ke root/SYSTEM
7. **Extract** bukti (flags, configs, data sensitif)

---

## Komponen Utama Sistem

### 1. MCP Pentest Server (`server.py`)

**Apa itu?** Server utama yang menghubungkan AI dengan 65 tools keamanan.

**Cara kerja:**
- AI mengirim perintah via MCP Protocol
- Server menjalankan tools (nmap, ffuf, nuclei, dll)
- Hasil dikembalikan ke AI untuk dianalisis

**Fitur v2.0:**
- **Async mode** — scan jalan di background, AI gak perlu nunggu
- **Smart cache** — hasil scan disimpan, scan ulang = instant
- **Process management** — bisa list, cek status, kill scan yang jalan

### 2. Decision Engine (`decision_engine.py`)

**Apa itu?** "Otak" yang memutuskan tools apa yang harus dipakai dan urutan serangannya.

**Cara kerja:**
1. Analisis target (IP, port, teknologi)
2. Prioritaskan attack paths berdasarkan efektivitas
3. Rekomendasikan tools yang paling cocok
4. Hindari deteksi Wazuh (stealth mode)

### 3. PTG Manager (`ptg_manager.py`)

**Apa itu?** Penjejak Progress Testing Graph — semacam "peta serangan" yang mencatat apa yang sudah dan belum dicoba.

**Struktur PTG (18 node):**
```
VPN Connect → JumpServer Recon → JumpServer Exploit
    → Internal Scan → Web Server Attack → Database Attack
    → NFS Attack → Windows Attack → Privilege Escalation
    → Data Extraction → MITRE Mapping → CVSS Scoring
    → UU PDP Mapping → Correlation → Report Generation
```

### 4. Experience Knowledge Base (`ekb_manager.py`)

**Apa itu?** "Memori" yang menyimpan pola serangan yang pernah berhasil/gagal.

**Cara kerja:**
- Setiap serangan disimpan: apa yang dilakukan, berhasil atau tidak, apa yang dipelajari
- Sebelum menyerang, AI cek EKB: "Pernah coba ini sebelumnya? Hasilnya gimana?"
- Menghindari pengulangan yang sama (anti-looping)

### 5. Vulnerability Correlator (`vulnerability_correlator.py`)

**Apa itu?** Menemukan rantai kerentanan — bagaimana satu celah bisa dihubungkan ke celah lain untuk eskalasi.

**Contoh:**
```
Finding 1: Open port 22 (SSH) pada JumpServer
Finding 2: JumpServer versi lama (CVE-2023-XXXX)
Finding 3: Default credential "admin:admin" masih aktif

Correlator: "Gabungkan ketiganya → SSH brute force dengan default creds → exploit CVE → root access"
```

### 6. MITRE ATT&CK Mapper

**Apa itu?** Mapping otomatis temuan teknis ke framework MITRE ATT&CK (standar industri).

**Contoh:**
```
Temuan: BOLA/IDOR pada /api/v1/users/{id}
→ T1210 (Remote Services Exploitation) [Lateral Movement]
→ Pasal 38, 39 UU PDP
```

### 7. CVSS Calculator

**Apa itu?** Menghitung skor keparahan kerentanan (0.0 - 10.0).

**Skala:**
| Skor | Severity | Warna |
|------|----------|-------|
| 0.0 | None | Abu-abu |
| 0.1-3.9 | Low | Biru |
| 4.0-6.9 | Medium | Kuning |
| 7.0-8.9 | High | Oranye |
| 9.0-10.0 | Critical | Merah |

### 8. UU PDP RAG Database

**Apa itu?** Database UU No. 27 Tahun 2022 tentang Perlindungan Data Pribadi yang bisa di-search secara semantik.

**Cara kerja:**
- PDF UU PDP di-chunk menjadi 340 bagian
- Setiap bagian di-convert ke vector (angka yang merepresentasikan makna)
- AI bisa query: "akses tidak sah" → sistem cari pasal yang relevan
- Hasil: Pasal 38, 39, 65 dengan konteks lengkap

### 9. Credential Manager

**Apa itu?** Penyimpanan kredensial untuk gray-box testing.

**3 Role:**
| Role | Fungsi | Contoh |
|------|--------|--------|
| **Attacker** | Akun staff — testing horizontal IDOR | user: ops |
| **Victim** | Akun user biasa — target IDOR | user: victim |
| **Admin** | Akun admin — testing privilege escalation | user: admin |

### 10. HTTP Dashboard (`http_dashboard.py`)

**Apa itu?** Dashboard web real-time yang menampilkan status pentest.

**Fitur:**
- Progress scan (running, success, failed)
- PTG progress (berapa node sudah selesai)
- MITRE chain (teknik apa yang sudah terpetakan)
- Jumlah findings

**Akses:** `http://127.0.0.1:8080`

---

## Cara Kerja Alur Penetration Testing

### Langkah 1: Connect VPN

```bash
sudo pppd pty "sstpc --nolaunchpppd --user test --password test --cert-warn blackops.surf:6443" user test password test noauth refuse-pap refuse-chap refuse-mschap refuse-eap name sstp-client nodetach
```

AI akan otomatis cek koneksi VPN sebelum mulai scanning.

### Langkah 2: Set Target

AI memanggil `ptg_set_target` untuk mengkonfigurasi target dan credentials.

### Langkah 3: Reconnaissance

AI menjalankan tools scanning secara otomatis:

| Tool | Fungsi | Output |
|------|--------|--------|
| **Nmap** | Scan port dan service | Port terbuka, versi service, OS |
| **FFUF** | Cari hidden endpoint | URL tersembunyi, API endpoints |
| **Nuclei** | Scan kerentanan | CVE, misconfigurations |

### Langkah 4: Exploitation

Setelah recon, AI mencoba exploit:

| Teknik | Target | Tool |
|--------|--------|------|
| **BOLA/IDOR** | API endpoints | curl + auth token |
| **Privilege Escalation** | Mass assignment | curl + JSON payload |
| **SQL Injection** | Input fields | sqlmap |
| **XSS** | Form/parameter | dalfox |
| **Credential Exposure** | JS bundles, responses | curl + regex |

### Langkah 5: MITRE + CVSS + UU PDP

Setiap temuan otomatis di-map:
- **MITRE ATT&CK** → Teknik dan taktik serangan
- **CVSS v3.1** → Skor keparahan
- **UU PDP** → Pasal yang dilanggar

### Langkah 6: Report Generation

Laporan lengkap di-generate dalam format Markdown dan PDF:
- Executive summary
- Temuan lengkap dengan bukti
- MITRE ATT&CK chain
- CVSS scores
- UU PDP compliance audit
- Rekomendasi mitigasi

---

## 65 MCP Tools yang Tersedia

### Target & Credential (3 tools)

| Tool | Fungsi | Contoh |
|------|--------|--------|
| `ptg_set_target` | Set target URL + credentials | Target: `192.168.168.10` |
| `ptg_setup_credentials` | Konfigurasi kredensial gray-box | Token, cookie, username |
| `ptg_credential_status` | Cek status kredensial | Configured / Not configured |

### Process Management (4 tools) — BARU v2.0

| Tool | Fungsi | Contoh |
|------|--------|--------|
| `pentest_process_list` | List semua scan yang jalan | `proc-abc123: nmap running` |
| `pentest_process_status` | Cek status scan tertentu | `completed, output: ...` |
| `pentest_process_terminate` | Kill scan yang stuck | `terminated` |
| `pentest_run_async` | Run command di background | `pentest_run_async("nmap", "nmap -sV 10.10.10.13")` |

### Reconnaissance (4 tools)

| Tool | Fungsi | Parameter |
|------|--------|-----------|
| `ptg_nmap_scan` | Scan port dan service | `target`, `scan_type` (quick/service/vuln/os/full/stealth), `ports`, `async_mode` |
| `ptg_ffuf_scan` | Cari hidden endpoint | `target`, `mode` (dir/vhost/api/param), `wordlist`, `async_mode` |
| `ptg_nuclei_scan` | Scan kerentanan | `target`, `severity`, `tags`, `async_mode` |
| `ptg_curl_request` | HTTP request manual | `url`, `method`, `headers`, `data`, `timeout` |

### Exploitation (9 tools)

| Tool | Fungsi | Parameter |
|------|--------|-----------|
| `ptg_test_bola` | Test Broken Object Level Authorization | `target`, `endpoint`, `victim_id`, `auth_token` |
| `ptg_test_idor` | Test Insecure Direct Object Reference | `target`, `endpoint`, `victim_identifier`, `auth_token` |
| `ptg_test_privilege_escalation` | Test eskalasi hak akses | `target`, `endpoint`, `payload`, `auth_token` |
| `ptg_test_session_hijacking` | Test pencurian session | `target`, `endpoint` |
| `ptg_test_credential_exposure` | Test kredensial bocor | `target`, `endpoint` |
| `ptg_test_data_exfiltration` | Test kebocoran data | `target`, `endpoint` |
| `ptg_sqlmap_scan` | SQL injection otomatis | `target`, `method`, `data`, `level`, `risk`, `async_mode` |
| `ptg_dalfox_scan` | XSS otomatis | `target`, `method`, `data`, `async_mode` |

### MITRE ATT&CK (5 tools)

| Tool | Fungsi |
|------|--------|
| `ptg_mitre_map_action` | Map aksi ke MITRE technique + UU PDP |
| `ptg_mitre_list_techniques` | List semua teknik yang terpetakan |
| `ptg_mitre_chain_report` | Generate chain report |
| `ptg_mitre_export_navigator` | Export MITRE Navigator layer (JSON) |
| `ptg_mitre_export_chain` | Export chain report (JSON) |

### CVSS Calculator (3 tools)

| Tool | Fungsi |
|------|--------|
| `ptg_cvss_calculate` | Hitung CVSS dari metrik |
| `ptg_cvss_from_vector` | Hitung CVSS dari vector string |
| `ptg_cvss_common_vectors` | List vector umum |

### UU PDP Compliance (2 tools)

| Tool | Fungsi |
|------|--------|
| `ptg_uu_pdp_query` | Query database UU PDP |
| `ptg_uu_pdp_map_finding` | Map teknik ke pasal UU PDP |

### Wazuh (1 tool)

| Tool | Fungsi |
|------|--------|
| `ptg_wazuh_block_ip` | Generate script block IP di Wazuh |

### Reporting (2 tools)

| Tool | Fungsi |
|------|--------|
| `ptg_findings_summary` | Summary semua temuan |
| `ptg_generate_report` | Generate laporan MD + PDF |

### Session Management (3 tools)

| Tool | Fungsi |
|------|--------|
| `ptg_session_status` | Status sesi pentest |
| `ptg_list_mitre_techniques` | List MITRE techniques |
| `ptg_list_uu_pdp_mappings` | List mapping UU PDP |

### VPN & Connectivity (2 tools)

| Tool | Fungsi |
|------|--------|
| `pentest_check_vpn` | Cek koneksi VPN |
| `pentest_check_connectivity` | Cek target reachable |

### Decision Engine (5 tools)

| Tool | Fungsi |
|------|--------|
| `pentest_analyze_target` | Analisis profil target |
| `pentest_prioritize_paths` | Prioritaskan attack paths |
| `pentest_recommend_tools` | Rekomendasi tools |
| `pentest_list_lab_chains` | List attack chains yang tersedia |
| `pentest_get_chain_detail` | Detail chain tertentu |

### Tool Registry (3 tools)

| Tool | Fungsi |
|------|--------|
| `pentest_list_tools` | List semua tools keamanan |
| `pentest_tool_stats` | Statistik penggunaan tools |
| `pentest_install_hint` | Cara install tool yang missing |

### PTG (3 tools)

| Tool | Fungsi |
|------|--------|
| `pentest_ptg_read` | Baca state PTG |
| `pentest_ptg_update` | Update node PTG |
| `pentest_ptg_stats` | Statistik PTG |

### Summarizer (3 tools)

| Tool | Fungsi |
|------|--------|
| `pentest_summarize` | Kompres output tool jadi summary |
| `pentest_summarize_read` | Baca semua summary |
| `pentest_get_context` | Konsolidasi konteks semua fase |

### EKB (3 tools)

| Tool | Fungsi |
|------|--------|
| `pentest_ekb_query` | Query pola serangan sebelumnya |
| `pentest_ekb_save` | Simpan pola serangan baru |
| `pentest_ekb_list` | List semua entri EKB |

### Vulnerability Correlator (5 tools)

| Tool | Fungsi |
|------|--------|
| `pentest_correlate_findings` | Temukan rantai kerentanan |
| `pentest_add_finding` | Tambah finding untuk korelasi |
| `pentest_recommend_chains` | Rekomendasi chain dari severity |
| `pentest_analyze_chain_potential` | Analisis chain yang mungkin |
| `pentest_list_chain_types` | List tipe chain |

### Self-Reflection (1 tool)

| Tool | Fungsi |
|------|--------|
| `pentest_self_reflect` | Analisis request yang diblok + saran evasion |

### CVE Correlator (2 tools)

| Tool | Fungsi |
|------|--------|
| `pentest_cve_correlate` | Match tech stack ke CVE |
| `pentest_cve_search` | Search CVE by keyword |

### Dashboard (2 tools)

| Tool | Fungsi |
|------|--------|
| `pentest_start_dashboard` | Start dashboard HTTP |
| `pentest_dashboard_status` | Status dashboard |

### Effectiveness Tracker (1 tool)

| Tool | Fungsi |
|------|--------|
| `pentest_effectiveness_stats` | Statistik efektivitas tools |

---

## Fitur v2.0: Async, Cache, Process Management

### Masalah di v1.0

Di versi sebelumnya, saat AI menjalankan scan (misalnya nmap full scan yang bisa 30 menit):
1. **Server freeze** — gak bisa respond ke AI
2. **AI timeout** — disconnect setelah 60-90 detik
3. **Dashboard lag** — compete resource dengan server utama

### Solusi di v2.0

#### 1. Async Process Management

**Sebelum (blocking):**
```python
result = subprocess.check_output("nmap -sV -sC -O -p- 192.168.168.10", timeout=120)
# AI harus nunggu 30 menit di sini — gak bisa ngapa-ngapain
```

**Sesudah (async):**
```python
# AI panggil → langsung dapat PID, bisa lanjut kerja lain
response = ptg_nmap_scan("192.168.168.10", scan_type="full", async_mode=True)
# Response: {"process_id": "proc-abc123", "pid": 12345, "status": "running"}

# AI poll status setiap beberapa detik
status = pentest_process_status("proc-abc123")
# Response: {"status": "completed", "output": "..."}
```

#### 2. Smart Caching

**Cara kerja:**
```
Scan 1: nmap -F -sV 192.168.168.10
→ Run scan (30 detik)
→ Simpan hasil ke cache (TTL: 2 jam)

Scan 2: nmap -F -sV 192.168.168.10  (parameter sama)
→ Check cache → HIT!
→ Return hasil instant (0 detik)
```

**Manfaat:**
- Mengurangi noise ke Wazuh (gak scan berulang kali)
- Hemat waktu (hasil instant)
- Hemat bandwidth

#### 3. Dashboard Terpisah

**Sebelum:** Dashboard jalan di thread yang sama dengan MCP server → compete CPU/memory.

**Sesudah:** Dashboard bisa dijalankan sebagai proses terpisah:
```bash
# Terminal 1: Dashboard
python3 run_server.py --dashboard

# Terminal 2: MCP Server
python3 run_server.py
```

#### 4. Process Management

4 tools baru untuk mengontrol scan:

| Tool | Fungsi | Contoh Output |
|------|--------|---------------|
| `pentest_process_list` | List semua proses | `{"processes": [{"id": "proc-abc", "tool": "nmap", "status": "running"}]}` |
| `pentest_process_status` | Cek status + output | `{"status": "completed", "output": "PORT 22 OPEN..."}` |
| `pentest_process_terminate` | Kill proses | `{"status": "terminated"}` |
| `pentest_run_async` | Run arbitrary command | `{"process_id": "proc-xyz", "pid": 54321}` |

---

## Panduan Penggunaan

### Quick Start

```bash
# 1. Connect VPN
sudo pppd pty "sstpc --nolaunchpppd --user test --password test --cert-warn blackops.surf:6443" user test password test noauth refuse-pap refuse-chap refuse-mschap refuse-eap name sstp-client nodetach

# 2. Start dashboard (opsional)
python3 /home/vedara/Documents/Kelompok\ 7/mcp-pentest-server/src/run_server.py --dashboard

# 3. Buka opencode di folder project
cd /home/vedara/Documents/Kelompok\ 7
opencode

# 4. Jalankan pentest
/pentest
```

### Slash Commands

| Command | Fungsi |
|---------|--------|
| `/pentest` | Full pipeline: recon → exploit → report |
| `/set <target> --token <jwt>` | Set target dan credentials |
| `/audit <scope>` | Audit spesifik (recon/api/auth/full) |
| `/report` | Generate laporan dari findings yang ada |

### Contoh Penggunaan Manual

```
# Set target
Call ptg_set_target with:
  target_url: "192.168.168.10"
  auth_token: "ops_token_here"
  role: "attacker"

# Scan JumpServer (async)
Call ptg_nmap_scan with:
  target: "192.168.168.10"
  scan_type: "stealth"
  async_mode: true

# Poll status
Call pentest_process_status with:
  process_id: "proc-abc123"

# Test BOLA
Call ptg_test_bola with:
  target: "http://192.168.168.10"
  endpoint: "/api/v1/users/"
  victim_id: "admin"
  auth_token: "ops_token_here"

# Generate report
Call ptg_generate_report
```

---

## Attack Chain yang Sudah Didesain

### Chain 1: JumpServer → Internal (Easy)

```
1. VPN Connect → blackops.surf:6443
2. Nmap scan JumpServer (192.168.168.10)
3. Exploit JumpServer CVE / default credentials
4. SSH pivot ke internal network
5. Nmap scan 10.10.10.0/24
6. Exploit Web Server (SQLi/RCE)
7. Access Database
8. Extract PII data
9. MITRE + CVSS + UU PDP mapping
10. Report
```

### Chain 2: API Abuse → Privilege Escalation (Medium)

```
1. VPN Connect
2. Login ke JumpServer dengan ops credentials
3. Enumerate API endpoints (/api/v1/users/, /api/v1/assets/, /api/v1/perms/)
4. Horizontal IDOR — access data user lain
5. Mass assignment — role=ops → role=admin
6. Vertical privilege escalation
7. Access restricted endpoints
8. Extract sensitive data
9. MITRE + CVSS + UU PDP mapping
10. Report
```

### Chain 3: Full Chain (Hard)

```
1. VPN Connect
2. Recon JumpServer + Internal
3. Exploit JumpServer → gain access
4. Pivot ke internal
5. Exploit Web Server → RCE
6. Lateral movement ke Database
7. Dump credentials
8. Access Windows Server (SMB/EternalBlue)
9. Domain Admin → full compromise
10. Extract all evidence
11. MITRE + CVSS + UU PDP mapping
12. Report
```

---

## Mapping ke MITRE ATT&CK dan UU PDP

### Contoh Mapping Lengkap

| Aksi | MITRE Technique | Taktik | UU PDP | CVSS |
|------|----------------|--------|--------|------|
| Login dengan credential | T1078 (Valid Accounts) | Initial Access | Pasal 23, 35, 36, 39, 65 | 7.5 (High) |
| Enumerate user accounts | T1087 (Account Discovery) | Discovery | Pasal 28, 31, 32, 38 | 5.3 (Medium) |
| BOLA/IDOR | T1210 (Remote Services) | Lateral Movement | Pasal 38, 39, 51 | 8.0 (High) |
| Mass assignment | T1068 (Exploit for Priv Esc) | Privilege Escalation | Pasal 35, 36, 39 | 7.2 (High) |
| Extract PII | T1213 (Data from Repos) | Collection | Pasal 16, 35, 38 | 8.5 (High) |
| Exfiltrate data | T1567 (Exfil Over Web Service) | Exfiltration | Pasal 35, 38, 45, 46, 55 | 9.0 (Critical) |
| Exploit CVE | T1210 (Exploit Remote Services) | Lateral Movement | Pasal 35, 36, 39, 67 | 9.8 (Critical) |

### Coverage

- **333 teknik MITRE** terpetakan ke aksi pentest
- **48/48 pasal UU PDP** tercover (100%)
- **1,014 mapping** technique-pasal

---

## Wazuh SIEM dan Evasion

### Apa Itu Wazuh?

Wazuh adalah **SIEM (Security Information and Event Management)** yang memantau semua aktivitas di infrastruktur lab. Jika mendeteksi serangan, Wazuh akan:
1. Generate alert
2. Kirim notifikasi ke **Telegram** tim SOC
3. Bisa trigger **Active Response** (block IP otomatis)

### Cara Menghindari Deteksi

| Teknik | Implementasi |
|--------|-------------|
| **Stealth scan** | `nmap -T1 --scan-delay 5s` (lambat, gak trigger threshold) |
| **Random headers** | Rotasi User-Agent, Accept, dll |
| **Encoding payload** | URL encode, base64, hex encoding |
| **Timing** | Jeda 2-5 detik antar request |
| **Log clearing** | Hapus jejak setelah exploit |

### Wazuh Evasion di Sistem

Sistem punya modul **Self-Reflection** yang otomatis:
1. Deteksi kalau request diblok
2. Analisis metode deteksi Wazuh
3. Sarankan bypass technique
4. Generate payload alternatif

```
pentest_self_reflect(
    agent="nmap",
    blocked_payload="-sV -sC -O",
    response_code=0,
    response_snippet="Connection reset",
    attempt_number=1
)
→ Suggestion: "Try -sS (SYN scan) instead of -sV. Add --scan-delay 5s."
```

---

## Troubleshooting

### VPN Disconnect

**Masalah:** VPN connect tapi gak bisa reach JumpServer.

**Solusi:**
```bash
# 1. Cek interface
ip addr show ppp0

# 2. Tambah route manual
sudo ip route add 192.168.168.0/24 dev ppp0
sudo ip route add 10.10.10.0/24 dev ppp0

# 3. Test connectivity
nc -zv -w 5 192.168.168.10 22
```

### MCP Server Disconnect/Lag

**Masalah:** AI disconnect saat scan berjalan lama.

**Solusi v2.0:** Gunakan async mode:
```
ptg_nmap_scan(target="192.168.168.10", scan_type="full", async_mode=True)
# AI gak freeze, bisa lanjut kerja lain
```

### Dashboard Gak Start

**Masalah:** Port 8080 sudah dipakai.

**Solusi:**
```bash
# Cek port
lsof -i :8080

# Kill proses yang占用
kill -9 <PID>

# Atau start di port lain
python3 server.py --dashboard  # Edit port di http_dashboard.py
```

### Tool Not Found

**Masalah:** `nmap not found`, `ffuf not found`, dll.

**Solusi:**
```bash
# Install missing tools
sudo dnf install nmap
go install github.com/ffuf/ffuf@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

### Cache Stale

**Masalah:** Hasil scan lama, gak update.

**Solusi:**
```bash
# Clear cache
rm -rf /home/vedara/Documents/Kelompok\ 7/mcp-pentest-server/cache/
# Cache akan rebuild otomatis saat scan berikutnya
```

---

## Struktur File

```
Kelompok 7/
├── mcp-pentest-server/
│   └── src/
│       ├── server.py                    # MCP Server utama (65 tools) — v2.0
│       ├── run_server.py                # Wrapper script
│       ├── decision_engine.py           # Otak: tool selection + attack paths
│       ├── tool_registry.py             # Registry 150+ security tools
│       ├── ptg_manager.py               # Progress Testing Graph (18 nodes)
│       ├── summarizer.py                # Output compression
│       ├── ekb_manager.py               # Experience Knowledge Base
│       ├── vulnerability_correlator.py  # Chain discovery
│       ├── self_reflect.py              # Wazuh evasion analysis
│       ├── cve_correlator.py            # Tech stack → CVE matching
│       ├── cache_manager.py             # Smart caching (LRU)
│       ├── http_dashboard.py            # Real-time dashboard
│       ├── effectiveness_tracker.py     # Tool success rate tracking
│       ├── guards.py                    # WAF/Wazuh detection + evasion
│       └── validators.py                # Input validation + lab scope
│
├── scripts/
│   ├── mitre_attack_mapper.py           # MITRE → UU PDP mapping
│   ├── credential_manager.py            # Gray box credentials
│   └── mcp_metasploit.py                # Metasploit MCP server
│
├── agent_orchestrator.py                # AI Agent Orchestrator
├── tools_bridge.py                      # Security Tools Bridge
├── index_uu_pdp.py                      # RAG indexer: PDF → ChromaDB
├── cvss_calculator.py                   # CVSS v3.1 calculator
│
├── db_uu_pdp/                           # ChromaDB vector store (340 chunks)
├── UU Nomor 27 Tahun 2022.pdf           # Source document UU PDP
├── mitre_attack_db.json                 # MITRE STIX database (858 techniques)
│
├── .env.graybox                         # Gray box credentials (gitignored)
├── .opencode/
│   └── opencode.jsonc                   # OpenCode MCP configuration
│
├── skills/
│   ├── api_pentest.md                   # Skill: API Pentester
│   ├── pdp_compliance_auditor.md        # Skill: PDP Compliance Auditor
│   └── mitre_attack_mapper.md           # Skill: MITRE Mapper
│
├── README.md                            # Dokumentasi utama
├── CLAUDE.md                            # AI Agent configuration
├── Rules_of_Engagement.md               # Rules of Engagement
├── GRAYBOX_QUICKSTART.md               # Quick start guide
└── DOKUMENTASI_PROYEK_KELOMPOK_7.md    # Dokumentasi proyek
```

---

## Ringkasan

| Aspek | Detail |
|-------|--------|
| **Nama** | Unified-Shield MCP Pentest Server v2.0 |
| **Tim** | Kelompok 7 — Capstone Project Cybersecurity 2026 |
| **Framework** | MITRE ATT&CK v15 + CVSS v3.1 + UU No. 27/2022 |
| **Total Tools** | 65 MCP tools |
| **MITRE Coverage** | 333 techniques, 14 tactics |
| **UU PDP Coverage** | 48/48 pasal (100%) |
| **Target** | VPN → JumpServer → Internal (10.10.10.0/24) |
| **SIEM** | Wazuh (10.10.10.12) — evasion required |
| **Arsitektur** | Async + Cached + Process Management |
| **Dashboard** | HTTP SSE di port 8080 |

---

*Dokumentasi ini dibuat untuk keperluan akademik Capstone Project Cybersecurity 2026.*
*Terakhir diupdate: Mei 2026*
