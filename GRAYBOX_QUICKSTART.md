# Gray Box Testing — Quick Start

## Cara Pakai

### 1. Setup Credentials (sekali aja)

```bash
# Interactive setup
python run_graybox.py --setup

# Atau edit langsung
nano .env.graybox
```

### 2. Jalankan Pentest

```bash
# Pakai credentials yang udah disimpen
python run_graybox.py

# Atau quick run tanpa setup
python run_graybox.py --target https://target.api --token "jms_sessionid=abc123"

# Dengan proxy Burp Suite
python run_graybox.py --proxy http://127.0.0.1:8080
```

### 3. Cek Status

```bash
python run_graybox.py --status
```

## Output

Setelah running, laporan otomatis tersimpan:

```
├── graybox-<chain>-report.md       # Full report (MITRE + UU PDP)
├── graybox-<chain>-navigator.json  # ATT&CK Navigator layer
└── graybox-<chain>-chain.json      # Chain report JSON
```

## Credential File

`.env.graybox` — **TIDAK** di-commit ke git (sudah di-gitignore).

Format:
```ini
TARGET_URL=https://api.bank-pdp.local
AUTH_METHOD=cookie
SESSION_COOKIE=jms_sessionid=your_session_id

# Multi-account untuk IDOR testing
ATTACKER_USERNAME=staff
ATTACKER_PASSWORD=staff_pass
VICTIM_USERNAME=victim
VICTIM_PASSWORD=victim_pass
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin_pass
```

## Workflow

```
1. Setup credentials  →  python run_graybox.py --setup
2. Run pentest        →  python run_graybox.py
3. Review report      →  cat graybox-*-report.md
4. Visualize MITRE    →  Load navigator.json ke attack.mitre.org
```
