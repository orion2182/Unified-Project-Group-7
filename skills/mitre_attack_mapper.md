# Skill: MITRE ATT&CK Mapper & Attack Chain Builder
**ID:** SKILL-MITRE-ATTACK-001
**Description:** Memetakan setiap aksi pentesting ke framework MITRE ATT&CK Enterprise dan mengintegrasikan mapping ke UU PDP No. 27 Tahun 2022.

## 1. Capabilities
- Map pentest actions → MITRE ATT&CK technique ID (real data dari STIX dataset)
- Build attack chains: Initial Access → Discovery → Credential Access → Privilege Escalation → Collection → Exfiltration → Impact
- Generate MITRE ATT&CK Navigator layer JSON untuk visual heatmap
- Cross-reference MITRE techniques → UU PDP articles
- Export chain reports dengan technical + legal mapping

## 2. MITRE → UU PDP Mapping Logic

| MITRE Tactic | Technique Examples | UU PDP Articles | Legal Risk |
|-------------|-------------------|-----------------|------------|
| **Initial Access** | T1078 (Valid Accounts), T1190 (Exploit Public App) | Pasal 39 | Akses tidak sah terhadap data pribadi |
| **Reconnaissance** | T1595 (Active Scanning) | Pasal 31 | Pengumpulan informasi tanpa otorisasi |
| **Discovery** | T1087 (Account Discovery), T1046 (Service Discovery) | Pasal 38, 39 | Penemuan akun/data tanpa otorisasi |
| **Credential Access** | T1539 (Steal Cookie), T1552 (Unsecured Creds) | Pasal 35, 39 | Pencurian kredensial, keamanan tidak memadai |
| **Privilege Escalation** | T1068 (Exploit for Priv Esc), T1098 (Account Manipulation) | Pasal 35, 39 | Eskalasi hak akses ke data pribadi |
| **Lateral Movement** | T1210 (Remote Services Exploitation) | Pasal 38, 39 | Pergerakan lateral ke data pribadi |
| **Collection** | T1005 (Local System Data), T1213 (Info Repositories) | Pasal 35, 38 | Pengumpulan data tanpa otorisasi |
| **Exfiltration** | T1567 (Over Web Service), T1041 (Over C2) | Pasal 35, 46 | Eksfiltrasi data pribadi |
| **Impact** | T1486 (Data Encrypted), T1485 (Data Destruction) | Pasal 35, 46, 57 | Kerusakan data pribadi, sanksi administratif |
| **Defense Evasion** | T1070 (Indicator Removal), T1562 (Impair Defenses) | Pasal 31, 35 | Penghambatan audit dan deteksi |

## 3. Workflow Execution Steps

### Phase 1: Gray Box Setup
```
1. Login dengan credentials → T1078 (Valid Accounts)
2. Capture session details → T1539 (Session Cookie)
3. Map accessible endpoints → T1046 (Service Discovery)
```

### Phase 2: Discovery & Enumeration
```
1. Account discovery → T1087 (Account Discovery)
2. Permission discovery → T1069 (Permission Groups Discovery)
3. API endpoint fuzzing → T1595 (Active Scanning)
4. Data model mapping → T1087.004 (Cloud Account Discovery)
```

### Phase 3: Exploitation
```
1. IDOR/BOLA testing → T1210 (Remote Services Exploitation)
2. Mass assignment → T1098 (Account Manipulation)
3. Privilege escalation → T1068 (Exploitation for Priv Esc)
4. Credential theft → T1552 (Unsecured Credentials)
```

### Phase 4: Impact Assessment
```
1. Data collection → T1005 (Data from Local System)
2. Data exfiltration simulation → T1567 (Over Web Service)
3. Impact analysis → T1485/T1486 (Data Destruction/Encryption)
```

## 4. Integration Commands

### Python API
```python
from scripts.mitre_attack_mapper import MitreAttackMapper

mapper = MitreAttackMapper()

# Map single action
result = mapper.map_action("login_with_credentials", evidence="Staff login OK", severity="Medium")

# Build attack chain
chain = mapper.create_chain("graybox-001", "https://target.api")
mapper.add_to_chain("graybox-001", "login_with_credentials", "Login OK", "Medium")
mapper.add_to_chain("graybox-001", "account_discovery", "Found 50 users", "Medium")
mapper.add_to_chain("graybox-001", "privilege_escalation_exploit", "Role changed to admin", "Critical")

# Generate reports
report = mapper.get_chain_report("graybox-001")
mapper.export_navigator_layer("graybox-001", "navigator-layer.json")
```

### CLI Usage
```bash
# Map single action
python scripts/mitre_attack_mapper.py login_with_credentials "Staff login OK" "Medium"

# List all available actions
python scripts/mitre_attack_mapper.py --list
```

## 5. ATT&CK Navigator Integration

1. Generate layer JSON: `mapper.export_navigator_layer(chain_id, output_path)`
2. Open https://mitre-attack.github.io/attack-navigator/
3. Load layer JSON
4. Visual heatmap akan show:
   - Red: Initial Access techniques
   - Yellow: Discovery techniques
   - Magenta: Credential Access
   - Orange: Privilege Escalation
   - Cyan: Collection
   - Blue: Exfiltration
   - Purple: Impact

## 6. Report Template (MITRE + UU PDP)

### [CHAIN-ID] Attack Chain Report
**Target:** {target_url}
**Chain ID:** {chain_id}
**Techniques Mapped:** {count}
**Tactics Covered:** {tactics}

#### Technique Sequence
| # | Technique ID | Technique Name | Tactic | UU PDP | Risk |
|---|-------------|---------------|--------|--------|------|
| 1 | T1078 | Valid Accounts | Initial Access | Pasal 39 | Akses tidak sah |
| 2 | T1087 | Account Discovery | Discovery | Pasal 38, 39 | Penemuan akun |

#### Legal Mapping Summary
- **Pasal 35:** Keamanan data pribadi (X techniques)
- **Pasal 38:** Hak data subject (X techniques)
- **Pasal 39:** Larangan akses tidak sah (X techniques)
- **Pasal 46:** Notifikasi kegagalan (X techniques)
- **Pasal 57:** Sanksi administratif (X techniques)

#### ATT&CK Navigator Layer
- File: `{chain_id}-navigator.json`
- Load di: https://mitre-attack.github.io/attack-navigator/

## 7. Available Pentest Actions (60+ mappings)

### Initial Access (2)
- `login_with_credentials` → T1078
- `exploit_public_app` → T1190

### Reconnaissance (3)
- `active_scanning` → T1595
- `vulnerability_scanning` → T1595.001
- `subdomain_enumeration` → T1595.002

### Discovery (5)
- `account_discovery` → T1087
- `cloud_account_discovery` → T1087.004
- `api_endpoint_discovery` → T1046
- `permission_discovery` → T1069
- `cloud_infrastructure_discovery` → T1580

### Credential Access (5)
- `steal_session_cookie` → T1539
- `steal_access_token` → T1528
- `unsecured_credentials` → T1552
- `brute_force` → T1110
- `credential_stuffing` → T1110.004

### Privilege Escalation (3)
- `privilege_escalation_exploit` → T1068
- `account_manipulation` → T1098
- `valid_accounts_cloud` → T1078.004

### Lateral Movement (2)
- `lateral_movement_api` → T1210
- `internal_service_exploitation` → T1210

### Collection (5)
- `data_from_local_system` → T1005
- `data_from_info_repos` → T1213
- `data_from_cloud_storage` → T1530
- `data_staged` → T1074
- `archive_collected_data` → T1560

### Exfiltration (3)
- `exfiltration_over_web_service` → T1567
- `exfiltration_over_c2` → T1041
- `exfiltration_over_alternative_protocol` → T1048

### Impact (4)
- `data_encrypted_impact` → T1486
- `data_destruction` → T1485
- `defacement` → T1491
- `endpoint_denial_of_service` → T1499

### Defense Evasion (3)
- `indicator_removal` → T1070
- `impair_defenses` → T1562
- `obfuscated_files` → T1027

### Execution (2)
- `command_and_script_interpreter` → T1059
- `serverless_execution` → T1648

### Persistence (2)
- `create_account` → T1136
- `external_remote_services` → T1133
