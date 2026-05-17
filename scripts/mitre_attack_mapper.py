#!/usr/bin/env python3
"""MITRE ATT&CK Mapper for Gray Box Pentesting.

Maps pentest actions → MITRE ATT&CK techniques → UU PDP articles.
Uses real MITRE STIX data from enterprise-attack.json.
"""

import json
import os
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path


# ============================================================
# Constants: Pentest Action → MITRE Technique Mapping
# ============================================================

PENTEST_ACTION_MAP = {
    # Initial Access
    "login_with_credentials": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "subtechnique": None,
        "tactic": "initial-access",
        "description": "Using valid credentials to gain initial access to the system"
    },
    "exploit_public_app": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "subtechnique": None,
        "tactic": "initial-access",
        "description": "Exploiting vulnerabilities in internet-facing applications"
    },
    "sql_injection": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "subtechnique": None,
        "tactic": "initial-access",
        "description": "SQL injection in web application"
    },
    "xss_attack": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "subtechnique": None,
        "tactic": "initial-access",
        "description": "Cross-site scripting in web application"
    },

    # Reconnaissance
    "active_scanning": {
        "technique_id": "T1595",
        "technique_name": "Active Scanning",
        "subtechnique": None,
        "tactic": "reconnaissance",
        "description": "Scanning target infrastructure for vulnerabilities"
    },
    "vulnerability_scanning": {
        "technique_id": "T1595.001",
        "technique_name": "Active Scanning: Scanning IP Blocks",
        "subtechnique": "001",
        "tactic": "reconnaissance",
        "description": "Scanning IP ranges for live hosts and services"
    },
    "subdomain_enumeration": {
        "technique_id": "T1595.002",
        "technique_name": "Active Scanning: Vulnerability Scanning",
        "subtechnique": "002",
        "tactic": "reconnaissance",
        "description": "Enumerating subdomains and attack surface"
    },

    # Discovery
    "account_discovery": {
        "technique_id": "T1087",
        "technique_name": "Account Discovery",
        "subtechnique": None,
        "tactic": "discovery",
        "description": "Discovering valid accounts on the system"
    },
    "cloud_account_discovery": {
        "technique_id": "T1087.004",
        "technique_name": "Account Discovery: Cloud Account",
        "subtechnique": "004",
        "tactic": "discovery",
        "description": "Discovering cloud accounts and roles"
    },
    "api_endpoint_discovery": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "subtechnique": None,
        "tactic": "discovery",
        "description": "Discovering API endpoints and services"
    },
    "permission_discovery": {
        "technique_id": "T1069",
        "technique_name": "Permission Groups Discovery",
        "subtechnique": None,
        "tactic": "discovery",
        "description": "Discovering user permissions and roles"
    },
    "cloud_infrastructure_discovery": {
        "technique_id": "T1580",
        "technique_name": "Cloud Infrastructure Discovery",
        "subtechnique": None,
        "tactic": "discovery",
        "description": "Discovering cloud infrastructure resources"
    },

    # Credential Access
    "steal_session_cookie": {
        "technique_id": "T1539",
        "technique_name": "Steal Web Session Cookie",
        "subtechnique": None,
        "tactic": "credential-access",
        "description": "Stealing web session cookies for authentication bypass"
    },
    "steal_access_token": {
        "technique_id": "T1528",
        "technique_name": "Steal Application Access Token",
        "subtechnique": None,
        "tactic": "credential-access",
        "description": "Stealing application access tokens"
    },
    "unsecured_credentials": {
        "technique_id": "T1552",
        "technique_name": "Unsecured Credentials",
        "subtechnique": None,
        "tactic": "credential-access",
        "description": "Finding credentials stored insecurely"
    },
    "brute_force": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "subtechnique": None,
        "tactic": "credential-access",
        "description": "Brute forcing authentication"
    },
    "credential_stuffing": {
        "technique_id": "T1110.004",
        "technique_name": "Brute Force: Credential Stuffing",
        "subtechnique": "004",
        "tactic": "credential-access",
        "description": "Using leaked credentials from other breaches"
    },

    # Privilege Escalation
    "privilege_escalation_exploit": {
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "subtechnique": None,
        "tactic": "privilege-escalation",
        "description": "Exploiting vulnerability to escalate privileges"
    },
    "account_manipulation": {
        "technique_id": "T1098",
        "technique_name": "Account Manipulation",
        "subtechnique": None,
        "tactic": "privilege-escalation",
        "description": "Manipulating accounts to maintain or elevate access"
    },
    "valid_accounts_cloud": {
        "technique_id": "T1078.004",
        "technique_name": "Valid Accounts: Cloud Accounts",
        "subtechnique": "004",
        "tactic": "privilege-escalation",
        "description": "Using cloud accounts for privilege escalation"
    },

    # Lateral Movement
    "lateral_movement_api": {
        "technique_id": "T1210",
        "technique_name": "Exploitation of Remote Services",
        "subtechnique": None,
        "tactic": "lateral-movement",
        "description": "Moving laterally via API exploitation"
    },
    "internal_service_exploitation": {
        "technique_id": "T1210",
        "technique_name": "Exploitation of Remote Services",
        "subtechnique": None,
        "tactic": "lateral-movement",
        "description": "Exploiting internal services after initial access"
    },

    # Collection
    "data_from_local_system": {
        "technique_id": "T1005",
        "technique_name": "Data from Local System",
        "subtechnique": None,
        "tactic": "collection",
        "description": "Collecting data from local system sources"
    },
    "data_from_info_repos": {
        "technique_id": "T1213",
        "technique_name": "Data from Information Repositories",
        "subtechnique": None,
        "tactic": "collection",
        "description": "Mining data from information repositories"
    },
    "data_from_cloud_storage": {
        "technique_id": "T1530",
        "technique_name": "Data from Cloud Storage",
        "subtechnique": None,
        "tactic": "collection",
        "description": "Accessing data from cloud storage"
    },
    "data_staged": {
        "technique_id": "T1074",
        "technique_name": "Data Staged",
        "subtechnique": None,
        "tactic": "collection",
        "description": "Staging collected data before exfiltration"
    },
    "archive_collected_data": {
        "technique_id": "T1560",
        "technique_name": "Archive Collected Data",
        "subtechnique": None,
        "tactic": "collection",
        "description": "Compressing/encrypting collected data"
    },

    # Exfiltration
    "exfiltration_over_web_service": {
        "technique_id": "T1567",
        "technique_name": "Exfiltration Over Web Service",
        "subtechnique": None,
        "tactic": "exfiltration",
        "description": "Exfiltrating data over web services"
    },
    "exfiltration_over_c2": {
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "subtechnique": None,
        "tactic": "exfiltration",
        "description": "Exfiltrating data over command and control channel"
    },
    "exfiltration_over_alternative_protocol": {
        "technique_id": "T1048",
        "technique_name": "Exfiltration Over Alternative Protocol",
        "subtechnique": None,
        "tactic": "exfiltration",
        "description": "Exfiltrating data over alternative protocols"
    },

    # Impact
    "data_encrypted_impact": {
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "subtechnique": None,
        "tactic": "impact",
        "description": "Encrypting data to impact availability"
    },
    "data_destruction": {
        "technique_id": "T1485",
        "technique_name": "Data Destruction",
        "subtechnique": None,
        "tactic": "impact",
        "description": "Destroying data to impact availability"
    },
    "defacement": {
        "technique_id": "T1491",
        "technique_name": "Defacement",
        "subtechnique": None,
        "tactic": "impact",
        "description": "Defacing web application or system"
    },
    "endpoint_denial_of_service": {
        "technique_id": "T1499",
        "technique_name": "Endpoint Denial of Service",
        "subtechnique": None,
        "tactic": "impact",
        "description": "Denial of service against endpoint"
    },

    # Defense Evasion
    "indicator_removal": {
        "technique_id": "T1070",
        "technique_name": "Indicator Removal",
        "subtechnique": None,
        "tactic": "defense-evasion",
        "description": "Removing indicators of compromise"
    },
    "impair_defenses": {
        "technique_id": "T1562",
        "technique_name": "Impair Defenses",
        "subtechnique": None,
        "tactic": "defense-evasion",
        "description": "Impairing security defenses"
    },
    "obfuscated_files": {
        "technique_id": "T1027",
        "technique_name": "Obfuscated Files or Information",
        "subtechnique": None,
        "tactic": "defense-evasion",
        "description": "Obfuscating files or information to evade detection"
    },

    # Execution
    "command_and_script_interpreter": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "subtechnique": None,
        "tactic": "execution",
        "description": "Using command and script interpreters to execute commands"
    },
    "serverless_execution": {
        "technique_id": "T1648",
        "technique_name": "Serverless Execution",
        "subtechnique": None,
        "tactic": "execution",
        "description": "Executing code via serverless functions"
    },

    # Persistence
    "create_account": {
        "technique_id": "T1136",
        "technique_name": "Create Account",
        "subtechnique": None,
        "tactic": "persistence",
        "description": "Creating account for persistence"
    },
    "external_remote_services": {
        "technique_id": "T1133",
        "technique_name": "External Remote Services",
        "subtechnique": None,
        "tactic": "persistence",
        "description": "Using external remote services for persistence"
    },

    # Additional common pentest actions
    "bola": {
        "technique_id": "T1210",
        "technique_name": "Exploitation of Remote Services",
        "subtechnique": None,
        "tactic": "lateral-movement",
        "description": "Broken Object Level Authorization (BOLA/IDOR) exploitation"
    },
    "rce": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "subtechnique": None,
        "tactic": "initial-access",
        "description": "Remote Code Execution via application exploitation"
    },
    "data_exfiltration": {
        "technique_id": "T1567",
        "technique_name": "Exfiltration Over Web Service",
        "subtechnique": None,
        "tactic": "exfiltration",
        "description": "Data exfiltration via web services or APIs"
    },
}


# ============================================================
# MITRE → UU PDP Mapping
# ============================================================

MITRE_UU_PDP_MAP = {
    "T1003": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "OS credential dumping"},
    "T1003.001": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "LSASS memory credential dumping"},
    "T1003.002": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Security account manager dumping"},
    "T1003.003": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "NTDS credential dumping"},
    "T1003.004": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "LSA secret extraction"},
    "T1003.005": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Cached domain credentials"},
    "T1003.006": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "DCSync credential extraction"},
    "T1003.007": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "ProcFS credential extraction"},
    "T1003.008": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "/etc/passwd and /etc/shadow extraction"},
    "T1005": {"pasal": ["Pasal 16", "Pasal 27", "Pasal 35", "Pasal 38"], "risk": "Pengumpulan data dari sistem lokal tanpa otorisasi (melanggar Pasal 16: pemrosesan data terbatas pada tujuan, Pasal 35: keamanan data)"},
    "T1011": {"pasal": ["Pasal 35", "Pasal 38", "Pasal 46"], "risk": "Exfiltration over other network medium"},
    "T1011.001": {"pasal": ["Pasal 35", "Pasal 38", "Pasal 46"], "risk": "Exfiltration over Bluetooth"},
    "T1016": {"pasal": ["Pasal 31", "Pasal 38"], "risk": "System network configuration discovery"},
    "T1018": {"pasal": ["Pasal 31", "Pasal 38"], "risk": "Remote system discovery"},
    "T1020": {"pasal": ["Pasal 35", "Pasal 38", "Pasal 46"], "risk": "Automated exfiltration"},
    "T1020.001": {"pasal": ["Pasal 35", "Pasal 38", "Pasal 46"], "risk": "Traffic duplication"},
    "T1021": {"pasal": ["Pasal 38", "Pasal 39"], "risk": "Remote services untuk lateral movement"},
    "T1021.001": {"pasal": ["Pasal 38", "Pasal 39"], "risk": "Remote desktop protocol"},
    "T1021.002": {"pasal": ["Pasal 38", "Pasal 39"], "risk": "SMB/Windows admin shares"},
    "T1021.003": {"pasal": ["Pasal 38", "Pasal 39"], "risk": "Distributed Component Object Model"},
    "T1021.004": {"pasal": ["Pasal 38", "Pasal 39"], "risk": "SSH"},
    "T1021.005": {"pasal": ["Pasal 38", "Pasal 39"], "risk": "VNC"},
    "T1021.006": {"pasal": ["Pasal 38", "Pasal 39"], "risk": "Windows remote management"},
    "T1021.007": {"pasal": ["Pasal 38", "Pasal 39"], "risk": "Cloud services"},
    "T1021.008": {"pasal": ["Pasal 38", "Pasal 39"], "risk": "Direct cloud VM connections"},
    "T1027": {"pasal": ["Pasal 31", "Pasal 33", "Pasal 35", "Pasal 36", "Pasal 37", "Pasal 47"], "risk": "Obfuscasi file atau informasi untuk menghindari deteksi (melanggar Pasal 31: perekaman kegiatan, Pasal 35: keamanan data)"},
    "T1027.001": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Binary padding"},
    "T1027.002": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Software packing"},
    "T1027.003": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Steganography"},
    "T1027.004": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Compile after delivery"},
    "T1027.005": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Indicator removal from tools"},
    "T1027.006": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "HTML smuggling"},
    "T1027.007": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Dynamic API resolution"},
    "T1027.008": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Stripped payloads"},
    "T1027.009": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Embedded payload"},
    "T1027.010": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Command obfuscation"},
    "T1027.011": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Fileless storage"},
    "T1027.012": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "LNK icon obfuscation"},
    "T1027.013": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Arbitrary code encoding"},
    "T1029": {"pasal": ["Pasal 35", "Pasal 38", "Pasal 46"], "risk": "Scheduled transfer"},
    "T1030": {"pasal": ["Pasal 35", "Pasal 38", "Pasal 46"], "risk": "Data transfer size limits"},
    "T1039": {"pasal": ["Pasal 16", "Pasal 35", "Pasal 38"], "risk": "Data from network shared drive"},
    "T1040": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 38", "Pasal 39"], "risk": "Network sniffing untuk intercept kredensial"},
    "T1041": {"pasal": ["Pasal 35", "Pasal 38", "Pasal 46"], "risk": "Eksfiltrasi data melalui channel C2 (melanggar Pasal 35, 38, 46)"},
    "T1046": {"pasal": ["Pasal 31", "Pasal 38"], "risk": "Discovery layanan jaringan tanpa otorisasi (melanggar Pasal 31: perekaman kegiatan)"},
    "T1048": {"pasal": ["Pasal 35", "Pasal 38", "Pasal 46"], "risk": "Eksfiltrasi data melalui protokol alternatif (melanggar Pasal 35, 38, 46)"},
    "T1048.001": {"pasal": ["Pasal 35", "Pasal 38", "Pasal 46"], "risk": "Exfiltration over symmetric encrypted non-C2 protocol"},
    "T1048.002": {"pasal": ["Pasal 35", "Pasal 38", "Pasal 46"], "risk": "Exfiltration over asymmetric encrypted non-C2 protocol"},
    "T1048.003": {"pasal": ["Pasal 35", "Pasal 38", "Pasal 46"], "risk": "Exfiltration over unencrypted non-C2 protocol"},
    "T1052": {"pasal": ["Pasal 35", "Pasal 38", "Pasal 46"], "risk": "Exfiltration over physical medium"},
    "T1052.001": {"pasal": ["Pasal 35", "Pasal 38", "Pasal 46"], "risk": "Exfiltration over USB"},
    "T1056": {"pasal": ["Pasal 16", "Pasal 26", "Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Input capture terhadap data disabilitas melanggar Pasal 26: pemrosesan data pribadi penyandang disabilitas"},
    "T1056.001": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Keylogging"},
    "T1056.002": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "GUI input capture"},
    "T1056.003": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Web portal capture"},
    "T1056.004": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Credential API hooking"},
    "T1057": {"pasal": ["Pasal 31", "Pasal 38"], "risk": "Process discovery"},
    "T1059": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Command and script interpreter untuk eksekusi kode berbahaya (melanggar Pasal 35: keamanan data, Pasal 36: langkah teknis, Pasal 39: pencegahan akses tidak sah)"},
    "T1059.001": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "PowerShell execution"},
    "T1059.002": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "AppleScript execution"},
    "T1059.003": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Windows command shell"},
    "T1059.004": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Unix shell"},
    "T1059.005": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Visual Basic execution"},
    "T1059.006": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Python execution"},
    "T1059.007": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "JavaScript execution"},
    "T1059.008": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Network device CLI"},
    "T1059.009": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Cloud API execution"},
    "T1059.010": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "AutoHotkey/AutoIT"},
    "T1068": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Eksploitasi kerentanan untuk eskalasi hak akses ke data pribadi (melanggar Pasal 35: keamanan data, Pasal 36: langkah teknis, Pasal 39: pencegahan akses tidak sah)"},
    "T1069": {"pasal": ["Pasal 28", "Pasal 32", "Pasal 38"], "risk": "Discovery permission groups dan akses data (melanggar Pasal 28: pemrosesan terbatas)"},
    "T1069.001": {"pasal": ["Pasal 28", "Pasal 32", "Pasal 38"], "risk": "Discovery local groups tanpa otorisasi"},
    "T1069.002": {"pasal": ["Pasal 28", "Pasal 32", "Pasal 38"], "risk": "Discovery domain groups tanpa otorisasi"},
    "T1069.003": {"pasal": ["Pasal 28", "Pasal 32", "Pasal 38"], "risk": "Discovery cloud groups tanpa otorisasi"},
    "T1070": {"pasal": ["Pasal 31", "Pasal 33", "Pasal 35", "Pasal 36", "Pasal 47", "Pasal 49", "Pasal 54"], "risk": "Penghapusan indikator kompromi yang menghambat audit trail (melanggar Pasal 31: perekaman kegiatan, Pasal 35: keamanan data, Pasal 36: langkah teknis)"},
    "T1070.001": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Clear Windows event logs"},
    "T1070.002": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Clear Linux/Mac system logs"},
    "T1070.003": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Clear command history"},
    "T1070.004": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "File deletion"},
    "T1070.005": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Network share connection removal"},
    "T1070.006": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Timestomp"},
    "T1070.007": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Clear mail server data"},
    "T1070.008": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Clear cloud account activity logs"},
    "T1070.009": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Clear persistence mechanisms"},
    "T1071": {"pasal": ["Pasal 19", "Pasal 31", "Pasal 35", "Pasal 38", "Pasal 51"], "risk": "Application layer protocol C2 melanggar Pasal 19: pengendali dan prosesor data pribadi"},
    "T1071.001": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 38"], "risk": "Web protocols C2"},
    "T1071.002": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 38"], "risk": "File transfer protocols C2"},
    "T1071.003": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 38"], "risk": "Mail protocols C2"},
    "T1071.004": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 38"], "risk": "DNS C2"},
    "T1072": {"pasal": ["Pasal 38", "Pasal 39"], "risk": "Software deployment tools untuk lateral movement"},
    "T1074": {"pasal": ["Pasal 16", "Pasal 35", "Pasal 38"], "risk": "Staging data sebelum eksfiltrasi (melanggar Pasal 16: pemrosesan data)"},
    "T1074.001": {"pasal": ["Pasal 16", "Pasal 35", "Pasal 38"], "risk": "Local data staging"},
    "T1074.002": {"pasal": ["Pasal 16", "Pasal 35", "Pasal 38"], "risk": "Remote data staging"},
    "T1078": {"pasal": ["Pasal 23", "Pasal 35", "Pasal 36", "Pasal 39", "Pasal 65"], "risk": "Akses tidak sah terhadap data pribadi menggunakan kredensial valid (melanggar Pasal 39: pencegahan akses tidak sah, Pasal 65: larangan memperoleh data pribadi bukan miliknya)"},
    "T1078.001": {"pasal": ["Pasal 39", "Pasal 65", "Pasal 67"], "risk": "Penyalahgunaan kredensial default/known untuk akses tidak sah"},
    "T1078.002": {"pasal": ["Pasal 39", "Pasal 65", "Pasal 67"], "risk": "Penyalahgunaan kredensial domain untuk akses tidak sah"},
    "T1078.003": {"pasal": ["Pasal 39", "Pasal 65", "Pasal 67"], "risk": "Penyalahgunaan kredensial lokal untuk akses tidak sah"},
    "T1078.004": {"pasal": ["Pasal 39", "Pasal 56", "Pasal 65", "Pasal 67"], "risk": "Penyalahgunaan akun cloud untuk akses tidak sah dan transfer data lintas batas"},
    "T1080": {"pasal": ["Pasal 38", "Pasal 39"], "risk": "Tainted shared content"},
    "T1082": {"pasal": ["Pasal 31", "Pasal 38"], "risk": "System information discovery"},
    "T1083": {"pasal": ["Pasal 31", "Pasal 38"], "risk": "File and directory discovery"},
    "T1087": {"pasal": ["Pasal 32", "Pasal 38", "Pasal 39"], "risk": "Penemuan akun dan data pengguna tanpa otorisasi (melanggar Pasal 32: hak akses subjek data, Pasal 38: perlindungan dari pemrosesan tidak sah)"},
    "T1087.001": {"pasal": ["Pasal 32", "Pasal 38", "Pasal 39"], "risk": "Penemuan akun lokal tanpa otorisasi"},
    "T1087.002": {"pasal": ["Pasal 32", "Pasal 38", "Pasal 39"], "risk": "Penemuan akun domain tanpa otorisasi"},
    "T1087.003": {"pasal": ["Pasal 32", "Pasal 38", "Pasal 39"], "risk": "Penemuan akun email tanpa otorisasi"},
    "T1087.004": {"pasal": ["Pasal 32", "Pasal 38", "Pasal 39", "Pasal 56"], "risk": "Penemuan akun cloud tanpa otorisasi dan potensi transfer data lintas batas"},
    "T1090": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 38"], "risk": "Proxy untuk C2"},
    "T1090.001": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 38"], "risk": "Internal proxy"},
    "T1090.002": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 38"], "risk": "External proxy"},
    "T1090.003": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 38"], "risk": "Multi-hop proxy"},
    "T1090.004": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 38"], "risk": "Domain fronting"},
    "T1091": {"pasal": ["Pasal 38", "Pasal 39"], "risk": "Replication through removable media"},
    "T1092": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 38"], "risk": "Communication through removable media"},
    "T1098": {"pasal": ["Pasal 28", "Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Manipulasi akun untuk mempertahankan atau meningkatkan akses (melanggar Pasal 28: pemrosesan terbatas, Pasal 39: pencegahan akses tidak sah)"},
    "T1098.001": {"pasal": ["Pasal 28", "Pasal 35", "Pasal 39"], "risk": "Additional cloud credentials"},
    "T1098.002": {"pasal": ["Pasal 28", "Pasal 35", "Pasal 39"], "risk": "Additional email delegate permissions"},
    "T1098.003": {"pasal": ["Pasal 28", "Pasal 35", "Pasal 39"], "risk": "Additional cloud roles"},
    "T1098.004": {"pasal": ["Pasal 28", "Pasal 35", "Pasal 39"], "risk": "SSH authorized keys modification"},
    "T1098.005": {"pasal": ["Pasal 28", "Pasal 35", "Pasal 39"], "risk": "Device registration"},
    "T1102": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 38"], "risk": "Web service C2"},
    "T1102.001": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 38"], "risk": "Dead drop resolver"},
    "T1102.002": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 38"], "risk": "Bidirectional communication"},
    "T1102.003": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 38"], "risk": "One-way communication"},
    "T1104": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 38"], "risk": "Multi-stage channels"},
    "T1105": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 38"], "risk": "Ingress tool transfer"},
    "T1110": {"pasal": ["Pasal 25", "Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Brute force terhadap sistem autentikasi (melanggar Pasal 35: keamanan data, Pasal 39: pencegahan akses tidak sah)"},
    "T1110.001": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Password guessing"},
    "T1110.002": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Password cracking"},
    "T1110.003": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Password spraying"},
    "T1110.004": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Credential stuffing menggunakan kredensial dari breach lain"},
    "T1113": {"pasal": ["Pasal 16", "Pasal 17", "Pasal 35", "Pasal 38"], "risk": "Screen capture melanggar Pasal 17: pemasangan alat pemroses data visual di tempat umum harus sesuai ketentuan"},
    "T1114": {"pasal": ["Pasal 16", "Pasal 35", "Pasal 38"], "risk": "Email collection"},
    "T1114.001": {"pasal": ["Pasal 16", "Pasal 35", "Pasal 38"], "risk": "Local email collection"},
    "T1114.002": {"pasal": ["Pasal 16", "Pasal 35", "Pasal 38"], "risk": "Remote email collection"},
    "T1114.003": {"pasal": ["Pasal 16", "Pasal 35", "Pasal 38"], "risk": "Email forward rule"},
    "T1115": {"pasal": ["Pasal 16", "Pasal 35", "Pasal 38"], "risk": "Clipboard data collection"},
    "T1119": {"pasal": ["Pasal 16", "Pasal 35", "Pasal 38"], "risk": "Automated collection"},
    "T1120": {"pasal": ["Pasal 31", "Pasal 38"], "risk": "Peripheral device discovery"},
    "T1123": {"pasal": ["Pasal 16", "Pasal 35", "Pasal 38"], "risk": "Audio capture"},
    "T1125": {"pasal": ["Pasal 16", "Pasal 17", "Pasal 35", "Pasal 38"], "risk": "Video capture melanggar Pasal 17: pemrosesan data visual tanpa persetujuan"},
    "T1132": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 38"], "risk": "Data encoding"},
    "T1132.001": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 38"], "risk": "Standard encoding"},
    "T1132.002": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 38"], "risk": "Non-standard encoding"},
    "T1133": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39", "Pasal 51"], "risk": "External remote services melalui prosesor melanggar Pasal 51"},
    "T1134": {"pasal": ["Pasal 28", "Pasal 35", "Pasal 39"], "risk": "Access token manipulation"},
    "T1134.001": {"pasal": ["Pasal 28", "Pasal 35", "Pasal 39"], "risk": "Token impersonation/theft"},
    "T1134.002": {"pasal": ["Pasal 28", "Pasal 35", "Pasal 39"], "risk": "Create process with token"},
    "T1134.003": {"pasal": ["Pasal 28", "Pasal 35", "Pasal 39"], "risk": "Make and impersonate token"},
    "T1134.004": {"pasal": ["Pasal 28", "Pasal 35", "Pasal 39"], "risk": "Parent PID spoofing"},
    "T1134.005": {"pasal": ["Pasal 28", "Pasal 35", "Pasal 39"], "risk": "SID-history injection"},
    "T1135": {"pasal": ["Pasal 31", "Pasal 38"], "risk": "Network share discovery"},
    "T1136": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Pembuatan akun untuk persistensi akses tidak sah (melanggar Pasal 35: keamanan data, Pasal 36: langkah teknis, Pasal 39: pencegahan akses tidak sah)"},
    "T1136.001": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Local account creation"},
    "T1136.002": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Domain account creation"},
    "T1136.003": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Cloud account creation"},
    "T1137": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Office application startup"},
    "T1176": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Browser extensions"},
    "T1185": {"pasal": ["Pasal 16", "Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Browser session hijacking"},
    "T1190": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Eksploitasi kerentanan aplikasi publik yang memproses data pribadi (melanggar Pasal 35: kewajiban melindungi data, Pasal 36: langkah teknis keamanan)"},
    "T1197": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "BITS jobs untuk defense evasion"},
    "T1201": {"pasal": ["Pasal 31", "Pasal 38"], "risk": "Password policy discovery"},
    "T1202": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Indirect command execution"},
    "T1205": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 38", "Pasal 39"], "risk": "Traffic signaling untuk lateral movement"},
    "T1210": {"pasal": ["Pasal 38", "Pasal 39", "Pasal 51"], "risk": "Eksploitasi remote services untuk pergerakan lateral ke data pribadi di sistem lain (melanggar Pasal 38: perlindungan dari pemrosesan tidak sah, Pasal 39: pencegahan akses tidak sah)"},
    "T1212": {"pasal": ["Pasal 16", "Pasal 35", "Pasal 38"], "risk": "Exploitation for credential access"},
    "T1213": {"pasal": ["Pasal 16", "Pasal 35", "Pasal 38"], "risk": "Pengumpulan data dari repositori informasi (melanggar Pasal 16: pemrosesan data, Pasal 35: keamanan data)"},
    "T1213.001": {"pasal": ["Pasal 16", "Pasal 35", "Pasal 38"], "risk": "Confluence data collection"},
    "T1213.002": {"pasal": ["Pasal 16", "Pasal 35", "Pasal 38"], "risk": "Sharepoint data collection"},
    "T1213.003": {"pasal": ["Pasal 16", "Pasal 35", "Pasal 38"], "risk": "Code repositories data collection"},
    "T1217": {"pasal": ["Pasal 31", "Pasal 38"], "risk": "Browser information discovery"},
    "T1218": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "System binary proxy execution"},
    "T1219": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 38"], "risk": "Remote access software"},
    "T1220": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "XSL script processing"},
    "T1221": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Template injection"},
    "T1222": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "File and directory permissions modification"},
    "T1480": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Execution guardrails"},
    "T1480.001": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Environmental keying"},
    "T1482": {"pasal": ["Pasal 31", "Pasal 38"], "risk": "Domain trust discovery"},
    "T1485": {"pasal": ["Pasal 30", "Pasal 35", "Pasal 36", "Pasal 40", "Pasal 41", "Pasal 43", "Pasal 44", "Pasal 45", "Pasal 46", "Pasal 48", "Pasal 57", "Pasal 66", "Pasal 67", "Pasal 68", "Pasal 69", "Pasal 71", "Pasal 73"], "risk": "Data destruction setelah penarikan persetujuan melanggar Pasal 40: kewajiban menghentikan pemrosesan"},
    "T1486": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 46", "Pasal 48", "Pasal 57", "Pasal 67", "Pasal 69", "Pasal 71", "Pasal 73"], "risk": "Enkripsi data untuk impact/ransomware (melanggar Pasal 35: keamanan data, Pasal 46: notifikasi kegagalan, Pasal 57: sanksi administratif, Pasal 67: pidana)"},
    "T1491": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 57"], "risk": "Defacement sistem yang memproses data pribadi (melanggar Pasal 35, 36, 57)"},
    "T1491.001": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 57"], "risk": "Defacement: internal website"},
    "T1491.002": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 57"], "risk": "Defacement: external website"},
    "T1499": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 41", "Pasal 48", "Pasal 57"], "risk": "Endpoint DoS melanggar Pasal 41: penundaan dan pembatasan pemrosesan data pribadi"},
    "T1499.001": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 57"], "risk": "OS exhaustion: CPU/memory"},
    "T1499.002": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 57"], "risk": "OS exhaustion: disk space"},
    "T1499.003": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 57"], "risk": "OS exhaustion: network bandwidth"},
    "T1499.004": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 57"], "risk": "Application exhaustion"},
    "T1505": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Server software component"},
    "T1518": {"pasal": ["Pasal 31", "Pasal 38"], "risk": "Software discovery"},
    "T1518.001": {"pasal": ["Pasal 31", "Pasal 38"], "risk": "Security software discovery"},
    "T1525": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Implant internal module"},
    "T1526": {"pasal": ["Pasal 31", "Pasal 38"], "risk": "Cloud service discovery"},
    "T1528": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Pencurian access token untuk akses tidak sah"},
    "T1529": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 41", "Pasal 42", "Pasal 57"], "risk": "System shutdown melanggar Pasal 42: pengakhiran pemrosesan data pribadi"},
    "T1530": {"pasal": ["Pasal 16", "Pasal 35", "Pasal 38", "Pasal 56"], "risk": "Pengumpulan data dari cloud storage (melanggar Pasal 16: pemrosesan data, Pasal 56: transfer data)"},
    "T1531": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 40", "Pasal 43", "Pasal 57"], "risk": "Account access removal melanggar Pasal 40: penghentian pemrosesan data"},
    "T1534": {"pasal": ["Pasal 38", "Pasal 39"], "risk": "Internal spearphishing"},
    "T1535": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Unused/unsupported cloud regions"},
    "T1537": {"pasal": ["Pasal 35", "Pasal 38", "Pasal 46", "Pasal 55", "Pasal 56"], "risk": "Transfer data to cloud account melanggar Pasal 55 dan Pasal 56"},
    "T1538": {"pasal": ["Pasal 31", "Pasal 38"], "risk": "Cloud service dashboard discovery"},
    "T1539": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Pencurian session cookie untuk akses tidak sah (melanggar Pasal 35: keamanan data, Pasal 36: langkah teknis, Pasal 39: pencegahan akses tidak sah)"},
    "T1542": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Pre-OS boot persistence"},
    "T1543": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Create/modify system process"},
    "T1546": {"pasal": ["Pasal 28", "Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Event triggered execution untuk persistensi dan eskalasi"},
    "T1547": {"pasal": ["Pasal 28", "Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Boot/logon autostart execution"},
    "T1548": {"pasal": ["Pasal 28", "Pasal 35", "Pasal 39"], "risk": "Abuse elevation control mechanism"},
    "T1548.001": {"pasal": ["Pasal 28", "Pasal 35", "Pasal 39"], "risk": "Setuid/setgid bit abuse"},
    "T1548.002": {"pasal": ["Pasal 28", "Pasal 35", "Pasal 39"], "risk": "Bypass UAC"},
    "T1548.003": {"pasal": ["Pasal 28", "Pasal 35", "Pasal 39"], "risk": "Sudo and sudo caching"},
    "T1548.004": {"pasal": ["Pasal 28", "Pasal 35", "Pasal 39"], "risk": "Elevated execution with prompt"},
    "T1548.005": {"pasal": ["Pasal 28", "Pasal 35", "Pasal 39"], "risk": "Temporary elevated cloud access"},
    "T1550": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36", "Pasal 38", "Pasal 39"], "risk": "Use alternate authentication material"},
    "T1550.001": {"pasal": ["Pasal 38", "Pasal 39"], "risk": "Application access token"},
    "T1550.002": {"pasal": ["Pasal 38", "Pasal 39"], "risk": "Pass the hash"},
    "T1550.003": {"pasal": ["Pasal 38", "Pasal 39"], "risk": "Pass the ticket"},
    "T1550.004": {"pasal": ["Pasal 38", "Pasal 39"], "risk": "Web session cookie"},
    "T1552": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 52"], "risk": "Kredensial tidak diamankan sesuai standar keamanan (melanggar Pasal 35: kewajiban melindungi data, Pasal 36: langkah teknis operasional)"},
    "T1552.001": {"pasal": ["Pasal 35", "Pasal 36"], "risk": "Credentials in files tanpa proteksi"},
    "T1552.002": {"pasal": ["Pasal 35", "Pasal 36"], "risk": "Credentials in registry tanpa proteksi"},
    "T1552.003": {"pasal": ["Pasal 35", "Pasal 36"], "risk": "Bash history credentials"},
    "T1552.004": {"pasal": ["Pasal 35", "Pasal 36"], "risk": "Private keys tidak diamankan"},
    "T1552.005": {"pasal": ["Pasal 35", "Pasal 36"], "risk": "Cloud instance metadata credentials"},
    "T1552.006": {"pasal": ["Pasal 35", "Pasal 36"], "risk": "Group policy preferences credentials"},
    "T1552.007": {"pasal": ["Pasal 35", "Pasal 36"], "risk": "Container API credentials"},
    "T1552.008": {"pasal": ["Pasal 35", "Pasal 36"], "risk": "Chat client credentials"},
    "T1553": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Subvert trust controls"},
    "T1554": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Compromise client software binary"},
    "T1555": {"pasal": ["Pasal 24", "Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Credentials from password stores melanggar Pasal 24: kewajiban menunjukkan bukti persetujuan"},
    "T1555.001": {"pasal": ["Pasal 35", "Pasal 36"], "risk": "Keychain credentials"},
    "T1555.002": {"pasal": ["Pasal 35", "Pasal 36"], "risk": "Securityd memory credentials"},
    "T1555.003": {"pasal": ["Pasal 35", "Pasal 36"], "risk": "Credentials from web browsers"},
    "T1555.004": {"pasal": ["Pasal 35", "Pasal 36"], "risk": "Windows credential manager"},
    "T1555.005": {"pasal": ["Pasal 35", "Pasal 36"], "risk": "Password managers"},
    "T1556": {"pasal": ["Pasal 21", "Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Modify authentication process melanggar Pasal 21: kewajiban menyampaikan informasi pemrosesan"},
    "T1556.001": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Domain controller authentication"},
    "T1556.002": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Password filter DLL"},
    "T1556.003": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Pluggable authentication modules"},
    "T1556.004": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Network device authentication"},
    "T1556.005": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Reversible encryption"},
    "T1556.006": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Multi-factor authentication modification"},
    "T1556.007": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Hybrid identity modification"},
    "T1556.008": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Network provider DLL"},
    "T1557": {"pasal": ["Pasal 16", "Pasal 35", "Pasal 39"], "risk": "Adversary-in-the-middle"},
    "T1557.001": {"pasal": ["Pasal 16", "Pasal 35", "Pasal 39"], "risk": "LLMNR/NBT-NS poisoning"},
    "T1557.002": {"pasal": ["Pasal 16", "Pasal 35", "Pasal 39"], "risk": "ARP cache poisoning"},
    "T1557.003": {"pasal": ["Pasal 16", "Pasal 35", "Pasal 39"], "risk": "DHCP spoofing"},
    "T1560": {"pasal": ["Pasal 16", "Pasal 18", "Pasal 35", "Pasal 38"], "risk": "Arsip data yang dikumpulkan sebelum eksfiltrasi (melanggar Pasal 16: pemrosesan data)"},
    "T1560.001": {"pasal": ["Pasal 16", "Pasal 35"], "risk": "Archive via utility"},
    "T1560.002": {"pasal": ["Pasal 16", "Pasal 35"], "risk": "Archive via library"},
    "T1560.003": {"pasal": ["Pasal 16", "Pasal 35"], "risk": "Archive via custom method"},
    "T1561": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 43", "Pasal 44", "Pasal 57"], "risk": "Unauthorized data destruction melanggar Pasal 44: kewajiban memusnahkan data pribadi"},
    "T1561.001": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 57"], "risk": "Disk content wipe"},
    "T1561.002": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 57"], "risk": "Disk structure wipe"},
    "T1562": {"pasal": ["Pasal 31", "Pasal 33", "Pasal 35", "Pasal 36", "Pasal 37", "Pasal 47", "Pasal 49", "Pasal 50", "Pasal 53"], "risk": "Impair defenses keamanan (melanggar Pasal 31: perekaman kegiatan, Pasal 35: keamanan data)"},
    "T1562.001": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Disable/modify tools"},
    "T1562.002": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Disable Windows event logging"},
    "T1562.003": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Impair command history logging"},
    "T1562.004": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Disable/modify firewall rules"},
    "T1562.006": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Indicator blocking"},
    "T1562.007": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Disable/modify cloud firewall"},
    "T1562.008": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Disable cloud logs"},
    "T1562.009": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Safe mode boot"},
    "T1562.010": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Downgrade attack"},
    "T1562.011": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Spoof security alerting"},
    "T1562.012": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Disable/modify Linux audit"},
    "T1563": {"pasal": ["Pasal 38", "Pasal 39"], "risk": "Remote service session hijacking"},
    "T1563.001": {"pasal": ["Pasal 38", "Pasal 39"], "risk": "SSH hijacking"},
    "T1563.002": {"pasal": ["Pasal 38", "Pasal 39"], "risk": "RDP hijacking"},
    "T1564": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Hide artifacts"},
    "T1565": {"pasal": ["Pasal 29", "Pasal 30", "Pasal 35", "Pasal 36", "Pasal 57", "Pasal 66", "Pasal 67", "Pasal 68", "Pasal 69", "Pasal 71", "Pasal 73"], "risk": "Pemalsuan data pribadi melanggar Pasal 66: larangan membuat data pribadi palsu dengan maksud menguntungkan diri"},
    "T1565.001": {"pasal": ["Pasal 29", "Pasal 30", "Pasal 35", "Pasal 36", "Pasal 57"], "risk": "Stored data manipulated melanggar Pasal 29: akurasi data pribadi"},
    "T1565.002": {"pasal": ["Pasal 29", "Pasal 30", "Pasal 35", "Pasal 36", "Pasal 57"], "risk": "Transmitted data manipulated melanggar Pasal 29: akurasi data pribadi"},
    "T1565.003": {"pasal": ["Pasal 29", "Pasal 30", "Pasal 35", "Pasal 36", "Pasal 57"], "risk": "Runtime data manipulated melanggar Pasal 29: akurasi data pribadi"},
    "T1567": {"pasal": ["Pasal 35", "Pasal 38", "Pasal 45", "Pasal 46", "Pasal 55"], "risk": "Eksfiltrasi data pribadi melalui web service (melanggar Pasal 35: keamanan data, Pasal 38: perlindungan dari pemrosesan tidak sah, Pasal 46: notifikasi kegagalan perlindungan data)"},
    "T1567.001": {"pasal": ["Pasal 35", "Pasal 38", "Pasal 46"], "risk": "Exfiltration to code repository"},
    "T1567.002": {"pasal": ["Pasal 35", "Pasal 38", "Pasal 46"], "risk": "Exfiltration to cloud storage"},
    "T1567.003": {"pasal": ["Pasal 35", "Pasal 38", "Pasal 46"], "risk": "Exfiltration to text storage"},
    "T1567.004": {"pasal": ["Pasal 35", "Pasal 38", "Pasal 46"], "risk": "Exfiltration via web service C2"},
    "T1568": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 38"], "risk": "Dynamic resolution"},
    "T1568.001": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 38"], "risk": "Fast flux DNS"},
    "T1568.002": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 38"], "risk": "Domain generation algorithms"},
    "T1568.003": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 38"], "risk": "DNS calculation"},
    "T1570": {"pasal": ["Pasal 38", "Pasal 39"], "risk": "Lateral tool transfer"},
    "T1571": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 38"], "risk": "Non-standard port"},
    "T1572": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 38"], "risk": "Protocol tunneling"},
    "T1573": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 38"], "risk": "Encrypted channel"},
    "T1573.001": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 38"], "risk": "Symmetric cryptography"},
    "T1573.002": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 38"], "risk": "Asymmetric cryptography"},
    "T1574": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Hijack execution flow"},
    "T1578": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Modify cloud compute infrastructure"},
    "T1580": {"pasal": ["Pasal 35", "Pasal 38", "Pasal 56"], "risk": "Discovery infrastruktur cloud yang menyimpan data pribadi (melanggar Pasal 35: keamanan data, Pasal 56: transfer data)"},
    "T1583": {"pasal": ["Pasal 38", "Pasal 65"], "risk": "Akuisisi infrastruktur untuk serangan (melanggar Pasal 38: perlindungan dari pemrosesan tidak sah)"},
    "T1584": {"pasal": ["Pasal 38", "Pasal 65"], "risk": "Kompromi infrastruktur untuk serangan"},
    "T1585": {"pasal": ["Pasal 38", "Pasal 65"], "risk": "Membuat akun untuk operasi ofensif"},
    "T1586": {"pasal": ["Pasal 38", "Pasal 65"], "risk": "Kompromi akun untuk operasi ofensif"},
    "T1587": {"pasal": ["Pasal 38", "Pasal 65"], "risk": "Pengembangan kemampuan exploit"},
    "T1588": {"pasal": ["Pasal 38", "Pasal 65"], "risk": "Akuisisi kemampuan ofensif (malware, exploit)"},
    "T1592": {"pasal": ["Pasal 31", "Pasal 38"], "risk": "Pengumpulan informasi host tanpa otorisasi"},
    "T1592.001": {"pasal": ["Pasal 31", "Pasal 38"], "risk": "Pengumpulan informasi hardware tanpa otorisasi"},
    "T1592.002": {"pasal": ["Pasal 31", "Pasal 38"], "risk": "Pengumpulan informasi software tanpa otorisasi"},
    "T1592.003": {"pasal": ["Pasal 31", "Pasal 38"], "risk": "Pengumpulan informasi firmware tanpa otorisasi"},
    "T1592.004": {"pasal": ["Pasal 31", "Pasal 38"], "risk": "Pengumpulan informasi klien tanpa otorisasi"},
    "T1595": {"pasal": ["Pasal 20", "Pasal 31", "Pasal 34", "Pasal 35", "Pasal 38"], "risk": "Active scanning untuk pengumpulan informasi sistem tanpa otorisasi (melanggar Pasal 31: perekaman kegiatan, Pasal 38: perlindungan dari pemrosesan tidak sah)"},
    "T1595.001": {"pasal": ["Pasal 31", "Pasal 38"], "risk": "Scanning IP blocks tanpa otorisasi"},
    "T1595.002": {"pasal": ["Pasal 31", "Pasal 38"], "risk": "Vulnerability scanning tanpa otorisasi"},
    "T1597": {"pasal": ["Pasal 31", "Pasal 38"], "risk": "Search closed-source domain untuk intel"},
    "T1598": {"pasal": ["Pasal 31", "Pasal 38"], "risk": "Phishing untuk reconnaissance"},
    "T1600": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Weaken encryption"},
    "T1601": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Modify system image"},
    "T1602": {"pasal": ["Pasal 16", "Pasal 35", "Pasal 38"], "risk": "Data from configuration repository"},
    "T1602.001": {"pasal": ["Pasal 16", "Pasal 35", "Pasal 38"], "risk": "SNMP (MIB dump)"},
    "T1602.002": {"pasal": ["Pasal 16", "Pasal 35", "Pasal 38"], "risk": "Network device configuration dump"},
    "T1606": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Forge web credentials"},
    "T1606.001": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Web cookies forgery"},
    "T1606.002": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "SAML tokens forgery"},
    "T1608": {"pasal": ["Pasal 38", "Pasal 65"], "risk": "Staging kemampuan untuk operasi ofensif"},
    "T1609": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Container administration command"},
    "T1610": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Deploy container"},
    "T1611": {"pasal": ["Pasal 28", "Pasal 35", "Pasal 39"], "risk": "Container escape"},
    "T1612": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Build image on host"},
    "T1613": {"pasal": ["Pasal 31", "Pasal 38"], "risk": "Container and resource discovery"},
    "T1615": {"pasal": ["Pasal 31", "Pasal 38"], "risk": "Group policy discovery"},
    "T1619": {"pasal": ["Pasal 31", "Pasal 38"], "risk": "Cloud storage object discovery"},
    "T1620": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Reflective code loading"},
    "T1621": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Multi-factor authentication request generation"},
    "T1622": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 36"], "risk": "Debugger evasion"},
    "T1648": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Serverless execution untuk akses tidak sah"},
    "T1650": {"pasal": ["Pasal 38", "Pasal 65"], "risk": "Akuisisi akses (access brokers)"},
    "T1651": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 39"], "risk": "Cloud administration command"},
    "T1652": {"pasal": ["Pasal 31", "Pasal 38"], "risk": "Driver discovery"},
    "T1654": {"pasal": ["Pasal 31", "Pasal 38"], "risk": "Log enumeration"},
    "T1657": {"pasal": ["Pasal 35", "Pasal 36", "Pasal 57"], "risk": "Financial theft"},
    "T1659": {"pasal": ["Pasal 31", "Pasal 35", "Pasal 38"], "risk": "Content injection/redirect"}
}


# ============================================================
# Data Classes
# ============================================================

@dataclass
class AttackTechnique:
    """Represents a single MITRE ATT&CK technique mapping."""
    action: str
    technique_id: str
    technique_name: str
    tactic: str
    description: str
    uu_pdp_pasal: List[str]
    uu_pdp_risk: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    evidence: str = ""
    severity: str = ""
    status: str = "observed"  # observed, confirmed, mitigated


@dataclass
class AttackChain:
    """Represents a full attack chain with multiple techniques."""
    chain_id: str
    target: str
    techniques: List[AttackTechnique] = field(default_factory=list)
    start_time: str = field(default_factory=lambda: datetime.now().isoformat())
    end_time: str = ""
    status: str = "in_progress"  # in_progress, completed, blocked

    def add_technique(self, technique: AttackTechnique):
        self.techniques.append(technique)

    def get_tactics(self) -> List[str]:
        return list(set(t.tactic for t in self.techniques))

    def get_technique_ids(self) -> List[str]:
        return [t.technique_id for t in self.techniques]


# ============================================================
# MITRE ATT&CK Mapper Class
# ============================================================

class MitreAttackMapper:
    """Maps pentest actions to MITRE ATT&CK techniques and UU PDP articles."""

    def __init__(self, db_path: Optional[str] = None):
        # Try multiple locations for the MITRE DB
        if db_path is None:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            parent_dir = os.path.dirname(script_dir)
            possible_paths = [
                os.path.join(parent_dir, "mitre_attack_db.json"),
                os.path.join(script_dir, "mitre_attack_db.json"),
                "/home/vedara/Documents/Kelompok 7/mitre_attack_db.json",
            ]
            for p in possible_paths:
                if os.path.exists(p):
                    db_path = p
                    break
            else:
                db_path = possible_paths[0]  # Default to parent dir
        self.db_path = db_path
        self.mitre_db = self._load_mitre_db()
        self.chains: Dict[str, AttackChain] = {}

    def _load_mitre_db(self) -> Dict:
        """Load MITRE ATT&CK database from JSON file."""
        try:
            with open(self.db_path) as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"[WARN] MITRE DB not found at {self.db_path}")
            return {}
        except json.JSONDecodeError:
            print(f"[ERROR] Invalid JSON in MITRE DB")
            return {}

    def map_action(self, action: str, evidence: str = "", severity: str = "") -> Optional[AttackTechnique]:
        """Map a pentest action to MITRE ATT&CK technique + UU PDP."""
        if action not in PENTEST_ACTION_MAP:
            print(f"[WARN] Unknown action: {action}")
            return None

        mapping = PENTEST_ACTION_MAP[action]
        technique_id = mapping["technique_id"]

        # Get UU PDP mapping
        uu_pdp = MITRE_UU_PDP_MAP.get(technique_id, {
            "pasal": ["Pasal 35"],
            "risk": "Potensi pelanggaran keamanan data pribadi"
        })

        # Get technique details from MITRE DB
        technique_details = self.mitre_db.get("techniques", {}).get(technique_id, {})
        description = technique_details.get("description", mapping["description"])

        return AttackTechnique(
            action=action,
            technique_id=technique_id,
            technique_name=mapping["technique_name"],
            tactic=mapping["tactic"],
            description=description[:300] if description else mapping["description"],
            uu_pdp_pasal=uu_pdp["pasal"],
            uu_pdp_risk=uu_pdp["risk"],
            evidence=evidence,
            severity=severity
        )

    def create_chain(self, chain_id: str, target: str) -> AttackChain:
        """Create a new attack chain."""
        chain = AttackChain(chain_id=chain_id, target=target)
        self.chains[chain_id] = chain
        return chain

    def add_to_chain(self, chain_id: str, action: str, evidence: str = "", severity: str = "") -> bool:
        """Add a technique to an existing chain."""
        if chain_id not in self.chains:
            print(f"[ERROR] Chain {chain_id} not found")
            return False

        technique = self.map_action(action, evidence, severity)
        if technique:
            self.chains[chain_id].add_technique(technique)
            return True
        return False

    def get_chain_report(self, chain_id: str) -> Dict:
        """Generate a report for an attack chain."""
        if chain_id not in self.chains:
            return {"error": f"Chain {chain_id} not found"}

        chain = self.chains[chain_id]
        return {
            "chain_id": chain.chain_id,
            "target": chain.target,
            "status": chain.status,
            "start_time": chain.start_time,
            "end_time": chain.end_time or datetime.now().isoformat(),
            "tactics_covered": chain.get_tactics(),
            "techniques_count": len(chain.techniques),
            "techniques": [asdict(t) for t in chain.techniques],
            "uu_pdp_articles": list(set(
                pasal for t in chain.techniques for pasal in t.uu_pdp_pasal
            )),
        }

    def generate_navigator_layer(self, chain_id: str) -> Dict:
        """Generate MITRE ATT&CK Navigator layer JSON for visualization."""
        if chain_id not in self.chains:
            return {"error": f"Chain {chain_id} not found"}

        chain = self.chains[chain_id]
        techniques = []

        for t in chain.techniques:
            # Color based on tactic
            tactic_colors = {
                "reconnaissance": "#FFA500",
                "initial-access": "#FF0000",
                "discovery": "#FFFF00",
                "credential-access": "#FF00FF",
                "privilege-escalation": "#FF4500",
                "lateral-movement": "#8B0000",
                "collection": "#00FFFF",
                "exfiltration": "#0000FF",
                "impact": "#800080",
                "defense-evasion": "#008080",
                "execution": "#00FF00",
                "persistence": "#008000",
            }

            techniques.append({
                "techniqueID": t.technique_id,
                "tactic": t.tactic,
                "color": tactic_colors.get(t.tactic, "#CCCCCC"),
                "comment": f"{t.action}\nUU PDP: {', '.join(t.uu_pdp_pasal)}\n{t.uu_pdp_risk}",
                "enabled": True
            })

        return {
            "name": f"Attack Chain: {chain_id} - {chain.target}",
            "versions": {
                "attack": "15",
                "navigator": "5.0",
                "layer": "4.5"
            },
            "domain": "enterprise-attack",
            "description": f"MITRE ATT&CK mapping for gray box pentest against {chain.target}",
            "filters": {
                "platforms": ["Windows", "Linux", "macOS", "Network", "PRE", "Containers", "IaaS", "SaaS", "Google Workspace", "Office 365", "Azure AD"]
            },
            "sorting": 3,
            "layout": {
                "layout": "side",
                "aggregateFunction": "average",
                "showID": True,
                "showName": True,
                "showAggregateHeaders": True
            },
            "hideDisabled": True,
            "techniques": techniques,
            "gradient": {
                "colors": ["#ff6666", "#ffe766", "#8ec843"],
                "minValue": 0,
                "maxValue": 100
            },
            "metadata": [
                {
                    "name": "Target",
                    "value": chain.target
                },
                {
                    "name": "Chain ID",
                    "value": chain_id
                },
                {
                    "name": "UU PDP",
                    "value": ", ".join(set(
                        pasal for t in chain.techniques for pasal in t.uu_pdp_pasal
                    ))
                }
            ]
        }

    def export_chain_json(self, chain_id: str, output_path: str) -> bool:
        """Export attack chain to JSON file."""
        if chain_id not in self.chains:
            return False

        report = self.get_chain_report(chain_id)
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)
        return True

    def export_navigator_layer(self, chain_id: str, output_path: str) -> bool:
        """Export MITRE ATT&CK Navigator layer to JSON file."""
        if chain_id not in self.chains:
            return False

        layer = self.generate_navigator_layer(chain_id)
        with open(output_path, "w") as f:
            json.dump(layer, f, indent=2)
        return True

    def list_available_actions(self) -> List[str]:
        """List all available pentest actions that can be mapped."""
        return list(PENTEST_ACTION_MAP.keys())

    def get_technique_info(self, technique_id: str) -> Optional[Dict]:
        """Get detailed info about a MITRE technique."""
        techniques = self.mitre_db.get("techniques", {})
        if technique_id in techniques:
            return techniques[technique_id]

        # Try without subtechnique
        base_id = technique_id.split(".")[0]
        if base_id in techniques:
            return techniques[base_id]

        return None


# ============================================================
# CLI Usage
# ============================================================

if __name__ == "__main__":
    import sys

    mapper = MitreAttackMapper()

    if len(sys.argv) < 2:
        print("Usage: python mitre_attack_mapper.py <action> [evidence] [severity]")
        print("\nAvailable actions:")
        for action in mapper.list_available_actions():
            print(f"  - {action}")
        sys.exit(1)

    action = sys.argv[1]
    evidence = sys.argv[2] if len(sys.argv) > 2 else ""
    severity = sys.argv[3] if len(sys.argv) > 3 else ""

    result = mapper.map_action(action, evidence, severity)
    if result:
        print(json.dumps(asdict(result), indent=2))
    else:
        print(f"Action '{action}' not found in mapping database")
        sys.exit(1)
