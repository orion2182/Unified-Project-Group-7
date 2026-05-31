#!/usr/bin/env python3
"""Unified-PDP — Health Check Script"""

import sys
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

def check_python_version():
    """Check Python version."""
    version = sys.version_info
    if version.major < 3 or version.minor < 8:
        print(f"[-] Python 3.8+ required (found {version.major}.{version.minor})")
        return False
    print(f"[✓] Python {version.major}.{version.minor}.{version.micro}")
    return True

def check_dependencies():
    """Check Python dependencies."""
    required = ["mcp", "pydantic", "requests"]
    missing = []

    for package in required:
        try:
            __import__(package)
            print(f"[✓] {package}")
        except ImportError:
            missing.append(package)
            print(f"[-] {package} (missing)")

    if missing:
        print(f"\nInstall missing: pip install {' '.join(missing)}")
        return False
    return True

def check_security_tools():
    """Check critical security tools."""
    tools = {
        "nmap": "Network scanner",
        "nuclei": "Vulnerability scanner",
        "ffuf": "Web fuzzer",
        "sqlmap": "SQL injection tester",
        "dalfox": "XSS scanner",
    }

    missing = []
    for tool, desc in tools.items():
        try:
            subprocess.run(
                [tool, "--help"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            print(f"[✓] {tool} ({desc})")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            missing.append(tool)
            print(f"[-] {tool} ({desc})")

    if missing:
        print(f"\nInstall missing: bash scripts/install_tools.sh")
    return len(missing) == 0

def check_k7_components():
    """Check Kelompok 7 components."""
    components = [
        ("scripts.mitre_attack_mapper", "MITRE ATT&CK mapping"),
        ("scripts.cvss_calculator", "CVSS v3.1 calculator"),
        ("scripts.credential_manager", "Credential manager"),
        ("tools_bridge", "Tools bridge"),
    ]

    sys.path.insert(0, str(PROJECT_ROOT.parent))
    missing = []

    for module, desc in components:
        try:
            __import__(module)
            print(f"[✓] {module.split('.')[-1]} ({desc})")
        except ImportError:
            missing.append(module)
            print(f"[-] {module.split('.')[-1]} ({desc})")

    return len(missing) == 0

def check_rag_database():
    """Check RAG database."""
    db_path = PROJECT_ROOT.parent / "db_uu_pdp"
    if db_path.exists():
        print(f"[✓] UU PDP RAG database ({db_path})")
        return True
    else:
        print(f"[-] UU PDP RAG database not found")
        print(f"   Run: python {PROJECT_ROOT.parent / 'index_uu_pdp.py'}")
        return False

def main():
    print("=" * 50)
    print(" Unified-PDP Health Check")
    print("=" * 50)
    print()

    checks = [
        ("Python Version", check_python_version),
        ("Python Dependencies", check_dependencies),
        ("Security Tools", check_security_tools),
        ("Kelompok 7 Components", check_k7_components),
        ("RAG Database", check_rag_database),
    ]

    results = []
    for name, check_func in checks:
        print(f"\n{name}:")
        print("-" * 30)
        results.append(check_func())

    print("\n" + "=" * 50)
    passed = sum(results)
    total = len(results)
    print(f" Status: {passed}/{total} checks passed")

    if all(results):
        print(" Result: ✓ READY")
    else:
        print(" Result: ⚠ NEEDS SETUP")
        print("\nRun: bash scripts/install_tools.sh")
        print("     pip install -r requirements.txt")

    print("=" * 50)

    return 0 if all(results) else 1

if __name__ == "__main__":
    sys.exit(main())
