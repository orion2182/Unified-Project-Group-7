#!/usr/bin/env python3
"""One-command gray box pentest runner.

Usage:
    python run_graybox.py              # Run with stored credentials
    python run_graybox.py --setup      # Interactive credential setup
    python run_graybox.py --status     # Show credential status
    python run_graybox.py --target URL --token TOKEN  # Quick run
"""

import sys
import os
import argparse

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scripts.credential_manager import CredentialManager


def main():
    parser = argparse.ArgumentParser(description="Gray Box Pentest Runner")
    parser.add_argument("--setup", action="store_true", help="Interactive credential setup")
    parser.add_argument("--status", action="store_true", help="Show credential status")
    parser.add_argument("--target", type=str, help="Target URL")
    parser.add_argument("--token", type=str, help="Auth token (JWT or session cookie)")
    parser.add_argument("--cookie", type=str, help="Session cookie")
    parser.add_argument("--role", type=str, default="attacker", help="Account role (attacker/victim/admin)")
    parser.add_argument("--chain", type=str, help="Chain ID for MITRE mapping")
    parser.add_argument("--output", type=str, help="Output directory for reports")
    parser.add_argument("--proxy", type=str, help="Proxy URL for Burp Suite capture")

    args = parser.parse_args()

    cm = CredentialManager()

    # Setup mode
    if args.setup:
        cm.setup_interactive()
        return

    # Status mode
    if args.status:
        print(cm.status())
        return

    # Quick setup via CLI args
    if args.target:
        cm.config.target_url = args.target
    if args.token:
        if args.token.startswith("Bearer "):
            cm.config.attacker.bearer_token = args.token[7:]
            cm.config.auth_method = "bearer"
        elif "=" in args.token:
            cm.config.attacker.session_cookie = args.token
            cm.config.auth_method = "cookie"
        else:
            cm.config.attacker.bearer_token = args.token
            cm.config.auth_method = "bearer"
    if args.cookie:
        cm.config.attacker.session_cookie = args.cookie
        cm.config.auth_method = "cookie"
    if args.proxy:
        cm.config.proxy_url = args.proxy

    # Check if configured
    if not cm.is_configured():
        print("[-] No credentials configured.")
        print("\nOptions:")
        print("  1. Interactive setup:  python run_graybox.py --setup")
        print("  2. Quick setup:        python run_graybox.py --target URL --token TOKEN")
        print("  3. Edit config:        nano .env.graybox")
        sys.exit(1)

    # Print status
    print(cm.status())

    # Run pentest
    from agent_orchestrator import UnifiedAIAgent
    agent = UnifiedAIAgent()

    # Setup target
    chain_id = args.chain or f"graybox-{os.uname().nodename}"
    agent.setup_target(cm.config.target_url, auth_token=cm.config.attacker.bearer_token or cm.config.attacker.session_cookie)

    # Run full workflow
    findings = agent.run_pentest(cm.config.target_url)

    # Legal audit
    legal = agent.audit_compliance('pelanggaran data pribadi akses tidak sah')

    # Generate report
    output_dir = args.output or "."
    os.makedirs(output_dir, exist_ok=True)
    report_path = os.path.join(output_dir, f"{chain_id}-report.md")
    agent.generate_report(findings, legal, output_path=report_path)

    # Export MITRE artifacts
    agent.tools.export_navigator_layer(os.path.join(output_dir, f"{chain_id}-navigator.json"))
    agent.tools.export_chain_report(os.path.join(output_dir, f"{chain_id}-chain.json"))

    print(f"\n[+] Reports saved to: {output_dir}/")
    print(f"    - {chain_id}-report.md")
    print(f"    - {chain_id}-navigator.json")
    print(f"    - {chain_id}-chain.json")
    print(f"\n[V] GRAY BOX PENTEST COMPLETE!")


if __name__ == "__main__":
    main()
