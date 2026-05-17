"""Credential manager for gray box testing.

Loads credentials from .env.graybox and provides them to the testing framework.
Supports multiple account roles for IDOR and privilege escalation testing.
"""

import os
import json
from typing import Optional, Dict
from dataclasses import dataclass, field, asdict
from pathlib import Path


@dataclass
class AccountCredentials:
    """Credentials for a single account role."""
    role: str
    username: str = ""
    password: str = ""
    session_cookie: str = ""
    bearer_token: str = ""
    auth_method: str = "cookie"  # cookie | bearer | basic

    def get_auth_header(self) -> str:
        """Get the Authorization header for this account."""
        if self.auth_method == "bearer" and self.bearer_token:
            return f"Authorization: Bearer {self.bearer_token}"
        elif self.auth_method == "cookie" and self.session_cookie:
            return f"Cookie: {self.session_cookie}"
        elif self.auth_method == "basic" and self.username and self.password:
            import base64
            creds = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
            return f"Authorization: Basic {creds}"
        return ""

    def get_cookie_string(self) -> str:
        """Get the cookie string for this account."""
        if self.session_cookie:
            return self.session_cookie
        return ""

    def has_valid_auth(self) -> bool:
        """Check if this account has valid authentication."""
        if self.auth_method == "bearer" and self.bearer_token:
            return self.bearer_token != "eyJhbGciOiJIUzI1NiIs..."
        elif self.auth_method == "cookie" and self.session_cookie:
            return self.session_cookie != "jms_sessionid=your_session_id_here"
        elif self.auth_method == "basic" and self.username and self.password:
            return self.password != "your_password_here"
        return False


@dataclass
class GrayBoxConfig:
    """Full gray box testing configuration."""
    target_url: str = ""
    auth_method: str = "cookie"
    proxy_url: str = ""
    request_delay: int = 500
    max_retries: int = 3
    request_timeout: int = 30

    # Account roles
    attacker: AccountCredentials = field(default_factory=lambda: AccountCredentials(role="attacker"))
    victim: AccountCredentials = field(default_factory=lambda: AccountCredentials(role="victim"))
    admin: AccountCredentials = field(default_factory=lambda: AccountCredentials(role="admin"))

    def get_active_account(self, role: str = "attacker") -> Optional[AccountCredentials]:
        """Get credentials for a specific role."""
        accounts = {
            "attacker": self.attacker,
            "victim": self.victim,
            "admin": self.admin,
        }
        return accounts.get(role)

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return {
            "target_url": self.target_url,
            "auth_method": self.auth_method,
            "proxy_url": self.proxy_url,
            "request_delay": self.request_delay,
            "max_retries": self.max_retries,
            "request_timeout": self.request_timeout,
            "attacker": asdict(self.attacker),
            "victim": asdict(self.victim),
            "admin": asdict(self.admin),
        }


class CredentialManager:
    """Manages gray box testing credentials."""

    def __init__(self, env_path: Optional[str] = None):
        if env_path is None:
            # Auto-detect: look for .env.graybox in script dir and parent dir
            script_dir = Path(__file__).parent
            possible_paths = [
                script_dir / ".env.graybox",
                script_dir.parent / ".env.graybox",
                Path.cwd() / ".env.graybox",
            ]
            for p in possible_paths:
                if p.exists():
                    env_path = str(p)
                    break
            else:
                env_path = str(script_dir.parent / ".env.graybox")

        self.env_path = env_path
        self.config = GrayBoxConfig()
        self._load_credentials()

    def _load_credentials(self):
        """Load credentials from .env.graybox file."""
        if not os.path.exists(self.env_path):
            print(f"[WARN] Credential file not found: {self.env_path}")
            print(f"  Run: python scripts/setup_graybox.py")
            return

        with open(self.env_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                if '=' not in line:
                    continue

                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()

                # Parse config
                if key == "TARGET_URL":
                    self.config.target_url = value
                elif key == "AUTH_METHOD":
                    self.config.auth_method = value
                elif key == "SESSION_COOKIE":
                    self.config.attacker.session_cookie = value
                elif key == "BEARER_TOKEN":
                    self.config.attacker.bearer_token = value
                elif key == "BASIC_USERNAME":
                    self.config.attacker.username = value
                elif key == "BASIC_PASSWORD":
                    self.config.attacker.password = value
                elif key == "ATTACKER_USERNAME":
                    self.config.attacker.username = value
                elif key == "ATTACKER_PASSWORD":
                    self.config.attacker.password = value
                elif key == "ATTACKER_ROLE":
                    self.config.attacker.role = value
                elif key == "VICTIM_USERNAME":
                    self.config.victim.username = value
                elif key == "VICTIM_PASSWORD":
                    self.config.victim.password = value
                elif key == "VICTIM_ROLE":
                    self.config.victim.role = value
                elif key == "ADMIN_USERNAME":
                    self.config.admin.username = value
                elif key == "ADMIN_PASSWORD":
                    self.config.admin.password = value
                elif key == "ADMIN_ROLE":
                    self.config.admin.role = value
                elif key == "PROXY_URL":
                    self.config.proxy_url = value
                elif key == "REQUEST_DELAY":
                    self.config.request_delay = int(value)
                elif key == "MAX_RETRIES":
                    self.config.max_retries = int(value)
                elif key == "REQUEST_TIMEOUT":
                    self.config.request_timeout = int(value)

        # Set auth method for all accounts
        for account in [self.config.attacker, self.config.victim, self.config.admin]:
            account.auth_method = self.config.auth_method

    def save_credentials(self):
        """Save credentials to .env.graybox file."""
        lines = [
            "# Gray Box Testing Credentials",
            f"TARGET_URL={self.config.target_url}",
            f"AUTH_METHOD={self.config.auth_method}",
            "",
            "# Attacker account",
            f"ATTACKER_ROLE={self.config.attacker.role}",
            f"ATTACKER_USERNAME={self.config.attacker.username}",
            f"ATTACKER_PASSWORD={self.config.attacker.password}",
            "",
            "# Victim account (for IDOR testing)",
            f"VICTIM_ROLE={self.config.victim.role}",
            f"VICTIM_USERNAME={self.config.victim.username}",
            f"VICTIM_PASSWORD={self.config.victim.password}",
            "",
            "# Admin account (for privilege escalation)",
            f"ADMIN_ROLE={self.config.admin.role}",
            f"ADMIN_USERNAME={self.config.admin.username}",
            f"ADMIN_PASSWORD={self.config.admin.password}",
            "",
            "# Optional settings",
            f"PROXY_URL={self.config.proxy_url}",
            f"REQUEST_DELAY={self.config.request_delay}",
            f"MAX_RETRIES={self.config.max_retries}",
            f"REQUEST_TIMEOUT={self.config.request_timeout}",
        ]

        with open(self.env_path, 'w') as f:
            f.write('\n'.join(lines) + '\n')

        print(f"[+] Credentials saved to: {self.env_path}")

    def get_auth_header(self, role: str = "attacker") -> str:
        """Get auth header for a specific role."""
        account = self.config.get_active_account(role)
        if account:
            return account.get_auth_header()
        return ""

    def get_cookie(self, role: str = "attacker") -> str:
        """Get cookie string for a specific role."""
        account = self.config.get_active_account(role)
        if account:
            return account.get_cookie_string()
        return ""

    def is_configured(self) -> bool:
        """Check if credentials are configured."""
        return bool(self.config.target_url) and self.config.attacker.has_valid_auth()

    def status(self) -> str:
        """Print credential status."""
        status_lines = [
            "\n" + "=" * 50,
            "GRAY BOX CREDENTIAL STATUS",
            "=" * 50,
            f"Target URL: {self.config.target_url or 'NOT SET'}",
            f"Auth Method: {self.config.auth_method}",
            f"Proxy: {self.config.proxy_url or 'None'}",
            "",
            "Accounts:",
        ]

        for role_name, account in [
            ("Attacker", self.config.attacker),
            ("Victim", self.config.victim),
            ("Admin", self.config.admin),
        ]:
            auth_status = "CONFIGURED" if account.has_valid_auth() else "NOT SET"
            status_lines.append(f"  {role_name} ({account.role}): {auth_status}")
            if account.username:
                status_lines.append(f"    Username: {account.username}")
            if account.session_cookie:
                cookie_preview = account.session_cookie[:30] + "..." if len(account.session_cookie) > 30 else account.session_cookie
                status_lines.append(f"    Cookie: {cookie_preview}")
            if account.bearer_token:
                token_preview = account.bearer_token[:30] + "..." if len(account.bearer_token) > 30 else account.bearer_token
                status_lines.append(f"    Token: {token_preview}")

        status_lines.append("=" * 50)
        return '\n'.join(status_lines)

    def setup_interactive(self):
        """Interactive credential setup."""
        print("\n" + "=" * 50)
        print("GRAY BOX CREDENTIAL SETUP")
        print("=" * 50)

        # Target URL
        current = self.config.target_url
        new_url = input(f"\nTarget URL [{current}]: ").strip()
        if new_url:
            self.config.target_url = new_url

        # Auth method
        print(f"\nAuth method: {self.config.auth_method}")
        print("  1) Cookie-based (session)")
        print("  2) Bearer token (JWT)")
        print("  3) Basic auth (username/password)")
        choice = input("Select auth method [1-3]: ").strip()
        if choice == "1":
            self.config.auth_method = "cookie"
        elif choice == "2":
            self.config.auth_method = "bearer"
        elif choice == "3":
            self.config.auth_method = "basic"

        # Attacker credentials
        print(f"\n--- Attacker Account ({self.config.attacker.role}) ---")
        if self.config.auth_method == "cookie":
            cookie = input(f"Session cookie: ").strip()
            if cookie:
                self.config.attacker.session_cookie = cookie
        elif self.config.auth_method == "bearer":
            token = input(f"Bearer token: ").strip()
            if token:
                self.config.attacker.bearer_token = token
        elif self.config.auth_method == "basic":
            username = input(f"Username: ").strip()
            password = input(f"Password: ").strip()
            if username:
                self.config.attacker.username = username
            if password:
                self.config.attacker.password = password

        # Victim credentials (optional)
        print(f"\n--- Victim Account (for IDOR testing) ---")
        has_victim = input("Configure victim account? [y/N]: ").strip().lower()
        if has_victim == "y":
            if self.config.auth_method == "cookie":
                cookie = input(f"Victim session cookie: ").strip()
                if cookie:
                    self.config.victim.session_cookie = cookie
            elif self.config.auth_method == "bearer":
                token = input(f"Victim bearer token: ").strip()
                if token:
                    self.config.victim.bearer_token = token
            elif self.config.auth_method == "basic":
                username = input(f"Victim username: ").strip()
                password = input(f"Victim password: ").strip()
                if username:
                    self.config.victim.username = username
                if password:
                    self.config.victim.password = password

        # Admin credentials (optional)
        print(f"\n--- Admin Account (for privilege escalation) ---")
        has_admin = input("Configure admin account? [y/N]: ").strip().lower()
        if has_admin == "y":
            if self.config.auth_method == "cookie":
                cookie = input(f"Admin session cookie: ").strip()
                if cookie:
                    self.config.admin.session_cookie = cookie
            elif self.config.auth_method == "bearer":
                token = input(f"Admin bearer token: ").strip()
                if token:
                    self.config.admin.bearer_token = token
            elif self.config.auth_method == "basic":
                username = input(f"Admin username: ").strip()
                password = input(f"Admin password: ").strip()
                if username:
                    self.config.admin.username = username
                if password:
                    self.config.admin.password = password

        # Save
        self.save_credentials()
        print(self.status())


if __name__ == "__main__":
    import sys

    cm = CredentialManager()

    if len(sys.argv) < 2:
        print(cm.status())
        print("\nUsage:")
        print("  python scripts/credential_manager.py status     - Show credential status")
        print("  python scripts/credential_manager.py setup      - Interactive setup")
        print("  python scripts/credential_manager.py test       - Test credentials")
        print("  python scripts/credential_manager.py run        - Run gray box pentest")
        sys.exit(0)

    command = sys.argv[1]

    if command == "status":
        print(cm.status())

    elif command == "setup":
        cm.setup_interactive()

    elif command == "test":
        if cm.is_configured():
            print("[+] Credentials configured!")
            print(f"    Target: {cm.config.target_url}")
            print(f"    Auth: {cm.config.auth_method}")
            print(f"    Header: {cm.get_auth_header()}")
        else:
            print("[-] Credentials not configured. Run: python scripts/credential_manager.py setup")

    elif command == "run":
        if not cm.is_configured():
            print("[-] Credentials not configured. Run: python scripts/credential_manager.py setup")
            sys.exit(1)

        # Import and run the orchestrator
        from agent_orchestrator import UnifiedAIAgent
        agent = UnifiedAIAgent()

        # Setup with loaded credentials
        auth_header = cm.get_auth_header()
        token = ""
        if cm.config.auth_method == "bearer":
            token = cm.config.attacker.bearer_token
        elif cm.config.auth_method == "cookie":
            # Extract token from cookie
            if "=" in cm.config.attacker.session_cookie:
                token = cm.config.attacker.session_cookie.split("=", 1)[1]

        agent.run_full_workflow(cm.config.target_url, auth_token=token)

    else:
        print(f"Unknown command: {command}")
        sys.exit(1)
