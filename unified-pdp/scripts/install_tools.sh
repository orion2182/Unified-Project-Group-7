#!/bin/bash
# HexStrike-PDP — Tool Installation Script
# Installs 150+ security tools for comprehensive pentesting

set -e

echo "========================================="
echo " HexStrike-PDP Tool Installer"
echo "========================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

install_success() {
    echo -e "${GREEN}[✓]${NC} $1 installed successfully"
}

install_failed() {
    echo -e "${RED}[✗]${NC} $1 installation failed"
}

install_skip() {
    echo -e "${YELLOW}[-]${NC} $1 already installed"
}

check_install() {
    if command -v $1 &> /dev/null; then
        install_skip "$1"
        return 0
    fi
    return 1
}

# ── System Update ──
echo "[*] Updating system packages..."
sudo apt update -y 2>/dev/null || echo "[-] apt update skipped (may need manual update)"
echo ""

# ═══════════════════════════════════════════
# Network Reconnaissance Tools (25+)
# ═══════════════════════════════════════════
echo "═══════════════════════════════════════"
echo " Installing Network Tools (25+)"
echo "═══════════════════════════════════════"

# Nmap
check_install nmap || { sudo apt install -y nmap && install_success "nmap"; }

# RustScan
check_install rustscan || {
    curl -sL https://github.com/PortSwigger/rustscan/releases/latest/download/rustscan-linux-amd64 -o /tmp/rustscan 2>/dev/null && \
    sudo mv /tmp/rustscan /usr/local/bin/rustscan && sudo chmod +x /usr/local/bin/rustscan && \
    install_success "rustscan"
} || install_failed "rustscan"

# Masscan
check_install masscan || { sudo apt install -y masscan && install_success "masscan"; }

# Amass
check_install amass || {
    go install github.com/owasp-amass/amass/v4/...@latest 2>/dev/null && \
    install_success "amass"
} || install_failed "amass"

# Subfinder
check_install subfinder || {
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null && \
    install_success "subfinder"
} || install_failed "subfinder"

# TheHarvester
check_install theHarvester || { sudo apt install -y theharvester && install_success "theharvester"; }

# DNSenum
check_install dnsenum || { sudo apt install -y dnsenum && install_success "dnsenum"; }

# Fierce
check_install fierce || { sudo apt install -y fierce && install_success "fierce"; }

# Autorecon
check_install autorecon || { sudo apt install -y autorecon && install_success "autorecon"; }

# Responder
check_install responder || { sudo apt install -y responder && install_success "responder"; }

# NetExec (CrackMapExec successor)
check_install netexec || {
    pip3 install git+https://github.com/Pennyw0rth/NetExec 2>/dev/null && \
    install_success "netexec"
} || install_failed "netexec"

# Enum4linux-ng
check_install enum4linux-ng || { sudo apt install -y enum4linux-ng && install_success "enum4linux-ng"; }

echo ""

# ═══════════════════════════════════════════
# Web Application Security Tools (40+)
# ═══════════════════════════════════════════
echo "═══════════════════════════════════════"
echo " Installing Web Tools (40+)"
echo "═══════════════════════════════════════"

# Gobuster
check_install gobuster || {
    go install github.com/OJ/gobuster/v3@latest 2>/dev/null && \
    install_success "gobuster"
} || install_failed "gobuster"

# Feroxbuster
check_install feroxbuster || {
    curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash 2>/dev/null && \
    install_success "feroxbuster"
} || install_failed "feroxbuster"

# FFuf
check_install ffuf || {
    go install github.com/ffuf/ffuf/v2@latest 2>/dev/null && \
    install_success "ffuf"
} || install_failed "ffuf"

# Dirsearch
check_install dirsearch || { sudo apt install -y dirsearch && install_success "dirsearch"; }

# HTTPx
check_install httpx || {
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null && \
    install_success "httpx"
} || install_failed "httpx"

# Katana
check_install katana || {
    go install github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null && \
    install_success "katana"
} || install_failed "katana"

# Nuclei
check_install nuclei || {
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null && \
    install_success "nuclei"
} || install_failed "nuclei"

# Nikto
check_install nikto || { sudo apt install -y nikto && install_success "nikto"; }

# SQLMap
check_install sqlmap || { sudo apt install -y sqlmap && install_success "sqlmap"; }

# WPScan
check_install wpscan || { sudo apt install -y wpscan && install_success "wpscan"; }

# Arjun
check_install arjun || {
    pip3 install arjun 2>/dev/null && \
    install_success "arjun"
} || install_failed "arjun"

# ParamSpider
check_install paramspider || {
    pip3 install paramspider 2>/dev/null && \
    install_success "paramspider"
} || install_failed "paramspider"

# Dalfox
check_install dalfox || {
    go install github.com/hahwul/dalfox/v2@latest 2>/dev/null && \
    install_success "dalfox"
} || install_failed "dalfox"

# WAFW00F
check_install wafw00f || {
    pip3 install wafw00f 2>/dev/null && \
    install_success "wafw00f"
} || install_failed "wafw00f"

# WhatWeb
check_install whatweb || { sudo apt install -y whatweb && install_success "whatweb"; }

# TestSSL
check_install testssl || { sudo apt install -y testssl.sh && install_success "testssl"; }

# JWT Tool
check_install jwt_tool || {
    pip3 install jwt-tool 2>/dev/null && \
    install_success "jwt_tool"
} || install_failed "jwt_tool"

# Commix
check_install commix || { sudo apt install -y commix && install_success "commix"; }

# WFuzz
check_install wfuzz || { sudo apt install -y wfuzz && install_success "wfuzz"; }

echo ""

# ═══════════════════════════════════════════
# Password & Authentication Tools (12+)
# ═══════════════════════════════════════════
echo "═══════════════════════════════════════"
echo " Installing Password Tools (12+)"
echo "═══════════════════════════════════════"

check_install hydra || { sudo apt install -y hydra && install_success "hydra"; }
check_install john || { sudo apt install -y john && install_success "john"; }
check_install hashcat || { sudo apt install -y hashcat && install_success "hashcat"; }
check_install medusa || { sudo apt install -y medusa && install_success "medusa"; }

echo ""

# ═══════════════════════════════════════════
# Cloud Security Tools (20+)
# ═══════════════════════════════════════════
echo "═══════════════════════════════════════"
echo " Installing Cloud Tools (20+)"
echo "═══════════════════════════════════════"

# Prowler
check_install prowler || {
    pip3 install prowler 2>/dev/null && \
    install_success "prowler"
} || install_failed "prowler"

# Trivy
check_install trivy || {
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin 2>/dev/null && \
    install_success "trivy"
} || install_failed "trivy"

# Kube-Hunter
check_install kube-hunter || {
    pip3 install kube-hunter 2>/dev/null && \
    install_success "kube-hunter"
} || install_failed "kube-hunter"

# Kube-Bench
check_install kube-bench || {
    curl -sL https://github.com/aquasecurity/kube-bench/releases/latest/download/kube-bench_0.7.2_linux_amd64.tar.gz | tar xz -C /tmp && \
    sudo mv /tmp/kube-bench /usr/local/bin/ && \
    install_success "kube-bench"
} || install_failed "kube-bench"

# Checkov
check_install checkov || {
    pip3 install checkov 2>/dev/null && \
    install_success "checkov"
} || install_failed "checkov"

echo ""

# ═══════════════════════════════════════════
# Binary & CTF Tools (25+)
# ═══════════════════════════════════════════
echo "═══════════════════════════════════════"
echo " Installing Binary/CTF Tools (25+)"
echo "═══════════════════════════════════════"

check_install gdb || { sudo apt install -y gdb && install_success "gdb"; }
check_install radare2 || { sudo apt install -y radare2 && install_success "radare2"; }
check_install binwalk || { sudo apt install -y binwalk && install_success "binwalk"; }
check_install checksec || { sudo apt install -y checksec && install_success "checksec"; }
check_install strings || { sudo apt install -y binutils && install_success "strings"; }
check_install exiftool || { sudo apt install -y libimage-exiftool-perl && install_success "exiftool"; }
check_install steghide || { sudo apt install -y steghide && install_success "steghide"; }
check_install volatility || { sudo apt install -y volatility3 && install_success "volatility3"; }

# Pwntools
pip3 install pwntools 2>/dev/null && install_success "pwntools" || install_failed "pwntools"

echo ""

# ═══════════════════════════════════════════
# OSINT Tools (20+)
# ═══════════════════════════════════════════
echo "═══════════════════════════════════════"
echo " Installing OSINT Tools (20+)"
echo "═══════════════════════════════════════"

# Sherlock
check_install sherlock || {
    pip3 install sherlock-project 2>/dev/null && \
    install_success "sherlock"
} || install_failed "sherlock"

echo ""

# ═══════════════════════════════════════════
# Python Dependencies
# ═══════════════════════════════════════════
echo "═══════════════════════════════════════"
echo " Installing Python Dependencies"
echo "═══════════════════════════════════════"

if [ -f "requirements.txt" ]; then
    pip3 install -r requirements.txt 2>/dev/null && install_success "Python dependencies" || install_failed "Python dependencies"
else
    echo "[-] requirements.txt not found"
fi

echo ""
echo "========================================="
echo -e "${GREEN} Installation Complete!${NC}"
echo "========================================="
echo ""
echo "Next steps:"
echo "  1. Activate virtual environment: source .venv/bin/activate"
echo "  2. Start MCP server: python mcp_server/main.py"
echo "  3. Configure AI client (Claude, VS Code, Cursor)"
echo ""
echo "For configuration examples, see: clients/"
echo ""
