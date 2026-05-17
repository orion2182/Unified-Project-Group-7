#!/bin/bash
# Metasploit Framework Installation Script for Fedora
# Run as: chmod +x install_metasploit.sh && ./install_metasploit.sh

set -e

echo "=============================================="
echo "  Metasploit Framework Installer (Fedora)"
echo "=============================================="

# Step 1: Ruby dependencies
echo "[*] Installing Ruby dependencies..."
sudo dnf -y install ruby-irb rubygems rubygem-bigdecimal rubygem-rake rubygem-i18n rubygem-bundler

# Step 2: Git and SVN
echo "[*] Installing git and svn..."
sudo dnf -y install git svn

# Step 3: Build dependencies for native extensions
echo "[*] Installing build dependencies..."
sudo dnf -y install ruby-devel libpcap-devel

# Step 4: Get latest rake
echo "[*] Installing latest rake..."
sudo gem install rake

# Step 5: Database support (PostgreSQL recommended)
echo "[*] Installing PostgreSQL..."
sudo dnf -y install postgresql-server postgresql-devel
sudo gem install pg

# Step 6: Clone Metasploit from GitHub
echo "[*] Cloning Metasploit Framework..."
cd /opt
sudo git clone https://github.com/rapid7/metasploit-framework.git
sudo chown -R root:root /opt/metasploit-framework

# Step 7: Create symlinks
echo "[*] Creating symlinks..."
sudo ln -sf /opt/metasploit-framework/msf* /usr/local/bin/
sudo ln -sf /opt/metasploit-framework/msfconsole /usr/local/bin/
sudo ln -sf /opt/metasploit-framework/msfvenom /usr/local/bin/

# Step 8: Install gems
echo "[*] Installing Ruby gems..."
cd /opt/metasploit-framework
sudo bundle install

echo ""
echo "=============================================="
echo "[V] METASPLOIT INSTALLATION COMPLETE!"
echo "=============================================="
echo ""
echo "Verify with:"
echo "  msfconsole --version"
echo "  msfvenom --version"
echo ""
echo "Note: For database, run: sudo systemctl start postgresql"