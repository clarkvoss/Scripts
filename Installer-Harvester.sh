#!/bin/bash

# Auto-installer for dependencies required by Js-endpoint-harvester.sh
# This script assumes a Debian-based system (e.g., Ubuntu/Kali) and requires sudo privileges.
# It installs Go, Python, and other base tools, then installs the specific recon tools.
# Run with: sudo bash installer.sh
# Note: Some tools may require manual configuration or PATH updates after installation.
#       Restart your shell or run 'source ~/.profile' after installation.

set -euo pipefail

echo "[+] Starting installation of dependencies..."

# Update package list
sudo apt update -y

# Install base dependencies
sudo apt install -y golang-go python3 python3-pip git curl jq parallel ruby-full build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev wget libbz2-dev

# Install Go if not present (version 1.21+ recommended)
if ! command -v go &> /dev/null; then
    echo "[+] Installing Go..."
    wget https://go.dev/dl/go1.21.3.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf go1.21.3.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' | sudo tee -a /etc/profile
    export PATH=$PATH:/usr/local/go/bin
    rm go1.21.3.linux-amd64.tar.gz
else
    echo "[+] Go is already installed."
fi

# Install Python pip dependencies globally or in user space
pip3 install --user requests beautifulsoup4

# Install Go-based tools
echo "[+] Installing Go-based tools..."
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/hakluke/hakrawler@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/jaeles-project/gospider@latest
go install github.com/tomnomnom/gf@latest

# Move Go binaries to /usr/local/bin if needed
cp ~/go/bin/* /usr/local/bin/ || true

# Install Arjun
echo "[+] Installing Arjun..."
pip3 install arjun

# Install ParamSpider
echo "[+] Installing ParamSpider..."
git clone https://github.com/devanshbatham/ParamSpider /tmp/ParamSpider
cd /tmp/ParamSpider
pip3 install -r requirements.txt
sudo cp paramspider.py /usr/local/bin/paramspider
cd -
rm -rf /tmp/ParamSpider

# Install CeWL
echo "[+] Installing CeWL..."
git clone https://github.com/digininja/CeWL /tmp/CeWL
cd /tmp/CeWL
gem install bundler
bundle install
sudo cp cewl.rb /usr/local/bin/cewl
cd -
rm -rf /tmp/CeWL

# Install Interlace
echo "[+] Installing Interlace..."
git clone https://github.com/codingo/Interlace /tmp/Interlace
cd /tmp/Interlace
python3 setup.py install
cd -
rm -rf /tmp/Interlace

# Install LinkFinder (placed in /opt/LinkFinder)
echo "[+] Installing LinkFinder..."
sudo git clone https://github.com/GerbenJavado/LinkFinder /opt/LinkFinder
cd /opt/LinkFinder
sudo python3 setup.py install
cd -

# Install SecretFinder (placed in /opt/SecretFinder)
echo "[+] Installing SecretFinder..."
sudo git clone https://github.com/m4ll0k/SecretFinder /opt/SecretFinder
cd /opt/SecretFinder
sudo pip3 install -r requirements.txt
cd -

echo "[+] Installation complete! Please ensure /usr/local/bin is in your PATH."
echo "    You may need to restart your terminal or run 'source ~/.profile'."
echo "    Test by running: waybackurls --version (or similar for other tools)."