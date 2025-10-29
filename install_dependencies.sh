#!/bin/bash

echo "[*] Updating package lists..."
sudo apt update

echo "[*] Installing required tools..."
sudo apt install -y \
    curl wget jq git python3-pip nmap whois subfinder assetfinder \
    gau httpx sqlmap feroxbuster ffuf nuclei dalfox gospider \
    waybackurls hakrawler amass xsstrike gf xargs ffuf metabigor \
    cariddi prips bbrf shodan massdns dnsgen gowitness naabu psql

echo "[*] Installing Python tools..."
pip3 install uro xsstrike secretfinder airixss freq paramspider

echo "[*] Installing Go-based tools..."
GO_PACKAGES=(
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
  "github.com/projectdiscovery/httpx/cmd/httpx"
  "github.com/projectdiscovery/nuclei/v2/cmd/nuclei"
  "github.com/projectdiscovery/naabu/v2/cmd/naabu"
  "github.com/tomnomnom/anew"
  "github.com/tomnomnom/qsreplace"
  "github.com/hakluke/hakrawler"
  "github.com/jaeles-project/jaeles"
  "github.com/ffuf/ffuf"
)

for pkg in "${GO_PACKAGES[@]}"; do
  go install "$pkg@latest"
done

echo "[*] Installation complete!"
