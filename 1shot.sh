#!/bin/bash

echo "# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ #     "
echo "# █▀▀ █▀█ █▀▀ ▄▀█ ▀█▀ █▀▀ █▀▄   █▄▄ █▄█   █▀█ █▀█ █░░ █▄█ █▀▄▀█ █▀█ █▀█ █▀█ █░█         "
echo "# █▄▄ █▀▄ ██▄ █▀█ ░█░ ██▄ █▄▀   █▄█ ░█░   █▀▀ █▄█ █▄▄ ░█░ █░▀░█ █▄█ █▀▄ █▀▀ █▀█         "
echo "# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ #     "
echo "# Project Discovery Recon Oneshot                                                       "
echo "# Using : Naabu, Subfinder, Katana, Httpx, Shuffledns & MassDNS                         "
echo "# Available @ : https://github.com/projectdiscovery                                     "
echo "# USAGE: ./1shot.sh <domain.com>                                                        "
echo "# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ #     "
echo "#  █░█░█ █░█░█ █░█░█ ░ █░░ █ █▄░█ █▄▀ █▀▀ █▀▄ █ █▄░█ ░ █▀▀ █▀█ █▀▄▀█ ░░▄▀ █ █▄░█ ░░▄▀ █▄▄ █▀█ █▄█ █▀▀ █▀▀ ▀█ █▀▀ "
echo "#  ▀▄▀▄▀ ▀▄▀▄▀ ▀▄▀▄▀ ▄ █▄▄ █ █░▀█ █░█ ██▄ █▄▀ █ █░▀█ ▄ █▄▄ █▄█ █░▀░█ ▄▀░░ █ █░▀█ ▄▀░░ █▄█ █▀▄ ░█░ █▄▄ ██▄ █▄ █▄█ "
echo "# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ # "


TARGET=$1
DATE=$(date +%F)
WORKSPACE="recon_${TARGET}_${DATE}"

if [ -z "$TARGET" ]; then
    echo "Usage: ./1shot.sh <domain.com>"
    exit 1
fi

echo "[+] Creating workspace: $WORKSPACE"
mkdir -p "$WORKSPACE"
cd "$WORKSPACE" || exit

# --- RESOLVER MANAGEMENT ---
# ShuffleDNS needs a solid list of public resolvers to accuratly report live targets.
if [ ! -f "resolvers.txt" ]; then
    echo "[+] Downloading fresh trusted resolvers..."
    wget -q https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt -O resolvers.txt
fi
# ---------------------------

# 1. Subdomain Discovery (Subfinder)
echo "[+] Running Subfinder..."
subfinder -d "$TARGET" -all -silent > subfinder_raw.txt
echo "[+] Found $(wc -l < subfinder_raw.txt) raw subdomains."

if [ ! -s subfinder_raw.txt ]; then
    echo "[-] No subdomains found. Exiting."
    exit 1
fi

# 2. DNS Resolution & Filtering (ShuffleDNS + MassDNS)
# This confirms which subdomains actually resolve to an IP, dropping dead hosts.
echo "[+] Running ShuffleDNS (Resolving via MassDNS)..."
shuffledns -d "$TARGET" -list subfinder_raw.txt -r resolvers.txt -mode resolve -silent > alive_subdomains.txt
echo "[+] Resolved $(wc -l < alive_subdomains.txt) ALIVE subdomains."

if [ ! -s alive_subdomains.txt ]; then
    echo "[-] No alive subdomains resolved. Exiting."
    exit 1
fi

# 3. Port Scanning (Naabu)
# Now Naabu only scans hosts we know are online.
echo "[+] Running Naabu (Port Scan)..."
naabu -list alive_subdomains.txt -c 50 -rate 1000 -silent > open_ports.txt

if [ ! -s open_ports.txt ]; then
    echo "[-] No open ports found. Exiting."
    exit 1
fi

# 4. HTTP Service Discovery (httpx)
echo "[+] Running httpx (Web Service Probe)..."
cat open_ports.txt | httpx -silent -title -tech-detect -status-code -json -o web_assets.json

# Extract Base URLs for the next steps
jq -r '.url' web_assets.json > live_urls.txt
echo "[+] Live Base URLs identified: $(wc -l < live_urls.txt)"

# 5. Spidering & Crawling (Katana)
echo "[+] Running Katana (Crawler)..."
katana -list live_urls.txt -jc -kf all -ct 2 -d 3 -silent | grep -ivE '\.(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)$' | sort -u > crawled_endpoints.txt
echo "[+] Actionable Endpoints Crawled: $(wc -l < crawled_endpoints.txt)"


# 6. Reporting
echo "-------------------------------------------------------"
echo "Reconnaissance Complete for $TARGET"
echo "Summary:"
echo " - Raw Subdomains:      $(wc -l < subfinder_raw.txt)"
echo " - Alive Subdomains:    $(wc -l < alive_subdomains.txt)"
echo " - Open Ports:          $(wc -l < open_ports.txt)"
echo " - Live Web Servers:    $(wc -l < live_urls.txt)"
echo " - Crawled Endpoints:   $(wc -l < crawled_endpoints.txt)"
echo "-------------------------------------------------------"
echo "Data stored in: $PWD"
