#!/bin/bash

DOMAINS_FILE=$1
SHODAN_OUTPUT="shodan_ssl_results.txt"
NAABU_OUTPUT="naabu_results.txt"

# Clear previous output files
> "$SHODAN_OUTPUT"
> "$NAABU_OUTPUT"

# Check Shodan CLI auth
if ! shodan info &>/dev/null; then
    echo "[!] Shodan CLI not authenticated. Run: shodan init YOUR_API_KEY"
    exit 1
fi

echo "[*] Starting Shodan SSL IP extraction..."

while read -r domain; do
    [[ -z "$domain" ]] && continue
    echo "[*] Searching for IPs with SSL: $domain"
    shodan search --fields ip_str "ssl:$domain" 2>/dev/null | tee -a "$SHODAN_OUTPUT"
done < "$DOMAINS_FILE"

# Deduplicate IPs for scanning
sort -u "$SHODAN_OUTPUT" > shodan_ips.txt

echo "[*] Running Naabu full port scan on resolved IPs..."
nuclei -l shodan_ips.txt  -o "$NAABU_OUTPUT"

echo "[+] Done!"
echo " - Shodan results saved to: $SHODAN_OUTPUT"
echo " - Naabu scan results saved to: $NAABU_OUTPUT"
