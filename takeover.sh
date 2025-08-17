#!/bin/bash

INPUT_FILE="$1"
if [[ ! -f "$INPUT_FILE" ]]; then
    echo "[!] Usage: $0 domains.txt"
    exit 1
fi

WORKDIR="takeover_file_scan_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$WORKDIR"

ALL_DOMAINS="$WORKDIR/all_subdomains.txt"
ALL_DIGS="$WORKDIR/all_digs.txt"
ALL_CNAME="$WORKDIR/all_cnames.txt"
POTENTIAL_TAKEOVERS="$WORKDIR/potential_takeovers.txt"

echo "[*] Starting subdomain takeover scan from $INPUT_FILE..."

while read domain; do
    echo "[*] Finding subdomains for: $domain"
    subfinder -d "$domain" -silent
done < "$INPUT_FILE" | sort -u | tee "$ALL_DOMAINS"

echo "[*] Running dig on all discovered subdomains..."
cat "$ALL_DOMAINS" | while read sub; do
    dig "$sub" +noall +answer
done | tee "$ALL_DIGS"

echo "[*] Extracting CNAME records..."
grep -i "CNAME" "$ALL_DIGS" | tee "$ALL_CNAME"

echo "[*] Identifying potential 3rd-party takeovers..."
awk '{print $1 " CNAME -> " $5}' "$ALL_CNAME" | tee "$POTENTIAL_TAKEOVERS"

echo "[+] Done! Results:"
echo " - All Subdomains: $ALL_DOMAINS"
echo " - dig Output:     $ALL_DIGS"
echo " - CNAME Records:  $ALL_CNAME"
echo " - Takeover Leads: $POTENTIAL_TAKEOVERS"
