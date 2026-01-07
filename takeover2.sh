#!/bin/bash

INPUT_FILE="$1"
if [[ ! -f "$INPUT_FILE" ]]; then
    echo "[!] Usage: $0 domains.txt"
    exit 1
fi

WORKDIR="takeover_file_scan_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$WORKDIR"

RAW_SUBS="$WORKDIR/raw_subdomains.txt"
ALL_SUBS="$WORKDIR/all_subdomains.txt"
STAGE2_SUBS="$WORKDIR/stage2_alterx.txt"

ALL_DIGS="$WORKDIR/all_digs.txt"
ALL_CNAME="$WORKDIR/all_cnames.txt"
POTENTIAL_TAKEOVERS="$WORKDIR/potential_takeovers.txt"

> "$RAW_SUBS"

echo "[*] Starting enumeration with inline alterx..."

while read -r domain; do
    echo "[*] Target: $domain"

    TMP_RAW="$WORKDIR/${domain}_subs.txt"

    {
        subfinder -d "$domain" -silent
        chaos-client -d "$domain"
        assetfinder --subs-only "$domain"
        alterx -d "$domain" -silent
    } | sort -u | tee "$TMP_RAW"

    cat "$TMP_RAW" >> "$RAW_SUBS"

done < "$INPUT_FILE"

echo "[*] Deduplicating collected subdomains..."
sort -u "$RAW_SUBS" | tee "$ALL_SUBS"

echo "[*] Running alterx stage-2 (global permutations)..."
alterx -list "$ALL_SUBS" -silent | sort -u | tee "$STAGE2_SUBS"

echo "[*] Finalizing subdomain list..."
cat "$ALL_SUBS" "$STAGE2_SUBS" | sort -u | tee "$ALL_SUBS.final"
mv "$ALL_SUBS.final" "$ALL_SUBS"

echo "[*] Running DNS dig on final subdomain list..."
while read -r sub; do
    dig "$sub" +noall +answer
done < "$ALL_SUBS" | tee "$ALL_DIGS"

echo "[*] Extracting CNAME records..."
grep -i "CNAME" "$ALL_DIGS" | tee "$ALL_CNAME"

echo "[*] Identifying potential takeover candidates..."
awk '{print $1 " CNAME -> " $5}' "$ALL_CNAME" | tee "$POTENTIAL_TAKEOVERS"

echo
echo "[+] Done"
echo " - Raw + stage1 subs: $RAW_SUBS"
echo " - Final subdomains:  $ALL_SUBS"
echo " - CNAME records:    $ALL_CNAME"
echo " - Takeover leads:   $POTENTIAL_TAKEOVERS"
