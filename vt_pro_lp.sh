#!/bin/bash

if [ $# -ne 1 ]; then
  echo "Usage: $0 domains.txt"
  exit 1
fi

INPUT="$1"

for tool in vt jq httpx; do
  command -v $tool >/dev/null 2>&1 || {
    echo "[!] Missing tool: $tool"
    exit 1
  }
done

#if [ -z "$VT_API_KEY" ]; then
#  echo "[!] VT_API_KEY not set"
#  exit 1
#fi

OUTDIR="vt_recon_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"

ALL_DOMAINS="$OUTDIR/domains_all.txt"
LIVE_DOMAINS="$OUTDIR/live_domains.txt"
HTTPX_JSON="$OUTDIR/httpx_full.json"
IP_FILE="$OUTDIR/ip.txt"

touch "$ALL_DOMAINS"

echo "[+] VT-only recon started"

while read -r DOMAIN; do
  DOMAIN=$(echo "$DOMAIN" | sed 's#https\?://##' | xargs)
  [ -z "$DOMAIN" ] && continue

  echo "[+] VirusTotal enum: $DOMAIN"

  # root domain
  echo "$DOMAIN" >> "$ALL_DOMAINS"

  # VT subdomains (JSON SAFE)
  vt domain "$DOMAIN" --format json 2>/dev/null \
    | jq -r '.data.attributes.subdomains[]?' \
    | sed "s/^/./" \
    | sed "s/^/$DOMAIN/" \
    >> "$ALL_DOMAINS"

done < "$INPUT"

sort -u "$ALL_DOMAINS" -o "$ALL_DOMAINS"

echo "[+] Checking live domains"
httpx -l "$ALL_DOMAINS" -silent > "$LIVE_DOMAINS"

echo "[+] Collecting httpx full info"
httpx -l "$LIVE_DOMAINS" \
  -status-code \
  -title \
  -tech-detect \
  -web-server \
  -content-length \
  -ip \
  -ports 80,443,8080,8000,8888,3000,5000 \
  -json > "$HTTPX_JSON"

jq -r '.ip' "$HTTPX_JSON" | sort -u > "$IP_FILE"

echo "[✓] Done"
echo "[✓] Domains : $(wc -l < "$ALL_DOMAINS")"
echo "[✓] Live    : $(wc -l < "$LIVE_DOMAINS")"
echo "[✓] IPs     : $(wc -l < "$IP_FILE")"
