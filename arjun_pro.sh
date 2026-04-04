#!/bin/bash

# ==============================
# CONFIG
# ==============================
OUTDIR="recon_output"
THREADS=20
SECLISTS_PARAMS="/usr/share/seclists/Discovery/Web-Content/Parameters/burp-parameter-names.txt"

mkdir -p "$OUTDIR"

INPUT_FILE="$1"

if [[ -z "$INPUT_FILE" ]]; then
  echo "Usage: $0 urls.txt"
  exit 1
fi

# ==============================
# AUTO-DETECT MODE (URL FILE)
# ==============================
first_line=$(grep -m1 -v '^$' "$INPUT_FILE")

if [[ ! "$first_line" =~ ^https?:// ]]; then
  echo "[!] This script expects a URL file"
  exit 1
fi

echo "[+] URL mode detected"

# ==============================
# NORMALIZE URLS
# ==============================
echo "[+] Normalizing URLs..."
sort -u "$INPUT_FILE" | sed 's/#.*//' > "$OUTDIR/all_urls.txt"

# ==============================
# FILTER DYNAMIC ENDPOINTS
# ==============================
echo "[+] Filtering dynamic endpoints..."

grep -Ei '\?|\.php|\.aspx|\.jsp|\.do|\.action' "$OUTDIR/all_urls.txt" | \
grep -Evi 'robots\.txt$|\.css$|\.js$|\.png$|\.jpg$|\.jpeg$|\.svg$|\.gif$' | \
sort -u > "$OUTDIR/arjun_targets.txt"

# ==============================
# EXTRACT HISTORICAL PARAMETERS
# ==============================
echo "[+] Extracting historical parameters..."

grep '?' "$OUTDIR/arjun_targets.txt" | \
sed 's/.*?//' | \
tr '&' '\n' | \
cut -d= -f1 | \
grep -Ev '^$' | \
sort -u > "$OUTDIR/url_params.txt"

# ==============================
# MERGE WITH SECLISTS (SAFE)
# ==============================
echo "[+] Building final parameter wordlist..."

if [[ -f "$SECLISTS_PARAMS" ]]; then
  cat "$OUTDIR/url_params.txt" "$SECLISTS_PARAMS" | sort -u > "$OUTDIR/final_params.txt"
else
  echo "[!] SecLists not found — using URL params only"
  cp "$OUTDIR/url_params.txt" "$OUTDIR/final_params.txt"
fi

# ==============================
# SELECT HIGH-VALUE ARJUN TARGETS
# ==============================
echo "[+] Selecting high-value endpoints (dynamic + historical params)..."

awk -F'?' '
  /\?/ { seen[$1]=1 }                             # endpoints that had params
  /\.(php|aspx|jsp|do|action)$/ { dyn[$0]=1 }     # dynamic endpoints
  END {
    for (e in seen)
      if (dyn[e]) print e
  }
' "$OUTDIR/arjun_targets.txt" | sort -u > "$OUTDIR/arjun_high_value.txt"

# ==============================
# RUN ARJUN
# ==============================
echo "[+] Running Arjun on high-value targets..."

while read -r endpoint; do
  clean=$(echo "$endpoint" | sed 's|https\?://||g' | tr '/' '_')

  arjun \
    -u "$endpoint" \
    -m GET,POST \
    -w "$OUTDIR/final_params.txt" \
    -t "$THREADS" \
    -o "$OUTDIR/arjun_$clean.json"

done < "$OUTDIR/arjun_high_value.txt"

echo "[+] Done. Results saved in $OUTDIR/"
