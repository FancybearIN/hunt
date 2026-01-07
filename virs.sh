#!/usr/bin/env bash

API_KEY="834a3eef1c74c2977b7d5230e06ba6cba023fc81b39e63bb19d757140f72569d"
INPUT="$1"
OUTDIR="vt_output"
SLEEP=16   # VT public API ≈ 4 req/min

mkdir -p "$OUTDIR/raw" "$OUTDIR/pretty" "$OUTDIR/extracted"

while read -r domain; do
  [[ -z "$domain" ]] && continue
  echo "[*] Processing $domain"

  RAW="$OUTDIR/raw/${domain}.json"
  PRETTY="$OUTDIR/pretty/${domain}.pretty.json"
  EXTRACT="$OUTDIR/extracted/${domain}.summary.txt"

  curl -s \
    "https://www.virustotal.com/vtapi/v2/domain/report?apikey=${API_KEY}&domain=${domain}" \
    -o "$RAW"

  # sanity check
  if ! jq -e '.response_code' "$RAW" >/dev/null 2>&1; then
    echo "[!] Invalid response for $domain"
    continue
  fi

  # pretty JSON
  jq '.' "$RAW" > "$PRETTY"

  # extract high-value intel
  {
    echo "Domain: $domain"
    echo "------------------------------------"
    echo "[Subdomains]"
    jq -r '.subdomains[]?' "$RAW"

    echo
    echo "[Resolved IPs]"
    jq -r '.resolutions[]? | "\(.ip_address) \(.last_resolved)"' "$RAW"

    echo
    echo "[Sibling Domains]"
    jq -r '.domain_siblings[]?' "$RAW"

    echo
    echo "[Detected URLs]"
    jq -r '.detected_urls[]? | "\(.url) | positives=\(.positives)/\(.total)"' "$RAW"

    echo
    echo "[Whois Snippet]"
    jq -r '.whois // "N/A"' "$RAW" | head -n 20
  } > "$EXTRACT"

  sleep "$SLEEP"
done < "$INPUT"

echo "[✓] Done. Output in $OUTDIR/"
