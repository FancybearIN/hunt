#!/bin/bash

# =========================
# USAGE CHECK
# =========================
if [ $# -ne 1 ]; then
  echo "Usage: $0 subdomains.txt"
  exit 1
fi

INPUT_FILE="$1"

if [ ! -f "$INPUT_FILE" ]; then
  echo "[!] File not found: $INPUT_FILE"
  exit 1
fi

# =========================
# TOOLS CHECK
# =========================
for tool in httpx jq; do
  command -v $tool >/dev/null 2>&1 || {
    echo "[!] Missing dependency: $tool"
    exit 1
  }
done

# =========================
# OUTPUT DIR
# =========================
BASENAME=$(basename "$INPUT_FILE" .txt)
OUTDIR="recon_${BASENAME}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"

echo "[+] Recon started"
echo "[+] Input : $INPUT_FILE"
echo "[+] Output: $OUTDIR"

# =========================
# NORMALIZE INPUT
# =========================
sed -E 's#^https?://##' "$INPUT_FILE" | sort -u > "$OUTDIR/targets.txt"

# =========================
# LIVE CHECK
# =========================
echo "[+] Checking live hosts"

httpx -l "$OUTDIR/targets.txt" \
  -silent \
  -timeout 5 \
  -retries 2 > "$OUTDIR/live.txt"

# =========================
# HTTPX FULL ENUM
# =========================
echo "[+] Enumerating tech, ports, IP"

httpx -l "$OUTDIR/live.txt" \
  -tech-detect \
  -status-code \
  -title \
  -web-server \
  -content-length \
  -ip \
  -ports 80,443,8080,8000,8888,3000,5000 \
  -json > "$OUTDIR/httpx_full.json"

# =========================
# SUMMARY
# =========================
jq -r '
"\(.url) | \(.status_code) | port:\(.port) | \(.title) | \(.webserver) | \(.tech) | IP:\(.ip)"
' "$OUTDIR/httpx_full.json" > "$OUTDIR/httpx_summary.txt"

# =========================
# IP FILE
# =========================
jq -r '.ip' "$OUTDIR/httpx_full.json" | sort -u > "$OUTDIR/ips.txt"

# =========================
# DIRSEARCH URLS
# =========================
sed 's#/$##' "$OUTDIR/live.txt" | sort -u > "$OUTDIR/dirsearch_urls.txt"

# =========================
# INTERESTING FINDINGS
# =========================
jq -r '
select(
  (.url | test("admin|api|auth|login|dev|stage|internal|beta"; "i"))
  or (.status_code != 200)
  or (.port != 80 and .port != 443)
)
| "\(.url) | \(.status_code) | port:\(.port) | \(.tech) | \(.title)"
' "$OUTDIR/httpx_full.json" > "$OUTDIR/interesting.txt"

# =========================
# DONE
# =========================
echo "[✓] Recon completed"
echo "[✓] Files generated:"
ls -1 "$OUTDIR"
