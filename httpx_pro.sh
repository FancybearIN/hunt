#!/usr/bin/env bash
# ==========================================
# httpx_pro.sh - Parallel httpx runner
# Usage: bash httpx_pro.sh <subdomains.txt>
# ==========================================

set -euo pipefail

# ---------- AUTO SYSTEM TUNING ----------
CPU_CORES=$(nproc)
PARALLEL_JOBS=$((CPU_CORES * 2))
HTTPX_THREADS=100
CHUNK_SIZE=5000
TIMEOUT=5
RETRIES=2

# ---------- WEB PORTS -------------------
WEB_PORTS="80,81,443,3000,3001,4443,5000,5001,7001,7443,8000,8008,8080,8081,8082,8083,8443,8444,8888,9000,9001,9090,9200,9443,10000"

# ---------- INPUT CHECK -----------------
if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <all_subdomains.txt>"
  exit 1
fi

INPUT_FILE="$1"

if [[ ! -f "$INPUT_FILE" ]]; then
  echo "[!] Input file not found"
  exit 1
fi

# ---------- OUTPUT FILES ----------------
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTDIR="httpx_results_$TIMESTAMP"
mkdir -p "$OUTDIR"

HTTPX_FULL="$OUTDIR/httpx_full.txt"           # full httpx output with status/title/tech
HTTPX_URLS="$OUTDIR/urls.txt"                  # https://sub.domain.com:port
HTTPX_CLEAN="$OUTDIR/clean.txt"                # sub.domain.com:port  (NO http/https)
HTTPX_DOMAINS_ONLY="$OUTDIR/domains_only.txt"  # sub.domain.com       (no port, no scheme)
HTTPX_200="$OUTDIR/status_200.txt"             # only 200 OK URLs
HTTPX_403="$OUTDIR/status_403.txt"             # 403 — potential bypass targets
HTTPX_401="$OUTDIR/status_401.txt"             # 401 — auth required pages
HTTPX_REDIRECT="$OUTDIR/redirects.txt"         # 301/302 redirects
HTTPX_ERRORS="$OUTDIR/errors.txt"              # 500/502/503 error pages
HTTPX_INTERESTING="$OUTDIR/interesting.txt"    # login/admin/api/dashboard pages

# ---------- WORKDIR ---------------------
WORKDIR=$(mktemp -d)
CHUNKS="$WORKDIR/chunks"
RESULTS="$WORKDIR/results"
mkdir -p "$CHUNKS" "$RESULTS"

TOTAL=$(wc -l < "$INPUT_FILE")
echo "======================================="
echo "[*] Input file : $INPUT_FILE"
echo "[*] Subdomains : $TOTAL"
echo "[*] CPU cores  : $CPU_CORES"
echo "[*] Jobs       : $PARALLEL_JOBS"
echo "[*] Threads    : $HTTPX_THREADS"
echo "[*] Ports      : $WEB_PORTS"
echo "[*] Output dir : $OUTDIR/"
echo "======================================="

# ---------- SPLIT -----------------------
split -l "$CHUNK_SIZE" "$INPUT_FILE" "$CHUNKS/subs_"

# ---------- PARALLEL HTTPX --------------
ls "$CHUNKS"/subs_* | xargs -P "$PARALLEL_JOBS" -I {} bash -c '
  httpx \
    -l {} \
    -ports '"$WEB_PORTS"' \
    -threads '"$HTTPX_THREADS"' \
    -timeout '"$TIMEOUT"' \
    -retries '"$RETRIES"' \
    -silent \
    -status-code \
    -title \
    -tech-detect \
    -ip \
    -follow-redirects \
    -o '"$RESULTS"'/$(basename {}).out
'

# ---------- MERGE FULL OUTPUT -----------
cat "$RESULTS"/*.out 2>/dev/null | sort -u > "$HTTPX_FULL"
TOTAL_FOUND=$(wc -l < "$HTTPX_FULL")

# ---------- URLS ONLY (with scheme) -----
# e.g. https://sub.domain.com:8080
awk '{print $1}' "$HTTPX_FULL" | sort -u > "$HTTPX_URLS"

# ---------- CLEAN (NO http:// or https://) -----
# e.g. sub.domain.com:8080
sed -E 's|https?://||g' "$HTTPX_URLS" \
  | sed 's|/$||g' \
  | sort -u > "$HTTPX_CLEAN"

# ---------- DOMAINS ONLY (no port, no scheme) -----
# e.g. sub.domain.com
sed -E 's|https?://||g' "$HTTPX_URLS" \
  | cut -d':' -f1 \
  | cut -d'/' -f1 \
  | sort -u > "$HTTPX_DOMAINS_ONLY"

# ---------- FILTER BY STATUS CODE -------
grep " \[200\]" "$HTTPX_FULL" | awk '{print $1}' | sort -u > "$HTTPX_200"
grep " \[403\]" "$HTTPX_FULL" | awk '{print $1}' | sort -u > "$HTTPX_403"
grep " \[401\]" "$HTTPX_FULL" | awk '{print $1}' | sort -u > "$HTTPX_401"
grep -E " \[30[1278]\]" "$HTTPX_FULL" | awk '{print $1}' | sort -u > "$HTTPX_REDIRECT"
grep -E " \[50[0-9]\]" "$HTTPX_FULL" | awk '{print $1}' | sort -u > "$HTTPX_ERRORS"

# ---------- INTERESTING PAGES -----------
grep -Ei "(login|admin|dashboard|portal|api|swagger|jenkins|kibana|grafana|phpmyadmin|jira|gitlab|manage|console|monitor|internal|dev|staging|test|upload|backup)" \
  "$HTTPX_FULL" | awk '{print $1}' | sort -u > "$HTTPX_INTERESTING"

# ---------- REMOVE EMPTY FILES ----------
for f in "$OUTDIR"/*.txt; do
  [[ ! -s "$f" ]] && rm -f "$f"
done

# ---------- CLEANUP ---------------------
rm -rf "$WORKDIR"

# ---------- SUMMARY ---------------------
echo ""
echo "======================================="
echo "[✓] Scan complete"
echo "======================================="
echo "[*] Total live hosts     : $TOTAL_FOUND"
echo ""
echo "--- Output Files ---"
[[ -f "$HTTPX_FULL" ]]         && echo "[✓] Full output          : $HTTPX_FULL ($(wc -l < $HTTPX_FULL) lines)"
[[ -f "$HTTPX_URLS" ]]         && echo "[✓] URLs (with scheme)   : $HTTPX_URLS ($(wc -l < $HTTPX_URLS) lines)"
[[ -f "$HTTPX_CLEAN" ]]        && echo "[✓] Clean (no scheme)    : $HTTPX_CLEAN ($(wc -l < $HTTPX_CLEAN) lines)"
[[ -f "$HTTPX_DOMAINS_ONLY" ]] && echo "[✓] Domains only         : $HTTPX_DOMAINS_ONLY ($(wc -l < $HTTPX_DOMAINS_ONLY) lines)"
echo ""
echo "--- By Status Code ---"
[[ -f "$HTTPX_200" ]]          && echo "[✓] 200 OK               : $HTTPX_200 ($(wc -l < $HTTPX_200) lines)"
[[ -f "$HTTPX_401" ]]          && echo "[✓] 401 Unauthorized     : $HTTPX_401 ($(wc -l < $HTTPX_401) lines)"
[[ -f "$HTTPX_403" ]]          && echo "[✓] 403 Forbidden        : $HTTPX_403 ($(wc -l < $HTTPX_403) lines)"
[[ -f "$HTTPX_REDIRECT" ]]     && echo "[✓] 301/302 Redirects    : $HTTPX_REDIRECT ($(wc -l < $HTTPX_REDIRECT) lines)"
[[ -f "$HTTPX_ERRORS" ]]       && echo "[✓] 5xx Errors           : $HTTPX_ERRORS ($(wc -l < $HTTPX_ERRORS) lines)"
echo ""
echo "--- High Priority ---"
[[ -f "$HTTPX_INTERESTING" ]]  && echo "[🔥] Interesting pages   : $HTTPX_INTERESTING ($(wc -l < $HTTPX_INTERESTING) lines)"
echo ""
echo "--- Next Steps ---"
echo "  1. cat $HTTPX_INTERESTING   → manually visit each"
echo "  2. cat $HTTPX_403           → test 403 bypass techniques"
echo "  3. cat $HTTPX_401           → test for auth bypass"
echo "  4. cat $HTTPX_CLEAN         → feed into nuclei/other tools (no scheme)"
echo "  5. nuclei -l $HTTPX_200 -t exposures/ -t misconfiguration/"
echo "======================================="
