#!/bin/bash
# ============================================================
# saaho.sh - Shodan Deep Recon + Nuclei Scanner
# Usage: bash saaho.sh domains.txt
# ============================================================

DOMAINS_FILE="$1"
if [[ ! -f "$DOMAINS_FILE" ]]; then
    echo "[!] Usage: $0 domains.txt"
    exit 1
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m'

# Check Shodan auth
if ! shodan info &>/dev/null; then
    echo -e "${RED}[!] Shodan CLI not authenticated. Run: shodan init YOUR_API_KEY${NC}"
    exit 1
fi

WORKDIR="shodan_recon_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$WORKDIR"

# Output files
RAW_IPS="$WORKDIR/raw_ips.txt"
CLEAN_IPS="$WORKDIR/unique_ips.txt"
SHODAN_FULL="$WORKDIR/shodan_full.txt"
OPEN_PORTS="$WORKDIR/open_ports.txt"
EXPOSED_PANELS="$WORKDIR/exposed_panels.txt"
INTERESTING="$WORKDIR/interesting_findings.txt"
NUCLEI_OUT="$WORKDIR/nuclei_results.txt"
NAABU_OUT="$WORKDIR/naabu_ports.txt"
REPORT="$WORKDIR/REPORT.txt"

> "$RAW_IPS"
> "$SHODAN_FULL"
> "$INTERESTING"

# ============================================================
# STEP 1 — SHODAN IP EXTRACTION WITH MULTIPLE DORKS
# ============================================================
echo -e "${CYAN}[*] STEP 1: Running Shodan dorks per domain...${NC}"

while read -r domain; do
    [[ -z "$domain" ]] && continue
    echo -e "${BLUE}[+] Target: $domain${NC}"

    # ---- SSL/TLS dorks ----
    echo -e "  ${YELLOW}[~] SSL cert dorks...${NC}"
    shodan search --fields ip_str,port,org,hostnames "ssl:$domain" 2>/dev/null \
        | tee -a "$SHODAN_FULL" | awk '{print $1}' >> "$RAW_IPS"

    shodan search --fields ip_str,port,org,hostnames "ssl.cert.subject.cn:$domain" 2>/dev/null \
        | tee -a "$SHODAN_FULL" | awk '{print $1}' >> "$RAW_IPS"

    shodan search --fields ip_str,port,org,hostnames "ssl.cert.subject.cn:*.$domain" 2>/dev/null \
        | tee -a "$SHODAN_FULL" | awk '{print $1}' >> "$RAW_IPS"

    shodan search --fields ip_str,port,org,hostnames "ssl.cert.issuer.cn:$domain" 2>/dev/null \
        | tee -a "$SHODAN_FULL" | awk '{print $1}' >> "$RAW_IPS"

    # ---- HTTP title/header dorks ----
    echo -e "  ${YELLOW}[~] HTTP header/title dorks...${NC}"
    shodan search --fields ip_str,port,org,hostnames "http.title:$domain" 2>/dev/null \
        | tee -a "$SHODAN_FULL" | awk '{print $1}' >> "$RAW_IPS"

    shodan search --fields ip_str,port,org,hostnames "http.html:$domain" 2>/dev/null \
        | tee -a "$SHODAN_FULL" | awk '{print $1}' >> "$RAW_IPS"

    shodan search --fields ip_str,port,org,hostnames "http.favicon.hash:-*domain*" 2>/dev/null \
        | tee -a "$SHODAN_FULL" | awk '{print $1}' >> "$RAW_IPS"

    # ---- Hostname dorks ----
    echo -e "  ${YELLOW}[~] Hostname dorks...${NC}"
    shodan search --fields ip_str,port,org,hostnames "hostname:$domain" 2>/dev/null \
        | tee -a "$SHODAN_FULL" | awk '{print $1}' >> "$RAW_IPS"

    shodan search --fields ip_str,port,org,hostnames "hostname:*.$domain" 2>/dev/null \
        | tee -a "$SHODAN_FULL" | awk '{print $1}' >> "$RAW_IPS"

    # ---- Org/ASN based ----
    echo -e "  ${YELLOW}[~] Org dorks...${NC}"
    ORG=$(echo "$domain" | awk -F'.' '{print $1}')
    shodan search --fields ip_str,port,org,hostnames "org:\"$ORG\"" 2>/dev/null \
        | tee -a "$SHODAN_FULL" | awk '{print $1}' >> "$RAW_IPS"

    # ---- Exposed services dorks ----
    echo -e "  ${YELLOW}[~] Exposed services dorks...${NC}"

    # Admin panels
    shodan search --fields ip_str,port,org "http.title:\"admin\" ssl:$domain" 2>/dev/null \
        | tee -a "$SHODAN_FULL" | tee -a "$EXPOSED_PANELS" | awk '{print $1}' >> "$RAW_IPS"

    shodan search --fields ip_str,port,org "http.title:\"login\" ssl:$domain" 2>/dev/null \
        | tee -a "$SHODAN_FULL" | tee -a "$EXPOSED_PANELS" | awk '{print $1}' >> "$RAW_IPS"

    shodan search --fields ip_str,port,org "http.title:\"dashboard\" ssl:$domain" 2>/dev/null \
        | tee -a "$SHODAN_FULL" | tee -a "$EXPOSED_PANELS" | awk '{print $1}' >> "$RAW_IPS"

    # Jenkins
    shodan search --fields ip_str,port,org "http.title:\"Dashboard [Jenkins]\" ssl:$domain" 2>/dev/null \
        | tee -a "$SHODAN_FULL" | tee -a "$INTERESTING" | awk '{print $1}' >> "$RAW_IPS"

    # Kibana
    shodan search --fields ip_str,port,org "http.title:\"Kibana\" ssl:$domain" 2>/dev/null \
        | tee -a "$SHODAN_FULL" | tee -a "$INTERESTING" | awk '{print $1}' >> "$RAW_IPS"

    # Grafana
    shodan search --fields ip_str,port,org "http.title:\"Grafana\" ssl:$domain" 2>/dev/null \
        | tee -a "$SHODAN_FULL" | tee -a "$INTERESTING" | awk '{print $1}' >> "$RAW_IPS"

    # Elasticsearch
    shodan search --fields ip_str,port,org "product:\"Elastic\" ssl:$domain" 2>/dev/null \
        | tee -a "$SHODAN_FULL" | tee -a "$INTERESTING" | awk '{print $1}' >> "$RAW_IPS"

    # MongoDB exposed
    shodan search --fields ip_str,port,org "product:\"MongoDB\" ssl:$domain" 2>/dev/null \
        | tee -a "$SHODAN_FULL" | tee -a "$INTERESTING" | awk '{print $1}' >> "$RAW_IPS"

    # Redis exposed
    shodan search --fields ip_str,port,org "product:\"Redis\" ssl:$domain" 2>/dev/null \
        | tee -a "$SHODAN_FULL" | tee -a "$INTERESTING" | awk '{print $1}' >> "$RAW_IPS"

    # Spring Boot actuator
    shodan search --fields ip_str,port,org "http.title:\"Spring\" ssl:$domain" 2>/dev/null \
        | tee -a "$SHODAN_FULL" | tee -a "$INTERESTING" | awk '{print $1}' >> "$RAW_IPS"

    # phpMyAdmin
    shodan search --fields ip_str,port,org "http.title:\"phpMyAdmin\" ssl:$domain" 2>/dev/null \
        | tee -a "$SHODAN_FULL" | tee -a "$INTERESTING" | awk '{print $1}' >> "$RAW_IPS"

    # Jira
    shodan search --fields ip_str,port,org "http.title:\"Jira\" ssl:$domain" 2>/dev/null \
        | tee -a "$SHODAN_FULL" | tee -a "$INTERESTING" | awk '{print $1}' >> "$RAW_IPS"

    # Gitlab
    shodan search --fields ip_str,port,org "http.title:\"GitLab\" ssl:$domain" 2>/dev/null \
        | tee -a "$SHODAN_FULL" | tee -a "$INTERESTING" | awk '{print $1}' >> "$RAW_IPS"

    # Exposed .git
    shodan search --fields ip_str,port,org "http.html:\".git\" ssl:$domain" 2>/dev/null \
        | tee -a "$SHODAN_FULL" | tee -a "$INTERESTING" | awk '{print $1}' >> "$RAW_IPS"

    # RDP exposed
    shodan search --fields ip_str,port,org "port:3389 ssl:$domain" 2>/dev/null \
        | tee -a "$SHODAN_FULL" | tee -a "$INTERESTING" | awk '{print $1}' >> "$RAW_IPS"

    # FTP exposed
    shodan search --fields ip_str,port,org "port:21 ssl:$domain" 2>/dev/null \
        | tee -a "$SHODAN_FULL" | tee -a "$INTERESTING" | awk '{print $1}' >> "$RAW_IPS"

    # Telnet
    shodan search --fields ip_str,port,org "port:23 ssl:$domain" 2>/dev/null \
        | tee -a "$SHODAN_FULL" | tee -a "$INTERESTING" | awk '{print $1}' >> "$RAW_IPS"

    # Swagger UI
    shodan search --fields ip_str,port,org "http.title:\"Swagger UI\" ssl:$domain" 2>/dev/null \
        | tee -a "$SHODAN_FULL" | tee -a "$INTERESTING" | awk '{print $1}' >> "$RAW_IPS"

    echo -e "${GREEN}  [+] Done with $domain${NC}"
    echo ""

done < "$DOMAINS_FILE"

# ============================================================
# STEP 2 — CLEAN & DEDUPLICATE IPs
# ============================================================
echo -e "${CYAN}[*] STEP 2: Deduplicating IPs...${NC}"
grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' "$RAW_IPS" | sort -u > "$CLEAN_IPS"
TOTAL_IPS=$(wc -l < "$CLEAN_IPS")
echo -e "${GREEN}[+] $TOTAL_IPS unique IPs collected${NC}"

# ============================================================
# STEP 3 — PORT SCAN WITH NAABU
# ============================================================
echo -e "\n${CYAN}[*] STEP 3: Port scanning with Naabu...${NC}"
if command -v naabu &>/dev/null; then
    naabu -list "$CLEAN_IPS" \
        -p 21,22,23,25,80,443,445,3306,3389,5432,5900,6379,8080,8443,8888,9200,27017 \
        -silent -o "$NAABU_OUT" 2>/dev/null
    echo -e "${GREEN}[+] Port scan saved to $NAABU_OUT${NC}"
else
    echo -e "${YELLOW}[!] naabu not found — skipping port scan${NC}"
    cp "$CLEAN_IPS" "$NAABU_OUT"
fi

# ============================================================
# STEP 4 — NUCLEI SCAN
# ============================================================
echo -e "\n${CYAN}[*] STEP 4: Running Nuclei on discovered IPs...${NC}"
if command -v nuclei &>/dev/null; then
    nuclei -list "$NAABU_OUT" \
        -t exposures/ \
        -t misconfiguration/ \
        -t takeovers/ \
        -t vulnerabilities/ \
        -t panels/ \
        -severity medium,high,critical \
        -silent \
        -o "$NUCLEI_OUT" 2>/dev/null
    echo -e "${GREEN}[+] Nuclei results saved to $NUCLEI_OUT${NC}"
else
    echo -e "${YELLOW}[!] nuclei not found — skipping${NC}"
fi

# ============================================================
# STEP 5 — GENERATE REPORT
# ============================================================
echo -e "\n${CYAN}[*] STEP 5: Generating report...${NC}"

cat > "$REPORT" << EOF
================================================================
  SHODAN RECON REPORT
  Date    : $(date)
  Targets : $(cat $DOMAINS_FILE | wc -l) domains
================================================================

SUMMARY
-------
Total IPs Found       : $(wc -l < $CLEAN_IPS)
Exposed Panels        : $(wc -l < $EXPOSED_PANELS 2>/dev/null || echo 0)
Interesting Services  : $(wc -l < $INTERESTING 2>/dev/null || echo 0)
Nuclei Findings       : $(wc -l < $NUCLEI_OUT 2>/dev/null || echo 0)

================================================================
INTERESTING SERVICES (HIGH PRIORITY)
================================================================
$(cat $INTERESTING 2>/dev/null || echo "None found")

================================================================
EXPOSED ADMIN PANELS
================================================================
$(cat $EXPOSED_PANELS 2>/dev/null || echo "None found")

================================================================
ALL UNIQUE IPs
================================================================
$(cat $CLEAN_IPS)

================================================================
MANUAL TESTING CHECKLIST
================================================================

For each IP in interesting_findings.txt:

[ ] Jenkins exposed?
    → Try /script endpoint for RCE
    → Check if auth is required
    → URL: http://IP:PORT/script

[ ] Kibana exposed?
    → Access without login?
    → Check for internal data exposure
    → URL: http://IP:PORT/app/kibana

[ ] Elasticsearch exposed?
    → curl http://IP:9200/_cat/indices
    → curl http://IP:9200/_all/_search
    → Any PII/customer data = Critical

[ ] Redis exposed?
    → redis-cli -h IP ping
    → redis-cli -h IP keys *
    → Unauthenticated = High

[ ] MongoDB exposed?
    → mongo --host IP --port 27017
    → show dbs
    → Unauthenticated = Critical

[ ] Grafana exposed?
    → Default creds: admin/admin
    → Check datasources for DB access

[ ] Swagger UI exposed?
    → Document all API endpoints
    → Test each for auth bypass
    → Try IDOR on IDs

[ ] RDP/FTP/Telnet open?
    → Note and report as network exposure
    → Do NOT brute force

[ ] phpMyAdmin exposed?
    → Try default creds
    → Note version for CVEs

[ ] GitLab/Jira exposed?
    → Check for public repos/issues
    → Test user registration

================================================================
DORK REFERENCE (run manually on shodan.io)
================================================================

ssl:"TARGET_DOMAIN"
ssl.cert.subject.cn:"TARGET_DOMAIN"
hostname:"TARGET_DOMAIN"
org:"COMPANY_NAME"
http.title:"admin" ssl:"TARGET_DOMAIN"
http.title:"Jenkins" ssl:"TARGET_DOMAIN"
http.title:"Kibana" ssl:"TARGET_DOMAIN"
http.title:"Grafana" ssl:"TARGET_DOMAIN"
http.title:"Swagger" ssl:"TARGET_DOMAIN"
product:"Elastic" ssl:"TARGET_DOMAIN"
product:"Redis" ssl:"TARGET_DOMAIN"
product:"MongoDB" ssl:"TARGET_DOMAIN"
port:3389 ssl:"TARGET_DOMAIN"
port:6379 ssl:"TARGET_DOMAIN"
port:9200 ssl:"TARGET_DOMAIN"
port:27017 ssl:"TARGET_DOMAIN"

================================================================
EOF

echo -e "${GREEN}[+] Report saved to $REPORT${NC}"

# ============================================================
# SUMMARY
# ============================================================
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━ SCAN COMPLETE ━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  Unique IPs Found      : $(wc -l < $CLEAN_IPS)${NC}"
echo -e "${RED}  Interesting Services  : $(wc -l < $INTERESTING 2>/dev/null || echo 0)${NC}"
echo -e "${RED}  Exposed Panels        : $(wc -l < $EXPOSED_PANELS 2>/dev/null || echo 0)${NC}"
echo -e "${RED}  Nuclei Findings       : $(wc -l < $NUCLEI_OUT 2>/dev/null || echo 0)${NC}"
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━ OUTPUT FILES ━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  All IPs          → $CLEAN_IPS"
echo -e "  Open Ports       → $NAABU_OUT"
echo -e "  Interesting      → $INTERESTING"
echo -e "  Admin Panels     → $EXPOSED_PANELS"
echo -e "  Nuclei Results   → $NUCLEI_OUT"
echo -e "  Full Report      → $REPORT"
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━ NEXT STEPS ━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  1. cat $INTERESTING        → manually visit each service"
echo -e "  2. cat $NUCLEI_OUT         → triage nuclei findings"
echo -e "  3. cat $REPORT             → full checklist inside"
echo -e "  4. Manual dorks on shodan.io using DORK REFERENCE in report"
