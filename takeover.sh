#!/bin/bash
# ============================================================
# takeover.sh - Subdomain Takeover Hunter
# Usage: bash takeover.sh domains.txt
# ============================================================

INPUT_FILE="$1"
if [[ ! -f "$INPUT_FILE" ]]; then
    echo "[!] Usage: $0 domains.txt"
    exit 1
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m'

WORKDIR="takeover_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$WORKDIR"

ALL_DOMAINS="$WORKDIR/all_subdomains.txt"
ALL_DIGS="$WORKDIR/all_digs.txt"
ALL_CNAME="$WORKDIR/all_cnames.txt"
DANGLING="$WORKDIR/dangling_dns.txt"
POTENTIAL_TAKEOVERS="$WORKDIR/potential_takeovers.txt"
MANUAL_CHECKLIST="$WORKDIR/manual_checklist.txt"
NO_RESOLVE="$WORKDIR/no_resolve.txt"

# ============================================================
# STEP 1 — SUBDOMAIN ENUMERATION
# ============================================================
echo -e "${CYAN}[*] STEP 1: Enumerating subdomains...${NC}"

while read domain; do
    echo -e "${BLUE}[+] Enumerating: $domain${NC}"

    # subfinder
    if command -v subfinder &>/dev/null; then
        subfinder -d "$domain" -silent 2>/dev/null
    fi

    # assetfinder
    if command -v assetfinder &>/dev/null; then
        assetfinder --subs-only "$domain" 2>/dev/null
    fi

    # chaos
    if command -v chaos &>/dev/null; then
        chaos -d "$domain" -silent 2>/dev/null
    fi

    # amass passive
    if command -v amass &>/dev/null; then
        amass enum -passive -d "$domain" 2>/dev/null
    fi

    # crt.sh (no tool needed)
    curl -s "https://crt.sh/?q=%25.$domain&output=json" 2>/dev/null \
        | python3 -c "
import sys,json
try:
    data=json.load(sys.stdin)
    [print(n.strip()) for d in data for n in d.get('name_value','').split('\n')]
except:
    pass
" 2>/dev/null

done < "$INPUT_FILE" | \
    sed 's/\*\.//g' | \
    tr '[:upper:]' '[:lower:]' | \
    grep -Ev "^$|^#" | \
    sort -u | tee "$ALL_DOMAINS"

TOTAL=$(wc -l < "$ALL_DOMAINS")
echo -e "${GREEN}[+] Found $TOTAL unique subdomains${NC}"

# ============================================================
# STEP 2 — DNS RESOLUTION CHECK
# ============================================================
echo -e "\n${CYAN}[*] STEP 2: Checking DNS resolution...${NC}"

> "$NO_RESOLVE"
> "$ALL_DIGS"

cat "$ALL_DOMAINS" | while read sub; do
    result=$(dig "$sub" +noall +answer +time=3 +tries=1 2>/dev/null)
    if [[ -z "$result" ]]; then
        echo "$sub" >> "$NO_RESOLVE"
    else
        echo "$result" >> "$ALL_DIGS"
    fi
done

NO_RESOLVE_COUNT=$(wc -l < "$NO_RESOLVE")
echo -e "${YELLOW}[!] $NO_RESOLVE_COUNT subdomains have NO DNS resolution (dangling candidates)${NC}"

# ============================================================
# STEP 3 — CNAME EXTRACTION
# ============================================================
echo -e "\n${CYAN}[*] STEP 3: Extracting CNAME records...${NC}"

grep -i "CNAME" "$ALL_DIGS" | tee "$ALL_CNAME"
CNAME_COUNT=$(wc -l < "$ALL_CNAME")
echo -e "${GREEN}[+] Found $CNAME_COUNT CNAME records${NC}"

# ============================================================
# STEP 4 — FINGERPRINT VULNERABLE SERVICES
# ============================================================
echo -e "\n${CYAN}[*] STEP 4: Fingerprinting vulnerable 3rd-party services...${NC}"

> "$POTENTIAL_TAKEOVERS"

# Known vulnerable CNAME patterns
declare -A SERVICES
SERVICES["github.io"]="GitHub Pages"
SERVICES["githubusercontent.com"]="GitHub Pages"
SERVICES["heroku.com"]="Heroku"
SERVICES["herokudns.com"]="Heroku"
SERVICES["amazonaws.com"]="AWS S3"
SERVICES["s3.amazonaws.com"]="AWS S3"
SERVICES["cloudfront.net"]="AWS CloudFront"
SERVICES["azurewebsites.net"]="Azure"
SERVICES["azure-api.net"]="Azure API"
SERVICES["cloudapp.net"]="Azure"
SERVICES["azureedge.net"]="Azure CDN"
SERVICES["trafficmanager.net"]="Azure Traffic Manager"
SERVICES["wordpress.com"]="WordPress"
SERVICES["ghost.io"]="Ghost"
SERVICES["tumblr.com"]="Tumblr"
SERVICES["shopify.com"]="Shopify"
SERVICES["myshopify.com"]="Shopify"
SERVICES["squarespace.com"]="Squarespace"
SERVICES["squarespace-cdn.com"]="Squarespace"
SERVICES["fastly.net"]="Fastly"
SERVICES["pantheonsite.io"]="Pantheon"
SERVICES["getgrav.org"]="Grav CMS"
SERVICES["zendesk.com"]="Zendesk"
SERVICES["desk.com"]="Desk/Salesforce"
SERVICES["helpscoutdocs.com"]="HelpScout"
SERVICES["readme.io"]="ReadMe"
SERVICES["cargo.site"]="Cargo"
SERVICES["webflow.io"]="Webflow"
SERVICES["netlify.app"]="Netlify"
SERVICES["netlify.com"]="Netlify"
SERVICES["vercel.app"]="Vercel"
SERVICES["surge.sh"]="Surge.sh"
SERVICES["fly.dev"]="Fly.io"
SERVICES["render.com"]="Render"
SERVICES["strikingly.com"]="Strikingly"
SERVICES["bitbucket.io"]="Bitbucket"
SERVICES["gitbook.io"]="GitBook"
SERVICES["hubspot.com"]="HubSpot"
SERVICES["hs-sites.com"]="HubSpot"
SERVICES["hs-analytics.net"]="HubSpot"
SERVICES["mailgun.org"]="Mailgun"
SERVICES["sendgrid.net"]="SendGrid"
SERVICES["freshdesk.com"]="Freshdesk"
SERVICES["freshservice.com"]="Freshservice"
SERVICES["intercom.io"]="Intercom"
SERVICES["custom.intercom.help"]="Intercom"
SERVICES["statuspage.io"]="Statuspage"
SERVICES["uservoice.com"]="UserVoice"
SERVICES["helpjuice.com"]="HelpJuice"
SERVICES["tilda.cc"]="Tilda"
SERVICES["wix.com"]="Wix"
SERVICES["wixdns.net"]="Wix"

cat "$ALL_CNAME" | while read line; do
    subdomain=$(echo "$line" | awk '{print $1}')
    cname=$(echo "$line" | awk '{print $NF}' | sed 's/\.$//')

    for pattern in "${!SERVICES[@]}"; do
        if echo "$cname" | grep -qi "$pattern"; then
            service="${SERVICES[$pattern]}"

            # Check if CNAME target resolves
            target_resolves=$(dig "$cname" +short +time=3 +tries=1 2>/dev/null)

            if [[ -z "$target_resolves" ]]; then
                STATUS="${RED}[DANGLING - HIGH RISK]${NC}"
                RISK="HIGH"
            else
                STATUS="${YELLOW}[RESOLVES - VERIFY MANUALLY]${NC}"
                RISK="MEDIUM"
            fi

            echo -e "$STATUS $subdomain → $cname ($service)" | tee -a "$POTENTIAL_TAKEOVERS"
            break
        fi
    done
done

# ============================================================
# STEP 5 — HTTP FINGERPRINT (check for error pages)
# ============================================================
echo -e "\n${CYAN}[*] STEP 5: HTTP fingerprinting for takeover signatures...${NC}"

# Known error messages indicating unclaimed service
declare -A ERROR_SIGNATURES
ERROR_SIGNATURES["There isn't a GitHub Pages site here"]="GitHub Pages"
ERROR_SIGNATURES["No such app"]="Heroku"
ERROR_SIGNATURES["NoSuchBucket"]="AWS S3"
ERROR_SIGNATURES["The specified bucket does not exist"]="AWS S3"
ERROR_SIGNATURES["The request could not be satisfied"]="AWS CloudFront"
ERROR_SIGNATURES["404 Not Found"]="Generic 404"
ERROR_SIGNATURES["Do you want to register"]="Fastly"
ERROR_SIGNATURES["This domain is not configured"]="Webflow/Netlify"
ERROR_SIGNATURES["Project not found"]="Vercel"
ERROR_SIGNATURES["Repository not found"]="Bitbucket"
ERROR_SIGNATURES["Help Center Closed"]="Zendesk"
ERROR_SIGNATURES["is not a registered InCloud YouTrack"]="JetBrains"
ERROR_SIGNATURES["Unrecognized domain"]="Shopify"

cat "$POTENTIAL_TAKEOVERS" | grep -oP 'https?://\S+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | \
sort -u | while read sub; do
    # Try HTTP and HTTPS
    for scheme in https http; do
        response=$(curl -sk --max-time 8 --connect-timeout 5 \
            -A "Mozilla/5.0" \
            -w "\n%{http_code}" \
            "$scheme://$sub" 2>/dev/null | tail -2)

        body=$(echo "$response" | head -1)
        status=$(echo "$response" | tail -1)

        for sig in "${!ERROR_SIGNATURES[@]}"; do
            if echo "$body" | grep -qi "$sig"; then
                service="${ERROR_SIGNATURES[$sig]}"
                echo -e "${RED}[CONFIRMED TAKEOVER CANDIDATE]${NC} $scheme://$sub"
                echo -e "  Service  : $service"
                echo -e "  Signature: $sig"
                echo -e "  HTTP Code: $status"
                echo ""
                echo "CONFIRMED: $scheme://$sub | $service | $sig | HTTP $status" >> "$DANGLING"
                break 2
            fi
        done
    done
done

# ============================================================
# STEP 6 — MANUAL CHECKLIST
# ============================================================
echo -e "\n${CYAN}[*] STEP 6: Generating manual checklist...${NC}"

cat > "$MANUAL_CHECKLIST" << 'EOF'
================================================================
  MANUAL SUBDOMAIN TAKEOVER CHECKLIST
================================================================

FOR EACH SUBDOMAIN IN potential_takeovers.txt:

[ ] STEP 1 - CONFIRM CNAME IS DANGLING
    Command: dig <subdomain> CNAME +short
    ✓ If CNAME points to unclaimed 3rd party = vulnerable
    ✗ If CNAME resolves to valid IP = likely not vulnerable

[ ] STEP 2 - VISIT THE SUBDOMAIN IN BROWSER
    Look for these error pages:

    GitHub Pages  → "There isn't a GitHub Pages site here"
                    Fix: Register username.github.io matching the CNAME
    
    Heroku        → "No such app"
                    Fix: Create a Heroku app with the same name
    
    AWS S3        → "NoSuchBucket" or "The bucket does not exist"
                    Fix: Create S3 bucket with exact same name as CNAME
    
    Netlify       → "Not found - No sites with that name"
                    Fix: Register the site name on Netlify
    
    Shopify       → "Sorry, this shop is currently unavailable"
                    Fix: Register store name on Shopify
    
    Azure         → "404 Web Site not found"
                    Fix: Create Azure Web App with the same name
    
    Fastly        → "Fastly error: unknown domain"
                    Fix: Add domain in Fastly service
    
    Zendesk       → "Help Center Closed"
                    Fix: Register subdomain in Zendesk

[ ] STEP 3 - VERIFY YOU CAN CLAIM IT
    - GitHub Pages : Can you create a repo / org matching the CNAME?
    - Heroku       : Can you create an app with that name?
    - S3           : Can you create that bucket name in any region?
    - Netlify      : Can you add that custom domain?

[ ] STEP 4 - PROOF OF CONCEPT (DO NOT EXPLOIT)
    - Create a simple HTML page: <h1>Subdomain Takeover PoC - [YourName]</h1>
    - Claim the service (GitHub repo, Heroku app etc.)
    - Screenshot showing YOUR content loading on THEIR subdomain
    - DO NOT store any real data or intercept traffic

[ ] STEP 5 - REPORT ON HACKERONE
    Title   : Subdomain Takeover on <subdomain> via <service>
    Severity: Usually Medium–High (Critical if sensitive subdomain)
    Include :
      - The vulnerable subdomain
      - The dangling CNAME value
      - Screenshot of error page
      - Screenshot of your PoC HTML loading
      - Steps to reproduce

================================================================
  QUICK COMMANDS REFERENCE
================================================================

# Check CNAME
dig <subdomain> CNAME +short

# Check if target resolves
dig <cname-target> +short

# Check HTTP response
curl -sk https://<subdomain> | grep -i "not found\|no such\|error"

# Check with httpx
echo "<subdomain>" | httpx -silent -status-code -title

# Verify with nuclei
nuclei -u <subdomain> -t takeovers/

================================================================
EOF

echo -e "${GREEN}[+] Manual checklist saved to $MANUAL_CHECKLIST${NC}"

# ============================================================
# SUMMARY
# ============================================================
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━ SCAN SUMMARY ━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}[*] Total Subdomains Found   : $(wc -l < $ALL_DOMAINS)${NC}"
echo -e "${CYAN}[*] No DNS Resolution        : $(wc -l < $NO_RESOLVE)${NC}"
echo -e "${CYAN}[*] CNAME Records Found      : $(wc -l < $ALL_CNAME)${NC}"
echo -e "${CYAN}[*] Potential Takeovers      : $(wc -l < $POTENTIAL_TAKEOVERS)${NC}"
CONFIRMED=$(wc -l < "$DANGLING" 2>/dev/null || echo 0)
echo -e "${RED}[!] Confirmed Candidates     : $CONFIRMED${NC}"
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━ OUTPUT FILES ━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  All Subdomains   → $ALL_DOMAINS"
echo -e "  No DNS Resolve   → $NO_RESOLVE"
echo -e "  CNAME Records    → $ALL_CNAME"
echo -e "  Takeover Leads   → $POTENTIAL_TAKEOVERS"
echo -e "  Confirmed        → $DANGLING"
echo -e "  Manual Checklist → $MANUAL_CHECKLIST"
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━ NEXT STEPS ━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  1. cat $POTENTIAL_TAKEOVERS"
echo -e "  2. For each DANGLING entry → visit in browser"
echo -e "  3. Follow steps in $MANUAL_CHECKLIST"
echo -e "  4. Run: nuclei -l $ALL_DOMAINS -t takeovers/"
