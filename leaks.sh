#!/bin/bash
# ============================================================
# leaks.sh - Enhanced Secret & Sensitive Data Hunter
# Usage: bash leaks.sh <input_file>
# Default input: way.txt
# ============================================================

INPUT="${1:-way.txt}"
OUT="leaks"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

if [[ ! -f "$INPUT" ]]; then
  echo -e "${RED}[!] Input file '$INPUT' not found!${NC}"
  exit 1
fi

mkdir -p "$OUT"
echo -e "${CYAN}[*] Reading from: $INPUT${NC}"
echo -e "${CYAN}[*] Output dir : $OUT/${NC}"
echo ""

run_grep() {
  local label="$1"
  local file="$2"
  local pattern="$3"
  grep -Eio "$pattern" "$INPUT" | sort -u > "$OUT/$file"
  local count
  count=$(wc -l < "$OUT/$file")
  if [[ $count -gt 0 ]]; then
    echo -e "${RED}[FOUND]${NC} ${label}: ${RED}$count${NC} hits → $OUT/$file"
  else
    echo -e "${GREEN}[CLEAN]${NC} ${label}: 0 hits"
  fi
}

echo -e "${YELLOW}━━━━━━━━━━━━━━━━ API KEYS & TOKENS ━━━━━━━━━━━━━━━━${NC}"
run_grep "Generic API Key"         "api_keys.txt"        "(api[_-]?key|apikey|api[_-]?secret|client[_-]?secret|app[_-]?key|service[_-]?key)[=:\"' ]+([A-Za-z0-9_\-]{16,64})"
run_grep "Access Tokens"           "access_tokens.txt"   "(access[_-]?token|auth[_-]?token|oauth[_-]?token|bearer[_-]?token)[=:\"' ]+([A-Za-z0-9_\-]{16,128})"
run_grep "Generic Secrets"         "secrets.txt"         "(secret[_-]?key|private[_-]?key|encryption[_-]?key|signing[_-]?key)[=:\"' ]+([A-Za-z0-9_+/=]{16,})"
run_grep "Passwords in URLs"       "passwords.txt"       "(password|passwd|pwd)[=:\"' ]+([^&\"' ]{6,})"

echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━ CLOUD PROVIDERS ━━━━━━━━━━━━━━━━━━${NC}"
run_grep "AWS Access Key"          "aws_access.txt"      "AKIA[0-9A-Z]{16}"
run_grep "AWS Secret Key"          "aws_secret.txt"      "(aws[_-]?secret[_-]?access[_-]?key|aws_secret)[=:\"' ]+([A-Za-z0-9/+=]{40})"
run_grep "AWS ARN"                 "aws_arn.txt"         "arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:[0-9]{12}:[^\s\"]+"
run_grep "Google API Key"          "google_api.txt"      "AIza[0-9A-Za-z\-_]{35}"
run_grep "Google OAuth"            "google_oauth.txt"    "[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"
run_grep "Firebase URL"            "firebase.txt"        "https://[a-z0-9\-]+\.firebaseio\.com"
run_grep "Azure Storage"           "azure.txt"           "DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+"

echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━ TOKENS & AUTH ━━━━━━━━━━━━━━━━━━━━${NC}"
run_grep "JWT Tokens"              "jwt.txt"             "eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
run_grep "Basic Auth in URL"       "basic_auth.txt"      "https?://[^:\" ]+:[^@\" ]+@[a-zA-Z0-9.\-]+"
run_grep "Bearer Token"            "bearer.txt"          "bearer[=:\"' ]+[A-Za-z0-9_\-\.]{20,}"
run_grep "Authorization Header"    "auth_header.txt"     "authorization[=:\"' ]+[A-Za-z0-9_\-\. ]{10,}"
run_grep "Session Tokens"          "session.txt"         "(session[_-]?id|sess[_-]?token|PHPSESSID|JSESSIONID)[=:\"' ]+[A-Za-z0-9_\-]{16,}"

echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━ SENSITIVE FILES ━━━━━━━━━━━━━━━━━━${NC}"
run_grep "Config & Env Files"      "config_files.txt"    "\.(env|env\.local|env\.prod|config|cfg|conf|ini|properties|settings)[\"'&? ]"
run_grep "Backup Files"            "backup_files.txt"    "\.(bak|backup|old|orig|copy|tmp|swp|save)[\"'&? ]"
run_grep "Database Files"          "db_files.txt"        "\.(sql|db|sqlite|sqlite3|dump|mdb)[\"'&? ]"
run_grep "Log Files"               "log_files.txt"       "\.(log|logs|error_log|access_log)[\"'&? ]"
run_grep "Archive Files"           "archive_files.txt"   "\.(zip|tar|tar\.gz|tgz|rar|7z|gz)[\"'&? ]"
run_grep "Source Code"             "source_files.txt"    "\.(php\.bak|asp\.bak|aspx\.old|jsp\.bak|git|svn)[\"'&? ]"
run_grep "JSON & XML Data"         "data_files.txt"      "\.(json|xml|yaml|yml|toml)[\"'&? ]"

echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━ ENDPOINTS ━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
run_grep "Admin Panels"            "admin.txt"           "/(admin|administrator|wp-admin|cpanel|dashboard|manager|control)[/\"'?& ]"
run_grep "API Endpoints"           "api_endpoints.txt"   "/(api|v1|v2|v3|rest|graphql|gql|soap|rpc)[/\"'?& ]"
run_grep "Debug & Test Pages"      "debug.txt"           "/(debug|test|dev|staging|beta|internal|phpinfo|server-status|actuator)[/\"'?& ]"
run_grep "Login & Auth Pages"      "auth_pages.txt"      "/(login|signin|signup|register|auth|oauth|sso|logout)[/\"'?& ]"
run_grep "Upload Endpoints"        "upload.txt"          "/(upload|uploads|file|files|media|attachment|import)[/\"'?& ]"
run_grep "Redirect Parameters"     "redirects.txt"       "[?&](url|redirect|redirect_uri|callback|return|next|goto|dest|target|forward)="

echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━ PII & SENSITIVE DATA ━━━━━━━━━━━━━━${NC}"
run_grep "Email Addresses"         "emails.txt"          "[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
run_grep "Phone Numbers"           "phones.txt"          "(\+?[0-9]{1,3}[\s\-]?)?(\([0-9]{2,4}\)|[0-9]{2,4})[\s\-]?[0-9]{3,4}[\s\-]?[0-9]{3,6}"
run_grep "Private IP Addresses"    "internal_ips.txt"    "(192\.168\.[0-9]{1,3}\.[0-9]{1,3}|10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3})"
run_grep "Credit Card Numbers"     "cc_numbers.txt"      "\b4[0-9]{12}(?:[0-9]{3})?\b|\b5[1-5][0-9]{14}\b|\b3[47][0-9]{13}\b"

echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━ 3RD PARTY SERVICES ━━━━━━━━━━━━━━━━${NC}"
run_grep "Slack Tokens"            "slack.txt"           "xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}"
run_grep "GitHub Tokens"           "github.txt"          "gh[pousr]_[A-Za-z0-9]{36}"
run_grep "Stripe Keys"             "stripe.txt"          "(sk|pk)_(live|test)_[A-Za-z0-9]{24,}"
run_grep "Twilio Keys"             "twilio.txt"          "AC[a-z0-9]{32}"
run_grep "SendGrid Keys"           "sendgrid.txt"        "SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"
run_grep "Mailchimp Keys"          "mailchimp.txt"       "[0-9a-f]{32}-us[0-9]{1,2}"
run_grep "NPM Tokens"              "npm.txt"             "npm_[A-Za-z0-9]{36}"

echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━ SUMMARY ━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
TOTAL=$(cat "$OUT"/*.txt 2>/dev/null | wc -l)
echo -e "${CYAN}[*] Total unique findings: ${RED}$TOTAL${NC}"
echo -e "${CYAN}[*] All results saved in: ${GREEN}./$OUT/${NC}"
echo ""
echo -e "${YELLOW}[!] NEXT STEPS:${NC}"
echo -e "    1. cat $OUT/jwt.txt       → Decode at jwt.io, check expiry & claims"
echo -e "    2. cat $OUT/aws_access.txt → Test with: aws sts get-caller-identity"
echo -e "    3. cat $OUT/api_keys.txt  → Google each key format to identify service"
echo -e "    4. cat $OUT/redirects.txt → Test for open redirect vulnerabilities"
echo -e "    5. cat $OUT/api_endpoints.txt → Manually probe each in Burp Suite"
