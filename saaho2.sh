#!/bin/bash

# ==========================================================
# Shodan Scope Hunter + Built-in Nuclei
# Scoped | Student-safe | High ROI
# ==========================================================

DOMAINS_FILE="$1"

if [[ -z "$DOMAINS_FILE" ]]; then
  echo "Usage: $0 domains.txt"
  exit 1
fi

RAW="shodan_raw.txt"
TARGETS="targets_ip_port.txt"
LIVE="live_http.txt"
NUCLEI_OUT="nuclei_findings.txt"

> "$RAW"
> "$TARGETS"
> "$LIVE"
> "$NUCLEI_OUT"

# ----------------------------
# Dependency checks
# ----------------------------
for bin in shodan httpx nuclei; do
  if ! command -v $bin &>/dev/null; then
    echo "[!] Missing dependency: $bin"
    exit 1
  fi
done

# ----------------------------
# Shodan auth check
# ----------------------------
if ! shodan info &>/dev/null; then
  echo "[!] Shodan not authenticated"
  echo "Run: shodan init YOUR_API_KEY"
  exit 1
fi

# -------------------------------
# QUERY CATEGORIES
# -------------------------------

AUTH_ADMIN=(
  'http.title:"Admin Login"'
  'http.title:"Administrator Login"'
  'http.title:"Admin Panel"'
  'http.title:"Control Panel"'
  'http.title:"Dashboard" "Admin"'
  'http.title:"Login" "Admin"'
  'http.html:"admin/login"'
  'http.html:"/admin"'
  'http.html:"/backend"'
  'http.html:"/manage"'
)

CLOUD=(
  'product:"Amazon EC2"'
  'product:"Google Compute Engine"'
  'product:"Microsoft Azure"'
  'ssl:"cloudflare"'
  'http.html:"AWS_ACCESS_KEY_ID"'
  'http.html:"AZURE_STORAGE"'
  'http.html:"googleapis.com"'
)

DEVOPS=(
  'product:"Docker"'
  'port:2375'
  'port:2376'
  'http.title:"Docker Registry"'
  'product:"Kubernetes"'
  'port:10250'
  'port:6443'
  'http.title:"Kubernetes Dashboard"'
  'http.title:"Traefik"'
  'http.title:"Portainer"'
)

DATABASES=(
  'product:"MongoDB"'
  'port:27017'
  'product:"MySQL"'
  'product:"PostgreSQL"'
  'product:"Redis"'
  'port:6379'
  'product:"Elasticsearch"'
  'port:9200'
  'http.title:"phpMyAdmin"'
  'http.title:"Adminer"'
)

DEBUG_BACKUP=(
  'http.title:"Index of /"'
  'http.html:".env"'
  'http.html:"config.php"'
  'http.html:"wp-config.php"'
  'http.html:"backup"'
  'http.html:".git"'
  'http.html:"debug=true"'
  'http.html:"stack trace"'
  'http.html:"Exception"'
  'http.html:"Fatal error"'
)

IDENTITY=(
  'product:"Keycloak"'
  'http.title:"Keycloak"'
  'product:"Auth0"'
  'http.title:"SSO Login"'
  'http.title:"Single Sign-On"'
  'http.html:"SAMLRequest"'
  'http.html:"oauth"'
  'http.html:"openid"'
  'http.html:"jwt"'
  'http.html:"token="'
)

API_GRAPHQL=(
  'http.title:"Swagger UI"'
  'http.title:"API Docs"'
  'http.html:"swagger"'
  'http.html:"openapi"'
  'http.html:"/v1/"'
  'http.html:"/v2/"'
  'http.html:"/api/"'
  'http.html:"GraphQL"'
  'http.title:"GraphiQL"'
  'http.html:"query {"'
)

CMS_FRAMEWORKS=(
  'product:"WordPress"'
  'http.html:"wp-content"'
  'http.title:"Joomla"'
  'http.title:"Drupal"'
  'product:"Laravel"'
  'http.html:"APP_KEY="'
  'http.html:"laravel.log"'
  'product:"Django"'
  'http.html:"DEBUG = True"'
  'http.html:"SECRET_KEY"'
)

CICD=(
  'product:"Jenkins"'
  'http.title:"Jenkins"'
  'product:"GitLab"'
  'http.title:"GitLab"'
  'product:"Gitea"'
  'product:"TeamCity"'
  'product:"CircleCI"'
  'http.html:"pipeline"'
  'http.html:"runner"'
)

MONITORING=(
  'product:"Grafana"'
  'http.title:"Grafana"'
  'product:"Prometheus"'
  'http.title:"Prometheus"'
  'product:"Kibana"'
  'http.title:"Kibana"'
  'product:"Zabbix"'
  'product:"Nagios"'
  'http.title:"Monitoring"'
  'http.title:"Metrics"'
)

ALL_GROUPS=(
  AUTH_ADMIN[@]
  CLOUD[@]
  DEVOPS[@]
  DATABASES[@]
  DEBUG_BACKUP[@]
  IDENTITY[@]
  API_GRAPHQL[@]
  CMS_FRAMEWORKS[@]
  CICD[@]
  MONITORING[@]
)

# ----------------------------
# SHODAN RECON (SCOPED)
# ----------------------------

echo "[*] Starting Shodan scoped recon..."

while read -r domain; do
  [[ -z "$domain" ]] && continue
  echo "[*] Scope: $domain"

  for group in "${ALL_GROUPS[@]}"; do
    query="${!group}"
    echo "    [+] $query"

    shodan search \
      --limit 100 \
      --fields ip_str,port,product \
      "ssl:$domain $query" >> "$RAW" 2>/dev/null
  done

done < "$DOMAINS_FILE"

# ----------------------------
# NORMALIZE TARGETS
# ----------------------------

echo "[*] Normalizing IP:PORT..."
awk '{print $1 ":" $2}' "$RAW" | sort -u > "$TARGETS"

# ----------------------------
# HTTP PROBING
# ----------------------------

echo "[*] Probing live HTTP services..."
httpx -l "$TARGETS" \
  -silent \
  -title \
  -status-code \
  -tech-detect \
  -o "$LIVE"

# ----------------------------
# NUCLEI (BUILT-IN)
# ----------------------------

echo "[*] Running nuclei (high-signal templates)..."

nuclei -l "$LIVE" \
  -severity high,critical \
  -t exposures/ \
  -t misconfiguration/ \
  -t default-logins/ \
  -t cves/ \
  -o "$NUCLEI_OUT"

# ----------------------------
# DONE
# ----------------------------

echo
echo "[+] COMPLETE"
echo "    Shodan raw     : $RAW"
echo "    Targets        : $TARGETS"
echo "    Live HTTP      : $LIVE"
echo "    Nuclei output  : $NUCLEI_OUT"
