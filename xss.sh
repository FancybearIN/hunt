#!/bin/bash

# Check for input
if [ -z "$1" ]; then
  echo "Usage: $0 domains.txt"
  exit 1
fi

domains="$1"

# Step 1: Find subdomains for all domains
echo "[*] Running subfinder..."
subfinder -dL "$domains" -silent | gau | gf xss | uro | Gxss | kxss | tee gxss_output.txt
# Step 5: Final output cleanup
cat gxss_output.txt | grep -oP '^URL: \K\S+' | sed 's/=.*/=/' | sort -u > final.txt

echo "[+] Done. Outputs:"

