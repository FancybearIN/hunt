#!/bin/bash

INPUT="$1"
BASE="recon"
EVIL="https://evil.com"

if [ -z "$INPUT" ]; then
  echo "Usage: $0 domains_only.txt"
  exit 1
fi

mkdir -p $BASE/{paramspider,cleaned,redirects,dalfox,reuse,logs}

echo "[+] Running ParamSpider on domains"

paramspider -l "$INPUT" \
  | grep -E '^https?://' \
  > $BASE/paramspider/raw_params.txt 2>> $BASE/logs/paramspider.log

echo "[+] Normalizing params"
sed 's/=.*/=FUZZ/' $BASE/paramspider/raw_params.txt \
| sort -u \
> $BASE/cleaned/all_params_fuzz.txt

echo "[+] Cleaning noise"
grep -Ev 'utm_|fbclid|gclid|ga=' \
$BASE/cleaned/all_params_fuzz.txt \
> $BASE/cleaned/params_clean.txt

echo "[+] Extracting redirect params"
grep -Ei 'redirect|return|next|url=|callback|continue|dest' \
$BASE/cleaned/params_clean.txt \
> $BASE/redirects/redirect_params.txt

if command -v qsreplace >/dev/null; then
  echo "[+] Testing open redirects"
  cat $BASE/redirects/redirect_params.txt \
  | qsreplace "$EVIL" \
  | httpx -silent -location \
  > $BASE/redirects/redirect_tested.txt
fi

if command -v dalfox >/dev/null; then
  echo "[+] Running Dalfox"
  dalfox file $BASE/cleaned/params_clean.txt \
    --only-poc r \
    --skip-bav \
    --mass \
    --silence \
    --output $BASE/dalfox/xss_results.txt
fi

echo "[+] Detecting reused params"
cut -d'=' -f1 $BASE/cleaned/params_clean.txt \
| sort | uniq -d \
> $BASE/reuse/reused_params.txt

while read p; do
  grep "$p=" $BASE/cleaned/params_clean.txt
done < $BASE/reuse/reused_params.txt \
> $BASE/reuse/reused_param_urls.txt

echo "[✓] Done"
