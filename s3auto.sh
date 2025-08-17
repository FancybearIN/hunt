#!/bin/bash

# Usage: ./s3_recon.sh target.com

set -e
TARGET=$1

if [ -z "$TARGET" ]; then
  echo "[!] Usage: $0 <target-domain>"
  exit 1
fi

echo "[*] Creating workspace..."
mkdir -p s3_recon/{results,tools}

cd s3_recon/tools

# Clone or skip tools if already present
echo "[*] Checking and cloning tools if not already cloned..."

[ ! -d "dorks-eye" ] && git clone https://github.com/BullsEye0/dorks-eye.git
[ ! -d "S3BucketMisconf" ] && git clone https://github.com/Atharv834/S3BucketMisconf.git
[ ! -d "java2s3" ] && git clone https://github.com/mexploit30/java2s3.git
[ ! -d "lazys3" ] && git clone https://github.com/nahamsec/lazys3.git
[ ! -d "S3Scanner" ] && git clone https://github.com/sa7mon/S3Scanner.git || true

# Install requirements only once
if [ ! -f "requirements_installed.flag" ]; then
  echo "[*] Installing Python dependencies..."
  pip install -r dorks-eye/requirements.txt || true
  pip install -r java2s3/requirements.txt || true
  touch requirements_installed.flag
fi

cd ../..

echo "[*] Running Subfinder to get subdomains..."
subfinder -d $TARGET -all -silent > s3_recon/results/subs.txt

echo "[*] Running HTTPX on subdomains..."
httpx -l s3_recon/results/subs.txt -sc -title -td -silent | tee s3_recon/results/httpx.txt

echo "[*] Searching for S3 buckets via HTTPX result (Amazon S3)..."
grep "Amazon S3" s3_recon/results/httpx.txt | tee s3_recon/results/s3_by_httpx.txt

echo "[*] Running Nuclei with S3 detection template..."
nuclei -l s3_recon/results/subs.txt -t ~/.local/nuclei-templates/http/technologies/s3-detect.yaml -silent -o s3_recon/results/s3_nuclei.txt

echo "[*] Running DorkEye for Google Dorks..."
cd s3_recon/tools/dorks-eye
python3 dorks-eye.py -s "site:s3.amazonaws.com $TARGET" -o ../../results/dorkeye.txt
cd ../..

echo "[*] Running Katana to find JavaScript files..."
katana -u https://$TARGET -d 5 -jc | grep '\.js$' | tee s3_recon/results/alljs.txt

echo "[*] Extracting S3 URLs from JS files..."
cat s3_recon/results/alljs.txt | xargs -I {} curl -s {} | grep -oE 'http[s]?://[^"]*\.s3\.amazonaws\.com[^" ]*' | sort -u > s3_recon/results/s3_from_js.txt

echo "[*] Running java2s3 to extract S3 from JS of subdomains..."
cat s3_recon/results/subs.txt | httpx -silent -o s3_recon/tools/java2s3/input.txt
cd s3_recon/tools/java2s3
python3 java2s3.py input.txt $TARGET output.txt
cd ../..
cp s3_recon/tools/java2s3/output.txt s3_recon/results/s3_java2s3.txt

echo "[*] Running LazyS3 (brute-force)..."
cd s3_recon/tools/lazys3
ruby lazys3.rb $TARGET > ../../results/lazys3.txt || true
cd ../..

echo "[*] Generating wordlist using Cewl..."
cewl https://$TARGET -d 3 -w s3_recon/results/cewl.txt

echo "[*] Scanning buckets using S3Scanner..."
cd s3_recon/tools/S3Scanner
python3 s3scanner.py -b ../../results/cewl.txt -e -t 10 > ../../results/s3scanner.txt
cd ../..

echo "[*] Running S3Misconfig with all found S3 URLs..."
cat s3_recon/results/*.txt | grep -oP 'https?://[a-zA-Z0-9.-]*s3(\.dualstack)?\.ap-[a-z0-9-]+\.amazonaws\.com/[^\s"<>]+' | sort -u > s3_recon/results/all_s3_urls.txt

cd s3_recon/tools/S3BucketMisconf
python3 s3misconfig.py -f ../../results/all_s3_urls.txt -o ../../results/s3misconfig_output.html
cd ../..

echo "[*] 🎉 All done! Results saved in s3_recon/results/"
