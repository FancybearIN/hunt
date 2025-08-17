I built you Crlfat.sh — a single-file Bash tool to automate CRLF hunting at scale, including GBK unicode bypass payloads, response-splitting probes, header/body injection checks, multi-domain scanning, concurrency, and optional nuclei integration. It follows the methods in the article you shared and adds practical extras (tokenized indicators, CSV/NDJSON reporting, raw-response capture, discovery via httpx).

Quick start

download the script from the canvas and make it executable:

chmod +x Crlfat.sh


single target:

./Crlfat.sh -u https://target.com


multi-domain (file or stdin) with discovery and concurrency:

subfinder -d example.com -all | httpx -silent | ./Crlfat.sh -l - --discover --concurrency 20


path vs query testing:

./Crlfat.sh -u https://target.com -m path
./Crlfat.sh -u https://target.com -m query


add headers / proxy / follow redirects:

./Crlfat.sh -u https://target.com -H "X-Trace: test" --proxy http://127.0.0.1:8080 --follow


also run your nuclei template:

./Crlfat.sh -u https://target.com --nuclei cRlf.yaml

Output

crlfat_out/findings.csv and findings.ndjson with: time, url, mode, payload, status, indicator(s), notes.

crlfat_out/raw/ keeps each raw curl -i response for PoC screenshots and manual review.

Payload coverage (highlights)

Classic header injection: Set-Cookie, X-Injection-Test

Redirects: Location: https://evil.<token>.test

Body/XSS: <script>alert('CRLF-<token>')</script>, <svg onload=...>

Response splitting with forged second response

Unicode/encoding variants: %0a, %5Cr%5Cn, anchor # splits, traversal+CRLF

GBK bypass sequences (嘍/嘊, 嘼/嘾) chained into JS injection

Notes

Dependencies: bash, curl, awk/sed/grep; optional: httpx, jq, xargs.

Be gentle with --concurrency and --rate. Only test assets you’re authorized to assess.

Want me to wire in GAU/Katana collection as a built-in pre-step or add a Burp-friendly report exporter (HTML with collapsible raw responses)?
