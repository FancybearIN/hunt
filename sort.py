import sys
from urllib.parse import urlparse, parse_qsl

if len(sys.argv) != 2:
    print("Usage: python sort.py urls.txt")
    sys.exit(1)

input_file = sys.argv[1]
endpoint_params = {}

with open(input_file, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue

        if not line.startswith(("http://", "https://")):
            line = "http://" + line

        p = urlparse(line)

        scheme = p.scheme or "http"
        netloc = p.netloc
        path = p.path or "/"

        endpoint = f"{scheme}://{netloc}{path}"

        params = [k for k, _ in parse_qsl(p.query)]

        if endpoint not in endpoint_params:
            endpoint_params[endpoint] = set()

        for param in params:
            endpoint_params[endpoint].add(param)

results = set()

for endpoint, params in endpoint_params.items():
    if not params:
        continue

    # single param
    for p in params:
        results.add(f"{endpoint}?{p}=")

    # combined params
    combo = "&".join(f"{p}=" for p in sorted(params))
    results.add(f"{endpoint}?{combo}")

for r in sorted(results):
    print(r)
