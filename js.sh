#!/bin/bash

BASE_URL="$1"
TMP_DIR="js_crawl_tmp"
VISITED_FILE="$TMP_DIR/visited.txt"
FOUND_JS="$TMP_DIR/found.txt"
OUTPUT_FILE="unique_js_urls.txt"

mkdir -p "$TMP_DIR"
> "$VISITED_FILE"
> "$FOUND_JS"
> "$OUTPUT_FILE"

# Regex to find .js filenames
js_regex='[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.js'

# Recursive JS crawler
crawl_js() {
    local url="$1"

    # Avoid revisits
    grep -qxF "$url" "$VISITED_FILE" && return
    echo "$url" >> "$VISITED_FILE"

    echo "[+] Downloading: $url"
    js_content=$(curl -s "$url")

    # Scan for secrets
    echo "$js_content" | grep -iE 'api[_-]?key|secret|token|config|firebase|env|endpoint|access[_-]?key|client[_-]?id|auth|url' && \
        echo "[!!] Possible secret found in: $url"

    # Find .js references and recurse
    echo "$js_content" | grep -oE "$js_regex" | sort -u | while read -r js_file; do
        full_url="$BASE_URL/$js_file"
        if ! grep -qxF "$full_url" "$FOUND_JS"; then
            echo "$full_url" >> "$FOUND_JS"
            crawl_js "$full_url"
        fi
    done
}

# Start the crawl
crawl_js "$BASE_URL"

# Save final unique list
sort -u "$FOUND_JS" > "$OUTPUT_FILE"

echo -e "\n✅ Unique JS URLs saved to: $OUTPUT_FILE"

