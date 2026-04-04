#!/bin/bash

INPUT="$1"
[ -z "$INPUT" ] && echo "Usage: $0 <file>" && exit 1

cat "$INPUT" | \
grep '^http' | \
sed 's/+http/\nhttp/g' | \

while read -r url; do
    [[ "$url" != *"?"* ]] && continue

    base="${url%%\?*}"
    query="${url#*\?}"

    IFS='&' read -ra params <<< "$query"

    keys=()

    for p in "${params[@]}"; do
        key="${p%%=*}"
        val="${p#*=}"

        # ✅ preserve FUZZ position
        if [[ "$val" == "FUZZ" ]]; then
            keys+=("$key=FUZZ")
        else
            keys+=("$key=")
        fi
    done

    # 🔥 normalize order (critical)
    normalized=$(printf "%s\n" "${keys[@]}" | sort | tr '\n' '&')
    normalized="${normalized%&}"

    echo "$base?$normalized"

done | sort -u
