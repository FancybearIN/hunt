#!/bin/bash

INPUT="$1"
FUZZ_KEYWORD="FUZZ"

# sanity check
if [ -z "$INPUT" ]; then
    echo "Usage: $0 <input_file>"
    exit 1
fi

while read -r url; do
    [[ "$url" != *"?"* ]] && continue

    base="${url%%\?*}"
    query="${url#*\?}"

    IFS='&' read -ra params <<< "$query"

    keys=()
    values=()

    for p in "${params[@]}"; do
        key="${p%%=*}"
        val="${p#*=}"
        keys+=("$key")
        values+=("$val")
    done

    for ((i=0; i<${#keys[@]}; i++)); do
        new_query=""

        for ((j=0; j<${#keys[@]}; j++)); do
            if [[ $i -eq $j ]]; then
                new_query+="${keys[$j]}=$FUZZ_KEYWORD&"
            else
                new_query+="${keys[$j]}=${values[$j]}&"
            fi
        done

        new_query="${new_query%&}"
        echo "$base?$new_query"
    done

done < "$INPUT"
