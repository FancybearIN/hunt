#!/bin/bash

# Usage: ./gf_split.sh input.txt
# Example: ./gf_split.sh all_urls.txt

INPUT_FILE="$1"
OUTPUT_DIR="gf_output"

if [[ -z "$INPUT_FILE" || ! -f "$INPUT_FILE" ]]; then
  echo "Usage: $0 <input_file>"
  exit 1
fi

mkdir -p "$OUTPUT_DIR"

for pattern in $(gf -list); do
  echo "[+] Processing gf pattern: $pattern"

  PATTERN_DIR="$OUTPUT_DIR/$pattern"
  OUTPUT_FILE="$PATTERN_DIR/$pattern.txt"

  mkdir -p "$PATTERN_DIR"

  gf "$pattern" "$INPUT_FILE" > "$OUTPUT_FILE"

  # Remove empty files
  if [[ ! -s "$OUTPUT_FILE" ]]; then
    rm -f "$OUTPUT_FILE"
    rmdir "$PATTERN_DIR"
    echo "    [-] No matches, skipped"
  else
    echo "    [+] Saved to $OUTPUT_FILE"
  fi
done

echo "[✓] Done. Results stored in $OUTPUT_DIR/"
