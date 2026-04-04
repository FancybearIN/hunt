#!/usr/bin/env bash
# ==========================================
# Universal Parallel Tool Runner
# Works with waybackurls, gau, httpx, dnsx, etc.
# ==========================================

set -euo pipefail

# ---------- AUTO TUNING -------------------
CPU_CORES=$(nproc)
PARALLEL_JOBS=$((CPU_CORES * 2))
CHUNK_SIZE=5000

# ---------- INPUT CHECK ------------------
if [[ $# -lt 3 ]]; then
  echo "Usage:"
  echo "  $0 <tool_command> <input_file> <output_file>"
  echo ""
  echo "Example:"
  echo "  $0 \"waybackurls\" domains.txt wayback.txt"
  echo "  $0 \"httpx -silent\" subs.txt httpx.txt"
  exit 1
fi

TOOL_CMD="$1"
INPUT_FILE="$2"
OUTPUT_FILE="$3"

if [[ ! -f "$INPUT_FILE" ]]; then
  echo "[!] Input file not found"
  exit 1
fi

TOTAL=$(wc -l < "$INPUT_FILE")

echo "[*] Tool        : $TOOL_CMD"
echo "[*] Input lines : $TOTAL"
echo "[*] CPU cores   : $CPU_CORES"
echo "[*] Jobs        : $PARALLEL_JOBS"
echo "[*] Chunk size  : $CHUNK_SIZE"
echo "----------------------------------------"

# ---------- WORKDIR ----------------------
WORKDIR=$(mktemp -d)
CHUNKS="$WORKDIR/chunks"
RESULTS="$WORKDIR/results"

mkdir -p "$CHUNKS" "$RESULTS"

# ---------- SPLIT ------------------------
split -l "$CHUNK_SIZE" "$INPUT_FILE" "$CHUNKS/input_"

# ---------- PARALLEL EXEC ----------------
ls "$CHUNKS"/input_* | xargs -P "$PARALLEL_JOBS" -I {} bash -c '
  cat {} | '"$TOOL_CMD"' >> '"$RESULTS"'/out.txt
'

# ---------- MERGE ------------------------
sort -u "$RESULTS/out.txt" > "$OUTPUT_FILE"

# ---------- CLEANUP ----------------------
rm -rf "$WORKDIR"

echo "----------------------------------------"
echo "[✓] Output saved : $OUTPUT_FILE"
echo "[✓] Done"
