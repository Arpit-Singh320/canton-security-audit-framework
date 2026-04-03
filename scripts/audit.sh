#!/usr/bin/env bash
# audit.sh — Run the Canton Security Audit Framework and output an HTML report.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ANALYZER="$ROOT/analyzer/main.py"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT/.audit-reports}"
FORMAT="${FORMAT:-html}"
TARGET="${1:-$ROOT}"

command -v python3 &>/dev/null || { echo "Error: python3 is required."; exit 1; }

mkdir -p "$OUTPUT_DIR"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTFILE="$OUTPUT_DIR/audit_${TIMESTAMP}.${FORMAT}"

echo "Canton Security Audit Framework"
echo "================================"
echo "Target  : $TARGET"
echo "Format  : $FORMAT"
echo "Output  : $OUTFILE"
echo ""

python3 "$ANALYZER"   --target "$TARGET"   --format "$FORMAT"   --output "$OUTFILE"   --rules authority_leak,choice_abuse,time_attack,disclosure

echo ""
echo "Audit complete → $OUTFILE"

if [[ "$FORMAT" == "html" ]]; then
  echo ""
  if command -v open &>/dev/null; then
    open "$OUTFILE"
  elif command -v xdg-open &>/dev/null; then
    xdg-open "$OUTFILE"
  fi
fi
