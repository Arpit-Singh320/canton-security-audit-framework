#!/bin/bash
set -euo pipefail

# canton-security-audit-framework: audit.sh
#
# A one-command script to perform a static security analysis on a Daml project.
# It builds the project, runs the security scanner, and generates a standalone
# HTML report.

# --- Configuration ---
SCRIPT_NAME=$(basename "$0")
REPORT_DIR="security-reports"
REPORT_FILENAME="daml_security_audit_$(date +'%Y%m%d_%H%M%S').html"
# This is the core scanner executable provided by this project.
# It's assumed to be in the user's PATH.
SCANNER_CMD="daml-security-scanner"

# --- Helper Functions ---

# Print script usage information.
print_usage() {
  echo "Usage: $SCRIPT_NAME <path_to_daml_project>"
  echo
  echo "  Performs a static security analysis on a Daml project and generates an HTML report."
  echo
  echo "  Arguments:"
  echo "    <path_to_daml_project>   The root directory of the Daml project to audit."
  echo
  echo "  Prerequisites:"
  echo "    - dpm (Canton's Digital Asset Package Manager)"
  echo "    - $SCANNER_CMD (this project's executable)"
  echo "    - pandoc (for HTML report generation)"
}

# Check for required command-line dependencies.
check_deps() {
  local missing_deps=0
  for cmd in dpm "$SCANNER_CMD" pandoc; do
    if ! command -v "$cmd" &> /dev/null; then
      echo "❌ Error: Required command not found: '$cmd'"
      missing_deps=1
    fi
  done
  if [ $missing_deps -eq 1 ]; then
    echo "Please install all required dependencies and ensure they are in your PATH."
    exit 1
  fi
}

# Generate embedded CSS for the HTML report.
generate_css() {
cat <<'EOF'
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; max-width: 960px; margin: 2rem auto; padding: 0 1.5rem; }
h1, h2, h3, h4 { font-weight: 600; margin-top: 2em; border-bottom: 1px solid #eaecef; padding-bottom: 0.3em; }
h1 { font-size: 2.25em; }
code { background-color: #f6f8fa; padding: .2em .4em; font-family: SFMono-Regular, Consolas, "Liberation Mono", Menlo, monospace; font-size: 85%; border-radius: 6px; }
pre { background-color: #f6f8fa; padding: 16px; overflow: auto; border-radius: 6px; }
pre > code { padding: 0; background-color: transparent; }
table { border-collapse: collapse; width: 100%; margin: 1em 0; display: block; overflow: auto; }
th, td { border: 1px solid #dfe2e5; padding: 8px 12px; }
th { background-color: #f6f8fa; font-weight: 600; }
.severity-high { color: #d73a49; font-weight: bold; }
.severity-medium { color: #d48806; font-weight: bold; }
.severity-low { color: #6f42c1; }
.severity-info { color: #0366d6; }
.summary { background-color: #f6f8fa; border-left: 4px solid #0366d6; padding: 1em 1.5em; margin: 2em 0; }
.summary h2 { border-bottom: none; }
EOF
}

# --- Main Script ---

# Handle command-line arguments.
if [[ "$#" -eq 0 || "$1" == "-h" || "$1" == "--help" ]]; then
  print_usage
  exit 0
fi

PROJECT_PATH="$1"
if [ ! -d "$PROJECT_PATH" ]; then
  echo "❌ Error: Project directory not found at '$PROJECT_PATH'"
  print_usage
  exit 1
fi

# A valid Daml project must contain one of these files at its root.
if [ ! -f "$PROJECT_PATH/daml.yaml" ] && [ ! -f "$PROJECT_PATH/multi-package.yaml" ]; then
    echo "❌ Error: No 'daml.yaml' or 'multi-package.yaml' found in '$PROJECT_PATH'."
    echo "   Please provide the path to the root of a valid Daml project."
    exit 1
fi

# Check for dependencies before starting.
check_deps

# --- Execution ---

echo "▶️  Starting Daml Security Audit for project at: $PROJECT_PATH"

# Resolve absolute path for clarity and to handle relative paths correctly.
PROJECT_PATH=$(cd "$PROJECT_PATH" && pwd)
cd "$PROJECT_PATH"

# 1. Build the Daml project to produce a DAR file.
echo "   1. Compiling Daml project with 'dpm build'..."
DPM_LOG_FILE=$(mktemp)
# Use --all to support multi-package projects seamlessly.
if ! dpm build --all &> "$DPM_LOG_FILE"; then
    echo "❌ Error: 'dpm build' failed. See log for details:"
    cat "$DPM_LOG_FILE"
    rm "$DPM_LOG_FILE"
    exit 1
fi
rm "$DPM_LOG_FILE"
echo "   ✅ Project compiled successfully."

# 2. Find the newest generated DAR file.
#    This handles mono-repos or multi-package projects by picking the most recent artifact.
DAR_FILE=$(find . -path "*/.daml/dist/*.dar" -print0 | xargs -0 ls -t | head -n 1)
if [ -z "$DAR_FILE" ] || [ ! -f "$DAR_FILE" ]; then
  echo "❌ Error: Could not find any .dar file in '.daml/dist/' after build."
  exit 1
fi
echo "   ✅ Found DAR file to analyze: $DAR_FILE"

# 3. Run the static analysis scanner.
echo "   2. Running static analysis with '$SCANNER_CMD'..."
TMP_MD_REPORT=$(mktemp)
# The scanner is assumed to take a DAR file path and output a markdown report to stdout.
if ! "$SCANNER_CMD" scan "$DAR_FILE" > "$TMP_MD_REPORT"; then
    echo "❌ Error: The security scanner failed. Run '$SCANNER_CMD scan \"$DAR_FILE\"' manually for details."
    rm "$TMP_MD_REPORT"
    exit 1
fi
echo "   ✅ Static analysis complete."

# 4. Generate the final HTML report.
echo "   3. Generating HTML report with Pandoc..."
mkdir -p "$REPORT_DIR"
REPORT_PATH="$PROJECT_PATH/$REPORT_DIR/$REPORT_FILENAME"

pandoc "$TMP_MD_REPORT" \
  --from markdown \
  --to html \
  --standalone \
  --metadata title="Daml Security Audit Report: $(basename "$PROJECT_PATH")" \
  --css <(generate_css) \
  --output "$REPORT_PATH"

echo "   ✅ HTML report generated."

# Cleanup temporary files.
rm "$TMP_MD_REPORT"

# --- Completion ---

echo
echo "🎉 Audit Complete! 🎉"
echo "   Report saved to: $REPORT_PATH"

# Optional: Try to open the report automatically.
if command -v open &> /dev/null; then
  # macOS
  open "$REPORT_PATH"
elif command -v xdg-open &> /dev/null; then
  # Linux
  xdg-open "$REPORT_PATH"
fi

exit 0