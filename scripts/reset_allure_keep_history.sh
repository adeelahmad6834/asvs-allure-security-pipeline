
#!/usr/bin/env bash
set -euo pipefail
ALLURE_RESULTS_DIR="${ALLURE_RESULTS_DIR:-./allure-results}"
mkdir -p "$ALLURE_RESULTS_DIR"
tmp=".allure-history-tmp"
rm -rf "$tmp"
if [[ -d "$ALLURE_RESULTS_DIR/history" ]]; then
  mkdir -p "$tmp"
  cp -R "$ALLURE_RESULTS_DIR/history/." "$tmp/" 2>/dev/null || true
fi
rm -rf "$ALLURE_RESULTS_DIR"/*
mkdir -p "$ALLURE_RESULTS_DIR/history"
if [[ -d "$tmp" ]]; then
  cp -R "$tmp/." "$ALLURE_RESULTS_DIR/history/" 2>/dev/null || true
  rm -rf "$tmp"
fi
echo "✅ Reset $ALLURE_RESULTS_DIR (history preserved)."
