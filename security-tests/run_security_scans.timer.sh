#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# Timed Security Runner (wrapper)
# - Calls your base script: security-tests/run_security_scans.sh
# - Per-iteration Allure handling:
#     * Reset once per iteration (keep history/)
#     * Accumulate results across all tools in that iteration
# - Per-tool timings -> CSV
# - Artifact sanity checks
# - macOS Bash 3.2 compatible (no `mapfile`)
# ---------------------------------------------------------------------------

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_RUN="${BASE_RUN:-$SELF_DIR/run_security_scans.sh}"
[[ -x "$BASE_RUN" ]] || { echo "❌ Base script not found/executable at: $BASE_RUN"; exit 2; }

# ---------- Defaults (env overrides) ----------
SEC_REPORT_DIR="${SEC_REPORT_DIR:-./security-reports}"
ALLURE_RESULTS_DIR="${ALLURE_RESULTS_DIR:-./allure-results}"   # base script should write here
TIMING_CSV="${TIMING_CSV:-$SEC_REPORT_DIR/timings.csv}"

ODC_IMAGE="${ODC_IMAGE:-owasp/dependency-check:latest}"
TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy:0.53.0}"
ZAP_IMAGE="${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}"

ODC_DATA_DIR="${ODC_DATA_DIR:-$HOME/odc-data}"
TRIVY_CACHE_DIR="${TRIVY_CACHE_DIR:-$HOME/.cache/trivy}"

# Platform autodetect (Apple Silicon)
HOST_ARCH="$(uname -m)"
case "$HOST_ARCH" in
  arm64|aarch64) : "${ODC_PLATFORM:=linux/amd64}"; : "${TRIVY_PLATFORM:=linux/arm64}" ;;
  x86_64|amd64)  : "${ODC_PLATFORM:=linux/amd64}"; : "${TRIVY_PLATFORM:=linux/amd64}" ;;
  *)             : "${ODC_PLATFORM:=linux/amd64}"; : "${TRIVY_PLATFORM:=linux/amd64}" ;;
esac

ITERATIONS="${ITERATIONS:-3}"   # env can override; CLI flag can override further
REPO_URL=""
BRANCH=""
TOOLS="odc,trivy-fs,npm-audit"   # add: zap,sonar,bandit,semgrep,gitleaks
ZAP_MODE="${ZAP_MODE:-baseline}"
TARGET_URL=""
OPENAPI_SPEC=""

# Optional gates (warn-only by default)
: "${FAIL_ON_CRITICAL:=false}"   # true|false
: "${MAX_HIGH:=}"                # number or empty
: "${MAX_TOTAL:=}"               # number or empty

# Extra args passthrough to BASE_RUN (after `--`)
declare -a EXTRA_ARGS=()

usage() {
  cat <<EOF
Usage:
  $0 --repo-url <URL> [--branch main] \\
     [--tools odc,trivy-fs,npm-audit[,zap,sonar,bandit,semgrep,gitleaks]] [--iterations 1] \\
     [--zap-mode baseline|full|openapi|auth] [--target-url http://...] [--openapi /path.yaml]
     [-- <extra args passed to base script>]

Env options:
  SEC_REPORT_DIR, ALLURE_RESULTS_DIR, TIMING_CSV, SKIP_WARMUP=true
  ODC_IMAGE, TRIVY_IMAGE, ZAP_IMAGE
  ODC_DATA_DIR, TRIVY_CACHE_DIR
  ODC_PLATFORM, TRIVY_PLATFORM
  FAIL_ON_CRITICAL, MAX_HIGH, MAX_TOTAL
EOF
  exit 2
}

# ---------- CLI ----------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-url) REPO_URL="$2"; shift 2 ;;
    --branch) BRANCH="$2"; shift 2 ;;
    --tools) TOOLS="$2"; shift 2 ;;
    --iterations) ITERATIONS="$2"; shift 2 ;;
    --zap-mode) ZAP_MODE="$2"; shift 2 ;;
    --target-url) TARGET_URL="$2"; shift 2 ;;
    --openapi) OPENAPI_SPEC="$2"; shift 2 ;;
    --) shift; EXTRA_ARGS=("$@"); break ;;
    -h|--help) usage ;;
    *) echo "Unknown arg: $1"; usage ;;
  esac
done

[[ -n "$REPO_URL" ]] || { echo "❌ --repo-url is required"; usage; }
[[ "$ITERATIONS" =~ ^[0-9]+$ ]] || { echo "❌ --iterations must be a non-negative integer"; exit 2; }

command -v docker >/dev/null 2>&1 || { echo "❌ Docker is required"; exit 2; }
mkdir -p "$SEC_REPORT_DIR" "$ODC_DATA_DIR" "$TRIVY_CACHE_DIR" "$ALLURE_RESULTS_DIR"

# ---------- Timing helpers ----------
_ts() { date +%s; }

_csv_init() {
  [[ -f "$TIMING_CSV" ]] || echo "timestamp,tool,mode,repo,branch,duration_seconds,exit_code,notes" > "$TIMING_CSV"
}

_csv_escape() { local f="${1-}"; f=${f//\"/\"\"}; printf '"%s"' "$f"; }

_csv_row() {
  local ts="$1" tool="$2" mode="$3" repo="$4" br="$5" dur="$6" ec="$7" notes="$8"
  {
    _csv_escape "$ts";    printf ','
    _csv_escape "$tool";  printf ','
    _csv_escape "$mode";  printf ','
    _csv_escape "$repo";  printf ','
    _csv_escape "$br";    printf ','
    _csv_escape "$dur";   printf ','
    _csv_escape "$ec";    printf ','
    _csv_escape "$notes"; printf '\n'
  } >> "$TIMING_CSV"
}

_run_timed() {
  # _run_timed <tool> <mode> <notes> -- <cmd...>
  local tool="$1"; shift
  local mode="$1"; shift
  local notes="$1"; shift
  [[ "${1:-}" == "--" ]] && shift
  local start=$(_ts) ec=0
  "$@" || ec=$?
  local end=$(_ts)
  _csv_row "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$tool" "$mode" "$REPO_URL" "${BRANCH:-}" "$((end-start))" "$ec" "$notes"
  return $ec
}

_run_base() {
  local args=("$@")
  if ((${#EXTRA_ARGS[@]})); then args+=("--"); args+=("${EXTRA_ARGS[@]}"); fi
  bash "$BASE_RUN" "${args[@]}"
}

# ---------- Allure accumulation (DO NOT lose prior tools) ----------
ACCUM_DIR=".allure-accumulate"

_rsync_copy() {
  # _rsync_copy <src/> <dst/>
  local src="$1" dst="$2"
  if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete "$src" "$dst" 2>/dev/null || true
  else
    # Poor man's rsync
    rm -rf "$dst"
    mkdir -p "$dst"
    cp -R "$src"/* "$dst"/ 2>/dev/null || true
  fi
}

allure_init_iteration() {
  mkdir -p "$ALLURE_RESULTS_DIR"
  # preserve history
  local tmp=".allure-history-tmp"
  rm -rf "$tmp"
  if [[ -d "$ALLURE_RESULTS_DIR/history" ]]; then
    mkdir -p "$tmp"
    cp -R "$ALLURE_RESULTS_DIR/history/." "$tmp/" 2>/dev/null || true
  fi
  # hard reset
  rm -rf "$ALLURE_RESULTS_DIR"/*
  mkdir -p "$ALLURE_RESULTS_DIR/history"
  if [[ -d "$tmp" ]]; then
    cp -R "$tmp/." "$ALLURE_RESULTS_DIR/history/" 2>/dev/null || true
    rm -rf "$tmp"
  fi
  # init accumulator with whatever is in results now (history only)
  rm -rf "$ACCUM_DIR"
  mkdir -p "$ACCUM_DIR"
  _rsync_copy "$ALLURE_RESULTS_DIR/" "$ACCUM_DIR/"
}

allure_before_tool() {
  # Re-seed allure-results from accumulator so base script appends to existing set
  mkdir -p "$ALLURE_RESULTS_DIR"
  _rsync_copy "$ACCUM_DIR/" "$ALLURE_RESULTS_DIR/"
}

allure_after_tool() {
  # Capture whatever the base script just wrote and merge into accumulator
  mkdir -p "$ALLURE_RESULTS_DIR" "$ACCUM_DIR"
  _rsync_copy "$ALLURE_RESULTS_DIR/" "$ACCUM_DIR/"
}

# ---------- Artifact checks ----------
require_file() { local f="$1"; [[ -s "$f" ]] || { echo "❌ Missing/empty: $f"; return 2; }; }
json_ok()      { local f="$1"; if command -v jq >/dev/null 2>&1; then jq -e . "$f" >/dev/null 2>&1 || { echo "❌ Invalid JSON: $f"; return 2; }; else [[ -s "$f" ]]; fi; }

# ---------- Warm caches (outside timing) ----------
if [[ "${SKIP_WARMUP:-false}" != "true" ]]; then
  echo "== Warm-up (outside timing) =="
  docker run --rm --platform "${ODC_PLATFORM}" \
    -v "$ODC_DATA_DIR":/usr/share/dependency-check/data \
    "$ODC_IMAGE" --updateonly --data /usr/share/dependency-check/data >/dev/null || true
  docker run --rm --platform "${TRIVY_PLATFORM}" \
    -v "$TRIVY_CACHE_DIR":/root/.cache/ "$TRIVY_IMAGE" image --quiet alpine:3.19 >/dev/null 2>&1 || true
else
  echo "== Warm-up skipped (SKIP_WARMUP=true) =="
fi

# ---------- Parse TOOLS CSV -> array (Bash 3.2 friendly) ----------
TOOL_ARR=(); OLDIFS="$IFS"; IFS=','; for raw in $TOOLS; do
  t="$(printf '%s' "$raw" | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')"
  [ -n "$t" ] && TOOL_ARR+=("$t")
done; IFS="$OLDIFS"

# ---------- Main: loop iterations, inside loop over tools ----------
_csv_init

iter=1
while (( iter <= ITERATIONS )); do
  echo "================ Iteration $iter/$ITERATIONS ================"
  # Start fresh results (keep trend), and init accumulator
  allure_init_iteration

  for tool in "${TOOL_ARR[@]}"; do
    echo "== Tool: $tool =="
    # Make sure previous tools' results are present so nothing gets wiped
    allure_before_tool

    case "$tool" in
      odc)
        _run_timed "odc" "json" "noupdate/auto" -- \
          _run_base --repo-url "$REPO_URL" ${BRANCH:+--branch "$BRANCH"} --tools odc
        require_file "$SEC_REPORT_DIR/dependency-check-report.json"
        json_ok     "$SEC_REPORT_DIR/dependency-check-report.json"
        ;;
      trivy-fs)
        _run_timed "trivy-fs" "vuln,misconfig,secret" "skip-db-update" -- \
          _run_base --repo-url "$REPO_URL" ${BRANCH:+--branch "$BRANCH"} --tools trivy-fs
        require_file "$SEC_REPORT_DIR/trivy-fs-report.json"
        json_ok     "$SEC_REPORT_DIR/trivy-fs-report.json"
        ;;
      npm-audit)
        _run_timed "npm-audit" "json" "" -- \
          _run_base --repo-url "$REPO_URL" ${BRANCH:+--branch "$BRANCH"} --tools npm-audit
        require_file "$SEC_REPORT_DIR/npm-audit.json"
        json_ok     "$SEC_REPORT_DIR/npm-audit.json"
        ;;
      zap)
        if [[ "$ZAP_MODE" == "openapi" ]]; then
          [[ -n "${OPENAPI_SPEC:-}" ]] || { echo "⚠️ ZAP openapi spec missing; skipping."; continue; }
        else
          [[ -n "${TARGET_URL:-}" ]] || { echo "⚠️ ZAP target-url missing; skipping."; continue; }
        fi
        _run_timed "zap" "$ZAP_MODE" "baseline=${ZAP_BASELINE_TIME:-10};full=${ZAP_FULL_TIME:-10}" -- \
          _run_base --repo-url "$REPO_URL" ${BRANCH:+--branch "$BRANCH"} \
            --tools zap --zap-mode "$ZAP_MODE" \
            ${TARGET_URL:+--target-url "$TARGET_URL"} \
            ${OPENAPI_SPEC:+--openapi "$OPENAPI_SPEC"}
        if [[ -s "$SEC_REPORT_DIR/zap-report.json" ]]; then
          json_ok "$SEC_REPORT_DIR/zap-report.json"
        elif [[ -s "$SEC_REPORT_DIR/zap-report.html" ]]; then
          : # ok
        else
          echo "⚠️ ZAP report not found (html/json)"
        fi
        ;;
      sonar)
        _run_timed "sonar" "scanner" "" -- \
          _run_base --repo-url "$REPO_URL" ${BRANCH:+--branch "$BRANCH"} --tools sonar
        [[ -s "$SEC_REPORT_DIR/sonar-issues.json" ]] || echo "⚠️ sonar-issues.json missing"
        [[ -s "$SEC_REPORT_DIR/sonar-scanner.log" ]] || echo "⚠️ sonar-scanner.log missing"
        ;;
      bandit)
        _run_timed "bandit" "json" "" -- \
          _run_base --repo-url "$REPO_URL" ${BRANCH:+--branch "$BRANCH"} --tools bandit
        [[ -s "$SEC_REPORT_DIR/bandit-report.json" ]] && json_ok "$SEC_REPORT_DIR/bandit-report.json" || echo "⚠️ bandit-report.json missing"
        ;;
      semgrep)
        _run_timed "semgrep" "ci" "" -- \
          _run_base --repo-url "$REPO_URL" ${BRANCH:+--branch "$BRANCH"} --tools semgrep
        require_file "$SEC_REPORT_DIR/semgrep-report.json"
        json_ok     "$SEC_REPORT_DIR/semgrep-report.json"
        ;;
      gitleaks)
        _run_timed "gitleaks" "detect" "" -- \
          _run_base --repo-url "$REPO_URL" ${BRANCH:+--branch "$BRANCH"} --tools gitleaks
        require_file "$SEC_REPORT_DIR/gitleaks-report.json"
        json_ok     "$SEC_REPORT_DIR/gitleaks-report.json"
        ;;
      *)
        echo "⚠️ Unknown tool: $tool (skipped)"
        ;;
    esac

    # Capture/merge whatever was written by this tool
    allure_after_tool
  done

  echo "== Iteration $iter complete =="
  iter=$((iter+1))
done

echo "✅ Timings written to: $TIMING_CSV"
echo "🎉 Done."
