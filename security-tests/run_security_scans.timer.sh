#!/usr/bin/env bash
set -euo pipefail

# Wrapper for: security-tests/run_security_scans.sh
# Measures wall-clock timings tool-by-tool and appends to CSV (with safe quoting).

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_RUN="$SELF_DIR/run_security_scans.sh"
[[ -x "$BASE_RUN" ]] || { echo "❌ Base script not found/executable at: $BASE_RUN"; exit 2; }

# ---------- Defaults (override via env) ----------
SEC_REPORT_DIR="${SEC_REPORT_DIR:-./security-reports}"
TIMING_CSV="${TIMING_CSV:-$SEC_REPORT_DIR/timings.csv}"

ODC_IMAGE="${ODC_IMAGE:-owasp/dependency-check:latest}"
TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy:0.53.0}"
ZAP_IMAGE="${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}"

ODC_DATA_DIR="${ODC_DATA_DIR:-$HOME/odc-data}"
TRIVY_CACHE_DIR="${TRIVY_CACHE_DIR:-$HOME/.cache/trivy}"

# Platform autodetect (good for Apple Silicon laptops)
HOST_ARCH="$(uname -m)"
case "$HOST_ARCH" in
  arm64|aarch64) : "${ODC_PLATFORM:=linux/amd64}"; : "${TRIVY_PLATFORM:=linux/arm64}" ;;
  x86_64|amd64)  : "${ODC_PLATFORM:=linux/amd64}"; : "${TRIVY_PLATFORM:=linux/amd64}" ;;
  *)             : "${ODC_PLATFORM:=linux/amd64}"; : "${TRIVY_PLATFORM:=linux/amd64}" ;;
esac

ITERATIONS=3
REPO_URL=""
BRANCH=""
TOOLS="odc,trivy-fs,npm-audit"   # add: zap,sonar,bandit,semgrep,gitleaks
ZAP_MODE="${ZAP_MODE:-baseline}"
TARGET_URL=""
OPENAPI_SPEC=""

# Extra args passthrough (after a lone --)
declare -a EXTRA_ARGS=()

usage() {
  cat <<EOF
Usage:
  $0 --repo-url <URL> [--branch main] \\
     [--tools odc,trivy-fs,npm-audit[,zap,sonar,bandit,semgrep,gitleaks]] [--iterations 3]
     [--zap-mode baseline|full|openapi|auth] [--target-url http://...] [--openapi /path.yaml]
     [-- <extra args passed to base script>]

Env options:
  SEC_REPORT_DIR, TIMING_CSV, SKIP_WARMUP=true
  ODC_IMAGE, TRIVY_IMAGE, ZAP_IMAGE
  ODC_DATA_DIR, TRIVY_CACHE_DIR
  ODC_PLATFORM, TRIVY_PLATFORM

Notes:
- Sonar needs env set: SONAR_HOST_URL, SONAR_TOKEN (or SONAR_LOGIN), SONAR_PROJECT_KEY
- This script only TIMES tools; results are produced by run_security_scans.sh
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

mkdir -p "$SEC_REPORT_DIR" "$ODC_DATA_DIR" "$TRIVY_CACHE_DIR"

# ---------- Timing helpers ----------
_ts() { date +%s; }

_csv_init() {
  [[ -f "$TIMING_CSV" ]] || echo "timestamp,tool,mode,repo,branch,duration_seconds,exit_code,notes" > "$TIMING_CSV"
}

_csv_escape() {
  # Escape " by doubling it, wrap field in "
  local f="${1-}"
  f=${f//\"/\"\"}
  printf '"%s"' "$f"
}

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

# Helper to call base script with optional extras safely
_run_base() {
  local args=("$@")
  if ((${#EXTRA_ARGS[@]})); then
    args+=("--")
    args+=("${EXTRA_ARGS[@]}")
  fi
  bash "$BASE_RUN" "${args[@]}"
}

# ---------- Warm caches (outside timing) ----------
if [[ "${SKIP_WARMUP:-false}" != "true" ]]; then
  echo "== Warm-up (outside timing) =="
  # ODC NVD DB
  docker run --rm --platform "${ODC_PLATFORM}" \
    -v "$ODC_DATA_DIR":/usr/share/dependency-check/data \
    "$ODC_IMAGE" --updateonly --data /usr/share/dependency-check/data >/dev/null || true

  # Trivy DB: do a tiny scan to populate cache
  docker run --rm --platform "${TRIVY_PLATFORM}" \
    -v "$TRIVY_CACHE_DIR":/root/.cache/ "$TRIVY_IMAGE" image --quiet alpine:3.19 >/dev/null 2>&1 || true
else
  echo "== Warm-up skipped (SKIP_WARMUP=true) =="
fi

# ---------- Timed runs ----------
_csv_init

run_tool() {
  local tool="$1"
  for i in $(seq 1 "$ITERATIONS"); do
    echo "== $tool (run $i/$ITERATIONS) =="
    case "$tool" in
      odc)
        _run_timed "odc" "json" "noupdate" -- \
          _run_base --repo-url "$REPO_URL" ${BRANCH:+--branch "$BRANCH"} --tools odc
        ;;
      trivy-fs)
        _run_timed "trivy-fs" "vuln,misconfig,secret" "skip-db-update" -- \
          _run_base --repo-url "$REPO_URL" ${BRANCH:+--branch "$BRANCH"} --tools trivy-fs
        ;;
      npm-audit)
        _run_timed "npm-audit" "json" "" -- \
          _run_base --repo-url "$REPO_URL" ${BRANCH:+--branch "$BRANCH"} --tools npm-audit
        ;;
      zap)
        if [[ "$ZAP_MODE" == "openapi" ]]; then
          if [[ -z "${OPENAPI_SPEC:-}" ]]; then
            echo "⚠️ ZAP openapi spec missing; skipping."
            continue
          fi
        else
          if [[ -z "${TARGET_URL:-}" ]]; then
            echo "⚠️ ZAP target-url missing; skipping."
            continue
          fi
        fi
        _run_timed "zap" "$ZAP_MODE" "baseline=${ZAP_BASELINE_TIME:-10};full=${ZAP_FULL_TIME:-10}" -- \
          _run_base --repo-url "$REPO_URL" ${BRANCH:+--branch "$BRANCH"} \
            --tools zap --zap-mode "$ZAP_MODE" \
            ${TARGET_URL:+--target-url "$TARGET_URL"} \
            ${OPENAPI_SPEC:+--openapi "$OPENAPI_SPEC"}
        ;;
      sonar)
        _run_timed "sonar" "scanner" "" -- \
          _run_base --repo-url "$REPO_URL" ${BRANCH:+--branch "$BRANCH"} --tools sonar
        ;;
      bandit)
        _run_timed "bandit" "json" "" -- \
          _run_base --repo-url "$REPO_URL" ${BRANCH:+--branch "$BRANCH"} --tools bandit
        ;;
      semgrep)
        _run_timed "semgrep" "ci" "" -- \
          _run_base --repo-url "$REPO_URL" ${BRANCH:+--branch "$BRANCH"} --tools semgrep
        ;;
      gitleaks)
        _run_timed "gitleaks" "detect" "" -- \
          _run_base --repo-url "$REPO_URL" ${BRANCH:+--branch "$BRANCH"} --tools gitleaks
        ;;
      *)
        echo "⚠️ Unknown tool: $tool (skipped)"
        ;;
    esac
  done
}

# Robust CSV → array: split, trim, drop empties (Bash 3.2/macOS friendly)
TOOL_ARR=()
OLDIFS="$IFS"
IFS=','

for raw in $TOOLS; do
  t="$(printf '%s' "$raw" | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')"
  [ -n "$t" ] && TOOL_ARR+=("$t")
done

IFS="$OLDIFS"

for t in "${TOOL_ARR[@]}"; do
  run_tool "$t"
done

echo "✅ Timings written to: $TIMING_CSV"
