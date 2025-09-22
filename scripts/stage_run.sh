#!/usr/bin/env bash
set -euo pipefail
# Usage: bash scripts/stage_run.sh <slug> [repo_dir_name]

slug="${1:-}"; repo_dir="${2:-}"
[[ -n "$slug" ]] || { echo "Usage: $0 <slug> [repo_dir_name]"; exit 2; }

date_utc="$(date -u +%Y%m%d)"
RUN_ROOT="runs/${date_utc}-${slug}"

mkdir -p "$RUN_ROOT"/{git,odc,trivy,npm-audit,zap,semgrep,bandit,gitleaks,sonar,allure,allure-results,screenshots,logs}

# Repo metadata (best effort)
if [[ -n "${repo_dir:-}" && -d "${repo_dir}/.git" ]]; then
  git -C "$repo_dir" rev-parse HEAD > "$RUN_ROOT/git/commit.txt" 2>/dev/null || true
  git -C "$repo_dir" rev-parse --abbrev-ref HEAD > "$RUN_ROOT/git/branch.txt" 2>/dev/null || echo "main" > "$RUN_ROOT/git/branch.txt"
  git -C "$repo_dir" remote get-url origin > "$RUN_ROOT/git/repo_url.txt" 2>/dev/null || true
fi

# Copy artifacts (best-effort; ignore if missing)
cp -f security-reports/dependency-check-report.json "$RUN_ROOT/odc/" 2>/dev/null || true
cp -f security-reports/dependency-check-*.json     "$RUN_ROOT/odc/" 2>/dev/null || true
cp -f security-reports/dependency-check-report.html "$RUN_ROOT/odc/" 2>/dev/null || true

cp -f security-reports/trivy-fs-report.json "$RUN_ROOT/trivy/" 2>/dev/null || true
cp -f security-reports/trivy_fs.json        "$RUN_ROOT/trivy/" 2>/dev/null || true

cp -f security-reports/npm-audit.json "$RUN_ROOT/npm-audit/" 2>/dev/null || true
cp -f security-reports/npm_audit.json "$RUN_ROOT/npm-audit/" 2>/dev/null || true

cp -f security-reports/zap-report.json "$RUN_ROOT/zap/" 2>/dev/null || true
cp -f security-reports/zap-report.html "$RUN_ROOT/zap/" 2>/dev/null || true

cp -f security-reports/semgrep-report.json "$RUN_ROOT/semgrep/" 2>/dev/null || true
cp -f security-reports/bandit-report.json  "$RUN_ROOT/bandit/" 2>/dev/null || true
cp -f security-reports/gitleaks-report.json "$RUN_ROOT/gitleaks/" 2>/dev/null || true
cp -f security-reports/sonar-issues.json "$RUN_ROOT/sonar/" 2>/dev/null || true

cp -f security-reports/timings.csv "$RUN_ROOT/logs/" 2>/dev/null || true

# Allure HTML (prefer subdir like allure-report/NodeGoat/, else copy flat)
if ls allure-report/*/index.html >/dev/null 2>&1; then
  latest="$(ls -dt allure-report/*/ | head -1)"
  cp -R "${latest%/}/." "$RUN_ROOT/allure/" 2>/dev/null || true
elif [[ -d "allure-report" ]]; then
  cp -R allure-report/* "$RUN_ROOT/allure/" 2>/dev/null || true
fi

# Raw results (optional)
[[ -d allure-results ]] && cp -R allure-results/* "$RUN_ROOT/allure-results/" 2>/dev/null || true

touch "$RUN_ROOT/evidence_log.md"
printf '%s\n' "$RUN_ROOT" > .last_run_root

echo "✅ Staged run at: $RUN_ROOT"
echo "Tip: export RUN_ROOT=\"$(cat .last_run_root)\""
