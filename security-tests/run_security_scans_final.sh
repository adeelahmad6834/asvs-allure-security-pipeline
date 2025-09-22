#!/usr/bin/env bash
set -euo pipefail

# Detect whether we're constructing a URL for a process running INSIDE docker
normalize_for_scanner() {
  # If scanner runs in Docker and user gave localhost, map to host.docker.internal
  local url="$1"
  if [[ -S /var/run/docker.sock ]] && [[ "$url" =~ ^http://(localhost|127\.0\.0\.1)(:[0-9]+)?$ ]]; then
    echo "http://host.docker.internal${BASH_REMATCH[2]:-:9000}"
  else
    echo "$url"
  fi
}

# When fetching with curl from the HOST, prefer localhost and avoid host.docker.internal
normalize_for_host() {
  local url="$1"
  if [[ "$url" =~ ^http://host\.docker\.internal(:[0-9]+)?$ ]]; then
    echo "http://localhost${BASH_REMATCH[1]:-:9000}"
  else
    echo "$url"
  fi
}

# =============================================================================
# Security Scans Switchboard (PUBLIC-SAFE)
# Tools: Dependency-Check, Trivy FS, ZAP (baseline|full|openapi|auth), npm audit, Bandit, SonarQube
# Added: Semgrep (SAST), Gitleaks (secrets in tree/history)
# Parser: security-tests/parsers/asvs-unified-to-allure.ts
#
# Env you might set:
#   HOST_PWD                 : host path of your workspace (fixes macOS nested mounts)
#   NVD_API_KEY              : Dependency-Check token
#   ODC_DATA_DIR             : cache dir for ODC (default: project/.odc-cache when nested Docker)
#   TRIVY_CACHE_DIR          : cache dir for Trivy
#   GENERATE_ALLURE=true     : auto-generate Allure HTML (default true)
#   ALLURE_VERSION           : default 2.29.0
#   ZAP_BASELINE_TIME=10     : minutes for baseline/openapi scan
#   ZAP_FULL_TIME=10         : minutes for full/auth scan
#   ZAP_IMAGE                : zaproxy image (default ghcr.io/zaproxy/zaproxy:stable)
#   TRIVY_IMAGE              : aquasec/trivy image (default latest)
#   ODC_IMAGE                : owasp/dependency-check (default latest)
#   SEMGREP_IMAGE            : semgrep/semgrep (default latest)
#   SEMGREP_CONFIGS          : CSV of semgrep configs (default: p/owasp-top-ten,p/nodejsscan)
#   SEMGREP_EXCLUDES         : paths to exclude (CSV) [fallback; .semgrepignore preferred]
#   SEMGREP_TIMEOUT          : seconds (default 300; 0 = unlimited)
#   GITLEAKS_IMAGE           : zricethezav/gitleaks (default latest)
#   GITLEAKS_CONFIG          : path to gitleaks.toml (default: security-tests/config/gitleaks.toml if exists)
#   GITLEAKS_MODE            : dir|git|history  (history is strongest)
#   GITLEAKS_HISTORY         : legacy boolean; if true → sets GITLEAKS_MODE=history
#   GITLEAKS_LOG_OPTS        : e.g. --since=2024-01-01 to limit history
# =============================================================================

# ---------------------------
# Configuration (env overrides)
# ---------------------------
SEC_REPORT_DIR="${SEC_REPORT_DIR:-./security-reports}"
ALLURE_REPORT_ROOT="${ALLURE_REPORT_ROOT:-./allure-report}"
ASVS_PARSER="${ASVS_PARSER:-security-tests/parsers/asvs-unified-to-allure.ts}"

ALLURE_VERSION="${ALLURE_VERSION:-2.29.0}"
ZAP_IMAGE="${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}"
TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy:latest}"
ODC_IMAGE="${ODC_IMAGE:-owasp/dependency-check:latest}"
SEMGREP_IMAGE="${SEMGREP_IMAGE:-semgrep/semgrep:latest}"
SEMGREP_CONFIGS="${SEMGREP_CONFIGS:-p/owasp-top-ten,p/nodejsscan}"
SEMGREP_EXCLUDES="${SEMGREP_EXCLUDES:-node_modules,dist,build,coverage,.next,.git}"
SEMGREP_TIMEOUT="${SEMGREP_TIMEOUT:-300}"

GITLEAKS_IMAGE="${GITLEAKS_IMAGE:-zricethezav/gitleaks:latest}"
GITLEAKS_MODE="${GITLEAKS_MODE:-dir}"
GITLEAKS_HISTORY="${GITLEAKS_HISTORY:-false}"
GITLEAKS_LOG_OPTS="${GITLEAKS_LOG_OPTS:-}"

TRIVY_CACHE_DIR="${TRIVY_CACHE_DIR:-$HOME/.cache/trivy}"
ODC_DATA_DIR_DEFAULT="$HOME/odc-data"
ODC_DATA_DIR="${ODC_DATA_DIR:-$ODC_DATA_DIR_DEFAULT}"

GENERATE_ALLURE="${GENERATE_ALLURE:-true}"
# NEW: Default for community Sonar (no branch analysis). Set true on Dev/Enterprise/SonarCloud.
SONAR_USE_BRANCH="${SONAR_USE_BRANCH:-false}"

# ---------------------------
# CLI args
# ---------------------------
REPO_URL=""
BRANCH=""
TOOLS=""                   # csv: odc,trivy-fs,zap,npm-audit,bandit,sonar,semgrep,gitleaks
ZAP_MODE="${ZAP_MODE:-baseline}"   # baseline|full|openapi|auth
TARGET_URL=""
OPENAPI_SPEC=""
TARGET_IMAGE=""            # reserved
TARGET_PORT=""

# Auth-mode extras
ZAP_AUTH_MODE_VIA_AF="${ZAP_AUTH_MODE_VIA_AF:-form}"  # form (default)
ZAP_CONTEXT_NAME="${ZAP_CONTEXT_NAME:-icms}"
ZAP_LOGIN_URL=""
ZAP_AUTH_USER=""
ZAP_AUTH_PASS=""
ZAP_USER_FIELD="${ZAP_USER_FIELD:-username}"
ZAP_PASS_FIELD="${ZAP_PASS_FIELD:-password}"
ZAP_LOGGED_IN_REGEX="${ZAP_LOGGED_IN_REGEX:-Logout}"
ZAP_LOGGED_OUT_REGEX="${ZAP_LOGGED_OUT_REGEX:-Login}"
ZAP_EXCLUDE_REGEX="${ZAP_EXCLUDE_REGEX:-/logout|/signout}"
ZAP_USE_AJAX="${ZAP_USE_AJAX:-true}"
ZAP_POLICY="${ZAP_POLICY:-Default Policy}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-url) REPO_URL="$2"; shift 2 ;;
    --branch) BRANCH="$2"; shift 2 ;;
    --tools) TOOLS="$2"; shift 2 ;;
    --zap-mode) ZAP_MODE="$2"; shift 2 ;;
    --target-url) TARGET_URL="$2"; shift 2 ;;
    --openapi) OPENAPI_SPEC="$2"; shift 2 ;;
    --target-image) TARGET_IMAGE="$2"; shift 2 ;;
    --target-port) TARGET_PORT="$2"; shift 2 ;;

    --zap-login-url) ZAP_LOGIN_URL="$2"; shift 2 ;;
    --zap-auth-user) ZAP_AUTH_USER="$2"; shift 2 ;;
    --zap-auth-pass) ZAP_AUTH_PASS="$2"; shift 2 ;;
    --zap-user-field) ZAP_USER_FIELD="$2"; shift 2 ;;
    --zap-pass-field) ZAP_PASS_FIELD="$2"; shift 2 ;;
    --zap-logged-in) ZAP_LOGGED_IN_REGEX="$2"; shift 2 ;;
    --zap-logged-out) ZAP_LOGGED_OUT_REGEX="$2"; shift 2 ;;
    --zap-exclude) ZAP_EXCLUDE_REGEX="$2"; shift 2 ;;
    --zap-policy) ZAP_POLICY="$2"; shift 2 ;;
    --zap-spider-ajax) ZAP_USE_AJAX="$2"; shift 2 ;;

    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -n "$REPO_URL" ]] || { echo "❌ --repo-url is required"; exit 2; }

# ---------------------------
# Utilities (security-aware)
# ---------------------------
die() { echo "❌ $*" >&2; exit 1; }

redact_url() {
  # Mask token/user:pass in URLs
  printf '%s' "$1" | sed -E 's#(https?://)([^:@/]+):([^@/]+)@#\1\2:***@#g'
}

redact_file() {
  # redact_file <src> <dst>
  local src="$1" dst="$2"
  sed -E \
    -e 's/([Pp]assword: *").*(")/\1***\2/g' \
    -e 's/([Uu]sername: *").*(")/\1***\2/g' \
    -e 's/(loginRequestData: *").*(")/\1***\2/g' \
    -e 's/([Aa]uthorization: *Bearer +)[A-Za-z0-9\._-]+/\1***REDACTED***/gi' \
    -e 's/(Set-Cookie: [^=]+=)[^;]+/\1***REDACTED***/gi' \
    -e 's/(X-Api-Key: *)[A-Za-z0-9_-]+/\1***REDACTED***/gi' \
    -e 's/(password=)[^&"]+/\1***REDACTED***/gi' \
    -e 's/(oauth2:)[^@]+(@)/\1***\2/g' \
    "$src" > "$dst" || cp "$src" "$dst"
}

redact_log_and_attach() {
  # redact_log_and_attach <out_dir> <title> <message> <source_log> [extra attachments...]
  local out_dir="$1"; shift
  local title="$1"; shift
  local message="$1"; shift
  local src="$1"; shift
  local red="$SEC_REPORT_DIR/$(basename "$src" .log).redacted.log"
  sed -E \
    -e 's/(Authorization: *Bearer +)[A-Za-z0-9\._-]+/\1***REDACTED***/gi' \
    -e 's/(Set-Cookie: [^=]+=)[^;]+/\1***REDACTED***/gi' \
    -e 's/(X-Api-Key: *)[A-Za-z0-9_-]+/\1***REDACTED***/gi' \
    -e 's/(password=)[^&"]+/\1***REDACTED***/gi' \
    "$src" > "$red" || cp "$src" "$red"
  add_artifact_note "$out_dir" "$title" "$message" "$red" "$@"
}

need_npx() {
  if ! command -v npx >/dev/null 2>&1; then
    die "npx not found. Install Node.js or ensure dev deps (ts-node, typescript, uuid) are installed."
  fi
}

repo_name_from_url() { basename -s .git "$1"; }

uuid_make() {
  if command -v uuidgen >/dev/null 2>&1; then uuidgen; else echo "u$(date +%s%N)$RANDOM"; fi
}

install_local_allure() {
  local ver="$ALLURE_VERSION"
  local dest="$SEC_REPORT_DIR/_bin/allure-$ver"
  local tarball="allure-$ver.tgz"
  local url="https://repo1.maven.org/maven2/io/qameta/allure/allure-commandline/$ver/allure-commandline-$ver.tgz"

  if command -v allure >/dev/null 2>&1; then
    echo "🧩 Using system Allure CLI: $(command -v allure)"
    echo "allure"
    return 0
  fi

  if [[ -x "$dest/bin/allure" ]]; then
    echo "🧩 Using cached Allure CLI: $dest/bin/allure"
    echo "$dest/bin/allure"
    return 0
  fi

  echo "⬇️  Downloading Allure $ver …"
  mkdir -p "$SEC_REPORT_DIR/_bin"
  (curl -fsSL "$url" -o "$SEC_REPORT_DIR/_bin/$tarball" || wget -qO "$SEC_REPORT_DIR/_bin/$tarball" "$url") \
    || die "Failed to download Allure CLI"
  tar -xzf "$SEC_REPORT_DIR/_bin/$tarball" -C "$SEC_REPORT_DIR/_bin"
  mv "$SEC_REPORT_DIR/_bin/allure-$ver" "$dest"
  chmod +x "$dest/bin/allure"
  echo "$dest/bin/allure"
}

write_allure_context() {
  local out_dir="$1"
  local project="$2"
  local repo="$3"
  local scanners="$4"

  mkdir -p "$out_dir"
  cat > "$out_dir/environment.properties" <<EOF
project=$project
branch=${BRANCH:-}
repo=$repo
scanners=$scanners
target=${TARGET_URL:-}
EOF

  cat > "$out_dir/executor.json" <<'JSON'
{
  "name": "Local",
  "type": "pipeline",
  "buildName": "security-scan",
  "buildOrder": 1
}
JSON

  if [[ ! -f "$out_dir"/categories.json ]]; then
  cat > "$out_dir"/categories.json <<'JSON'
[
  { "name": "🔥 Critical", "matchedStatuses": ["failed","passed"],
    "messageRegex": "(?s).*\\[\\[SEVERITY:CRITICAL\\]\\].*",
    "traceRegex":   "(?s).*\\[\\[SEVERITY:CRITICAL\\]\\].*" },

  { "name": "⚡ High",     "matchedStatuses": ["failed","passed"],
    "messageRegex": "(?s).*\\[\\[SEVERITY:HIGH\\]\\].*",
    "traceRegex":   "(?s).*\\[\\[SEVERITY:HIGH\\]\\].*" },

  { "name": "🟠 Medium",   "matchedStatuses": ["failed","passed"],
    "messageRegex": "(?s).*\\[\\[SEVERITY:MEDIUM\\]\\].*",
    "traceRegex":   "(?s).*\\[\\[SEVERITY:MEDIUM\\]\\].*" },

  { "name": "🟡 Low",      "matchedStatuses": ["failed","passed"],
    "messageRegex": "(?s).*\\[\\[SEVERITY:LOW\\]\\].*",
    "traceRegex":   "(?s).*\\[\\[SEVERITY:LOW\\]\\].*" },

  { "name": "ℹ️ Unknown",  "matchedStatuses": ["failed","passed"],
    "messageRegex": "(?s).*\\[\\[SEVERITY:UNKNOWN\\]\\].*",
    "traceRegex":   "(?s).*\\[\\[SEVERITY:UNKNOWN\\]\\].*" },

  { "name": "Artifacts & Notes", "matchedStatuses": ["passed","failed"],
    "messageRegex": "(?s).*Artifacts.*" },

  { "name": "Other (no severity token)", "matchedStatuses": ["failed","passed"],
    "messageRegex": "(?s)^(?!.*\\[\\[SEVERITY:).*$" }
]
JSON
  fi
}

carry_history() {
  local results_dir="$1"
  local report_dir="$2"
  if [[ -d "$report_dir/history" ]]; then
    mkdir -p "$results_dir/history"
    cp -R "$report_dir/history/." "$results_dir/history/" || true
  fi
}

have_usable_allure() { allure --version >/dev/null 2>&1; }

generate_allure_report() {
  local src="$1" dest="$2"
  echo "🧩 Generating Allure report…"
  rm -rf "$dest"

  if have_usable_allure; then
    echo "🧩 Using system Allure CLI: $(command -v allure)"
    allure generate "$src" --clean -o "$dest"
  else
    echo "⬇️  Downloading Allure ${ALLURE_VERSION} …"
    install_local_allure >/dev/null
    "$SEC_REPORT_DIR/_bin/allure-$ALLURE_VERSION/bin/allure" generate "$src" --clean -o "$dest"
  fi

  echo "📊 Allure report generated → $dest"
}

note_result() {
  local out_dir="$1"; local name="$2"; local msg="$3"
  python3 - "$out_dir" "$name" "$msg" <<'PY'
import sys, os, json, time, uuid
out_dir, name, msg = sys.argv[1], sys.argv[2], sys.argv[3]
os.makedirs(out_dir, exist_ok=True)
u = str(uuid.uuid4()).upper()
now = int(time.time()*1000)
res = {
  "uuid": u,
  "historyId": u,
  "name": name,
  "fullName": name,
  "status": "passed",
  "labels": [{"name":"feature","value":"Meta"},{"name":"severity","value":"trivial"}],
  "statusDetails": {"message": msg},
  "start": now, "stop": now
}
with open(os.path.join(out_dir, f"{u}-result.json"), "w", encoding="utf-8") as f:
    json.dump(res, f, ensure_ascii=False)
PY
}

_mime_for() {
  local f_lc; f_lc="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case "$f_lc" in
    *.html|*.htm) echo "text/html" ;;
    *.json)       echo "application/json" ;;
    *.log|*.txt)  echo "text/plain" ;;
    *)            echo "application/octet-stream" ;;
  esac
}

add_artifact_note() {
  local out_dir="$1"; shift
  local title="$1";  shift
  local message="$1"; shift
  python3 - "$out_dir" "$title" "$message" "$@" <<'PY'
import sys, os, json, time, uuid, shutil, mimetypes
out_dir, title, message, *files = sys.argv[1:]
os.makedirs(out_dir, exist_ok=True)
u = str(uuid.uuid4()).upper()
atts=[]
for src in files:
    if os.path.isfile(src):
        base=os.path.basename(src)
        dest=os.path.join(out_dir, f"{u}-{base}")
        try: shutil.copy2(src, dest)
        except Exception: continue
        mime=mimetypes.guess_type(base)[0] or "application/octet-stream"
        atts.append({"name":base,"source":os.path.basename(dest),"type":mime})
now=int(time.time()*1000)
res={
  "uuid":u,"historyId":u,"name":title,"fullName":title,"status":"passed",
  "labels":[{"name":"feature","value":"Artifacts"},{"name":"severity","value":"trivial"}],
  "statusDetails":{"message":message},"attachments":atts,
  "start":now,"stop":now
}
with open(os.path.join(out_dir, f"{u}-result.json"), "w", encoding="utf-8") as f:
    json.dump(res, f, ensure_ascii=False)
PY
}

run_parser() {
  local in_json="$1"
  local tool="$2"
  local out_dir="$3"

  [[ -f "$in_json" ]] || die "Parser input missing: $in_json"
  mkdir -p "$out_dir"

  need_npx
  set +e
  npx ts-node "$ASVS_PARSER" --in "$in_json" --out "$out_dir" --tool "$tool"
  local ec=$?
  set -e
  if [[ $ec -ne 0 ]]; then
    add_artifact_note "$out_dir" \
      "Parser fallback: $tool" \
      "Parser could not convert $tool output. Raw artifact attached (redacted where applicable)." \
      "$in_json"
  fi
}

# ---------------------------
# Host path awareness (fix macOS nested Docker mounts)
# ---------------------------
if [[ -S /var/run/docker.sock && -n "${HOST_PWD:-}" ]]; then
  WORKSPACE_DIR="$HOST_PWD"
else
  WORKSPACE_DIR="$(pwd)"
fi

# Ensure ODC DB cache persists in project if nested Docker is used
if [[ -S /var/run/docker.sock && -n "${HOST_PWD:-}" && "${ODC_DATA_DIR}" = "$ODC_DATA_DIR_DEFAULT" ]]; then
  ODC_DATA_DIR="$WORKSPACE_DIR/.odc-cache"
fi

mkdir -p "$SEC_REPORT_DIR" "$ODC_DATA_DIR" "$TRIVY_CACHE_DIR" "$ALLURE_REPORT_ROOT"

# ---------------------------
# Clone / prepare repo (token safe)
# ---------------------------
REPO_URL_NORM="$REPO_URL"
if [[ "$REPO_URL" =~ ^https://gitlab\.com/ ]] && [[ -n "${GITLAB_TOKEN:-}" ]]; then
  REPO_URL_NORM="https://oauth2:${GITLAB_TOKEN}@${REPO_URL#https://}"
fi

LOCAL_DIR="$(repo_name_from_url "$REPO_URL")"
mkdir -p "$SEC_REPORT_DIR"

# SSH known_hosts (if needed)
if [[ "$REPO_URL" =~ ^git@ ]]; then
  mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"
  ssh-keyscan -H gitlab.com github.com 2>/dev/null >> "$HOME/.ssh/known_hosts" || true
  chmod 600 "$HOME/.ssh/known_hosts" || true
fi

if [[ ! -d "$LOCAL_DIR" ]]; then
  echo "📥 Cloning $(redact_url "$REPO_URL_NORM") ..."
  git clone "$REPO_URL_NORM" "$LOCAL_DIR"
fi
git -C "$LOCAL_DIR" remote set-url origin "$REPO_URL_NORM"

# pick default branch if not provided
if [[ -z "$BRANCH" ]]; then
  if HEAD_REF="$(git -C "$LOCAL_DIR" symbolic-ref -q refs/remotes/origin/HEAD 2>/dev/null)"; then
    BRANCH="${HEAD_REF#refs/remotes/origin/}"
  else
    BRANCH="master"
  fi
fi
echo "📂 Repo $LOCAL_DIR exists, pulling latest..."
(
  cd "$LOCAL_DIR"
  git fetch --all --prune
  git checkout "$BRANCH"
  git pull --ff-only || true
)

# mark safe if needed
git config --global --add safe.directory "$WORKSPACE_DIR/$LOCAL_DIR" 2>/dev/null || true

# npm install (unless skipped) — log kept local, NOT attached
if [[ "${SKIP_NPM_INSTALL:-}" != "true" ]]; then
  if [[ -f "$LOCAL_DIR/package.json" ]]; then
    echo "📦 npm install in $LOCAL_DIR ..."
    (cd "$LOCAL_DIR" && npm install --no-audit 2>npm-install.log) || \
    (echo "⚠️ retry --legacy-peer-deps" && cd "$LOCAL_DIR" && npm install --legacy-peer-deps --no-audit 2>>npm-install.log) || \
    (echo "⚠️ retry --force" && cd "$LOCAL_DIR" && npm install --force --no-audit 2>>npm-install.log) || \
    (echo "❗ npm install failed; continuing with best-effort." >&2)
    cp "$LOCAL_DIR/npm-install.log" "$SEC_REPORT_DIR/npm-install-${LOCAL_DIR}.log" 2>/dev/null || true
  fi
else
  echo "ℹ️ Skipping npm install (SKIP_NPM_INSTALL=true)."
fi

# Generate lockfiles (ignore scripts) to help ODC/Trivy when missing
if [[ -f "$LOCAL_DIR/package.json" && ! -f "$LOCAL_DIR/package-lock.json" ]]; then
  echo "🔧 Generating root package-lock.json (lockfile-only)…"
  (cd "$LOCAL_DIR" && npm install --package-lock-only --ignore-scripts || true)
fi
if [[ -f "$LOCAL_DIR/build/package.json" && ! -f "$LOCAL_DIR/build/package-lock.json" ]]; then
  echo "🔧 Generating build/ package-lock.json (lockfile-only)…"
  (npm --prefix "$LOCAL_DIR/build" install --package-lock-only --ignore-scripts || true)
fi

# Resolve Allure dirs
ALLURE_RESULTS_DIR="./allure-results/${LOCAL_DIR}"
ALLURE_REPORT_DIR="${ALLURE_REPORT_ROOT}/${LOCAL_DIR}"
mkdir -p "$ALLURE_RESULTS_DIR"
carry_history "$ALLURE_RESULTS_DIR" "$ALLURE_REPORT_DIR"

# ---------------------------
# ZAP AF plan builder (for auth)
# ---------------------------
write_zap_af_plan() {
  local plan="$1"
  local target_url="$2"
  local login_url="$3"
  local ctx_name="${4:-icms}"

  local auth_user="$5"
  local auth_pass="$6"
  local user_field="$7"
  local pass_field="$8"

  local logged_in_rx="${9:-Logout}"
  local logged_out_rx="${10:-Login}"
  local exclude_regex="${11:-}"
  local use_ajax="${12:-false}"
  local policy="${13:-Default Policy}"

  target_url="${target_url%/}/"

  local exclude_lines=""
  if [ -n "$exclude_regex" ]; then
    IFS='|' read -r -a _ex <<< "$exclude_regex"
    for p in "${!_ex[@]}"; do
      local s="${_ex[$p]}"
      s="${s#"${s%%[![:space:]]*}"}"; s="${s%"${s##*[![:space:]]}"}"
      [ -n "$s" ] && exclude_lines+="      - \"$s\"\n"
    done
  fi

  cat > "$plan" <<YAML
env:
  contexts:
    - name: $ctx_name
      urls:
        - "$target_url"
      excludePaths:
$(if [ -n "$exclude_lines" ]; then printf "%b" "$exclude_lines"; else echo "        # (none)"; fi)
      authentication:
        method: formBasedAuthentication
        parameters:
          loginUrl: "$login_url"
          loginRequestData: "${user_field}={%username%}&${pass_field}={%password%}"
        verification:
          method: contains
          loggedInRegex: "$logged_in_rx"
          loggedOutRegex: "$logged_out_rx"
      sessionManagement:
        method: cookie
      users:
        - name: ${ctx_name}-user
          credentials:
            username: "$auth_user"
            password: "$auth_pass"

jobs:
  - type: passiveScan-wait
    parameters:
      maxDuration: ${ZAP_BASELINE_TIME:-10}

  - type: spider
    parameters:
      context: $ctx_name
      user: ${ctx_name}-user
      url: "$target_url"
      maxDuration: ${ZAP_BASELINE_TIME:-10}

  - type: spiderAjax
    parameters:
      context: $ctx_name
      user: ${ctx_name}-user
      url: "$target_url"
      maxDuration: 5
      runOnlyIfModern: $use_ajax

  - type: activeScan
    parameters:
      context: $ctx_name
      user: ${ctx_name}-user
      policy: "$policy"

  - type: report
    parameters:
      template: traditional-html
      reportDir: /zap/wrk
      reportFile: zap-report.html
      reportTitle: Authenticated Scan

  - type: report
    parameters:
      template: traditional-json
      reportDir: /zap/wrk
      reportFile: zap-report.json
      reportTitle: Authenticated Scan (JSON)
YAML
  echo "   Plan written → $plan"
}

# ---------------------------
# Scanners
# ---------------------------
run_odc() {
  local REPORT_JSON="$SEC_REPORT_DIR/dependency-check-report.json"
  echo "🔍 Running Dependency-Check..."

  # Sanity check: make sure the cache really exists
  if [[ ! -f "$ODC_DATA_DIR/odc.mv.db" && ! -f "$ODC_DATA_DIR/dc.h2.db" ]]; then
    die "ODC cache not found in $ODC_DATA_DIR (expect odc.mv.db or dc.h2.db). Copy a working cache or allow updates."
  fi

  docker run --platform linux/amd64 --rm \
    -v "$WORKSPACE_DIR":/workspace \
    -w /workspace \
    -v "$ODC_DATA_DIR":/usr/share/dependency-check/data \
    -e "NVD_API_KEY=${NVD_API_KEY:-}" \
    -e "HTTP_PROXY=${HTTP_PROXY:-}" \
    -e "HTTPS_PROXY=${HTTPS_PROXY:-}" \
    -e "NO_PROXY=${NO_PROXY:-}" \
    "$ODC_IMAGE" \
      --project "$LOCAL_DIR" \
      --scan "/workspace/$LOCAL_DIR" \
      --format JSON \
      --out "/workspace/$SEC_REPORT_DIR/dependency-check-report.json" \
      --disableArchive \
      --noupdate \
      --nvdApiKey "${NVD_API_KEY:-}" \
      --nvdApiDelay "${NVD_API_DELAY:-2000}"

  [[ -f "$REPORT_JSON" ]] || die "ODC JSON not found: $REPORT_JSON"
  echo "✅ ODC report: $REPORT_JSON"

    # Optional: write a compact/minified copy for easy sharing
  if [[ "${MINIFY_ODC:-true}" == "true" ]]; then
    local ODC_MIN="$SEC_REPORT_DIR/dependency-check-report.min.json"
    if command -v node >/dev/null 2>&1; then
      node security-tests/tools/minify-odc.js "$REPORT_JSON" "$ODC_MIN" || true
      [[ -s "$ODC_MIN" ]] && echo "📦 ODC minified → $ODC_MIN"
    else
      echo "ℹ️ Node not found; skipping ODC minify."
    fi
  fi

  run_parser "$REPORT_JSON" dependency-check "$ALLURE_RESULTS_DIR"
}

run_trivy_fs() {
  local REPORT_JSON="$SEC_REPORT_DIR/trivy-fs-report.json"
  echo "🔎 Running Trivy FS scan..."
  docker run --rm \
    -v "$WORKSPACE_DIR":/work -w /work \
    -v "$TRIVY_CACHE_DIR":/root/.cache/ \
    "$TRIVY_IMAGE" fs \
      --scanners vuln,misconfig,secret \
      --format json \
      --output "$REPORT_JSON" \
      --skip-db-update \
      "$LOCAL_DIR"

  [[ -f "$REPORT_JSON" ]] || die "Trivy JSON not found: $REPORT_JSON"
  echo "✅ Trivy FS report: $REPORT_JSON"
  run_parser "$REPORT_JSON" trivy "$ALLURE_RESULTS_DIR"
}

run_zap() {
  local mode="$1"
  local ZAP_JSON="$SEC_REPORT_DIR/zap-report.json"
  local ZAP_HTML="$SEC_REPORT_DIR/zap-report.html"
  local ZAP_LOG="$SEC_REPORT_DIR/zap-console.log"

  echo "🕷️ Running ZAP ($mode) ..."
  set +e
  case "$mode" in
    baseline)
      [[ -n "$TARGET_URL" ]] || die "--target-url is required for ZAP baseline"
      docker run --rm \
        -v "$WORKSPACE_DIR":/zap/wrk:rw -w /zap/wrk \
        "$ZAP_IMAGE" zap-baseline.py \
          -t "$TARGET_URL" \
          -m "${ZAP_BASELINE_TIME:-10}" \
          -J "$ZAP_JSON" \
          -r "$ZAP_HTML" \
        2>&1 | tee "$ZAP_LOG"
      ;;
    full)
      [[ -n "$TARGET_URL" ]] || die "--target-url is required for ZAP full"
      docker run --rm \
        -v "$WORKSPACE_DIR":/zap/wrk:rw -w /zap/wrk \
        "$ZAP_IMAGE" zap-full-scan.py \
          -t "$TARGET_URL" \
          -m "${ZAP_FULL_TIME:-10}" \
          -J "$ZAP_JSON" \
          -r "$ZAP_HTML" \
        2>&1 | tee "$ZAP_LOG"
      ;;
    openapi)
      [[ -n "$OPENAPI_SPEC" ]] || die "--openapi is required for ZAP openapi mode"
      docker run --rm \
        -v "$WORKSPACE_DIR":/zap/wrk:rw -w /zap/wrk \
        "$ZAP_IMAGE" zap-api-scan.py \
          -t "$OPENAPI_SPEC" \
          -f openapi \
          -m "${ZAP_BASELINE_TIME:-10}" \
          -J "$ZAP_JSON" \
          -r "$ZAP_HTML" \
        2>&1 | tee "$ZAP_LOG"
      ;;
    *) die "Unknown ZAP mode: $mode" ;;
  esac
  local ec=${PIPESTATUS[0]}
  set -e

  if [[ -f "$ZAP_JSON" ]]; then
    run_parser "$ZAP_JSON" zap "$ALLURE_RESULTS_DIR"
  else
    note_result "$ALLURE_RESULTS_DIR" "ZAP: Skipped" "ZAP JSON not found – check volumes/paths."
  fi

  redact_log_and_attach "$ALLURE_RESULTS_DIR" \
    "ZAP ($mode) artifacts" \
    "ZAP exit=$ec • HTML, JSON, console log (redacted) attached." \
    "$ZAP_LOG" "$ZAP_HTML" "$ZAP_JSON"
}

run_zap_auth() {
  [[ -n "$TARGET_URL" ]] || die "--target-url is required for ZAP auth"
  [[ -n "$ZAP_LOGIN_URL" ]] || die "--zap-login-url is required for ZAP auth"
  [[ -n "$ZAP_AUTH_USER" && -n "$ZAP_AUTH_PASS" ]] || die "--zap-auth-user and --zap-auth-pass are required"

  local PLAN="$SEC_REPORT_DIR/zap-af-plan.yaml"
  local PLAN_REDACTED="$SEC_REPORT_DIR/zap-af-plan.redacted.yaml"
  local ZAP_JSON="$SEC_REPORT_DIR/zap-report.json"
  local ZAP_HTML="$SEC_REPORT_DIR/zap-report.html"
  local ZAP_LOG="$SEC_REPORT_DIR/zap-console.log"

  echo "🕷️ Running ZAP (authenticated AF) ..."
  write_zap_af_plan "$PLAN" \
    "$TARGET_URL" "$ZAP_LOGIN_URL" "${ZAP_CONTEXT_NAME:-icms}" \
    "$ZAP_AUTH_USER" "$ZAP_AUTH_PASS" \
    "$ZAP_USER_FIELD" "$ZAP_PASS_FIELD" \
    "${ZAP_LOGGED_IN_REGEX:-Logout}" "${ZAP_LOGGED_OUT_REGEX:-Login}" \
    "${ZAP_EXCLUDE_REGEX:-/logout}" "${ZAP_USE_AJAX:-true}" "${ZAP_POLICY:-Default Policy}"

  # Redact plan before attaching
  redact_file "$PLAN" "$PLAN_REDACTED"

  set +e
  docker run --rm \
    -v "$WORKSPACE_DIR":/zap/wrk:rw -w /zap/wrk \
    "$ZAP_IMAGE" zap.sh -cmd -autorun "/zap/wrk/${PLAN#./}" \
    2>&1 | tee "$ZAP_LOG"
  local ec=${PIPESTATUS[0]}
  set -e

  if [[ -f "$ZAP_JSON" ]]; then
    run_parser "$ZAP_JSON" zap "$ALLURE_RESULTS_DIR"
  else
    note_result "$ALLURE_RESULTS_DIR" "ZAP (auth): No JSON" "Check ZAP plan & console logs."
  fi

  redact_log_and_attach "$ALLURE_RESULTS_DIR" \
    "ZAP (auth) artifacts" \
    "Exit=$ec • Redacted plan, logs (redacted), and reports attached." \
    "$ZAP_LOG" "$PLAN_REDACTED" "$ZAP_HTML" "$ZAP_JSON"
}

run_npm_audit() {
  local REPORT_JSON="$SEC_REPORT_DIR/npm-audit.json"
  if [[ -f "$LOCAL_DIR/package.json" ]]; then
    echo "🔎 Running npm audit (json)..."
    set +e
    (cd "$LOCAL_DIR" && npm audit --json) > "$REPORT_JSON" 2>/dev/null
    set -e
    if [[ -s "$REPORT_JSON" ]]; then
      echo "✅ npm audit report: $REPORT_JSON"
      run_parser "$REPORT_JSON" npm-audit "$ALLURE_RESULTS_DIR"
    else
      note_result "$ALLURE_RESULTS_DIR" "npm-audit: Skipped" "Empty audit output."
    fi
  else
    note_result "$ALLURE_RESULTS_DIR" "npm-audit: Skipped" "No package.json found."
  fi
}

run_bandit() {
  echo "🐍 Running Bandit (dockerized)…"
  local REPORT_JSON="$SEC_REPORT_DIR/bandit-report.json"
  local EXCLUDES="node_modules,dist,build,coverage,e2e,examples,.next"

  if find "$LOCAL_DIR" -type f -name "*.py" \
       -not -path "*/node_modules/*" -not -path "*/dist/*" \
       -not -path "*/build/*" -not -path "*/coverage/*" \
       -not -path "*/e2e/*" -not -path "*/examples/*" | grep -q .; then

    docker run --rm \
      -v "$WORKSPACE_DIR":/work -w /work \
      python:3.12-slim bash -lc "
        pip install --no-cache-dir bandit >/dev/null 2>&1 && \
        bandit -r '$LOCAL_DIR' -x '$EXCLUDES' -f json -o '$REPORT_JSON' || true
      "

    if [[ -s "$REPORT_JSON" ]]; then
      echo "✅ Bandit report: $REPORT_JSON"
      run_parser "$REPORT_JSON" bandit "$ALLURE_RESULTS_DIR"
    else
      printf '{"results":[],"errors":[],"generated_at":"%s","metrics":{"_totals":{"SEVERITY.HIGH":0,"SEVERITY.MEDIUM":0,"SEVERITY.LOW":0,"SEVERITY.UNDEFINED":0,"CONFIDENCE.HIGH":0,"CONFIDENCE.MEDIUM":0,"CONFIDENCE.LOW":0,"CONFIDENCE.UNDEFINED":0}}}\n' "$(date -u +%FT%TZ)" > "$REPORT_JSON"
      add_artifact_note "$ALLURE_RESULTS_DIR" "Bandit stub" "No findings or output; stub written." "$REPORT_JSON"
    fi

  else
    printf '{"results":[],"errors":[],"generated_at":"%s","metrics":{"_totals":{"SEVERITY.HIGH":0,"SEVERITY.MEDIUM":0,"SEVERITY.LOW":0,"SEVERITY.UNDEFINED":0,"CONFIDENCE.HIGH":0,"CONFIDENCE.MEDIUM":0,"CONFIDENCE.LOW":0,"CONFIDENCE.UNDEFINED":0}}}\n' "$(date -u +%FT%TZ)" > "$REPORT_JSON"
    add_artifact_note "$ALLURE_RESULTS_DIR" "Bandit: Skipped" "No applicable Python files; stub attached." "$REPORT_JSON"
  fi
}

run_semgrep() {
  echo "🔎 Running Semgrep…"
  local REPORT_JSON="$SEC_REPORT_DIR/semgrep-report.json"
  local TIMEOUT="${SEMGREP_TIMEOUT:-300}"
  local EXCLUDES_FILE=".semgrepignore"
  local CFG_DIR="$WORKSPACE_DIR/security-tests/config"
  local CFG_ARGS=()
  local MOUNT_CFG=()

  # Prefer local semgrep.local.yml if present (merged with registry packs)
  if [[ -f "$CFG_DIR/semgrep.local.yml" ]]; then
    CFG_ARGS+=( --config /cfg/semgrep.local.yml )
    MOUNT_CFG=(-v "$CFG_DIR":/cfg:ro)
  fi

  # Merge registry packs
  IFS=',' read -r -a PACKS <<< "${SEMGREP_CONFIGS:-p/owasp-top-ten,p/nodejsscan}"
  for p in "${PACKS[@]}"; do
    [[ -n "$p" ]] && CFG_ARGS+=( --config "$p" )
  done

  set +e
  docker run --rm \
    -v "$WORKSPACE_DIR/$LOCAL_DIR":/src:ro \
    -v "$WORKSPACE_DIR/$SEC_REPORT_DIR":/out \
    -v "$WORKSPACE_DIR":/rootfs:ro \
    "${MOUNT_CFG[@]+"${MOUNT_CFG[@]}"}" \
    -w /src \
    "${SEMGREP_IMAGE:-semgrep/semgrep:latest}" \
    semgrep scan \
      "${CFG_ARGS[@]}" \
      --json --output /out/semgrep-report.json \
      --timeout "$TIMEOUT" 
  local ec=$?
  set -e

  if [[ -s "$REPORT_JSON" ]]; then
    echo "✅ Semgrep report: $REPORT_JSON"
    run_parser "$REPORT_JSON" semgrep "$ALLURE_RESULTS_DIR"
  else
    note_result "$ALLURE_RESULTS_DIR" "Semgrep: Skipped" "No output generated (exit=$ec)."
  fi
}

run_gitleaks() {
  echo "🔐 Running Gitleaks…"
  local REPORT_JSON="$SEC_REPORT_DIR/gitleaks-report.json"

  # Legacy boolean → mode
  _to_lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }
  if [[ "$(_to_lower "${GITLEAKS_HISTORY:-}")" == "true" ]]; then
    GITLEAKS_MODE="history"
  fi

  local -a CONFIG_ARG=()
  local -a CFG_MOUNT=()
  local -a MODE_FLAGS=(--no-git)
  local -a LOGOPTS=()

  # Config preference: env path > repo /security-tests/config/gitleaks.toml > repo .gitleaks.toml > none
  if [[ -n "${GITLEAKS_CONFIG:-}" && -f "$GITLEAKS_CONFIG" ]]; then
    CFG_MOUNT=(-v "$(cd "$(dirname "$GITLEAKS_CONFIG")"; pwd)":/cfg)
    CONFIG_ARG=(-c "/cfg/$(basename "$GITLEAKS_CONFIG")")
  elif [[ -f "$WORKSPACE_DIR/security-tests/config/gitleaks.toml" ]]; then
    CFG_MOUNT=(-v "$WORKSPACE_DIR/security-tests/config":/cfg)
    CONFIG_ARG=(-c "/cfg/gitleaks.toml")
  elif [[ -f "$LOCAL_DIR/.gitleaks.toml" ]]; then
    CFG_MOUNT=()
    CONFIG_ARG=(-c "/src/.gitleaks.toml")
  else
    CFG_MOUNT=()
    CONFIG_ARG=()
  fi

  # Mode flags
  case "$GITLEAKS_MODE" in
    dir)      MODE_FLAGS=(--no-git) ;;
    git)      MODE_FLAGS=() ;;
    history)  MODE_FLAGS=(); LOGOPTS=(--log-opts="--all ${GITLEAKS_LOG_OPTS}") ;;
    *)        MODE_FLAGS=(--no-git) ;;
  esac

  set +e
  rm -f "$REPORT_JSON"

  docker run --rm \
    -v "$WORKSPACE_DIR/$LOCAL_DIR":/src:ro \
    -v "$WORKSPACE_DIR/$SEC_REPORT_DIR":/out \
    ${CFG_MOUNT[@]+"${CFG_MOUNT[@]}"} \
    "${GITLEAKS_IMAGE:-zricethezav/gitleaks:latest}" detect \
      -s /src \
      ${MODE_FLAGS[@]+"${MODE_FLAGS[@]}"} \
      ${LOGOPTS[@]+"${LOGOPTS[@]}"} \
      --report-format json \
      --report-path /out/gitleaks-report.json \
      --exit-code 3 \
      ${CONFIG_ARG[@]+"${CONFIG_ARG[@]}"}
  local ec=$?
  set -e

  if [[ $ec -eq 0 && -s "$REPORT_JSON" ]]; then
    echo "✅ Gitleaks report: $REPORT_JSON"
    run_parser "$REPORT_JSON" gitleaks "$ALLURE_RESULTS_DIR"
  else
    note_result "$ALLURE_RESULTS_DIR" "Gitleaks: failed or empty" "Exit=$ec. Check gitleaks config/logs."
  fi

}

run_sonar() {
  if [[ -z "${SONAR_PROJECT_KEY:-}" ]]; then
    note_result "$ALLURE_RESULTS_DIR" "SonarScanner: Skipped" "Set SONAR_PROJECT_KEY, SONAR_HOST_URL, and SONAR_TOKEN/SONAR_LOGIN."
    return 0
  fi
  local LOGIN="${SONAR_LOGIN:-$SONAR_TOKEN}"
  if [[ -z "$LOGIN" ]]; then
    note_result "$ALLURE_RESULTS_DIR" "SonarScanner: Skipped" "Set SONAR_LOGIN or SONAR_TOKEN for authentication."
    return 0
  fi

  local EXCLUSIONS="${SONAR_EXCLUSIONS:-**/node_modules/**,**/dist/**,**/build/**,**/.next/**,**/coverage/**}"
  local QG_WAIT="${SONAR_QG_WAIT:-true}"
  local SCM_DISABLED="${SONAR_SCM_DISABLED:-true}"
  local SCAN_HEAP="${SONAR_SCANNER_OPTS:- -Xmx2048m}"
  local EXTRA="${SONAR_SCANNER_EXTRA:-}"
  # Export so helper functions see it
  export SONAR_USE_BRANCH

  mkdir -p "$SEC_REPORT_DIR"
  local SONAR_LOG="$SEC_REPORT_DIR/sonar-scanner.log"
  local SONAR_LOG_REDACT="$SEC_REPORT_DIR/sonar-scanner.redacted.log"
  local SONAR_JSON="$SEC_REPORT_DIR/sonar-issues.json"

  # URL for inside the scanner container
  local SQ_URL_SCANNER; SQ_URL_SCANNER="$(normalize_for_scanner "${SONAR_HOST_URL:-http://localhost:9000}")"

  echo "📡 SonarScanner → $SQ_URL_SCANNER • project=$SONAR_PROJECT_KEY • branch=${BRANCH:-<none>}"

  set +e
  docker run --rm --platform linux/amd64 \
    -e SONAR_HOST_URL="$SQ_URL_SCANNER" \
    -e SONAR_LOGIN="$LOGIN" \
    -e SONAR_SCANNER_OPTS="$SCAN_HEAP" \
    -v "$WORKSPACE_DIR":/usr/src -w /usr/src \
    sonarsource/sonar-scanner-cli:latest \
      -D"sonar.projectKey=$SONAR_PROJECT_KEY" \
      -D"sonar.projectName=${SONAR_PROJECT_NAME:-$SONAR_PROJECT_KEY}" \
      -D"sonar.sources=$LOCAL_DIR" \
      -D"sonar.exclusions=$EXCLUSIONS" \
      -D"sonar.sourceEncoding=UTF-8" \
      -D"sonar.qualitygate.wait=$QG_WAIT" \
      -D"sonar.scm.disabled=$SCM_DISABLED" \
      -D"sonar.login=$LOGIN" \
      $([[ "$SONAR_USE_BRANCH" == "true" && -n "$BRANCH" ]] && echo -D"sonar.branch.name=$BRANCH") \
      ${EXTRA:+$EXTRA} \
    2>&1 | tee "$SONAR_LOG"
  local ec=${PIPESTATUS[0]}
  set -e

  # Redact + attach scanner log
  sed -E 's/(token|login|password|Authorization)([^[:alnum:]]+)[^[:space:]]+/\1\2***REDACTED***/gi' \
    "$SONAR_LOG" > "$SONAR_LOG_REDACT" || cp "$SONAR_LOG" "$SONAR_LOG_REDACT"
  add_artifact_note "$ALLURE_RESULTS_DIR" "SonarScanner run" "SonarScanner exit=$ec • redacted console log attached." "$SONAR_LOG_REDACT"

  # URL for fetching from the HOST
    # URL for fetching from the HOST (never host.docker.internal)
  local HOST_URL_FETCH; HOST_URL_FETCH="$(normalize_for_host "${SONAR_HOST_URL:-http://localhost:9000}")"
  echo "DBG[sonar] host fetch base = $HOST_URL_FETCH"

  if wait_for_sonar_ce_and_fetch "$HOST_URL_FETCH" "$SONAR_PROJECT_KEY" "$SONAR_LOG" "$SONAR_JSON"; then
    :
  else
    echo "DBG[sonar] primary fetch failed — trying direct single-page fallback"
    # final fallback: one page w/ components
    local FALLBACK_URL="$HOST_URL_FETCH/api/issues/search?componentKeys=$SONAR_PROJECT_KEY&ps=500&statuses=OPEN,REOPENED,CONFIRMED"

    local code
    if [[ -n "${SONAR_TOKEN:-${SONAR_LOGIN:-}}" ]]; then
      code="$(curl -sS -w '%{http_code}' -u "${SONAR_TOKEN:-${SONAR_LOGIN:-}}:" -o "$SONAR_JSON" "$FALLBACK_URL")"
    else
      code="$(curl -sS -w '%{http_code}' -o "$SONAR_JSON" "$FALLBACK_URL")"
    fi
    echo "DBG[sonar] direct fallback HTTP $code, bytes=$(wc -c <"$SONAR_JSON" 2>/dev/null || echo 0)"
  fi

  if [[ -s "$SONAR_JSON" ]]; then
    if command -v jq >/dev/null 2>&1; then
      echo "DBG[sonar] issues=$(jq '.issues|length' "$SONAR_JSON") components=$(jq '.components|length' "$SONAR_JSON")"
    else
      echo "DBG[sonar] fetched $(wc -c <"$SONAR_JSON") bytes to $SONAR_JSON"
    fi
    add_artifact_note "$ALLURE_RESULTS_DIR" "Sonar issues JSON" "Raw issues/components payload attached." "$SONAR_JSON"
    export SONAR_HOST_URL="$HOST_URL_FETCH"
    # Use legacy-friendly alias so older parsers pick it up
run_parser "$SONAR_JSON" sonarqube "$ALLURE_RESULTS_DIR"
  # Call the parser first (preferred path)
  export SONAR_HOST_URL="$HOST_URL_FETCH"
  run_parser "$SONAR_JSON" sonar "$ALLURE_RESULTS_DIR"

  # --- Fallback: if the parser produced zero Sonar tests, emit minimal Allure results here ---
  # Count how many tests we have with feature=sonar
  local SONAR_TESTS_COUNT
  SONAR_TESTS_COUNT="$(
python3 - "$ALLURE_RESULTS_DIR" <<'PY'
import sys, os, json
out_dir = sys.argv[1]
count = 0
for f in os.listdir(out_dir):
    if not f.endswith("-result.json"): 
        continue
    try:
        j = json.load(open(os.path.join(out_dir,f), encoding="utf-8"))
    except Exception:
        continue
    labs = j.get("labels", [])
    if any(l.get("name")=="feature" and l.get("value")=="sonar" for l in labs):
        count += 1
print(count)
PY
  )"

  if [[ "${SONAR_TESTS_COUNT:-0}" -eq 0 && -s "$SONAR_JSON" ]]; then
    echo "DBG[sonar] parser emitted no tests — using inline fallback converter."
node - "$SONAR_JSON" "$ALLURE_RESULTS_DIR" "${SONAR_HOST_URL:-}" <<'NODE'
const fs = require('fs'); const path = require('path'); const crypto = require('crypto');
const inFile = process.argv[2], outDir = process.argv[3], host = (process.argv[4]||'').replace(/\/+$/,'');
const now = Date.now();
const j = JSON.parse(fs.readFileSync(inFile,'utf8'));
const comps = new Map();
for (const c of Array.isArray(j.components)? j.components: []) {
  const key = String(c.key||''); const nice = String(c.path||c.longName||c.name||key);
  if (key) comps.set(key, nice);
}
function sevMap(s){
  s = String(s||'').toUpperCase();
  if (s==='BLOCKER'||s==='CRITICAL') return 'critical';
  if (s==='MAJOR') return 'high';
  if (s==='MINOR') return 'medium';
  if (s==='INFO') return 'low';
  return 'unknown';
}
function allureSev(s){
  if (s==='critical') return 'critical';
  if (s==='high') return 'normal';
  if (s==='medium') return 'minor';
  return 'trivial';
}
function uuid(){ return crypto.randomUUID ? crypto.randomUUID() : (Date.now().toString(16)+Math.random().toString(16).slice(2)); }
const issues = Array.isArray(j.issues) ? j.issues : [];
let written = 0;
for (const it of issues) {
  const rule = String(it.rule||'');
  const sev  = sevMap(it.severity);
  const comp = String(it.component||'');
  const file = comps.get(comp) || (comp.includes(':') ? comp.split(':').pop() : comp) || 'file';
  const line = it.line ? `:${it.line}` : '';
  const msg  = String(it.message || rule || 'Sonar issue');
  const project = String(it.project||'');
  const key = String(it.key||'');
  const url = (host && project && key) ? `${host}/project/issues?open=${encodeURIComponent(key)}&id=${encodeURIComponent(project)}` : '';
  const sevTok = `[[SEVERITY:${(sev||'unknown').toUpperCase()}]]`;
  const res = {
    uuid: uuid(),
    historyId: uuid(),
    name: msg,
    fullName: `${file}${line} :: ${msg}`,
    status: (sev==='critical'||sev==='high') ? 'failed' : 'passed',
    statusDetails: {
      message: `${sevTok}\n${it.type||'ISSUE'} • ${rule}${line?` • line ${line.slice(1)}`:''}${url?`\n\n${url}`:''}`,
      trace: sevTok
    },
    labels: [
      {name:'feature', value:'sonar'},
      {name:'severity', value: allureSev(sev)},
      {name:'epic', value:'Static Application Security Testing'},
      {name:'tag', value:'Tool:sonar'},
      {name:'parentSuite', value:`Severity: ${(sev||'unknown').toUpperCase()}`},
    ],
    steps: [{
      name: `${(sev==='critical')?'🔥 CRITICAL':(sev==='high')?'⚡ HIGH':(sev==='medium')?'🟠 MEDIUM':'🟡 LOW'} ${msg}`,
      status: (sev==='critical'||sev==='high') ? 'failed' : 'passed',
      statusDetails: { message: `File: ${file}${line}\nRule: ${rule}\nStatus: ${it.status||'OPEN'}\nType: ${it.type||'ISSUE'}` }
    }],
    attachments: [],
    start: now, stop: now
  };
  fs.writeFileSync(path.join(outDir, `${uuid()}-result.json`), JSON.stringify(res, null, 2));
  written++;
}
console.log(`DBG[sonar] fallback wrote ${written} allure tests`);
NODE
  fi


  else
    # Write a stub so you can see *something* in Allure and inspect logs/URL
    echo '{"issues":[],"components":[]}' > "$SONAR_JSON"
    add_artifact_note "$ALLURE_RESULTS_DIR" \
      "Sonar: JSON not fetched" \
      "Fetch failed; attaching stub JSON and scanner logs for debugging. Verify token, URL, and project key." \
      "$SONAR_JSON" "$SONAR_LOG_REDACT"
  fi
}

fetch_sonar_issues_json() {
  local HOST="$1" PK="$2" OUT="$3" TOK="${4:-${SONAR_TOKEN:-${SONAR_LOGIN:-}}}"
  local BR="${BRANCH:-}"
  mkdir -p "$(dirname "$OUT")"

  # If jq is missing, fetch one page including components so the parser still works
  if ! command -v jq >/dev/null 2>&1; then
    local url="$HOST/api/issues/search?componentKeys=$PK&ps=500&statuses=OPEN,REOPENED,CONFIRMED"

    [[ -n "$BR" && "$SONAR_USE_BRANCH" == "true" ]] && url="$url&branch=$BR"
    echo "DBG[sonar] single-page fetch: $url"
    local code
    if [[ -n "$TOK" ]]; then
      code="$(curl -sS -w '%{http_code}' -u "$TOK:" -o "$OUT" "$url")"
    else
      code="$(curl -sS -w '%{http_code}' -o "$OUT" "$url")"
    fi
    echo "DBG[sonar] single-page HTTP $code, bytes=$(wc -c <"$OUT" 2>/dev/null || echo 0)"
    [[ "$code" == "200" && -s "$OUT" ]] || return 1
    return 0
  fi

  local tmpdir; tmpdir="$(mktemp -d)"
  local page=1 page_size=500 got=0
  printf '[]' >"$tmpdir/issues.json"
  printf '[]' >"$tmpdir/components.json"

  while :; do
    local u="$HOST/api/issues/search?componentKeys=$PK&ps=$page_size&p=$page&statuses=OPEN,REOPENED,CONFIRMED"

    [[ -n "$BR" && "$SONAR_USE_BRANCH" == "true" ]] && u="$u&branch=$BR"
    echo "DBG[sonar] page $page: $u"

    local pj="$tmpdir/p_${page}.json"
    local code
    if [[ -n "$TOK" ]]; then
      code="$(curl -sS -w '%{http_code}' -u "$TOK:" -o "$pj" "$u")"
    else
      code="$(curl -sS -w '%{http_code}' -o "$pj" "$u")"
    fi
    echo "DBG[sonar] page $page HTTP $code"
    [[ "$code" == "200" ]] || break

    local n; n="$(jq '.issues|length' "$pj")"
    (( n > 0 )) || break
    got=1

    jq -s '.[0] + .[1] | flatten' \
      "$tmpdir/issues.json" <(jq '.issues' "$pj") > "$tmpdir/issues.new" && mv "$tmpdir/issues.new" "$tmpdir/issues.json"

    jq -s '.[0] + .[1] | flatten | unique_by(.key)' \
      "$tmpdir/components.json" <(jq '.components // []' "$pj") > "$tmpdir/components.new" && mv "$tmpdir/components.new" "$tmpdir/components.json"

    ((page++))
  done

  if (( got == 0 )); then
    echo "DBG[sonar] paged fetch produced no pages — falling back to single-page."
    rm -rf "$tmpdir"
    # Fallback single page (same as no-jq path)
    local url="$HOST/api/issues/search?componentKeys=$PK&ps=500&statuses=OPEN,REOPENED,CONFIRMED"
    [[ -n "$BR" && "$SONAR_USE_BRANCH" == "true" ]] && url="$url&branch=$BR"
    local code
    if [[ -n "$TOK" ]]; then
      code="$(curl -sS -w '%{http_code}' -u "$TOK:" -o "$OUT" "$url")"
    else
      code="$(curl -sS -w '%{http_code}' -o "$OUT" "$url")"
    fi
    echo "DBG[sonar] fallback single-page HTTP $code, bytes=$(wc -c <"$OUT" 2>/dev/null || echo 0)"
    [[ "$code" == "200" && -s "$OUT" ]] || return 1
    return 0
  fi

  jq -n --argjson issues "$(cat "$tmpdir/issues.json")" \
        --argjson components "$(cat "$tmpdir/components.json")" \
        '{issues:$issues, components:$components}' > "$OUT"
  rm -rf "$tmpdir"
  echo "DBG[sonar] merged JSON bytes=$(wc -c <"$OUT" 2>/dev/null || echo 0)"
  [[ -s "$OUT" ]]
}

wait_for_sonar_ce_and_fetch() {
  local HOST="$1" PK="$2" LOG="$3" OUT="$4"
  local TOK="${SONAR_TOKEN:-${SONAR_LOGIN:-}}"
  local BR="${BRANCH:-}"

  mkdir -p "$(dirname "$OUT")"

  local CE_TASK_ID=""
  CE_TASK_ID="$(grep -Eo 'ceTaskId=[a-zA-Z0-9_]+' "$LOG" 2>/dev/null | head -n1 | cut -d= -f2 || true)"

  if [[ -n "$CE_TASK_ID" ]]; then
    local tries=60 status=""
    while (( tries-- > 0 )); do
      if [[ -n "$TOK" ]]; then
        status="$(curl -sS -u "$TOK:" "$HOST/api/ce/task?id=$CE_TASK_ID" | sed -n 's/.*"status":"\([^"]\+\)".*/\1/p')"
      else
        status="$(curl -sS "$HOST/api/ce/task?id=$CE_TASK_ID" | sed -n 's/.*"status":"\([^"]\+\)".*/\1/p')"
      fi
      echo "DBG[sonar] CE task $CE_TASK_ID status=$status"
      [[ "$status" == "SUCCESS" || "$status" == "FAILED" || "$status" == "CANCELED" ]] && break
      sleep 2
    done
  fi

  fetch_sonar_issues_json "$HOST" "$PK" "$OUT" "$TOK"
}

# ---------------------------
# Run requested tools
# ---------------------------
TOOLS="${TOOLS:-odc,trivy-fs}"  # default
IFS=',' read -r -a TOOL_ARR <<< "$TOOLS"

SCANNERS_SEEN=()

for t in "${TOOL_ARR[@]}"; do
  case "$t" in
    odc)        run_odc;        SCANNERS_SEEN+=("odc") ;;
    trivy-fs)   run_trivy_fs;   SCANNERS_SEEN+=("trivy-fs") ;;
    zap)
      if [[ "$ZAP_MODE" == "auth" ]]; then
        run_zap_auth
      else
        run_zap "$ZAP_MODE"
      fi
      SCANNERS_SEEN+=("zap")
      ;;
    npm-audit)  run_npm_audit;  SCANNERS_SEEN+=("npm-audit") ;;
    bandit)     run_bandit;     SCANNERS_SEEN+=("bandit") ;;
    semgrep)    run_semgrep;    SCANNERS_SEEN+=("semgrep") ;;
    gitleaks)   run_gitleaks;   SCANNERS_SEEN+=("gitleaks") ;;
    sonar)      run_sonar;      SCANNERS_SEEN+=("sonar") ;;
    *) echo "⚠️ Unknown tool: $t (skipped)";;
  esac
done

# ---------------------------
# Finalize + Allure
# ---------------------------
write_allure_context "$ALLURE_RESULTS_DIR" "$LOCAL_DIR" "$REPO_URL" "$(IFS=,; echo "${SCANNERS_SEEN[*]}")"

if [[ "$GENERATE_ALLURE" == "true" ]]; then
  generate_allure_report "$ALLURE_RESULTS_DIR" "$ALLURE_REPORT_DIR"
else
  echo "ℹ️ Skipping HTML generation (GENERATE_ALLURE=false)."
  echo "   To build locally:"
  echo "   allure generate \"$ALLURE_RESULTS_DIR\" --clean -o \"$ALLURE_REPORT_DIR\""
  echo "   allure open \"$ALLURE_REPORT_DIR\""
fi

echo "🎉 Complete."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Allure RESULTS : $ALLURE_RESULTS_DIR"
echo "Allure REPORT  : $ALLURE_REPORT_DIR"
echo
echo "Open the report locally:"
echo "  - If Allure CLI is installed:  allure open \"$ALLURE_REPORT_DIR\""
if command -v open >/dev/null 2>&1; then
  echo "  - Or just open the file:       open \"$ALLURE_REPORT_DIR/index.html\"   # macOS"
else
  echo "  - Or just open the file:       xdg-open \"$ALLURE_REPORT_DIR/index.html\" # Linux"
fi
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
