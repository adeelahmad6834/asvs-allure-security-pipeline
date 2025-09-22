# DevSecOps Security Scans Switchboard

Run a consistent set of security scanners against **any** Git repo (OSS or internal) and turn raw outputs into a polished **Allure** report with ASVS and OWASP tags, ownership hints, and CSV summaries.

## What this is
- A single entrypoint script: `security-tests/run_security_scans.sh`
- Runs scanners in Docker, parses their outputs with a **unified TypeScript parser** (`security-tests/parsers/asvs-unified-to-allure.ts`)
- Produces:
  - **Allure results** in `./allure-results/<repo>`
  - **Allure HTML** in `./allure-report/<repo>`
  - **CSV rollups** (severity, ASVS counts, top offenders)
  - **Raw artifacts** in `./security-reports/*` (with redactions where needed)

## Supported scanners
- **OWASP Dependency‑Check** (SCA)
- **Trivy FS** (vulns + misconfig + secrets)
- **OWASP ZAP** (baseline / full / OpenAPI / authenticated) — DAST
- **Semgrep** (multi‑lang SAST)
- **Gitleaks** (secrets in tree/history)
- **npm audit** (Node SCA)
- **Bandit** (Python SAST)
- **SonarQube / SonarScanner** (optional — issues → Allure)

## Safety & privacy defaults
- Credentials/URLs are redacted in logs attached to Allure.
- For ZAP, a redacted copy of the Automation Framework plan is attached; raw credentials are never written.
- Tip: If you expect sensitive page evidence, configure the parser to drop/replace `instance.evidence` before writing Allure steps.

---

## 1) Prerequisites
- **Docker** (required)
- **Node.js 18+** (for `npx ts-node` used by the parser)
- **Allure CLI** (optional)
  - If **not** installed and `GENERATE_ALLURE=true` (default), the script auto‑downloads Allure into `security-reports/_bin/` and uses that copy.
  - Manual install docs: https://docs.qameta.io/allure/#_installing_a_commandline

---

## 2) Quick start (NodeGoat demo)

### 2.1 Run NodeGoat locally (optional, for ZAP demo)
```bash
git clone https://github.com/OWASP/NodeGoat.git
cd NodeGoat
docker compose up -d --build
# wait until http://localhost:4000 responds with 200/302
```

### 2.2 Run the pipeline on NodeGoat
From this repo’s root:
```bash
cp .env.example .env.local   # then edit if needed

bash security-tests/run_security_scans.sh \
  --repo-url https://github.com/OWASP/NodeGoat.git \
  --tools odc,trivy-fs,zap,npm-audit,semgrep,gitleaks,sonar \
  --zap-mode baseline \
  --target-url "http://host.docker.internal:4000"
```

### 2.3 Open the Allure report
```bash
# If Allure CLI is installed:
allure open "./allure-report/NodeGoat"

# Or open the HTML directly:
open "./allure-report/NodeGoat/index.html"     # macOS
xdg-open "./allure-report/NodeGoat/index.html" # Linux
```

---

## 3) Usage

```bash
bash security-tests/run_security_scans.sh \
  --repo-url <URL> \
  [--branch main] \
  [--tools odc,trivy-fs[,zap,semgrep,gitleaks,npm-audit,bandit,sonar]] \
  [--zap-mode baseline|full|openapi|auth] \
  [--target-url http(s)://app.local] \
  [--openapi /abs/path/to/openapi.yaml]
```

### Examples
**Everything except ZAP & Sonar**
```bash
--tools odc,trivy-fs,npm-audit,bandit,semgrep,gitleaks
```

**ZAP baseline against a live target**
```bash
--tools zap --zap-mode baseline --target-url https://demo.testfire.net
```

**ZAP via OpenAPI spec**
```bash
--tools zap --zap-mode openapi --openapi /absolute/path/api.yaml
```

**ZAP authenticated (form)**
```bash
--tools zap --zap-mode auth \
  --target-url https://app.example.com \
  --zap-login-url https://app.example.com/login \
  --zap-auth-user "$ZAP_USER" \
  --zap-auth-pass "$ZAP_PASS" \
  --zap-user-field username \
  --zap-pass-field password
```

---

## 4) Environment variables

Create `.env.local` from the example and adjust as needed:

### General
- `SEC_REPORT_DIR` (default `./security-reports`)
- `ALLURE_REPORT_ROOT` (default `./allure-report`)
- `GENERATE_ALLURE` (`true|false`, default `true`)

### Allure
- `ALLURE_VERSION` (default `2.29.0`)

### Dependency‑Check
- `NVD_API_KEY` (recommended)
- `ODC_DATA_DIR` (default `$HOME/odc-data` or `./.odc-cache` if you mount one in CI)
- `ODC_IMAGE` (default `owasp/dependency-check:latest`)

### Trivy
- `TRIVY_CACHE_DIR` (default `$HOME/.cache/trivy`)
- `TRIVY_IMAGE` (default `aquasec/trivy:latest`)

### ZAP
- `ZAP_IMAGE` (default `ghcr.io/zaproxy/zaproxy:stable`)
- `ZAP_BASELINE_TIME` / `ZAP_FULL_TIME` (minutes, default `10`)
- `ZAP_POLICY` (default `Default Policy`)
- `ZAP_EXCLUDE_REGEX` (pipe‑separated)
- `ZAP_USE_AJAX` (`true|false`)

### Semgrep
- `SEMGREP_IMAGE` (default `semgrep/semgrep:latest`)
- `SEMGREP_CONFIGS` (default `p/owasp-top-ten,p/nodejsscan`)
- `SEMGREP_EXCLUDES` (default `node_modules,dist,build,coverage,.next,.git`)
- `SEMGREP_TIMEOUT` (seconds, `0` = no limit)

### Gitleaks
- `GITLEAKS_IMAGE` (default `zricethezav/gitleaks:latest`)
- `GITLEAKS_MODE` (`dir|git|history`, default `dir`)
- `GITLEAKS_CONFIG` (path to `.toml` rules)
- `GITLEAKS_LOG_OPTS` (e.g., `--since=2024-01-01`)

### Sonar (optional)
- `SONAR_HOST_URL` (e.g., `https://sonarcloud.io` or `http://localhost:9000`)
- `SONAR_PROJECT_KEY` (required)
- `SONAR_TOKEN` or `SONAR_LOGIN`
- `SONAR_USE_BRANCH` (keep `false` for Community Edition)
- `SONAR_EXCLUSIONS`, `SONAR_QG_WAIT`, `SONAR_SCANNER_OPTS`, `SONAR_SCANNER_EXTRA`

> Quick export pattern:
```bash
set -a; source ./.env.local; set +a
```

---

## 5) What the script does
1. Clones the target repo (prints **redacted** URL; never writes tokens).
2. Optionally runs a minimal `npm install` to improve SCA coverage (stderr not attached).
3. Runs selected scanners in Docker (multi‑arch image hints below).
4. Parses results into Allure with ASVS/OWASP tags and ownership hints.
5. Generates Allure HTML (skip with `GENERATE_ALLURE=false`).

**Multi‑arch hints (Apple Silicon friendly):**
- ODC → `linux/amd64` (emulated)
- Trivy → `linux/arm64`

---

## 6) Outputs
- **Allure results:** `./allure-results/<repo>`  
  - `categories.json` (severity buckets via `[[SEVERITY:...]]` tokens)  
  - `severity-summary.csv`, `asvs-summary.csv`, `top-offenders.csv`
- **Allure report:** `./allure-report/<repo>` (HTML)
- **Raw scanner outputs:** `./security-reports/*` (JSON/HTML, redacted logs)

---

## 7) Troubleshooting
- **ZAP can’t reach your localhost app** → use `--target-url http://host.docker.internal:PORT` (Dockerized ZAP vs host app).
- **Sonar 400s on issue fetch** → keep `SONAR_USE_BRANCH=false` (Community), verify token & project, test the API call with `curl`.
- **Dependency‑Check DB missing** → set `ODC_DATA_DIR` to a warm cache; avoids long DB downloads.
- **Allure binary not found** → the script will auto‑download `allure-<version>` under `security-reports/_bin/`.

---

## 8) Repository hygiene

**.gitignore**
```
# security outputs & reports
security-reports/
allure-report/
allure-results/
**/*.redacted.*
**/zap-af-plan.yaml
**/*.log
**/*.tgz

# node & tool caches
node_modules/
.odc-cache/

# IDE
.idea/
.vscode/
```

**env.example**
```
# Minimal, non‑secret placeholders
NVD_API_KEY=replace_me
SONAR_HOST_URL=https://sonarcloud.io
SONAR_PROJECT_KEY=your.project
SONAR_TOKEN=replace_me
GITLAB_TOKEN=replace_me
```

**Folder layout**
```
devsecops-switchboard/
├─ security-tests/
│  ├─ run_security_scans.sh
│  ├─ run_security_scans_timed.sh
│  └─ parsers/
│     └─ asvs-unified-to-allure.ts
├─ shared-asvs-map.json
├─ shared-owasp-map.json
├─ shared-owners-map.json
├─ README.md
├─ .gitignore
├─ SECURITY.md
├─ LICENSE
└─ env.example
```

**Publish to GitHub**
```bash
git init
git add .
git commit -m "Initial public release: DevSecOps security scans switchboard"
git branch -M main
git remote add origin https://github.com/<you>/devsecops-switchboard.git
git push -u origin main
```

---

## 9) Contributing
PRs welcome. Avoid sharing live credentials/endpoints in issues. See `SECURITY.md` for sensitive disclosures.

## 10) License
MIT (recommended). Include a `LICENSE` file in your repo.
