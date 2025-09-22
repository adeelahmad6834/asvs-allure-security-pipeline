# ASVS Allure Security Pipeline

A unified DevSecOps pipeline that runs multiple security scanners, parses their findings, and exports results into **Allure reports** mapped against **OWASP ASVS v5**.  
Useful both for industrial pipelines (CI/CD) and reproducible academic work (e.g., thesis).  

---

## Supported Scanners

- **OWASP Dependency-Check** – SCA for Java/Node  
- **Trivy** – filesystem & container image scans  
- **OWASP ZAP** – baseline/full/auth DAST  
- **npm audit** – Node.js dependency audit  
- **Semgrep** – SAST with OWASP/CI rules  
- **Gitleaks** – secret scanning (tree/history)  
- **SonarQube** – code quality + vuln checks  
- **Bandit** – Python SAST (if Python code present)

---

## Safety & Privacy Defaults

- Credentials and URLs are redacted in logs.  
- ZAP Authentication is excluded (future work).  
- Gitleaks defaults to scanning **only the current tree** unless `GITLEAKS_HISTORY=true`.  
- Sonar runs against a **local container** (no external upload).  

---

## Repository Layout

```
security-tests/
  ├── run_security_scans.sh         # main entrypoint
  ├── run_security_scans.timer.sh   # wrapper for timings
  ├── parsers/asvs-unified-to-allure.ts
  ├── config/
  │    ├── gitleaks.toml
  │    └── semgrep-rules/
  └── ...
.env.example                         # copy → .env.local
```

---

## Environment Variables

Copy `.env.example` → `.env.local` and edit.  
Here are the key knobs (all optional, sensible defaults included):

### General
- `HOST_PWD` – workspace path (macOS Docker fix)  
- `GENERATE_ALLURE` – generate HTML automatically (`true`)  
- `ALLURE_VERSION` – default `2.29.0`  
- `ITERATIONS` – how many runs per tool for timing  

### Dependency-Check
- `NVD_API_KEY` – for faster CVE sync  
- `ODC_DATA_DIR` – cache dir  
- `ODC_PLATFORM` – container platform override  

### Trivy
- `TRIVY_CACHE_DIR` – cache dir  
- `TRIVY_PLATFORM` – container platform override  
- `TRIVY_SEVERITY` – default HIGH,CRITICAL  

### ZAP
- `ZAP_IMAGE` – default `ghcr.io/zaproxy/zaproxy:stable`  
- `ZAP_BASELINE_TIME` / `ZAP_FULL_TIME` – scan duration minutes  

### Gitleaks
- `GITLEAKS_IMAGE` – default `zricethezav/gitleaks:latest`  
- `GITLEAKS_HISTORY` – `true` = scan full history  
- `GITLEAKS_CONFIG` – config file path  
- `GITLEAKS_LOG_OPTS` – optional git log filters  

### SonarQube
- `SONAR_HOST_URL` – usually `http://host.docker.internal:9000`  
- `SONAR_TOKEN` – local auth token  
- `SONAR_SCANNER_EXTRA` – extra args  

---

## Outputs

- **Allure results** → `./allure-results/<repo>`  
- **Allure HTML report** → `./allure-report/<repo>`  
- **Scanner JSONs** → `./security-reports/`  
- **categories.json** → maps findings to ASVS controls  
- **timings.csv** → duration + exit codes (for reproducibility)

---

## Daily Flow (TL;DR)

1. **Warm caches once**  
   ```bash
   bash security-tests/run_security_scans.sh --warmup
   ```

2. **Run a staging snapshot**  
   ```bash
   git checkout -b thesis-freeze-1
   bash security-tests/run_security_scans.sh --repo-url <url> --tools odc,trivy-fs,...
   ```

3. **Run with timing**  
   ```bash
   bash security-tests/run_security_scans.timer.sh --repo-url <url> --tools odc,trivy-fs,zap,...
   ```

4. **View results**  
   ```bash
   allure open ./allure-report/<repo>
   ```

5. **Inspect timings**  
   ```bash
   column -t -s, timings.csv | less -S
   ```

---

## Staging & Freeze

- Tag stable points for reproducibility:
  ```bash
  git tag -a thesis-freeze-1 -m "Thesis pipeline freeze"
  git push origin thesis-freeze-1
  ```
- For later updates, create new tags (`thesis-freeze-2`, `thesis-final`).

---

## Troubleshooting

- If Allure report shows “Loading…” endlessly:  
  → Clear cache or restart system. Sometimes stale JS bundles cause this.  
- On macOS, add Homebrew’s path to `~/.zprofile`:  
  ```bash
  eval "$(/opt/homebrew/bin/brew shellenv)"
  ```  
- For Gitleaks “ambiguous argument” errors:  
  → Set `GITLEAKS_HISTORY=false` to scan only current tree.
