/**
 * asvs-unified-to-allure.ts
 *
 * Unified → Allure parser with ASVS labeling + ownership + summaries
 * + severity token in BOTH message & trace + token-based categories.
 * Now with compact rendering & full-list attachments for noisy items.
 *
 * Supports:
 *   - OWASP Dependency-Check (JSON)
 *   - Trivy (fs/image JSON)
 *   - OWASP ZAP (JSON from baseline/full/api-scan)
 *   - Semgrep (JSON)
 *   - Gitleaks (JSON / array / NDJSON)
 *   - npm audit (JSON)
 *
 * Usage:
 *   npx ts-node security-tests/parsers/asvs-unified-to-allure.ts \
 *     --in <report.json> --out <allure-results-dir> \
 *     [--tool dependency-check|trivy|zap|semgrep|gitleaks|npm-audit] \
 *     [--asvs-map shared-asvs-map.json] \
 *     [--owasp-map shared-owasp-map.json] \
 *     [--owners-map shared-owners-map.json] \
 *     [--dc-mode dependency|finding]
 *
 * Env (optional):
 *   MAX_ITEMS_IN_BODY=15   # how many items to show inline for aggregated tests
 *   MAX_REFS_IN_BODY=8     # max reference URLs to inline per item
 */

import * as fs from 'fs';
import * as path from 'path';
import { randomUUID } from 'crypto';

// === Severity rollup (cross-tool) ============================
type Severity = 'critical' | 'high' | 'medium' | 'low' | 'unknown';

type Rollup = {
  timestamp: string;
  totals: Record<Severity, number>;
  byTool: Record<string, Record<Severity, number>>;
};

function getSummaryPath(outDir: string): string {
  const forced = process.env.ROLLUP_PATH;
  return forced && forced.trim() ? forced : path.join(outDir, 'severity-rollup.json');
}
function emptyBuckets(): Record<Severity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
}
function loadRollup(p: string): Rollup {
  try {
    const j = JSON.parse(fs.readFileSync(p, 'utf8'));
    if (j && j.totals && j.byTool) return j as Rollup;
  } catch { }
  return { timestamp: new Date().toISOString(), totals: emptyBuckets(), byTool: {} };
}
function saveRollup(p: string, r: Rollup) {
  r.timestamp = new Date().toISOString();
  fs.writeFileSync(p, JSON.stringify(r, null, 2));
  // Also emit a CSV neighbor for convenience
  const csvPath = p.replace(/\.json$/i, '.csv');
  const hdr = 'tool,critical,high,medium,low,unknown,total';
  const lines: string[] = [hdr];

  const sum = { ...emptyBuckets() };
  (Object.keys(sum) as Severity[]).forEach(sev => { sum[sev] = r.totals[sev] || 0; });
  const sumTotal = Object.values(sum).reduce((a, b) => a + b, 0);
  lines.push(`ALL,${sum.critical},${sum.high},${sum.medium},${sum.low},${sum.unknown},${sumTotal}`);

  const tools = Object.keys(r.byTool).sort();
  for (const t of tools) {
    const b = r.byTool[t] || emptyBuckets();
    const total = (b.critical || 0) + (b.high || 0) + (b.medium || 0) + (b.low || 0) + (b.unknown || 0);
    lines.push(`${t},${b.critical || 0},${b.high || 0},${b.medium || 0},${b.low || 0},${b.unknown || 0},${total}`);
  }
  fs.writeFileSync(csvPath, lines.join('\n'));
}

// --------------------------- CLI ---------------------------
type Tool = 'dependency-check' | 'trivy' | 'zap' | 'semgrep' | 'gitleaks' | 'npm-audit' | 'sonar';
type DcMode = 'dependency' | 'finding';

type Cli = {
  inPath: string;
  outDir: string;
  tool?: Tool;
  asvsMapPath: string;
  owaspMapPath?: string;
  ownersMapPath?: string;
  dcMode: DcMode;
};

function parseCli(): Cli {
  const args = process.argv.slice(2);
  const get = (k: string) => {
    const i = args.indexOf(k);
    return i >= 0 ? args[i + 1] : undefined;
  };
  const inPath = get('--in') || get('-i');
  const outDir = get('--out') || get('-o');

  // normalize tool aliases and guard unknowns so autodetect can run
  const rawTool = (get('--tool') || '').toLowerCase();
  const alias: Record<string, Tool> = {
    'dependency-check': 'dependency-check',
    'dependencycheck': 'dependency-check',
    'trivy': 'trivy',
    'zap': 'zap',
    'semgrep': 'semgrep',
    'gitleaks': 'gitleaks',
    'npm-audit': 'npm-audit',
    'npmaudit': 'npm-audit',
    'npm': 'npm-audit',
    'sonar': 'sonar',
    'sonarqube': 'sonar',  // 👈 the important one
  };
  const tool = (alias[rawTool] as Tool | undefined);

  const asvsMapPath = get('--asvs-map') || 'shared-asvs-map.json';
  const owaspMapPath = get('--owasp-map') || 'shared-owasp-map.json';
  const ownersMapPath = get('--owners-map') || 'shared-owners-map.json';
  const dcMode = ((get('--dc-mode') as DcMode) || 'dependency');

  if (!inPath || !outDir) {
    console.error(
      'Usage: ts-node asvs-unified-to-allure.ts --in <report.json> --out <allure-results-dir> ' +
      '[--tool dependency-check|trivy|zap|semgrep|gitleaks|npm-audit|sonar] [--asvs-map file] [--owasp-map file] [--owners-map file] [--dc-mode dependency|finding]'
    );
    process.exit(2);
  }
  return { inPath, outDir, tool, asvsMapPath, owaspMapPath, ownersMapPath, dcMode };
}

const cli = parseCli();
fs.mkdirSync(cli.outDir, { recursive: true });

// --------------------------- Compact rendering knobs ---------------------------
const MAX_ITEMS_IN_BODY = Number(process.env.MAX_ITEMS_IN_BODY || 15);
const MAX_REFS_IN_BODY = Number(process.env.MAX_REFS_IN_BODY || 8);

// --------------------------- Fingerprinting (dedupe) ---------------------------
const seenFindings = new Set<string>();
function fingerprint(f: NormFinding): string {
  if (f.tool === 'dependency-check' || f.tool === 'trivy' || f.tool === 'npm-audit') {
    return `${f.tool}::${(f.name || '').toLowerCase()}::${(f.groupName || '').toLowerCase()}::${(f.ruleKey || '').toLowerCase()}`;
  }
  if (f.tool === 'semgrep' || f.tool === 'zap' || f.tool === 'gitleaks' || f.tool === 'sonar') {
    return `${f.tool}::${(f.ruleKey || '').toLowerCase()}::${(f.groupName || '').toLowerCase()}`;
  }
  return `${f.tool}::${(f.name || '').toLowerCase()}::${(f.ruleKey || '').toLowerCase()}`;
}


// --------------------------- Maps ---------------------------
type AsvsRef = { id: string | null; chapter: string; level: string[]; title: string };
type AsvsEntry = { asvs?: AsvsRef[]; epic?: string };

type AsvsMap = {
  ['dependency-check']?: Record<string, AsvsEntry>;
  ['trivy']?: Record<string, AsvsEntry>;
  ['zap']?: Record<string, AsvsEntry>;
  ['semgrep']?: Record<string, AsvsEntry>;
  ['gitleaks']?: Record<string, AsvsEntry>;
  ['npm-audit']?: Record<string, AsvsEntry>;
  ['sonar']?: Record<string, AsvsEntry>;
};
const asvsMap: AsvsMap | null = fs.existsSync(cli.asvsMapPath)
  ? JSON.parse(fs.readFileSync(cli.asvsMapPath, 'utf8'))
  : null;

type LegacyEntry = { owasp?: string; epic?: string };
type LegacyMap = {
  ['dependency-check']?: Record<string, LegacyEntry>;
  ['trivy']?: Record<string, LegacyEntry>;
  ['zap']?: Record<string, LegacyEntry>;
  ['semgrep']?: Record<string, LegacyEntry>;
  ['gitleaks']?: Record<string, LegacyEntry>;
  ['npm-audit']?: Record<string, LegacyEntry>;
  ['sonar']?: Record<string, LegacyEntry>;
};
const owaspMap: LegacyMap | null =
  cli.owaspMapPath && fs.existsSync(cli.owaspMapPath)
    ? JSON.parse(fs.readFileSync(cli.owaspMapPath, 'utf8'))
    : null;

type OwnersRule = {
  packageEquals?: string;
  packageIncludes?: string;
  targetIncludes?: string;
  type?: string;
  ruleId?: string;
  siteIncludes?: string;
  owner?: string;
  component?: string;
};
type OwnersMap = {
  ['dependency-check']?: OwnersRule[];
  ['trivy']?: OwnersRule[];
  ['zap']?: OwnersRule[];
  ['semgrep']?: OwnersRule[];
  ['gitleaks']?: OwnersRule[];
  ['npm-audit']?: OwnersRule[];
  ['sonar']?: OwnersRule[];
};
const ownersMap: OwnersMap | null =
  cli.ownersMapPath && fs.existsSync(cli.ownersMapPath)
    ? JSON.parse(fs.readFileSync(cli.ownersMapPath, 'utf8'))
    : null;

// --------------------------- Helpers ---------------------------
function normalizeSeverity(s: string): 'critical' | 'high' | 'medium' | 'low' | 'unknown' {
  const t = (s || '').toLowerCase();
  if (t === 'critical') return 'critical';
  if (t === 'high') return 'high';
  if (t === 'medium' || t === 'moderate') return 'medium';
  if (t === 'low' || t === 'info' || t === 'informational') return 'low';
  return 'unknown';
}
function mapSeverityToAllure(severity: string): 'critical' | 'normal' | 'minor' | 'trivial' {
  switch (normalizeSeverity(severity)) {
    case 'critical': return 'critical';
    case 'high': return 'normal';
    case 'medium': return 'minor';
    case 'low': default: return 'trivial';
  }
}
function badge(sev: string): string {
  switch (normalizeSeverity(sev)) {
    case 'critical': return '🔥 CRITICAL';
    case 'high': return '⚡ HIGH';
    case 'medium': return '🟠 MEDIUM';
    case 'low': default: return '🟡 LOW';
  }
}
function getHighestSeverity(severities: string[]): 'critical' | 'high' | 'medium' | 'low' | 'unknown' {
  const s = severities.map(normalizeSeverity);
  if (s.includes('critical')) return 'critical';
  if (s.includes('high')) return 'high';
  if (s.includes('medium')) return 'medium';
  if (s.includes('low')) return 'low';
  return 'unknown';
}
function trimLines(text: string, maxLines = 12): string {
  const lines = String(text || '').split('\n');
  return lines.length > maxLines ? lines.slice(0, maxLines).join('\n') + '\n…' : text;
}
function safeArray<T = unknown>(v: any): T[] { return Array.isArray(v) ? v : []; }
function uniq<T>(arr: T[]): T[] { return Array.from(new Set(arr)); }

// attachments helpers
function makeAttachment(name: string, type: string, content: string) {
  return { name, type, source: `${randomUUID()}-attachment`, __body: content };
}

// write test + any staged attachments
function writeAllureTest(outDir: string, test: any) {
  const fileName = `${randomUUID()}-result.json`;

  const atts = Array.isArray(test.__attachments) ? test.__attachments.slice() : [];
  delete test.__attachments;

  fs.writeFileSync(path.join(outDir, fileName), JSON.stringify(test, null, 2));

  for (const a of atts) {
    if (!a?.__body) continue;
    fs.writeFileSync(path.join(outDir, a.source), a.__body);
  }
}

function writeAllureRollupTest(outDir: string, r: Rollup) {
  const sum = r.totals;
  const msg =
    `Severity totals (cross-tool)\n` +
    `  • Critical: ${sum.critical}\n` +
    `  • High    : ${sum.high}\n` +
    `  • Medium  : ${sum.medium}\n` +
    `  • Low     : ${sum.low}\n` +
    `  • Unknown : ${sum.unknown}\n` +
    `Updated: ${r.timestamp}`;

  const csvPath = getSummaryPath(outDir).replace(/\.json$/i, '.csv');
  const jsonPath = getSummaryPath(outDir);

  // Stage attachments (if files exist)
  const atts: any[] = [];
  try { atts.push({ name: 'severity-rollup.csv', type: 'text/csv', source: path.basename(csvPath), __body: fs.readFileSync(csvPath, 'utf8') }); } catch { }
  try { atts.push({ name: 'severity-rollup.json', type: 'application/json', source: path.basename(jsonPath), __body: fs.readFileSync(jsonPath, 'utf8') }); } catch { }

  const test = {
    uuid: randomUUID(),
    historyId: randomUUID(),
    name: 'Severity Rollup Summary',
    fullName: 'Meta :: Severity Rollup Summary',
    status: 'passed',
    statusDetails: { message: msg },
    labels: [
      { name: 'feature', value: 'Meta' },
      { name: 'parentSuite', value: 'Severity: INFO' },
      { name: 'severity', value: 'trivial' }
    ],
    steps: [],
    attachments: atts.map(a => ({ name: a.name, source: a.source, type: a.type })),
    __attachments: atts,
    start: Date.now(),
    stop: Date.now()
  };
  writeAllureTest(outDir, test);
}

// --------------------------- Normalized model ---------------------------
type NormVuln = {
  id?: string;
  name: string;
  severity: string;
  score?: string | null;
  description?: string;
  references?: string[];
};
type NormFinding = {
  tool: Tool;
  ruleKey: string;
  name: string;
  description?: string;
  severity: string;
  score?: string | null;
  references?: string[];
  cwe?: string | number | null;
  groupName: string;
  vulns?: NormVuln[];
  // internal: raw list for attachments (optional)
  __occurrences?: any[];
};

// --------------------------- ASVS labeling ---------------------------
type AsvsLookupResult = {
  labels: Array<{ name: string; value: string }>;
  refs: AsvsRef[];
  epic?: string;
  legacyOwaspTag?: string;
};

function applyAsvsLabels(f: NormFinding): AsvsLookupResult {
  const out: AsvsLookupResult = { labels: [], refs: [] };
  const tool = f.tool;
  const section = asvsMap?.[tool];

  const candidates = uniq(
    [
      f.ruleKey,
      (f.ruleKey as any)?.toUpperCase?.(),
      (f.ruleKey as any)?.toLowerCase?.(),
      f.cwe ? `CWE-${f.cwe}` : undefined,
      f.cwe ? String(f.cwe) : undefined,
      tool === 'dependency-check' ? 'dependency' : undefined,
      tool === 'trivy' && f.ruleKey === 'VULNERABILITY' ? 'VULNERABILITY' : undefined,
      tool === 'trivy' && f.ruleKey === 'MISCONFIGURATION' ? 'MISCONFIGURATION' : undefined,
      tool === 'trivy' && f.ruleKey === 'SECRET' ? 'SECRET' : undefined,
      f.name,
      'default',
    ].filter(Boolean) as string[]
  );

  let entry: AsvsEntry | undefined;
  if (section) {
    for (const key of candidates) {
      if (section[key]) { entry = section[key]; break; }
    }
  }

  if (entry?.asvs?.length) {
    for (const ref of entry.asvs) {
      const tagVal = ref.id ? `ASVS:5.0.0/${ref.id}` : `ASVS:5.0.0/${ref.chapter.replace(/\s+/g, '-')}`;
      out.labels.push({ name: 'tag', value: tagVal });
      out.labels.push({ name: 'suite', value: `ASVS: ${ref.chapter}` });
      (ref.level || []).forEach((l) => out.labels.push({ name: 'level', value: l }));
      out.refs.push(ref);
    }
    if (entry.epic) out.epic = entry.epic;
    return out;
  }

  // legacy fallback
  let legacy: LegacyEntry | undefined;
  const legacySection = owaspMap?.[tool];
  if (legacySection) {
    for (const key of candidates) {
      if (legacySection[key]) { legacy = legacySection[key]; break; }
    }
  }
  if (legacy?.owasp) {
    out.legacyOwaspTag = `OWASP:${legacy.owasp}`;
    if (legacy.epic) out.epic = legacy.epic;
    out.labels.push({ name: 'tag', value: out.legacyOwaspTag });
  }
  return out;
}

// --------------------------- Ownership labeling ---------------------------
function assignOwnership(tool: Tool, finding: any): { owner?: string; component?: string } {
  if (!ownersMap) return {};
  const rules: OwnersRule[] = ownersMap[tool] || [];

  for (const r of rules) {
    if (tool === 'dependency-check') {
      const pkg = String(finding.name || finding.groupName || '');
      if (r.packageEquals && pkg === r.packageEquals) return { owner: r.owner, component: r.component };
      if (r.packageIncludes && pkg.toLowerCase().includes(String(r.packageIncludes).toLowerCase()))
        return { owner: r.owner, component: r.component };
    } else if (tool === 'trivy') {
      const t = String(finding.ruleKey || '');
      const target = String(finding.groupName || '');
      const typeOk = r.type ? t.toUpperCase() === r.type.toUpperCase() : true;
      const targetOk = r.targetIncludes
        ? target.toLowerCase().includes(String(r.targetIncludes).toLowerCase())
        : true;
      if (typeOk && targetOk) return { owner: r.owner, component: r.component };
    } else if (tool === 'zap') {
      const ruleId = String(finding.ruleKey || '');
      const site = String(finding.groupName || '');
      if (r.ruleId && r.ruleId === ruleId) return { owner: r.owner, component: r.component };
      if (r.siteIncludes && site.toLowerCase().includes(String(r.siteIncludes).toLowerCase()))
        return { owner: r.owner, component: r.component };
    } else if (tool === 'semgrep') {
      const ruleId = String(finding.ruleKey || '');
      const file = String(finding.groupName || '');
      if (r.ruleId && r.ruleId === ruleId) return { owner: r.owner, component: r.component };
      if (r.targetIncludes && file.toLowerCase().includes(String(r.targetIncludes).toLowerCase()))
        return { owner: r.owner, component: r.component };
    } else if (tool === 'gitleaks') {
      const ruleId = String(finding.ruleKey || '');
      const file = String(finding.groupName || '');
      if (r.ruleId && r.ruleId === ruleId) return { owner: r.owner, component: r.component };
      if (r.targetIncludes && file.toLowerCase().includes(String(r.targetIncludes).toLowerCase()))
        return { owner: r.owner, component: r.component };
    } else if (tool === 'npm-audit') {
      const pkg = String(finding.name || finding.groupName || '');
      if (r.packageEquals && pkg === r.packageEquals) return { owner: r.owner, component: r.component };
      if (r.packageIncludes && pkg.toLowerCase().includes(String(r.packageIncludes).toLowerCase()))
        return { owner: r.owner, component: r.component };
    } else if (tool === 'sonar') {
      const ruleId = String(finding.ruleKey || '');
      const file = String(finding.groupName || '');
      if (r.ruleId && r.ruleId === ruleId) return { owner: r.owner, component: r.component };
      if (r.targetIncludes && file.toLowerCase().includes(String(r.targetIncludes).toLowerCase()))
        return { owner: r.owner, component: r.component };
    }
  }
  return {};
}

// --------------------------- Auto-detect tool ---------------------------
function autodetectTool(obj: any): Tool | undefined {
  if (obj && Array.isArray(obj.dependencies)) return 'dependency-check';
  if (obj && (Array.isArray(obj.Results) || obj.ArtifactName)) return 'trivy';
  if (obj && (Array.isArray(obj.site) || Array.isArray(obj.alerts) || obj['@version'] || obj['report'])) return 'zap';
  if (obj && Array.isArray(obj.results) && obj.results.some((r: any) => r?.check_id || r?.extra?.severity)) return 'semgrep';
  if (obj && (Array.isArray((obj as any).leaks) || Array.isArray(obj) || (obj.__ndjson && Array.isArray(obj.items)))) return 'gitleaks';
  if (obj && (obj.auditReportVersion || obj.vulnerabilities || obj.advisories)) return 'npm-audit';
  if (obj && Array.isArray(obj.issues) && Array.isArray(obj.components)) return 'sonar';
  return undefined;
}

// --------------------------- Parsers ---------------------------
// Dependency-Check
function parseDependencyCheck(obj: any): NormFinding[] {
  const out: NormFinding[] = [];
  const deps = safeArray<any>(obj.dependencies);

  if (cli.dcMode === 'finding') {
    // one test per vulnerability (no grouping)
    for (const dep of deps) {
      if (!dep?.vulnerabilities?.length) continue;
      const depName = dep.fileName || dep.filePath || 'unknown-dependency';
      for (const v of dep.vulnerabilities) {
        const sev = normalizeSeverity(v.cvssv3?.baseSeverity || v.cvssv2?.severity || v.severity || 'unknown');
        const score = v.cvssv3?.baseScore?.toString() || v.cvssv2?.score?.toString() || null;
        const refs: string[] = [];
        const refObjs = v.references || v.reference || [];
        if (Array.isArray(refObjs)) for (const r of refObjs) refs.push(typeof r === 'string' ? r : (r?.url || ''));

        out.push({
          tool: 'dependency-check',
          ruleKey: sev.toUpperCase(),
          name: v.name || depName,
          description: v.description || '',
          severity: sev,
          score,
          references: refs.filter(Boolean),
          cwe: v.cwe || null,
          groupName: depName,
        });
      }
    }
    return out;
  }

  // default: per-dependency aggregation (1 test per dependency) + compact body
  for (const dep of deps) {
    if (!dep?.vulnerabilities?.length) continue;
    const depName = dep.fileName || dep.filePath || 'unknown-dependency';

    const vulns: NormVuln[] = [];
    const severities: string[] = [];
    const occurrences: { id?: string; severity: string; score?: string | null; refTop?: string; description?: string }[] = [];

    for (const v of dep.vulnerabilities) {
      const sev = normalizeSeverity(v.cvssv3?.baseSeverity || v.cvssv2?.severity || v.severity || 'unknown');
      severities.push(sev);
      const score = v.cvssv3?.baseScore?.toString() || v.cvssv2?.score?.toString() || null;
      const refs: string[] = [];
      const refObjs = v.references || v.reference || [];
      if (Array.isArray(refObjs)) for (const r of refObjs) refs.push(typeof r === 'string' ? r : (r?.url || ''));

      const refsTrim = refs.filter(Boolean);

      vulns.push({
        id: v.name,
        name: v.name || 'Vulnerability',
        severity: sev,
        score,
        description: v.description || '',
        references: refsTrim.slice(0, MAX_REFS_IN_BODY),
      });

      occurrences.push({
        id: v.name,
        severity: sev,
        score,
        refTop: refsTrim[0],
        description: v.description || '',
      });
    }

    const highest = getHighestSeverity(severities);
    const prettyName = `${depName} — ${occurrences.length} occurrences`;

    out.push({
      tool: 'dependency-check',
      ruleKey: highest.toUpperCase(),
      name: prettyName,
      description: `${occurrences.length} vulnerabilities detected in ${depName}.`,
      severity: highest,
      score: null,
      references: [],
      cwe: null,
      groupName: depName,
      vulns,
      __occurrences: occurrences,
    });
  }

  return out;
}

// Trivy (fs/image)
function parseTrivy(obj: any): NormFinding[] {
  const out: NormFinding[] = [];
  const results = safeArray<any>(obj.Results);

  for (const res of results) {
    const type: string = res.Type || res.Class || 'VULNERABILITY';
    const target = res.Target || obj.ArtifactName || 'artifact';

    for (const v of safeArray<any>(res.Vulnerabilities)) {
      const severity = normalizeSeverity(v.Severity || 'UNKNOWN');
      const score =
        (v.CVSS?.nvd?.V3Score || v.CVSS?.nvd?.V2Score || v.CVSS?.redhat?.V3Score || v.CVSS?.ghsa?.V3Score)?.toString() ||
        null;
      out.push({
        tool: 'trivy',
        ruleKey: (type || 'VULNERABILITY').toUpperCase(),
        name: v.PkgName || v.VulnerabilityID || 'dependency',
        description: v.Description || '',
        severity,
        score,
        references: safeArray<string>(v.References),
        cwe: (Array.isArray(v.CweIDs) && v.CweIDs[0]) || null,
        groupName: String(target),
      });
    }

    for (const m of safeArray<any>(res.Misconfigurations)) {
      const severity = normalizeSeverity(m.Severity || 'UNKNOWN');
      const desc = `${m.Message || ''}\n${m.Description || ''}`.trim();
      out.push({
        tool: 'trivy',
        ruleKey: 'MISCONFIGURATION',
        name: m.ID || m.Title || 'misconfiguration',
        description: desc,
        severity,
        score: null,
        references: safeArray<string>(m.References),
        cwe: null,
        groupName: String(target),
      });
    }

    for (const s of safeArray<any>(res.Secrets)) {
      const severity = normalizeSeverity(s.Severity || 'UNKNOWN');
      out.push({
        tool: 'trivy',
        ruleKey: 'SECRET',
        name: s.RuleID || s.Title || 'secret',
        description: s.Title || '',
        severity,
        score: null,
        references: [],
        cwe: null,
        groupName: String(target),
      });
    }
  }

  return out;
}

// ZAP
function parseZap(obj: any): NormFinding[] {
  const out: NormFinding[] = [];

  const normZapSeverity = (raw: any): string => {
    const s = String(raw ?? '').toLowerCase();
    if (s === '0' || s === 'informational' || s === 'info') return 'low';
    if (s === '1' || s === 'low') return 'low';
    if (s === '2' || s === 'medium') return 'medium';
    if (s === '3' || s === 'high') return 'high';
    return s || 'unknown';
  };

  const pushAlert = (a: any, group: string) => {
    if (!a) return;
    const pluginId = String(a.pluginId ?? a.pluginid ?? a.ruleId ?? a.id ?? '');
    const name = a.name ?? a.alert ?? (pluginId ? `ZAP-${pluginId}` : 'ZAP finding');
    const severity = normZapSeverity(a.risk ?? a.riskcode ?? a.severity);
    const desc = a.desc ?? a.description ?? '';
    const refs: string[] = [];

    if (a.reference) refs.push(String(a.reference));
    if (a.referenceLink) refs.push(String(a.referenceLink));
    if (Array.isArray(a.instances)) for (const inst of a.instances) if (inst?.uri) refs.push(String(inst.uri));

    out.push({
      tool: 'zap',
      ruleKey: pluginId || (a.cweid ? `CWE-${a.cweid}` : name),
      name,
      description: desc,
      severity: normalizeSeverity(severity),
      score: null,
      references: uniq(refs.filter(Boolean)).slice(0, 12),
      cwe: a.cweid ?? a.cweId ?? null,
      groupName: group,
    });
  };

  if (Array.isArray(obj.alerts)) for (const a of obj.alerts) pushAlert(a, 'ZAP');

  const sites = Array.isArray(obj.site) ? obj.site : obj.site ? [obj.site] : [];
  for (const site of sites) {
    const group = site?.name ?? site?.['@name'] ?? site?.url ?? 'ZAP Site';
    if (Array.isArray(site.alerts)) for (const a of site.alerts) pushAlert(a, group);
    if (Array.isArray(site.alertsItems)) for (const a of site.alertsItems) pushAlert(a, group);
  }
  return out;
}

// Semgrep
function parseSemgrep(obj: any): NormFinding[] {
  const out: NormFinding[] = [];
  const results = Array.isArray(obj.results) ? obj.results : [];
  const sevMap = (s: string) => {
    const t = (s || '').toLowerCase();
    if (t === 'error') return 'high';
    if (t === 'warning' || t === 'warn') return 'medium';
    if (t === 'info' || t === 'informational') return 'low';
    return 'unknown';
  };

  for (const r of results) {
    const ruleId = String(r.check_id || 'semgrep-rule');
    const file = String(r.path || r.abs_path || 'file');
    const extra = r.extra || {};
    const severity = sevMap(extra.severity || 'unknown');
    const desc = extra.message || '';
    const md = extra.metadata || {};
    const refs: string[] = [];

    if (Array.isArray(md.references)) refs.push(...md.references);
    if (md.reference) refs.push(String(md.reference));
    if (md.owasp) refs.push(String(md.owasp));
    if (md.cwe) {
      const c = typeof md.cwe === 'string' ? md.cwe : (md.cwe?.id ?? '');
      if (c) refs.push(String(c));
    }

    // Extract CWE: handle both string format "cwe-79" and object format {id: "79"}
    let cweNumber: string | null = null;
    if (md.cwe) {
      if (typeof md.cwe === 'string') {
        // Extract number from "cwe-79" or "CWE-79"
        const match = md.cwe.match(/cwe-?(\d+)/i);
        cweNumber = match ? match[1] : null;
      } else if (md.cwe?.id) {
        cweNumber = String(md.cwe.id);
      }
    }

    out.push({
      tool: 'semgrep',
      ruleKey: ruleId,
      name: ruleId,
      description: desc,
      severity,
      score: null,
      references: refs.filter(Boolean).slice(0, 12),
      cwe: cweNumber,
      groupName: file,
    });
  }
  return out;
}

// Gitleaks
function parseGitleaks(obj: any): NormFinding[] {
  let leaks: any[] = [];
  if (Array.isArray(obj)) leaks = obj;
  else if (obj && Array.isArray(obj.leaks)) leaks = obj.leaks;
  else if (obj && obj.__ndjson && Array.isArray(obj.items)) leaks = obj.items;

  const out: NormFinding[] = [];
  for (const l of leaks) {
    const ruleId = String(l.RuleID || l.rule || l.Description || 'gitleaks-rule');
    const file = String(l.File || l.file || l.Path || 'file');
    const where =
      (l.StartLine ? `:${l.StartLine}` : '') + (l.EndLine && l.EndLine !== l.StartLine ? `-${l.EndLine}` : '');
    const desc = l.Description || `Potential secret in ${file}${where}`;
    const severity = 'high'; // default

    out.push({
      tool: 'gitleaks',
      ruleKey: ruleId,
      name: ruleId,
      description: desc,
      severity,
      score: null,
      references: [],
      cwe: null,
      groupName: file,
    });
  }
  return out;
}

// npm audit
function parseNpmAudit(obj: any): NormFinding[] {
  const out: NormFinding[] = [];

  if (obj && obj.vulnerabilities && typeof obj.vulnerabilities === 'object') {
    for (const [pkg, v] of Object.entries<any>(obj.vulnerabilities)) {
      const sev = normalizeSeverity(v.severity || 'UNKNOWN');
      const via = Array.isArray(v.via) ? v.via : (v.via ? [v.via] : []);
      const refs: string[] = [];
      let name = pkg;

      const descParts: string[] = [];
      for (const item of via) {
        if (typeof item === 'string') {
          descParts.push(item);
        } else if (item && typeof item === 'object') {
          if (item.title) descParts.push(item.title);
          if (item.url) refs.push(String(item.url));
          if (item.name) name = `${pkg} (${item.name})`;
        }
      }

      out.push({
        tool: 'npm-audit',
        ruleKey: (sev || 'unknown').toUpperCase(),
        name,
        description: descParts.join('\n'),
        severity: sev,
        score: null,
        references: uniq(refs).slice(0, 10),
        cwe: null,
        groupName: pkg,
      });
    }
    return out;
  }

  if (obj && obj.advisories && typeof obj.advisories === 'object') {
    for (const adv of Object.values<any>(obj.advisories)) {
      const sev = normalizeSeverity(adv.severity || 'UNKNOWN');
      const refs = [adv.url].filter(Boolean);
      out.push({
        tool: 'npm-audit',
        ruleKey: (sev || 'unknown').toUpperCase(),
        name: adv.module_name || adv.title || 'npm-audit finding',
        description: adv.overview || adv.title || '',
        severity: sev,
        score: null,
        references: refs,
        cwe: Array.isArray(adv.cwe) ? adv.cwe[0] : adv.cwe || null,
        groupName: adv.module_name || 'package',
      });
    }
  }
  return out;
}

// ---------- Sonar knobs ----------
const SONAR_TYPES = new Set(
  (process.env.SONAR_TYPES || 'VULNERABILITY,SECURITY_HOTSPOT') // default: only security items
    .split(',')
    .map(s => s.trim().toUpperCase())
    .filter(Boolean)
);

// Treat CODE_SMELL/BUG as "quality" unless user opts in
const SONAR_INCLUDE_QUALITY = String(process.env.SONAR_INCLUDE_QUALITY || '0') === '1';

const SONAR_MIN_SEVERITY = (process.env.SONAR_MIN_SEVERITY || 'low').toLowerCase() as
  'unknown' | 'low' | 'medium' | 'high' | 'critical';

const SONAR_AGGREGATE = String(process.env.SONAR_AGGREGATE || '1') === '1';

const sevRank: Record<'unknown' | 'low' | 'medium' | 'high' | 'critical', number> = {
  unknown: 0, low: 1, medium: 2, high: 3, critical: 4,
};

function mapSonarSev(s: string): 'critical' | 'high' | 'medium' | 'low' | 'unknown' {
  const t = (s || '').toUpperCase();
  if (t === 'BLOCKER' || t === 'CRITICAL') return 'critical';
  if (t === 'MAJOR') return 'high';
  if (t === 'MINOR') return 'medium';
  if (t === 'INFO') return 'low';
  return 'unknown';
}

function sonarIssueUrl(issueKey: string, project: string): string {
  const host = (process.env.SONAR_HOST_URL || '').replace(/\/+$/, '');
  return (host && issueKey && project)
    ? `${host}/project/issues?open=${encodeURIComponent(issueKey)}&id=${encodeURIComponent(project)}`
    : '';
}


// ---------- SonarQube (api/issues/search payload) with filters + aggregation ----------
function parseSonar(obj: any): NormFinding[] {
  const out: NormFinding[] = [];

  // components: map component key -> readable path
  const comps = new Map<string, string>();
  for (const c of safeArray<any>(obj.components)) {
    if (c?.key) comps.set(String(c.key), String(c.path || c.longName || c.name || c.key));
  }

  // Normalize, then filter by type + min severity
  const normalized = safeArray<any>(obj.issues).map((it) => {
    const type = String(it.type || 'ISSUE').toUpperCase(); // CODE_SMELL | BUG | VULNERABILITY | SECURITY_HOTSPOT
    const sev = mapSonarSev(String(it.severity || ''));
    const component = String(it.component || '');
    const filePath = comps.get(component) || (component.includes(':') ? component.split(':').pop()! : component) || 'file';
    const lineNum = it.line ? Number(it.line) : undefined;
    const rule = String(it.rule || '');
    const message = String(it.message || rule || 'Sonar issue');
    const project = String(it.project || '');
    const key = String(it.key || '');
    const url = sonarIssueUrl(key, project);
    const tags = safeArray<string>(it.tags);

    return { type, sev, filePath, lineNum, rule, message, url, tags };
  });

  // Type gate
  const keepByType = (it: any) => {
    if (SONAR_TYPES.has(it.type)) return true; // VULNERABILITY / SECURITY_HOTSPOT
    if (SONAR_INCLUDE_QUALITY && (it.type === 'CODE_SMELL' || it.type === 'BUG')) return true;
    return false;
  };

  const filtered = normalized
    .filter(keepByType)
    .filter(it => sevRank[it.sev] >= sevRank[SONAR_MIN_SEVERITY]);

  if (!filtered.length) return out;

  if (!SONAR_AGGREGATE) {
    for (const it of filtered) {
      out.push({
        tool: 'sonar',
        ruleKey: it.rule || it.type,
        name: it.message,
        description:
          `${it.type} • ${it.rule}${it.lineNum ? ` • line ${it.lineNum}` : ''}` +
          (it.tags?.length ? `\nTags: ${it.tags.join(', ')}` : ''),
        severity: it.sev,
        score: null,
        references: it.url ? [it.url] : [],
        cwe: null,
        groupName: `${it.filePath}${it.lineNum ? `:${it.lineNum}` : ''}`,
      });
    }
    return out;
  }

  // Aggregate: group by (rule, file) to avoid spam
  const buckets = new Map<string, {
    filePath: string;
    type: string;
    rule: string;
    items: { line?: number; sev: 'critical' | 'high' | 'medium' | 'low' | 'unknown'; message: string; url: string; tags: string[] }[];
  }>();

  for (const it of filtered) {
    const id = `${it.rule}::${it.filePath}`;
    const b = buckets.get(id) || { filePath: it.filePath, type: it.type, rule: it.rule || it.type, items: [] };
    b.items.push({ line: it.lineNum, sev: it.sev, message: it.message, url: it.url, tags: it.tags });
    buckets.set(id, b);
  }

  for (const b of buckets.values()) {
    const highest = getHighestSeverity(b.items.map(i => i.sev));
    const total = b.items.length;

    // Build inline top N and attachments
    const head = b.items.slice(0, MAX_ITEMS_IN_BODY);
    const inline = head.map((x, i) => {
      const where = x.line ? ` (line ${x.line})` : '';
      const ref = x.url ? `\n   ref: ${x.url}` : '';
      const tags = x.tags?.length ? `\n   tags: ${x.tags.join(', ')}` : '';
      return `${i + 1}. ${x.message}${where} — ${normalizeSeverity(x.sev).toUpperCase()}${ref}${tags}`;
    });
    if (total > head.length) inline.push(`… and ${total - head.length} more (see attachment).`);

    const data = b.items.map(x => ({
      line: x.line ?? '',
      severity: x.sev,
      message: x.message,
      url: x.url,
      tags: x.tags,
    }));

    const csv = [
      'line,severity,message,url,tags',
      ...data.map(d => [
        d.line,
        d.severity,
        JSON.stringify(d.message || ''),
        JSON.stringify(d.url || ''),
        JSON.stringify((d.tags || []).join('|')),
      ].join(','))
    ].join('\n');

    const atts = [
      makeAttachment('sonar-occurrences.csv', 'text/csv', csv),
      makeAttachment('sonar-occurrences.json', 'application/json', JSON.stringify(data, null, 2)),
    ];

    // Feed the "vulns" path so the compact step renderer kicks in
    const vulns = head.map((x, i) => ({
      id: `occ-${i + 1}`,
      name: x.message + (x.line ? ` (line ${x.line})` : ''),
      severity: x.sev,
      score: null,
      description: '',
      references: x.url ? [x.url] : [],
    }));

    out.push({
      tool: 'sonar',
      ruleKey: b.rule,
      name: `${b.filePath} :: ${b.rule} — ${total} occurrence${total === 1 ? '' : 's'}`,
      description: `${b.type} • ${b.rule}`,
      severity: highest,
      score: null,
      references: uniq(b.items.map(x => x.url).filter(Boolean)).slice(0, MAX_REFS_IN_BODY),
      cwe: null,
      groupName: b.filePath,
      vulns,
      __occurrences: data,
      // let createAllureFromFinding turn these into actual attachments
      __attachments: atts
    } as any);
  }

  return out;
}

// --------------------------- Writers + Summaries ---------------------------
const asvsSummary: Record<string, { chapter: string; levels: Set<string>; count: number; tools: Set<string> }> = {};
function bumpAsvsSummary(refs: AsvsRef[], toolName: string) {
  for (const ref of refs) {
    const key = ref.id ?? ref.chapter;
    if (!asvsSummary[key]) {
      asvsSummary[key] = { chapter: ref.chapter, levels: new Set(ref.level || []), count: 0, tools: new Set() };
    }
    asvsSummary[key].count += 1;
    (ref.level || []).forEach((l) => asvsSummary[key].levels.add(l));
    asvsSummary[key].tools.add(toolName);
  }
}
type SevRow = { total: number; byTool: Record<string, number>; byOwner: Record<string, number> };
const sevSummary: Record<string, SevRow> = {};
type OffenderRow = {
  key: string; tool: string; type: string;
  critical: number; high: number; medium: number; low: number; total: number;
};
const offenders: Record<string, OffenderRow> = {};
function bumpSeverity(sev: string, tool: string, owner?: string) {
  const k = normalizeSeverity(sev);
  const row = (sevSummary[k] ||= { total: 0, byTool: {}, byOwner: {} });
  row.total++;
  row.byTool[tool] = (row.byTool[tool] || 0) + 1;
  const own = owner || 'Unowned';
  row.byOwner[own] = (row.byOwner[own] || 0) + 1;
}
function bumpOffender(f: NormFinding, sev: string) {
  let key: string, type: string;
  if (f.tool === 'dependency-check') { key = f.groupName; type = 'package'; }
  else if (f.tool === 'zap') { key = f.ruleKey; type = 'zap-rule'; }
  else {
    if (f.ruleKey === 'MISCONFIGURATION' || f.ruleKey === 'SECRET') { key = f.groupName; type = f.ruleKey.toLowerCase(); }
    else { key = f.name; type = 'package'; }
  }
  const id = `${f.tool}::${type}::${key}`;
  const row = (offenders[id] ||= { key, tool: f.tool, type, critical: 0, high: 0, medium: 0, low: 0, total: 0 });
  const n = normalizeSeverity(sev) as 'critical' | 'high' | 'medium' | 'low' | 'unknown';
  if (n === 'critical' || n === 'high' || n === 'medium' || n === 'low') (row as any)[n] += 1;
  row.total += 1;
}
function writeSeveritySummaryCSV(outDir: string) {
  const rows = ['severity,total,byTool,byOwner'];
  for (const [sev, row] of Object.entries(sevSummary)) {
    rows.push(`${sev},${row.total},${JSON.stringify(row.byTool)},${JSON.stringify(row.byOwner)}`);
  }
  fs.writeFileSync(path.join(outDir, 'severity-summary.csv'), rows.join('\n'));
}
function writeTopOffendersCSV(outDir: string) {
  const arr = Object.values(offenders).sort((a, b) => b.critical - a.critical || b.high - a.high || b.total - a.total);
  const rows = ['tool,type,key,critical,high,medium,low,total'];
  for (const r of arr) rows.push(`${r.tool},${r.type},${JSON.stringify(r.key)},${r.critical},${r.high},${r.medium},${r.low},${r.total}`);
  fs.writeFileSync(path.join(outDir, 'top-offenders.csv'), rows.join('\n'));
}

function mergeCurrentInvocationIntoRollup(outDir: string, toolName: string): Rollup {
  // Convert current run's in-memory summary into buckets
  const current = emptyBuckets();
  for (const [sevKey, row] of Object.entries(sevSummary)) {
    const sev = (sevKey as Severity);
    current[sev] = (current[sev] || 0) + (row.total || 0);
  }

  const rollPath = getSummaryPath(outDir);
  const r = loadRollup(rollPath);

  if (!r.byTool[toolName]) r.byTool[toolName] = emptyBuckets();

  (Object.keys(current) as Severity[]).forEach((sev) => {
    const n = current[sev] || 0;
    if (n > 0) {
      r.totals[sev] = (r.totals[sev] || 0) + n;
      r.byTool[toolName][sev] = (r.byTool[toolName][sev] || 0) + n;
    }
  });

  saveRollup(rollPath, r);
  return r;
}

// Token-based categories
function writeSeverityCategoriesJSON(outDir: string) {
  const tok = (s: string) => `(?s).*\\[\\[SEVERITY:${s}\\]\\].*`;
  const noTok = '(?s)^(?!.*\\[\\[SEVERITY:).*$';
  const categories = [
    { name: '🔥 Critical', matchedStatuses: ['failed', 'passed'], messageRegex: tok('CRITICAL'), traceRegex: tok('CRITICAL') },
    { name: '⚡ High', matchedStatuses: ['failed', 'passed'], messageRegex: tok('HIGH'), traceRegex: tok('HIGH') },
    { name: '🟠 Medium', matchedStatuses: ['failed', 'passed'], messageRegex: tok('MEDIUM'), traceRegex: tok('MEDIUM') },
    { name: '🟡 Low', matchedStatuses: ['failed', 'passed'], messageRegex: tok('LOW'), traceRegex: tok('LOW') },
    { name: 'ℹ️ Unknown', matchedStatuses: ['failed', 'passed'], messageRegex: tok('UNKNOWN'), traceRegex: tok('UNKNOWN') },
    { name: 'Artifacts & Notes', matchedStatuses: ['passed', 'failed'], messageRegex: '(?s).*Artifacts.*' },
    { name: 'Other (no severity token)', matchedStatuses: ['failed', 'passed'], messageRegex: noTok }
  ];
  fs.writeFileSync(path.join(outDir, 'categories.json'), JSON.stringify(categories, null, 2));
}

// --------------------------- Defaults ---------------------------
function defaultEpicForTool(f: NormFinding): string {
  switch (f.tool) {
    case 'dependency-check': return 'Insecure Dependency';
    case 'trivy':
      if (f.ruleKey === 'MISCONFIGURATION') return 'Security Misconfiguration';
      if (f.ruleKey === 'SECRET') return 'Secret Exposure';
      return 'Insecure Dependency';
    case 'zap': return 'Dynamic Application Security Testing';
    case 'semgrep': return 'Static Application Security Testing';
    case 'gitleaks': return 'Secret Exposure';
    case 'npm-audit': return 'Insecure Dependency';
    case 'sonar': return 'Static Application Security Testing';
    default: return 'Security Finding';
  }
}

// --------------------------- Test creation (compact) ---------------------------
function createAllureFromFinding(f: NormFinding) {
  type CsvRow = {
    id: string;
    severity: string;
    score: string;
    top_ref: string;
    description: string;
  };

  const { labels: asvsLabels, refs: asvsRefs, epic, legacyOwaspTag } = applyAsvsLabels(f);
  const own = assignOwnership(f.tool, f);

  const fp = fingerprint(f);
  if (seenFindings.has(fp)) return null;
  seenFindings.add(fp);

  const now = Date.now();

  let steps: any[] = [];
  let attachList: { name: string; type: string; source: string; __body: string }[] | null = null;

  if (Array.isArray(f.vulns) && f.vulns.length) {
    const total = f.vulns.length;
    const head = f.vulns.slice(0, MAX_ITEMS_IN_BODY);
    const more = total - head.length;

    const lines = head.map((v, i) => {
      const refs = (v.references || []).slice(0, MAX_REFS_IN_BODY);
      const hdr = `${i + 1}. ${v.name}${v.score ? ` (${v.score}/10)` : ''} — ${normalizeSeverity(v.severity).toUpperCase()}`;
      const desc = v.description ? `\n   ${trimLines(v.description, 4)}` : '';
      const r = refs.length ? `\n   refs:\n   - ${refs.join('\n   - ')}` : '';
      return hdr + desc + r;
    });
    if (more > 0) lines.push(`… and ${more} more (see attachment).`);

    steps = [{
      name: `${badge(getHighestSeverity(head.map(x => x.severity)))} ${f.name}`,
      status: head.some(v => ['critical', 'high'].includes(normalizeSeverity(v.severity))) ? 'failed' : 'passed',
      statusDetails: { message: lines.join('\n\n') }
    }];

    const occ = (f as any).__occurrences && (f as any).__occurrences.length ? (f as any).__occurrences : f.vulns;

    const data: CsvRow[] = occ.map((v: any): CsvRow => ({
      id: String(v.id || v.name || ''),
      severity: String(v.severity || ''),
      score: String(v.score || ''),
      top_ref: String((v.references && v.references[0]) || v.refTop || ''),
      description: String((v.description || '')).replace(/\s+/g, ' ').slice(0, 300)
    }));

    const csv =
      'id,severity,score,top_ref,description\n' +
      data
        .map((d: CsvRow) =>
          [
            JSON.stringify(d.id),
            d.severity,
            d.score,
            JSON.stringify(d.top_ref),
            JSON.stringify(d.description)
          ].join(',')
        )
        .join('\n');

    attachList = [
      makeAttachment('full-occurrence-list.csv', 'text/csv', csv),
      makeAttachment('full-occurrence-list.json', 'application/json', JSON.stringify(data, null, 2))
    ];
  } else {
    steps = [{
      name: `${badge(f.severity)} ${f.name}${f.score ? ` (${f.score}/10)` : ''}`,
      status: ['critical', 'high'].includes(normalizeSeverity(f.severity)) ? 'failed' : 'passed',
      statusDetails: {
        message:
          `Severity: ${normalizeSeverity(f.severity).toUpperCase()}${f.score ? ` (${f.score}/10)` : ''}\n\n` +
          (f.description ? trimLines(f.description, 18) + '\n\n' : '') +
          (f.references?.length ? `References:\n- ${f.references.slice(0, MAX_REFS_IN_BODY).join('\n- ')}` : '')
      }
    }];
  }

  const topStepSeverity =
    Array.isArray(f.vulns) && f.vulns.length
      ? getHighestSeverity(f.vulns.map((v) => v.severity))
      : normalizeSeverity(f.severity);

  const sevUP = topStepSeverity.toUpperCase();
  const severityToken = `[[SEVERITY:${sevUP}]]`;

  const test: any = {
    uuid: randomUUID(),
    historyId: randomUUID(),
    name: f.name,
    fullName: `${f.groupName} :: ${f.name}`,
    status: steps.some((s) => s.status === 'failed') ? 'failed' : 'passed',
    statusDetails: {
      message:
        `${severityToken}\n` +
        (asvsRefs.length
          ? `ASVS: ${asvsRefs
            .map((r) => (r.id ?? r.chapter) + (r.level?.length ? ` [${r.level.join(',')}]` : ''))
            .join('; ')}\n\n`
          : '') +
        (f.description || ''),
      trace: severityToken,
    },
    labels: [
      { name: 'feature', value: f.tool },
      { name: 'severity', value: mapSeverityToAllure(topStepSeverity) },
      { name: 'epic', value: epic || defaultEpicForTool(f) },
      { name: 'tag', value: `Tool:${f.tool}` },
      ...(legacyOwaspTag ? [{ name: 'tag', value: legacyOwaspTag }] : []),
      ...asvsLabels,
      ...(own.owner ? [{ name: 'owner', value: own.owner }] : []),
      ...(own.component ? [{ name: 'component', value: own.component }] : []),
      { name: 'parentSuite', value: `Severity: ${sevUP}` },
      ...(f.tool === 'dependency-check' ? [{ name: 'package', value: f.groupName }] : []),
    ],
    steps,
    attachments: [],
    start: now,
    stop: now + 600
  };

  const staged = ([] as { name: string; type: string; source: string; __body: string }[])
    .concat(attachList || [])
    .concat(((f as any).__attachments || []) as any[]);

  if (staged.length) {
    test.attachments = staged.map(a => ({ name: a.name, source: a.source, type: a.type }));
    test.__attachments = staged;
  }

  bumpAsvsSummary(asvsRefs, f.tool);
  bumpSeverity(topStepSeverity, f.tool, own.owner);
  bumpOffender(f, topStepSeverity);

  return test;
}

// --------------------------- Main ---------------------------
function main() {
  const raw = fs.readFileSync(cli.inPath, 'utf8');
  let obj: any;
  try {
    obj = JSON.parse(raw);
  } catch {
    // minimal NDJSON fallback (e.g., some gitleaks outputs)
    const lines = raw.split(/\r?\n/).filter(Boolean);
    const nd: any[] = [];
    let ok = true;
    for (const line of lines) { try { nd.push(JSON.parse(line)); } catch { ok = false; break; } }
    if (ok) obj = { __ndjson: true, items: nd };
    else {
      console.error(`❌ Failed to parse JSON: ${cli.inPath}`);
      process.exit(1);
    }
  }

  let tool: Tool | undefined = cli.tool || autodetectTool(obj);
  if (!tool) {
    console.error('❌ Could not auto-detect tool. Pass --tool dependency-check|trivy|zap|semgrep|gitleaks|npm-audit');
    process.exit(2);
  }

  let findings: NormFinding[] = [];
  if (tool === 'dependency-check') findings = parseDependencyCheck(obj);
  else if (tool === 'trivy') findings = parseTrivy(obj);
  else if (tool === 'zap') findings = parseZap(obj);
  else if (tool === 'semgrep') findings = parseSemgrep(obj);
  else if (tool === 'gitleaks') findings = parseGitleaks(obj);
  else if (tool === 'npm-audit') findings = parseNpmAudit(obj);
  else if (tool === 'sonar') findings = parseSonar(obj);

  if (!findings.length) {
    console.log('ℹ️ No findings detected to convert.');
    writeSeverityCategoriesJSON(cli.outDir);

    // NEW: still register this tool with zeroes so it shows up in rollup
    try {
      const toolName = (cli.tool || autodetectTool(obj) || 'unknown-tool') as string;
      // sevSummary is empty here (all zeros), which is fine—we want to seed the tool
      const r = mergeCurrentInvocationIntoRollup(cli.outDir, toolName);
      console.log(
        `🧮 Rollup so far → C:${r.totals.critical} H:${r.totals.high} M:${r.totals.medium} L:${r.totals.low} U:${r.totals.unknown}`
      );
      // Optional: also show the rollup card in Allure (comment out if you don't want it)
      writeAllureRollupTest(cli.outDir, r);
    } catch (e) {
      console.warn('⚠️ Failed to update severity rollup on empty run:', (e as Error)?.message || e);
    }

    return;
  }

  let written = 0;
  for (const f of findings) {
    const test = createAllureFromFinding(f);
    if (test) { writeAllureTest(cli.outDir, test); written++; }
  }

  writeSeverityCategoriesJSON(cli.outDir);

  if (Object.keys(asvsSummary).length) {
    const rows = ['control,chapter,levels,count,tools'];
    for (const [k, v] of Object.entries(asvsSummary)) {
      rows.push(
        `${JSON.stringify(k)},${JSON.stringify(v.chapter)},${JSON.stringify(Array.from(v.levels))},${v.count},${JSON.stringify(Array.from(v.tools))}`
      );
    }
    fs.writeFileSync(path.join(cli.outDir, 'asvs-summary.csv'), rows.join('\n'));
  }

  writeSeveritySummaryCSV(cli.outDir);
  writeTopOffendersCSV(cli.outDir);

  console.log(`✅ Parsed ${written} findings from ${tool} → ${path.resolve(cli.outDir)}`);

  // Persist a cross-tool severity rollup and (optionally) show it in Allure
  try {
    const r = mergeCurrentInvocationIntoRollup(cli.outDir, tool);
    console.log(`🧮 Rollup so far → C:${r.totals.critical} H:${r.totals.high} M:${r.totals.medium} L:${r.totals.low} U:${r.totals.unknown} (see ${path.relative(process.cwd(), getSummaryPath(cli.outDir))})`);
    // Comment out the next line if you DON'T want a rollup card visible in Allure:
    writeAllureRollupTest(cli.outDir, r);
  } catch (e) {
    console.warn('⚠️ Failed to update severity rollup:', (e as Error)?.message || e);
  }

}

main();
