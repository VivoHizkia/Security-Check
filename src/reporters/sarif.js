import { createHash } from 'node:crypto';

// SARIF 2.1.0 for GitHub code scanning (and any other SARIF viewer).
// https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

const LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
// GitHub reads properties["security-severity"] (CVSS-like 0–10) to label alerts critical/high/medium/low.
const SECURITY_SEVERITY = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0' };

/** "src/a.js:12" → { uri: "src/a.js", line: 12 }; URLs (live-site findings) have no file location. */
export function parseLocation(location) {
  if (!location || /^[a-z][a-z0-9+.-]*:\/\//i.test(location)) return null;
  const m = location.match(/^(.*?):(\d+)$/);
  return m ? { uri: m[1], line: Number(m[2]) } : { uri: location, line: null };
}

const fingerprint = (f, uri) => createHash('sha256').update(`${f.id}|${uri}|${f.title}`).digest('hex').slice(0, 32);

export function renderSarif(report) {
  const rules = new Map();
  const results = [];
  let skipped = 0;

  for (const f of report.findings) {
    const loc = parseLocation(f.location);
    if (!loc) { skipped++; continue; }
    if (!rules.has(f.id)) {
      rules.set(f.id, {
        id: f.id,
        name: f.id.replace(/(^|-)(\w)/g, (_, __, c) => c.toUpperCase()),
        shortDescription: { text: f.title },
        help: { text: f.fix || f.title, markdown: f.fix ? `**Fix:** ${f.fix}` : f.title },
        defaultConfiguration: { level: LEVEL[f.severity] },
        properties: {
          tags: ['security', f.scanner],
          ...(SECURITY_SEVERITY[f.severity] && { 'security-severity': SECURITY_SEVERITY[f.severity] }),
        },
      });
    }
    results.push({
      ruleId: f.id,
      ruleIndex: [...rules.keys()].indexOf(f.id),
      level: LEVEL[f.severity],
      message: { text: [f.title, f.detail, f.fix && `Fix: ${f.fix}`].filter(Boolean).join('\n') },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: encodeURI(loc.uri), uriBaseId: '%SRCROOT%' },
          ...(loc.line && { region: { startLine: loc.line } }),
        },
      }],
      partialFingerprints: { 'tameng/v1': fingerprint(f, loc.uri) },
      properties: { severity: f.severity, scanner: f.scanner },
    });
  }

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'tameng', version: report.meta.version, rules: [...rules.values()] } },
      results,
      properties: { score: report.summary.score, grade: report.summary.grade, liveSiteFindingsOmitted: skipped },
    }],
  };
}
