export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

export const SEVERITY_RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

const PENALTY = { critical: 25, high: 10, medium: 4, low: 1, info: 0 };

export function finding({ id, scanner, severity, title, detail = '', location = '', fix = '' }) {
  if (!SEVERITY_RANK[severity]) throw new Error(`Unknown severity "${severity}" for ${id}`);
  return { id, scanner, severity, title, detail, location, fix };
}

export function summarize(findings) {
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  let penalty = 0;
  for (const f of findings) {
    counts[f.severity] += 1;
    penalty += PENALTY[f.severity];
  }
  const score = Math.max(0, 100 - penalty);
  const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
  return { counts, score, grade, total: findings.length };
}

export function sortFindings(findings) {
  return [...findings].sort(
    (a, b) =>
      SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
      a.scanner.localeCompare(b.scanner) ||
      a.location.localeCompare(b.location, undefined, { numeric: true }),
  );
}

export function meetsThreshold(findings, threshold) {
  if (!threshold || threshold === 'none') return false;
  const min = SEVERITY_RANK[threshold];
  if (!min) throw new Error(`--fail-on must be one of: ${SEVERITIES.join(', ')}, none`);
  return findings.some((f) => SEVERITY_RANK[f.severity] >= min);
}
