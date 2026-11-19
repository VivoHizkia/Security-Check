import { SEVERITIES } from '../findings.js';

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code) => (s) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : String(s));
const bold = c('1');
const dim = c('2');
const STYLE = {
  critical: c('1;97;41'),
  high: c('1;31'),
  medium: c('1;33'),
  low: c('1;36'),
  info: c('2'),
};
const GRADE = { A: c('1;32'), B: c('1;32'), C: c('1;33'), D: c('1;31'), F: c('1;97;41') };

export function renderConsole({ meta, summary, findings }, { minSeverity = 'info' } = {}) {
  const out = [];
  const visible = findings.filter((f) => SEVERITIES.indexOf(f.severity) <= SEVERITIES.indexOf(minSeverity));

  out.push('');
  out.push(`  ${bold('tameng')} ${dim(`v${meta.version} · security self-scan`)}`);
  if (meta.path) out.push(`  ${dim('project')} ${meta.path} ${dim(`(${meta.filesScanned} files)`)}`);
  if (meta.url) out.push(`  ${dim('url    ')} ${meta.url}`);
  out.push('');

  if (!visible.length) {
    out.push(`  ${c('1;32')('✓ No findings.')} ${dim('Nice.')}`);
  }

  let current = null;
  for (const f of visible) {
    if (f.severity !== current) {
      current = f.severity;
      out.push(`  ${STYLE[f.severity](` ${f.severity.toUpperCase()} `)}`);
    }
    out.push(`    ${bold(f.title)}  ${dim(`[${f.scanner}]`)}`);
    if (f.location) out.push(`      ${c('4')(f.location)}`);
    if (f.detail) out.push(`      ${dim(f.detail)}`);
    if (f.fix) out.push(`      ${c('32')('→')} ${f.fix}`);
  }

  const counts = SEVERITIES.filter((s) => summary.counts[s]).map((s) => STYLE[s](`${summary.counts[s]} ${s}`));
  out.push('');
  out.push(`  ${'─'.repeat(52)}`);
  out.push(`  Score ${GRADE[summary.grade](` ${summary.score}/100 · ${summary.grade} `)}   ${counts.join(dim(' · ')) || dim('0 findings')}`);
  out.push(`  ${dim(`done in ${(meta.durationMs / 1000).toFixed(1)}s`)}`);
  out.push('');
  return out.join('\n');
}
