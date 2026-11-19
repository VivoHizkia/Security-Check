#!/usr/bin/env node
import { writeFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { runScan, SCANNERS } from '../src/index.js';
import { meetsThreshold, SEVERITIES } from '../src/findings.js';
import { renderConsole } from '../src/reporters/console.js';
import { renderHtml } from '../src/reporters/html.js';
import { renderSarif } from '../src/reporters/sarif.js';

const HELP = `
tameng — security self-scanner for your own web apps

Usage
  tameng [path] [options]

  tameng .                                   scan the current project
  tameng ./api --url https://api.myapp.com   scan code + the deployed site
  tameng --url https://myapp.com             only check the live site
  tameng . --html report.html --fail-on high
  tameng serve                               local dashboard: history, trends, attack surface

Options
  --url <url>          check headers, cookies, CORS and exposed files of a site you own
  --html <file>        write an HTML report
  --json <file>        write a JSON report ("-" for stdout)
  --sarif <file>       write SARIF 2.1.0 for GitHub code scanning ("-" for stdout)
  --only <list>        comma list: ${SCANNERS.join(', ')}
  --min <severity>     hide findings below this level in the terminal (default: info)
  --fail-on <sev>      exit 1 if a finding at/above this level exists (CI). Default: none
  --offline            skip the dependency lookup on api.osv.dev
  --no-probes          don't request /.env, /.git/config, … on --url
  --save               also store this scan in the dashboard history (~/.tameng)
  --port <n>           dashboard port for "tameng serve" (default 7777, 127.0.0.1 only)
  -q, --quiet          no terminal report
  -h, --help           show this help
  -v, --version        show version

Only scan systems you own or are authorised to test.
`;

async function main() {
  let args;
  try {
    args = parseArgs({
      allowPositionals: true,
      options: {
        url: { type: 'string' },
        html: { type: 'string' },
        json: { type: 'string' },
        sarif: { type: 'string' },
        only: { type: 'string' },
        min: { type: 'string', default: 'info' },
        'fail-on': { type: 'string', default: 'none' },
        offline: { type: 'boolean', default: false },
        'no-probes': { type: 'boolean', default: false },
        port: { type: 'string', default: '7777' },
        save: { type: 'boolean', default: false },
        quiet: { type: 'boolean', short: 'q', default: false },
        help: { type: 'boolean', short: 'h', default: false },
        version: { type: 'boolean', short: 'v', default: false },
      },
    });
  } catch (err) {
    console.error(`tameng: ${err.message}\nRun tameng --help for usage.`);
    return 2;
  }
  const { values: o, positionals } = args;

  if (o.help) { console.log(HELP); return 0; }
  if (o.version) { console.log('0.1.0'); return 0; }
  if (!SEVERITIES.includes(o.min)) { console.error(`tameng: --min must be one of ${SEVERITIES.join(', ')}`); return 2; }

  if (positionals[0] === 'serve') {
    const port = Number(o.port);
    if (!Number.isInteger(port) || port < 0 || port > 65535) { console.error('tameng: --port must be a number between 0 and 65535'); return 2; }
    const { createDashboard } = await import('../src/dashboard/server.js');
    const { homeDir } = await import('../src/history.js');
    const url = await createDashboard().listen(port);
    console.log(`\n  tameng dashboard → ${url}\n  history in ${homeDir()}\n  Ctrl+C to stop\n`);
    return new Promise(() => {}); // keep running until interrupted
  }

  const scanPath = positionals[0] ?? (o.url ? null : '.');
  if (o.json === '-' && o.sarif === '-') { console.error('tameng: only one of --json and --sarif can write to stdout'); return 2; }
  const jsonToStdout = o.json === '-' || o.sarif === '-';
  const interactive = process.stderr.isTTY && !o.quiet && !jsonToStdout;

  const report = await runScan({
    path: scanPath,
    url: o.url,
    only: o.only ? o.only.split(',').map((s) => s.trim()).filter(Boolean) : undefined,
    offline: o.offline,
    probes: !o['no-probes'],
    onStep: (step) => interactive && process.stderr.write(`\r\x1b[2K  … ${step}`),
  });
  if (interactive) process.stderr.write('\r\x1b[2K');

  if (!o.quiet && !jsonToStdout) console.log(renderConsole(report, { minSeverity: o.min }));
  const emit = async (target, label, data) => {
    const text = JSON.stringify(data, null, 2);
    if (target === '-') process.stdout.write(`${text}\n`);
    else { await writeFile(target, text); if (!o.quiet && !jsonToStdout) console.log(`  ${label} report → ${target}`); }
  };
  if (o.json) await emit(o.json, 'JSON', report);
  if (o.sarif) await emit(o.sarif, 'SARIF', renderSarif(report));
  if (o.html) {
    await writeFile(o.html, renderHtml(report));
    if (!o.quiet && !jsonToStdout) console.log(`  HTML report → ${o.html}\n`);
  }

  if (o.save) {
    if (!scanPath) { console.error('tameng: --save needs a project folder'); return 2; }
    const history = await import('../src/history.js');
    const project = await history.addProject({ path: scanPath, url: o.url });
    await history.saveScan(project.id, report);
    if (!o.quiet && !jsonToStdout) console.log(`  Saved to history → ${history.homeDir()}\n`);
  }

  return meetsThreshold(report.findings, o['fail-on']) ? 1 : 0;
}

main().then(
  (code) => { process.exitCode = code; },
  (err) => { console.error(`tameng: ${err.message}`); process.exitCode = 2; },
);
