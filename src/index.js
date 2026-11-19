import path from 'node:path';
import { collectFiles } from './files.js';
import { sortFindings, summarize } from './findings.js';
import { scanSecrets } from './scanners/secrets.js';
import { scanConfig } from './scanners/config.js';
import { scanCode } from './scanners/code.js';
import { scanDeps } from './scanners/deps.js';
import { scanUrl } from './scanners/headers.js';
import { scanLaravel } from './scanners/laravel.js';
import { collectSurface } from './surface.js';

export const SCANNERS = ['secrets', 'config', 'code', 'laravel', 'deps', 'headers'];

/**
 * Run a scan.
 * @param {object} opts
 * @param {string} [opts.path]   project folder to scan
 * @param {string} [opts.url]    deployed URL to check (your own site)
 * @param {string[]} [opts.only] subset of SCANNERS
 * @param {boolean} [opts.offline] skip the OSV dependency lookup
 * @param {boolean} [opts.probes]  check for exposed files like /.env (default true)
 * @param {Function} [opts.fetch]  injectable fetch (tests)
 * @param {Function} [opts.onStep] progress callback
 */
export async function runScan(opts = {}) {
  const { url, offline = false, probes = true, fetch: fetchFn = globalThis.fetch, onStep = () => {} } = opts;
  const only = new Set(opts.only?.length ? opts.only : SCANNERS);
  for (const s of only) if (!SCANNERS.includes(s)) throw new Error(`Unknown scanner "${s}". Use: ${SCANNERS.join(', ')}`);

  const startedAt = new Date();
  const findings = [];
  const meta = { tool: 'tameng', version: '0.1.0', startedAt: startedAt.toISOString(), path: null, url: url || null, filesScanned: 0, scanners: [...only] };

  let surface = null;
  if (opts.path) {
    const root = path.resolve(opts.path);
    meta.path = root;
    onStep('Reading files');
    const { files, lockfiles } = await collectFiles(root);
    meta.filesScanned = files.length;
    meta.lockfiles = lockfiles.map((l) => l.rel);

    if (only.has('secrets')) { onStep('Looking for leaked secrets'); findings.push(...(await scanSecrets(root, files))); }
    if (only.has('config')) { onStep('Checking configuration'); findings.push(...scanConfig(files)); }
    if (only.has('code')) { onStep('Checking risky code patterns'); findings.push(...scanCode(files)); }
    if (only.has('laravel')) { onStep('Checking Laravel routes and middleware'); findings.push(...scanLaravel(files)); }
    surface = collectSurface(files);
    if (only.has('deps')) { onStep('Checking dependencies against OSV'); findings.push(...(await scanDeps(lockfiles, { fetch: fetchFn, offline, files }))); }
  }

  if (url && only.has('headers')) {
    onStep(`Checking ${url}`);
    findings.push(...(await scanUrl(url, { fetch: fetchFn, probes })));
  }

  const sorted = sortFindings(findings);
  meta.durationMs = Date.now() - startedAt.getTime();
  return { meta, summary: summarize(sorted), findings: sorted, surface };
}
