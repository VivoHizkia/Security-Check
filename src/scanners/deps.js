import { readFile } from 'node:fs/promises';
import { finding, SEVERITY_RANK } from '../findings.js';

const SCANNER = 'deps';
const OSV = 'https://api.osv.dev/v1';
const SEMVERISH = /^\d+(\.\d+)*([-.+][0-9A-Za-z.-]+)?$/;

// ── Lockfile parsers ──────────────────────────────────────────────────

export function parseNpmLock(text) {
  const json = JSON.parse(text);
  const out = [];
  if (json.packages) {
    for (const [key, val] of Object.entries(json.packages)) {
      if (!key || val.link || !val.version) continue;
      const name = val.name || key.slice(key.lastIndexOf('node_modules/') + 'node_modules/'.length);
      out.push({ ecosystem: 'npm', name, version: val.version, dev: Boolean(val.dev) });
    }
  } else if (json.dependencies) {
    const walk = (deps) => {
      for (const [name, val] of Object.entries(deps)) {
        if (val.version) out.push({ ecosystem: 'npm', name, version: val.version, dev: Boolean(val.dev) });
        if (val.dependencies) walk(val.dependencies);
      }
    };
    walk(json.dependencies);
  }
  return out;
}

export function parseYarnLock(text) {
  const out = [];
  for (const block of text.split(/\r?\n\s*\r?\n/)) {
    const lines = block.split(/\r?\n/).filter((l) => l.trim() && !l.trim().startsWith('#'));
    if (!lines.length || /^\s/.test(lines[0])) continue;
    const firstSpec = lines[0].replace(/:$/, '').split(',')[0].trim().replace(/^"|"$/g, '');
    if (firstSpec === '__metadata') continue;
    const at = firstSpec.indexOf('@npm:') > 0 ? firstSpec.indexOf('@npm:') : firstSpec.lastIndexOf('@');
    if (at <= 0) continue;
    const name = firstSpec.slice(0, at);
    const vline = lines.find((l) => /^\s+version:?\s/.test(l));
    const version = vline?.match(/version:?\s+"?([^"\s]+)"?/)?.[1];
    if (version) out.push({ ecosystem: 'npm', name, version });
  }
  return out;
}

const unquote = (s) => s.trim().replace(/^(['"])(.*)\1$/, '$2');

/**
 * Marks packages reachable only from dev roots as dev. Anything reachable from a production root,
 * or not reachable at all (incomplete graph), stays production: the cautious side.
 */
function markDevByReachability(pkgs, edges, prodRoots, devRoots) {
  const walk = (roots) => {
    const seen = new Set();
    const stack = [...roots];
    while (stack.length) {
      const k = stack.pop();
      if (seen.has(k)) continue;
      seen.add(k);
      for (const next of edges.get(k) || []) stack.push(next);
    }
    return seen;
  };
  const prod = walk(prodRoots);
  const dev = walk(devRoots);
  for (const p of pkgs) p.dev = dev.has(`${p.name}@${p.version}`) && !prod.has(`${p.name}@${p.version}`);
}

const stripPeers = (v) => unquote(v).replace(/\(.*$/, '');
/** "15.0.3(react@19)" under name "next" → next@15.0.3; aliases like "string-width@4.2.3" keep their own name. */
function pnpmRef(name, value) {
  const v = stripPeers(value);
  const alias = v.match(/^(@?[^@]+)@(\d.*)$/);
  return alias ? `${alias[1]}@${alias[2]}` : /^\d/.test(v) ? `${name}@${v}` : null;
}

/**
 * pnpm-lock.yaml, versions 5 to 9, without a YAML library.
 *   v5: /@scope/name/1.2.3_peer@1.0.0:   (dev: true inside)
 *   v6: /@scope/name@1.2.3(peer@1.0.0):  (dev: true inside)
 *   v9: '@scope/name@1.2.3':            (dev status derived from importers + the snapshots graph)
 */
export function parsePnpmLock(text) {
  const lines = text.split(/\r?\n/);
  const major = Number(unquote(lines.find((l) => l.startsWith('lockfileVersion:'))?.split(':')[1] ?? '9').split('.')[0]) || 9;
  const out = [];
  const prodRoots = [];
  const devRoots = [];
  const edges = new Map();
  let section = null;
  let importerGroup = null;
  let importerDep = null;
  let snapshot = null;
  let snapshotGroup = null;
  let current = null;

  for (const line of lines) {
    if (!line.trim() || line.trimStart().startsWith('#')) continue;
    const indent = line.length - line.trimStart().length;
    if (indent === 0) { section = line.replace(/:.*$/, ''); current = null; continue; }

    if (section === 'importers') {
      if (indent === 4) importerGroup = line.trim().replace(/:$/, '');
      else if (indent === 6) importerDep = unquote(line.trim().replace(/:.*$/, ''));
      else if (indent === 8 && importerDep && /^version:/.test(line.trim())) {
        const ref = pnpmRef(importerDep, line.trim().slice('version:'.length));
        if (ref) (importerGroup === 'devDependencies' ? devRoots : prodRoots).push(ref);
      }
      continue;
    }
    if (section === 'snapshots') {
      if (indent === 2) {
        snapshot = stripPeers(line.trim().replace(/:$/, ''));
        snapshotGroup = null;
      } else if (indent === 4) snapshotGroup = line.trim().replace(/:$/, '');
      else if (indent === 6 && snapshot && /^(dependencies|optionalDependencies)$/.test(snapshotGroup)) {
        const m = line.trim().match(/^(['"]?[^'":]+['"]?):\s*(.+)$/);
        const ref = m && pnpmRef(unquote(m[1]), m[2]);
        if (ref) edges.set(snapshot, [...(edges.get(snapshot) || []), ref]);
      }
      continue;
    }
    if (section !== 'packages') continue;

    if (indent === 2 && line.trimEnd().endsWith(':')) {
      let key = unquote(line.trim().slice(0, -1)).replace(/^\//, '');
      let name;
      let version;
      if (major < 6) {
        const at = key.lastIndexOf('/');
        name = key.slice(0, at);
        version = key.slice(at + 1).replace(/_.*$/, '');
      } else {
        key = key.replace(/\(.*$/, '');
        const at = key.lastIndexOf('@');
        if (at <= 0) { current = null; continue; }
        name = key.slice(0, at);
        version = key.slice(at + 1);
      }
      current = { ecosystem: 'npm', name, version, dev: false };
      out.push(current);
    } else if (current && indent === 4 && /^dev:\s*true\b/.test(line.trim())) {
      current.dev = true;
    }
  }
  if (major >= 9 && (prodRoots.length || devRoots.length)) markDevByReachability(out, edges, prodRoots, devRoots);
  return out;
}

/** "next/postcss" → ["next", "postcss"]; "@babel/core/semver" → ["@babel/core", "semver"]. */
function splitBunKey(key) {
  const parts = key.split('/');
  const out = [];
  for (let i = 0; i < parts.length; i++) out.push(parts[i].startsWith('@') ? `${parts[i]}/${parts[++i]}` : parts[i]);
  return out;
}

/**
 * bun.lock (text format, Bun ≥ 1.2): JSONC with "packages": { key: ["name@version", registry, { dependencies }, integrity] }.
 * Keys are hoisting paths ("next/postcss" = the postcss nested under next), resolved like node_modules lookups.
 */
export function parseBunLock(text) {
  const json = JSON.parse(text.replace(/,(\s*[}\]])/g, '$1'));
  const packages = json.packages || {};
  const out = [];
  const refOf = new Map(); // key → "name@version"
  for (const [key, entry] of Object.entries(packages)) {
    const spec = Array.isArray(entry) ? entry[0] : null;
    const at = typeof spec === 'string' ? spec.lastIndexOf('@') : -1;
    if (at <= 0) continue;
    out.push({ ecosystem: 'npm', name: spec.slice(0, at), version: spec.slice(at + 1), dev: false });
    refOf.set(key, spec);
  }
  const resolve = (fromKey, name) => {
    const path = fromKey ? splitBunKey(fromKey) : [];
    for (let i = path.length; i >= 0; i--) {
      const ref = refOf.get([...path.slice(0, i), name].join('/'));
      if (ref) return ref;
    }
    return null;
  };
  const edges = new Map();
  for (const [key, entry] of Object.entries(packages)) {
    const meta = Array.isArray(entry) ? entry.find((x) => x && typeof x === 'object' && !Array.isArray(x)) : null;
    const deps = Object.keys({ ...meta?.dependencies, ...meta?.optionalDependencies });
    if (refOf.has(key)) edges.set(refOf.get(key), deps.map((d) => resolve(key, d)).filter(Boolean));
  }
  const prodRoots = [];
  const devRoots = [];
  for (const ws of Object.values(json.workspaces || {})) {
    for (const d of Object.keys({ ...ws.dependencies, ...ws.optionalDependencies })) prodRoots.push(resolve('', d));
    for (const d of Object.keys(ws.devDependencies || {})) devRoots.push(resolve('', d));
  }
  if (prodRoots.length || devRoots.length) markDevByReachability(out, edges, prodRoots.filter(Boolean), devRoots.filter(Boolean));
  return out;
}

export function parseComposerLock(text) {
  const json = JSON.parse(text);
  const map = (list, dev) => (list || [])
    .filter((p) => p.name && p.version)
    .map((p) => ({ ecosystem: 'Packagist', name: p.name, version: p.version.replace(/^v/, ''), dev }));
  return [...map(json.packages, false), ...map(json['packages-dev'], true)];
}

export function parseRequirements(text) {
  const out = [];
  for (const raw of text.split(/\r?\n/)) {
    const m = raw.replace(/#.*$/, '').trim().match(/^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?\s*==\s*([^\s;]+)/);
    if (m) out.push({ ecosystem: 'PyPI', name: m[1], version: m[2] });
  }
  return out;
}

const PARSERS = {
  'package-lock.json': parseNpmLock,
  'npm-shrinkwrap.json': parseNpmLock,
  'yarn.lock': parseYarnLock,
  'pnpm-lock.yaml': parsePnpmLock,
  'bun.lock': parseBunLock,
  'composer.lock': parseComposerLock,
  'requirements.txt': parseRequirements,
};

// ── OSV lookup ────────────────────────────────────────────────────────

const DOWNGRADE = { critical: 'high', high: 'medium', medium: 'low', low: 'low', info: 'info' };
const OSV_SEVERITY = { CRITICAL: 'critical', HIGH: 'high', MODERATE: 'medium', MEDIUM: 'medium', LOW: 'low' };

function severityOf(vuln) {
  if (vuln.id.startsWith('MAL-')) return 'critical';
  const label = vuln.database_specific?.severity || vuln.affected?.find((a) => a.ecosystem_specific?.severity)?.ecosystem_specific?.severity;
  if (label && OSV_SEVERITY[String(label).toUpperCase()]) return OSV_SEVERITY[String(label).toUpperCase()];
  const cvss = vuln.severity?.find((s) => /^CVSS/.test(s.type))?.score;
  const numeric = typeof cvss === 'string' && /^\d+(\.\d+)?$/.test(cvss) ? Number(cvss) : null;
  if (numeric !== null) return numeric >= 9 ? 'critical' : numeric >= 7 ? 'high' : numeric >= 4 ? 'medium' : 'low';
  return 'medium';
}

function fixedVersions(vuln, pkg) {
  const fixed = new Set();
  for (const affected of vuln.affected || []) {
    if (affected.package?.name !== pkg.name) continue;
    for (const range of affected.ranges || []) {
      for (const event of range.events || []) if (event.fixed) fixed.add(event.fixed);
    }
  }
  return [...fixed];
}

const splitIds = (s) => s.split('.').map((x) => (/^\d+$/.test(x) ? Number(x) : x));

function compareIds(pa, pb, missing) {
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? missing;
    const y = pb[i] ?? missing;
    if (x === y) continue;
    if (typeof x === 'number' && typeof y === 'number') return x - y;
    if (typeof x === 'number') return -1; // semver: numeric identifiers sort before alphanumeric
    if (typeof y === 'number') return 1;
    return x < y ? -1 : 1;
  }
  return 0;
}

/** Semver-style precedence: build metadata is ignored and 1.0.0-rc.1 < 1.0.0. */
export function compareVersions(a, b) {
  const parse = (v) => {
    const [core, ...pre] = String(v).split('+')[0].split('-');
    return { core: splitIds(core), pre: pre.length ? splitIds(pre.join('-')) : null };
  };
  const va = parse(a);
  const vb = parse(b);
  const byCore = compareIds(va.core, vb.core, 0);
  if (byCore) return byCore;
  if (!va.pre || !vb.pre) return (va.pre ? -1 : 0) + (vb.pre ? 1 : 0);
  return compareIds(va.pre, vb.pre, -Infinity); // a shorter pre-release list sorts first
}

/** For each advisory take the lowest fixed version above the installed one, then the highest of those. */
export function upgradeTarget(pkg, vulns) {
  let best = null;
  let partial = false;
  for (const vuln of vulns) {
    const candidates = fixedVersions(vuln, pkg).filter((v) => compareVersions(v, pkg.version) > 0).sort(compareVersions);
    if (!candidates.length) { partial = true; continue; }
    if (!best || compareVersions(candidates[0], best) > 0) best = candidates[0];
  }
  return { version: best, partial: partial && Boolean(best) };
}

async function mapLimit(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i]);
    }
  });
  await Promise.all(workers);
  return results;
}

async function queryOsv(pkgs, fetchFn) {
  const hits = [];
  for (let i = 0; i < pkgs.length; i += 500) {
    const chunk = pkgs.slice(i, i + 500);
    const res = await fetchFn(`${OSV}/querybatch`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ queries: chunk.map((p) => ({ package: { name: p.name, ecosystem: p.ecosystem }, version: p.version })) }),
      signal: AbortSignal.timeout(30_000),
    });
    if (!res.ok) throw new Error(`OSV returned HTTP ${res.status}`);
    const data = await res.json();
    (data.results || []).forEach((r, j) => {
      if (r.vulns?.length) hits.push({ pkg: chunk[j], ids: r.vulns.map((v) => v.id) });
    });
  }
  return hits;
}

const MANIFESTS = {
  'package.json': { locks: ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'bun.lockb'], install: 'npm install' },
  'composer.json': { locks: ['composer.lock'], install: 'composer update --lock' },
};

function declaresDeps(file) {
  try {
    const json = JSON.parse(file.text);
    if (file.name === 'composer.json') {
      return Object.keys({ ...json.require, ...json['require-dev'] }).some((n) => n !== 'php' && !n.startsWith('ext-'));
    }
    return Object.keys({ ...json.dependencies, ...json.devDependencies, ...json.optionalDependencies }).length > 0;
  } catch {
    return false;
  }
}

/** Manifests with dependencies but no lockfile in their folder or any parent (monorepo roots count). */
export function manifestsWithoutLock(files, lockfiles) {
  const dirOf = (rel) => (rel.includes('/') ? rel.slice(0, rel.lastIndexOf('/')) : '');
  const lockDirs = new Set(lockfiles.map((l) => `${l.name}|${dirOf(l.rel)}`));
  return files.filter((f) => {
    const spec = MANIFESTS[f.name];
    if (!spec || !declaresDeps(f)) return false;
    const parts = dirOf(f.rel).split('/').filter(Boolean);
    for (let i = parts.length; i >= 0; i--) {
      const dir = parts.slice(0, i).join('/');
      if (spec.locks.some((lock) => lockDirs.has(`${lock}|${dir}`))) return false;
    }
    return true;
  });
}

export async function scanDeps(lockfiles, { fetch: fetchFn = globalThis.fetch, offline = false, files = [] } = {}) {
  const findings = [];
  const pkgs = new Map();

  for (const m of manifestsWithoutLock(files, lockfiles)) {
    findings.push(finding({ id: 'deps-no-lockfile', scanner: SCANNER, severity: 'info',
      title: `${m.name} has no lockfile, so its dependencies were not checked`, location: m.rel,
      detail: 'Without a lockfile the installed versions are unknown and every install can pull different code.',
      fix: `Run ${MANIFESTS[m.name].install} and commit the generated lockfile.` }));
  }

  for (const lock of lockfiles) {
    const parse = PARSERS[lock.name];
    if (!parse) {
      findings.push(finding({ id: 'deps-unsupported-lockfile', scanner: SCANNER, severity: 'info',
        title: `${lock.name} is not supported yet`, location: lock.rel, fix: 'Run your package manager\'s own audit command.' }));
      continue;
    }
    let list;
    try {
      list = parse(await readFile(lock.full, 'utf8'));
    } catch (err) {
      findings.push(finding({ id: 'deps-parse-error', scanner: SCANNER, severity: 'info',
        title: `Could not parse ${lock.name}`, location: lock.rel, detail: err.message }));
      continue;
    }
    for (const p of list) {
      if (!SEMVERISH.test(p.version)) continue;
      const key = `${p.ecosystem}:${p.name}@${p.version}`;
      const known = pkgs.get(key);
      if (!known) pkgs.set(key, { ...p, source: lock.rel });
      else if (!p.dev) known.dev = false; // used in production by at least one lockfile
    }
  }

  if (!pkgs.size) return findings;
  if (offline) {
    findings.push(finding({ id: 'deps-skipped', scanner: SCANNER, severity: 'info',
      title: `Dependency check skipped (--offline, ${pkgs.size} packages found)` }));
    return findings;
  }

  try {
    const hits = await queryOsv([...pkgs.values()], fetchFn);
    const ids = [...new Set(hits.flatMap((h) => h.ids))];
    const details = new Map();
    await mapLimit(ids, 8, async (id) => {
      const res = await fetchFn(`${OSV}/vulns/${encodeURIComponent(id)}`, { signal: AbortSignal.timeout(20_000) });
      if (res.ok) details.set(id, await res.json());
    });

    // One finding per package@version, carrying its worst severity and the upgrade that fixes all of it.
    for (const { pkg, ids: vulnIds } of hits) {
      const vulns = vulnIds.map((id) => details.get(id) || { id });
      let severity = vulns.map(severityOf).sort((a, b) => SEVERITY_RANK[b] - SEVERITY_RANK[a])[0];
      // Dev-only packages don't ship to production: one level lower (malicious code stays critical, it runs on your machine).
      if (pkg.dev && !vulns.some((v) => v.id.startsWith('MAL-'))) severity = DOWNGRADE[severity];
      const malicious = vulns.some((v) => v.id.startsWith('MAL-'));
      const target = upgradeTarget(pkg, vulns);
      const label = (v) => (v.aliases || []).find((a) => a.startsWith('CVE-')) || v.id;
      const title = vulns.length === 1
        ? `${pkg.name}@${pkg.version} — ${vulns[0].summary || (malicious ? 'Malicious package' : 'Known vulnerability')}`
        : `${pkg.name}@${pkg.version} — ${vulns.length} known vulnerabilities${malicious ? ' (incl. malicious code report)' : ''}`;
      const scope = pkg.dev ? ' (dev dependency)' : '';
      findings.push(finding({
        id: 'vulnerable-dependency', scanner: SCANNER, severity, title: title + scope, location: pkg.source,
        detail: vulns.length === 1
          ? `${label(vulns[0])} · https://osv.dev/vulnerability/${vulns[0].id}`
          : vulns.map((v) => `${label(v)}${v.summary ? ` (${v.summary})` : ''}`).join(' · '),
        fix: target.version
          ? `Upgrade ${pkg.name} to ${target.version} or later${target.partial ? ' (some advisories have no fix yet)' : ''}.`
          : 'No fixed version published yet; consider replacing the package.',
      }));
    }
  } catch (err) {
    findings.push(finding({ id: 'deps-skipped', scanner: SCANNER, severity: 'info',
      title: 'Dependency check skipped: could not reach api.osv.dev', detail: err.message,
      fix: 'Check your internet connection or run again with --offline to silence this.' }));
  }
  return findings;
}
