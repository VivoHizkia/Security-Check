import { createHash, randomBytes } from 'node:crypto';
import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

// Local scan history: ~/.tameng (or $TAMENG_HOME)
//   projects.json                  [{ id, name, path, url, createdAt }]
//   history/<id>/index.json        [{ scanId, startedAt, score, grade, counts, total, durationMs }]
//   history/<id>/<scanId>.json     full report (findings are already masked)

const MAX_SCANS = 200;

export function homeDir() {
  return process.env.TAMENG_HOME || path.join(os.homedir(), '.tameng');
}

async function readJson(file, fallback) {
  try {
    return JSON.parse(await readFile(file, 'utf8'));
  } catch (err) {
    if (err.code === 'ENOENT') return fallback;
    throw err;
  }
}

async function writeJson(file, data) {
  await mkdir(path.dirname(file), { recursive: true });
  const tmp = `${file}.${randomBytes(4).toString('hex')}.tmp`;
  await writeFile(tmp, JSON.stringify(data, null, 2));
  await rename(tmp, file);
}

const projectsFile = () => path.join(homeDir(), 'projects.json');
const historyDir = (id) => path.join(homeDir(), 'history', id);
const SAFE_ID = /^[a-f0-9]{12}$/;
const SAFE_SCAN = /^\d{8}T\d{6}Z-[a-f0-9]{4}$/;

const normalize = (p) => (process.platform === 'win32' ? path.resolve(p).toLowerCase() : path.resolve(p));
export const projectId = (absPath) => createHash('sha256').update(normalize(absPath)).digest('hex').slice(0, 12);

export async function listProjects() {
  return readJson(projectsFile(), []);
}

export async function getProject(id) {
  if (!SAFE_ID.test(id)) return null;
  return (await listProjects()).find((p) => p.id === id) ?? null;
}

export async function addProject({ path: dir, url = null, name = null }) {
  const abs = path.resolve(dir);
  const projects = await listProjects();
  const id = projectId(abs);
  const existing = projects.find((p) => p.id === id);
  if (existing) return existing;
  const project = { id, name: name || path.basename(abs), path: abs, url: url || null, createdAt: new Date().toISOString() };
  await writeJson(projectsFile(), [...projects, project]);
  return project;
}

export async function updateProject(id, changes) {
  const projects = await listProjects();
  const project = projects.find((p) => p.id === id);
  if (!project) return null;
  if ('name' in changes && changes.name) project.name = String(changes.name).slice(0, 100);
  if ('url' in changes) project.url = changes.url || null;
  await writeJson(projectsFile(), projects);
  return project;
}

export async function removeProject(id) {
  if (!SAFE_ID.test(id)) return false;
  const projects = await listProjects();
  if (!projects.some((p) => p.id === id)) return false;
  await writeJson(projectsFile(), projects.filter((p) => p.id !== id));
  await rm(historyDir(id), { recursive: true, force: true });
  return true;
}

export async function listScans(id) {
  if (!SAFE_ID.test(id)) return [];
  return readJson(path.join(historyDir(id), 'index.json'), []);
}

export async function getScan(id, scanId) {
  if (!SAFE_ID.test(id) || !SAFE_SCAN.test(scanId)) return null;
  return readJson(path.join(historyDir(id), `${scanId}.json`), null);
}

export async function saveScan(id, report) {
  if (!SAFE_ID.test(id)) throw new Error('Invalid project id');
  const stamp = report.meta.startedAt.replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');
  const scanId = `${stamp}-${randomBytes(2).toString('hex')}`;
  await writeJson(path.join(historyDir(id), `${scanId}.json`), report);
  const index = await listScans(id);
  index.push({ scanId, startedAt: report.meta.startedAt, durationMs: report.meta.durationMs, url: report.meta.url, ...report.summary });
  const dropped = index.length > MAX_SCANS ? index.splice(0, index.length - MAX_SCANS) : [];
  await writeJson(path.join(historyDir(id), 'index.json'), index);
  await Promise.all(dropped.map((s) => rm(path.join(historyDir(id), `${s.scanId}.json`), { force: true })));
  return scanId;
}

// ── Diff between two scans ──────────────────────────────────────────

/** Identity ignores the line number, so moving code around does not count as new + fixed. */
export const findingKey = (f) => `${f.id}|${f.location.replace(/:\d+$/, '')}|${f.title}`;

/**
 * Scanners whose findings can be compared between two reports. A finding that disappears only because
 * the second scan skipped that check (offline, no --url, --only) must not show up as "fixed".
 */
export function comparableScanners(prevReport, currReport) {
  const ran = (r) => {
    const set = new Set(r.meta.scanners || []);
    if (r.findings.some((f) => f.id === 'deps-skipped')) set.delete('deps'); // offline, or OSV unreachable
    if (!r.meta.url) set.delete('headers');
    return set;
  };
  const a = ran(prevReport);
  const b = ran(currReport);
  const both = new Set([...a].filter((s) => b.has(s)));
  if (prevReport.meta.url !== currReport.meta.url) both.delete('headers');
  const notCompared = [...new Set([...a, ...b])].filter((s) => !both.has(s));
  return { scanners: both, notCompared };
}

/** Diff two reports, comparing only checks that ran fully in both. */
export function diffReports(previous, current) {
  if (!previous) return { ...diffFindings(null, current.findings), notCompared: [] };
  const { scanners, notCompared } = comparableScanners(previous, current);
  const keep = (f) => scanners.has(f.scanner);
  return { ...diffFindings(previous.findings.filter(keep), current.findings.filter(keep)), notCompared };
}

export function diffFindings(previous, current) {
  if (!previous) return { added: [], fixed: [], unchanged: current.length, firstScan: true };
  const pool = new Map();
  for (const f of previous) {
    const k = findingKey(f);
    pool.set(k, [...(pool.get(k) || []), f]);
  }
  const added = [];
  let unchanged = 0;
  for (const f of current) {
    const bucket = pool.get(findingKey(f));
    if (bucket?.length) { bucket.shift(); unchanged++; } else added.push(f);
  }
  const fixed = [...pool.values()].flat();
  return { added, fixed, unchanged, firstScan: false };
}
