import http from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { stat } from 'node:fs/promises';
import os from 'node:os';
import { runScan } from '../index.js';
import * as history from '../history.js';
import { renderPage } from './page.js';

// Local dashboard. It can start scans (including outbound requests to a --url), so it is locked down:
//  - binds to 127.0.0.1 only
//  - rejects any Host header other than localhost/127.0.0.1:<port>  (DNS rebinding)
//  - every /api call needs the per-process token embedded in the page  (other sites can't read it)
//  - state-changing calls must be application/json and same-origin    (no form-based CSRF)

const MAX_BODY = 64 * 1024;

const send = (res, status, data, headers = {}) => {
  const body = typeof data === 'string' ? data : JSON.stringify(data);
  res.writeHead(status, {
    'content-type': typeof data === 'string' ? 'text/html; charset=utf-8' : 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'x-frame-options': 'DENY',
    'cross-origin-opener-policy': 'same-origin',
    'cross-origin-resource-policy': 'same-origin',
    ...headers,
  });
  res.end(body);
};

const fail = (res, status, error) => send(res, status, { error });

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) { reject(Object.assign(new Error('Body too large'), { status: 413 })); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(Object.assign(new Error('Invalid JSON'), { status: 400 }));
      }
    });
    req.on('error', reject);
  });
}

function cleanUrl(value) {
  if (value === undefined) return undefined;
  if (value === null || value === '') return null;
  let u;
  try { u = new URL(String(value)); } catch { throw Object.assign(new Error('URL is not valid'), { status: 400 }); }
  if (!/^https?:$/.test(u.protocol)) throw Object.assign(new Error('URL must start with http:// or https://'), { status: 400 });
  return u.toString();
}

async function projectView(p) {
  const scans = await history.listScans(p.id);
  const last = scans.at(-1) ?? null;
  return { ...p, last, trend: scans.slice(-20).map((s) => ({ score: s.score, at: s.startedAt })) };
}

/** Report + diff against the scan before it. */
async function scanView(id, scanId) {
  const scans = await history.listScans(id);
  const i = scans.findIndex((s) => s.scanId === scanId);
  if (i === -1) return null;
  const report = await history.getScan(id, scanId);
  if (!report) return null;
  const previous = i > 0 ? await history.getScan(id, scans[i - 1].scanId) : null;
  return { scanId, report, diff: history.diffReports(previous, report) };
}

export function createDashboard({ scan = runScan, token = randomBytes(24).toString('hex') } = {}) {
  let port = 0;
  const running = new Set();
  const tokenBuf = Buffer.from(token);
  const goodToken = (value) => {
    const b = Buffer.from(String(value || ''));
    return b.length === tokenBuf.length && timingSafeEqual(b, tokenBuf);
  };

  const routes = [
    ['GET', /^\/api\/projects$/, async () => ({ projects: await Promise.all((await history.listProjects()).map(projectView)) })],

    ['POST', /^\/api\/projects$/, async (_m, body) => {
      const dir = String(body.path || '').trim().replace(/^~(?=$|[\\/])/, os.homedir());
      if (!dir) throw Object.assign(new Error('Folder path is required'), { status: 400 });
      const info = await stat(dir).catch(() => null);
      if (!info?.isDirectory()) throw Object.assign(new Error('That folder does not exist'), { status: 400 });
      return { project: await projectView(await history.addProject({ path: dir, url: cleanUrl(body.url), name: body.name ? String(body.name).slice(0, 100) : null })) };
    }],

    ['PATCH', /^\/api\/projects\/([a-f0-9]{12})$/, async ([, id], body) => {
      const p = await history.updateProject(id, { ...('name' in body && { name: body.name }), ...('url' in body && { url: cleanUrl(body.url) }) });
      if (!p) throw Object.assign(new Error('Project not found'), { status: 404 });
      return { project: await projectView(p) };
    }],

    ['DELETE', /^\/api\/projects\/([a-f0-9]{12})$/, async ([, id]) => {
      if (!(await history.removeProject(id))) throw Object.assign(new Error('Project not found'), { status: 404 });
      return { ok: true };
    }],

    ['GET', /^\/api\/projects\/([a-f0-9]{12})\/scans$/, async ([, id]) => ({ scans: await history.listScans(id) })],

    ['GET', /^\/api\/projects\/([a-f0-9]{12})\/scans\/([\w-]+)$/, async ([, id, scanId]) => {
      const view = await scanView(id, scanId);
      if (!view) throw Object.assign(new Error('Scan not found'), { status: 404 });
      return view;
    }],

    ['POST', /^\/api\/projects\/([a-f0-9]{12})\/scan$/, async ([, id], body) => {
      const p = await history.getProject(id);
      if (!p) throw Object.assign(new Error('Project not found'), { status: 404 });
      if (running.has(id)) throw Object.assign(new Error('A scan of this project is already running'), { status: 409 });
      running.add(id);
      try {
        const report = await scan({ path: p.path, url: body.withUrl === false ? undefined : p.url || undefined, offline: Boolean(body.offline) });
        const scanId = await history.saveScan(id, report);
        return scanView(id, scanId);
      } finally {
        running.delete(id);
      }
    }],
  ];

  const server = http.createServer(async (req, res) => {
    const host = req.headers.host || '';
    if (host !== `127.0.0.1:${port}` && host !== `localhost:${port}`) return fail(res, 421, 'Unexpected Host header');
    const url = new URL(req.url, `http://${host}`);

    if (req.method === 'GET' && url.pathname === '/') {
      const nonce = randomBytes(16).toString('base64');
      return send(res, 200, renderPage({ token, nonce }), {
        'content-security-policy': `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
      });
    }
    if (!url.pathname.startsWith('/api/')) return fail(res, 404, 'Not found');

    if (!goodToken(req.headers['x-tameng-token'])) return fail(res, 403, 'Missing or wrong token');
    const origin = req.headers.origin;
    if (origin && origin !== `http://${host}`) return fail(res, 403, 'Cross-origin request blocked');
    if (req.method !== 'GET' && !/^application\/json\b/.test(req.headers['content-type'] || '')) {
      return fail(res, 415, 'Send application/json');
    }

    const route = routes.find(([method, re]) => method === req.method && re.test(url.pathname));
    if (!route) return fail(res, 404, 'Not found');
    try {
      const body = req.method === 'GET' ? {} : await readBody(req);
      send(res, 200, await route[2](url.pathname.match(route[1]), body));
    } catch (err) {
      send(res, err.status || 500, { error: err.status ? err.message : `Scan failed: ${err.message}` });
    }
  });

  return {
    server,
    token,
    listen: (wantedPort = 7777) => new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(wantedPort, '127.0.0.1', () => {
        port = server.address().port;
        resolve(`http://127.0.0.1:${port}/`);
      });
    }),
    close: () => new Promise((r) => server.close(r)),
  };
}
