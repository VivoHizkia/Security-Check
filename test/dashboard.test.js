import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import { createDashboard } from '../src/dashboard/server.js';
import { renderPage } from '../src/dashboard/page.js';
import { diffFindings, diffReports, findingKey } from '../src/history.js';
import { collectSurface, nextRoutePath } from '../src/surface.js';
import { collectFiles } from '../src/files.js';
import { makeProject } from './helpers.js';

let home;
before(async () => {
  home = await mkdtemp(path.join(os.tmpdir(), 'tameng-home-'));
  process.env.TAMENG_HOME = home;
});
after(async () => {
  delete process.env.TAMENG_HOME;
  await rm(home, { recursive: true, force: true });
});

const f = (id, location, severity = 'medium') => ({ id, scanner: 'code', severity, title: id, detail: '', location, fix: '' });

test('diffFindings ignores line moves and counts duplicates', () => {
  assert.equal(findingKey(f('js-eval', 'a.js:3')), findingKey(f('js-eval', 'a.js:40')));
  const prev = [f('js-eval', 'a.js:3'), f('js-eval', 'a.js:9'), f('js-ssrf', 'b.js:1')];
  const curr = [f('js-eval', 'a.js:5'), f('cors-any-origin', 'server.js:2')];
  const d = diffFindings(prev, curr);
  assert.deepEqual(d.added.map((x) => x.id), ['cors-any-origin']);
  assert.deepEqual(d.fixed.map((x) => x.id).sort(), ['js-eval', 'js-ssrf'], 'one of the two evals is gone');
  assert.equal(d.unchanged, 1);
  assert.equal(diffFindings(null, curr).firstScan, true);
});

test('diffReports never calls a finding fixed when its check was skipped', () => {
  const all = ['secrets', 'config', 'code', 'laravel', 'deps', 'headers'];
  const report = (findings, meta = {}) => ({ meta: { scanners: all, url: null, ...meta }, findings });
  const vuln = { ...f('vulnerable-dependency', 'package-lock.json', 'high'), scanner: 'deps' };
  const skipped = { ...f('deps-skipped', '', 'info'), scanner: 'deps' };
  const powered = { ...f('next-powered-by', 'next.config.mjs', 'low'), scanner: 'config' };
  const csp = { ...f('missing-csp', 'https://app.example', 'medium'), scanner: 'headers' };

  const offline = diffReports(report([vuln, powered]), report([powered, skipped]));
  assert.deepEqual(offline.fixed, [], 'offline scan must not mark the vulnerable dependency as fixed');
  assert.deepEqual(offline.notCompared, ['deps']);

  const backOnline = diffReports(report([powered, skipped]), report([vuln, powered]));
  assert.deepEqual(backOnline.added, [], 'coming back online is not a "new" vulnerability either');

  const noUrl = diffReports(report([csp], { url: 'https://app.example' }), report([]));
  assert.deepEqual(noUrl.fixed, [], 'dropping --url does not fix headers');
  assert.deepEqual(noUrl.notCompared, ['headers']);

  const real = diffReports(report([vuln, powered]), report([vuln]));
  assert.deepEqual(real.fixed.map((x) => x.id), ['next-powered-by'], 'real fixes still show up');
});

test('nextRoutePath handles route groups, params and catch-alls', () => {
  assert.equal(nextRoutePath('src/app/(shop)/products/[id]/route.ts'), '/products/{id}');
  assert.equal(nextRoutePath('app/api/files/[...path]/route.js'), '/api/files/{...path}');
  assert.equal(nextRoutePath('app/route.ts'), '/');
});

test('attack surface lists Next routes, Server Actions and Express routes with auth hints', async () => {
  const p = await makeProject({
    'src/app/api/orders/route.ts': 'export async function GET() {}\nexport async function POST(req) { const s = await getServerSession(); }\n',
    'src/app/actions.ts': [
      "'use server';",
      'export async function login(form) { return startSession(form); }',
      'export async function deletePost(id) { const user = await requireUser(); }',
    ].join('\n'),
    'src/pages/api/legacy/[id].ts': 'export default function handler(req, res) {}',
    'server/index.js': "const express = require('express');\nconst app = express();\napp.get('/health', (req, res) => res.send('ok'));\napp.post('/admin/users', requireAuth, createUser);\n",
    'src/middleware.ts': 'export const config = { matcher: ["/dashboard/:path*"] };',
  });
  try {
    const { endpoints, notes } = collectSurface((await collectFiles(p.root)).files);
    const row = (e) => `${e.kind} ${e.method} ${e.path} ${e.auth}`;
    assert.deepEqual(endpoints.map(row).sort(), [
      'express GET /health unknown',
      'express POST /admin/users likely',
      'next-pages-api ANY /api/legacy/{id} unknown',
      'next-route GET /api/orders likely',
      'next-route POST /api/orders likely',
      'server-action POST action:deletePost likely',
      'server-action POST action:login unknown',
    ].sort());
    assert.match(notes[0], /middleware/);
  } finally {
    await p.cleanup();
  }
});

test('dashboard page: inline script compiles and carries the nonce', () => {
  const html = renderPage({ token: 'tok', nonce: 'abc' });
  const script = html.match(/<script nonce="abc">([\s\S]*)<\/script>/)?.[1];
  assert.ok(script, 'script tag with nonce');
  assert.doesNotThrow(() => new vm.Script(script), 'inline script must be valid JavaScript');
  assert.ok(!/\sstyle="/.test(html + script), 'no style attributes: the CSP only allows nonce-tagged styles');
});

test('dashboard: locked to localhost, token, same origin and JSON; full scan flow works', async () => {
  const project = await makeProject({ 'src/a.js': 'eval(input);\n' });
  let calls = 0;
  const fakeScan = async ({ path: dir }) => {
    calls++;
    const findings = calls === 1 ? [f('js-eval', 'src/a.js:1')] : [];
    return { meta: { tool: 'tameng', version: '0.1.0', startedAt: new Date(Date.now() + calls * 1000).toISOString(), path: dir, url: null, filesScanned: 1, durationMs: 5, scanners: ['secrets', 'config', 'code', 'laravel', 'deps', 'headers'] },
      summary: { counts: { critical: 0, high: 0, medium: findings.length, low: 0, info: 0 }, score: 100 - 4 * findings.length, grade: 'A', total: findings.length },
      findings, surface: { endpoints: [], notes: [] } };
  };
  const dash = createDashboard({ scan: fakeScan, token: 't'.repeat(48) });
  const base = await dash.listen(0);
  const { port } = dash.server.address();
  const call = (method, url, { body, headers = {} } = {}) => fetch(base.replace(/\/$/, '') + url, {
    method, body: body && JSON.stringify(body),
    headers: { 'x-tameng-token': dash.token, ...(body && { 'content-type': 'application/json' }), ...headers },
  });
  try {
    const page = await fetch(base);
    assert.equal(page.status, 200);
    assert.match(page.headers.get('content-security-policy'), /script-src 'nonce-/);
    assert.match(await page.text(), new RegExp(dash.token));

    assert.equal((await fetch(`${base}api/projects`)).status, 403, 'no token');
    assert.equal((await call('GET', '/api/projects', { headers: { 'x-tameng-token': 'x'.repeat(48) } })).status, 403, 'wrong token');
    assert.equal((await call('POST', '/api/projects', { body: { path: project.root }, headers: { origin: 'https://evil.example' } })).status, 403, 'cross-origin');
    assert.equal((await fetch(`${base}api/projects`, { method: 'POST', headers: { 'x-tameng-token': dash.token, 'content-type': 'text/plain' }, body: '{}' })).status, 415, 'form-style body');
    const rebind = await new Promise((resolve) => {
      import('node:http').then(({ request }) => request({ host: '127.0.0.1', port, path: '/', headers: { host: `attacker.example:${port}` } }, (res) => resolve(res.statusCode)).end());
    });
    assert.equal(rebind, 421, 'DNS rebinding: foreign Host header');

    assert.equal((await call('POST', '/api/projects', { body: { path: path.join(project.root, 'nope') } })).status, 400);
    assert.equal((await call('POST', '/api/projects', { body: { path: project.root, url: 'javascript:alert(1)' } })).status, 400, 'only http(s) URLs');

    const added = await (await call('POST', '/api/projects', { body: { path: project.root } })).json();
    const id = added.project.id;
    const first = await (await call('POST', `/api/projects/${id}/scan`, { body: { offline: true } })).json();
    assert.equal(first.report.findings.length, 1);
    assert.equal(first.diff.firstScan, true);
    const second = await (await call('POST', `/api/projects/${id}/scan`, { body: {} })).json();
    assert.deepEqual(second.diff.fixed.map((x) => x.id), ['js-eval']);

    const { projects } = await (await call('GET', '/api/projects')).json();
    assert.deepEqual(projects[0].trend.map((t) => t.score), [96, 100]);
    const { scans } = await (await call('GET', `/api/projects/${id}/scans`)).json();
    assert.equal(scans.length, 2);
    assert.equal((await call('GET', `/api/projects/${id}/scans/..%2F..%2Fprojects`)).status, 404, 'scan ids cannot escape the folder');

    assert.equal((await call('PATCH', `/api/projects/${id}`, { body: { url: 'https://my-app.example' } })).status, 200);
    assert.equal((await call('DELETE', `/api/projects/${id}`, { body: {} })).status, 200);
    assert.deepEqual((await (await call('GET', '/api/projects')).json()).projects, []);
  } finally {
    await dash.close();
    await project.cleanup();
  }
});
