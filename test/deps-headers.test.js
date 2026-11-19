import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { compareVersions, parseBunLock, parsePnpmLock, parseComposerLock, parseNpmLock, parseRequirements, parseYarnLock, scanDeps, upgradeTarget } from '../src/scanners/deps.js';
import { scanUrl } from '../src/scanners/headers.js';
import { collectFiles } from '../src/files.js';
import { ids, makeProject } from './helpers.js';

test('lockfile parsers', () => {
  assert.deepEqual(parseNpmLock(JSON.stringify({ packages: { '': {}, 'node_modules/lodash': { version: '4.17.20' }, 'node_modules/a/node_modules/@x/y': { version: '1.0.0' } } })),
    [{ ecosystem: 'npm', name: 'lodash', version: '4.17.20', dev: false }, { ecosystem: 'npm', name: '@x/y', version: '1.0.0', dev: false }]);
  assert.deepEqual(parseYarnLock('# yarn lockfile v1\n\n"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.2.0"\n\nminimist@^1.2.0:\n  version "1.2.5"\n'),
    [{ ecosystem: 'npm', name: '@babel/core', version: '7.2.0' }, { ecosystem: 'npm', name: 'minimist', version: '1.2.5' }]);
  assert.deepEqual(parseComposerLock(JSON.stringify({ packages: [{ name: 'laravel/framework', version: 'v10.0.0' }] })),
    [{ ecosystem: 'Packagist', name: 'laravel/framework', version: '10.0.0', dev: false }]);
  assert.deepEqual(parseRequirements('fastapi==0.95.0\nrequests>=2\nuvicorn[standard]==0.20.0 # web\n'),
    [{ ecosystem: 'PyPI', name: 'fastapi', version: '0.95.0' }, { ecosystem: 'PyPI', name: 'uvicorn', version: '0.20.0' }]);
});

test('deps: maps OSV results to findings (mocked)', async () => {
  const p = await makeProject({ 'package-lock.json': JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/lodash': { version: '4.17.20' } } }) });
  const fakeFetch = async (url) => {
    if (url.endsWith('/querybatch')) return new Response(JSON.stringify({ results: [{ vulns: [{ id: 'GHSA-35jh-r3h4-6jhm' }] }] }));
    return new Response(JSON.stringify({
      id: 'GHSA-35jh-r3h4-6jhm', summary: 'Command Injection in lodash', aliases: ['CVE-2021-23337'],
      database_specific: { severity: 'HIGH' },
      affected: [{ package: { name: 'lodash', ecosystem: 'npm' }, ranges: [{ events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] }],
    }));
  };
  try {
    const { lockfiles } = await collectFiles(p.root);
    const [f] = await scanDeps(lockfiles, { fetch: fakeFetch });
    assert.equal(f.severity, 'high');
    assert.match(f.title, /lodash@4\.17\.20/);
    assert.match(f.detail, /CVE-2021-23337/);
    assert.match(f.fix, /4\.17\.21/);

    const devLock = await makeProject({ 'package-lock.json': JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/lodash': { version: '4.17.20', dev: true } } }) });
    const [dev] = await scanDeps((await collectFiles(devLock.root)).lockfiles, { fetch: fakeFetch });
    assert.equal(dev.severity, 'medium', 'dev-only dependency is one level lower');
    assert.match(dev.title, /\(dev dependency\)/);
    await devLock.cleanup();

    const [skipped] = await scanDeps(lockfiles, { fetch: async () => { throw new Error('ENOTFOUND'); } });
    assert.equal(skipped.id, 'deps-skipped');
  } finally {
    await p.cleanup();
  }
});

test('pnpm-lock.yaml v5, v6 and v9, and bun.lock', () => {
  const v5 = [
    'lockfileVersion: 5.4', '', 'specifiers:', '  next: ^13.0.0', '', 'packages:', '',
    '  /@babel/core/7.21.0:', '    resolution: {integrity: sha512-x}', '    dev: true', '',
    '  /next/13.4.0_react@18.2.0:', '    resolution: {integrity: sha512-y}', '    dev: false', '',
  ].join('\n');
  assert.deepEqual(parsePnpmLock(v5), [
    { ecosystem: 'npm', name: '@babel/core', version: '7.21.0', dev: true },
    { ecosystem: 'npm', name: 'next', version: '13.4.0', dev: false },
  ]);

  const v6 = [
    "lockfileVersion: '6.0'", '', 'packages:', '',
    '  /@types/node@20.11.0:', '    resolution: {integrity: sha512-a}', '    dev: true', '',
    '  /next@14.1.0(react-dom@18.2.0)(react@18.2.0):', '    resolution: {integrity: sha512-b}', '    dev: false', '',
  ].join('\n');
  assert.deepEqual(parsePnpmLock(v6).map((p) => `${p.name}@${p.version}:${p.dev}`), ['@types/node@20.11.0:true', 'next@14.1.0:false']);

  const v9 = [
    "lockfileVersion: '9.0'", '', 'importers:', '', '  .:',
    '    dependencies:', '      next:', '        specifier: ^15.0.0', '        version: 15.0.3(react@19.0.0)',
    '    devDependencies:', '      typescript:', '        specifier: ^5.6.0', '        version: 5.6.3', '',
    'packages:', '',
    "  '@next/env@15.0.3':", '    resolution: {integrity: sha512-c}', '',
    '  next@15.0.3:', '    resolution: {integrity: sha512-d}', '',
    '  typescript@5.6.3:', '    resolution: {integrity: sha512-e}', '    hasBin: true', '',
    'snapshots:', '', '  next@15.0.3(react@19.0.0):', '    dependencies:', "      '@next/env': 15.0.3", '',
  ].join('\n');
  assert.deepEqual(parsePnpmLock(v9).map((p) => `${p.name}@${p.version}:${p.dev}`),
    ['@next/env@15.0.3:false', 'next@15.0.3:false', 'typescript@5.6.3:true'], 'snapshots are not double counted');

  const bun = '{\n  "lockfileVersion": 1,\n  "workspaces": { "": { "name": "app" } },\n  "packages": {\n    "@types/node": ["@types/node@22.9.0", "", {}, "sha512-x"],\n    "hono": ["hono@4.6.10", "", {}, "sha512-y"],\n    "app": ["app@workspace:."],\n  },\n}\n';
  assert.deepEqual(parseBunLock(bun).map((p) => `${p.name}@${p.version}`), ['@types/node@22.9.0', 'hono@4.6.10', 'app@workspace:.']);
});

test('pnpm v9 and bun: transitive dev-only packages are dev, shared ones stay production', () => {
  const v9 = [
    "lockfileVersion: '9.0'", '', 'importers:', '', '  .:',
    '    dependencies:', '      express:', '        specifier: ^4.19.0', '        version: 4.19.2',
    '    devDependencies:', '      eslint:', '        specifier: ^9.0.0', '        version: 9.1.0', '',
    'packages:', '',
    '  express@4.19.2:', '    resolution: {integrity: a}', '',
    '  debug@2.6.9:', '    resolution: {integrity: b}', '',
    '  eslint@9.1.0:', '    resolution: {integrity: c}', '',
    '  minimatch@3.1.2:', '    resolution: {integrity: d}', '',
    '  string-width@4.2.3:', '    resolution: {integrity: e}', '',
    '  orphan@1.0.0:', '    resolution: {integrity: f}', '',
    'snapshots:', '',
    '  express@4.19.2:', '    dependencies:', '      debug: 2.6.9', '',
    '  eslint@9.1.0(jiti@1.0.0):', '    dependencies:', '      debug: 2.6.9', '      minimatch: 3.1.2', "      string-width-cjs: string-width@4.2.3", '',
  ].join('\n');
  assert.deepEqual(Object.fromEntries(parsePnpmLock(v9).map((p) => [p.name, p.dev])), {
    express: false, debug: false, eslint: true, minimatch: true, 'string-width': true, orphan: false,
  }, 'debug is shared with production; orphan is unreachable so it stays production');

  const bun = JSON.stringify({
    lockfileVersion: 1,
    workspaces: { '': { name: 'app', dependencies: { hono: '^4' }, devDependencies: { vitest: '^2' } } },
    packages: {
      hono: ['hono@4.6.10', '', {}, 'sha'],
      vitest: ['vitest@2.1.0', '', { dependencies: { chai: '^5', 'pretty-format': '^29' } }, 'sha'],
      chai: ['chai@5.1.0', '', {}, 'sha'],
      'pretty-format': ['pretty-format@29.7.0', '', { dependencies: { 'react-is': '^18' } }, 'sha'],
      'react-is': ['react-is@18.3.1', '', {}, 'sha'],
      'pretty-format/react-is': ['react-is@17.0.2', '', {}, 'sha'],
    },
  });
  assert.deepEqual(parseBunLock(bun).map((p) => `${p.name}@${p.version}:${p.dev}`), [
    'hono@4.6.10:false', 'vitest@2.1.0:true', 'chai@5.1.0:true', 'pretty-format@29.7.0:true',
    'react-is@18.3.1:false', 'react-is@17.0.2:true',
  ], 'nested key "pretty-format/react-is" wins over the hoisted one');
});

test('compareVersions follows semver precedence', () => {
  const sign = (a, b) => Math.sign(compareVersions(a, b));
  assert.equal(sign('2.0.0', '2.0.0-rc.1'), 1, 'release is newer than its pre-release');
  assert.equal(sign('1.0.0-alpha.2', '1.0.0-alpha.10'), -1, 'numeric identifiers compare as numbers');
  assert.equal(sign('1.0.0-alpha', '1.0.0-alpha.1'), -1);
  assert.equal(sign('1.0.0-alpha.1', '1.0.0-beta'), -1, 'numeric sorts before alphanumeric');
  assert.equal(sign('1.2.3+build.5', '1.2.3'), 0, 'build metadata is ignored');
  assert.equal(sign('10.2.7', '10.2.6'), 1);
  assert.equal(sign('5.4.0.1', '5.4'), 1);
  assert.deepEqual(upgradeTarget({ name: 'x', version: '2.0.0-rc.1' },
    [{ id: 'A', affected: [{ package: { name: 'x' }, ranges: [{ events: [{ introduced: '0' }, { fixed: '2.0.0' }] }] }] }]),
  { version: '2.0.0', partial: false }, 'a pre-release gets the real fix as upgrade target');
});

test('deps: manifests without a lockfile are reported, monorepo children and empty manifests are not', async () => {
  const p = await makeProject({
    'site/package.json': JSON.stringify({ dependencies: { express: '^4.19.0' } }),
    'api/composer.json': JSON.stringify({ require: { php: '^8.2', 'laravel/framework': '^11.0' } }),
    'tools/package.json': JSON.stringify({ name: 'tools', private: true }),
    'mono/package-lock.json': JSON.stringify({ lockfileVersion: 3, packages: {} }),
    'mono/package.json': JSON.stringify({ workspaces: ['apps/*'], devDependencies: { turbo: '^2.0.0' } }),
    'mono/apps/web/package.json': JSON.stringify({ dependencies: { next: '^15.0.0' } }),
    'bunapp/bun.lockb': 'binary',
    'bunapp/package.json': JSON.stringify({ dependencies: { hono: '^4.0.0' } }),
  });
  try {
    const { files, lockfiles } = await collectFiles(p.root);
    const found = await scanDeps(lockfiles, { files, offline: true });
    assert.deepEqual(found.filter((f) => f.id === 'deps-no-lockfile').map((f) => f.location).sort(),
      ['api/composer.json', 'site/package.json']);
  } finally {
    await p.cleanup();
  }
});

function serve(handler) {
  return new Promise((resolve) => {
    const server = http.createServer(handler).listen(0, '127.0.0.1', () => {
      resolve({ url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((r) => server.close(r)) });
    });
  });
}

test('headers: a sloppy server gets flagged', async () => {
  const s = await serve((req, res) => {
    if (req.url === '/.env') return res.end('APP_NAME=Laravel\nAPP_KEY=base64:abc\n');
    if (req.url === '/.git/config') { res.statusCode = 404; return res.end(); }
    res.setHeader('X-Powered-By', 'Express');
    res.setHeader('Server', 'Apache/2.4.41 (Ubuntu)');
    res.setHeader('Set-Cookie', 'connect.sid=abc; Path=/');
    if (req.headers.origin) {
      res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
    res.end('<!doctype html><title>app</title>');
  });
  try {
    const got = ids(await scanUrl(s.url));
    for (const id of ['missing-csp', 'clickjacking', 'missing-nosniff', 'missing-referrer-policy', 'version-disclosure',
      'cors-reflects-origin', 'insecure-cookie', 'exposed-env']) {
      assert.ok(got.includes(id), `expected ${id}, got ${got}`);
    }
    assert.ok(!got.includes('exposed-git'));
    assert.ok(!got.includes('no-https'), 'localhost is exempt from the HTTPS check');
  } finally {
    await s.close();
  }
});

test('headers: a hardened server is clean and SPA fallbacks are not false positives', async () => {
  const s = await serve((req, res) => {
    res.setHeader('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none'; object-src 'none'");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=()');
    res.setHeader('Set-Cookie', 'session=abc; Path=/; HttpOnly; SameSite=Lax');
    res.end('<!doctype html><html><body>SPA</body></html>'); // same page for every path, incl. /.env
  });
  try {
    assert.deepEqual(await scanUrl(s.url), []);
  } finally {
    await s.close();
  }
});
