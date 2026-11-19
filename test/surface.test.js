import { test } from 'node:test';
import assert from 'node:assert/strict';
import { collectFiles } from '../src/files.js';
import { collectSurface, matcherToRegExp } from '../src/surface.js';
import { makeProject } from './helpers.js';

async function surface(files) {
  const p = await makeProject(files);
  try {
    return collectSurface((await collectFiles(p.root)).files);
  } finally {
    await p.cleanup();
  }
}

const rows = (s, kind) => s.endpoints.filter((e) => !kind || e.kind === kind).map((e) => `${e.method} ${e.path} ${e.auth}`).sort();

test('matcherToRegExp follows Next.js matcher syntax', () => {
  const m = (src, p) => matcherToRegExp(src).test(p);
  assert.ok(m('/dashboard/:path*', '/dashboard'));
  assert.ok(m('/dashboard/:path*', '/dashboard/a/b'));
  assert.ok(!m('/dashboard/:path*', '/dashboards'));
  assert.ok(m('/api/:path+', '/api/x'));
  assert.ok(!m('/api/:path+', '/api'));
  assert.ok(m('/users/:id', '/users/42'));
  assert.ok(!m('/users/:id', '/users/42/edit'));
  const def = '/((?!api|_next/static|_next/image|favicon.ico).*)';
  assert.ok(m(def, '/dashboard/settings'));
  assert.ok(!m(def, '/api/orders'), 'the usual "everything except api" matcher');
  assert.ok(!m(def, '/_next/static/chunk.js'));
});

const routes = {
  'src/app/api/orders/route.ts': 'export async function GET() {}',
  'src/app/api/public/route.ts': 'export async function GET() {}',
  'src/app/dashboard/api/stats/route.ts': 'export async function GET() {}',
  'src/app/api/me/route.ts': 'export async function GET() { const s = await getServerSession(); }',
};

test('Next middleware: next-auth re-export with a matcher guards only matching routes', async () => {
  const s = await surface({
    ...routes,
    'src/middleware.ts': 'export { default } from "next-auth/middleware";\nexport const config = { matcher: ["/api/orders/:path*", "/dashboard/:path*"] };\n',
  });
  assert.deepEqual(rows(s, 'next-route'), [
    'GET /api/me likely',
    'GET /api/orders middleware',
    'GET /api/public unknown',
    'GET /dashboard/api/stats middleware',
  ]);
  assert.match(s.notes[0], /src\/middleware\.ts runs an auth check; 2 routes/);
});

test('Next proxy.ts (Next 16) with Clerk public routes and no matcher', async () => {
  const s = await surface({
    ...routes,
    'proxy.ts': [
      "import { clerkMiddleware, createRouteMatcher } from '@clerk/nextjs/server';",
      "const isPublicRoute = createRouteMatcher(['/api/public(.*)', '/sign-in(.*)']);",
      'export default clerkMiddleware(async (auth, req) => { if (!isPublicRoute(req)) await auth.protect(); });',
    ].join('\n'),
  });
  assert.deepEqual(rows(s, 'next-route'), [
    'GET /api/me likely',
    'GET /api/orders middleware',
    'GET /api/public unknown',
    'GET /dashboard/api/stats middleware',
  ]);
});

test('Next middleware is not counted when it has no auth logic or only conditional matchers', async () => {
  const noAuth = await surface({ ...routes, 'middleware.ts': 'export function middleware(req) { return NextResponse.next(); }\nexport const config = { matcher: "/api/:path*" };' });
  assert.ok(rows(noAuth, 'next-route').every((r) => !r.endsWith('middleware')));
  assert.match(noAuth.notes[0], /no auth check was found/);

  const conditional = await surface({
    ...routes,
    'middleware.ts': [
      'export async function middleware(req) { const token = await getToken({ req }); if (!token) return NextResponse.redirect(new URL("/login", req.url)); }',
      'export const config = { matcher: [{ source: "/api/:path*", has: [{ type: "header", key: "x-internal" }] }] };',
    ].join('\n'),
  });
  assert.ok(rows(conditional, 'next-route').every((r) => !r.endsWith('middleware')), 'has/missing conditions cannot be evaluated, so no claim');
});

test('Express: mount prefixes nest, inline require works, auth middleware in front of a router counts', async () => {
  const s = await surface({
    'server.js': [
      "const express = require('express');",
      "const apiRouter = require('./routes/api');",
      'const app = express();',
      "app.get('/health', (req, res) => res.send('ok'));",
      "app.use('/api', apiRouter);",
      "app.use('/admin', requireAdmin, require('./routes/admin'));",
      'const hooks = express.Router();',
      "hooks.post('/stripe', handleStripe);",
      "app.use('/webhooks', hooks);",
      "app.use('/assets', express.static('public'));",
    ].join('\n'),
    'routes/api.js': [
      "const router = require('express').Router();",
      "import usersRouter from './users.js';",
      "router.get('/status', status);",
      "router.use('/users', requireAuth, usersRouter);",
      'module.exports = router;',
    ].join('\n'),
    'routes/users.js': "const router = require('express').Router();\nrouter.get('/', list);\nrouter.delete('/:id', remove);\nexport default router;\n",
    'routes/admin.js': "const router = require('express').Router();\nrouter.post('/purge', purge);\nmodule.exports = router;\n",
  });
  assert.deepEqual(rows(s, 'express'), [
    'DELETE /api/users/:id likely',
    'GET /api/status unknown',
    'GET /api/users likely',
    'GET /health unknown',
    'POST /admin/purge likely',
    'POST /webhooks/stripe unknown',
  ]);
});
