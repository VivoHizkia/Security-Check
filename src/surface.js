import { isTestPath, lineOf } from './files.js';
import { routesWithProtection } from './scanners/laravel.js';

// Attack-surface inventory of the scanned project's own code: every endpoint a visitor can reach,
// and whether something visibly guards it. `auth` is one of:
//   required  – auth middleware is attached (Laravel: route, group or controller)
//   none      – nothing guards it (Laravel only, where this can be known from the code)
//   likely    – the handler calls something that looks like an auth/session check
//   unknown   – nothing found in the handler; it may still be guarded by middleware elsewhere

const HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
const AUTH_CALL = /\b(?:auth|getServerSession|jwtVerify|validateRequest|withAuth|(?:require|current|getCurrent|get|verify|ensure|check|validate|assert)(?:User|Account|Session|Auth|Admin|Member|Viewer|Token|Login)\w*)\s*\(|supabase\.auth\.|\bclerkClient\b/;
const EXPRESS_AUTH = /\b(?:auth\w*|requireAuth|isAuthenticated|ensureAuth\w*|protect|verifyToken|checkJwt|jwtAuth|passport\.authenticate|authorize\w*|isAdmin|requireAdmin|requireRole)\b/;
const JS_FILE = /\.[cm]?[jt]sx?$/;

/** app/(shop)/products/[id]/route.ts → /products/{id} */
export function nextRoutePath(rel) {
  const m = rel.match(/(?:^|\/)(?:src\/)?(app|pages)\/(.*)$/);
  if (!m) return null;
  const parts = m[2].split('/');
  parts.pop(); // route.ts, or the pages/api file name (handled by the caller)
  const segments = parts
    .filter((s) => !/^\(.*\)$/.test(s) && !s.startsWith('@'))
    .map((s) => s.replace(/^\[\[?\.\.\.(\w+)\]\]?$/, '{...$1}').replace(/^\[(\w+)\]$/, '{$1}'));
  return `/${segments.join('/')}`.replace(/\/+$/, '') || '/';
}

function nextAppRoutes(file) {
  if (!/(?:^|\/)(?:src\/)?app\/(?:.*\/)?route\.[cm]?[jt]sx?$/.test(file.rel)) return [];
  const path = nextRoutePath(file.rel);
  const methods = HTTP_METHODS.filter((m) => new RegExp(`export\\s+(?:async\\s+)?(?:function\\s+${m}\\b|const\\s+${m}\\b)|export\\s*\\{[^}]*\\b${m}\\b`).test(file.text));
  const auth = AUTH_CALL.test(file.text) ? 'likely' : 'unknown';
  return (methods.length ? methods : ['ANY']).map((method) => ({ kind: 'next-route', method, path, file: file.rel, line: 1, auth }));
}

function nextPagesApi(file) {
  const m = file.rel.match(/(?:^|\/)(?:src\/)?pages\/(api\/.*)\.[cm]?[jt]sx?$/);
  if (!m) return [];
  const route = m[1].replace(/\/index$/, '').split('/')
    .map((s) => s.replace(/^\[\[?\.\.\.(\w+)\]\]?$/, '{...$1}').replace(/^\[(\w+)\]$/, '{$1}')).join('/');
  return [{ kind: 'next-pages-api', method: 'ANY', path: `/${route}`, file: file.rel, line: 1, auth: AUTH_CALL.test(file.text) ? 'likely' : 'unknown' }];
}

/** Server Actions are POST endpoints anyone can call, even if no form on the site uses them. */
function serverActions(file) {
  const head = file.text.replace(/^(?:\s*(?:\/\/[^\n]*|\/\*[\s\S]*?\*\/))*\s*/, '');
  if (!/^['"]use server['"]/.test(head)) return [];
  const out = [];
  for (const m of file.text.matchAll(/export\s+(?:async\s+function\s+(\w+)|const\s+(\w+)\s*=\s*async\b)/g)) {
    const name = m[1] || m[2];
    const next = file.text.slice(m.index + m[0].length).search(/\nexport\s/);
    const body = file.text.slice(m.index, next === -1 ? undefined : m.index + m[0].length + next);
    out.push({ kind: 'server-action', method: 'POST', path: `action:${name}`, file: file.rel, line: lineOf(file.text, m.index), auth: AUTH_CALL.test(body) ? 'likely' : 'unknown' });
  }
  return out;
}

function expressRoutes(file) {
  const out = [];
  const re = /\b(?:app|router|\w+Router|api|server)\.(get|post|put|patch|delete|all)\s*\(\s*(['"`])(\/[^'"`]*)\2([^\n]*)/g;
  for (const m of file.text.matchAll(re)) {
    out.push({ kind: 'express', method: m[1] === 'all' ? 'ANY' : m[1].toUpperCase(), path: m[3], file: file.rel,
      line: lineOf(file.text, m.index), auth: EXPRESS_AUTH.test(m[4]) ? 'likely' : 'unknown' });
  }
  return out;
}

export function collectSurface(files) {
  const endpoints = [];
  for (const r of routesWithProtection(files)) {
    endpoints.push({ kind: 'laravel', method: r.verb === 'any' ? 'ANY' : r.verb === 'match' ? 'MATCH' : r.verb.toUpperCase(),
      path: r.uri, file: r.file, line: r.line, auth: r.protected ? 'required' : 'none', admin: r.admin });
  }
  for (const file of files) {
    if (!JS_FILE.test(file.name) || isTestPath(file.rel)) continue;
    endpoints.push(...nextAppRoutes(file), ...nextPagesApi(file), ...serverActions(file));
    if (!/(?:^|\/)(?:src\/)?(?:app|pages)\//.test(file.rel) && /\bexpress\b|Router\(\)/.test(file.text)) endpoints.push(...expressRoutes(file));
  }
  const nextMiddleware = files.find((f) => /^(?:src\/)?middleware\.[cm]?[jt]s$/.test(f.rel));
  return {
    endpoints: endpoints.sort((a, b) => a.path.localeCompare(b.path) || a.method.localeCompare(b.method)),
    notes: nextMiddleware ? [`Next.js middleware (${nextMiddleware.rel}) may guard routes marked "unknown"; check its matcher.`] : [],
  };
}
