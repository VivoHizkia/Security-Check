import path from 'node:path';
import { isTestPath, lineOf } from './files.js';
import { routesWithProtection } from './scanners/laravel.js';

// Attack-surface inventory of the scanned project's own code: every endpoint a visitor can reach,
// and whether something visibly guards it. `auth` is one of:
//   required    – auth middleware is attached (Laravel: route, group or controller)
//   none        – nothing guards it (Laravel only, where this can be known from the code)
//   likely      – the handler, or middleware mounted in front of it, calls an auth/session check
//   middleware  – Next.js middleware/proxy whose matcher covers this path runs an auth check
//   unknown     – nothing found; it may still be guarded somewhere tameng cannot see

const HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
const AUTH_CALL = /\b(?:auth|getServerSession|jwtVerify|validateRequest|withAuth|getToken|(?:require|current|getCurrent|get|verify|ensure|check|validate|assert|update)(?:User|Account|Session|Auth|Admin|Member|Viewer|Token|Login)\w*)\s*\(|supabase\.auth\.|\bclerkClient\b|\bclerkMiddleware\b|\.protect\s*\(/;
const EXPRESS_AUTH = /\b(?:auth\w*|requireAuth|isAuthenticated|ensureAuth\w*|protect|verifyToken|checkJwt|jwtAuth|passport\.authenticate|authorize\w*|isAdmin|requireAdmin|requireRole)\b/;
const JS_FILE = /\.[cm]?[jt]sx?$/;

const segmentsToPath = (segments) => `/${segments
  .filter((s) => !/^\(.*\)$/.test(s) && !s.startsWith('@'))
  .map((s) => s.replace(/^\[\[?\.\.\.(\w+)\]\]?$/, '{...$1}').replace(/^\[(\w+)\]$/, '{$1}'))
  .join('/')}`.replace(/\/+$/, '') || '/';

/** app/(shop)/products/[id]/route.ts → /products/{id} */
export function nextRoutePath(rel) {
  const m = rel.match(/(?:^|\/)(?:src\/)?(app|pages)\/(.*)$/);
  if (!m) return null;
  return segmentsToPath(m[2].split('/').slice(0, -1));
}

function nextAppRoutes(file) {
  if (!/(?:^|\/)(?:src\/)?app\/(?:.*\/)?route\.[cm]?[jt]sx?$/.test(file.rel)) return [];
  const route = nextRoutePath(file.rel);
  const methods = HTTP_METHODS.filter((m) => new RegExp(`export\\s+(?:async\\s+)?(?:function\\s+${m}\\b|const\\s+${m}\\b)|export\\s*\\{[^}]*\\b${m}\\b`).test(file.text));
  const auth = AUTH_CALL.test(file.text) ? 'likely' : 'unknown';
  return (methods.length ? methods : ['ANY']).map((method) => ({ kind: 'next-route', method, path: route, file: file.rel, line: 1, auth }));
}

function nextPagesApi(file) {
  const m = file.rel.match(/(?:^|\/)(?:src\/)?pages\/(api\/.*)\.[cm]?[jt]sx?$/);
  if (!m) return [];
  const route = segmentsToPath(m[1].replace(/\/index$/, '').split('/'));
  return [{ kind: 'next-pages-api', method: 'ANY', path: route, file: file.rel, line: 1, auth: AUTH_CALL.test(file.text) ? 'likely' : 'unknown' }];
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

// ── Next.js middleware / proxy ──────────────────────────────────────

const quoted = (text) => [...text.matchAll(/(['"`])((?:\\.|(?!\1).)*)\1/g)].map((m) => m[2]);

/** path-to-regexp subset used by Next matchers: /a/:p*, /a/:p+, /a/:p?, :p, and raw (regex) groups. */
export function matcherToRegExp(source) {
  let out = '';
  for (let i = 0; i < source.length;) {
    const rest = source.slice(i);
    let m;
    if (rest[0] === '(') {
      let depth = 0;
      let j = i;
      for (; j < source.length; j++) {
        if (source[j] === '\\') { j++; continue; }
        if (source[j] === '(') depth++;
        else if (source[j] === ')' && --depth === 0) break;
      }
      out += `(?:${source.slice(i + 1, j)})`;
      i = j + 1;
    } else if ((m = rest.match(/^\/:(\w+)([*+?])/))) {
      out += m[2] === '*' ? '(?:/.*)?' : m[2] === '+' ? '/.+' : '(?:/[^/]+)?';
      i += m[0].length;
    } else if ((m = rest.match(/^:(\w+)(?:\(([^)]*)\))?/))) {
      out += m[2] ? `(?:${m[2]})` : '[^/]+';
      i += m[0].length;
    } else {
      out += rest[0].replace(/[.+*?^${}|[\]\\]/g, '\\$&');
      i += 1;
    }
  }
  try {
    return new RegExp(`^${out}/?$`);
  } catch {
    return null;
  }
}

/** Top-level elements of `matcher: [...]` (or the single string), split with bracket and string awareness. */
function matcherElements(text) {
  const at = text.search(/\bmatcher\s*:/);
  if (at === -1) return null;
  let i = text.indexOf(':', at) + 1;
  while (/\s/.test(text[i])) i++;
  if (text[i] !== '[') return quoted(text.slice(i, i + 500)).slice(0, 1);
  const out = [];
  let depth = 0;
  let start = i + 1;
  let quote = null;
  for (let j = i; j < text.length; j++) {
    const c = text[j];
    if (quote) { if (c === '\\') j++; else if (c === quote) quote = null; continue; }
    if (c === '"' || c === "'" || c === '`') quote = c;
    else if (c === '[' || c === '{' || c === '(') depth++;
    else if (c === ']' || c === '}' || c === ')') {
      depth--;
      if (depth === 0) { out.push(text.slice(start, j)); break; }
    } else if (c === ',' && depth === 1) { out.push(text.slice(start, j)); start = j + 1; }
  }
  return out.map((s) => s.trim()).filter(Boolean);
}

/**
 * Reads middleware.ts / proxy.ts. Returns null when it has no auth logic, otherwise a function
 * telling whether a request path is covered by it. Matchers with has/missing conditions are skipped
 * (tameng cannot evaluate them, so it does not claim protection for them).
 */
export function nextMiddlewareGuard(files) {
  const file = files.find((f) => /^(?:src\/)?(?:middleware|proxy)\.[cm]?[jt]s$/.test(f.rel));
  if (!file) return null;
  const text = file.text;
  const reExportsAuth = /export\s*\{\s*default\s*\}\s*from\s*['"](?:next-auth\/middleware|@clerk\/nextjs)/.test(text);
  if (!reExportsAuth && !AUTH_CALL.test(text) && !/cookies\.get\s*\(\s*['"`][^'"`]*(?:session|token|auth|sid)/i.test(text)) {
    return { file: file.rel, covers: () => false, hasAuth: false };
  }

  let matchers = null; // null = middleware runs for every path
  const elements = matcherElements(text);
  if (elements) {
    matchers = elements
      .map((el) => (el.startsWith('{')
        ? (/\b(?:has|missing)\s*:/.test(el) ? null : el.match(/source\s*:\s*(['"`])(.*?)\1/)?.[2])
        : quoted(el)[0]))
      .filter(Boolean)
      .map(matcherToRegExp)
      .filter(Boolean);
  }

  // Clerk-style route matchers narrow (or widen) what the auth logic applies to.
  const routeMatcher = (name) => {
    const m = text.match(new RegExp(`${name}\\s*=\\s*createRouteMatcher\\s*\\(\\s*(\\[[\\s\\S]*?\\])`));
    return m ? quoted(m[1]).map((p) => matcherToRegExp(p.replace(/\(\.\*\)$/, '/:rest*'))).filter(Boolean) : null;
  };
  const protectedOnly = routeMatcher('isProtectedRoute');
  const publicRoutes = routeMatcher('isPublicRoute');

  const covers = (p) => {
    if (matchers && !matchers.some((re) => re.test(p))) return false;
    if (protectedOnly) return protectedOnly.some((re) => re.test(p));
    if (publicRoutes) return !publicRoutes.some((re) => re.test(p));
    return true;
  };
  return { file: file.rel, covers, hasAuth: true };
}

/** /api/files/{...path} → /api/files/x/y so it can be tested against a matcher. */
const samplePath = (p) => p.replace(/\{\.\.\.\w+\}/g, 'x/y').replace(/\{\w+\}/g, 'x1');

// ── Express ─────────────────────────────────────────────────────────

const ROUTE_CALL = /\b(\w+)\.(get|post|put|patch|delete|all)\s*\(\s*(['"`])(\/[^'"`]*)\3([^\n]*)/g;

function resolveImport(fromRel, spec, known) {
  if (!spec.startsWith('.')) return null;
  const base = path.posix.normalize(path.posix.join(path.posix.dirname(fromRel), spec));
  const candidates = [base, ...['.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx'].flatMap((ext) => [base + ext, `${base}/index${ext}`])];
  return candidates.find((c) => known.has(c)) ?? null;
}

/** Local name → file, for `const x = require('./y')` and `import x from './y'`. */
function importsOf(file, known) {
  const map = new Map();
  for (const m of file.text.matchAll(/\b(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)|\bimport\s+(\w+)(?:\s*,\s*\{[^}]*\})?\s+from\s+['"]([^'"]+)['"]/g)) {
    const target = resolveImport(file.rel, m[2] || m[4], known);
    if (target) map.set(m[1] || m[3], target);
  }
  return map;
}

/**
 * app.use('/api/users', requireAuth, usersRouter) → routes in usersRouter's file get the prefix,
 * and `likely` auth when middleware in front of them looks like an auth guard. Mounts nest.
 */
function expressRoutes(files) {
  const expressFiles = files.filter((f) => JS_FILE.test(f.name) && !isTestPath(f.rel)
    && !/(?:^|\/)(?:src\/)?(?:app|pages)\//.test(f.rel) && /\bexpress\b|Router\s*\(/.test(f.text));
  const known = new Set(expressFiles.map((f) => f.rel));

  // mounts: { from, prefix, target: { file } | { file, object }, auth }
  const mounts = [];
  for (const file of expressFiles) {
    const imports = importsOf(file, known);
    for (const m of file.text.matchAll(/\b\w+\.use\s*\(\s*(['"`])(\/[^'"`]*)\1\s*,([^;]*?)\)\s*;?\s*$/gm)) {
      const args = m[3];
      const inline = args.match(/require\s*\(\s*['"]([^'"]+)['"]\s*\)\s*$/);
      const lastId = args.trim().match(/(\w+)\s*$/)?.[1];
      const targetFile = inline ? resolveImport(file.rel, inline[1], known) : imports.get(lastId);
      const target = targetFile ? { file: targetFile } : lastId ? { file: file.rel, object: lastId } : null;
      if (!target) continue;
      const guard = inline ? args.slice(0, inline.index) : args.slice(0, args.lastIndexOf(lastId));
      mounts.push({ from: file.rel, prefix: m[2], target, auth: EXPRESS_AUTH.test(guard) });
    }
  }

  // Every way a file (or a router object inside it) is reached from a root app.
  const join = (a, b) => `/${[a, b].join('/').split('/').filter(Boolean).join('/')}`;
  const reach = (file, object, seen = new Set()) => {
    const key = `${file}#${object ?? ''}`;
    if (seen.has(key)) return [];
    seen.add(key);
    const into = mounts.filter((mt) => mt.target.file === file && (object ? mt.target.object === object : !mt.target.object));
    if (!into.length) return object ? [] : [{ prefix: '', auth: false }];
    return into.flatMap((mt) => reach(mt.from, null, seen).map((p) => ({ prefix: join(p.prefix, mt.prefix), auth: p.auth || mt.auth })));
  };

  const out = [];
  for (const file of expressFiles) {
    // Objects that are an app or a router: declared from express()/Router(), or the conventional names.
    const routers = new Set(['app', 'router', 'server']);
    for (const d of file.text.matchAll(/\b(\w+)\s*=\s*(?:express\s*\(\s*\)|(?:express\s*\.\s*)?Router\s*\(|require\s*\(\s*['"]express['"]\s*\)\s*(?:\.\s*Router\s*)?\()/g)) routers.add(d[1]);
    for (const m of file.text.matchAll(ROUTE_CALL)) {
      const [, object, verb, , route, rest] = m;
      if (!routers.has(object) && !/^\w+Router$/.test(object)) continue;
      const local = reach(file.rel, object);
      const via = local.length ? local : reach(file.rel, null);
      for (const { prefix, auth } of via) {
        out.push({ kind: 'express', method: verb === 'all' ? 'ANY' : verb.toUpperCase(), path: join(prefix, route).replace(/(.)\/$/, '$1'),
          file: file.rel, line: lineOf(file.text, m.index), auth: auth || EXPRESS_AUTH.test(rest) ? 'likely' : 'unknown' });
      }
    }
  }
  return out;
}

// ── Inventory ───────────────────────────────────────────────────────

export function collectSurface(files) {
  const endpoints = [];
  for (const r of routesWithProtection(files)) {
    endpoints.push({ kind: 'laravel', method: r.verb === 'any' ? 'ANY' : r.verb === 'match' ? 'MATCH' : r.verb.toUpperCase(),
      path: r.uri, file: r.file, line: r.line, auth: r.protected ? 'required' : 'none', admin: r.admin });
  }
  for (const file of files) {
    if (!JS_FILE.test(file.name) || isTestPath(file.rel)) continue;
    endpoints.push(...nextAppRoutes(file), ...nextPagesApi(file), ...serverActions(file));
  }
  endpoints.push(...expressRoutes(files));

  const notes = [];
  const mw = nextMiddlewareGuard(files);
  if (mw?.hasAuth) {
    let covered = 0;
    for (const e of endpoints) {
      if ((e.kind === 'next-route' || e.kind === 'next-pages-api') && e.auth === 'unknown' && mw.covers(samplePath(e.path))) {
        e.auth = 'middleware';
        covered++;
      }
    }
    notes.push(`${mw.file} runs an auth check; ${covered} route${covered === 1 ? '' : 's'} fall under its matcher. Server Actions post to page URLs, so check those by hand.`);
  } else if (mw) {
    notes.push(`${mw.file} exists but no auth check was found in it, so it is not counted as protection.`);
  }
  return {
    endpoints: endpoints.sort((a, b) => a.path.localeCompare(b.path) || a.method.localeCompare(b.method)),
    notes,
  };
}
