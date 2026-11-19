import { finding } from '../findings.js';
import { isTestPath, lineOf } from '../files.js';

const SCANNER = 'laravel';

// Middleware that stops anonymous visitors. `guest`, `throttle`, `web` do not.
const AUTH_MIDDLEWARE = /^(?:auth\b|auth:|can:|role|permission|verified|password\.confirm|signed|abilities|ability|sanctum|jwt|admin|is[_-]?admin|ensure\w*(?:admin|auth|role)|\w*(?:Authenticate|Admin|Role|Permission)\w*$)/i;
const ADMIN_SEGMENT = /^(?:admin|administrator|superadmin|backoffice|back-office|backend|dashboard|panel|cpanel|cp|manage|management|cms|internal|staff|moderator)$/i;
// Pages that must stay reachable for guests even under /admin.
const GUEST_SEGMENT = /^(?:login|signin|sign-in|logout|register|forgot-password|reset-password|password|two-factor-challenge)$/i;
const ROUTE_VERBS = 'get|post|put|patch|delete|options|any|match|resource|apiResource|resources|apiResources|view';
const SKIP_ROUTE_FILES = /(?:^|\/)(?:console|channels)\.php$/;

// ── A tiny PHP lexer ─────────────────────────────────────────────────
// Returns two strings with the same length as the input:
//   code:   comments blanked out, everything else intact (used to extract values)
//   shape:  additionally string contents blanked (used to match brackets safely)

export function lexPhp(src) {
  const code = src.split('');
  const shape = src.split('');
  const blank = (arr, i) => { if (arr[i] !== '\n') arr[i] = ' '; };
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    const n = src[i + 1];
    if ((c === '/' && n === '/') || (c === '#' && n !== '[')) {
      while (i < src.length && src[i] !== '\n') { blank(code, i); blank(shape, i); i++; }
    } else if (c === '/' && n === '*') {
      const end = src.indexOf('*/', i + 2);
      const stop = end === -1 ? src.length : end + 2;
      for (; i < stop; i++) { blank(code, i); blank(shape, i); }
    } else if (c === '\'' || c === '"') {
      i++;
      while (i < src.length && src[i] !== c) {
        if (src[i] === '\\') { blank(shape, i); i++; }
        blank(shape, i);
        i++;
      }
      i++;
    } else {
      i++;
    }
  }
  return { code: code.join(''), shape: shape.join('') };
}

const OPEN = { '(': ')', '[': ']', '{': '}' };

/** Index just past the bracket that closes the one at `start`, using the string-blanked shape. */
function closeOf(shape, start) {
  const stack = [];
  for (let i = start; i < shape.length; i++) {
    const c = shape[i];
    if (OPEN[c]) stack.push(OPEN[c]);
    else if (c === ')' || c === ']' || c === '}') {
      if (stack.pop() !== c) return -1;
      if (!stack.length) return i + 1;
    }
  }
  return -1;
}

/** End of the statement starting at `start`: the first `;` outside any brackets. */
function statementEnd(shape, start, limit) {
  let depth = 0;
  for (let i = start; i < limit; i++) {
    const c = shape[i];
    if (OPEN[c]) depth++;
    else if (c === ')' || c === ']' || c === '}') depth--;
    else if (c === ';' && depth <= 0) return i + 1;
    if (depth < 0) return i;
  }
  return limit;
}

const strings = (text) => [...text.matchAll(/'([^'\\]*(?:\\.[^'\\]*)*)'|"([^"\\]*(?:\\.[^"\\]*)*)"/g)].map((m) => m[1] ?? m[2]);
const classes = (text) => [...text.matchAll(/([A-Za-z_\\][\w\\]*)::class/g)].map((m) => m[1].split('\\').pop());

/** Middleware, prefix and controller declared by a route chain or group attribute array. */
function readChain(text) {
  const middleware = [];
  const without = [];
  let prefix = '';
  for (const m of text.matchAll(/(withoutMiddleware|middleware)\s*\(\s*(\[[^\]]*\]|[^)]*)\)|['"](middleware|excluded_middleware)['"]\s*=>\s*(\[[^\]]*\]|['"][^'"]*['"])/g)) {
    const raw = m[2] ?? m[4];
    const names = [...strings(raw), ...classes(raw)];
    if (m[1] === 'withoutMiddleware' || m[3] === 'excluded_middleware') without.push(...names);
    else middleware.push(...names);
  }
  for (const m of text.matchAll(/prefix\s*\(\s*['"]([^'"]*)['"]|['"]prefix['"]\s*=>\s*['"]([^'"]*)['"]/g)) {
    prefix = joinUri(prefix, m[1] ?? m[2]);
  }
  const controller = text.match(/(?:Route::|->)\s*controller\s*\(\s*([\w\\]+)::class/)?.[1]?.split('\\').pop();
  return { middleware, without, prefix, controller };
}

function joinUri(a, b) {
  return [a, b].map((s) => (s || '').replace(/^\/+|\/+$/g, '')).filter(Boolean).join('/');
}

function extend(ctx, chain) {
  return {
    prefix: joinUri(ctx.prefix, chain.prefix),
    middleware: [...ctx.middleware, ...chain.middleware].filter((m) => !chain.without.includes(m)),
    controller: chain.controller || ctx.controller,
  };
}

/**
 * Walk one route file. Returns routes with their effective prefix/middleware,
 * plus route files it pulls in (require / ->group(base_path(...))) with the context they inherit.
 */
export function parseRoutes(src, baseCtx = { prefix: '', middleware: [], controller: null }) {
  const { code, shape } = lexPhp(src);
  const routes = [];
  const includes = [];

  const walk = (from, to, ctx) => {
    const re = /\bRoute::|\b(?:require|include)(?:_once)?\b/g;
    re.lastIndex = from;
    let m;
    while ((m = re.exec(shape)) && m.index < to) {
      const end = statementEnd(shape, m.index, to);
      const stmt = code.slice(m.index, end);

      if (!m[0].startsWith('Route::')) {
        const file = stmt.match(/['"]\/?((?:[\w.-]+\/)*[\w.-]+\.php)['"]/)?.[1];
        if (file) includes.push({ file: file.split('/').pop(), ctx });
        re.lastIndex = end;
        continue;
      }

      const groupAt = stmt.search(/(?:->|Route::)\s*group\s*\(/);
      if (groupAt !== -1) {
        const groupCtx = extend(ctx, readChain(stmt.slice(0, groupAt) + attrArray(stmt.slice(groupAt))));
        const fileArg = stmt.slice(groupAt).match(/['"]\/?(?:\.\.\/)*(?:routes\/)?([\w.-]+\.php)['"]/);
        const bodyRel = shape.slice(m.index + groupAt, end).search(/\{/);
        if (fileArg && !/function|fn\s*\(/.test(stmt.slice(groupAt))) {
          includes.push({ file: fileArg[1], ctx: groupCtx });
        } else if (bodyRel !== -1) {
          const open = m.index + groupAt + bodyRel;
          const close = closeOf(shape, open);
          if (close !== -1) walk(open + 1, close - 1, groupCtx);
        }
        re.lastIndex = end;
        continue;
      }

      const verb = stmt.match(new RegExp(`(?:Route::|->)\\s*(${ROUTE_VERBS})\\s*\\(`));
      if (verb) routes.push(readRoute(stmt, shape.slice(m.index, end), verb, ctx, lineOf(src, m.index)));
      re.lastIndex = end;
    }
  };

  walk(0, shape.length, baseCtx);
  return { routes, includes };
}

/** One route definition: its URI, target and the middleware chained before or after the verb call. */
function readRoute(stmt, stmtShape, verb, ctx, line) {
  const open = verb.index + verb[0].length - 1;
  const close = closeOf(stmtShape, open);
  const args = stmt.slice(open + 1, close === -1 ? stmt.length : close - 1);
  // String arguments before the action ([X::class, 'm'], X::class or a closure).
  const head = args.split(/,\s*(?=\[\s*[\w\\]+::class|[\w\\]+::class|(?:static\s+)?function\b|fn\b)/)[0];
  const argStrings = strings(head);
  const uri = verb[1] === 'match'
    ? strings(head.replace(/^\s*\[[^\]]*\]/, ''))[0]
    : argStrings[0];
  const action = args.match(/\[\s*([\w\\]+)::class\s*,\s*['"](\w+)['"]\s*\]/);
  const invokable = args.match(/^\s*['"][^'"]*['"]\s*,\s*([\w\\]+)::class/);
  const atString = args.match(/['"]([\w\\]+)@(\w+)['"]/);
  const routeCtx = extend(ctx, readChain(stmt.slice(0, verb.index) + (close === -1 ? '' : stmt.slice(close))));
  const controller = (action?.[1] || invokable?.[1] || atString?.[1] || routeCtx.controller || '').split('\\').pop() || null;
  const method = action?.[2] || atString?.[2]
    || (routeCtx.controller && !action && !invokable && verb[1] !== 'view' ? argStrings[1] : null) || null;
  return { verb: verb[1], uri: `/${joinUri(routeCtx.prefix, uri ?? '')}`, controller: verb[1] === 'view' ? null : controller,
    method, middleware: routeCtx.middleware, line };
}

/** For Route::group([...], function () {}) the attributes live in the first argument. */
function attrArray(groupCall) {
  const m = groupCall.match(/group\s*\(\s*(\[[\s\S]*?\])\s*,/);
  return m ? m[1] : '';
}

// ── Controller middleware ───────────────────────────────────────────

/** Map of controller class name → function(method) telling whether the controller itself requires auth. */
export function controllerGuards(files) {
  const guards = new Map();
  for (const file of files) {
    if (!/\.php$/.test(file.name) || !/Controller/.test(file.text)) continue;
    const cls = file.text.match(/\bclass\s+(\w+)/)?.[1];
    if (!cls) continue;
    const { code } = lexPhp(file.text);
    const rules = [];
    // Laravel ≤10: $this->middleware('auth')->except(['index'])
    for (const m of code.matchAll(/\$this->middleware\s*\(([^;]*?)\)([^;]*);/g)) {
      const names = [...strings(m[1]), ...classes(m[1])];
      if (!names.some((n) => AUTH_MIDDLEWARE.test(n))) continue;
      rules.push(scopeRule(m[2]));
    }
    // Laravel 11: static function middleware(): array { return ['auth', new Middleware('auth', except: [...])]; }
    const body = code.match(/static\s+function\s+middleware\s*\(\s*\)[^{]*\{([\s\S]*?)\n\s*\}/)?.[1];
    if (body) {
      for (const entry of body.matchAll(/new\s+Middleware\s*\(([^;]*?)\)(?=\s*[,\]])|(['"][^'"]+['"])/g)) {
        const text = entry[1] ?? entry[2];
        const first = text.split(',')[0];
        const names = [...strings(first), ...classes(first)];
        if (!names.some((n) => AUTH_MIDDLEWARE.test(n))) continue;
        rules.push(scopeRule(text.replace(/^[^,]*/, '').replace(/(only|except)\s*:/g, '->$1(')));
      }
    }
    if (rules.length) guards.set(cls, (method) => rules.some((r) => r(method)));
  }
  return guards;
}

function scopeRule(tail) {
  const only = tail.match(/only\s*\(\s*(\[[^\]]*\]|['"][^'"]*['"])/);
  const except = tail.match(/except\s*\(\s*(\[[^\]]*\]|['"][^'"]*['"])/);
  return (method) => {
    if (!method) return !only; // resource / unknown method: protected unless the guard is method-scoped
    if (only) return strings(only[1]).includes(method);
    if (except) return !strings(except[1]).includes(method);
    return true;
  };
}

// ── Checks ──────────────────────────────────────────────────────────

const isLaravel = (files) => files.some((f) => f.rel === 'artisan')
  || files.some((f) => f.name === 'composer.json' && /"laravel\/framework"/.test(f.text));

function isAdminUri(uri) {
  const segments = uri.split('/').filter((s) => s && !s.startsWith('{'));
  return segments.some((s) => ADMIN_SEGMENT.test(s)) && !segments.some((s) => GUEST_SEGMENT.test(s));
}

/** All routes of a project with the context of whatever file includes them. */
export function collectRoutes(files) {
  const routeFiles = files.filter((f) => /(?:^|\/)routes\/.+\.php$/.test(f.rel) && !SKIP_ROUTE_FILES.test(f.rel) && !isTestPath(f.rel));
  const loaders = files.filter((f) => /\.php$/.test(f.name) && !routeFiles.includes(f)
    && /group\s*\(\s*(?:base_path|__DIR__)/.test(f.text));

  // Contexts handed to a route file by whoever loads it (bootstrap/app.php, a RouteServiceProvider, a parent route file).
  const inherited = new Map();
  for (const f of [...loaders, ...routeFiles]) {
    for (const inc of parseRoutes(f.text).includes) if (!inherited.has(inc.file)) inherited.set(inc.file, inc.ctx);
  }

  const out = [];
  for (const f of routeFiles) {
    const name = f.rel.split('/').pop();
    const base = inherited.get(name)
      ?? { prefix: name === 'api.php' ? 'api' : '', middleware: [], controller: null };
    for (const r of parseRoutes(f.text, base).routes) out.push({ ...r, file: f.rel });
  }
  return out;
}

/** Every route with `protected` = auth middleware on the route, a group, or the controller. */
export function routesWithProtection(files) {
  if (!isLaravel(files)) return [];
  const guards = controllerGuards(files);
  return collectRoutes(files).map((r) => ({
    ...r,
    admin: isAdminUri(r.uri),
    protected: r.middleware.some((m) => AUTH_MIDDLEWARE.test(m)) || Boolean(r.controller && guards.get(r.controller)?.(r.method)),
  }));
}

function checkRoutes(files, add) {
  for (const r of routesWithProtection(files)) {
    if (!r.admin) continue;
    const target = r.controller ? `${r.controller}${r.method ? `@${r.method}` : ''}` : r.verb === 'view' ? 'view' : 'closure';
    const verb = r.verb.toUpperCase();

    if (!r.protected) {
      add({ id: 'laravel-admin-route-no-auth', severity: 'high', title: 'Admin route reachable without authentication',
        location: `${r.file}:${r.line}`,
        detail: `${verb} ${r.uri} → ${target}: no auth middleware on the route, its groups or the controller.`,
        fix: "Put it inside Route::middleware(['auth', 'can:admin'])->group(...), or guard the controller." });
    }
    if (r.verb === 'any') {
      add({ id: 'laravel-route-any-admin', severity: 'medium', title: 'Route::any on an admin path',
        location: `${r.file}:${r.line}`,
        detail: `${r.uri} also answers GET, and Laravel skips CSRF checks for GET, so a link or <img> can trigger it.`,
        fix: 'Declare the real verbs: Route::post(...) / Route::delete(...), or Route::match([\'post\'], ...).' });
    }
  }
}

function checkCsrf(files, add) {
  for (const file of files) {
    if (!/\.php$/.test(file.name) || isTestPath(file.rel)) continue;
    const { code } = lexPhp(file.text);
    const m = code.match(/(?:\$except\s*=|validateCsrfTokens\s*\(\s*except\s*:)\s*\[([^\]]*)\]/);
    if (!m) continue;
    if (strings(m[1]).some((p) => /^\/?\*$/.test(p.trim()))) {
      add({ id: 'laravel-csrf-disabled', severity: 'high', title: 'CSRF protection disabled for every route',
        location: `${file.rel}:${lineOf(code, m.index)}`,
        detail: "The CSRF except list contains '*', so any website can submit forms as your logged-in users.",
        fix: "List only the webhook paths that need it, e.g. ['stripe/webhook']." });
    }
  }
}

function checkComposer(files, add) {
  for (const file of files.filter((f) => f.name === 'composer.json')) {
    let json;
    try { json = JSON.parse(file.text); } catch { continue; }
    for (const pkg of ['barryvdh/laravel-debugbar', 'laravel/telescope']) {
      if (json.require?.[pkg]) {
        add({ id: 'laravel-debug-tool-in-require', severity: 'low', title: `${pkg} is a production dependency`,
          location: file.rel,
          detail: 'Debug tooling installed on the server can expose queries, requests and session data if it is ever enabled.',
          fix: `composer remove ${pkg} && composer require --dev ${pkg}` });
      }
    }
  }
}

export function scanLaravel(files) {
  if (!isLaravel(files)) return [];
  const findings = [];
  const add = (f) => findings.push(finding({ scanner: SCANNER, ...f }));
  checkRoutes(files, add);
  checkCsrf(files, add);
  checkComposer(files, add);
  return findings;
}
