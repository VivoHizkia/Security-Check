import { finding } from '../findings.js';

const SCANNER = 'headers';
const UA = 'tameng/0.1 (security self-scan)';
const TIMEOUT = 15_000;

/** Well-known files that should never be reachable on a production site. `test` avoids SPA catch-all false positives. */
const PROBES = [
  { path: '/.env', id: 'exposed-env', severity: 'critical', title: '.env file is publicly downloadable',
    test: (b) => /^[A-Z][A-Z0-9_]*=/m.test(b) && !/<html|<!doctype/i.test(b),
    fix: 'Point the web root at /public (Laravel) or block dotfiles in nginx: location ~ /\\. { deny all; }. Rotate every secret in it.' },
  { path: '/.git/config', id: 'exposed-git', severity: 'critical', title: '.git directory is publicly accessible',
    test: (b) => /\[core\]/.test(b),
    fix: 'Block /.git at the web server; attackers can rebuild your whole source code from it.' },
  { path: '/storage/logs/laravel.log', id: 'exposed-laravel-log', severity: 'high', title: 'Laravel log file is public',
    test: (b) => /^\[\d{4}-\d{2}-\d{2}[ T][\d:]+\]\s+\w+\.(?:ERROR|WARNING|INFO|DEBUG)/m.test(b),
    fix: 'Serve only the /public directory; logs often contain tokens, emails and stack traces.' },
  { path: '/phpinfo.php', id: 'exposed-phpinfo', severity: 'high', title: 'phpinfo() page is public',
    test: (b) => /PHP Version \d/.test(b) && /phpinfo/i.test(b), fix: 'Delete phpinfo.php from the server.' },
  { path: '/telescope/requests', id: 'exposed-telescope', severity: 'high', title: 'Laravel Telescope dashboard is public',
    test: (b) => /window\.Telescope|id="telescope"/.test(b), fix: 'Restrict Telescope with its gate in TelescopeServiceProvider, or disable it in production.' },
  { path: '/.vscode/sftp.json', id: 'exposed-sftp-config', severity: 'high', title: 'Editor SFTP config (with credentials) is public',
    test: (b) => /"host"\s*:/.test(b) && /"(?:password|privateKeyPath|username)"\s*:/.test(b), fix: 'Remove the file from the server and change the SFTP password.' },
  { path: '/server-status', id: 'exposed-server-status', severity: 'medium', title: 'Apache server-status is public',
    test: (b) => /Apache Server Status/i.test(b), fix: 'Restrict mod_status to localhost.' },
  { path: '/.DS_Store', id: 'exposed-ds-store', severity: 'low', title: '.DS_Store file is public (leaks file names)',
    test: (b) => b.includes('Bud1'), fix: 'Delete .DS_Store files from the server and block dotfiles.' },
];

function isLocalHost(hostname) {
  return /^(localhost|127\.\d+\.\d+\.\d+|\[?::1\]?|0\.0\.0\.0)$/.test(hostname) || /\.(local|test|localhost)$/.test(hostname);
}

function parseCsp(value) {
  const directives = new Map();
  for (const part of value.split(';')) {
    const [name, ...sources] = part.trim().split(/\s+/);
    if (name) directives.set(name.toLowerCase(), sources);
  }
  return directives;
}

function getSetCookies(headers) {
  if (typeof headers.getSetCookie === 'function') return headers.getSetCookie();
  const raw = headers.get('set-cookie');
  return raw ? raw.split(/,(?=\s*[^;=\s]+=)/) : [];
}

async function get(fetchFn, url, init = {}) {
  return fetchFn(url, {
    redirect: 'follow',
    ...init,
    headers: { 'user-agent': UA, ...(init.headers || {}) },
    signal: AbortSignal.timeout(TIMEOUT),
  });
}

export async function scanUrl(rawUrl, { fetch: fetchFn = globalThis.fetch, probes = true } = {}) {
  const findings = [];
  const add = (f) => findings.push(finding({ scanner: SCANNER, ...f }));

  let url;
  try {
    url = new URL(/^https?:\/\//i.test(rawUrl) ? rawUrl : `https://${rawUrl}`);
  } catch {
    add({ id: 'invalid-url', severity: 'info', title: `Invalid URL: ${rawUrl}` });
    return findings;
  }
  const local = isLocalHost(url.hostname);

  let res;
  try {
    res = await get(fetchFn, url);
  } catch (err) {
    add({ id: 'unreachable', severity: 'info', title: `Could not reach ${url.href}`, detail: err.cause?.code || err.message });
    return findings;
  }
  const finalUrl = new URL(res.url || url.href);
  const h = res.headers;
  const https = finalUrl.protocol === 'https:';
  const where = finalUrl.origin;

  // ── Transport ──────────────────────────────────────────────────────
  if (!https && !local) {
    add({ id: 'no-https', severity: 'high', title: 'Site is served over plain HTTP', location: where,
      fix: 'Enable HTTPS (Let\'s Encrypt / Cloudflare) and redirect all HTTP traffic to it.' });
  }
  if (https && !local) {
    const httpUrl = new URL(finalUrl.href);
    httpUrl.protocol = 'http:';
    try {
      const r = await get(fetchFn, httpUrl, { redirect: 'manual' });
      const loc = r.headers.get('location') || '';
      if (!(r.status >= 300 && r.status < 400 && /^https:/i.test(loc))) {
        add({ id: 'http-no-redirect', severity: 'medium', title: 'HTTP version does not redirect to HTTPS', location: httpUrl.origin,
          detail: `GET ${httpUrl.origin} → ${r.status}${loc ? ` (Location: ${loc})` : ''}`, fix: 'Return a 301 redirect from http:// to https://.' });
      }
    } catch {
      /* port 80 closed is fine */
    }

    const hsts = h.get('strict-transport-security');
    if (!hsts) {
      add({ id: 'missing-hsts', severity: 'medium', title: 'Missing Strict-Transport-Security (HSTS)', location: where,
        fix: 'Strict-Transport-Security: max-age=31536000; includeSubDomains' });
    } else {
      const maxAge = Number(hsts.match(/max-age\s*=\s*"?(\d+)/i)?.[1] ?? 0);
      if (maxAge < 15_552_000) {
        add({ id: 'weak-hsts', severity: 'low', title: 'HSTS max-age is shorter than 180 days', location: where,
          detail: `max-age=${maxAge}`, fix: 'Use max-age=31536000 (one year).' });
      }
    }
  }

  // ── Content-Security-Policy & framing ─────────────────────────────
  const cspRaw = h.get('content-security-policy');
  const csp = cspRaw ? parseCsp(cspRaw) : null;
  if (!csp) {
    add({ id: 'missing-csp', severity: 'medium', title: 'Missing Content-Security-Policy', location: where,
      detail: h.get('content-security-policy-report-only') ? 'Only a Report-Only policy is set, which enforces nothing.' : '',
      fix: "Start with: Content-Security-Policy: default-src 'self'; frame-ancestors 'self'; object-src 'none'" });
  } else {
    const script = csp.get('script-src') || csp.get('default-src') || [];
    const hasNonce = script.some((s) => /^'(nonce-|sha(256|384|512)-)/.test(s));
    const strictDynamic = script.includes("'strict-dynamic'");
    if (script.includes("'unsafe-inline'") && !hasNonce) {
      add({ id: 'csp-unsafe-inline', severity: 'medium', title: "CSP allows 'unsafe-inline' scripts", location: where,
        detail: 'Inline script injection (XSS) is not blocked.', fix: "Replace 'unsafe-inline' with nonces or hashes." });
    }
    if (script.includes("'unsafe-eval'")) {
      add({ id: 'csp-unsafe-eval', severity: 'low', title: "CSP allows 'unsafe-eval'", location: where, fix: "Remove 'unsafe-eval' if your bundle does not need it." });
    }
    if (!strictDynamic && script.some((s) => s === '*' || s === 'https:' || s === 'http:' || s === 'data:')) {
      add({ id: 'csp-wildcard-script', severity: 'medium', title: 'CSP lets scripts load from anywhere', location: where,
        detail: `script sources: ${script.join(' ')}`, fix: 'List the exact script hosts you use.' });
    }
    if (!csp.has('script-src') && !csp.has('default-src')) {
      add({ id: 'csp-no-script-src', severity: 'medium', title: 'CSP has no script-src or default-src', location: where,
        fix: "Add default-src 'self' so scripts are restricted." });
    }
  }

  const xfo = (h.get('x-frame-options') || '').toUpperCase();
  if (!/DENY|SAMEORIGIN/.test(xfo) && !csp?.has('frame-ancestors')) {
    add({ id: 'clickjacking', severity: 'medium', title: 'Page can be framed by other sites (clickjacking)', location: where,
      fix: "Send X-Frame-Options: DENY or CSP frame-ancestors 'self'." });
  }

  // ── Other headers ─────────────────────────────────────────────────
  if ((h.get('x-content-type-options') || '').toLowerCase() !== 'nosniff') {
    add({ id: 'missing-nosniff', severity: 'low', title: 'Missing X-Content-Type-Options: nosniff', location: where, fix: 'X-Content-Type-Options: nosniff' });
  }
  const referrer = h.get('referrer-policy');
  if (!referrer) {
    add({ id: 'missing-referrer-policy', severity: 'low', title: 'Missing Referrer-Policy', location: where, fix: 'Referrer-Policy: strict-origin-when-cross-origin' });
  } else if (/unsafe-url/i.test(referrer)) {
    add({ id: 'unsafe-referrer-policy', severity: 'low', title: 'Referrer-Policy leaks full URLs', location: where, detail: referrer,
      fix: 'Use strict-origin-when-cross-origin.' });
  }
  if (!h.get('permissions-policy')) {
    add({ id: 'missing-permissions-policy', severity: 'info', title: 'Missing Permissions-Policy', location: where,
      fix: 'Permissions-Policy: camera=(), microphone=(), geolocation=()' });
  }
  for (const name of ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator']) {
    const value = h.get(name);
    if (!value) continue;
    if (name === 'server' && !/\d/.test(value)) continue; // "nginx" / "cloudflare" alone is harmless
    add({ id: 'version-disclosure', severity: 'low', title: `${name} header discloses software${/\d/.test(value) ? ' version' : ''}`, location: where,
      detail: `${name}: ${value}`, fix: name === 'x-powered-by' ? 'Remove it (Express: app.disable("x-powered-by"); PHP: expose_php = Off).' : 'Hide version numbers (nginx: server_tokens off).' });
  }

  // ── CORS ──────────────────────────────────────────────────────────
  const acao = h.get('access-control-allow-origin');
  const acac = (h.get('access-control-allow-credentials') || '').toLowerCase() === 'true';
  if (acao === '*' && acac) {
    add({ id: 'cors-wildcard-credentials', severity: 'high', title: 'CORS: wildcard origin combined with credentials', location: where,
      fix: 'Return a specific trusted origin when credentials are allowed.' });
  }
  try {
    const probeOrigin = 'https://tameng-cors-check.invalid';
    const r = await get(fetchFn, finalUrl, { headers: { origin: probeOrigin } });
    if (r.headers.get('access-control-allow-origin') === probeOrigin) {
      const creds = (r.headers.get('access-control-allow-credentials') || '').toLowerCase() === 'true';
      add({ id: 'cors-reflects-origin', severity: creds ? 'high' : 'medium',
        title: creds ? 'CORS reflects any Origin and allows credentials' : 'CORS reflects any Origin', location: where,
        detail: creds ? 'Any website can make logged-in requests and read the responses.' : 'Any website can read responses from this endpoint.',
        fix: 'Compare the Origin header against an allow-list before echoing it.' });
    }
  } catch {
    /* ignore */
  }

  // ── Cookies ───────────────────────────────────────────────────────
  for (const cookie of getSetCookies(h)) {
    const [pair, ...attrs] = cookie.split(';').map((s) => s.trim());
    const name = pair.split('=')[0];
    const flags = attrs.map((a) => a.toLowerCase());
    const has = (flag) => flags.some((f) => f === flag || f.startsWith(`${flag}=`));
    const sameSite = flags.find((f) => f.startsWith('samesite='))?.split('=')[1];
    const sensitive = /sess|sid|token|auth|jwt|remember|login/i.test(name) && !/xsrf|csrf/i.test(name);
    const problems = [];
    if (https && !has('secure')) problems.push('Secure');
    if (!has('httponly') && !/xsrf|csrf/i.test(name)) problems.push('HttpOnly');
    if (!sameSite) problems.push('SameSite');
    if (sameSite === 'none' && !has('secure')) problems.push('Secure (required with SameSite=None)');
    if (!problems.length) continue;
    const severe = sensitive && (problems.includes('Secure') || problems.includes('HttpOnly'));
    add({ id: 'insecure-cookie', severity: severe ? 'medium' : 'low', title: `Cookie "${name}" is missing ${problems.join(', ')}`, location: where,
      fix: 'Set-Cookie: …; Secure; HttpOnly; SameSite=Lax' });
  }

  // ── Exposed files ─────────────────────────────────────────────────
  if (probes) {
    for (const probe of PROBES) {
      const target = new URL(probe.path, finalUrl.origin);
      try {
        const r = await get(fetchFn, target, { redirect: 'manual' });
        if (r.status !== 200) continue;
        const body = (await r.text()).slice(0, 65_536);
        if (probe.test(body)) {
          add({ id: probe.id, severity: probe.severity, title: probe.title, location: target.href, fix: probe.fix });
        }
      } catch {
        /* ignore */
      }
    }
  }

  return findings;
}
