import { finding } from '../findings.js';
import { isEnvExample, isEnvFile, isTestPath, lineOf } from '../files.js';

const SCANNER = 'config';

const PUBLIC_PREFIX = /\b((?:NEXT_PUBLIC|VITE|REACT_APP|NUXT_PUBLIC|EXPO_PUBLIC|GATSBY|PUBLIC)_[A-Z0-9_]*(?:SECRET|PRIVATE|PASSWORD|PASSWD|SERVICE_ROLE|ADMIN_KEY|DB_)[A-Z0-9_]*)\b/g;
const SOURCE_EXT = /\.(?:[cm]?[jt]sx?|vue|svelte|astro)$/;
const DB_PORTS = { 3306: 'MySQL', 5432: 'PostgreSQL', 27017: 'MongoDB', 6379: 'Redis', 9200: 'Elasticsearch', 5984: 'CouchDB', 11211: 'Memcached' };
const WEAK_DB_PASSWORDS = new Set(['root', 'password', 'secret', '123456', '12345678', 'admin', 'postgres', 'mysql', 'pass', 'changeme', 'example']);

export function parseEnv(text) {
  const vars = new Map();
  text.split(/\r?\n/).forEach((raw, i) => {
    const m = raw.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (!m) return;
    const value = m[2].replace(/\s+#.*$/, '').trim().replace(/^(['"])(.*)\1$/, '$2');
    vars.set(m[1], { value, line: i + 1 });
  });
  return vars;
}

export function scanConfig(files) {
  const findings = [];
  const add = (f) => findings.push(finding({ scanner: SCANNER, ...f }));

  checkLaravelEnv(files, add);
  checkPublicSecrets(files, add);
  checkPackageJson(files, add);
  checkCors(files, add);
  checkNext(files, add);
  checkDocker(files, add);

  return findings;
}

function checkLaravelEnv(files, add) {
  for (const file of files.filter((f) => isEnvFile(f.name))) {
    const env = parseEnv(file.text);
    const appEnv = env.get('APP_ENV')?.value?.toLowerCase();
    const isProd = appEnv === 'production' || appEnv === 'prod';
    const debug = env.get('APP_DEBUG');

    if (debug && /^(true|1)$/i.test(debug.value)) {
      add(isProd
        ? { id: 'laravel-debug-production', severity: 'critical', title: 'APP_DEBUG=true with APP_ENV=production',
            location: `${file.rel}:${debug.line}`, detail: 'Error pages will leak stack traces, env values and queries to visitors.',
            fix: 'Set APP_DEBUG=false in production, then run `php artisan config:cache`.' }
        : { id: 'laravel-debug-enabled', severity: 'info', title: 'APP_DEBUG is enabled',
            location: `${file.rel}:${debug.line}`, detail: 'Fine for local development.',
            fix: 'Make sure the production server sets APP_DEBUG=false.' });
    }
    if (isProd && env.has('APP_KEY') && !env.get('APP_KEY').value) {
      add({ id: 'laravel-missing-app-key', severity: 'high', title: 'APP_KEY is empty in a production env file',
        location: `${file.rel}:${env.get('APP_KEY').line}`, fix: 'Run `php artisan key:generate` on the server.' });
    }
    const secureCookie = env.get('SESSION_SECURE_COOKIE');
    if (isProd && env.has('APP_KEY') && (!secureCookie || !/^(true|1)$/i.test(secureCookie.value))) {
      add({ id: 'laravel-insecure-session-cookie', severity: 'low', title: 'Session cookie not forced to HTTPS',
        location: secureCookie ? `${file.rel}:${secureCookie.line}` : file.rel,
        fix: 'Set SESSION_SECURE_COOKIE=true when the site runs on HTTPS.' });
    }
  }
}

function checkPublicSecrets(files, add) {
  const seen = new Set();
  for (const file of files) {
    const relevant = isEnvFile(file.name) || isEnvExample(file.name) || (SOURCE_EXT.test(file.name) && !isTestPath(file.rel));
    if (!relevant) continue;
    PUBLIC_PREFIX.lastIndex = 0;
    let m;
    while ((m = PUBLIC_PREFIX.exec(file.text))) {
      const name = m[1];
      if (seen.has(name)) continue;
      seen.add(name);
      add({ id: 'public-env-secret', severity: 'high', title: 'Secret exposed through a browser-public env variable',
        location: `${file.rel}:${lineOf(file.text, m.index)}`,
        detail: `${name} is inlined into the client bundle; anyone can read it in DevTools.`,
        fix: 'Drop the public prefix and only use this value in server code (API route, server action, backend).' });
    }
  }
}

function checkPackageJson(files, add) {
  for (const file of files.filter((f) => f.name === 'package.json')) {
    let pkg;
    try {
      pkg = JSON.parse(file.text);
    } catch {
      continue;
    }
    const deps = { ...pkg.dependencies, ...pkg.devDependencies };
    if (pkg.dependencies?.express && !deps.helmet) {
      add({ id: 'express-no-helmet', severity: 'low', title: 'Express app without helmet', location: file.rel,
        detail: 'Express sends X-Powered-By and no security headers by default.',
        fix: 'npm i helmet, then app.use(helmet()) before your routes.' });
    }
  }
}

function checkCors(files, add) {
  for (const file of files) {
    const { text, rel } = file;
    if (SOURCE_EXT.test(file.name) && !isTestPath(rel)) {
      const credentials = /credentials\s*:\s*true/.test(text);
      const bare = /\bcors\(\s*\)/.exec(text);
      if (bare) {
        add({ id: 'cors-any-origin', severity: 'medium', title: 'CORS allows every origin', location: `${rel}:${lineOf(text, bare.index)}`,
          detail: 'cors() with no options answers Access-Control-Allow-Origin: *.',
          fix: 'Pass an explicit allow-list: cors({ origin: ["https://app.example.com"] }).' });
      }
      const loose = /origin\s*:\s*(true|['"]\*['"])/.exec(text);
      if (loose) {
        const reflects = loose[1] === 'true';
        add({
          id: credentials ? 'cors-credentials-any-origin' : 'cors-any-origin',
          severity: credentials ? 'high' : 'medium',
          title: credentials ? 'CORS trusts every origin and allows credentials' : 'CORS allows every origin',
          location: `${rel}:${lineOf(text, loose.index)}`,
          detail: reflects
            ? 'origin: true reflects whatever Origin the browser sends.'
            : 'Any website can read responses from this API.',
          fix: 'Use an explicit allow-list of trusted origins.',
        });
      }
      const header = /['"]Access-Control-Allow-Origin['"]\s*,\s*['"]\*['"]/i.exec(text);
      if (header) {
        add({ id: 'cors-any-origin', severity: 'medium', title: 'Access-Control-Allow-Origin set to *', location: `${rel}:${lineOf(text, header.index)}`,
          fix: 'Return the specific trusted origin instead of *.' });
      }
    }
    if (rel.endsWith('config/cors.php')) {
      const star = /['"]allowed_origins['"]\s*=>\s*\[\s*['"]\*['"]\s*\]/.exec(text);
      if (star) {
        const creds = /['"]supports_credentials['"]\s*=>\s*true/.test(text);
        add({ id: creds ? 'cors-credentials-any-origin' : 'cors-any-origin', severity: creds ? 'high' : 'medium',
          title: creds ? 'Laravel CORS allows every origin with credentials' : 'Laravel CORS allows every origin',
          location: `${rel}:${lineOf(text, star.index)}`,
          fix: "List your frontend domains in 'allowed_origins' (e.g. env('FRONTEND_URL'))." });
      }
    }
  }
}

function checkNext(files, add) {
  for (const file of files.filter((f) => /^next\.config\.(js|mjs|cjs|ts)$/.test(f.name))) {
    if (!/poweredByHeader\s*:\s*false/.test(file.text)) {
      add({ id: 'next-powered-by', severity: 'low', title: 'Next.js sends X-Powered-By: Next.js', location: file.rel,
        fix: 'Add poweredByHeader: false to next.config.' });
    }
    if (!/headers\s*\(/.test(file.text)) {
      add({ id: 'next-no-security-headers', severity: 'info', title: 'No custom security headers in next.config', location: file.rel,
        fix: 'Add an async headers() block (CSP, HSTS, X-Frame-Options…) or set them at your proxy / Vercel config.' });
    }
  }
}

function checkDocker(files, add) {
  for (const file of files.filter((f) => /^Dockerfile(\..+)?$|\.dockerfile$/i.test(f.name))) {
    const { text, rel } = file;
    if (!/^\s*USER\s+(?!root\b)\S+/im.test(text)) {
      add({ id: 'docker-runs-as-root', severity: 'low', title: 'Container runs as root', location: rel,
        fix: 'Add a non-root user, e.g. `USER node` (Node images) or `USER www-data`.' });
    }
    const re = /^\s*(ENV|ARG)\s+([A-Z0-9_]*(?:SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE_KEY)[A-Z0-9_]*)[=\s]+(\S+)/gim;
    let m;
    while ((m = re.exec(text))) {
      add({ id: 'docker-baked-secret', severity: 'medium', title: `Secret baked into image via ${m[1].toUpperCase()}`,
        location: `${rel}:${lineOf(text, m.index)}`, detail: `${m[2]} is visible to anyone who pulls the image (docker history).`,
        fix: 'Pass secrets at runtime (env_file, Docker secrets) or use BuildKit --mount=type=secret.' });
    }
  }

  for (const file of files.filter((f) => /^(docker-)?compose(\.[\w-]+)?\.ya?ml$/.test(f.name))) {
    const { text, rel } = file;
    const portRe = /^\s*-\s*['"]?(?:0\.0\.0\.0:)?(\d+):(\d+)['"]?\s*(?:#.*)?$/gm;
    let m;
    while ((m = portRe.exec(text))) {
      const service = DB_PORTS[m[2]];
      if (!service) continue;
      add({ id: 'compose-db-port-public', severity: 'medium', title: `${service} port published on all interfaces`,
        location: `${rel}:${lineOf(text, m.index)}`, detail: `"${m[1]}:${m[2]}" exposes the database to the network (and Docker bypasses ufw).`,
        fix: `Bind to localhost ("127.0.0.1:${m[1]}:${m[2]}") or drop the mapping and use the internal network.` });
    }
    const pwRe = /(MYSQL_ROOT_PASSWORD|MYSQL_PASSWORD|POSTGRES_PASSWORD|MONGO_INITDB_ROOT_PASSWORD|MARIADB_ROOT_PASSWORD)\s*[:=]\s*['"]?([^'"\s]*)['"]?/g;
    while ((m = pwRe.exec(text))) {
      const value = m[2];
      if (value.startsWith('$')) continue;
      if (!value || WEAK_DB_PASSWORDS.has(value.toLowerCase())) {
        add({ id: 'compose-weak-db-password', severity: 'medium', title: 'Weak or empty database password in compose file',
          location: `${rel}:${lineOf(text, m.index)}`, detail: `${m[1]}=${value || '(empty)'}`,
          fix: 'Use a strong password from an .env file: ${DB_PASSWORD}.' });
      }
    }
    if (/MYSQL_ALLOW_EMPTY_PASSWORD\s*[:=]\s*['"]?(yes|true|1)/i.test(text)) {
      add({ id: 'compose-weak-db-password', severity: 'medium', title: 'MySQL allows an empty root password', location: rel,
        fix: 'Remove MYSQL_ALLOW_EMPTY_PASSWORD and set a strong password.' });
    }
  }
}
