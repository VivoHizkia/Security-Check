import { test } from 'node:test';
import assert from 'node:assert/strict';
import { collectFiles } from '../src/files.js';
import { scanConfig } from '../src/scanners/config.js';
import { scanCode } from '../src/scanners/code.js';
import { ids, makeProject } from './helpers.js';

async function scan(files, fn) {
  const p = await makeProject(files);
  try {
    return fn((await collectFiles(p.root)).files);
  } finally {
    await p.cleanup();
  }
}

test('Laravel: debug in production is critical, locally only info', async () => {
  const prod = await scan({ '.env': 'APP_ENV=production\nAPP_DEBUG=true\nAPP_KEY=\n' }, scanConfig);
  assert.ok(ids(prod).includes('laravel-debug-production'));
  assert.ok(ids(prod).includes('laravel-missing-app-key'));
  const local = await scan({ '.env': 'APP_ENV=local\nAPP_DEBUG=true\nAPP_KEY=base64:x\n' }, scanConfig);
  assert.deepEqual(local.map((f) => [f.id, f.severity]), [['laravel-debug-enabled', 'info']]);
});

test('browser-public env vars holding secrets', async () => {
  const found = await scan({
    '.env.local': 'NEXT_PUBLIC_SUPABASE_URL=https://x.supabase.co\nNEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=eyJ...\n',
    'src/api.ts': 'const s = import.meta.env.VITE_STRIPE_SECRET;\n',
  }, scanConfig);
  const names = found.filter((f) => f.id === 'public-env-secret').map((f) => f.detail.split(' ')[0]);
  assert.deepEqual(names.sort(), ['NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY', 'VITE_STRIPE_SECRET']);
});

test('CORS, helmet, Next and Docker checks', async () => {
  const found = await scan({
    'package.json': JSON.stringify({ dependencies: { express: '^4.19.0' } }),
    'server.js': "app.use(cors({ origin: true, credentials: true }));\n",
    'config/cors.php': "<?php return ['allowed_origins' => ['*'], 'supports_credentials' => false];",
    'next.config.mjs': 'export default { reactStrictMode: true };',
    'Dockerfile': 'FROM node:20\nENV API_TOKEN=abc123\nCMD ["node","server.js"]\n',
    'docker-compose.yml': 'services:\n  db:\n    image: mysql:8\n    ports:\n      - "3306:3306"\n    environment:\n      MYSQL_ROOT_PASSWORD: root\n  cache:\n    ports:\n      - "127.0.0.1:6379:6379"\n',
  }, scanConfig);
  const got = ids(found);
  for (const id of ['express-no-helmet', 'cors-credentials-any-origin', 'cors-any-origin', 'next-powered-by',
    'docker-runs-as-root', 'docker-baked-secret', 'compose-db-port-public', 'compose-weak-db-password']) {
    assert.ok(got.includes(id), `expected ${id}, got ${got}`);
  }
  assert.equal(found.filter((f) => f.id === 'compose-db-port-public').length, 1, 'localhost-bound Redis must not be flagged');
});

test('risky code patterns across JS, PHP, Blade and Python', async () => {
  const found = await scan({
    'routes/user.js': [
      'db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);',
      'exec("convert " + req.body.file);',
      'res.redirect(req.query.next);',
      'db.query("SELECT * FROM users WHERE id = ?", [id]);',
      '// eval(something) in a comment is ignored',
    ].join('\n'),
    'app/Http/Controllers/UserController.php': [
      '<?php',
      '$users = DB::select("SELECT * FROM users WHERE name = \'$name\'");',
      "$ok = DB::select('SELECT * FROM users WHERE id = ?', [$id]);",
      'User::create($request->all());',
      'class Post extends Model { protected $guarded = []; }',
    ].join('\n'),
    'resources/views/post.blade.php': '<div>{!! $post->body !!}</div>\n{!! csrf_field() !!}\n',
    'app/main.py': 'cur.execute(f"SELECT * FROM t WHERE id={uid}")\nrequests.get(u, verify=False)\n',
    'tests/fixtures.test.js': 'eval("1+1")',
  }, scanCode);
  const got = ids(found);
  for (const id of ['js-sql-injection', 'js-command-injection', 'js-open-redirect', 'php-sql-injection',
    'laravel-request-all', 'laravel-mass-assignment', 'blade-unescaped', 'py-sql-injection', 'py-tls-disabled']) {
    assert.ok(got.includes(id), `expected ${id}, got ${got}`);
  }
  assert.equal(found.filter((f) => f.id === 'js-sql-injection').length, 1, 'parameterised query must not be flagged');
  assert.equal(found.filter((f) => f.id === 'php-sql-injection').length, 1);
  assert.equal(found.filter((f) => f.id === 'blade-unescaped').length, 1, 'csrf_field() is allow-listed');
  assert.ok(!got.includes('js-eval'), 'comments and test files are skipped');
});

test('NoSQL injection, path traversal, SSRF, express.static and PHP file inclusion', async () => {
  const lines = (rel, list) => [rel, list.join('\n')];
  const found = await scan(Object.fromEntries([
    lines('server/routes.js', [
      'const user = await User.findOne(req.body);', // 1 nosql
      'const user2 = await User.findOne({ email: String(req.body.email) });', // safe
      'res.sendFile(path.join(__dirname, "uploads", req.params.name));', // 3 traversal
      'res.sendFile(req.params.name, { root: UPLOADS });', // safe: root option
      'res.sendFile(path.join(__dirname, "index.html"));', // safe
      'const r = await fetch(req.query.url);', // 6 ssrf
      'const r2 = await fetch(`${API_BASE}/users/${id}`);', // safe
      'app.use(express.static(__dirname));', // 8 static root
      'app.use(express.static(path.join(__dirname, "public")));', // safe
      "app.use(express.static('public'));", // safe
    ]),
    lines('app/api/preview/route.ts', [
      'const page = await fetch(searchParams.get("url"));', // 1 ssrf
    ]),
    lines('public/page.php', [
      '<?php',
      'include $_GET["page"] . ".php";', // 2 inclusion
      "include __DIR__ . '/partials/header.php';", // safe
      'echo file_get_contents($request->input("file"));', // 4 file read
      "$cfg = file_get_contents(__DIR__ . '/config.json');", // safe
    ]),
  ]), scanCode);
  const at = (id) => found.filter((f) => f.id === id).map((f) => f.location);
  assert.deepEqual(at('js-nosql-injection'), ['server/routes.js:1']);
  assert.deepEqual(at('js-path-traversal'), ['server/routes.js:3']);
  assert.deepEqual(at('js-ssrf').sort(), ['app/api/preview/route.ts:1', 'server/routes.js:6']);
  assert.deepEqual(at('express-static-root'), ['server/routes.js:8']);
  assert.deepEqual(at('php-file-inclusion'), ['public/page.php:2']);
  assert.deepEqual(at('php-file-from-request'), ['public/page.php:4']);
});

test('Blade {!! !!}: escaped values and plain-text mail views are fine, raw HTML views are not', async () => {
  const found = await scan({
    'resources/views/post.blade.php': '{!! $post->body !!}\n{!! e($post->title) !!}\n{!! nl2br(e($post->excerpt)) !!}\n{!! Purifier::clean($post->html) !!}\n',
    'resources/views/mail/document.blade.php': '<p>{!! $paragraph !!}</p>\n',
    'resources/views/mail/document-text.blade.php': '{!! $tenant->name !!}\n{!! $paragraph !!}\n',
    'app/Mail/DocumentMail.php': "<?php\nreturn new Content(view: 'mail.document', text: 'mail.document-text');\n",
  }, scanCode);
  assert.deepEqual(found.filter((f) => f.id === 'blade-unescaped').map((f) => f.location).sort(),
    ['resources/views/mail/document.blade.php:1', 'resources/views/post.blade.php:1']);
});

test('innerHTML: variables are flagged, literals and ALL_CAPS constants are not', async () => {
  const found = await scan({
    'public/widget.js': [
      'el.innerHTML = msg.text;',
      'el.innerHTML = open ? body : CHAT_ICON;',
      'button.innerHTML = CHAT_ICON;',
      'button.innerHTML = open ? CLOSE_ICON : CHAT_ICON;',
      'el.innerHTML = "";',
    ].join('\n'),
  }, scanCode);
  assert.deepEqual(found.filter((f) => f.id === 'js-inner-html').map((f) => f.location),
    ['public/widget.js:1', 'public/widget.js:2']);
});
