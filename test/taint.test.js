import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeTaint, lex } from '../src/taint.js';
import { scanCode } from '../src/scanners/code.js';
import { hasDirective } from '../src/files.js';

const sinks = (code, opts) => analyzeTaint(code, opts).map((f) => `${f.sink}@${f.line}`);

test('lexer: templates, regex literals, comments and JSX apostrophes', () => {
  const toks = lex('const a = `x${b + `y${c}`}z`; // fetch(req.query.u)\nconst r = /[/]"/g; const s = "it\'s";');
  const ids = toks.filter((t) => t.t === 'id').map((t) => t.v);
  assert.deepEqual(ids, ['const', 'a', 'b', 'c', 'const', 'r', 'const', 's'], 'comment content is not code');
  assert.ok(toks.some((t) => t.t === 're' && t.v === '/[/]"/g'), 'regex with / inside a class and a quote');
  const jsx = lex("return <p>Don't panic</p>;\nconst x = req.body;");
  assert.equal(jsx.find((t) => t.v === 'x').line, 2, 'a stray apostrophe only affects its own line');
});

test('taint: true positives across lines', () => {
  assert.deepEqual(sinks([
    'export async function POST(req) {',
    '  const { url } = await req.json();',
    '  const res = await fetch(url);',
    '}',
  ].join('\n')), ['ssrf@3'], 'Next route handler: body → destructuring → fetch');

  assert.deepEqual(sinks([
    "import mongoose from 'mongoose';",
    'app.post("/login", async (req, res) => {',
    '  const filter = req.body;',
    '  const user = await User.findOne(filter);',
    '  const u2 = await User.findOne({ email: req.body.email });',
    '});',
  ].join('\n')), ['nosql@4', 'nosqlField@5']);

  assert.deepEqual(sinks([
    "import fs from 'node:fs';",
    'app.get("/f/:name", (req, res) => {',
    '  const name = req.params.name;',
    '  const full = path.join(UPLOADS, name);',
    '  res.sendFile(full);',
    '  fs.readFileSync(full);',
    '});',
  ].join('\n')), ['path@5', 'path@6'], 'taint survives path.join');

  assert.deepEqual(sinks([
    'router.get("/u", async (req, res) => {',
    '  const id = req.query.id;',
    '  const sql = `SELECT * FROM users WHERE id = ${id}`;',
    '  await db.query(sql);',
    '});',
  ].join('\n')), ['sql@4'], 'taint survives a template literal');

  assert.deepEqual(sinks([
    "'use server';",
    "import { redirect } from 'next/navigation';",
    'export async function save(formData: FormData): Promise<{ ok: boolean }> {',
    "  const next = formData.get('next') as string;",
    '  redirect(next);',
    '}',
  ].join('\n')), ['redirect@5'], 'Server Action arguments are client input, even with a return type');

  assert.deepEqual(sinks([
    "const { exec } = require('child_process');",
    'app.post("/build", (req, res) => {',
    '  const branch = req.body.branch;',
    "  exec('git checkout ' + branch);",
    '});',
  ].join('\n')), ['cmd@4']);

  assert.deepEqual(sinks([
    'export default async function Page({ searchParams }) {',
    '  const target = searchParams.url;',
    '  const page = await fetch(new URL(target));',
    '}',
  ].join('\n')), ['ssrf@3'], 'searchParams and new URL()');
});

test('taint: look-alikes that must not fire', () => {
  const none = (code, why, opts) => assert.deepEqual(sinks(code, opts), [], why);

  none('app.get("/u/:id", async (req, res) => {\n  const id = Number(req.params.id);\n  await db.query(`SELECT * FROM t WHERE id = ${id}`);\n});', 'Number() cleans it');
  none('export async function POST(req) {\n  const body = await req.json();\n  const url = parsePublicUrl(body.url);\n  await fetch(url);\n}', 'unknown helper may validate: no claim');
  none('app.post("/u", async (req, res) => {\n  const id = req.body.id;\n  await db.query("SELECT * FROM t WHERE id = ?", [id]);\n});', 'parameterised query');
  none([
    'function a(req) { const url = req.query.u; return url; }',
    'function b() { const url = "https://api.example.com"; return fetch(url); }',
  ].join('\n'), 'same name in another function');
  none([
    'app.get("/x", (req, res) => {',
    '  const url = req.query.u;',
    '  const check = (url) => fetch(url);',
    '});',
  ].join('\n'), 'parameter shadows the outer tainted name');
  none("import mongoose from 'mongoose';\nconst u = await User.findOne({ where: { email: req.body.email } });", 'Sequelize-style where in a Mongo-using file');
  none('const u = await User.findOne({ email: req.body.email });', 'no Mongo import: findOne could be anything');
  none("import mongoose from 'mongoose';\napp.post('/l', async (req, res) => {\n  const email = req.body.email;\n  await User.findOne({ email: String(email) });\n});", 'cast value; the key `email` is not a use');
  none('app.get("/f", (req, res) => {\n  const name = req.query.f;\n  res.sendFile(name, { root: PUBLIC_DIR });\n});', 'sendFile with root');
  none('const id = req.params.id;\nconst rows = await prisma.$queryRaw`SELECT * FROM t WHERE id = ${id}`;', 'Prisma tagged template is parameterised');
  none('app.get("/r", (req, res) => {\n  const ok = /^[a-z]+$/.exec(req.query.q);\n});', 'RegExp#exec is not child_process.exec');
  none('// const x = req.body; fetch(x)\nconst s = "fetch(req.query.url)";', 'comments and strings');
});

test('validation guards: strong enough for the sink → quiet, too weak → still reported', () => {
  const handler = (guard, sinkLine) => [
    'export async function POST(req) {',
    '  const data = await req.formData();',
    '  const next = String(data.get("next") ?? "/");',
    `  ${guard}`,
    `  ${sinkLine}`,
    '}',
  ].join('\n');

  // relative-path check in front of a fixed origin: the host cannot change
  assert.deepEqual(sinks(handler('if (!next.startsWith("/") || next.startsWith("//")) return new Response("bad", { status: 400 });', 'await fetch(ORIGIN + next);')), []);
  assert.deepEqual(sinks(handler('if (!next.startsWith("/")) return null;', 'await fetch(ORIGIN + next);')), [], "'/' alone is enough for a fixed origin");
  // the same '/' check is NOT enough for a redirect: //evil.com passes it
  assert.deepEqual(sinks(handler('if (!next.startsWith("/")) return null;', 'return NextResponse.redirect(new URL(next, req.url));')), ['redirect@5']);
  assert.deepEqual(sinks(handler('if (!next.startsWith("/") || next.startsWith("//")) return null;', 'return NextResponse.redirect(new URL(next, req.url));')), []);
  // weak checks are not validation
  assert.deepEqual(sinks(handler('if (!next.startsWith("http")) return null;', 'await fetch(next);')), ['ssrf@5']);
  assert.deepEqual(sinks(handler('if (!next) return null;', 'await fetch(next);')), ['ssrf@5']);
  // allow-list and anchored regex validate for every sink, also inside a positive block
  assert.deepEqual(sinks(handler('if (!ALLOWED.includes(next)) throw new Error("no");', 'await db.query(`SELECT * FROM ${next}`);')), []);
  assert.deepEqual(sinks(handler('if (/^[a-z]+$/.test(next)) { await db.query(`SELECT * FROM ${next}`); }', '')), []);
  assert.deepEqual(sinks(handler('if (next === "") return null;', 'await db.query(`SELECT * FROM ${next}`);')), ['sql@5'], 'ruling out "" is not an allow-list');
});

test('directive detection stays linear on bundles full of comment lines', () => {
  const bundle = '/******/ \t\n'.repeat(3000) + '/***/ \n';
  const t0 = Date.now();
  assert.equal(hasDirective(bundle, 'use server'), false);
  assert.equal(hasDirective(`// note\n/* x */\n  'use server';\nexport async function a() {}`, 'use server'), true);
  analyzeTaint(bundle + 'const x = req.body;');
  assert.ok(Date.now() - t0 < 500, `took ${Date.now() - t0} ms; the old regex took seconds to minutes here`);
});

test('scanCode reports multi-line flows once, with the flow in the detail', () => {
  const file = (rel, text) => ({ rel, name: rel.split('/').pop(), full: rel, text });
  const found = scanCode([
    file('src/app/api/preview/route.ts', 'export async function POST(req: Request) {\n  const { url } = await req.json();\n  return fetch(url);\n}\n'),
    file('server/routes.js', 'const r = await fetch(req.query.url);\n'), // single line: the pattern rule already reports it
  ]);
  const ssrf = found.filter((f) => f.id === 'js-ssrf');
  assert.deepEqual(ssrf.map((f) => f.location), ['src/app/api/preview/route.ts:3', 'server/routes.js:1']);
  assert.match(ssrf[0].detail, /flow: req\.json\(\) → url \(line 2\) → fetch\(\)/);
});
