import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeProject, analyzeTaint } from '../src/taint.js';

const sinks = (code) => analyzeTaint(code).map((f) => `${f.sink}@${f.line}`);
const project = (files) => {
  const out = {};
  for (const [rel, list] of analyzeProject(Object.entries(files).map(([rel, text]) => ({ rel, text, nextAppFile: rel.includes('app/') })))) {
    if (list.length) out[rel] = list.map((f) => `${f.sink}@${f.line}`);
  }
  return out;
};

test('helpers in the same file: transformers pass taint, sink helpers report at the call', () => {
  assert.deepEqual(sinks([
    'function buildSql(id) { return `SELECT * FROM users WHERE id = ${id}`; }',
    'app.get("/u", async (req, res) => {',
    '  await db.query(buildSql(req.query.id));',
    '});',
  ].join('\n')), ['sql@3'], 'return value of a transformer');

  const found = analyzeTaint([
    'const run = async (sql) => {',
    '  return db.query(sql);',
    '};',
    'app.post("/r", async (req, res) => {',
    '  await run(`DELETE FROM t WHERE id = ${req.body.id}`);',
    '});',
  ].join('\n'));
  assert.deepEqual(found.map((f) => `${f.sink}@${f.line}`), ['sql@5']);
  assert.match(found[0].flow, /req\.body → run\(\) → db\.query\(\) \(input\.js:2\)/);

  assert.deepEqual(sinks([
    'function target(req) { return req.query.next; }',
    'app.get("/go", (req, res) => res.redirect(target(req)));',
  ].join('\n')), ['redirect@2'], 'a helper that returns request data');
});

test('across files: ESM with the @/ alias, CommonJS require, and helper chains', () => {
  assert.deepEqual(project({
    'src/lib/http.ts': 'export async function get(url: string) {\n  return fetch(url, { cache: "no-store" });\n}\n',
    'src/app/api/preview/route.ts': [
      "import { get } from '@/lib/http';",
      'export async function POST(req: Request) {',
      '  const { url } = await req.json();',
      '  return get(url);',
      '}',
    ].join('\n'),
  }), { 'src/app/api/preview/route.ts': ['ssrf@4'] });

  assert.deepEqual(project({
    'lib/users.js': "const mongoose = require('mongoose');\nfunction findUser(filter) {\n  return User.findOne(filter);\n}\nmodule.exports = { findUser };\n",
    'routes/login.js': "const { findUser } = require('../lib/users');\nrouter.post('/login', async (req, res) => {\n  const user = await findUser(req.body);\n});\n",
  }), { 'routes/login.js': ['nosql@3'] });

  assert.deepEqual(project({
    'lib/shell.js': "import { exec } from 'node:child_process';\nexport function run(cmd) { return exec(cmd); }\n",
    'lib/git.js': "import { run } from './shell.js';\nexport const checkout = (branch) => run('git checkout ' + branch);\n",
    'server.js': "import * as git from './lib/git.js';\napp.post('/deploy', (req, res) => {\n  git.checkout(req.body.branch);\n});\n",
  }), { 'server.js': ['cmd@3'] }, 'route → checkout() → run() → exec(), namespace import');
});

test('TypeScript generics and pinned destinations', () => {
  assert.deepEqual(project({
    'src/lib/store.ts': [
      'export async function createBot(db: Db, settings: { name: string }): Promise<Bot> {',
      '  const rows = await db.query<BotRow>(`INSERT INTO bots (name) VALUES ($1) RETURNING id`, [settings.name]);',
      '  return toBot(rows[0]);',
      '}',
      'function toBot(row: BotRow): Bot { return { id: row.id }; }',
    ].join('\n'),
    'src/app/actions.ts': [
      "'use server';",
      "import { redirect } from 'next/navigation';",
      "import { createBot } from '@/lib/store';",
      'export async function create(form: FormData) {',
      "  const bot = await createBot(db, { name: String(form.get('name')) });",
      '  redirect(`/bots/${bot.id}`);',
      '  redirect(bot.homepage);',
      '}',
    ].join('\n'),
  }), {}, 'db.query<Row>(…) is a library call; `/bots/${…}` cannot leave the site');

  assert.deepEqual(sinks([
    'export async function GET(req) {',
    "  const id = req.nextUrl.searchParams.get('id');",
    '  await fetch(`https://api.example.com/items/${id}`);',
    '  await fetch(`${id}/items`);',
    "  await fetch('https://api.example.com?q=' + id);",
    '  return Response.redirect(`//${id}`);',
    '}',
  ].join('\n')), ['ssrf@4', 'redirect@6'], 'a fixed host or path is pinned; //… and a leading variable are not');

  assert.deepEqual(sinks([
    'function load<T>(url: string): Promise<T> { return fetch(url).then((r) => r.json()); }',
    'const parse = <T,>(raw: string): T => JSON.parse(raw);',
    'export async function POST(req) {',
    '  const { url } = await req.json();',
    '  const data = await load<Array<Map<string, number>>>(url);',
    '}',
  ].join('\n')), ['ssrf@5'], 'generic declarations and nested type arguments still resolve');
});

test('across files: validators and allow-lists stop taint, unrelated parameters do not leak', () => {
  assert.deepEqual(project({
    'src/lib/safe-url.ts': [
      'export function parsePublicUrl(text: string): URL {',
      '  const url = new URL(text);',
      "  if (isPrivateHost(url.hostname)) throw new Error('private address');",
      '  return url;',
      '}',
    ].join('\n'),
    'src/app/actions.ts': [
      "'use server';",
      "import { parsePublicUrl } from '@/lib/safe-url';",
      'export async function crawl(formData: FormData) {',
      "  const url = parsePublicUrl(String(formData.get('url')));",
      '  await fetch(url);',
      '}',
    ].join('\n'),
  }), {}, 'a helper that can throw is a validator');

  assert.deepEqual(sinks([
    "const COLUMNS = ['name', 'created_at'];",
    'function sortColumn(col) {',
    '  if (!COLUMNS.includes(col)) return "id";',
    '  return col;',
    '}',
    'app.get("/list", async (req, res) => {',
    '  await db.query(`SELECT * FROM t ORDER BY ${sortColumn(req.query.sort)}`);',
    '});',
  ].join('\n')), [], 'the returned value passed an allow-list inside the helper');

  assert.deepEqual(sinks([
    'function audit(value) { console.log(value); return Date.now(); }',
    'app.get("/x", async (req, res) => { await fetch(`https://api.example.com/t/${audit(req.query.q)}`); });',
  ].join('\n')), [], 'the helper does not return its parameter');

  assert.deepEqual(project({
    'a.js': 'export function format(x) { return `<${x}>`; }\n',
    'b.js': 'export function format(x) { return "constant"; }\n',
    'route.js': "import { format } from './b.js';\napp.get('/', async (req, res) => { await fetch(format(req.query.u)); });\n",
  }), {}, 'the imported function is used, not a same-named one elsewhere');
});
