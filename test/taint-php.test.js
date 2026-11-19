import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzePhp, analyzePhpProject, lexPhpTokens } from '../src/taint-php.js';

const php = (...lines) => ['<?php', '', ...lines].join('\n');
const sinks = (code, rel) => analyzePhp(code, rel).map((f) => `${f.sink}@${f.line}`);
const project = (files) => {
  const out = {};
  for (const [rel, list] of analyzePhpProject(Object.entries(files).map(([rel, text]) => ({ rel, text })))) {
    if (list.length) out[rel] = list.map((f) => `${f.sink}@${f.line}`);
  }
  return out;
};

test('PHP lexer: interpolation, heredoc, comments and inline HTML', () => {
  const toks = lexPhpTokens([
    '<html><?php echo "x"; ?> it\'s HTML <?php',
    '$a = "Hello {$user->name} and $id[0]"; // $b = $_GET["x"];',
    "$sql = <<<SQL\nSELECT * FROM t WHERE id = $id\nSQL;",
    '# comment $c',
  ].join('\n'));
  const vars = toks.filter((t) => t.t === 'var').map((t) => t.v);
  assert.deepEqual(vars, ['a', 'sql'], 'comments and HTML are not code');
  const dstr = toks.find((t) => t.t === 'dstr' && t.v.startsWith('Hello'));
  assert.equal(dstr.head, 'Hello ');
  assert.deepEqual(dstr.parts.map((p) => p.filter((t) => t.t === 'var').map((t) => t.v)), [['user'], ['id']]);
  const heredoc = toks.find((t) => t.t === 'dstr' && t.v.includes('SELECT'));
  assert.deepEqual(heredoc.parts[0].filter((t) => t.t === 'var').map((t) => t.v), ['id']);
});

test('PHP taint: Laravel vulnerabilities across lines', () => {
  assert.deepEqual(sinks(php(
    'class UserController extends Controller {',
    '  public function search(Request $request) {',
    "    $term = $request->input('q');",
    '    return DB::select("SELECT * FROM users WHERE name LIKE \'%$term%\'");',
    '  }',
    '}',
  )), ['sql@6'], 'input() → interpolated DB::select');

  assert.deepEqual(sinks(php(
    'class PostController extends Controller {',
    '  public function show(string $slug) {',
    '    return DB::table("posts")->whereRaw("slug = \'" . $slug . "\'")->first();',
    '  }',
    '  public function byId(int $id) {',
    '    return DB::select("SELECT * FROM posts WHERE id = $id");',
    '  }',
    '}',
  ), 'app/Http/Controllers/PostController.php'), ['sql@5'], 'string route parameter is input; int is cast by PHP');

  assert.deepEqual(sinks(php(
    'function deploy(Request $request) {',
    '  $branch = $request->branch;',
    '  Process::run("git checkout $branch");',
    "  Process::run(['git', 'checkout', $branch]);",
    '  $out = `ls ${branch}`;',
    '}',
  )), ['cmd@5', 'cmd@7'], 'string command and backticks; an argument array has no shell');

  assert.deepEqual(sinks(php(
    'function go(Request $request) {',
    "  $next = $request->query('next');",
    '  return redirect()->away($next);',
    '}',
    'function fetch(Request $request) {',
    "  $url = $request->input('url');",
    '  return Http::timeout(5)->withHeaders([])->get($url);',
    '}',
    'function legacy() {',
    "  header('Location: ' . $_GET['to']);",
    '}',
  )), ['redirect@5', 'ssrf@9', 'redirect@12']);

  assert.deepEqual(sinks(php(
    'function upload(Request $request) {',
    "  $name = $request->file('doc')->getClientOriginalName();",
    "  Storage::put('docs/' . $name, 'x');",
    "  $page = $_GET['page'];",
    "  include $page . '.php';",
    "  $q = $request->q;",
    '  $run = function () use ($q) { return DB::select("SELECT $q"); };',
    '  $lost = function () { return DB::select("SELECT $q"); };',
    '}',
  )), ['file@5', 'include@7', 'sql@9'], 'upload name, include, closure use (a closure without use sees nothing)');
});

test('PHP taint: look-alikes that must not fire', () => {
  const none = (code, why, rel) => assert.deepEqual(sinks(code, rel), [], why);
  none(php('function a(Request $request) {', '  $id = (int) $request->id;', '  return DB::select("SELECT * FROM t WHERE id = $id");', '}'), '(int) cast');
  none(php('function a(Request $request) {', "  $id = $request->input('id');", '  return DB::select("SELECT * FROM t WHERE id = ?", [$id]);', '}'), 'bindings');
  none(php('function a(Request $request) {', '  $sort = $request->sort;', "  abort_unless(in_array($sort, ['name', 'date'], true), 400);", '  return DB::select("SELECT * FROM t ORDER BY $sort");', '}'), 'abort_unless allow-list');
  none(php('function a(Request $request) {', '  $page = $request->page;', "  if (!preg_match('/^[a-z]+$/', $page)) { abort(404); }", '  include "pages/$page.php";', '}'), 'anchored preg_match + abort');
  none(php('function a(Request $request) {', '  $name = $request->user()->name;', '  return DB::select("SELECT * FROM t WHERE owner = \'$name\'");', '}'), 'the signed-in user is not request input');
  none(php('function a(Request $request, int $id) {', "  return redirect('/dashboard/' . $request->tab);", "  return redirect()->route('home');", '}'), 'pinned path and named routes');
  none(php('function a(Request $request) {', '  $id = $request->id;', '  return Http::get("https://api.example.com/items/$id");', '}'), 'fixed host');
  none(php('function a(Request $request) {', "  $file = basename($request->input('f'));", "  return response()->download(storage_path('exports/' . $file));", '}'), 'basename');
  none(php('// DB::select("SELECT $x"); ?>', '<p>$_GET["x"] in HTML</p>'), 'comments and HTML');
});

test('PHP taint across files: controller → service, static helpers, validators', () => {
  assert.deepEqual(project({
    'app/Http/Controllers/PostController.php': php(
      'namespace App\\Http\\Controllers;',
      'use App\\Services\\PostService;',
      'class PostController extends Controller {',
      '  public function __construct(private PostService $posts) {}',
      '  public function index(Request $request) {',
      "    return $this->posts->search($request->input('q'));",
      '  }',
      '}',
    ),
    'app/Services/PostService.php': php(
      'namespace App\\Services;',
      'class PostService {',
      '  public function search(string $term) {',
      '    return $this->query("title LIKE \'%$term%\'");',
      '  }',
      '  private function query(string $where) {',
      '    return DB::table("posts")->whereRaw($where)->get();',
      '  }',
      '}',
    ),
  }), { 'app/Http/Controllers/PostController.php': ['sql@8'] }, 'promoted property → service → private helper → whereRaw');

  assert.deepEqual(project({
    'app/Support/Paths.php': php(
      'class Paths {',
      '  public static function safe(string $p): string {',
      "    if (str_contains($p, '..')) { throw new InvalidArgumentException('bad path'); }",
      '    return $p;',
      '  }',
      '  public static function raw(string $p): string { return "/data/$p"; }',
      '}',
    ),
    'app/Http/Controllers/FileController.php': php(
      'class FileController extends Controller {',
      '  public function show(Request $request) {',
      '    $a = file_get_contents(Paths::safe($request->f));',
      '    $b = file_get_contents(Paths::raw($request->f));',
      '  }',
      '}',
    ),
  }), { 'app/Http/Controllers/FileController.php': ['file@6'] }, 'a validator helper cleans, a transformer does not');
});
