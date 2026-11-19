import { test } from 'node:test';
import assert from 'node:assert/strict';
import { collectFiles } from '../src/files.js';
import { collectRoutes, lexPhp, parseRoutes, scanLaravel } from '../src/scanners/laravel.js';
import { makeProject } from './helpers.js';

async function scan(files) {
  const p = await makeProject({ artisan: '#!/usr/bin/env php\n', ...files });
  try {
    const { files: loaded } = await collectFiles(p.root);
    return { findings: scanLaravel(loaded), routes: collectRoutes(loaded) };
  } finally {
    await p.cleanup();
  }
}

const php = (...lines) => ['<?php', '', 'use Illuminate\\Support\\Facades\\Route;', ...lines].join('\n');
const where = (findings, id) => findings.filter((f) => f.id === id).map((f) => f.location).sort();

test('lexPhp blanks comments and keeps string contents out of the bracket shape', () => {
  const { code, shape } = lexPhp("$a = '}'; // Route::get('/x')\n/* { */ $b = \"(\";");
  assert.ok(!code.includes('Route::'), 'line comment removed');
  assert.ok(!code.includes('/*'), 'block comment removed');
  assert.ok(code.includes("'}'"), 'strings are kept in code');
  assert.ok(!/['"][{}()]['"]/.test(shape), 'brackets inside strings are blanked in shape');
  assert.equal(code.length, shape.length);
});

test('parseRoutes resolves nested prefixes, middleware and controller groups', () => {
  const { routes } = parseRoutes(php(
    "Route::get('/', fn () => view('welcome'));",
    "Route::middleware(['auth', 'verified'])->prefix('admin')->group(function () {",
    "    Route::get('/users', [UserController::class, 'index'])->name('admin.users');",
    "    Route::prefix('reports')->group(function () {",
    "        Route::get('{id}', [ReportController::class, 'show']);",
    '    });',
    '});',
    "Route::group(['prefix' => 'panel', 'middleware' => 'auth:sanctum'], function () {",
    "    Route::match(['get', 'post'], 'settings', [SettingsController::class, 'update']);",
    '});',
    "Route::controller(OrderController::class)->prefix('manage')->group(function () {",
    "    Route::get('/orders', 'index');",
    '});',
    "Route::get('/admin/export', ExportController::class)->middleware('auth');",
    "Route::middleware('auth')->get('/dashboard', fn () => view('dash'))->withoutMiddleware('auth');",
  ));
  const byUri = Object.fromEntries(routes.map((r) => [r.uri, r]));
  assert.deepEqual(Object.keys(byUri), ['/', '/admin/users', '/admin/reports/{id}', '/panel/settings', '/manage/orders', '/admin/export', '/dashboard']);
  assert.deepEqual(byUri['/admin/reports/{id}'].middleware, ['auth', 'verified']);
  assert.equal(byUri['/admin/reports/{id}'].controller, 'ReportController');
  assert.deepEqual(byUri['/panel/settings'].middleware, ['auth:sanctum']);
  assert.equal(byUri['/panel/settings'].verb, 'match');
  assert.deepEqual([byUri['/manage/orders'].controller, byUri['/manage/orders'].method], ['OrderController', 'index']);
  assert.deepEqual(byUri['/admin/export'].middleware, ['auth'], 'middleware chained after the verb counts');
  assert.deepEqual(byUri['/dashboard'].middleware, [], 'withoutMiddleware removes it again');
});

test('laravel: unprotected admin routes are flagged, protected ones are not', async () => {
  const { findings } = await scan({
    'routes/web.php': php(
      "Route::get('/admin', [AdminController::class, 'index']);", // 4 open
      "Route::get('/admin/login', [AdminAuthController::class, 'showLogin']);", // guest page: fine
      "Route::get('/dashboard', fn () => view('dashboard'))->middleware(['auth', 'verified']);", // fine
      "Route::prefix('admin')->middleware('can:manage-users')->group(function () {",
      "    Route::resource('users', UserController::class);", // fine
      '});',
      "Route::prefix('backoffice')->group(function () {",
      "    Route::any('/purge-cache', [CacheController::class, 'purge']);", // 11 open + any
      "    Route::get('/stats', [StatsController::class, 'index']);", // controller guards it: fine
      "    Route::get('/stats/public', [StatsController::class, 'public']);", // 13 excluded from guard
      '});',
      "Route::middleware('auth')->group(function () {",
      "    require __DIR__.'/admin.php';",
      '});',
      "// Route::get('/admin/old', [OldController::class, 'index']);", // commented out
      "Route::get('/blog/{slug}', [PostController::class, 'show']);", // not admin
    ),
    'routes/admin.php': php("Route::get('/cms/pages', [PageController::class, 'index']);"), // fine: required inside auth group
    'routes/internal.php': php("Route::post('/sync', SyncController::class);"), // 4 open via bootstrap/app.php
    'bootstrap/app.php': php(
      'return Application::configure(basePath: dirname(__DIR__))',
      '    ->withRouting(',
      "        web: __DIR__.'/../routes/web.php',",
      '        then: function () {',
      "            Route::middleware('web')->prefix('internal')->group(base_path('routes/internal.php'));",
      '        },',
      '    )->create();',
    ),
    'app/Http/Controllers/StatsController.php': php(
      'class StatsController extends Controller',
      '{',
      '    public function __construct()',
      '    {',
      "        $this->middleware('auth')->except(['public']);",
      '    }',
      '}',
    ),
    'app/Http/Controllers/AdminController.php': php(
      'class AdminController extends Controller implements HasMiddleware',
      '{',
      '    public static function middleware(): array',
      '    {',
      "        return [new Middleware('auth', only: ['edit'])];",
      '    }',
      '}',
    ),
  });
  assert.deepEqual(where(findings, 'laravel-admin-route-no-auth'),
    ['routes/internal.php:4', 'routes/web.php:11', 'routes/web.php:13', 'routes/web.php:4']);
  assert.deepEqual(where(findings, 'laravel-route-any-admin'), ['routes/web.php:11']);
  const open = findings.find((f) => f.location === 'routes/internal.php:4');
  assert.match(open.detail, /POST \/internal\/sync → SyncController/);
});

test('laravel: CSRF wildcard and debug tooling in require', async () => {
  const { findings } = await scan({
    'app/Http/Middleware/VerifyCsrfToken.php': php('class VerifyCsrfToken extends Middleware', '{', "    protected $except = ['*'];", '}'),
    'bootstrap/app.php': php("$middleware->validateCsrfTokens(except: ['stripe/*']);"),
    'composer.json': JSON.stringify({ require: { 'laravel/framework': '^11.0', 'barryvdh/laravel-debugbar': '^3.9' }, 'require-dev': { 'laravel/telescope': '^5.0' } }),
  });
  assert.deepEqual(where(findings, 'laravel-csrf-disabled'), ['app/Http/Middleware/VerifyCsrfToken.php:6']);
  assert.deepEqual(findings.filter((f) => f.id === 'laravel-debug-tool-in-require').map((f) => f.title),
    ['barryvdh/laravel-debugbar is a production dependency']);
});

test('laravel scanner stays silent outside Laravel projects', async () => {
  const p = await makeProject({ 'routes/web.php': php("Route::get('/admin', fn () => 'x');") });
  try {
    assert.deepEqual(scanLaravel((await collectFiles(p.root)).files), []);
  } finally {
    await p.cleanup();
  }
});
