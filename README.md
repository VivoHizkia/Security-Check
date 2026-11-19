# tameng 🛡️

**A security self-scanner for the web apps you build.** One command checks your project and your deployed site for leaked secrets, misconfiguration, risky code and vulnerable dependencies, then tells you exactly how to fix each one.

*Tameng* is Indonesian for "shield".

```
$ npx tameng . --url https://myapp.com

   CRITICAL
    Env file is committed to git  [secrets]
      .env
      → git rm --cached .env, add it to .gitignore, then rotate every secret it contained.
   HIGH
    eval() on request data (remote code execution)  [code]
      app/routes/contributions.js:32
      const preTax = eval(req.body.preTax);
      → Parse the value instead, e.g. Number(req.body.x) or JSON.parse; never eval user input.
    lodash@4.17.11 — 3 known vulnerabilities  [deps]
      package-lock.json
      → Upgrade lodash to 4.17.21 or later.
   MEDIUM
    Missing Content-Security-Policy  [headers]
      https://myapp.com
  ────────────────────────────────────────────────────
  Score  51/100 · D    1 critical · 2 high · 1 medium
```

- **Zero dependencies.** Plain Node.js 18+, nothing to `npm install`.
- **Built for real stacks:** Laravel, Express, Next.js / Vite / React, Vue, FastAPI, Docker Compose.
- **CI-ready:** `--fail-on high` makes the pipeline fail. JSON, a filterable HTML report, and SARIF for GitHub code scanning.
- **Local dashboard:** `tameng serve` keeps every scan, shows the score trend, what is new or fixed since last time, and an inventory of every endpoint in your code.

## What it checks

| Scanner | Looks for |
|---|---|
| `secrets` | AWS / GitHub / Stripe / OpenAI / Anthropic / Slack / Google / Telegram keys, private keys, DB URLs with passwords, hard-coded JWTs and credentials. Flags `.env` files that are **committed** or **not in .gitignore**, and real values in `.env.example`. Values are always masked in reports. |
| `config` | Laravel `APP_DEBUG=true` in production and missing `APP_KEY`. Secrets in browser-public env vars (`NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*`). Wide-open CORS (Express and `config/cors.php`), Express without helmet, Next.js `X-Powered-By`. Docker running as root or with secrets baked in, DB ports published on `0.0.0.0`, weak DB passwords in compose files. |
| `code` | SQL built by string interpolation (JS, Laravel `DB::raw`/`whereRaw`, PHP, Python), command injection, `eval` on request data, open redirects, MongoDB filters taken straight from `req.body`/`req.query`, file paths from the request (`res.sendFile`, `fs.*`, PHP `include`/`file_get_contents`), server-side `fetch` of a request-supplied URL (SSRF), `express.static` serving the project root, `$guarded = []`, `$request->all()`, unescaped Blade `{!! !!}`, `v-html`, `dangerouslySetInnerHTML`, disabled TLS verification, `pickle`/unsafe `yaml.load`. For JavaScript/TypeScript it also does **taint tracking**: request data (`req.body`, `await req.json()`, `formData.get()`, `searchParams`, Server Action arguments) is followed through variables, destructuring, template strings, `path.join` and `new URL` into SQL, shell, `eval`, MongoDB filters, file paths, `fetch` and redirects, even when source and sink are lines apart. Each finding shows the flow, e.g. `req.json() → url (line 2) → fetch()`. Validation is understood per sink: an allow-list or anchored regex clears everything, and `startsWith('/')` clears `fetch(ORIGIN + path)` but not a redirect (`//evil.com`). |
| `laravel` | Admin routes (`/admin`, `/dashboard`, `/panel`, `/backoffice`, `/cms`, …) reachable without auth. It follows nested `Route::middleware()->prefix()->group()`, `Route::group([...])`, route files pulled in with `require` or `->group(base_path(...))` (including Laravel 11 `bootstrap/app.php`), `->withoutMiddleware()`, and controller middleware (`$this->middleware('auth')->except([...])` and `HasMiddleware`). Also `Route::any` on admin paths (GET skips CSRF), CSRF disabled with `'*'`, and Debugbar/Telescope as production dependencies. Login, register and password-reset pages under `/admin` are allowed to be public. |
| `deps` | Every package in `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml` (v5–v9; for v9 dev-only packages are found by walking the dependency graph), `bun.lock` (same), `composer.lock` and pinned `requirements.txt`, checked against [OSV.dev](https://osv.dev) (GitHub advisories, npm, Packagist, PyPI, malicious-package reports). One finding per package, with the upgrade that fixes all of its advisories. Dev-only packages are ranked one level lower. A `package.json` / `composer.json` with dependencies but no lockfile (in its folder or a parent) is reported, so "no findings" never silently means "not checked". |
| `headers` (with `--url`) | HTTPS and the HTTP→HTTPS redirect, HSTS, CSP quality (`unsafe-inline`, wildcards), clickjacking protection, `nosniff`, Referrer-Policy, version-leaking headers, CORS that reflects any origin, cookie flags (`Secure`, `HttpOnly`, `SameSite`), and publicly reachable `/.env`, `/.git/config`, `storage/logs/laravel.log`, `phpinfo.php`, Telescope, `.vscode/sftp.json`. Content checks prevent SPA catch-all pages from causing false alarms. |

## Usage

```bash
# from a clone
node bin/tameng.js ./my-app

# or install globally from the folder
npm install -g .
tameng ./my-app
```

```
tameng [path] [options]

  --url <url>          check a deployed site you own
  --html <file>        write an HTML report
  --json <file>        write a JSON report ("-" for stdout)
  --sarif <file>       write SARIF 2.1.0 for GitHub code scanning ("-" for stdout)
  --only <list>        secrets,config,code,laravel,deps,headers
  --min <severity>     hide lower findings in the terminal
  --fail-on <sev>      exit 1 when a finding at/above this level exists
  --offline            skip the OSV lookup
  --no-probes          don't request /.env, /.git/config … on --url
  --save               also store the scan in the dashboard history
  -q, --quiet          no terminal output

tameng serve [--port 7777]   local dashboard
```

The JSON report also contains `surface`: the endpoint inventory described below.

## Dashboard

```bash
tameng serve            # → http://127.0.0.1:7777/
tameng ./my-app --save  # a CLI/CI scan that also lands in the dashboard history
```

Add your project folders (and optionally the URL where each one is deployed), then press **Scan now**. For every project you get:

- **Score trend** across all scans, and **what is new / fixed since the previous scan**. A check that did not run in both scans (offline, no URL) is listed as *not compared* instead of looking "fixed".
- **Findings** with filters by severity and text.
- **Attack surface**: every endpoint the code exposes. That includes Laravel routes (with the exact auth status), Next.js route handlers and `pages/api`, **Server Actions** (public POST endpoints even when no form uses them) and Express routes with their full mounted path. Each one is marked *auth required*, *auth check found*, *middleware auth*, *no auth* or *no auth check found*, so you can review the ones nobody guards.
  - Next.js `middleware.ts` / `proxy.ts`: its `matcher` (path patterns and regex groups) and Clerk `createRouteMatcher` public/protected lists decide which routes it covers. It only counts when it actually runs an auth check (next-auth, Clerk, Supabase, `getToken`, a session cookie, …).
  - Express: `app.use('/api', requireAuth, apiRouter)` gives every route in `apiRouter`'s file the `/api` prefix and the auth guard. Mounts nest across files (`require`/`import`) and work with routers declared in the same file.

History is stored in `~/.tameng` (override with `TAMENG_HOME`). Reports there contain only masked secrets.

The dashboard can start scans, so it is locked down: it listens on `127.0.0.1` only, rejects foreign `Host` headers (DNS rebinding), requires a per-process token for every API call, only accepts same-origin JSON requests (no CSRF), and serves a strict nonce-based CSP.

Exit codes: `0` ok, `1` the `--fail-on` threshold was hit, `2` usage or runtime error.

### Ignoring things

- Add `tameng-ignore` anywhere on a line to skip that line.
- Add a `.tamengignore` file (same syntax as `.gitignore`) to skip paths:

```
docs/
legacy/old-admin/
```

`node_modules`, `vendor`, `dist`, `build`, `.next`, `storage` and similar folders are always skipped. Test folders are skipped for code patterns and generic passwords, but recognisable API keys in tests are still reported.

## Use it in GitHub Actions

```yaml
# .github/workflows/security.yml
name: security
on: [push, pull_request]
jobs:
  tameng:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - run: npx --yes github:YOUR_USER/tameng . --fail-on high --html tameng-report.html
      - uses: actions/upload-artifact@v4
        if: always()
        with: { name: tameng-report, path: tameng-report.html }
```

### Findings in the Security tab and on pull requests (SARIF)

```yaml
# .github/workflows/tameng-code-scanning.yml
name: tameng code scanning
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  tameng:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - run: npx --yes github:YOUR_USER/tameng . --sarif tameng.sarif -q
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: tameng.sarif, category: tameng }
```

Each finding becomes a code-scanning alert on its file and line, with the fix as help text and GitHub's severity derived from tameng's. Live-site findings (`--url`) have no file to attach to, so they are left out of SARIF. Their count is kept in `runs[0].properties.liveSiteFindingsOmitted`.

## Score

Every scan starts at 100. Each finding takes points off: critical −25, high −10, medium −4, low −1. Grades: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, F below that. Use the score to track progress, but fix the criticals first.

## Limits (be honest with yourself)

- The code checks point you to places worth reviewing; they are not proof of a vulnerability, and they will miss logic bugs. Taint tracking stays inside one file and does not follow data through your own helper functions: a helper is assumed to validate, which avoids false alarms but can hide a real flow. For whole-program analysis, add Semgrep or CodeQL.
- The attack-surface inventory and the Laravel route checks read your code, not your running app. Middleware registered in unusual ways (packages, custom route macros, Next.js matchers with `has`/`missing` conditions) is not counted, so a guarded route can look open. Treat them as a review list.
- `--url` sends a handful of ordinary GET requests (about 12). **Only scan sites you own or are authorised to test.**

## Development

```bash
npm test     # node:test, no dependencies; fixtures are generated at runtime
```

The project layout:

```
bin/tameng.js            CLI (scan, serve)
src/index.js             orchestrator (runScan)
src/files.js             file walker, .gitignore/.tamengignore matcher
src/scanners/*.js        secrets, config, code, laravel, deps, headers
src/taint.js             JS/TS lexer + intra-file taint tracking (source → sink)
src/surface.js           endpoint inventory (attack surface)
src/history.js           ~/.tameng store, diff between scans
src/reporters/*.js       console, html, sarif
src/dashboard/           local server + single-page UI
test/                    unit and end-to-end tests
```

To add a rule, append an entry to `RULES` in `src/scanners/code.js` or `secrets.js` and add a case to the tests.

## License

MIT
