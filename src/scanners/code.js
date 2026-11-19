import { finding } from '../findings.js';
import { isTestPath, snippet } from '../files.js';
import { analyzeProject, SINKS } from '../taint.js';

const SCANNER = 'code';

const JS = /\.(?:[cm]?[jt]sx?)$/;
const VUE = /\.vue$/;
const PHP = /\.php$/;
const BLADE = /\.blade\.php$/;
const PY = /\.py$/;

/**
 * Pattern rules for risky code. These are "look here" pointers, not proofs:
 * each one names the pattern and how to make it safe.
 */
const RULES = [
  // ── JavaScript / TypeScript ─────────────────────────────────────────
  { id: 'js-sql-injection', lang: JS, severity: 'high', title: 'SQL built with string interpolation',
    re: /\.(?:query|execute|raw|unsafe|\$queryRawUnsafe|\$executeRawUnsafe)\s*\(\s*(?:`[^`]*\$\{|['"]\s*(?:SELECT|INSERT|UPDATE|DELETE|REPLACE)\b[^'"]*['"]\s*\+)/i,
    fix: 'Use placeholders: db.query("SELECT * FROM users WHERE id = ?", [id]).' },
  { id: 'js-command-injection', lang: JS, severity: 'high', title: 'Shell command built from variables',
    re: /\b(?:exec|execSync|spawnSync|spawn)\s*\(\s*(?:`[^`]*\$\{|['"][^'"]*['"]\s*\+)/,
    fix: 'Use execFile/spawn with an argument array and never pass user input through a shell.' },
  { id: 'js-eval-request', lang: JS, severity: 'high', title: 'eval() on request data (remote code execution)',
    re: /(?<![.\w])eval\s*\(\s*req\./, fix: 'Parse the value instead, e.g. Number(req.body.x) or JSON.parse; never eval user input.' },
  { id: 'js-eval', lang: JS, severity: 'medium', title: 'eval() / new Function()',
    re: /(?<![.\w])eval\s*\((?!\s*req\.)|\bnew\s+Function\s*\(/,
    fix: 'Replace with JSON.parse or explicit logic; eval on user input is remote code execution.' },
  { id: 'js-tls-disabled', lang: JS, severity: 'medium', title: 'TLS certificate verification disabled',
    re: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0/,
    fix: 'Keep verification on; add the CA certificate instead of disabling the check.' },
  { id: 'js-mongo-where', lang: JS, severity: 'medium', title: 'MongoDB $where operator',
    re: /['"]?\$where['"]?\s*:/, fix: 'Rewrite the query with normal operators; $where runs JavaScript on the server.' },
  { id: 'js-open-redirect', lang: JS, severity: 'medium', title: 'Redirect target taken from the request',
    re: /\bres\.redirect\s*\(\s*req\.(?:query|body|params)\b/,
    fix: 'Only redirect to relative paths or an allow-list of URLs.' },
  { id: 'js-nosql-injection', lang: JS, severity: 'high', title: 'Query filter taken straight from the request',
    re: /\.(?:find|findOne|findOneAndUpdate|findOneAndDelete|updateOne|updateMany|deleteOne|deleteMany|countDocuments|exists)\s*\(\s*req\.(?:body|query|params)\s*[,)]/,
    fix: 'Build the filter from validated fields: findOne({ email: String(req.body.email) }); a raw body lets clients send operators like {"$ne": null}.' },
  { id: 'js-path-traversal', lang: JS, severity: 'high', title: 'File path taken from the request',
    re: /(?:\bres\.(?:sendFile|download)|\bfs(?:\.promises)?\.(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlink|unlinkSync|rm|rmSync))\s*\(\s*(?:path\.(?:join|resolve)\s*\([^)]*?)?req\.(?:query|body|params)\.(?![^;]*\broot\s*:)/,
    fix: 'Resolve the path, then check it stays inside your base folder: if (!full.startsWith(BASE + path.sep)) reject; or use res.sendFile(name, { root: BASE }).' },
  { id: 'js-ssrf', lang: JS, severity: 'medium', title: 'Server-side request to a URL from the request',
    re: /\b(?:fetch|axios(?:\.(?:get|post|put|patch|delete|head|request))?|got|needle)\s*\(\s*(?:req\.(?:query|body|params)\.|searchParams\.get\s*\()/,
    fix: 'Only allow http(s) URLs on an allow-list of hosts, and block private/loopback IPs (169.254.169.254, 10.x, 127.x) after DNS resolution.' },
  { id: 'express-static-root', lang: JS, severity: 'high', title: 'express.static serves the whole project folder',
    re: /\bexpress\.static\s*\(\s*(?:['"]\.\/?['"]|__dirname\s*\)|process\.cwd\(\)\s*\)|path\.(?:join|resolve)\s*\(\s*__dirname\s*\))/,
    fix: 'Serve a dedicated folder only: express.static(path.join(__dirname, "public")); otherwise /.env and your source are downloadable.' },
  { id: 'react-dangerous-html', lang: JS, severity: 'low', title: 'dangerouslySetInnerHTML',
    re: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?!['"`])/,
    fix: 'Sanitize with DOMPurify first, or render the data as text.' },
  { id: 'js-inner-html', lang: JS, severity: 'low', title: 'innerHTML assigned from a variable',
    // Skips string literals and ALL_CAPS constants (cond ? A_ICON : B_ICON), which by convention never hold user data.
    re: /\.(?:innerHTML|outerHTML)\s*=\s*(?!\s*['"`]|\s*$|\s*(?:[\w.!]+\s*\?\s*)?[A-Z][A-Z0-9_]*(?:\s*:\s*[A-Z][A-Z0-9_]*)?\s*;?\s*$)/, fix: 'Use textContent, or sanitize the HTML with DOMPurify.' },
  { id: 'vue-v-html', lang: VUE, severity: 'low', title: 'v-html renders raw HTML', re: /\bv-html\s*=/,
    fix: 'Use {{ }} interpolation, or sanitize the HTML with DOMPurify.' },

  // ── PHP / Laravel ───────────────────────────────────────────────────
  { id: 'php-sql-injection', lang: PHP, severity: 'high', title: 'Raw SQL with interpolated variables',
    re: /(?:DB::(?:raw|select|statement|unprepared|insert|update|delete)|->(?:where|select|orderBy|having|groupBy)Raw|->query|mysqli_query)\s*\((?:\s*\$\w+\s*,)?\s*(?:"[^"]*\$[a-zA-Z_{]|['"][^'"]*['"]\s*\.\s*\$)/,
    fix: 'Use bindings: DB::select("... where id = ?", [$id]) or whereRaw("x = ?", [$value]).' },
  { id: 'php-superglobal-query', lang: PHP, severity: 'high', title: 'Request data passed straight into a query',
    re: /(?:->query|mysqli_query|mysql_query|pg_query)\s*\([^;]*\$_(?:GET|POST|REQUEST|COOKIE)/,
    fix: 'Use prepared statements (PDO::prepare / mysqli_prepare) or the query builder.' },
  { id: 'php-command-injection', lang: PHP, severity: 'high', title: 'Shell command with request data',
    re: /\b(?:shell_exec|exec|system|passthru|popen|proc_open)\s*\([^;]*(?:\$_(?:GET|POST|REQUEST|COOKIE)|\$request|request\()/,
    fix: 'Avoid the shell; if you must, wrap every argument in escapeshellarg().' },
  { id: 'php-unserialize', lang: PHP, severity: 'high', title: 'unserialize() on request data',
    re: /\bunserialize\s*\([^;]*(?:\$_(?:GET|POST|REQUEST|COOKIE)|\$request|request\()/,
    fix: 'Use json_decode instead; unserialize on untrusted input enables object injection.' },
  { id: 'php-file-inclusion', lang: PHP, severity: 'high', title: 'include/require with a path from the request',
    re: /\b(?:include|include_once|require|require_once)\b\s*\(?[^;]*(?:\$_(?:GET|POST|REQUEST|COOKIE)|\$request->(?:input|query|get)\s*\(|request\s*\(\s*['"])/,
    fix: 'Map the request value to a fixed allow-list: $pages = ["home" => "home.php"]; include $pages[$key] ?? "404.php";' },
  { id: 'php-file-from-request', lang: PHP, severity: 'high', title: 'File read with a path or URL from the request',
    re: /\b(?:file_get_contents|fopen|readfile|file|unlink|copy)\s*\([^;]*(?:\$_(?:GET|POST|REQUEST|COOKIE)|\$request->(?:input|query|get)\s*\()/,
    fix: 'Use basename() plus a fixed base directory (and realpath() check) for files; for URLs, allow-list the hosts.' },
  { id: 'php-eval', lang: PHP, severity: 'medium', title: 'eval() in PHP', re: /(?<![\w>])eval\s*\(/,
    fix: 'Remove eval; there is almost always a safer construct.' },
  { id: 'laravel-mass-assignment', lang: PHP, severity: 'medium', title: 'Mass assignment guard disabled',
    re: /\$guarded\s*=\s*\[\s*\]|Model::unguard\(\)/,
    fix: 'Declare $fillable with the exact columns users may set.' },
  { id: 'laravel-request-all', lang: PHP, severity: 'low', title: 'Model filled with $request->all()',
    re: /::(?:create|update|fill|forceCreate)\s*\(\s*\$request->all\(\)|->(?:update|fill)\s*\(\s*\$request->all\(\)/,
    fix: 'Pass $request->validated() (or $request->only([...])) instead.' },
  { id: 'blade-unescaped', lang: BLADE, severity: 'low', title: 'Unescaped Blade output {!! !!}',
    re: /\{!!\s*(?!\s*(?:csrf_field|method_field|\$\w+->links|\$slot|\$attributes)\b)/,
    fix: 'Use {{ }} unless the HTML is trusted or sanitized (e.g. with HTMLPurifier).' },

  // ── Python ──────────────────────────────────────────────────────────
  { id: 'py-sql-injection', lang: PY, severity: 'high', title: 'SQL built with f-string / format',
    re: /\.execute\s*\(\s*(?:f["']|["'][^"']*["']\s*(?:%|\.format\())/,
    fix: 'Use parameters: cursor.execute("... WHERE id = %s", (user_id,)).' },
  { id: 'py-shell-true', lang: PY, severity: 'medium', title: 'subprocess with shell=True', re: /\bshell\s*=\s*True/,
    fix: 'Pass an argument list and leave shell=False.' },
  { id: 'py-tls-disabled', lang: PY, severity: 'medium', title: 'TLS verification disabled (verify=False)', re: /\bverify\s*=\s*False/,
    fix: 'Keep verification on; point verify= at a CA bundle if needed.' },
  { id: 'py-unsafe-deserialize', lang: PY, severity: 'medium', title: 'Unsafe deserialization',
    re: /\bpickle\.loads?\s*\(|\byaml\.load\s*\((?![^)]*Loader\s*=\s*(?:yaml\.)?SafeLoader)/,
    fix: 'Use json, or yaml.safe_load; never unpickle untrusted data.' },
];

export function scanCode(files) {
  const findings = [];
  const taint = projectTaint(files);
  for (const file of files) {
    if (isTestPath(file.rel)) continue;
    const rules = RULES.filter((r) => r.lang.test(file.name));
    if (!rules.length) continue;

    const lines = file.text.split(/\r?\n/);
    const flagged = new Set(); // "id:line" already reported by a pattern rule
    lines.forEach((line, i) => {
      if (line.length > 2000 || line.includes('tameng-ignore')) return;
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) return;
      for (const rule of rules) {
        if (!rule.re.test(line)) continue;
        flagged.add(`${rule.id}:${i + 1}`);
        findings.push(finding({
          id: rule.id, scanner: SCANNER, severity: rule.severity, title: rule.title,
          location: `${file.rel}:${i + 1}`, detail: snippet(line), fix: rule.fix,
        }));
      }
    });

    if (taint.has(file.rel)) findings.push(...taintFindings(file, lines, flagged, taint.get(file.rel)));
  }
  return findings;
}

/** Taint results for every JS/TS source file, analysed together so calls across files resolve. */
function projectTaint(files) {
  const js = files.filter((f) => JS.test(f.name) && !isTestPath(f.rel) && !f.text.split('\n').some((l) => l.length > 5000));
  try {
    return analyzeProject(js.map((f) => ({ rel: f.rel, text: f.text, nextAppFile: /(?:^|\/)(?:src\/)?app\//.test(f.rel) })));
  } catch {
    return new Map(); // unusual syntax: the line-based rules still ran
  }
}

/** Flows found by taint tracking: across lines, through helpers, across files. */
function taintFindings(file, lines, flagged, results) {
  const out = [];
  for (const r of results) {
    const sink = SINKS[r.sink];
    const line = lines[r.line - 1] ?? '';
    if (line.includes('tameng-ignore') || flagged.has(`${sink.id}:${r.line}`)) continue;
    flagged.add(`${sink.id}:${r.line}`);
    out.push(finding({
      id: sink.id, scanner: SCANNER, severity: sink.severity, title: sink.title,
      location: `${file.rel}:${r.line}`, detail: `${snippet(line)}  ·  flow: ${r.flow}`, fix: sink.fix,
    }));
  }
  return out;
}
