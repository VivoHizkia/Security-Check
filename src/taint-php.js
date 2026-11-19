// Taint tracking for PHP / Laravel, across functions, methods and files.
//
// Same model as taint.js: request data (Laravel Request methods, request(), $_GET…, controller
// route parameters, uploaded file names) is followed through variables, string interpolation,
// concatenation and project functions/methods into SQL, shell, eval, include, file access,
// outgoing HTTP, redirects and unserialize.
//
// PHP specifics: variables are function-scoped (not block-scoped); closures only see `use (…)`
// variables; `fn () =>` sees the whole parent scope. Methods resolve through $this, self::,
// static::, Class::, typed parameters and promoted constructor properties
// ($this->users->find($id) → UserService::find). Library functions are clean unless listed as
// pass-through; helpers that can reject input (throw, abort, return null) are validators.

// ── Lexer ───────────────────────────────────────────────────────────

const PUNCT = ['<=>', '**=', '...', '??=', '?->', '===', '!==', '<<=', '>>=',
  '->', '=>', '::', '==', '!=', '<>', '<=', '>=', '&&', '||', '??', '++', '--', '+=', '-=', '*=', '/=', '.=', '%=',
  '&=', '|=', '^=', '<<', '>>', '**'];

/**
 * Tokens: { t: 'var' | 'id' | 'str' | 'dstr' | 'shell' | 'num' | 'p', v, line }.
 * 'dstr' (double-quoted / heredoc) and 'shell' (backticks) carry `head` (text before the first
 * interpolation) and `parts` (token lists of the interpolated expressions).
 */
export function lexPhpTokens(src) {
  const tokens = [];
  let i = 0;
  let line = 1;
  let php = !/^\s*<\?/.test(src) && !src.includes('<?') ? true : false; // a fragment without <?php is code
  const push = (t, v, extra) => tokens.push({ t, v, line, ...extra });
  const advance = (to) => { for (; i < to; i++) if (src[i] === '\n') line++; };

  /** Interpolated string body → { head, parts }. `end` is the index of the closing delimiter. */
  const interpolate = (body, startLine) => {
    const parts = [];
    let head = null;
    let k = 0;
    let lineHere = startLine;
    while (k < body.length) {
      const c = body[k];
      if (c === '\n') lineHere++;
      if (c === '\\') { k += 2; continue; }
      const simple = c === '$' && /[A-Za-z_]/.test(body[k + 1] || '');
      const braced = c === '{' && body[k + 1] === '$';
      const dollarBrace = c === '$' && body[k + 1] === '{';
      if (!simple && !braced && !dollarBrace) { k++; continue; }
      if (head === null) head = body.slice(0, k);
      if (simple) {
        let m = body.slice(k).match(/^\$[A-Za-z_]\w*(?:->[A-Za-z_]\w*|\[[^\]\n]{0,80}\])?/)[0];
        parts.push(lexPhpTokens(`<?php ${m};`).map((t) => ({ ...t, line: lineHere })));
        k += m.length;
      } else {
        let depth = 0;
        let e = k;
        for (; e < body.length; e++) {
          if (body[e] === '{') depth++;
          else if (body[e] === '}' && --depth === 0) break;
        }
        const inner = body.slice(k + (braced ? 1 : 2), e);
        parts.push(lexPhpTokens(`<?php ${dollarBrace ? `$${inner}` : inner};`).map((t) => ({ ...t, line: lineHere })));
        k = e + 1;
      }
    }
    return { head: head === null ? body : head, parts };
  };

  while (i < src.length) {
    if (!php) {
      const open = src.indexOf('<?', i);
      if (open === -1) { advance(src.length); break; }
      advance(open);
      i += src.startsWith('<?php', i) ? 5 : src.startsWith('<?=', i) ? 3 : 2;
      php = true;
      continue;
    }
    const c = src[i];
    const n = src[i + 1];
    if (c === '\n') { line++; i++; continue; }
    if (c === ' ' || c === '\t' || c === '\r') { i++; continue; }
    if (c === '?' && n === '>') { i += 2; php = false; push('p', ';'); continue; }
    if ((c === '/' && n === '/') || (c === '#' && n !== '[')) {
      while (i < src.length && src[i] !== '\n' && !(src[i] === '?' && src[i + 1] === '>')) i++;
      continue;
    }
    if (c === '#' && n === '[') { // attribute
      let depth = 0;
      let e = i + 1;
      for (; e < src.length; e++) { if (src[e] === '[') depth++; else if (src[e] === ']' && --depth === 0) break; }
      advance(e + 1);
      continue;
    }
    if (c === '/' && n === '*') { const end = src.indexOf('*/', i + 2); advance(end === -1 ? src.length : end + 2); continue; }
    if (c === '$' && /[A-Za-z_]/.test(n || '')) {
      let j = i + 1;
      while (j < src.length && /\w/.test(src[j])) j++;
      push('var', src.slice(i + 1, j));
      i = j;
      continue;
    }
    if (c === '\'') {
      let j = i + 1;
      while (j < src.length && src[j] !== '\'') j += src[j] === '\\' ? 2 : 1;
      const startLine = line;
      push('str', src.slice(i + 1, j).replace(/\\(['\\])/g, '$1'));
      tokens[tokens.length - 1].line = startLine;
      advance(j + 1);
      continue;
    }
    if (c === '"' || c === '`') {
      let j = i + 1;
      while (j < src.length && src[j] !== c) j += src[j] === '\\' ? 2 : 1;
      const startLine = line;
      const { head, parts } = interpolate(src.slice(i + 1, j), startLine);
      tokens.push({ t: c === '`' ? 'shell' : 'dstr', v: src.slice(i + 1, j), head, parts, line: startLine });
      advance(j + 1);
      continue;
    }
    if (c === '<' && src.startsWith('<<<', i)) { // heredoc / nowdoc
      const m = src.slice(i, i + 120).match(/^<<<[ \t]*(['"]?)([A-Za-z_]\w*)\1\r?\n/);
      if (m) {
        const closeRe = new RegExp(`\\n[ \\t]*${m[2]}\\b`);
        const bodyStart = i + m[0].length;
        const rel = src.slice(bodyStart).search(closeRe);
        const bodyEnd = rel === -1 ? src.length : bodyStart + rel;
        const startLine = line;
        if (m[1] === '\'') tokens.push({ t: 'str', v: src.slice(bodyStart, bodyEnd), line: startLine });
        else {
          const { head, parts } = interpolate(src.slice(bodyStart, bodyEnd), startLine + 1);
          tokens.push({ t: 'dstr', v: src.slice(bodyStart, bodyEnd), head, parts, line: startLine });
        }
        const after = rel === -1 ? src.length : bodyEnd + src.slice(bodyEnd).match(closeRe)[0].length;
        advance(after);
        continue;
      }
    }
    if (/[A-Za-z_\\]/.test(c)) {
      let j = i + 1;
      while (j < src.length && /[\w\\]/.test(src[j])) j++;
      push('id', src.slice(i, j));
      i = j;
      continue;
    }
    if (/[0-9]/.test(c)) {
      let j = i + 1;
      while (j < src.length && /[\w.]/.test(src[j])) j++;
      push('num', src.slice(i, j));
      i = j;
      continue;
    }
    const multi = PUNCT.find((p) => src.startsWith(p, i));
    push('p', multi || c);
    i += multi ? multi.length : 1;
  }
  return tokens;
}

// ── Helpers ─────────────────────────────────────────────────────────

const OPENERS = { '(': ')', '[': ']', '{': '}' };
const isP = (t, v) => t?.t === 'p' && t.v === v;
const isId = (t, v) => t?.t === 'id' && t.v.toLowerCase() === v;
const short = (name) => name.replace(/^\\/, '').split('\\').pop();

function skipGroup(toks, i) {
  let depth = 0;
  for (let j = i; j < toks.length; j++) {
    const k = toks[j];
    if (k.t === 'p' && OPENERS[k.v]) depth++;
    else if (k.t === 'p' && (k.v === ')' || k.v === ']' || k.v === '}')) depth--;
    if (depth === 0) return j + 1;
  }
  return toks.length;
}

/** Statement end from j: the `;` at depth 0 (or a closing bracket of an enclosing group). */
function statementEnd(toks, j) {
  let depth = 0;
  for (let k = j; k < toks.length; k++) {
    const t = toks[k];
    if (t.t === 'p' && OPENERS[t.v]) depth++;
    else if (t.t === 'p' && (t.v === ')' || t.v === ']' || t.v === '}')) { if (depth === 0) return k; depth--; }
    else if (depth === 0 && isP(t, ';')) return k + 1;
  }
  return toks.length;
}

/** Parameters of the `(` at `open`: [{ name, type, visibility, index }] and the closing index. */
function paramList(toks, open) {
  const close = skipGroup(toks, open);
  const params = [];
  let index = 0;
  let depth = 0;
  let pending = { type: null, visibility: null };
  let inDefault = false;
  for (let p = open + 1; p < close - 1; p++) {
    const t = toks[p];
    if (t.t === 'p' && OPENERS[t.v]) { depth++; continue; }
    if (t.t === 'p' && [')', ']', '}'].includes(t.v)) { depth--; continue; }
    if (depth > 0) continue;
    if (isP(t, ',')) { index++; pending = { type: null, visibility: null }; inDefault = false; continue; }
    if (isP(t, '=')) { inDefault = true; continue; }
    if (inDefault) continue;
    if (t.t === 'id') {
      const v = t.v.toLowerCase();
      if (['public', 'protected', 'private'].includes(v)) pending.visibility = v;
      else if (v !== 'readonly') pending.type = pending.type ? `${pending.type}|${t.v}` : t.v;
      continue;
    }
    if (t.t === 'var') params.push({ name: t.v, type: pending.type, visibility: pending.visibility, index });
  }
  return { params, close };
}

// ── Sources, sinks, pass-throughs ──────────────────────────────────

const SUPERGLOBALS = new Set(['_GET', '_POST', '_REQUEST', '_COOKIE', '_FILES']);
const REQUEST_INPUT = new Set(['input', 'get', 'query', 'post', 'all', 'only', 'except', 'route', 'header', 'cookie', 'string', 'str',
  'json', 'validated', 'safe', 'collect', 'keys', 'getcontent', 'server']);
const REQUEST_NOT_INPUT_PROPS = new Set(['attributes', 'files', 'server', 'headers', 'cookies', 'session']);
const UPLOAD_NAME = new Set(['getclientoriginalname', 'getclientoriginalextension', 'getclientmimetype']);
const SCALAR_TYPES = /^\??(?:string|mixed)$/i; // route parameters typed like this carry raw input

const PASS_THROUGH = new Set(['trim', 'ltrim', 'rtrim', 'strtolower', 'strtoupper', 'ucfirst', 'lcfirst', 'urldecode', 'rawurldecode',
  'base64_decode', 'json_decode', 'sprintf', 'vsprintf', 'implode', 'join', 'str_pad', 'substr', 'mb_substr', 'mb_strtolower',
  'mb_strtoupper', 'strval', 'html_entity_decode', 'stripslashes', 'str_replace', 'str_ireplace', 'preg_replace', 'storage_path',
  'public_path', 'base_path', 'app_path', 'resource_path', 'database_path', 'config_path', 'realpath', 'dirname', 'array_merge',
  'array_values', 'reset', 'end', 'current', 'array_shift', 'array_pop', 'data_get', 'arr::get', 'str::lower', 'str::upper',
  'str::of', 'str::replace', 'str::after', 'str::before', 'str::finish', 'str::start', 'str::slug', 'urlencode', 'rawurlencode']);
const CLEANERS = new Set(['intval', 'floatval', 'boolval', 'basename', 'escapeshellarg', 'escapeshellcmd', 'addslashes',
  'mysqli_real_escape_string', 'pg_escape_string', 'pg_escape_literal', 'md5', 'sha1', 'hash', 'password_hash', 'count', 'strlen',
  'is_numeric', 'ctype_digit', 'in_array', 'array_key_exists', 'isset', 'empty', 'uniqid', 'str::uuid', 'str::random', 'crc32']);
const CASTS_CLEAN = new Set(['int', 'integer', 'float', 'double', 'bool', 'boolean']);

export const PHP_SINKS = {
  sql: { id: 'php-sql-injection', severity: 'high', title: 'Request data reaches a raw SQL query',
    fix: 'Use bindings: DB::select("… where id = ?", [$id]), whereRaw("x = ?", [$v]), or the query builder; never interpolate input into SQL.' },
  cmd: { id: 'php-command-injection', severity: 'high', title: 'Request data reaches a shell command',
    fix: 'Avoid the shell: Process::run([...]) with an argument array, or wrap every value in escapeshellarg() and allow-list it.' },
  eval: { id: 'php-code-injection', severity: 'high', title: 'Request data reaches eval / assert',
    fix: 'Remove eval; parse or map the value instead. Executing request data is remote code execution.' },
  include: { id: 'php-file-inclusion', severity: 'high', title: 'Request data decides which file is included',
    fix: 'Map the value to a fixed allow-list: $pages = ["home" => "home.php"]; include $pages[$key] ?? "404.php";' },
  file: { id: 'php-file-from-request', severity: 'high', title: 'Request data reaches a file path or URL read',
    fix: 'Use basename() with a fixed base directory and check realpath() stays inside it; never pass input straight to file functions.' },
  ssrf: { id: 'php-ssrf', severity: 'medium', title: 'Server-side HTTP request to a URL from the request',
    fix: 'Allow only https URLs on an allow-list of hosts and block private/loopback IPs (169.254.169.254, 10.x, 127.x) after DNS resolution.' },
  redirect: { id: 'php-open-redirect', severity: 'medium', title: 'Redirect target comes from the request',
    fix: 'Redirect only to a named route, a relative path starting with a single "/", or an allow-list of URLs.' },
  unserialize: { id: 'php-unserialize', severity: 'high', title: 'unserialize() on request data',
    fix: 'Use json_decode instead; unserialize on untrusted input enables object injection.' },
};

const VALID = { NONE: 0, RELATIVE: 1, STRICT: 2, EXACT: 3 };
const NEEDED = { ssrf: VALID.RELATIVE, redirect: VALID.STRICT };
const needed = (sink) => NEEDED[sink] ?? VALID.EXACT;

const FILE_FUNCS = new Set(['file_get_contents', 'fopen', 'readfile', 'file', 'unlink', 'copy', 'rename', 'file_put_contents',
  'mkdir', 'rmdir', 'opendir', 'scandir', 'parse_ini_file', 'simplexml_load_file', 'fpassthru', 'glob']);
const CMD_FUNCS = new Set(['exec', 'shell_exec', 'system', 'passthru', 'popen', 'proc_open', 'pcntl_exec']);
const DB_STATIC_SQL = new Set(['select', 'statement', 'unprepared', 'insert', 'update', 'delete', 'raw', 'scalar', 'selectone', 'cursor', 'affectingstatement']);
const RAW_METHODS = new Set(['whereraw', 'orwhereraw', 'selectraw', 'orderbyraw', 'havingraw', 'orhavingraw', 'groupbyraw', 'fromraw', 'wherecolumnraw']);
const HTTP_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'head', 'send']);

/**
 * Sink for a call. `call`: { kind: 'func' | 'static' | 'method', name, cls?, receiver?, chainHead? }.
 * Returns { sink, arg } (arg = argument index to check, 'all', or 'location' for header()) or null.
 */
function classifySink(call) {
  const name = call.name.toLowerCase();
  if (call.kind === 'func') {
    if (name === 'eval' || name === 'assert') return { sink: 'eval', arg: 0 };
    if (name === 'create_function') return { sink: 'eval', arg: 1 };
    if (CMD_FUNCS.has(name)) return { sink: 'cmd', arg: 0 };
    if (FILE_FUNCS.has(name)) return { sink: 'file', arg: name === 'copy' || name === 'rename' ? 'all' : 0 };
    if (name === 'mysqli_query') return { sink: 'sql', arg: 1 };
    if (name === 'mysql_query' || name === 'sqlsrv_query') return { sink: 'sql', arg: name === 'sqlsrv_query' ? 1 : 0 };
    if (name === 'pg_query') return { sink: 'sql', arg: 'last' };
    if (name === 'curl_init' || name === 'get_headers' || name === 'fsockopen') return { sink: 'ssrf', arg: 0 };
    if (name === 'curl_setopt') return { sink: 'ssrf', arg: 2, when: (args) => args[1]?.text === 'CURLOPT_URL' };
    if (name === 'redirect') return { sink: 'redirect', arg: 0 };
    if (name === 'header') return { sink: 'redirect', arg: 'location' };
    if (name === 'unserialize') return { sink: 'unserialize', arg: 0 };
    return null;
  }
  const cls = (call.cls || '').toLowerCase();
  if (call.kind === 'static') {
    if (cls === 'db' && DB_STATIC_SQL.has(name)) return { sink: 'sql', arg: 0 };
    if (cls === 'http' && HTTP_METHODS.has(name)) return { sink: 'ssrf', arg: name === 'send' ? 1 : 0 };
    if (cls === 'process' && ['run', 'start', 'fromshellcommandline'].includes(name)) return { sink: 'cmd', arg: 0, stringOnly: true };
    if (cls === 'storage' && ['get', 'download', 'delete', 'put', 'readstream', 'response', 'exists', 'path'].includes(name)) return { sink: 'file', arg: 0 };
    if (cls === 'file' && ['get', 'delete', 'put', 'requireonce', 'getrequire', 'exists'].includes(name)) return { sink: 'file', arg: 0 };
    if (cls === 'redirect' && ['to', 'away'].includes(name)) return { sink: 'redirect', arg: 0 };
    return null;
  }
  // method call
  const head = (call.chainHead || '').toLowerCase();
  if (RAW_METHODS.has(name)) return { sink: 'sql', arg: 0 };
  if (head === 'http' && HTTP_METHODS.has(name)) return { sink: 'ssrf', arg: name === 'send' ? 1 : 0 };
  if (head === 'storage' && ['get', 'download', 'delete', 'put', 'readstream', 'response', 'path'].includes(name)) return { sink: 'file', arg: 0 };
  if (head === 'redirect()' && ['to', 'away'].includes(name)) return { sink: 'redirect', arg: 0 };
  if (head === 'response()' && ['download', 'file'].includes(name)) return { sink: 'file', arg: 0 };
  const recv = (call.receiver || '').toLowerCase();
  if (/(?:pdo|db|dbh|conn|connection|mysqli|database)$/.test(recv) && ['query', 'exec', 'prepare', 'multi_query', 'real_query'].includes(name)) return { sink: 'sql', arg: 0 };
  if (/(?:client|guzzle|http)$/.test(recv) && ['get', 'post', 'put', 'patch', 'delete', 'head'].includes(name)) return { sink: 'ssrf', arg: 0 };
  if (/(?:client|guzzle|http)$/.test(recv) && name === 'request') return { sink: 'ssrf', arg: 1 };
  return null;
}

/** Validation found in a condition (or abort_if/abort_unless arguments): var → level. */
function guardChecks(cond) {
  const found = new Map();
  const raise = (v, level) => found.set(v, Math.max(found.get(v) || 0, level));
  const prefixes = new Map();
  for (let j = 0; j < cond.length; j++) {
    const k = cond[j];
    const callArg = (at) => (isP(cond[at], '(') && cond[at + 1]?.t === 'var' ? cond[at + 1].v : null);
    if (isId(k, 'in_array') || isId(k, 'ctype_digit') || isId(k, 'ctype_alnum') || isId(k, 'ctype_alpha') || isId(k, 'is_numeric') || isId(k, 'array_key_exists')) {
      const v = callArg(j + 1);
      if (v) raise(v, VALID.EXACT);
      if (isId(k, 'array_key_exists') && cond[j + 2]?.t === 'var') raise(cond[j + 2].v, VALID.EXACT);
    }
    if (isId(k, 'preg_match') && isP(cond[j + 1], '(') && (cond[j + 2]?.t === 'str' || cond[j + 2]?.t === 'dstr') && isP(cond[j + 3], ',') && cond[j + 4]?.t === 'var') {
      const re = cond[j + 2].v;
      const d = re[0];
      if (re[1] === '^' && new RegExp(`\\$\\${d}[a-z]*$`).test(re)) raise(cond[j + 4].v, VALID.EXACT);
    }
    if (isId(k, 'filter_var') && isP(cond[j + 1], '(') && cond[j + 2]?.t === 'var') {
      const end = skipGroup(cond, j + 1);
      if (cond.slice(j, end).some((t) => t.t === 'id' && /FILTER_VALIDATE_(?:INT|FLOAT|BOOL)/.test(t.v))) raise(cond[j + 2].v, VALID.EXACT);
    }
    if (k.t === 'p' && ['===', '==', '!==', '!='].includes(k.v)) {
      const [l, r] = [cond[j - 1], cond[j + 1]];
      if (l?.t === 'var' && r?.t === 'str' && r.v) raise(l.v, VALID.EXACT);
      if (r?.t === 'var' && l?.t === 'str' && l.v) raise(r.v, VALID.EXACT);
    }
    const startsWith = isId(k, 'str_starts_with') || (isId(k, 'str') && isP(cond[j + 1], '::') && isId(cond[j + 2], 'startswith'));
    if (startsWith) {
      const open = isId(k, 'str') ? j + 3 : j + 1;
      if (isP(cond[open], '(') && cond[open + 1]?.t === 'var' && isP(cond[open + 2], ',') && cond[open + 3]?.t === 'str') {
        const v = cond[open + 1].v;
        prefixes.set(v, new Set([...(prefixes.get(v) || []), cond[open + 3].v]));
      }
    }
  }
  for (const [v, set] of prefixes) {
    if (set.has('/') && set.has('//')) raise(v, VALID.STRICT);
    else if (set.has('/')) raise(v, VALID.RELATIVE);
  }
  return found;
}

const EXIT_WORDS = new Set(['return', 'throw', 'abort', 'exit', 'die', 'redirect']);

function isValidatorBody(body) {
  for (let j = 0; j < body.length; j++) {
    const t = body[j];
    if (t.t !== 'id') continue;
    const v = t.v.toLowerCase();
    if (['throw', 'abort', 'abort_if', 'abort_unless'].includes(v)) return true;
    if (v === 'if' && isP(body[j + 1], '(')) {
      const condEnd = skipGroup(body, j + 1);
      const blockEnd = isP(body[condEnd], '{') ? skipGroup(body, condEnd) : statementEnd(body, condEnd);
      for (let r = condEnd; r < blockEnd; r++) {
        if (isId(body[r], 'return')) {
          const nx = body[r + 1];
          if (!nx || isP(nx, ';') || isId(nx, 'null') || isId(nx, 'false')) return true;
        }
      }
    }
  }
  return false;
}

// ── Single-run analysis ─────────────────────────────────────────────

/**
 * env: { rel, resolve(call, ctx) → summary | null, params: [{ name, index }] | null,
 *        isControllerFile, cls (class name while summarising a method), propTypes (Map) }
 */
function analyzeTokens(toks, env) {
  const summaryMode = Boolean(env.params);
  const findings = [];
  const seen = new Set();
  const paramSinks = new Map();
  const returns = [];

  // Function-level scopes. Each frame: { vars: Map, requestVars: Set, varTypes: Map, cls, propTypes, depthAtStart }
  const frames = [{ vars: new Map(), requestVars: new Set(['request']), varTypes: new Map(), cls: env.cls || null, propTypes: env.propTypes || new Map() }];
  if (summaryMode) {
    for (const p of env.params) {
      frames[0].vars.set(p.name, { flow: `parameter $${p.name}`, raw: true, validated: 0, origins: [`p${p.index}`], line: 0 });
      if (p.type && /request$/i.test(short(p.type))) frames[0].requestVars.add(p.name);
      if (p.type && !/^\??(?:string|int|float|bool|array|mixed|callable|iterable|object|null)$/i.test(p.type)) frames[0].varTypes.set(p.name, short(p.type.replace(/^\?/, '')));
    }
  }
  const frame = () => frames[frames.length - 1];
  const lookup = (name) => frame().vars.get(name);

  /** Taint of `arr` from `from` to the end of the expression. */
  const exprTaint = (arr, from, { stopAtComma = true } = {}) => {
    let depth = 0;
    let flow = null;
    let raw = false;
    let validated = Infinity;
    const origins = new Set();
    let cleanNext = false;
    const take = (t) => {
      flow = flow || t.flow;
      if (t.raw) raw = true;
      validated = Math.min(validated, t.validated || 0);
      for (const o of t.origins) origins.add(o);
    };
    let j = from;
    for (; j < arr.length; j++) {
      const k = arr[j];
      if (depth === 0) {
        if (k.t === 'p' && [';', ')', ']', '}'].includes(k.v)) break;
        if (stopAtComma && isP(k, ',')) break;
      }
      // (int) $x
      if (isP(k, '(') && arr[j + 1]?.t === 'id' && isP(arr[j + 2], ')') && CASTS_CLEAN.has(arr[j + 1].v.toLowerCase())) { cleanNext = true; j += 2; continue; }
      if (isP(k, '(') && arr[j + 1]?.t === 'id' && isP(arr[j + 2], ')') && arr[j + 1].v.toLowerCase() === 'string') { j += 2; continue; }
      if (k.t === 'p' && OPENERS[k.v]) { depth++; continue; }
      if (k.t === 'p' && [')', ']', '}'].includes(k.v)) { depth--; continue; }
      if (k.t === 'dstr' || k.t === 'shell') {
        for (const part of k.parts) { const r = exprTaint(part, 0); if (r.flow) take({ ...r, raw: false }); }
        continue;
      }
      if (isId(k, 'function')) { // closure as a value
        const open = arr.findIndex((t, n) => n > j && isP(t, '{'));
        j = open === -1 ? arr.length : skipGroup(arr, open) - 1;
        continue;
      }
      if (isId(k, 'fn') && isP(arr[j + 1], '(')) { j = skipGroup(arr, j + 1); continue; } // fn () => … : skip params, body is read in place
      if (isP(arr[j - 1], '->') || isP(arr[j - 1], '?->') || isP(arr[j - 1], '::')) continue; // member name, not a value
      const ref = readRef(arr, j);
      if (!ref) continue;
      j = ref.end - 1;
      const t = valueOf(ref, arr);
      if (t && !cleanNext) take(t);
      cleanNext = false; // a cast applies to exactly one operand
    }
    return { flow, raw: Boolean(flow) && raw, validated: flow ? validated : 0, origins: [...origins], end: j };
  };

  /**
   * A value reference starting at j: a variable chain ($a->b->c(…)[…]), a function call, a static
   * call (Cls::m(…)), `new Cls(…)` or `request()->…`. Returns { kind, …, end } or null.
   */
  function readRef(arr, j) {
    const k = arr[j];
    const steps = []; // { op: '->' | '::' | '[]' | '()', name?, open? }
    let end;
    let base;
    if (k.t === 'var') { base = { type: 'var', name: k.v }; end = j + 1; }
    else if (k.t === 'id' && isP(arr[j + 1], '(')) { base = { type: 'func', name: k.v }; steps.push({ op: '()', open: j + 1 }); end = skipGroup(arr, j + 1); }
    else if (k.t === 'id' && isP(arr[j + 1], '::') && (arr[j + 2]?.t === 'id' || arr[j + 2]?.t === 'var')) { base = { type: 'class', name: k.v }; end = j + 1; }
    else if (isId(k, 'new') && arr[j + 1]?.t === 'id') {
      base = { type: 'new', name: arr[j + 1].v };
      end = isP(arr[j + 2], '(') ? skipGroup(arr, j + 2) : j + 2;
      if (isP(arr[j + 2], '(')) steps.push({ op: '()', open: j + 2 });
    } else return null;
    for (;;) {
      const t = arr[end];
      if ((isP(t, '->') || isP(t, '?->') || isP(t, '::')) && (arr[end + 1]?.t === 'id' || arr[end + 1]?.t === 'var')) {
        steps.push({ op: t.v === '::' ? '::' : '->', name: arr[end + 1].v });
        end += 2;
        if (isP(arr[end], '(')) { steps.push({ op: '()', open: end }); end = skipGroup(arr, end); }
        continue;
      }
      if (isP(t, '[')) { steps.push({ op: '[]', open: end }); end = skipGroup(arr, end); continue; }
      break;
    }
    return { base, steps, end, line: k.line };
  }

  /** Argument taints of the call whose `(` is at `open`. */
  function readArgs(arr, open) {
    const close = skipGroup(arr, open);
    const args = [];
    let p = open + 1;
    while (p < close - 1) {
      // named argument  name: value
      if (arr[p]?.t === 'id' && isP(arr[p + 1], ':') && !isP(arr[p + 1], '::')) p += 2;
      const r = exprTaint(arr, p);
      const text = arr.slice(p, r.end).map((t) => t.v).join('');
      args.push({ ...r, text, first: arr[p] });
      if (r.end <= p) break;
      p = isP(arr[r.end], ',') ? r.end + 1 : close;
    }
    return args;
  }

  /** Taint of a reference (variable chain, call…), or null. Also handles calls to summarised functions. */
  function valueOf(ref, arr) {
    const { base, steps } = ref;
    const f = frame();
    const req = (flow) => ({ flow, raw: true, validated: 0, origins: ['req'] });

    if (base.type === 'var') {
      if (SUPERGLOBALS.has(base.name)) return req(`$${base.name}`);
      if (f.requestVars.has(base.name) && steps.length) {
        const first = steps[0];
        if (first.op === '->' && steps[1]?.op === '()') {
          const m = first.name.toLowerCase();
          if (REQUEST_INPUT.has(m)) return req(`$${base.name}->${first.name}()`);
          if (m === 'file' && steps.some((s) => s.name && UPLOAD_NAME.has(s.name.toLowerCase()))) return req(`$${base.name}->file()->${steps.find((s) => s.name && UPLOAD_NAME.has(s.name.toLowerCase())).name}()`);
          return null; // user(), ip(), integer(), boolean() …
        }
        if (first.op === '->' && !REQUEST_NOT_INPUT_PROPS.has(first.name.toLowerCase())) {
          if (first.name.toLowerCase() === 'query' || first.name.toLowerCase() === 'request') return req(`$${base.name}->${first.name}`);
          return req(`$${base.name}->${first.name}`);
        }
        return null;
      }
      if (base.name === 'this') {
        // $this->method(…) / $this->prop->method(…)
        const call = steps.findIndex((s) => s.op === '()');
        if (call === 1 && steps[0].op === '->') return callValue({ kind: 'method', cls: f.cls, name: steps[0].name }, arr, steps[1].open, `$this->${steps[0].name}`);
        if (call === 2 && steps[0].op === '->' && steps[1].op === '->') {
          const type = f.propTypes.get(steps[0].name);
          if (type) return callValue({ kind: 'method', cls: type, name: steps[1].name }, arr, steps[2].open, `$this->${steps[0].name}->${steps[1].name}`);
        }
        return null;
      }
      // $svc->method(…) on a typed variable
      if (steps[0]?.op === '->' && steps[1]?.op === '()' && f.varTypes.has(base.name)) {
        return callValue({ kind: 'method', cls: f.varTypes.get(base.name), name: steps[0].name }, arr, steps[1].open, `$${base.name}->${steps[0].name}`);
      }
      const t = lookup(base.name);
      if (!t) return null;
      return { flow: t.line ? `${t.flow} → $${base.name} (line ${t.line})` : t.flow, raw: t.raw, validated: t.validated || 0, origins: t.origins };
    }

    if (base.type === 'func') {
      const name = base.name.toLowerCase();
      const open = steps[0].open;
      if (name === 'request') {
        const args = readArgs(arr, open);
        if (args.length) return req('request()');
        const m = steps[1]?.name?.toLowerCase();
        if (steps[1]?.op === '->' && m && REQUEST_INPUT.has(m)) return req(`request()->${steps[1].name}()`);
        if (steps[1]?.op === '->' && m && steps[2]?.op !== '()' && !REQUEST_NOT_INPUT_PROPS.has(m)) return req(`request()->${steps[1].name}`);
        return null;
      }
      if (name === 'filter_var') {
        const args = readArgs(arr, open);
        if (/FILTER_VALIDATE_(?:INT|FLOAT|BOOL)/.test(args[1]?.text || '')) return null;
        return args[0]?.flow ? args[0] : null;
      }
      if (CLEANERS.has(name)) return null;
      if (PASS_THROUGH.has(name)) {
        let out = null;
        for (const a of readArgs(arr, open)) if (a.flow) out = out ? { ...out, origins: [...new Set([...out.origins, ...a.origins])] } : { flow: `${a.flow} → ${base.name}()`, raw: false, validated: a.validated, origins: a.origins };
        return out;
      }
      return callValue({ kind: 'func', name: base.name }, arr, open, base.name);
    }

    if (base.type === 'class') {
      const cls = short(base.name);
      const lower = cls.toLowerCase();
      const first = steps[0];
      if (!first) return null;
      if (lower === 'request' && first.op === '::' && REQUEST_INPUT.has(first.name.toLowerCase())) return req(`Request::${first.name}()`);
      const key = `${lower}::${first.name.toLowerCase()}`;
      if (CLEANERS.has(key)) return null;
      if (PASS_THROUGH.has(key) && steps[1]?.op === '()') {
        let out = null;
        for (const a of readArgs(arr, steps[1].open)) if (a.flow) out = out || { flow: `${a.flow} → ${cls}::${first.name}()`, raw: false, validated: a.validated, origins: a.origins };
        return out;
      }
      if (steps[1]?.op === '()') {
        const target = ['self', 'static', 'parent'].includes(lower) ? f.cls : cls;
        return callValue({ kind: 'method', cls: target, name: first.name }, arr, steps[1].open, `${cls}::${first.name}`);
      }
      return null;
    }
    return null; // new Foo(…): an object, not request data
  }

  /** Value returned by a summarised project function or method. */
  function callValue(call, arr, open, label) {
    const summary = env.resolve(call);
    if (!summary) return null;
    const args = readArgs(arr, open);
    let res = null;
    const add = (t) => {
      if (!t?.flow) return;
      res = res ? { ...res, raw: res.raw || t.raw, validated: Math.min(res.validated, t.validated), origins: [...new Set([...res.origins, ...t.origins])] } : t;
    };
    for (const idx of summary.returnsParams) {
      const a = args[idx];
      if (a?.flow) add({ flow: `${a.flow} → ${label}()`, raw: a.raw && summary.returnRaw, validated: Math.max(a.validated, summary.returnValidated), origins: a.origins });
    }
    if (summary.returnsReq) add({ flow: `${summary.returnsReq} → ${label}()`, raw: summary.returnRaw, validated: 0, origins: ['req'] });
    return res;
  }

  const report = (kind, t, line, flowText, where) => {
    if (t.origins.includes('req') && !summaryMode) {
      const key = `${kind}:${line}`;
      if (!seen.has(key)) { seen.add(key); findings.push({ sink: kind, line, flow: flowText }); }
    }
    for (const o of t.origins) {
      if (!o.startsWith('p')) continue;
      const idx = Number(o.slice(1));
      const list = paramSinks.get(idx) || [];
      if (!list.some((x) => x.sink === kind && x.where === where)) list.push({ sink: kind, where });
      paramSinks.set(idx, list);
    }
  };

  /** Check a sink call: `args` are the argument taints, `spec` from classifySink. */
  const checkSink = (spec, args, line, label) => {
    let picks;
    if (spec.arg === 'all') picks = args;
    else if (spec.arg === 'last') picks = args.slice(-1);
    else if (spec.arg === 'location') {
      const a = args[0];
      if (!a || !/^location\s*:/i.test(a.first?.t === 'str' || a.first?.t === 'dstr' ? (a.first.head ?? a.first.v) : '')) return;
      const rest = (a.first.head ?? a.first.v).replace(/^location\s*:\s*/i, '');
      if (/^\/[^/\\]/.test(rest)) return; // Location: /fixed/path…
      picks = [a];
    } else picks = [args[spec.arg]];
    if (spec.when && !spec.when(args)) return;
    for (const a of picks) {
      if (!a?.flow) continue;
      if (spec.stringOnly && isP(a.first, '[')) continue; // Process::run([...]) runs without a shell
      // a literal head that pins the destination
      const head = a.first?.t === 'str' ? a.first.v : a.first?.t === 'dstr' ? a.first.head : null;
      if (head != null && spec.sink === 'redirect' && /^\/[^/\\]/.test(head)) continue;
      if (head != null && spec.sink === 'ssrf' && /^https?:\/\/[^/?#\s]+[/?#]/i.test(head)) continue;
      if (a.validated >= needed(spec.sink)) continue;
      report(spec.sink, a, line, `${a.flow} → ${label}()`, `${label}() (${env.rel}:${line})`);
    }
  };

  // Walk state
  const braceKinds = []; // 'fn' | 'class' | 'block'
  const pendingBodies = new Map(); // index of `{` → frame to push
  let currentClass = env.cls || null;
  const classAt = new Map(); // `{` index → class name
  const propTypes = env.propTypes || new Map();
  const arrowEnds = [];

  if (summaryMode && env.exprBody) {
    const r = exprTaint(toks, 0);
    if (r.flow) returns.push(r);
  }

  for (let i = 0; i < toks.length; i++) {
    const k = toks[i];
    while (arrowEnds.length && i >= arrowEnds[arrowEnds.length - 1]) { arrowEnds.pop(); frames.pop(); }

    if (isP(k, '{')) {
      if (pendingBodies.has(i)) { frames.push(pendingBodies.get(i)); braceKinds.push('fn'); }
      else if (classAt.has(i)) { currentClass = classAt.get(i); braceKinds.push('class'); }
      else braceKinds.push('block');
      continue;
    }
    if (isP(k, '}')) {
      const kind = braceKinds.pop();
      if (kind === 'fn' && frames.length > 1) frames.pop();
      if (kind === 'class') currentClass = env.cls || null;
      continue;
    }

    // backtick shell execution
    if (k.t === 'shell') {
      for (const part of k.parts) {
        const r = exprTaint(part, 0);
        if (r.flow) report('cmd', r, k.line, `${r.flow} → \`…\``, `backtick shell (${env.rel}:${k.line})`);
      }
      continue;
    }

    if (k.t === 'id') {
      const v = k.v.toLowerCase();

      if ((v === 'class' || v === 'trait') && toks[i + 1]?.t === 'id' && !isP(toks[i - 1], '::')) {
        const open = toks.findIndex((t, n) => n > i && isP(t, '{'));
        if (open !== -1) classAt.set(open, toks[i + 1].v);
        continue;
      }

      if (v === 'return' && summaryMode && frames.length === 1 && braceKinds.every((b) => b !== 'fn')) {
        const r = exprTaint(toks, i + 1);
        if (r.flow) returns.push(r);
        continue;
      }

      // include / require (language constructs, parentheses optional)
      if (['include', 'include_once', 'require', 'require_once'].includes(v)) {
        const r = exprTaint(toks, i + 1);
        if (r.flow && r.validated < VALID.EXACT) report('include', r, k.line, `${r.flow} → ${v}`, `${v} (${env.rel}:${k.line})`);
        continue;
      }

      // if (…) guards and abort_if / abort_unless
      if ((v === 'if' || v === 'elseif') && isP(toks[i + 1], '(')) {
        const condEnd = skipGroup(toks, i + 1);
        const checks = guardChecks(toks.slice(i + 2, condEnd - 1));
        if (checks.size) {
          const blockEnd = isP(toks[condEnd], '{') ? skipGroup(toks, condEnd) : statementEnd(toks, condEnd);
          const exits = toks.slice(condEnd, blockEnd).some((t) => t.t === 'id' && EXIT_WORDS.has(t.v.toLowerCase()));
          if (exits) {
            for (const [name, level] of checks) {
              const info = lookup(name);
              if (info) frame().vars.set(name, { ...info, validated: Math.max(info.validated || 0, level) });
            }
          }
        }
        continue;
      }
      if ((v === 'abort_if' || v === 'abort_unless') && isP(toks[i + 1], '(')) {
        const end = skipGroup(toks, i + 1);
        for (const [name, level] of guardChecks(toks.slice(i + 2, end - 1))) {
          const info = lookup(name);
          if (info) frame().vars.set(name, { ...info, validated: Math.max(info.validated || 0, level) });
        }
        continue;
      }

      // foreach ($list as $k => $v)
      if (v === 'foreach' && isP(toks[i + 1], '(')) {
        const end = skipGroup(toks, i + 1);
        const asAt = toks.findIndex((t, n) => n > i + 1 && n < end && isId(t, 'as'));
        if (asAt !== -1) {
          const src = exprTaint(toks, i + 2, { stopAtComma: false });
          const vars = toks.slice(asAt + 1, end - 1).filter((t) => t.t === 'var').map((t) => t.v);
          for (const name of vars) frame().vars.set(name, src.flow ? { ...src, line: k.line } : undefined);
        }
        continue;
      }

      // function / method / closure
      if (v === 'function') {
        const named = toks[i + 1]?.t === 'id' && isP(toks[i + 2], '(');
        const amp = isP(toks[i + 1], '&') ? 1 : 0;
        const open = named ? i + 2 : (isP(toks[i + 1 + amp], '(') ? i + 1 + amp : -1);
        if (open === -1) continue;
        const { params, close } = paramList(toks, open);
        let body = close;
        const uses = [];
        if (isId(toks[body], 'use') && isP(toks[body + 1], '(')) {
          const ue = skipGroup(toks, body + 1);
          for (let u = body + 2; u < ue - 1; u++) if (toks[u].t === 'var') uses.push(toks[u].v);
          body = ue;
        }
        while (body < toks.length && !isP(toks[body], '{') && !isP(toks[body], ';')) body++;
        if (!isP(toks[body], '{')) continue; // abstract / interface method
        const methodName = named ? toks[i + 1].v : null;
        const modifiers = toks.slice(Math.max(0, i - 3), i).map((t) => t.v.toLowerCase());
        const isPublic = !modifiers.includes('private') && !modifiers.includes('protected');
        const newFrame = { vars: new Map(), requestVars: new Set(), varTypes: new Map(), cls: currentClass, propTypes };
        if (!named) for (const u of uses) newFrame.vars.set(u, lookup(u));
        for (const p of params) {
          const type = p.type ? p.type.replace(/^\?/, '') : null;
          if (type && /request$/i.test(short(type))) { newFrame.requestVars.add(p.name); continue; }
          if (type && !/^(?:string|int|float|bool|array|mixed|callable|iterable|object|null)$/i.test(type)) newFrame.varTypes.set(p.name, short(type));
          if (p.visibility && type) propTypes.set(p.name, short(type)); // promoted constructor property
          // Controller actions: untyped or string route parameters are raw input
          const routeParam = !summaryMode && env.isControllerFile && currentClass && isPublic && methodName && !methodName.startsWith('__')
            && (!type || SCALAR_TYPES.test(type));
          newFrame.vars.set(p.name, routeParam ? { flow: `route parameter $${p.name}`, raw: true, validated: 0, origins: ['req'], line: k.line } : undefined);
        }
        if (!newFrame.requestVars.size) newFrame.requestVars.add('request');
        pendingBodies.set(body, newFrame);
        continue;
      }
    }

    // fn (…) => expr : sees the parent scope; parameters shadow it
    if (isId(k, 'fn') && isP(toks[i + 1], '(')) {
      const { params, close } = paramList(toks, i + 1);
      if (isP(toks[close], '=>')) {
        const copy = { ...frame(), vars: new Map(frame().vars) };
        for (const p of params) copy.vars.set(p.name, undefined);
        frames.push(copy);
        arrowEnds.push(Math.max(close + 2, exprTaint(toks, close + 1).end));
        i = close;
      }
      continue;
    }

    // Typed properties: private UserService $users;
    if (k.t === 'id' && ['private', 'protected', 'public'].includes(k.v.toLowerCase()) && braceKinds[braceKinds.length - 1] === 'class') {
      let j = i + 1;
      if (isId(toks[j], 'readonly') || isId(toks[j], 'static')) j++;
      if (toks[j]?.t === 'id' && toks[j + 1]?.t === 'var' && !/^\??(?:string|int|float|bool|array|mixed)$/i.test(toks[j].v)) propTypes.set(toks[j + 1].v, short(toks[j].v.replace(/^\?/, '')));
      continue;
    }

    // Assignments: $x = …, $x .= …, $x['k'] = …, [$a, $b] = …, list($a, $b) = …
    if (k.t === 'var' || ((isP(k, '[') || isId(k, 'list')) && !['var', 'id'].includes(toks[i - 1]?.t) && !isP(toks[i - 1], ']') && !isP(toks[i - 1], ')'))) {
      let names;
      let eqAt;
      if (k.t === 'var') {
        let j = i + 1;
        while (isP(toks[j], '[')) j = skipGroup(toks, j); // $x['k'] = …
        if (toks[j]?.t === 'p' && ['=', '.=', '??='].includes(toks[j].v) && !isP(toks[i - 1], '->') && !isP(toks[i - 1], '::')) { names = [k.v]; eqAt = j; }
      } else {
        const open = isId(k, 'list') ? i + 1 : i;
        const end = skipGroup(toks, open);
        if (isP(toks[end], '=')) { names = toks.slice(open, end).filter((t) => t.t === 'var').map((t) => t.v); eqAt = end; }
      }
      if (names) {
        const op = toks[eqAt].v;
        const r = exprTaint(toks, eqAt + 1);
        for (const n of names) {
          const before = lookup(n);
          const keep = (op === '.=' || op === '??=' || toks[i + 1]?.v === '[') && before;
          const info = r.flow ? { ...r, line: k.line } : keep ? before : undefined;
          frame().vars.set(n, info);
        }
        i = eqAt; // walk the right-hand side for nested sinks
        continue;
      }
    }

    // Calls: sinks, and project functions whose parameters reach sinks
    if (isP(toks[i - 1], '->') || isP(toks[i - 1], '?->') || isP(toks[i - 1], '::')) continue; // middle of a chain
    const ref = readRef(toks, i);
    if (!ref) continue;
    const callStep = ref.steps.findIndex((s) => s.op === '()');
    if (callStep === -1) { i = ref.end - 1; continue; }
    // examine every call in the chain: Http::withHeaders(…)->get($url)
    for (let s = 0; s < ref.steps.length; s++) {
      const step = ref.steps[s];
      if (step.op !== '()') continue;
      let call;
      let label;
      if (ref.base.type === 'func' && s === 0) { call = { kind: 'func', name: ref.base.name }; label = ref.base.name; }
      else {
        const nameStep = ref.steps[s - 1];
        if (!nameStep?.name) continue;
        const chainHead = ref.base.type === 'class' ? short(ref.base.name) : ref.base.type === 'func' ? `${ref.base.name.toLowerCase()}()` : null;
        const viaStatic = nameStep.op === '::' && s === 1 && ref.base.type === 'class';
        call = viaStatic
          ? { kind: 'static', cls: short(ref.base.name), name: nameStep.name }
          : { kind: 'method', name: nameStep.name, chainHead, receiver: ref.base.type === 'var' && s === 1 ? ref.base.name : ref.steps[s - 2]?.name };
        label = viaStatic ? `${short(ref.base.name)}::${nameStep.name}` : `->${nameStep.name}`;
      }
      const spec = classifySink(call);
      if (spec) { checkSink(spec, readArgs(toks, step.open), k.line, label); continue; }

      // project function / method with parameter sinks
      let target = null;
      if (call.kind === 'func') target = { kind: 'func', name: call.name };
      else if (ref.base.type === 'var' && ref.base.name === 'this' && s === 1) target = { kind: 'method', cls: frame().cls, name: call.name };
      else if (ref.base.type === 'var' && ref.base.name === 'this' && s === 2) target = { kind: 'method', cls: frame().propTypes.get(ref.steps[0].name), name: call.name };
      else if (ref.base.type === 'var' && s === 1 && frame().varTypes.has(ref.base.name)) target = { kind: 'method', cls: frame().varTypes.get(ref.base.name), name: call.name };
      else if (call.kind === 'static') target = { kind: 'method', cls: ['self', 'static', 'parent'].includes(call.cls.toLowerCase()) ? frame().cls : call.cls, name: call.name };
      const summary = target && target.cls !== null ? env.resolve(target) : null;
      if (summary?.paramSinks.size) {
        const args = readArgs(toks, step.open);
        for (const [idx, list] of summary.paramSinks) {
          const a = args[idx];
          if (!a?.flow) continue;
          for (const ps of list) {
            if (a.validated >= needed(ps.sink)) continue;
            report(ps.sink, a, k.line, `${a.flow} → ${label}() → ${ps.where}`, `${label}() → ${ps.where}`);
          }
        }
      }
    }
    // keep walking inside the arguments (they may hold assignments or sinks)
    i = ref.steps[callStep].open;
  }
  return { findings, paramSinks, returns };
}

// ── Project-wide analysis ───────────────────────────────────────────

/** Functions and methods: { name, cls, params, bodyStart, bodyEnd } (bodyStart = index of `{`). */
function findDefs(toks) {
  const defs = [];
  const classAt = [];
  for (let i = 0; i < toks.length; i++) {
    const k = toks[i];
    if ((isId(k, 'class') || isId(k, 'trait')) && toks[i + 1]?.t === 'id' && !isP(toks[i - 1], '::')) {
      const open = toks.findIndex((t, n) => n > i && isP(t, '{'));
      if (open !== -1) classAt.push({ name: toks[i + 1].v, start: open, end: skipGroup(toks, open) });
      continue;
    }
    if (isId(k, 'function') && toks[i + 1]?.t === 'id' && isP(toks[i + 2], '(')) {
      const { params, close } = paramList(toks, i + 2);
      let body = close;
      while (body < toks.length && !isP(toks[body], '{') && !isP(toks[body], ';')) body++;
      if (!isP(toks[body], '{')) continue;
      const owner = classAt.filter((c) => c.start < i && i < c.end).pop();
      defs.push({ name: toks[i + 1].v, cls: owner?.name ?? null, params, bodyStart: body, bodyEnd: skipGroup(toks, body) });
    }
  }
  return { defs, classes: classAt.map((c) => c.name) };
}

/** Promoted constructor properties and typed properties of each class: class → Map(prop → type). */
function findPropTypes(toks, classes) {
  const out = new Map();
  for (const c of classes) out.set(c, new Map());
  let current = null;
  const ranges = [];
  for (let i = 0; i < toks.length; i++) {
    if ((isId(toks[i], 'class') || isId(toks[i], 'trait')) && toks[i + 1]?.t === 'id' && !isP(toks[i - 1], '::')) {
      const open = toks.findIndex((t, n) => n > i && isP(t, '{'));
      if (open !== -1) ranges.push({ name: toks[i + 1].v, start: open, end: skipGroup(toks, open) });
    }
  }
  for (const r of ranges) {
    current = out.get(r.name);
    for (let i = r.start; i < r.end; i++) {
      const t = toks[i];
      if (isId(t, 'function') && isId(toks[i + 1], '__construct') && isP(toks[i + 2], '(')) {
        for (const p of paramList(toks, i + 2).params) if (p.visibility && p.type) current.set(p.name, short(p.type.replace(/^\?/, '')));
      }
      if (t.t === 'id' && ['private', 'protected', 'public'].includes(t.v.toLowerCase())) {
        let j = i + 1;
        if (isId(toks[j], 'readonly') || isId(toks[j], 'static')) j++;
        if (toks[j]?.t === 'id' && toks[j + 1]?.t === 'var' && !/^\??(?:string|int|float|bool|array|mixed)$/i.test(toks[j].v)) current.set(toks[j + 1].v, short(toks[j].v.replace(/^\?/, '')));
      }
    }
  }
  return out;
}

/** files: [{ rel, text }] → Map rel → [{ sink, line, flow }] */
export function analyzePhpProject(files) {
  const units = [];
  for (const f of files) {
    const toks = lexPhpTokens(f.text);
    const { defs, classes } = findDefs(toks);
    units.push({ rel: f.rel, toks, defs, propTypes: findPropTypes(toks, classes),
      isControllerFile: /(?:^|\/)app\/Http\/Controllers\//.test(f.rel) || /Controller\.php$/.test(f.rel) });
  }
  const functions = new Map(); // lower name → [unit, def] (global functions)
  const methods = new Map(); // `class::method` lower → [unit, def]
  for (const u of units) {
    for (const d of u.defs) {
      const key = d.cls ? `${d.cls.toLowerCase()}::${d.name.toLowerCase()}` : d.name.toLowerCase();
      (d.cls ? methods : functions).set(key, [u, d]);
    }
  }
  let summaries = new Map();
  const keyOf = (u, d) => `${u.rel}#${d.cls ?? ''}::${d.name}`;
  const resolve = (call) => {
    let hit;
    if (call.kind === 'func') hit = functions.get(call.name.replace(/^\\/, '').toLowerCase());
    else if (call.cls) hit = methods.get(`${short(call.cls).toLowerCase()}::${call.name.toLowerCase()}`);
    return hit ? summaries.get(keyOf(hit[0], hit[1])) ?? null : null;
  };

  const summarize = (u, d) => {
    const body = u.toks.slice(d.bodyStart + 1, d.bodyEnd - 1);
    const run = analyzeTokens(body, { rel: u.rel, resolve, params: d.params.map((p) => ({ ...p })), cls: d.cls, propTypes: u.propTypes.get(d.cls) || new Map() });
    const returnsParams = new Set();
    let returnsReq = null;
    let returnRaw = false;
    let returnValidated = Infinity;
    for (const r of run.returns) {
      for (const o of r.origins) {
        if (o === 'req') returnsReq = returnsReq || r.flow;
        else returnsParams.add(Number(o.slice(1)));
      }
      returnRaw = returnRaw || r.raw;
      returnValidated = Math.min(returnValidated, r.validated);
    }
    const validator = isValidatorBody(body);
    return { returnsParams: validator ? new Set() : returnsParams, returnsReq, returnRaw,
      returnValidated: returnValidated === Infinity ? 0 : returnValidated, paramSinks: run.paramSinks };
  };

  for (let round = 0; round < 2; round++) {
    const next = new Map();
    for (const u of units) for (const d of u.defs) {
      try { next.set(keyOf(u, d), summarize(u, d)); } catch { /* unusual syntax: unsummarised */ }
    }
    summaries = next;
  }

  const results = new Map();
  for (const u of units) {
    try {
      results.set(u.rel, analyzeTokens(u.toks, { rel: u.rel, resolve, params: null, isControllerFile: u.isControllerFile }).findings);
    } catch {
      results.set(u.rel, []);
    }
  }
  return results;
}

export function analyzePhp(text, rel = 'input.php') {
  return analyzePhpProject([{ rel, text }]).get(rel) || [];
}
