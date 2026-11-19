// Taint tracking for JavaScript / TypeScript, across functions and files.
//
// Follows request data from a source (req.body, await req.json(), formData.get(), searchParams,
// Server Action arguments) through variables and function calls to a dangerous sink (SQL, shell,
// eval, Mongo filter, file path, server-side fetch, redirect).
//
// How it works
//   1. Every function in the project gets a summary: which parameters it returns (a transformer),
//      whether it returns request data, which parameters reach a sink inside it (possibly through
//      other helpers), and whether it can reject input (a validator: it throws or bails out early).
//   2. Calls are resolved by name in the same file, or through import / require to another file
//      (relative paths and the @/ alias). Summaries are computed in two rounds so helpers that call
//      helpers resolve too.
//   3. Each file is then analysed with those summaries.
//
// Rules of thumb, chosen to keep false positives low:
//   - A validator's return value is clean. An unknown function (a library, something unresolved)
//     is also treated as clean: it may validate, and guessing wrong is noisy.
//   - Taint flows through assignment, destructuring, member access, template literals,
//     concatenation and a few pass-through calls (new URL, path.join, String, JSON.parse).
//   - Validation guards are graded per sink (see VALID).
//   - Scopes are lexical, so a `url` in one function never taints a `url` in another.

import { hasDirective } from './files.js';

// ── Lexer ───────────────────────────────────────────────────────────

const PUNCT = ['>>>=', '...', '===', '!==', '**=', '<<=', '>>=', '>>>', '&&=', '||=', '??=',
  '=>', '==', '!=', '<=', '>=', '&&', '||', '??', '?.', '++', '--', '+=', '-=', '*=', '/=', '%=',
  '&=', '|=', '^=', '**', '<<', '>>'];
const REGEX_AFTER_KEYWORD = new Set(['return', 'typeof', 'case', 'do', 'else', 'in', 'of', 'new', 'delete', 'void', 'throw', 'yield', 'await', 'instanceof']);

/**
 * Tokens: { t: 'id' | 'num' | 'str' | 'p' | 're' | 'tpl', v, line }. A template literal becomes
 * tpl'`' … (tpl'${' expression tokens tpl'}')* … tpl'`'. Strings never span lines, so a stray
 * apostrophe in JSX text only damages its own line.
 */
export function lex(src) {
  const tokens = [];
  const frames = [{ tpl: false, braces: 0 }];
  let line = 1;
  let i = 0;
  const push = (t, v) => tokens.push({ t, v, line });
  const regexAllowed = () => {
    const p = tokens[tokens.length - 1];
    if (!p) return true;
    if (p.t === 'p') return ![')', ']', '}'].includes(p.v);
    if (p.t === 'tpl') return p.v === '${';
    if (p.t === 'id') return REGEX_AFTER_KEYWORD.has(p.v);
    return false;
  };
  // `opener`: the token of an opening backtick, which records the literal text before the first ${
  // (needed to tell `/dashboard/${id}` – a fixed path – from `${url}`).
  const readTemplate = (opener = null) => {
    const start = i;
    while (i < src.length) {
      const c = src[i];
      if (c === '\\') { i += 2; continue; }
      if (c === '\n') line++;
      if (c === '`') { if (opener) opener.head = src.slice(start, i); push('tpl', '`'); i++; return; }
      if (c === '$' && src[i + 1] === '{') {
        if (opener) opener.head = src.slice(start, i);
        push('tpl', '${'); i += 2; frames.push({ tpl: true, braces: 0 }); return;
      }
      i++;
    }
  };

  while (i < src.length) {
    const c = src[i];
    const n = src[i + 1];
    if (c === '\n') { line++; i++; continue; }
    if (c === ' ' || c === '\t' || c === '\r') { i++; continue; }
    if (c === '/' && n === '/') { while (i < src.length && src[i] !== '\n') i++; continue; }
    if (c === '/' && n === '*') {
      const end = src.indexOf('*/', i + 2);
      const stop = end === -1 ? src.length : end + 2;
      for (; i < stop; i++) if (src[i] === '\n') line++;
      continue;
    }
    if (c === '\'' || c === '"') {
      let j = i + 1;
      while (j < src.length && src[j] !== c && src[j] !== '\n') j += src[j] === '\\' ? 2 : 1;
      push('str', src.slice(i + 1, j));
      i = src[j] === c ? j + 1 : j;
      continue;
    }
    if (c === '`') { push('tpl', '`'); i++; readTemplate(tokens[tokens.length - 1]); continue; }
    if (c === '/' && regexAllowed()) {
      let j = i + 1;
      let inClass = false;
      while (j < src.length && src[j] !== '\n') {
        if (src[j] === '\\') { j += 2; continue; }
        if (src[j] === '[') inClass = true;
        else if (src[j] === ']') inClass = false;
        else if (src[j] === '/' && !inClass) break;
        j++;
      }
      j++;
      while (/[a-z]/i.test(src[j] || '')) j++;
      push('re', src.slice(i, j));
      i = j;
      continue;
    }
    if (/[A-Za-z_$]/.test(c)) {
      let j = i + 1;
      while (j < src.length && /[\w$]/.test(src[j])) j++;
      push('id', src.slice(i, j));
      i = j;
      continue;
    }
    if (/[0-9]/.test(c) || (c === '.' && /[0-9]/.test(n || ''))) {
      let j = i + 1;
      while (j < src.length && /[\w.]/.test(src[j])) j++;
      push('num', src.slice(i, j));
      i = j;
      continue;
    }
    const frame = frames[frames.length - 1];
    if (c === '{') frame.braces++;
    if (c === '}') {
      if (frame.tpl && frame.braces === 0) { frames.pop(); push('tpl', '}'); i++; readTemplate(); continue; }
      frame.braces--;
    }
    const multi = PUNCT.find((p) => src.startsWith(p, i));
    push('p', multi || c);
    i += multi ? multi.length : 1;
  }
  return tokens;
}

// ── Token-stream helpers ────────────────────────────────────────────

const OPENERS = { '(': ')', '[': ']', '{': '}' };
const isP = (tok, v) => tok?.t === 'p' && tok.v === v;
const TYPE_ARG_TOKENS = new Set(['.', ',', '[', ']', '|', '&', '{', '}', ':', '?', '<', '>', ';']);

/**
 * Index of the `(` that makes the chain ending at j a call, or -1. Understands TypeScript type
 * arguments: db.query<Row>(…) is a call, not `db.query < Row > (…)`.
 */
function callOpen(toks, j) {
  if (isP(toks[j], '(')) return j;
  if (!isP(toks[j], '<')) return -1;
  let depth = 0;
  for (let k = j; k < toks.length && k < j + 40; k++) {
    const t = toks[k];
    if (isP(t, '>>') || isP(t, '>>>')) { // Array<Map<K, V>> : the lexer joins the closing brackets
      depth -= t.v.length;
      if (depth <= 0) return depth === 0 && isP(toks[k + 1], '(') ? k + 1 : -1;
      continue;
    }
    if (t.t === 'p' && !TYPE_ARG_TOKENS.has(t.v)) return -1; // an operator: a comparison, not type arguments
    if (isP(t, '<')) depth++;
    else if (isP(t, '>') && --depth === 0) return isP(toks[k + 1], '(') ? k + 1 : -1;
    else if (isP(t, ';')) return -1;
  }
  return -1;
}
const isCall = (toks, j) => callOpen(toks, j) !== -1;

/** Index just past the token that closes the opener at `i`. */
function skipGroup(toks, i) {
  let depth = 0;
  for (let j = i; j < toks.length; j++) {
    const k = toks[j];
    if (k.t === 'p' && OPENERS[k.v]) depth++;
    else if (k.t === 'p' && (k.v === ')' || k.v === ']' || k.v === '}')) depth--;
    else if (k.t === 'tpl') {
      if (k.v === '${') depth++;
      else if (k.v === '}') depth--;
      else if (k.v === '`') {
        let d = 0;
        for (j = j + 1; j < toks.length; j++) {
          const t = toks[j];
          if (t.t === 'tpl' && t.v === '${') d++;
          else if (t.t === 'tpl' && t.v === '}') d--;
          else if (t.t === 'tpl' && t.v === '`' && d === 0) break;
        }
        if (depth === 0) return j + 1;
        continue;
      }
    }
    if (depth === 0) return j + 1;
  }
  return toks.length;
}

/** `a.b?.c` starting at i → { names: ['a','b','c'], end } (end = first token after the chain). */
function readChain(toks, i) {
  const names = [toks[i].v];
  let j = i + 1;
  while (j + 1 < toks.length && toks[j].t === 'p' && (toks[j].v === '.' || toks[j].v === '?.') && toks[j + 1].t === 'id') {
    names.push(toks[j + 1].v);
    j += 2;
  }
  return { names, end: j };
}

/**
 * Parameters between `(` at `open` and its `)`: [[name, index]], where destructured names share
 * the index of their parameter. Type annotations and default values are skipped.
 */
function paramList(toks, open) {
  const close = skipGroup(toks, open);
  const out = [];
  let index = 0;
  let depth = 0;
  let inType = false;
  let inDefault = false;
  for (let p = open + 1; p < close - 1; p++) {
    const t = toks[p];
    if (t.t === 'p' && (OPENERS[t.v] || t.v === '<')) { depth++; continue; }
    if (t.t === 'p' && [')', ']', '}', '>'].includes(t.v)) { depth--; continue; }
    if (depth === 0 && isP(t, ',')) { index++; inType = false; inDefault = false; continue; }
    if (depth === 0 && isP(t, ':')) { inType = true; continue; }
    if (depth === 0 && isP(t, '=')) { inDefault = true; continue; }
    if (inType || inDefault || t.t !== 'id') continue;
    const prev = toks[p - 1];
    const next = toks[p + 1];
    if (depth > 0 && isP(next, ':')) continue; // { key: binding }
    if (prev.t === 'p' && ['(', ',', '{', '[', '...', ':'].includes(prev.v)) out.push([t.v, index]);
  }
  return { params: out, close };
}

/** Index of the body `{` after a parameter list (skips a return type like Promise<{ ok: boolean }>), or -1. */
function bodyAfter(toks, close) {
  let angle = 0;
  for (let b = close; b < toks.length && b < close + 60; b++) {
    const t = toks[b];
    if (isP(t, '<')) angle++;
    else if (isP(t, '>')) angle--;
    else if (isP(t, '=>')) return isP(toks[b + 1], '{') ? b + 1 : -1;
    else if (isP(t, '{') && angle <= 0) return b;
    else if (isP(t, ';')) break;
  }
  return -1;
}

// ── Sources, pass-throughs, sinks ──────────────────────────────────

const REQUEST_OBJECTS = new Set(['req', 'request']);
const REQUEST_FIELDS = new Set(['body', 'query', 'params', 'headers', 'cookies', 'json', 'formData', 'text']);
const PASS_THROUGH = new Set(['String', 'URL', 'decodeURIComponent', 'decodeURI', 'JSON.parse', 'path.join', 'path.resolve',
  'path.normalize', 'join', 'resolve', 'Object.assign', 'Buffer.from', 'unescape']);
const NOT_A_VALUE = new Set(['function', 'class']);

const FS_FUNCS = new Set(['readFile', 'readFileSync', 'createReadStream', 'writeFile', 'writeFileSync', 'appendFile', 'appendFileSync',
  'unlink', 'unlinkSync', 'rm', 'rmSync', 'readdir', 'readdirSync', 'open', 'openSync', 'stat', 'statSync', 'copyFile', 'rename']);
const MONGO_FUNCS = new Set(['find', 'findOne', 'findOneAndUpdate', 'findOneAndDelete', 'findOneAndReplace', 'updateOne', 'updateMany',
  'deleteOne', 'deleteMany', 'countDocuments', 'exists', 'aggregate']);
const SQL_FUNCS = new Set(['query', 'execute', 'raw', 'unsafe', '$queryRawUnsafe', '$executeRawUnsafe']);

export const SINKS = {
  sql: { id: 'js-sql-injection', severity: 'high', title: 'Request data reaches a SQL string',
    fix: 'Pass values as parameters: db.query("… WHERE id = ?", [id]) or a query builder; never build SQL from request data.' },
  cmd: { id: 'js-command-injection', severity: 'high', title: 'Request data reaches a shell command',
    fix: 'Use execFile/spawn with an argument array and an allow-list of values; never pass request data through a shell.' },
  eval: { id: 'js-eval-request', severity: 'high', title: 'Request data reaches eval / new Function',
    fix: 'Parse the value instead (Number(), JSON.parse) and never execute request data as code.' },
  nosql: { id: 'js-nosql-injection', severity: 'high', title: 'Request data used as a MongoDB filter',
    fix: 'Build the filter from validated, cast fields: { email: String(body.email) }, or enable mongoose sanitizeFilter.' },
  nosqlField: { id: 'js-nosql-injection', severity: 'medium', title: 'Request field used in a MongoDB filter without casting',
    fix: 'Cast the value (String(body.email)) or validate it, so a client cannot send operators like {"$ne": null}.' },
  path: { id: 'js-path-traversal', severity: 'high', title: 'Request data reaches a file path',
    fix: 'Resolve the path and check it stays inside your base folder, or use res.sendFile(name, { root: BASE }).' },
  ssrf: { id: 'js-ssrf', severity: 'medium', title: 'Server-side request to a URL from the request',
    fix: 'Allow only http(s) URLs on an allow-list of hosts and block private/loopback IPs (169.254.169.254, 10.x, 127.x) after DNS resolution.' },
  redirect: { id: 'js-open-redirect', severity: 'medium', title: 'Redirect target comes from the request',
    fix: 'Only redirect to relative paths starting with a single "/", or to an allow-list of URLs.' },
};

function classifySink(names, ctx) {
  const last = names[names.length - 1];
  const first = names[0];
  const full = names.join('.');
  if (full === 'eval' || (ctx.prevIsNew && full === 'Function') || /^vm\.runIn\w+Context$|^vm\.runInThisContext$/.test(full)) return 'eval';
  if ((last === 'exec' || last === 'execSync') && (names.length === 1 ? ctx.importsChildProcess : /^(?:child_?process|cp|childProcess)$/i.test(first))) return 'cmd';
  if (SQL_FUNCS.has(last) && names.length > 1) return 'sql';
  if (MONGO_FUNCS.has(last) && names.length > 1 && ctx.usesMongo) return 'nosql';
  if (FS_FUNCS.has(last) && (names.length === 1 ? ctx.importsFs : /^(?:fs|fsp|fsPromises|promises)$/.test(names[names.length - 2]))) return 'path';
  if (first === 'res' && (last === 'sendFile' || last === 'download')) return 'path';
  if (full === 'fetch' || full === 'got' || full === 'undiciFetch' || first === 'axios' || /^(?:https?|undici)\.(?:get|request|fetch)$/.test(full)) return 'ssrf';
  if ((first === 'res' || first === 'reply' || first === 'NextResponse' || first === 'Response') && last === 'redirect') return 'redirect';
  if (full === 'redirect' && ctx.importsNextRedirect) return 'redirect';
  return null;
}

function fileContext(text) {
  return {
    usesMongo: /\bmongoose\b|\bmongodb\b|\.collection\s*\(/.test(text),
    importsChildProcess: /['"](?:node:)?child_process['"]/.test(text),
    importsFs: /['"](?:node:)?fs(?:\/promises)?['"]/.test(text),
    importsNextRedirect: /['"]next\/navigation['"]/.test(text),
    useServer: hasDirective(text, 'use server'),
  };
}

// ── Validation guards ───────────────────────────────────────────────

/**
 * How well a value has been checked. Which level is enough depends on the sink:
 *   RELATIVE  x.startsWith('/')                      → fine for fetch(ORIGIN + x), not for redirects (//evil.com)
 *   STRICT    x.startsWith('/') and rejects '//'     → also fine for redirects
 *   EXACT     allow-list, equality with a literal, anchored regex → fine everywhere
 * Weak checks (x.startsWith('http'), !x, x.length) are not validation.
 */
export const VALID = { NONE: 0, RELATIVE: 1, STRICT: 2, EXACT: 3 };
const NEEDED_VALIDATION = { ssrf: VALID.RELATIVE, redirect: VALID.STRICT };
const needed = (sink) => NEEDED_VALIDATION[sink] ?? VALID.EXACT;

/** Map of variable → validation level for the checks found in an `if (…)` condition. */
function guardChecks(cond) {
  const found = new Map();
  const raise = (name, level) => found.set(name, Math.max(found.get(name) || 0, level));
  const startsWith = new Map();
  for (let j = 0; j < cond.length; j++) {
    const k = cond[j];
    if (k.t === 'id' && cond[j + 1]?.v === '.' && cond[j + 2]?.v === 'startsWith' && cond[j + 3]?.v === '(' && cond[j + 4]?.t === 'str') {
      startsWith.set(k.v, new Set([...(startsWith.get(k.v) || []), cond[j + 4].v]));
    }
    if (isP(k, '.') && ['includes', 'has'].includes(cond[j + 1]?.v) && cond[j + 2]?.v === '(' && cond[j + 3]?.t === 'id' && cond[j + 4]?.v === ')') {
      raise(cond[j + 3].v, VALID.EXACT);
    }
    if (k.t === 'p' && ['===', '!==', '==', '!='].includes(k.v)) {
      const [l, r] = [cond[j - 1], cond[j + 1]];
      if (l?.t === 'id' && r?.t === 'str' && r.v) raise(l.v, VALID.EXACT);
      if (r?.t === 'id' && l?.t === 'str' && l.v) raise(r.v, VALID.EXACT);
    }
    if (k.t === 're' && /^\/\^.*\$\/[a-z]*$/.test(k.v) && cond[j + 1]?.v === '.' && cond[j + 2]?.v === 'test' && cond[j + 3]?.v === '(' && cond[j + 4]?.t === 'id' && cond[j + 5]?.v === ')') {
      raise(cond[j + 4].v, VALID.EXACT);
    }
  }
  for (const [name, prefixes] of startsWith) {
    if (prefixes.has('/') && prefixes.has('//')) raise(name, VALID.STRICT);
    else if (prefixes.has('/')) raise(name, VALID.RELATIVE);
  }
  return found;
}

/** End of a brace-less statement (if (…) return x;) starting at j. */
function statementEndAt(toks, j) {
  let depth = 0;
  for (let k = j; k < toks.length; k++) {
    const t = toks[k];
    if (t.t === 'p' && OPENERS[t.v]) depth++;
    else if (t.t === 'p' && (t.v === ')' || t.v === ']' || t.v === '}')) { if (depth === 0) return k; depth--; }
    else if (depth === 0 && isP(t, ';')) return k + 1;
    if (depth === 0 && k > j && t.line > toks[k - 1].line) return k;
  }
  return toks.length;
}

function startsStatement(toks, j) {
  const k = toks[j];
  if (k.t === 'id') return true;
  if (k.t === 'str' || k.t === 'num') return !(toks[j + 1]?.t === 'p' && ['.', '?.'].includes(toks[j + 1].v));
  return false;
}
function continues(prev) {
  return (prev.t === 'p' && !['}', ')', ']'].includes(prev.v)) || (prev.t === 'tpl' && prev.v === '${');
}
function skipFunction(toks, j) {
  for (let k = j; k < toks.length; k++) if (isP(toks[k], '{')) return skipGroup(toks, k);
  return toks.length;
}
function skipArrowBody(toks, j) {
  return isP(toks[j + 1], '{') ? skipGroup(toks, j + 1) : j + 1;
}

/** A function that can reject its input: it throws, or bails out with return null/undefined/false. */
function isValidatorBody(body) {
  for (let j = 0; j < body.length; j++) {
    if (body[j].t !== 'id') continue;
    if (body[j].v === 'throw') return true;
    if (body[j].v === 'if' && isP(body[j + 1], '(')) {
      const condEnd = skipGroup(body, j + 1);
      const blockEnd = isP(body[condEnd], '{') ? skipGroup(body, condEnd) : statementEndAt(body, condEnd);
      for (let r = condEnd; r < blockEnd; r++) {
        if (body[r].t === 'id' && body[r].v === 'return') {
          const v = body[r + 1];
          if (!v || isP(v, ';') || isP(v, '}') || (v.t === 'id' && ['null', 'undefined', 'false'].includes(v.v)) || v.line > body[r].line) return true;
        }
      }
    }
  }
  return false;
}

// ── Single-run analysis ─────────────────────────────────────────────

/**
 * Taint values: { flow, raw, validated, origins }. `origins` holds 'req' for request data and
 * 'p0', 'p1', … for the parameters of the function being summarised.
 *
 * env: { ctx, rel, nextAppFile, resolve(names) → summary | null, params: [[name, index]] | null,
 *        exprBody: boolean }
 * Returns { findings, paramSinks: Map<index, [{ sink, where }]>, returns: [taint] }.
 */
function analyzeTokens(toks, env) {
  const { ctx, nextAppFile, resolve } = env;
  const summaryMode = Boolean(env.params);
  const scopes = [new Map()];
  if (summaryMode) {
    for (const [name, index] of env.params) {
      scopes[0].set(name, { flow: `parameter "${name}"`, raw: true, validated: 0, origins: [`p${index}`], line: toks[0]?.line ?? 0 });
    }
  }
  const lookup = (name) => {
    for (let s = scopes.length - 1; s >= 0; s--) if (scopes[s].has(name)) return scopes[s].get(name);
    return undefined;
  };
  const declare = (name, info) => scopes[scopes.length - 1].set(name, info);
  const assign = (name, info) => {
    for (let s = scopes.length - 1; s >= 0; s--) if (scopes[s].has(name)) { scopes[s].set(name, info); return; }
    declare(name, info);
  };

  /** Request data, or a tainted variable. `raw` = not yet coerced to a string. */
  const sourceOf = (names, end) => {
    const [a, b] = names;
    if (REQUEST_OBJECTS.has(a) && REQUEST_FIELDS.has(b)) {
      if (['json', 'formData', 'text'].includes(b) && !isCall(toks, end)) return null;
      return { flow: `${a}.${b}${['json', 'formData', 'text'].includes(b) ? '()' : ''}`, raw: true, validated: 0, origins: ['req'] };
    }
    if (a === 'ctx' && (b === 'query' || b === 'params' || (b === 'request' && names[2] === 'body'))) {
      return { flow: names.slice(0, b === 'request' ? 3 : 2).join('.'), raw: true, validated: 0, origins: ['req'] };
    }
    if (names.includes('searchParams')) return { flow: 'searchParams', raw: true, validated: 0, origins: ['req'] };
    if (nextAppFile && a === 'params') return { flow: 'params', raw: true, validated: 0, origins: ['req'] };
    const t = lookup(a);
    if (t) return { flow: t.line && !t.flow.startsWith('parameter') ? `${t.flow} → ${a} (line ${t.line})` : t.flow, raw: t.raw, validated: t.validated || 0, origins: t.origins };
    return null;
  };

  /** Taint of each argument of the call whose `(` is at `open`. */
  const readArgs = (open) => {
    const close = skipGroup(toks, open);
    const args = [];
    let p = open + 1;
    while (p < close - 1) {
      const r = exprTaint(p);
      args.push(r);
      if (r.end <= p) break;
      p = isP(toks[r.end], ',') ? r.end + 1 : close;
    }
    return args;
  };

  /** Return value of a call to a summarised function, given the taint of its arguments. */
  const callResult = (summary, callee, open) => {
    const args = readArgs(open);
    let res = null;
    const add = (t) => {
      if (!t?.flow) return;
      res = res
        ? { flow: res.flow, raw: res.raw || t.raw, validated: Math.min(res.validated, t.validated), origins: [...new Set([...res.origins, ...t.origins])] }
        : t;
    };
    for (const idx of summary.returnsParams) {
      const a = args[idx];
      if (a?.flow) add({ flow: `${a.flow} → ${callee}()`, raw: a.raw && summary.returnRaw, validated: Math.max(a.validated, summary.returnValidated), origins: a.origins });
    }
    if (summary.returnsReq) add({ flow: `${summary.returnsReq} → ${callee}()`, raw: summary.returnRaw, validated: 0, origins: ['req'] });
    return { result: res, args };
  };

  /**
   * Taint of the expression starting at `from`, up to its end (`;`, a top-level `,`, a closing
   * bracket, or a line break that ends the statement).
   */
  const exprTaint = (from, { stopAtComma = true } = {}) => {
    const groups = [];
    let flow = null;
    let raw = false;
    let validated = Infinity;
    const origins = new Set();
    const take = (src) => {
      flow = flow || src.flow;
      if (src.raw && !groups.some((g) => g === 'S(' || g === '`')) raw = true;
      validated = Math.min(validated, src.validated || 0);
      for (const o of src.origins) origins.add(o);
    };
    let j = from;
    for (; j < toks.length; j++) {
      const k = toks[j];
      if (groups.length === 0) {
        if (k.t === 'p' && (k.v === ';' || k.v === ')' || k.v === ']' || k.v === '}')) break;
        if (k.t === 'tpl' && k.v === '}') break;
        if (stopAtComma && isP(k, ',')) break;
        if (j > from && k.line > toks[j - 1].line && startsStatement(toks, j) && !continues(toks[j - 1])) break;
      }
      if (k.t === 'id' && NOT_A_VALUE.has(k.v)) { j = skipFunction(toks, j) - 1; continue; }
      if (isP(k, '=>')) { j = skipArrowBody(toks, j) - 1; continue; }
      if (k.t === 'tpl' && k.v === '`') { if (groups[groups.length - 1] === '`') groups.pop(); else groups.push('`'); continue; }
      if (k.t === 'tpl' && k.v === '${') { groups.push('${'); continue; }
      if (k.t === 'tpl' && k.v === '}') { groups.pop(); continue; }
      if (k.t === 'p' && OPENERS[k.v]) { groups.push(k.v); continue; }
      if (k.t === 'p' && (k.v === ')' || k.v === ']' || k.v === '}')) { groups.pop(); continue; }
      if (k.t !== 'id') continue;
      if (groups[groups.length - 1] === '{' && isP(toks[j + 1], ':')) { j++; continue; } // object key
      const { names, end } = readChain(toks, j);
      const src = sourceOf(names, end);
      const callee = names.join('.');
      const open = callOpen(toks, end);
      if (src) {
        take(src);
        j = (open !== -1 ? skipGroup(toks, open) : end) - 1;
        continue;
      }
      if (open !== -1) {
        if (callee === 'String') { groups.push('S('); j = open; continue; }
        if (PASS_THROUGH.has(callee) || (names[0] === 'path' && PASS_THROUGH.has(names[names.length - 1]))) { j = open - 1; continue; }
        const summary = resolve(names);
        if (summary) {
          const { result } = callResult(summary, callee, open);
          if (result) take(result);
        }
        j = skipGroup(toks, open) - 1; // unknown or summarised call: arguments already accounted for
        continue;
      }
      j = end - 1;
    }
    return { flow, raw: Boolean(flow) && raw, validated: flow ? validated : 0, origins: [...origins], end: j };
  };

  const patternNames = (i) => {
    if (toks[i].t === 'id') return { names: [toks[i].v], end: i + 1 };
    const end = skipGroup(toks, i);
    const names = [];
    for (let j = i + 1; j < end - 1; j++) {
      const k = toks[j];
      if (k.t !== 'id') continue;
      if (isP(toks[j + 1], ':')) continue;
      if (isP(toks[j + 1], '=')) { names.push(k.v); j = exprTaint(j + 2).end - 1; continue; }
      names.push(k.v);
    }
    return { names, end };
  };

  const findings = [];
  const seen = new Set();
  const paramSinks = new Map();
  const returns = [];

  /** A sink reached by taint `t`: a finding for request data, a parameter sink while summarising. */
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

  const bodyParams = new Map();
  const fnBodies = new Set();
  const braceIsFn = [];
  let fnDepth = 0;
  const arrowParamNames = (i) => {
    const prev = toks[i - 1];
    if (prev?.t === 'id') return [prev.v];
    if (!isP(prev, ')')) return [];
    let d = 0;
    for (let o = i - 1; o >= 0; o--) {
      if (isP(toks[o], ')')) d++;
      else if (isP(toks[o], '(') && --d === 0) return paramList(toks, o).params.map(([n]) => n);
    }
    return [];
  };
  const exprScopeEnds = [];

  if (summaryMode && env.exprBody) {
    const r = exprTaint(0);
    if (r.flow) returns.push(r);
  }

  for (let i = 0; i < toks.length; i++) {
    const k = toks[i];
    while (exprScopeEnds.length && i >= exprScopeEnds[exprScopeEnds.length - 1]) { exprScopeEnds.pop(); scopes.pop(); }

    if (isP(k, '=>') && !isP(toks[i + 1], '{')) {
      scopes.push(new Map(arrowParamNames(i).map((n) => [n, undefined])));
      exprScopeEnds.push(Math.max(i + 2, exprTaint(i + 1).end));
      continue;
    }
    if (isP(k, '{')) {
      scopes.push(new Map());
      for (const [n, info] of bodyParams.get(i) || []) declare(n, info);
      const isFn = fnBodies.has(i);
      braceIsFn.push(isFn);
      if (isFn) fnDepth++;
      continue;
    }
    if (isP(k, '}')) {
      if (scopes.length > 1) scopes.pop();
      if (braceIsFn.pop()) fnDepth--;
      continue;
    }
    if (isP(k, '=>') && isP(toks[i + 1], '{')) {
      if (!bodyParams.has(i + 1)) bodyParams.set(i + 1, arrowParamNames(i).map((n) => [n, undefined]));
      fnBodies.add(i + 1);
      continue;
    }
    if (k.t !== 'id') continue;

    if (k.v === 'return' && summaryMode && fnDepth === 0) {
      const r = exprTaint(i + 1);
      if (r.flow) returns.push(r);
      continue;
    }

    if (k.v === 'if' && isCall(toks, i + 1)) {
      const condEnd = skipGroup(toks, i + 1);
      const checks = guardChecks(toks.slice(i + 2, condEnd - 1));
      if (checks.size) {
        const blockStart = condEnd;
        const blockEnd = isP(toks[blockStart], '{') ? skipGroup(toks, blockStart) : statementEndAt(toks, blockStart);
        const exits = toks.slice(blockStart, blockEnd).some((t) => t.t === 'id' && ['return', 'throw', 'redirect', 'notFound'].includes(t.v));
        for (const [name, level] of checks) {
          const info = lookup(name);
          if (!info) continue;
          const better = { ...info, validated: Math.max(info.validated || 0, level) };
          if (exits) assign(name, better);
          else if (isP(toks[blockStart], '{')) bodyParams.set(blockStart, [...(bodyParams.get(blockStart) || []), [name, better]]);
        }
      }
      continue;
    }

    if (k.v === 'function') {
      const open = callOpen(toks, toks[i + 1]?.t === 'id' ? i + 2 : i + 1); // function f<T>(…) too
      if (open !== -1) {
        const { params, close } = paramList(toks, open);
        const body = bodyAfter(toks, close);
        const exported = toks.slice(Math.max(0, i - 3), i).some((t) => t.v === 'export');
        const taint = ctx.useServer && exported
          ? (n) => ({ flow: `Server Action argument "${n}"`, raw: true, validated: 0, origins: ['req'], line: k.line })
          : () => undefined;
        if (body !== -1) {
          if (!bodyParams.has(body)) bodyParams.set(body, params.map(([n]) => [n, taint(n)]));
          fnBodies.add(body);
        }
      }
      continue;
    }

    if ((k.v === 'const' || k.v === 'let' || k.v === 'var') && toks[i + 1]) {
      let j = i + 1;
      let resumeAt = i;
      let firstEq = false;
      for (;;) {
        if (!toks[j] || !(toks[j].t === 'id' || isP(toks[j], '{') || isP(toks[j], '['))) break;
        const { names, end } = patternNames(j);
        if (!firstEq) resumeAt = end - 1;
        let eq = end;
        if (isP(toks[eq], ':')) {
          let d = 0;
          for (eq += 1; eq < toks.length; eq++) {
            const t = toks[eq];
            if (t.t === 'p' && (OPENERS[t.v] || t.v === '<')) d++;
            else if (t.t === 'p' && [')', ']', '}', '>'].includes(t.v)) d--;
            else if (d <= 0 && t.t === 'p' && (t.v === '=' || t.v === ';' || t.v === ',')) break;
          }
        }
        if (!isP(toks[eq], '=')) { for (const n of names) declare(n, undefined); break; }
        const r = exprTaint(eq + 1);
        for (const n of names) declare(n, r.flow ? { ...r, line: toks[eq].line } : undefined);
        if (resumeAt < eq && !firstEq) { resumeAt = eq; firstEq = true; }
        if (isP(toks[r.end], ',') && toks[r.end + 1]?.t === 'id' && isP(toks[r.end + 2], '=')) { j = r.end + 1; continue; }
        break;
      }
      i = resumeAt;
      continue;
    }

    const prev = toks[i - 1];
    if (isP(toks[i + 1], '=') && !(isP(prev, '.') || isP(prev, '?.'))) {
      const r = exprTaint(i + 2);
      assign(k.v, r.flow ? { ...r, line: k.line } : undefined);
      continue;
    }

    if (isP(prev, '.') || isP(prev, '?.')) continue;
    const { names, end: chainEnd } = readChain(toks, i);
    const end = callOpen(toks, chainEnd);
    if (end === -1) { i = chainEnd - 1; continue; }
    const calleeName = names.join('.');
    const sink = classifySink(names, { ...ctx, prevIsNew: prev?.t === 'id' && prev.v === 'new' });

    if (sink) {
      const close = skipGroup(toks, end);
      const argStart = end + 1;
      // A literal head that pins the destination: `/dashboard/${id}` stays on this site,
      // `https://api.example.com/${id}` stays on that host. Neither is a redirect or SSRF risk.
      const head = toks[argStart]?.t === 'str' ? toks[argStart].v : toks[argStart]?.t === 'tpl' ? toks[argStart].head : null;
      const pinned = head != null && ((sink === 'redirect' && /^\/[^/\\]/.test(head)) || (sink === 'ssrf' && /^https?:\/\/[^/?#\s]+[/?#]/i.test(head)));
      if (pinned) { i = end - 1; continue; }
      const where = `${calleeName}() (${env.rel}:${k.line})`;
      if (sink === 'redirect' || sink === 'eval') {
        const r = exprTaint(argStart, { stopAtComma: false });
        if (r.flow && r.validated < needed(sink)) report(sink, r, k.line, `${r.flow} → ${calleeName}()`, where);
      } else if (sink === 'path' && names[0] === 'res' && toks.slice(argStart, close).some((t) => t.t === 'id' && t.v === 'root')) {
        // sendFile(name, { root }) refuses ../ escapes
      } else if (sink === 'nosql') {
        const isLiteral = isP(toks[argStart], '{');
        const body = isLiteral ? toks.slice(argStart, skipGroup(toks, argStart)) : [];
        const isSequelizeStyle = body.some((t, n) => t.t === 'id' && t.v === 'where' && isP(body[n + 1], ':'));
        const r = isSequelizeStyle ? null : exprTaint(argStart);
        if (r?.raw) report(isLiteral ? 'nosqlField' : 'nosql', r, k.line, `${r.flow} → ${calleeName}()`, where);
      } else {
        const r = exprTaint(argStart);
        if (r.flow && r.validated < needed(sink)) report(sink, r, k.line, `${r.flow} → ${calleeName}()`, where);
      }
      i = end - 1;
      continue;
    }

    // A call to a project function whose parameters reach a sink inside it.
    const summary = resolve(names);
    if (summary && summary.paramSinks.size) {
      const args = readArgs(end);
      for (const [idx, list] of summary.paramSinks) {
        const a = args[idx];
        if (!a?.flow) continue;
        for (const ps of list) {
          if ((ps.sink === 'nosql' || ps.sink === 'nosqlField') && !a.raw) continue;
          if (a.validated >= needed(ps.sink)) continue;
          report(ps.sink, a, k.line, `${a.flow} → ${calleeName}() → ${ps.where}`, `${calleeName}() → ${ps.where}`);
        }
      }
    }
    i = end - 1;
  }
  return { findings, paramSinks, returns };
}

// ── Project-wide analysis ───────────────────────────────────────────

/** Named functions in a file: declarations, `const f = (…) => …`, `const f = function …`, `exports.f = …`. */
function findFunctions(toks) {
  const defs = [];
  const add = (name, at, exported, i) => {
    const open = callOpen(toks, at);
    if (open === -1) return;
    const { params, close } = paramList(toks, open);
    let bodyStart = bodyAfter(toks, close);
    let exprBody = false;
    let bodyEnd;
    if (bodyStart === -1) {
      // expression-bodied arrow: (…) => expr
      let a = close;
      while (a < toks.length && a < close + 60 && !isP(toks[a], '=>') && !isP(toks[a], ';') && !isP(toks[a], '{')) a++;
      if (!isP(toks[a], '=>')) return;
      bodyStart = a + 1;
      exprBody = true;
      bodyEnd = statementEndAt(toks, bodyStart);
    } else {
      bodyEnd = skipGroup(toks, bodyStart);
    }
    defs.push({ name, params, bodyStart, bodyEnd, exprBody, exported, line: toks[i].line });
  };
  for (let i = 0; i < toks.length; i++) {
    const k = toks[i];
    if (k.t !== 'id') continue;
    const exported = toks[i - 1]?.v === 'export' || (toks[i - 1]?.v === 'async' && toks[i - 2]?.v === 'export')
      || (toks[i - 1]?.v === 'default' && toks[i - 2]?.v === 'export');
    if (k.v === 'function' && toks[i + 1]?.t === 'id') {
      const exp = exported || (toks[i - 1]?.v === 'async' && toks[i - 2]?.v === 'export') || (toks[i - 1]?.v === 'async' && toks[i - 2]?.v === 'default');
      add(toks[i + 1].v, i + 2, exp, i);
      continue;
    }
    // const name = [async] function (…) / [async] (…) => / [async] x =>
    if ((k.v === 'const' || k.v === 'let' || k.v === 'var') && toks[i + 1]?.t === 'id' && isP(toks[i + 2], '=')) {
      let j = i + 3;
      if (toks[j]?.v === 'async') j++;
      if (toks[j]?.v === 'function') { add(toks[i + 1].v, toks[j + 1]?.t === 'id' ? j + 2 : j + 1, exported, i); continue; }
      if (isP(toks[j], '(') || isP(toks[j], '<')) { add(toks[i + 1].v, j, exported, i); continue; } // (…) => or <T>(…) =>
      if (toks[j]?.t === 'id' && isP(toks[j + 1], '=>')) {
        // single bare parameter: synthesise a parameter list view
        const bodyStart = j + 2;
        const exprBody = !isP(toks[bodyStart], '{');
        defs.push({ name: toks[i + 1].v, params: [[toks[j].v, 0]], bodyStart, bodyEnd: exprBody ? statementEndAt(toks, bodyStart) : skipGroup(toks, bodyStart), exprBody, exported, line: k.line });
      }
      continue;
    }
    // exports.name = …  /  module.exports.name = …
    if ((k.v === 'exports' || (k.v === 'module' && toks[i + 2]?.v === 'exports')) && !isP(toks[i - 1], '.')) {
      const at = k.v === 'module' ? i + 2 : i;
      if (isP(toks[at + 1], '.') && toks[at + 2]?.t === 'id' && isP(toks[at + 3], '=')) {
        let j = at + 4;
        if (toks[j]?.v === 'async') j++;
        if (toks[j]?.v === 'function') add(toks[at + 2].v, toks[j + 1]?.t === 'id' ? j + 2 : j + 1, true, i);
        else if (isP(toks[j], '(')) add(toks[at + 2].v, j, true, i);
      }
    }
  }
  return defs;
}

/** exportName → local function name. */
function findExports(toks, defs) {
  const map = new Map();
  for (const d of defs) if (d.exported) map.set(d.name, d.name);
  for (let i = 0; i < toks.length; i++) {
    const k = toks[i];
    if (k.t !== 'id') continue;
    if (k.v === 'export' && toks[i + 1]?.v === 'default' && toks[i + 2]?.t === 'id' && toks[i + 2].v !== 'function' && toks[i + 2].v !== 'async') {
      map.set('default', toks[i + 2].v);
    }
    if (k.v === 'export' && toks[i + 1]?.v === 'default' && (toks[i + 2]?.v === 'function' || toks[i + 3]?.v === 'function')) {
      const at = toks[i + 2].v === 'function' ? i + 3 : i + 4;
      if (toks[at]?.t === 'id') map.set('default', toks[at].v);
    }
    if (k.v === 'export' && isP(toks[i + 1], '{')) {
      const end = skipGroup(toks, i + 1);
      for (let j = i + 2; j < end - 1; j++) {
        if (toks[j].t !== 'id') continue;
        if (toks[j + 1]?.v === 'as' && toks[j + 2]?.t === 'id') { map.set(toks[j + 2].v, toks[j].v); j += 2; } else map.set(toks[j].v, toks[j].v);
      }
    }
    if (k.v === 'module' && isP(toks[i + 1], '.') && toks[i + 2]?.v === 'exports' && isP(toks[i + 3], '=')) {
      if (isP(toks[i + 4], '{')) {
        const end = skipGroup(toks, i + 4);
        for (let j = i + 5; j < end - 1; j++) {
          if (toks[j].t !== 'id') continue;
          if (isP(toks[j + 1], ':') && toks[j + 2]?.t === 'id') { map.set(toks[j].v, toks[j + 2].v); j += 2; } else if (isP(toks[j + 1], ',') || isP(toks[j + 1], '}') || j === end - 2) map.set(toks[j].v, toks[j].v);
        }
      } else if (toks[i + 4]?.t === 'id') {
        map.set('default', toks[i + 4].v);
      }
    }
  }
  return map;
}

// Kept deliberately simple: one bounded lazy clause, no runs of optional \s* (those backtrack badly).
const IMPORT_RE = /\bimport\b([^;'"`]{1,600}?)\bfrom\s*['"]([^'"\n]{1,200})['"]/g;
const REQUIRE_RE = /\b(?:const|let|var)\s+(?:([\w$]+)|\{([^}]{0,600})\})\s*=\s*require\s*\(\s*['"]([^'"\n]{1,200})['"]\s*\)/g;

/** local name → { spec, exp } (exp: export name, 'default', or '*' for a namespace / module object) */
function findImports(text) {
  const map = new Map();
  for (const m of text.matchAll(IMPORT_RE)) {
    const clause = m[1].trim().replace(/^type\s+/, '');
    const spec = m[2];
    const named = clause.match(/\{([^}]*)\}/)?.[1];
    const ns = clause.match(/\*\s*as\s+([\w$]+)/)?.[1];
    const def = clause.match(/^([\w$]+)/)?.[1];
    if (def) map.set(def, { spec, exp: 'default', ns: true });
    if (ns) map.set(ns, { spec, exp: '*' });
    for (const part of (named || '').split(',')) {
      const [orig, local] = part.replace(/^\s*type\s+/, '').trim().split(/\s+as\s+/).map((s) => s.trim());
      if (orig && /^[\w$]+$/.test(orig)) map.set(local || orig, { spec, exp: orig });
    }
  }
  for (const m of text.matchAll(REQUIRE_RE)) {
    const [, whole, named, spec] = m;
    if (whole) map.set(whole, { spec, exp: 'default', ns: true });
    for (const part of (named || '').split(',')) {
      const [orig, local] = part.trim().split(/\s*:\s*/).map((s) => s.trim());
      if (orig && /^[\w$]+$/.test(orig)) map.set(local || orig, { spec, exp: orig });
    }
  }
  return map;
}

const EXTENSIONS = ['', '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '/index.ts', '/index.tsx', '/index.js', '/index.mjs'];

function resolveSpec(fromRel, spec, known) {
  let bases;
  if (spec.startsWith('.')) {
    const dir = fromRel.includes('/') ? fromRel.slice(0, fromRel.lastIndexOf('/')) : '';
    const parts = [];
    for (const seg of `${dir}/${spec}`.split('/')) {
      if (!seg || seg === '.') continue;
      if (seg === '..') parts.pop(); else parts.push(seg);
    }
    bases = [parts.join('/')];
  } else if (/^[@~]\//.test(spec)) {
    bases = [`src/${spec.slice(2)}`, spec.slice(2)]; // the common tsconfig alias
  } else {
    return null;
  }
  for (const base of bases) {
    const stripped = base.replace(/\.(?:js|mjs|cjs)$/, '');
    for (const ext of EXTENSIONS) {
      for (const candidate of [base + ext, stripped + ext]) if (known.has(candidate)) return candidate;
    }
  }
  return null;
}

/**
 * Analyse a set of files together. `files`: [{ rel, text, nextAppFile? }].
 * Returns Map rel → [{ sink, line, flow }].
 */
export function analyzeProject(files) {
  const units = new Map();
  for (const f of files) {
    const toks = lex(f.text);
    const defs = findFunctions(toks);
    units.set(f.rel, {
      rel: f.rel, toks, ctx: fileContext(f.text), nextAppFile: Boolean(f.nextAppFile),
      defs, byName: new Map(defs.map((d) => [d.name, d])), exports: findExports(toks, defs), imports: findImports(f.text),
    });
  }
  const known = new Set(units.keys());
  let summaries = new Map(); // `${rel}#${name}` → summary

  const resolverFor = (unit) => (names) => {
    if (names.length === 1) {
      if (unit.byName.has(names[0])) return summaries.get(`${unit.rel}#${names[0]}`) ?? null;
      const imp = unit.imports.get(names[0]);
      if (!imp) return null;
      const target = resolveSpec(unit.rel, imp.spec, known);
      if (!target) return null;
      const local = units.get(target).exports.get(imp.exp === '*' ? 'default' : imp.exp);
      return local ? summaries.get(`${target}#${local}`) ?? null : null;
    }
    if (names.length === 2) {
      const imp = unit.imports.get(names[0]);
      if (!imp || !(imp.exp === '*' || imp.ns)) return null;
      const target = resolveSpec(unit.rel, imp.spec, known);
      if (!target) return null;
      const local = units.get(target).exports.get(names[1]);
      return local ? summaries.get(`${target}#${local}`) ?? null : null;
    }
    return null;
  };

  const summarize = (unit, def) => {
    const body = def.exprBody ? unit.toks.slice(def.bodyStart, def.bodyEnd) : unit.toks.slice(def.bodyStart + 1, def.bodyEnd - 1);
    const run = analyzeTokens(body, {
      ctx: unit.ctx, rel: unit.rel, nextAppFile: unit.nextAppFile, resolve: resolverFor(unit),
      params: def.params, exprBody: def.exprBody,
    });
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
    const validator = !def.exprBody && isValidatorBody(body);
    return {
      returnsParams: validator ? new Set() : returnsParams,
      returnsReq,
      returnRaw,
      returnValidated: returnValidated === Infinity ? 0 : returnValidated,
      paramSinks: run.paramSinks,
    };
  };

  for (let round = 0; round < 2; round++) {
    const next = new Map();
    for (const unit of units.values()) {
      for (const def of unit.defs) {
        try {
          next.set(`${unit.rel}#${def.name}`, summarize(unit, def));
        } catch {
          // unusual syntax: leave the function unsummarised (calls to it are treated as clean)
        }
      }
    }
    summaries = next;
  }

  const results = new Map();
  for (const unit of units.values()) {
    try {
      results.set(unit.rel, analyzeTokens(unit.toks, { ctx: unit.ctx, rel: unit.rel, nextAppFile: unit.nextAppFile, resolve: resolverFor(unit), params: null }).findings);
    } catch {
      results.set(unit.rel, []);
    }
  }
  return results;
}

/** Single-file convenience wrapper (helpers in the same file are still followed). */
export function analyzeTaint(text, { nextAppFile = false, rel = 'input.js' } = {}) {
  return analyzeProject([{ rel, text, nextAppFile }]).get(rel) || [];
}
