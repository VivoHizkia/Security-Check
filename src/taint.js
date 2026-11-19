// Intra-file taint tracking for JavaScript / TypeScript.
//
// Follows request data from a source (req.body, await req.json(), formData.get(), searchParams,
// Server Action arguments) through variables to a dangerous sink (SQL, shell, eval, Mongo filter,
// file path, server-side fetch, redirect). Rules of thumb, chosen to keep false positives low:
//   - Taint flows through assignment, destructuring, member access, template literals, string
//     concatenation and a short list of pass-through calls (new URL, path.join, String, JSON.parse).
//   - Any other function call stops it: an unknown helper may validate or sanitize, so its result
//     is treated as clean. Number(), parseInt() and friends always clean.
//   - Scopes are lexical (braces), so a `url` in one function never taints a `url` in another.
// It does not follow data across files or through function return values.

import { hasDirective } from './files.js';

// ── Lexer ───────────────────────────────────────────────────────────

const PUNCT = ['>>>=', '...', '===', '!==', '**=', '<<=', '>>=', '>>>', '&&=', '||=', '??=',
  '=>', '==', '!=', '<=', '>=', '&&', '||', '??', '?.', '++', '--', '+=', '-=', '*=', '/=', '%=',
  '&=', '|=', '^=', '**', '<<', '>>'];
const REGEX_AFTER_KEYWORD = new Set(['return', 'typeof', 'case', 'do', 'else', 'in', 'of', 'new', 'delete', 'void', 'throw', 'yield', 'await', 'instanceof']);

/**
 * Tokens: { t: 'id' | 'num' | 'str' | 'p' | 'tpl', v, line }. A template literal becomes
 * tpl'`' … (tpl'${' expression tokens tpl'}')* … tpl'`'. Strings never span lines, so a stray
 * apostrophe in JSX text only damages its own line.
 */
export function lex(src) {
  const tokens = [];
  const frames = [{ tpl: false, braces: 0 }];
  let line = 1;
  let i = 0;
  const push = (t, v) => tokens.push({ t, v, line });
  const prevSignificant = () => tokens[tokens.length - 1];
  const regexAllowed = () => {
    const p = prevSignificant();
    if (!p) return true;
    if (p.t === 'p') return ![')', ']', '}'].includes(p.v);
    if (p.t === 'tpl') return p.v === '${';
    if (p.t === 'id') return REGEX_AFTER_KEYWORD.has(p.v);
    return false;
  };

  const readTemplate = () => {
    // called right after an opening ` or after the } closing a ${ … }
    while (i < src.length) {
      const c = src[i];
      if (c === '\\') { i += 2; continue; }
      if (c === '\n') line++;
      if (c === '`') { push('tpl', '`'); i++; return; }
      if (c === '$' && src[i + 1] === '{') { push('tpl', '${'); i += 2; frames.push({ tpl: true, braces: 0 }); return; }
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
    if (c === '`') { push('tpl', '`'); i++; readTemplate(); continue; }
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

// ── Helpers over the token stream ──────────────────────────────────

const OPENERS = { '(': ')', '[': ']', '{': '}' };

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
        // a template's own backticks: find its closing one at the same nesting
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

const isCall = (toks, j) => toks[j]?.t === 'p' && toks[j].v === '(';

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

// ── Analysis ────────────────────────────────────────────────────────

/**
 * Returns [{ sink, line, flow }] for every sink call whose relevant argument carries request data.
 * `flow` describes where the data came from, e.g. "req.body → filter (line 4)".
 */
export function analyzeTaint(text, { nextAppFile = false } = {}) {
  const toks = lex(text);
  const ctx = {
    usesMongo: /\bmongoose\b|\bmongodb\b|\.collection\s*\(/.test(text),
    importsChildProcess: /['"](?:node:)?child_process['"]/.test(text),
    importsFs: /['"](?:node:)?fs(?:\/promises)?['"]/.test(text),
    importsNextRedirect: /['"]next\/navigation['"]/.test(text),
    useServer: hasDirective(text, 'use server'),
  };
  const scopes = [new Map()];
  const lookup = (name) => {
    for (let s = scopes.length - 1; s >= 0; s--) if (scopes[s].has(name)) return scopes[s].get(name);
    return undefined;
  };
  const declare = (name, info) => scopes[scopes.length - 1].set(name, info);
  const assign = (name, info) => {
    for (let s = scopes.length - 1; s >= 0; s--) if (scopes[s].has(name)) { scopes[s].set(name, info); return; }
    declare(name, info);
  };

  /**
   * { flow, raw } if the chain is request data, else null. `raw` is false once the value has been
   * coerced to a string (String(), a template literal): still dangerous for SQL, paths or URLs,
   * but no longer able to smuggle a Mongo operator object.
   */
  const sourceOf = (names, end) => {
    const [a, b] = names;
    if (REQUEST_OBJECTS.has(a) && REQUEST_FIELDS.has(b)) {
      if (['json', 'formData', 'text'].includes(b) && !isCall(toks, end)) return null;
      return { flow: `${a}.${b}${['json', 'formData', 'text'].includes(b) ? '()' : ''}`, raw: true };
    }
    if (a === 'ctx' && (b === 'query' || b === 'params' || (b === 'request' && names[2] === 'body'))) return { flow: names.slice(0, b === 'request' ? 3 : 2).join('.'), raw: true };
    if (names.includes('searchParams')) return { flow: 'searchParams', raw: true };
    if (nextAppFile && a === 'params') return { flow: 'params', raw: true };
    const t = lookup(a);
    if (t) return { flow: t.flow ? `${t.flow} → ${a} (line ${t.line})` : `${a} (line ${t.line})`, raw: t.raw, validated: t.validated || 0 };
    return null;
  };

  /**
   * Taint of the expression starting at `from`, up to its end (`;`, a top-level `,`, a closing
   * bracket, or a line break that ends the statement). Returns { flow, end }.
   */
  const exprTaint = (from, { stopAtComma = true } = {}) => {
    const groups = []; // open brackets inside the expression: '(' '[' '{' '`' '${', and 'S(' for String(…)
    let flow = null;
    let raw = false;
    let validated = Infinity; // weakest validation among the tainted values used
    let j = from;
    for (; j < toks.length; j++) {
      const k = toks[j];
      const depth = groups.length;
      if (depth === 0) {
        if (k.t === 'p' && (k.v === ';' || k.v === ')' || k.v === ']' || k.v === '}')) break;
        if (k.t === 'tpl' && k.v === '}') break;
        if (stopAtComma && k.t === 'p' && k.v === ',') break;
        if (j > from && k.line > toks[j - 1].line && startsStatement(toks, j) && !continues(toks[j - 1])) break;
      }
      if (k.t === 'id' && NOT_A_VALUE.has(k.v)) { j = skipFunction(toks, j) - 1; continue; }
      if (k.t === 'p' && k.v === '=>') { j = skipArrowBody(toks, j) - 1; continue; }
      // Brackets and template literals
      if (k.t === 'tpl' && k.v === '`') {
        if (groups[groups.length - 1] === '`') groups.pop(); else groups.push('`');
        continue;
      }
      if (k.t === 'tpl' && k.v === '${') { groups.push('${'); continue; }
      if (k.t === 'tpl' && k.v === '}') { groups.pop(); continue; }
      if (k.t === 'p' && OPENERS[k.v]) { groups.push(k.v); continue; }
      if (k.t === 'p' && (k.v === ')' || k.v === ']' || k.v === '}')) { groups.pop(); continue; }
      if (k.t === 'id') {
        // `{ key: value }`: the key is a name, not a use of a variable
        if (groups[groups.length - 1] === '{' && toks[j + 1]?.t === 'p' && toks[j + 1].v === ':') { j++; continue; }
        const { names, end } = readChain(toks, j);
        const src = sourceOf(names, end);
        const callee = names.join('.');
        if (src) {
          flow = flow || src.flow;
          if (src.raw && !groups.some((g) => g === 'S(' || g === '`')) raw = true;
          validated = Math.min(validated, src.validated || 0);
          j = (isCall(toks, end) ? skipGroup(toks, end) : end) - 1;
          continue;
        }
        if (isCall(toks, end)) {
          if (callee === 'String') { groups.push('S('); j = end; continue; }
          const pass = PASS_THROUGH.has(callee) || (names[0] === 'path' && PASS_THROUGH.has(names[names.length - 1]));
          if (!pass) { j = skipGroup(toks, end) - 1; continue; } // unknown call: its result is clean
          j = end - 1;
          continue;
        }
        j = end - 1;
      }
    }
    return { flow, raw: Boolean(flow) && raw, validated: flow ? validated : 0, end: j };
  };

  /** Names bound by a declaration pattern at i: `x`, `{ a, b: c, ...rest }`, `[a, b]`. */
  const patternNames = (i) => {
    if (toks[i].t === 'id') return { names: [toks[i].v], end: i + 1 };
    const end = skipGroup(toks, i);
    const names = [];
    for (let j = i + 1; j < end - 1; j++) {
      const k = toks[j];
      if (k.t !== 'id') continue;
      const next = toks[j + 1];
      if (next && next.t === 'p' && next.v === ':') continue; // `key:` → the binding comes after
      if (next && next.t === 'p' && next.v === '=') { names.push(k.v); j = exprTaint(j + 2).end - 1; continue; } // default value
      names.push(k.v);
    }
    return { names, end };
  };

  const findings = [];
  const seen = new Set();
  const bodyParams = new Map(); // index of a function body's `{` → [[name, taint]]

  /** Parameter names between `(` at open and its `)`, plus the index of the body `{` after it. */
  const paramsAndBody = (open) => {
    const close = skipGroup(toks, open);
    const names = [];
    for (let p = open + 1; p < close - 1; p++) {
      const prev = toks[p - 1];
      if (toks[p].t === 'id' && prev.t === 'p' && ['(', ',', '{', '[', '...'].includes(prev.v)) names.push(toks[p].v);
    }
    let angle = 0;
    for (let b = close; b < toks.length; b++) { // skip a return type like Promise<{ ok: boolean }>
      const t = toks[b];
      if (t.t === 'p' && t.v === '<') angle++;
      else if (t.t === 'p' && t.v === '>') angle--;
      else if (t.t === 'p' && t.v === '{' && angle <= 0) return { names, body: b };
      else if (t.t === 'p' && t.v === ';') break;
    }
    return { names, body: -1 };
  };

  /** Parameter names of the arrow function whose `=>` is at index i. */
  const arrowParams = (i) => {
    const prevTok = toks[i - 1];
    if (prevTok?.t === 'id') return [prevTok.v];
    if (!(prevTok?.t === 'p' && prevTok.v === ')')) return [];
    let d = 0;
    for (let o = i - 1; o >= 0; o--) {
      if (toks[o].t === 'p' && toks[o].v === ')') d++;
      else if (toks[o].t === 'p' && toks[o].v === '(' && --d === 0) return paramsAndBody(o).names;
    }
    return [];
  };

  const exprScopeEnds = []; // expression-bodied arrows: index where their parameter scope ends

  for (let i = 0; i < toks.length; i++) {
    const k = toks[i];
    while (exprScopeEnds.length && i >= exprScopeEnds[exprScopeEnds.length - 1]) { exprScopeEnds.pop(); scopes.pop(); }

    if (k.t === 'p' && k.v === '=>' && toks[i + 1]?.v !== '{') {
      // x => expr   or   (a, b) => expr : parameters shadow outer names until the expression ends
      const names = arrowParams(i);
      scopes.push(new Map(names.map((n) => [n, undefined])));
      exprScopeEnds.push(Math.max(i + 2, exprTaint(i + 1).end));
      continue;
    }
    if (k.t === 'p' && k.v === '{') {
      scopes.push(new Map());
      for (const [n, info] of bodyParams.get(i) || []) declare(n, info);
      continue;
    }
    if (k.t === 'p' && k.v === '}') { if (scopes.length > 1) scopes.pop(); continue; }
    if (k.t === 'p' && k.v === '=>' && toks[i + 1]?.v === '{') {
      // (a, b) => {   or   a => {   : parameters shadow outer names
      if (!bodyParams.has(i + 1)) bodyParams.set(i + 1, arrowParams(i).map((n) => [n, undefined]));
      continue;
    }
    if (k.t !== 'id') continue;

    // if (<validation of x>) return …   or   if (<validation of x>) { …sink… }
    if (k.v === 'if' && isCall(toks, i + 1)) {
      const condEnd = skipGroup(toks, i + 1);
      const checks = guardChecks(toks.slice(i + 2, condEnd - 1));
      if (checks.size) {
        const blockStart = condEnd;
        const blockEnd = toks[blockStart]?.v === '{' ? skipGroup(toks, blockStart) : statementEndAt(toks, blockStart);
        const exits = toks.slice(blockStart, blockEnd).some((t) => t.t === 'id' && ['return', 'throw', 'redirect', 'notFound'].includes(t.v));
        for (const [name, level] of checks) {
          const info = lookup(name);
          if (!info) continue;
          const better = { ...info, validated: Math.max(info.validated || 0, level) };
          if (exits) assign(name, better); // invalid values left the function: the rest of it sees a checked value
          else if (toks[blockStart]?.v === '{') bodyParams.set(blockStart, [...(bodyParams.get(blockStart) || []), [name, better]]);
        }
      }
      continue;
    }

    if (k.v === 'function') {
      const open = toks[i + 1]?.t === 'id' ? i + 2 : i + 1;
      if (isCall(toks, open)) {
        const { names, body } = paramsAndBody(open);
        // Server Action: every argument of an exported function in a 'use server' file is client input.
        const exported = toks.slice(Math.max(0, i - 3), i).some((t) => t.v === 'export');
        const taint = ctx.useServer && exported
          ? (n) => ({ flow: `Server Action argument "${n}"`, raw: true, line: k.line })
          : () => undefined;
        if (body !== -1 && !bodyParams.has(body)) bodyParams.set(body, names.map((n) => [n, taint(n)]));
      }
      continue;
    }

    // Declarations: const|let|var pattern [: Type] = expr
    if ((k.v === 'const' || k.v === 'let' || k.v === 'var') && toks[i + 1]) {
      let j = i + 1;
      let resumeAt = i;
      let firstEq = false;
      for (;;) {
        if (!toks[j] || !(toks[j].t === 'id' || (toks[j].t === 'p' && (toks[j].v === '{' || toks[j].v === '[')))) break;
        const { names, end } = patternNames(j);
        if (!firstEq) resumeAt = end - 1;
        let eq = end;
        if (toks[eq]?.t === 'p' && toks[eq].v === ':') { // TypeScript annotation
          let d = 0;
          for (eq += 1; eq < toks.length; eq++) {
            const t = toks[eq];
            if (t.t === 'p' && (OPENERS[t.v] || t.v === '<')) d++;
            else if (t.t === 'p' && [')', ']', '}', '>'].includes(t.v)) d--;
            else if (d <= 0 && t.t === 'p' && (t.v === '=' || t.v === ';' || t.v === ',')) break;
          }
        }
        if (!(toks[eq]?.t === 'p' && toks[eq].v === '=')) { for (const n of names) declare(n, undefined); break; }
        const { flow, raw, validated, end: exprEnd } = exprTaint(eq + 1);
        for (const n of names) declare(n, flow ? { flow, raw, validated, line: toks[eq].line } : undefined);
        if (resumeAt < eq && !firstEq) { resumeAt = eq; firstEq = true; }
        if (toks[exprEnd]?.t === 'p' && toks[exprEnd].v === ',' && toks[exprEnd + 1]?.t === 'id' && toks[exprEnd + 2]?.v === '=') {
          j = exprEnd + 1;
          continue;
        }
        break;
      }
      i = resumeAt; // skip the binding pattern, keep walking the RHS so nested functions and sinks are seen
      continue;
    }

    // Plain assignment: x = expr
    const prev = toks[i - 1];
    if (toks[i + 1]?.t === 'p' && toks[i + 1].v === '=' && !(prev && prev.t === 'p' && (prev.v === '.' || prev.v === '?.'))) {
      const { flow, raw, validated } = exprTaint(i + 2);
      assign(k.v, flow ? { flow, raw, validated, line: k.line } : undefined);
      continue;
    }

    // Sink calls
    if (prev && prev.t === 'p' && (prev.v === '.' || prev.v === '?.')) continue; // middle of a chain
    const { names, end } = readChain(toks, i);
    if (!isCall(toks, end)) { i = end - 1; continue; }
    const sink = classifySink(names, { ...ctx, prevIsNew: prev?.t === 'id' && prev.v === 'new' });
    if (!sink) { i = end - 1; continue; }

    const close = skipGroup(toks, end);
    const argStart = end + 1;
    let found = null;
    let kind = sink;
    if (sink === 'redirect' || sink === 'eval') {
      const r = exprTaint(argStart, { stopAtComma: false }); // any argument
      if (r.flow && r.validated < (NEEDED_VALIDATION[sink] ?? VALID.EXACT)) found = r.flow;
    } else if (sink === 'path' && names[0] === 'res' && toks.slice(argStart, close).some((t) => t.t === 'id' && t.v === 'root')) {
      found = null; // sendFile(name, { root }) refuses ../ escapes
    } else if (sink === 'nosql') {
      // only a raw (uncast) value can carry an operator object like {"$ne": null}
      const isLiteral = toks[argStart]?.t === 'p' && toks[argStart].v === '{';
      const body = isLiteral ? toks.slice(argStart, skipGroup(toks, argStart)) : [];
      const isSequelizeStyle = body.some((t, n) => t.t === 'id' && t.v === 'where' && body[n + 1]?.v === ':');
      const r = isSequelizeStyle ? null : exprTaint(argStart);
      if (r?.raw) { found = r.flow; kind = isLiteral ? 'nosqlField' : 'nosql'; }
    } else {
      const r = exprTaint(argStart);
      if (r.flow && r.validated < (NEEDED_VALIDATION[sink] ?? VALID.EXACT)) found = r.flow;
    }
    if (found) {
      const key = `${kind}:${k.line}`;
      if (!seen.has(key)) {
        seen.add(key);
        findings.push({ sink: kind, line: k.line, flow: `${found} → ${names.join('.')}()` });
      }
    }
    i = end - 1; // continue inside the arguments, they can hold nested sinks
  }
  return findings;
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

/** Map of variable → validation level for the checks found in an `if (…)` condition. */
function guardChecks(cond) {
  const found = new Map();
  const raise = (name, level) => found.set(name, Math.max(found.get(name) || 0, level));
  const startsWith = new Map(); // name → Set of prefixes it is checked against
  for (let j = 0; j < cond.length; j++) {
    const k = cond[j];
    // x.startsWith('/')
    if (k.t === 'id' && cond[j + 1]?.v === '.' && cond[j + 2]?.v === 'startsWith' && cond[j + 3]?.v === '(' && cond[j + 4]?.t === 'str') {
      startsWith.set(k.v, new Set([...(startsWith.get(k.v) || []), cond[j + 4].v]));
    }
    // list.includes(x) / set.has(x)
    if (k.t === 'p' && k.v === '.' && ['includes', 'has'].includes(cond[j + 1]?.v) && cond[j + 2]?.v === '(' && cond[j + 3]?.t === 'id' && cond[j + 4]?.v === ')') {
      raise(cond[j + 3].v, VALID.EXACT);
    }
    // x === 'literal' / 'literal' !== x (a non-empty literal: x === '' only rules out one value)
    if (k.t === 'p' && ['===', '!==', '==', '!='].includes(k.v)) {
      const [l, r] = [cond[j - 1], cond[j + 1]];
      if (l?.t === 'id' && r?.t === 'str' && r.v) raise(l.v, VALID.EXACT);
      if (r?.t === 'id' && l?.t === 'str' && l.v) raise(r.v, VALID.EXACT);
    }
    // /^…$/.test(x)
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
    else if (depth === 0 && t.t === 'p' && t.v === ';') return k + 1;
    if (depth === 0 && k > j && t.line > toks[k - 1].line) return k;
  }
  return toks.length;
}

// ── Statement-boundary helpers for exprTaint ───────────────────────

const STATEMENT_START = new Set(['const', 'let', 'var', 'return', 'if', 'for', 'while', 'switch', 'throw', 'try', 'export', 'import', 'function', 'class', 'do', 'else', 'break', 'continue']);
function startsStatement(toks, j) {
  const k = toks[j];
  if (k.t === 'id' && STATEMENT_START.has(k.v)) return true;
  if (k.t === 'id' || k.t === 'str' || k.t === 'num') {
    const next = toks[j + 1];
    return !(next && next.t === 'p' && ['.', '?.'].includes(next.v)) || k.t === 'id';
  }
  return false;
}
function continues(prev) {
  return prev.t === 'p' && !['}', ')', ']'].includes(prev.v) || (prev.t === 'tpl' && prev.v === '${');
}
function skipFunction(toks, j) {
  for (let k = j; k < toks.length; k++) if (toks[k].t === 'p' && toks[k].v === '{') return skipGroup(toks, k);
  return toks.length;
}
function skipArrowBody(toks, j) {
  const next = toks[j + 1];
  if (next && next.t === 'p' && next.v === '{') return skipGroup(toks, j + 1);
  return j + 1;
}
