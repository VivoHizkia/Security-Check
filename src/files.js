import { readdir, readFile, stat } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import path from 'node:path';

const IGNORED_DIRS = new Set([
  'node_modules', 'vendor', '.git', '.hg', '.svn', 'dist', 'build', 'out', '.next', '.nuxt',
  '.output', '.svelte-kit', '.vercel', '.netlify', '.turbo', '.cache', 'coverage', 'storage',
  '__pycache__', '.venv', 'venv', '.idea', '.gradle', 'Pods',
]);

const BINARY_EXT = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.avif', '.ico', '.bmp', '.tiff', '.psd',
  '.woff', '.woff2', '.ttf', '.otf', '.eot', '.mp3', '.mp4', '.mov', '.webm', '.wav', '.ogg',
  '.zip', '.gz', '.tgz', '.rar', '.7z', '.tar', '.pdf', '.exe', '.dll', '.so', '.dylib',
  '.jar', '.class', '.wasm', '.map', '.sqlite', '.db', '.bin', '.apk', '.aab', '.ipa',
]);

export const LOCKFILES = new Set([
  'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'composer.lock', 'requirements.txt',
  'pnpm-lock.yaml', 'bun.lock', 'bun.lockb',
]);

const MAX_FILE_SIZE = 1_000_000;

/**
 * Walks a project and loads every text file worth scanning.
 * Lockfiles are returned separately: they are huge and only the dependency scanner needs them.
 */
export async function collectFiles(root) {
  const files = [];
  const lockfiles = [];
  const stack = [root];
  let userIgnored = () => false;
  try {
    userIgnored = createIgnoreMatcher(await readFile(path.join(root, '.tamengignore'), 'utf8'));
  } catch {
    /* no .tamengignore */
  }

  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isSymbolicLink()) continue;
      const rel = path.relative(root, full).split(path.sep).join('/');
      if (userIgnored(rel)) continue;
      if (entry.isDirectory()) {
        if (!IGNORED_DIRS.has(entry.name)) stack.push(full);
        continue;
      }
      if (!entry.isFile()) continue;

      if (LOCKFILES.has(entry.name)) {
        lockfiles.push({ full, rel, name: entry.name });
        continue;
      }
      if (BINARY_EXT.has(path.extname(entry.name).toLowerCase())) continue;
      if (/\.min\.(js|css)$/.test(entry.name)) continue;

      let info;
      try {
        info = await stat(full);
      } catch {
        continue;
      }
      if (info.size > MAX_FILE_SIZE) continue;

      const text = await readText(full);
      if (text !== null) files.push({ full, rel, name: entry.name, text });
    }
  }

  files.sort((a, b) => a.rel.localeCompare(b.rel));
  lockfiles.sort((a, b) => a.rel.localeCompare(b.rel));
  return { files, lockfiles };
}

async function readText(file) {
  try {
    const buf = await readFile(file);
    if (buf.subarray(0, 8000).includes(0)) return null;
    return buf.toString('utf8');
  } catch {
    return null;
  }
}

export function isEnvFile(name) {
  return name === '.env' || (name.startsWith('.env.') && !isEnvExample(name));
}

export function isEnvExample(name) {
  return /^\.env\.(example|sample|template|dist|defaults?)$/i.test(name) || /^\.env\.[\w-]*example$/i.test(name);
}

export function isTestPath(rel) {
  return /(^|\/)(tests?|__tests__|spec|__mocks__|fixtures?)\//i.test(rel) || /\.(test|spec)\.[cm]?[jt]sx?$/.test(rel);
}

/** Files tracked by git, or null when the folder is not a repo / git is missing. */
export function gitTrackedFiles(root) {
  return new Promise((resolve) => {
    execFile('git', ['-C', root, 'ls-files', '-z'], { maxBuffer: 64 * 1024 * 1024 }, (err, stdout) => {
      if (err) return resolve(null);
      resolve(new Set(stdout.split('\0').filter(Boolean)));
    });
  });
}

/** Minimal .gitignore matcher: enough to answer "is this .env ignored?". */
export function createIgnoreMatcher(gitignoreText) {
  const rules = [];
  for (let line of (gitignoreText || '').split(/\r?\n/)) {
    line = line.trim();
    if (!line || line.startsWith('#')) continue;
    const negate = line.startsWith('!');
    if (negate) line = line.slice(1);
    const anchored = line.startsWith('/') || line.slice(0, -1).includes('/');
    line = line.replace(/^\//, '').replace(/\/$/, '');
    const source = line
      .split('**')
      .map((part) => part.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*').replace(/\?/g, '[^/]'))
      .join('.*');
    rules.push({ negate, anchored, re: new RegExp(`^${source}$`) });
  }
  return (rel) => {
    const base = rel.split('/').pop();
    let ignored = false;
    for (const rule of rules) {
      const hit = rule.anchored ? rule.re.test(rel) : rule.re.test(base) || rule.re.test(rel);
      if (hit) ignored = !rule.negate;
    }
    return ignored;
  };
}

export function lineOf(text, index) {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

export function snippet(line, max = 120) {
  const s = line.trim().replace(/\s+/g, ' ');
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}
