import path from 'node:path';
import { finding } from '../findings.js';
import { createIgnoreMatcher, gitTrackedFiles, isEnvExample, isEnvFile, isTestPath } from '../files.js';

const SCANNER = 'secrets';

const RULES = [
  { id: 'aws-access-key', severity: 'critical', title: 'AWS access key ID', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    fix: 'Deactivate the key in AWS IAM, then load credentials from the environment or an IAM role.' },
  { id: 'private-key', severity: 'critical', title: 'Private key in source', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g,
    fix: 'Treat the key as compromised: rotate it and keep key files out of the repository.', noValue: true },
  { id: 'github-token', severity: 'critical', title: 'GitHub token', re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})/g,
    fix: 'Revoke it at github.com/settings/tokens and use a secret store instead.' },
  { id: 'stripe-live-key', severity: 'critical', title: 'Stripe live secret key', re: /\b[sr]k_live_[0-9a-zA-Z]{20,}/g,
    fix: 'Roll the key in the Stripe dashboard and read it from the environment.' },
  { id: 'anthropic-key', severity: 'critical', title: 'Anthropic API key', re: /\bsk-ant-[A-Za-z0-9_-]{20,}/g,
    fix: 'Revoke it in the Anthropic Console and read it from the environment.' },
  { id: 'openai-key', severity: 'critical', title: 'OpenAI API key', re: /\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}/g,
    fix: 'Revoke it in the OpenAI dashboard and read it from the environment.' },
  { id: 'slack-token', severity: 'high', title: 'Slack token', re: /\bxox[abposr]-[A-Za-z0-9-]{10,}/g,
    fix: 'Revoke the token in your Slack app settings.' },
  { id: 'slack-webhook', severity: 'high', title: 'Slack webhook URL', re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]{20,}/g,
    fix: 'Regenerate the webhook; anyone with this URL can post to your workspace.' },
  { id: 'google-api-key', severity: 'high', title: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    fix: 'Restrict the key (HTTP referrer / API restrictions) or rotate it if it is a server key.' },
  { id: 'telegram-bot-token', severity: 'high', title: 'Telegram bot token', re: /\b\d{8,10}:AA[0-9A-Za-z_-]{33}\b/g,
    fix: 'Revoke it via @BotFather (/revoke) and read it from the environment.' },
  { id: 'db-url-credentials', severity: 'high', title: 'Database URL with embedded password',
    re: /\b(?:mysql|mariadb|postgres(?:ql)?|mongodb(?:\+srv)?|redis|rediss|amqp):\/\/[^\s:/@'"`]+:[^\s@'"`]+@[^\s'"`]+/g,
    fix: 'Move the connection string to an environment variable and change the password.' },
  { id: 'jwt', severity: 'medium', title: 'Hard-coded JWT', re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    fix: 'Do not ship long-lived tokens in code; issue them at runtime.' },
  { id: 'hardcoded-credential', severity: 'medium', title: 'Hard-coded credential',
    // Name parts are bounded ({0,40}) and anchored: unbounded [..]* on both sides of the keyword backtracks cubically.
    re: /(['"]?)((?<![A-Za-z0-9_.-])[A-Za-z0-9_.-]{0,40}?(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)[A-Za-z0-9_.-]{0,40})\1\s{0,10}(?:=>|:|=)\s{0,10}(['"`])([^'"`\s]{8,500})\3/gi,
    valueGroup: 4, fix: 'Read the value from an environment variable or secret manager.' },
];

const PLACEHOLDER = /^(?:\$\{|\{\{|<|%|your|my[_-]?|xxx|\*{3}|change[_-]?me|example|placeholder|dummy|sample|test|fake|redacted|replace|insert|enter|todo|none|null|undefined|password|secret|secretkey|required|env\(|process\.env|import\.meta)/i;

const ENV_SECRET_NAME = /^([A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|TOKEN|PRIVATE|API_KEY|ACCESS_KEY|AUTH_KEY)[A-Z0-9_]*)\s*=\s*(.*)$/;

export function mask(value) {
  if (value.length <= 8) return `${value.slice(0, 2)}****`;
  return `${value.slice(0, 4)}****${value.slice(-2)}`;
}

function maskDbUrl(url) {
  return url.replace(/(:\/\/[^:/@]+:)[^@]+@/, '$1****@');
}

export async function scanSecrets(root, files) {
  const findings = [];

  for (const file of files) {
    if (isEnvFile(file.name)) continue; // secrets are supposed to live here; handled below
    const lines = file.text.split(/\r?\n/);
    const seen = new Set();
    const inTests = isTestPath(file.rel);

    lines.forEach((line, i) => {
      if (line.length > 4000 || line.includes('tameng-ignore')) return;
      for (const rule of RULES) {
        rule.re.lastIndex = 0;
        let m;
        while ((m = rule.re.exec(line))) {
          const value = rule.valueGroup ? m[rule.valueGroup] : m[0];
          if (rule.id === 'db-url-credentials' && /:\/\/[^:]*[<{$%][^@]*@|:\/\/[^@]*:[<{$%*]/.test(value)) continue; // <user>:<pass> placeholders
          if (rule.valueGroup) {
            if (inTests) continue; // fixture passwords in tests are noise; real key formats above still apply
            if (/^\$2[aby]?\$\d\d\$|^\$argon2/.test(value)) continue; // password hash, not a secret
            if (/^\$[A-Za-z_]/.test(value)) continue; // template / shell variable
            if (PLACEHOLDER.test(value) || value.toLowerCase() === m[2].toLowerCase()) continue;
            if (/^[a-z]+(?:[._-][a-z]+)*$/.test(value) && value.length < 16) continue; // looks like an identifier / config name
            if (/^[A-Z0-9_]+$/.test(value)) continue; // probably the NAME of an env var
            if (/^\\{0,2}(?:[A-Z][A-Za-z0-9_]*\\{1,2})+[A-Z][A-Za-z0-9_]*$/.test(value)) continue; // a PHP class name: 'auth.password' => 'Illuminate\\…\\Provider'
            if (/\?\s*$/.test(line.slice(0, m.index))) continue; // ternary branch (cond ? "new-password" : "current-password"), not key: value
          }
          const key = `${rule.id}:${value}`;
          if (seen.has(key)) continue;
          seen.add(key);
          const shown = rule.noValue ? '' : rule.id === 'db-url-credentials' ? maskDbUrl(value) : mask(value);
          findings.push(finding({
            id: rule.id, scanner: SCANNER, severity: rule.severity, title: rule.title,
            detail: shown ? `Value: ${shown}` : '', location: `${file.rel}:${i + 1}`, fix: rule.fix,
          }));
        }
      }
    });

    if (isEnvExample(file.name)) findings.push(...checkEnvExample(file, lines));
  }

  findings.push(...(await checkEnvFilesExposure(root, files)));
  return findings;
}

function checkEnvExample(file, lines) {
  const out = [];
  lines.forEach((line, i) => {
    const m = line.trim().match(ENV_SECRET_NAME);
    if (!m) return;
    const value = m[2].replace(/^['"]|['"]$/g, '').trim();
    if (value.length < 12 || PLACEHOLDER.test(value) || /^[a-z_\-.]+$/i.test(value)) return;
    out.push(finding({
      id: 'env-example-real-value', scanner: SCANNER, severity: 'medium',
      title: 'Example env file contains a real-looking secret',
      detail: `${m[1]}=${mask(value)}`, location: `${file.rel}:${i + 1}`,
      fix: 'Example files are committed and shared; replace the value with a placeholder.',
    }));
  });
  return out;
}

async function checkEnvFilesExposure(root, files) {
  const out = [];
  const envFiles = files.filter((f) => isEnvFile(f.name));
  if (!envFiles.length) return out;

  const tracked = await gitTrackedFiles(root);
  const ignoreFiles = files.filter((f) => f.name === '.gitignore');

  for (const env of envFiles) {
    if (tracked?.has(env.rel)) {
      out.push(finding({
        id: 'env-committed', scanner: SCANNER, severity: 'critical',
        title: 'Env file is committed to git', location: env.rel,
        detail: 'Everyone with access to the repo (and its history) can read these secrets.',
        fix: `git rm --cached ${env.rel}, add it to .gitignore, then rotate every secret it contained.`,
      }));
      continue;
    }
    // Apply every .gitignore that sits in the env file's directory or above it.
    const ignored = ignoreFiles.some((gi) => {
      const dir = path.posix.dirname(gi.rel);
      const base = dir === '.' ? '' : `${dir}/`;
      if (base && !env.rel.startsWith(base)) return false;
      return createIgnoreMatcher(gi.text)(env.rel.slice(base.length));
    });
    if (!ignored) {
      out.push(finding({
        id: 'env-not-ignored', scanner: SCANNER, severity: 'high',
        title: 'Env file is not covered by .gitignore', location: env.rel,
        detail: 'The next `git add .` will commit your secrets.',
        fix: 'Add `.env` and `.env.*` (plus `!.env.example`) to .gitignore.',
      }));
    }
  }
  return out;
}
