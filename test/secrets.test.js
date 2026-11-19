import { test } from 'node:test';
import assert from 'node:assert/strict';
import { collectFiles } from '../src/files.js';
import { scanSecrets, mask } from '../src/scanners/secrets.js';
import { fake, ids, makeProject } from './helpers.js';

test('detects hard-coded keys and masks them', async () => {
  const p = await makeProject({
    'src/aws.js': `const key = "${fake.aws()}";\n`,
    'src/pay.js': `stripe(${JSON.stringify(fake.stripe())})\n`,
    'deploy/id_rsa': fake.privateKey(),
    'config/db.js': 'module.exports = "mysql://admin:hunter2pass@db.internal:3306/app";\n', // tameng-ignore
    'config/app.php': "return ['api_key' => 'Zx81kd9QpL2mvB7r'];\n",
  });
  try {
    const { files } = await collectFiles(p.root);
    const found = await scanSecrets(p.root, files);
    const got = ids(found);
    for (const id of ['aws-access-key', 'stripe-live-key', 'private-key', 'db-url-credentials', 'hardcoded-credential']) {
      assert.ok(got.includes(id), `expected ${id}, got ${got}`);
    }
    const aws = found.find((f) => f.id === 'aws-access-key');
    assert.equal(aws.location, 'src/aws.js:1');
    assert.ok(!aws.detail.includes(fake.aws()), 'secret must be masked');
    assert.ok(found.find((f) => f.id === 'db-url-credentials').detail.includes('admin:****@'));
  } finally {
    await p.cleanup();
  }
});

test('ignores placeholders, env lookups and tameng-ignore lines', async () => {
  const p = await makeProject({
    'a.js': [
      'const password = process.env.DB_PASSWORD;',
      'const apiKey = "your_api_key_here";',
      'const secret = "${SECRET}";',
      `const k = "${fake.aws()}"; // tameng-ignore`,
      'const tokenType = "bearer_token";',
      'const hash = { password: "$2a$10$abcdefghijklmnopqrstuv" };',
      '// mongodb://<username>:<password>@cluster0.example.net/db',
    ].join('\n'),
    'src/AuthForm.tsx': '<input autoComplete={signup ? "new-password" : "current-password"} />\n',
    '.env.example': 'APP_KEY=\nDB_PASSWORD=secret\nSTRIPE_SECRET=sk_test_xxx\n',
  });
  try {
    const { files } = await collectFiles(p.root);
    assert.deepEqual(await scanSecrets(p.root, files), []);
  } finally {
    await p.cleanup();
  }
});

test('hard-coded credential rule stays fast on pathological lines', async () => {
  const line = 'password'.repeat(240); // used to take about a second per line (cubic backtracking)
  const p = await makeProject({ 'src/dump.js': `${line}\n`.repeat(20) });
  try {
    const { files } = await collectFiles(p.root);
    const t0 = Date.now();
    await scanSecrets(p.root, files);
    assert.ok(Date.now() - t0 < 1000, `took ${Date.now() - t0} ms`);
  } finally {
    await p.cleanup();
  }
});

test('flags real-looking values in .env.example', async () => {
  const p = await makeProject({ '.env.example': 'MAILGUN_SECRET=key-9f8e7d6c5b4a39281716\n' });
  try {
    const { files } = await collectFiles(p.root);
    assert.deepEqual(ids(await scanSecrets(p.root, files)), ['env-example-real-value']);
  } finally {
    await p.cleanup();
  }
});

test('.env without .gitignore is reported, ignored one is not', async () => {
  const bad = await makeProject({ '.env': 'APP_KEY=base64:abc\n' });
  const good = await makeProject({ '.env': 'APP_KEY=base64:abc\n', '.gitignore': '/vendor\n.env\n' });
  try {
    assert.deepEqual(ids(await scanSecrets(bad.root, (await collectFiles(bad.root)).files)), ['env-not-ignored']);
    assert.deepEqual(await scanSecrets(good.root, (await collectFiles(good.root)).files), []);
  } finally {
    await bad.cleanup();
    await good.cleanup();
  }
});

test('mask keeps only the edges', () => {
  assert.equal(mask('abcdefghijklmnop'), 'abcd****op');
  assert.equal(mask('short'), 'sh****');
});
