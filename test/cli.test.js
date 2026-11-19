import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { fake, makeProject } from './helpers.js';

const BIN = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'tameng.js');

const run = (args) => new Promise((resolve) => {
  execFile(process.execPath, [BIN, ...args], (err, stdout, stderr) => resolve({ code: err ? err.code : 0, stdout, stderr }));
});

test('CLI: exit codes, JSON and HTML output', async () => {
  const p = await makeProject({ 'src/a.js': `const k = "${fake.aws()}";\n`, 'README.md': '# demo' });
  const jsonFile = path.join(p.root, 'out.json');
  const htmlFile = path.join(p.root, 'out.html');
  try {
    const clean = await run([p.root, '--only', 'code', '--fail-on', 'high', '-q']);
    assert.equal(clean.code, 0);

    const dirty = await run([p.root, '--offline', '--fail-on', 'high', '--json', jsonFile, '--html', htmlFile]);
    assert.equal(dirty.code, 1, dirty.stderr);
    assert.match(dirty.stdout, /AWS access key ID/);

    const report = JSON.parse(await readFile(jsonFile, 'utf8'));
    assert.equal(report.summary.counts.critical, 1);
    assert.equal(report.summary.grade, 'B');

    const html = await readFile(htmlFile, 'utf8');
    assert.match(html, /AWS access key ID/);
    assert.ok(!html.includes(fake.aws()), 'HTML report must not contain the raw secret');

    const sarifFile = path.join(p.root, 'out.sarif');
    await run([p.root, '--offline', '--sarif', sarifFile, '-q']);
    const sarifText = await readFile(sarifFile, 'utf8');
    assert.ok(!sarifText.includes(fake.aws()), 'SARIF report must not contain the raw secret');
    const sarif = JSON.parse(sarifText);
    assert.equal(sarif.version, '2.1.0');
    const [result] = sarif.runs[0].results;
    assert.equal(result.ruleId, 'aws-access-key');
    assert.equal(result.level, 'error');
    assert.deepEqual(result.locations[0].physicalLocation, { artifactLocation: { uri: 'src/a.js', uriBaseId: '%SRCROOT%' }, region: { startLine: 1 } });
    assert.equal(sarif.runs[0].tool.driver.rules[0].properties['security-severity'], '9.5');

    const both = await run([p.root, '--offline', '--json', '-', '--sarif', '-']);
    assert.equal(both.code, 2, 'two reports cannot share stdout');

    const stdoutJson = await run([p.root, '--offline', '--json', '-']);
    assert.equal(JSON.parse(stdoutJson.stdout).findings.length, 1);

    await writeFile(path.join(p.root, '.tamengignore'), 'src/\n');
    const ignored = await run([p.root, '--offline', '--fail-on', 'low', '-q']);
    assert.equal(ignored.code, 0, '.tamengignore excludes paths');

    const bad = await run(['--only', 'nope']);
    assert.equal(bad.code, 2);
  } finally {
    await p.cleanup();
  }
});
