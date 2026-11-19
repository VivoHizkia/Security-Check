import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseLocation, renderSarif } from '../src/reporters/sarif.js';
import { finding, summarize } from '../src/findings.js';

test('parseLocation splits file and line, and gives URLs no file location', () => {
  assert.deepEqual(parseLocation('src/a.js:12'), { uri: 'src/a.js', line: 12 });
  assert.deepEqual(parseLocation('package-lock.json'), { uri: 'package-lock.json', line: null });
  assert.equal(parseLocation('https://myapp.com/.env'), null);
  assert.equal(parseLocation(''), null);
});

test('SARIF: one rule per id, stable fingerprints, live-site findings counted not dropped silently', () => {
  const findings = [
    finding({ id: 'js-eval', scanner: 'code', severity: 'medium', title: 'eval() / new Function()', location: 'a.js:3', fix: 'Remove it.' }),
    finding({ id: 'js-eval', scanner: 'code', severity: 'medium', title: 'eval() / new Function()', location: 'b.js:9', fix: 'Remove it.' }),
    finding({ id: 'deps-no-lockfile', scanner: 'deps', severity: 'info', title: 'No lockfile', location: 'package.json' }),
    finding({ id: 'missing-csp', scanner: 'headers', severity: 'medium', title: 'Missing CSP', location: 'https://myapp.com' }),
  ];
  const report = { meta: { version: '0.1.0' }, summary: summarize(findings), findings };
  const run = renderSarif(report).runs[0];
  assert.deepEqual(run.tool.driver.rules.map((r) => r.id), ['js-eval', 'deps-no-lockfile']);
  assert.equal(run.tool.driver.rules[0].name, 'JsEval');
  assert.equal(run.results.length, 3);
  assert.equal(run.properties.liveSiteFindingsOmitted, 1);
  assert.equal(run.results[2].level, 'note');
  assert.equal(run.results[2].locations[0].physicalLocation.region, undefined, 'no line → no region');
  assert.equal(run.tool.driver.rules[1].properties['security-severity'], undefined, 'info has no security severity');
  const again = renderSarif(report).runs[0];
  assert.deepEqual(again.results.map((r) => r.partialFingerprints), run.results.map((r) => r.partialFingerprints));
  assert.notEqual(run.results[0].partialFingerprints['tameng/v1'], run.results[1].partialFingerprints['tameng/v1']);
});
