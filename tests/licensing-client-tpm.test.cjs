'use strict';
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const root = path.resolve(__dirname, '..');
const production = path.join(root, 'src/licensing/native/bin/Lianpu.Device.exe');
const isolated = path.join(root, 'tests/work/licensing-client-tpm/Lianpu.Device.Test.exe');
const enabled = process.platform === 'win32' && fs.existsSync(production) && fs.existsSync(isolated);
function call(executable, args, input = '') {
  const result = spawnSync(executable, args, { input, encoding: 'utf8', windowsHide: true, timeout: 15000 });
  assert.ifError(result.error);
  assert.equal(result.stderr, '');
  const lines = result.stdout.trim().split(/\r?\n/);
  assert.equal(lines.length, 1, 'helper writes exactly one JSON object');
  const value = JSON.parse(lines[0]);
  assert.equal(value.version, 1);
  assert.equal(result.status, value.ok ? 0 : value.state === 'needs_admin' ? 20 : 1);
  return value;
}

test('TPM helper rejects key/provider selection and destructive commands before native work', { skip: !enabled }, () => {
  for (const args of [['prepare', 'other-key'], ['status', '--key=x'], ['clear'], ['delete'], ['export-private']]) {
    const result = call(production, args);
    assert.equal(result.code, 'INVALID_COMMAND');
    assert.equal(result.operation, 'input');
    assert.equal(result.testMode, false);
  }
});

test('TPM helper enforces canonical base64url and a bounded challenge before accessing hardware', { skip: !enabled }, () => {
  for (const input of ['', 'YQ==', ' YQ', 'Y Q', 'YQ\n\n', 'YR', 'A']) {
    const result = call(isolated, ['sign'], input);
    assert.equal(result.code, 'INVALID_CHALLENGE');
    assert.equal(result.operation, 'input');
    assert.equal(result.testMode, true);
  }
  assert.equal(call(isolated, ['sign'], 'A'.repeat(21849)).code, 'CHALLENGE_TOO_LARGE');
});

test('TPM status is read-only and keeps production and isolated storage distinct', { skip: !enabled }, () => {
  const directories = [path.join(process.env.ProgramData, 'Lianpu', 'Licensing', 'v1'), path.join(process.env.ProgramData, 'Lianpu', 'LicensingIsolatedTest', 'v1')];
  const before = directories.map(directory => fs.existsSync(directory));
  const normal = call(production, ['status']);
  const fixture = call(isolated, ['status']);
  assert.equal(normal.testMode, false);
  assert.equal(fixture.testMode, true);
  assert.equal(normal.storage.path.toLowerCase(), directories[0].toLowerCase());
  assert.equal(fixture.storage.path.toLowerCase(), directories[1].toLowerCase());
  assert.deepEqual(directories.map(directory => fs.existsSync(directory)), before);
  const states = new Set(['ready', 'not_prepared', 'no_tpm', 'tpm_not_2', 'needs_admin', 'unsupported', 'tpm_not_ready', 'error']);
  assert.ok(states.has(normal.state));
  assert.ok(states.has(fixture.state));
  if (!normal.ok) assert.ok(normal.code);
  if (!fixture.ok) assert.ok(fixture.code);
});
