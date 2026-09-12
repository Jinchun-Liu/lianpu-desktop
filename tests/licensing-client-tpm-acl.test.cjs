'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const source = path.join(root, 'src/licensing/native/LianpuTpm.cs');
const harness = path.join(__dirname, 'licensing-client-tpm-acl.cs');
const compiler = path.join(process.env.WINDIR || 'C:\\Windows', 'Microsoft.NET/Framework64/v4.0.30319/csc.exe');
const outputDirectory = path.join(__dirname, 'work/licensing-client-tpm-acl');
const executable = path.join(outputDirectory, 'AclPolicyTests.exe');
const sha = file => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');

test('Pure native ACL policy and persistent-readback boundaries; never executes the TPM helper entry point', { skip: process.platform !== 'win32' || !fs.existsSync(compiler) }, () => {
  const evidence = {
    recordedAt: new Date().toISOString(),
    hypothesis: 'ACL preparation performs no unnecessary write, preserves explicit administrator denials, and requires permissions plus unchanged identity after reopening.',
    decisionValue: 'Determines whether the corrected native permission flow is ready for a separately authorized hardware acceptance run.',
    stopCondition: 'Stop on the first compilation or pure-policy test failure; never invoke TPM APIs, a production helper command, elevation, or filesystem ACL changes.',
    affectedClaim: 'Pure ACL interpretation and preparation control flow only; actual TPM permissions and cross-user signing remain unverified.',
    sourceHashes: { 'src/licensing/native/LianpuTpm.cs': sha(source), 'tests/licensing-client-tpm-acl.cs': sha(harness), 'tests/licensing-client-tpm-acl.test.cjs': sha(__filename) },
    hardwareInvoked: false
  };
  fs.mkdirSync(outputDirectory, { recursive: true });
  const compiled = spawnSync(compiler, ['/nologo', '/target:exe', '/platform:x64', '/optimize+', '/warnaserror+', '/utf8output', '/reference:System.Web.Extensions.dll', '/main:AclPolicyTests', `/out:${executable}`, source, harness], { windowsHide: true, encoding: 'utf8', timeout: 30000 });
  assert.ifError(compiled.error);
  assert.equal(compiled.status, 0, compiled.stdout + compiled.stderr);
  const checked = spawnSync(executable, [], { windowsHide: true, encoding: 'utf8', timeout: 10000 });
  assert.ifError(checked.error);
  const result = JSON.parse(checked.stdout.trim());
  evidence.testExecutableSha256 = sha(executable);
  evidence.result = result;
  evidence.exitCode = checked.status;
  fs.writeFileSync(path.join(outputDirectory, 'verification.json'), JSON.stringify(evidence, null, 2) + '\n');
  assert.equal(result.pureAclOnly, true);
  assert.equal(checked.status, 0, JSON.stringify(result));
  assert.equal(result.tests, 17);
  assert.equal(result.results.filter(item => item.passed).length, 17, JSON.stringify(result));
});
