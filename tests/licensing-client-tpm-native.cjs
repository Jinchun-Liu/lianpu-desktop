'use strict';
// Explicit hardware acceptance. Never prepares, signs with, deletes or changes the
// production device key. The isolated helper embeds its own fixed test key name.
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const native = path.join(root, 'src/licensing/native');
const artifactDirectory = path.join(root, 'tests/work/licensing-client-tpm');
const production = path.join(native, 'bin/Lianpu.Device.exe');
const isolated = path.join(artifactDirectory, 'Lianpu.Device.Test.exe');
if (process.platform !== 'win32') throw new Error('This acceptance check requires real Windows hardware.');
const sha = file => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const evidence = {
  recordedAt: new Date().toISOString(), platform: process.platform, architecture: process.arch,
  hypothesis: 'The fixed machine-scoped TPM P-256 key can be prepared once and can sign a challenge after the helper exits and restarts, without modifying the production key.',
  decisionValue: 'Determines whether native device proof is accepted on this machine or remains blocked by TPM/Windows permissions.',
  stopCondition: 'Stop key preparation/signature attempts on no TPM, unsupported TPM, Windows access denial, or the first policy/signature failure. Do not elevate permissions or use a software key.',
  affectedArtifact: 'Windows TPM licensing helper hardware acceptance; does not establish full installer or cross-user acceptance.',
  sourceHashes: {
    'src/licensing/native/LianpuTpm.cs': sha(path.join(native, 'LianpuTpm.cs')),
    'src/licensing/native/build.ps1': sha(path.join(native, 'build.ps1')),
    'src/licensing/native/bin/Lianpu.Device.exe': sha(production),
    'tests/work/licensing-client-tpm/Lianpu.Device.Test.exe': sha(isolated),
    'tests/licensing-client-tpm-native.cjs': sha(__filename)
  },
  calls: [], checks: [], limitations: ['No production key preparation or production signing.', 'No Windows account change, Windows reinstallation, TPM reset, or actual product reinstall was performed.']
};
function call(executable, command, input = '') {
  const response = spawnSync(executable, [command], { input, encoding: 'utf8', windowsHide: true, timeout: 20000 });
  assert.ifError(response.error);
  assert.equal(response.stderr, '');
  const result = JSON.parse(response.stdout.trim());
  evidence.calls.push({ helper: path.basename(executable), command, exitCode: response.status, result });
  assert.equal(result.testMode, executable === isolated);
  return result;
}
try {
  const productionBefore = call(production, 'status');
  const before = call(isolated, 'status');
  evidence.checks.push({ name: 'Read-only production and isolated probe', status: 'passed' });
  if (['ready', 'not_prepared'].includes(before.state)) {
    const prepared = call(isolated, 'prepare');
    if (!prepared.ok || prepared.state !== 'ready') {
      evidence.outcome = 'blocked';
      evidence.blocker = { state: prepared.state, code: prepared.code, nativeCode: prepared.nativeCode, operation: prepared.operation };
      evidence.checks.push({ name: 'Isolated machine key preparation', status: 'blocked', reason: prepared.state });
      evidence.checks.push({ name: 'Real TPM signature and restart persistence', status: 'not_run' });
    } else {
      assert.equal(prepared.tpm.version, '2.0');
      assert.equal(prepared.key.machineKey, true);
      assert.equal(prepared.key.hardwareBacked, true);
      assert.equal(prepared.key.exportable, false);
      assert.equal(prepared.key.provider, 'Microsoft Platform Crypto Provider');
      assert.equal(prepared.storage.prepared, true);
      const challenge = Buffer.concat([Buffer.from('LIANPU-LICENSING/v1/preparation\0'), crypto.randomBytes(32)]);
      const signed = call(isolated, 'sign', challenge.toString('base64url'));
      assert.equal(signed.ok, true);
      assert.equal(signed.deviceId, prepared.deviceId);
      const publicDer = Buffer.from(signed.publicKeySpki, 'base64url');
      assert.equal(crypto.createHash('sha256').update(publicDer).digest('hex'), signed.deviceId);
      assert.equal(Buffer.from(signed.signature, 'base64url').length, 64);
      const key = crypto.createPublicKey({ key: publicDer, format: 'der', type: 'spki' });
      assert.equal(key.asymmetricKeyDetails.namedCurve, 'prime256v1');
      assert.equal(crypto.verify('sha256', challenge, { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(signed.signature, 'base64url')), true);
      assert.equal(crypto.verify('sha256', Buffer.from('different challenge'), { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(signed.signature, 'base64url')), false);
      const reopened = call(isolated, 'prepare');
      assert.equal(reopened.deviceId, prepared.deviceId);
      assert.equal(reopened.key.created, false);
      evidence.checks.push({ name: 'Isolated machine key policy and prepared directory ACL', status: 'passed' });
      evidence.checks.push({ name: 'Real TPM signature verified independently by Node/OpenSSL; altered challenge rejected', status: 'passed' });
      evidence.checks.push({ name: 'Same isolated device identity after helper process restart and repeated prepare', status: 'passed' });
      evidence.outcome = 'passed';
      evidence.limitations.push('The isolated test key is intentionally retained; no key deletion command exists.');
    }
  } else {
    evidence.outcome = 'blocked'; evidence.blocker = { state: before.state, code: before.code };
    evidence.checks.push({ name: 'Real TPM key preparation and signature', status: 'not_run', reason: before.state });
  }
  const productionAfter = call(production, 'status');
  assert.equal(productionAfter.state, productionBefore.state);
  assert.equal(productionAfter.deviceId, productionBefore.deviceId);
  assert.equal(productionAfter.storage.exists, productionBefore.storage.exists);
  evidence.checks.push({ name: 'Production project key/storage state unchanged', status: 'passed' });
} catch (error) {
  evidence.outcome = 'failed'; evidence.error = { message: error.message, stack: error.stack }; process.exitCode = 1;
} finally {
  fs.mkdirSync(artifactDirectory, { recursive: true });
  const output = path.join(artifactDirectory, 'verification.json');
  fs.writeFileSync(output, JSON.stringify(evidence, null, 2) + '\n');
  console.log(JSON.stringify({ outcome: evidence.outcome, blocker: evidence.blocker, evidence: output, checks: evidence.checks }));
}
