'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const { VaultIdentity } = require('../src/auth.cjs');
function fixture(t, clock) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lianpu-auth-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return new VaultIdentity(path.join(dir, 'identity.json'), clock);
}
// Hypothesis: wrong credentials cannot read the data key; decide whether local vault access can ship; stop at first bypass.
test('local password wraps a random key, survives restart, and lock zeroes the original buffer', t => {
  const auth = fixture(t), setup = auth.setup({ name: '管理员', password: 'Only-test-password-123!' });
  const original = auth.key, expected = Buffer.from(original), raw = fs.readFileSync(auth.file, 'utf8');
  assert.equal(raw.includes('Only-test-password-123!'), false); assert.equal(raw.includes(expected.toString('base64')), false);
  auth.lock(); assert.equal(original.every(x => x === 0), true);
  const reopened = new VaultIdentity(auth.file);
  assert.throws(() => reopened.unlock({ id: setup.id, password: 'wrong' }), { code: 'LOGIN_FAILED' });
  reopened.unlock({ id: setup.id, password: 'Only-test-password-123!' }); assert.deepEqual(reopened.key, expected);
});
// Hypothesis: persisted backoff survives restart; decides exposure of password entry; stop after bounded five-error branch.
test('five failed attempts trigger persisted rate limiting', t => {
  let now = Date.now(); const auth = fixture(t, () => now), { id } = auth.setup({ name: '管理员', password: 'Only-test-password-123!' });
  auth.lock(); for (let i = 0; i < 5; i++) assert.throws(() => auth.unlock({ id, password: 'wrong' }));
  const reopened = new VaultIdentity(auth.file, () => now);
  assert.throws(() => reopened.unlock({ id, password: 'Only-test-password-123!' }), { code: 'TRY_LATER' });
  now += 31_000; reopened.unlock({ id, password: 'Only-test-password-123!' }); assert.ok(reopened.key);
});
// Hypothesis: password rotation and recovery preserve business key and revoke old materials; stop once each transition is checked.
test('password change and one-use rotated recovery preserve the data key', t => {
  const auth = fixture(t), { id, recoveryCode } = auth.setup({ name: '管理员', password: 'Only-test-password-123!' }), key = Buffer.from(auth.key);
  auth.changePassword({ oldPassword: 'Only-test-password-123!', newPassword: 'Next-password-456!' }); auth.lock();
  assert.throws(() => auth.unlock({ id, password: 'Only-test-password-123!' }));
  auth.unlock({ id, password: 'Next-password-456!' }); assert.deepEqual(auth.key, key); auth.lock();
  const recovered = auth.recover({ recoveryCode, newPassword: 'Recovered-password-789!' }); assert.deepEqual(auth.key, key);
  assert.notEqual(recovered.recoveryCode, recoveryCode); auth.lock();
  assert.throws(() => auth.recover({ recoveryCode, newPassword: 'Unwanted-password-999!' }), { code: 'RECOVERY_FAILED' });
  auth.unlock({ id, password: 'Recovered-password-789!' }); assert.deepEqual(auth.key, key);
});
// Hypothesis: a member receives the same vault key but cannot create new identities; app permission tests enforce its business scope separately.
test('member identity has separate credentials and cannot create members', t => {
  const auth = fixture(t); auth.setup({ name: '管理员', password: 'Owner-password-123!' }); const key = Buffer.from(auth.key);
  auth.addMember({ id: 'support-1', name: '客服', password: 'Member-password-123!' }); auth.lock();
  auth.unlock({ id: 'support-1', password: 'Member-password-123!' }); assert.deepEqual(auth.key, key);
  assert.throws(() => auth.addMember({ id: 'new', name: '越权', password: 'Other-password-123!' }), { code: 'FORBIDDEN' });
});
